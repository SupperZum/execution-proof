//! Bounded descriptor packets over a privately created Linux socketpair.
//!
//! These endpoints have no pathname listener or arbitrary-FD constructor. Their
//! authenticity depends on trusted startup retaining the two endpoints and
//! closing inherited aliases. This transport does not validate rootfs contents,
//! admission, peer roles, or acknowledge custody. A successful send only queues
//! a packet; it does not establish that the peer accepted it.

use std::fmt;
use std::io;
use std::mem::{size_of, size_of_val, zeroed};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

pub const MAX_PACKET_BYTES: usize = 4096;
const CONTROL_WORDS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    InvalidPayload,
    Io(i32),
    Disconnected,
    Truncated,
    UnexpectedAncillary,
    DescriptorCount,
    PartialSend,
    Failed,
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "private descriptor transport: {self:?}")
    }
}

impl std::error::Error for TransportError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendOutcome {
    Sent,
    WouldBlock,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FdExpectation {
    None,
    One,
}

pub struct ReceivedPacket {
    payload: Vec<u8>,
    descriptor: Option<OwnedFd>,
}

impl ReceivedPacket {
    pub fn into_parts(self) -> (Vec<u8>, Option<OwnedFd>) {
        (self.payload, self.descriptor)
    }
}

/// A duplex endpoint with exclusive Rust ownership and bounded kernel queues.
///
/// Methods never block or spawn workers. The caller owns readiness/deadline and
/// cancellation policy. A protocol or syscall failure closes this endpoint and
/// discards its queued descriptors; subsequent operations fail. `WouldBlock`
/// leaves a complete packet unsent, so the caller retains its borrowed source FD.
pub struct PrivateFdChannel {
    descriptor: Option<OwnedFd>,
}

impl PrivateFdChannel {
    pub fn pair() -> Result<(Self, Self), TransportError> {
        let mut descriptors = [-1; 2];
        // SAFETY: the output array holds exactly two descriptors; all arguments
        // are fixed Linux UAPI values. CLOEXEC and NONBLOCK are atomic at create.
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
                descriptors.as_mut_ptr(),
            )
        } != 0
        {
            return Err(last_error());
        }
        // SAFETY: successful socketpair returns two distinct owned descriptors.
        let first = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        let second = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        Ok((
            Self {
                descriptor: Some(first),
            },
            Self {
                descriptor: Some(second),
            },
        ))
    }

    pub fn try_send(
        &mut self,
        payload: &[u8],
        descriptor: Option<BorrowedFd<'_>>,
    ) -> Result<SendOutcome, TransportError> {
        let socket = self.socket()?;
        if payload.is_empty() || payload.len() > MAX_PACKET_BYTES {
            return Err(TransportError::InvalidPayload);
        }
        let mut vector = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        // The usize array provides cmsghdr alignment on Linux architectures.
        let mut control = [0usize; CONTROL_WORDS];
        // SAFETY: all-zero msghdr has null optional pointers and valid counters.
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        if let Some(descriptor) = descriptor {
            message.msg_control = control.as_mut_ptr().cast();
            // SAFETY: bounded fixed integer input to the Linux CMSG layout API.
            message.msg_controllen =
                unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) } as usize;
            let header = message.msg_control.cast::<libc::cmsghdr>();
            // SAFETY: aligned control storage contains the header, its data and
            // required padding. Only one borrowed descriptor is transmitted.
            unsafe {
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as usize;
                libc::CMSG_DATA(header)
                    .cast::<libc::c_int>()
                    .write_unaligned(descriptor.as_raw_fd());
            }
        }
        // SAFETY: all message buffers are live for this syscall; sendmsg reads
        // them. NOSIGNAL prevents peer exit from raising process-wide SIGPIPE.
        let sent =
            unsafe { libc::sendmsg(socket, &message, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) };
        if sent < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(SendOutcome::WouldBlock);
            }
            return self.fail(io_error(error));
        }
        if sent as usize != payload.len() {
            return self.fail(TransportError::PartialSend);
        }
        Ok(SendOutcome::Sent)
    }

    pub fn try_receive(
        &mut self,
        expected: FdExpectation,
    ) -> Result<Option<ReceivedPacket>, TransportError> {
        let socket = self.socket()?;
        let mut payload = [0u8; MAX_PACKET_BYTES];
        let mut vector = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        let mut control = [0usize; CONTROL_WORDS];
        // SAFETY: all-zero msghdr has null optional pointers and valid counters.
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = size_of_val(&control);
        // SAFETY: each output points to live, correctly sized/aligned storage.
        // CLOEXEC is applied atomically to every delivered descriptor.
        let received = unsafe {
            libc::recvmsg(
                socket,
                &mut message,
                libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return self.fail(io_error(error));
        }
        // Parse and adopt/close every delivered SCM_RIGHTS descriptor before
        // inspecting packet flags. Even a rejected/truncated packet may carry
        // live FDs. Linux closes descriptors that did not fit the control buffer.
        let parsed = collect_descriptor(&message, &control, expected);
        if matches!(parsed, Err(TransportError::UnexpectedAncillary)) {
            return self.fail(TransportError::UnexpectedAncillary);
        }
        if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            return self.fail(TransportError::Truncated);
        }
        if received == 0 {
            return self.fail(TransportError::Disconnected);
        }
        let descriptor = match parsed {
            Ok(descriptor) => descriptor,
            Err(error) => return self.fail(error),
        };
        Ok(Some(ReceivedPacket {
            payload: payload[..received as usize].to_vec(),
            descriptor,
        }))
    }

    fn socket(&self) -> Result<libc::c_int, TransportError> {
        self.descriptor
            .as_ref()
            .map(AsRawFd::as_raw_fd)
            .ok_or(TransportError::Failed)
    }

    fn fail<T>(&mut self, error: TransportError) -> Result<T, TransportError> {
        drop(self.descriptor.take());
        Err(error)
    }
}

fn collect_descriptor(
    message: &libc::msghdr,
    control: &[usize; CONTROL_WORDS],
    expected: FdExpectation,
) -> Result<Option<OwnedFd>, TransportError> {
    let mut descriptor = None;
    let mut descriptor_count = 0;
    let mut rejected = false;
    let mut offset = 0;
    let length = message.msg_controllen.min(size_of_val(control));
    // SAFETY: fixed zero-data Linux CMSG layout query has no pointer arguments.
    let data_offset = unsafe { libc::CMSG_LEN(0) } as usize;
    while length.saturating_sub(offset) >= size_of::<libc::cmsghdr>() {
        // SAFETY: bounds above cover the header; read_unaligned avoids assuming
        // anything about a malformed peer's next header alignment.
        let header = unsafe {
            control
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<libc::cmsghdr>()
                .read_unaligned()
        };
        if header.cmsg_len < data_offset || header.cmsg_len > length - offset {
            rejected = true;
            break;
        }
        let data_length = header.cmsg_len - data_offset;
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            rejected |= data_length == 0 || !data_length.is_multiple_of(size_of::<libc::c_int>());
            for index in 0..data_length / size_of::<libc::c_int>() {
                // SAFETY: the checked cmsg length covers this complete integer.
                // The kernel installed these SCM_RIGHTS FDs in this process.
                let raw = unsafe {
                    control
                        .as_ptr()
                        .cast::<u8>()
                        .add(offset + data_offset + index * size_of::<libc::c_int>())
                        .cast::<libc::c_int>()
                        .read_unaligned()
                };
                if raw < 0 {
                    rejected = true;
                    continue;
                }
                // SAFETY: each installed SCM_RIGHTS entry is a distinct owned
                // FD, even if the sender repeated the same source descriptor.
                let owned = unsafe { OwnedFd::from_raw_fd(raw) };
                descriptor_count += 1;
                if descriptor.is_none() {
                    descriptor = Some(owned);
                }
                // Any additional owned FD closes here; parse all headers even
                // after rejection so no later SCM_RIGHTS entry is leaked.
            }
        } else {
            rejected = true;
        }
        let aligned = (header.cmsg_len + size_of::<usize>() - 1) & !(size_of::<usize>() - 1);
        offset += aligned;
    }
    if rejected {
        return Err(TransportError::UnexpectedAncillary);
    }
    let accepted_count = match expected {
        FdExpectation::None => descriptor_count == 0,
        FdExpectation::One => descriptor_count == 1,
    };
    if !accepted_count {
        return Err(TransportError::DescriptorCount);
    }
    Ok(descriptor)
}

fn io_error(error: io::Error) -> TransportError {
    TransportError::Io(error.raw_os_error().unwrap_or(libc::EIO))
}

fn last_error() -> TransportError {
    io_error(io::Error::last_os_error())
}

#[cfg(test)]
#[path = "fd_transport_tests.rs"]
mod tests;
