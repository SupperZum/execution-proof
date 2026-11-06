use super::*;
use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt;

fn source(label: &std::ffi::CStr) -> File {
    // SAFETY: a live NUL-terminated name and fixed descriptor creation flags.
    let raw = unsafe { libc::memfd_create(label.as_ptr(), libc::MFD_CLOEXEC) };
    assert!(raw >= 0);
    // SAFETY: successful memfd_create returns a new exclusively owned FD.
    let file = unsafe { File::from_raw_fd(raw) };
    file.write_all_at(b"source bytes", 0).unwrap();
    file
}

fn aliases(label: &str) -> usize {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::read_link(entry.path()).ok())
        .filter(|path| path.to_string_lossy().contains(label))
        .count()
}

fn raw_send(channel: &PrivateFdChannel, payload: &[u8], descriptors: &[libc::c_int]) {
    let mut vector = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    // SAFETY: the integer input fits the Linux CMSG layout helper's domain.
    let control_bytes = unsafe {
        libc::CMSG_SPACE(std::mem::size_of_val(descriptors).try_into().unwrap()) as usize
    };
    let mut control = vec![0usize; control_bytes.div_ceil(size_of::<usize>())];
    // SAFETY: zero is valid for all optional msghdr fields.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    if !descriptors.is_empty() {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control_bytes;
        let header = message.msg_control.cast::<libc::cmsghdr>();
        // SAFETY: aligned, completely initialized storage covers header and the
        // bounded descriptor slice. These intentionally bypass public limits.
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(descriptors) as u32) as usize;
            std::ptr::copy_nonoverlapping(
                descriptors.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(header),
                std::mem::size_of_val(descriptors),
            );
        }
    }
    // SAFETY: live socket and initialized message buffers for this syscall.
    let sent = unsafe {
        libc::sendmsg(
            channel.socket().unwrap(),
            &message,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    assert_eq!(
        sent,
        payload.len() as isize,
        "{}",
        io::Error::last_os_error()
    );
}

#[test]
fn private_pair_has_atomic_nonblocking_cloexec_and_sequence_packets() {
    let (first, second) = PrivateFdChannel::pair().unwrap();
    for endpoint in [&first, &second] {
        let raw = endpoint.socket().unwrap();
        // SAFETY: descriptor inspections have no pointer arguments.
        assert_ne!(
            unsafe { libc::fcntl(raw, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0,
            "{}",
            io::Error::last_os_error()
        );
        assert_ne!(
            unsafe { libc::fcntl(raw, libc::F_GETFL) } & libc::O_NONBLOCK,
            0
        );
        let mut socket_type = 0;
        let mut length = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: initialized output integer and its exact size.
        assert_eq!(
            unsafe {
                libc::getsockopt(
                    raw,
                    libc::SOL_SOCKET,
                    libc::SO_TYPE,
                    (&mut socket_type as *mut libc::c_int).cast(),
                    &mut length,
                )
            },
            0,
            "{}",
            io::Error::last_os_error()
        );
        assert_eq!(socket_type, libc::SOCK_SEQPACKET);
    }
}

#[test]
fn descriptor_packet_preserves_bytes_and_receiver_cloexec_without_consuming_source() {
    let source = source(c"onb17-transport-positive");
    let (mut sender, mut receiver) = PrivateFdChannel::pair().unwrap();
    assert!(receiver.try_receive(FdExpectation::One).unwrap().is_none());
    assert_eq!(
        sender.try_send(b"offer", Some(source.as_fd())),
        Ok(SendOutcome::Sent)
    );
    let (payload, received) = receiver
        .try_receive(FdExpectation::One)
        .unwrap()
        .unwrap()
        .into_parts();
    assert_eq!(payload, b"offer");
    let received = received.unwrap();
    // SAFETY: F_GETFD only inspects the live received descriptor.
    assert_ne!(
        unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0,
        "{}",
        io::Error::last_os_error()
    );
    let file = File::from(received);
    let mut bytes = [0; 12];
    file.read_exact_at(&mut bytes, 0).unwrap();
    assert_eq!(&bytes, b"source bytes");
    assert_eq!(aliases("onb17-transport-positive"), 2);
    drop(file);
    assert_eq!(aliases("onb17-transport-positive"), 1);
}

#[test]
fn control_packets_are_duplex_and_retain_packet_boundaries() {
    let (mut first, mut second) = PrivateFdChannel::pair().unwrap();
    for payload in [b"first".as_slice(), b"second"] {
        assert_eq!(first.try_send(payload, None).unwrap(), SendOutcome::Sent);
    }
    for expected in [b"first".as_slice(), b"second"] {
        let (payload, descriptor) = second
            .try_receive(FdExpectation::None)
            .unwrap()
            .unwrap()
            .into_parts();
        assert_eq!(payload, expected);
        assert!(descriptor.is_none());
    }
    assert_eq!(second.try_send(b"ack", None).unwrap(), SendOutcome::Sent);
    assert_eq!(
        first
            .try_receive(FdExpectation::None)
            .unwrap()
            .unwrap()
            .into_parts()
            .0,
        b"ack"
    );
}

#[test]
fn local_payload_rejection_does_not_send_or_poison_channel() {
    let (mut sender, mut receiver) = PrivateFdChannel::pair().unwrap();
    for invalid in [Vec::new(), vec![1; MAX_PACKET_BYTES + 1]] {
        assert_eq!(
            sender.try_send(&invalid, None),
            Err(TransportError::InvalidPayload)
        );
        assert!(receiver.try_receive(FdExpectation::None).unwrap().is_none());
    }
    assert_eq!(
        sender.try_send(&[7; MAX_PACKET_BYTES], None),
        Ok(SendOutcome::Sent)
    );
    assert_eq!(
        receiver
            .try_receive(FdExpectation::None)
            .unwrap()
            .unwrap()
            .into_parts()
            .0
            .len(),
        MAX_PACKET_BYTES
    );
}

#[test]
fn wrong_descriptor_counts_close_every_received_descriptor_and_endpoint() {
    let source = source(c"onb17-transport-wrong-count");
    for (count, expected) in [
        (0, FdExpectation::One),
        (1, FdExpectation::None),
        (2, FdExpectation::One),
    ] {
        let (sender, mut receiver) = PrivateFdChannel::pair().unwrap();
        raw_send(&sender, b"offer", &vec![source.as_raw_fd(); count]);
        assert!(matches!(
            receiver.try_receive(expected),
            Err(TransportError::DescriptorCount)
        ));
        assert_eq!(aliases("onb17-transport-wrong-count"), 1);
        assert!(matches!(
            receiver.try_receive(expected),
            Err(TransportError::Failed)
        ));
    }
}

#[test]
fn oversized_packet_closes_delivered_descriptor_and_terminally_rejects() {
    let source = source(c"onb17-transport-data-truncation");
    let (sender, mut receiver) = PrivateFdChannel::pair().unwrap();
    raw_send(&sender, &[1; MAX_PACKET_BYTES + 1], &[source.as_raw_fd()]);
    assert!(matches!(
        receiver.try_receive(FdExpectation::One),
        Err(TransportError::Truncated)
    ));
    assert_eq!(aliases("onb17-transport-data-truncation"), 1);
    assert!(matches!(
        receiver.try_receive(FdExpectation::One),
        Err(TransportError::Failed)
    ));
}

#[test]
fn truncated_ancillary_closes_all_installed_and_kernel_discarded_descriptors() {
    let source = source(c"onb17-transport-control-truncation");
    let (sender, mut receiver) = PrivateFdChannel::pair().unwrap();
    // Linux accepts up to253 SCM_RIGHTS entries.80 exceeds the bounded receive
    // control buffer on both32-bit and64-bit Linux.
    raw_send(&sender, b"offer", &[source.as_raw_fd(); 80]);
    assert!(receiver.try_receive(FdExpectation::One).is_err());
    assert_eq!(aliases("onb17-transport-control-truncation"), 1);
}

#[test]
fn unexpected_credentials_are_rejected_after_closing_rights() {
    let source = source(c"onb17-transport-credentials");
    for payload in [b"offer".as_slice(), b""] {
        let (sender, mut receiver) = PrivateFdChannel::pair().unwrap();
        let enabled: libc::c_int = 1;
        // SAFETY: fixed option reads an initialized integer of the exact size.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    receiver.socket().unwrap(),
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    (&enabled as *const libc::c_int).cast(),
                    size_of_val(&enabled) as libc::socklen_t,
                )
            },
            0,
            "{}",
            io::Error::last_os_error()
        );
        raw_send(&sender, payload, &[source.as_raw_fd()]);
        assert!(matches!(
            receiver.try_receive(FdExpectation::One),
            Err(TransportError::UnexpectedAncillary)
        ));
        assert_eq!(aliases("onb17-transport-credentials"), 1);
    }
}

#[test]
fn peer_exit_and_unread_queue_drop_never_signal_or_publish_a_packet() {
    let source = source(c"onb17-transport-peer-exit");
    let (mut sender, receiver) = PrivateFdChannel::pair().unwrap();
    assert_eq!(
        sender.try_send(b"queued", Some(source.as_fd())),
        Ok(SendOutcome::Sent)
    );
    drop(receiver);
    assert_eq!(aliases("onb17-transport-peer-exit"), 1);
    assert!(matches!(
        sender.try_send(b"later", None),
        Err(TransportError::Io(_))
    ));
    assert_eq!(sender.try_send(b"again", None), Err(TransportError::Failed));
    for expected in [FdExpectation::None, FdExpectation::One] {
        let (sender, mut receiver) = PrivateFdChannel::pair().unwrap();
        drop(sender);
        assert!(matches!(
            receiver.try_receive(expected),
            Err(TransportError::Disconnected)
        ));
        // A zero-byte malformed packet can carry live FDs on SOCK_SEQPACKET;
        // rejecting it must still close every delivered descriptor.
        let (sender, mut receiver) = PrivateFdChannel::pair().unwrap();
        raw_send(&sender, b"", &[source.as_raw_fd()]);
        assert!(matches!(
            receiver.try_receive(expected),
            Err(TransportError::Disconnected)
        ));
        assert_eq!(aliases("onb17-transport-peer-exit"), 1);
    }
}

#[test]
fn full_kernel_queue_reports_would_block_without_a_partial_packet() {
    let source = source(c"onb17-transport-backpressure");
    let (mut sender, mut receiver) = PrivateFdChannel::pair().unwrap();
    let payload = [3; MAX_PACKET_BYTES];
    let mut sent = 0;
    for _ in 0..1024 {
        match sender.try_send(&payload, Some(source.as_fd())).unwrap() {
            SendOutcome::Sent => sent += 1,
            SendOutcome::WouldBlock => break,
        }
    }
    assert!(sent > 0 && sent < 1024);
    for _ in 0..sent {
        let (bytes, descriptor) = receiver
            .try_receive(FdExpectation::One)
            .unwrap()
            .unwrap()
            .into_parts();
        assert_eq!(bytes, payload);
        drop(descriptor);
    }
    assert!(receiver.try_receive(FdExpectation::One).unwrap().is_none());
    assert_eq!(aliases("onb17-transport-backpressure"), 1);
    assert_eq!(
        sender.try_send(b"retry", Some(source.as_fd())),
        Ok(SendOutcome::Sent)
    );
}
