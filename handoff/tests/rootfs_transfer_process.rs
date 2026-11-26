//! Native process-separation check of the production descriptor transport.
//! This single-thread fork fixture does not wire trusted startup through exec,
//! construct a checked rootfs lease, or execute any workload.

use execution_proof_handoff::fd_transport::{FdExpectation, PrivateFdChannel, SendOutcome};
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::time::{Duration, Instant};

const BYTES: &[u8] = b"isolated-source";
const MAX_WAIT: Duration = Duration::from_secs(3);
const REQUIRED_SEALS: libc::c_int = libc::F_SEAL_WRITE
    | libc::F_SEAL_GROW
    | libc::F_SEAL_SHRINK
    | libc::F_SEAL_SEAL
    | libc::F_SEAL_EXEC;

fn descriptor_count() -> Result<usize, String> {
    std::fs::read_dir("/proc/self/fd")
        .map_err(|_| "cannot count descriptors".to_owned())?
        .map(|entry| {
            entry
                .map(|_| ())
                .map_err(|_| "descriptor enumeration failed".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|entries| entries.len())
}

fn source() -> Result<File, String> {
    // SAFETY: fixed live name and fixed Linux data-only sealing flags.
    let raw = unsafe {
        libc::memfd_create(
            c"onb17-process-transfer".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | libc::MFD_NOEXEC_SEAL,
        )
    };
    if raw < 0 {
        return Err("data-only memfd unavailable".into());
    }
    // SAFETY: a successful creation returned a new exclusively owned FD.
    let file = unsafe { File::from_raw_fd(raw) };
    file.write_all_at(BYTES, 0)
        .map_err(|_| "fixture write failed")?;
    // SAFETY: fcntl adds fixed seals; lseek only sets the owned source offset.
    if unsafe { libc::fcntl(raw, libc::F_ADD_SEALS, REQUIRED_SEALS) } != 0
        || unsafe { libc::lseek(raw, 5, libc::SEEK_SET) } != 5
    {
        return Err("fixture sealing/offset failed".into());
    }
    Ok(file)
}

fn send_until_ready(
    channel: &mut PrivateFdChannel,
    payload: &[u8],
    source: Option<std::os::fd::BorrowedFd<'_>>,
) -> Result<(), String> {
    let deadline = Instant::now() + MAX_WAIT;
    while Instant::now() < deadline {
        match channel.try_send(payload, source) {
            Ok(SendOutcome::Sent) => return Ok(()),
            Ok(SendOutcome::WouldBlock) => std::thread::sleep(Duration::from_millis(5)),
            Err(error) => return Err(format!("send failed: {error}")),
        }
    }
    Err("send deadline expired".into())
}

fn receive_until_ready(
    channel: &mut PrivateFdChannel,
    expected: FdExpectation,
) -> Result<(Vec<u8>, Option<std::os::fd::OwnedFd>), String> {
    let deadline = Instant::now() + MAX_WAIT;
    while Instant::now() < deadline {
        match channel.try_receive(expected) {
            Ok(Some(packet)) => return Ok(packet.into_parts()),
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(error) => return Err(format!("receive failed: {error}")),
        }
    }
    Err("receive deadline expired".into())
}

fn child(mut channel: PrivateFdChannel, inherited_source: File) -> Result<(), String> {
    // The child must obtain the source through SCM_RIGHTS, not its fork alias.
    drop(inherited_source);
    let (payload, received) = receive_until_ready(&mut channel, FdExpectation::One)?;
    if payload != b"offer-v1" {
        return Err("wrong offer bytes".into());
    }
    let file = File::from(received.ok_or("missing received source")?);
    // SAFETY: live descriptor inspections with no pointer arguments.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    let offset = unsafe { libc::lseek(file.as_raw_fd(), 0, libc::SEEK_CUR) };
    let metadata = file.metadata().map_err(|_| "received metadata failed")?;
    if flags < 0
        || flags & libc::FD_CLOEXEC == 0
        || seals < 0
        || seals & REQUIRED_SEALS != REQUIRED_SEALS
        || offset != 5
        || !metadata.is_file()
        || metadata.mode() & 0o111 != 0
        || metadata.len() != BYTES.len() as u64
    {
        return Err("received source profile mismatch".into());
    }
    let mut bytes = [0; BYTES.len()];
    file.read_exact_at(&mut bytes, 0)
        .map_err(|_| "received positional read failed")?;
    if bytes != BYTES {
        return Err("received content mismatch".into());
    }
    drop(file);
    send_until_ready(&mut channel, b"receipt-v1", None)?;
    drop(channel);
    Ok(())
}

fn wait_child(pid: libc::pid_t, reaped: &mut bool) -> Result<(), String> {
    let deadline = Instant::now() + MAX_WAIT;
    while Instant::now() < deadline {
        let mut status = 0;
        // SAFETY: pid is the still-owned child; status points to a live integer.
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result == pid {
            *reaped = true;
            return if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                Ok(())
            } else {
                Err("child rejected transport check".into())
            };
        }
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                // Do not signal a PID after ownership of that child was lost.
                *reaped = true;
            }
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err("child wait failed".into());
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Err("child wait deadline expired".into())
}

fn run() -> Result<(usize, usize), String> {
    let before = descriptor_count()?;
    let mountinfo = std::fs::read("/proc/self/mountinfo").map_err(|_| "mountinfo unavailable")?;
    let source = source()?;
    let (mut sender, receiver) = PrivateFdChannel::pair().map_err(|error| error.to_string())?;
    let threads = std::fs::read_dir("/proc/self/task")
        .map_err(|_| "thread enumeration failed")?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "thread enumeration failed")?;
    if threads.len() != 1 {
        return Err("fork fixture requires a single thread".into());
    }
    drop(threads);
    // Explicit SIG_IGN/SA_NOCLDWAIT could auto-reap the child and permit PID
    // reuse before failure cleanup. Require normal, exclusively owned reaping.
    // SAFETY: initialized sigaction output; null new action only queries state.
    let mut child_action: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut child_action) } != 0
        || child_action.sa_sigaction != libc::SIG_DFL
        || child_action.sa_flags & libc::SA_NOCLDWAIT != 0
    {
        return Err("fork fixture requires default SIGCHLD reaping".into());
    }
    // SAFETY: this harness is single-threaded and has no async runtime. Each
    // branch immediately drops the other endpoint; child exits without unwinding
    // into a test runtime. This is not a production startup implementation.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err("fork failed".into());
    }
    if pid == 0 {
        drop(sender);
        let status = i32::from(child(receiver, source).is_err());
        // SAFETY: child owns no outstanding work and must not return to main.
        unsafe { libc::_exit(status) };
    }
    drop(receiver);
    let mut reaped = false;
    let outcome = (|| {
        send_until_ready(&mut sender, b"offer-v1", Some(source.as_fd()))?;
        let (receipt, descriptor) = receive_until_ready(&mut sender, FdExpectation::None)?;
        if receipt != b"receipt-v1" || descriptor.is_some() {
            return Err("wrong receipt".into());
        }
        // SAFETY: inspecting the live source's shared open-file-description.
        if unsafe { libc::lseek(source.as_raw_fd(), 0, libc::SEEK_CUR) } != 5 {
            return Err("receiver changed source offset".into());
        }
        wait_child(pid, &mut reaped)
    })();
    if outcome.is_err() && !reaped {
        // SAFETY: kill is limited to the still-owned child PID created above;
        // no arbitrary child or process group is targeted. Reaping remains
        // deadline-bounded even if the kernel does not complete child exit.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let _ = wait_child(pid, &mut reaped);
        if !reaped {
            return Err("child cleanup deadline expired".into());
        }
    }
    outcome?;
    drop(sender);
    drop(source);
    let after = descriptor_count()?;
    if before != after {
        return Err("parent descriptor leak".into());
    }
    if std::fs::read("/proc/self/mountinfo").map_err(|_| "mountinfo unavailable")? != mountinfo {
        return Err("mount namespace changed".into());
    }
    Ok((before, after))
}

fn main() {
    match run() {
        Ok((before, after)) => println!(
            "{{\"status\":\"PASS\",\"scope\":\"single-thread fork separation using production private FD transport\",\"descriptors_before\":{before},\"descriptors_after\":{after},\"separate_processes\":true,\"received_descriptor_cloexec\":true,\"sealed_data_only_source\":true,\"shared_offset_unchanged\":true,\"namespace_mountinfo_unchanged\":true,\"target_executed\":false}}"
        ),
        Err(error) => {
            eprintln!("rootfs transfer process check failed: {error}");
            std::process::exit(1);
        }
    }
}
