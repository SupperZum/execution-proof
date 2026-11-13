//! Real exec of two pinned role fixtures using the production startup module.
//! Only this helper binary executes; no application/workload ELF is launched.

use execution_proof_handoff::{
    fd_transport::{FdExpectation, SendOutcome},
    startup::{
        launch_kata_role, launch_roles, ExpectedStartup, PinnedRoleExecutable, Role, RoleCommand,
        StartupBoundChannel, StartupError,
    },
};
use ring::digest;
use std::{
    ffi::OsString,
    fs::File,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::fs::FileExt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

const BOOT: [u8; 48] = [0x5a; 48];

fn self_digest() -> [u8; 48] {
    digest::digest(&digest::SHA384, &std::fs::read("/proc/self/exe").unwrap())
        .as_ref()
        .try_into()
        .unwrap()
}
fn child(mode: &str) -> Result<(), StartupError> {
    let role = if mode == "--startup-preparation" {
        Role::Preparation
    } else {
        Role::Kata
    };
    let own = self_digest();
    let expected = ExpectedStartup {
        role,
        boot_config_sha384: if mode == "--startup-wrong-context" {
            [0x5b; 48]
        } else {
            BOOT
        },
        own_executable_sha384: own,
        peer_executable_sha384: own,
    };
    let locations = std::env::var("ONB17_STARTUP_FDS").unwrap();
    let (channel_raw, ticket_raw) = locations.split_once(':').unwrap();
    let channel_raw: i32 = channel_raw.parse().unwrap();
    let ticket_raw: i32 = ticket_raw.parse().unwrap();
    assert!(channel_raw >= 128 && ticket_raw >= 128 && channel_raw != ticket_raw);
    // SAFETY: the fixture launcher passes exclusive descriptors identified by
    // its location hint. This entry runs before other descriptor-owning code.
    let mut channel =
        unsafe { StartupBoundChannel::accept_inherited(expected, Duration::from_secs(3)) }?;
    let mut death_signal = 0;
    // SAFETY: PR_GET_PDEATHSIG writes one initialized integer in this process.
    if unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut death_signal, 0, 0, 0) } != 0
        || death_signal != libc::SIGKILL
    {
        return Err(StartupError::InvalidBootstrap);
    }
    let descriptors: Vec<i32> = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .parse()
                .unwrap()
        })
        .collect();
    for raw in descriptors {
        if raw >= 3 && raw != channel_raw && unsafe { libc::fcntl(raw, libc::F_GETFD) } >= 0 {
            return Err(StartupError::InvalidBootstrap);
        }
    }
    if unsafe { libc::fcntl(channel_raw, libc::F_GETFD) } & libc::FD_CLOEXEC == 0
        || unsafe { libc::fcntl(ticket_raw, libc::F_GETFD) } >= 0
    {
        return Err(StartupError::InvalidSocket);
    }
    exchange(&mut channel)
}
fn exchange(channel: &mut StartupBoundChannel) -> Result<(), StartupError> {
    let role_byte = if channel.role() == Role::Preparation {
        1
    } else {
        2
    };
    let mut payload = vec![role_byte];
    payload.extend_from_slice(&channel.binding_commitment());
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        if Instant::now() >= until {
            return Err(StartupError::Deadline);
        }
        if channel
            .try_send(&payload, None)
            .map_err(StartupError::Transport)?
            == SendOutcome::Sent
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    loop {
        if Instant::now() >= until {
            return Err(StartupError::Deadline);
        }
        if let Some(packet) = channel
            .try_receive(FdExpectation::None)
            .map_err(StartupError::Transport)?
        {
            let (peer, no_fd) = packet.into_parts();
            drop(no_fd);
            if peer.len() != payload.len() || peer[0] == role_byte || peer[1..] != payload[1..] {
                return Err(StartupError::PeerMismatch);
            }
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn command(mode: &str, hash: [u8; 48]) -> RoleCommand {
    let pinned =
        PinnedRoleExecutable::new(File::open("/proc/self/exe").unwrap(), hash, 128 << 20).unwrap();
    RoleCommand::new(pinned, vec![OsString::from(mode)]).unwrap()
}
fn descriptors() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

// A native ELF64 image with a valid PT_LOAD and a deliberately missing dynamic
// interpreter. The kernel must report ENOENT before any program instruction can
// run. This distinguishes lost exec errors from the second fixture's ENOEXEC.
fn missing_interpreter_elf() -> Vec<u8> {
    let own = std::fs::read("/proc/self/exe").unwrap();
    assert_eq!(&own[..6], b"\x7fELF\x02\x01");
    let mut bytes = vec![0; 256];
    bytes[..64].copy_from_slice(&own[..64]);
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x4000e0u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[40..48].fill(0);
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
    bytes[58..64].fill(0);
    // PT_INTERP at offset 176.
    let interpreter = b"/onb17-missing-loader\0";
    bytes[64..68].copy_from_slice(&3u32.to_le_bytes());
    bytes[72..80].copy_from_slice(&176u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&(interpreter.len() as u64).to_le_bytes());
    bytes[112..120].copy_from_slice(&1u64.to_le_bytes());
    // PT_LOAD covers the complete file with an executable page.
    bytes[120..124].copy_from_slice(&1u32.to_le_bytes());
    bytes[124..128].copy_from_slice(&5u32.to_le_bytes());
    bytes[136..144].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[152..160].copy_from_slice(&256u64.to_le_bytes());
    bytes[160..168].copy_from_slice(&4096u64.to_le_bytes());
    bytes[168..176].copy_from_slice(&4096u64.to_le_bytes());
    bytes[176..176 + interpreter.len()].copy_from_slice(interpreter);
    bytes
}
fn negative_command(bytes: &[u8]) -> RoleCommand {
    let raw =
        unsafe { libc::memfd_create(c"startup-negative-fixture".as_ptr(), libc::MFD_CLOEXEC) };
    assert!(raw >= 0);
    let source = unsafe { File::from_raw_fd(raw) };
    source.write_all_at(bytes, 0).unwrap();
    let hash = digest::digest(&digest::SHA384, bytes)
        .as_ref()
        .try_into()
        .unwrap();
    RoleCommand::new(
        PinnedRoleExecutable::new(source, hash, 4096).unwrap(),
        Vec::new(),
    )
    .unwrap()
}
fn concurrent_spawn_errors_are_preserved() {
    let missing = missing_interpreter_elf();
    let stop = Arc::new(AtomicBool::new(false));
    let churners: Vec<_> = (0..4)
        .map(|_| {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let held: Vec<_> = (0..24).map(|_| File::open("/dev/null").unwrap()).collect();
                    std::thread::yield_now();
                    drop(held);
                }
            })
        })
        .collect();
    for _ in 0..256 {
        let result = launch_roles(
            negative_command(&missing),
            negative_command(b"\x7fELFbad-native-fixture"),
            BOOT,
        );
        assert!(matches!(result, Err(StartupError::Kernel(libc::ENOENT))));
    }
    stop.store(true, Ordering::Release);
    for churner in churners {
        churner.join().unwrap();
    }
    // No child from a failed Command::spawn may remain waiting for a reaper.
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}
fn main() {
    let arguments: Vec<_> = std::env::args().collect();
    if let Some(mode) = arguments.get(1) {
        std::process::exit(if child(mode).is_ok() { 0 } else { 1 });
    }
    let before = descriptors();
    let mounts = std::fs::read("/proc/self/mountinfo").unwrap();
    let hash = self_digest();
    {
        // Deliberately non-CLOEXEC foreign alias: production pre_exec must close
        // it on exec while preserving exactly the two reserved role locations.
        let null = File::open("/dev/null").unwrap();
        let raw = unsafe { libc::fcntl(null.as_raw_fd(), libc::F_DUPFD, 64) };
        assert!(raw >= 64);
        let _foreign = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut roles = launch_roles(
            command("--startup-preparation", hash),
            command("--startup-kata", hash),
            BOOT,
        )
        .unwrap();
        roles.wait(Duration::from_secs(8)).unwrap();
    }
    for mode in ["--startup-preparation", "--startup-wrong-context"] {
        let mut roles = launch_roles(
            command("--startup-preparation", hash),
            command(mode, hash),
            BOOT,
        )
        .unwrap();
        assert!(roles.wait(Duration::from_secs(8)).is_err());
    }
    {
        let (mut preparation, mut kata) = launch_kata_role(
            command("--startup-kata", hash),
            hash,
            128 << 20,
            BOOT,
            Duration::from_secs(4),
        )
        .unwrap();
        assert_eq!(preparation.role(), Role::Preparation);
        assert_eq!(preparation.own_executable_sha384(), &hash);
        assert_eq!(preparation.peer_executable_sha384(), &hash);
        exchange(&mut preparation).unwrap();
        kata.wait(Duration::from_secs(8)).unwrap();
    }
    assert!(matches!(
        launch_kata_role(
            command("--startup-kata", hash),
            [0; 48],
            128 << 20,
            BOOT,
            Duration::from_secs(4),
        ),
        Err(StartupError::ArtifactMismatch)
    ));
    assert!(launch_kata_role(
        command("--startup-wrong-context", hash),
        hash,
        128 << 20,
        BOOT,
        Duration::from_secs(4),
    )
    .is_err());
    let wrong =
        PinnedRoleExecutable::new(File::open("/proc/self/exe").unwrap(), [0; 48], 128 << 20);
    assert!(matches!(wrong, Err(StartupError::ArtifactMismatch)));
    concurrent_spawn_errors_are_preserved();
    assert_eq!(descriptors(), before);
    assert_eq!(std::fs::read("/proc/self/mountinfo").unwrap(), mounts);
    println!("{{\"status\":\"PASS\",\"scope\":\"pinned role helpers across exec, including actual hosted preparation plus Kata child\",\"descriptors_before\":{before},\"descriptors_after\":{},\"mutual_role_boot_binding\":true,\"hosted_preparation_identity_checked\":true,\"foreign_alias_closed_on_exec\":true,\"parent_death_signal_checked\":true,\"wrong_role_and_context_rejected\":true,\"artifact_mismatch_rejected\":true,\"concurrent_fd_churn_exec_failures\":256,\"exec_errors_preserved_and_reaped\":true,\"namespace_mountinfo_unchanged\":true,\"workload_executed\":false}}", descriptors());
}
