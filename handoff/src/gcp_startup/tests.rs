use super::*;

// Separate owned test process: no software authority or production startup
// path uses these actions. Blocking is ended by the tested owner kill/join.
#[test]
fn readiness_process_fixture() {
    let Ok(action) = std::env::var("ONB17_TEST_READY_ACTION") else {
        return;
    };
    let fd: i32 = std::env::var("ONB17_TEST_READY_FD")
        .unwrap()
        .parse()
        .unwrap();
    let bytes: &[u8] = match action.as_str() {
        "ready" | "marker-without-eof" => b"R",
        "wrong" => b"X",
        "extra" => b"RR",
        "eof" | "silent" | "exit-before-ready" => b"",
        _ => panic!("unknown readiness fixture action"),
    };
    if !bytes.is_empty() {
        assert_eq!(
            unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) },
            bytes.len() as isize
        );
    }
    if !matches!(action.as_str(), "silent" | "marker-without-eof") {
        assert_eq!(unsafe { libc::close(fd) }, 0);
    }
    if action == "exit-before-ready" {
        std::process::exit(0);
    }
    loop {
        unsafe { libc::pause() };
    }
}

fn readiness_child(action: &str) -> (ManagementRelayOwner, File, libc::pid_t) {
    use std::os::unix::process::CommandExt;
    let (reader, writer) = management_readiness_pipe().unwrap();
    let fd = writer.as_raw_fd();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "gcp_startup::tests::readiness_process_fixture"])
        .env("ONB17_TEST_READY_ACTION", action)
        .env("ONB17_TEST_READY_FD", fd.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    let pid = child.id() as libc::pid_t;
    drop(writer);
    (
        ManagementRelayOwner {
            child,
            stopped: false,
            _launch_thread: std::marker::PhantomData,
        },
        reader,
        pid,
    )
}

fn assert_reaped(pid: libc::pid_t) {
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[test]
fn management_readiness_retains_owner_only_after_exact_marker_and_eof() {
    let (owner, reader, pid) = readiness_child("ready");
    let mut owner =
        finish_management_startup(owner, reader, std::time::Duration::from_secs(5)).unwrap();
    assert!(owner.is_running().unwrap());
    owner.stop_and_wait().unwrap();
    assert!(!owner.is_running().unwrap());
    assert_reaped(pid);
}

#[test]
fn management_readiness_failures_kill_and_join_the_child() {
    for action in [
        "wrong",
        "extra",
        "eof",
        "silent",
        "marker-without-eof",
        "exit-before-ready",
    ] {
        let (owner, reader, pid) = readiness_child(action);
        let deadline = if matches!(action, "silent" | "marker-without-eof") {
            std::time::Duration::from_millis(20)
        } else {
            std::time::Duration::from_secs(5)
        };
        assert!(finish_management_startup(owner, reader, deadline).is_err());
        assert_reaped(pid);
    }
}

#[test]
fn export_uses_readonly_noexec_sealed_inode_and_exact_digest() {
    let (p, file) = Publication::export(b"public-only-execution-evidence").unwrap();
    assert_eq!(
        Publication::decode(&p.encode().unwrap())
            .unwrap()
            .read_export(&file)
            .unwrap(),
        b"public-only-execution-evidence"
    );
    let wrong = sealed_public_file(b"foreign-public-evidence", MAX_PUBLIC_EXPORT).unwrap();
    assert!(p.read_export(&wrong).is_err());
    assert!(sealed_public_file(&[], 16).is_err());
    assert!(sealed_public_file(&[0; 17], 16).is_err());
    let unsealed = File::open("/proc/self/exe").unwrap();
    assert!(read_sealed_public(&unsealed, 256 << 20).is_err());
}
#[test]
fn publication_control_domain_reserved_bits_and_descriptor_bounds_are_closed() {
    for kind in [
        PublicationKind::Ready,
        PublicationKind::Unproven,
        PublicationKind::Stop,
    ] {
        let p = Publication::control(kind).unwrap();
        assert_eq!(
            Publication::decode(&p.encode().unwrap()).unwrap().kind,
            kind
        );
    }
    let frame = Publication::control(PublicationKind::Ready)
        .unwrap()
        .encode()
        .unwrap();
    for i in [0, 8, 10, 11, 16, 24] {
        let mut b = frame;
        b[i] ^= 0xff;
        assert!(Publication::decode(&b).is_err());
    }
    assert!(Publication::decode(&frame[..71]).is_err());
    assert!(Publication::control(PublicationKind::Export).is_err());
    assert!(Publication {
        kind: PublicationKind::Export,
        length: (MAX_PUBLIC_EXPORT + 1) as u64,
        sha384: [1; 48]
    }
    .encode()
    .is_err());
}
#[test]
fn file_hash_covers_multiple_chunks_and_requires_exact_size() {
    let mut bytes = vec![0xa5; 8192 + 17];
    bytes[8192] = 0x5a;
    let file = sealed_public_file(&bytes, bytes.len()).unwrap();
    assert_eq!(file_hash(&file, bytes.len() as u64).unwrap(), hash(&bytes));
    assert!(file_hash(&file, bytes.len() as u64 - 1).is_err());
    assert!(file_hash(&file, bytes.len() as u64 + 1).is_err());
}
#[test]
fn ordinary_host_root_cannot_supply_a_trusted_role_view() {
    assert!(load_embedded(Role::Kata).is_err());
    assert!(load_embedded(Role::Preparation).is_err());
}
