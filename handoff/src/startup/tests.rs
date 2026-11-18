use super::*;
use std::os::fd::AsFd;

fn bootstrap(role: Role) -> Bootstrap {
    Bootstrap {
        role,
        nonce: [1; 32],
        boot: [2; 48],
        preparation: [3; 48],
        kata: [4; 48],
    }
}
fn expected(role: Role) -> ExpectedStartup {
    let boot = bootstrap(role);
    ExpectedStartup {
        role,
        boot_config_sha384: boot.boot,
        own_executable_sha384: *boot.own(),
        peer_executable_sha384: *boot.peer(),
    }
}
fn source(bytes: &[u8]) -> File {
    let file = memfd(false).unwrap();
    file.write_all_at(bytes, 0).unwrap();
    file
}

#[test]
fn inherited_locations_are_bounded_canonical_distinct_nonstdio_metadata() {
    assert_eq!(inherited_locations(b"128:129"), Ok((128, 129)));
    for invalid in [
        b"".as_slice(),
        b"3:4",
        b"127:128",
        b"128:128",
        b"0128:129",
        b"128:+129",
        b"128: 129",
        b"128:129:130",
        b"128:129\0",
        b"2147483648:129",
        b"128:2147483647",
        b"11111111111111111111111111111111",
    ] {
        assert_eq!(
            inherited_locations(invalid),
            Err(StartupError::MissingInherited),
            "{invalid:?}"
        );
    }
}

#[test]
fn parent_reserves_distinct_cloexec_aliases_before_command_can_allocate() {
    let original = source(b"descriptor fixture");
    let first = reserve_inherited(&original).unwrap();
    let second = reserve_inherited(&original).unwrap();
    assert!(first.as_raw_fd() >= MIN_INHERITED_FD);
    assert!(second.as_raw_fd() > first.as_raw_fd());
    for reserved in [first, second] {
        assert_eq!(
            unsafe { libc::fcntl(reserved.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            libc::FD_CLOEXEC
        );
    }
    assert_eq!(original.metadata().unwrap().len(), 18);
}

#[test]
fn startup_bootstrap_has_one_strict_bounded_frame() {
    let wire = bootstrap(Role::Preparation).encode(1);
    assert_eq!(Bootstrap::decode(&wire).unwrap().encode(1), wire);
    for len in 0..WIRE_BYTES {
        assert!(Bootstrap::decode(&wire[..len]).is_err());
    }
    let mut extra = wire.to_vec();
    extra.push(0);
    assert!(Bootstrap::decode(&extra).is_err());
    for offset in [0, 8, 10, 11, 12, 15] {
        let mut changed = wire;
        changed[offset] ^= 0x80;
        assert!(Bootstrap::decode(&changed).is_err(), "{offset}");
    }
    let mut no_nonce = wire;
    no_nonce[16..48].fill(0);
    assert!(Bootstrap::decode(&no_nonce).is_err());
}

#[test]
fn bootstrap_requires_strong_noexec_seals_and_exact_length() {
    for case in 0..4 {
        let mut bytes = bootstrap(Role::Preparation).encode(1).to_vec();
        if case == 1 {
            bytes.push(0);
        }
        let file = if case == 2 {
            memfd(true).unwrap()
        } else {
            memfd(false).unwrap()
        };
        file.write_all_at(&bytes, 0).unwrap();
        if case != 0 {
            seal(&file, if case == 2 { 0o500 } else { 0o600 }).unwrap();
        }
        let result = read_bootstrap(file.into());
        if case == 3 {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(StartupError::InvalidBootstrap)));
        }
    }
}

#[test]
fn native_role_snapshot_checks_size_format_digest_and_inode_seals() {
    let bytes = b"\x7fELFtrusted-role-fixture";
    let hash = digest::digest(&digest::SHA384, bytes)
        .as_ref()
        .try_into()
        .unwrap();
    let pinned = PinnedRoleExecutable::new(source(bytes), hash, 4096).unwrap();
    assert_eq!(pinned.sha384(), &hash);
    assert_eq!(
        unsafe { libc::fcntl(pinned.file.as_raw_fd(), libc::F_GET_SEALS) } & CONTENT_SEALS,
        CONTENT_SEALS
    );
    assert_eq!(pinned.file.metadata().unwrap().mode() & 0o777, 0o500);
    assert_eq!(
        unsafe { libc::fcntl(pinned.file.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE,
        libc::O_RDONLY
    );
    assert!(matches!(
        PinnedRoleExecutable::new(source(bytes), [0; 48], 4096),
        Err(StartupError::ArtifactMismatch)
    ));
    assert!(matches!(
        PinnedRoleExecutable::new(source(bytes), hash, 1),
        Err(StartupError::InvalidExecutable)
    ));
    assert!(matches!(
        PinnedRoleExecutable::new(source(bytes), hash, 0),
        Err(StartupError::InvalidLimit)
    ));
    assert!(matches!(
        PinnedRoleExecutable::new(source(b"#!/bin/sh\n"), [0; 48], 4096),
        Err(StartupError::InvalidExecutable)
    ));
    assert!(pinned.file.write_all_at(b"x", 0).is_err());
}

#[test]
fn startup_rejects_regular_stream_unconnected_and_blocking_descriptors() {
    let file = source(b"not a socket");
    assert!(validate_socket(&file.into()).is_err());
    for kind in [libc::SOCK_STREAM, libc::SOCK_DGRAM] {
        let mut pair = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    kind | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    0,
                    pair.as_mut_ptr(),
                )
            },
            0
        );
        let first = unsafe { OwnedFd::from_raw_fd(pair[0]) };
        let _second = unsafe { OwnedFd::from_raw_fd(pair[1]) };
        assert_eq!(validate_socket(&first), Err(StartupError::InvalidSocket));
    }
    let (first, _second) = PrivateFdChannel::pair().unwrap();
    let fd = first.into_startup_fd().unwrap();
    assert_eq!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, 0) }, 0);
    assert_eq!(validate_socket(&fd), Err(StartupError::InvalidSocket));
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    assert!(raw >= 0);
    let unconnected = unsafe { OwnedFd::from_raw_fd(raw) };
    assert_eq!(
        validate_socket(&unconnected),
        Err(StartupError::InvalidSocket)
    );
}

#[test]
fn independently_expected_role_boot_and_artifacts_are_required() {
    for case in 0..4 {
        let (first, _second) = PrivateFdChannel::pair().unwrap();
        let mut configuration = expected(Role::Preparation);
        match case {
            0 => configuration.role = Role::Kata,
            1 => configuration.boot_config_sha384[0] ^= 1,
            2 => configuration.own_executable_sha384[0] ^= 1,
            _ => configuration.peer_executable_sha384[0] ^= 1,
        }
        let result = StartupBoundChannel::accept_descriptors(
            first.into_startup_fd().unwrap(),
            make_ticket(&bootstrap(Role::Preparation)).unwrap().into(),
            configuration,
            Duration::from_secs(1),
        );
        assert!(
            matches!(result, Err(StartupError::BindingMismatch)),
            "{case}"
        );
    }
}

#[test]
fn private_role_handshake_mints_matching_boot_binding_and_preserves_transport() {
    let (first, second) = PrivateFdChannel::pair().unwrap();
    let prep_ticket = make_ticket(&bootstrap(Role::Preparation)).unwrap();
    let kata_ticket = make_ticket(&bootstrap(Role::Kata)).unwrap();
    let join = std::thread::spawn(move || {
        StartupBoundChannel::accept_descriptors(
            first.into_startup_fd().unwrap(),
            prep_ticket.into(),
            expected(Role::Preparation),
            Duration::from_secs(2),
        )
        .unwrap()
    });
    let mut kata = StartupBoundChannel::accept_descriptors(
        second.into_startup_fd().unwrap(),
        kata_ticket.into(),
        expected(Role::Kata),
        Duration::from_secs(2),
    )
    .unwrap();
    let mut preparation = join.join().unwrap();
    assert_eq!(preparation.binding_commitment(), kata.binding_commitment());
    assert_eq!(preparation.role(), Role::Preparation);
    assert_eq!(kata.role(), Role::Kata);
    assert_eq!(preparation.boot_config_sha384(), &[2; 48]);
    assert_eq!(kata.channel_nonce(), &[1; 32]);
    let data = source(b"descriptor");
    assert_eq!(
        preparation.try_send(b"offer", Some(data.as_fd())),
        Ok(SendOutcome::Sent)
    );
    let (payload, received) = kata
        .try_receive(FdExpectation::One)
        .unwrap()
        .unwrap()
        .into_parts();
    assert_eq!(payload, b"offer");
    assert!(received.is_some());
}

#[test]
fn wrong_peer_bootstrap_and_extra_descriptor_do_not_mint_a_binding() {
    for with_descriptor in [false, true] {
        let (first, mut second) = PrivateFdChannel::pair().unwrap();
        let mut wrong = bootstrap(Role::Kata).encode(2);
        wrong[16] ^= 1;
        let descriptor = source(b"unexpected");
        assert_eq!(
            second.try_send(&wrong, with_descriptor.then(|| descriptor.as_fd())),
            Ok(SendOutcome::Sent)
        );
        let result = StartupBoundChannel::accept_descriptors(
            first.into_startup_fd().unwrap(),
            make_ticket(&bootstrap(Role::Preparation)).unwrap().into(),
            expected(Role::Preparation),
            Duration::from_secs(1),
        );
        assert!(matches!(
            result,
            Err(StartupError::PeerMismatch | StartupError::Transport(_))
        ));
    }
}

#[test]
fn role_handshake_has_deadline_and_peer_exit_is_terminal() {
    let (first, second) = PrivateFdChannel::pair().unwrap();
    let result = StartupBoundChannel::accept_descriptors(
        first.into_startup_fd().unwrap(),
        make_ticket(&bootstrap(Role::Preparation)).unwrap().into(),
        expected(Role::Preparation),
        Duration::from_millis(5),
    );
    assert!(matches!(result, Err(StartupError::Deadline)));
    drop(second);
    let (first, second) = PrivateFdChannel::pair().unwrap();
    drop(second);
    let result = StartupBoundChannel::accept_descriptors(
        first.into_startup_fd().unwrap(),
        make_ticket(&bootstrap(Role::Preparation)).unwrap().into(),
        expected(Role::Preparation),
        Duration::from_secs(1),
    );
    assert!(matches!(result, Err(StartupError::Transport(_))));
    assert_eq!(deadline(Duration::ZERO), Err(StartupError::InvalidLimit));
}

#[test]
fn role_arguments_are_bounded_and_do_not_use_a_shell() {
    let bytes = b"\x7fELFtrusted-role-fixture";
    let hash = digest::digest(&digest::SHA384, bytes)
        .as_ref()
        .try_into()
        .unwrap();
    let pinned = || PinnedRoleExecutable::new(source(bytes), hash, 4096).unwrap();
    assert!(RoleCommand::new(pinned(), vec![OsString::from("$(not-a-shell)")]).is_ok());
    assert!(matches!(
        RoleCommand::new(pinned(), vec![OsString::from("arg"); 65]),
        Err(StartupError::InvalidArguments)
    ));
    assert!(matches!(
        RoleCommand::new(pinned(), vec![OsString::from("a".repeat(16385))]),
        Err(StartupError::InvalidArguments)
    ));
}

#[test]
fn hosted_preparation_checks_actual_self_identity_and_bounds_before_spawning() {
    let bytes = b"\x7fELFtrusted-role-fixture";
    let hash = digest::digest(&digest::SHA384, bytes)
        .as_ref()
        .try_into()
        .unwrap();
    let role = || {
        RoleCommand::new(
            PinnedRoleExecutable::new(source(bytes), hash, 4096).unwrap(),
            Vec::new(),
        )
        .unwrap()
    };
    assert!(matches!(
        launch_kata_role(role(), [0; 48], 128 << 20, [2; 48], Duration::from_secs(2),),
        Err(StartupError::ArtifactMismatch)
    ));
    assert!(matches!(
        launch_kata_role(role(), [0; 48], 0, [2; 48], Duration::from_secs(2),),
        Err(StartupError::InvalidLimit)
    ));
    assert!(matches!(
        launch_kata_role(role(), [0; 48], 1, [2; 48], Duration::from_secs(2),),
        Err(StartupError::InvalidExecutable)
    ));
}
