use super::*;
use std::{
    io::Write,
    os::{
        fd::OwnedFd,
        unix::{fs::PermissionsExt, net::UnixStream},
    },
};

fn input(bytes: &[u8], eof: bool) -> std::fs::File {
    let (reader, mut writer) = UnixStream::pair().unwrap();
    writer.write_all(bytes).unwrap();
    if !eof {
        // A separate test holds its writer rather than this helper.
        panic!("input helper requires EOF");
    }
    drop(writer);
    OwnedFd::from(reader).into()
}
fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut v = (bytes.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(bytes);
    v
}
#[test]
fn private_frame_requires_exact_bounded_body_and_eof() {
    let bytes = b"test-only-opaque-private-input";
    assert_eq!(
        &*framed_credential(input(&frame(bytes), true), Duration::from_secs(1)).unwrap(),
        bytes
    );
    let mut trailing = frame(bytes);
    trailing.push(1);
    for bad in [
        trailing,
        vec![0; 4],
        (65537u32).to_be_bytes().to_vec(),
        vec![0, 0, 0, 4, 1],
    ] {
        assert!(framed_credential(input(&bad, true), Duration::from_secs(1)).is_err());
    }
    let file = tempfile::tempfile().unwrap();
    assert!(framed_credential(file, Duration::from_secs(1)).is_err());
}
#[test]
fn private_frame_no_eof_has_one_absolute_deadline() {
    let (reader, mut writer) = UnixStream::pair().unwrap();
    writer.write_all(&frame(b"private-input")).unwrap();
    let start = Instant::now();
    assert!(framed_credential(OwnedFd::from(reader).into(), Duration::from_millis(20)).is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
    drop(writer);
}
fn memfd(bytes: &[u8], readonly: bool, seal: bool) -> i32 {
    let name = c"test-credential";
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    assert!(fd >= 0);
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    f.write_all(bytes).unwrap();
    if seal {
        assert_eq!(
            unsafe {
                libc::fcntl(
                    fd,
                    libc::F_ADD_SEALS,
                    libc::F_SEAL_WRITE
                        | libc::F_SEAL_GROW
                        | libc::F_SEAL_SHRINK
                        | libc::F_SEAL_SEAL,
                )
            },
            0
        );
    }
    let file = if readonly {
        OpenOptions::new()
            .read(true)
            .open(format!("/proc/self/fd/{fd}"))
            .unwrap()
    } else {
        f
    };
    let high = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 128) };
    assert!(high >= 128);
    high
}
#[test]
fn inherited_private_fd_is_sealed_readonly_owned_and_closed() {
    for (readonly, seal, ok) in [
        (true, true, true),
        (true, false, false),
        (false, true, false),
    ] {
        let fd = memfd(b"private-input", readonly, seal);
        let result = unsafe { take_credential_fd(fd) };
        assert_eq!(result.is_ok(), ok);
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    }
    assert!(unsafe { take_credential_fd(3) }.is_err());
}
#[test]
fn operator_files_reject_symlink_shared_writable_and_oversize() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("private");
    std::fs::write(&path, b"private-test-input").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(operator_file(&path, 32, true).is_ok());
    assert!(operator_file(&path, 2, true).is_err());
    let link = root.path().join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(operator_file(&link, 32, true).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(operator_file(&path, 32, true).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(operator_file(&path, 32, false).is_err());
}
#[test]
fn credential_requires_real_rsa_key_and_exact_selected_identity() {
    let key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let pem = Zeroizing::new(key.private_key_to_pem_pkcs8().unwrap());
    let mut credential = serde_json::json!({"type":"service_account","project_id":"test-project","private_key_id":"11".repeat(20),"private_key":std::str::from_utf8(&pem).unwrap(),"client_email":"test@test-project.iam.gserviceaccount.com","client_id":"123456789012345678901","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_x509_cert_url":"https://www.googleapis.com/robot/v1/metadata/x509/test","universe_domain":"googleapis.com"});
    let encoded = Zeroizing::new(serde_json::to_vec(&credential).unwrap());
    assert!(validate_credential(
        &encoded,
        "test-project",
        "test@test-project.iam.gserviceaccount.com"
    )
    .is_ok());
    assert!(validate_credential(
        &encoded,
        "other-project",
        "test@test-project.iam.gserviceaccount.com"
    )
    .is_err());
    credential["token_uri"] = "https://attacker.invalid/token".into();
    assert!(validate_credential(
        &serde_json::to_vec(&credential).unwrap(),
        "test-project",
        "test@test-project.iam.gserviceaccount.com"
    )
    .is_err());
    credential["private_key"] = "not-a-key".into();
    assert!(validate_credential(
        &serde_json::to_vec(&credential).unwrap(),
        "test-project",
        "test@test-project.iam.gserviceaccount.com"
    )
    .is_err());
    // This whole object is cfg(test) only and contains no cloud credential.
}
