use super::*;
use std::{
    fs,
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{symlink, PermissionsExt},
    },
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "onb17-gcp-operator-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn pipe() -> (fs::File, fs::File) {
    let mut pair = [-1; 2];
    // SAFETY: two output slots, then unique ownership of both successful FDs.
    assert_eq!(
        unsafe { libc::pipe2(pair.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    unsafe {
        (
            fs::File::from_raw_fd(pair[0]),
            fs::File::from_raw_fd(pair[1]),
        )
    }
}

#[test]
fn private_operator_inputs_reject_links_permissions_and_excess_bytes() {
    let dir = Directory::new();
    let file = dir.0.join("private-key");
    fs::write(&file, b"KEY-SENTINEL-NEVER-PUBLIC").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        read_operator_file(&file, 100, true).unwrap(),
        b"KEY-SENTINEL-NEVER-PUBLIC"
    );
    assert!(read_operator_file(&file, 2, true).is_err());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(read_operator_file(&file, 100, true).is_err());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.0.join("symlink");
    symlink(&file, &link).unwrap();
    assert!(read_operator_file(&link, 100, true).is_err());
    let hard = dir.0.join("hardlink");
    fs::hard_link(&file, &hard).unwrap();
    assert!(read_operator_file(&file, 100, true).is_err());
}
#[test]
fn stdin_deadline_and_eof_are_real_and_restore_descriptor_flags() {
    let (read, mut write) = pipe();
    let before = unsafe { libc::fcntl(read.as_raw_fd(), libc::F_GETFL) };
    assert_eq!(
        read_request(read.as_raw_fd(), Duration::from_millis(20)).unwrap_err(),
        PublicError::IoDeadline
    );
    assert_eq!(
        unsafe { libc::fcntl(read.as_raw_fd(), libc::F_GETFL) },
        before
    );
    write.write_all(b"public-request").unwrap();
    drop(write);
    assert_eq!(
        read_request(read.as_raw_fd(), Duration::from_secs(1)).unwrap(),
        b"public-request"
    );
}
#[test]
fn oversized_stdin_is_rejected_and_writer_is_joined() {
    let (read, mut write) = pipe();
    let worker = std::thread::spawn(move || write.write_all(&vec![b'x'; MAX_REQUEST_BYTES + 1]));
    assert_eq!(
        read_request(read.as_raw_fd(), Duration::from_secs(2)).unwrap_err(),
        PublicError::RequestLimit
    );
    drop(read);
    let _ = worker.join().unwrap();
}
#[test]
fn unconsumed_stdout_has_a_finite_deadline() {
    let (_read, write) = pipe();
    // No reader drains this pipe; bounded output must stop under backpressure.
    assert_eq!(
        write_response(
            write.as_raw_fd(),
            &vec![1; 4 << 20],
            Duration::from_millis(20)
        )
        .unwrap_err(),
        PublicError::IoDeadline
    );
}
#[test]
fn request_schema_cannot_add_operator_paths_or_arbitrary_signing_fields() {
    let mut wire = serde_json::json!({"version":1,"purpose":REQUEST_PURPOSE,"request":{"operation":"begin","signed_intent_json":[1]}});
    assert!(serde_json::from_value::<Request>(wire.clone()).is_ok());
    for field in [
        "signer",
        "worker_path",
        "authority_public_key",
        "signing_bytes",
    ] {
        wire["request"][field] = "untrusted".into();
        assert!(serde_json::from_value::<Request>(wire.clone()).is_err());
        wire["request"].as_object_mut().unwrap().remove(field);
    }
    wire["request"]["operation"] = "init".into();
    assert!(serde_json::from_value::<Request>(wire).is_err());
}
#[test]
fn argument_duplicates_and_out_of_budget_capacity_are_rejected() {
    let good = [
        "request",
        "--config",
        "c",
        "--qualification",
        "q",
        "--signer",
        "s",
        "--store",
        "d",
        "--collateral",
        "a",
        "--capacity",
        "32",
    ];
    assert!(Arguments::parse(good.iter().map(OsString::from)).is_ok());
    let mut duplicate = good.to_vec();
    duplicate.extend(["--config", "other"]);
    assert!(Arguments::parse(duplicate.iter().map(OsString::from)).is_err());
    let mut excess = good;
    excess[12] = "1025";
    assert!(Arguments::parse(excess.iter().map(OsString::from)).is_err());
    assert!(Arguments::parse([OsString::from("reset")].into_iter()).is_err());
}
