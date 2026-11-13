use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static PROCESS_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn pinned(path: &str) -> TrustedWorker {
    let path = std::fs::canonicalize(path).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    TrustedWorker::open(&path, &crate::hash(&bytes)).unwrap()
}

#[test]
fn incorrect_worker_commitment_cannot_execute() {
    let path = std::fs::canonicalize("/bin/cat").unwrap();
    assert_eq!(
        TrustedWorker::open(&path, &"00".repeat(48)).err(),
        Some(WorkerError::InvalidBinary)
    );
}

#[test]
fn sealed_worker_survives_original_file_replacement() {
    let _serial = PROCESS_TEST.lock().unwrap();
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "onb17-pinned-worker-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let bytes = std::fs::read("/bin/cat").unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(&bytes).unwrap();
    drop(file);
    let worker = TrustedWorker::open(&path, &crate::hash(&bytes)).unwrap();
    std::fs::write(&path, b"replaced after pinning").unwrap();
    std::fs::remove_file(path).unwrap();
    assert_eq!(
        run_bounded(&worker, b"sealed bytes", Duration::from_secs(2)).unwrap(),
        b"sealed bytes"
    );
}

#[test]
fn stdout_flood_is_bounded_even_when_the_worker_ignores_stdin() {
    let _serial = PROCESS_TEST.lock().unwrap();
    assert_eq!(
        run_bounded(
            &pinned("/usr/bin/yes"),
            &vec![0; 1 << 20],
            Duration::from_secs(2)
        ),
        Err(WorkerError::TooLarge)
    );
}

#[test]
fn silent_worker_is_killed_and_reaped_at_the_elapsed_deadline() {
    let _serial = PROCESS_TEST.lock().unwrap();
    assert_eq!(
        run_bounded(
            &pinned("/bin/sh"),
            b"exec /bin/sleep 5\n",
            Duration::from_millis(50)
        ),
        Err(WorkerError::Deadline)
    );
}

#[test]
fn worker_runs_with_cpu_and_address_space_limits() {
    let _serial = PROCESS_TEST.lock().unwrap();
    assert_eq!(
        run_bounded(
            &pinned("/bin/sh"),
            b"ulimit -t\nulimit -v\n",
            Duration::from_secs(2)
        )
        .unwrap(),
        b"10\n524288\n"
    );
}

#[test]
fn worker_cannot_open_a_collateral_network_socket() {
    let _serial = PROCESS_TEST.lock().unwrap();
    assert_eq!(
        run_bounded(
            &pinned("/usr/bin/python3"),
            b"import socket\ntry:\n socket.socket()\nexcept PermissionError:\n print('network-denied')\n",
            Duration::from_secs(2)
        ).unwrap(),
        b"network-denied\n"
    );
}

#[test]
fn worker_process_creation_is_denied() {
    let _serial = PROCESS_TEST.lock().unwrap();
    assert_eq!(
        run_bounded(
            &pinned("/usr/bin/python3"),
            b"import os\ntry:\n p=os.fork()\nexcept PermissionError:\n print('fork-denied')\nelse:\n if p==0: os._exit(0)\n os.waitpid(p,0)\n print('fork-allowed')\n",
            Duration::from_secs(2)
        ).unwrap(),
        b"fork-denied\n"
    );
}

#[test]
fn verifier_threads_still_share_the_limited_process() {
    let _serial = PROCESS_TEST.lock().unwrap();
    assert_eq!(
        run_bounded(
            &pinned("/usr/bin/python3"),
            b"import threading\nt=threading.Thread(target=lambda: print('thread-ok'))\nt.start()\nt.join()\n",
            Duration::from_secs(2)
        ).unwrap(),
        b"thread-ok\n"
    );
}
