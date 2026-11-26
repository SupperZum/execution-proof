use super::*;
use std::{
    io::{Read, Write},
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
enum SignalAt {
    BeforeClaim,
    BeforeWrite,
    AfterWrite,
}

#[test]
fn watchdog_and_publisher_share_one_verdict_and_preserve_pipe_flags() {
    let version = if env!("CARGO_BIN_NAME") == "gcp-execution-proof-verifier" {
        2
    } else {
        1
    };
    let invalid = VerificationError::Invalid("test_input");
    let verdict = if version == 2 {
        invalid.gcp_verdict()
    } else {
        invalid.verdict()
    };
    let mut line = serde_json::to_vec(&verdict).unwrap();
    line.push(b'\n');
    for signal in [libc::SIGALRM, libc::SIGXCPU] {
        for full in [false, true] {
            for phase in [
                SignalAt::BeforeClaim,
                SignalAt::BeforeWrite,
                SignalAt::AfterWrite,
            ] {
                let (mut reader, mut writer) = std::io::pipe().unwrap();
                let fd = writer.as_raw_fd();
                let mut contents = Vec::new();
                if full {
                    let capacity = unsafe { libc::fcntl(fd, libc::F_GETPIPE_SZ) };
                    assert!(capacity > 0);
                    contents.resize(capacity as usize, b'x');
                    writer.write_all(&contents).unwrap();
                }
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                let pid = unsafe { libc::fork() };
                assert!(pid >= 0);
                if pid == 0 {
                    // Use only lock-free atomics and async-signal-safe system calls.
                    unsafe {
                        if libc::dup2(fd, 1) < 0
                            || libc::signal(signal, crate::resource_limit as *const () as usize)
                                == libc::SIG_ERR
                        {
                            libc::_exit(9);
                        }
                        if matches!(phase, SignalAt::BeforeClaim) {
                            libc::raise(signal);
                        }
                        PUBLISHING.store(true, Ordering::Release);
                        if matches!(phase, SignalAt::BeforeWrite) {
                            libc::raise(signal);
                        }
                        let written = write_line(&line);
                        if matches!(phase, SignalAt::AfterWrite) {
                            libc::raise(signal);
                        }
                        libc::_exit(if written { 1 } else { 2 });
                    }
                }
                let deadline = Instant::now() + Duration::from_secs(2);
                let mut status = 0;
                loop {
                    let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                    if result == pid {
                        break;
                    }
                    assert_eq!(result, 0);
                    if Instant::now() >= deadline {
                        unsafe {
                            libc::kill(pid, libc::SIGKILL);
                            libc::waitpid(pid, &mut status, 0);
                        }
                        panic!("verdict publication stalled");
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) }, flags);
                drop(writer);
                let mut output = Vec::new();
                reader.read_to_end(&mut output).unwrap();
                assert!(libc::WIFEXITED(status));
                let watchdog_won = matches!(phase, SignalAt::BeforeClaim);
                assert_eq!(
                    libc::WEXITSTATUS(status),
                    if full || watchdog_won { 2 } else { 1 }
                );
                if full {
                    assert_eq!(output, contents);
                } else {
                    let record: serde_json::Value = serde_json::from_slice(&output).unwrap();
                    assert_eq!(record["version"], version);
                    assert_eq!(
                        record["status"],
                        if watchdog_won { "unproven" } else { "invalid" }
                    );
                    assert_eq!(
                        record["reason"],
                        if watchdog_won {
                            "verifier_resource_limit"
                        } else {
                            "test_input"
                        }
                    );
                }
            }
        }
    }
}
