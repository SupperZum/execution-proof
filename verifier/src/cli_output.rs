use execution_proof_verifier::{VerificationError, VerificationVerdict};
use std::sync::atomic::{AtomicBool, Ordering};

static PUBLISHING: AtomicBool = AtomicBool::new(false);

// A verdict fits in one pipe buffer. Stage it in a private pipe so splice can
// use per-call nonblocking I/O without changing the caller's stdout flags.
unsafe fn write_line(line: &[u8]) -> bool {
    use libc::STDOUT_FILENO as OUT;
    if line.len() > libc::PIPE_BUF {
        return false;
    }
    let mut stat = std::mem::MaybeUninit::uninit();
    if libc::fstat(OUT, stat.as_mut_ptr()) != 0 {
        return false;
    }
    let len = line.len();
    let ptr = line.as_ptr().cast();
    let count = match stat.assume_init().st_mode & libc::S_IFMT {
        libc::S_IFIFO => {
            let mut pipe = [-1; 2];
            if libc::pipe2(pipe.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) != 0
                || libc::write(pipe[1], ptr, len) != len as isize
            {
                return false;
            }
            // Both descriptors are released by the immediately following _exit.
            libc::splice(
                pipe[0],
                std::ptr::null_mut(),
                OUT,
                std::ptr::null_mut(),
                len,
                libc::SPLICE_F_NONBLOCK,
            )
        }
        libc::S_IFSOCK => libc::send(OUT, ptr, len, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL),
        _ => libc::write(OUT, ptr, len),
    };
    count == len as isize
}

pub fn watchdog(line: &'static [u8]) {
    if !PUBLISHING.swap(true, Ordering::AcqRel) {
        execution_proof_verifier::worker::abort_active_worker();
        unsafe {
            write_line(line);
            libc::_exit(2);
        }
    }
}

pub fn finish(verdict: VerificationVerdict) -> ! {
    let mut line = serde_json::to_vec(&verdict).unwrap_or_else(|_| std::process::exit(3));
    line.push(b'\n');
    let status = match verdict.status() {
        "verified_exec" => 0,
        "invalid" => 1,
        _ => 2,
    };
    if PUBLISHING.swap(true, Ordering::AcqRel) {
        // A watchdog on another thread owns publication and process exit.
        loop {
            unsafe {
                libc::pause();
            }
        }
    }
    unsafe {
        libc::_exit(if write_line(&line) { status } else { 2 });
    }
}

pub fn limits(handler: extern "C" fn(libc::c_int)) -> Result<(), VerificationError> {
    // These process limits are operational watchdogs, not trusted exec time.
    unsafe {
        let mut action = std::mem::zeroed::<libc::sigaction>();
        action.sa_sigaction = handler as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaddset(&mut action.sa_mask, libc::SIGALRM);
        libc::sigaddset(&mut action.sa_mask, libc::SIGXCPU);
        if libc::sigaction(libc::SIGALRM, &action, std::ptr::null_mut()) != 0
            || libc::sigaction(libc::SIGXCPU, &action, std::ptr::null_mut()) != 0
        {
            return Err(VerificationError::BackendUnavailable("watchdog_install"));
        }
        let cpu = libc::rlimit {
            rlim_cur: 10,
            rlim_max: 11,
        };
        let address_space = libc::rlimit {
            rlim_cur: 512 << 20,
            rlim_max: 512 << 20,
        };
        if libc::setrlimit(libc::RLIMIT_CPU, &cpu) != 0
            || libc::setrlimit(libc::RLIMIT_AS, &address_space) != 0
        {
            return Err(VerificationError::BackendUnavailable("process_limits"));
        }
        libc::alarm(30);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
