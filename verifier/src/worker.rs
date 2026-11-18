//! A pinned local verifier process with bounded input, output and resources.

use crate::protocol::{
    TdxWorkerRequest, TdxWorkerResponse, MAX_WORKER_REQUEST_BYTES, MAX_WORKER_RESPONSE_BYTES,
};
use ring::digest::{Context, SHA384};
use std::{
    ffi::OsString,
    fmt,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{fs::OpenOptionsExt, process::CommandExt},
    },
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicBool, AtomicI32, Ordering},
    time::{Duration, Instant},
};

const MAX_BINARY_BYTES: u64 = 256 << 20;
const MAX_STDERR_BYTES: usize = 16 << 10;
const ELAPSED_LIMIT: Duration = Duration::from_secs(30);
const ADDRESS_SPACE_LIMIT: libc::rlim_t = 512 << 20;
static ACTIVE_WORKER: AtomicI32 = AtomicI32::new(0);
static ACTIVE_OWNER_THREAD: AtomicI32 = AtomicI32::new(0);
static WORKER_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

const fn instruction(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}
// x86_64 native syscalls only; closed inherited descriptors plus denial of
// socket creation/connect prevent collateral retrieval through the network.
// Threads share the process's CPU/AS limits; new processes cannot reset them.
static OFFLINE_FILTER: [libc::sock_filter; 32] = [
    instruction(0x20, 4, 0, 0),
    instruction(0x15, 0xc000003e, 1, 0),
    instruction(0x06, 0x80000000, 0, 0),
    instruction(0x20, 0, 0, 0),
    instruction(0x45, 0x40000000, 0, 1),
    instruction(0x06, 0x00050000 | libc::EPERM as u32, 0, 0),
    instruction(0x15, libc::SYS_socket as u32, 0, 1),
    instruction(0x06, 0x00050000 | libc::EPERM as u32, 0, 0),
    instruction(0x15, libc::SYS_socketpair as u32, 0, 1),
    instruction(0x06, 0x00050000 | libc::EPERM as u32, 0, 0),
    instruction(0x15, libc::SYS_connect as u32, 0, 1),
    instruction(0x06, 0x00050000 | libc::EPERM as u32, 0, 0),
    instruction(0x15, libc::SYS_fork as u32, 0, 1),
    instruction(0x06, 0x00050000 | libc::EPERM as u32, 0, 0),
    instruction(0x15, libc::SYS_vfork as u32, 0, 1),
    instruction(0x06, 0x00050000 | libc::EPERM as u32, 0, 0),
    // libc can fall back from clone3 to clone for pthread creation.
    instruction(0x15, libc::SYS_clone3 as u32, 0, 1),
    instruction(0x06, 0x00050000 | libc::ENOSYS as u32, 0, 0),
    instruction(0x15, libc::SYS_setsid as u32, 0, 1),
    instruction(0x06, 0x00050000 | libc::EPERM as u32, 0, 0),
    instruction(0x15, libc::SYS_setpgid as u32, 0, 1),
    instruction(0x06, 0x00050000 | libc::EPERM as u32, 0, 0),
    instruction(0x15, libc::SYS_prctl as u32, 0, 4),
    instruction(0x20, 16, 0, 0),
    instruction(0x15, libc::PR_SET_PDEATHSIG as u32, 0, 1),
    instruction(0x06, 0x00050000 | libc::EPERM as u32, 0, 0),
    instruction(0x06, 0x7fff0000, 0, 0),
    instruction(0x15, libc::SYS_clone as u32, 0, 3),
    instruction(0x20, 16, 0, 0),
    instruction(0x45, libc::CLONE_THREAD as u32, 1, 0),
    instruction(0x06, 0x00050000 | libc::EPERM as u32, 0, 0),
    instruction(0x06, 0x7fff0000, 0, 0),
];

struct WorkerPermit;
impl WorkerPermit {
    fn acquire() -> Result<Self, WorkerError> {
        WORKER_IN_FLIGHT
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| WorkerError::Busy)?;
        Ok(Self)
    }
}
impl Drop for WorkerPermit {
    fn drop(&mut self) {
        WORKER_IN_FLIGHT.store(false, Ordering::Release);
    }
}

/// Used by the CLI's process watchdog on the thread owning the worker.
/// Calls from other threads do nothing, avoiding stale process-group IDs while
/// the owner reaps. Only lock-free loads and direct syscalls run here.
pub fn abort_active_worker() {
    let thread = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
    if ACTIVE_OWNER_THREAD.load(Ordering::Acquire) != thread {
        return;
    }
    let pid = ACTIVE_WORKER.load(Ordering::Acquire);
    if pid > 0 {
        unsafe { libc::kill(-pid, libc::SIGKILL) };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerError {
    InvalidBinary,
    Io,
    TooLarge,
    Deadline,
    NonzeroExit,
    InvalidRequest,
    InvalidResponse,
    Busy,
    ResourceLimit,
}

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "local TDX verifier rejected: {self:?}")
    }
}
impl std::error::Error for WorkerError {}

/// Selected from relying-party configuration, never from an evidence pack.
/// The sealed executable copy closes the hash-to-exec replacement window.
pub struct TrustedWorker {
    executable: File,
    executable_path: OsString,
    process_budget: bool,
}

impl TrustedWorker {
    pub fn open(path: &Path, expected_sha384: &str) -> Result<Self, WorkerError> {
        if expected_sha384.len() != 96
            || !expected_sha384
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(WorkerError::InvalidBinary);
        }
        let mut source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| WorkerError::InvalidBinary)?;
        let metadata = source.metadata().map_err(|_| WorkerError::Io)?;
        if !metadata.is_file() || !(4..=MAX_BINARY_BYTES).contains(&metadata.len()) {
            return Err(WorkerError::InvalidBinary);
        }
        // MFD_EXEC is explicit: a host configured to disallow executable
        // memfds rejects this worker rather than selecting a path fallback.
        let raw = unsafe {
            libc::memfd_create(
                c"onb17-tdx-verifier".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | 0x0010,
            )
        };
        if raw < 0 {
            return Err(WorkerError::Io);
        }
        // SAFETY: the successful syscall returned one new owned descriptor.
        let original = unsafe { File::from_raw_fd(raw) };
        let alias = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 128) };
        if alias < 0 {
            return Err(WorkerError::Io);
        }
        // Keep it clear of stdio descriptors even in callers with closed IO.
        let mut executable = unsafe { File::from_raw_fd(alias) };
        drop(original);
        let mut hash = Context::new(&SHA384);
        let mut buffer = [0u8; 8192];
        let mut total = 0u64;
        loop {
            let n = source.read(&mut buffer).map_err(|_| WorkerError::Io)?;
            if n == 0 {
                break;
            }
            if total == 0 && (n < 4 || &buffer[..4] != b"\x7fELF") {
                return Err(WorkerError::InvalidBinary);
            }
            total = total.checked_add(n as u64).ok_or(WorkerError::TooLarge)?;
            if total > MAX_BINARY_BYTES {
                return Err(WorkerError::TooLarge);
            }
            hash.update(&buffer[..n]);
            executable
                .write_all(&buffer[..n])
                .map_err(|_| WorkerError::Io)?;
        }
        let actual = hash
            .finish()
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        if total != metadata.len() || actual != expected_sha384 {
            return Err(WorkerError::InvalidBinary);
        }
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        if unsafe { libc::fcntl(executable.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
            return Err(WorkerError::Io);
        }
        let executable_path = OsString::from(format!("/proc/self/fd/{}", executable.as_raw_fd()));
        Ok(Self {
            executable,
            executable_path,
            process_budget: false,
        })
    }

    /// The CLI has one pack per process. Count its parsing and signature work
    /// against the same CPU/RAM budget as the native verifier subprocess.
    pub fn with_process_budget(mut self) -> Self {
        self.process_budget = true;
        self
    }
}

struct OwnedChild {
    child: Child,
    reaped: bool,
}

impl OwnedChild {
    fn finish(&mut self) -> Result<ExitStatus, WorkerError> {
        // waitid below has not reaped the leader, so this process-group ID
        // cannot have been recycled. Terminate any remaining worker children.
        unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
        ACTIVE_OWNER_THREAD.store(0, Ordering::Release);
        let _ = ACTIVE_WORKER.compare_exchange(
            self.child.id() as i32,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        let status = self.child.wait().map_err(|_| WorkerError::Io)?;
        self.reaped = true;
        Ok(status)
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reaped {
            unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
            ACTIVE_OWNER_THREAD.store(0, Ordering::Release);
            let _ = ACTIVE_WORKER.compare_exchange(
                self.child.id() as i32,
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct BlockWatchdogs(libc::sigset_t);
impl BlockWatchdogs {
    fn new() -> Result<Self, WorkerError> {
        let mut signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        let mut old = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        unsafe {
            libc::sigemptyset(&mut signals);
            libc::sigaddset(&mut signals, libc::SIGALRM);
            libc::sigaddset(&mut signals, libc::SIGXCPU);
            if libc::pthread_sigmask(libc::SIG_BLOCK, &signals, &mut old) != 0 {
                return Err(WorkerError::Io);
            }
        }
        Ok(Self(old))
    }
}
impl Drop for BlockWatchdogs {
    fn drop(&mut self) {
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut()) };
    }
}

fn usage(who: i32) -> Result<(f64, u64), WorkerError> {
    let mut value = unsafe { std::mem::zeroed::<libc::rusage>() };
    if unsafe { libc::getrusage(who, &mut value) } != 0 {
        return Err(WorkerError::Io);
    }
    let seconds = value.ru_utime.tv_sec as f64
        + value.ru_stime.tv_sec as f64
        + (value.ru_utime.tv_usec + value.ru_stime.tv_usec) as f64 / 1_000_000.0;
    Ok((seconds, value.ru_maxrss.max(0) as u64 * 1024))
}

fn child_cpu(pid: u32) -> Result<f64, WorkerError> {
    let bytes =
        std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|_| WorkerError::Io)?;
    let tail = bytes.rsplit_once(')').ok_or(WorkerError::Io)?.1;
    let fields: Vec<_> = tail.split_ascii_whitespace().collect();
    let utime = fields
        .get(11)
        .ok_or(WorkerError::Io)?
        .parse::<u64>()
        .map_err(|_| WorkerError::Io)?;
    let stime = fields
        .get(12)
        .ok_or(WorkerError::Io)?
        .parse::<u64>()
        .map_err(|_| WorkerError::Io)?;
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks <= 0 {
        return Err(WorkerError::Io);
    }
    Ok((utime.saturating_add(stime)) as f64 / ticks as f64)
}

fn nonblocking(fd: i32) -> Result<(), WorkerError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(WorkerError::Io);
    }
    Ok(())
}

fn drain(reader: &mut impl Read, bytes: &mut Vec<u8>, maximum: usize) -> Result<bool, WorkerError> {
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                if n > maximum.saturating_sub(bytes.len()) {
                    return Err(WorkerError::TooLarge);
                }
                bytes.extend_from_slice(&buffer[..n]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(WorkerError::Io),
        }
    }
}

fn exited_without_reaping(pid: u32) -> Result<bool, WorkerError> {
    // SAFETY: initialized siginfo is a valid writable syscall result. WNOWAIT
    // preserves the leader and its PID until OwnedChild finishes the group.
    let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(WorkerError::Io);
    }
    Ok(unsafe { info.si_pid() } != 0)
}

/// The returned response remains data. Only the graph verifier can turn it
/// into a verdict after checking the exact request and relying-party policy.
pub fn run_worker(
    request: &TdxWorkerRequest,
    worker: &TrustedWorker,
) -> Result<TdxWorkerResponse, WorkerError> {
    let input = request.encode().map_err(|_| WorkerError::InvalidRequest)?;
    if input.len() > MAX_WORKER_REQUEST_BYTES {
        return Err(WorkerError::TooLarge);
    }
    let output = run_bounded(worker, &input, ELAPSED_LIMIT)?;
    TdxWorkerResponse::decode(&output).map_err(|_| WorkerError::InvalidResponse)
}

/// GCP hardware facts use the same pinned executable, process ownership and
/// no-network budgets as the legacy worker, with a distinct wire protocol.
/// No execution verdict or producer qualification is minted here.
pub fn run_gcp_worker(
    request: &crate::gcp_worker_protocol::GcpHardwareRequest,
    worker: &TrustedWorker,
) -> Result<crate::gcp_worker_protocol::GcpHardwareResponse, WorkerError> {
    let input = request.encode().map_err(|_| WorkerError::InvalidRequest)?;
    if input.len() > MAX_WORKER_REQUEST_BYTES {
        return Err(WorkerError::TooLarge);
    }
    let output = run_bounded(worker, &input, ELAPSED_LIMIT)?;
    let response = crate::gcp_worker_protocol::GcpHardwareResponse::decode(&output)
        .map_err(|_| WorkerError::InvalidResponse)?;
    response
        .check_request(request)
        .map_err(|_| WorkerError::InvalidResponse)?;
    Ok(response)
}

/// Pre-grant requests have a separate domain and never decode as post-exec R.
pub fn run_gcp_pregrant_worker(
    request: &crate::gcp_pregrant_protocol::GcpPregrantRequest,
    worker: &TrustedWorker,
) -> Result<crate::gcp_pregrant_protocol::GcpPregrantResponse, WorkerError> {
    let input = request.encode().map_err(|_| WorkerError::InvalidRequest)?;
    if input.len() > MAX_WORKER_REQUEST_BYTES {
        return Err(WorkerError::TooLarge);
    }
    let output = run_bounded(worker, &input, ELAPSED_LIMIT)?;
    let response = crate::gcp_pregrant_protocol::GcpPregrantResponse::decode(&output)
        .map_err(|_| WorkerError::InvalidResponse)?;
    response
        .check_request(request)
        .map_err(|_| WorkerError::InvalidResponse)?;
    Ok(response)
}

/// Historical bootstrap checking cannot issue a fresh grant. The request and
/// response domains are distinct from the issuer's live pre-grant worker.
pub fn run_gcp_bootstrap_history_worker(
    request: &crate::gcp_bootstrap_history::GcpBootstrapHistoryRequest,
    worker: &TrustedWorker,
) -> Result<crate::gcp_bootstrap_history::GcpBootstrapHistoryResponse, WorkerError> {
    let input = request.encode().map_err(|_| WorkerError::InvalidRequest)?;
    if input.len() > MAX_WORKER_REQUEST_BYTES {
        return Err(WorkerError::TooLarge);
    }
    let output = run_bounded(worker, &input, ELAPSED_LIMIT)?;
    let response = crate::gcp_bootstrap_history::GcpBootstrapHistoryResponse::decode(&output)
        .map_err(|_| WorkerError::InvalidResponse)?;
    response
        .check_request(request)
        .map_err(|_| WorkerError::InvalidResponse)?;
    Ok(response)
}

pub fn verify_with_worker(
    graph: crate::ValidatedGraph,
    worker: &TrustedWorker,
) -> Result<crate::VerificationVerdict, crate::VerificationError> {
    use crate::VerificationError;
    let request = graph.worker_request()?;
    let response = run_worker(&request, worker).map_err(|error| match error {
        WorkerError::TooLarge | WorkerError::ResourceLimit => {
            VerificationError::ResourceLimit("tdx_worker_resource_limit")
        }
        WorkerError::InvalidRequest | WorkerError::InvalidResponse => {
            VerificationError::Invalid("tdx_worker_protocol")
        }
        WorkerError::Deadline => VerificationError::BackendUnavailable("tdx_worker_deadline"),
        _ => VerificationError::BackendUnavailable("tdx_worker_unavailable"),
    })?;
    graph.apply_worker_response(response)
}

fn run_bounded(
    worker: &TrustedWorker,
    input: &[u8],
    elapsed: Duration,
) -> Result<Vec<u8>, WorkerError> {
    let _permit = WorkerPermit::acquire()?;
    if !cfg!(target_arch = "x86_64") {
        return Err(WorkerError::InvalidBinary);
    }
    let deadline = Instant::now()
        .checked_add(elapsed)
        .ok_or(WorkerError::Deadline)?;
    let creator_pid = unsafe { libc::getpid() };
    let (parent_cpu, parent_ram) = if worker.process_budget {
        usage(libc::RUSAGE_SELF)?
    } else {
        (0.0, 0)
    };
    if parent_cpu >= 10.0 || parent_ram >= ADDRESS_SPACE_LIMIT {
        return Err(WorkerError::ResourceLimit);
    }
    let child_cpu_limit = (10.0 - parent_cpu).ceil() as libc::rlim_t;
    let child_memory_limit = ADDRESS_SPACE_LIMIT - parent_ram;
    let children_cpu_before = usage(libc::RUSAGE_CHILDREN)?.0;
    let blocked = BlockWatchdogs::new()?;
    let original_mask = blocked.0;
    // Retain the descriptor until the child has resolved its sealed executable.
    let _executable = &worker.executable;
    let mut command = Command::new(&worker.executable_path);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    // SAFETY: only libc syscalls over constants run after fork, before exec.
    unsafe {
        command.pre_exec(move || {
            for (resource, current, maximum) in [
                (libc::RLIMIT_CPU, child_cpu_limit, child_cpu_limit),
                (libc::RLIMIT_AS, child_memory_limit, child_memory_limit),
                (libc::RLIMIT_CORE, 0, 0),
            ] {
                let limit = libc::rlimit {
                    rlim_cur: current,
                    rlim_max: maximum,
                };
                if libc::setrlimit(resource, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                || libc::getppid() != creator_pid
                || libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) != 0
                || libc::sigprocmask(libc::SIG_SETMASK, &original_mask, std::ptr::null_mut()) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let filter = libc::sock_fprog {
                len: OFFLINE_FILTER.len() as u16,
                filter: OFFLINE_FILTER.as_ptr().cast_mut(),
            };
            if libc::prctl(libc::PR_SET_SECCOMP, 2, &filter) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().map_err(|_| WorkerError::Io)?;
    let mut owned = OwnedChild {
        child,
        reaped: false,
    };
    if ACTIVE_WORKER
        .compare_exchange(
            0,
            owned.child.id() as i32,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return Err(WorkerError::Busy);
    }
    ACTIVE_OWNER_THREAD.store(
        unsafe { libc::syscall(libc::SYS_gettid) } as i32,
        Ordering::Release,
    );
    drop(blocked);
    let stdin = owned.child.stdin.take().ok_or(WorkerError::Io)?;
    let mut stdout = owned.child.stdout.take().ok_or(WorkerError::Io)?;
    let mut stderr = owned.child.stderr.take().ok_or(WorkerError::Io)?;
    nonblocking(stdin.as_raw_fd())?;
    nonblocking(stdout.as_raw_fd())?;
    nonblocking(stderr.as_raw_fd())?;
    let mut stdin = if input.is_empty() { None } else { Some(stdin) };
    let mut written = 0;
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let mut output_eof = false;
    let mut errors_eof = false;
    loop {
        if Instant::now() >= deadline {
            return Err(WorkerError::Deadline);
        }
        if worker.process_budget
            && usage(libc::RUSAGE_SELF)?.0 + child_cpu(owned.child.id())? >= 10.0
        {
            return Err(WorkerError::ResourceLimit);
        }
        if let Some(pipe) = stdin.as_mut() {
            match pipe.write(&input[written..]) {
                Ok(0) => return Err(WorkerError::Io),
                Ok(n) => written += n,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => (),
                Err(_) => return Err(WorkerError::Io),
            }
            if written == input.len() {
                stdin.take();
            }
        }
        if !output_eof {
            output_eof = drain(&mut stdout, &mut output, MAX_WORKER_RESPONSE_BYTES)?;
        }
        if !errors_eof {
            errors_eof = drain(&mut stderr, &mut errors, MAX_STDERR_BYTES)?;
        }
        if exited_without_reaping(owned.child.id())? && output_eof && errors_eof {
            let status = owned.finish()?;
            if worker.process_budget {
                let (parent_cpu, parent_ram) = usage(libc::RUSAGE_SELF)?;
                let (children_cpu, children_ram) = usage(libc::RUSAGE_CHILDREN)?;
                if parent_cpu + (children_cpu - children_cpu_before).max(0.0) > 10.0
                    || parent_ram.saturating_add(children_ram) > ADDRESS_SPACE_LIMIT
                {
                    return Err(WorkerError::ResourceLimit);
                }
            }
            return if status.success() {
                Ok(output)
            } else {
                Err(WorkerError::NonzeroExit)
            };
        }
        let mut polls = [
            libc::pollfd {
                fd: stdin.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLOUT,
                revents: 0,
            },
            libc::pollfd {
                fd: if output_eof { -1 } else { stdout.as_raw_fd() },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if errors_eof { -1 } else { stderr.as_raw_fd() },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let wait_ms = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(50) as i32;
        let result = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as _, wait_ms) };
        if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(WorkerError::Io);
        }
    }
}

#[cfg(test)]
mod tests;
