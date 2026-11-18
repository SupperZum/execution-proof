//! One-request, local-only experimental operator. No service or cloud calls.
use onb17_qualification_experiment::{Experiment, Rejected, Request, MAX_REQUEST, UNPROVEN};
use std::{
    os::fd::RawFd,
    path::PathBuf,
    time::{Duration, Instant},
};
fn require(b: bool) -> Result<(), Rejected> {
    if b {
        Ok(())
    } else {
        Err(Rejected)
    }
}
extern "C" fn stop(_: libc::c_int) {
    execution_proof_verifier::worker::abort_active_worker();
    unsafe { libc::_exit(124) }
}
struct Flags(RawFd, libc::c_int);
impl Flags {
    fn new(fd: RawFd) -> Result<Self, Rejected> {
        let old = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        require(
            old >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, old | libc::O_NONBLOCK) } == 0,
        )?;
        Ok(Self(fd, old))
    }
}
impl Drop for Flags {
    fn drop(&mut self) {
        unsafe { libc::fcntl(self.0, libc::F_SETFL, self.1) };
    }
}
fn ready(fd: RawFd, events: libc::c_short, until: Instant) -> Result<(), Rejected> {
    loop {
        let left = until
            .checked_duration_since(Instant::now())
            .ok_or(Rejected)?;
        let mut poll = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut poll, 1, left.as_millis().min(i32::MAX as u128) as i32) };
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        require(n > 0 && poll.revents & (libc::POLLERR | libc::POLLNVAL) == 0)?;
        return Ok(());
    }
}
fn input() -> Result<Vec<u8>, Rejected> {
    let _flags = Flags::new(0)?;
    let end = Instant::now() + Duration::from_secs(10);
    let mut out = Vec::new();
    loop {
        ready(0, libc::POLLIN, end)?;
        let mut bytes = [0; 8192];
        let n = unsafe { libc::read(0, bytes.as_mut_ptr().cast(), bytes.len()) };
        if n == 0 {
            return Ok(out);
        }
        if n < 0 {
            if matches!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(Rejected);
        }
        require(out.len() + n as usize <= MAX_REQUEST)?;
        out.extend_from_slice(&bytes[..n as usize]);
    }
}
fn output(value: &serde_json::Value) -> Result<(), Rejected> {
    let bytes = serde_json::to_vec(value).map_err(|_| Rejected)?;
    require(bytes.len() <= 128 << 10)?;
    let _flags = Flags::new(1)?;
    let until = Instant::now() + Duration::from_secs(10);
    let mut offset = 0;
    while offset < bytes.len() {
        ready(1, libc::POLLOUT, until)?;
        let n = unsafe { libc::write(1, bytes[offset..].as_ptr().cast(), bytes.len() - offset) };
        if n < 0
            && matches!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            )
        {
            continue;
        }
        require(n > 0)?;
        offset += n as usize;
    }
    Ok(())
}
fn run() -> Result<serde_json::Value, Rejected> {
    require(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0)?;
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    require(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } == 0)?;
    unsafe {
        libc::signal(libc::SIGALRM, stop as *const () as usize);
        libc::signal(libc::SIGTERM, stop as *const () as usize);
        libc::signal(libc::SIGINT, stop as *const () as usize);
        libc::alarm(90);
    }
    let mut args = std::env::args_os().skip(1);
    let operation = args.next().ok_or(Rejected)?;
    let mut config = None;
    let mut signer = None;
    let mut collateral = None;
    while let Some(flag) = args.next() {
        let slot = match flag.to_str() {
            Some("--config") => &mut config,
            Some("--signer") => &mut signer,
            Some("--collateral") => &mut collateral,
            _ => return Err(Rejected),
        };
        require(slot.is_none())?;
        *slot = Some(PathBuf::from(args.next().ok_or(Rejected)?));
    }
    let input = input()?;
    // Location/authority choices are only explicit trusted operator arguments.
    // A clean exec launcher must also control the loader environment before main.
    unsafe { libc::clearenv() };
    let app = Experiment::open(
        &config.ok_or(Rejected)?,
        &signer.ok_or(Rejected)?,
        &collateral.ok_or(Rejected)?,
    )?;
    if operation == "bootstrap-only" {
        require(input.is_empty())?;
        return app.bootstrap_only();
    }
    if operation == "status" {
        require(input.is_empty())?;
        return app.status();
    }
    let request: Request = serde_json::from_slice(&input).map_err(|_| Rejected)?;
    require(matches!(
        (operation.to_str(), &request),
        (Some("issue"), Request::Issue { .. })
            | (Some("startup-plan"), Request::StartupPlan { .. })
            | (Some("redeem"), Request::Redeem { .. })
    ))?;
    app.request(request)
}
fn main() {
    let result = run();
    let (value, status) = match result {
        Ok(value) => (value, 0),
        Err(_) => (
            serde_json::json!({"version":1,"purpose":"onb17.gcp-qualification-experiment-response.v1",
            "claim_status":UNPROVEN,"producer_qualified":false,"execution_verified":false,"error":"experiment_rejected"}),
            1,
        ),
    };
    let status = if output(&value).is_ok() { status } else { 1 };
    unsafe { libc::alarm(0) };
    std::process::exit(status)
}
