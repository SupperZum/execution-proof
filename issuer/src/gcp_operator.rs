//! Bounded one-request operator CLI. Operator files are selected before reading
//! untrusted stdin; requests cannot select keys, firmware references, files or a worker.
//! This is not an HTTP server or TLS terminator. A trusted frontend owns those.
//! StartupPlan's task selector/snapshot are operator-selected public bindings;
//! a frontend must pin them rather than blindly forward hostile CP values.

use crate::{
    gcp::{GcpBootstrapSubmission, GcpIssuer, GcpIssuerConfig, GcpIssuerError},
    AdmissionPublicationKind, GrantPublication,
};
use execution_proof_contract::{
    admission::gcp::GcpAdmissionOperation, gcp_policy_receipt::GcpLaunchPolicyAggregateV2,
};
use execution_proof_gcp_journal::{Error as JournalError, Journal, PublicationJournal};
use ring::signature::Ed25519KeyPair;
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs::OpenOptions,
    io::Read,
    os::{
        fd::RawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

pub const REQUEST_PURPOSE: &str = "qlad.execution-proof.gcp-authority-request.v1";
pub const RESPONSE_PURPOSE: &str = "qlad.execution-proof.gcp-authority-response.v1";
pub const MAX_REQUEST_BYTES: usize = 4 << 20;
pub const MAX_RESPONSE_BYTES: usize = 64 << 10;
const MAX_CONFIG_BYTES: usize = 32 << 10;
const MAX_CONTROL_BYTES: usize = 16 << 10;
const MAX_COLLATERAL_BYTES: usize = 4 << 20;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u16,
    pub purpose: String,
    pub request: Operation,
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Begin {
        signed_intent_json: Vec<u8>,
    },
    Issue {
        challenge_id: String,
        submission: Box<GcpBootstrapSubmission>,
    },
    StartupPlan {
        grant_id: String,
        aggregate_json: Vec<u8>,
        container_id: String,
        trust_snapshot_sha384: String,
        execution_audience: String,
    },
    PinPolicyAdmission {
        grant_id: String,
        expected: Box<GcpLaunchPolicyAggregateV2>,
        guest_nonce: String,
    },
    RedeemPolicyAggregate {
        grant_id: String,
        aggregate_json: Vec<u8>,
        recorder_request_json: Vec<u8>,
    },
    StatusPolicyAggregate {
        grant_id: String,
        aggregate_json: Vec<u8>,
        recorder_request_json: Vec<u8>,
    },
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Publication {
    FirstIssued,
    FirstAuthorized,
    Existing,
}
#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ResponseBody {
    Initialized,
    Challenge {
        signed_challenge_json: Vec<u8>,
    },
    Grant {
        signed_grant_json: Vec<u8>,
        publication: Publication,
    },
    StartupPlan {
        signed_plan_json: Vec<u8>,
    },
    PolicyPinned,
    Admission {
        signed_authorization_json: Vec<u8>,
        publication: Publication,
    },
    PolicyStatus {
        signed_authorization_json: Option<Vec<u8>>,
    },
    Error {
        code: PublicError,
    },
}
#[derive(Serialize)]
pub struct Response {
    pub version: u16,
    pub purpose: &'static str,
    pub result: ResponseBody,
}
impl Response {
    fn new(result: ResponseBody) -> Self {
        Self {
            version: 1,
            purpose: RESPONSE_PURPOSE,
            result,
        }
    }
    fn encode(&self) -> Result<Vec<u8>, PublicError> {
        let mut bytes = serde_json::to_vec(self).map_err(|_| PublicError::Internal)?;
        if bytes.len() >= MAX_RESPONSE_BYTES {
            return Err(PublicError::ResponseLimit);
        }
        bytes.push(b'\n');
        Ok(bytes)
    }
}
/// Deliberately contains no path, request, key, signed bytes or source errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicError {
    Arguments,
    OperatorInput,
    OperatorKey,
    OperatorConfiguration,
    RequestMalformed,
    RequestDomain,
    RequestLimit,
    RequestRejected,
    RequestExpired,
    HardwareUnavailable,
    HardwareRejected,
    StateRejected,
    StateBusy,
    ClockUnavailable,
    JournalUnavailable,
    IoDeadline,
    Io,
    ResponseLimit,
    Internal,
}
impl From<GcpIssuerError> for PublicError {
    fn from(error: GcpIssuerError) -> Self {
        match error {
            GcpIssuerError::HardwareUnavailable => Self::HardwareUnavailable,
            GcpIssuerError::HardwareRejected => Self::HardwareRejected,
            GcpIssuerError::Issuer(crate::Error::Contract(
                execution_proof_contract::Error::Expired,
            ))
            | GcpIssuerError::Issuer(crate::Error::Store(crate::StoreError::Expired)) => {
                Self::RequestExpired
            }
            GcpIssuerError::Issuer(crate::Error::Store(crate::StoreError::Busy)) => Self::StateBusy,
            GcpIssuerError::Issuer(crate::Error::Store(crate::StoreError::ClockUnavailable)) => {
                Self::ClockUnavailable
            }
            GcpIssuerError::Issuer(crate::Error::Store(_)) => Self::StateRejected,
            _ => Self::RequestRejected,
        }
    }
}

impl From<JournalError> for PublicError {
    fn from(error: JournalError) -> Self {
        match error {
            JournalError::Conflict => Self::StateRejected,
            JournalError::Unavailable => Self::JournalUnavailable,
        }
    }
}

/// Dispatches only the typed authority operations. The caller owns the already
/// configured authority and the authenticated transport; this does not add one.
pub fn execute_request(issuer: &GcpIssuer, bytes: &[u8]) -> Result<Response, PublicError> {
    dispatch(issuer, bytes, None)
}

pub(crate) fn dispatch(
    issuer: &GcpIssuer,
    bytes: &[u8],
    journal: Option<&dyn PublicationJournal>,
) -> Result<Response, PublicError> {
    dispatch_operation(issuer, parse_operation(bytes)?, journal)
}

fn parse_operation(bytes: &[u8]) -> Result<Operation, PublicError> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return Err(PublicError::RequestLimit);
    }
    let request: Request =
        serde_json::from_slice(bytes).map_err(|_| PublicError::RequestMalformed)?;
    if request.version != 1 || request.purpose != REQUEST_PURPOSE {
        return Err(PublicError::RequestDomain);
    }
    Ok(request.request)
}

fn dispatch_operation(
    issuer: &GcpIssuer,
    operation: Operation,
    journal: Option<&dyn PublicationJournal>,
) -> Result<Response, PublicError> {
    let result = match operation {
        Operation::Begin { signed_intent_json } => {
            let signed = issuer.begin(&signed_intent_json)?;
            if let Some(journal) = journal {
                issuer.journal_begin(journal, &signed.statement.challenge_id)?;
            }
            ResponseBody::Challenge {
                signed_challenge_json: serde_json::to_vec(&signed)
                    .map_err(|_| PublicError::Internal)?,
            }
        }
        Operation::Issue {
            challenge_id,
            submission,
        } => {
            if let Some(journal) = journal {
                issuer.journal_attempt(&challenge_id)?.check(journal)?;
            }
            let issued = issuer.issue(&challenge_id, &submission)?;
            let first = if let Some(journal) = journal {
                issuer.journal_issue(journal, &challenge_id, &issued.signed_grant_json)?
            } else {
                matches!(issued.publication, GrantPublication::FirstIssued)
            };
            ResponseBody::Grant {
                signed_grant_json: issued.signed_grant_json,
                publication: if first {
                    Publication::FirstIssued
                } else {
                    Publication::Existing
                },
            }
        }
        Operation::StartupPlan {
            grant_id,
            aggregate_json,
            container_id,
            trust_snapshot_sha384,
            execution_audience,
        } => {
            if let Some(journal) = journal {
                issuer.check_journal_grant(journal, &grant_id)?;
            }
            ResponseBody::StartupPlan {
                signed_plan_json: issuer.startup_plan(
                    &grant_id,
                    &aggregate_json,
                    &container_id,
                    &trust_snapshot_sha384,
                    &execution_audience,
                )?,
            }
        }
        Operation::PinPolicyAdmission {
            grant_id,
            expected,
            guest_nonce,
        } => {
            if let Some(journal) = journal {
                issuer.check_journal_grant(journal, &grant_id)?;
            }
            issuer.pin_policy_admission(&grant_id, &expected, &guest_nonce)?;
            if let Some(journal) = journal {
                issuer.publish_journal_pin(journal, &grant_id)?;
            }
            ResponseBody::PolicyPinned
        }
        Operation::RedeemPolicyAggregate {
            grant_id,
            aggregate_json,
            recorder_request_json,
        } => {
            let (wire, first) = if let Some(journal) = journal {
                let entry = issuer
                    .journal_admission(
                        journal,
                        &grant_id,
                        &aggregate_json,
                        &recorder_request_json,
                        GcpAdmissionOperation::Redeem,
                    )?
                    .ok_or(PublicError::Internal)?;
                (entry.payload, entry.first)
            } else {
                let publication = issuer.redeem_policy_aggregate(
                    &grant_id,
                    &aggregate_json,
                    &recorder_request_json,
                )?;
                (
                    publication.signed_authorization_json,
                    matches!(
                        publication.publication,
                        AdmissionPublicationKind::FirstAuthorized
                    ),
                )
            };
            ResponseBody::Admission {
                signed_authorization_json: wire,
                publication: if first {
                    Publication::FirstAuthorized
                } else {
                    Publication::Existing
                },
            }
        }
        Operation::StatusPolicyAggregate {
            grant_id,
            aggregate_json,
            recorder_request_json,
        } => ResponseBody::PolicyStatus {
            signed_authorization_json: if let Some(journal) = journal {
                issuer
                    .journal_admission(
                        journal,
                        &grant_id,
                        &aggregate_json,
                        &recorder_request_json,
                        GcpAdmissionOperation::Status,
                    )?
                    .map(|entry| entry.payload)
            } else {
                issuer.status_policy_aggregate(
                    &grant_id,
                    &aggregate_json,
                    &recorder_request_json,
                )?
            },
        },
    };
    let response = Response::new(result);
    response.encode()?;
    Ok(response)
}

struct Arguments {
    initialize: bool,
    config: PathBuf,
    qualification: PathBuf,
    signer: PathBuf,
    store: PathBuf,
    collateral: PathBuf,
    capacity: usize,
    journal_bucket: Option<String>,
}
impl Arguments {
    fn parse(mut values: impl Iterator<Item = OsString>) -> Result<Self, PublicError> {
        let initialize = match values.next().as_deref() {
            Some(value) if value == "init" => true,
            Some(value) if value == "request" => false,
            _ => return Err(PublicError::Arguments),
        };
        let mut config = None;
        let mut qualification = None;
        let mut signer = None;
        let mut store = None;
        let mut collateral = None;
        let mut capacity = None;
        let mut journal_bucket = None;
        while let Some(flag) = values.next() {
            let value = values.next().ok_or(PublicError::Arguments)?;
            let destination = match flag.to_str() {
                Some("--config") => &mut config,
                Some("--qualification") => &mut qualification,
                Some("--signer") => &mut signer,
                Some("--store") => &mut store,
                Some("--collateral") => &mut collateral,
                Some("--journal-bucket") => {
                    if journal_bucket.is_some() {
                        return Err(PublicError::Arguments);
                    }
                    let bucket = value.into_string().map_err(|_| PublicError::Arguments)?;
                    if !Journal::valid_bucket(&bucket) {
                        return Err(PublicError::Arguments);
                    }
                    journal_bucket = Some(bucket);
                    continue;
                }
                Some("--capacity") => {
                    if capacity.is_some() {
                        return Err(PublicError::Arguments);
                    }
                    let parsed = value
                        .to_str()
                        .and_then(|v| v.parse::<usize>().ok())
                        .filter(|v| (1..=1024).contains(v))
                        .ok_or(PublicError::Arguments)?;
                    capacity = Some(parsed);
                    continue;
                }
                _ => return Err(PublicError::Arguments),
            };
            if destination.is_some() || value.is_empty() {
                return Err(PublicError::Arguments);
            }
            *destination = Some(PathBuf::from(value));
        }
        Ok(Self {
            initialize,
            config: config.ok_or(PublicError::Arguments)?,
            qualification: qualification.ok_or(PublicError::Arguments)?,
            signer: signer.ok_or(PublicError::Arguments)?,
            store: store.ok_or(PublicError::Arguments)?,
            collateral: collateral.ok_or(PublicError::Arguments)?,
            capacity: capacity.ok_or(PublicError::Arguments)?,
            journal_bucket,
        })
    }
}

fn read_operator_file(path: &Path, limit: usize, private: bool) -> Result<Vec<u8>, PublicError> {
    // NONBLOCK prevents a selected FIFO/device from blocking before metadata
    // rejection. NOFOLLOW rejects a swapped final-component symlink.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| PublicError::OperatorInput)?;
    let metadata = file.metadata().map_err(|_| PublicError::OperatorInput)?;
    // SAFETY: geteuid has no pointer arguments and cannot invalidate Rust data.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > limit as u64
        || (metadata.uid() != uid && metadata.uid() != 0)
        || metadata.mode() & 0o022 != 0
        || (private && (metadata.uid() != uid || metadata.mode() & 0o077 != 0))
    {
        return Err(PublicError::OperatorInput);
    }
    let mut bytes = Vec::new();
    let read = file.take(limit as u64 + 1).read_to_end(&mut bytes);
    if read.is_err() || bytes.is_empty() || bytes.len() > limit {
        if private {
            bytes.zeroize();
        }
        return Err(PublicError::OperatorInput);
    }
    Ok(bytes)
}
fn authority(args: &Arguments, mode: crate::gcp::OpenMode) -> Result<GcpIssuer, PublicError> {
    let mut config: GcpIssuerConfig =
        serde_json::from_slice(&read_operator_file(&args.config, MAX_CONFIG_BYTES, false)?)
            .map_err(|_| PublicError::OperatorConfiguration)?;
    // The large collateral has one explicit operator path and one budget. It
    // cannot be embedded in config or substituted by a submitted operation.
    if !config.collateral_json.is_empty() {
        return Err(PublicError::OperatorConfiguration);
    }
    config.collateral_json = read_operator_file(&args.collateral, MAX_COLLATERAL_BYTES, false)?;
    let qualification = read_operator_file(&args.qualification, MAX_CONTROL_BYTES, false)?;
    let pkcs8 = Zeroizing::new(read_operator_file(&args.signer, MAX_CONTROL_BYTES, true)?);
    let signer = Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| PublicError::OperatorKey)?;
    let result = GcpIssuer::open(
        crate::gcp::StoreOptions {
            path: &args.store,
            capacity: args.capacity,
            journal_bucket: args.journal_bucket.as_deref(),
        },
        config,
        &qualification,
        signer,
        std::sync::Arc::new(crate::SystemClock),
        mode,
    );
    result.map_err(PublicError::from)
}

struct Nonblocking(RawFd, libc::c_int);
impl Nonblocking {
    fn set(fd: RawFd) -> Result<Self, PublicError> {
        // SAFETY: fcntl uses a live process-owned stdio descriptor; flags are
        // scalar. The dedicated CLI has no concurrent readers/writers.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(PublicError::Io);
        }
        Ok(Self(fd, flags))
    }
}
impl Drop for Nonblocking {
    fn drop(&mut self) {
        // SAFETY: restore flags on the same live process-owned descriptor.
        unsafe {
            libc::fcntl(self.0, libc::F_SETFL, self.1);
        }
    }
}
fn wait_fd(fd: RawFd, events: i16, deadline: Instant) -> Result<(), PublicError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(PublicError::IoDeadline)?;
        let ms = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        let mut poll = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: poll references exactly one initialized record for this call.
        let result = unsafe { libc::poll(&mut poll, 1, ms) };
        if result == 0 {
            return Err(PublicError::IoDeadline);
        }
        if result < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(PublicError::Io);
        }
        if poll.revents & libc::POLLNVAL != 0 {
            return Err(PublicError::Io);
        }
        return Ok(());
    }
}
fn read_request(fd: RawFd, timeout: Duration) -> Result<Vec<u8>, PublicError> {
    let _flags = Nonblocking::set(fd)?;
    let deadline = Instant::now() + timeout;
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 16 << 10];
    loop {
        wait_fd(fd, libc::POLLIN, deadline)?;
        // SAFETY: buffer is writable for its exact length, fd is owned/live.
        let n = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if n == 0 {
            return Ok(bytes);
        }
        if n < 0 {
            if matches!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(PublicError::Io);
        }
        if bytes.len().saturating_add(n as usize) > MAX_REQUEST_BYTES {
            return Err(PublicError::RequestLimit);
        }
        bytes.extend_from_slice(&buffer[..n as usize]);
    }
}
fn write_response(fd: RawFd, bytes: &[u8], timeout: Duration) -> Result<(), PublicError> {
    let _flags = Nonblocking::set(fd)?;
    let deadline = Instant::now() + timeout;
    let mut offset = 0;
    while offset < bytes.len() {
        wait_fd(fd, libc::POLLOUT, deadline)?;
        // SAFETY: bytes[offset..] remains live/readable for the exact length.
        let n = unsafe { libc::write(fd, bytes[offset..].as_ptr().cast(), bytes.len() - offset) };
        if n <= 0 {
            if n < 0
                && matches!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                )
            {
                continue;
            }
            return Err(PublicError::Io);
        }
        offset += n as usize;
    }
    Ok(())
}
fn protect_process() -> Result<(), PublicError> {
    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid read-only rlimit pointer and scalar prctl arguments. Only
    // this dedicated operator process is affected; no parent policy is changed.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) } != 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
    {
        return Err(PublicError::OperatorConfiguration);
    }
    Ok(())
}
fn run_inner() -> Result<Response, PublicError> {
    protect_process()?;
    let args = Arguments::parse(std::env::args_os().skip(1))?;
    if args.initialize {
        authority(&args, crate::gcp::OpenMode::Initialize)?;
        return Ok(Response::new(ResponseBody::Initialized));
    }
    let request = parse_operation(&read_request(libc::STDIN_FILENO, IO_TIMEOUT)?)?;
    let mode = match &request {
        Operation::StatusPolicyAggregate { .. } => crate::gcp::OpenMode::HistoricalStatus,
        _ => crate::gcp::OpenMode::Live,
    };
    let issuer = authority(&args, mode)?;
    let journal = args
        .journal_bucket
        .as_deref()
        .map(Journal::connect)
        .transpose()?;
    dispatch_operation(
        &issuer,
        request,
        journal.as_ref().map(|v| v as &dyn PublicationJournal),
    )
}
/// Dedicated-process entrypoint. Every failure is one fixed public code; no
/// private key, path, environment, request or nested source error is formatted.
pub fn run_stdio() -> ExitCode {
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(run_inner).unwrap_or(Err(PublicError::Internal));
    let mut failed = result.is_err();
    let response = result.unwrap_or_else(|code| Response::new(ResponseBody::Error { code }));
    let bytes = response.encode().unwrap_or_else(|_| {
        failed = true;
        b"{\"version\":1,\"purpose\":\"qlad.execution-proof.gcp-authority-response.v1\",\"result\":{\"status\":\"error\",\"code\":\"response_limit\"}}\n".to_vec()
    });
    if write_response(libc::STDOUT_FILENO, &bytes, IO_TIMEOUT).is_err() || failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests;
