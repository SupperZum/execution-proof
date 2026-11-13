//! Bounded, boot-local bookkeeping for a preparation **reference** and a task.
//!
//! A reference does not establish encrypted-content preparation, rootfs custody,
//! bootstrap/key origin, or an observed exec. This crate neither opens paths nor
//! releases a FIFO. Only a one-use aggregate admission can register a reference; the
//! caller still needs the real CDH and authenticated runtime handoff backends.
//! State and tombstones are retained for the lifetime of the table. A restart is
//! not replay protection: only a newly enrolled boot may create a new table.

use admission::AcceptedAttemptContext;
use execution_proof_contract::LaunchBinding;
#[cfg(any(test, feature = "software-lab"))]
use execution_proof_contract::VerifiedStatements;
pub mod admission;
#[cfg(feature = "rootfs-custody")]
pub use execution_proof_contract::execution;
#[cfg(feature = "rootfs-custody")]
pub use execution_proof_contract::execution_quote;
#[cfg(all(target_os = "linux", feature = "rootfs-transfer"))]
pub mod fd_transport;
#[cfg(all(target_os = "linux", feature = "gcp-startup"))]
pub mod gcp_startup;
#[cfg(all(target_os = "linux", feature = "rootfs-custody"))]
pub mod rootfs_custody;
#[cfg(all(target_os = "linux", feature = "rootfs-transfer"))]
pub mod rootfs_offer;
#[cfg(all(target_os = "linux", feature = "gcp-startup"))]
pub mod sandbox_gateway;
#[cfg(all(target_os = "linux", feature = "rootfs-startup"))]
pub mod startup;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

/// The narrow profile bounds both retained entries and generation reservations.
pub const MAX_CAPACITY: usize = 1024;
const MAX_ID_BYTES: usize = 128;
const APPLICATION_ROLE: &str = "application-init";

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedReason {
    AuthorityBootAndContentAdaptersUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrepareError {
    UnsupportedProtocolVersion,
    MissingProofProfile,
    Unsupported(UnsupportedReason),
}

impl fmt::Display for PrepareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "preparation unavailable: {self:?}")
    }
}

impl std::error::Error for PrepareError {}

/// No production preparation/proof profile is supported by these primitives.
pub fn supported_proof_profiles() -> &'static [&'static str] {
    &[]
}

/// The production entry fails before any side effect. The uninhabited success
/// type prevents bookkeeping references from masquerading as prepared content.
pub fn prepare_launch(
    protocol_version: u16,
    proof_profile: Option<&str>,
) -> Result<std::convert::Infallible, PrepareError> {
    if protocol_version != PROTOCOL_VERSION {
        return Err(PrepareError::UnsupportedProtocolVersion);
    }
    if proof_profile.is_none_or(str::is_empty) {
        return Err(PrepareError::MissingProofProfile);
    }
    Err(PrepareError::Unsupported(
        UnsupportedReason::AuthorityBootAndContentAdaptersUnavailable,
    ))
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PreparationId([u8; 32]);

impl PreparationId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An untrusted identifier plus the exact aggregate admission context commitment.
///
/// Anyone may construct a reference. Only `register` associates it with verified
/// admission. The type deliberately contains no caller path or rootfs claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparationReference {
    pub id: PreparationId,
    pub context_sha384: [u8; 48],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskIdentity {
    pub boot_id: String,
    pub attempt_id: String,
    pub selected_manifest_sha256: String,
    pub effective_launch_sha384: String,
    pub container_role: String,
    /// Issued by the runtime's single task-lifetime owner, not a numeric PID.
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Registered,
    Bound,
    Consumed,
    AbortedBeforeConsume,
    AbortedAfterConsume,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Registration {
    Inserted,
    Existing(Status),
}

/// A unique successful consume transition, not an execution or custody proof.
///
/// The token is not cloneable or deserializable. Retrying `consume` never issues
/// another token, including if this token was dropped before the caller acted.
#[derive(Debug)]
pub struct ReleasePermit {
    reference: PreparationReference,
    task: TaskIdentity,
}

impl ReleasePermit {
    pub fn reference(&self) -> &PreparationReference {
        &self.reference
    }

    pub fn task(&self) -> &TaskIdentity {
        &self.task
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidCapacity,
    InvalidBootId,
    InvalidPreparationId,
    InvalidContextDigest,
    ContextMismatch,
    WrongBoot,
    WrongAttempt,
    WrongManifest,
    WrongEffectiveLaunch,
    WrongRole,
    InvalidGeneration,
    UnknownReference,
    ReferenceConflict,
    GrantAlreadyRegistered,
    AttemptAlreadyRegistered,
    GenerationAlreadyBound,
    WrongTask,
    NotBound,
    AlreadyConsumed,
    Aborted,
    CapacityExhausted,
    Poisoned,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "handoff rejected: {self:?}")
    }
}

impl std::error::Error for Error {}

struct Entry {
    reference: PreparationReference,
    grant_id: String,
    attempt_id: String,
    manifest: String,
    effective_launch: String,
    task: Option<TaskIdentity>,
    status: Status,
}

/// One table per freshly enrolled boot, owned by the trusted runtime process.
///
/// All mutations linearize under one mutex. There is no I/O, callback, await, or
/// task spawn under the lock. Exhaustion and poisoning reject further actions;
/// no terminal entry or task generation is evicted to make space.
pub struct BootTable {
    boot_id: String,
    capacity: usize,
    entries: Mutex<BTreeMap<PreparationId, Entry>>,
}

impl BootTable {
    pub fn new(boot_id: String, capacity: usize) -> Result<Self, Error> {
        if capacity == 0 || capacity > MAX_CAPACITY {
            return Err(Error::InvalidCapacity);
        }
        if boot_id.is_empty()
            || boot_id.len() > MAX_ID_BYTES
            || !boot_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
        {
            return Err(Error::InvalidBootId);
        }
        Ok(Self {
            boot_id,
            capacity,
            entries: Mutex::new(BTreeMap::new()),
        })
    }

    /// Consumes the unique accepted context even if registration rejects. Retry
    /// uses status; it cannot recover preparation authority from an old receipt.
    /// ```compile_fail
    /// use execution_proof_contract::VerifiedStatements;
    /// use execution_proof_handoff::{BootTable, PreparationReference};
    /// fn early(table: &BootTable, old: VerifiedStatements, reference: PreparationReference) {
    ///     table.register(old, reference);
    /// }
    /// ```
    pub fn register(
        &self,
        admission: AcceptedAttemptContext,
        reference: PreparationReference,
    ) -> Result<Registration, Error> {
        self.register_binding(
            admission.binding(),
            admission.grant_id(),
            admission.context_digest(),
            reference,
        )
    }

    /// Early L/A software fixtures only; unavailable in the default runtime API.
    #[cfg(any(test, feature = "software-lab"))]
    pub fn register_lab(
        &self,
        statements: &VerifiedStatements,
        reference: PreparationReference,
    ) -> Result<Registration, Error> {
        self.register_binding(
            statements.binding(),
            statements.grant_id(),
            statements.context_digest(),
            reference,
        )
    }

    fn register_binding(
        &self,
        binding: &LaunchBinding,
        grant_id: &str,
        context_digest: &str,
        reference: PreparationReference,
    ) -> Result<Registration, Error> {
        validate_reference(&reference)?;
        let mut entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        if let Some(entry) = entries.get(&reference.id) {
            exact_reference(entry, &reference)?;
        }
        if binding.boot_id != self.boot_id {
            return Err(Error::WrongBoot);
        }
        if binding.container_role != APPLICATION_ROLE {
            return Err(Error::WrongRole);
        }
        if reference.context_sha384 != decode_sha384(context_digest)? {
            return Err(Error::ContextMismatch);
        }
        if let Some(entry) = entries.get(&reference.id) {
            return Ok(Registration::Existing(entry.status));
        }
        // The narrow boot profile reserves grant and attempt IDs globally.
        // A new reference ID or newly signed appraisal cannot re-arm them.
        if entries.values().any(|e| e.attempt_id == binding.attempt_id) {
            return Err(Error::AttemptAlreadyRegistered);
        }
        if entries.values().any(|e| e.grant_id == grant_id) {
            return Err(Error::GrantAlreadyRegistered);
        }
        if entries.len() == self.capacity {
            return Err(Error::CapacityExhausted);
        }
        entries.insert(
            reference.id,
            Entry {
                reference,
                grant_id: grant_id.to_owned(),
                attempt_id: binding.attempt_id.clone(),
                manifest: binding.selected_manifest_sha256.clone(),
                effective_launch: binding.effective_launch_sha384.clone(),
                task: None,
                status: Status::Registered,
            },
        );
        Ok(Registration::Inserted)
    }

    pub fn bind(
        &self,
        reference: &PreparationReference,
        task: TaskIdentity,
    ) -> Result<Status, Error> {
        validate_reference(reference)?;
        let mut entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        let entry = entries.get(&reference.id).ok_or(Error::UnknownReference)?;
        exact_reference(entry, reference)?;
        self.check_task(entry, &task)?;
        if let Some(bound) = &entry.task {
            if bound != &task {
                return Err(Error::WrongTask);
            }
            return match entry.status {
                Status::Bound => Ok(Status::Bound),
                Status::Consumed => Err(Error::AlreadyConsumed),
                Status::AbortedBeforeConsume | Status::AbortedAfterConsume => Err(Error::Aborted),
                Status::Registered => unreachable!("a registered entry has no task"),
            };
        }
        if entry.status != Status::Registered {
            return Err(Error::Aborted);
        }
        if entries.values().any(|e| {
            e.task
                .as_ref()
                .is_some_and(|bound| bound.generation == task.generation)
        }) {
            return Err(Error::GenerationAlreadyBound);
        }
        let entry = entries
            .get_mut(&reference.id)
            .expect("entry held under lock");
        entry.task = Some(task);
        entry.status = Status::Bound;
        Ok(Status::Bound)
    }

    pub fn consume(
        &self,
        reference: &PreparationReference,
        task: &TaskIdentity,
    ) -> Result<ReleasePermit, Error> {
        validate_reference(reference)?;
        let mut entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        let entry = entries
            .get_mut(&reference.id)
            .ok_or(Error::UnknownReference)?;
        exact_reference(entry, reference)?;
        self.check_task(entry, task)?;
        if let Some(bound) = &entry.task {
            if bound != task {
                return Err(Error::WrongTask);
            }
        }
        match entry.status {
            Status::Registered => Err(Error::NotBound),
            Status::Bound => {
                entry.status = Status::Consumed;
                Ok(ReleasePermit {
                    reference: *reference,
                    task: task.clone(),
                })
            }
            Status::Consumed => Err(Error::AlreadyConsumed),
            Status::AbortedBeforeConsume | Status::AbortedAfterConsume => Err(Error::Aborted),
        }
    }

    /// A status reply is observational. It never grants permission to release.
    pub fn status(&self, reference: &PreparationReference) -> Result<Status, Error> {
        validate_reference(reference)?;
        let entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        let entry = entries.get(&reference.id).ok_or(Error::UnknownReference)?;
        exact_reference(entry, reference)?;
        Ok(entry.status)
    }

    /// Marks terminal state without revoking a returned permit or stopping a task.
    /// The runtime owner must coordinate revocation and task termination.
    pub fn abort(&self, reference: &PreparationReference) -> Result<Status, Error> {
        validate_reference(reference)?;
        let mut entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        let entry = entries
            .get_mut(&reference.id)
            .ok_or(Error::UnknownReference)?;
        exact_reference(entry, reference)?;
        entry.status = match entry.status {
            Status::Registered | Status::Bound | Status::AbortedBeforeConsume => {
                Status::AbortedBeforeConsume
            }
            Status::Consumed | Status::AbortedAfterConsume => Status::AbortedAfterConsume,
        };
        Ok(entry.status)
    }

    fn check_task(&self, entry: &Entry, task: &TaskIdentity) -> Result<(), Error> {
        if task.boot_id != self.boot_id {
            return Err(Error::WrongBoot);
        }
        if task.attempt_id != entry.attempt_id {
            return Err(Error::WrongAttempt);
        }
        if task.selected_manifest_sha256 != entry.manifest {
            return Err(Error::WrongManifest);
        }
        if task.effective_launch_sha384 != entry.effective_launch {
            return Err(Error::WrongEffectiveLaunch);
        }
        if task.container_role != APPLICATION_ROLE {
            return Err(Error::WrongRole);
        }
        if task.generation == 0 {
            return Err(Error::InvalidGeneration);
        }
        Ok(())
    }
}

fn exact_reference(entry: &Entry, reference: &PreparationReference) -> Result<(), Error> {
    if &entry.reference != reference {
        Err(Error::ReferenceConflict)
    } else {
        Ok(())
    }
}

fn validate_reference(reference: &PreparationReference) -> Result<(), Error> {
    if reference.id.0 == [0; 32] {
        Err(Error::InvalidPreparationId)
    } else {
        Ok(())
    }
}

fn decode_sha384(value: &str) -> Result<[u8; 48], Error> {
    if value.len() != 96 {
        return Err(Error::InvalidContextDigest);
    }
    fn nibble(value: u8) -> Result<u8, Error> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err(Error::InvalidContextDigest),
        }
    }
    let mut decoded = [0; 48];
    for (out, pair) in decoded.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        *out = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests;
