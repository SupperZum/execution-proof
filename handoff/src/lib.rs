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
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    // These private fixtures isolate table transitions. Cross-crate admission
    // tests exercise register with actual signed/verified contract statements.
    fn fixture(capacity: usize) -> (BootTable, PreparationReference, TaskIdentity) {
        let table = BootTable::new("boot-1".into(), capacity).unwrap();
        let reference = prep_ref(1);
        let task = task(1);
        insert_fixture(&table, reference, &task);
        (table, reference, task)
    }

    fn prep_ref(value: u8) -> PreparationReference {
        PreparationReference {
            id: PreparationId::new([value; 32]),
            context_sha384: [value; 48],
        }
    }

    fn task(generation: u64) -> TaskIdentity {
        TaskIdentity {
            boot_id: "boot-1".into(),
            attempt_id: format!("attempt-{generation}"),
            selected_manifest_sha256: "a".repeat(64),
            effective_launch_sha384: "c".repeat(96),
            container_role: APPLICATION_ROLE.into(),
            generation,
        }
    }

    fn insert_fixture(table: &BootTable, reference: PreparationReference, task: &TaskIdentity) {
        table.entries.lock().unwrap().insert(
            reference.id,
            Entry {
                reference,
                grant_id: format!("grant-{}", task.generation),
                attempt_id: task.attempt_id.clone(),
                manifest: task.selected_manifest_sha256.clone(),
                effective_launch: task.effective_launch_sha384.clone(),
                task: None,
                status: Status::Registered,
            },
        );
    }

    #[test]
    fn production_preparation_advertises_no_capability_and_never_succeeds() {
        assert!(supported_proof_profiles().is_empty());
        assert_eq!(
            prepare_launch(PROTOCOL_VERSION, None),
            Err(PrepareError::MissingProofProfile)
        );
        assert_eq!(
            prepare_launch(PROTOCOL_VERSION, Some("")),
            Err(PrepareError::MissingProofProfile)
        );
        assert_eq!(
            prepare_launch(0, Some("profile")),
            Err(PrepareError::UnsupportedProtocolVersion)
        );
        assert_eq!(
            prepare_launch(PROTOCOL_VERSION, Some("profile")),
            Err(PrepareError::Unsupported(
                UnsupportedReason::AuthorityBootAndContentAdaptersUnavailable
            ))
        );
    }

    #[test]
    fn consumes_once_and_status_or_registration_is_not_a_second_permit() {
        let (table, reference, task) = fixture(1);
        assert!(matches!(
            table.consume(&reference, &task),
            Err(Error::NotBound)
        ));
        assert_eq!(table.bind(&reference, task.clone()), Ok(Status::Bound));
        assert_eq!(table.bind(&reference, task.clone()), Ok(Status::Bound));
        let permit = table.consume(&reference, &task).unwrap();
        assert_eq!(permit.reference(), &reference);
        assert_eq!(permit.task(), &task);
        drop(permit);
        assert_eq!(table.status(&reference), Ok(Status::Consumed));
        assert!(matches!(
            table.consume(&reference, &task),
            Err(Error::AlreadyConsumed)
        ));
        assert_eq!(table.bind(&reference, task), Err(Error::AlreadyConsumed));
    }

    #[test]
    fn wrong_identity_or_reference_cannot_change_or_consume_state() {
        let (table, reference, task) = fixture(1);
        let cases: Vec<(TaskIdentity, Error)> = vec![
            (
                TaskIdentity {
                    boot_id: "other".into(),
                    ..task.clone()
                },
                Error::WrongBoot,
            ),
            (
                TaskIdentity {
                    attempt_id: "other".into(),
                    ..task.clone()
                },
                Error::WrongAttempt,
            ),
            (
                TaskIdentity {
                    selected_manifest_sha256: "b".repeat(64),
                    ..task.clone()
                },
                Error::WrongManifest,
            ),
            (
                TaskIdentity {
                    effective_launch_sha384: "d".repeat(96),
                    ..task.clone()
                },
                Error::WrongEffectiveLaunch,
            ),
            (
                TaskIdentity {
                    container_role: "helper".into(),
                    ..task.clone()
                },
                Error::WrongRole,
            ),
            (
                TaskIdentity {
                    generation: 0,
                    ..task.clone()
                },
                Error::InvalidGeneration,
            ),
        ];
        for (wrong, expected) in cases {
            assert_eq!(table.bind(&reference, wrong.clone()), Err(expected));
            assert!(matches!(table.consume(&reference, &wrong), Err(error) if error == expected));
            assert_eq!(table.status(&reference), Ok(Status::Registered));
        }
        let mut changed = reference;
        changed.context_sha384[0] ^= 1;
        assert_eq!(table.status(&changed), Err(Error::ReferenceConflict));
        assert_eq!(table.abort(&changed), Err(Error::ReferenceConflict));
        table.bind(&reference, task.clone()).unwrap();
        let changed_generation = TaskIdentity {
            generation: 2,
            ..task
        };
        assert_eq!(
            table.bind(&reference, changed_generation.clone()),
            Err(Error::WrongTask)
        );
        assert!(matches!(
            table.consume(&reference, &changed_generation),
            Err(Error::WrongTask)
        ));
        assert_eq!(table.status(&reference), Ok(Status::Bound));
    }

    #[test]
    fn aborted_and_consumed_tombstones_preserve_generations() {
        let (table, reference, task) = fixture(2);
        table.bind(&reference, task.clone()).unwrap();
        assert_eq!(table.abort(&reference), Ok(Status::AbortedBeforeConsume));
        assert_eq!(table.abort(&reference), Ok(Status::AbortedBeforeConsume));
        assert!(matches!(
            table.consume(&reference, &task),
            Err(Error::Aborted)
        ));
        assert_eq!(table.bind(&reference, task.clone()), Err(Error::Aborted));
        let second = prep_ref(2);
        let second_task = TaskIdentity {
            attempt_id: "attempt-2".into(),
            ..task
        };
        insert_fixture(&table, second, &second_task);
        assert_eq!(
            table.bind(&second, second_task.clone()),
            Err(Error::GenerationAlreadyBound)
        );
        let second_task = TaskIdentity {
            generation: 2,
            ..second_task
        };
        table.bind(&second, second_task.clone()).unwrap();
        let permit = table.consume(&second, &second_task).unwrap();
        drop(permit);
        assert_eq!(table.abort(&second), Ok(Status::AbortedAfterConsume));
        assert_eq!(table.abort(&second), Ok(Status::AbortedAfterConsume));
        assert!(matches!(
            table.consume(&second, &second_task),
            Err(Error::Aborted)
        ));
        assert_eq!(table.entries.lock().unwrap().len(), 2);
    }

    #[test]
    fn simultaneous_consumers_have_exactly_one_winner() {
        let (table, reference, task) = fixture(1);
        table.bind(&reference, task.clone()).unwrap();
        let table = Arc::new(table);
        let barrier = Arc::new(Barrier::new(16));
        let mut threads = Vec::new();
        for _ in 0..16 {
            let table = table.clone();
            let barrier = barrier.clone();
            let task = task.clone();
            threads.push(thread::spawn(move || {
                barrier.wait();
                table.consume(&reference, &task)
            }));
        }
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(Error::AlreadyConsumed)))
                .count(),
            15
        );
        assert_eq!(table.status(&reference), Ok(Status::Consumed));
    }

    #[test]
    fn racing_abort_and_consume_never_reopens() {
        let (table, reference, task) = fixture(1);
        table.bind(&reference, task.clone()).unwrap();
        let table = Arc::new(table);
        let barrier = Arc::new(Barrier::new(2));
        let consumer = {
            let table = table.clone();
            let barrier = barrier.clone();
            let task = task.clone();
            thread::spawn(move || {
                barrier.wait();
                table.consume(&reference, &task)
            })
        };
        barrier.wait();
        let terminal = table.abort(&reference).unwrap();
        match consumer.join().unwrap() {
            Ok(_) => assert_eq!(terminal, Status::AbortedAfterConsume),
            Err(Error::Aborted) => assert_eq!(terminal, Status::AbortedBeforeConsume),
            other => panic!("unexpected consume result: {other:?}"),
        }
        assert!(matches!(
            table.consume(&reference, &task),
            Err(Error::Aborted)
        ));
    }

    #[test]
    fn invalid_boot_capacity_reference_and_poison_fail_closed() {
        assert!(matches!(
            BootTable::new("boot".into(), 0),
            Err(Error::InvalidCapacity)
        ));
        assert!(matches!(
            BootTable::new("boot".into(), MAX_CAPACITY + 1),
            Err(Error::InvalidCapacity)
        ));
        for boot in [
            "",
            "with space",
            "slash/path",
            &"b".repeat(MAX_ID_BYTES + 1),
        ] {
            assert!(matches!(
                BootTable::new(boot.into(), 1),
                Err(Error::InvalidBootId)
            ));
        }
        let (table, reference, task) = fixture(1);
        assert_eq!(table.status(&prep_ref(0)), Err(Error::InvalidPreparationId));
        assert_eq!(table.status(&prep_ref(9)), Err(Error::UnknownReference));
        let table = Arc::new(table);
        let poison = table.clone();
        assert!(thread::spawn(move || {
            let _guard = poison.entries.lock().unwrap();
            panic!("poison fixture");
        })
        .join()
        .is_err());
        assert_eq!(table.status(&reference), Err(Error::Poisoned));
        assert!(matches!(
            table.consume(&reference, &task),
            Err(Error::Poisoned)
        ));
    }

    #[test]
    fn context_decoder_accepts_only_canonical_fixed_size_lowercase_hex() {
        assert_eq!(decode_sha384(&"ab".repeat(48)), Ok([0xab; 48]));
        for bad in [
            "a".repeat(95),
            "a".repeat(97),
            "AB".repeat(48),
            "z".repeat(96),
        ] {
            assert_eq!(decode_sha384(&bad), Err(Error::InvalidContextDigest));
        }
    }
}
