use super::*;
use execution_proof_contract::{
    bootstrap::{TenantIntent, TENANT_INTENT_PURPOSE, TENANT_INTENT_VERSION},
    verify_statements, AppraisalVerdict, EvaluationCommitments, KbsAssociation, LaunchBinding,
    ProofAppraisal, TrustedExpectations, APPRAISAL_PURPOSE, GRANT_PURPOSE, VERSION,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Serialize;
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Barrier,
    },
    thread,
};

struct FixedClock;
impl IssuerClock for FixedClock {
    fn now_unix_seconds(&self) -> Result<u64, ClockError> {
        Ok(1000)
    }
}
fn initialize(path: &Path, identity: &str, capacity: usize) -> Result<Store, StoreError> {
    Store::initialize_new(path, identity, capacity, &FixedClock)
}
trait LabOperations {
    fn reserve_lab(&self, candidate: &ChallengeRecord) -> Result<ChallengeRecord, StoreError>;
    fn issue_lab(
        &self,
        id: &str,
        challenge: &str,
        context: &str,
        key: &str,
        wire: &[u8],
        grant: &str,
    ) -> Result<IssuedRecord, StoreError>;
    fn redeem_lab(&self, statements: &VerifiedStatements) -> Result<Redemption, StoreError>;
}
impl LabOperations for Store {
    fn reserve_lab(&self, candidate: &ChallengeRecord) -> Result<ChallengeRecord, StoreError> {
        self.reserve(candidate, &FixedClock, 3600)
    }
    fn issue_lab(
        &self,
        id: &str,
        challenge: &str,
        context: &str,
        key: &str,
        wire: &[u8],
        grant: &str,
    ) -> Result<IssuedRecord, StoreError> {
        self.issue(id, challenge, context, key, wire, grant, &FixedClock)
            .map(|result| result.record)
    }
    fn redeem_lab(&self, statements: &VerifiedStatements) -> Result<Redemption, StoreError> {
        self.redeem(statements, &FixedClock)
    }
}

struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("onb17-store-{}-{nonce}-{id}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn db(&self) -> PathBuf {
        self.0.join("admission.sqlite")
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn identity() -> String {
    "11".repeat(48)
}
fn encoding(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn key(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}
fn signed<T: Serialize + Clone>(statement: &T, bytes: &[u8], seed: u8) -> Vec<u8> {
    serde_json::to_vec(&Signed {
        statement: statement.clone(),
        signature: encoding(key(seed).sign(bytes).as_ref()),
    })
    .unwrap()
}
fn candidate(attempt: &str, random: u8) -> ChallengeRecord {
    let intent = TenantIntent {
        version: TENANT_INTENT_VERSION,
        validity: ValidityWindow {
            not_before: 1000,
            expires: 2000,
        },
        purpose: TENANT_INTENT_PURPOSE.into(),
        audience: "lab".into(),
        authority: "authority".into(),
        tenant: "tenant".into(),
        workload_id: "workload".into(),
        container_role: "application-init".into(),
        attempt_id: attempt.into(),
        selected_manifest_sha256: "12".repeat(32),
        effective_launch_sha384: "13".repeat(48),
        profile_sha384: "14".repeat(48),
        launch_policy_sha384: "15".repeat(48),
        image_policy_sha384: "16".repeat(48),
    };
    let digest = intent.digest_sha384().unwrap();
    ChallengeRecord {
        challenge: BootstrapChallenge {
            version: BOOTSTRAP_VERSION,
            validity: intent.validity,
            purpose: CHALLENGE_PURPOSE.into(),
            audience: "lab".into(),
            authority: "authority".into(),
            tenant: "tenant".into(),
            workload_id: "workload".into(),
            attempt_id: attempt.into(),
            challenge_id: format!("challenge-{random}"),
            nonce_hex: format!("{random:02x}").repeat(32),
            intent_sha384: digest.clone(),
            boot_profile_sha384: "17".repeat(48),
            producer_profile_sha384: "18".repeat(48),
        },
        grant_id: format!("grant-{random}"),
        signed_intent_json: signed(&intent, &intent.signing_bytes().unwrap(), 1),
        intent_sha384: digest,
    }
}
fn launch(record: &ChallengeRecord, bootstrap_context: &str) -> LaunchGrant {
    let intent: Signed<TenantIntent> = serde_json::from_slice(&record.signed_intent_json).unwrap();
    let i = intent.statement;
    LaunchGrant {
        version: VERSION,
        validity: record.challenge.validity,
        purpose: GRANT_PURPOSE.into(),
        audience: "lab".into(),
        proof_required: true,
        grant_id: record.grant_id.clone(),
        binding: LaunchBinding {
            authority: i.authority,
            tenant: i.tenant,
            workload_id: i.workload_id,
            container_role: i.container_role,
            attempt_id: i.attempt_id,
            boot_id: "boot-1".into(),
            channel_key_sha384: sha384(key(3).public_key().as_ref()),
            bootstrap_context_sha384: bootstrap_context.into(),
            selected_manifest_sha256: i.selected_manifest_sha256,
            effective_launch_sha384: i.effective_launch_sha384,
            profile_sha384: i.profile_sha384,
            launch_policy_sha384: i.launch_policy_sha384,
            image_policy_sha384: i.image_policy_sha384,
            challenge_sha384: record.challenge.digest_sha384().unwrap(),
        },
    }
}
fn issued_fixture(store: &Store, record: &ChallengeRecord) -> (IssuedRecord, LaunchGrant, Vec<u8>) {
    let context = "21".repeat(48);
    let grant = launch(record, &context);
    let wire = signed(&grant, &grant.signing_bytes().unwrap(), 2);
    let issued = store
        .issue_lab(
            &record.challenge.challenge_id,
            &record.challenge.digest_sha384().unwrap(),
            &context,
            &encoding(key(3).public_key().as_ref()),
            &wire,
            &grant.digest_sha384().unwrap(),
        )
        .unwrap();
    (issued, grant, wire)
}
fn policy_authorization_fixture(
    store: &Store,
    issued: &IssuedRecord,
    grant: &LaunchGrant,
) -> AdmissionAuthorizationV1 {
    use execution_proof_contract::policy_receipt::{
        PolicyCommitments, ResourcePolicyRequest, POLICY_AGGREGATE_PROFILE,
        POLICY_AGGREGATE_PURPOSE, POLICY_AGGREGATE_VERSION,
    };
    let expected = LaunchPolicyAggregateV1 {
        version: POLICY_AGGREGATE_VERSION,
        purpose: POLICY_AGGREGATE_PURPOSE.into(),
        audience: "lab-policy".into(),
        issuer: "kbs".into(),
        profile: POLICY_AGGREGATE_PROFILE.into(),
        grant_sha384: issued.grant_digest.clone(),
        authority_key_sha384: sha384(key(2).public_key().as_ref()),
        session_id: "31".repeat(32),
        nonce: "quote".into(),
        runtime_sha384: "32".repeat(48),
        init_data_sha384: "33".repeat(48),
        evidence_sha384: "34".repeat(48),
        recorder_key_sha384: sha384(key(3).public_key().as_ref()),
        request: ResourcePolicyRequest {
            method: "GET".into(),
            plugin: "resource".into(),
            resource_path: ["repo".into(), "key".into(), "v1".into()],
            workflow_id: "workflow".into(),
            request_nonce: "35".repeat(32),
        },
        as_evaluation: PolicyCommitments {
            policy_id: "launch_cpu".into(),
            policy_sha384: grant.binding.launch_policy_sha384.clone(),
            input_sha384: "36".repeat(48),
            data_sha384: None,
        },
        kbs_evaluation: PolicyCommitments {
            policy_id: "restricted_resource".into(),
            policy_sha384: "37".repeat(48),
            input_sha384: "38".repeat(48),
            data_sha384: Some("39".repeat(48)),
        },
    };
    let pin = PolicyPin {
        grant_id: grant.grant_id.clone(),
        expected_json: serde_json::to_vec(&expected).unwrap(),
        expected_digest: expected.digest_sha384().unwrap(),
        guest_nonce: "41".repeat(32),
        policy_digest: "42".repeat(48),
    };
    store.pin_policy(&pin).unwrap();
    // Internal database fixture, not a contract/producer verification test.
    // The public issuer path independently derives this complete template.
    AdmissionAuthorizationV1 {
        version: ADMISSION_VERSION,
        purpose: ADMISSION_PURPOSE.into(),
        audience: "guest".into(),
        issuer: "authority".into(),
        profile: ADMISSION_PROFILE.into(),
        grant_id: grant.grant_id.clone(),
        grant_sha384: issued.grant_digest.clone(),
        aggregate_sha384: pin.expected_digest.clone(),
        aggregate_key_sha384: sha384(key(4).public_key().as_ref()),
        context_sha384: "43".repeat(48),
        guest_nonce: pin.guest_nonce,
        admission_policy_sha384: pin.policy_digest,
        validity: grant.validity,
        binding: grant.binding.clone(),
    }
}

fn verified(grant: &LaunchGrant, wire: &[u8], policy: u8) -> VerifiedStatements {
    let evaluation = EvaluationCommitments {
        policy_id: "policy".into(),
        policy_sha384: format!("{policy:02x}").repeat(48),
        input_sha384: "31".repeat(48),
        rvps_sha384: "32".repeat(48),
        acceptance_policy_sha384: "33".repeat(48),
        kbs: KbsAssociation {
            decision_sha384: "34".repeat(48),
            policy_sha384: "35".repeat(48),
            input_sha384: "36".repeat(48),
            session_sha384: "37".repeat(48),
        },
    };
    let appraisal = ProofAppraisal {
        version: VERSION,
        purpose: APPRAISAL_PURPOSE.into(),
        audience: "lab".into(),
        issuer: "as".into(),
        verdict: AppraisalVerdict::Affirming,
        grant_sha384: grant.digest_sha384().unwrap(),
        binding: grant.binding.clone(),
        evaluation: evaluation.clone(),
    };
    let a_wire = signed(&appraisal, &appraisal.signing_bytes().unwrap(), 4);
    let expectations = TrustedExpectations {
        authority_public_key: key(2).public_key().as_ref().try_into().unwrap(),
        as_proof_public_key: key(4).public_key().as_ref().try_into().unwrap(),
        audience: "lab".into(),
        as_issuer: "as".into(),
        grant_id: grant.grant_id.clone(),
        binding: grant.binding.clone(),
        evaluation,
    };
    verify_statements(wire, &a_wire, &expectations).unwrap()
}

#[test]
fn reserve_retries_keep_original_randomness_and_capacity_survives_reopen() {
    let dir = TestDir::new();
    let path = dir.db();
    let first = candidate("attempt-1", 1);
    let store = initialize(&path, &identity(), 1).unwrap();
    assert_eq!(store.reserve_lab(&first).unwrap(), first);
    assert_eq!(
        store.reserve_lab(&candidate("attempt-1", 2)).unwrap(),
        first
    );
    let mut conflict = candidate("attempt-1", 3);
    conflict.challenge.boot_profile_sha384 = "99".repeat(48);
    assert!(matches!(
        store.reserve_lab(&conflict),
        Err(StoreError::Conflict)
    ));
    drop(store);
    let reopened = Store::open_existing(&path, &identity(), 1).unwrap();
    assert_eq!(
        reopened.challenge(&first.challenge.challenge_id).unwrap(),
        first
    );
    assert!(matches!(
        reopened.reserve_lab(&candidate("attempt-2", 4)),
        Err(StoreError::CapacityExhausted)
    ));
    assert!(matches!(
        initialize(&path, &identity(), 1),
        Err(StoreError::AlreadyExists)
    ));
}

#[test]
fn issuance_is_durable_exact_and_conflicting_enrollment_never_rearms() {
    let dir = TestDir::new();
    let path = dir.db();
    let first = candidate("attempt-1", 1);
    let store = initialize(&path, &identity(), 1).unwrap();
    store.reserve_lab(&first).unwrap();
    let (issued, grant, wire) = issued_fixture(&store, &first);
    drop(store);
    let store = Store::open_existing(&path, &identity(), 1).unwrap();
    assert_eq!(store.get_issued(&first.grant_id).unwrap(), issued);
    assert_eq!(
        store
            .issue_lab(
                &first.challenge.challenge_id,
                &first.challenge.digest_sha384().unwrap(),
                &issued.bootstrap_context_digest,
                &issued.recorder_public_key_hex,
                &wire,
                &grant.digest_sha384().unwrap()
            )
            .unwrap(),
        issued
    );
    assert!(matches!(
        store.issue_lab(
            &first.challenge.challenge_id,
            &first.challenge.digest_sha384().unwrap(),
            &"99".repeat(48),
            &issued.recorder_public_key_hex,
            &wire,
            &grant.digest_sha384().unwrap()
        ),
        Err(StoreError::Conflict)
    ));
    assert!(matches!(
        store.issue_lab(
            &first.challenge.challenge_id,
            &"99".repeat(48),
            &issued.bootstrap_context_digest,
            &issued.recorder_public_key_hex,
            &wire,
            &grant.digest_sha384().unwrap()
        ),
        Err(StoreError::Conflict)
    ));
    assert_eq!(store.get_issued(&first.grant_id).unwrap(), issued);
}

#[test]
fn independent_connections_reserve_one_persisted_challenge() {
    let dir = TestDir::new();
    let path = dir.db();
    drop(initialize(&path, &identity(), 1).unwrap());
    let barrier = Arc::new(Barrier::new(8));
    let mut workers = Vec::new();
    for i in 1..=8 {
        let path = path.clone();
        let barrier = barrier.clone();
        workers.push(thread::spawn(move || {
            let store = Store::open_existing(&path, &identity(), 1).unwrap();
            barrier.wait();
            store.reserve_lab(&candidate("attempt", i)).unwrap()
        }));
    }
    let rows: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert!(rows.iter().all(|row| row == &rows[0]));
    let reopened = Store::open_existing(&path, &identity(), 1).unwrap();
    assert_eq!(
        reopened.challenge(&rows[0].challenge.challenge_id).unwrap(),
        rows[0]
    );
}

#[test]
fn independent_connections_redeem_one_context_once_and_reopen_retains_it() {
    let dir = TestDir::new();
    let path = dir.db();
    let record = candidate("attempt", 1);
    let store = initialize(&path, &identity(), 1).unwrap();
    store.reserve_lab(&record).unwrap();
    let (_, grant, wire) = issued_fixture(&store, &record);
    drop(store);
    let barrier = Arc::new(Barrier::new(8));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let path = path.clone();
        let barrier = barrier.clone();
        let grant = grant.clone();
        let wire = wire.clone();
        workers.push(thread::spawn(move || {
            let store = Store::open_existing(&path, &identity(), 1).unwrap();
            let statements = verified(&grant, &wire, 0x30);
            barrier.wait();
            store.redeem_lab(&statements).unwrap()
        }));
    }
    let outcomes: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| **o == Redemption::FirstRedeemed)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| **o == Redemption::AlreadyRedeemed)
            .count(),
        7
    );
    let store = Store::open_existing(&path, &identity(), 1).unwrap();
    let statements = verified(&grant, &wire, 0x30);
    assert_eq!(
        store
            .status(&grant.grant_id, statements.context_digest())
            .unwrap(),
        RedemptionStatus::Redeemed
    );
    assert_eq!(
        store.redeem_lab(&statements).unwrap(),
        Redemption::AlreadyRedeemed
    );
    let changed = verified(&grant, &wire, 0x40);
    assert!(matches!(
        store.redeem_lab(&changed),
        Err(StoreError::Conflict)
    ));
    assert!(matches!(
        store.status(&grant.grant_id, changed.context_digest()),
        Err(StoreError::Conflict)
    ));
    assert!(matches!(
        store.reserve_lab(&candidate("next-attempt", 2)),
        Err(StoreError::CapacityExhausted)
    ));
}

#[test]
fn busy_timeout_does_not_mutate_and_dropped_transaction_rolls_back() {
    let dir = TestDir::new();
    let path = dir.db();
    let store = initialize(&path, &identity(), 2).unwrap();
    let blocker = Connection::open(&path).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(matches!(
        store.reserve_lab(&candidate("attempt", 1)),
        Err(StoreError::Busy)
    ));
    blocker.execute_batch("ROLLBACK").unwrap();
    let record = candidate("attempt", 1);
    store.reserve_lab(&record).unwrap();
    {
        let mut raw = Connection::open(&path).unwrap();
        let transaction = raw
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        transaction.execute("DELETE FROM challenges", []).unwrap();
    }
    drop(store);
    let reopened = Store::open_existing(&path, &identity(), 2).unwrap();
    assert_eq!(
        reopened.challenge(&record.challenge.challenge_id).unwrap(),
        record
    );
}

#[test]
fn missing_corrupt_schema_payload_and_wrong_identity_fail_closed() {
    let dir = TestDir::new();
    let path = dir.db();
    assert!(Store::open_existing(&path, &identity(), 1).is_err());
    assert!(!path.exists());
    let store = initialize(&path, &identity(), 1).unwrap();
    store.reserve_lab(&candidate("attempt", 1)).unwrap();
    drop(store);
    assert!(matches!(
        Store::open_existing(&path, &"22".repeat(48), 1),
        Err(StoreError::IdentityMismatch)
    ));
    assert!(matches!(
        Store::open_existing(&path, &identity(), 2),
        Err(StoreError::IdentityMismatch)
    ));
    let raw = Connection::open(&path).unwrap();
    raw.execute("UPDATE challenges SET intent_json=x'01'", [])
        .unwrap();
    drop(raw);
    assert!(matches!(
        Store::open_existing(&path, &identity(), 1),
        Err(StoreError::Corrupt)
    ));
    let other = dir.0.join("schema.sqlite");
    drop(initialize(&other, &identity(), 1).unwrap());
    let raw = Connection::open(&other).unwrap();
    raw.execute_batch("CREATE TABLE extra(x TEXT) STRICT")
        .unwrap();
    drop(raw);
    assert!(matches!(
        Store::open_existing(&other, &identity(), 1),
        Err(StoreError::Corrupt)
    ));
    std::fs::write(&path, b"not a SQLite database").unwrap();
    assert!(matches!(
        Store::open_existing(&path, &identity(), 1),
        Err(StoreError::Corrupt)
    ));
}

struct ManualClock {
    value: Mutex<Result<u64, ClockError>>,
    reads: std::sync::atomic::AtomicUsize,
}
impl ManualClock {
    fn new(now: u64) -> Self {
        Self {
            value: Mutex::new(Ok(now)),
            reads: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    fn set(&self, value: Result<u64, ClockError>) {
        *self.value.lock().unwrap() = value;
    }
}
impl IssuerClock for ManualClock {
    fn now_unix_seconds(&self) -> Result<u64, ClockError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        *self.value.lock().unwrap()
    }
}
fn issue_at(
    store: &Store,
    record: &ChallengeRecord,
    clock: &dyn IssuerClock,
) -> Result<IssueOutcome, StoreError> {
    let context = "21".repeat(48);
    let grant = launch(record, &context);
    let wire = signed(&grant, &grant.signing_bytes().unwrap(), 2);
    store.issue(
        &record.challenge.challenge_id,
        &record.challenge.digest_sha384().unwrap(),
        &context,
        &encoding(key(3).public_key().as_ref()),
        &wire,
        &grant.digest_sha384().unwrap(),
        clock,
    )
}

#[test]
fn clock_failures_do_not_create_or_reset_and_denials_preserve_high_water() {
    let dir = TestDir::new();
    let path = dir.db();
    let clock = ManualClock::new(500);
    clock.set(Err(ClockError::Unavailable));
    assert!(matches!(
        Store::initialize_new(&path, &identity(), 2, &clock),
        Err(StoreError::ClockUnavailable)
    ));
    assert!(!path.exists());
    clock.set(Ok(i64::MAX as u64 + 1));
    assert!(matches!(
        Store::initialize_new(&path, &identity(), 2, &clock),
        Err(StoreError::ClockOutOfRange)
    ));
    assert!(!path.exists());
    clock.set(Ok(500));
    let store = Store::initialize_new(&path, &identity(), 2, &clock).unwrap();
    clock.set(Ok(600));
    assert!(matches!(
        store.reserve(&candidate("early", 1), &clock, 30),
        Err(StoreError::NotYetValid)
    ));
    clock.set(Ok(599));
    assert!(matches!(
        store.reserve(&candidate("next", 2), &clock, 30),
        Err(StoreError::ClockRegression)
    ));
    drop(store);
    let reopened = Store::open_existing(&path, &identity(), 2).unwrap();
    clock.set(Err(ClockError::Unavailable));
    assert!(matches!(
        reopened.reserve(&candidate("next", 2), &clock, 30),
        Err(StoreError::ClockUnavailable)
    ));
    clock.set(Ok(599));
    assert!(matches!(
        reopened.reserve(&candidate("next", 2), &clock, 30),
        Err(StoreError::ClockRegression)
    ));
    clock.set(Ok(1000));
    let actual = reopened.reserve(&candidate("next", 2), &clock, 30).unwrap();
    assert_eq!(
        actual.challenge.validity,
        ValidityWindow {
            not_before: 1000,
            expires: 1030
        }
    );
    assert!(matches!(
        reopened.challenge("challenge-1"),
        Err(StoreError::NotFound)
    ));
}

#[test]
fn expiry_never_renews_pending_and_historical_issuance_does_not_read_clock() {
    let dir = TestDir::new();
    let path = dir.db();
    let clock = ManualClock::new(1000);
    let store = Store::initialize_new(&path, &identity(), 3, &clock).unwrap();
    let pending = store.reserve(&candidate("pending", 1), &clock, 30).unwrap();
    let issued = store.reserve(&candidate("issued", 2), &clock, 30).unwrap();
    let first = issue_at(&store, &issued, &clock).unwrap();
    assert_eq!(first.publication, GrantPublication::FirstIssued);
    clock.set(Ok(1030));
    assert!(matches!(
        store.reserve(&candidate("pending", 3), &clock, 30),
        Err(StoreError::Expired)
    ));
    assert_eq!(
        store.challenge(&pending.challenge.challenge_id).unwrap(),
        pending
    );
    assert!(matches!(
        issue_at(&store, &pending, &clock),
        Err(StoreError::Expired)
    ));
    assert!(matches!(
        store.get_issued(&pending.grant_id),
        Err(StoreError::NotFound)
    ));
    let reads = clock.reads.load(Ordering::SeqCst);
    clock.set(Err(ClockError::Unavailable));
    let retry = issue_at(&store, &issued, &clock).unwrap();
    assert_eq!(retry.publication, GrantPublication::Existing);
    assert_eq!(retry.record, first.record);
    assert_eq!(clock.reads.load(Ordering::SeqCst), reads);
    let grant = launch(&issued, &"21".repeat(48));
    let wire = signed(&grant, &grant.signing_bytes().unwrap(), 2);
    let statements = verified(&grant, &wire, 0x30);
    assert_eq!(
        store
            .status(&grant.grant_id, statements.context_digest())
            .unwrap(),
        RedemptionStatus::Issued
    );
    assert_eq!(clock.reads.load(Ordering::SeqCst), reads);
    clock.set(Ok(1029));
    assert!(matches!(
        store.redeem(&statements, &clock),
        Err(StoreError::ClockRegression)
    ));
}

thread_local! {
    static QUEUE_HOOK: std::cell::RefCell<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>> = const { std::cell::RefCell::new(None) };
}
thread_local! {
    static STATUS_READ_HOOK: std::cell::RefCell<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>> = const { std::cell::RefCell::new(None) };
}
pub(super) fn after_policy_status_first_read() {
    STATUS_READ_HOOK.with(|hook| {
        if let Some((read, resume)) = hook.borrow_mut().take() {
            read.send(()).unwrap();
            resume.recv_timeout(Duration::from_secs(5)).unwrap();
        }
    });
}

fn await_writer_release(_: i32) -> bool {
    QUEUE_HOOK.with(|hook| {
        if let Some((queued, released)) = hook.borrow_mut().take() {
            queued.send(()).unwrap();
            released.recv_timeout(Duration::from_secs(5)).unwrap();
            true
        } else {
            false
        }
    })
}

#[test]
fn first_redeem_samples_clock_after_writer_queue_crosses_expiry() {
    let dir = TestDir::new();
    let path = dir.db();
    let clock = Arc::new(ManualClock::new(1000));
    let store = Store::initialize_new(&path, &identity(), 2, clock.as_ref()).unwrap();
    let record = store
        .reserve(&candidate("queued", 1), clock.as_ref(), 30)
        .unwrap();
    issue_at(&store, &record, clock.as_ref()).unwrap();
    let grant = launch(&record, &"21".repeat(48));
    let wire = signed(&grant, &grant.signing_bytes().unwrap(), 2);
    let statements = verified(&grant, &wire, 0x30);
    let worker_store = Store::open_existing(&path, &identity(), 2).unwrap();
    worker_store
        .connection
        .lock()
        .unwrap()
        .busy_handler(Some(await_writer_release))
        .unwrap();
    let blocker = Connection::open(&path).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let (queued_tx, queued_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let worker_clock = clock.clone();
    let reads = clock.reads.load(Ordering::SeqCst);
    let worker = thread::spawn(move || {
        QUEUE_HOOK.with(|hook| *hook.borrow_mut() = Some((queued_tx, release_rx)));
        worker_store.redeem(&statements, worker_clock.as_ref())
    });
    queued_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        clock.reads.load(Ordering::SeqCst),
        reads,
        "clock sampled before SQLite writer acquisition"
    );
    clock.set(Ok(1030));
    blocker.execute_batch("ROLLBACK").unwrap();
    release_tx.send(()).unwrap();
    assert!(matches!(worker.join().unwrap(), Err(StoreError::Expired)));
    let current = store.get_issued(&grant.grant_id).unwrap();
    assert!(current.redemption_context.is_none());
    drop(store);
    let reopened = Store::open_existing(&path, &identity(), 2).unwrap();
    clock.set(Ok(1029));
    assert!(matches!(
        reopened.reserve(&candidate("later", 2), clock.as_ref(), 30),
        Err(StoreError::ClockRegression)
    ));
}

#[test]
fn policy_receipt_signing_waits_for_writer_and_expiry_keeps_both_slots_empty() {
    let dir = TestDir::new();
    let path = dir.db();
    let clock = Arc::new(ManualClock::new(1000));
    let authority: [u8; 32] = key(2).public_key().as_ref().try_into().unwrap();
    let store =
        Store::initialize_new_policy(&path, &identity(), 2, clock.as_ref(), authority).unwrap();
    let reservation = store
        .reserve(&candidate("queued-policy", 1), clock.as_ref(), 30)
        .unwrap();
    let issued = issue_at(&store, &reservation, clock.as_ref())
        .unwrap()
        .record;
    let grant = launch(&reservation, &"21".repeat(48));
    let early = verified(&grant, &issued.signed_grant_json, 1);
    assert!(matches!(
        store.redeem(&early, clock.as_ref()),
        Err(StoreError::InvalidInput)
    ));
    assert!(matches!(
        store.status(early.grant_id(), early.context_digest()),
        Err(StoreError::InvalidInput)
    ));
    assert!(store
        .get_issued(early.grant_id())
        .unwrap()
        .redemption_context
        .is_none());
    let template = policy_authorization_fixture(&store, &issued, &grant);
    let worker_store = Store::open_existing_policy(&path, &identity(), 2, authority).unwrap();
    worker_store
        .connection
        .lock()
        .unwrap()
        .busy_handler(Some(await_writer_release))
        .unwrap();
    let blocker = Connection::open(&path).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let (queued_tx, queued_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let worker_clock = clock.clone();
    let reads = clock.reads.load(Ordering::SeqCst);
    let id = template.grant_id.clone();
    let worker = thread::spawn(move || {
        QUEUE_HOOK.with(|hook| *hook.borrow_mut() = Some((queued_tx, release_rx)));
        worker_store.redeem_policy(&template, &key(2), worker_clock.as_ref())
    });
    queued_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(clock.reads.load(Ordering::SeqCst), reads);
    clock.set(Ok(1030));
    blocker.execute_batch("ROLLBACK").unwrap();
    release_tx.send(()).unwrap();
    assert!(matches!(worker.join().unwrap(), Err(StoreError::Expired)));
    assert!(store.get_issued(&id).unwrap().redemption_context.is_none());
    assert!(read_policy_pin(&store.connection.lock().unwrap(), &id)
        .unwrap()
        .1
        .is_none());
    drop(store);
    let reopened = Store::open_existing_policy(&path, &identity(), 2, authority).unwrap();
    clock.set(Ok(1029));
    assert!(matches!(
        reopened.reserve(&candidate("after-policy-denial", 2), clock.as_ref(), 30),
        Err(StoreError::ClockRegression)
    ));
}

#[test]
fn policy_status_keeps_one_read_snapshot_during_cross_connection_redemption() {
    let dir = TestDir::new();
    let path = dir.db();
    let authority: [u8; 32] = key(2).public_key().as_ref().try_into().unwrap();
    let writer =
        Store::initialize_new_policy(&path, &identity(), 2, &FixedClock, authority).unwrap();
    let reservation = writer
        .reserve_lab(&candidate("status-snapshot", 1))
        .unwrap();
    let (issued, grant, _) = issued_fixture(&writer, &reservation);
    let template = policy_authorization_fixture(&writer, &issued, &grant);
    let reader_store = Store::open_existing_policy(&path, &identity(), 2, authority).unwrap();
    // No timing assumption: a competing commit either succeeds between the
    // old autocommit reads or reports Busy while the fixed snapshot is live.
    writer
        .connection
        .lock()
        .unwrap()
        .busy_timeout(Duration::ZERO)
        .unwrap();
    let (read_tx, read_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let reader_template = template.clone();
    let reader = thread::spawn(move || {
        STATUS_READ_HOOK.with(|hook| *hook.borrow_mut() = Some((read_tx, resume_rx)));
        reader_store.policy_status(&reader_template)
    });
    read_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let concurrent_redemption = writer.redeem_policy(&template, &key(2), &FixedClock);
    resume_tx.send(()).unwrap();
    let reader_status = reader.join().unwrap();
    if let Err(error) = &reader_status {
        eprintln!("status during cross-connection redemption: {error}");
    }
    assert!(
        matches!(reader_status, Ok(None)),
        "status must retain the pending snapshot read before redemption"
    );
    assert!(matches!(concurrent_redemption, Err(StoreError::Busy)));
    assert!(writer
        .get_issued(&template.grant_id)
        .unwrap()
        .redemption_context
        .is_none());
    let publication = writer
        .redeem_policy(&template, &key(2), &FixedClock)
        .unwrap();
    assert_eq!(
        publication.publication,
        AdmissionPublicationKind::FirstAuthorized
    );
    assert_eq!(
        writer.policy_status(&template).unwrap(),
        Some(publication.bytes.clone())
    );
    let retry = writer
        .redeem_policy(&template, &key(2), &FixedClock)
        .unwrap();
    assert_eq!(retry.publication, AdmissionPublicationKind::Existing);
    assert_eq!(retry.bytes, publication.bytes);
}

#[test]
fn consumed_history_works_with_failed_clock_and_old_schema_is_not_migrated() {
    let dir = TestDir::new();
    let path = dir.db();
    let clock = ManualClock::new(1000);
    let store = Store::initialize_new(&path, &identity(), 1, &clock).unwrap();
    let record = store.reserve(&candidate("history", 1), &clock, 30).unwrap();
    issue_at(&store, &record, &clock).unwrap();
    let grant = launch(&record, &"21".repeat(48));
    let wire = signed(&grant, &grant.signing_bytes().unwrap(), 2);
    let statements = verified(&grant, &wire, 0x30);
    assert_eq!(
        store.redeem(&statements, &clock).unwrap(),
        Redemption::FirstRedeemed
    );
    let reads = clock.reads.load(Ordering::SeqCst);
    clock.set(Err(ClockError::Unavailable));
    assert_eq!(
        store.redeem(&statements, &clock).unwrap(),
        Redemption::AlreadyRedeemed
    );
    assert_eq!(clock.reads.load(Ordering::SeqCst), reads);
    assert_eq!(
        store
            .status(&grant.grant_id, statements.context_digest())
            .unwrap(),
        RedemptionStatus::Redeemed
    );
    drop(store);
    let raw = Connection::open(&path).unwrap();
    raw.pragma_update(None, "user_version", 1).unwrap();
    drop(raw);
    assert!(matches!(
        Store::open_existing(&path, &identity(), 1),
        Err(StoreError::Corrupt)
    ));
    let raw = Connection::open(&path).unwrap();
    let version: i64 = raw
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 1);
}
