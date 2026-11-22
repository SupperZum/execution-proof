//! Software fixtures only. No fixture signing key or fake QVL dispatch is
//! compiled into a non-test build.

use super::*;
use execution_proof_contract::{
    bootstrap::{TenantIntent, TENANT_INTENT_PURPOSE},
    gcp_bootstrap::{
        bootstrap_possession_signing_bytes, report_data, GCP_BOOTSTRAP_BINDING_PURPOSE,
    },
    gcp_profile::{
        GcpProducerQualificationV1, GcpQualificationEvidenceRefs, GCP_QUALIFICATION_CLAIM,
        GCP_QUALIFICATION_PROFILE, GCP_QUALIFICATION_PURPOSE,
    },
    policy_receipt::{PolicyCommitments, ResourcePolicyRequest},
    ValidityWindow,
};
use execution_proof_verifier::{
    gcp_boot_evidence::{check_boot_evidence, GcpInstanceIdentity, QuotePaddingPolicy},
    gcp_tdx_policy::{
        GCP_TDX_ALLOWED_ATTRIBUTES, GCP_TDX_POLICY_PURPOSE, INTEL_TDX_MODULE_1_5_34_MR_SEAM,
    },
    gcp_worker_protocol::GcpHardwareFacts,
};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "onb17-gcp-issuer-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn db(&self) -> PathBuf {
        self.0.join("issuer.sqlite")
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
struct Steps(Mutex<std::collections::VecDeque<Result<u64, ClockError>>>);
impl IssuerClock for Steps {
    fn now_unix_seconds(&self) -> Result<u64, ClockError> {
        self.0
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected clock sample")
    }
}
struct ManualClock(Mutex<Result<u64, ClockError>>);
impl ManualClock {
    fn new(now: u64) -> Self {
        Self(Mutex::new(Ok(now)))
    }
    fn set(&self, value: Result<u64, ClockError>) {
        *self.0.lock().unwrap() = value;
    }
}
impl IssuerClock for ManualClock {
    fn now_unix_seconds(&self) -> Result<u64, ClockError> {
        *self.0.lock().unwrap()
    }
}
fn key(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}
fn pubkey(seed: u8) -> [u8; 32] {
    public_key(&key(seed)).unwrap()
}
fn signed<T: Serialize + Clone>(s: &T, bytes: &[u8], seed: u8) -> Vec<u8> {
    serde_json::to_vec(&Signed {
        statement: s.clone(),
        signature: hex(key(seed).sign(bytes).as_ref()),
    })
    .unwrap()
}
fn config() -> GcpIssuerConfig {
    let boot_binding = GcpBootBindingV1::new([1; 48], [2; 48], [3; 48], [4; 48]).unwrap();
    let boot_policy=GcpBootEvidencePolicy {
        expected_pe_sha384:"c4240c5a835ca1c7b6b9c3dd762477870ba5b7a295ec0f551eb45d442be8926b3d887ea59fa348ff5e8832aaf595c8b4".into(),
        expected_firmware_mrtd:"f21e6b48743fe14c2d090078ca1197f09ae4c99438677f2c79901ef80e2aeefe2f9a7eb6e3eb3b5047c4f1511731e5d3".into(),
        expected_instance:GcpInstanceIdentity{instance_id:1159420029374854386,numerical_project_id:876967775446,zone:"us-central1-a".into()},quote_padding:QuotePaddingPolicy::GcpTsmZeroPadded8000,
    };
    let module_policy = GcpTdxModulePolicyV1 {
        version: 1,
        purpose: GCP_TDX_POLICY_PURPOSE.into(),
        expected_mr_seam: INTEL_TDX_MODULE_1_5_34_MR_SEAM.into(),
        allowed_td_attributes: GCP_TDX_ALLOWED_ATTRIBUTES,
    };
    GcpIssuerConfig {
        authorization_ttl_secs: 120,
        authority: "authority-one".into(),
        tenant: "tenant-one".into(),
        audience: "launch".into(),
        tenant_public_key: pubkey(2),
        qualification: GcpQualificationExpectations {
            qualification_public_key: pubkey(4),
            issuer: "reviewed-profile-authority".into(),
            boot_binding_sha384: boot_binding.digest_sha384().unwrap(),
            pe_sha384: boot_policy.expected_pe_sha384.clone(),
            firmware_mrtd: boot_policy.expected_firmware_mrtd.clone(),
            module_policy_sha384: hash(&module_policy.encode().unwrap()),
            evidence_refs: GcpQualificationEvidenceRefs {
                artifact_closure_sha384: "31".repeat(48),
                firmware_causality_sha384: "32".repeat(48),
                producer_isolation_sha384: "33".repeat(48),
                no_state_copy_sha384: "34".repeat(48),
                qualification_review_sha384: "35".repeat(48),
            },
        },
        boot_binding,
        boot_policy,
        module_policy,
        launch_policy_sha384: "41".repeat(48),
        image_policy_sha384: "42".repeat(48),
        policy_admission: GcpPolicyAdmissionConfig {
            kbs_proof_public_key: pubkey(3),
            aggregate_audience: "policy-proof".into(),
            aggregate_issuer: "kbs".into(),
            as_policy_id: "launch-policy".into(),
            as_policy_sha384: "41".repeat(48),
            as_data_sha384: None,
            kbs_policy_id: "resource-policy".into(),
            kbs_policy_sha384: "43".repeat(48),
            resource_path: ["repo".into(), "image".into(), "key".into()],
            workflow_id: "kms-direct".into(),
            receipt_audience: "cdh".into(),
        },
        pregrant_worker_path: "/bin/true".into(),
        pregrant_worker_sha384: hash(&std::fs::read("/bin/true").unwrap()),
        collateral_json: b"{}".to_vec(),
    }
}
fn qualification(c: &GcpIssuerConfig) -> Vec<u8> {
    let e = &c.qualification;
    let s = GcpProducerQualificationV1 {
        version: 1,
        purpose: GCP_QUALIFICATION_PURPOSE.into(),
        profile: GCP_QUALIFICATION_PROFILE.into(),
        claim: GCP_QUALIFICATION_CLAIM.into(),
        qualification_id: "SOFTWARE-FIXTURE-NOT-DEPLOYED".into(),
        issuer: e.issuer.clone(),
        boot_binding_sha384: e.boot_binding_sha384.clone(),
        pe_sha384: e.pe_sha384.clone(),
        firmware_mrtd: e.firmware_mrtd.clone(),
        module_policy_sha384: e.module_policy_sha384.clone(),
        evidence_refs: e.evidence_refs.clone(),
        validity: ValidityWindow {
            not_before: 100,
            expires: 240,
        },
    };
    signed(&s, &s.signing_bytes().unwrap(), 4)
}
fn issuer(dir: &TestDir, c: GcpIssuerConfig, clock: Arc<ManualClock>) -> GcpIssuer {
    let q = qualification(&c);
    GcpIssuer::initialize_new_with_clock(&dir.db(), c, &q, key(1), 16, clock).unwrap()
}
fn intent(c: &GcpIssuerConfig, attempt: &str) -> Vec<u8> {
    let s = TenantIntent {
        version: 2,
        purpose: TENANT_INTENT_PURPOSE.into(),
        audience: c.audience.clone(),
        authority: c.authority.clone(),
        tenant: c.tenant.clone(),
        workload_id: "workload-one".into(),
        container_role: "application-init".into(),
        attempt_id: attempt.into(),
        selected_manifest_sha256: "51".repeat(32),
        effective_launch_sha384: "52".repeat(48),
        profile_sha384: c.boot_binding.digest_sha384().unwrap(),
        launch_policy_sha384: c.launch_policy_sha384.clone(),
        image_policy_sha384: c.image_policy_sha384.clone(),
        validity: ValidityWindow {
            not_before: 100,
            expires: 500,
        },
    };
    signed(&s, &s.signing_bytes().unwrap(), 2)
}
fn submission(challenge: &GcpBootstrapChallenge) -> GcpBootstrapSubmission {
    let keywrap_public_key = TeePubKey::RSA {
        alg: "RSA-OAEP-256".into(),
        k_mod: URL_SAFE_NO_PAD.encode([0xff; 256]),
        k_exp: "AQAB".into(),
    };
    let binding = GcpBootstrapBinding {
        version: 3,
        purpose: GCP_BOOTSTRAP_BINDING_PURPOSE.into(),
        challenge_sha384: challenge.digest_sha384().unwrap(),
        boot_binding_sha384: challenge.boot_binding.digest_sha384().unwrap(),
        boot_id: "boot-one".into(),
        boot_nonce_hex: "61".repeat(32),
        recorder_key_sha384: hash(&pubkey(5)),
        keywrap_key_sha384: keywrap_digest(&keywrap_public_key).unwrap(),
    };
    let mut evidence = GcpLaunchEvidenceV2::new(
        include_bytes!("../../../verifier/tests/fixtures/gcp_boot_v1/baseline-quote.bin").to_vec(),
        include_bytes!("../../../verifier/tests/fixtures/gcp_boot_v1/baseline-acpi-ccel.bin")
            .to_vec(),
        include_bytes!("../../../verifier/tests/fixtures/gcp_boot_v1/baseline-ccel.bin").to_vec(),
    )
    .unwrap();
    // Changes invalidate the Intel signature. Only the private software test
    // dispatch below supplies a Checked response; production always runs QVL.
    evidence.tdx_quote[568..632].copy_from_slice(&report_data(challenge, &binding).unwrap());
    let possession_signature_hex = hex(key(5)
        .sign(&bootstrap_possession_signing_bytes(challenge, &binding, &evidence).unwrap())
        .as_ref());
    GcpBootstrapSubmission {
        binding,
        evidence,
        recorder_public_key: pubkey(5),
        possession_signature_hex,
        keywrap_public_key,
    }
}
fn checked(r: &GcpPregrantRequest) -> Result<GcpPregrantResponse, GcpIssuerError> {
    let s = check_boot_evidence(
        &r.evidence.ccel_table,
        &r.evidence.ccel_log,
        &r.evidence.tdx_quote,
        &r.derived_report_data().unwrap(),
        &r.boot_policy,
    )
    .unwrap();
    let q = s.quote;
    let facts = GcpHardwareFacts {
        quote_sha384: hex(&q.quote_sha384),
        report_data: hex(&q.report_data),
        boot_binding_sha384: r.boot_binding_sha384().unwrap(),
        mr_config_id: hex(&q.mr_config_id),
        mr_td: hex(&q.mr_td),
        mr_owner: hex(&q.mr_owner),
        mr_seam: hex(&q.mr_seam),
        td_attributes: q.td_attributes,
        rtmrs: q.rtmrs.map(|v| hex(&v)),
        event_count: s.event_count,
        evaluation_time_unix_seconds: r.expected_challenge.validity.not_before,
    };
    Ok(GcpPregrantResponse::new(
        r,
        GcpHardwareStatus::Checked,
        "SOFTWARE_TEST_ONLY",
        Some(facts),
    )
    .unwrap())
}
fn issue_fixture(i: &GcpIssuer) -> (IssuedGrant, GcpBootstrapSubmission) {
    let c = i.begin(&intent(&i.config, "attempt-one")).unwrap();
    let s = submission(&c.statement);
    let g = i
        .issue_checked(&c.statement.challenge_id, &s, checked)
        .unwrap();
    (g, s)
}
fn aggregate(i: &GcpIssuer, grant: &VerifiedLaunchGrant) -> GcpLaunchPolicyAggregateV2 {
    let p = &i.config.policy_admission;
    GcpLaunchPolicyAggregateV2 {
        version: 2,
        purpose: execution_proof_contract::gcp_policy_receipt::POLICY_AGGREGATE_PURPOSE.into(),
        profile: POLICY_AGGREGATE_PROFILE.into(),
        audience: p.aggregate_audience.clone(),
        issuer: p.aggregate_issuer.clone(),
        grant_sha384: grant.grant_digest().into(),
        authority_key_sha384: grant.authority_key_sha384().into(),
        session_id: "71".repeat(32),
        nonce: "session-nonce".into(),
        runtime_sha384: "72".repeat(48),
        boot_binding_sha384: i.config.boot_binding.digest_sha384().unwrap(),
        evidence_sha384: "73".repeat(48),
        recorder_key_sha384: grant.binding().channel_key_sha384.clone(),
        request: ResourcePolicyRequest {
            resource_path: p.resource_path.clone(),
            workflow_id: p.workflow_id.clone(),
            method: "GET".into(),
            plugin: "resource".into(),
            request_nonce: "74".repeat(32),
        },
        as_evaluation: PolicyCommitments {
            policy_id: p.as_policy_id.clone(),
            policy_sha384: p.as_policy_sha384.clone(),
            input_sha384: "75".repeat(48),
            data_sha384: p.as_data_sha384.clone(),
        },
        kbs_evaluation: PolicyCommitments {
            policy_id: p.kbs_policy_id.clone(),
            policy_sha384: p.kbs_policy_sha384.clone(),
            input_sha384: "76".repeat(48),
            data_sha384: None,
        },
    }
}
fn policy_wires(
    i: &GcpIssuer,
    g: &IssuedGrant,
    operation: GcpAdmissionOperation,
) -> (String, Vec<u8>, Vec<u8>) {
    let signed_grant: Signed<LaunchGrant> = serde_json::from_slice(&g.signed_grant_json).unwrap();
    let id = signed_grant.statement.grant_id;
    let (_, grant) = i.grant(&id).unwrap();
    let a = aggregate(i, &grant);
    let nonce = "81".repeat(32);
    i.pin_policy_admission(&id, &a, &nonce).unwrap();
    let a_wire = signed(&a, &a.signing_bytes().unwrap(), 3);
    let verified = verify_policy_aggregate(
        &a_wire,
        &grant,
        &GcpAggregateExpectations {
            kbs_proof_public_key: pubkey(3),
            boot_binding: i.config.boot_binding.clone(),
            expected: a,
        },
    )
    .unwrap();
    let req = GcpAdmissionRequestV2::new(
        &grant,
        &verified,
        &nonce,
        i.admission_policy_sha384(),
        &i.config.audience,
        operation,
    )
    .unwrap();
    (id, a_wire, signed(&req, &req.signing_bytes().unwrap(), 5))
}

#[test]
fn qualification_and_separate_roots_are_required_before_database_creation() {
    let d = TestDir::new();
    let mut c = config();
    let q = qualification(&c);
    c.qualification.qualification_public_key = pubkey(1);
    assert!(GcpIssuer::initialize_new_with_clock(
        &d.db(),
        c,
        &q,
        key(1),
        16,
        Arc::new(ManualClock::new(150))
    )
    .is_err());
    assert!(!d.db().exists());
    let mut c = config();
    c.qualification.qualification_public_key = pubkey(1);
    let raw: Signed<GcpProducerQualificationV1> =
        serde_json::from_slice(&qualification(&c)).unwrap();
    let same_authority = signed(&raw.statement, &raw.statement.signing_bytes().unwrap(), 1);
    assert!(matches!(
        GcpIssuer::initialize_new_with_clock(
            &d.db(),
            c,
            &same_authority,
            key(1),
            16,
            Arc::new(ManualClock::new(150))
        ),
        Err(GcpIssuerError::Issuer(Error::InvalidConfiguration))
    ));
    assert!(!d.db().exists());
    let c = config();
    assert!(GcpIssuer::initialize_new_with_clock(
        &d.db(),
        c.clone(),
        &qualification(&c),
        key(1),
        16,
        Arc::new(ManualClock::new(240))
    )
    .is_err());
    assert!(!d.db().exists());
    let mut c = config();
    c.module_policy.allowed_td_attributes = 0;
    assert!(GcpIssuer::initialize_new_with_clock(
        &d.db(),
        c.clone(),
        &qualification(&config()),
        key(1),
        16,
        Arc::new(ManualClock::new(150))
    )
    .is_err());
    assert!(!d.db().exists());
}
#[test]
fn retries_publish_only_gcp_challenge_and_clip_window_to_qualification() {
    let d = TestDir::new();
    let c = config();
    let i = issuer(&d, c.clone(), Arc::new(ManualClock::new(150)));
    let wire = intent(&c, "attempt-one");
    let a = i.begin(&wire).unwrap();
    let b = i.begin(&wire).unwrap();
    assert_eq!(a.statement, b.statement);
    assert_eq!(a.signature, b.signature);
    assert_eq!(
        a.statement.validity,
        ValidityWindow {
            not_before: 150,
            expires: 240
        }
    );
    assert_eq!(a.statement.version, 3);
    let connection = rusqlite::Connection::open(d.db()).unwrap();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        5
    );
    assert!(store::Store::open_existing(&d.db(), &"11".repeat(48), 16).is_err());
}
#[test]
fn private_software_issue_binds_actual_capture_and_is_durable_byte_stable() {
    let d = TestDir::new();
    let c = config();
    let clock = Arc::new(ManualClock::new(150));
    let i = issuer(&d, c.clone(), clock.clone());
    let challenge = i.begin(&intent(&c, "attempt-one")).unwrap();
    let journal = JournalFixture::default();
    i.journal_begin(&journal, &challenge.statement.challenge_id)
        .unwrap();
    let s = submission(&challenge.statement);
    let first = i
        .issue_checked(&challenge.statement.challenge_id, &s, checked)
        .unwrap();
    assert_eq!(first.publication, GrantPublication::FirstIssued);
    assert!(i
        .journal_issue(
            &journal,
            &challenge.statement.challenge_id,
            &first.signed_grant_json
        )
        .unwrap());
    // The caller lost the publication response and resubmits the same capture.
    let second = i
        .issue_checked(&challenge.statement.challenge_id, &s, checked)
        .unwrap();
    assert_eq!(second.publication, GrantPublication::Existing);
    assert_eq!(first.signed_grant_json, second.signed_grant_json);
    assert!(!i
        .journal_issue(
            &journal,
            &challenge.statement.challenge_id,
            &second.signed_grant_json
        )
        .unwrap());
    let rows: (i64, i64) = rusqlite::Connection::open(d.db())
        .unwrap()
        .query_row(
            "SELECT count(*), count(grant_json) FROM challenges",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(rows, (1, 1));
    let l: Signed<LaunchGrant> = serde_json::from_slice(&first.signed_grant_json).unwrap();
    assert_eq!(
        l.statement.binding.challenge_sha384,
        challenge.statement.digest_sha384().unwrap()
    );
    assert_eq!(
        l.statement.binding.bootstrap_context_sha384,
        bootstrap_context_sha384(&challenge.statement, &s.binding, &s.evidence).unwrap()
    );
    drop(i);
    let reopened = GcpIssuer::open_existing_with_clock(
        &d.db(),
        c.clone(),
        &qualification(&c),
        key(1),
        16,
        clock,
    )
    .unwrap();
    assert_eq!(
        reopened
            .grant(&l.statement.grant_id)
            .unwrap()
            .1
            .grant_digest(),
        l.statement.digest_sha384().unwrap()
    );
}
#[test]
fn bad_possession_keywrap_or_unproven_hardware_never_issues() {
    let d = TestDir::new();
    let c = config();
    let i = issuer(&d, c.clone(), Arc::new(ManualClock::new(150)));
    let challenge = i.begin(&intent(&c, "attempt-one")).unwrap();
    let mut bad = submission(&challenge.statement);
    bad.possession_signature_hex = "00".repeat(64);
    assert!(i
        .issue_checked(&challenge.statement.challenge_id, &bad, checked)
        .is_err());
    let mut bad = submission(&challenge.statement);
    bad.keywrap_public_key = TeePubKey::RSA {
        alg: "RSA1_5".into(),
        k_mod: URL_SAFE_NO_PAD.encode([0xff; 256]),
        k_exp: "AQAB".into(),
    };
    assert!(i
        .issue_checked(&challenge.statement.challenge_id, &bad, checked)
        .is_err());
    let s = submission(&challenge.statement);
    assert!(matches!(
        i.issue_checked(&challenge.statement.challenge_id, &s, |r| Ok(
            GcpPregrantResponse::new(r, GcpHardwareStatus::Unproven, "not_available", None)
                .unwrap()
        )),
        Err(GcpIssuerError::HardwareUnavailable)
    ));
    let r = i
        .store
        .challenge(&challenge.statement.challenge_id)
        .unwrap();
    assert!(i.store.get_issued(&r.grant_id).is_err());
}
#[test]
fn public_issue_always_uses_pinned_process_not_software_dispatch() {
    let d = TestDir::new();
    let mut c = config();
    c.pregrant_worker_path = "/bin/false".into();
    c.pregrant_worker_sha384 = hash(&std::fs::read(&c.pregrant_worker_path).unwrap());
    let i = issuer(&d, c.clone(), Arc::new(ManualClock::new(150)));
    let challenge = i.begin(&intent(&c, "attempt-one")).unwrap();
    let s = submission(&challenge.statement);
    assert!(matches!(
        i.issue(&challenge.statement.challenge_id, &s),
        Err(GcpIssuerError::HardwareUnavailable)
    ));
    assert!(i
        .store
        .get_issued(
            &i.store
                .challenge(&challenge.statement.challenge_id)
                .unwrap()
                .grant_id
        )
        .is_err());
    check_foreign_digest_rejection();
}

fn check_foreign_digest_rejection() {
    let d = TestDir::new();
    let mut c = config();
    let source = d.0.join("foreign-response.c");
    let response = serde_json::json!({
        "version": 3, "purpose": "qlad.execution-proof.gcp-pregrant-hardware-response.v3",
        "request_sha384": "00".repeat(48), "status": "unproven", "reason": "fixture", "facts": null
    });
    std::fs::write(&source, format!(
        "#include <stdio.h>\nint main(void) {{ while (getchar() != EOF) {{}} puts({:?}); return 0; }}\n",
        response.to_string()
    )).unwrap();
    c.pregrant_worker_path = d.0.join("worker");
    assert!(std::process::Command::new("cc")
        .arg(&source)
        .arg("-o")
        .arg(&c.pregrant_worker_path)
        .status()
        .unwrap()
        .success());
    c.pregrant_worker_sha384 = hash(&std::fs::read(&c.pregrant_worker_path).unwrap());
    let i = issuer(&d, c.clone(), Arc::new(ManualClock::new(150)));
    let challenge = i.begin(&intent(&c, "attempt-one")).unwrap();
    let id = &challenge.statement.challenge_id;
    let submission = submission(&challenge.statement);
    assert!(matches!(
        i.issue(id, &submission),
        Err(GcpIssuerError::HardwareRejected)
    ));
    let grant_id = i.store.challenge(id).unwrap().grant_id;
    assert!(i.store.get_issued(&grant_id).is_err());
    assert!(matches!(
        i.issue_checked(id, &submission, |_| Err(WorkerError::Deadline.into())),
        Err(GcpIssuerError::HardwareUnavailable)
    ));
    assert!(i.store.get_issued(&grant_id).is_err());
}

#[test]
fn qualification_expiring_during_hardware_check_cannot_publish_a_grant() {
    let d = TestDir::new();
    let c = config();
    let clock = Arc::new(ManualClock::new(150));
    let i = issuer(&d, c.clone(), clock.clone());
    let challenge = i.begin(&intent(&c, "attempt-one")).unwrap();
    let submission = submission(&challenge.statement);
    assert!(matches!(
        i.issue_checked(&challenge.statement.challenge_id, &submission, |r| {
            clock.set(Ok(240));
            checked(r)
        }),
        Err(GcpIssuerError::Issuer(Error::Contract(
            execution_proof_contract::Error::Expired
        )))
    ));
    let reservation = i
        .store
        .challenge(&challenge.statement.challenge_id)
        .unwrap();
    assert!(matches!(
        i.store.get_issued(&reservation.grant_id),
        Err(StoreError::NotFound)
    ));
    clock.set(Ok(239));
    assert!(matches!(
        i.begin(&intent(&c, "another-attempt")),
        Err(GcpIssuerError::Issuer(Error::Store(
            StoreError::ClockRegression
        )))
    ));
}
#[test]
fn gcp_policy_admission_consumes_once_and_historical_status_survives_failed_clock() {
    let d = TestDir::new();
    let mut c = config();
    c.pregrant_worker_path = d.0.join("worker");
    std::fs::copy("/bin/true", &c.pregrant_worker_path).unwrap();
    let clock = Arc::new(ManualClock::new(150));
    let i = issuer(&d, c.clone(), clock.clone());
    let (g, _) = issue_fixture(&i);
    let (id, a, wire) = policy_wires(&i, &g, GcpAdmissionOperation::Redeem);
    let first = i.redeem_policy_aggregate(&id, &a, &wire).unwrap();
    assert_eq!(first.publication, AdmissionPublicationKind::FirstAuthorized);
    let second = i.redeem_policy_aggregate(&id, &a, &wire).unwrap();
    assert_eq!(second.publication, AdmissionPublicationKind::Existing);
    assert_eq!(
        first.signed_authorization_json,
        second.signed_authorization_json
    );
    let (_, _, status) = policy_wires(&i, &g, GcpAdmissionOperation::Status);
    let later_intent = intent(&c, "later");
    clock.set(Ok(240));
    assert!(matches!(
        i.redeem_policy_aggregate(&id, &a, &wire),
        Err(GcpIssuerError::Issuer(Error::Contract(
            execution_proof_contract::Error::Expired
        )))
    ));
    clock.set(Ok(241));
    assert!(matches!(
        i.begin(&later_intent),
        Err(GcpIssuerError::Issuer(Error::Contract(
            execution_proof_contract::Error::Expired
        )))
    ));
    assert_eq!(
        i.status_policy_aggregate(&id, &a, &status)
            .unwrap()
            .unwrap(),
        first.signed_authorization_json
    );
    drop(i);
    clock.set(Err(ClockError::Unavailable));
    let reopened = GcpIssuer::open_existing_with_clock(
        &d.db(),
        c.clone(),
        &qualification(&c),
        key(1),
        16,
        clock.clone(),
    )
    .unwrap();
    clock.set(Ok(239));
    assert!(matches!(
        reopened.begin(&later_intent),
        Err(GcpIssuerError::Issuer(Error::Store(
            StoreError::ClockRegression
        )))
    ));
    let db = rusqlite::Connection::open(d.db()).unwrap();
    let persisted: (i64, i64, i64, i64) = db
        .query_row(
            "SELECT last_seen_unix_seconds,
                    (SELECT count(*) FROM challenges),
                    (SELECT count(grant_json) FROM challenges),
                    (SELECT count(receipt_json) FROM policy_admissions)
             FROM store_meta WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(persisted, (241, 1, 1, 1));

    drop(reopened);
    std::fs::remove_file(&c.pregrant_worker_path).unwrap();
    clock.set(Err(ClockError::Unavailable));
    assert!(matches!(
        GcpIssuer::open_existing_with_clock(
            &d.db(),
            c.clone(),
            &qualification(&c),
            key(1),
            16,
            clock.clone()
        ),
        Err(GcpIssuerError::HardwareUnavailable)
    ));
    let historical = GcpIssuer::open(
        &d.db(),
        c.clone(),
        &qualification(&c),
        key(1),
        16,
        clock.clone(),
        OpenMode::HistoricalStatus,
        None,
    )
    .unwrap();
    assert!(historical.status_policy_aggregate(&id, &a, &wire).is_err());
    assert_eq!(
        historical
            .status_policy_aggregate(&id, &a, &status)
            .unwrap()
            .unwrap(),
        first.signed_authorization_json
    );
}
#[test]
fn policy_substitution_wrong_request_domain_and_changed_profile_are_rejected() {
    let d = TestDir::new();
    let c = config();
    let clock = Arc::new(ManualClock::new(150));
    let i = issuer(&d, c.clone(), clock.clone());
    let (g, _) = issue_fixture(&i);
    let (id, a, wire) = policy_wires(&i, &g, GcpAdmissionOperation::Redeem);
    let mut parsed: Signed<GcpLaunchPolicyAggregateV2> = serde_json::from_slice(&a).unwrap();
    parsed.statement.kbs_evaluation.input_sha384 = "99".repeat(48);
    let replaced = signed(
        &parsed.statement,
        &parsed.statement.signing_bytes().unwrap(),
        3,
    );
    assert!(i.redeem_policy_aggregate(&id, &replaced, &wire).is_err());
    let mut req: Signed<GcpAdmissionRequestV2> = serde_json::from_slice(&wire).unwrap();
    req.statement.operation = GcpAdmissionOperation::Status;
    assert!(i
        .redeem_policy_aggregate(
            &id,
            &a,
            &signed(&req.statement, &req.statement.signing_bytes().unwrap(), 5)
        )
        .is_err());
    drop(i);
    let mut changed = c.clone();
    changed.boot_policy.expected_instance.instance_id += 1;
    assert!(GcpIssuer::open_existing_with_clock(
        &d.db(),
        changed,
        &qualification(&c),
        key(1),
        16,
        clock
    )
    .is_err());
}

#[test]
fn startup_plan_rejects_clock_regression_but_historical_status_returns_the_receipt() {
    let d = TestDir::new();
    let mut c = config();
    c.authorization_ttl_secs = 20;
    let clock = Arc::new(ManualClock::new(150));
    let i = issuer(&d, c.clone(), clock.clone());
    let (issued, _) = issue_fixture(&i);
    let (id, aggregate, redeem) = policy_wires(&i, &issued, GcpAdmissionOperation::Redeem);
    let (_, _, status) = policy_wires(&i, &issued, GcpAdmissionOperation::Status);
    let receipt = i.redeem_policy_aggregate(&id, &aggregate, &redeem).unwrap();

    // Another reservation records the first grant's expiry in the shared store.
    clock.set(Ok(170));
    i.begin(&intent(&c, "attempt-two")).unwrap();
    drop(i);
    clock.set(Ok(160));
    let i = GcpIssuer::open_existing_with_clock(
        &d.db(),
        c.clone(),
        &qualification(&c),
        key(1),
        16,
        clock,
    )
    .unwrap();
    assert!(matches!(
        i.startup_plan(&id, &aggregate, "application", &"91".repeat(48), "auditor"),
        Err(GcpIssuerError::Issuer(Error::Store(
            StoreError::ClockRegression
        )))
    ));
    assert_eq!(
        i.status_policy_aggregate(&id, &aggregate, &status).unwrap(),
        Some(receipt.signed_authorization_json)
    );
}

#[test]
fn startup_plan_signs_only_stored_grant_and_actual_configured_kbs_aggregate() {
    let d = TestDir::new();
    let clock = Arc::new(ManualClock::new(150));
    let i = issuer(&d, config(), clock.clone());
    let (issued, _) = issue_fixture(&i);
    let wire: Signed<LaunchGrant> = serde_json::from_slice(&issued.signed_grant_json).unwrap();
    let id = &wire.statement.grant_id;
    let (_, grant) = i.grant(id).unwrap();
    let a = aggregate(&i, &grant);
    let a_bytes = signed(&a, &a.signing_bytes().unwrap(), 3);
    let plan = i
        .startup_plan(id, &a_bytes, "application", &"91".repeat(48), "auditor")
        .unwrap();
    let verified_a = verify_policy_aggregate(
        &a_bytes,
        &grant,
        &GcpAggregateExpectations {
            kbs_proof_public_key: pubkey(3),
            boot_binding: i.config.boot_binding.clone(),
            expected: a.clone(),
        },
    )
    .unwrap();
    let checked = execution_proof_contract::gcp_startup::verify_attempt_plan(
        &plan,
        &i.authority_public_key(),
        &grant,
        &verified_a,
        &i.config.boot_binding,
    )
    .unwrap();
    let retry = i
        .startup_plan(id, &a_bytes, "application", &"91".repeat(48), "auditor")
        .unwrap();
    let retried = execution_proof_contract::gcp_startup::verify_attempt_plan(
        &retry,
        &i.authority_public_key(),
        &grant,
        &verified_a,
        &i.config.boot_binding,
    )
    .unwrap();
    assert_ne!(checked.execution_nonce_hex, retried.execution_nonce_hex);
    assert_eq!(checked.admission_policy_sha384, i.admission_policy_sha384());
    assert_eq!(
        checked.effective_spec_sha384,
        grant.binding().effective_launch_sha384
    );
    assert_eq!(checked.container_id, "application");
    assert_eq!(checked.execution_audience, "auditor");
    assert!(matches!(i.store.policy_pin(id), Err(StoreError::NotFound)));
    assert!(i.store.get_issued(id).unwrap().redemption_context.is_none());
    assert!(i
        .startup_plan(
            id,
            &signed(&a, &a.signing_bytes().unwrap(), 9),
            "application",
            &"91".repeat(48),
            "auditor"
        )
        .is_err());
    let mut wrong = a;
    wrong.as_evaluation.policy_sha384 = "99".repeat(48);
    assert!(i
        .startup_plan(
            id,
            &signed(&wrong, &wrong.signing_bytes().unwrap(), 3),
            "application",
            &"91".repeat(48),
            "auditor"
        )
        .is_err());
    assert!(i
        .startup_plan(id, &a_bytes, "../escape", &"91".repeat(48), "auditor")
        .is_err());
    assert!(i
        .startup_plan(id, &a_bytes, "application", &"00".repeat(48), "auditor")
        .is_err());
    assert!(i
        .startup_plan(id, &a_bytes, "application", &"91".repeat(48), "")
        .is_err());
    clock.set(Ok(240));
    assert!(i
        .startup_plan(id, &a_bytes, "application", &"91".repeat(48), "auditor")
        .is_err());
}

mod journal_fixture {
    use execution_proof_gcp_journal::{Entry, Error as JournalError, PublicationJournal};
    use std::{cell::RefCell, collections::BTreeMap};

    type Records = BTreeMap<(String, Vec<u8>), (Vec<u8>, Vec<u8>)>;
    #[derive(Default)]
    pub(super) struct JournalFixture {
        pub(super) pin_uploads: std::cell::Cell<usize>,
        pub(super) lose_reserve_readback: std::cell::Cell<bool>,
        pub(super) fail_consume: std::cell::Cell<bool>,
        records: RefCell<Records>,
    }
    impl PublicationJournal for JournalFixture {
        fn publish(
            &self,
            stage: &str,
            identity: &[u8],
            binding: &[u8],
            payload: &[u8],
            window: Option<(u64, u64)>,
        ) -> Result<Entry, JournalError> {
            if stage == "consume" && self.fail_consume.get() {
                return Err(JournalError::Unavailable);
            }
            if stage == "pin" {
                self.pin_uploads.set(self.pin_uploads.get() + 1);
            }
            if let Some(payload) = self.read(stage, identity, binding, window)? {
                return Ok(Entry {
                    first: false,
                    payload,
                });
            }
            self.records.borrow_mut().insert(
                (stage.into(), identity.to_vec()),
                (binding.to_vec(), payload.to_vec()),
            );
            if stage == "reserve" && self.lose_reserve_readback.replace(false) {
                return Err(JournalError::Unavailable);
            }
            Ok(Entry {
                first: true,
                payload: payload.to_vec(),
            })
        }

        fn read(
            &self,
            stage: &str,
            identity: &[u8],
            binding: &[u8],
            _: Option<(u64, u64)>,
        ) -> Result<Option<Vec<u8>>, JournalError> {
            match self
                .records
                .borrow()
                .get(&(stage.into(), identity.to_vec()))
            {
                Some((saved, payload)) if saved == binding => Ok(Some(payload.clone())),
                Some(_) => Err(JournalError::Conflict),
                None => Ok(None),
            }
        }
    }
}
use journal_fixture::JournalFixture;

fn pin_request(
    grant_id: &str,
    expected: &GcpLaunchPolicyAggregateV2,
    nonce: &str,
) -> serde_json::Value {
    serde_json::json!({"operation":"pin_policy_admission","grant_id":grant_id,
        "expected":expected,"guest_nonce":nonce})
}

#[test]
fn expired_grant_blocks_first_local_pin_and_first_journal_upload() {
    use crate::gcp_operator::{dispatch, PublicError, REQUEST_PURPOSE};

    for local_pin in [false, true] {
        let directory = TestDir::new();
        let clock = Arc::new(ManualClock::new(150));
        let mut c = config();
        c.authorization_ttl_secs = 20;
        let issuer = issuer(&directory, c, clock.clone());
        let journal = JournalFixture::default();
        let (issued, _) = issue_fixture(&issuer);
        let signed: Signed<LaunchGrant> =
            serde_json::from_slice(&issued.signed_grant_json).unwrap();
        let id = &signed.statement.grant_id;
        let (record, grant) = issuer.grant(id).unwrap();
        let challenge = &record.reservation.challenge.challenge_id;
        issuer.journal_begin(&journal, challenge).unwrap();
        issuer
            .journal_issue(&journal, challenge, &issued.signed_grant_json)
            .unwrap();
        let expected = aggregate(&issuer, &grant);
        let nonce = "81".repeat(32);
        if local_pin {
            // Recovery after the local commit, before the first external write.
            issuer.pin_policy_admission(id, &expected, &nonce).unwrap();
        }
        let expiry = grant.validity().expires;
        issuer.qualification.validity().check_at(expiry).unwrap();
        clock.set(Ok(expiry));
        let wire = serde_json::to_vec(&serde_json::json!({
            "version":1, "purpose":REQUEST_PURPOSE, "request":pin_request(id,&expected,&nonce)
        }))
        .unwrap();
        assert!(matches!(
            dispatch(&issuer, &wire, Some(&journal)),
            Err(PublicError::RequestExpired)
        ));
        assert_eq!(journal.pin_uploads.get(), 0);
        let count: i64 = rusqlite::Connection::open(directory.db())
            .unwrap()
            .query_row("SELECT count(*) FROM policy_admissions", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, i64::from(local_pin));
    }
}

#[test]
fn stdio_dispatch_only_publishes_committed_journal_results() {
    use crate::gcp_operator::{dispatch, PublicError, ResponseBody, REQUEST_PURPOSE};

    let directory = TestDir::new();
    let mut config = config();
    config.authorization_ttl_secs = 20;
    let clock = Arc::new(ManualClock::new(150));
    let issuer = issuer(&directory, config.clone(), clock.clone());
    let journal = JournalFixture::default();
    let snapshot = |directory: &TestDir| {
        let copy = TestDir::new();
        rusqlite::Connection::open(directory.db())
            .unwrap()
            .execute("VACUUM INTO ?1", [copy.db().to_str().unwrap()])
            .unwrap();
        copy
    };
    let reopen = |copy: &TestDir| {
        GcpIssuer::open_existing_with_clock(
            &copy.db(),
            config.clone(),
            &qualification(&config),
            key(1),
            16,
            clock.clone(),
        )
        .unwrap()
    };
    let before_reserve = snapshot(&directory);
    let call = |issuer: &GcpIssuer, request| {
        let wire = serde_json::to_vec(&serde_json::json!({
            "version": 1, "purpose": REQUEST_PURPOSE, "request": request,
        }))
        .unwrap();
        dispatch(issuer, &wire, Some(&journal)).map(|response| response.result)
    };
    let begin =
        serde_json::json!({"operation":"begin","signed_intent_json":intent(&config,"attempt-one")});
    journal.lose_reserve_readback.set(true);
    assert!(matches!(
        call(&issuer, begin.clone()),
        Err(PublicError::JournalUnavailable)
    ));
    clock.set(Ok(151));
    let Ok(ResponseBody::Challenge {
        signed_challenge_json,
    }) = call(&issuer, begin.clone())
    else {
        panic!("expected a committed challenge");
    };
    let Ok(ResponseBody::Challenge {
        signed_challenge_json: retry,
    }) = call(&issuer, begin.clone())
    else {
        panic!("expected the same challenge after retry");
    };
    assert_eq!(retry, signed_challenge_json);
    assert!(matches!(
        call(&reopen(&before_reserve), begin),
        Err(PublicError::StateRejected)
    ));

    // The pregrant fixture checks software inputs before returning its fixed verdict.
    let (grant, _) = issue_fixture(&issuer);
    let challenge: Signed<GcpBootstrapChallenge> =
        serde_json::from_slice(&signed_challenge_json).unwrap();
    assert_eq!(challenge.statement.validity.not_before, 150);
    let (grant_id, aggregate, redeem) =
        policy_wires(&issuer, &grant, GcpAdmissionOperation::Redeem);
    let (_, _, status) = policy_wires(&issuer, &grant, GcpAdmissionOperation::Status);
    let redeem = serde_json::json!({"operation":"redeem_policy_aggregate","grant_id":grant_id,
        "aggregate_json":aggregate,"recorder_request_json":redeem});
    let status = serde_json::json!({"operation":"status_policy_aggregate","grant_id":grant_id,
        "aggregate_json":aggregate,"recorder_request_json":status});
    assert!(matches!(
        call(&issuer, redeem.clone()),
        Err(PublicError::StateRejected)
    ));
    assert!(issuer
        .journal_issue(
            &journal,
            &challenge.statement.challenge_id,
            &grant.signed_grant_json
        )
        .unwrap());
    assert!(matches!(
        call(&issuer, redeem.clone()),
        Err(PublicError::StateRejected)
    ));
    let signed: Signed<GcpLaunchPolicyAggregateV2> = serde_json::from_slice(&aggregate).unwrap();
    let expected = signed.statement;
    let nonce = "81".repeat(32);
    let pin = pin_request(&grant_id, &expected, &nonce);
    for _ in 0..2 {
        assert!(matches!(
            call(&issuer, pin.clone()),
            Ok(ResponseBody::PolicyPinned)
        ));
    }
    let mut changed = expected.clone();
    changed.evidence_sha384 = "82".repeat(48);
    for conflict in [
        pin_request(&grant_id, &expected, &"82".repeat(32)),
        pin_request(&grant_id, &changed, &nonce),
    ] {
        assert!(matches!(
            call(&issuer, conflict),
            Err(PublicError::StateRejected)
        ));
    }
    assert!(matches!(
        call(&issuer, pin.clone()),
        Ok(ResponseBody::PolicyPinned)
    ));
    assert_eq!(journal.pin_uploads.get(), 1);

    let before_consume = snapshot(&directory);

    assert!(matches!(
        call(&issuer, status.clone()),
        Ok(ResponseBody::PolicyStatus {
            signed_authorization_json: None
        })
    ));
    journal.fail_consume.set(true);
    assert!(matches!(
        call(&issuer, redeem.clone()),
        Err(PublicError::JournalUnavailable)
    ));
    assert!(issuer
        .store
        .get_issued(&grant_id)
        .unwrap()
        .redemption_context
        .is_some());
    assert!(matches!(
        call(&issuer, status.clone()),
        Ok(ResponseBody::PolicyStatus {
            signed_authorization_json: None
        })
    ));
    journal.fail_consume.set(false);
    let Ok(ResponseBody::Admission {
        signed_authorization_json,
        publication: crate::gcp_operator::Publication::FirstAuthorized,
    }) = call(&issuer, redeem.clone())
    else {
        panic!("expected first journaled receipt");
    };
    let Ok(ResponseBody::Admission {
        signed_authorization_json: retry,
        publication: crate::gcp_operator::Publication::Existing,
    }) = call(&issuer, redeem)
    else {
        panic!("expected existing journaled receipt");
    };
    assert_eq!(retry, signed_authorization_json);
    let expires = challenge.statement.validity.expires;
    issuer.qualification.validity().check_at(expires).unwrap();
    clock.set(Ok(expires));
    assert!(matches!(call(&issuer, pin), Ok(ResponseBody::PolicyPinned)));
    assert_eq!(journal.pin_uploads.get(), 1);
    clock.set(Err(ClockError::Unavailable));
    let restored = reopen(&before_consume);
    assert_eq!(
        restored
            .status_policy_aggregate(
                &grant_id,
                &aggregate,
                &serde_json::from_value::<Vec<u8>>(status["recorder_request_json"].clone())
                    .unwrap(),
            )
            .unwrap(),
        None
    );
    assert!(
        matches!(call(&restored, status), Ok(ResponseBody::PolicyStatus { signed_authorization_json: Some(receipt) }) if receipt == signed_authorization_json)
    );
}

#[test]
fn challenge_expiry_and_invalid_submission_stop_before_worker() {
    use crate::gcp_operator::PublicError;
    let dir = TestDir::new();
    let mut cfg = config();
    cfg.authorization_ttl_secs = 10;
    let clock = Arc::new(ManualClock::new(150));
    let issuer = issuer(&dir, cfg.clone(), clock.clone());
    let challenge = issuer
        .begin(&intent(&cfg, "attempt-one"))
        .unwrap()
        .statement;
    let original = submission(&challenge);
    let mut bad_pop = submission(&challenge);
    bad_pop.possession_signature_hex = "00".repeat(64);
    let mut bad_wrap = submission(&challenge);
    bad_wrap.binding.keywrap_key_sha384 = "00".repeat(48);
    let run = |input: &GcpBootstrapSubmission| {
        issuer
            .issue_checked(&challenge.challenge_id, input, |_| {
                panic!("unexpected worker invocation")
            })
            .map_err(PublicError::from)
            .unwrap_err()
    };
    assert_eq!(run(&bad_pop), PublicError::RequestRejected);
    assert_eq!(run(&bad_wrap), PublicError::RequestRejected);
    clock.set(Ok(challenge.validity.expires));
    issuer.require_live_qualification().unwrap();
    assert_eq!(run(&original), PublicError::RequestExpired);
}

#[test]
fn clock_failure_before_or_inside_reserve_has_the_same_public_code() {
    use crate::gcp_operator::PublicError;
    for samples in [
        vec![Err(ClockError::Unavailable)],
        vec![Ok(150), Err(ClockError::Unavailable)],
    ] {
        let dir = TestDir::new();
        let cfg = config();
        let mut authority = issuer(&dir, cfg.clone(), Arc::new(ManualClock::new(150)));
        authority.clock = Arc::new(Steps(Mutex::new(samples.into())));
        assert_eq!(
            authority
                .begin(&intent(&cfg, "clock"))
                .map_err(PublicError::from)
                .unwrap_err(),
            PublicError::ClockUnavailable
        );
        let db = rusqlite::Connection::open(dir.db()).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM challenges", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}

#[test]
#[ignore = "requires a built GCP_AUTHORITY_TEST_BIN and the GKE controller Python dependencies"]
fn real_cli_and_serial_adapter_recover_one_committed_receipt() {
    use execution_proof_contract::gcp_profile::GcpProducerQualificationV1;
    use std::os::unix::fs::PermissionsExt;
    let binary = std::env::var("GCP_AUTHORITY_TEST_BIN").unwrap();
    let dir = TestDir::new();
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut cfg = config();
    cfg.pregrant_worker_path = dir.0.join("worker");
    std::fs::copy("/bin/true", &cfg.pregrant_worker_path).unwrap();
    let now = SystemClock.now_unix_seconds().unwrap();
    let window = ValidityWindow {
        not_before: now - 1,
        expires: now + 120,
    };
    let mut q: Signed<GcpProducerQualificationV1> =
        serde_json::from_slice(&qualification(&cfg)).unwrap();
    q.statement.validity = window;
    let q = signed(&q.statement, &q.statement.signing_bytes().unwrap(), 4);
    let mut tenant: Signed<TenantIntent> =
        serde_json::from_slice(&intent(&cfg, "recovery")).unwrap();
    tenant.statement.validity = window;
    let tenant = signed(
        &tenant.statement,
        &tenant.statement.signing_bytes().unwrap(),
        2,
    );
    let private = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let signer = Ed25519KeyPair::from_pkcs8(private.as_ref()).unwrap();
    let issuer = GcpIssuer::initialize_new(&dir.db(), cfg.clone(), &q, signer, 32).unwrap();
    let challenge = issuer.begin(&tenant).unwrap();
    let g = issuer
        .issue_checked(
            &challenge.statement.challenge_id,
            &submission(&challenge.statement),
            checked,
        )
        .unwrap();
    let (_, aggregate, redeem) = policy_wires(&issuer, &g, GcpAdmissionOperation::Redeem);
    let (_, _, status) = policy_wires(&issuer, &g, GcpAdmissionOperation::Status);
    drop(issuer);
    for (name, bytes) in [
        ("signed_q", q),
        ("authority_key", private.as_ref().to_vec()),
        ("collateral", std::mem::take(&mut cfg.collateral_json)),
        ("issuer_config", serde_json::to_vec(&cfg).unwrap()),
        ("intent", tenant),
        ("grant", g.signed_grant_json),
        ("aggregate", aggregate),
        ("redeem", redeem),
        ("status", status),
    ] {
        let path = dir.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let gke = Path::new(env!("CARGO_MANIFEST_DIR")).join("../integration/gke");
    let python = std::env::var_os("GCP_RECOVERY_TEST_PYTHON").unwrap_or_else(|| "python3".into());
    let result = std::process::Command::new(python)
        .arg(gke.join("tests/recover_committed_admission.py"))
        .arg(&dir.0)
        .arg(binary)
        .env("PYTHONPATH", gke.join("tools/controller"))
        .status()
        .unwrap();
    assert!(result.success());
}

#[test]
fn startup_plan_checks_grant_expiry_at_the_final_signing_clock_sample() {
    let dir = TestDir::new();
    let mut config = config();
    config.authorization_ttl_secs = 10;
    let mut issuer = issuer(&dir, config, Arc::new(ManualClock::new(150)));
    let (issued, _) = issue_fixture(&issuer);
    let grant: Signed<LaunchGrant> = serde_json::from_slice(&issued.signed_grant_json).unwrap();
    let id = &grant.statement.grant_id;
    let (_, verified) = issuer.grant(id).unwrap();
    let aggregate = aggregate(&issuer, &verified);
    let raw = signed(&aggregate, &aggregate.signing_bytes().unwrap(), 3);
    let expires = grant.statement.validity.expires;
    issuer.qualification.validity().check_at(expires).unwrap();
    issuer.clock = Arc::new(Steps(Mutex::new([Ok(expires - 1), Ok(expires)].into())));
    let result = issuer.startup_plan(id, &raw, "application", &"91".repeat(48), "auditor");
    assert_eq!(
        result
            .map_err(crate::gcp_operator::PublicError::from)
            .unwrap_err(),
        crate::gcp_operator::PublicError::RequestExpired
    );
}
