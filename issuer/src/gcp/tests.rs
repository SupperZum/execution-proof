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
        evaluation_time_unix_seconds: 150,
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
        4
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
    let s = submission(&challenge.statement);
    let first = i
        .issue_checked(&challenge.statement.challenge_id, &s, checked)
        .unwrap();
    assert_eq!(first.publication, GrantPublication::FirstIssued);
    let second = i
        .issue_checked(&challenge.statement.challenge_id, &s, checked)
        .unwrap();
    assert_eq!(second.publication, GrantPublication::Existing);
    assert_eq!(first.signed_grant_json, second.signed_grant_json);
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
    let c = config();
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
}

#[test]
fn qualification_expiring_during_hardware_check_cannot_publish_a_grant() {
    let d = TestDir::new();
    let c = config();
    let clock = Arc::new(ManualClock::new(150));
    let i = issuer(&d, c.clone(), clock.clone());
    let challenge = i.begin(&intent(&c, "attempt-one")).unwrap();
    let submission = submission(&challenge.statement);
    assert!(i
        .issue_checked(&challenge.statement.challenge_id, &submission, |r| {
            clock.set(Ok(240));
            checked(r)
        })
        .is_err());
    assert!(i
        .store
        .get_issued(
            &i.store
                .challenge(&challenge.statement.challenge_id)
                .unwrap()
                .grant_id
        )
        .is_err());
}
#[test]
fn gcp_policy_admission_consumes_once_and_historical_status_survives_failed_clock() {
    let d = TestDir::new();
    let c = config();
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
    clock.set(Ok(240));
    assert!(i.redeem_policy_aggregate(&id, &a, &wire).is_err());
    assert!(i.begin(&intent(&c, "later")).is_err());
    assert_eq!(
        i.status_policy_aggregate(&id, &a, &status)
            .unwrap()
            .unwrap(),
        first.signed_authorization_json
    );
    clock.set(Err(ClockError::Unavailable));
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
