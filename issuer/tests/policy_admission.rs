//! Durable policy admission with real signatures and physical SQLite files.
//! Aggregates are signed software fixtures; no TEE or execution is claimed.

mod support;
use execution_proof_contract::{
    admission::{policy_admission_context, verify_admission_authorization, AdmissionExpectations},
    policy_receipt::{
        verify_policy_aggregate, AggregateExpectations, LaunchPolicyAggregateV1, PolicyCommitments,
        ResourcePolicyRequest, POLICY_AGGREGATE_PROFILE, POLICY_AGGREGATE_PURPOSE,
        POLICY_AGGREGATE_VERSION,
    },
    verify_launch_grant_historical, GrantExpectations, LaunchGrant, Signed, VerifiedLaunchGrant,
};
use execution_proof_handoff::admission::{
    AdmissionCheck, GateStatus, GuestAdmissionConfig, GuestAdmissionError, GuestAdmissionGate,
};
use execution_proof_issuer::{
    AdmissionPublicationKind, ClockError, Error, PolicyAdmissionConfig, RecorderRequest,
    SoftwareIssuer, StoreError, POLICY_REDEEM_PURPOSE, POLICY_STATUS_PURPOSE, REDEEM_PURPOSE,
    REQUEST_VERSION, STATUS_PURPOSE,
};
use std::sync::{Arc, Barrier};
use support::{hash, signed, Fixture, Key};

struct Lab {
    base: Fixture,
    kbs: Key,
}
struct Case {
    grant: VerifiedLaunchGrant,
    aggregate: LaunchPolicyAggregateV1,
    aggregate_wire: Vec<u8>,
    nonce: String,
    context: String,
    grant_wire: Vec<u8>,
}
impl Lab {
    fn new() -> Self {
        Self {
            base: Fixture::new(),
            kbs: Key::new(),
        }
    }
    fn config(&self) -> PolicyAdmissionConfig {
        let base = self.base.config();
        PolicyAdmissionConfig {
            kbs_proof_public_key: self.kbs.public(),
            aggregate_audience: "policy-auditor".into(),
            aggregate_issuer: "software-kbs-producer".into(),
            aggregate_profile: POLICY_AGGREGATE_PROFILE.into(),
            as_policy_id: "launch_cpu".into(),
            as_policy_sha384: base.launch_policy_sha384,
            as_data_sha384: Some(hash("static-as-data")),
            kbs_policy_id: "restricted_resource".into(),
            kbs_policy_sha384: base.kbs_policy_sha384,
            init_data_sha384: hash("measured-init-data"),
            resource_path: ["tenant-a".into(), "image-key".into(), "v1".into()],
            workflow_id: "image-decrypt-policy".into(),
            receipt_audience: "guest-admission".into(),
        }
    }
    fn create(&self) -> SoftwareIssuer {
        SoftwareIssuer::initialize_new_with_policy_admission_and_clock(
            &self.base.db(),
            self.base.config(),
            self.config(),
            self.base.authority.pair(),
            8,
            self.base.clock.clone(),
        )
        .unwrap()
    }
    fn reopen(&self) -> SoftwareIssuer {
        SoftwareIssuer::open_existing_with_policy_admission_and_clock(
            &self.base.db(),
            self.base.config(),
            self.config(),
            self.base.authority.pair(),
            8,
            self.base.clock.clone(),
        )
        .unwrap()
    }
    fn case(&self, issuer: &SoftwareIssuer, attempt: &str) -> Case {
        let enrollment = self.base.enrollment(issuer, attempt);
        let grant_wire = enrollment.issue(issuer);
        let base = self.base.config();
        let grant = verify_launch_grant_historical(
            &grant_wire,
            &GrantExpectations {
                authority_public_key: self.base.authority.public(),
                audience: base.audience,
                authority: base.authority,
                tenant: base.tenant,
                profile_sha384: base.profile_sha384,
                launch_policy_sha384: base.launch_policy_sha384,
                image_policy_sha384: base.image_policy_sha384,
            },
        )
        .unwrap();
        let policy = self.config();
        let aggregate = LaunchPolicyAggregateV1 {
            version: POLICY_AGGREGATE_VERSION,
            purpose: POLICY_AGGREGATE_PURPOSE.into(),
            audience: policy.aggregate_audience,
            issuer: policy.aggregate_issuer,
            profile: policy.aggregate_profile,
            grant_sha384: grant.grant_digest().into(),
            authority_key_sha384: grant.authority_key_sha384().into(),
            session_id: "31".repeat(32),
            nonce: format!("quote-{attempt}"),
            runtime_sha384: hash(&format!("runtime-{attempt}")),
            init_data_sha384: policy.init_data_sha384,
            evidence_sha384: hash(&format!("evidence-{attempt}")),
            recorder_key_sha384: grant.binding().channel_key_sha384.clone(),
            request: ResourcePolicyRequest {
                method: "GET".into(),
                plugin: "resource".into(),
                resource_path: policy.resource_path,
                workflow_id: policy.workflow_id,
                request_nonce: "32".repeat(32),
            },
            as_evaluation: PolicyCommitments {
                policy_id: policy.as_policy_id,
                policy_sha384: policy.as_policy_sha384,
                input_sha384: hash(&format!("as-input-{attempt}")),
                data_sha384: policy.as_data_sha384,
            },
            kbs_evaluation: PolicyCommitments {
                policy_id: policy.kbs_policy_id,
                policy_sha384: policy.kbs_policy_sha384,
                input_sha384: hash(&format!("kbs-input-{attempt}")),
                data_sha384: Some(hash(&format!("request-data-{attempt}"))),
            },
        };
        let aggregate_wire = signed(&aggregate, &aggregate.signing_bytes().unwrap(), &self.kbs);
        let verified = verify_policy_aggregate(
            &aggregate_wire,
            &grant,
            &AggregateExpectations {
                kbs_proof_public_key: self.kbs.public(),
                expected: aggregate.clone(),
            },
        )
        .unwrap();
        let nonce = "41".repeat(32);
        let context = policy_admission_context(
            &grant,
            &verified,
            &nonce,
            issuer.admission_policy_sha384().unwrap(),
        )
        .unwrap();
        Case {
            grant,
            aggregate,
            aggregate_wire,
            nonce,
            context,
            grant_wire,
        }
    }
    fn request(&self, case: &Case, purpose: &str, key: &Key) -> Vec<u8> {
        let request = RecorderRequest {
            version: REQUEST_VERSION,
            purpose: purpose.into(),
            audience: self.base.config().audience,
            grant_sha384: case.grant.grant_digest().into(),
            context_sha384: case.context.clone(),
        };
        signed(&request, &request.signing_bytes().unwrap(), key)
    }
    fn pin(&self, issuer: &SoftwareIssuer, case: &Case) {
        issuer
            .pin_policy_admission(case.grant.grant_id(), &case.aggregate, &case.nonce)
            .unwrap();
    }
}

#[test]
fn immutable_pin_durable_receipt_and_historical_reopen_preserve_exact_bytes() {
    let lab = Lab::new();
    let issuer = lab.create();
    let case = lab.case(&issuer, "one");
    let request = lab.request(&case, POLICY_REDEEM_PURPOSE, &lab.base.recorder);
    assert!(matches!(
        issuer.redeem_policy_aggregate(case.grant.grant_id(), &case.aggregate_wire, &request),
        Err(Error::Store(StoreError::NotFound))
    ));
    lab.pin(&issuer, &case);
    lab.pin(&issuer, &case);
    let mut changed = case.aggregate.clone();
    changed.evidence_sha384 = hash("other-evidence");
    assert!(matches!(
        issuer.pin_policy_admission(case.grant.grant_id(), &changed, &case.nonce),
        Err(Error::Store(StoreError::Conflict))
    ));
    assert!(issuer
        .pin_policy_admission(case.grant.grant_id(), &case.aggregate, &"42".repeat(32))
        .is_err());
    let status = lab.request(&case, POLICY_STATUS_PURPOSE, &lab.base.recorder);
    assert!(issuer
        .status_policy_aggregate(case.grant.grant_id(), &case.aggregate_wire, &status)
        .unwrap()
        .is_none());
    let first = issuer
        .redeem_policy_aggregate(case.grant.grant_id(), &case.aggregate_wire, &request)
        .unwrap();
    assert_eq!(first.publication, AdmissionPublicationKind::FirstAuthorized);
    let aggregate = verify_policy_aggregate(
        &case.aggregate_wire,
        &case.grant,
        &AggregateExpectations {
            kbs_proof_public_key: lab.kbs.public(),
            expected: case.aggregate.clone(),
        },
    )
    .unwrap();
    let verified = verify_admission_authorization(
        &first.signed_authorization_json,
        &case.grant,
        &aggregate,
        &AdmissionExpectations {
            authority_public_key: lab.base.authority.public(),
            aggregate: AggregateExpectations {
                kbs_proof_public_key: lab.kbs.public(),
                expected: case.aggregate.clone(),
            },
            audience: lab.config().receipt_audience,
            issuer: lab.base.config().authority,
            boot_id: case.grant.binding().boot_id.clone(),
            attempt_id: case.grant.binding().attempt_id.clone(),
            guest_nonce: case.nonce.clone(),
            admission_policy_sha384: issuer.admission_policy_sha384().unwrap().into(),
        },
        1000,
    )
    .unwrap();
    assert_eq!(verified.context_digest(), case.context);
    assert_eq!(verified.validity(), case.grant.validity());
    drop(issuer);
    lab.base.clock.fail(ClockError::Unavailable);
    let reads = lab.base.clock.reads();
    let reopened = lab.reopen();
    let retry = reopened
        .redeem_policy_aggregate(case.grant.grant_id(), &case.aggregate_wire, &request)
        .unwrap();
    assert_eq!(retry.publication, AdmissionPublicationKind::Existing);
    assert_eq!(
        retry.signed_authorization_json,
        first.signed_authorization_json
    );
    assert_eq!(
        reopened
            .status_policy_aggregate(case.grant.grant_id(), &case.aggregate_wire, &status)
            .unwrap()
            .unwrap(),
        first.signed_authorization_json
    );
    lab.pin(&reopened, &case);
    assert_eq!(
        lab.base.clock.reads(),
        reads,
        "history and exact pins must not read live clock"
    );
}

#[test]
fn foreign_signature_changed_pinned_context_and_request_purpose_do_not_consume() {
    let lab = Lab::new();
    let issuer = lab.create();
    let case = lab.case(&issuer, "one");
    lab.pin(&issuer, &case);
    let request = lab.request(&case, POLICY_REDEEM_PURPOSE, &lab.base.recorder);
    let foreign = signed(
        &case.aggregate,
        &case.aggregate.signing_bytes().unwrap(),
        &Key::new(),
    );
    assert!(issuer
        .redeem_policy_aggregate(case.grant.grant_id(), &foreign, &request)
        .is_err());
    for field in [
        "session", "runtime", "evidence", "input", "resource", "issuer", "profile",
    ] {
        let mut altered = case.aggregate.clone();
        match field {
            "session" => altered.session_id = "33".repeat(32),
            "runtime" => altered.runtime_sha384 = hash("other-runtime"),
            "evidence" => altered.evidence_sha384 = hash("other-evidence"),
            "input" => altered.as_evaluation.input_sha384 = hash("other-input"),
            "resource" => altered.request.resource_path[0] = "other-tenant".into(),
            "issuer" => altered.issuer = "other-kbs".into(),
            "profile" => altered.profile = "other-profile".into(),
            _ => unreachable!(),
        };
        let wire = signed(&altered, &altered.signing_bytes().unwrap(), &lab.kbs);
        assert!(
            issuer
                .redeem_policy_aggregate(case.grant.grant_id(), &wire, &request)
                .is_err(),
            "{field}"
        );
    }
    assert!(issuer
        .redeem_policy_aggregate(
            case.grant.grant_id(),
            &case.aggregate_wire,
            &lab.request(&case, POLICY_STATUS_PURPOSE, &lab.base.recorder)
        )
        .is_err());
    assert!(issuer
        .redeem_policy_aggregate(
            case.grant.grant_id(),
            &case.aggregate_wire,
            &lab.request(&case, REDEEM_PURPOSE, &lab.base.recorder)
        )
        .is_err());
    assert!(issuer
        .redeem_policy_aggregate(
            case.grant.grant_id(),
            &case.aggregate_wire,
            &lab.request(&case, POLICY_REDEEM_PURPOSE, &Key::new())
        )
        .is_err());
    assert_eq!(
        issuer
            .redeem_policy_aggregate(case.grant.grant_id(), &case.aggregate_wire, &request)
            .unwrap()
            .publication,
        AdmissionPublicationKind::FirstAuthorized
    );
}

#[test]
fn operator_pins_must_match_static_policy_scope_and_owned_issued_grant() {
    let lab = Lab::new();
    let issuer = lab.create();
    let case = lab.case(&issuer, "one");
    for field in [
        "authority",
        "recorder",
        "as-policy",
        "kbs-policy",
        "references",
        "init",
        "resource",
        "workflow",
        "audience",
    ] {
        let mut altered = case.aggregate.clone();
        match field {
            "authority" => altered.authority_key_sha384 = hash("attacker-authority"),
            "recorder" => altered.recorder_key_sha384 = hash("other-recorder"),
            "as-policy" => altered.as_evaluation.policy_sha384 = hash("other-as-policy"),
            "kbs-policy" => altered.kbs_evaluation.policy_sha384 = hash("other-kbs-policy"),
            "references" => altered.as_evaluation.data_sha384 = None,
            "init" => altered.init_data_sha384 = hash("other-init"),
            "resource" => altered.request.resource_path[0] = "other-tenant".into(),
            "workflow" => altered.request.workflow_id = "other-workflow".into(),
            "audience" => altered.audience = "other-audience".into(),
            _ => unreachable!(),
        };
        assert!(
            issuer
                .pin_policy_admission(case.grant.grant_id(), &altered, &case.nonce)
                .is_err(),
            "{field}"
        );
    }
    lab.pin(&issuer, &case);
    let second = lab.case(&issuer, "two");
    assert!(issuer
        .pin_policy_admission(second.grant.grant_id(), &case.aggregate, &second.nonce)
        .is_err());
}

#[test]
fn policy_profile_rejects_early_redeem_and_status_without_consuming_aggregate_slot() {
    let lab = Lab::new();
    let issuer = lab.create();
    let enrollment = lab.base.enrollment(&issuer, "one");
    let old_wire = enrollment.issue(&issuer);
    let old = lab.base.statements(&enrollment, &old_wire);
    let case = lab.case(&issuer, "one");
    assert_eq!(case.grant_wire, old_wire);
    lab.pin(&issuer, &case);
    let old_redeem = lab.base.request(&old, REDEEM_PURPOSE, &lab.base.recorder);
    let old_status = lab.base.request(&old, STATUS_PURPOSE, &lab.base.recorder);
    for consumed in [false, true] {
        assert!(matches!(
            issuer.redeem(&old, &old_redeem),
            Err(Error::PolicyMismatch)
        ));
        assert!(matches!(
            issuer.status(&old, &old_status),
            Err(Error::PolicyMismatch)
        ));
        let status = issuer
            .status_policy_aggregate(
                case.grant.grant_id(),
                &case.aggregate_wire,
                &lab.request(&case, POLICY_STATUS_PURPOSE, &lab.base.recorder),
            )
            .unwrap();
        assert_eq!(status.is_some(), consumed);
        if !consumed {
            let publication = issuer
                .redeem_policy_aggregate(
                    case.grant.grant_id(),
                    &case.aggregate_wire,
                    &lab.request(&case, POLICY_REDEEM_PURPOSE, &lab.base.recorder),
                )
                .unwrap();
            assert_eq!(
                publication.publication,
                AdmissionPublicationKind::FirstAuthorized
            );
        }
    }
}

#[test]
fn independent_connections_publish_only_one_authorization_and_preserve_its_bytes() {
    let lab = Arc::new(Lab::new());
    let issuer = lab.create();
    let case = Arc::new(lab.case(&issuer, "one"));
    lab.pin(&issuer, &case);
    drop(issuer);
    let barrier = Arc::new(Barrier::new(2));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let lab = lab.clone();
        let case = case.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            let issuer = lab.reopen();
            let request = lab.request(&case, POLICY_REDEEM_PURPOSE, &lab.base.recorder);
            barrier.wait();
            issuer
                .redeem_policy_aggregate(case.grant.grant_id(), &case.aggregate_wire, &request)
                .unwrap()
        }));
    }
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|r| r.publication == AdmissionPublicationKind::FirstAuthorized)
            .count(),
        1
    );
    assert_eq!(
        results[0].signed_authorization_json,
        results[1].signed_authorization_json
    );
}

#[test]
fn concurrent_early_redemption_cannot_compete_with_policy_admission() {
    let lab = Arc::new(Lab::new());
    let issuer = lab.create();
    let enrollment = lab.base.enrollment(&issuer, "mixed-race");
    let wire = enrollment.issue(&issuer);
    let old = lab.base.statements(&enrollment, &wire);
    let old_request = lab.base.request(&old, REDEEM_PURPOSE, &lab.base.recorder);
    let case = lab.case(&issuer, "mixed-race");
    lab.pin(&issuer, &case);
    let old_connection = lab.reopen();
    let new_connection = lab.reopen();
    let request = lab.request(&case, POLICY_REDEEM_PURPOSE, &lab.base.recorder);
    let barrier = Arc::new(Barrier::new(2));
    let old_barrier = barrier.clone();
    let old_thread = std::thread::spawn(move || {
        old_barrier.wait();
        old_connection.redeem(&old, &old_request)
    });
    let new_thread = std::thread::spawn(move || {
        barrier.wait();
        new_connection.redeem_policy_aggregate(
            case.grant.grant_id(),
            &case.aggregate_wire,
            &request,
        )
    });
    let old_result = old_thread.join().unwrap();
    let new_result = new_thread.join().unwrap();
    assert!(matches!(old_result, Err(Error::PolicyMismatch)));
    assert_eq!(
        new_result.unwrap().publication,
        AdmissionPublicationKind::FirstAuthorized
    );
    lab.reopen(); // Rejected early calls cannot corrupt the aggregate record.
}

#[test]
fn stored_receipt_signature_is_checked_even_when_its_wire_hash_is_recomputed() {
    let lab = Lab::new();
    let issuer = lab.create();
    let case = lab.case(&issuer, "corruption");
    lab.pin(&issuer, &case);
    let request = lab.request(&case, POLICY_REDEEM_PURPOSE, &lab.base.recorder);
    let receipt = issuer
        .redeem_policy_aggregate(case.grant.grant_id(), &case.aggregate_wire, &request)
        .unwrap();
    drop(issuer);
    let mut wire: execution_proof_contract::Signed<
        execution_proof_contract::admission::AdmissionAuthorizationV1,
    > = serde_json::from_slice(&receipt.signed_authorization_json).unwrap();
    wire.statement.audience = "tampered-guest".into();
    let bytes = serde_json::to_vec(&wire).unwrap();
    let digest = support::hex(ring::digest::digest(&ring::digest::SHA384, &bytes).as_ref());
    let connection = rusqlite::Connection::open(lab.base.db()).unwrap();
    connection
        .execute(
            "UPDATE policy_admissions SET receipt_json=?1,receipt_wire_digest=?2 WHERE grant_id=?3",
            rusqlite::params![bytes, digest, case.grant.grant_id()],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        SoftwareIssuer::open_existing_with_policy_admission_and_clock(
            &lab.base.db(),
            lab.base.config(),
            lab.config(),
            lab.base.authority.pair(),
            8,
            lab.base.clock.clone()
        ),
        Err(Error::Store(StoreError::Corrupt))
    ));
}

#[test]
fn clock_failures_expiry_high_water_and_explicit_profile_identity_fail_closed() {
    let lab = Lab::new();
    let issuer = lab.create();
    let case = lab.case(&issuer, "one");
    lab.pin(&issuer, &case);
    let request = lab.request(&case, POLICY_REDEEM_PURPOSE, &lab.base.recorder);
    lab.base.clock.fail(ClockError::Unavailable);
    assert!(matches!(
        issuer.redeem_policy_aggregate(case.grant.grant_id(), &case.aggregate_wire, &request),
        Err(Error::Store(StoreError::ClockUnavailable))
    ));
    lab.base.clock.set(1030);
    assert!(matches!(
        issuer.redeem_policy_aggregate(case.grant.grant_id(), &case.aggregate_wire, &request),
        Err(Error::Store(StoreError::Expired))
    ));
    drop(issuer);
    lab.base.clock.set(1029);
    let reopened = lab.reopen();
    assert!(matches!(
        reopened.redeem_policy_aggregate(case.grant.grant_id(), &case.aggregate_wire, &request),
        Err(Error::Store(StoreError::ClockRegression))
    ));
    assert!(SoftwareIssuer::open_existing_with_clock(
        &lab.base.db(),
        lab.base.config(),
        lab.base.authority.pair(),
        8,
        lab.base.clock.clone()
    )
    .is_err());
    let mut changed = lab.config();
    changed.receipt_audience = "other-guest".into();
    assert!(matches!(
        SoftwareIssuer::open_existing_with_policy_admission_and_clock(
            &lab.base.db(),
            lab.base.config(),
            changed,
            lab.base.authority.pair(),
            8,
            lab.base.clock.clone()
        ),
        Err(Error::Store(StoreError::IdentityMismatch))
    ));
    let mut changed_key = lab.config();
    changed_key.kbs_proof_public_key = Key::new().public();
    assert!(matches!(
        SoftwareIssuer::open_existing_with_policy_admission_and_clock(
            &lab.base.db(),
            lab.base.config(),
            changed_key,
            lab.base.authority.pair(),
            8,
            lab.base.clock.clone()
        ),
        Err(Error::Store(StoreError::IdentityMismatch))
    ));
    let schema: i64 = rusqlite::Connection::open(lab.base.db())
        .unwrap()
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(schema, 3);
    let legacy = Fixture::new();
    drop(legacy.create(8));
    assert!(
        SoftwareIssuer::open_existing_with_policy_admission_and_clock(
            &legacy.db(),
            legacy.config(),
            lab.config(),
            legacy.authority.pair(),
            8,
            legacy.clock.clone()
        )
        .is_err()
    );
    let schema: i64 = rusqlite::Connection::open(legacy.db())
        .unwrap()
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(schema, 2);
}

#[test]
fn committed_receipt_first_delivery_after_expiry_activates_only_original_pending_gate() {
    let lab = Lab::new();
    let issuer = lab.create();
    let mut case = lab.case(&issuer, "delayed-first-delivery");
    let base = lab.base.config();
    let gate_config = || GuestAdmissionConfig {
        grant: GrantExpectations {
            authority_public_key: lab.base.authority.public(),
            audience: base.audience.clone(),
            authority: base.authority.clone(),
            tenant: base.tenant.clone(),
            profile_sha384: base.profile_sha384.clone(),
            launch_policy_sha384: base.launch_policy_sha384.clone(),
            image_policy_sha384: base.image_policy_sha384.clone(),
        },
        expected_grant: serde_json::from_slice::<Signed<LaunchGrant>>(&case.grant_wire)
            .unwrap()
            .statement,
        aggregate: AggregateExpectations {
            kbs_proof_public_key: lab.kbs.public(),
            expected: case.aggregate.clone(),
        },
        audience: lab.config().receipt_audience,
        issuer: base.authority.clone(),
        admission_policy_sha384: issuer.admission_policy_sha384().unwrap().into(),
    };
    let gate = GuestAdmissionGate::new(gate_config()).unwrap();
    let lost_continuity = GuestAdmissionGate::new(gate_config()).unwrap();
    case.nonce = gate.challenge_nonce().into();
    let aggregate = verify_policy_aggregate(
        &case.aggregate_wire,
        &case.grant,
        &AggregateExpectations {
            kbs_proof_public_key: lab.kbs.public(),
            expected: case.aggregate.clone(),
        },
    )
    .unwrap();
    case.context = policy_admission_context(
        &case.grant,
        &aggregate,
        &case.nonce,
        issuer.admission_policy_sha384().unwrap(),
    )
    .unwrap();
    lab.pin(&issuer, &case);
    let request = lab.request(&case, POLICY_REDEEM_PURPOSE, &lab.base.recorder);
    let committed = issuer
        .redeem_policy_aggregate(case.grant.grant_id(), &case.aggregate_wire, &request)
        .unwrap();
    assert_eq!(
        committed.publication,
        AdmissionPublicationKind::FirstAuthorized
    );
    assert_eq!(gate.status().unwrap(), GateStatus::Pending); // Reply was lost/delayed.
    lab.base.clock.set(case.grant.validity().expires);
    let retry = issuer
        .redeem_policy_aggregate(case.grant.grant_id(), &case.aggregate_wire, &request)
        .unwrap();
    assert_eq!(retry.publication, AdmissionPublicationKind::Existing);
    assert_eq!(
        retry.signed_authorization_json,
        committed.signed_authorization_json
    );
    let config = lab.base.config();
    assert_eq!(
        execution_proof_contract::verify_launch_grant(
            &case.grant_wire,
            &GrantExpectations {
                authority_public_key: lab.base.authority.public(),
                audience: config.audience,
                authority: config.authority,
                tenant: config.tenant,
                profile_sha384: config.profile_sha384,
                launch_policy_sha384: config.launch_policy_sha384,
                image_policy_sha384: config.image_policy_sha384,
            },
            case.grant.validity().expires
        )
        .err(),
        Some(execution_proof_contract::Error::Expired)
    );
    assert_eq!(
        gate.verify_bundle(
            &case.grant_wire,
            &case.aggregate_wire,
            &retry.signed_authorization_json
        )
        .unwrap(),
        AdmissionCheck::FirstVerified
    );
    let context = gate.take_accepted_attempt().unwrap();
    assert_eq!(context.context_digest(), case.context);
    drop(context);
    assert_eq!(
        gate.verify_bundle(
            &case.grant_wire,
            &case.aggregate_wire,
            &retry.signed_authorization_json
        )
        .unwrap(),
        AdmissionCheck::Historical
    );
    assert_eq!(gate.status().unwrap(), GateStatus::Consumed);
    assert_eq!(
        gate.take_accepted_attempt().err(),
        Some(GuestAdmissionError::AlreadyConsumed)
    );
    assert_ne!(lost_continuity.challenge_nonce(), gate.challenge_nonce());
    assert!(lost_continuity
        .verify_bundle(
            &case.grant_wire,
            &case.aggregate_wire,
            &retry.signed_authorization_json
        )
        .is_err());
    assert_eq!(
        lost_continuity.take_accepted_attempt().err(),
        Some(GuestAdmissionError::NotReady)
    );
    assert!(execution_proof_handoff::supported_proof_profiles().is_empty());
}
