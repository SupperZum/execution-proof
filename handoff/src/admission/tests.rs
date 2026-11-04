use super::*;
use execution_proof_contract::{
    admission::{
        policy_admission_context, AdmissionAuthorizationV1, ADMISSION_PROFILE, ADMISSION_PURPOSE,
        ADMISSION_VERSION,
    },
    policy_receipt::{LaunchPolicyAggregateV1, PolicyCommitments, ResourcePolicyRequest},
    LaunchBinding, Signed, ValidityWindow,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Serialize;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Barrier,
};

struct Clock {
    value: Mutex<Result<u64, GuestClockError>>,
    calls: AtomicUsize,
}
impl Clock {
    fn new(value: u64) -> Arc<Self> {
        Arc::new(Self {
            value: Mutex::new(Ok(value)),
            calls: AtomicUsize::new(0),
        })
    }
    fn set(&self, value: Result<u64, GuestClockError>) {
        *self.value.lock().unwrap() = value;
    }
}
impl GuestClock for Clock {
    fn now_unix_seconds(&self) -> Result<u64, GuestClockError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.value.lock().unwrap()
    }
}
fn key() -> Ed25519KeyPair {
    let encoded = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(encoded.as_ref()).unwrap()
}
fn sign<T: Serialize>(statement: T, transcript: &[u8], key: &Ed25519KeyPair) -> Vec<u8> {
    serde_json::to_vec(&Signed {
        statement,
        signature: hex(key.sign(transcript).as_ref()),
    })
    .unwrap()
}
struct Fixture {
    authority: Ed25519KeyPair,
    producer: Ed25519KeyPair,
    grant: LaunchGrant,
    aggregate: LaunchPolicyAggregateV1,
    grant_wire: Vec<u8>,
    aggregate_wire: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        let authority = key();
        let producer = key();
        let grant = LaunchGrant {
            version: VERSION,
            purpose: GRANT_PURPOSE.into(),
            audience: "guest-software-fixture".into(),
            proof_required: true,
            grant_id: "grant-1".into(),
            validity: ValidityWindow {
                not_before: 100,
                expires: 200,
            },
            binding: LaunchBinding {
                authority: "authority".into(),
                tenant: "tenant".into(),
                workload_id: "workload".into(),
                container_role: "application-init".into(),
                attempt_id: "attempt".into(),
                boot_id: "boot".into(),
                channel_key_sha384: "11".repeat(48),
                bootstrap_context_sha384: "12".repeat(48),
                selected_manifest_sha256: "13".repeat(32),
                effective_launch_sha384: "14".repeat(48),
                profile_sha384: "15".repeat(48),
                launch_policy_sha384: "16".repeat(48),
                image_policy_sha384: "17".repeat(48),
                challenge_sha384: "18".repeat(48),
            },
        };
        let aggregate = LaunchPolicyAggregateV1 {
            version: POLICY_AGGREGATE_VERSION,
            purpose: POLICY_AGGREGATE_PURPOSE.into(),
            audience: "auditor".into(),
            issuer: "kbs-proof".into(),
            profile: POLICY_AGGREGATE_PROFILE.into(),
            grant_sha384: grant.digest_sha384().unwrap(),
            authority_key_sha384: hash(authority.public_key().as_ref()),
            session_id: "19".repeat(32),
            nonce: "software-quote-nonce".into(),
            runtime_sha384: "1a".repeat(48),
            init_data_sha384: "1b".repeat(48),
            evidence_sha384: "1c".repeat(48),
            recorder_key_sha384: grant.binding.channel_key_sha384.clone(),
            request: ResourcePolicyRequest {
                method: "GET".into(),
                plugin: "resource".into(),
                resource_path: ["tenant".into(), "image-key".into(), "v1".into()],
                workflow_id: "workflow".into(),
                request_nonce: "1d".repeat(32),
            },
            as_evaluation: PolicyCommitments {
                policy_id: "launch_cpu".into(),
                policy_sha384: grant.binding.launch_policy_sha384.clone(),
                input_sha384: "1e".repeat(48),
                data_sha384: None,
            },
            kbs_evaluation: PolicyCommitments {
                policy_id: "restricted_resource".into(),
                policy_sha384: "1f".repeat(48),
                input_sha384: "20".repeat(48),
                data_sha384: Some("21".repeat(48)),
            },
        };
        let grant_wire = sign(grant.clone(), &grant.signing_bytes().unwrap(), &authority);
        let aggregate_wire = sign(
            aggregate.clone(),
            &aggregate.signing_bytes().unwrap(),
            &producer,
        );
        Self {
            authority,
            producer,
            grant,
            aggregate,
            grant_wire,
            aggregate_wire,
        }
    }
    fn config(&self) -> GuestAdmissionConfig {
        GuestAdmissionConfig {
            grant: GrantExpectations {
                authority_public_key: self.authority.public_key().as_ref().try_into().unwrap(),
                audience: self.grant.audience.clone(),
                authority: self.grant.binding.authority.clone(),
                tenant: self.grant.binding.tenant.clone(),
                profile_sha384: self.grant.binding.profile_sha384.clone(),
                launch_policy_sha384: self.grant.binding.launch_policy_sha384.clone(),
                image_policy_sha384: self.grant.binding.image_policy_sha384.clone(),
            },
            expected_grant: self.grant.clone(),
            aggregate: AggregateExpectations {
                kbs_proof_public_key: self.producer.public_key().as_ref().try_into().unwrap(),
                expected: self.aggregate.clone(),
            },
            audience: "guest-preparation".into(),
            issuer: "authority-admission".into(),
            admission_policy_sha384: "22".repeat(48),
        }
    }
    fn gate(&self, clock: Arc<Clock>) -> GuestAdmissionGate {
        GuestAdmissionGate::new(self.config(), clock).unwrap()
    }
    fn receipt(&self, nonce: &str) -> AdmissionAuthorizationV1 {
        let config = self.config();
        let grant = verify_launch_grant(&self.grant_wire, &config.grant, 100).unwrap();
        let aggregate =
            verify_policy_aggregate(&self.aggregate_wire, &grant, &config.aggregate).unwrap();
        AdmissionAuthorizationV1 {
            version: ADMISSION_VERSION,
            purpose: ADMISSION_PURPOSE.into(),
            audience: config.audience,
            issuer: config.issuer,
            profile: ADMISSION_PROFILE.into(),
            grant_id: self.grant.grant_id.clone(),
            grant_sha384: grant.grant_digest().into(),
            aggregate_sha384: aggregate.digest_sha384().into(),
            aggregate_key_sha384: aggregate.kbs_proof_key_sha384().into(),
            context_sha384: policy_admission_context(
                &grant,
                &aggregate,
                nonce,
                &config.admission_policy_sha384,
            )
            .unwrap(),
            guest_nonce: nonce.into(),
            admission_policy_sha384: config.admission_policy_sha384,
            validity: self.grant.validity,
            binding: self.grant.binding.clone(),
        }
    }
    fn receipt_wire(&self, gate: &GuestAdmissionGate) -> Vec<u8> {
        self.sign_receipt(self.receipt(gate.challenge_nonce()))
    }
    fn sign_receipt(&self, receipt: AdmissionAuthorizationV1) -> Vec<u8> {
        let bytes = receipt.signing_bytes().unwrap();
        sign(receipt, &bytes, &self.authority)
    }
}

#[test]
fn valid_signed_bundle_still_cannot_prepare_and_exact_history_skips_clock() {
    let f = Fixture::new();
    let clock = Clock::new(100);
    let gate = f.gate(clock.clone());
    let receipt = f.receipt_wire(&gate);
    assert_eq!(gate.status().unwrap(), GateStatus::Pending);
    assert_eq!(
        gate.validate_for_preparation(&f.grant_wire, &f.aggregate_wire, &receipt)
            .err(),
        Some(GuestAdmissionError::Unsupported(
            GuestUnsupportedReason::ContentPreparationUnavailable
        ))
    );
    assert_eq!(gate.status().unwrap(), GateStatus::Verified);
    let calls = clock.calls.load(Ordering::SeqCst);
    clock.set(Err(GuestClockError::Unavailable));
    assert_eq!(
        gate.verify_bundle(&f.grant_wire, &f.aggregate_wire, &receipt)
            .unwrap(),
        AdmissionCheck::Historical
    );
    assert_eq!(
        gate.validate_for_preparation(&f.grant_wire, &f.aggregate_wire, &receipt)
            .err(),
        Some(GuestAdmissionError::Unsupported(
            GuestUnsupportedReason::ContentPreparationUnavailable
        ))
    );
    assert_eq!(clock.calls.load(Ordering::SeqCst), calls);
    assert!(crate::supported_proof_profiles().is_empty());
    assert!(crate::prepare_launch(
        crate::PROTOCOL_VERSION,
        Some("software-policy-admission-only")
    )
    .is_err());
}

#[test]
fn each_actual_signature_and_own_configured_roots_are_required() {
    let f = Fixture::new();
    let attacker = key();
    for which in 0..5 {
        let mut config = f.config();
        if which == 3 {
            config.grant.authority_public_key = attacker.public_key().as_ref().try_into().unwrap();
            config.aggregate.expected.authority_key_sha384 = hash(attacker.public_key().as_ref());
        }
        if which == 4 {
            config.aggregate.kbs_proof_public_key =
                attacker.public_key().as_ref().try_into().unwrap();
        }
        let gate = GuestAdmissionGate::new(config, Clock::new(100)).unwrap();
        let mut grant = f.grant_wire.clone();
        let mut aggregate = f.aggregate_wire.clone();
        let mut receipt = f.receipt_wire(&gate);
        match which {
            0 => {
                grant = sign(
                    f.grant.clone(),
                    &f.grant.signing_bytes().unwrap(),
                    &attacker,
                )
            }
            1 => {
                aggregate = sign(
                    f.aggregate.clone(),
                    &f.aggregate.signing_bytes().unwrap(),
                    &attacker,
                )
            }
            2 => {
                let value = f.receipt(gate.challenge_nonce());
                receipt = sign(value.clone(), &value.signing_bytes().unwrap(), &attacker);
            }
            _ => {}
        }
        assert_eq!(
            gate.verify_bundle(&grant, &aggregate, &receipt),
            Err(GuestAdmissionError::Contract(
                execution_proof_contract::Error::InvalidSignature
            ))
        );
        assert_eq!(gate.status().unwrap(), GateStatus::Pending);
    }
}

#[test]
fn signed_wrong_nonce_boot_attempt_content_policy_or_domain_is_rejected() {
    let f = Fixture::new();
    for which in 0..8 {
        let gate = f.gate(Clock::new(100));
        let mut receipt = f.receipt(gate.challenge_nonce());
        match which {
            0 => receipt = f.receipt("different-guest-nonce"),
            1 => receipt.binding.boot_id = "other-boot".into(),
            2 => receipt.binding.attempt_id = "other-attempt".into(),
            3 => receipt.binding.selected_manifest_sha256 = "23".repeat(32),
            4 => receipt.binding.effective_launch_sha384 = "24".repeat(48),
            5 => receipt.admission_policy_sha384 = "25".repeat(48),
            6 => receipt.purpose = execution_proof_contract::APPRAISAL_PURPOSE.into(),
            7 => receipt.aggregate_key_sha384 = "26".repeat(48),
            _ => unreachable!(),
        }
        assert!(gate
            .verify_bundle(&f.grant_wire, &f.aggregate_wire, &f.sign_receipt(receipt))
            .is_err());
        assert_eq!(gate.status().unwrap(), GateStatus::Pending);
    }
}

#[test]
fn fresh_gate_nonce_prevents_cross_gate_receipt_and_changed_raw_retry_conflicts() {
    let f = Fixture::new();
    let first = f.gate(Clock::new(100));
    let other = f.gate(Clock::new(100));
    assert_ne!(first.challenge_nonce(), other.challenge_nonce());
    let receipt = f.receipt_wire(&first);
    assert!(other
        .verify_bundle(&f.grant_wire, &f.aggregate_wire, &receipt)
        .is_err());
    assert_eq!(
        first
            .verify_bundle(&f.grant_wire, &f.aggregate_wire, &receipt)
            .unwrap(),
        AdmissionCheck::FirstVerified
    );
    let value: serde_json::Value = serde_json::from_slice(&f.grant_wire).unwrap();
    let pretty = serde_json::to_vec_pretty(&value).unwrap();
    assert_eq!(
        first.verify_bundle(&pretty, &f.aggregate_wire, &receipt),
        Err(GuestAdmissionError::Conflict)
    );
    assert_eq!(
        first
            .verify_bundle(&f.grant_wire, &f.aggregate_wire, &receipt)
            .unwrap(),
        AdmissionCheck::Historical
    );
}

#[test]
fn clock_failures_regression_and_expiry_denial_keep_pending_and_highwater() {
    let f = Fixture::new();
    let clock = Clock::new(200);
    let gate = f.gate(clock.clone());
    let receipt = f.receipt_wire(&gate);
    assert_eq!(
        gate.verify_bundle(&f.grant_wire, &f.aggregate_wire, &receipt),
        Err(GuestAdmissionError::Contract(
            execution_proof_contract::Error::Expired
        ))
    );
    clock.set(Ok(199));
    assert_eq!(
        gate.verify_bundle(&f.grant_wire, &f.aggregate_wire, &receipt),
        Err(GuestAdmissionError::ClockRegression)
    );
    assert_eq!(gate.status().unwrap(), GateStatus::Pending);
    for value in [
        Err(GuestClockError::Unavailable),
        Err(GuestClockError::OutOfRange),
        Ok(u64::MAX),
    ] {
        let clock = Clock::new(100);
        let gate = f.gate(clock.clone());
        clock.set(value);
        assert!(gate
            .verify_bundle(&f.grant_wire, &f.aggregate_wire, &f.receipt_wire(&gate))
            .is_err());
        assert_eq!(gate.status().unwrap(), GateStatus::Pending);
    }
    let clock = Clock::new(99);
    let gate = f.gate(clock.clone());
    let receipt = f.receipt_wire(&gate);
    assert_eq!(
        gate.verify_bundle(&f.grant_wire, &f.aggregate_wire, &receipt),
        Err(GuestAdmissionError::Contract(
            execution_proof_contract::Error::NotYetValid
        ))
    );
    clock.set(Ok(100));
    assert_eq!(
        gate.verify_bundle(&f.grant_wire, &f.aggregate_wire, &receipt)
            .unwrap(),
        AdmissionCheck::FirstVerified
    );
}

#[test]
fn simultaneous_exact_submissions_have_one_first_verification_without_rearming() {
    let f = Fixture::new();
    let gate = Arc::new(f.gate(Clock::new(100)));
    let receipt = Arc::new(f.receipt_wire(&gate));
    let grant = Arc::new(f.grant_wire);
    let aggregate = Arc::new(f.aggregate_wire);
    let barrier = Arc::new(Barrier::new(8));
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let (gate, receipt, grant, aggregate, barrier) = (
                gate.clone(),
                receipt.clone(),
                grant.clone(),
                aggregate.clone(),
                barrier.clone(),
            );
            std::thread::spawn(move || {
                barrier.wait();
                gate.verify_bundle(&grant, &aggregate, &receipt).unwrap()
            })
        })
        .collect();
    let outcomes: Vec<_> = tasks.into_iter().map(|task| task.join().unwrap()).collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| **value == AdmissionCheck::FirstVerified)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| **value == AdmissionCheck::Historical)
            .count(),
        7
    );
    assert_eq!(gate.status().unwrap(), GateStatus::Verified);
}

#[test]
fn outer_bounds_precede_clock_and_trusted_exact_grant_is_not_request_selected() {
    let f = Fixture::new();
    let clock = Clock::new(100);
    let gate = f.gate(clock.clone());
    let oversized = vec![b' '; MAX_WIRE_BYTES + 1];
    for values in [
        (&oversized[..], b"".as_slice(), b"".as_slice()),
        (b"".as_slice(), &oversized[..], b"".as_slice()),
        (b"".as_slice(), b"".as_slice(), &oversized[..]),
    ] {
        assert_eq!(
            gate.verify_bundle(values.0, values.1, values.2),
            Err(GuestAdmissionError::TooLarge)
        );
    }
    assert_eq!(clock.calls.load(Ordering::SeqCst), 0);
    let mut other = f.grant.clone();
    other.binding.boot_id = "other-boot".into();
    let other_wire = sign(other.clone(), &other.signing_bytes().unwrap(), &f.authority);
    assert_eq!(
        gate.verify_bundle(&other_wire, &f.aggregate_wire, &f.receipt_wire(&gate)),
        Err(GuestAdmissionError::BindingMismatch)
    );
}
