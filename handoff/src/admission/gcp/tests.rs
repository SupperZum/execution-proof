use super::*;
use execution_proof_contract::{
    admission::{
        gcp::policy_admission_context_gcp, AdmissionAuthorizationV1, ADMISSION_PROFILE,
        ADMISSION_PURPOSE, ADMISSION_VERSION,
    },
    gcp_policy_receipt::GcpLaunchPolicyAggregateV2,
    policy_receipt::{PolicyCommitments, ResourcePolicyRequest},
    LaunchBinding, Signed, ValidityWindow,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Serialize;
use std::sync::{Arc, Barrier};

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
    aggregate: GcpLaunchPolicyAggregateV2,
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
                profile_sha384: binding().digest_sha384().unwrap(),
                launch_policy_sha384: "16".repeat(48),
                image_policy_sha384: "17".repeat(48),
                challenge_sha384: "18".repeat(48),
            },
        };
        let aggregate = GcpLaunchPolicyAggregateV2 {
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
            boot_binding_sha384: binding().digest_sha384().unwrap(),
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
    fn config(&self) -> GcpGuestAdmissionConfig {
        GcpGuestAdmissionConfig {
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
            aggregate: GcpAggregateExpectations {
                boot_binding: binding(),
                kbs_proof_public_key: self.producer.public_key().as_ref().try_into().unwrap(),
                expected: self.aggregate.clone(),
            },
            audience: "guest-preparation".into(),
            issuer: "authority-admission".into(),
            admission_policy_sha384: "22".repeat(48),
        }
    }
    fn gate(&self) -> GcpGuestAdmissionGate {
        GcpGuestAdmissionGate::new(self.config()).unwrap()
    }
    fn receipt(&self, nonce: &str) -> AdmissionAuthorizationV1 {
        let config = self.config();
        let grant = verify_launch_grant_historical(&self.grant_wire, &config.grant).unwrap();
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
            context_sha384: policy_admission_context_gcp(
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
    fn receipt_wire(&self, gate: &GcpGuestAdmissionGate) -> Vec<u8> {
        self.sign_receipt(self.receipt(gate.challenge_nonce()))
    }
    fn sign_receipt(&self, receipt: AdmissionAuthorizationV1) -> Vec<u8> {
        let bytes = receipt.signing_bytes().unwrap();
        sign(receipt, &bytes, &self.authority)
    }
}

#[test]
fn valid_bundle_transfers_context_once_and_never_opens_preparation() {
    let f = Fixture::new();
    let gate = f.gate();
    let receipt = f.receipt_wire(&gate);
    assert_eq!(
        gate.take_accepted_attempt().err(),
        Some(GuestAdmissionError::NotReady)
    );
    assert_eq!(gate.status().unwrap(), GateStatus::Pending);
    assert_eq!(
        gate.validate_for_preparation(&f.grant_wire, &f.aggregate_wire, &receipt)
            .err(),
        Some(GuestAdmissionError::Unsupported(
            GuestUnsupportedReason::ContentPreparationUnavailable
        ))
    );
    assert_eq!(gate.status().unwrap(), GateStatus::Verified);
    let context = gate.take_accepted_attempt().unwrap();
    assert_eq!(context.binding(), &f.grant.binding);
    assert_eq!(context.grant_id(), f.grant.grant_id);
    assert_eq!(context.grant_digest(), f.aggregate.grant_sha384);
    assert_eq!(
        context.aggregate_digest(),
        f.aggregate.digest_sha384().unwrap()
    );
    assert_eq!(
        context.authority_key_sha384(),
        hash(f.authority.public_key().as_ref())
    );
    assert_eq!(
        context.aggregate_key_sha384(),
        hash(f.producer.public_key().as_ref())
    );
    assert_eq!(context.validity(), &f.grant.validity);
    assert_eq!(
        context.context_digest(),
        f.receipt(gate.challenge_nonce()).context_sha384
    );
    assert_eq!(context.guest_nonce(), gate.challenge_nonce());
    assert_eq!(context.workflow_id(), f.aggregate.request.workflow_id);
    assert_eq!(context.resource_path(), &f.aggregate.request.resource_path);
    drop(context); // Cancellation or failure after transfer cannot recover authority.
    assert_eq!(gate.status().unwrap(), GateStatus::Consumed);
    assert_eq!(
        gate.verify_bundle(&f.grant_wire, &f.aggregate_wire, &receipt)
            .unwrap(),
        AdmissionCheck::Historical
    );
    assert_eq!(
        gate.take_accepted_attempt().err(),
        Some(GuestAdmissionError::AlreadyConsumed)
    );
    assert_eq!(
        gate.validate_for_preparation(&f.grant_wire, &f.aggregate_wire, &receipt)
            .err(),
        Some(GuestAdmissionError::Unsupported(
            GuestUnsupportedReason::ContentPreparationUnavailable
        ))
    );
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
        let gate = GcpGuestAdmissionGate::new(config).unwrap();
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
        let gate = f.gate();
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
    let first = f.gate();
    let other = f.gate();
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
fn authority_time_authentication_does_not_depend_on_guest_time() {
    let f = Fixture::new();
    let gate = f.gate();
    let receipt = f.receipt_wire(&gate);
    let config = f.config();
    // A conservative live wrapper still rejects expiry; the guest authenticates
    // an authority-committed result against its own pending continuity instead.
    assert_eq!(
        execution_proof_contract::verify_launch_grant(&f.grant_wire, &config.grant, 200).err(),
        Some(execution_proof_contract::Error::Expired)
    );
    assert_eq!(
        gate.verify_bundle(&f.grant_wire, &f.aggregate_wire, &receipt)
            .unwrap(),
        AdmissionCheck::FirstVerified
    );
    let _accepted = gate.take_accepted_attempt().unwrap();
    let restored = f.gate();
    assert_ne!(gate.challenge_nonce(), restored.challenge_nonce());
    assert!(restored
        .verify_bundle(&f.grant_wire, &f.aggregate_wire, &receipt)
        .is_err());
    assert_eq!(
        restored.take_accepted_attempt().err(),
        Some(GuestAdmissionError::NotReady)
    );
}

#[test]
fn simultaneous_exact_submissions_have_one_first_verification_without_rearming() {
    let f = Fixture::new();
    let gate = Arc::new(f.gate());
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
fn outer_bounds_and_trusted_exact_grant_are_not_request_selected() {
    let f = Fixture::new();
    let gate = f.gate();
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
    let mut other = f.grant.clone();
    other.binding.boot_id = "other-boot".into();
    let other_wire = sign(other.clone(), &other.signing_bytes().unwrap(), &f.authority);
    assert_eq!(
        gate.verify_bundle(&other_wire, &f.aggregate_wire, &f.receipt_wire(&gate)),
        Err(GuestAdmissionError::BindingMismatch)
    );
}

#[test]
fn simultaneous_context_takes_have_one_winner_even_after_exact_retries() {
    let f = Fixture::new();
    let gate = Arc::new(f.gate());
    let receipt = f.receipt_wire(&gate);
    gate.verify_bundle(&f.grant_wire, &f.aggregate_wire, &receipt)
        .unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let (gate, barrier) = (gate.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                gate.take_accepted_attempt().map(|_| ())
            })
        })
        .collect();
    let outcomes: Vec<_> = tasks.into_iter().map(|task| task.join().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Err(GuestAdmissionError::AlreadyConsumed))
            .count(),
        7
    );
    assert_eq!(
        gate.verify_bundle(&f.grant_wire, &f.aggregate_wire, &receipt)
            .unwrap(),
        AdmissionCheck::Historical
    );
    assert_eq!(
        gate.take_accepted_attempt().err(),
        Some(GuestAdmissionError::AlreadyConsumed)
    );
}

#[test]
fn aggregate_context_is_consumed_by_reference_registration_and_abort_never_rearms() {
    let f = Fixture::new();
    let gate = f.gate();
    let receipt = f.receipt_wire(&gate);
    gate.verify_bundle(&f.grant_wire, &f.aggregate_wire, &receipt)
        .unwrap();
    let accepted = gate.take_accepted_attempt().unwrap();
    let reference = crate::PreparationReference {
        id: crate::PreparationId::new([7; 32]),
        context_sha384: crate::decode_sha384(accepted.context_digest()).unwrap(),
    };
    let table = crate::BootTable::new(f.grant.binding.boot_id.clone(), 1).unwrap();
    assert_eq!(
        table.register(accepted, reference).unwrap(),
        crate::Registration::Inserted
    );
    let binding = &f.grant.binding;
    let task = crate::TaskIdentity {
        boot_id: binding.boot_id.clone(),
        attempt_id: binding.attempt_id.clone(),
        selected_manifest_sha256: binding.selected_manifest_sha256.clone(),
        effective_launch_sha384: binding.effective_launch_sha384.clone(),
        container_role: binding.container_role.clone(),
        generation: 1,
    };
    table.bind(&reference, task.clone()).unwrap();
    let _bookkeeping = table.consume(&reference, &task).unwrap();
    table.abort(&reference).unwrap();
    assert_eq!(
        table.consume(&reference, &task).err(),
        Some(crate::Error::Aborted)
    );
    assert_eq!(
        gate.verify_bundle(&f.grant_wire, &f.aggregate_wire, &receipt)
            .unwrap(),
        AdmissionCheck::Historical
    );
    assert_eq!(
        gate.take_accepted_attempt().err(),
        Some(GuestAdmissionError::AlreadyConsumed)
    );
    assert!(crate::supported_proof_profiles().is_empty());
}

#[test]
fn registration_failure_also_consumes_the_local_context() {
    let f = Fixture::new();
    let gate = f.gate();
    let receipt = f.receipt_wire(&gate);
    gate.verify_bundle(&f.grant_wire, &f.aggregate_wire, &receipt)
        .unwrap();
    let accepted = gate.take_accepted_attempt().unwrap();
    let reference = crate::PreparationReference {
        id: crate::PreparationId::new([8; 32]),
        context_sha384: crate::decode_sha384(accepted.context_digest()).unwrap(),
    };
    let other_boot = crate::BootTable::new("other-boot".into(), 1).unwrap();
    assert_eq!(
        other_boot.register(accepted, reference),
        Err(crate::Error::WrongBoot)
    );
    assert_eq!(
        gate.take_accepted_attempt().err(),
        Some(GuestAdmissionError::AlreadyConsumed)
    );
}

fn binding() -> execution_proof_contract::gcp_boot_binding::GcpBootBindingV1 {
    execution_proof_contract::gcp_boot_binding::GcpBootBindingV1::new(
        [1; 48], [2; 48], [3; 48], [4; 48],
    )
    .unwrap()
}

#[cfg(feature = "rootfs-custody")]
mod receiver_enrollment_tests;
