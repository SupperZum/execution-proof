use super::*;
use crate::{
    policy_receipt::{
        verify_policy_aggregate, LaunchPolicyAggregateV1, PolicyCommitments, ResourcePolicyRequest,
        POLICY_AGGREGATE_PROFILE, POLICY_AGGREGATE_PURPOSE, POLICY_AGGREGATE_VERSION,
    },
    verify_launch_grant, verify_launch_grant_historical, GrantExpectations, LaunchGrant,
    GRANT_PURPOSE, MAX_WIRE_BYTES, VERSION,
};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde::Serialize;

struct Fixture {
    authority: Ed25519KeyPair,
    grant: VerifiedLaunchGrant,
    aggregate: VerifiedPolicyAggregate,
    receipt: AdmissionAuthorizationV1,
    expected: AdmissionExpectations,
    grant_wire: Vec<u8>,
    grant_expected: GrantExpectations,
}
fn key() -> Ed25519KeyPair {
    let bytes = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(bytes.as_ref()).unwrap()
}
fn signed<T: Serialize + Clone>(statement: &T, bytes: &[u8], key: &Ed25519KeyPair) -> Vec<u8> {
    serde_json::to_vec(&Signed {
        statement: statement.clone(),
        signature: crate::hex(key.sign(bytes).as_ref()),
    })
    .unwrap()
}
fn fixture() -> Fixture {
    let (authority, recorder, proof) = (key(), key(), key());
    let raw = LaunchGrant {
        version: VERSION,
        purpose: GRANT_PURPOSE.into(),
        audience: "admission-test".into(),
        proof_required: true,
        grant_id: "grant".into(),
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
            channel_key_sha384: sha384(recorder.public_key().as_ref()),
            bootstrap_context_sha384: "01".repeat(48),
            selected_manifest_sha256: "02".repeat(32),
            effective_launch_sha384: "03".repeat(48),
            profile_sha384: "04".repeat(48),
            launch_policy_sha384: "05".repeat(48),
            image_policy_sha384: "06".repeat(48),
            challenge_sha384: "07".repeat(48),
        },
    };
    let grant_expected = GrantExpectations {
        authority_public_key: authority.public_key().as_ref().try_into().unwrap(),
        audience: raw.audience.clone(),
        authority: raw.binding.authority.clone(),
        tenant: raw.binding.tenant.clone(),
        profile_sha384: raw.binding.profile_sha384.clone(),
        launch_policy_sha384: raw.binding.launch_policy_sha384.clone(),
        image_policy_sha384: raw.binding.image_policy_sha384.clone(),
    };
    let grant_wire = signed(&raw, &raw.signing_bytes().unwrap(), &authority);
    let grant = verify_launch_grant(&grant_wire, &grant_expected, 100).unwrap();
    let payload = LaunchPolicyAggregateV1 {
        version: POLICY_AGGREGATE_VERSION,
        purpose: POLICY_AGGREGATE_PURPOSE.into(),
        audience: "policy-consumer".into(),
        issuer: "combined-producer".into(),
        profile: POLICY_AGGREGATE_PROFILE.into(),
        grant_sha384: grant.grant_digest().into(),
        authority_key_sha384: grant.authority_key_sha384().into(),
        session_id: "08".repeat(32),
        nonce: "session-nonce".into(),
        runtime_sha384: "09".repeat(48),
        init_data_sha384: "0a".repeat(48),
        evidence_sha384: "0b".repeat(48),
        recorder_key_sha384: grant.binding().channel_key_sha384.clone(),
        request: ResourcePolicyRequest {
            method: "GET".into(),
            plugin: "resource".into(),
            resource_path: ["repo".into(), "credential".into(), "version".into()],
            workflow_id: "policy-only".into(),
            request_nonce: "resource-nonce".into(),
        },
        as_evaluation: PolicyCommitments {
            policy_id: "launch_cpu".into(),
            policy_sha384: grant.binding().launch_policy_sha384.clone(),
            input_sha384: "0c".repeat(48),
            data_sha384: None,
        },
        kbs_evaluation: PolicyCommitments {
            policy_id: "resource-launch".into(),
            policy_sha384: "0d".repeat(48),
            input_sha384: "0e".repeat(48),
            data_sha384: Some("0f".repeat(48)),
        },
    };
    let aggregate_expected = AggregateExpectations {
        kbs_proof_public_key: proof.public_key().as_ref().try_into().unwrap(),
        expected: payload,
    };
    let wire = signed(
        &aggregate_expected.expected,
        &aggregate_expected.expected.signing_bytes().unwrap(),
        &proof,
    );
    let aggregate = verify_policy_aggregate(&wire, &grant, &aggregate_expected).unwrap();
    let expected = AdmissionExpectations {
        authority_public_key: grant_expected.authority_public_key,
        aggregate: aggregate_expected,
        audience: "guest-admission".into(),
        issuer: "authority".into(),
        boot_id: "boot".into(),
        attempt_id: "attempt".into(),
        guest_nonce: "guest-owned-nonce".into(),
        admission_policy_sha384: "10".repeat(48),
    };
    let receipt = AdmissionAuthorizationV1 {
        version: ADMISSION_VERSION,
        purpose: ADMISSION_PURPOSE.into(),
        audience: expected.audience.clone(),
        issuer: expected.issuer.clone(),
        profile: ADMISSION_PROFILE.into(),
        grant_id: grant.grant_id().into(),
        grant_sha384: grant.grant_digest().into(),
        aggregate_sha384: aggregate.digest_sha384().into(),
        aggregate_key_sha384: aggregate.kbs_proof_key_sha384().into(),
        context_sha384: policy_admission_context(
            &grant,
            &aggregate,
            &expected.guest_nonce,
            &expected.admission_policy_sha384,
        )
        .unwrap(),
        guest_nonce: expected.guest_nonce.clone(),
        admission_policy_sha384: expected.admission_policy_sha384.clone(),
        validity: *grant.validity(),
        binding: grant.binding().clone(),
    };
    Fixture {
        authority,
        grant,
        aggregate,
        receipt,
        expected,
        grant_wire,
        grant_expected,
    }
}
fn wire(f: &Fixture) -> Vec<u8> {
    signed(
        &f.receipt,
        &f.receipt.signing_bytes().unwrap(),
        &f.authority,
    )
}
fn verify(f: &Fixture, now: u64) -> Result<VerifiedAdmissionAuthorization, Error> {
    verify_admission_authorization(&wire(f), &f.grant, &f.aggregate, &f.expected, now)
}

#[test]
fn authentic_current_receipt_preserves_exact_context_and_only_software_scope() {
    let f = fixture();
    let verified = verify(&f, 100).unwrap();
    assert_eq!(verified.binding(), f.grant.binding());
    assert_eq!(verified.grant_id(), f.grant.grant_id());
    assert_eq!(verified.grant_digest(), f.grant.grant_digest());
    assert_eq!(verified.aggregate_digest(), f.aggregate.digest_sha384());
    assert_eq!(verified.context_digest(), f.receipt.context_sha384);
    assert_eq!(verified.validity(), f.grant.validity());
    assert_eq!(
        verified.authority_key_sha384(),
        f.grant.authority_key_sha384()
    );
    assert_eq!(
        verified.aggregate_key_sha384(),
        f.aggregate.kbs_proof_key_sha384()
    );
    assert_eq!(verified.guest_nonce(), f.expected.guest_nonce);
    assert_eq!(
        verified.admission_policy_sha384(),
        f.expected.admission_policy_sha384
    );
    assert_eq!(
        f.receipt.digest_sha384().unwrap(),
        sha384(&f.receipt.signing_bytes().unwrap())
    );
    assert!(verify(&f, 199).is_ok());
    assert_eq!(verify(&f, 99).err(), Some(Error::NotYetValid));
    assert_eq!(verify(&f, 200).err(), Some(Error::Expired));
}

#[test]
fn authority_signature_and_dedicated_purpose_profile_are_required() {
    let f = fixture();
    let forged = signed(&f.receipt, &f.receipt.signing_bytes().unwrap(), &key());
    assert_eq!(
        verify_admission_authorization(&forged, &f.grant, &f.aggregate, &f.expected, 100).err(),
        Some(Error::InvalidSignature)
    );
    for (change, error) in [
        (
            (|r: &mut AdmissionAuthorizationV1| r.purpose = crate::APPRAISAL_PURPOSE.into())
                as fn(&mut AdmissionAuthorizationV1),
            Error::WrongPurpose,
        ),
        (|r| r.version += 1, Error::UnsupportedVersion),
        (
            |r| r.audience = "other-audience".into(),
            Error::WrongAudience,
        ),
        (|r| r.issuer = "other-authority".into(), Error::WrongIssuer),
        (
            |r| r.profile = "exec-authorized".into(),
            Error::BindingMismatch,
        ),
    ] {
        let mut f = fixture();
        change(&mut f.receipt);
        assert_eq!(verify(&f, 100).err(), Some(error));
    }
}

#[test]
fn every_binding_nonce_policy_and_window_mutation_is_rejected() {
    let changes: [fn(&mut AdmissionAuthorizationV1); 14] = [
        |r| r.grant_id = "other-grant".into(),
        |r| r.grant_sha384 = "11".repeat(48),
        |r| r.aggregate_sha384 = "11".repeat(48),
        |r| r.aggregate_key_sha384 = "11".repeat(48),
        |r| r.context_sha384 = "11".repeat(48),
        |r| r.guest_nonce.push('x'),
        |r| r.admission_policy_sha384 = "11".repeat(48),
        |r| r.validity.not_before = 101,
        |r| r.validity.expires = 201,
        |r| r.binding.boot_id = "other-boot".into(),
        |r| r.binding.attempt_id = "other-attempt".into(),
        |r| r.binding.selected_manifest_sha256 = "11".repeat(32),
        |r| r.binding.effective_launch_sha384 = "11".repeat(48),
        |r| r.binding.channel_key_sha384 = "11".repeat(48),
    ];
    for change in changes {
        let mut f = fixture();
        change(&mut f.receipt);
        assert_eq!(verify(&f, 150).err(), Some(Error::BindingMismatch));
    }
    for change in [
        (|e: &mut AdmissionExpectations| e.boot_id = "other-boot".into())
            as fn(&mut AdmissionExpectations),
        |e| e.attempt_id = "other-attempt".into(),
        |e| e.guest_nonce.push('x'),
        |e| e.admission_policy_sha384 = "11".repeat(48),
        |e| e.aggregate.expected.as_evaluation.input_sha384 = "11".repeat(48),
        |e| e.aggregate.expected.kbs_evaluation.data_sha384 = None,
        |e| e.aggregate.expected.request.resource_path[2] = "other".into(),
    ] {
        let mut f = fixture();
        change(&mut f.expected);
        assert_eq!(verify(&f, 150).err(), Some(Error::BindingMismatch));
    }
}

#[test]
fn context_changes_for_guest_nonce_policy_or_actual_producer_key() {
    let f = fixture();
    let context = policy_admission_context(
        &f.grant,
        &f.aggregate,
        "guest-owned-nonce",
        &"10".repeat(48),
    )
    .unwrap();
    assert_ne!(
        context,
        policy_admission_context(
            &f.grant,
            &f.aggregate,
            "other-guest-nonce",
            &"10".repeat(48)
        )
        .unwrap()
    );
    assert_ne!(
        context,
        policy_admission_context(
            &f.grant,
            &f.aggregate,
            "guest-owned-nonce",
            &"11".repeat(48)
        )
        .unwrap()
    );
    let attacker = key();
    let foreign_expected = AggregateExpectations {
        kbs_proof_public_key: attacker.public_key().as_ref().try_into().unwrap(),
        expected: f.expected.aggregate.expected.clone(),
    };
    let payload = &foreign_expected.expected;
    let raw = signed(payload, &payload.signing_bytes().unwrap(), &attacker);
    let foreign = verify_policy_aggregate(&raw, &f.grant, &foreign_expected).unwrap();
    assert_eq!(foreign.digest_sha384(), f.aggregate.digest_sha384());
    assert_ne!(
        context,
        policy_admission_context(
            &f.grant,
            &foreign,
            &f.expected.guest_nonce,
            &f.expected.admission_policy_sha384
        )
        .unwrap()
    );
    assert_eq!(
        verify_admission_authorization(&wire(&f), &f.grant, &foreign, &f.expected, 100).err(),
        Some(Error::ConfusedKeys)
    );
    let mut raw: Signed<LaunchGrant> = serde_json::from_slice(&f.grant_wire).unwrap();
    raw.signature = crate::hex(
        attacker
            .sign(&raw.statement.signing_bytes().unwrap())
            .as_ref(),
    );
    let receipt = wire(&f);
    let mut expected = f.grant_expected;
    expected.authority_public_key = attacker.public_key().as_ref().try_into().unwrap();
    let foreign_grant =
        verify_launch_grant(&serde_json::to_vec(&raw).unwrap(), &expected, 100).unwrap();
    assert_eq!(foreign_grant.grant_digest(), f.grant.grant_digest());
    assert_eq!(
        verify_admission_authorization(&receipt, &foreign_grant, &f.aggregate, &f.expected, 100)
            .err(),
        Some(Error::BindingMismatch)
    );
}

#[test]
fn strict_bounded_wire_and_canonical_fields_have_no_legacy_fallback() {
    let f = fixture();
    let bytes = wire(&f);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let mut unknown = value.clone();
    unknown["statement"]["exec_allowed"] = true.into();
    let mut omitted = value.clone();
    omitted["statement"]
        .as_object_mut()
        .unwrap()
        .remove("guest_nonce");
    let duplicate = String::from_utf8(bytes)
        .unwrap()
        .replacen("\"version\":1", "\"version\":1,\"version\":1", 1)
        .into_bytes();
    for raw in [
        serde_json::to_vec(&unknown).unwrap(),
        serde_json::to_vec(&omitted).unwrap(),
        duplicate,
    ] {
        assert_eq!(
            verify_admission_authorization(&raw, &f.grant, &f.aggregate, &f.expected, 100).err(),
            Some(Error::Malformed)
        );
    }
    assert_eq!(
        verify_admission_authorization(
            &vec![b' '; MAX_WIRE_BYTES + 1],
            &f.grant,
            &f.aggregate,
            &f.expected,
            100
        )
        .err(),
        Some(Error::TooLarge)
    );
    for (nonce, policy) in [
        ("".to_owned(), "10".repeat(48)),
        ("x".repeat(257), "10".repeat(48)),
        ("\u{0430}".into(), "10".repeat(48)),
        ("nonce".into(), "AA".repeat(48)),
    ] {
        assert_eq!(
            policy_admission_context(&f.grant, &f.aggregate, &nonce, &policy).err(),
            Some(Error::InvalidField)
        );
    }
}

#[test]
fn historical_grant_authentication_never_renews_its_signed_window() {
    let f = fixture();
    let stored = verify_launch_grant_historical(&f.grant_wire, &f.grant_expected).unwrap();
    assert_eq!(stored.validity(), f.grant.validity());
    assert_eq!(stored.grant_digest(), f.grant.grant_digest());
    assert_eq!(
        verify_launch_grant(&f.grant_wire, &f.grant_expected, 200).err(),
        Some(Error::Expired)
    );
    assert_eq!(
        verify_admission_authorization(&wire(&f), &stored, &f.aggregate, &f.expected, 200).err(),
        Some(Error::Expired)
    );
    let mut altered: Signed<LaunchGrant> = serde_json::from_slice(&f.grant_wire).unwrap();
    altered.statement.binding.tenant = "other-tenant".into();
    assert_eq!(
        verify_launch_grant_historical(&serde_json::to_vec(&altered).unwrap(), &f.grant_expected)
            .err(),
        Some(Error::InvalidSignature)
    );
}

#[test]
fn historical_receipt_authentication_preserves_context_without_renewing_window() {
    let f = fixture();
    let receipt = wire(&f);
    let authenticated =
        verify_admission_authorization_historical(&receipt, &f.grant, &f.aggregate, &f.expected)
            .unwrap();
    assert_eq!(authenticated.validity(), f.grant.validity());
    assert_eq!(authenticated.context_digest(), f.receipt.context_sha384);
    assert_eq!(verify(&f, 200).err(), Some(Error::Expired));
    let mut altered: Signed<AdmissionAuthorizationV1> = serde_json::from_slice(&receipt).unwrap();
    altered.signature = crate::hex(
        key()
            .sign(&altered.statement.signing_bytes().unwrap())
            .as_ref(),
    );
    assert_eq!(
        verify_admission_authorization_historical(
            &serde_json::to_vec(&altered).unwrap(),
            &f.grant,
            &f.aggregate,
            &f.expected
        )
        .err(),
        Some(Error::InvalidSignature)
    );
    let mut expected = f.expected;
    expected.guest_nonce.push('x');
    assert_eq!(
        verify_admission_authorization_historical(&receipt, &f.grant, &f.aggregate, &expected)
            .err(),
        Some(Error::BindingMismatch)
    );
}
