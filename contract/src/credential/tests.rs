use super::*;
use crate::{
    policy_receipt::{
        tests::{fixture, key, wire},
        verify_policy_aggregate,
    },
    session::{operation_signing_bytes, verify_operation_pop, SessionOperation},
};
use ring::signature::{Ed25519KeyPair, KeyPair};

fn receipt(
    grant: &VerifiedLaunchGrant,
    aggregate: &VerifiedPolicyAggregate,
    jwe: &[u8],
) -> CredentialDeliveryV1 {
    let policy = aggregate.statement();
    CredentialDeliveryV1 {
        version: CREDENTIAL_DELIVERY_VERSION,
        purpose: CREDENTIAL_DELIVERY_PURPOSE.into(),
        audience: "credential-recorder".into(),
        issuer: "credential-producer".into(),
        profile: CREDENTIAL_DELIVERY_PROFILE.into(),
        grant_sha384: grant.grant_digest().into(),
        aggregate_sha384: aggregate.digest_sha384().into(),
        request_sha384: policy.request.digest_sha384().unwrap(),
        session_id: policy.session_id.clone(),
        runtime_sha384: policy.runtime_sha384.clone(),
        evidence_sha384: policy.evidence_sha384.clone(),
        init_data_sha384: policy.init_data_sha384.clone(),
        recorder_key_sha384: policy.recorder_key_sha384.clone(),
        keywrap_sha384: "10".repeat(48),
        ciphertext_sha384: sha384(jwe),
        workflow_id: policy.request.workflow_id.clone(),
        resource_path: policy.request.resource_path.clone(),
        validity: *grant.validity(),
    }
}
fn sign(statement: &CredentialDeliveryV1, key: &Ed25519KeyPair) -> Vec<u8> {
    serde_json::to_vec(&Signed {
        statement: statement.clone(),
        signature: crate::hex(key.sign(&statement.signing_bytes().unwrap()).as_ref()),
    })
    .unwrap()
}
fn expectations(f: &crate::policy_receipt::tests::Fixture) -> DeliveryExpectations {
    DeliveryExpectations {
        aggregate: AggregateExpectations {
            kbs_proof_public_key: f.expected.kbs_proof_public_key,
            expected: f.expected.expected.clone(),
        },
        audience: "credential-recorder".into(),
        issuer: "credential-producer".into(),
        keywrap_sha384: "10".repeat(48),
    }
}

#[test]
fn authentic_publication_binds_exact_ciphertext_not_plaintext_or_recipient_receipt() {
    let f = fixture();
    let aggregate =
        verify_policy_aggregate(&wire(&f.expected.expected, &f.proof), &f.grant, &f.expected)
            .unwrap();
    let ciphertext = b"opaque-jwe-publication";
    let raw = receipt(&f.grant, &aggregate, ciphertext);
    let verified = verify_credential_delivery(
        &sign(&raw, &f.proof),
        &f.grant,
        &aggregate,
        &expectations(&f),
        ciphertext,
        100,
    )
    .unwrap();
    assert!(verified.statement() == &raw);
    assert_eq!(verified.ciphertext_sha384(), sha384(ciphertext));
    assert_eq!(
        verified.kbs_proof_key_sha384(),
        sha384(f.proof.public_key().as_ref())
    );
    assert_eq!(verified.grant_digest(), f.grant.grant_digest());
    assert_eq!(verified.validity(), f.grant.validity());
    assert_eq!(verified.digest_sha384(), raw.digest_sha384().unwrap());
}

#[test]
fn signatures_actual_producer_and_independent_aggregate_expectations_are_required() {
    let f = fixture();
    let aggregate =
        verify_policy_aggregate(&wire(&f.expected.expected, &f.proof), &f.grant, &f.expected)
            .unwrap();
    let jwe = b"jwe";
    let raw = receipt(&f.grant, &aggregate, jwe);
    let good = sign(&raw, &f.proof);
    assert_eq!(
        verify_credential_delivery(
            &sign(&raw, &key()),
            &f.grant,
            &aggregate,
            &expectations(&f),
            jwe,
            100
        )
        .err(),
        Some(Error::InvalidSignature)
    );
    let attacker = key();
    let mut attacker_expected = expectations(&f);
    attacker_expected.aggregate.kbs_proof_public_key =
        attacker.public_key().as_ref().try_into().unwrap();
    let foreign_wrapper = verify_policy_aggregate(
        &wire(&f.expected.expected, &attacker),
        &f.grant,
        &attacker_expected.aggregate,
    )
    .unwrap();
    assert_eq!(
        verify_credential_delivery(
            &good,
            &f.grant,
            &foreign_wrapper,
            &expectations(&f),
            jwe,
            100
        )
        .err(),
        Some(Error::ConfusedKeys)
    );
    let mut changed = expectations(&f);
    changed.aggregate.expected.as_evaluation.input_sha384 = "99".repeat(48);
    assert_eq!(
        verify_credential_delivery(&good, &f.grant, &aggregate, &changed, jwe, 100).err(),
        Some(Error::BindingMismatch)
    );
}

#[test]
fn signed_context_domain_recipient_window_and_every_commitment_substitution_are_rejected() {
    let f = fixture();
    let aggregate =
        verify_policy_aggregate(&wire(&f.expected.expected, &f.proof), &f.grant, &f.expected)
            .unwrap();
    let jwe = b"jwe";
    let original = receipt(&f.grant, &aggregate, jwe);
    let changes: Vec<fn(&mut CredentialDeliveryV1)> = vec![
        |r| r.version += 1,
        |r| r.purpose = crate::admission::ADMISSION_PURPOSE.into(),
        |r| r.profile = crate::policy_receipt::POLICY_AGGREGATE_PROFILE.into(),
        |r| r.audience.push('x'),
        |r| r.issuer.push('x'),
        |r| r.grant_sha384 = "99".repeat(48),
        |r| r.aggregate_sha384 = "99".repeat(48),
        |r| r.request_sha384 = "99".repeat(48),
        |r| r.session_id = "99".repeat(32),
        |r| r.runtime_sha384 = "99".repeat(48),
        |r| r.evidence_sha384 = "99".repeat(48),
        |r| r.init_data_sha384 = "99".repeat(48),
        |r| r.recorder_key_sha384 = "99".repeat(48),
        |r| r.keywrap_sha384 = "99".repeat(48),
        |r| r.ciphertext_sha384 = "99".repeat(48),
        |r| r.workflow_id.push('x'),
        |r| r.resource_path[0].push('x'),
        |r| r.resource_path[1].push('x'),
        |r| r.resource_path[2].push('x'),
        |r| r.validity.expires += 1,
        |r| r.validity.not_before += 1,
    ];
    for change in changes {
        let mut raw = original.clone();
        change(&mut raw);
        assert!(verify_credential_delivery(
            &sign(&raw, &f.proof),
            &f.grant,
            &aggregate,
            &expectations(&f),
            jwe,
            100
        )
        .is_err());
    }
    assert!(verify_credential_delivery(
        &sign(&original, &f.proof),
        &f.grant,
        &aggregate,
        &expectations(&f),
        b"different-jwe",
        100
    )
    .is_err());
}

#[test]
fn even_exact_retry_requires_current_half_open_window_and_bounded_strict_wire() {
    let f = fixture();
    let aggregate =
        verify_policy_aggregate(&wire(&f.expected.expected, &f.proof), &f.grant, &f.expected)
            .unwrap();
    let jwe = b"jwe";
    let raw = receipt(&f.grant, &aggregate, jwe);
    let signed = sign(&raw, &f.proof);
    for (now, expected) in [
        (99, Error::NotYetValid),
        (200, Error::Expired),
        (u64::MAX, Error::InvalidTime),
    ] {
        assert_eq!(
            verify_credential_delivery(&signed, &f.grant, &aggregate, &expectations(&f), jwe, now)
                .err(),
            Some(expected)
        );
    }
    let mut unknown: serde_json::Value = serde_json::from_slice(&signed).unwrap();
    unknown["statement"]["accepted"] = true.into();
    assert_eq!(
        verify_credential_delivery(
            &serde_json::to_vec(&unknown).unwrap(),
            &f.grant,
            &aggregate,
            &expectations(&f),
            jwe,
            100
        )
        .err(),
        Some(Error::Malformed)
    );
    assert_eq!(
        verify_credential_delivery(
            &vec![b' '; crate::MAX_WIRE_BYTES + 1],
            &f.grant,
            &aggregate,
            &expectations(&f),
            jwe,
            100
        )
        .err(),
        Some(Error::TooLarge)
    );
    assert_eq!(
        verify_credential_delivery(
            &signed,
            &f.grant,
            &aggregate,
            &expectations(&f),
            &vec![0; MAX_CREDENTIAL_JWE_BYTES + 1],
            100
        )
        .err(),
        Some(Error::TooLarge)
    );
    let duplicate = String::from_utf8(signed.clone()).unwrap().replacen(
        "\"version\":1",
        "\"version\":1,\"version\":1",
        1,
    );
    assert_eq!(
        verify_credential_delivery(
            duplicate.as_bytes(),
            &f.grant,
            &aggregate,
            &expectations(&f),
            jwe,
            100
        )
        .err(),
        Some(Error::Malformed)
    );
    let mut invalid = raw.clone();
    invalid.keywrap_sha384 = "AB".repeat(48);
    assert_eq!(invalid.signing_bytes().err(), Some(Error::InvalidField));
}

#[test]
fn credential_operation_pop_cannot_reuse_policy_decision_signature() {
    let f = fixture();
    let policy = &f.expected.expected;
    let operation = SessionOperation::CredentialDelivery {
        session_id: policy.session_id.clone(),
        nonce: policy.request.request_nonce.clone(),
        runtime_sha384: policy.runtime_sha384.clone(),
        evidence_sha384: policy.evidence_sha384.clone(),
        request_sha384: policy.request.digest_sha384().unwrap(),
        aggregate_sha384: policy.digest_sha384().unwrap(),
    };
    let bytes = operation_signing_bytes(&f.grant, &operation).unwrap();
    let signature = crate::hex(f.recorder.sign(&bytes).as_ref());
    let public = f.recorder.public_key().as_ref().try_into().unwrap();
    verify_operation_pop(&f.grant, &operation, &public, &signature).unwrap();
    let policy_operation = SessionOperation::ResourceDecision {
        session_id: policy.session_id.clone(),
        nonce: policy.request.request_nonce.clone(),
        runtime_sha384: policy.runtime_sha384.clone(),
        evidence_sha384: policy.evidence_sha384.clone(),
        request_sha384: policy.request.digest_sha384().unwrap(),
    };
    assert_eq!(
        verify_operation_pop(&f.grant, &policy_operation, &public, &signature).err(),
        Some(Error::InvalidSignature)
    );
}

#[test]
fn historical_delivery_authentication_retains_exact_ciphertext_and_producer_checks() {
    let f = fixture();
    let aggregate =
        verify_policy_aggregate(&wire(&f.expected.expected, &f.proof), &f.grant, &f.expected)
            .unwrap();
    let jwe = b"authority-accepted-jwe";
    let statement = receipt(&f.grant, &aggregate, jwe);
    let signed = sign(&statement, &f.proof);
    let expected = expectations(&f);
    let authenticated =
        verify_credential_delivery_historical(&signed, &f.grant, &aggregate, &expected, jwe)
            .unwrap();
    assert_eq!(authenticated.validity(), f.grant.validity());
    assert_eq!(
        verify_credential_delivery(&signed, &f.grant, &aggregate, &expected, jwe, 200).err(),
        Some(Error::Expired)
    );
    assert_eq!(
        verify_credential_delivery_historical(
            &signed,
            &f.grant,
            &aggregate,
            &expected,
            b"substituted"
        )
        .err(),
        Some(Error::BindingMismatch)
    );
    assert_eq!(
        verify_credential_delivery_historical(
            &sign(&statement, &key()),
            &f.grant,
            &aggregate,
            &expected,
            jwe
        )
        .err(),
        Some(Error::InvalidSignature)
    );
}
