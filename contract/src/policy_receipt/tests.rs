use super::*;
use crate::{
    session::{operation_signing_bytes, verify_operation_pop, SessionOperation},
    verify_launch_grant, GrantExpectations, LaunchBinding, LaunchGrant, ValidityWindow,
    GRANT_PURPOSE, MAX_WIRE_BYTES, VERSION,
};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};

pub(crate) struct Fixture {
    pub(crate) grant: VerifiedLaunchGrant,
    pub(crate) raw_grant: LaunchGrant,
    pub(crate) authority: Ed25519KeyPair,
    pub(crate) recorder: Ed25519KeyPair,
    pub(crate) proof: Ed25519KeyPair,
    pub(crate) expected: AggregateExpectations,
}

pub(crate) fn key() -> Ed25519KeyPair {
    let encoded = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(encoded.as_ref()).unwrap()
}

fn authenticate(raw: &LaunchGrant, authority: &Ed25519KeyPair) -> VerifiedLaunchGrant {
    let expected = GrantExpectations {
        authority_public_key: authority.public_key().as_ref().try_into().unwrap(),
        audience: raw.audience.clone(),
        authority: raw.binding.authority.clone(),
        tenant: raw.binding.tenant.clone(),
        profile_sha384: raw.binding.profile_sha384.clone(),
        launch_policy_sha384: raw.binding.launch_policy_sha384.clone(),
        image_policy_sha384: raw.binding.image_policy_sha384.clone(),
    };
    let wire = serde_json::to_vec(&Signed {
        statement: raw.clone(),
        signature: crate::hex(authority.sign(&raw.signing_bytes().unwrap()).as_ref()),
    })
    .unwrap();
    verify_launch_grant(&wire, &expected, 100).unwrap()
}

pub(crate) fn fixture() -> Fixture {
    let (authority, recorder, proof) = (key(), key(), key());
    let raw_grant = LaunchGrant {
        version: VERSION,
        purpose: GRANT_PURPOSE.into(),
        audience: "policy-consumer".into(),
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
    let grant = authenticate(&raw_grant, &authority);
    let statement = LaunchPolicyAggregateV1 {
        version: POLICY_AGGREGATE_VERSION,
        purpose: POLICY_AGGREGATE_PURPOSE.into(),
        audience: "policy-consumer".into(),
        issuer: "combined-kbs-producer".into(),
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
            resource_path: ["repository".into(), "credential".into(), "version".into()],
            workflow_id: "policy-check".into(),
            request_nonce: "resource-nonce".into(),
        },
        as_evaluation: PolicyCommitments {
            policy_id: "launch_cpu".into(),
            policy_sha384: grant.binding().launch_policy_sha384.clone(),
            input_sha384: "0c".repeat(48),
            data_sha384: None,
        },
        kbs_evaluation: PolicyCommitments {
            policy_id: "resource-policy".into(),
            policy_sha384: "0d".repeat(48),
            input_sha384: "0e".repeat(48),
            data_sha384: Some("0f".repeat(48)),
        },
    };
    let expected = AggregateExpectations {
        kbs_proof_public_key: proof.public_key().as_ref().try_into().unwrap(),
        expected: statement,
    };
    Fixture {
        grant,
        raw_grant,
        authority,
        recorder,
        proof,
        expected,
    }
}

pub(crate) fn wire(statement: &LaunchPolicyAggregateV1, signer: &Ed25519KeyPair) -> Vec<u8> {
    serde_json::to_vec(&Signed {
        statement: statement.clone(),
        signature: crate::hex(signer.sign(&statement.signing_bytes().unwrap()).as_ref()),
    })
    .unwrap()
}

fn rejected(f: &Fixture, statement: &LaunchPolicyAggregateV1, error: Error) {
    assert_eq!(
        verify_policy_aggregate(&wire(statement, &f.proof), &f.grant, &f.expected).err(),
        Some(error)
    );
}

#[test]
fn dedicated_signature_authenticates_exact_policy_only_statement() {
    let f = fixture();
    let raw = wire(&f.expected.expected, &f.proof);
    let verified = verify_policy_aggregate(&raw, &f.grant, &f.expected).unwrap();
    assert!(verified.statement() == &f.expected.expected);
    assert_eq!(
        verified.digest_sha384(),
        f.expected.expected.digest_sha384().unwrap()
    );
    assert_eq!(
        verified.kbs_proof_key_sha384(),
        sha384(f.proof.public_key().as_ref())
    );
    let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(
        verify_policy_aggregate(
            &serde_json::to_vec_pretty(&value).unwrap(),
            &f.grant,
            &f.expected
        )
        .unwrap()
        .digest_sha384(),
        verified.digest_sha384()
    );
    assert_eq!(
        value["statement"]["as_evaluation"]["data_sha384"],
        serde_json::Value::Null
    );
}

#[test]
fn wrong_roots_purpose_audience_issuer_version_and_profile_fail_closed() {
    let f = fixture();
    assert_eq!(
        verify_policy_aggregate(&wire(&f.expected.expected, &key()), &f.grant, &f.expected).err(),
        Some(Error::InvalidSignature)
    );
    for (change, error) in [
        (
            (|s: &mut LaunchPolicyAggregateV1| s.purpose = "access-token".into())
                as fn(&mut LaunchPolicyAggregateV1),
            Error::WrongPurpose,
        ),
        (
            |s| s.audience = "resource-access".into(),
            Error::WrongAudience,
        ),
        (|s| s.issuer = "other-producer".into(), Error::WrongIssuer),
        (|s| s.version += 1, Error::UnsupportedVersion),
        (
            |s| s.profile = "resource-delivered".into(),
            Error::BindingMismatch,
        ),
    ] {
        let mut changed = f.expected.expected.clone();
        change(&mut changed);
        rejected(&f, &changed, error);
    }
}

#[test]
fn every_session_request_and_evaluation_change_is_bound() {
    let f = fixture();
    let changes: [fn(&mut LaunchPolicyAggregateV1); 15] = [
        |s| s.session_id = "10".repeat(32),
        |s| s.nonce.push('x'),
        |s| s.runtime_sha384 = "10".repeat(48),
        |s| s.init_data_sha384 = "10".repeat(48),
        |s| s.evidence_sha384 = "10".repeat(48),
        |s| s.request.resource_path[2] = "other-version".into(),
        |s| s.request.workflow_id = "other-workflow".into(),
        |s| s.request.request_nonce.push('x'),
        |s| s.as_evaluation.policy_id = "other_cpu".into(),
        |s| s.as_evaluation.input_sha384 = "10".repeat(48),
        |s| s.as_evaluation.data_sha384 = Some("10".repeat(48)),
        |s| s.kbs_evaluation.policy_id = "other-resource-policy".into(),
        |s| s.kbs_evaluation.policy_sha384 = "10".repeat(48),
        |s| s.kbs_evaluation.input_sha384 = "10".repeat(48),
        |s| s.kbs_evaluation.data_sha384 = None,
    ];
    for change in changes {
        let mut changed = f.expected.expected.clone();
        change(&mut changed);
        rejected(&f, &changed, Error::BindingMismatch);
    }
}

#[test]
fn grant_bindings_and_actual_authority_key_cannot_be_relabelled() {
    let f = fixture();
    let foreign = authenticate(&f.raw_grant, &key());
    assert_eq!(foreign.grant_digest(), f.grant.grant_digest());
    assert_eq!(
        verify_policy_aggregate(&wire(&f.expected.expected, &f.proof), &foreign, &f.expected).err(),
        Some(Error::BindingMismatch)
    );
    for change in [
        (|s: &mut LaunchPolicyAggregateV1| s.grant_sha384 = "10".repeat(48))
            as fn(&mut LaunchPolicyAggregateV1),
        |s| s.authority_key_sha384 = "10".repeat(48),
        |s| s.as_evaluation.policy_sha384 = "10".repeat(48),
        |s| s.recorder_key_sha384 = "10".repeat(48),
    ] {
        let mut expected = AggregateExpectations {
            kbs_proof_public_key: f.expected.kbs_proof_public_key,
            expected: f.expected.expected.clone(),
        };
        change(&mut expected.expected);
        assert_eq!(
            verify_policy_aggregate(&wire(&expected.expected, &f.proof), &f.grant, &expected).err(),
            Some(Error::BindingMismatch)
        );
    }
    for signer in [&f.authority, &f.recorder] {
        let expected = AggregateExpectations {
            kbs_proof_public_key: signer.public_key().as_ref().try_into().unwrap(),
            expected: f.expected.expected.clone(),
        };
        assert_eq!(
            verify_policy_aggregate(&wire(&expected.expected, signer), &f.grant, &expected).err(),
            Some(Error::ConfusedKeys)
        );
    }
}

#[test]
fn strict_bounded_wire_and_fixed_resource_request_profile() {
    let f = fixture();
    let raw = wire(&f.expected.expected, &f.proof);
    let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let mut extra = value.clone();
    extra["statement"]["access_token"] = true.into();
    let mut omitted = value.clone();
    omitted["statement"]["as_evaluation"]
        .as_object_mut()
        .unwrap()
        .remove("data_sha384");
    let duplicate = String::from_utf8(raw.clone())
        .unwrap()
        .replacen("\"version\":1", "\"version\":1,\"version\":1", 1)
        .into_bytes();
    for malformed in [
        serde_json::to_vec(&extra).unwrap(),
        serde_json::to_vec(&omitted).unwrap(),
        duplicate,
    ] {
        assert_eq!(
            verify_policy_aggregate(&malformed, &f.grant, &f.expected).err(),
            Some(Error::Malformed)
        );
    }
    assert_eq!(
        verify_policy_aggregate(&vec![b' '; MAX_WIRE_BYTES + 1], &f.grant, &f.expected).err(),
        Some(Error::TooLarge)
    );
    for change in [
        (|s: &mut LaunchPolicyAggregateV1| s.runtime_sha384 = "AA".repeat(48))
            as fn(&mut LaunchPolicyAggregateV1),
        |s| s.session_id = "aa".repeat(33),
        |s| s.nonce = "x".repeat(257),
        |s| s.request.method = "POST".into(),
        |s| s.request.plugin = "other".into(),
        |s| s.request.resource_path[0] = "..".into(),
        |s| s.request.resource_path[1] = "a/b".into(),
        |s| s.request.request_nonce = "\u{0430}".into(),
    ] {
        let mut changed = f.expected.expected.clone();
        change(&mut changed);
        assert_eq!(changed.signing_bytes().err(), Some(Error::InvalidField));
    }
}

fn operation(f: &Fixture, decision: bool) -> SessionOperation {
    let s = &f.expected.expected;
    if decision {
        SessionOperation::ResourceDecision {
            session_id: s.session_id.clone(),
            nonce: s.nonce.clone(),
            runtime_sha384: s.runtime_sha384.clone(),
            evidence_sha384: s.evidence_sha384.clone(),
            request_sha384: s.request.digest_sha384().unwrap(),
        }
    } else {
        SessionOperation::ResourceChallenge {
            session_id: s.session_id.clone(),
            nonce: s.nonce.clone(),
            runtime_sha384: s.runtime_sha384.clone(),
            evidence_sha384: s.evidence_sha384.clone(),
        }
    }
}

#[test]
fn recorder_operations_bind_kind_key_request_and_grant() {
    let f = fixture();
    let public = f.recorder.public_key().as_ref().try_into().unwrap();
    let begin = SessionOperation::Begin {
        key_sha384: "01".repeat(48),
    };
    for op in [&begin, &operation(&f, false), &operation(&f, true)] {
        let signature = crate::hex(
            f.recorder
                .sign(&operation_signing_bytes(&f.grant, op).unwrap())
                .as_ref(),
        );
        assert_eq!(
            verify_operation_pop(&f.grant, op, &public, &signature),
            Ok(())
        );
    }
    let challenge = operation(&f, false);
    let signature = crate::hex(
        f.recorder
            .sign(&operation_signing_bytes(&f.grant, &challenge).unwrap())
            .as_ref(),
    );
    assert_eq!(
        verify_operation_pop(&f.grant, &operation(&f, true), &public, &signature),
        Err(Error::InvalidSignature)
    );
    let signature = crate::hex(
        f.recorder
            .sign(&operation_signing_bytes(&f.grant, &begin).unwrap())
            .as_ref(),
    );
    let changed = SessionOperation::Begin {
        key_sha384: "02".repeat(48),
    };
    assert_eq!(
        verify_operation_pop(&f.grant, &changed, &public, &signature),
        Err(Error::InvalidSignature)
    );
    let mut raw = f.raw_grant.clone();
    raw.grant_id = "other-grant".into();
    let other = authenticate(&raw, &f.authority);
    assert_eq!(
        verify_operation_pop(&other, &begin, &public, &signature),
        Err(Error::InvalidSignature)
    );
    assert_eq!(
        verify_operation_pop(
            &f.grant,
            &begin,
            &key().public_key().as_ref().try_into().unwrap(),
            &signature
        ),
        Err(Error::BindingMismatch)
    );
    let mut changed = operation(&f, true);
    if let SessionOperation::ResourceDecision { request_sha384, .. } = &mut changed {
        *request_sha384 = "10".repeat(48);
    }
    let signature = crate::hex(
        f.recorder
            .sign(&operation_signing_bytes(&f.grant, &operation(&f, true)).unwrap())
            .as_ref(),
    );
    assert_eq!(
        verify_operation_pop(&f.grant, &changed, &public, &signature),
        Err(Error::InvalidSignature)
    );
}

#[test]
fn operation_input_bounds_and_domains_fail_closed() {
    let f = fixture();
    for change in [
        (|op: &mut SessionOperation| {
            if let SessionOperation::ResourceDecision { session_id, .. } = op {
                *session_id = "00".repeat(31);
            }
        }) as fn(&mut SessionOperation),
        |op| {
            if let SessionOperation::ResourceDecision { nonce, .. } = op {
                *nonce = String::new();
            }
        },
        |op| {
            if let SessionOperation::ResourceDecision { nonce, .. } = op {
                *nonce = "\u{0430}".into();
            }
        },
        |op| {
            if let SessionOperation::ResourceDecision { runtime_sha384, .. } = op {
                *runtime_sha384 = "AA".repeat(48);
            }
        },
        |op| {
            if let SessionOperation::ResourceDecision { request_sha384, .. } = op {
                *request_sha384 = "gg".repeat(48);
            }
        },
    ] {
        let mut op = operation(&f, true);
        change(&mut op);
        assert_eq!(
            operation_signing_bytes(&f.grant, &op).err(),
            Some(Error::InvalidField)
        );
    }
    let op = operation(&f, true);
    let mut bytes = operation_signing_bytes(&f.grant, &op).unwrap();
    let marker = crate::session::OPERATION_PURPOSE.as_bytes();
    let offset = bytes
        .windows(marker.len())
        .position(|part| part == marker)
        .unwrap();
    bytes[offset] ^= 1;
    let signature = crate::hex(f.recorder.sign(&bytes).as_ref());
    assert_eq!(
        verify_operation_pop(
            &f.grant,
            &op,
            &f.recorder.public_key().as_ref().try_into().unwrap(),
            &signature
        ),
        Err(Error::InvalidSignature)
    );
}
