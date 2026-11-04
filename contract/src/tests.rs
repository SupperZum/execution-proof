use super::*;
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};

struct Fixture {
    l: LaunchGrant,
    a: ProofAppraisal,
    expected: TrustedExpectations,
    lk: Ed25519KeyPair,
    ak: Ed25519KeyPair,
}

fn key() -> Ed25519KeyPair {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

fn fixture() -> Fixture {
    let (lk, ak) = (key(), key());
    let binding = LaunchBinding {
        authority: "tenant-authority".into(),
        tenant: "tenant-1".into(),
        workload_id: "workload-1".into(),
        container_role: "application-init".into(),
        attempt_id: "attempt-1".into(),
        boot_id: "boot-1".into(),
        channel_key_sha384: "01".repeat(48),
        bootstrap_context_sha384: "10".repeat(48),
        selected_manifest_sha256: "02".repeat(32),
        effective_launch_sha384: "03".repeat(48),
        profile_sha384: "04".repeat(48),
        launch_policy_sha384: "05".repeat(48),
        image_policy_sha384: "06".repeat(48),
        challenge_sha384: "07".repeat(48),
    };
    let evaluation = EvaluationCommitments {
        policy_id: "affirming_tdx".into(),
        policy_sha384: "08".repeat(48),
        input_sha384: "09".repeat(48),
        rvps_sha384: "0a".repeat(48),
        acceptance_policy_sha384: "0b".repeat(48),
        kbs: KbsAssociation {
            decision_sha384: "0c".repeat(48),
            policy_sha384: "0d".repeat(48),
            input_sha384: "0e".repeat(48),
            session_sha384: "0f".repeat(48),
        },
    };
    let l = LaunchGrant {
        version: VERSION,
        purpose: GRANT_PURPOSE.into(),
        audience: "prototype-verifier".into(),
        proof_required: true,
        grant_id: "grant-1".into(),
        validity: ValidityWindow {
            not_before: 100,
            expires: 200,
        },
        binding: binding.clone(),
    };
    let a = ProofAppraisal {
        version: VERSION,
        purpose: APPRAISAL_PURPOSE.into(),
        audience: l.audience.clone(),
        issuer: "as-1".into(),
        verdict: AppraisalVerdict::Affirming,
        grant_sha384: l.digest_sha384().unwrap(),
        binding: binding.clone(),
        evaluation: evaluation.clone(),
    };
    let expected = TrustedExpectations {
        authority_public_key: lk.public_key().as_ref().try_into().unwrap(),
        as_proof_public_key: ak.public_key().as_ref().try_into().unwrap(),
        audience: l.audience.clone(),
        as_issuer: a.issuer.clone(),
        grant_id: l.grant_id.clone(),
        binding,
        evaluation,
    };
    Fixture {
        l,
        a,
        expected,
        lk,
        ak,
    }
}

fn signed<T: Serialize + Clone>(value: &T, transcript: &[u8], key: &Ed25519KeyPair) -> Vec<u8> {
    serde_json::to_vec(&Signed {
        statement: value.clone(),
        signature: hex(key.sign(transcript).as_ref()),
    })
    .unwrap()
}

fn wire(f: &Fixture) -> (Vec<u8>, Vec<u8>) {
    (
        signed(&f.l, &f.l.signing_bytes().unwrap(), &f.lk),
        signed(&f.a, &f.a.signing_bytes().unwrap(), &f.ak),
    )
}

fn outcome(f: &Fixture) -> Result<VerifiedStatements, Error> {
    let (l, a) = wire(f);
    verify_statements(&l, &a, &f.expected)
}

fn rejected(result: Result<VerifiedStatements, Error>, expected: Error) {
    assert_eq!(result.err(), Some(expected));
}

#[test]
fn authentic_statements_and_deterministic_framing() {
    let f = fixture();
    let result = outcome(&f).unwrap();
    assert_eq!(result.binding(), &f.l.binding);
    assert_eq!(result.grant_digest(), f.l.digest_sha384().unwrap());
    assert_eq!(result.appraisal_digest(), f.a.digest_sha384().unwrap());
    assert_eq!(result.context_digest().len(), 96);
    assert_eq!(
        result.authority_key_sha384(),
        sha384(&f.expected.authority_public_key)
    );
    assert_eq!(
        result.as_proof_key_sha384(),
        sha384(&f.expected.as_proof_public_key)
    );
    assert_eq!(
        result.context_digest(),
        outcome(&f).unwrap().context_digest()
    );
    let (l, a) = wire(&f);
    let value: serde_json::Value = serde_json::from_slice(&l).unwrap();
    let pretty = serde_json::to_vec_pretty(&value).unwrap();
    assert_eq!(
        verify_statements(&pretty, &a, &f.expected)
            .unwrap()
            .context_digest(),
        result.context_digest()
    );
    assert_ne!(f.l.signing_bytes().unwrap(), f.a.signing_bytes().unwrap());
}

#[test]
fn forged_or_cross_domain_signatures_rejected() {
    let f = fixture();
    let (l, a) = wire(&f);
    let attacker = key();
    let bad_l = signed(&f.l, &f.l.signing_bytes().unwrap(), &attacker);
    rejected(
        verify_statements(&bad_l, &a, &f.expected),
        Error::InvalidSignature,
    );
    let bad_a = signed(&f.a, &f.a.signing_bytes().unwrap(), &attacker);
    rejected(
        verify_statements(&l, &bad_a, &f.expected),
        Error::InvalidSignature,
    );
    let crossed = signed(&f.a, &f.a.signing_bytes().unwrap(), &f.lk);
    rejected(
        verify_statements(&l, &crossed, &f.expected),
        Error::InvalidSignature,
    );
}

#[test]
fn purpose_audience_issuer_version_and_proof_required_are_enforced() {
    let mut f = fixture();
    f.l.purpose = "resource-access".into();
    rejected(outcome(&f), Error::WrongPurpose);
    let mut f = fixture();
    f.a.purpose = "resource-access".into();
    rejected(outcome(&f), Error::WrongPurpose);
    let mut f = fixture();
    f.l.audience = "other".into();
    rejected(outcome(&f), Error::WrongAudience);
    let mut f = fixture();
    f.a.audience = "other".into();
    rejected(outcome(&f), Error::WrongAudience);
    let mut f = fixture();
    f.a.issuer = "other-as".into();
    rejected(outcome(&f), Error::WrongIssuer);
    let mut f = fixture();
    f.l.version = VERSION + 1;
    rejected(outcome(&f), Error::UnsupportedVersion);
    let mut f = fixture();
    f.a.version = VERSION + 1;
    rejected(outcome(&f), Error::UnsupportedVersion);
    let mut f = fixture();
    f.l.proof_required = false;
    rejected(outcome(&f), Error::ProofRequired);
    let mut f = fixture();
    f.expected.as_proof_public_key = f.expected.authority_public_key;
    rejected(outcome(&f), Error::ConfusedKeys);
}

#[test]
fn negative_and_unknown_signed_appraisals_rejected() {
    for verdict in [AppraisalVerdict::Negative, AppraisalVerdict::Unknown] {
        let mut f = fixture();
        f.a.verdict = verdict;
        rejected(outcome(&f), Error::UnacceptedAppraisal);
    }
}

#[test]
fn every_identity_content_and_policy_field_is_pinned_externally() {
    for mutate in [
        |b: &mut LaunchBinding| b.authority = "other".into(),
        |b: &mut LaunchBinding| b.tenant = "other".into(),
        |b: &mut LaunchBinding| b.workload_id = "other".into(),
        |b: &mut LaunchBinding| b.attempt_id = "other".into(),
        |b: &mut LaunchBinding| b.boot_id = "other".into(),
        |b: &mut LaunchBinding| b.channel_key_sha384 = "11".repeat(48),
        |b: &mut LaunchBinding| b.bootstrap_context_sha384 = "11".repeat(48),
        |b: &mut LaunchBinding| b.selected_manifest_sha256 = "11".repeat(32),
        |b: &mut LaunchBinding| b.effective_launch_sha384 = "11".repeat(48),
        |b: &mut LaunchBinding| b.profile_sha384 = "11".repeat(48),
        |b: &mut LaunchBinding| b.launch_policy_sha384 = "11".repeat(48),
        |b: &mut LaunchBinding| b.image_policy_sha384 = "11".repeat(48),
        |b: &mut LaunchBinding| b.challenge_sha384 = "11".repeat(48),
    ] {
        let mut f = fixture();
        mutate(&mut f.expected.binding);
        rejected(outcome(&f), Error::BindingMismatch);
        let mut f = fixture();
        mutate(&mut f.a.binding);
        rejected(outcome(&f), Error::BindingMismatch);
    }
    let mut f = fixture();
    f.l.binding.container_role = "helper".into();
    rejected(outcome(&f), Error::UnsupportedRole);
    let mut f = fixture();
    f.expected.grant_id = "other".into();
    rejected(outcome(&f), Error::BindingMismatch);
    let mut f = fixture();
    f.a.grant_sha384 = "ff".repeat(48);
    rejected(outcome(&f), Error::BindingMismatch);
}

#[test]
fn policy_input_reference_predicate_and_kbs_session_bindings_are_required() {
    for mutate in [
        |e: &mut EvaluationCommitments| e.policy_id = "other".into(),
        |e: &mut EvaluationCommitments| e.policy_sha384 = "11".repeat(48),
        |e: &mut EvaluationCommitments| e.input_sha384 = "11".repeat(48),
        |e: &mut EvaluationCommitments| e.rvps_sha384 = "11".repeat(48),
        |e: &mut EvaluationCommitments| e.acceptance_policy_sha384 = "11".repeat(48),
        |e: &mut EvaluationCommitments| e.kbs.decision_sha384 = "11".repeat(48),
        |e: &mut EvaluationCommitments| e.kbs.policy_sha384 = "11".repeat(48),
        |e: &mut EvaluationCommitments| e.kbs.input_sha384 = "11".repeat(48),
        |e: &mut EvaluationCommitments| e.kbs.session_sha384 = "11".repeat(48),
    ] {
        let mut f = fixture();
        mutate(&mut f.a.evaluation);
        rejected(outcome(&f), Error::BindingMismatch);
    }
    let f = fixture();
    let (l, a) = wire(&f);
    let mut v: serde_json::Value = serde_json::from_slice(&a).unwrap();
    v["statement"]["evaluation"]["kbs"]["decision_sha384"] = "".into();
    rejected(
        verify_statements(&l, &serde_json::to_vec(&v).unwrap(), &f.expected),
        Error::InvalidField,
    );
    v["statement"]["evaluation"]
        .as_object_mut()
        .unwrap()
        .remove("kbs");
    rejected(
        verify_statements(&l, &serde_json::to_vec(&v).unwrap(), &f.expected),
        Error::Malformed,
    );
}

#[test]
fn strict_bounded_json_hex_and_identifiers() {
    let f = fixture();
    let (l, a) = wire(&f);
    rejected(
        verify_statements(&vec![b' '; MAX_WIRE_BYTES + 1], &a, &f.expected),
        Error::TooLarge,
    );
    rejected(
        verify_statements(&l, &vec![b' '; MAX_WIRE_BYTES + 1], &f.expected),
        Error::TooLarge,
    );
    let mut v: serde_json::Value = serde_json::from_slice(&l).unwrap();
    v["unexpected"] = true.into();
    rejected(
        verify_statements(&serde_json::to_vec(&v).unwrap(), &a, &f.expected),
        Error::Malformed,
    );
    let raw = String::from_utf8(l.clone()).unwrap().replacen(
        &format!("\"version\":{VERSION}"),
        &format!("\"version\":{VERSION},\"version\":{VERSION}"),
        1,
    );
    rejected(
        verify_statements(raw.as_bytes(), &a, &f.expected),
        Error::Malformed,
    );
    let mut v: serde_json::Value = serde_json::from_slice(&l).unwrap();
    v["statement"]["binding"]["boot_id"] = "x".repeat(MAX_ID_BYTES + 1).into();
    rejected(
        verify_statements(&serde_json::to_vec(&v).unwrap(), &a, &f.expected),
        Error::InvalidField,
    );
    for bad in ["AB".repeat(48), "00".repeat(47), "zz".repeat(48)] {
        let mut v: serde_json::Value = serde_json::from_slice(&l).unwrap();
        v["statement"]["binding"]["channel_key_sha384"] = bad.into();
        rejected(
            verify_statements(&serde_json::to_vec(&v).unwrap(), &a, &f.expected),
            Error::InvalidField,
        );
    }
    let mut v: serde_json::Value = serde_json::from_slice(&l).unwrap();
    v["statement"]["binding"]["attempt_id"] = "../escape".into();
    rejected(
        verify_statements(&serde_json::to_vec(&v).unwrap(), &a, &f.expected),
        Error::InvalidField,
    );
    v["statement"]["binding"]["attempt_id"] = "".into();
    rejected(
        verify_statements(&serde_json::to_vec(&v).unwrap(), &a, &f.expected),
        Error::InvalidField,
    );
}

#[test]
fn validity_windows_are_half_open_bounded_and_big_endian_framed() {
    let window = ValidityWindow {
        not_before: 100,
        expires: 200,
    };
    assert_eq!(window.check_at(99), Err(Error::NotYetValid));
    assert_eq!(window.check_at(100), Ok(()));
    assert_eq!(window.check_at(199), Ok(()));
    assert_eq!(window.check_at(200), Err(Error::Expired));
    assert_eq!(window.check_at(u64::MAX), Err(Error::InvalidTime));
    for window in [
        ValidityWindow {
            not_before: 1,
            expires: 1,
        },
        ValidityWindow {
            not_before: 2,
            expires: 1,
        },
        ValidityWindow {
            not_before: 0,
            expires: u64::MAX,
        },
    ] {
        assert_eq!(window.validate(), Err(Error::InvalidTime));
    }
    assert_eq!(
        ValidityWindow {
            not_before: 0,
            expires: 1
        }
        .check_at(0),
        Ok(())
    );
    let edge = ValidityWindow {
        not_before: i64::MAX as u64 - 1,
        expires: i64::MAX as u64,
    };
    assert_eq!(edge.check_at(i64::MAX as u64 - 1), Ok(()));
    assert_eq!(edge.check_at(i64::MAX as u64), Err(Error::Expired));
    let mut frames = Vec::new();
    ValidityWindow {
        not_before: 1,
        expires: 2,
    }
    .append_to(&mut frames)
    .unwrap();
    assert_eq!(
        frames,
        [0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 2]
    );
}

#[test]
fn online_verification_checks_signed_window_but_historical_authentication_is_explicit() {
    let f = fixture();
    let (l, a) = wire(&f);
    for now in [100, 199] {
        assert_eq!(
            verify_statements_at(&l, &a, &f.expected, now)
                .unwrap()
                .validity(),
            &f.l.validity
        );
    }
    rejected(
        verify_statements_at(&l, &a, &f.expected, 99),
        Error::NotYetValid,
    );
    rejected(
        verify_statements_at(&l, &a, &f.expected, 200),
        Error::Expired,
    );
    rejected(
        verify_statements_at(&l, &a, &f.expected, u64::MAX),
        Error::InvalidTime,
    );
    // Signature-only inspection does not assert current authorization validity.
    assert!(verify_statements(&l, &a, &f.expected).is_ok());
    let mut altered: serde_json::Value = serde_json::from_slice(&l).unwrap();
    altered["statement"]["validity"]["expires"] = 201.into();
    rejected(
        verify_statements_at(&serde_json::to_vec(&altered).unwrap(), &a, &f.expected, 200),
        Error::InvalidSignature,
    );
    let mut changed = fixture();
    changed.l.validity.expires = 201;
    rejected(outcome(&changed), Error::BindingMismatch); // old appraisal H(L) cannot cover a new window.
}

#[test]
fn missing_invalid_overflowing_or_old_grant_windows_fail_closed() {
    let f = fixture();
    let (l, a) = wire(&f);
    let original: serde_json::Value = serde_json::from_slice(&l).unwrap();
    let mut missing = original.clone();
    missing["statement"]
        .as_object_mut()
        .unwrap()
        .remove("validity");
    rejected(
        verify_statements(&serde_json::to_vec(&missing).unwrap(), &a, &f.expected),
        Error::Malformed,
    );
    for invalid in [
        serde_json::json!({"not_before":100,"expires":100}),
        serde_json::json!({"not_before":0,"expires":u64::MAX}),
    ] {
        let mut value = original.clone();
        value["statement"]["validity"] = invalid;
        rejected(
            verify_statements(&serde_json::to_vec(&value).unwrap(), &a, &f.expected),
            Error::InvalidTime,
        );
    }
    let mut negative = original.clone();
    negative["statement"]["validity"]["not_before"] = (-1).into();
    rejected(
        verify_statements(&serde_json::to_vec(&negative).unwrap(), &a, &f.expected),
        Error::Malformed,
    );
    let mut extra = original;
    extra["statement"]["validity"]["clock"] = "guest".into();
    rejected(
        verify_statements(&serde_json::to_vec(&extra).unwrap(), &a, &f.expected),
        Error::Malformed,
    );
    let mut old = fixture();
    old.l.version = VERSION - 1;
    rejected(outcome(&old), Error::UnsupportedVersion);
}

fn unappraised_grant() -> (LaunchGrant, GrantExpectations, Ed25519KeyPair) {
    let authority = key();
    let binding = LaunchBinding {
        authority: "standalone-authority".into(),
        tenant: "standalone-tenant".into(),
        workload_id: "workload-before-appraisal".into(),
        container_role: "application-init".into(),
        attempt_id: "attempt-one".into(),
        boot_id: "software-boot".into(),
        channel_key_sha384: "01".repeat(48),
        bootstrap_context_sha384: "02".repeat(48),
        selected_manifest_sha256: "03".repeat(32),
        effective_launch_sha384: "04".repeat(48),
        profile_sha384: "05".repeat(48),
        launch_policy_sha384: "06".repeat(48),
        image_policy_sha384: "07".repeat(48),
        challenge_sha384: "08".repeat(48),
    };
    let grant = LaunchGrant {
        version: VERSION,
        purpose: GRANT_PURPOSE.into(),
        audience: "standalone-as".into(),
        proof_required: true,
        grant_id: "standalone-grant".into(),
        validity: ValidityWindow {
            not_before: 100,
            expires: 200,
        },
        binding,
    };
    let expected = GrantExpectations {
        authority_public_key: authority.public_key().as_ref().try_into().unwrap(),
        audience: grant.audience.clone(),
        authority: grant.binding.authority.clone(),
        tenant: grant.binding.tenant.clone(),
        profile_sha384: grant.binding.profile_sha384.clone(),
        launch_policy_sha384: grant.binding.launch_policy_sha384.clone(),
        image_policy_sha384: grant.binding.image_policy_sha384.clone(),
    };
    (grant, expected, authority)
}

#[test]
fn standalone_grant_requires_no_appraisal_and_checks_current_window() {
    let (grant, expected, authority) = unappraised_grant();
    let wire = signed(&grant, &grant.signing_bytes().unwrap(), &authority);
    // No AS key, appraisal, verdict, or policy-evaluation object is produced here.
    for now in [100, 199] {
        let verified = verify_launch_grant(&wire, &expected, now).unwrap();
        assert_eq!(verified.binding(), &grant.binding);
        assert_eq!(verified.grant_id(), grant.grant_id);
        assert_eq!(verified.validity(), &grant.validity);
        assert_eq!(verified.grant_digest(), grant.digest_sha384().unwrap());
        assert_eq!(
            verified.authority_key_sha384(),
            sha384(&expected.authority_public_key)
        );
    }
    assert_eq!(
        verify_launch_grant(&wire, &expected, 99).err(),
        Some(Error::NotYetValid)
    );
    assert_eq!(
        verify_launch_grant(&wire, &expected, 200).err(),
        Some(Error::Expired)
    );
    assert_eq!(
        verify_launch_grant(&wire, &expected, u64::MAX).err(),
        Some(Error::InvalidTime)
    );
}

#[test]
fn standalone_grant_enforces_external_authority_tenant_and_policy_scope() {
    for mutate in [
        |b: &mut LaunchBinding| b.authority = "foreign-authority".into(),
        |b: &mut LaunchBinding| b.tenant = "foreign-tenant".into(),
        |b: &mut LaunchBinding| b.profile_sha384 = "11".repeat(48),
        |b: &mut LaunchBinding| b.launch_policy_sha384 = "11".repeat(48),
        |b: &mut LaunchBinding| b.image_policy_sha384 = "11".repeat(48),
    ] {
        let (mut grant, expected, authority) = unappraised_grant();
        mutate(&mut grant.binding);
        let wire = signed(&grant, &grant.signing_bytes().unwrap(), &authority);
        assert_eq!(
            verify_launch_grant(&wire, &expected, 100).err(),
            Some(Error::BindingMismatch)
        );
    }
    let (grant, mut expected, authority) = unappraised_grant();
    let wire = signed(&grant, &grant.signing_bytes().unwrap(), &authority);
    expected.audience = "foreign-as".into();
    assert_eq!(
        verify_launch_grant(&wire, &expected, 100).err(),
        Some(Error::WrongAudience)
    );
    expected.audience = grant.audience.clone();
    expected.authority_public_key = key().public_key().as_ref().try_into().unwrap();
    assert_eq!(
        verify_launch_grant(&wire, &expected, 100).err(),
        Some(Error::InvalidSignature)
    );
}

#[test]
fn standalone_grant_rejects_forgery_wrong_purpose_version_and_launch_mode() {
    let (grant, expected, _) = unappraised_grant();
    let forged = signed(&grant, &grant.signing_bytes().unwrap(), &key());
    assert_eq!(
        verify_launch_grant(&forged, &expected, 100).err(),
        Some(Error::InvalidSignature)
    );
    for (mutate, error) in [
        (
            (|g: &mut LaunchGrant| g.version = VERSION - 1) as fn(&mut LaunchGrant),
            Error::UnsupportedVersion,
        ),
        (
            |g: &mut LaunchGrant| g.purpose = "resource-access".into(),
            Error::WrongPurpose,
        ),
        (
            |g: &mut LaunchGrant| g.proof_required = false,
            Error::ProofRequired,
        ),
        (
            |g: &mut LaunchGrant| g.binding.container_role = "helper".into(),
            Error::UnsupportedRole,
        ),
    ] {
        let (mut grant, expected, authority) = unappraised_grant();
        mutate(&mut grant);
        let wire = signed(&grant, &grant.signing_bytes().unwrap(), &authority);
        assert_eq!(
            verify_launch_grant(&wire, &expected, 100).err(),
            Some(error)
        );
    }
}

#[test]
fn standalone_grant_wire_is_strict_bounded_and_signature_covers_content() {
    let (grant, expected, authority) = unappraised_grant();
    let wire = signed(&grant, &grant.signing_bytes().unwrap(), &authority);
    let original: serde_json::Value = serde_json::from_slice(&wire).unwrap();
    let mut changed = original.clone();
    changed["statement"]["binding"]["selected_manifest_sha256"] = "ff".repeat(32).into();
    assert_eq!(
        verify_launch_grant(&serde_json::to_vec(&changed).unwrap(), &expected, 100).err(),
        Some(Error::InvalidSignature)
    );
    let mut changed = original.clone();
    changed["statement"]["accepted"] = true.into();
    assert_eq!(
        verify_launch_grant(&serde_json::to_vec(&changed).unwrap(), &expected, 100).err(),
        Some(Error::Malformed)
    );
    let mut missing = original;
    missing["statement"]
        .as_object_mut()
        .unwrap()
        .remove("validity");
    assert_eq!(
        verify_launch_grant(&serde_json::to_vec(&missing).unwrap(), &expected, 100).err(),
        Some(Error::Malformed)
    );
    let mut double = wire.clone();
    double.extend_from_slice(&wire);
    assert_eq!(
        verify_launch_grant(&double, &expected, 100).err(),
        Some(Error::Malformed)
    );
    let duplicate = String::from_utf8(wire).unwrap().replacen(
        "\"proof_required\":true",
        "\"proof_required\":true,\"proof_required\":true",
        1,
    );
    assert_eq!(
        verify_launch_grant(duplicate.as_bytes(), &expected, 100).err(),
        Some(Error::Malformed)
    );
    assert_eq!(
        verify_launch_grant(&vec![b' '; MAX_WIRE_BYTES + 1], &expected, 100).err(),
        Some(Error::TooLarge)
    );
}
