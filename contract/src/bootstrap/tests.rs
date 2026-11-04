use super::*;
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};

fn key() -> Ed25519KeyPair {
    let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap()
}

fn public(key: &Ed25519KeyPair) -> [u8; 32] {
    key.public_key().as_ref().try_into().unwrap()
}

fn signed<T: Serialize + Clone>(statement: &T, bytes: &[u8], key: &Ed25519KeyPair) -> Vec<u8> {
    serde_json::to_vec(&Signed {
        statement: statement.clone(),
        signature: super::super::hex(key.sign(bytes).as_ref()),
    })
    .unwrap()
}

fn intent() -> TenantIntent {
    TenantIntent {
        version: TENANT_INTENT_VERSION,
        purpose: TENANT_INTENT_PURPOSE.into(),
        audience: "software-issuer".into(),
        authority: "authority-one".into(),
        tenant: "tenant-one".into(),
        workload_id: "workload-one".into(),
        container_role: "application-init".into(),
        attempt_id: "attempt-one".into(),
        selected_manifest_sha256: "01".repeat(32),
        effective_launch_sha384: "02".repeat(48),
        profile_sha384: "03".repeat(48),
        launch_policy_sha384: "04".repeat(48),
        image_policy_sha384: "05".repeat(48),
        validity: ValidityWindow {
            not_before: 100,
            expires: 300,
        },
    }
}

fn tenant_expected(key: &Ed25519KeyPair) -> TenantIntentExpectations {
    let intent = intent();
    TenantIntentExpectations {
        tenant_public_key: public(key),
        audience: intent.audience,
        authority: intent.authority,
        tenant: intent.tenant,
        profile_sha384: intent.profile_sha384,
    }
}

struct Fixture {
    appraisal: BootstrapAppraisal,
    possession: RecorderPossession,
    expected: BootstrapExpectations,
    verifier: Ed25519KeyPair,
    recorder: Ed25519KeyPair,
}

fn fixture() -> Fixture {
    let (verifier, recorder) = (key(), key());
    let challenge = BootstrapChallenge {
        version: BOOTSTRAP_VERSION,
        purpose: CHALLENGE_PURPOSE.into(),
        audience: "software-issuer".into(),
        authority: "authority-one".into(),
        tenant: "tenant-one".into(),
        workload_id: "workload-one".into(),
        attempt_id: "attempt-one".into(),
        challenge_id: "challenge-one".into(),
        nonce_hex: "06".repeat(32),
        intent_sha384: intent().digest_sha384().unwrap(),
        boot_profile_sha384: "07".repeat(48),
        producer_profile_sha384: "08".repeat(48),
        validity: ValidityWindow {
            not_before: 100,
            expires: 200,
        },
    };
    let appraisal = BootstrapAppraisal {
        version: BOOTSTRAP_VERSION,
        purpose: BOOTSTRAP_APPRAISAL_PURPOSE.into(),
        audience: challenge.audience.clone(),
        issuer: "software-bootstrap-verifier".into(),
        verdict: AppraisalVerdict::Affirming,
        binding: BootstrapBinding {
            challenge_sha384: challenge.digest_sha384().unwrap(),
            boot_id: "software-boot-one".into(),
            boot_nonce_hex: "09".repeat(32),
            recorder_public_key_hex: super::super::hex(&public(&recorder)),
        },
        boot_profile_sha384: challenge.boot_profile_sha384.clone(),
        producer_profile_sha384: challenge.producer_profile_sha384.clone(),
        evidence_sha384: "0a".repeat(48),
        policy_sha384: "0b".repeat(48),
        input_sha384: "0c".repeat(48),
        rvps_sha384: "0d".repeat(48),
    };
    let possession = RecorderPossession {
        version: BOOTSTRAP_VERSION,
        purpose: POSSESSION_PURPOSE.into(),
        audience: challenge.audience.clone(),
        challenge_sha384: challenge.digest_sha384().unwrap(),
        appraisal_sha384: appraisal.digest_sha384().unwrap(),
    };
    let expected = BootstrapExpectations {
        challenge,
        verifier_public_key: public(&verifier),
        verifier_issuer: appraisal.issuer.clone(),
        policy_sha384: appraisal.policy_sha384.clone(),
        input_sha384: appraisal.input_sha384.clone(),
        rvps_sha384: appraisal.rvps_sha384.clone(),
    };
    Fixture {
        appraisal,
        possession,
        expected,
        verifier,
        recorder,
    }
}

fn wire(f: &Fixture) -> (Vec<u8>, Vec<u8>) {
    (
        signed(
            &f.appraisal,
            &f.appraisal.signing_bytes().unwrap(),
            &f.verifier,
        ),
        signed(
            &f.possession,
            &f.possession.signing_bytes().unwrap(),
            &f.recorder,
        ),
    )
}

fn verify(f: &Fixture) -> Result<VerifiedBootstrapStatements, Error> {
    let (a, p) = wire(f);
    verify_bootstrap_statements(&a, &p, &f.expected)
}

#[test]
fn authentic_software_statements_preserve_exact_keys_context_and_scope() {
    let f = fixture();
    let v = verify(&f).unwrap();
    assert_eq!(v.challenge(), &f.expected.challenge);
    assert_eq!(v.binding(), &f.appraisal.binding);
    assert_eq!(v.recorder_public_key(), &public(&f.recorder));
    assert_eq!(
        v.recorder_public_key_hex(),
        super::super::hex(&public(&f.recorder))
    );
    assert_eq!(v.channel_key_sha384(), sha384(&public(&f.recorder)));
    assert_eq!(v.verifier_key_sha384(), sha384(&public(&f.verifier)));
    assert_eq!(
        v.challenge_digest(),
        f.expected.challenge.digest_sha384().unwrap()
    );
    assert_eq!(v.appraisal_digest(), f.appraisal.digest_sha384().unwrap());
    assert_eq!(v.boot_id(), "software-boot-one");
    assert_eq!(v.context_digest(), verify(&f).unwrap().context_digest());
    assert_ne!(
        f.expected.challenge.signing_bytes().unwrap(),
        f.appraisal.binding.signing_bytes().unwrap()
    );
}

#[test]
fn recorder_possession_and_dedicated_verifier_signatures_are_both_required() {
    let f = fixture();
    let (a, p) = wire(&f);
    let attacker = key();
    let fake_a = signed(
        &f.appraisal,
        &f.appraisal.signing_bytes().unwrap(),
        &attacker,
    );
    assert_eq!(
        verify_bootstrap_statements(&fake_a, &p, &f.expected).err(),
        Some(Error::InvalidSignature)
    );
    let fake_p = signed(
        &f.possession,
        &f.possession.signing_bytes().unwrap(),
        &attacker,
    );
    assert_eq!(
        verify_bootstrap_statements(&a, &fake_p, &f.expected).err(),
        Some(Error::InvalidSignature)
    );
    let mut f = fixture();
    f.expected.verifier_public_key = public(&f.recorder);
    assert_eq!(verify(&f).err(), Some(Error::ConfusedKeys));
}

#[test]
fn challenge_nonce_scope_and_intent_cannot_be_substituted() {
    for mutate in [
        |c: &mut BootstrapChallenge| c.nonce_hex = "11".repeat(32),
        |c: &mut BootstrapChallenge| c.challenge_id = "other".into(),
        |c: &mut BootstrapChallenge| c.authority = "other".into(),
        |c: &mut BootstrapChallenge| c.tenant = "other".into(),
        |c: &mut BootstrapChallenge| c.workload_id = "other".into(),
        |c: &mut BootstrapChallenge| c.attempt_id = "other".into(),
        |c: &mut BootstrapChallenge| c.intent_sha384 = "11".repeat(48),
    ] {
        let mut f = fixture();
        mutate(&mut f.expected.challenge);
        assert_eq!(verify(&f).err(), Some(Error::BindingMismatch));
    }
    let mut f = fixture();
    f.expected.challenge.nonce_hex = "00".repeat(32);
    assert_eq!(verify(&f).err(), Some(Error::InvalidField));
}

#[test]
fn profile_policy_reference_key_boot_and_receipt_swaps_rejected() {
    for mutate in [
        |a: &mut BootstrapAppraisal| a.binding.challenge_sha384 = "11".repeat(48),
        |a: &mut BootstrapAppraisal| a.boot_profile_sha384 = "11".repeat(48),
        |a: &mut BootstrapAppraisal| a.producer_profile_sha384 = "11".repeat(48),
        |a: &mut BootstrapAppraisal| a.policy_sha384 = "11".repeat(48),
        |a: &mut BootstrapAppraisal| a.input_sha384 = "11".repeat(48),
        |a: &mut BootstrapAppraisal| a.rvps_sha384 = "11".repeat(48),
        |a: &mut BootstrapAppraisal| a.binding.boot_id = "other".into(),
        |a: &mut BootstrapAppraisal| a.binding.boot_nonce_hex = "11".repeat(32),
    ] {
        let mut f = fixture();
        mutate(&mut f.appraisal);
        assert_eq!(verify(&f).err(), Some(Error::BindingMismatch));
    }
    let mut f = fixture();
    f.possession.challenge_sha384 = "11".repeat(48);
    assert_eq!(verify(&f).err(), Some(Error::BindingMismatch));
    let mut f = fixture();
    f.possession.appraisal_sha384 = "11".repeat(48);
    assert_eq!(verify(&f).err(), Some(Error::BindingMismatch));
    let mut f = fixture();
    f.appraisal.binding.recorder_public_key_hex = super::super::hex(&public(&key()));
    assert_eq!(verify(&f).err(), Some(Error::InvalidSignature));
}

#[test]
fn bootstrap_version_purpose_audience_issuer_and_verdict_are_enforced() {
    let mut f = fixture();
    f.appraisal.version = BOOTSTRAP_VERSION + 1;
    assert_eq!(verify(&f).err(), Some(Error::UnsupportedVersion));
    let mut f = fixture();
    f.possession.version = BOOTSTRAP_VERSION + 1;
    assert_eq!(verify(&f).err(), Some(Error::UnsupportedVersion));
    let mut f = fixture();
    f.appraisal.purpose = "resource-access".into();
    assert_eq!(verify(&f).err(), Some(Error::WrongPurpose));
    let mut f = fixture();
    f.possession.purpose = "resource-access".into();
    assert_eq!(verify(&f).err(), Some(Error::WrongPurpose));
    let mut f = fixture();
    f.appraisal.audience = "other".into();
    assert_eq!(verify(&f).err(), Some(Error::WrongAudience));
    let mut f = fixture();
    f.possession.audience = "other".into();
    assert_eq!(verify(&f).err(), Some(Error::WrongAudience));
    let mut f = fixture();
    f.appraisal.issuer = "other".into();
    assert_eq!(verify(&f).err(), Some(Error::WrongIssuer));
    for verdict in [AppraisalVerdict::Negative, AppraisalVerdict::Unknown] {
        let mut f = fixture();
        f.appraisal.verdict = verdict;
        assert_eq!(verify(&f).err(), Some(Error::UnacceptedAppraisal));
    }
}

#[test]
fn bootstrap_json_is_bounded_and_rejects_unknown_duplicate_and_invalid_fields() {
    let f = fixture();
    let (a, p) = wire(&f);
    assert_eq!(
        verify_bootstrap_statements(
            &vec![b' '; super::super::MAX_WIRE_BYTES + 1],
            &p,
            &f.expected
        )
        .err(),
        Some(Error::TooLarge)
    );
    assert_eq!(
        verify_bootstrap_statements(
            &a,
            &vec![b' '; super::super::MAX_WIRE_BYTES + 1],
            &f.expected
        )
        .err(),
        Some(Error::TooLarge)
    );
    let mut v: serde_json::Value = serde_json::from_slice(&a).unwrap();
    v["statement"]["binding"]["accepted"] = true.into();
    assert_eq!(
        verify_bootstrap_statements(&serde_json::to_vec(&v).unwrap(), &p, &f.expected).err(),
        Some(Error::Malformed)
    );
    let duplicate = String::from_utf8(a.clone()).unwrap().replacen(
        &format!("\"version\":{BOOTSTRAP_VERSION}"),
        &format!("\"version\":{BOOTSTRAP_VERSION},\"version\":{BOOTSTRAP_VERSION}"),
        1,
    );
    assert_eq!(
        verify_bootstrap_statements(duplicate.as_bytes(), &p, &f.expected).err(),
        Some(Error::Malformed)
    );
    for bad in ["AB".repeat(32), "00".repeat(31), "zz".repeat(32)] {
        let mut v: serde_json::Value = serde_json::from_slice(&a).unwrap();
        v["statement"]["binding"]["recorder_public_key_hex"] = bad.into();
        assert_eq!(
            verify_bootstrap_statements(&serde_json::to_vec(&v).unwrap(), &p, &f.expected).err(),
            Some(Error::InvalidField)
        );
    }
}

#[test]
fn independent_tenant_signature_scope_and_software_profile_are_required() {
    let tenant = key();
    let i = intent();
    let expected = tenant_expected(&tenant);
    let json = signed(&i, &i.signing_bytes().unwrap(), &tenant);
    let verified = verify_tenant_intent(&json, &expected).unwrap();
    assert_eq!(verified.statement(), &i);
    assert_eq!(verified.digest_sha384(), i.digest_sha384().unwrap());
    assert_eq!(verified.tenant_key_sha384(), sha384(&public(&tenant)));
    let attacker = key();
    let fake = signed(&i, &i.signing_bytes().unwrap(), &attacker);
    assert_eq!(
        verify_tenant_intent(&fake, &expected).err(),
        Some(Error::InvalidSignature)
    );
    for mutate in [
        |i: &mut TenantIntent| i.authority = "other".into(),
        |i: &mut TenantIntent| i.tenant = "other".into(),
        |i: &mut TenantIntent| i.profile_sha384 = "11".repeat(48),
    ] {
        let mut i = intent();
        mutate(&mut i);
        let json = signed(&i, &i.signing_bytes().unwrap(), &tenant);
        assert_eq!(
            verify_tenant_intent(&json, &expected).err(),
            Some(Error::BindingMismatch)
        );
    }
    let mut i = intent();
    i.purpose = "resource-access".into();
    assert_eq!(
        verify_tenant_intent(&signed(&i, &i.signing_bytes().unwrap(), &tenant), &expected).err(),
        Some(Error::WrongPurpose)
    );
    let mut i = intent();
    i.audience = "other".into();
    assert_eq!(
        verify_tenant_intent(&signed(&i, &i.signing_bytes().unwrap(), &tenant), &expected).err(),
        Some(Error::WrongAudience)
    );
    let mut i = intent();
    i.container_role = "helper".into();
    assert_eq!(
        verify_tenant_intent(&signed(&i, &i.signing_bytes().unwrap(), &tenant), &expected).err(),
        Some(Error::UnsupportedRole)
    );
    assert_eq!(
        verify_tenant_intent(&vec![b' '; super::super::MAX_WIRE_BYTES + 1], &expected).err(),
        Some(Error::TooLarge)
    );
    let mut v: serde_json::Value = serde_json::from_slice(&json).unwrap();
    v["statement"]["accepted"] = true.into();
    assert_eq!(
        verify_tenant_intent(&serde_json::to_vec(&v).unwrap(), &expected).err(),
        Some(Error::Malformed)
    );
}

#[test]
fn signed_issuer_challenge_enforces_exact_scope_signature_and_half_open_window() {
    let f = fixture();
    let authority = key();
    let challenge = &f.expected.challenge;
    let wire = signed(challenge, &challenge.signing_bytes().unwrap(), &authority);
    for now in [100, 199] {
        assert_eq!(
            verify_bootstrap_challenge(&wire, &public(&authority), challenge, now),
            Ok(challenge.clone())
        );
    }
    assert_eq!(
        verify_bootstrap_challenge(&wire, &public(&authority), challenge, 99).err(),
        Some(Error::NotYetValid)
    );
    assert_eq!(
        verify_bootstrap_challenge(&wire, &public(&authority), challenge, 200).err(),
        Some(Error::Expired)
    );
    assert_eq!(
        verify_bootstrap_challenge(&wire, &public(&authority), challenge, u64::MAX).err(),
        Some(Error::InvalidTime)
    );
    assert_eq!(
        verify_bootstrap_challenge(&wire, &public(&key()), challenge, 100).err(),
        Some(Error::InvalidSignature)
    );
    let mut other = challenge.clone();
    other.nonce_hex = "11".repeat(32);
    assert_eq!(
        verify_bootstrap_challenge(&wire, &public(&authority), &other, 100).err(),
        Some(Error::BindingMismatch)
    );
    let mut tampered: serde_json::Value = serde_json::from_slice(&wire).unwrap();
    tampered["statement"]["validity"]["expires"] = 201.into();
    let mut enlarged = challenge.clone();
    enlarged.validity.expires = 201;
    assert_eq!(
        verify_bootstrap_challenge(
            &serde_json::to_vec(&tampered).unwrap(),
            &public(&authority),
            &enlarged,
            100
        )
        .err(),
        Some(Error::InvalidSignature)
    );
    let mut old = challenge.clone();
    old.version = BOOTSTRAP_VERSION - 1;
    let old_wire = signed(&old, &old.signing_bytes().unwrap(), &authority);
    assert_eq!(
        verify_bootstrap_challenge(&old_wire, &public(&authority), &old, 100).err(),
        Some(Error::UnsupportedVersion)
    );
    assert_eq!(
        verify_bootstrap_challenge(
            &serde_json::to_vec(challenge).unwrap(),
            &public(&authority),
            challenge,
            100
        )
        .err(),
        Some(Error::Malformed)
    );
}

#[test]
fn tenant_and_challenge_windows_are_required_signed_and_bound_into_bootstrap() {
    let tenant = key();
    let expected = tenant_expected(&tenant);
    let i = intent();
    let wire = signed(&i, &i.signing_bytes().unwrap(), &tenant);
    let mut value: serde_json::Value = serde_json::from_slice(&wire).unwrap();
    value["statement"]["validity"]["expires"] = 301.into();
    assert_eq!(
        verify_tenant_intent(&serde_json::to_vec(&value).unwrap(), &expected).err(),
        Some(Error::InvalidSignature)
    );
    value["statement"]
        .as_object_mut()
        .unwrap()
        .remove("validity");
    assert_eq!(
        verify_tenant_intent(&serde_json::to_vec(&value).unwrap(), &expected).err(),
        Some(Error::Malformed)
    );
    let mut old = i;
    old.version = TENANT_INTENT_VERSION - 1;
    assert_eq!(
        verify_tenant_intent(
            &signed(&old, &old.signing_bytes().unwrap(), &tenant),
            &expected
        )
        .err(),
        Some(Error::UnsupportedVersion)
    );
    let mut f = fixture();
    f.expected.challenge.validity.expires += 1;
    assert_eq!(verify(&f).err(), Some(Error::BindingMismatch));
    let mut f = fixture();
    f.expected.challenge.validity.expires = f.expected.challenge.validity.not_before;
    assert_eq!(verify(&f).err(), Some(Error::InvalidTime));
}

#[test]
fn malformed_overflowing_or_duplicate_challenge_time_fields_fail_closed() {
    let f = fixture();
    let authority = key();
    let c = &f.expected.challenge;
    let wire = signed(c, &c.signing_bytes().unwrap(), &authority);
    let original: serde_json::Value = serde_json::from_slice(&wire).unwrap();
    let mut value = original.clone();
    value["statement"]
        .as_object_mut()
        .unwrap()
        .remove("validity");
    assert_eq!(
        verify_bootstrap_challenge(
            &serde_json::to_vec(&value).unwrap(),
            &public(&authority),
            c,
            100
        )
        .err(),
        Some(Error::Malformed)
    );
    let mut value = original.clone();
    value["statement"]["validity"]["expires"] = u64::MAX.into();
    assert_eq!(
        verify_bootstrap_challenge(
            &serde_json::to_vec(&value).unwrap(),
            &public(&authority),
            c,
            100
        )
        .err(),
        Some(Error::InvalidTime)
    );
    let mut value = original;
    value["statement"]["validity"]["not_before"] = (-1).into();
    assert_eq!(
        verify_bootstrap_challenge(
            &serde_json::to_vec(&value).unwrap(),
            &public(&authority),
            c,
            100
        )
        .err(),
        Some(Error::Malformed)
    );
    let duplicate = String::from_utf8(wire).unwrap().replacen(
        "\"expires\":200",
        "\"expires\":200,\"expires\":200",
        1,
    );
    assert_eq!(
        verify_bootstrap_challenge(duplicate.as_bytes(), &public(&authority), c, 100).err(),
        Some(Error::Malformed)
    );
}
