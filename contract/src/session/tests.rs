use super::*;
use crate::{
    verify_launch_grant, GrantExpectations, LaunchBinding, LaunchGrant, Signed, ValidityWindow,
    GRANT_PURPOSE,
};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};

const NONCE: &str = "fresh-session-nonce";

fn key() -> Ed25519KeyPair {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

fn grant(recorder: &Ed25519KeyPair, id: &str) -> VerifiedLaunchGrant {
    let authority = key();
    let statement = LaunchGrant {
        version: VERSION,
        purpose: GRANT_PURPOSE.into(),
        audience: "software-session-test".into(),
        proof_required: true,
        grant_id: id.into(),
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
    let expected = GrantExpectations {
        authority_public_key: authority.public_key().as_ref().try_into().unwrap(),
        audience: statement.audience.clone(),
        authority: statement.binding.authority.clone(),
        tenant: statement.binding.tenant.clone(),
        profile_sha384: statement.binding.profile_sha384.clone(),
        launch_policy_sha384: statement.binding.launch_policy_sha384.clone(),
        image_policy_sha384: statement.binding.image_policy_sha384.clone(),
    };
    let signature = crate::hex(authority.sign(&statement.signing_bytes().unwrap()).as_ref());
    let json = serde_json::to_vec(&Signed {
        statement,
        signature,
    })
    .unwrap();
    verify_launch_grant(&json, &expected, 100).unwrap()
}

fn verify(
    grant: &VerifiedLaunchGrant,
    recorder: &Ed25519KeyPair,
    signature: &str,
) -> Result<VerifiedRecorderSession, Error> {
    verify_recorder_session_pop(
        grant,
        NONCE,
        &"08".repeat(48),
        &"09".repeat(48),
        &recorder.public_key().as_ref().try_into().unwrap(),
        signature,
    )
}

fn sign(grant: &VerifiedLaunchGrant, recorder: &Ed25519KeyPair) -> String {
    let bytes =
        recorder_session_signing_bytes(grant, NONCE, &"08".repeat(48), &"09".repeat(48)).unwrap();
    crate::hex(recorder.sign(&bytes).as_ref())
}

#[test]
fn actual_recorder_signature_yields_only_bound_session_facts() {
    let recorder = key();
    let grant = grant(&recorder, "grant-1");
    let verified = verify(&grant, &recorder, &sign(&grant, &recorder)).unwrap();
    assert_eq!(verified.grant_digest(), grant.grant_digest());
    assert_eq!(verified.nonce(), NONCE);
    assert_eq!(verified.runtime_sha384(), "08".repeat(48));
    assert_eq!(verified.evidence_sha384(), "09".repeat(48));
    assert_eq!(
        verified.key_sha384(),
        sha384(recorder.public_key().as_ref())
    );
}

#[test]
fn forged_signature_or_unbound_key_is_rejected() {
    let recorder = key();
    let grant = grant(&recorder, "grant-1");
    let attacker = key();
    assert_eq!(
        verify(&grant, &recorder, &sign(&grant, &attacker)).err(),
        Some(Error::InvalidSignature)
    );
    assert_eq!(
        verify(&grant, &attacker, &sign(&grant, &attacker)).err(),
        Some(Error::BindingMismatch)
    );
    assert_eq!(
        verify(&grant, &recorder, &"00".repeat(64)).err(),
        Some(Error::InvalidSignature)
    );
    assert_eq!(
        verify(&grant, &recorder, "bad").err(),
        Some(Error::InvalidField)
    );
}

#[test]
fn another_grant_or_session_input_cannot_reuse_signature() {
    let recorder = key();
    let first = grant(&recorder, "grant-1");
    let second = grant(&recorder, "grant-2");
    let signature = sign(&first, &recorder);
    assert_eq!(
        verify(&second, &recorder, &signature).err(),
        Some(Error::InvalidSignature)
    );
    for (nonce, runtime, evidence) in [
        ("other-nonce", "08".repeat(48), "09".repeat(48)),
        (NONCE, "0a".repeat(48), "09".repeat(48)),
        (NONCE, "08".repeat(48), "0a".repeat(48)),
        (NONCE, "09".repeat(48), "08".repeat(48)),
    ] {
        assert_eq!(
            verify_recorder_session_pop(
                &first,
                nonce,
                &runtime,
                &evidence,
                &recorder.public_key().as_ref().try_into().unwrap(),
                &signature
            )
            .err(),
            Some(Error::InvalidSignature)
        );
    }
}

#[test]
fn protocol_version_and_purpose_are_signed() {
    let recorder = key();
    let grant = grant(&recorder, "grant-1");
    let bytes =
        recorder_session_signing_bytes(&grant, NONCE, &"08".repeat(48), &"09".repeat(48)).unwrap();
    for pattern in [&VERSION.to_be_bytes()[..], SESSION_PURPOSE.as_bytes()] {
        let mut changed = bytes.clone();
        let offset = changed
            .windows(pattern.len())
            .position(|p| p == pattern)
            .unwrap();
        changed[offset + pattern.len() - 1] ^= 1;
        let signature = crate::hex(recorder.sign(&changed).as_ref());
        assert_eq!(
            verify(&grant, &recorder, &signature).err(),
            Some(Error::InvalidSignature)
        );
    }
}

#[test]
fn nonce_and_hashes_are_bounded_and_canonical_before_signing() {
    let recorder = key();
    let grant = grant(&recorder, "grant-1");
    let hash = "0a".repeat(48);
    for nonce in [
        "",
        "non-ascii-\u{0430}",
        &"n".repeat(MAX_SESSION_NONCE_BYTES + 1),
    ] {
        assert_eq!(
            recorder_session_signing_bytes(&grant, nonce, &hash, &hash).err(),
            Some(Error::InvalidField)
        );
    }
    assert!(recorder_session_signing_bytes(
        &grant,
        &"n".repeat(MAX_SESSION_NONCE_BYTES),
        &hash,
        &hash
    )
    .is_ok());
    for bad in [
        "0a".repeat(47),
        "0a".repeat(49),
        "0A".repeat(48),
        "gg".repeat(48),
    ] {
        assert_eq!(
            recorder_session_signing_bytes(&grant, NONCE, &bad, &hash).err(),
            Some(Error::InvalidField)
        );
        assert_eq!(
            recorder_session_signing_bytes(&grant, NONCE, &hash, &bad).err(),
            Some(Error::InvalidField)
        );
    }
}
