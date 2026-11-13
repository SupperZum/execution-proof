use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};

fn challenge() -> GcpBootstrapChallenge {
    GcpBootstrapChallenge {
        version: GCP_BOOTSTRAP_VERSION,
        purpose: GCP_BOOTSTRAP_CHALLENGE_PURPOSE.into(),
        audience: "bootstrap-audience".into(),
        authority: "authority-one".into(),
        tenant: "tenant-one".into(),
        workload_id: "workload-one".into(),
        attempt_id: "attempt-one".into(),
        challenge_id: "challenge-one".into(),
        nonce_hex: "05".repeat(32),
        intent_sha384: "06".repeat(48),
        boot_binding: GcpBootBindingV1::new([1; 48], [2; 48], [3; 48], [4; 48]).unwrap(),
        validity: ValidityWindow {
            not_before: 100,
            expires: 300,
        },
    }
}

fn binding() -> GcpBootstrapBinding {
    let challenge = challenge();
    GcpBootstrapBinding {
        version: GCP_BOOTSTRAP_VERSION,
        purpose: GCP_BOOTSTRAP_BINDING_PURPOSE.into(),
        challenge_sha384: challenge.digest_sha384().unwrap(),
        boot_binding_sha384: challenge.boot_binding.digest_sha384().unwrap(),
        boot_id: "boot-one".into(),
        boot_nonce_hex: "07".repeat(32),
        recorder_key_sha384: "08".repeat(48),
        keywrap_key_sha384: "09".repeat(48),
    }
}

fn signed(value: &GcpBootstrapChallenge, key: &Ed25519KeyPair) -> Vec<u8> {
    serde_json::to_vec(&Signed {
        statement: value,
        signature: crate::hex(key.sign(&value.canonical_bytes().unwrap()).as_ref()),
    })
    .unwrap()
}

#[test]
fn independent_golden_and_all64_field_comparison() {
    let challenge = challenge();
    let binding = binding();
    assert_eq!(challenge.canonical_bytes().unwrap().len(), 361);
    assert_eq!(binding.canonical_bytes().unwrap().len(), 348);
    assert_eq!(challenge.digest_sha384().unwrap(), "48de6d3756b53a4db9aa7d657f9ad07be87221134ba1b25afe20faeb0d47d9a20ff8c207d4a8e13f200401cf8778e29d");
    assert_eq!(binding.digest_sha384().unwrap(), "d539cd079bc90ba34b1b577a4519812d30bfcffb8d936c9e00caeee0f462e763d151e5720bf11f4ca477d627fa139edb");
    let expected = report_data(&challenge, &binding).unwrap();
    assert_eq!(crate::hex(&expected), "429c48f52eafbd030ac85b66094c6df2dc86f9f5e1d424e95759745edb76b3e83fa08bbfb1dcf112704428a29f867b5700000000000000000000000000000000");
    assert_eq!(&expected[48..], &[0; 16]);
    assert_eq!(check_report_data(&challenge, &binding, &expected), Ok(()));
    for index in [0, 47, 48, 63] {
        let mut altered = expected;
        altered[index] ^= 1;
        assert_eq!(
            check_report_data(&challenge, &binding, &altered),
            Err(Error::BindingMismatch)
        );
    }
    assert_eq!(
        GcpBootstrapChallenge::decode(&challenge.encode().unwrap()).unwrap(),
        challenge
    );
    assert_eq!(
        GcpBootstrapBinding::decode(&binding.encode().unwrap()).unwrap(),
        binding
    );
}

#[test]
fn every_authority_challenge_field_changes_report_and_old_binding_rejects() {
    let original = challenge();
    let expected = report_data(&original, &binding()).unwrap();
    for field in 0..16 {
        let mut changed = original.clone();
        match field {
            0 => changed.audience.push('x'),
            1 => changed.authority.push('x'),
            2 => changed.tenant.push('x'),
            3 => changed.workload_id.push('x'),
            4 => changed.attempt_id.push('x'),
            5 => changed.challenge_id.push('x'),
            6 => changed.nonce_hex = "0a".repeat(32),
            7 => changed.intent_sha384 = "0a".repeat(48),
            8 => changed.boot_binding.config_sha384 = "0a".repeat(48),
            9 => changed.boot_binding.producer_core_sha384 = "0a".repeat(48),
            10 => changed.boot_binding.artifact_manifest_sha384 = "0a".repeat(48),
            11 => changed.boot_binding.reference_policy_sha384 = "0a".repeat(48),
            12 => changed.validity.not_before += 1,
            13 => changed.validity.expires += 1,
            // Verify changes in independent nonce bytes, not just a one-byte fixture.
            14 => changed.nonce_hex.replace_range(62.., "aa"),
            _ => changed.intent_sha384.replace_range(94.., "aa"),
        }
        assert_eq!(
            report_data(&changed, &binding()),
            Err(Error::BindingMismatch)
        );
        let mut updated_binding = binding();
        updated_binding.challenge_sha384 = changed.digest_sha384().unwrap();
        updated_binding.boot_binding_sha384 = changed.boot_binding.digest_sha384().unwrap();
        assert_ne!(
            report_data(&changed, &updated_binding).unwrap(),
            expected,
            "field {field}"
        );
    }
}

#[test]
fn boot_and_both_key_commitments_are_indispensable() {
    let expected = report_data(&challenge(), &binding()).unwrap();
    for field in 0..4 {
        let mut changed = binding();
        match field {
            0 => changed.boot_id.push('x'),
            1 => changed.boot_nonce_hex = "0a".repeat(32),
            2 => changed.recorder_key_sha384 = "0a".repeat(48),
            _ => changed.keywrap_key_sha384 = "0a".repeat(48),
        }
        assert_ne!(report_data(&challenge(), &changed).unwrap(), expected);
    }
    for field in 0..2 {
        let mut changed = binding();
        if field == 0 {
            changed.challenge_sha384 = "0a".repeat(48);
        } else {
            changed.boot_binding_sha384 = "0a".repeat(48);
        }
        assert_eq!(
            report_data(&challenge(), &changed),
            Err(Error::BindingMismatch)
        );
    }
    let mut confused = binding();
    confused
        .keywrap_key_sha384
        .clone_from(&confused.recorder_key_sha384);
    assert_eq!(confused.validate(), Err(Error::ConfusedKeys));
}

#[test]
fn authenticated_challenge_checks_exact_saved_scope_signature_and_trusted_window() {
    let authority = Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
    let foreign = Ed25519KeyPair::from_seed_unchecked(&[2; 32]).unwrap();
    let key: [u8; 32] = authority.public_key().as_ref().try_into().unwrap();
    let expected = challenge();
    let wire = signed(&expected, &authority);
    assert_eq!(
        verify_challenge(&wire, &key, &expected, 100).unwrap(),
        expected
    );
    assert_eq!(
        verify_challenge(&wire, &key, &expected, 99),
        Err(Error::NotYetValid)
    );
    assert_eq!(
        verify_challenge(&wire, &key, &expected, 300),
        Err(Error::Expired)
    );
    assert_eq!(
        verify_challenge(&signed(&expected, &foreign), &key, &expected, 150),
        Err(Error::InvalidSignature)
    );
    let mut replacement = expected.clone();
    replacement.tenant = "tenant-two".into();
    assert_eq!(
        verify_challenge(&signed(&replacement, &authority), &key, &expected, 150),
        Err(Error::BindingMismatch)
    );
    let mut value: serde_json::Value = serde_json::from_slice(&wire).unwrap();
    value["statement"]["nonce_hex"] = "0a".repeat(32).into();
    assert!(verify_challenge(&serde_json::to_vec(&value).unwrap(), &key, &expected, 150).is_err());
}

#[test]
fn unknown_domains_mixed_legacy_and_execution_families_reject() {
    let mut value = challenge();
    value.version = 2;
    assert_eq!(value.validate(), Err(Error::UnsupportedVersion));
    value = challenge();
    value.purpose = crate::bootstrap::CHALLENGE_PURPOSE.into();
    assert_eq!(value.validate(), Err(Error::WrongPurpose));
    value.purpose = crate::gcp_execution_quote::GCP_QUOTE_CHALLENGE_PURPOSE.into();
    assert_eq!(value.validate(), Err(Error::WrongPurpose));
    assert!(
        crate::decode::<crate::bootstrap::BootstrapChallenge>(&challenge().encode().unwrap())
            .is_err()
    );
    assert!(
        crate::gcp_execution_quote::GcpQuoteChallenge::decode(&challenge().encode().unwrap())
            .is_err()
    );
    let legacy = crate::bootstrap::BootstrapChallenge {
        version: 2,
        purpose: crate::bootstrap::CHALLENGE_PURPOSE.into(),
        audience: "a".into(),
        authority: "a".into(),
        tenant: "t".into(),
        workload_id: "w".into(),
        attempt_id: "a".into(),
        challenge_id: "c".into(),
        nonce_hex: "01".repeat(32),
        intent_sha384: "01".repeat(48),
        boot_profile_sha384: "02".repeat(48),
        producer_profile_sha384: "03".repeat(48),
        validity: ValidityWindow {
            not_before: 100,
            expires: 300,
        },
    };
    assert!(GcpBootstrapChallenge::decode(&serde_json::to_vec(&legacy).unwrap()).is_err());
    let mut value = binding();
    value.version = 2;
    assert_eq!(value.validate(), Err(Error::UnsupportedVersion));
    value = binding();
    value.purpose = crate::bootstrap::POSSESSION_PURPOSE.into();
    assert_eq!(value.validate(), Err(Error::WrongPurpose));
}

#[test]
fn strict_decoder_and_semantics_reject_malformed_zero_duplicate_or_missing_fields() {
    for encoded in [challenge().encode().unwrap(), binding().encode().unwrap()] {
        let wire = String::from_utf8(encoded).unwrap();
        for prefix in ["\"version\":3,", "\"extra\":false,"] {
            let malformed = wire.replacen('{', &format!("{{{prefix}"), 1);
            assert!(GcpBootstrapChallenge::decode(malformed.as_bytes()).is_err());
            assert!(GcpBootstrapBinding::decode(malformed.as_bytes()).is_err());
        }
    }
    for hash_field in ["nonce_hex", "intent_sha384"] {
        let length = if hash_field == "nonce_hex" { 32 } else { 48 };
        for bad in ["00".repeat(length), "AB".repeat(length), String::new()] {
            let mut value = serde_json::to_value(challenge()).unwrap();
            value[hash_field] = bad.into();
            assert!(GcpBootstrapChallenge::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }
    for hash_field in [
        "challenge_sha384",
        "boot_binding_sha384",
        "boot_nonce_hex",
        "recorder_key_sha384",
        "keywrap_key_sha384",
    ] {
        let mut value = serde_json::to_value(binding()).unwrap();
        value[hash_field] = "00"
            .repeat(if hash_field == "boot_nonce_hex" {
                32
            } else {
                48
            })
            .into();
        assert!(GcpBootstrapBinding::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let mut invalid_time = challenge();
    invalid_time.validity.not_before = invalid_time.validity.expires;
    assert_eq!(invalid_time.validate(), Err(Error::InvalidTime));
    let too_large = vec![b' '; crate::MAX_WIRE_BYTES + 1];
    assert_eq!(
        GcpBootstrapChallenge::decode(&too_large),
        Err(Error::TooLarge)
    );
    assert_eq!(
        GcpBootstrapBinding::decode(&too_large),
        Err(Error::TooLarge)
    );
    let mut missing = serde_json::to_value(challenge()).unwrap();
    missing.as_object_mut().unwrap().remove("boot_binding");
    assert!(GcpBootstrapChallenge::decode(&serde_json::to_vec(&missing).unwrap()).is_err());
}

#[test]
fn context_and_possession_match_independent_capture_golden() {
    let challenge = challenge();
    let original = binding();
    let evidence = crate::gcp_session::GcpLaunchEvidenceV2::new(vec![1], vec![2], vec![3]).unwrap();
    assert_eq!(bootstrap_context_sha384(&challenge,&original,&evidence).unwrap(),
        "bf55055e45bfc50f67b89d4f30802b18095e93a5f7b53a574d7035be0db907aba8bd58507f6a272ef1cfba9a7ba9e706");
    let transcript = bootstrap_possession_signing_bytes(&challenge, &original, &evidence).unwrap();
    assert_eq!(transcript.len(), 168);
    assert_eq!(crate::sha384(&transcript),"98776632a4da0d40f58d0c1a660f8dd422c9e9bca3a7e4bf9ad8b7f0ca2ec84f253f76f8efeb41d3ce8e91c0b91a429d");
    let key = Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap();
    let public: [u8; 32] = key.public_key().as_ref().try_into().unwrap();
    let mut binding = original;
    binding.recorder_key_sha384 = crate::sha384(&public);
    let message = bootstrap_possession_signing_bytes(&challenge, &binding, &evidence).unwrap();
    let signature = crate::hex(key.sign(&message).as_ref());
    assert_eq!(
        verify_bootstrap_possession(&challenge, &binding, &evidence, &public, &signature),
        Ok(())
    );
    for field in 0..3 {
        let mut changed = evidence.clone();
        [
            &mut changed.tdx_quote,
            &mut changed.ccel_table,
            &mut changed.ccel_log,
        ][field][0] ^= 1;
        assert!(
            verify_bootstrap_possession(&challenge, &binding, &changed, &public, &signature)
                .is_err()
        );
    }
    assert!(
        verify_bootstrap_possession(&challenge, &binding, &evidence, &[7; 32], &signature).is_err()
    );
    let foreign = crate::hex(key.sign(&challenge.canonical_bytes().unwrap()).as_ref());
    assert!(
        verify_bootstrap_possession(&challenge, &binding, &evidence, &public, &foreign).is_err()
    );
}

#[test]
fn guest_signature_check_is_not_a_trusted_time_check() {
    let challenge = challenge();
    let key = Ed25519KeyPair::from_seed_unchecked(&[17; 32]).unwrap();
    let public = key.public_key().as_ref().try_into().unwrap();
    let wire = signed(&challenge, &key);
    assert_eq!(
        verify_challenge_signature(&wire, &public, &challenge),
        Ok(challenge.clone())
    );
    assert_eq!(
        verify_challenge(&wire, &public, &challenge, 301),
        Err(Error::Expired)
    );
    let mut changed = challenge.clone();
    changed.attempt_id.push('x');
    assert!(verify_challenge_signature(&wire, &public, &changed).is_err());
    assert!(verify_challenge_signature(&wire, &[4; 32], &challenge).is_err());
}
