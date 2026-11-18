use super::*;

fn binding() -> GcpBootBindingV1 {
    GcpBootBindingV1::new([1; 48], [2; 48], [3; 48], [4; 48]).unwrap()
}

#[test]
fn golden_transcript_and_digest() {
    let value = binding();
    // Expected digest is generated independently with Python hashlib and
    // struct.pack over the specified domain, version, and ordered frames.
    assert_eq!(value.digest_sha384().unwrap(), "ded556a34b417b849256926ed6020ff711638d6db38174dc5bcb199d4382ab283882695f92f290cd02d4e236462c731d");
    let bytes = value.canonical_bytes().unwrap();
    assert_eq!(bytes.len(), 334);
    assert_eq!(&bytes[..18], b"QLAD-EXEC-PROOF\0\0\x01");
    assert_eq!(
        GcpBootBindingV1::decode(&value.encode().unwrap()).unwrap(),
        value
    );
}

#[test]
fn every_commitment_and_its_position_changes_binding() {
    let value = binding();
    let expected = value.digest_sha384().unwrap();
    for index in 0..4 {
        let mut changed = value.clone();
        let fields = [
            &mut changed.config_sha384,
            &mut changed.producer_core_sha384,
            &mut changed.artifact_manifest_sha384,
            &mut changed.reference_policy_sha384,
        ];
        *fields.into_iter().nth(index).unwrap() = hex(&[5; 48]);
        assert_ne!(changed.digest_sha384().unwrap(), expected);
    }
    let mut swapped = value;
    std::mem::swap(
        &mut swapped.config_sha384,
        &mut swapped.producer_core_sha384,
    );
    assert_ne!(swapped.digest_sha384().unwrap(), expected);
}

#[test]
fn rejects_zero_malformed_and_noncanonical_hashes_in_every_position() {
    for index in 0..4 {
        for invalid in [
            "00".repeat(48),
            "AB".repeat(48),
            "ab".repeat(47),
            "gg".repeat(48),
        ] {
            let mut value = binding();
            let fields = [
                &mut value.config_sha384,
                &mut value.producer_core_sha384,
                &mut value.artifact_manifest_sha384,
                &mut value.reference_policy_sha384,
            ];
            *fields.into_iter().nth(index).unwrap() = invalid;
            assert_eq!(value.canonical_bytes(), Err(Error::InvalidField));
            assert_eq!(value.encode(), Err(Error::InvalidField));
            assert_eq!(
                GcpBootBindingV1::decode(&serde_json::to_vec(&value).unwrap()),
                Err(Error::InvalidField)
            );
        }
    }
    assert_eq!(
        GcpBootBindingV1::new([0; 48], [2; 48], [3; 48], [4; 48]),
        Err(Error::InvalidField)
    );
}

#[test]
fn rejects_unknown_version_purpose_and_profile_without_fallback() {
    fn rejected(value: &GcpBootBindingV1, error: Error) {
        assert_eq!(value.validate(), Err(error));
        assert_eq!(value.canonical_bytes(), Err(error));
        assert_eq!(
            GcpBootBindingV1::decode(&serde_json::to_vec(value).unwrap()),
            Err(error)
        );
    }
    let mut value = binding();
    value.version = 2;
    rejected(&value, Error::UnsupportedVersion);
    value = binding();
    value.purpose = "qlad.execution-proof.exec-quote.v1".into();
    rejected(&value, Error::WrongPurpose);
    value = binding();
    value.profile = "legacyNonzeroMrconfigV1".into();
    rejected(&value, Error::InvalidField);
}

#[test]
fn strict_bounded_decoder_rejects_unknown_duplicate_and_missing_fields() {
    let value = binding();
    let wire = String::from_utf8(value.encode().unwrap()).unwrap();
    let unknown = wire.replacen('{', "{\"mrconfigid\":\"zero\",", 1);
    let duplicate = wire.replacen('{', "{\"version\":1,", 1);
    let missing = wire.replace(
        &format!("\"config_sha384\":\"{}\",", value.config_sha384),
        "",
    );
    for bytes in [unknown, duplicate, missing] {
        assert_eq!(
            GcpBootBindingV1::decode(bytes.as_bytes()),
            Err(Error::Malformed)
        );
    }
    assert_eq!(
        GcpBootBindingV1::decode(&vec![b' '; crate::MAX_WIRE_BYTES + 1]),
        Err(Error::TooLarge)
    );
}

#[test]
fn json_order_and_whitespace_do_not_change_ordered_transcript() {
    let value = binding();
    let mut object = serde_json::to_value(&value).unwrap();
    // serde_json::Map's sorted serialization differs from struct field order.
    let wire = serde_json::to_vec_pretty(object.as_object_mut().unwrap()).unwrap();
    let decoded = GcpBootBindingV1::decode(&wire).unwrap();
    assert_eq!(decoded.canonical_bytes(), value.canonical_bytes());
}
