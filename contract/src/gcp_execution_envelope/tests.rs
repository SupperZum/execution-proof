use super::*;
use crate::{
    execution_quote::{
        ExecutionQuoteEnvelope, QuoteChallenge, QUOTE_CHALLENGE_PURPOSE, QUOTE_CHALLENGE_VERSION,
    },
    gcp_boot_binding::GcpBootBindingV1,
    gcp_execution_quote::{GCP_QUOTE_CHALLENGE_PURPOSE, GCP_QUOTE_CHALLENGE_VERSION},
};

fn challenge() -> GcpQuoteChallenge {
    GcpQuoteChallenge {
        version: GCP_QUOTE_CHALLENGE_VERSION,
        purpose: GCP_QUOTE_CHALLENGE_PURPOSE.into(),
        audience: "verifier.test".into(),
        nonce: "07".repeat(32),
        record_sha384: "08".repeat(48),
        boot_binding: GcpBootBindingV1::new([1; 48], [2; 48], [3; 48], [4; 48]).unwrap(),
        trust_snapshot_sha384: "09".repeat(48),
    }
}
fn envelope() -> GcpExecutionEnvelope {
    GcpExecutionEnvelope::new(
        challenge(),
        vec![1, 2, 0, 0],
        b"CCEL-original-descriptor".to_vec(),
        vec![3, 4, 0, 0],
    )
    .unwrap()
}

#[test]
fn original_quote_table_log_and_padding_roundtrip_without_interpretation() {
    let value = envelope();
    let decoded = GcpExecutionEnvelope::decode(&value.encode().unwrap()).unwrap();
    assert_eq!(decoded, value);
    assert_eq!(decoded.tdx_quote, [1, 2, 0, 0]);
    assert_eq!(decoded.ccel_log, [3, 4, 0, 0]);
    // Syntax/bounds validation intentionally does not claim ACPI or quote validity.
    assert_eq!(decoded.ccel_table, b"CCEL-original-descriptor");
}

#[test]
fn exact_shared_budget_accepted_and_one_more_byte_rejected_in_any_order() {
    let mut value = envelope();
    value.tdx_quote =
        vec![0; MAX_GCP_DECODED_EVIDENCE_BYTES - value.ccel_table.len() - value.ccel_log.len()];
    assert!(value.validate().is_ok());
    assert!(GcpExecutionEnvelope::decode(&value.encode().unwrap()).is_ok());
    value.tdx_quote.push(0);
    assert_eq!(value.validate(), Err(Error::TooLarge));
    let wire = serde_json::to_vec(&value).unwrap();
    assert_eq!(GcpExecutionEnvelope::decode(&wire), Err(Error::Malformed));
    // Sorted map order sends log/table before quote; the same shared budget applies.
    let reordered = serde_json::to_value(&value).unwrap();
    assert_eq!(
        GcpExecutionEnvelope::decode(&serde_json::to_vec(&reordered).unwrap()),
        Err(Error::Malformed)
    );
}

#[test]
fn strict_empty_invalid_byte_duplicate_unknown_missing_and_wire_bounds() {
    for field in ["tdx_quote", "ccel_table", "ccel_log"] {
        for bad in [
            serde_json::json!([]),
            serde_json::json!([256]),
            serde_json::json!([-1]),
            serde_json::json!([1.2]),
            serde_json::json!("AA=="),
        ] {
            let mut value = serde_json::to_value(envelope()).unwrap();
            value[field] = bad;
            assert_eq!(
                GcpExecutionEnvelope::decode(&serde_json::to_vec(&value).unwrap()),
                Err(Error::Malformed)
            );
        }
        let mut value = serde_json::to_value(envelope()).unwrap();
        value.as_object_mut().unwrap().remove(field);
        assert_eq!(
            GcpExecutionEnvelope::decode(&serde_json::to_vec(&value).unwrap()),
            Err(Error::Malformed)
        );
    }
    let wire = String::from_utf8(envelope().encode().unwrap()).unwrap();
    for extra in ["\"unknown\":0,", "\"tdx_quote\":[1],", "\"version\":2,"] {
        let bad = format!("{{{extra}{}", &wire[1..]);
        assert_eq!(
            GcpExecutionEnvelope::decode(bad.as_bytes()),
            Err(Error::Malformed)
        );
    }
    assert_eq!(
        GcpExecutionEnvelope::decode(&vec![b' '; MAX_GCP_ENVELOPE_BYTES + 1]),
        Err(Error::TooLarge)
    );
    let mut value = envelope();
    value.ccel_table.clear();
    assert_eq!(value.encode(), Err(Error::InvalidField));
    // Decoded arrays can fit while decimal JSON representation exceeds4MiB.
    value.ccel_table =
        vec![255; MAX_GCP_DECODED_EVIDENCE_BYTES - value.tdx_quote.len() - value.ccel_log.len()];
    assert_eq!(value.encode(), Err(Error::TooLarge));
}

#[test]
fn wrong_domains_nested_binding_and_mixed_legacy_envelopes_fail_closed() {
    let mutations: &[fn(&mut GcpExecutionEnvelope)] = &[
        |e| e.version = 1,
        |e| e.purpose.push('x'),
        |e| e.profile.push('x'),
        |e| e.challenge.version = 1,
        |e| e.challenge.purpose.push('x'),
        |e| e.challenge.boot_binding.profile.push('x'),
        |e| e.challenge.boot_binding.config_sha384 = "00".repeat(48),
    ];
    for mutate in mutations {
        let mut value = envelope();
        mutate(&mut value);
        assert!(value.encode().is_err());
        assert!(GcpExecutionEnvelope::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let legacy = ExecutionQuoteEnvelope::new(
        QuoteChallenge {
            version: QUOTE_CHALLENGE_VERSION,
            purpose: QUOTE_CHALLENGE_PURPOSE.into(),
            audience: "verifier.test".into(),
            nonce: "07".repeat(32),
            record_sha384: "08".repeat(48),
            producer_profile_sha384: "02".repeat(48),
            trust_snapshot_sha384: "09".repeat(48),
        },
        vec![1],
    )
    .unwrap();
    assert!(GcpExecutionEnvelope::decode(&legacy.encode().unwrap()).is_err());
    assert!(ExecutionQuoteEnvelope::decode(&envelope().encode().unwrap()).is_err());
}
