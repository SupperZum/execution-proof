use super::*;
use crate::execution::*;

fn record() -> ExecutionRecord {
    ExecutionRecord {
        version: EXECUTION_RECORD_VERSION,
        purpose: EXECUTION_RECORD_PURPOSE.into(),
        profile: EXECUTION_RECORD_PROFILE.into(),
        claim: EXECUTION_RECORD_CLAIM.into(),
        event_id: "10".repeat(32),
        grant_sha384: "11".repeat(48),
        admission_context_sha384: "22".repeat(48),
        preparation_record_sha384: "33".repeat(48),
        startup_binding_sha384: "44".repeat(48),
        candidate_spec_sha384: "55".repeat(48),
        final_spec_sha384: "66".repeat(48),
        image_sha384: "77".repeat(48),
        executable_sha384: "88".repeat(48),
        mount_id: 42,
        task: ExecutionTask {
            container_id: "container.1".into(),
            generation: 7,
            pid: 1234,
            process_start_time_ticks: 5678,
        },
    }
}

fn challenge(record: &ExecutionRecord) -> QuoteChallenge {
    QuoteChallenge::new("verifier.test".into(), [7; 32], record, [8; 48], [9; 48]).unwrap()
}

#[test]
fn quote_report_commits_every_challenge_field_and_full_record() {
    let record = record();
    let challenge = challenge(&record);
    let expected = report_data(&record, &challenge).unwrap();
    // Independently encoded from the ordered frame specification in Python.
    assert_eq!(challenge.canonical_bytes().unwrap().len(), 304);
    assert_eq!(hex(&challenge.sha384().unwrap()), "946da0554724faa875b673526d2614c06cfd9d6368015f845b7d73891e44f127f6a7597f9b7bb7ae75be52d9e0651d8d");
    assert_eq!(hex(&expected), "64e099dd6e382cd552603608e3aef9ab925f666cf3236e3a0ec17f47e7bbf6974a74569d0eb66e8c3f2915b27f517dfb00000000000000000000000000000000");
    assert_eq!(&expected[48..], &[0; 16]);
    for mutate in [
        (|c: &mut QuoteChallenge| c.audience.push('x')) as fn(&mut QuoteChallenge),
        |c| c.nonce.replace_range(..2, "01"),
        |c| c.producer_profile_sha384.replace_range(..2, "01"),
        |c| c.trust_snapshot_sha384.replace_range(..2, "01"),
    ] {
        let mut changed = challenge.clone();
        mutate(&mut changed);
        assert_ne!(report_data(&record, &changed).unwrap(), expected);
    }
    let mut changed = record.clone();
    changed.task.pid += 1;
    assert_eq!(
        report_data(&changed, &challenge),
        Err(Error::BindingMismatch)
    );
}

#[test]
fn challenge_json_spelling_does_not_change_transcript() {
    let record = record();
    let expected = challenge(&record);
    let pretty = serde_json::to_vec_pretty(&expected).unwrap();
    let parsed = QuoteChallenge::decode(&pretty).unwrap();
    assert_eq!(parsed.sha384(), expected.sha384());
    assert_eq!(
        QuoteChallenge::decode(&expected.encode().unwrap()),
        Ok(expected)
    );
}

#[test]
fn challenge_rejects_wrong_domains_and_noncanonical_hex() {
    let original = challenge(&record());
    for mutate in [
        (|c: &mut QuoteChallenge| c.version += 1) as fn(&mut QuoteChallenge),
        |c| c.purpose.push('x'),
        |c| c.audience.clear(),
        |c| c.nonce = "00".repeat(32),
        |c| c.nonce = "AA".repeat(32),
        |c| {
            c.record_sha384.pop();
        },
    ] {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert!(changed.validate().is_err());
    }
}

#[test]
fn challenge_rejects_unknown_duplicate_fields_and_oversize() {
    let wire = String::from_utf8(challenge(&record()).encode().unwrap()).unwrap();
    for extra in [r#""extra":0,"#, r#""version":1,"#] {
        let changed = format!("{{{extra}{}", &wire[1..]);
        assert_eq!(
            QuoteChallenge::decode(changed.as_bytes()),
            Err(Error::Malformed)
        );
    }
    assert_eq!(
        QuoteChallenge::decode(&vec![b' '; crate::MAX_WIRE_BYTES + 1]),
        Err(Error::TooLarge)
    );
}

#[test]
fn envelope_is_public_data_with_strict_transport_bounds() {
    let envelope =
        ExecutionQuoteEnvelope::new(challenge(&record()), b"opaque-evidence".to_vec()).unwrap();
    assert_eq!(
        ExecutionQuoteEnvelope::decode(&envelope.encode().unwrap()),
        Ok(envelope.clone())
    );
    let mut invalid = envelope.clone();
    invalid.profile.push('x');
    assert_eq!(invalid.encode(), Err(Error::InvalidField));
    invalid = envelope.clone();
    invalid.tdx_evidence.clear();
    assert_eq!(invalid.encode(), Err(Error::TooLarge));
    invalid.tdx_evidence = vec![0; MAX_TDX_EVIDENCE_BYTES + 1];
    assert_eq!(invalid.encode(), Err(Error::TooLarge));
}

#[test]
fn envelope_rejects_unknown_duplicate_and_wrong_typed_bytes() {
    let envelope = ExecutionQuoteEnvelope::new(challenge(&record()), vec![1]).unwrap();
    let wire = String::from_utf8(envelope.encode().unwrap()).unwrap();
    for extra in [r#""extra":0,"#, r#""version":1,"#] {
        let changed = format!("{{{extra}{}", &wire[1..]);
        assert_eq!(
            ExecutionQuoteEnvelope::decode(changed.as_bytes()),
            Err(Error::Malformed)
        );
    }
    let wrong_type = wire.replace("\"tdx_evidence\":[1]", "\"tdx_evidence\":[256]");
    assert_eq!(
        ExecutionQuoteEnvelope::decode(wrong_type.as_bytes()),
        Err(Error::Malformed)
    );
}
