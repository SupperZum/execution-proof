use super::*;

fn fixture() -> ExecutionRecord {
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

fn rejects(record: &ExecutionRecord, expected: Error) {
    assert_eq!(record.validate(), Err(expected));
    assert_eq!(record.canonical_bytes(), Err(expected));
    assert_eq!(record.sha384(), Err(expected));
    assert_eq!(record.encode(), Err(expected));
    let wire = serde_json::to_vec(record).unwrap();
    assert_eq!(ExecutionRecord::decode(&wire), Err(expected));
}

#[test]
fn fixed_binary_transcript_and_sha384_golden() {
    let record = fixture();
    let bytes = record.canonical_bytes().unwrap();
    // Computed independently from the versioned ordered frame specification.
    assert_eq!(bytes.len(), 649);
    assert_eq!(
        crate::hex(&record.sha384().unwrap()),
        "dbaf38edc86940b79c82e764041df2263cda878609a6da32d385b6b745e5311ea8f5580efa835625e53a1a279f1e75c7"
    );
    assert_eq!(
        ExecutionRecord::decode(&record.encode().unwrap()),
        Ok(record)
    );
}

#[test]
fn every_observation_and_reference_is_committed() {
    let record = fixture();
    let expected = record.sha384().unwrap();
    let mutations: &[fn(&mut ExecutionRecord)] = &[
        |r| r.event_id.replace_range(..2, "20"),
        |r| r.grant_sha384.replace_range(..2, "20"),
        |r| r.admission_context_sha384.replace_range(..2, "20"),
        |r| r.preparation_record_sha384.replace_range(..2, "20"),
        |r| r.startup_binding_sha384.replace_range(..2, "20"),
        |r| r.candidate_spec_sha384.replace_range(..2, "20"),
        |r| r.final_spec_sha384.replace_range(..2, "20"),
        |r| r.image_sha384.replace_range(..2, "20"),
        |r| r.executable_sha384.replace_range(..2, "20"),
        |r| r.mount_id += 1,
        |r| r.task.container_id.push('x'),
        |r| r.task.generation += 1,
        |r| r.task.pid += 1,
        |r| r.task.process_start_time_ticks += 1,
    ];
    for mutation in mutations {
        let mut altered = record.clone();
        mutation(&mut altered);
        assert_ne!(altered.sha384().unwrap(), expected);
    }
    let mut swapped = record.clone();
    std::mem::swap(
        &mut swapped.candidate_spec_sha384,
        &mut swapped.final_spec_sha384,
    );
    assert_ne!(swapped.sha384().unwrap(), expected);
}

#[test]
fn json_spelling_does_not_change_the_binary_commitment() {
    let record = fixture();
    let value = serde_json::to_value(&record).unwrap();
    // serde_json's map ordering differs from the declared struct field order.
    let pretty = serde_json::to_string_pretty(&value).unwrap();
    let escaped = pretty.replace("container.1", "container\\u002e1");
    let decoded = ExecutionRecord::decode(escaped.as_bytes()).unwrap();
    assert_eq!(decoded, record);
    assert_eq!(decoded.canonical_bytes(), record.canonical_bytes());
    assert_eq!(decoded.sha384(), record.sha384());
}

#[test]
fn versions_purposes_profiles_and_claims_are_exact() {
    let mut record = fixture();
    record.version += 1;
    rejects(&record, Error::UnsupportedVersion);
    let mut record = fixture();
    record.purpose.push('x');
    rejects(&record, Error::WrongPurpose);
    for mutation in [
        ("profile", "onb17.dynamic-elf-exec-committed.v1"),
        ("claim", "application_ready"),
    ] {
        let mut record = fixture();
        match mutation.0 {
            "profile" => record.profile = mutation.1.into(),
            "claim" => record.claim = mutation.1.into(),
            _ => unreachable!(),
        }
        rejects(&record, Error::InvalidField);
    }
}

#[test]
fn event_identity_and_fixed_digest_domains_reject_malformed_values() {
    for invalid in ["00".repeat(32), "a".repeat(63), "A1".repeat(32)] {
        let mut record = fixture();
        record.event_id = invalid;
        rejects(&record, Error::InvalidField);
    }
    let fields: &[fn(&mut ExecutionRecord) -> &mut String] = &[
        |r| &mut r.grant_sha384,
        |r| &mut r.admission_context_sha384,
        |r| &mut r.preparation_record_sha384,
        |r| &mut r.startup_binding_sha384,
        |r| &mut r.candidate_spec_sha384,
        |r| &mut r.final_spec_sha384,
        |r| &mut r.image_sha384,
        |r| &mut r.executable_sha384,
    ];
    for field in fields {
        for invalid in [
            "a".repeat(95),
            "ab".repeat(49),
            "A1".repeat(48),
            "zz".repeat(48),
        ] {
            let mut record = fixture();
            *field(&mut record) = invalid;
            rejects(&record, Error::InvalidField);
        }
    }
}

#[test]
fn numeric_identity_and_identifier_limits_are_enforced() {
    let mutations: &[fn(&mut ExecutionRecord)] = &[
        |r| r.mount_id = 0,
        |r| r.mount_id = i64::MAX as u64 + 1,
        |r| r.task.generation = 0,
        |r| r.task.pid = 0,
        |r| r.task.pid = i32::MAX as u32 + 1,
        |r| r.task.process_start_time_ticks = 0,
        |r| r.task.container_id.clear(),
        |r| r.task.container_id = "a".repeat(crate::MAX_ID_BYTES + 1),
        |r| r.task.container_id = "with/slash".into(),
        |r| r.task.container_id = "with space".into(),
        |r| r.task.container_id = "nöde".into(),
    ];
    for mutation in mutations {
        let mut record = fixture();
        mutation(&mut record);
        rejects(&record, Error::InvalidField);
    }
    let mut boundary = fixture();
    boundary.mount_id = i64::MAX as u64;
    boundary.task.pid = i32::MAX as u32;
    boundary.task.generation = u64::MAX;
    boundary.task.process_start_time_ticks = u64::MAX;
    boundary.task.container_id = "a".repeat(crate::MAX_ID_BYTES);
    assert_eq!(
        ExecutionRecord::decode(&boundary.encode().unwrap()),
        Ok(boundary)
    );
}

#[test]
fn strict_json_rejects_unknown_duplicate_and_wrongly_typed_fields() {
    let raw = String::from_utf8(fixture().encode().unwrap()).unwrap();
    for altered in [
        raw.replacen("{", r#"{"verified":true,"#, 1),
        raw.replacen(r#""version":1"#, r#""version":1,"version":1"#, 1),
        raw.replacen(r#""generation":7"#, r#""generation":7,"generation":7"#, 1),
        raw.replacen(r#""task":{"#, r#""task":{"unexpected":"x","#, 1),
        raw.replacen(r#""pid":1234"#, r#""pid":1234.0"#, 1),
        raw.replacen(r#""generation":7"#, r#""generation":"7""#, 1),
        format!("{raw}{{}}"),
        raw[..raw.len() - 1].into(),
    ] {
        assert_eq!(
            ExecutionRecord::decode(altered.as_bytes()),
            Err(Error::Malformed)
        );
    }
}

#[test]
fn wire_limit_precedes_json_parse() {
    assert_eq!(
        ExecutionRecord::decode(&vec![0; MAX_WIRE_BYTES + 1]),
        Err(Error::TooLarge)
    );
    assert_eq!(
        ExecutionRecord::decode(&vec![b' '; MAX_WIRE_BYTES]),
        Err(Error::Malformed)
    );
}
