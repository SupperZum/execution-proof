use super::*;

const QUOTE: &[u8] = include_bytes!("../tests/fixtures/gcp_boot_v1/baseline-quote.bin");
const LOG: &[u8] = include_bytes!("../tests/fixtures/gcp_boot_v1/baseline-ccel.bin");
const TABLE: &[u8] = include_bytes!("../tests/fixtures/gcp_boot_v1/baseline-acpi-ccel.bin");
const REPORT: &[u8; 64] =
    include_bytes!("../tests/fixtures/gcp_boot_v1/baseline-host-challenge.bin");
// Firmware MRTD and PE Authenticode digests are independent fixture references.
const FIRMWARE: &str = "f21e6b48743fe14c2d090078ca1197f09ae4c99438677f2c79901ef80e2aeefe2f9a7eb6e3eb3b5047c4f1511731e5d3";
const BASE_PE: &str = "c4240c5a835ca1c7b6b9c3dd762477870ba5b7a295ec0f551eb45d442be8926b3d887ea59fa348ff5e8832aaf595c8b4";
const MUTANT_PE: &str = "4152d65c10b28c65596e39d8324f3a2a89d45a1a47d90f249141d82c8392649b2263da7420c8a0b95e197f253bc9e337";
fn policy() -> GcpBootEvidencePolicy {
    GcpBootEvidencePolicy {
        expected_pe_sha384: BASE_PE.into(),
        expected_firmware_mrtd: FIRMWARE.into(),
        expected_instance: GcpInstanceIdentity {
            instance_id: 1159420029374854386,
            numerical_project_id: 876967775446,
            zone: "us-central1-a".into(),
        },
        quote_padding: QuotePaddingPolicy::GcpTsmZeroPadded8000,
    }
}
fn check(q: &[u8], l: &[u8], t: &[u8]) -> Result<StructuralBootEvidence> {
    check_boot_evidence(t, l, q, REPORT, &policy())
}

#[test]
fn baseline_replays_all_four_registers_with_independent_references() {
    let facts = check(QUOTE, LOG, TABLE).unwrap();
    assert_eq!(facts.event_count, 22);
    assert_eq!(facts.extended_event_counts, [14, 6, 0, 0]);
    assert_eq!(facts.used_log_bytes, 25047);
    assert_eq!(facts.quote.declared_frame_bytes, 4935);
    assert_eq!(facts.quote.trailing_zero_padding_bytes, 3065);
    assert_eq!(facts.quote.td_attributes, 1 << 28);
    assert_eq!(facts.quote.mr_config_id, [0; 48]);
    assert_eq!(facts.quote.report_data, *REPORT);
}

#[test]
fn real_mutant_requires_its_independent_reference_and_real_wrapper_rejects() {
    let quote = include_bytes!("../tests/fixtures/gcp_boot_v1/mutant-quote.bin");
    let log = include_bytes!("../tests/fixtures/gcp_boot_v1/mutant-ccel.bin");
    let mut p = policy();
    p.expected_instance.instance_id = 8408765100589872418;
    assert_eq!(
        check_boot_evidence(TABLE, log, quote, REPORT, &p),
        Err(invalid("gcp_boot_sequence"))
    );
    p.expected_pe_sha384 = MUTANT_PE.into();
    assert!(check_boot_evidence(TABLE, log, quote, REPORT, &p).is_ok());
    p = policy();
    p.expected_instance.instance_id = 6514067374908142565;
    assert_eq!(
        check_boot_evidence(
            TABLE,
            include_bytes!("../tests/fixtures/gcp_boot_v1/wrapper-ccel.bin"),
            include_bytes!("../tests/fixtures/gcp_boot_v1/wrapper-quote.bin"),
            REPORT,
            &p
        ),
        Err(invalid("gcp_boot_sequence"))
    );
}

#[test]
fn every_report_data_byte_is_compared_and_instance_firmware_are_bound() {
    for byte in 0..64 {
        let mut expected = *REPORT;
        expected[byte] ^= 1;
        assert_eq!(
            check_boot_evidence(TABLE, LOG, QUOTE, &expected, &policy()),
            Err(invalid("gcp_boot_report_data"))
        );
    }
    let mut p = policy();
    p.expected_instance.instance_id += 1;
    assert_eq!(
        check_boot_evidence(TABLE, LOG, QUOTE, REPORT, &p),
        Err(invalid("gcp_boot_instance"))
    );
    p = policy();
    p.expected_instance.numerical_project_id += 1;
    assert_eq!(
        check_boot_evidence(TABLE, LOG, QUOTE, REPORT, &p),
        Err(invalid("gcp_boot_instance"))
    );
    p = policy();
    p.expected_instance.zone = "us-central1-b".into();
    assert_eq!(
        check_boot_evidence(TABLE, LOG, QUOTE, REPORT, &p),
        Err(invalid("gcp_boot_instance"))
    );
    p = policy();
    p.expected_firmware_mrtd = "12".repeat(48);
    assert_eq!(
        check_boot_evidence(TABLE, LOG, QUOTE, REPORT, &p),
        Err(invalid("gcp_boot_firmware"))
    );
}

#[test]
fn strict_wire_policy_rejects_unknown_fields_malformed_hex_and_profile() {
    let p = policy();
    let bytes = serde_json::to_vec(&p).unwrap();
    assert_eq!(
        serde_json::from_slice::<GcpBootEvidencePolicy>(&bytes).unwrap(),
        p
    );
    let mut value = serde_json::to_value(p).unwrap();
    value["quote_padding"] = "guess_from_input".into();
    assert!(serde_json::from_value::<GcpBootEvidencePolicy>(value).is_err());
    let mut value = serde_json::to_value(policy()).unwrap();
    value["unknown"] = 1.into();
    assert!(serde_json::from_value::<GcpBootEvidencePolicy>(value).is_err());
    for invalid_hex in ["00".repeat(48), "AB".repeat(48), "ff".repeat(47)] {
        let mut p = policy();
        p.expected_pe_sha384 = invalid_hex;
        assert!(p.validate().is_err());
    }
    for zone in ["", "a\"", "A", "a/../b"] {
        let mut p = policy();
        p.expected_instance.zone = zone.into();
        assert!(p.validate().is_err());
    }
    let mut p = policy();
    p.expected_instance.instance_id = 0;
    assert!(p.validate().is_err());
}

#[test]
fn quote_padding_is_explicit_and_never_trims_nonzero_tail() {
    let f = parse_quote(QUOTE, QuotePaddingPolicy::GcpTsmZeroPadded8000).unwrap();
    assert!(parse_quote(QUOTE, QuotePaddingPolicy::ExactFrame).is_err());
    assert!(parse_quote(
        &QUOTE[..f.declared_frame_bytes],
        QuotePaddingPolicy::ExactFrame
    )
    .is_ok());
    assert!(parse_quote(&QUOTE[..7999], QuotePaddingPolicy::GcpTsmZeroPadded8000).is_err());
    let mut q = QUOTE.to_vec();
    q[7999] = 1;
    assert!(parse_quote(&q, QuotePaddingPolicy::GcpTsmZeroPadded8000).is_err());
    let mut q = QUOTE[..f.declared_frame_bytes].to_vec();
    q.push(0);
    assert!(parse_quote(&q, QuotePaddingPolicy::ExactFrame).is_err());
}

#[test]
fn strict_quote_headers_nested_sizes_and_truncations_fail_without_panic() {
    for offset in [0, 2, 4, 8, 12, 636 + 128] {
        let mut q = QUOTE.to_vec();
        q[offset] ^= 0x40;
        assert!(parse_quote(&q, QuotePaddingPolicy::GcpTsmZeroPadded8000).is_err());
    }
    for n in 0..QUOTE.len() {
        assert!(parse_quote(&QUOTE[..n], QuotePaddingPolicy::GcpTsmZeroPadded8000).is_err());
    }
    let f = parse_quote(QUOTE, QuotePaddingPolicy::GcpTsmZeroPadded8000).unwrap();
    let mut q = QUOTE[..f.declared_frame_bytes].to_vec();
    q[632..636].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(parse_quote(&q, QuotePaddingPolicy::ExactFrame).is_err());
}

#[test]
fn v5_bodies_are_distinct_and_declared_type_width_must_match() {
    let f = parse_quote(QUOTE, QuotePaddingPolicy::GcpTsmZeroPadded8000).unwrap();
    for (kind, width) in [(2u16, 584u32), (3, 648)] {
        let mut q = QUOTE[..48].to_vec();
        q[..2].copy_from_slice(&5u16.to_le_bytes());
        q.extend_from_slice(&kind.to_le_bytes());
        q.extend_from_slice(&width.to_le_bytes());
        q.extend_from_slice(&QUOTE[48..632]);
        if kind == 3 {
            q.extend_from_slice(&[0; 64]);
        }
        q.extend_from_slice(&QUOTE[632..f.declared_frame_bytes]);
        let public = parse_quote(&q, QuotePaddingPolicy::ExactFrame).unwrap();
        assert_eq!(public.report_data, *REPORT);
        assert_eq!(public.rtmrs, f.rtmrs);
        q[50] ^= 1;
        assert!(parse_quote(&q, QuotePaddingPolicy::ExactFrame).is_err());
    }
}

#[test]
fn acpi_descriptor_checksum_type_capacity_and_address_overflow_fail() {
    for offset in [0, 4, 8, 9, 36, 40, 48] {
        let mut t = TABLE.to_vec();
        t[offset] ^= 1;
        assert!(check(QUOTE, LOG, &t).is_err());
    }
    for offset in [36, 40] {
        let mut t = TABLE.to_vec();
        t[offset] ^= 1;
        t[9] = 0;
        t[9] = 0u8.wrapping_sub(t.iter().fold(0u8, |s, b| s.wrapping_add(*b)));
        assert!(check(QUOTE, LOG, &t).is_err());
    }
    let mut t = TABLE.to_vec();
    t[48..56].copy_from_slice(&u64::MAX.to_le_bytes());
    t[9] = 0;
    t[9] = 0u8.wrapping_sub(t.iter().fold(0u8, |s, b| s.wrapping_add(*b)));
    assert!(check(QUOTE, LOG, &t).is_err());
    assert!(check(QUOTE, LOG, &TABLE[..55]).is_err());
}

fn layout(log: &[u8]) -> Vec<(usize, usize, usize)> {
    let mut c = Cursor::new(log);
    c.take(28).unwrap();
    let n = c.u32().unwrap() as usize;
    c.take(n).unwrap();
    let mut rows = Vec::new();
    while c.remaining().len() >= 8
        && c.remaining()[..8] != [0xff; 8]
        && c.remaining()[..8] != [0; 8]
    {
        let start = c.offset;
        c.take(8).unwrap();
        let count = c.u32().unwrap();
        c.take(count as usize * 50).unwrap();
        let n = c.u32().unwrap() as usize;
        let data = c.offset;
        c.take(n).unwrap();
        rows.push((start, data, c.offset));
    }
    rows
}
fn altered_quote_for_log(log: &[u8]) -> Vec<u8> {
    let parsed = parse_log(log).unwrap();
    let mut q = QUOTE.to_vec();
    let mut r = [[0; 48]; 4];
    for e in parsed.events {
        if e.kind == NO_ACTION {
            continue;
        }
        let i = (e.mr - 1) as usize;
        let mut b = [0; 96];
        b[..48].copy_from_slice(&r[i]);
        b[48..].copy_from_slice(e.digest.as_ref().unwrap());
        r[i] = sha384(&b);
    }
    for (i, r) in r.iter().enumerate() {
        q[376 + i * 48..424 + i * 48].copy_from_slice(r);
    }
    q // Synthetic structural fixture only; signature is deliberately invalid.
}

#[test]
fn event_replay_hidden_padding_and_all_register_tampering_fail() {
    for register in 0..4 {
        let mut q = QUOTE.to_vec();
        q[376 + register * 48] ^= 1;
        assert_eq!(
            check(&q, LOG, TABLE),
            Err(invalid("gcp_ccel_rtmr_mismatch"))
        );
    }
    let mut log = LOG.to_vec();
    log[LOG.len() - 1] = 0;
    assert!(parse_log(&log).is_err());
    let mut log = LOG.to_vec();
    let rows = layout(LOG);
    log[rows[2].0 + 14] ^= 1;
    assert_eq!(
        check(QUOTE, &log, TABLE),
        Err(invalid("gcp_ccel_rtmr_mismatch"))
    );
}

#[test]
fn algorithms_counts_unknown_events_and_size_bounds_fail_closed() {
    let rows = layout(LOG);
    for (offset, bytes) in [
        (rows[2].0 + 12, 0x000bu32.to_le_bytes().to_vec()),
        (rows[2].0 + 8, 2u32.to_le_bytes().to_vec()),
        (rows[2].0 + 4, 0xdeadbeefu32.to_le_bytes().to_vec()),
        (rows[2].1 - 4, u32::MAX.to_le_bytes().to_vec()),
    ] {
        let mut l = LOG.to_vec();
        l[offset..offset + bytes.len()].copy_from_slice(&bytes);
        assert!(parse_log(&l).is_err());
    }
    // First Spec ID digest algorithm must be SHA384, not an arbitrary bank.
    let mut log = LOG.to_vec();
    log[60] ^= 1;
    assert!(parse_log(&log).is_err());
    assert!(parse_log(&vec![0; MAX_LOG_BYTES + 1]).is_err());
    assert!(parse_quote(
        &vec![0; MAX_QUOTE_BYTES + 1],
        QuotePaddingPolicy::ExactFrame
    )
    .is_err());
}

#[test]
fn malformed_image_device_path_and_duplicate_image_are_rejected() {
    let rows = layout(LOG);
    let image = rows[19];
    for off in [image.1 + 31, image.1 + 32, image.2 - 3] {
        let mut l = LOG.to_vec();
        l[off] ^= 0xff;
        assert!(parse_log(&l).is_err());
    }
    let mut l = LOG.to_vec();
    l[image.1 + 8..image.1 + 16].fill(0);
    assert!(parse_log(&l).is_err());
    let mut l = LOG[..image.2].to_vec();
    l.extend_from_slice(&LOG[image.0..image.2]);
    l.extend_from_slice(&LOG[image.2..]);
    l.truncate(LOG.len());
    let q = altered_quote_for_log(&l);
    assert_eq!(check(&q, &l, TABLE), Err(invalid("gcp_boot_sequence")));
}

#[test]
fn replay_consistent_sequence_substitutions_still_fail() {
    let rows = layout(LOG);
    // Swapping EBS events and recomputing the public RTMR field cannot hide
    // their wrong order. This intentionally does not claim a valid signature.
    let mut l = LOG[..rows[20].0].to_vec();
    l.extend_from_slice(&LOG[rows[21].0..rows[21].2]);
    l.extend_from_slice(&LOG[rows[20].0..rows[20].2]);
    l.extend_from_slice(&LOG[rows[21].2..]);
    let q = altered_quote_for_log(&l);
    assert_eq!(check(&q, &l, TABLE), Err(invalid("gcp_boot_sequence")));
    // Event-data labels must agree with their measured digests: relabeling
    // success as another string must reject even though replay is unchanged.
    let mut l = LOG.to_vec();
    l[rows[21].1] ^= 1;
    assert_eq!(check(QUOTE, &l, TABLE), Err(invalid("gcp_boot_sequence")));
    // Dropping the complete final success event keeps a well-framed log but
    // fails the required closed-profile final state after replay is updated.
    let mut l = LOG[..rows[21].0].to_vec();
    l.resize(LOG.len(), 0xff);
    let q = altered_quote_for_log(&l);
    assert_eq!(check(&q, &l, TABLE), Err(invalid("gcp_boot_incomplete")));
}

#[test]
fn event_count_limit_and_informational_digest_rules_are_enforced() {
    let first = layout(LOG)[0].0;
    let mut log = LOG[..first].to_vec();
    for _ in 0..=MAX_EVENTS {
        log.extend_from_slice(&0u32.to_le_bytes());
        log.extend_from_slice(&NO_ACTION.to_le_bytes());
        log.extend_from_slice(&0u32.to_le_bytes());
        log.extend_from_slice(&0u32.to_le_bytes());
    }
    assert_eq!(
        parse_log(&log).unwrap_err(),
        VerificationError::ResourceLimit("gcp_ccel_events")
    );
    let rows = layout(LOG);
    let mut log = LOG.to_vec();
    // A nominal informational event may not smuggle a nonzero measured digest.
    log[rows[0].0 + 8..rows[0].0 + 12].copy_from_slice(&1u32.to_le_bytes());
    log[rows[0].0 + 12..rows[0].0 + 14].copy_from_slice(&SHA384_ALG.to_le_bytes());
    log[rows[0].0 + 14..rows[0].0 + 62].fill(1);
    assert!(parse_log(&log).is_err());
    let mut log = LOG.to_vec();
    log[rows[2].0..rows[2].0 + 4].fill(0);
    assert_eq!(
        parse_log(&log).unwrap_err(),
        invalid("gcp_ccel_measured_event")
    );
}

#[test]
fn missing_or_malformed_gpt_rejects_even_with_matching_replay() {
    let rows = layout(LOG);
    let mut l = LOG[..rows[18].0].to_vec();
    l.extend_from_slice(&LOG[rows[18].2..]);
    l.resize(LOG.len(), 0xff);
    let q = altered_quote_for_log(&l);
    assert_eq!(check(&q, &l, TABLE), Err(invalid("gcp_boot_sequence")));
    for offset in [
        rows[18].1,
        rows[18].1 + 12,
        rows[18].1 + 84,
        rows[18].1 + 92,
    ] {
        let mut l = LOG.to_vec();
        l[offset] ^= 1;
        assert!(check(QUOTE, &l, TABLE).is_err());
    }
}
