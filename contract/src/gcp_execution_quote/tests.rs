use super::*;
use crate::execution::*;
use crate::execution_quote::QuoteChallenge;

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

fn challenge(record: &ExecutionRecord) -> GcpQuoteChallenge {
    GcpQuoteChallenge::new(
        "verifier.test".into(),
        [7; 32],
        record,
        GcpBootBindingV1::new([1; 48], [2; 48], [3; 48], [4; 48]).unwrap(),
        [9; 48],
    )
    .unwrap()
}

#[test]
fn independent_golden_and_full64_commitment() {
    let r = record();
    let c = challenge(&r);
    assert_eq!(c.canonical_bytes().unwrap().len(), 312);
    assert_eq!(crate::sha384(&c.canonical_bytes().unwrap()),
        "d8b1f3cd7018ce7b8cb7c991826a05c86d7af9a0936ce68046d13da4ad1f5a74fa48d0f052e4c76722fcdfeb6ffc5ae7");
    assert_eq!(hex(&report_data(&r, &c).unwrap()),
        "d7d1c1d5f9a6c39e87081770632e32cc5ce81b4b16163d59f5f7a9837401b8277b9fb41a0f27a2959d41608d04d438f700000000000000000000000000000000");
    assert_eq!(GcpQuoteChallenge::decode(&c.encode().unwrap()), Ok(c));
}

#[test]
fn every_gcp_context_field_changes_report_and_record_mismatch_rejects() {
    let r = record();
    let c = challenge(&r);
    let expected = report_data(&r, &c).unwrap();
    let mutations: &[fn(&mut GcpQuoteChallenge)] = &[
        |c| c.audience.push('x'),
        |c| c.nonce.replace_range(..2, "08"),
        |c| c.boot_binding.config_sha384.replace_range(..2, "08"),
        |c| c.boot_binding.producer_core_sha384.replace_range(..2, "08"),
        |c| {
            c.boot_binding
                .artifact_manifest_sha384
                .replace_range(..2, "08")
        },
        |c| {
            c.boot_binding
                .reference_policy_sha384
                .replace_range(..2, "08")
        },
        |c| c.trust_snapshot_sha384.replace_range(..2, "08"),
    ];
    for mutate in mutations {
        let mut changed = c.clone();
        mutate(&mut changed);
        assert_ne!(report_data(&r, &changed).unwrap(), expected);
    }
    let mut changed = r.clone();
    changed.task.generation += 1;
    assert_eq!(report_data(&changed, &c), Err(Error::BindingMismatch));
}

#[test]
fn legacy_and_gcp_wire_families_cannot_be_reinterpreted() {
    let r = record();
    let legacy =
        QuoteChallenge::new("verifier.test".into(), [7; 32], &r, [2; 48], [9; 48]).unwrap();
    let gcp = challenge(&r);
    assert!(GcpQuoteChallenge::decode(&legacy.encode().unwrap()).is_err());
    assert!(QuoteChallenge::decode(&gcp.encode().unwrap()).is_err());
    assert_ne!(
        report_data(&r, &gcp).unwrap(),
        crate::execution_quote::report_data(&r, &legacy).unwrap()
    );
}

#[test]
fn malformed_unknown_duplicate_domains_and_bounds_reject() {
    let r = record();
    let c = challenge(&r);
    let wire = String::from_utf8(c.encode().unwrap()).unwrap();
    for extra in [r#""extra":0,"#, r#""version":2,"#] {
        let changed = format!("{{{extra}{}", &wire[1..]);
        assert_eq!(
            GcpQuoteChallenge::decode(changed.as_bytes()),
            Err(Error::Malformed)
        );
    }
    let mutations: &[fn(&mut GcpQuoteChallenge)] = &[
        |c| c.version = 1,
        |c| c.purpose.push('x'),
        |c| c.nonce = "00".repeat(32),
        |c| c.trust_snapshot_sha384 = "00".repeat(48),
        |c| c.record_sha384 = "00".repeat(48),
        |c| c.boot_binding.version = 2,
        |c| c.boot_binding.config_sha384 = "AA".repeat(48),
        |c| c.boot_binding.reference_policy_sha384 = "00".repeat(48),
    ];
    for mutate in mutations {
        let mut changed = c.clone();
        mutate(&mut changed);
        assert!(changed.encode().is_err());
        assert!(report_data(&r, &changed).is_err());
    }
    assert_eq!(
        GcpQuoteChallenge::decode(&vec![b' '; crate::MAX_WIRE_BYTES + 1]),
        Err(Error::TooLarge)
    );
}
