use super::*;
use crate::gcp_boot_evidence::{GcpInstanceIdentity, QuotePaddingPolicy};
use crate::gcp_tdx_policy::{
    GCP_TDX_ALLOWED_ATTRIBUTES, GCP_TDX_POLICY_PURPOSE, GCP_TDX_POLICY_VERSION,
    INTEL_TDX_MODULE_1_5_34_MR_SEAM,
};
use execution_proof_contract::{
    gcp_boot_binding::GcpBootBindingV1,
    gcp_execution_quote::{GcpQuoteChallenge, GCP_QUOTE_CHALLENGE_PURPOSE},
};

fn record() -> ExecutionRecord {
    use execution_proof_contract::execution::*;
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
fn rebind(request: &mut GcpHardwareRequest) {
    request.envelope.challenge.record_sha384 = crate::hex(&request.record.sha384().unwrap());
    request.expected_boot_binding_sha384 = request
        .envelope
        .challenge
        .boot_binding
        .digest_sha384()
        .unwrap();
    request.expected_report_data =
        crate::hex(&report_data(&request.record, &request.envelope.challenge).unwrap());
}
fn request() -> GcpHardwareRequest {
    let binding = GcpBootBindingV1::new([1; 48], [2; 48], [3; 48], [4; 48]).unwrap();
    let mut value = GcpHardwareRequest {
        record: record(),
        version: 2,
        purpose: "qlad.execution-proof.gcp-hardware-request.v2".into(),
        envelope: GcpExecutionEnvelope::new(
            GcpQuoteChallenge {
                version: 2,
                purpose: GCP_QUOTE_CHALLENGE_PURPOSE.into(),
                audience: "verifier.test".into(),
                nonce: "07".repeat(32),
                record_sha384: "08".repeat(48),
                boot_binding: binding.clone(),
                trust_snapshot_sha384: "09".repeat(48),
            },
            include_bytes!("../tests/fixtures/gcp_boot_v1/baseline-quote.bin").to_vec(),
            include_bytes!("../tests/fixtures/gcp_boot_v1/baseline-acpi-ccel.bin").to_vec(),
            include_bytes!("../tests/fixtures/gcp_boot_v1/baseline-ccel.bin").to_vec(),
        )
        .unwrap(),
        expected_report_data: format!("{}{}", "12".repeat(48), "00".repeat(16)),
        expected_boot_binding_sha384: binding.digest_sha384().unwrap(),
        boot_policy: GcpBootEvidencePolicy {
            expected_pe_sha384: "c4240c5a835ca1c7b6b9c3dd762477870ba5b7a295ec0f551eb45d442be8926b3d887ea59fa348ff5e8832aaf595c8b4".into(),
            expected_firmware_mrtd: "f21e6b48743fe14c2d090078ca1197f09ae4c99438677f2c79901ef80e2aeefe2f9a7eb6e3eb3b5047c4f1511731e5d3".into(),
            expected_instance: GcpInstanceIdentity {
                instance_id: 1159420029374854386,
                numerical_project_id: 876967775446,
                zone: "us-central1-a".into(),
            },
            quote_padding: QuotePaddingPolicy::GcpTsmZeroPadded8000,
        },
        module_policy: GcpTdxModulePolicyV1 {
            version: GCP_TDX_POLICY_VERSION,
            purpose: GCP_TDX_POLICY_PURPOSE.into(),
            expected_mr_seam: INTEL_TDX_MODULE_1_5_34_MR_SEAM.into(),
            allowed_td_attributes: GCP_TDX_ALLOWED_ATTRIBUTES,
        },
        collateral_json: b"{}".to_vec(),
    };
    rebind(&mut value);
    // Public protocol-only fixture: changing REPORT_DATA invalidates the Intel
    // signature. These tests exercise structural consistency, never QVL.
    value.envelope.tdx_quote[568..632]
        .copy_from_slice(&report_data(&value.record, &value.envelope.challenge).unwrap());
    value
}
fn facts(request: &GcpHardwareRequest) -> GcpHardwareFacts {
    let expected: [u8; 64] = crate::gcp_boot_evidence::parse_quote(
        &request.envelope.tdx_quote,
        request.boot_policy.quote_padding,
    )
    .unwrap()
    .report_data;
    let checked = crate::gcp_boot_evidence::check_boot_evidence(
        &request.envelope.ccel_table,
        &request.envelope.ccel_log,
        &request.envelope.tdx_quote,
        &expected,
        &request.boot_policy,
    )
    .unwrap();
    let raw = checked.quote;
    GcpHardwareFacts {
        quote_sha384: crate::hex(&raw.quote_sha384),
        report_data: crate::hex(&raw.report_data),
        boot_binding_sha384: request.expected_boot_binding_sha384.clone(),
        mr_config_id: crate::hex(&raw.mr_config_id),
        mr_td: crate::hex(&raw.mr_td),
        mr_owner: crate::hex(&raw.mr_owner),
        mr_seam: crate::hex(&raw.mr_seam),
        td_attributes: raw.td_attributes,
        rtmrs: raw.rtmrs.map(|v| crate::hex(&v)),
        event_count: checked.event_count,
        evaluation_time_unix_seconds: 1,
    }
}

#[test]
fn request_digest_covers_evidence_and_every_selected_policy_context() {
    let original = request();
    let expected = original.sha384().unwrap();
    let mutations: &[fn(&mut GcpHardwareRequest)] = &[
        |r| r.envelope.tdx_quote.push(0),
        |r| r.envelope.ccel_table.push(0),
        |r| r.envelope.ccel_log.push(0),
        |r| r.envelope.challenge.audience.push('x'),
        |r| r.record.task.generation += 1,
        |r| r.envelope.challenge.nonce = "0b".repeat(32),
        |r| r.envelope.challenge.trust_snapshot_sha384 = "0c".repeat(48),
        |r| {
            r.envelope.challenge.boot_binding.config_sha384 = "0d".repeat(48);
            r.expected_boot_binding_sha384 =
                r.envelope.challenge.boot_binding.digest_sha384().unwrap();
        },
        |r| r.collateral_json.push(b' '),
        |r| r.boot_policy.expected_pe_sha384 = "23".repeat(48),
        |r| r.boot_policy.expected_firmware_mrtd = "24".repeat(48),
        |r| r.boot_policy.expected_instance.instance_id += 1,
        |r| r.boot_policy.expected_instance.numerical_project_id += 1,
        |r| r.boot_policy.expected_instance.zone = "us-east1-b".into(),
        |r| r.boot_policy.quote_padding = QuotePaddingPolicy::ExactFrame,
        |r| r.module_policy.allowed_td_attributes = 0,
    ];
    for mutate in mutations {
        let mut changed = original.clone();
        mutate(&mut changed);
        rebind(&mut changed);
        assert_ne!(changed.sha384().unwrap(), expected);
    }
    let decoded = GcpHardwareRequest::decode(&original.encode().unwrap()).unwrap();
    assert_eq!(decoded.sha384().unwrap(), expected);
}

#[test]
fn report_full64_domain_and_binding_mismatches_reject() {
    let mutations: &[fn(&mut GcpHardwareRequest)] = &[
        |r| r.version = 1,
        |r| r.purpose.push('x'),
        |r| r.expected_report_data = "00".repeat(64),
        |r| r.expected_report_data.replace_range(126.., "01"),
        |r| r.expected_report_data = "AB".repeat(64),
        |r| r.expected_report_data.pop().map(|_| ()).unwrap(),
        |r| r.expected_boot_binding_sha384 = "04".repeat(48),
        |r| r.envelope.challenge.boot_binding.producer_core_sha384 = "05".repeat(48),
        |r| r.module_policy.purpose.push('x'),
        |r| r.expected_report_data.replace_range(..2, "13"),
        |r| r.record.task.generation += 1,
        |r| r.boot_policy.expected_pe_sha384 = "00".repeat(48),
        |r| r.boot_policy.expected_instance.instance_id = 0,
    ];
    for mutate in mutations {
        let mut value = request();
        mutate(&mut value);
        assert!(value.encode().is_err());
        assert!(GcpHardwareRequest::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}

#[test]
fn responses_require_checked_facts_and_bind_exact_request_digest() {
    let request = request();
    assert!(
        GcpHardwareResponse::new(&request, GcpHardwareStatus::Checked, "checked", None).is_err()
    );
    for status in [GcpHardwareStatus::Invalid, GcpHardwareStatus::Unproven] {
        assert!(
            GcpHardwareResponse::new(&request, status, "reason", Some(facts(&request))).is_err()
        );
        assert!(GcpHardwareResponse::new(&request, status, "reason", None).is_ok());
    }
    let response = GcpHardwareResponse::new(
        &request,
        GcpHardwareStatus::Checked,
        "hardware_and_boot_predicates_checked",
        Some(facts(&request)),
    )
    .unwrap();
    assert_eq!(response.request_sha384, request.sha384().unwrap());
    assert!(GcpHardwareResponse::decode(&response.encode().unwrap()).is_ok());
    let mut invalid = response.clone();
    invalid.facts.as_mut().unwrap().event_count = 0;
    assert!(invalid.encode().is_err());
    let mut invalid = response;
    invalid.facts.as_mut().unwrap().evaluation_time_unix_seconds = 0;
    assert!(invalid.encode().is_err());
}

#[test]
fn request_response_unknown_duplicate_mixed_and_oversized_wire_reject() {
    let request = request();
    let wire = String::from_utf8(request.encode().unwrap()).unwrap();
    for extra in ["\"unknown\":true,", "\"version\":2,"] {
        let bad = format!("{{{extra}{}", &wire[1..]);
        assert!(GcpHardwareRequest::decode(bad.as_bytes()).is_err());
    }
    assert!(GcpHardwareRequest::decode(&vec![b' '; MAX_GCP_WORKER_REQUEST_BYTES + 1]).is_err());
    let response =
        GcpHardwareResponse::new(&request, GcpHardwareStatus::Unproven, "not_qualified", None)
            .unwrap();
    assert!(GcpHardwareRequest::decode(&response.encode().unwrap()).is_err());
    assert!(GcpHardwareResponse::decode(&request.encode().unwrap()).is_err());
    let wire = String::from_utf8(response.encode().unwrap()).unwrap();
    for extra in ["\"unknown\":true,", "\"status\":\"checked\","] {
        let bad = format!("{{{extra}{}", &wire[1..]);
        assert!(GcpHardwareResponse::decode(bad.as_bytes()).is_err());
    }
    assert!(GcpHardwareResponse::decode(&vec![b' '; MAX_GCP_WORKER_RESPONSE_BYTES + 1]).is_err());
}

#[test]
fn foreign_binding_with_old_report_and_record_substitution_are_not_checked_contexts() {
    let original = request();
    let mut changed = original.clone();
    changed.envelope.challenge.boot_binding.config_sha384 = "ac".repeat(48);
    changed.expected_boot_binding_sha384 = changed
        .envelope
        .challenge
        .boot_binding
        .digest_sha384()
        .unwrap();
    assert_eq!(
        changed.validate(),
        Err(VerificationError::Invalid("gcp_report_binding"))
    );
    // Even coherent public B/challenge references cannot retain the old quote binding.
    assert_eq!(changed.expected_report_data, original.expected_report_data);
    let mut changed = original.clone();
    changed.record.task.generation += 1;
    assert_eq!(
        changed.validate(),
        Err(VerificationError::Invalid("gcp_record_binding"))
    );
    changed.envelope.challenge.record_sha384 = crate::hex(&changed.record.sha384().unwrap());
    assert_eq!(
        changed.validate(),
        Err(VerificationError::Invalid("gcp_report_binding"))
    );
}

#[test]
fn checked_constructor_and_decoded_response_reject_foreign_request_and_fact_bindings() {
    let request = request();
    let response = GcpHardwareResponse::new(
        &request,
        GcpHardwareStatus::Checked,
        "checked",
        Some(facts(&request)),
    )
    .unwrap();
    let decoded = GcpHardwareResponse::decode(&response.encode().unwrap()).unwrap();
    assert_eq!(decoded.check_request(&request), Ok(()));
    let mutations: &[fn(&mut GcpHardwareFacts)] = &[
        |f| f.report_data.replace_range(126.., "01"),
        |f| f.report_data.replace_range(..2, "ff"),
        |f| f.boot_binding_sha384 = "ac".repeat(48),
        |f| f.quote_sha384 = "ad".repeat(48),
    ];
    for mutate in mutations {
        let mut changed = facts(&request);
        mutate(&mut changed);
        assert!(matches!(
            GcpHardwareResponse::new(
                &request,
                GcpHardwareStatus::Checked,
                "checked",
                Some(changed.clone())
            ),
            Err(VerificationError::Invalid("gcp_worker_fact_binding"))
        ));
        // Public decode is not response authenticity: the relying parent must check_request.
        let mut tampered = decoded.clone();
        tampered.facts = Some(changed);
        let tampered = GcpHardwareResponse::decode(&tampered.encode().unwrap()).unwrap();
        assert_eq!(
            tampered.check_request(&request),
            Err(VerificationError::Invalid("gcp_worker_fact_binding"))
        );
    }
    let mut foreign = request.clone();
    foreign.collateral_json.push(b' ');
    assert_eq!(
        decoded.check_request(&foreign),
        Err(VerificationError::Invalid("gcp_worker_request_mismatch"))
    );
    let mut altered_request_digest = decoded;
    altered_request_digest.request_sha384 = "ae".repeat(48);
    assert_eq!(
        altered_request_digest.check_request(&request),
        Err(VerificationError::Invalid("gcp_worker_request_mismatch"))
    );
}
