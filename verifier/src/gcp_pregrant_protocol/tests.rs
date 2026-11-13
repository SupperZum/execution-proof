//! Public software protocol fixtures only; no QVL or hardware identity claim.
use super::*;
use crate::gcp_boot_evidence::{GcpInstanceIdentity, QuotePaddingPolicy};
use crate::gcp_tdx_policy::{
    GCP_TDX_ALLOWED_ATTRIBUTES, GCP_TDX_POLICY_PURPOSE, INTEL_TDX_MODULE_1_5_34_MR_SEAM,
};
use execution_proof_contract::{
    gcp_boot_binding::GcpBootBindingV1,
    gcp_bootstrap::{
        GCP_BOOTSTRAP_BINDING_PURPOSE, GCP_BOOTSTRAP_CHALLENGE_PURPOSE, GCP_BOOTSTRAP_VERSION,
    },
    Signed, ValidityWindow,
};
use ring::signature::{Ed25519KeyPair, KeyPair};

fn key(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}
fn sign(challenge: &GcpBootstrapChallenge, signer: &Ed25519KeyPair) -> Vec<u8> {
    serde_json::to_vec(&Signed {
        statement: challenge.clone(),
        signature: crate::hex(signer.sign(&challenge.canonical_bytes().unwrap()).as_ref()),
    })
    .unwrap()
}
fn rebind(request: &mut GcpPregrantRequest) {
    request.binding.challenge_sha384 = request.expected_challenge.digest_sha384().unwrap();
    request.binding.boot_binding_sha384 = request
        .expected_challenge
        .boot_binding
        .digest_sha384()
        .unwrap();
}
fn request() -> GcpPregrantRequest {
    let authority = key(1);
    let challenge = GcpBootstrapChallenge {
        version: GCP_BOOTSTRAP_VERSION,
        purpose: GCP_BOOTSTRAP_CHALLENGE_PURPOSE.into(),
        audience: "gcp-issuer".into(),
        authority: "authority-one".into(),
        tenant: "tenant-one".into(),
        workload_id: "workload-one".into(),
        attempt_id: "attempt-one".into(),
        challenge_id: "challenge-one".into(),
        nonce_hex: "11".repeat(32),
        intent_sha384: "12".repeat(48),
        boot_binding: GcpBootBindingV1::new([1; 48], [2; 48], [3; 48], [4; 48]).unwrap(),
        validity: ValidityWindow {
            not_before: 100,
            expires: 300,
        },
    };
    let binding = GcpBootstrapBinding {
        version: GCP_BOOTSTRAP_VERSION,
        purpose: GCP_BOOTSTRAP_BINDING_PURPOSE.into(),
        challenge_sha384: challenge.digest_sha384().unwrap(),
        boot_binding_sha384: challenge.boot_binding.digest_sha384().unwrap(),
        boot_id: "boot-one".into(),
        boot_nonce_hex: "13".repeat(32),
        recorder_key_sha384: "14".repeat(48),
        keywrap_key_sha384: "15".repeat(48),
    };
    let mut request = GcpPregrantRequest {
        version: 3,
        purpose: "qlad.execution-proof.gcp-pregrant-hardware-request.v3".into(),
        signed_challenge_json: sign(&challenge, &authority),
        expected_challenge: challenge,
        authority_public_key: authority.public_key().as_ref().try_into().unwrap(),
        binding,
        evidence: GcpLaunchEvidenceV2::new(
            include_bytes!("../../tests/fixtures/gcp_boot_v1/baseline-quote.bin").to_vec(),
            include_bytes!("../../tests/fixtures/gcp_boot_v1/baseline-acpi-ccel.bin").to_vec(),
            include_bytes!("../../tests/fixtures/gcp_boot_v1/baseline-ccel.bin").to_vec()).unwrap(),
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
            version: 1,
            purpose: GCP_TDX_POLICY_PURPOSE.into(),
            expected_mr_seam: INTEL_TDX_MODULE_1_5_34_MR_SEAM.into(),
            allowed_td_attributes: GCP_TDX_ALLOWED_ATTRIBUTES,
        },
        collateral_json: b"{}".to_vec(),
    };
    // Intentional signature-invalid public fixture: REPORT_DATA is changed for
    // structural/protocol checks only. No QVL or key-origin success is asserted.
    let expected = request.derived_report_data().unwrap();
    request.evidence.tdx_quote[568..632].copy_from_slice(&expected);
    request
}
fn facts(request: &GcpPregrantRequest) -> GcpHardwareFacts {
    let expected = request.derived_report_data().unwrap();
    let checked = crate::gcp_boot_evidence::check_boot_evidence(
        &request.evidence.ccel_table,
        &request.evidence.ccel_log,
        &request.evidence.tdx_quote,
        &expected,
        &request.boot_policy,
    )
    .unwrap();
    let raw = checked.quote;
    GcpHardwareFacts {
        quote_sha384: crate::hex(&raw.quote_sha384),
        report_data: crate::hex(&raw.report_data),
        boot_binding_sha384: request.boot_binding_sha384().unwrap(),
        mr_config_id: crate::hex(&raw.mr_config_id),
        mr_td: crate::hex(&raw.mr_td),
        mr_owner: crate::hex(&raw.mr_owner),
        mr_seam: crate::hex(&raw.mr_seam),
        td_attributes: raw.td_attributes,
        rtmrs: raw.rtmrs.map(|v| crate::hex(&v)),
        event_count: checked.event_count,
        evaluation_time_unix_seconds: 150,
    }
}

#[test]
fn authentic_saved_challenge_and_half_open_trusted_clock_are_checked() {
    let r = request();
    assert!(r.validate().is_ok());
    assert!(r.verify_authority(100).is_ok());
    assert!(r.verify_authority(299).is_ok());
    assert!(r.verify_authority(99).is_err());
    assert!(r.verify_authority(300).is_err());
    assert!(r.verify_authority(u64::MAX).is_err());
    assert_eq!(
        GcpPregrantRequest::decode(&r.encode().unwrap())
            .unwrap()
            .sha384()
            .unwrap(),
        r.sha384().unwrap()
    );
    let mut foreign = r.clone();
    foreign.authority_public_key = key(2).public_key().as_ref().try_into().unwrap();
    assert!(foreign.verify_authority(150).is_err());
    foreign = r.clone();
    foreign.signed_challenge_json = sign(&foreign.expected_challenge, &key(2));
    assert!(foreign.verify_authority(150).is_err());
    foreign = r;
    let mut wire: serde_json::Value =
        serde_json::from_slice(&foreign.signed_challenge_json).unwrap();
    wire["signature"] = "ff".repeat(64).into();
    foreign.signed_challenge_json = serde_json::to_vec(&wire).unwrap();
    // Syntactic validation is deliberately not authentication.
    assert!(foreign.validate().is_ok());
    assert!(foreign.verify_authority(150).is_err());
}

#[test]
fn signed_scope_cannot_be_replaced_by_rebinding_public_nonce_profile_or_window() {
    let original = request();
    for field in 0..10 {
        let mut changed = original.clone();
        match field {
            0 => changed.expected_challenge.tenant.push('x'),
            1 => changed.expected_challenge.workload_id.push('x'),
            2 => changed.expected_challenge.attempt_id.push('x'),
            3 => changed.expected_challenge.nonce_hex = "31".repeat(32),
            4 => changed.expected_challenge.boot_binding.config_sha384 = "32".repeat(48),
            5 => changed.expected_challenge.boot_binding.producer_core_sha384 = "32".repeat(48),
            6 => {
                changed
                    .expected_challenge
                    .boot_binding
                    .artifact_manifest_sha384 = "32".repeat(48)
            }
            7 => {
                changed
                    .expected_challenge
                    .boot_binding
                    .reference_policy_sha384 = "32".repeat(48)
            }
            8 => changed.expected_challenge.validity.not_before += 1,
            _ => changed.expected_challenge.validity.expires += 1,
        };
        rebind(&mut changed);
        assert!(changed.validate().is_ok());
        assert!(changed.verify_authority(150).is_err(), "field {field}");
        assert_ne!(changed.sha384().unwrap(), original.sha384().unwrap());
    }
}

#[test]
fn full_report_binds_boot_nonce_and_both_keys_without_claiming_key_possession() {
    let original = request();
    let expected = original.derived_report_data().unwrap();
    assert_eq!(&expected[48..], &[0; 16]);
    for field in 0..4 {
        let mut changed = original.clone();
        match field {
            0 => changed.binding.recorder_key_sha384 = "31".repeat(48),
            1 => changed.binding.keywrap_key_sha384 = "32".repeat(48),
            2 => changed.binding.boot_nonce_hex = "33".repeat(32),
            _ => changed.binding.boot_id.push('x'),
        };
        assert!(changed.verify_authority(150).is_ok());
        assert_ne!(changed.derived_report_data().unwrap(), expected);
        let response = GcpPregrantResponse::new(
            &original,
            GcpHardwareStatus::Checked,
            "software_fixture",
            Some(facts(&original)),
        )
        .unwrap();
        assert!(response.check_request(&changed).is_err());
    }
    let mut swapped = original.clone();
    swapped.binding.challenge_sha384 = "34".repeat(48);
    assert!(swapped.validate().is_err());
    swapped = original.clone();
    swapped.binding.boot_binding_sha384 = "35".repeat(48);
    assert!(swapped.validate().is_err());
    swapped = original;
    swapped.binding.keywrap_key_sha384 = swapped.binding.recorder_key_sha384.clone();
    assert!(swapped.validate().is_err());
}

#[test]
fn pregrant_v3_and_execution_v2_domains_unknown_fields_and_bounds_do_not_mix() {
    let r = request();
    let wire = r.encode().unwrap();
    assert!(crate::gcp_worker_protocol::GcpHardwareRequest::decode(&wire).is_err());
    for field in ["version", "purpose", "expected_report_data"] {
        let mut value: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        value[field] = match field {
            "version" => 2.into(),
            "purpose" => "qlad.execution-proof.gcp-hardware-request.v2".into(),
            _ => "11".repeat(64).into(),
        };
        assert!(GcpPregrantRequest::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let duplicate = String::from_utf8(wire)
        .unwrap()
        .replacen('{', "{\"version\":3,", 1);
    assert!(GcpPregrantRequest::decode(duplicate.as_bytes()).is_err());
    assert!(GcpPregrantRequest::decode(&vec![b' '; MAX_GCP_WORKER_REQUEST_BYTES + 1]).is_err());
    let mut huge = r;
    huge.signed_challenge_json = vec![0; 16 * 1024 + 1];
    assert!(huge.validate().is_err());
}

#[test]
fn response_request_digest_full64_status_and_fact_domain_contradictions_reject() {
    let r = request();
    let response = GcpPregrantResponse::new(
        &r,
        GcpHardwareStatus::Checked,
        "software_fixture",
        Some(facts(&r)),
    )
    .unwrap();
    assert!(GcpPregrantResponse::decode(&response.encode().unwrap())
        .unwrap()
        .check_request(&r)
        .is_ok());
    let mut changed = response.clone();
    changed.request_sha384 = "11".repeat(48);
    assert!(changed.check_request(&r).is_err());
    for index in [0, 94, 96, 126] {
        let mut changed = response.clone();
        changed
            .facts
            .as_mut()
            .unwrap()
            .report_data
            .replace_range(index..index + 2, "ff");
        assert!(changed.check_request(&r).is_err());
    }
    let mut changed = response.clone();
    changed.version = 2;
    assert!(changed.validate().is_err());
    changed = response.clone();
    changed.purpose = "qlad.execution-proof.gcp-hardware-response.v2".into();
    assert!(changed.validate().is_err());
    changed = response.clone();
    changed.status = GcpHardwareStatus::Invalid;
    assert!(changed.validate().is_err());
    changed = response;
    changed.facts = None;
    assert!(changed.validate().is_err());
    assert!(
        GcpPregrantResponse::new(&r, GcpHardwareStatus::Unproven, "tdx_unavailable", None).is_ok()
    );
}

#[test]
fn checked_facts_must_agree_with_selected_module_boot_policy_and_signed_window() {
    let r = request();
    for field in 0..11 {
        let mut changed = facts(&r);
        match field {
            0 => changed.mr_td = "41".repeat(48),
            1 => changed.mr_owner = "42".repeat(48),
            2 => changed.mr_seam = "43".repeat(48),
            3 => changed.td_attributes |= 1,
            4 => changed.td_attributes |= 1 << 29,
            5 => changed.td_attributes |= 1 << 63,
            6 => changed.evaluation_time_unix_seconds = 99,
            7 => changed.evaluation_time_unix_seconds = 300,
            8 => changed.mr_config_id = "44".repeat(48),
            9 => changed.rtmrs[2] = "45".repeat(48),
            _ => changed.event_count += 1,
        };
        assert!(
            GcpPregrantResponse::new(
                &r,
                GcpHardwareStatus::Checked,
                "software_fixture",
                Some(changed)
            )
            .is_err(),
            "field {field}"
        );
    }
}
