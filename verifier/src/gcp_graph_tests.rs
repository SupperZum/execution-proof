//! These in-memory fixtures test signatures and graph logic. The private
//! response constructor below is never a production TDX verification backend.
use super::*;
#[path = "gcp_artifact_fixture.rs"]
mod artifact_fixture;
use crate::schema::*;
use crate::{gcp_worker_protocol::GcpHardwareFacts, hash};
use execution_proof_contract::{
    admission::{
        gcp::policy_admission_context_gcp, AdmissionAuthorizationV1, ADMISSION_PROFILE,
        ADMISSION_PURPOSE,
    },
    execution::{
        ExecutionTask, EXECUTION_RECORD_CLAIM, EXECUTION_RECORD_PROFILE, EXECUTION_RECORD_PURPOSE,
    },
    gcp_bootstrap::{
        GcpBootstrapBinding, GcpBootstrapChallenge, GCP_BOOTSTRAP_BINDING_PURPOSE,
        GCP_BOOTSTRAP_CHALLENGE_PURPOSE,
    },
    gcp_credential::{
        GcpCredentialDeliveryV2, CREDENTIAL_DELIVERY_PROFILE, CREDENTIAL_DELIVERY_PURPOSE,
    },
    gcp_policy_receipt::{
        verify_policy_aggregate, GcpAggregateExpectations, GcpLaunchPolicyAggregateV2,
        POLICY_AGGREGATE_PROFILE, POLICY_AGGREGATE_PURPOSE,
    },
    gcp_profile::{
        GcpProducerQualificationV1, GcpQualificationEvidenceRefs, GcpQualificationExpectations,
        GCP_QUALIFICATION_CLAIM, GCP_QUALIFICATION_PROFILE, GCP_QUALIFICATION_PURPOSE,
    },
    gcp_session::GcpLaunchEvidenceV2,
    policy_receipt::{PolicyCommitments, ResourcePolicyRequest},
    LaunchBinding, LaunchGrant, Signed, ValidityWindow, GRANT_PURPOSE,
};
use execution_proof_handoff::{
    admission::gcp::{GcpGuestAdmissionConfig, GcpGuestAdmissionGate},
    rootfs_custody::{BuilderProvenance, LayerProvenance, SignatureProvenance},
    rootfs_offer::{BackingDescriptor, RootfsOfferDraft},
};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};

fn key() -> Ed25519KeyPair {
    let bytes = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(bytes.as_ref()).unwrap()
}
fn public(key: &Ed25519KeyPair) -> [u8; 32] {
    key.public_key().as_ref().try_into().unwrap()
}
fn signed<T: serde::Serialize>(statement: T, bytes: &[u8], key: &Ed25519KeyPair) -> Vec<u8> {
    serde_json::to_vec(&Signed {
        statement,
        signature: hex(key.sign(bytes).as_ref()),
    })
    .unwrap()
}
fn digest(bytes: &[u8]) -> [u8; 48] {
    ring::digest::digest(&ring::digest::SHA384, bytes)
        .as_ref()
        .try_into()
        .unwrap()
}

fn fixture() -> (GcpEvidencePackV2, GcpTrustConfigV2, GcpQuoteChallenge) {
    fixture_with_qualification_window(ValidityWindow {
        not_before: 1,
        expires: 100,
    })
}
fn fixture_with_qualification_window(
    qualification_window: ValidityWindow,
) -> (GcpEvidencePackV2, GcpTrustConfigV2, GcpQuoteChallenge) {
    let (authority, kbs, recorder, reviewer) = (key(), key(), key(), key());
    let (c, d, a, v, artifact_expected) = artifact_fixture::artifact_fixture(
        [public(&authority), public(&kbs), public(&reviewer)],
        hash(b"as-policy"),
        hash(b"image-policy"),
        boot_policy().expected_pe_sha384,
        boot_policy().expected_firmware_mrtd,
        hash(&module_policy().encode().unwrap()),
    );
    let values = [
        (ObjectKind::AsPolicy, b"as-policy".as_slice()),
        (ObjectKind::AsInput, b"as-input"),
        (ObjectKind::KbsPolicy, b"kbs-policy"),
        (ObjectKind::KbsInput, b"kbs-input"),
        (ObjectKind::AdmissionPolicy, b"admission-policy"),
        (ObjectKind::ImagePolicy, b"image-policy"),
        (ObjectKind::ProducerProfile, d.as_slice()),
        (ObjectKind::TrustSnapshot, b"trust-snapshot"),
        (ObjectKind::PrelaunchEvidence, b"prelaunch-evidence"),
        (ObjectKind::SignatureKey, b"image-key"),
        (ObjectKind::SignaturePayload, b"image-signature-payload"),
        (ObjectKind::Signature, b"image-signature"),
        (ObjectKind::SignatureRepository, b"image-repository"),
        (ObjectKind::DcapCollateral, b"{}"),
        (ObjectKind::GcpConfig, c.as_slice()),
        (ObjectKind::GcpArtifactManifest, a.as_slice()),
        (ObjectKind::GcpReferencePolicy, v.as_slice()),
        (ObjectKind::GcpArtifactClosure, b"artifact-closure"),
        (ObjectKind::GcpFirmwareCausality, b"firmware-causality"),
        (ObjectKind::GcpProducerIsolation, b"producer-isolation"),
        (ObjectKind::GcpNoStateCopy, b"no-state-copy"),
        (ObjectKind::GcpQualificationReview, b"review"),
    ];
    let objects: Vec<_> = values
        .into_iter()
        .map(|(kind, bytes)| SupportingObject {
            kind,
            sha384: hash(bytes),
            bytes: bytes.to_vec(),
        })
        .collect();
    let object_hash = |kind| {
        objects
            .iter()
            .find(|object| object.kind == kind)
            .unwrap()
            .sha384
            .clone()
    };
    let boot_binding = artifact_expected.boot_binding.clone();
    let boot_challenge = GcpBootstrapChallenge {
        version: 3,
        purpose: GCP_BOOTSTRAP_CHALLENGE_PURPOSE.into(),
        audience: "launch".into(),
        authority: "authority".into(),
        tenant: "tenant".into(),
        workload_id: "workload".into(),
        attempt_id: "attempt".into(),
        challenge_id: "challenge".into(),
        nonce_hex: "31".repeat(32),
        intent_sha384: hash(b"intent"),
        boot_binding: boot_binding.clone(),
        validity: ValidityWindow {
            not_before: 10,
            expires: 20,
        },
    };
    let boot_local = GcpBootstrapBinding {
        version: 3,
        purpose: GCP_BOOTSTRAP_BINDING_PURPOSE.into(),
        challenge_sha384: boot_challenge.digest_sha384().unwrap(),
        boot_binding_sha384: boot_binding.digest_sha384().unwrap(),
        boot_id: "boot".into(),
        boot_nonce_hex: "32".repeat(32),
        recorder_key_sha384: hash(&public(&recorder)),
        keywrap_key_sha384: hash(b"keywrap"),
    };
    let mut boot_evidence = raw_evidence();
    let report =
        execution_proof_contract::gcp_bootstrap::report_data(&boot_challenge, &boot_local).unwrap();
    boot_evidence.tdx_quote[568..632].copy_from_slice(&report);
    let boot_context =
        bootstrap_context_sha384(&boot_challenge, &boot_local, &boot_evidence).unwrap();
    let bootstrap = crate::gcp_schema::GcpBootstrapPublication {
        challenge: boot_challenge.clone(),
        signed_challenge: signed(
            boot_challenge.clone(),
            &boot_challenge.canonical_bytes().unwrap(),
            &authority,
        ),
        binding: boot_local.clone(),
        evidence: boot_evidence.clone(),
        recorder_public_key: public(&recorder),
        possession_signature: hex(recorder
            .sign(
                &execution_proof_contract::gcp_bootstrap::bootstrap_possession_signing_bytes(
                    &boot_challenge,
                    &boot_local,
                    &boot_evidence,
                )
                .unwrap(),
            )
            .as_ref()),
    };
    let grant = LaunchGrant {
        version: 3,
        purpose: GRANT_PURPOSE.into(),
        audience: "launch".into(),
        proof_required: true,
        grant_id: "grant-1".into(),
        validity: ValidityWindow {
            not_before: 10,
            expires: 20,
        },
        binding: LaunchBinding {
            authority: "authority".into(),
            tenant: "tenant".into(),
            workload_id: "workload".into(),
            container_role: "application-init".into(),
            attempt_id: "attempt".into(),
            boot_id: "boot".into(),
            channel_key_sha384: hash(&public(&recorder)),
            bootstrap_context_sha384: boot_context,
            selected_manifest_sha256: "12".repeat(32),
            effective_launch_sha384: hash(b"candidate"),
            profile_sha384: boot_binding.digest_sha384().unwrap(),
            launch_policy_sha384: object_hash(ObjectKind::AsPolicy),
            image_policy_sha384: object_hash(ObjectKind::ImagePolicy),
            challenge_sha384: boot_challenge.digest_sha384().unwrap(),
        },
    };
    let grant_trust = GrantTrust {
        authority_public_key: public(&authority),
        audience: grant.audience.clone(),
        authority: grant.binding.authority.clone(),
        tenant: grant.binding.tenant.clone(),
        profile_sha384: grant.binding.profile_sha384.clone(),
        launch_policy_sha384: grant.binding.launch_policy_sha384.clone(),
        image_policy_sha384: grant.binding.image_policy_sha384.clone(),
    };
    let grant_expect = || GrantExpectations {
        authority_public_key: grant_trust.authority_public_key,
        audience: grant_trust.audience.clone(),
        authority: grant_trust.authority.clone(),
        tenant: grant_trust.tenant.clone(),
        profile_sha384: grant_trust.profile_sha384.clone(),
        launch_policy_sha384: grant_trust.launch_policy_sha384.clone(),
        image_policy_sha384: grant_trust.image_policy_sha384.clone(),
    };
    let grant_bytes = signed(grant.clone(), &grant.signing_bytes().unwrap(), &authority);
    let verified_grant = verify_launch_grant_historical(&grant_bytes, &grant_expect()).unwrap();
    let aggregate = GcpLaunchPolicyAggregateV2 {
        version: 2,
        purpose: POLICY_AGGREGATE_PURPOSE.into(),
        audience: "policy".into(),
        issuer: "kbs".into(),
        profile: POLICY_AGGREGATE_PROFILE.into(),
        grant_sha384: verified_grant.grant_digest().into(),
        authority_key_sha384: hash(&public(&authority)),
        session_id: "34".repeat(32),
        nonce: "fresh-session".into(),
        runtime_sha384: hash(b"runtime"),
        boot_binding_sha384: boot_binding.digest_sha384().unwrap(),
        evidence_sha384: object_hash(ObjectKind::PrelaunchEvidence),
        recorder_key_sha384: grant.binding.channel_key_sha384.clone(),
        request: ResourcePolicyRequest {
            method: "GET".into(),
            plugin: "resource".into(),
            resource_path: ["default".into(), "credentials".into(), "gcp".into()],
            workflow_id: "workflow".into(),
            request_nonce: "request-nonce".into(),
        },
        as_evaluation: PolicyCommitments {
            policy_id: "launch".into(),
            policy_sha384: object_hash(ObjectKind::AsPolicy),
            input_sha384: object_hash(ObjectKind::AsInput),
            data_sha384: None,
        },
        kbs_evaluation: PolicyCommitments {
            policy_id: "resource".into(),
            policy_sha384: object_hash(ObjectKind::KbsPolicy),
            input_sha384: object_hash(ObjectKind::KbsInput),
            data_sha384: None,
        },
    };
    let aggregate_expect = || GcpAggregateExpectations {
        boot_binding: boot_binding.clone(),
        kbs_proof_public_key: public(&kbs),
        expected: aggregate.clone(),
    };
    let aggregate_bytes = signed(aggregate.clone(), &aggregate.signing_bytes().unwrap(), &kbs);
    let verified_aggregate =
        verify_policy_aggregate(&aggregate_bytes, &verified_grant, &aggregate_expect()).unwrap();
    let gate = GcpGuestAdmissionGate::new(GcpGuestAdmissionConfig {
        grant: grant_expect(),
        expected_grant: grant.clone(),
        aggregate: aggregate_expect(),
        audience: "admission".into(),
        issuer: "authority".into(),
        admission_policy_sha384: object_hash(ObjectKind::AdmissionPolicy),
    })
    .unwrap();
    let admission = AdmissionAuthorizationV1 {
        version: 1,
        purpose: ADMISSION_PURPOSE.into(),
        audience: "admission".into(),
        issuer: "authority".into(),
        profile: ADMISSION_PROFILE.into(),
        grant_id: grant.grant_id.clone(),
        grant_sha384: verified_grant.grant_digest().into(),
        aggregate_sha384: verified_aggregate.digest_sha384().into(),
        aggregate_key_sha384: hash(&public(&kbs)),
        context_sha384: policy_admission_context_gcp(
            &verified_grant,
            &verified_aggregate,
            gate.challenge_nonce(),
            &object_hash(ObjectKind::AdmissionPolicy),
        )
        .unwrap(),
        guest_nonce: gate.challenge_nonce().into(),
        admission_policy_sha384: object_hash(ObjectKind::AdmissionPolicy),
        validity: grant.validity,
        binding: grant.binding.clone(),
    };
    let admission_bytes = signed(
        admission.clone(),
        &admission.signing_bytes().unwrap(),
        &authority,
    );
    gate.verify_bundle(&grant_bytes, &aggregate_bytes, &admission_bytes)
        .unwrap();
    let accepted = gate.take_accepted_attempt().unwrap();
    let credential = GcpCredentialDeliveryV2 {
        version: 2,
        purpose: CREDENTIAL_DELIVERY_PURPOSE.into(),
        audience: "credential".into(),
        issuer: "kbs".into(),
        profile: CREDENTIAL_DELIVERY_PROFILE.into(),
        grant_sha384: verified_grant.grant_digest().into(),
        aggregate_sha384: verified_aggregate.digest_sha384().into(),
        request_sha384: aggregate.request.digest_sha384().unwrap(),
        session_id: aggregate.session_id.clone(),
        runtime_sha384: aggregate.runtime_sha384.clone(),
        evidence_sha384: aggregate.evidence_sha384.clone(),
        boot_binding_sha384: aggregate.boot_binding_sha384.clone(),
        recorder_key_sha384: aggregate.recorder_key_sha384.clone(),
        keywrap_sha384: hash(b"keywrap"),
        ciphertext_sha384: hash(b"unexported-jwe"),
        workflow_id: aggregate.request.workflow_id.clone(),
        resource_path: aggregate.request.resource_path.clone(),
        validity: grant.validity,
    };
    let credential_bytes = signed(
        credential.clone(),
        &credential.signing_bytes().unwrap(),
        &kbs,
    );
    let provenance = PreparationProvenance {
        context_sha384: accepted.context_digest().into(),
        manifest_sha256: grant.binding.selected_manifest_sha256.clone(),
        config_sha256: "78".repeat(32),
        credential_delivery_sha384: credential.digest_sha384().unwrap(),
        signature: SignatureProvenance {
            policy_sha384: grant.binding.image_policy_sha384.clone(),
            key_sha384: object_hash(ObjectKind::SignatureKey),
            payload_sha384: object_hash(ObjectKind::SignaturePayload),
            signature_sha384: object_hash(ObjectKind::Signature),
            repository_sha384: object_hash(ObjectKind::SignatureRepository),
        },
        kms_key_version:
            "projects/test/locations/test/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1".into(),
        layers: vec![LayerProvenance {
            original_index: 0,
            blob_sha256: "90".repeat(32),
            descriptor_size: 100,
            plaintext_sha256: "91".repeat(32),
            diff_id: format!("sha256:{}", "92".repeat(32)),
            tar_sha384: hash(b"tar"),
            tar_bytes: 1024,
            tar_entries: 1,
            packet_ordinal: 0,
            packet_sha384: hash(b"packet"),
            kms_ciphertext_sha384: hash(b"kms-ciphertext"),
        }],
        builder: BuilderProvenance {
            tool_sha384: hash(b"builder"),
            input_tar_sha384: hash(b"tar"),
            image_sha384: hash(b"erofs"),
            image_bytes: 8192,
            inodes: 2,
        },
        candidate_spec_sha384: grant.binding.effective_launch_sha384.clone(),
    };
    let provenance_bytes = provenance.encode(MAX_PROVENANCE_BYTES).unwrap();
    let offer = RootfsOfferDraft::new(
        &accepted,
        BackingDescriptor {
            sha384: digest(b"erofs"),
            byte_len: 8192,
        },
        8192,
    )
    .unwrap();
    let announcement = CustodyAnnouncement {
        offer,
        provenance_sha384: digest(&provenance_bytes),
        provenance_bytes: provenance_bytes.len() as u64,
    };
    let receipt = ValidatedReceipt {
        announcement_sha384: announcement.commitment().unwrap(),
        provenance_sha384: digest(&provenance_bytes),
        image_sha384: digest(b"erofs"),
        candidate_spec_sha384: digest(b"candidate"),
        executable_sha384: digest(b"executable"),
        startup_binding_sha384: digest(b"startup"),
        receiver_nonce: [3; 32],
        mount_id: 7,
        inodes: 2,
    };
    let preparation = PreparationRecord {
        context_sha384: accepted.context_digest().into(),
        offer_sha384: hex(&announcement.offer.commitment()),
        provenance_sha384: hash(&provenance_bytes),
        validated_receipt_sha384: hex(&receipt.commitment().unwrap()),
        image_sha384: hash(b"erofs"),
        candidate_spec_sha384: grant.binding.effective_launch_sha384.clone(),
        executable_sha384: hash(b"executable"),
        startup_binding_sha384: hash(b"startup"),
        receiver_nonce: hex(&receipt.receiver_nonce),
        mount_id: 7,
        inodes: 2,
    };
    let record = ExecutionRecord {
        version: 1,
        purpose: EXECUTION_RECORD_PURPOSE.into(),
        profile: EXECUTION_RECORD_PROFILE.into(),
        claim: EXECUTION_RECORD_CLAIM.into(),
        event_id: "ab".repeat(32),
        grant_sha384: verified_grant.grant_digest().into(),
        admission_context_sha384: accepted.context_digest().into(),
        preparation_record_sha384: hex(&preparation.sha384().unwrap()),
        startup_binding_sha384: preparation.startup_binding_sha384.clone(),
        candidate_spec_sha384: preparation.candidate_spec_sha384.clone(),
        final_spec_sha384: hash(b"effective-projection-with-actual-mount"),
        image_sha384: preparation.image_sha384.clone(),
        executable_sha384: preparation.executable_sha384.clone(),
        mount_id: 7,
        task: ExecutionTask {
            container_id: "container".into(),
            generation: 1,
            pid: 100,
            process_start_time_ticks: 42,
        },
    };
    let challenge = GcpQuoteChallenge::new(
        "independent-verifier".into(),
        [11; 32],
        &record,
        boot_binding.clone(),
        digest(b"trust-snapshot"),
    )
    .unwrap();
    let mut raw = raw_evidence();
    raw.tdx_quote[568..632].copy_from_slice(&report_data(&record, &challenge).unwrap());
    let quote = GcpExecutionEnvelope::new(
        challenge.clone(),
        raw.tdx_quote,
        raw.ccel_table,
        raw.ccel_log,
    )
    .unwrap();
    let refs = GcpQualificationEvidenceRefs {
        artifact_closure_sha384: object_hash(ObjectKind::GcpArtifactClosure),
        firmware_causality_sha384: object_hash(ObjectKind::GcpFirmwareCausality),
        producer_isolation_sha384: object_hash(ObjectKind::GcpProducerIsolation),
        no_state_copy_sha384: object_hash(ObjectKind::GcpNoStateCopy),
        qualification_review_sha384: object_hash(ObjectKind::GcpQualificationReview),
    };
    let qualification_expected = GcpQualificationExpectations {
        qualification_public_key: public(&reviewer),
        issuer: "independent-review".into(),
        boot_binding_sha384: boot_binding.digest_sha384().unwrap(),
        pe_sha384: boot_policy().expected_pe_sha384,
        firmware_mrtd: boot_policy().expected_firmware_mrtd,
        module_policy_sha384: hash(&module_policy().encode().unwrap()),
        evidence_refs: refs.clone(),
    };
    let decision = GcpProducerQualificationV1 {
        version: 1,
        purpose: GCP_QUALIFICATION_PURPOSE.into(),
        profile: GCP_QUALIFICATION_PROFILE.into(),
        claim: GCP_QUALIFICATION_CLAIM.into(),
        qualification_id: "software-fixture-only".into(),
        issuer: qualification_expected.issuer.clone(),
        boot_binding_sha384: qualification_expected.boot_binding_sha384.clone(),
        pe_sha384: qualification_expected.pe_sha384.clone(),
        firmware_mrtd: qualification_expected.firmware_mrtd.clone(),
        module_policy_sha384: qualification_expected.module_policy_sha384.clone(),
        evidence_refs: refs,
        validity: qualification_window,
    };
    let qualification = signed(
        decision.clone(),
        &decision.signing_bytes().unwrap(),
        &reviewer,
    );
    let trust = GcpTrustConfigV2 {
        version: 2,
        purpose: crate::gcp_schema::GCP_TRUST_PURPOSE.into(),
        grant: grant_trust,
        aggregate_public_key: public(&kbs),
        aggregate_expected: aggregate,
        admission: AdmissionTrust {
            audience: admission.audience,
            issuer: admission.issuer,
            boot_id: grant.binding.boot_id,
            attempt_id: grant.binding.attempt_id,
            guest_nonce: admission.guest_nonce,
            admission_policy_sha384: admission.admission_policy_sha384,
        },
        credential: CredentialTrust {
            audience: credential.audience,
            issuer: credential.issuer,
            keywrap_sha384: credential.keywrap_sha384,
        },
        quote: crate::gcp_schema::GcpQuoteTrust {
            audience: challenge.audience.clone(),
            boot_binding,
            trust_snapshot_sha384: challenge.trust_snapshot_sha384.clone(),
            boot_policy: boot_policy(),
            module_policy: module_policy(),
        },
        qualification: qualification_expected,
        artifacts: artifact_expected,
    };
    let pack = EvidencePack {
        version: 1,
        purpose: PACK_PURPOSE.into(),
        admission: AdmissionBundle {
            grant: grant_bytes,
            aggregate: aggregate_bytes,
            receipt: admission_bytes,
        }
        .encode(MAX_PROVENANCE_BYTES)
        .unwrap(),
        preparation: preparation.encode(MAX_PROVENANCE_BYTES).unwrap(),
        provenance: provenance_bytes,
        announcement: announcement.encode().unwrap(),
        validated_receipt: receipt.encode().unwrap(),
        record: record.encode().unwrap(),
        quote: quote.encode().unwrap(),
        credential_receipt: credential_bytes,
        objects,
    };
    (
        GcpEvidencePackV2 {
            version: 2,
            purpose: crate::gcp_schema::GCP_PACK_PURPOSE.into(),
            execution: pack,
            bootstrap,
            qualification,
        },
        trust,
        challenge,
    )
}

fn raw_evidence() -> GcpLaunchEvidenceV2 {
    GcpLaunchEvidenceV2::new(
        include_bytes!("../tests/fixtures/gcp_boot_v1/baseline-quote.bin").to_vec(),
        include_bytes!("../tests/fixtures/gcp_boot_v1/baseline-acpi-ccel.bin").to_vec(),
        include_bytes!("../tests/fixtures/gcp_boot_v1/baseline-ccel.bin").to_vec(),
    )
    .unwrap()
}
fn boot_policy() -> crate::gcp_boot_evidence::GcpBootEvidencePolicy {
    use crate::gcp_boot_evidence::*;
    GcpBootEvidencePolicy { expected_pe_sha384: "c4240c5a835ca1c7b6b9c3dd762477870ba5b7a295ec0f551eb45d442be8926b3d887ea59fa348ff5e8832aaf595c8b4".into(), expected_firmware_mrtd: "f21e6b48743fe14c2d090078ca1197f09ae4c99438677f2c79901ef80e2aeefe2f9a7eb6e3eb3b5047c4f1511731e5d3".into(), expected_instance: GcpInstanceIdentity { instance_id: 1159420029374854386, numerical_project_id: 876967775446, zone: "us-central1-a".into() }, quote_padding: QuotePaddingPolicy::GcpTsmZeroPadded8000 }
}
fn module_policy() -> crate::gcp_tdx_policy::GcpTdxModulePolicyV1 {
    use crate::gcp_tdx_policy::*;
    GcpTdxModulePolicyV1 {
        version: 1,
        purpose: GCP_TDX_POLICY_PURPOSE.into(),
        expected_mr_seam: INTEL_TDX_MODULE_1_5_34_MR_SEAM.into(),
        allowed_td_attributes: GCP_TDX_ALLOWED_ATTRIBUTES,
    }
}

// Private software-only summaries bypass QVL in this test module. The quote
// REPORT_DATA fields were changed, so both Intel signatures are INVALID.
fn fake_facts(evidence: &GcpLaunchEvidenceV2, binding: &str) -> GcpHardwareFacts {
    let policy = boot_policy();
    let raw =
        crate::gcp_boot_evidence::parse_quote(&evidence.tdx_quote, policy.quote_padding).unwrap();
    let checked = crate::gcp_boot_evidence::check_boot_evidence(
        &evidence.ccel_table,
        &evidence.ccel_log,
        &evidence.tdx_quote,
        &raw.report_data,
        &policy,
    )
    .unwrap();
    GcpHardwareFacts {
        quote_sha384: hex(&raw.quote_sha384),
        report_data: hex(&raw.report_data),
        boot_binding_sha384: binding.into(),
        mr_config_id: hex(&raw.mr_config_id),
        mr_td: hex(&raw.mr_td),
        mr_owner: hex(&raw.mr_owner),
        mr_seam: hex(&raw.mr_seam),
        td_attributes: raw.td_attributes,
        rtmrs: raw.rtmrs.map(|r| hex(&r)),
        event_count: checked.event_count,
        evaluation_time_unix_seconds: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    }
}
fn fake_responses(graph: &ValidatedGcpGraph) -> (GcpBootstrapHistoryResponse, GcpHardwareResponse) {
    let before = fake_facts(
        &graph.bootstrap.bootstrap.evidence,
        &graph.execution.expected_boot_binding_sha384,
    );
    let e = &graph.execution.envelope;
    let after = fake_facts(
        &GcpLaunchEvidenceV2::new(
            e.tdx_quote.clone(),
            e.ccel_table.clone(),
            e.ccel_log.clone(),
        )
        .unwrap(),
        &graph.execution.expected_boot_binding_sha384,
    );
    (
        GcpBootstrapHistoryResponse::new(
            &graph.bootstrap,
            GcpHardwareStatus::Checked,
            "private_software_fixture",
            Some(before),
        )
        .unwrap(),
        GcpHardwareResponse::new(
            &graph.execution,
            GcpHardwareStatus::Checked,
            "private_software_fixture",
            Some(after),
        )
        .unwrap(),
    )
}
#[test]
fn software_graph_binds_both_captures_and_requires_two_checked_results() {
    let (pack, trust, challenge) = fixture();
    let pack = GcpEvidencePackV2::decode(&pack.encode().unwrap()).unwrap();
    let trust = GcpTrustConfigV2::decode(&trust.encode().unwrap()).unwrap();
    let graph = verify_gcp_graph(pack, &trust, &challenge).unwrap();
    let (before, after) = fake_responses(&graph);
    assert_eq!(
        graph.apply(before, after).unwrap().status(),
        "verified_exec"
    );
    for status in [GcpHardwareStatus::Invalid, GcpHardwareStatus::Unproven] {
        for bootstrap_failed in [true, false] {
            let (pack, trust, challenge) = fixture();
            let graph = verify_gcp_graph(pack, &trust, &challenge).unwrap();
            let (mut before, mut after) = fake_responses(&graph);
            if bootstrap_failed {
                before = GcpBootstrapHistoryResponse::new(
                    &graph.bootstrap,
                    status,
                    "software_failure",
                    None,
                )
                .unwrap();
            } else {
                after =
                    GcpHardwareResponse::new(&graph.execution, status, "software_failure", None)
                        .unwrap();
            }
            assert!(graph.apply(before, after).is_err());
        }
    }
}
#[test]
fn historical_bootstrap_cannot_reopen_live_grant_window_or_mix_domains() {
    let (pack, trust, challenge) = fixture();
    let graph = verify_gcp_graph(pack, &trust, &challenge).unwrap();
    let request = &graph.bootstrap;
    assert!(request.validate().is_ok());
    assert!(request.bootstrap.verify_authority(150).is_err());
    assert!(
        crate::gcp_pregrant_protocol::GcpPregrantRequest::decode(&request.encode().unwrap())
            .is_err()
    );
    let (response, _) = fake_responses(&graph);
    assert!(
        crate::gcp_pregrant_protocol::GcpPregrantResponse::decode(&response.encode().unwrap())
            .is_err()
    );
    assert!(GcpBootstrapHistoryRequest::decode(&request.bootstrap.encode().unwrap()).is_err());
}
#[test]
fn experimental_execution_without_qualification_cannot_enter_the_normal_graph() {
    let (mut pack, trust, challenge) = fixture();
    pack.qualification.clear();
    assert!(verify_gcp_graph(pack, &trust, &challenge).is_err());
}
#[test]
fn later_valid_qualification_cannot_promote_an_earlier_experimental_window() {
    // The existing signed fixture's bootstrap and L are valid from 10 to 20.
    // A valid qualification covering that exact window still authenticates.
    let (pack, trust, challenge) = fixture_with_qualification_window(ValidityWindow {
        not_before: 10,
        expires: 20,
    });
    assert!(verify_gcp_graph(pack, &trust, &challenge).is_ok());
    // Re-sign the actual qualification with its independent fixture reviewer;
    // this tests the graph's temporal binding, not a broken signature.
    for not_before in [20, 21, 100] {
        let (pack, trust, challenge) = fixture_with_qualification_window(ValidityWindow {
            not_before,
            expires: 200,
        });
        assert!(matches!(
            verify_gcp_graph(pack, &trust, &challenge),
            Err(VerificationError::Invalid("gcp_qualification_window"))
        ));
    }
}
#[test]
fn every_public_bootstrap_component_is_bound_to_signed_launch() {
    let mutations: &[fn(&mut GcpEvidencePackV2)] = &[
        |p| p.bootstrap.challenge.nonce_hex = "99".repeat(32),
        |p| p.bootstrap.challenge.attempt_id.push('x'),
        |p| p.bootstrap.challenge.boot_binding.config_sha384 = "99".repeat(48),
        |p| p.bootstrap.binding.boot_nonce_hex = "99".repeat(32),
        |p| p.bootstrap.binding.boot_id.push('x'),
        |p| p.bootstrap.binding.recorder_key_sha384 = "99".repeat(48),
        |p| p.bootstrap.binding.keywrap_key_sha384 = "99".repeat(48),
        |p| p.bootstrap.recorder_public_key[0] ^= 1,
        |p| p.bootstrap.possession_signature = "99".repeat(64),
        |p| p.bootstrap.evidence.tdx_quote[700] ^= 1,
        |p| p.bootstrap.evidence.ccel_table[10] ^= 1,
        |p| p.bootstrap.evidence.ccel_log[100] ^= 1,
        |p| p.qualification[10] ^= 1,
        |p| {
            p.execution
                .objects
                .retain(|o| o.kind != ObjectKind::GcpNoStateCopy)
        },
        |p| {
            p.execution
                .objects
                .iter_mut()
                .find(|o| o.kind == ObjectKind::GcpConfig)
                .unwrap()
                .bytes
                .push(1)
        },
        |p| {
            let o = p.execution.objects[0].clone();
            p.execution.objects.push(o);
        },
    ];
    for (i, mutate) in mutations.iter().enumerate() {
        let (mut pack, trust, challenge) = fixture();
        mutate(&mut pack);
        assert!(
            verify_gcp_graph(pack, &trust, &challenge).is_err(),
            "mutation {i}"
        );
    }
}
#[test]
fn qualification_roots_references_and_legacy_profiles_cannot_self_enroll() {
    let mutations: &[fn(&mut GcpTrustConfigV2)] = &[
        |t| t.qualification.qualification_public_key = t.grant.authority_public_key,
        |t| t.qualification.qualification_public_key = t.aggregate_public_key,
        |t| t.qualification.qualification_public_key = public(&key()),
        |t| t.qualification.evidence_refs.producer_isolation_sha384 = "99".repeat(48),
        |t| t.quote.boot_policy.expected_pe_sha384 = "99".repeat(48),
        |t| t.quote.module_policy.allowed_td_attributes |= 1 << 29,
        |t| t.quote.boot_policy.expected_instance.instance_id += 1,
        |t| t.quote.boot_binding.artifact_manifest_sha384 = "99".repeat(48),
    ];
    for (i, mutate) in mutations.iter().enumerate() {
        let (pack, mut trust, challenge) = fixture();
        mutate(&mut trust);
        match verify_gcp_graph(pack, &trust, &challenge) {
            Err(_) => (),
            Ok(graph) => {
                // Instance identity is appraised by the hardware workers.
                let before = fake_facts(
                    &graph.bootstrap.bootstrap.evidence,
                    &graph.execution.expected_boot_binding_sha384,
                );
                assert!(
                    GcpBootstrapHistoryResponse::new(
                        &graph.bootstrap,
                        GcpHardwareStatus::Checked,
                        "private_software_fixture",
                        Some(before)
                    )
                    .is_err(),
                    "trust mutation {i}"
                );
            }
        }
    }
    let (pack, trust, challenge) = fixture();
    assert!(crate::EvidencePack::decode(&pack.encode().unwrap()).is_err());
    assert!(crate::TrustConfig::decode(&trust.encode().unwrap()).is_err());
    assert!(
        execution_proof_contract::execution_quote::QuoteChallenge::decode(
            &challenge.encode().unwrap()
        )
        .is_err()
    );
}
#[test]
fn mismatched_or_stale_worker_public_summaries_do_not_pass() {
    for mutation in 0..5 {
        let (pack, trust, challenge) = fixture();
        let graph = verify_gcp_graph(pack, &trust, &challenge).unwrap();
        let (mut before, mut after) = fake_responses(&graph);
        match mutation {
            0 => before.request_sha384 = "99".repeat(48),
            1 => after.facts.as_mut().unwrap().report_data = "99".repeat(64),
            2 => after.facts.as_mut().unwrap().td_attributes |= 1 << 29,
            3 => before.facts.as_mut().unwrap().evaluation_time_unix_seconds = 1,
            _ => after.facts.as_mut().unwrap().event_count += 1,
        }
        assert!(graph.apply(before, after).is_err());
    }
}

#[test]
fn protected_gcp_export_bridge_is_bounded_and_never_accepts_legacy_exports() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let (pack, trust, challenge) = fixture();
    let e = &pack.execution;
    let wire = serde_json::json!({
        "version":2,"purpose":"qlad.execution-proof.protected-export.v2",
        "record_b64":STANDARD.encode(&e.record), "admission_b64":STANDARD.encode(&e.admission),
        "preparation_b64":STANDARD.encode(&e.preparation), "provenance_b64":STANDARD.encode(&e.provenance),
        "announcement_b64":STANDARD.encode(&e.announcement), "validated_receipt_b64":STANDARD.encode(&e.validated_receipt),
        "quote_b64":STANDARD.encode(&e.quote),
    });
    let assemble = |wire: &serde_json::Value| {
        GcpEvidencePackV2::from_protected_export(
            &serde_json::to_vec(wire).unwrap(),
            e.credential_receipt.clone(),
            e.objects.clone(),
            pack.bootstrap.clone(),
            pack.qualification.clone(),
        )
    };
    let rebuilt = assemble(&wire).unwrap();
    assert_eq!(rebuilt.encode().unwrap(), pack.encode().unwrap());
    assert!(verify_gcp_graph(rebuilt, &trust, &challenge).is_ok());
    assert!(EvidencePack::from_protected_export(
        &serde_json::to_vec(&wire).unwrap(),
        e.credential_receipt.clone(),
        e.objects.clone()
    )
    .is_err());
    for mutation in 0..4 {
        let mut changed = wire.clone();
        match mutation {
            0 => {
                changed["version"] = 1.into();
                changed["purpose"] = "qlad.execution-proof.protected-export.v1".into();
            }
            1 => {
                changed["record_b64"] = format!("{}\n", wire["record_b64"].as_str().unwrap()).into()
            }
            2 => changed["untrusted"] = true.into(),
            _ => changed["quote_b64"] = "AA==".repeat(2 << 20).into(),
        }
        assert!(assemble(&changed).is_err());
    }
    let mut many = pack.clone();
    while many.execution.objects.len() <= 44 {
        many.execution
            .objects
            .push(many.execution.objects[0].clone());
    }
    assert!(matches!(
        many.validate(),
        Err(VerificationError::ResourceLimit("gcp_object_count"))
    ));
}
