//! These in-memory fixtures test signatures and graph logic. The private
//! response constructor below is never a production TDX verification backend.
use super::*;
use crate::{
    protocol::{TdxClaims, WORKER_RESPONSE_PURPOSE},
    schema::*,
};
use execution_proof_contract::{
    admission::{
        policy_admission_context, AdmissionAuthorizationV1, ADMISSION_PROFILE, ADMISSION_PURPOSE,
    },
    credential::{CredentialDeliveryV1, CREDENTIAL_DELIVERY_PROFILE, CREDENTIAL_DELIVERY_PURPOSE},
    execution::{
        ExecutionTask, EXECUTION_RECORD_CLAIM, EXECUTION_RECORD_PROFILE, EXECUTION_RECORD_PURPOSE,
    },
    policy_receipt::{
        LaunchPolicyAggregateV1, PolicyCommitments, ResourcePolicyRequest,
        POLICY_AGGREGATE_PROFILE, POLICY_AGGREGATE_PURPOSE,
    },
    LaunchBinding, LaunchGrant, Signed, ValidityWindow, GRANT_PURPOSE,
};
use execution_proof_handoff::{
    admission::{GuestAdmissionConfig, GuestAdmissionGate},
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

fn fixture() -> (EvidencePack, TrustConfig, QuoteChallenge) {
    let (authority, kbs) = (key(), key());
    let values = [
        (ObjectKind::AsPolicy, b"as-policy".as_slice()),
        (ObjectKind::AsInput, b"as-input"),
        (ObjectKind::KbsPolicy, b"kbs-policy"),
        (ObjectKind::KbsInput, b"kbs-input"),
        (ObjectKind::AdmissionPolicy, b"admission-policy"),
        (ObjectKind::ImagePolicy, b"image-policy"),
        (ObjectKind::ProducerProfile, b"producer-profile"),
        (ObjectKind::TrustSnapshot, b"trust-snapshot"),
        (ObjectKind::PrelaunchEvidence, b"prelaunch-evidence"),
        (ObjectKind::SignatureKey, b"image-key"),
        (ObjectKind::SignaturePayload, b"image-signature-payload"),
        (ObjectKind::Signature, b"image-signature"),
        (ObjectKind::SignatureRepository, b"image-repository"),
        (ObjectKind::DcapCollateral, b"{}"),
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
            channel_key_sha384: hash(b"channel-key"),
            bootstrap_context_sha384: hash(b"bootstrap"),
            selected_manifest_sha256: "12".repeat(32),
            effective_launch_sha384: hash(b"candidate"),
            profile_sha384: hash(b"launch-profile"),
            launch_policy_sha384: object_hash(ObjectKind::AsPolicy),
            image_policy_sha384: object_hash(ObjectKind::ImagePolicy),
            challenge_sha384: hash(b"bootstrap-challenge"),
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
    let aggregate = LaunchPolicyAggregateV1 {
        version: 1,
        purpose: POLICY_AGGREGATE_PURPOSE.into(),
        audience: "policy".into(),
        issuer: "kbs".into(),
        profile: POLICY_AGGREGATE_PROFILE.into(),
        grant_sha384: verified_grant.grant_digest().into(),
        authority_key_sha384: hash(&public(&authority)),
        session_id: "34".repeat(32),
        nonce: "fresh-session".into(),
        runtime_sha384: hash(b"runtime"),
        init_data_sha384: "56".repeat(48),
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
    let aggregate_expect = || AggregateExpectations {
        kbs_proof_public_key: public(&kbs),
        expected: aggregate.clone(),
    };
    let aggregate_bytes = signed(aggregate.clone(), &aggregate.signing_bytes().unwrap(), &kbs);
    let verified_aggregate =
        verify_policy_aggregate(&aggregate_bytes, &verified_grant, &aggregate_expect()).unwrap();
    let gate = GuestAdmissionGate::new(GuestAdmissionConfig {
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
        context_sha384: policy_admission_context(
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
    let credential = CredentialDeliveryV1 {
        version: 1,
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
        init_data_sha384: aggregate.init_data_sha384.clone(),
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
    let challenge = QuoteChallenge::new(
        "independent-verifier".into(),
        [11; 32],
        &record,
        digest(b"producer-profile"),
        digest(b"trust-snapshot"),
    )
    .unwrap();
    let quote = ExecutionQuoteEnvelope::new(
        challenge.clone(),
        br#"{"quote":"opaque-test-evidence"}"#.to_vec(),
    )
    .unwrap();
    let trust = TrustConfig {
        version: 1,
        purpose: TRUST_PURPOSE.into(),
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
        quote: QuoteTrust {
            audience: challenge.audience.clone(),
            producer_profile_sha384: challenge.producer_profile_sha384.clone(),
            trust_snapshot_sha384: challenge.trust_snapshot_sha384.clone(),
            mr_config_id: "56".repeat(48),
            mr_td: "cd".repeat(48),
            rtmrs: [
                "de".repeat(48),
                "ef".repeat(48),
                "01".repeat(48),
                "23".repeat(48),
            ],
            producer_isolation_qualified: true,
        },
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
    (pack, trust, challenge)
}

fn private_response(graph: &ValidatedGraph) -> TdxWorkerResponse {
    TdxWorkerResponse {
        version: 1,
        purpose: WORKER_RESPONSE_PURPOSE.into(),
        request_sha384: graph.request.sha384_hex().unwrap(),
        status: WorkerStatus::Verified,
        reason: "private_fixture_only".into(),
        claims: Some(TdxClaims {
            evidence_sha384: hash(&graph.request.evidence_json),
            report_data: graph.request.expected_report_data.clone(),
            mr_config_id: graph.trust.mr_config_id.clone(),
            mr_td: graph.trust.mr_td.clone(),
            rtmrs: graph.trust.rtmrs.clone(),
            debug: false,
            tcb_status: "UpToDate".into(),
            collateral_expiration_status: 0,
            evaluation_time_unix_seconds: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }),
    }
}

#[test]
fn authenticates_complete_graph_without_current_grant_reauthorization() {
    let (pack, trust, challenge) = fixture();
    if let Some(directory) = std::env::var_os("ONB17_VERIFIER_PUBLIC_FIXTURE_DIR") {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let directory = std::path::PathBuf::from(directory).canonicalize().unwrap();
        assert!(directory.starts_with("/tmp"));
        for (name, bytes) in [
            ("pack.json", pack.encode().unwrap()),
            ("trust.json", trust.encode().unwrap()),
            ("challenge.json", challenge.encode().unwrap()),
        ] {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.join(name))
                .unwrap();
            file.write_all(&bytes).unwrap();
        }
    }
    let graph = verify_graph(pack, &trust, &challenge).unwrap();
    assert!(graph
        .request
        .expected_report_data
        .ends_with(&"00".repeat(16)));
    let response = private_response(&graph);
    let verdict = graph.apply_worker_response(response).unwrap();
    assert_eq!(verdict.status(), "verified_exec");
    assert_eq!(
        verdict.time_semantics,
        "current_collateral_evaluation_of_historical_authorization"
    );
}

#[test]
fn missing_supporting_object_is_unproven_not_success_or_invalid() {
    let (mut pack, trust, challenge) = fixture();
    pack.objects
        .retain(|object| object.kind != ObjectKind::DcapCollateral);
    assert!(matches!(
        verify_graph(pack, &trust, &challenge),
        Err(VerificationError::MissingEvidence(_))
    ));
}

#[test]
fn modified_supporting_bytes_duplicate_role_and_unreferenced_data_reject() {
    for mutation in 0..3 {
        let (mut pack, trust, challenge) = fixture();
        match mutation {
            0 => pack.objects[0].bytes.push(0),
            1 => pack.objects.push(pack.objects[0].clone()),
            _ => pack.objects.push(SupportingObject {
                kind: ObjectKind::AsData,
                sha384: hash(b"unexpected"),
                bytes: b"unexpected".to_vec(),
            }),
        }
        assert!(matches!(
            verify_graph(pack, &trust, &challenge),
            Err(VerificationError::Invalid(_))
        ));
    }
}

#[test]
fn task_preparation_and_challenge_substitution_reject_before_quote_worker() {
    for mutation in 0..4 {
        let (mut pack, trust, mut challenge) = fixture();
        match mutation {
            0 => {
                let mut r = ExecutionRecord::decode(&pack.record).unwrap();
                r.mount_id += 1;
                pack.record = r.encode().unwrap();
            }
            1 => {
                let mut p =
                    PreparationRecord::decode(&pack.preparation, MAX_PROVENANCE_BYTES).unwrap();
                p.startup_binding_sha384 = hash(b"foreign");
                pack.preparation = p.encode(MAX_PROVENANCE_BYTES).unwrap();
            }
            2 => {
                challenge.nonce = "ef".repeat(32);
            }
            _ => {
                pack.admission[20] ^= 1;
            }
        }
        assert!(matches!(
            verify_graph(pack, &trust, &challenge),
            Err(VerificationError::Invalid(_))
        ));
    }
}

#[test]
fn worker_claims_cannot_change_request_measurements_padding_or_tcb() {
    for mutation in 0..7 {
        let (pack, trust, challenge) = fixture();
        let graph = verify_graph(pack, &trust, &challenge).unwrap();
        let mut response = private_response(&graph);
        if mutation == 0 {
            response.request_sha384 = hash(b"foreign request");
        } else {
            let claims = response.claims.as_mut().unwrap();
            match mutation {
                1 => claims.report_data.replace_range(126.., "01"),
                2 => claims.mr_td = hash(b"foreign td"),
                3 => claims.rtmrs[0] = hash(b"foreign runtime"),
                4 => claims.debug = true,
                5 => claims.tcb_status = "OutOfDate".into(),
                _ => claims.collateral_expiration_status = 1,
            }
        }
        assert!(matches!(
            graph.apply_worker_response(response),
            Err(VerificationError::Invalid(_))
        ));
    }
}

#[test]
fn worker_observed_clock_must_fit_the_current_verification_window() {
    for stale in [true, false] {
        let (pack, trust, challenge) = fixture();
        let graph = verify_graph(pack, &trust, &challenge).unwrap();
        let mut response = private_response(&graph);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        response
            .claims
            .as_mut()
            .unwrap()
            .evaluation_time_unix_seconds = if stale { now - 60 } else { now + 60 };
        assert_eq!(
            graph.apply_worker_response(response).err(),
            Some(VerificationError::BackendUnavailable(
                "worker_evaluation_clock"
            ))
        );
    }
}

#[test]
fn generic_quote_without_qualified_producer_mapping_cannot_verify_exec() {
    let (pack, mut trust, challenge) = fixture();
    trust.quote.producer_isolation_qualified = false;
    let graph = verify_graph(pack, &trust, &challenge).unwrap();
    let response = private_response(&graph);
    assert_eq!(
        graph.apply_worker_response(response).err(),
        Some(VerificationError::MissingEvidence(
            "producer_isolation_not_qualified"
        ))
    );
}

#[test]
fn external_trust_key_and_policy_changes_cannot_be_selected_by_pack() {
    for mutation in 0..2 {
        let (pack, mut trust, challenge) = fixture();
        if mutation == 0 {
            trust.aggregate_public_key = public(&key());
        } else {
            trust.grant.image_policy_sha384 = hash(b"foreign-policy");
        }
        assert!(matches!(
            verify_graph(pack, &trust, &challenge),
            Err(VerificationError::Invalid(_))
        ));
    }
}

#[test]
fn pack_transport_is_bounded_and_rejects_ambiguous_schema() {
    let (pack, trust, _) = fixture();
    let wire = pack.encode().unwrap();
    assert_eq!(EvidencePack::decode(&wire).unwrap().record, pack.record);
    assert_eq!(
        TrustConfig::decode(&trust.encode().unwrap())
            .unwrap()
            .quote
            .mr_td,
        trust.quote.mr_td
    );
    let text = String::from_utf8(wire).unwrap();
    for prefix in ["\"version\":1,", "\"extra\":0,"] {
        assert!(EvidencePack::decode(format!("{{{prefix}{}", &text[1..]).as_bytes()).is_err());
    }
    assert!(matches!(
        EvidencePack::decode(&vec![b' '; MAX_PACK_BYTES + 1]),
        Err(VerificationError::ResourceLimit(_))
    ));
    let nested = format!("{}0{}", "[".repeat(17), "]".repeat(17));
    assert!(matches!(
        schema::decode::<serde_json::Value>(nested.as_bytes(), 1024),
        Err(VerificationError::ResourceLimit("json_depth"))
    ));
}

fn exported_wire(pack: &EvidencePack) -> serde_json::Value {
    use base64::{engine::general_purpose::STANDARD, Engine};
    serde_json::json!({
        "version":1,"purpose":"qlad.execution-proof.protected-export.v1",
        "record_b64":STANDARD.encode(&pack.record),
        "admission_b64":STANDARD.encode(&pack.admission),
        "preparation_b64":STANDARD.encode(&pack.preparation),
        "provenance_b64":STANDARD.encode(&pack.provenance),
        "announcement_b64":STANDARD.encode(&pack.announcement),
        "validated_receipt_b64":STANDARD.encode(&pack.validated_receipt),
        "quote_b64":STANDARD.encode(&pack.quote),
    })
}

#[test]
fn protected_export_assembles_the_same_public_graph_without_minting_authority() {
    let (pack, trust, challenge) = fixture();
    let wire = serde_json::to_vec(&exported_wire(&pack)).unwrap();
    let assembled = EvidencePack::from_protected_export(
        &wire,
        pack.credential_receipt.clone(),
        pack.objects.clone(),
    )
    .unwrap();
    assert_eq!(assembled.encode().unwrap(), pack.encode().unwrap());
    verify_graph(assembled, &trust, &challenge).unwrap();
}

#[test]
fn protected_export_rejects_domain_base64_ambiguity_and_wire_limits() {
    for mutation in 0..5 {
        let (pack, _, _) = fixture();
        let mut wire = exported_wire(&pack);
        match mutation {
            0 => wire["purpose"] = "foreign-export".into(),
            1 => wire["record_b64"] = "YQ".into(),
            2 => wire["record_b64"] = " ".into(),
            3 => wire["extra"] = true.into(),
            _ => wire["record_b64"] = "A".repeat((16 << 10) * 2).into(),
        }
        assert!(EvidencePack::from_protected_export(
            &serde_json::to_vec(&wire).unwrap(),
            pack.credential_receipt,
            pack.objects
        )
        .is_err());
    }
    let (pack, _, _) = fixture();
    let text = serde_json::to_string(&exported_wire(&pack)).unwrap();
    assert!(EvidencePack::from_protected_export(
        format!("{{\"version\":1,{}", &text[1..]).as_bytes(),
        pack.credential_receipt.clone(),
        pack.objects.clone()
    )
    .is_err());
    assert!(matches!(
        EvidencePack::from_protected_export(
            &vec![b' '; MAX_PROTECTED_EXPORT_BYTES + 1],
            pack.credential_receipt,
            pack.objects
        ),
        Err(VerificationError::ResourceLimit(_))
    ));
}
