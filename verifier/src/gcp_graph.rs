//! GCP graph authentication is distinct from boot/QVL checking. Success requires
//! both pinned hardware workers and an independently selected signed exact-profile
//! qualification. Neither pack fields nor a public hardware summary enable it.
use crate::{
    gcp_bootstrap_history::{GcpBootstrapHistoryRequest, GcpBootstrapHistoryResponse},
    gcp_pregrant_protocol::GcpPregrantRequest,
    gcp_schema::{GcpEvidencePackV2, GcpTrustConfigV2},
    gcp_worker_protocol::{GcpHardwareRequest, GcpHardwareResponse, GcpHardwareStatus},
    graph::Objects,
    hex,
    schema::{EvidencePack, ObjectKind},
    VerificationError, VerificationVerdict,
};
use execution_proof_contract::{
    admission::gcp::{verify_gcp_admission_authorization_historical, GcpAdmissionExpectations},
    execution::ExecutionRecord,
    gcp_bootstrap::{
        bootstrap_context_sha384, verify_bootstrap_possession, verify_challenge_signature,
    },
    gcp_credential::{verify_credential_metadata_historical, GcpDeliveryExpectations},
    gcp_execution_envelope::GcpExecutionEnvelope,
    gcp_execution_quote::{report_data, GcpQuoteChallenge},
    gcp_policy_receipt::{verify_policy_aggregate, GcpAggregateExpectations},
    gcp_profile::verify_gcp_qualification_historical,
    verify_launch_grant_historical, GrantExpectations, ValidityWindow,
};
use execution_proof_handoff::rootfs_custody::{
    AdmissionBundle, CustodyAnnouncement, PCommit, PreparationProvenance, PreparationRecord,
    ValidatedReceipt, MAX_PROVENANCE_BYTES,
};

pub struct ValidatedGcpGraph {
    record: ExecutionRecord,
    bootstrap: GcpBootstrapHistoryRequest,
    execution: GcpHardwareRequest,
}
fn signed_error(_: execution_proof_contract::Error) -> VerificationError {
    VerificationError::Invalid("gcp_signed_statement_rejected")
}
fn custody_error(_: execution_proof_handoff::rootfs_custody::CustodyError) -> VerificationError {
    VerificationError::Invalid("gcp_custody_object_rejected")
}
fn require(equal: bool, reason: &'static str) -> Result<(), VerificationError> {
    if equal {
        Ok(())
    } else {
        Err(VerificationError::Invalid(reason))
    }
}
fn contained(inner: &ValidityWindow, outer: &ValidityWindow) -> bool {
    inner.not_before >= outer.not_before && inner.expires <= outer.expires
}

pub fn verify_gcp_graph(
    pack: GcpEvidencePackV2,
    trust: &GcpTrustConfigV2,
    expected_challenge: &GcpQuoteChallenge,
) -> Result<ValidatedGcpGraph, VerificationError> {
    pack.validate()?;
    trust.validate()?;
    expected_challenge.validate().map_err(signed_error)?;
    let qualification =
        verify_gcp_qualification_historical(&pack.qualification, &trust.qualification)
            .map_err(signed_error)?;
    let boot = pack.bootstrap;
    let pack: EvidencePack = pack.execution;
    let admission =
        AdmissionBundle::decode(&pack.admission, MAX_PROVENANCE_BYTES).map_err(custody_error)?;
    let grant = verify_launch_grant_historical(
        &admission.grant,
        &GrantExpectations {
            authority_public_key: trust.grant.authority_public_key,
            audience: trust.grant.audience.clone(),
            authority: trust.grant.authority.clone(),
            tenant: trust.grant.tenant.clone(),
            profile_sha384: trust.grant.profile_sha384.clone(),
            launch_policy_sha384: trust.grant.launch_policy_sha384.clone(),
            image_policy_sha384: trust.grant.image_policy_sha384.clone(),
        },
    )
    .map_err(signed_error)?;
    verify_challenge_signature(
        &boot.signed_challenge,
        &trust.grant.authority_public_key,
        &boot.challenge,
    )
    .map_err(signed_error)?;
    let binding = grant.binding();
    require(
        boot.challenge.authority == binding.authority
            && boot.challenge.tenant == binding.tenant
            && boot.challenge.workload_id == binding.workload_id
            && boot.challenge.attempt_id == binding.attempt_id
            && boot.challenge.audience == trust.grant.audience
            && boot.challenge.boot_binding == trust.quote.boot_binding,
        "gcp_bootstrap_scope",
    )?;
    require(
        binding.challenge_sha384 == boot.challenge.digest_sha384().map_err(signed_error)?
            && binding.bootstrap_context_sha384
                == bootstrap_context_sha384(&boot.challenge, &boot.binding, &boot.evidence)
                    .map_err(signed_error)?
            && binding.boot_id == boot.binding.boot_id
            && binding.channel_key_sha384 == boot.binding.recorder_key_sha384
            && boot.binding.keywrap_key_sha384 == trust.credential.keywrap_sha384,
        "gcp_bootstrap_grant_binding",
    )?;
    require(
        contained(grant.validity(), &boot.challenge.validity)
            && contained(&boot.challenge.validity, qualification.validity()),
        "gcp_qualification_window",
    )?;
    // Freshness at issuance was enforced by the issuer. This historical check
    // authenticates the original window; it cannot issue or consume a new grant.
    verify_bootstrap_possession(
        &boot.challenge,
        &boot.binding,
        &boot.evidence,
        &boot.recorder_public_key,
        &boot.possession_signature,
    )
    .map_err(signed_error)?;
    require(
        boot.recorder_public_key != trust.grant.authority_public_key
            && boot.recorder_public_key != trust.aggregate_public_key
            && boot.recorder_public_key != trust.qualification.qualification_public_key,
        "gcp_recorder_key_separation",
    )?;
    let aggregate_expectations = || GcpAggregateExpectations {
        kbs_proof_public_key: trust.aggregate_public_key,
        boot_binding: trust.quote.boot_binding.clone(),
        expected: trust.aggregate_expected.clone(),
    };
    let aggregate =
        verify_policy_aggregate(&admission.aggregate, &grant, &aggregate_expectations())
            .map_err(signed_error)?;
    let accepted = verify_gcp_admission_authorization_historical(
        &admission.receipt,
        &grant,
        &aggregate,
        &GcpAdmissionExpectations {
            authority_public_key: trust.grant.authority_public_key,
            aggregate: aggregate_expectations(),
            audience: trust.admission.audience.clone(),
            issuer: trust.admission.issuer.clone(),
            boot_id: trust.admission.boot_id.clone(),
            attempt_id: trust.admission.attempt_id.clone(),
            guest_nonce: trust.admission.guest_nonce.clone(),
            admission_policy_sha384: trust.admission.admission_policy_sha384.clone(),
        },
    )
    .map_err(signed_error)?;
    let credential = verify_credential_metadata_historical(
        &pack.credential_receipt,
        &grant,
        &aggregate,
        &GcpDeliveryExpectations {
            aggregate: aggregate_expectations(),
            audience: trust.credential.audience.clone(),
            issuer: trust.credential.issuer.clone(),
            keywrap_sha384: trust.credential.keywrap_sha384.clone(),
        },
    )
    .map_err(signed_error)?;
    let record = ExecutionRecord::decode(&pack.record).map_err(signed_error)?;
    let preparation = PreparationRecord::decode(&pack.preparation, MAX_PROVENANCE_BYTES)
        .map_err(custody_error)?;
    let provenance = PreparationProvenance::decode(&pack.provenance, MAX_PROVENANCE_BYTES)
        .map_err(custody_error)?;
    let announcement =
        CustodyAnnouncement::decode(&pack.announcement, i64::MAX as u64, MAX_PROVENANCE_BYTES)
            .map_err(custody_error)?;
    let receipt = ValidatedReceipt::decode(&pack.validated_receipt).map_err(custody_error)?;
    PCommit {
        record: preparation.clone(),
        record_sha384: preparation.sha384().map_err(custody_error)?,
    }
    .validate_for(&announcement, &receipt)
    .map_err(custody_error)?;
    provenance
        .validate_for(&announcement)
        .map_err(custody_error)?;
    require(record.grant_sha384 == grant.grant_digest(), "record_grant")?;
    require(
        record.admission_context_sha384 == accepted.context_digest(),
        "record_context",
    )?;
    require(
        record.preparation_record_sha384 == hex(&preparation.sha384().map_err(custody_error)?),
        "record_preparation",
    )?;
    require(
        record.admission_context_sha384 == preparation.context_sha384
            && record.admission_context_sha384 == provenance.context_sha384,
        "preparation_context",
    )?;
    require(
        preparation.provenance_sha384
            == hex(&provenance
                .sha384(MAX_PROVENANCE_BYTES)
                .map_err(custody_error)?),
        "preparation_provenance",
    )?;
    require(
        record.image_sha384 == preparation.image_sha384
            && record.image_sha384 == provenance.builder.image_sha384,
        "image_binding",
    )?;
    require(
        record.executable_sha384 == preparation.executable_sha384,
        "executable_binding",
    )?;
    require(
        record.candidate_spec_sha384 == preparation.candidate_spec_sha384
            && record.candidate_spec_sha384 == provenance.candidate_spec_sha384
            && record.candidate_spec_sha384 == grant.binding().effective_launch_sha384,
        "candidate_binding",
    )?;
    require(
        record.startup_binding_sha384 == preparation.startup_binding_sha384
            && record.mount_id == preparation.mount_id,
        "startup_mount_binding",
    )?;
    require(
        provenance.manifest_sha256 == grant.binding().selected_manifest_sha256,
        "manifest_binding",
    )?;
    require(
        provenance.signature.policy_sha384 == grant.binding().image_policy_sha384,
        "image_policy_binding",
    )?;
    require(
        provenance.credential_delivery_sha384 == credential.receipt_sha384(),
        "credential_binding",
    )?;
    let quote = GcpExecutionEnvelope::decode(&pack.quote).map_err(signed_error)?;
    require(
        quote.challenge == *expected_challenge,
        "gcp_challenge_mismatch",
    )?;
    require(
        expected_challenge.audience == trust.quote.audience
            && expected_challenge.boot_binding == trust.quote.boot_binding
            && expected_challenge.trust_snapshot_sha384 == trust.quote.trust_snapshot_sha384,
        "gcp_quote_trust_scope",
    )?;
    let expected_report = report_data(&record, expected_challenge).map_err(signed_error)?;
    let mut objects = Objects::new(&pack.objects)?;
    let policy = aggregate.statement();
    let b = &trust.quote.boot_binding;
    let artifacts = execution_proof_contract::gcp_artifact::verify_artifacts(
        objects.get(ObjectKind::GcpConfig, Some(&b.config_sha384))?,
        objects.get(ObjectKind::ProducerProfile, Some(&b.producer_core_sha384))?,
        objects.get(
            ObjectKind::GcpArtifactManifest,
            Some(&b.artifact_manifest_sha384),
        )?,
        objects.get(
            ObjectKind::GcpReferencePolicy,
            Some(&b.reference_policy_sha384),
        )?,
        &trust.artifacts,
    )
    .map_err(signed_error)?;
    let config = artifacts.config();
    require(
        boot.recorder_public_key != config.roots.build_public_key
            && boot.recorder_public_key != config.roots.reference_public_key,
        "gcp_recorder_artifact_key_separation",
    )?;
    require(
        config.roots.authority_public_key == trust.grant.authority_public_key
            && config.roots.kbs_proof_public_key == trust.aggregate_public_key
            && config.roots.qualification_public_key
                == trust.qualification.qualification_public_key
            && config.authority == trust.grant.authority
            && config.tenant == trust.grant.tenant
            && config.grant_audience == trust.grant.audience
            && config.aggregate_audience == policy.audience
            && config.admission_receipt_audience == trust.admission.audience
            && config.launch_policy_sha384 == trust.grant.launch_policy_sha384
            && config.image_policy_sha384 == trust.grant.image_policy_sha384
            && config.resource_path == policy.request.resource_path
            && config.workflow_id == policy.request.workflow_id,
        "gcp_closed_config_scope",
    )?;
    let refs = &trust.qualification.evidence_refs;
    for (kind, digest) in [
        (ObjectKind::AsPolicy, &policy.as_evaluation.policy_sha384),
        (ObjectKind::AsInput, &policy.as_evaluation.input_sha384),
        (ObjectKind::KbsPolicy, &policy.kbs_evaluation.policy_sha384),
        (ObjectKind::KbsInput, &policy.kbs_evaluation.input_sha384),
        (
            ObjectKind::AdmissionPolicy,
            &trust.admission.admission_policy_sha384,
        ),
        (ObjectKind::ImagePolicy, &trust.grant.image_policy_sha384),
        (ObjectKind::ProducerProfile, &b.producer_core_sha384),
        (ObjectKind::GcpConfig, &b.config_sha384),
        (ObjectKind::GcpArtifactManifest, &b.artifact_manifest_sha384),
        (ObjectKind::GcpReferencePolicy, &b.reference_policy_sha384),
        (
            ObjectKind::TrustSnapshot,
            &trust.quote.trust_snapshot_sha384,
        ),
        (ObjectKind::PrelaunchEvidence, &policy.evidence_sha384),
        (ObjectKind::SignatureKey, &provenance.signature.key_sha384),
        (
            ObjectKind::SignaturePayload,
            &provenance.signature.payload_sha384,
        ),
        (
            ObjectKind::Signature,
            &provenance.signature.signature_sha384,
        ),
        (
            ObjectKind::SignatureRepository,
            &provenance.signature.repository_sha384,
        ),
        (
            ObjectKind::GcpArtifactClosure,
            &refs.artifact_closure_sha384,
        ),
        (
            ObjectKind::GcpFirmwareCausality,
            &refs.firmware_causality_sha384,
        ),
        (
            ObjectKind::GcpProducerIsolation,
            &refs.producer_isolation_sha384,
        ),
        (ObjectKind::GcpNoStateCopy, &refs.no_state_copy_sha384),
        (
            ObjectKind::GcpQualificationReview,
            &refs.qualification_review_sha384,
        ),
    ] {
        objects.get(kind, Some(digest))?;
    }
    if let Some(digest) = &policy.as_evaluation.data_sha384 {
        objects.get(ObjectKind::AsData, Some(digest))?;
    }
    if let Some(digest) = &policy.kbs_evaluation.data_sha384 {
        objects.get(ObjectKind::KbsData, Some(digest))?;
    }
    let collateral = objects.get(ObjectKind::DcapCollateral, None)?.to_vec();
    objects.finish()?;
    let bootstrap = GcpBootstrapHistoryRequest::new(GcpPregrantRequest {
        version: 3,
        purpose: "qlad.execution-proof.gcp-pregrant-hardware-request.v3".into(),
        expected_challenge: boot.challenge,
        authority_public_key: trust.grant.authority_public_key,
        signed_challenge_json: boot.signed_challenge,
        binding: boot.binding,
        evidence: boot.evidence,
        boot_policy: trust.quote.boot_policy.clone(),
        module_policy: trust.quote.module_policy.clone(),
        collateral_json: collateral.clone(),
    })?;
    let execution = GcpHardwareRequest {
        version: 2,
        purpose: "qlad.execution-proof.gcp-hardware-request.v2".into(),
        envelope: quote,
        record: record.clone(),
        expected_report_data: hex(&expected_report),
        expected_boot_binding_sha384: trust.grant.profile_sha384.clone(),
        boot_policy: trust.quote.boot_policy.clone(),
        module_policy: trust.quote.module_policy.clone(),
        collateral_json: collateral,
    };
    execution.validate()?;
    Ok(ValidatedGcpGraph {
        record,
        bootstrap,
        execution,
    })
}
impl ValidatedGcpGraph {
    fn apply(
        self,
        bootstrap: GcpBootstrapHistoryResponse,
        execution: GcpHardwareResponse,
    ) -> Result<VerificationVerdict, VerificationError> {
        bootstrap.check_request(&self.bootstrap)?;
        execution.check_request(&self.execution)?;
        for status in [bootstrap.status, execution.status] {
            match status {
                GcpHardwareStatus::Invalid => {
                    return Err(VerificationError::Invalid("gcp_tdx_verification_failed"))
                }
                GcpHardwareStatus::Unproven => {
                    return Err(VerificationError::BackendUnavailable(
                        "gcp_tdx_verification_unavailable",
                    ))
                }
                GcpHardwareStatus::Checked => (),
            }
        }
        let before = bootstrap
            .facts
            .ok_or(VerificationError::Invalid("gcp_bootstrap_facts_missing"))?;
        let after = execution
            .facts
            .ok_or(VerificationError::Invalid("gcp_execution_facts_missing"))?;
        // A worker summary from a different target/evaluation must not substitute
        // for either exact quote. Each worker already repeated all raw predicates.
        require(
            before.mr_owner == after.mr_owner
                && before.mr_td == after.mr_td
                && before.mr_seam == after.mr_seam
                && before.td_attributes == after.td_attributes,
            "gcp_boot_execution_target",
        )?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| VerificationError::BackendUnavailable("verifier_clock"))?
            .as_secs();
        for at in [
            before.evaluation_time_unix_seconds,
            after.evaluation_time_unix_seconds,
        ] {
            if at > now.saturating_add(1) || now.saturating_sub(at) > 61 {
                return Err(VerificationError::BackendUnavailable(
                    "gcp_worker_evaluation_clock",
                ));
            }
        }
        Ok(VerificationVerdict {
            version: 2,
            status: "verified_exec",
            reason: "verified_current_gcp_tdx_execution_graph".into(),
            claim: "exec_committed",
            event_id: Some(self.record.event_id.clone()),
            record_sha384: Some(hex(&self.record.sha384().map_err(signed_error)?)),
            identity_scope: "authorized_workload_attempt",
            time_semantics: "current_collateral_evaluation_of_historical_authorization",
            evaluation_time_unix_seconds: Some(after.evaluation_time_unix_seconds),
        })
    }
}
/// Both executable pins are relying-party configuration. Submitted summaries
/// are never accepted in lieu of actually invoking these owned offline workers.
pub fn verify_gcp_with_workers(
    graph: ValidatedGcpGraph,
    bootstrap_worker: &crate::worker::TrustedWorker,
    execution_worker: &crate::worker::TrustedWorker,
) -> Result<VerificationVerdict, VerificationError> {
    let map = |error| match error {
        crate::worker::WorkerError::InvalidRequest
        | crate::worker::WorkerError::InvalidResponse => {
            VerificationError::Invalid("gcp_pinned_worker_protocol")
        }
        crate::worker::WorkerError::TooLarge | crate::worker::WorkerError::ResourceLimit => {
            VerificationError::ResourceLimit("gcp_pinned_worker_resource_limit")
        }
        crate::worker::WorkerError::Deadline => {
            VerificationError::BackendUnavailable("gcp_pinned_worker_deadline")
        }
        _ => VerificationError::BackendUnavailable("gcp_pinned_worker_unavailable"),
    };
    let bootstrap =
        crate::worker::run_gcp_bootstrap_history_worker(&graph.bootstrap, bootstrap_worker)
            .map_err(map)?;
    let execution =
        crate::worker::run_gcp_worker(&graph.execution, execution_worker).map_err(map)?;
    graph.apply(bootstrap, execution)
}

#[cfg(test)]
#[path = "gcp_graph_tests.rs"]
mod tests;
