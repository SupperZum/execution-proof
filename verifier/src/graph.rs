use crate::{
    hash, hex,
    protocol::{TdxWorkerRequest, TdxWorkerResponse, WorkerStatus},
    schema::{self, EvidencePack, ObjectKind, QuoteTrust, SupportingObject, TrustConfig},
    VerificationError, VerificationVerdict,
};
use execution_proof_contract::{
    admission::{verify_admission_authorization_historical, AdmissionExpectations},
    credential::{verify_credential_metadata_historical, DeliveryExpectations},
    execution::ExecutionRecord,
    execution_quote::{report_data, ExecutionQuoteEnvelope, QuoteChallenge},
    policy_receipt::{verify_policy_aggregate, AggregateExpectations},
    verify_launch_grant_historical, GrantExpectations,
};
use execution_proof_handoff::rootfs_custody::{
    AdmissionBundle, CustodyAnnouncement, PCommit, PreparationProvenance, PreparationRecord,
    ValidatedReceipt, MAX_PROVENANCE_BYTES,
};

/// Authenticated object graph only. Its private fields prevent replacing R or
/// expected claims between graph validation and the pinned worker invocation.
pub struct ValidatedGraph {
    record: ExecutionRecord,
    request: TdxWorkerRequest,
    trust: QuoteTrust,
}

fn signed_error(_: execution_proof_contract::Error) -> VerificationError {
    VerificationError::Invalid("signed_statement_rejected")
}
fn custody_error(_: execution_proof_handoff::rootfs_custody::CustodyError) -> VerificationError {
    VerificationError::Invalid("custody_object_rejected")
}
fn require(equal: bool, reason: &'static str) -> Result<(), VerificationError> {
    if equal {
        Ok(())
    } else {
        Err(VerificationError::Invalid(reason))
    }
}

pub(crate) struct Objects<'a> {
    objects: &'a [SupportingObject],
    used: Vec<ObjectKind>,
}
impl<'a> Objects<'a> {
    pub(crate) fn new(objects: &'a [SupportingObject]) -> Result<Self, VerificationError> {
        for (index, object) in objects.iter().enumerate() {
            require(
                object.sha384 == hash(&object.bytes),
                "supporting_object_digest",
            )?;
            require(
                !objects[..index]
                    .iter()
                    .any(|other| other.kind == object.kind),
                "duplicate_object_kind",
            )?;
        }
        Ok(Self {
            objects,
            used: Vec::new(),
        })
    }
    pub(crate) fn get(
        &mut self,
        kind: ObjectKind,
        digest: Option<&str>,
    ) -> Result<&'a [u8], VerificationError> {
        let object = self
            .objects
            .iter()
            .find(|object| object.kind == kind)
            .ok_or(VerificationError::MissingEvidence(
                "supporting_object_missing",
            ))?;
        if let Some(digest) = digest {
            require(object.sha384 == digest, "supporting_reference_mismatch")?;
        }
        self.used.push(kind);
        Ok(&object.bytes)
    }
    pub(crate) fn finish(&self) -> Result<(), VerificationError> {
        require(
            self.objects
                .iter()
                .all(|object| self.used.contains(&object.kind)),
            "unreferenced_supporting_object",
        )
    }
}

pub fn verify_graph(
    pack: EvidencePack,
    trust: &TrustConfig,
    expected_challenge: &QuoteChallenge,
) -> Result<ValidatedGraph, VerificationError> {
    pack.validate()?;
    trust.validate()?;
    expected_challenge.validate().map_err(signed_error)?;
    // A public in-memory caller gets the same total serialized bound as the CLI.
    schema::encode(&pack, schema::MAX_PACK_BYTES)?;
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
    let aggregate_expectations = || AggregateExpectations {
        kbs_proof_public_key: trust.aggregate_public_key,
        expected: trust.aggregate_expected.clone(),
    };
    let aggregate =
        verify_policy_aggregate(&admission.aggregate, &grant, &aggregate_expectations())
            .map_err(signed_error)?;
    let accepted = verify_admission_authorization_historical(
        &admission.receipt,
        &grant,
        &aggregate,
        &AdmissionExpectations {
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
        &DeliveryExpectations {
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
    require(
        aggregate.statement().init_data_sha384 == trust.quote.mr_config_id,
        "prelaunch_init_data",
    )?;
    let quote = ExecutionQuoteEnvelope::decode(&pack.quote).map_err(signed_error)?;
    require(quote.challenge == *expected_challenge, "challenge_mismatch")?;
    require(
        expected_challenge.audience == trust.quote.audience
            && expected_challenge.producer_profile_sha384 == trust.quote.producer_profile_sha384
            && expected_challenge.trust_snapshot_sha384 == trust.quote.trust_snapshot_sha384,
        "quote_trust_scope",
    )?;
    let expected_report = report_data(&record, expected_challenge).map_err(signed_error)?;

    let mut objects = Objects::new(&pack.objects)?;
    let policy = aggregate.statement();
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
        (
            ObjectKind::ProducerProfile,
            &trust.quote.producer_profile_sha384,
        ),
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
    let request = TdxWorkerRequest::new(
        quote.tdx_evidence,
        hex(&expected_report),
        trust.quote.mr_config_id.clone(),
        collateral,
    )?;
    Ok(ValidatedGraph {
        record,
        request,
        trust: trust.quote.clone(),
    })
}

impl ValidatedGraph {
    pub(crate) fn worker_request(&self) -> Result<TdxWorkerRequest, VerificationError> {
        self.request.validate()?;
        Ok(self.request.clone())
    }
    pub(crate) fn apply_worker_response(
        self,
        response: TdxWorkerResponse,
    ) -> Result<VerificationVerdict, VerificationError> {
        response.validate()?;
        require(
            response.request_sha384 == self.request.sha384_hex()?,
            "worker_request_binding",
        )?;
        match response.status {
            WorkerStatus::Invalid => {
                return Err(VerificationError::Invalid("tdx_verification_failed"))
            }
            WorkerStatus::Unproven => {
                return Err(VerificationError::BackendUnavailable(
                    "tdx_verification_unavailable",
                ))
            }
            WorkerStatus::Verified => (),
        }
        let claims = response
            .claims
            .ok_or(VerificationError::Invalid("worker_claims_missing"))?;
        require(
            claims.evidence_sha384 == hash(&self.request.evidence_json),
            "worker_evidence_binding",
        )?;
        require(
            claims.report_data == self.request.expected_report_data
                && claims.mr_config_id == self.trust.mr_config_id,
            "tdx_report_init_binding",
        )?;
        require(
            claims.mr_td == self.trust.mr_td && claims.rtmrs == self.trust.rtmrs && !claims.debug,
            "tdx_measurement_policy",
        )?;
        require(
            claims.tcb_status == "UpToDate" && claims.collateral_expiration_status == 0,
            "tdx_tcb_policy",
        )?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| VerificationError::BackendUnavailable("verifier_clock"))?
            .as_secs();
        // The pinned worker reports its observed current clock, not exact QVL
        // time or exec time. A clock jump/old response cannot yield "current".
        if claims.evaluation_time_unix_seconds > now.saturating_add(1)
            || now.saturating_sub(claims.evaluation_time_unix_seconds) > 31
        {
            return Err(VerificationError::BackendUnavailable(
                "worker_evaluation_clock",
            ));
        }
        if !self.trust.producer_isolation_qualified {
            return Err(VerificationError::MissingEvidence(
                "producer_isolation_not_qualified",
            ));
        }
        Ok(VerificationVerdict {
            version: 1,
            status: "verified_exec",
            reason: "verified_current_tdx_execution_graph".into(),
            claim: "exec_committed",
            event_id: Some(self.record.event_id.clone()),
            record_sha384: Some(hex(&self.record.sha384().map_err(signed_error)?)),
            identity_scope: "authorized_workload_attempt",
            time_semantics: "current_collateral_evaluation_of_historical_authorization",
            evaluation_time_unix_seconds: Some(claims.evaluation_time_unix_seconds),
        })
    }
}

#[cfg(test)]
#[path = "graph_tests.rs"]
mod tests;
