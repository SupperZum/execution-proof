//! Explicit GCP launch authority. A signed qualification is operator-selected;
//! hardware bootstrap is checked by a pinned offline worker before issuing L.
//! No default service activation, discovery enrollment, or qualification signing
//! is provided by this module.

use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use execution_proof_contract::{
    admission::{
        gcp::{
            policy_admission_context_gcp, verify_gcp_admission_request, GcpAdmissionOperation,
            GcpAdmissionRequestV2,
        },
        AdmissionAuthorizationV1, ADMISSION_PROFILE, ADMISSION_PURPOSE, ADMISSION_VERSION,
    },
    gcp_boot_binding::GcpBootBindingV1,
    gcp_bootstrap::{
        bootstrap_context_sha384, verify_bootstrap_possession, GcpBootstrapBinding,
        GcpBootstrapChallenge, GCP_BOOTSTRAP_CHALLENGE_PURPOSE, GCP_BOOTSTRAP_VERSION,
    },
    gcp_policy_receipt::{
        verify_policy_aggregate, GcpAggregateExpectations, GcpLaunchPolicyAggregateV2,
        POLICY_AGGREGATE_PROFILE,
    },
    gcp_profile::{
        verify_gcp_qualification_historical, GcpQualificationExpectations, VerifiedGcpQualification,
    },
    gcp_session::GcpLaunchEvidenceV2,
    verify_launch_grant_historical, GrantExpectations, VerifiedLaunchGrant,
};
use execution_proof_verifier::{
    gcp_boot_evidence::GcpBootEvidencePolicy,
    gcp_pregrant_protocol::{GcpPregrantRequest, GcpPregrantResponse},
    gcp_tdx_policy::GcpTdxModulePolicyV1,
    gcp_worker_protocol::GcpHardwareStatus,
    worker::{run_gcp_pregrant_worker, TrustedWorker},
};
use kbs_types::TeePubKey;
use std::path::PathBuf;

/// Trusted local selection, fixed for the lifetime of this store. In particular,
/// instance identity, reference roots, and worker are not selected by the guest.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpIssuerConfig {
    pub authorization_ttl_secs: u64,
    pub authority: String,
    pub tenant: String,
    pub audience: String,
    pub tenant_public_key: [u8; 32],
    pub boot_binding: GcpBootBindingV1,
    pub launch_policy_sha384: String,
    pub image_policy_sha384: String,
    pub boot_policy: GcpBootEvidencePolicy,
    pub module_policy: GcpTdxModulePolicyV1,
    pub qualification: GcpQualificationExpectations,
    pub policy_admission: GcpPolicyAdmissionConfig,
    pub pregrant_worker_path: PathBuf,
    pub pregrant_worker_sha384: String,
    /// Operator-supplied archived DCAP collateral; never retrieved by a worker.
    #[serde(default)]
    pub collateral_json: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpPolicyAdmissionConfig {
    pub kbs_proof_public_key: [u8; 32],
    pub aggregate_audience: String,
    pub aggregate_issuer: String,
    pub as_policy_id: String,
    pub as_policy_sha384: String,
    pub as_data_sha384: Option<String>,
    pub kbs_policy_id: String,
    pub kbs_policy_sha384: String,
    pub resource_path: [String; 3],
    pub workflow_id: String,
    pub receipt_audience: String,
}

#[derive(Debug)]
pub enum GcpIssuerError {
    Issuer(Error),
    HardwareUnavailable,
    HardwareRejected,
}
impl fmt::Display for GcpIssuerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Issuer(_) => "GCP issuer rejected request",
            Self::HardwareUnavailable => "GCP bootstrap hardware verifier unavailable",
            Self::HardwareRejected => "GCP bootstrap hardware evidence rejected",
        })
    }
}
impl std::error::Error for GcpIssuerError {}
impl From<Error> for GcpIssuerError {
    fn from(value: Error) -> Self {
        Self::Issuer(value)
    }
}
impl From<execution_proof_contract::Error> for GcpIssuerError {
    fn from(value: execution_proof_contract::Error) -> Self {
        Error::Contract(value).into()
    }
}
impl From<StoreError> for GcpIssuerError {
    fn from(value: StoreError) -> Self {
        Error::Store(value).into()
    }
}

/// Submitted public capture, without a caller-selected verifier or references.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpBootstrapSubmission {
    pub binding: GcpBootstrapBinding,
    pub evidence: GcpLaunchEvidenceV2,
    pub recorder_public_key: [u8; 32],
    pub possession_signature_hex: String,
    pub keywrap_public_key: TeePubKey,
}

pub struct GcpIssuer {
    config: GcpIssuerConfig,
    signer: Ed25519KeyPair,
    qualification: VerifiedGcpQualification,
    store: store::Store,
    clock: Arc<dyn IssuerClock>,
    worker: TrustedWorker,
    admission_policy_sha384: String,
}

impl GcpIssuer {
    pub fn initialize_new(
        path: &Path,
        config: GcpIssuerConfig,
        signed_qualification_json: &[u8],
        signer: Ed25519KeyPair,
        capacity: usize,
    ) -> Result<Self, GcpIssuerError> {
        Self::initialize_new_with_clock(
            path,
            config,
            signed_qualification_json,
            signer,
            capacity,
            Arc::new(SystemClock),
        )
    }
    pub fn initialize_new_with_clock(
        path: &Path,
        config: GcpIssuerConfig,
        signed_qualification_json: &[u8],
        signer: Ed25519KeyPair,
        capacity: usize,
        clock: Arc<dyn IssuerClock>,
    ) -> Result<Self, GcpIssuerError> {
        Self::open(
            path,
            config,
            signed_qualification_json,
            signer,
            capacity,
            clock,
            true,
        )
    }
    pub fn open_existing(
        path: &Path,
        config: GcpIssuerConfig,
        signed_qualification_json: &[u8],
        signer: Ed25519KeyPair,
        capacity: usize,
    ) -> Result<Self, GcpIssuerError> {
        Self::open_existing_with_clock(
            path,
            config,
            signed_qualification_json,
            signer,
            capacity,
            Arc::new(SystemClock),
        )
    }
    pub fn open_existing_with_clock(
        path: &Path,
        config: GcpIssuerConfig,
        signed_qualification_json: &[u8],
        signer: Ed25519KeyPair,
        capacity: usize,
        clock: Arc<dyn IssuerClock>,
    ) -> Result<Self, GcpIssuerError> {
        Self::open(
            path,
            config,
            signed_qualification_json,
            signer,
            capacity,
            clock,
            false,
        )
    }
    fn open(
        path: &Path,
        config: GcpIssuerConfig,
        signed_qualification_json: &[u8],
        signer: Ed25519KeyPair,
        capacity: usize,
        clock: Arc<dyn IssuerClock>,
        initialize: bool,
    ) -> Result<Self, GcpIssuerError> {
        let qualification =
            verify_gcp_qualification_historical(signed_qualification_json, &config.qualification)?;
        let (identity, admission_policy_sha384) = identity(&config, &signer, &qualification)?;
        // Fresh initialization cannot install an expired/unreviewed profile.
        // Reopening permits historical status; every new permission checks again.
        if initialize {
            let now = clock
                .now_unix_seconds()
                .map_err(|_| Error::InvalidConfiguration)?;
            qualification.validity().check_at(now)?;
        }
        let worker =
            TrustedWorker::open(&config.pregrant_worker_path, &config.pregrant_worker_sha384)
                .map_err(|_| GcpIssuerError::HardwareUnavailable)?;
        let authority = public_key(&signer)?;
        let store = if initialize {
            store::Store::initialize_new_gcp_policy(
                path,
                &identity,
                capacity,
                clock.as_ref(),
                authority,
                *qualification.validity(),
            )?
        } else {
            store::Store::open_existing_gcp_policy(
                path,
                &identity,
                capacity,
                authority,
                *qualification.validity(),
            )?
        };
        Ok(Self {
            config,
            signer,
            qualification,
            store,
            clock,
            worker,
            admission_policy_sha384,
        })
    }
    pub fn authority_public_key(&self) -> [u8; 32] {
        public_key(&self.signer).expect("validated Ed25519 key")
    }
    pub fn admission_policy_sha384(&self) -> &str {
        &self.admission_policy_sha384
    }
    pub fn qualification_sha384(&self) -> &str {
        self.qualification.digest_sha384()
    }

    pub fn begin(
        &self,
        signed_intent: &[u8],
    ) -> Result<Signed<GcpBootstrapChallenge>, GcpIssuerError> {
        self.require_live_qualification()?;
        let intent = self.verify_intent(signed_intent)?;
        let statement = intent.statement();
        // This internal record allocates nonce/window and SQL CAS only. Its
        // legacy encoding is never signed, published, or accepted as GCP wire.
        let reservation = self.store.reserve(
            &store::ChallengeRecord {
                challenge: BootstrapChallenge {
                    validity: statement.validity,
                    version: BOOTSTRAP_VERSION,
                    purpose: CHALLENGE_PURPOSE.into(),
                    audience: self.config.audience.clone(),
                    authority: statement.authority.clone(),
                    tenant: statement.tenant.clone(),
                    workload_id: statement.workload_id.clone(),
                    attempt_id: statement.attempt_id.clone(),
                    challenge_id: random_id()?,
                    nonce_hex: random_id()?,
                    intent_sha384: intent.digest_sha384().into(),
                    boot_profile_sha384: self.config.boot_binding.digest_sha384()?,
                    producer_profile_sha384: self.config.boot_binding.digest_sha384()?,
                },
                grant_id: format!("grant-{}", random_id()?),
                signed_intent_json: signed_intent.into(),
                intent_sha384: intent.digest_sha384().into(),
            },
            self.clock.as_ref(),
            self.config.authorization_ttl_secs,
        )?;
        self.signed_challenge(&reservation)
    }

    pub fn issue(
        &self,
        challenge_id: &str,
        submission: &GcpBootstrapSubmission,
    ) -> Result<IssuedGrant, GcpIssuerError> {
        self.issue_checked(challenge_id, submission, |request| {
            run_gcp_pregrant_worker(request, &self.worker)
                .map_err(|_| GcpIssuerError::HardwareUnavailable)
        })
    }

    // Private dispatch permits software unit fixtures; production callers cannot
    // substitute hardware verdicts or supply an already "verified" capability.
    fn issue_checked(
        &self,
        challenge_id: &str,
        submission: &GcpBootstrapSubmission,
        check: impl FnOnce(&GcpPregrantRequest) -> Result<GcpPregrantResponse, GcpIssuerError>,
    ) -> Result<IssuedGrant, GcpIssuerError> {
        self.require_live_qualification()?;
        let reservation = self.store.challenge(challenge_id)?;
        let intent = self.verify_intent(&reservation.signed_intent_json)?;
        if intent.digest_sha384() != reservation.intent_sha384 {
            return Err(Error::BindingMismatch.into());
        }
        let challenge = self.signed_challenge(&reservation)?;
        let keywrap = keywrap_digest(&submission.keywrap_public_key)?;
        if keywrap != submission.binding.keywrap_key_sha384
            || [
                self.authority_public_key(),
                self.config.tenant_public_key,
                self.config.qualification.qualification_public_key,
                self.config.policy_admission.kbs_proof_public_key,
            ]
            .contains(&submission.recorder_public_key)
        {
            return Err(Error::BindingMismatch.into());
        }
        verify_bootstrap_possession(
            &challenge.statement,
            &submission.binding,
            &submission.evidence,
            &submission.recorder_public_key,
            &submission.possession_signature_hex,
        )?;
        let request = GcpPregrantRequest {
            version: 3,
            purpose: "qlad.execution-proof.gcp-pregrant-hardware-request.v3".into(),
            expected_challenge: challenge.statement.clone(),
            authority_public_key: self.authority_public_key(),
            signed_challenge_json: serde_json::to_vec(&challenge)
                .map_err(|_| Error::InvalidRequest)?,
            binding: submission.binding.clone(),
            evidence: submission.evidence.clone(),
            boot_policy: self.config.boot_policy.clone(),
            module_policy: self.config.module_policy.clone(),
            collateral_json: self.config.collateral_json.clone(),
        };
        request
            .verify_authority(self.now()?)
            .map_err(|_| GcpIssuerError::HardwareRejected)?;
        let response = check(&request)?;
        response
            .check_request(&request)
            .map_err(|_| GcpIssuerError::HardwareRejected)?;
        match response.status {
            GcpHardwareStatus::Checked => {}
            GcpHardwareStatus::Invalid => return Err(GcpIssuerError::HardwareRejected),
            GcpHardwareStatus::Unproven => return Err(GcpIssuerError::HardwareUnavailable),
        }
        self.require_live_qualification()?;
        let context = bootstrap_context_sha384(
            &challenge.statement,
            &submission.binding,
            &submission.evidence,
        )?;
        let t = intent.statement();
        let grant = LaunchGrant {
            validity: challenge.statement.validity,
            version: VERSION,
            purpose: GRANT_PURPOSE.into(),
            audience: self.config.audience.clone(),
            proof_required: true,
            grant_id: reservation.grant_id.clone(),
            binding: LaunchBinding {
                authority: t.authority.clone(),
                tenant: t.tenant.clone(),
                workload_id: t.workload_id.clone(),
                container_role: t.container_role.clone(),
                attempt_id: t.attempt_id.clone(),
                boot_id: submission.binding.boot_id.clone(),
                channel_key_sha384: hash(&submission.recorder_public_key),
                bootstrap_context_sha384: context.clone(),
                selected_manifest_sha256: t.selected_manifest_sha256.clone(),
                effective_launch_sha384: t.effective_launch_sha384.clone(),
                profile_sha384: t.profile_sha384.clone(),
                launch_policy_sha384: t.launch_policy_sha384.clone(),
                image_policy_sha384: t.image_policy_sha384.clone(),
                challenge_sha384: challenge.statement.digest_sha384()?,
            },
        };
        let grant_digest = grant.digest_sha384()?;
        let bytes = serde_json::to_vec(&Signed {
            signature: hex(self.signer.sign(&grant.signing_bytes()?).as_ref()),
            statement: grant,
        })
        .map_err(|_| Error::InvalidRequest)?;
        let issued = self.store.issue(
            challenge_id,
            &reservation.challenge.digest_sha384()?,
            &context,
            &hex(&submission.recorder_public_key),
            &bytes,
            &grant_digest,
            self.clock.as_ref(),
        )?;
        Ok(IssuedGrant {
            signed_grant_json: issued.record.signed_grant_json,
            publication: issued.publication,
        })
    }

    pub fn pin_policy_admission(
        &self,
        grant_id: &str,
        expected: &GcpLaunchPolicyAggregateV2,
        guest_nonce: &str,
    ) -> Result<(), GcpIssuerError> {
        self.require_live_qualification()?;
        let (_, grant) = self.grant(grant_id)?;
        self.validate_expected(expected, &grant)?;
        // Context validation enforces the same guest nonce syntax as admission.
        decode_hex(guest_nonce, 32)?;
        self.store.pin_policy(&store::PolicyPin {
            grant_id: grant_id.into(),
            expected_json: serde_json::to_vec(expected).map_err(|_| Error::InvalidRequest)?,
            expected_digest: expected.digest_sha384()?,
            guest_nonce: guest_nonce.into(),
            policy_digest: self.admission_policy_sha384.clone(),
        })?;
        Ok(())
    }

    /// A bounded non-authorizing startup statement derived from this store's L
    /// and an actual KBS signature. The task selector is not a Pod identity.
    /// No grant, redemption state or resource permission is created here.
    pub fn startup_plan(
        &self,
        grant_id: &str,
        aggregate_json: &[u8],
        container_id: &str,
        trust_snapshot_sha384: &str,
        execution_audience: &str,
    ) -> Result<Vec<u8>, GcpIssuerError> {
        use execution_proof_contract::gcp_startup::{GcpAttemptPlanV1, PLAN_PURPOSE};
        self.require_live_qualification()?;
        if aggregate_json.is_empty() || aggregate_json.len() > MAX_WIRE_BYTES {
            return Err(Error::InvalidRequest.into());
        }
        let (_, grant) = self.grant(grant_id)?;
        let signed: Signed<GcpLaunchPolicyAggregateV2> =
            serde_json::from_slice(aggregate_json).map_err(|_| Error::InvalidRequest)?;
        self.validate_expected(&signed.statement, &grant)?;
        let aggregate = verify_policy_aggregate(
            aggregate_json,
            &grant,
            &GcpAggregateExpectations {
                kbs_proof_public_key: self.config.policy_admission.kbs_proof_public_key,
                boot_binding: self.config.boot_binding.clone(),
                expected: signed.statement,
            },
        )?;
        let plan = GcpAttemptPlanV1 {
            version: 1,
            purpose: PLAN_PURPOSE.into(),
            authority: self.config.authority.clone(),
            boot_binding: self.config.boot_binding.clone(),
            grant_sha384: grant.grant_digest().into(),
            aggregate_sha384: aggregate.digest_sha384().into(),
            admission_policy_sha384: self.admission_policy_sha384.clone(),
            container_id: container_id.into(),
            effective_spec_sha384: grant.binding().effective_launch_sha384.clone(),
            trust_snapshot_sha384: trust_snapshot_sha384.into(),
            execution_audience: execution_audience.into(),
            execution_nonce_hex: random_id()?,
        };
        let bytes = plan.signing_bytes()?;
        // Store/verification work may have queued. Plans retain the old L's
        // window and cannot be newly signed after qualification or L expiry.
        let now = self.now()?;
        self.qualification.validity().check_at(now)?;
        grant.validity().check_at(now)?;
        let result = serde_json::to_vec(&Signed {
            statement: plan,
            signature: hex(self.signer.sign(&bytes).as_ref()),
        })
        .map_err(|_| Error::InvalidRequest)?;
        if result.len() > MAX_WIRE_BYTES {
            return Err(Error::InvalidRequest.into());
        }
        Ok(result)
    }

    pub fn redeem_policy_aggregate(
        &self,
        grant_id: &str,
        aggregate_json: &[u8],
        recorder_request_json: &[u8],
    ) -> Result<AdmissionPublication, GcpIssuerError> {
        self.require_live_qualification()?;
        let authorization = self.authenticate_policy_request(
            grant_id,
            aggregate_json,
            recorder_request_json,
            GcpAdmissionOperation::Redeem,
        )?;
        let outcome =
            self.store
                .redeem_policy(&authorization, &self.signer, self.clock.as_ref())?;
        Ok(AdmissionPublication {
            signed_authorization_json: outcome.bytes,
            publication: outcome.publication,
        })
    }
    /// Historical retrieval never renews an authorization or requires a live qualification.
    pub fn status_policy_aggregate(
        &self,
        grant_id: &str,
        aggregate_json: &[u8],
        recorder_request_json: &[u8],
    ) -> Result<Option<Vec<u8>>, GcpIssuerError> {
        let authorization = self.authenticate_policy_request(
            grant_id,
            aggregate_json,
            recorder_request_json,
            GcpAdmissionOperation::Status,
        )?;
        Ok(self.store.policy_status(&authorization)?)
    }
    fn now(&self) -> Result<u64, GcpIssuerError> {
        self.clock
            .now_unix_seconds()
            .map_err(|_| Error::InvalidRequest.into())
    }
    fn require_live_qualification(&self) -> Result<(), GcpIssuerError> {
        self.qualification.validity().check_at(self.now()?)?;
        Ok(())
    }
    fn verify_intent(&self, bytes: &[u8]) -> Result<VerifiedTenantIntent, GcpIssuerError> {
        let intent = verify_tenant_intent(
            bytes,
            &TenantIntentExpectations {
                tenant_public_key: self.config.tenant_public_key,
                audience: self.config.audience.clone(),
                authority: self.config.authority.clone(),
                tenant: self.config.tenant.clone(),
                profile_sha384: self.config.boot_binding.digest_sha384()?,
            },
        )?;
        let t = intent.statement();
        if t.launch_policy_sha384 != self.config.launch_policy_sha384
            || t.image_policy_sha384 != self.config.image_policy_sha384
            || t.container_role != "application-init"
        {
            return Err(Error::PolicyMismatch.into());
        }
        Ok(intent)
    }
    fn signed_challenge(
        &self,
        reservation: &store::ChallengeRecord,
    ) -> Result<Signed<GcpBootstrapChallenge>, GcpIssuerError> {
        let c = &reservation.challenge;
        let statement = GcpBootstrapChallenge {
            version: GCP_BOOTSTRAP_VERSION,
            purpose: GCP_BOOTSTRAP_CHALLENGE_PURPOSE.into(),
            audience: self.config.audience.clone(),
            authority: c.authority.clone(),
            tenant: c.tenant.clone(),
            workload_id: c.workload_id.clone(),
            attempt_id: c.attempt_id.clone(),
            challenge_id: c.challenge_id.clone(),
            nonce_hex: c.nonce_hex.clone(),
            intent_sha384: c.intent_sha384.clone(),
            boot_binding: self.config.boot_binding.clone(),
            validity: c.validity,
        };
        let signature = hex(self.signer.sign(&statement.canonical_bytes()?).as_ref());
        Ok(Signed {
            statement,
            signature,
        })
    }
    fn grant(
        &self,
        grant_id: &str,
    ) -> Result<(store::IssuedRecord, VerifiedLaunchGrant), GcpIssuerError> {
        let issued = self.store.get_issued(grant_id)?;
        let grant = verify_launch_grant_historical(
            &issued.signed_grant_json,
            &GrantExpectations {
                authority_public_key: self.authority_public_key(),
                audience: self.config.audience.clone(),
                authority: self.config.authority.clone(),
                tenant: self.config.tenant.clone(),
                profile_sha384: self.config.boot_binding.digest_sha384()?,
                launch_policy_sha384: self.config.launch_policy_sha384.clone(),
                image_policy_sha384: self.config.image_policy_sha384.clone(),
            },
        )?;
        if grant.grant_id() != grant_id
            || grant.grant_digest() != issued.grant_digest
            || grant.binding().bootstrap_context_sha384 != issued.bootstrap_context_digest
            || grant.binding().channel_key_sha384
                != hash(&decode_hex(&issued.recorder_public_key_hex, 32)?)
        {
            return Err(Error::BindingMismatch.into());
        }
        Ok((issued, grant))
    }
    fn validate_expected(
        &self,
        e: &GcpLaunchPolicyAggregateV2,
        grant: &VerifiedLaunchGrant,
    ) -> Result<(), GcpIssuerError> {
        e.signing_bytes()?;
        let p = &self.config.policy_admission;
        if e.profile != POLICY_AGGREGATE_PROFILE
            || e.audience != p.aggregate_audience
            || e.issuer != p.aggregate_issuer
            || e.grant_sha384 != grant.grant_digest()
            || e.authority_key_sha384 != grant.authority_key_sha384()
            || e.boot_binding_sha384 != self.config.boot_binding.digest_sha384()?
            || e.recorder_key_sha384 != grant.binding().channel_key_sha384
            || e.as_evaluation.policy_id != p.as_policy_id
            || e.as_evaluation.policy_sha384 != p.as_policy_sha384
            || e.as_evaluation.data_sha384 != p.as_data_sha384
            || e.kbs_evaluation.policy_id != p.kbs_policy_id
            || e.kbs_evaluation.policy_sha384 != p.kbs_policy_sha384
            || e.request.resource_path != p.resource_path
            || e.request.workflow_id != p.workflow_id
        {
            return Err(Error::PolicyMismatch.into());
        }
        Ok(())
    }
    fn authenticate_policy_request(
        &self,
        grant_id: &str,
        aggregate_json: &[u8],
        wire: &[u8],
        operation: GcpAdmissionOperation,
    ) -> Result<AdmissionAuthorizationV1, GcpIssuerError> {
        let (issued, grant) = self.grant(grant_id)?;
        let pin = self.store.policy_pin(grant_id)?;
        if pin.policy_digest != self.admission_policy_sha384 {
            return Err(Error::PolicyMismatch.into());
        }
        let expected: GcpLaunchPolicyAggregateV2 =
            serde_json::from_slice(&pin.expected_json).map_err(|_| Error::InvalidRequest)?;
        self.validate_expected(&expected, &grant)?;
        let aggregate = verify_policy_aggregate(
            aggregate_json,
            &grant,
            &GcpAggregateExpectations {
                kbs_proof_public_key: self.config.policy_admission.kbs_proof_public_key,
                boot_binding: self.config.boot_binding.clone(),
                expected,
            },
        )?;
        if aggregate.digest_sha384() != pin.expected_digest {
            return Err(Error::BindingMismatch.into());
        }
        let context = policy_admission_context_gcp(
            &grant,
            &aggregate,
            &pin.guest_nonce,
            &self.admission_policy_sha384,
        )?;
        if wire.len() > MAX_WIRE_BYTES {
            return Err(Error::InvalidRequest.into());
        }
        let expected_request = GcpAdmissionRequestV2::new(
            &grant,
            &aggregate,
            &pin.guest_nonce,
            &self.admission_policy_sha384,
            &self.config.audience,
            operation,
        )?;
        let recorder: [u8; 32] = decode_hex(&issued.recorder_public_key_hex, 32)?
            .try_into()
            .map_err(|_| Error::InvalidRequest)?;
        verify_gcp_admission_request(wire, &recorder, &expected_request, &grant)?;
        Ok(AdmissionAuthorizationV1 {
            version: ADMISSION_VERSION,
            purpose: ADMISSION_PURPOSE.into(),
            audience: self.config.policy_admission.receipt_audience.clone(),
            issuer: self.config.authority.clone(),
            profile: ADMISSION_PROFILE.into(),
            grant_id: grant.grant_id().into(),
            grant_sha384: grant.grant_digest().into(),
            aggregate_sha384: aggregate.digest_sha384().into(),
            aggregate_key_sha384: aggregate.kbs_proof_key_sha384().into(),
            context_sha384: context,
            guest_nonce: pin.guest_nonce,
            admission_policy_sha384: self.admission_policy_sha384.clone(),
            validity: *grant.validity(),
            binding: grant.binding().clone(),
        })
    }
}

fn public_key(signer: &Ed25519KeyPair) -> Result<[u8; 32], Error> {
    signer
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_| Error::InvalidConfiguration)
}
fn keywrap_digest(key: &TeePubKey) -> Result<String, Error> {
    match key {
        TeePubKey::RSA { alg, k_mod, k_exp } if alg == "RSA-OAEP-256" && k_exp == "AQAB" => {
            let modulus = URL_SAFE_NO_PAD
                .decode(k_mod)
                .map_err(|_| Error::InvalidRequest)?;
            if modulus.len() != 256
                || modulus[0] & 0x80 == 0
                || modulus[255] & 1 == 0
                || URL_SAFE_NO_PAD.encode(&modulus) != *k_mod
            {
                return Err(Error::InvalidRequest);
            }
        }
        _ => return Err(Error::InvalidRequest),
    }
    Ok(hash(
        &serde_json_canonicalizer::to_vec(key).map_err(|_| Error::InvalidRequest)?,
    ))
}
fn identity(
    config: &GcpIssuerConfig,
    signer: &Ed25519KeyPair,
    qualification: &VerifiedGcpQualification,
) -> Result<(String, String), GcpIssuerError> {
    if !(1..=MAX_AUTHORIZATION_TTL_SECS).contains(&config.authorization_ttl_secs) {
        return Err(Error::InvalidConfiguration.into());
    }
    config.boot_binding.validate()?;
    config
        .boot_policy
        .validate()
        .map_err(|_| Error::InvalidConfiguration)?;
    config
        .module_policy
        .validate()
        .map_err(|_| Error::InvalidConfiguration)?;
    let p = &config.policy_admission;
    for id in [
        &config.authority,
        &config.tenant,
        &config.audience,
        &p.aggregate_audience,
        &p.aggregate_issuer,
        &p.as_policy_id,
        &p.kbs_policy_id,
        &p.workflow_id,
        &p.receipt_audience,
    ] {
        identifier(id)?;
    }
    for value in [
        &config.launch_policy_sha384,
        &config.image_policy_sha384,
        &p.as_policy_sha384,
        &p.kbs_policy_sha384,
        &config.pregrant_worker_sha384,
    ] {
        decode_hex(value, 48)?;
    }
    if let Some(data) = &p.as_data_sha384 {
        decode_hex(data, 48)?;
    }
    let keys = [
        public_key(signer)?,
        config.tenant_public_key,
        p.kbs_proof_public_key,
        config.qualification.qualification_public_key,
    ];
    for (i, key) in keys.iter().enumerate() {
        if *key == [0; 32] || keys[..i].contains(key) {
            return Err(Error::InvalidConfiguration.into());
        }
    }
    if config.collateral_json.is_empty()
        || config.collateral_json.len() > 4 << 20
        || config.qualification.boot_binding_sha384 != config.boot_binding.digest_sha384()?
        || config.qualification.pe_sha384 != config.boot_policy.expected_pe_sha384
        || config.qualification.firmware_mrtd != config.boot_policy.expected_firmware_mrtd
        || config.qualification.module_policy_sha384
            != hash(
                &config
                    .module_policy
                    .encode()
                    .map_err(|_| Error::InvalidConfiguration)?,
            )
        || p.as_policy_sha384 != config.launch_policy_sha384
        || p.resource_path.iter().any(|v| !resource_part(v))
    {
        return Err(Error::InvalidConfiguration.into());
    }
    let encoded = serde_json::to_vec(config).map_err(|_| Error::InvalidConfiguration)?;
    let mut policy = b"QLAD-GCP-ISSUER-POLICY-ADMISSION-v1\0".to_vec();
    frame(&mut policy, &public_key(signer)?);
    frame(&mut policy, &encoded);
    frame(&mut policy, qualification.digest_sha384().as_bytes());
    let admission = hash(&policy);
    let mut identity = b"QLAD-GCP-ISSUER-STORE-v1\0".to_vec();
    frame(&mut identity, admission.as_bytes());
    Ok((hash(&identity), admission))
}

fn resource_part(value: &str) -> bool {
    if value.len() > 128 {
        return false;
    }
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        && bytes.all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

#[cfg(test)]
mod tests;
