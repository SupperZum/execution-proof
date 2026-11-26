//! Isolated experimental permissions, never a qualification or production issuer.
//! The authority public key stays the exact C root so empirical qualification
//! applies to the same PE. All experimental windows end before a later, truthful
//! qualification begins; no result from this tool is a qualified execution claim.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use execution_proof_contract::{
    admission::{
        gcp::{
            policy_admission_context_gcp, verify_gcp_admission_request, GcpAdmissionOperation,
            GcpAdmissionRequestV2,
        },
        AdmissionAuthorizationV1, ADMISSION_PROFILE, ADMISSION_PURPOSE, ADMISSION_VERSION,
    },
    bootstrap::{verify_tenant_intent, TenantIntentExpectations},
    gcp_artifact::{verify_artifacts, ArtifactVerificationExpectations, ClosedBootConfigV1},
    gcp_bootstrap::{
        bootstrap_context_sha384, verify_bootstrap_possession, verify_challenge,
        GcpBootstrapBinding, GcpBootstrapChallenge, GCP_BOOTSTRAP_CHALLENGE_PURPOSE,
        GCP_BOOTSTRAP_VERSION,
    },
    gcp_policy_receipt::{
        verify_policy_aggregate, GcpAggregateExpectations, GcpLaunchPolicyAggregateV2,
        VerifiedGcpPolicyAggregate,
    },
    gcp_session::GcpLaunchEvidenceV2,
    gcp_startup::{GcpAttemptPlanV1, PLAN_PURPOSE},
    policy_receipt::ResourcePolicyRequest,
    verify_launch_grant_historical, GrantExpectations, LaunchBinding, LaunchGrant, Signed,
    ValidityWindow, VerifiedLaunchGrant, GRANT_PURPOSE, VERSION,
};
use execution_proof_verifier::{
    gcp_boot_evidence::GcpBootEvidencePolicy,
    gcp_pregrant_protocol::{GcpPregrantRequest, GcpPregrantResponse},
    gcp_tdx_policy::GcpTdxModulePolicyV1,
    gcp_worker_protocol::GcpHardwareStatus,
    worker::{run_gcp_pregrant_worker, TrustedWorker},
};
use kbs_types::TeePubKey;
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub const MAX_REQUEST: usize = 8 << 20;
const MAX_STATE: usize = 12 << 20;
pub const EXPERIMENT_PURPOSE: &str = "onb17.gcp-qualification-experiment.v1";
pub const UNPROVEN: &str = "UNPROVEN_QUALIFICATION_EXPERIMENT";
type Result<T> = std::result::Result<T, Rejected>;
#[derive(Debug)]
pub struct Rejected;
impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("experiment rejected")
    }
}
impl std::error::Error for Rejected {}
fn checked<T, E>(r: std::result::Result<T, E>) -> Result<T> {
    r.map_err(|_| Rejected)
}
fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(Rejected)
    }
}
pub fn hash(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA384, bytes).as_ref())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    checked(serde_json::to_vec(value))
}
fn kbs_data_sha384(request: &ResourcePolicyRequest) -> Result<String> {
    // Match the JSON bytes Trustee supplies to the GCP resource policy.
    let data = serde_json::json!({
        "method": request.method,
        "plugin": request.plugin,
        "resource-path": request.resource_path,
        "workflow-id": request.workflow_id,
        "request_nonce": request.request_nonce,
        "query": {},
    });
    Ok(hash(&encode(&data)?))
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    checked(serde_json::from_slice(bytes))
}
fn now() -> Result<u64> {
    checked(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)).map(|v| v.as_secs())
}
fn random_id() -> Result<String> {
    let mut b = [0; 32];
    checked(SystemRandom::new().fill(&mut b))?;
    require(b != [0; 32])?;
    Ok(hex(&b))
}
fn public(key: &Ed25519KeyPair) -> Result<[u8; 32]> {
    checked(key.public_key().as_ref().try_into())
}
fn signed<T: Serialize>(key: &Ed25519KeyPair, value: T, message: &[u8]) -> Result<Vec<u8>> {
    encode(&Signed {
        statement: value,
        signature: hex(key.sign(message).as_ref()),
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPaths {
    pub config: PathBuf,
    pub core: PathBuf,
    pub manifest: PathBuf,
    pub references: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyScope {
    pub aggregate_issuer: String,
    pub as_policy_id: String,
    pub as_data_sha384: Option<String>,
    pub kbs_policy_id: String,
    pub kbs_policy_sha384: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentConfig {
    pub version: u16,
    pub purpose: String,
    pub retire_before: u64,
    pub window_seconds: u64,
    pub state_path: PathBuf,
    pub artifacts: ArtifactPaths,
    pub artifact_expectations: ArtifactVerificationExpectations,
    pub boot_policy: GcpBootEvidencePolicy,
    pub module_policy: GcpTdxModulePolicyV1,
    pub pregrant_worker_path: PathBuf,
    pub pregrant_worker_sha384: String,
    pub tenant_public_key: [u8; 32],
    pub signed_intent_path: PathBuf,
    pub signed_intent_sha384: String,
    pub policy: PolicyScope,
    pub container_id: String,
    pub execution_audience: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub binding: GcpBootstrapBinding,
    pub evidence: GcpLaunchEvidenceV2,
    pub recorder_public_key: [u8; 32],
    pub possession_signature_hex: String,
    pub keywrap_public_key: TeePubKey,
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Issue {
        submission: Box<Submission>,
    },
    StartupPlan {
        aggregate_json: Vec<u8>,
    },
    Redeem {
        guest_nonce: String,
        recorder_request_json: Vec<u8>,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u16,
    purpose: String,
    identity: String,
    retire_before: u64,
    last_now: u64,
    signed_challenge: Vec<u8>,
    submission: Option<Submission>,
    signed_grant: Option<Vec<u8>>,
    hardware_request_sha384: Option<String>,
    hardware_response: Option<GcpPregrantResponse>,
    aggregate: Option<Vec<u8>>,
    signed_plan: Option<Vec<u8>>,
    guest_nonce: Option<String>,
    redemption_sha384: Option<String>,
    authorization: Option<Vec<u8>>,
}
pub struct Experiment {
    config: ExperimentConfig,
    c: ClosedBootConfigV1,
    key: Ed25519KeyPair,
    authority: [u8; 32],
    intent: execution_proof_contract::bootstrap::TenantIntent,
    intent_sha384: String,
    identity: String,
    admission_policy: String,
    snapshot: String,
    collateral: Vec<u8>,
    worker: TrustedWorker,
}
impl Experiment {
    /// All inputs are trusted operator selections. No key or qualification file
    /// can be selected by a controller request; qualification keys are never read.
    pub fn open(config_path: &Path, signer_path: &Path, collateral_path: &Path) -> Result<Self> {
        let config_bytes = read_operator(config_path, 128 << 10, false)?;
        let config: ExperimentConfig = decode(&config_bytes)?;
        require(
            config.version == 1
                && config.purpose == EXPERIMENT_PURPOSE
                && config.state_path.is_absolute()
                && (1..=300).contains(&config.window_seconds),
        )?;
        let c_bytes = read_operator(&config.artifacts.config, 64 << 10, false)?;
        let d = read_operator(&config.artifacts.core, 64 << 10, false)?;
        let a = read_operator(&config.artifacts.manifest, 32 << 10, false)?;
        let v = read_operator(&config.artifacts.references, 32 << 10, false)?;
        let artifacts = checked(verify_artifacts(
            &c_bytes,
            &d,
            &a,
            &v,
            &config.artifact_expectations,
        ))?;
        let c = artifacts.config().clone();
        let pkcs8 = Zeroizing::new(read_operator(signer_path, 16 << 10, true)?);
        let key = checked(Ed25519KeyPair::from_pkcs8(&pkcs8))?;
        let authority = public(&key)?;
        require(
            authority == c.roots.authority_public_key
                && config.artifact_expectations.build_public_key == c.roots.build_public_key
                && config.artifact_expectations.reference_public_key
                    == c.roots.reference_public_key
                && config.boot_policy.expected_pe_sha384
                    == config.artifact_expectations.pe_authenticode_sha384
                && config.boot_policy.expected_firmware_mrtd
                    == config.artifact_expectations.firmware_mrtd
                && hash(&checked(config.module_policy.encode())?)
                    == config.artifact_expectations.module_policy_sha384
                && config.tenant_public_key != [0; 32]
                && ![
                    authority,
                    c.roots.kbs_proof_public_key,
                    c.roots.qualification_public_key,
                ]
                .contains(&config.tenant_public_key),
        )?;
        checked(config.boot_policy.validate())?;
        checked(config.module_policy.validate())?;
        let intent_bytes = read_operator(&config.signed_intent_path, 32 << 10, false)?;
        require(hash(&intent_bytes) == config.signed_intent_sha384)?;
        let verified = checked(verify_tenant_intent(
            &intent_bytes,
            &TenantIntentExpectations {
                tenant_public_key: config.tenant_public_key,
                audience: c.grant_audience.clone(),
                authority: c.authority.clone(),
                tenant: c.tenant.clone(),
                profile_sha384: checked(config.artifact_expectations.boot_binding.digest_sha384())?,
            },
        ))?;
        let intent = verified.statement().clone();
        require(
            intent.workload_id.starts_with("qexp-")
                && intent.attempt_id.starts_with("qexp-")
                && config.container_id.starts_with("qexp-")
                && config.execution_audience.starts_with("qexp-")
                && intent.container_role == "application-init"
                && intent.launch_policy_sha384 == c.launch_policy_sha384
                && intent.image_policy_sha384 == c.image_policy_sha384
                && intent.validity.expires <= config.retire_before,
        )?;
        let collateral = read_operator(collateral_path, 4 << 20, false)?;
        let worker = checked(TrustedWorker::open(
            &config.pregrant_worker_path,
            &config.pregrant_worker_sha384,
        ))?;
        let identity = hash(&encode(&(
            EXPERIMENT_PURPOSE,
            &config_bytes,
            hash(&collateral),
            authority,
            hash(&c_bytes),
            hash(&d),
            hash(&a),
            hash(&v),
        ))?);
        let admission_policy = hash(&encode(&(
            "onb17.experimental-admission-NOT-QUALIFIED.v1",
            &identity,
        ))?);
        let snapshot = hash(&encode(&(
            "onb17.experimental-execution-snapshot-NOT-QUALIFIED.v1",
            &identity,
        ))?);
        Ok(Self {
            config,
            c,
            key,
            authority,
            intent,
            intent_sha384: verified.digest_sha384().into(),
            identity,
            admission_policy,
            snapshot,
            collateral,
            worker,
        })
    }
    fn clock(&self, state: &mut State) -> Result<u64> {
        let t = now()?;
        require(t >= state.last_now && t < self.config.retire_before)?;
        state.last_now = t;
        Ok(t)
    }
    fn output(&self, result: serde_json::Value, permission: bool) -> serde_json::Value {
        serde_json::json!({"version":1,"purpose":"onb17.gcp-qualification-experiment-response.v1",
            "claim_status":UNPROVEN,"permission_issued_now":permission,
            "retire_before":self.config.retire_before,"producer_qualified":false,"execution_verified":false,
            "admission_policy_sha384":self.admission_policy,"trust_snapshot_sha384":self.snapshot,"result":result})
    }
    pub fn bootstrap_only(&self) -> Result<serde_json::Value> {
        let time = now()?;
        checked(self.intent.validity.check_at(time))?;
        let expires = time
            .checked_add(self.config.window_seconds)
            .ok_or(Rejected)?
            .min(self.intent.validity.expires)
            .min(self.config.retire_before);
        require(time < expires)?;
        let challenge = GcpBootstrapChallenge {
            version: GCP_BOOTSTRAP_VERSION,
            purpose: GCP_BOOTSTRAP_CHALLENGE_PURPOSE.into(),
            audience: self.c.grant_audience.clone(),
            authority: self.c.authority.clone(),
            tenant: self.c.tenant.clone(),
            workload_id: self.intent.workload_id.clone(),
            attempt_id: self.intent.attempt_id.clone(),
            challenge_id: format!("qexp-{}", random_id()?),
            nonce_hex: random_id()?,
            intent_sha384: self.intent_sha384.clone(),
            boot_binding: self.config.artifact_expectations.boot_binding.clone(),
            validity: ValidityWindow {
                not_before: time,
                expires,
            },
        };
        let wire = signed(
            &self.key,
            challenge.clone(),
            &checked(challenge.canonical_bytes())?,
        )?;
        let state = State {
            version: 1,
            purpose: EXPERIMENT_PURPOSE.into(),
            identity: self.identity.clone(),
            retire_before: self.config.retire_before,
            last_now: time,
            signed_challenge: wire.clone(),
            submission: None,
            signed_grant: None,
            hardware_request_sha384: None,
            hardware_response: None,
            aggregate: None,
            signed_plan: None,
            guest_nonce: None,
            redemption_sha384: None,
            authorization: None,
        };
        let mut file = open_state(&self.config.state_path, true)?;
        persist(&mut file, &state)?;
        let parent = self.config.state_path.parent().ok_or(Rejected)?;
        checked(
            checked(
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(parent),
            )?
            .sync_all(),
        )?;
        Ok(self.output(
            serde_json::json!({"status":"challenge","challenge":challenge,
            "signed_challenge_json":wire}),
            false,
        ))
    }
    pub fn request(&self, request: Request) -> Result<serde_json::Value> {
        let mut file = open_state(&self.config.state_path, false)?;
        let mut bytes = Vec::new();
        checked(
            (&mut file)
                .take(MAX_STATE as u64 + 1)
                .read_to_end(&mut bytes),
        )?;
        require(!bytes.is_empty() && bytes.len() <= MAX_STATE)?;
        let mut state: State = decode(&bytes)?;
        require(
            state.version == 1
                && state.purpose == EXPERIMENT_PURPOSE
                && state.identity == self.identity
                && state.retire_before == self.config.retire_before,
        )?;
        let out = match request {
            Request::Issue { submission } => self.issue(&mut state, *submission)?,
            Request::StartupPlan { aggregate_json } => self.plan(&mut state, aggregate_json)?,
            Request::Redeem {
                guest_nonce,
                recorder_request_json,
            } => self.redeem(&mut state, guest_nonce, recorder_request_json)?,
        };
        // A crash can leave a rejected/corrupt state, never a resettable permit.
        // File locking serializes all callers; fsync precedes permission output.
        persist(&mut file, &state)?;
        Ok(out)
    }
    /// Recover already committed public wire after lost stdout. No permission,
    /// nonce, plan, validity window or one-use transition is generated here.
    pub fn status(&self) -> Result<serde_json::Value> {
        let mut file = open_state(&self.config.state_path, false)?;
        let mut data = Vec::new();
        checked(
            (&mut file)
                .take(MAX_STATE as u64 + 1)
                .read_to_end(&mut data),
        )?;
        require(data.len() <= MAX_STATE)?;
        let state: State = decode(&data)?;
        require(
            state.identity == self.identity
                && state.version == 1
                && state.purpose == EXPERIMENT_PURPOSE,
        )?;
        Ok(self.output(serde_json::json!({"status":"historical_status","signed_challenge_json":state.signed_challenge,
            "signed_grant_json":state.signed_grant,"signed_plan_json":state.signed_plan,
            "signed_authorization_json":state.authorization,"hardware_request_sha384":state.hardware_request_sha384}),false))
    }
    fn challenge(&self, state: &State, time: u64) -> Result<GcpBootstrapChallenge> {
        let signed: Signed<GcpBootstrapChallenge> = decode(&state.signed_challenge)?;
        let c = &signed.statement;
        require(
            c.authority == self.c.authority
                && c.tenant == self.c.tenant
                && c.audience == self.c.grant_audience
                && c.workload_id == self.intent.workload_id
                && c.attempt_id == self.intent.attempt_id
                && c.intent_sha384 == self.intent_sha384
                && c.boot_binding == self.config.artifact_expectations.boot_binding
                && c.validity.not_before >= self.intent.validity.not_before
                && c.validity.expires <= self.intent.validity.expires
                && c.validity.expires <= self.config.retire_before
                && c.validity.expires.saturating_sub(c.validity.not_before)
                    <= self.config.window_seconds,
        )?;
        checked(verify_challenge(
            &state.signed_challenge,
            &self.authority,
            c,
            time,
        ))
    }
    fn issue(&self, state: &mut State, submission: Submission) -> Result<serde_json::Value> {
        require(state.signed_grant.is_none() && state.submission.is_none())?;
        let t = self.clock(state)?;
        let challenge = self.challenge(state, t)?;
        let wrap = keywrap_digest(&submission.keywrap_public_key)?;
        require(
            wrap == submission.binding.keywrap_key_sha384
                && ![
                    self.authority,
                    self.config.tenant_public_key,
                    self.c.roots.kbs_proof_public_key,
                    self.c.roots.qualification_public_key,
                ]
                .contains(&submission.recorder_public_key),
        )?;
        checked(verify_bootstrap_possession(
            &challenge,
            &submission.binding,
            &submission.evidence,
            &submission.recorder_public_key,
            &submission.possession_signature_hex,
        ))?;
        let request = GcpPregrantRequest {
            version: 3,
            purpose: "qlad.execution-proof.gcp-pregrant-hardware-request.v3".into(),
            expected_challenge: challenge.clone(),
            authority_public_key: self.authority,
            signed_challenge_json: state.signed_challenge.clone(),
            binding: submission.binding.clone(),
            evidence: submission.evidence.clone(),
            boot_policy: self.config.boot_policy.clone(),
            module_policy: self.config.module_policy.clone(),
            collateral_json: self.collateral.clone(),
        };
        checked(request.verify_authority(t))?;
        let response = checked(run_gcp_pregrant_worker(&request, &self.worker))?;
        checked(response.check_request(&request))?;
        require(response.status == GcpHardwareStatus::Checked)?;
        let after = self.clock(state)?;
        checked(challenge.validity.check_at(after))?;
        let grant = LaunchGrant {
            version: VERSION,
            purpose: GRANT_PURPOSE.into(),
            audience: self.c.grant_audience.clone(),
            proof_required: true,
            grant_id: format!("qexp-{}", random_id()?),
            validity: challenge.validity,
            binding: LaunchBinding {
                authority: self.c.authority.clone(),
                tenant: self.c.tenant.clone(),
                workload_id: self.intent.workload_id.clone(),
                container_role: self.intent.container_role.clone(),
                attempt_id: self.intent.attempt_id.clone(),
                boot_id: submission.binding.boot_id.clone(),
                channel_key_sha384: hash(&submission.recorder_public_key),
                bootstrap_context_sha384: checked(bootstrap_context_sha384(
                    &challenge,
                    &submission.binding,
                    &submission.evidence,
                ))?,
                selected_manifest_sha256: self.intent.selected_manifest_sha256.clone(),
                effective_launch_sha384: self.intent.effective_launch_sha384.clone(),
                profile_sha384: self.intent.profile_sha384.clone(),
                launch_policy_sha384: self.intent.launch_policy_sha384.clone(),
                image_policy_sha384: self.intent.image_policy_sha384.clone(),
                challenge_sha384: checked(challenge.digest_sha384())?,
            },
        };
        let wire = signed(&self.key, grant.clone(), &checked(grant.signing_bytes())?)?;
        state.hardware_request_sha384 = Some(checked(request.sha384())?);
        state.hardware_response = Some(response);
        state.signed_grant = Some(wire.clone());
        state.submission = Some(submission);
        Ok(self.output(
            serde_json::json!({"status":"grant","signed_grant_json":wire,"grant":grant}),
            true,
        ))
    }
    fn grant(&self, state: &State) -> Result<VerifiedLaunchGrant> {
        let wire = state.signed_grant.as_ref().ok_or(Rejected)?;
        let grant = checked(verify_launch_grant_historical(
            wire,
            &GrantExpectations {
                authority_public_key: self.authority,
                audience: self.c.grant_audience.clone(),
                authority: self.c.authority.clone(),
                tenant: self.c.tenant.clone(),
                profile_sha384: self.intent.profile_sha384.clone(),
                launch_policy_sha384: self.c.launch_policy_sha384.clone(),
                image_policy_sha384: self.c.image_policy_sha384.clone(),
            },
        ))?;
        let s: Signed<GcpBootstrapChallenge> = decode(&state.signed_challenge)?;
        // Authenticate historical saved challenge at its original lower bound;
        // fresh operations check the real current clock separately.
        let challenge = self.challenge(state, s.statement.validity.not_before)?;
        let submission = state.submission.as_ref().ok_or(Rejected)?;
        checked(verify_bootstrap_possession(
            &challenge,
            &submission.binding,
            &submission.evidence,
            &submission.recorder_public_key,
            &submission.possession_signature_hex,
        ))?;
        require(
            grant.grant_id().starts_with("qexp-")
                && *grant.validity() == challenge.validity
                && grant.binding().workload_id == self.intent.workload_id
                && grant.binding().attempt_id == self.intent.attempt_id
                && grant.binding().container_role == self.intent.container_role
                && grant.binding().selected_manifest_sha256 == self.intent.selected_manifest_sha256
                && grant.binding().effective_launch_sha384 == self.intent.effective_launch_sha384
                && grant.binding().boot_id == submission.binding.boot_id
                && grant.binding().channel_key_sha384 == hash(&submission.recorder_public_key)
                && grant.binding().challenge_sha384 == checked(challenge.digest_sha384())?
                && grant.binding().bootstrap_context_sha384
                    == checked(bootstrap_context_sha384(
                        &challenge,
                        &submission.binding,
                        &submission.evidence,
                    ))?,
        )?;
        Ok(grant)
    }
    fn aggregate(
        &self,
        wire: &[u8],
        grant: &VerifiedLaunchGrant,
    ) -> Result<VerifiedGcpPolicyAggregate> {
        require(!wire.is_empty() && wire.len() <= 32 << 10)?;
        let a: Signed<GcpLaunchPolicyAggregateV2> = decode(wire)?;
        let e = &a.statement;
        let p = &self.config.policy;
        require(
            e.audience == self.c.aggregate_audience
                && e.issuer == p.aggregate_issuer
                && e.as_evaluation.policy_id == p.as_policy_id
                && e.as_evaluation.policy_sha384 == self.c.launch_policy_sha384
                && e.as_evaluation.data_sha384 == p.as_data_sha384
                && e.kbs_evaluation.policy_id == p.kbs_policy_id
                && e.kbs_evaluation.policy_sha384 == p.kbs_policy_sha384
                && e.request.resource_path == self.c.resource_path
                && e.request.workflow_id == self.c.workflow_id,
        )?;
        let verified = checked(verify_policy_aggregate(
            wire,
            grant,
            &GcpAggregateExpectations {
                kbs_proof_public_key: self.c.roots.kbs_proof_public_key,
                boot_binding: self.config.artifact_expectations.boot_binding.clone(),
                expected: a.statement,
            },
        ))?;
        let statement = verified.statement();
        let expected_data = kbs_data_sha384(&statement.request)?;
        require(statement.kbs_evaluation.data_sha384.as_deref() == Some(expected_data.as_str()))?;
        Ok(verified)
    }
    fn plan(&self, state: &mut State, wire: Vec<u8>) -> Result<serde_json::Value> {
        require(state.signed_plan.is_none() && state.aggregate.is_none())?;
        let t = self.clock(state)?;
        let grant = self.grant(state)?;
        checked(grant.validity().check_at(t))?;
        let aggregate = self.aggregate(&wire, &grant)?;
        let plan = GcpAttemptPlanV1 {
            version: 1,
            purpose: PLAN_PURPOSE.into(),
            authority: self.c.authority.clone(),
            boot_binding: self.config.artifact_expectations.boot_binding.clone(),
            grant_sha384: grant.grant_digest().into(),
            aggregate_sha384: aggregate.digest_sha384().into(),
            admission_policy_sha384: self.admission_policy.clone(),
            container_id: self.config.container_id.clone(),
            effective_spec_sha384: self.intent.effective_launch_sha384.clone(),
            trust_snapshot_sha384: self.snapshot.clone(),
            execution_audience: self.config.execution_audience.clone(),
            execution_nonce_hex: random_id()?,
        };
        let signed_plan = signed(&self.key, plan.clone(), &checked(plan.signing_bytes())?)?;
        checked(grant.validity().check_at(self.clock(state)?))?;
        state.aggregate = Some(wire);
        state.signed_plan = Some(signed_plan.clone());
        Ok(self.output(serde_json::json!({"status":"startup_plan","signed_plan_json":signed_plan,"startup_plan":plan}),true))
    }
    fn redeem(
        &self,
        state: &mut State,
        guest_nonce: String,
        request: Vec<u8>,
    ) -> Result<serde_json::Value> {
        require(!request.is_empty() && request.len() <= 32 << 10 && state.signed_plan.is_some())?;
        let grant = self.grant(state)?;
        let aggregate = self.aggregate(state.aggregate.as_ref().ok_or(Rejected)?, &grant)?;
        let expected = checked(GcpAdmissionRequestV2::new(
            &grant,
            &aggregate,
            &guest_nonce,
            &self.admission_policy,
            &self.c.grant_audience,
            GcpAdmissionOperation::Redeem,
        ))?;
        let recorder = state
            .submission
            .as_ref()
            .ok_or(Rejected)?
            .recorder_public_key;
        checked(verify_gcp_admission_request(
            &request, &recorder, &expected, &grant,
        ))?;
        let request_hash = hash(&request);
        if let Some(wire) = &state.authorization {
            require(
                state.redemption_sha384.as_ref() == Some(&request_hash)
                    && state.guest_nonce.as_ref() == Some(&guest_nonce),
            )?;
            return Ok(self.output(serde_json::json!({"status":"historical_admission","signed_authorization_json":wire}),false));
        }
        checked(grant.validity().check_at(self.clock(state)?))?;
        let admission = AdmissionAuthorizationV1 {
            version: ADMISSION_VERSION,
            purpose: ADMISSION_PURPOSE.into(),
            audience: self.c.admission_receipt_audience.clone(),
            issuer: self.c.authority.clone(),
            profile: ADMISSION_PROFILE.into(),
            grant_id: grant.grant_id().into(),
            grant_sha384: grant.grant_digest().into(),
            aggregate_sha384: aggregate.digest_sha384().into(),
            aggregate_key_sha384: aggregate.kbs_proof_key_sha384().into(),
            context_sha384: checked(policy_admission_context_gcp(
                &grant,
                &aggregate,
                &guest_nonce,
                &self.admission_policy,
            ))?,
            guest_nonce: guest_nonce.clone(),
            admission_policy_sha384: self.admission_policy.clone(),
            validity: *grant.validity(),
            binding: grant.binding().clone(),
        };
        let wire = signed(
            &self.key,
            admission.clone(),
            &checked(admission.signing_bytes())?,
        )?;
        checked(grant.validity().check_at(self.clock(state)?))?;
        state.guest_nonce = Some(guest_nonce);
        state.redemption_sha384 = Some(request_hash);
        state.authorization = Some(wire.clone());
        Ok(self.output(
            serde_json::json!({"status":"admission","signed_authorization_json":wire}),
            true,
        ))
    }
}
fn keywrap_digest(key: &TeePubKey) -> Result<String> {
    match key {
        TeePubKey::RSA { alg, k_mod, k_exp } if alg == "RSA-OAEP-256" && k_exp == "AQAB" => {
            let modulus = checked(URL_SAFE_NO_PAD.decode(k_mod))?;
            require(
                modulus.len() == 256
                    && modulus[0] & 0x80 != 0
                    && modulus[255] & 1 != 0
                    && URL_SAFE_NO_PAD.encode(&modulus) == *k_mod,
            )?;
        }
        _ => return Err(Rejected),
    }
    Ok(hash(&checked(serde_json_canonicalizer::to_vec(key))?))
}
pub fn read_operator(path: &Path, limit: usize, private: bool) -> Result<Vec<u8>> {
    let mut file = checked(
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path),
    )?;
    let m = checked(file.metadata())?;
    let uid = unsafe { libc::geteuid() };
    require(
        m.is_file()
            && m.nlink() == 1
            && m.len() > 0
            && m.len() <= limit as u64
            && (m.uid() == uid || (!private && m.uid() == 0))
            && m.mode() & 0o022 == 0
            && (!private || m.mode() & 0o077 == 0),
    )?;
    let mut bytes = Zeroizing::new(Vec::new());
    checked((&mut file).take(limit as u64 + 1).read_to_end(&mut bytes))?;
    require(!bytes.is_empty() && bytes.len() <= limit)?;
    Ok(std::mem::take(&mut *bytes))
}
fn open_state(path: &Path, create: bool) -> Result<File> {
    let parent = path.parent().ok_or(Rejected)?;
    let m = checked(std::fs::symlink_metadata(parent))?;
    require(
        m.is_dir()
            && !m.file_type().is_symlink()
            && m.uid() == unsafe { libc::geteuid() }
            && m.permissions().mode() & 0o077 == 0,
    )?;
    let file = checked(
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(create)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path),
    )?;
    let m = checked(file.metadata())?;
    require(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o777 == 0o600
            && m.len() <= MAX_STATE as u64,
    )?;
    require(
        unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&file),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } == 0,
    )?;
    Ok(file)
}
fn persist(file: &mut File, state: &State) -> Result<()> {
    let bytes = encode(state)?;
    require(bytes.len() <= MAX_STATE)?;
    checked(file.seek(SeekFrom::Start(0)))?;
    checked(file.set_len(0))?;
    checked(file.write_all(&bytes))?;
    checked(file.sync_all())
}

#[cfg(test)]
mod tests;
