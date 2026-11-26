//! Signed intent, bootstrap PoP and durable admission for the software profile.
//! The default-off GCP module adds a separately qualified hardware bootstrap;
//! neither profile produces protected execution evidence.

mod clock;
#[cfg(feature = "gcp")]
pub mod gcp;
#[cfg(feature = "gcp")]
pub mod gcp_operator;
mod policy_admission;
mod store;

pub use clock::{ClockError, IssuerClock, SystemClock};
pub use policy_admission::{
    AdmissionPublication, PolicyAdmissionConfig, POLICY_REDEEM_PURPOSE, POLICY_STATUS_PURPOSE,
};
pub use store::AdmissionPublicationKind;
pub use store::{GrantPublication, Redemption, RedemptionStatus, StoreError};

use execution_proof_contract::bootstrap::{
    verify_bootstrap_statements, verify_tenant_intent, BootstrapChallenge, BootstrapExpectations,
    TenantIntentExpectations, VerifiedTenantIntent, BOOTSTRAP_VERSION, CHALLENGE_PURPOSE,
};
use execution_proof_contract::{
    LaunchBinding, LaunchGrant, Signed, VerifiedStatements, GRANT_PURPOSE, VERSION,
};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
    signature::{self, Ed25519KeyPair, KeyPair},
};
use serde::{Deserialize, Serialize};
use std::{fmt, path::Path, sync::Arc};

pub const REQUEST_VERSION: u16 = 1;
pub const REDEEM_PURPOSE: &str = "qlad.execution-proof.redeem.v1";
pub const STATUS_PURPOSE: &str = "qlad.execution-proof.status.v1";
const MAX_WIRE_BYTES: usize = 16 * 1024;
pub const MAX_AUTHORIZATION_TTL_SECS: u64 = 3600;

/// Operator-owned configuration, never selected by an unverified request.
/// Keys are public. The authority signing key is held separately in memory.
#[derive(Clone, Serialize)]
pub struct IssuerConfig {
    /// Bounded software-profile authorization window, clipped to tenant intent.
    pub authorization_ttl_secs: u64,
    pub authority: String,
    pub tenant: String,
    pub audience: String,
    pub tenant_public_key: [u8; 32],
    pub bootstrap_verifier_public_key: [u8; 32],
    pub as_proof_public_key: [u8; 32],
    pub bootstrap_verifier_issuer: String,
    pub as_issuer: String,
    pub profile_sha384: String,
    pub launch_policy_sha384: String,
    pub image_policy_sha384: String,
    pub boot_profile_sha384: String,
    pub producer_profile_sha384: String,
    pub bootstrap_policy_sha384: String,
    pub bootstrap_input_sha384: String,
    pub bootstrap_rvps_sha384: String,
    pub appraisal_policy_id: String,
    pub appraisal_policy_sha384: String,
    pub appraisal_acceptance_policy_sha384: String,
    pub appraisal_rvps_sha384: String,
    pub kbs_policy_sha384: String,
}

/// Publication metadata is not a new execution/release permission.
/// Existing bytes are historical retrieval and retain their signed old window.
#[derive(Debug)]
pub struct IssuedGrant {
    pub signed_grant_json: Vec<u8>,
    pub publication: GrantPublication,
}

/// Recorder authentication bound to one operation and its grant/context commitments.
/// Possession proves a signature, not an authenticated network channel.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecorderRequest {
    pub version: u16,
    pub purpose: String,
    pub audience: String,
    pub grant_sha384: String,
    pub context_sha384: String,
}

impl RecorderRequest {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        identifier(&self.purpose)?;
        identifier(&self.audience)?;
        decode_hex(&self.grant_sha384, 48)?;
        decode_hex(&self.context_sha384, 48)?;
        let mut bytes = b"QLAD-ISSUER-RECORDER-REQUEST\0".to_vec();
        bytes.extend_from_slice(&self.version.to_be_bytes());
        for field in [
            &self.purpose,
            &self.audience,
            &self.grant_sha384,
            &self.context_sha384,
        ] {
            frame(&mut bytes, field.as_bytes());
        }
        Ok(bytes)
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidConfiguration,
    InvalidRequest,
    UntrustedKey,
    PolicyMismatch,
    BindingMismatch,
    InvalidSignature,
    EntropyUnavailable,
    Contract(execution_proof_contract::Error),
    Store(StoreError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print submitted statements, signatures or persisted row contents.
        f.write_str(match self {
            Self::InvalidConfiguration => "issuer configuration rejected",
            Self::InvalidRequest => "issuer request rejected",
            Self::UntrustedKey => "issuer trust root mismatch",
            Self::PolicyMismatch => "issuer policy mismatch",
            Self::BindingMismatch => "issuer binding mismatch",
            Self::InvalidSignature => "issuer recorder signature rejected",
            Self::EntropyUnavailable => "issuer entropy unavailable",
            Self::Contract(_) => "issuer statement verification rejected",
            Self::Store(_) => "issuer admission store rejected request",
        })
    }
}
impl std::error::Error for Error {}
impl From<execution_proof_contract::Error> for Error {
    fn from(error: execution_proof_contract::Error) -> Self {
        Self::Contract(error)
    }
}
impl From<StoreError> for Error {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// Signed grant issuance and SQLite admission for the software profile.
/// It does not verify TEE evidence, produce AS/KBS appraisals, prepare images or
/// authorize the production Kata proof path. The clock governs authorization
/// acceptance only, not the physical time or deadline of a later kernel exec.
pub struct SoftwareIssuer {
    config: IssuerConfig,
    signer: Ed25519KeyPair,
    store: store::Store,
    clock: Arc<dyn IssuerClock>,
    policy_admission: Option<policy_admission::PolicyAdmissionState>,
}

impl SoftwareIssuer {
    pub fn initialize_new(
        path: &Path,
        config: IssuerConfig,
        signer: Ed25519KeyPair,
        capacity: usize,
    ) -> Result<Self, Error> {
        Self::initialize_new_with_clock(path, config, signer, capacity, Arc::new(SystemClock))
    }

    pub fn initialize_new_with_clock(
        path: &Path,
        config: IssuerConfig,
        signer: Ed25519KeyPair,
        capacity: usize,
        clock: Arc<dyn IssuerClock>,
    ) -> Result<Self, Error> {
        let identity = store_identity(&config, &signer)?;
        let store = store::Store::initialize_new(path, &identity, capacity, clock.as_ref())?;
        Ok(Self {
            config,
            signer,
            store,
            clock,
            policy_admission: None,
        })
    }

    pub fn open_existing(
        path: &Path,
        config: IssuerConfig,
        signer: Ed25519KeyPair,
        capacity: usize,
    ) -> Result<Self, Error> {
        Self::open_existing_with_clock(path, config, signer, capacity, Arc::new(SystemClock))
    }

    pub fn open_existing_with_clock(
        path: &Path,
        config: IssuerConfig,
        signer: Ed25519KeyPair,
        capacity: usize,
        clock: Arc<dyn IssuerClock>,
    ) -> Result<Self, Error> {
        let identity = store_identity(&config, &signer)?;
        let store = store::Store::open_existing(path, &identity, capacity)?;
        Ok(Self {
            config,
            signer,
            store,
            clock,
            policy_admission: None,
        })
    }

    pub fn authority_public_key(&self) -> [u8; 32] {
        self.signer
            .public_key()
            .as_ref()
            .try_into()
            .expect("Ed25519 public key has 32 bytes")
    }

    pub fn begin(&self, signed_intent: &[u8]) -> Result<Signed<BootstrapChallenge>, Error> {
        let intent = self.verify_intent(signed_intent)?;
        let statement = intent.statement();
        let challenge = BootstrapChallenge {
            // Store stamps the final window under its write transaction/clock.
            validity: statement.validity,
            version: BOOTSTRAP_VERSION,
            purpose: CHALLENGE_PURPOSE.into(),
            audience: self.config.audience.clone(),
            authority: self.config.authority.clone(),
            tenant: self.config.tenant.clone(),
            workload_id: statement.workload_id.clone(),
            attempt_id: statement.attempt_id.clone(),
            challenge_id: random_id()?,
            nonce_hex: random_id()?,
            intent_sha384: intent.digest_sha384().into(),
            boot_profile_sha384: self.config.boot_profile_sha384.clone(),
            producer_profile_sha384: self.config.producer_profile_sha384.clone(),
        };
        let reservation = self.store.reserve(
            &store::ChallengeRecord {
                challenge,
                grant_id: format!("grant-{}", random_id()?),
                signed_intent_json: signed_intent.to_vec(),
                intent_sha384: intent.digest_sha384().into(),
            },
            self.clock.as_ref(),
            self.config.authorization_ttl_secs,
        )?;
        let signature = self.signer.sign(&reservation.challenge.signing_bytes()?);
        Ok(Signed {
            statement: reservation.challenge,
            signature: hex(signature.as_ref()),
        })
    }

    pub fn issue(
        &self,
        challenge_id: &str,
        appraisal_json: &[u8],
        possession_json: &[u8],
    ) -> Result<IssuedGrant, Error> {
        identifier(challenge_id)?;
        let reservation = self.store.challenge(challenge_id)?;
        let intent = self.verify_intent(&reservation.signed_intent_json)?;
        if intent.digest_sha384() != reservation.intent_sha384 {
            return Err(Error::BindingMismatch);
        }
        let boot = verify_bootstrap_statements(
            appraisal_json,
            possession_json,
            &BootstrapExpectations {
                challenge: reservation.challenge.clone(),
                verifier_public_key: self.config.bootstrap_verifier_public_key,
                verifier_issuer: self.config.bootstrap_verifier_issuer.clone(),
                policy_sha384: self.config.bootstrap_policy_sha384.clone(),
                input_sha384: self.config.bootstrap_input_sha384.clone(),
                rvps_sha384: self.config.bootstrap_rvps_sha384.clone(),
            },
        )?;
        let t = intent.statement();
        let mut launch_challenge = b"QLAD-LAUNCH-CHALLENGE\0".to_vec();
        for value in [
            reservation.challenge.nonce_hex.as_str(),
            reservation.grant_id.as_str(),
            intent.digest_sha384(),
        ] {
            frame(&mut launch_challenge, value.as_bytes());
        }
        let grant = LaunchGrant {
            // Reusing the committed challenge window makes retries byte-stable.
            validity: reservation.challenge.validity,
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
                boot_id: boot.boot_id().into(),
                channel_key_sha384: boot.channel_key_sha384().into(),
                bootstrap_context_sha384: boot.context_digest().into(),
                selected_manifest_sha256: t.selected_manifest_sha256.clone(),
                effective_launch_sha384: t.effective_launch_sha384.clone(),
                profile_sha384: t.profile_sha384.clone(),
                launch_policy_sha384: t.launch_policy_sha384.clone(),
                image_policy_sha384: t.image_policy_sha384.clone(),
                challenge_sha384: hash(&launch_challenge),
            },
        };
        let signature = self.signer.sign(&grant.signing_bytes()?);
        let grant_digest = grant.digest_sha384()?;
        let bytes = serde_json::to_vec(&Signed {
            statement: grant,
            signature: hex(signature.as_ref()),
        })
        .map_err(|_| Error::InvalidRequest)?;
        let issued = self.store.issue(
            challenge_id,
            boot.challenge_digest(),
            boot.context_digest(),
            boot.recorder_public_key_hex(),
            &bytes,
            &grant_digest,
            self.clock.as_ref(),
        )?;
        Ok(IssuedGrant {
            signed_grant_json: issued.record.signed_grant_json,
            publication: issued.publication,
        })
    }

    /// Early L/A software-lab API; never a fallback for a policy-admission store.
    pub fn redeem(
        &self,
        statements: &VerifiedStatements,
        recorder_request_json: &[u8],
    ) -> Result<Redemption, Error> {
        if self.policy_admission.is_some() {
            return Err(Error::PolicyMismatch);
        }
        self.authenticate_recorder(statements, recorder_request_json, REDEEM_PURPOSE)?;
        Ok(self.store.redeem(statements, self.clock.as_ref())?)
    }

    /// Early L/A software-lab API; never a fallback for a policy-admission store.
    pub fn status(
        &self,
        statements: &VerifiedStatements,
        recorder_request_json: &[u8],
    ) -> Result<RedemptionStatus, Error> {
        if self.policy_admission.is_some() {
            return Err(Error::PolicyMismatch);
        }
        self.authenticate_recorder(statements, recorder_request_json, STATUS_PURPOSE)?;
        Ok(self
            .store
            .status(statements.grant_id(), statements.context_digest())?)
    }

    fn verify_intent(&self, bytes: &[u8]) -> Result<VerifiedTenantIntent, Error> {
        let intent = verify_tenant_intent(
            bytes,
            &TenantIntentExpectations {
                tenant_public_key: self.config.tenant_public_key,
                audience: self.config.audience.clone(),
                authority: self.config.authority.clone(),
                tenant: self.config.tenant.clone(),
                profile_sha384: self.config.profile_sha384.clone(),
            },
        )?;
        let t = intent.statement();
        if t.launch_policy_sha384 != self.config.launch_policy_sha384
            || t.image_policy_sha384 != self.config.image_policy_sha384
            || t.container_role != "application-init"
        {
            return Err(Error::PolicyMismatch);
        }
        Ok(intent)
    }

    fn authenticate_recorder(
        &self,
        statements: &VerifiedStatements,
        wire: &[u8],
        purpose: &str,
    ) -> Result<(), Error> {
        if statements.authority_key_sha384() != hash(self.signer.public_key().as_ref())
            || statements.as_proof_key_sha384() != hash(&self.config.as_proof_public_key)
        {
            return Err(Error::UntrustedKey);
        }
        let binding = statements.binding();
        let e = statements.evaluation();
        if binding.authority != self.config.authority
            || binding.tenant != self.config.tenant
            || statements.appraisal_issuer() != self.config.as_issuer
            || binding.profile_sha384 != self.config.profile_sha384
            || binding.launch_policy_sha384 != self.config.launch_policy_sha384
            || binding.image_policy_sha384 != self.config.image_policy_sha384
            || e.policy_id != self.config.appraisal_policy_id
            || e.policy_sha384 != self.config.appraisal_policy_sha384
            || e.acceptance_policy_sha384 != self.config.appraisal_acceptance_policy_sha384
            || e.rvps_sha384 != self.config.appraisal_rvps_sha384
            || e.kbs.policy_sha384 != self.config.kbs_policy_sha384
        {
            return Err(Error::PolicyMismatch);
        }
        let issued = self.store.get_issued(statements.grant_id())?;
        if issued.grant_digest != statements.grant_digest()
            || issued.bootstrap_context_digest != binding.bootstrap_context_sha384
            || hash(&decode_hex(&issued.recorder_public_key_hex, 32)?) != binding.channel_key_sha384
        {
            return Err(Error::BindingMismatch);
        }
        if wire.len() > MAX_WIRE_BYTES {
            return Err(Error::InvalidRequest);
        }
        let signed: Signed<RecorderRequest> =
            serde_json::from_slice(wire).map_err(|_| Error::InvalidRequest)?;
        let request = &signed.statement;
        if request.version != REQUEST_VERSION
            || request.purpose != purpose
            || request.audience != self.config.audience
            || request.grant_sha384 != statements.grant_digest()
            || request.context_sha384 != statements.context_digest()
        {
            return Err(Error::BindingMismatch);
        }
        signature::UnparsedPublicKey::new(
            &signature::ED25519,
            decode_hex(&issued.recorder_public_key_hex, 32)?,
        )
        .verify(
            &request.signing_bytes()?,
            &decode_hex(&signed.signature, 64)?,
        )
        .map_err(|_| Error::InvalidSignature)
    }
}

fn store_identity(config: &IssuerConfig, signer: &Ed25519KeyPair) -> Result<String, Error> {
    if !(1..=MAX_AUTHORIZATION_TTL_SECS).contains(&config.authorization_ttl_secs) {
        return Err(Error::InvalidConfiguration);
    }
    for id in [
        &config.authority,
        &config.tenant,
        &config.audience,
        &config.bootstrap_verifier_issuer,
        &config.as_issuer,
        &config.appraisal_policy_id,
    ] {
        identifier(id).map_err(|_| Error::InvalidConfiguration)?;
    }
    for value in [
        &config.profile_sha384,
        &config.launch_policy_sha384,
        &config.image_policy_sha384,
        &config.boot_profile_sha384,
        &config.producer_profile_sha384,
        &config.bootstrap_policy_sha384,
        &config.bootstrap_input_sha384,
        &config.bootstrap_rvps_sha384,
        &config.appraisal_policy_sha384,
        &config.appraisal_acceptance_policy_sha384,
        &config.appraisal_rvps_sha384,
        &config.kbs_policy_sha384,
    ] {
        decode_hex(value, 48).map_err(|_| Error::InvalidConfiguration)?;
    }
    let authority: [u8; 32] = signer
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_| Error::InvalidConfiguration)?;
    let keys = [
        authority,
        config.tenant_public_key,
        config.bootstrap_verifier_public_key,
        config.as_proof_public_key,
    ];
    for (i, key) in keys.iter().enumerate() {
        if key == &[0; 32] || keys[..i].contains(key) {
            return Err(Error::InvalidConfiguration);
        }
    }
    let mut identity = b"QLAD-SOFTWARE-ISSUER-STORE\0".to_vec();
    identity.extend_from_slice(&VERSION.to_be_bytes());
    frame(&mut identity, &authority);
    frame(
        &mut identity,
        &serde_json::to_vec(config).map_err(|_| Error::InvalidConfiguration)?,
    );
    Ok(hash(&identity))
}

fn identifier(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
    {
        return Err(Error::InvalidRequest);
    }
    Ok(())
}
fn frame(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}
fn hash(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA384, bytes).as_ref())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn decode_hex(value: &str, len: usize) -> Result<Vec<u8>, Error> {
    if value.len() != len * 2
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error::InvalidRequest);
    }
    fn nibble(c: u8) -> u8 {
        if c <= b'9' {
            c - b'0'
        } else {
            c - b'a' + 10
        }
    }
    Ok(value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect())
}
fn random_id() -> Result<String, Error> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::EntropyUnavailable)?;
    Ok(hex(&bytes))
}
