//! Explicit schema3 software admission. Operator pins are trusted local inputs,
//! not request-selected expectations. The receipt authenticates a durable issuer
//! decision; it does not establish prepared content, hardware origin, or exec.

use super::*;
use execution_proof_contract::{
    admission::{
        policy_admission_context, AdmissionAuthorizationV1, ADMISSION_PROFILE, ADMISSION_PURPOSE,
        ADMISSION_VERSION,
    },
    policy_receipt::{
        verify_policy_aggregate, AggregateExpectations, LaunchPolicyAggregateV1,
        VerifiedPolicyAggregate, POLICY_AGGREGATE_PROFILE, POLICY_AGGREGATE_PURPOSE,
        POLICY_AGGREGATE_VERSION,
    },
    verify_launch_grant_historical, GrantExpectations, VerifiedLaunchGrant,
};

pub const POLICY_REDEEM_PURPOSE: &str = "qlad.execution-proof.redeem-policy-aggregate.v1";
pub const POLICY_STATUS_PURPOSE: &str = "qlad.execution-proof.status-policy-aggregate.v1";

/// Constructor-only public trust and request scope. Dynamic session/input hashes
/// must also be pinned through the operator API before any aggregate is redeemed.
#[derive(Clone, Serialize)]
pub struct PolicyAdmissionConfig {
    pub kbs_proof_public_key: [u8; 32],
    pub aggregate_audience: String,
    pub aggregate_issuer: String,
    pub aggregate_profile: String,
    pub as_policy_id: String,
    pub as_policy_sha384: String,
    pub as_data_sha384: Option<String>,
    pub kbs_policy_id: String,
    pub kbs_policy_sha384: String,
    pub init_data_sha384: String,
    pub resource_path: [String; 3],
    pub workflow_id: String,
    pub receipt_audience: String,
}

pub struct AdmissionPublication {
    pub signed_authorization_json: Vec<u8>,
    /// Existing is historical retrieval of the same durable decision, not a new
    /// permission or a second receipt publication with a refreshed lease.
    pub publication: store::AdmissionPublicationKind,
}

pub(crate) struct PolicyAdmissionState {
    config: PolicyAdmissionConfig,
    policy_sha384: String,
}

impl SoftwareIssuer {
    pub fn initialize_new_with_policy_admission(
        path: &Path,
        config: IssuerConfig,
        policy: PolicyAdmissionConfig,
        signer: Ed25519KeyPair,
        capacity: usize,
    ) -> Result<Self, Error> {
        Self::initialize_new_with_policy_admission_and_clock(
            path,
            config,
            policy,
            signer,
            capacity,
            Arc::new(SystemClock),
        )
    }
    pub fn initialize_new_with_policy_admission_and_clock(
        path: &Path,
        config: IssuerConfig,
        policy: PolicyAdmissionConfig,
        signer: Ed25519KeyPair,
        capacity: usize,
        clock: Arc<dyn IssuerClock>,
    ) -> Result<Self, Error> {
        let (identity, policy_sha384) = policy_identity(&config, &policy, &signer)?;
        let authority = signer
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| Error::InvalidConfiguration)?;
        let store = store::Store::initialize_new_policy(
            path,
            &identity,
            capacity,
            clock.as_ref(),
            authority,
        )?;
        Ok(Self {
            config,
            signer,
            store,
            clock,
            policy_admission: Some(PolicyAdmissionState {
                config: policy,
                policy_sha384,
            }),
        })
    }
    pub fn open_existing_with_policy_admission(
        path: &Path,
        config: IssuerConfig,
        policy: PolicyAdmissionConfig,
        signer: Ed25519KeyPair,
        capacity: usize,
    ) -> Result<Self, Error> {
        Self::open_existing_with_policy_admission_and_clock(
            path,
            config,
            policy,
            signer,
            capacity,
            Arc::new(SystemClock),
        )
    }
    pub fn open_existing_with_policy_admission_and_clock(
        path: &Path,
        config: IssuerConfig,
        policy: PolicyAdmissionConfig,
        signer: Ed25519KeyPair,
        capacity: usize,
        clock: Arc<dyn IssuerClock>,
    ) -> Result<Self, Error> {
        let (identity, policy_sha384) = policy_identity(&config, &policy, &signer)?;
        let authority = signer
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| Error::InvalidConfiguration)?;
        let store = store::Store::open_existing_policy(path, &identity, capacity, authority)?;
        Ok(Self {
            config,
            signer,
            store,
            clock,
            policy_admission: Some(PolicyAdmissionState {
                config: policy,
                policy_sha384,
            }),
        })
    }

    pub fn admission_policy_sha384(&self) -> Option<&str> {
        self.policy_admission
            .as_ref()
            .map(|state| state.policy_sha384.as_str())
    }

    /// Trusted operator provisioning, deliberately separate from redemption.
    /// Exact retries preserve the committed expectation; changed pins conflict.
    /// This method does not consume the grant or produce an authorization.
    pub fn pin_policy_admission(
        &self,
        grant_id: &str,
        expected: &LaunchPolicyAggregateV1,
        guest_nonce: &str,
    ) -> Result<(), Error> {
        let state = self.policy_state()?;
        let (_, grant) = self.policy_grant(grant_id)?;
        validate_expected(state, expected, &grant)?;
        decode_hex(guest_nonce, 32)?;
        let bytes = serde_json::to_vec(expected).map_err(|_| Error::InvalidRequest)?;
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(Error::InvalidRequest);
        }
        self.store.pin_policy(&store::PolicyPin {
            grant_id: grant_id.to_owned(),
            expected_json: bytes,
            expected_digest: expected.digest_sha384()?,
            guest_nonce: guest_nonce.to_owned(),
            policy_digest: state.policy_sha384.clone(),
        })?;
        Ok(())
    }

    pub fn redeem_policy_aggregate(
        &self,
        grant_id: &str,
        aggregate_json: &[u8],
        recorder_request_json: &[u8],
    ) -> Result<AdmissionPublication, Error> {
        let authorization = self.authenticate_policy_request(
            grant_id,
            aggregate_json,
            recorder_request_json,
            POLICY_REDEEM_PURPOSE,
        )?;
        let outcome =
            self.store
                .redeem_policy(&authorization, &self.signer, self.clock.as_ref())?;
        Ok(AdmissionPublication {
            signed_authorization_json: outcome.bytes,
            publication: outcome.publication,
        })
    }

    /// Read-only historical status; Some contains the original signed receipt.
    /// It never reads the live clock or grants another admission.
    pub fn status_policy_aggregate(
        &self,
        grant_id: &str,
        aggregate_json: &[u8],
        recorder_request_json: &[u8],
    ) -> Result<Option<Vec<u8>>, Error> {
        let authorization = self.authenticate_policy_request(
            grant_id,
            aggregate_json,
            recorder_request_json,
            POLICY_STATUS_PURPOSE,
        )?;
        Ok(self.store.policy_status(&authorization)?)
    }

    fn policy_state(&self) -> Result<&PolicyAdmissionState, Error> {
        self.policy_admission
            .as_ref()
            .ok_or(Error::InvalidConfiguration)
    }

    fn policy_grant(
        &self,
        grant_id: &str,
    ) -> Result<(store::IssuedRecord, VerifiedLaunchGrant), Error> {
        identifier(grant_id)?;
        let issued = self.store.get_issued(grant_id)?;
        let grant = verify_launch_grant_historical(
            &issued.signed_grant_json,
            &GrantExpectations {
                authority_public_key: self.authority_public_key(),
                audience: self.config.audience.clone(),
                authority: self.config.authority.clone(),
                tenant: self.config.tenant.clone(),
                profile_sha384: self.config.profile_sha384.clone(),
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
            return Err(Error::BindingMismatch);
        }
        Ok((issued, grant))
    }

    fn authenticate_policy_request(
        &self,
        grant_id: &str,
        aggregate_json: &[u8],
        wire: &[u8],
        purpose: &str,
    ) -> Result<AdmissionAuthorizationV1, Error> {
        let state = self.policy_state()?;
        let (issued, grant) = self.policy_grant(grant_id)?;
        let pin = self.store.policy_pin(grant_id)?;
        if pin.policy_digest != state.policy_sha384 {
            return Err(Error::PolicyMismatch);
        }
        let expected: LaunchPolicyAggregateV1 =
            serde_json::from_slice(&pin.expected_json).map_err(|_| Error::InvalidRequest)?;
        validate_expected(state, &expected, &grant)?;
        let aggregate = verify_policy_aggregate(
            aggregate_json,
            &grant,
            &AggregateExpectations {
                kbs_proof_public_key: state.config.kbs_proof_public_key,
                expected,
            },
        )?;
        // The verifier above owns the trust selection. These checks make the
        // actual roots explicit at the state-changing issuer boundary as well.
        if aggregate.kbs_proof_key_sha384() != hash(&state.config.kbs_proof_public_key)
            || grant.authority_key_sha384() != hash(self.signer.public_key().as_ref())
            || aggregate.digest_sha384() != pin.expected_digest
        {
            return Err(Error::UntrustedKey);
        }
        let context =
            policy_admission_context(&grant, &aggregate, &pin.guest_nonce, &state.policy_sha384)?;
        self.authenticate_policy_recorder(&issued, &grant, &context, wire, purpose)?;
        Ok(authorization(
            self,
            &grant,
            &aggregate,
            &pin.guest_nonce,
            &state.policy_sha384,
            context,
        ))
    }

    fn authenticate_policy_recorder(
        &self,
        issued: &store::IssuedRecord,
        grant: &VerifiedLaunchGrant,
        context: &str,
        wire: &[u8],
        purpose: &str,
    ) -> Result<(), Error> {
        if wire.len() > MAX_WIRE_BYTES {
            return Err(Error::InvalidRequest);
        }
        let signed: Signed<RecorderRequest> =
            serde_json::from_slice(wire).map_err(|_| Error::InvalidRequest)?;
        let request = &signed.statement;
        if request.version != REQUEST_VERSION
            || request.purpose != purpose
            || request.audience != self.config.audience
            || request.grant_sha384 != grant.grant_digest()
            || request.context_sha384 != context
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

fn authorization(
    issuer: &SoftwareIssuer,
    grant: &VerifiedLaunchGrant,
    aggregate: &VerifiedPolicyAggregate,
    nonce: &str,
    policy: &str,
    context: String,
) -> AdmissionAuthorizationV1 {
    AdmissionAuthorizationV1 {
        version: ADMISSION_VERSION,
        purpose: ADMISSION_PURPOSE.into(),
        audience: issuer
            .policy_admission
            .as_ref()
            .expect("validated policy mode")
            .config
            .receipt_audience
            .clone(),
        issuer: issuer.config.authority.clone(),
        profile: ADMISSION_PROFILE.into(),
        grant_id: grant.grant_id().into(),
        grant_sha384: grant.grant_digest().into(),
        aggregate_sha384: aggregate.digest_sha384().into(),
        aggregate_key_sha384: aggregate.kbs_proof_key_sha384().into(),
        context_sha384: context,
        guest_nonce: nonce.into(),
        admission_policy_sha384: policy.into(),
        validity: *grant.validity(),
        binding: grant.binding().clone(),
    }
}

fn validate_expected(
    state: &PolicyAdmissionState,
    expected: &LaunchPolicyAggregateV1,
    grant: &VerifiedLaunchGrant,
) -> Result<(), Error> {
    expected.signing_bytes()?;
    let policy = &state.config;
    if expected.version != POLICY_AGGREGATE_VERSION
        || expected.purpose != POLICY_AGGREGATE_PURPOSE
        || expected.profile != policy.aggregate_profile
        || expected.audience != policy.aggregate_audience
        || expected.issuer != policy.aggregate_issuer
        || expected.grant_sha384 != grant.grant_digest()
        || expected.authority_key_sha384 != grant.authority_key_sha384()
        || expected.recorder_key_sha384 != grant.binding().channel_key_sha384
        || expected.init_data_sha384 != policy.init_data_sha384
        || expected.as_evaluation.policy_id != policy.as_policy_id
        || expected.as_evaluation.policy_sha384 != policy.as_policy_sha384
        || expected.as_evaluation.data_sha384 != policy.as_data_sha384
        || expected.kbs_evaluation.policy_id != policy.kbs_policy_id
        || expected.kbs_evaluation.policy_sha384 != policy.kbs_policy_sha384
        || expected.request.resource_path != policy.resource_path
        || expected.request.workflow_id != policy.workflow_id
        || hash(&policy.kbs_proof_public_key) == grant.binding().channel_key_sha384
    {
        return Err(Error::PolicyMismatch);
    }
    Ok(())
}

fn policy_identity(
    base: &IssuerConfig,
    policy: &PolicyAdmissionConfig,
    signer: &Ed25519KeyPair,
) -> Result<(String, String), Error> {
    let base_identity = store_identity(base, signer)?;
    for id in [
        &policy.aggregate_audience,
        &policy.aggregate_issuer,
        &policy.aggregate_profile,
        &policy.as_policy_id,
        &policy.kbs_policy_id,
        &policy.workflow_id,
        &policy.receipt_audience,
    ] {
        identifier(id).map_err(|_| Error::InvalidConfiguration)?;
    }
    for hash in [
        &policy.as_policy_sha384,
        &policy.kbs_policy_sha384,
        &policy.init_data_sha384,
    ] {
        decode_hex(hash, 48).map_err(|_| Error::InvalidConfiguration)?;
    }
    if let Some(data) = &policy.as_data_sha384 {
        decode_hex(data, 48).map_err(|_| Error::InvalidConfiguration)?;
    }
    if policy.aggregate_profile != POLICY_AGGREGATE_PROFILE
        || policy.as_policy_sha384 != base.launch_policy_sha384
        || policy.kbs_policy_sha384 != base.kbs_policy_sha384
        || policy.resource_path.iter().any(|part| !resource_part(part))
        || policy.kbs_proof_public_key == [0; 32]
        || [
            base.tenant_public_key,
            base.bootstrap_verifier_public_key,
            base.as_proof_public_key,
            signer
                .public_key()
                .as_ref()
                .try_into()
                .map_err(|_| Error::InvalidConfiguration)?,
        ]
        .contains(&policy.kbs_proof_public_key)
    {
        return Err(Error::InvalidConfiguration);
    }
    let mut bytes = b"QLAD-ISSUER-POLICY-ADMISSION-CONFIG\0".to_vec();
    frame(&mut bytes, ADMISSION_PROFILE.as_bytes());
    frame(&mut bytes, base_identity.as_bytes());
    frame(
        &mut bytes,
        &serde_json::to_vec(policy).map_err(|_| Error::InvalidConfiguration)?,
    );
    let policy_sha384 = hash(&bytes);
    let mut identity = b"QLAD-ISSUER-SCHEMA3-POLICY-ADMISSION\0".to_vec();
    frame(&mut identity, base_identity.as_bytes());
    frame(&mut identity, policy_sha384.as_bytes());
    Ok((hash(&identity), policy_sha384))
}

fn resource_part(value: &str) -> bool {
    if value.len() > 128 {
        return false;
    }
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}
