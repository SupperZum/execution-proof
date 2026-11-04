//! Memory-only client for the opt-in launch policy protocol.
//! Transport success never establishes attestation or execution acceptance.

use base64::{engine::general_purpose::STANDARD, Engine};
use execution_proof_contract::{
    credential::{
        verify_credential_delivery, DeliveryExpectations, VerifiedCredentialDelivery,
        MAX_CREDENTIAL_JWE_BYTES,
    },
    policy_receipt::{
        verify_policy_aggregate, AggregateExpectations, ResourcePolicyRequest,
        VerifiedPolicyAggregate,
    },
    session::{operation_signing_bytes, recorder_session_signing_bytes, SessionOperation},
    verify_launch_grant, GrantExpectations, VerifiedLaunchGrant,
};
use kbs_types::TeePubKey;
use ring::{
    digest,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt;

pub const MAX_RESPONSE_BYTES: usize = 32 * 1024;
pub const MAX_RUNTIME_BYTES: usize = 16 * 1024;
pub const MAX_EVIDENCE_BYTES: usize = 1024 * 1024;
pub const MAX_CREDENTIAL_RESPONSE_BYTES: usize = 256 * 1024;

#[cfg(feature = "https")]
pub mod https;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientError {
    Contract(execution_proof_contract::Error),
    TooLarge,
    Malformed,
    InvalidField,
    BindingMismatch,
    Conflict,
    NotReady,
    InvalidOrigin,
    Transport,
    HttpStatus,
}
impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "launch client rejected: {self:?}")
    }
}
impl std::error::Error for ClientError {}
impl From<execution_proof_contract::Error> for ClientError {
    fn from(error: execution_proof_contract::Error) -> Self {
        Self::Contract(error)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BeginResponse {
    session_id: String,
    quote_nonce: String,
    grant_digest: String,
    canonical_runtime_b64: String,
    init_data_sha384: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceChallengeResponse {
    session_id: String,
    request_nonce: String,
    grant_sha384: String,
    runtime_sha384: String,
    evidence_sha384: String,
    init_data_sha384: String,
    recorder_key_sha384: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialResponse {
    signed_delivery_b64: String,
    jwe_b64: String,
}

/// The encrypted bytes are exposed only after authenticating their producer,
/// exact ciphertext digest, current signed window and client-owned context.
pub struct VerifiedCredentialResponse {
    delivery: VerifiedCredentialDelivery,
    jwe: Vec<u8>,
}
impl VerifiedCredentialResponse {
    pub fn delivery(&self) -> &VerifiedCredentialDelivery {
        &self.delivery
    }
    pub fn jwe_bytes(&self) -> &[u8] {
        &self.jwe
    }
}

struct BeginContext {
    session_id: String,
    nonce: String,
    runtime: Vec<u8>,
    report_data: [u8; 48],
}

/// Keys remain in memory. No raw Debug, serialization, or caller-derived trust roots.
/// The grant is time-checked at construction; the server must independently check
/// its trusted clock before each new admission. Aggregate verification is not a
/// current authorization or an execution verdict.
pub struct ClientProtocol {
    grant: VerifiedLaunchGrant,
    signed_grant: Vec<u8>,
    recorder: Ed25519KeyPair,
    keywrap: TeePubKey,
    key_sha384: String,
    expected_init: [u8; 48],
    begin: Option<BeginContext>,
    evidence: Option<Vec<u8>>,
    resource_nonce: Option<String>,
    request: Option<ResourcePolicyRequest>,
}

impl ClientProtocol {
    pub fn new(
        signed_grant: Vec<u8>,
        expected: &GrantExpectations,
        trusted_now: u64,
        recorder: Ed25519KeyPair,
        keywrap: TeePubKey,
        expected_init: [u8; 48],
    ) -> Result<Self, ClientError> {
        let grant = verify_launch_grant(&signed_grant, expected, trusted_now)?;
        if hash(recorder.public_key().as_ref()) != grant.binding().channel_key_sha384 {
            return Err(ClientError::BindingMismatch);
        }
        let fields: Vec<&str> = match &keywrap {
            TeePubKey::RSA { alg, k_mod, k_exp } => vec![alg, k_mod, k_exp],
            TeePubKey::EC { crv, alg, x, y } => vec![crv, alg, x, y],
        };
        if fields
            .iter()
            .any(|value| value.is_empty() || value.len() > 4096)
        {
            return Err(ClientError::InvalidField);
        }
        let canonical_key =
            serde_json_canonicalizer::to_vec(&keywrap).map_err(|_| ClientError::Malformed)?;
        if canonical_key.len() > MAX_RUNTIME_BYTES {
            return Err(ClientError::TooLarge);
        }
        Ok(Self {
            grant,
            signed_grant,
            recorder,
            keywrap,
            key_sha384: hash(&canonical_key),
            expected_init,
            begin: None,
            evidence: None,
            resource_nonce: None,
            request: None,
        })
    }

    pub fn grant(&self) -> &VerifiedLaunchGrant {
        &self.grant
    }
    pub fn expected_init_data(&self) -> [u8; 48] {
        self.expected_init
    }

    pub fn credential_request(
        &self,
        aggregate_json: &[u8],
        expected: &AggregateExpectations,
    ) -> Result<Vec<u8>, ClientError> {
        let aggregate = self.verify_aggregate(aggregate_json, expected)?;
        let policy = aggregate.statement();
        let signature = self.sign_operation(&SessionOperation::CredentialDelivery {
            session_id: policy.session_id.clone(),
            nonce: policy.request.request_nonce.clone(),
            runtime_sha384: policy.runtime_sha384.clone(),
            evidence_sha384: policy.evidence_sha384.clone(),
            request_sha384: policy.request.digest_sha384()?,
            aggregate_sha384: aggregate.digest_sha384().into(),
        })?;
        encode(&serde_json::json!({
            "session_id":policy.session_id,"aggregate_sha384":aggregate.digest_sha384(),
            "recorder_public_key_hex":self.public_key(),"signature_hex":signature,
        }))
    }

    /// Verifies fresh acceptance, including exact retries. Historical policy
    /// authentication alone never exposes credential ciphertext after expiry.
    pub fn verify_credential_response(
        &self,
        response_json: &[u8],
        aggregate_json: &[u8],
        expected: &DeliveryExpectations,
        trusted_now: u64,
    ) -> Result<VerifiedCredentialResponse, ClientError> {
        if response_json.len() > MAX_CREDENTIAL_RESPONSE_BYTES {
            return Err(ClientError::TooLarge);
        }
        if expected.keywrap_sha384 != self.key_sha384 {
            return Err(ClientError::BindingMismatch);
        }
        let aggregate = self.verify_aggregate(aggregate_json, &expected.aggregate)?;
        let response: CredentialResponse =
            serde_json::from_slice(response_json).map_err(|_| ClientError::Malformed)?;
        let receipt = canonical_base64(
            &response.signed_delivery_b64,
            execution_proof_contract::MAX_WIRE_BYTES,
        )?;
        let jwe = canonical_base64(&response.jwe_b64, MAX_CREDENTIAL_JWE_BYTES)?;
        let delivery = verify_credential_delivery(
            &receipt,
            &self.grant,
            &aggregate,
            expected,
            &jwe,
            trusted_now,
        )?;
        Ok(VerifiedCredentialResponse { delivery, jwe })
    }
    pub fn session_id(&self) -> Option<&str> {
        self.begin.as_ref().map(|value| value.session_id.as_str())
    }
    pub fn quote_nonce(&self) -> Option<&str> {
        self.begin.as_ref().map(|value| value.nonce.as_str())
    }
    pub fn request_nonce(&self) -> Option<&str> {
        self.resource_nonce.as_deref()
    }

    pub fn begin_request(&self) -> Result<Vec<u8>, ClientError> {
        let signature = self.sign_operation(&SessionOperation::Begin {
            key_sha384: self.key_sha384.clone(),
        })?;
        encode(
            &serde_json::json!({"signed_grant_b64":STANDARD.encode(&self.signed_grant),
            "keywrap_public_key":self.keywrap,"recorder_public_key_hex":self.public_key(),"signature_hex":signature}),
        )
    }

    pub fn accept_begin_response(&mut self, bytes: &[u8]) -> Result<(), ClientError> {
        let response: BeginResponse = decode(bytes)?;
        lower_hex(&response.session_id, 32)?;
        let nonce_hash = response
            .quote_nonce
            .strip_prefix("onb17-launch-v1:")
            .ok_or(ClientError::InvalidField)?;
        lower_hex(nonce_hash, 48)?;
        if response.grant_digest != self.grant.grant_digest()
            || response.init_data_sha384 != hex(&self.expected_init)
        {
            return Err(ClientError::BindingMismatch);
        }
        let supplied_runtime =
            canonical_base64(&response.canonical_runtime_b64, MAX_RUNTIME_BYTES)?;
        let runtime = serde_json_canonicalizer::to_vec(&serde_json::json!({
            "tee-pubkey":self.keywrap,"nonce":response.quote_nonce,"additional-evidence":"",
        }))
        .map_err(|_| ClientError::Malformed)?;
        if runtime.len() > MAX_RUNTIME_BYTES {
            return Err(ClientError::TooLarge);
        }
        if supplied_runtime != runtime {
            return Err(ClientError::BindingMismatch);
        }
        if let Some(previous) = &self.begin {
            if previous.session_id != response.session_id
                || previous.nonce != response.quote_nonce
                || previous.runtime != runtime
            {
                return Err(ClientError::Conflict);
            }
            return Ok(());
        }
        let report_data = digest::digest(&digest::SHA384, &runtime)
            .as_ref()
            .try_into()
            .map_err(|_| ClientError::Malformed)?;
        self.begin = Some(BeginContext {
            session_id: response.session_id,
            nonce: response.quote_nonce,
            runtime,
            report_data,
        });
        Ok(())
    }

    pub fn report_data(&self) -> Result<[u8; 48], ClientError> {
        Ok(self.begin()?.report_data)
    }

    pub fn capture_request(&mut self, evidence: &[u8]) -> Result<Vec<u8>, ClientError> {
        if evidence.is_empty() || evidence.len() > MAX_EVIDENCE_BYTES {
            return Err(ClientError::TooLarge);
        }
        if self.evidence.as_ref().is_some_and(|old| old != evidence) {
            return Err(ClientError::Conflict);
        }
        let begin = self.begin()?;
        let bytes = recorder_session_signing_bytes(
            &self.grant,
            &begin.nonce,
            &hex(&begin.report_data),
            &hash(evidence),
        )?;
        let request = encode(
            &serde_json::json!({"session_id":begin.session_id,"evidence_b64":STANDARD.encode(evidence),
            "recorder_public_key_hex":self.public_key(),"signature_hex":hex(self.recorder.sign(&bytes).as_ref())}),
        )?;
        if self.evidence.is_none() {
            self.evidence = Some(evidence.to_vec());
        }
        Ok(request)
    }

    pub fn resource_challenge_request(&self) -> Result<Vec<u8>, ClientError> {
        let begin = self.begin()?;
        let signature = self.sign_operation(&SessionOperation::ResourceChallenge {
            session_id: begin.session_id.clone(),
            nonce: begin.nonce.clone(),
            runtime_sha384: hex(&begin.report_data),
            evidence_sha384: hash(self.evidence()?),
        })?;
        encode(
            &serde_json::json!({"session_id":begin.session_id,"recorder_public_key_hex":self.public_key(),"signature_hex":signature}),
        )
    }

    pub fn accept_resource_challenge_response(&mut self, bytes: &[u8]) -> Result<(), ClientError> {
        let response: ResourceChallengeResponse = decode(bytes)?;
        lower_hex(&response.request_nonce, 32)?;
        let begin = self.begin()?;
        if response.session_id != begin.session_id
            || response.grant_sha384 != self.grant.grant_digest()
            || response.runtime_sha384 != hex(&begin.report_data)
            || response.evidence_sha384 != hash(self.evidence()?)
            || response.init_data_sha384 != hex(&self.expected_init)
            || response.recorder_key_sha384 != self.grant.binding().channel_key_sha384
        {
            return Err(ClientError::BindingMismatch);
        }
        if self
            .resource_nonce
            .as_ref()
            .is_some_and(|old| old != &response.request_nonce)
        {
            return Err(ClientError::Conflict);
        }
        self.resource_nonce = Some(response.request_nonce);
        Ok(())
    }

    pub fn resource_decision_request(
        &mut self,
        request: &ResourcePolicyRequest,
    ) -> Result<Vec<u8>, ClientError> {
        if self.request.as_ref().is_some_and(|old| old != request) {
            return Err(ClientError::Conflict);
        }
        let request_digest = request.digest_sha384()?;
        let nonce = self.resource_nonce.as_ref().ok_or(ClientError::NotReady)?;
        if &request.request_nonce != nonce {
            return Err(ClientError::BindingMismatch);
        }
        let begin = self.begin()?;
        let signature = self.sign_operation(&SessionOperation::ResourceDecision {
            session_id: begin.session_id.clone(),
            nonce: nonce.clone(),
            runtime_sha384: hex(&begin.report_data),
            evidence_sha384: hash(self.evidence()?),
            request_sha384: request_digest,
        })?;
        let bytes = encode(
            &serde_json::json!({"session_id":begin.session_id,"request":request,
            "recorder_public_key_hex":self.public_key(),"signature_hex":signature}),
        )?;
        if self.request.is_none() {
            self.request = Some(request.clone());
        }
        Ok(bytes)
    }

    /// Expectations must be selected independently; server JSON never creates them.
    pub fn verify_aggregate(
        &self,
        bytes: &[u8],
        expected: &AggregateExpectations,
    ) -> Result<VerifiedPolicyAggregate, ClientError> {
        let begin = self.begin()?;
        let request = self.request.as_ref().ok_or(ClientError::NotReady)?;
        let statement = &expected.expected;
        if statement.grant_sha384 != self.grant.grant_digest()
            || statement.authority_key_sha384 != self.grant.authority_key_sha384()
            || statement.session_id != begin.session_id
            || statement.nonce != begin.nonce
            || statement.runtime_sha384 != hex(&begin.report_data)
            || statement.init_data_sha384 != hex(&self.expected_init)
            || statement.evidence_sha384 != hash(self.evidence()?)
            || statement.recorder_key_sha384 != self.grant.binding().channel_key_sha384
            || &statement.request != request
        {
            return Err(ClientError::BindingMismatch);
        }
        Ok(verify_policy_aggregate(bytes, &self.grant, expected)?)
    }

    fn begin(&self) -> Result<&BeginContext, ClientError> {
        self.begin.as_ref().ok_or(ClientError::NotReady)
    }
    fn evidence(&self) -> Result<&[u8], ClientError> {
        self.evidence.as_deref().ok_or(ClientError::NotReady)
    }
    fn public_key(&self) -> String {
        hex(self.recorder.public_key().as_ref())
    }
    fn sign_operation(&self, operation: &SessionOperation) -> Result<String, ClientError> {
        Ok(hex(self
            .recorder
            .sign(&operation_signing_bytes(&self.grant, operation)?)
            .as_ref()))
    }
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ClientError> {
    serde_json::to_vec(value).map_err(|_| ClientError::Malformed)
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ClientError> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ClientError::TooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| ClientError::Malformed)
}
fn canonical_base64(value: &str, limit: usize) -> Result<Vec<u8>, ClientError> {
    if value.len() > limit.div_ceil(3) * 4 {
        return Err(ClientError::TooLarge);
    }
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| ClientError::InvalidField)?;
    if decoded.len() > limit {
        return Err(ClientError::TooLarge);
    }
    if STANDARD.encode(&decoded) != value {
        return Err(ClientError::InvalidField);
    }
    Ok(decoded)
}
fn lower_hex(value: &str, bytes: usize) -> Result<(), ClientError> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ClientError::InvalidField);
    }
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| {
            [
                DIGITS[(b >> 4) as usize] as char,
                DIGITS[(b & 15) as usize] as char,
            ]
        })
        .collect()
}
fn hash(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA384, bytes).as_ref())
}

#[cfg(test)]
mod tests;
