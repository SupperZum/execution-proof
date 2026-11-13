//! Separate GCP v2 client. B is explicitly selected by trusted configuration;
//! signed publication/PoP proves association, not hardware key origin or exec.
use super::{
    canonical_base64, decode, encode, hash, hex, lower_hex, BeginContext, ClientError,
    MAX_CREDENTIAL_RESPONSE_BYTES, MAX_RUNTIME_BYTES,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use execution_proof_contract::{
    admission::gcp::{GcpAdmissionOperation, GcpAdmissionRequestV2},
    gcp_boot_binding::GcpBootBindingV1,
    gcp_credential::{
        verify_credential_delivery_historical, GcpDeliveryExpectations,
        VerifiedGcpCredentialDelivery, MAX_CREDENTIAL_JWE_BYTES,
    },
    gcp_policy_receipt::{
        verify_policy_aggregate, GcpAggregateExpectations, VerifiedGcpPolicyAggregate,
    },
    gcp_session::{self, GcpLaunchEvidence, SessionOperation},
    policy_receipt::ResourcePolicyRequest,
    verify_launch_grant, verify_launch_grant_historical, GrantExpectations, VerifiedLaunchGrant,
};
use kbs_types::TeePubKey;
use ring::{
    digest,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde::{Deserialize, Serialize};

pub const WIRE_VERSION: u16 = 2;
// New-profile transport overhead: <=4MiB JSON evidence plus Base64/wrapper.
// The shared decoded raw evidence limit remains1MiB; legacy stays2MiB.
pub const MAX_REQUEST_BYTES: usize = 6 << 20;
pub const BEGIN_PURPOSE: &str = "qlad.execution-proof.gcp-launch-begin.v2";
pub const CAPTURE_PURPOSE: &str = "qlad.execution-proof.gcp-launch-capture.v2";
pub const RESOURCE_CHALLENGE_PURPOSE: &str =
    "qlad.execution-proof.gcp-launch-resource-challenge.v2";
pub const RESOURCE_DECISION_PURPOSE: &str = "qlad.execution-proof.gcp-launch-resource-decision.v2";
pub const CREDENTIAL_PURPOSE: &str = "qlad.execution-proof.gcp-launch-credential-delivery.v2";
#[cfg(feature = "https")]
pub mod https;
macro_rules! wire {
    ($name:ident {$($field:ident:$ty:ty),* $(,)?})=>{
        #[derive(Serialize,Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {pub version:u16,pub purpose:String,pub boot_binding_sha384:String,$(pub $field:$ty),*}
    }
}
wire!(GcpBeginRequestV2 {
    signed_grant_b64: String,
    keywrap_public_key: TeePubKey,
    recorder_public_key_hex: String,
    signature_hex: String
});
wire!(GcpBeginResponseV2 {
    session_id: String,
    quote_nonce: String,
    grant_digest: String,
    canonical_runtime_b64: String,
    server_nonce_hex: String
});
wire!(GcpCaptureRequestV2 {
    session_id: String,
    evidence_b64: String,
    recorder_public_key_hex: String,
    signature_hex: String
});
wire!(GcpResourceChallengeRequestV2 {
    session_id: String,
    recorder_public_key_hex: String,
    signature_hex: String
});
wire!(GcpResourceChallengeResponseV2 {
    session_id: String,
    request_nonce: String,
    grant_sha384: String,
    runtime_sha384: String,
    evidence_sha384: String,
    recorder_key_sha384: String
});
wire!(GcpResourceDecisionRequestV2 {
    session_id: String,
    request: ResourcePolicyRequest,
    recorder_public_key_hex: String,
    signature_hex: String
});
wire!(GcpCredentialRequestV2 {
    session_id: String,
    aggregate_sha384: String,
    recorder_public_key_hex: String,
    signature_hex: String
});
wire!(GcpCredentialResponseV2 {
    signed_delivery_b64: String,
    jwe_b64: String
});
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpCredentialOutcome {
    Pending,
}
wire!(GcpCredentialPendingV2 {
    outcome: GcpCredentialOutcome
});
#[derive(Deserialize)]
#[serde(untagged)]
enum CredentialPublication {
    Ready(GcpCredentialResponseV2),
    Pending(GcpCredentialPendingV2),
}

/// Domain checking for the fixed server route. The server must independently
/// select B and a live stored session; these public fields cannot select policy.
pub fn check_wire_domain(
    version: u16,
    purpose: &str,
    binding: &str,
    expected_purpose: &str,
    selected_binding: &str,
) -> Result<(), ClientError> {
    if version != WIRE_VERSION || purpose != expected_purpose {
        return Err(ClientError::InvalidField);
    }
    lower_hex(binding, 48)?;
    if binding.bytes().all(|b| b == b'0') {
        return Err(ClientError::InvalidField);
    }
    if binding != selected_binding {
        return Err(ClientError::BindingMismatch);
    }
    Ok(())
}
fn request_encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ClientError> {
    let bytes = encode(value)?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(ClientError::TooLarge);
    }
    Ok(bytes)
}
fn raw48(value: &str) -> Result<[u8; 48], ClientError> {
    lower_hex(value, 48)?;
    let mut out = [0; 48];
    for (b, pair) in out
        .iter_mut()
        .zip(value.as_bytes().as_chunks::<2>().0.iter())
    {
        let n = |v: u8| {
            if v.is_ascii_digit() {
                v - b'0'
            } else {
                v - b'a' + 10
            }
        };
        *b = n(pair[0]) * 16 + n(pair[1]);
    }
    Ok(out)
}
fn raw32(value: &str) -> Result<[u8; 32], ClientError> {
    lower_hex(value, 32)?;
    let mut out = [0; 32];
    for (b, pair) in out
        .iter_mut()
        .zip(value.as_bytes().as_chunks::<2>().0.iter())
    {
        let n = |v: u8| {
            if v.is_ascii_digit() {
                v - b'0'
            } else {
                v - b'a' + 10
            }
        };
        *b = n(pair[0]) * 16 + n(pair[1]);
    }
    if out == [0; 32] {
        return Err(ClientError::InvalidField);
    }
    Ok(out)
}
/// Matches the independently specified AS v2 transcript. A supplied server
/// nonce alone proves no freshness: the server must own one-use pending state.
pub fn quote_nonce(
    grant_digest: &str,
    binding: &GcpBootBindingV1,
    server_nonce: [u8; 32],
) -> Result<String, ClientError> {
    lower_hex(grant_digest, 48)?;
    if server_nonce == [0; 32] {
        return Err(ClientError::InvalidField);
    }
    let b = raw48(&binding.digest_sha384()?)?;
    let mut bytes = Vec::new();
    for field in [
        b"qlad.execution-proof.gcp-launch-quote-nonce.v2".as_slice(),
        grant_digest.as_bytes(),
        server_nonce.as_slice(),
        b.as_slice(),
    ] {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    Ok(format!("onb17-gcp-launch-v2:{}", hash(&bytes)))
}

pub struct VerifiedGcpCredentialResponse {
    delivery: VerifiedGcpCredentialDelivery,
    jwe: Vec<u8>,
}
impl VerifiedGcpCredentialResponse {
    pub fn delivery(&self) -> &VerifiedGcpCredentialDelivery {
        &self.delivery
    }
    pub fn jwe_bytes(&self) -> &[u8] {
        &self.jwe
    }
}
/// Memory-only key/state owner, deliberately without Debug/Serialize. Creating
/// this client authenticates L and B equality, never boot/key-origin admission.
pub struct GcpClientProtocol {
    grant: VerifiedLaunchGrant,
    signed_grant: Vec<u8>,
    issuer_request_audience: String,
    recorder: Ed25519KeyPair,
    keywrap: TeePubKey,
    key_sha384: String,
    boot_binding: GcpBootBindingV1,
    boot_digest: String,
    begin: Option<BeginContext>,
    evidence: Option<Vec<u8>>,
    resource_nonce: Option<String>,
    request: Option<ResourcePolicyRequest>,
}
impl GcpClientProtocol {
    pub fn new(
        signed_grant: Vec<u8>,
        expected: &GrantExpectations,
        trusted_now: u64,
        recorder: Ed25519KeyPair,
        keywrap: TeePubKey,
        boot_binding: GcpBootBindingV1,
    ) -> Result<Self, ClientError> {
        let grant = verify_launch_grant(&signed_grant, expected, trusted_now)?;
        Self::from_verified(
            signed_grant,
            grant,
            recorder,
            keywrap,
            boot_binding,
            &expected.audience,
        )
    }
    pub fn new_authority_time(
        signed_grant: Vec<u8>,
        expected: &GrantExpectations,
        recorder: Ed25519KeyPair,
        keywrap: TeePubKey,
        boot_binding: GcpBootBindingV1,
    ) -> Result<Self, ClientError> {
        let grant = verify_launch_grant_historical(&signed_grant, expected)?;
        Self::from_verified(
            signed_grant,
            grant,
            recorder,
            keywrap,
            boot_binding,
            &expected.audience,
        )
    }
    fn from_verified(
        signed_grant: Vec<u8>,
        grant: VerifiedLaunchGrant,
        recorder: Ed25519KeyPair,
        keywrap: TeePubKey,
        boot_binding: GcpBootBindingV1,
        issuer_request_audience: &str,
    ) -> Result<Self, ClientError> {
        let boot_digest = gcp_session::require_boot_binding(&grant, &boot_binding)?;
        if hash(recorder.public_key().as_ref()) != grant.binding().channel_key_sha384 {
            return Err(ClientError::BindingMismatch);
        }
        let fields: Vec<&str> = match &keywrap {
            TeePubKey::RSA { alg, k_mod, k_exp } => vec![alg, k_mod, k_exp],
            TeePubKey::EC { crv, alg, x, y } => vec![crv, alg, x, y],
        };
        if fields.iter().any(|v| v.is_empty() || v.len() > 4096) {
            return Err(ClientError::InvalidField);
        }
        let key = serde_json_canonicalizer::to_vec(&keywrap).map_err(|_| ClientError::Malformed)?;
        if key.len() > MAX_RUNTIME_BYTES {
            return Err(ClientError::TooLarge);
        }
        Ok(Self {
            grant,
            signed_grant,
            issuer_request_audience: issuer_request_audience.into(),
            recorder,
            keywrap,
            key_sha384: hash(&key),
            boot_binding,
            boot_digest,
            begin: None,
            evidence: None,
            resource_nonce: None,
            request: None,
        })
    }
    pub fn grant(&self) -> &VerifiedLaunchGrant {
        &self.grant
    }
    pub fn boot_binding(&self) -> &GcpBootBindingV1 {
        &self.boot_binding
    }
    pub fn boot_binding_sha384(&self) -> &str {
        &self.boot_digest
    }
    pub fn session_id(&self) -> Option<&str> {
        self.begin.as_ref().map(|b| b.session_id.as_str())
    }
    pub fn quote_nonce(&self) -> Option<&str> {
        self.begin.as_ref().map(|b| b.nonce.as_str())
    }
    pub fn request_nonce(&self) -> Option<&str> {
        self.resource_nonce.as_deref()
    }
    pub fn canonical_runtime(&self) -> Result<&[u8], ClientError> {
        Ok(&self.begin()?.runtime)
    }
    pub fn report_data(&self) -> Result<[u8; 48], ClientError> {
        Ok(self.begin()?.report_data)
    }
    /// The final sixteen zero bytes are mandatory AS REPORT_DATA bytes.
    pub fn report_data_full64(&self) -> Result<[u8; 64], ClientError> {
        let mut out = [0; 64];
        out[..48].copy_from_slice(&self.begin()?.report_data);
        Ok(out)
    }
    pub fn runtime_sha384(&self) -> Result<String, ClientError> {
        Ok(hex(&self.begin()?.report_data))
    }
    pub fn begin_request(&self) -> Result<Vec<u8>, ClientError> {
        request_encode(&GcpBeginRequestV2 {
            version: 2,
            purpose: BEGIN_PURPOSE.into(),
            boot_binding_sha384: self.boot_digest.clone(),
            signed_grant_b64: STANDARD.encode(&self.signed_grant),
            keywrap_public_key: self.keywrap.clone(),
            recorder_public_key_hex: self.public_key(),
            signature_hex: self.sign_operation(&SessionOperation::Begin {
                key_sha384: self.key_sha384.clone(),
            })?,
        })
    }
    pub fn accept_begin_response(&mut self, bytes: &[u8]) -> Result<(), ClientError> {
        let response: GcpBeginResponseV2 = decode(bytes)?;
        check_wire_domain(
            response.version,
            &response.purpose,
            &response.boot_binding_sha384,
            BEGIN_PURPOSE,
            &self.boot_digest,
        )?;
        raw32(&response.session_id)?;
        let server_nonce = raw32(&response.server_nonce_hex)?;
        if response.grant_digest != self.grant.grant_digest()
            || response.quote_nonce
                != quote_nonce(self.grant.grant_digest(), &self.boot_binding, server_nonce)?
        {
            return Err(ClientError::BindingMismatch);
        }
        let supplied = canonical_base64(&response.canonical_runtime_b64, MAX_RUNTIME_BYTES)?;
        let runtime=serde_json_canonicalizer::to_vec(&serde_json::json!({"tee-pubkey":self.keywrap,"nonce":response.quote_nonce,"additional-evidence":""})).map_err(|_|ClientError::Malformed)?;
        if runtime.len() > MAX_RUNTIME_BYTES {
            return Err(ClientError::TooLarge);
        }
        if supplied != runtime {
            return Err(ClientError::BindingMismatch);
        }
        if let Some(old) = &self.begin {
            if old.session_id != response.session_id
                || old.nonce != response.quote_nonce
                || old.runtime != runtime
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
    pub fn capture_request(&mut self, evidence: &[u8]) -> Result<Vec<u8>, ClientError> {
        // Decode only the v2 raw quote/table/log family under its shared1MiB cap.
        GcpLaunchEvidence::decode(evidence)?;
        if self.evidence.as_ref().is_some_and(|old| old != evidence) {
            return Err(ClientError::Conflict);
        }
        let b = self.begin()?;
        let signing = gcp_session::recorder_session_signing_bytes(
            &self.grant,
            &self.boot_binding,
            &b.nonce,
            &hex(&b.report_data),
            &hash(evidence),
        )?;
        let bytes = request_encode(&GcpCaptureRequestV2 {
            version: 2,
            purpose: CAPTURE_PURPOSE.into(),
            boot_binding_sha384: self.boot_digest.clone(),
            session_id: b.session_id.clone(),
            evidence_b64: STANDARD.encode(evidence),
            recorder_public_key_hex: self.public_key(),
            signature_hex: hex(self.recorder.sign(&signing).as_ref()),
        })?;
        if self.evidence.is_none() {
            self.evidence = Some(evidence.to_vec());
        }
        Ok(bytes)
    }
    pub fn resource_challenge_request(&self) -> Result<Vec<u8>, ClientError> {
        let b = self.begin()?;
        let signature = self.sign_operation(&SessionOperation::ResourceChallenge {
            session_id: b.session_id.clone(),
            nonce: b.nonce.clone(),
            runtime_sha384: hex(&b.report_data),
            evidence_sha384: hash(self.evidence()?),
        })?;
        request_encode(&GcpResourceChallengeRequestV2 {
            version: 2,
            purpose: RESOURCE_CHALLENGE_PURPOSE.into(),
            boot_binding_sha384: self.boot_digest.clone(),
            session_id: b.session_id.clone(),
            recorder_public_key_hex: self.public_key(),
            signature_hex: signature,
        })
    }
    pub fn accept_resource_challenge_response(&mut self, bytes: &[u8]) -> Result<(), ClientError> {
        let r: GcpResourceChallengeResponseV2 = decode(bytes)?;
        check_wire_domain(
            r.version,
            &r.purpose,
            &r.boot_binding_sha384,
            RESOURCE_CHALLENGE_PURPOSE,
            &self.boot_digest,
        )?;
        raw32(&r.request_nonce)?;
        let b = self.begin()?;
        if r.session_id != b.session_id
            || r.grant_sha384 != self.grant.grant_digest()
            || r.runtime_sha384 != hex(&b.report_data)
            || r.evidence_sha384 != hash(self.evidence()?)
            || r.recorder_key_sha384 != self.grant.binding().channel_key_sha384
        {
            return Err(ClientError::BindingMismatch);
        }
        if self
            .resource_nonce
            .as_ref()
            .is_some_and(|old| old != &r.request_nonce)
        {
            return Err(ClientError::Conflict);
        }
        self.resource_nonce = Some(r.request_nonce);
        Ok(())
    }
    pub fn resource_decision_request(
        &mut self,
        request: &ResourcePolicyRequest,
    ) -> Result<Vec<u8>, ClientError> {
        if self.request.as_ref().is_some_and(|old| old != request) {
            return Err(ClientError::Conflict);
        }
        let nonce = self.resource_nonce.as_ref().ok_or(ClientError::NotReady)?;
        if &request.request_nonce != nonce {
            return Err(ClientError::BindingMismatch);
        }
        let b = self.begin()?;
        let signature = self.sign_operation(&SessionOperation::ResourceDecision {
            session_id: b.session_id.clone(),
            nonce: nonce.clone(),
            runtime_sha384: hex(&b.report_data),
            evidence_sha384: hash(self.evidence()?),
            request_sha384: request.digest_sha384()?,
        })?;
        let bytes = request_encode(&GcpResourceDecisionRequestV2 {
            version: 2,
            purpose: RESOURCE_DECISION_PURPOSE.into(),
            boot_binding_sha384: self.boot_digest.clone(),
            session_id: b.session_id.clone(),
            request: request.clone(),
            recorder_public_key_hex: self.public_key(),
            signature_hex: signature,
        })?;
        if self.request.is_none() {
            self.request = Some(request.clone());
        }
        Ok(bytes)
    }
    pub fn verify_aggregate(
        &self,
        bytes: &[u8],
        expected: &GcpAggregateExpectations,
    ) -> Result<VerifiedGcpPolicyAggregate, ClientError> {
        let b = self.begin()?;
        let request = self.request.as_ref().ok_or(ClientError::NotReady)?;
        let s = &expected.expected;
        if expected.boot_binding != self.boot_binding
            || s.boot_binding_sha384 != self.boot_digest
            || s.grant_sha384 != self.grant.grant_digest()
            || s.authority_key_sha384 != self.grant.authority_key_sha384()
            || s.session_id != b.session_id
            || s.nonce != b.nonce
            || s.runtime_sha384 != hex(&b.report_data)
            || s.evidence_sha384 != hash(self.evidence()?)
            || s.recorder_key_sha384 != self.grant.binding().channel_key_sha384
            || &s.request != request
        {
            return Err(ClientError::BindingMismatch);
        }
        Ok(verify_policy_aggregate(bytes, &self.grant, expected)?)
    }
    pub fn credential_request(
        &self,
        aggregate_json: &[u8],
        expected: &GcpAggregateExpectations,
    ) -> Result<Vec<u8>, ClientError> {
        let a = self.verify_aggregate(aggregate_json, expected)?;
        let s = a.statement();
        let signature = self.sign_operation(&SessionOperation::CredentialDelivery {
            session_id: s.session_id.clone(),
            nonce: s.request.request_nonce.clone(),
            runtime_sha384: s.runtime_sha384.clone(),
            evidence_sha384: s.evidence_sha384.clone(),
            request_sha384: s.request.digest_sha384()?,
            aggregate_sha384: a.digest_sha384().into(),
        })?;
        request_encode(&GcpCredentialRequestV2 {
            version: 2,
            purpose: CREDENTIAL_PURPOSE.into(),
            boot_binding_sha384: self.boot_digest.clone(),
            session_id: s.session_id.clone(),
            aggregate_sha384: a.digest_sha384().into(),
            recorder_public_key_hex: self.public_key(),
            signature_hex: signature,
        })
    }

    /// Sign only this client's accepted GCP session and typed issuer operation.
    /// Audience comes from constructor-selected grant expectations; callers
    /// cannot use this as an arbitrary message or credential signing API.
    pub fn sign_policy_admission_request(
        &self,
        aggregate: &VerifiedGcpPolicyAggregate,
        guest_nonce: &str,
        admission_policy_sha384: &str,
        operation: GcpAdmissionOperation,
    ) -> Result<Vec<u8>, ClientError> {
        let b = self.begin()?;
        let request = self.request.as_ref().ok_or(ClientError::NotReady)?;
        let s = aggregate.statement();
        if s.boot_binding_sha384 != self.boot_digest
            || s.grant_sha384 != self.grant.grant_digest()
            || s.authority_key_sha384 != self.grant.authority_key_sha384()
            || s.session_id != b.session_id
            || s.nonce != b.nonce
            || s.runtime_sha384 != hex(&b.report_data)
            || s.evidence_sha384 != hash(self.evidence()?)
            || s.recorder_key_sha384 != self.grant.binding().channel_key_sha384
            || &s.request != request
        {
            return Err(ClientError::BindingMismatch);
        }
        let statement = GcpAdmissionRequestV2::new(
            &self.grant,
            aggregate,
            guest_nonce,
            admission_policy_sha384,
            &self.issuer_request_audience,
            operation,
        )?;
        let signature = hex(self.recorder.sign(&statement.signing_bytes()?).as_ref());
        encode(&execution_proof_contract::Signed {
            statement,
            signature,
        })
    }
    pub fn verify_credential_response_historical(
        &self,
        bytes: &[u8],
        aggregate_json: &[u8],
        expected: &GcpDeliveryExpectations,
    ) -> Result<VerifiedGcpCredentialResponse, ClientError> {
        if bytes.len() > MAX_CREDENTIAL_RESPONSE_BYTES {
            return Err(ClientError::TooLarge);
        }
        if expected.keywrap_sha384 != self.key_sha384 {
            return Err(ClientError::BindingMismatch);
        }
        let aggregate = self.verify_aggregate(aggregate_json, &expected.aggregate)?;
        let publication: CredentialPublication =
            serde_json::from_slice(bytes).map_err(|_| ClientError::Malformed)?;
        let response = match publication {
            CredentialPublication::Ready(response) => response,
            CredentialPublication::Pending(pending) => {
                check_wire_domain(
                    pending.version,
                    &pending.purpose,
                    &pending.boot_binding_sha384,
                    CREDENTIAL_PURPOSE,
                    &self.boot_digest,
                )?;
                return Err(ClientError::NotReady);
            }
        };
        check_wire_domain(
            response.version,
            &response.purpose,
            &response.boot_binding_sha384,
            CREDENTIAL_PURPOSE,
            &self.boot_digest,
        )?;
        let receipt = canonical_base64(
            &response.signed_delivery_b64,
            execution_proof_contract::MAX_WIRE_BYTES,
        )?;
        let jwe = canonical_base64(&response.jwe_b64, MAX_CREDENTIAL_JWE_BYTES)?;
        let delivery = verify_credential_delivery_historical(
            &receipt,
            &self.grant,
            &aggregate,
            expected,
            &jwe,
        )?;
        Ok(VerifiedGcpCredentialResponse { delivery, jwe })
    }
    pub fn verify_credential_response(
        &self,
        bytes: &[u8],
        aggregate: &[u8],
        expected: &GcpDeliveryExpectations,
        trusted_now: u64,
    ) -> Result<VerifiedGcpCredentialResponse, ClientError> {
        let verified = self.verify_credential_response_historical(bytes, aggregate, expected)?;
        verified.delivery.validity().check_at(trusted_now)?;
        Ok(verified)
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
            .sign(&gcp_session::operation_signing_bytes(
                &self.grant,
                &self.boot_binding,
                operation,
            )?)
            .as_ref()))
    }
}
#[cfg(test)]
mod tests;
