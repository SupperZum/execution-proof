//! Pre-grant hardware requests use authenticated, separately saved authority
//! challenges. Checked hardware facts do not enroll a key or authorize a grant;
//! producer qualification, PoP and atomic replay consumption remain mandatory.

use crate::{
    gcp_boot_evidence::GcpBootEvidencePolicy,
    gcp_tdx_policy::GcpTdxModulePolicyV1,
    gcp_worker_protocol::{
        GcpHardwareFacts, GcpHardwareStatus, MAX_GCP_WORKER_REQUEST_BYTES,
        MAX_GCP_WORKER_RESPONSE_BYTES,
    },
    hash, schema, VerificationError,
};
use execution_proof_contract::{
    gcp_bootstrap::{report_data, verify_challenge, GcpBootstrapBinding, GcpBootstrapChallenge},
    gcp_session::GcpLaunchEvidenceV2,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpPregrantRequest {
    pub version: u16,
    pub purpose: String,
    /// The issuer's saved pending challenge, never copied from guest evidence.
    pub expected_challenge: GcpBootstrapChallenge,
    pub authority_public_key: [u8; 32],
    #[serde(deserialize_with = "schema::object_bytes")]
    pub signed_challenge_json: Vec<u8>,
    pub binding: GcpBootstrapBinding,
    pub evidence: GcpLaunchEvidenceV2,
    pub boot_policy: GcpBootEvidencePolicy,
    pub module_policy: GcpTdxModulePolicyV1,
    #[serde(deserialize_with = "schema::object_bytes")]
    pub collateral_json: Vec<u8>,
}
impl GcpPregrantRequest {
    pub fn validate(&self) -> Result<(), VerificationError> {
        if self.version != 3
            || self.purpose != "qlad.execution-proof.gcp-pregrant-hardware-request.v3"
        {
            return Err(VerificationError::Invalid("gcp_pregrant_domain"));
        }
        if self.authority_public_key == [0; 32]
            || self.signed_challenge_json.is_empty()
            || self.signed_challenge_json.len() > 16 * 1024
        {
            return Err(VerificationError::Invalid("gcp_pregrant_authority"));
        }
        self.derived_report_data()?;
        self.evidence
            .encode()
            .map_err(|_| VerificationError::Invalid("gcp_pregrant_evidence"))?;
        self.boot_policy.validate()?;
        self.module_policy.validate()?;
        schema::bounded_bytes(&self.collateral_json, 4 << 20)
    }
    pub fn derived_report_data(&self) -> Result<[u8; 64], VerificationError> {
        report_data(&self.expected_challenge, &self.binding)
            .map_err(|_| VerificationError::Invalid("gcp_pregrant_binding"))
    }
    pub fn verify_authority(&self, trusted_now: u64) -> Result<(), VerificationError> {
        self.validate()?;
        verify_challenge(
            &self.signed_challenge_json,
            &self.authority_public_key,
            &self.expected_challenge,
            trusted_now,
        )
        .map_err(|_| VerificationError::Invalid("gcp_pregrant_challenge"))?;
        Ok(())
    }
    pub fn boot_binding_sha384(&self) -> Result<String, VerificationError> {
        self.expected_challenge
            .boot_binding
            .digest_sha384()
            .map_err(|_| VerificationError::Invalid("gcp_pregrant_binding"))
    }
    pub fn sha384(&self) -> Result<String, VerificationError> {
        self.validate()?;
        Ok(hash(&schema::encode(self, MAX_GCP_WORKER_REQUEST_BYTES)?))
    }
    pub fn encode(&self) -> Result<Vec<u8>, VerificationError> {
        self.validate()?;
        schema::encode(self, MAX_GCP_WORKER_REQUEST_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, VerificationError> {
        let value: Self = schema::decode(bytes, MAX_GCP_WORKER_REQUEST_BYTES)?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpPregrantResponse {
    pub version: u16,
    pub purpose: String,
    pub request_sha384: String,
    pub status: GcpHardwareStatus,
    pub reason: String,
    pub facts: Option<GcpHardwareFacts>,
}
impl GcpPregrantResponse {
    pub fn new(
        request: &GcpPregrantRequest,
        status: GcpHardwareStatus,
        reason: &str,
        facts: Option<GcpHardwareFacts>,
    ) -> Result<Self, VerificationError> {
        let value = Self {
            version: 3,
            purpose: "qlad.execution-proof.gcp-pregrant-hardware-response.v3".into(),
            request_sha384: request.sha384()?,
            status,
            reason: reason.into(),
            facts,
        };
        value.check_request(request)?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), VerificationError> {
        if self.version != 3
            || self.purpose != "qlad.execution-proof.gcp-pregrant-hardware-response.v3"
        {
            return Err(VerificationError::Invalid("gcp_pregrant_response_domain"));
        }
        crate::hex_field(&self.request_sha384, 48)?;
        crate::identifier(&self.reason)?;
        match (self.status, &self.facts) {
            (GcpHardwareStatus::Checked, Some(facts)) => facts.validate(),
            (GcpHardwareStatus::Invalid | GcpHardwareStatus::Unproven, None) => Ok(()),
            _ => Err(VerificationError::Invalid("gcp_pregrant_response_status")),
        }
    }
    pub fn check_request(&self, request: &GcpPregrantRequest) -> Result<(), VerificationError> {
        self.validate()?;
        if self.request_sha384 != request.sha384()? {
            return Err(VerificationError::Invalid("gcp_pregrant_response_request"));
        }
        if let Some(facts) = &self.facts {
            if facts.report_data != crate::hex(&request.derived_report_data()?)
                || facts.boot_binding_sha384 != request.boot_binding_sha384()?
                || facts.quote_sha384 != hash(&request.evidence.tdx_quote)
            {
                return Err(VerificationError::Invalid("gcp_pregrant_response_binding"));
            }
            request.verify_authority(facts.evaluation_time_unix_seconds)?;
            facts.check_boot_policy(
                &request.evidence.tdx_quote,
                &request.evidence.ccel_table,
                &request.evidence.ccel_log,
                &request.boot_policy,
                &request.module_policy,
            )?;
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, VerificationError> {
        self.validate()?;
        schema::encode(self, MAX_GCP_WORKER_RESPONSE_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, VerificationError> {
        let value: Self = schema::decode(bytes, MAX_GCP_WORKER_RESPONSE_BYTES)?;
        value.validate()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
