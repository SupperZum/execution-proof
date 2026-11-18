//! Offline bootstrap appraisal has a separate domain from live grant issuance.
//! It authenticates the old authority challenge without reopening its window.
//! A checked result cannot be passed to the live issuer/pre-grant API.

use crate::{
    gcp_pregrant_protocol::GcpPregrantRequest,
    gcp_worker_protocol::{
        GcpHardwareFacts, GcpHardwareStatus, MAX_GCP_WORKER_REQUEST_BYTES,
        MAX_GCP_WORKER_RESPONSE_BYTES,
    },
    hash, schema, VerificationError,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpBootstrapHistoryRequest {
    pub version: u16,
    pub purpose: String,
    pub bootstrap: GcpPregrantRequest,
}

impl GcpBootstrapHistoryRequest {
    pub fn new(bootstrap: GcpPregrantRequest) -> Result<Self, VerificationError> {
        let value = Self {
            version: 1,
            purpose: "qlad.execution-proof.gcp-bootstrap-history-request.v1".into(),
            bootstrap,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), VerificationError> {
        if self.version != 1
            || self.purpose != "qlad.execution-proof.gcp-bootstrap-history-request.v1"
        {
            return Err(VerificationError::Invalid("gcp_history_request_domain"));
        }
        self.bootstrap.validate()?;
        execution_proof_contract::gcp_bootstrap::verify_challenge_signature(
            &self.bootstrap.signed_challenge_json,
            &self.bootstrap.authority_public_key,
            &self.bootstrap.expected_challenge,
        )
        .map_err(|_| VerificationError::Invalid("gcp_history_authority"))?;
        Ok(())
    }
    pub fn sha384(&self) -> Result<String, VerificationError> {
        Ok(hash(&self.encode()?))
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
pub struct GcpBootstrapHistoryResponse {
    pub version: u16,
    pub purpose: String,
    pub request_sha384: String,
    pub status: GcpHardwareStatus,
    pub reason: String,
    pub facts: Option<GcpHardwareFacts>,
}
impl GcpBootstrapHistoryResponse {
    pub fn new(
        request: &GcpBootstrapHistoryRequest,
        status: GcpHardwareStatus,
        reason: &str,
        facts: Option<GcpHardwareFacts>,
    ) -> Result<Self, VerificationError> {
        let value = Self {
            version: 1,
            purpose: "qlad.execution-proof.gcp-bootstrap-history-response.v1".into(),
            request_sha384: request.sha384()?,
            status,
            reason: reason.into(),
            facts,
        };
        value.check_request(request)?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), VerificationError> {
        if self.version != 1
            || self.purpose != "qlad.execution-proof.gcp-bootstrap-history-response.v1"
        {
            return Err(VerificationError::Invalid("gcp_history_response_domain"));
        }
        crate::hex_field(&self.request_sha384, 48)?;
        crate::identifier(&self.reason)?;
        match (self.status, &self.facts) {
            (GcpHardwareStatus::Checked, Some(facts)) => facts.validate(),
            (GcpHardwareStatus::Invalid | GcpHardwareStatus::Unproven, None) => Ok(()),
            _ => Err(VerificationError::Invalid("gcp_history_response_status")),
        }
    }
    pub fn check_request(
        &self,
        request: &GcpBootstrapHistoryRequest,
    ) -> Result<(), VerificationError> {
        self.validate()?;
        if self.request_sha384 != request.sha384()? {
            return Err(VerificationError::Invalid("gcp_history_response_request"));
        }
        if let Some(facts) = &self.facts {
            let b = &request.bootstrap;
            if facts.report_data != crate::hex(&b.derived_report_data()?)
                || facts.boot_binding_sha384 != b.boot_binding_sha384()?
                || facts.quote_sha384 != hash(&b.evidence.tdx_quote)
            {
                return Err(VerificationError::Invalid("gcp_history_response_binding"));
            }
            facts.check_boot_policy(
                &b.evidence.tdx_quote,
                &b.evidence.ccel_table,
                &b.evidence.ccel_log,
                &b.boot_policy,
                &b.module_policy,
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
