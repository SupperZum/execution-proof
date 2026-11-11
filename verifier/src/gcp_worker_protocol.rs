//! Scoped GCP worker protocol. A checked response authenticates hardware and
//! structural boot predicates only; it cannot create an execution verdict or
//! qualify producer isolation. The parent pins the worker outside the pack.

use crate::{
    gcp_boot_evidence::GcpBootEvidencePolicy, gcp_tdx_policy::GcpTdxModulePolicyV1, hash,
    hex_field, schema, VerificationError,
};
use execution_proof_contract::{
    execution::ExecutionRecord, gcp_execution_envelope::GcpExecutionEnvelope,
    gcp_execution_quote::report_data,
};
use serde::{Deserialize, Serialize};

pub const MAX_GCP_WORKER_REQUEST_BYTES: usize = 24 << 20;
pub const MAX_GCP_WORKER_RESPONSE_BYTES: usize = 16 << 10;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpHardwareRequest {
    pub version: u16,
    pub purpose: String,
    pub envelope: GcpExecutionEnvelope,
    pub record: ExecutionRecord,
    pub expected_report_data: String,
    pub expected_boot_binding_sha384: String,
    pub boot_policy: GcpBootEvidencePolicy,
    pub module_policy: GcpTdxModulePolicyV1,
    #[serde(deserialize_with = "schema::object_bytes")]
    pub collateral_json: Vec<u8>,
}

impl GcpHardwareRequest {
    pub fn validate(&self) -> Result<(), VerificationError> {
        if self.version != 2 || self.purpose != "qlad.execution-proof.gcp-hardware-request.v2" {
            return Err(VerificationError::Invalid("gcp_worker_request_domain"));
        }
        self.envelope
            .encode()
            .map_err(|_| VerificationError::Invalid("gcp_envelope"))?;
        hex_field(&self.expected_report_data, 64)?;
        if self.expected_report_data[..96].bytes().all(|b| b == b'0')
            || self.expected_report_data[96..].bytes().any(|b| b != b'0')
        {
            return Err(VerificationError::Invalid("gcp_report_domain"));
        }
        hex_field(&self.expected_boot_binding_sha384, 48)?;
        let binding = self
            .envelope
            .challenge
            .boot_binding
            .digest_sha384()
            .map_err(|_| VerificationError::Invalid("gcp_boot_binding"))?;
        if binding != self.expected_boot_binding_sha384 {
            return Err(VerificationError::Invalid("gcp_boot_binding"));
        }
        let report = report_data(&self.record, &self.envelope.challenge)
            .map_err(|_| VerificationError::Invalid("gcp_record_binding"))?;
        if crate::hex(&report) != self.expected_report_data {
            return Err(VerificationError::Invalid("gcp_report_binding"));
        }
        self.boot_policy.validate()?;
        self.module_policy.validate()?;
        schema::bounded_bytes(&self.collateral_json, 4 << 20)?;
        Ok(())
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
        let request: Self = schema::decode(bytes, MAX_GCP_WORKER_REQUEST_BYTES)?;
        request.validate()?;
        Ok(request)
    }
}

#[cfg(test)]
#[path = "gcp_worker_protocol_tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpHardwareStatus {
    Checked,
    Invalid,
    Unproven,
}

/// Public summary returned only after the exact original quote has passed QVL
/// and the independently selected structural/module predicates. This statement
/// is not proof that a protected recorder produced R or enrolled the keys.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpHardwareFacts {
    pub quote_sha384: String,
    pub report_data: String,
    pub boot_binding_sha384: String,
    pub mr_config_id: String,
    pub mr_td: String,
    pub mr_owner: String,
    pub mr_seam: String,
    pub td_attributes: u64,
    pub rtmrs: [String; 4],
    pub event_count: usize,
    pub evaluation_time_unix_seconds: u64,
}

impl GcpHardwareFacts {
    /// Repeat the submitted public evidence and independently selected policy
    /// checks. Authentication still comes only from the pinned QVL worker.
    pub(crate) fn check_boot_policy(
        &self,
        quote: &[u8],
        table: &[u8],
        log: &[u8],
        boot: &GcpBootEvidencePolicy,
        module: &GcpTdxModulePolicyV1,
    ) -> Result<(), VerificationError> {
        use crate::gcp_boot_evidence::{check_boot_evidence, parse_quote};
        let raw = parse_quote(quote, boot.quote_padding)?;
        let checked = check_boot_evidence(table, log, quote, &raw.report_data, boot)?;
        module.check_facts(&crate::gcp_tdx_policy::GcpTdxModuleFacts {
            mr_seam: crate::hex(&raw.mr_seam),
            td_attributes: raw.td_attributes,
        })?;
        if raw.quote_version != 4
            || self.quote_sha384 != crate::hex(&raw.quote_sha384)
            || self.report_data != crate::hex(&raw.report_data)
            || self.mr_config_id != crate::hex(&raw.mr_config_id)
            || self.mr_td != crate::hex(&raw.mr_td)
            || self.mr_owner != crate::hex(&raw.mr_owner)
            || self.mr_seam != crate::hex(&raw.mr_seam)
            || self.td_attributes != raw.td_attributes
            || self.rtmrs != raw.rtmrs.map(|x| crate::hex(&x))
            || self.event_count != checked.event_count
        {
            return Err(VerificationError::Invalid("gcp_worker_fact_policy"));
        }
        Ok(())
    }
    pub(crate) fn validate(&self) -> Result<(), VerificationError> {
        for value in [
            &self.quote_sha384,
            &self.boot_binding_sha384,
            &self.mr_config_id,
            &self.mr_td,
            &self.mr_owner,
            &self.mr_seam,
        ] {
            hex_field(value, 48)?;
        }
        for value in &self.rtmrs {
            hex_field(value, 48)?;
        }
        hex_field(&self.report_data, 64)?;
        if !(1..=4096).contains(&self.event_count)
            || self.evaluation_time_unix_seconds == 0
            || self.evaluation_time_unix_seconds > i64::MAX as u64
        {
            return Err(VerificationError::Invalid("gcp_worker_facts"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpHardwareResponse {
    pub version: u16,
    pub purpose: String,
    pub request_sha384: String,
    pub status: GcpHardwareStatus,
    pub reason: String,
    pub facts: Option<GcpHardwareFacts>,
}

impl GcpHardwareResponse {
    pub fn new(
        request: &GcpHardwareRequest,
        status: GcpHardwareStatus,
        reason: &str,
        facts: Option<GcpHardwareFacts>,
    ) -> Result<Self, VerificationError> {
        let result = Self {
            version: 2,
            purpose: "qlad.execution-proof.gcp-hardware-response.v2".into(),
            request_sha384: request.sha384()?,
            status,
            reason: reason.into(),
            facts,
        };
        result.validate()?;
        result.check_request(request)?;
        Ok(result)
    }
    /// Required after decoding an independently pinned worker's response.
    pub fn check_request(&self, request: &GcpHardwareRequest) -> Result<(), VerificationError> {
        self.validate()?;
        if self.request_sha384 != request.sha384()? {
            return Err(VerificationError::Invalid("gcp_worker_request_mismatch"));
        }
        if let Some(facts) = &self.facts {
            if facts.report_data != request.expected_report_data
                || facts.boot_binding_sha384 != request.expected_boot_binding_sha384
                || facts.quote_sha384 != hash(&request.envelope.tdx_quote)
            {
                return Err(VerificationError::Invalid("gcp_worker_fact_binding"));
            }
            facts.check_boot_policy(
                &request.envelope.tdx_quote,
                &request.envelope.ccel_table,
                &request.envelope.ccel_log,
                &request.boot_policy,
                &request.module_policy,
            )?;
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<(), VerificationError> {
        if self.version != 2 || self.purpose != "qlad.execution-proof.gcp-hardware-response.v2" {
            return Err(VerificationError::Invalid("gcp_worker_response_domain"));
        }
        hex_field(&self.request_sha384, 48)?;
        crate::identifier(&self.reason)?;
        match (self.status, &self.facts) {
            (GcpHardwareStatus::Checked, Some(facts)) => facts.validate(),
            (GcpHardwareStatus::Invalid | GcpHardwareStatus::Unproven, None) => Ok(()),
            _ => Err(VerificationError::Invalid("gcp_worker_response_status")),
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>, VerificationError> {
        self.validate()?;
        schema::encode(self, MAX_GCP_WORKER_RESPONSE_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, VerificationError> {
        let response: Self = schema::decode(bytes, MAX_GCP_WORKER_RESPONSE_BYTES)?;
        response.validate()?;
        Ok(response)
    }
}
