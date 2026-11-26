//! Strict data-only stdin/stdout protocol for the separately pinned TDX worker.

use crate::{hash, hex_field, schema, VerificationError};
use serde::{Deserialize, Serialize};

pub const WORKER_REQUEST_PURPOSE: &str = "qlad.execution-proof.tdx-worker-request.v1";
pub const WORKER_RESPONSE_PURPOSE: &str = "qlad.execution-proof.tdx-worker-response.v1";
pub const MAX_WORKER_REQUEST_BYTES: usize = 24 << 20;
pub const MAX_WORKER_RESPONSE_BYTES: usize = 16 << 10;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TdxWorkerRequest {
    pub version: u16,
    pub purpose: String,
    #[serde(deserialize_with = "schema::evidence_bytes")]
    pub evidence_json: Vec<u8>,
    pub expected_report_data: String,
    pub expected_mr_config_id: String,
    #[serde(deserialize_with = "schema::object_bytes")]
    pub collateral_json: Vec<u8>,
}

impl TdxWorkerRequest {
    pub fn new(
        evidence_json: Vec<u8>,
        expected_report_data: String,
        expected_mr_config_id: String,
        collateral_json: Vec<u8>,
    ) -> Result<Self, VerificationError> {
        let value = Self {
            version: 1,
            purpose: WORKER_REQUEST_PURPOSE.into(),
            evidence_json,
            expected_report_data,
            expected_mr_config_id,
            collateral_json,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), VerificationError> {
        if self.version != 1 || self.purpose != WORKER_REQUEST_PURPOSE {
            return Err(VerificationError::Invalid("worker_request_domain"));
        }
        schema::bounded_bytes(&self.evidence_json, 1 << 20)?;
        schema::bounded_bytes(&self.collateral_json, 4 << 20)?;
        hex_field(&self.expected_report_data, 64)?;
        hex_field(&self.expected_mr_config_id, 48)?;
        Ok(())
    }
    pub fn sha384_hex(&self) -> Result<String, VerificationError> {
        self.validate()?;
        let mut bytes = Vec::new();
        for value in [
            b"qlad/tdx-worker-request/v1".as_slice(),
            &self.version.to_be_bytes(),
            self.purpose.as_bytes(),
            hash(&self.evidence_json).as_bytes(),
            self.expected_report_data.as_bytes(),
            self.expected_mr_config_id.as_bytes(),
            hash(&self.collateral_json).as_bytes(),
        ] {
            bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
            bytes.extend_from_slice(value);
        }
        Ok(hash(&bytes))
    }
    pub fn encode(&self) -> Result<Vec<u8>, VerificationError> {
        self.validate()?;
        schema::encode(self, MAX_WORKER_REQUEST_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, VerificationError> {
        let value: Self = schema::decode(bytes, MAX_WORKER_REQUEST_BYTES)?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerStatus {
    Verified,
    Invalid,
    Unproven,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TdxClaims {
    pub evidence_sha384: String,
    pub report_data: String,
    pub mr_config_id: String,
    pub mr_td: String,
    pub rtmrs: [String; 4],
    pub debug: bool,
    pub tcb_status: String,
    pub collateral_expiration_status: u32,
    pub evaluation_time_unix_seconds: u64,
}

impl TdxClaims {
    fn validate(&self) -> Result<(), VerificationError> {
        for value in [&self.evidence_sha384, &self.mr_config_id, &self.mr_td] {
            hex_field(value, 48)?;
        }
        for value in &self.rtmrs {
            hex_field(value, 48)?;
        }
        hex_field(&self.report_data, 64)?;
        crate::identifier(&self.tcb_status)?;
        if self.evaluation_time_unix_seconds == 0
            || self.evaluation_time_unix_seconds > i64::MAX as u64
        {
            return Err(VerificationError::Invalid("worker_evaluation_time"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TdxWorkerResponse {
    pub version: u16,
    pub purpose: String,
    pub request_sha384: String,
    pub status: WorkerStatus,
    pub reason: String,
    pub claims: Option<TdxClaims>,
}

impl TdxWorkerResponse {
    pub fn new(
        request: &TdxWorkerRequest,
        status: WorkerStatus,
        reason: String,
        claims: Option<TdxClaims>,
    ) -> Result<Self, VerificationError> {
        let value = Self {
            version: 1,
            purpose: WORKER_RESPONSE_PURPOSE.into(),
            request_sha384: request.sha384_hex()?,
            status,
            reason,
            claims,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), VerificationError> {
        if self.version != 1 || self.purpose != WORKER_RESPONSE_PURPOSE {
            return Err(VerificationError::Invalid("worker_response_domain"));
        }
        hex_field(&self.request_sha384, 48)?;
        crate::identifier(&self.reason)?;
        match (self.status, &self.claims) {
            (WorkerStatus::Verified, Some(claims)) => claims.validate(),
            (WorkerStatus::Invalid | WorkerStatus::Unproven, None) => Ok(()),
            _ => Err(VerificationError::Invalid("worker_response_status")),
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>, VerificationError> {
        self.validate()?;
        schema::encode(self, MAX_WORKER_RESPONSE_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, VerificationError> {
        let value: Self = schema::decode(bytes, MAX_WORKER_RESPONSE_BYTES)?;
        value.validate()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> TdxWorkerRequest {
        TdxWorkerRequest::new(
            b"{\"quote\":\"fixture\"}".to_vec(),
            "12".repeat(64),
            "34".repeat(48),
            b"{}".to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn request_commitment_covers_all_payload_and_expected_bytes() {
        let original = request();
        let expected = original.sha384_hex().unwrap();
        for mutation in 0..4 {
            let mut changed = original.clone();
            match mutation {
                0 => changed.evidence_json.push(b' '),
                1 => changed.expected_report_data.replace_range(126.., "01"),
                2 => changed.expected_mr_config_id.replace_range(..2, "01"),
                _ => changed.collateral_json.push(b' '),
            }
            assert_ne!(changed.sha384_hex().unwrap(), expected);
        }
        let decoded = TdxWorkerRequest::decode(&original.encode().unwrap()).unwrap();
        assert_eq!(decoded.sha384_hex().unwrap(), expected);
    }

    #[test]
    fn worker_protocol_rejects_ambiguous_fields_and_oversized_decoded_data() {
        let request = request();
        let wire = String::from_utf8(request.encode().unwrap()).unwrap();
        for prefix in ["\"version\":1,", "\"extra\":0,"] {
            assert!(
                TdxWorkerRequest::decode(format!("{{{prefix}{}", &wire[1..]).as_bytes()).is_err()
            );
        }
        let mut oversized = request;
        oversized.evidence_json = vec![0; (1 << 20) + 1];
        assert!(matches!(
            oversized.encode(),
            Err(VerificationError::ResourceLimit(_))
        ));
        assert!(matches!(
            TdxWorkerResponse::decode(&vec![b' '; MAX_WORKER_RESPONSE_BYTES + 1]),
            Err(VerificationError::ResourceLimit(_))
        ));
    }

    #[test]
    fn backend_unavailable_does_not_supply_verified_claims() {
        let request = request();
        let response = TdxWorkerResponse::new(
            &request,
            WorkerStatus::Unproven,
            "tdx_backend_unavailable".into(),
            None,
        )
        .unwrap();
        let wire = response.encode().unwrap();
        assert_eq!(
            TdxWorkerResponse::decode(&wire).unwrap().status,
            WorkerStatus::Unproven
        );
        assert!(
            TdxWorkerResponse::new(&request, WorkerStatus::Verified, "fixture".into(), None)
                .is_err()
        );
    }
}
