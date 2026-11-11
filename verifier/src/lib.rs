//! Independent verification of a flat, local execution evidence graph.
//! Trust inputs and the pinned TDX worker are selected outside the submitted pack.

pub mod gcp_boot_evidence;
pub mod gcp_bootstrap_history;
pub mod gcp_graph;
pub mod gcp_pregrant_protocol;
pub mod gcp_schema;
pub mod gcp_tdx_policy;
pub mod gcp_worker_protocol;
mod graph;
pub mod protocol;
pub mod schema;
pub mod worker;

pub use graph::{verify_graph, ValidatedGraph};
pub use schema::{EvidencePack, TrustConfig};
use serde::Serialize;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    Invalid(&'static str),
    MissingEvidence(&'static str),
    ResourceLimit(&'static str),
    BackendUnavailable(&'static str),
}

impl fmt::Display for VerificationError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::Invalid(reason)
            | Self::MissingEvidence(reason)
            | Self::ResourceLimit(reason)
            | Self::BackendUnavailable(reason) => reason,
        };
        out.write_str(reason)
    }
}
impl std::error::Error for VerificationError {}

impl VerificationError {
    /// Failure output in the separate GCP v2 verifier family. An error cannot
    /// construct a successful verdict or qualify a producer.
    pub fn gcp_verdict(self) -> VerificationVerdict {
        let mut verdict = self.verdict();
        verdict.version = 2;
        verdict
    }
    pub fn verdict(self) -> VerificationVerdict {
        VerificationVerdict {
            version: 1,
            status: if matches!(self, Self::Invalid(_)) {
                "invalid"
            } else {
                "unproven"
            },
            reason: self.to_string(),
            claim: "exec_committed",
            event_id: None,
            record_sha384: None,
            identity_scope: "authorized_workload_attempt",
            time_semantics: "current_collateral_evaluation_of_historical_authorization",
            evaluation_time_unix_seconds: None,
        }
    }
}

/// An output of the fixed verification flow, never an authorization capability.
/// There is no public success constructor or Deserialize implementation.
#[derive(Debug, Serialize)]
pub struct VerificationVerdict {
    pub(crate) version: u16,
    pub(crate) status: &'static str,
    pub(crate) reason: String,
    pub(crate) claim: &'static str,
    pub(crate) event_id: Option<String>,
    pub(crate) record_sha384: Option<String>,
    pub(crate) identity_scope: &'static str,
    pub(crate) time_semantics: &'static str,
    pub(crate) evaluation_time_unix_seconds: Option<u64>,
}

impl VerificationVerdict {
    pub fn status(&self) -> &str {
        self.status
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn hash(bytes: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA384, bytes).as_ref())
}

pub(crate) fn hex_field(value: &str, bytes: usize) -> Result<(), VerificationError> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        return Err(VerificationError::Invalid("noncanonical_hex"));
    }
    Ok(())
}

pub(crate) fn identifier(value: &str) -> Result<(), VerificationError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"_.:-".contains(&v))
    {
        return Err(VerificationError::Invalid("invalid_identifier"));
    }
    Ok(())
}
