//! Non-authorizing module/attribute predicates for a separately selected GCP
//! TDX policy. These public facts are not QVL-authenticated claims. Satisfying
//! this predicate proves neither boot causality nor deployed producer isolation,
//! and cannot produce an execution verdict or a no-state-copy capability.

use crate::{hex_field, schema, VerificationError};
use serde::{Deserialize, Serialize};

pub const GCP_TDX_POLICY_VERSION: u16 = 1;
pub const GCP_TDX_POLICY_PURPOSE: &str = "qlad.execution-proof.gcp-tdx-module-policy.v1";
pub const MAX_GCP_TDX_POLICY_BYTES: usize = 1024;
/// Independent Intel release reference, not a measurement learned from a quote.
/// https://github.com/intel/confidential-computing.tdx.tdx-module/releases/tag/TDX_MODULE_1.5.34
pub const INTEL_TDX_MODULE_1_5_34_MR_SEAM: &str = "ab62561a173acbd18ee50ff37750db44184c6cf5e886df74247cc575e163b04c34b9e18374757c235affa614d4127f6b";

const TD_ATTRIBUTE_DEBUG: u64 = 1;
const TD_ATTRIBUTE_MIGRATABLE: u64 = 1 << 29;
/// Intel source 9fd3c8b1d52ba3092f7d99d9eb036644f9765a79,
/// src/common/data_structures/td_control_structures.h, defines SEPT_VE_DIS
/// as bit 28, DEBUG as bit 0 and MIGRATABLE as bit 29. This closed profile
/// permits only SEPT_VE_DIS. Every other attribute,
/// including attributes defined by another module revision, fails closed.
pub const GCP_TDX_ALLOWED_ATTRIBUTES: u64 = 1 << 28;

/// Operator trust input, selected outside the submitted evidence pack. The
/// expected module measurement must come from an independently authenticated
/// vendor reference, never from the quote being evaluated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpTdxModulePolicyV1 {
    pub version: u16,
    pub purpose: String,
    pub expected_mr_seam: String,
    pub allowed_td_attributes: u64,
}

/// The QVL worker must authenticate the quote before applying these fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpTdxModuleFacts {
    pub mr_seam: String,
    pub td_attributes: u64,
}

impl GcpTdxModulePolicyV1 {
    pub fn validate(&self) -> Result<(), VerificationError> {
        if self.version != GCP_TDX_POLICY_VERSION || self.purpose != GCP_TDX_POLICY_PURPOSE {
            return Err(VerificationError::Invalid("gcp_tdx_policy_domain"));
        }
        hex_field(&self.expected_mr_seam, 48)?;
        if self.expected_mr_seam != INTEL_TDX_MODULE_1_5_34_MR_SEAM {
            return Err(VerificationError::Invalid("gcp_tdx_policy_module"));
        }
        if self.allowed_td_attributes & !GCP_TDX_ALLOWED_ATTRIBUTES != 0 {
            return Err(VerificationError::Invalid("gcp_tdx_policy_attributes"));
        }
        Ok(())
    }

    /// Check the supplied facts against the selected module policy.
    pub fn check_facts(&self, facts: &GcpTdxModuleFacts) -> Result<(), VerificationError> {
        self.validate()?;
        hex_field(&facts.mr_seam, 48)?;
        if facts.mr_seam != self.expected_mr_seam {
            return Err(VerificationError::Invalid("gcp_tdx_module_mismatch"));
        }
        if facts.td_attributes & TD_ATTRIBUTE_DEBUG != 0 {
            return Err(VerificationError::Invalid("gcp_tdx_debug"));
        }
        if facts.td_attributes & TD_ATTRIBUTE_MIGRATABLE != 0 {
            return Err(VerificationError::Invalid("gcp_tdx_migratable"));
        }
        if facts.td_attributes & !self.allowed_td_attributes != 0 {
            return Err(VerificationError::Invalid("gcp_tdx_attributes"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, VerificationError> {
        self.validate()?;
        schema::encode(self, MAX_GCP_TDX_POLICY_BYTES)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, VerificationError> {
        let value: Self = schema::decode(bytes, MAX_GCP_TDX_POLICY_BYTES)?;
        value.validate()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
