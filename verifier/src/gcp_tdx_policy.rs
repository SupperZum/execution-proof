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
mod tests {
    use super::*;

    fn policy() -> GcpTdxModulePolicyV1 {
        GcpTdxModulePolicyV1 {
            version: GCP_TDX_POLICY_VERSION,
            purpose: GCP_TDX_POLICY_PURPOSE.into(),
            expected_mr_seam: INTEL_TDX_MODULE_1_5_34_MR_SEAM.into(),
            allowed_td_attributes: GCP_TDX_ALLOWED_ATTRIBUTES,
        }
    }

    fn facts() -> GcpTdxModuleFacts {
        GcpTdxModuleFacts {
            mr_seam: policy().expected_mr_seam,
            td_attributes: GCP_TDX_ALLOWED_ATTRIBUTES,
        }
    }

    #[test]
    fn independently_selected_module_and_allowmask_control_predicate() {
        let selected = policy();
        assert_eq!(selected.check_facts(&facts()), Ok(()));
        assert_eq!(
            GcpTdxModulePolicyV1::decode(&selected.encode().unwrap()).unwrap(),
            selected
        );
        let mut strict = selected;
        strict.allowed_td_attributes = 0;
        assert_eq!(
            strict.check_facts(&facts()),
            Err(VerificationError::Invalid("gcp_tdx_attributes"))
        );
        let mut no_attributes = facts();
        no_attributes.td_attributes = 0;
        assert_eq!(strict.check_facts(&no_attributes), Ok(()));
    }

    #[test]
    fn debug_and_migration_are_rejected_even_when_policy_tries_allowing_them() {
        for (flag, reason) in [
            (TD_ATTRIBUTE_DEBUG, "gcp_tdx_debug"),
            (TD_ATTRIBUTE_MIGRATABLE, "gcp_tdx_migratable"),
        ] {
            let mut public = facts();
            public.td_attributes |= flag;
            assert_eq!(
                policy().check_facts(&public),
                Err(VerificationError::Invalid(reason))
            );
            let mut untrusted_policy = policy();
            untrusted_policy.allowed_td_attributes |= flag;
            assert_eq!(
                untrusted_policy.check_facts(&public),
                Err(VerificationError::Invalid("gcp_tdx_policy_attributes"))
            );
        }
    }

    #[test]
    fn every_unrecognized_attribute_bit_is_rejected() {
        for bit in 0..64 {
            if GCP_TDX_ALLOWED_ATTRIBUTES & (1 << bit) != 0 {
                continue;
            }
            let mut public = facts();
            public.td_attributes |= 1 << bit;
            assert!(
                policy().check_facts(&public).is_err(),
                "attribute bit {bit}"
            );
        }
    }

    #[test]
    fn module_mismatch_and_malformed_measurements_reject() {
        let mut public = facts();
        public.mr_seam = "34".repeat(48);
        assert_eq!(
            policy().check_facts(&public),
            Err(VerificationError::Invalid("gcp_tdx_module_mismatch"))
        );
        for malformed in ["AB".repeat(48), "12".repeat(47), "gg".repeat(48)] {
            public.mr_seam = malformed.clone();
            assert!(policy().check_facts(&public).is_err());
            let mut selected = policy();
            selected.expected_mr_seam = malformed;
            assert!(selected.validate().is_err());
        }
        let mut selected = policy();
        selected.expected_mr_seam = "00".repeat(48);
        assert!(selected.validate().is_err());
        // Even mutually matching public fields cannot enroll an unknown module.
        selected.expected_mr_seam = "34".repeat(48);
        public.mr_seam.clone_from(&selected.expected_mr_seam);
        assert_eq!(
            selected.check_facts(&public),
            Err(VerificationError::Invalid("gcp_tdx_policy_module"))
        );
    }

    #[test]
    fn unknown_version_purpose_fields_and_oversize_policy_reject() {
        let mut selected = policy();
        selected.version = 2;
        assert!(selected.check_facts(&facts()).is_err());
        assert!(GcpTdxModulePolicyV1::decode(&serde_json::to_vec(&selected).unwrap()).is_err());
        selected = policy();
        selected.purpose = "qlad.execution-proof.verifier-trust.v1".into();
        assert!(selected.check_facts(&facts()).is_err());
        let wire = String::from_utf8(policy().encode().unwrap()).unwrap();
        for field in ["\"version\":1,", "\"unknown\":0,"] {
            let malformed = wire.replacen('{', &format!("{{{field}"), 1);
            assert!(GcpTdxModulePolicyV1::decode(malformed.as_bytes()).is_err());
        }
        assert!(matches!(
            GcpTdxModulePolicyV1::decode(&vec![b' '; MAX_GCP_TDX_POLICY_BYTES + 1]),
            Err(VerificationError::ResourceLimit(_))
        ));
    }
}
