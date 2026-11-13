//! Public commitments for the GCP embedded-PE profile. A syntactically valid
//! binding authenticates no manifest, measurement, producer or execution. It
//! cannot construct a trusted boot context or select an authorizing profile.

use crate::{frame, hex, hex_bytes, sha384, transcript, Error};
use serde::{Deserialize, Serialize};

pub const GCP_BOOT_BINDING_VERSION: u16 = 1;
pub const GCP_BOOT_BINDING_PURPOSE: &str = "qlad.execution-proof.gcp-boot-binding.v1";
pub const GCP_BOOT_PROFILE: &str = "onb17.gcp-tdx-embedded-pe.v1";

/// Commitments to exact configuration (C), producer core (D), signed artifact
/// manifest (A), and independently trusted reference policy set (V).
///
/// Callers must authenticate A/V and their relationship to C/D separately.
/// MRCONFIGID is deliberately absent and is never interpreted as one of these
/// commitments. Deserialization creates public data, never a capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpBootBindingV1 {
    pub version: u16,
    pub purpose: String,
    pub profile: String,
    pub config_sha384: String,
    pub producer_core_sha384: String,
    pub artifact_manifest_sha384: String,
    pub reference_policy_sha384: String,
}

impl GcpBootBindingV1 {
    pub fn new(
        config: [u8; 48],
        producer_core: [u8; 48],
        artifact_manifest: [u8; 48],
        reference_policy: [u8; 48],
    ) -> Result<Self, Error> {
        let value = Self {
            version: GCP_BOOT_BINDING_VERSION,
            purpose: GCP_BOOT_BINDING_PURPOSE.into(),
            profile: GCP_BOOT_PROFILE.into(),
            config_sha384: hex(&config),
            producer_core_sha384: hex(&producer_core),
            artifact_manifest_sha384: hex(&artifact_manifest),
            reference_policy_sha384: hex(&reference_policy),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.version != GCP_BOOT_BINDING_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if self.purpose != GCP_BOOT_BINDING_PURPOSE {
            return Err(Error::WrongPurpose);
        }
        if self.profile != GCP_BOOT_PROFILE {
            return Err(Error::InvalidField);
        }
        for hash in self.commitments() {
            if hex_bytes(hash, 48)? == [0; 48] {
                return Err(Error::InvalidField);
            }
        }
        Ok(())
    }

    fn commitments(&self) -> [&str; 4] {
        [
            &self.config_sha384,
            &self.producer_core_sha384,
            &self.artifact_manifest_sha384,
            &self.reference_policy_sha384,
        ]
    }

    /// Domain-separated transcript with ordered raw 48-byte hash frames.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut bytes = transcript(b"gcp-embedded-pe-boot-binding", self.version);
        frame(&mut bytes, self.purpose.as_bytes());
        frame(&mut bytes, self.profile.as_bytes());
        for hash in self.commitments() {
            frame(&mut bytes, &hex_bytes(hash, 48)?);
        }
        Ok(bytes)
    }

    pub fn digest_sha384(&self) -> Result<String, Error> {
        Ok(sha384(&self.canonical_bytes()?))
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| Error::Malformed)?;
        if bytes.len() > crate::MAX_WIRE_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let value: Self = crate::decode(bytes)?;
        value.validate()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
