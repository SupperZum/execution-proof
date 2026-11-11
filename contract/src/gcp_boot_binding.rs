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
mod tests {
    use super::*;

    fn binding() -> GcpBootBindingV1 {
        GcpBootBindingV1::new([1; 48], [2; 48], [3; 48], [4; 48]).unwrap()
    }

    #[test]
    fn golden_transcript_and_digest() {
        let value = binding();
        // Expected digest is generated independently with Python hashlib and
        // struct.pack over the specified domain, version, and ordered frames.
        assert_eq!(value.digest_sha384().unwrap(), "ded556a34b417b849256926ed6020ff711638d6db38174dc5bcb199d4382ab283882695f92f290cd02d4e236462c731d");
        let bytes = value.canonical_bytes().unwrap();
        assert_eq!(bytes.len(), 334);
        assert_eq!(&bytes[..18], b"QLAD-EXEC-PROOF\0\0\x01");
        assert_eq!(
            GcpBootBindingV1::decode(&value.encode().unwrap()).unwrap(),
            value
        );
    }

    #[test]
    fn every_commitment_and_its_position_changes_binding() {
        let value = binding();
        let expected = value.digest_sha384().unwrap();
        for index in 0..4 {
            let mut changed = value.clone();
            let fields = [
                &mut changed.config_sha384,
                &mut changed.producer_core_sha384,
                &mut changed.artifact_manifest_sha384,
                &mut changed.reference_policy_sha384,
            ];
            *fields.into_iter().nth(index).unwrap() = hex(&[5; 48]);
            assert_ne!(changed.digest_sha384().unwrap(), expected);
        }
        let mut swapped = value;
        std::mem::swap(
            &mut swapped.config_sha384,
            &mut swapped.producer_core_sha384,
        );
        assert_ne!(swapped.digest_sha384().unwrap(), expected);
    }

    #[test]
    fn rejects_zero_malformed_and_noncanonical_hashes_in_every_position() {
        for index in 0..4 {
            for invalid in [
                "00".repeat(48),
                "AB".repeat(48),
                "ab".repeat(47),
                "gg".repeat(48),
            ] {
                let mut value = binding();
                let fields = [
                    &mut value.config_sha384,
                    &mut value.producer_core_sha384,
                    &mut value.artifact_manifest_sha384,
                    &mut value.reference_policy_sha384,
                ];
                *fields.into_iter().nth(index).unwrap() = invalid;
                assert_eq!(value.canonical_bytes(), Err(Error::InvalidField));
                assert_eq!(value.encode(), Err(Error::InvalidField));
                assert_eq!(
                    GcpBootBindingV1::decode(&serde_json::to_vec(&value).unwrap()),
                    Err(Error::InvalidField)
                );
            }
        }
        assert_eq!(
            GcpBootBindingV1::new([0; 48], [2; 48], [3; 48], [4; 48]),
            Err(Error::InvalidField)
        );
    }

    #[test]
    fn rejects_unknown_version_purpose_and_profile_without_fallback() {
        fn rejected(value: &GcpBootBindingV1, error: Error) {
            assert_eq!(value.validate(), Err(error));
            assert_eq!(value.canonical_bytes(), Err(error));
            assert_eq!(
                GcpBootBindingV1::decode(&serde_json::to_vec(value).unwrap()),
                Err(error)
            );
        }
        let mut value = binding();
        value.version = 2;
        rejected(&value, Error::UnsupportedVersion);
        value = binding();
        value.purpose = "qlad.execution-proof.exec-quote.v1".into();
        rejected(&value, Error::WrongPurpose);
        value = binding();
        value.profile = "legacyNonzeroMrconfigV1".into();
        rejected(&value, Error::InvalidField);
    }

    #[test]
    fn strict_bounded_decoder_rejects_unknown_duplicate_and_missing_fields() {
        let value = binding();
        let wire = String::from_utf8(value.encode().unwrap()).unwrap();
        let unknown = wire.replacen('{', "{\"mrconfigid\":\"zero\",", 1);
        let duplicate = wire.replacen('{', "{\"version\":1,", 1);
        let missing = wire.replace(
            &format!("\"config_sha384\":\"{}\",", value.config_sha384),
            "",
        );
        for bytes in [unknown, duplicate, missing] {
            assert_eq!(
                GcpBootBindingV1::decode(bytes.as_bytes()),
                Err(Error::Malformed)
            );
        }
        assert_eq!(
            GcpBootBindingV1::decode(&vec![b' '; crate::MAX_WIRE_BYTES + 1]),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn json_order_and_whitespace_do_not_change_ordered_transcript() {
        let value = binding();
        let mut object = serde_json::to_value(&value).unwrap();
        // serde_json::Map's sorted serialization differs from struct field order.
        let wire = serde_json::to_vec_pretty(object.as_object_mut().unwrap()).unwrap();
        let decoded = GcpBootBindingV1::decode(&wire).unwrap();
        assert_eq!(decoded.canonical_bytes(), value.canonical_bytes());
    }
}
