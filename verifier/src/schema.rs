//! Flat local-only wire objects. References are hashes, never paths or URLs.

use crate::{hex_field, identifier, VerificationError};
use base64::{engine::general_purpose::STANDARD, Engine};
use execution_proof_contract::policy_receipt::LaunchPolicyAggregateV1;
use serde::{de, Deserialize, Deserializer, Serialize};
use std::fmt;

pub const PACK_PURPOSE: &str = "qlad.execution-proof.local-execution-pack.v1";
pub const TRUST_PURPOSE: &str = "qlad.execution-proof.verifier-trust.v1";
pub const MAX_PACK_BYTES: usize = 16 << 20;
pub const MAX_OBJECT_BYTES: usize = 4 << 20;
pub const MAX_OBJECTS: usize = 64;
pub const MAX_TRUST_BYTES: usize = 1 << 20;
pub const MAX_PROTECTED_EXPORT_BYTES: usize = 12 << 20;
pub const MAX_JSON_DEPTH: usize = 16;
const EMBEDDED_OBJECTS: usize = 11;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    AsPolicy,
    AsInput,
    AsData,
    KbsPolicy,
    KbsInput,
    KbsData,
    AdmissionPolicy,
    ImagePolicy,
    ProducerProfile,
    TrustSnapshot,
    DcapCollateral,
    PrelaunchEvidence,
    SignatureKey,
    SignaturePayload,
    Signature,
    SignatureRepository,
    GcpConfig,
    GcpArtifactManifest,
    GcpReferencePolicy,
    GcpArtifactClosure,
    GcpFirmwareCausality,
    GcpProducerIsolation,
    GcpNoStateCopy,
    GcpQualificationReview,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportingObject {
    pub kind: ObjectKind,
    pub sha384: String,
    #[serde(deserialize_with = "object_bytes")]
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePack {
    pub version: u16,
    pub purpose: String,
    #[serde(deserialize_with = "object_bytes")]
    pub admission: Vec<u8>,
    #[serde(deserialize_with = "object_bytes")]
    pub preparation: Vec<u8>,
    #[serde(deserialize_with = "object_bytes")]
    pub provenance: Vec<u8>,
    #[serde(deserialize_with = "object_bytes")]
    pub announcement: Vec<u8>,
    #[serde(deserialize_with = "object_bytes")]
    pub validated_receipt: Vec<u8>,
    #[serde(deserialize_with = "control_bytes")]
    pub record: Vec<u8>,
    #[serde(deserialize_with = "object_bytes")]
    pub quote: Vec<u8>,
    #[serde(deserialize_with = "control_bytes")]
    pub credential_receipt: Vec<u8>,
    #[serde(deserialize_with = "supporting_objects")]
    pub objects: Vec<SupportingObject>,
}

impl EvidencePack {
    /// Assemble public bytes from the protected exporter. This checks only the
    /// transport; the resulting pack still needs the independent graph/TDX flow.
    pub fn from_protected_export(
        export_bytes: &[u8],
        credential_receipt: Vec<u8>,
        objects: Vec<SupportingObject>,
    ) -> Result<Self, VerificationError> {
        Self::from_scoped_protected_export(
            export_bytes,
            credential_receipt,
            objects,
            1,
            "qlad.execution-proof.protected-export.v1",
        )
    }
    pub(crate) fn from_scoped_protected_export(
        export_bytes: &[u8],
        credential_receipt: Vec<u8>,
        objects: Vec<SupportingObject>,
        version: u16,
        purpose: &str,
    ) -> Result<Self, VerificationError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ExportWire {
            version: u16,
            purpose: String,
            record_b64: String,
            admission_b64: String,
            preparation_b64: String,
            provenance_b64: String,
            announcement_b64: String,
            validated_receipt_b64: String,
            quote_b64: String,
        }
        fn field(value: String, limit: usize) -> Result<Vec<u8>, VerificationError> {
            if value.len() > limit.div_ceil(3) * 4 {
                return Err(VerificationError::ResourceLimit("protected_export_field"));
            }
            let bytes = STANDARD
                .decode(&value)
                .map_err(|_| VerificationError::Invalid("protected_export_base64"))?;
            bounded_bytes(&bytes, limit)?;
            if STANDARD.encode(&bytes) != value {
                return Err(VerificationError::Invalid("protected_export_base64"));
            }
            Ok(bytes)
        }
        let export: ExportWire = decode(export_bytes, MAX_PROTECTED_EXPORT_BYTES)?;
        if export.version != version || export.purpose != purpose {
            return Err(VerificationError::Invalid("protected_export_domain"));
        }
        let pack = Self {
            version: 1,
            purpose: PACK_PURPOSE.into(),
            record: field(export.record_b64, 16 << 10)?,
            admission: field(export.admission_b64, 1 << 20)?,
            preparation: field(export.preparation_b64, 1 << 20)?,
            provenance: field(export.provenance_b64, 1 << 20)?,
            announcement: field(
                export.announcement_b64,
                execution_proof_handoff::rootfs_custody::ANNOUNCEMENT_WIRE_BYTES,
            )?,
            validated_receipt: field(
                export.validated_receipt_b64,
                execution_proof_handoff::rootfs_custody::VALIDATED_RECEIPT_WIRE_BYTES,
            )?,
            quote: field(
                export.quote_b64,
                execution_proof_contract::execution_quote::MAX_QUOTE_ENVELOPE_BYTES,
            )?,
            credential_receipt,
            objects,
        };
        pack.validate()?;
        encode(&pack, MAX_PACK_BYTES)?;
        Ok(pack)
    }
    pub fn validate(&self) -> Result<(), VerificationError> {
        if self.version != 1 || self.purpose != PACK_PURPOSE {
            return Err(VerificationError::Invalid("pack_domain"));
        }
        if self.objects.len() + EMBEDDED_OBJECTS > MAX_OBJECTS {
            return Err(VerificationError::ResourceLimit("object_count"));
        }
        for bytes in [
            &self.admission,
            &self.preparation,
            &self.provenance,
            &self.announcement,
            &self.validated_receipt,
            &self.record,
            &self.quote,
            &self.credential_receipt,
        ] {
            bounded_bytes(bytes, MAX_OBJECT_BYTES)?;
            encode(bytes, MAX_OBJECT_BYTES)?;
        }
        for bytes in [&self.record, &self.credential_receipt] {
            bounded_bytes(bytes, 16 << 10)?;
        }
        for object in &self.objects {
            hex_field(&object.sha384, 48)?;
            bounded_bytes(&object.bytes, MAX_OBJECT_BYTES)?;
            encode(object, MAX_OBJECT_BYTES)?;
        }
        Ok(())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, VerificationError> {
        let value: Self = decode(bytes, MAX_PACK_BYTES)?;
        value.validate()?;
        Ok(value)
    }
    pub fn encode(&self) -> Result<Vec<u8>, VerificationError> {
        self.validate()?;
        encode(self, MAX_PACK_BYTES)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantTrust {
    pub authority_public_key: [u8; 32],
    pub audience: String,
    pub authority: String,
    pub tenant: String,
    pub profile_sha384: String,
    pub launch_policy_sha384: String,
    pub image_policy_sha384: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionTrust {
    pub audience: String,
    pub issuer: String,
    pub boot_id: String,
    pub attempt_id: String,
    pub guest_nonce: String,
    pub admission_policy_sha384: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialTrust {
    pub audience: String,
    pub issuer: String,
    pub keywrap_sha384: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteTrust {
    pub audience: String,
    pub producer_profile_sha384: String,
    pub trust_snapshot_sha384: String,
    pub mr_config_id: String,
    pub mr_td: String,
    pub rtmrs: [String; 4],
    /// An operator's independently reviewed measurement-to-producer mapping.
    /// A pack cannot enable this or supply its own accepted measurements.
    pub producer_isolation_qualified: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustConfig {
    pub version: u16,
    pub purpose: String,
    pub grant: GrantTrust,
    pub aggregate_public_key: [u8; 32],
    pub aggregate_expected: LaunchPolicyAggregateV1,
    pub admission: AdmissionTrust,
    pub credential: CredentialTrust,
    pub quote: QuoteTrust,
}

impl TrustConfig {
    pub fn validate(&self) -> Result<(), VerificationError> {
        if self.version != 1 || self.purpose != TRUST_PURPOSE {
            return Err(VerificationError::Invalid("trust_domain"));
        }
        for value in [
            &self.grant.audience,
            &self.grant.authority,
            &self.grant.tenant,
            &self.admission.audience,
            &self.admission.issuer,
            &self.admission.boot_id,
            &self.admission.attempt_id,
            &self.credential.audience,
            &self.credential.issuer,
            &self.quote.audience,
        ] {
            identifier(value)?;
        }
        for value in [
            &self.grant.profile_sha384,
            &self.grant.launch_policy_sha384,
            &self.grant.image_policy_sha384,
            &self.admission.admission_policy_sha384,
            &self.credential.keywrap_sha384,
            &self.quote.producer_profile_sha384,
            &self.quote.trust_snapshot_sha384,
            &self.quote.mr_config_id,
            &self.quote.mr_td,
        ] {
            hex_field(value, 48)?;
        }
        for value in &self.quote.rtmrs {
            hex_field(value, 48)?;
        }
        if self.admission.guest_nonce.is_empty()
            || self.admission.guest_nonce.len() > 256
            || !self.admission.guest_nonce.is_ascii()
        {
            return Err(VerificationError::Invalid("guest_nonce"));
        }
        self.aggregate_expected
            .signing_bytes()
            .map_err(|_| VerificationError::Invalid("aggregate_expectations"))?;
        Ok(())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, VerificationError> {
        let value: Self = decode(bytes, MAX_TRUST_BYTES)?;
        value.validate()?;
        Ok(value)
    }
    pub fn encode(&self) -> Result<Vec<u8>, VerificationError> {
        self.validate()?;
        encode(self, MAX_TRUST_BYTES)
    }
}

pub fn bounded_bytes(bytes: &[u8], maximum: usize) -> Result<(), VerificationError> {
    if bytes.is_empty() {
        return Err(VerificationError::MissingEvidence("empty_object"));
    }
    if bytes.len() > maximum {
        return Err(VerificationError::ResourceLimit("object_bytes"));
    }
    Ok(())
}

pub fn decode<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, VerificationError> {
    bounded_bytes(bytes, maximum)?;
    json_depth(bytes)?;
    serde_json::from_slice(bytes).map_err(|_| VerificationError::Invalid("malformed_json"))
}

pub fn encode<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>, VerificationError> {
    let mut output = LimitedOutput {
        bytes: Vec::new(),
        maximum,
    };
    serde_json::to_writer(&mut output, value)
        .map_err(|_| VerificationError::ResourceLimit("serialized_bytes"))?;
    Ok(output.bytes)
}

struct LimitedOutput {
    bytes: Vec<u8>,
    maximum: usize,
}
impl std::io::Write for LimitedOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("serialization limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn json_depth(bytes: &[u8]) -> Result<(), VerificationError> {
    let (mut depth, mut string, mut escaped) = (0usize, false, false);
    for byte in bytes {
        if string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                string = false;
            }
        } else {
            match byte {
                b'"' => string = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > MAX_JSON_DEPTH {
                        return Err(VerificationError::ResourceLimit("json_depth"));
                    }
                }
                b'}' | b']' => {
                    depth = depth
                        .checked_sub(1)
                        .ok_or(VerificationError::Invalid("json_structure"))?;
                }
                _ => (),
            }
        }
    }
    Ok(())
}

fn bytes<'de, D: Deserializer<'de>, const MAX: usize>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    struct Bytes<const MAX: usize>;
    impl<'de, const MAX: usize> de::Visitor<'de> for Bytes<MAX> {
        type Value = Vec<u8>;
        fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
            out.write_str("bounded nonempty bytes")
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            let mut bytes = Vec::new();
            while let Some(byte) = seq.next_element::<u8>()? {
                if bytes.len() == MAX {
                    return Err(de::Error::custom("object byte limit"));
                }
                bytes.push(byte);
            }
            if bytes.is_empty() {
                return Err(de::Error::custom("empty object"));
            }
            Ok(bytes)
        }
    }
    deserializer.deserialize_seq(Bytes::<MAX>)
}
pub fn object_bytes<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    bytes::<D, MAX_OBJECT_BYTES>(d)
}
pub fn control_bytes<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    bytes::<D, { 16 << 10 }>(d)
}
pub fn evidence_bytes<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    bytes::<D, { 1 << 20 }>(d)
}

fn supporting_objects<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<SupportingObject>, D::Error> {
    struct Objects;
    impl<'de> de::Visitor<'de> for Objects {
        type Value = Vec<SupportingObject>;
        fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
            out.write_str("bounded supporting objects")
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut result = Vec::new();
            while let Some(value) = seq.next_element()? {
                if result.len() + EMBEDDED_OBJECTS == MAX_OBJECTS {
                    return Err(de::Error::custom("object count"));
                }
                result.push(value);
            }
            Ok(result)
        }
    }
    d.deserialize_seq(Objects)
}
