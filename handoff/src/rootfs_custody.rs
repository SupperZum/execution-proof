//! Secret-free preparation records and custody transaction data.
//!
//! These wire values are not capabilities. Decoding a record, constructing a
//! receipt, or completing this pure bookkeeping state machine does not validate
//! an FD, authenticate a peer, create a rootfs lease, or permit task execution.
//! The producer must derive provenance from its retained checked preparation;
//! the receiver must retain its independently checked actual view. Their trusted
//! endpoint owners enforce that relationship. The receiver owner publishes a
//! lease that retains P and its checked view.

use crate::rootfs_offer::{RootfsOfferDraft, BACKING_ADAPTER, IMAGE_PROFILE, OFFER_WIRE_BYTES};
use ring::digest;
use serde::{de, Deserialize, Deserializer, Serialize};
use std::fmt;

pub const MAX_PROVENANCE_BYTES: usize = 1 << 20;
pub const MAX_PROVENANCE_LAYERS: usize = 32;
pub const ANNOUNCEMENT_WIRE_BYTES: usize = 272;
pub const PROVENANCE_DESCRIPTOR_WIRE_BYTES: usize = 120;
pub const VALIDATED_RECEIPT_WIRE_BYTES: usize = 352;
pub const P_COMMIT_WIRE_BYTES: usize = 496;
pub const FINALIZED_ACK_WIRE_BYTES: usize = 144;
pub const ADMISSION_DESCRIPTOR_WIRE_BYTES: usize = 72;

const HEADER: usize = 16;
const MAGIC: &[u8; 8] = b"ONB17CST";
const VERSION: u16 = 1;
const PROFILE: u8 = 1;
const ANNOUNCEMENT: u8 = 1;
const PROVENANCE_DESCRIPTOR: u8 = 2;
const VALIDATED_RECEIPT: u8 = 3;
const P_COMMIT: u8 = 4;
const FINALIZED_ACK: u8 = 5;
const ADMISSION_DESCRIPTOR: u8 = 6;
const PROVENANCE_PURPOSE: &str = "onb17/preparation-provenance/v1";
const RECORD_PURPOSE: &str = "onb17/preparation-record/v1";
const ADMISSION_PURPOSE: &str = "onb17/receiver-admission-bundle/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyError {
    InvalidLimit,
    TooLarge,
    InvalidRecord,
    NonCanonical,
    InvalidFrame,
    BindingMismatch,
    Conflict,
    NotCommitted,
    Terminal,
}
impl fmt::Display for CustodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rootfs custody data rejected: {self:?}")
    }
}
impl std::error::Error for CustodyError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureProvenance {
    pub policy_sha384: String,
    pub key_sha384: String,
    pub payload_sha384: String,
    pub signature_sha384: String,
    pub repository_sha384: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayerProvenance {
    pub original_index: u32,
    pub blob_sha256: String,
    pub descriptor_size: u64,
    pub plaintext_sha256: String,
    pub diff_id: String,
    pub tar_sha384: String,
    pub tar_bytes: u64,
    pub tar_entries: u64,
    pub packet_ordinal: u32,
    pub packet_sha384: String,
    pub kms_ciphertext_sha384: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuilderProvenance {
    pub tool_sha384: String,
    pub input_tar_sha384: String,
    pub image_sha384: String,
    pub image_bytes: u64,
    pub inodes: u64,
}

/// A bounded description, not proof that the described preparation occurred.
/// Duplicate blob/DiffID values remain distinct original layer occurrences.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationProvenance {
    pub context_sha384: String,
    pub manifest_sha256: String,
    pub config_sha256: String,
    pub credential_delivery_sha384: String,
    pub signature: SignatureProvenance,
    pub kms_key_version: String,
    #[serde(deserialize_with = "deserialize_layers")]
    pub layers: Vec<LayerProvenance>,
    pub builder: BuilderProvenance,
    pub candidate_spec_sha384: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    version: u16,
    purpose: String,
    image_profile: String,
    backing_adapter: String,
    body: T,
}

/// Only public signed statements. Credential responses and bearer/key material
/// are not part of this receiver-verification bundle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionBundle {
    #[serde(deserialize_with = "deserialize_statement")]
    pub grant: Vec<u8>,
    #[serde(deserialize_with = "deserialize_statement")]
    pub aggregate: Vec<u8>,
    #[serde(deserialize_with = "deserialize_statement")]
    pub receipt: Vec<u8>,
}
impl AdmissionBundle {
    pub fn encode(&self, max_bytes: usize) -> Result<Vec<u8>, CustodyError> {
        check_limit(max_bytes)?;
        for statement in [&self.grant, &self.aggregate, &self.receipt] {
            if statement.is_empty() || statement.len() > execution_proof_contract::MAX_WIRE_BYTES {
                return Err(CustodyError::InvalidRecord);
            }
        }
        encode_envelope(ADMISSION_PURPOSE, self, max_bytes)
    }
    pub fn decode(bytes: &[u8], max_bytes: usize) -> Result<Self, CustodyError> {
        check_wire_bound(bytes, max_bytes)?;
        let envelope: Envelope<Self> =
            serde_json::from_slice(bytes).map_err(|_| CustodyError::InvalidRecord)?;
        check_envelope(&envelope, ADMISSION_PURPOSE)?;
        let bundle = envelope.body;
        if bundle.encode(max_bytes)? != bytes {
            return Err(CustodyError::NonCanonical);
        }
        Ok(bundle)
    }
    pub fn sha384(&self, max_bytes: usize) -> Result<[u8; 48], CustodyError> {
        Ok(hash(&self.encode(max_bytes)?))
    }
}

/// Sent with exactly one sealed AdmissionBundle metadata FD.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionDescriptor {
    pub sha384: [u8; 48],
    pub byte_len: u64,
}
impl AdmissionDescriptor {
    pub fn encode(&self) -> Result<Vec<u8>, CustodyError> {
        if self.byte_len == 0 || self.byte_len > MAX_PROVENANCE_BYTES as u64 {
            return Err(CustodyError::InvalidRecord);
        }
        let mut bytes = frame(ADMISSION_DESCRIPTOR, ADMISSION_DESCRIPTOR_WIRE_BYTES);
        bytes.extend_from_slice(&self.sha384);
        push_u64(&mut bytes, self.byte_len);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, CustodyError> {
        check_header(bytes, ADMISSION_DESCRIPTOR, ADMISSION_DESCRIPTOR_WIRE_BYTES)?;
        let result = Self {
            sha384: array(bytes, 16),
            byte_len: read_u64(bytes, 64),
        };
        result.encode()?;
        Ok(result)
    }
}

impl PreparationProvenance {
    pub fn validate(&self, max_bytes: usize) -> Result<(), CustodyError> {
        self.encode(max_bytes).map(drop)
    }

    pub fn encode(&self, max_bytes: usize) -> Result<Vec<u8>, CustodyError> {
        check_limit(max_bytes)?;
        self.validate_fields()?;
        encode_envelope(PROVENANCE_PURPOSE, self, max_bytes)
    }

    pub fn decode(bytes: &[u8], max_bytes: usize) -> Result<Self, CustodyError> {
        check_wire_bound(bytes, max_bytes)?;
        let envelope: Envelope<Self> =
            serde_json::from_slice(bytes).map_err(|_| CustodyError::InvalidRecord)?;
        check_envelope(&envelope, PROVENANCE_PURPOSE)?;
        let record = envelope.body;
        if record.encode(max_bytes)? != bytes {
            return Err(CustodyError::NonCanonical);
        }
        Ok(record)
    }

    /// SHA384 of the exact canonical, purpose-tagged JSON bytes. This is also
    /// the digest checked when adopting the separately sealed metadata FD.
    pub fn sha384(&self, max_bytes: usize) -> Result<[u8; 48], CustodyError> {
        Ok(hash(&self.encode(max_bytes)?))
    }

    pub fn validate_for(&self, announcement: &CustodyAnnouncement) -> Result<(), CustodyError> {
        announcement.validate()?;
        let offer = &announcement.offer;
        if parse_hex::<48>(&self.context_sha384)? != *offer.context_sha384()
            || parse_hex::<48>(&self.candidate_spec_sha384)? != *offer.candidate_spec_sha384()
            || parse_hex::<48>(&self.builder.image_sha384)? != offer.backing().sha384
            || self.builder.image_bytes != offer.backing().byte_len
        {
            return Err(CustodyError::BindingMismatch);
        }
        let encoded = self.encode(MAX_PROVENANCE_BYTES)?;
        if encoded.len() as u64 != announcement.provenance_bytes
            || hash(&encoded) != announcement.provenance_sha384
        {
            return Err(CustodyError::BindingMismatch);
        }
        Ok(())
    }

    fn validate_fields(&self) -> Result<(), CustodyError> {
        for value in [
            &self.context_sha384,
            &self.credential_delivery_sha384,
            &self.signature.policy_sha384,
            &self.signature.key_sha384,
            &self.signature.payload_sha384,
            &self.signature.signature_sha384,
            &self.signature.repository_sha384,
            &self.builder.tool_sha384,
            &self.builder.input_tar_sha384,
            &self.builder.image_sha384,
            &self.candidate_spec_sha384,
        ] {
            parse_hex::<48>(value)?;
        }
        parse_hex::<32>(&self.manifest_sha256)?;
        parse_hex::<32>(&self.config_sha256)?;
        if self.kms_key_version.is_empty()
            || self.kms_key_version.len() > 1024
            || !self
                .kms_key_version
                .bytes()
                .all(|b| (0x21..=0x7e).contains(&b))
            || self.layers.is_empty()
            || self.layers.len() > MAX_PROVENANCE_LAYERS
        {
            return Err(CustodyError::InvalidRecord);
        }
        bounded_positive(self.builder.image_bytes)?;
        bounded_positive(self.builder.inodes)?;
        for (index, layer) in self.layers.iter().enumerate() {
            if layer.original_index != index as u32 {
                return Err(CustodyError::InvalidRecord);
            }
            parse_hex::<32>(&layer.blob_sha256)?;
            parse_hex::<32>(&layer.plaintext_sha256)?;
            parse_hex::<32>(
                layer
                    .diff_id
                    .strip_prefix("sha256:")
                    .ok_or(CustodyError::InvalidRecord)?,
            )?;
            for value in [
                &layer.tar_sha384,
                &layer.packet_sha384,
                &layer.kms_ciphertext_sha384,
            ] {
                parse_hex::<48>(value)?;
            }
            bounded_positive(layer.descriptor_size)?;
            bounded_positive(layer.tar_bytes)?;
            if layer.tar_entries > isize::MAX as u64 {
                return Err(CustodyError::InvalidRecord);
            }
        }
        Ok(())
    }
}

/// Data sent with exactly one sealed image FD. The following provenance packet
/// carries the separately sealed metadata FD, under this announcement identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyAnnouncement {
    pub offer: RootfsOfferDraft,
    pub provenance_sha384: [u8; 48],
    pub provenance_bytes: u64,
}
impl CustodyAnnouncement {
    pub fn encode(&self) -> Result<Vec<u8>, CustodyError> {
        self.validate()?;
        let mut bytes = frame(ANNOUNCEMENT, ANNOUNCEMENT_WIRE_BYTES);
        bytes.extend_from_slice(&self.offer.encode());
        bytes.extend_from_slice(&self.provenance_sha384);
        push_u64(&mut bytes, self.provenance_bytes);
        Ok(bytes)
    }
    pub fn decode(
        bytes: &[u8],
        max_backing_bytes: u64,
        max_provenance_bytes: usize,
    ) -> Result<Self, CustodyError> {
        check_header(bytes, ANNOUNCEMENT, ANNOUNCEMENT_WIRE_BYTES)?;
        check_limit(max_provenance_bytes)?;
        let result = Self {
            offer: RootfsOfferDraft::decode(
                &bytes[HEADER..HEADER + OFFER_WIRE_BYTES],
                max_backing_bytes,
            )
            .map_err(|_| CustodyError::InvalidFrame)?,
            provenance_sha384: array(bytes, 216),
            provenance_bytes: read_u64(bytes, 264),
        };
        result.validate()?;
        if result.provenance_bytes > max_provenance_bytes as u64 {
            return Err(CustodyError::TooLarge);
        }
        Ok(result)
    }
    pub fn commitment(&self) -> Result<[u8; 48], CustodyError> {
        Ok(frame_hash(
            b"onb17/custody/announcement/v1\0",
            &self.encode()?,
        ))
    }
    pub fn validate(&self) -> Result<(), CustodyError> {
        if self.provenance_bytes == 0 || self.provenance_bytes > MAX_PROVENANCE_BYTES as u64 {
            return Err(CustodyError::InvalidRecord);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenanceDescriptor {
    pub announcement_sha384: [u8; 48],
    pub provenance_sha384: [u8; 48],
    pub provenance_bytes: u64,
}
impl ProvenanceDescriptor {
    pub fn for_announcement(announcement: &CustodyAnnouncement) -> Result<Self, CustodyError> {
        Ok(Self {
            announcement_sha384: announcement.commitment()?,
            provenance_sha384: announcement.provenance_sha384,
            provenance_bytes: announcement.provenance_bytes,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>, CustodyError> {
        if self.provenance_bytes == 0 || self.provenance_bytes > MAX_PROVENANCE_BYTES as u64 {
            return Err(CustodyError::InvalidRecord);
        }
        let mut bytes = frame(PROVENANCE_DESCRIPTOR, PROVENANCE_DESCRIPTOR_WIRE_BYTES);
        bytes.extend_from_slice(&self.announcement_sha384);
        bytes.extend_from_slice(&self.provenance_sha384);
        push_u64(&mut bytes, self.provenance_bytes);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, CustodyError> {
        check_header(
            bytes,
            PROVENANCE_DESCRIPTOR,
            PROVENANCE_DESCRIPTOR_WIRE_BYTES,
        )?;
        let result = Self {
            announcement_sha384: array(bytes, 16),
            provenance_sha384: array(bytes, 64),
            provenance_bytes: read_u64(bytes, 112),
        };
        result.encode()?;
        Ok(result)
    }
    pub fn validate_for(&self, announcement: &CustodyAnnouncement) -> Result<(), CustodyError> {
        if self != &Self::for_announcement(announcement)? {
            return Err(CustodyError::BindingMismatch);
        }
        Ok(())
    }
}

/// Raw observations from the receiver. Only its actual checked-view owner may
/// send this as a validation statement over the role-authenticated channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedReceipt {
    pub announcement_sha384: [u8; 48],
    pub provenance_sha384: [u8; 48],
    pub image_sha384: [u8; 48],
    pub candidate_spec_sha384: [u8; 48],
    pub executable_sha384: [u8; 48],
    pub startup_binding_sha384: [u8; 48],
    pub receiver_nonce: [u8; 32],
    pub mount_id: u64,
    pub inodes: u64,
}
impl ValidatedReceipt {
    pub fn encode(&self) -> Result<Vec<u8>, CustodyError> {
        self.validate()?;
        let mut bytes = frame(VALIDATED_RECEIPT, VALIDATED_RECEIPT_WIRE_BYTES);
        for value in [
            &self.announcement_sha384,
            &self.provenance_sha384,
            &self.image_sha384,
            &self.candidate_spec_sha384,
            &self.executable_sha384,
            &self.startup_binding_sha384,
        ] {
            bytes.extend_from_slice(value);
        }
        bytes.extend_from_slice(&self.receiver_nonce);
        push_u64(&mut bytes, self.mount_id);
        push_u64(&mut bytes, self.inodes);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, CustodyError> {
        check_header(bytes, VALIDATED_RECEIPT, VALIDATED_RECEIPT_WIRE_BYTES)?;
        let result = Self {
            announcement_sha384: array(bytes, 16),
            provenance_sha384: array(bytes, 64),
            image_sha384: array(bytes, 112),
            candidate_spec_sha384: array(bytes, 160),
            executable_sha384: array(bytes, 208),
            startup_binding_sha384: array(bytes, 256),
            receiver_nonce: array(bytes, 304),
            mount_id: read_u64(bytes, 336),
            inodes: read_u64(bytes, 344),
        };
        result.validate()?;
        Ok(result)
    }
    pub fn commitment(&self) -> Result<[u8; 48], CustodyError> {
        Ok(frame_hash(
            b"onb17/custody/validated-receipt/v1\0",
            &self.encode()?,
        ))
    }
    pub fn validate_for(&self, announcement: &CustodyAnnouncement) -> Result<(), CustodyError> {
        self.validate()?;
        if self.announcement_sha384 != announcement.commitment()?
            || self.provenance_sha384 != announcement.provenance_sha384
            || self.image_sha384 != announcement.offer.backing().sha384
            || self.candidate_spec_sha384 != *announcement.offer.candidate_spec_sha384()
        {
            return Err(CustodyError::BindingMismatch);
        }
        Ok(())
    }
    fn validate(&self) -> Result<(), CustodyError> {
        if self.receiver_nonce == [0; 32] {
            return Err(CustodyError::InvalidRecord);
        }
        bounded_positive(self.mount_id)?;
        bounded_positive(self.inodes)
    }
}

/// Exportable P data. Possession or decoding does not grant a usable lease.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationRecord {
    pub context_sha384: String,
    pub offer_sha384: String,
    pub provenance_sha384: String,
    pub validated_receipt_sha384: String,
    pub image_sha384: String,
    pub candidate_spec_sha384: String,
    pub executable_sha384: String,
    pub startup_binding_sha384: String,
    pub receiver_nonce: String,
    pub mount_id: u64,
    pub inodes: u64,
}
impl PreparationRecord {
    pub fn encode(&self, max_bytes: usize) -> Result<Vec<u8>, CustodyError> {
        check_limit(max_bytes)?;
        self.validate()?;
        encode_envelope(RECORD_PURPOSE, self, max_bytes)
    }
    pub fn decode(bytes: &[u8], max_bytes: usize) -> Result<Self, CustodyError> {
        check_wire_bound(bytes, max_bytes)?;
        let envelope: Envelope<Self> =
            serde_json::from_slice(bytes).map_err(|_| CustodyError::InvalidRecord)?;
        check_envelope(&envelope, RECORD_PURPOSE)?;
        let record = envelope.body;
        if record.encode(max_bytes)? != bytes {
            return Err(CustodyError::NonCanonical);
        }
        Ok(record)
    }
    pub fn sha384(&self) -> Result<[u8; 48], CustodyError> {
        Ok(hash(&self.encode(MAX_PROVENANCE_BYTES)?))
    }
    fn validate(&self) -> Result<(), CustodyError> {
        for value in [
            &self.context_sha384,
            &self.offer_sha384,
            &self.provenance_sha384,
            &self.validated_receipt_sha384,
            &self.image_sha384,
            &self.candidate_spec_sha384,
            &self.executable_sha384,
            &self.startup_binding_sha384,
        ] {
            parse_hex::<48>(value)?;
        }
        if parse_hex::<32>(&self.receiver_nonce)? == [0; 32] {
            return Err(CustodyError::InvalidRecord);
        }
        bounded_positive(self.mount_id)?;
        bounded_positive(self.inodes)
    }
    fn for_validation(
        announcement: &CustodyAnnouncement,
        receipt: &ValidatedReceipt,
    ) -> Result<Self, CustodyError> {
        receipt.validate_for(announcement)?;
        Ok(Self {
            context_sha384: hex(announcement.offer.context_sha384()),
            offer_sha384: hex(&announcement.offer.commitment()),
            provenance_sha384: hex(&announcement.provenance_sha384),
            validated_receipt_sha384: hex(&receipt.commitment()?),
            image_sha384: hex(&receipt.image_sha384),
            candidate_spec_sha384: hex(&receipt.candidate_spec_sha384),
            executable_sha384: hex(&receipt.executable_sha384),
            startup_binding_sha384: hex(&receipt.startup_binding_sha384),
            receiver_nonce: hex(&receipt.receiver_nonce),
            mount_id: receipt.mount_id,
            inodes: receipt.inodes,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PCommit {
    pub record: PreparationRecord,
    pub record_sha384: [u8; 48],
}
impl PCommit {
    pub fn encode(&self) -> Result<Vec<u8>, CustodyError> {
        self.validate()?;
        let mut bytes = frame(P_COMMIT, P_COMMIT_WIRE_BYTES);
        for value in [
            &self.record.context_sha384,
            &self.record.offer_sha384,
            &self.record.provenance_sha384,
            &self.record.validated_receipt_sha384,
            &self.record.image_sha384,
            &self.record.candidate_spec_sha384,
            &self.record.executable_sha384,
            &self.record.startup_binding_sha384,
        ] {
            bytes.extend_from_slice(&parse_hex::<48>(value)?);
        }
        bytes.extend_from_slice(&parse_hex::<32>(&self.record.receiver_nonce)?);
        push_u64(&mut bytes, self.record.mount_id);
        push_u64(&mut bytes, self.record.inodes);
        bytes.extend_from_slice(&self.record_sha384);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, CustodyError> {
        check_header(bytes, P_COMMIT, P_COMMIT_WIRE_BYTES)?;
        let result = Self {
            record: PreparationRecord {
                context_sha384: hex(&bytes[16..64]),
                offer_sha384: hex(&bytes[64..112]),
                provenance_sha384: hex(&bytes[112..160]),
                validated_receipt_sha384: hex(&bytes[160..208]),
                image_sha384: hex(&bytes[208..256]),
                candidate_spec_sha384: hex(&bytes[256..304]),
                executable_sha384: hex(&bytes[304..352]),
                startup_binding_sha384: hex(&bytes[352..400]),
                receiver_nonce: hex(&bytes[400..432]),
                mount_id: read_u64(bytes, 432),
                inodes: read_u64(bytes, 440),
            },
            record_sha384: array(bytes, 448),
        };
        result.validate()?;
        Ok(result)
    }
    pub fn validate_for(
        &self,
        announcement: &CustodyAnnouncement,
        receipt: &ValidatedReceipt,
    ) -> Result<(), CustodyError> {
        self.validate()?;
        if self.record != PreparationRecord::for_validation(announcement, receipt)? {
            return Err(CustodyError::BindingMismatch);
        }
        Ok(())
    }
    fn validate(&self) -> Result<(), CustodyError> {
        if self.record.sha384()? != self.record_sha384 {
            return Err(CustodyError::BindingMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedAck {
    pub announcement_sha384: [u8; 48],
    pub record_sha384: [u8; 48],
    pub receiver_nonce: [u8; 32],
}
impl FinalizedAck {
    pub fn for_commit(
        announcement: &CustodyAnnouncement,
        commit: &PCommit,
    ) -> Result<Self, CustodyError> {
        commit.validate()?;
        if commit.record.offer_sha384 != hex(&announcement.offer.commitment())
            || commit.record.provenance_sha384 != hex(&announcement.provenance_sha384)
            || commit.record.context_sha384 != hex(announcement.offer.context_sha384())
            || commit.record.image_sha384 != hex(&announcement.offer.backing().sha384)
            || commit.record.candidate_spec_sha384
                != hex(announcement.offer.candidate_spec_sha384())
        {
            return Err(CustodyError::BindingMismatch);
        }
        Ok(Self {
            announcement_sha384: announcement.commitment()?,
            record_sha384: commit.record_sha384,
            receiver_nonce: parse_hex::<32>(&commit.record.receiver_nonce)?,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>, CustodyError> {
        if self.receiver_nonce == [0; 32] {
            return Err(CustodyError::InvalidRecord);
        }
        let mut bytes = frame(FINALIZED_ACK, FINALIZED_ACK_WIRE_BYTES);
        bytes.extend_from_slice(&self.announcement_sha384);
        bytes.extend_from_slice(&self.record_sha384);
        bytes.extend_from_slice(&self.receiver_nonce);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, CustodyError> {
        check_header(bytes, FINALIZED_ACK, FINALIZED_ACK_WIRE_BYTES)?;
        let result = Self {
            announcement_sha384: array(bytes, 16),
            record_sha384: array(bytes, 64),
            receiver_nonce: array(bytes, 112),
        };
        result.encode()?;
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyProgress {
    First,
    Historical,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProducerStatus {
    AwaitingValidation,
    Committed,
    Finalized,
    Aborted,
    Unknown,
}

/// One still-live producer transaction. Trusted outer ownership retains its
/// checked preparation, exact provenance and authenticated role channel.
pub struct ProducerTransaction {
    announcement: CustodyAnnouncement,
    validated: Option<ValidatedReceipt>,
    commit: Option<PCommit>,
    status: ProducerStatus,
}
impl ProducerTransaction {
    pub fn new(announcement: CustodyAnnouncement) -> Result<Self, CustodyError> {
        announcement.validate()?;
        Ok(Self {
            announcement,
            validated: None,
            commit: None,
            status: ProducerStatus::AwaitingValidation,
        })
    }
    pub fn announcement(&self) -> &CustodyAnnouncement {
        &self.announcement
    }
    pub fn status(&self) -> ProducerStatus {
        self.status
    }
    pub fn committed(&self) -> Option<&PCommit> {
        if matches!(
            self.status,
            ProducerStatus::Committed | ProducerStatus::Finalized
        ) {
            self.commit.as_ref()
        } else {
            None
        }
    }
    pub fn validated(
        &mut self,
        receipt: &ValidatedReceipt,
    ) -> Result<(PCommit, CustodyProgress), CustodyError> {
        if matches!(
            self.status,
            ProducerStatus::Aborted | ProducerStatus::Unknown
        ) {
            return Err(CustodyError::Terminal);
        }
        if let Some(previous) = &self.validated {
            if previous != receipt {
                self.status = ProducerStatus::Unknown;
                return Err(CustodyError::Conflict);
            }
            return self
                .commit
                .clone()
                .map(|commit| (commit, CustodyProgress::Historical))
                .ok_or(CustodyError::NotCommitted);
        }
        let record = match PreparationRecord::for_validation(&self.announcement, receipt) {
            Ok(record) => record,
            Err(error) => {
                self.status = ProducerStatus::Unknown;
                return Err(error);
            }
        };
        let commit = PCommit {
            record_sha384: record.sha384()?,
            record,
        };
        self.validated = Some(receipt.clone());
        self.commit = Some(commit.clone());
        self.status = ProducerStatus::Committed;
        Ok((commit, CustodyProgress::First))
    }
    pub fn finalized(&mut self, ack: &FinalizedAck) -> Result<CustodyProgress, CustodyError> {
        if matches!(
            self.status,
            ProducerStatus::Aborted | ProducerStatus::Unknown
        ) {
            return Err(CustodyError::Terminal);
        }
        let Some(commit) = self.commit.as_ref() else {
            self.status = ProducerStatus::Aborted;
            return Err(CustodyError::NotCommitted);
        };
        if ack != &FinalizedAck::for_commit(&self.announcement, commit)? {
            self.status = ProducerStatus::Unknown;
            return Err(CustodyError::Conflict);
        }
        let progress = if self.status == ProducerStatus::Finalized {
            CustodyProgress::Historical
        } else {
            CustodyProgress::First
        };
        self.status = ProducerStatus::Finalized;
        Ok(progress)
    }
    pub fn abort(&mut self) {
        self.status = if self.status == ProducerStatus::AwaitingValidation
            || self.status == ProducerStatus::Aborted
        {
            ProducerStatus::Aborted
        } else {
            ProducerStatus::Unknown
        };
    }
}

fn check_limit(max_bytes: usize) -> Result<(), CustodyError> {
    if max_bytes == 0 || max_bytes > MAX_PROVENANCE_BYTES {
        Err(CustodyError::InvalidLimit)
    } else {
        Ok(())
    }
}
fn check_wire_bound(bytes: &[u8], max_bytes: usize) -> Result<(), CustodyError> {
    check_limit(max_bytes)?;
    if bytes.len() > max_bytes {
        Err(CustodyError::TooLarge)
    } else {
        Ok(())
    }
}
fn bounded_positive(value: u64) -> Result<(), CustodyError> {
    if value == 0 || value > isize::MAX as u64 {
        Err(CustodyError::InvalidRecord)
    } else {
        Ok(())
    }
}
fn encode_envelope(
    body_purpose: &str,
    body: &impl Serialize,
    max_bytes: usize,
) -> Result<Vec<u8>, CustodyError> {
    let envelope = Envelope {
        version: VERSION,
        purpose: body_purpose.to_owned(),
        image_profile: IMAGE_PROFILE.to_owned(),
        backing_adapter: BACKING_ADAPTER.to_owned(),
        body,
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|_| CustodyError::InvalidRecord)?;
    if bytes.len() > max_bytes {
        Err(CustodyError::TooLarge)
    } else {
        Ok(bytes)
    }
}
fn check_envelope<T>(envelope: &Envelope<T>, purpose: &str) -> Result<(), CustodyError> {
    if envelope.version != VERSION
        || envelope.purpose != purpose
        || envelope.image_profile != IMAGE_PROFILE
        || envelope.backing_adapter != BACKING_ADAPTER
    {
        Err(CustodyError::InvalidRecord)
    } else {
        Ok(())
    }
}
fn hash(bytes: &[u8]) -> [u8; 48] {
    let value = digest::digest(&digest::SHA384, bytes);
    let mut result = [0; 48];
    result.copy_from_slice(value.as_ref());
    result
}
fn frame_hash(domain: &[u8], bytes: &[u8]) -> [u8; 48] {
    let mut context = digest::Context::new(&digest::SHA384);
    context.update(domain);
    context.update(bytes);
    let mut result = [0; 48];
    result.copy_from_slice(context.finish().as_ref());
    result
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn parse_hex<const N: usize>(value: &str) -> Result<[u8; N], CustodyError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CustodyError::InvalidRecord);
    }
    let mut result = [0; N];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        result[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Ok(result)
}
fn frame(purpose: u8, capacity: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(purpose);
    bytes.push(PROFILE);
    bytes.extend_from_slice(&[0; 4]);
    bytes
}
fn check_header(bytes: &[u8], purpose: u8, len: usize) -> Result<(), CustodyError> {
    if bytes.len() != len
        || bytes[..8] != *MAGIC
        || bytes[8..10] != VERSION.to_be_bytes()
        || bytes[10] != purpose
        || bytes[11] != PROFILE
        || bytes[12..16] != [0; 4]
    {
        Err(CustodyError::InvalidFrame)
    } else {
        Ok(())
    }
}
fn array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut result = [0; N];
    result.copy_from_slice(&bytes[offset..offset + N]);
    result
}
fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}
fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(array(bytes, offset))
}

fn deserialize_layers<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<LayerProvenance>, D::Error> {
    struct Layers;
    impl<'de> de::Visitor<'de> for Layers {
        type Value = Vec<LayerProvenance>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("at most32 ordered original layers")
        }
        fn visit_seq<A: de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> Result<Self::Value, A::Error> {
            let mut layers = Vec::new();
            while let Some(layer) = sequence.next_element()? {
                if layers.len() == MAX_PROVENANCE_LAYERS {
                    return Err(de::Error::custom("too many preparation layers"));
                }
                layers.push(layer);
            }
            Ok(layers)
        }
    }
    deserializer.deserialize_seq(Layers)
}

fn deserialize_statement<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    struct Statement;
    impl<'de> de::Visitor<'de> for Statement {
        type Value = Vec<u8>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded public signed-statement byte array")
        }
        fn visit_seq<A: de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> Result<Self::Value, A::Error> {
            let mut bytes = Vec::new();
            while let Some(byte) = sequence.next_element()? {
                if bytes.len() == execution_proof_contract::MAX_WIRE_BYTES {
                    return Err(de::Error::custom("signed statement exceeds its wire bound"));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }
    deserializer.deserialize_seq(Statement)
}

#[cfg(test)]
#[path = "rootfs_custody_tests.rs"]
mod tests;
