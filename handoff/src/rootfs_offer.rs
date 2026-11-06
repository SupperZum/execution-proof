//! Non-authorizing rootfs offer envelopes and boot-local transfer bookkeeping.
//!
//! An envelope receipt says only that the peer retained this exact metadata. It
//! does not authenticate the peer, verify a received FD, validate a mounted view,
//! or create a preparation record, rootfs lease, or permission to start. Callers
//! must use a private channel whose endpoints belong to trusted startup roles.
//! Each state owner belongs to one still-live admission attempt. It must not be
//! recreated after cancellation, restart, or uncertain delivery to recover the
//! old attempt. This is bounded local state, not durable replay protection.

use crate::admission::AcceptedAttemptContext;
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use std::fmt;

pub const OFFER_WIRE_BYTES: usize = 200;
pub const RECEIPT_WIRE_BYTES: usize = 96;
pub const BACKING_ADAPTER: &str = "private-ro-ramfs-v1";
pub const IMAGE_PROFILE: &str = "erofs-utils-1.8.10/4096/extended/plain/single-device/v1";
const MAGIC: &[u8; 8] = b"ONB17OFR";
const VERSION: u16 = 1;
const OFFER_PURPOSE: u8 = 1;
const RECEIPT_PURPOSE: u8 = 2;
// Wire profile 1 fixes both IMAGE_PROFILE and BACKING_ADAPTER. A change to
// either representation requires a distinct profile rather than new defaults.
const PROFILE: u8 = 1;
const OFFER_DOMAIN: &[u8] = b"onb17/rootfs-offer/envelope/v1\0";
const RECEIPT_DOMAIN: &[u8] = b"onb17/rootfs-offer/envelope-receipt/v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfferError {
    InvalidLimit,
    InvalidContextDigest,
    InvalidFrame,
    UnsupportedVersion,
    UnsupportedPurpose,
    UnsupportedProfile,
    InvalidNonce,
    EmptyBacking,
    BackingTooLarge,
    EntropyUnavailable,
    BindingMismatch,
    Conflict,
    NotSent,
    NotReceived,
    Terminal,
}

impl fmt::Display for OfferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rootfs offer rejected: {self:?}")
    }
}
impl std::error::Error for OfferError {}

/// Untrusted byte-description metadata, never a checked backing capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackingDescriptor {
    pub sha384: [u8; 48],
    pub byte_len: u64,
}

/// A transport draft with no content, custody, admission, or execution authority.
/// Decoded drafts have exactly the same non-authorizing status as new drafts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootfsOfferDraft {
    context_sha384: [u8; 48],
    transfer_nonce: [u8; 32],
    backing: BackingDescriptor,
    candidate_spec_sha384: [u8; 48],
}

impl RootfsOfferDraft {
    /// Generate one fresh transfer nonce from the live accepted context. The
    /// caller still must derive the backing descriptor from its checked owner.
    pub fn new(
        context: &AcceptedAttemptContext,
        backing: BackingDescriptor,
        max_backing_bytes: u64,
    ) -> Result<Self, OfferError> {
        let candidate_spec_sha384 = decode_digest(&context.binding().effective_launch_sha384)?;
        let nonce = fresh_nonce()?;
        Self::from_context_fields(
            context.context_digest(),
            &context.binding().effective_launch_sha384,
            backing,
            candidate_spec_sha384,
            max_backing_bytes,
            nonce,
        )
    }

    fn from_context_fields(
        context_digest: &str,
        expected_spec_digest: &str,
        backing: BackingDescriptor,
        candidate_spec_sha384: [u8; 48],
        max_backing_bytes: u64,
        transfer_nonce: [u8; 32],
    ) -> Result<Self, OfferError> {
        let context_sha384 = decode_digest(context_digest)?;
        let expected_spec = decode_digest(expected_spec_digest)?;
        if expected_spec != candidate_spec_sha384 {
            return Err(OfferError::BindingMismatch);
        }
        check_backing(backing, max_backing_bytes)?;
        check_nonce(&transfer_nonce)?;
        Ok(Self {
            context_sha384,
            transfer_nonce,
            backing,
            candidate_spec_sha384,
        })
    }

    pub fn context_sha384(&self) -> &[u8; 48] {
        &self.context_sha384
    }
    pub fn transfer_nonce(&self) -> &[u8; 32] {
        &self.transfer_nonce
    }
    pub fn backing(&self) -> BackingDescriptor {
        self.backing
    }
    pub fn candidate_spec_sha384(&self) -> &[u8; 48] {
        &self.candidate_spec_sha384
    }
    pub fn backing_adapter(&self) -> &'static str {
        BACKING_ADAPTER
    }
    pub fn image_profile(&self) -> &'static str {
        IMAGE_PROFILE
    }

    pub fn encode(&self) -> [u8; OFFER_WIRE_BYTES] {
        let mut bytes = [0; OFFER_WIRE_BYTES];
        write_header(&mut bytes, OFFER_PURPOSE);
        bytes[16..64].copy_from_slice(&self.context_sha384);
        bytes[64..96].copy_from_slice(&self.transfer_nonce);
        bytes[96..144].copy_from_slice(&self.backing.sha384);
        bytes[144..152].copy_from_slice(&self.backing.byte_len.to_be_bytes());
        bytes[152..200].copy_from_slice(&self.candidate_spec_sha384);
        bytes
    }

    /// Parse bounded untrusted metadata. The receiver must independently compare
    /// its context/spec expectations and verify the accompanying sealed FD.
    pub fn decode(bytes: &[u8], max_backing_bytes: u64) -> Result<Self, OfferError> {
        check_header(bytes, OFFER_WIRE_BYTES, OFFER_PURPOSE)?;
        let mut context_sha384 = [0; 48];
        context_sha384.copy_from_slice(&bytes[16..64]);
        let mut transfer_nonce = [0; 32];
        transfer_nonce.copy_from_slice(&bytes[64..96]);
        check_nonce(&transfer_nonce)?;
        let mut sha384 = [0; 48];
        sha384.copy_from_slice(&bytes[96..144]);
        let mut length = [0; 8];
        length.copy_from_slice(&bytes[144..152]);
        let backing = BackingDescriptor {
            sha384,
            byte_len: u64::from_be_bytes(length),
        };
        check_backing(backing, max_backing_bytes)?;
        let mut candidate_spec_sha384 = [0; 48];
        candidate_spec_sha384.copy_from_slice(&bytes[152..200]);
        Ok(Self {
            context_sha384,
            transfer_nonce,
            backing,
            candidate_spec_sha384,
        })
    }

    pub fn commitment(&self) -> [u8; 48] {
        commitment(OFFER_DOMAIN, &self.encode())
    }
}

/// Receipt of an exact metadata envelope, with no validated-custody meaning.
/// Possession of this value or a successful transport syscall grants nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfferReceipt {
    transfer_nonce: [u8; 32],
    offer_sha384: [u8; 48],
}

impl OfferReceipt {
    fn for_offer(offer: &RootfsOfferDraft) -> Self {
        Self {
            transfer_nonce: *offer.transfer_nonce(),
            offer_sha384: offer.commitment(),
        }
    }
    fn matches(&self, offer: &RootfsOfferDraft) -> bool {
        self.transfer_nonce == *offer.transfer_nonce() && self.offer_sha384 == offer.commitment()
    }
    pub fn encode(&self) -> [u8; RECEIPT_WIRE_BYTES] {
        let mut bytes = [0; RECEIPT_WIRE_BYTES];
        write_header(&mut bytes, RECEIPT_PURPOSE);
        bytes[16..48].copy_from_slice(&self.transfer_nonce);
        bytes[48..96].copy_from_slice(&self.offer_sha384);
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, OfferError> {
        check_header(bytes, RECEIPT_WIRE_BYTES, RECEIPT_PURPOSE)?;
        let mut transfer_nonce = [0; 32];
        transfer_nonce.copy_from_slice(&bytes[16..48]);
        check_nonce(&transfer_nonce)?;
        let mut offer_sha384 = [0; 48];
        offer_sha384.copy_from_slice(&bytes[48..96]);
        Ok(Self {
            transfer_nonce,
            offer_sha384,
        })
    }
    pub fn commitment(&self) -> [u8; 48] {
        commitment(RECEIPT_DOMAIN, &self.encode())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfferProgress {
    First,
    Historical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SenderStatus {
    Ready,
    Sent,
    EnvelopeReceived,
    Aborted,
    Unknown,
}

/// One retained sender state per attempt. No Clone, deserialization, or restore.
pub struct SenderTransfer {
    draft: RootfsOfferDraft,
    status: SenderStatus,
}

impl SenderTransfer {
    pub fn new(draft: RootfsOfferDraft) -> Self {
        Self {
            draft,
            status: SenderStatus::Ready,
        }
    }
    pub fn draft(&self) -> &RootfsOfferDraft {
        &self.draft
    }
    pub fn status(&self) -> SenderStatus {
        self.status
    }

    /// Record delivery intent before a syscall or await can have remote effects.
    /// `Sent` means delivery may have occurred, not that sendmsg succeeded.
    /// Exact retransmission retains the same nonce and metadata. A received
    /// envelope is historical and must not initiate a new transfer.
    pub fn mark_sent(&mut self) -> Result<OfferProgress, OfferError> {
        match self.status {
            SenderStatus::Ready => {
                self.status = SenderStatus::Sent;
                Ok(OfferProgress::First)
            }
            SenderStatus::Sent | SenderStatus::EnvelopeReceived => Ok(OfferProgress::Historical),
            SenderStatus::Aborted | SenderStatus::Unknown => Err(OfferError::Terminal),
        }
    }
    pub fn accept_receipt(&mut self, receipt: &OfferReceipt) -> Result<OfferProgress, OfferError> {
        if matches!(self.status, SenderStatus::Aborted | SenderStatus::Unknown) {
            return Err(OfferError::Terminal);
        }
        if self.status == SenderStatus::Ready {
            self.status = SenderStatus::Aborted;
            return Err(OfferError::NotSent);
        }
        if !receipt.matches(&self.draft) {
            self.status = SenderStatus::Unknown;
            return Err(OfferError::Conflict);
        }
        if self.status == SenderStatus::EnvelopeReceived {
            Ok(OfferProgress::Historical)
        } else {
            self.status = SenderStatus::EnvelopeReceived;
            Ok(OfferProgress::First)
        }
    }
    /// Local abort cannot retract an FD already queued or retained by the peer.
    pub fn abort(&mut self) {
        self.status = match self.status {
            SenderStatus::Ready | SenderStatus::Aborted => SenderStatus::Aborted,
            SenderStatus::Sent | SenderStatus::EnvelopeReceived | SenderStatus::Unknown => {
                SenderStatus::Unknown
            }
        };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiverStatus {
    Pending,
    EnvelopeReceived,
    Aborted,
}

/// Bounded one-attempt metadata state, retained including its terminal tombstone.
/// Expectations come from the trusted receiver owner, never the received offer.
/// A caller must close a duplicate received FD even on an exact historical offer.
pub struct ReceiverTransfer {
    expected_context_sha384: [u8; 48],
    expected_spec_sha384: [u8; 48],
    max_backing_bytes: u64,
    retained: Option<RootfsOfferDraft>,
    status: ReceiverStatus,
}

impl ReceiverTransfer {
    pub fn new(
        expected_context_sha384: [u8; 48],
        expected_spec_sha384: [u8; 48],
        max_backing_bytes: u64,
    ) -> Result<Self, OfferError> {
        check_limit(max_backing_bytes)?;
        Ok(Self {
            expected_context_sha384,
            expected_spec_sha384,
            max_backing_bytes,
            retained: None,
            status: ReceiverStatus::Pending,
        })
    }
    pub fn status(&self) -> ReceiverStatus {
        self.status
    }
    pub fn receive(&mut self, draft: RootfsOfferDraft) -> Result<OfferProgress, OfferError> {
        if self.status == ReceiverStatus::Aborted {
            return Err(OfferError::Terminal);
        }
        if let Err(error) = check_backing(draft.backing, self.max_backing_bytes) {
            self.abort();
            return Err(error);
        }
        if draft.context_sha384 != self.expected_context_sha384
            || draft.candidate_spec_sha384 != self.expected_spec_sha384
        {
            self.abort();
            return Err(OfferError::BindingMismatch);
        }
        if let Some(retained) = &self.retained {
            if retained != &draft {
                self.abort();
                return Err(OfferError::Conflict);
            }
            return Ok(OfferProgress::Historical);
        }
        self.retained = Some(draft);
        self.status = ReceiverStatus::EnvelopeReceived;
        Ok(OfferProgress::First)
    }
    pub fn receipt(&self) -> Result<OfferReceipt, OfferError> {
        if self.status == ReceiverStatus::Aborted {
            return Err(OfferError::Terminal);
        }
        self.retained
            .as_ref()
            .map(OfferReceipt::for_offer)
            .ok_or(OfferError::NotReceived)
    }
    pub fn abort(&mut self) {
        self.status = ReceiverStatus::Aborted;
    }
}

fn fresh_nonce() -> Result<[u8; 32], OfferError> {
    let mut nonce = [0; 32];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| OfferError::EntropyUnavailable)?;
    check_nonce(&nonce).map_err(|_| OfferError::EntropyUnavailable)?;
    Ok(nonce)
}

fn check_nonce(nonce: &[u8; 32]) -> Result<(), OfferError> {
    if *nonce == [0; 32] {
        Err(OfferError::InvalidNonce)
    } else {
        Ok(())
    }
}

fn check_limit(max_backing_bytes: u64) -> Result<(), OfferError> {
    if max_backing_bytes == 0 || max_backing_bytes > isize::MAX as u64 {
        Err(OfferError::InvalidLimit)
    } else {
        Ok(())
    }
}

fn check_backing(backing: BackingDescriptor, max_backing_bytes: u64) -> Result<(), OfferError> {
    check_limit(max_backing_bytes)?;
    if backing.byte_len == 0 {
        Err(OfferError::EmptyBacking)
    } else if backing.byte_len > max_backing_bytes {
        Err(OfferError::BackingTooLarge)
    } else {
        Ok(())
    }
}

fn decode_digest(value: &str) -> Result<[u8; 48], OfferError> {
    crate::decode_sha384(value).map_err(|_| OfferError::InvalidContextDigest)
}

fn write_header(bytes: &mut [u8], purpose: u8) {
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[10] = purpose;
    bytes[11] = PROFILE;
}

fn check_header(bytes: &[u8], expected_len: usize, purpose: u8) -> Result<(), OfferError> {
    if bytes.len() != expected_len || &bytes[..8] != MAGIC || bytes[12..16] != [0; 4] {
        return Err(OfferError::InvalidFrame);
    }
    if bytes[8..10] != VERSION.to_be_bytes() {
        return Err(OfferError::UnsupportedVersion);
    }
    if bytes[10] != purpose {
        return Err(OfferError::UnsupportedPurpose);
    }
    if bytes[11] != PROFILE {
        return Err(OfferError::UnsupportedProfile);
    }
    Ok(())
}

fn commitment(domain: &[u8], bytes: &[u8]) -> [u8; 48] {
    let mut hash = digest::Context::new(&digest::SHA384);
    hash.update(domain);
    hash.update(bytes);
    let mut result = [0; 48];
    result.copy_from_slice(hash.finish().as_ref());
    result
}

#[cfg(test)]
#[path = "rootfs_offer_tests.rs"]
mod tests;
