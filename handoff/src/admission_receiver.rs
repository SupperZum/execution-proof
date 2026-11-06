//! Verification-only receiver admission for the producer's still-pending gate.
//!
//! A fresh receiver challenge and the producer's factory-owned nonce cross an
//! authenticated startup channel before the producer consumes its context. The
//! receiver independently verifies the signed admission bundle. It cannot obtain
//! a preparation context or provision a gate from a caller-supplied raw nonce.

use super::*;
use crate::startup::{Role, StartupBoundChannel, StartupBoundPacket};

pub const RECEIVER_CHALLENGE_BYTES: usize = 144;
pub const RECEIVER_ENROLLMENT_BYTES: usize = 176;
const MAGIC: &[u8; 8] = b"ONB17ENR";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiverEnrollmentError {
    WrongRole,
    InvalidFrame,
    StartupBinding,
    GrantMismatch,
    ChallengeMismatch,
    EntropyUnavailable,
    NotPending,
    Conflict,
    Poisoned,
    Admission(GuestAdmissionError),
}
impl fmt::Display for ReceiverEnrollmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "receiver admission enrollment rejected: {self:?}")
    }
}
impl std::error::Error for ReceiverEnrollmentError {}

/// One receiver-owned fresh challenge. Its nonce has no public constructor.
pub struct ReceiverChallenge {
    nonce: [u8; 32],
    startup_binding: [u8; 48],
    grant_sha384: [u8; 48],
}
impl ReceiverChallenge {
    pub fn new(
        channel: &StartupBoundChannel,
        expected_grant_sha384: [u8; 48],
    ) -> Result<Self, ReceiverEnrollmentError> {
        require_role(channel, Role::Kata)?;
        let mut nonce = [0; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| ReceiverEnrollmentError::EntropyUnavailable)?;
        if nonce == [0; 32] {
            return Err(ReceiverEnrollmentError::EntropyUnavailable);
        }
        Ok(Self {
            nonce,
            startup_binding: channel.binding_commitment(),
            grant_sha384: expected_grant_sha384,
        })
    }
    pub fn encode(&self) -> [u8; RECEIVER_CHALLENGE_BYTES] {
        let mut wire = [0; RECEIVER_CHALLENGE_BYTES];
        write_header(&mut wire, 1);
        wire[16..48].copy_from_slice(&self.nonce);
        wire[48..96].copy_from_slice(&self.startup_binding);
        wire[96..144].copy_from_slice(&self.grant_sha384);
        wire
    }
    /// Consume this challenge once; an enrollment from another live challenge,
    /// channel or grant cannot select the receiver's admission nonce.
    pub fn accept(
        self,
        packet: StartupBoundPacket,
        channel: &StartupBoundChannel,
    ) -> Result<PendingReceiverEnrollment, ReceiverEnrollmentError> {
        require_packet(&packet, channel, Role::Kata)?;
        let (wire, descriptor) = packet.into_parts();
        if descriptor.is_some() {
            return Err(ReceiverEnrollmentError::InvalidFrame);
        }
        check_header(&wire, RECEIVER_ENROLLMENT_BYTES, 2)?;
        if self.startup_binding != channel.binding_commitment()
            || wire[80..128] != self.startup_binding
        {
            return Err(ReceiverEnrollmentError::StartupBinding);
        }
        if wire[16..48] != self.nonce {
            return Err(ReceiverEnrollmentError::ChallengeMismatch);
        }
        if wire[128..176] != self.grant_sha384 {
            return Err(ReceiverEnrollmentError::GrantMismatch);
        }
        let gate_nonce = wire[48..80]
            .try_into()
            .map_err(|_| ReceiverEnrollmentError::InvalidFrame)?;
        if gate_nonce == [0; 32] {
            return Err(ReceiverEnrollmentError::InvalidFrame);
        }
        Ok(PendingReceiverEnrollment {
            gate_nonce,
            startup_binding: self.startup_binding,
            grant_sha384: self.grant_sha384,
        })
    }
}

/// Authenticated projection, never a deserializable gate/preparation capability.
/// ```compile_fail
/// use execution_proof_handoff::admission::PendingReceiverEnrollment;
/// let _: PendingReceiverEnrollment = serde_json::from_str("{}").unwrap();
/// ```
pub struct PendingReceiverEnrollment {
    gate_nonce: [u8; 32],
    startup_binding: [u8; 48],
    grant_sha384: [u8; 48],
}

impl GuestAdmissionGate {
    /// Project only the nonce of this factory-owned still-pending gate. The
    /// first exact challenge is retained; another challenge cannot replace it.
    pub fn receiver_enrollment(
        &self,
        challenge: StartupBoundPacket,
        channel: &StartupBoundChannel,
    ) -> Result<Vec<u8>, ReceiverEnrollmentError> {
        require_packet(&challenge, channel, Role::Preparation)?;
        let (challenge, descriptor) = challenge.into_parts();
        if descriptor.is_some() {
            return Err(ReceiverEnrollmentError::InvalidFrame);
        }
        check_header(&challenge, RECEIVER_CHALLENGE_BYTES, 1)?;
        if challenge[16..48] == [0; 32] {
            return Err(ReceiverEnrollmentError::InvalidFrame);
        }
        if challenge[48..96] != channel.binding_commitment() {
            return Err(ReceiverEnrollmentError::StartupBinding);
        }
        let grant = decode_hex::<48>(&self.expected_grant_digest)?;
        if challenge[96..144] != grant {
            return Err(ReceiverEnrollmentError::GrantMismatch);
        }
        let commitment = receiver_challenge_commitment(&challenge);
        let mut state = self
            .state
            .lock()
            .map_err(|_| ReceiverEnrollmentError::Poisoned)?;
        if state.verified.is_some() {
            return Err(ReceiverEnrollmentError::NotPending);
        }
        if state
            .enrollment
            .is_some_and(|existing| existing != commitment)
        {
            return Err(ReceiverEnrollmentError::Conflict);
        }
        let gate_nonce = decode_hex::<32>(&self.expected.guest_nonce)?;
        if gate_nonce == [0; 32] {
            return Err(ReceiverEnrollmentError::InvalidFrame);
        }
        let mut wire = [0; RECEIVER_ENROLLMENT_BYTES];
        write_header(&mut wire, 2);
        wire[16..48].copy_from_slice(&challenge[16..48]);
        wire[48..80].copy_from_slice(&gate_nonce);
        wire[80..128].copy_from_slice(&channel.binding_commitment());
        wire[128..176].copy_from_slice(&grant);
        state.enrollment = Some(commitment);
        Ok(wire.to_vec())
    }
}

/// Independently configured verification-only gate for the same factory nonce.
pub struct ReceiverAdmissionVerifier {
    gate: GuestAdmissionGate,
    startup_binding: [u8; 48],
}
impl ReceiverAdmissionVerifier {
    pub fn new(
        configuration: GuestAdmissionConfig,
        enrollment: PendingReceiverEnrollment,
    ) -> Result<Self, ReceiverEnrollmentError> {
        // Validate every independent root/expectation using the normal factory.
        // Only this private authenticated enrollment path substitutes its nonce;
        // the resulting gate is never exposed as a preparation gate.
        let mut gate =
            GuestAdmissionGate::new(configuration).map_err(ReceiverEnrollmentError::Admission)?;
        if decode_hex::<48>(&gate.expected_grant_digest)? != enrollment.grant_sha384 {
            return Err(ReceiverEnrollmentError::GrantMismatch);
        }
        gate.expected.guest_nonce = hex(&enrollment.gate_nonce);
        Ok(Self {
            gate,
            startup_binding: enrollment.startup_binding,
        })
    }
    pub fn verify_bundle(
        &self,
        grant: &[u8],
        aggregate: &[u8],
        receipt: &[u8],
    ) -> Result<AdmissionCheck, GuestAdmissionError> {
        self.gate.verify_bundle(grant, aggregate, receipt)
    }
    pub fn take_verified(&self) -> Result<VerifiedReceiverAdmission, GuestAdmissionError> {
        Ok(VerifiedReceiverAdmission {
            context: self.gate.take_accepted_attempt()?,
            startup_binding: self.startup_binding,
        })
    }
}

/// Receiver-only authenticated admission. No conversion to a producer context.
/// ```compile_fail
/// use execution_proof_handoff::admission::{AcceptedAttemptContext, VerifiedReceiverAdmission};
/// fn promote(value: VerifiedReceiverAdmission) -> AcceptedAttemptContext { value.into_accepted_attempt() }
/// ```
pub struct VerifiedReceiverAdmission {
    context: AcceptedAttemptContext,
    startup_binding: [u8; 48],
}
impl VerifiedReceiverAdmission {
    pub fn binding(&self) -> &LaunchBinding {
        self.context.binding()
    }
    pub fn context_digest(&self) -> &str {
        self.context.context_digest()
    }
    pub fn grant_digest(&self) -> &str {
        self.context.grant_digest()
    }
    pub fn aggregate_digest(&self) -> &str {
        self.context.aggregate_digest()
    }
    pub fn authority_key_sha384(&self) -> &str {
        self.context.authority_key_sha384()
    }
    pub fn aggregate_key_sha384(&self) -> &str {
        self.context.aggregate_key_sha384()
    }
    pub fn startup_binding_sha384(&self) -> &[u8; 48] {
        &self.startup_binding
    }
}

fn require_role(channel: &StartupBoundChannel, role: Role) -> Result<(), ReceiverEnrollmentError> {
    if channel.role() == role {
        Ok(())
    } else {
        Err(ReceiverEnrollmentError::WrongRole)
    }
}
fn require_packet(
    packet: &StartupBoundPacket,
    channel: &StartupBoundChannel,
    role: Role,
) -> Result<(), ReceiverEnrollmentError> {
    require_role(channel, role)?;
    if packet.recipient_role() != role {
        return Err(ReceiverEnrollmentError::WrongRole);
    }
    if packet.startup_binding_sha384() != &channel.binding_commitment() {
        return Err(ReceiverEnrollmentError::StartupBinding);
    }
    Ok(())
}
fn write_header(wire: &mut [u8], purpose: u8) {
    wire[..8].copy_from_slice(MAGIC);
    wire[8..10].copy_from_slice(&1u16.to_be_bytes());
    wire[10] = purpose;
    wire[11] = 1;
}
fn check_header(wire: &[u8], length: usize, purpose: u8) -> Result<(), ReceiverEnrollmentError> {
    if wire.len() != length
        || &wire[..8] != MAGIC
        || wire[8..10] != 1u16.to_be_bytes()
        || wire[10] != purpose
        || wire[11] != 1
        || wire[12..16] != [0; 4]
    {
        Err(ReceiverEnrollmentError::InvalidFrame)
    } else {
        Ok(())
    }
}
fn decode_hex<const N: usize>(input: &str) -> Result<[u8; N], ReceiverEnrollmentError> {
    if input.len() != N * 2
        || !input
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ReceiverEnrollmentError::InvalidFrame);
    }
    let mut output = [0; N];
    for (byte, pair) in output.iter_mut().zip(input.as_bytes().as_chunks::<2>().0) {
        let digit = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        };
        *byte = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(output)
}
fn receiver_challenge_commitment(wire: &[u8]) -> [u8; 48] {
    let mut hash = digest::Context::new(&digest::SHA384);
    hash.update(b"onb17/receiver-admission-enrollment/v1\0");
    hash.update(wire);
    hash.finish()
        .as_ref()
        .try_into()
        .expect("SHA384 is 48 bytes")
}
