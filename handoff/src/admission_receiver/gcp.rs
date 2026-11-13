//! GCP-typed receiver verification through the unchanged authenticated enrollment.
use super::*;
use crate::admission::gcp::{GcpGuestAdmissionConfig, GcpGuestAdmissionGate};

impl GcpGuestAdmissionGate {
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
pub struct GcpReceiverAdmissionVerifier {
    gate: GcpGuestAdmissionGate,
    startup_binding: [u8; 48],
}
impl GcpReceiverAdmissionVerifier {
    pub fn new(
        configuration: GcpGuestAdmissionConfig,
        enrollment: PendingReceiverEnrollment,
    ) -> Result<Self, ReceiverEnrollmentError> {
        // Validate every independent root/expectation using the normal factory.
        // Only this private authenticated enrollment path substitutes its nonce;
        // the resulting gate is never exposed as a preparation gate.
        let mut gate = GcpGuestAdmissionGate::new(configuration)
            .map_err(ReceiverEnrollmentError::Admission)?;
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
