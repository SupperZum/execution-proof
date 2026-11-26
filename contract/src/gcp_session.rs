//! GCP v2 recorder possession transcripts. B is operator-selected outside the
//! request; signatures establish possession/association, not hardware or replay
//! consumption. Legacy canonical inputs are framed inside distinct GCP domains.

use crate::{
    frame, gcp_boot_binding::GcpBootBindingV1, hex_bytes, session, sha384, transcript,
    verify_signature, Error, VerifiedLaunchGrant,
};

pub use session::SessionOperation;
#[path = "gcp_launch_evidence.rs"]
mod evidence;
pub use evidence::GcpLaunchEvidenceV2 as GcpLaunchEvidence;
pub use evidence::{
    GcpLaunchEvidenceV2, GCP_LAUNCH_EVIDENCE_PROFILE, GCP_LAUNCH_EVIDENCE_PURPOSE,
    GCP_LAUNCH_EVIDENCE_VERSION,
};
pub const SESSION_VERSION: u16 = 2;
pub const SESSION_PURPOSE: &str = "qlad.execution-proof.gcp-recorder-session.v2";
pub const OPERATION_PURPOSE: &str = "qlad.execution-proof.gcp-recorder-operation.v2";

/// Explicit GCP launch profile: the authenticated grant's opaque profile field
/// commits to the complete externally selected C/D/A/V binding.
pub fn require_boot_binding(
    grant: &VerifiedLaunchGrant,
    binding: &GcpBootBindingV1,
) -> Result<String, Error> {
    let digest = binding.digest_sha384()?;
    require_binding_digest(grant, &digest)?;
    Ok(digest)
}

pub(crate) fn require_binding_digest(
    grant: &VerifiedLaunchGrant,
    digest: &str,
) -> Result<(), Error> {
    if hex_bytes(digest, 48)? == [0; 48] || grant.binding().profile_sha384 != digest {
        return Err(Error::BindingMismatch);
    }
    Ok(())
}

pub fn operation_signing_bytes(
    grant: &VerifiedLaunchGrant,
    binding: &GcpBootBindingV1,
    operation: &SessionOperation,
) -> Result<Vec<u8>, Error> {
    let digest = require_boot_binding(grant, binding)?;
    let input = session::operation_signing_bytes(grant, operation)?;
    let mut out = transcript(b"gcp-recorder-operation", SESSION_VERSION);
    frame(&mut out, OPERATION_PURPOSE.as_bytes());
    frame(&mut out, &hex_bytes(&digest, 48)?);
    frame(&mut out, &input);
    Ok(out)
}

pub fn verify_operation_pop(
    grant: &VerifiedLaunchGrant,
    binding: &GcpBootBindingV1,
    operation: &SessionOperation,
    recorder_public_key: &[u8; 32],
    signature: &str,
) -> Result<(), Error> {
    let bytes = operation_signing_bytes(grant, binding, operation)?;
    if sha384(recorder_public_key) != grant.binding().channel_key_sha384 {
        return Err(Error::BindingMismatch);
    }
    verify_signature(recorder_public_key, &bytes, signature)
}

pub fn recorder_session_signing_bytes(
    grant: &VerifiedLaunchGrant,
    binding: &GcpBootBindingV1,
    nonce: &str,
    runtime_sha384: &str,
    evidence_sha384: &str,
) -> Result<Vec<u8>, Error> {
    let digest = require_boot_binding(grant, binding)?;
    let input =
        session::recorder_session_signing_bytes(grant, nonce, runtime_sha384, evidence_sha384)?;
    let mut out = transcript(b"gcp-recorder-session", SESSION_VERSION);
    frame(&mut out, SESSION_PURPOSE.as_bytes());
    frame(&mut out, &hex_bytes(&digest, 48)?);
    frame(&mut out, &input);
    Ok(out)
}

/// Authenticated GCP-scoped signature only, distinct from the legacy type.
/// No constructor, deserialization, or conversion to a hardware claim exists.
pub struct VerifiedGcpRecorderSession {
    grant_digest: String,
    boot_binding_sha384: String,
    nonce: String,
    runtime_sha384: String,
    evidence_sha384: String,
    key_sha384: String,
}

impl VerifiedGcpRecorderSession {
    pub fn grant_digest(&self) -> &str {
        &self.grant_digest
    }
    pub fn boot_binding_sha384(&self) -> &str {
        &self.boot_binding_sha384
    }
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn runtime_sha384(&self) -> &str {
        &self.runtime_sha384
    }
    pub fn evidence_sha384(&self) -> &str {
        &self.evidence_sha384
    }
    pub fn key_sha384(&self) -> &str {
        &self.key_sha384
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verify_recorder_session_pop(
    grant: &VerifiedLaunchGrant,
    binding: &GcpBootBindingV1,
    nonce: &str,
    runtime_sha384: &str,
    evidence_sha384: &str,
    recorder_public_key: &[u8; 32],
    signature: &str,
) -> Result<VerifiedGcpRecorderSession, Error> {
    let bytes =
        recorder_session_signing_bytes(grant, binding, nonce, runtime_sha384, evidence_sha384)?;
    let key_sha384 = sha384(recorder_public_key);
    if key_sha384 != grant.binding().channel_key_sha384 {
        return Err(Error::BindingMismatch);
    }
    verify_signature(recorder_public_key, &bytes, signature)?;
    Ok(VerifiedGcpRecorderSession {
        grant_digest: grant.grant_digest().into(),
        boot_binding_sha384: binding.digest_sha384()?,
        nonce: nonce.into(),
        runtime_sha384: runtime_sha384.into(),
        evidence_sha384: evidence_sha384.into(),
        key_sha384,
    })
}
