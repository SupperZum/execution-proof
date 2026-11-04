//! Recorder key possession bound to an authenticated grant and exact session input.
//!
//! The caller must supply its expected fresh nonce and the hashes of the actual
//! runtime/evidence bytes. This module does not establish nonce uniqueness,
//! evidence validity, hardware key origin, or freshness of a previously checked
//! grant. Admission must independently check its clock and replay state.

use crate::{
    frame, hex_bytes, sha384, transcript, verify_signature, Error, VerifiedLaunchGrant, VERSION,
};

pub const SESSION_VERSION: u16 = 1;
pub const SESSION_PURPOSE: &str = "qlad.execution-proof.recorder-session.v1";
pub const MAX_SESSION_NONCE_BYTES: usize = 256;
pub const OPERATION_VERSION: u16 = 1;
pub const OPERATION_PURPOSE: &str = "qlad.execution-proof.recorder-operation.v1";

/// Distinct recorder operations; none is a resource-access credential.
pub enum SessionOperation {
    /// SHA384 of the canonical JCS encoding of the typed JWE public key.
    Begin { key_sha384: String },
    ResourceChallenge {
        session_id: String,
        nonce: String,
        runtime_sha384: String,
        evidence_sha384: String,
    },
    ResourceDecision {
        session_id: String,
        nonce: String,
        runtime_sha384: String,
        evidence_sha384: String,
        request_sha384: String,
    },
    CredentialDelivery {
        session_id: String,
        nonce: String,
        runtime_sha384: String,
        evidence_sha384: String,
        request_sha384: String,
        aggregate_sha384: String,
    },
}

/// Bind a recorder signature to one operation, grant, and exact expected inputs.
/// The caller must hash the actual typed JWE key/request and manage nonce state.
pub fn operation_signing_bytes(
    grant: &VerifiedLaunchGrant,
    operation: &SessionOperation,
) -> Result<Vec<u8>, Error> {
    let mut out = transcript(b"recorder-operation", VERSION);
    frame(&mut out, &OPERATION_VERSION.to_be_bytes());
    frame(&mut out, OPERATION_PURPOSE.as_bytes());
    frame(&mut out, grant.grant_digest().as_bytes());
    match operation {
        SessionOperation::Begin { key_sha384 } => {
            hex_bytes(key_sha384, 48)?;
            frame(&mut out, b"begin");
            frame(&mut out, key_sha384.as_bytes());
        }
        SessionOperation::ResourceChallenge {
            session_id,
            nonce,
            runtime_sha384,
            evidence_sha384,
        }
        | SessionOperation::ResourceDecision {
            session_id,
            nonce,
            runtime_sha384,
            evidence_sha384,
            ..
        }
        | SessionOperation::CredentialDelivery {
            session_id,
            nonce,
            runtime_sha384,
            evidence_sha384,
            ..
        } => {
            hex_bytes(session_id, 32)?;
            if nonce.is_empty() || nonce.len() > MAX_SESSION_NONCE_BYTES || !nonce.is_ascii() {
                return Err(Error::InvalidField);
            }
            hex_bytes(runtime_sha384, 48)?;
            hex_bytes(evidence_sha384, 48)?;
            let tag = match operation {
                SessionOperation::ResourceDecision { .. } => b"resource-decision".as_slice(),
                SessionOperation::CredentialDelivery { .. } => b"credential-delivery".as_slice(),
                _ => b"resource-challenge".as_slice(),
            };
            frame(&mut out, tag);
            for field in [session_id, nonce, runtime_sha384, evidence_sha384] {
                frame(&mut out, field.as_bytes());
            }
            if let SessionOperation::ResourceDecision { request_sha384, .. }
            | SessionOperation::CredentialDelivery { request_sha384, .. } = operation
            {
                hex_bytes(request_sha384, 48)?;
                frame(&mut out, request_sha384.as_bytes());
            }
            if let SessionOperation::CredentialDelivery {
                aggregate_sha384, ..
            } = operation
            {
                hex_bytes(aggregate_sha384, 48)?;
                frame(&mut out, aggregate_sha384.as_bytes());
            }
        }
    }
    Ok(out)
}

/// Verify possession of the signed grant's recorder key for the exact operation.
pub fn verify_operation_pop(
    grant: &VerifiedLaunchGrant,
    operation: &SessionOperation,
    recorder_public_key: &[u8; 32],
    signature: &str,
) -> Result<(), Error> {
    let bytes = operation_signing_bytes(grant, operation)?;
    if sha384(recorder_public_key) != grant.binding().channel_key_sha384 {
        return Err(Error::BindingMismatch);
    }
    verify_signature(recorder_public_key, &bytes, signature)
}

/// Authenticated possession and session association only, never a hardware claim.
/// There is no public constructor, Deserialize, Clone, or Debug implementation.
pub struct VerifiedRecorderSession {
    grant_digest: String,
    nonce: String,
    runtime_sha384: String,
    evidence_sha384: String,
    key_sha384: String,
}

impl VerifiedRecorderSession {
    pub fn grant_digest(&self) -> &str {
        &self.grant_digest
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

/// Client signing transcript; JSON serialization is not part of the signature.
pub fn recorder_session_signing_bytes(
    grant: &VerifiedLaunchGrant,
    nonce: &str,
    runtime_sha384: &str,
    evidence_sha384: &str,
) -> Result<Vec<u8>, Error> {
    if nonce.is_empty() || nonce.len() > MAX_SESSION_NONCE_BYTES || !nonce.is_ascii() {
        return Err(Error::InvalidField);
    }
    hex_bytes(runtime_sha384, 48)?;
    hex_bytes(evidence_sha384, 48)?;
    let mut out = transcript(b"recorder-session", VERSION);
    frame(&mut out, &SESSION_VERSION.to_be_bytes());
    for field in [
        SESSION_PURPOSE,
        grant.grant_digest(),
        nonce,
        runtime_sha384,
        evidence_sha384,
    ] {
        frame(&mut out, field.as_bytes());
    }
    Ok(out)
}

/// Authenticate the grant's recorder key over the expected session transcript.
pub fn verify_recorder_session_pop(
    grant: &VerifiedLaunchGrant,
    nonce: &str,
    runtime_sha384: &str,
    evidence_sha384: &str,
    recorder_public_key: &[u8; 32],
    signature: &str,
) -> Result<VerifiedRecorderSession, Error> {
    let bytes = recorder_session_signing_bytes(grant, nonce, runtime_sha384, evidence_sha384)?;
    let key_sha384 = sha384(recorder_public_key);
    if key_sha384 != grant.binding().channel_key_sha384 {
        return Err(Error::BindingMismatch);
    }
    verify_signature(recorder_public_key, &bytes, signature)?;
    Ok(VerifiedRecorderSession {
        grant_digest: grant.grant_digest().into(),
        nonce: nonce.into(),
        runtime_sha384: runtime_sha384.into(),
        evidence_sha384: evidence_sha384.into(),
        key_sha384,
    })
}

#[cfg(test)]
mod tests;
