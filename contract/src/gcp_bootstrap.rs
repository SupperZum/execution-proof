//! Public GCP pre-grant bootstrap transcripts. Signature verification checks
//! authority intent and a supplied trusted clock, not hardware, key custody,
//! producer isolation or replay-store consumption. REPORT_DATA computation is
//! public and cannot collect a quote or mint a trusted boot capability.

use crate::{
    frame, gcp_boot_binding::GcpBootBindingV1, hex_bytes, identifier, sha384, transcript,
    verify_signature, Error, Signed, ValidityWindow,
};
use ring::digest;
use serde::{Deserialize, Serialize};

pub const GCP_BOOTSTRAP_VERSION: u16 = 3;
pub const GCP_BOOTSTRAP_CHALLENGE_PURPOSE: &str = "qlad.execution-proof.gcp-bootstrap-challenge.v3";
pub const GCP_BOOTSTRAP_BINDING_PURPOSE: &str = "qlad.execution-proof.gcp-bootstrap-binding.v3";
pub const GCP_BOOTSTRAP_REPORT_PURPOSE: &str = "qlad.execution-proof.gcp-bootstrap-report.v3";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpBootstrapChallenge {
    pub version: u16,
    pub purpose: String,
    pub audience: String,
    pub authority: String,
    pub tenant: String,
    pub workload_id: String,
    pub attempt_id: String,
    pub challenge_id: String,
    pub nonce_hex: String,
    pub intent_sha384: String,
    pub boot_binding: GcpBootBindingV1,
    pub validity: ValidityWindow,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpBootstrapBinding {
    pub version: u16,
    pub purpose: String,
    pub challenge_sha384: String,
    pub boot_binding_sha384: String,
    pub boot_id: String,
    pub boot_nonce_hex: String,
    /// SHA384 of the raw 32-byte Ed25519 public key, as in channel_key_sha384.
    pub recorder_key_sha384: String,
    /// SHA384 of the canonical TeePubKey JSON bytes used by the KBS client.
    /// Key algorithm/shape validation and possession are separate requirements.
    pub keywrap_key_sha384: String,
}

fn nonzero_hash(value: &str, length: usize) -> Result<(), Error> {
    if hex_bytes(value, length)?.iter().all(|byte| *byte == 0) {
        return Err(Error::InvalidField);
    }
    Ok(())
}

impl GcpBootstrapChallenge {
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != GCP_BOOTSTRAP_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if self.purpose != GCP_BOOTSTRAP_CHALLENGE_PURPOSE {
            return Err(Error::WrongPurpose);
        }
        for value in [
            &self.audience,
            &self.authority,
            &self.tenant,
            &self.workload_id,
            &self.attempt_id,
            &self.challenge_id,
        ] {
            identifier(value)?;
        }
        nonzero_hash(&self.nonce_hex, 32)?;
        nonzero_hash(&self.intent_sha384, 48)?;
        self.boot_binding.validate()?;
        self.validity.validate()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut bytes = transcript(b"gcp-bootstrap-challenge", self.version);
        for value in [
            &self.purpose,
            &self.audience,
            &self.authority,
            &self.tenant,
            &self.workload_id,
            &self.attempt_id,
            &self.challenge_id,
        ] {
            frame(&mut bytes, value.as_bytes());
        }
        frame(&mut bytes, &hex_bytes(&self.nonce_hex, 32)?);
        frame(&mut bytes, &hex_bytes(&self.intent_sha384, 48)?);
        frame(
            &mut bytes,
            &hex_bytes(&self.boot_binding.digest_sha384()?, 48)?,
        );
        self.validity.append_to(&mut bytes)?;
        Ok(bytes)
    }

    pub fn digest_sha384(&self) -> Result<String, Error> {
        Ok(sha384(&self.canonical_bytes()?))
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        encode(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let value: Self = crate::decode(bytes)?;
        value.validate()?;
        Ok(value)
    }
}

impl GcpBootstrapBinding {
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != GCP_BOOTSTRAP_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if self.purpose != GCP_BOOTSTRAP_BINDING_PURPOSE {
            return Err(Error::WrongPurpose);
        }
        identifier(&self.boot_id)?;
        nonzero_hash(&self.boot_nonce_hex, 32)?;
        for hash in [
            &self.challenge_sha384,
            &self.boot_binding_sha384,
            &self.recorder_key_sha384,
            &self.keywrap_key_sha384,
        ] {
            nonzero_hash(hash, 48)?;
        }
        // The Ed25519 recorder and encryption key have distinct roles.
        if self.recorder_key_sha384 == self.keywrap_key_sha384 {
            return Err(Error::ConfusedKeys);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut bytes = transcript(b"gcp-bootstrap-binding", self.version);
        frame(&mut bytes, self.purpose.as_bytes());
        frame(&mut bytes, &hex_bytes(&self.challenge_sha384, 48)?);
        frame(&mut bytes, &hex_bytes(&self.boot_binding_sha384, 48)?);
        frame(&mut bytes, self.boot_id.as_bytes());
        frame(&mut bytes, &hex_bytes(&self.boot_nonce_hex, 32)?);
        frame(&mut bytes, &hex_bytes(&self.recorder_key_sha384, 48)?);
        frame(&mut bytes, &hex_bytes(&self.keywrap_key_sha384, 48)?);
        Ok(bytes)
    }

    pub fn digest_sha384(&self) -> Result<String, Error> {
        Ok(sha384(&self.canonical_bytes()?))
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        encode(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let value: Self = crate::decode(bytes)?;
        value.validate()?;
        Ok(value)
    }
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::Malformed)?;
    if bytes.len() > crate::MAX_WIRE_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(bytes)
}

/// Authenticate the exact issuer challenge saved outside the submitted request.
/// The caller must provide a trusted clock and atomically consume fresh pending
/// challenge state separately. A public return value conveys no hardware claim.
pub fn verify_challenge(
    signed_json: &[u8],
    authority_public_key: &[u8; 32],
    expected: &GcpBootstrapChallenge,
    trusted_now: u64,
) -> Result<GcpBootstrapChallenge, Error> {
    let challenge = verify_challenge_signature(signed_json, authority_public_key, expected)?;
    challenge.validity.check_at(trusted_now)?;
    Ok(challenge)
}

/// Authenticate the exact challenge without using a guest wall clock. This
/// grants no freshness or permission: the authority must check its own clock
/// and consume pending state before issuing any launch authorization.
pub fn verify_challenge_signature(
    signed_json: &[u8],
    authority_public_key: &[u8; 32],
    expected: &GcpBootstrapChallenge,
) -> Result<GcpBootstrapChallenge, Error> {
    expected.validate()?;
    let signed: Signed<GcpBootstrapChallenge> = crate::decode(signed_json)?;
    let bytes = signed.statement.canonical_bytes()?;
    if signed.statement != *expected {
        return Err(Error::BindingMismatch);
    }
    verify_signature(authority_public_key, &bytes, &signed.signature)?;
    Ok(signed.statement)
}

/// Commitment to the public pre-grant capture carried by L's opaque bootstrap
/// context field. The issuer must verify actual QVL/boot/producer predicates
/// before signing L; hashing public input is not an appraisal capability.
pub fn bootstrap_context_sha384(
    challenge: &GcpBootstrapChallenge,
    binding: &GcpBootstrapBinding,
    evidence: &crate::gcp_session::GcpLaunchEvidenceV2,
) -> Result<String, Error> {
    report_data(challenge, binding)?;
    evidence.encode()?;
    let mut bytes = transcript(b"gcp-bootstrap-context", GCP_BOOTSTRAP_VERSION);
    frame(&mut bytes, b"qlad.execution-proof.gcp-bootstrap-context.v3");
    for hash in [
        challenge.digest_sha384()?,
        challenge.boot_binding.digest_sha384()?,
        binding.digest_sha384()?,
    ] {
        frame(&mut bytes, &hex_bytes(&hash, 48)?);
    }
    for value in [
        &evidence.tdx_quote,
        &evidence.ccel_table,
        &evidence.ccel_log,
    ] {
        frame(&mut bytes, digest::digest(&digest::SHA384, value).as_ref());
    }
    Ok(crate::sha384(&bytes))
}

/// Key possession for this exact captured pre-grant context, distinct from
/// session operations, authority challenges and execution-quote transcripts.
pub fn bootstrap_possession_signing_bytes(
    challenge: &GcpBootstrapChallenge,
    binding: &GcpBootstrapBinding,
    evidence: &crate::gcp_session::GcpLaunchEvidenceV2,
) -> Result<Vec<u8>, Error> {
    let context = bootstrap_context_sha384(challenge, binding, evidence)?;
    let mut bytes = transcript(b"gcp-bootstrap-recorder-possession", GCP_BOOTSTRAP_VERSION);
    frame(
        &mut bytes,
        b"qlad.execution-proof.gcp-bootstrap-recorder-possession.v3",
    );
    frame(&mut bytes, &hex_bytes(&context, 48)?);
    Ok(bytes)
}

pub fn verify_bootstrap_possession(
    challenge: &GcpBootstrapChallenge,
    binding: &GcpBootstrapBinding,
    evidence: &crate::gcp_session::GcpLaunchEvidenceV2,
    recorder_public_key: &[u8; 32],
    signature_hex: &str,
) -> Result<(), Error> {
    if crate::sha384(recorder_public_key) != binding.recorder_key_sha384 {
        return Err(Error::BindingMismatch);
    }
    verify_signature(
        recorder_public_key,
        &bootstrap_possession_signing_bytes(challenge, binding, evidence)?,
        signature_hex,
    )
}

/// Candidate bootstrap REPORT_DATA only. The measured producer must authenticate
/// the challenge before collection; the independent appraiser must repeat that
/// authentication, the saved fresh-context checks, and full 64-byte comparison.
pub fn report_data(
    challenge: &GcpBootstrapChallenge,
    binding: &GcpBootstrapBinding,
) -> Result<[u8; 64], Error> {
    let challenge_digest = challenge.digest_sha384()?;
    let binding_bytes = binding.canonical_bytes()?;
    if binding.challenge_sha384 != challenge_digest
        || binding.boot_binding_sha384 != challenge.boot_binding.digest_sha384()?
    {
        return Err(Error::BindingMismatch);
    }
    let mut bytes = transcript(b"gcp-bootstrap-report-data", GCP_BOOTSTRAP_VERSION);
    frame(&mut bytes, GCP_BOOTSTRAP_REPORT_PURPOSE.as_bytes());
    frame(&mut bytes, &hex_bytes(&challenge_digest, 48)?);
    frame(&mut bytes, &binding_bytes);
    let mut output = [0; 64];
    output[..48].copy_from_slice(digest::digest(&digest::SHA384, &bytes).as_ref());
    Ok(output)
}

/// Compare the entire public candidate field, including the final sixteen zero
/// bytes. This comparison does not authenticate the source of `actual`.
pub fn check_report_data(
    challenge: &GcpBootstrapChallenge,
    binding: &GcpBootstrapBinding,
    actual: &[u8; 64],
) -> Result<(), Error> {
    if report_data(challenge, binding)? != *actual {
        return Err(Error::BindingMismatch);
    }
    Ok(())
}

#[cfg(test)]
#[path = "gcp_bootstrap_tests.rs"]
mod tests;
