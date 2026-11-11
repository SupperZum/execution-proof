//! Public GCP execution challenge transcripts. These bytes mint no capture or
//! boot capability and do not authorize collection, enrollment or execution.
//! The GCP collector and verifier must independently enforce the boot binding.

use crate::{
    execution::ExecutionRecord, frame, gcp_boot_binding::GcpBootBindingV1, hex, hex_bytes,
    identifier, transcript, Error,
};
use ring::digest;
use serde::{Deserialize, Serialize};

pub const GCP_QUOTE_CHALLENGE_VERSION: u16 = 2;
pub const GCP_QUOTE_CHALLENGE_PURPOSE: &str = "qlad.execution-proof.gcp-exec-quote-challenge.v2";
pub const GCP_EXECUTION_QUOTE_PURPOSE: &str = "qlad.execution-proof.gcp-exec-quote.v2";
pub const GCP_EXECUTION_QUOTE_PROFILE: &str = "onb17.protected-r-gcp-tdx-quote.v2";

/// A distinct wire family: legacy challenges cannot select the GCP profile.
/// The producer core identity is committed through `boot_binding`, while the
/// trust snapshot commits to the relying party's complete verification policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpQuoteChallenge {
    pub version: u16,
    pub purpose: String,
    pub audience: String,
    pub nonce: String,
    pub record_sha384: String,
    pub boot_binding: GcpBootBindingV1,
    pub trust_snapshot_sha384: String,
}

impl GcpQuoteChallenge {
    pub fn new(
        audience: String,
        nonce: [u8; 32],
        record: &ExecutionRecord,
        boot_binding: GcpBootBindingV1,
        trust_snapshot: [u8; 48],
    ) -> Result<Self, Error> {
        let value = Self {
            version: GCP_QUOTE_CHALLENGE_VERSION,
            purpose: GCP_QUOTE_CHALLENGE_PURPOSE.into(),
            audience,
            nonce: hex(&nonce),
            record_sha384: hex(&record.sha384()?),
            boot_binding,
            trust_snapshot_sha384: hex(&trust_snapshot),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.version != GCP_QUOTE_CHALLENGE_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if self.purpose != GCP_QUOTE_CHALLENGE_PURPOSE {
            return Err(Error::WrongPurpose);
        }
        identifier(&self.audience)?;
        if hex_bytes(&self.nonce, 32)? == [0; 32] {
            return Err(Error::InvalidField);
        }
        for value in [&self.record_sha384, &self.trust_snapshot_sha384] {
            if hex_bytes(value, 48)? == [0; 48] {
                return Err(Error::InvalidField);
            }
        }
        self.boot_binding.validate()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut bytes = transcript(b"gcp-execution-quote-challenge", self.version);
        frame(&mut bytes, self.purpose.as_bytes());
        frame(&mut bytes, self.audience.as_bytes());
        frame(&mut bytes, &hex_bytes(&self.nonce, 32)?);
        frame(&mut bytes, &hex_bytes(&self.record_sha384, 48)?);
        frame(
            &mut bytes,
            &hex_bytes(&self.boot_binding.digest_sha384()?, 48)?,
        );
        frame(&mut bytes, &hex_bytes(&self.trust_snapshot_sha384, 48)?);
        Ok(bytes)
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

/// All 64 bytes must be compared by the hardware appraiser. The final sixteen
/// zero bytes are part of the transcript contract, never ignored padding.
pub fn report_data(
    record: &ExecutionRecord,
    challenge: &GcpQuoteChallenge,
) -> Result<[u8; 64], Error> {
    let record_digest = record.sha384()?;
    if hex_bytes(&challenge.record_sha384, 48)? != record_digest {
        return Err(Error::BindingMismatch);
    }
    let mut bytes = transcript(b"protected-r-gcp-tdx-quote", GCP_QUOTE_CHALLENGE_VERSION);
    frame(&mut bytes, GCP_EXECUTION_QUOTE_PURPOSE.as_bytes());
    frame(&mut bytes, GCP_EXECUTION_QUOTE_PROFILE.as_bytes());
    frame(&mut bytes, &record_digest);
    frame(&mut bytes, &challenge.canonical_bytes()?);
    let mut output = [0; 64];
    output[..48].copy_from_slice(digest::digest(&digest::SHA384, &bytes).as_ref());
    Ok(output)
}

#[cfg(test)]
#[path = "gcp_execution_quote_tests.rs"]
mod tests;
