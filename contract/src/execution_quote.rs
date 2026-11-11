//! Public post-exec quote transcripts. Decoding these data cannot mint a
//! captured record, invoke a protected producer, or authenticate a TDX quote.

use crate::{execution::ExecutionRecord, frame, hex_bytes, identifier, transcript, Error};
use ring::digest;
use serde::{de, Deserialize, Deserializer, Serialize};
use std::fmt;

pub const QUOTE_CHALLENGE_VERSION: u16 = 1;
pub const QUOTE_CHALLENGE_PURPOSE: &str = "qlad.execution-proof.exec-quote-challenge.v1";
pub const EXECUTION_QUOTE_VERSION: u16 = 1;
pub const EXECUTION_QUOTE_PURPOSE: &str = "qlad.execution-proof.exec-quote.v1";
pub const EXECUTION_QUOTE_PROFILE: &str = "onb17.protected-r-tdx-quote.v1";
pub const MAX_TDX_EVIDENCE_BYTES: usize = 1 << 20;
pub const MAX_QUOTE_ENVELOPE_BYTES: usize = 4 << 20;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteChallenge {
    pub version: u16,
    pub purpose: String,
    pub audience: String,
    pub nonce: String,
    pub record_sha384: String,
    pub producer_profile_sha384: String,
    pub trust_snapshot_sha384: String,
}

impl QuoteChallenge {
    pub fn new(
        audience: String,
        nonce: [u8; 32],
        record: &ExecutionRecord,
        producer_profile: [u8; 48],
        trust_snapshot: [u8; 48],
    ) -> Result<Self, Error> {
        let value = Self {
            version: QUOTE_CHALLENGE_VERSION,
            purpose: QUOTE_CHALLENGE_PURPOSE.into(),
            audience,
            nonce: hex(&nonce),
            record_sha384: hex(&record.sha384()?),
            producer_profile_sha384: hex(&producer_profile),
            trust_snapshot_sha384: hex(&trust_snapshot),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.version != QUOTE_CHALLENGE_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if self.purpose != QUOTE_CHALLENGE_PURPOSE {
            return Err(Error::WrongPurpose);
        }
        identifier(&self.audience)?;
        if hex_bytes(&self.nonce, 32)? == [0; 32] {
            return Err(Error::InvalidField);
        }
        for value in [
            &self.record_sha384,
            &self.producer_profile_sha384,
            &self.trust_snapshot_sha384,
        ] {
            hex_bytes(value, 48)?;
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut bytes = transcript(b"execution-quote-challenge", self.version);
        frame(&mut bytes, self.purpose.as_bytes());
        frame(&mut bytes, self.audience.as_bytes());
        frame(&mut bytes, &hex_bytes(&self.nonce, 32)?);
        for value in [
            &self.record_sha384,
            &self.producer_profile_sha384,
            &self.trust_snapshot_sha384,
        ] {
            frame(&mut bytes, &hex_bytes(value, 48)?);
        }
        Ok(bytes)
    }

    pub fn sha384(&self) -> Result<[u8; 48], Error> {
        Ok(hash(&self.canonical_bytes()?))
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

/// SHA384 of the framed profile, canonical R commitment and challenge transcript,
/// followed by exactly sixteen zero bytes for TDX's 64-byte REPORT_DATA field.
pub fn report_data(
    record: &ExecutionRecord,
    challenge: &QuoteChallenge,
) -> Result<[u8; 64], Error> {
    let record_digest = record.sha384()?;
    if hex_bytes(&challenge.record_sha384, 48)? != record_digest {
        return Err(Error::BindingMismatch);
    }
    let mut bytes = transcript(b"protected-r-tdx-quote", EXECUTION_QUOTE_VERSION);
    frame(&mut bytes, EXECUTION_QUOTE_PURPOSE.as_bytes());
    frame(&mut bytes, EXECUTION_QUOTE_PROFILE.as_bytes());
    frame(&mut bytes, &record_digest);
    frame(&mut bytes, &challenge.canonical_bytes()?);
    let mut output = [0; 64];
    output[..48].copy_from_slice(&hash(&bytes));
    Ok(output)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionQuoteEnvelope {
    pub version: u16,
    pub purpose: String,
    pub profile: String,
    pub challenge: QuoteChallenge,
    #[serde(deserialize_with = "evidence_bytes")]
    pub tdx_evidence: Vec<u8>,
}

impl ExecutionQuoteEnvelope {
    pub fn new(challenge: QuoteChallenge, tdx_evidence: Vec<u8>) -> Result<Self, Error> {
        let value = Self {
            version: EXECUTION_QUOTE_VERSION,
            purpose: EXECUTION_QUOTE_PURPOSE.into(),
            profile: EXECUTION_QUOTE_PROFILE.into(),
            challenge,
            tdx_evidence,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.version != EXECUTION_QUOTE_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if self.purpose != EXECUTION_QUOTE_PURPOSE {
            return Err(Error::WrongPurpose);
        }
        if self.profile != EXECUTION_QUOTE_PROFILE {
            return Err(Error::InvalidField);
        }
        self.challenge.validate()?;
        if self.tdx_evidence.is_empty() || self.tdx_evidence.len() > MAX_TDX_EVIDENCE_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| Error::Malformed)?;
        if bytes.len() > MAX_QUOTE_ENVELOPE_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_QUOTE_ENVELOPE_BYTES {
            return Err(Error::TooLarge);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Error::Malformed)?;
        value.validate()?;
        Ok(value)
    }
}

fn evidence_bytes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    struct Bytes;
    impl<'de> de::Visitor<'de> for Bytes {
        type Value = Vec<u8>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a nonempty bounded byte array")
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut sequence: A) -> Result<Vec<u8>, A::Error> {
            let mut bytes = Vec::new();
            while let Some(byte) = sequence.next_element::<u8>()? {
                if bytes.len() == MAX_TDX_EVIDENCE_BYTES {
                    return Err(de::Error::custom("TDX evidence byte limit"));
                }
                bytes.push(byte);
            }
            if bytes.is_empty() {
                return Err(de::Error::custom("empty TDX evidence"));
            }
            Ok(bytes)
        }
    }
    deserializer.deserialize_seq(Bytes)
}

fn hash(bytes: &[u8]) -> [u8; 48] {
    digest::digest(&digest::SHA384, bytes)
        .as_ref()
        .try_into()
        .expect("SHA384 output length")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
#[path = "execution_quote_tests.rs"]
mod tests;
