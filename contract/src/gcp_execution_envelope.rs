//! Bounded public transport for original GCP TDX evidence. Parsing authenticates
//! neither a quote, a CCEL event, a reference policy nor an execution producer.
//! Collectors retain original padding; appraisers verify crypto, full REPORT_DATA,
//! CCEL replay and independently provisioned reference/qualification policy.

use crate::{
    gcp_execution_quote::{
        GcpQuoteChallenge, GCP_EXECUTION_QUOTE_PROFILE, GCP_EXECUTION_QUOTE_PURPOSE,
    },
    Error,
};
use serde::{
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use std::fmt;

pub const GCP_EXECUTION_ENVELOPE_VERSION: u16 = 2;
pub const MAX_GCP_DECODED_EVIDENCE_BYTES: usize = 1 << 20;
pub const MAX_GCP_ENVELOPE_BYTES: usize = 4 << 20;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GcpExecutionEnvelope {
    pub version: u16,
    pub purpose: String,
    pub profile: String,
    pub challenge: GcpQuoteChallenge,
    pub tdx_quote: Vec<u8>,
    /// Original ACPI CCEL table bytes, distinct from its event log.
    pub ccel_table: Vec<u8>,
    pub ccel_log: Vec<u8>,
}

impl GcpExecutionEnvelope {
    pub fn new(
        challenge: GcpQuoteChallenge,
        tdx_quote: Vec<u8>,
        ccel_table: Vec<u8>,
        ccel_log: Vec<u8>,
    ) -> Result<Self, Error> {
        let value = Self {
            version: GCP_EXECUTION_ENVELOPE_VERSION,
            purpose: GCP_EXECUTION_QUOTE_PURPOSE.into(),
            profile: GCP_EXECUTION_QUOTE_PROFILE.into(),
            challenge,
            tdx_quote,
            ccel_table,
            ccel_log,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != GCP_EXECUTION_ENVELOPE_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if self.purpose != GCP_EXECUTION_QUOTE_PURPOSE {
            return Err(Error::WrongPurpose);
        }
        if self.profile != GCP_EXECUTION_QUOTE_PROFILE {
            return Err(Error::InvalidField);
        }
        self.challenge.validate()?;
        let mut total = 0usize;
        for bytes in [&self.tdx_quote, &self.ccel_table, &self.ccel_log] {
            if bytes.is_empty() {
                return Err(Error::InvalidField);
            }
            total = total.checked_add(bytes.len()).ok_or(Error::TooLarge)?;
            if total > MAX_GCP_DECODED_EVIDENCE_BYTES {
                return Err(Error::TooLarge);
            }
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| Error::Malformed)?;
        if bytes.len() > MAX_GCP_ENVELOPE_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_GCP_ENVELOPE_BYTES {
            return Err(Error::TooLarge);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Error::Malformed)?;
        value.validate()?;
        Ok(value)
    }
}

/// One shared budget for all three arrays, regardless of JSON field order.
/// Never reserve from an untrusted sequence length hint.
pub(crate) struct EvidenceBytes<'a>(pub(crate) &'a mut usize);
impl<'de> DeserializeSeed<'de> for EvidenceBytes<'_> {
    type Value = Vec<u8>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        struct Bytes<'a>(&'a mut usize);
        impl<'de> Visitor<'de> for Bytes<'_> {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a nonempty byte array within the shared evidence budget")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut bytes = Vec::new();
                while let Some(byte) = sequence.next_element::<u8>()? {
                    if *self.0 == 0 {
                        return Err(de::Error::custom("combined GCP evidence byte limit"));
                    }
                    *self.0 -= 1;
                    bytes.push(byte);
                }
                if bytes.is_empty() {
                    return Err(de::Error::custom("empty GCP evidence array"));
                }
                Ok(bytes)
            }
        }
        deserializer.deserialize_seq(Bytes(self.0))
    }
}

impl<'de> Deserialize<'de> for GcpExecutionEnvelope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Version,
            Purpose,
            Profile,
            Challenge,
            TdxQuote,
            CcelTable,
            CcelLog,
        }
        struct Envelope;
        impl<'de> Visitor<'de> for Envelope {
            type Value = GcpExecutionEnvelope;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a strict GCP execution envelope")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let (mut version, mut purpose, mut profile, mut challenge) =
                    (None, None, None, None);
                let (mut tdx_quote, mut ccel_table, mut ccel_log) = (None, None, None);
                let mut remaining = MAX_GCP_DECODED_EVIDENCE_BYTES;
                macro_rules! scalar {
                    ($slot:ident) => {{
                        if $slot.is_some() {
                            return Err(de::Error::duplicate_field(stringify!($slot)));
                        }
                        $slot = Some(map.next_value()?);
                    }};
                }
                macro_rules! evidence {
                    ($slot:ident) => {{
                        if $slot.is_some() {
                            return Err(de::Error::duplicate_field(stringify!($slot)));
                        }
                        $slot = Some(map.next_value_seed(EvidenceBytes(&mut remaining))?);
                    }};
                }
                while let Some(field) = map.next_key()? {
                    match field {
                        Field::Version => scalar!(version),
                        Field::Purpose => scalar!(purpose),
                        Field::Profile => scalar!(profile),
                        Field::Challenge => scalar!(challenge),
                        Field::TdxQuote => evidence!(tdx_quote),
                        Field::CcelTable => evidence!(ccel_table),
                        Field::CcelLog => evidence!(ccel_log),
                    }
                }
                macro_rules! required {
                    ($slot:ident) => {
                        $slot.ok_or_else(|| de::Error::missing_field(stringify!($slot)))?
                    };
                }
                let value = GcpExecutionEnvelope {
                    version: required!(version),
                    purpose: required!(purpose),
                    profile: required!(profile),
                    challenge: required!(challenge),
                    tdx_quote: required!(tdx_quote),
                    ccel_table: required!(ccel_table),
                    ccel_log: required!(ccel_log),
                };
                value.validate().map_err(de::Error::custom)?;
                Ok(value)
            }
        }
        deserializer.deserialize_map(Envelope)
    }
}

#[cfg(test)]
#[path = "gcp_execution_envelope_tests.rs"]
mod tests;
