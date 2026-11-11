//! Bounded data-only prelaunch transport; no execution record or quote privilege.
use crate::{
    gcp_execution_envelope::{
        EvidenceBytes, MAX_GCP_DECODED_EVIDENCE_BYTES, MAX_GCP_ENVELOPE_BYTES,
    },
    Error,
};
use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use std::fmt;

pub const GCP_LAUNCH_EVIDENCE_VERSION: u16 = 2;
pub const GCP_LAUNCH_EVIDENCE_PURPOSE: &str = "qlad.execution-proof.gcp-launch-evidence.v2";
pub const GCP_LAUNCH_EVIDENCE_PROFILE: &str = "onb17.gcp-launch-evidence.v2";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GcpLaunchEvidenceV2 {
    pub version: u16,
    pub purpose: String,
    pub profile: String,
    pub tdx_quote: Vec<u8>,
    pub ccel_table: Vec<u8>,
    pub ccel_log: Vec<u8>,
}
impl GcpLaunchEvidenceV2 {
    pub fn new(tdx_quote: Vec<u8>, ccel_table: Vec<u8>, ccel_log: Vec<u8>) -> Result<Self, Error> {
        let value = Self {
            version: GCP_LAUNCH_EVIDENCE_VERSION,
            purpose: GCP_LAUNCH_EVIDENCE_PURPOSE.into(),
            profile: GCP_LAUNCH_EVIDENCE_PROFILE.into(),
            tdx_quote,
            ccel_table,
            ccel_log,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != GCP_LAUNCH_EVIDENCE_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if self.purpose != GCP_LAUNCH_EVIDENCE_PURPOSE {
            return Err(Error::WrongPurpose);
        }
        if self.profile != GCP_LAUNCH_EVIDENCE_PROFILE {
            return Err(Error::InvalidField);
        }
        let mut total = 0usize;
        for value in [&self.tdx_quote, &self.ccel_table, &self.ccel_log] {
            if value.is_empty() {
                return Err(Error::InvalidField);
            }
            total = total.checked_add(value.len()).ok_or(Error::TooLarge)?;
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

impl<'de> Deserialize<'de> for GcpLaunchEvidenceV2 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Version,
            Purpose,
            Profile,
            TdxQuote,
            CcelTable,
            CcelLog,
        }
        struct Evidence;
        impl<'de> Visitor<'de> for Evidence {
            type Value = GcpLaunchEvidenceV2;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("strict GCP prelaunch evidence")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let (mut version, mut purpose, mut profile) = (None, None, None);
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
                let value = GcpLaunchEvidenceV2 {
                    version: required!(version),
                    purpose: required!(purpose),
                    profile: required!(profile),
                    tdx_quote: required!(tdx_quote),
                    ccel_table: required!(ccel_table),
                    ccel_log: required!(ccel_log),
                };
                value.validate().map_err(de::Error::custom)?;
                Ok(value)
            }
        }
        deserializer.deserialize_map(Evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prelaunch_preserves_original_bytes_but_rejects_execution_and_legacy_domains() {
        let value = GcpLaunchEvidenceV2::new(vec![1, 0, 0], vec![2], vec![3]).unwrap();
        assert_eq!(
            GcpLaunchEvidenceV2::decode(&value.encode().unwrap()).unwrap(),
            value
        );
        for prefix in [
            "\"version\":2,",
            "\"challenge\":{},",
            "\"init_data_sha384\":\"legacy\",",
        ] {
            let wire = String::from_utf8(value.encode().unwrap()).unwrap();
            assert!(GcpLaunchEvidenceV2::decode(
                wire.replacen('{', &format!("{{{prefix}"), 1).as_bytes()
            )
            .is_err());
        }
        let mut wrong = value.clone();
        wrong.purpose = crate::gcp_execution_quote::GCP_EXECUTION_QUOTE_PURPOSE.into();
        assert!(wrong.validate().is_err());
        wrong = value;
        wrong.version = 1;
        assert!(wrong.validate().is_err());
    }
    #[test]
    fn combined_budget_applies_before_allocation_in_every_field_order() {
        for long_field in ["tdx_quote", "ccel_table", "ccel_log"] {
            let mut object =
                serde_json::to_value(GcpLaunchEvidenceV2::new(vec![1], vec![2], vec![3]).unwrap())
                    .unwrap();
            object[long_field] =
                serde_json::to_value(vec![0u8; MAX_GCP_DECODED_EVIDENCE_BYTES - 2]).unwrap();
            let wire = serde_json::to_vec(&object).unwrap();
            assert!(GcpLaunchEvidenceV2::decode(&wire).is_ok());
            object[long_field].as_array_mut().unwrap().push(0.into());
            assert!(GcpLaunchEvidenceV2::decode(&serde_json::to_vec(&object).unwrap()).is_err());
        }
        assert!(GcpLaunchEvidenceV2::new(vec![], vec![1], vec![1]).is_err());
        assert!(GcpLaunchEvidenceV2::decode(&vec![b' '; MAX_GCP_ENVELOPE_BYTES + 1]).is_err());
    }
}
