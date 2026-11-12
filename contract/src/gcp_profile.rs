//! An independently selected reference authority's signed qualification decision.
//! The signature authenticates the authority's statement. Runtime admission
//! requires a separate authorization.
//! The decision is outside B, preventing a profile/qualification hash cycle.

use crate::{
    frame, hex_bytes, identifier, transcript, verify_signature, Error, Signed, ValidityWindow,
};
use serde::{Deserialize, Serialize};

pub const GCP_QUALIFICATION_VERSION: u16 = 1;
pub const GCP_QUALIFICATION_PURPOSE: &str = "qlad.execution-proof.gcp-producer-qualification.v1";
pub const GCP_QUALIFICATION_PROFILE: &str = "onb17.gcp-exact-profile-d5-d7.v1";
pub const GCP_QUALIFICATION_CLAIM: &str = "exact_profile_boot_producer_d5_d7_qualified";

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GcpQualificationEvidenceRefs {
    pub artifact_closure_sha384: String,
    pub firmware_causality_sha384: String,
    pub producer_isolation_sha384: String,
    pub no_state_copy_sha384: String,
    pub qualification_review_sha384: String,
}
impl GcpQualificationEvidenceRefs {
    fn hashes(&self) -> [&str; 5] {
        [
            &self.artifact_closure_sha384,
            &self.firmware_causality_sha384,
            &self.producer_isolation_sha384,
            &self.no_state_copy_sha384,
            &self.qualification_review_sha384,
        ]
    }
    pub fn validate(&self) -> Result<(), Error> {
        for value in self.hashes() {
            nonzero_hash(value)?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GcpProducerQualificationV1 {
    pub version: u16,
    pub purpose: String,
    pub profile: String,
    pub claim: String,
    pub qualification_id: String,
    pub issuer: String,
    pub boot_binding_sha384: String,
    pub pe_sha384: String,
    pub firmware_mrtd: String,
    pub module_policy_sha384: String,
    pub evidence_refs: GcpQualificationEvidenceRefs,
    pub validity: ValidityWindow,
}
impl GcpProducerQualificationV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.version != GCP_QUALIFICATION_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if self.purpose != GCP_QUALIFICATION_PURPOSE {
            return Err(Error::WrongPurpose);
        }
        if self.profile != GCP_QUALIFICATION_PROFILE || self.claim != GCP_QUALIFICATION_CLAIM {
            return Err(Error::InvalidField);
        }
        identifier(&self.qualification_id)?;
        identifier(&self.issuer)?;
        self.validity.validate()?;
        self.evidence_refs.validate()?;
        let mut bytes = transcript(b"gcp-producer-qualification", self.version);
        for value in [
            &self.purpose,
            &self.profile,
            &self.claim,
            &self.qualification_id,
            &self.issuer,
        ] {
            frame(&mut bytes, value.as_bytes());
        }
        for value in [
            &self.boot_binding_sha384,
            &self.pe_sha384,
            &self.firmware_mrtd,
            &self.module_policy_sha384,
        ]
        .into_iter()
        .map(String::as_str)
        .chain(self.evidence_refs.hashes())
        {
            nonzero_hash(value)?;
            frame(&mut bytes, &hex_bytes(value, 48)?);
        }
        self.validity.append_to(&mut bytes)?;
        Ok(bytes)
    }
    pub fn digest_sha384(&self) -> Result<String, Error> {
        Ok(crate::sha384(&self.signing_bytes()?))
    }
}
fn nonzero_hash(value: &str) -> Result<(), Error> {
    if hex_bytes(value, 48)? == [0; 48] {
        return Err(Error::InvalidField);
    }
    Ok(())
}

/// All fields are relying-party/issuer-selected outside submitted pack bytes.
/// Callers must separately enforce qualification-root separation from tenant,
/// grant and credential signers. Evidence hashes are selected reviewed references,
/// never learned from a discovery quote being appraised.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpQualificationExpectations {
    pub qualification_public_key: [u8; 32],
    pub issuer: String,
    pub boot_binding_sha384: String,
    pub pe_sha384: String,
    pub firmware_mrtd: String,
    pub module_policy_sha384: String,
    pub evidence_refs: GcpQualificationEvidenceRefs,
}
/// Authenticated authority statement only. No public constructor/serde/boolean
/// or conversion can turn this statement into protected execution or key origin.
pub struct VerifiedGcpQualification {
    statement: GcpProducerQualificationV1,
    digest: String,
}
impl VerifiedGcpQualification {
    pub fn statement(&self) -> &GcpProducerQualificationV1 {
        &self.statement
    }
    pub fn digest_sha384(&self) -> &str {
        &self.digest
    }
    pub fn validity(&self) -> &ValidityWindow {
        &self.statement.validity
    }
}
pub fn verify_gcp_qualification(
    bytes: &[u8],
    expected: &GcpQualificationExpectations,
    trusted_now: u64,
) -> Result<VerifiedGcpQualification, Error> {
    let verified = verify_gcp_qualification_historical(bytes, expected)?;
    verified.validity().check_at(trusted_now)?;
    Ok(verified)
}
/// Historical signature/expectation authentication only; creates no fresh
/// authorization. Issuers must check their own live clock before every new L/A.
pub fn verify_gcp_qualification_historical(
    bytes: &[u8],
    expected: &GcpQualificationExpectations,
) -> Result<VerifiedGcpQualification, Error> {
    if expected.qualification_public_key == [0; 32] {
        return Err(Error::ConfusedKeys);
    }
    identifier(&expected.issuer)?;
    expected.evidence_refs.validate()?;
    for value in [
        &expected.boot_binding_sha384,
        &expected.pe_sha384,
        &expected.firmware_mrtd,
        &expected.module_policy_sha384,
    ] {
        nonzero_hash(value)?;
    }
    let signed: Signed<GcpProducerQualificationV1> = crate::decode(bytes)?;
    let statement = &signed.statement;
    let signing = statement.signing_bytes()?;
    if statement.issuer != expected.issuer {
        return Err(Error::WrongIssuer);
    }
    if statement.boot_binding_sha384 != expected.boot_binding_sha384
        || statement.pe_sha384 != expected.pe_sha384
        || statement.firmware_mrtd != expected.firmware_mrtd
        || statement.module_policy_sha384 != expected.module_policy_sha384
        || statement.evidence_refs != expected.evidence_refs
    {
        return Err(Error::BindingMismatch);
    }
    verify_signature(
        &expected.qualification_public_key,
        &signing,
        &signed.signature,
    )?;
    Ok(VerifiedGcpQualification {
        statement: signed.statement,
        digest: crate::sha384(&signing),
    })
}

#[cfg(test)]
#[path = "gcp_profile_tests.rs"]
mod tests;
