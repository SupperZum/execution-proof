//! GCP combined KBS-producer statements, not an independent AS signature,
//! hardware appraisal, resource permission, credential delivery or execution.

use crate::{
    decode, frame,
    gcp_boot_binding::GcpBootBindingV1,
    gcp_session, hex_bytes, identifier,
    policy_receipt::{PolicyCommitments, ResourcePolicyRequest},
    sha384, transcript, verify_signature, Error, Signed, VerifiedLaunchGrant,
};
use serde::{Deserialize, Serialize};

pub const POLICY_AGGREGATE_VERSION: u16 = 2;
pub const POLICY_AGGREGATE_PURPOSE: &str = "qlad.execution-proof.gcp-kbs-policy-aggregate.v2";
pub const POLICY_AGGREGATE_PROFILE: &str = "onb17.gcp-kbs-combined-policy-only.v2";

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GcpLaunchPolicyAggregateV2 {
    pub version: u16,
    pub purpose: String,
    pub audience: String,
    pub issuer: String,
    pub profile: String,
    pub grant_sha384: String,
    pub authority_key_sha384: String,
    pub session_id: String,
    pub nonce: String,
    pub runtime_sha384: String,
    pub boot_binding_sha384: String,
    pub evidence_sha384: String,
    pub recorder_key_sha384: String,
    pub request: ResourcePolicyRequest,
    pub as_evaluation: PolicyCommitments,
    pub kbs_evaluation: PolicyCommitments,
}

impl GcpLaunchPolicyAggregateV2 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.version != POLICY_AGGREGATE_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if self.purpose != POLICY_AGGREGATE_PURPOSE {
            return Err(Error::WrongPurpose);
        }
        if self.profile != POLICY_AGGREGATE_PROFILE {
            return Err(Error::InvalidField);
        }
        let mut out = transcript(b"gcp-kbs-policy-aggregate", self.version);
        for value in [&self.purpose, &self.audience, &self.issuer, &self.profile] {
            identifier(value)?;
            frame(&mut out, value.as_bytes());
        }
        for hash in [
            &self.grant_sha384,
            &self.authority_key_sha384,
            &self.runtime_sha384,
            &self.boot_binding_sha384,
            &self.evidence_sha384,
            &self.recorder_key_sha384,
        ] {
            hex_bytes(hash, 48)?;
            frame(&mut out, hash.as_bytes());
        }
        hex_bytes(&self.session_id, 32)?;
        if self.nonce.is_empty()
            || self.nonce.len() > crate::session::MAX_SESSION_NONCE_BYTES
            || !self.nonce.is_ascii()
        {
            return Err(Error::InvalidField);
        }
        frame(&mut out, self.session_id.as_bytes());
        frame(&mut out, self.nonce.as_bytes());
        frame(&mut out, &self.request.signing_bytes()?);
        self.as_evaluation.append_to(&mut out)?;
        self.kbs_evaluation.append_to(&mut out)?;
        Ok(out)
    }
    pub fn digest_sha384(&self) -> Result<String, Error> {
        Ok(sha384(&self.signing_bytes()?))
    }
}

/// Entire payload and boot binding are selected outside submitted JSON.
pub struct GcpAggregateExpectations {
    pub kbs_proof_public_key: [u8; 32],
    pub boot_binding: GcpBootBindingV1,
    pub expected: GcpLaunchPolicyAggregateV2,
}

/// Authenticated policy statements only. No legacy conversion or Deserialize.
pub struct VerifiedGcpPolicyAggregate {
    statement: GcpLaunchPolicyAggregateV2,
    digest: String,
    key_digest: String,
}
impl VerifiedGcpPolicyAggregate {
    pub fn statement(&self) -> &GcpLaunchPolicyAggregateV2 {
        &self.statement
    }
    pub fn digest_sha384(&self) -> &str {
        &self.digest
    }
    pub fn kbs_proof_key_sha384(&self) -> &str {
        &self.key_digest
    }
}

pub fn verify_policy_aggregate(
    bytes: &[u8],
    grant: &VerifiedLaunchGrant,
    expected: &GcpAggregateExpectations,
) -> Result<VerifiedGcpPolicyAggregate, Error> {
    let boot_digest = gcp_session::require_boot_binding(grant, &expected.boot_binding)?;
    expected.expected.signing_bytes()?;
    let signed: Signed<GcpLaunchPolicyAggregateV2> = decode(bytes)?;
    let statement = &signed.statement;
    let signing_bytes = statement.signing_bytes()?;
    if statement.audience != expected.expected.audience {
        return Err(Error::WrongAudience);
    }
    if statement.issuer != expected.expected.issuer {
        return Err(Error::WrongIssuer);
    }
    if statement != &expected.expected
        || statement.boot_binding_sha384 != boot_digest
        || statement.grant_sha384 != grant.grant_digest()
        || statement.authority_key_sha384 != grant.authority_key_sha384()
        || statement.as_evaluation.policy_sha384 != grant.binding().launch_policy_sha384
        || statement.recorder_key_sha384 != grant.binding().channel_key_sha384
    {
        return Err(Error::BindingMismatch);
    }
    let key_digest = sha384(&expected.kbs_proof_public_key);
    if key_digest == grant.authority_key_sha384()
        || key_digest == grant.binding().channel_key_sha384
    {
        return Err(Error::ConfusedKeys);
    }
    verify_signature(
        &expected.kbs_proof_public_key,
        &signing_bytes,
        &signed.signature,
    )?;
    Ok(VerifiedGcpPolicyAggregate {
        statement: signed.statement,
        digest: sha384(&signing_bytes),
        key_digest,
    })
}
