//! Dedicated KBS statements about actual AS and resource-policy evaluations.
//!
//! This profile trusts the configured combined KBS producer for both evaluations;
//! it does not contain an independent AS signature. A valid signature authenticates
//! that producer's statements, not hardware key origin, resource retrieval,
//! credential provisioning, JWE delivery, content preparation, or execution.
//! These JSON envelopes are not access JWTs or admission capabilities.

use crate::{
    decode, frame, hex_bytes, identifier, sha384, transcript, verify_signature, Error, Signed,
    VerifiedLaunchGrant,
};
use serde::{Deserialize, Deserializer, Serialize};

pub const POLICY_AGGREGATE_VERSION: u16 = 1;
pub const POLICY_AGGREGATE_PURPOSE: &str = "qlad.execution-proof.kbs-policy-aggregate.v1";
pub const POLICY_AGGREGATE_PROFILE: &str = "onb17.kbs-combined-policy-only.v1";

/// The supported request is GET/resource with three path segments, no query/body.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourcePolicyRequest {
    pub method: String,
    pub plugin: String,
    pub resource_path: [String; 3],
    pub workflow_id: String,
    pub request_nonce: String,
}

fn nonce(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > crate::session::MAX_SESSION_NONCE_BYTES
        || !value.is_ascii()
    {
        return Err(Error::InvalidField);
    }
    Ok(())
}

impl ResourcePolicyRequest {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.method != "GET" || self.plugin != "resource" {
            return Err(Error::InvalidField);
        }
        identifier(&self.workflow_id)?;
        nonce(&self.request_nonce)?;
        for part in &self.resource_path {
            identifier(part)?;
            if part == "." || part == ".." {
                return Err(Error::InvalidField);
            }
        }
        let mut out = transcript(b"resource-policy-request", POLICY_AGGREGATE_VERSION);
        for field in [
            &self.method,
            &self.plugin,
            &self.resource_path[0],
            &self.resource_path[1],
            &self.resource_path[2],
            &self.workflow_id,
            &self.request_nonce,
        ] {
            frame(&mut out, field.as_bytes());
        }
        Ok(out)
    }

    pub fn digest_sha384(&self) -> Result<String, Error> {
        Ok(sha384(&self.signing_bytes()?))
    }
}

/// Exact captured bytes. Static data is not independently authenticated RVPS.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyCommitments {
    pub policy_id: String,
    pub policy_sha384: String,
    pub input_sha384: String,
    /// Required JSON member: null means no static data, never an omitted default.
    #[serde(deserialize_with = "required_optional_hash")]
    pub data_sha384: Option<String>,
}

fn required_optional_hash<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}

impl PolicyCommitments {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        identifier(&self.policy_id)?;
        hex_bytes(&self.policy_sha384, 48)?;
        hex_bytes(&self.input_sha384, 48)?;
        for field in [&self.policy_id, &self.policy_sha384, &self.input_sha384] {
            frame(out, field.as_bytes());
        }
        match &self.data_sha384 {
            Some(hash) => {
                hex_bytes(hash, 48)?;
                frame(out, &[1]);
                frame(out, hash.as_bytes());
            }
            None => frame(out, &[0]),
        }
        Ok(())
    }
}

/// Fixed profile asserts strict affirmative AS policy and strict allow KBS policy.
/// The trusted producer must derive these fields from its actual session flow.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LaunchPolicyAggregateV1 {
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
    pub init_data_sha384: String,
    pub evidence_sha384: String,
    pub recorder_key_sha384: String,
    pub request: ResourcePolicyRequest,
    pub as_evaluation: PolicyCommitments,
    pub kbs_evaluation: PolicyCommitments,
}

impl LaunchPolicyAggregateV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        for id in [&self.purpose, &self.audience, &self.issuer, &self.profile] {
            identifier(id)?;
        }
        hex_bytes(&self.session_id, 32)?;
        nonce(&self.nonce)?;
        let mut out = transcript(b"kbs-policy-aggregate", self.version);
        for field in [&self.purpose, &self.audience, &self.issuer, &self.profile] {
            frame(&mut out, field.as_bytes());
        }
        for hash in [
            &self.grant_sha384,
            &self.authority_key_sha384,
            &self.runtime_sha384,
            &self.init_data_sha384,
            &self.evidence_sha384,
            &self.recorder_key_sha384,
        ] {
            hex_bytes(hash, 48)?;
            frame(&mut out, hash.as_bytes());
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

/// Full independently selected expected payload, never copied from received JSON.
/// The dedicated KBS proof key must not be registered with access-token verifiers.
pub struct AggregateExpectations {
    pub kbs_proof_public_key: [u8; 32],
    pub expected: LaunchPolicyAggregateV1,
}

/// Authenticated combined-producer policy statements, without resource permission.
/// No public constructor, Deserialize, Clone, or raw Debug is provided.
pub struct VerifiedPolicyAggregate {
    statement: LaunchPolicyAggregateV1,
    digest: String,
    key_digest: String,
}

impl VerifiedPolicyAggregate {
    pub fn statement(&self) -> &LaunchPolicyAggregateV1 {
        &self.statement
    }
    pub fn digest_sha384(&self) -> &str {
        &self.digest
    }
    pub fn kbs_proof_key_sha384(&self) -> &str {
        &self.key_digest
    }
}

/// Authenticate the exact configured policy-only statement; no clock/replay claim.
/// Callers admitting new work must recheck grant validity and their replay state.
pub fn verify_policy_aggregate(
    bytes: &[u8],
    grant: &VerifiedLaunchGrant,
    expected: &AggregateExpectations,
) -> Result<VerifiedPolicyAggregate, Error> {
    let signed: Signed<LaunchPolicyAggregateV1> = decode(bytes)?;
    expected.expected.signing_bytes()?;
    let statement = &signed.statement;
    let signing_bytes = statement.signing_bytes()?;
    if statement.version != POLICY_AGGREGATE_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if statement.purpose != POLICY_AGGREGATE_PURPOSE {
        return Err(Error::WrongPurpose);
    }
    if statement.audience != expected.expected.audience {
        return Err(Error::WrongAudience);
    }
    if statement.issuer != expected.expected.issuer {
        return Err(Error::WrongIssuer);
    }
    if statement.profile != POLICY_AGGREGATE_PROFILE
        || statement != &expected.expected
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
    Ok(VerifiedPolicyAggregate {
        statement: signed.statement,
        digest: sha384(&signing_bytes),
        key_digest,
    })
}

#[cfg(test)]
pub(crate) mod tests;
