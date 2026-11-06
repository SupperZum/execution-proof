//! Authority-signed authorization of a subsequent software admission stage.
//!
//! Policy aggregates remain non-authorizing. This separate receipt authenticates
//! an authority decision over an exact grant/aggregate/guest-nonce context. Its
//! signature does not itself prove a durable consume, nonce origin, real guest
//! identity, CDH custody, resource delivery, or execution. The issuer must commit
//! its one-time transition before publishing, and the guest must own replay state.
//! Current acceptance time is not a deadline for a later physical execution.

use crate::{
    binding_frames, decode, frame, hex_bytes, identifier,
    policy_receipt::{AggregateExpectations, VerifiedPolicyAggregate},
    sha384, transcript, validate_binding, verify_signature, Error, LaunchBinding, Signed,
    ValidityWindow, VerifiedLaunchGrant,
};
use serde::{Deserialize, Serialize};

pub const ADMISSION_VERSION: u16 = 1;
pub const ADMISSION_PURPOSE: &str = "qlad.execution-proof.preparation-admission.v1";
pub const ADMISSION_PROFILE: &str = "onb17.software-policy-admission-only.v1";

fn validate_nonce(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > crate::session::MAX_SESSION_NONCE_BYTES
        || !value.is_ascii()
    {
        return Err(Error::InvalidField);
    }
    Ok(())
}

/// New wire domain, not an AS appraisal or an execution/custody capability.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionAuthorizationV1 {
    pub version: u16,
    pub purpose: String,
    pub audience: String,
    pub issuer: String,
    pub profile: String,
    pub grant_id: String,
    pub grant_sha384: String,
    pub aggregate_sha384: String,
    pub aggregate_key_sha384: String,
    pub context_sha384: String,
    pub guest_nonce: String,
    pub admission_policy_sha384: String,
    pub validity: ValidityWindow,
    pub binding: LaunchBinding,
}

impl AdmissionAuthorizationV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        for id in [
            &self.purpose,
            &self.audience,
            &self.issuer,
            &self.profile,
            &self.grant_id,
        ] {
            identifier(id)?;
        }
        validate_nonce(&self.guest_nonce)?;
        validate_binding(&self.binding)?;
        let mut out = transcript(b"preparation-admission", self.version);
        for field in [
            &self.purpose,
            &self.audience,
            &self.issuer,
            &self.profile,
            &self.grant_id,
        ] {
            frame(&mut out, field.as_bytes());
        }
        for hash in [
            &self.grant_sha384,
            &self.aggregate_sha384,
            &self.aggregate_key_sha384,
            &self.context_sha384,
            &self.admission_policy_sha384,
        ] {
            hex_bytes(hash, 48)?;
            frame(&mut out, hash.as_bytes());
        }
        frame(&mut out, self.guest_nonce.as_bytes());
        self.validity.append_to(&mut out)?;
        binding_frames(&mut out, &self.binding);
        Ok(out)
    }
    pub fn digest_sha384(&self) -> Result<String, Error> {
        Ok(sha384(&self.signing_bytes()?))
    }
}

/// Agreement of authenticated objects only, never an issuer consume operation.
pub fn policy_admission_context(
    grant: &VerifiedLaunchGrant,
    aggregate: &VerifiedPolicyAggregate,
    guest_nonce: &str,
    admission_policy_sha384: &str,
) -> Result<String, Error> {
    validate_nonce(guest_nonce)?;
    hex_bytes(admission_policy_sha384, 48)?;
    let statement = aggregate.statement();
    if statement.grant_sha384 != grant.grant_digest()
        || statement.authority_key_sha384 != grant.authority_key_sha384()
        || statement.recorder_key_sha384 != grant.binding().channel_key_sha384
        || statement.as_evaluation.policy_sha384 != grant.binding().launch_policy_sha384
    {
        return Err(Error::BindingMismatch);
    }
    let mut out = transcript(b"policy-admission-context", ADMISSION_VERSION);
    for field in [
        ADMISSION_PROFILE,
        grant.grant_digest(),
        grant.authority_key_sha384(),
        aggregate.digest_sha384(),
        aggregate.kbs_proof_key_sha384(),
        guest_nonce,
        admission_policy_sha384,
    ] {
        frame(&mut out, field.as_bytes());
    }
    Ok(sha384(&out))
}

/// Guest/operator-owned expectations, never populated from the received bundle.
/// Exact aggregate expectations include producer, policies, input/data, and request.
pub struct AdmissionExpectations {
    pub authority_public_key: [u8; 32],
    pub aggregate: AggregateExpectations,
    pub audience: String,
    pub issuer: String,
    pub boot_id: String,
    pub attempt_id: String,
    pub guest_nonce: String,
    pub admission_policy_sha384: String,
}

/// Authenticated software admission statement, not a one-time exec permit.
/// No public constructor, Deserialize, Clone, or raw Debug implementation.
pub struct VerifiedAdmissionAuthorization {
    authorization: AdmissionAuthorizationV1,
    authority_key_digest: String,
}

impl VerifiedAdmissionAuthorization {
    pub fn binding(&self) -> &LaunchBinding {
        &self.authorization.binding
    }
    pub fn grant_id(&self) -> &str {
        &self.authorization.grant_id
    }
    pub fn grant_digest(&self) -> &str {
        &self.authorization.grant_sha384
    }
    pub fn aggregate_digest(&self) -> &str {
        &self.authorization.aggregate_sha384
    }
    pub fn context_digest(&self) -> &str {
        &self.authorization.context_sha384
    }
    pub fn validity(&self) -> &ValidityWindow {
        &self.authorization.validity
    }
    pub fn authority_key_sha384(&self) -> &str {
        &self.authority_key_digest
    }
    pub fn aggregate_key_sha384(&self) -> &str {
        &self.authorization.aggregate_key_sha384
    }
    pub fn guest_nonce(&self) -> &str {
        &self.authorization.guest_nonce
    }
    pub fn admission_policy_sha384(&self) -> &str {
        &self.authorization.admission_policy_sha384
    }
}

/// Authenticates the statement and checks a trusted authority/lab clock.
pub fn verify_admission_authorization(
    receipt_json: &[u8],
    grant: &VerifiedLaunchGrant,
    aggregate: &VerifiedPolicyAggregate,
    expected: &AdmissionExpectations,
    trusted_now: u64,
) -> Result<VerifiedAdmissionAuthorization, Error> {
    let verified =
        verify_admission_authorization_historical(receipt_json, grant, aggregate, expected)?;
    verified.validity().check_at(trusted_now)?;
    Ok(verified)
}

/// Authenticates an already accepted publication and its exact signed context.
/// This performs no current-time check and creates no new admission permission.
/// A guest caller must retain its own pending nonce and one-use admission state.
pub fn verify_admission_authorization_historical(
    receipt_json: &[u8],
    grant: &VerifiedLaunchGrant,
    aggregate: &VerifiedPolicyAggregate,
    expected: &AdmissionExpectations,
) -> Result<VerifiedAdmissionAuthorization, Error> {
    let signed: Signed<AdmissionAuthorizationV1> = decode(receipt_json)?;
    for id in [
        &expected.audience,
        &expected.issuer,
        &expected.boot_id,
        &expected.attempt_id,
    ] {
        identifier(id)?;
    }
    expected.aggregate.expected.signing_bytes()?;
    let context = policy_admission_context(
        grant,
        aggregate,
        &expected.guest_nonce,
        &expected.admission_policy_sha384,
    )?;
    let authority_key_digest = sha384(&expected.authority_public_key);
    if grant.authority_key_sha384() != authority_key_digest
        || aggregate.kbs_proof_key_sha384() != sha384(&expected.aggregate.kbs_proof_public_key)
    {
        return Err(Error::ConfusedKeys);
    }
    let authorization = &signed.statement;
    let bytes = authorization.signing_bytes()?;
    if authorization.version != ADMISSION_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if authorization.purpose != ADMISSION_PURPOSE {
        return Err(Error::WrongPurpose);
    }
    if authorization.audience != expected.audience {
        return Err(Error::WrongAudience);
    }
    if authorization.issuer != expected.issuer {
        return Err(Error::WrongIssuer);
    }
    if authorization.profile != ADMISSION_PROFILE
        || aggregate.statement() != &expected.aggregate.expected
        || authorization.grant_id != grant.grant_id()
        || authorization.grant_sha384 != grant.grant_digest()
        || authorization.aggregate_sha384 != aggregate.digest_sha384()
        || authorization.aggregate_key_sha384 != aggregate.kbs_proof_key_sha384()
        || authorization.context_sha384 != context
        || authorization.guest_nonce != expected.guest_nonce
        || authorization.admission_policy_sha384 != expected.admission_policy_sha384
        || authorization.validity != *grant.validity()
        || authorization.binding != *grant.binding()
        || grant.binding().boot_id != expected.boot_id
        || grant.binding().attempt_id != expected.attempt_id
    {
        return Err(Error::BindingMismatch);
    }
    verify_signature(&expected.authority_public_key, &bytes, &signed.signature)?;
    Ok(VerifiedAdmissionAuthorization {
        authorization: signed.statement,
        authority_key_digest,
    })
}

#[cfg(test)]
mod tests;
