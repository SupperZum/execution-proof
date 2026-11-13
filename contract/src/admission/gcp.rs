//! GCP-scoped verification of the unchanged generic preparation admission wire.
//! Strong GCP aggregate verification precedes the generic authority context.
use super::*;
use crate::gcp_policy_receipt::{GcpAggregateExpectations, VerifiedGcpPolicyAggregate};

pub const GCP_ADMISSION_REQUEST_VERSION: u16 = 2;
pub const GCP_ADMISSION_REQUEST_PURPOSE: &str =
    "qlad.execution-proof.gcp-issuer-admission-request.v2";

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpAdmissionOperation {
    Redeem,
    Status,
}

/// A typed recorder proof of possession for the issuer's admission operation.
/// It is not a resource token, launch authorization, or signing service.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpAdmissionRequestV2 {
    pub version: u16,
    pub purpose: String,
    pub operation: GcpAdmissionOperation,
    pub audience: String,
    pub grant_sha384: String,
    pub boot_binding_sha384: String,
    pub context_sha384: String,
}
impl GcpAdmissionRequestV2 {
    pub fn new(
        grant: &VerifiedLaunchGrant,
        aggregate: &VerifiedGcpPolicyAggregate,
        guest_nonce: &str,
        admission_policy_sha384: &str,
        audience: &str,
        operation: GcpAdmissionOperation,
    ) -> Result<Self, Error> {
        let request = Self {
            version: GCP_ADMISSION_REQUEST_VERSION,
            purpose: GCP_ADMISSION_REQUEST_PURPOSE.into(),
            operation,
            audience: audience.into(),
            grant_sha384: grant.grant_digest().into(),
            boot_binding_sha384: grant.binding().profile_sha384.clone(),
            context_sha384: policy_admission_context_gcp(
                grant,
                aggregate,
                guest_nonce,
                admission_policy_sha384,
            )?,
        };
        request.signing_bytes()?;
        Ok(request)
    }
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.version != GCP_ADMISSION_REQUEST_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if self.purpose != GCP_ADMISSION_REQUEST_PURPOSE {
            return Err(Error::WrongPurpose);
        }
        identifier(&self.audience)?;
        let mut out = transcript(b"gcp-issuer-admission-request", self.version);
        frame(&mut out, self.purpose.as_bytes());
        frame(
            &mut out,
            match self.operation {
                GcpAdmissionOperation::Redeem => b"redeem",
                GcpAdmissionOperation::Status => b"status",
            },
        );
        frame(&mut out, self.audience.as_bytes());
        for value in [
            &self.grant_sha384,
            &self.boot_binding_sha384,
            &self.context_sha384,
        ] {
            let raw = hex_bytes(value, 48)?;
            if raw == [0; 48] {
                return Err(Error::InvalidField);
            }
            frame(&mut out, &raw);
        }
        Ok(out)
    }
}

/// Authentication of the exact typed operation. The issuer must separately
/// atomically consume the grant and enforce its own current authorization clock.
pub fn verify_gcp_admission_request(
    wire: &[u8],
    recorder_public_key: &[u8; 32],
    expected: &GcpAdmissionRequestV2,
    grant: &VerifiedLaunchGrant,
) -> Result<GcpAdmissionRequestV2, Error> {
    expected.signing_bytes()?;
    if sha384(recorder_public_key) != grant.binding().channel_key_sha384
        || expected.grant_sha384 != grant.grant_digest()
        || expected.boot_binding_sha384 != grant.binding().profile_sha384
    {
        return Err(Error::BindingMismatch);
    }
    let signed: Signed<GcpAdmissionRequestV2> = decode(wire)?;
    let bytes = signed.statement.signing_bytes()?;
    if signed.statement != *expected {
        return Err(Error::BindingMismatch);
    }
    verify_signature(recorder_public_key, &bytes, &signed.signature)?;
    Ok(signed.statement)
}

/// Agreement of authenticated objects only, never an issuer consume operation.
pub fn policy_admission_context_gcp(
    grant: &VerifiedLaunchGrant,
    aggregate: &VerifiedGcpPolicyAggregate,
    guest_nonce: &str,
    admission_policy_sha384: &str,
) -> Result<String, Error> {
    validate_nonce(guest_nonce)?;
    hex_bytes(admission_policy_sha384, 48)?;
    let statement = aggregate.statement();
    if statement.boot_binding_sha384 != grant.binding().profile_sha384 {
        return Err(Error::BindingMismatch);
    }
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
pub struct GcpAdmissionExpectations {
    pub authority_public_key: [u8; 32],
    pub aggregate: GcpAggregateExpectations,
    pub audience: String,
    pub issuer: String,
    pub boot_id: String,
    pub attempt_id: String,
    pub guest_nonce: String,
    pub admission_policy_sha384: String,
}

/// Authenticates the statement and checks the supplied trusted clock.
pub fn verify_gcp_admission_authorization(
    receipt_json: &[u8],
    grant: &VerifiedLaunchGrant,
    aggregate: &VerifiedGcpPolicyAggregate,
    expected: &GcpAdmissionExpectations,
    trusted_now: u64,
) -> Result<VerifiedAdmissionAuthorization, Error> {
    let verified =
        verify_gcp_admission_authorization_historical(receipt_json, grant, aggregate, expected)?;
    verified.validity().check_at(trusted_now)?;
    Ok(verified)
}

/// Authenticates an already accepted publication and its exact signed context.
/// This performs no current-time check and creates no new admission permission.
/// A guest caller must retain its own pending nonce and one-use admission state.
pub fn verify_gcp_admission_authorization_historical(
    receipt_json: &[u8],
    grant: &VerifiedLaunchGrant,
    aggregate: &VerifiedGcpPolicyAggregate,
    expected: &GcpAdmissionExpectations,
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
    crate::gcp_session::require_boot_binding(grant, &expected.aggregate.boot_binding)?;
    if aggregate.statement().boot_binding_sha384
        != expected.aggregate.boot_binding.digest_sha384()?
    {
        return Err(Error::BindingMismatch);
    }
    let context = policy_admission_context_gcp(
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
