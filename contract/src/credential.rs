//! KBS-authenticated publication of one encrypted credential to a launch key.
//! A publication is not recipient receipt, provisioning, Cloud KMS use or exec.
//! Plaintext and plaintext hashes are deliberately absent from this wire object.

use crate::{
    decode, frame, hex_bytes, identifier,
    policy_receipt::{AggregateExpectations, VerifiedPolicyAggregate},
    sha384, transcript, verify_signature, Error, Signed, ValidityWindow, VerifiedLaunchGrant,
};
use serde::{Deserialize, Serialize};

pub const CREDENTIAL_DELIVERY_VERSION: u16 = 1;
pub const CREDENTIAL_DELIVERY_PURPOSE: &str = "qlad.execution-proof.credential-delivery.v1";
pub const CREDENTIAL_DELIVERY_PROFILE: &str = "onb17.kbs-credential-delivery-only.v1";
pub const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
pub const MAX_CREDENTIAL_JWE_BYTES: usize = 128 * 1024;

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CredentialDeliveryV1 {
    pub version: u16,
    pub purpose: String,
    pub audience: String,
    pub issuer: String,
    pub profile: String,
    pub grant_sha384: String,
    pub aggregate_sha384: String,
    pub request_sha384: String,
    pub session_id: String,
    pub runtime_sha384: String,
    pub evidence_sha384: String,
    pub init_data_sha384: String,
    pub recorder_key_sha384: String,
    pub keywrap_sha384: String,
    pub ciphertext_sha384: String,
    pub workflow_id: String,
    pub resource_path: [String; 3],
    pub validity: ValidityWindow,
}

impl CredentialDeliveryV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = transcript(b"credential-delivery", self.version);
        for value in [
            &self.purpose,
            &self.audience,
            &self.issuer,
            &self.profile,
            &self.workflow_id,
        ] {
            identifier(value)?;
            frame(&mut out, value.as_bytes());
        }
        hex_bytes(&self.session_id, 32)?;
        frame(&mut out, self.session_id.as_bytes());
        for value in [
            &self.grant_sha384,
            &self.aggregate_sha384,
            &self.request_sha384,
            &self.runtime_sha384,
            &self.evidence_sha384,
            &self.init_data_sha384,
            &self.recorder_key_sha384,
            &self.keywrap_sha384,
            &self.ciphertext_sha384,
        ] {
            hex_bytes(value, 48)?;
            frame(&mut out, value.as_bytes());
        }
        for part in &self.resource_path {
            let mut bytes = part.bytes();
            if part.len() > 128
                || !bytes
                    .next()
                    .is_some_and(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                || !bytes.all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            {
                return Err(Error::InvalidField);
            }
            frame(&mut out, part.as_bytes());
        }
        self.validity.append_to(&mut out)?;
        Ok(out)
    }

    pub fn digest_sha384(&self) -> Result<String, Error> {
        Ok(sha384(&self.signing_bytes()?))
    }
}

/// Configured independently of the submitted response. The client additionally
/// checks this key commitment against its own generated recipient key.
pub struct DeliveryExpectations {
    pub aggregate: AggregateExpectations,
    pub audience: String,
    pub issuer: String,
    pub keywrap_sha384: String,
}

/// Authenticated publication metadata only; no Deserialize/Clone/Debug escape.
pub struct VerifiedCredentialDelivery {
    statement: CredentialDeliveryV1,
    digest: String,
    producer: String,
}

impl VerifiedCredentialDelivery {
    pub fn statement(&self) -> &CredentialDeliveryV1 {
        &self.statement
    }
    pub fn digest_sha384(&self) -> &str {
        &self.digest
    }
    pub fn grant_digest(&self) -> &str {
        &self.statement.grant_sha384
    }
    pub fn aggregate_digest(&self) -> &str {
        &self.statement.aggregate_sha384
    }
    pub fn kbs_proof_key_sha384(&self) -> &str {
        &self.producer
    }
    pub fn keywrap_sha384(&self) -> &str {
        &self.statement.keywrap_sha384
    }
    pub fn ciphertext_sha384(&self) -> &str {
        &self.statement.ciphertext_sha384
    }
    pub fn workflow_id(&self) -> &str {
        &self.statement.workflow_id
    }
    pub fn resource_path(&self) -> &[String; 3] {
        &self.statement.resource_path
    }
    pub fn validity(&self) -> &ValidityWindow {
        &self.statement.validity
    }
}

pub fn verify_credential_delivery(
    receipt_json: &[u8],
    grant: &VerifiedLaunchGrant,
    aggregate: &VerifiedPolicyAggregate,
    expected: &DeliveryExpectations,
    jwe_bytes: &[u8],
    trusted_now: u64,
) -> Result<VerifiedCredentialDelivery, Error> {
    if jwe_bytes.is_empty() || jwe_bytes.len() > MAX_CREDENTIAL_JWE_BYTES {
        return Err(Error::TooLarge);
    }
    identifier(&expected.audience)?;
    identifier(&expected.issuer)?;
    hex_bytes(&expected.keywrap_sha384, 48)?;
    let signed: Signed<CredentialDeliveryV1> = decode(receipt_json)?;
    let statement = &signed.statement;
    let bytes = statement.signing_bytes()?;
    if statement.version != CREDENTIAL_DELIVERY_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if statement.purpose != CREDENTIAL_DELIVERY_PURPOSE {
        return Err(Error::WrongPurpose);
    }
    if statement.audience != expected.audience {
        return Err(Error::WrongAudience);
    }
    if statement.issuer != expected.issuer {
        return Err(Error::WrongIssuer);
    }
    let producer = sha384(&expected.aggregate.kbs_proof_public_key);
    let policy = aggregate.statement();
    if aggregate.kbs_proof_key_sha384() != producer {
        return Err(Error::ConfusedKeys);
    }
    if statement.profile != CREDENTIAL_DELIVERY_PROFILE
        || policy != &expected.aggregate.expected
        || policy.grant_sha384 != grant.grant_digest()
        || policy.authority_key_sha384 != grant.authority_key_sha384()
        || policy.recorder_key_sha384 != grant.binding().channel_key_sha384
        || policy.as_evaluation.policy_sha384 != grant.binding().launch_policy_sha384
        || statement.grant_sha384 != grant.grant_digest()
        || statement.aggregate_sha384 != aggregate.digest_sha384()
        || statement.request_sha384 != policy.request.digest_sha384()?
        || statement.session_id != policy.session_id
        || statement.runtime_sha384 != policy.runtime_sha384
        || statement.evidence_sha384 != policy.evidence_sha384
        || statement.init_data_sha384 != policy.init_data_sha384
        || statement.recorder_key_sha384 != policy.recorder_key_sha384
        || statement.keywrap_sha384 != expected.keywrap_sha384
        || statement.ciphertext_sha384 != sha384(jwe_bytes)
        || statement.workflow_id != policy.request.workflow_id
        || statement.resource_path != policy.request.resource_path
        || statement.validity != *grant.validity()
    {
        return Err(Error::BindingMismatch);
    }
    verify_signature(
        &expected.aggregate.kbs_proof_public_key,
        &bytes,
        &signed.signature,
    )?;
    statement.validity.check_at(trusted_now)?;
    Ok(VerifiedCredentialDelivery {
        digest: sha384(&bytes),
        statement: signed.statement,
        producer,
    })
}

#[cfg(test)]
mod tests;
