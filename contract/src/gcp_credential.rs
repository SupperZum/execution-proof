//! GCP v2 namespace: the grant profile, aggregate and publication share the
//! independently selected complete boot binding. No MRCONFIGID reinterpretation.
//! KBS-authenticated publication of one encrypted credential to a launch key.
//! A publication is not recipient receipt, provisioning, Cloud KMS use or exec.
//! Plaintext and plaintext hashes are deliberately absent from this wire object.

use crate::{
    decode, frame,
    gcp_policy_receipt::{GcpAggregateExpectations, VerifiedGcpPolicyAggregate},
    hex_bytes, identifier, sha384, transcript, verify_signature, Error, Signed, ValidityWindow,
    VerifiedLaunchGrant,
};
use serde::{Deserialize, Serialize};

pub const CREDENTIAL_DELIVERY_VERSION: u16 = 2;
pub const CREDENTIAL_DELIVERY_PURPOSE: &str = "qlad.execution-proof.gcp-credential-delivery.v2";
pub const CREDENTIAL_DELIVERY_PROFILE: &str = "onb17.gcp-kbs-credential-delivery-only.v2";
pub use crate::credential::{MAX_CREDENTIAL_BYTES, MAX_CREDENTIAL_JWE_BYTES};

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GcpCredentialDeliveryV2 {
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
    pub boot_binding_sha384: String,
    pub recorder_key_sha384: String,
    pub keywrap_sha384: String,
    pub ciphertext_sha384: String,
    pub workflow_id: String,
    pub resource_path: [String; 3],
    pub validity: ValidityWindow,
}

impl GcpCredentialDeliveryV2 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.version != CREDENTIAL_DELIVERY_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if self.purpose != CREDENTIAL_DELIVERY_PURPOSE {
            return Err(Error::WrongPurpose);
        }
        if self.profile != CREDENTIAL_DELIVERY_PROFILE {
            return Err(Error::InvalidField);
        }
        let mut out = transcript(b"gcp-credential-delivery", self.version);
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
            &self.boot_binding_sha384,
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
pub struct GcpDeliveryExpectations {
    pub aggregate: GcpAggregateExpectations,
    pub audience: String,
    pub issuer: String,
    pub keywrap_sha384: String,
}

/// Authenticated publication metadata only; no Deserialize/Clone/Debug escape.
/// No implicit conversion can move the result into the legacy wire family.
///
/// ```compile_fail
/// use execution_proof_contract::{gcp_credential::VerifiedGcpCredentialDelivery, credential::VerifiedCredentialDelivery};
/// fn legacy(value: VerifiedGcpCredentialDelivery) -> VerifiedCredentialDelivery { value }
/// ```
pub struct VerifiedGcpCredentialDelivery {
    statement: GcpCredentialDeliveryV2,
    digest: String,
    producer: String,
}

impl VerifiedGcpCredentialDelivery {
    pub fn statement(&self) -> &GcpCredentialDeliveryV2 {
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

/// Authenticated public publication metadata without checking ciphertext bytes.
/// This distinct type cannot be used as a checked credential-delivery result.
///
/// ```compile_fail
/// use execution_proof_contract::gcp_credential::{VerifiedGcpCredentialMetadata, VerifiedGcpCredentialDelivery};
/// fn delivery(metadata: VerifiedGcpCredentialMetadata) -> VerifiedGcpCredentialDelivery { metadata }
/// ```
pub struct VerifiedGcpCredentialMetadata {
    publication: VerifiedGcpCredentialDelivery,
}

impl VerifiedGcpCredentialMetadata {
    pub fn statement(&self) -> &GcpCredentialDeliveryV2 {
        self.publication.statement()
    }
    pub fn receipt_sha384(&self) -> &str {
        self.publication.digest_sha384()
    }
    pub fn kbs_proof_key_sha384(&self) -> &str {
        self.publication.kbs_proof_key_sha384()
    }
}

/// Verify the signed publication commitment for a public evidence pack.
/// No ciphertext, recipient receipt, decryption or provisioning is asserted.
pub fn verify_credential_metadata_historical(
    receipt_json: &[u8],
    grant: &VerifiedLaunchGrant,
    aggregate: &VerifiedGcpPolicyAggregate,
    expected: &GcpDeliveryExpectations,
) -> Result<VerifiedGcpCredentialMetadata, Error> {
    Ok(VerifiedGcpCredentialMetadata {
        publication: verify_publication(receipt_json, grant, aggregate, expected, None)?,
    })
}

/// Authenticates the statement and checks the supplied trusted clock.
pub fn verify_credential_delivery(
    receipt_json: &[u8],
    grant: &VerifiedLaunchGrant,
    aggregate: &VerifiedGcpPolicyAggregate,
    expected: &GcpDeliveryExpectations,
    jwe_bytes: &[u8],
    trusted_now: u64,
) -> Result<VerifiedGcpCredentialDelivery, Error> {
    let verified =
        verify_credential_delivery_historical(receipt_json, grant, aggregate, expected, jwe_bytes)?;
    verified.validity().check_at(trusted_now)?;
    Ok(verified)
}

/// Authenticates an already accepted publication and its exact signed context.
/// This performs no current-time check and creates no new admission permission.
/// A guest caller must retain its own pending nonce and one-use admission state.
pub fn verify_credential_delivery_historical(
    receipt_json: &[u8],
    grant: &VerifiedLaunchGrant,
    aggregate: &VerifiedGcpPolicyAggregate,
    expected: &GcpDeliveryExpectations,
    jwe_bytes: &[u8],
) -> Result<VerifiedGcpCredentialDelivery, Error> {
    if jwe_bytes.is_empty() || jwe_bytes.len() > MAX_CREDENTIAL_JWE_BYTES {
        return Err(Error::TooLarge);
    }
    verify_publication(receipt_json, grant, aggregate, expected, Some(jwe_bytes))
}

fn verify_publication(
    receipt_json: &[u8],
    grant: &VerifiedLaunchGrant,
    aggregate: &VerifiedGcpPolicyAggregate,
    expected: &GcpDeliveryExpectations,
    jwe_bytes: Option<&[u8]>,
) -> Result<VerifiedGcpCredentialDelivery, Error> {
    let boot_digest =
        crate::gcp_session::require_boot_binding(grant, &expected.aggregate.boot_binding)?;
    identifier(&expected.audience)?;
    identifier(&expected.issuer)?;
    hex_bytes(&expected.keywrap_sha384, 48)?;
    let signed: Signed<GcpCredentialDeliveryV2> = decode(receipt_json)?;
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
        || policy.boot_binding_sha384 != boot_digest
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
        || statement.boot_binding_sha384 != policy.boot_binding_sha384
        || statement.recorder_key_sha384 != policy.recorder_key_sha384
        || statement.keywrap_sha384 != expected.keywrap_sha384
        || jwe_bytes.is_some_and(|bytes| statement.ciphertext_sha384 != sha384(bytes))
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
    Ok(VerifiedGcpCredentialDelivery {
        digest: sha384(&bytes),
        statement: signed.statement,
        producer,
    })
}
