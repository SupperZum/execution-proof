//! GCP v2 packs and externally selected trust inputs. No producer-qualified
//! boolean is accepted. The exact reference authority decision is authenticated
//! separately from the execution graph and from hardware verification.
use crate::{
    gcp_boot_evidence::GcpBootEvidencePolicy,
    gcp_tdx_policy::GcpTdxModulePolicyV1,
    hash, hex_field, identifier,
    schema::{
        self, AdmissionTrust, CredentialTrust, EvidencePack, GrantTrust, MAX_PACK_BYTES,
        MAX_TRUST_BYTES,
    },
    VerificationError,
};
use execution_proof_contract::{
    gcp_artifact::{ArtifactVerificationExpectations, GcpQuoteFraming},
    gcp_boot_binding::GcpBootBindingV1,
    gcp_bootstrap::{GcpBootstrapBinding, GcpBootstrapChallenge},
    gcp_policy_receipt::GcpLaunchPolicyAggregateV2,
    gcp_profile::GcpQualificationExpectations,
    gcp_session::GcpLaunchEvidenceV2,
};
use serde::{Deserialize, Serialize};

pub const GCP_PACK_PURPOSE: &str = "qlad.execution-proof.gcp-local-execution-pack.v2";
pub const GCP_TRUST_PURPOSE: &str = "qlad.execution-proof.gcp-verifier-trust.v2";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpBootstrapPublication {
    pub challenge: GcpBootstrapChallenge,
    #[serde(deserialize_with = "schema::control_bytes")]
    pub signed_challenge: Vec<u8>,
    pub binding: GcpBootstrapBinding,
    pub evidence: GcpLaunchEvidenceV2,
    pub recorder_public_key: [u8; 32],
    pub possession_signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpEvidencePackV2 {
    pub version: u16,
    pub purpose: String,
    /// Reuses the bounded public custody-byte container only. Its payloads are
    /// checked exclusively by the GCP graph, never by the legacy verifier.
    pub execution: EvidencePack,
    pub bootstrap: GcpBootstrapPublication,
    #[serde(deserialize_with = "schema::control_bytes")]
    pub qualification: Vec<u8>,
}
impl GcpEvidencePackV2 {
    pub fn from_protected_export(
        export: &[u8],
        credential_receipt: Vec<u8>,
        objects: Vec<schema::SupportingObject>,
        bootstrap: GcpBootstrapPublication,
        qualification: Vec<u8>,
    ) -> Result<Self, VerificationError> {
        let execution = EvidencePack::from_scoped_protected_export(
            export,
            credential_receipt,
            objects,
            2,
            "qlad.execution-proof.protected-export.v2",
        )?;
        let pack = Self {
            version: 2,
            purpose: GCP_PACK_PURPOSE.into(),
            execution,
            bootstrap,
            qualification,
        };
        pack.validate()?;
        Ok(pack)
    }
    pub fn validate(&self) -> Result<(), VerificationError> {
        if self.version != 2 || self.purpose != GCP_PACK_PURPOSE {
            return Err(VerificationError::Invalid("gcp_pack_domain"));
        }
        self.execution.validate()?;
        if self.execution.objects.len() + 20 > schema::MAX_OBJECTS {
            return Err(VerificationError::ResourceLimit("gcp_object_count"));
        }
        schema::bounded_bytes(&self.qualification, 16 << 10)?;
        schema::bounded_bytes(&self.bootstrap.signed_challenge, 16 << 10)?;
        self.bootstrap
            .challenge
            .validate()
            .map_err(|_| VerificationError::Invalid("gcp_pack_bootstrap"))?;
        self.bootstrap
            .binding
            .validate()
            .map_err(|_| VerificationError::Invalid("gcp_pack_bootstrap"))?;
        self.bootstrap
            .evidence
            .encode()
            .map_err(|_| VerificationError::Invalid("gcp_pack_bootstrap"))?;
        hex_field(&self.bootstrap.possession_signature, 64)?;
        // One total serialization ceiling includes both raw quote triplets,
        // the qualification, and every supporting object.
        schema::encode(self, MAX_PACK_BYTES)?;
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, VerificationError> {
        self.validate()?;
        schema::encode(self, MAX_PACK_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, VerificationError> {
        let value: Self = schema::decode(bytes, MAX_PACK_BYTES)?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpQuoteTrust {
    pub audience: String,
    pub boot_binding: GcpBootBindingV1,
    pub trust_snapshot_sha384: String,
    pub boot_policy: GcpBootEvidencePolicy,
    pub module_policy: GcpTdxModulePolicyV1,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpTrustConfigV2 {
    pub version: u16,
    pub purpose: String,
    pub grant: GrantTrust,
    pub aggregate_public_key: [u8; 32],
    pub aggregate_expected: GcpLaunchPolicyAggregateV2,
    pub admission: AdmissionTrust,
    pub credential: CredentialTrust,
    pub quote: GcpQuoteTrust,
    pub qualification: GcpQualificationExpectations,
    pub artifacts: ArtifactVerificationExpectations,
}
impl GcpTrustConfigV2 {
    pub fn validate(&self) -> Result<(), VerificationError> {
        if self.version != 2 || self.purpose != GCP_TRUST_PURPOSE {
            return Err(VerificationError::Invalid("gcp_trust_domain"));
        }
        for id in [
            &self.grant.audience,
            &self.grant.authority,
            &self.grant.tenant,
            &self.admission.audience,
            &self.admission.issuer,
            &self.admission.boot_id,
            &self.admission.attempt_id,
            &self.credential.audience,
            &self.credential.issuer,
            &self.quote.audience,
        ] {
            identifier(id)?;
        }
        for digest in [
            &self.grant.profile_sha384,
            &self.grant.launch_policy_sha384,
            &self.grant.image_policy_sha384,
            &self.admission.admission_policy_sha384,
            &self.credential.keywrap_sha384,
            &self.quote.trust_snapshot_sha384,
        ] {
            hex_field(digest, 48)?;
        }
        self.aggregate_expected
            .signing_bytes()
            .map_err(|_| VerificationError::Invalid("gcp_aggregate_expectations"))?;
        self.quote.boot_policy.validate()?;
        self.quote.module_policy.validate()?;
        let b = self
            .quote
            .boot_binding
            .digest_sha384()
            .map_err(|_| VerificationError::Invalid("gcp_trust_binding"))?;
        let q = &self.qualification;
        let a = &self.artifacts;
        let framing = match self.quote.boot_policy.quote_padding {
            crate::gcp_boot_evidence::QuotePaddingPolicy::ExactFrame => GcpQuoteFraming::ExactFrame,
            crate::gcp_boot_evidence::QuotePaddingPolicy::GcpTsmZeroPadded8000 => {
                GcpQuoteFraming::GcpTsmZeroPadded8000
            }
        };
        if a.boot_binding != self.quote.boot_binding
            || a.pe_authenticode_sha384 != self.quote.boot_policy.expected_pe_sha384
            || a.firmware_mrtd != self.quote.boot_policy.expected_firmware_mrtd
            || a.module_policy_sha384 != q.module_policy_sha384
            || a.quote_framing != framing
        {
            return Err(VerificationError::Invalid("gcp_trust_artifact_binding"));
        }
        let keys = [
            self.grant.authority_public_key,
            self.aggregate_public_key,
            q.qualification_public_key,
            a.build_public_key,
            a.reference_public_key,
        ];
        if keys
            .iter()
            .enumerate()
            .any(|(i, key)| *key == [0; 32] || keys[..i].contains(key))
        {
            return Err(VerificationError::Invalid("gcp_trust_artifact_keys"));
        }
        if self.grant.profile_sha384 != b
            || self.aggregate_expected.boot_binding_sha384 != b
            || q.boot_binding_sha384 != b
            || q.pe_sha384 != self.quote.boot_policy.expected_pe_sha384
            || q.firmware_mrtd != self.quote.boot_policy.expected_firmware_mrtd
            || q.module_policy_sha384 != hash(&self.quote.module_policy.encode()?)
        {
            return Err(VerificationError::Invalid(
                "gcp_trust_qualification_binding",
            ));
        }
        q.evidence_refs
            .validate()
            .map_err(|_| VerificationError::Invalid("gcp_trust_qualification_refs"))?;
        identifier(&q.issuer)?;
        if self.admission.guest_nonce.is_empty()
            || self.admission.guest_nonce.len() > 256
            || !self.admission.guest_nonce.is_ascii()
        {
            return Err(VerificationError::Invalid("gcp_trust_nonce"));
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, VerificationError> {
        self.validate()?;
        schema::encode(self, MAX_TRUST_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, VerificationError> {
        let value: Self = schema::decode(bytes, MAX_TRUST_BYTES)?;
        value.validate()?;
        Ok(value)
    }
}
