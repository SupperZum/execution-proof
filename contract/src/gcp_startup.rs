//! Public authority-selected attempt configuration. Authentication binds a
//! configuration to L and the GCP aggregate; it creates no boot/custody/exec
//! capability. The guest still owns fresh keys, gates and physical role startup.
use crate::gcp_boot_binding::GcpBootBindingV1;
use crate::gcp_policy_receipt::VerifiedGcpPolicyAggregate;
use crate::{
    frame, hex_bytes, identifier, sha384, transcript, verify_signature, Error, Signed,
    VerifiedLaunchGrant,
};
use serde::{Deserialize, Serialize};

pub const PLAN_PURPOSE: &str = "qlad.execution-proof.gcp-attempt-plan.v1";
pub const CAPSULE_PURPOSE: &str = "qlad.execution-proof.gcp-role-capsule.v1";
pub const MAX_CAPSULE_BYTES: usize = 2 << 20;
pub const MAX_SPEC_BYTES: usize = 256 << 10;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpAttemptPlanV1 {
    pub version: u16,
    pub purpose: String,
    pub authority: String,
    pub boot_binding: GcpBootBindingV1,
    pub grant_sha384: String,
    pub aggregate_sha384: String,
    pub admission_policy_sha384: String,
    /// An authorized task selector, not authoritative Kubernetes Pod identity.
    pub container_id: String,
    pub execution_audience: String,
    pub execution_nonce_hex: String,
    pub effective_spec_sha384: String,
    pub trust_snapshot_sha384: String,
}
impl GcpAttemptPlanV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.version != 1 {
            return Err(Error::UnsupportedVersion);
        }
        if self.purpose != PLAN_PURPOSE {
            return Err(Error::WrongPurpose);
        }
        identifier(&self.authority)?;
        identifier(&self.container_id)?;
        identifier(&self.execution_audience)?;
        let mut out = transcript(b"gcp-attempt-plan", self.version);
        for value in [
            &self.purpose,
            &self.authority,
            &self.container_id,
            &self.execution_audience,
        ] {
            frame(&mut out, value.as_bytes());
        }
        let nonce = hex_bytes(&self.execution_nonce_hex, 32)?;
        if nonce == [0; 32] {
            return Err(Error::InvalidField);
        }
        frame(&mut out, &nonce);
        for value in [
            self.boot_binding.digest_sha384()?,
            self.grant_sha384.clone(),
            self.aggregate_sha384.clone(),
            self.admission_policy_sha384.clone(),
            self.effective_spec_sha384.clone(),
            self.trust_snapshot_sha384.clone(),
        ] {
            let raw = hex_bytes(&value, 48)?;
            if raw == [0; 48] {
                return Err(Error::InvalidField);
            }
            frame(&mut out, &raw);
        }
        Ok(out)
    }
}
pub fn verify_attempt_plan(
    bytes: &[u8],
    authority: &[u8; 32],
    grant: &VerifiedLaunchGrant,
    aggregate: &VerifiedGcpPolicyAggregate,
    boot_binding: &GcpBootBindingV1,
) -> Result<GcpAttemptPlanV1, Error> {
    let signed: Signed<GcpAttemptPlanV1> = crate::decode(bytes)?;
    let p = &signed.statement;
    let input = p.signing_bytes()?;
    if grant.authority_key_sha384() != sha384(authority)
        || p.authority != grant.binding().authority
        || p.boot_binding != *boot_binding
        || p.boot_binding.digest_sha384()? != grant.binding().profile_sha384
        || p.grant_sha384 != grant.grant_digest()
        || p.grant_sha384 != aggregate.statement().grant_sha384
        || p.aggregate_sha384 != aggregate.digest_sha384()
        || p.effective_spec_sha384 != grant.binding().effective_launch_sha384
    {
        return Err(Error::BindingMismatch);
    }
    verify_signature(authority, &input, &signed.signature)?;
    Ok(signed.statement)
}

/// Transport bytes only, never a serialized trusted startup capability. All
/// arrays are individually bounded during decoding and share the outer 2MiB cap.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpRoleCapsuleV1 {
    pub version: u16,
    pub purpose: String,
    #[serde(deserialize_with = "control")]
    pub signed_manifest: Vec<u8>,
    #[serde(deserialize_with = "control")]
    pub signed_references: Vec<u8>,
    #[serde(deserialize_with = "control")]
    pub signed_grant: Vec<u8>,
    #[serde(deserialize_with = "control")]
    pub signed_aggregate: Vec<u8>,
    #[serde(deserialize_with = "control")]
    pub signed_plan: Vec<u8>,
    #[serde(deserialize_with = "spec")]
    pub effective_spec: Vec<u8>,
}
impl GcpRoleCapsuleV1 {
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != 1 {
            return Err(Error::UnsupportedVersion);
        }
        if self.purpose != CAPSULE_PURPOSE {
            return Err(Error::WrongPurpose);
        }
        for b in [
            &self.signed_manifest,
            &self.signed_references,
            &self.signed_grant,
            &self.signed_aggregate,
            &self.signed_plan,
        ] {
            if b.is_empty() || b.len() > 32 << 10 {
                return Err(Error::TooLarge);
            }
        }
        if self.effective_spec.is_empty() || self.effective_spec.len() > MAX_SPEC_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let b = serde_json::to_vec(self).map_err(|_| Error::Malformed)?;
        if b.len() > MAX_CAPSULE_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.is_empty() || b.len() > MAX_CAPSULE_BYTES {
            return Err(Error::TooLarge);
        }
        let value: Self = serde_json::from_slice(b).map_err(|_| Error::Malformed)?;
        value.validate()?;
        Ok(value)
    }
}
fn bounded<'de, D: serde::Deserializer<'de>, const N: usize>(d: D) -> Result<Vec<u8>, D::Error> {
    struct Bytes<const N: usize>;
    impl<'de, const N: usize> serde::de::Visitor<'de> for Bytes<N> {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("bounded public startup bytes")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            let mut v = Vec::new();
            while let Some(b) = seq.next_element::<u8>()? {
                if v.len() == N {
                    return Err(serde::de::Error::custom("startup bytes limit"));
                }
                v.push(b);
            }
            if v.is_empty() {
                return Err(serde::de::Error::custom("empty startup bytes"));
            }
            Ok(v)
        }
    }
    d.deserialize_seq(Bytes::<N>)
}
fn control<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    bounded::<D, { 32 << 10 }>(d)
}
fn spec<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    bounded::<D, MAX_SPEC_BYTES>(d)
}
