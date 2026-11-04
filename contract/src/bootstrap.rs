//! Authenticated tenant intent and bootstrap statements for a software protocol.
//!
//! A signature and recorder-key possession do not establish hardware attestation,
//! key origin/custody, protected channel termination, measured configuration, or
//! clone resistance. The bootstrap verifier backend and producer isolation are
//! absent. These types must not enable a production proof profile. The issuer
//! must select trust roots/profiles independently and consume its saved challenge
//! atomically. This module supplies neither replay state nor a clock. The signed
//! challenge verifier checks its window only at the supplied trusted instant.

use super::{
    decode, frame, hex_bytes, identifier, sha384, transcript, verify_signature, AppraisalVerdict,
    Error, Signed, ValidityWindow,
};
use serde::{Deserialize, Serialize};

pub const BOOTSTRAP_VERSION: u16 = 2;
pub const TENANT_INTENT_VERSION: u16 = 2;
pub const CHALLENGE_PURPOSE: &str = "qlad.execution-proof.bootstrap-challenge.v2";
pub const BOOTSTRAP_APPRAISAL_PURPOSE: &str = "qlad.execution-proof.bootstrap-appraisal.v2";
pub const POSSESSION_PURPOSE: &str = "qlad.execution-proof.recorder-possession.v2";
pub const TENANT_INTENT_PURPOSE: &str = "qlad.execution-proof.tenant-intent.v2";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapChallenge {
    pub version: u16,
    pub purpose: String,
    pub audience: String,
    pub authority: String,
    pub tenant: String,
    pub workload_id: String,
    pub attempt_id: String,
    pub challenge_id: String,
    pub nonce_hex: String,
    pub intent_sha384: String,
    pub boot_profile_sha384: String,
    pub producer_profile_sha384: String,
    pub validity: ValidityWindow,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapBinding {
    pub challenge_sha384: String,
    pub boot_id: String,
    pub boot_nonce_hex: String,
    pub recorder_public_key_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapAppraisal {
    pub version: u16,
    pub purpose: String,
    pub audience: String,
    pub issuer: String,
    pub verdict: AppraisalVerdict,
    pub binding: BootstrapBinding,
    pub boot_profile_sha384: String,
    pub producer_profile_sha384: String,
    pub evidence_sha384: String,
    pub policy_sha384: String,
    pub input_sha384: String,
    pub rvps_sha384: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecorderPossession {
    pub version: u16,
    pub purpose: String,
    pub audience: String,
    pub challenge_sha384: String,
    pub appraisal_sha384: String,
}

/// The challenge comes from the issuer's trusted pending row, not the request.
pub struct BootstrapExpectations {
    pub challenge: BootstrapChallenge,
    pub verifier_public_key: [u8; 32],
    pub verifier_issuer: String,
    pub policy_sha384: String,
    pub input_sha384: String,
    pub rvps_sha384: String,
}

/// Verified signature/PoP statements only, deliberately not `VerifiedBoot`.
pub struct VerifiedBootstrapStatements {
    challenge: BootstrapChallenge,
    appraisal: BootstrapAppraisal,
    recorder_public_key: [u8; 32],
    channel_key_digest: String,
    challenge_digest: String,
    appraisal_digest: String,
    context_digest: String,
    verifier_key_digest: String,
}

impl VerifiedBootstrapStatements {
    pub fn binding(&self) -> &BootstrapBinding {
        &self.appraisal.binding
    }
    pub fn challenge(&self) -> &BootstrapChallenge {
        &self.challenge
    }
    pub fn boot_id(&self) -> &str {
        &self.appraisal.binding.boot_id
    }
    pub fn recorder_public_key(&self) -> &[u8; 32] {
        &self.recorder_public_key
    }
    pub fn recorder_public_key_hex(&self) -> &str {
        &self.appraisal.binding.recorder_public_key_hex
    }
    pub fn channel_key_sha384(&self) -> &str {
        &self.channel_key_digest
    }
    pub fn challenge_digest(&self) -> &str {
        &self.challenge_digest
    }
    pub fn appraisal_digest(&self) -> &str {
        &self.appraisal_digest
    }
    pub fn context_digest(&self) -> &str {
        &self.context_digest
    }
    pub fn verifier_key_sha384(&self) -> &str {
        &self.verifier_key_digest
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TenantIntent {
    pub version: u16,
    pub purpose: String,
    pub audience: String,
    pub authority: String,
    pub tenant: String,
    pub workload_id: String,
    pub container_role: String,
    pub attempt_id: String,
    pub selected_manifest_sha256: String,
    pub effective_launch_sha384: String,
    pub profile_sha384: String,
    pub launch_policy_sha384: String,
    pub image_policy_sha384: String,
    pub validity: ValidityWindow,
}

/// Operator-selected tenant key, scope, and allowed software-lab profile.
pub struct TenantIntentExpectations {
    pub tenant_public_key: [u8; 32],
    pub audience: String,
    pub authority: String,
    pub tenant: String,
    pub profile_sha384: String,
}

/// Signature and configured scope only; no bootstrap or execution authorization.
pub struct VerifiedTenantIntent {
    statement: TenantIntent,
    digest: String,
    tenant_key_digest: String,
}

impl VerifiedTenantIntent {
    pub fn statement(&self) -> &TenantIntent {
        &self.statement
    }
    pub fn digest_sha384(&self) -> &str {
        &self.digest
    }
    pub fn tenant_key_sha384(&self) -> &str {
        &self.tenant_key_digest
    }
}

fn nonce(value: &str) -> Result<(), Error> {
    if hex_bytes(value, 32)?.iter().all(|b| *b == 0) {
        return Err(Error::InvalidField);
    }
    Ok(())
}

fn strings(out: &mut Vec<u8>, values: &[&str]) {
    for value in values {
        frame(out, value.as_bytes());
    }
}

impl BootstrapChallenge {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        for value in [
            &self.purpose,
            &self.audience,
            &self.authority,
            &self.tenant,
            &self.workload_id,
            &self.attempt_id,
            &self.challenge_id,
        ] {
            identifier(value)?;
        }
        nonce(&self.nonce_hex)?;
        for value in [
            &self.intent_sha384,
            &self.boot_profile_sha384,
            &self.producer_profile_sha384,
        ] {
            hex_bytes(value, 48)?;
        }
        let mut out = transcript(b"bootstrap-challenge", self.version);
        strings(
            &mut out,
            &[
                &self.purpose,
                &self.audience,
                &self.authority,
                &self.tenant,
                &self.workload_id,
                &self.attempt_id,
                &self.challenge_id,
                &self.nonce_hex,
                &self.intent_sha384,
                &self.boot_profile_sha384,
                &self.producer_profile_sha384,
            ],
        );
        self.validity.append_to(&mut out)?;
        Ok(out)
    }
    pub fn digest_sha384(&self) -> Result<String, Error> {
        Ok(sha384(&self.signing_bytes()?))
    }
}

impl BootstrapBinding {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        identifier(&self.boot_id)?;
        nonce(&self.boot_nonce_hex)?;
        hex_bytes(&self.challenge_sha384, 48)?;
        hex_bytes(&self.recorder_public_key_hex, 32)?;
        let mut out = transcript(b"bootstrap-binding", BOOTSTRAP_VERSION);
        strings(
            &mut out,
            &[
                &self.challenge_sha384,
                &self.boot_id,
                &self.boot_nonce_hex,
                &self.recorder_public_key_hex,
            ],
        );
        Ok(out)
    }
    /// Candidate expected REPORT_DATA digest only; computing it is not attestation.
    pub fn digest_sha384(&self) -> Result<String, Error> {
        Ok(sha384(&self.signing_bytes()?))
    }
}

impl BootstrapAppraisal {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        for value in [&self.purpose, &self.audience, &self.issuer] {
            identifier(value)?;
        }
        for value in [
            &self.boot_profile_sha384,
            &self.producer_profile_sha384,
            &self.evidence_sha384,
            &self.policy_sha384,
            &self.input_sha384,
            &self.rvps_sha384,
        ] {
            hex_bytes(value, 48)?;
        }
        let binding = self.binding.signing_bytes()?;
        let mut out = transcript(b"bootstrap-appraisal", self.version);
        strings(&mut out, &[&self.purpose, &self.audience, &self.issuer]);
        let verdict = match self.verdict {
            AppraisalVerdict::Affirming => 1,
            AppraisalVerdict::Negative => 2,
            AppraisalVerdict::Unknown => 3,
        };
        frame(&mut out, &[verdict]);
        frame(&mut out, &binding);
        strings(
            &mut out,
            &[
                &self.boot_profile_sha384,
                &self.producer_profile_sha384,
                &self.evidence_sha384,
                &self.policy_sha384,
                &self.input_sha384,
                &self.rvps_sha384,
            ],
        );
        Ok(out)
    }
    pub fn digest_sha384(&self) -> Result<String, Error> {
        Ok(sha384(&self.signing_bytes()?))
    }
}

impl RecorderPossession {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        for value in [&self.purpose, &self.audience] {
            identifier(value)?;
        }
        for value in [&self.challenge_sha384, &self.appraisal_sha384] {
            hex_bytes(value, 48)?;
        }
        let mut out = transcript(b"recorder-possession", self.version);
        strings(
            &mut out,
            &[
                &self.purpose,
                &self.audience,
                &self.challenge_sha384,
                &self.appraisal_sha384,
            ],
        );
        Ok(out)
    }
    pub fn digest_sha384(&self) -> Result<String, Error> {
        Ok(sha384(&self.signing_bytes()?))
    }
}

impl TenantIntent {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        for value in [
            &self.purpose,
            &self.audience,
            &self.authority,
            &self.tenant,
            &self.workload_id,
            &self.container_role,
            &self.attempt_id,
        ] {
            identifier(value)?;
        }
        hex_bytes(&self.selected_manifest_sha256, 32)?;
        for value in [
            &self.effective_launch_sha384,
            &self.profile_sha384,
            &self.launch_policy_sha384,
            &self.image_policy_sha384,
        ] {
            hex_bytes(value, 48)?;
        }
        let mut out = transcript(b"tenant-intent", self.version);
        strings(
            &mut out,
            &[
                &self.purpose,
                &self.audience,
                &self.authority,
                &self.tenant,
                &self.workload_id,
                &self.container_role,
                &self.attempt_id,
                &self.selected_manifest_sha256,
                &self.effective_launch_sha384,
                &self.profile_sha384,
                &self.launch_policy_sha384,
                &self.image_policy_sha384,
            ],
        );
        self.validity.append_to(&mut out)?;
        Ok(out)
    }
    pub fn digest_sha384(&self) -> Result<String, Error> {
        Ok(sha384(&self.signing_bytes()?))
    }
}

pub fn verify_tenant_intent(
    json: &[u8],
    expected: &TenantIntentExpectations,
) -> Result<VerifiedTenantIntent, Error> {
    let signed: Signed<TenantIntent> = decode(json)?;
    for value in [&expected.audience, &expected.authority, &expected.tenant] {
        identifier(value)?;
    }
    hex_bytes(&expected.profile_sha384, 48)?;
    let intent = &signed.statement;
    let bytes = intent.signing_bytes()?;
    if intent.version != TENANT_INTENT_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if intent.purpose != TENANT_INTENT_PURPOSE {
        return Err(Error::WrongPurpose);
    }
    if intent.audience != expected.audience {
        return Err(Error::WrongAudience);
    }
    if intent.authority != expected.authority
        || intent.tenant != expected.tenant
        || intent.profile_sha384 != expected.profile_sha384
    {
        return Err(Error::BindingMismatch);
    }
    if intent.container_role != "application-init" {
        return Err(Error::UnsupportedRole);
    }
    verify_signature(&expected.tenant_public_key, &bytes, &signed.signature)?;
    Ok(VerifiedTenantIntent {
        statement: signed.statement,
        digest: sha384(&bytes),
        tenant_key_digest: sha384(&expected.tenant_public_key),
    })
}

/// Authenticate the issuer's exact signed challenge and its acceptance window.
/// Expected scope/profiles and the key originate outside the unverified request.
pub fn verify_bootstrap_challenge(
    json: &[u8],
    authority_public_key: &[u8; 32],
    expected: &BootstrapChallenge,
    trusted_now: u64,
) -> Result<BootstrapChallenge, Error> {
    let signed: Signed<BootstrapChallenge> = decode(json)?;
    let challenge = &signed.statement;
    let bytes = challenge.signing_bytes()?;
    if challenge.version != BOOTSTRAP_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if challenge.purpose != CHALLENGE_PURPOSE {
        return Err(Error::WrongPurpose);
    }
    if challenge != expected {
        return Err(Error::BindingMismatch);
    }
    verify_signature(authority_public_key, &bytes, &signed.signature)?;
    challenge.validity.check_at(trusted_now)?;
    Ok(signed.statement)
}

pub fn verify_bootstrap_statements(
    appraisal_json: &[u8],
    possession_json: &[u8],
    expected: &BootstrapExpectations,
) -> Result<VerifiedBootstrapStatements, Error> {
    let appraisal: Signed<BootstrapAppraisal> = decode(appraisal_json)?;
    let possession: Signed<RecorderPossession> = decode(possession_json)?;
    let challenge_digest = expected.challenge.digest_sha384()?;
    if expected.challenge.version != BOOTSTRAP_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if expected.challenge.purpose != CHALLENGE_PURPOSE {
        return Err(Error::WrongPurpose);
    }
    identifier(&expected.verifier_issuer)?;
    for value in [
        &expected.policy_sha384,
        &expected.input_sha384,
        &expected.rvps_sha384,
    ] {
        hex_bytes(value, 48)?;
    }
    let a = &appraisal.statement;
    let p = &possession.statement;
    let a_bytes = a.signing_bytes()?;
    let p_bytes = p.signing_bytes()?;
    if a.version != BOOTSTRAP_VERSION || p.version != BOOTSTRAP_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if a.purpose != BOOTSTRAP_APPRAISAL_PURPOSE || p.purpose != POSSESSION_PURPOSE {
        return Err(Error::WrongPurpose);
    }
    if a.audience != expected.challenge.audience || p.audience != expected.challenge.audience {
        return Err(Error::WrongAudience);
    }
    if a.issuer != expected.verifier_issuer {
        return Err(Error::WrongIssuer);
    }
    let recorder_public_key: [u8; 32] = hex_bytes(&a.binding.recorder_public_key_hex, 32)?
        .try_into()
        .map_err(|_| Error::InvalidField)?;
    if recorder_public_key == expected.verifier_public_key {
        return Err(Error::ConfusedKeys);
    }
    verify_signature(
        &expected.verifier_public_key,
        &a_bytes,
        &appraisal.signature,
    )?;
    verify_signature(&recorder_public_key, &p_bytes, &possession.signature)?;
    if a.verdict != AppraisalVerdict::Affirming {
        return Err(Error::UnacceptedAppraisal);
    }
    let appraisal_digest = sha384(&a_bytes);
    if a.binding.challenge_sha384 != challenge_digest
        || p.challenge_sha384 != challenge_digest
        || p.appraisal_sha384 != appraisal_digest
        || a.boot_profile_sha384 != expected.challenge.boot_profile_sha384
        || a.producer_profile_sha384 != expected.challenge.producer_profile_sha384
        || a.policy_sha384 != expected.policy_sha384
        || a.input_sha384 != expected.input_sha384
        || a.rvps_sha384 != expected.rvps_sha384
    {
        return Err(Error::BindingMismatch);
    }
    let verifier_key_digest = sha384(&expected.verifier_public_key);
    let channel_key_digest = sha384(&recorder_public_key);
    let mut context = transcript(b"authenticated-bootstrap-statements", BOOTSTRAP_VERSION);
    strings(
        &mut context,
        &[
            &challenge_digest,
            &appraisal_digest,
            &sha384(&p_bytes),
            &verifier_key_digest,
            &channel_key_digest,
        ],
    );
    Ok(VerifiedBootstrapStatements {
        challenge: expected.challenge.clone(),
        appraisal: appraisal.statement,
        recorder_public_key,
        channel_key_digest,
        challenge_digest,
        appraisal_digest,
        context_digest: sha384(&context),
        verifier_key_digest,
    })
}

#[cfg(test)]
mod tests;
