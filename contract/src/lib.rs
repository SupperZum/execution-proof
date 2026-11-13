//! Bounded authentication of launch/appraisal statements, not an execution proof.
//!
//! `VerifiedStatements` establishes signatures and exact relying-party expectations.
//! It does NOT establish boot/key origin, freshness against a replay store, actual
//! AS/KBS evaluation, KBS receipt authenticity, rootfs custody, or deployed TCB
//! enforcement. In particular, signed AS hashes about KBS are authenticated AS
//! statements about associations, not independently verified KBS decisions.

use ring::{digest, signature};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt;

pub mod admission;
pub mod bootstrap;
pub mod credential;
pub mod execution;
pub mod execution_quote;
pub mod gcp_artifact;
pub mod gcp_boot_binding;
pub mod gcp_bootstrap;
pub mod gcp_credential;
pub mod gcp_execution_envelope;
pub mod gcp_execution_quote;
pub mod gcp_policy_receipt;
pub mod gcp_profile;
pub mod gcp_session;
pub mod gcp_startup;
pub mod policy_receipt;
pub mod session;

pub const VERSION: u16 = 3;
pub const GRANT_PURPOSE: &str = "qlad.execution-proof.launch.v3";
pub const APPRAISAL_PURPOSE: &str = "qlad.execution-proof.appraisal.v3";
pub const MAX_WIRE_BYTES: usize = 16 * 1024;
pub const MAX_ID_BYTES: usize = 128;

/// Signed authorization acceptance interval in Unix seconds, never an exec deadline.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValidityWindow {
    pub not_before: u64,
    pub expires: u64,
}

impl ValidityWindow {
    /// The upper bound is compatible with the issuer's signed SQLite INTEGERs.
    pub fn validate(&self) -> Result<(), Error> {
        if self.not_before >= self.expires || self.expires > i64::MAX as u64 {
            return Err(Error::InvalidTime);
        }
        Ok(())
    }

    /// The caller supplies its trusted clock; a guest/request timestamp is not sufficient.
    pub fn check_at(&self, trusted_now: u64) -> Result<(), Error> {
        self.validate()?;
        if trusted_now > i64::MAX as u64 {
            return Err(Error::InvalidTime);
        }
        if trusted_now < self.not_before {
            return Err(Error::NotYetValid);
        }
        if trusted_now >= self.expires {
            return Err(Error::Expired);
        }
        Ok(())
    }

    fn append_to(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.validate()?;
        frame(out, &self.not_before.to_be_bytes());
        frame(out, &self.expires.to_be_bytes());
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LaunchBinding {
    pub authority: String,
    pub tenant: String,
    pub workload_id: String,
    pub container_role: String,
    pub attempt_id: String,
    pub boot_id: String,
    pub channel_key_sha384: String,
    pub bootstrap_context_sha384: String,
    pub selected_manifest_sha256: String,
    pub effective_launch_sha384: String,
    pub profile_sha384: String,
    pub launch_policy_sha384: String,
    pub image_policy_sha384: String,
    pub challenge_sha384: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KbsAssociation {
    pub decision_sha384: String,
    pub policy_sha384: String,
    pub input_sha384: String,
    pub session_sha384: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationCommitments {
    pub policy_id: String,
    pub policy_sha384: String,
    pub input_sha384: String,
    pub rvps_sha384: String,
    pub acceptance_policy_sha384: String,
    pub kbs: KbsAssociation,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LaunchGrant {
    pub version: u16,
    pub purpose: String,
    pub audience: String,
    pub proof_required: bool,
    pub grant_id: String,
    pub validity: ValidityWindow,
    pub binding: LaunchBinding,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AppraisalVerdict {
    Affirming,
    Negative,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProofAppraisal {
    pub version: u16,
    pub purpose: String,
    pub audience: String,
    pub issuer: String,
    pub verdict: AppraisalVerdict,
    pub grant_sha384: String,
    pub binding: LaunchBinding,
    pub evaluation: EvaluationCommitments,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub statement: T,
    /// Lowercase hex encoding of an Ed25519 signature (64 bytes).
    pub signature: String,
}

/// Operator-selected grant trust and policy scope, not supplied by the grant.
pub struct GrantExpectations {
    pub authority_public_key: [u8; 32],
    pub audience: String,
    pub authority: String,
    pub tenant: String,
    pub profile_sha384: String,
    pub launch_policy_sha384: String,
    pub image_policy_sha384: String,
}

/// An authenticated authority grant; the current verifier also checks its clock.
/// This is not proof of bootstrap/key origin, attestation, preparation, or exec.
/// Historical verification authenticates signatures only. A later admission must
/// recheck its own clock before changing state.
pub struct VerifiedLaunchGrant {
    grant: LaunchGrant,
    grant_digest: String,
    authority_key_digest: String,
}

impl VerifiedLaunchGrant {
    pub fn binding(&self) -> &LaunchBinding {
        &self.grant.binding
    }
    pub fn grant_id(&self) -> &str {
        &self.grant.grant_id
    }
    pub fn validity(&self) -> &ValidityWindow {
        &self.grant.validity
    }
    pub fn grant_digest(&self) -> &str {
        &self.grant_digest
    }
    pub fn authority_key_sha384(&self) -> &str {
        &self.authority_key_digest
    }
}

/// Selected by the relying party, never populated from the unverified bundle.
pub struct TrustedExpectations {
    pub authority_public_key: [u8; 32],
    pub as_proof_public_key: [u8; 32],
    pub audience: String,
    pub as_issuer: String,
    pub grant_id: String,
    pub binding: LaunchBinding,
    pub evaluation: EvaluationCommitments,
}

/// Authenticated statements only; no execution/admission capability is implied.
/// There is deliberately no public constructor, Deserialize, or Clone.
pub struct VerifiedStatements {
    grant: LaunchGrant,
    appraisal: ProofAppraisal,
    grant_digest: String,
    appraisal_digest: String,
    context_digest: String,
    authority_key_digest: String,
    as_proof_key_digest: String,
}

impl VerifiedStatements {
    pub fn validity(&self) -> &ValidityWindow {
        &self.grant.validity
    }
    pub fn binding(&self) -> &LaunchBinding {
        &self.grant.binding
    }
    pub fn evaluation(&self) -> &EvaluationCommitments {
        &self.appraisal.evaluation
    }
    pub fn appraisal_issuer(&self) -> &str {
        &self.appraisal.issuer
    }
    pub fn grant_id(&self) -> &str {
        &self.grant.grant_id
    }
    pub fn grant_digest(&self) -> &str {
        &self.grant_digest
    }
    pub fn appraisal_digest(&self) -> &str {
        &self.appraisal_digest
    }
    /// Domain-separated SHA-384 over the exact grant/appraisal transcript hashes.
    pub fn context_digest(&self) -> &str {
        &self.context_digest
    }
    /// Fingerprint of the actual key used to authenticate the grant.
    pub fn authority_key_sha384(&self) -> &str {
        &self.authority_key_digest
    }
    /// Fingerprint of the actual key used to authenticate the appraisal.
    pub fn as_proof_key_sha384(&self) -> &str {
        &self.as_proof_key_digest
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    Malformed,
    InvalidField,
    UnsupportedVersion,
    UnsupportedRole,
    WrongPurpose,
    WrongAudience,
    WrongIssuer,
    ConfusedKeys,
    ProofRequired,
    UnacceptedAppraisal,
    BindingMismatch,
    InvalidSignature,
    InvalidTime,
    NotYetValid,
    Expired,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "execution statement rejected: {self:?}")
    }
}
impl std::error::Error for Error {}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(Error::TooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| Error::Malformed)
}

fn identifier(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    {
        return Err(Error::InvalidField);
    }
    Ok(())
}

fn hex_bytes(value: &str, byte_count: usize) -> Result<Vec<u8>, Error> {
    if value.len() != byte_count * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::InvalidField);
    }
    fn nibble(b: u8) -> u8 {
        if b <= b'9' {
            b - b'0'
        } else {
            b - b'a' + 10
        }
    }
    Ok(value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| (nibble(p[0]) << 4) | nibble(p[1]))
        .collect())
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    value
        .iter()
        .flat_map(|b| {
            [
                DIGITS[(b >> 4) as usize] as char,
                DIGITS[(b & 15) as usize] as char,
            ]
        })
        .collect()
}

fn sha384(value: &[u8]) -> String {
    hex(digest::digest(&digest::SHA384, value).as_ref())
}

fn validate_binding(binding: &LaunchBinding) -> Result<(), Error> {
    for id in [
        &binding.authority,
        &binding.tenant,
        &binding.workload_id,
        &binding.container_role,
        &binding.attempt_id,
        &binding.boot_id,
    ] {
        identifier(id)?;
    }
    for hash in [
        &binding.channel_key_sha384,
        &binding.bootstrap_context_sha384,
        &binding.effective_launch_sha384,
        &binding.profile_sha384,
        &binding.launch_policy_sha384,
        &binding.image_policy_sha384,
        &binding.challenge_sha384,
    ] {
        hex_bytes(hash, 48)?;
    }
    hex_bytes(&binding.selected_manifest_sha256, 32)?;
    Ok(())
}

fn validate_evaluation(evaluation: &EvaluationCommitments) -> Result<(), Error> {
    identifier(&evaluation.policy_id)?;
    for hash in [
        &evaluation.policy_sha384,
        &evaluation.input_sha384,
        &evaluation.rvps_sha384,
        &evaluation.acceptance_policy_sha384,
        &evaluation.kbs.decision_sha384,
        &evaluation.kbs.policy_sha384,
        &evaluation.kbs.input_sha384,
        &evaluation.kbs.session_sha384,
    ] {
        hex_bytes(hash, 48)?;
    }
    Ok(())
}

// Every variable field has a validated length <=128; fixed hashes <=96. Frames
// use a u32 big-endian byte length, with no map ordering or JSON canonicalization.
fn frame(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn transcript(domain: &[u8], version: u16) -> Vec<u8> {
    let mut out = b"QLAD-EXEC-PROOF\0".to_vec();
    out.extend_from_slice(&version.to_be_bytes());
    frame(&mut out, domain);
    out
}

fn binding_frames(out: &mut Vec<u8>, binding: &LaunchBinding) {
    for field in [
        &binding.authority,
        &binding.tenant,
        &binding.workload_id,
        &binding.container_role,
        &binding.attempt_id,
        &binding.boot_id,
        &binding.channel_key_sha384,
        &binding.bootstrap_context_sha384,
        &binding.selected_manifest_sha256,
        &binding.effective_launch_sha384,
        &binding.profile_sha384,
        &binding.launch_policy_sha384,
        &binding.image_policy_sha384,
        &binding.challenge_sha384,
    ] {
        frame(out, field.as_bytes());
    }
}

impl LaunchGrant {
    /// Fixed ordered signing transcript. JSON spelling/order is never signed.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        identifier(&self.purpose)?;
        identifier(&self.audience)?;
        identifier(&self.grant_id)?;
        validate_binding(&self.binding)?;
        let mut out = transcript(b"launch-grant", self.version);
        for field in [&self.purpose, &self.audience, &self.grant_id] {
            frame(&mut out, field.as_bytes());
        }
        frame(&mut out, &[u8::from(self.proof_required)]);
        self.validity.append_to(&mut out)?;
        binding_frames(&mut out, &self.binding);
        Ok(out)
    }
    pub fn digest_sha384(&self) -> Result<String, Error> {
        Ok(sha384(&self.signing_bytes()?))
    }
}

impl ProofAppraisal {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        for id in [&self.purpose, &self.audience, &self.issuer] {
            identifier(id)?;
        }
        validate_binding(&self.binding)?;
        validate_evaluation(&self.evaluation)?;
        hex_bytes(&self.grant_sha384, 48)?;
        let mut out = transcript(b"proof-appraisal", self.version);
        for field in [
            &self.purpose,
            &self.audience,
            &self.issuer,
            &self.grant_sha384,
        ] {
            frame(&mut out, field.as_bytes());
        }
        let verdict = match self.verdict {
            AppraisalVerdict::Affirming => 1,
            AppraisalVerdict::Negative => 2,
            AppraisalVerdict::Unknown => 3,
        };
        frame(&mut out, &[verdict]);
        binding_frames(&mut out, &self.binding);
        let e = &self.evaluation;
        for field in [
            &e.policy_id,
            &e.policy_sha384,
            &e.input_sha384,
            &e.rvps_sha384,
            &e.acceptance_policy_sha384,
            &e.kbs.decision_sha384,
            &e.kbs.policy_sha384,
            &e.kbs.input_sha384,
            &e.kbs.session_sha384,
        ] {
            frame(&mut out, field.as_bytes());
        }
        Ok(out)
    }
    pub fn digest_sha384(&self) -> Result<String, Error> {
        Ok(sha384(&self.signing_bytes()?))
    }
}

fn verify_signature(key: &[u8; 32], bytes: &[u8], encoded: &str) -> Result<(), Error> {
    let sig = hex_bytes(encoded, 64)?;
    signature::UnparsedPublicKey::new(&signature::ED25519, key)
        .verify(bytes, &sig)
        .map_err(|_| Error::InvalidSignature)
}

/// Verify L before producing A, without requiring the appraisal being created.
pub fn verify_launch_grant(
    grant_json: &[u8],
    expected: &GrantExpectations,
    trusted_now: u64,
) -> Result<VerifiedLaunchGrant, Error> {
    let grant = verify_launch_grant_historical(grant_json, expected)?;
    grant.validity().check_at(trusted_now)?;
    Ok(grant)
}

/// Authenticate a stored grant's signature, shape, and configured trust/policies.
/// This does not check current validity and never grants fresh permission.
pub fn verify_launch_grant_historical(
    grant_json: &[u8],
    expected: &GrantExpectations,
) -> Result<VerifiedLaunchGrant, Error> {
    let signed: Signed<LaunchGrant> = decode(grant_json)?;
    for id in [&expected.audience, &expected.authority, &expected.tenant] {
        identifier(id)?;
    }
    for hash in [
        &expected.profile_sha384,
        &expected.launch_policy_sha384,
        &expected.image_policy_sha384,
    ] {
        hex_bytes(hash, 48)?;
    }
    let grant = &signed.statement;
    let bytes = grant.signing_bytes()?;
    if grant.version != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if grant.purpose != GRANT_PURPOSE {
        return Err(Error::WrongPurpose);
    }
    if grant.audience != expected.audience {
        return Err(Error::WrongAudience);
    }
    if !grant.proof_required {
        return Err(Error::ProofRequired);
    }
    if grant.binding.container_role != "application-init" {
        return Err(Error::UnsupportedRole);
    }
    verify_signature(&expected.authority_public_key, &bytes, &signed.signature)?;
    let binding = &grant.binding;
    if binding.authority != expected.authority
        || binding.tenant != expected.tenant
        || binding.profile_sha384 != expected.profile_sha384
        || binding.launch_policy_sha384 != expected.launch_policy_sha384
        || binding.image_policy_sha384 != expected.image_policy_sha384
    {
        return Err(Error::BindingMismatch);
    }
    Ok(VerifiedLaunchGrant {
        grant: signed.statement,
        grant_digest: sha384(&bytes),
        authority_key_digest: sha384(&expected.authority_public_key),
    })
}

/// Authenticate signatures/bindings and window shape for historical inspection.
/// This function does not check whether the grant is valid at the current time.
pub fn verify_statements(
    grant_json: &[u8],
    appraisal_json: &[u8],
    expected: &TrustedExpectations,
) -> Result<VerifiedStatements, Error> {
    let grant: Signed<LaunchGrant> = decode(grant_json)?;
    let appraisal: Signed<ProofAppraisal> = decode(appraisal_json)?;
    if expected.authority_public_key == expected.as_proof_public_key {
        return Err(Error::ConfusedKeys);
    }
    for id in [&expected.audience, &expected.as_issuer, &expected.grant_id] {
        identifier(id)?;
    }
    validate_binding(&expected.binding)?;
    validate_evaluation(&expected.evaluation)?;
    let l = &grant.statement;
    let a = &appraisal.statement;
    let l_bytes = l.signing_bytes()?;
    let a_bytes = a.signing_bytes()?;
    if l.version != VERSION || a.version != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if l.purpose != GRANT_PURPOSE || a.purpose != APPRAISAL_PURPOSE {
        return Err(Error::WrongPurpose);
    }
    if l.audience != expected.audience || a.audience != expected.audience {
        return Err(Error::WrongAudience);
    }
    if a.issuer != expected.as_issuer {
        return Err(Error::WrongIssuer);
    }
    if !l.proof_required {
        return Err(Error::ProofRequired);
    }
    if l.binding.container_role != "application-init" {
        return Err(Error::UnsupportedRole);
    }
    verify_signature(&expected.authority_public_key, &l_bytes, &grant.signature)?;
    verify_signature(
        &expected.as_proof_public_key,
        &a_bytes,
        &appraisal.signature,
    )?;
    if a.verdict != AppraisalVerdict::Affirming {
        return Err(Error::UnacceptedAppraisal);
    }
    let grant_digest = sha384(&l_bytes);
    if l.grant_id != expected.grant_id
        || l.binding != expected.binding
        || a.binding != l.binding
        || a.grant_sha384 != grant_digest
        || a.evaluation != expected.evaluation
    {
        return Err(Error::BindingMismatch);
    }
    let appraisal_digest = sha384(&a_bytes);
    let mut context = transcript(b"authenticated-statements", VERSION);
    frame(&mut context, grant_digest.as_bytes());
    frame(&mut context, appraisal_digest.as_bytes());
    Ok(VerifiedStatements {
        grant: grant.statement,
        appraisal: appraisal.statement,
        grant_digest,
        appraisal_digest,
        context_digest: sha384(&context),
        authority_key_digest: sha384(&expected.authority_public_key),
        as_proof_key_digest: sha384(&expected.as_proof_public_key),
    })
}

/// Authenticate statements and enforce the grant's current acceptance window.
/// A later admission must recheck its own trusted clock before changing state.
pub fn verify_statements_at(
    grant_json: &[u8],
    appraisal_json: &[u8],
    expected: &TrustedExpectations,
    trusted_now: u64,
) -> Result<VerifiedStatements, Error> {
    let statements = verify_statements(grant_json, appraisal_json, expected)?;
    statements.validity().check_at(trusted_now)?;
    Ok(statements)
}

#[cfg(test)]
mod tests;
