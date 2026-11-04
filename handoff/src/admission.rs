//! Guest-owned, boot-local verification of a software preparation admission.
//!
//! Constructor inputs and clock must come from the trusted guest owner. RPC
//! fields cannot choose roots, expectations, time, or the generated nonce. This
//! gate records verification of one exact bundle, not preparation, custody, an
//! execution permission, or a durable/clone-resistant consume. Production
//! preparation remains unavailable even after all signatures verify.

use execution_proof_contract::{
    admission::{verify_admission_authorization, AdmissionExpectations},
    policy_receipt::{
        verify_policy_aggregate, AggregateExpectations, POLICY_AGGREGATE_PROFILE,
        POLICY_AGGREGATE_PURPOSE, POLICY_AGGREGATE_VERSION,
    },
    verify_launch_grant, GrantExpectations, LaunchGrant, GRANT_PURPOSE, MAX_WIRE_BYTES, VERSION,
};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use std::{
    convert::Infallible,
    fmt,
    sync::{Arc, Mutex},
};

pub struct GuestAdmissionConfig {
    pub grant: GrantExpectations,
    pub expected_grant: LaunchGrant,
    pub aggregate: AggregateExpectations,
    pub audience: String,
    pub issuer: String,
    pub admission_policy_sha384: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestClockError {
    Unavailable,
    OutOfRange,
}

/// The embedding guest chooses this dependency once. No request timestamp or
/// default wall clock is provided: the host can change the ordinary guest clock.
pub trait GuestClock: Send + Sync {
    fn now_unix_seconds(&self) -> Result<u64, GuestClockError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionCheck {
    FirstVerified,
    Historical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateStatus {
    Pending,
    Verified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestUnsupportedReason {
    ContentPreparationUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestAdmissionError {
    InvalidConfiguration,
    EntropyUnavailable,
    TooLarge,
    ClockUnavailable,
    ClockOutOfRange,
    ClockRegression,
    Contract(execution_proof_contract::Error),
    BindingMismatch,
    Conflict,
    Poisoned,
    Unsupported(GuestUnsupportedReason),
}

impl fmt::Display for GuestAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "guest admission configuration rejected",
            Self::EntropyUnavailable => "guest admission entropy unavailable",
            Self::TooLarge => "guest admission bundle exceeds bounds",
            Self::ClockUnavailable => "guest admission clock unavailable",
            Self::ClockOutOfRange => "guest admission clock out of range",
            Self::ClockRegression => "guest admission clock regressed",
            Self::Contract(_) => "guest admission signatures or scope rejected",
            Self::BindingMismatch => "guest admission differs from trusted grant",
            Self::Conflict => "guest admission bundle conflicts with retained verification",
            Self::Poisoned => "guest admission state unavailable",
            Self::Unsupported(_) => "guest content preparation unavailable",
        })
    }
}
impl std::error::Error for GuestAdmissionError {}
impl From<execution_proof_contract::Error> for GuestAdmissionError {
    fn from(error: execution_proof_contract::Error) -> Self {
        Self::Contract(error)
    }
}

struct Bundle {
    grant: Vec<u8>,
    aggregate: Vec<u8>,
    receipt: Vec<u8>,
}
impl Bundle {
    fn matches(&self, grant: &[u8], aggregate: &[u8], receipt: &[u8]) -> bool {
        self.grant == grant && self.aggregate == aggregate && self.receipt == receipt
    }
}
#[derive(Default)]
struct State {
    last_seen_unix_seconds: Option<u64>,
    verified: Option<Bundle>,
}

/// One instance per trusted boot/attempt. The owner must retain it for that
/// lifetime; creating another instance is not durable replay protection.
pub struct GuestAdmissionGate {
    grant: GrantExpectations,
    expected_grant_digest: String,
    expected: AdmissionExpectations,
    clock: Arc<dyn GuestClock>,
    state: Mutex<State>,
}

impl GuestAdmissionGate {
    pub fn new(
        config: GuestAdmissionConfig,
        clock: Arc<dyn GuestClock>,
    ) -> Result<Self, GuestAdmissionError> {
        let expected_grant_digest = config
            .expected_grant
            .digest_sha384()
            .map_err(|_| GuestAdmissionError::InvalidConfiguration)?;
        let binding = &config.expected_grant.binding;
        let aggregate = &config.aggregate.expected;
        let authority_digest = hash(&config.grant.authority_public_key);
        let aggregate_key_digest = hash(&config.aggregate.kbs_proof_public_key);
        if config.expected_grant.version != VERSION
            || config.expected_grant.purpose != GRANT_PURPOSE
            || !config.expected_grant.proof_required
            || binding.container_role != "application-init"
            || config.expected_grant.audience != config.grant.audience
            || binding.authority != config.grant.authority
            || binding.tenant != config.grant.tenant
            || binding.profile_sha384 != config.grant.profile_sha384
            || binding.launch_policy_sha384 != config.grant.launch_policy_sha384
            || binding.image_policy_sha384 != config.grant.image_policy_sha384
            || aggregate.signing_bytes().is_err()
            || aggregate.version != POLICY_AGGREGATE_VERSION
            || aggregate.purpose != POLICY_AGGREGATE_PURPOSE
            || aggregate.profile != POLICY_AGGREGATE_PROFILE
            || aggregate.grant_sha384 != expected_grant_digest
            || aggregate.authority_key_sha384 != authority_digest
            || aggregate.recorder_key_sha384 != binding.channel_key_sha384
            || aggregate.as_evaluation.policy_sha384 != binding.launch_policy_sha384
            || aggregate_key_digest == authority_digest
            || aggregate_key_digest == binding.channel_key_sha384
            || !identifier(&config.audience)
            || !identifier(&config.issuer)
            || !sha384_hex(&config.admission_policy_sha384)
        {
            return Err(GuestAdmissionError::InvalidConfiguration);
        }
        let mut nonce = [0; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| GuestAdmissionError::EntropyUnavailable)?;
        let expected = AdmissionExpectations {
            authority_public_key: config.grant.authority_public_key,
            aggregate: config.aggregate,
            audience: config.audience,
            issuer: config.issuer,
            boot_id: binding.boot_id.clone(),
            attempt_id: binding.attempt_id.clone(),
            guest_nonce: hex(&nonce),
            admission_policy_sha384: config.admission_policy_sha384,
        };
        Ok(Self {
            grant: config.grant,
            expected_grant_digest,
            expected,
            clock,
            state: Mutex::new(State::default()),
        })
    }

    pub fn challenge_nonce(&self) -> &str {
        &self.expected.guest_nonce
    }

    /// Only metadata is returned. Historical success cannot authorize preparation.
    /// Exact raw bytes are retained; a changed bundle never rearms this gate.
    pub fn verify_bundle(
        &self,
        grant_json: &[u8],
        aggregate_json: &[u8],
        receipt_json: &[u8],
    ) -> Result<AdmissionCheck, GuestAdmissionError> {
        if [grant_json, aggregate_json, receipt_json]
            .iter()
            .any(|bytes| bytes.len() > MAX_WIRE_BYTES)
        {
            return Err(GuestAdmissionError::TooLarge);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| GuestAdmissionError::Poisoned)?;
        if let Some(bundle) = &state.verified {
            return if bundle.matches(grant_json, aggregate_json, receipt_json) {
                Ok(AdmissionCheck::Historical)
            } else {
                Err(GuestAdmissionError::Conflict)
            };
        }
        let now = self.clock.now_unix_seconds().map_err(|error| match error {
            GuestClockError::Unavailable => GuestAdmissionError::ClockUnavailable,
            GuestClockError::OutOfRange => GuestAdmissionError::ClockOutOfRange,
        })?;
        if now > i64::MAX as u64 {
            return Err(GuestAdmissionError::ClockOutOfRange);
        }
        if state.last_seen_unix_seconds.is_some_and(|last| now < last) {
            return Err(GuestAdmissionError::ClockRegression);
        }
        // Preserve healthy observed time even when subsequent validity/crypto
        // checks reject. This watermark is boot-local, not anti-rollback storage.
        state.last_seen_unix_seconds = Some(now);
        let grant = verify_launch_grant(grant_json, &self.grant, now)?;
        if grant.grant_digest() != self.expected_grant_digest {
            return Err(GuestAdmissionError::BindingMismatch);
        }
        let aggregate = verify_policy_aggregate(aggregate_json, &grant, &self.expected.aggregate)?;
        let _verified =
            verify_admission_authorization(receipt_json, &grant, &aggregate, &self.expected, now)?;
        state.verified = Some(Bundle {
            grant: grant_json.to_vec(),
            aggregate: aggregate_json.to_vec(),
            receipt: receipt_json.to_vec(),
        });
        Ok(AdmissionCheck::FirstVerified)
    }

    pub fn status(&self) -> Result<GateStatus, GuestAdmissionError> {
        let state = self
            .state
            .lock()
            .map_err(|_| GuestAdmissionError::Poisoned)?;
        Ok(if state.verified.is_some() {
            GateStatus::Verified
        } else {
            GateStatus::Pending
        })
    }

    /// Records verification only, then always refuses production preparation.
    /// No CDH call, path/mount I/O, task binding or FIFO release occurs here.
    pub fn validate_for_preparation(
        &self,
        grant: &[u8],
        aggregate: &[u8],
        receipt: &[u8],
    ) -> Result<Infallible, GuestAdmissionError> {
        self.verify_bundle(grant, aggregate, receipt)?;
        Err(GuestAdmissionError::Unsupported(
            GuestUnsupportedReason::ContentPreparationUnavailable,
        ))
    }
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
}
fn sha384_hex(value: &str) -> bool {
    value.len() == 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                DIGITS[(byte >> 4) as usize] as char,
                DIGITS[(byte & 15) as usize] as char,
            ]
        })
        .collect()
}
fn hash(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA384, bytes).as_ref())
}

#[cfg(test)]
mod tests;
