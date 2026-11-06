//! Guest-owned, boot-local verification of a software preparation admission.
//!
//! Constructor inputs come from the trusted guest owner. RPC fields cannot choose
//! roots, expectations, or the internally generated nonce. Authorities own live
//! acceptance time; this gate authenticates the committed result against one
//! still-live pending attempt and transfers its local context at most once.
//! Production preparation remains unavailable. This is neither durable replay
//! protection nor a claim of TEE/clone-resistant state or observed execution.

use execution_proof_contract::{
    admission::{
        verify_admission_authorization_historical, AdmissionExpectations,
        VerifiedAdmissionAuthorization,
    },
    policy_receipt::{
        verify_policy_aggregate, AggregateExpectations, POLICY_AGGREGATE_PROFILE,
        POLICY_AGGREGATE_PURPOSE, POLICY_AGGREGATE_VERSION,
    },
    verify_launch_grant_historical, GrantExpectations, LaunchBinding, LaunchGrant, ValidityWindow,
    GRANT_PURPOSE, MAX_WIRE_BYTES, VERSION,
};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use std::{convert::Infallible, fmt, sync::Mutex};

#[cfg(all(target_os = "linux", feature = "rootfs-custody"))]
#[path = "admission_receiver.rs"]
mod receiver;
#[cfg(all(target_os = "linux", feature = "rootfs-custody"))]
pub use receiver::{
    PendingReceiverEnrollment, ReceiverAdmissionVerifier, ReceiverChallenge,
    ReceiverEnrollmentError, VerifiedReceiverAdmission,
};

pub struct GuestAdmissionConfig {
    pub grant: GrantExpectations,
    pub expected_grant: LaunchGrant,
    pub aggregate: AggregateExpectations,
    pub audience: String,
    pub issuer: String,
    pub admission_policy_sha384: String,
}

/// One local admission, minted only by a live pending gate and transferred once.
/// There is no public constructor, Clone, Deserialize, or raw Debug implementation.
/// Borrow this context while preparing; consuming it for bookkeeping does not
/// establish actual content preparation, rootfs custody, or execution.
///
/// Raw authenticated statements cannot be wrapped by an external caller:
/// ```compile_fail
/// use execution_proof_contract::admission::VerifiedAdmissionAuthorization;
/// use execution_proof_handoff::admission::AcceptedAttemptContext;
/// fn forge(authorization: VerifiedAdmissionAuthorization) -> AcceptedAttemptContext {
///     AcceptedAttemptContext { authorization, workflow_id: String::new(), resource_path: Default::default() }
/// }
/// ```
/// A transferred context cannot be duplicated:
/// ```compile_fail
/// use execution_proof_handoff::admission::AcceptedAttemptContext;
/// fn duplicate(context: &AcceptedAttemptContext) -> AcceptedAttemptContext {
///     context.clone()
/// }
/// ```
/// It cannot be restored from wire data:
/// ```compile_fail
/// use execution_proof_handoff::admission::AcceptedAttemptContext;
/// let _: AcceptedAttemptContext = serde_json::from_str("{}").unwrap();
/// ```
/// Raw formatting is deliberately unavailable:
/// ```compile_fail
/// use execution_proof_handoff::admission::AcceptedAttemptContext;
/// fn log(context: &AcceptedAttemptContext) { let _ = format!("{context:?}"); }
/// ```
pub struct AcceptedAttemptContext {
    authorization: VerifiedAdmissionAuthorization,
    workflow_id: String,
    resource_path: [String; 3],
}

impl AcceptedAttemptContext {
    pub fn binding(&self) -> &LaunchBinding {
        self.authorization.binding()
    }
    pub fn grant_id(&self) -> &str {
        self.authorization.grant_id()
    }
    pub fn grant_digest(&self) -> &str {
        self.authorization.grant_digest()
    }
    pub fn aggregate_digest(&self) -> &str {
        self.authorization.aggregate_digest()
    }
    pub fn authority_key_sha384(&self) -> &str {
        self.authorization.authority_key_sha384()
    }
    pub fn aggregate_key_sha384(&self) -> &str {
        self.authorization.aggregate_key_sha384()
    }
    pub fn validity(&self) -> &ValidityWindow {
        self.authorization.validity()
    }
    pub fn context_digest(&self) -> &str {
        self.authorization.context_digest()
    }
    pub fn guest_nonce(&self) -> &str {
        self.authorization.guest_nonce()
    }
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }
    pub fn resource_path(&self) -> &[String; 3] {
        &self.resource_path
    }
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
    Consumed,
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
    NotReady,
    AlreadyConsumed,
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
            Self::NotReady => "guest admission not yet verified",
            Self::AlreadyConsumed => "guest admission context already transferred",
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
    verified: Option<Bundle>,
    accepted: Option<AcceptedAttemptContext>,
    #[cfg(feature = "rootfs-custody")]
    enrollment: Option<[u8; 48]>,
}

/// One instance per trusted boot/attempt. The owner must retain it for that
/// lifetime. State loss creates a fresh nonce, rejecting old receipts; it cannot
/// restore an old consumed grant or provide durable/clone-resistant protection.
pub struct GuestAdmissionGate {
    grant: GrantExpectations,
    expected_grant_digest: String,
    expected: AdmissionExpectations,
    state: Mutex<State>,
}

impl GuestAdmissionGate {
    pub fn new(config: GuestAdmissionConfig) -> Result<Self, GuestAdmissionError> {
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
            state: Mutex::new(State::default()),
        })
    }

    pub fn challenge_nonce(&self) -> &str {
        &self.expected.guest_nonce
    }

    /// Authenticates one committed receipt for this still-live pending nonce.
    /// First delivery may occur after the authority acceptance window: the guest
    /// has no trusted current clock or physical exec deadline. Exact retries are
    /// historical metadata and cannot replenish a transferred context. A changed
    /// bundle never rearms this gate; new authority acceptance remains server-only.
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
        let grant = verify_launch_grant_historical(grant_json, &self.grant)?;
        if grant.grant_digest() != self.expected_grant_digest {
            return Err(GuestAdmissionError::BindingMismatch);
        }
        let aggregate = verify_policy_aggregate(aggregate_json, &grant, &self.expected.aggregate)?;
        let authorization = verify_admission_authorization_historical(
            receipt_json,
            &grant,
            &aggregate,
            &self.expected,
        )?;
        let request = &aggregate.statement().request;
        state.accepted = Some(AcceptedAttemptContext {
            authorization,
            workflow_id: request.workflow_id.clone(),
            resource_path: request.resource_path.clone(),
        });
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
        Ok(match (&state.verified, &state.accepted) {
            (None, _) => GateStatus::Pending,
            (Some(_), Some(_)) => GateStatus::Verified,
            (Some(_), None) => GateStatus::Consumed,
        })
    }

    /// Transfers the accepted context exactly once, including if the caller drops
    /// it or later preparation fails. The retained bundle is a historical tombstone.
    pub fn take_accepted_attempt(&self) -> Result<AcceptedAttemptContext, GuestAdmissionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| GuestAdmissionError::Poisoned)?;
        if state.verified.is_none() {
            return Err(GuestAdmissionError::NotReady);
        }
        state
            .accepted
            .take()
            .ok_or(GuestAdmissionError::AlreadyConsumed)
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
