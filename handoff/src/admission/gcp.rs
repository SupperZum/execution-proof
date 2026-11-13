//! Separate GCP aggregate verification and guest-owned one-use admission state.
//! Accepted context retains the generic unchanged admission semantics.
use super::*;
use execution_proof_contract::{
    admission::gcp::{verify_gcp_admission_authorization_historical, GcpAdmissionExpectations},
    gcp_policy_receipt::{
        verify_policy_aggregate, GcpAggregateExpectations, POLICY_AGGREGATE_PROFILE,
        POLICY_AGGREGATE_PURPOSE, POLICY_AGGREGATE_VERSION,
    },
};

pub struct GcpGuestAdmissionConfig {
    pub grant: GrantExpectations,
    pub expected_grant: LaunchGrant,
    pub aggregate: GcpAggregateExpectations,
    pub audience: String,
    pub issuer: String,
    pub admission_policy_sha384: String,
}

/// One instance per trusted boot/attempt. The owner must retain it for that
/// lifetime. State loss creates a fresh nonce, rejecting old receipts; it cannot
/// restore an old consumed grant or provide durable/clone-resistant protection.
pub struct GcpGuestAdmissionGate {
    pub(super) grant: GrantExpectations,
    pub(super) expected_grant_digest: String,
    pub(super) expected: GcpAdmissionExpectations,
    pub(super) state: Mutex<State>,
}

impl GcpGuestAdmissionGate {
    pub fn new(config: GcpGuestAdmissionConfig) -> Result<Self, GuestAdmissionError> {
        let expected_grant_digest = config
            .expected_grant
            .digest_sha384()
            .map_err(|_| GuestAdmissionError::InvalidConfiguration)?;
        let binding = &config.expected_grant.binding;
        let boot_binding = config
            .aggregate
            .boot_binding
            .digest_sha384()
            .map_err(|_| GuestAdmissionError::InvalidConfiguration)?;
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
            || binding.profile_sha384 != boot_binding
            || aggregate.boot_binding_sha384 != boot_binding
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
        if nonce == [0; 32] {
            return Err(GuestAdmissionError::EntropyUnavailable);
        }
        let expected = GcpAdmissionExpectations {
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
        let authorization = verify_gcp_admission_authorization_historical(
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

#[cfg(test)]
mod tests;
