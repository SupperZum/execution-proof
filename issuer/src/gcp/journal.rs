use super::*;
use crate::gcp_operator::PublicError;
use execution_proof_contract::ValidityWindow;
use execution_proof_gcp_journal::{Entry, PublicationJournal};
use ring::signature::{UnparsedPublicKey, ED25519};

type Window = Option<(u64, u64)>;

pub(crate) struct Attempt {
    identity: Vec<u8>,
    intent: String,
    reservation: Vec<u8>,
}

impl Attempt {
    pub(crate) fn check(&self, journal: &dyn PublicationJournal) -> Result<(), PublicError> {
        self.require(
            journal,
            "reserve",
            self.intent.as_bytes(),
            &self.reservation,
            None,
        )
    }

    fn require(
        &self,
        journal: &dyn PublicationJournal,
        stage: &str,
        binding: &[u8],
        expected: &[u8],
        window: Window,
    ) -> Result<(), PublicError> {
        let saved = journal.read(stage, &self.identity, binding, window)?;
        if saved.as_deref() != Some(expected) {
            return Err(PublicError::StateRejected);
        }
        Ok(())
    }

    fn publish_exact(
        &self,
        journal: &dyn PublicationJournal,
        stage: &str,
        binding: &[u8],
        expected: &[u8],
        window: Window,
    ) -> Result<bool, PublicError> {
        let entry = journal.publish(stage, &self.identity, binding, expected, window)?;
        if entry.payload != expected {
            return Err(PublicError::StateRejected);
        }
        Ok(entry.first)
    }
}

pub(crate) struct Grant {
    attempt: Attempt,
    wire: Vec<u8>,
    validity: ValidityWindow,
}

impl Grant {
    fn window(&self) -> Window {
        Some((self.validity.not_before, self.validity.expires))
    }

    fn check(&self, journal: &dyn PublicationJournal) -> Result<(), PublicError> {
        self.attempt.check(journal)?;
        self.attempt.require(
            journal,
            "grant",
            &self.attempt.reservation,
            &self.wire,
            self.window(),
        )
    }
}

impl GcpIssuer {
    pub(crate) fn journal_attempt(&self, challenge_id: &str) -> Result<Attempt, PublicError> {
        let reservation = self
            .store
            .challenge(challenge_id)
            .map_err(GcpIssuerError::from)?;
        let c = &reservation.challenge;
        let identity =
            serde_json::to_vec(&[&c.authority, &c.tenant, &c.workload_id, &c.attempt_id])
                .map_err(|_| PublicError::Internal)?;
        let challenge = self.signed_challenge(&reservation)?;
        let wire = serde_json::to_vec(&(challenge, reservation.grant_id))
            .map_err(|_| PublicError::Internal)?;
        Ok(Attempt {
            identity,
            intent: reservation.intent_sha384,
            reservation: wire,
        })
    }

    pub(crate) fn journal_begin(
        &self,
        journal: &dyn PublicationJournal,
        challenge_id: &str,
    ) -> Result<(), PublicError> {
        let attempt = self.journal_attempt(challenge_id)?;
        attempt.publish_exact(
            journal,
            "reserve",
            attempt.intent.as_bytes(),
            &attempt.reservation,
            None,
        )?;
        Ok(())
    }

    pub(crate) fn journal_issue(
        &self,
        journal: &dyn PublicationJournal,
        challenge_id: &str,
        wire: &[u8],
    ) -> Result<bool, PublicError> {
        let reservation = self
            .store
            .challenge(challenge_id)
            .map_err(GcpIssuerError::from)?;
        let grant = self.journal_grant(&reservation.grant_id)?;
        if wire != grant.wire {
            return Err(PublicError::StateRejected);
        }
        grant.attempt.check(journal)?;
        // Qualification and L must both still cover the first external commit.
        if let Some(existing) = journal.read(
            "grant",
            &grant.attempt.identity,
            &grant.attempt.reservation,
            grant.window(),
        )? {
            if existing == wire {
                return Ok(false);
            }
            return Err(PublicError::StateRejected);
        }
        let window = self.journal_live_window(reservation.challenge.validity);
        grant
            .attempt
            .publish_exact(journal, "grant", &grant.attempt.reservation, wire, window)
    }

    fn journal_grant(&self, grant_id: &str) -> Result<Grant, PublicError> {
        let (issued, grant) = self.grant(grant_id)?;
        Ok(Grant {
            attempt: self.journal_attempt(&issued.reservation.challenge.challenge_id)?,
            wire: issued.signed_grant_json,
            validity: *grant.validity(),
        })
    }

    pub(crate) fn check_journal_grant(
        &self,
        journal: &dyn PublicationJournal,
        grant_id: &str,
    ) -> Result<(), PublicError> {
        self.journal_grant(grant_id)?.check(journal)
    }

    fn journal_pin_wire(&self, grant_id: &str) -> Result<Vec<u8>, PublicError> {
        let pin = self
            .store
            .policy_pin(grant_id)
            .map_err(GcpIssuerError::from)?;
        serde_json::to_vec(&(
            pin.grant_id,
            pin.expected_digest,
            pin.guest_nonce,
            pin.policy_digest,
        ))
        .map_err(|_| PublicError::Internal)
    }

    pub(crate) fn publish_journal_pin(
        &self,
        journal: &dyn PublicationJournal,
        grant_id: &str,
    ) -> Result<(), PublicError> {
        let grant = self.journal_grant(grant_id)?;
        grant.check(journal)?;
        let pin = self.journal_pin_wire(grant_id)?;
        if let Some(existing) =
            journal.read("pin", &grant.attempt.identity, &grant.wire, grant.window())?
        {
            if existing == pin {
                return Ok(());
            }
            return Err(PublicError::StateRejected);
        }
        grant.attempt.publish_exact(
            journal,
            "pin",
            &grant.wire,
            &pin,
            self.journal_live_window(grant.validity),
        )?;
        Ok(())
    }

    fn journal_live_window(&self, validity: ValidityWindow) -> Window {
        let q = self.qualification.validity();
        Some((
            q.not_before.max(validity.not_before),
            q.expires.min(validity.expires),
        ))
    }

    pub(crate) fn journal_admission(
        &self,
        journal: &dyn PublicationJournal,
        grant_id: &str,
        aggregate: &[u8],
        request: &[u8],
        operation: GcpAdmissionOperation,
    ) -> Result<Option<Entry>, PublicError> {
        if operation == GcpAdmissionOperation::Redeem {
            self.require_live_qualification()?;
        }
        let authorization =
            self.authenticate_policy_request(grant_id, aggregate, request, operation)?;
        let grant = self.journal_grant(grant_id)?;
        grant.check(journal)?;
        grant.attempt.require(
            journal,
            "pin",
            &grant.wire,
            &self.journal_pin_wire(grant_id)?,
            grant.window(),
        )?;

        let key = &grant.attempt.identity;
        let binding = authorization
            .signing_bytes()
            .map_err(GcpIssuerError::from)?;
        let entry = if let Some(payload) = journal.read("consume", key, &binding, grant.window())? {
            Entry {
                first: false,
                payload,
            }
        } else if operation == GcpAdmissionOperation::Status {
            return Ok(None);
        } else {
            let local = self.redeem_policy_aggregate(grant_id, aggregate, request)?;
            let window = self.journal_live_window(authorization.validity);
            journal.publish(
                "consume",
                key,
                &binding,
                &local.signed_authorization_json,
                window,
            )?
        };
        let signed: Signed<AdmissionAuthorizationV1> =
            serde_json::from_slice(&entry.payload).map_err(|_| PublicError::StateRejected)?;
        let signature =
            decode_hex(&signed.signature, 64).map_err(|_| PublicError::StateRejected)?;
        if signed.statement != authorization {
            return Err(PublicError::StateRejected);
        }
        UnparsedPublicKey::new(&ED25519, self.authority_public_key())
            .verify(&binding, &signature)
            .map_err(|_| PublicError::StateRejected)?;
        Ok(Some(entry))
    }
}
