//! Durable software-lab admission bookkeeping, not rollback/clone protection.
//!
//! The trusted issuer owns this path and its parent directory. No request IDs
//! become paths; no private keys are stored. A missing store is never silently
//! reinitialized. Deleting/restoring/copying the database defeats this local
//! persistence boundary and is outside the supported profile.

use crate::{ClockError, IssuerClock};
use execution_proof_contract::{
    admission::{
        AdmissionAuthorizationV1, ADMISSION_PROFILE, ADMISSION_PURPOSE, ADMISSION_VERSION,
    },
    bootstrap::{BootstrapChallenge, TenantIntent, BOOTSTRAP_VERSION, CHALLENGE_PURPOSE},
    policy_receipt::LaunchPolicyAggregateV1,
    LaunchGrant, Signed, ValidityWindow, VerifiedStatements,
};
use ring::{
    digest,
    signature::{self, Ed25519KeyPair, KeyPair},
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{fmt, fs::OpenOptions, path::Path, sync::Mutex, time::Duration};

const MAX_CAPACITY: usize = 1024;
const MAX_WIRE: usize = 16 * 1024;
const APPLICATION_ID: i64 = 0x514c4150;
const SCHEMA_VERSION: i64 = 2;
const POLICY_SCHEMA_VERSION: i64 = 3;
const META_SCHEMA: &str = "CREATE TABLE store_meta (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 identity_sha384 TEXT NOT NULL CHECK(length(identity_sha384)=96),
 capacity INTEGER NOT NULL CHECK(capacity BETWEEN 1 AND 1024),
 last_seen_unix_seconds INTEGER NOT NULL CHECK(last_seen_unix_seconds>=0)
) STRICT";
const RECORD_SCHEMA: &str = "CREATE TABLE challenges (
 challenge_id TEXT PRIMARY KEY,
 authority TEXT NOT NULL,
 tenant TEXT NOT NULL,
 workload_id TEXT NOT NULL,
 attempt_id TEXT NOT NULL,
 challenge_json BLOB NOT NULL CHECK(length(challenge_json) BETWEEN 1 AND 16384),
 challenge_digest TEXT NOT NULL CHECK(length(challenge_digest)=96),
 grant_id TEXT NOT NULL UNIQUE,
 intent_json BLOB NOT NULL CHECK(length(intent_json) BETWEEN 1 AND 16384),
 intent_digest TEXT NOT NULL CHECK(length(intent_digest)=96),
 intent_wire_digest TEXT NOT NULL CHECK(length(intent_wire_digest)=96),
 bootstrap_context TEXT,
 recorder_key TEXT,
 grant_json BLOB,
 grant_digest TEXT,
 grant_wire_digest TEXT,
 redeemed_context TEXT,
 UNIQUE(authority,tenant,workload_id,attempt_id),
 CHECK((bootstrap_context IS NULL AND recorder_key IS NULL AND grant_json IS NULL
        AND grant_digest IS NULL AND grant_wire_digest IS NULL AND redeemed_context IS NULL)
    OR (bootstrap_context IS NOT NULL AND recorder_key IS NOT NULL AND grant_json IS NOT NULL
        AND grant_digest IS NOT NULL AND grant_wire_digest IS NOT NULL
        AND length(bootstrap_context)=96 AND length(recorder_key)=64
        AND length(grant_json) BETWEEN 1 AND 16384 AND length(grant_digest)=96
        AND length(grant_wire_digest)=96
        AND (redeemed_context IS NULL OR length(redeemed_context)=96)))
) STRICT";
const SELECT_RECORD: &str = "SELECT challenge_id,authority,tenant,workload_id,attempt_id,
 challenge_json,challenge_digest,grant_id,intent_json,intent_digest,intent_wire_digest,
 bootstrap_context,recorder_key,grant_json,grant_digest,grant_wire_digest,redeemed_context
 FROM challenges";
const POLICY_SCHEMA: &str = "CREATE TABLE policy_admissions (
 grant_id TEXT PRIMARY KEY REFERENCES challenges(grant_id),
 expected_json BLOB NOT NULL CHECK(length(expected_json) BETWEEN 1 AND 16384),
 expected_digest TEXT NOT NULL CHECK(length(expected_digest)=96),
 guest_nonce TEXT NOT NULL CHECK(length(guest_nonce) BETWEEN 1 AND 256),
 policy_digest TEXT NOT NULL CHECK(length(policy_digest)=96),
 receipt_json BLOB,
 receipt_wire_digest TEXT,
 CHECK((receipt_json IS NULL AND receipt_wire_digest IS NULL)
    OR (receipt_json IS NOT NULL AND length(receipt_json) BETWEEN 1 AND 16384
        AND receipt_wire_digest IS NOT NULL AND length(receipt_wire_digest)=96))
) STRICT";

#[derive(Clone, Copy)]
enum StoreProfile {
    Legacy,
    PolicyAdmission([u8; 32]),
    #[cfg(feature = "gcp")]
    GcpPolicyAdmission {
        authority: [u8; 32],
        qualification: ValidityWindow,
    },
}
impl StoreProfile {
    fn version(self) -> i64 {
        match self {
            Self::Legacy => SCHEMA_VERSION,
            Self::PolicyAdmission(_) => POLICY_SCHEMA_VERSION,
            #[cfg(feature = "gcp")]
            Self::GcpPolicyAdmission { .. } => 4,
        }
    }
    fn policy_authority(self) -> Option<[u8; 32]> {
        match self {
            Self::Legacy => None,
            Self::PolicyAdmission(key) => Some(key),
            #[cfg(feature = "gcp")]
            Self::GcpPolicyAdmission { authority, .. } => Some(authority),
        }
    }
}

#[derive(Clone)]
pub(crate) struct PolicyPin {
    pub(crate) grant_id: String,
    pub(crate) expected_json: Vec<u8>,
    pub(crate) expected_digest: String,
    pub(crate) guest_nonce: String,
    pub(crate) policy_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionPublicationKind {
    FirstAuthorized,
    Existing,
}

pub(crate) struct PolicyReceiptOutcome {
    pub(crate) bytes: Vec<u8>,
    pub(crate) publication: AdmissionPublicationKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChallengeRecord {
    pub(crate) challenge: BootstrapChallenge,
    pub(crate) grant_id: String,
    pub(crate) signed_intent_json: Vec<u8>,
    pub(crate) intent_sha384: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IssuedRecord {
    pub(crate) reservation: ChallengeRecord,
    pub(crate) bootstrap_context_digest: String,
    pub(crate) recorder_public_key_hex: String,
    pub(crate) signed_grant_json: Vec<u8>,
    pub(crate) grant_digest: String,
    pub(crate) redemption_context: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantPublication {
    FirstIssued,
    Existing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IssueOutcome {
    pub(crate) record: IssuedRecord,
    pub(crate) publication: GrantPublication,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Redemption {
    FirstRedeemed,
    AlreadyRedeemed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedemptionStatus {
    Issued,
    Redeemed,
}

#[derive(Debug)]
pub enum StoreError {
    InvalidInput,
    ClockUnavailable,
    ClockOutOfRange,
    ClockRegression,
    Expired,
    NotYetValid,
    NotFound,
    Conflict,
    CapacityExhausted,
    Busy,
    Corrupt,
    IdentityMismatch,
    AlreadyExists,
    Io(std::io::Error),
    Sql(rusqlite::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not echo SQL parameters, statements, or payloads in error messages.
        f.write_str(match self {
            Self::InvalidInput => "invalid store input",
            Self::ClockUnavailable => "issuer clock temporarily unavailable",
            Self::ClockOutOfRange => "issuer clock outside supported range",
            Self::ClockRegression => "issuer clock regressed",
            Self::Expired => "authorization expired",
            Self::NotYetValid => "authorization not yet valid",
            Self::NotFound => "store record not found",
            Self::Conflict => "store binding conflict",
            Self::CapacityExhausted => "store capacity exhausted",
            Self::Busy => "store temporarily busy",
            Self::Corrupt => "store integrity check failed",
            Self::IdentityMismatch => "store identity or capacity mismatch",
            Self::AlreadyExists => "store already exists",
            Self::Io(_) => "store I/O failure",
            Self::Sql(_) => "store database failure",
        })
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sql(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        match &error {
            rusqlite::Error::SqliteFailure(code, _) => match code.code {
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked => {
                    Self::Busy
                }
                rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase => {
                    Self::Corrupt
                }
                _ => Self::Sql(error),
            },
            _ => Self::Sql(error),
        }
    }
}

pub(crate) struct Store {
    connection: Mutex<Connection>,
    capacity: usize,
    profile: StoreProfile,
}

impl Store {
    pub(crate) fn initialize_new(
        path: &Path,
        store_identity_sha384: &str,
        capacity: usize,
        clock: &dyn IssuerClock,
    ) -> Result<Self, StoreError> {
        Self::initialize_profile(
            path,
            store_identity_sha384,
            capacity,
            clock,
            StoreProfile::Legacy,
        )
    }

    pub(crate) fn initialize_new_policy(
        path: &Path,
        identity: &str,
        capacity: usize,
        clock: &dyn IssuerClock,
        authority: [u8; 32],
    ) -> Result<Self, StoreError> {
        Self::initialize_profile(
            path,
            identity,
            capacity,
            clock,
            StoreProfile::PolicyAdmission(authority),
        )
    }

    #[cfg(feature = "gcp")]
    pub(crate) fn initialize_new_gcp_policy(
        path: &Path,
        identity: &str,
        capacity: usize,
        clock: &dyn IssuerClock,
        authority: [u8; 32],
        qualification: ValidityWindow,
    ) -> Result<Self, StoreError> {
        Self::initialize_profile(
            path,
            identity,
            capacity,
            clock,
            StoreProfile::GcpPolicyAdmission {
                authority,
                qualification,
            },
        )
    }
    #[cfg(feature = "gcp")]
    pub(crate) fn open_existing_gcp_policy(
        path: &Path,
        identity: &str,
        capacity: usize,
        authority: [u8; 32],
        qualification: ValidityWindow,
    ) -> Result<Self, StoreError> {
        Self::open_profile(
            path,
            identity,
            capacity,
            StoreProfile::GcpPolicyAdmission {
                authority,
                qualification,
            },
        )
    }

    fn initialize_profile(
        path: &Path,
        store_identity_sha384: &str,
        capacity: usize,
        clock: &dyn IssuerClock,
        profile: StoreProfile,
    ) -> Result<Self, StoreError> {
        validate_config(store_identity_sha384, capacity)?;
        // A retryable clock failure must not leave a partially initialized file.
        let initial_time = clock_now(clock)?;
        #[cfg(feature = "gcp")]
        if let StoreProfile::GcpPolicyAdmission { qualification, .. } = profile {
            check_window(qualification, initial_time)?;
        }
        let mut options = OpenOptions::new();
        options.write(true).read(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                StoreError::AlreadyExists
            } else {
                StoreError::Io(error)
            }
        })?;
        drop(file);
        let mut connection = open_connection(path)?;
        let mode: String = connection.query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0))?;
        if mode != "delete" {
            return Err(StoreError::Corrupt);
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(META_SCHEMA)?;
        transaction.execute_batch(RECORD_SCHEMA)?;
        if profile.policy_authority().is_some() {
            transaction.execute_batch(POLICY_SCHEMA)?;
        }
        transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
        transaction.pragma_update(None, "user_version", profile.version())?;
        transaction.execute(
            "INSERT INTO store_meta(singleton,identity_sha384,capacity,last_seen_unix_seconds) VALUES(1,?1,?2,?3)",
            params![store_identity_sha384, capacity as i64, initial_time as i64],
        )?;
        transaction.commit()?;
        // Persist the newly created directory entry before acknowledging init.
        #[cfg(unix)]
        std::fs::File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )
        .and_then(|parent| parent.sync_all())
        .map_err(StoreError::Io)?;
        Ok(Self {
            connection: Mutex::new(connection),
            capacity,
            profile,
        })
    }

    pub(crate) fn open_existing(
        path: &Path,
        expected_identity: &str,
        capacity: usize,
    ) -> Result<Self, StoreError> {
        Self::open_profile(path, expected_identity, capacity, StoreProfile::Legacy)
    }

    pub(crate) fn open_existing_policy(
        path: &Path,
        identity: &str,
        capacity: usize,
        authority: [u8; 32],
    ) -> Result<Self, StoreError> {
        Self::open_profile(
            path,
            identity,
            capacity,
            StoreProfile::PolicyAdmission(authority),
        )
    }

    fn open_profile(
        path: &Path,
        expected_identity: &str,
        capacity: usize,
        profile: StoreProfile,
    ) -> Result<Self, StoreError> {
        validate_config(expected_identity, capacity)?;
        // READ_WRITE without CREATE: missing state cannot become a fresh store.
        let connection = open_connection(path)?;
        validate_database(&connection, expected_identity, capacity, profile)?;
        Ok(Self {
            connection: Mutex::new(connection),
            capacity,
            profile,
        })
    }

    /// A repeated logical attempt returns its original nonce and grant ID.
    /// Candidate randomness is deliberately excluded from retry comparison.
    pub(crate) fn reserve(
        &self,
        candidate: &ChallengeRecord,
        clock: &dyn IssuerClock,
        ttl_seconds: u64,
    ) -> Result<ChallengeRecord, StoreError> {
        validate_challenge(candidate)?;
        if !(1..=3600).contains(&ttl_seconds) {
            return Err(StoreError::InvalidInput);
        }
        let mut connection = self.connection.lock().map_err(|_| StoreError::Corrupt)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let query = format!(
            "{SELECT_RECORD} WHERE authority=?1 AND tenant=?2 AND workload_id=?3 AND attempt_id=?4"
        );
        let found = transaction
            .query_row(
                &query,
                params![
                    candidate.challenge.authority,
                    candidate.challenge.tenant,
                    candidate.challenge.workload_id,
                    candidate.challenge.attempt_id
                ],
                RawRow::read,
            )
            .optional()?;
        if let Some(raw) = found {
            let (existing, _) = raw.decode()?;
            if !same_request(&existing, candidate) {
                return Err(StoreError::Conflict);
            }
            let now = observe_clock(&transaction, clock)?;
            if let Err(error) = check_record_window(&existing, now) {
                // Expected denial still persists the observed clock high-water.
                transaction.commit()?;
                return Err(error);
            }
            transaction.commit()?;
            return Ok(existing);
        }
        let collision: i64 = transaction.query_row(
            "SELECT count(*) FROM challenges WHERE challenge_id=?1 OR grant_id=?2",
            params![candidate.challenge.challenge_id, candidate.grant_id],
            |r| r.get(0),
        )?;
        if collision != 0 {
            return Err(StoreError::Conflict);
        }
        let count: i64 =
            transaction.query_row("SELECT count(*) FROM challenges", [], |r| r.get(0))?;
        if count >= self.capacity as i64 {
            return Err(StoreError::CapacityExhausted);
        }
        let now = observe_clock(&transaction, clock)?;
        let intent_window = intent_window(candidate)?;
        if let Err(error) = check_window(intent_window, now) {
            transaction.commit()?;
            return Err(error);
        }
        let expires = now
            .checked_add(ttl_seconds)
            .ok_or(StoreError::ClockOutOfRange)?
            .min(intent_window.expires);
        #[cfg(feature = "gcp")]
        let expires = if let StoreProfile::GcpPolicyAdmission { qualification, .. } = self.profile {
            if let Err(error) = check_window(qualification, now) {
                transaction.commit()?;
                return Err(error);
            }
            expires.min(qualification.expires)
        } else {
            expires
        };
        let mut actual = candidate.clone();
        actual.challenge.validity = ValidityWindow {
            not_before: now,
            expires,
        };
        let challenge_json =
            serde_json::to_vec(&actual.challenge).map_err(|_| StoreError::InvalidInput)?;
        transaction.execute("INSERT INTO challenges(challenge_id,authority,tenant,workload_id,attempt_id,challenge_json,challenge_digest,grant_id,intent_json,intent_digest,intent_wire_digest)
          VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)", params![actual.challenge.challenge_id,
            actual.challenge.authority,actual.challenge.tenant,actual.challenge.workload_id,actual.challenge.attempt_id,
            challenge_json,actual.challenge.digest_sha384().map_err(|_| StoreError::InvalidInput)?,actual.grant_id,
            actual.signed_intent_json,actual.intent_sha384,sha384(&actual.signed_intent_json)])?;
        transaction.commit()?;
        Ok(actual)
    }

    pub(crate) fn challenge(&self, challenge_id: &str) -> Result<ChallengeRecord, StoreError> {
        identifier(challenge_id)?;
        let connection = self.connection.lock().map_err(|_| StoreError::Corrupt)?;
        Ok(find_challenge(&connection, challenge_id)?.decode()?.0)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue(
        &self,
        challenge_id: &str,
        expected_challenge_digest: &str,
        bootstrap_context_digest: &str,
        recorder_public_key_hex: &str,
        signed_grant_json: &[u8],
        grant_digest: &str,
        clock: &dyn IssuerClock,
    ) -> Result<IssueOutcome, StoreError> {
        identifier(challenge_id)?;
        for value in [
            expected_challenge_digest,
            bootstrap_context_digest,
            grant_digest,
        ] {
            hex(value, 48)?;
        }
        hex(recorder_public_key_hex, 32)?;
        bounded_wire(signed_grant_json)?;
        let mut connection = self.connection.lock().map_err(|_| StoreError::Corrupt)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (reservation, existing) = find_challenge(&transaction, challenge_id)?.decode()?;
        if reservation
            .challenge
            .digest_sha384()
            .map_err(|_| StoreError::Corrupt)?
            != expected_challenge_digest
        {
            return Err(StoreError::Conflict);
        }
        let proposed = IssuedRecord {
            reservation,
            bootstrap_context_digest: bootstrap_context_digest.into(),
            recorder_public_key_hex: recorder_public_key_hex.into(),
            signed_grant_json: signed_grant_json.into(),
            grant_digest: grant_digest.into(),
            redemption_context: None,
        };
        validate_issued(&proposed).map_err(|_| StoreError::Conflict)?;
        if let Some(existing) = existing {
            if existing.bootstrap_context_digest != proposed.bootstrap_context_digest
                || existing.recorder_public_key_hex != proposed.recorder_public_key_hex
                || existing.signed_grant_json != proposed.signed_grant_json
                || existing.grant_digest != proposed.grant_digest
            {
                return Err(StoreError::Conflict);
            }
            transaction.commit()?;
            return Ok(IssueOutcome {
                record: existing,
                publication: GrantPublication::Existing,
            });
        }
        let now = observe_clock(&transaction, clock)?;
        if let Err(error) = check_record_window(&proposed.reservation, now) {
            transaction.commit()?;
            return Err(error);
        }
        let changed = transaction.execute("UPDATE challenges SET bootstrap_context=?1,recorder_key=?2,grant_json=?3,grant_digest=?4,grant_wire_digest=?5
            WHERE challenge_id=?6 AND bootstrap_context IS NULL",params![bootstrap_context_digest,recorder_public_key_hex,
                signed_grant_json,grant_digest,sha384(signed_grant_json),challenge_id])?;
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
        transaction.commit()?;
        Ok(IssueOutcome {
            record: proposed,
            publication: GrantPublication::FirstIssued,
        })
    }

    pub(crate) fn get_issued(&self, grant_id: &str) -> Result<IssuedRecord, StoreError> {
        identifier(grant_id)?;
        let connection = self.connection.lock().map_err(|_| StoreError::Corrupt)?;
        find_grant(&connection, grant_id)?
            .decode()?
            .1
            .ok_or(StoreError::NotFound)
    }

    /// Commits before replying. AlreadyRedeemed is status, not another permit.
    pub(crate) fn redeem(
        &self,
        statements: &VerifiedStatements,
        clock: &dyn IssuerClock,
    ) -> Result<Redemption, StoreError> {
        if !matches!(self.profile, StoreProfile::Legacy) {
            return Err(StoreError::InvalidInput);
        }
        let mut connection = self.connection.lock().map_err(|_| StoreError::Corrupt)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, issued) = find_grant(&transaction, statements.grant_id())?.decode()?;
        let issued = issued.ok_or(StoreError::NotFound)?;
        let stored: Signed<LaunchGrant> =
            serde_json::from_slice(&issued.signed_grant_json).map_err(|_| StoreError::Corrupt)?;
        if issued.grant_digest != statements.grant_digest()
            || stored.statement.binding != *statements.binding()
        {
            return Err(StoreError::Conflict);
        }
        let outcome = match &issued.redemption_context {
            Some(context) if context == statements.context_digest() => Redemption::AlreadyRedeemed,
            Some(_) => return Err(StoreError::Conflict),
            None => {
                let now = observe_clock(&transaction, clock)?;
                if let Err(error) = check_record_window(&issued.reservation, now) {
                    transaction.commit()?;
                    return Err(error);
                }
                let changed = transaction.execute("UPDATE challenges SET redeemed_context=?1 WHERE grant_id=?2 AND redeemed_context IS NULL",
                    params![statements.context_digest(),statements.grant_id()])?;
                if changed != 1 {
                    return Err(StoreError::Conflict);
                }
                Redemption::FirstRedeemed
            }
        };
        transaction.commit()?;
        Ok(outcome)
    }

    pub(crate) fn status(
        &self,
        grant_id: &str,
        context_digest: &str,
    ) -> Result<RedemptionStatus, StoreError> {
        if !matches!(self.profile, StoreProfile::Legacy) {
            return Err(StoreError::InvalidInput);
        }
        hex(context_digest, 48)?;
        let issued = self.get_issued(grant_id)?;
        match issued.redemption_context {
            None => Ok(RedemptionStatus::Issued),
            Some(context) if context == context_digest => Ok(RedemptionStatus::Redeemed),
            Some(_) => Err(StoreError::Conflict),
        }
    }

    /// Operator-owned immutable expectations. This never consumes a grant.
    pub(crate) fn pin_policy(&self, pin: &PolicyPin) -> Result<(), StoreError> {
        let authority = self.policy_authority()?;
        validate_pin_profile(pin, self.profile)?;
        let mut connection = self.connection.lock().map_err(|_| StoreError::Corrupt)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, issued) = find_grant(&transaction, &pin.grant_id)?.decode()?;
        let issued = issued.ok_or(StoreError::NotFound)?;
        validate_pin_issued_profile(pin, &issued, &authority, self.profile)?;
        match read_policy_pin_profile(&transaction, &pin.grant_id, self.profile) {
            Ok((existing, _)) => {
                if existing.expected_json != pin.expected_json
                    || existing.expected_digest != pin.expected_digest
                    || existing.guest_nonce != pin.guest_nonce
                    || existing.policy_digest != pin.policy_digest
                {
                    return Err(StoreError::Conflict);
                }
                transaction.commit()?;
                return Ok(());
            }
            Err(StoreError::NotFound) => {}
            Err(error) => return Err(error),
        }
        if issued.redemption_context.is_some() {
            return Err(StoreError::Conflict);
        }
        transaction.execute("INSERT INTO policy_admissions(grant_id,expected_json,expected_digest,guest_nonce,policy_digest) VALUES(?1,?2,?3,?4,?5)",
            params![pin.grant_id,pin.expected_json,pin.expected_digest,pin.guest_nonce,pin.policy_digest])?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn policy_pin(&self, grant_id: &str) -> Result<PolicyPin, StoreError> {
        self.policy_authority()?;
        identifier(grant_id)?;
        let connection = self.connection.lock().map_err(|_| StoreError::Corrupt)?;
        Ok(read_policy_pin_profile(&connection, grant_id, self.profile)?.0)
    }

    /// The authority signs only after acquiring the SQLite writer lock and
    /// observing the current window. Receipt bytes and the shared consume slot
    /// commit together, so response loss never requires another authorization.
    pub(crate) fn redeem_policy(
        &self,
        authorization: &AdmissionAuthorizationV1,
        signer: &Ed25519KeyPair,
        clock: &dyn IssuerClock,
    ) -> Result<PolicyReceiptOutcome, StoreError> {
        let authority = self.policy_authority()?;
        if signer.public_key().as_ref() != authority {
            return Err(StoreError::Conflict);
        }
        let mut connection = self.connection.lock().map_err(|_| StoreError::Corrupt)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, issued) = find_grant(&transaction, &authorization.grant_id)?.decode()?;
        let issued = issued.ok_or(StoreError::NotFound)?;
        let (pin, existing) =
            read_policy_pin_profile(&transaction, &authorization.grant_id, self.profile)?;
        validate_pin_issued_profile(&pin, &issued, &authority, self.profile)?;
        validate_authorization(authorization, &pin, &issued)?;
        if let Some(context) = &issued.redemption_context {
            if context != &authorization.context_sha384 {
                return Err(StoreError::Conflict);
            }
            let bytes = existing.ok_or(StoreError::Conflict)?;
            let receipt = decode_receipt(&bytes, &pin, &issued, &authority)?;
            if receipt != *authorization {
                return Err(StoreError::Conflict);
            }
            transaction.commit()?;
            return Ok(PolicyReceiptOutcome {
                bytes,
                publication: AdmissionPublicationKind::Existing,
            });
        }
        if existing.is_some() {
            return Err(StoreError::Corrupt);
        }
        let now = observe_clock(&transaction, clock)?;
        if let Err(error) = check_record_window(&issued.reservation, now) {
            transaction.commit()?;
            return Err(error);
        }
        let signing_bytes = authorization
            .signing_bytes()
            .map_err(|_| StoreError::InvalidInput)?;
        let bytes = serde_json::to_vec(&Signed {
            statement: authorization.clone(),
            signature: crate::hex(signer.sign(&signing_bytes).as_ref()),
        })
        .map_err(|_| StoreError::InvalidInput)?;
        bounded_wire(&bytes)?;
        let consumed = transaction.execute("UPDATE challenges SET redeemed_context=?1 WHERE grant_id=?2 AND redeemed_context IS NULL",params![authorization.context_sha384,authorization.grant_id])?;
        let saved = transaction.execute("UPDATE policy_admissions SET receipt_json=?1,receipt_wire_digest=?2 WHERE grant_id=?3 AND receipt_json IS NULL",params![bytes,sha384(&bytes),authorization.grant_id])?;
        if consumed != 1 || saved != 1 {
            return Err(StoreError::Conflict);
        }
        transaction.commit()?;
        Ok(PolicyReceiptOutcome {
            bytes,
            publication: AdmissionPublicationKind::FirstAuthorized,
        })
    }

    pub(crate) fn policy_status(
        &self,
        authorization: &AdmissionAuthorizationV1,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let authority = self.policy_authority()?;
        let mut connection = self.connection.lock().map_err(|_| StoreError::Corrupt)?;
        // Both rows describe one durable transition. Keep a read snapshot even
        // when another issuer connection commits redemption between the reads.
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let (_, issued) = find_grant(&transaction, &authorization.grant_id)?.decode()?;
        let issued = issued.ok_or(StoreError::NotFound)?;
        #[cfg(test)]
        tests::after_policy_status_first_read();
        let (pin, receipt) =
            read_policy_pin_profile(&transaction, &authorization.grant_id, self.profile)?;
        validate_pin_issued_profile(&pin, &issued, &authority, self.profile)?;
        validate_authorization(authorization, &pin, &issued)?;
        let receipt = match issued.redemption_context.as_deref() {
            None if receipt.is_none() => None,
            Some(context) if context == authorization.context_sha384 => {
                let bytes = receipt.ok_or(StoreError::Conflict)?;
                if decode_receipt(&bytes, &pin, &issued, &authority)? != *authorization {
                    return Err(StoreError::Conflict);
                }
                Some(bytes)
            }
            _ => return Err(StoreError::Conflict),
        };
        transaction.commit()?;
        Ok(receipt)
    }

    fn policy_authority(&self) -> Result<[u8; 32], StoreError> {
        self.profile
            .policy_authority()
            .ok_or(StoreError::InvalidInput)
    }
}

fn open_connection(path: &Path) -> Result<Connection, StoreError> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    connection.busy_timeout(Duration::from_millis(250))?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    Ok(connection)
}

fn clock_now(clock: &dyn IssuerClock) -> Result<u64, StoreError> {
    let now = clock.now_unix_seconds().map_err(|error| match error {
        ClockError::Unavailable => StoreError::ClockUnavailable,
        ClockError::OutOfRange => StoreError::ClockOutOfRange,
    })?;
    if now > i64::MAX as u64 {
        return Err(StoreError::ClockOutOfRange);
    }
    Ok(now)
}

/// Called only after BEGIN IMMEDIATE, including after any SQLite writer queue.
/// Expected validity denials must commit this metadata-only update.
fn observe_clock(connection: &Connection, clock: &dyn IssuerClock) -> Result<u64, StoreError> {
    let now = clock_now(clock)?;
    let previous: i64 = connection.query_row(
        "SELECT last_seen_unix_seconds FROM store_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if previous < 0 {
        return Err(StoreError::Corrupt);
    }
    if now < previous as u64 {
        return Err(StoreError::ClockRegression);
    }
    let changed = connection.execute(
        "UPDATE store_meta SET last_seen_unix_seconds=?1 WHERE singleton=1",
        [now as i64],
    )?;
    if changed != 1 {
        return Err(StoreError::Corrupt);
    }
    Ok(now)
}

fn intent_window(record: &ChallengeRecord) -> Result<ValidityWindow, StoreError> {
    let signed: Signed<TenantIntent> =
        serde_json::from_slice(&record.signed_intent_json).map_err(|_| StoreError::Corrupt)?;
    Ok(signed.statement.validity)
}

fn check_window(window: ValidityWindow, now: u64) -> Result<(), StoreError> {
    if now < window.not_before {
        Err(StoreError::NotYetValid)
    } else if now >= window.expires {
        Err(StoreError::Expired)
    } else {
        Ok(())
    }
}

fn check_record_window(record: &ChallengeRecord, now: u64) -> Result<(), StoreError> {
    check_window(intent_window(record)?, now)?;
    check_window(record.challenge.validity, now)
}

fn validate_database(
    connection: &Connection,
    identity: &str,
    capacity: usize,
    profile: StoreProfile,
) -> Result<(), StoreError> {
    let app_id: i64 = connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let mode: String = connection.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
    let check: String = connection.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
    if app_id != APPLICATION_ID || version != profile.version() || mode != "delete" || check != "ok"
    {
        return Err(StoreError::Corrupt);
    }
    let mut schema = connection.prepare(
        "SELECT name,sql FROM sqlite_schema WHERE type IN ('table','view','trigger') ORDER BY name",
    )?;
    let definitions: Vec<(String, String)> = schema
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let mut expected_schema = vec![("challenges".into(), RECORD_SCHEMA.into())];
    if profile.policy_authority().is_some() {
        expected_schema.push(("policy_admissions".into(), POLICY_SCHEMA.into()));
    }
    expected_schema.push(("store_meta".into(), META_SCHEMA.into()));
    if definitions != expected_schema {
        return Err(StoreError::Corrupt);
    }
    let (stored_identity, stored_capacity, last_seen): (String, i64, i64) = connection.query_row(
        "SELECT identity_sha384,capacity,last_seen_unix_seconds FROM store_meta WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    if last_seen < 0 {
        return Err(StoreError::Corrupt);
    }
    if stored_identity != identity || stored_capacity != capacity as i64 {
        return Err(StoreError::IdentityMismatch);
    }
    let count: i64 = connection.query_row("SELECT count(*) FROM challenges", [], |r| r.get(0))?;
    if count > capacity as i64 {
        return Err(StoreError::Corrupt);
    }
    let mut records = connection.prepare(SELECT_RECORD)?;
    let rows = records.query_map([], RawRow::read)?;
    for row in rows {
        row?.decode()?;
    }
    if let Some(authority) = profile.policy_authority() {
        let foreign_error: Option<i64> = connection
            .query_row(
                "SELECT rowid FROM pragma_foreign_key_check LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if foreign_error.is_some() {
            return Err(StoreError::Corrupt);
        }
        let mut query = connection.prepare("SELECT grant_id FROM policy_admissions")?;
        let ids = query
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        for id in ids {
            let (pin, receipt) = read_policy_pin_profile(connection, &id, profile)?;
            let (_, issued) = find_grant(connection, &id)?.decode()?;
            let issued = issued.ok_or(StoreError::Corrupt)?;
            validate_pin_issued_profile(&pin, &issued, &authority, profile)
                .map_err(|_| StoreError::Corrupt)?;
            if let Some(bytes) = receipt {
                let statement = decode_receipt(&bytes, &pin, &issued, &authority)?;
                if issued.redemption_context.as_deref() != Some(&statement.context_sha384) {
                    return Err(StoreError::Corrupt);
                }
            }
        }
    }
    Ok(())
}

fn validate_pin_profile(pin: &PolicyPin, profile: StoreProfile) -> Result<(), StoreError> {
    #[cfg(feature = "gcp")]
    if matches!(profile, StoreProfile::GcpPolicyAdmission { .. }) {
        return validate_gcp_pin(pin).map(|_| ());
    }
    let _ = profile;
    validate_pin(pin).map(|_| ())
}
fn validate_pin_issued_profile(
    pin: &PolicyPin,
    issued: &IssuedRecord,
    authority: &[u8; 32],
    profile: StoreProfile,
) -> Result<(), StoreError> {
    #[cfg(feature = "gcp")]
    if matches!(profile, StoreProfile::GcpPolicyAdmission { .. }) {
        let expected = validate_gcp_pin(pin)?;
        let grant: Signed<LaunchGrant> =
            serde_json::from_slice(&issued.signed_grant_json).map_err(|_| StoreError::Corrupt)?;
        if pin.grant_id != issued.reservation.grant_id
            || expected.grant_sha384 != issued.grant_digest
            || expected.authority_key_sha384 != sha384(authority)
            || expected.recorder_key_sha384
                != sha384(
                    &crate::decode_hex(&issued.recorder_public_key_hex, 32)
                        .map_err(|_| StoreError::Corrupt)?,
                )
            || expected.boot_binding_sha384 != grant.statement.binding.profile_sha384
        {
            return Err(StoreError::Conflict);
        }
        return Ok(());
    }
    let _ = profile;
    validate_pin_issued(pin, issued, authority)
}
fn read_policy_pin_profile(
    connection: &Connection,
    grant_id: &str,
    profile: StoreProfile,
) -> Result<(PolicyPin, Option<Vec<u8>>), StoreError> {
    #[cfg(feature = "gcp")]
    if matches!(profile, StoreProfile::GcpPolicyAdmission { .. }) {
        return read_gcp_policy_pin(connection, grant_id);
    }
    let _ = profile;
    read_policy_pin(connection, grant_id)
}
#[cfg(feature = "gcp")]
fn validate_gcp_pin(
    pin: &PolicyPin,
) -> Result<execution_proof_contract::gcp_policy_receipt::GcpLaunchPolicyAggregateV2, StoreError> {
    identifier(&pin.grant_id)?;
    bounded_wire(&pin.expected_json)?;
    hex(&pin.expected_digest, 48)?;
    hex(&pin.policy_digest, 48)?;
    if pin.guest_nonce.is_empty() || pin.guest_nonce.len() > 256 || !pin.guest_nonce.is_ascii() {
        return Err(StoreError::InvalidInput);
    }
    let expected: execution_proof_contract::gcp_policy_receipt::GcpLaunchPolicyAggregateV2 =
        serde_json::from_slice(&pin.expected_json).map_err(|_| StoreError::InvalidInput)?;
    if expected
        .digest_sha384()
        .map_err(|_| StoreError::InvalidInput)?
        != pin.expected_digest
    {
        return Err(StoreError::Conflict);
    }
    Ok(expected)
}
#[cfg(feature = "gcp")]
fn read_gcp_policy_pin(
    connection: &Connection,
    grant_id: &str,
) -> Result<(PolicyPin, Option<Vec<u8>>), StoreError> {
    let (pin,receipt,wire_digest)=connection.query_row(
        "SELECT expected_json,expected_digest,guest_nonce,policy_digest,receipt_json,receipt_wire_digest FROM policy_admissions WHERE grant_id=?1",[grant_id],|row|Ok((
            PolicyPin{grant_id:grant_id.to_owned(),expected_json:row.get(0)?,expected_digest:row.get(1)?,guest_nonce:row.get(2)?,policy_digest:row.get(3)?},row.get::<_,Option<Vec<u8>>>(4)?,row.get::<_,Option<String>>(5)?
        ))).optional()?.ok_or(StoreError::NotFound)?;
    validate_gcp_pin(&pin).map_err(|_| StoreError::Corrupt)?;
    match (&receipt, wire_digest) {
        (None, None) => {}
        (Some(bytes), Some(hash))
            if !bytes.is_empty() && bytes.len() <= MAX_WIRE && sha384(bytes) == hash => {}
        _ => return Err(StoreError::Corrupt),
    }
    Ok((pin, receipt))
}

fn validate_pin(pin: &PolicyPin) -> Result<LaunchPolicyAggregateV1, StoreError> {
    identifier(&pin.grant_id)?;
    bounded_wire(&pin.expected_json)?;
    hex(&pin.expected_digest, 48)?;
    hex(&pin.policy_digest, 48)?;
    if pin.guest_nonce.is_empty() || pin.guest_nonce.len() > 256 || !pin.guest_nonce.is_ascii() {
        return Err(StoreError::InvalidInput);
    }
    let expected: LaunchPolicyAggregateV1 =
        serde_json::from_slice(&pin.expected_json).map_err(|_| StoreError::InvalidInput)?;
    if expected
        .digest_sha384()
        .map_err(|_| StoreError::InvalidInput)?
        != pin.expected_digest
    {
        return Err(StoreError::Conflict);
    }
    Ok(expected)
}

fn validate_pin_issued(
    pin: &PolicyPin,
    issued: &IssuedRecord,
    authority: &[u8; 32],
) -> Result<(), StoreError> {
    let expected = validate_pin(pin)?;
    if pin.grant_id != issued.reservation.grant_id
        || expected.grant_sha384 != issued.grant_digest
        || expected.authority_key_sha384 != sha384(authority)
        || expected.recorder_key_sha384
            != sha384(
                &crate::decode_hex(&issued.recorder_public_key_hex, 32)
                    .map_err(|_| StoreError::Corrupt)?,
            )
    {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

fn read_policy_pin(
    connection: &Connection,
    grant_id: &str,
) -> Result<(PolicyPin, Option<Vec<u8>>), StoreError> {
    let (pin,receipt,wire_digest)=connection.query_row(
        "SELECT expected_json,expected_digest,guest_nonce,policy_digest,receipt_json,receipt_wire_digest FROM policy_admissions WHERE grant_id=?1",[grant_id],|row|Ok((
            PolicyPin{grant_id:grant_id.to_owned(),expected_json:row.get(0)?,expected_digest:row.get(1)?,guest_nonce:row.get(2)?,policy_digest:row.get(3)?},
            row.get::<_,Option<Vec<u8>>>(4)?,row.get::<_,Option<String>>(5)?
        ))).optional()?.ok_or(StoreError::NotFound)?;
    validate_pin(&pin).map_err(|_| StoreError::Corrupt)?;
    match (&receipt, wire_digest) {
        (None, None) => {}
        (Some(bytes), Some(hash))
            if !bytes.is_empty() && bytes.len() <= MAX_WIRE && sha384(bytes) == hash => {}
        _ => return Err(StoreError::Corrupt),
    }
    Ok((pin, receipt))
}

fn validate_authorization(
    authorization: &AdmissionAuthorizationV1,
    pin: &PolicyPin,
    issued: &IssuedRecord,
) -> Result<(), StoreError> {
    authorization
        .signing_bytes()
        .map_err(|_| StoreError::InvalidInput)?;
    let stored: Signed<LaunchGrant> =
        serde_json::from_slice(&issued.signed_grant_json).map_err(|_| StoreError::Corrupt)?;
    if authorization.version != ADMISSION_VERSION
        || authorization.purpose != ADMISSION_PURPOSE
        || authorization.profile != ADMISSION_PROFILE
        || authorization.grant_id != pin.grant_id
        || authorization.grant_sha384 != issued.grant_digest
        || authorization.aggregate_sha384 != pin.expected_digest
        || authorization.guest_nonce != pin.guest_nonce
        || authorization.admission_policy_sha384 != pin.policy_digest
        || authorization.binding != stored.statement.binding
        || authorization.validity != stored.statement.validity
    {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

fn decode_receipt(
    bytes: &[u8],
    pin: &PolicyPin,
    issued: &IssuedRecord,
    authority: &[u8; 32],
) -> Result<AdmissionAuthorizationV1, StoreError> {
    bounded_wire(bytes).map_err(|_| StoreError::Corrupt)?;
    let signed: Signed<AdmissionAuthorizationV1> =
        serde_json::from_slice(bytes).map_err(|_| StoreError::Corrupt)?;
    validate_authorization(&signed.statement, pin, issued).map_err(|_| StoreError::Corrupt)?;
    signature::UnparsedPublicKey::new(&signature::ED25519, authority)
        .verify(
            &signed
                .statement
                .signing_bytes()
                .map_err(|_| StoreError::Corrupt)?,
            &crate::decode_hex(&signed.signature, 64).map_err(|_| StoreError::Corrupt)?,
        )
        .map_err(|_| StoreError::Corrupt)?;
    Ok(signed.statement)
}

struct RawRow {
    id: String,
    authority: String,
    tenant: String,
    workload: String,
    attempt: String,
    challenge_json: Vec<u8>,
    challenge_digest: String,
    grant_id: String,
    intent_json: Vec<u8>,
    intent_digest: String,
    intent_wire_digest: String,
    bootstrap_context: Option<String>,
    recorder_key: Option<String>,
    grant_json: Option<Vec<u8>>,
    grant_digest: Option<String>,
    grant_wire_digest: Option<String>,
    redeemed_context: Option<String>,
}

impl RawRow {
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            authority: row.get(1)?,
            tenant: row.get(2)?,
            workload: row.get(3)?,
            attempt: row.get(4)?,
            challenge_json: row.get(5)?,
            challenge_digest: row.get(6)?,
            grant_id: row.get(7)?,
            intent_json: row.get(8)?,
            intent_digest: row.get(9)?,
            intent_wire_digest: row.get(10)?,
            bootstrap_context: row.get(11)?,
            recorder_key: row.get(12)?,
            grant_json: row.get(13)?,
            grant_digest: row.get(14)?,
            grant_wire_digest: row.get(15)?,
            redeemed_context: row.get(16)?,
        })
    }
    fn decode(self) -> Result<(ChallengeRecord, Option<IssuedRecord>), StoreError> {
        bounded_wire(&self.challenge_json).map_err(|_| StoreError::Corrupt)?;
        let challenge: BootstrapChallenge =
            serde_json::from_slice(&self.challenge_json).map_err(|_| StoreError::Corrupt)?;
        if challenge.challenge_id != self.id
            || challenge.authority != self.authority
            || challenge.tenant != self.tenant
            || challenge.workload_id != self.workload
            || challenge.attempt_id != self.attempt
            || challenge.digest_sha384().map_err(|_| StoreError::Corrupt)? != self.challenge_digest
            || sha384(&self.intent_json) != self.intent_wire_digest
        {
            return Err(StoreError::Corrupt);
        }
        let reservation = ChallengeRecord {
            challenge,
            grant_id: self.grant_id,
            signed_intent_json: self.intent_json,
            intent_sha384: self.intent_digest,
        };
        validate_challenge(&reservation).map_err(|_| StoreError::Corrupt)?;
        match (
            self.bootstrap_context,
            self.recorder_key,
            self.grant_json,
            self.grant_digest,
            self.grant_wire_digest,
        ) {
            (None, None, None, None, None) if self.redeemed_context.is_none() => {
                Ok((reservation, None))
            }
            (Some(context), Some(key), Some(wire), Some(grant_digest), Some(wire_digest)) => {
                if sha384(&wire) != wire_digest {
                    return Err(StoreError::Corrupt);
                }
                let issued = IssuedRecord {
                    reservation: reservation.clone(),
                    bootstrap_context_digest: context,
                    recorder_public_key_hex: key,
                    signed_grant_json: wire,
                    grant_digest,
                    redemption_context: self.redeemed_context,
                };
                validate_issued(&issued).map_err(|_| StoreError::Corrupt)?;
                Ok((reservation, Some(issued)))
            }
            _ => Err(StoreError::Corrupt),
        }
    }
}

fn find_challenge(connection: &Connection, id: &str) -> Result<RawRow, StoreError> {
    let sql = format!("{SELECT_RECORD} WHERE challenge_id=?1");
    connection
        .query_row(&sql, [id], RawRow::read)
        .optional()?
        .ok_or(StoreError::NotFound)
}
fn find_grant(connection: &Connection, id: &str) -> Result<RawRow, StoreError> {
    let sql = format!("{SELECT_RECORD} WHERE grant_id=?1");
    connection
        .query_row(&sql, [id], RawRow::read)
        .optional()?
        .ok_or(StoreError::NotFound)
}
fn validate_config(identity: &str, capacity: usize) -> Result<(), StoreError> {
    hex(identity, 48)?;
    if capacity == 0 || capacity > MAX_CAPACITY {
        return Err(StoreError::InvalidInput);
    }
    Ok(())
}
fn validate_challenge(record: &ChallengeRecord) -> Result<(), StoreError> {
    record
        .challenge
        .signing_bytes()
        .map_err(|_| StoreError::InvalidInput)?;
    if record.challenge.version != BOOTSTRAP_VERSION
        || record.challenge.purpose != CHALLENGE_PURPOSE
        || record.challenge.intent_sha384 != record.intent_sha384
    {
        return Err(StoreError::InvalidInput);
    }
    identifier(&record.grant_id)?;
    hex(&record.intent_sha384, 48)?;
    bounded_wire(&record.signed_intent_json)?;
    let intent: Signed<TenantIntent> =
        serde_json::from_slice(&record.signed_intent_json).map_err(|_| StoreError::InvalidInput)?;
    hex(&intent.signature, 64)?;
    let i = &intent.statement;
    let c = &record.challenge;
    if i.digest_sha384().map_err(|_| StoreError::InvalidInput)? != record.intent_sha384
        || i.authority != c.authority
        || i.tenant != c.tenant
        || i.workload_id != c.workload_id
        || i.attempt_id != c.attempt_id
        || c.validity.not_before < i.validity.not_before
        || c.validity.expires > i.validity.expires
    {
        return Err(StoreError::InvalidInput);
    }
    Ok(())
}
fn same_request(a: &ChallengeRecord, b: &ChallengeRecord) -> bool {
    let (a_c, b_c) = (&a.challenge, &b.challenge);
    a.intent_sha384 == b.intent_sha384
        && a_c.version == b_c.version
        && a_c.purpose == b_c.purpose
        && a_c.audience == b_c.audience
        && a_c.authority == b_c.authority
        && a_c.tenant == b_c.tenant
        && a_c.workload_id == b_c.workload_id
        && a_c.attempt_id == b_c.attempt_id
        && a_c.boot_profile_sha384 == b_c.boot_profile_sha384
        && a_c.producer_profile_sha384 == b_c.producer_profile_sha384
}
fn validate_issued(record: &IssuedRecord) -> Result<(), StoreError> {
    hex(&record.bootstrap_context_digest, 48)?;
    hex(&record.recorder_public_key_hex, 32)?;
    bounded_wire(&record.signed_grant_json)?;
    hex(&record.grant_digest, 48)?;
    if let Some(context) = &record.redemption_context {
        hex(context, 48)?;
    }
    let signed: Signed<LaunchGrant> =
        serde_json::from_slice(&record.signed_grant_json).map_err(|_| StoreError::InvalidInput)?;
    // Signature authentication belongs to the trusted issuer/contract gate. Here
    // we verify persisted public bytes and their exact reservation association.
    hex(&signed.signature, 64)?;
    let l = &signed.statement;
    let c = &record.reservation.challenge;
    if l.version != execution_proof_contract::VERSION
        || l.purpose != execution_proof_contract::GRANT_PURPOSE
        || !l.proof_required
        || l.binding.container_role != "application-init"
        || l.digest_sha384().map_err(|_| StoreError::InvalidInput)? != record.grant_digest
        || l.grant_id != record.reservation.grant_id
        || l.binding.authority != c.authority
        || l.binding.tenant != c.tenant
        || l.binding.workload_id != c.workload_id
        || l.binding.attempt_id != c.attempt_id
        || l.binding.bootstrap_context_sha384 != record.bootstrap_context_digest
        || l.validity != c.validity
    {
        return Err(StoreError::Conflict);
    }
    Ok(())
}
fn bounded_wire(bytes: &[u8]) -> Result<(), StoreError> {
    if bytes.is_empty() || bytes.len() > MAX_WIRE {
        Err(StoreError::InvalidInput)
    } else {
        Ok(())
    }
}
fn identifier(value: &str) -> Result<(), StoreError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    {
        Err(StoreError::InvalidInput)
    } else {
        Ok(())
    }
}
fn hex(value: &str, bytes: usize) -> Result<(), StoreError> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Err(StoreError::InvalidInput)
    } else {
        Ok(())
    }
}
fn sha384(value: &[u8]) -> String {
    digest::digest(&digest::SHA384, value)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests;
