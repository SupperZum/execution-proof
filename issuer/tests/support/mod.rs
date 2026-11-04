//! Software-only fixtures: all private keys stay in memory; the DB stores no private keys.
// Shared helpers are compiled independently by each integration-test binary.
#![allow(dead_code)]

use execution_proof_contract::bootstrap::{
    verify_bootstrap_challenge, verify_bootstrap_statements, BootstrapAppraisal, BootstrapBinding,
    BootstrapChallenge, BootstrapExpectations, RecorderPossession, TenantIntent,
    BOOTSTRAP_APPRAISAL_PURPOSE, BOOTSTRAP_VERSION, CHALLENGE_PURPOSE, POSSESSION_PURPOSE,
    TENANT_INTENT_PURPOSE, TENANT_INTENT_VERSION,
};
use execution_proof_contract::{
    verify_statements, AppraisalVerdict, EvaluationCommitments, KbsAssociation, LaunchBinding,
    LaunchGrant, ProofAppraisal, Signed, TrustedExpectations, ValidityWindow, VerifiedStatements,
    APPRAISAL_PURPOSE, VERSION,
};
use execution_proof_issuer::{
    ClockError, IssuerClock, IssuerConfig, RecorderRequest, SoftwareIssuer, REQUEST_VERSION,
};
use ring::digest::{digest, SHA256, SHA384};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

enum ClockState {
    Time(u64),
    Unavailable,
    OutOfRange,
}

pub struct ManualClock {
    state: Mutex<ClockState>,
    reads: AtomicUsize,
}

impl ManualClock {
    pub fn new(now: u64) -> Self {
        Self {
            state: Mutex::new(ClockState::Time(now)),
            reads: AtomicUsize::new(0),
        }
    }

    pub fn set(&self, now: u64) {
        *self.state.lock().unwrap() = ClockState::Time(now);
    }

    pub fn fail(&self, error: ClockError) {
        *self.state.lock().unwrap() = match error {
            ClockError::Unavailable => ClockState::Unavailable,
            ClockError::OutOfRange => ClockState::OutOfRange,
        };
    }

    /// Fixture observation only; production APIs never accept this value in a request.
    pub fn current(&self) -> u64 {
        match &*self.state.lock().unwrap() {
            ClockState::Time(now) => *now,
            _ => panic!("fixture clock unavailable"),
        }
    }

    pub fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

impl IssuerClock for ManualClock {
    fn now_unix_seconds(&self) -> Result<u64, ClockError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        match &*self.state.lock().unwrap() {
            ClockState::Time(now) => Ok(*now),
            ClockState::Unavailable => Err(ClockError::Unavailable),
            ClockState::OutOfRange => Err(ClockError::OutOfRange),
        }
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn hash(label: &str) -> String {
    hex(digest(&SHA384, label.as_bytes()).as_ref())
}

pub struct Key {
    pkcs8: Vec<u8>,
    pair: Ed25519KeyPair,
}

impl Key {
    pub fn new() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Self {
            pair: Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap(),
            pkcs8: pkcs8.as_ref().to_owned(),
        }
    }

    pub fn pair(&self) -> Ed25519KeyPair {
        Ed25519KeyPair::from_pkcs8(&self.pkcs8).unwrap()
    }

    pub fn public(&self) -> [u8; 32] {
        self.pair.public_key().as_ref().try_into().unwrap()
    }
}

pub fn signed<T: Clone + Serialize>(statement: &T, bytes: &[u8], key: &Key) -> Vec<u8> {
    serde_json::to_vec(&Signed {
        statement: statement.clone(),
        signature: hex(key.pair.sign(bytes).as_ref()),
    })
    .unwrap()
}

pub struct Fixture {
    pub tenant: Key,
    pub bootstrap: Key,
    pub recorder: Key,
    pub authority: Key,
    pub appraisal: Key,
    pub clock: Arc<ManualClock>,
    dir: PathBuf,
}

impl Fixture {
    pub fn new() -> Self {
        let mut random = [0; 16];
        SystemRandom::new().fill(&mut random).unwrap();
        let dir = std::env::temp_dir().join(format!("onb17-software-issuer-{}", hex(&random)));
        std::fs::create_dir(&dir).unwrap();
        Self {
            tenant: Key::new(),
            bootstrap: Key::new(),
            recorder: Key::new(),
            authority: Key::new(),
            appraisal: Key::new(),
            clock: Arc::new(ManualClock::new(1000)),
            dir,
        }
    }

    pub fn db(&self) -> PathBuf {
        self.dir.join("admission.sqlite3")
    }

    pub fn config(&self) -> IssuerConfig {
        IssuerConfig {
            authority: "software-authority".into(),
            tenant: "tenant-a".into(),
            audience: "software-runtime".into(),
            tenant_public_key: self.tenant.public(),
            bootstrap_verifier_public_key: self.bootstrap.public(),
            as_proof_public_key: self.appraisal.public(),
            bootstrap_verifier_issuer: "software-bootstrap-verifier".into(),
            as_issuer: "software-as-fixture".into(),
            profile_sha384: hash("software-only-proof-profile"),
            launch_policy_sha384: hash("software-launch-policy"),
            image_policy_sha384: hash("software-image-policy"),
            boot_profile_sha384: hash("software-only-boot-profile"),
            producer_profile_sha384: hash("software-only-producer-profile"),
            bootstrap_policy_sha384: hash("software-bootstrap-policy"),
            bootstrap_input_sha384: hash("software-bootstrap-input"),
            bootstrap_rvps_sha384: hash("software-bootstrap-reference-values"),
            appraisal_policy_id: "software-appraisal-policy".into(),
            appraisal_policy_sha384: hash("software-appraisal-policy"),
            appraisal_acceptance_policy_sha384: hash("software-appraisal-acceptance"),
            appraisal_rvps_sha384: hash("software-appraisal-reference-values"),
            kbs_policy_sha384: hash("software-kbs-policy"),
            authorization_ttl_secs: 30,
        }
    }

    pub fn create(&self, capacity: usize) -> SoftwareIssuer {
        SoftwareIssuer::initialize_new_with_clock(
            &self.db(),
            self.config(),
            self.authority.pair(),
            capacity,
            self.clock.clone(),
        )
        .unwrap()
    }

    pub fn reopen(&self, capacity: usize) -> SoftwareIssuer {
        SoftwareIssuer::open_existing_with_clock(
            &self.db(),
            self.config(),
            self.authority.pair(),
            capacity,
            self.clock.clone(),
        )
        .unwrap()
    }

    pub fn intent(&self, attempt: &str) -> TenantIntent {
        let config = self.config();
        TenantIntent {
            version: TENANT_INTENT_VERSION,
            purpose: TENANT_INTENT_PURPOSE.into(),
            audience: config.audience,
            authority: config.authority,
            tenant: config.tenant,
            workload_id: "software-workload".into(),
            container_role: "application-init".into(),
            attempt_id: attempt.into(),
            selected_manifest_sha256: hex(
                digest(&SHA256, b"software-encrypted-manifest-fixture").as_ref()
            ),
            effective_launch_sha384: hash("software-effective-launch"),
            profile_sha384: config.profile_sha384,
            launch_policy_sha384: config.launch_policy_sha384,
            image_policy_sha384: config.image_policy_sha384,
            validity: ValidityWindow {
                not_before: 900,
                expires: 2000,
            },
        }
    }

    pub fn enrollment(&self, issuer: &SoftwareIssuer, attempt: &str) -> Enrollment {
        let intent = self.intent(attempt);
        self.enrollment_with_intent(issuer, intent)
    }

    pub fn authenticate_challenge(
        &self,
        response: &Signed<BootstrapChallenge>,
        intent: &TenantIntent,
        validity: ValidityWindow,
    ) -> BootstrapChallenge {
        let config = self.config();
        let expected = BootstrapChallenge {
            version: BOOTSTRAP_VERSION,
            purpose: CHALLENGE_PURPOSE.into(),
            audience: config.audience.clone(),
            authority: config.authority.clone(),
            tenant: config.tenant.clone(),
            workload_id: intent.workload_id.clone(),
            attempt_id: intent.attempt_id.clone(),
            challenge_id: response.statement.challenge_id.clone(),
            nonce_hex: response.statement.nonce_hex.clone(),
            intent_sha384: intent.digest_sha384().unwrap(),
            boot_profile_sha384: config.boot_profile_sha384.clone(),
            producer_profile_sha384: config.producer_profile_sha384.clone(),
            validity,
        };
        verify_bootstrap_challenge(
            &serde_json::to_vec(response).unwrap(),
            &self.authority.public(),
            &expected,
            self.clock.current(),
        )
        .unwrap()
    }

    pub fn enrollment_with_intent(
        &self,
        issuer: &SoftwareIssuer,
        intent: TenantIntent,
    ) -> Enrollment {
        let intent_json = signed(&intent, &intent.signing_bytes().unwrap(), &self.tenant);
        let response = issuer.begin(&intent_json).unwrap();
        let config = self.config();
        let now = self.clock.current();
        let challenge_json = serde_json::to_vec(&response).unwrap();
        let challenge = self.authenticate_challenge(
            &response,
            &intent,
            ValidityWindow {
                not_before: now,
                expires: now
                    .checked_add(config.authorization_ttl_secs)
                    .unwrap()
                    .min(intent.validity.expires),
            },
        );
        let appraisal = BootstrapAppraisal {
            version: BOOTSTRAP_VERSION,
            purpose: BOOTSTRAP_APPRAISAL_PURPOSE.into(),
            audience: config.audience.clone(),
            issuer: config.bootstrap_verifier_issuer,
            verdict: AppraisalVerdict::Affirming,
            binding: BootstrapBinding {
                challenge_sha384: challenge.digest_sha384().unwrap(),
                boot_id: "software-fixture-boot".into(),
                boot_nonce_hex: hex(&[42; 32]),
                recorder_public_key_hex: hex(&self.recorder.public()),
            },
            boot_profile_sha384: config.boot_profile_sha384,
            producer_profile_sha384: config.producer_profile_sha384,
            evidence_sha384: hash("software-only-boot-evidence"),
            policy_sha384: config.bootstrap_policy_sha384,
            input_sha384: config.bootstrap_input_sha384,
            rvps_sha384: config.bootstrap_rvps_sha384,
        };
        let possession = RecorderPossession {
            version: BOOTSTRAP_VERSION,
            purpose: POSSESSION_PURPOSE.into(),
            audience: config.audience,
            challenge_sha384: challenge.digest_sha384().unwrap(),
            appraisal_sha384: appraisal.digest_sha384().unwrap(),
        };
        let appraisal_json = signed(
            &appraisal,
            &appraisal.signing_bytes().unwrap(),
            &self.bootstrap,
        );
        let possession_json = signed(
            &possession,
            &possession.signing_bytes().unwrap(),
            &self.recorder,
        );
        Enrollment {
            intent,
            challenge,
            challenge_json,
            appraisal,
            possession,
            appraisal_json,
            possession_json,
        }
    }

    pub fn statements(&self, enrollment: &Enrollment, grant_json: &[u8]) -> VerifiedStatements {
        self.statements_with_keys(enrollment, grant_json, &self.authority, &self.appraisal)
    }

    pub fn statements_with_keys(
        &self,
        enrollment: &Enrollment,
        grant_json: &[u8],
        authority: &Key,
        appraisal: &Key,
    ) -> VerifiedStatements {
        self.statements_with_issuer(
            enrollment,
            grant_json,
            authority,
            appraisal,
            &self.config().as_issuer,
        )
    }

    pub fn statements_claiming_as_issuer(
        &self,
        enrollment: &Enrollment,
        grant_json: &[u8],
        as_issuer: &str,
    ) -> VerifiedStatements {
        self.statements_with_issuer(
            enrollment,
            grant_json,
            &self.authority,
            &self.appraisal,
            as_issuer,
        )
    }

    fn statements_with_issuer(
        &self,
        enrollment: &Enrollment,
        grant_json: &[u8],
        authority: &Key,
        appraisal: &Key,
        as_issuer: &str,
    ) -> VerifiedStatements {
        let grant: Signed<LaunchGrant> = serde_json::from_slice(grant_json).unwrap();
        let mut config = self.config();
        config.as_issuer = as_issuer.into();
        let bootstrap = verify_bootstrap_statements(
            &enrollment.appraisal_json,
            &enrollment.possession_json,
            &BootstrapExpectations {
                challenge: enrollment.challenge.clone(),
                verifier_public_key: self.bootstrap.public(),
                verifier_issuer: config.bootstrap_verifier_issuer.clone(),
                policy_sha384: config.bootstrap_policy_sha384.clone(),
                input_sha384: config.bootstrap_input_sha384.clone(),
                rvps_sha384: config.bootstrap_rvps_sha384.clone(),
            },
        )
        .unwrap();
        let mut launch_challenge = b"QLAD-LAUNCH-CHALLENGE\0".to_vec();
        for value in [
            enrollment.challenge.nonce_hex.as_str(),
            grant.statement.grant_id.as_str(),
            enrollment.challenge.intent_sha384.as_str(),
        ] {
            launch_challenge.extend_from_slice(&(value.len() as u32).to_be_bytes());
            launch_challenge.extend_from_slice(value.as_bytes());
        }
        // Expected identity/content/policies originate in the signed intent and fixture config,
        // while bootstrap fields come from independently verified software boot statements.
        let intent = &enrollment.intent;
        let binding = LaunchBinding {
            authority: config.authority.clone(),
            tenant: config.tenant.clone(),
            workload_id: intent.workload_id.clone(),
            container_role: intent.container_role.clone(),
            attempt_id: intent.attempt_id.clone(),
            boot_id: bootstrap.boot_id().into(),
            channel_key_sha384: bootstrap.channel_key_sha384().into(),
            bootstrap_context_sha384: bootstrap.context_digest().into(),
            selected_manifest_sha256: intent.selected_manifest_sha256.clone(),
            effective_launch_sha384: intent.effective_launch_sha384.clone(),
            profile_sha384: config.profile_sha384.clone(),
            launch_policy_sha384: config.launch_policy_sha384.clone(),
            image_policy_sha384: config.image_policy_sha384.clone(),
            challenge_sha384: hex(digest(&SHA384, &launch_challenge).as_ref()),
        };
        assert_eq!(grant.statement.binding, binding);
        assert_eq!(grant.statement.validity, enrollment.challenge.validity);
        let evaluation = EvaluationCommitments {
            policy_id: config.appraisal_policy_id,
            policy_sha384: config.appraisal_policy_sha384,
            input_sha384: hash("software-appraisal-input"),
            rvps_sha384: config.appraisal_rvps_sha384,
            acceptance_policy_sha384: config.appraisal_acceptance_policy_sha384,
            kbs: KbsAssociation {
                decision_sha384: hash("software-kbs-decision-association-not-receipt"),
                policy_sha384: config.kbs_policy_sha384,
                input_sha384: hash("software-kbs-input"),
                session_sha384: hash(&format!(
                    "software-session:{}",
                    enrollment.intent.attempt_id
                )),
            },
        };
        let statement = ProofAppraisal {
            version: VERSION,
            purpose: APPRAISAL_PURPOSE.into(),
            audience: config.audience.clone(),
            issuer: config.as_issuer.clone(),
            verdict: AppraisalVerdict::Affirming,
            grant_sha384: grant.statement.digest_sha384().unwrap(),
            binding: binding.clone(),
            evaluation: evaluation.clone(),
        };
        // Preserve the actual issuer signature in the normal flow. Only the explicit
        // attacker-root test re-signs its identical payload under an untrusted root.
        let grant_json = if authority.public() == self.authority.public() {
            grant_json.to_vec()
        } else {
            signed(
                &grant.statement,
                &grant.statement.signing_bytes().unwrap(),
                authority,
            )
        };
        let appraisal_json = signed(&statement, &statement.signing_bytes().unwrap(), appraisal);
        verify_statements(
            &grant_json,
            &appraisal_json,
            &TrustedExpectations {
                authority_public_key: authority.public(),
                as_proof_public_key: appraisal.public(),
                audience: config.audience,
                as_issuer: config.as_issuer,
                grant_id: grant.statement.grant_id,
                binding,
                evaluation,
            },
        )
        .unwrap()
    }

    pub fn request(&self, statements: &VerifiedStatements, purpose: &str, key: &Key) -> Vec<u8> {
        let request = RecorderRequest {
            version: REQUEST_VERSION,
            purpose: purpose.into(),
            audience: self.config().audience,
            grant_sha384: statements.grant_digest().into(),
            context_sha384: statements.context_digest().into(),
        };
        signed(&request, &request.signing_bytes().unwrap(), key)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub struct Enrollment {
    pub intent: TenantIntent,
    pub challenge: BootstrapChallenge,
    pub challenge_json: Vec<u8>,
    pub appraisal: BootstrapAppraisal,
    pub possession: RecorderPossession,
    pub appraisal_json: Vec<u8>,
    pub possession_json: Vec<u8>,
}

impl Enrollment {
    pub fn issue(&self, issuer: &SoftwareIssuer) -> Vec<u8> {
        issuer
            .issue(
                &self.challenge.challenge_id,
                &self.appraisal_json,
                &self.possession_json,
            )
            .unwrap()
            .signed_grant_json
    }
}
