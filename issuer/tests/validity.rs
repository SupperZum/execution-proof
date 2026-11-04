//! Trusted issuer-clock tests. Fixture timestamps are never request parameters.

mod support;

use execution_proof_contract::bootstrap::{
    verify_bootstrap_challenge, BootstrapChallenge, TenantIntent,
};
use execution_proof_contract::{LaunchGrant, Signed, ValidityWindow};
use execution_proof_issuer::{
    ClockError, Error, GrantPublication, Redemption, RedemptionStatus, SoftwareIssuer, StoreError,
    REDEEM_PURPOSE, STATUS_PURPOSE,
};
use std::sync::Arc;
use support::{signed, Fixture, Key, ManualClock};

fn intent_wire(fixture: &Fixture, intent: &TenantIntent) -> Vec<u8> {
    signed(intent, &intent.signing_bytes().unwrap(), &fixture.tenant)
}

#[test]
fn intent_window_accepts_exact_not_before_and_excludes_exact_expiry() {
    for now in [999, 1000, 1999, 2000] {
        let fixture = Fixture::new();
        fixture.clock.set(now);
        let issuer = fixture.create(1);
        let mut intent = fixture.intent("window-edge");
        intent.validity = ValidityWindow {
            not_before: 1000,
            expires: 2000,
        };
        let result = issuer.begin(&intent_wire(&fixture, &intent));
        if now == 999 {
            assert!(matches!(result, Err(Error::Store(StoreError::NotYetValid))));
            fixture.clock.set(1000);
            fixture.enrollment(&issuer, "rightful-attempt");
        } else if now == 2000 {
            assert!(matches!(result, Err(Error::Store(StoreError::Expired))));
        } else {
            let challenge = fixture.authenticate_challenge(
                &result.unwrap(),
                &intent,
                ValidityWindow {
                    not_before: now,
                    expires: (now + 30).min(2000),
                },
            );
            assert_eq!(challenge.validity.not_before, now);
        }
    }
}

#[test]
fn grant_copies_challenge_window_without_refresh_and_first_redeem_is_half_open() {
    for now in [1000, 1029, 1030] {
        let fixture = Fixture::new();
        let issuer = fixture.create(1);
        let enrollment = fixture.enrollment(&issuer, "attempt-one");
        let grant = enrollment.issue(&issuer);
        let statements = fixture.statements(&enrollment, &grant);
        assert_eq!(
            statements.validity(),
            &ValidityWindow {
                not_before: 1000,
                expires: 1030
            }
        );
        fixture.clock.set(now);
        let request = fixture.request(&statements, REDEEM_PURPOSE, &fixture.recorder);
        let result = issuer.redeem(&statements, &request);
        if now == 1030 {
            assert!(matches!(result, Err(Error::Store(StoreError::Expired))));
        } else {
            assert_eq!(result.unwrap(), Redemption::FirstRedeemed);
        }
    }

    let fixture = Fixture::new();
    let issuer = fixture.create(1);
    let mut intent = fixture.intent("short-intent");
    intent.validity.expires = 1010;
    let enrollment = fixture.enrollment_with_intent(&issuer, intent);
    assert_eq!(enrollment.challenge.validity.expires, 1010);
    fixture.clock.set(1009);
    let issued = issuer
        .issue(
            &enrollment.challenge.challenge_id,
            &enrollment.appraisal_json,
            &enrollment.possession_json,
        )
        .unwrap();
    assert_eq!(issued.publication, GrantPublication::FirstIssued);
    let grant: Signed<LaunchGrant> = serde_json::from_slice(&issued.signed_grant_json).unwrap();
    assert_eq!(grant.statement.validity, enrollment.challenge.validity);
    fixture.statements(&enrollment, &issued.signed_grant_json);
}

#[test]
fn configured_ttl_limits_and_unrepresentable_clock_fail_before_new_authorization() {
    for ttl in [0, 3601, u64::MAX] {
        let fixture = Fixture::new();
        let mut config = fixture.config();
        config.authorization_ttl_secs = ttl;
        assert!(SoftwareIssuer::initialize_new_with_clock(
            &fixture.db(),
            config,
            fixture.authority.pair(),
            1,
            fixture.clock.clone()
        )
        .is_err());
        assert!(!fixture.db().exists());
    }
    let fixture = Fixture::new();
    let mut config = fixture.config();
    config.authorization_ttl_secs = 3600;
    let issuer = SoftwareIssuer::initialize_new_with_clock(
        &fixture.db(),
        config,
        fixture.authority.pair(),
        1,
        fixture.clock.clone(),
    )
    .unwrap();
    let mut intent = fixture.intent("max-ttl");
    intent.validity.expires = 5000;
    let response = issuer.begin(&intent_wire(&fixture, &intent)).unwrap();
    fixture.authenticate_challenge(
        &response,
        &intent,
        ValidityWindow {
            not_before: 1000,
            expires: 4600,
        },
    );

    let fixture = Fixture::new();
    let issuer = fixture.create(1);
    fixture.clock.set(u64::MAX);
    let intent = fixture.intent("out-of-range");
    assert!(matches!(
        issuer.begin(&intent_wire(&fixture, &intent)),
        Err(Error::Store(StoreError::ClockOutOfRange))
    ));
    fixture.clock.set(1000);
    fixture.enrollment(&issuer, "rightful-attempt");

    // The largest representable interval is clamped before serialization to SQLite;
    // adding the configured TTL must neither wrap nor truncate to a negative integer.
    let fixture = Fixture::new();
    let limit = i64::MAX as u64;
    fixture.clock.set(limit - 1);
    let issuer = fixture.create(1);
    let mut intent = fixture.intent("near-integer-limit");
    intent.validity = ValidityWindow {
        not_before: limit - 10,
        expires: limit,
    };
    let enrollment = fixture.enrollment_with_intent(&issuer, intent);
    assert_eq!(
        enrollment.challenge.validity,
        ValidityWindow {
            not_before: limit - 1,
            expires: limit
        }
    );
    enrollment.issue(&issuer);
}

#[test]
fn signed_windows_and_challenge_scope_cannot_be_grafted() {
    let fixture = Fixture::new();
    let issuer = fixture.create(1);
    let intent = fixture.intent("attempt-one");
    let original = intent_wire(&fixture, &intent);
    let mut altered: Signed<TenantIntent> = serde_json::from_slice(&original).unwrap();
    altered.statement.validity.expires += 1;
    assert!(issuer
        .begin(&serde_json::to_vec(&altered).unwrap())
        .is_err());
    let enrollment = fixture.enrollment(&issuer, "attempt-one");
    let attacker = Key::new();
    assert!(verify_bootstrap_challenge(
        &enrollment.challenge_json,
        &attacker.public(),
        &enrollment.challenge,
        1000
    )
    .is_err());
    let mut graft: Signed<BootstrapChallenge> =
        serde_json::from_slice(&enrollment.challenge_json).unwrap();
    graft.statement.validity.expires += 1;
    assert!(verify_bootstrap_challenge(
        &serde_json::to_vec(&graft).unwrap(),
        &fixture.authority.public(),
        &enrollment.challenge,
        1000
    )
    .is_err());
    // Even a valid signature for a different window or attempt does not satisfy this scope.
    let wire = signed(
        &graft.statement,
        &graft.statement.signing_bytes().unwrap(),
        &fixture.authority,
    );
    assert!(verify_bootstrap_challenge(
        &wire,
        &fixture.authority.public(),
        &enrollment.challenge,
        1000
    )
    .is_err());
    graft.statement = enrollment.challenge.clone();
    graft.statement.attempt_id = "different-attempt".into();
    let wire = signed(
        &graft.statement,
        &graft.statement.signing_bytes().unwrap(),
        &fixture.authority,
    );
    assert!(verify_bootstrap_challenge(
        &wire,
        &fixture.authority.public(),
        &enrollment.challenge,
        1000
    )
    .is_err());
    enrollment.issue(&issuer);
}

#[test]
fn request_supplied_time_is_rejected_and_cannot_disable_expiry() {
    let fixture = Fixture::new();
    let issuer = fixture.create(1);
    let intent = fixture.intent("untrusted-time");
    let mut wire: serde_json::Value =
        serde_json::from_slice(&intent_wire(&fixture, &intent)).unwrap();
    wire["statement"]["now_unix_seconds"] = 0.into();
    assert!(issuer.begin(&serde_json::to_vec(&wire).unwrap()).is_err());
    let enrollment = fixture.enrollment(&issuer, "rightful-attempt");
    let grant = enrollment.issue(&issuer);
    let statements = fixture.statements(&enrollment, &grant);
    let request = fixture.request(&statements, REDEEM_PURPOSE, &fixture.recorder);
    let mut wire: serde_json::Value = serde_json::from_slice(&request).unwrap();
    wire["statement"]["now_unix_seconds"] = 1000.into();
    assert!(issuer
        .redeem(&statements, &serde_json::to_vec(&wire).unwrap())
        .is_err());
    fixture.clock.set(1030);
    assert!(matches!(
        issuer.redeem(&statements, &request),
        Err(Error::Store(StoreError::Expired))
    ));
}

#[test]
fn clock_failures_do_not_reserve_issue_or_consume() {
    for failure in [ClockError::Unavailable, ClockError::OutOfRange] {
        let fixture = Fixture::new();
        let issuer = fixture.create(1);
        fixture.clock.fail(failure);
        let intent = fixture.intent("failed-before-reserve");
        assert!(issuer.begin(&intent_wire(&fixture, &intent)).is_err());
        fixture.clock.set(1000);
        let enrollment = fixture.enrollment(&issuer, "rightful-attempt");
        fixture.clock.fail(failure);
        assert!(issuer
            .issue(
                &enrollment.challenge.challenge_id,
                &enrollment.appraisal_json,
                &enrollment.possession_json
            )
            .is_err());
        fixture.clock.set(1000);
        let issued = issuer
            .issue(
                &enrollment.challenge.challenge_id,
                &enrollment.appraisal_json,
                &enrollment.possession_json,
            )
            .unwrap();
        assert_eq!(issued.publication, GrantPublication::FirstIssued);
        let statements = fixture.statements(&enrollment, &issued.signed_grant_json);
        let request = fixture.request(&statements, REDEEM_PURPOSE, &fixture.recorder);
        fixture.clock.fail(failure);
        assert!(issuer.redeem(&statements, &request).is_err());
        let status = fixture.request(&statements, STATUS_PURPOSE, &fixture.recorder);
        assert_eq!(
            issuer.status(&statements, &status).unwrap(),
            RedemptionStatus::Issued
        );
        fixture.clock.set(1000);
        assert_eq!(
            issuer.redeem(&statements, &request).unwrap(),
            Redemption::FirstRedeemed
        );
    }
}

#[test]
fn clock_watermark_is_shared_across_connections_and_survives_reopen() {
    let fixture = Fixture::new();
    let first = fixture.create(3);
    let other_clock = Arc::new(ManualClock::new(1000));
    let second = SoftwareIssuer::open_existing_with_clock(
        &fixture.db(),
        fixture.config(),
        fixture.authority.pair(),
        3,
        other_clock.clone(),
    )
    .unwrap();
    fixture.clock.set(1010);
    fixture.enrollment(&first, "first-attempt");
    other_clock.set(1009);
    let second_intent = fixture.intent("second-attempt");
    assert!(matches!(
        second.begin(&intent_wire(&fixture, &second_intent)),
        Err(Error::Store(StoreError::ClockRegression))
    ));
    drop(second);
    let reopened = SoftwareIssuer::open_existing_with_clock(
        &fixture.db(),
        fixture.config(),
        fixture.authority.pair(),
        3,
        other_clock.clone(),
    )
    .unwrap();
    assert!(matches!(
        reopened.begin(&intent_wire(&fixture, &second_intent)),
        Err(Error::Store(StoreError::ClockRegression))
    ));
    other_clock.set(1010);
    let response = reopened
        .begin(&intent_wire(&fixture, &second_intent))
        .unwrap();
    fixture.authenticate_challenge(
        &response,
        &second_intent,
        ValidityWindow {
            not_before: 1010,
            expires: 1040,
        },
    );
}

#[test]
fn expiry_denial_persists_high_watermark_without_issuing_or_refreshing_pending_attempt() {
    let fixture = Fixture::new();
    let issuer = fixture.create(2);
    let enrollment = fixture.enrollment(&issuer, "pending");
    fixture.clock.set(1030);
    assert!(matches!(
        issuer.issue(
            &enrollment.challenge.challenge_id,
            &enrollment.appraisal_json,
            &enrollment.possession_json
        ),
        Err(Error::Store(StoreError::Expired))
    ));
    assert!(matches!(
        issuer.begin(&intent_wire(&fixture, &enrollment.intent)),
        Err(Error::Store(StoreError::Expired))
    ));
    drop(issuer);
    fixture.clock.set(1029);
    let reopened = fixture.reopen(2);
    let fresh = fixture.intent("fresh-attempt");
    assert!(matches!(
        reopened.begin(&intent_wire(&fixture, &fresh)),
        Err(Error::Store(StoreError::ClockRegression))
    ));
    fixture.clock.set(1030);
    fixture.enrollment(&reopened, "fresh-attempt");
    assert!(matches!(
        reopened.issue(
            &enrollment.challenge.challenge_id,
            &enrollment.appraisal_json,
            &enrollment.possession_json
        ),
        Err(Error::Store(StoreError::Expired))
    ));
}

#[test]
fn historical_retry_status_and_already_redeemed_never_refresh_an_expired_grant() {
    let fixture = Fixture::new();
    let issuer = fixture.create(2);
    let consumed = fixture.enrollment(&issuer, "consumed");
    let issued = issuer
        .issue(
            &consumed.challenge.challenge_id,
            &consumed.appraisal_json,
            &consumed.possession_json,
        )
        .unwrap();
    assert_eq!(issued.publication, GrantPublication::FirstIssued);
    let statements = fixture.statements(&consumed, &issued.signed_grant_json);
    let redeem = fixture.request(&statements, REDEEM_PURPOSE, &fixture.recorder);
    assert_eq!(
        issuer.redeem(&statements, &redeem).unwrap(),
        Redemption::FirstRedeemed
    );
    let pending = fixture.enrollment(&issuer, "issued-not-redeemed");
    let pending_bytes = pending.issue(&issuer);
    let pending_statements = fixture.statements(&pending, &pending_bytes);
    let pending_redeem = fixture.request(&pending_statements, REDEEM_PURPOSE, &fixture.recorder);
    fixture.clock.set(1030);
    assert!(matches!(
        issuer.redeem(&pending_statements, &pending_redeem),
        Err(Error::Store(StoreError::Expired))
    ));
    drop(issuer);
    fixture.clock.fail(ClockError::Unavailable);
    let reopened = fixture.reopen(2);
    let reads = fixture.clock.reads();
    let historical = reopened
        .issue(
            &consumed.challenge.challenge_id,
            &consumed.appraisal_json,
            &consumed.possession_json,
        )
        .unwrap();
    assert_eq!(historical.publication, GrantPublication::Existing);
    assert_eq!(historical.signed_grant_json, issued.signed_grant_json);
    assert_eq!(
        reopened.redeem(&statements, &redeem).unwrap(),
        Redemption::AlreadyRedeemed
    );
    let status = fixture.request(&statements, STATUS_PURPOSE, &fixture.recorder);
    assert_eq!(
        reopened.status(&statements, &status).unwrap(),
        RedemptionStatus::Redeemed
    );
    let pending_status = fixture.request(&pending_statements, STATUS_PURPOSE, &fixture.recorder);
    assert_eq!(
        reopened
            .status(&pending_statements, &pending_status)
            .unwrap(),
        RedemptionStatus::Issued
    );
    assert_eq!(
        fixture.clock.reads(),
        reads,
        "historical retrieval must not consult the live clock"
    );
    fixture.clock.set(1029);
    assert_eq!(
        reopened.redeem(&statements, &redeem).unwrap(),
        Redemption::AlreadyRedeemed
    );
    assert!(matches!(
        reopened.redeem(&pending_statements, &pending_redeem),
        Err(Error::Store(StoreError::ClockRegression))
    ));
}
