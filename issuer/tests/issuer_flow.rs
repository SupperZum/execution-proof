//! Real signatures and a physical SQLite store, with software-only boot/AS fixtures.
//! This suite does not attest hardware, prepare an encrypted rootfs, or execute a workload.

mod support;

use execution_proof_contract::bootstrap::{verify_bootstrap_challenge, RecorderPossession};
use execution_proof_issuer::{
    Redemption, RedemptionStatus, SoftwareIssuer, REDEEM_PURPOSE, STATUS_PURPOSE,
};
use std::sync::{Arc, Barrier};
use support::{signed, Fixture, Key};

#[test]
fn software_issue_redeem_and_reopen_preserve_exact_state() {
    let fixture = Fixture::new();
    let issuer = fixture.create(8);
    assert_eq!(issuer.authority_public_key(), fixture.authority.public());
    let enrollment = fixture.enrollment(&issuer, "attempt-one");
    let first = enrollment.issue(&issuer);
    assert_eq!(first, enrollment.issue(&issuer));
    let statements = fixture.statements(&enrollment, &first);
    let status = fixture.request(&statements, STATUS_PURPOSE, &fixture.recorder);
    let redeem = fixture.request(&statements, REDEEM_PURPOSE, &fixture.recorder);
    assert_eq!(
        issuer.status(&statements, &status).unwrap(),
        RedemptionStatus::Issued
    );
    assert_eq!(
        issuer.redeem(&statements, &redeem).unwrap(),
        Redemption::FirstRedeemed
    );
    drop(issuer);

    let header = std::fs::read(fixture.db()).unwrap();
    assert_eq!(&header[..16], b"SQLite format 3\0");
    let reopened = fixture.reopen(8);
    assert_eq!(enrollment.issue(&reopened), first);
    let intent_json = signed(
        &enrollment.intent,
        &enrollment.intent.signing_bytes().unwrap(),
        &fixture.tenant,
    );
    let retry = reopened.begin(&intent_json).unwrap();
    assert_eq!(
        verify_bootstrap_challenge(
            &serde_json::to_vec(&retry).unwrap(),
            &fixture.authority.public(),
            &enrollment.challenge,
            fixture.clock.current(),
        )
        .unwrap(),
        enrollment.challenge
    );
    assert_eq!(
        reopened.status(&statements, &status).unwrap(),
        RedemptionStatus::Redeemed
    );
    assert_eq!(
        reopened.redeem(&statements, &redeem).unwrap(),
        Redemption::AlreadyRedeemed
    );
    assert!(SoftwareIssuer::initialize_new(
        &fixture.db(),
        fixture.config(),
        fixture.authority.pair(),
        8
    )
    .is_err());
}

#[test]
fn forged_boot_recorder_and_wrong_producer_do_not_poison_valid_issuance() {
    let fixture = Fixture::new();
    let issuer = fixture.create(1);
    let enrollment = fixture.enrollment(&issuer, "attempt-one");
    let attacker = Key::new();
    let bad_appraisal = signed(
        &enrollment.appraisal,
        &enrollment.appraisal.signing_bytes().unwrap(),
        &attacker,
    );
    assert!(issuer
        .issue(
            &enrollment.challenge.challenge_id,
            &bad_appraisal,
            &enrollment.possession_json
        )
        .is_err());
    let bad_possession = signed(
        &enrollment.possession,
        &enrollment.possession.signing_bytes().unwrap(),
        &attacker,
    );
    assert!(issuer
        .issue(
            &enrollment.challenge.challenge_id,
            &enrollment.appraisal_json,
            &bad_possession
        )
        .is_err());

    let mut wrong_profile = enrollment.appraisal.clone();
    wrong_profile.producer_profile_sha384 = support::hash("unapproved-software-producer");
    let profile_appraisal = signed(
        &wrong_profile,
        &wrong_profile.signing_bytes().unwrap(),
        &fixture.bootstrap,
    );
    let profile_possession = RecorderPossession {
        appraisal_sha384: wrong_profile.digest_sha384().unwrap(),
        ..enrollment.possession.clone()
    };
    let profile_pop = signed(
        &profile_possession,
        &profile_possession.signing_bytes().unwrap(),
        &fixture.recorder,
    );
    assert!(issuer
        .issue(
            &enrollment.challenge.challenge_id,
            &profile_appraisal,
            &profile_pop
        )
        .is_err());
    let grant = enrollment.issue(&issuer);
    fixture.statements(&enrollment, &grant);
}

#[test]
fn signed_intent_scope_profile_and_mutation_cannot_create_another_authorization() {
    let fixture = Fixture::new();
    let issuer = fixture.create(1);
    let original = fixture.intent("attempt-one");
    let attacker = Key::new();
    let forged = signed(&original, &original.signing_bytes().unwrap(), &attacker);
    assert!(issuer.begin(&forged).is_err());
    for field in [
        "tenant",
        "audience",
        "profile",
        "launch_policy",
        "image_policy",
    ] {
        let mut altered = original.clone();
        match field {
            "tenant" => altered.tenant = "tenant-b".into(),
            "audience" => altered.audience = "other-runtime".into(),
            "profile" => altered.profile_sha384 = support::hash("other-proof-profile"),
            "launch_policy" => altered.launch_policy_sha384 = support::hash("other-launch-policy"),
            "image_policy" => altered.image_policy_sha384 = support::hash("other-image-policy"),
            _ => unreachable!(),
        }
        let wire = signed(&altered, &altered.signing_bytes().unwrap(), &fixture.tenant);
        assert!(issuer.begin(&wire).is_err(), "{field}");
    }
    let enrollment = fixture.enrollment(&issuer, "attempt-one");
    let mut altered = original;
    altered.selected_manifest_sha256 = "ab".repeat(32);
    let wire = signed(&altered, &altered.signing_bytes().unwrap(), &fixture.tenant);
    assert!(issuer.begin(&wire).is_err());
    enrollment.issue(&issuer);
}

#[test]
fn old_boot_response_and_recorder_requests_cannot_cross_attempts_or_purposes() {
    let fixture = Fixture::new();
    let issuer = fixture.create(2);
    let first = fixture.enrollment(&issuer, "attempt-one");
    let second = fixture.enrollment(&issuer, "attempt-two");
    assert_ne!(first.challenge.challenge_id, second.challenge.challenge_id);
    assert_ne!(first.challenge.nonce_hex, second.challenge.nonce_hex);
    assert!(issuer
        .issue(
            &second.challenge.challenge_id,
            &first.appraisal_json,
            &first.possession_json
        )
        .is_err());
    let first_grant = first.issue(&issuer);
    let second_grant = second.issue(&issuer);
    let first_statements = fixture.statements(&first, &first_grant);
    let second_statements = fixture.statements(&second, &second_grant);
    let first_redeem = fixture.request(&first_statements, REDEEM_PURPOSE, &fixture.recorder);
    assert!(issuer.redeem(&second_statements, &first_redeem).is_err());
    let second_status = fixture.request(&second_statements, STATUS_PURPOSE, &fixture.recorder);
    assert!(issuer.redeem(&second_statements, &second_status).is_err());
    let second_redeem = fixture.request(&second_statements, REDEEM_PURPOSE, &fixture.recorder);
    assert!(issuer.status(&second_statements, &second_redeem).is_err());
    let attacker = Key::new();
    let foreign = fixture.request(&second_statements, REDEEM_PURPOSE, &attacker);
    assert!(issuer.redeem(&second_statements, &foreign).is_err());
    assert_eq!(
        issuer.status(&second_statements, &second_status).unwrap(),
        RedemptionStatus::Issued
    );
    assert_eq!(
        issuer.redeem(&second_statements, &second_redeem).unwrap(),
        Redemption::FirstRedeemed
    );
}

#[test]
fn concurrent_independent_connections_have_one_issue_and_one_redeem_transition() {
    let fixture = Fixture::new();
    let issuer = fixture.create(2);
    let enrollment = fixture.enrollment(&issuer, "attempt-one");
    drop(issuer);
    let connections = [fixture.reopen(2), fixture.reopen(2)];
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = connections
        .into_iter()
        .map(|connection| {
            let barrier = barrier.clone();
            let challenge = enrollment.challenge.challenge_id.clone();
            let appraisal = enrollment.appraisal_json.clone();
            let possession = enrollment.possession_json.clone();
            std::thread::spawn(move || {
                barrier.wait();
                connection
                    .issue(&challenge, &appraisal, &possession)
                    .unwrap()
                    .signed_grant_json
            })
        })
        .collect();
    let grants: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(grants[0], grants[1]);

    let connections = [fixture.reopen(2), fixture.reopen(2)];
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = connections
        .into_iter()
        .map(|connection| {
            let barrier = barrier.clone();
            let statements = fixture.statements(&enrollment, &grants[0]);
            let request = fixture.request(&statements, REDEEM_PURPOSE, &fixture.recorder);
            std::thread::spawn(move || {
                barrier.wait();
                connection.redeem(&statements, &request).unwrap()
            })
        })
        .collect();
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Redemption::FirstRedeemed)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Redemption::AlreadyRedeemed)
            .count(),
        1
    );
}

#[test]
fn attacker_root_verified_wrapper_cannot_redeem_even_the_exact_issued_context() {
    let fixture = Fixture::new();
    let issuer = fixture.create(1);
    let enrollment = fixture.enrollment(&issuer, "attempt-one");
    let grant = enrollment.issue(&issuer);
    let legitimate = fixture.statements(&enrollment, &grant);
    let attacker_authority = Key::new();
    let attacker_as = Key::new();
    let wrapped =
        fixture.statements_with_keys(&enrollment, &grant, &attacker_authority, &attacker_as);
    assert_eq!(legitimate.grant_digest(), wrapped.grant_digest());
    assert_eq!(legitimate.context_digest(), wrapped.context_digest());
    let request = fixture.request(&wrapped, REDEEM_PURPOSE, &fixture.recorder);
    assert!(issuer.redeem(&wrapped, &request).is_err());
    let status = fixture.request(&legitimate, STATUS_PURPOSE, &fixture.recorder);
    assert_eq!(
        issuer.status(&legitimate, &status).unwrap(),
        RedemptionStatus::Issued
    );
    let request = fixture.request(&legitimate, REDEEM_PURPOSE, &fixture.recorder);
    assert_eq!(
        issuer.redeem(&legitimate, &request).unwrap(),
        Redemption::FirstRedeemed
    );
}

#[test]
fn same_as_key_with_unconfigured_issuer_cannot_query_or_redeem() {
    let fixture = Fixture::new();
    let issuer = fixture.create(1);
    let enrollment = fixture.enrollment(&issuer, "attempt-one");
    let grant = enrollment.issue(&issuer);
    let legitimate = fixture.statements(&enrollment, &grant);
    let foreign = fixture.statements_claiming_as_issuer(&enrollment, &grant, "other-as");
    assert_eq!(legitimate.grant_digest(), foreign.grant_digest());
    assert_eq!(
        legitimate.authority_key_sha384(),
        foreign.authority_key_sha384()
    );
    assert_eq!(
        legitimate.as_proof_key_sha384(),
        foreign.as_proof_key_sha384()
    );
    assert_ne!(legitimate.context_digest(), foreign.context_digest());

    let status = fixture.request(&foreign, STATUS_PURPOSE, &fixture.recorder);
    let redeem = fixture.request(&foreign, REDEEM_PURPOSE, &fixture.recorder);
    // Evaluate both calls so a missing gate on either operation is visible.
    let status_result = issuer.status(&foreign, &status);
    let redeem_result = issuer.redeem(&foreign, &redeem);
    assert!(
        status_result.is_err() && redeem_result.is_err(),
        "unconfigured AS issuer: status={status_result:?}, redeem={redeem_result:?}"
    );

    let status = fixture.request(&legitimate, STATUS_PURPOSE, &fixture.recorder);
    assert_eq!(
        issuer.status(&legitimate, &status).unwrap(),
        RedemptionStatus::Issued
    );
    let redeem = fixture.request(&legitimate, REDEEM_PURPOSE, &fixture.recorder);
    assert_eq!(
        issuer.redeem(&legitimate, &redeem).unwrap(),
        Redemption::FirstRedeemed
    );
}
