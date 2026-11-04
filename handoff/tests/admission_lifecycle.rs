//! Cross-crate software contract checks with real ephemeral signatures.
//! No fixture boot is attested and no fixture preparation reference is a rootfs.

use execution_proof_contract::{
    verify_statements, AppraisalVerdict, EvaluationCommitments, KbsAssociation, LaunchBinding,
    LaunchGrant, ProofAppraisal, Signed, TrustedExpectations, ValidityWindow, VerifiedStatements,
    APPRAISAL_PURPOSE, GRANT_PURPOSE, VERSION,
};
use execution_proof_handoff::{
    BootTable, Error, PreparationId, PreparationReference, Registration, Status, TaskIdentity,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::sync::{Arc, Barrier};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn authenticated_statements(attempt: &str) -> VerifiedStatements {
    authenticated_statements_for_grant(attempt, &format!("grant-{attempt}"))
}

fn authenticated_statements_for_grant(attempt: &str, grant_id: &str) -> VerifiedStatements {
    let random = SystemRandom::new();
    let authority =
        Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&random).unwrap().as_ref())
            .unwrap();
    let appraisal_key =
        Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&random).unwrap().as_ref())
            .unwrap();
    let binding = LaunchBinding {
        authority: "fixture-authority".into(),
        tenant: "tenant-one".into(),
        workload_id: "authorized-workload-one".into(),
        container_role: "application-init".into(),
        attempt_id: attempt.into(),
        boot_id: "software-fixture-boot".into(),
        channel_key_sha384: "11".repeat(48),
        bootstrap_context_sha384: "10".repeat(48),
        selected_manifest_sha256: "22".repeat(32),
        effective_launch_sha384: "33".repeat(48),
        profile_sha384: "44".repeat(48),
        launch_policy_sha384: "55".repeat(48),
        image_policy_sha384: "66".repeat(48),
        challenge_sha384: "77".repeat(48),
    };
    let evaluation = EvaluationCommitments {
        policy_id: "fixture-tdx-appraisal-policy".into(),
        policy_sha384: "88".repeat(48),
        input_sha384: "99".repeat(48),
        rvps_sha384: "aa".repeat(48),
        acceptance_policy_sha384: "bb".repeat(48),
        kbs: KbsAssociation {
            decision_sha384: "cc".repeat(48),
            policy_sha384: "dd".repeat(48),
            input_sha384: "ee".repeat(48),
            session_sha384: "ff".repeat(48),
        },
    };
    let grant = LaunchGrant {
        validity: ValidityWindow {
            not_before: 1,
            expires: 2000,
        },
        version: VERSION,
        purpose: GRANT_PURPOSE.into(),
        audience: "fixture-runtime".into(),
        proof_required: true,
        grant_id: grant_id.into(),
        binding: binding.clone(),
    };
    let appraisal = ProofAppraisal {
        version: VERSION,
        purpose: APPRAISAL_PURPOSE.into(),
        audience: "fixture-runtime".into(),
        issuer: "fixture-as-proof-issuer".into(),
        verdict: AppraisalVerdict::Affirming,
        grant_sha384: grant.digest_sha384().unwrap(),
        binding: binding.clone(),
        evaluation: evaluation.clone(),
    };
    let expected = TrustedExpectations {
        authority_public_key: authority.public_key().as_ref().try_into().unwrap(),
        as_proof_public_key: appraisal_key.public_key().as_ref().try_into().unwrap(),
        audience: "fixture-runtime".into(),
        as_issuer: "fixture-as-proof-issuer".into(),
        grant_id: grant.grant_id.clone(),
        binding,
        evaluation,
    };
    let signed_grant = Signed {
        signature: hex(authority.sign(&grant.signing_bytes().unwrap()).as_ref()),
        statement: grant,
    };
    let signed_appraisal = Signed {
        signature: hex(appraisal_key
            .sign(&appraisal.signing_bytes().unwrap())
            .as_ref()),
        statement: appraisal,
    };
    verify_statements(
        &serde_json::to_vec(&signed_grant).unwrap(),
        &serde_json::to_vec(&signed_appraisal).unwrap(),
        &expected,
    )
    .unwrap()
}

fn reference(statements: &VerifiedStatements, id: u8) -> PreparationReference {
    let mut digest = [0; 48];
    for (i, pair) in statements
        .context_digest()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .enumerate()
    {
        let text = std::str::from_utf8(pair).unwrap();
        digest[i] = u8::from_str_radix(text, 16).unwrap();
    }
    PreparationReference {
        id: PreparationId::new([id; 32]),
        context_sha384: digest,
    }
}

fn task(statements: &VerifiedStatements) -> TaskIdentity {
    let binding = statements.binding();
    TaskIdentity {
        boot_id: binding.boot_id.clone(),
        attempt_id: binding.attempt_id.clone(),
        selected_manifest_sha256: binding.selected_manifest_sha256.clone(),
        effective_launch_sha384: binding.effective_launch_sha384.clone(),
        container_role: binding.container_role.clone(),
        generation: 1,
    }
}

#[test]
fn signed_statements_bind_once_and_abort_does_not_reopen_attempt() {
    let statements = authenticated_statements("attempt-one");
    let table = BootTable::new(statements.binding().boot_id.clone(), 1).unwrap();
    let reference_one = reference(&statements, 1);
    let task = task(&statements);
    assert_eq!(
        table.register(&statements, reference_one).unwrap(),
        Registration::Inserted
    );
    assert_eq!(
        table.bind(&reference_one, task.clone()).unwrap(),
        Status::Bound
    );
    let permit = table.consume(&reference_one, &task).unwrap();
    assert_eq!(permit.task(), &task);
    drop(permit); // A lost reply must never produce a second release permission.
    assert_eq!(table.status(&reference_one).unwrap(), Status::Consumed);
    assert_eq!(
        table.consume(&reference_one, &task).unwrap_err(),
        Error::AlreadyConsumed
    );
    assert_eq!(
        table.abort(&reference_one).unwrap(),
        Status::AbortedAfterConsume
    );
    assert_eq!(
        table.consume(&reference_one, &task).unwrap_err(),
        Error::Aborted
    );
    assert_eq!(
        table.register(&statements, reference_one).unwrap(),
        Registration::Existing(Status::AbortedAfterConsume)
    );
    assert_eq!(
        table
            .register(&statements, reference(&statements, 2))
            .unwrap_err(),
        Error::AttemptAlreadyRegistered
    );
}

#[test]
fn concurrent_consumers_of_signed_context_receive_one_permit() {
    let statements = authenticated_statements("attempt-race");
    let table = Arc::new(BootTable::new(statements.binding().boot_id.clone(), 1).unwrap());
    let reference = reference(&statements, 3);
    let task = task(&statements);
    table.register(&statements, reference).unwrap();
    table.bind(&reference, task.clone()).unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            let task = task.clone();
            std::thread::spawn(move || {
                barrier.wait();
                table.consume(&reference, &task)
            })
        })
        .collect();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(Error::AlreadyConsumed)))
            .count(),
        7
    );
    assert_eq!(table.status(&reference).unwrap(), Status::Consumed);
}

#[test]
fn signed_grant_reservation_survives_abort_and_capacity_does_not_evict() {
    let first = authenticated_statements_for_grant("attempt-first", "one-grant");
    let first_reference = reference(&first, 4);
    let table = BootTable::new(first.binding().boot_id.clone(), 1).unwrap();
    table.register(&first, first_reference).unwrap();
    assert_eq!(
        table.abort(&first_reference).unwrap(),
        Status::AbortedBeforeConsume
    );

    // A freshly signed statement is insufficient to reopen a consumed namespace.
    let reused_grant = authenticated_statements_for_grant("attempt-second", "one-grant");
    assert_eq!(
        table
            .register(&reused_grant, reference(&reused_grant, 5))
            .unwrap_err(),
        Error::GrantAlreadyRegistered
    );
    // Terminal entries remain reserved; full tables reject new work instead of eviction.
    let distinct = authenticated_statements("attempt-third");
    assert_eq!(
        table
            .register(&distinct, reference(&distinct, 6))
            .unwrap_err(),
        Error::CapacityExhausted
    );
    assert_eq!(
        table.status(&first_reference).unwrap(),
        Status::AbortedBeforeConsume
    );
}
