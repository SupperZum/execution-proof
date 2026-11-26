use super::*;
use std::sync::{Arc, Barrier};
use std::thread;

// These private fixtures isolate table transitions. Cross-crate admission
// tests exercise register with actual signed/verified contract statements.
fn fixture(capacity: usize) -> (BootTable, PreparationReference, TaskIdentity) {
    let table = BootTable::new("boot-1".into(), capacity).unwrap();
    let reference = prep_ref(1);
    let task = task(1);
    insert_fixture(&table, reference, &task);
    (table, reference, task)
}

fn prep_ref(value: u8) -> PreparationReference {
    PreparationReference {
        id: PreparationId::new([value; 32]),
        context_sha384: [value; 48],
    }
}

fn task(generation: u64) -> TaskIdentity {
    TaskIdentity {
        boot_id: "boot-1".into(),
        attempt_id: format!("attempt-{generation}"),
        selected_manifest_sha256: "a".repeat(64),
        effective_launch_sha384: "c".repeat(96),
        container_role: APPLICATION_ROLE.into(),
        generation,
    }
}

fn insert_fixture(table: &BootTable, reference: PreparationReference, task: &TaskIdentity) {
    table.entries.lock().unwrap().insert(
        reference.id,
        Entry {
            reference,
            grant_id: format!("grant-{}", task.generation),
            attempt_id: task.attempt_id.clone(),
            manifest: task.selected_manifest_sha256.clone(),
            effective_launch: task.effective_launch_sha384.clone(),
            task: None,
            status: Status::Registered,
        },
    );
}

#[test]
fn production_preparation_advertises_no_capability_and_never_succeeds() {
    assert!(supported_proof_profiles().is_empty());
    assert_eq!(
        prepare_launch(PROTOCOL_VERSION, None),
        Err(PrepareError::MissingProofProfile)
    );
    assert_eq!(
        prepare_launch(PROTOCOL_VERSION, Some("")),
        Err(PrepareError::MissingProofProfile)
    );
    assert_eq!(
        prepare_launch(0, Some("profile")),
        Err(PrepareError::UnsupportedProtocolVersion)
    );
    assert_eq!(
        prepare_launch(PROTOCOL_VERSION, Some("profile")),
        Err(PrepareError::Unsupported(
            UnsupportedReason::AuthorityBootAndContentAdaptersUnavailable
        ))
    );
}

#[test]
fn consumes_once_and_status_or_registration_is_not_a_second_permit() {
    let (table, reference, task) = fixture(1);
    assert!(matches!(
        table.consume(&reference, &task),
        Err(Error::NotBound)
    ));
    assert_eq!(table.bind(&reference, task.clone()), Ok(Status::Bound));
    assert_eq!(table.bind(&reference, task.clone()), Ok(Status::Bound));
    let permit = table.consume(&reference, &task).unwrap();
    assert_eq!(permit.reference(), &reference);
    assert_eq!(permit.task(), &task);
    drop(permit);
    assert_eq!(table.status(&reference), Ok(Status::Consumed));
    assert!(matches!(
        table.consume(&reference, &task),
        Err(Error::AlreadyConsumed)
    ));
    assert_eq!(table.bind(&reference, task), Err(Error::AlreadyConsumed));
}

#[test]
fn wrong_identity_or_reference_cannot_change_or_consume_state() {
    let (table, reference, task) = fixture(1);
    let cases: Vec<(TaskIdentity, Error)> = vec![
        (
            TaskIdentity {
                boot_id: "other".into(),
                ..task.clone()
            },
            Error::WrongBoot,
        ),
        (
            TaskIdentity {
                attempt_id: "other".into(),
                ..task.clone()
            },
            Error::WrongAttempt,
        ),
        (
            TaskIdentity {
                selected_manifest_sha256: "b".repeat(64),
                ..task.clone()
            },
            Error::WrongManifest,
        ),
        (
            TaskIdentity {
                effective_launch_sha384: "d".repeat(96),
                ..task.clone()
            },
            Error::WrongEffectiveLaunch,
        ),
        (
            TaskIdentity {
                container_role: "helper".into(),
                ..task.clone()
            },
            Error::WrongRole,
        ),
        (
            TaskIdentity {
                generation: 0,
                ..task.clone()
            },
            Error::InvalidGeneration,
        ),
    ];
    for (wrong, expected) in cases {
        assert_eq!(table.bind(&reference, wrong.clone()), Err(expected));
        assert!(matches!(table.consume(&reference, &wrong), Err(error) if error == expected));
        assert_eq!(table.status(&reference), Ok(Status::Registered));
    }
    let mut changed = reference;
    changed.context_sha384[0] ^= 1;
    assert_eq!(table.status(&changed), Err(Error::ReferenceConflict));
    assert_eq!(table.abort(&changed), Err(Error::ReferenceConflict));
    table.bind(&reference, task.clone()).unwrap();
    let changed_generation = TaskIdentity {
        generation: 2,
        ..task
    };
    assert_eq!(
        table.bind(&reference, changed_generation.clone()),
        Err(Error::WrongTask)
    );
    assert!(matches!(
        table.consume(&reference, &changed_generation),
        Err(Error::WrongTask)
    ));
    assert_eq!(table.status(&reference), Ok(Status::Bound));
}

#[test]
fn aborted_and_consumed_tombstones_preserve_generations() {
    let (table, reference, task) = fixture(2);
    table.bind(&reference, task.clone()).unwrap();
    assert_eq!(table.abort(&reference), Ok(Status::AbortedBeforeConsume));
    assert_eq!(table.abort(&reference), Ok(Status::AbortedBeforeConsume));
    assert!(matches!(
        table.consume(&reference, &task),
        Err(Error::Aborted)
    ));
    assert_eq!(table.bind(&reference, task.clone()), Err(Error::Aborted));
    let second = prep_ref(2);
    let second_task = TaskIdentity {
        attempt_id: "attempt-2".into(),
        ..task
    };
    insert_fixture(&table, second, &second_task);
    assert_eq!(
        table.bind(&second, second_task.clone()),
        Err(Error::GenerationAlreadyBound)
    );
    let second_task = TaskIdentity {
        generation: 2,
        ..second_task
    };
    table.bind(&second, second_task.clone()).unwrap();
    let permit = table.consume(&second, &second_task).unwrap();
    drop(permit);
    assert_eq!(table.abort(&second), Ok(Status::AbortedAfterConsume));
    assert_eq!(table.abort(&second), Ok(Status::AbortedAfterConsume));
    assert!(matches!(
        table.consume(&second, &second_task),
        Err(Error::Aborted)
    ));
    assert_eq!(table.entries.lock().unwrap().len(), 2);
}

#[test]
fn simultaneous_consumers_have_exactly_one_winner() {
    let (table, reference, task) = fixture(1);
    table.bind(&reference, task.clone()).unwrap();
    let table = Arc::new(table);
    let barrier = Arc::new(Barrier::new(16));
    let mut threads = Vec::new();
    for _ in 0..16 {
        let table = table.clone();
        let barrier = barrier.clone();
        let task = task.clone();
        threads.push(thread::spawn(move || {
            barrier.wait();
            table.consume(&reference, &task)
        }));
    }
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(Error::AlreadyConsumed)))
            .count(),
        15
    );
    assert_eq!(table.status(&reference), Ok(Status::Consumed));
}

#[test]
fn racing_abort_and_consume_never_reopens() {
    let (table, reference, task) = fixture(1);
    table.bind(&reference, task.clone()).unwrap();
    let table = Arc::new(table);
    let barrier = Arc::new(Barrier::new(2));
    let consumer = {
        let table = table.clone();
        let barrier = barrier.clone();
        let task = task.clone();
        thread::spawn(move || {
            barrier.wait();
            table.consume(&reference, &task)
        })
    };
    barrier.wait();
    let terminal = table.abort(&reference).unwrap();
    match consumer.join().unwrap() {
        Ok(_) => assert_eq!(terminal, Status::AbortedAfterConsume),
        Err(Error::Aborted) => assert_eq!(terminal, Status::AbortedBeforeConsume),
        other => panic!("unexpected consume result: {other:?}"),
    }
    assert!(matches!(
        table.consume(&reference, &task),
        Err(Error::Aborted)
    ));
}

#[test]
fn invalid_boot_capacity_reference_and_poison_fail_closed() {
    assert!(matches!(
        BootTable::new("boot".into(), 0),
        Err(Error::InvalidCapacity)
    ));
    assert!(matches!(
        BootTable::new("boot".into(), MAX_CAPACITY + 1),
        Err(Error::InvalidCapacity)
    ));
    for boot in [
        "",
        "with space",
        "slash/path",
        &"b".repeat(MAX_ID_BYTES + 1),
    ] {
        assert!(matches!(
            BootTable::new(boot.into(), 1),
            Err(Error::InvalidBootId)
        ));
    }
    let (table, reference, task) = fixture(1);
    assert_eq!(table.status(&prep_ref(0)), Err(Error::InvalidPreparationId));
    assert_eq!(table.status(&prep_ref(9)), Err(Error::UnknownReference));
    let table = Arc::new(table);
    let poison = table.clone();
    assert!(thread::spawn(move || {
        let _guard = poison.entries.lock().unwrap();
        panic!("poison fixture");
    })
    .join()
    .is_err());
    assert_eq!(table.status(&reference), Err(Error::Poisoned));
    assert!(matches!(
        table.consume(&reference, &task),
        Err(Error::Poisoned)
    ));
}

#[test]
fn context_decoder_accepts_only_canonical_fixed_size_lowercase_hex() {
    assert_eq!(decode_sha384(&"ab".repeat(48)), Ok([0xab; 48]));
    for bad in [
        "a".repeat(95),
        "a".repeat(97),
        "AB".repeat(48),
        "z".repeat(96),
    ] {
        assert_eq!(decode_sha384(&bad), Err(Error::InvalidContextDigest));
    }
}
