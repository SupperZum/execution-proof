use super::*;
use crate::admission::{ReceiverAdmissionVerifier, ReceiverChallenge, ReceiverEnrollmentError};

fn packet(
    bytes: &[u8],
    sender: &mut crate::startup::StartupBoundChannel,
    recipient: &mut crate::startup::StartupBoundChannel,
) -> crate::startup::StartupBoundPacket {
    assert_eq!(
        sender.try_send(bytes, None),
        Ok(crate::fd_transport::SendOutcome::Sent)
    );
    recipient
        .try_receive_bound(crate::fd_transport::FdExpectation::None)
        .unwrap()
        .unwrap()
}

fn grant_digest(fixture: &Fixture) -> [u8; 48] {
    let hex = fixture.grant.digest_sha384().unwrap();
    std::array::from_fn(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
}

#[test]
fn authenticated_factory_nonce_is_verified_independently_without_a_preparation_export() {
    let fixture = Fixture::new();
    let gate = fixture.gate();
    let (mut preparation, mut kata) = crate::startup::test_pair();
    let challenge = ReceiverChallenge::new(&kata, grant_digest(&fixture)).unwrap();
    let request = challenge.encode();
    let response = gate
        .receiver_enrollment(packet(&request, &mut kata, &mut preparation), &preparation)
        .unwrap();
    assert_eq!(
        gate.receiver_enrollment(packet(&request, &mut kata, &mut preparation), &preparation)
            .unwrap(),
        response
    );
    let pending = challenge
        .accept(packet(&response, &mut preparation, &mut kata), &kata)
        .unwrap();
    let receiver = ReceiverAdmissionVerifier::new(fixture.config(), pending).unwrap();
    let receipt = fixture.receipt_wire(&gate);
    assert_eq!(
        gate.verify_bundle(&fixture.grant_wire, &fixture.aggregate_wire, &receipt),
        Ok(AdmissionCheck::FirstVerified)
    );
    let producer_context = gate.take_accepted_attempt().unwrap();
    assert_eq!(
        receiver.verify_bundle(&fixture.grant_wire, &fixture.aggregate_wire, &receipt),
        Ok(AdmissionCheck::FirstVerified)
    );
    let admission = receiver.take_verified().unwrap();
    assert_eq!(
        admission.context_digest(),
        producer_context.context_digest()
    );
    assert_eq!(admission.binding(), producer_context.binding());
    assert_eq!(admission.grant_digest(), producer_context.grant_digest());
    assert_eq!(
        admission.aggregate_digest(),
        producer_context.aggregate_digest()
    );
    assert_eq!(
        admission.startup_binding_sha384(),
        &kata.binding_commitment()
    );
    assert!(matches!(
        receiver.take_verified(),
        Err(GuestAdmissionError::AlreadyConsumed)
    ));
    assert_eq!(
        receiver.verify_bundle(&fixture.grant_wire, &fixture.aggregate_wire, &receipt),
        Ok(AdmissionCheck::Historical)
    );
    assert_eq!(
        gate.receiver_enrollment(packet(&request, &mut kata, &mut preparation), &preparation),
        Err(ReceiverEnrollmentError::NotPending)
    );
}

#[test]
fn pending_gate_retains_one_exact_challenge_and_never_rebinds_receiver() {
    let fixture = Fixture::new();
    let gate = fixture.gate();
    let (mut preparation, mut kata) = crate::startup::test_pair();
    let first = ReceiverChallenge::new(&kata, grant_digest(&fixture)).unwrap();
    let second = ReceiverChallenge::new(&kata, grant_digest(&fixture)).unwrap();
    assert_ne!(first.encode(), second.encode());
    let enrollment = gate
        .receiver_enrollment(
            packet(&first.encode(), &mut kata, &mut preparation),
            &preparation,
        )
        .unwrap();
    assert_eq!(
        gate.receiver_enrollment(
            packet(&second.encode(), &mut kata, &mut preparation),
            &preparation
        ),
        Err(ReceiverEnrollmentError::Conflict)
    );
    assert!(matches!(
        second.accept(packet(&enrollment, &mut preparation, &mut kata), &kata),
        Err(ReceiverEnrollmentError::ChallengeMismatch)
    ));
    assert!(first
        .accept(packet(&enrollment, &mut preparation, &mut kata), &kata)
        .is_ok());
}

#[test]
fn role_channel_and_grant_mismatches_cannot_select_a_receiver_nonce() {
    let fixture = Fixture::new();
    let gate = fixture.gate();
    let (mut preparation, mut kata) = crate::startup::test_pair();
    assert!(matches!(
        ReceiverChallenge::new(&preparation, grant_digest(&fixture)),
        Err(ReceiverEnrollmentError::WrongRole)
    ));
    let challenge = ReceiverChallenge::new(&kata, grant_digest(&fixture)).unwrap();
    assert_eq!(
        gate.receiver_enrollment(
            packet(&challenge.encode(), &mut kata, &mut preparation),
            &kata
        ),
        Err(ReceiverEnrollmentError::WrongRole)
    );
    let mut wrong_channel = challenge.encode();
    wrong_channel[48] ^= 1;
    assert_eq!(
        gate.receiver_enrollment(
            packet(&wrong_channel, &mut kata, &mut preparation),
            &preparation
        ),
        Err(ReceiverEnrollmentError::StartupBinding)
    );
    let mut wrong_grant = challenge.encode();
    wrong_grant[96] ^= 1;
    assert_eq!(
        gate.receiver_enrollment(
            packet(&wrong_grant, &mut kata, &mut preparation),
            &preparation
        ),
        Err(ReceiverEnrollmentError::GrantMismatch)
    );
    let response = gate
        .receiver_enrollment(
            packet(&challenge.encode(), &mut kata, &mut preparation),
            &preparation,
        )
        .unwrap();
    assert!(matches!(
        challenge.accept(packet(&response, &mut preparation, &mut kata), &preparation),
        Err(ReceiverEnrollmentError::WrongRole)
    ));
}

#[test]
fn malformed_fixed_frames_are_rejected_before_nonce_projection() {
    let fixture = Fixture::new();
    let (mut preparation, mut kata) = crate::startup::test_pair();
    let request = ReceiverChallenge::new(&kata, grant_digest(&fixture))
        .unwrap()
        .encode();
    for length in 1..request.len() {
        assert_eq!(
            fixture.gate().receiver_enrollment(
                packet(&request[..length], &mut kata, &mut preparation),
                &preparation
            ),
            Err(ReceiverEnrollmentError::InvalidFrame)
        );
    }
    for offset in [0, 8, 10, 11, 12, 15] {
        let mut changed = request;
        changed[offset] ^= 0x80;
        assert_eq!(
            fixture
                .gate()
                .receiver_enrollment(packet(&changed, &mut kata, &mut preparation), &preparation),
            Err(ReceiverEnrollmentError::InvalidFrame)
        );
    }
    let mut empty_nonce = request;
    empty_nonce[16..48].fill(0);
    assert_eq!(
        fixture.gate().receiver_enrollment(
            packet(&empty_nonce, &mut kata, &mut preparation),
            &preparation
        ),
        Err(ReceiverEnrollmentError::InvalidFrame)
    );
    for length in [1, 15, 175, 177] {
        let challenge = ReceiverChallenge::new(&kata, grant_digest(&fixture)).unwrap();
        assert!(matches!(
            challenge.accept(packet(&vec![0; length], &mut preparation, &mut kata), &kata),
            Err(ReceiverEnrollmentError::InvalidFrame)
        ));
    }
}

#[test]
fn enrolled_receiver_rejects_other_nonce_grant_roots_and_scope() {
    let fixture = Fixture::new();
    let gate = fixture.gate();
    let (mut preparation, mut kata) = crate::startup::test_pair();
    let challenge = ReceiverChallenge::new(&kata, grant_digest(&fixture)).unwrap();
    let response = gate
        .receiver_enrollment(
            packet(&challenge.encode(), &mut kata, &mut preparation),
            &preparation,
        )
        .unwrap();
    let pending = challenge
        .accept(packet(&response, &mut preparation, &mut kata), &kata)
        .unwrap();
    let receiver = ReceiverAdmissionVerifier::new(fixture.config(), pending).unwrap();
    let other_gate = fixture.gate();
    let receipt = fixture.receipt_wire(&other_gate);
    assert!(receiver
        .verify_bundle(&fixture.grant_wire, &fixture.aggregate_wire, &receipt)
        .is_err());
    assert!(matches!(
        receiver.take_verified(),
        Err(GuestAdmissionError::NotReady)
    ));
    let correct = fixture.receipt_wire(&gate);
    assert_eq!(
        receiver.verify_bundle(&fixture.grant_wire, &fixture.aggregate_wire, &correct),
        Ok(AdmissionCheck::FirstVerified)
    );
    let mut wrong = correct;
    wrong.push(b' ');
    assert_eq!(
        receiver.verify_bundle(&fixture.grant_wire, &fixture.aggregate_wire, &wrong),
        Err(GuestAdmissionError::Conflict)
    );
}

#[test]
fn receiver_configuration_stays_independent_of_authenticated_enrollment() {
    for case in ["grant", "authority", "aggregate", "scope"] {
        let fixture = Fixture::new();
        let gate = fixture.gate();
        let (mut preparation, mut kata) = crate::startup::test_pair();
        let challenge = ReceiverChallenge::new(&kata, grant_digest(&fixture)).unwrap();
        let response = gate
            .receiver_enrollment(
                packet(&challenge.encode(), &mut kata, &mut preparation),
                &preparation,
            )
            .unwrap();
        let pending = challenge
            .accept(packet(&response, &mut preparation, &mut kata), &kata)
            .unwrap();
        let mut config = fixture.config();
        match case {
            "grant" => {
                config.expected_grant.grant_id = "different-grant".into();
                config.aggregate.expected.grant_sha384 =
                    config.expected_grant.digest_sha384().unwrap();
            }
            "authority" => config.grant.authority_public_key = [0; 32],
            "aggregate" => {
                config.aggregate.kbs_proof_public_key = config.grant.authority_public_key
            }
            _ => config.grant.image_policy_sha384 = "ab".repeat(48),
        }
        assert!(
            ReceiverAdmissionVerifier::new(config, pending).is_err(),
            "{case}"
        );
    }
}

#[test]
fn enrollment_rejects_forged_packet_provenance_zero_nonce_and_descriptor() {
    use crate::fd_transport::{FdExpectation, SendOutcome};
    use std::os::fd::AsFd;
    for case in ["other-channel", "zero-nonce", "descriptor"] {
        let fixture = Fixture::new();
        let gate = fixture.gate();
        let (mut preparation, mut kata) = crate::startup::test_pair();
        let challenge = ReceiverChallenge::new(&kata, grant_digest(&fixture)).unwrap();
        let mut response = gate
            .receiver_enrollment(
                packet(&challenge.encode(), &mut kata, &mut preparation),
                &preparation,
            )
            .unwrap();
        let (incoming, expected_error) = match case {
            "other-channel" => {
                let (mut other_preparation, mut other_kata) = crate::startup::test_pair();
                (
                    packet(&response, &mut other_preparation, &mut other_kata),
                    ReceiverEnrollmentError::StartupBinding,
                )
            }
            "zero-nonce" => {
                response[48..80].fill(0);
                (
                    packet(&response, &mut preparation, &mut kata),
                    ReceiverEnrollmentError::InvalidFrame,
                )
            }
            _ => {
                let extra = std::fs::File::open("/dev/null").unwrap();
                assert_eq!(
                    preparation.try_send(&response, Some(extra.as_fd())),
                    Ok(SendOutcome::Sent)
                );
                (
                    kata.try_receive_bound(FdExpectation::One).unwrap().unwrap(),
                    ReceiverEnrollmentError::InvalidFrame,
                )
            }
        };
        assert!(
            matches!(challenge.accept(incoming, &kata), Err(error) if error == expected_error),
            "{case}"
        );
    }
}
