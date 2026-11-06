use super::*;

fn draft(nonce: u8) -> RootfsOfferDraft {
    RootfsOfferDraft::from_context_fields(
        &"11".repeat(48),
        &"22".repeat(48),
        BackingDescriptor {
            sha384: [0x33; 48],
            byte_len: 8192,
        },
        [0x22; 48],
        16384,
        [nonce; 32],
    )
    .unwrap()
}

fn receiver() -> ReceiverTransfer {
    ReceiverTransfer::new([0x11; 48], [0x22; 48], 16384).unwrap()
}

#[test]
fn canonical_offer_roundtrip_preserves_every_binding_and_fixed_profile() {
    let offer = draft(7);
    let encoded = offer.encode();
    assert_eq!(encoded.len(), OFFER_WIRE_BYTES);
    assert_eq!(RootfsOfferDraft::decode(&encoded, 16384).unwrap(), offer);
    assert_eq!(offer.context_sha384(), &[0x11; 48]);
    assert_eq!(offer.transfer_nonce(), &[7; 32]);
    assert_eq!(offer.backing().sha384, [0x33; 48]);
    assert_eq!(offer.backing().byte_len, 8192);
    assert_eq!(offer.candidate_spec_sha384(), &[0x22; 48]);
    assert_eq!(offer.backing_adapter(), "private-ro-ramfs-v1");
    assert_eq!(
        offer.image_profile(),
        "erofs-utils-1.8.10/4096/extended/plain/single-device/v1"
    );
    assert_ne!(offer.commitment(), draft(8).commitment());
    for index in [16, 64, 96, 151, 152] {
        let mut altered = encoded;
        altered[index] ^= 1;
        let altered = RootfsOfferDraft::decode(&altered, 16384).unwrap();
        assert_ne!(offer.commitment(), altered.commitment());
    }
}

#[test]
fn offer_parser_rejects_noncanonical_frames_and_limits() {
    let encoded = draft(7).encode();
    for length in 0..OFFER_WIRE_BYTES {
        assert_eq!(
            RootfsOfferDraft::decode(&encoded[..length], 16384),
            Err(OfferError::InvalidFrame)
        );
    }
    let mut extra = encoded.to_vec();
    extra.push(0);
    assert_eq!(
        RootfsOfferDraft::decode(&extra, 16384),
        Err(OfferError::InvalidFrame)
    );
    for (index, expected) in [
        (0, OfferError::InvalidFrame),
        (8, OfferError::UnsupportedVersion),
        (10, OfferError::UnsupportedPurpose),
        (11, OfferError::UnsupportedProfile),
        (12, OfferError::InvalidFrame),
        (15, OfferError::InvalidFrame),
    ] {
        let mut altered = encoded;
        altered[index] ^= 1;
        assert_eq!(RootfsOfferDraft::decode(&altered, 16384), Err(expected));
    }
    for limit in [0, u64::MAX] {
        assert_eq!(
            RootfsOfferDraft::decode(&encoded, limit),
            Err(OfferError::InvalidLimit)
        );
        assert!(matches!(
            ReceiverTransfer::new([1; 48], [2; 48], limit),
            Err(OfferError::InvalidLimit)
        ));
    }
    assert_eq!(
        RootfsOfferDraft::decode(&encoded, 8191),
        Err(OfferError::BackingTooLarge)
    );
    let mut altered = encoded;
    altered[144..152].fill(0);
    assert_eq!(
        RootfsOfferDraft::decode(&altered, 16384),
        Err(OfferError::EmptyBacking)
    );
    altered = encoded;
    altered[64..96].fill(0);
    assert_eq!(
        RootfsOfferDraft::decode(&altered, 16384),
        Err(OfferError::InvalidNonce)
    );
}

#[test]
fn new_draft_requires_canonical_context_and_admission_pinned_candidate() {
    let backing = draft(7).backing();
    for malformed in ["ab".repeat(47), "AB".repeat(48), "zz".repeat(48)] {
        assert_eq!(
            RootfsOfferDraft::from_context_fields(
                &malformed,
                &"22".repeat(48),
                backing,
                [0x22; 48],
                16384,
                [7; 32],
            ),
            Err(OfferError::InvalidContextDigest)
        );
        assert_eq!(
            RootfsOfferDraft::from_context_fields(
                &"11".repeat(48),
                &malformed,
                backing,
                [0x22; 48],
                16384,
                [7; 32],
            ),
            Err(OfferError::InvalidContextDigest)
        );
    }
    assert_eq!(
        RootfsOfferDraft::from_context_fields(
            &"11".repeat(48),
            &"22".repeat(48),
            backing,
            [0x23; 48],
            16384,
            [7; 32],
        ),
        Err(OfferError::BindingMismatch)
    );
    let one = fresh_nonce().unwrap();
    let two = fresh_nonce().unwrap();
    assert_ne!(one, [0; 32]);
    assert_ne!(two, [0; 32]);
    assert_ne!(one, two);
}

#[test]
fn exact_receipt_is_historical_and_cannot_mean_validated_custody() {
    let offer = draft(7);
    let mut sender = SenderTransfer::new(offer.clone());
    let mut receiver = receiver();
    assert_eq!(sender.status(), SenderStatus::Ready);
    assert_eq!(receiver.status(), ReceiverStatus::Pending);
    assert_eq!(receiver.receipt(), Err(OfferError::NotReceived));
    assert_eq!(sender.mark_sent(), Ok(OfferProgress::First));
    assert_eq!(sender.mark_sent(), Ok(OfferProgress::Historical));
    assert_eq!(receiver.receive(offer.clone()), Ok(OfferProgress::First));
    let receipt = receiver.receipt().unwrap();
    let wire = receipt.encode();
    assert_eq!(wire.len(), RECEIPT_WIRE_BYTES);
    assert_eq!(OfferReceipt::decode(&wire), Ok(receipt.clone()));
    assert_ne!(receipt.commitment(), offer.commitment());
    assert_eq!(sender.accept_receipt(&receipt), Ok(OfferProgress::First));
    assert_eq!(sender.status(), SenderStatus::EnvelopeReceived);
    assert_eq!(receiver.status(), ReceiverStatus::EnvelopeReceived);
    assert_eq!(receiver.receive(offer), Ok(OfferProgress::Historical));
    assert_eq!(receiver.receipt(), Ok(receipt.clone()));
    assert_eq!(
        sender.accept_receipt(&receipt),
        Ok(OfferProgress::Historical)
    );
    assert_eq!(sender.mark_sent(), Ok(OfferProgress::Historical));
}

#[test]
fn receipt_parser_requires_disjoint_purpose_and_canonical_length() {
    let receipt = OfferReceipt::for_offer(&draft(7));
    let encoded = receipt.encode();
    for length in 0..RECEIPT_WIRE_BYTES {
        assert_eq!(
            OfferReceipt::decode(&encoded[..length]),
            Err(OfferError::InvalidFrame)
        );
    }
    let mut extra = encoded.to_vec();
    extra.push(0);
    assert_eq!(OfferReceipt::decode(&extra), Err(OfferError::InvalidFrame));
    for (index, expected) in [
        (0, OfferError::InvalidFrame),
        (8, OfferError::UnsupportedVersion),
        (10, OfferError::UnsupportedPurpose),
        (11, OfferError::UnsupportedProfile),
        (12, OfferError::InvalidFrame),
    ] {
        let mut altered = encoded;
        altered[index] ^= 1;
        assert_eq!(OfferReceipt::decode(&altered), Err(expected));
    }
    let mut altered = encoded;
    altered[16..48].fill(0);
    assert_eq!(
        OfferReceipt::decode(&altered),
        Err(OfferError::InvalidNonce)
    );
    assert_eq!(
        RootfsOfferDraft::decode(&encoded, 16384),
        Err(OfferError::InvalidFrame)
    );
    assert_eq!(
        OfferReceipt::decode(&draft(7).encode()),
        Err(OfferError::InvalidFrame)
    );
}

#[test]
fn wrong_receipt_nonce_or_hash_is_terminal_even_after_prior_receipt() {
    for initially_received in [false, true] {
        for index in [16, 48, 95] {
            let offer = draft(7);
            let good = OfferReceipt::for_offer(&offer);
            let mut sender = SenderTransfer::new(offer);
            sender.mark_sent().unwrap();
            if initially_received {
                sender.accept_receipt(&good).unwrap();
            }
            let mut wrong = good.encode();
            wrong[index] ^= 1;
            let wrong = OfferReceipt::decode(&wrong).unwrap();
            assert_eq!(sender.accept_receipt(&wrong), Err(OfferError::Conflict));
            assert_eq!(sender.status(), SenderStatus::Unknown);
            assert_eq!(sender.accept_receipt(&good), Err(OfferError::Terminal));
            assert_eq!(sender.mark_sent(), Err(OfferError::Terminal));
        }
    }
    let offer = draft(7);
    let receipt = OfferReceipt::for_offer(&offer);
    let mut sender = SenderTransfer::new(offer);
    assert_eq!(sender.accept_receipt(&receipt), Err(OfferError::NotSent));
    assert_eq!(sender.status(), SenderStatus::Aborted);
    assert_eq!(sender.mark_sent(), Err(OfferError::Terminal));
}

#[test]
fn receiver_rejects_wrong_expectations_conflicts_and_oversize_without_recovery() {
    for index in [16, 152] {
        let mut bytes = draft(7).encode();
        bytes[index] ^= 1;
        let wrong = RootfsOfferDraft::decode(&bytes, 16384).unwrap();
        let mut receiver = receiver();
        assert_eq!(receiver.receive(wrong), Err(OfferError::BindingMismatch));
        assert_eq!(receiver.status(), ReceiverStatus::Aborted);
        assert_eq!(receiver.receipt(), Err(OfferError::Terminal));
        assert_eq!(receiver.receive(draft(7)), Err(OfferError::Terminal));
    }
    for index in [64, 96, 151] {
        let offer = draft(7);
        let mut bytes = offer.encode();
        bytes[index] ^= 1;
        let wrong = RootfsOfferDraft::decode(&bytes, 16384).unwrap();
        let mut receiver = receiver();
        receiver.receive(offer.clone()).unwrap();
        assert_eq!(receiver.receive(wrong), Err(OfferError::Conflict));
        assert_eq!(receiver.receive(offer), Err(OfferError::Terminal));
        assert_eq!(receiver.receipt(), Err(OfferError::Terminal));
    }
    let mut receiver = ReceiverTransfer::new([0x11; 48], [0x22; 48], 8191).unwrap();
    assert_eq!(receiver.receive(draft(7)), Err(OfferError::BackingTooLarge));
    assert_eq!(receiver.status(), ReceiverStatus::Aborted);
    assert_eq!(receiver.receive(draft(7)), Err(OfferError::Terminal));
}

#[test]
fn abort_retains_terminal_tombstones_and_after_send_never_claims_peer_rollback() {
    for sent in [false, true] {
        for received in [false, true] {
            if received && !sent {
                continue;
            }
            let offer = draft(7);
            let receipt = OfferReceipt::for_offer(&offer);
            let mut sender = SenderTransfer::new(offer);
            if sent {
                sender.mark_sent().unwrap();
            }
            if received {
                sender.accept_receipt(&receipt).unwrap();
            }
            sender.abort();
            sender.abort();
            assert_eq!(
                sender.status(),
                if sent {
                    SenderStatus::Unknown
                } else {
                    SenderStatus::Aborted
                }
            );
            assert_eq!(sender.accept_receipt(&receipt), Err(OfferError::Terminal));
            assert_eq!(sender.mark_sent(), Err(OfferError::Terminal));
        }
    }
    for received in [false, true] {
        let mut receiver = receiver();
        if received {
            receiver.receive(draft(7)).unwrap();
        }
        receiver.abort();
        receiver.abort();
        assert_eq!(receiver.status(), ReceiverStatus::Aborted);
        assert_eq!(receiver.receipt(), Err(OfferError::Terminal));
        assert_eq!(receiver.receive(draft(7)), Err(OfferError::Terminal));
    }
}
