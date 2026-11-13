use super::*;

const LIMIT: usize = MAX_PROVENANCE_BYTES;

fn offer() -> RootfsOfferDraft {
    let mut wire = [0; OFFER_WIRE_BYTES];
    wire[..8].copy_from_slice(b"ONB17OFR");
    wire[8..10].copy_from_slice(&1u16.to_be_bytes());
    wire[10] = 1;
    wire[11] = 1;
    wire[16..64].copy_from_slice(&[1; 48]);
    wire[64..96].copy_from_slice(&[2; 32]);
    wire[96..144].copy_from_slice(&[3; 48]);
    wire[144..152].copy_from_slice(&8192u64.to_be_bytes());
    wire[152..200].copy_from_slice(&[4; 48]);
    // This deliberately decodes non-authorizing data, not an admission or view.
    RootfsOfferDraft::decode(&wire, 1 << 20).unwrap()
}

fn provenance(count: usize) -> PreparationProvenance {
    PreparationProvenance {
        context_sha384: "01".repeat(48),
        manifest_sha256: "11".repeat(32),
        config_sha256: "12".repeat(32),
        credential_delivery_sha384: "13".repeat(48),
        signature: SignatureProvenance {
            policy_sha384: "21".repeat(48),
            key_sha384: "22".repeat(48),
            payload_sha384: "23".repeat(48),
            signature_sha384: "24".repeat(48),
            repository_sha384: "25".repeat(48),
        },
        kms_key_version:
            "projects/test/locations/global/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1"
                .into(),
        layers: (0..count)
            .map(|index| LayerProvenance {
                original_index: index as u32,
                blob_sha256: "31".repeat(32),
                descriptor_size: 4096,
                plaintext_sha256: "32".repeat(32),
                diff_id: format!("sha256:{}", "33".repeat(32)),
                tar_sha384: "34".repeat(48),
                tar_bytes: 2048,
                tar_entries: 1,
                packet_ordinal: 0,
                packet_sha384: "35".repeat(48),
                kms_ciphertext_sha384: "36".repeat(48),
            })
            .collect(),
        builder: BuilderProvenance {
            tool_sha384: "41".repeat(48),
            input_tar_sha384: "42".repeat(48),
            image_sha384: "03".repeat(48),
            image_bytes: 8192,
            inodes: 2,
        },
        candidate_spec_sha384: "04".repeat(48),
    }
}

fn announcement() -> CustodyAnnouncement {
    let provenance = provenance(2);
    let bytes = provenance.encode(LIMIT).unwrap();
    CustodyAnnouncement {
        offer: offer(),
        provenance_sha384: hash(&bytes),
        provenance_bytes: bytes.len() as u64,
    }
}

fn validated(announcement: &CustodyAnnouncement) -> ValidatedReceipt {
    ValidatedReceipt {
        announcement_sha384: announcement.commitment().unwrap(),
        provenance_sha384: announcement.provenance_sha384,
        image_sha384: announcement.offer.backing().sha384,
        candidate_spec_sha384: *announcement.offer.candidate_spec_sha384(),
        executable_sha384: [6; 48],
        startup_binding_sha384: [8; 48],
        receiver_nonce: [7; 32],
        mount_id: 99,
        inodes: 2,
    }
}

fn committed(announcement: &CustodyAnnouncement) -> (ValidatedReceipt, PCommit) {
    let receipt = validated(announcement);
    let mut producer = ProducerTransaction::new(announcement.clone()).unwrap();
    let (commit, progress) = producer.validated(&receipt).unwrap();
    assert_eq!(progress, CustodyProgress::First);
    (receipt, commit)
}

#[test]
fn public_admission_bundle_and_descriptor_are_bounded_and_canonical() {
    let bundle = AdmissionBundle {
        grant: br#"{"signed":"grant"}"#.to_vec(),
        aggregate: br#"{"signed":"aggregate"}"#.to_vec(),
        receipt: br#"{"signed":"receipt"}"#.to_vec(),
    };
    let bytes = bundle.encode(LIMIT).unwrap();
    assert_eq!(AdmissionBundle::decode(&bytes, LIMIT), Ok(bundle.clone()));
    assert_eq!(bundle.sha384(LIMIT), Ok(hash(&bytes)));
    let descriptor = AdmissionDescriptor {
        sha384: hash(&bytes),
        byte_len: bytes.len() as u64,
    };
    let wire = descriptor.encode().unwrap();
    assert_eq!(wire.len(), ADMISSION_DESCRIPTOR_WIRE_BYTES);
    assert_eq!(AdmissionDescriptor::decode(&wire), Ok(descriptor.clone()));
    for case in 0..4 {
        let mut bad = bundle.clone();
        match case {
            0 => bad.grant.clear(),
            1 => bad.aggregate = vec![0; execution_proof_contract::MAX_WIRE_BYTES + 1],
            2 => bad.receipt.clear(),
            _ => bad.receipt = vec![0; execution_proof_contract::MAX_WIRE_BYTES + 1],
        }
        assert!(bad.encode(LIMIT).is_err());
    }
    let mut oversized = bundle.clone();
    oversized.grant = vec![1; execution_proof_contract::MAX_WIRE_BYTES + 1];
    let raw = serde_json::to_vec(&Envelope {
        version: VERSION,
        purpose: ADMISSION_PURPOSE.to_owned(),
        image_profile: IMAGE_PROFILE.to_owned(),
        backing_adapter: BACKING_ADAPTER.to_owned(),
        body: oversized,
    })
    .unwrap();
    assert_eq!(
        AdmissionBundle::decode(&raw, LIMIT),
        Err(CustodyError::InvalidRecord)
    );
    for limit in [0, LIMIT + 1] {
        assert_eq!(bundle.encode(limit), Err(CustodyError::InvalidLimit));
        assert_eq!(
            AdmissionBundle::decode(&bytes, limit),
            Err(CustodyError::InvalidLimit)
        );
    }
    assert_eq!(
        AdmissionBundle::decode(&bytes, bytes.len() - 1),
        Err(CustodyError::TooLarge)
    );
    let mut spaced = bytes.clone();
    spaced.push(b' ');
    assert_eq!(
        AdmissionBundle::decode(&spaced, LIMIT),
        Err(CustodyError::NonCanonical)
    );
    let mut invalid = descriptor.clone();
    invalid.byte_len = 0;
    assert!(invalid.encode().is_err());
    invalid.byte_len = LIMIT as u64 + 1;
    assert!(invalid.encode().is_err());
    for offset in [0, 8, 10, 11, 12, 15] {
        let mut altered = wire.clone();
        altered[offset] ^= 0x80;
        assert!(AdmissionDescriptor::decode(&altered).is_err());
    }
    for len in 0..wire.len() {
        assert!(AdmissionDescriptor::decode(&wire[..len]).is_err());
    }
    let mut extra = wire;
    extra.push(0);
    assert!(AdmissionDescriptor::decode(&extra).is_err());
}

#[test]
fn provenance_roundtrip_preserves_all_original_duplicate_layer_occurrences() {
    for count in [1, 2, 32] {
        let record = provenance(count);
        let bytes = record.encode(LIMIT).unwrap();
        assert_eq!(
            PreparationProvenance::decode(&bytes, LIMIT),
            Ok(record.clone())
        );
        assert_eq!(record.sha384(LIMIT), Ok(hash(&bytes)));
        assert_eq!(record.layers.len(), count);
        for (index, layer) in record.layers.iter().enumerate() {
            assert_eq!(layer.original_index, index as u32);
            assert_eq!(layer.blob_sha256, "31".repeat(32));
        }
        if count == 32 {
            assert!(bytes.len() > 4096); // Metadata is sent in its own sealed FD.
        }
    }
    let mut record = provenance(2);
    record.layers.swap(0, 1);
    assert_eq!(record.encode(LIMIT), Err(CustodyError::InvalidRecord));
    record.layers[0].original_index = 0;
    record.layers[1].original_index = 1;
    record.layers[1].tar_sha384 = "37".repeat(48);
    let original = record.sha384(LIMIT).unwrap();
    record.layers[1].packet_ordinal += 1;
    assert_ne!(record.sha384(LIMIT).unwrap(), original);
}

#[test]
fn provenance_decoder_requires_canonical_purpose_tagged_bounded_json() {
    let record = provenance(2);
    let bytes = record.encode(LIMIT).unwrap();
    for limit in [0, LIMIT + 1] {
        assert_eq!(record.encode(limit), Err(CustodyError::InvalidLimit));
        assert_eq!(
            PreparationProvenance::decode(&bytes, limit),
            Err(CustodyError::InvalidLimit)
        );
    }
    assert_eq!(record.encode(bytes.len() - 1), Err(CustodyError::TooLarge));
    assert_eq!(
        PreparationProvenance::decode(&bytes, bytes.len() - 1),
        Err(CustodyError::TooLarge)
    );
    for altered in [
        [b" ".as_slice(), &bytes].concat(),
        [&bytes, b"\n".as_slice()].concat(),
    ] {
        assert_eq!(
            PreparationProvenance::decode(&altered, LIMIT),
            Err(CustodyError::NonCanonical)
        );
    }
    let text = std::str::from_utf8(&bytes).unwrap();
    for altered in [
        text.replacen("\"version\":1", "\"version\":1,\"version\":1", 1),
        text.replacen("\"version\":1", "\"version\":2", 1),
        text.replacen(PROVENANCE_PURPOSE, RECORD_PURPOSE, 1),
        text.replacen(IMAGE_PROFILE, "untrusted-profile", 1),
        text.replacen(BACKING_ADAPTER, "untrusted-adapter", 1),
        text.replacen("\"body\":{", "\"body\":{\"credential\":\"secret\",", 1),
        text.replacen("\"original_index\":0", "\"original_index\":0.0", 1),
    ] {
        assert!(PreparationProvenance::decode(altered.as_bytes(), LIMIT).is_err());
    }
}

#[test]
fn provenance_rejects_invalid_fields_and_excess_layers_without_deduplication() {
    for case in 0..14 {
        let mut record = provenance(2);
        match case {
            0 => record.context_sha384 = "AA".repeat(48),
            1 => {
                record.manifest_sha256.pop();
            }
            2 => record.layers[0].blob_sha256 = "gg".repeat(32),
            3 => record.layers[0].diff_id = "33".repeat(32),
            4 => record.layers[1].original_index = 0,
            5 => record.layers.clear(),
            6 => record.kms_key_version = "x".repeat(1025),
            7 => record.kms_key_version.push('\n'),
            8 => record.builder.image_bytes = 0,
            9 => record.builder.inodes = u64::MAX,
            10 => record.layers[0].descriptor_size = 0,
            11 => record.layers[0].tar_bytes = u64::MAX,
            12 => record.layers[0].tar_entries = u64::MAX,
            _ => record.signature.payload_sha384.clear(),
        }
        assert!(record.encode(LIMIT).is_err(), "case{case}");
    }
    let record = provenance(33);
    assert_eq!(record.encode(LIMIT), Err(CustodyError::InvalidRecord));
    // Bypass the checked encoder to exercise the independent decode layer cap.
    let raw = serde_json::to_vec(&Envelope {
        version: VERSION,
        purpose: PROVENANCE_PURPOSE.to_owned(),
        image_profile: IMAGE_PROFILE.to_owned(),
        backing_adapter: BACKING_ADAPTER.to_owned(),
        body: record,
    })
    .unwrap();
    assert!(PreparationProvenance::decode(&raw, LIMIT).is_err());
}

#[test]
fn provenance_must_match_announcement_and_the_entire_sealed_metadata_digest() {
    let announcement = announcement();
    let record = provenance(2);
    record.validate_for(&announcement).unwrap();
    for case in 0..6 {
        let mut altered = record.clone();
        match case {
            0 => altered.context_sha384 = "05".repeat(48),
            1 => altered.candidate_spec_sha384 = "05".repeat(48),
            2 => altered.builder.image_sha384 = "05".repeat(48),
            3 => altered.builder.image_bytes += 1,
            4 => altered.signature.signature_sha384 = "05".repeat(48),
            _ => altered.layers[1].kms_ciphertext_sha384 = "05".repeat(48),
        }
        assert_eq!(
            altered.validate_for(&announcement),
            Err(CustodyError::BindingMismatch)
        );
    }
    let mut wrong_size = announcement.clone();
    wrong_size.provenance_bytes += 1;
    assert_eq!(
        record.validate_for(&wrong_size),
        Err(CustodyError::BindingMismatch)
    );
}

#[test]
fn all_control_frames_have_fixed_disjoint_framing_and_exact_roundtrips() {
    let announcement = announcement();
    let descriptor = ProvenanceDescriptor::for_announcement(&announcement).unwrap();
    let (receipt, commit) = committed(&announcement);
    let ack = FinalizedAck::for_commit(&announcement, &commit).unwrap();
    let admission = AdmissionDescriptor {
        sha384: [9; 48],
        byte_len: 100,
    };
    let frames = [
        (announcement.encode().unwrap(), ANNOUNCEMENT_WIRE_BYTES),
        (
            descriptor.encode().unwrap(),
            PROVENANCE_DESCRIPTOR_WIRE_BYTES,
        ),
        (receipt.encode().unwrap(), VALIDATED_RECEIPT_WIRE_BYTES),
        (commit.encode().unwrap(), P_COMMIT_WIRE_BYTES),
        (ack.encode().unwrap(), FINALIZED_ACK_WIRE_BYTES),
        (admission.encode().unwrap(), ADMISSION_DESCRIPTOR_WIRE_BYTES),
    ];
    assert_eq!(
        CustodyAnnouncement::decode(&frames[0].0, 1 << 20, LIMIT),
        Ok(announcement)
    );
    assert_eq!(ProvenanceDescriptor::decode(&frames[1].0), Ok(descriptor));
    assert_eq!(ValidatedReceipt::decode(&frames[2].0), Ok(receipt));
    assert_eq!(PCommit::decode(&frames[3].0), Ok(commit));
    assert_eq!(FinalizedAck::decode(&frames[4].0), Ok(ack));
    assert_eq!(AdmissionDescriptor::decode(&frames[5].0), Ok(admission));
    for (bytes, expected) in &frames {
        assert_eq!(bytes.len(), *expected);
        assert!(bytes.len() <= 4096);
    }
    for (index, (bytes, _)) in frames.iter().enumerate() {
        let rejects = |value: &[u8]| match index {
            0 => CustodyAnnouncement::decode(value, 1 << 20, LIMIT).is_err(),
            1 => ProvenanceDescriptor::decode(value).is_err(),
            2 => ValidatedReceipt::decode(value).is_err(),
            3 => PCommit::decode(value).is_err(),
            4 => FinalizedAck::decode(value).is_err(),
            _ => AdmissionDescriptor::decode(value).is_err(),
        };
        for length in 0..bytes.len() {
            assert!(rejects(&bytes[..length]));
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(rejects(&extra));
        for offset in [0, 8, 10, 11, 12, 15] {
            let mut altered = bytes.clone();
            altered[offset] ^= 0x80;
            assert!(rejects(&altered));
        }
        for (other, _) in &frames {
            if other != bytes {
                assert!(rejects(other));
            }
        }
    }
}

#[test]
fn descriptor_and_receipt_require_exact_announcement_and_positive_view_identity() {
    let announcement = announcement();
    let descriptor = ProvenanceDescriptor::for_announcement(&announcement).unwrap();
    descriptor.validate_for(&announcement).unwrap();
    for case in 0..3 {
        let mut altered = descriptor.clone();
        match case {
            0 => altered.announcement_sha384[0] ^= 1,
            1 => altered.provenance_sha384[0] ^= 1,
            _ => altered.provenance_bytes += 1,
        }
        assert_eq!(
            altered.validate_for(&announcement),
            Err(CustodyError::BindingMismatch)
        );
    }
    let receipt = validated(&announcement);
    receipt.validate_for(&announcement).unwrap();
    for case in 0..7 {
        let mut altered = receipt.clone();
        match case {
            0 => altered.announcement_sha384[0] ^= 1,
            1 => altered.provenance_sha384[0] ^= 1,
            2 => altered.image_sha384[0] ^= 1,
            3 => altered.candidate_spec_sha384[0] ^= 1,
            4 => altered.receiver_nonce = [0; 32],
            5 => altered.mount_id = 0,
            _ => altered.inodes = 0,
        }
        assert!(altered.validate_for(&announcement).is_err());
    }
    let mut oversized = announcement.clone();
    oversized.provenance_bytes = LIMIT as u64 + 1;
    assert!(oversized.encode().is_err());
    let bytes = announcement.encode().unwrap();
    assert_eq!(
        CustodyAnnouncement::decode(&bytes, 1 << 20, announcement.provenance_bytes as usize - 1),
        Err(CustodyError::TooLarge)
    );
    assert!(CustodyAnnouncement::decode(&bytes, 8191, LIMIT).is_err());
}

#[test]
fn producer_lost_response_retries_return_same_p_commit_and_finalized_status() {
    let announcement = announcement();
    let receipt = validated(&announcement);
    let mut producer = ProducerTransaction::new(announcement.clone()).unwrap();
    assert_eq!(producer.status(), ProducerStatus::AwaitingValidation);
    assert!(producer.committed().is_none());
    let (commit, progress) = producer.validated(&receipt).unwrap();
    assert_eq!(progress, CustodyProgress::First);
    assert_eq!(producer.status(), ProducerStatus::Committed);
    assert_eq!(producer.committed(), Some(&commit));
    commit.validate_for(&announcement, &receipt).unwrap();
    assert_eq!(
        producer.validated(&receipt),
        Ok((commit.clone(), CustodyProgress::Historical))
    );
    let ack = FinalizedAck::for_commit(&announcement, &commit).unwrap();
    assert_eq!(producer.finalized(&ack), Ok(CustodyProgress::First));
    assert_eq!(producer.finalized(&ack), Ok(CustodyProgress::Historical));
    assert_eq!(producer.status(), ProducerStatus::Finalized);
    assert_eq!(
        producer.validated(&receipt),
        Ok((commit, CustodyProgress::Historical))
    );
}

#[test]
fn producer_conflict_abort_and_unknown_states_never_resurrect_or_reissue_commit() {
    let announcement = announcement();
    let receipt = validated(&announcement);
    let mut aborted = ProducerTransaction::new(announcement.clone()).unwrap();
    aborted.abort();
    assert_eq!(aborted.status(), ProducerStatus::Aborted);
    assert_eq!(aborted.validated(&receipt), Err(CustodyError::Terminal));
    let mut producer = ProducerTransaction::new(announcement.clone()).unwrap();
    let (commit, _) = producer.validated(&receipt).unwrap();
    producer.abort();
    assert_eq!(producer.status(), ProducerStatus::Unknown);
    assert!(producer.committed().is_none());
    assert_eq!(producer.validated(&receipt), Err(CustodyError::Terminal));
    assert_eq!(
        producer.finalized(&FinalizedAck::for_commit(&announcement, &commit).unwrap()),
        Err(CustodyError::Terminal)
    );
    for after_commit in [false, true] {
        let mut producer = ProducerTransaction::new(announcement.clone()).unwrap();
        if after_commit {
            producer.validated(&receipt).unwrap();
        }
        let mut wrong = receipt.clone();
        if after_commit {
            wrong.receiver_nonce[0] ^= 1;
        } else {
            wrong.image_sha384[0] ^= 1;
        }
        assert!(producer.validated(&wrong).is_err());
        assert_eq!(producer.status(), ProducerStatus::Unknown);
        assert_eq!(producer.validated(&receipt), Err(CustodyError::Terminal));
    }
    let mut producer = ProducerTransaction::new(announcement.clone()).unwrap();
    let mut ack = FinalizedAck::for_commit(&announcement, &commit).unwrap();
    assert_eq!(producer.finalized(&ack), Err(CustodyError::NotCommitted));
    assert_eq!(producer.status(), ProducerStatus::Aborted);
    let mut producer = ProducerTransaction::new(announcement).unwrap();
    producer.validated(&receipt).unwrap();
    ack.record_sha384[0] ^= 1;
    assert_eq!(producer.finalized(&ack), Err(CustodyError::Conflict));
    assert_eq!(producer.status(), ProducerStatus::Unknown);
}

#[test]
fn p_record_is_canonical_self_consistent_and_binds_all_receiver_observations() {
    let announcement = announcement();
    let (receipt, commit) = committed(&announcement);
    let bytes = commit.record.encode(LIMIT).unwrap();
    assert_eq!(
        PreparationRecord::decode(&bytes, LIMIT),
        Ok(commit.record.clone())
    );
    assert_eq!(commit.record_sha384, hash(&bytes));
    let mut wrong_hash = commit.clone();
    wrong_hash.record_sha384[0] ^= 1;
    assert!(wrong_hash.encode().is_err());
    let mut changed_wire = commit.encode().unwrap();
    changed_wire[208] ^= 1;
    assert_eq!(
        PCommit::decode(&changed_wire),
        Err(CustodyError::BindingMismatch)
    );
    for case in 0..5 {
        let mut altered = receipt.clone();
        match case {
            0 => altered.executable_sha384[0] ^= 1,
            1 => altered.receiver_nonce[0] ^= 1,
            2 => altered.mount_id += 1,
            3 => altered.inodes += 1,
            _ => altered.startup_binding_sha384[0] ^= 1,
        }
        assert_eq!(
            commit.validate_for(&announcement, &altered),
            Err(CustodyError::BindingMismatch)
        );
        let mut producer = ProducerTransaction::new(announcement.clone()).unwrap();
        assert_ne!(
            producer.validated(&altered).unwrap().0.record_sha384,
            commit.record_sha384
        );
    }
    let mut spaced = bytes.clone();
    spaced.push(b' ');
    assert_eq!(
        PreparationRecord::decode(&spaced, LIMIT),
        Err(CustodyError::NonCanonical)
    );
    let mut altered = commit.record.clone();
    altered.image_sha384 = "aa".repeat(48);
    let forged = PCommit {
        record_sha384: altered.sha384().unwrap(),
        record: altered,
    };
    assert!(FinalizedAck::for_commit(&announcement, &forged).is_err());
}
