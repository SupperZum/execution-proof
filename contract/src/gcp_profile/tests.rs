use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};

fn signer(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}
fn fixture() -> (GcpProducerQualificationV1, GcpQualificationExpectations) {
    let refs = GcpQualificationEvidenceRefs {
        artifact_closure_sha384: "11".repeat(48),
        firmware_causality_sha384: "12".repeat(48),
        producer_isolation_sha384: "13".repeat(48),
        no_state_copy_sha384: "14".repeat(48),
        qualification_review_sha384: "15".repeat(48),
    };
    let expected = GcpQualificationExpectations {
        qualification_public_key: signer(1).public_key().as_ref().try_into().unwrap(),
        issuer: "qualification-authority".into(),
        boot_binding_sha384: "21".repeat(48),
        pe_sha384: "22".repeat(48),
        firmware_mrtd: "23".repeat(48),
        module_policy_sha384: "24".repeat(48),
        evidence_refs: refs.clone(),
    };
    let statement = GcpProducerQualificationV1 {
        version: GCP_QUALIFICATION_VERSION,
        purpose: GCP_QUALIFICATION_PURPOSE.into(),
        profile: GCP_QUALIFICATION_PROFILE.into(),
        claim: GCP_QUALIFICATION_CLAIM.into(),
        qualification_id: "software-fixture-only".into(),
        issuer: expected.issuer.clone(),
        boot_binding_sha384: expected.boot_binding_sha384.clone(),
        pe_sha384: expected.pe_sha384.clone(),
        firmware_mrtd: expected.firmware_mrtd.clone(),
        module_policy_sha384: expected.module_policy_sha384.clone(),
        evidence_refs: refs,
        validity: ValidityWindow {
            not_before: 100,
            expires: 200,
        },
    };
    (statement, expected)
}
fn wire(statement: GcpProducerQualificationV1, seed: u8) -> Vec<u8> {
    let signature = crate::hex(
        signer(seed)
            .sign(&statement.signing_bytes().unwrap())
            .as_ref(),
    );
    serde_json::to_vec(&Signed {
        statement,
        signature,
    })
    .unwrap()
}

#[test]
fn authenticated_qualification_has_exact_external_expectations_and_half_open_window() {
    let (s, e) = fixture();
    let bytes = wire(s.clone(), 1);
    let verified = verify_gcp_qualification(&bytes, &e, 100).unwrap();
    assert_eq!(verified.digest_sha384(), s.digest_sha384().unwrap());
    assert!(verify_gcp_qualification(&bytes, &e, 199).is_ok());
    for now in [99, 200, u64::MAX] {
        assert!(verify_gcp_qualification(&bytes, &e, now).is_err());
    }
    assert!(verify_gcp_qualification_historical(&bytes, &e).is_ok());
    assert!(verify_gcp_qualification_historical(&wire(s, 2), &e).is_err());
}
#[test]
fn every_reference_and_profile_commitment_is_selected_outside_the_statement() {
    let (s, e) = fixture();
    let bytes = wire(s, 1);
    for index in 0..10 {
        let mut changed = e.clone();
        match index {
            0 => changed.issuer = "other".into(),
            1 => changed.boot_binding_sha384 = "31".repeat(48),
            2 => changed.pe_sha384 = "31".repeat(48),
            3 => changed.firmware_mrtd = "31".repeat(48),
            4 => changed.module_policy_sha384 = "31".repeat(48),
            5 => changed.evidence_refs.artifact_closure_sha384 = "31".repeat(48),
            6 => changed.evidence_refs.firmware_causality_sha384 = "31".repeat(48),
            7 => changed.evidence_refs.producer_isolation_sha384 = "31".repeat(48),
            8 => changed.evidence_refs.no_state_copy_sha384 = "31".repeat(48),
            _ => changed.evidence_refs.qualification_review_sha384 = "31".repeat(48),
        }
        assert!(verify_gcp_qualification_historical(&bytes, &changed).is_err());
    }
}
#[test]
fn malformed_unknown_zero_and_weaker_claims_are_rejected() {
    let (s, e) = fixture();
    let bytes = wire(s.clone(), 1);
    for name in ["purpose", "profile", "claim"] {
        let mut v = serde_json::to_value(&s).unwrap();
        v[name] = "weaker".into();
        let changed: GcpProducerQualificationV1 = serde_json::from_value(v).unwrap();
        assert!(changed.signing_bytes().is_err());
    }
    let mut zero = s;
    zero.evidence_refs.no_state_copy_sha384 = "00".repeat(48);
    assert!(zero.signing_bytes().is_err());
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["statement"]["qualified"] = true.into();
    assert!(verify_gcp_qualification_historical(&serde_json::to_vec(&v).unwrap(), &e).is_err());
    let mut selected = e;
    selected.qualification_public_key = [0; 32];
    assert!(verify_gcp_qualification_historical(&bytes, &selected).is_err());
    assert!(
        verify_gcp_qualification_historical(&vec![b' '; crate::MAX_WIRE_BYTES + 1], &selected)
            .is_err()
    );
}
