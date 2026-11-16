//! Synthetic transport fixtures only. No private signing key or actual Q exists.
use super::*;
use execution_proof_contract::{
    gcp_boot_binding::GcpBootBindingV1,
    gcp_bootstrap::{GCP_BOOTSTRAP_BINDING_PURPOSE, GCP_BOOTSTRAP_CHALLENGE_PURPOSE},
    ValidityWindow,
};
use serde_json::json;
use std::{
    os::unix::fs::symlink,
    sync::atomic::{AtomicU64, Ordering},
};

fn boot() -> GcpBootstrapPublication {
    let binding = GcpBootBindingV1::new([1; 48], [2; 48], [3; 48], [4; 48]).unwrap();
    let challenge = GcpBootstrapChallenge {
        version: 3,
        purpose: GCP_BOOTSTRAP_CHALLENGE_PURPOSE.into(),
        audience: "fixture-launch".into(),
        authority: "fixture-authority".into(),
        tenant: "fixture-tenant".into(),
        workload_id: "fixture-workload".into(),
        attempt_id: "fixture-attempt".into(),
        challenge_id: "fixture-challenge".into(),
        nonce_hex: "11".repeat(32),
        intent_sha384: "22".repeat(48),
        boot_binding: binding.clone(),
        validity: ValidityWindow {
            not_before: 1,
            expires: 100,
        },
    };
    let local = GcpBootstrapBinding {
        version: 3,
        purpose: GCP_BOOTSTRAP_BINDING_PURPOSE.into(),
        challenge_sha384: challenge.digest_sha384().unwrap(),
        boot_binding_sha384: binding.digest_sha384().unwrap(),
        boot_id: "fixture-boot".into(),
        boot_nonce_hex: "33".repeat(32),
        recorder_key_sha384: "44".repeat(48),
        keywrap_key_sha384: "55".repeat(48),
    };
    GcpBootstrapPublication {
        signed_challenge: serde_json::to_vec(
            &json!({"statement":challenge,"signature":"66".repeat(64)}),
        )
        .unwrap(),
        challenge,
        binding: local,
        evidence: GcpLaunchEvidenceV2::new(vec![1], vec![2], vec![3]).unwrap(),
        recorder_public_key: [7; 32],
        possession_signature: "88".repeat(64),
    }
}
fn export() -> Vec<u8> {
    serde_json::to_vec(
        &json!({"version":2,"purpose":"qlad.execution-proof.protected-export.v2",
        "record_b64":"AQ==","admission_b64":"Ag==","preparation_b64":"Aw==","provenance_b64":"BA==",
        "announcement_b64":"BQ==","validated_receipt_b64":"Bg==","quote_b64":"Bw=="}),
    )
    .unwrap()
}
fn policy_archive() -> (Vec<u8>, PolicyTranscript) {
    let statement: GcpLaunchPolicyAggregateV2 = serde_json::from_value(json!({
        "version":2,"purpose":"qlad.execution-proof.gcp-kbs-policy-aggregate.v2","audience":"fixture-aggregate",
        "issuer":"fixture-kbs","profile":"onb17.gcp-kbs-combined-policy-only.v2","grant_sha384":"11".repeat(48),
        "authority_key_sha384":"12".repeat(48),"session_id":"13".repeat(32),"nonce":"fixture-nonce",
        "runtime_sha384":"14".repeat(48),"boot_binding_sha384":"15".repeat(48),"evidence_sha384":"16".repeat(48),
        "recorder_key_sha384":"17".repeat(48),"request":{"method":"GET","plugin":"resource",
            "resource_path":["fixture","manual","credential"],"workflow_id":"fixture-workflow","request_nonce":"fixture-request"},
        "as_evaluation":{"policy_id":"fixture-as","policy_sha384":"18".repeat(48),"input_sha384":"19".repeat(48),"data_sha384":null},
        "kbs_evaluation":{"policy_id":"fixture-kbs","policy_sha384":"20".repeat(48),"input_sha384":"21".repeat(48),"data_sha384":"22".repeat(48)}
    })).unwrap();
    let signed =
        serde_json::to_vec(&json!({"statement":statement,"signature":"23".repeat(64)})).unwrap();
    let objects: Vec<_> = [
        "as_policy",
        "as_input",
        "kbs_policy",
        "kbs_input",
        "kbs_data",
    ]
    .iter()
    .map(|kind| {
        let body = serde_json::to_vec(&json!({"fixture":kind})).unwrap();
        json!({"kind":kind,"sha384":hash(&body),"body_b64":STANDARD.encode(body)})
    })
    .collect();
    let receipt = b"{\"fixture_signed_receipt\":true}";
    let archive = serde_json::to_vec(&json!({"version":1,"purpose":"qlad.execution-proof.gcp-original-policy-archive.v1",
        "session_id":statement.session_id,"aggregate_sha384":statement.digest_sha384().unwrap(),
        "signed_aggregate_b64":STANDARD.encode(&signed),"objects":objects,"credential_receipt_b64":STANDARD.encode(receipt)})).unwrap();
    (
        archive,
        PolicyTranscript {
            signed_aggregate: signed,
            begin_response_base64: STANDARD.encode(b"{}"),
            capture_request_base64: String::new(),
            capture_response_base64: STANDARD.encode(b"{}"),
            resource_challenge_response_base64: STANDARD.encode(b"{}"),
            resource_decision_response_base64: STANDARD.encode(b"{}"),
        },
    )
}

#[test]
fn typed_transport_constructor_preserves_original_bytes_without_verdict() {
    let pack = GcpEvidencePackV2::from_protected_export(
        &export(),
        b"fixture receipt".to_vec(),
        vec![],
        boot(),
        b"{}".to_vec(),
    )
    .unwrap();
    assert_eq!(pack.execution.record, [1]);
    assert_eq!(pack.execution.quote, [7]);
    assert_eq!(pack.execution.credential_receipt, b"fixture receipt");
    let encoded = pack.encode().unwrap();
    let decoded = GcpEvidencePackV2::decode(&encoded).unwrap();
    assert_eq!(
        decoded.bootstrap.signed_challenge,
        pack.bootstrap.signed_challenge
    );
    // Typed transport validity is intentionally weaker than graph/hardware proof.
    assert_eq!(decoded.qualification, b"{}");
}
#[test]
fn protected_export_domain_missing_field_and_noncanonical_base64_rejected() {
    let original: serde_json::Value = serde_json::from_slice(&export()).unwrap();
    for mutation in 0..3 {
        let mut value = original.clone();
        match mutation {
            0 => value["version"] = 1.into(),
            1 => {
                value.as_object_mut().unwrap().remove("record_b64");
            }
            _ => value["quote_b64"] = "Bx==".into(),
        }
        assert!(GcpEvidencePackV2::from_protected_export(
            &serde_json::to_vec(&value).unwrap(),
            b"receipt".to_vec(),
            vec![],
            boot(),
            b"{}".to_vec()
        )
        .is_err());
    }
}
#[test]
fn bootstrap_reconstructs_exact_signed_challenge_and_original_possession() {
    let expected = boot();
    let wire = serde_json::to_vec(&json!({"challenge_id":expected.challenge.challenge_id,
        "submission":{"binding":expected.binding,"evidence":expected.evidence,"recorder_public_key":expected.recorder_public_key,
            "possession_signature_hex":expected.possession_signature,"keywrap_public_key":{"kty":"RSA","k_mod":"public"}}})).unwrap();
    let actual = bootstrap(&wire, expected.signed_challenge.clone()).unwrap();
    assert_eq!(actual.signed_challenge, expected.signed_challenge);
    assert_eq!(actual.possession_signature, expected.possession_signature);
    let mut bad: serde_json::Value = serde_json::from_slice(&wire).unwrap();
    bad["challenge_id"] = "other".into();
    assert!(bootstrap(
        &serde_json::to_vec(&bad).unwrap(),
        expected.signed_challenge
    )
    .is_err());
}
#[test]
fn archive_preserves_five_original_objects_and_signed_receipt() {
    let (raw, policy) = policy_archive();
    let mut objects = vec![];
    let receipt = original_archive(&raw, &policy, &mut objects).unwrap();
    assert_eq!(objects.len(), 5);
    assert_eq!(receipt, b"{\"fixture_signed_receipt\":true}");
    for object in objects {
        assert_eq!(hash(&object.bytes), object.sha384);
    }
}
#[test]
fn missing_receipt_jwe_or_other_aggregate_archive_rejected() {
    let (raw, mut policy) = policy_archive();
    let original: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    for mutation in 0..3 {
        let mut value = original.clone();
        match mutation {
            0 => {
                value
                    .as_object_mut()
                    .unwrap()
                    .remove("credential_receipt_b64");
            }
            1 => {
                value["credential_receipt_b64"] = STANDARD
                    .encode(b"{\"jwe_b64\":\"must-not-persist\"}")
                    .into()
            }
            _ => value["aggregate_sha384"] = "ff".repeat(48).into(),
        }
        assert!(
            original_archive(&serde_json::to_vec(&value).unwrap(), &policy, &mut vec![]).is_err()
        );
    }
    policy.signed_aggregate.push(b' ');
    assert!(original_archive(&raw, &policy, &mut vec![]).is_err());
}
#[test]
fn prelaunch_extracts_original_evidence_bytes() {
    let (_, mut policy) = policy_archive();
    let evidence = GcpLaunchEvidenceV2::new(vec![1, 2, 3], vec![4], vec![5])
        .unwrap()
        .encode()
        .unwrap();
    let capture = serde_json::to_vec(&execution_proof_client::gcp::GcpCaptureRequestV2 {
        version: execution_proof_client::gcp::WIRE_VERSION,
        purpose: execution_proof_client::gcp::CAPTURE_PURPOSE.into(),
        boot_binding_sha384: "15".repeat(48),
        session_id: "11".repeat(32),
        evidence_b64: STANDARD.encode(&evidence),
        recorder_public_key_hex: "22".repeat(32),
        signature_hex: "33".repeat(64),
    })
    .unwrap();
    policy.capture_request_base64 = STANDARD.encode(capture);
    let mut objects = vec![];
    prelaunch(policy, &mut objects, &"15".repeat(48)).unwrap();
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0].kind, ObjectKind::PrelaunchEvidence);
    assert_eq!(objects[0].bytes, evidence);
}
#[test]
fn actual_capture_wire_rejects_wrong_version_purpose_or_selected_boot_binding() {
    for mutation in 0..3 {
        let (_, mut policy) = policy_archive();
        let mut capture = execution_proof_client::gcp::GcpCaptureRequestV2 {
            version: execution_proof_client::gcp::WIRE_VERSION,
            purpose: execution_proof_client::gcp::CAPTURE_PURPOSE.into(),
            boot_binding_sha384: "15".repeat(48),
            session_id: "11".repeat(32),
            evidence_b64: STANDARD.encode(boot().evidence.encode().unwrap()),
            recorder_public_key_hex: "22".repeat(32),
            signature_hex: "33".repeat(64),
        };
        match mutation {
            0 => capture.version = 1,
            1 => capture.purpose = "legacy".into(),
            _ => capture.boot_binding_sha384 = "ff".repeat(48),
        }
        policy.capture_request_base64 = STANDARD.encode(serde_json::to_vec(&capture).unwrap());
        assert!(prelaunch(policy, &mut vec![], &"15".repeat(48)).is_err());
    }
}
#[test]
fn duplicate_kind_and_changed_object_digest_rejected_but_equal_bytes_other_kind_allowed() {
    let raw = b"public policy".to_vec();
    let mut objects = vec![];
    let object = |kind| SupportingObject {
        kind,
        sha384: hash(&raw),
        bytes: raw.clone(),
    };
    add_object(&mut objects, object(ObjectKind::AsPolicy)).unwrap();
    assert!(add_object(&mut objects, object(ObjectKind::AsPolicy)).is_err());
    add_object(&mut objects, object(ObjectKind::KbsPolicy)).unwrap();
    let mut bad = object(ObjectKind::AdmissionPolicy);
    bad.sha384 = "00".repeat(48);
    assert!(add_object(&mut objects, bad).is_err());
}
#[test]
fn private_markers_fields_and_recursive_duplicate_keys_rejected() {
    for raw in [
        br#"{"note":"PRIVATE KEY"}"#.as_slice(),
        br#"{"access_token":"x"}"#,
        br#"{"a":{"private_key":"x"}}"#,
        br#"{"x":1,"x":2}"#,
        br#"{"x":{"note":"PRIVATE KEY","note":"public"}}"#,
        br#"[{"a":1,"\u0061":2}]"#,
    ] {
        assert!(json::<serde_json::Value>(raw).is_err());
    }
    assert!(json::<serde_json::Value>(br#"{"public":[1,"quote",{"key":"PUBLIC KEY"}]}"#).is_ok());
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "public-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn pinned_reader_rejects_wrong_hash_symlink_hardlink_and_outside_root() {
    let directory = Directory::new();
    let path = directory.0.join("public.json");
    fs::write(&path, b"{\"public\":true}").unwrap();
    let mut inputs = Inputs { total: 0 };
    let pin = Pin {
        path: path.clone(),
        sha384: hash(b"{\"public\":true}"),
    };
    assert_eq!(inputs.get(&pin, 100).unwrap(), b"{\"public\":true}");
    assert!(inputs
        .get(
            &Pin {
                path: path.clone(),
                sha384: "00".repeat(48)
            },
            100
        )
        .is_err());
    fs::write(&path, b"{\"access_token\":\"synthetic-token\"}").unwrap();
    assert!(read(&path, 100).is_err());
    fs::write(&path, b"{\"public\":true}").unwrap();
    let linked = directory.0.join("link.json");
    symlink(&path, &linked).unwrap();
    assert!(read(&linked, 100).is_err());
    let hard = directory.0.join("hard.json");
    fs::hard_link(&path, hard).unwrap();
    assert!(read(&path, 100).is_err());
    assert!(canonical(Path::new("/tmp")).is_err());
    assert!(canonical(Path::new("relative")).is_err());
}
#[test]
fn output_create_only_and_non_authorizing_receipt() {
    let directory = Directory::new();
    let path = directory.0.join("output");
    let assembled = Assembled {
        pack: b"pack".to_vec(),
        trust: b"trust".to_vec(),
        challenge: b"challenge".to_vec(),
    };
    publish(&path, &assembled).unwrap();
    assert!(publish(&path, &assembled).is_err());
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("assembly.json")).unwrap()).unwrap();
    assert_eq!(receipt["execution_verified"], false);
    assert_eq!(receipt["hardware_verification_run"], false);
    assert_eq!(
        fs::metadata(path.join("pack.json")).unwrap().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
}
#[test]
fn selection_unknown_fields_and_other_domain_rejected_before_io() {
    assert!(json::<Selection>(br#"{"version":1,"purpose":"x","credential_json":{}}"#).is_err());
    assert!(b64("AQ", 100).is_err());
    assert!(b64("", 100).is_err());
    assert!(b64("AAAA", 1).is_err());
}
