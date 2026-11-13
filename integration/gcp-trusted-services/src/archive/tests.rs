use super::*;
use execution_proof_contract::{
    gcp_credential::{CREDENTIAL_DELIVERY_PROFILE, CREDENTIAL_DELIVERY_PURPOSE},
    gcp_policy_receipt::{POLICY_AGGREGATE_PROFILE, POLICY_AGGREGATE_PURPOSE},
    policy_receipt::{PolicyCommitments, ResourcePolicyRequest},
    ValidityWindow,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::os::unix::fs::PermissionsExt;
fn delivery_fixture() -> (tempfile::TempDir, Archive, DeliveryScope, Vec<u8>, Vec<u8>) {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let archive = Archive::open(root.path()).unwrap();
    // Deterministic software fixture only; not an operator key.
    let signer = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
    let key = signer.public_key().as_ref().try_into().unwrap();
    let scope = DeliveryScope {
        public_key: key,
        audience: "delivery".into(),
        issuer: "kbs".into(),
        boot_binding_sha384: "11".repeat(48),
    };
    let commitments = PolicyCommitments {
        policy_id: "policy".into(),
        policy_sha384: "22".repeat(48),
        input_sha384: "33".repeat(48),
        data_sha384: None,
    };
    let aggregate = GcpLaunchPolicyAggregateV2 {
        version: 2,
        purpose: POLICY_AGGREGATE_PURPOSE.into(),
        profile: POLICY_AGGREGATE_PROFILE.into(),
        audience: "aggregate".into(),
        issuer: "kbs".into(),
        grant_sha384: "44".repeat(48),
        authority_key_sha384: "55".repeat(48),
        session_id: "66".repeat(32),
        nonce: "nonce".into(),
        runtime_sha384: "77".repeat(48),
        boot_binding_sha384: scope.boot_binding_sha384.clone(),
        evidence_sha384: "88".repeat(48),
        recorder_key_sha384: "99".repeat(48),
        request: ResourcePolicyRequest {
            method: "GET".into(),
            plugin: "resource".into(),
            resource_path: ["onb17".into(), "manual".into(), "credential".into()],
            workflow_id: "workflow".into(),
            request_nonce: "request".into(),
        },
        as_evaluation: commitments.clone(),
        kbs_evaluation: commitments,
    };
    let aggregate_digest = aggregate.digest_sha384().unwrap();
    let aggregate_signature =
        hex::encode(signer.sign(&aggregate.signing_bytes().unwrap()).as_ref());
    let signed_aggregate = serde_json::to_vec(&Signed {
        statement: aggregate.clone(),
        signature: aggregate_signature,
    })
    .unwrap();
    let record = Record {
        version: 1,
        purpose: "qlad.execution-proof.gcp-original-policy-archive.v1".into(),
        session_id: aggregate.session_id.clone(),
        aggregate_sha384: aggregate_digest.clone(),
        signed_aggregate_b64: STANDARD.encode(&signed_aggregate),
        objects: vec![object(
            "as_input",
            b"{ \"original\": true }",
            &hash(b"{ \"original\": true }"),
        )
        .unwrap()],
        credential_receipt_b64: None,
    };
    archive.store_record(&record).unwrap();
    let receipt = GcpCredentialDeliveryV2 {
        version: 2,
        purpose: CREDENTIAL_DELIVERY_PURPOSE.into(),
        profile: CREDENTIAL_DELIVERY_PROFILE.into(),
        audience: scope.audience.clone(),
        issuer: scope.issuer.clone(),
        grant_sha384: aggregate.grant_sha384.clone(),
        aggregate_sha384: aggregate_digest,
        request_sha384: aggregate.request.digest_sha384().unwrap(),
        session_id: aggregate.session_id.clone(),
        runtime_sha384: aggregate.runtime_sha384.clone(),
        evidence_sha384: aggregate.evidence_sha384.clone(),
        boot_binding_sha384: scope.boot_binding_sha384.clone(),
        recorder_key_sha384: aggregate.recorder_key_sha384.clone(),
        keywrap_sha384: "aa".repeat(48),
        ciphertext_sha384: "bb".repeat(48),
        workflow_id: aggregate.request.workflow_id.clone(),
        resource_path: aggregate.request.resource_path.clone(),
        validity: ValidityWindow {
            not_before: 1,
            expires: 2,
        },
    };
    let signature = hex::encode(signer.sign(&receipt.signing_bytes().unwrap()).as_ref());
    // Whitespace in this original signed receipt must survive archival.
    let signed_receipt = serde_json::to_vec_pretty(&Signed {
        statement: receipt,
        signature,
    })
    .unwrap();
    let response=serde_json::to_vec(&serde_json::json!({"version":2,"purpose":execution_proof_client::gcp::CREDENTIAL_PURPOSE,
        "boot_binding_sha384":scope.boot_binding_sha384,"signed_delivery_b64":STANDARD.encode(&signed_receipt),
        "jwe_b64":"FALSE_ENCRYPTED_CREDENTIAL_MUST_NEVER_BE_ARCHIVED"})).unwrap();
    (root, archive, scope, response, signed_receipt)
}
#[test]
fn delivery_archives_only_original_signed_public_receipt_and_preserves_policy_bodies() {
    let (root, archive, scope, response, receipt) = delivery_fixture();
    archive.store_delivery_response(&response, &scope).unwrap();
    archive.store_delivery_response(&response, &scope).unwrap();
    let path = std::fs::read_dir(root.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let raw = std::fs::read(path).unwrap();
    assert!(!raw
        .windows(b"FALSE_ENCRYPTED".len())
        .any(|v| v == b"FALSE_ENCRYPTED"));
    let mut stored: Record = serde_json::from_slice(&raw).unwrap();
    assert_eq!(
        STANDARD
            .decode(stored.credential_receipt_b64.take().unwrap())
            .unwrap(),
        receipt
    );
    assert_eq!(
        STANDARD.decode(&stored.objects[0].body_b64).unwrap(),
        b"{ \"original\": true }"
    );
    archive.store_record(&stored).unwrap(); // Aggregate retry preserves the later receipt.
}
#[test]
fn delivery_retry_requires_directory_sync_after_rename() {
    let (root, mut archive, scope, response, receipt) = delivery_fixture();
    let directory = std::mem::replace(&mut archive.directory, File::open("/dev/null").unwrap());

    // The rename is visible, but syncing the stand-in directory FD fails.
    assert!(archive.store_delivery_response(&response, &scope).is_err());
    let path = std::fs::read_dir(root.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let raw = std::fs::read(&path).unwrap();
    let stored: Record = serde_json::from_slice(&raw).unwrap();
    assert_eq!(
        STANDARD
            .decode(stored.credential_receipt_b64.unwrap())
            .unwrap(),
        receipt
    );
    assert!(archive.store_delivery_response(&response, &scope).is_err());

    archive.directory = directory;
    archive.store_delivery_response(&response, &scope).unwrap();
    assert_eq!(std::fs::read(path).unwrap(), raw);
}
#[test]
fn delivery_rejects_foreign_key_domain_and_private_or_duplicate_fields_before_archive_update() {
    let (root, archive, mut scope, response, _) = delivery_fixture();
    let path = std::fs::read_dir(root.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let before = std::fs::read(&path).unwrap();
    scope.public_key = [8; 32];
    assert!(archive.store_delivery_response(&response, &scope).is_err());
    let (_, _, scope, _, _) = delivery_fixture();
    for name in ["purpose", "boot_binding_sha384"] {
        let mut body: serde_json::Value = serde_json::from_slice(&response).unwrap();
        body[name] = "foreign".into();
        assert!(archive
            .store_delivery_response(&serde_json::to_vec(&body).unwrap(), &scope)
            .is_err());
    }
    let mut body: serde_json::Value = serde_json::from_slice(&response).unwrap();
    body["access_token"] = "FALSE_PRIVATE".into();
    assert!(archive
        .store_delivery_response(&serde_json::to_vec(&body).unwrap(), &scope)
        .is_err());
    let duplicate = String::from_utf8(response.clone()).unwrap().replacen(
        "{",
        "{\"signed_delivery_b64\":\"invalid\",",
        1,
    );
    assert!(archive
        .store_delivery_response(duplicate.as_bytes(), &scope)
        .is_err());
    assert_eq!(std::fs::read(path).unwrap(), before);
}
#[test]
fn delivery_requires_original_aggregate_and_rejects_changed_signed_receipt() {
    let (root, archive, scope, response, _) = delivery_fixture();
    let path = std::fs::read_dir(root.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let original = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(archive.store_delivery_response(&response, &scope).is_err());
    std::fs::write(&path, &original).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    archive.store_delivery_response(&response, &scope).unwrap();
    let mut body: serde_json::Value = serde_json::from_slice(&response).unwrap();
    let mut receipt: serde_json::Value = serde_json::from_slice(
        &STANDARD
            .decode(body["signed_delivery_b64"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    receipt["statement"]["resource_path"] = serde_json::json!(["foreign", "resource", "path"]);
    let signer = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
    let statement: GcpCredentialDeliveryV2 =
        serde_json::from_value(receipt["statement"].clone()).unwrap();
    receipt["signature"] =
        hex::encode(signer.sign(&statement.signing_bytes().unwrap()).as_ref()).into();
    body["signed_delivery_b64"] = STANDARD
        .encode(serde_json::to_vec(&receipt).unwrap())
        .into();
    assert!(archive
        .store_delivery_response(&serde_json::to_vec(&body).unwrap(), &scope)
        .is_err());
    receipt["statement"]["resource_path"] = serde_json::json!(["onb17", "manual", "credential"]);
    receipt["statement"]["keywrap_sha384"] = "cc".repeat(48).into();
    let statement: GcpCredentialDeliveryV2 =
        serde_json::from_value(receipt["statement"].clone()).unwrap();
    receipt["signature"] =
        hex::encode(signer.sign(&statement.signing_bytes().unwrap()).as_ref()).into();
    body["signed_delivery_b64"] = STANDARD
        .encode(serde_json::to_vec(&receipt).unwrap())
        .into();
    assert!(archive
        .store_delivery_response(&serde_json::to_vec(&body).unwrap(), &scope)
        .is_err());
}
#[test]
fn archive_public_schema_rejects_extra_fields_and_nested_credentials() {
    let mut a = serde_json::json!({"profile":"onb17.gcp-launch-quote.v2","tee":"tdx","tee_class":"cpu","grant_digest":"public","claims":{},"runtime_data":{},"boot_binding":{},"boot_binding_sha384":"public","boot_policy":{},"module_policy":{}});
    let k = serde_json::json!({"profile":"onb17.gcp-verified-launch-resource-input.v2","verified_launch":{"grant_sha384":"public","authority_key_sha384":"public","binding":{},"session_id":"public","nonce":"public","runtime_sha384":"public","boot_binding_sha384":"public","evidence_sha384":"public","claims":{}}});
    let d = serde_json::json!({"method":"GET","plugin":"resource","resource-path":"public/public/public","workflow-id":"public","request_nonce":"public","query":{}});
    let check = |a: &serde_json::Value| {
        public_inputs(
            &serde_json::to_vec(a).unwrap(),
            &serde_json::to_vec(&k).unwrap(),
            &serde_json::to_vec(&d).unwrap(),
        )
    };
    assert!(check(&a).is_ok());
    a["extra"] = "unexpected".into();
    assert!(check(&a).is_err());
    a.as_object_mut().unwrap().remove("extra");
    a["claims"]["private_key"] = "test-only-not-a-key".into();
    assert!(check(&a).is_err());
    let private = b"-----BEGIN PRIVATE KEY-----\ntest-only\n-----END PRIVATE KEY-----";
    assert!(object("as_input", private, &hash(private)).is_err());
}
#[test]
fn archive_is_exact_private_idempotent_and_capacity_bounded() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let archive = Archive::open(root.path()).unwrap();
    assert!(Archive::open(root.path()).is_err());
    let policy = b"package policy\n default allow := false\n";
    let input = b"{ \"original\" : true }";
    let mut record = Record {
        version: 1,
        purpose: "qlad.execution-proof.gcp-original-policy-archive.v1".into(),
        session_id: "11".repeat(32),
        aggregate_sha384: "22".repeat(48),
        signed_aggregate_b64: STANDARD.encode(b"public-test-signature-object"),
        objects: vec![
            object("as_policy", policy, &hash(policy)).unwrap(),
            object("as_input", input, &hash(input)).unwrap(),
        ],
        credential_receipt_b64: None,
    };
    archive.store_record(&record).unwrap();
    archive.store_record(&record).unwrap();
    let path = std::fs::read_dir(root.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        STANDARD
            .decode(value["objects"][1]["body_b64"].as_str().unwrap())
            .unwrap(),
        input
    );
    assert_eq!(std::fs::metadata(path).unwrap().mode() & 0o777, 0o600);
    record.session_id = "33".repeat(32);
    assert!(archive.store_record(&record).is_err());
    assert!(object("as_input", input, &"00".repeat(48)).is_err());
}
