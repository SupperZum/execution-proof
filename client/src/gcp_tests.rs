use super::*;
use execution_proof_contract::{
    gcp_credential::{
        GcpCredentialDeliveryV2, CREDENTIAL_DELIVERY_PROFILE, CREDENTIAL_DELIVERY_PURPOSE,
        CREDENTIAL_DELIVERY_VERSION,
    },
    gcp_policy_receipt::{
        GcpLaunchPolicyAggregateV2, POLICY_AGGREGATE_PROFILE, POLICY_AGGREGATE_PURPOSE,
        POLICY_AGGREGATE_VERSION,
    },
    policy_receipt::PolicyCommitments,
    LaunchBinding, LaunchGrant, Signed, ValidityWindow, GRANT_PURPOSE, VERSION,
};
use ring::rand::SystemRandom;
use serde_json::{json, Value};
fn key() -> Ed25519KeyPair {
    let bytes = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(bytes.as_ref()).unwrap()
}
fn binding() -> GcpBootBindingV1 {
    GcpBootBindingV1::new([1; 48], [2; 48], [3; 48], [4; 48]).unwrap()
}
fn input() -> (Vec<u8>, GrantExpectations, Ed25519KeyPair, TeePubKey) {
    let authority = key();
    let recorder = key();
    let raw = LaunchGrant {
        version: VERSION,
        purpose: GRANT_PURPOSE.into(),
        audience: "client-test".into(),
        proof_required: true,
        grant_id: "grant".into(),
        validity: ValidityWindow {
            not_before: 100,
            expires: 200,
        },
        binding: LaunchBinding {
            authority: "authority".into(),
            tenant: "tenant".into(),
            workload_id: "workload".into(),
            container_role: "application-init".into(),
            attempt_id: "attempt".into(),
            boot_id: "boot".into(),
            channel_key_sha384: hash(recorder.public_key().as_ref()),
            bootstrap_context_sha384: "01".repeat(48),
            selected_manifest_sha256: "02".repeat(32),
            effective_launch_sha384: "03".repeat(48),
            profile_sha384: binding().digest_sha384().unwrap(),
            launch_policy_sha384: "05".repeat(48),
            image_policy_sha384: "06".repeat(48),
            challenge_sha384: "07".repeat(48),
        },
    };
    let expected = GrantExpectations {
        authority_public_key: authority.public_key().as_ref().try_into().unwrap(),
        audience: raw.audience.clone(),
        authority: raw.binding.authority.clone(),
        tenant: raw.binding.tenant.clone(),
        profile_sha384: raw.binding.profile_sha384.clone(),
        launch_policy_sha384: raw.binding.launch_policy_sha384.clone(),
        image_policy_sha384: raw.binding.image_policy_sha384.clone(),
    };
    let signature = hex(authority.sign(&raw.signing_bytes().unwrap()).as_ref());
    (
        serde_json::to_vec(&Signed {
            statement: raw,
            signature,
        })
        .unwrap(),
        expected,
        recorder,
        TeePubKey::RSA {
            alg: "RSA-OAEP-256".into(),
            k_mod: "AQID".into(),
            k_exp: "AQAB".into(),
        },
    )
}
fn client() -> GcpClientProtocol {
    let (w, e, r, k) = input();
    GcpClientProtocol::new_authority_time(w, &e, r, k, binding()).unwrap()
}
fn begin(c: &GcpClientProtocol) -> Vec<u8> {
    let nonce = quote_nonce(c.grant.grant_digest(), &c.boot_binding, [9; 32]).unwrap();
    let runtime = serde_json_canonicalizer::to_vec(
        &json!({"tee-pubkey":c.keywrap,"nonce":nonce,"additional-evidence":""}),
    )
    .unwrap();
    encode(&GcpBeginResponseV2 {
        version: 2,
        purpose: BEGIN_PURPOSE.into(),
        boot_binding_sha384: c.boot_digest.clone(),
        session_id: "0a".repeat(32),
        quote_nonce: nonce,
        grant_digest: c.grant.grant_digest().into(),
        canonical_runtime_b64: STANDARD.encode(runtime),
        server_nonce_hex: "09".repeat(32),
    })
    .unwrap()
}
fn evidence() -> Vec<u8> {
    GcpLaunchEvidence::new(vec![1], vec![2], vec![3])
        .unwrap()
        .encode()
        .unwrap()
}
fn resource(c: &GcpClientProtocol) -> Vec<u8> {
    encode(&GcpResourceChallengeResponseV2 {
        version: 2,
        purpose: RESOURCE_CHALLENGE_PURPOSE.into(),
        boot_binding_sha384: c.boot_digest.clone(),
        session_id: c.session_id().unwrap().into(),
        request_nonce: "0b".repeat(32),
        grant_sha384: c.grant.grant_digest().into(),
        runtime_sha384: c.runtime_sha384().unwrap(),
        evidence_sha384: hash(c.evidence().unwrap()),
        recorder_key_sha384: c.grant.binding().channel_key_sha384.clone(),
    })
    .unwrap()
}
fn ready() -> GcpClientProtocol {
    let mut c = client();
    c.accept_begin_response(&begin(&c)).unwrap();
    c.capture_request(&evidence()).unwrap();
    c.accept_resource_challenge_response(&resource(&c)).unwrap();
    c.resource_decision_request(&ResourcePolicyRequest {
        method: "GET".into(),
        plugin: "resource".into(),
        resource_path: ["repo".into(), "credential".into(), "version".into()],
        workflow_id: "gcp-check".into(),
        request_nonce: c.request_nonce().unwrap().into(),
    })
    .unwrap();
    c
}
fn commitments() -> PolicyCommitments {
    PolicyCommitments {
        policy_sha384: "05".repeat(48),
        input_sha384: "11".repeat(48),
        policy_id: "launch-policy".into(),
        data_sha384: None,
    }
}
fn aggregate(c: &GcpClientProtocol, kbs: &Ed25519KeyPair) -> (Vec<u8>, GcpAggregateExpectations) {
    let s = GcpLaunchPolicyAggregateV2 {
        version: POLICY_AGGREGATE_VERSION,
        purpose: POLICY_AGGREGATE_PURPOSE.into(),
        audience: "verifier".into(),
        issuer: "kbs".into(),
        profile: POLICY_AGGREGATE_PROFILE.into(),
        grant_sha384: c.grant.grant_digest().into(),
        authority_key_sha384: c.grant.authority_key_sha384().into(),
        session_id: c.session_id().unwrap().into(),
        nonce: c.quote_nonce().unwrap().into(),
        runtime_sha384: c.runtime_sha384().unwrap(),
        boot_binding_sha384: c.boot_digest.clone(),
        evidence_sha384: hash(c.evidence().unwrap()),
        recorder_key_sha384: c.grant.binding().channel_key_sha384.clone(),
        request: c.request.clone().unwrap(),
        as_evaluation: commitments(),
        kbs_evaluation: commitments(),
    };
    let sig = hex(kbs.sign(&s.signing_bytes().unwrap()).as_ref());
    let e = GcpAggregateExpectations {
        kbs_proof_public_key: kbs.public_key().as_ref().try_into().unwrap(),
        boot_binding: binding(),
        expected: s.clone(),
    };
    (
        encode(&Signed {
            statement: s,
            signature: sig,
        })
        .unwrap(),
        e,
    )
}

#[test]
fn issuer_admission_signer_is_bound_to_selected_audience_and_current_session() {
    let c = ready();
    let (wire, expected) = aggregate(&c, &key());
    let verified = c.verify_aggregate(&wire, &expected).unwrap();
    let request = c
        .sign_policy_admission_request(
            &verified,
            "guest-nonce",
            &"21".repeat(48),
            GcpAdmissionOperation::Redeem,
        )
        .unwrap();
    let parsed: Signed<GcpAdmissionRequestV2> = serde_json::from_slice(&request).unwrap();
    assert_eq!(parsed.statement.audience, "client-test");
    execution_proof_contract::admission::gcp::verify_gcp_admission_request(
        &request,
        &c.recorder.public_key().as_ref().try_into().unwrap(),
        &parsed.statement,
        &c.grant,
    )
    .unwrap();
    let mut status = parsed.statement.clone();
    status.operation = GcpAdmissionOperation::Status;
    assert!(
        execution_proof_contract::admission::gcp::verify_gcp_admission_request(
            &request,
            &c.recorder.public_key().as_ref().try_into().unwrap(),
            &status,
            &c.grant
        )
        .is_err()
    );
    assert!(matches!(
        ready().sign_policy_admission_request(
            &verified,
            "guest-nonce",
            &"21".repeat(48),
            GcpAdmissionOperation::Redeem
        ),
        Err(ClientError::BindingMismatch)
    ));
    assert!(matches!(
        client().sign_policy_admission_request(
            &verified,
            "guest-nonce",
            &"21".repeat(48),
            GcpAdmissionOperation::Redeem
        ),
        Err(ClientError::NotReady)
    ));
    assert!(c
        .sign_policy_admission_request(
            &verified,
            "",
            &"21".repeat(48),
            GcpAdmissionOperation::Redeem
        )
        .is_err());
}
#[test]
fn constructor_enforces_actual_signed_profile_and_recorder_key() {
    let (w, e, r, k) = input();
    let mut b = binding();
    b.config_sha384 = "21".repeat(48);
    assert!(matches!(
        GcpClientProtocol::new_authority_time(w, &e, r, k, b),
        Err(ClientError::Contract(
            execution_proof_contract::Error::BindingMismatch
        ))
    ));
    let (w, e, _, k) = input();
    assert!(matches!(
        GcpClientProtocol::new_authority_time(w, &e, key(), k, binding()),
        Err(ClientError::BindingMismatch)
    ));
}
#[test]
fn begin_rederives_as_nonce_and_full64_canonical_runtime() {
    let mut c = client();
    let wire = c.begin_request().unwrap();
    let r: GcpBeginRequestV2 = serde_json::from_slice(&wire).unwrap();
    assert_eq!(r.version, 2);
    gcp_session::verify_operation_pop(
        &c.grant,
        &binding(),
        &SessionOperation::Begin {
            key_sha384: c.key_sha384.clone(),
        },
        &c.recorder.public_key().as_ref().try_into().unwrap(),
        &r.signature_hex,
    )
    .unwrap();
    let b = begin(&c);
    c.accept_begin_response(&b).unwrap();
    c.accept_begin_response(&b).unwrap();
    assert_eq!(
        c.report_data_full64().unwrap()[..48],
        c.report_data().unwrap()
    );
    assert_eq!(c.report_data_full64().unwrap()[48..], [0; 16]);
    assert_eq!(
        c.runtime_sha384().unwrap(),
        hash(c.canonical_runtime().unwrap())
    );
}
#[test]
fn mixed_peer_wrong_b_server_nonce_and_runtime_substitutions_reject() {
    for field in [
        "version",
        "purpose",
        "boot_binding_sha384",
        "server_nonce_hex",
        "canonical_runtime_b64",
        "quote_nonce",
    ] {
        let mut c = client();
        let mut v: Value = serde_json::from_slice(&begin(&c)).unwrap();
        v[field] = match field {
            "version" => 1.into(),
            "purpose" => CAPTURE_PURPOSE.into(),
            "boot_binding_sha384" => "22".repeat(48).into(),
            "server_nonce_hex" => "23".repeat(32).into(),
            "canonical_runtime_b64" => STANDARD.encode(b"{}").into(),
            _ => format!("onb17-launch-v1:{}", "24".repeat(48)).into(),
        };
        assert!(
            c.accept_begin_response(&encode(&v).unwrap()).is_err(),
            "{field}"
        );
        assert!(c.session_id().is_none());
    }
    let mut c = client();
    let mut v: Value = serde_json::from_slice(&begin(&c)).unwrap();
    v["init_data_sha384"] = "00".repeat(48).into();
    assert!(c.accept_begin_response(&encode(&v).unwrap()).is_err());
}
#[test]
fn capture_signs_distinct_v2_session_and_rejects_legacy_or_changed_evidence() {
    let mut c = client();
    c.accept_begin_response(&begin(&c)).unwrap();
    let bytes = c.capture_request(&evidence()).unwrap();
    let r: GcpCaptureRequestV2 = serde_json::from_slice(&bytes).unwrap();
    gcp_session::verify_recorder_session_pop(
        &c.grant,
        &binding(),
        c.quote_nonce().unwrap(),
        &c.runtime_sha384().unwrap(),
        &hash(&evidence()),
        &c.recorder.public_key().as_ref().try_into().unwrap(),
        &r.signature_hex,
    )
    .unwrap();
    assert!(c.capture_request(b"{\"quote\":\"old\"}").is_err());
    let other = GcpLaunchEvidence::new(vec![9], vec![2], vec![3])
        .unwrap()
        .encode()
        .unwrap();
    assert_eq!(
        c.capture_request(&other).unwrap_err(),
        ClientError::Conflict
    );
}
#[test]
fn actual_signed_aggregate_and_credential_ciphertext_are_bound_and_redacted() {
    let c = ready();
    let kbs = key();
    let (a, expected) = aggregate(&c, &kbs);
    let verified = c.verify_aggregate(&a, &expected).unwrap();
    let body = c.credential_request(&a, &expected).unwrap();
    let op: GcpCredentialRequestV2 = serde_json::from_slice(&body).unwrap();
    assert_eq!(op.aggregate_sha384, verified.digest_sha384());
    let jwe = b"seeded-confidential-ciphertext-not-a-real-JWE";
    let r = GcpCredentialDeliveryV2 {
        version: CREDENTIAL_DELIVERY_VERSION,
        purpose: CREDENTIAL_DELIVERY_PURPOSE.into(),
        audience: "credential".into(),
        issuer: "kbs".into(),
        profile: CREDENTIAL_DELIVERY_PROFILE.into(),
        grant_sha384: c.grant.grant_digest().into(),
        aggregate_sha384: verified.digest_sha384().into(),
        request_sha384: c.request.as_ref().unwrap().digest_sha384().unwrap(),
        session_id: c.session_id().unwrap().into(),
        runtime_sha384: c.runtime_sha384().unwrap(),
        evidence_sha384: hash(c.evidence().unwrap()),
        boot_binding_sha384: c.boot_digest.clone(),
        recorder_key_sha384: c.grant.binding().channel_key_sha384.clone(),
        keywrap_sha384: c.key_sha384.clone(),
        ciphertext_sha384: hash(jwe),
        workflow_id: c.request.as_ref().unwrap().workflow_id.clone(),
        resource_path: c.request.as_ref().unwrap().resource_path.clone(),
        validity: ValidityWindow {
            not_before: 100,
            expires: 200,
        },
    };
    let signature = hex(kbs.sign(&r.signing_bytes().unwrap()).as_ref());
    let receipt = encode(&Signed {
        statement: r,
        signature,
    })
    .unwrap();
    let delivery = GcpDeliveryExpectations {
        aggregate: expected,
        audience: "credential".into(),
        issuer: "kbs".into(),
        keywrap_sha384: c.key_sha384.clone(),
    };
    let response = encode(&GcpCredentialResponseV2 {
        version: 2,
        purpose: CREDENTIAL_PURPOSE.into(),
        boot_binding_sha384: c.boot_digest.clone(),
        signed_delivery_b64: STANDARD.encode(receipt),
        jwe_b64: STANDARD.encode(jwe),
    })
    .unwrap();
    let ok = c
        .verify_credential_response_historical(&response, &a, &delivery)
        .unwrap();
    assert_eq!(ok.jwe_bytes(), jwe);
    let mut v: Value = serde_json::from_slice(&response).unwrap();
    v["jwe_b64"] = STANDARD.encode(b"substituted-secret").into();
    let error = c
        .verify_credential_response_historical(&encode(&v).unwrap(), &a, &delivery)
        .err()
        .unwrap();
    let public = format!("{error:?} {error}");
    assert!(!public.contains("secret"));
    assert!(!public.contains("seeded"));
    let pending = encode(&GcpCredentialPendingV2 {
        version: 2,
        purpose: CREDENTIAL_PURPOSE.into(),
        boot_binding_sha384: c.boot_digest.clone(),
        outcome: GcpCredentialOutcome::Pending,
    })
    .unwrap();
    assert!(matches!(
        c.verify_credential_response_historical(&pending, &a, &delivery),
        Err(ClientError::NotReady)
    ));
    v["outcome"] = "pending".into();
    assert!(c
        .verify_credential_response_historical(&encode(&v).unwrap(), &a, &delivery)
        .is_err());
}

#[test]
fn as_nonce_matches_independent_u64_framed_golden_and_domains_do_not_mix() {
    assert_eq!(quote_nonce(&"11".repeat(48),&binding(),[9;32]).unwrap(),"onb17-gcp-launch-v2:b32528341a9105afb8e25633024f1e8c1916f1e78d37e699f888c7f837b510bf5bbdb9f2d983afae8f68b2264da955be");
    assert!(quote_nonce(&"11".repeat(48), &binding(), [0; 32]).is_err());
    let mut c = client();
    c.accept_begin_response(&begin(&c)).unwrap();
    assert!(c.capture_request(b"legacy").is_err());
    assert!(check_wire_domain(
        1,
        BEGIN_PURPOSE,
        c.boot_binding_sha384(),
        BEGIN_PURPOSE,
        c.boot_binding_sha384()
    )
    .is_err());
}
#[test]
fn all_resource_challenge_context_substitutions_reject_without_state() {
    let mut c = client();
    c.accept_begin_response(&begin(&c)).unwrap();
    c.capture_request(&evidence()).unwrap();
    for field in [
        "boot_binding_sha384",
        "runtime_sha384",
        "grant_sha384",
        "evidence_sha384",
        "recorder_key_sha384",
    ] {
        let mut v: Value = serde_json::from_slice(&resource(&c)).unwrap();
        v[field] = "33".repeat(48).into();
        assert!(c
            .accept_resource_challenge_response(&encode(&v).unwrap())
            .is_err());
        assert!(c.request_nonce().is_none());
    }
    c.accept_resource_challenge_response(&resource(&c)).unwrap();
    let mut v: Value = serde_json::from_slice(&resource(&c)).unwrap();
    v["request_nonce"] = "44".repeat(32).into();
    assert_eq!(
        c.accept_resource_challenge_response(&encode(&v).unwrap()),
        Err(ClientError::Conflict)
    );
}
#[test]
fn full_decoded_budget_has_separate_new_transport_overhead_bound() {
    let mut c = client();
    c.accept_begin_response(&begin(&c)).unwrap();
    let evidence = GcpLaunchEvidence::new(vec![1], vec![2], vec![1; (1 << 20) - 2])
        .unwrap()
        .encode()
        .unwrap();
    let request = c.capture_request(&evidence).unwrap();
    assert!(request.len() > 2 << 20);
    assert!(request.len() <= MAX_REQUEST_BYTES);
    assert!(GcpLaunchEvidence::new(vec![1], vec![2], vec![1; 1 << 20]).is_err());
}
