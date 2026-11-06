use super::*;
use execution_proof_contract::{
    policy_receipt::{
        LaunchPolicyAggregateV1, PolicyCommitments, POLICY_AGGREGATE_PROFILE,
        POLICY_AGGREGATE_PURPOSE, POLICY_AGGREGATE_VERSION,
    },
    session::{verify_operation_pop, verify_recorder_session_pop},
    LaunchBinding, LaunchGrant, Signed, ValidityWindow, GRANT_PURPOSE, VERSION,
};
use ring::rand::SystemRandom;
use serde_json::{json, Value};

fn key() -> Ed25519KeyPair {
    let bytes = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(bytes.as_ref()).unwrap()
}

fn inputs() -> (Vec<u8>, GrantExpectations, Ed25519KeyPair, TeePubKey) {
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
            profile_sha384: "04".repeat(48),
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
    let wire = serde_json::to_vec(&Signed {
        statement: raw,
        signature,
    })
    .unwrap();
    (
        wire,
        expected,
        recorder,
        TeePubKey::RSA {
            alg: "RSA-OAEP-256".into(),
            k_mod: "AQID".into(),
            k_exp: "AQAB".into(),
        },
    )
}
fn client() -> ClientProtocol {
    let (wire, expected, recorder, keywrap) = inputs();
    ClientProtocol::new(wire, &expected, 100, recorder, keywrap, [8; 48]).unwrap()
}
fn begin_response(client: &ClientProtocol) -> Vec<u8> {
    let quote_nonce = format!("onb17-launch-v1:{}", "09".repeat(48));
    let runtime = serde_json_canonicalizer::to_vec(
        &json!({"tee-pubkey":client.keywrap,"nonce":quote_nonce,"additional-evidence":""}),
    )
    .unwrap();
    serde_json::to_vec(&json!({"session_id":"0a".repeat(32),"quote_nonce":quote_nonce,"grant_digest":client.grant.grant_digest(),"canonical_runtime_b64":STANDARD.encode(runtime),"init_data_sha384":hex(&client.expected_init)})).unwrap()
}
fn resource_response(client: &ClientProtocol) -> Vec<u8> {
    serde_json::to_vec(&json!({"session_id":client.session_id().unwrap(),"request_nonce":"0b".repeat(32),"grant_sha384":client.grant.grant_digest(),"runtime_sha384":hex(&client.report_data().unwrap()),
        "evidence_sha384":hash(client.evidence().unwrap()),"init_data_sha384":hex(&client.expected_init),"recorder_key_sha384":client.grant.binding().channel_key_sha384})).unwrap()
}
fn ready() -> ClientProtocol {
    let mut client = client();
    client
        .accept_begin_response(&begin_response(&client))
        .unwrap();
    client
        .capture_request(b"{\"quote\":\"fixture-only\"}")
        .unwrap();
    client
        .accept_resource_challenge_response(&resource_response(&client))
        .unwrap();
    client
}
fn request(client: &ClientProtocol) -> ResourcePolicyRequest {
    ResourcePolicyRequest {
        method: "GET".into(),
        plugin: "resource".into(),
        resource_path: ["repo".into(), "credential".into(), "version".into()],
        workflow_id: "policy-check".into(),
        request_nonce: client.request_nonce().unwrap().into(),
    }
}

#[test]
fn constructor_rejects_foreign_authority_wrong_recorder_and_expiry() {
    let (wire, mut expected, recorder, keywrap) = inputs();
    expected.authority_public_key = key().public_key().as_ref().try_into().unwrap();
    assert!(matches!(
        ClientProtocol::new(wire, &expected, 100, recorder, keywrap, [8; 48]),
        Err(ClientError::Contract(
            execution_proof_contract::Error::InvalidSignature
        ))
    ));
    let (wire, expected, _, keywrap) = inputs();
    assert!(matches!(
        ClientProtocol::new(wire, &expected, 100, key(), keywrap, [8; 48]),
        Err(ClientError::BindingMismatch)
    ));
    let (wire, expected, recorder, keywrap) = inputs();
    assert!(matches!(
        ClientProtocol::new(wire, &expected, 200, recorder, keywrap, [8; 48]),
        Err(ClientError::Contract(
            execution_proof_contract::Error::Expired
        ))
    ));
}

#[test]
fn begin_codec_signs_actual_key_and_rederives_own_runtime() {
    let mut client = client();
    let first = client.begin_request().unwrap();
    assert_eq!(first, client.begin_request().unwrap());
    let dto: Value = serde_json::from_slice(&first).unwrap();
    let public = client.recorder.public_key().as_ref().try_into().unwrap();
    let op = SessionOperation::Begin {
        key_sha384: hash(&serde_json_canonicalizer::to_vec(&client.keywrap).unwrap()),
    };
    assert_eq!(
        verify_operation_pop(
            &client.grant,
            &op,
            &public,
            dto["signature_hex"].as_str().unwrap()
        ),
        Ok(())
    );
    assert_eq!(
        STANDARD
            .decode(dto["signed_grant_b64"].as_str().unwrap())
            .unwrap(),
        client.signed_grant
    );
    let response = begin_response(&client);
    client.accept_begin_response(&response).unwrap();
    client.accept_begin_response(&response).unwrap();
    assert_eq!(
        client.report_data().unwrap().as_slice(),
        digest::digest(&digest::SHA384, &client.begin().unwrap().runtime).as_ref()
    );
    let mut changed: Value = serde_json::from_slice(&response).unwrap();
    changed["session_id"] = "11".repeat(32).into();
    assert_eq!(
        client.accept_begin_response(&serde_json::to_vec(&changed).unwrap()),
        Err(ClientError::Conflict)
    );
}

#[test]
fn untrusted_begin_context_and_strict_response_shape_cannot_replace_own_state() {
    for field in ["grant_digest", "init_data_sha384"] {
        let mut client = client();
        let mut value: Value = serde_json::from_slice(&begin_response(&client)).unwrap();
        value[field] = "10".repeat(48).into();
        assert_eq!(
            client.accept_begin_response(&serde_json::to_vec(&value).unwrap()),
            Err(ClientError::BindingMismatch)
        );
        assert!(client.session_id().is_none());
    }
    let mut client = client();
    let raw = begin_response(&client);
    let mut value: Value = serde_json::from_slice(&raw).unwrap();
    value["canonical_runtime_b64"] = STANDARD.encode(b"foreign-runtime-key").into();
    assert_eq!(
        client.accept_begin_response(&serde_json::to_vec(&value).unwrap()),
        Err(ClientError::BindingMismatch)
    );
    let mut extra: Value = serde_json::from_slice(&raw).unwrap();
    extra["accepted"] = true.into();
    assert_eq!(
        client.accept_begin_response(&serde_json::to_vec(&extra).unwrap()),
        Err(ClientError::Malformed)
    );
    let duplicate = String::from_utf8(raw.clone()).unwrap().replacen(
        "\"session_id\":",
        "\"session_id\":\"duplicate\",\"session_id\":",
        1,
    );
    assert_eq!(
        client.accept_begin_response(duplicate.as_bytes()),
        Err(ClientError::Malformed)
    );
    assert_eq!(
        client.accept_begin_response(&vec![b' '; MAX_RESPONSE_BYTES + 1]),
        Err(ClientError::TooLarge)
    );
    let mut bad_nonce: Value = serde_json::from_slice(&raw).unwrap();
    bad_nonce["quote_nonce"] = "unrelated-domain".into();
    assert_eq!(
        client.accept_begin_response(&serde_json::to_vec(&bad_nonce).unwrap()),
        Err(ClientError::InvalidField)
    );
    assert_eq!(canonical_base64("Zh==", 10), Err(ClientError::InvalidField));
}

#[test]
fn capture_and_resource_operations_preserve_exact_bytes_and_nonce_roles() {
    let mut client = client();
    assert_eq!(client.report_data().err(), Some(ClientError::NotReady));
    client
        .accept_begin_response(&begin_response(&client))
        .unwrap();
    let evidence = b"{\"quote\":\"exact-whitespace\"}";
    let first = client.capture_request(evidence).unwrap();
    assert_eq!(first, client.capture_request(evidence).unwrap());
    assert_eq!(
        client.capture_request(b"different"),
        Err(ClientError::Conflict)
    );
    let dto: Value = serde_json::from_slice(&first).unwrap();
    let public = client.recorder.public_key().as_ref().try_into().unwrap();
    assert!(verify_recorder_session_pop(
        &client.grant,
        client.quote_nonce().unwrap(),
        &hex(&client.report_data().unwrap()),
        &hash(evidence),
        &public,
        dto["signature_hex"].as_str().unwrap()
    )
    .is_ok());
    let dto: Value = serde_json::from_slice(&client.resource_challenge_request().unwrap()).unwrap();
    let op = SessionOperation::ResourceChallenge {
        session_id: client.session_id().unwrap().into(),
        nonce: client.quote_nonce().unwrap().into(),
        runtime_sha384: hex(&client.report_data().unwrap()),
        evidence_sha384: hash(evidence),
    };
    assert_eq!(
        verify_operation_pop(
            &client.grant,
            &op,
            &public,
            dto["signature_hex"].as_str().unwrap()
        ),
        Ok(())
    );
    let response = resource_response(&client);
    client
        .accept_resource_challenge_response(&response)
        .unwrap();
    let request = request(&client);
    let first = client.resource_decision_request(&request).unwrap();
    assert_eq!(first, client.resource_decision_request(&request).unwrap());
    let dto: Value = serde_json::from_slice(&first).unwrap();
    let op = SessionOperation::ResourceDecision {
        session_id: client.session_id().unwrap().into(),
        nonce: client.request_nonce().unwrap().into(),
        runtime_sha384: hex(&client.report_data().unwrap()),
        evidence_sha384: hash(evidence),
        request_sha384: request.digest_sha384().unwrap(),
    };
    assert_eq!(
        verify_operation_pop(
            &client.grant,
            &op,
            &public,
            dto["signature_hex"].as_str().unwrap()
        ),
        Ok(())
    );
    let mut changed = request.clone();
    changed.resource_path[2] = "other".into();
    assert_eq!(
        client.resource_decision_request(&changed),
        Err(ClientError::Conflict)
    );
    let mut changed: Value = serde_json::from_slice(&response).unwrap();
    changed["request_nonce"] = "0c".repeat(32).into();
    assert_eq!(
        client.accept_resource_challenge_response(&serde_json::to_vec(&changed).unwrap()),
        Err(ClientError::Conflict)
    );
}

#[test]
fn resource_challenge_must_match_every_retained_context_field() {
    for field in [
        "session_id",
        "grant_sha384",
        "runtime_sha384",
        "evidence_sha384",
        "init_data_sha384",
        "recorder_key_sha384",
    ] {
        let mut client = ready();
        client.resource_nonce = None;
        let mut response: Value = serde_json::from_slice(&resource_response(&client)).unwrap();
        response[field] = "10"
            .repeat(if field == "session_id" { 32 } else { 48 })
            .into();
        assert_eq!(
            client.accept_resource_challenge_response(&serde_json::to_vec(&response).unwrap()),
            Err(ClientError::BindingMismatch)
        );
        assert!(client.request_nonce().is_none());
    }
}

#[test]
fn near_bound_runtime_fits_the_base64_response_envelope() {
    let (wire, expected, recorder, _) = inputs();
    let keywrap = TeePubKey::EC {
        crv: "c".repeat(4000),
        alg: "a".repeat(4000),
        x: "x".repeat(4000),
        y: "y".repeat(4000),
    };
    let mut client = ClientProtocol::new(wire, &expected, 100, recorder, keywrap, [8; 48]).unwrap();
    let response = begin_response(&client);
    let mut value: Value = serde_json::from_slice(&response).unwrap();
    let runtime = STANDARD
        .decode(value["canonical_runtime_b64"].as_str().unwrap())
        .unwrap();
    assert!(runtime.len() <= 16 * 1024);
    assert!(response.len() > 16 * 1024 && response.len() < 32 * 1024);
    client.accept_begin_response(&response).unwrap();
    value["canonical_runtime_b64"] = STANDARD.encode(vec![b'x'; MAX_RUNTIME_BYTES + 1]).into();
    assert_eq!(
        client.accept_begin_response(&serde_json::to_vec(&value).unwrap()),
        Err(ClientError::TooLarge)
    );
}

#[test]
fn aggregate_verification_uses_independent_expectations_and_own_submitted_request() {
    let mut client = ready();
    let request = request(&client);
    client.resource_decision_request(&request).unwrap();
    let proof = key();
    let statement = LaunchPolicyAggregateV1 {
        version: POLICY_AGGREGATE_VERSION,
        purpose: POLICY_AGGREGATE_PURPOSE.into(),
        audience: "policy-consumer".into(),
        issuer: "combined-producer".into(),
        profile: POLICY_AGGREGATE_PROFILE.into(),
        grant_sha384: client.grant.grant_digest().into(),
        authority_key_sha384: client.grant.authority_key_sha384().into(),
        session_id: client.session_id().unwrap().into(),
        nonce: client.quote_nonce().unwrap().into(),
        runtime_sha384: hex(&client.report_data().unwrap()),
        init_data_sha384: hex(&client.expected_init),
        evidence_sha384: hash(client.evidence().unwrap()),
        recorder_key_sha384: client.grant.binding().channel_key_sha384.clone(),
        request,
        as_evaluation: PolicyCommitments {
            policy_id: "launch_cpu".into(),
            policy_sha384: client.grant.binding().launch_policy_sha384.clone(),
            input_sha384: "0c".repeat(48),
            data_sha384: None,
        },
        kbs_evaluation: PolicyCommitments {
            policy_id: "resource-policy".into(),
            policy_sha384: "0d".repeat(48),
            input_sha384: "0e".repeat(48),
            data_sha384: Some("0f".repeat(48)),
        },
    };
    let mut expected = AggregateExpectations {
        kbs_proof_public_key: proof.public_key().as_ref().try_into().unwrap(),
        expected: statement,
    };
    let sign = |s: &LaunchPolicyAggregateV1, k: &Ed25519KeyPair| {
        serde_json::to_vec(&Signed {
            statement: s.clone(),
            signature: hex(k.sign(&s.signing_bytes().unwrap()).as_ref()),
        })
        .unwrap()
    };
    assert!(client
        .verify_aggregate(&sign(&expected.expected, &proof), &expected)
        .is_ok());
    assert!(matches!(
        client.verify_aggregate(&sign(&expected.expected, &key()), &expected),
        Err(ClientError::Contract(
            execution_proof_contract::Error::InvalidSignature
        ))
    ));
    expected.expected.request.resource_path[2] = "other-resource".into();
    assert!(matches!(
        client.verify_aggregate(&sign(&expected.expected, &proof), &expected),
        Err(ClientError::BindingMismatch)
    ));
}

fn credential_fixture(jwe: &[u8]) -> (ClientProtocol, DeliveryExpectations, Vec<u8>, Vec<u8>) {
    use execution_proof_contract::credential::{
        CredentialDeliveryV1, CREDENTIAL_DELIVERY_PROFILE, CREDENTIAL_DELIVERY_PURPOSE,
        CREDENTIAL_DELIVERY_VERSION,
    };
    let mut client = ready();
    let request = request(&client);
    client.resource_decision_request(&request).unwrap();
    let producer = key();
    let statement = LaunchPolicyAggregateV1 {
        version: POLICY_AGGREGATE_VERSION,
        purpose: POLICY_AGGREGATE_PURPOSE.into(),
        audience: "aggregate-consumer".into(),
        issuer: "aggregate-producer".into(),
        profile: POLICY_AGGREGATE_PROFILE.into(),
        grant_sha384: client.grant.grant_digest().into(),
        authority_key_sha384: client.grant.authority_key_sha384().into(),
        session_id: client.session_id().unwrap().into(),
        nonce: client.quote_nonce().unwrap().into(),
        runtime_sha384: hex(&client.report_data().unwrap()),
        init_data_sha384: hex(&client.expected_init),
        evidence_sha384: hash(client.evidence().unwrap()),
        recorder_key_sha384: client.grant.binding().channel_key_sha384.clone(),
        request,
        as_evaluation: PolicyCommitments {
            policy_id: "launch_cpu".into(),
            policy_sha384: client.grant.binding().launch_policy_sha384.clone(),
            input_sha384: "0c".repeat(48),
            data_sha384: None,
        },
        kbs_evaluation: PolicyCommitments {
            policy_id: "resource-launch".into(),
            policy_sha384: "0d".repeat(48),
            input_sha384: "0e".repeat(48),
            data_sha384: Some("0f".repeat(48)),
        },
    };
    let receipt = CredentialDeliveryV1 {
        version: CREDENTIAL_DELIVERY_VERSION,
        purpose: CREDENTIAL_DELIVERY_PURPOSE.into(),
        audience: "credential-consumer".into(),
        issuer: "credential-producer".into(),
        profile: CREDENTIAL_DELIVERY_PROFILE.into(),
        grant_sha384: statement.grant_sha384.clone(),
        aggregate_sha384: statement.digest_sha384().unwrap(),
        request_sha384: statement.request.digest_sha384().unwrap(),
        session_id: statement.session_id.clone(),
        runtime_sha384: statement.runtime_sha384.clone(),
        evidence_sha384: statement.evidence_sha384.clone(),
        init_data_sha384: statement.init_data_sha384.clone(),
        recorder_key_sha384: statement.recorder_key_sha384.clone(),
        keywrap_sha384: client.key_sha384.clone(),
        ciphertext_sha384: hash(jwe),
        workflow_id: statement.request.workflow_id.clone(),
        resource_path: statement.request.resource_path.clone(),
        validity: *client.grant.validity(),
    };
    let aggregate = serde_json::to_vec(&Signed {
        signature: hex(producer.sign(&statement.signing_bytes().unwrap()).as_ref()),
        statement: statement.clone(),
    })
    .unwrap();
    let receipt = serde_json::to_vec(&Signed {
        signature: hex(producer.sign(&receipt.signing_bytes().unwrap()).as_ref()),
        statement: receipt,
    })
    .unwrap();
    let expected = DeliveryExpectations {
        aggregate: AggregateExpectations {
            kbs_proof_public_key: producer.public_key().as_ref().try_into().unwrap(),
            expected: statement,
        },
        audience: "credential-consumer".into(),
        issuer: "credential-producer".into(),
        keywrap_sha384: client.key_sha384.clone(),
    };
    let response = serde_json::to_vec(
        &json!({"signed_delivery_b64":STANDARD.encode(receipt),"jwe_b64":STANDARD.encode(jwe)}),
    )
    .unwrap();
    (client, expected, aggregate, response)
}

#[test]
fn credential_request_has_own_operation_domain_and_exact_aggregate_context() {
    let (client, expected, aggregate, _) = credential_fixture(b"jwe");
    let request = client
        .credential_request(&aggregate, &expected.aggregate)
        .unwrap();
    assert_eq!(
        request,
        client
            .credential_request(&aggregate, &expected.aggregate)
            .unwrap()
    );
    let request: Value = serde_json::from_slice(&request).unwrap();
    let a = &expected.aggregate.expected;
    let op = SessionOperation::CredentialDelivery {
        session_id: a.session_id.clone(),
        nonce: a.request.request_nonce.clone(),
        runtime_sha384: a.runtime_sha384.clone(),
        evidence_sha384: a.evidence_sha384.clone(),
        request_sha384: a.request.digest_sha384().unwrap(),
        aggregate_sha384: a.digest_sha384().unwrap(),
    };
    let public = client.recorder.public_key().as_ref().try_into().unwrap();
    verify_operation_pop(
        &client.grant,
        &op,
        &public,
        request["signature_hex"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(request["aggregate_sha384"], a.digest_sha384().unwrap());
    assert_eq!(client.expected_init_data(), [8; 48]);
}

#[test]
fn credential_response_authenticates_origin_ciphertext_recipient_and_current_window() {
    let (client, mut expected, aggregate, response) = credential_fixture(b"exact-jwe");
    let verified = client
        .verify_credential_response(&response, &aggregate, &expected, 100)
        .unwrap();
    assert_eq!(verified.jwe_bytes(), b"exact-jwe");
    assert_eq!(verified.delivery().ciphertext_sha384(), hash(b"exact-jwe"));
    assert_eq!(
        client
            .verify_credential_response(&response, &aggregate, &expected, 200)
            .err(),
        Some(ClientError::Contract(
            execution_proof_contract::Error::Expired
        ))
    );
    expected.keywrap_sha384 = "99".repeat(48);
    assert_eq!(
        client
            .verify_credential_response(&response, &aggregate, &expected, 100)
            .err(),
        Some(ClientError::BindingMismatch)
    );
    expected.keywrap_sha384 = client.key_sha384.clone();
    let mut forged: Value = serde_json::from_slice(&response).unwrap();
    forged["jwe_b64"] = STANDARD.encode(b"attacker-encrypted-to-public-key").into();
    assert_eq!(
        client
            .verify_credential_response(
                &serde_json::to_vec(&forged).unwrap(),
                &aggregate,
                &expected,
                100
            )
            .err(),
        Some(ClientError::Contract(
            execution_proof_contract::Error::BindingMismatch
        ))
    );
    expected.aggregate.kbs_proof_public_key = key().public_key().as_ref().try_into().unwrap();
    assert_eq!(
        client
            .verify_credential_response(&response, &aggregate, &expected, 100)
            .err(),
        Some(ClientError::Contract(
            execution_proof_contract::Error::InvalidSignature
        ))
    );
}

#[test]
fn credential_envelope_bounds_and_unknown_duplicate_fields_are_strict() {
    let payload = vec![0; MAX_CREDENTIAL_JWE_BYTES];
    let (client, expected, aggregate, response) = credential_fixture(&payload);
    assert!(response.len() < MAX_CREDENTIAL_RESPONSE_BYTES);
    assert_eq!(
        client
            .verify_credential_response(&response, &aggregate, &expected, 100)
            .unwrap()
            .jwe_bytes()
            .len(),
        payload.len()
    );
    let mut malformed: Value = serde_json::from_slice(&response).unwrap();
    malformed["jwe_b64"] = STANDARD
        .encode(vec![0; MAX_CREDENTIAL_JWE_BYTES + 1])
        .into();
    assert_eq!(
        client
            .verify_credential_response(
                &serde_json::to_vec(&malformed).unwrap(),
                &aggregate,
                &expected,
                100
            )
            .err(),
        Some(ClientError::TooLarge)
    );
    malformed["caller_accepted"] = true.into();
    assert_eq!(
        client
            .verify_credential_response(
                &serde_json::to_vec(&malformed).unwrap(),
                &aggregate,
                &expected,
                100
            )
            .err(),
        Some(ClientError::Malformed)
    );
    let duplicate = String::from_utf8(response)
        .unwrap()
        .replacen("{", "{\"jwe_b64\":\"AAAA\",", 1);
    assert_eq!(
        client
            .verify_credential_response(duplicate.as_bytes(), &aggregate, &expected, 100)
            .err(),
        Some(ClientError::Malformed)
    );
    assert_eq!(
        client
            .verify_credential_response(
                &vec![0; MAX_CREDENTIAL_RESPONSE_BYTES + 1],
                &aggregate,
                &expected,
                100
            )
            .err(),
        Some(ClientError::TooLarge)
    );
}

#[test]
fn authority_time_client_authenticates_without_a_guest_clock_but_cannot_mint_permission() {
    let (wire, expected, recorder, keywrap) = inputs();
    assert_eq!(
        verify_launch_grant(&wire, &expected, 200).err(),
        Some(execution_proof_contract::Error::Expired)
    );
    let client =
        ClientProtocol::new_authority_time(wire, &expected, recorder, keywrap, [8; 48]).unwrap();
    assert_eq!(client.grant().validity().expires, 200);
    assert!(client.begin_request().is_ok());
    let (mut forged, expected, recorder, keywrap) = inputs();
    let raw: Value = serde_json::from_slice(&forged).unwrap();
    let mut raw = raw;
    raw["statement"]["binding"]["boot_id"] = "other-boot".into();
    forged = serde_json::to_vec(&raw).unwrap();
    assert_eq!(
        ClientProtocol::new_authority_time(forged, &expected, recorder, keywrap, [8; 48]).err(),
        Some(ClientError::Contract(
            execution_proof_contract::Error::InvalidSignature
        ))
    );
}

#[test]
fn authority_time_credential_response_authenticates_a_delayed_committed_publication() {
    let (client, expected, aggregate, response) = credential_fixture(b"exact-jwe");
    let verified = client
        .verify_credential_response_historical(&response, &aggregate, &expected)
        .unwrap();
    assert_eq!(verified.jwe_bytes(), b"exact-jwe");
    assert_eq!(verified.delivery().validity().expires, 200);
    assert_eq!(
        client
            .verify_credential_response(&response, &aggregate, &expected, 200)
            .err(),
        Some(ClientError::Contract(
            execution_proof_contract::Error::Expired
        ))
    );
    let mut changed: Value = serde_json::from_slice(&response).unwrap();
    changed["jwe_b64"] = STANDARD.encode(b"substituted").into();
    assert_eq!(
        client
            .verify_credential_response_historical(
                &serde_json::to_vec(&changed).unwrap(),
                &aggregate,
                &expected
            )
            .err(),
        Some(ClientError::Contract(
            execution_proof_contract::Error::BindingMismatch
        ))
    );
}
