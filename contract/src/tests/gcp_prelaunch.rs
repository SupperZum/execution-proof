use crate::{
    gcp_boot_binding::GcpBootBindingV1, gcp_credential as credential, gcp_policy_receipt as policy,
    gcp_session as session, *,
};
use ring::signature::{Ed25519KeyPair, KeyPair};

fn public(key: &Ed25519KeyPair) -> [u8; 32] {
    key.public_key().as_ref().try_into().unwrap()
}
fn signed<T: Serialize + Clone>(statement: &T, bytes: &[u8], key: &Ed25519KeyPair) -> Vec<u8> {
    serde_json::to_vec(&Signed {
        statement: statement.clone(),
        signature: hex(key.sign(bytes).as_ref()),
    })
    .unwrap()
}

struct Fixture {
    grant: VerifiedLaunchGrant,
    boot: GcpBootBindingV1,
    recorder: Ed25519KeyPair,
    kbs: Ed25519KeyPair,
    aggregate: policy::GcpLaunchPolicyAggregateV2,
    delivery: credential::GcpCredentialDeliveryV2,
}

#[test]
fn independent_python_golden_commits_every_family_to_the_same_grant_and_boot_binding() {
    let f = Fixture::new();
    assert_eq!(f.grant.grant_digest(), "b5ed38b6f07346417df3dc6cc2a81774f499c92f6d5fdc10d2be0e1e1ffb0c911678b60ebcc0c10548f81c3b31ab582c");
    assert_eq!(f.aggregate.digest_sha384().unwrap(), "0de5ba681b2cb401ab915b3c9a18ebe77f9c79715adb0134059ba166151a2aa2b432c10cc7d0c1eb3f061169ba5177ea");
    assert_eq!(f.delivery.digest_sha384().unwrap(), "f111aa07ea93e02bd8e57b72b73b04bfbe0930453c91833b568402da8d3aed80aad5ec78c59f07787de333ef0604f223");
    let operation = session::operation_signing_bytes(
        &f.grant,
        &f.boot,
        &session::SessionOperation::Begin {
            key_sha384: "17".repeat(48),
        },
    )
    .unwrap();
    assert_eq!(sha384(&operation), "96a99890eea08e661881d99756e4fdf39918e88d32424e195b665d84fdbaa2aa4af6c091c575416ea8c47bfa2002102e");
    assert_eq!(operation.len(), 451);
    assert_eq!(f.aggregate.signing_bytes().unwrap().len(), 1400);
    assert_eq!(f.delivery.signing_bytes().unwrap().len(), 1201);
    let aggregate_wire = signed(&f.aggregate, &f.aggregate.signing_bytes().unwrap(), &f.kbs);
    assert!(
        crate::decode::<Signed<crate::policy_receipt::LaunchPolicyAggregateV1>>(&aggregate_wire)
            .is_err()
    );
    let delivery_wire = signed(&f.delivery, &f.delivery.signing_bytes().unwrap(), &f.kbs);
    assert!(
        crate::decode::<Signed<crate::credential::CredentialDeliveryV1>>(&delivery_wire).is_err()
    );
}
impl Fixture {
    fn new() -> Self {
        let authority = Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
        let recorder = Ed25519KeyPair::from_seed_unchecked(&[2; 32]).unwrap();
        let kbs = Ed25519KeyPair::from_seed_unchecked(&[3; 32]).unwrap();
        let boot = GcpBootBindingV1::new([1; 48], [2; 48], [3; 48], [4; 48]).unwrap();
        let raw = LaunchGrant {
            version: VERSION,
            purpose: GRANT_PURPOSE.into(),
            audience: "gcp-issuer".into(),
            proof_required: true,
            grant_id: "grant-one".into(),
            validity: ValidityWindow {
                not_before: 100,
                expires: 300,
            },
            binding: LaunchBinding {
                authority: "authority-one".into(),
                tenant: "tenant-one".into(),
                workload_id: "workload-one".into(),
                container_role: "application-init".into(),
                attempt_id: "attempt-one".into(),
                boot_id: "boot-one".into(),
                channel_key_sha384: sha384(&public(&recorder)),
                bootstrap_context_sha384: "10".repeat(48),
                selected_manifest_sha256: "14".repeat(32),
                effective_launch_sha384: "15".repeat(48),
                profile_sha384: boot.digest_sha384().unwrap(),
                launch_policy_sha384: "11".repeat(48),
                image_policy_sha384: "12".repeat(48),
                challenge_sha384: "13".repeat(48),
            },
        };
        let wire = signed(&raw, &raw.signing_bytes().unwrap(), &authority);
        let expected = GrantExpectations {
            authority_public_key: public(&authority),
            audience: raw.audience.clone(),
            authority: raw.binding.authority.clone(),
            tenant: raw.binding.tenant.clone(),
            profile_sha384: boot.digest_sha384().unwrap(),
            launch_policy_sha384: "11".repeat(48),
            image_policy_sha384: "12".repeat(48),
        };
        let grant = verify_launch_grant(&wire, &expected, 150).unwrap();
        let commitments = |id: &str, hash: &str| crate::policy_receipt::PolicyCommitments {
            policy_id: id.into(),
            policy_sha384: hash.repeat(48),
            input_sha384: "19".repeat(48),
            data_sha384: None,
        };
        let aggregate = policy::GcpLaunchPolicyAggregateV2 {
            version: policy::POLICY_AGGREGATE_VERSION,
            purpose: policy::POLICY_AGGREGATE_PURPOSE.into(),
            audience: "gcp-policy".into(),
            issuer: "kbs-one".into(),
            profile: policy::POLICY_AGGREGATE_PROFILE.into(),
            grant_sha384: grant.grant_digest().into(),
            authority_key_sha384: grant.authority_key_sha384().into(),
            session_id: "20".repeat(32),
            nonce: "nonce-one".into(),
            runtime_sha384: "21".repeat(48),
            boot_binding_sha384: boot.digest_sha384().unwrap(),
            evidence_sha384: "22".repeat(48),
            recorder_key_sha384: sha384(&public(&recorder)),
            request: crate::policy_receipt::ResourcePolicyRequest {
                method: "GET".into(),
                plugin: "resource".into(),
                resource_path: ["repo".into(), "kind".into(), "image".into()],
                workflow_id: "workflow-one".into(),
                request_nonce: "request-one".into(),
            },
            as_evaluation: commitments("as-one", "11"),
            kbs_evaluation: commitments("kbs-one", "16"),
        };
        let delivery = credential::GcpCredentialDeliveryV2 {
            version: credential::CREDENTIAL_DELIVERY_VERSION,
            purpose: credential::CREDENTIAL_DELIVERY_PURPOSE.into(),
            audience: "gcp-delivery".into(),
            issuer: "kbs-one".into(),
            profile: credential::CREDENTIAL_DELIVERY_PROFILE.into(),
            grant_sha384: grant.grant_digest().into(),
            aggregate_sha384: aggregate.digest_sha384().unwrap(),
            request_sha384: aggregate.request.digest_sha384().unwrap(),
            session_id: aggregate.session_id.clone(),
            runtime_sha384: aggregate.runtime_sha384.clone(),
            evidence_sha384: aggregate.evidence_sha384.clone(),
            boot_binding_sha384: boot.digest_sha384().unwrap(),
            recorder_key_sha384: aggregate.recorder_key_sha384.clone(),
            keywrap_sha384: "17".repeat(48),
            ciphertext_sha384: sha384(b"dummy-jwe-ciphertext"),
            workflow_id: aggregate.request.workflow_id.clone(),
            resource_path: aggregate.request.resource_path.clone(),
            validity: raw.validity,
        };
        Self {
            grant,
            boot,
            recorder,
            kbs,
            aggregate,
            delivery,
        }
    }
    fn expected(&self) -> policy::GcpAggregateExpectations {
        policy::GcpAggregateExpectations {
            kbs_proof_public_key: public(&self.kbs),
            boot_binding: self.boot.clone(),
            expected: self.aggregate.clone(),
        }
    }
    fn delivery_expected(&self) -> credential::GcpDeliveryExpectations {
        credential::GcpDeliveryExpectations {
            aggregate: self.expected(),
            audience: "gcp-delivery".into(),
            issuer: "kbs-one".into(),
            keywrap_sha384: "17".repeat(48),
        }
    }
    fn verified_aggregate(&self) -> policy::VerifiedGcpPolicyAggregate {
        policy::verify_policy_aggregate(
            &signed(
                &self.aggregate,
                &self.aggregate.signing_bytes().unwrap(),
                &self.kbs,
            ),
            &self.grant,
            &self.expected(),
        )
        .unwrap()
    }
}

#[test]
fn genuine_signatures_authenticate_gcp_statements_without_minting_hardware_claims() {
    let f = Fixture::new();
    let aggregate = f.verified_aggregate();
    let wire = signed(&f.delivery, &f.delivery.signing_bytes().unwrap(), &f.kbs);
    let publication = credential::verify_credential_delivery(
        &wire,
        &f.grant,
        &aggregate,
        &f.delivery_expected(),
        b"dummy-jwe-ciphertext",
        150,
    )
    .unwrap();
    assert_eq!(
        publication.statement().boot_binding_sha384,
        f.boot.digest_sha384().unwrap()
    );
    assert!(credential::verify_credential_delivery(
        &wire,
        &f.grant,
        &aggregate,
        &f.delivery_expected(),
        b"dummy-jwe-ciphertext",
        300
    )
    .is_err());
    assert!(credential::verify_credential_metadata_historical(
        &wire,
        &f.grant,
        &aggregate,
        &f.delivery_expected()
    )
    .is_ok());
    let bytes = session::recorder_session_signing_bytes(
        &f.grant,
        &f.boot,
        "nonce",
        "21".repeat(48).as_str(),
        "22".repeat(48).as_str(),
    )
    .unwrap();
    let signature = hex(f.recorder.sign(&bytes).as_ref());
    let verified = session::verify_recorder_session_pop(
        &f.grant,
        &f.boot,
        "nonce",
        &"21".repeat(48),
        &"22".repeat(48),
        &public(&f.recorder),
        &signature,
    )
    .unwrap();
    assert_eq!(
        verified.boot_binding_sha384(),
        f.boot.digest_sha384().unwrap()
    );
}

#[test]
fn legacy_signatures_and_gcp_signatures_cannot_cross_session_or_operation_domains() {
    let f = Fixture::new();
    let op = session::SessionOperation::Begin {
        key_sha384: "17".repeat(48),
    };
    let old = crate::session::operation_signing_bytes(&f.grant, &op).unwrap();
    let new = session::operation_signing_bytes(&f.grant, &f.boot, &op).unwrap();
    assert_ne!(old, new);
    assert!(session::verify_operation_pop(
        &f.grant,
        &f.boot,
        &op,
        &public(&f.recorder),
        &hex(f.recorder.sign(&old).as_ref())
    )
    .is_err());
    assert!(crate::session::verify_operation_pop(
        &f.grant,
        &op,
        &public(&f.recorder),
        &hex(f.recorder.sign(&new).as_ref())
    )
    .is_err());
    assert!(session::verify_operation_pop(
        &f.grant,
        &f.boot,
        &op,
        &public(&f.recorder),
        &hex(f.recorder.sign(&new).as_ref())
    )
    .is_ok());
    let old = crate::session::recorder_session_signing_bytes(
        &f.grant,
        "n",
        &"21".repeat(48),
        &"22".repeat(48),
    )
    .unwrap();
    assert!(session::verify_recorder_session_pop(
        &f.grant,
        &f.boot,
        "n",
        &"21".repeat(48),
        &"22".repeat(48),
        &public(&f.recorder),
        &hex(f.recorder.sign(&old).as_ref())
    )
    .is_err());
}

#[test]
fn separately_selected_boot_binding_cannot_be_reenrolled_by_matching_public_fields() {
    let f = Fixture::new();
    for part in 0..4 {
        let mut selected = f.boot.clone();
        match part {
            0 => selected.config_sha384 = "33".repeat(48),
            1 => selected.producer_core_sha384 = "33".repeat(48),
            2 => selected.artifact_manifest_sha384 = "33".repeat(48),
            _ => selected.reference_policy_sha384 = "33".repeat(48),
        };
        assert!(session::operation_signing_bytes(
            &f.grant,
            &selected,
            &session::SessionOperation::Begin {
                key_sha384: "17".repeat(48)
            }
        )
        .is_err());
        let mut expected = f.expected();
        expected.boot_binding = selected.clone();
        expected.expected.boot_binding_sha384 = selected.digest_sha384().unwrap();
        let wire = signed(
            &expected.expected,
            &expected.expected.signing_bytes().unwrap(),
            &f.kbs,
        );
        assert!(policy::verify_policy_aggregate(&wire, &f.grant, &expected).is_err());
    }
}

#[test]
fn signed_aggregate_and_delivery_substitutions_cannot_escape_expected_context() {
    let f = Fixture::new();
    let aggregate = f.verified_aggregate();
    for part in 0..8 {
        let mut changed = f.aggregate.clone();
        match part {
            0 => changed.boot_binding_sha384 = "33".repeat(48),
            1 => changed.grant_sha384 = "33".repeat(48),
            2 => changed.nonce.push('x'),
            3 => changed.runtime_sha384 = "33".repeat(48),
            4 => changed.evidence_sha384 = "33".repeat(48),
            5 => changed.as_evaluation.input_sha384 = "33".repeat(48),
            6 => changed.kbs_evaluation.policy_sha384 = "33".repeat(48),
            _ => changed.request.workflow_id.push('x'),
        };
        assert!(policy::verify_policy_aggregate(
            &signed(&changed, &changed.signing_bytes().unwrap(), &f.kbs),
            &f.grant,
            &f.expected()
        )
        .is_err());
    }
    for part in 0..8 {
        let mut changed = f.delivery.clone();
        match part {
            0 => changed.boot_binding_sha384 = "33".repeat(48),
            1 => changed.aggregate_sha384 = "33".repeat(48),
            2 => changed.request_sha384 = "33".repeat(48),
            3 => changed.keywrap_sha384 = "33".repeat(48),
            4 => changed.ciphertext_sha384 = "33".repeat(48),
            5 => changed.resource_path[0].push('x'),
            6 => changed.workflow_id.push('x'),
            _ => changed.validity.expires += 1,
        };
        let wire = signed(&changed, &changed.signing_bytes().unwrap(), &f.kbs);
        assert!(credential::verify_credential_delivery_historical(
            &wire,
            &f.grant,
            &aggregate,
            &f.delivery_expected(),
            b"dummy-jwe-ciphertext"
        )
        .is_err());
    }
    let foreign = Ed25519KeyPair::from_seed_unchecked(&[4; 32]).unwrap();
    assert!(policy::verify_policy_aggregate(
        &signed(
            &f.aggregate,
            &f.aggregate.signing_bytes().unwrap(),
            &foreign
        ),
        &f.grant,
        &f.expected()
    )
    .is_err());
    assert!(credential::verify_credential_delivery_historical(
        &signed(&f.delivery, &f.delivery.signing_bytes().unwrap(), &foreign),
        &f.grant,
        &aggregate,
        &f.delivery_expected(),
        b"dummy-jwe-ciphertext"
    )
    .is_err());
}

#[test]
fn unknown_mixed_peer_fields_versions_purposes_and_bounds_are_rejected() {
    let f = Fixture::new();
    let aggregate = f.verified_aggregate();
    let wire = signed(&f.aggregate, &f.aggregate.signing_bytes().unwrap(), &f.kbs);
    for field in [
        "version",
        "purpose",
        "profile",
        "audience",
        "issuer",
        "init_data_sha384",
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        value["statement"][field] = match field {
            "version" => 1.into(),
            "purpose" => crate::policy_receipt::POLICY_AGGREGATE_PURPOSE.into(),
            "profile" => crate::policy_receipt::POLICY_AGGREGATE_PROFILE.into(),
            _ => "legacy".into(),
        };
        assert!(policy::verify_policy_aggregate(
            &serde_json::to_vec(&value).unwrap(),
            &f.grant,
            &f.expected()
        )
        .is_err());
    }
    let wire = signed(&f.delivery, &f.delivery.signing_bytes().unwrap(), &f.kbs);
    for field in [
        "version",
        "purpose",
        "profile",
        "audience",
        "issuer",
        "init_data_sha384",
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        value["statement"][field] = match field {
            "version" => 1.into(),
            "purpose" => crate::credential::CREDENTIAL_DELIVERY_PURPOSE.into(),
            "profile" => crate::credential::CREDENTIAL_DELIVERY_PROFILE.into(),
            _ => "legacy".into(),
        };
        assert!(credential::verify_credential_metadata_historical(
            &serde_json::to_vec(&value).unwrap(),
            &f.grant,
            &aggregate,
            &f.delivery_expected()
        )
        .is_err());
    }
    assert!(policy::verify_policy_aggregate(
        &vec![b' '; MAX_WIRE_BYTES + 1],
        &f.grant,
        &f.expected()
    )
    .is_err());
    assert!(credential::verify_credential_delivery_historical(
        &wire,
        &f.grant,
        &aggregate,
        &f.delivery_expected(),
        &[]
    )
    .is_err());
    assert!(credential::verify_credential_delivery_historical(
        &wire,
        &f.grant,
        &aggregate,
        &f.delivery_expected(),
        &vec![0; credential::MAX_CREDENTIAL_JWE_BYTES + 1]
    )
    .is_err());
}

#[test]
fn startup_plan_authenticates_exact_attempt_and_cannot_be_a_generic_signing_input() {
    use crate::gcp_startup::*;
    let f = Fixture::new();
    let authority = Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
    let aggregate_wire = signed(&f.aggregate, &f.aggregate.signing_bytes().unwrap(), &f.kbs);
    let aggregate =
        policy::verify_policy_aggregate(&aggregate_wire, &f.grant, &f.expected()).unwrap();
    let plan = GcpAttemptPlanV1 {
        version: 1,
        purpose: PLAN_PURPOSE.into(),
        authority: f.grant.binding().authority.clone(),
        boot_binding: f.boot.clone(),
        grant_sha384: f.grant.grant_digest().into(),
        aggregate_sha384: aggregate.digest_sha384().into(),
        admission_policy_sha384: "aa".repeat(48),
        container_id: "task-alias".into(),
        execution_audience: "independent-verifier".into(),
        execution_nonce_hex: "ab".repeat(32),
        effective_spec_sha384: f.grant.binding().effective_launch_sha384.clone(),
        trust_snapshot_sha384: "ac".repeat(48),
    };
    let check =
        |wire: &[u8]| verify_attempt_plan(wire, &public(&authority), &f.grant, &aggregate, &f.boot);
    let wire = signed(&plan, &plan.signing_bytes().unwrap(), &authority);
    assert_eq!(check(&wire).unwrap(), plan);
    for mutate in [
        |p: &mut GcpAttemptPlanV1| p.grant_sha384 = "bb".repeat(48),
        |p: &mut GcpAttemptPlanV1| p.aggregate_sha384 = "bb".repeat(48),
        |p: &mut GcpAttemptPlanV1| p.effective_spec_sha384 = "bb".repeat(48),
        |p: &mut GcpAttemptPlanV1| p.boot_binding.config_sha384 = "bb".repeat(48),
    ] {
        let mut bad = plan.clone();
        mutate(&mut bad);
        assert!(check(&signed(&bad, &bad.signing_bytes().unwrap(), &authority)).is_err());
    }
    let mut changed = plan.clone();
    changed.execution_nonce_hex = "ad".repeat(32);
    let stale = serde_json::to_vec(&Signed {
        statement: changed,
        signature: hex(authority.sign(&plan.signing_bytes().unwrap()).as_ref()),
    })
    .unwrap();
    assert!(check(&stale).is_err());
    let other = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
    assert!(check(&signed(&plan, &plan.signing_bytes().unwrap(), &other)).is_err());
    for nonce in ["00".repeat(32), "AF".repeat(32), "ab".repeat(31)] {
        let mut bad = plan.clone();
        bad.execution_nonce_hex = nonce;
        assert!(bad.signing_bytes().is_err());
    }
}
#[test]
fn startup_capsule_has_distinct_domain_and_incremental_field_limits() {
    use crate::gcp_startup::*;
    let capsule = GcpRoleCapsuleV1 {
        version: 1,
        purpose: CAPSULE_PURPOSE.into(),
        signed_manifest: vec![1],
        signed_references: vec![2],
        signed_grant: vec![3],
        signed_aggregate: vec![4],
        signed_plan: vec![5],
        effective_spec: b"{}".to_vec(),
    };
    assert_eq!(
        GcpRoleCapsuleV1::decode(&capsule.encode().unwrap())
            .unwrap()
            .effective_spec,
        b"{}"
    );
    let mut wire: serde_json::Value = serde_json::from_slice(&capsule.encode().unwrap()).unwrap();
    wire["unknown"] = true.into();
    assert!(GcpRoleCapsuleV1::decode(&serde_json::to_vec(&wire).unwrap()).is_err());
    wire.as_object_mut().unwrap().remove("unknown");
    wire["signed_manifest"] = serde_json::json!(vec![1u8; (32 << 10) + 1]);
    assert!(GcpRoleCapsuleV1::decode(&serde_json::to_vec(&wire).unwrap()).is_err());
    assert!(GcpRoleCapsuleV1::decode(&vec![b' '; MAX_CAPSULE_BYTES + 1]).is_err());
}
