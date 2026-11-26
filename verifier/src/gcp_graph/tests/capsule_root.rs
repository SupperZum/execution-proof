//! Create public capsule inputs for the isolated EROFS loader test.
use super::*;
use execution_proof_contract::{
    gcp_artifact::{validate_config_core, BootArtifactManifestV1, ReferencePolicySetV1},
    gcp_boot_binding::GcpBootBindingV1,
    gcp_startup::{GcpAttemptPlanV1, GcpRoleCapsuleV1, CAPSULE_PURPOSE, PLAN_PURPOSE},
};
use std::{fs, path::PathBuf};

#[test]
#[ignore = "requires an EROFS test root prepared by the native loader fixture"]
fn prepare_native_capsules() {
    let dir = PathBuf::from(std::env::var_os("CAPSULE_FIXTURE_DIR").unwrap());
    let c = fs::read(dir.join("root/onb17/boot/config.json")).unwrap();
    let d = fs::read(dir.join("root/onb17/boot/producer-core.json")).unwrap();
    let (cfg, _) = validate_config_core(&c, &d).unwrap();
    let test_key = |seed| Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    let (authority, proof, build, reference) =
        (test_key(1), test_key(4), test_key(201), test_key(202));
    assert_eq!(cfg.roots.authority_public_key, public(&authority));
    assert_eq!(cfg.roots.kbs_proof_public_key, public(&proof));
    assert_eq!(cfg.roots.build_public_key, public(&build));
    assert_eq!(cfg.roots.reference_public_key, public(&reference));

    let (pack, trust, _) = fixture();
    let object = |kind| {
        &pack
            .execution
            .objects
            .iter()
            .find(|o| o.kind == kind)
            .unwrap()
            .bytes
    };
    let mut a = serde_json::from_slice::<Signed<BootArtifactManifestV1>>(object(
        ObjectKind::GcpArtifactManifest,
    ))
    .unwrap()
    .statement;
    a.config_sha384 = hash(&c);
    a.producer_core_sha384 = hash(&d);
    let a = signed(a.clone(), &a.signing_bytes().unwrap(), &build);
    let mut v = serde_json::from_slice::<Signed<ReferencePolicySetV1>>(object(
        ObjectKind::GcpReferencePolicy,
    ))
    .unwrap()
    .statement;
    v.artifact_manifest_sha384 = hash(&a);
    let v = signed(v.clone(), &v.signing_bytes().unwrap(), &reference);
    let boot = GcpBootBindingV1::new(digest(&c), digest(&d), digest(&a), digest(&v)).unwrap();
    let spec = br#"{"fixture":"capsule"}"#;
    let bundle = AdmissionBundle::decode(&pack.execution.admission, MAX_PROVENANCE_BYTES).unwrap();
    let mut grant = serde_json::from_slice::<Signed<LaunchGrant>>(&bundle.grant)
        .unwrap()
        .statement;
    grant.audience = cfg.grant_audience.clone();
    grant.binding.authority = cfg.authority.clone();
    grant.binding.tenant = cfg.tenant.clone();
    grant.binding.profile_sha384 = boot.digest_sha384().unwrap();
    grant.binding.launch_policy_sha384 = cfg.launch_policy_sha384.clone();
    grant.binding.image_policy_sha384 = cfg.image_policy_sha384.clone();
    grant.binding.effective_launch_sha384 = hash(spec);
    let grant_digest = grant.digest_sha384().unwrap();
    let grant_wire = signed(grant.clone(), &grant.signing_bytes().unwrap(), &authority);

    let verified_grant = verify_launch_grant_historical(
        &grant_wire,
        &GrantExpectations {
            authority_public_key: public(&authority),
            audience: cfg.grant_audience.clone(),
            authority: cfg.authority.clone(),
            tenant: cfg.tenant.clone(),
            profile_sha384: boot.digest_sha384().unwrap(),
            launch_policy_sha384: cfg.launch_policy_sha384.clone(),
            image_policy_sha384: cfg.image_policy_sha384.clone(),
        },
    )
    .unwrap();
    for case in ["valid", "spec", "resource", "workflow"] {
        let mut agg = trust.aggregate_expected.clone();
        agg.grant_sha384 = grant_digest.clone();
        agg.authority_key_sha384 = hash(&public(&authority));
        agg.boot_binding_sha384 = boot.digest_sha384().unwrap();
        agg.audience = cfg.aggregate_audience.clone();
        agg.request.resource_path = cfg.resource_path.clone();
        agg.request.workflow_id = cfg.workflow_id.clone();
        if case == "resource" {
            agg.request.resource_path[2] = "other-resource".into();
        }
        if case == "workflow" {
            agg.request.workflow_id = "other-workflow".into();
        }
        let plan = GcpAttemptPlanV1 {
            version: 1,
            purpose: PLAN_PURPOSE.into(),
            authority: cfg.authority.clone(),
            boot_binding: boot.clone(),
            grant_sha384: grant_digest.clone(),
            aggregate_sha384: agg.digest_sha384().unwrap(),
            admission_policy_sha384: hash(b"admission"),
            container_id: "fixture".into(),
            execution_audience: "test".into(),
            execution_nonce_hex: "11".repeat(32),
            effective_spec_sha384: hash(spec),
            trust_snapshot_sha384: hash(b"trust"),
        };
        let agg_wire = signed(agg.clone(), &agg.signing_bytes().unwrap(), &proof);
        let plan_wire = signed(plan.clone(), &plan.signing_bytes().unwrap(), &authority);
        let verified_aggregate = verify_policy_aggregate(
            &agg_wire,
            &verified_grant,
            &GcpAggregateExpectations {
                kbs_proof_public_key: public(&proof),
                boot_binding: boot.clone(),
                expected: agg,
            },
        )
        .unwrap();
        execution_proof_contract::gcp_startup::verify_attempt_plan(
            &plan_wire,
            &public(&authority),
            &verified_grant,
            &verified_aggregate,
            &boot,
        )
        .unwrap();
        let capsule = GcpRoleCapsuleV1 {
            version: 1,
            purpose: CAPSULE_PURPOSE.into(),
            signed_manifest: a.clone(),
            signed_references: v.clone(),
            signed_grant: grant_wire.clone(),
            signed_aggregate: agg_wire,
            signed_plan: plan_wire,
            effective_spec: if case == "spec" {
                b"{}".to_vec()
            } else {
                spec.to_vec()
            },
        };
        fs::write(dir.join(format!("{case}.json")), capsule.encode().unwrap()).unwrap();
    }
}
