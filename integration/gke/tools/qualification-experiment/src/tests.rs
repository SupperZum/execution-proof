//! Software crypto/state controls only. Fixture quotes are deliberately signature
//! invalid; no success QVL summary/qualification is exported or production-built.
use super::*;
#[path = "../../../../../verifier/src/gcp_graph/tests/artifact_fixture.rs"]
mod artifact_fixture;
use execution_proof_contract::{
    bootstrap::{TenantIntent, TENANT_INTENT_PURPOSE},
    gcp_bootstrap::{
        bootstrap_possession_signing_bytes, report_data, GCP_BOOTSTRAP_BINDING_PURPOSE,
    },
    gcp_policy_receipt::{
        POLICY_AGGREGATE_PROFILE, POLICY_AGGREGATE_PURPOSE, POLICY_AGGREGATE_VERSION,
    },
    policy_receipt::{PolicyCommitments, ResourcePolicyRequest},
};
use execution_proof_verifier::{
    gcp_boot_evidence::{GcpInstanceIdentity, QuotePaddingPolicy},
    gcp_tdx_policy::{
        GCP_TDX_ALLOWED_ATTRIBUTES, GCP_TDX_POLICY_PURPOSE, INTEL_TDX_MODULE_1_5_34_MR_SEAM,
    },
};

struct Fixture {
    root: PathBuf,
    app: Experiment,
    kbs: Ed25519KeyPair,
    tenant: Ed25519KeyPair,
}
fn key(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}
fn write(path: &Path, value: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(value).unwrap();
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}
impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("onb17-qualification-test-{}", random_id().unwrap()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let encoded = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let authority = Ed25519KeyPair::from_pkcs8(encoded.as_ref()).unwrap();
        write(&root.join("authority.pk8"), encoded.as_ref());
        let kbs = key(3);
        let tenant = key(2);
        let module = GcpTdxModulePolicyV1 {
            version: 1,
            purpose: GCP_TDX_POLICY_PURPOSE.into(),
            expected_mr_seam: INTEL_TDX_MODULE_1_5_34_MR_SEAM.into(),
            allowed_td_attributes: GCP_TDX_ALLOWED_ATTRIBUTES,
        };
        let (c, d, a, v, expected) = artifact_fixture::artifact_fixture(
            [
                public(&authority).unwrap(),
                public(&kbs).unwrap(),
                public(&key(4)).unwrap(),
            ],
            "31".repeat(48),
            "32".repeat(48),
            "33".repeat(48),
            "34".repeat(48),
            hash(&module.encode().unwrap()),
        );
        for (name, value) in [("c", c), ("d", d), ("a", a), ("v", v)] {
            write(&root.join(name), &value)
        }
        let c: ClosedBootConfigV1 = decode(&std::fs::read(root.join("c")).unwrap()).unwrap();
        let t = now().unwrap();
        let intent = TenantIntent {
            version: 2,
            purpose: TENANT_INTENT_PURPOSE.into(),
            audience: c.grant_audience.clone(),
            authority: c.authority.clone(),
            tenant: c.tenant.clone(),
            workload_id: "qexp-workload".into(),
            container_role: "application-init".into(),
            attempt_id: "qexp-attempt".into(),
            selected_manifest_sha256: "44".repeat(32),
            effective_launch_sha384: "45".repeat(48),
            profile_sha384: expected.boot_binding.digest_sha384().unwrap(),
            launch_policy_sha384: c.launch_policy_sha384.clone(),
            image_policy_sha384: c.image_policy_sha384.clone(),
            validity: ValidityWindow {
                not_before: t - 1,
                expires: t + 240,
            },
        };
        let wire = signed(&tenant, intent.clone(), &intent.signing_bytes().unwrap()).unwrap();
        write(&root.join("intent"), &wire);
        let config = ExperimentConfig {
            version: 1,
            purpose: EXPERIMENT_PURPOSE.into(),
            retire_before: t + 240,
            window_seconds: 120,
            state_path: root.join("state"),
            artifacts: ArtifactPaths {
                config: root.join("c"),
                core: root.join("d"),
                manifest: root.join("a"),
                references: root.join("v"),
            },
            boot_policy: GcpBootEvidencePolicy {
                expected_pe_sha384: expected.pe_authenticode_sha384.clone(),
                expected_firmware_mrtd: expected.firmware_mrtd.clone(),
                expected_instance: GcpInstanceIdentity {
                    instance_id: 1,
                    numerical_project_id: 2,
                    zone: "us-central1-a".into(),
                },
                quote_padding: QuotePaddingPolicy::GcpTsmZeroPadded8000,
            },
            module_policy: module,
            artifact_expectations: expected,
            pregrant_worker_path: PathBuf::from("/bin/true"),
            pregrant_worker_sha384: hash(&std::fs::read("/bin/true").unwrap()),
            tenant_public_key: public(&tenant).unwrap(),
            signed_intent_path: root.join("intent"),
            signed_intent_sha384: hash(&wire),
            policy: PolicyScope {
                aggregate_issuer: "kbs".into(),
                as_policy_id: "as".into(),
                as_data_sha384: None,
                kbs_policy_id: "kbs".into(),
                kbs_policy_sha384: "46".repeat(48),
            },
            container_id: "qexp-task".into(),
            execution_audience: "qexp-evidence".into(),
        };
        write(&root.join("config"), &encode(&config).unwrap());
        write(&root.join("collateral"), b"{}");
        let app = Experiment::open(
            &root.join("config"),
            &root.join("authority.pk8"),
            &root.join("collateral"),
        )
        .unwrap();
        Self {
            root,
            app,
            kbs,
            tenant,
        }
    }
    fn reopen(&self) -> Result<Experiment> {
        Experiment::open(
            &self.root.join("config"),
            &self.root.join("authority.pk8"),
            &self.root.join("collateral"),
        )
    }
    fn save_config(&self, edit: impl FnOnce(&mut ExperimentConfig)) {
        let mut c: ExperimentConfig =
            decode(&std::fs::read(self.root.join("config")).unwrap()).unwrap();
        edit(&mut c);
        write(&self.root.join("config"), &encode(&c).unwrap());
    }
    fn state(&self) -> State {
        decode(&std::fs::read(self.root.join("state")).unwrap()).unwrap()
    }
    fn save_state(&self, state: &State) {
        write(&self.root.join("state"), &encode(state).unwrap())
    }
    fn submission(&self) -> Submission {
        let state = self.state();
        let challenge: Signed<GcpBootstrapChallenge> = decode(&state.signed_challenge).unwrap();
        let c = &challenge.statement;
        let keywrap = TeePubKey::RSA {
            alg: "RSA-OAEP-256".into(),
            k_mod: URL_SAFE_NO_PAD.encode([0xff; 256]),
            k_exp: "AQAB".into(),
        };
        let binding = GcpBootstrapBinding {
            version: 3,
            purpose: GCP_BOOTSTRAP_BINDING_PURPOSE.into(),
            challenge_sha384: c.digest_sha384().unwrap(),
            boot_binding_sha384: c.boot_binding.digest_sha384().unwrap(),
            boot_id: "qexp-boot".into(),
            boot_nonce_hex: "51".repeat(32),
            recorder_key_sha384: hash(&public(&key(5)).unwrap()),
            keywrap_key_sha384: keywrap_digest(&keywrap).unwrap(),
        };
        let mut evidence=GcpLaunchEvidenceV2::new(
            include_bytes!("../../../../../verifier/tests/fixtures/gcp_boot_v1/baseline-quote.bin").to_vec(),
            include_bytes!("../../../../../verifier/tests/fixtures/gcp_boot_v1/baseline-acpi-ccel.bin").to_vec(),
            include_bytes!("../../../../../verifier/tests/fixtures/gcp_boot_v1/baseline-ccel.bin").to_vec()).unwrap();
        // Editing REPORT_DATA invalidates the Intel signature. No hardware
        // success fixture exists in the CLI's issue path or these tests.
        evidence.tdx_quote[568..632].copy_from_slice(&report_data(c, &binding).unwrap());
        let signature = hex(key(5)
            .sign(&bootstrap_possession_signing_bytes(c, &binding, &evidence).unwrap())
            .as_ref());
        Submission {
            binding,
            evidence,
            recorder_public_key: public(&key(5)).unwrap(),
            possession_signature_hex: signature,
            keywrap_public_key: keywrap,
        }
    }
    // Test-only pre-issued software state for testing later signed transitions.
    // This deliberately does not exercise successful hardware issuance.
    fn software_issued(&self) {
        self.app.bootstrap_only().unwrap();
        let mut state = self.state();
        let submission = self.submission();
        let challenge: Signed<GcpBootstrapChallenge> = decode(&state.signed_challenge).unwrap();
        let c = challenge.statement;
        let t = &self.app.intent;
        let grant = LaunchGrant {
            version: VERSION,
            purpose: GRANT_PURPOSE.into(),
            audience: self.app.c.grant_audience.clone(),
            proof_required: true,
            grant_id: "qexp-software-state-only".into(),
            validity: c.validity,
            binding: LaunchBinding {
                authority: t.authority.clone(),
                tenant: t.tenant.clone(),
                workload_id: t.workload_id.clone(),
                container_role: t.container_role.clone(),
                attempt_id: t.attempt_id.clone(),
                boot_id: submission.binding.boot_id.clone(),
                channel_key_sha384: hash(&submission.recorder_public_key),
                bootstrap_context_sha384: bootstrap_context_sha384(
                    &c,
                    &submission.binding,
                    &submission.evidence,
                )
                .unwrap(),
                selected_manifest_sha256: t.selected_manifest_sha256.clone(),
                effective_launch_sha384: t.effective_launch_sha384.clone(),
                profile_sha384: t.profile_sha384.clone(),
                launch_policy_sha384: t.launch_policy_sha384.clone(),
                image_policy_sha384: t.image_policy_sha384.clone(),
                challenge_sha384: c.digest_sha384().unwrap(),
            },
        };
        state.signed_grant = Some(
            signed(
                &self.app.key,
                grant.clone(),
                &grant.signing_bytes().unwrap(),
            )
            .unwrap(),
        );
        state.submission = Some(submission);
        self.save_state(&state);
    }
    fn aggregate(&self) -> Vec<u8> {
        let grant = self.app.grant(&self.state()).unwrap();
        let p = &self.app.config.policy;
        let a = GcpLaunchPolicyAggregateV2 {
            version: POLICY_AGGREGATE_VERSION,
            purpose: POLICY_AGGREGATE_PURPOSE.into(),
            audience: self.app.c.aggregate_audience.clone(),
            issuer: p.aggregate_issuer.clone(),
            profile: POLICY_AGGREGATE_PROFILE.into(),
            grant_sha384: grant.grant_digest().into(),
            authority_key_sha384: grant.authority_key_sha384().into(),
            session_id: "52".repeat(32),
            nonce: "actual-kbs-challenge-fixture".into(),
            runtime_sha384: "53".repeat(48),
            boot_binding_sha384: grant.binding().profile_sha384.clone(),
            evidence_sha384: "54".repeat(48),
            recorder_key_sha384: grant.binding().channel_key_sha384.clone(),
            request: ResourcePolicyRequest {
                method: "GET".into(),
                plugin: "resource".into(),
                resource_path: self.app.c.resource_path.clone(),
                workflow_id: self.app.c.workflow_id.clone(),
                request_nonce: "resource-nonce".into(),
            },
            as_evaluation: PolicyCommitments {
                policy_id: p.as_policy_id.clone(),
                policy_sha384: self.app.c.launch_policy_sha384.clone(),
                input_sha384: "55".repeat(48),
                data_sha384: None,
            },
            kbs_evaluation: PolicyCommitments {
                policy_id: p.kbs_policy_id.clone(),
                policy_sha384: p.kbs_policy_sha384.clone(),
                input_sha384: "56".repeat(48),
                data_sha384: None,
            },
        };
        signed(&self.kbs, a.clone(), &a.signing_bytes().unwrap()).unwrap()
    }
    fn redemption(&self, nonce: &str) -> Vec<u8> {
        let state = self.state();
        let grant = self.app.grant(&state).unwrap();
        let aggregate = self
            .app
            .aggregate(state.aggregate.as_ref().unwrap(), &grant)
            .unwrap();
        let r = GcpAdmissionRequestV2::new(
            &grant,
            &aggregate,
            nonce,
            &self.app.admission_policy,
            &self.app.c.grant_audience,
            GcpAdmissionOperation::Redeem,
        )
        .unwrap();
        signed(&key(5), r.clone(), &r.signing_bytes().unwrap()).unwrap()
    }
}
#[test]
fn real_bootstrap_signature_no_qualification_or_permission_and_no_reinitialization() {
    let f = Fixture::new();
    let c_before = std::fs::read(f.root.join("c")).unwrap();
    let out = f.app.bootstrap_only().unwrap();
    assert_eq!(out["claim_status"], UNPROVEN);
    assert_eq!(out["permission_issued_now"], false);
    assert_eq!(out["producer_qualified"], false);
    let state = f.state();
    let signed: Signed<GcpBootstrapChallenge> = decode(&state.signed_challenge).unwrap();
    verify_challenge(
        &state.signed_challenge,
        &f.app.authority,
        &signed.statement,
        now().unwrap(),
    )
    .unwrap();
    assert!(signed.statement.validity.expires <= f.app.config.retire_before);
    assert!(f.app.bootstrap_only().is_err());
    assert_eq!(c_before, std::fs::read(f.root.join("c")).unwrap());
    assert!(state.signed_grant.is_none());
}
#[test]
fn operator_selected_scope_signature_key_and_window_fail_closed() {
    let f = Fixture::new();
    f.save_config(|c| c.window_seconds = 301);
    assert!(f.reopen().is_err());
    let f = Fixture::new();
    f.save_config(|c| c.container_id = "normal-container".into());
    assert!(f.reopen().is_err());
    let f = Fixture::new();
    let mut intent = f.app.intent.clone();
    intent.workload_id = "ordinary-workload".into();
    let wire = signed(&f.tenant, intent.clone(), &intent.signing_bytes().unwrap()).unwrap();
    write(&f.root.join("intent"), &wire);
    f.save_config(|c| c.signed_intent_sha384 = hash(&wire));
    assert!(f.reopen().is_err());
    let f = Fixture::new();
    let mut value: serde_json::Value =
        decode(&std::fs::read(f.root.join("config")).unwrap()).unwrap();
    value["qualification"] = serde_json::json!({"claim":"qualified"});
    write(&f.root.join("config"), &encode(&value).unwrap());
    assert!(f.reopen().is_err());
    let f = Fixture::new();
    let mut manifest: serde_json::Value =
        decode(&std::fs::read(f.root.join("a")).unwrap()).unwrap();
    manifest["signature"] = serde_json::json!("00".repeat(64));
    write(&f.root.join("a"), &encode(&manifest).unwrap());
    assert!(f.reopen().is_err());
}
#[test]
fn actual_pinned_nonworker_cannot_issue_and_bad_pop_never_mutates() {
    let f = Fixture::new();
    f.app.bootstrap_only().unwrap();
    let before = std::fs::read(f.root.join("state")).unwrap();
    let mut bad = f.submission();
    bad.possession_signature_hex = "00".repeat(64);
    assert!(f
        .app
        .request(Request::Issue {
            submission: Box::new(bad)
        })
        .is_err());
    assert!(f
        .app
        .request(Request::Issue {
            submission: Box::new(f.submission())
        })
        .is_err());
    assert_eq!(before, std::fs::read(f.root.join("state")).unwrap());
    assert!(f.state().signed_grant.is_none());
}
#[test]
fn state_mode_lock_and_corruption_have_no_reset_fallback() {
    let f = Fixture::new();
    f.app.bootstrap_only().unwrap();
    let state = f.root.join("state");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(f.app.status().is_err());
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
    let lock = open_state(&state, false).unwrap();
    assert!(f.app.status().is_err());
    drop(lock);
    assert!(f.app.status().is_ok());
    write(&state, b"broken state");
    assert!(f.app.status().is_err());
    assert!(f.app.bootstrap_only().is_err());
}
#[test]
fn operator_key_links_and_permissions_are_rejected() {
    let f = Fixture::new();
    let signer = f.root.join("authority.pk8");
    std::fs::set_permissions(&signer, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(f.reopen().is_err());
    std::fs::set_permissions(&signer, std::fs::Permissions::from_mode(0o600)).unwrap();
    let alias = f.root.join("key-alias");
    std::fs::hard_link(&signer, &alias).unwrap();
    assert!(f.reopen().is_err());
    std::fs::remove_file(&alias).unwrap();
    std::fs::rename(&signer, &alias).unwrap();
    std::os::unix::fs::symlink(&alias, &signer).unwrap();
    assert!(f.reopen().is_err());
}
#[test]
fn requests_cannot_supply_hardware_or_qualification_shortcuts() {
    for value in [
        serde_json::json!({"operation":"redeem","guest_nonce":"x","recorder_request_json":[],"verified":true}),
        serde_json::json!({"operation":"startup_plan","aggregate_json":[],"worker":"/bin/true"}),
        serde_json::json!({"operation":"sign_qualification","statement":{}}),
        serde_json::json!({"operation":"reset"}),
    ] {
        assert!(decode::<Request>(&encode(&value).unwrap()).is_err());
    }
}
#[test]
fn only_signed_pinned_policy_aggregate_can_create_one_plan() {
    let f = Fixture::new();
    f.software_issued();
    let wire = f.aggregate();
    let mut bad: Signed<GcpLaunchPolicyAggregateV2> = decode(&wire).unwrap();
    bad.statement.kbs_evaluation.policy_sha384 = "66".repeat(48);
    let wrong = signed(
        &f.kbs,
        bad.statement.clone(),
        &bad.statement.signing_bytes().unwrap(),
    )
    .unwrap();
    assert!(f
        .app
        .request(Request::StartupPlan {
            aggregate_json: wrong
        })
        .is_err());
    let out = f
        .app
        .request(Request::StartupPlan {
            aggregate_json: wire.clone(),
        })
        .unwrap();
    assert_eq!(out["result"]["status"], "startup_plan");
    assert!(f
        .app
        .request(Request::StartupPlan {
            aggregate_json: wire
        })
        .is_err());
}
#[test]
fn nonce_pop_one_use_and_historical_exact_retry_preserve_original_window() {
    let f = Fixture::new();
    f.software_issued();
    f.app
        .request(Request::StartupPlan {
            aggregate_json: f.aggregate(),
        })
        .unwrap();
    let request = f.redemption("factory-nonce");
    assert!(f
        .app
        .request(Request::Redeem {
            guest_nonce: "host-override".into(),
            recorder_request_json: request.clone()
        })
        .is_err());
    let out = f
        .app
        .request(Request::Redeem {
            guest_nonce: "factory-nonce".into(),
            recorder_request_json: request.clone(),
        })
        .unwrap();
    let wire = out["result"]["signed_authorization_json"].clone();
    let mut state = f.state();
    state.last_now = now().unwrap() + 1000;
    f.save_state(&state);
    let retry = f
        .app
        .request(Request::Redeem {
            guest_nonce: "factory-nonce".into(),
            recorder_request_json: request,
        })
        .unwrap();
    assert_eq!(wire, retry["result"]["signed_authorization_json"]);
    assert_eq!(retry["permission_issued_now"], false);
    assert!(f
        .app
        .request(Request::Redeem {
            guest_nonce: "other-guest".into(),
            recorder_request_json: f.redemption("other-guest")
        })
        .is_err());
    let a: Signed<AdmissionAuthorizationV1> = decode(&f.state().authorization.unwrap()).unwrap();
    assert!(a.statement.validity.expires <= f.app.config.retire_before);
}
#[test]
fn trusted_clock_retirement_and_saved_context_cannot_be_extended() {
    let f = Fixture::new();
    f.app.bootstrap_only().unwrap();
    let mut s = f.state();
    s.last_now = now().unwrap() + 1000;
    f.save_state(&s);
    assert!(f
        .app
        .request(Request::Issue {
            submission: Box::new(f.submission())
        })
        .is_err());
    let f = Fixture::new();
    f.software_issued();
    let mut s = f.state();
    let mut l: Signed<LaunchGrant> = decode(s.signed_grant.as_ref().unwrap()).unwrap();
    l.statement.validity.expires = f.app.config.retire_before + 1;
    s.signed_grant = Some(
        signed(
            &f.app.key,
            l.statement.clone(),
            &l.statement.signing_bytes().unwrap(),
        )
        .unwrap(),
    );
    f.save_state(&s);
    assert!(f.app.grant(&s).is_err());
}
#[test]
#[ignore = "requires a separately built CLI artifact via ONB17_EXPERIMENT_CLI"]
fn actual_cli_bootstrap_status_and_unknown_operation() {
    let bin =
        std::env::var_os("ONB17_EXPERIMENT_CLI").expect("explicit built CLI artifact required");
    let f = Fixture::new();
    let run = |op: &str| {
        std::process::Command::new(&bin)
            .arg(op)
            .arg("--config")
            .arg(f.root.join("config"))
            .arg("--signer")
            .arg(f.root.join("authority.pk8"))
            .arg("--collateral")
            .arg(f.root.join("collateral"))
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap()
    };
    let boot = run("bootstrap-only");
    assert!(boot.status.success());
    let out: serde_json::Value = decode(&boot.stdout).unwrap();
    assert_eq!(out["producer_qualified"], false);
    assert!(run("status").status.success());
    assert!(!run("bootstrap-only").status.success());
    assert!(!run("sign-anything").status.success());
}
