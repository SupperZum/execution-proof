#![cfg(feature = "gcp")]
//! Actual CLI processes with software operator keys. These fixtures never issue
//! a hardware-authorized L and are not deployed profile qualification.
use execution_proof_contract::{
    bootstrap::{TenantIntent, TENANT_INTENT_PURPOSE},
    gcp_boot_binding::GcpBootBindingV1,
    gcp_profile::{
        GcpProducerQualificationV1, GcpQualificationEvidenceRefs, GcpQualificationExpectations,
        GCP_QUALIFICATION_CLAIM, GCP_QUALIFICATION_PROFILE, GCP_QUALIFICATION_PURPOSE,
    },
    Signed, ValidityWindow,
};
use execution_proof_issuer::{
    gcp::{GcpIssuerConfig, GcpPolicyAdmissionConfig},
    gcp_operator::REQUEST_PURPOSE,
};
use execution_proof_verifier::{
    gcp_boot_evidence::{GcpBootEvidencePolicy, GcpInstanceIdentity, QuotePaddingPolicy},
    gcp_tdx_policy::{
        GcpTdxModulePolicyV1, GCP_TDX_ALLOWED_ATTRIBUTES, GCP_TDX_POLICY_PURPOSE,
        INTEL_TDX_MODULE_1_5_34_MR_SEAM,
    },
};
use ring::{
    digest,
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    dir: PathBuf,
    config: GcpIssuerConfig,
    tenant: Ed25519KeyPair,
    reviewer: Ed25519KeyPair,
    qualification: Vec<u8>,
    now: u64,
}
fn hash(b: &[u8]) -> String {
    digest::digest(&digest::SHA384, b)
        .as_ref()
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}
fn key() -> (Vec<u8>, Ed25519KeyPair) {
    let bytes = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let owned = bytes.as_ref().to_vec();
    let key = Ed25519KeyPair::from_pkcs8(&owned).unwrap();
    (owned, key)
}
fn public(k: &Ed25519KeyPair) -> [u8; 32] {
    k.public_key().as_ref().try_into().unwrap()
}
fn signed<T: serde::Serialize>(s: T, b: &[u8], k: &Ed25519KeyPair) -> Vec<u8> {
    serde_json::to_vec(&Signed {
        statement: s,
        signature: k
            .sign(b)
            .as_ref()
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>(),
    })
    .unwrap()
}
fn write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "onb17-authority-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let (private, _) = key();
        let (_, tenant) = key();
        let (_, kbs) = key();
        let (_, reviewer) = key();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let boot_binding = GcpBootBindingV1::new([1; 48], [2; 48], [3; 48], [4; 48]).unwrap();
        let boot_policy = GcpBootEvidencePolicy {
            expected_pe_sha384: "11".repeat(48),
            expected_firmware_mrtd: "12".repeat(48),
            expected_instance: GcpInstanceIdentity {
                instance_id: 1,
                numerical_project_id: 2,
                zone: "us-central1-a".into(),
            },
            quote_padding: QuotePaddingPolicy::GcpTsmZeroPadded8000,
        };
        let module_policy = GcpTdxModulePolicyV1 {
            version: 1,
            purpose: GCP_TDX_POLICY_PURPOSE.into(),
            expected_mr_seam: INTEL_TDX_MODULE_1_5_34_MR_SEAM.into(),
            allowed_td_attributes: GCP_TDX_ALLOWED_ATTRIBUTES,
        };
        let expectation = GcpQualificationExpectations {
            qualification_public_key: public(&reviewer),
            issuer: "software-review-fixture".into(),
            boot_binding_sha384: boot_binding.digest_sha384().unwrap(),
            pe_sha384: boot_policy.expected_pe_sha384.clone(),
            firmware_mrtd: boot_policy.expected_firmware_mrtd.clone(),
            module_policy_sha384: hash(&module_policy.encode().unwrap()),
            evidence_refs: GcpQualificationEvidenceRefs {
                artifact_closure_sha384: "21".repeat(48),
                firmware_causality_sha384: "22".repeat(48),
                producer_isolation_sha384: "23".repeat(48),
                no_state_copy_sha384: "24".repeat(48),
                qualification_review_sha384: "25".repeat(48),
            },
        };
        let q = GcpProducerQualificationV1 {
            version: 1,
            purpose: GCP_QUALIFICATION_PURPOSE.into(),
            profile: GCP_QUALIFICATION_PROFILE.into(),
            claim: GCP_QUALIFICATION_CLAIM.into(),
            qualification_id: "SOFTWARE-NOT-DEPLOYED".into(),
            issuer: expectation.issuer.clone(),
            boot_binding_sha384: expectation.boot_binding_sha384.clone(),
            pe_sha384: expectation.pe_sha384.clone(),
            firmware_mrtd: expectation.firmware_mrtd.clone(),
            module_policy_sha384: expectation.module_policy_sha384.clone(),
            evidence_refs: expectation.evidence_refs.clone(),
            validity: ValidityWindow {
                not_before: now.saturating_sub(1),
                expires: now + 300,
            },
        };
        let qualification = signed(q.clone(), &q.signing_bytes().unwrap(), &reviewer);
        let config = GcpIssuerConfig {
            authorization_ttl_secs: 120,
            authority: "authority".into(),
            tenant: "tenant".into(),
            audience: "launch".into(),
            tenant_public_key: public(&tenant),
            boot_binding,
            launch_policy_sha384: "31".repeat(48),
            image_policy_sha384: "32".repeat(48),
            boot_policy,
            module_policy,
            qualification: expectation,
            policy_admission: GcpPolicyAdmissionConfig {
                kbs_proof_public_key: public(&kbs),
                aggregate_audience: "policy".into(),
                aggregate_issuer: "kbs".into(),
                as_policy_id: "launch".into(),
                as_policy_sha384: "31".repeat(48),
                as_data_sha384: None,
                kbs_policy_id: "resource".into(),
                kbs_policy_sha384: "33".repeat(48),
                resource_path: ["default".into(), "credentials".into(), "gcp".into()],
                workflow_id: "kms-direct".into(),
                receipt_audience: "cdh".into(),
            },
            pregrant_worker_path: "/bin/true".into(),
            pregrant_worker_sha384: hash(&fs::read("/bin/true").unwrap()),
            collateral_json: Vec::new(),
        };
        write(
            &dir.join("config.json"),
            &serde_json::to_vec(&config).unwrap(),
        );
        write(&dir.join("qualification.json"), &qualification);
        write(&dir.join("signer.pk8"), &private);
        write(&dir.join("collateral.json"), b"{}");
        Self {
            dir,
            config,
            tenant,
            reviewer,
            qualification,
            now,
        }
    }
    fn run(&self, command: &str, request: Option<&[u8]>) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_gcp-authority"))
            .env_clear()
            .arg(command)
            .arg("--config")
            .arg(self.dir.join("config.json"))
            .arg("--qualification")
            .arg(self.dir.join("qualification.json"))
            .arg("--signer")
            .arg(self.dir.join("signer.pk8"))
            .arg("--store")
            .arg(self.dir.join("issuer.sqlite"))
            .arg("--collateral")
            .arg(self.dir.join("collateral.json"))
            .args(["--capacity", "8"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(bytes) = request {
            child.stdin.take().unwrap().write_all(bytes).unwrap();
        } else {
            drop(child.stdin.take());
        }
        child.wait_with_output().unwrap()
    }
    fn begin(&self) -> Vec<u8> {
        let c = &self.config;
        let t = TenantIntent {
            version: 2,
            purpose: TENANT_INTENT_PURPOSE.into(),
            audience: c.audience.clone(),
            authority: c.authority.clone(),
            tenant: c.tenant.clone(),
            workload_id: "workload".into(),
            container_role: "application-init".into(),
            attempt_id: "attempt".into(),
            selected_manifest_sha256: "41".repeat(32),
            effective_launch_sha384: "42".repeat(48),
            profile_sha384: c.boot_binding.digest_sha384().unwrap(),
            launch_policy_sha384: c.launch_policy_sha384.clone(),
            image_policy_sha384: c.image_policy_sha384.clone(),
            validity: ValidityWindow {
                not_before: self.now.saturating_sub(1),
                expires: self.now + 300,
            },
        };
        serde_json::to_vec(&serde_json::json!({"version":1,"purpose":REQUEST_PURPOSE,"request":{"operation":"begin","signed_intent_json":signed(t.clone(),&t.signing_bytes().unwrap(),&self.tenant)}})).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.dir).unwrap();
    }
}
fn value(o: &Output) -> serde_json::Value {
    assert!(o.stderr.is_empty());
    serde_json::from_slice(&o.stdout).unwrap()
}

#[test]
fn actual_cli_init_and_durable_begin_never_reset_or_accept_operator_overrides() {
    let f = Fixture::new();
    let init = f.run("init", None);
    assert!(init.status.success());
    assert_eq!(value(&init)["result"]["status"], "initialized");
    let request = f.begin();
    let one = f.run("request", Some(&request));
    assert!(one.status.success());
    assert_eq!(value(&one)["result"]["status"], "challenge");
    let two = f.run("request", Some(&request));
    assert!(two.status.success());
    assert_eq!(one.stdout, two.stdout);
    let reset = f.run("init", None);
    assert!(!reset.status.success());
    assert_eq!(value(&reset)["result"]["code"], "state_rejected");
    let mut unknown: serde_json::Value = serde_json::from_slice(&request).unwrap();
    unknown["request"]["signer"] = "HOSTILE-PATH-SECRET".into();
    let denied = f.run("request", Some(&serde_json::to_vec(&unknown).unwrap()));
    assert!(!denied.status.success());
    assert_eq!(value(&denied)["result"]["code"], "request_malformed");
    assert!(!String::from_utf8_lossy(&denied.stdout).contains("HOSTILE-PATH-SECRET"));
}
#[test]
fn actual_cli_expired_or_forged_qualification_creates_no_store() {
    let f = Fixture::new();
    let mut q: Signed<GcpProducerQualificationV1> =
        serde_json::from_slice(&f.qualification).unwrap();
    q.statement.validity = ValidityWindow {
        not_before: f.now - 100,
        expires: f.now - 50,
    };
    let expired = signed(
        q.statement.clone(),
        &q.statement.signing_bytes().unwrap(),
        &f.reviewer,
    );
    write(&f.dir.join("qualification.json"), &expired);
    let result = f.run("init", None);
    assert!(!result.status.success());
    assert_eq!(value(&result)["result"]["code"], "request_expired");
    assert!(!f.dir.join("issuer.sqlite").exists());
    let mut forged: serde_json::Value = serde_json::from_slice(&f.qualification).unwrap();
    forged["signature"] = "00".repeat(64).into();
    write(
        &f.dir.join("qualification.json"),
        &serde_json::to_vec(&forged).unwrap(),
    );
    let result = f.run("init", None);
    assert!(!result.status.success());
    assert_eq!(value(&result)["result"]["status"], "error");
    assert!(!f.dir.join("issuer.sqlite").exists());
}
#[test]
fn actual_cli_private_input_is_not_logged_on_permission_or_key_error() {
    let f = Fixture::new();
    let sentinel = b"PRIVATE-KEY-SENTINEL-NOT-VALID-PKCS8";
    write(&f.dir.join("signer.pk8"), sentinel);
    for mode in [0o600, 0o644] {
        fs::set_permissions(f.dir.join("signer.pk8"), fs::Permissions::from_mode(mode)).unwrap();
        let result = f.run("init", None);
        assert!(!result.status.success());
        assert_eq!(value(&result)["result"]["status"], "error");
        assert!(!result.stdout.windows(sentinel.len()).any(|s| s == sentinel));
        assert!(!f.dir.join("issuer.sqlite").exists());
    }
}
