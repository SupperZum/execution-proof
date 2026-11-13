use crate::launch_policy::{evaluate_kbs_policy, evaluate_launch_policy, PolicyDecision};
use key_value_storage::{KvStorageProvider, StorageBackendConfig, StorageProvider};
use policy_engine::{rego::Regorus, PolicyEngine};
use serde_json::json;

#[tokio::test]
async fn rendered_manual_policies_use_actual_regorus_and_preserve_original_input() {
    let directory = tempfile::tempdir().unwrap();
    let out = directory.path().join("policy");
    let status = std::process::Command::new("/usr/bin/python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/render-policies.py"))
        .args([
            "--authority",
            "operator",
            "--tenant",
            "tenant",
            "--container-role",
            "task",
            "--workflow-id",
            "workflow",
            "--resource-path",
            "onb17/kms/direct",
            "--workload-prefix",
            "qexp-",
            "--workload-prefix",
            "normal-",
        ])
        .arg("--output")
        .arg(&out)
        .status()
        .unwrap();
    assert!(status.success());
    let provider = KvStorageProvider::new(StorageBackendConfig::default());
    let engine: PolicyEngine<Regorus> =
        PolicyEngine::new(provider.get_or_register("test-rendered").await.unwrap());
    for (id, file) in [("as", "as.rego"), ("kbs", "kbs.rego")] {
        engine
            .set_policy(id, &std::fs::read_to_string(out.join(file)).unwrap(), false)
            .await
            .unwrap();
    }
    let claims = json!({"td_attributes":{"debug":false},"tcb_status":"UpToDate","collateral_expiration_status":"0"});
    let mut a = json!({"profile":"onb17.gcp-launch-quote.v2","tee":"tdx","tee_class":"cpu","claims":claims});
    let raw = format!("  {}\n", a);
    let facts = evaluate_launch_policy(&engine, "as", &raw, None)
        .await
        .unwrap();
    assert_eq!(facts.decision(), PolicyDecision::Accepted);
    assert_eq!(facts.capture().input_bytes(), raw.as_bytes());
    a["claims"]["td_attributes"]["debug"] = true.into();
    assert_eq!(
        evaluate_launch_policy(&engine, "as", &a.to_string(), None)
            .await
            .unwrap()
            .decision(),
        PolicyDecision::Denied
    );
    let mut k = json!({"profile":"onb17.gcp-verified-launch-resource-input.v2","verified_launch":{"claims":claims,"binding":{"authority":"operator","tenant":"tenant","container_role":"task","workload_id":"qexp-one"}}});
    let mut data = json!({"method":"GET","plugin":"resource","resource-path":["onb17","kms","direct"],"workflow-id":"workflow","query":{}});
    let raw = format!("  {}\n", k);
    let d = format!("{} \n", data);
    let facts = evaluate_kbs_policy(&engine, "kbs", &d, &raw).await.unwrap();
    assert_eq!(facts.capture().input_bytes(), raw.as_bytes());
    assert_eq!(facts.capture().data_bytes().unwrap(), d.as_bytes());
    for (field, bad) in [
        ("authority", "other"),
        ("tenant", "other"),
        ("container_role", "other"),
        ("workload_id", "unapproved-one"),
    ] {
        let old = k["verified_launch"]["binding"][field].take();
        k["verified_launch"]["binding"][field] = bad.into();
        assert!(evaluate_kbs_policy(&engine, "kbs", &d, &k.to_string())
            .await
            .is_err());
        k["verified_launch"]["binding"][field] = old;
    }
    data["resource-path"] = json!(["onb17", "kms", "other"]);
    assert!(
        evaluate_kbs_policy(&engine, "kbs", &data.to_string(), &k.to_string())
            .await
            .is_err()
    );
    k["verified_launch"]["claims"]["tcb_status"] = "OutOfDate".into();
    assert!(evaluate_kbs_policy(&engine, "kbs", &d, &k.to_string())
        .await
        .is_err());
}
