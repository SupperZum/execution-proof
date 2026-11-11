//! Private operator archive of original captured bytes. It is data only and
//! never participates in granting a session, credential or execution lease.
use crate::gcp_launch_resource::GcpPolicyCaptureSnapshot;
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use execution_proof_contract::{
    gcp_credential::GcpCredentialDeliveryV2, gcp_policy_receipt::GcpLaunchPolicyAggregateV2, Signed,
};
use ring::signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::Mutex,
};

const MAX_ARCHIVE: usize = 16 << 20;
const MAX_OBJECT: usize = 1 << 20;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Object {
    kind: String,
    sha384: String,
    body_b64: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u16,
    purpose: String,
    session_id: String,
    aggregate_sha384: String,
    signed_aggregate_b64: String,
    objects: Vec<Object>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_receipt_b64: Option<String>,
}

pub struct DeliveryScope {
    pub public_key: [u8; 32],
    pub audience: String,
    pub issuer: String,
    pub boot_binding_sha384: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryResponse {
    version: u16,
    purpose: String,
    boot_binding_sha384: String,
    signed_delivery_b64: String,
    // The middleware forwards the unchanged HTTP body. Its archive parser
    // deliberately neither retains nor hashes the encrypted credential field.
    #[serde(rename = "jwe_b64")]
    _encrypted_credential: serde::de::IgnoredAny,
}

pub struct Archive {
    path: PathBuf,
    directory: File,
    completed: Mutex<HashSet<String>>,
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha384::digest(bytes))
}
fn identifier(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn object(kind: &'static str, bytes: &[u8], expected: &str) -> Result<Object> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_OBJECT && hash(bytes) == expected,
        "archive object rejected"
    );
    ensure!(
        !(bytes.windows(10).any(|v| v == b"-----BEGIN")
            && bytes.windows(11).any(|v| v == b"PRIVATE KEY")),
        "private key material is not an archive object"
    );
    Ok(Object {
        kind: kind.into(),
        sha384: expected.into(),
        body_b64: STANDARD.encode(bytes),
    })
}
fn keys(value: &serde_json::Value, names: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == names.len() && names.iter().all(|name| object.contains_key(*name))
    })
}
fn no_private_fields(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(object) => object.iter().all(|(name, value)| {
            !matches!(
                name.as_str(),
                "private_key"
                    | "private_key_data"
                    | "access_token"
                    | "refresh_token"
                    | "client_secret"
                    | "management_tls_private_key_pem"
                    | "credential_json"
                    | "service_account_json"
            ) && no_private_fields(value)
        }),
        serde_json::Value::Array(values) => values.iter().all(no_private_fields),
        _ => true,
    }
}
fn public_inputs(as_input: &[u8], kbs_input: &[u8], kbs_data: &[u8]) -> Result<()> {
    let a: serde_json::Value = serde_json::from_slice(as_input)?;
    let k: serde_json::Value = serde_json::from_slice(kbs_input)?;
    let d: serde_json::Value = serde_json::from_slice(kbs_data)?;
    ensure!(
        keys(
            &a,
            &[
                "profile",
                "tee",
                "tee_class",
                "grant_digest",
                "claims",
                "runtime_data",
                "boot_binding",
                "boot_binding_sha384",
                "boot_policy",
                "module_policy"
            ]
        ) && a["profile"] == "onb17.gcp-launch-quote.v2"
            && a["tee"] == "tdx"
            && a["tee_class"] == "cpu",
        "unexpected AS archive input schema"
    );
    ensure!(
        keys(&k, &["profile", "verified_launch"])
            && k["profile"] == "onb17.gcp-verified-launch-resource-input.v2"
            && keys(
                &k["verified_launch"],
                &[
                    "grant_sha384",
                    "authority_key_sha384",
                    "binding",
                    "session_id",
                    "nonce",
                    "runtime_sha384",
                    "boot_binding_sha384",
                    "evidence_sha384",
                    "claims"
                ]
            ),
        "unexpected KBS archive input schema"
    );
    ensure!(
        keys(
            &d,
            &[
                "method",
                "plugin",
                "resource-path",
                "workflow-id",
                "request_nonce",
                "query"
            ]
        ) && d["method"] == "GET"
            && d["plugin"] == "resource"
            && d["query"] == serde_json::json!({}),
        "unexpected KBS archive data schema"
    );
    ensure!(
        no_private_fields(&a) && no_private_fields(&k) && no_private_fields(&d),
        "private fields are not policy archive data"
    );
    Ok(())
}
impl Archive {
    /// One new empty directory per manual service attempt. The retained lock
    /// prevents a second process from claiming the same private archive owner.
    pub fn open(path: &Path) -> Result<Self> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = directory.metadata()?;
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o777 == 0o700,
            "archive ownership rejected"
        );
        ensure!(
            unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "archive already owned"
        );
        ensure!(
            std::fs::read_dir(path)?.next().is_none(),
            "new empty archive directory required"
        );
        Ok(Self {
            path: path.into(),
            directory,
            completed: Mutex::new(HashSet::new()),
        })
    }
    pub fn store(&self, snapshot: &GcpPolicyCaptureSnapshot) -> Result<()> {
        ensure!(
            snapshot.as_capture().data_bytes().is_none(),
            "manual profile has no AS data archive"
        );
        public_inputs(
            snapshot.as_capture().input_bytes(),
            snapshot.kbs_capture().input_bytes(),
            snapshot
                .kbs_capture()
                .data_bytes()
                .ok_or_else(|| anyhow::anyhow!("KBS request data missing"))?,
        )?;
        let mut objects = Vec::new();
        for (prefix, capture) in [
            (true, snapshot.as_capture()),
            (false, snapshot.kbs_capture()),
        ] {
            objects.push(object(
                if prefix { "as_policy" } else { "kbs_policy" },
                capture.policy_bytes(),
                capture.policy_commitment().sha384(),
            )?);
            objects.push(object(
                if prefix { "as_input" } else { "kbs_input" },
                capture.input_bytes(),
                capture.input_commitment().sha384(),
            )?);
            if let Some(bytes) = capture.data_bytes() {
                objects.push(object(
                    if prefix { "as_data" } else { "kbs_data" },
                    bytes,
                    capture
                        .data_commitment()
                        .ok_or_else(|| anyhow::anyhow!("archive data commitment missing"))?
                        .sha384(),
                )?);
            }
        }
        let record = Record {
            version: 1,
            purpose: "qlad.execution-proof.gcp-original-policy-archive.v1".into(),
            session_id: snapshot.session_id().into(),
            aggregate_sha384: snapshot.aggregate_sha384().into(),
            signed_aggregate_b64: STANDARD.encode(snapshot.signed_aggregate_json()),
            objects,
            credential_receipt_b64: None,
        };
        self.store_record(&record)
    }
    /// Add only the original signed public receipt after a successful delivery.
    /// The existing aggregate/policy bodies remain byte-for-byte unchanged.
    pub fn store_delivery_response(&self, response: &[u8], scope: &DeliveryScope) -> Result<()> {
        ensure!(response.len() <= 128 << 10, "delivery response bound");
        let response: DeliveryResponse = serde_json::from_slice(response)?;
        ensure!(
            response.version == execution_proof_client::gcp::WIRE_VERSION
                && response.purpose == execution_proof_client::gcp::CREDENTIAL_PURPOSE
                && response.boot_binding_sha384 == scope.boot_binding_sha384
                && response.signed_delivery_b64.len() <= (16usize << 10).div_ceil(3) * 4,
            "delivery response domain rejected"
        );
        let wire = STANDARD.decode(&response.signed_delivery_b64)?;
        ensure!(
            !wire.is_empty()
                && wire.len() <= 16 << 10
                && STANDARD.encode(&wire) == response.signed_delivery_b64,
            "delivery receipt encoding rejected"
        );
        let receipt: Signed<GcpCredentialDeliveryV2> = serde_json::from_slice(&wire)?;
        let statement = &receipt.statement;
        verify_signature(
            &scope.public_key,
            &statement.signing_bytes()?,
            &receipt.signature,
        )?;
        ensure!(
            statement.audience == scope.audience
                && statement.issuer == scope.issuer
                && statement.boot_binding_sha384 == scope.boot_binding_sha384,
            "delivery receipt scope rejected"
        );
        let name = format!(
            "{}-{}.json",
            statement.session_id, statement.aggregate_sha384
        );
        let completed = self
            .completed
            .lock()
            .map_err(|_| anyhow::anyhow!("archive unavailable"))?;
        ensure!(
            completed.contains(&name),
            "original aggregate archive required before delivery"
        );
        let path = self.path.join(&name);
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_file()
                && meta.nlink() == 1
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.mode() & 0o777 == 0o600
                && meta.len() <= MAX_ARCHIVE as u64,
            "original archive metadata rejected"
        );
        let mut original = Vec::new();
        file.take(MAX_ARCHIVE as u64 + 1)
            .read_to_end(&mut original)?;
        ensure!(
            original.len() as u64 == meta.len(),
            "original archive size changed"
        );
        let mut record: Record = serde_json::from_slice(&original)?;
        ensure!(
            record.version == 1
                && record.purpose == "qlad.execution-proof.gcp-original-policy-archive.v1"
                && record.session_id == statement.session_id
                && record.aggregate_sha384 == statement.aggregate_sha384,
            "original archive delivery identity rejected"
        );
        let aggregate_wire = STANDARD.decode(&record.signed_aggregate_b64)?;
        ensure!(
            aggregate_wire.len() <= 32 << 10
                && STANDARD.encode(&aggregate_wire) == record.signed_aggregate_b64,
            "original aggregate encoding rejected"
        );
        let aggregate: Signed<GcpLaunchPolicyAggregateV2> =
            serde_json::from_slice(&aggregate_wire)?;
        let aggregate_bytes = aggregate.statement.signing_bytes()?;
        verify_signature(&scope.public_key, &aggregate_bytes, &aggregate.signature)?;
        let aggregate = aggregate.statement;
        ensure!(
            aggregate.digest_sha384()? == statement.aggregate_sha384
                && aggregate.session_id == statement.session_id
                && aggregate.grant_sha384 == statement.grant_sha384
                && aggregate.runtime_sha384 == statement.runtime_sha384
                && aggregate.evidence_sha384 == statement.evidence_sha384
                && aggregate.boot_binding_sha384 == statement.boot_binding_sha384
                && aggregate.recorder_key_sha384 == statement.recorder_key_sha384
                && aggregate.request.digest_sha384()? == statement.request_sha384
                && aggregate.request.workflow_id == statement.workflow_id
                && aggregate.request.resource_path == statement.resource_path,
            "delivery receipt differs from original aggregate"
        );
        if let Some(existing) = &record.credential_receipt_b64 {
            ensure!(
                existing == &response.signed_delivery_b64,
                "delivery receipt retry differs"
            );
            return Ok(());
        }
        record.credential_receipt_b64 = Some(response.signed_delivery_b64);
        let updated = serde_json::to_vec(&record)?;
        ensure!(updated.len() <= MAX_ARCHIVE, "archive byte budget");
        let mut temporary = tempfile::NamedTempFile::new_in(&self.path)?;
        temporary.write_all(&updated)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(&path)
            .map_err(|_| anyhow::anyhow!("delivery archive commit rejected"))?;
        self.directory.sync_all()?;
        Ok(())
    }
    fn store_record(&self, record: &Record) -> Result<()> {
        ensure!(
            identifier(&record.session_id, 64) && identifier(&record.aggregate_sha384, 96),
            "archive selector rejected"
        );
        let bytes = serde_json::to_vec(record)?;
        ensure!(bytes.len() <= MAX_ARCHIVE, "archive byte budget");
        let mut completed = self
            .completed
            .lock()
            .map_err(|_| anyhow::anyhow!("archive unavailable"))?;
        let name = format!("{}-{}.json", record.session_id, record.aggregate_sha384);
        ensure!(
            completed.is_empty() || completed.contains(&name),
            "one archived attempt per service process"
        );
        let path = self.path.join(&name);
        if path.exists() {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(&path)?;
            let meta = file.metadata()?;
            ensure!(
                meta.is_file()
                    && meta.uid() == unsafe { libc::geteuid() }
                    && meta.mode() & 0o777 == 0o600
                    && meta.len() <= MAX_ARCHIVE as u64,
                "archive retry metadata rejected"
            );
            let mut old = Vec::new();
            file.take(MAX_ARCHIVE as u64 + 1).read_to_end(&mut old)?;
            if old != bytes {
                let mut with_delivery: Record = serde_json::from_slice(&old)?;
                ensure!(
                    with_delivery.credential_receipt_b64.take().is_some()
                        && record.credential_receipt_b64.is_none()
                        && serde_json::to_vec(&with_delivery)? == bytes,
                    "archive retry differs"
                );
            }
        } else {
            let mut temp = tempfile::NamedTempFile::new_in(&self.path)?;
            temp.write_all(&bytes)?;
            temp.as_file().sync_all()?;
            temp.persist_noclobber(&path)
                .map_err(|_| anyhow::anyhow!("archive commit rejected"))?;
        }
        self.directory.sync_all()?;
        completed.insert(name);
        Ok(())
    }
}

fn verify_signature(key: &[u8; 32], bytes: &[u8], encoded: &str) -> Result<()> {
    let decoded = hex::decode(encoded)?;
    ensure!(
        decoded.len() == 64 && hex::encode(&decoded) == encoded,
        "archive signature encoding rejected"
    );
    signature::UnparsedPublicKey::new(&signature::ED25519, key)
        .verify(bytes, &decoded)
        .map_err(|_| anyhow::anyhow!("archive signature rejected"))
}

#[cfg(test)]
mod tests {
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
        receipt["statement"]["resource_path"] =
            serde_json::json!(["onb17", "manual", "credential"]);
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
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
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
}
