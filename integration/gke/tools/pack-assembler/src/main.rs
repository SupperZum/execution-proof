//! Public-byte transport assembly. Only the independent pinned workers can
//! complete hardware verification; this program never emits a verified verdict.
use base64::{engine::general_purpose::STANDARD, Engine};
use execution_proof_client::gcp::{
    GcpCaptureRequestV2, CAPTURE_PURPOSE, MAX_REQUEST_BYTES, WIRE_VERSION,
};
use execution_proof_contract::{
    gcp_bootstrap::{GcpBootstrapBinding, GcpBootstrapChallenge},
    gcp_execution_envelope::MAX_GCP_ENVELOPE_BYTES,
    gcp_execution_quote::GcpQuoteChallenge,
    gcp_policy_receipt::GcpLaunchPolicyAggregateV2,
    gcp_session::GcpLaunchEvidenceV2,
    Signed,
};
use execution_proof_verifier::{
    gcp_graph::verify_gcp_graph,
    gcp_schema::{GcpBootstrapPublication, GcpEvidencePackV2, GcpTrustConfigV2},
    schema::{ObjectKind, SupportingObject, MAX_OBJECT_BYTES, MAX_PACK_BYTES, MAX_TRUST_BYTES},
};
use ring::digest;
use rustix::fs::{renameat_with, RenameFlags, CWD};
use serde::{de, Deserialize, Deserializer, Serialize};
use std::{
    collections::BTreeSet,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
mod trust;
const ROOT: &str = env!("PROOF_PUBLIC_INPUT_ROOT");
const MAX_TOTAL_INPUT: usize = 32 << 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    path: PathBuf,
    sha384: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectedObject {
    kind: ObjectKind,
    file: Pin,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    version: u16,
    purpose: String,
    protected_export: Pin,
    bootstrap_transcript: Pin,
    signed_bootstrap_challenge: Pin,
    original_policy_archive: Pin,
    policy_transcript: Pin,
    signed_qualification: Pin,
    /// Complete independently selected trust, never inferred from the pack.
    trust: Pin,
    /// Independently selected expected quote challenge, never copied from quote.
    challenge: Pin,
    objects: Vec<SelectedObject>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapTranscript {
    challenge_id: String,
    submission: BootstrapSubmission,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapSubmission {
    binding: GcpBootstrapBinding,
    evidence: GcpLaunchEvidenceV2,
    recorder_public_key: [u8; 32],
    possession_signature_hex: String,
    keywrap_public_key: serde_json::Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchivedObject {
    kind: ObjectKind,
    sha384: String,
    body_b64: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyArchive {
    version: u16,
    purpose: String,
    session_id: String,
    aggregate_sha384: String,
    signed_aggregate_b64: String,
    objects: Vec<ArchivedObject>,
    // A public signed receipt only. A JWE/credential response has no field here.
    credential_receipt_b64: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTranscript {
    signed_aggregate: Vec<u8>,
    begin_response_base64: String,
    capture_request_base64: String,
    capture_response_base64: String,
    resource_challenge_response_base64: String,
    resource_decision_response_base64: String,
}
fn require(value: bool, reason: &'static str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(reason.into())
    }
}
fn hash(raw: &[u8]) -> String {
    digest::digest(&digest::SHA384, raw)
        .as_ref()
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}
fn hex(value: &str, bytes: usize) -> Result<()> {
    require(
        value.len() == bytes * 2
            && value
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v)),
        "noncanonical hex rejected",
    )
}
fn canonical(path: &Path) -> Result<()> {
    let root = Path::new(ROOT);
    require(
        root.is_absolute() && root != Path::new("/") && fs::canonicalize(root)? == root,
        "canonical public input root required",
    )?;
    require(
        path.is_absolute() && path.starts_with(root) && fs::canonicalize(path)? == path,
        "public canonical workspace path required",
    )
}
fn read(path: &Path, cap: usize) -> Result<Vec<u8>> {
    canonical(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    require(
        m.is_file() && m.nlink() == 1 && m.len() > 0 && m.len() <= cap as u64,
        "bounded single-link regular input required",
    )?;
    let mut raw = Vec::new();
    file.take(cap as u64 + 1).read_to_end(&mut raw)?;
    require(raw.len() as u64 == m.len(), "input size changed")?;
    public_raw(&raw)?;
    // Public raw policies/signatures need not be JSON. When a selected raw file
    // is valid JSON, apply the private-field/duplicate fence before hashing it.
    if serde_json::from_slice::<serde_json::Value>(&raw).is_ok() {
        json::<serde_json::Value>(&raw)?;
    }
    Ok(raw)
}
fn public_raw(raw: &[u8]) -> Result<()> {
    require(
        !raw.windows(b"PRIVATE KEY".len())
            .any(|v| v == b"PRIVATE KEY"),
        "private marker rejected",
    )
}
fn public_value(value: &serde_json::Value) -> Result<()> {
    match value {
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                require(
                    ![
                        "private_key",
                        "private_key_data",
                        "privateKeyData",
                        "access_token",
                        "refresh_token",
                        "client_secret",
                        "credential_json",
                        "service_account_json",
                        "jwe_b64",
                    ]
                    .contains(&key.as_str()),
                    "private field rejected",
                )?;
                public_value(value)?;
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                public_value(value)?;
            }
        }
        serde_json::Value::String(value) => public_raw(value.as_bytes())?,
        _ => (),
    }
    Ok(())
}
// Reject recursively before Value can erase an earlier duplicate private field.
struct NoDuplicates;
impl<'de> Deserialize<'de> for NoDuplicates {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = NoDuplicates;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON without duplicate keys")
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(NoDuplicates)
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> std::result::Result<Self::Value, E> {
                Ok(NoDuplicates)
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> std::result::Result<Self::Value, E> {
                Ok(NoDuplicates)
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> std::result::Result<Self::Value, E> {
                Ok(NoDuplicates)
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Self::Value, E> {
                Ok(NoDuplicates)
            }
            fn visit_str<E: de::Error>(self, _: &str) -> std::result::Result<Self::Value, E> {
                Ok(NoDuplicates)
            }
            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                while seq.next_element::<NoDuplicates>()?.is_some() {}
                Ok(NoDuplicates)
            }
            fn visit_map<A: de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut keys = BTreeSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !keys.insert(key) {
                        return Err(de::Error::custom("duplicate key rejected"));
                    }
                    map.next_value::<NoDuplicates>()?;
                }
                Ok(NoDuplicates)
            }
        }
        decoder.deserialize_any(Visitor)
    }
}
fn json<T: de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    public_raw(raw)?;
    let mut decoder = serde_json::Deserializer::from_slice(raw);
    NoDuplicates::deserialize(&mut decoder)?;
    decoder.end()?;
    public_value(&serde_json::from_slice(raw)?)?;
    Ok(serde_json::from_slice(raw)?)
}
fn b64(value: &str, cap: usize) -> Result<Vec<u8>> {
    require(value.len() <= cap.div_ceil(3) * 4, "base64 input bound")?;
    let raw = STANDARD.decode(value)?;
    require(
        !raw.is_empty() && raw.len() <= cap && STANDARD.encode(&raw) == value,
        "canonical bounded base64 required",
    )?;
    public_raw(&raw)?;
    Ok(raw)
}
struct Inputs {
    total: usize,
}
impl Inputs {
    fn get(&mut self, pin: &Pin, cap: usize) -> Result<Vec<u8>> {
        hex(&pin.sha384, 48)?;
        let raw = read(&pin.path, cap)?;
        require(hash(&raw) == pin.sha384, "selected input pin changed")?;
        self.total = self
            .total
            .checked_add(raw.len())
            .ok_or("input total overflow")?;
        require(self.total <= MAX_TOTAL_INPUT, "input total bound")?;
        Ok(raw)
    }
}
fn add_object(objects: &mut Vec<SupportingObject>, object: SupportingObject) -> Result<()> {
    require(
        objects.len() < 24 && !objects.iter().any(|v| v.kind == object.kind),
        "duplicate/extra supporting object rejected",
    )?;
    hex(&object.sha384, 48)?;
    require(
        !object.bytes.is_empty()
            && object.bytes.len() <= MAX_OBJECT_BYTES
            && hash(&object.bytes) == object.sha384,
        "supporting object bytes/hash rejected",
    )?;
    public_raw(&object.bytes)?;
    if matches!(
        object.kind,
        ObjectKind::AsInput
            | ObjectKind::AsData
            | ObjectKind::KbsInput
            | ObjectKind::KbsData
            | ObjectKind::GcpConfig
            | ObjectKind::ProducerProfile
            | ObjectKind::GcpArtifactManifest
            | ObjectKind::GcpReferencePolicy
            | ObjectKind::GcpArtifactClosure
            | ObjectKind::GcpFirmwareCausality
            | ObjectKind::GcpProducerIsolation
            | ObjectKind::GcpNoStateCopy
            | ObjectKind::GcpQualificationReview
            | ObjectKind::TrustSnapshot
            | ObjectKind::DcapCollateral
            | ObjectKind::PrelaunchEvidence
    ) {
        json::<serde_json::Value>(&object.bytes)?;
    }
    objects.push(object);
    Ok(())
}
fn original_archive(
    raw: &[u8],
    policy: &PolicyTranscript,
    objects: &mut Vec<SupportingObject>,
) -> Result<Vec<u8>> {
    let archive: PolicyArchive = json(raw)?;
    require(
        archive.version == 1
            && archive.purpose == "qlad.execution-proof.gcp-original-policy-archive.v1",
        "original policy archive domain rejected",
    )?;
    hex(&archive.session_id, 32)?;
    hex(&archive.aggregate_sha384, 48)?;
    let signed = b64(&archive.signed_aggregate_b64, 32 << 10)?;
    require(
        signed == policy.signed_aggregate,
        "original aggregate/transcript mismatch",
    )?;
    let aggregate: Signed<GcpLaunchPolicyAggregateV2> = json(&signed)?;
    require(
        aggregate.statement.session_id == archive.session_id
            && aggregate.statement.digest_sha384()? == archive.aggregate_sha384,
        "archive aggregate identity rejected",
    )?;
    require(
        archive.objects.len() == 5,
        "exact original policy objects required",
    )?;
    for (object, kind) in archive.objects.into_iter().zip([
        ObjectKind::AsPolicy,
        ObjectKind::AsInput,
        ObjectKind::KbsPolicy,
        ObjectKind::KbsInput,
        ObjectKind::KbsData,
    ]) {
        require(
            object.kind == kind,
            "original policy object order/kind rejected",
        )?;
        add_object(
            objects,
            SupportingObject {
                kind: object.kind,
                sha384: object.sha384,
                bytes: b64(&object.body_b64, 1 << 20)?,
            },
        )?;
    }
    let receipt = b64(&archive.credential_receipt_b64, 16 << 10)?;
    json::<serde_json::Value>(&receipt)?;
    Ok(receipt)
}
fn prelaunch(
    policy: PolicyTranscript,
    objects: &mut Vec<SupportingObject>,
    boot_binding_sha384: &str,
) -> Result<()> {
    // Validate every retained public response without retaining any raw resource
    // HTTP delivery response. That response contains the credential JWE.
    for value in [
        &policy.begin_response_base64,
        &policy.capture_response_base64,
        &policy.resource_challenge_response_base64,
        &policy.resource_decision_response_base64,
    ] {
        json::<serde_json::Value>(&b64(value, 1 << 20)?)?;
    }
    let capture: GcpCaptureRequestV2 =
        json(&b64(&policy.capture_request_base64, MAX_REQUEST_BYTES)?)?;
    require(
        capture.version == WIRE_VERSION
            && capture.purpose == CAPTURE_PURPOSE
            && capture.boot_binding_sha384 == boot_binding_sha384,
        "GCP capture domain/binding rejected",
    )?;
    hex(&capture.session_id, 32)?;
    hex(&capture.recorder_public_key_hex, 32)?;
    hex(&capture.signature_hex, 64)?;
    let evidence = b64(&capture.evidence_b64, MAX_GCP_ENVELOPE_BYTES)?;
    let typed: GcpLaunchEvidenceV2 = json(&evidence)?;
    typed.encode()?;
    add_object(
        objects,
        SupportingObject {
            kind: ObjectKind::PrelaunchEvidence,
            sha384: hash(&evidence),
            bytes: evidence,
        },
    )
}
fn bootstrap(transcript: &[u8], signed_challenge: Vec<u8>) -> Result<GcpBootstrapPublication> {
    let boot: BootstrapTranscript = json(transcript)?;
    let signed: Signed<GcpBootstrapChallenge> = json(&signed_challenge)?;
    require(
        boot.challenge_id == signed.statement.challenge_id,
        "bootstrap challenge ID mismatch",
    )?;
    public_value(&boot.submission.keywrap_public_key)?;
    Ok(GcpBootstrapPublication {
        challenge: signed.statement,
        signed_challenge,
        binding: boot.submission.binding,
        evidence: boot.submission.evidence,
        recorder_public_key: boot.submission.recorder_public_key,
        possession_signature: boot.submission.possession_signature_hex,
    })
}
struct Assembled {
    pack: Vec<u8>,
    trust: Vec<u8>,
    challenge: Vec<u8>,
}
fn assemble(selection_path: &Path) -> Result<Assembled> {
    let selection: Selection = json(&read(selection_path, 64 << 10)?)?;
    require(
        selection.version == 1
            && selection.purpose == "onb17.manual-public-pack-selection.v1"
            && selection.objects.len() <= 18,
        "public assembly selection rejected",
    )?;
    let mut inputs = Inputs { total: 0 };
    let export = inputs.get(&selection.protected_export, 12 << 20)?;
    json::<serde_json::Value>(&export)?;
    let boot_raw = inputs.get(&selection.bootstrap_transcript, 4 << 20)?;
    let signed_challenge = inputs.get(&selection.signed_bootstrap_challenge, 16 << 10)?;
    let boot = bootstrap(&boot_raw, signed_challenge)?;
    let q = inputs.get(&selection.signed_qualification, 16 << 10)?;
    json::<serde_json::Value>(&q)?;
    let trust_raw = inputs.get(&selection.trust, MAX_TRUST_BYTES)?;
    json::<serde_json::Value>(&trust_raw)?;
    let trust = GcpTrustConfigV2::decode(&trust_raw)?;
    let challenge_raw = inputs.get(&selection.challenge, 16 << 10)?;
    json::<serde_json::Value>(&challenge_raw)?;
    let challenge = GcpQuoteChallenge::decode(&challenge_raw)?;
    let policy: PolicyTranscript = json(&inputs.get(&selection.policy_transcript, 17 << 20)?)?;
    let original_aggregate = policy.signed_aggregate.clone();
    let mut objects = Vec::new();
    let receipt = original_archive(
        &inputs.get(&selection.original_policy_archive, 8 << 20)?,
        &policy,
        &mut objects,
    )?;
    prelaunch(
        policy,
        &mut objects,
        &trust.quote.boot_binding.digest_sha384()?,
    )?;
    for selected in selection.objects {
        let bytes = inputs.get(&selected.file, MAX_OBJECT_BYTES)?;
        add_object(
            &mut objects,
            SupportingObject {
                kind: selected.kind,
                sha384: selected.file.sha384,
                bytes,
            },
        )?;
    }
    let pack = GcpEvidencePackV2::from_protected_export(&export, receipt, objects, boot, q)?;
    let admission = execution_proof_handoff::rootfs_custody::AdmissionBundle::decode(
        &pack.execution.admission,
        execution_proof_handoff::rootfs_custody::MAX_PROVENANCE_BYTES,
    )?;
    require(
        admission.aggregate == original_aggregate,
        "protected/original aggregate bytes differ",
    )?;
    // Authenticates only the public graph. Neither bootstrap nor execution QVL
    // worker runs here, so this cannot produce a verified_exec verdict.
    verify_gcp_graph(pack.clone(), &trust, &challenge)?;
    Ok(Assembled {
        pack: pack.encode()?,
        trust: trust.encode()?,
        challenge: challenge.encode()?,
    })
}
#[derive(Serialize)]
struct OutputReceipt {
    purpose: &'static str,
    pack_sha384: String,
    trust_sha384: String,
    challenge_sha384: String,
    public_graph_authenticated: bool,
    hardware_verification_run: bool,
    execution_verified: bool,
}
fn receipt(assembled: &Assembled) -> OutputReceipt {
    OutputReceipt {
        purpose: "onb17.manual-public-pack-assembled.v1",
        pack_sha384: hash(&assembled.pack),
        trust_sha384: hash(&assembled.trust),
        challenge_sha384: hash(&assembled.challenge),
        public_graph_authenticated: true,
        hardware_verification_run: false,
        execution_verified: false,
    }
}
fn publish(output: &Path, assembled: &Assembled) -> Result<()> {
    publish_directory(output, |dir| write_pack(dir, assembled))
}
fn publish_directory(output: &Path, populate: impl FnOnce(&Path) -> Result<()>) -> Result<()> {
    let parent = output.parent().ok_or("output parent required")?;
    canonical(parent)?;
    let name = output
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or("output name required")?;
    require(
        !name.is_empty()
            && name.len() <= 128
            && name
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || b"-_".contains(&v)),
        "simple output directory name required",
    )?;
    let parent_dir = File::open(parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".pack-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)?;
    populate(staging.path())?;
    File::open(staging.path())?.sync_all()?;
    renameat_with(
        CWD,
        staging.path(),
        &parent_dir,
        name,
        RenameFlags::NOREPLACE,
    )?;
    let _ = staging.keep();
    parent_dir.sync_all()?;
    Ok(())
}
fn write_pack(output: &Path, assembled: &Assembled) -> Result<()> {
    let record = serde_json::to_vec(&receipt(assembled))?;
    for (name, raw) in [
        ("pack.json", assembled.pack.as_slice()),
        ("trust.json", assembled.trust.as_slice()),
        ("challenge.json", assembled.challenge.as_slice()),
        ("assembly.json", record.as_slice()),
    ] {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(output.join(name))?;
        file.write_all(raw)?;
        file.sync_all()?;
    }
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.is_empty() {
        println!("Public pack assembler: inert; explicit check/assemble selection required.");
        return Ok(());
    }
    if args.len() == 2 && args[0] == "check-basis" {
        trust::check_basis(Path::new(&args[1]))?;
        println!("{{\"status\":\"STATIC_TRUST_BASIS_CHECKED\",\"hardware_verification_run\":false,\"execution_verified\":false}}");
        return Ok(());
    }
    if args.len() == 3 && args[0] == "prepare-trust" {
        return trust::run(Path::new(&args[1]), Path::new(&args[2]));
    }
    if args.len() == 3 && args[0] == "admission-policy" {
        return trust::admission_policy(Path::new(&args[1]), Path::new(&args[2]));
    }
    require(
        (args.len() == 2 && args[0] == "check") || (args.len() == 3 && args[0] == "assemble"),
        "expected check selection or assemble selection output",
    )?;
    let assembled = assemble(Path::new(&args[1]))?;
    require(
        assembled.pack.len() <= MAX_PACK_BYTES,
        "pack serialization bound",
    )?;
    if args[0] == "assemble" {
        publish(Path::new(&args[2]), &assembled)?;
    }
    println!("{}", serde_json::to_string(&receipt(&assembled))?);
    Ok(())
}
fn main() {
    // Public-only inputs, but avoid payload-bearing panic/error diagnostics.
    std::panic::set_hook(Box::new(|_| {}));
    if run().is_err() {
        eprintln!("public_pack_assembly_rejected");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests;
