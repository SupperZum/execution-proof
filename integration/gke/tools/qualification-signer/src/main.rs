//! Signs the reviewed qualification decision. Runtime authorization requires a separate grant.
use execution_proof_contract::{
    gcp_artifact::{verify_artifacts, ArtifactVerificationExpectations},
    gcp_boot_binding::GcpBootBindingV1,
    gcp_profile::{
        verify_gcp_qualification, GcpProducerQualificationV1, GcpQualificationExpectations,
    },
    Signed, ValidityWindow,
};
use ring::{
    digest,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde::{de, Deserialize, Deserializer};
use std::{
    collections::BTreeSet,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const WORKFLOW: &str = env!("PROOF_WORKFLOW_ID");
const EXPERIMENT: &str = env!("PROOF_QUALIFICATION_PREFIX");
const NORMAL: &str = env!("PROOF_WORKLOAD_PREFIX");
const MAX_REVIEW_AGE: u64 = 120;
const FILES: [&str; 5] = [
    "artifact-closure.json",
    "firmware-causality.json",
    "producer-isolation.json",
    "no-state-copy.json",
    "qualification-review.json",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    version: u16,
    purpose: String,
    expected: GcpQualificationExpectations,
    reviewer: String,
    review_sha384: String,
    experiment_namespace: String,
    normal_namespace: String,
    workflow_id: String,
    retired_instance_id: String,
    retired_at: u64,
    experimental_retire_before: u64,
    absolute_deadline: u64,
}

// The fifth digest is deliberately absent: a review cannot hash itself or the
// Q that will contain its hash. Q commits this receipt's exact original bytes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewedEvidence {
    artifact_closure_sha384: String,
    firmware_causality_sha384: String,
    producer_isolation_sha384: String,
    no_state_copy_sha384: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    version: u16,
    purpose: String,
    reviewer: String,
    reviewed_at: u64,
    qualification_id: String,
    issuer: String,
    validity: ValidityWindow,
    boot_binding_sha384: String,
    pe_sha384: String,
    firmware_mrtd: String,
    module_policy_sha384: String,
    evidence_refs: ReviewedEvidence,
    retired_instance_id: String,
    retired_at: u64,
    experimental_retire_before: u64,
    experiment_namespace: String,
    normal_namespace: String,
    workflow_id: String,
    decision: String,
    authentication_only: bool,
}

fn require(value: bool, reason: &'static str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(reason.into())
    }
}
fn hash(bytes: &[u8]) -> String {
    digest::digest(&digest::SHA384, bytes)
        .as_ref()
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}
fn canonical(path: &Path) -> Result<()> {
    require(
        path.is_absolute() && fs::canonicalize(path)? == path,
        "canonical absolute path required",
    )
}
fn open(path: &Path, cap: usize) -> Result<File> {
    canonical(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    require(
        m.is_file() && m.nlink() == 1 && m.len() > 0 && m.len() <= cap as u64,
        "bounded single-link regular file required",
    )?;
    Ok(file)
}
fn read(path: &Path, cap: usize) -> Result<Vec<u8>> {
    let file = open(path, cap)?;
    let length = file.metadata()?.len();
    let mut raw = Vec::new();
    file.take(cap as u64 + 1).read_to_end(&mut raw)?;
    require(raw.len() as u64 == length, "file size changed")?;
    Ok(raw)
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
        serde_json::Value::String(value) => {
            require(!value.contains("PRIVATE KEY"), "private marker rejected")?
        }
        _ => {}
    }
    Ok(())
}
// Value normally overwrites duplicate object members. Reject recursively before
// that lossy conversion so escaped/nested private fields cannot disappear.
struct NoDuplicates;
impl<'de> Deserialize<'de> for NoDuplicates {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = NoDuplicates;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON without duplicate keys")
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
                        return Err(de::Error::custom("duplicate JSON key rejected"));
                    }
                    map.next_value::<NoDuplicates>()?;
                }
                Ok(NoDuplicates)
            }
        }
        decoder.deserialize_any(Visitor)
    }
}
fn public_json(path: &Path, cap: usize) -> Result<Vec<u8>> {
    let raw = read(path, cap)?;
    let mut decoder = serde_json::Deserializer::from_slice(&raw);
    NoDuplicates::deserialize(&mut decoder)?;
    decoder.end()?;
    public_value(&serde_json::from_slice(&raw)?)?;
    Ok(raw)
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn check_time(
    q: &GcpProducerQualificationV1,
    s: &Selection,
    r: &Review,
    now: u64,
    fresh: bool,
) -> Result<()> {
    q.validity.check_at(now)?;
    require(
        r.experimental_retire_before < q.validity.not_before
            && r.retired_at <= r.reviewed_at
            && r.reviewed_at <= q.validity.not_before
            && q.validity.not_before - r.reviewed_at <= MAX_REVIEW_AGE
            && (!fresh
                || (now
                    .checked_sub(r.reviewed_at)
                    .is_some_and(|v| v <= MAX_REVIEW_AGE)
                    && now
                        .checked_sub(q.validity.not_before)
                        .is_some_and(|v| v <= MAX_REVIEW_AGE)))
            && q.validity.expires <= s.absolute_deadline,
        "retirement/review/live window rejected",
    )
}
fn check(
    q_path: &Path,
    selection: &Path,
    evidence: &Path,
    public: &Path,
    signed: bool,
) -> Result<(GcpProducerQualificationV1, Selection, Review)> {
    let q_raw = public_json(q_path, 16 << 10)?;
    let q: GcpProducerQualificationV1 = if signed {
        serde_json::from_slice::<Signed<GcpProducerQualificationV1>>(&q_raw)?.statement
    } else {
        serde_json::from_slice(&q_raw)?
    };
    q.signing_bytes()?;
    let s: Selection = serde_json::from_slice(&public_json(selection, 32 << 10)?)?;
    canonical(evidence)?;
    require(evidence.is_dir(), "evidence directory required")?;
    let entries = fs::read_dir(evidence)?.collect::<std::io::Result<Vec<_>>>()?;
    require(
        entries.len() == FILES.len()
            && entries.iter().all(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| FILES.contains(&name))
            }),
        "exact five public evidence files required",
    )?;
    let root = read(public, 32)?;
    require(
        root.len() == 32
            && root.as_slice() == s.expected.qualification_public_key
            && s.expected.qualification_public_key != [0; 32],
        "selected public root mismatch",
    )?;
    require(
        s.version == 1
            && s.purpose == "onb17.manual-qualification-selection.v1"
            && !s.reviewer.is_empty()
            && s.reviewer.len() <= 128
            && s.reviewer
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c))
            && s.workflow_id == WORKFLOW
            && s.experiment_namespace == EXPERIMENT
            && s.normal_namespace == NORMAL
            && !s.retired_instance_id.is_empty()
            && s.retired_instance_id.len() <= 20
            && s.retired_instance_id.bytes().all(|c| c.is_ascii_digit())
            && !s.retired_instance_id.starts_with('0'),
        "selection scope rejected",
    )?;
    let e = &s.expected;
    require(
        q.issuer == e.issuer
            && q.boot_binding_sha384 == e.boot_binding_sha384
            && q.pe_sha384 == e.pe_sha384
            && q.firmware_mrtd == e.firmware_mrtd
            && q.module_policy_sha384 == e.module_policy_sha384
            && q.evidence_refs == e.evidence_refs,
        "qualification expectation mismatch",
    )?;
    let refs = &q.evidence_refs;
    let hashes = [
        &refs.artifact_closure_sha384,
        &refs.firmware_causality_sha384,
        &refs.producer_isolation_sha384,
        &refs.no_state_copy_sha384,
        &refs.qualification_review_sha384,
    ];
    let mut review_raw = Vec::new();
    for (name, expected) in FILES.iter().zip(hashes) {
        let raw = public_json(&evidence.join(name), 1 << 20)?;
        require(hash(&raw) == *expected, "original evidence digest mismatch")?;
        if *name == FILES[4] {
            review_raw = raw;
        }
    }
    require(
        hash(&review_raw) == s.review_sha384,
        "selected review receipt mismatch",
    )?;
    let r: Review = serde_json::from_slice(&review_raw)?;
    require(
        r.version == 1
            && r.purpose == "onb17.manual-qualification-independent-review.v1"
            && r.reviewer == s.reviewer
            && r.qualification_id == q.qualification_id
            && r.issuer == q.issuer
            && r.validity == q.validity
            && r.boot_binding_sha384 == q.boot_binding_sha384
            && r.pe_sha384 == q.pe_sha384
            && r.firmware_mrtd == q.firmware_mrtd
            && r.module_policy_sha384 == q.module_policy_sha384
            && r.evidence_refs.artifact_closure_sha384 == refs.artifact_closure_sha384
            && r.evidence_refs.firmware_causality_sha384 == refs.firmware_causality_sha384
            && r.evidence_refs.producer_isolation_sha384 == refs.producer_isolation_sha384
            && r.evidence_refs.no_state_copy_sha384 == refs.no_state_copy_sha384
            && r.retired_instance_id == s.retired_instance_id
            && r.retired_at == s.retired_at
            && r.experimental_retire_before == s.experimental_retire_before
            && r.workflow_id == s.workflow_id
            && r.experiment_namespace == s.experiment_namespace
            && r.normal_namespace == s.normal_namespace
            && r.decision == "accepted_exact_profile_d5_d7"
            && r.authentication_only,
        "independent review scope rejected",
    )?;
    check_time(&q, &s, &r, now()?, !signed)?;
    if signed {
        verify_gcp_qualification(&q_raw, &s.expected, now()?)?;
    }
    Ok((q, s, r))
}
fn private_key(path: &Path, public: &[u8; 32]) -> Result<Ed25519KeyPair> {
    canonical(path)?;
    let parent = path.parent().ok_or("private directory missing")?;
    let m = fs::symlink_metadata(parent)?;
    require(
        path.file_name().and_then(|n| n.to_str()) == Some("qualification.pk8")
            && parent.parent() == Some(Path::new("/tmp"))
            && m.is_dir()
            && m.mode() & 0o777 == 0o700
            && m.uid() == unsafe { libc::geteuid() },
        "private path rejected",
    )?;
    let file = open(path, 83)?;
    let m = file.metadata()?;
    require(
        m.len() == 83 && m.mode() & 0o777 == 0o600 && m.uid() == unsafe { libc::geteuid() },
        "private metadata rejected",
    )?;
    let mut raw = Zeroizing::new(Vec::with_capacity(84));
    file.take(84).read_to_end(&mut raw)?;
    require(
        raw.len() == 83
            && raw.starts_with(&[
                0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
                0x04, 0x20,
            ]),
        "strict PKCS8v2 required",
    )?;
    let key = Ed25519KeyPair::from_pkcs8(&raw).map_err(|_| "private key rejected")?;
    require(
        key.public_key().as_ref() == public,
        "private/public root mismatch",
    )?;
    Ok(key)
}
fn output_path(path: &Path) -> Result<()> {
    require(
        path.is_absolute() && path.file_name().is_some(),
        "absolute output file required",
    )?;
    let parent = path.parent().ok_or("output directory missing")?;
    canonical(parent)?;
    require(
        !path.components().any(|c| {
            matches!(
                c,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        }),
        "canonical output required",
    )?;
    let m = fs::symlink_metadata(parent)?;
    require(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o777 == 0o700,
        "private output directory required",
    )?;
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("create-only output required".into()),
    }
}
fn profile_check(args: &[std::ffi::OsString]) -> Result<()> {
    let external = Path::new(&args[4]);
    canonical(external)?;
    let e: ArtifactVerificationExpectations =
        serde_json::from_slice(&public_json(&external.join("expectations.json"), 32 << 10)?)?;
    let b: GcpBootBindingV1 =
        serde_json::from_slice(&public_json(&external.join("binding.json"), 16 << 10)?)?;
    require(b == e.boot_binding, "external B mismatch")?;
    let a = verify_artifacts(
        &public_json(Path::new(&args[2]), 64 << 10)?,
        &public_json(Path::new(&args[3]), 1 << 20)?,
        &public_json(&external.join("signed-manifest.json"), 32 << 10)?,
        &public_json(&external.join("signed-references.json"), 32 << 10)?,
        &e,
    )?;
    require(
        hash(&read(Path::new(&args[5]), 64 << 20)?) == a.manifest().pe_file_sha384,
        "PE file digest mismatch",
    )?;
    println!("{{\"status\":\"PUBLIC_PROFILE_AUTHENTICATED_NOT_QUALIFIED\",\"boot_binding_sha384\":\"{}\",\"qualification_signed\":false}}", b.digest_sha384()?);
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() == 6 && args[1] == "profile-check" {
        return profile_check(&args);
    }
    let signing = args.get(1).is_some_and(|v| v == "sign");
    let signed = args.get(1).is_some_and(|v| v == "check-signed");
    require(
        (args.len() == 6 && (args[1] == "check" || signed)) || (args.len() == 8 && signing),
        "closed typed command required",
    )?;
    if signing {
        output_path(Path::new(&args[7]))?;
    }
    let (q, s, r) = check(
        Path::new(&args[2]),
        Path::new(&args[3]),
        Path::new(&args[4]),
        Path::new(&args[5]),
        signed,
    )?;
    if !signing {
        println!("{{\"status\":\"{}\",\"qualification_signed\":{},\"review_reproduced\":false,\"execution_verified\":false}}",
            if signed { "SIGNED_REVIEW_DECISION_AUTHENTICATED" } else { "REVIEWED_INPUTS_CHECKED_NOT_SIGNED" }, signed);
        return Ok(());
    }
    let limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    require(
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limits) } == 0
            && unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "dump protection rejected",
    )?;
    check_time(&q, &s, &r, now()?, true)?;
    let key = private_key(Path::new(&args[6]), &s.expected.qualification_public_key)?;
    let signature = key
        .sign(&q.signing_bytes()?)
        .as_ref()
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect();
    check_time(&q, &s, &r, now()?, true)?;
    let signed = serde_json::to_vec(&Signed {
        statement: q,
        signature,
    })?;
    verify_gcp_qualification(&signed, &s.expected, now()?)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&args[7])?;
    file.write_all(&signed)?;
    file.sync_all()?;
    File::open(
        Path::new(&args[7])
            .parent()
            .ok_or("output parent missing")?,
    )?
    .sync_all()?;
    println!("{{\"status\":\"REVIEW_DECISION_AUTHENTICATED\",\"qualification_signed\":true,\"review_reproduced\":false,\"execution_verified\":false}}");
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("qualification decision signer rejected");
        std::process::exit(1);
    }
}
