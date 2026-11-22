mod cli_output;
use execution_proof_contract::execution_quote::QuoteChallenge;
use execution_proof_verifier::{
    schema::{MAX_PACK_BYTES, MAX_TRUST_BYTES},
    verify_graph,
    worker::{verify_with_worker, TrustedWorker},
    EvidencePack, TrustConfig, VerificationError,
};
use std::{
    collections::BTreeMap, fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt, path::Path,
};

extern "C" fn resource_limit(_: libc::c_int) {
    // Only async-signal-safe operations run here; no allocation or locks.
    const RESULT: &[u8] = b"{\"version\":1,\"status\":\"unproven\",\"reason\":\"verifier_resource_limit\",\"claim\":\"exec_committed\",\"event_id\":null,\"record_sha384\":null,\"identity_scope\":\"authorized_workload_attempt\",\"time_semantics\":\"current_collateral_evaluation_of_historical_authorization\",\"evaluation_time_unix_seconds\":null}\n";
    cli_output::watchdog(RESULT);
}

fn read(path: &Path, limit: usize) -> Result<Vec<u8>, VerificationError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| VerificationError::MissingEvidence("input_unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| VerificationError::MissingEvidence("input_metadata"))?;
    if !metadata.is_file() {
        return Err(VerificationError::Invalid("input_not_regular_file"));
    }
    if metadata.len() > limit as u64 {
        return Err(VerificationError::ResourceLimit("input_bytes"));
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| VerificationError::MissingEvidence("input_read"))?;
    if bytes.len() > limit {
        return Err(VerificationError::ResourceLimit("input_bytes"));
    }
    Ok(bytes)
}

fn run() -> Result<execution_proof_verifier::VerificationVerdict, VerificationError> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 10 {
        return Err(VerificationError::Invalid(
            "expected_pack_trust_challenge_worker_and_worker_sha384",
        ));
    }
    let mut options = BTreeMap::new();
    for pair in arguments.as_chunks::<2>().0 {
        let key = pair[0]
            .to_str()
            .ok_or(VerificationError::Invalid("argument_encoding"))?;
        if ![
            "--pack",
            "--trust",
            "--challenge",
            "--tdx-worker",
            "--tdx-worker-sha384",
        ]
        .contains(&key)
            || options.insert(key, &pair[1]).is_some()
        {
            return Err(VerificationError::Invalid("unknown_or_duplicate_argument"));
        }
    }
    let get = |key| {
        options
            .get(key)
            .copied()
            .ok_or(VerificationError::Invalid("missing_argument"))
    };
    let pack = EvidencePack::decode(&read(Path::new(get("--pack")?), MAX_PACK_BYTES)?)?;
    let trust = TrustConfig::decode(&read(Path::new(get("--trust")?), MAX_TRUST_BYTES)?)?;
    let challenge = QuoteChallenge::decode(&read(Path::new(get("--challenge")?), 16 << 10)?)
        .map_err(|_| VerificationError::Invalid("challenge_rejected"))?;
    let graph = verify_graph(pack, &trust, &challenge)?;
    let worker_hash = get("--tdx-worker-sha384")?
        .to_str()
        .ok_or(VerificationError::Invalid("worker_hash_encoding"))?;
    let worker = TrustedWorker::open(Path::new(get("--tdx-worker")?), worker_hash)
        .map_err(|_| VerificationError::BackendUnavailable("worker_pin_rejected"))?
        .with_process_budget();
    verify_with_worker(graph, &worker)
}

fn main() {
    let verdict = match cli_output::limits(resource_limit).and_then(|_| run()) {
        Ok(value) => value,
        Err(error) => error.verdict(),
    };
    cli_output::finish(verdict)
}
