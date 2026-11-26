use std::{
    env,
    error::Error,
    ffi::OsStr,
    fs::File,
    io::{self, Read, Write},
};

use execution_proof_contract::gcp_artifact::{
    validate_config_core, MAX_CONFIG_BYTES, MAX_CORE_BYTES,
};
use execution_proof_handoff::gcp_startup::{
    rpc_policy_bytes, WORKLOAD_POLICY_BYTES, WORKLOAD_POLICY_PATH,
};
use ring::digest::{digest, SHA384};

fn read_input(path: &OsStr, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn sha384(bytes: &[u8]) -> String {
    digest(&SHA384, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    let paths: Vec<_> = env::args_os().skip(1).collect();
    match paths.as_slice() {
        [mode] if mode == "--rpc-policy" => io::stdout().write_all(rpc_policy_bytes(false))?,
        [mode] if mode == "--sandbox-rpc-policy" => {
            io::stdout().write_all(rpc_policy_bytes(true))?
        }
        [mode] if mode == "--workload-policy" => io::stdout().write_all(WORKLOAD_POLICY_BYTES)?,
        [config, core, relay @ ..] if relay.len() <= 1 => {
            let (config, core) = validate_config_core(
                &read_input(config, MAX_CONFIG_BYTES)?,
                &read_input(core, MAX_CORE_BYTES)?,
            )?;
            let sandbox_gateway = match (config.management_relay.as_ref(), relay.first()) {
                (Some(expected), Some(path)) => {
                    expected
                        .authenticated_config(&read_input(path, 16 << 10)?)?
                        .sandbox_gateway
                }
                (_, None) => false,
                (None, Some(_)) => {
                    return Err("relay config supplied without a pinned relay".into())
                }
            };
            let workload_sha384 = sha384(WORKLOAD_POLICY_BYTES);
            if config.rpc_policy_sha384 != sha384(rpc_policy_bytes(sandbox_gateway))
                || !core.leaves.iter().any(|leaf| {
                    leaf.path == WORKLOAD_POLICY_PATH
                        && leaf.sha384 == workload_sha384
                        && leaf.size_bytes == WORKLOAD_POLICY_BYTES.len() as u64
                })
            {
                return Err("producer must use the fixed GCP RPC and workload policy bytes".into());
            }
        }
        _ => {
            return Err(
                "usage: gcp-build-inputs CONFIG.json PRODUCER-CORE.json [RELAY.json] | --rpc-policy | --sandbox-rpc-policy | --workload-policy"
                    .into(),
            );
        }
    }
    Ok(())
}
