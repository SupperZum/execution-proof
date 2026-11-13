//! One bounded local operator request. A separately owned TLS frontend may
//! invoke this process; no submitted request controls operator paths or roots.
fn main() -> std::process::ExitCode {
    execution_proof_issuer::gcp_operator::run_stdio()
}
