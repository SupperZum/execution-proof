use anyhow::{ensure, Result};
use onb17_gcp_trusted_services::server;
use std::path::Path;

fn run() -> Result<()> {
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "disable dumping"
    );
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    ensure!(
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } == 0,
        "disable cores"
    );
    unsafe { libc::umask(0o077) };
    let args: Vec<String> = std::env::args().collect();
    ensure!(
        (args.len() == 3 && (args[1] == "--check-config" || args[1] == "--check-startup"))
            || (args.len() == 5 && args[1] == "--serve" && args[3] == "--credential-fd")
            || (args.len() == 4 && args[1] == "--serve" && args[3] == "--credential-stdin"),
        "explicit server mode required"
    );
    let environment = std::env::vars_os().map(|(key, _)| key).collect::<Vec<_>>();
    // SAFETY: this entrypoint has not constructed the runtime or called any
    // verifier/server code which could start worker threads.
    for key in environment {
        unsafe { std::env::remove_var(key) }
    }
    let inputs = server::load(Path::new(&args[2]))?;
    if args[1] == "--check-config" {
        println!("{{\"status\":\"public_config_checked\",\"production_qualified\":false}}");
        return Ok(());
    }
    if args[1] == "--check-startup" {
        server::check_startup(&inputs)?;
        println!("{{\"status\":\"startup_inputs_checked\",\"production_qualified\":false}}");
        return Ok(());
    }
    // SAFETY: this dedicated startup owns the one inherited credential alias and
    // transfers it before any worker/runtime thread exists. It is not a path.
    let credential = if args[3] == "--credential-stdin" {
        server::take_credential_stdin()?
    } else {
        let fd: i32 = args[4].parse()?;
        ensure!(
            fd.to_string() == args[4],
            "canonical descriptor hint required"
        );
        unsafe { server::take_credential_fd(fd) }?
    };
    actix_web::rt::System::new().block_on(server::serve(inputs, credential))
}
fn main() -> std::process::ExitCode {
    std::panic::set_hook(Box::new(|_| {}));
    match std::panic::catch_unwind(run) {
        Ok(Ok(())) => std::process::ExitCode::SUCCESS,
        _ => {
            eprintln!("trusted GCP service startup or lifecycle rejected");
            std::process::ExitCode::FAILURE
        }
    }
}
