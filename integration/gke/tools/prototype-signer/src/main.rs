//! Trusted local prototype A/V/tenant signer. No qualification signing command.
use execution_proof_contract::{
    bootstrap::{verify_tenant_intent, TenantIntent, TenantIntentExpectations},
    gcp_artifact::{BootArtifactManifestV1, ReferencePolicySetV1},
    gcp_boot_binding::GcpBootBindingV1,
    Signed,
};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn filename(kind: &str) -> Result<&'static str> {
    match kind {
        "manifest" => Ok("build.pk8"),
        "reference" => Ok("reference.pk8"),
        "tenant-intent" => Ok("tenant.pk8"),
        _ => Err("statement kind rejected".into()),
    }
}

fn read(path: &Path, max: usize, private: bool) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 || meta.len() == 0 || meta.len() > max as u64 {
        return Err("input file rejected".into());
    }
    if private && (meta.mode() & 0o777 != 0o600 || meta.uid() != unsafe { libc::geteuid() }) {
        return Err("private permissions rejected".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take((max + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != meta.len() {
        return Err("changed input rejected".into());
    }
    Ok(bytes)
}

fn statement(kind: &str, raw: &[u8]) -> Result<(serde_json::Value, Vec<u8>)> {
    let (value, bytes) = match kind {
        "manifest" => {
            let value: BootArtifactManifestV1 = serde_json::from_slice(raw)?;
            let bytes = value.signing_bytes()?;
            (serde_json::to_value(value)?, bytes)
        }
        "reference" => {
            let value: ReferencePolicySetV1 = serde_json::from_slice(raw)?;
            let bytes = value.signing_bytes()?;
            (serde_json::to_value(value)?, bytes)
        }
        "tenant-intent" => {
            let value: TenantIntent = serde_json::from_slice(raw)?;
            let bytes = value.signing_bytes()?;
            (serde_json::to_value(value)?, bytes)
        }
        _ => return Err("statement kind rejected".into()),
    };
    Ok((value, bytes))
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() == 3 && args[1] == "binding-digest" {
        let raw = read(Path::new(&args[2]), 4096, false)?;
        let binding: GcpBootBindingV1 = serde_json::from_slice(&raw)?;
        println!("{}", binding.digest_sha384()?);
        return Ok(());
    }
    if args.len() != 6 {
        return Err("arguments rejected".into());
    }
    let kind = args[1].to_str().ok_or("kind rejected")?;
    let expected_name = filename(kind)?;
    let output = Path::new(&args[5]);
    if !output.is_absolute() || output.file_name().is_none() {
        return Err("absolute output file required".into());
    }
    let limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limits) } != 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
    {
        return Err("dump protection rejected".into());
    }
    let signer_path = Path::new(&args[3]);
    let parent = signer_path.parent().ok_or("private directory missing")?;
    let meta = fs::symlink_metadata(parent)?;
    if signer_path.file_name().and_then(|v| v.to_str()) != Some(expected_name)
        || fs::canonicalize(signer_path)? != signer_path
        || parent.parent() != Some(Path::new("/tmp"))
        || !meta.is_dir()
        || meta.mode() & 0o777 != 0o700
        || meta.uid() != unsafe { libc::geteuid() }
    {
        return Err("operator signer path rejected".into());
    }
    let raw = read(Path::new(&args[2]), 64 << 10, false)?;
    let (value, bytes) = statement(kind, &raw)?;
    let public = read(Path::new(&args[4]), 32, false)?;
    let public_array: [u8; 32] = public.as_slice().try_into()?;
    if public_array == [0; 32] {
        return Err("public root rejected".into());
    }
    let private = Zeroizing::new(read(signer_path, 83, true)?);
    if private.len() != 83 {
        return Err("strict PKCS8v2 required".into());
    }
    let key = Ed25519KeyPair::from_pkcs8(&private).map_err(|_| "operator key rejected")?;
    if key.public_key().as_ref() != public_array {
        return Err("selected public root mismatch".into());
    }
    let signature = key.sign(&bytes);
    UnparsedPublicKey::new(&ED25519, public_array)
        .verify(&bytes, signature.as_ref())
        .map_err(|_| "signature selfcheck rejected")?;
    let signature: String = signature
        .as_ref()
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect();
    let signed = serde_json::to_vec(&Signed {
        statement: value,
        signature,
    })?;
    if kind == "tenant-intent" {
        let intent: Signed<TenantIntent> = serde_json::from_slice(&signed)?;
        verify_tenant_intent(
            &signed,
            &TenantIntentExpectations {
                tenant_public_key: public_array,
                audience: intent.statement.audience.clone(),
                authority: intent.statement.authority.clone(),
                tenant: intent.statement.tenant.clone(),
                profile_sha384: intent.statement.profile_sha384.clone(),
            },
        )?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output)?;
    file.write_all(&signed)?;
    file.sync_all()?;
    fs::File::open(output.parent().ok_or("output parent missing")?)?.sync_all()?;
    println!("{{\"status\":\"prototype_statement_signed\",\"qualification_signed\":false}}");
    Ok(())
}

fn main() {
    if run().is_err() {
        eprintln!("prototype statement signer rejected");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_signing_roles_are_closed() {
        assert_eq!(filename("manifest").unwrap(), "build.pk8");
        assert_eq!(filename("reference").unwrap(), "reference.pk8");
        assert_eq!(filename("tenant-intent").unwrap(), "tenant.pk8");
        for kind in ["qualification", "challenge", "authority", "raw", ""] {
            assert!(filename(kind).is_err());
            assert!(statement(kind, b"{}").is_err());
        }
    }
}
