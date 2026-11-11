use crate::{
    archive::{Archive, DeliveryScope},
    gcp_launch_credential::{LaunchCredentialConfig, LaunchCredentialService},
    gcp_launch_http::{self, LaunchHttpBackend, LaunchHttpService, ResourceDecisionResponse},
    gcp_launch_resource::{LaunchResourceConfig, LaunchResourceService},
    gcp_launch_session::{FreshLaunchSessions, SessionClock, SessionConfig, SessionError},
    plugins::resource::{RepositoryConfig, ResourceStorage, RESOURCE_STORAGE_NAMESPACE},
};
use actix_web::{
    body::to_bytes_limited,
    dev::{Service, ServiceResponse},
    web, App, HttpResponse, HttpServer,
};
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use execution_proof_contract::{
    gcp_boot_binding::GcpBootBindingV1,
    gcp_policy_receipt::{GcpLaunchPolicyAggregateV2, POLICY_AGGREGATE_PROFILE},
    GrantExpectations, Signed,
};
use execution_proof_verifier::{
    gcp_boot_evidence::GcpBootEvidencePolicy, gcp_tdx_policy::GcpTdxModulePolicyV1,
};
use key_value_storage::{KvStorageProvider, SetParameters, StorageBackendConfig, StorageProvider};
use openssl::{
    pkey::PKey,
    ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslVersion},
    x509::X509,
};
use policy_engine::{rego::Regorus, PolicyEngine};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Deserialize;
use sha2::{Digest, Sha384};
use std::{
    fs::OpenOptions,
    io::Read,
    net::SocketAddr,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::{mpsc, Arc},
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantConfig {
    pub authority_public_key: [u8; 32],
    pub audience: String,
    pub authority: String,
    pub tenant: String,
    pub image_policy_sha384: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilePin {
    pub path: PathBuf,
    pub sha384: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub id: String,
    pub policy: FilePin,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u16,
    pub purpose: String,
    pub listen: SocketAddr,
    pub server_name: String,
    pub grant: GrantConfig,
    pub boot_binding: GcpBootBindingV1,
    pub boot_policy: GcpBootEvidencePolicy,
    pub module_policy: GcpTdxModulePolicyV1,
    pub as_policy: PolicyConfig,
    pub as_data: Option<FilePin>,
    pub kbs_policy: PolicyConfig,
    pub aggregate_audience: String,
    pub aggregate_issuer: String,
    pub delivery_audience: String,
    pub delivery_issuer: String,
    pub resource_path: [String; 3],
    pub workflow_id: String,
    pub credential_project_id: String,
    pub credential_client_email: String,
    pub kbs_proof_public_key: [u8; 32],
    pub kbs_proof_key_path: PathBuf,
    pub tls_certificate: FilePin,
    pub tls_private_key_path: PathBuf,
    pub offline_collateral: FilePin,
    pub archive_directory: PathBuf,
    pub lifetime_seconds: u64,
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha384::digest(bytes))
}
fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
pub fn operator_file(path: &Path, limit: usize, secret: bool) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(path.is_absolute(), "absolute operator file required");
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    let owner = unsafe { libc::geteuid() };
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && (metadata.uid() == owner || (!secret && metadata.uid() == 0))
            && metadata.mode() & if secret { 0o077 } else { 0o022 } == 0
            && metadata.len() > 0
            && metadata.len() <= limit as u64,
        "operator file metadata rejected"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= limit,
        "operator file bound"
    );
    Ok(bytes)
}
fn pinned(file: &FilePin, limit: usize) -> Result<Vec<u8>> {
    ensure!(
        file.sha384.len() == 96
            && file
                .sha384
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "file pin encoding"
    );
    let bytes = operator_file(&file.path, limit, false)?;
    ensure!(hash(&bytes) == file.sha384, "selected public file changed");
    Ok(bytes.to_vec())
}
pub struct PublicInputs {
    pub config: Config,
    as_policy: String,
    as_data: Option<String>,
    kbs_policy: String,
    verifier: verifier::VerifierConfig,
    certificates: Vec<X509>,
}
pub fn load(path: &Path) -> Result<PublicInputs> {
    let config: Config = serde_json::from_slice(&operator_file(path, 64 << 10, false)?)?;
    ensure!(
        config.version == 1 && config.purpose == "qlad.execution-proof.gcp-trusted-kbs-config.v1",
        "service domain rejected"
    );
    ensure!(
        config.listen.is_ipv4()
            && !config.listen.ip().is_unspecified()
            && !config.listen.ip().is_multicast()
            && config.listen.port() != 0
            && config.lifetime_seconds >= 1
            && config.lifetime_seconds <= 14400,
        "service address/lifetime rejected"
    );
    ensure!(
        config.server_name.len() <= 253
            && config.server_name.split('.').all(|p| !p.is_empty()
                && p.len() <= 63
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')),
        "server name rejected"
    );
    config.boot_binding.validate()?;
    config.boot_policy.validate()?;
    config.module_policy.validate()?;
    ensure!(
        config.as_data.is_none(),
        "manual profile requires no external AS reference data"
    );
    ensure!(
        config.grant.authority_public_key != [0; 32]
            && config.kbs_proof_public_key != [0; 32]
            && config.grant.authority_public_key != config.kbs_proof_public_key,
        "separate public proof roots required"
    );
    ensure!(
        [
            &config.grant.audience,
            &config.grant.authority,
            &config.grant.tenant,
            &config.as_policy.id,
            &config.kbs_policy.id,
            &config.aggregate_audience,
            &config.aggregate_issuer,
            &config.delivery_audience,
            &config.delivery_issuer,
            &config.workflow_id
        ]
        .iter()
        .all(|v| id(v))
            && config.kbs_policy.id != "resource-policy",
        "service scope identifiers rejected"
    );
    ensure!(
        config
            .resource_path
            .iter()
            .all(|v| id(v) && !v.contains(':')),
        "resource scope rejected"
    );
    ensure!(
        id(&config.credential_project_id)
            && config.credential_client_email
                == format!(
                    "{}@{}.iam.gserviceaccount.com",
                    config
                        .credential_client_email
                        .split('@')
                        .next()
                        .unwrap_or(""),
                    config.credential_project_id
                )
            && config
                .credential_client_email
                .split('@')
                .next()
                .is_some_and(|v| id(v) && !v.contains(':')),
        "credential identity scope rejected"
    );
    let as_policy = String::from_utf8(pinned(&config.as_policy.policy, 1 << 20)?)?;
    let kbs_policy = String::from_utf8(pinned(&config.kbs_policy.policy, 1 << 20)?)?;
    for policy in [&as_policy, &kbs_policy] {
        regorus::Engine::new().add_policy("selected-policy.rego".into(), policy.clone())?;
    }
    let as_data = config
        .as_data
        .as_ref()
        .map(|pin| pinned(pin, 1 << 20).and_then(|b| Ok(String::from_utf8(b)?)))
        .transpose()?;
    if let Some(data) = &as_data {
        let _: serde_json::Value = serde_json::from_str(data)?;
    }
    let collateral: collateral_schema::PlatformCollaterals =
        serde_json::from_slice(&pinned(&config.offline_collateral, 4 << 20)?)?;
    ensure!(
        !collateral.collaterals.tcbinfos.is_empty()
            && collateral.collaterals.tdqeidentity_early.is_some()
            && !collateral.collaterals.rootcacrl.is_empty(),
        "offline TDX early collateral set unavailable"
    );
    let collateral = config
        .offline_collateral
        .path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("collateral path encoding"))?;
    ensure!(
        collateral
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b)),
        "literal offline collateral path required"
    );
    let verifier = serde_json::from_value(
        serde_json::json!({"dcap_verifier":{"collateral_service":format!("file://{collateral}"),"use_secure_cert":true,"tcb_update_type":"early"}}),
    )?;
    let certificates = X509::stack_from_pem(&pinned(&config.tls_certificate, 64 << 10)?)?;
    ensure!(
        !certificates.is_empty() && certificates.len() <= 8,
        "TLS certificate chain bound"
    );
    ensure!(
        certificates[0]
            .subject_alt_names()
            .is_some_and(|names| names
                .iter()
                .any(|name| name.dnsname() == Some(config.server_name.as_str()))),
        "TLS server SAN mismatch"
    );
    Ok(PublicInputs {
        config,
        as_policy,
        as_data,
        kbs_policy,
        verifier,
        certificates,
    })
}

/// The inherited descriptor contains only the bounded opaque Google SA JSON.
/// This initializer never accepts a payload path or writes plaintext to disk.
///
/// # Safety
/// Caller must transfer one owned inherited alias exactly once before threads
/// can close or reassign descriptors. It must not alias another live File owner.
pub unsafe fn take_credential_fd(fd: i32) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        (128..=4095).contains(&fd),
        "private descriptor alias rejected"
    );
    // SAFETY: caller transfers this inherited startup alias exactly once before threads.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    let required = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    ensure!(
        metadata.is_file()
            && metadata.len() > 0
            && metadata.len() <= 64 << 10
            && flags >= 0
            && flags & libc::O_ACCMODE == libc::O_RDONLY
            && seals >= 0
            && seals & required == required,
        "sealed read-only credential required"
    );
    let mut bytes = Zeroizing::new(vec![0; metadata.len() as usize]);
    file.read_exact_at(&mut bytes, 0)?;
    Ok(bytes)
}
/// SSH uses a pipe, not inherited descriptor numbers across the network. Read
/// one bounded length-prefixed private frame, with a shared absolute deadline,
/// and keep its bytes only in the owning process. A TTY or regular file fails.
pub fn take_credential_stdin() -> Result<Zeroizing<Vec<u8>>> {
    let fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 128) };
    ensure!(fd >= 0, "private input unavailable");
    // SAFETY: this new duplicate is owned by this pre-thread entrypoint.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    framed_credential(file, Duration::from_secs(10))
}
fn framed_credential(file: std::fs::File, timeout: Duration) -> Result<Zeroizing<Vec<u8>>> {
    let fd = file.as_raw_fd();
    let meta = file.metadata()?;
    ensure!(
        matches!(meta.mode() & libc::S_IFMT, libc::S_IFIFO | libc::S_IFSOCK),
        "private input must be a non-TTY pipe"
    );
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure!(
        flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
        "private input mode rejected"
    );
    let deadline = Instant::now() + timeout;
    fn read(fd: i32, bytes: &mut [u8], deadline: Instant) -> Result<usize> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            ensure!(!remaining.is_zero(), "private input deadline");
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            };
            let n = unsafe {
                libc::poll(
                    &mut pfd,
                    1,
                    remaining.as_millis().clamp(1, i32::MAX as u128) as i32,
                )
            };
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            ensure!(
                n > 0 && pfd.revents & (libc::POLLERR | libc::POLLNVAL) == 0,
                "private input unavailable"
            );
            let read = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
            if read < 0
                && matches!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                )
            {
                continue;
            }
            ensure!(read >= 0, "private input unavailable");
            return Ok(read as usize);
        }
    }
    fn exact(fd: i32, mut bytes: &mut [u8], deadline: Instant) -> Result<()> {
        while !bytes.is_empty() {
            let n = read(fd, bytes, deadline)?;
            ensure!(n > 0, "private input ended early");
            bytes = &mut bytes[n..];
        }
        Ok(())
    }
    let mut header = [0; 4];
    exact(file.as_raw_fd(), &mut header, deadline)?;
    let size = u32::from_be_bytes(header) as usize;
    ensure!((1..=64 << 10).contains(&size), "private input bound");
    let mut bytes = Zeroizing::new(vec![0; size]);
    exact(file.as_raw_fd(), &mut bytes, deadline)?;
    let mut trailing = [0; 1];
    ensure!(
        read(fd, &mut trailing, deadline)? == 0,
        "one private frame followed by EOF required"
    );
    Ok(bytes)
}
struct Clock;
impl SessionClock for Clock {
    fn now_unix_seconds(&self) -> std::result::Result<u64, SessionError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|t| t.as_secs())
            .map_err(|_| SessionError::ClockUnavailable)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceAccount {
    #[serde(rename = "type")]
    kind: String,
    project_id: String,
    private_key_id: String,
    #[serde(deserialize_with = "private_text")]
    private_key: Zeroizing<String>,
    client_email: String,
    client_id: String,
    auth_uri: String,
    token_uri: String,
    auth_provider_x509_cert_url: String,
    client_x509_cert_url: String,
    universe_domain: Option<String>,
}
fn private_text<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}
fn validate_credential(bytes: &[u8], project: &str, email: &str) -> Result<()> {
    let account: ServiceAccount = serde_json::from_slice(bytes)?;
    ensure!(
        account.kind == "service_account"
            && account.project_id == project
            && account.client_email == email
            && account.private_key_id.len() == 40
            && account
                .private_key_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && (10..=30).contains(&account.client_id.len())
            && account.client_id.bytes().all(|b| b.is_ascii_digit())
            && account.auth_uri == "https://accounts.google.com/o/oauth2/auth"
            && account.token_uri == "https://oauth2.googleapis.com/token"
            && account.auth_provider_x509_cert_url == "https://www.googleapis.com/oauth2/v1/certs"
            && account
                .client_x509_cert_url
                .starts_with("https://www.googleapis.com/robot/v1/metadata/x509/")
            && account
                .universe_domain
                .as_deref()
                .is_none_or(|v| v == "googleapis.com"),
        "credential scope rejected"
    );
    let key = PKey::private_key_from_pem(account.private_key.as_bytes())?;
    ensure!(
        key.id() == openssl::pkey::Id::RSA && key.bits() == 2048,
        "credential key profile rejected"
    );
    Ok(())
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
struct Deadline {
    cancel: Option<mpsc::SyncSender<()>>,
    join: Option<JoinHandle<()>>,
}
impl Deadline {
    fn new(seconds: u64) -> Self {
        let (tx, rx) = mpsc::sync_channel(1);
        let join = std::thread::spawn(move || {
            if rx.recv_timeout(Duration::from_secs(seconds)).is_err() {
                unsafe { libc::_exit(124) }
            }
        });
        Self {
            cancel: Some(tx),
            join: Some(join),
        }
    }
}
impl Drop for Deadline {
    fn drop(&mut self) {
        if let Some(tx) = self.cancel.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn proof_signers(c: &Config) -> Result<(Ed25519KeyPair, Ed25519KeyPair)> {
    let key = operator_file(&c.kbs_proof_key_path, 16 << 10, true)?;
    let pair =
        Ed25519KeyPair::from_pkcs8(&key).map_err(|_| anyhow::anyhow!("KBS proof key rejected"))?;
    ensure!(
        pair.public_key().as_ref() == c.kbs_proof_public_key,
        "KBS proof key mismatch"
    );
    let signer =
        Ed25519KeyPair::from_pkcs8(&key).map_err(|_| anyhow::anyhow!("KBS proof key rejected"))?;
    Ok((pair, signer))
}
fn tls_inputs(c: &Config, certificates: Vec<X509>) -> Result<SslAcceptorBuilder> {
    let private =
        PKey::private_key_from_pem(&operator_file(&c.tls_private_key_path, 16 << 10, true)?)?;
    ensure!(
        private.id() == openssl::pkey::Id::EC
            && private.ec_key()?.group().curve_name() == Some(openssl::nid::Nid::X9_62_PRIME256V1),
        "management TLS requires a separate P-256 key"
    );
    let mut tls = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
    tls.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    tls.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    tls.set_certificate(&certificates[0])?;
    for certificate in certificates.into_iter().skip(1) {
        tls.add_extra_chain_cert(certificate)?;
    }
    tls.set_private_key(&private)?;
    tls.check_private_key()?;
    Ok(tls)
}
/// Validate private proof/TLS key pairing before any SA key is created or read.
/// This performs no bind, session, quote, resource or permission operation.
pub fn check_startup(inputs: &PublicInputs) -> Result<()> {
    let _ = proof_signers(&inputs.config)?;
    let _ = tls_inputs(&inputs.config, inputs.certificates.clone())?;
    Ok(())
}
pub async fn serve(inputs: PublicInputs, credential: Zeroizing<Vec<u8>>) -> Result<()> {
    let c = inputs.config;
    let delivery_scope = Arc::new(DeliveryScope {
        public_key: c.kbs_proof_public_key,
        audience: c.delivery_audience.clone(),
        issuer: c.delivery_issuer.clone(),
        boot_binding_sha384: c.boot_binding.digest_sha384()?,
    });
    let _deadline = Deadline::new(c.lifetime_seconds);
    validate_credential(
        &credential,
        &c.credential_project_id,
        &c.credential_client_email,
    )?;
    let (pair, signer) = proof_signers(&c)?;
    let tls = tls_inputs(&c, inputs.certificates)?;
    let provider = KvStorageProvider::new(StorageBackendConfig::default());
    let as_engine: PolicyEngine<Regorus> =
        PolicyEngine::new(provider.get_or_register("onb17-as-policy").await?);
    let kbs_engine: PolicyEngine<Regorus> =
        PolicyEngine::new(provider.get_or_register("onb17-kbs-policy").await?);
    as_engine
        .set_policy(&c.as_policy.id, &inputs.as_policy, false)
        .await?;
    kbs_engine
        .set_policy(&c.kbs_policy.id, &inputs.kbs_policy, false)
        .await?;
    let sessions = FreshLaunchSessions::new(
        SessionConfig {
            grant_expectations: GrantExpectations {
                authority_public_key: c.grant.authority_public_key,
                audience: c.grant.audience,
                authority: c.grant.authority,
                tenant: c.grant.tenant,
                profile_sha384: c.boot_binding.digest_sha384()?,
                launch_policy_sha384: c.as_policy.policy.sha384,
                image_policy_sha384: c.grant.image_policy_sha384,
            },
            boot_binding: c.boot_binding,
            boot_policy: c.boot_policy,
            module_policy: c.module_policy,
            selected_policy_id: c.as_policy.id,
            reference_data: inputs.as_data,
            capacity: 1,
        },
        Arc::new(Clock),
    )?;
    let resource = LaunchResourceService::new(LaunchResourceConfig {
        sessions: sessions.clone(),
        engine: kbs_engine,
        policy_id: c.kbs_policy.id,
        policy_sha384: c.kbs_policy.policy.sha384,
        signer: pair,
        audience: c.aggregate_audience,
        issuer: c.aggregate_issuer,
        profile: POLICY_AGGREGATE_PROFILE.into(),
        capacity: 1,
    })?;
    let repository = provider.get_or_register(RESOURCE_STORAGE_NAMESPACE).await?;
    let path = c.resource_path.join("/");
    repository
        .set(&path, &credential, SetParameters { overwrite: false })
        .await?;
    drop(credential);
    let storage = ResourceStorage::new(RepositoryConfig::KvStorage, provider.clone()).await?;
    let delivery = LaunchCredentialService::new(LaunchCredentialConfig {
        resource: resource.clone(),
        storage,
        resource_path: c.resource_path,
        workflow_id: c.workflow_id,
        signer,
        audience: c.delivery_audience,
        issuer: c.delivery_issuer,
        capacity: 1,
    })?;
    let service = web::Data::new(
        LaunchHttpService::new(
            sessions,
            LaunchHttpBackend {
                verifier_config: Some(inputs.verifier),
                storage: provider,
                engine: as_engine,
            },
            resource.clone(),
        )?
        .with_credential_service(delivery)?,
    );
    let archive = Arc::new(Archive::open(&c.archive_directory)?);
    let permits = Arc::new(tokio::sync::Semaphore::new(8));
    let server = HttpServer::new(move || {
        let resource = resource.clone();
        let archive = archive.clone();
        let delivery_scope = delivery_scope.clone();
        let permits = permits.clone();
        App::new()
            .app_data(service.clone())
            .configure(gcp_launch_http::configure)
            .wrap_fn(move |request, server| {
                let needs_archive = request.path()
                    == format!("{}/resource-decision", gcp_launch_http::LAUNCH_HTTP_PREFIX);
                let needs_delivery = request.path()
                    == format!(
                        "{}/credential-delivery",
                        gcp_launch_http::LAUNCH_HTTP_PREFIX
                    );
                let permit = permits.clone().try_acquire_owned();
                let future = permit.as_ref().ok().map(|_| server.call(request));
                let resource = resource.clone();
                let archive = archive.clone();
                let delivery_scope = delivery_scope.clone();
                async move {
                    let _permit = permit.map_err(|_| {
                        actix_web::error::ErrorServiceUnavailable(
                            "trusted service capacity exhausted",
                        )
                    })?;
                    let response = future
                        .ok_or_else(|| {
                            actix_web::error::ErrorServiceUnavailable(
                                "trusted service capacity exhausted",
                            )
                        })?
                        .await?;
                    if !(needs_archive || needs_delivery)
                        || response.status() != actix_web::http::StatusCode::OK
                    {
                        return Ok(response.map_into_boxed_body());
                    }
                    let (request, response) = response.into_parts();
                    let status = response.status();
                    let bytes = to_bytes_limited(response.into_body(), 128 << 10)
                        .await
                        .map_err(|_| {
                            actix_web::error::ErrorServiceUnavailable("policy response bound")
                        })?
                        .map_err(|_| {
                            actix_web::error::ErrorServiceUnavailable("policy response unavailable")
                        })?;
                    let committed = (|| -> Result<()> {
                        if needs_delivery {
                            return archive.store_delivery_response(&bytes, &delivery_scope);
                        }
                        let response: ResourceDecisionResponse = serde_json::from_slice(&bytes)?;
                        let wire = STANDARD.decode(
                            response
                                .signed_aggregate_b64
                                .ok_or_else(|| anyhow::anyhow!("aggregate unavailable"))?,
                        )?;
                        ensure!(wire.len() <= 32 << 10, "aggregate bound");
                        let aggregate: Signed<GcpLaunchPolicyAggregateV2> =
                            serde_json::from_slice(&wire)?;
                        let digest = aggregate.statement.digest_sha384()?;
                        let snapshot = resource
                            .export_policy_capture(&aggregate.statement.session_id, &digest)?;
                        ensure!(
                            snapshot.signed_aggregate_json() == wire,
                            "archive service identity mismatch"
                        );
                        archive.store(&snapshot)
                    })();
                    committed.map_err(|_| {
                        actix_web::error::ErrorServiceUnavailable(
                            "original policy archive unavailable",
                        )
                    })?;
                    Ok(ServiceResponse::new(
                        request,
                        HttpResponse::build(status)
                            .content_type("application/json")
                            .body(bytes),
                    )
                    .map_into_boxed_body())
                }
            })
    })
    .workers(1)
    .backlog(16)
    .max_connections(16)
    .client_request_timeout(Duration::from_secs(10))
    .client_disconnect_timeout(Duration::from_secs(5))
    .keep_alive(Duration::from_secs(5))
    .shutdown_timeout(5)
    .bind_openssl(c.listen, tls)?
    .run();
    println!("{{\"status\":\"https_listening\",\"production_qualified\":false}}");
    server.await?;
    Ok(())
}
