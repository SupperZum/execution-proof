//! Fixed-path, immutable-view readback for the GCP role entrypoints. This
//! authenticates local bytes and authority statements. It does not prove that
//! firmware booted this view; independent hardware qualification remains required.
use crate::startup::{ExpectedStartup, Role};
use execution_proof_contract::{
    gcp_artifact::{
        self, ArtifactVerificationExpectations, AuthenticatedArtifacts, BootArtifactManifestV1,
        ClosedBootConfigV1, ProducerCoreV1, ReferencePolicySetV1,
    },
    gcp_boot_binding::GcpBootBindingV1,
    gcp_policy_receipt::{
        verify_policy_aggregate, GcpAggregateExpectations, GcpLaunchPolicyAggregateV2,
    },
    gcp_startup::{verify_attempt_plan, GcpAttemptPlanV1, GcpRoleCapsuleV1, MAX_CAPSULE_BYTES},
    verify_launch_grant_historical, GrantExpectations, LaunchGrant, Signed,
};
use ring::digest::{Context, SHA384};
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    },
};

pub const CONFIG_PATH: &str = "/onb17/boot/config.json";
pub const CORE_PATH: &str = "/onb17/boot/producer-core.json";
pub const KATA_SOCKET: &str = "/run/onb17/kata-agent.sock";
pub const MAX_PUBLIC_EXPORT: usize = 12 << 20;
pub const WORKLOAD_POLICY_PATH: &str = "/onb17/policy/workload.json";
pub const WORKLOAD_POLICY_BYTES: &[u8] = br#"{"version":1,"purpose":"qlad.execution-proof.gcp-static-workload-policy.v1","uid":1000,"gid":1000,"syscalls":["execveat","exit_group","write"],"image_bytes":33554432,"inodes":4096}"#;
pub const WORKLOAD_UID: u32 = 1000;
pub const WORKLOAD_GID: u32 = 1000;
pub const WORKLOAD_SYSCALLS: [&str; 3] = ["execveat", "exit_group", "write"];
pub const MAX_IMAGE_BYTES: u64 = 32 << 20;
pub const MAX_IMAGE_INODES: u64 = 4096;
pub const RPC_POLICY_BYTES: &[u8] = br#"{"version":1,"purpose":"qlad.execution-proof.gcp-rpc-policy.v1","service":"grpc.AgentService","task_methods":["CloseStdin","CreateContainer","ReadStderr","ReadStdout","RemoveContainer","SignalProcess","StartContainer","WaitProcess","WriteStdin"],"handshake_methods":["CreateSandbox","GetGuestDetails"],"task_requires_sandbox_ack":true,"inflight_requests":32,"sandbox_alias_bytes":128,"sandbox_dns":false,"sandbox_storages":false,"sandbox_hooks":false,"sandbox_kernel_modules":false,"sandbox_shared_pidns":false,"memory_hotplug":false,"signals":[9],"stdio_bytes":32768,"unknown_top_level_fields":false,"other_methods":false}"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupRejected;
impl std::fmt::Display for StartupRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GCP role startup rejected")
    }
}
impl std::error::Error for StartupRejected {}
type Result<T> = std::result::Result<T, StartupRejected>;
fn reject<T, E>(r: std::result::Result<T, E>) -> Result<T> {
    r.map_err(|_| StartupRejected)
}
fn hash(b: &[u8]) -> String {
    hex(ring::digest::digest(&SHA384, b).as_ref())
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn raw48(s: &str) -> Result<[u8; 48]> {
    if s.len() != 96
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(StartupRejected);
    }
    let mut b = [0; 48];
    for (i, v) in b.iter_mut().enumerate() {
        *v = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| StartupRejected)?;
    }
    Ok(b)
}

/// Non-serializable authenticated public configuration, not a boot capability.
/// File owners remain alive while the role uses its fixed immutable closure.
pub struct LoadedRole {
    artifacts: AuthenticatedArtifacts,
    binding: GcpBootBindingV1,
    capsule: GcpRoleCapsuleV1,
    grant: LaunchGrant,
    aggregate: GcpLaunchPolicyAggregateV2,
    plan: GcpAttemptPlanV1,
    expected: ExpectedStartup,
    _files: Vec<File>,
}
impl LoadedRole {
    pub fn artifacts(&self) -> &AuthenticatedArtifacts {
        &self.artifacts
    }
    pub fn binding(&self) -> &GcpBootBindingV1 {
        &self.binding
    }
    pub fn capsule(&self) -> &GcpRoleCapsuleV1 {
        &self.capsule
    }
    pub fn grant(&self) -> &LaunchGrant {
        &self.grant
    }
    pub fn aggregate(&self) -> &GcpLaunchPolicyAggregateV2 {
        &self.aggregate
    }
    pub fn plan(&self) -> &GcpAttemptPlanV1 {
        &self.plan
    }
    pub fn expected_startup(&self) -> ExpectedStartup {
        ExpectedStartup {
            role: self.expected.role,
            boot_config_sha384: self.expected.boot_config_sha384,
            own_executable_sha384: self.expected.own_executable_sha384,
            peer_executable_sha384: self.expected.peer_executable_sha384,
        }
    }
}

/// The environment supplies only a descriptor location hint. It cannot select
/// roots, paths, accepted role bytes, policy, B, or a successful gate result.
pub fn load(role: Role) -> Result<LoadedRole> {
    let hint = std::env::var("ONB17_GCP_CAPSULE_FD").map_err(|_| StartupRejected)?;
    if hint.is_empty()
        || hint.len() > 10
        || hint.starts_with('0')
        || !hint.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(StartupRejected);
    }
    let fd: i32 = hint.parse().map_err(|_| StartupRejected)?;
    if fd < 128 {
        return Err(StartupRejected);
    }
    let alias = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 128) };
    if alias < 0 {
        return Err(StartupRejected);
    }
    let file = unsafe { File::from_raw_fd(alias) };
    let loaded = load_capsule(role, file)?;
    // The launcher clears CLOEXEC so the capsule reaches this role.
    // Restore it after validating the capsule to confine the inherited alias.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(StartupRejected);
    }
    Ok(loaded)
}
pub fn load_capsule(role: Role, capsule_file: File) -> Result<LoadedRole> {
    let capsule = reject(GcpRoleCapsuleV1::decode(&read_sealed_public(
        &capsule_file,
        MAX_CAPSULE_BYTES,
    )?))?;
    let EmbeddedRole {
        config,
        core: _,
        c,
        d,
        mut files,
        expected: expected_startup,
    } = load_embedded(role)?;
    let (binding, artifacts) = authenticate_artifacts(
        &config,
        &c,
        &d,
        &capsule.signed_manifest,
        &capsule.signed_references,
    )?;
    files.push(capsule_file);
    let grant_expect = GrantExpectations {
        authority_public_key: config.roots.authority_public_key,
        audience: config.grant_audience.clone(),
        authority: config.authority.clone(),
        tenant: config.tenant.clone(),
        profile_sha384: reject(binding.digest_sha384())?,
        launch_policy_sha384: config.launch_policy_sha384.clone(),
        image_policy_sha384: config.image_policy_sha384.clone(),
    };
    let grant = reject(verify_launch_grant_historical(
        &capsule.signed_grant,
        &grant_expect,
    ))?;
    let ag: Signed<GcpLaunchPolicyAggregateV2> =
        reject(serde_json::from_slice(&capsule.signed_aggregate))?;
    let aggregate = reject(verify_policy_aggregate(
        &capsule.signed_aggregate,
        &grant,
        &GcpAggregateExpectations {
            kbs_proof_public_key: config.roots.kbs_proof_public_key,
            boot_binding: binding.clone(),
            expected: ag.statement.clone(),
        },
    ))?;
    if aggregate.statement().audience != config.aggregate_audience
        || aggregate.statement().request.resource_path != config.resource_path
        || aggregate.statement().request.workflow_id != config.workflow_id
    {
        return Err(StartupRejected);
    }
    let plan = reject(verify_attempt_plan(
        &capsule.signed_plan,
        &config.roots.authority_public_key,
        &grant,
        &aggregate,
        &binding,
    ))?;
    if hash(&capsule.effective_spec) != plan.effective_spec_sha384 {
        return Err(StartupRejected);
    }
    let signed_grant: Signed<LaunchGrant> = reject(serde_json::from_slice(&capsule.signed_grant))?;
    Ok(LoadedRole {
        artifacts,
        binding,
        capsule,
        grant: signed_grant.statement,
        aggregate: ag.statement,
        plan,
        expected: expected_startup,
        _files: files,
    })
}

pub struct EmbeddedRole {
    config: ClosedBootConfigV1,
    core: ProducerCoreV1,
    c: Vec<u8>,
    d: Vec<u8>,
    files: Vec<File>,
    expected: ExpectedStartup,
}
impl EmbeddedRole {
    pub fn config(&self) -> &ClosedBootConfigV1 {
        &self.config
    }
    pub fn core(&self) -> &ProducerCoreV1 {
        &self.core
    }
    pub fn authenticate_artifacts(
        &self,
        a: &[u8],
        v: &[u8],
    ) -> Result<(GcpBootBindingV1, AuthenticatedArtifacts)> {
        authenticate_artifacts(&self.config, &self.c, &self.d, a, v)
    }
    pub fn expected_startup(&self) -> ExpectedStartup {
        ExpectedStartup {
            role: self.expected.role,
            boot_config_sha384: self.expected.boot_config_sha384,
            own_executable_sha384: self.expected.own_executable_sha384,
            peer_executable_sha384: self.expected.peer_executable_sha384,
        }
    }
    pub fn read_leaf(&self, path: &str, max: usize) -> Result<Vec<u8>> {
        let leaf = self
            .core
            .leaves
            .iter()
            .find(|l| l.path == path)
            .ok_or(StartupRejected)?;
        let (_, bytes) = fixed_file(path, max)?;
        if bytes.len() as u64 != leaf.size_bytes || hash(&bytes) != leaf.sha384 {
            return Err(StartupRejected);
        }
        Ok(bytes)
    }
}
/// Perform this fixed immutable closure check before generating recorder keys or
/// opening any host-reachable listener. No untrusted path or root is accepted.
pub fn load_embedded(role: Role) -> Result<EmbeddedRole> {
    let (c_file, c) = fixed_file(CONFIG_PATH, gcp_artifact::MAX_CONFIG_BYTES)?;
    let (d_file, d) = fixed_file(CORE_PATH, gcp_artifact::MAX_CORE_BYTES)?;
    let (config, core) = reject(gcp_artifact::validate_config_core(&c, &d))?;
    if core.config_sha384 != hash(&c)
        || config.rpc_policy_sha384 != hash(RPC_POLICY_BYTES)
        || !core.leaves.iter().any(|l| {
            l.path == WORKLOAD_POLICY_PATH
                && l.sha384 == hash(WORKLOAD_POLICY_BYTES)
                && l.size_bytes == WORKLOAD_POLICY_BYTES.len() as u64
        })
    {
        return Err(StartupRejected);
    }
    let mut files = vec![c_file, d_file];
    for leaf in &core.leaves {
        let (file, bytes) = fixed_file(
            &leaf.path,
            usize::try_from(leaf.size_bytes).map_err(|_| StartupRejected)?,
        )?;
        if bytes.len() as u64 != leaf.size_bytes || hash(&bytes) != leaf.sha384 {
            return Err(StartupRejected);
        }
        files.push(file);
    }
    if let Some(relay) = &config.management_relay {
        let (_, bytes) = fixed_file(&relay.configuration_path, 16 << 10)?;
        reject(relay.check_config_bytes(&bytes))?;
    }
    verify_inventory(&core)?;
    let own = match role {
        Role::Preparation => &config.cdh_path,
        Role::Kata => &config.kata_agent_path,
    };
    let peer = match role {
        Role::Preparation => &config.kata_agent_path,
        Role::Kata => &config.cdh_path,
    };
    let leaf = |p: &str| {
        core.leaves
            .iter()
            .find(|l| l.path == p)
            .ok_or(StartupRejected)
    };
    let own_leaf = leaf(own)?;
    let self_file = reject(File::open("/proc/self/exe"))?;
    let seals = unsafe { libc::fcntl(self_file.as_raw_fd(), libc::F_GET_SEALS) };
    let required = libc::F_SEAL_WRITE
        | libc::F_SEAL_GROW
        | libc::F_SEAL_SHRINK
        | libc::F_SEAL_SEAL
        | libc::F_SEAL_EXEC;
    if seals < 0 || seals & required != required {
        readonly_erofs(&self_file)?;
    }
    if file_hash(&self_file, own_leaf.size_bytes)? != own_leaf.sha384 {
        return Err(StartupRejected);
    }
    files.push(self_file);
    let expected = ExpectedStartup {
        role,
        boot_config_sha384: raw48(&hash(&c))?,
        own_executable_sha384: raw48(&own_leaf.sha384)?,
        peer_executable_sha384: raw48(&leaf(peer)?.sha384)?,
    };
    Ok(EmbeddedRole {
        config,
        core,
        c,
        d,
        files,
        expected,
    })
}
fn authenticate_artifacts(
    config: &ClosedBootConfigV1,
    c: &[u8],
    d: &[u8],
    a_bytes: &[u8],
    v_bytes: &[u8],
) -> Result<(GcpBootBindingV1, AuthenticatedArtifacts)> {
    if a_bytes.is_empty()
        || a_bytes.len() > gcp_artifact::MAX_MANIFEST_BYTES
        || v_bytes.is_empty()
        || v_bytes.len() > gcp_artifact::MAX_REFERENCE_BYTES
    {
        return Err(StartupRejected);
    }
    let a: Signed<BootArtifactManifestV1> = reject(serde_json::from_slice(a_bytes))?;
    let v: Signed<ReferencePolicySetV1> = reject(serde_json::from_slice(v_bytes))?;
    let binding = reject(GcpBootBindingV1::new(
        raw48(&hash(c))?,
        raw48(&hash(d))?,
        raw48(&hash(a_bytes))?,
        raw48(&hash(v_bytes))?,
    ))?;
    let expected = ArtifactVerificationExpectations {
        build_public_key: config.roots.build_public_key,
        reference_public_key: config.roots.reference_public_key,
        build_issuer: a.statement.issuer.clone(),
        reference_issuer: v.statement.issuer.clone(),
        boot_binding: binding.clone(),
        pe_authenticode_sha384: v.statement.pe_authenticode_sha384.clone(),
        firmware_mrtd: v.statement.firmware_mrtd.clone(),
        module_policy_sha384: v.statement.module_policy_sha384.clone(),
        firmware_endorsement_sha384: v.statement.firmware_endorsement_sha384.clone(),
        quote_framing: v.statement.quote_framing,
    };
    let artifacts = reject(gcp_artifact::verify_artifacts(
        c, d, a_bytes, v_bytes, &expected,
    ))?;
    Ok((binding, artifacts))
}

fn readonly_erofs(file: &File) -> Result<()> {
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut fs) } != 0
        || unsafe { libc::fstatvfs(file.as_raw_fd(), &mut vfs) } != 0
        || fs.f_type as u64 != 0xe0f5e1e2
        || vfs.f_flag & libc::ST_RDONLY == 0
    {
        return Err(StartupRejected);
    }
    Ok(())
}
fn verify_inventory(core: &ProducerCoreV1) -> Result<()> {
    fn visit(path: &str, depth: usize, count: &mut usize, core: &ProducerCoreV1) -> Result<()> {
        if depth > 16 || *count > 256 {
            return Err(StartupRejected);
        }
        for e in reject(std::fs::read_dir(path))? {
            let e = reject(e)?;
            let name = e.file_name().into_string().map_err(|_| StartupRejected)?;
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                return Err(StartupRejected);
            }
            let p = if path == "/" {
                format!("/{name}")
            } else {
                format!("{path}/{name}")
            };
            // These four runtime mount roots are established by measured PID1;
            // none may provide executable loader/config/TCB leaf paths.
            if ["/run", "/proc", "/sys", "/dev"].contains(&p.as_str()) {
                continue;
            }
            *count += 1;
            if *count > 256 {
                return Err(StartupRejected);
            }
            let ty = reject(e.file_type())?;
            if ty.is_dir() {
                visit(&p, depth + 1, count, core)?;
            } else if !ty.is_file()
                || !(p == CONFIG_PATH || p == CORE_PATH || core.leaves.iter().any(|l| l.path == p))
            {
                return Err(StartupRejected);
            }
        }
        Ok(())
    }
    visit("/", 0, &mut 0, core)
}
fn fixed_file(path: &str, max: usize) -> Result<(File, Vec<u8>)> {
    if !path.starts_with('/') || path.len() > 256 {
        return Err(StartupRejected);
    }
    let mut file = reject(File::open("/"))?;
    readonly_erofs(&file)?;
    let parts: Vec<_> = path[1..].split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() || *part == "." || *part == ".." {
            return Err(StartupRejected);
        }
        let name = reject(CString::new(*part))?;
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | if i + 1 < parts.len() {
                libc::O_DIRECTORY
            } else {
                0
            };
        let raw = unsafe { libc::openat(file.as_raw_fd(), name.as_ptr(), flags) };
        if raw < 0 {
            return Err(StartupRejected);
        }
        file = unsafe { File::from_raw_fd(raw) };
        readonly_erofs(&file)?;
        let meta = reject(file.metadata())?;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(StartupRejected);
        }
    }
    let meta = reject(file.metadata())?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > max as u64 {
        return Err(StartupRejected);
    }
    let mut bytes = Vec::new();
    reject((&file).take(max as u64 + 1).read_to_end(&mut bytes))?;
    if bytes.len() > max {
        return Err(StartupRejected);
    }
    Ok((file, bytes))
}
fn file_hash(file: &File, size: u64) -> Result<String> {
    if reject(file.metadata())?.len() != size {
        return Err(StartupRejected);
    }
    let mut ctx = Context::new(&SHA384);
    let mut b = [0; 8192];
    let mut off = 0;
    while off < size {
        let n = (size - off).min(b.len() as u64) as usize;
        reject(file.read_exact_at(&mut b[..n], off))?;
        ctx.update(&b[..n]);
        off += n as u64;
    }
    Ok(hex(ctx.finish().as_ref()))
}

pub fn sealed_public_file(bytes: &[u8], max: usize) -> Result<File> {
    if bytes.is_empty() || bytes.len() > max {
        return Err(StartupRejected);
    }
    let name = CString::new("gcp-public-capsule").map_err(|_| StartupRejected)?;
    let fd = unsafe {
        libc::memfd_create(
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | libc::MFD_NOEXEC_SEAL,
        )
    };
    if fd < 0 {
        return Err(StartupRejected);
    }
    let mut writer = unsafe { File::from_raw_fd(fd) };
    reject(writer.write_all(bytes))?;
    let seals = libc::F_SEAL_WRITE
        | libc::F_SEAL_GROW
        | libc::F_SEAL_SHRINK
        | libc::F_SEAL_SEAL
        | libc::F_SEAL_EXEC;
    if unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err(StartupRejected);
    }
    let file = reject(
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(format!("/proc/self/fd/{}", writer.as_raw_fd())),
    )?;
    drop(writer);
    Ok(file)
}
pub fn read_sealed_public(file: &File, max: usize) -> Result<Vec<u8>> {
    let meta = reject(file.metadata())?;
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    let required = libc::F_SEAL_WRITE
        | libc::F_SEAL_GROW
        | libc::F_SEAL_SHRINK
        | libc::F_SEAL_SEAL
        | libc::F_SEAL_EXEC;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if !meta.is_file()
        || meta.mode() & 0o111 != 0
        || meta.len() == 0
        || meta.len() > max as u64
        || seals < 0
        || seals & required != required
        || flags < 0
        || flags & libc::O_ACCMODE != libc::O_RDONLY
    {
        return Err(StartupRejected);
    }
    let mut bytes = vec![0; meta.len() as usize];
    reject(file.read_exact_at(&mut bytes, 0))?;
    Ok(bytes)
}

/// Owns the unprivileged transport process on its launching thread. Its private
/// TLS key serves management only; it is never a proof/attestation signing key.
pub struct ManagementRelayOwner {
    child: std::process::Child,
    stopped: bool,
    _launch_thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl ManagementRelayOwner {
    pub fn stop_and_wait(&mut self) -> Result<()> {
        if !self.stopped {
            if reject(self.child.try_wait())?.is_none() {
                // The child can exit between try_wait and kill. Always wait
                // even if kill reports that race; cleanup must still reap it.
                let _ = self.child.kill();
                reject(self.child.wait())?;
            }
            self.stopped = true;
        }
        Ok(())
    }
    pub fn is_running(&mut self) -> Result<bool> {
        Ok(!self.stopped && reject(self.child.try_wait())?.is_none())
    }
}
impl Drop for ManagementRelayOwner {
    fn drop(&mut self) {
        let _ = self.stop_and_wait();
    }
}

fn management_readiness_pipe() -> Result<(File, File)> {
    let mut pair = [-1; 2];
    if unsafe { libc::pipe2(pair.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(StartupRejected);
    }
    // SAFETY: pipe2 returned two new, distinct owned descriptors.
    Ok(unsafe { (File::from_raw_fd(pair[0]), File::from_raw_fd(pair[1])) })
}

fn wait_management_readiness(reader: &File, timeout: std::time::Duration) -> Result<()> {
    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .ok_or(StartupRejected)?;
    let mut bytes = [0u8; 2];
    let mut used = 0;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(StartupRejected);
        }
        let mut pfd = libc::pollfd {
            fd: reader.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        let milliseconds = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let polled = unsafe { libc::poll(&mut pfd, 1, milliseconds) };
        if polled < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if polled <= 0 || pfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(StartupRejected);
        }
        let n = unsafe {
            libc::read(
                reader.as_raw_fd(),
                bytes[used..].as_mut_ptr().cast(),
                bytes.len() - used,
            )
        };
        if n < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(StartupRejected);
        }
        if n == 0 {
            return if used == 1 && bytes[0] == b'R' {
                Ok(())
            } else {
                Err(StartupRejected)
            };
        }
        used += n as usize;
        if used == bytes.len() {
            return Err(StartupRejected);
        }
    }
}

fn finish_management_startup(
    mut owner: ManagementRelayOwner,
    reader: File,
    timeout: std::time::Duration,
) -> Result<ManagementRelayOwner> {
    // Every failure drops the owning child handle, which kills and reaps it.
    // EOF is required after exactly one marker byte; no writer remains retained
    // in the parent and an incomplete/malformed acknowledgement cannot pass.
    wait_management_readiness(&reader, timeout)?;
    if !owner.is_running()? {
        return Err(StartupRejected);
    }
    Ok(owner)
}

pub fn launch_management_relay(
    embedded: &EmbeddedRole,
    private_key: &[u8],
) -> Result<ManagementRelayOwner> {
    use std::os::unix::process::CommandExt;
    let c = embedded
        .config
        .management_relay
        .as_ref()
        .ok_or(StartupRejected)?;
    if private_key.is_empty() || private_key.len() > 16 << 10 {
        return Err(StartupRejected);
    }
    let cfg = embedded.read_leaf(&c.configuration_path, 16 << 10)?;
    reject(c.check_config_bytes(&cfg))?;
    let ca = sealed_public_file(&embedded.read_leaf(&c.client_ca_path, 64 << 10)?, 64 << 10)?;
    let cert = sealed_public_file(
        &embedded.read_leaf(&c.server_certificate_path, 64 << 10)?,
        64 << 10,
    )?;
    let key = sealed_public_file(private_key, 16 << 10)?;
    let (executable, bytes) = fixed_file(&c.executable_path, 256 << 20)?;
    let leaf = embedded
        .core
        .leaves
        .iter()
        .find(|l| l.path == c.executable_path)
        .ok_or(StartupRejected)?;
    if hash(&bytes) != leaf.sha384
        || bytes.len() as u64 != leaf.size_bytes
        || reject(executable.metadata())?.mode() & 0o005 != 0o005
    {
        return Err(StartupRejected);
    }
    fn reserve(file: &File) -> Result<File> {
        let n = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 128) };
        if n < 0 {
            return Err(StartupRejected);
        }
        Ok(unsafe { File::from_raw_fd(n) })
    }
    let inputs = [reserve(&ca)?, reserve(&cert)?, reserve(&key)?];
    let (ready_reader, ready_source) = management_readiness_pipe()?;
    let ready_writer = reserve(&ready_source)?;
    drop(ready_source);
    let executable = reserve(&executable)?;
    let raw = inputs.each_ref().map(AsRawFd::as_raw_fd);
    let ready_fd = ready_writer.as_raw_fd();
    let executable_fd = executable.as_raw_fd();
    if raw.iter().any(|fd| *fd > 4095) || ready_fd > 4095 {
        return Err(StartupRejected);
    }
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0
        || action.sa_sigaction == libc::SIG_IGN
        || action.sa_flags & libc::SA_NOCLDWAIT != 0
    {
        return Err(StartupRejected);
    }
    let parent = unsafe { libc::getpid() };
    let uid = c.uid;
    let gid = c.gid;
    let mut command = std::process::Command::new(format!("/proc/self/fd/{executable_fd}"));
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env(
            "ONB17_MANAGEMENT_TLS_FDS",
            format!("{}:{}:{}", raw[0], raw[1], raw[2]),
        )
        .env("ONB17_MANAGEMENT_READY_FD", ready_fd.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    unsafe {
        command.pre_exec(move || {
            let fail = || std::io::Error::last_os_error();
            if libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(fail());
            }
            for fd in raw.into_iter().chain([ready_fd]) {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(fail());
                }
            }
            // Lock root/setuid capability semantics, clear the entire bounding set,
            // then drop all identities before installing PDEATHSIG (setuid clears it).
            if libc::prctl(libc::PR_SET_SECUREBITS, 1 | 2 | 8 | 32, 0, 0, 0) != 0 {
                return Err(fail());
            }
            for cap in 0..64 {
                if libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 {
                    if *libc::__errno_location() == libc::EINVAL {
                        break;
                    }
                    return Err(fail());
                }
            }
            if libc::setgroups(1, &gid) != 0
                || libc::setresgid(gid, gid, gid) != 0
                || libc::setresuid(uid, uid, uid) != 0
                || libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_CLEAR_ALL,
                    0,
                    0,
                    0,
                ) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                || libc::getppid() != parent
            {
                return Err(fail());
            }
            Ok(())
        });
    }
    let child = reject(command.spawn())?;
    // Drop the parent's only writer alias before waiting, so child close/exit
    // gives EOF. No inherited channel or TLS credential is used as readiness.
    drop(ready_writer);
    let owner = ManagementRelayOwner {
        child,
        stopped: false,
        _launch_thread: std::marker::PhantomData,
    };
    finish_management_startup(owner, ready_reader, std::time::Duration::from_secs(10))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationKind {
    Ready,
    Export,
    Unproven,
    Stop,
}
pub struct Publication {
    pub kind: PublicationKind,
    pub length: u64,
    pub sha384: [u8; 48],
}
impl Publication {
    pub fn control(kind: PublicationKind) -> Result<Self> {
        if kind == PublicationKind::Export {
            return Err(StartupRejected);
        }
        Ok(Self {
            kind,
            length: 0,
            sha384: [0; 48],
        })
    }
    pub fn export(bytes: &[u8]) -> Result<(Self, File)> {
        let file = sealed_public_file(bytes, MAX_PUBLIC_EXPORT)?;
        Ok((
            Self {
                kind: PublicationKind::Export,
                length: bytes.len() as u64,
                sha384: raw48(&hash(bytes))?,
            },
            file,
        ))
    }
    pub fn encode(&self) -> Result<[u8; 72]> {
        self.validate()?;
        let mut b = [0; 72];
        b[..8].copy_from_slice(b"ONB17GCP");
        b[8..10].copy_from_slice(&1u16.to_be_bytes());
        b[10] = match self.kind {
            PublicationKind::Ready => 1,
            PublicationKind::Export => 2,
            PublicationKind::Unproven => 3,
            PublicationKind::Stop => 4,
        };
        b[16..24].copy_from_slice(&self.length.to_be_bytes());
        b[24..].copy_from_slice(&self.sha384);
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != 72 || &b[..8] != b"ONB17GCP" || b[8..10] != [0, 1] || b[11..16] != [0; 5] {
            return Err(StartupRejected);
        }
        let kind = match b[10] {
            1 => PublicationKind::Ready,
            2 => PublicationKind::Export,
            3 => PublicationKind::Unproven,
            4 => PublicationKind::Stop,
            _ => return Err(StartupRejected),
        };
        let p = Self {
            kind,
            length: u64::from_be_bytes(b[16..24].try_into().map_err(|_| StartupRejected)?),
            sha384: b[24..].try_into().map_err(|_| StartupRejected)?,
        };
        p.validate()?;
        Ok(p)
    }
    fn validate(&self) -> Result<()> {
        if self.kind == PublicationKind::Export {
            if self.length == 0 || self.length > MAX_PUBLIC_EXPORT as u64 || self.sha384 == [0; 48]
            {
                return Err(StartupRejected);
            }
        } else if self.length != 0 || self.sha384 != [0; 48] {
            return Err(StartupRejected);
        }
        Ok(())
    }
    pub fn read_export(&self, file: &File) -> Result<Vec<u8>> {
        self.validate()?;
        if self.kind != PublicationKind::Export {
            return Err(StartupRejected);
        }
        let bytes = read_sealed_public(file, MAX_PUBLIC_EXPORT)?;
        if bytes.len() as u64 != self.length || raw48(&hash(&bytes))? != self.sha384 {
            return Err(StartupRejected);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Separate owned test process: no software authority or production startup
    // path uses these actions. Blocking is ended by the tested owner kill/join.
    #[test]
    fn readiness_process_fixture() {
        let Ok(action) = std::env::var("ONB17_TEST_READY_ACTION") else {
            return;
        };
        let fd: i32 = std::env::var("ONB17_TEST_READY_FD")
            .unwrap()
            .parse()
            .unwrap();
        let bytes: &[u8] = match action.as_str() {
            "ready" | "marker-without-eof" => b"R",
            "wrong" => b"X",
            "extra" => b"RR",
            "eof" | "silent" | "exit-before-ready" => b"",
            _ => panic!("unknown readiness fixture action"),
        };
        if !bytes.is_empty() {
            assert_eq!(
                unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) },
                bytes.len() as isize
            );
        }
        if !matches!(action.as_str(), "silent" | "marker-without-eof") {
            assert_eq!(unsafe { libc::close(fd) }, 0);
        }
        if action == "exit-before-ready" {
            std::process::exit(0);
        }
        loop {
            unsafe { libc::pause() };
        }
    }

    fn readiness_child(action: &str) -> (ManagementRelayOwner, File, libc::pid_t) {
        use std::os::unix::process::CommandExt;
        let (reader, writer) = management_readiness_pipe().unwrap();
        let fd = writer.as_raw_fd();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "gcp_startup::tests::readiness_process_fixture"])
            .env("ONB17_TEST_READY_ACTION", action)
            .env("ONB17_TEST_READY_FD", fd.to_string())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        let pid = child.id() as libc::pid_t;
        drop(writer);
        (
            ManagementRelayOwner {
                child,
                stopped: false,
                _launch_thread: std::marker::PhantomData,
            },
            reader,
            pid,
        )
    }

    fn assert_reaped(pid: libc::pid_t) {
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn management_readiness_retains_owner_only_after_exact_marker_and_eof() {
        let (owner, reader, pid) = readiness_child("ready");
        let mut owner =
            finish_management_startup(owner, reader, std::time::Duration::from_secs(5)).unwrap();
        assert!(owner.is_running().unwrap());
        owner.stop_and_wait().unwrap();
        assert!(!owner.is_running().unwrap());
        assert_reaped(pid);
    }

    #[test]
    fn management_readiness_failures_kill_and_join_the_child() {
        for action in [
            "wrong",
            "extra",
            "eof",
            "silent",
            "marker-without-eof",
            "exit-before-ready",
        ] {
            let (owner, reader, pid) = readiness_child(action);
            let deadline = if matches!(action, "silent" | "marker-without-eof") {
                std::time::Duration::from_millis(20)
            } else {
                std::time::Duration::from_secs(5)
            };
            assert!(finish_management_startup(owner, reader, deadline).is_err());
            assert_reaped(pid);
        }
    }

    #[test]
    fn export_uses_readonly_noexec_sealed_inode_and_exact_digest() {
        let (p, file) = Publication::export(b"public-only-execution-evidence").unwrap();
        assert_eq!(
            Publication::decode(&p.encode().unwrap())
                .unwrap()
                .read_export(&file)
                .unwrap(),
            b"public-only-execution-evidence"
        );
        let wrong = sealed_public_file(b"foreign-public-evidence", MAX_PUBLIC_EXPORT).unwrap();
        assert!(p.read_export(&wrong).is_err());
        assert!(sealed_public_file(&[], 16).is_err());
        assert!(sealed_public_file(&[0; 17], 16).is_err());
        let unsealed = File::open("/proc/self/exe").unwrap();
        assert!(read_sealed_public(&unsealed, 256 << 20).is_err());
    }
    #[test]
    fn publication_control_domain_reserved_bits_and_descriptor_bounds_are_closed() {
        for kind in [
            PublicationKind::Ready,
            PublicationKind::Unproven,
            PublicationKind::Stop,
        ] {
            let p = Publication::control(kind).unwrap();
            assert_eq!(
                Publication::decode(&p.encode().unwrap()).unwrap().kind,
                kind
            );
        }
        let frame = Publication::control(PublicationKind::Ready)
            .unwrap()
            .encode()
            .unwrap();
        for i in [0, 8, 10, 11, 16, 24] {
            let mut b = frame;
            b[i] ^= 0xff;
            assert!(Publication::decode(&b).is_err());
        }
        assert!(Publication::decode(&frame[..71]).is_err());
        assert!(Publication::control(PublicationKind::Export).is_err());
        assert!(Publication {
            kind: PublicationKind::Export,
            length: (MAX_PUBLIC_EXPORT + 1) as u64,
            sha384: [1; 48]
        }
        .encode()
        .is_err());
    }
    #[test]
    fn ordinary_host_root_cannot_supply_a_trusted_role_view() {
        assert!(load_embedded(Role::Kata).is_err());
        assert!(load_embedded(Role::Preparation).is_err());
    }
}
