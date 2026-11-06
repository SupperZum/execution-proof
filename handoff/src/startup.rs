//! Trusted role startup over an inherited private socketpair.
//!
//! Executable bytes are copied into sealed executable inodes before launch.
//! The inherited bootstrap is compared with independently provisioned role
//! expectations; environment variables, RPC fields and the bootstrap itself
//! cannot select those expectations. This proves local launcher/FD custody,
//! not measured boot, guest-root isolation or external attestation.

use crate::fd_transport::{
    FdExpectation, PrivateFdChannel, ReceivedPacket, SendOutcome, TransportError,
};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use std::{
    ffi::OsString,
    fmt,
    fs::File,
    io,
    marker::PhantomData,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileExt, MetadataExt},
            process::CommandExt,
        },
    },
    process::{Child, Command, ExitStatus, Stdio},
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const INHERITED_FDS_ENV: &str = "ONB17_STARTUP_FDS";
const MIN_INHERITED_FD: i32 = 128;
const WIRE_BYTES: usize = 192;
const CONTENT_SEALS: i32 = libc::F_SEAL_WRITE
    | libc::F_SEAL_GROW
    | libc::F_SEAL_SHRINK
    | libc::F_SEAL_SEAL
    | libc::F_SEAL_EXEC;
static INHERITED_TAKEN: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Preparation,
    Kata,
}
impl Role {
    fn wire(self) -> u8 {
        match self {
            Self::Preparation => 1,
            Self::Kata => 2,
        }
    }
    fn peer(self) -> Self {
        match self {
            Self::Preparation => Self::Kata,
            Self::Kata => Self::Preparation,
        }
    }
}

/// Trusted role configuration, supplied independently of inherited/wire data.
pub struct ExpectedStartup {
    pub role: Role,
    pub boot_config_sha384: [u8; 48],
    pub own_executable_sha384: [u8; 48],
    pub peer_executable_sha384: [u8; 48],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupError {
    InvalidLimit,
    InvalidExecutable,
    ArtifactMismatch,
    InvalidArguments,
    MissingInherited,
    AlreadyTaken,
    InvalidSocket,
    InvalidBootstrap,
    BindingMismatch,
    PeerMismatch,
    EntropyUnavailable,
    Deadline,
    ChildFailure,
    SignalPolicy,
    Kernel(i32),
    Transport(TransportError),
}
impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "trusted startup rejected: {self:?}")
    }
}
impl std::error::Error for StartupError {}

/// An immutable snapshot of a trusted, hash-pinned native role executable.
/// Runtime loader/shared-library trust remains part of the guest artifact.
pub struct PinnedRoleExecutable {
    file: File,
    sha384: [u8; 48],
}
impl PinnedRoleExecutable {
    pub fn new(
        source: File,
        expected_sha384: [u8; 48],
        max_bytes: u64,
    ) -> Result<Self, StartupError> {
        if max_bytes == 0 || max_bytes > isize::MAX as u64 {
            return Err(StartupError::InvalidLimit);
        }
        let metadata = source.metadata().map_err(io_error)?;
        if !metadata.is_file() || metadata.len() < 4 || metadata.len() > max_bytes {
            return Err(StartupError::InvalidExecutable);
        }
        let mut magic = [0; 4];
        source.read_exact_at(&mut magic, 0).map_err(io_error)?;
        if magic != *b"\x7fELF" {
            return Err(StartupError::InvalidExecutable);
        }
        let writer = memfd(true)?;
        let mut hash = digest::Context::new(&digest::SHA384);
        let mut buffer = [0u8; 8192];
        let mut offset = 0;
        while offset < metadata.len() {
            let count = (metadata.len() - offset).min(buffer.len() as u64) as usize;
            source
                .read_exact_at(&mut buffer[..count], offset)
                .map_err(io_error)?;
            writer
                .write_all_at(&buffer[..count], offset)
                .map_err(io_error)?;
            hash.update(&buffer[..count]);
            offset += count as u64;
        }
        let sha384: [u8; 48] = hash
            .finish()
            .as_ref()
            .try_into()
            .map_err(|_| StartupError::ArtifactMismatch)?;
        if sha384 != expected_sha384 {
            return Err(StartupError::ArtifactMismatch);
        }
        seal(&writer, 0o500)?;
        let file = readonly_alias(&writer)?;
        // The source may have changed while copying. Check the actual sealed
        // executable snapshot, not only the earlier source header sample.
        file.read_exact_at(&mut magic, 0).map_err(io_error)?;
        if magic != *b"\x7fELF" {
            return Err(StartupError::InvalidExecutable);
        }
        Ok(Self { file, sha384 })
    }
    pub fn sha384(&self) -> &[u8; 48] {
        &self.sha384
    }
}

pub struct RoleCommand {
    executable: PinnedRoleExecutable,
    arguments: Vec<OsString>,
}
impl RoleCommand {
    pub fn new(
        executable: PinnedRoleExecutable,
        arguments: Vec<OsString>,
    ) -> Result<Self, StartupError> {
        let bytes = arguments
            .iter()
            .try_fold(0usize, |total, arg| total.checked_add(arg.as_bytes().len()));
        if arguments.len() > 64
            || bytes.is_none_or(|n| n > 16384)
            || arguments.iter().any(|arg| arg.as_bytes().contains(&0))
        {
            return Err(StartupError::InvalidArguments);
        }
        Ok(Self {
            executable,
            arguments,
        })
    }
}

struct Bootstrap {
    role: Role,
    nonce: [u8; 32],
    boot: [u8; 48],
    preparation: [u8; 48],
    kata: [u8; 48],
}
impl Bootstrap {
    fn encode(&self, purpose: u8) -> [u8; WIRE_BYTES] {
        let mut wire = [0; WIRE_BYTES];
        wire[..8].copy_from_slice(b"ONB17STP");
        wire[8..10].copy_from_slice(&1u16.to_be_bytes());
        wire[10] = self.role.wire();
        wire[11] = purpose;
        wire[16..48].copy_from_slice(&self.nonce);
        wire[48..96].copy_from_slice(&self.boot);
        wire[96..144].copy_from_slice(&self.preparation);
        wire[144..192].copy_from_slice(&self.kata);
        wire
    }
    fn decode(wire: &[u8]) -> Result<Self, StartupError> {
        if wire.len() != WIRE_BYTES
            || &wire[..8] != b"ONB17STP"
            || wire[8..10] != 1u16.to_be_bytes()
            || wire[11] != 1
            || wire[12..16] != [0; 4]
        {
            return Err(StartupError::InvalidBootstrap);
        }
        let role = match wire[10] {
            1 => Role::Preparation,
            2 => Role::Kata,
            _ => return Err(StartupError::InvalidBootstrap),
        };
        let nonce = wire[16..48]
            .try_into()
            .map_err(|_| StartupError::InvalidBootstrap)?;
        if nonce == [0; 32] {
            return Err(StartupError::InvalidBootstrap);
        }
        Ok(Self {
            role,
            nonce,
            boot: wire[48..96]
                .try_into()
                .map_err(|_| StartupError::InvalidBootstrap)?,
            preparation: wire[96..144]
                .try_into()
                .map_err(|_| StartupError::InvalidBootstrap)?,
            kata: wire[144..192]
                .try_into()
                .map_err(|_| StartupError::InvalidBootstrap)?,
        })
    }
    fn own(&self) -> &[u8; 48] {
        match self.role {
            Role::Preparation => &self.preparation,
            Role::Kata => &self.kata,
        }
    }
    fn peer(&self) -> &[u8; 48] {
        match self.role {
            Role::Preparation => &self.kata,
            Role::Kata => &self.preparation,
        }
    }
    fn commitment(&self) -> [u8; 48] {
        let wire = self.encode(0);
        let mut hash = digest::Context::new(&digest::SHA384);
        hash.update(b"onb17/trusted-role-startup/v1\0");
        hash.update(&wire[16..]);
        hash.finish()
            .as_ref()
            .try_into()
            .expect("SHA384 is 48 bytes")
    }
}

/// A non-Clone endpoint whose bootstrap and peer role were checked before use.
/// This marker depends on trusted launcher/expected-configuration provenance.
pub struct StartupBoundChannel {
    channel: PrivateFdChannel,
    bootstrap: Bootstrap,
}

/// A packet actually received by a startup-bound endpoint. The fields and
/// constructor are private; reading or extracting bytes cannot recreate this
/// source witness from host/RPC data.
/// ```compile_fail
/// use execution_proof_handoff::startup::{Role, StartupBoundPacket};
/// let packet = StartupBoundPacket {
///     startup_binding: [0; 48], recipient_role: Role::Kata,
///     payload: Vec::new(), descriptor: None,
/// };
/// ```
pub struct StartupBoundPacket {
    startup_binding: [u8; 48],
    recipient_role: Role,
    payload: Vec<u8>,
    descriptor: Option<OwnedFd>,
}
impl StartupBoundPacket {
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    pub fn startup_binding_sha384(&self) -> &[u8; 48] {
        &self.startup_binding
    }
    pub fn recipient_role(&self) -> Role {
        self.recipient_role
    }
    pub fn into_parts(self) -> (Vec<u8>, Option<OwnedFd>) {
        (self.payload, self.descriptor)
    }
}
impl StartupBoundChannel {
    /// Take the launcher-owned inherited descriptors, exactly once.
    /// The bounded environment hint supplies only descriptor locations, never
    /// role identity, configuration or executable expectations.
    ///
    /// # Safety
    /// The trusted role entrypoint must own the two descriptors named by the
    /// launcher hint without any Rust owners or aliases, and call this before
    /// other code can close/reassign them. The hint is untrusted metadata.
    /// Expected configuration must not be derived from RPC, environment or the
    /// inherited ticket. The launcher/reaper must retain its trusted lifecycle.
    pub unsafe fn accept_inherited(
        expected: ExpectedStartup,
        timeout: Duration,
    ) -> Result<Self, StartupError> {
        if INHERITED_TAKEN.swap(true, Ordering::AcqRel) {
            return Err(StartupError::AlreadyTaken);
        }
        let hint = std::env::var_os(INHERITED_FDS_ENV).ok_or(StartupError::MissingInherited)?;
        let (channel_raw, ticket_raw) = inherited_locations(hint.as_bytes())?;
        let endpoint = take_inherited(channel_raw)?;
        let ticket = take_inherited(ticket_raw)?;
        Self::accept_descriptors(endpoint, ticket, expected, timeout)
    }
    fn accept_descriptors(
        endpoint: OwnedFd,
        ticket: OwnedFd,
        expected: ExpectedStartup,
        timeout: Duration,
    ) -> Result<Self, StartupError> {
        let deadline = deadline(timeout)?;
        validate_socket(&endpoint)?;
        let bootstrap = read_bootstrap(ticket)?;
        if bootstrap.role != expected.role
            || bootstrap.boot != expected.boot_config_sha384
            || bootstrap.own() != &expected.own_executable_sha384
            || bootstrap.peer() != &expected.peer_executable_sha384
        {
            return Err(StartupError::BindingMismatch);
        }
        let mut channel = PrivateFdChannel::from_startup_fd(endpoint);
        let hello = bootstrap.encode(2);
        loop {
            check_deadline(deadline)?;
            match channel
                .try_send(&hello, None)
                .map_err(StartupError::Transport)?
            {
                SendOutcome::Sent => break,
                SendOutcome::WouldBlock => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        let peer = Bootstrap {
            role: bootstrap.role.peer(),
            nonce: bootstrap.nonce,
            boot: bootstrap.boot,
            preparation: bootstrap.preparation,
            kata: bootstrap.kata,
        };
        loop {
            check_deadline(deadline)?;
            if let Some(packet) = channel
                .try_receive(FdExpectation::None)
                .map_err(StartupError::Transport)?
            {
                let (wire, no_fd) = packet.into_parts();
                drop(no_fd);
                if wire != peer.encode(2) {
                    return Err(StartupError::PeerMismatch);
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(Self { channel, bootstrap })
    }
    pub fn role(&self) -> Role {
        self.bootstrap.role
    }
    pub fn boot_config_sha384(&self) -> &[u8; 48] {
        &self.bootstrap.boot
    }
    pub fn channel_nonce(&self) -> &[u8; 32] {
        &self.bootstrap.nonce
    }
    pub fn own_executable_sha384(&self) -> &[u8; 48] {
        self.bootstrap.own()
    }
    pub fn peer_executable_sha384(&self) -> &[u8; 48] {
        self.bootstrap.peer()
    }
    pub fn binding_commitment(&self) -> [u8; 48] {
        self.bootstrap.commitment()
    }
    pub fn try_send(
        &mut self,
        payload: &[u8],
        descriptor: Option<std::os::fd::BorrowedFd<'_>>,
    ) -> Result<SendOutcome, TransportError> {
        self.channel.try_send(payload, descriptor)
    }
    pub fn try_receive(
        &mut self,
        expectation: FdExpectation,
    ) -> Result<Option<ReceivedPacket>, TransportError> {
        self.channel.try_receive(expectation)
    }
    pub fn try_receive_bound(
        &mut self,
        expectation: FdExpectation,
    ) -> Result<Option<StartupBoundPacket>, TransportError> {
        self.channel.try_receive(expectation).map(|packet| {
            packet.map(|packet| {
                let (payload, descriptor) = packet.into_parts();
                StartupBoundPacket {
                    startup_binding: self.binding_commitment(),
                    recipient_role: self.role(),
                    payload,
                    descriptor,
                }
            })
        })
    }
}

/// Launch both pinned roles. No shell, ambient environment or pathname service
/// listener is used; only stdio plus two reserved owned FDs survive each exec.
/// Descriptor location hints do not select trusted role expectations. The caller must
/// keep SIGCHLD at its default non-autoreaping policy while this owner exists.
pub fn launch_roles(
    preparation: RoleCommand,
    kata: RoleCommand,
    boot_config_sha384: [u8; 48],
) -> Result<LaunchedRoles, StartupError> {
    require_signal_policy()?;
    let (preparation_endpoint, kata_endpoint) =
        PrivateFdChannel::pair().map_err(StartupError::Transport)?;
    let mut nonce = [0; 32];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| StartupError::EntropyUnavailable)?;
    if nonce == [0; 32] {
        return Err(StartupError::EntropyUnavailable);
    }
    let bootstrap = Bootstrap {
        role: Role::Preparation,
        nonce,
        boot: boot_config_sha384,
        preparation: preparation.executable.sha384,
        kata: kata.executable.sha384,
    };
    let preparation_ticket = make_ticket(&bootstrap)?;
    let kata_ticket = make_ticket(&Bootstrap {
        role: Role::Kata,
        ..bootstrap
    })?;
    let first = spawn_role(preparation, preparation_endpoint, preparation_ticket)?;
    let mut children = LaunchedRoles {
        preparation: ChildSlot {
            child: first,
            status: None,
        },
        kata: None,
        _launch_thread: PhantomData,
    };
    children.kata = Some(ChildSlot {
        child: spawn_role(kata, kata_endpoint, kata_ticket)?,
        status: None,
    });
    Ok(children)
}

/// Host the preparation role in this trusted launcher process and exec only
/// the pinned Kata role. The actual current executable must match the supplied
/// independent preparation artifact pin; no producer state is serialized.
///
/// This is local trusted-process identity, not attestation or runtime memory
/// integrity. Procfs, the process image and role configuration must be trusted.
pub fn launch_kata_role(
    kata: RoleCommand,
    expected_preparation_sha384: [u8; 48],
    max_self_bytes: usize,
    boot_config_sha384: [u8; 48],
    timeout: Duration,
) -> Result<(StartupBoundChannel, LaunchedRole), StartupError> {
    let startup_deadline = deadline(timeout)?;
    require_signal_policy()?;
    let preparation = PinnedRoleExecutable::new(
        File::open("/proc/self/exe").map_err(io_error)?,
        expected_preparation_sha384,
        max_self_bytes as u64,
    )?;
    check_deadline(startup_deadline)?;
    let (preparation_endpoint, kata_endpoint) =
        PrivateFdChannel::pair().map_err(StartupError::Transport)?;
    let mut nonce = [0; 32];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| StartupError::EntropyUnavailable)?;
    if nonce == [0; 32] {
        return Err(StartupError::EntropyUnavailable);
    }
    let preparation_bootstrap = Bootstrap {
        role: Role::Preparation,
        nonce,
        boot: boot_config_sha384,
        preparation: preparation.sha384,
        kata: kata.executable.sha384,
    };
    let kata_bootstrap = Bootstrap {
        role: Role::Kata,
        ..preparation_bootstrap
    };
    let preparation_ticket = make_ticket(&preparation_bootstrap)?;
    let kata_ticket = make_ticket(&kata_bootstrap)?;
    let child = spawn_role(kata, kata_endpoint, kata_ticket)?;
    let owner = LaunchedRole {
        child: ChildSlot {
            child,
            status: None,
        },
        _launch_thread: PhantomData,
    };
    let remaining = startup_deadline
        .checked_duration_since(Instant::now())
        .ok_or(StartupError::Deadline)?;
    let channel = StartupBoundChannel::accept_descriptors(
        preparation_endpoint
            .into_startup_fd()
            .map_err(StartupError::Transport)?,
        preparation_ticket.into(),
        ExpectedStartup {
            role: Role::Preparation,
            boot_config_sha384,
            own_executable_sha384: expected_preparation_sha384,
            peer_executable_sha384: kata_bootstrap.kata,
        },
        remaining,
    )?;
    Ok((channel, owner))
}

struct ChildSlot {
    child: Child,
    status: Option<ExitStatus>,
}

/// One Kata child owned by its persistent preparation/launcher thread.
/// ```compile_fail
/// use execution_proof_handoff::startup::LaunchedRole;
/// fn move_owner(role: LaunchedRole) { std::thread::spawn(move || drop(role)); }
/// ```
pub struct LaunchedRole {
    child: ChildSlot,
    _launch_thread: PhantomData<Rc<()>>,
}
impl LaunchedRole {
    pub fn wait(&mut self, timeout: Duration) -> Result<(), StartupError> {
        let deadline = deadline(timeout)?;
        loop {
            if self.child.reap()? {
                return if self.child.status.is_some_and(|status| status.success()) {
                    Ok(())
                } else {
                    Err(StartupError::ChildFailure)
                };
            }
            check_deadline(deadline)?;
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    pub fn terminate_and_wait(&mut self) {
        self.child.stop();
    }
}
impl Drop for LaunchedRole {
    fn drop(&mut self) {
        self.terminate_and_wait();
    }
}
impl ChildSlot {
    fn reap(&mut self) -> Result<bool, StartupError> {
        if self.status.is_none() {
            self.status = self.child.try_wait().map_err(io_error)?;
        }
        Ok(self.status.is_some())
    }
    fn stop(&mut self) {
        if self.status.is_none() {
            let _ = self.child.kill();
            self.status = self.child.wait().ok();
        }
    }
}
/// The owner stays on the launching thread: Linux PDEATHSIG tracks that thread,
/// not just its process. Moving this owner to another thread is rejected.
/// ```compile_fail
/// use execution_proof_handoff::startup::LaunchedRoles;
/// fn move_owner(roles: LaunchedRoles) {
///     std::thread::spawn(move || drop(roles));
/// }
/// ```
pub struct LaunchedRoles {
    preparation: ChildSlot,
    kata: Option<ChildSlot>,
    _launch_thread: PhantomData<Rc<()>>,
}
impl LaunchedRoles {
    /// Poll normal exits until the deadline, retaining ownership on timeout.
    /// Drop kills/reaps owned children; it cannot preempt a stuck kernel wait.
    pub fn wait(&mut self, timeout: Duration) -> Result<(), StartupError> {
        let deadline = deadline(timeout)?;
        loop {
            let first = self.preparation.reap()?;
            let second = self
                .kata
                .as_mut()
                .ok_or(StartupError::ChildFailure)?
                .reap()?;
            if first && second {
                return if self.preparation.status.is_some_and(|s| s.success())
                    && self
                        .kata
                        .as_ref()
                        .and_then(|s| s.status)
                        .is_some_and(|s| s.success())
                {
                    Ok(())
                } else {
                    Err(StartupError::ChildFailure)
                };
            }
            check_deadline(deadline)?;
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    pub fn terminate_and_wait(&mut self) {
        self.preparation.stop();
        if let Some(kata) = &mut self.kata {
            kata.stop();
        }
    }
}
impl Drop for LaunchedRoles {
    fn drop(&mut self) {
        self.terminate_and_wait();
    }
}

fn spawn_role(
    role: RoleCommand,
    endpoint: PrivateFdChannel,
    ticket: File,
) -> Result<Child, StartupError> {
    let endpoint = endpoint
        .into_startup_fd()
        .map_err(StartupError::Transport)?;
    // Reserve every handoff location in the parent before Command creates its
    // internal exec-error socketpair. Keeping these aliases owned through spawn
    // prevents concurrent low-FD closes from letting that socketpair reuse a
    // handoff target. The child never remaps or overwrites any descriptor.
    let channel_alias = reserve_inherited(&endpoint)?;
    let ticket_alias = reserve_inherited(&ticket)?;
    let executable_alias = reserve_inherited(&role.executable.file)?;
    let channel_raw = channel_alias.as_raw_fd();
    let ticket_raw = ticket_alias.as_raw_fd();
    let executable_raw = executable_alias.as_raw_fd();
    // SAFETY: getpid takes no pointers and returns this launcher's process ID.
    let expected_parent = unsafe { libc::getpid() };
    let mut command = Command::new(format!("/proc/self/fd/{executable_raw}"));
    command
        .args(&role.arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .env(INHERITED_FDS_ENV, format!("{channel_raw}:{ticket_raw}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: only fixed Linux syscalls and scalar errno creation occur after
    // fork. All descriptor allocation happened in the parent. CLOEXEC rather
    // than early closure preserves Command's separate exec-error socketpair;
    // no dup operation can overwrite either of its descriptors.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            // If the launcher died before PR_SET_PDEATHSIG was installed, the
            // kernel has already reparented us. Never exec an orphan role.
            if libc::getppid() != expected_parent {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            if libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            for raw in [channel_raw, ticket_raw] {
                if libc::fcntl(raw, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let child = command.spawn().map_err(io_error)?;
    drop((
        channel_alias,
        ticket_alias,
        executable_alias,
        endpoint,
        ticket,
        role,
    ));
    Ok(child)
}

fn reserve_inherited(fd: &impl AsRawFd) -> Result<OwnedFd, StartupError> {
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, MIN_INHERITED_FD) };
    if raw < 0 {
        return Err(last_error());
    }
    // SAFETY: successful F_DUPFD_CLOEXEC creates a new exclusively owned alias.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}
fn inherited_locations(hint: &[u8]) -> Result<(i32, i32), StartupError> {
    if hint.len() > 21 {
        return Err(StartupError::MissingInherited);
    }
    let mut parts = hint.split(|byte| *byte == b':');
    let parse = |part: Option<&[u8]>| {
        let part = part.ok_or(StartupError::MissingInherited)?;
        if part.is_empty() || part[0] == b'0' || !part.iter().all(u8::is_ascii_digit) {
            return Err(StartupError::MissingInherited);
        }
        let value = part.iter().try_fold(0i32, |value, digit| {
            value.checked_mul(10)?.checked_add(i32::from(digit - b'0'))
        });
        value
            .filter(|value| *value >= MIN_INHERITED_FD)
            .ok_or(StartupError::MissingInherited)
    };
    let channel = parse(parts.next())?;
    let ticket = parse(parts.next())?;
    if parts.next().is_some() || channel == ticket {
        return Err(StartupError::MissingInherited);
    }
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(last_error());
    }
    if channel as libc::rlim_t >= limit.rlim_cur || ticket as libc::rlim_t >= limit.rlim_cur {
        return Err(StartupError::MissingInherited);
    }
    Ok((channel, ticket))
}
fn take_inherited(raw: i32) -> Result<OwnedFd, StartupError> {
    if unsafe { libc::fcntl(raw, libc::F_GETFD) } < 0 {
        return Err(StartupError::MissingInherited);
    }
    // SAFETY: accept_inherited's caller guarantees exclusive ownership of the
    // hinted descriptor. Validation above rejects absent descriptors.
    let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
    if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(last_error());
    }
    Ok(descriptor)
}
fn validate_socket(fd: &OwnedFd) -> Result<(), StartupError> {
    for (option, expected) in [
        (libc::SO_TYPE, libc::SOCK_SEQPACKET),
        (libc::SO_DOMAIN, libc::AF_UNIX),
        (libc::SO_ACCEPTCONN, 0),
    ] {
        let mut value = 0;
        let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&mut value as *mut i32).cast(),
                &mut size,
            )
        } != 0
        {
            return Err(last_error());
        }
        if size as usize != std::mem::size_of_val(&value) || value != expected {
            return Err(StartupError::InvalidSocket);
        }
    }
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    let descriptor_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 || descriptor_flags < 0 {
        return Err(last_error());
    }
    if flags & libc::O_NONBLOCK == 0 || descriptor_flags & libc::FD_CLOEXEC == 0 {
        return Err(StartupError::InvalidSocket);
    }
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&address) as libc::socklen_t;
    if unsafe {
        libc::getpeername(
            fd.as_raw_fd(),
            (&mut address as *mut libc::sockaddr_un).cast(),
            &mut size,
        )
    } != 0
        || address.sun_family as i32 != libc::AF_UNIX
    {
        return Err(StartupError::InvalidSocket);
    }
    Ok(())
}
fn make_ticket(bootstrap: &Bootstrap) -> Result<File, StartupError> {
    let file = memfd(false)?;
    file.write_all_at(&bootstrap.encode(1), 0)
        .map_err(io_error)?;
    seal(&file, 0o600)?;
    readonly_alias(&file)
}
fn read_bootstrap(ticket: OwnedFd) -> Result<Bootstrap, StartupError> {
    let file = File::from(ticket);
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    let metadata = file.metadata().map_err(io_error)?;
    if seals < 0
        || seals & CONTENT_SEALS != CONTENT_SEALS
        || !metadata.is_file()
        || metadata.len() != WIRE_BYTES as u64
        || metadata.mode() & 0o111 != 0
    {
        return Err(StartupError::InvalidBootstrap);
    }
    let mut wire = [0; WIRE_BYTES];
    file.read_exact_at(&mut wire, 0).map_err(io_error)?;
    Bootstrap::decode(&wire)
}
fn memfd(executable: bool) -> Result<File, StartupError> {
    let flags = libc::MFD_CLOEXEC
        | libc::MFD_ALLOW_SEALING
        | if executable {
            libc::MFD_EXEC
        } else {
            libc::MFD_NOEXEC_SEAL
        };
    let raw = unsafe { libc::memfd_create(c"trusted-role-startup".as_ptr(), flags) };
    if raw < 0 {
        return Err(last_error());
    }
    // SAFETY: successful memfd_create returns one exclusively owned descriptor.
    Ok(unsafe { File::from_raw_fd(raw) })
}
fn seal(file: &File, mode: libc::mode_t) -> Result<(), StartupError> {
    if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, CONTENT_SEALS) } != 0
    {
        return Err(last_error());
    }
    Ok(())
}
fn readonly_alias(file: &File) -> Result<File, StartupError> {
    File::open(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(io_error)
}
fn require_signal_policy() -> Result<(), StartupError> {
    let mut policy: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut policy) } != 0 {
        return Err(last_error());
    }
    if policy.sa_sigaction != libc::SIG_DFL || policy.sa_flags & libc::SA_NOCLDWAIT != 0 {
        return Err(StartupError::SignalPolicy);
    }
    Ok(())
}
fn deadline(timeout: Duration) -> Result<Instant, StartupError> {
    if timeout.is_zero() {
        return Err(StartupError::InvalidLimit);
    }
    Instant::now()
        .checked_add(timeout)
        .ok_or(StartupError::InvalidLimit)
}
fn check_deadline(deadline: Instant) -> Result<(), StartupError> {
    if Instant::now() >= deadline {
        Err(StartupError::Deadline)
    } else {
        Ok(())
    }
}
fn io_error(error: io::Error) -> StartupError {
    StartupError::Kernel(error.raw_os_error().unwrap_or(libc::EIO))
}

fn last_error() -> StartupError {
    StartupError::Kernel(
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO),
    )
}

#[cfg(test)]
#[path = "startup_tests.rs"]
mod tests;
