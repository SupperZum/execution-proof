#!/usr/bin/env python3
"""Fixed direct-SSH serial transport; no gcloud, cloud API, key generation or logs.

Public protocol bytes are data, never hardware/producer verdicts. The caller owns
crypto appraisal, experimental permission and VM cleanup. One gateway per process
owns its SSH group, watchdog and adopted descendants until close.
"""
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
import base64
import ctypes
import hashlib
import json
import math
import os
import re
import select
import signal
import stat
import struct
import subprocess
import threading
import time
import zlib

SSH = Path('/usr/bin/ssh')
RESPONSE = 'qlad.execution-proof.gcp-preparation-publication.v1'
CONTROL = 'qlad.execution-proof.gcp-preparation-control.v1'
MARKER = b'ONB17_PROOF_STARTUP_V1 '
MAX_STARTUP = 1 << 20
MAX_PUBLIC = 17 << 20
PUBLIC_MAGIC = b'ONB2'
MAX_PUBLIC_WIRE = MAX_PUBLIC + (64 << 10)
PUBLIC_BASE_SECONDS = 60
PUBLIC_BYTES_PER_SECOND = 8192
PUBLIC_MAX_SECONDS = 300
MAX_INPUT = 4 << 20
MAX_STDERR = 64 << 10
MAX_TERMINAL = 256
POSTGRANT_STAGES = frozenset(('grant_verify', 'recorder_init', 'https_init', 'begin',
                             'collect', 'capture', 'challenge', 'decision', 'aggregate'))
POSTGRANT_ERROR_CLASSES = frozenset(('rejected', 'transport', 'http_status'))
REPORT_CLEANUP_CLASSES = frozenset((
    'report_cleanup_failed', 'attester_unavailable_report_cleanup_failed',
    'binding_mismatch_report_cleanup_failed', 'invalid_evidence_report_cleanup_failed',
    'too_large_report_cleanup_failed'))
COLLECTION_ERROR_CLASSES = REPORT_CLEANUP_CLASSES | frozenset(('attester_unavailable', 'binding_mismatch', 'invalid_evidence', 'too_large'))
STAGING_CLEANUP_CLASSES = tuple(
    cause + '_cleanup_failed' for cause in (
        'staging_write_failed', 'staging_too_large', 'staging_archive_rejected',
        'staging_type_collision', 'staging_file_operation'))
BUILDER_CLEANUP_CLASSES = tuple(
    cause + suffix for cause in ('builder', 'builder_cancelled', 'builder_operation', 'builder_child_failed')
    for suffix in ('_reap_failed', '_scratch_failed', '_reap_and_scratch_failed'))
READY_ERROR_CLASSES = {
    'admission_input': ('rejected',),
    'credential_request': ('rejected',),
    'credential_http': ('rejected', 'transport', 'http_status'),
    'prepare': ('admission_rejected', 'credential_rejected', 'registry_rejected',
                'preparation_rejected', 'deadline', 'rejected',
                'executable_invalid_limits', 'executable_too_large',
                'executable_missing_node', 'executable_identity_mismatch',
                'executable_workspace_mismatch', 'executable_permission_denied',
                'executable_content_mismatch', 'executable_file_operation',
                'executable_elf_rejected', 'staging_write_failed', 'builder_child_failed',
                *STAGING_CLEANUP_CLASSES, *BUILDER_CLEANUP_CLASSES),
    'custody_progress': ('deadline', 'rejected'),
    'kata_ready': ('rejected',),
    'management_relay': ('rejected',),
}
TERMINAL_STATUS = frozenset(('ROLE_FAILED', 'ROLE_EXITED_ZERO', 'ROLE_TIMEOUT_OR_WAIT_ERROR'))
_WATCHDOG_JOIN_SECONDS = 3
_REAP_SECONDS = 2
_ACTIVE = threading.Lock()
_PENDING_REAP = None
_LIBC = ctypes.CDLL(None, use_errno=True)


class GatewayError(Exception):
    """Only fixed non-secret codes are ever exceptions or summary fields."""
    def __init__(self, code):
        self.code = code
        self.guest_stage = None
        self.error_class = None
        self.guest_terminal_status = None
        super().__init__(code)


def _require(ok, code):
    if not ok:
        raise GatewayError(code)


def _object(pairs):
    value = {}
    for key, item in pairs:
        _require(key not in value, 'duplicate_json_field')
        value[key] = item
    return value


def _constant(_):
    raise GatewayError('nonfinite_json')


def _json(raw):
    try:
        return json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise GatewayError('invalid_json') from None


def _keys(value, expected):
    _require(type(value) is dict and value.keys() == set(expected), 'public_schema')


def _integer(value, low, high):
    _require(type(value) is int and low <= value <= high, 'public_integer')


def _identifier(value, maximum=128):
    _require(type(value) is str and 1 <= len(value) <= maximum and value.isascii()
             and all(32 < ord(c) < 127 for c in value), 'public_identifier')


def _hex(value, size):
    _require(type(value) is str and re.fullmatch('[0-9a-f]{' + str(size * 2) + '}', value), 'public_hex')


def _bytes(value, maximum, minimum=1):
    _require(type(value) is list and minimum <= len(value) <= maximum
             and all(type(v) is int and 0 <= v <= 255 for v in value), 'public_bytes')


def _no_secret(value, depth=0):
    _require(depth <= 32, 'public_depth')
    if isinstance(value, str):
        _require('PRIVATE KEY' not in value, 'secret_in_public_output')
    elif isinstance(value, dict):
        for key, item in value.items():
            _require(key not in {'private_key', 'private_key_id', 'client_secret', 'access_token',
                                'refresh_token', 'credentials', 'management_tls_private_key_pem'},
                     'secret_in_public_output')
            _no_secret(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (str, dict, list)):
                _no_secret(item, depth + 1)


def _signed_public(raw, purpose, version, maximum=32 << 10):
    _require(isinstance(raw, (bytes, bytearray)) and 0 < len(raw) <= maximum, 'signed_object_bound')
    value = _json(raw)
    _keys(value, ['statement', 'signature'])
    _hex(value['signature'], 64)
    statement = value['statement']
    _require(type(statement) is dict and statement.get('purpose') == purpose
             and type(statement.get('version')) is int and statement['version'] == version,
             'signed_object_domain')
    _no_secret(statement)
    return value


def _b64_public(value, maximum=(MAX_PUBLIC * 3) // 4):
    _require(type(value) is str and 0 < len(value) <= ((maximum + 2) // 3) * 4, 'public_base64')
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError:
        raise GatewayError('public_base64') from None
    _require(0 < len(raw) <= maximum and base64.b64encode(raw).decode('ascii') == value,
             'public_base64')
    _require(b'PRIVATE KEY' not in raw, 'secret_in_public_output')
    if raw[:1] in (b'{', b'['):
        _no_secret(_json(raw))
    return raw


def postgrant_diagnostic(stage, error_class):
    return ((stage in POSTGRANT_STAGES and error_class in POSTGRANT_ERROR_CLASSES)
            or (stage == 'collect' and error_class in COLLECTION_ERROR_CLASSES))


def bootstrap_diagnostic(stage, error_class):
    return stage == 'bootstrap_collect' and (error_class == 'rejected' or error_class in COLLECTION_ERROR_CLASSES)


def report_cleanup_result(publication):
    if publication == {}:
        return {}
    _keys(publication, ['report_cleanup'])
    code = publication['report_cleanup']
    _require(type(code) is str and code in REPORT_CLEANUP_CLASSES, 'public_schema')
    return {'report_cleanup': code}


def diagnostic_error(publication, phases, ready_diagnostics):
    stage, error_class = publication['stage'], publication['error_class']
    if phases == {'bootstrap'} and bootstrap_diagnostic(stage, error_class):
        code = 'guest_bootstrap_failed'
    elif phases == {'policy'} and postgrant_diagnostic(stage, error_class):
        code = 'guest_postgrant_failed'
    elif stage == 'management_relay' and error_class == 'rejected' and phases in (
            {'sandbox-candidate'}, {'admission_request'}, {'ready'}, {'export', 'unproven'}):
        code = 'guest_management_relay_failed'
    elif stage == 'sandbox_lifetime' and error_class == 'rejected' and phases == {'admission_request'}:
        code = 'guest_sandbox_lifetime_failed'
    elif ready_diagnostics and error_class in READY_ERROR_CLASSES.get(stage, ()):
        code = 'guest_ready_failed'
    else:
        raise GatewayError('unexpected_phase')
    error = GatewayError(code)
    error.guest_stage = stage
    error.error_class = error_class
    return error


def public_frame(raw, *, ready_diagnostics=False):
    """Strict version, purpose, phase and field shape; no request/purpose injection."""
    _require(0 < len(raw) <= MAX_PUBLIC, 'public_frame_bound')
    value = _json(raw)
    _keys(value, ['version', 'purpose', 'phase', 'publication'])
    _require(type(value['version']) is int and value['version'] == 1
             and value['purpose'] == RESPONSE, 'public_domain')
    phase, p = value['phase'], value['publication']
    _require(type(phase) is str, 'public_phase')
    _no_secret(value)
    if phase in ('control-ready', 'ready') or (phase == 'unproven' and p == {}):
        _keys(p, [])
    elif phase == 'unproven' and isinstance(p, dict) and 'report_cleanup' in p:
        report_cleanup_result(p)
    elif phase == 'unproven':
        _keys(p, ['stage', 'error_class'])
        stage, error_class = p['stage'], p['error_class']
        _require(type(stage) is str and type(error_class) is str
                 and (postgrant_diagnostic(stage, error_class) or bootstrap_diagnostic(stage, error_class)
                      or (stage in ('management_relay', 'sandbox_lifetime') and error_class == 'rejected')
                      or (ready_diagnostics and error_class in READY_ERROR_CLASSES.get(stage, ()))),
                 'public_schema')
    elif phase == 'bootstrap':
        _keys(p, ['challenge_id', 'submission'])
        _identifier(p['challenge_id'])
        s = p['submission']
        _keys(s, ['binding', 'evidence', 'recorder_public_key', 'possession_signature_hex', 'keywrap_public_key'])
        b = s['binding']
        _keys(b, ['version', 'purpose', 'challenge_sha384', 'boot_binding_sha384', 'boot_id',
                  'boot_nonce_hex', 'recorder_key_sha384', 'keywrap_key_sha384'])
        _require(type(b['version']) is int and b['version'] == 3
                 and b['purpose'] == 'qlad.execution-proof.gcp-bootstrap-binding.v3', 'bootstrap_domain')
        for field in ('challenge_sha384', 'boot_binding_sha384', 'recorder_key_sha384', 'keywrap_key_sha384'):
            _hex(b[field], 48)
        _hex(b['boot_nonce_hex'], 32)
        _identifier(b['boot_id'])
        _bytes(s['recorder_public_key'], 32, 32)
        _hex(s['possession_signature_hex'], 64)
        k = s['keywrap_public_key']
        _keys(k, ['kty', 'alg', 'n', 'e'])
        _require(k['kty'] == 'RSA' and k['alg'] == 'RSA-OAEP-256' and k['e'] == 'AQAB'
                 and type(k['n']) is str and re.fullmatch('[A-Za-z0-9_-]{342}', k['n']), 'keywrap_shape')
        e = s['evidence']
        _keys(e, ['version', 'purpose', 'profile', 'tdx_quote', 'ccel_table', 'ccel_log'])
        _require(type(e['version']) is int and e['version'] == 2
                 and e['purpose'] == 'qlad.execution-proof.gcp-launch-evidence.v2'
                 and e['profile'] == 'onb17.gcp-launch-evidence.v2', 'evidence_domain')
        for field in ('tdx_quote', 'ccel_table', 'ccel_log'):
            _bytes(e[field], 1 << 20)
        _require(sum(len(e[field]) for field in ('tdx_quote', 'ccel_table', 'ccel_log')) <= 1 << 20,
                 'evidence_bound')
    elif phase == 'policy':
        fields = ['signed_aggregate', 'begin_response_base64', 'capture_request_base64',
                  'capture_response_base64', 'resource_challenge_response_base64', 'resource_decision_response_base64']
        _keys(p, fields)
        _bytes(p['signed_aggregate'], 32 << 10)
        _signed_public(bytes(p['signed_aggregate']), 'qlad.execution-proof.gcp-kbs-policy-aggregate.v2', 2)
        for field in fields[1:]:
            _b64_public(p[field])
    elif phase == 'admission_request':
        _keys(p, ['guest_nonce', 'recorder_request_json'])
        _identifier(p['guest_nonce'], 512)
        _bytes(p['recorder_request_json'], 32 << 10)
        _signed_public(bytes(p['recorder_request_json']), 'qlad.execution-proof.gcp-issuer-admission-request.v2', 2)
    elif phase == 'export':
        _keys(p, ['export_json_base64'])
        _b64_public(p['export_json_base64'])
    else:
        raise GatewayError('public_phase')
    return value


def public_wire_seconds(wire_size):
    _require(type(wire_size) is int and 0 < wire_size <= MAX_PUBLIC_WIRE, 'public_wire_bound')
    return min(PUBLIC_MAX_SECONDS,
               PUBLIC_BASE_SECONDS + (wire_size + PUBLIC_BYTES_PER_SECOND - 1) // PUBLIC_BYTES_PER_SECOND)


def decode_public_wire(wire, plain_size):
    """One bounded RFC1950 stream; no flush or automatic legacy decoding."""
    _require(type(wire) is bytes and 0 < len(wire) <= MAX_PUBLIC_WIRE, 'public_wire_bound')
    _require(type(plain_size) is int and 0 < plain_size <= MAX_PUBLIC, 'public_frame_bound')
    try:
        decoder = zlib.decompressobj()
        raw = decoder.decompress(wire, plain_size + 1)
        _require(len(raw) == plain_size and decoder.eof and not decoder.unconsumed_tail
                 and not decoder.unused_data, 'public_compression')
        return raw
    except zlib.error:
        raise GatewayError('public_compression') from None


def _regular(path, limit, private=False):
    _require(type(path) is Path or isinstance(path, Path), 'operator_file')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= limit
                     and info.st_uid in ({os.geteuid()} if private else {os.geteuid(), 0})
                     and info.st_mode & (0o077 if private else 0o022) == 0, 'operator_file')
            value = os.read(fd, limit + 1)
            _require(0 < len(value) <= limit and len(value) == info.st_size, 'operator_file')
            return value
        finally:
            os.close(fd)
    except OSError:
        raise GatewayError('operator_file') from None


def _directory(path):
    try:
        info = path.lstat()
        _require(path.is_absolute() and path.resolve(strict=True) == path
                 and stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                 and stat.S_IMODE(info.st_mode) == 0o700, 'operator_directory')
    except OSError:
        raise GatewayError('operator_directory') from None


def _ssh_strings(raw):
    values = []
    while raw:
        _require(len(raw) >= 4, 'host_key_format')
        size = struct.unpack('>I', raw[:4])[0]
        _require(0 < size <= 8192 and 4 + size <= len(raw), 'host_key_format')
        values.append(raw[4:4 + size])
        raw = raw[4 + size:]
    return values


def prepare_known_hosts(public_file, expected_sha384, directory, host):
    """Normalize the already fetched official public file; never fetch or trust-on-first-use."""
    directory = Path(directory)
    _directory(directory)
    raw = _regular(Path(public_file), 64 << 10)
    _hex(expected_sha384, 48)
    _require(hashlib.sha384(raw).hexdigest() == expected_sha384, 'host_key_pin')
    keys = []
    for line in raw.splitlines():
        fields = line.split()
        _require(2 <= len(fields) and fields[0] in
                 (b'ssh-ed25519', b'ssh-rsa', b'ecdsa-sha2-nistp256'), 'host_key_format')
        try:
            wire = base64.b64decode(fields[1], validate=True)
        except ValueError:
            raise GatewayError('host_key_format') from None
        values = _ssh_strings(wire)
        _require(values and values[0] == fields[0], 'host_key_format')
        if fields[0] == b'ssh-ed25519':
            _require(len(values) == 2 and len(values[1]) == 32, 'host_key_format')
        elif fields[0] == b'ssh-rsa':
            _require(len(values) == 3 and 1 <= len(values[1]) <= 8 and 256 <= len(values[2]) <= 1025,
                     'host_key_format')
        else:
            _require(len(values) == 3 and values[1] == b'nistp256' and len(values[2]) == 65
                     and values[2][0] == 4, 'host_key_format')
        key = fields[0] + b' ' + base64.b64encode(wire)
        _require(key not in keys and len(keys) < 32, 'host_key_format')
        keys.append(key)
    _require(keys, 'host_key_format')
    normalized = b''.join(f'[{host}]:9600 '.encode() + key + b'\n' for key in keys)
    path = directory / 'serial_known_hosts'
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(normalized)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise GatewayError('known_hosts_create') from None
    return path, hashlib.sha384(normalized).hexdigest()


@dataclass(frozen=True)
class Config:
    project: str
    zone: str
    instance: str
    directory: Path
    private_key: Path
    known_hosts: Path
    known_hosts_sha384: str
    absolute_deadline: float
    phase_seconds: float = 60
    ssh_user: str = 'onb17operator'


def serial_host(zone):
    _require(re.fullmatch(r'[a-z]+-[a-z0-9]+[0-9]-[a-z]', zone), 'serial_zone')
    return zone.rsplit('-', 1)[0] + '-ssh-serialport.googleapis.com'


def ssh_command(config):
    host = serial_host(config.zone)
    _require(re.fullmatch(r'[a-z][a-z0-9-]{4,28}[a-z0-9]', config.project), 'serial_project')
    _require(type(config.instance) is str
             and len(config.instance) <= 63 and re.fullmatch('[a-z][a-z0-9-]*[a-z0-9]', config.instance),
             'instance_scope')
    _directory(config.directory)
    _directory(config.private_key.parent)
    _require(config.known_hosts.parent == config.directory,
             'operator_directory')
    _require(all(re.fullmatch('[A-Za-z0-9_-]+', path.name)
                 for path in (config.private_key, config.known_hosts)), 'operator_file_name')
    key = _regular(config.private_key, 64 << 10, private=True)
    _require(key.startswith((b'-----BEGIN OPENSSH PRIVATE KEY-----', b'-----BEGIN PRIVATE KEY-----',
                             b'-----BEGIN RSA PRIVATE KEY-----')), 'ssh_key_format')
    known = _regular(config.known_hosts, 64 << 10)
    _hex(config.known_hosts_sha384, 48)
    _require(hashlib.sha384(known).hexdigest() == config.known_hosts_sha384
             and all(line.startswith(f'[{host}]:9600 '.encode()) for line in known.splitlines()), 'host_key_pin')
    _require(type(config.absolute_deadline) in (float, int) and math.isfinite(config.absolute_deadline)
             and 0 < config.absolute_deadline - time.monotonic() <= 14400
             and type(config.phase_seconds) in (float, int) and 0 < config.phase_seconds <= 60, 'deadline')
    _require(type(config.ssh_user) is str and re.fullmatch(r'[a-z][a-z0-9_-]{0,30}', config.ssh_user),
             'serial_ssh_user')
    username = (config.project + '.' + config.zone + '.' + config.instance + '.' + config.ssh_user + '.port=1.max-connections=1.'
                'replay-lines=1000000.replay-bytes=1048576.on-dropped-output=disconnect')
    options = {
        'StrictHostKeyChecking': 'yes', 'UserKnownHostsFile': str(config.known_hosts),
        'GlobalKnownHostsFile': '/dev/null', 'IdentityAgent': 'none', 'IdentitiesOnly': 'yes',
        'ForwardAgent': 'no', 'ForwardX11': 'no', 'ClearAllForwardings': 'yes',
        'ControlMaster': 'no', 'ControlPath': 'none', 'ProxyCommand': 'none', 'ProxyJump': 'none',
        'BatchMode': 'yes', 'EscapeChar': 'none', 'RequestTTY': 'no', 'PermitLocalCommand': 'no',
        'LocalCommand': 'none', 'AddKeysToAgent': 'no', 'PasswordAuthentication': 'no',
        'KbdInteractiveAuthentication': 'no', 'GSSAPIAuthentication': 'no',
        'HostbasedAuthentication': 'no', 'PreferredAuthentications': 'publickey',
        'ConnectionAttempts': '1', 'ConnectTimeout': '10', 'ServerAliveInterval': '5',
        'ServerAliveCountMax': '2', 'LogLevel': 'ERROR', 'UpdateHostKeys': 'no', 'VerifyHostKeyDNS': 'no',
    }
    command = [str(SSH), '-F', '/dev/null', '-T', '-p', '9600', '-i', str(config.private_key)]
    for key, value in options.items():
        command.extend(['-o', key + '=' + value])
    return command + ['-l', username, host]


class SerialGateway:
    def __init__(self, config):
        self.config = config
        self._child = None
        self._thread = None
        self._end = threading.Event()
        self._lock = threading.Lock()
        self._kill_sent = False
        self._reaped = False
        self._buffer = bytearray()
        self._stderr = 0
        self._received = 0
        self._sent = 0
        self._frames = 0
        self._stage = 'startup'
        self._failure = None
        self._exit = None
        self._subreaper = None
        self._active = False
        self._stderr_open = True
        self._eof = False

    def __enter__(self):
        global _PENDING_REAP
        command = ssh_command(self.config)
        _require(_ACTIVE.acquire(blocking=False), 'gateway_already_active')
        self._active = True
        try:
            if _PENDING_REAP is not None:
                _PENDING_REAP._kill_reap()
                _PENDING_REAP = None
            old = ctypes.c_int()
            _require(_LIBC.prctl(37, ctypes.byref(old), 0, 0, 0) == 0, 'subreaper')
            self._subreaper = old.value
            _require(_LIBC.prctl(36, 1, 0, 0, 0) == 0, 'subreaper')
            self._child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
                                           start_new_session=True, close_fds=True)
            for stream in (self._child.stdin, self._child.stdout, self._child.stderr):
                os.set_blocking(stream.fileno(), False)
            self._thread = threading.Thread(target=self._watchdog, name='onb17-serial-deadline', daemon=False)
            self._thread.start()
            return self
        except BaseException:
            self.close()
            raise

    def _watchdog(self):
        if not self._end.wait(max(0, self.config.absolute_deadline - time.monotonic())):
            self._failure = 'absolute_deadline'
            try:
                self._kill_group(time.monotonic() + _REAP_SECONDS)
            except (GatewayError, OSError):
                self._failure = 'ssh_kill_failed'

    def _kill_group(self, until):
        # Only the foreground owner waits. Once signalled, the watchdog can
        # never signal this group again, even after its PID has been reused.
        _require(self._lock.acquire(timeout=max(0, until - time.monotonic())), 'ssh_kill_timeout')
        try:
            if self._child is None or self._kill_sent:
                return
            try:
                os.killpg(self._child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self._kill_sent = True
        finally:
            self._lock.release()

    def _kill_reap(self):
        if self._child is None or self._reaped:
            return
        until = time.monotonic() + _REAP_SECONDS
        self._kill_group(until)
        if self._exit is None:
            try:
                self._exit = self._child.wait(timeout=max(0, until - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise GatewayError('child_reap_timeout') from None
        while True:
            try:
                pid, _ = os.waitpid(-self._child.pid, os.WNOHANG)
            except ChildProcessError:
                self._reaped = True
                return
            _require(time.monotonic() < until, 'descendant_reap_timeout')
            if not pid:
                time.sleep(.01)

    def close(self):
        global _PENDING_REAP
        if not self._active:
            return
        self._end.set()
        try:
            with ExitStack() as cleanup:
                if self._child is not None:
                    for stream in (self._child.stdin, self._child.stdout, self._child.stderr):
                        cleanup.callback(stream.close)
                cleanup.callback(self._kill_reap)
                if self._thread is not None and self._thread.ident is not None:
                    try:
                        self._thread.join(timeout=_WATCHDOG_JOIN_SECONDS)
                    except RuntimeError:
                        raise GatewayError('watchdog_join_failed') from None
                    _require(not self._thread.is_alive(), 'watchdog_join_timeout')
        finally:
            # Keep the original child handle across a bounded wait failure.
            # The next owner drains it before starting another SSH group.
            if self._child is not None and not self._reaped:
                _PENDING_REAP = self
            self._buffer[:] = b'\0' * len(self._buffer)
            self._buffer.clear()
            try:
                if self._subreaper is not None:
                    _require(_LIBC.prctl(36, self._subreaper, 0, 0, 0) == 0, 'subreaper')
                    self._subreaper = None
            finally:
                self._active = False
                _ACTIVE.release()

    def __exit__(self, exc_type, exc, traceback):
        try:
            self.close()
        except Exception as cleanup_error:
            if exc is None:
                raise
            code = cleanup_error.code if isinstance(cleanup_error, GatewayError) else type(cleanup_error).__name__
            exc.add_note('serial_cleanup: ' + code)

    def _deadline(self):
        return min(self.config.absolute_deadline, time.monotonic() + self.config.phase_seconds)

    def _io(self, until, writable=False, allow_eof=False):
        _require(self._child is not None and self._exit is None and self._failure is None, 'ssh_closed')
        left = min(until, self.config.absolute_deadline) - time.monotonic()
        _require(left > 0, 'phase_deadline')
        try:
            streams = ([] if self._eof else [self._child.stdout]) + ([self._child.stderr] if self._stderr_open else [])
            reads, writes, _ = select.select(streams,
                                            [self._child.stdin] if writable else [], [], min(left, .1))
            for stream in reads:
                value = os.read(stream.fileno(), 65536)
                if stream is self._child.stderr:
                    if not value:
                        self._stderr_open = False
                    self._stderr += len(value)
                    _require(self._stderr <= MAX_STDERR, 'stderr_bound')
                else:
                    if not value:
                        self._eof = True
                        _require(allow_eof, 'ssh_eof')
                        continue
                    self._received += len(value)
                    self._buffer.extend(value)
                    _require(len(self._buffer) <= MAX_PUBLIC_WIRE + MAX_STARTUP + 12, 'serial_buffer_bound')
            return bool(writes)
        except (OSError, ValueError):
            raise GatewayError('ssh_io') from None

    def _exact(self, size, until):
        while len(self._buffer) < size:
            self._io(until)
        _require(time.monotonic() < min(until, self.config.absolute_deadline), 'phase_deadline')
        value = bytes(self._buffer[:size])
        del self._buffer[:size]
        return value

    def _public(self, phases, *, deadline=float("inf")):
        try:
            started = time.monotonic()
            header_until = min(deadline, self.config.absolute_deadline, started + self.config.phase_seconds)
            prefix = self._exact(4, header_until)
            if prefix != PUBLIC_MAGIC:
                self._terminal(prefix, header_until)
                raise GatewayError('public_wire_magic')
            wire_size, plain_size = struct.unpack('>II', self._exact(8, header_until))
            seconds = public_wire_seconds(wire_size)
            _require(0 < plain_size <= MAX_PUBLIC, 'public_frame_bound')
            until = min(deadline, self.config.absolute_deadline, started + seconds)
            raw = decode_public_wire(self._exact(wire_size, until), plain_size)
            ready_diagnostics = self._stage == 'admission-sent' and phases == {'ready'}
            value = public_frame(raw, ready_diagnostics=ready_diagnostics)
            _require(time.monotonic() < until, 'phase_deadline')
            if value['phase'] == 'unproven' and 'report_cleanup' in value['publication']:
                _require(phases == {'export', 'unproven'}, 'unexpected_phase')
            elif value['phase'] == 'unproven' and value['publication']:
                error = diagnostic_error(value['publication'], phases, ready_diagnostics)
                self._frames += 1
                self._stage = 'unproven'
                raise error
            _require(value['phase'] in phases, 'unexpected_phase')
            self._frames += 1
            self._stage = value['phase']
            return value['publication']
        except GatewayError as error:
            self._failure = self._failure or error.code
            raise

    def _terminal(self, prefix, until):
        # Only a terminal record at the current frame boundary is recognized.
        # Never scan past arbitrary bytes or resume accepting policy afterward.
        _require(prefix == MARKER[:4], 'public_wire_magic')
        _require(prefix + self._exact(len(MARKER) - 4, until) == MARKER, 'public_wire_magic')
        line = bytearray()
        while not line.endswith(b'\n'):
            _require(len(line) < MAX_TERMINAL, 'public_wire_magic')
            line.extend(self._exact(1, until))
        value = _json(line)
        _keys(value, ['status', 'stage', 'errno'])
        status, stage, number = value['status'], value['stage'], value['errno']
        valid = (type(number) is int and
                 ((status in ('ROLE_FAILED', 'ROLE_EXITED_ZERO') and stage == 'after-child' and number == 0)
                  or (status == 'ROLE_TIMEOUT_OR_WAIT_ERROR' and stage == 'wait' and 0 <= number <= 4095)))
        _require(valid, 'public_wire_magic')
        error = GatewayError('guest_terminated')
        error.guest_terminal_status = status
        raise error

    def wait_control_ready(self):
        _require(self._stage == 'startup', 'operation_order')
        until = self._deadline()
        consumed = 0
        while True:
            while b'\n' not in self._buffer:
                self._io(until)
                _require(consumed + len(self._buffer) <= MAX_STARTUP, 'startup_bound')
            end = self._buffer.index(10) + 1
            line = bytes(self._buffer[:end]).rstrip(b'\r\n')
            del self._buffer[:end]
            consumed += end
            _require(consumed <= MAX_STARTUP, 'startup_bound')
            if MARKER not in line:
                continue
            _require(line.startswith(MARKER), 'startup_marker')
            value = _json(line[len(MARKER):])
            _keys(value, ['status', 'stage', 'errno'])
            _require(value == {'status': 'IMMUTABLE_VIEW_ESTABLISHED', 'stage': 'before-role', 'errno': 0}
                     and type(value['errno']) is int, 'startup_rejected')
            break
        self._public({'control-ready'})

    def _control_writable(self, until):
        writable = self._io(until, writable=True)
        # The same poll may have read a response while stdin became writable.
        _require(not self._buffer, 'unsolicited_serial_output')
        _require(time.monotonic() < until, 'phase_deadline')
        return writable

    def _write(self, raw, *, deadline=float("inf")):
        _require(len(raw) <= MAX_INPUT, 'control_bound')
        _require(not self._buffer, 'unsolicited_serial_output')
        until = min(deadline, self._deadline())
        packet = bytearray(struct.pack('>I', len(raw)))
        packet.extend(raw)
        view = memoryview(packet)
        offset = 0
        try:
            while offset < len(packet):
                if self._control_writable(until):
                    try:
                        count = os.write(self._child.stdin.fileno(), view[offset:offset + 65536])
                    except BlockingIOError:
                        continue
                    except OSError:
                        raise GatewayError('ssh_write') from None
                    _require(count > 0, 'ssh_write')
                    offset += count
                    self._sent += count
        except GatewayError as error:
            self._failure = self._failure or error.code
            raise
        finally:
            view.release()
            packet[:] = b'\0' * len(packet)

    def _control(self, request, *, deadline=float("inf")):
        raw = json.dumps({'version': 1, 'purpose': CONTROL, 'request': request},
                         separators=(',', ':'), ensure_ascii=True).encode('ascii')
        self._write(raw, deadline=deadline)

    def send_boot(self, manifest, references, challenge, management_key):
        _require(self._stage == 'control-ready', 'operation_order')
        _signed_public(manifest, 'qlad.execution-proof.gcp-boot-artifact-manifest.v1', 1)
        _signed_public(references, 'qlad.execution-proof.gcp-reference-policy-set.v1', 1)
        _signed_public(challenge, 'qlad.execution-proof.gcp-bootstrap-challenge.v3', 3)
        _management_key(management_key)
        public = json.dumps({'version': 1, 'purpose': CONTROL, 'request': {
            'signed_manifest': list(manifest), 'signed_references': list(references),
            'signed_bootstrap_challenge': list(challenge)}}, separators=(',', ':')).encode('ascii')
        secret = escaped_pem(management_key)
        raw = bytearray(public[:-2])
        try:
            raw.extend(b',"management_tls_private_key_pem":"')
            raw.extend(secret)
            raw.extend(b'"}}')
            self._write(raw)
            self._stage = 'boot-sent'
        finally:
            secret[:] = b'\0' * len(secret)
            raw[:] = b'\0' * len(raw)

    def receive_bootstrap(self):
        _require(self._stage == 'boot-sent', 'operation_order')
        return self._public({'bootstrap'})

    def send_grant(self, signed_grant):
        _require(self._stage == 'bootstrap', 'operation_order')
        _signed_public(signed_grant, 'qlad.execution-proof.launch.v3', 3)
        self._control({'signed_grant': list(signed_grant)})
        self._stage = 'grant-sent'

    def receive_policy(self):
        _require(self._stage == 'grant-sent', 'operation_order')
        return self._public({'policy'})

    def send_plan(self, signed_plan, effective_spec):
        _require(self._stage == 'policy', 'operation_order')
        _signed_public(signed_plan, 'qlad.execution-proof.gcp-attempt-plan.v1', 1)
        _require(isinstance(effective_spec, (bytes, bytearray)) and 0 < len(effective_spec) <= 256 << 10, 'spec_bound')
        _no_secret(_json(effective_spec))
        self._control({'signed_plan': list(signed_plan), 'effective_spec': list(effective_spec)})
        self._stage = 'plan-sent'

    def receive_admission_request(self):
        _require(self._stage == 'plan-sent', 'operation_order')
        return self._public({'admission_request'})

    def request_admission_status(self, deadline):
        _require(self._stage == 'admission_request', 'operation_order')
        self._control({'request_status': True}, deadline=deadline)
        return self._public({'admission_request'}, deadline=deadline)

    def send_admission(self, signed_authorization):
        _require(self._stage == 'admission_request', 'operation_order')
        _signed_public(signed_authorization, 'qlad.execution-proof.preparation-admission.v1', 1)
        self._control({'signed_authorization': list(signed_authorization)})
        self._stage = 'admission-sent'

    def receive_ready(self):
        _require(self._stage == 'admission-sent', 'operation_order')
        return self._public({'ready'})

    def receive_execution(self):
        _require(self._stage == 'ready', 'operation_order')
        p = self._public({'export', 'unproven'})
        return self._stage, p

    def send_stop(self):
        _require(self._stage in ('export', 'unproven'), 'operation_order')
        self._control({'stop': True})
        self._stage = 'stop-sent'
        until = self._deadline()
        while not self._eof:
            self._io(until, allow_eof=True)
            _require(len(self._buffer) <= 64 << 10, 'shutdown_output_bound')
        self._kill_reap()
        self._stage = 'stopped'

    def summary(self):
        return {'transport': 'direct-fixed-ssh-serial', 'instance': self.config.instance,
                'phase': self._stage, 'public_frames': self._frames, 'received_bytes': self._received,
                'sent_bytes': self._sent, 'discarded_stderr_bytes': self._stderr, 'ssh_exit': self._exit,
                'failure': self._failure, 'raw_serial_retained': False, 'raw_input_retained': False,
                'credentials_on_serial': False, 'hardware_verified': False, 'producer_qualified': False,
                'execution_verified': False}


def _der(value, offset):
    _require(offset + 2 <= len(value), 'management_key_format')
    tag, size = value[offset], value[offset + 1]
    offset += 2
    if size & 0x80:
        width = size & 0x7f
        _require(1 <= width <= 2 and offset + width <= len(value), 'management_key_format')
        size = int.from_bytes(value[offset:offset + width], 'big')
        offset += width
    _require(offset + size <= len(value), 'management_key_format')
    return tag, value[offset:offset + size], offset + size


def escaped_pem(value):
    """Encode the only JSON escapes in the validated PEM alphabet."""
    escaped = bytearray()
    for byte in value:
        if byte == 13:
            escaped.extend(b'\\r')
        elif byte == 10:
            escaped.extend(b'\\n')
        else:
            escaped.append(byte)
    return escaped


def _management_key(value):
    # Only unencrypted PKCS8 P256 management identity; neither an Ed25519 proof
    # signer nor a Google service-account JSON/RSA key can enter this API.
    _require(isinstance(value, (bytes, bytearray)) and 1 <= len(value) <= 16 << 10, 'management_key_format')
    lines = value.splitlines()
    _require(lines and lines[0] == b'-----BEGIN PRIVATE KEY-----' and lines[-1] == b'-----END PRIVATE KEY-----'
             and all(re.fullmatch(b'[A-Za-z0-9+/=]+', line) for line in lines[1:-1]), 'management_key_format')
    try:
        der = base64.b64decode(b''.join(lines[1:-1]), validate=True)
    except ValueError:
        raise GatewayError('management_key_format') from None
    tag, seq, end = _der(der, 0)
    _require(tag == 0x30 and end == len(der), 'management_key_format')
    tag, version, offset = _der(seq, 0)
    _require(tag == 2 and version == b'\0', 'management_key_format')
    tag, algorithm, offset = _der(seq, offset)
    _require(tag == 0x30 and algorithm == bytes.fromhex('06072a8648ce3d020106082a8648ce3d030107'), 'management_key_format')
    tag, private, end = _der(seq, offset)
    _require(tag == 4 and 1 <= len(private) <= 1024 and end == len(seq), 'management_key_format')
