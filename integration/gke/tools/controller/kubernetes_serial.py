"""Bounded ONB2 controller for one Kubernetes attempt on borrowed local FDs."""

import hashlib
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import time
from dataclasses import asdict, dataclass
from types import SimpleNamespace


import serial_gateway as serial
import attempt_driver as attempt
from authority_frontend import AuthorityUnavailable


GatewayError = serial.GatewayError
AttemptError = attempt.AttemptError
_PLAN_PURPOSE = "qlad.execution-proof.gcp-attempt-plan.v1"


@dataclass
class AttemptOutcome:
    protected_export_available: bool = False
    transport_completed: bool = False


def _deadline_is_bounded(deadline):
    now = time.monotonic()
    return type(deadline) in (int, float) and now < deadline <= now + 900


def _require_local_fd(fd):
    serial._require(type(fd) is int and fd >= 0, "local_serial_fd")
    try:
        mode = os.fstat(fd).st_mode
        if stat.S_ISSOCK(mode):
            duplicate = os.dup(fd)
            try:
                stream = socket.socket(fileno=duplicate)
            except OSError:
                os.close(duplicate)
                raise
            with stream:
                local = stream.family == socket.AF_UNIX and stream.type == socket.SOCK_STREAM
        else:
            local = stat.S_ISFIFO(mode) or (stat.S_ISCHR(mode) and os.isatty(fd))
        serial._require(local and not os.get_blocking(fd), "local_serial_fd")
    except (OSError, TypeError, ValueError):
        raise GatewayError("local_serial_fd") from None


def _candidate(value):
    serial._keys(value, ["container_id", "wire_sha384"])
    serial._hex(value["container_id"], 32)
    serial._hex(value["wire_sha384"], 48)
    serial._require(value["wire_sha384"] != "0" * 96, "candidate_commitment")
    return value


def _publication(raw, phases):
    value = serial._json(raw)
    serial._keys(value, ["version", "purpose", "phase", "publication"])
    serial._require(
        type(value["version"]) is int and value["version"] == 1
        and value["purpose"] == serial.RESPONSE, "public_domain"
    )
    if phases == {"sandbox-candidate"} and value["phase"] == "unproven":
        serial._keys(value["publication"], ["stage", "error_class"])
        raise serial.diagnostic_error(value["publication"], phases, False)
    serial._require(type(value["phase"]) is str and value["phase"] in phases, "unexpected_phase")
    return value


class LocalSerial:
    """The caller owns the nonblocking pipe, TTY, or Unix stream descriptors."""

    _deadline = serial.SerialGateway._deadline
    _exact = serial.SerialGateway._exact
    _terminal = serial.SerialGateway._terminal
    _control = serial.SerialGateway._control
    _control_writable = serial.SerialGateway._control_writable
    wait_control_ready = serial.SerialGateway.wait_control_ready
    receive_bootstrap = serial.SerialGateway.receive_bootstrap
    send_grant = serial.SerialGateway.send_grant
    receive_policy = serial.SerialGateway.receive_policy
    receive_admission_request = serial.SerialGateway.receive_admission_request
    request_admission_status = serial.SerialGateway.request_admission_status
    send_admission = serial.SerialGateway.send_admission
    receive_ready = serial.SerialGateway.receive_ready
    receive_execution = serial.SerialGateway.receive_execution

    def __init__(self, read_fd, write_fd, deadline, *, phase_seconds=60):
        serial._require(_deadline_is_bounded(deadline), "attempt_deadline")
        serial._require(
            type(phase_seconds) in (int, float) and 0 < phase_seconds <= 60,
            "phase_deadline",
        )
        _require_local_fd(read_fd)
        _require_local_fd(write_fd)
        self.config = SimpleNamespace(absolute_deadline=deadline, phase_seconds=phase_seconds)
        self._read_fd = read_fd
        self._write_fd = write_fd
        self._buffer = bytearray()
        self._stage = "startup"
        self._failure = None
        self._candidate = None
        self._software_fixture = False

    def _io(self, until, writable=False):
        serial._require(self._failure is None, "local_serial_closed")
        left = min(until, self.config.absolute_deadline) - time.monotonic()
        serial._require(left > 0, "phase_deadline")
        try:
            reads, writes, _ = select.select(
                [self._read_fd], [self._write_fd] if writable else [], [], left
            )
            if reads:
                try:
                    data = os.read(self._read_fd, 65536)
                except BlockingIOError:
                    return bool(writes)
                serial._require(data, "local_serial_eof")
                self._buffer.extend(data)
                serial._require(
                    len(self._buffer) <= serial.MAX_PUBLIC_WIRE + serial.MAX_STARTUP + 12,
                    "serial_buffer_bound",
                )
            return bool(writes)
        except (OSError, ValueError):
            raise GatewayError("local_serial_io") from None

    def _write(self, raw, *, deadline=float("inf")):
        serial._require(0 < len(raw) <= serial.MAX_INPUT, "control_bound")
        serial._require(not self._buffer, "unsolicited_serial_output")
        until = min(deadline, self._deadline())
        packet = bytearray(struct.pack(">I", len(raw)))
        packet.extend(raw)
        try:
            with memoryview(packet) as view:
                offset = 0
                while offset < len(packet):
                    if not self._control_writable(until):
                        continue
                    try:
                        count = os.write(self._write_fd, view[offset:offset + 65536])
                    except BlockingIOError:
                        continue
                    serial._require(count > 0, "local_serial_write")
                    offset += count
        except OSError:
            self._failure = "local_serial_write"
            raise GatewayError(self._failure) from None
        except GatewayError as error:
            self._failure = self._failure or error.code
            raise
        finally:
            packet[:] = b"\0" * len(packet)

    def _public(self, phases, *, deadline=float("inf")):
        serial._require(self._failure is None, "local_serial_closed")
        try:
            started = time.monotonic()
            header_until = min(deadline, self.config.absolute_deadline, started + self.config.phase_seconds)
            prefix = self._exact(4, header_until)
            if prefix != serial.PUBLIC_MAGIC:
                self._terminal(prefix, header_until)
                raise GatewayError("public_wire_magic")
            wire_size, plain_size = struct.unpack(">II", self._exact(8, header_until))
            until = min(deadline, self.config.absolute_deadline, started + serial.public_wire_seconds(wire_size))
            serial._require(0 < plain_size <= serial.MAX_PUBLIC, "public_frame_bound")
            raw = serial.decode_public_wire(self._exact(wire_size, until), plain_size)
            ready_diagnostics = self._stage == "admission-sent" and phases == {"ready"}
            value = self._decode_public(raw, phases, ready_diagnostics)
            serial._require(time.monotonic() < until, "phase_deadline")
            if value["phase"] == "unproven" and "report_cleanup" in value["publication"]:
                serial._require(phases == {"export", "unproven"}, "unexpected_phase")
            elif value["phase"] == "unproven" and value["publication"]:
                error = serial.diagnostic_error(value["publication"], phases, ready_diagnostics)
                self._stage = "unproven"
                raise error
            serial._require(value["phase"] in phases, "unexpected_phase")
            self._stage = value["phase"]
            return value["publication"]
        except GatewayError as error:
            self._failure = self._failure or error.code
            raise

    def _decode_public(self, raw, phases, ready_diagnostics):
        if phases == {"sandbox-ready"}:
            value = _publication(raw, phases)
            serial._keys(value["publication"], [])
        elif phases == {"sandbox-candidate"}:
            value = _publication(raw, phases)
            _candidate(value["publication"])
        elif self._software_fixture and phases == {"local-record"}:
            value = _publication(raw, phases)
            serial._keys(value["publication"], ["record_json_base64"])
        elif self._software_fixture and phases == {"app-exited"}:
            value = _publication(raw, phases)
            publication = value["publication"]
            serial._keys(publication, ["container_id", "exit_code"])
            serial._require(
                publication["container_id"] == self._candidate
                and type(publication["exit_code"]) is int and publication["exit_code"] == 0,
                "local_app_exit",
            )
        elif self._software_fixture and phases == {"quote-unavailable"}:
            value = _publication(raw, phases)
            publication = value["publication"]
            serial._keys(publication, ["attempts", "hardware_quote_available"])
            serial._require(
                type(publication["attempts"]) is int and publication["attempts"] == 3
                and publication["hardware_quote_available"] is False, "local_quote_status",
            )
        else:
            value = serial.public_frame(raw, ready_diagnostics=ready_diagnostics)
        return value

    def send_boot(self, manifest, references, challenge, management_key):
        serial._require(not self._software_fixture, "operation_order")
        serial.SerialGateway.send_boot(self, manifest, references, challenge, management_key)

    def receive_sandbox_ready(self):
        expected_stage = "control-ready" if self._software_fixture else "policy"
        serial._require(self._stage == expected_stage, "operation_order")
        return self._public({"sandbox-ready"})

    def receive_candidate(self):
        serial._require(self._stage == "sandbox-ready", "operation_order")
        publication = self._public({"sandbox-candidate"})
        self._candidate = publication["container_id"]
        return publication

    def send_plan(self, signed_plan, effective_spec):
        serial._require(not self._software_fixture and self._stage == "sandbox-candidate",
                        "operation_order")
        _plan_binding(signed_plan, effective_spec, self._candidate)
        self._control({"signed_plan": list(signed_plan), "effective_spec": list(effective_spec)})
        self._stage = "plan-sent"

    def send_stop(self):
        stages = ("quote-unavailable",) if self._software_fixture else ("export", "unproven")
        serial._require(self._stage in stages, "operation_order")
        self._control({"stop": True})
        self._stage = "stop-sent"

    def wait_local_control_ready(self):
        """Opt in to the software fixture protocol before reading its first frame."""
        serial._require(self._stage == "startup" and not self._software_fixture, "operation_order")
        self._software_fixture = True
        self._public({"control-ready"})

    def send_local_bind(self, cid):
        serial._require(self._software_fixture and self._stage == "sandbox-candidate",
                        "operation_order")
        serial._require(cid == self._candidate, "candidate_worker_mismatch")
        self._control({"bind": {"container_id": cid}})
        self._stage = "bind-sent"

    def receive_local_record(self):
        serial._require(self._software_fixture and self._stage == "bind-sent", "operation_order")
        return self._public({"local-record"})

    def send_local_record_received(self):
        serial._require(self._software_fixture and self._stage == "local-record", "operation_order")
        self._control({"record_received": True})
        self._stage = "record-received"

    def receive_local_app_exit(self):
        serial._require(self._software_fixture and self._stage == "record-received",
                        "operation_order")
        return self._public({"app-exited"})

    def receive_local_quote_status(self):
        serial._require(self._software_fixture and self._stage == "app-exited", "operation_order")
        return self._public({"quote-unavailable"})


@dataclass(frozen=True)
class ExpectedPod:
    pod_uid: str
    container_name: str
    attempt: int
    image_ref: str


@dataclass(frozen=True)
class WorkerReadback:
    pod_uid: str
    sandbox_id: str
    container_id: str
    container_name: str
    attempt: int
    image_ref: str


def _pod_identity(pod):
    serial._identifier(pod.pod_uid)
    serial._identifier(pod.container_name)
    serial._integer(pod.attempt, 0, (1 << 32) - 1)
    serial._require(
        type(pod.image_ref) is str
        and re.fullmatch(r"[A-Za-z0-9._:/\[\]-]{1,512}@sha256:[0-9a-f]{64}", pod.image_ref),
        "worker_image_digest",
    )
    return pod.pod_uid, pod.container_name, pod.attempt, pod.image_ref


def match_candidate(candidate, expected, readback):
    """Compare a guest publication to a unique, independently selected CRI app."""
    _candidate(candidate)
    attempt.require(type(expected) is ExpectedPod, "expected_pod")
    attempt.require(type(readback) is WorkerReadback, "worker_readback")
    attempt.require(_pod_identity(readback) == _pod_identity(expected), "worker_identity")
    serial._hex(readback.sandbox_id, 32)
    serial._hex(readback.container_id, 32)
    attempt.require(readback.sandbox_id != readback.container_id, "worker_container_id")
    attempt.require(readback.container_id == candidate["container_id"], "candidate_worker_mismatch")
    return readback.container_id


def _plan_binding(plan, spec, cid):
    value = serial._signed_public(plan, _PLAN_PURPOSE, 1)
    attempt.public_json(spec, 256 << 10)
    statement = value["statement"]
    attempt.require(
        statement.get("container_id") == cid
        and statement.get("effective_spec_sha384") == hashlib.sha384(spec).hexdigest(),
        "plan_binding",
    )


def _record_binding(raw, cid):
    record = attempt.public_json(raw, 16 << 10)
    digests = (
        "grant_sha384", "admission_context_sha384", "preparation_record_sha384",
        "startup_binding_sha384", "candidate_spec_sha384", "final_spec_sha384",
        "image_sha384", "executable_sha384",
    )
    serial._keys(record, ("version", "purpose", "profile", "claim", "event_id",
                          "mount_id", "task", *digests))
    attempt.require(
        type(record["version"]) is int and record["version"] == 1
        and record["purpose"] == "qlad.execution-proof.exec-record.v1"
        and record["profile"] == "onb17.static-elf-exec-committed.v1"
        and record["claim"] == "exec_committed", "export_record_domain"
    )
    serial._hex(record["event_id"], 32)
    attempt.require(record["event_id"] != "0" * 64, "export_record_event")
    for name in digests:
        serial._hex(record[name], 48)
    serial._integer(record["mount_id"], 1, (1 << 63) - 1)
    task = record["task"]
    serial._keys(task, ("container_id", "generation", "pid", "process_start_time_ticks"))
    attempt.require(task["container_id"] == cid, "export_record_binding")
    serial._integer(task["generation"], 1, (1 << 64) - 1)
    serial._integer(task["pid"], 1, (1 << 31) - 1)
    serial._integer(task["process_start_time_ticks"], 1, (1 << 64) - 1)


def _protected_export(publication, cid):
    serial._keys(publication, ["export_json_base64"])
    raw = serial._b64_public(publication["export_json_base64"])
    value = attempt.public_json(raw)
    field_limits = {
        "record_b64": 16 << 10,
        "admission_b64": 1 << 20,
        "preparation_b64": 16 << 10,
        "provenance_b64": 1 << 20,
        "announcement_b64": 1024,
        "validated_receipt_b64": 1024,
        "quote_b64": 4 << 20,
    }
    import guest_readback
    fields = ("version", "purpose", *field_limits)
    if guest_readback.FIELD in value:
        fields += (guest_readback.FIELD,)
    serial._keys(value, fields)
    attempt.require(type(value["version"]) is int and value["version"] == 2
                    and value["purpose"] == "qlad.execution-proof.protected-export.v2", "export_domain")
    decoded = {name: serial._b64_public(value[name], limit) for name, limit in field_limits.items()}
    _record_binding(decoded["record_b64"], cid)
    if guest_readback.FIELD in value:
        try:
            guest_readback.verify(value, decoded["record_b64"])
        except (ValueError, KeyError, TypeError) as error:
            raise GatewayError("guest_readback_binding") from error
    quote = attempt.public_json(decoded["quote_b64"], 4 << 20)
    serial._keys(quote, ("version", "purpose", "profile", "challenge", "tdx_quote", "ccel_table", "ccel_log"))
    attempt.require(type(quote["version"]) is int and quote["version"] == 2
                    and quote["purpose"] == "qlad.execution-proof.gcp-exec-quote.v2"
                    and quote["profile"] == "onb17.protected-r-gcp-tdx-quote.v2"
                    and type(quote["challenge"]) is dict, "export_quote_domain")
    for name in ("tdx_quote", "ccel_table", "ccel_log"):
        serial._bytes(quote[name], 1 << 20)
    attempt.require(sum(len(quote[name]) for name in ("tdx_quote", "ccel_table", "ccel_log")) <= 1 << 20,
                    "export_quote_bound")
    # Require the Intel TDX wire header before retaining an export. The
    # independent verifier appraises the original quote and its binding to R.
    tdx = bytes(quote["tdx_quote"])
    attempt.require(
        636 < len(tdx) <= 512 << 10
        and tdx[:2] in (b"\x04\x00", b"\x05\x00")
        and tdx[2:12] == b"\x02\x00\x81\x00\x00\x00\x00\x00\x00\x00"
        and tdx[12:28] == bytes.fromhex("939a7233f79c4ca9940a0db3957f0607"),
        "export_tdx_quote_header",
    )
    return raw


def _sync_archive_parent(archive):
    descriptor = os.open(archive.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _archive_local_record(archive, raw):
    descriptor = os.open(
        "record.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600, dir_fd=archive.directory,
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(archive.directory)


def drive(gateway, authority, read_worker, *, expected, manifest, references, effective_spec,
          management_key, archive_directory, deadline, target_receipt=None, before_stop=None, outcome=None):
    """Run the GCP-format protocol over the supplied transport without a cloud client.

    The trusted authority supplies signed inputs. The worker callback selects a
    unique READY sandbox and CREATED container using independent Pod identity.
    Callbacks must honor the deadline. The caller owns Kubernetes/QEMU teardown.
    """
    attempt.require(_deadline_is_bounded(deadline), "attempt_deadline")
    attempt.require(type(expected) is ExpectedPod, "expected_pod")
    _pod_identity(expected)
    serial._management_key(management_key)
    serial._signed_public(manifest, "qlad.execution-proof.gcp-boot-artifact-manifest.v1", 1)
    serial._signed_public(references, "qlad.execution-proof.gcp-reference-policy-set.v1", 1)
    attempt.public_json(effective_spec, 256 << 10)
    if outcome is None:
        outcome = AttemptOutcome()
    archive = attempt.PublicArchive(archive_directory, management_key)

    def live():
        attempt.require(time.monotonic() < deadline, "attempt_deadline")

    try:
        _sync_archive_parent(archive)
        challenge = authority.bootstrap(deadline)
        statement = serial._signed_public(challenge, "qlad.execution-proof.gcp-bootstrap-challenge.v3", 3)["statement"]
        challenge_id = statement.get("challenge_id")
        serial._identifier(challenge_id)
        archive.put("manifest.json", manifest)
        archive.put("references.json", references)
        archive.put("challenge.json", challenge)
        live()
        gateway.wait_control_ready()
        live()
        gateway.send_boot(manifest, references, challenge, management_key)
        bootstrap = gateway.receive_bootstrap()
        attempt.require(bootstrap["challenge_id"] == challenge_id, "bootstrap_challenge")
        archive.put("bootstrap.json", attempt.encode(bootstrap))

        live()
        grant = authority.issue(challenge_id, bootstrap["submission"], deadline)
        serial._signed_public(grant, "qlad.execution-proof.launch.v3", 3)
        archive.put("grant.json", grant)
        live()
        gateway.send_grant(grant)
        policy = gateway.receive_policy()
        aggregate = attempt.wire(policy, "signed_aggregate")
        serial._signed_public(aggregate, "qlad.execution-proof.gcp-kbs-policy-aggregate.v2", 2)
        archive.put("policy.json", attempt.encode(policy))

        stage = "sandbox-ready"
        candidate = None
        try:
            gateway.receive_sandbox_ready()
            stage = "sandbox-candidate"
            candidate = gateway.receive_candidate()
            stage = "worker-readback"
            live()
            readback = read_worker(deadline)
            live()
            cid = match_candidate(candidate, expected, readback)
        except Exception as error:
            diagnostic = {"stage": stage, "candidate": candidate, "execution_verified": False}
            try:
                archive.put("failure.json", attempt.encode(diagnostic))
            except (OSError, attempt.AttemptError, GatewayError):
                error.add_note("could not archive the public failure checkpoint")
            raise
        receipt = {"worker": asdict(readback), "candidate": candidate}
        if target_receipt is not None:
            receipt["target"] = target_receipt
        archive.put("controller.json", attempt.encode(receipt))
        live()
        try:
            plan = authority.startup_plan(grant, aggregate, cid, deadline)
        except AuthorityUnavailable:
            live()
            attempt.require(read_worker(deadline) == readback, "worker_selection_changed")
            live()
            plan = authority.startup_plan(grant, aggregate, cid, deadline)
        live()
        _plan_binding(plan, effective_spec, cid)
        archive.put("plan.json", plan)
        live()
        gateway.send_plan(plan, effective_spec)

        request = gateway.receive_admission_request()
        archive.put("admission-request.json", attempt.encode(request))
        live()
        authorization = attempt.admit_pending(authority, gateway, grant, aggregate, request, deadline)
        serial._signed_public(authorization, "qlad.execution-proof.preparation-admission.v1", 1)
        archive.put("authorization.json", authorization)
        live()
        gateway.send_admission(authorization)
        gateway.receive_ready()

        phase, publication = gateway.receive_execution()
        live()
        attempt.require(phase in ("export", "unproven"), "unexpected_execution_phase")
        if phase == "export":
            archive.put("export.json", _protected_export(publication, cid))
            outcome.protected_export_available = True
        result = {
            "phase": phase,
            "container_id": cid,
            "protected_export_available": outcome.protected_export_available,
            "hardware_verified": False,
            "producer_qualified": False,
            "execution_verified": False,
        }
        # Early sandbox treats Stop as the archive acknowledgement. Retain
        # both the original export and the terminal receipt before sending it.
        if phase == "unproven":
            result.update(serial.report_cleanup_result(publication))
        archive.put("result.json", attempt.encode(result))
        live()
        try:
            if before_stop is not None:
                before_stop()
        finally:
            gateway.send_stop()
        outcome.transport_completed = True
        return result | {"transport_completed": True}
    finally:
        archive.close()


def drive_local(gateway, read_worker, teardown_worker, *, expected, archive_directory, deadline,
                before_ack=None):
    """Archive the software fixture's original R before acknowledging it.

    The worker callback supplies the independent CREATED container readback.
    The teardown callback confirms worker cleanup while the fixture waits for Stop.
    This path issues no launch or admission authorization and expects no TDX quote.
    """
    attempt.require(_deadline_is_bounded(deadline), "attempt_deadline")
    attempt.require(type(expected) is ExpectedPod, "expected_pod")
    _pod_identity(expected)
    archive = attempt.PublicArchive(archive_directory, b"")

    def live():
        attempt.require(time.monotonic() < deadline, "attempt_deadline")

    try:
        _sync_archive_parent(archive)
        gateway.wait_local_control_ready()
        gateway.receive_sandbox_ready()
        candidate = gateway.receive_candidate()
        live()
        readback = read_worker(deadline)
        live()
        cid = match_candidate(candidate, expected, readback)
        archive.put("controller.json", attempt.encode({"worker": asdict(readback), "candidate": candidate}))
        live()
        gateway.send_local_bind(cid)

        publication = gateway.receive_local_record()
        raw = serial._b64_public(publication["record_json_base64"], 16 << 10)
        _record_binding(raw, cid)
        _archive_local_record(archive, raw)
        if before_ack is not None:
            before_ack(deadline)
        live()
        gateway.send_local_record_received()

        app_exit = gateway.receive_local_app_exit()
        quote_status = gateway.receive_local_quote_status()
        live()
        teardown_worker(deadline)
        live()
        gateway.send_stop()
        result = {
            "phase": "local-record",
            "container_id": cid,
            "record_file": "record.json",
            "record_json_sha384": hashlib.sha384(raw).hexdigest(),
            "app_exit_code": app_exit["exit_code"],
            "quote_attempts": quote_status["attempts"],
            "hardware_quote_available": False,
            "execution_verified": False,
            "worker_teardown_confirmed": True,
        }
        archive.put("result.json", attempt.encode(result))
        return {**result, "record_path": str(archive.path.absolute() / "record.json")}
    finally:
        archive.close()
