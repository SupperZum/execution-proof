"""Early sandbox serial and Kata sequence for one direct TDX qualification VM."""

import hashlib
import os
import re
import select
import stat
import subprocess
import time
from pathlib import Path

import kubernetes_serial as controller


serial = controller.serial
attempt = controller.attempt
require = attempt.require
_QEXP = re.compile(r"qexp-[a-z0-9](?:[a-z0-9-]{0,94}[a-z0-9])?")
_IMAGE = re.compile(r"[a-z0-9][a-z0-9.:-]*(?:/[a-z0-9][a-z0-9_.-]*)+@sha256:[0-9a-f]{64}")


def validate_cid(cid):
    require(type(cid) is str and _QEXP.fullmatch(cid) is not None, "qualification_cid")
    return cid


def _candidate(value, expected_cid):
    serial._keys(value, ["container_id", "wire_sha384"])
    require(value["container_id"] == expected_cid, "qualification_cid")
    serial._hex(value["wire_sha384"], 48)
    require(value["wire_sha384"] != "0" * 96, "candidate_commitment")
    return value


def decode_candidate(raw, expected_cid):
    value = controller._publication(raw, {"sandbox-candidate"})
    _candidate(value["publication"], validate_cid(expected_cid))
    return value


class QualificationSerial(controller.LocalSerial):
    def __init__(self, read_fd, write_fd, deadline, *, expected_cid, phase_seconds=60):
        super().__init__(read_fd, write_fd, deadline, phase_seconds=phase_seconds)
        self.expected_cid = validate_cid(expected_cid)

    def _decode_public(self, raw, phases, ready_diagnostics):
        if phases == {"sandbox-candidate"}:
            return decode_candidate(raw, self.expected_cid)
        return super()._decode_public(raw, phases, ready_diagnostics)


def _live(deadline):
    remaining = deadline - time.monotonic()
    require(remaining > 0, "attempt_deadline")
    return remaining


def _pending(value, expected_cid):
    serial._keys(value, ["phase", "container_id", "wire_sha384"])
    require(value["phase"] == "pending", "qualification_kata_phase")
    return _candidate({key: value[key] for key in ("container_id", "wire_sha384")}, expected_cid)


def _finished(value):
    serial._keys(value, ["phase", "wait_status"])
    require(value["phase"] == "finished" and type(value["wait_status"]) is int
            and value["wait_status"] == 0, "qualification_task_exit")
    return value


def drive(gateway, authority, kata, *, expected_cid, manifest, references, effective_spec,
          management_key, archive_directory, deadline, phase_hooks=None, target_receipt=None):
    """Archive the protected export before ACK, then join the operator's Kata caller."""
    require(controller._deadline_is_bounded(deadline), "attempt_deadline")
    validate_cid(expected_cid)
    serial._management_key(management_key)
    serial._signed_public(manifest, "qlad.execution-proof.gcp-boot-artifact-manifest.v1", 1)
    serial._signed_public(references, "qlad.execution-proof.gcp-reference-policy-set.v1", 1)
    attempt.public_json(effective_spec, 256 << 10)
    archive = attempt.PublicArchive(archive_directory, management_key)
    try:
        controller._sync_archive_parent(archive)
        challenge = authority.bootstrap(deadline)
        challenge_id = serial._signed_public(
            challenge, "qlad.execution-proof.gcp-bootstrap-challenge.v3", 3
        )["statement"].get("challenge_id")
        serial._identifier(challenge_id)
        for name, raw in (("manifest", manifest), ("references", references), ("challenge", challenge)):
            archive.put(name + ".json", raw)
        _live(deadline)
        gateway.wait_control_ready()
        _live(deadline)
        gateway.send_boot(manifest, references, challenge, management_key)
        if phase_hooks is not None:
            phase_hooks.start()
        bootstrap = gateway.receive_bootstrap()
        require(bootstrap["challenge_id"] == challenge_id, "bootstrap_challenge")
        archive.put("bootstrap.json", attempt.encode(bootstrap))

        grant_deadline = min(deadline, time.monotonic() + 50) if phase_hooks is not None else deadline
        _live(grant_deadline)
        grant = authority.issue(challenge_id, bootstrap["submission"], grant_deadline)
        serial._signed_public(grant, "qlad.execution-proof.launch.v3", 3)
        archive.put("grant.json", grant)
        if phase_hooks is not None:
            phase_hooks.before_grant(grant_deadline)
        _live(grant_deadline)
        gateway.send_grant(grant)
        policy = gateway.receive_policy()
        aggregate = attempt.wire(policy, "signed_aggregate")
        serial._signed_public(aggregate, "qlad.execution-proof.gcp-kbs-policy-aggregate.v2", 2)
        archive.put("policy.json", attempt.encode(policy))

        gateway.receive_sandbox_ready()
        # The gateway holds one Create for at most 60 seconds. Keep Plan and
        # admission inside a single, shorter budget from the owner's dispatch.
        bind_deadline = min(deadline, time.monotonic() + 50)
        submitted = _pending(kata.pending(bind_deadline), expected_cid)
        candidate = _candidate(gateway.receive_candidate(), expected_cid)
        require(candidate == submitted, "qualification_wire_commitment")

        _live(bind_deadline)
        plan = authority.startup_plan(grant, aggregate, bind_deadline)
        controller._plan_binding(plan, effective_spec, expected_cid)
        archive.put("plan.json", plan)
        if phase_hooks is not None:
            phase_hooks.before_plan(bind_deadline)
        _live(bind_deadline)
        gateway.send_plan(plan, effective_spec)
        request = gateway.receive_admission_request()
        archive.put("admission-request.json", attempt.encode(request))
        _live(bind_deadline)
        authorization = authority.admit(
            grant, aggregate, request["guest_nonce"], attempt.wire(request, "recorder_request_json"),
            bind_deadline,
        )
        serial._signed_public(authorization, "qlad.execution-proof.preparation-admission.v1", 1)
        archive.put("authorization.json", authorization)
        if phase_hooks is not None:
            phase_hooks.before_admission(bind_deadline)
        _live(bind_deadline)
        gateway.send_admission(authorization)
        gateway.receive_ready()
        _live(bind_deadline)
        kata.start(bind_deadline)

        phase, publication = gateway.receive_execution()
        _live(deadline)
        require(phase in ("export", "unproven"), "unexpected_execution_phase")
        if phase == "export":
            archive.put("export.json", controller._protected_export(publication, expected_cid))
        else:
            serial._keys(publication, [])
        result = {
            "mode": "qualification_experiment",
            "phase": phase,
            "container_id": expected_cid,
            "candidate": candidate,
            "protected_export_available": phase == "export",
            "producer_qualified": False,
            "execution_verified": False,
        }
        archive.put("result.json", attempt.encode(result))
        _live(deadline)
        gateway.send_stop()
        terminal = _finished(kata.finish(deadline))
        receipt = {"candidate": candidate, "task": terminal}
        if target_receipt is not None:
            receipt["target"] = target_receipt
        archive.put("controller.json", attempt.encode(receipt))
        return result | {"transport_completed": True}
    finally:
        archive.close()


class KataProcess:
    """Own the exact caller process over an already authenticated Unix proxy."""

    def __init__(self, binary, binary_sha384, socket_path=None, *, cid, sandbox, image, relay_config=None):
        self.binary = Path(binary)
        require((socket_path is None) != (relay_config is None), "qualification_kata_transport")
        transport_path = Path(relay_config if relay_config is not None else socket_path)
        require(self.binary.is_absolute() and transport_path.is_absolute(), "qualification_kata_path")
        self.transport = ("--relay-config" if relay_config is not None else "--socket", str(transport_path))
        serial._hex(binary_sha384, 48)
        self.binary_sha384 = binary_sha384
        self.cid, self.sandbox = validate_cid(cid), validate_cid(sandbox)
        require(cid != sandbox, "qualification_kata_sandbox")
        require(type(image) is str and len(image) <= 512 and _IMAGE.fullmatch(image) is not None,
                "qualification_kata_image")
        self.image = image
        self.process = None
        self.phase = None
        self.buffer = bytearray()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self.process is not None:
            try:
                if self.process.poll() is None:
                    self.process.kill()
                self.process.wait(timeout=3)
            finally:
                self.process.stdin.close()
                self.process.stdout.close()

    def _receipt(self, deadline):
        while b"\n" not in self.buffer:
            require(len(self.buffer) < 512, "qualification_kata_receipt")
            ready, _, _ = select.select([self.process.stdout], [], [], _live(deadline))
            require(ready, "attempt_deadline")
            data = self.process.stdout.read(512 - len(self.buffer))
            require(data, "qualification_kata_exit")
            self.buffer.extend(data)
        raw, _, tail = self.buffer.partition(b"\n")
        self.buffer = bytearray(tail)
        return attempt.public_json(bytes(raw), 512)

    def pending(self, deadline):
        require(self.process is None, "qualification_kata_phase")
        _live(deadline)
        fd = os.open(self.binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as executable:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and bool(info.st_mode & 0o111)
                    and 0 < info.st_size <= 64 << 20, "qualification_kata_binary")
            require(hashlib.file_digest(executable, "sha384").hexdigest() == self.binary_sha384,
                    "qualification_kata_binary_pin")
            _live(deadline)
            # The attempt owns this process. Its independent total timeout
            # covers execution and ACK, while pending has the shorter deadline.
            self.process = subprocess.Popen(
                [f"/proc/self/fd/{fd}", *self.transport, "--cid", self.cid,
                 "--sandbox", self.sandbox, "--image", self.image, "--timeout-seconds", "300"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                bufsize=0, close_fds=True, pass_fds=(fd,), env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            )
        value = self._receipt(deadline)
        _pending(value, self.cid)
        self.phase = "pending"
        return value

    def start(self, deadline):
        require(self.phase == "pending", "qualification_kata_phase")
        _live(deadline)
        require(self.process.stdin.write(b"START\n") == 6, "qualification_kata_control")
        require(self._receipt(deadline) == {"phase": "started"}, "qualification_kata_phase")
        self.phase = "started"

    def finish(self, deadline):
        require(self.phase == "started", "qualification_kata_phase")
        value = _finished(self._receipt(deadline))
        try:
            status = self.process.wait(timeout=_live(deadline))
        except subprocess.TimeoutExpired:
            raise attempt.AttemptError("qualification_kata_exit") from None
        require(status == 0 and not self.buffer and self.process.stdout.read(1) == b"",
                "qualification_kata_exit")
        self.phase = "finished"
        return value
