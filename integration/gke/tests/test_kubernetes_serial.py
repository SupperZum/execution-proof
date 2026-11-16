"""Exercise one local serial attempt and fail-closed transitions over real FDs."""

import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import select
import stat
import struct
import tempfile
from threading import Event
import time
import unittest
from unittest import mock
import zlib

import kubernetes_serial as controller


CID = "a1" * 32
SANDBOX = "b2" * 32
CANDIDATE = {"container_id": CID, "wire_sha384": "c3" * 48}
EXPECTED = controller.ExpectedPod("pod-uid", "app", 0, "local/app@sha256:" + "d4" * 32)
READBACK = controller.WorkerReadback(
    EXPECTED.pod_uid, SANDBOX, CID, EXPECTED.container_name, EXPECTED.attempt, EXPECTED.image_ref
)
SPEC = b'{"fixture":true}'


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode()


def b64(raw):
    return base64.b64encode(raw).decode()


def signed(purpose, version=1, **fields):
    return encode({"statement": {"version": version, "purpose": purpose, **fields}, "signature": "11" * 64})


def policy_fixture():
    aggregate = signed("qlad.execution-proof.gcp-kbs-policy-aggregate.v2", 2)
    policy = {"signed_aggregate": list(aggregate)}
    for name in ("begin_response", "capture_request", "capture_response",
                 "resource_challenge_response", "resource_decision_response"):
        policy[name + "_base64"] = b64(b"{}")
    return policy


def record(cid=CID):
    digests = (
        "grant_sha384", "admission_context_sha384", "preparation_record_sha384",
        "startup_binding_sha384", "candidate_spec_sha384", "final_spec_sha384",
        "image_sha384", "executable_sha384",
    )
    return encode({
        "version": 1,
        "purpose": "qlad.execution-proof.exec-record.v1",
        "profile": "onb17.static-elf-exec-committed.v1",
        "claim": "exec_committed",
        "event_id": "ab" * 32,
        **{name: "cd" * 48 for name in digests},
        "mount_id": 2,
        "task": {"container_id": cid, "generation": 1, "pid": 3, "process_start_time_ticks": 4},
    })


def export_fixture():
    # Deliberately invalid quote body with the format header needed by the
    # transport. The controller must never claim independent verification.
    header = bytes.fromhex("040002008100000000000000939a7233f79c4ca9940a0db3957f0607")
    quote = {
        "version": 2, "purpose": "qlad.execution-proof.gcp-exec-quote.v2",
        "profile": "onb17.protected-r-gcp-tdx-quote.v2", "challenge": {},
        "tdx_quote": list(header.ljust(637, b"\x00")), "ccel_table": [2], "ccel_log": [3],
    }
    export = {name + "_b64": b64(b"{}") for name in
              ("admission", "preparation", "provenance", "announcement", "validated_receipt")}
    export.update(version=2, purpose="qlad.execution-proof.protected-export.v2",
                  record_b64=b64(record()), quote_b64=b64(encode(quote)))
    return encode(export)


def wire(raw):
    compressed = zlib.compress(raw)
    return b"ONB2" + struct.pack(">II", len(compressed), len(raw)) + compressed


def publish(peer, phase, publication):
    peer.sendall(wire(encode({
        "version": 1, "purpose": controller.serial.RESPONSE, "phase": phase, "publication": publication,
    })))


def request(peer):
    def exact(size):
        value = bytearray()
        while len(value) < size:
            chunk = peer.recv(size - len(value))
            if not chunk:
                raise EOFError("test peer")
            value.extend(chunk)
        return value

    size, = struct.unpack(">I", exact(4))
    value = json.loads(exact(size))
    assert set(value) == {"version", "purpose", "request"}
    assert value["version"] == 1 and value["purpose"] == controller.serial.CONTROL
    return value["request"]


class PipePeer:
    def __init__(self, read_fd, write_fd):
        self.read_fd = read_fd
        self.write_fd = write_fd
        self.timeout = 1

    def sendall(self, value):
        if os.write(self.write_fd, value) != len(value):
            raise IOError("short test peer write")

    def recv(self, size):
        ready, _, _ = select.select([self.read_fd], [], [], self.timeout)
        if not ready:
            raise TimeoutError("test peer")
        return os.read(self.read_fd, size)


class SerialTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.archive = Path(scratch.name) / "public"
        self.host_read, peer_write = os.pipe()
        peer_read, self.host_write = os.pipe()
        for fd in (self.host_read, self.host_write, peer_read, peer_write):
            self.addCleanup(os.close, fd)
        os.set_blocking(self.host_read, False)
        os.set_blocking(self.host_write, False)
        self.peer = PipePeer(peer_read, peer_write)
        self.deadline = time.monotonic() + 2
        self.gateway = controller.LocalSerial(
            self.host_read, self.host_write, self.deadline, phase_seconds=0.5
        )

    def startup_local(self):
        publish(self.peer, "control-ready", {})
        publish(self.peer, "sandbox-ready", {})
        publish(self.peer, "sandbox-candidate", CANDIDATE)

    def run_local(self, read_worker=lambda _: READBACK, teardown=lambda _: None):
        return controller.drive_local(
            self.gateway, read_worker, teardown, expected=EXPECTED, archive_directory=self.archive,
            deadline=self.deadline,
        )

    def assert_no_control(self):
        self.peer.timeout = 0.05
        with self.assertRaises(TimeoutError):
            self.peer.recv(1)

    def test_local_record_is_durable_before_task_resume_and_stop_follows_worker_teardown(self):
        raw = record()
        events = []

        def fixture():
            self.startup_local()
            self.assertEqual(request(self.peer), {"bind": {"container_id": CID}})
            events.append("bind")
            publish(self.peer, "local-record", {"record_json_base64": b64(raw)})
            self.assertEqual(request(self.peer), {"record_received": True})
            self.assertEqual((self.archive / "record.json").read_bytes(), raw)
            events.append("record-received")
            publish(self.peer, "app-exited", {"container_id": CID, "exit_code": 0})
            publish(self.peer, "quote-unavailable", {"attempts": 3, "hardware_quote_available": False})
            self.assertEqual(request(self.peer), {"stop": True})
            events.append("stop")

        def read_worker(deadline):
            self.assertEqual(deadline, self.deadline)
            events.append("worker-read")
            return READBACK

        def teardown(deadline):
            self.assertEqual(deadline, self.deadline)
            self.assertEqual((self.archive / "record.json").read_bytes(), raw)
            events.append("teardown")

        with ThreadPoolExecutor(max_workers=1) as executor:
            peer = executor.submit(fixture)
            result = self.run_local(read_worker, teardown)
            peer.result(timeout=1)
        self.assertEqual(events, ["worker-read", "bind", "record-received", "teardown", "stop"])
        self.assertEqual(Path(result["record_path"]), self.archive / "record.json")
        self.assertEqual(result["record_json_sha384"], hashlib.sha384(raw).hexdigest())
        self.assertFalse(result["hardware_quote_available"])
        self.assertFalse(result["execution_verified"])
        self.assertEqual(stat.S_IMODE((self.archive / "record.json").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.archive.stat().st_mode), 0o700)
        self.assertEqual(set(path.name for path in self.archive.iterdir()),
                         {"controller.json", "record.json", "result.json"})

    def test_worker_cid_mismatch_prevents_bind(self):
        self.startup_local()
        with self.assertRaisesRegex(controller.AttemptError, "^candidate_worker_mismatch$"):
            self.run_local(lambda _: replace(READBACK, container_id="ef" * 32))
        self.assert_no_control()
        self.assertEqual(list(self.archive.iterdir()), [])

    def test_worker_identity_mismatches(self):
        for changes in ({"pod_uid": "other"}, {"container_name": "other"}, {"attempt": 1},
                        {"image_ref": "local/app@sha256:" + "ef" * 32}):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(controller.AttemptError, "^worker_identity$"):
                    controller.match_candidate(CANDIDATE, EXPECTED, replace(READBACK, **changes))

    def test_wrong_record_cid_prevents_exec_release(self):
        def fixture():
            self.startup_local()
            self.assertEqual(request(self.peer), {"bind": {"container_id": CID}})
            publish(self.peer, "local-record", {"record_json_base64": b64(record("ef" * 32))})

        with ThreadPoolExecutor(max_workers=1) as executor:
            peer = executor.submit(fixture)
            with self.assertRaisesRegex(controller.AttemptError, "^export_record_binding$"):
                self.run_local()
            peer.result(timeout=1)
        self.assert_no_control()
        self.assertFalse((self.archive / "record.json").exists())

    def test_record_archive_failure_prevents_exec_release(self):
        def fixture():
            self.startup_local()
            self.assertEqual(request(self.peer), {"bind": {"container_id": CID}})
            publish(self.peer, "local-record", {"record_json_base64": b64(record())})

        with ThreadPoolExecutor(max_workers=1) as executor:
            peer = executor.submit(fixture)
            with mock.patch.object(controller, "_archive_local_record", side_effect=OSError("fixture")):
                with self.assertRaises(OSError):
                    self.run_local()
            peer.result(timeout=1)
        self.assert_no_control()

    def test_duplicate_public_phase_field_fails_closed_even_with_another_frame_buffered(self):
        publish(self.peer, "control-ready", {})
        self.peer.sendall(wire(b'{"version":1,"purpose":"' + controller.serial.RESPONSE.encode()
                               + b'","phase":"sandbox-ready","phase":"sandbox-ready","publication":{}}'))
        publish(self.peer, "sandbox-ready", {})
        self.gateway.wait_local_control_ready()
        with self.assertRaisesRegex(controller.GatewayError, "^duplicate_json_field$"):
            self.gateway.receive_sandbox_ready()
        with self.assertRaisesRegex(controller.GatewayError, "^local_serial_closed$"):
            self.gateway.receive_sandbox_ready()

    def test_candidate_deadline_is_bounded(self):
        deadline = time.monotonic() + 1
        gateway = controller.LocalSerial(
            self.host_read, self.host_write, deadline, phase_seconds=0.05
        )
        publish(self.peer, "control-ready", {})
        publish(self.peer, "sandbox-ready", {})
        gateway.wait_local_control_ready()
        gateway.receive_sandbox_ready()
        with self.assertRaisesRegex(controller.GatewayError, "^phase_deadline$"):
            gateway.receive_candidate()
        self.assert_no_control()

    def test_production_plan_requires_ready_candidate_and_exact_binding(self):
        # Grant-sent is the post-bootstrap boundary. The existing ONB2 policy
        # parser remains in use before the two new phases.
        self.gateway._stage = "grant-sent"
        policy = policy_fixture()
        publish(self.peer, "policy", policy)
        publish(self.peer, "sandbox-ready", {})
        publish(self.peer, "sandbox-candidate", CANDIDATE)
        self.assertEqual(self.gateway.receive_policy(), policy)
        valid_plan = signed(controller._PLAN_PURPOSE, container_id=CID,
                            effective_spec_sha384=hashlib.sha384(SPEC).hexdigest())
        with self.assertRaisesRegex(controller.GatewayError, "^operation_order$"):
            self.gateway.send_plan(valid_plan, SPEC)
        self.gateway.receive_sandbox_ready()
        self.assertEqual(self.gateway.receive_candidate(), CANDIDATE)
        wrong_plan = signed(controller._PLAN_PURPOSE, container_id="ef" * 32,
                            effective_spec_sha384=hashlib.sha384(SPEC).hexdigest())
        for plan, spec in ((wrong_plan, SPEC), (valid_plan, b"{}")):
            with self.assertRaisesRegex(controller.AttemptError, "^plan_binding$"):
                self.gateway.send_plan(plan, spec)
        self.assert_no_control()
        self.gateway.send_plan(valid_plan, SPEC)
        self.assertEqual(request(self.peer), {"signed_plan": list(valid_plan), "effective_spec": list(SPEC)})

    def run_normal_driver(self, terminal, *, worker_error=None):
        manifest = signed("qlad.execution-proof.gcp-boot-artifact-manifest.v1")
        references = signed("qlad.execution-proof.gcp-reference-policy-set.v1")
        challenge = signed("qlad.execution-proof.gcp-bootstrap-challenge.v3", 3, challenge_id="fixture")
        grant = signed("qlad.execution-proof.launch.v3", 3)
        plan = signed(controller._PLAN_PURPOSE, container_id=CID,
                      effective_spec_sha384=hashlib.sha384(SPEC).hexdigest())
        admission_request = signed("qlad.execution-proof.gcp-issuer-admission-request.v2", 2)
        auth = signed("qlad.execution-proof.preparation-admission.v1")
        # This DER passes format-only checks and has no usable private scalar.
        management = (
            b"-----BEGIN PRIVATE KEY-----\n"
            + base64.b64encode(bytes.fromhex("3041020100301306072a8648ce3d020106082a8648ce3d0301070427"
                                             "30250201010420") + bytes(32))
            + b"\n-----END PRIVATE KEY-----\n"
        )
        boot = {
            "challenge_id": "fixture",
            "submission": {
                "binding": {
                    "version": 3, "purpose": "qlad.execution-proof.gcp-bootstrap-binding.v3",
                    "challenge_sha384": "10" * 48, "boot_binding_sha384": "11" * 48,
                    "boot_id": "fixture", "boot_nonce_hex": "12" * 32,
                    "recorder_key_sha384": "13" * 48, "keywrap_key_sha384": "14" * 48,
                },
                "evidence": {
                    "version": 2, "purpose": "qlad.execution-proof.gcp-launch-evidence.v2",
                    "profile": "onb17.gcp-launch-evidence.v2", "tdx_quote": [1],
                    "ccel_table": [2], "ccel_log": [3],
                },
                "recorder_public_key": [4] * 32, "possession_signature_hex": "15" * 64,
                "keywrap_public_key": {"kty": "RSA", "alg": "RSA-OAEP-256", "n": "A" * 342, "e": "AQAB"},
            },
        }
        events = []
        policy = policy_fixture()

        def fixture():
            self.peer.sendall(controller.serial.MARKER
                              + b'{"status":"IMMUTABLE_VIEW_ESTABLISHED","stage":"before-role","errno":0}\n')
            publish(self.peer, "control-ready", {})
            self.assertEqual(set(request(self.peer)), {"signed_manifest", "signed_references",
                             "signed_bootstrap_challenge", "management_tls_private_key_pem"})
            publish(self.peer, "bootstrap", boot)
            self.assertEqual(request(self.peer), {"signed_grant": list(grant)})
            publish(self.peer, "policy", policy)
            publish(self.peer, "sandbox-ready", {})
            publish(self.peer, "sandbox-candidate", CANDIDATE)
            if worker_error is not None:
                return
            self.assertEqual(request(self.peer), {"signed_plan": list(plan), "effective_spec": list(SPEC)})
            publish(self.peer, "admission_request", {"guest_nonce": "nonce",
                                                     "recorder_request_json": list(admission_request)})
            self.assertEqual(request(self.peer), {"signed_authorization": list(auth)})
            publish(self.peer, "ready", {})
            terminal()

        def startup_plan(_grant, _aggregate, cid, deadline):
            self.assertEqual((cid, deadline), (CID, self.deadline))
            events.append("plan")
            return plan

        def worker_readback(_):
            events.append("worker-read")
            if worker_error is not None:
                raise worker_error
            return READBACK

        authority = mock.Mock()
        authority.bootstrap.return_value = challenge
        authority.issue.return_value = grant
        authority.startup_plan.side_effect = startup_plan
        authority.admit.return_value = auth

        def drive():
            return controller.drive(
                self.gateway, authority, worker_readback, expected=EXPECTED, manifest=manifest,
                references=references, effective_spec=SPEC, management_key=management,
                archive_directory=self.archive, deadline=self.deadline,
            )

        with ThreadPoolExecutor(max_workers=1) as executor:
            peer = executor.submit(fixture)
            try:
                if worker_error is not None:
                    with self.assertRaises(type(worker_error)) as failure:
                        drive()
                    self.assertIs(failure.exception, worker_error)
                    authority.startup_plan.assert_not_called()
                    authority.admit.assert_not_called()
                    self.assert_no_control()
                    return
                result = drive()
            finally:
                peer.result(timeout=1)
        self.assertEqual(events, ["worker-read", "plan"])
        authority.issue.assert_called_once_with("fixture", boot["submission"], self.deadline)
        authority.admit.assert_called_once_with(grant, bytes(policy["signed_aggregate"]), "nonce",
                                                admission_request, self.deadline)
        for path in self.archive.iterdir():
            self.assertFalse(b"PRIVATE KEY" in path.read_bytes(), path.name)
        return result

    def test_normal_driver_binds_after_independent_worker_readback(self):
        def terminal():
            publish(self.peer, "unproven", {})
            self.assertEqual(request(self.peer), {"stop": True})
            self.assertEqual(json.loads((self.archive / "result.json").read_bytes())["phase"], "unproven")

        result = self.run_normal_driver(terminal)
        self.assertEqual(result["phase"], "unproven")
        self.assertTrue(result["transport_completed"])
        self.assertFalse(result["protected_export_available"])
        self.assertFalse(result["execution_verified"])
        self.assertFalse((self.archive / "export.json").exists())

    def test_normal_driver_retains_guest_candidate_when_worker_readback_fails(self):
        self.run_normal_driver(None, worker_error=RuntimeError("simulated target disappeared"))
        self.assertEqual(json.loads((self.archive / "failure.json").read_bytes()), {
            "stage": "worker-readback", "candidate": CANDIDATE, "execution_verified": False,
        })
        self.assertFalse((self.archive / "controller.json").exists())
        self.assertFalse((self.archive / "plan.json").exists())

    def test_normal_driver_ack_follows_delayed_export_and_fsync(self):
        raw = export_fixture()
        terminal_synced, allow_ack = Event(), Event()
        synced = []
        fsync = os.fsync

        def delay_fsync(fd):
            fsync(fd)
            name = Path(os.readlink(f"/proc/self/fd/{fd}")).name
            if name in ("export.json", "result.json"):
                synced.append(name)
            if name == "result.json":
                terminal_synced.set()
                self.assertTrue(allow_ack.wait(timeout=1))

        def terminal():
            self.assert_no_control()
            publish(self.peer, "export", {"export_json_base64": b64(raw)})
            try:
                self.assertTrue(terminal_synced.wait(timeout=1))
                self.assert_no_control()
            finally:
                allow_ack.set()
            self.peer.timeout = 1
            self.assertEqual(request(self.peer), {"stop": True})
            self.assertEqual((self.archive / "export.json").read_bytes(), raw)

        with mock.patch.object(os, "fsync", side_effect=delay_fsync):
            result = self.run_normal_driver(terminal)
        self.assertEqual(synced, ["export.json", "result.json"])
        self.assertTrue(result["protected_export_available"])
        self.assertFalse(result["execution_verified"])

    def test_normal_driver_does_not_ack_failed_export_fsync(self):
        fsync = os.fsync

        def fail_export_fsync(fd):
            if Path(os.readlink(f"/proc/self/fd/{fd}")).name == "export.json":
                raise OSError("injected export fsync failure")
            fsync(fd)

        def terminal():
            publish(self.peer, "export", {"export_json_base64": b64(export_fixture())})
            self.assert_no_control()

        with mock.patch.object(os, "fsync", side_effect=fail_export_fsync):
            with self.assertRaisesRegex(OSError, "^injected export fsync failure$"):
                self.run_normal_driver(terminal)
        self.assertFalse((self.archive / "result.json").exists())

    def test_production_rejects_local_record_and_export_without_tdx(self):
        self.gateway._stage = "ready"
        publish(self.peer, "local-record", {"record_json_base64": b64(record())})
        with self.assertRaisesRegex(controller.GatewayError, "^public_phase$"):
            self.gateway.receive_execution()

        quote = {
            "version": 2, "purpose": "qlad.execution-proof.gcp-exec-quote.v2",
            "profile": "onb17.protected-r-gcp-tdx-quote.v2", "challenge": {},
            "tdx_quote": [1], "ccel_table": [2], "ccel_log": [3],
        }
        export = {name + "_b64": b64(b"{}") for name in
                  ("admission", "preparation", "provenance", "announcement", "validated_receipt")}
        export.update(version=2, purpose="qlad.execution-proof.protected-export.v2",
                      record_b64=b64(record()), quote_b64=b64(encode(quote)))
        with self.assertRaisesRegex(controller.AttemptError, "^export_tdx_quote_header$"):
            controller._protected_export({"export_json_base64": b64(encode(export))}, CID)

    def test_borrowed_descriptor_validation_rejects_blocking_and_regular_files(self):
        blocking, other = os.pipe()
        self.addCleanup(os.close, blocking)
        self.addCleanup(os.close, other)
        with self.assertRaisesRegex(controller.GatewayError, "^local_serial_fd$"):
            controller.LocalSerial(blocking, self.host_write, self.deadline)
        with tempfile.TemporaryFile() as regular:
            os.set_blocking(regular.fileno(), False)
            with self.assertRaisesRegex(controller.GatewayError, "^local_serial_fd$"):
                controller.LocalSerial(regular.fileno(), self.host_write, self.deadline)


if __name__ == "__main__":
    unittest.main()
