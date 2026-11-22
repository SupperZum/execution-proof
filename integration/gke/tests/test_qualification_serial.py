"""Exercise qualification over ONB2 pipes with a fixed standalone Kata task."""

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import tempfile
from threading import Event
import time
import unittest
from unittest import mock

import kubernetes_serial as transport
import qualification_serial as controller
import run
from test_kubernetes_serial import (
    SPEC, PipePeer, b64, encode, export_fixture, policy_fixture, publish, record, request, signed,
)


CID = "qexp-fixture-app"
CANDIDATE = {"container_id": CID, "wire_sha384": "c3" * 48}
MANIFEST = signed("qlad.execution-proof.gcp-boot-artifact-manifest.v1")
REFERENCES = signed("qlad.execution-proof.gcp-reference-policy-set.v1")
CHALLENGE = signed("qlad.execution-proof.gcp-bootstrap-challenge.v3", 3, challenge_id="fixture")
GRANT = signed("qlad.execution-proof.launch.v3", 3)
PLAN = signed(transport._PLAN_PURPOSE, container_id=CID,
              effective_spec_sha384=hashlib.sha384(SPEC).hexdigest())
ADMISSION_REQUEST = signed("qlad.execution-proof.gcp-issuer-admission-request.v2", 2)
AUTHORIZATION = signed("qlad.execution-proof.preparation-admission.v1")
PENDING = {"phase": "pending", **CANDIDATE}
POLICY = policy_fixture()
AGGREGATE = bytes(POLICY["signed_aggregate"])
# Format-only fixture with no usable private scalar.
MANAGEMENT = (
    b"-----BEGIN PRIVATE KEY-----\n"
    + base64.b64encode(bytes.fromhex("3041020100301306072a8648ce3d020106082a8648ce3d0301070427"
                                     "30250201010420") + bytes(32))
    + b"\n-----END PRIVATE KEY-----\n"
)
BOOTSTRAP = {
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


def qualification_export():
    export = json.loads(export_fixture())
    export["record_b64"] = b64(record(CID))
    return encode(export)


class QualificationSerialTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.archive = Path(scratch.name) / "public"
        host_read, peer_write = os.pipe()
        peer_read, host_write = os.pipe()
        for fd in (host_read, host_write, peer_read, peer_write):
            self.addCleanup(os.close, fd)
        os.set_blocking(host_read, False)
        os.set_blocking(host_write, False)
        self.peer = PipePeer(peer_read, peer_write)
        self.deadline = time.monotonic() + 4
        self.gateway = controller.QualificationSerial(
            host_read, host_write, self.deadline, expected_cid=CID, phase_seconds=1,
        )
        self.authority = mock.Mock(spec_set=["bootstrap", "issue", "startup_plan", "admit"])
        self.authority.bootstrap.return_value = CHALLENGE
        self.authority.issue.return_value = GRANT
        self.authority.startup_plan.return_value = PLAN
        self.authority.admit.return_value = AUTHORIZATION
        self.kata = mock.Mock(spec_set=["pending", "start", "finish"])
        self.kata.pending.return_value = PENDING
        self.kata.start.return_value = None
        self.kata.finish.return_value = {"phase": "finished", "wait_status": 0}
        self.events = mock.Mock()
        self.events.attach_mock(self.authority, "authority")
        self.events.attach_mock(self.kata, "kata")

    def drive(self, *, outcome=None):
        return controller.drive(
            self.gateway, self.authority, self.kata, expected_cid=CID, manifest=MANIFEST,
            references=REFERENCES, effective_spec=SPEC, management_key=MANAGEMENT,
            archive_directory=self.archive, deadline=self.deadline, outcome=outcome,
        )

    def test_boot_preserves_pem_line_endings_in_framed_json(self):
        for ending in (b"\n", b"\r\n"):
            with self.subTest(ending=ending):
                key = MANAGEMENT.replace(b"\n", ending)
                self.gateway._stage = "control-ready"
                self.gateway.send_boot(MANIFEST, REFERENCES, CHALLENGE, key)
                decoded = request(self.peer)
                self.assertEqual(decoded["management_tls_private_key_pem"].encode("ascii"), key)
                self.assertEqual(self.gateway._stage, "boot-sent")

    def publish_candidate(self, candidate=CANDIDATE):
        self.peer.sendall(transport.serial.MARKER
                          + b'{"status":"IMMUTABLE_VIEW_ESTABLISHED","stage":"before-role","errno":0}\n')
        publish(self.peer, "control-ready", {})
        self.assertEqual(request(self.peer), {
            "signed_manifest": list(MANIFEST), "signed_references": list(REFERENCES),
            "signed_bootstrap_challenge": list(CHALLENGE),
            "management_tls_private_key_pem": MANAGEMENT.decode("ascii"),
        })
        publish(self.peer, "bootstrap", BOOTSTRAP)
        self.assertEqual(request(self.peer), {"signed_grant": list(GRANT)})
        publish(self.peer, "policy", POLICY)
        publish(self.peer, "sandbox-ready", {})
        publish(self.peer, "sandbox-candidate", candidate)

    def publish_ready(self):
        self.publish_candidate()
        self.assertEqual(request(self.peer), {"signed_plan": list(PLAN), "effective_spec": list(SPEC)})
        publish(self.peer, "admission_request", {"guest_nonce": "nonce",
                                                "recorder_request_json": list(ADMISSION_REQUEST)})
        self.assertEqual(request(self.peer), {"signed_authorization": list(AUTHORIZATION)})
        self.kata.start.assert_not_called()
        publish(self.peer, "ready", {})

    def assert_no_control(self):
        readable, _, _ = select.select([self.peer.read_fd], [], [], 0.05)
        self.assertEqual(readable, [])

    def assert_authority_and_kata_order(self):
        call = mock.call
        self.assertEqual(self.events.mock_calls, [
            call.authority.bootstrap(self.deadline),
            call.authority.issue("fixture", BOOTSTRAP["submission"], self.deadline),
            call.kata.pending(self.deadline),
            call.authority.startup_plan(GRANT, AGGREGATE, self.deadline),
            call.authority.admit(GRANT, AGGREGATE, "nonce", ADMISSION_REQUEST, self.deadline),
            call.kata.start(self.deadline),
            call.kata.finish(self.deadline),
        ])

    def test_export_is_synced_before_stop_and_kata_finish(self):
        raw = qualification_export()
        started, ack = Event(), Event()
        archive_syncs = []
        real_fsync = os.fsync

        def sync(fd):
            real_fsync(fd)
            path = Path(os.readlink(f"/proc/self/fd/{fd}"))
            if path == self.archive or path.parent == self.archive:
                archive_syncs.append(path.name)

        def start(_deadline):
            started.set()

        def finish(_deadline):
            self.assertTrue(ack.wait(timeout=1))
            return {"phase": "finished", "wait_status": 0}

        def fixture():
            self.publish_ready()
            self.assertTrue(started.wait(timeout=1))
            publish(self.peer, "export", {"export_json_base64": b64(raw)})
            self.assertEqual(request(self.peer), {"stop": True})
            self.assertEqual((self.archive / "export.json").read_bytes(), raw)
            self.assertEqual(archive_syncs[-4:], ["export.json", "public", "result.json", "public"])
            ack.set()

        self.kata.start.side_effect = start
        self.kata.finish.side_effect = finish
        with mock.patch.object(os, "fsync", side_effect=sync):
            with ThreadPoolExecutor(max_workers=1) as executor:
                peer = executor.submit(fixture)
                result = self.drive()
                peer.result(timeout=1)
        self.assert_authority_and_kata_order()
        self.assertEqual(result["phase"], "export")
        self.assertTrue(result["protected_export_available"])
        self.assertFalse(result["execution_verified"])
        self.assertFalse(result["producer_qualified"])
        self.assertTrue((self.archive / "controller.json").is_file())
        for file in self.archive.iterdir():
            self.assertNotIn(b"PRIVATE KEY", file.read_bytes(), file.name)

    def test_kata_finish_failure_reports_archived_export(self):
        raw = qualification_export()
        def fixture():
            self.publish_ready()
            publish(self.peer, "export", {"export_json_base64": b64(raw)})
            self.assertEqual(request(self.peer), {"stop": True})

        self.kata.finish.side_effect = TimeoutError()
        with ThreadPoolExecutor(max_workers=1) as executor:
            peer = executor.submit(fixture)
            with mock.patch("builtins.print") as report, self.assertRaises(TimeoutError):
                run.controller_attempt(self.drive)
            peer.result(timeout=1)
        self.assertEqual(json.loads(report.call_args.args[0]), {
            "protected_export_available": True, "transport_completed": False, "retirement": "external"})
        self.assertEqual((self.archive / "export.json").read_bytes(), raw)

    def test_unproven_stops_and_finishes_without_export(self):
        def fixture():
            self.publish_ready()
            publish(self.peer, "unproven", {})
            self.assertEqual(request(self.peer), {"stop": True})
            terminal = json.loads((self.archive / "result.json").read_bytes())
            self.assertEqual(terminal["phase"], "unproven")

        with ThreadPoolExecutor(max_workers=1) as executor:
            peer = executor.submit(fixture)
            result = self.drive()
            peer.result(timeout=1)
        self.assert_authority_and_kata_order()
        self.assertEqual(result["phase"], "unproven")
        self.assertFalse(result["protected_export_available"])
        self.assertFalse((self.archive / "export.json").exists())

    def test_report_cleanup_alone_is_retained_on_qualification(self):
        def fixture():
            self.publish_ready()
            publish(self.peer, "unproven", {"report_cleanup": "report_cleanup_failed"})
            self.assertEqual(request(self.peer), {"stop": True})
            return json.loads((self.archive / "result.json").read_bytes())

        with ThreadPoolExecutor(max_workers=1) as executor:
            peer = executor.submit(fixture)
            result = self.drive()
            self.assertEqual(peer.result(timeout=1)["report_cleanup"], "report_cleanup_failed")
        self.assertEqual(result["phase"], "unproven")
        self.assertFalse(result["protected_export_available"])
        self.assertFalse((self.archive / "export.json").exists())

    def assert_rejected_before_plan(self, candidate, error):
        with ThreadPoolExecutor(max_workers=1) as executor:
            peer = executor.submit(self.publish_candidate, candidate)
            with self.assertRaisesRegex(transport.AttemptError, f"^{error}$"):
                self.drive()
            peer.result(timeout=1)
        self.authority.startup_plan.assert_not_called()
        self.kata.start.assert_not_called()
        self.kata.finish.assert_not_called()
        self.assertFalse((self.archive / "plan.json").exists())
        self.assert_no_control()

    def test_guest_cid_mismatch_prevents_plan(self):
        self.assert_rejected_before_plan({**CANDIDATE, "container_id": "qexp-unrelated"}, "qualification_cid")

    def test_pending_cid_mismatch_prevents_plan(self):
        self.kata.pending.return_value = {**PENDING, "container_id": "qexp-unrelated"}
        self.assert_rejected_before_plan(CANDIDATE, "qualification_cid")
        self.kata.pending.assert_called_once_with(self.deadline)

    def test_pending_wire_digest_mismatch_prevents_plan(self):
        self.kata.pending.return_value = {**PENDING, "wire_sha384": "ef" * 48}
        self.assert_rejected_before_plan(CANDIDATE, "qualification_wire_commitment")
        self.kata.pending.assert_called_once_with(self.deadline)

    def test_failed_export_fsync_prevents_stop_and_kata_finish(self):
        real_fsync = os.fsync

        def fail_export_sync(fd):
            if Path(os.readlink(f"/proc/self/fd/{fd}")).name == "export.json":
                raise OSError("injected export fsync failure")
            real_fsync(fd)

        def fixture():
            self.publish_ready()
            publish(self.peer, "export", {"export_json_base64": b64(qualification_export())})

        with mock.patch.object(os, "fsync", side_effect=fail_export_sync):
            with ThreadPoolExecutor(max_workers=1) as executor:
                peer = executor.submit(fixture)
                with self.assertRaisesRegex(OSError, "^injected export fsync failure$"):
                    self.drive()
                peer.result(timeout=1)
        self.kata.start.assert_called_once_with(self.deadline)
        self.kata.finish.assert_not_called()
        self.assertFalse((self.archive / "controller.json").exists())
        self.assert_no_control()


class KataProcessTests(unittest.TestCase):
    def test_wait_failure_preserves_primary_and_closes_both_pipes(self):
        for primary, wait_error, code in (
            (controller.attempt.AttemptError("attempt_deadline"), subprocess.TimeoutExpired("fixture", 3),
             "qualification_kata_wait_timeout"),
            (None, OSError("fixture"), "qualification_kata_wait_failed"),
        ):
            with self.subTest(primary=primary):
                kata = controller.KataProcess("/bin/cat", "ab" * 48, "/tmp/fixture.sock",
                    cid=CID, sandbox="qexp-sandbox", image="local/app@sha256:" + "12" * 32)
                with subprocess.Popen(["/bin/cat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as process:
                    kata.process = process
                    with mock.patch.object(process, "wait", side_effect=wait_error) as wait:
                        with self.assertRaises(controller.attempt.AttemptError) as failed:
                            with kata:
                                if primary is not None:
                                    raise primary
                    wait.assert_called_once_with(timeout=3)
                    if primary is not None:
                        self.assertIs(failed.exception, primary)
                        self.assertEqual(primary.__notes__, ["serial_cleanup: " + code])
                    else:
                        self.assertEqual(failed.exception.args, (code,))
                    self.assertTrue(process.stdin.closed)
                    self.assertTrue(process.stdout.closed)
                    self.assertIsNotNone(process.wait(timeout=3))

    def test_pinned_executable_and_start_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "kata-fixture"
            binary.write_text(
                "#!/usr/bin/python3\n"
                "import json, sys\n"
                'assert sys.argv[1] == "--relay-config"\n'
                f"print(json.dumps({PENDING!r}), flush=True)\n"
                'assert sys.stdin.buffer.readline() == b"START\\n"\n'
                "print(json.dumps({'phase': 'started'}), flush=True)\n"
                "print(json.dumps({'phase': 'finished', 'wait_status': 0}), flush=True)\n"
            )
            binary.chmod(0o700)
            options = dict(cid=CID, sandbox="qexp-fixture-pause",
                           image="registry.invalid/onb17/proof@sha256:" + "11" * 32,
                           relay_config=root / "relay.json")
            deadline = time.monotonic() + 3
            with controller.KataProcess(binary, "ab" * 48, **options) as wrong_pin:
                with self.assertRaisesRegex(controller.attempt.AttemptError, "qualification_kata_binary_pin"):
                    wrong_pin.pending(deadline)
                self.assertIsNone(wrong_pin.process)
            pin = hashlib.sha384(binary.read_bytes()).hexdigest()
            with controller.KataProcess(binary, pin, **options) as kata:
                self.assertEqual(kata.pending(deadline), PENDING)
                self.assertIsNone(kata.process.poll())
                kata.start(deadline)
                self.assertEqual(kata.finish(deadline), {"phase": "finished", "wait_status": 0})


if __name__ == "__main__":
    unittest.main()
