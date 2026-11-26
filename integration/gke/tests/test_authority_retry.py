"""Normal GKE authority retries at the pinned subprocess and guest handoff boundaries."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import run
from test_kubernetes_serial import CID, CANDIDATE, EXPECTED, READBACK, SPEC, encode, signed
from test_qualification_serial import BOOTSTRAP, CHALLENGE, MANAGEMENT, MANIFEST, POLICY, REFERENCES


def reply(status, **fields):
    return encode({"version": 1, "purpose": "qlad.execution-proof.gcp-authority-response.v1",
                   "result": {"status": status, **fields}})


class AuthorityRetryTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name)
        self.archive = root / "archive"
        pin = root / "authority"
        pin.write_bytes(b"pinned test executable")
        pin.chmod(0o700)
        config = {key: str(root / key) for key in
                  ("issuer_config", "authority_key", "collateral", "signed_q", "issuer_store")}
        config["authority"] = {"path": str(pin), "sha384": hashlib.sha384(pin.read_bytes()).hexdigest()}
        config["authority_journal_bucket"] = "test-bucket"
        execute = mock.Mock(wraps=run.executor(config, experimental=False))
        self.authority = run.cloud.LateCidAuthority(execute, signed("qlad.execution-proof.tenant-intent.v2", 2),
                                                   b"{}", "auditor")
        self.grant = signed("qlad.execution-proof.launch.v3", 3, grant_id="grant-1")
        self.deadline = time.monotonic() + 10

    def test_recovery_before_guest_delivery(self):
        gateway = mock.Mock()
        gateway.receive_bootstrap.return_value = BOOTSTRAP
        gateway.receive_policy.return_value = POLICY
        gateway.receive_candidate.return_value = CANDIDATE
        # Stop at the admission boundary; no pin or consume should have been requested.
        gateway.receive_admission_request.side_effect = EOFError
        requests = {"begin": [], "issue": [], "startup_plan": []}
        plans = []

        def command(args, deadline, *, stdin, **kwargs):
            self.assertIn("--journal-bucket", args)
            body = json.loads(stdin)["request"]
            op = body["operation"]
            requests[op].append(stdin)
            if op == "begin":
                out = reply("challenge", signed_challenge_json=list(CHALLENGE))
            elif op == "issue":
                self.assertEqual(body["challenge_id"], BOOTSTRAP["challenge_id"])
                self.assertEqual(body["submission"], BOOTSTRAP["submission"])
                self.assertFalse((self.archive / "grant.json").exists())
                gateway.send_grant.assert_not_called()
                if len(requests[op]) == 1:
                    raise subprocess.TimeoutExpired(args, 1, output=b'{"version":')
                out = reply("grant", publication="existing", signed_grant_json=list(self.grant))
            else:
                self.assertEqual(body["container_id"], CID)
                self.assertEqual(body["aggregate_json"], POLICY["signed_aggregate"])
                self.assertEqual(body["trust_snapshot_sha384"], hashlib.sha384(b"{}").hexdigest())
                self.assertEqual(body["execution_audience"], "auditor")
                self.assertFalse((self.archive / "plan.json").exists())
                gateway.send_plan.assert_not_called()
                plans.append(signed(run.kube._PLAN_PURPOSE, container_id=CID,
                                    effective_spec_sha384=hashlib.sha384(SPEC).hexdigest(),
                                    trust_snapshot_sha384=body["trust_snapshot_sha384"],
                                    execution_audience="auditor", execution_nonce_hex=f"{len(plans)+1:064x}"))
                if len(plans) == 1:
                    return subprocess.CompletedProcess(args, -9, b"")
                out = reply("startup_plan", signed_plan_json=list(plans[-1]))
            return subprocess.CompletedProcess(args, 0, out)

        worker = mock.Mock(return_value=READBACK)
        with mock.patch.object(run, "_command", side_effect=command), self.assertRaises(EOFError):
            run.kube.drive(gateway, self.authority, worker, expected=EXPECTED, manifest=MANIFEST,
                           references=REFERENCES, effective_spec=SPEC, management_key=MANAGEMENT,
                           archive_directory=self.archive, deadline=self.deadline)
        for op in ("issue", "startup_plan"):
            self.assertEqual(len(requests[op]), 2)
            self.assertEqual(*requests[op])
        self.assertEqual(worker.call_args_list, [mock.call(self.deadline)] * 2)
        self.assertEqual([c.args[-1] for c in self.authority.execute.call_args_list], [self.deadline] * 5)
        self.assertNotEqual(*plans)
        self.assertEqual((self.archive / "grant.json").read_bytes(), self.grant)
        self.assertEqual((self.archive / "plan.json").read_bytes(), plans[1])
        gateway.send_grant.assert_called_once_with(self.grant)
        gateway.send_plan.assert_called_once_with(plans[1], SPEC)

    def test_redeem_lost_after_commit_requests_status_from_same_guest(self):
        aggregate = bytes(POLICY["signed_aggregate"])
        self.authority.grant, self.authority.aggregate, self.authority.plan = self.grant, aggregate, b"plan"
        purpose = "qlad.execution-proof.gcp-issuer-admission-request.v2"
        redeem = signed(purpose, 2, operation="redeem")
        status = signed(purpose, 2, operation="status")
        receipt = signed("qlad.execution-proof.preparation-admission.v1")
        gateway = mock.Mock()
        gateway.request_admission_status.return_value = {"guest_nonce":"nonce", "recorder_request_json":list(status)}
        operations = []
        def command(args, deadline, *, stdin, **kwargs):
            self.assertEqual(deadline, self.deadline)
            request = json.loads(stdin)["request"]
            op = request["operation"]
            operations.append(op)
            if op == "pin_policy_admission":
                out = reply("policy_pinned")
            elif op == "redeem_policy_aggregate":
                self.assertEqual(bytes(request["recorder_request_json"]), redeem)
                raise subprocess.TimeoutExpired(args, 1)
            elif op == "status_policy_aggregate":
                self.assertEqual(bytes(request["recorder_request_json"]), status)
                out = reply("policy_status", signed_authorization_json=list(receipt))
            else:
                self.fail(op)
            return subprocess.CompletedProcess(args, 0, out)
        with mock.patch.object(run, "_command", side_effect=command):
            recovered = run.kube.attempt.admit_pending(self.authority, gateway, self.grant, aggregate,
                         {"guest_nonce":"nonce", "recorder_request_json":list(redeem)}, self.deadline)
        self.assertEqual(recovered, receipt)
        self.assertEqual(operations, ["pin_policy_admission","redeem_policy_aggregate","status_policy_aggregate"])
        gateway.request_admission_status.assert_called_once_with(self.deadline)

    def test_transient_cli_codes_retry_once_and_conflicts_are_terminal(self):
        self.authority.challenge = CHALLENGE
        for code, count in (("request_expired", 1), ("state_rejected", 1), ("journal_unavailable", 2), ("state_busy", 2), ("clock_unavailable", 2)):
            with self.subTest(code=code), mock.patch.object(run, "_command", return_value=
                    subprocess.CompletedProcess([], 1, reply("error", code=code))) as command:
                with self.assertRaises(run.kube.AttemptError):
                    self.authority.issue("fixture", BOOTSTRAP["submission"], self.deadline)
                self.assertEqual(command.call_count, count)

    def test_plan_retry_rejects_changed_inputs_and_a_third_request(self):
        for change in ("cid", "aggregate", "snapshot", "audience", "deadline", "none"):
            with self.subTest(change=change):
                execute = mock.Mock(side_effect=run.cloud.frontend.AuthorityUnavailable("lost"))
                authority = run.cloud.LateCidAuthority(execute, self.authority.signed_intent, b"{}", "auditor")
                authority.grant = self.grant
                aggregate = bytearray(POLICY["signed_aggregate"])
                with self.assertRaises(run.cloud.frontend.AuthorityUnavailable):
                    authority.startup_plan(self.grant, aggregate, CID, self.deadline)
                cid, deadline = CID, self.deadline
                if change == "cid":
                    cid = "0" * 64
                elif change == "aggregate":
                    aggregate.extend(b" ")
                elif change == "snapshot":
                    authority.trust_snapshot_sha384 = "ab" * 48
                elif change == "audience":
                    authority.execution_audience = "another-auditor"
                elif change == "deadline":
                    deadline += 1
                with self.assertRaises(run.kube.AttemptError):
                    authority.startup_plan(self.grant, aggregate, cid, deadline)
                with self.assertRaisesRegex(run.kube.AttemptError, "authority_order"):
                    authority.startup_plan(self.grant, aggregate, cid, deadline)
                self.assertEqual(execute.call_count, 2 if change == "none" else 1)

    def test_deadline_and_changed_worker_stop_plan_retry(self):
        for expired in (False, True):
            with self.subTest(expired=expired), tempfile.TemporaryDirectory() as scratch:
                gateway = mock.Mock()
                gateway.receive_bootstrap.return_value = BOOTSTRAP
                gateway.receive_policy.return_value = POLICY
                gateway.receive_candidate.return_value = CANDIDATE
                worker = mock.Mock(side_effect=[READBACK, replace(READBACK, container_id="0" * 64)])
                now = self.deadline - 1

                def execute(family, operation, raw, deadline):
                    nonlocal now
                    op = json.loads(raw)["request"]["operation"]
                    if op == "begin":
                        return reply("challenge", signed_challenge_json=list(CHALLENGE))
                    if op == "issue":
                        return reply("grant", publication="first_issued", signed_grant_json=list(self.grant))
                    self.assertEqual(op, "startup_plan")
                    if expired:
                        now = deadline
                    raise run.cloud.frontend.AuthorityUnavailable("authority_response_lost")

                authority = run.cloud.LateCidAuthority(mock.Mock(side_effect=execute), self.authority.signed_intent,
                                                      b"{}", "auditor")
                with mock.patch.object(time, "monotonic", side_effect=lambda: now), self.assertRaisesRegex(
                        run.kube.AttemptError, "attempt_deadline" if expired else "worker_selection_changed"):
                    run.kube.drive(gateway, authority, worker, expected=EXPECTED, manifest=MANIFEST,
                                   references=REFERENCES, effective_spec=SPEC, management_key=MANAGEMENT,
                                   archive_directory=Path(scratch) / "archive", deadline=self.deadline)
                self.assertEqual(authority.execute.call_count, 3)
                self.assertEqual(worker.call_count, 1 if expired else 2)
                gateway.send_plan.assert_not_called()
