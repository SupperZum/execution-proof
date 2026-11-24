import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, nullcontext
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import yaml

import run as operator
import tenant_intent
from render import ROOT


class IntentIssuanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = self.root / "state"
        self.store.mkdir(mode=0o700)
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.inputs = dict(namespace="execution-proof", pod_uid="da918b06-4070-4fd4-bd15-4d57062d7b00",
                           pod_name="proof-1", container_name="workload", attempt=0,
                           resource_version="1", context="gke_fixture_us-central1-a_cluster",
                           image_ref="registry.example.org/app@sha256:" + "a" * 64)
        self.fields = dict(audience="app", authority="authority", tenant="tenant",
                           container_role="application-init", profile_sha384="0" * 96,
                           launch_policy_sha384="1" * 96, image_policy_sha384="2" * 96,
                           selected_manifest_sha256="a" * 64, effective_launch_sha384="3" * 96)
        self.q_expires = int(time.time()) + 600
        self.prefix = "normal-fixture-"
        self.sign_calls = 0

    def sign(self, statement):
        self.sign_calls += 1
        signature = self.key.sign(tenant_intent.signed_intent_bytes(statement))
        return json.dumps(dict(statement=statement, signature=signature.hex())).encode()

    def issue(self, sign=None):
        return tenant_intent.issue_once(self.store, "cluster", self.inputs, self.fields, self.public,
                                       "4" * 96, self.q_expires, 60, time.monotonic() + 10,
                                       self.sign if sign is None else sign, normal_namespace=self.prefix)

    def test_metadata_retry_and_replacement(self):
        first = self.issue()
        self.inputs["resource_version"] = "2"
        self.assertEqual(self.issue(), first)
        self.inputs["pod_uid"] = "42d640d5-cb09-4baa-b9f1-ec7885388028"
        second = self.issue()
        for key in ("attempt_id", "workload_id"):
            self.assertNotEqual(json.loads(first)["statement"][key], json.loads(second)["statement"][key])
        for wire in (first, second):
            statement = tenant_intent.verified_statement(wire, self.public)
            for field in ("workload_id", "attempt_id"):
                self.assertRegex(statement[field], "^normal-fixture-[0-9a-f]{32}$")
        self.assertEqual(self.sign_calls, 2)

    def test_invalid_namespace_stops_before_signing(self):
        for prefix in (None, "", "qexp-test-", "bad/", "é", "x" * 97):
            with self.subTest(prefix=prefix), self.assertRaisesRegex(
                    operator.cloud.protocol.AttemptError, "^intent_normal_namespace$"):
                self.prefix = prefix
                self.issue()
        self.assertEqual(self.sign_calls, 0)

    def test_recovery_preserves_receipts_with_incompatible_ids(self):
        original = json.loads(self.issue())["statement"]
        with closing(sqlite3.connect(self.store / "attempts.sqlite")) as db:
            for field in ("workload_id", "attempt_id"):
                for invalid in ("a" * 32, "other-attempt", self.prefix, self.prefix + "/"):
                    with self.subTest(field=field, invalid=invalid):
                        wire = self.sign(dict(original, **{field: invalid}))
                        record = (wire, operator.hash384(wire))
                        db.execute("UPDATE attempts SET wire=?, wire_sha384=?", record)
                        db.commit()
                        with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, "^intent_receipt_namespace$"):
                            self.issue(sign=Mock(side_effect=AssertionError("unexpected reissue")))
                        self.assertEqual(db.execute("SELECT wire, wire_sha384 FROM attempts").fetchall(), [record])

    def test_conflict_and_expiry_preserve_original(self):
        original = self.issue()
        with patch.dict(self.fields, image_policy_sha384="b" * 96):
            with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, "intent_request_conflict"):
                self.issue()
        expires = json.loads(original)["statement"]["validity"]["expires"]
        with patch.object(time, "time", return_value=expires):
            with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, "tenant_intent_window"):
                self.issue()
        self.assertEqual(self.sign_calls, 1)

    def test_concurrent_requests_only_sign_once(self):
        start = threading.Barrier(2)

        def request():
            start.wait(timeout=5)
            return self.issue()

        with ThreadPoolExecutor(max_workers=2) as workers:
            first, second = [workers.submit(request) for _ in range(2)]
            self.assertEqual(first.result(), second.result())
        self.assertEqual(self.sign_calls, 1)

    def test_corrupt_wire_is_rejected_without_reissuing(self):
        self.issue()
        with closing(sqlite3.connect(self.store / "attempts.sqlite")) as db:
            db.execute("UPDATE attempts SET wire=?", (b"{}",))
            db.commit()
        with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, "intent_receipt_digest"):
            self.issue()
        self.assertEqual(self.sign_calls, 1)

    def test_interrupted_transaction_and_mismatched_statement(self):
        def interrupted(statement):
            self.sign(statement)
            raise OSError("signer interrupted")

        with self.assertRaises(OSError):
            self.issue(interrupted)

        def wrong_statement(statement):
            return self.sign(dict(statement, attempt_id="another-attempt"))

        with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, "intent_signer_result"):
            self.issue(wrong_statement)
        wire = self.issue()
        with closing(sqlite3.connect(self.store / "attempts.sqlite")) as db:
            self.assertEqual(db.execute("SELECT wire FROM attempts").fetchall(), [(wire,)])

    def prepare_cli(self):
        signer = self.root / "intent-signer"
        shutil.copyfile(Path(os.environ["GKE_INTENT_SIGNER_BIN"]).resolve(strict=True), signer)
        signer.chmod(0o700)

        def write(name, value):
            file = self.root / name
            file.write_bytes(json.dumps(value).encode())
            file.chmod(0o600)
            return str(file)

        def pin(file):
            return {"path": str(file), "sha384": operator.hash384(file.read_bytes())}

        target = yaml.safe_load((ROOT / "templates/pod.yaml").read_text())
        target["metadata"].update(uid=self.inputs["pod_uid"], resourceVersion="42")
        target["spec"]["containers"][0]["image"] = self.inputs["image_ref"]
        pod_file = write("pod.json", target)
        kubectl = self.root / "kubectl"
        kubectl.write_text(f'#!/bin/sh\nexec /bin/cat "{pod_file}"\n')
        kubectl.chmod(0o700)
        deployment = json.loads((ROOT / "deployment.example.json").read_bytes())
        deployment.update(project="fixture", network="fixture-net", subnet="fixture-subnet",
                          workload_image=self.inputs["image_ref"])
        boot = write("boot.json", {"roots": {"qualification_public_key": list(self.public)}})
        binding = dict(version=1, purpose="qlad.execution-proof.gcp-boot-binding.v1",
                       profile="onb17.gcp-tdx-embedded-pe.v1",
                       **{key: "0" * 96 for key in operator.BOOT_FIELDS})
        binding["config_sha384"] = operator.hash384(Path(boot).read_bytes())
        artifacts = {}
        for field, name in zip(operator.BOOT_FIELDS[1:], ("producer_core", "manifest", "references")):
            artifacts[name] = write(name + ".json", {"kind": name})
            binding[field] = operator.hash384(Path(artifacts[name]).read_bytes())
        q = {"statement": {"boot_binding_sha384": operator.boot_digest(binding),
                           "validity": {"not_before": int(time.time()) - 1, "expires": self.q_expires}}}
        # Only the qualification checker and Kubernetes API are test doubles.
        checker = self.root / "check-q"
        checker.write_text('#!/bin/sh\n[ "$1" = check-signed ]\n')
        checker.chmod(0o700)
        private = self.root / "tenant.pk8"
        seed = self.key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                      serialization.NoEncryption())
        private.write_bytes(bytes.fromhex("3051020101300506032b657004220420") + seed
                            + bytes.fromhex("812100") + self.public)
        private.chmod(0o600)
        public = self.root / "tenant.pub"
        public.write_bytes(self.public)
        public.chmod(0o600)
        issuer = dict(self.fields, boot_binding=binding, tenant_public_key=list(self.public))
        config = dict(context=self.inputs["context"], kubeconfig=str(self.root / "kubeconfig"),
                      deadline_seconds=30, intent_cluster_id="cluster", intent_store=str(self.store),
                      intent_ttl_seconds=60, tenant_key=str(private), tenant_public_key=str(public),
                      intent_signer=pin(signer), issuer_config=write("issuer.json", issuer),
                      binding=write("binding.json", {"boot_binding": binding}), boot_config=boot,
                      signed_q=write("q.json", q), qualification_checker=pin(checker),
                      qualification_public_key=str(public), evidence_dir=str(self.root),
                      selection=write("selection.json", {"normal_namespace": self.prefix,
                                                        "expected": {"qualification_public_key": list(self.public)}}))
        config.update(artifacts, pod_receipt=str(self.root / "receipt.json"), image_id="123")
        args = [sys.executable, "-B", str(ROOT / "tools/controller/run.py"), "issue-intent",
                write("deployment.json", deployment), write("operator.json", config)]
        env = dict(os.environ, PATH=str(self.root) + ":" + os.environ["PATH"])
        return args, env

    @unittest.skipUnless(os.environ.get("GKE_INTENT_SIGNER_BIN"), "requires built prototype signer")
    def test_two_cli_processes_and_process_restart_with_rust_signer(self):
        args, env = self.prepare_cli()
        with subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as one, \
             subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as two:
            first, err = one.communicate(timeout=15)
            self.assertEqual(one.returncode, 0, err)
            second, err = two.communicate(timeout=15)
            self.assertEqual(two.returncode, 0, err)
        self.assertEqual(second, first)
        # Recovery must not need the signing key or mint another signature.
        (self.root / "tenant.pk8").unlink()
        recovered = subprocess.run(args, env=env, capture_output=True, check=True, timeout=15)
        self.assertEqual(recovered.stdout, first)
        statement = tenant_intent.verified_statement(first, self.public)
        self.assertEqual(statement["selected_manifest_sha256"], self.fields["selected_manifest_sha256"])
        for field in ("workload_id", "attempt_id"):
            self.assertTrue(statement[field].startswith(self.prefix))
        with closing(sqlite3.connect(self.store / "attempts.sqlite")) as db:
            self.assertEqual(db.execute("SELECT wire FROM attempts").fetchall(), [(first,)])

    @unittest.skipUnless(os.environ.get("GKE_INTENT_SIGNER_BIN"), "requires built prototype signer")
    def test_schedule_cli_recovers_both_patch_outcomes(self):
        args, env = self.prepare_cli()
        args[3] = "schedule"
        args.extend(["--pod-uid", self.inputs["pod_uid"]])
        gcloud = self.root / "gcloud"
        gcloud.write_text("""#!/bin/sh
case "$*" in
    *"projects describe"*) echo 1234 ;;
    *"images describe"*) echo '{"id":"123","status":"READY","guestOsFeatures":[{"type":"TDX_CAPABLE"}]}' ;;
    *) exit 1 ;;
esac
""")
        gcloud.chmod(0o700)
        kubectl = self.root / "kubectl"
        kubectl.write_text("""#!/usr/bin/python3
import hashlib, json, sqlite3, sys
from pathlib import Path

root = Path(__file__).parent
file = root / "pod.json"
pod = json.loads(file.read_bytes())
if "get" in sys.argv:
    print(json.dumps(pod))
elif "patch" in sys.argv:
    receipt = json.loads((root / "receipt.json").read_bytes())
    assert receipt["pod_uid"] == pod["metadata"]["uid"]
    with sqlite3.connect(root / "state/attempts.sqlite") as db:
        [(wire,)] = db.execute("SELECT wire FROM attempts").fetchall()
    assert hashlib.sha384(wire).hexdigest() == receipt["signed_intent_sha384"]
    operations = json.loads(sys.argv[-1])
    assert operations == [
        {"op": "test", "path": "/metadata/uid", "value": pod["metadata"]["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion", "value": pod["metadata"]["resourceVersion"]},
        {"op": "test", "path": "/spec/schedulingGates", "value": pod["spec"]["schedulingGates"]},
        {"op": "test", "path": "/spec/containers/0/image", "value": pod["spec"]["containers"][0]["image"]},
        {"op": "remove", "path": "/spec/schedulingGates/0"}]
    with (root / "patches").open("a") as log:
        print(pod["metadata"]["resourceVersion"], receipt["signed_intent_sha384"], file=log)
    if pod["metadata"]["resourceVersion"] == "42":
        # API advanced metadata before the first patch was applied.
        pod["metadata"]["resourceVersion"] = "43"
    else:
        # The second patch took effect, but its acknowledgement was lost.
        del pod["spec"]["schedulingGates"]
        pod["spec"]["nodeName"] = "worker"
        pod["status"] = {"phase": "Running"}
        pod["metadata"]["resourceVersion"] = "44"
    file.write_text(json.dumps(pod))
    sys.exit(1)
else:
    sys.exit(2)
""")
        result = subprocess.run(args, env=env, capture_output=True, check=True, timeout=15)
        scheduled = json.loads(result.stdout)
        (self.root / "tenant.pk8").unlink()
        restarted = subprocess.run(args, env=env, capture_output=True, check=True, timeout=15)
        self.assertEqual(result.stdout, restarted.stdout)
        with closing(sqlite3.connect(self.store / "attempts.sqlite")) as db:
            [(wire,)] = db.execute("SELECT wire FROM attempts").fetchall()
        digest = operator.hash384(wire)
        self.assertEqual(scheduled, {"scheduled": True, "pod_uid": self.inputs["pod_uid"],
                                     "attempt_id": json.loads(wire)["statement"]["attempt_id"],
                                     "signed_intent_sha384": digest})
        self.assertEqual((self.root / "patches").read_text().splitlines(), ["42 " + digest, "43 " + digest])
        with closing(sqlite3.connect(self.store / "attempts.sqlite")) as db:
            db.execute("DELETE FROM attempts")
            db.commit()
        missing = subprocess.run(args, env=env, capture_output=True, timeout=15)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn(b"missing_committed_intent", missing.stderr)
        self.assertEqual(missing.stdout, b"")
        self.assertEqual((self.root / "patches").read_text().splitlines(), ["42 " + digest, "43 " + digest])

    def schedule_launch_pod(self, files, name, uid):
        deployment_file, base_config = files
        config = json.loads(Path(base_config).read_bytes())
        directory = self.root / uid
        directory.mkdir()
        issuer = directory / "issuer.json"
        shutil.copyfile(config["issuer_config"], issuer)
        config.update(issuer_config=str(issuer), pod_receipt=str(directory / "receipt.json"),
                      trust_snapshot=str(directory / "snapshot.json"), execution_audience="aud",
                      archive=str(directory / "archive"), unit="fixture.service")
        operator_file = directory / "operator.json"
        operator_file.write_text(json.dumps(config))
        pod = json.loads((self.root / "pod.json").read_bytes())
        pod["metadata"].update(name=name, uid=uid)
        client = Mock(config=config, profile=json.loads(Path(deployment_file).read_bytes()), image_id=123)
        client.pod.return_value = pod
        deadline = time.monotonic() + 30
        operator.schedule_pod_intent(client, name, uid, deadline)
        client.k.assert_called_once()
        self.assertEqual(client.k.call_args.args[0][:5], ["-n", operator.NAMESPACE, "patch", "pod", name])
        del pod["spec"]["schedulingGates"]
        pod["spec"]["nodeName"] = "worker"
        identity = json.dumps([config["intent_cluster_id"], operator.NAMESPACE, uid, "workload", 0])
        with closing(sqlite3.connect(self.store / "attempts.sqlite")) as db:
            [(wire,)] = db.execute("SELECT wire FROM attempts WHERE identity=?", (identity,)).fetchall()
        return client, [deployment_file, str(operator_file)], name, uid, wire

    def scheduled_launch_fixture(self):
        self.addCleanup(os.umask, os.umask(0o077))
        args, _ = self.prepare_cli()
        pod = self.schedule_launch_pod(args[4:], "proof-2", self.inputs["pod_uid"])
        (self.root / "tenant.pk8").unlink()
        return pod

    @unittest.skipUnless(os.environ.get("GKE_INTENT_SIGNER_BIN"), "requires built prototype signer")
    def test_automatic_launch_sends_committed_wire_in_begin(self):
        self.check_launch_begin(*self.scheduled_launch_fixture())

    def check_launch_begin(self, client, files, name, uid, wire, *, foreign_receipt=False, instance_id=41):
        config = client.config
        target = operator.cloud.PodTarget(operator.cloud.Scope("fixture", "us-central1-a", 1234),
            operator.NAMESPACE, name, operator.kube.ExpectedPod(uid, "workload", 0, self.inputs["image_ref"]),
            "worker", "peer-uid", f"podvm-{name}-abcdef12", instance_id, 123)
        client.pod_target.return_value = target
        for key, extra in (("selection", {"retired_instance_id": "40"}),
                           ("issuer_config", {"boot_policy": {"expected_instance": target.gce_identity()}})):
            Path(config[key]).write_text(json.dumps(operator.document(config, key) | extra))

        class BeginReceived(Exception):
            pass

        def execute(family, operation, raw, deadline):
            self.assertEqual(family, "normal")
            if operation == "init":
                return json.dumps({"version": 1, "purpose": "qlad.execution-proof.gcp-authority-response.v1",
                                   "result": {"status": "initialized"}}).encode()
            self.assertEqual(operation, "request")
            request = json.loads(raw)["request"]
            self.assertEqual(request["operation"], "begin")
            self.assertEqual(bytes(request["signed_intent_json"]), wire)
            raise BeginReceived

        def drive(gateway, authority, read_worker, *, effective_spec, **kwargs):
            self.assertIn(f"HOSTNAME={name}", json.loads(effective_spec)["process"]["env"])
            self.assertEqual(operator.hash384(effective_spec),
                             tenant_intent.verified_statement(wire, self.public)["effective_launch_sha384"])
            authority.bootstrap(kwargs["deadline"])

        with (
            patch.object(sys, "argv", ["run.py", "launch", *files, "--pod-name", name, "--pod-uid", uid]),
            patch.object(operator.no_swap_guard, "verify"), patch.object(operator.serial, "_LIBC"),
            patch.object(operator.resource, "setrlimit"), patch.object(operator, "Clients", return_value=client),
            patch.object(operator, "executor", return_value=execute) as executor, patch.object(operator, "worker_pin"),
            patch.object(operator, "heartbeat", return_value=nullcontext()), patch.object(operator, "serial_config",
                return_value=nullcontext()), patch.object(operator, "management_key", return_value=nullcontext()),
            patch.object(operator.cloud, "GceSerial", return_value=nullcontext()),
            patch.object(operator.kube, "drive", side_effect=drive), patch("builtins.print"),
        ):
            operator.serial._LIBC.prctl.return_value = 0
            if foreign_receipt:
                with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, "^scheduled_pod_receipt$"):
                    operator.main()
                executor.assert_not_called()
                return
            with self.assertRaises(BeginReceived):
                operator.main()
        self.assertEqual(client.pod_target.call_args.args[2], name)
        snapshot = operator.document(config, "trust_snapshot")
        self.assertEqual((snapshot["pod_uid"], snapshot["signed_intent_sha384"]), (uid, operator.hash384(wire)))

    @unittest.skipUnless(os.environ.get("GKE_INTENT_SIGNER_BIN"), "requires built prototype signer")
    def test_automatic_launch_rejects_substitutions_before_authority(self):
        client, _, name, uid, wire = self.scheduled_launch_fixture()
        config = client.config
        pod = client.pod.return_value
        receipt_path = Path(config["pod_receipt"])
        receipt = json.loads(receipt_path.read_bytes())
        binding, values = operator.boot_artifacts(config)
        alternate = "42d640d5-cb09-4baa-b9f1-ec7885388028"

        def rejected(label):
            with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, label):
                operator.launch(client, config, binding, values, time.monotonic() + 30, name=name, uid=uid)

        with patch.object(operator.cloud, "LateCidAuthority") as authority:
            for key, value in (("pod_uid", alternate), ("signed_intent_sha384", "0" * 96),
                               ("effective_launch_sha384", "0" * 96), ("attempt_id", "another-attempt")):
                with self.subTest(field=key):
                    receipt_path.write_text(json.dumps(dict(receipt, **{key: value})))
                    rejected("scheduled_pod_receipt")
            receipt_path.write_text(json.dumps(receipt))
            with patch.dict(pod["metadata"], uid=alternate):
                rejected("pod_identity")
            with patch.dict(pod["spec"]["containers"][0], command=["/other"]):
                rejected("container_profile")
            with patch.dict(pod["spec"], schedulingGates=[{"name": operator.GATE}]):
                rejected("expected_open_gate")
            templates = self.root / "templates"
            templates.mkdir()
            shutil.copyfile(ROOT / "templates/pod.yaml", templates / "pod.yaml")
            spec = (ROOT / "templates/pod-effective-spec.example.json").read_bytes()
            (templates / "pod-effective-spec.example.json").write_bytes(spec + b"\n")
            with patch.object(operator, "ROOT", self.root):
                rejected("intent_request_conflict")
            # Another valid signature for the same workload cannot replace the scheduled attempt.
            other = self.sign(dict(json.loads(wire)["statement"], attempt_id=self.prefix + "0" * 32))
            with closing(sqlite3.connect(self.store / "attempts.sqlite")) as db:
                db.execute("UPDATE attempts SET wire=?, wire_sha384=?", (other, operator.hash384(other)))
                db.commit()
                rejected("scheduled_pod_receipt")
                db.execute("DELETE FROM attempts")
                db.commit()
            rejected("missing_committed_intent")
            authority.assert_not_called()
            client.pod_target.assert_not_called()

    @unittest.skipUnless(os.environ.get("GKE_INTENT_SIGNER_BIN"), "requires built prototype signer")
    def test_three_pods_accept_only_their_own_scheduling_receipt(self):
        self.addCleanup(os.umask, os.umask(0o077))
        args, _ = self.prepare_cli()
        uids = [self.inputs["pod_uid"], "42d640d5-cb09-4baa-b9f1-ec7885388028",
                "a475cf37-8769-48c4-ad35-219d120c3c72"]
        pods = [self.schedule_launch_pod(args[4:], f"proof-{i}", uid) for i, uid in enumerate(uids, 1)]
        (self.root / "tenant.pk8").unlink()
        originals = {}
        for client, _, name, uid, wire in pods:
            raw = Path(client.config["pod_receipt"]).read_bytes()
            receipt = json.loads(raw)
            statement = tenant_intent.verified_statement(wire, self.public)
            self.assertEqual((receipt["pod_uid"], receipt["signed_intent_sha384"]), (uid, operator.hash384(wire)))
            for field in ("attempt_id", "workload_id"):
                self.assertEqual(receipt[field], statement[field])
            originals[name] = raw
        for field in ("attempt_id", "workload_id"):
            self.assertEqual(len({json.loads(raw)[field] for raw in originals.values()}), 3)

        for instance_id, pod in enumerate(pods, 41):
            client, _, name, _, _ = pod
            path = Path(client.config["pod_receipt"])
            for source_name, original in originals.items():
                with self.subTest(event=name, receipt=source_name):
                    path.write_bytes(original)
                    self.check_launch_begin(*pod, foreign_receipt=source_name != name, instance_id=instance_id)
            path.write_bytes(originals[name])
        with closing(sqlite3.connect(self.store / "attempts.sqlite")) as db:
            self.assertCountEqual(db.execute("SELECT wire FROM attempts").fetchall(),
                                  [(wire,) for _, _, _, _, wire in pods])
