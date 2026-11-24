import hashlib
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

import yaml

import run as operator
from render import ROOT


class PodIntentInputsTests(unittest.TestCase):
    def setUp(self):
        self.pod = yaml.safe_load((ROOT / "templates/pod.yaml").read_text())
        self.name = "proof-2"
        self.uid = "da918b06-4070-4fd4-bd15-4d57062d7b00"
        self.image = "registry.example.org/proof@sha256:" + "a" * 64
        self.pod["metadata"].update(name=self.name, uid=self.uid, resourceVersion="123")
        self.spec = self.pod["spec"]
        self.app = self.spec["containers"][0]
        self.app.update(image=self.image, resources={}, terminationMessagePolicy="File",
                        terminationMessagePath="/dev/termination-log")
        self.spec.update(securityContext={}, dnsPolicy="ClusterFirst", serviceAccountName="default")
        self.spec["nodeSelector"]["execution-proof-worker"] = "true"
        self.client = Mock()
        self.client.profile = {"workload_image": self.image, "project": "fixture", "zone": "us-central1-a"}
        self.client.config = {"context": "gke_fixture_us-central1-a_cluster"}
        self.client.pod.return_value = self.pod

    def select(self):
        return operator.select_pod_inputs(self.client, self.name, 30)

    def test_persisted_pod_selects_exact_inputs(self):
        result = self.select()
        self.client.pod.assert_called_once_with(30, self.name)
        self.assertEqual((result["pod_uid"], result["resource_version"], result["container_name"],
                          result["attempt"], result["selected_manifest_sha256"]),
                         (self.uid, "123", "workload", 0, "a" * 64))
        wire = result["effective_spec"].encode()
        self.assertIn("HOSTNAME=proof-2", json.loads(wire)["process"]["env"])
        self.assertEqual(result["effective_launch_sha384"], hashlib.sha384(wire).hexdigest())
        self.name = self.pod["metadata"]["name"] = "proof-1"
        self.assertEqual(self.select()["effective_spec"].encode(),
                         (ROOT / "templates/pod-effective-spec.example.json").read_bytes())

    def test_cli_reads_only_the_named_pod(self):
        config = dict(self.client.config, kubeconfig="/private/kubeconfig", deadline_seconds=30)
        output = io.StringIO()
        argv = ["run.py", "select-intent-inputs", "deployment", __file__, "--pod-name", self.name]
        with (
            patch("sys.argv", argv),
            patch.object(operator, "read_profile", return_value=self.client.profile),
            patch.object(operator.serial, "_regular", return_value=json.dumps(config).encode()),
            patch.object(operator, "run", return_value=json.dumps(self.pod).encode()) as run,
            patch.object(operator.os, "umask"),
            patch.object(operator.resource, "setrlimit"),
            redirect_stdout(output),
        ):
            self.assertEqual(operator.main(), 0)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0], [
            "kubectl", "--kubeconfig", config["kubeconfig"], "--context", config["context"],
            "-n", "execution-proof", "get", "pod", self.name, "-o", "json"])
        self.assertEqual(json.loads(output.getvalue()), self.select())

    def test_missing_uid(self):
        del self.pod["metadata"]["uid"]
        with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, "pod_identity"):
            self.select()

    def test_requires_current_pod_identity(self):
        for field, value in (("namespace", "other"), ("name", "proof-3"),
                             ("deletionTimestamp", "2026-01-01T00:00:00Z"), ("resourceVersion", "")):
            with self.subTest(field=field), patch.dict(self.pod["metadata"], {field: value}):
                with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, "pod_identity"):
                    self.select()
        self.pod["status"] = {"phase": "Succeeded"}
        with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, "pod_phase"):
            self.select()

    def test_requires_the_selected_encrypted_manifest(self):
        for image in ("registry.example.org/proof:latest", self.image[:-1] + "b"):
            with self.subTest(image=image):
                self.app["image"] = image
                with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, "pod_image"):
                    self.select()

    def test_workload_overrides_rejected(self):
        for field, value in (("command", ["/other"]), ("args", ["extra"]), ("env", []),
                             ("volumeMounts", [{"name": "extra", "mountPath": "/work"}]),
                             ("securityContext", {})):
            with self.subTest(field=field), patch.dict(self.app, {field: value}):
                with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, "container_profile"):
                    self.select()

    def test_requires_first_gated_start(self):
        for field, value in (("containers", [self.app, self.app]),
                             ("schedulingGates", []), ("nodeName", "worker"),
                             ("restartPolicy", "Always"), ("hostname", "other"),
                             ("initContainers", [self.app])):
            with self.subTest(field=field), patch.dict(self.spec, {field: value}):
                with self.assertRaises(operator.cloud.protocol.AttemptError):
                    self.select()

    def prepare_schedule(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.receipt = Path(directory) / "receipt.json"
        self.client.config.update(pod_receipt=str(self.receipt), intent_cluster_id="cluster")
        self.client.image_id = 123
        self.enterContext(patch.object(operator, "boot_artifacts", return_value=({}, {"boot_config": b"boot"})))
        statement = {"attempt_id": "attempt", "workload_id": "workload",
                     "validity": {"not_before": 0, "expires": int(time.time()) + 60}}
        self.issuance = self.enterContext(patch.object(
            operator, "committed_pod_intent", return_value=(json.dumps({"statement": statement}).encode(), "q")))

    def schedule(self):
        return operator.schedule_pod_intent(self.client, self.name, self.uid, time.monotonic() + 30)

    def test_replaced_pod_stops_pending_event_and_restart(self):
        self.prepare_schedule()

        def replace(*_):
            self.pod["metadata"]["uid"] = "42d640d5-cb09-4baa-b9f1-ec7885388028"
            raise operator.subprocess.TimeoutExpired("kubectl", 1)

        self.client.k.side_effect = replace
        for _ in range(2):
            with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, "expected_gated_pod"):
                self.schedule()
        self.assertEqual(json.loads(self.receipt.read_bytes())["pod_uid"], self.uid)
        self.client.k.assert_called_once()
        self.issuance.assert_called_once()

    def test_changed_workload_rejected_on_gate_readback(self):
        self.prepare_schedule()

        def change(*_):
            self.app["command"] = ["/other"]
            self.pod["metadata"]["resourceVersion"] = "124"
            raise operator.subprocess.TimeoutExpired("kubectl", 1)

        self.client.k.side_effect = change
        with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, "container_profile"):
            self.schedule()
        self.client.k.assert_called_once()
        self.issuance.assert_called_once()

    def test_open_gate_without_schedule_receipt_is_rejected(self):
        self.prepare_schedule()
        del self.spec["schedulingGates"]
        with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, "missing_schedule_receipt"):
            self.schedule()
        self.client.k.assert_not_called()
        self.issuance.assert_not_called()

    def test_receipt_with_different_intent_is_rejected(self):
        self.prepare_schedule()
        self.schedule()
        del self.spec["schedulingGates"]
        receipt = json.loads(self.receipt.read_bytes())
        self.receipt.write_text(json.dumps(dict(receipt, signed_intent_sha384="0" * 96)))
        with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, "scheduled_pod_receipt"):
            self.schedule()
        self.assertTrue(self.issuance.call_args.kwargs["existing_only"])
        self.client.k.assert_called_once()

    def test_intent_expired_before_patch(self):
        self.prepare_schedule()
        wire, q_hash = self.issuance.return_value
        envelope = json.loads(wire)
        envelope["statement"]["validity"]["expires"] = int(time.time())
        self.issuance.return_value = json.dumps(envelope).encode(), q_hash
        with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, "tenant_intent_window"):
            self.schedule()
        self.client.k.assert_not_called()

    def test_automatic_receipt_requires_event_uid_for_launch(self):
        self.prepare_schedule()
        self.schedule()
        with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, "launch_event_uid_required"):
            operator.launch(self.client, self.client.config, {}, {}, time.monotonic() + 30)
        self.client.pod_target.assert_not_called()
