import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import prepare_management_key
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

    def test_restarted_container_cannot_reuse_first_start_intent(self):
        self.pod["status"] = {"phase": "Running", "containerStatuses": [{"name": "workload", "restartCount": 1}]}
        self.spec.pop("schedulingGates")
        with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, "pod_start_number"):
            operator.pod_intent_inputs(self.client, self.name, self.pod, gate_open=True)

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
        self.client.config.update(pod_receipt=str(self.receipt), intent_cluster_id="cluster", launch_queue=directory)
        self.client.image_id = 123
        self.enterContext(patch.object(operator, "boot_artifacts", return_value=({}, {"boot_config": b"boot"})))
        statement = {"attempt_id": "attempt", "workload_id": "workload",
                     "validity": {"not_before": 0, "expires": int(time.time()) + 60}}
        self.issuance = self.enterContext(patch.object(
            operator, "committed_pod_intent", return_value=(json.dumps({"statement": statement}).encode(), "q")))

    def schedule(self):
        deadline = time.monotonic() + 30
        operator.schedule_pod_intent(self.client, self.name, self.uid, deadline)
        return operator.reconcile_pod_intent(self.client, self.name, self.uid, deadline, before_patch=lambda _: None)

    def test_missing_queue_and_failed_readiness_preserve_gate(self):
        self.prepare_schedule()
        deadline = time.monotonic() + 30
        with patch.dict(self.client.config):
            del self.client.config["launch_queue"]
            with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, "launch_queue_required"):
                operator.schedule_pod_intent(self.client, self.name, self.uid, deadline)
        self.assertFalse(self.receipt.exists())
        operator.schedule_pod_intent(self.client, self.name, self.uid, deadline)
        queue = operator.LaunchQueue(self.receipt.parent)
        receipt = queue.next_ready("cluster")
        self.assertEqual(receipt, json.loads(self.receipt.read_bytes()))
        with patch.object(operator, "worker_ready", side_effect=operator.cloud.protocol.AttemptError("worker_unavailable")), patch.object(operator, "launch") as launch:
            with self.assertRaisesRegex(operator.cloud.protocol.AttemptError, "worker_unavailable"):
                operator.queued_launch(self.client, self.client.config, {}, {}, deadline,
                                       name=self.name, uid=self.uid)
            launch.assert_not_called()
        self.client.k.assert_not_called()
        self.assertEqual(self.spec["schedulingGates"], [{"name": operator.GATE}])
        self.assertIsNone(queue.next_ready("cluster"))

    def test_collector_transport_is_not_a_launch_readiness_dependency(self):
        self.spec["nodeSelector"]["kubernetes.io/hostname"] = "worker"
        worker = {"metadata": {"uid": "node-uid", "labels": {"kubernetes.io/hostname": "worker"}},
                  "spec": {"providerID": "gce://fixture/us-central1-a/worker"}}
        self.client.k.side_effect = [json.dumps(worker), '{"items":[]}']
        self.client.scope.zone = "us-central1-a"
        config = {"worker": {"uid": "node-uid", "provider_id": worker["spec"]["providerID"]},
                  "collector_tls": "/private/collector.json", "binding": "/private/binding.json",
                  "serial_host_public_keys": "/public/serial.keys", "serial_host_public_sha384": "pin",
                  "profile_probe": "/private/profile-probe"}
        receipt = {"pod_name": self.name, "pod_uid": self.uid, "attempt_id": "attempt", "q_sha384": "q"}
        endpoint = Mock()
        endpoint.connection.side_effect = OSError("collector offline")
        with tempfile.TemporaryDirectory() as directory:
            known = Path(directory) / "known_hosts"
            known.write_bytes(b"serial-host-key\n")
            with (
                patch.object(operator.archive_delivery, "Endpoint", return_value=endpoint) as create_endpoint,
                patch.object(operator.serial, "prepare_known_hosts", return_value=(known, None)),
                patch.object(operator, "management_key"),
                patch.object(operator, "document", return_value={"boot_binding": {}}),
                patch.object(operator, "boot_digest", return_value="boot"),
                patch.object(operator, "binary", return_value=json.dumps({
                    "attempt_id": "attempt", "q_sha384": "q", "boot_binding_sha384": "boot",
                    "authority_checked": True, "kbs_checked": True})),
                patch.object(operator, "worker_command", return_value=["guard", "ready", self.uid]) as guard,
                patch.object(operator, "run", return_value=known.read_bytes()),
            ):
                operator.worker_ready(self.client, config, receipt, time.monotonic() + 30)
        create_endpoint.assert_called_once_with(Path(config["collector_tls"]))
        endpoint.connection.assert_not_called()
        guard.assert_called_once_with(config, "single_guest", "ready", self.uid)

    @unittest.skipUnless((os.geteuid(), os.getegid()) == (0, 0), "requires the launch service UID and GID")
    def test_prepared_management_key_matches_launcher_and_wrong_owner_keeps_gate_closed(self):
        self.prepare_schedule()
        self.spec["nodeSelector"]["kubernetes.io/hostname"] = "worker"
        directory = self.receipt.parent
        key = directory / "management-server-key.pem"
        pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        key.write_bytes(pem)
        key.chmod(0o640)
        with self.assertRaisesRegex(ValueError, "owner-only"):
            prepare_management_key.prepare(key)
        key.chmod(0o600)
        os.chown(key, 999, 999)
        known = directory / "known_hosts"
        known.write_bytes(b"serial-host-key\n")
        binding = directory / "binding.json"
        binding.write_text('{"boot_binding":{}}')
        config = self.client.config
        provider_id = "gce://fixture/us-central1-a/worker"
        config.update(management_key=str(key), collector_tls="/private/collector.json",
                      binding=str(binding), serial_host_public_keys="/public/serial.keys",
                      serial_host_public_sha384="pin", profile_probe="/private/profile-probe",
                      worker={"uid": "node-uid", "provider_id": provider_id})
        self.client.scope.zone = "us-central1-a"
        node = {"metadata": {"uid": "node-uid", "labels": {"kubernetes.io/hostname": "worker"}},
                "spec": {"providerID": provider_id}}
        self.client.k.side_effect = [json.dumps(node), '{"items":[]}', json.dumps(node), '{"items":[]}']
        deadline = time.monotonic() + 30
        operator.schedule_pod_intent(self.client, self.name, self.uid, deadline)
        receipt = json.loads(self.receipt.read_bytes())
        with (
            patch.object(operator.archive_delivery, "Endpoint"),
            patch.object(operator.serial, "prepare_known_hosts", return_value=(known, None)),
            patch.object(operator, "boot_digest", return_value="boot"),
            patch.object(operator, "binary", return_value=json.dumps({
                "attempt_id": receipt["attempt_id"], "q_sha384": receipt["q_sha384"],
                "boot_binding_sha384": "boot", "authority_checked": True, "kbs_checked": True})),
            patch.object(operator, "worker_command", return_value=["guard", "ready", self.uid]) as guard,
            patch.object(operator, "run", return_value=known.read_bytes()),
            patch.object(operator, "launch") as launch,
        ):
            with self.assertRaisesRegex(operator.serial.GatewayError, "operator_file"):
                operator.queued_launch(self.client, config, {}, {}, deadline, name=self.name, uid=self.uid)
            self.assertEqual(self.spec["schedulingGates"], [{"name": operator.GATE}])
            self.assertEqual([call.args[0][0] for call in self.client.k.call_args_list], ["get", "-n"])
            guard.assert_not_called()
            launch.assert_not_called()

            subprocess.check_call([sys.executable, "-B", prepare_management_key.__file__, str(key)])
            info = key.stat()
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (0, 0, 0o600))
            self.assertEqual(key.read_bytes(), pem)
            operator.worker_ready(self.client, config, receipt, deadline)
            guard.assert_called_once_with(config, "single_guest", "ready", self.uid)

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
        self.assertEqual(self.issuance.call_count, 2)

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
        self.assertEqual(self.issuance.call_count, 2)

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
