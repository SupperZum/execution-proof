import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import kubernetes_gcp_serial as gcp
import run as operator
import serial_gateway as serial


class ProjectBindingTests(unittest.TestCase):
    def setUp(self):
        self.scope = gcp.Scope("fixture-proof", "europe-west4-a", 1234)
        self.root = "https://www.googleapis.com/compute/v1/projects/fixture-proof/zones/europe-west4-a"
        self.uid = "439da190-b8db-48bb-b3f0-aec56ff8abf4"
        self.image = "example.invalid/proof@sha256:" + "a" * 64
        self.expected = gcp.controller.ExpectedPod(self.uid, "workload", 0, self.image)
        self.name = "podvm-proof-1-1234aabb"
        self.pod = {"apiVersion": "v1", "kind": "Pod",
                    "metadata": {"name": "proof-1", "namespace": "execution-proof", "uid": self.uid},
                    "spec": {"runtimeClassName": "kata-remote", "nodeName": "worker",
                             "containers": [{"name": "workload", "image": self.image}]}}
        self.peer = {"apiVersion": "confidentialcontainers.org/v1alpha1", "kind": "PeerPod",
                     "metadata": {"namespace": "execution-proof",
                                  "uid": "ed1aa190-b8db-48bb-b3f0-aec56ff8abf4", "ownerReferences": [
                                      {"apiVersion": "v1", "kind": "Pod", "controller": True,
                                       "name": "proof-1", "uid": self.uid}]},
                     "spec": {"cloudProvider": "gcp", "instanceID": self.name}}
        self.disk = {"name": "disk-1", "selfLink": self.root + "/disks/disk-1", "sourceImageId": "789"}
        self.vm = {"name": self.name, "status": "RUNNING", "id": "456",
                   "selfLink": self.root + "/instances/" + self.name,
                   "confidentialInstanceConfig": {"confidentialInstanceType": "TDX"},
                   "disks": [{"boot": True, "source": self.disk["selfLink"]}]}

    def bind(self):
        return gcp.bind_target(self.pod, [self.peer], self.vm, self.disk, namespace="execution-proof",
                               pod_name="proof-1", expected=self.expected, image_id="789", scope=self.scope)

    def test_target_contains_new_project_and_zone(self):
        self.assertEqual(self.bind().gce_identity(), {
            "instance_id": 456, "numerical_project_id": 1234, "zone": "europe-west4-a"})

    def test_issuer_instance_pins_require_json_integers(self):
        # Use 1 in both readbacks: Python also compares true equal to this ID.
        self.vm["id"] = "1"
        self.scope = gcp.Scope(self.scope.project, self.scope.zone, 1)
        target = self.bind()
        identity = target.gce_identity()
        spec = b"{}"
        intent = gcp.protocol.encode({"signature": "00" * 64, "statement": {
            "purpose": "qlad.execution-proof.tenant-intent.v2", "version": 2,
            "container_role": "application-init", "selected_manifest_sha256": "a" * 64,
            "effective_launch_sha384": operator.hash384(spec)}})

        def check(pin):
            config = gcp.protocol.encode({"boot_policy": {"expected_instance": pin}})
            gcp.validate_issuer_pins(target, config, intent, spec)

        check(identity)
        for field in ("instance_id", "numerical_project_id"):
            for value in (True, 1.0):
                with self.subTest(field=field, value=value):
                    with self.assertRaisesRegex(gcp.protocol.AttemptError, "^authority_instance_pin$"):
                        check({**identity, field: value})

    def test_rejects_other_project(self):
        self.vm["selfLink"] = self.vm["selfLink"].replace("fixture-proof", "other-proof")
        with self.assertRaisesRegex(gcp.protocol.AttemptError, "compute_instance"):
            self.bind()

    def test_rejects_other_pod(self):
        self.pod["metadata"]["uid"] = self.peer["metadata"]["uid"]
        with self.assertRaisesRegex(gcp.protocol.AttemptError, "pod_identity"):
            self.bind()

    def test_rejects_other_image(self):
        self.disk["sourceImageId"] = "99"
        with self.assertRaisesRegex(gcp.protocol.AttemptError, "compute_boot_image"):
            self.bind()

    def test_stock_controller_rejects_attached_google_account(self):
        client = operator.Clients.__new__(operator.Clients)
        client.pod = Mock(return_value=self.pod)
        client.k = Mock(return_value=json.dumps({"items": [self.peer]}).encode())
        client.compute = Mock(return_value={**self.vm, "serviceAccounts": [{}]})
        client.boot_disk = Mock(return_value=self.disk)
        client.image_id, client.scope = 789, self.scope
        with self.assertRaisesRegex(gcp.protocol.AttemptError, "stock_caa_service_account"):
            client.pod_target(self.expected, time.monotonic() + 10)

    def test_serial_restricts_login_to_the_bound_zone(self):
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory).resolve()
            identity = directory / "test_ssh"
            identity.write_bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----\nfixture")
            identity.chmod(0o600)
            hosts = directory / "known_hosts"
            content = b"[europe-west4-ssh-serialport.googleapis.com]:9600 ssh-ed25519 fixture\n"
            hosts.write_bytes(content)
            hosts.chmod(0o600)
            config = serial.Config("fixture-proof", "europe-west4-a", self.name, directory, identity,
                                   hosts, operator.hash384(content), time.monotonic() + 30)
            argv = serial.ssh_command(config)
            self.assertEqual(argv[-1], "europe-west4-ssh-serialport.googleapis.com")
            self.assertTrue(argv[-2].startswith(f"fixture-proof.europe-west4-a.{self.name}."))


class SchedulingTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.receipt = Path(directory.name) / "receipt.json"
        q = Path(directory.name) / "signed-q"
        q.write_bytes(b"fixture")
        q.chmod(0o600)
        self.config = {"context": "gke_project_zone_cluster", "pod_receipt": str(self.receipt), "signed_q": str(q)}
        self.uid = "439da190-b8db-48bb-b3f0-aec56ff8abf4"
        self.client = Mock(image_id=123, profile={"workload_image": "registry/app"})
        self.client.scope.project, self.client.scope.zone = "project", "zone"
        self.spec = {"schedulingGates": [{"name": operator.GATE}], "runtimeClassName": "kata-remote",
                     "containers": [{"name": "workload", "image": "registry/app"}]}
        self.pod = {"metadata": {"uid": self.uid}, "spec": self.spec}
        self.client.pod.return_value = self.pod
        for check in ("check_q", "check_intent"):
            self.enterContext(patch.object(operator, check))

    def schedule(self):
        return operator.schedule(self.client, self.config, {}, {}, time.monotonic() + 30)

    def applied_without_reply(self, args, deadline):
        self.assertEqual(json.loads(args[-1]), [
            {"op": "test", "path": "/metadata/uid", "value": self.uid},
            {"op": "test", "path": "/spec/schedulingGates", "value": [{"name": operator.GATE}]},
            {"op": "test", "path": "/spec/containers/0/image", "value": "registry/app"},
            {"op": "remove", "path": "/spec/schedulingGates/0"}])
        self.assertEqual(json.loads(self.receipt.read_bytes())["pod_uid"], self.uid)
        del self.spec["schedulingGates"]
        self.spec["nodeName"] = "assigned"
        raise operator.subprocess.TimeoutExpired("kubectl", 1)

    def test_applied_patch_lost_reply_and_restart(self):
        self.client.k.side_effect = self.applied_without_reply
        result = self.schedule()
        self.assertEqual(result, {"pod_uid": self.uid, "scheduled": True})
        self.assertEqual(self.schedule(), result)
        self.client.k.assert_called_once()

    def test_unapplied_patch_resumes_with_the_same_receipt(self):
        self.client.k.side_effect = gcp.protocol.AttemptError("operator_command_failed")
        with self.assertRaises(gcp.protocol.AttemptError):
            self.schedule()
        original = self.receipt.stat()
        self.assertEqual(self.client.k.call_count, 2)
        self.client.k.side_effect = self.applied_without_reply
        self.assertTrue(self.schedule()["scheduled"])
        self.assertEqual(self.client.k.call_count, 3)
        self.assertEqual(self.receipt.stat().st_ino, original.st_ino)

    def test_replacement_rejected_during_readback_and_restart(self):
        def replace(*_):
            self.pod["metadata"]["uid"] = "739da190-b8db-48bb-b3f0-aec56ff8abf4"
            raise gcp.protocol.AttemptError("operator_command_failed")
        self.client.k.side_effect = replace
        with self.assertRaisesRegex(gcp.protocol.AttemptError, "expected_gated_pod"):
            self.schedule()
        with self.assertRaisesRegex(gcp.protocol.AttemptError, "scheduled_pod_receipt"):
            self.schedule()
        self.client.k.assert_called_once()

    def test_gate_already_removed_requires_matching_receipt(self):
        del self.spec["schedulingGates"]
        with self.assertRaisesRegex(gcp.protocol.AttemptError, "expected_gated_pod"):
            self.schedule()
        self.assertFalse(self.receipt.exists())
        self.receipt.write_text(json.dumps({"pod_uid": self.uid, "image_id": 123,
                                            "context": self.config["context"], "q_sha384": "other"}))
        self.receipt.chmod(0o600)
        with self.assertRaisesRegex(gcp.protocol.AttemptError, "scheduled_pod_receipt"):
            self.schedule()
        self.client.k.assert_not_called()


class BootBindingTests(unittest.TestCase):
    def test_integer_version_preserves_rust_golden_digest(self):
        binding = {
            "version": 1, "purpose": "qlad.execution-proof.gcp-boot-binding.v1",
            "profile": "onb17.gcp-tdx-embedded-pe.v1", "config_sha384": "01" * 48,
            "producer_core_sha384": "02" * 48, "artifact_manifest_sha384": "03" * 48,
            "reference_policy_sha384": "04" * 48,
        }
        self.assertEqual(operator.boot_digest(binding),
                         "ded556a34b417b849256926ed6020ff711638d6db38174dc5"
                         "bcb199d4382ab283882695f92f290cd02d4e236462c731d")
        for version in (True, 1.0):
            with self.subTest(version=version):
                with self.assertRaisesRegex(gcp.protocol.AttemptError, "^boot_binding$"):
                    operator.boot_digest({**binding, "version": version})


if __name__ == "__main__":
    unittest.main()
