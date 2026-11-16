import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock

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


if __name__ == "__main__":
    unittest.main()
