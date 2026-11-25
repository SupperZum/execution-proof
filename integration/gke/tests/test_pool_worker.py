import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

import pool_worker
import run


class PoolWorkerTests(unittest.TestCase):
    def test_assignment_survives_process_restart_and_replacement_needs_new_attempt(self):
        first = {"name": "worker", "uid": "first", "provider_id": "fixture", "host": "10.0.0.8"}
        replacement = {**first, "uid": "replacement"}
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            self.assertEqual(pool_worker.allocate(state, "cluster", "attempt", [first]), first)
            self.assertEqual(pool_worker.allocate(state, "cluster", "attempt", [replacement]), first)
            with self.assertRaisesRegex(run.cloud.protocol.AttemptError, "worker_pool_exhausted"):
                pool_worker.allocate(state, "cluster", "another", [first])
            self.assertEqual(pool_worker.allocate(state, "cluster", "another", [replacement]), replacement)

    def test_host_keys_must_be_unique_and_from_console_block(self):
        def key(byte):
            return "ssh-ed25519 " + base64.b64encode(pool_worker.ED25519 + bytes([byte]) * 32).decode()

        first = key(1)
        block = "-----BEGIN SSH HOST KEY KEYS-----\r\n" + first + " node\r\n-----END SSH HOST KEY KEYS-----"
        self.assertEqual(pool_worker.host_key(key(2) + "\n" + block), first)
        with self.assertRaisesRegex(run.cloud.protocol.AttemptError, "worker_host_key"):
            pool_worker.host_key(block + "\n" + block.replace(first, key(2)))

    def test_patch_adds_worker_selector_before_releasing_gate(self):
        client = Mock()
        run.patch_gate(client, "proof", "uid", "image", 30, resource_version="123", worker_node="worker")
        patch = json.loads(client.k.call_args.args[0][-1])
        self.assertEqual(patch[1], {"op": "test", "path": "/metadata/resourceVersion", "value": "123"})
        self.assertEqual(patch[-2:], [
            {"op": "add", "path": "/spec/nodeSelector/kubernetes.io~1hostname", "value": "worker"},
            {"op": "remove", "path": "/spec/schedulingGates/0"},
        ])

    def test_worker_dispatch_binds_readback_to_the_armed_uid(self):
        source = run.ROOT / "worker/daemonset/worker-access.py"
        spec = importlib.util.spec_from_file_location("worker_access", source)
        access = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(access)
        uid = "97027d7c-30d0-4c6e-a003-634c1b74ff32"
        image = "registry.example.org/proof@sha256:" + "a" * 64
        other_uid = "1" + uid[1:]
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            ready = f"sudo -n /run/execution-proof/single-guest ready {uid}"
            self.assertEqual(access.command(ready, image, state)[1:], ["ready", uid])
            (state / "pod-uid").write_text(uid)
            readback = (f"sudo -n /run/execution-proof/worker-readback /run/containerd/containerd.sock "
                        f"{uid} {image} gcp-kata execution-proof proof-1 0")
            self.assertEqual(access.command(readback, image, state)[2], uid)
            for changed in (readback.replace(uid, other_uid), readback.replace("a" * 64, "b" * 64),
                            readback.removesuffix("0") + "1"):
                with self.assertRaises(ValueError):
                    access.command(changed, image, state)
