import json
from pathlib import Path
import io
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from collector import Unavailable, digest
from pod_verifier import PodVerifier, staged_inputs


class PodVerifierTests(unittest.TestCase):
    def test_staging_recovers_after_interruption_and_serializes_writers(self):
        with tempfile.TemporaryDirectory() as root, patch("pod_verifier.INPUT_DIR", Path(root)):
            orphan = Path(root, "request-abandoned")
            orphan.mkdir()
            (orphan / "pack").write_bytes(b"old")
            with staged_inputs((b"pack", b"trust", b"challenge")) as name:
                self.assertFalse(orphan.exists())
                current = Path(root, name)
                self.assertEqual((current / "pack").read_bytes(), b"pack")
                with self.assertRaises(BlockingIOError), staged_inputs((b"x", b"y", b"z")):
                    self.fail("overlapping writer")
                self.assertTrue(current.exists())
            self.assertFalse(current.exists())

    def test_result_from_other_inputs_is_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp, patch("pod_verifier.INPUT_DIR", Path(tmp)):
            pin = Path(tmp, "manifest")
            pin.write_bytes(b"test")
            client = PodVerifier(pin)
            sock = MagicMock()
            sock.__enter__.return_value = sock
            reply = {"verdict": {"status": "verified_exec"},
                     "inputs": [digest(b"a"), digest(b"other trust"), digest(b"c")]}
            sock.makefile.return_value = io.BytesIO(json.dumps(reply).encode())
            with patch("pod_verifier.socket.socket", return_value=sock), patch("pod_verifier.peer_uid", return_value=65531):
                with self.assertRaises(Unavailable):
                    client(b"a", b"b", b"c")
