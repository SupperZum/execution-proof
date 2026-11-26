from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature

from collector import Conflict, Rejected, Store, Unavailable, Verifier, digest, encode
from deliver import verify_receipt
from outbox import Outbox


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name)
        self.store = Store(self.state)
        self.trust = b'{"admission":{"attempt_id":"a"}}'
        self.record = "1" * 96
        self.challenge = encode({"record_sha384": self.record})
        self.store.register(self.trust, self.challenge)
        self.key = Ed25519PrivateKey.generate()
        self.verdict = {"version": 2, "claim": "exec_committed", "identity_scope": "authorized_workload_attempt",
                        "event_id": "a" * 64, "record_sha384": self.record, "status": "verified_exec"}

    def submit(self, raw=b"pack"):
        return self.store.submit("a", raw, lambda *_: self.verdict, self.key)

    def test_verifier_distinguishes_startup_failure_from_invalid_evidence(self):
        verify = Verifier.__new__(Verifier)
        verify.runtime, verify.args = self.state, ["verifier"]
        for code, stdout, error in [(1, b"", Unavailable), (0, b"[]", Unavailable),
                                    (1, b'{"status":"invalid"}', Rejected)]:
            outcome = subprocess.CompletedProcess([], code, stdout, b"")
            with self.subTest(code=code, stdout=stdout), patch("collector.subprocess.run", return_value=outcome):
                with self.assertRaises(error):
                    verify(b"pack", self.trust, self.challenge)

    def test_lost_response_survives_restart(self):
        first = self.submit()
        self.store = Store(self.state)
        second = self.store.submit("a", b"pack", lambda *_: self.fail("verified twice"), self.key)
        self.assertEqual(first, second)
        self.assertEqual(self.store.fetch("a", "pack"), b"pack")
        self.assertEqual(json.loads(self.store.fetch("a", None))["delivery"], "archived")
        with self.assertRaises(Conflict):
            self.submit(b"changed")
        with self.assertRaises(Conflict):
            self.store.register(self.trust + b" ", self.challenge)

    def test_commit_failure_gives_no_ack(self):
        with closing(self.store.connect()) as db, db:
            db.execute("CREATE TABLE parent (id INTEGER PRIMARY KEY)")
            db.execute("CREATE TABLE child (id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED)")
            db.execute("CREATE TRIGGER fail_commit AFTER UPDATE ON attempts BEGIN INSERT INTO child VALUES(1); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.submit()
        self.assertIsNone(self.store.fetch("a", "receipt"))
        self.assertIsNone(self.store.fetch("a", "pack"))
        self.assertEqual(json.loads(self.store.fetch("a", None))["delivery"], "pending")

        with closing(self.store.connect()) as db, db:
            db.execute("DROP TRIGGER fail_commit")
        self.assertEqual(self.submit(), self.store.fetch("a", "receipt"))

    def test_store_binds_signer_across_restarts(self):
        self.store.bind_signer(self.key)
        reopened = Store(self.state)
        reopened.bind_signer(self.key)
        with self.assertRaises(Conflict):
            reopened.bind_signer(Ed25519PrivateKey.generate())

    def test_only_verified_matching_input_can_commit(self):
        self.verdict["record_sha384"] = "0" * 96
        with self.assertRaises(Rejected):
            self.submit()
        self.assertIsNone(self.store.fetch("a", "receipt"))
        self.store.mark_missing("a")
        self.assertEqual(json.loads(self.store.fetch("a", None))["delivery"], "unproven")
        with self.assertRaises(KeyError):
            self.store.submit("unknown", b"pack", None, self.key)

    def test_outbox_keeps_originals_until_ack_is_verified(self):
        bundle = self.state / "bundle"
        bundle.mkdir()
        pack = bundle / "pack.json"
        pack.write_bytes(b"original")
        (bundle / "trust.json").write_bytes(self.trust)
        (bundle / "challenge.json").write_bytes(self.challenge)
        queue = Outbox(self.state)
        self.assertEqual(queue.enqueue(bundle), "a")
        self.assertEqual(queue.enqueue(bundle), "a")
        pack.write_bytes(b"different")
        with self.assertRaises(Conflict):
            queue.enqueue(bundle)
        with patch("outbox.submit", side_effect=InvalidSignature):
            self.assertEqual(queue.flush(self.state / "socket", self.key.public_key()), 1)
        queue = Outbox(self.state)
        self.assertEqual(queue.status("a")["delivery"], "pending")
        with closing(queue.connect()) as db:
            self.assertEqual(db.execute("SELECT pack,trust,challenge FROM deliveries").fetchall(),
                             [(b"original", self.trust, self.challenge)])
        receipt = json.loads(self.submit(b"original"))
        with patch("outbox.submit", return_value=receipt):
            self.assertEqual(queue.flush(self.state / "socket", self.key.public_key()), 0)
        self.assertEqual(queue.status("a")["receipt"], receipt)
        with closing(queue.connect()) as db:
            self.assertEqual(db.execute("SELECT pack,trust,challenge FROM deliveries").fetchall(),
                             [(None, None, None)])

    def test_receipt_requires_pinned_signer_and_matching_context(self):
        receipt = json.loads(self.submit())
        expected = receipt["statement"]
        self.assertEqual(expected["pack_sha384"], digest(b"pack"))
        verify_receipt(receipt, self.key.public_key(), expected)
        for field in ("attempt_id", "event_id", "pack_sha384", "verdict_sha384"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_receipt(receipt, self.key.public_key(), dict(expected, **{field: "other"}))
        with self.assertRaises(InvalidSignature):
            verify_receipt(receipt, Ed25519PrivateKey.generate().public_key(), expected)


if __name__ == "__main__":
    unittest.main()
