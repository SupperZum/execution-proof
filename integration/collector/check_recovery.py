"""Exercise lost ACK and retrieval with previously collected GCP evidence."""
import argparse
from contextlib import closing, contextmanager
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from collector import PREFIX, Store, Verifier, digest
from deliver import LocalConnection, deliver
from outbox import Outbox


@contextmanager
def server(state, secret, runtime, manifest):
    proc = subprocess.Popen([sys.executable, "-B", str(Path(__file__).with_name("collector.py")),
                             "--state", str(state), "serve", "--key", str(secret),
                             "--runtime", str(runtime), "--manifest", str(manifest)])
    try:
        deadline = time.monotonic() + 10
        while proc.poll() is None and time.monotonic() < deadline:
            try:
                with closing(LocalConnection(state / "collector.sock")) as conn:
                    conn.connect()
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("service did not start")
        yield
    finally:
        proc.kill()
        proc.wait(timeout=10)


def request(sock, method, path, body=None):
    with closing(LocalConnection(sock)) as conn:
        conn.request(method, path, body)
        response = conn.getresponse()
        return response.status, response.read()


def check(bundles, runtime, manifest):
    verifier = Verifier(runtime, manifest)
    key = Ed25519PrivateKey.generate()
    attempts = []
    with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory(dir="/dev/shm") as key_dir:
        state = Path(tmp)
        secret = Path(key_dir) / "key.pem"
        secret.touch(mode=0o600)
        secret.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
        sock = state / "collector.sock"
        store = Store(state)
        for bundle in bundles:
            attempt = store.register((bundle / "trust.json").read_bytes(), (bundle / "challenge.json").read_bytes())
            assert json.loads(store.fetch(attempt, None))["delivery"] == "pending"
            attempts.append(attempt)
        assert len(set(attempts)) == len(bundles) >= 2
        spool = state / "outbox"
        spool.mkdir(mode=0o700)
        queue = Outbox(spool)
        for bundle, expected in zip(bundles, attempts):
            assert queue.enqueue(bundle) == expected
        assert queue.flush(sock, key.public_key()) == len(bundles)
        assert all(queue.status(attempt)["delivery"] == "pending" for attempt in attempts)
        path = PREFIX + attempts[0] + "/pack"
        with server(state, secret, runtime, manifest):
            status, _ = request(sock, "PUT", path, (bundles[1] / "pack.json").read_bytes())
            assert status == 422 and store.fetch(attempts[0], "receipt") is None
            # Submit the genuine packet and wait for durable visibility from an
            # independent connection. Kill the service without consuming its ACK.
            with closing(LocalConnection(sock)) as conn:
                conn.request("PUT", path, (bundles[0] / "pack.json").read_bytes())
                deadline = time.monotonic() + 70
                while time.monotonic() < deadline:
                    original = store.fetch(attempts[0], "receipt")
                    if original is not None:
                        break
                    time.sleep(0.05)
                else:
                    raise RuntimeError("submission did not commit")
        results = []
        with server(state, secret, runtime, manifest):
            queue = Outbox(spool)
            assert queue.flush(sock, key.public_key()) == 0
            for bundle, attempt in zip(bundles, attempts):
                receipt = deliver(bundle, sock, key.public_key())
                status, stored = request(sock, "GET", PREFIX + attempt + "/receipt")
                assert status == 200 and receipt == json.loads(stored)
                assert queue.status(attempt)["receipt"] == receipt
                if attempt == attempts[0]:
                    assert stored == original
                inputs = []
                for name in ("pack", "trust", "challenge"):
                    status, raw = request(sock, "GET", PREFIX + attempt + "/" + name)
                    assert status == 200 and raw == (bundle / (name + ".json")).read_bytes()
                    inputs.append(raw)
                verdict = verifier(*inputs)
                assert verdict["claim"] == "exec_committed" and verdict["status"] == "verified_exec"
                assert verdict["event_id"] == receipt["statement"]["event_id"]
                status, archived_verdict = request(sock, "GET", PREFIX + attempt + "/verdict")
                assert status == 200 and digest(archived_verdict) == receipt["statement"]["verdict_sha384"]
                archived = json.loads(archived_verdict)
                # Re-evaluation of collateral records its own wall-clock time.
                timestamp = "evaluation_time_unix_seconds"
                assert 0 < archived[timestamp] <= verdict[timestamp]
                assert archived == dict(verdict, **{timestamp: archived[timestamp]})
                results.append(dict(attempt_id=attempt, event_id=verdict["event_id"], pack_sha384=digest(inputs[0]),
                                    receipt_sha384=digest(stored), receipt=receipt, archived_verdict=archived, retrieval_verdict=verdict))
            status, _ = request(sock, "PUT", path, (bundles[1] / "pack.json").read_bytes())
            assert status == 409
        with closing(store.connect()) as db:
            assert db.execute("SELECT COUNT(*) FROM attempts WHERE receipt IS NOT NULL").fetchone() == (len(bundles),)
        public_pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo)
        return {"collector_public_key_pem": public_pem.decode(), "originals_verified_after_retrieval": results,
                "first_receipt_identical_after_restart": True,
                "first_receipt_sha384_before_restart": digest(original),
                "bundles_queued_while_offline": len(bundles),
                "wrong_bundle_before_commit": 422, "different_bundle_after_commit": 409}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("bundles", nargs="+", type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.bundles, args.runtime, args.manifest), indent=2))
