"""Local durable collector for independently verified GCP execution-proof bundles."""
import argparse
import base64
from contextlib import closing
import fcntl
from hashlib import sha384
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import re
import socketserver
import sqlite3
import stat
import subprocess
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PACK_LIMIT = 16 << 20
TRUST_LIMIT = 1 << 20
CHALLENGE_LIMIT = 64 << 10
PREFIX = "/v1/attempts/"
ID = r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}"
DOMAIN = b"execution-proof.collector.receipt.v1\0"
ARTIFACTS = {"pack", "challenge", "trust", "verdict", "receipt"}


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(raw):
    return sha384(raw).hexdigest()


def bounded(path, limit):
    with Path(path).open("rb") as stream:
        raw = stream.read(limit + 1)
    if not 0 < len(raw) <= limit:
        raise ValueError("invalid input size")
    return raw


def private_dir(path):
    if path.resolve() != path or not path.is_dir():
        raise ValueError("use an absolute private state directory")
    info = path.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("state directory must be owned by this user and mode 0700")


class Conflict(Exception):
    pass


class Unavailable(Exception):
    pass


class Rejected(Exception):
    pass


class Store:
    def __init__(self, directory):
        private_dir(directory)
        self.path = directory / "collector.sqlite"
        with closing(self.connect()) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS attempts (
                id TEXT PRIMARY KEY, trust BLOB NOT NULL, challenge BLOB NOT NULL,
                missing INTEGER NOT NULL DEFAULT 0, pack BLOB, hash TEXT,
                verdict BLOB, receipt BLOB)""")
        fd = os.open(directory, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def bind_signer(self, signer):
        public = signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        with closing(self.connect()) as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS collector_key (id INTEGER PRIMARY KEY CHECK(id=1), public BLOB NOT NULL)")
            db.execute("INSERT INTO collector_key VALUES(1,?) ON CONFLICT(id) DO NOTHING", (public,))
            if db.execute("SELECT public FROM collector_key WHERE id=1").fetchone() != (public,):
                raise Conflict("signer differs from the key bound to this store")

    def register(self, trust, challenge):
        attempt = json.loads(trust)["admission"]["attempt_id"]
        if not isinstance(attempt, str) or not re.fullmatch(ID, attempt):
            raise ValueError("invalid attempt ID")
        if not re.fullmatch(r"[0-9a-f]{96}", json.loads(challenge)["record_sha384"]):
            raise ValueError("invalid challenge")
        with closing(self.connect()) as db, db:
            db.execute("INSERT INTO attempts(id,trust,challenge) VALUES(?,?,?) "
                       "ON CONFLICT(id) DO NOTHING", (attempt, trust, challenge))
            if db.execute("SELECT trust,challenge FROM attempts WHERE id=?", (attempt,)).fetchone() != (trust, challenge):
                raise Conflict("attempt already has different trusted inputs")
        return attempt

    def archive_qualification(self, grant, export, signer):
        statement = json.loads(grant)["statement"]
        binding = statement["binding"]
        attempt, grant_id = binding["attempt_id"], statement["grant_id"]
        if (statement.get("purpose") != "qlad.execution-proof.launch.v3" or statement.get("version") != 3
                or not re.fullmatch(r"qexp-[0-9a-f]{64}", grant_id)
                or not all(re.fullmatch(r"qexp-[A-Za-z0-9_.-]{1,122}", binding[field])
                           for field in ("attempt_id", "workload_id"))):
            raise Rejected("expected an experimental GCP grant")
        document = json.loads(export)
        if document.get("purpose") != "qlad.execution-proof.protected-export.v2" or document.get("version") != 2:
            raise Rejected("expected a protected export")
        self.bind_signer(signer)
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("""CREATE TABLE IF NOT EXISTS qualification_exports
                          (attempt TEXT PRIMARY KEY, grant_id TEXT UNIQUE, export BLOB, receipt BLOB)""")
            row = db.execute("SELECT grant_id,export,receipt FROM qualification_exports WHERE attempt=?",
                             (attempt,)).fetchone()
            if row:
                if row[:2] != (grant_id, export):
                    raise Conflict("qualification archive differs")
                return row[2]
            statement = {"purpose": "execution-proof.qualification.export-archived", "version": 1,
                         "attempt_id": attempt, "grant_id": grant_id, "export_sha384": digest(export)}
            message = b"execution-proof.qualification.export-archived.v1\0" + encode(statement)
            receipt = encode({"statement": statement, "signature": base64.b64encode(signer.sign(message)).decode()})
            db.execute("INSERT INTO qualification_exports VALUES(?,?,?,?)", (attempt, grant_id, export, receipt))
        return receipt

    def mark_missing(self, attempt, reason=None):
        with closing(self.connect()) as db, db:
            if db.execute("UPDATE attempts SET missing=1 WHERE id=? AND receipt IS NULL", (attempt,)).rowcount != 1:
                raise Conflict("unknown or already archived attempt")
            if reason is not None:
                db.execute("CREATE TABLE IF NOT EXISTS losses (id TEXT PRIMARY KEY, reason TEXT NOT NULL)")
                db.execute("INSERT INTO losses VALUES(?,?) ON CONFLICT(id) DO NOTHING", (attempt, reason))
                if db.execute("SELECT reason FROM losses WHERE id=?", (attempt,)).fetchone() != (reason,):
                    raise Conflict("conflicting loss record")

    def fetch(self, attempt, artifact):
        with closing(self.connect()) as db:
            if artifact in ARTIFACTS:
                row = db.execute(f"SELECT {artifact} FROM attempts WHERE id=?", (attempt,)).fetchone()
                return row[0] if row else None
            row = db.execute("SELECT missing,verdict FROM attempts WHERE id=?", (attempt,)).fetchone()
            if not row:
                return None
            missing, verdict = row
            state = "archived" if verdict else ("unproven" if missing else "pending")
            result = {"attempt_id": attempt, "delivery": state}
            if missing and not verdict and db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='losses'").fetchone():
                row = db.execute("SELECT reason FROM losses WHERE id=?", (attempt,)).fetchone()
                if row:
                    result["reason"] = row[0]
            if verdict:
                result.update(verdict=json.loads(verdict), bundle=PREFIX + attempt + "/pack",
                              receipt=PREFIX + attempt + "/receipt")
            return encode(result)

    def submit(self, attempt, pack, verify, signer):
        pack_hash = digest(pack)
        with closing(self.connect()) as db, db:
            # Reserve the write before verification. Concurrent retries and missing
            # notifications observe one ordered decision for this attempt.
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT trust,challenge,hash,receipt FROM attempts WHERE id=?", (attempt,)).fetchone()
            if row is None:
                raise KeyError(attempt)
            trust, challenge, prior_hash, prior_receipt = row
            if prior_receipt is not None:
                if pack_hash != prior_hash:
                    raise Conflict("different bundle already archived")
                return prior_receipt
            verdict = verify(pack, trust, challenge)
            if verdict.get("status") != "verified_exec":
                raise Rejected("execution not verified")
            if (verdict.get("version") != 2 or verdict.get("claim") != "exec_committed"
                    or verdict.get("identity_scope") != "authorized_workload_attempt"
                    or not re.fullmatch(r"[0-9a-f]{64}", verdict.get("event_id") or "")
                    or verdict.get("record_sha384") != json.loads(challenge)["record_sha384"]):
                raise Rejected("verdict binding mismatch")
            wire = encode(verdict)
            statement = {"version": 1, "purpose": "execution-proof.collector.receipt",
                         "attempt_id": attempt, "event_id": verdict["event_id"],
                         "record_sha384": verdict["record_sha384"], "pack_sha384": pack_hash,
                         "trust_sha384": digest(trust), "challenge_sha384": digest(challenge),
                         "verdict_sha384": digest(wire)}
            signature = signer.sign(DOMAIN + encode(statement))
            receipt = encode({"statement": statement, "signature": base64.b64encode(signature).decode()})
            db.execute("UPDATE attempts SET pack=?,hash=?,verdict=?,receipt=?,missing=0 WHERE id=?",
                       (pack, pack_hash, wire, receipt, attempt))
        return receipt


class Verifier:
    def __init__(self, runtime, manifest):
        self.runtime = runtime.resolve(strict=True)
        pins = {name: value for value, name in
                (line.split() for line in manifest.read_text().splitlines())}
        self.args = []
        for flag, name in [(None, "gcp-execution-proof-verifier"),
                           ("--tdx-worker", "gcp-tdx-hardware-verifier"),
                           ("--gcp-bootstrap-worker", "gcp-tdx-bootstrap-history-verifier")]:
            path = "opt/onb17/trusted/bin/" + name
            if digest((self.runtime / path).read_bytes()) != pins[path]:
                raise ValueError("verifier runtime pin mismatch")
            if flag:
                self.args.extend([flag, "/" + path, flag + "-sha384", pins[path]])
            else:
                self.args.append("/" + path)

    def __call__(self, pack, trust, challenge):
        with tempfile.TemporaryDirectory() as tmp:
            command = ["bwrap", "--die-with-parent", "--unshare-net", "--ro-bind", str(self.runtime),
                       "/", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
            args = self.args.copy()
            for name, raw in [("pack", pack), ("trust", trust), ("challenge", challenge)]:
                f = Path(tmp) / (name + ".json")
                f.write_bytes(raw)
                inside = "/tmp/" + f.name
                command.extend(["--ro-bind", str(f), inside])
                args.extend(["--" + name, inside])
            result = subprocess.run([*command, "--", *args], capture_output=True, timeout=60)
        return verifier_result(result)


def verifier_result(result):
    try:
        verdict = json.loads(result.stdout)
    except (ValueError, UnicodeError) as error:
        raise Unavailable("verifier returned no readable verdict") from error
    if not isinstance(verdict, dict):
        raise Unavailable("verifier returned no verdict object")
    if result.returncode == 1 and verdict.get("status") == "invalid":
        raise Rejected("invalid evidence")
    if result.returncode:
        raise Unavailable("verification unavailable")
    return verdict


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(20)
        super().setup()

    def log_message(self, *args):
        pass

    def reply(self, status, body=b""):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        match = re.fullmatch(PREFIX + f"({ID})(?:/(pack|trust|challenge|verdict|receipt))?", self.path)
        body = self.server.store.fetch(*match.groups()) if match else None
        if body is None:
            return self.reply(404)
        self.reply(200, body)

    def do_PUT(self):
        match = re.fullmatch(PREFIX + f"({ID})/pack", self.path)
        if not match:
            return self.reply(404)
        lengths = self.headers.get_all("Content-Length") or []
        if self.headers.get("Transfer-Encoding") or len(lengths) != 1 or not re.fullmatch("[0-9]{1,10}", lengths[0]):
            return self.reply(HTTPStatus.LENGTH_REQUIRED)
        length = int(lengths[0])
        if not 0 < length <= PACK_LIMIT:
            return self.reply(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        pack = self.rfile.read(length)
        if len(pack) != length:
            return self.reply(400)
        try:
            receipt = self.server.store.submit(match[1], pack, self.server.verify, self.server.signer)
        except KeyError:
            return self.reply(404)
        except Conflict:
            return self.reply(409)
        except Rejected:
            return self.reply(422)
        except (Unavailable, OSError, ValueError, sqlite3.Error, subprocess.TimeoutExpired):
            return self.reply(503)
        self.reply(200, receipt)


def serve(state, store, signer, verify, tls_config=None):
    socket_path = state / "collector.sock"
    with (state / "collector.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        store.bind_signer(signer)
        if tls_config is not None:
            from tls_api import service
            with service(tls_config, store, signer, verify) as server:
                server.serve_forever()
            return
        if socket_path.exists():
            if not stat.S_ISSOCK(socket_path.lstat().st_mode):
                raise ValueError("unexpected socket path")
            socket_path.unlink()
        try:
            with socketserver.UnixStreamServer(str(socket_path), Handler) as server:
                server.store, server.signer, server.verify = store, signer, verify
                server.serve_forever()
        finally:
            socket_path.unlink(missing_ok=True)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    commands = parser.add_subparsers(dest="action", required=True)
    register = commands.add_parser("register")
    register.add_argument("--trust", type=Path, required=True)
    register.add_argument("--challenge", type=Path, required=True)
    qualification = commands.add_parser("archive-qualification")
    for name in ("key", "grant", "export"):
        qualification.add_argument("--" + name, type=Path, required=True)
    commands.add_parser("mark-missing").add_argument("attempt")
    service = commands.add_parser("serve")
    service.add_argument("--tls-config", type=Path)
    backend = service.add_mutually_exclusive_group(required=True)
    backend.add_argument("--runtime", type=Path)
    backend.add_argument("--pod-verifier", action="store_true")
    for opt in ("key", "manifest"):
        service.add_argument("--" + opt, type=Path, required=True)
    args = parser.parse_args()
    store = Store(args.state)
    if args.action == "register":
        print(PREFIX + store.register(bounded(args.trust, TRUST_LIMIT), bounded(args.challenge, CHALLENGE_LIMIT)))
    elif args.action == "mark-missing":
        store.mark_missing(args.attempt)
    else:
        if args.key.stat().st_uid != os.geteuid() or args.key.stat().st_mode & 0o077:
            parser.error("collector key must be private and owned by this user")
        signer = serialization.load_pem_private_key(bounded(args.key, 4096), password=None)
        if not isinstance(signer, Ed25519PrivateKey):
            parser.error("expected Ed25519 signing key")
        if args.action == "archive-qualification":
            receipt = store.archive_qualification(bounded(args.grant, TRUST_LIMIT), bounded(args.export, PACK_LIMIT), signer)
            print(receipt.decode())
        else:
            if args.pod_verifier:
                from pod_verifier import PodVerifier
                verify = PodVerifier(args.manifest)
            else:
                verify = Verifier(args.runtime, args.manifest)
            serve(args.state, store, signer, verify, args.tls_config)


if __name__ == "__main__":
    import sys
    sys.modules["collector"] = sys.modules[__name__]
    main()
