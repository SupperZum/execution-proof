"""Persist public assembly inputs and resume enqueue after a sender restart."""
import argparse
import base64
import http.client
from contextlib import closing
from hashlib import file_digest
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import sys
import time

from collector import CHALLENGE_LIMIT, ID, TRUST_LIMIT, Conflict, bounded, digest, encode, private_dir
from outbox import Outbox

FIELDS = ("protected_export", "bootstrap_transcript", "signed_bootstrap_challenge", "original_policy_archive",
          "policy_transcript", "signed_qualification", "trust", "challenge")
INPUT_LIMIT = 32 << 20


def pins(selection):
    if (set(selection) != {*FIELDS, "version", "purpose", "objects"}
            or selection["version"] != 1 or selection["purpose"] != "onb17.manual-public-pack-selection.v1"
            or not isinstance(selection["objects"], list) or len(selection["objects"]) > 18):
        raise ValueError("invalid assembly selection")
    for field in FIELDS:
        yield selection[field]
    for obj in selection["objects"]:
        yield obj["file"]


class AssemblyJobs:
    def __init__(self, state):
        private_dir(state)
        self.path = state / "assembly.sqlite"
        with closing(self.connect()) as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS inputs (hash TEXT PRIMARY KEY, bytes BLOB NOT NULL)")
            db.execute("""CREATE TABLE IF NOT EXISTS jobs
                          (attempt TEXT PRIMARY KEY, selection BLOB NOT NULL, queued INTEGER NOT NULL)""")

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.execute("PRAGMA synchronous=EXTRA")
        return db

    def stage(self, selection_path, public_root, trust_path, challenge_path):
        selection = json.loads(bounded(selection_path, 64 << 10))
        trust = bounded(trust_path, TRUST_LIMIT)
        challenge = bounded(challenge_path, CHALLENGE_LIMIT)
        if selection["trust"]["sha384"] != digest(trust) or selection["challenge"]["sha384"] != digest(challenge):
            raise ValueError("selection differs from independently supplied context")
        attempt = json.loads(trust)["admission"]["attempt_id"]
        if not re.fullmatch(ID, attempt):
            raise ValueError("invalid attempt ID")
        total = 0
        public_root = public_root.resolve(strict=True)
        if public_root == Path("/"):
            raise ValueError("dedicated public input root required")
        with closing(self.connect()) as db, db:
            for pin in pins(selection):
                path = Path(pin["path"])
                if (not path.is_relative_to(public_root) or path.resolve(strict=True) != path
                        or not path.is_file() or path.stat().st_nlink != 1):
                    raise ValueError("expected a regular file in the public input root")
                raw = bounded(path, INPUT_LIMIT - total)
                total += len(raw)
                checksum = digest(raw)
                if checksum != pin["sha384"]:
                    raise ValueError("assembly input changed")
                db.execute("INSERT INTO inputs VALUES(?,?) ON CONFLICT(hash) DO NOTHING", (checksum, raw))
                pin["path"] = checksum
            original = encode(selection)
            db.execute("INSERT INTO jobs VALUES(?,?,0) ON CONFLICT(attempt) DO NOTHING", (attempt, original))
            if db.execute("SELECT selection FROM jobs WHERE attempt=?", (attempt,)).fetchone() != (original,):
                raise Conflict("conflicting assembly inputs")
        return attempt

    def register(self, endpoint, *, recheck=False):
        from collector import PREFIX
        failures = 0
        with closing(self.connect()) as db:
            with db:
                db.execute("""CREATE TABLE IF NOT EXISTS registrations (
                    attempt TEXT PRIMARY KEY, status TEXT NOT NULL)""")
            rows = db.execute("""SELECT jobs.attempt, selection FROM jobs LEFT JOIN registrations
                                 USING(attempt) WHERE ? OR status IS NULL OR status != 'registered'""", (recheck,)).fetchall()
            for attempt, wire in rows:
                selection = json.loads(wire)
                payload = {}
                for name in ("trust", "challenge"):
                    checksum = selection[name]["sha384"]
                    raw, = db.execute("SELECT bytes FROM inputs WHERE hash=?", (checksum,)).fetchone()
                    if digest(raw) != checksum:
                        raise ValueError("registered input changed")
                    payload[name] = base64.b64encode(raw).decode("ascii")
                try:
                    with closing(endpoint.connection()) as conn:
                        conn.request("PUT", PREFIX + attempt + "/context", encode(payload),
                                     {"Content-Type": "application/json"})
                        response = conn.getresponse()
                        status = {403: "denied", 409: "conflict"}.get(response.status, "pending")
                        if response.status == 200 and json.loads(response.read(4096)) == {"attempt_id": attempt}:
                            status = "registered"
                except (OSError, http.client.HTTPException, ValueError):
                    status = "pending"
                with db:
                    db.execute("""INSERT INTO registrations VALUES(?,?) ON CONFLICT(attempt)
                                  DO UPDATE SET status=excluded.status""", (attempt, status))
                failures += status != "registered"
                print(json.dumps({"attempt_id": attempt, "registration": status}), flush=True)
        return failures

    def resume(self, assembler, expected_hash, work, spool):
        private_dir(work)
        queue = Outbox(spool)
        with assembler.open("rb") as binary, closing(self.connect()) as db:
            if file_digest(binary, "sha384").hexdigest() != expected_hash:
                raise ValueError("assembler pin mismatch")
            jobs = db.execute("SELECT attempt,selection FROM jobs WHERE queued=0 ORDER BY rowid")
            for attempt, wire in jobs.fetchall():
                selection = json.loads(wire)
                with tempfile.TemporaryDirectory(dir=work) as tmp:
                    directory = Path(tmp)
                    for pin in pins(selection):
                        checksum = pin["sha384"]
                        if not re.fullmatch("[a-f0-9]{96}", checksum) or pin["path"] != checksum:
                            raise ValueError("invalid stored assembly input")
                        dest = directory / checksum
                        if not dest.exists():
                            row = db.execute("SELECT bytes FROM inputs WHERE hash=?", (checksum,)).fetchone()
                            if row is None or digest(row[0]) != checksum:
                                raise ValueError("stored assembly input changed")
                            dest.write_bytes(row[0])
                        pin["path"] = str(dest)
                    selected = directory / "selection.json"
                    selected.write_bytes(encode(selection))
                    output = directory / "bundle"
                    fd = binary.fileno()
                    subprocess.run([f"/proc/self/fd/{fd}", "assemble", selected, output],
                                   pass_fds=(fd,), stdout=subprocess.DEVNULL, check=True, timeout=120)
                    for name in ("trust", "challenge"):
                        if digest(bounded(output / (name + ".json"), TRUST_LIMIT)) != selection[name]["sha384"]:
                            raise ValueError("assembled context differs from registered bytes")
                    if queue.enqueue(output) != attempt:
                        raise ValueError("unexpected assembled attempt")
                    with db:
                        db.execute("UPDATE jobs SET queued=1 WHERE attempt=?", (attempt,))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    actions = parser.add_subparsers(dest="action", required=True)
    stage = actions.add_parser("stage")
    for name in ("selection", "public-root", "trust", "challenge"):
        stage.add_argument("--" + name, type=Path, required=True)
    register = actions.add_parser("register")
    register.add_argument("--tls-config", type=Path, required=True)
    register.add_argument("--watch", action="store_true")
    resume = actions.add_parser("resume")
    resume.add_argument("--watch", action="store_true")
    for name in ("assembler", "work", "spool"):
        resume.add_argument("--" + name, type=Path, required=True)
    resume.add_argument("--assembler-sha384", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    jobs = AssemblyJobs(args.state)
    if args.action == "stage":
        print(jobs.stage(args.selection, args.public_root, args.trust, args.challenge))
    elif args.action == "register":
        from tls_api import Endpoint
        endpoint = Endpoint(args.tls_config)
        recheck = True
        while True:
            failures = jobs.register(endpoint, recheck=recheck)
            recheck = False
            if not args.watch:
                return int(bool(failures))
            time.sleep(5)
    else:
        while True:
            jobs.resume(args.assembler, args.assembler_sha384, args.work, args.spool)
            if not args.watch:
                return 0
            time.sleep(5)


if __name__ == "__main__":
    sys.exit(main())
