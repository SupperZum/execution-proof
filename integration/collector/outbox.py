"""Queue public verifier bundles locally and deliver them outside the workload lifecycle."""
import argparse
from contextlib import closing
import http.client
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from collector import CHALLENGE_LIMIT, ID, PACK_LIMIT, TRUST_LIMIT, Conflict, bounded, digest, encode, private_dir
from deliver import SubmissionError, submit


class Outbox:
    def __init__(self, directory):
        private_dir(directory)
        self.path = directory / "outbox.sqlite"
        with closing(self.connect()) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS deliveries (
                attempt TEXT PRIMARY KEY, pack BLOB, trust BLOB, challenge BLOB,
                pack_hash TEXT NOT NULL, trust_hash TEXT NOT NULL, challenge_hash TEXT NOT NULL,
                ack BLOB)""")
            db.execute("CREATE TABLE IF NOT EXISTS failures (attempt TEXT PRIMARY KEY, reason TEXT NOT NULL)")
        fd = os.open(directory, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.execute("PRAGMA synchronous=FULL")
        return db

    def enqueue(self, bundle):
        pack = bounded(bundle / "pack.json", PACK_LIMIT)
        trust = bounded(bundle / "trust.json", TRUST_LIMIT)
        challenge = bounded(bundle / "challenge.json", CHALLENGE_LIMIT)
        attempt = json.loads(trust)["admission"]["attempt_id"]
        if not re.fullmatch(ID, attempt):
            raise ValueError("invalid attempt ID")
        hashes = digest(pack), digest(trust), digest(challenge)
        with closing(self.connect()) as db, db:
            db.execute("INSERT INTO deliveries VALUES(?,?,?,?,?,?,?,NULL) ON CONFLICT(attempt) DO NOTHING",
                       (attempt, pack, trust, challenge, *hashes))
            row = db.execute("SELECT pack_hash,trust_hash,challenge_hash FROM deliveries WHERE attempt=?",
                             (attempt,)).fetchone()
            if row != hashes:
                raise Conflict("different submission already queued for this attempt")
        return attempt

    def flush(self, socket_path, public):
        with closing(self.connect()) as db:
            pending = db.execute("SELECT attempt FROM deliveries WHERE ack IS NULL ORDER BY rowid").fetchall()
            for (attempt,) in pending:
                row = db.execute("SELECT pack,trust,challenge FROM deliveries WHERE attempt=? AND ack IS NULL",
                                 (attempt,)).fetchone()
                if row is None:
                    continue
                try:
                    ack = submit(*row, socket_path, public)
                except (OSError, http.client.HTTPException, InvalidSignature, ValueError, KeyError, TypeError, AttributeError, RecursionError) as err:
                    reason = err.reason if isinstance(err, SubmissionError) else type(err).__name__
                    with db:
                        db.execute("INSERT INTO failures VALUES(?,?) ON CONFLICT(attempt) DO UPDATE "
                                   "SET reason=excluded.reason", (attempt, reason))
                    print(f"{attempt}: delivery pending ({reason})", file=sys.stderr)
                    continue
                # Keep the bytes through response loss, timeouts and crashes.
                # Release the queue copy in the transaction that records the checked ACK.
                with db:
                    db.execute("UPDATE deliveries SET ack=?,pack=NULL,trust=NULL,challenge=NULL "
                               "WHERE attempt=? AND ack IS NULL", (encode(ack), attempt))
            return db.execute("SELECT COUNT(*) FROM deliveries WHERE ack IS NULL").fetchone()[0]

    def status(self, attempt):
        with closing(self.connect()) as db:
            row = db.execute("""SELECT ack,reason FROM deliveries LEFT JOIN failures USING(attempt)
                                WHERE attempt=?""", (attempt,)).fetchone()
        if row is None:
            raise ValueError("attempt not queued")
        return {**({"reason": row[1]} if row[1] and not row[0] else {}),
                "attempt_id": attempt, "delivery": "archived" if row[0] else "pending",
                "receipt": json.loads(row[0]) if row[0] else None}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("enqueue").add_argument("bundle", type=Path)
    actions.add_parser("status").add_argument("attempt")
    flush = actions.add_parser("flush")
    transport = flush.add_mutually_exclusive_group(required=True)
    transport.add_argument("--socket", type=Path)
    transport.add_argument("--tls-config", type=Path)
    flush.add_argument("--public-key", type=Path, required=True)
    flush.add_argument("--watch", action="store_true")
    args = parser.parse_args()
    queue = Outbox(args.state)
    if args.action == "enqueue":
        print(queue.enqueue(args.bundle))
    elif args.action == "status":
        print(encode(queue.status(args.attempt)).decode())
    else:
        public = serialization.load_pem_public_key(bounded(args.public_key, 4096))
        if not isinstance(public, Ed25519PublicKey):
            parser.error("expected Ed25519 collector key")
        from tls_api import Endpoint
        destination = Endpoint(args.tls_config) if args.tls_config else args.socket
        while True:
            pending = queue.flush(destination, public)
            if not args.watch:
                return int(bool(pending))
            time.sleep(5)
    return 0


if __name__ == "__main__":
    sys.exit(main())
