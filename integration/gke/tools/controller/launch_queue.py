"""Persistent handoff from the scheduler to independent GKE launch workers."""

from contextlib import closing
import json
import sqlite3
import time

from attempt_driver import require
import serial_gateway as serial


class LaunchQueue:
    def __init__(self, directory):
        serial._directory(directory)
        self.path = directory / "launch.sqlite"
        with closing(self.connect()) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS launches (
                cluster TEXT, uid TEXT, attempt TEXT UNIQUE NOT NULL, receipt TEXT NOT NULL,
                expires INTEGER NOT NULL, phase TEXT NOT NULL, reason TEXT,
                PRIMARY KEY(cluster, uid))""")

    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.execute("PRAGMA synchronous=EXTRA")
        return db

    def publish(self, receipt):
        cluster, uid, attempt = (receipt[key] for key in ("cluster_id", "pod_uid", "attempt_id"))
        wire = json.dumps(receipt, sort_keys=True)
        with closing(self.connect()) as db, db:
            db.execute("""INSERT INTO launches VALUES(?,?,?,?,?,'ready',NULL)
                          ON CONFLICT(cluster,uid) DO NOTHING""",
                       (cluster, uid, attempt, wire, receipt["validity"]["expires"]))
            row = db.execute("SELECT receipt FROM launches WHERE cluster=? AND uid=?", (cluster, uid)).fetchone()
            require(row == (wire,), "launch_receipt_conflict")

    def next_ready(self, cluster):
        with closing(self.connect()) as db:
            row = db.execute("""SELECT receipt FROM launches WHERE cluster=? AND phase='ready'
                                ORDER BY rowid LIMIT 1""", (cluster,)).fetchone()
        return json.loads(row[0]) if row else None

    def claim(self, receipt):
        attempt = receipt["attempt_id"]
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT receipt,phase FROM launches WHERE attempt=?", (attempt,)).fetchone()
            require(row and row[0] == json.dumps(receipt, sort_keys=True), "launch_receipt_conflict")
            require(row[1] == "ready", "launch_already_claimed")
            expired = int(time.time()) >= receipt["validity"]["expires"]
            if expired:
                db.execute("UPDATE launches SET phase='expired',reason='tenant_intent_window' WHERE attempt=?",
                           (attempt,))
            else:
                # A dead worker may already have caused exec. Keep its claim until
                # an independent recovery has determined the original outcome.
                require(not db.execute("SELECT 1 FROM launches WHERE phase='claimed' LIMIT 1").fetchone(),
                        "launch_capacity")
                db.execute("UPDATE launches SET phase='claimed' WHERE attempt=?", (attempt,))
        require(not expired, "tenant_intent_window")

    def finish(self, attempt, phase, reason=None):
        require(phase in ("recovery_required", "exported", "expired"), "launch_phase")
        with closing(self.connect()) as db, db:
            changed = db.execute("UPDATE launches SET phase=?, reason=? WHERE attempt=? AND phase='claimed'",
                                 (phase, reason, attempt)).rowcount
            require(changed == 1, "launch_claim_missing")
