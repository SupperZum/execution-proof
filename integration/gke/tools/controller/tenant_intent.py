"""Durable per-container intent issuance for the trusted GKE controller."""

from contextlib import closing
import hashlib
import json
import re
import secrets
import sqlite3
import struct
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import serial_gateway as serial
from attempt_driver import require


def signed_intent_bytes(statement):
    fields = ("purpose", "audience", "authority", "tenant", "workload_id", "container_role",
              "attempt_id", "selected_manifest_sha256", "effective_launch_sha384", "profile_sha384",
              "launch_policy_sha384", "image_policy_sha384")
    require(statement.keys() == {*fields, "version", "validity"} and statement["version"] == 2,
            "tenant_intent_schema")
    window = statement["validity"]
    require(window.keys() == {"not_before", "expires"}
            and all(type(window[key]) is int for key in window)
            and 0 <= window["not_before"] < window["expires"] < (1 << 63), "tenant_intent_window")
    entries = [b"tenant-intent", *(statement[key].encode() for key in fields),
               struct.pack(">Q", window["not_before"]), struct.pack(">Q", window["expires"])]
    return b"QLAD-EXEC-PROOF\0" + struct.pack(">H", 2) + b"".join(
        struct.pack(">I", len(value)) + value for value in entries)


def verified_statement(wire, public_key):
    envelope = serial._signed_public(wire, "qlad.execution-proof.tenant-intent.v2", 2)
    statement = envelope["statement"]
    Ed25519PublicKey.from_public_bytes(public_key).verify(bytes.fromhex(envelope["signature"]),
                                                         signed_intent_bytes(statement))
    return statement


def issue_once(directory, cluster_id, inputs, fields, public_key, q_hash, q_expires, ttl, deadline, sign,
               *, normal_namespace, existing_only=False, receipt_for=None):
    serial._directory(directory)
    serial._identifier(cluster_id)
    # The assembler allows 128 ASCII characters. Each generated suffix uses 32.
    require(isinstance(normal_namespace, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", normal_namespace)
            and not normal_namespace.startswith("qexp-"), "intent_normal_namespace")
    require(type(ttl) is int and 1 <= ttl <= 3600, "intent_ttl")
    identity = json.dumps([cluster_id, inputs["namespace"], inputs["pod_uid"],
                           inputs["container_name"], inputs["attempt"]])
    # resourceVersion guards the subsequent patch. A metadata-only update
    # does not identify a new start or change the signed launch parameters.
    request = json.dumps({"context": inputs["context"], "pod_name": inputs["pod_name"],
                          "image_ref": inputs["image_ref"], "fields": fields, "q_sha384": q_hash,
                          "tenant_key_sha384": hashlib.sha384(public_key).hexdigest(), "ttl": ttl},
                         sort_keys=True)
    remaining = deadline - time.monotonic()
    require(remaining > 0, "controller_deadline")
    database = (directory / "attempts.sqlite").as_uri()
    mode = "rw" if existing_only else "rwc"
    with closing(sqlite3.connect(f"{database}?mode={mode}", uri=True, timeout=remaining)) as db:
        db.execute("PRAGMA synchronous=EXTRA")
        db.execute("BEGIN IMMEDIATE")
        db.execute("""CREATE TABLE IF NOT EXISTS attempts (
            identity TEXT PRIMARY KEY, request TEXT NOT NULL, resource_version TEXT NOT NULL,
            wire BLOB NOT NULL, wire_sha384 TEXT NOT NULL)""")
        row = db.execute("SELECT request, wire, wire_sha384 FROM attempts WHERE identity=?",
                         (identity,)).fetchone()
        now = int(time.time())
        if row is None:
            require(not existing_only, "missing_committed_intent")
            cutoff = min(now + ttl, q_expires)
            require(now < cutoff, "tenant_intent_window")
            expected = dict(fields, purpose="qlad.execution-proof.tenant-intent.v2", version=2,
                            workload_id=normal_namespace + secrets.token_hex(16),
                            attempt_id=normal_namespace + secrets.token_hex(16),
                            validity={"not_before": now, "expires": cutoff})
            wire = sign(expected)
            require(verified_statement(wire, public_key) == expected, "intent_signer_result")
            db.execute("INSERT INTO attempts VALUES (?,?,?,?,?)",
                       (identity, request, inputs["resource_version"], wire, hashlib.sha384(wire).hexdigest()))
            window = expected["validity"]
        else:
            saved, wire, digest = row
            require(saved == request, "intent_request_conflict")
            require(hashlib.sha384(wire).hexdigest() == digest, "intent_receipt_digest")
            statement = verified_statement(wire, public_key)
            require(all(statement[key] == value for key, value in fields.items()), "intent_receipt_fields")
            for key in ("workload_id", "attempt_id"):
                value = statement[key]
                require(value.startswith(normal_namespace) and len(value) > len(normal_namespace)
                        and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value), "intent_receipt_namespace")
            window = statement["validity"]
        require(window["not_before"] <= int(time.time()) < window["expires"] <= q_expires,
                "tenant_intent_window")
        if receipt_for is not None:
            receipt = json.dumps(receipt_for(wire, q_hash), sort_keys=True)
            db.execute("""CREATE TABLE IF NOT EXISTS schedule_receipts (
                identity TEXT PRIMARY KEY, receipt TEXT NOT NULL)""")
            db.execute("INSERT INTO schedule_receipts VALUES(?,?) ON CONFLICT(identity) DO NOTHING",
                       (identity, receipt))
            stored, = db.execute("SELECT receipt FROM schedule_receipts WHERE identity=?", (identity,)).fetchone()
            require(stored == receipt, "scheduled_pod_receipt")
        require(time.monotonic() < deadline, "controller_deadline")
        db.commit()
    return wire
