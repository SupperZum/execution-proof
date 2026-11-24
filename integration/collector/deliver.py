"""Deliver a completed verifier pack and validate the collector's durable receipt."""
import argparse
import base64
from contextlib import closing
import http.client
import json
from pathlib import Path
import re
import socket

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from collector import CHALLENGE_LIMIT, DOMAIN, ID, PACK_LIMIT, PREFIX, TRUST_LIMIT, bounded, digest, encode


class LocalConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=90)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def verify_receipt(receipt, key, expected):
    if set(receipt) != {"statement", "signature"}:
        raise ValueError("invalid receipt envelope")
    statement = receipt["statement"]
    key.verify(base64.b64decode(receipt["signature"], validate=True), DOMAIN + encode(statement))
    if statement != expected:
        raise ValueError("receipt belongs to different evidence")


def deliver(directory, socket_path, key):
    pack = bounded(directory / "pack.json", PACK_LIMIT)
    trust = bounded(directory / "trust.json", TRUST_LIMIT)
    challenge = bounded(directory / "challenge.json", CHALLENGE_LIMIT)
    return submit(pack, trust, challenge, socket_path, key)


def submit(pack, trust, challenge, socket_path, key):
    attempt = json.loads(trust)["admission"]["attempt_id"]
    if not re.fullmatch(ID, attempt):
        raise ValueError("invalid attempt ID")
    record = json.loads(pack)["execution"]["record"]
    if not isinstance(record, list):
        raise ValueError("expected encoded execution record bytes")
    event = json.loads(bytes(record))["event_id"]
    # The verifier authenticates the contract's framed record digest against
    # this independently selected challenge. The receipt also binds the full pack.
    record_hash = json.loads(challenge)["record_sha384"]
    path = PREFIX + attempt
    with closing(LocalConnection(socket_path)) as connection:
        connection.request("PUT", path + "/pack", pack, {"Content-Type": "application/json"})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f"collector returned HTTP {response.status}")
        receipt = json.loads(response.read(8192))
    with closing(LocalConnection(socket_path)) as connection:
        connection.request("GET", path + "/verdict")
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("stored verdict unavailable")
        verdict = response.read(8192)
    result = json.loads(verdict)
    if (result.get("status"), result.get("claim"), result.get("identity_scope"),
            result.get("event_id"), result.get("record_sha384")) != (
            "verified_exec", "exec_committed", "authorized_workload_attempt", event, record_hash):
        raise ValueError("stored verdict mismatches the submission")
    verify_receipt(receipt, key, {
        "version": 1, "purpose": "execution-proof.collector.receipt", "attempt_id": attempt,
        "event_id": event, "record_sha384": record_hash, "pack_sha384": digest(pack),
        "trust_sha384": digest(trust), "challenge_sha384": digest(challenge),
        "verdict_sha384": digest(verdict),
    })
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    options = parser.parse_args()
    public = serialization.load_pem_public_key(bounded(options.public_key, 4096))
    if not isinstance(public, Ed25519PublicKey):
        parser.error("expected Ed25519 collector public key")
    print(encode(deliver(options.bundle, options.socket, public)).decode())
