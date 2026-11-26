"""Verify an archived attempt against the reader's independently provisioned inputs."""
import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from collector import CHALLENGE_LIMIT, PACK_LIMIT, TRUST_LIMIT, Verifier, bounded, digest
from deliver import verify_receipt


def verify(download, runtime, manifest, trust_path, challenge_path, public_key):
    return verify_archive(download, trust_path, challenge_path, public_key, Verifier(runtime, manifest))


def verify_archive(download, trust_path, challenge_path, public_key, replay):
    pack = bounded(download / "pack.json", PACK_LIMIT)
    trust = bounded(trust_path, TRUST_LIMIT)
    challenge = bounded(challenge_path, CHALLENGE_LIMIT)
    if (trust != bounded(download / "trust.json", TRUST_LIMIT)
            or challenge != bounded(download / "challenge.json", CHALLENGE_LIMIT)):
        raise ValueError("archived context differs from reader's trusted context")
    archived = bounded(download / "verdict.json", 8192)
    original = json.loads(archived)
    actual = replay(pack, trust, challenge)
    fields = ("version", "status", "claim", "identity_scope", "event_id", "record_sha384")
    if (actual["status"], actual["claim"], actual["identity_scope"]) != (
            "verified_exec", "exec_committed", "authorized_workload_attempt"):
        raise ValueError("execution proof rejected")
    if any(actual[k] != original[k] for k in fields):
        raise ValueError("archived verdict differs from independent verification")
    key = serialization.load_pem_public_key(bounded(public_key, 4096))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("expected Ed25519 collector key")
    expected = {"version": 1, "purpose": "execution-proof.collector.receipt",
                "attempt_id": json.loads(trust)["admission"]["attempt_id"],
                "event_id": actual["event_id"], "record_sha384": actual["record_sha384"],
                "pack_sha384": digest(pack), "trust_sha384": digest(trust),
                "challenge_sha384": digest(challenge), "verdict_sha384": digest(archived)}
    verify_receipt(json.loads(bounded(download / "receipt.json", 8192)), key, expected)
    return {k: actual[k] for k in fields} | {"attempt_id": expected["attempt_id"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("download", "runtime", "manifest", "trust", "challenge", "public-key"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    result = verify(args.download, args.runtime, args.manifest, args.trust, args.challenge, args.public_key)
    print(json.dumps(result, sort_keys=True))
