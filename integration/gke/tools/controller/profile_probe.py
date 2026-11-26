"""Check the prepared normal Authority and KBS inputs on their trusted helper."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import time

import run


def probe(config, request, deadline):
    run.require(set(request) == {"attempt_id", "q_sha384", "boot_binding_sha384"}, "profile_probe_request")
    run.serial._identifier(request["attempt_id"])
    run.require(run.hash384(run.read(config, "signed_q")) == request["q_sha384"], "qualification_pin")
    binding = run.document(config, "issuer_config")["boot_binding"]
    run.require(run.boot_digest(binding) == request["boot_binding_sha384"]
                and run.document(config, "kbs_config")["boot_binding"] == binding, "authority_boot_binding")
    # init is create-only and fixes the store policy. Probe in a scratch
    # directory on the helper. The launch initializes its own target-bound DB.
    with tempfile.TemporaryDirectory() as directory:
        settings = dict(config, issuer_store=str(Path(directory) / "probe.sqlite"))
        run.require("authority_journal_bucket" not in settings, "profile_probe_store")
        raw = run.executor(settings, experimental=False)("normal", "init", b"", deadline)
        result = run.kube.attempt.public_json(raw, 64 << 10)
        run.require(result == {"version": 1, "purpose": "qlad.execution-proof.gcp-authority-response.v1",
                    "result": {"status": "initialized"}}, "authority_not_ready")
    raw = run.binary(config["kbs"], ["--check-startup", str(run.path(config, "kbs_config"))], deadline)
    run.require(json.loads(raw) == {"status": "startup_inputs_checked", "production_qualified": False},
                "kbs_not_ready")
    return dict(request, authority_checked=True, kbs_checked=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("settings", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    config = json.loads(run.serial._regular(args.settings, 64 << 10, private=True))
    wire = sys.stdin.buffer.read(1025)
    run.require(0 < len(wire) <= 1024, "profile_probe_request")
    print(json.dumps(probe(config, json.loads(wire), time.monotonic() + 20)))


if __name__ == "__main__":
    main()
