#!/usr/bin/env python3
"""Verify GCP TDX execution packs against a relying-party Pod enrollment."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from uuid import UUID


TOOLS = ("verifier", "tdx-worker", "gcp-bootstrap-worker")
UID_SOURCE = "trusted_kubernetes_api_and_launch_handoff"
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
EXPECTATIONS_PURPOSE = "onb17.kubernetes-pod-execution-expectations.v1"
FIRST_POD_EXPECTATIONS_PURPOSE = "onb17.kubernetes-first-pod-execution-expectations.v1"


class VerificationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def read_regular(path, limit):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "expected regular input file")
        raw = stream.read(limit + 1)
    require(0 < len(raw) <= limit, "input size rejected")
    return raw


def decode(raw):
    def object_from_pairs(pairs):
        result = dict(pairs)
        require(len(result) == len(pairs), "duplicate JSON key")
        return result

    return json.loads(raw, object_pairs_hook=object_from_pairs)


def sha384(raw):
    return hashlib.sha384(raw).hexdigest()


def distinct(rows, fields):
    for field in fields:
        require(len({row[field] for row in rows}) == len(rows), f"duplicate {field}")


def check_plan(plan, *, first_pod=False):
    purpose = FIRST_POD_EXPECTATIONS_PURPOSE if first_pod else EXPECTATIONS_PURPOSE
    require(plan["purpose"] == purpose, "expectations purpose rejected")
    require(plan["uid_source"] == UID_SOURCE, "trusted API and launch handoff required")
    require(bool(plan["cluster"]) and DNS_LABEL.fullmatch(plan["namespace"]), "cluster or namespace missing")
    image = re.fullmatch(r"[^\s@]+@sha256:([0-9a-f]{64})", plan["encrypted_image"])
    require(image is not None, "expected digest-pinned encrypted image")
    pods = plan["pods"]
    expected_pods = 1 if first_pod else 3
    require(isinstance(pods, list) and len(pods) == expected_pods,
            "expected one first Pod" if first_pod else "expected three Pods")
    for pod in pods:
        require(DNS_LABEL.fullmatch(pod["name"]), "invalid Pod name")
        require(str(UUID(pod["pod_uid"])) == pod["pod_uid"], "invalid Pod UID")
        require(all(pod[field] for field in ("workload_id", "attempt_id", "boot_id", "container_id")),
                "missing launch binding")
        instance = pod["gcp_instance"]
        for field in ("instance_id", "numerical_project_id"):
            require(re.fullmatch(r"[1-9][0-9]{0,19}", instance[field]), "invalid numeric GCE identity")
        require(DNS_LABEL.fullmatch(instance["zone"]), "invalid GCE zone")
    distinct(pods, ("name", "pod_uid", "workload_id", "attempt_id", "boot_id", "container_id", "challenge_sha384"))
    distinct([pod["gcp_instance"] for pod in pods], ("instance_id",))
    return image.group(1)


def summarize_verified(pod, manifest_sha256, pack_raw, challenge, verdict):
    # The pinned verifier authenticates these fields on these same pack bytes.
    pack = decode(pack_raw)
    bootstrap = pack["bootstrap"]
    for field in ("workload_id", "attempt_id"):
        require(bootstrap["challenge"][field] == pod[field], f"{pod['name']} {field} mismatch")
    require(bootstrap["binding"]["boot_id"] == pod["boot_id"], f"{pod['name']} boot_id mismatch")
    execution = pack["execution"]
    provenance = decode(bytes(execution["provenance"]))["body"]
    require(provenance["manifest_sha256"] == manifest_sha256, f"{pod['name']} encrypted manifest mismatch")
    record = decode(bytes(execution["record"]))
    quote = decode(bytes(execution["quote"]))
    require(record["task"]["container_id"] == pod["container_id"], f"{pod['name']} application container mismatch")
    require(verdict["event_id"] == record["event_id"], f"{pod['name']} event mismatch")
    require(verdict["record_sha384"] == challenge["record_sha384"], f"{pod['name']} record mismatch")
    return {
        "name": pod["name"],
        "pod_uid": pod["pod_uid"],
        "workload_id": pod["workload_id"],
        "attempt_id": pod["attempt_id"],
        "boot_id": pod["boot_id"],
        "container_id": pod["container_id"],
        "gcp_instance": pod["gcp_instance"],
        "bootstrap_quote_sha384": sha384(bytes(bootstrap["evidence"]["tdx_quote"])),
        "execution_quote_sha384": sha384(bytes(quote["tdx_quote"])),
        "execution_challenge_nonce": challenge["nonce"],
        "pack_sha384": sha384(pack_raw),
        "event_id": verdict["event_id"],
        "record_sha384": verdict["record_sha384"],
        "verdict": verdict,
    }


def verify_pod(args, pod, tool_paths, tool_pins, manifest_sha256, tmp):
    name = pod["name"]
    relying_party = args.expectations.parent / name
    pack = read_regular(args.packs / name / "pack.json", 16 << 20)
    trust = read_regular(relying_party / "trust.json", 1 << 20)
    challenge = read_regular(relying_party / "challenge.json", 16 << 10)
    require(sha384(trust) == pod["trust_sha384"], f"{name} trust pin mismatch")
    require(sha384(challenge) == pod["challenge_sha384"], f"{name} challenge pin mismatch")
    verified_instance = decode(trust)["quote"]["boot_policy"]["expected_instance"]
    require(all(str(verified_instance[field]) == pod["gcp_instance"][field]
                for field in ("instance_id", "numerical_project_id", "zone")), f"{name} GCE identity mismatch")

    # Run on private snapshots so the extracted fields come from the checked bytes.
    for filename, raw in (("pack.json", pack), ("trust.json", trust), ("challenge.json", challenge)):
        (tmp / filename).write_bytes(raw)
    result = subprocess.run(
        [tool_paths["verifier"], "--pack", "pack.json", "--trust", "trust.json", "--challenge", "challenge.json",
         "--tdx-worker", tool_paths["tdx-worker"], "--tdx-worker-sha384", tool_pins["tdx-worker"],
         "--gcp-bootstrap-worker", tool_paths["gcp-bootstrap-worker"],
         "--gcp-bootstrap-worker-sha384", tool_pins["gcp-bootstrap-worker"]],
        cwd=tmp, env={"PATH": "/usr/bin:/bin", "LANG": "C"}, timeout=35,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
    )
    require(result.returncode == 0, f"{name} independent verifier exit {result.returncode}")
    verdict = decode(result.stdout)
    require(
        verdict["version"] == 2 and verdict["status"] == "verified_exec"
        and verdict["claim"] == "exec_committed" and verdict["identity_scope"] == "authorized_workload_attempt",
        f"{name} unexpected independent verdict",
    )
    return summarize_verified(pod, manifest_sha256, pack, decode(challenge), verdict)


def verify(args):
    raw = read_regular(args.expectations, 64 << 10)
    require(sha384(raw) == args.expectations_sha384, "expectations pin mismatch")
    plan = decode(raw)
    manifest_sha256 = check_plan(plan, first_pod=args.first_pod)
    tool_pins = plan["tools_sha384"]
    tool_paths = {key: getattr(args, key.replace("-", "_")).resolve(strict=True) for key in TOOLS}
    preload = Path("/etc/ld.so.preload")
    require(not preload.exists() and not preload.is_symlink(), "system loader preload present")
    for key, path in tool_paths.items():
        with path.open("rb") as stream:
            require(hashlib.file_digest(stream, "sha384").hexdigest() == tool_pins[key], f"{key} pin mismatch")

    with tempfile.TemporaryDirectory(prefix="onb17-verify-") as directory:
        results = [verify_pod(args, pod, tool_paths, tool_pins, manifest_sha256, Path(directory)) for pod in plan["pods"]]
    distinct(results, ("event_id", "record_sha384", "execution_challenge_nonce", "bootstrap_quote_sha384",
                       "execution_quote_sha384", "pack_sha384"))
    return {
        "purpose": ("onb17.kubernetes-first-pod-execution-report.v1" if args.first_pod
                    else "onb17.kubernetes-pod-execution-report.v1"),
        "cluster": plan["cluster"],
        "namespace": plan["namespace"],
        "encrypted_image": plan["encrypted_image"],
        "uid_source": plan["uid_source"],
        "expectations_sha384": args.expectations_sha384,
        "pods": results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expectations", required=True, type=Path)
    parser.add_argument("--expectations-sha384", required=True)
    parser.add_argument("--packs", required=True, type=Path)
    parser.add_argument("--first-pod", action="store_true",
                        help="verify the first Pod using separately pinned one-Pod expectations")
    for key in TOOLS:
        parser.add_argument(f"--{key}", required=True, type=Path)
    try:
        print(json.dumps(verify(parser.parse_args()), indent=2))
    except VerificationError as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    except (OSError, KeyError, TypeError, ValueError, AttributeError, RecursionError, subprocess.SubprocessError):
        print("verification failed: malformed or unavailable input", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
