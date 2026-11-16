from pathlib import Path
import argparse
import base64
import hashlib
import json
import time

from run import binary

parser = argparse.ArgumentParser(description="Independently verify both qualification TDX quotes.")
parser.add_argument("archive", type=Path)
parser.add_argument("config", type=Path)
parser.add_argument("experiment", type=Path)
parser.add_argument("collateral", type=Path)
parser.add_argument("expected_binding")
parser.add_argument("workers", type=Path, help="JSON with bootstrap_worker and execution_worker path/SHA-384 pins")
parser.add_argument("out", type=Path)
args = parser.parse_args()
if not __debug__:
    raise SystemExit("Run without Python optimization to retain all verification checks")
workers = json.loads(args.workers.read_bytes())


def digest(raw):
    return hashlib.sha384(raw).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def check(stem, worker, request, reason):
    wire = json.dumps(request, separators=(",", ":")).encode()
    (args.out / f"{stem}-request.json").write_bytes(wire)
    response_wire = binary(workers[worker], [], time.monotonic() + 60, wire)
    assert len(response_wire) <= 16384
    (args.out / f"{stem}-response.json").write_bytes(response_wire)
    response = json.loads(response_wire)
    assert response["status"] == "checked"
    assert response["reason"] == reason and response["facts"]["boot_binding_sha384"] == args.expected_binding
    return response["facts"]


args.out.mkdir(mode=0o700)
experiment = read(args.experiment)
config = read(args.config)
authority_wire = (args.archive / "challenge.json").read_bytes()
challenge = json.loads(authority_wire)["statement"]
submission = read(args.archive / "bootstrap.json")["submission"]
export = read(args.archive / "export.json")
plan = read(args.archive / "plan.json")["statement"]
record_raw = base64.b64decode(export["record_b64"], validate=True)
envelope_raw = base64.b64decode(export["quote_b64"], validate=True)
(args.out / "record.original.json").write_bytes(record_raw)
(args.out / "envelope.original.json").write_bytes(envelope_raw)
record = json.loads(record_raw)
envelope = json.loads(envelope_raw)
assert export["purpose"] == "qlad.execution-proof.protected-export.v2"
assert record["claim"] == "exec_committed" and record["task"]["container_id"] == experiment["container_id"]
assert plan["container_id"] == experiment["container_id"]
assert envelope["challenge"]["audience"] == experiment["execution_audience"]
assert envelope["challenge"]["trust_snapshot_sha384"] == plan["trust_snapshot_sha384"]
assert envelope["challenge"]["boot_binding"] == experiment["artifact_expectations"]["boot_binding"]
assert challenge["boot_binding"] == envelope["challenge"]["boot_binding"]
collateral = list(args.collateral.read_bytes())
pregrant = {
    "version": 3, "purpose": "qlad.execution-proof.gcp-pregrant-hardware-request.v3",
    "expected_challenge": challenge, "authority_public_key": config["roots"]["authority_public_key"],
    "signed_challenge_json": list(authority_wire), "binding": submission["binding"],
    "evidence": submission["evidence"], "boot_policy": experiment["boot_policy"],
    "module_policy": experiment["module_policy"], "collateral_json": collateral,
}
bootstrap = check("bootstrap-history", "bootstrap_worker", {
    "version": 1, "purpose": "qlad.execution-proof.gcp-bootstrap-history-request.v1", "bootstrap": pregrant,
}, "historical_bootstrap_hardware_checked")
raw_quote = bytes(envelope["tdx_quote"])
assert len(raw_quote) == 8000 and int.from_bytes(raw_quote[:2], "little") == 4
# The pinned worker independently derives all 64 bytes from typed R and the
# challenge, checks equality with this field and authenticates the raw quote.
execution = check("execution-hardware", "execution_worker", {
    "version": 2, "purpose": "qlad.execution-proof.gcp-hardware-request.v2", "envelope": envelope,
    "record": record, "expected_report_data": raw_quote[568:632].hex(),
    "expected_boot_binding_sha384": args.expected_binding, "boot_policy": experiment["boot_policy"],
    "module_policy": experiment["module_policy"], "collateral_json": collateral,
}, "hardware_and_boot_predicates_checked")
assert bootstrap["mr_owner"] == execution["mr_owner"] and bootstrap["mr_td"] == execution["mr_td"]
assert bootstrap["quote_sha384"] != execution["quote_sha384"]
assert bootstrap["quote_sha384"] == digest(bytes(submission["evidence"]["tdx_quote"]))
assert execution["quote_sha384"] == digest(raw_quote)
print(json.dumps({"bootstrap_checked": True, "execution_quote_checked": True,
                  "bootstrap_quote_sha384": bootstrap["quote_sha384"],
                  "execution_quote_sha384": execution["quote_sha384"],
                  "original_export_sha384": digest((args.archive / "export.json").read_bytes()),
                  "producer_qualified": False, "execution_verified": False}))
