"""Reconcile gated Pods in the GKE proof namespace using the tenant scheduler identity."""

import argparse
import copy
import json
import os
from pathlib import Path
import resource
import sqlite3
import subprocess
import sys
import time
from urllib.parse import urlencode

from cryptography.exceptions import InvalidSignature

import run

PODS = f"/api/v1/namespaces/{run.NAMESPACE}/pods"
ERRORS = (OSError, ValueError, KeyError, TypeError, sqlite3.Error, InvalidSignature,
          subprocess.TimeoutExpired, run.serial.GatewayError, run.cloud.protocol.AttemptError)


def public_error(error):
    if isinstance(error, (run.serial.GatewayError, run.cloud.protocol.AttemptError)):
        return str(error)
    return type(error).__name__


def reconcile(client, state, pod):
    meta = pod.get("metadata", {})
    name, uid = meta.get("name"), meta.get("uid")
    if (pod.get("kind") != "Pod" or meta.get("namespace") != run.NAMESPACE
            or not run.cloud._matches(run.cloud._DNS_LABEL, name)
            or not run.cloud._matches(run.cloud._UUID, uid) or meta.get("deletionTimestamp")):
        return
    receipt = state / (uid + ".json")
    gated = pod["spec"].get("schedulingGates") == [{"name": run.GATE}]
    if not gated and not receipt.exists():
        return
    # Always re-read the named Pod in schedule_pod_intent. Watch bytes select
    # candidates only; the API read and conditional patch bind the event UID.
    selected = copy.copy(client)
    selected.config = dict(client.config, pod_receipt=str(receipt))
    try:
        result = run.schedule_pod_intent(selected, name, uid,
                                         time.monotonic() + client.config["deadline_seconds"])
    except ERRORS as error:
        result = {"pod_uid": uid, "scheduled": False, "reason": public_error(error)}
    print(json.dumps(result, sort_keys=True), flush=True)


def list_and_watch(client, state):
    def get(query):
        return client.k(["get", "--raw", PODS + "?" + urlencode(query)], time.monotonic() + 20)

    query = {"limit": "16"}
    while True:
        page = json.loads(get(query))
        run.require(page.get("kind") == "PodList", "pod_list")
        for pod in page["items"]:
            # Kubernetes can omit type metadata from items of a typed PodList.
            reconcile(client, state, {"kind": "Pod", **pod})
        meta = page["metadata"]
        if not meta.get("continue"):
            break
        query["continue"] = meta["continue"]

    version = meta["resourceVersion"]
    run.require(isinstance(version, str) and version and version != "0", "list_resource_version")
    # Bound the buffered watch so transient scheduling errors also get a relist.
    events = get({"watch": "true", "resourceVersion": version, "timeoutSeconds": "8"})
    for line in events.splitlines():
        event = json.loads(line)
        if event["type"] == "ERROR":
            return
        if event["type"] in ("ADDED", "MODIFIED"):
            reconcile(client, state, event["object"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("deployment", type=Path)
    parser.add_argument("operator", type=Path)
    parser.add_argument("--receipts", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    run.serial._directory(args.receipts)
    profile = run.read_profile(args.deployment)
    config = json.loads(run.serial._regular(args.operator.resolve(strict=True), 64 << 10, private=True))
    seconds = config["deadline_seconds"]
    run.require(type(seconds) is int and 15 <= seconds <= 300, "deadline_seconds")
    while True:
        try:
            client = run.Clients(profile, config, time.monotonic() + seconds)
            list_and_watch(client, args.receipts)
        except ERRORS as error:
            print(json.dumps({"relist": public_error(error)}), file=sys.stderr, flush=True)
        time.sleep(1)


if __name__ == "__main__":
    main()
