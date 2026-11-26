"""Persist a single-worker assignment and pin its SSH identity through Compute."""

import base64
from contextlib import closing
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import re
import sqlite3

import kubernetes_gcp_serial as cloud
import serial_gateway as serial

require = cloud.require
POOL = "cloud.google.com/gke-nodepool"
HOST = "kubernetes.io/hostname"
ISOLATE = "node-restriction.kubernetes.io/onb17"
ED25519 = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"


def worker_identity(node, name, scope, pool):
    meta, spec, status = node["metadata"], node["spec"], node["status"]
    labels = meta["labels"]
    provider = f"gce://{scope.project}/{scope.zone}/{name}"
    require(cloud._matches(cloud._DNS_LABEL, name)
            and meta["name"] == labels.get(HOST) == name
            and cloud._matches(cloud._UUID, meta.get("uid"))
            and spec["providerID"] == provider and labels.get(POOL) == pool
            and labels.get(ISOLATE) == "true" and "deletionTimestamp" not in meta
            and any(t == {"key": "execution-proof/worker", "value": "true", "effect": "NoSchedule"}
                    for t in spec.get("taints", ())),
            "worker_pool_identity")
    (ip,) = [str(IPv4Address(item["address"])) for item in status["addresses"]
             if item["type"] == "InternalIP"]
    return {"name": name, "uid": meta["uid"], "provider_id": provider, "host": ip}


def available(node, requested):
    meta, spec, status = node["metadata"], node["spec"], node["status"]
    return ((requested is None or meta["name"] == requested)
            and (not spec.get("unschedulable"))
            and "deletionTimestamp" not in meta
            and meta.get("labels", {}).get("katacontainers.io/kata-runtime") == "true"
            and any(x["type"] == "Ready" and x["status"] == "True" for x in status.get("conditions", ())))


def compute_identity(client, worker, deadline):
    instance = client.compute("instances", worker["name"], deadline)
    network = f"projects/{client.scope.project}/global/networks/{client.profile['network']}"
    (nic,) = instance["networkInterfaces"]
    require(instance["name"] == worker["name"] and instance["status"] == "RUNNING"
            and cloud._compute_link(instance["selfLink"], f"instances/{worker['name']}", client.scope)
            and nic["networkIP"] == worker["host"] and nic["network"].endswith("/" + network),
            "worker_compute_identity")
    return str(cloud._numeric_id(instance["id"]))


def host_key(console):
    blocks = re.findall(r"(?s)-----BEGIN SSH HOST KEY KEYS-----\s+(.*?)-----END SSH HOST KEY KEYS-----", console)
    keys = set(re.findall(r"\bssh-ed25519 ([A-Za-z0-9+/]+={0,2})", "\n".join(blocks)))
    require(len(keys) == 1, "worker_host_key")
    (key,) = keys
    raw = base64.b64decode(key, validate=True)
    require(len(raw) == len(ED25519) + 32 and raw.startswith(ED25519), "worker_host_key")
    return "ssh-ed25519 " + key


def allocate(directory, cluster, attempt, candidates):
    with closing(sqlite3.connect(directory / "workers.sqlite", timeout=5)) as db, db:
        db.execute("PRAGMA synchronous=EXTRA")
        db.execute("""CREATE TABLE IF NOT EXISTS assignments (
            cluster TEXT, attempt TEXT, name TEXT, uid TEXT, provider_id TEXT, host TEXT,
            PRIMARY KEY(cluster, attempt), UNIQUE(cluster, uid))""")
        db.execute("BEGIN IMMEDIATE")
        existing = db.execute(
            "SELECT name,uid,provider_id,host FROM assignments WHERE cluster=? AND attempt=?",
            (cluster, attempt)).fetchone()
        if existing:
            return dict(zip(("name", "uid", "provider_id", "host"), existing))
        for worker in candidates:
            result = db.execute(
                "INSERT INTO assignments VALUES(?,?,?,?,?,?) ON CONFLICT(cluster,uid) DO NOTHING",
                (cluster, attempt, worker["name"], worker["uid"], worker["provider_id"], worker["host"]))
            if result.rowcount:
                return worker
        raise cloud.protocol.AttemptError("worker_pool_exhausted")


def assign(client, config, receipt, pod, deadline):
    profile = config["worker_pool"]
    pool = profile["name"]
    require(cloud._matches(cloud._DNS_LABEL, pool) and client.reader is not None, "worker_pool_settings")
    storage = Path(profile["state"])
    serial._directory(storage)
    attempt = receipt["attempt_id"]
    serial._identifier(attempt)
    requested = pod["spec"]["nodeSelector"].get(HOST)
    nodes = json.loads(client.k(["get", "nodes", "-l", f"{POOL}={pool},{ISOLATE}=true",
                                 "-o", "json"], deadline))["items"]
    candidates = [worker_identity(node, node["metadata"]["name"], client.scope, pool)
                  for node in sorted(nodes, key=lambda node: node["metadata"]["name"]) if available(node, requested)]
    worker = allocate(storage, receipt["cluster_id"], attempt, candidates)
    require(worker in candidates, "worker_assignment_unavailable")
    instance_id = compute_identity(client, worker, deadline)
    key = host_key(client.reader.serial_output(worker["name"], deadline))
    require(compute_identity(client, worker, deadline) == instance_id, "worker_compute_changed")

    # Refreshing an existing attempt must keep the same Compute identity and
    # host key. The node IP is useful only with this pinned host key.
    pinned = storage / (worker["uid"] + ".host")
    expected = f"[{worker['host']}]:2222 {key} {instance_id}\n"
    try:
        with pinned.open("x") as out:
            out.write(expected)
            out.flush()
            os.fsync(out.fileno())
    except FileExistsError:
        require(pinned.read_text() == expected, "worker_host_key_changed")
    return {**worker, "pool": pool, "instance_id": instance_id, "port": 2222,
            "user": "onb17-worker", "key": profile["key"], "known_hosts": str(pinned),
            "single_guest": "/run/execution-proof/single-guest",
            "readback": "/run/execution-proof/worker-readback",
            "heartbeat": "/run/execution-proof/caa-heartbeat"}


def check(client, config, name, node, deadline):
    expected = {key: config[key] for key in ("name", "host", "uid", "provider_id")}
    current = worker_identity(node, name, client.scope, config["pool"])
    require(current == expected and compute_identity(client, current, deadline) == config["instance_id"],
            "worker_pool_changed")
