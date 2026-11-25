#!/usr/bin/env python3
"""Package the GKE worker bootstrap and render the dedicated pool manifests."""

import argparse
import base64
from hashlib import file_digest, sha384
import io
import json
from pathlib import Path
import re
import shutil
import ssl
import sys
import tarfile

import yaml

HERE = Path(__file__).resolve().parent
GKE = HERE.parents[1]
sys.path.insert(0, str(GKE / "tools"))
import render as stock

POOL = "cloud.google.com/gke-nodepool"
ISOLATION = "node-restriction.kubernetes.io/onb17"
TAINT = "execution-proof/worker"
TOLERATION = {"key": TAINT, "operator": "Equal", "value": "true", "effect": "NoSchedule"}
WORKER_FILES = ("single-guest", "worker-readback", "caa-heartbeat")


def digest(path, algorithm="sha384"):
    with path.open("rb") as stream:
        return file_digest(stream, algorithm).hexdigest()


def pack(args):
    worker = GKE / "worker"
    files = {name: args.binaries / name for name in WORKER_FILES}
    pins = json.loads(args.binary_pins.read_bytes())
    for name, path in files.items():
        stock.require(digest(path) == pins[name], f"unexpected binary digest: {name}")
    for name in ("check-runtime.sh", "import-caa.sh"):
        files[name] = worker / name
    for name in ("onb17-single-guest.service", "onb17-single-guest.socket"):
        files[name] = worker / "single-guest" / name
    for name in ("caa-linux-amd64.oci.tar", "caa-build-receipt.json"):
        files[name] = args.assets / name
    caa = stock.checked_caa_image(args.assets)
    mapping = (worker / "cri-images.toml").read_bytes()
    stock.require(mapping.startswith(b"version = 3\n"), "expected containerd config v3")
    generated = {"cri-images.toml": mapping.removeprefix(b"version = 3\n"),
                 "caa-image.json": json.dumps(caa, sort_keys=True).encode() + b"\n"}
    if args.registry_ca:
        ca = args.registry_ca.read_text(encoding="ascii")
        certificate = r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----"
        stock.require(re.fullmatch(fr"\s*(?:{certificate}\s*)+", ca), "expected a public CA certificate bundle")
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=ca)
        generated["registry-ca.crt"] = ca.encode("ascii")
    if args.controller_public_key:
        stock.require(args.profile is not None, "--controller-public-key requires --profile")
        profile = stock.read_profile(args.profile)
        key_line, = args.controller_public_key.read_text(encoding="ascii").strip().splitlines()
        algorithm, key, *_ = key_line.split()
        stock.require(algorithm == "ssh-ed25519", "expected a controller Ed25519 public key")
        wire = base64.b64decode(key, validate=True)
        stock.require(len(wire) == 51 and wire.startswith(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"),
                      "invalid Ed25519 public key")
        generated["worker-access.json"] = json.dumps({
            "key": f"{algorithm} {key}", "image": profile["workload_image"]}, sort_keys=True).encode() + b"\n"
        for name in ("worker-access.py", "onb17-worker-access.service"):
            files[name] = HERE / name
    args.output.mkdir(mode=0o700)
    for name in ("Dockerfile", "entrypoint.sh", "install-worker.sh"):
        shutil.copyfile(HERE / name, args.output / name)
    archive = args.output / "worker.tar"
    with tarfile.open(archive, "w") as bundle:
        for name, path in sorted(files.items()):
            entry = tarfile.TarInfo(name)
            entry.size = path.stat().st_size
            entry.mode = 0o644
            with path.open("rb") as stream:
                bundle.addfile(entry, stream)
        for name, raw in sorted(generated.items()):
            entry = tarfile.TarInfo(name)
            entry.size = len(raw)
            entry.mode = 0o644
            bundle.addfile(entry, io.BytesIO(raw))
    members = {name: digest(path) for name, path in files.items()}
    members.update({name: sha384(raw).hexdigest() for name, raw in generated.items()})
    receipt = {"worker_sha384": digest(archive), "caa": caa, "members": members}
    print(json.dumps(receipt, indent=2, sort_keys=True))


def dedicated(scheduling, pool):
    selector = {POOL: pool, ISOLATION: "true", "kubernetes.io/arch": "amd64",
                "kubernetes.io/os": "linux"}
    scheduling.setdefault("nodeSelector", {}).update(selector)
    scheduling.setdefault("tolerations", []).append(TOLERATION)


def scope_caa(objects):
    workload_roles = {"pod-viewer", "peerpod-editor"}
    omitted = {"cm-editor", "pp-secrets"}
    result = []
    for obj in objects:
        kind = obj["kind"]
        meta = obj["metadata"]
        name = meta["name"]
        if name in omitted:
            continue
        if name in workload_roles:
            meta["namespace"] = stock.WORKLOAD_NS
            obj["kind"] = {"ClusterRole": "Role", "ClusterRoleBinding": "RoleBinding"}[kind]
            if kind == "ClusterRole" and name == "pod-viewer":
                for rule in obj["rules"]:
                    rule["verbs"] = ["get"]
        if obj["kind"].endswith("RoleBinding"):
            role = obj["roleRef"]
            if name in workload_roles:
                role["kind"] = "Role"
            if role["kind"] == "ClusterRole":
                role["name"] = "onb17-caa-" + role["name"]
        if obj["kind"] in ("ClusterRole", "ClusterRoleBinding"):
            meta["name"] = "onb17-caa-" + name
        result.append(obj)
    # CAA startup lists Pods with spec.nodeName across namespaces so it can
    # restore PeerPod connections after an adaptor restart.
    name = "onb17-caa-node-pods"
    subject, = [obj["metadata"] for obj in result if obj["kind"] == "ServiceAccount"]
    api = "rbac.authorization.k8s.io"
    result.extend([
        {"apiVersion": api + "/v1", "kind": "ClusterRole", "metadata": {"name": name},
         "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["list"]}]},
        {"apiVersion": api + "/v1", "kind": "ClusterRoleBinding", "metadata": {"name": name},
         "roleRef": {"apiGroup": api, "kind": "ClusterRole", "name": name},
         "subjects": [{"kind": "ServiceAccount", "name": subject["name"], "namespace": subject["namespace"]}]},
    ])
    return result


def manifests(args):
    stock.require(re.fullmatch(stock.DNS, args.pool), "invalid proof pool name")
    stock.require(re.fullmatch(r"[a-f0-9]{96}", args.worker_sha384), "expected worker SHA-384")
    stock.require(re.fullmatch(r"[a-z0-9][a-z0-9._:/-]+@" + stock.DIGEST, args.installer),
                  "expected a digest-pinned installer image")
    profile = stock.read_profile(args.profile)
    stock.verify_charts(args.assets)
    caa_image = stock.checked_caa_image(args.assets)
    kata_chart = args.assets / "charts/kata-deploy-4.0.0.tgz"
    # Values follow the same order as the two source profiles. The single-guest
    # drop-in is the only difference from the stock Kata render.
    values = yaml.safe_load((GKE / "templates/kata-values.yaml").read_bytes())
    private = yaml.safe_load((GKE / "templates/kata-single-guest-values.yaml").read_bytes())
    values["shims"]["remote"]["dropIn"] = private["shims"]["remote"]["dropIn"]
    kata = [obj for obj in stock.helm(kata_chart, "proof-kata", values, profile["kubernetes_version"])
            if "helm.sh/hook" not in obj["metadata"].get("annotations", {})]
    kata_ds, = [obj for obj in kata if obj["kind"] == "DaemonSet"]
    runtime, = [obj for obj in kata if obj["kind"] == "RuntimeClass"]
    spec = kata_ds["spec"]["template"]["spec"]
    stock.require(spec.get("hostPID") is True, "Kata installer needs the node's PID namespace")
    dedicated(spec, args.pool)
    dedicated(runtime["scheduling"], args.pool)
    spec.setdefault("volumes", []).append({
        "name": "onb17-worker", "hostPath": {
            "path": "/var/lib/onb17-worker-install", "type": "DirectoryOrCreate"}})
    spec.setdefault("initContainers", []).append({
        "name": "onb17-worker", "image": args.installer,
        "env": [{"name": "WORKER_SHA384", "value": args.worker_sha384},
                {"name": "NODE_IP", "valueFrom": {"fieldRef": {"fieldPath": "status.hostIP"}}}],
        "securityContext": {"privileged": True, "readOnlyRootFilesystem": True},
        "volumeMounts": [{"name": "onb17-worker", "mountPath": "/worker"}],
        "resources": {"requests": {"cpu": "25m", "memory": "32Mi"}}})

    caa = scope_caa(stock.caa_manifests(profile, args.assets, caa_image, namespace_finalizers=True))
    caa_ds, = [obj for obj in caa if obj["kind"] == "DaemonSet"]
    caa_config, = [obj for obj in caa if obj["kind"] == "ConfigMap"]
    caa_config["data"]["PEERPODS_LIMIT_PER_NODE"] = "1"
    caa_ds["spec"]["updateStrategy"] = {"type": "RollingUpdate", "rollingUpdate": {"maxUnavailable": 1}}
    caa_spec = caa_ds["spec"]["template"]["spec"]
    caa_spec["nodeSelector"].pop("node.kubernetes.io/worker", None)
    dedicated(caa_spec, args.pool)
    pod = yaml.safe_load((GKE / "templates/pod.yaml").read_bytes())
    pod["spec"]["containers"][0]["image"] = profile["workload_image"]
    namespaces = [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": stock.WORKLOAD_NS}},
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": stock.RUNTIME_NS,
         "labels": {"pod-security.kubernetes.io/enforce": "privileged"}}},
    ]
    args.output.mkdir(mode=0o700)
    for name, objects in (("namespaces", namespaces), ("kata", kata), ("caa", caa), ("pod", [pod])):
        with (args.output / f"{name}.yaml").open("x") as stream:
            yaml.safe_dump_all(objects, stream, explicit_start=True, sort_keys=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    package = commands.add_parser("pack")
    package.add_argument("--binaries", type=Path, required=True)
    package.add_argument("--binary-pins", type=Path, required=True)
    package.add_argument("--registry-ca", type=Path)
    package.add_argument("--controller-public-key", type=Path)
    package.add_argument("--profile", type=Path)
    manifest = commands.add_parser("manifests")
    manifest.add_argument("--profile", type=Path, required=True)
    manifest.add_argument("--pool", required=True)
    manifest.add_argument("--installer", required=True)
    manifest.add_argument("--worker-sha384", required=True)
    for command in (package, manifest):
        command.add_argument("--assets", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        (pack if args.command == "pack" else manifests)(args)
    except (ValueError, OSError, KeyError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
