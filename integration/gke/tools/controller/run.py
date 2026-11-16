#!/usr/bin/env python3
"""Drive one stock-CAA Pod or direct TDX qualification using operator-owned inputs."""

import argparse
from contextlib import contextmanager
from hashlib import file_digest, sha384
import json
import os
from pathlib import Path
import re
import resource
import stat
import struct
import subprocess
import sys
import tempfile
import time

import kubernetes_gcp_serial as cloud
import kubernetes_serial as kube
import no_swap_guard
import qualification_gcp as qualification
import qualification_serial
import serial_gateway as serial


TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
from render import read_profile  # noqa: E402
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


NAMESPACE = "execution-proof"
POD = "proof-1"
GATE = "execution-proof/attempt-bound"
BOOT_FIELDS = ("config_sha384", "producer_core_sha384",
               "artifact_manifest_sha384", "reference_policy_sha384")
require = cloud.require


def timeout(deadline, cap=30):
    remaining = min(deadline - time.monotonic(), cap)
    require(remaining > 0, "controller_deadline")
    return remaining


def run(args, deadline, *, stdin=b"", env=None, pass_fds=(), cap=4 << 20):
    result = subprocess.run(args, input=stdin, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, env=env, pass_fds=pass_fds,
                            timeout=timeout(deadline))
    require(result.returncode == 0 and len(result.stdout) <= cap, "operator_command_failed")
    return result.stdout


def read(config, name, cap=4 << 20):
    return serial._regular(path(config, name), cap)


def path(config, name):
    value = Path(config[name])
    require(value.is_absolute(), f"absolute_path_required_{name}")
    return value


def document(config, name):
    return json.loads(read(config, name))


def write_json(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def hash384(raw):
    return sha384(raw).hexdigest()


def boot_digest(binding):
    require(binding.keys() == {"version", "purpose", "profile", *BOOT_FIELDS}
            and binding["version"] == 1
            and binding["purpose"] == "qlad.execution-proof.gcp-boot-binding.v1"
            and binding["profile"] == "onb17.gcp-tdx-embedded-pe.v1", "boot_binding")
    def frame(raw):
        return struct.pack(">I", len(raw)) + raw
    transcript = b"QLAD-EXEC-PROOF\0" + struct.pack(">H", 1)
    for text in ("gcp-embedded-pe-boot-binding", binding["purpose"], binding["profile"]):
        transcript += frame(text.encode())
    for field in BOOT_FIELDS:
        serial._hex(binding[field], 48)
        transcript += frame(bytes.fromhex(binding[field]))
    return hash384(transcript)


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


def binary(pin, args, deadline, stdin=b""):
    location = path(pin, "path")
    serial._hex(pin["sha384"], 48)
    fd = os.open(location, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and bool(info.st_mode & 0o111)
                and info.st_uid in {0, os.geteuid()} and not info.st_mode & 0o022
                and 0 < info.st_size <= 128 << 20, "trusted_binary")
        require(file_digest(stream, "sha384").hexdigest() == pin["sha384"],
                "trusted_binary_pin")
        return run([f"/proc/self/fd/{fd}", *args], deadline, stdin=stdin, cap=64 << 10,
                   env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, pass_fds=(fd,))


class Clients:
    def __init__(self, profile, config, deadline):
        self.profile = profile
        self.config = config
        self.cloud = profile["project"], profile["zone"]
        # Strict argv allowlist: only caller-owned deployment inputs select an
        # authenticated context. Server readbacks never supply flags.
        number = self.gcloud(["projects", "describe", self.cloud[0],
                              "--format=value(projectNumber)"], deadline).decode().strip()
        self.scope = cloud.Scope(*self.cloud, cloud._numeric_id(number))
        image = self.gcloud(["compute", "images", "describe", profile["podvm_image"],
                             "--format=json"], deadline)
        image = json.loads(image)
        self.image_id = cloud._numeric_id(config["image_id"])
        require(image["status"] == "READY" and cloud._numeric_id(image["id"]) == self.image_id
                and "TDX_CAPABLE" in {item["type"] for item in image["guestOsFeatures"]},
                "compute_image_pin")

    def gcloud(self, arguments, deadline):
        return run(["gcloud", "--quiet", "--project", self.cloud[0], *arguments], deadline)

    def k(self, arguments, deadline):
        name = self.config["context"]
        require(re.fullmatch(r"[A-Za-z0-9_.:@-]+", name) and not name.startswith("-"),
                "kube_context")
        return run(["kubectl", "--kubeconfig", str(path(self.config, "kubeconfig")),
                    "--context", name, *arguments], deadline)

    def compute(self, resource, name, deadline):
        require(resource in ("instances", "disks") and cloud._matches(cloud._DNS_LABEL, name),
                "compute_name")
        return json.loads(self.gcloud(["compute", resource, "describe", name,
                                       "--zone", self.scope.zone, "--format=json"], deadline))

    def boot_disk(self, instance, deadline):
        source, = [row["source"] for row in instance["disks"] if row.get("boot") is True]
        return self.compute("disks", source.rsplit("/", 1)[-1], deadline)

    def pod(self, deadline):
        return json.loads(self.k(["-n", NAMESPACE, "get", "pod", POD, "-o", "json"], deadline))

    def pod_target(self, expected, deadline):
        pod = self.pod(deadline)
        peers = json.loads(self.k(["-n", NAMESPACE, "get", "peerpods", "-o", "json"], deadline))["items"]
        candidates = [peer for peer in peers if any(
            owner.get("uid") == expected.pod_uid
            for owner in peer["metadata"].get("ownerReferences", []))]
        peer, = candidates
        instance = self.compute("instances", peer["spec"]["instanceID"], deadline)
        disk = self.boot_disk(instance, deadline)
        require(instance.get("serviceAccounts", []) == [], "stock_caa_service_account")
        return cloud.bind_target(pod, peers, instance, disk, namespace=NAMESPACE, pod_name=POD,
                                 expected=expected, image_id=str(self.image_id), scope=self.scope)

    def qualification_target(self, deadline):
        name = self.config["qualification_vm"]
        instance = self.compute("instances", name, deadline)
        disk = self.boot_disk(instance, deadline)
        confidential = instance["confidentialInstanceConfig"]
        require(instance["name"] == name and instance["status"] == "RUNNING"
                and cloud._compute_link(instance["selfLink"], f"instances/{name}", self.scope)
                and confidential.get("enableConfidentialCompute", True) is True
                and confidential["confidentialInstanceType"] == "TDX"
                and instance.get("serviceAccounts", []) == [], "qualification_instance")
        require(cloud._compute_link(disk["selfLink"], f"disks/{disk['name']}", self.scope)
                and [row["source"] for row in instance["disks"] if row.get("boot") is True]
                    == [disk["selfLink"]]
                and cloud._numeric_id(disk["sourceImageId"]) == self.image_id,
                "qualification_disk")
        return qualification.QualificationTarget(self.scope, name,
            cloud._numeric_id(instance["id"]), cloud._numeric_id(disk["id"]), self.image_id)


def artifacts(config):
    values = {name: read(config, name) for name in
              ("boot_config", "producer_core", "manifest", "references", "effective_spec")}
    binding = document(config, "binding")["boot_binding"]
    keys = ("boot_config", "producer_core", "manifest", "references")
    require(all(binding[field] == hash384(values[name])
                for field, name in zip(BOOT_FIELDS, keys)), "boot_artifact_pins")
    return binding, values


def check_q(config, binding, values, deadline):
    q = document(config, "signed_q")["statement"]
    selection = document(config, "selection")
    roots = json.loads(values["boot_config"])["roots"]
    require(selection["expected"]["qualification_public_key"] == roots["qualification_public_key"],
            "qualification_signer_root")
    require(q["boot_binding_sha384"] == boot_digest(binding), "qualification_boot_binding")
    window = q["validity"]
    require(window["not_before"] <= time.time() and
            window["expires"] > time.time() + timeout(deadline, 900), "qualification_window")
    binary(config["qualification_checker"], ["check-signed", *(str(path(config, name))
           for name in ("signed_q", "selection", "evidence_dir", "qualification_public_key"))], deadline)


def check_intent(config, binding, values, image):
    wire = read(config, "signed_intent", 64 << 10)
    envelope = serial._signed_public(wire, "qlad.execution-proof.tenant-intent.v2", 2)
    statement = envelope["statement"]
    key = read(config, "tenant_public_key", 32)
    require(len(key) == 32, "tenant_public_key")
    Ed25519PublicKey.from_public_bytes(key).verify(bytes.fromhex(envelope["signature"]),
                                                  signed_intent_bytes(statement))
    require(statement["selected_manifest_sha256"] == image.rsplit(":", 1)[1]
            and statement["effective_launch_sha384"] == hash384(values["effective_spec"])
            and statement["profile_sha384"] == boot_digest(binding)
            and statement["validity"]["not_before"] <= time.time() < statement["validity"]["expires"],
            "tenant_intent_pins")
    return wire


def schedule(client, config, binding, values, deadline):
    check_q(config, binding, values, deadline)
    check_intent(config, binding, values, client.profile["workload_image"])
    receipt = path(config, "pod_receipt")
    require(config["context"].startswith(f"gke_{client.scope.project}_{client.scope.zone}_"),
            "kube_context_project_zone")
    pod = client.pod(deadline)
    uid = pod["metadata"]["uid"]
    pod_spec = pod["spec"]
    require(cloud._matches(cloud._UUID, uid) and pod_spec.get("nodeName") is None
            and pod_spec.get("schedulingGates") == [{"name": GATE}]
            and pod_spec["runtimeClassName"] == "kata-remote"
            and len(pod_spec["containers"]) == 1
            and pod_spec["containers"][0]["name"] == "workload"
            and pod_spec["containers"][0]["image"] == client.profile["workload_image"],
            "expected_gated_pod")
    write_json(receipt, {"pod_uid": uid, "context": config["context"], "image_id": client.image_id,
                         "q_sha384": hash384(read(config, "signed_q"))})
    patch = [
        {"op": "test", "path": "/metadata/uid", "value": uid},
        {"op": "test", "path": "/spec/schedulingGates", "value": [{"name": GATE}]},
        {"op": "remove", "path": "/spec/schedulingGates/0"},
    ]
    client.k(["-n", NAMESPACE, "patch", "pod", POD, "--type=json", "-p", json.dumps(patch)], deadline)
    return {"pod_uid": uid, "scheduled": True}


@contextmanager
def serial_config(target, config, deadline):
    # Serial and management keys come from different trust paths.
    with tempfile.TemporaryDirectory(prefix="onb17-proof-serial-", dir="/tmp") as temporary:
        directory = Path(temporary)
        private = path(config, "serial_key")
        known, pin = serial.prepare_known_hosts(path(config, "serial_host_public_keys"),
                                               config["serial_host_public_sha384"], directory,
                                               serial.serial_host(target.scope.zone))
        yield serial.Config(target.scope.project, target.scope.zone, target.instance, directory,
                            private, known, pin, deadline, ssh_user=config["serial_user"])


def executor(config, *, experimental):
    location = "experiment_config" if experimental else "issuer_config"
    args = ["--config", str(path(config, location)), "--signer", str(path(config, "authority_key")),
            "--collateral", str(path(config, "collateral"))]
    if not experimental:
        args += ["--qualification", str(path(config, "signed_q")), "--store", str(path(config, "issuer_store")),
                 "--capacity", "32"]
    def execute(family, operation, raw, deadline):
        allowed = ("bootstrap-only", "issue", "startup-plan", "redeem") if experimental else ("init", "request")
        require(family == ("experiment" if experimental else "normal") and operation in allowed,
                "authority_operation")
        return binary(config["authority"], [operation, *args], deadline, raw)
    return execute


def worker_command(config, tool, *args):
    worker = config["worker"]
    host, user = worker["host"], worker["user"]
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host)
            and re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", user), "worker_ssh_target")
    program = str(path(worker, tool))
    require(all(re.fullmatch(r"[A-Za-z0-9_./:@+-]+", arg) for arg in (program, *args)),
            "worker_command_arguments")
    return ["/usr/bin/ssh", "-F", "/dev/null", "-T", "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={path(worker, 'known_hosts')}", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10", "-i", str(path(worker, "key")),
            f"{user}@{host}", "sudo", "-n", program, *args]


@contextmanager
def heartbeat(config, target, deadline):
    args = worker_command(config, "heartbeat", target.expected.pod_uid, POD,
                          target.instance.rsplit("-", 1)[1])
    with subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          bufsize=0) as process:
        try:
            yield
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        markers = process.stdout.read(512).splitlines()
        require(b"ONB17_CAA_HEARTBEAT_BOUND" in markers and
                b"ONB17_CAA_HEARTBEAT_READY" in markers, "caa_heartbeat_receipt")


def worker_pin(client, config, target, deadline):
    worker = json.loads(client.k(["get", "node", target.node_name, "-o", "json"], deadline))
    require(worker["metadata"]["uid"] == config["worker"]["uid"]
            and worker["spec"]["providerID"] == config["worker"]["provider_id"], "worker_identity")


def launch(client, config, binding, values, deadline):
    check_q(config, binding, values, deadline)
    intent = check_intent(config, binding, values, client.profile["workload_image"])
    receipt = document(config, "pod_receipt")
    require(receipt["image_id"] == client.image_id and receipt["context"] == config["context"]
            and receipt["q_sha384"] == hash384(read(config, "signed_q")), "scheduled_pod_receipt")
    expected = kube.ExpectedPod(receipt["pod_uid"], "workload", 0, client.profile["workload_image"])
    target = client.pod_target(expected, deadline)
    require(str(target.instance_id) != document(config, "selection")["retired_instance_id"],
            "qualification_instance_reuse")
    issuer = read(config, "issuer_config")
    issuer_settings = json.loads(issuer)
    require(issuer_settings["boot_binding"] == binding, "authority_boot_binding")
    require(bytes(issuer_settings["tenant_public_key"]) == read(config, "tenant_public_key", 32),
            "authority_tenant_key")
    cloud.validate_issuer_pins(target, issuer, intent, values["effective_spec"])
    worker_pin(client, config, target, deadline)
    snapshot = kube.attempt.encode({"version": 1, "purpose": "onb17.kubernetes-first-pod-trust-snapshot.v1",
        "target": target.receipt(), "pod_uid": expected.pod_uid, "image_ref": expected.image_ref,
        "boot_binding": binding, "issuer_config_sha384": hash384(issuer),
        "signed_intent_sha384": hash384(intent), "q_sha384": receipt["q_sha384"]})
    write_json(path(config, "trust_snapshot"), json.loads(snapshot))
    # Hash the persisted original snapshot bytes used by the assembler.
    snapshot = read(config, "trust_snapshot")
    authority = cloud.LateCidAuthority(executor(config, experimental=False), intent, snapshot,
                                       config["execution_audience"])
    authority.initialize_normal(deadline)
    def read_target(until):
        return client.pod_target(expected, until)
    def read_worker(until):
        require(read_target(until) == target, "worker_target_changed")
        worker_pin(client, config, target, until)
        raw = run(worker_command(config, "readback", "/run/containerd/containerd.sock", expected.pod_uid,
                   expected.image_ref, "gcp-kata", NAMESPACE, POD, "0"), until, cap=4096)
        result = cloud.decode_worker_readback(raw)
        require(cloud._vm_prefix(POD) + result.sandbox_id[:8] == target.instance,
                "worker_podvm_binding")
        return result
    with heartbeat(config, target, deadline), serial_config(target, config, deadline) as serial_options, \
            management_key(config) as key:
        with cloud.GceSerial(target, serial_options, read_target) as gateway:
            return kube.drive(gateway, authority, read_worker, expected=expected,
                manifest=values["manifest"], references=values["references"],
                effective_spec=values["effective_spec"], management_key=key,
                archive_directory=path(config, "archive"), deadline=deadline, target_receipt=target.receipt())


def qualify(client, config, binding, values, deadline):
    intent = check_intent(config, binding, values, client.profile["workload_image"])
    target = client.qualification_target(deadline)
    experiment = read(config, "experiment_config")
    require(json.loads(experiment)["artifact_expectations"]["boot_binding"] == binding,
            "qualification_boot_binding")
    snapshot = qualification.derive_trust_snapshot_sha384(experiment, values["boot_config"],
        values["producer_core"], values["manifest"], values["references"], read(config, "collateral"))
    cid = config["qualification_cid"]
    selection, retire_before = qualification.validate_experiment_pins(
        target, experiment, intent, values["effective_spec"], cid=cid, image_ref=client.profile["workload_image"],
        trust_snapshot_sha384=snapshot, manifest=values["manifest"], references=values["references"])
    require(retire_before >= time.time() + timeout(deadline, 900), "qualification_retirement_window")
    def refresh(until):
        require(client.qualification_target(until) == target, "qualification_target_changed")
    authority = qualification.QualificationAuthority(executor(config, experimental=True), refresh,
                                                     selection, retire_before)
    kata = qualification_serial.KataProcess(path(config["kata"], "path"), config["kata"]["sha384"],
        cid=cid, sandbox=config["qualification_sandbox"], image=client.profile["workload_image"],
        relay_config=path(config, "relay_config"))
    with kata, serial_config(target, config, deadline) as serial_options, management_key(config) as key:
        with qualification.QualificationGceSerial(target, serial_options, refresh, cid) as gateway:
            return qualification_serial.drive(gateway, authority, kata, expected_cid=cid,
                manifest=values["manifest"], references=values["references"],
                effective_spec=values["effective_spec"], management_key=key,
                archive_directory=path(config, "archive"), deadline=deadline, target_receipt=target.receipt())


@contextmanager
def management_key(config):
    key = bytearray(serial._regular(path(config, "management_key"), 64 << 10, private=True))
    try:
        yield key
    finally:
        key[:] = b"\0" * len(key)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("describe-pod", "describe-qualification", "preflight", "schedule", "launch", "qualify"))
    parser.add_argument("deployment", type=Path)
    parser.add_argument("operator", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if args.action in ("launch", "qualify"):
        require(serial._LIBC.prctl(4, 0, 0, 0, 0) == 0, "dump_protection")
    profile = read_profile(args.deployment)
    config = json.loads(serial._regular(args.operator.resolve(strict=True), 64 << 10, private=True))
    seconds = config["deadline_seconds"]
    require(type(seconds) is int and 15 <= seconds <= 300, "deadline_seconds")
    deadline = time.monotonic() + seconds
    if args.action in ("launch", "qualify"):
        no_swap_guard.verify(config["unit"])
    if args.action == "preflight":
        binding, values = artifacts(config)
        check_intent(config, binding, values, profile["workload_image"])
        if Path(config["signed_q"]).exists():
            check_q(config, binding, values, deadline)
        print(json.dumps({"public_inputs_checked": True}))
        return 0
    client = Clients(profile, config, deadline)
    if args.action == "describe-qualification":
        result = client.qualification_target(deadline).receipt()
    elif args.action == "describe-pod":
        receipt = document(config, "pod_receipt")
        require(receipt["context"] == config["context"] and receipt["image_id"] == client.image_id,
                "scheduled_pod_receipt")
        result = client.pod_target(kube.ExpectedPod(receipt["pod_uid"], "workload", 0,
                                   profile["workload_image"]), deadline).receipt()
    else:
        binding, values = artifacts(config)
        function = {"schedule": schedule, "launch": launch, "qualify": qualify}[args.action]
        result = function(client, config, binding, values, deadline)
    print(json.dumps(result, sort_keys=True))
    if args.action in ("launch", "qualify") and not result.get("protected_export_available"):
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired, InvalidSignature,
            cloud.protocol.AttemptError, serial.GatewayError, no_swap_guard.GuardError) as error:
        # Protocol exceptions expose fixed labels. Never emit repr of input
        # files or command output from tools handling credentials.
        reason = str(error) if isinstance(error, (cloud.protocol.AttemptError, serial.GatewayError,
                                                  no_swap_guard.GuardError)) else type(error).__name__
        sys.exit("execution proof controller stopped: " + reason)
