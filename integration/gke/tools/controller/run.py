#!/usr/bin/env python3
"""Drive one stock-CAA Pod or direct TDX qualification using operator-owned inputs."""

import argparse
import fcntl
from contextlib import contextmanager
from hashlib import file_digest, sha384
import json
import os
from pathlib import Path
import re
import resource
import selectors
import stat
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time

import yaml

import gce_reader
import kubernetes_gcp_serial as cloud
import kubernetes_serial as kube
import no_swap_guard
import pool_worker
import qualification_gcp as qualification
import qualification_serial
import archive_delivery
import serial_gateway as serial
import tenant_intent
from launch_queue import LaunchQueue


TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
from render import DIGEST, ROOT, read_profile  # noqa: E402
from cryptography.exceptions import InvalidSignature


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


def _command(args, deadline, *, stdin=b"", env=None, pass_fds=(), cap=4 << 20):
    seconds = timeout(deadline)
    until = min(deadline, time.monotonic() + seconds)
    output = bytearray()
    pending = memoryview(stdin)
    with subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env=env, pass_fds=pass_fds, bufsize=0) as process, selectors.DefaultSelector() as io:
        try:
            io.register(process.stdout, selectors.EVENT_READ)
            if pending:
                os.set_blocking(process.stdin.fileno(), False)
                io.register(process.stdin, selectors.EVENT_WRITE)
            else:
                process.stdin.close()
            while io.get_map():
                remaining = until - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(args, seconds)
                for key, _ in io.select(remaining):
                    if key.fileobj is process.stdout:
                        chunk = os.read(key.fd, min(65536, cap - len(output) + 1))
                        if chunk:
                            require(len(chunk) <= cap - len(output), "operator_command_failed")
                            output.extend(chunk)
                        else:
                            io.unregister(key.fd)
                    else:
                        try:
                            written = os.write(key.fd, pending[:65536])
                            pending = pending[written:]
                        except BrokenPipeError:
                            pending = pending[:0]
                        if not pending:
                            io.unregister(key.fd)
                            process.stdin.close()
            status = process.wait(timeout=max(0, until - time.monotonic()))
            return subprocess.CompletedProcess(args, status, bytes(output))
        except subprocess.TimeoutExpired:
            raise subprocess.TimeoutExpired(args, seconds, output=bytes(output)) from None
        finally:
            if process.returncode is None:
                process.kill()


def run(args, deadline, **kwargs):
    result = _command(args, deadline, **kwargs)
    require(result.returncode == 0, "operator_command_failed")
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


def boot_binding_v1(binding):
    return type(binding) is dict and type(binding.get("version")) is int and binding["version"] == 1


def boot_digest(binding):
    require(boot_binding_v1(binding) and binding.keys() == {"version", "purpose", "profile", *BOOT_FIELDS}
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


def run_authority_request(args, deadline, **kwargs):
    try:
        result = _command(args, deadline, **kwargs)
    except subprocess.TimeoutExpired as error:
        return interrupted_authority_response(error.stdout)
    if result.returncode == 1 or result.returncode < 0 or (result.returncode == 0 and not result.stdout):
        return interrupted_authority_response(result.stdout)
    require(result.returncode == 0, "operator_command_failed")
    return result.stdout


def interrupted_authority_response(raw):
    # The CLI emits one JSON line. On interruption it may have written only a prefix.
    if not raw:
        raise cloud.frontend.AuthorityUnavailable("authority_response_lost")
    try:
        response = kube.attempt.public_json(raw, 64 << 10)
    except serial.GatewayError as error:
        if error.code == "invalid_json" and not raw.endswith(b"\n"):
            raise cloud.frontend.AuthorityUnavailable("authority_response_lost") from None
        raise
    require(type(response) is dict and type(response.get("result")) is dict
            and response["result"].get("status") == "error", "operator_command_failed")
    return raw


def binary(pin, args, deadline, stdin=b"", *, invoke=run):
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
        return invoke([f"/proc/self/fd/{fd}", *args], deadline, stdin=stdin, cap=64 << 10,
                      env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, pass_fds=(fd,))


class KubernetesClient:
    def __init__(self, profile, config):
        self.profile = profile
        self.config = config

    def k(self, arguments, deadline):
        name = self.config["context"]
        require(re.fullmatch(r"[A-Za-z0-9_.:@-]+", name) and not name.startswith("-"),
                "kube_context")
        return run(["kubectl", "--kubeconfig", str(path(self.config, "kubeconfig")),
                    "--context", name, *arguments], deadline)

    def pod(self, deadline, name=POD):
        require(cloud._matches(cloud._DNS_LABEL, name), "pod_name")
        return json.loads(self.k(["-n", NAMESPACE, "get", "pod", name, "-o", "json"], deadline))


class Clients(KubernetesClient):
    def __init__(self, profile, config, deadline):
        super().__init__(profile, config)
        self.cloud = profile["project"], profile["zone"]
        # Strict argv allowlist: only caller-owned deployment inputs select an
        # authenticated context. Server readbacks never supply flags.
        self.reader = None
        if "gce_read_identity" in config:
            self.reader = gce_reader.GceReader(*self.cloud, config["gce_read_identity"], deadline)
            number = self.reader.project_number(deadline)
            image = self.reader.image(profile["podvm_image"], deadline)
        else:
            number = self.gcloud(["projects", "describe", self.cloud[0],
                                  "--format=value(projectNumber)"], deadline).decode().strip()
            image = json.loads(self.gcloud(["compute", "images", "describe", profile["podvm_image"],
                                              "--format=json"], deadline))
        self.scope = cloud.Scope(*self.cloud, cloud._numeric_id(number))
        self.image_id = cloud._numeric_id(config["image_id"])
        require(image["status"] == "READY" and cloud._numeric_id(image["id"]) == self.image_id
                and "TDX_CAPABLE" in {item["type"] for item in image["guestOsFeatures"]},
                "compute_image_pin")

    def gcloud(self, arguments, deadline):
        return run(["gcloud", "--quiet", "--project", self.cloud[0], *arguments], deadline)

    def compute(self, resource, name, deadline):
        require(resource in ("instances", "disks") and cloud._matches(cloud._DNS_LABEL, name),
                "compute_name")
        if self.reader is not None:
            return self.reader.zonal(resource, name, deadline)
        return json.loads(self.gcloud(["compute", resource, "describe", name,
                                       "--zone", self.scope.zone, "--format=json"], deadline))

    def boot_disk(self, instance, deadline):
        source, = [row["source"] for row in instance["disks"] if row.get("boot") is True]
        return self.compute("disks", source.rsplit("/", 1)[-1], deadline)

    def pod_target(self, expected, deadline, name=POD):
        pod = self.pod(deadline, name)
        peers = json.loads(self.k(["-n", NAMESPACE, "get", "peerpods", "-o", "json"], deadline))["items"]
        candidates = [peer for peer in peers if any(
            owner.get("uid") == expected.pod_uid
            for owner in peer["metadata"].get("ownerReferences", []))]
        peer, = candidates
        instance = self.compute("instances", peer["spec"]["instanceID"], deadline)
        disk = self.boot_disk(instance, deadline)
        require(instance.get("serviceAccounts", []) == [], "stock_caa_service_account")
        return cloud.bind_target(pod, peers, instance, disk, namespace=NAMESPACE, pod_name=name,
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


def boot_artifacts(config):
    keys = ("boot_config", "producer_core", "manifest", "references")
    values = {name: read(config, name) for name in keys}
    binding = document(config, "binding")["boot_binding"]
    require(all(binding[field] == hash384(values[name])
                for field, name in zip(BOOT_FIELDS, keys)), "boot_artifact_pins")
    return binding, values


def artifacts(config):
    binding, values = boot_artifacts(config)
    values["effective_spec"] = read(config, "effective_spec")
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
    return selection


def check_intent(config, binding, values, image):
    wire = read(config, "signed_intent", 64 << 10)
    key = read(config, "tenant_public_key", 32)
    require(len(key) == 32, "tenant_public_key")
    statement = tenant_intent.verified_statement(wire, key)
    require(statement["selected_manifest_sha256"] == image.rsplit(":", 1)[1]
            and statement["effective_launch_sha384"] == hash384(values["effective_spec"])
            and statement["profile_sha384"] == boot_digest(binding)
            and statement["validity"]["not_before"] <= time.time() < statement["validity"]["expires"],
            "tenant_intent_pins")
    return wire


def scheduling_gate(pod, uid, image):
    spec = pod["spec"]
    require(pod["metadata"]["uid"] == uid and not pod["metadata"].get("deletionTimestamp")
            and spec["runtimeClassName"] == "kata-remote" and len(spec["containers"]) == 1
            and spec["containers"][0]["name"] == "workload"
            and spec["containers"][0]["image"] == image, "expected_gated_pod")
    gates = spec.get("schedulingGates", [])
    if gates == []:
        return False
    require(gates == [{"name": GATE}] and spec.get("nodeName") is None, "expected_gated_pod")
    return True


def check_schedule_receipt(saved, expected):
    # JSON booleans and floating-point numbers cannot stand in for integer IDs or timestamps.
    require(json.dumps(saved, sort_keys=True) == json.dumps(expected, sort_keys=True), "scheduled_pod_receipt")


def bind_schedule_receipt(config, expected, gated, *, deadline=None):
    receipt = path(config, "pod_receipt")
    directory = os.open(receipt.parent, os.O_DIRECTORY | os.O_RDONLY)
    try:
        # Serialize publishers and keep the receipt complete for concurrent readers.
        while True:
            try:
                fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if deadline is None:
                    raise
                time.sleep(timeout(deadline, 0.01))
        if os.path.lexists(receipt):
            check_schedule_receipt(document(config, "pod_receipt"), expected)
            os.fsync(directory)
            return
        require(gated, "expected_gated_pod")
        with tempfile.NamedTemporaryFile(dir=receipt.parent, delete=False) as pending:
            try:
                pending.write((json.dumps(expected, sort_keys=True) + "\n").encode())
                pending.flush()
                os.fsync(pending.fileno())
                os.replace(pending.name, receipt)
                os.fsync(directory)
            finally:
                Path(pending.name).unlink(missing_ok=True)
    finally:
        os.close(directory)


def patch_gate(client, name, uid, image, deadline, *, resource_version=None, worker_node=None):
    patch = [
        {"op": "test", "path": "/metadata/uid", "value": uid},
        {"op": "test", "path": "/spec/schedulingGates", "value": [{"name": GATE}]},
        {"op": "test", "path": "/spec/containers/0/image", "value": image},
        {"op": "remove", "path": "/spec/schedulingGates/0"},
    ]
    if resource_version is not None:
        patch.insert(1, {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version})
    if worker_node is not None:
        require(resource_version is not None and cloud._matches(cloud._DNS_LABEL, worker_node), "worker_node_selector")
        patch.insert(-1, {"op": "add", "path": "/spec/nodeSelector/kubernetes.io~1hostname", "value": worker_node})
    client.k(["-n", NAMESPACE, "patch", "pod", name, "--type=json", "-p", json.dumps(patch)], deadline)


def schedule(client, config, binding, values, deadline):
    check_q(config, binding, values, deadline)
    image = client.profile["workload_image"]
    check_intent(config, binding, values, image)
    require(config["context"].startswith(f"gke_{client.scope.project}_{client.scope.zone}_"),
            "kube_context_project_zone")
    pod = client.pod(deadline)
    uid = pod["metadata"]["uid"]
    require(cloud._matches(cloud._UUID, uid), "expected_gated_pod")
    gated = scheduling_gate(pod, uid, image)
    receipt = {"pod_uid": uid, "context": config["context"], "image_id": client.image_id,
               "q_sha384": hash384(read(config, "signed_q"))}
    bind_schedule_receipt(config, receipt, gated)
    if gated:
        for attempt in range(2):
            try:
                patch_gate(client, POD, uid, image, deadline)
                break
            except (cloud.protocol.AttemptError, subprocess.TimeoutExpired):
                if not scheduling_gate(client.pod(deadline), uid, image):
                    break
                if attempt == 1:
                    raise
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
        journal = []
        if not experimental and "authority_journal_bucket" in config:
            bucket = config["authority_journal_bucket"]
            require(type(bucket) is str and re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", bucket),
                    "authority_journal_bucket")
            journal = ["--journal-bucket", bucket]
        invoke = run_authority_request if not experimental and operation == "request" else run
        return binary(config["authority"], [operation, *args, *journal], deadline, raw, invoke=invoke)
    return execute


def worker_command(config, tool, *args):
    worker = config["worker"]
    host, user = worker["host"], worker["user"]
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host)
            and re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", user), "worker_ssh_target")
    program = str(path(worker, tool))
    require(all(re.fullmatch(r"[A-Za-z0-9_./:@+-]+", arg) for arg in (program, *args)),
            "worker_command_arguments")
    port = worker.get("port", 22)
    require(type(port) is int and 1 <= port <= 65535, "worker_ssh_target")
    return ["/usr/bin/ssh", "-F", "/dev/null", "-T", "-p", str(port), "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={path(worker, 'known_hosts')}", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10", "-i", str(path(worker, "key")),
            f"{user}@{host}", "sudo", "-n", program, *args]


@contextmanager
def heartbeat(config, target, deadline):
    args = worker_command(config, "heartbeat", target.expected.pod_uid, target.pod_name,
                          target.instance.rsplit("-", 1)[1])
    with subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          bufsize=0) as process:
        def stop_helper():
            process.stdin.close()
            try:
                return process.wait(timeout=min(4, max(0, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                process.kill()
                return process.wait()

        def ready_receipt():
            os.set_blocking(process.stdout.fileno(), False)
            return process.stdout.read(512) == b"ONB17_CAA_HEARTBEAT_BOUND\nONB17_CAA_HEARTBEAT_READY\n"

        def finish():
            running = process.poll() is None
            status = stop_helper()
            require(running and status == 0, "caa_heartbeat_exit")
            require(ready_receipt(), "caa_heartbeat_receipt")

        try:
            yield finish
            if not process.stdin.closed:
                finish()
        except Exception as error:
            if not process.stdin.closed and stop_helper() != 0 and ready_receipt():
                error.add_note("caa_heartbeat_exit")
            raise
        finally:
            if not process.stdin.closed:
                stop_helper()


def worker_pin(client, config, target, deadline):
    worker = json.loads(client.k(["get", "node", target.node_name, "-o", "json"], deadline))
    if "pool" in config["worker"]:
        pool_worker.check(client, config["worker"], target.node_name, worker, deadline)
    require(worker["metadata"]["uid"] == config["worker"]["uid"]
            and worker["spec"]["providerID"] == config["worker"]["provider_id"], "worker_identity")


def launch(client, config, binding, values, deadline, *, name=POD, uid=None, outcome=None):
    receipt = document(config, "pod_receipt")
    image = client.profile["workload_image"]
    if uid is None:
        require(receipt.keys() == {"pod_uid", "context", "image_id", "q_sha384"}, "launch_event_uid_required")
        if "effective_spec" not in values:
            values = dict(values, effective_spec=read(config, "effective_spec"))
        check_q(config, binding, values, deadline)
        intent = check_intent(config, binding, values, image)
        require(receipt["image_id"] == client.image_id and receipt["context"] == config["context"]
                and receipt["q_sha384"] == hash384(read(config, "signed_q")), "scheduled_pod_receipt")
        uid = receipt["pod_uid"]
        effective_spec = values["effective_spec"]
    else:
        require(cloud._matches(cloud._UUID, uid) and receipt.get("pod_uid") == uid
                and receipt.get("pod_name") == name, "scheduled_pod_receipt")
        pod = read_intent_pod(client, name, deadline)
        inputs = pod_intent_inputs(client, name, pod, gate_open=True)
        require(inputs["pod_uid"] == uid, "pod_identity")
        intent, q_hash = committed_pod_intent(config, inputs, binding, values["boot_config"], deadline,
                                              existing_only=True)
        check_schedule_receipt(receipt, schedule_receipt(client, inputs, intent, q_hash))
        effective_spec = inputs["effective_spec"].encode()
    expected = kube.ExpectedPod(uid, "workload", 0, image)
    target = client.pod_target(expected, deadline, name)
    require(str(target.instance_id) != document(config, "selection")["retired_instance_id"],
            "qualification_instance_reuse")
    issuer = read(config, "issuer_config")
    issuer_settings = json.loads(issuer)
    issuer_binding = issuer_settings["boot_binding"]
    require(boot_binding_v1(issuer_binding) and issuer_binding == binding, "authority_boot_binding")
    require(bytes(issuer_settings["tenant_public_key"]) == read(config, "tenant_public_key", 32),
            "authority_tenant_key")
    cloud.validate_issuer_pins(target, issuer, intent, effective_spec)
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
        return client.pod_target(expected, until, name)
    def read_worker(until):
        require(read_target(until) == target, "worker_target_changed")
        worker_pin(client, config, target, until)
        raw = run(worker_command(config, "readback", "/run/containerd/containerd.sock", expected.pod_uid,
                   expected.image_ref, "gcp-kata", target.namespace, target.pod_name, "0"), until, cap=4096)
        result = cloud.decode_worker_readback(raw)
        require(cloud._vm_prefix(target.pod_name) + result.sandbox_id[:8] == target.instance,
                "worker_podvm_binding")
        return result
    confirm_archive = None
    if "collector_tls" in config or "collector_socket" in config:
        require(not ("collector_tls" in config and "collector_socket" in config), "collector_transport")
        destination = (archive_delivery.Endpoint(path(config, "collector_tls")) if "collector_tls" in config
                       else path(config, "collector_socket"))
        confirm_archive = archive_delivery.Relay(destination,
            json.loads(intent)["statement"]["attempt_id"])
    with heartbeat(config, target, deadline) as finish_heartbeat, serial_config(target, config, deadline) as serial_options, \
            management_key(config) as key:
        with cloud.GceSerial(target, serial_options, read_target) as gateway:
            return kube.drive(gateway, authority, read_worker, expected=expected,
                manifest=values["manifest"], references=values["references"],
                effective_spec=effective_spec, management_key=key,
                archive_directory=path(config, "archive"), deadline=deadline, target_receipt=target.receipt(),
                before_stop=finish_heartbeat, outcome=outcome, confirm_archive=confirm_archive)


def qualify(client, config, binding, values, deadline, *, outcome=None):
    intent = check_intent(config, binding, values, client.profile["workload_image"])
    target = client.qualification_target(deadline)
    experiment = read(config, "experiment_config")
    experiment_binding = json.loads(experiment)["artifact_expectations"]["boot_binding"]
    require(boot_binding_v1(experiment_binding) and experiment_binding == binding,
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
    confirmation = (archive_delivery.qualification_confirmation(path(config, "qualification_export_receipt"))
                    if "qualification_export_receipt" in config else None)
    with kata, serial_config(target, config, deadline) as serial_options, management_key(config) as key:
        with qualification.QualificationGceSerial(target, serial_options, refresh, cid) as gateway:
            return qualification_serial.drive(gateway, authority, kata, expected_cid=cid,
                manifest=values["manifest"], references=values["references"],
                effective_spec=values["effective_spec"], management_key=key,
                archive_directory=path(config, "archive"), deadline=deadline, target_receipt=target.receipt(),
                outcome=outcome, confirm_archive=confirmation)


@contextmanager
def management_key(config):
    key = bytearray(serial._regular(path(config, "management_key"), 64 << 10, private=True))
    try:
        yield key
    finally:
        key[:] = b"\0" * len(key)


def controller_attempt(function, *args, **kwargs):
    outcome = kube.AttemptOutcome()
    try:
        result = function(*args, outcome=outcome, **kwargs)
    except Exception:
        print(json.dumps({"protected_export_available": outcome.protected_export_available,
                          "transport_completed": outcome.transport_completed,
                          "retirement": "external"}, sort_keys=True), flush=True)
        raise
    return result | {"retirement": "external"}


def worker_ready(client, config, receipt, deadline):
    # Clients already read the project and the pinned Compute image with the
    # credentials of this process. Exercise the remaining pre-guest endpoints.
    pod = read_intent_pod(client, receipt["pod_name"], deadline)
    expected_worker = config["worker"]
    requested = pod["spec"]["nodeSelector"].get("kubernetes.io/hostname")
    node = expected_worker.get("name", requested)
    require(node and cloud._matches(cloud._DNS_LABEL, node), "worker_node_selector")
    require(requested in (None, node), "worker_node_selector")
    worker = json.loads(client.k(["get", "node", node, "-o", "json"], deadline))
    if "pool" in expected_worker:
        pool_worker.check(client, expected_worker, node, worker, deadline)
    require(worker["metadata"]["uid"] == expected_worker["uid"]
            and worker["spec"]["providerID"] == expected_worker["provider_id"]
            and worker["metadata"]["labels"]["kubernetes.io/hostname"] == node, "worker_identity")
    peers = json.loads(client.k(["-n", NAMESPACE, "get", "peerpods", "-o", "json"], deadline))
    require(not any(owner.get("uid") == receipt["pod_uid"] for peer in peers["items"]
                    for owner in peer["metadata"].get("ownerReferences", [])), "prior_peerpod")
    # Validate the local mTLS settings. Receipt lookup and delivery can retry
    # independently once the guest has exported the proof.
    archive_delivery.Endpoint(path(config, "collector_tls"))
    host = serial.serial_host(client.scope.zone)
    with tempfile.TemporaryDirectory() as work:
        known, _ = serial.prepare_known_hosts(path(config, "serial_host_public_keys"),
                            config["serial_host_public_sha384"], Path(work), host)
        scanned = run(["/usr/bin/ssh-keyscan", "-T", "4", "-p", "9600", host], deadline)
        require(set(known.read_bytes().splitlines()).intersection(scanned.splitlines()), "serial_host_key")
    with management_key(config):
        pass
    request = {"attempt_id": receipt["attempt_id"], "q_sha384": receipt["q_sha384"],
               "boot_binding_sha384": boot_digest(document(config, "binding")["boot_binding"])}
    response = binary(config["profile_probe"], [], deadline, json.dumps(request).encode())
    require(json.loads(response) == dict(request, authority_checked=True, kbs_checked=True), "profile_not_ready")
    run(worker_command(config, "single_guest", "ready", receipt["pod_uid"]), deadline)


def wait_for_peer(client, name, uid, deadline):
    while True:
        pod = client.pod(deadline, name)
        require(pod["metadata"]["uid"] == uid and not pod["metadata"].get("deletionTimestamp"), "pod_identity")
        peers = json.loads(client.k(["-n", NAMESPACE, "get", "peerpods", "-o", "json"], deadline))
        matches = [p for p in peers["items"] if any(o.get("uid") == uid
                   for o in p["metadata"].get("ownerReferences", []))]
        require(len(matches) <= 1, "multiple_peerpods")
        if matches and matches[0].get("spec", {}).get("instanceID") and pod["spec"].get("nodeName"):
            return
        time.sleep(timeout(deadline, 0.25))


def queued_launch(client, config, binding, values, deadline, *, name, uid):
    receipt = document(config, "pod_receipt")
    require(receipt.get("pod_uid") == uid and receipt.get("pod_name") == name
            and receipt.get("cluster_id") == config["intent_cluster_id"], "scheduled_pod_receipt")
    queue = LaunchQueue(path(config, "launch_queue"))
    queue.claim(receipt)
    attempt = receipt["attempt_id"]
    config = dict(config)
    try:
        def preflight(current):
            check_schedule_receipt(receipt, current)
            if "worker_pool" in config:
                pod = read_intent_pod(client, name, deadline)
                scheduling_gate(pod, uid, client.profile["workload_image"])
                config["worker"] = pool_worker.assign(client, config, current, pod, deadline)
            worker_ready(client, config, current, deadline)
            if "worker_pool" in config:
                return config["worker"]["name"]
        reconcile_pod_intent(client, name, uid, deadline, before_patch=preflight)
        wait_for_peer(client, name, uid, deadline)
        result = controller_attempt(launch, client, config, binding, values, deadline, name=name, uid=uid)
    except Exception as error:
        reason = str(error) if isinstance(error, (cloud.protocol.AttemptError, serial.GatewayError)) else type(error).__name__
        phase = "expired" if reason in ("tenant_intent_window", "qualification_window") else "recovery_required"
        queue.finish(attempt, phase, reason)
        raise
    phase = "exported" if result.get("protected_export_available") else "recovery_required"
    queue.finish(attempt, phase)
    return result


def select_pod_inputs(client, name, deadline):
    """Read a persisted, gated Pod and select the inputs to its first tenant intent."""
    return pod_intent_inputs(client, name, read_intent_pod(client, name, deadline))


def read_intent_pod(client, name, deadline):
    require(client.config["context"].startswith(f"gke_{client.profile['project']}_{client.profile['zone']}_"),
            "kube_context_project_zone")
    return client.pod(deadline, name)


def pod_intent_inputs(client, name, pod, *, gate_open=False):
    meta = cloud._object(pod, "metadata")
    spec = cloud._object(pod, "spec")
    require(pod.get("apiVersion") == "v1" and pod.get("kind") == "Pod"
            and meta.get("namespace") == NAMESPACE and meta.get("name") == name
            and cloud._matches(cloud._DNS_LABEL, name) and cloud._matches(cloud._UUID, meta.get("uid"))
            and isinstance(meta.get("resourceVersion"), str) and meta["resourceVersion"]
            and not meta.get("deletionTimestamp"), "pod_identity")
    status = pod.get("status", {})
    require(isinstance(status, dict) and (gate_open or status.get("phase", "Pending") == "Pending"),
            "pod_phase")

    statuses = status.get("containerStatuses", [])
    require(isinstance(statuses, list) and len(statuses) <= 1 and all(
        isinstance(row, dict) and row.get("name") == "workload"
        and type(row.get("restartCount")) is int and row["restartCount"] == 0 for row in statuses),
        "pod_start_number")

    template = yaml.safe_load((ROOT / "templates/pod.yaml").read_text())
    require(meta.get("annotations", {}) == template["metadata"]["annotations"], "pod_annotations")
    expected = template["spec"]
    if gate_open:
        # Only scheduling state may advance while recovering a committed intent.
        require(spec.get("schedulingGates", []) == [], "expected_open_gate")
        expected.pop("schedulingGates")
        spec = {key: value for key, value in spec.items() if key not in ("schedulingGates", "nodeName")}
    containers = spec.get("containers")
    require(type(containers) is list and len(containers) == 1 and type(containers[0]) is dict,
            "container_profile")
    app = containers[0]
    image = app.get("image")
    require(image == client.profile["workload_image"] and type(image) is str
            and re.fullmatch(r"[a-z0-9][a-z0-9._:/-]+@" + DIGEST, image), "pod_image")
    expected_app = expected.pop("containers")[0]
    expected_app["image"] = image
    for field, default in (("resources", {}), ("terminationMessagePath", "/dev/termination-log"),
                           ("terminationMessagePolicy", "File")):
        if field in app:
            expected_app[field] = default
    # Keep JSON booleans distinct from integers in securityContext.
    require(json.dumps(app, sort_keys=True) == json.dumps(expected_app, sort_keys=True),
            "container_profile")

    # GKE can augment scheduling fields when admitting the Pod. These fields
    # do not supply inputs to the protected application process.
    selectors = spec.get("nodeSelector", {})
    require(isinstance(selectors, dict) and selectors.get("kubernetes.io/arch") == "amd64",
            "pod_node_selector")
    expected["nodeSelector"] = selectors
    for field, default in (("dnsPolicy", "ClusterFirst"), ("securityContext", {}),
                           ("serviceAccount", "default"), ("serviceAccountName", "default")):
        if field in spec:
            expected[field] = default
    scheduling = {"containers", "overhead", "priority", "preemptionPolicy", "schedulerName",
                  "tolerations", "terminationGracePeriodSeconds"}
    actual = {key: value for key, value in spec.items() if key not in scheduling}
    require(json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True), "pod_profile")

    # Preserve the exact spec encoding used by the guest and verifier.
    wire = (ROOT / "templates/pod-effective-spec.example.json").read_bytes()
    hostname = f'"HOSTNAME={template["metadata"]["name"]}"'.encode()
    require(wire.count(hostname) == 1, "effective_spec_hostname")
    wire = wire.replace(hostname, f'"HOSTNAME={name}"'.encode())
    return {"context": client.config["context"], "namespace": NAMESPACE, "pod_name": name,
            "pod_uid": meta["uid"], "resource_version": meta["resourceVersion"],
            "container_name": app["name"], "container_role": "application-init", "attempt": 0,
            "image_ref": image, "selected_manifest_sha256": image.rsplit(":", 1)[1],
            "effective_spec": wire.decode(), "effective_launch_sha384": hash384(wire)}


def issue_pod_intent(client, name, deadline):
    inputs = select_pod_inputs(client, name, deadline)
    config = client.config
    binding = document(config, "binding")["boot_binding"]
    wire, _ = committed_pod_intent(config, inputs, binding, read(config, "boot_config"), deadline)
    return wire


def committed_pod_intent(config, inputs, binding, boot, deadline, *, existing_only=False, receipt_for=None):
    settings = document(config, "issuer_config")
    require(settings["boot_binding"] == binding and hash384(boot) == binding["config_sha384"],
            "authority_boot_binding")
    public_key = read(config, "tenant_public_key", 32)
    require(len(public_key) == 32 and settings["tenant_public_key"] == list(public_key),
            "authority_tenant_key")

    # Snapshot both files so issuance uses the Q and namespace checked together.
    with tempfile.TemporaryDirectory() as work:
        work = Path(work)
        q_wire = read(config, "signed_q")
        q_path = work / "qualification.json"
        q_path.write_bytes(q_wire)
        selection_path = work / "selection.json"
        selection_path.write_bytes(read(config, "selection", 32 << 10))
        selection = check_q(dict(config, signed_q=str(q_path), selection=str(selection_path)),
                            binding, {"boot_config": boot}, deadline)
        q_expires = json.loads(q_wire)["statement"]["validity"]["expires"]
        fields = {key: settings[key] for key in (
            "audience", "authority", "tenant", "launch_policy_sha384", "image_policy_sha384")}
        fields.update(profile_sha384=boot_digest(binding), container_role=inputs["container_role"],
                      selected_manifest_sha256=inputs["selected_manifest_sha256"],
                      effective_launch_sha384=inputs["effective_launch_sha384"])

        def sign(statement):
            unsigned = work / "statement.json"
            signed = work / "signed.json"
            write_json(unsigned, statement)
            binary(config["intent_signer"], ["tenant-intent", str(unsigned), str(path(config, "tenant_key")),
                   str(path(config, "tenant_public_key")), str(signed)], deadline)
            return serial._regular(signed, 64 << 10)

        q_hash = hash384(q_wire)
        wire = tenant_intent.issue_once(path(config, "intent_store"), config["intent_cluster_id"],
                                       inputs, fields, public_key, q_hash, q_expires,
                                       config["intent_ttl_seconds"], deadline, sign,
                                       normal_namespace=selection.get("normal_namespace"),
                                       existing_only=existing_only, receipt_for=receipt_for)
        return wire, q_hash


def schedule_receipt(client, inputs, wire, q_hash):
    statement = json.loads(wire)["statement"]
    return {"pod_uid": inputs["pod_uid"], "pod_name": inputs["pod_name"], "namespace": inputs["namespace"],
            "context": inputs["context"], "cluster_id": client.config["intent_cluster_id"],
            "image_id": client.image_id, "q_sha384": q_hash, "signed_intent_sha384": hash384(wire),
            "attempt_id": statement["attempt_id"], "workload_id": statement["workload_id"],
            "validity": statement["validity"], "effective_launch_sha384": inputs["effective_launch_sha384"]}


def schedule_pod_intent(client, name, uid, deadline):
    require("launch_queue" in client.config, "launch_queue_required")
    queue = LaunchQueue(path(client.config, "launch_queue"))
    return reconcile_pod_intent(client, name, uid, deadline, queue=queue)


def reconcile_pod_intent(client, name, uid, deadline, *, queue=None, before_patch=None):
    """Publish a checked receipt or open its gate from the claimed launch worker."""
    require((queue is None) != (before_patch is None), "launch_handoff_mode")
    config = client.config
    image = client.profile["workload_image"]
    require(cloud._matches(cloud._UUID, uid), "pod_identity")

    binding, values = boot_artifacts(config)

    def read_and_bind(prior=None):
        pod = read_intent_pod(client, name, deadline)
        gated = scheduling_gate(pod, uid, image)
        inputs = pod_intent_inputs(client, name, pod, gate_open=not gated)
        saved = os.path.lexists(path(config, "pod_receipt"))
        if prior is not None:
            require(saved and document(config, "pod_receipt") == prior, "scheduled_pod_receipt")
        if before_patch is not None:
            require(saved, "missing_schedule_receipt")
        if not saved:
            require(gated, "missing_schedule_receipt")
        def receipt_for(wire, q_hash):
            receipt = schedule_receipt(client, inputs, wire, q_hash)
            if saved:
                check_schedule_receipt(document(config, "pod_receipt"), receipt)
            return receipt

        wire, q_hash = committed_pod_intent(config, inputs, binding, values["boot_config"], deadline,
                                            existing_only=saved, receipt_for=receipt_for)
        receipt = schedule_receipt(client, inputs, wire, q_hash)
        bind_schedule_receipt(config, receipt, gated, deadline=deadline)
        return gated, inputs["resource_version"], receipt

    gated, version, receipt = read_and_bind()
    if queue is not None:
        queue.publish(receipt)
        return {"pod_uid": uid, "queued": True, "gate_open": not gated,
                "attempt_id": receipt["attempt_id"], "signed_intent_sha384": receipt["signed_intent_sha384"]}
    require(gated, "gate_open_before_worker")
    for attempt in range(2):
        window = receipt["validity"]
        require(window["not_before"] <= time.time() < window["expires"], "tenant_intent_window")
        if not gated:
            break
        node = before_patch(receipt)
        require(time.time() < window["expires"], "tenant_intent_window")
        try:
            patch_gate(client, name, uid, image, deadline, resource_version=version, worker_node=node)
            break
        except (cloud.protocol.AttemptError, subprocess.TimeoutExpired):
            gated, version, receipt = read_and_bind(receipt)
            if gated and attempt == 1:
                raise
    return {"pod_uid": uid, "scheduled": True, "attempt_id": receipt["attempt_id"],
            "signed_intent_sha384": receipt["signed_intent_sha384"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("describe-pod", "describe-qualification", "preflight",
                                          "select-intent-inputs", "issue-intent", "schedule", "launch", "launch-worker", "qualify"))
    parser.add_argument("deployment", type=Path)
    parser.add_argument("operator", type=Path)
    parser.add_argument("--pod-name", help="Kubernetes event Pod name")
    parser.add_argument("--pod-uid", help="Kubernetes event UID for automatic schedule or launch")
    args = parser.parse_args()
    automatic = args.pod_uid is not None
    name = POD if args.pod_name is None else args.pod_name
    if automatic and args.action not in ("schedule", "launch", "describe-pod"):
        parser.error("--pod-uid requires schedule, describe-pod or launch")
    if args.pod_name is not None and not automatic and args.action not in ("select-intent-inputs", "issue-intent"):
        parser.error("--pod-name requires intent selection, issuance or an event UID")
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if args.action in ("launch", "launch-worker", "qualify"):
        require(serial._LIBC.prctl(4, 0, 0, 0, 0) == 0, "dump_protection")
    profile = read_profile(args.deployment)
    config = json.loads(serial._regular(args.operator.resolve(strict=True), 64 << 10, private=True))
    seconds = config["deadline_seconds"]
    require(type(seconds) is int and 15 <= seconds <= 300, "deadline_seconds")
    deadline = time.monotonic() + seconds
    if args.action in ("launch", "launch-worker", "qualify"):
        no_swap_guard.verify(config["unit"])
    if args.action == "preflight":
        binding, values = artifacts(config)
        check_intent(config, binding, values, profile["workload_image"])
        if Path(config["signed_q"]).exists():
            check_q(config, binding, values, deadline)
        print(json.dumps({"public_inputs_checked": True}))
        return 0
    if args.action == "issue-intent":
        wire = issue_pod_intent(KubernetesClient(profile, config), name, deadline)
        sys.stdout.buffer.write(wire)
        return 0
    if args.action == "select-intent-inputs":
        client = KubernetesClient(profile, config)
        result = select_pod_inputs(client, name, deadline)
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.action == "launch-worker":
        # Each invocation owns one output set. A restart cannot reclaim an uncertain launch.
        queue = LaunchQueue(path(config, "launch_queue"))
        receipts = path(config, "schedule_receipts")
        serial._directory(receipts)
        while True:
            receipt = queue.next_ready(config["intent_cluster_id"])
            if receipt is not None:
                break
            time.sleep(0.25)
        uid, name = receipt["pod_uid"], receipt["pod_name"]
        require(cloud._matches(cloud._UUID, uid) and cloud._matches(cloud._DNS_LABEL, name), "pod_identity")
        config = dict(config, pod_receipt=str(receipts / (uid + ".json")))
        check_schedule_receipt(document(config, "pod_receipt"), receipt)
        deadline = time.monotonic() + seconds
        client = Clients(profile, config, deadline)
        binding, values = boot_artifacts(config)
        result = queued_launch(client, config, binding, values, deadline, name=name, uid=uid)
        print(json.dumps(result, sort_keys=True))
        return 0 if result.get("protected_export_available") else 2
    client = Clients(profile, config, deadline)
    if args.action == "schedule" and automatic:
        result = schedule_pod_intent(client, name, args.pod_uid, deadline)
    elif args.action == "schedule" and "launch_queue" in config:
        raise cloud.protocol.AttemptError("launch_event_uid_required")
    elif args.action == "launch":
        binding, values = boot_artifacts(config)
        if automatic or "launch_queue" in config:
            require("launch_queue" in config, "launch_queue_required")
            require(automatic, "launch_event_uid_required")
            result = queued_launch(client, config, binding, values, deadline, name=name, uid=args.pod_uid)
        else:
            result = controller_attempt(launch, client, config, binding, values, deadline, name=name, uid=args.pod_uid)
    elif args.action == "describe-qualification":
        result = client.qualification_target(deadline).receipt()
    elif args.action == "describe-pod":
        receipt = document(config, "pod_receipt")
        require(receipt["context"] == config["context"] and receipt["image_id"] == client.image_id,
                "scheduled_pod_receipt")
        if automatic or "pod_name" in receipt:
            require(automatic and receipt.get("pod_uid") == args.pod_uid and receipt.get("pod_name") == name
                    and receipt.get("cluster_id") == config["intent_cluster_id"], "scheduled_pod_receipt")
        result = client.pod_target(kube.ExpectedPod(receipt["pod_uid"], "workload", 0,
                                   profile["workload_image"]), deadline, name).receipt()
    else:
        binding, values = artifacts(config)
        if args.action == "schedule":
            result = schedule(client, config, binding, values, deadline)
        else:
            result = controller_attempt(qualify, client, config, binding, values, deadline)
    print(json.dumps(result, sort_keys=True))
    if args.action in ("launch", "qualify") and not result.get("protected_export_available"):
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, subprocess.TimeoutExpired, InvalidSignature,
            cloud.protocol.AttemptError, serial.GatewayError, no_swap_guard.GuardError) as error:
        # Protocol exceptions expose fixed labels. Never emit repr of input
        # files or command output from tools handling credentials.
        reason = str(error) if isinstance(error, (cloud.protocol.AttemptError, serial.GatewayError,
                                                  no_swap_guard.GuardError)) else type(error).__name__
        if isinstance(error, serial.GatewayError) and error.code in ("guest_bootstrap_failed", "guest_postgrant_failed"):
            diagnostic = cloud.protocol.failure_record(error, "console-command")
            if diagnostic.get("guest_stage") in ("bootstrap_collect", "collect"):
                reason = f"{reason} {diagnostic['guest_stage']}/{diagnostic['error_class']}"
        if "caa_heartbeat_exit" in getattr(error, "__notes__", ()):
            reason += " caa_heartbeat_exit"
        for note in getattr(error, "__notes__", ()):
            if note.startswith("serial_cleanup: "):
                reason += " " + note
        sys.exit("execution proof controller stopped: " + reason)
