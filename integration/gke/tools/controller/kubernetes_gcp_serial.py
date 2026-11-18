"""ONB2 over pinned GCE serial SSH for one independently identified PodVM.

The operator supplies authenticated readbacks and stages the authority and serial
access. This module has no resource discovery, provisioning, or cleanup calls.
"""

from dataclasses import asdict, dataclass
import hashlib
import re

import authority_frontend as frontend
import kubernetes_serial as controller


serial = controller.serial
protocol = controller.attempt
require = protocol.require
_PEER_POD_API = "confidentialcontainers.org/v1alpha1"
_DNS_LABEL = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?")
_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")


def _matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def _numeric_id(value):
    require(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value), "compute_numeric_id")
    numeric = int(value)
    require(numeric < 1 << 64, "compute_numeric_id")
    return numeric


def _compute_link(link, suffix, scope):
    location = f"/compute/v1/projects/{scope.project}/zones/{scope.zone}/{suffix}"
    return link in tuple(f"https://{host}{location}" for host in ("www.googleapis.com", "compute.googleapis.com"))


def _object(value, key):
    child = value.get(key) if type(value) is dict else None
    require(type(child) is dict, "readback_schema")
    return child


def decode_worker_readback(raw):
    """Decode the bounded CRI helper stdout, including the console marker."""
    require(type(raw) is bytes and len(raw) <= 4096, "worker_readback_bound")
    value = protocol.public_json(raw.removeprefix(b"ONB17_WORKER_READBACK "), 4096)
    serial._keys(value, ("pod_uid", "sandbox_id", "container_id", "container_name", "attempt", "image_ref"))
    readback = controller.WorkerReadback(**value)
    controller._pod_identity(readback)
    serial._hex(readback.sandbox_id, 32)
    serial._hex(readback.container_id, 32)
    return readback


@dataclass(frozen=True)
class Scope:
    project: str
    zone: str
    number: int


@dataclass(frozen=True)
class PodTarget:
    scope: Scope
    namespace: str
    pod_name: str
    expected: controller.ExpectedPod
    node_name: str
    peer_pod_uid: str
    instance: str
    instance_id: int
    image_id: int

    def gce_identity(self):
        return {"instance_id": self.instance_id, "numerical_project_id": self.scope.number, "zone": self.scope.zone}

    def receipt(self):
        value = asdict(self)
        del value["expected"], value["scope"]
        return {**value, "project": self.scope.project, **self.gce_identity()}


def _vm_prefix(pod_name):
    # CAA GenerateInstanceName: podvm + separator + up to 48 Pod-name bytes + SID[:8].
    require(_matches(_DNS_LABEL, pod_name), "pod_name")
    return f"podvm-{pod_name[:48]}-"


def bind_target(pod, peer_pods, instance, boot_disk, *, namespace, pod_name, expected, image_id, scope):
    """Check original API/Compute readbacks from the operator's pinned clients.

    Kubernetes context and PeerPod writer, Compute GETs, and the approved image
    ID are independently trusted inputs. The attached disk is read separately.
    """
    require(type(expected) is controller.ExpectedPod and _matches(_UUID, expected.pod_uid), "pod_uid")
    controller._pod_identity(expected)
    require(_matches(_DNS_LABEL, namespace), "pod_namespace")
    prefix = _vm_prefix(pod_name)
    metadata, spec = _object(pod, "metadata"), _object(pod, "spec")
    require(pod.get("apiVersion") == "v1" and pod.get("kind") == "Pod"
            and metadata.get("uid") == expected.pod_uid and metadata.get("name") == pod_name
            and metadata.get("namespace") == namespace and not metadata.get("deletionTimestamp")
            and spec.get("runtimeClassName") == "kata-remote", "pod_identity")
    node_name = spec.get("nodeName")
    require(type(node_name) is str and 0 < len(node_name) <= 253
            and all(_matches(_DNS_LABEL, label) for label in node_name.split(".")), "pod_node")
    containers = spec.get("containers")
    require(type(containers) is list and len(containers) == 1 and type(containers[0]) is dict
            and containers[0].get("name") == expected.container_name
            and containers[0].get("image") == expected.image_ref, "pod_workload")

    require(type(peer_pods) is list, "peer_pods")
    owned = []
    for item in peer_pods:
        peer = _object(item, "metadata")
        owners = peer.get("ownerReferences", [])
        require(type(owners) is list and all(type(ref) is dict for ref in owners), "peer_pod_owners")
        if peer.get("namespace") == namespace and any(ref.get("uid") == expected.pod_uid for ref in owners):
            owned.append((item, peer, owners))
    require(len(owned) == 1, "peer_pod_unique")
    item, peer, owners = owned[0]
    matching_owner = {"apiVersion": "v1", "kind": "Pod", "name": pod_name, "uid": expected.pod_uid}
    controlling = [ref for ref in owners if ref.get("controller") is True]
    require(len(controlling) == 1 and all(controlling[0].get(key) == val for key, val in matching_owner.items())
            and item.get("apiVersion") == _PEER_POD_API and item.get("kind") == "PeerPod"
            and _matches(_UUID, peer.get("uid")) and not peer.get("deletionTimestamp"), "peer_pod_identity")
    cloud = _object(item, "spec")
    name = cloud.get("instanceID")
    require(cloud.get("cloudProvider") == "gcp" and type(name) is str
            and re.fullmatch(re.escape(prefix) + r"[0-9a-f]{8}", name), "peer_pod_instance")

    confidential = _object(instance, "confidentialInstanceConfig")
    require(instance.get("name") == name and instance.get("status") == "RUNNING"
            and _compute_link(instance.get("selfLink"), f"instances/{name}", scope)
            and confidential.get("enableConfidentialCompute", True) is True
            and confidential.get("confidentialInstanceType") == "TDX", "compute_instance")
    require(type(boot_disk) is dict and _matches(_DNS_LABEL, boot_disk.get("name"))
            and _compute_link(boot_disk.get("selfLink"), f"disks/{boot_disk['name']}", scope), "compute_disk")
    disks = instance.get("disks")
    require(type(disks) is list and all(type(disk) is dict for disk in disks), "compute_disks")
    boot = [disk.get("source") for disk in disks if disk.get("boot") is True]
    expected_image = _numeric_id(image_id)
    require(boot == [boot_disk["selfLink"]]
            and _numeric_id(boot_disk.get("sourceImageId")) == expected_image, "compute_boot_image")
    return PodTarget(scope, namespace, pod_name, expected, node_name, peer["uid"], name,
                     _numeric_id(instance.get("id")), expected_image)


class GceSerial(serial.SerialGateway):
    _decode_public = controller.LocalSerial._decode_public
    receive_sandbox_ready = controller.LocalSerial.receive_sandbox_ready
    receive_candidate = controller.LocalSerial.receive_candidate
    send_plan = controller.LocalSerial.send_plan
    _software_fixture = False

    def __init__(self, target, config, read_target):
        require((config.project, config.zone, config.instance)
                == (target.scope.project, target.scope.zone, target.instance), "serial_target")
        super().__init__(config)
        self.target = target
        self.read_target = read_target
        self._candidate = None

    def _public(self, phases):
        result = controller.LocalSerial._public(self, phases)
        self._frames += 1
        return result

    def send_boot(self, manifest, references, challenge, management_key):
        require(self.read_target(self._deadline()) == self.target, "serial_target_changed")
        super().send_boot(manifest, references, challenge, management_key)


class LateCidAuthority(frontend.Authority):
    """The normal Rust authority protocol with CID selected at pending Create."""

    def __init__(self, execute, signed_intent, trust_snapshot, execution_audience):
        serial._signed_public(signed_intent, "qlad.execution-proof.tenant-intent.v2", 2)
        protocol.public_json(trust_snapshot, 1 << 20)
        serial._identifier(execution_audience)
        self.mode = "normal"
        self.execute, self.signed_intent = execute, signed_intent
        self.trust_snapshot_sha384 = hashlib.sha384(trust_snapshot).hexdigest()
        self.execution_audience = execution_audience
        self.selection = self.challenge = self.grant = self.aggregate = self.plan = None
        self.admitted = False

    def startup_plan(self, grant, aggregate, cid, deadline):
        require(self.selection is None and self.grant == grant and grant is not None, "authority_order")
        serial._hex(cid, 32)
        self.selection = frontend.Selection(cid, self.trust_snapshot_sha384, self.execution_audience)
        self.selection.validate()
        return super().startup_plan(grant, aggregate, deadline)


def validate_issuer_pins(target, issuer_config, signed_intent, effective_spec):
    config = protocol.public_json(issuer_config, 4 << 20)
    boot = _object(config, "boot_policy")
    require(boot.get("expected_instance") == target.gce_identity(), "authority_instance_pin")
    intent = serial._signed_public(signed_intent, "qlad.execution-proof.tenant-intent.v2", 2)["statement"]
    protocol.public_json(effective_spec, 256 << 10)
    require(intent.get("container_role") == "application-init"
            and intent.get("selected_manifest_sha256") == target.expected.image_ref.split("@sha256:", 1)[1]
            and intent.get("effective_launch_sha384") == hashlib.sha384(effective_spec).hexdigest(), "intent_workload_pin")
