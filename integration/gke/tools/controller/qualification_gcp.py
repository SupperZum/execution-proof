"""Wire an owned standalone GCE qualification VM to the early sandbox driver.

The operator owns creation, fresh authenticated Compute reads, Authority staging
and retirement. No resource discovery or lifecycle calls live here.
"""

from dataclasses import asdict, dataclass
import hashlib
import re
import time

import kubernetes_gcp_serial as cloud
import qualification_serial as qualification


serial = cloud.serial
protocol = cloud.protocol
require = cloud.require
_EXPERIMENT = "onb17.gcp-qualification-experiment.v1"
_ARTIFACT_DIGESTS = ("config_sha384", "producer_core_sha384",
                     "artifact_manifest_sha384", "reference_policy_sha384")


def _sha384(raw):
    return hashlib.sha384(raw).hexdigest()


@dataclass(frozen=True)
class QualificationTarget:
    scope: cloud.Scope
    instance: str
    instance_id: int
    boot_disk_id: int
    image_id: int

    def gce_identity(self):
        return {"instance_id": self.instance_id, "numerical_project_id": self.scope.number,
                "zone": self.scope.zone}

    def receipt(self):
        value = asdict(self)
        del value["scope"]
        return {**value, "project": self.scope.project, **self.gce_identity()}


def derive_trust_snapshot_sha384(experiment_config, boot_config, producer_core, manifest, references, collateral):
    """Derive the frozen Rust qexp snapshot from the actual public staging bytes."""
    config = protocol.public_json(experiment_config, 64 << 10)
    expectations = cloud._object(config, "artifact_expectations")
    binding = cloud._object(expectations, "boot_binding")
    artifacts = (boot_config, producer_core, manifest, references)
    digests = [_sha384(raw) for raw in artifacts]
    require(all(binding.get(field) == digest for field, digest in zip(_ARTIFACT_DIGESTS, digests)),
            "qualification_artifact_pin")
    boot = protocol.public_json(boot_config, 64 << 10)
    authority = cloud._object(boot, "roots").get("authority_public_key")
    require(type(authority) is list and len(authority) == 32 and any(authority)
            and all(type(byte) is int and 0 <= byte < 256 for byte in authority), "qualification_authority_root")
    protocol.public_json(collateral, 4 << 20)
    identity = _sha384(protocol.encode([_EXPERIMENT, list(experiment_config), _sha384(collateral),
                                       authority, *digests]))
    return _sha384(protocol.encode(["onb17.experimental-execution-snapshot-NOT-QUALIFIED.v1", identity]))


def validate_experiment_pins(target, experiment_config, signed_intent, effective_spec, *, cid, image_ref,
                             trust_snapshot_sha384, manifest, references):
    config = protocol.public_json(experiment_config, 64 << 10)
    require(type(config) is dict and type(config.get("version")) is int and config["version"] == 1
            and config.get("purpose") == _EXPERIMENT, "qualification_config_domain")
    expected_instance = cloud._object(cloud._object(config, "boot_policy"), "expected_instance")
    require(cloud.matches_instance_pin(expected_instance, target.gce_identity()), "qualification_instance_pin")
    qualification.validate_cid(cid)
    require(config.get("container_id") == cid, "qualification_selected_cid")
    audience = config.get("execution_audience")
    serial._identifier(audience)
    require(audience.startswith("qexp-"), "qualification_audience")
    retire_before = config.get("retire_before")
    now = time.time()
    require(type(retire_before) is int and now < retire_before, "qualification_retirement")

    intent = serial._signed_public(signed_intent, "qlad.execution-proof.tenant-intent.v2", 2)["statement"]
    protocol.public_json(effective_spec, 256 << 10)
    require(cloud._matches(re.compile(r"[^@\s]+@sha256:[0-9a-f]{64}"), image_ref), "qualification_image_ref")
    validity = cloud._object(intent, "validity")
    not_before, expires = validity.get("not_before"), validity.get("expires")
    require(type(not_before) is int and type(expires) is int and not_before <= now < expires <= retire_before,
            "qualification_intent_window")
    require(config.get("signed_intent_sha384") == _sha384(signed_intent)
            and intent.get("container_role") == "application-init"
            and intent.get("selected_manifest_sha256") == image_ref.rsplit(":", 1)[1]
            and intent.get("effective_launch_sha384") == _sha384(effective_spec), "qualification_intent_pin")
    serial._signed_public(manifest, "qlad.execution-proof.gcp-boot-artifact-manifest.v1", 1)
    serial._signed_public(references, "qlad.execution-proof.gcp-reference-policy-set.v1", 1)
    binding = cloud._object(cloud._object(config, "artifact_expectations"), "boot_binding")
    require(binding.get("artifact_manifest_sha384") == _sha384(manifest)
            and binding.get("reference_policy_sha384") == _sha384(references), "qualification_artifact_pin")
    serial._hex(trust_snapshot_sha384, 48)
    selection = cloud.frontend.Selection(cid, trust_snapshot_sha384, audience)
    selection.validate()
    return selection, retire_before


class QualificationGceSerial(serial.SerialGateway):
    """Use the pinned GCE serial SSH transport for early-sandbox phases."""

    _public = cloud.GceSerial._public
    receive_sandbox_ready = cloud.controller.LocalSerial.receive_sandbox_ready
    receive_candidate = cloud.controller.LocalSerial.receive_candidate
    send_plan = cloud.controller.LocalSerial.send_plan
    def send_stop(self):
        if self._stage == "qualification-export-archived":
            self._control({"stop": True})
            self._stage = "stop-sent"
        else:
            cloud.controller.LocalSerial.send_stop(self)

    _software_fixture = False

    def __init__(self, target, config, refresh, cid):
        super().__init__(config)
        require(type(target) is QualificationTarget and (config.project, config.zone, config.instance)
                == (target.scope.project, target.scope.zone, target.instance), "qualification_serial_target")
        self.refresh = refresh
        self.cid = qualification.validate_cid(cid)
        self._candidate = None

    def _decode_public(self, raw, phases, ready_diagnostics):
        if phases == {"sandbox-candidate"}:
            return qualification.decode_candidate(raw, self.cid)
        return cloud.controller.LocalSerial._decode_public(self, raw, phases, ready_diagnostics)

    def send_boot(self, manifest, references, challenge, management_key):
        self.refresh(self._deadline())
        super().send_boot(manifest, references, challenge, management_key)


class QualificationAuthority(cloud.frontend.Authority):
    def __init__(self, execute, refresh, selection, retire_before):
        super().__init__(execute, mode="qualification_experiment", selection=selection, retire_before=retire_before)
        self.refresh = refresh

    def _call(self, operation, request, expected_status, deadline):
        self.refresh(deadline)
        return super()._call(operation, request, expected_status, deadline)

    def startup_plan(self, grant, aggregate, deadline):
        plan = super().startup_plan(grant, aggregate, deadline)
        statement = protocol.public_json(plan)["statement"]
        require(statement.get("container_id") == self.selection.container_id
                and statement.get("trust_snapshot_sha384") == self.selection.trust_snapshot_sha384
                and statement.get("execution_audience") == self.selection.execution_audience,
                "qualification_plan_selection")
        return plan
