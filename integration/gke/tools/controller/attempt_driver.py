#!/usr/bin/env python3
"""One manual attempt protocol. No cloud creation, signer or proof verdict.

The caller supplies the fixed trusted authority transport, actual CAA controller,
and SerialGateway owner. Private SA credentials never enter this module. Software
tests of the choreography do not establish hardware authorization or execution.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import time

import serial_gateway as serial


class AttemptError(Exception):
    pass


class RedeemResponseLost(AttemptError):
    """The pending guest may already have a committed admission."""


def admit_pending(authority, gateway, grant, aggregate, request, deadline):
    nonce = request["guest_nonce"]
    try:
        return authority.admit(grant, aggregate, nonce, wire(request, "recorder_request_json"), deadline)
    except RedeemResponseLost:
        require(time.monotonic() < deadline, "authority_deadline")
        status = gateway.request_admission_status(deadline)
        require(status["guest_nonce"] == nonce, "authority_order")
        require(time.monotonic() < deadline, "authority_deadline")
        return authority.admission_status(grant, aggregate, wire(status, "recorder_request_json"), deadline)


PHASES=frozenset(('authority-bootstrap','wait-control-ready','send-boot','start-private-services',
    'receive-bootstrap','bootstrap-received','authority-issue','before-grant','send-grant','receive-policy',
    'authority-plan','before-plan','send-plan','receive-admission-request','authority-admit','before-admission',
    'send-admission','receive-ready','controller','receive-execution','stop','complete','console-command'))
SERIAL_REASONS=frozenset(('bootstrap_domain','control_bound','deadline','descendant_reap_timeout',
    'duplicate_json_field','evidence_bound','evidence_domain','gateway_already_active','host_key_format',
    'host_key_pin','instance_scope','invalid_json','keywrap_shape','known_hosts_create','management_key_format',
    'nonfinite_json','operation_order','operator_directory','operator_file','operator_file_name','phase_deadline',
    'public_base64','public_bytes','public_depth','public_domain','public_frame_bound','public_hex',
    'public_identifier','public_integer','public_phase','public_schema','public_wire_magic','public_wire_bound',
    'public_compression','guest_terminated','guest_management_relay_failed','guest_sandbox_lifetime_failed','guest_bootstrap_failed','guest_postgrant_failed','guest_ready_failed',
    'secret_in_public_output','serial_buffer_bound',
    'serial_ssh_user','shutdown_output_bound','signed_object_bound','signed_object_domain','spec_bound','ssh_closed',
    'ssh_eof','ssh_io','ssh_key_format','ssh_write','startup_bound','startup_marker','startup_rejected','stderr_bound',
    'subreaper','unexpected_phase','unsolicited_serial_output','watchdog_join_timeout'))
ATTEMPT_REASONS=frozenset(('archive_budget','archive_name','archive_write','attempt_deadline','attempt_mode',
    'authority_wire','bootstrap_challenge','challenge_id','execution_phase','plan_binding','private_retention',
    'public_bound','sandbox_alias','authority_mode','authority_order','authority_response_domain',
    'authority_response_status','experiment_response_scope','experimental_retirement','grant_id',
    'operator_plan_selection','operator_selection','selected_audience','selected_container','selected_snapshot',
    'authority_deadline','authority_directory','authority_endpoint','authority_host_key','authority_input_bound',
    'authority_instance','authority_io','authority_ip','authority_operation','authority_output_bound',
    'authority_process','authority_stderr_bound'))


def failure_record(error,phase):
    family,reason='UNCLASSIFIED','UNCLASSIFIED_FAILURE'
    if type(error) is serial.GatewayError and type(error.code) is str and error.code in SERIAL_REASONS:
        family,reason='SERIAL_GATEWAY',error.code
    elif type(error) is AttemptError and len(error.args)==1 and type(error.args[0]) is str and error.args[0] in ATTEMPT_REASONS:
        family,reason='ATTEMPT_PROTOCOL',error.args[0]
    record={'schema':'onb17.public-attempt-failure.v1','phase':phase if phase in PHASES else 'UNCLASSIFIED_PHASE',
            'error_family':family,'reason':reason,'raw_error_retained':False,'raw_serial_retained':False,
            'producer_qualified':False,'execution_verified':False}
    if family=='SERIAL_GATEWAY' and reason in ('guest_bootstrap_failed','guest_postgrant_failed'):
        stage,classification=error.guest_stage,error.error_class
        if type(stage) is str and type(classification) is str:
            if reason=='guest_bootstrap_failed' and phase in ('receive-bootstrap','console-command') and serial.bootstrap_diagnostic(stage,classification):
                record.update(guest_stage=stage,error_class=classification)
            elif reason=='guest_postgrant_failed' and serial.postgrant_diagnostic(stage,classification):
                record.update(guest_stage=stage,error_class=classification)
    if family=='SERIAL_GATEWAY' and reason=='guest_ready_failed' and phase in ('receive-ready','console-command'):
        stage,classification=error.guest_stage,error.error_class
        if type(stage) is str and type(classification) is str and classification in serial.READY_ERROR_CLASSES.get(stage, ()):
            record.update(guest_stage=stage,error_class=classification)
    if family=='SERIAL_GATEWAY' and reason=='guest_terminated':
        status=error.guest_terminal_status
        if type(status) is str and status in serial.TERMINAL_STATUS:
            record['guest_terminal_status']=status
    return record


def require(value, code):
    if not value:
        raise AttemptError(code)


def encode(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def public_json(raw, cap=17 << 20):
    require(isinstance(raw, (bytes, bytearray)) and 0 < len(raw) <= cap, "public_bound")
    value = serial._json(raw)
    serial._no_secret(value)
    return value


def wire(value, name, cap=32 << 10):
    result = value.get(name) if type(value) is dict else None
    require(type(result) is list and 0 < len(result) <= cap
            and all(type(byte) is int and 0 <= byte <= 255 for byte in result), "authority_wire")
    return bytes(result)


class PublicArchive:
    """Create-only, bounded original public bytes; never save a boot request."""
    def __init__(self, path, management_key):
        self.path = Path(path)
        self.path.mkdir(mode=0o700)
        self.directory = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        # The sole private input is a management P256 TLS key. Detect raw PEM,
        # JSON escaped PEM and DER/base64 body before retaining public material.
        lines = management_key.splitlines()
        body = b"".join(lines[1:-1])
        self.patterns = [management_key, serial.escaped_pem(management_key), body]
        self.total = 0
        self.count = 0

    def put(self, name, raw):
        require(name in {"manifest.json", "references.json", "challenge.json", "bootstrap.json",
                         "grant.json", "policy.json", "plan.json", "admission-request.json",
                         "authorization.json", "controller.json", "export.json", "result.json","failure.json"},
                "archive_name")
        public_json(raw)
        require(all(not pattern or pattern not in raw for pattern in self.patterns), "private_retention")
        require(self.count < 13 and self.total + len(raw) <= 32 << 20, "archive_budget")
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.directory)
        try:
            view = memoryview(raw)
            while view:
                size = os.write(fd, view)
                require(size > 0, "archive_write")
                view = view[size:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(self.directory)
        self.count += 1
        self.total += len(raw)

    def checkpoint(self,phase):
        require(phase in PHASES,'attempt_mode')
        raw=encode({'schema':'onb17.public-attempt-phase.v1','phase':phase,'execution_verified':False})
        fd=os.open('phase-next.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
                   0o600,dir_fd=self.directory)
        try:
            require(os.write(fd,raw)==len(raw),'archive_write');os.fsync(fd)
        finally:os.close(fd)
        os.replace('phase-next.json','phase.json',src_dir_fd=self.directory,dst_dir_fd=self.directory)
        os.fsync(self.directory)

    def close(self):
        if self.directory is not None:
            os.close(self.directory)
            self.directory = None
        self.patterns.clear()


def drive(gateway, authority, controller, *, manifest, references, effective_spec,
          management_key, archive_directory, deadline, mode, sandbox_alias, phase_hooks=None):
    """Authority methods return original signed JSON, never a software verdict.

    bootstrap() -> challenge bytes; issue(challenge_id, submission) -> L bytes;
    startup_plan(L, aggregate) -> signed plan bytes; admit(L, aggregate, nonce,
    recorder_request) -> A bytes. The separately implemented trusted frontend
    pins all operator selections. controller(control, deadline) drives real CAA
    and returns only its public result JSON. All callbacks share this deadline.
    """
    require(mode in ("qualification_experiment", "normal"), "attempt_mode")
    require(type(deadline) in (float, int) and time.monotonic() < deadline <= time.monotonic() + 900,
            "attempt_deadline")
    require(type(sandbox_alias) is str and 1 <= len(sandbox_alias) <= 128
            and all(byte.isascii() and (byte.isalnum() or byte in "-_.:") for byte in sandbox_alias),
            "sandbox_alias")
    serial._management_key(management_key)
    serial._signed_public(manifest, "qlad.execution-proof.gcp-boot-artifact-manifest.v1", 1)
    serial._signed_public(references, "qlad.execution-proof.gcp-reference-policy-set.v1", 1)
    public_json(effective_spec, 256 << 10)
    archive = PublicArchive(archive_directory, management_key)

    def live():
        require(time.monotonic() < deadline, "attempt_deadline")

    phase='authority-bootstrap'
    def checkpoint(value):
        nonlocal phase
        phase=value;archive.checkpoint(value)

    try:
        checkpoint('authority-bootstrap')
        challenge = authority.bootstrap(deadline)
        serial._signed_public(challenge, "qlad.execution-proof.gcp-bootstrap-challenge.v3", 3)
        challenge_id = public_json(challenge)["statement"].get("challenge_id")
        require(type(challenge_id) is str and challenge_id, "challenge_id")
        archive.put("manifest.json", manifest)
        archive.put("references.json", references)
        archive.put("challenge.json", challenge)
        live()
        checkpoint('wait-control-ready')
        gateway.wait_control_ready()
        checkpoint('send-boot')
        gateway.send_boot(manifest, references, challenge, management_key)
        if phase_hooks is not None:
            checkpoint('start-private-services')
            phase_hooks.start()  # Private startup begins only after public BOOT.
        checkpoint('receive-bootstrap')
        bootstrap = gateway.receive_bootstrap()
        checkpoint('bootstrap-received')
        grant_deadline = min(deadline, time.monotonic()+50) if phase_hooks is not None else deadline
        require(bootstrap["challenge_id"] == challenge_id, "bootstrap_challenge")
        archive.put("bootstrap.json", encode(bootstrap))
        live()
        checkpoint('authority-issue')
        grant = authority.issue(challenge_id, bootstrap["submission"], grant_deadline)
        serial._signed_public(grant, "qlad.execution-proof.launch.v3", 3)
        archive.put("grant.json", grant)
        if phase_hooks is not None:
            checkpoint('before-grant')
            phase_hooks.before_grant(grant_deadline)
        checkpoint('send-grant')
        gateway.send_grant(grant)
        checkpoint('receive-policy')
        policy = gateway.receive_policy()
        plan_deadline = min(deadline, time.monotonic()+50) if phase_hooks is not None else deadline
        archive.put("policy.json", encode(policy))
        aggregate = wire(policy, "signed_aggregate")
        live()
        checkpoint('authority-plan')
        plan = authority.startup_plan(grant, aggregate, plan_deadline)
        serial._signed_public(plan, "qlad.execution-proof.gcp-attempt-plan.v1", 1)
        parsed_plan = public_json(plan)
        statement = parsed_plan["statement"]
        # Only the effective spec uses a raw-byte digest here. L/aggregate use
        # Rust contract signing-byte digests, checked by the authority and guest;
        # hashing their signed JSON would reject every real production plan.
        require(statement.get("effective_spec_sha384") == hashlib.sha384(effective_spec).hexdigest(),
                "plan_binding")
        archive.put("plan.json", plan)
        if phase_hooks is not None:
            checkpoint('before-plan')
            phase_hooks.before_plan(plan_deadline)
        checkpoint('send-plan')
        gateway.send_plan(plan, effective_spec)
        checkpoint('receive-admission-request')
        request = gateway.receive_admission_request()
        admission_deadline = min(deadline, time.monotonic()+50) if phase_hooks is not None else deadline
        archive.put("admission-request.json", encode(request))
        live()
        checkpoint('authority-admit')
        authorization = admit_pending(authority, gateway, grant, aggregate, request, admission_deadline)
        serial._signed_public(authorization, "qlad.execution-proof.preparation-admission.v1", 1)
        archive.put("authorization.json", authorization)
        if phase_hooks is not None:
            checkpoint('before-admission')
            phase_hooks.before_admission(admission_deadline)
        checkpoint('send-admission')
        gateway.send_admission(authorization)
        checkpoint('receive-ready')
        gateway.receive_ready()
        live()
        control = {"version": 1, "purpose": "qlad.execution-proof.gcp-manual-task-control.v1",
                   "signed_plan": parsed_plan, "effective_spec": list(effective_spec),
                   "sandbox_alias": sandbox_alias}
        checkpoint('controller')
        result = controller(control, deadline)
        archive.put("controller.json", result)
        # A successful Wait/marker is transport evidence. Only a protected export
        # and independent verifier can establish the execution proof.
        live()
        checkpoint('receive-execution')
        publication_phase, publication = gateway.receive_execution()
        require(publication_phase in ("export", "unproven"), "execution_phase")
        if publication_phase == "export":
            export = serial._b64_public(publication["export_json_base64"])
            archive.put("export.json", export)
        checkpoint('stop')
        gateway.send_stop()
        summary = {"schema": "onb17.manual-gcp-attempt-protocol.v1", "mode": mode,
                   "transport_completed": True, "protected_export_available": publication_phase == "export",
                   "producer_qualified": False, "execution_verified": False,
                   "kubernetes_pods_accepted": False,
                   "qualification_experiment": mode == "qualification_experiment"}
        if publication_phase == "unproven":
            summary.update(serial.report_cleanup_result(publication))
        archive.put("result.json", encode(summary))
        checkpoint('complete')
        return summary
    except BaseException as error:
        # Persist only exact known class/literal reasons while the archive is
        # still open. No repr/traceback, payload, private input or error hash.
        try:archive.put('failure.json',encode(failure_record(error,phase)))
        except BaseException:pass
        raise
    finally:
        archive.close()
        # The outer caller's SerialGateway context always kills/reaps on error;
        # cloud cleanup remains its distinct lifecycle owner.
