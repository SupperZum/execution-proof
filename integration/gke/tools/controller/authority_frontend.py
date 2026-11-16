"""Trusted operator selections above the actual Rust authority CLI.

This adapter never signs or appraises a quote. A separately pinned SSH executor
runs only the fixed Rust entrypoints on the trusted VM. The untrusted management
VM receives the signed plan and task data, not these callbacks or private files.
"""
from dataclasses import dataclass
import re

import attempt_driver as protocol
import serial_gateway as serial


@dataclass(frozen=True)
class Selection:
    container_id: str
    trust_snapshot_sha384: str
    execution_audience: str

    def validate(self):
        protocol.require(re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", self.container_id), "selected_container")
        protocol.require(re.fullmatch(r"[0-9a-f]{96}", self.trust_snapshot_sha384), "selected_snapshot")
        protocol.require(re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", self.execution_audience), "selected_audience")


class Authority:
    """One attempt; execute(family, operation, original_stdin, deadline) is pinned.

    Family/operation select fixed executable and operator paths, never a command
    or path from a guest request. The executor owns remote process deadlines and
    private SSH identity. No SA JSON belongs in any request handled here.
    """
    def __init__(self, execute, *, mode, signed_intent=None, selection=None, retire_before=None):
        protocol.require(mode in ("normal", "qualification_experiment"), "authority_mode")
        if mode == "normal":
            protocol.require(isinstance(selection, Selection), "operator_selection")
            selection.validate()
            serial._signed_public(signed_intent, "qlad.execution-proof.tenant-intent.v2", 2)
        else:
            protocol.require(type(retire_before) is int and retire_before > 0, "experimental_retirement")
        self.execute = execute
        self.mode = mode
        self.signed_intent = signed_intent
        self.selection = selection
        self.retire_before = retire_before
        self.challenge = None
        self.grant = None
        self.aggregate = None
        self.plan = None
        self.admitted = False

    def _call(self, operation, request, expected_status, deadline):
        experimental = self.mode == "qualification_experiment"
        family = "experiment" if experimental else "normal"
        if experimental:
            data = b"" if request is None else protocol.encode(request)
        else:
            data = b"" if request is None else protocol.encode({
                "version": 1, "purpose": "qlad.execution-proof.gcp-authority-request.v1", "request": request})
        raw = self.execute(family, operation, data, deadline)
        response = protocol.public_json(raw, 64 << 10)
        purpose = ("onb17.gcp-qualification-experiment-response.v1" if experimental else
                   "qlad.execution-proof.gcp-authority-response.v1")
        protocol.require(type(response) is dict and type(response.get("version")) is int
                         and response["version"] == 1 and response.get("purpose") == purpose,
                         "authority_response_domain")
        if experimental:
            protocol.require(response.get("claim_status") == "UNPROVEN_QUALIFICATION_EXPERIMENT"
                             and response.get("producer_qualified") is False
                             and response.get("execution_verified") is False
                             and response.get("retire_before") == self.retire_before,
                             "experiment_response_scope")
        result = response.get("result")
        protocol.require(type(result) is dict and result.get("status") == expected_status,
                         "authority_response_status")
        return result

    def initialize_normal(self, deadline):
        protocol.require(self.mode == "normal" and self.challenge is None, "authority_order")
        self._call("init", None, "initialized", deadline)

    def bootstrap(self, deadline):
        protocol.require(self.challenge is None, "authority_order")
        if self.mode == "qualification_experiment":
            result = self._call("bootstrap-only", None, "challenge", deadline)
        else:
            result = self._call("request", {"operation": "begin", "signed_intent_json": list(self.signed_intent)},
                                "challenge", deadline)
        self.challenge = protocol.wire(result, "signed_challenge_json")
        serial._signed_public(self.challenge, "qlad.execution-proof.gcp-bootstrap-challenge.v3", 3)
        return self.challenge

    def issue(self, challenge_id, submission, deadline):
        protocol.require(self.challenge is not None and self.grant is None
                         and protocol.public_json(self.challenge)["statement"].get("challenge_id") == challenge_id,
                         "authority_order")
        request = {"operation": "issue", "submission": submission}
        if self.mode == "normal":
            request["challenge_id"] = challenge_id
        result = self._call("issue" if self.mode == "qualification_experiment" else "request",
                            request, "grant", deadline)
        self.grant = protocol.wire(result, "signed_grant_json")
        serial._signed_public(self.grant, "qlad.execution-proof.launch.v3", 3)
        return self.grant

    def _grant_id(self):
        value = protocol.public_json(self.grant)["statement"].get("grant_id")
        protocol.require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value), "grant_id")
        return value

    def startup_plan(self, grant, aggregate, deadline):
        protocol.require(self.grant == grant and self.plan is None, "authority_order")
        serial._signed_public(aggregate, "qlad.execution-proof.gcp-kbs-policy-aggregate.v2", 2)
        request = {"operation": "startup_plan", "aggregate_json": list(aggregate)}
        if self.mode == "normal":
            request.update(grant_id=self._grant_id(), container_id=self.selection.container_id,
                           trust_snapshot_sha384=self.selection.trust_snapshot_sha384,
                           execution_audience=self.selection.execution_audience)
        result = self._call("startup-plan" if self.mode == "qualification_experiment" else "request",
                            request, "startup_plan", deadline)
        plan = protocol.wire(result, "signed_plan_json")
        serial._signed_public(plan, "qlad.execution-proof.gcp-attempt-plan.v1", 1)
        if self.mode == "normal":
            statement = protocol.public_json(plan)["statement"]
            protocol.require(statement.get("container_id") == self.selection.container_id
                             and statement.get("trust_snapshot_sha384") == self.selection.trust_snapshot_sha384
                             and statement.get("execution_audience") == self.selection.execution_audience,
                             "operator_plan_selection")
        # Both actual Rust CLIs authenticate the KBS signature in startup_plan.
        # Retain that exact aggregate before accepting the later nonce/request.
        self.aggregate, self.plan = aggregate, plan
        return plan

    def admit(self, grant, aggregate, guest_nonce, recorder_request, deadline):
        protocol.require(self.grant == grant and self.aggregate == aggregate and self.plan is not None
                         and not self.admitted, "authority_order")
        if self.mode == "normal":
            self._call("request", {"operation": "pin_policy_admission", "grant_id": self._grant_id(),
                                   "expected": protocol.public_json(self.aggregate)["statement"],
                                   "guest_nonce": guest_nonce}, "policy_pinned", deadline)
            request = {"operation": "redeem_policy_aggregate", "grant_id": self._grant_id(),
                       "aggregate_json": list(self.aggregate), "recorder_request_json": list(recorder_request)}
        else:
            request = {"operation": "redeem", "guest_nonce": guest_nonce,
                       "recorder_request_json": list(recorder_request)}
        result = self._call("redeem" if self.mode == "qualification_experiment" else "request",
                            request, "admission", deadline)
        wire = protocol.wire(result, "signed_authorization_json")
        serial._signed_public(wire, "qlad.execution-proof.preparation-admission.v1", 1)
        self.admitted = True
        return wire
