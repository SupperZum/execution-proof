"""Relay a committed collector receipt to the waiting guest."""
from contextlib import closing
import http.client
import json
from pathlib import Path
import sys
import time

import serial_gateway as serial

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "collector"))
from deliver import LocalConnection
from tls_api import Endpoint


class Relay:
    def __init__(self, socket_path, attempt):
        serial._identifier(attempt)
        self.socket_path = socket_path
        self.attempt = attempt

    def receipt(self, deadline):
        with closing(self.socket_path.connection() if isinstance(self.socket_path, Endpoint)
                     else LocalConnection(self.socket_path)) as conn:
            conn.timeout = min(4, max(0.01, deadline - time.monotonic()))
            conn.request("GET", "/v1/attempts/" + self.attempt + "/receipt")
            response = conn.getresponse()
            if response.status in (404, 503):
                return None
            serial._require(response.status == 200, "archive_receipt_response")
            raw = response.read(8193)
            serial._require(0 < len(raw) <= 8192, "archive_receipt_size")
            value = json.loads(raw)
            serial._keys(value, ["statement", "signature"])
            serial._require(value["statement"]["attempt_id"] == self.attempt, "archive_attempt")
            serial._hex(value["statement"]["pack_sha384"], 48)
            return value

    def __call__(self, gateway, deadline):
        while time.monotonic() < deadline:
            gateway._control({"request_archive_status": True}, deadline=deadline)
            pending = gateway._public({"archive-pending"}, deadline=deadline)
            serial._require(pending == {"attempt_id": self.attempt}, "archive_pending_binding")
            try:
                receipt = self.receipt(deadline)
            except (OSError, http.client.HTTPException):
                receipt = None
            if receipt is not None:
                gateway._control({"archive_receipt": receipt}, deadline=deadline)
                confirmed = gateway._public({"archive-acknowledged"}, deadline=deadline)
                serial._require(confirmed == {"attempt_id": self.attempt,
                    "pack_sha384": receipt["statement"]["pack_sha384"]}, "archive_guest_binding")
                return {"guest": confirmed, "receipt": receipt}
            time.sleep(min(1, max(0, deadline - time.monotonic())))
        raise serial.GatewayError("archive_deadline")

def qualification_confirmation(receipt_path):
    """The collector publishes its receipt atomically after committing the raw export."""
    from hashlib import sha384

    def confirm(gateway, grant, export, deadline):
        statement = json.loads(grant)["statement"]
        attempt = statement["binding"]["attempt_id"]
        expected = {"version": 1, "purpose": "execution-proof.qualification.export-archived",
                    "grant_id": statement["grant_id"], "attempt_id": attempt,
                    "export_sha384": sha384(export).hexdigest()}
        while time.monotonic() < deadline:
            if not receipt_path.exists():
                time.sleep(min(0.2, max(0, deadline - time.monotonic())))
                continue
            receipt = json.loads(serial._regular(receipt_path, 8192))
            serial._keys(receipt, ["statement", "signature"])
            serial._require(receipt["statement"] == expected, "qualification_receipt_binding")
            gateway._control({"qualification_export_receipt": receipt}, deadline=deadline)
            guest = gateway._public({"qualification-export-archived"}, deadline=deadline)
            serial._require(guest == {"attempt_id": attempt, "export_sha384": expected["export_sha384"]},
                            "qualification_guest_binding")
            return {"receipt": receipt, "guest": guest}
        raise serial.GatewayError("qualification_archive_deadline")
    return confirm
