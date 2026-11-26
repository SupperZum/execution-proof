"""Exercise the normal adapter and operator against a live software issuer fixture."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import time

import run
from test_kubernetes_serial import PipePeer, publish, request


def main(directory, binary):
    def read(name):
        return (directory / name).read_bytes()

    config = {name: str(directory / name) for name in ("issuer_config", "authority_key", "collateral", "signed_q")}
    installed = directory / "gcp-authority"
    shutil.copyfile(binary, installed)
    installed.chmod(0o700)
    config["authority"] = {"path": str(installed), "sha384": hashlib.sha384(binary.read_bytes()).hexdigest()}
    config["issuer_store"] = str(directory / "issuer.sqlite")
    execute = run.executor(config, experimental=False)
    response_sizes = {}
    operations = []
    committed = []
    deadline = time.monotonic() + 10

    def lose_first_reply(family, operation, raw, until):
        assert until == deadline
        op = json.loads(raw)["request"]["operation"]
        operations.append(op)
        reply = execute(family, operation, raw, until)
        assert reply.endswith(b"\n") and len(reply) <= 64 << 10
        response_sizes[op] = len(reply)
        if op == "redeem_policy_aggregate":
            result = json.loads(reply)["result"]
            assert result["publication"] == "first_authorized"
            committed.append(bytes(result["signed_authorization_json"]))
            (directory / "worker").unlink()
            raise run.cloud.frontend.AuthorityUnavailable("authority_response_lost")
        return reply

    authority = run.cloud.LateCidAuthority(lose_first_reply, read("intent"), b"{}", "auditor")
    authority.grant, authority.aggregate, authority.plan = read("grant"), read("aggregate"), b"already-issued"
    host_read, guest_write = os.pipe()
    guest_read, host_write = os.pipe()
    try:
        os.set_blocking(host_read, False)
        os.set_blocking(host_write, False)
        gateway = run.kube.LocalSerial(host_read, host_write, deadline)
        gateway._stage = "plan-sent"
        peer = PipePeer(guest_read, guest_write)
        peer.timeout = 10
        nonce = "81" * 32

        def guest():
            publish(peer, "admission_request", {"guest_nonce":nonce, "recorder_request_json":list(read("redeem"))})
            assert request(peer) == {"request_status": True}
            publish(peer, "admission_request", {"guest_nonce":nonce, "recorder_request_json":list(read("status"))})
            return bytes(request(peer)["signed_authorization"])

        with ThreadPoolExecutor(1) as pool:
            receiver = pool.submit(guest)
            receipt = run.kube.attempt.admit_pending(authority, gateway, authority.grant, authority.aggregate,
                                                      gateway.receive_admission_request(), deadline)
            gateway.send_admission(receipt)
            assert receiver.result() == receipt == committed[0]
        assert operations == ["pin_policy_admission", "redeem_policy_aggregate", "status_policy_aggregate"]
        with sqlite3.connect(config["issuer_store"]) as db:
            assert db.execute("SELECT receipt_json FROM policy_admissions").fetchall() == [(receipt,)]
            assert db.execute("SELECT count(redeemed_context) FROM challenges").fetchone() == (1,)
        print("Operator stdout sizes in bytes (including newline)", response_sizes)
    finally:
        for fd in (host_read, host_write, guest_read, guest_write):
            os.close(fd)


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
