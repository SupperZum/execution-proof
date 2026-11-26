#!/usr/bin/python3
"""Dispatch the private controller's three operations on a proof worker."""

import json
import os
from pathlib import Path
import re

STATE = Path("/var/lib/onb17-single-guest")
CONFIG = Path("/var/lib/onb17-worker-access/access.json")
RUNTIME = "/run/execution-proof/"
UID = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
POD = r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?"


def command(raw, image, state_dir=STATE):
    prefix = "sudo -n " + RUNTIME
    if not raw.startswith(prefix):
        raise ValueError("worker command")
    args = raw[len(prefix):].split(" ")
    if len(args) == 3 and args[:2] == ["single-guest", "ready"] and re.fullmatch(UID, args[2]):
        return [RUNTIME + args[0], *args[1:]]

    uid = (state_dir / "pod-uid").read_text().rstrip("\n")
    if len(args) == 8 and args[:6] == [
        "worker-readback", "/run/containerd/containerd.sock", uid, image, "gcp-kata", "execution-proof"
    ] and re.fullmatch(POD, args[6]) and args[7] == "0":
        return [RUNTIME + args[0], *args[1:]]
    if (len(args) == 4 and args[:2] == ["caa-heartbeat", uid] and re.fullmatch(POD, args[2])
            and re.fullmatch(r"[a-f0-9]{8}", args[3])):
        return [RUNTIME + args[0], *args[1:]]
    raise ValueError("worker command")


if __name__ == "__main__":
    try:
        if os.geteuid() != 0:
            raise ValueError("worker identity")
        profile = json.loads(CONFIG.read_bytes())
        argv = command(os.environ.get("SSH_ORIGINAL_COMMAND", ""), profile["image"])
    except (OSError, ValueError, KeyError):
        raise SystemExit(126) from None
    os.execve(argv[0], argv, {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
