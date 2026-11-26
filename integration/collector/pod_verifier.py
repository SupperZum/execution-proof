"""Pinned, offline verifier for a dedicated container in the collector Pod."""
from contextlib import contextmanager
import ctypes
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import tempfile

from collector import (CHALLENGE_LIMIT, PACK_LIMIT, TRUST_LIMIT, Rejected, Unavailable,
                       Verifier, bounded, digest, encode, verifier_result)
from offline import restrict_network


# Abstract Unix sockets are scoped to this Linux network namespace.
ADDRESS = b"\0execution-proof.verifier.v1"
COLLECTOR_UID = 65532
VERIFIER_UID = 65531
MANIFEST = Path("/opt/onb17/trusted/manifest.sha384")
INPUT_DIR = Path("/run/verifier-inputs")
NAMES = ("pack", "trust", "challenge")
REQUEST_NAME = re.compile(r"request-[a-z0-9_]{1,48}")
PEERCRED = struct.Struct("3i")
LIMITS = (PACK_LIMIT, TRUST_LIMIT, CHALLENGE_LIMIT)
MAX_REPLY = 8192


def peer_uid(conn):
    return PEERCRED.unpack(conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, PEERCRED.size))[1]


@contextmanager
def staged_inputs(inputs):
    # Serialise users of this dedicated volume, including across collector restarts.
    fd = os.open(INPUT_DIR, os.O_DIRECTORY | os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for entry in INPUT_DIR.iterdir():
            if REQUEST_NAME.fullmatch(entry.name):
                shutil.rmtree(entry)
        with tempfile.TemporaryDirectory(prefix="request-", dir=INPUT_DIR) as tmp:
            directory = Path(tmp)
            for name, value in zip(NAMES, inputs):
                path = directory / name
                path.write_bytes(value)
                path.chmod(0o444)
            directory.chmod(0o755)
            yield directory.name
    finally:
        os.close(fd)


def manifest_id(path):
    return bytes.fromhex(digest(bounded(path, 65536)))


class PodVerifier:
    def __init__(self, manifest):
        self.pin = manifest_id(manifest)

    def __call__(self, pack, trust, challenge):
        inputs = (pack, trust, challenge)
        sizes = tuple(map(len, inputs))
        if not all(0 < size <= limit for size, limit in zip(sizes, LIMITS)):
            raise Rejected("invalid input size")
        try:
            with staged_inputs(inputs) as directory, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(70)
                conn.connect(ADDRESS)
                if peer_uid(conn) != VERIFIER_UID:
                    raise Unavailable("unexpected verifier identity")
                conn.sendall(b"EPV1" + self.pin + directory.encode("ascii"))
                conn.shutdown(socket.SHUT_WR)
                with conn.makefile("rb") as stream:
                    raw = stream.read(MAX_REPLY + 1)
            if len(raw) > MAX_REPLY:
                raise Unavailable("oversized verifier reply")
            reply = json.loads(raw)
            if not isinstance(reply, dict):
                raise Unavailable("invalid verifier reply")
            if reply.get("error") == "invalid":
                raise Rejected("invalid evidence")
            if (reply.get("inputs") != [digest(value) for value in inputs]
                    or not isinstance(reply.get("verdict"), dict)):
                raise Unavailable("missing or mismatched verifier result")
            return reply["verdict"]
        except (OSError, ValueError, RecursionError) as error:
            raise Unavailable("verifier unavailable") from error


def verify_request(conn, verifier, pin):
    with conn.makefile("rb") as stream:
        request = stream.read(128)
    if len(request) >= 128 or request[:52] != b"EPV1" + pin:
        raise Unavailable("verifier profile mismatch")
    name = request[52:].decode("ascii")
    if not REQUEST_NAME.fullmatch(name):
        raise ValueError("invalid request directory")
    args = verifier.args.copy()
    hashes = []
    for field, limit in zip(NAMES, LIMITS):
        path = INPUT_DIR / name / field
        hashes.append(digest(bounded(path, limit)))
        args.extend(["--" + field, path])
    result = subprocess.run(args, env={}, stdin=subprocess.DEVNULL, capture_output=True,
                            close_fds=True, timeout=60)
    return {"inputs": hashes, "verdict": verifier_result(result)}


def main():
    if os.geteuid() != VERIFIER_UID or not os.statvfs("/").f_flag & os.ST_RDONLY:
        raise SystemExit("verifier requires its dedicated UID and read-only container root")
    if not INPUT_DIR.is_dir() or not os.statvfs(INPUT_DIR).f_flag & os.ST_RDONLY:
        raise SystemExit("verifier inputs require a read-only mount")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    if status["NoNewPrivs"].strip() != "1" or int(status["CapBnd"], 16):
        raise SystemExit("verifier requires no-new-privileges and all capabilities dropped")
    # Keep the supervisor's descriptors private from child processes of the same UID.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0):  # PR_SET_DUMPABLE
        raise OSError(ctypes.get_errno(), "could not protect the verifier supervisor")
    verifier = Verifier(Path("/"), MANIFEST)
    pin = manifest_id(MANIFEST)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(ADDRESS)
        restrict_network()
        listener.listen(4)
        while True:
            conn, _ = listener.accept()
            with conn:
                if peer_uid(conn) != COLLECTOR_UID:
                    continue
                conn.settimeout(15)
                try:
                    reply = verify_request(conn, verifier, pin)
                except Rejected:
                    reply = {"error": "invalid"}
                except (Unavailable, OSError, ValueError, subprocess.TimeoutExpired):
                    reply = {"error": "unavailable"}
                try:
                    conn.sendall(encode(reply))
                except OSError:
                    pass


if __name__ == "__main__":
    main()
