#!/usr/bin/env python3
"""Package a measured x86-64 GNU guest rootfs with Kata's seccomp resolver."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tarfile
import tempfile

RESOLVER = "/lib/x86_64-linux-gnu/libseccomp.so.2"
LIBC = "/lib/x86_64-linux-gnu/libc.so.6"
LOADER = "/lib64/ld-linux-x86-64.so.2"
CONFIG = "/onb17/boot/config.json"
CORE = "/onb17/boot/producer-core.json"
CORE_PURPOSE = "qlad.execution-proof.gcp-producer-core.v1"
MAX_DOCUMENT = 64 << 10
MAX_LEAF = 256 << 20
MAX_TOTAL = 512 << 20
EXECUTABLE_KINDS = {
    "bootstrap_binary", "cdh_binary", "kata_agent_binary", "management_relay_binary",
    "helper_binary", "loader", "shared_library",
}
LEAF_KINDS = EXECUTABLE_KINDS | {
    "relay_config", "rpc_policy", "device_policy", "writer_policy", "tls_roots",
    "launch_policy", "image_policy", "data",
}


def read_regular(path, limit, *, allow_symlink=False):
    flags = os.O_RDONLY | os.O_NONBLOCK
    if not allow_symlink:
        flags |= os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError(f"expected a bounded regular file: {path}")
        data = stream.read(info.st_size + 1)
    if len(data) != info.st_size:
        raise ValueError(f"input size changed: {path}")
    return data


def sha384(data):
    return hashlib.sha384(data).hexdigest()


def unique_object(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("duplicate JSON key in producer core")
    return value


def load_core(path, config):
    core = json.loads(read_regular(path, MAX_DOCUMENT), object_pairs_hook=unique_object)
    if (
        not isinstance(core, dict)
        or core.keys() != {"version", "purpose", "config_sha384", "leaves"}
        or type(core["version"]) is not int
        or core["version"] != 1
        or core["purpose"] != CORE_PURPOSE
        or core["config_sha384"] != sha384(config)
        or not isinstance(core["leaves"], list)
        or not 0 < len(core["leaves"]) < 64
    ):
        raise ValueError("invalid producer core or boot config digest")

    previous = ""
    for leaf in core["leaves"]:
        if not isinstance(leaf, dict) or leaf.keys() != {"kind", "path", "sha384", "size_bytes"}:
            raise ValueError("invalid producer leaf")
        name = leaf["path"]
        if (
            not isinstance(name, str)
            or len(name) > 256
            or not re.fullmatch(r"/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", name)
            or any(part in {".", ".."} for part in name.split("/"))
            or name.split("/")[1] in {"dev", "proc", "run", "sys", "tmp"}
            or name <= previous
            or name in {CONFIG, CORE, RESOLVER}
            or not isinstance(leaf["kind"], str)
            or leaf["kind"] not in LEAF_KINDS
            or not isinstance(leaf["sha384"], str)
            or not re.fullmatch(r"[0-9a-f]{96}", leaf["sha384"])
            or leaf["sha384"] == "0" * 96
            or type(leaf["size_bytes"]) is not int
            or not 0 < leaf["size_bytes"] <= MAX_LEAF
        ):
            raise ValueError(f"invalid producer leaf: {name!r}")
        previous = name

    kinds = {leaf["path"]: leaf["kind"] for leaf in core["leaves"]}
    if kinds.get(LIBC) != "shared_library" or kinds.get(LOADER) != "loader":
        raise ValueError("producer core must measure the GNU libc and its loader")
    return core


def read_resolver(path, expected_sha384):
    data = read_regular(path, MAX_LEAF, allow_symlink=True)
    if sha384(data) != expected_sha384:
        raise ValueError("libseccomp SHA-384 mismatch")
    if (
        len(data) < 64 or data[:6] != b"\x7fELF\x02\x01"
        or struct.unpack_from("<HH", data, 16) != (3, 62)
    ):
        raise ValueError("libseccomp must be an x86-64 GNU shared object")

    # Inspect the same bytes that will enter the archive.
    with tempfile.NamedTemporaryFile() as candidate:
        candidate.write(data)
        candidate.flush()
        elf = subprocess.run(
            ["readelf", "-W", "-l", "-d", "--dyn-syms", candidate.name],
            capture_output=True, text=True, check=True, timeout=30,
            env={**os.environ, "LC_ALL": "C"},
        ).stdout
    stack_flags = ["".join(line.split()[6:-1]) for line in elf.splitlines()
                   if line.lstrip().startswith("GNU_STACK ")]
    if (
        re.findall(r"\(SONAME\)[^\n]*\[([^\]]+)\]", elf) != ["libseccomp.so.2"]
        or re.findall(r"\(NEEDED\)[^\n]*\[([^\]]+)\]", elf) != ["libc.so.6"]
        or re.search(r"^\s*INTERP\s|\((?:RPATH|RUNPATH)\)", elf, re.MULTILINE)
        or any("E" in flags for flags in stack_flags)
        or not re.search(
            r"^\s*\d+:\s+\S+\s+\d+\s+FUNC\s+(?:GLOBAL|WEAK)\s+(?:DEFAULT|PROTECTED)"
            r"\s+\d+\s+seccomp_syscall_resolve_name_arch(?:@@\S+)?$",
            elf, re.MULTILINE,
        )
    ):
        raise ValueError("libseccomp does not match the guest resolver profile")
    return data


def add_file(archive, name, mode, data):
    entry = tarfile.TarInfo(name.lstrip("/"))
    entry.mode = mode
    entry.size = len(data)
    archive.addfile(entry, io.BytesIO(data))


def package(args):
    root = args.leaves.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("staged leaves must be a directory")
    config = read_regular(args.config, MAX_DOCUMENT)
    core = load_core(args.core, config)
    resolver = read_resolver(args.libseccomp, args.libseccomp_sha384)
    leaves = {leaf["path"]: leaf for leaf in core["leaves"]}
    leaves[RESOLVER] = {
        "kind": "shared_library", "path": RESOLVER,
        "sha384": sha384(resolver), "size_bytes": len(resolver),
    }
    if sum(leaf["size_bytes"] for leaf in leaves.values()) > MAX_TOTAL:
        raise ValueError("producer leaf bytes exceed the inventory limit")
    core["leaves"] = [leaves[name] for name in sorted(leaves)]
    core_bytes = (json.dumps(core, indent=2) + "\n").encode()
    if len(core_bytes) > MAX_DOCUMENT:
        raise ValueError("producer core exceeds the document limit")
    embedded = {CONFIG: config, CORE: core_bytes}
    files = leaves.keys() | embedded.keys()
    dirs = {"", "dev", "proc", "run", "sys", "sys/kernel", "sys/kernel/config"}
    for name in files:
        dirs.update(str(parent) for parent in Path(name[1:]).parents if str(parent) != ".")
    if len(dirs) + len(files) > 256 or dirs & {name[1:] for name in files}:
        raise ValueError("invalid rootfs path inventory")

    with tempfile.NamedTemporaryFile(dir=args.output.parent) as output:
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name in sorted(dirs, key=lambda item: (item.count("/"), item)):
                entry = tarfile.TarInfo(name or ".")
                entry.type = tarfile.DIRTYPE
                entry.mode = 0o555
                archive.addfile(entry)
            for name in sorted(files):
                if name in embedded:
                    add_file(archive, name, 0o444, embedded[name])
                    continue
                leaf = leaves[name]
                if name == RESOLVER:
                    data = resolver
                else:
                    source = root / name[1:]
                    if source.resolve(strict=True) != source:
                        raise ValueError(f"symlink in staged leaf path: {name}")
                    data = read_regular(source, leaf["size_bytes"])
                if len(data) != leaf["size_bytes"] or sha384(data) != leaf["sha384"]:
                    raise ValueError(f"staged leaf does not match the producer core: {name}")
                mode = 0o555 if leaf["kind"] in EXECUTABLE_KINDS else 0o444
                add_file(archive, name, mode, data)
        output.flush()
        # Publish only after all leaf bytes match the embedded inventory.
        os.link(output.name, args.output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--leaves", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--libseccomp", type=Path, required=True)
    parser.add_argument("--libseccomp-sha384", required=True)
    parser.add_argument("--output", type=Path, required=True)
    try:
        package(parser.parse_args())
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError) as error:
        parser.exit(1, f"{parser.prog}: {error}\n")


if __name__ == "__main__":
    main()
