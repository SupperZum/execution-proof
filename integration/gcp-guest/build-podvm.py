#!/usr/bin/env python3
"""Build a local GCP PodVM disk from selected guest files and Linux sources."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
MAX_DOCUMENT = 64 << 10
MAX_LEAF = 256 << 20
MAX_TOTAL = 512 << 20
RESOLVER = "/lib/x86_64-linux-gnu/libseccomp.so.2"
RESERVED = {"/onb17/boot/config.json", "/onb17/boot/producer-core.json", RESOLVER}


def read_input(path, limit):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError(f"expected a bounded regular input file: {path}")
        data = stream.read(info.st_size + 1)
    if len(data) != info.st_size:
        raise ValueError(f"input changed size: {path}")
    return data


def unique_object(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("duplicate JSON field in input file list")
    return value


def stage_files(list_path, config, output):
    entries = json.loads(read_input(list_path, MAX_DOCUMENT), object_pairs_hook=unique_object)
    if not isinstance(entries, list) or not 0 < len(entries) < 64:
        raise ValueError("expected between 1 and 63 input file entries")

    leaves = {}
    total = 0
    for item in entries:
        if (
            not isinstance(item, dict)
            or item.keys() != {"path", "kind", "source"}
            or any(not isinstance(value, str) or not value for value in item.values())
        ):
            raise ValueError("each input file needs a path, kind, and source")
        name = item["path"]
        if (
            len(name) > 256
            or not re.fullmatch(r"/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", name)
            or any(part in {".", ".."} for part in name.split("/"))
            or name.split("/")[1] in {"dev", "proc", "run", "sys", "tmp"}
            or name in RESERVED or name in leaves
        ):
            raise ValueError(f"invalid or duplicate guest path: {name}")
        data = read_input(list_path.parent / item["source"], min(MAX_LEAF, MAX_TOTAL - total))
        if not data.startswith(b"\x7fELF") and re.search(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", data):
            raise ValueError(f"private keys belong outside the guest build inputs: {name}")
        total += len(data)
        target = output / name[1:]
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as staged:
            staged.write(data)
        leaves[name] = {
            "kind": item["kind"], "path": name, "sha384": hashlib.sha384(data).hexdigest(),
            "size_bytes": len(data),
        }
    return {
        "version": 1, "purpose": "qlad.execution-proof.gcp-producer-core.v1",
        "config_sha384": hashlib.sha384(config).hexdigest(),
        "leaves": [leaves[name] for name in sorted(leaves)],
    }


def run_script(name, *args):
    subprocess.run([sys.executable, "-B", HERE / name, *args], check=True)


def build(args):
    for tool in ("make", "readelf", "sgdisk", "mkfs.fat", "mmd", "mcopy", "tar", "gzip"):
        if shutil.which(tool) is None:
            raise ValueError(f"required build tool not on PATH: {tool}")
    files = args.files.resolve(strict=True)
    config = read_input(args.config, MAX_DOCUMENT)
    validator = args.validator.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    boot_config = output / "config.json"
    boot_config.write_bytes(config)
    base_core = output / "base-producer-core.json"
    leaves = output / "leaves"
    core = stage_files(files, config, leaves)
    base_core.write_text(json.dumps(core, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    subprocess.run([validator, boot_config, base_core], check=True)

    archive = output / "tcb.tar"
    run_script(
        "package-rootfs.py", "--leaves", leaves, "--config", boot_config, "--core", base_core,
        "--libseccomp", args.libseccomp, "--libseccomp-sha384", args.libseccomp_sha384,
        "--output", archive,
    )
    payload = output / "payload"
    run_script("build-payload.py", "--archive", archive, "--erofs-tools", args.erofs_tools,
               "--output", payload)
    subprocess.run([validator, boot_config, payload / "producer-core.json"], check=True)

    kernel = output / "kernel"
    run_script(
        "build-kernel.py", "--source", args.kernel_source, "--config", args.kernel_config,
        "--initramfs", payload / "builtin.cpio", "--output", kernel, "--jobs", str(args.jobs),
    )
    disk = output / "disk"
    run_script("build-disk.py", "--pe", kernel / "bootx64.efi", "--output", disk)
    print(disk / "disk.tar.gz")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=Path, required=True, help="JSON list of measured guest files")
    parser.add_argument("--config", type=Path, required=True, help="public boot configuration JSON")
    parser.add_argument("--validator", type=Path, required=True, help="gcp-build-inputs example executable")
    parser.add_argument("--libseccomp", type=Path, required=True)
    parser.add_argument("--libseccomp-sha384", required=True)
    parser.add_argument("--erofs-tools", type=Path, required=True)
    parser.add_argument("--kernel-source", type=Path, required=True)
    parser.add_argument("--kernel-config", type=Path, default=HERE / "gcp-tdx.defconfig")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--output", type=Path, required=True, help="new build output directory")
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    try:
        build(args)
    except subprocess.CalledProcessError as error:
        step = Path(error.cmd[2]).name if error.cmd[0] == sys.executable else "boot input validator"
        parser.exit(1, f"{step} failed with exit {error.returncode}\n")
    except (OSError, ValueError) as error:
        parser.exit(1, f"{parser.prog}: {error}\n")


if __name__ == "__main__":
    main()
