#!/usr/bin/env python3
"""Build the immutable GCP guest EROFS and built-in initramfs from a USTAR archive."""

import argparse
from hashlib import file_digest, sha384
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile

CONFIG = "onb17/boot/config.json"
CORE = "onb17/boot/producer-core.json"
MOUNT_DIRS = {"", "dev", "proc", "run", "sys", "sys/kernel", "sys/kernel/config"}
MAX_FILE = 256 << 20
MAX_BLOB = 512 << 20
MAX_TAR = MAX_BLOB + (2 << 20)
MAX_DOCUMENT = 64 << 10
MAX_ENTRIES = 256
INDEX_MAGIC = b"ONB17-TCB-IDX1\0\0"
EXECUTABLE_KINDS = {
    "bootstrap_binary", "cdh_binary", "kata_agent_binary", "management_relay_binary",
    "helper_binary", "loader", "shared_library",
}
LEAF_KINDS = EXECUTABLE_KINDS | {
    "relay_config", "rpc_policy", "device_policy", "writer_policy", "tls_roots",
    "launch_policy", "image_policy", "data",
}
TOOL_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"}
FILE_MODE = re.compile(r"^Uid: (\d+)\s+Gid: (\d+)\s+Access: ([0-7]{4})/", re.MULTILINE)


def digest(path):
    with path.open("rb") as stream:
        return file_digest(stream, "sha384").digest()


def snapshot_archive(path, snapshot):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as source, snapshot.open("xb") as target:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_TAR:
            raise ValueError("expected a bounded regular input archive")
        remaining = info.st_size
        while remaining:
            block = source.read(min(remaining, 1 << 20))
            if not block:
                raise ValueError("input archive shrank while being copied")
            target.write(block)
            remaining -= len(block)
        if source.read(1):
            raise ValueError("input archive grew while being copied")


def unique_object(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("duplicate JSON field")
    return value


def check_core(config_bytes, core_bytes, files):
    config = json.loads(config_bytes, object_pairs_hook=unique_object)
    core = json.loads(core_bytes, object_pairs_hook=unique_object)
    if (
        not isinstance(config, dict)
        or type(config.get("version")) is not int
        or config["version"] != 1
        or config.get("purpose") != "qlad.execution-proof.gcp-closed-boot-config.v1"
        or config.get("bootstrap_path") != "/init"
        or not isinstance(core, dict)
        or core.keys() != {"version", "purpose", "config_sha384", "leaves"}
        or type(core["version"]) is not int
        or core["version"] != 1
        or core["purpose"] != "qlad.execution-proof.gcp-producer-core.v1"
        or core["config_sha384"] != sha384(config_bytes).hexdigest()
        or not isinstance(core["leaves"], list)
        or not 0 < len(core["leaves"]) <= 64
    ):
        raise ValueError("invalid boot configuration or producer core")
    names = []
    bootstrap = []
    for leaf in core["leaves"]:
        if not isinstance(leaf, dict) or leaf.keys() != {"kind", "path", "sha384", "size_bytes"}:
            raise ValueError("invalid producer leaf")
        path = leaf["path"]
        kind = leaf["kind"]
        if (
            not isinstance(path, str) or not path.startswith("/")
            or path[1:] not in files or path[1:] in {CONFIG, CORE}
            or not isinstance(kind, str) or kind not in LEAF_KINDS
            or type(leaf["size_bytes"]) is not int
        ):
            raise ValueError("invalid producer leaf path, kind, or size")
        name = path[1:]
        mode = 0o555 if kind in EXECUTABLE_KINDS else 0o444
        size, actual_mode, sha = files[name]
        if (size, actual_mode, sha.hex()) != (leaf["size_bytes"], mode, leaf["sha384"]):
            raise ValueError(f"producer core does not match archive leaf: {name}")
        if kind == "bootstrap_binary":
            bootstrap.append(name)
        names.append(name)
    if names != sorted(set(files) - {CONFIG, CORE}) or bootstrap != ["init"]:
        raise ValueError("archive does not match the sorted producer inventory")


def validate_archive(path):
    directories = set()
    files = {}
    documents = {}
    total = 0
    with path.open("rb") as archive:
        while True:
            header = archive.read(tarfile.BLOCKSIZE)
            if header == bytes(tarfile.BLOCKSIZE):
                tail_limit = tarfile.RECORDSIZE + tarfile.BLOCKSIZE
                tail = archive.read(tail_limit + 1)
                if not tarfile.BLOCKSIZE <= len(tail) <= tail_limit or any(tail):
                    raise ValueError("invalid USTAR trailer")
                break
            if len(directories) + len(files) >= MAX_ENTRIES:
                raise ValueError("archive entry limit exceeded")
            # Read each raw USTAR header without interpreting extension records.
            item = tarfile.TarInfo.frombuf(header, "ascii", "strict")
            name = "" if item.name == "." else item.name
            if (
                name in directories or name in files or len(name) > 255
                or (name and not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", name))
                or any(part in {".", ".."} for part in name.split("/"))
                or item.uid != 0 or item.gid != 0 or item.mtime != 0
                or item.uname or item.gname
            ):
                raise ValueError(f"unsafe or noncanonical archive entry: {item.name!r}")
            if header != item.tobuf(format=tarfile.USTAR_FORMAT):
                raise ValueError("archive contains a noncanonical USTAR header")
            if item.type == tarfile.DIRTYPE and item.size == 0 and item.mode == 0o555:
                directories.add(name)
                continue
            if (
                not name or item.type != tarfile.REGTYPE
                or not 0 < item.size <= MAX_FILE or item.mode not in {0o444, 0o555}
            ):
                raise ValueError(f"unsupported archive entry: {item.name!r}")
            total += item.size
            if total > MAX_BLOB:
                raise ValueError("archive file bytes exceed the inventory limit")
            hasher = sha384()
            if name in {CONFIG, CORE}:
                if item.size > MAX_DOCUMENT or item.mode != 0o444:
                    raise ValueError("invalid embedded configuration or inventory document")
                data = archive.read(item.size)
                if len(data) != item.size:
                    raise ValueError("truncated embedded configuration or inventory document")
                documents[name] = data
                hasher.update(data)
            else:
                remaining = item.size
                while remaining:
                    block = archive.read(min(remaining, 1 << 20))
                    if not block:
                        raise ValueError("truncated archive member")
                    hasher.update(block)
                    remaining -= len(block)
            padding = -item.size % tarfile.BLOCKSIZE
            if archive.read(padding) != bytes(padding):
                raise ValueError("archive contains nonzero member padding")
            files[name] = (item.size, item.mode, hasher.digest())
    needed_dirs = MOUNT_DIRS | {
        str(parent) for name in files for parent in Path(name).parents if str(parent) != "."
    }
    if directories != needed_dirs or set(documents) != {CONFIG, CORE}:
        raise ValueError("archive directory or boot document inventory mismatch")
    check_core(documents[CONFIG], documents[CORE], files)
    return directories, files, documents[CORE]


def run_tool(command, timeout):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            env=TOOL_ENV, timeout=timeout)
    if result.returncode or b"<E>" in result.stdout:
        raise ValueError(f"{Path(command[0]).name} failed: {result.stdout[:1024].decode(errors='replace')}")
    return result.stdout


def check_readback(readback, blob, dump, directories, files):
    observed = {path.relative_to(readback).as_posix() for path in readback.rglob("*")}
    if observed != (directories - {""}) | files.keys():
        raise ValueError("EROFS readback inventory does not match the archive")
    for name in sorted(directories | files.keys()):
        path = readback / name
        info = path.lstat()
        expected_mode = 0o555
        if name in files:
            size, expected_mode, expected_sha = files[name]
            if not stat.S_ISREG(info.st_mode) or info.st_size != size or digest(path) != expected_sha:
                raise ValueError(f"EROFS file readback mismatch: /{name}")
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"EROFS directory readback mismatch: /{name}")
        if stat.S_IMODE(info.st_mode) != expected_mode:
            raise ValueError(f"EROFS extracted permissions mismatch: /{name}")
        metadata = run_tool([dump, f"--path=/{name}", blob], 10)
        match = FILE_MODE.search(metadata.decode("ascii")) if len(metadata) <= 16384 else None
        if not match or (int(match[1]), int(match[2]), int(match[3], 8)) != (0, 0, expected_mode):
            raise ValueError(f"EROFS on-disk ownership or permissions mismatch: /{name}")


def write_builtin_cpio(output, init, index, blob):
    directories = [(name, stat.S_IFDIR | 0o755, None, 0, 0)
                   for name in ("dev", "proc", "boot", "view")]
    entries = directories + [
        ("dev/console", stat.S_IFCHR | 0o600, None, 5, 1),
        ("init", stat.S_IFREG | 0o555, init, 0, 0),
        ("boot/tcb-index.bin", stat.S_IFREG | 0o444, index, 0, 0),
        ("boot/tcb.erofs", stat.S_IFREG | 0o444, blob, 0, 0),
        ("TRAILER!!!", 0, None, 0, 0),
    ]
    with output.open("xb") as stream:
        for inode, (name, mode, source, major, minor) in enumerate(entries, 1):
            encoded = name.encode("ascii") + b"\0"
            size = source.stat().st_size if source is not None else 0
            fields = (inode, mode, 0, 0, 2 if stat.S_ISDIR(mode) else 1, 0,
                      size, 0, 0, major, minor, len(encoded), 0)
            stream.write(b"070701" + "".join(f"{field:08x}" for field in fields).encode("ascii"))
            stream.write(encoded)
            stream.write(bytes(-stream.tell() % 4))
            if source is not None:
                with source.open("rb") as member:
                    shutil.copyfileobj(member, stream, length=1 << 20)
            stream.write(bytes(-stream.tell() % 4))
        stream.write(bytes(-stream.tell() % 512))


def build(args):
    tools = args.erofs_tools.resolve(strict=True)
    mkfs, fsck, dump = [tools / name for name in ("mkfs.erofs", "fsck.erofs", "dump.erofs")]
    for tool in (mkfs, fsck, dump):
        if not tool.is_file() or not os.access(tool, os.X_OK):
            raise ValueError(f"missing executable EROFS tool: {tool}")
    output = args.output.absolute()
    if os.path.lexists(output):
        raise FileExistsError(output)
    with tempfile.TemporaryDirectory(prefix=".gcp-payload-", dir=output.parent) as directory:
        staging = Path(directory)
        archive = staging / "tcb.tar"
        snapshot_archive(args.archive, archive)
        directories, files, core = validate_archive(archive)
        artifacts = staging / "artifacts"
        artifacts.mkdir(mode=0o700)
        blob = artifacts / "tcb.erofs"
        run_tool([mkfs, "--tar=f", "--sort=none", "-b4096",
                  "-Eforce-inode-extended,^inline_data,^xattr-name-filter", "-x-1",
                  "-T0", "--mkfs-time", "--preserve-mtime",
                  "-U00000000-0000-0000-0000-000000000000", "--quiet", blob, archive], 300)
        size = blob.stat().st_size
        if not 4096 <= size <= MAX_BLOB:
            raise ValueError("EROFS blob size is outside the boot limit")
        readback = staging / "readback"
        run_tool([fsck, f"--extract={readback}", "--no-preserve-owner", "--preserve-perms", blob], 300)
        check_readback(readback, blob, dump, directories, files)
        index = artifacts / "tcb-index.bin"
        index.write_bytes(INDEX_MAGIC + struct.pack(">Q", size) + digest(blob))
        (artifacts / "producer-core.json").write_bytes(core)
        write_builtin_cpio(artifacts / "builtin.cpio", readback / "init", index, blob)
        output.mkdir(mode=0o700)
        try:
            artifacts.rename(output)
        except OSError:
            output.rmdir()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--erofs-tools", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    try:
        build(parser.parse_args())
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(1, f"{parser.prog}: {error}\n")


if __name__ == "__main__":
    main()
