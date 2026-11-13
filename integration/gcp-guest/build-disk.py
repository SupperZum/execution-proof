#!/usr/bin/env python3
"""Package an x86-64 EFI boot image as a GCP raw-disk import archive."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import zlib


DISK_SIZE = 1 << 30
SECTOR_SIZE = 512
FIRST_LBA = 2048
PARTITION_SECTORS = DISK_SIZE // SECTOR_SIZE - 2 * FIRST_LBA
LAST_LBA = FIRST_LBA + PARTITION_SECTORS - 1
ESP_TYPE = bytes.fromhex("28732ac11ff8d211ba4b00a0c93ec93b")
MAX_EFI = 256 << 20
MAX_ARCHIVE = 64 << 20
EFI_PATH = "::/EFI/BOOT/BOOTX64.EFI"


def copy_efi(source, destination):
    with os.fdopen(os.open(source, os.O_RDONLY | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 64 <= info.st_size <= MAX_EFI:
            raise ValueError("expected a bounded EFI executable")
        dos = stream.read(64)
        if len(dos) != 64 or dos[:2] != b"MZ":
            raise ValueError("missing EFI executable header")
        offset = struct.unpack_from("<I", dos, 60)[0]
        if not 64 <= offset <= info.st_size - 94:
            raise ValueError("invalid EFI executable header offset")
        stream.seek(offset)
        pe = stream.read(94)
        if (
            len(pe) != 94 or pe[:4] != b"PE\0\0"
            or struct.unpack_from("<H", pe, 4)[0] != 0x8664
            or struct.unpack_from("<H", pe, 20)[0] < 70
            or struct.unpack_from("<H", pe, 24)[0] != 0x20B
            or struct.unpack_from("<H", pe, 92)[0] != 10
        ):
            raise ValueError("expected an x86-64 PE32+ EFI application")
        stream.seek(0)
        with destination.open("xb") as output:
            remaining = info.st_size
            while remaining:
                data = stream.read(min(remaining, 1 << 20))
                if not data:
                    raise ValueError("EFI executable changed while reading")
                output.write(data)
                remaining -= len(data)
            if stream.read(1):
                raise ValueError("EFI executable changed while reading")


def verify_gpt(raw):
    with raw.open("rb") as stream:
        stream.seek(SECTOR_SIZE)
        header = bytearray(stream.read(SECTOR_SIZE))
        if len(header) != SECTOR_SIZE or header[:8] != b"EFI PART":
            raise ValueError("missing primary GPT header")
        length, expected = struct.unpack_from("<II", header, 12)
        header[16:20] = bytes(4)
        if length != 92 or zlib.crc32(header[:length]) != expected:
            raise ValueError("invalid primary GPT header CRC")
        lba, count, entry_size, expected = struct.unpack_from("<QIII", header, 72)
        if (lba, count, entry_size) != (2, 128, 128):
            raise ValueError("unexpected primary GPT table geometry")
        stream.seek(lba * SECTOR_SIZE)
        table = stream.read(count * entry_size)
        if len(table) != count * entry_size or zlib.crc32(table) != expected:
            raise ValueError("invalid primary GPT table CRC")
        if (
            table[:16] != ESP_TYPE
            or struct.unpack_from("<QQ", table, 32) != (FIRST_LBA, LAST_LBA)
            or any(table[entry_size:])
        ):
            raise ValueError("expected one EFI system partition with fixed geometry")


def hashes(stream):
    sha384 = hashlib.sha384()
    md5 = hashlib.md5(usedforsecurity=False)
    size = 0
    for block in iter(lambda: stream.read(1 << 20), b""):
        sha384.update(block)
        md5.update(block)
        size += len(block)
    return {
        "bytes": size,
        "sha384": sha384.hexdigest(),
        "md5_base64": base64.b64encode(md5.digest()).decode("ascii"),
    }


def file_hashes(path):
    with path.open("rb") as stream:
        return hashes(stream)


def build(pe, output):
    tools = {}
    for name in ("sgdisk", "mkfs.fat", "mmd", "mcopy", "tar", "gzip"):
        executable = shutil.which(name)
        if executable is None:
            raise ValueError(f"required tool not on PATH: {name}")
        tools[name] = str(Path(executable).absolute())

    output = output.parent.resolve() / output.name
    if output.is_symlink() or (output.exists() and (not output.is_dir() or any(output.iterdir()))):
        raise ValueError("output must be a new or empty directory")
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix=".boot-disk-", dir=output.parent) as temporary:
        root = Path(temporary) / "disk"
        root.mkdir(mode=0o700)
        environment = {
            "PATH": os.defpath, "LC_ALL": "C", "TZ": "UTC", "MTOOLSRC": "/dev/null",
            "SOURCE_DATE_EPOCH": "315532800",
        }

        def run(tool, *args, stdout=subprocess.PIPE):
            result = subprocess.run(
                [tools[tool], *args], cwd=root, env=environment, stdout=stdout,
                stderr=subprocess.PIPE, timeout=120, check=False,
            )
            if result.returncode:
                detail = (result.stderr or result.stdout or b"").decode(errors="replace").strip()
                raise ValueError(f"{tool} failed: {detail}")
            return result.stdout

        staged = root / "bootx64.efi"
        copy_efi(pe, staged)
        expected_pe = file_hashes(staged)
        raw = root / "disk.raw"
        with raw.open("xb") as stream:
            stream.truncate(DISK_SIZE)

        run(
            "sgdisk", "--clear", "--disk-guid=17110900-0000-4000-8000-000000000001",
            f"--new=1:{FIRST_LBA}:{LAST_LBA}", "--typecode=1:EF00",
            "--partition-guid=1:17110900-0000-4000-8000-000000000002",
            "--change-name=1:ONB17ESP", raw.name,
        )
        run(
            "mkfs.fat", "--invariant", "-F", "32", "-i", "17110901", "-n", "ONB17ESP",
            f"--offset={FIRST_LBA}", raw.name, str(PARTITION_SECTORS // 2),
        )
        image = f"{raw.name}@@{FIRST_LBA * SECTOR_SIZE}"
        run("mmd", "-i", image, "::/EFI", "::/EFI/BOOT")
        run("mcopy", "-i", image, staged.name, EFI_PATH)
        readback = root / "efi-readback"
        run("mcopy", "-i", image, EFI_PATH, readback.name)
        if file_hashes(readback) != expected_pe:
            raise ValueError("EFI system partition executable readback mismatch")
        readback.unlink()
        staged.unlink()
        if b"No problems found." not in run("sgdisk", "--verify", raw.name):
            raise ValueError("GPT verification did not pass")
        verify_gpt(raw)

        expected_disk = file_hashes(raw)
        if expected_disk["bytes"] != DISK_SIZE:
            raise ValueError("unexpected raw disk length")
        tar_path = root / "disk.tar"
        compressed = root / "disk.tar.gz"
        run(
            "tar", "--format=oldgnu", "--sparse", "--mtime=@0", "--owner=0", "--group=0",
            "--numeric-owner", "--mode=0664", "-cf", tar_path.name, raw.name,
        )
        with compressed.open("xb") as stream:
            run("gzip", "-n", "-9", "-c", tar_path.name, stdout=stream)
        tar_path.unlink()
        if not 0 < compressed.stat().st_size <= MAX_ARCHIVE:
            raise ValueError("compressed disk archive exceeds the size limit")
        with tarfile.open(compressed, "r:gz") as archive:
            member = archive.next()
            if (
                member is None or member.name != raw.name or not member.isfile()
                or not member.issparse() or member.size != DISK_SIZE
                or (member.uid, member.gid, member.mtime) != (0, 0, 0)
            ):
                raise ValueError("expected one sparse, root-owned disk.raw TAR member")
            with archive.extractfile(member) as stream:
                if hashes(stream) != expected_disk:
                    raise ValueError("archive does not reproduce the logical raw disk")
            if archive.next() is not None:
                raise ValueError("unexpected additional disk archive member")
        if file_hashes(raw) != expected_disk:
            raise ValueError("raw disk changed during packaging")

        record = {
            "schema": "qlad.execution-proof.gcp-import-disk.v1",
            "format": "oldgnu_sparse", "member": raw.name,
            "gpt": {"first_lba": FIRST_LBA, "last_lba": LAST_LBA, "sector_bytes": SECTOR_SIZE},
            "efi": expected_pe, "logical_disk": expected_disk, "archive": file_hashes(compressed),
        }
        (root / "import-manifest.json").write_text(json.dumps(record, indent=2) + "\n")
        root.rename(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pe", required=True, type=Path, help="x86-64 EFI application")
    parser.add_argument("--output", required=True, type=Path, help="new or empty output directory")
    args = parser.parse_args()
    try:
        build(args.pe, args.output)
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(1, f"{parser.prog}: {error}\n")


if __name__ == "__main__":
    main()
