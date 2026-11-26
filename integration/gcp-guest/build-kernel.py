#!/usr/bin/env python3
"""Build a GCP x86-64 EFI kernel with the supplied built-in initramfs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import zlib

from pe_measure import covered, measure


COMMAND_LINE = "noinitrd console=ttyS0,115200 rdinit=/init panic=1 ip=dhcp quiet loglevel=0"
CONFIG_OVERRIDES = {
    "CONFIG_INITRAMFS_SOURCE": '"builtin.cpio"',
    "CONFIG_CMDLINE": json.dumps(COMMAND_LINE),
    "CONFIG_IP_PNP": "y",
    "CONFIG_IP_PNP_DHCP": "y",
}
REQUIRED_CONFIG = dict.fromkeys(
    (
        "CONFIG_X86_64", "CONFIG_EFI_STUB", "CONFIG_BLK_DEV_INITRD",
        "CONFIG_INITRAMFS_COMPRESSION_NONE", "CONFIG_KERNEL_GZIP", "CONFIG_IKCONFIG",
        "CONFIG_CMDLINE_BOOL", "CONFIG_CMDLINE_OVERRIDE", "CONFIG_INTEL_TDX_GUEST",
        "CONFIG_TDX_GUEST_DRIVER", "CONFIG_TSM_REPORTS", "CONFIG_CONFIGFS_FS",
        "CONFIG_GVE", "CONFIG_BLK_DEV_NVME", "CONFIG_EROFS_FS_BACKED_BY_FILE",
        "CONFIG_SECCOMP_FILTER",
    ),
    "y",
) | dict.fromkeys(("CONFIG_MODULES", "CONFIG_BOOT_CONFIG", "CONFIG_LOCALVERSION_AUTO"), "n")
TOOLCHAIN_VERSIONS = {
    "CONFIG_CC_VERSION_TEXT", "CONFIG_GCC_VERSION", "CONFIG_CLANG_VERSION",
    "CONFIG_AS_VERSION", "CONFIG_LD_VERSION", "CONFIG_LLD_VERSION",
    "CONFIG_RUSTC_VERSION", "CONFIG_RUSTC_LLVM_VERSION", "CONFIG_PAHOLE_VERSION",
}
MAX_CPIO_BYTES = 513 << 20
MAX_RAW_KERNEL_BYTES = 768 << 20
ASSIGNMENT = re.compile(r"(CONFIG_\w+)=(.*)")
DISABLED = re.compile(r"# (CONFIG_\w+) is not set")


def sha384(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha384").hexdigest()


def config_lines(text):
    values = {}
    for index, line in enumerate(text.splitlines()):
        assignment = ASSIGNMENT.fullmatch(line)
        disabled = DISABLED.fullmatch(line)
        match = assignment or disabled
        if match:
            symbol = match[1]
            if symbol in values:
                raise ValueError(f"duplicate kernel config setting {symbol}")
            values[symbol] = (index, assignment[2] if assignment else "n")
    return values


def configure(base, target):
    values = config_lines(base)
    lines = base.splitlines()
    for symbol, value in CONFIG_OVERRIDES.items():
        line = f"{symbol}={value}"
        if symbol in values:
            lines[values[symbol][0]] = line
        else:
            lines.append(line)
    text = "\n".join(lines) + "\n"
    target.write_text(text, encoding="utf-8")
    return {symbol: value for symbol, (_, value) in config_lines(text).items()}


def check_config(path, expected):
    actual = {symbol: value for symbol, (_, value) in config_lines(path.read_text()).items()}
    for symbol, value in (REQUIRED_CONFIG | CONFIG_OVERRIDES).items():
        if actual.get(symbol) != value:
            raise ValueError(f"resolved kernel config must set {symbol} to {value}")
    for symbol in sorted(expected.keys() - TOOLCHAIN_VERSIONS):
        if actual.get(symbol, "n") != expected[symbol]:
            raise ValueError(f"olddefconfig changed {symbol}: {expected[symbol]} -> {actual.get(symbol)}")


def readback(image, compressed, cpio, config):
    measurement = measure(image)
    offset = image.find(compressed)
    if offset < 0 or image.find(compressed, offset + 1) >= 0:
        raise ValueError("compressed kernel must appear exactly once in the EFI image")
    if not covered(measurement, offset, len(compressed)):
        raise ValueError("compressed kernel is outside the measured EFI image section")

    inflater = zlib.decompressobj(wbits=31)
    raw = inflater.decompress(compressed, MAX_RAW_KERNEL_BYTES + 1)
    if (len(raw) > MAX_RAW_KERNEL_BYTES or not inflater.eof
            or inflater.unused_data or inflater.unconsumed_tail):
        raise ValueError("invalid gzip kernel payload")
    if raw.count(cpio) != 1:
        raise ValueError("supplied initramfs must appear exactly once in the kernel payload")

    marker = b"IKCFG_ST\x1f\x8b\x08"
    config_offset = raw.find(marker)
    if config_offset < 0 or raw.find(marker, config_offset + 1) >= 0:
        raise ValueError("embedded kernel config absent or ambiguous")
    inflater = zlib.decompressobj(wbits=31)
    embedded = inflater.decompress(memoryview(raw)[config_offset + 8:], len(config) + 1)
    if (embedded != config or not inflater.eof or inflater.unconsumed_tail
            or not inflater.unused_data.startswith(b"IKCFG_ED")):
        raise ValueError("embedded kernel config differs from resolved config")
    return measurement


def build(args):
    source = args.source.resolve(strict=True)
    config = args.config.resolve(strict=True)
    initramfs = args.initramfs.resolve(strict=True)
    output = args.output.resolve()
    if not (source / "arch/x86/boot/Makefile").is_file():
        raise ValueError("source must be a Linux kernel tree with x86 support")
    if not initramfs.is_file() or not 6 <= initramfs.stat().st_size <= MAX_CPIO_BYTES:
        raise ValueError("initramfs must be a bounded newc CPIO archive")
    with initramfs.open("rb") as stream:
        if stream.read(6) != b"070701":
            raise ValueError("initramfs must be an uncompressed newc CPIO archive")
    if output.is_relative_to(source):
        raise ValueError("output must be outside the kernel source tree")
    output.mkdir(parents=True, exist_ok=False)
    build_dir = output / "build"
    build_dir.mkdir()
    cpio = build_dir / "builtin.cpio"
    shutil.copyfile(initramfs, cpio)
    initramfs_digest = sha384(cpio)
    config_bytes = config.read_bytes()
    expected = configure(config_bytes.decode("utf-8"), build_dir / ".config")

    env = os.environ.copy()
    env.update(
        LC_ALL="C",
        KCONFIG_CONFIG=".config",
        KCONFIG_NOSILENTUPDATE="1",
        SOURCE_DATE_EPOCH="0",
        KBUILD_BUILD_TIMESTAMP="1970-01-01 00:00:00 +0000",
        KBUILD_BUILD_USER="podvm",
        KBUILD_BUILD_HOST="local",
        KBUILD_BUILD_VERSION="1",
    )
    command = ["make", "-C", str(source), f"O={build_dir}", "ARCH=x86_64"]
    with (output / "build.log").open("wb") as log:
        subprocess.run(command + ["olddefconfig"], env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        check_config(build_dir / ".config", expected)
        resolved = (build_dir / ".config").read_bytes()
        subprocess.run(command + [f"-j{args.jobs}", "bzImage"], env=env, stdout=log,
                       stderr=subprocess.STDOUT, check=True)
    if (build_dir / ".config").read_bytes() != resolved or sha384(cpio) != initramfs_digest:
        raise ValueError("kernel build inputs changed during compilation")
    boot = build_dir / "arch/x86/boot"
    image = (boot / "bzImage").read_bytes()
    measured = readback(image, (boot / "compressed/vmlinux.bin.gz").read_bytes(), cpio.read_bytes(), resolved)
    (output / "bootx64.efi").write_bytes(image)
    (output / "resolved.config").write_bytes(resolved)
    receipt = {
        "kernel_release": (build_dir / "include/config/kernel.release").read_text().strip(),
        "input_config_sha384": hashlib.sha384(config_bytes).hexdigest(),
        "kernel_config_sha384": hashlib.sha384(resolved).hexdigest(),
        "initramfs_sha384": initramfs_digest,
        "initramfs_bytes": cpio.stat().st_size,
        "pe_file_sha384": measured["file_sha384"],
        "pe_authenticode_sha384": measured["authenticode_sha384"],
        "pe_bytes": len(image),
    }
    (output / "build-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--initramfs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    try:
        build(args)
    except subprocess.CalledProcessError as error:
        parser.exit(1, f"kernel build failed with exit {error.returncode}; see {args.output / 'build.log'}\n")
    except (OSError, ValueError, zlib.error) as error:
        parser.exit(1, f"kernel build failed: {error}\n")


if __name__ == "__main__":
    main()
