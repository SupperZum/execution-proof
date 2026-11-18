#!/usr/bin/env python3
"""Build the fixed native PID1; does not install, boot, mount, or sign an image."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha384(path.read_bytes()).hexdigest()


def inspect_static(path):
    data = path.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<HH', data, 16) != (2, 62):
        raise ValueError('static x86-64 ET_EXEC required')
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    if size != 56 or not 1 <= count <= 128 or offset + size * count > len(data):
        raise ValueError('invalid static ELF program headers')
    for i in range(count):
        kind, flags = struct.unpack_from('<II', data, offset + i * size)
        if kind in (2, 3) or kind == 0x6474e551 and flags & 1:
            raise ValueError('dynamic/interpreter/executable stack in PID1')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--crypto-archive', type=Path, required=True)
    p.add_argument('--crypto-includes', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    archive, includes, output = a.crypto_archive.resolve(), a.crypto_includes.resolve(), a.output.resolve()
    if not archive.is_file() or not (includes / 'x86_64-linux-gnu/openssl/opensslconf.h').is_file():
        p.error('workspace static OpenSSL archive and matching headers required')
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    command = ['/usr/bin/cc', '-static', '-no-pie', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
               '-Wno-deprecated-declarations', '-Wl,-z,noexecstack', '-Wl,-z,relro', '-Wl,-z,now',
               '-I' + str(includes), '-I' + str(includes / 'x86_64-linux-gnu'),
               str(HERE / 'init.c'), str(archive), '-ldl', '-pthread', '-o', str(output / 'init')]
    with (output / 'build.log').open('wb') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=120, check=False)
    receipt = {'schema': 'onb17.gcp-proof-init-build.v1', 'command': command,
               'exit_code': result.returncode, 'source_sha384': digest(HERE / 'init.c'),
               'recipe_sha384': digest(Path(__file__)), 'crypto_archive_sha384': digest(archive),
               'runtime': 'NOT_RUN', 'producer_qualified': False}
    if result.returncode == 0:
        inspect_static(output / 'init')
        receipt['artifact'] = {'sha384': digest(output / 'init'), 'bytes': (output / 'init').stat().st_size}
    (output / 'build-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
