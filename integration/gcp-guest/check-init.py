#!/usr/bin/env python3
"""Exercise PID1's inert index/blob reader without mounts or host changes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


MAGIC = b'ONB17-TCB-IDX1\0\0'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--init', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    executable = args.init.resolve(strict=True)
    if os.getpid() == 1:
        parser.error('inert checks must not run as PID1')
    results = []
    with tempfile.TemporaryDirectory(prefix='onb17-init-inspect-') as temporary:
        root = Path(temporary)
        blob = root / 'blob'
        content = b'closed-proof-startup-inspection\0' * 400
        blob.write_bytes(content)
        digest = hashlib.sha384(content).digest()

        def check(name, index_bytes, expected, selected=blob):
            index = root / 'index'
            index.write_bytes(index_bytes)
            result = subprocess.run([str(executable), '--inspect', str(index), str(selected)],
                                    capture_output=True, timeout=5, check=False)
            passed = result.returncode == expected
            results.append({'case': name, 'exit_code': result.returncode, 'passed': passed})
            if not passed:
                raise RuntimeError(f'{name}: exit {result.returncode}, expected {expected}')

        index = MAGIC + len(content).to_bytes(8, 'big') + digest
        assert len(index) == 72
        check('matching-index-and-bytes', index, 0)
        check('unknown-index-domain', b'X' + index[1:], 2)
        check('truncated-index', index[:-1], 2)
        check('extended-index', index + b'\0', 2)
        check('empty-blob-declaration', MAGIC + bytes(8) + digest, 2)
        check('oversized-blob-declaration', MAGIC + ((512 << 20) + 1).to_bytes(8, 'big') + digest, 2)
        check('blob-length-mismatch', MAGIC + (len(content) + 1).to_bytes(8, 'big') + digest, 2)
        check('digest-mismatch', index[:-1] + bytes([index[-1] ^ 1]), 2)
        link = root / 'link'
        link.symlink_to(blob)
        check('symlink-blob', index, 2, link)
        fifo = root / 'fifo'
        os.mkfifo(fifo)
        check('nonregular-blob-without-blocking', index, 2, fifo)
        blob.write_bytes(content[:-1] + bytes([content[-1] ^ 1]))
        check('same-size-mutated-blob', index, 2)
        result = subprocess.run([str(executable), '--config', 'caller-controlled'],
                                capture_output=True, timeout=5, check=False)
        results.append({'case': 'caller-config-rejected', 'exit_code': result.returncode,
                        'passed': result.returncode == 64})
    receipt = {'schema': 'onb17.gcp-proof-init-inspection.v1',
               'artifact_sha384': hashlib.sha384(executable.read_bytes()).hexdigest(),
               'recipe_sha384': hashlib.sha384(Path(__file__).read_bytes()).hexdigest(),
               'checks': results, 'passed': all(r['passed'] for r in results),
               'scope': 'inert content inspection only; no mount, role launch or hardware evidence'}
    args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))
    raise SystemExit(0 if receipt['passed'] else 1)


if __name__ == '__main__':
    main()
