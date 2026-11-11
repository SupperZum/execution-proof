#!/usr/bin/env python3
"""Build the GNU authority and verifier workers for the private runtime."""
import argparse, hashlib, json, os, signal, subprocess, time
from pathlib import Path

HERE=Path(__file__).resolve().parent
EPP = HERE.parents[1]
TRUSTEE = EPP.parent / 'trustee-launch-dev'
PREFIX = '/opt/onb17/trusted/lib'
GNU = 'x86_64-unknown-linux-gnu'
QVL_SHA384 = '90dc9d13d0e48d11521a384c24d98f5fd6f9dced97507ae6fce1d53e41b64892940de4df7b05e82c9bf014a76db283d2'
TDX_WORKERS = ('gcp-tdx-pregrant-verifier', 'gcp-tdx-hardware-verifier',
               'gcp-tdx-bootstrap-history-verifier')
ARTIFACT_NAMES = {'gcp-authority', 'gcp-execution-proof-verifier', *TDX_WORKERS}

def sha(path):
    with path.open('rb')as f:return hashlib.file_digest(f,'sha384').hexdigest()
def sources():
    paths=[]
    for root in [EPP/'contract',EPP/'verifier',EPP/'issuer',TRUSTEE/'deps/verifier',TRUSTEE/'deps/eventlog']:
        paths.extend(root.rglob('*.rs'));paths.append(root/'Cargo.toml')
    paths += [EPP/'Cargo.toml',EPP/'Cargo.lock',TRUSTEE/'Cargo.toml',TRUSTEE/'Cargo.lock',Path(__file__)]
    return {str(p):sha(p)for p in sorted(set(paths))}
def owned(command,cwd,env,log,seconds=1800):
    child=None;start=time.monotonic();observed=None
    try:
        with log.open('wb')as f:
            child=subprocess.Popen(command,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
            while time.monotonic()-start<seconds:
                status=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
                if status is not None:
                    observed=status.si_status if status.si_code==os.CLD_EXITED else-status.si_status;break
                time.sleep(.1)
            if observed is None:raise RuntimeError('bounded build deadline')
    finally:
        if child is not None:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            child.wait()
    if observed:raise RuntimeError('build failed; inspect public build log')
    return round(time.monotonic()-start,3)
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cargo', type=Path, required=True, help='Cargo from the selected GNU toolchain')
    parser.add_argument('--sgx-sdk', type=Path, required=True)
    parser.add_argument('--qvl-library', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    cargo = args.cargo.resolve(strict=True)
    sdk = args.sgx_sdk.resolve(strict=True)
    include = sdk / 'include'
    qvl = args.qvl_library.resolve(strict=True)
    if not (cargo.is_file() and os.access(cargo, os.X_OK) and include.is_dir()):
        parser.error('selected Cargo executable and SGX SDK include directory are required')
    if sha(qvl) != QVL_SHA384:
        parser.error('QVL library does not match the selected software verifier profile')
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise ValueError('external child reaper unsupported')
    out = args.output.resolve()
    target = args.target_dir.resolve() if args.target_dir else out / 'target'
    out.mkdir(parents=True, exist_ok=False)
    env = {
        'PATH': str(cargo.parent) + ':/usr/bin:/bin',
        'CARGO_HOME': str(Path(os.environ.get('CARGO_HOME', Path.home() / '.cargo')).resolve()),
        'CARGO_TARGET_DIR': str(target),
        'SGX_SDK': str(sdk),
        'BINDGEN_EXTRA_CLANG_ARGS': '-I' + str(include),
        'LIBRARY_PATH': str(args.qvl_library.absolute().parent),
        'LC_ALL': 'C',
        'TZ': 'UTC',
    }
    before = sources()
    checks = []
    plans = [
        (EPP, ['build', '-p', 'execution-proof-issuer', '--no-default-features',
               '--features', 'gcp', '--bin', 'gcp-authority'], 'gcp-authority'),
        (EPP, ['build', '-p', 'execution-proof-verifier', '--no-default-features',
               '--bin', 'gcp-execution-proof-verifier'], 'gcp-execution-proof-verifier'),
    ]
    plans.extend((TRUSTEE, ['rustc', '-p', 'verifier', '--no-default-features',
                           '--features', 'execution-quote-worker-tdx', '--bin', name], name)
                 for name in TDX_WORKERS)
    for cwd, flags, name in plans:
        command = [str(cargo), *flags, '--offline', '--locked', '--target', GNU]
        if flags[0] == 'rustc':
            command.extend(['--', '-C', 'link-arg=-Wl,-rpath,' + PREFIX])
        duration = owned(command, cwd, env, out / (name + '.log'))
        artifact = target / GNU / 'debug' / name
        checks.append({
            'name': name, 'command': command, 'cwd': str(cwd), 'exit': 0, 'seconds': duration,
            'artifact': {'path': str(artifact), 'sha384': sha(artifact), 'bytes': artifact.stat().st_size},
        })
        print(json.dumps({'built': name, 'seconds': duration}), flush=True)
    after = sources()
    if before != after or sha(qvl) != QVL_SHA384:
        raise ValueError('source or QVL library changed during the build')
    receipt = {
        'schema': 'onb17.trusted-service-actual-worker-build.v1',
        'cargo': str(cargo),
        'qvl_library': {'path': str(qvl), 'sha384': QVL_SHA384},
        'environment': env,
        'checks': checks,
        'source_before': before,
        'source_after': after,
        'source_unchanged': True,
        'production_qualified': False,
        'execution_verified': False,
    }
    (out / 'build.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    main()
