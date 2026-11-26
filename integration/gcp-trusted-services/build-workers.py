#!/usr/bin/env python3
"""Build the GNU authority and verifier workers for the private runtime."""
import argparse, hashlib, json, os, re, shutil, signal, subprocess, time
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

BUILD_SCHEMA = 'onb17.trusted-service-actual-worker-build.v2'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha384').hexdigest()


def worker_plans():
    yield EPP, 'execution-proof-issuer', 'gcp', ('gcp-authority',)
    yield EPP, 'execution-proof-verifier', 'gcp-journal', ('gcp-execution-proof-verifier',)
    yield TRUSTEE, 'verifier', 'execution-quote-worker-tdx', TDX_WORKERS


def selection(package, features):
    return ['--offline', '--locked', '--target', GNU, '-p', package,
            '--no-default-features', '--features', features]


def files_under(root, target, ancestors=frozenset()):
    directory = root.resolve(strict=True)
    if directory == target:
        return
    if directory in ancestors:
        raise ValueError(f'directory cycle in worker inputs: {root}')
    for entry in root.iterdir():
        if entry.name == '.git':
            continue
        if entry.is_dir():
            yield from files_under(entry, target, ancestors | {directory})
        else:
            yield entry


def sources(cargo, env):
    """Resolve local crates with the same Cargo selection as the worker build."""
    target = Path(env['CARGO_TARGET_DIR'])
    paths = {Path(__file__).resolve(), cargo}
    roots = set()
    graphs = {}
    config_dirs = {Path(env['CARGO_HOME'])}
    for cwd, package, features, bins in worker_plans():
        flags = selection(package, features)
        command = [str(cargo), 'tree', *flags, '--edges', 'normal,build',
                   '--color', 'never', '--prefix', 'none', '--format', '{p}\t{f}']
        tree = subprocess.check_output(command, cwd=cwd, env=env, text=True, timeout=60)
        rows = sorted({row.removesuffix(' (*)') for row in tree.splitlines() if row})
        graphs[package] = {'selection': flags, 'bins': sorted(bins), 'packages': rows}
        for row in rows:
            identity, _ = row.split('\t', 1)
            local = re.search(r' \((/.*)\)$', identity)
            if local:
                roots.add(Path(local[1]))
        paths.update((cwd / 'Cargo.toml', cwd / 'Cargo.lock'))
        config_dirs.update(parent / '.cargo' for parent in (cwd, *cwd.parents))
    for root in roots:
        paths.update(files_under(root, target))
    for directory in config_dirs:
        paths.update(p for p in (directory / 'config', directory / 'config.toml') if p.is_file())

    rustc = Path(env['RUSTC'])
    rust_version = subprocess.check_output([rustc, '-vV'], env=env, text=True, timeout=15)
    sysroot = Path(subprocess.check_output([rustc, '--print', 'sysroot'], env=env,
                                          text=True, timeout=15).strip())
    paths.add(rustc)
    paths.update((sysroot / 'lib').glob('*.so*'))
    rust_target = sysroot / 'lib/rustlib' / GNU
    paths.update(files_under(rust_target / 'lib', target))
    if (rust_target / 'bin').is_dir():
        paths.update(files_under(rust_target / 'bin', target))
    for name in ('cc', 'c++', 'ar', 'as', 'ld', 'clang', 'pkg-config'):
        executable = shutil.which(name, path=env['PATH'])
        if executable:
            paths.add(Path(executable))
    paths.update(files_under(Path(env['SGX_SDK']) / 'include', target))
    paths.add(Path(env['LIBRARY_PATH']) / 'libsgx_dcap_quoteverify.so')
    return {'graphs': graphs, 'rustc_version': rust_version, 'environment': env,
            'files': {str(p): sha(p) for p in sorted(paths)}}


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
        'RUSTC': str(cargo.with_name('rustc').resolve(strict=True)),
        'CARGO_HOME': str(Path(os.environ.get('CARGO_HOME', Path.home() / '.cargo')).resolve()),
        'CARGO_TARGET_DIR': str(target),
        'SGX_SDK': str(sdk),
        'BINDGEN_EXTRA_CLANG_ARGS': '-I' + str(include),
        'LIBRARY_PATH': str(args.qvl_library.absolute().parent),
        'LC_ALL': 'C',
        'TZ': 'UTC',
    }
    before = sources(cargo, env)
    checks = []
    for cwd, package, features, bins in worker_plans():
        for name in bins:
            verb = 'rustc' if name in TDX_WORKERS else 'build'
            command = [str(cargo), verb, *selection(package, features), '--bin', name]
            if verb == 'rustc':
                command.extend(['--', '-C', 'link-arg=-Wl,-rpath,' + PREFIX])
            duration = owned(command, cwd, env, out / (name + '.log'))
            artifact = target / GNU / 'debug' / name
            checks.append({
                'name': name, 'command': command, 'cwd': str(cwd), 'exit': 0, 'seconds': duration,
                'artifact': {'path': str(artifact), 'sha384': sha(artifact), 'bytes': artifact.stat().st_size},
            })
            print(json.dumps({'built': name, 'seconds': duration}), flush=True)
    after = sources(cargo, env)
    if before != after or sha(qvl) != QVL_SHA384:
        raise ValueError('source or QVL library changed during the build')
    receipt = {
        'schema': BUILD_SCHEMA,
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
