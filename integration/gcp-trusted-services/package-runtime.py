#!/usr/bin/env python3
"""Build/freeze a private GNU trusted-service chroot; never install or mount it.

Keys/config/collateral/SA JSON are deliberately absent. All native processes use
only already-pinned public code. Source binaries remain unchanged.
"""
import argparse, hashlib, importlib.util, ipaddress, json, re, shutil, struct, subprocess
from pathlib import Path

HERE=Path(__file__).resolve().parent
EPP=HERE.parents[1];BASE=EPP.parent;TRUSTEE=BASE/'trustee-launch-dev'
PREFIX=Path('/opt/onb17/trusted');GNU='x86_64-unknown-linux-gnu'
def sha(path):
    with path.open('rb')as f:return hashlib.file_digest(f,'sha384').hexdigest()
def digest(raw):return hashlib.sha384(raw).hexdigest()
def inventory():
    roots=[HERE,EPP/'contract',EPP/'client',EPP/'issuer',EPP/'verifier',EPP/'handoff',TRUSTEE/'attestation-service/src',TRUSTEE/'kbs/src',TRUSTEE/'deps/verifier',TRUSTEE/'deps/eventlog',TRUSTEE/'deps/policy-engine',TRUSTEE/'deps/key-value-storage']
    paths=[]
    for root in roots:
        paths += [p for p in root.rglob('*') if p.is_file() and p.suffix in {'.rs','.toml','.lock','.rego','.c','.h','.py'} and not set(p.parts)&{'target','__pycache__','.git'}]
    paths += [EPP/'Cargo.toml',EPP/'Cargo.lock',TRUSTEE/'Cargo.toml',TRUSTEE/'Cargo.lock']
    return {str(p.relative_to(BASE)):sha(p)for p in sorted(set(paths))}
def elf(path):
    data=path.read_bytes()
    if data[:6]!=b'\x7fELF\x02\x01':raise ValueError('GNU ELF64 required')
    offset=struct.unpack_from('<Q',data,32)[0];size,count=struct.unpack_from('<HH',data,54)
    headers=[];loads=[];interpreter=None
    for i in range(count):
        h=struct.unpack_from('<IIQQQQQQ',data,offset+size*i);headers.append(list(h))
        if h[0]==1:
            body=bytearray(data[h[2]:h[2]+h[5]])
            if h[2]==0:body[40:48]=bytes(8);body[58:64]=bytes(6)
            loads.append({'header':list(h),'sha384':digest(body)})
        if h[0]==3:interpreter=data[h[2]:h[2]+h[5]].rstrip(b'\0').decode()
    dynamic=subprocess.run(['/usr/bin/readelf','-d',str(path)],capture_output=True,timeout=15,check=True).stdout.decode()
    needed=re.findall(r'\(NEEDED\).*?\[(.*?)\]',dynamic)
    runpaths=re.findall(r'\((?:RUNPATH|RPATH)\).*?\[(.*?)\]',dynamic)
    if any(p!='/opt/onb17/trusted/lib'for p in runpaths):raise ValueError('unexpected runtime lookup path')
    return {'program_headers':headers,'load_segments':loads,'interpreter':interpreter,'needed':needed,'runpaths':runpaths}
def frozen(source,dest):
    before={'sha384':sha(source),'bytes':source.stat().st_size};original=elf(source)
    subprocess.run(['/usr/bin/strip','--strip-debug','-o',str(dest),str(source)],check=True,timeout=30)
    dest.chmod(0o555)
    if elf(dest)!=original or sha(source)!=before['sha384']:raise ValueError('strip altered runtime ELF or input')
    return {'input':{'path':str(source),**before},'artifact':{'path':str(dest),'sha384':sha(dest),'bytes':dest.stat().st_size},'runtime_elf':original,'strip':'--strip-debug; full PHDR/interpreter/dynamic dependencies/PT_LOAD preserved except ELF section-table header fields'}
def hosts(path):
    with path.open('rb') as stream:
        data = stream.read((64 << 10) + 1)
    if len(data) > 64 << 10:
        raise ValueError('hosts input exceeds 64 KiB')
    entries = ['127.0.0.1 localhost']
    for line in data.decode('ascii').splitlines():
        fields = line.partition('#')[0].split()
        if not fields:
            continue
        address = ipaddress.ip_address(fields[0])
        if len(fields) < 2 or any(not re.fullmatch(r'[A-Za-z0-9_.-]{1,253}', name)
                                  for name in fields[1:]):
            raise ValueError('hosts input must contain literal addresses and hostnames')
        entries.append(' '.join((str(address), *fields[1:])))
    return '\n'.join(entries) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workers-build', type=Path, required=True)
    parser.add_argument('--experiment', type=Path, required=True)
    parser.add_argument('--hosts-file', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    a = parser.parse_args()
    selected_hosts = hosts(a.hosts_file)
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    root = out / 'rootfs'
    for name in ['opt/onb17/trusted/bin','opt/onb17/trusted/lib','lib/x86_64-linux-gnu','lib64','etc','proc','dev','run','tmp']:(root/name).mkdir(parents=True,exist_ok=True)
    (root/'run').chmod(0o700);(root/'tmp').chmod(0o700)
    spec=importlib.util.spec_from_file_location('worker_recipe',HERE/'build-workers.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    previous=json.loads((a.workers_build/'build.json').read_text())
    if previous['schema'] != 'onb17.trusted-service-actual-worker-build.v1':
        raise ValueError('worker build receipt schema')
    if previous['source_after'] != mod.sources():
        raise ValueError('worker source changed since build')
    checks = previous['checks']
    if len(checks) != len(mod.ARTIFACT_NAMES) or {item['name'] for item in checks} != mod.ARTIFACT_NAMES:
        raise ValueError('worker build receipt is incomplete')
    qvl = Path(previous['qvl_library']['path']).resolve(strict=True)
    if sha(qvl) != previous['qvl_library']['sha384'] or sha(qvl) != mod.QVL_SHA384:
        raise ValueError('QVL library does not match the build')
    cargo = Path(previous['cargo']).resolve(strict=True)
    before=inventory();env=previous['environment']
    target = Path(env['CARGO_TARGET_DIR']).resolve(strict=True) / GNU / 'debug'
    command=[str(cargo),'rustc','--offline','--locked','--target',GNU,'--features','server','--bin','gcp-trusted-kbs','--','-C','link-arg=-Wl,-rpath,/opt/onb17/trusted/lib']
    seconds=mod.owned(command,str(HERE),env,out/'service-build.log',600)
    artifacts=[]
    paths=[]
    for item in checks:
        source = Path(item['artifact']['path'])
        if (source != target / item['name'] or item['exit'] != 0
                or sha(source) != item['artifact']['sha384']
                or source.stat().st_size != item['artifact']['bytes']):
            raise ValueError('worker binary changed since build')
        paths.append(source)
    experiment = a.experiment.resolve(strict=True)
    if experiment.name != 'onb17-qualification-experiment':
        raise ValueError('qualification experiment executable name rejected')
    paths += [target/'gcp-trusted-kbs', experiment]
    for source in paths:artifacts.append(frozen(source,root/'opt/onb17/trusted/bin'/source.name))
    if inventory()!=before:raise ValueError('local source changed during service build/freeze')
    libs={};todo=[name for artifact in artifacts for name in artifact['runtime_elf']['needed']]
    while todo:
        name=todo.pop()
        if name in libs:continue
        if not re.fullmatch(r'[A-Za-z0-9_.+-]+',name):raise ValueError('library soname rejected')
        source=qvl if name=='libsgx_dcap_quoteverify.so.1' else Path('/lib/x86_64-linux-gnu')/name
        source=source.resolve(strict=True);info=elf(source)
        libs[name]={'source':str(source),'sha384':sha(source),'bytes':source.stat().st_size,'needed':info['needed']}
        for directory in ['opt/onb17/trusted/lib','lib/x86_64-linux-gnu']:
            target=root/directory/name;shutil.copyfile(source,target);target.chmod(0o555)
        todo += info['needed']
    loader=Path('/lib64/ld-linux-x86-64.so.2').resolve(strict=True)
    shutil.copyfile(loader,root/'lib64/ld-linux-x86-64.so.2');(root/'lib64/ld-linux-x86-64.so.2').chmod(0o555)
    (root/'etc/nsswitch.conf').write_text('hosts: files\n')
    (root/'etc/hosts').write_text(selected_hosts)
    checks=[]
    for artifact in artifacts:
        path=Path(artifact['artifact']['path'])
        result=subprocess.run([str(root/'lib64/ld-linux-x86-64.so.2'),'--inhibit-cache','--library-path',str(root/'opt/onb17/trusted/lib'),'--list',str(path)],env={},capture_output=True,timeout=15,check=True)
        listing=result.stdout.decode()
        for name in libs:
            expected=str(root/'lib64/ld-linux-x86-64.so.2') if name=='ld-linux-x86-64.so.2' else f'{root}/opt/onb17/trusted/lib/{name}'
            if name+' =>' in listing and expected not in listing:raise ValueError('native loader escaped selected library closure')
        checks.append({'artifact':path.name,'loader_exit':0,'listing':listing})
    files={str(path.relative_to(root)):{'sha384':sha(path),'bytes':path.stat().st_size,'mode':oct(path.stat().st_mode&0o777)}for path in sorted(root.rglob('*'))if path.is_file()}
    receipt = {
        'schema': 'onb17.private-trusted-runtime-package.v1',
        'service_build': {'command': command, 'seconds': seconds},
        'source_before': before, 'source_after': inventory(), 'source_unchanged': True,
        'artifacts': artifacts, 'libraries': libs,
        'loader': {'source': str(loader), 'sha384': sha(loader)},
        'native_loader_checks': checks, 'rootfs_inventory': files,
        'production_qualified': False, 'deployment_run': False,
    }
    (out/'package.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'result':'PASS_BUILD_FREEZE_AND_NATIVE_LOADER','artifacts':len(artifacts),'libraries':len(libs),'rootfs_files':len(files)}))
if __name__=='__main__':main()
