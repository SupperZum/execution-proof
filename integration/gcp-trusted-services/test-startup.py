#!/usr/bin/env python3
"""Native HTTPS/startup negatives with ephemeral software test keys only.

No quote, L, cloud credential, policy acceptance or production root is created.
The dummy SA JSON is sent only over a private pipe, never written to a file.
"""
import argparse, base64, hashlib, http.client, json, os, select, signal, socket, ssl, subprocess, tempfile, time, traceback
from pathlib import Path

MARKER = b'{"status":"https_listening","production_qualified":false}\n'
ERROR = b'trusted GCP service startup or lifecycle rejected\n'
def sha(b): return hashlib.sha384(b).hexdigest()
def openssl(*args, data=None):
    p = subprocess.run(['/usr/bin/openssl', *args], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False)
    if p.returncode: raise RuntimeError('ephemeral test key operation failed')
    return p.stdout
def write(path, data):
    path.write_bytes(data); path.chmod(0o600)
def pin(path): return {'path':str(path),'sha384':sha(path.read_bytes())}
def fixture(root, collateral_source):
    proof = root/'proof.der'
    v1 = openssl('genpkey','-algorithm','ED25519','-outform','DER')
    pub = openssl('pkey','-inform','DER','-pubout','-outform','DER',data=v1)[-32:]
    # ring's strict production loader requires PKCS8 v2 with its public key.
    assert len(v1)==48 and v1[:16]==bytes.fromhex('302e020100300506032b657004220420')
    write(proof,bytes.fromhex('3051020101300506032b657004220420')+v1[-32:]+bytes.fromhex('812100')+pub)
    tls = root/'tls.pem'; cert = root/'cert.pem'
    write(tls,openssl('genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256'))
    write(cert,openssl('req','-new','-x509','-key',str(tls),'-days','1','-subj','/CN=kbs.onb17.test','-addext','subjectAltName=DNS:kbs.onb17.test'))
    policy = root/'policy.rego'; write(policy,b'package policy\ndefault launch_accepted := false\ndefault allow := false\n')
    collateral = root/'collateral.json'
    write(collateral, collateral_source.read_bytes())
    archive = root/'archive'; archive.mkdir(mode=0o700)
    with socket.socket() as s: s.bind(('127.0.0.1',0)); port=s.getsockname()[1]
    config = {'version':1,'purpose':'qlad.execution-proof.gcp-trusted-kbs-config.v1','listen':f'127.0.0.1:{port}','server_name':'kbs.onb17.test',
        'grant':{'authority_public_key':[17]*32,'audience':'launch-test','authority':'authority-test','tenant':'tenant-test','image_policy_sha384':'55'*48},
        'boot_binding':{'version':1,'purpose':'qlad.execution-proof.gcp-boot-binding.v1','profile':'onb17.gcp-tdx-embedded-pe.v1','config_sha384':'11'*48,'producer_core_sha384':'22'*48,'artifact_manifest_sha384':'33'*48,'reference_policy_sha384':'44'*48},
        'boot_policy':{'expected_pe_sha384':'66'*48,'expected_firmware_mrtd':'77'*48,'expected_instance':{'instance_id':1,'numerical_project_id':2,'zone':'us-central1-a'},'quote_padding':'gcp_tsm_zero_padded8000'},
        'module_policy':{'version':1,'purpose':'qlad.execution-proof.gcp-tdx-module-policy.v1','expected_mr_seam':'ab62561a173acbd18ee50ff37750db44184c6cf5e886df74247cc575e163b04c34b9e18374757c235affa614d4127f6b','allowed_td_attributes':268435456},
        'as_policy':{'id':'onb17-gcp-launch-test','policy':pin(policy)},'as_data':None,'kbs_policy':{'id':'onb17-gcp-resource-test','policy':pin(policy)},
        'aggregate_audience':'aggregate-test','aggregate_issuer':'kbs-test','delivery_audience':'delivery-test','delivery_issuer':'kbs-test',
        'resource_path':['onb17','kms','test'],'workflow_id':'workflow-test','credential_project_id':'test-project','credential_client_email':'test@test-project.iam.gserviceaccount.com',
        'kbs_proof_public_key':list(pub),'kbs_proof_key_path':str(proof),'tls_certificate':pin(cert),'tls_private_key_path':str(tls),
        'offline_collateral':pin(collateral),'archive_directory':str(archive),'lifetime_seconds':30}
    key = openssl('genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048')
    credential = bytearray(json.dumps({'type':'service_account','project_id':'test-project','private_key_id':'11'*20,'private_key':key.decode(),
        'client_email':config['credential_client_email'],'client_id':'123456789012345678901','auth_uri':'https://accounts.google.com/o/oauth2/auth',
        'token_uri':'https://oauth2.googleapis.com/token','auth_provider_x509_cert_url':'https://www.googleapis.com/oauth2/v1/certs',
        'client_x509_cert_url':'https://www.googleapis.com/robot/v1/metadata/x509/test','universe_domain':'googleapis.com'},separators=(',',':')).encode())
    path=root/'config.json'; write(path,json.dumps(config).encode())
    return config,path,credential,key,port,archive
def owned_start(binary, path, qvl_dir, credential=None, check_mode='--check-config'):
    command=[str(binary),check_mode,str(path)] if credential is None else [str(binary),'--serve',str(path),'--credential-stdin']
    p = subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,
        env={'LD_LIBRARY_PATH':str(qvl_dir)})
    try:
        if credential is not None:
            p.stdin.write(len(credential).to_bytes(4,'big'));p.stdin.write(credential)
        p.stdin.close(); p.stdin=None
    except BaseException:
        finish(p)
        raise
    return p
def capture(p):
    try:return p.communicate(timeout=8)
    except BaseException:
        finish(p)
        raise
def finish(p):
    try: os.killpg(p.pid,signal.SIGTERM)
    except ProcessLookupError: pass
    try: out,err=p.communicate(timeout=8)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid,signal.SIGKILL);out,err=p.communicate(timeout=5)
    return out,err
def request(port, path, method='POST', body=b'{}'):
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.minimum_version=ssl.TLSVersion.TLSv1_3;ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
    conn=http.client.HTTPSConnection('127.0.0.1',port,context=ctx,timeout=4)
    try:
        conn.request(method,path,body,{'Content-Type':'application/json'});r=conn.getresponse();data=r.read(8193)
        if len(data)>8192: raise RuntimeError('response bound')
        return r.status,data
    finally: conn.close()
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--collateral', type=Path, required=True)
    parser.add_argument('--qvl-library-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    qvl_dir = args.qvl_library_dir.resolve(strict=True)
    if not qvl_dir.is_dir():
        parser.error('QVL library directory required')
    checks=[]
    with tempfile.TemporaryDirectory(prefix='onb17-service-test-') as temp:
        root=Path(temp);root.chmod(0o700);config,path,credential,key,port,archive=fixture(root, args.collateral)
        patterns=[key,key.replace(b'\n',b'\\n'),bytes(credential),Path(config['tls_private_key_path']).read_bytes(),Path(config['kbs_proof_key_path']).read_bytes()]
        def clean(out,err):
            if any(v in out or v in err for v in patterns): raise RuntimeError('private test input appeared in output')
        p=owned_start(args.binary,path,qvl_dir)
        out,err=capture(p);clean(out,err)
        assert p.returncode==0 and out==b'{"status":"public_config_checked","production_qualified":false}\n' and not err
        checks.append('public config validates without secret input')
        p=owned_start(args.binary,path,qvl_dir,check_mode='--check-startup')
        out,err=capture(p);clean(out,err)
        assert p.returncode==0 and out==b'{"status":"startup_inputs_checked","production_qualified":false}\n' and not err
        checks.append('private proof and TLS inputs preflight before SA input')
        keypath=Path(config['kbs_proof_key_path']);saved=keypath.read_bytes();write(keypath,b'bad-test-only-proof-key')
        p=owned_start(args.binary,path,qvl_dir,check_mode='--check-startup');out,err=capture(p);clean(out,err)
        assert p.returncode!=0 and not out and err==ERROR
        write(keypath,saved);checks.append('invalid proof key rejects before SA input')
        config['server_name']='wrong.onb17.test';write(path,json.dumps(config).encode())
        p=owned_start(args.binary,path,qvl_dir);out,err=capture(p);clean(out,err)
        assert p.returncode!=0 and out==b'' and err==ERROR;checks.append('wrong pinned certificate SAN rejects with generic output')
        config['server_name']='kbs.onb17.test';write(path,json.dumps(config).encode())
        p=owned_start(args.binary,path,qvl_dir,b'{"private_key":"test-only-do-not-echo"}')
        out,err=capture(p);clean(out,err)
        assert p.returncode!=0 and out==b'' and err==ERROR;checks.append('invalid credential rejects before listen')
        p=owned_start(args.binary,path,qvl_dir,credential)
        first=b''
        try:
            assert select.select([p.stdout],[],[],8)[0], 'bounded startup'
            first=p.stdout.readline(256);assert first==MARKER,'exact readiness after bind'
            status,data=request(port,'/kbs/launch/gcp/v2/begin');assert status==400
            for legacy in ['/kbs/v0/auth','/kbs/v0/resource/onb17/kms/test','/kbs/v0/resource-policy','/metrics','/archive']:
                status,data=request(port,legacy,'GET');assert status==404
            assert list(archive.iterdir())==[]
            checks += ['actual TLS1.3 native listener ready','invalid GCP request rejects','legacy/admin/resource/archive routes absent','denied requests produce no archive']
        finally:
            out,err=finish(p);clean(first+out,err)
            assert p.poll() is not None
        checks.append('owned server killed or gracefully exited and reaped')
        credential[:]=bytes(len(credential))
    receipt={'schema':'onb17.trusted-service-native-startup-tests.v1','binary':{'path':str(args.binary.resolve()),'sha384':sha(args.binary.read_bytes())},'checks':checks,'result':'PASS','scope':'Ephemeral software keys and deny policy; no real SA, quote, L, accepted policy, archive, cloud or qualification.'}
    args.output.write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'result':'PASS','checks':len(checks)}))
if __name__=='__main__':
    try: main()
    except Exception as e:
        print(json.dumps({'result':'FAIL','exception':type(e).__name__,'line':traceback.extract_tb(e.__traceback__)[-1].lineno}));raise SystemExit(1) from None
