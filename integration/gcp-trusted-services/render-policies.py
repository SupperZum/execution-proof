#!/usr/bin/env python3
"""Render public manual-profile policies BEFORE C/D/PE freeze.

Operator selection is trusted configuration, never proof or attestation. No B,
PE or self-policy digest is embedded, avoiding a producer-artifact hash cycle.
"""
import argparse, hashlib, json, re
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for field in ['authority','tenant','container-role','workflow-id','resource-path']:
        p.add_argument('--'+field,required=True)
    p.add_argument('--workload-prefix',action='append',required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    for value in [a.authority,a.tenant,a.container_role,a.workflow_id,*a.workload_prefix]:
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',value):raise ValueError('scope identifier')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}/[A-Za-z0-9_.-]{1,128}/[A-Za-z0-9_.-]{1,128}',a.resource_path):raise ValueError('resource scope')
    if not 1<=len(a.workload_prefix)<=2 or len(set(a.workload_prefix))!=len(a.workload_prefix):raise ValueError('workload scope')
    q=json.dumps
    as_policy='''package policy
default launch_accepted := false
launch_accepted if {
    input.profile == "onb17.gcp-launch-quote.v2"
    input.tee == "tdx"
    input.tee_class == "cpu"
    input.claims.td_attributes.debug == false
    input.claims.tcb_status == "UpToDate"
    input.claims.collateral_expiration_status == "0"
}
'''
    kbs='''package policy
default allow := false
allow if {
    input.profile == "onb17.gcp-verified-launch-resource-input.v2"
    input.verified_launch.claims.td_attributes.debug == false
    input.verified_launch.claims.tcb_status == "UpToDate"
    input.verified_launch.claims.collateral_expiration_status == "0"
'''
    for field,value in [('authority',a.authority),('tenant',a.tenant),('container_role',a.container_role)]:
        kbs+=f'    input.verified_launch.binding.{field} == {q(value)}\n'
    kbs+=f'''    some prefix in {q(a.workload_prefix)}
    startswith(input.verified_launch.binding.workload_id, prefix)
    data.method == "GET"
    data.plugin == "resource"
    data["resource-path"] == {q(a.resource_path.split('/'))}
    data["workflow-id"] == {q(a.workflow_id)}
    data.query == {{}}
}}
'''
    a.output.mkdir(parents=True,exist_ok=False)
    receipt={}
    for name,text in [('as.rego',as_policy),('kbs.rego',kbs)]:
        raw=text.encode();(a.output/name).write_bytes(raw);receipt[name]={'bytes':len(raw),'sha384':hashlib.sha384(raw).hexdigest()}
    (a.output/'policy-pins.json').write_text(json.dumps({'schema':'onb17.public-manual-policy-pins.v1','files':receipt,'authorizing':False},indent=2)+'\n')
if __name__=='__main__':main()
