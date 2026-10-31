"""One H+ own-key NCC. Only actual public native Verify acceptance unlocks inversion."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import sys
import time
from publication.shared import check_limits
from .channel import write_setup,read_request,write_response
from .proof_runtime import own_records,beta_from_statement,verify_received
from . import native_build
from pq_sat_auth.prototypes.buov_cap_hplus_research_v0_1 import full_statement as ncc,public_setup
from pq_sat_auth.prototypes.buov_cap_hplus_research_v0_1.continuation import request_digest
from pq_rbbc.blind_uov_hplus_research_v0_1.uov import keygen,invert,evaluate_public_map


def run(metrics):
    start=time.monotonic();check_limits();native_build.audit();public_setup.audit_public_cache()
    pins=public_setup.public_setup_pins();setup=ncc.FullPublicSetup(pins.compiler_id,pins.setup_id,pins.trace_digest)
    begin=time.monotonic();public_map,secret_key=keygen(os.urandom(32));keygen_seconds=time.monotonic()-begin
    records=own_records(public_map,setup);snapshot=ncc.FullNCCSnapshot.from_records(records)
    hello=write_setup(sys.stdout.buffer,public_map.canonical_cpk,{k:v.hex() for k,v in records.items()},
        setup.compiler_id+setup.setup_id+setup.trace_digest)
    statement,proof,request_wire=read_request(sys.stdin.buffer)
    if sys.stdin.buffer.read(1):raise ValueError('one request and EOF')
    accepted,verifier=verify_received(statement,proof,snapshot,setup)
    z=None;rd=None;inversions=0;inversion_seconds=0.
    if accepted:
        beta=beta_from_statement(statement);begin=time.monotonic()
        z=invert(secret_key,beta,os.urandom(32));inversion_seconds=time.monotonic()-begin;inversions=1
        if evaluate_public_map(public_map,z)!=beta:raise ValueError('issuer inversion postcondition')
        rd=request_digest(statement,hashlib.sha256(proof).digest())
    response_wire=write_response(sys.stdout.buffer,rd,z)
    record=dict(schema='BUOVCAPHPlusNCCV1',accepted=accepted,proof_Verify=verifier['proof_Verify'],
        inversion_calls=inversions,verifier=verifier,keygen_seconds=keygen_seconds,inversion_seconds=inversion_seconds,
        setup_wire_bytes=hello,request_wire_bytes=request_wire,response_wire_bytes=response_wire,
        UE_witness_received=False,private_key_exported=False,secret_response_persisted=False,
        whole_seconds_including_UE_wait=time.monotonic()-start,
        memory_HWM_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024)
    with metrics.open('x') as f:json.dump(record,f,sort_keys=True,indent=2);f.write('\n')


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--metrics',type=Path,required=True)
    args=p.parse_args()
    try:run(args.metrics)
    except Exception as error:
        import traceback
        failure=dict(exception_type=type(error).__name__,stack=[dict(file=f.filename,line=f.lineno,function=f.name) for f in traceback.extract_tb(error.__traceback__)])
        with args.metrics.with_suffix('.failure.json').open('x') as target:json.dump(failure,target,sort_keys=True,indent=2)
        print('HPLUS_NCC_REJECT',file=sys.stderr);sys.exit(2)
