"""Public-only NCC reconstruction and pinned native invocation; no private state."""
from contextlib import ExitStack
import hashlib
import json
import os
import subprocess
import time
from . import native_build
from .regression import PUBLIC_T
from publication.shared import sealed_public
from pq_sat_auth.prototypes.buov_cap_hplus_research_v0_1 import full_statement as ncc,public_setup


def beta_from_statement(raw):
    if type(raw) is not bytes or len(raw)!=ncc.FRAME_BYTES:raise ValueError('H+ statement width')
    return raw[-ncc.PUBLIC_BYTES:][128:200]


def reconstruct(raw,snapshot,setup):
    return ncc.decode_statement(raw,snapshot=snapshot,beta=beta_from_statement(raw),setup=setup)


def own_records(public_map,setup):
    from pq_rbbc.blind_uov_hplus_research_v0_1.uov import issuer_key_id
    records={name:os.urandom(width) for name,width in ncc.OWN_FIELDS}
    records.update(relation_profile_digest=ncc.RELATION_ID,cap_profile_fingerprint=ncc.x18.FINGERPRINT,
        issuer_map_digest=public_map.public_map_digest,issuer_key_id=issuer_key_id(public_map),
        trace_public_key_digest=setup.trace_digest,configuration_generation=(1).to_bytes(8,'big'),
        suite_id=(1).to_bytes(2,'big'),session_expiry=(int(time.time())+86400).to_bytes(8,'big'))
    return records


def validate(record,proving,proof_bytes=None):
    data=public_setup.checkpoint()
    if record.get('schema')!='BUOVCAPHPlusProofExecutionV1':raise ValueError('H+ execution schema')
    for k in ('compiler_id','setup_id','actual_symbolic_setup','public_CS_identity','counts'):
        if not public_setup._exact(record.get(k),data[k]):raise ValueError('H+ actual profile '+k)
    if (record['private_values_received'] is not proving or record['compute_cores']!=1
            or record['security_bits']!=128 or record['statement_bytes']!=ncc.FRAME_BYTES
            or record['Prove']!=int(proving) or record['proof_Verify']!=int(not proving)):
        raise ValueError('H+ actual proof call metadata')
    if not proving and type(record.get('accepted')) is not bool:raise ValueError('actual native verdict')
    if proof_bytes is not None and record['proof_body_bytes']!=proof_bytes:raise ValueError('exact received proof length')
    return record


def native(mode,statement_path,proof_path,*,payload=None,pass_fds=()):
    native_build.audit();public_setup.audit_public_cache()
    cmd=[str(native_build.DEFAULT/'hplus_proof'),mode,str(statement_path),str(PUBLIC_T),str(proof_path)]
    if mode=='full-verify':
        if payload is not None:raise ValueError('NCC accepts no witness payload')
        cmd.append(str(public_setup.DEFAULT_CACHE))
    elif mode!='full-prove' or type(payload) is not bytes:raise ValueError('explicit UE private input')
    begin=time.monotonic()
    result=subprocess.run(cmd,input=payload if payload is not None else b'',pass_fds=pass_fds,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=1700,env=dict(os.environ,RAYON_NUM_THREADS='1'))
    # Never serialize native error diagnostics, which might reflect private assignments.
    if result.returncode or result.stderr or len(result.stdout)>128<<10:raise ValueError('H+ native proof worker failed')
    lines=result.stdout.splitlines()
    if len(lines)!=1 or not lines[0].startswith(b'HPLUS_PROOF '):raise ValueError('H+ proof telemetry framing')
    record=json.loads(lines[0][12:]);validate(record,mode=='full-prove');record['process_seconds']=time.monotonic()-begin
    return record


def verify_received(statement,proof,snapshot,setup):
    reconstruct(statement,snapshot,setup)
    with ExitStack() as stack:
        sf=stack.enter_context(sealed_public(statement,ncc.FRAME_BYTES))
        pf=stack.enter_context(sealed_public(proof,8<<20))
        record=native('full-verify',f'/proc/self/fd/{sf}',f'/proc/self/fd/{pf}',pass_fds=(sf,pf))
    validate(record,False,len(proof))
    return record['accepted'],record
