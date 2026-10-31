"""Single guarded H+ same-state research lifecycle; all private payloads stay in RAM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import secrets
import subprocess
import sys
import time
from . import regression as r,native_build
from .setup_run import wait_guard,captured_tail
from .proof_runtime import native,verify_received,own_records
from .ticket_consumer_run import ResearchTicketCAPKernel
from benchmarks.buov_cap_research_v0_1 import runner,binius_build
from publication.shared import bounded
from .channel import read_setup,write_request,read_response
from publication.shared import wire_measurement,validate_transfer
from pq_sat_auth.prototypes.buov_cap_hplus_research_v0_1 import public_setup,full_statement as ncc,full_assignment_input as ue
from pq_sat_auth.prototypes.buov_cap_hplus_research_v0_1.binius_checkpoint_plan import checkpoint_plan
from pq_sat_auth.prototypes.buov_cap_hplus_research_v0_1.continuation import continue_from_response,request_digest
from pq_sat_auth.prototypes.buov_cap_hplus_research_v0_1.ticket_consumer import ResearchPublicConfig
from pq_sat_auth.prototypes.buov_cap_hplus_research_v0_1.contract import SCOPE_FIELDS
from pq_rbbc.blind_uov_hplus_research_v0_1.prover import ProverRandomness
from pq_rbbc.blind_uov_hplus_research_v0_1.uov import UOVPublicMap,issuer_key_id
from pq_sat_auth.v3.final_ticket import trace_mceliece6688128_research_v0_1 as trace


def save(path,value):
    path.write_text(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n')


def source_pins():
    paths=[]
    for sub,glob in [('benchmarks/buov_cap_hplus_research_v0_1','*.py'),
            ('src/pq_sat_auth/prototypes/buov_cap_hplus_research_v0_1','*.py'),
            ('src/pq_rbbc/blind_uov_hplus_research_v0_1','*.py'),
            ('src/pq_rbbc/blind_uov_hplus_native_prover_v0_1','*.py')]:
        paths+=list((r.ROOT/sub).glob(glob))
    # Explicitly shared helpers; none of their old role entrypoints is called.
    paths += [r.ROOT/'publication/shared.py']
    for name in ('single_issuance_channel.py','lifecycle_channel.py','runner.py','binius_build.py'):
        paths.append(r.ROOT/'benchmarks/buov_cap_research_v0_1'/name)
    for name in ('ue_witness.py','binius_workspace_plan.py'):
        paths.append(r.ROOT/'src/pq_sat_auth/prototypes/buov_cap_research_v0_1'/name)
    return {str(p.relative_to(r.ROOT)):r.identity(p) for p in paths}


def worker(output):
    r.require_worker_boundary(output)
    # The generic runner supplies limits/lock; set the advisory role marker only after checking them.
    import fcntl
    with runner.LOCK.open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:pass
        else:raise ValueError('active shared heavy-job guard required')
    os.environ['BUOV_CAP_EXPLORATION_GUARDED']='1'
    whole=time.monotonic();output.mkdir(mode=0o700)
    pins=source_pins();libraries=native_build.provision();public_setup.audit_native_build();public_setup.audit_public_cache()
    cp=public_setup.checkpoint();ids=public_setup.public_setup_pins()
    setup=ncc.FullPublicSetup(ids.compiler_id,ids.setup_id,ids.trace_digest)
    # A fresh no-witness setup process exits before UE values and NCC private key coexist.
    begin=time.monotonic()
    child=subprocess.run([str(public_setup.DEFAULT_BUILD/'hplus_setup'),'load',str(public_setup.DEFAULT_CACHE),
        cp['public_cache']['sha256'],cp['public_CS_identity']['sha256']],input=captured_tail(),
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
    if child.returncode or child.stderr or len(child.stdout)>128<<10 or not child.stdout.startswith(b'HPLUS_SETUP '):
        raise ValueError('fresh public admission setup')
    public=json.loads(child.stdout[12:]);public_setup.validate_public_setup_result(public)
    plan=checkpoint_plan(public['counts'],public['actual_symbolic_setup'],public['after_setup']['RSS_bytes'],
        regenerated_masks=True,query_target=128)
    extra=(128<<20)+4*((2<<20)+4096);projection=plan['projected_with_margin_bytes']+extra
    if projection>=4<<30:raise ValueError('H+ Prove plus resident NCC admission')
    summary=dict(schema='BUOVCAPHPlusSameStateLifecycleV1',completed=False,phase='starting_NCC',
        parent_commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
        source_pins=pins,native_build=r.identity(native_build.DEFAULT/'build.json'),public_setup=public,
        public_admission_seconds=time.monotonic()-begin,allocation_plan=plan,
        resident_NCC_allowance_bytes=extra,projected_with_margin_bytes=projection,formal_RSS_bound=False,
        CAP_Init_calls=0,pi_iss_Prove=0,pi_iss_Verify=0,issuer_inversion_calls=0,UE_Append_calls=0,
        pi2_Prove=0,pi2_Verify=0,compute_cores=dict(UE=1,NCC=1,CAP=1),single_sample=True,
        Evidence_sealed=False,Proof_closed=False,Production_closed=False,security_qualification=False,
        production_entry_changed=False,private_payload_persisted=False)
    save(output/'summary.json',summary)
    issuer=subprocess.Popen([sys.executable,'-B','-m','benchmarks.buov_cap_hplus_research_v0_1.issuer',
        '--metrics',str(output/'NCC-metrics.json')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env=dict(os.environ,OMP_NUM_THREADS='1',OMP_THREAD_LIMIT='1',RAYON_NUM_THREADS='1'))
    kernel=None
    try:
        cpk,records,setup_ids,setup_wire=read_setup(issuer.stdout)
        if setup_ids!=setup.compiler_id+setup.setup_id+setup.trace_digest:raise ValueError('own NCC setup hello')
        public_map=UOVPublicMap(cpk);snapshot=ncc.FullNCCSnapshot.from_records({k:bytes.fromhex(v) for k,v in records.items()})
        own=snapshot.records()
        if own['issuer_map_digest']!=public_map.public_map_digest or own['issuer_key_id']!=issuer_key_id(public_map):
            raise ValueError('own NCC key/map')
        save(output/'NCC-own-public-records.json',records);(output/'issuer.cpk').write_bytes(cpk)
        flow=time.monotonic();begin=flow;trace_key=trace.TracePublicKeyV0_1(captured_tail())
        summary['phase']='CAP_Init_and_preparation';save(output/'summary.json',summary)
        prepared=ue.initialize_and_prepare(public_map,ProverRandomness(os.urandom(24),os.urandom(48)),
            snapshot=snapshot,setup=setup,SN=os.urandom(16),pk_H=os.urandom(1952),
            e=trace.encode_error_vector(tuple(sorted(secrets.SystemRandom().sample(range(6688),128)))),trace_public_key=trace_key)
        summary.update(CAP_Init_calls=1,CAP_preparation_seconds=time.monotonic()-begin,phase='UE_Prove')
        save(output/'summary.json',summary)
        statement=prepared.statement;sp=output/'issuance.nifs';sp.write_bytes(statement);proof=output/'issuance.research.zk.proof'
        p=native('full-prove',sp,proof,payload=prepared.private_frame)
        raw=bounded(proof,8<<20);pd=hashlib.sha256(raw).digest()
        validate_transfer(raw,statement,p,r.identity(proof),r.identity(sp))
        summary.update(pi_iss_Prove=1,prove=p,proof=r.identity(proof),statement=r.identity(sp),phase='NCC_Verify')
        save(output/'summary.json',summary)
        begin=time.monotonic();request_wire=write_request(issuer.stdin,statement,raw);issuer.stdin.close()
        rd,z,response_wire=read_response(issuer.stdout)
        if z is None or rd!=request_digest(statement,pd):raise ValueError('NCC response rejected or wrong request binding')
        request_seconds=time.monotonic()-begin
        if issuer.stdout.read(1):raise ValueError('NCC response EOF')
        issuer.wait(timeout=10)
        if issuer.returncode or issuer.stderr.read(1024):raise ValueError('NCC role failed')
        stats=json.loads(bounded(output/'NCC-metrics.json',128<<10))
        if (stats['accepted'] is not True or stats['proof_Verify']!=1 or stats['inversion_calls']!=1
                or any(stats[k] is not False for k in ('UE_witness_received','private_key_exported','secret_response_persisted'))):
            raise ValueError('NCC actual Verify/inversion')
        summary.update(pi_iss_Verify=1,issuer_inversion_calls=1,NCC=stats,phase='same_state_Append',
            request_response_seconds=request_seconds,wire=wire_measurement(setup_wire,request_wire,response_wire,stats,len(raw),len(statement)))
        summary['wire']['codec']='NIH1/v1 binary RAM pipe'
        save(output/'summary.json',summary)
        config=ResearchPublicConfig.from_records(public_map,{name:own[name] for name in SCOPE_FIELDS})
        _,scope,M=ue._content(snapshot=snapshot,setup=setup,SN=bytes(prepared.witness.field('SN')),
            pk_H=bytes(prepared.witness.field('pk_H')),e=bytes(prepared.witness.field('e')),trace_public_key=trace_key)
        if config.scope!=scope:raise ValueError('independently constructed same Scope')
        kernel=ResearchTicketCAPKernel(libraries,r.DEFAULT_EXPLORATION,config,M)
        result=continue_from_response(prepared,snapshot=snapshot,setup=setup,statement=statement,proof_digest=pd,
            response_z=z,response_request_digest=rd,trace_public_key=trace_key,kernel=kernel)
        flow_seconds=time.monotonic()-flow
        summary.update(UE_Append_calls=1,pi2_Prove=kernel.prove_calls,pi2_Verify=kernel.verify_calls,
            same_CAP_state_retained=True,flow_seconds=flow_seconds,
            continuation=dict(preflight_seconds=result.preflight_seconds,append_seconds=result.append_seconds,
                native_prove_seconds=result.native_prove_seconds,verify_seconds=result.verify_seconds,
                whole_seconds=result.whole_seconds,wire_lengths=result.wire_lengths),
            ticket_consumer=kernel.verifier_record,configuration_pin=kernel.configuration_pin,phase='separate_controls')
        save(output/'summary.json',summary)
        # Public-only negative controls; no additional inversion or second CAP state.
        summary['ticket_controls']=kernel.controls(result.c_r,result.c_z,result.pi_2)
        bad=bytearray(raw);bad[len(bad)//2]^=1
        accepted,badrecord=verify_received(statement,bytes(bad),snapshot,setup)
        if accepted:raise ValueError('changed issuance proof accepted')
        summary['issuance_bad_proof_control']=badrecord
        other=dict(own);other['ctx']=bytes([own['ctx'][0]^1])+own['ctx'][1:]
        try:ncc.decode_statement(statement,snapshot=ncc.FullNCCSnapshot.from_records(other),beta=prepared.beta,setup=setup)
        except ValueError:summary['own_records_mutation_rejected_before_native']=True
        else:raise ValueError('changed own records accepted')
        if kernel.prove_calls!=1 or kernel.verify_calls!=1:raise ValueError('one actual final CAP P/V')
        del result,prepared,z,M,bad
        if source_pins()!=pins:raise ValueError('lifecycle source drift')
        native_build.audit();public_setup.audit_public_cache()
        summary.update(completed=True,phase='completed',whole_seconds=time.monotonic()-whole,
            controller_HWM_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
            full_production_issuance_communication_bytes=None,security_binding_theorem_closed=False)
        save(output/'summary.json',summary)
        print('HPLUS_LIFECYCLE '+json.dumps(dict(completed=True,flow_seconds=flow_seconds,
            proof_body_bytes=len(raw),pi2_bytes=summary['continuation']['wire_lengths']['pi_2'],
            statement_bytes=len(statement),whole_seconds=summary['whole_seconds'])),flush=True)
    finally:
        if kernel is not None:kernel.close()
        if issuer.poll() is None:issuer.terminate();issuer.wait(timeout=10)
        for stream in (issuer.stdin,issuer.stdout,issuer.stderr):
            if stream is not None and not stream.closed:stream.close()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--label',default='lifecycle-v1')
    p.add_argument('--wait-seconds',type=int,default=120);p.add_argument('--worker',type=Path,help=argparse.SUPPRESS)
    args=p.parse_args()
    if args.worker:
        try:worker(args.worker)
        except Exception as error:
            import traceback
            save(args.worker/'failure.json',dict(exception_type=type(error).__name__,
                stack=[dict(file=f.filename,line=f.lineno,function=f.name) for f in traceback.extract_tb(error.__traceback__)]))
            # Avoid private data from exceptions/tracebacks in the persistent runner log.
            print('HPLUS_LIFECYCLE_REJECT',file=sys.stderr);raise SystemExit(2)
        return
    if not args.label.replace('-','').isalnum() or not 0<=args.wait_seconds<=300:p.error('bounded fresh label/wait')
    exp=r.DEFAULT_EXPLORATION
    if not native_build.DEFAULT.exists():
        wait_guard(lambda:binius_build.guarded_build([sys.executable,'-B','-m',
            'benchmarks.buov_cap_hplus_research_v0_1.native_build','--output',str(native_build.DEFAULT)],exp,
            native_build.DEFAULT.name),args.wait_seconds)
    native_build.audit()
    receipt=wait_guard(lambda:runner.run([sys.executable,'-B','-m',__spec__.name,'--worker',str(exp/args.label)],
        exp,args.label,policy=dict(runner.POLICY,threads=1)),args.wait_seconds)
    print(json.dumps({k:receipt[k] for k in ('exit','stop','wall_seconds','sampled_tree_rss_bytes','no_residual_group')}))


if __name__=='__main__':main()
