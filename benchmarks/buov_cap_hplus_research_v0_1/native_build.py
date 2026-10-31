"""Explicit guarded H+ proof/CAP build; no implicit compilation in consumers."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from . import regression as r
from pq_sat_auth.prototypes.buov_cap_hplus_research_v0_1 import public_setup

ROOT=r.ROOT
DEFAULT=r.DEFAULT_EXPLORATION/'lifecycle-v4-build'
PROVER_RLIB='libbinius_prover-eb76834c59421b92.rlib'


def sources():
    paths=list((ROOT/'native/buov_cap_hplus_research_v0_1/src').glob('*.rs'))
    paths+=list((ROOT/'native/blind_uov_cap_hplus_research_v0_1').glob('*.[ch]'))
    paths+=list((ROOT/'src/pq_rbbc/blind_uov_hplus_native_prover_v0_1').glob('*.py'))
    paths += [ROOT/n for n in ('src/pq_rbbc/blind_uov_native_prover_v0_1/prover.c',
        'src/pq_rbbc/blind_uov_native_prover_v0_1/prover.h',
        'native/blind_uov_cap_v0_1/relation.c','native/blind_uov_cap_v0_1/relation.h')]
    paths+=[Path(__file__).resolve(), ROOT/'manifests/buov_cap_hplus_research_v0_1/actual_setup.json']
    return {str(p.relative_to(ROOT)):r.identity(p) for p in paths}


def build(output):
    r.require_worker_boundary(output);public_setup.audit_sources()
    output.mkdir(mode=0o700);(output/'tmp').mkdir(mode=0o700)
    env=dict(os.environ,TMPDIR=str(output/'tmp'),TMP=str(output/'tmp'),TEMP=str(output/'tmp'))
    pins=json.loads((ROOT/'manifests/buov_cap_hplus_research_v0_1/local_build_inputs.json').read_text())
    if r.identity(r.RUSTC)!=pins['rustc']:raise ValueError('rustc pin')
    for n,p in pins['rlibs'].items():
        if r.identity(r.DEPS/n)!=p:raise ValueError('rlib drift: '+n)
    record=dict(schema='BUOVCAPHPlusLifecycleNativeBuildV1',source_pins=sources(),rlibs=pins['rlibs'],
        rustc=pins['rustc'],selected_prover_rlib=PROVER_RLIB,commands=[],binaries={})
    (output/'build-inputs.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    argv=[str(r.RUSTC),'--edition=2024','--crate-name','buov_cap_hplus_proof',
        str(ROOT/'native/buov_cap_hplus_research_v0_1/src/proof_main.rs'),'-C','opt-level=3',
        '-C','codegen-units=1','--cap-lints','allow','-L','dependency='+str(r.DEPS)]
    for n in ('anyhow','binius_core','binius_circuits','binius_frontend','binius_utils','sha3','serde_json',
            'bytes','binius_verifier','binius_iop','binius_hash','binius_transcript','binius_prover','rand'):
        matches=[k for k in pins['rlibs'] if k.startswith('lib'+n+'-')]
        chosen=PROVER_RLIB if n=='binius_prover' else matches[0] if len(matches)==1 else None
        if chosen not in matches:raise ValueError('explicit dependency selection: '+n)
        argv+=['--extern',n+'='+str(r.DEPS/chosen)]
    for extra,name in (([],'hplus_proof'),(['--test'],'hplus_proof_tests')):
        cmd=argv+extra+['-o',str(output/name)];record['commands'].append(cmd)
        subprocess.run(cmd,check=True,env=env)
    subprocess.run([str(output/'hplus_proof_tests'),'--test-threads=1'],check=True,env=env)
    cflags=['-O3','-std=c17','-fPIC','-shared','-fopenmp','-march=x86-64','-Wall','-Wextra','-Werror']
    dep=ROOT/'native/blind_uov_cap_v0_1'
    for name,files,extra in (
        ('librelation_hplus.so',[dep/'relation.c'],[]),
        ('libprover_hplus.so',[dep/'relation.c',ROOT/'native/blind_uov_cap_hplus_research_v0_1/prover.c'],['-I',str(dep)]),
        ('libopening_hplus.so',[ROOT/'native/blind_uov_cap_hplus_research_v0_1/opening.c'],['-lcrypto'])):
        cmd=['/usr/bin/gcc',*cflags,*map(str,files),*extra,'-o',str(output/name)]
        record['commands'].append(cmd);subprocess.run(cmd,check=True,env=env)
    for n in ('hplus_proof','hplus_proof_tests','librelation_hplus.so','libprover_hplus.so','libopening_hplus.so'):
        record['binaries'][n]=r.identity(output/n)
    if sources()!=record['source_pins']:raise ValueError('build source drift')
    (output/'build.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')


def audit(directory=DEFAULT):
    public_setup.audit_sources()
    record=json.loads((directory/'build.json').read_text())
    if record['schema']!='BUOVCAPHPlusLifecycleNativeBuildV1' or sources()!=record['source_pins']:
        raise ValueError('new lifecycle build/source drift')
    for n,p in record['binaries'].items():
        if r.identity(directory/n)!=p:raise ValueError('lifecycle binary drift')
    return record


def provision(exploration=None):
    record=audit()
    return dict(directory=DEFAULT,record=record)


def prover_kwargs(libraries):
    d=libraries['directory'];p=libraries['record']['binaries']['libprover_hplus.so']
    return dict(library_path=d/'libprover_hplus.so',expected_sha256=p['sha256'])


def verifier_kwargs(libraries):
    d=libraries['directory'];b=libraries['record']['binaries']
    return dict(relation_library_path=d/'librelation_hplus.so',relation_library_sha256=b['librelation_hplus.so']['sha256'],
        opening_library_path=d/'libopening_hplus.so',opening_library_sha256=b['libopening_hplus.so']['sha256'])


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True)
    build(p.parse_args().output)
