"""Explicit portable C17 build into a caller-supplied absolute /tmp directory."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
FLAGS = ['-O3','-std=c17','-fPIC','-shared','-fopenmp','-march=x86-64','-Wall','-Wextra','-Werror']

def build(destination: Path, profile='portable'):
    if type(destination) is not type(Path()) or not destination.is_absolute() or not destination.resolve().is_relative_to('/tmp'):
        raise ValueError('build destination must be an explicit absolute /tmp path')
    if profile not in ('portable','ubsan','asan','allocation-failure'):
        raise ValueError('unknown build profile')
    destination.mkdir(parents=True,exist_ok=True)
    flags=FLAGS.copy()
    if profile in ('asan','ubsan'):
        flags+=['-g','-fno-omit-frame-pointer','-fno-sanitize-recover=all',
                '-fsanitize='+('address,undefined' if profile=='asan' else 'undefined')]
    elif profile=='allocation-failure':
        flags+=['-DPQSAT_PROVER_TEST_ALLOC_FAIL=1']
    library=destination/('libpqsat_prover_'+profile+'.so')
    dep=ROOT/'native/blind_uov_cap_v0_1'
    sources=[dep/'relation.c',HERE/'prover.c']
    command=['/usr/bin/gcc',*flags,'-I',str(dep),*(str(p) for p in sources),'-o',str(library)]
    subprocess.run(command,check=True,cwd=destination)
    raw=library.read_bytes()
    record={'profile':profile,'command':command,'flags':flags,'library_path':str(library),
            'library_bytes':len(raw),'library_sha256':hashlib.sha256(raw).hexdigest(),
            'compiler':subprocess.check_output(['/usr/bin/gcc','--version'],text=True).strip(),
            'dependencies':subprocess.check_output(['ldd',str(library)],text=True).strip(),
            'sources':{str(p.relative_to(ROOT)):{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in [*sources,HERE/'prover.h',dep/'relation.h']}}
    (destination/('build_'+profile+'.json')).write_text(json.dumps(record,indent=2)+'\n')
    return record

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output-dir',type=Path,required=True)
    p.add_argument('--profile',choices=('portable','ubsan','asan','allocation-failure'),default='portable')
    a=p.parse_args()
    print(json.dumps(build(a.output_dir,a.profile),indent=2))
