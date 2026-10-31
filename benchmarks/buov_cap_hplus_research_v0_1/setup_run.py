"""Build/validate the new full PUBLIC H+ setup and its own bounded CS cache.

No private values, CAP.Init, inversion, Prove or proof Verify. Uses the same
shared lock/resource guards and dedicated exploration account as regression.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from . import regression as r
from benchmarks.buov_cap_research_v0_1 import runner, binius_build

ROOT = r.ROOT


def captured_tail():
    import hashlib
    with r.PUBLIC_T.open('rb') as source:
        tail = source.read(1044993)
    if len(tail) != 1044992 or hashlib.sha256(tail).hexdigest() != '4ce48825d1e78c704b89a160be8d47932ae9bc7948d282d0c7c12c8ccc63c986':
        raise ValueError('captured trusted public T identity')
    return tail


def build_worker(output):
    r.require_worker_boundary(output)
    output.mkdir(mode=0o700)
    (output/'tmp').mkdir(mode=0o700)
    env = dict(os.environ, TMPDIR=str(output/'tmp'), TEMP=str(output/'tmp'), TMP=str(output/'tmp'))
    pins = json.loads((ROOT/'manifests/buov_cap_hplus_research_v0_1/local_build_inputs.json').read_text())
    if r.identity(r.RUSTC) != pins['rustc']:
        raise ValueError('pinned local rustc')
    for name, pin in pins['rlibs'].items():
        if r.identity(r.DEPS/name) != pin:
            raise ValueError('read-only local rlib drift: '+name)
    for name, pin in pins['reused_native_sources'].items():
        if r.identity(ROOT/name) != pin:
            raise ValueError('reused native source drift: '+name)
    source = ROOT/'native/buov_cap_hplus_research_v0_1/src/setup_main.rs'
    argv = [str(r.RUSTC), '--edition=2024', '--crate-name', 'buov_cap_hplus_setup', str(source),
            '-C', 'opt-level=3', '-C', 'codegen-units=1', '--cap-lints', 'allow',
            '-L', 'dependency='+str(r.DEPS)]
    for name in ('anyhow', 'binius_core', 'binius_circuits', 'binius_frontend', 'binius_utils',
                 'sha3', 'serde_json', 'bytes', 'binius_verifier', 'binius_iop', 'binius_hash',
                 'binius_transcript'):
        matches = [key for key in pins['rlibs'] if key.startswith('lib'+name+'-')]
        if len(matches) != 1:
            raise ValueError('ambiguous setup direct dependency: '+name)
        argv += ['--extern', name+'='+str(r.DEPS/matches[0])]
    names = sorted((ROOT/'native/buov_cap_hplus_research_v0_1/src').glob('*.rs'))
    names += [Path(__file__).resolve(), Path(r.__file__).resolve()]
    record = dict(schema='BUOVCAPHPlusSetupBuildV1', parent_commit='97d72914',
        source_pins={str(p.relative_to(ROOT)): r.identity(p) for p in names},
        local_build_inputs=r.identity(ROOT/'manifests/buov_cap_hplus_research_v0_1/local_build_inputs.json'),
        commands=[], no_witness_or_proof=True)
    (output/'build-inputs.json').write_text(json.dumps(record, indent=2, sort_keys=True)+'\n')
    for extra, name in (([], 'hplus_setup'), (['--test'], 'hplus_setup_tests')):
        command = argv+extra+['-o', str(output/name)]
        record['commands'].append(command)
        subprocess.run(command, check=True, env=env)
    subprocess.run([str(output/'hplus_setup_tests'), '--test-threads=1'], check=True, env=env)
    record['binary'] = r.identity(output/'hplus_setup')
    record['test_binary'] = r.identity(output/'hplus_setup_tests')
    (output/'build.json').write_text(json.dumps(record, indent=2, sort_keys=True)+'\n')


def run_worker(output, build, mode, cache=None, cache_sha=None, cs_sha=None):
    r.require_worker_boundary(output)
    output.mkdir(mode=0o700)
    (output/'tmp').mkdir(mode=0o700)
    receipt = json.loads((build/'build.json').read_text())
    for name, pin in receipt['source_pins'].items():
        if r.identity(ROOT/name) != pin:
            raise ValueError('setup source drift after build: '+name)
    binary = build/'hplus_setup'
    if r.identity(binary) != receipt['binary']:
        raise ValueError('setup binary drift')
    env = dict(os.environ, TMPDIR=str(output/'tmp'), RAYON_NUM_THREADS='1')
    if mode == 'build':
        cache = output/'public.hplus-cs-cache'
        command = [str(binary), 'build', str(cache)]
    else:
        command = [str(binary), 'load', str(cache), cache_sha, cs_sha]
    start = time.monotonic()
    result = subprocess.run(command, input=captured_tail(), stdout=subprocess.PIPE, check=True, env=env)
    if len(result.stdout) > 64 << 10 or not result.stdout.startswith(b'HPLUS_SETUP '):
        raise ValueError('bounded native setup result grammar')
    actual = json.loads(result.stdout[len(b'HPLUS_SETUP '):])
    actual['worker_whole_seconds'] = time.monotonic()-start
    if actual['Prove'] or actual['Verify'] or actual['private_values_received'] or actual['private_ValueVec_allocated']:
        raise ValueError('public-only setup invariant')
    (output/'result.json').write_text(json.dumps(actual, indent=2, sort_keys=True)+'\n')
    print('HPLUS_PUBLIC_SETUP '+json.dumps(actual, sort_keys=True))


def wait_guard(call, seconds):
    deadline = time.monotonic()+seconds
    while True:
        try:
            return call()
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(min(1, max(0, deadline-time.monotonic())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', default='actual-setup-v1')
    parser.add_argument('--exploration', type=Path, default=r.DEFAULT_EXPLORATION)
    parser.add_argument('--wait-seconds', type=int, default=120)
    parser.add_argument('--worker', choices=('build', 'setup', 'load'), help=argparse.SUPPRESS)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--build', type=Path)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--cache-sha')
    parser.add_argument('--cs-sha')
    args = parser.parse_args()
    if args.worker:
        if args.worker == 'build':
            build_worker(args.output)
        else:
            run_worker(args.output, args.build, 'build' if args.worker == 'setup' else 'load',
                args.cache, args.cache_sha, args.cs_sha)
        return
    if any(v is not None for v in (args.output,args.build,args.cache,args.cache_sha,args.cs_sha)):
        parser.error('worker-only arguments')
    if not args.label.replace('-', '').isalnum() or not 0 <= args.wait_seconds <= 300:
        parser.error('fresh bounded label/wait')
    root = args.exploration.resolve()
    if root != args.exploration or root.parent != Path('/tmp') or not root.name.startswith('pqsat-buov-cap-hplus-'):
        parser.error('dedicated canonical H+ exploration root')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    runner.LOCK.parent.mkdir(exist_ok=True)
    with (root/(args.label+'-platform.json')).open('x') as f:
        json.dump(runner.platform(), f, indent=2)
    # Explicit pre-execution estimate, not a proof of RSS. The real guard remains decisive.
    plan = dict(schema='BUOVCAPHPlusPublicSetupAdmissionV1', logical_cs_bytes=872897760,
        conservative_estimate_bytes=2*872897760+(512<<20), estimated_below_rss_stop=True,
        estimated_RSS_is_hard_bound=False, creates_private_values=False, Prove=0, Verify=0,
        cache_file_bytes_expected=688968080, single_file_cap=1<<30, policy=runner.POLICY)
    with (root/(args.label+'-plan.json')).open('x') as f:
        json.dump(plan, f, indent=2)
    prefix = [sys.executable, '-m', 'benchmarks.buov_cap_hplus_research_v0_1.setup_run']
    build = root/(args.label+'-build')
    wait_guard(lambda: binius_build.guarded_build(prefix+['--worker','build','--output',str(build)],
        root, args.label+'-build'), args.wait_seconds)
    output = root/args.label
    wait_guard(lambda: runner.run(prefix+['--worker','setup','--output',str(output),'--build',str(build)],
        root, args.label), args.wait_seconds)
    original = json.loads((output/'result.json').read_text())
    cache = output/'public.hplus-cs-cache'
    loaded = root/(args.label+'-reload')
    wait_guard(lambda: runner.run(prefix+['--worker','load','--output',str(loaded),'--build',str(build),
        '--cache',str(cache),'--cache-sha',original['cache']['cache_sha256'],
        '--cs-sha',original['public_CS_identity']['sha256']], root,args.label+'-reload'), args.wait_seconds)
    reloaded = json.loads((loaded/'result.json').read_text())
    for field in ('compiler_id','setup_id','actual_symbolic_setup','public_CS_identity'):
        if original[field] != reloaded[field]:
            raise ValueError('cold/reloaded setup mismatch: '+field)
    summary = dict(result='passed', cold=original, reload=reloaded, public_cache=r.identity(cache),
        source_build=r.identity(build/'build.json'), new_profile=True, full_lifecycle_complete=False)
    with (root/(args.label+'-summary.json')).open('x') as f:
        json.dump(summary, f, indent=2, sort_keys=True)
    print(json.dumps(dict(result='passed',compiler_id=original['compiler_id'],setup_id=original['setup_id'],
        summary=str(root/(args.label+'-summary.json')))))


if __name__ == '__main__':
    main()
