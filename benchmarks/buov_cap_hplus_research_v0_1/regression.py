"""One guarded entry for the isolated H+ migration controls.

Uses the existing resource policy/shared lock and read-only local Rust rlibs.
No downloads, Cargo cache writes, CAP.Init, inversion, tickets, or proofs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time

from benchmarks.buov_cap_research_v0_1 import binius_build as build_guard
from benchmarks.buov_cap_research_v0_1 import runner

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EXPLORATION = Path('/tmp/pqsat-buov-cap-hplus-exploration-v0-1')
RUSTC = Path('/home/ucheng0830/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/bin/rustc')
DEPS = Path('/tmp/pqsat-buov-cap-exploration-v0-1/target128-target/release/deps')
PUBLIC_T = Path('/tmp/pqsat-buov-cap-exploration-v0-1/ncc-demo-20261019T071823-2/trace.T')


def identity(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        while chunk := source.read(1 << 20):
            digest.update(chunk)
    return dict(bytes=path.stat().st_size, sha256=digest.hexdigest())


def require_worker_boundary(output):
    # Direct worker invocation cannot silently run with an unbounded parent.
    for which, expected in ((resource.RLIMIT_AS, 8 << 30), (resource.RLIMIT_FSIZE, 1 << 30),
                            (resource.RLIMIT_CPU, 1802), (resource.RLIMIT_CORE, 0)):
        if resource.getrlimit(which) != (expected, expected):
            raise RuntimeError('worker requires inherited research guard limits')
    if len(os.sched_getaffinity(0)) != 1 or os.getpgrp() != os.getpid():
        raise RuntimeError('worker requires guarded session and one physical core')
    if (not output.is_absolute() or output.resolve() != output
            or output.parent.parent != Path('/tmp')
            or not output.parent.name.startswith('pqsat-buov-cap-hplus-')):
        raise ValueError('worker requires a dedicated H+ exploration output')


def worker(output):
    require_worker_boundary(output)
    if output.exists():
        raise FileExistsError('fresh H+ regression output required')
    output.mkdir(mode=0o700)
    scratch = output/'tmp'
    scratch.mkdir(mode=0o700)
    build_env = dict(os.environ, TMPDIR=str(scratch), TMP=str(scratch), TEMP=str(scratch))
    started = time.monotonic()
    expected = json.loads((ROOT/'manifests/buov_cap_hplus_research_v0_1/local_build_inputs.json').read_text())
    inputs = {}
    for name, pin in expected['rlibs'].items():
        path = DEPS/name
        if identity(path) != pin:
            raise ValueError('read-only local rlib drift: '+name)
        inputs[name] = pin
    if identity(RUSTC) != expected['rustc']:
        raise ValueError('local rustc drift')
    for name, pin in expected['reused_native_sources'].items():
        if identity(ROOT/name) != pin:
            raise ValueError('reused native source drift: '+name)
    source_names = [ROOT/'tests/test_buov_cap_hplus_research_v0_1.py']
    for directory, pattern in [('native/buov_cap_hplus_research_v0_1/src', '*.rs'),
                               ('native/blind_uov_cap_hplus_research_v0_1', '*.[ch]'),
                               ('src/pq_rbbc/blind_uov_hplus_research_v0_1', '*.py'),
                               ('benchmarks/buov_cap_hplus_research_v0_1', '*.py')]:
        source_names.extend(sorted((ROOT/directory).glob(pattern)))
    source_pins = {str(path.relative_to(ROOT)): identity(path) for path in source_names}
    (output/'build-inputs.json').write_text(json.dumps(dict(inputs=inputs,
        reused_native_sources=expected['reused_native_sources'], source_pins=source_pins,
        rustc=expected['rustc'], relation_changed=True, profile_changed=True,
        proof_or_ticket_generated=False), indent=2, sort_keys=True)+'\n')
    # Each output is inside the new storage account; old libraries stay intact.
    cflags = ['-O2', '-std=c17', '-fPIC', '-shared', '-fopenmp', '-Wall', '-Wextra', '-Werror', '-march=x86-64']
    commands = []
    for source, name in [('blind_uov_cap_hplus_research_v0_1', 'hplus'),
                         ('blind_uov_cap_opening_v0_1', 'legacy_control')]:
        argv = ['/usr/bin/gcc', *cflags, str(ROOT/'native'/source/'opening.c'),
                '-lcrypto', '-o', str(output/f'libopening_{name}.so')]
        commands.append(argv); subprocess.run(argv, check=True, env=build_env)
    argv = ['/usr/bin/gcc', *[f for f in cflags if f not in ('-fPIC', '-shared')],
        str(ROOT/'native/blind_uov_cap_hplus_research_v0_1/input_controls.c'),
        '-lcrypto', '-o', str(output/'input_controls')]
    commands.append(argv); subprocess.run(argv, check=True, env=build_env)
    extern = ['anyhow', 'binius_core', 'binius_circuits', 'binius_frontend',
              'binius_utils', 'sha3', 'serde_json']
    argv = [str(RUSTC), '--edition=2024', '--crate-name', 'buov_cap_hplus_research', '--test',
        str(ROOT/'native/buov_cap_hplus_research_v0_1/src/lib.rs'), '-C', 'opt-level=2',
        '-C', 'codegen-units=1', '--cap-lints', 'allow', '-L', 'dependency='+str(DEPS)]
    for name in extern:
        candidates = [key for key in inputs if key.startswith('lib'+name+'-')]
        if len(candidates) != 1:
            raise ValueError('ambiguous direct local rlib: '+name)
        argv += ['--extern', name+'='+str(DEPS/candidates[0])]
    argv += ['-o', str(output/'hplus_tests')]
    commands.append(argv); subprocess.run(argv, check=True, env=build_env)
    census_argv = argv.copy()
    census_argv.remove('--test')
    census_argv[census_argv.index(str(ROOT/'native/buov_cap_hplus_research_v0_1/src/lib.rs'))] = str(ROOT/'native/buov_cap_hplus_research_v0_1/src/census_main.rs')
    for name in ('sha2', 'binius_iop', 'binius_verifier'):
        candidates = [key for key in inputs if key.startswith('lib'+name+'-')]
        if len(candidates) != 1:
            raise ValueError('ambiguous parameter/census local rlib: '+name)
        census_argv += ['--extern', name+'='+str(DEPS/candidates[0])]
    census_argv[census_argv.index(str(output/'hplus_tests'))] = str(output/'hplus_census')
    commands.append(census_argv); subprocess.run(census_argv, check=True, env=build_env)
    record = dict(schema='BUOVCAPHPlusPublicRegressionV1', base_commit='e8f4aa35',
        inputs=inputs, commands=commands, rustc=expected['rustc'],
        reused_native_sources=expected['reused_native_sources'], source_pins=source_pins,
        gcc_version=subprocess.check_output(['/usr/bin/gcc', '--version'], text=True).splitlines()[0],
        security_qualification=False, proof_or_ticket_generated=False)
    # Write identities before testing; failures retain their build provenance.
    record['binaries'] = {name: identity(output/name) for name in
        ('hplus_tests', 'hplus_census', 'input_controls', 'libopening_hplus.so', 'libopening_legacy_control.so')}
    (output/'build.json').write_text(json.dumps(record, indent=2, sort_keys=True)+'\n')
    env = dict(build_env, PYTHONPATH=str(ROOT/'src')+os.pathsep+str(ROOT),
        PYTHONDONTWRITEBYTECODE='1', BUOV_HPLUS_TEST_BUILD=str(output))
    subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', str(ROOT/'tests'),
        '-p', 'test_buov_cap_hplus_research_v0_1.py', '-v'], check=True, env=env)
    subprocess.run([str(output/'hplus_tests'), '--test-threads=1'], check=True, env=env)
    # A bounded immutable capture: no large artifact copied, no witness supplied.
    with PUBLIC_T.open('rb') as source:
        public_tail = source.read(1044993)
    if len(public_tail) != 1044992 or hashlib.sha256(public_tail).hexdigest() != '4ce48825d1e78c704b89a160be8d47932ae9bc7948d282d0c7c12c8ccc63c986':
        raise ValueError('public T identity before count-only lowering')
    counted = subprocess.run([str(output/'hplus_census')], input=public_tail,
        stdout=subprocess.PIPE, check=True, env=env)
    census = json.loads(counted.stdout)
    (output/'census.json').write_text(json.dumps(census, sort_keys=True, indent=2)+'\n')
    record['census'] = census
    record.update(wall_seconds=time.monotonic()-started, result='passed')
    (output/'result.json').write_text(json.dumps(record, indent=2, sort_keys=True)+'\n')
    print('HPLUS_RESULT '+json.dumps(dict(result='passed',wall_seconds=record['wall_seconds'],
        profile='Hplus research', proof_or_ticket_generated=False)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exploration', type=Path, default=DEFAULT_EXPLORATION)
    parser.add_argument('--label', default='regression-v1')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--wait-seconds', type=int, default=0,
                        help='bounded wait for the SAME shared lock, at most 300 seconds')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        if args.output is None:
            parser.error('worker output required')
        worker(args.output)
        return
    if args.output is not None:
        parser.error('--output is worker-only')
    if not args.label.replace('-', '').isalnum():
        parser.error('alphanumeric/hyphen fresh label required')
    if not 0 <= args.wait_seconds <= 300:
        parser.error('bounded lock wait must be 0..300 seconds')
    exploration = args.exploration.resolve()
    if (exploration != args.exploration or exploration.parent != Path('/tmp')
            or not exploration.name.startswith('pqsat-buov-cap-hplus-')):
        parser.error('canonical dedicated /tmp exploration path required')
    exploration.mkdir(mode=0o700, parents=True, exist_ok=True)
    runner.LOCK.parent.mkdir(exist_ok=True)
    platform = runner.platform()
    with (exploration/(args.label+'-platform.json')).open('x') as target:
        target.write(json.dumps(platform, indent=2)+'\n')
    # The existing build guard allows rustc helper threads on ONE physical core;
    # all memory/time/storage limits and the shared heavy-job lock are reused.
    argv = [sys.executable, '-m', 'benchmarks.buov_cap_hplus_research_v0_1.regression', '--worker', '--output', str(exploration/args.label)]
    deadline = time.monotonic()+args.wait_seconds
    attempts = 0
    while True:
        try:
            receipt = build_guard.guarded_build(argv, exploration, args.label)
            break
        except BlockingIOError:
            attempts += 1
            if time.monotonic() >= deadline:
                (exploration/(args.label+'-admission.json')).write_text(json.dumps(dict(
                    result='not_started', reason='shared_heavy_job_lock_busy',
                    attempts=attempts, command=argv), indent=2)+'\n')
                raise
            time.sleep(min(5, max(0, deadline-time.monotonic())))
    print(json.dumps(dict(result='passed', guard=str(exploration/(args.label+'.json')),
        wall_seconds=receipt['wall_seconds'], tree_rss=receipt['sampled_tree_rss_bytes'])))


if __name__ == '__main__':
    main()
