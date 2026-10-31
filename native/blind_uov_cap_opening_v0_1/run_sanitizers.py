"""Generate exact inputs/oracle identities, then run independent C sanitizers."""
import json
import os
import struct
import subprocess
import sys
from build import BUILD, ROOT, build
sys.path.insert(0, str(ROOT))
from benchmarks.access_v3.native_cap_opening_v0_1.vectors import real_inputs, oracle, pack_vectors, sha


def main():
    inputs, stage, ctx, _ = real_inputs()
    ref = oracle(inputs, stage, ctx)
    data = dict(salt=inputs['salt'], hidden=struct.pack('<18H', *inputs['hidden_positions']),
                indices=struct.pack('<'+str(len(inputs['frontier_indices']))+'I', *inputs['frontier_indices']),
                seeds=b''.join(inputs['frontier_seeds']), commitments=b''.join(inputs['hidden_commitments']),
                fields=bytes((12, 12)+(11,)*16), corrections=stage['corrections'], alpha=stage['alpha_prime'],
                points=struct.pack('<4Q', *ref['points']))
    for key, value in dict(trans=ref['commitments'], eval=pack_vectors(ref['opened']),
                           coverage=bytes(s is not None for s in ref['leaves'].leaf_seeds_by_unified),
                           corrected=pack_vectors(ref['corrected']), xi=ref['xi']).items():
        data[key+'_sha'] = bytes.fromhex(sha(value))
    BUILD.mkdir(exist_ok=True)
    (BUILD/'oracle_inputs.h').write_text('\n'.join('static const uint8_t '+key+'[] = {'+','.join(map(str, value))+'};' for key,value in data.items()))
    records = []
    for profile in ('ubsan', 'asan'):
        record = build(profile)
        executable = BUILD / (profile+'-smoke')
        flags = [f for f in record['flags'] if f not in ('-shared', '-fPIC')]
        command = ['/usr/bin/gcc', *flags, '-no-pie', '-I'+str(BUILD),
                   str(ROOT/'native/blind_uov_cap_opening_v0_1/sanitizer_smoke.c'),
                   '-L'+str(BUILD), '-Wl,-rpath,'+str(BUILD), '-lopening_'+profile, '-lcrypto', '-o', str(executable)]
        subprocess.run(command, check=True)
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        result = subprocess.run([str(executable)], env=env, capture_output=True, text=True)
        record.update(harness_command=command, exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr,
                      oracle_full_transcript_and_evaluations=True, threads=[1,6,12])
        records.append(record)
        print(profile, result.returncode, result.stderr, flush=True)
    (BUILD/'sanitizers.json').write_text(json.dumps(records, indent=2)+'\n')
    return int(any(r['exit_code'] for r in records))

if __name__ == '__main__':
    sys.exit(main())
