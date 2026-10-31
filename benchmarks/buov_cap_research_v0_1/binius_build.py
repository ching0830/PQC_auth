"""Original bounded compiler guard and public file identity helper.

Unused historical Cargo staging entrypoints are excluded from this snapshot.
"""
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import time

def guarded_build(argv, root, label):
    """Public compiler tools: one physical core, at most eight helper threads.

    rustc uses five OS threads even with one frontend/backend/codegen job.
    This separate build-only profile preserves the original runner and its
    proof-thread gate. All memory/time/storage/output limits are reused.
    No witness/proving command is accepted by this entry point.
    """
    from . import runner as g
    import ctypes
    base = dict(g.POLICY)
    g.validate_policy(base)
    policy = dict(base, threads=8)
    child_output = Path(argv[argv.index('--output')+1])
    root = root.resolve()
    receipt, log = root/(label+'.json'), root/(label+'.log')
    if receipt.exists() or log.exists() or not label.replace('-', '').isalnum():
        raise ValueError('fresh build label')
    with g.LOCK.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        total, largest = g.usage(root)
        mem = g.available()
        g.admit(mem, total, largest, base)
        if ctypes.CDLL(None).prctl(36, 1, 0, 0, 0):
            raise RuntimeError('subreaper unavailable')
        g.limits(base)  # Parent and child inherit finite limits, CPU affinity {0}.
        started = time.monotonic()
        peak_tree = peak_process = peak_as = peak_threads = 0
        minimum = mem
        stop = None
        child = None
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        with log.open('xb', buffering=0) as output:
            try:
                child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output,
                    stderr=subprocess.STDOUT, start_new_session=True, close_fds=True,
                    preexec_fn=lambda: g.limits(base))
                while True:
                    rows = g.sample(child.pid)
                    peak_tree = max(peak_tree, sum(r['rss'] for r in rows))
                    peak_process = max([peak_process]+[r['rss'] for r in rows])
                    peak_as = max([peak_as]+[r['virtual'] for r in rows])
                    peak_threads = max([peak_threads]+[r['threads'] for r in rows])
                    minimum = min(minimum, g.available())
                    total, largest = g.usage(root)
                    output_bytes = log.stat().st_size + sum(p.stat().st_size for p in child_output.glob('*.log'))
                    stop = g.stop_reason(rows, minimum, time.monotonic()-started,
                        total, largest, output_bytes, policy)
                    if stop or child.poll() is not None:
                        break
                    time.sleep(.1)
            finally:
                if child is not None:
                    try: os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    child.wait()
                    while True:
                        try: os.waitpid(-child.pid, 0)
                        except ChildProcessError: break
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        record = dict(schema='BUOVCAPBiniusPublicBuildGuardV1', argv=argv, policy=policy,
            cpu_affinity=sorted(os.sched_getaffinity(0)), cargo_jobs=1,
            helper_threads_are_not_compute_cores=True, proof_profile_unchanged=True,
            wall_seconds=time.monotonic()-started, exit=child.returncode, stop=stop,
            sampled_tree_rss_bytes=peak_tree, sampled_process_rss_bytes=peak_process,
            sampled_process_as_bytes=peak_as, sampled_process_threads=peak_threads,
            MemAvailable_start=mem, MemAvailable_min=minimum,
            children_cpu_seconds=(after.ru_utime+after.ru_stime)-(before.ru_utime+before.ru_stime),
            sampled_rss_is_hard_bound=False, no_residual_group=not g.sample(child.pid),
            directory_bytes=g.usage(root)[0])
        receipt.write_text(json.dumps(record, sort_keys=True, indent=2)+'\n')
        if stop or child.returncode or not record['no_residual_group']:
            raise RuntimeError('bounded public build failed; retained receipt '+str(receipt))
        return record

def identity(path):
    path = Path(path)
    digest = hashlib.sha256()
    with path.open('rb') as source:
        while chunk := source.read(1 << 20):
            digest.update(chunk)
    return dict(bytes=path.stat().st_size, sha256=digest.hexdigest())
