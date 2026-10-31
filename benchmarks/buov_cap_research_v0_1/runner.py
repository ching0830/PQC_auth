"""Single-heavy-job Linux research runner. Sampled thresholds are not RSS bounds.

Trusted local commands only. Limits propagate to descendants; this is a resource
stop mechanism, not a sandbox against hostile programs escaping process groups.
Historical guards and their storage accounts are deliberately not imported.
"""
import ctypes
import fcntl
import json
import os
from pathlib import Path
import resource
import signal
import shutil
import subprocess
import time

GiB = 1 << 30
POLICY = dict(tree_rss=4*GiB, process_as=8*GiB, start_available=16*GiB,
              stop_available=8*GiB, wall_seconds=1800, file_bytes=GiB,
              directory_bytes=10*GiB, output_bytes=16 << 20, threads=1)
LOCK = Path('/tmp/pqsat-iss-parallel-research-dispatch-v0-1/shared-science-v0-1.lock')
THREAD_COUNTS = (1, 2, 4)  # Author-authorized parallel pilot; default remains1.

def physical_cpu_pool():
    """One allowed logical CPU per physical core; never select SMT siblings."""
    selected, seen = [], set()
    for cpu in sorted(os.sched_getaffinity(0)):
        root = Path('/sys/devices/system/cpu')/('cpu'+str(cpu))/'topology'
        key = ((root/'physical_package_id').read_text().strip(),
               (root/'core_id').read_text().strip())
        if key not in seen:
            seen.add(key)
            selected.append(cpu)
    return tuple(selected)

# Preserve the launcher's available pool before this supervisor narrows itself.
CPU_POOL = physical_cpu_pool()

def selected_cpus(threads):
    if (type(threads) is not int or threads not in THREAD_COUNTS or threads > len(CPU_POOL)
            or not CPU_POOL or CPU_POOL[0] != 0):
        raise ValueError('qualified physical-core thread count')
    return CPU_POOL[:threads]

def available():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1])*1024
    raise RuntimeError('MemAvailable unavailable')

def usage(root):
    total, largest = 0, 0
    for base, dirs, files in os.walk(root, followlinks=False):
        if any((Path(base)/name).is_symlink() for name in dirs+files):
            raise RuntimeError('exploration directory symlink')
        for name in files:
            try:
                n = (Path(base)/name).stat().st_size
            except FileNotFoundError:
                continue
            total += n
            largest = max(largest, n)
    return total, largest

def sample(pgid):
    rows = []
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():
            continue
        try:
            s = (p/'stat').read_text().rsplit(')', 1)[1].split()
            if int(s[2]) == pgid:
                rows.append(dict(pid=int(p.name), rss=int(s[21])*os.sysconf('SC_PAGE_SIZE'),
                                 virtual=int(s[20]), ticks=int(s[11])+int(s[12]), threads=int(s[17])))
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    return rows

def stop_reason(rows, mem, elapsed, total, largest, output, policy):
    if sum(r['rss'] for r in rows) > policy['tree_rss']: return 'tree_rss'
    if any(r['virtual'] > policy['process_as'] for r in rows): return 'process_as'
    if any(r.get('threads', 1) > policy['threads'] for r in rows): return 'threads'
    if mem < policy['stop_available']: return 'MemAvailable'
    if elapsed > policy['wall_seconds']: return 'wall_seconds'
    if total > policy['directory_bytes']: return 'directory_bytes'
    if largest > policy['file_bytes']: return 'file_bytes'
    if output > policy['output_bytes']: return 'output_bytes'
    return None

def limits(policy):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for which, n in ((resource.RLIMIT_AS, policy['process_as']),
                     (resource.RLIMIT_FSIZE, policy['file_bytes']),
                     (resource.RLIMIT_CPU, policy['wall_seconds']+2)):
        old = resource.getrlimit(which)[1]
        if old != resource.RLIM_INFINITY and old < n:
            raise RuntimeError('inherited hard limit below exploration policy')
        resource.setrlimit(which, (n, n))
    os.sched_setaffinity(0, set(selected_cpus(policy['threads'])))

def platform():
    cgroup = Path('/proc/self/cgroup').read_text().strip()
    entries = {}
    for row in cgroup.splitlines():
        if row.startswith('0::'):
            p = Path('/sys/fs/cgroup') / row[3:].lstrip('/')
            while p != Path('/sys/fs'):
                for name in ('memory.max', 'memory.high', 'pids.max', 'cpu.max'):
                    f = p/name
                    if f.is_file(): entries[str(f)] = f.read_text().strip()
                p = p.parent
    return dict(MemAvailable=available(), affinity=sorted(os.sched_getaffinity(0)),
                physical_cpu_pool=CPU_POOL, supported_thread_counts=THREAD_COUNTS,
                tmp_free_bytes=shutil.disk_usage('/tmp').free,
                cgroup=cgroup, cgroup_limits=entries,
                inherited_limits={str(k): resource.getrlimit(k) for k in
                                  (resource.RLIMIT_AS, resource.RLIMIT_FSIZE, resource.RLIMIT_CPU)},
                cgroup_settings_modified=False)

def validate_policy(p):
    if set(p) != set(POLICY): raise ValueError('exact policy fields')
    for k,v in p.items():
        if type(v) is not int or v <= 0: raise ValueError('positive integer policy')
        # Available-memory thresholds are minima: decreasing them loosens policy.
        if k in ('start_available','stop_available'):
            if v < POLICY[k]: raise ValueError('memory minimum cannot decrease')
        elif k == 'threads':
            if v not in THREAD_COUNTS: raise ValueError('bounded thread count')
        elif v > POLICY[k]: raise ValueError('resource maximum cannot increase')
    if p['start_available'] < p['stop_available']: raise ValueError('admission below runtime minimum')

def admit(mem, total, largest, policy):
    if mem < policy['start_available']: raise RuntimeError('admission MemAvailable')
    if total >= policy['directory_bytes'] or largest > policy['file_bytes']:
        raise RuntimeError('admission storage')

def run(argv, root, label, *, policy=None, expected=0):
    p = dict(POLICY if policy is None else policy)
    validate_policy(p)
    root = Path(root).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not label.replace('-', '').replace('_', '').isalnum(): raise ValueError('label')
    log, receipt = root/(label+'.log'), root/(label+'.json')
    if log.exists() or receipt.exists(): raise FileExistsError('fresh phase required')
    LOCK.parent.mkdir(exist_ok=True)
    with LOCK.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        mem = available()
        total, largest = usage(root)
        admit(mem,total,largest,p)
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0): raise OSError('subreaper unavailable')
        # Parent and child both inherit the complete new limits. A qualification
        # subprocess with tighter limits does not lower this supervisor's limits.
        limits(dict(POLICY, threads=p['threads']))
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', OMP_NUM_THREADS=str(p['threads']),
                   NIR_THREADS=str(p['threads']), OMP_THREAD_LIMIT=str(p['threads']),
                   OMP_DYNAMIC='FALSE', OMP_MAX_ACTIVE_LEVELS='1',
                   OMP_PROC_BIND='FALSE',
                   BUOV_CAP_CPUS=','.join(map(str, selected_cpus(p['threads']))),
                   OPENBLAS_NUM_THREADS='1', MKL_NUM_THREADS='1', NUMEXPR_NUM_THREADS='1',
                   VECLIB_MAXIMUM_THREADS='1')
        env.pop('GOMP_CPU_AFFINITY', None)
        env.pop('OMP_PLACES', None)
        started = time.monotonic()
        peak_tree = peak_process = peak_as = peak_threads = 0
        minimum_mem = mem
        reason = None
        child = None
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        with log.open('xb', buffering=0) as out:
            try:
                child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out,
                    stderr=subprocess.STDOUT, start_new_session=True, env=env,
                    close_fds=True, preexec_fn=lambda: limits(p))
                while True:
                    rows = sample(child.pid)
                    peak_tree = max(peak_tree, sum(r['rss'] for r in rows))
                    peak_process = max([peak_process]+[r['rss'] for r in rows])
                    peak_as = max([peak_as]+[r['virtual'] for r in rows])
                    peak_threads = max([peak_threads]+[r['threads'] for r in rows])
                    minimum_mem = min(minimum_mem, available())
                    total, largest = usage(root)
                    reason = stop_reason(rows, minimum_mem, time.monotonic()-started,
                                         total, largest, log.stat().st_size, p)
                    if reason or child.poll() is not None: break
                    time.sleep(.1)
            finally:
                if child is not None:
                    # Kill the group even if its direct leader exited first.
                    try: os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    child.wait()
                    while True:
                        try: os.waitpid(-child.pid, 0)
                        except ChildProcessError: break
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        residual = sample(child.pid)
        result = dict(schema='BUOVCAPExplorationRunV1', argv=argv, policy=p,
            wall_seconds=time.monotonic()-started, exit=child.returncode, stop=reason,
            sampled_tree_rss_bytes=peak_tree, sampled_process_rss_bytes=peak_process,
            sampled_process_as_bytes=peak_as, MemAvailable_start=mem, MemAvailable_min=minimum_mem,
            sampled_process_threads=peak_threads, cpu_affinity=selected_cpus(p['threads']),
            supervisor_rusage_hwm_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
            children_rusage_hwm_bytes=after.ru_maxrss*1024,
            children_rusage_hwm_scope='cumulative supervisor children; not phase-specific',
            children_cpu_seconds=(after.ru_utime+after.ru_stime)-(before.ru_utime+before.ru_stime),
            no_residual_group=not residual, log=str(log), sampled_rss_is_hard_bound=False,
            directory_bytes=usage(root)[0])
        receipt.write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
        if reason or child.returncode != expected or residual:
            raise RuntimeError('phase failed: '+label+'; '+str(reason)+'; see '+str(receipt))
        return result
