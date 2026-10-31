"""Explicit path relocation only. Frozen proof/profile/admission checks stay active."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH_OVERRIDES = (
    'regression.DEFAULT_EXPLORATION', 'regression.RUSTC', 'regression.DEPS', 'regression.PUBLIC_T',
    'public_setup.EXPLORATION', 'public_setup.DEFAULT_BUILD', 'public_setup.DEFAULT_CACHE',
    'native_build.DEFAULT',
)


def _unique(pairs):
    values = {}
    for key, value in pairs:
        if key in values:
            raise ValueError('duplicate configuration key')
        values[key] = value
    return values


def configuration(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
        raise ValueError('bounded regular configuration required')
    data = json.loads(path.read_text(), object_pairs_hook=_unique)
    if (type(data) is not dict or set(data) != {'schema', 'artifacts', 'run_root'}
            or data['schema'] != 'PQSAT.ThesisCode.Runtime.v0.1'):
        raise ValueError('exact versioned publication configuration required')
    result = {}
    for key in ('artifacts', 'run_root'):
        if type(data[key]) is not str:
            raise ValueError('absolute canonical path required')
        value = Path(data[key])
        if not value.is_absolute() or value != value.resolve() or '..' in value.parts:
            raise ValueError('absolute canonical non-symlink path required')
        result[key] = value
    run = result['run_root']
    if run.parent != Path('/tmp') or not run.name.startswith('pqsat-buov-cap-hplus-'):
        raise ValueError('dedicated /tmp/pqsat-buov-cap-hplus-* resource account required')
    if result['artifacts'] == run or result['artifacts'].is_relative_to(ROOT):
        raise ValueError('external inputs and writable account must be separate from source')
    return result


def verify_artifacts(directory):
    catalog = json.loads((ROOT/'provenance/external_artifacts.json').read_text())
    errors = []
    verified = 0
    for name, expected in catalog['artifacts'].items():
        path = directory/name
        try:
            if path.resolve() != path or not path.is_file() or path.stat().st_size != expected['bytes']:
                raise ValueError('missing/nonregular/symlink/size')
            with path.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            if digest != expected['sha256']:
                raise ValueError('SHA-256')
            if name in catalog['readonly'] and path.stat().st_mode & 0o222:
                raise ValueError('read-only input required')
            verified += 1
        except (OSError, ValueError) as error:
            errors.append({'artifact': name, 'reason': str(error) if isinstance(error, ValueError) else type(error).__name__})
    return dict(schema='PQSAT.ThesisCode.ArtifactCheck.v0.1', ready=not errors,
                verified=verified, required=len(catalog['artifacts']), errors=errors,
                cryptographicQualification=False)


def activate(path):
    """Applied in each role interpreter; changes only allowlisted Path values/defaults."""
    cfg = configuration(path)
    artifacts, run = cfg['artifacts'], cfg['run_root']
    from benchmarks.buov_cap_hplus_research_v0_1 import regression
    from pq_sat_auth.prototypes.buov_cap_hplus_research_v0_1 import public_setup
    regression.DEFAULT_EXPLORATION = run
    regression.RUSTC = artifacts/'toolchain/bin/rustc'
    regression.DEPS = artifacts/'deps'
    regression.PUBLIC_T = artifacts/'trace.T'
    public_setup.EXPLORATION = run
    public_setup.DEFAULT_BUILD = artifacts/'setup-build'
    public_setup.DEFAULT_CACHE = artifacts/'setup-cache/public.hplus-cs-cache'
    # These functions capture Path objects at definition time. Relocate the
    # captured path as well; their validation bodies are unchanged.
    public_setup.audit_native_build.__defaults__ = (public_setup.DEFAULT_BUILD,)
    public_setup.audit_public_cache.__defaults__ = (public_setup.DEFAULT_CACHE,)
    from benchmarks.buov_cap_hplus_research_v0_1 import native_build
    native_build.DEFAULT = run/'lifecycle-v4-build'
    native_build.audit.__defaults__ = (native_build.DEFAULT,)
    from benchmarks.buov_cap_research_v0_1 import runner
    runner.LOCK.parent.mkdir(mode=0o700, exist_ok=True)
    run.mkdir(mode=0o700, exist_ok=True)
    return cfg
