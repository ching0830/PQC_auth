"""NCC-owned public setup pins. Metadata checking is NOT proof verification.

Expected cache/CS/setup identities come only from the tracked actual checkpoint,
never UE records, a received descriptor, an environment variable or a success flag.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from pq_rbbc.blind_uov_hplus_research_v0_1.parameters import PROFILE_FINGERPRINT

ROOT = Path(__file__).resolve().parents[4]
CHECKPOINT = ROOT/'manifests/buov_cap_hplus_research_v0_1/actual_setup.json'
LOCAL_INPUTS = ROOT/'manifests/buov_cap_hplus_research_v0_1/local_build_inputs.json'
EXPLORATION = Path('/tmp/pqsat-buov-cap-hplus-exploration-v0-1')
DEFAULT_BUILD = EXPLORATION/'actual-setup-v1-build'
DEFAULT_CACHE = EXPLORATION/'actual-setup-v1/public.hplus-cs-cache'
CAP = 1 << 30


def _no_duplicates(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('duplicate setup metadata key')
        result[name] = value
    return result


def _json(path, cap=1 << 20):
    with path.open('rb') as source:
        raw = source.read(cap+1)
    if not 0 < len(raw) <= cap:
        raise ValueError('bounded public metadata')
    return json.loads(raw, object_pairs_hook=_no_duplicates,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite metadata')))


def identity(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        while chunk := source.read(1 << 20):
            digest.update(chunk)
    return dict(bytes=path.stat().st_size, sha256=digest.hexdigest())


def checkpoint():
    data = _json(CHECKPOINT)
    if (data['schema'] != 'BUOVCAPHPlusActualSetupCheckpointV1'
            or data['profile']['profile_fingerprint'] != PROFILE_FINGERPRINT.hex()
            or data['boundary']['Prove'] != 0 or data['boundary']['proof_Verify'] != 0):
        raise ValueError('trusted H+ actual public setup checkpoint')
    return data


@dataclass(frozen=True, slots=True)
class PublicSetupPins:
    compiler_id: bytes
    setup_id: bytes
    trace_digest: bytes

    def __post_init__(self):
        data = checkpoint()
        for name, expected in (('compiler_id',data['compiler_id']), ('setup_id',data['setup_id']),
                               ('trace_digest',data['measurements']['cold']['trace_sha256'])):
            value = getattr(self,name)
            if type(value) is not bytes or len(value) != 32 or value.hex() != expected:
                raise ValueError('own pinned H+ public '+name)


def public_setup_pins():
    data = checkpoint()
    return PublicSetupPins(bytes.fromhex(data['compiler_id']),bytes.fromhex(data['setup_id']),
        bytes.fromhex(data['measurements']['cold']['trace_sha256']))


def _exact(left, right):
    if type(left) is not type(right):
        return False
    if type(right) is dict:
        return left.keys() == right.keys() and all(_exact(left[k],v) for k,v in right.items())
    if type(right) is list:
        return len(left) == len(right) and all(_exact(a,b) for a,b in zip(left,right))
    return left == right


def validate_public_setup_result(result):
    """Check actual setup metadata against NCC's pins; never accept a proof."""
    data = checkpoint()
    if type(result) is not dict:
        raise ValueError('exact public setup record')
    for key in ('compiler_id','setup_id','actual_symbolic_setup','public_CS_identity','counts'):
        if not _exact(result.get(key),data[key]):
            raise ValueError('foreign/mutated H+ setup '+key)
    cache = result.get('cache')
    if type(cache) is not dict or any(not _exact(cache.get(key),value) for key,value in (
            ('cache_bytes',data['public_cache']['bytes']),('cache_sha256',data['public_cache']['sha256']),
            ('source_sha256',data['cache_source_sha256']))):
        raise ValueError('public setup cache identity')
    if (result.get('schema') != 'BUOVCAPHPlusActualSetupV1' or result.get('mode') not in ('build','load')
            or result.get('trace_sha256') != data['measurements']['cold']['trace_sha256']
            or result.get('profile_fingerprint') != data['profile']['profile_fingerprint']
            or result.get('relation_id') != data['profile']['relation_id']
            or result.get('private_values_received') is not False
            or result.get('private_ValueVec_allocated') is not False
            or type(result.get('Prove')) is not int or result['Prove'] != 0
            or type(result.get('Verify')) is not int or result['Verify'] != 0
            or result.get('satisfiability_checked') is not False
            or result.get('proof_body_bytes') is not None):
        raise ValueError('public setup phase boundary')


def validate_cache_header(raw):
    expected = bytes.fromhex(checkpoint()['cache_header_hex'])
    if type(raw) is not bytes or len(raw) != 160 or raw != expected:
        raise ValueError('foreign/mixed public H+ cache header')


def audit_sources():
    """Include shared native sources and their manifest, not just new files."""
    data = checkpoint()
    if identity(LOCAL_INPUTS) != data['local_build_inputs']:
        raise ValueError('local build input manifest drift')
    for inventory in (data['source_pins'],_json(LOCAL_INPUTS)['reused_native_sources']):
        for name, pin in inventory.items():
            if identity(ROOT/name) != pin:
                raise ValueError('public setup source drift: '+name)


def audit_native_build(build=DEFAULT_BUILD):
    data = checkpoint()
    if identity(build/'build.json') != data['native_build']:
        raise ValueError('exact H+ build receipt required')
    if identity(build/'hplus_setup') != data['native_binary']:
        raise ValueError('pinned H+ setup binary required')
    audit_sources()


def audit_public_cache(cache=DEFAULT_CACHE):
    """Bound shape/header before streaming checksum; no native decode here."""
    data = checkpoint()
    if cache.is_symlink() or not cache.is_file():
        raise ValueError('regular read-only public cache required')
    stat = cache.stat()
    if stat.st_mode & 0o222 or stat.st_size != data['public_cache']['bytes'] or stat.st_size > CAP:
        raise ValueError('public cache bounds/read-only gate')
    with cache.open('rb') as source:
        validate_cache_header(source.read(160))
    if identity(cache) != data['public_cache']:
        raise ValueError('public cache exact identity')
