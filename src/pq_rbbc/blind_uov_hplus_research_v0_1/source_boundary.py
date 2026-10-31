"""Verify reused source bytes BEFORE importing/executing the legacy package."""
import hashlib
import json
from pathlib import Path
from ._pins import MANIFEST_BYTES, MANIFEST_SHA256

ROOT = Path(__file__).resolve().parents[3]


def check_reused_sources():
    path = ROOT/'manifests/buov_cap_hplus_research_v0_1/profile.json'
    with path.open('rb') as source:
        raw = source.read(MANIFEST_BYTES+1)
    if len(raw) != MANIFEST_BYTES or hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ImportError('H+ profile manifest identity mismatch before legacy import')
    for name, pin in json.loads(raw)['reused_python_sources'].items():
        with (ROOT/name).open('rb') as source:
            shared = source.read(pin['bytes']+1)
        if len(shared) != pin['bytes'] or hashlib.sha256(shared).hexdigest() != pin['sha256']:
            raise ImportError('H+ reused source identity mismatch before import: '+name)
    return ROOT/'src/pq_rbbc/blind_uov_pqsat_v0_1'
