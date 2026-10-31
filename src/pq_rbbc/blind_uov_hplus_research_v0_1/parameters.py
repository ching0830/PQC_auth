"""Strict H+ profile delta over an immutable, identity-checked legacy ABI.

The small manifest is a complete delta, not an independent copy of historical
claims. Its fingerprint covers the exact parent identity and every changed
parameter. No legacy proof, setup, or public-CS cache is admitted by this API.
"""
from dataclasses import fields, is_dataclass, replace
import hashlib
from pathlib import Path

from pq_rbbc.blind_uov_pqsat_v0_1 import parameters as _base
from pq_rbbc.blind_uov_pqsat_v0_1.parameters import (  # Identical field/type ABI.
    ConcreteProfile, ConsistencyProfile, DomainSpec, FieldId, FieldSpec,
    ProfileSource, ProfileValidationError, EvaluationDomainGroup,
    EvaluationDomainKind, EvaluationDomainProfile, HiddenChallengeGroup,
    HiddenChallengeProfile, OneTreeProfile, RelationProfile, SymmetricProfile, TreeGroup,
)

ROOT = Path(__file__).resolve().parents[3]
SOURCE = 'manifests/buov_cap_hplus_research_v0_1/profile.json'
DEFAULT_PROFILE_MANIFEST = ROOT / SOURCE
PROFILE_ID = 'pqsat-blind-uov-hplus-research-v0.1'
PROFILE_VERSION_U16 = 2
SUITE_ID_U16 = 0xFF33
PROFILE_FINGERPRINT_DOMAIN = b'PQSAT-BUOV-CAP-HPLUS-0.1/PROFILE-FP'
# Generated from the reviewed canonical manifest; no dynamic profile creation.
from ._pins import MANIFEST_BYTES, MANIFEST_SHA256, PROFILE_FINGERPRINT


def _manifest(path=None):
    selected = DEFAULT_PROFILE_MANIFEST if path is None else path
    if not isinstance(selected, Path):
        raise ProfileValidationError('profile path must be Path or None')
    with selected.open('rb') as source:
        raw = source.read(MANIFEST_BYTES + 1)
    if len(raw) != MANIFEST_BYTES or hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ProfileValidationError('H+ manifest identity mismatch')
    return raw, _base._parse_json(raw, label='H+ profile delta')


def check_reused_sources():
    """Check every reused Python module before adding the sole fallback path."""
    from .source_boundary import check_reused_sources as check
    return check()


def _new_profile(raw, document):
    parent = _base.load_profile_manifest()
    canonical = _base._canonical_parameter_json(document)
    domains = tuple(DomainSpec(d.purpose, d.label.replace(
        b'PQSAT-BUOV-CAP-0.1/', b'PQSAT-BUOV-CAP-HPLUS-0.1/'))
        for d in parent.symmetric.domains)
    source = ProfileSource(SOURCE, hashlib.sha256(raw).digest(),
                           _base._git_blob_oid(raw), document['base_commit'])
    return replace(parent, profile_id=PROFILE_ID, profile_version_u16=PROFILE_VERSION_U16,
        suite_id_u16=SUITE_ID_U16, fingerprint=PROFILE_FINGERPRINT,
        hidden_challenge=replace(parent.hidden_challenge,
            raw_domain=b'PQSAT-BUOV-CAP-HPLUS-0.1/OPEN-INDEX'),
        symmetric=replace(parent.symmetric, domains=domains),
        consistency=ConsistencyProfile(64, 4, 256, 2048, 32, 18**2 * 32**4, 256, 227),
        source=source, _parameter_document_json=canonical)


def profile_fingerprint(profile):
    if type(profile) is not ConcreteProfile or type(profile._parameter_document_json) is not bytes:
        raise ProfileValidationError('canonical ConcreteProfile required')
    return hashlib.shake_256(_base._tuple_encode(PROFILE_FINGERPRINT_DOMAIN,
        (profile._parameter_document_json,))).digest(32)


def validate_profile(profile):
    raw, document = _manifest()
    expected = _new_profile(raw, document)
    def exact(left, right):
        if type(left) is not type(right):
            return False
        if is_dataclass(right):
            return all(exact(getattr(left, f.name), getattr(right, f.name)) for f in fields(right))
        if type(right) is tuple:
            return len(left) == len(right) and all(exact(a, b) for a, b in zip(left, right))
        return left == right
    if not exact(profile, expected):
        raise ProfileValidationError('foreign or altered H+ profile')
    # Avoid bool == int / dataclass-subclass equality at the changed boundary.
    for value in (profile.profile_version_u16, profile.suite_id_u16,
                  *[getattr(profile.consistency, name)
                    for name in ConsistencyProfile.__dataclass_fields__]):
        if type(value) is not int:
            raise ProfileValidationError('H+ parameter must be exact int')
    if type(profile.profile_id) is not str or type(profile.fingerprint) is not bytes:
        raise ProfileValidationError('H+ identity has noncanonical type')
    parent = _base.load_profile_manifest()
    # All untouched ABI fields still undergo the original strict validator.
    _base.validate_profile(replace(profile, profile_id=parent.profile_id,
        profile_version_u16=parent.profile_version_u16, suite_id_u16=parent.suite_id_u16,
        fingerprint=parent.fingerprint, hidden_challenge=parent.hidden_challenge,
        symmetric=parent.symmetric, consistency=parent.consistency, source=parent.source,
        _parameter_document_json=parent._parameter_document_json))
    if profile_fingerprint(profile) != PROFILE_FINGERPRINT:
        raise ProfileValidationError('H+ recomputed fingerprint mismatch')


def load_profile_manifest(path=None):
    raw, document = _manifest(path)
    profile = _new_profile(raw, document)
    validate_profile(profile)
    return profile
