"""Deliberately unauthenticated test inputs; no certificates or proof artifacts."""

from dataclasses import replace
import hashlib
from types import SimpleNamespace

import pq_rbbc_cap_commit as cap
from pq_rbbc.contracts.system import (
    KEY_ROLE_ORDER, KeyReference, KeyRole, SystemConfiguration,
    SystemInitializationBundle, ThresholdPolicy,
)
from pq_threshold_candidates import TraceInputs
from pq_threshold_candidates.gf import ReferenceWitness, encrypt_reference
from pq_threshold_candidates.gf.research_abi_v0_1 import (
    ResearchCommonPP, ResearchIssueStatement, ResearchIssueWitness,
    ResearchTicketM, ResearchTraceBinding,
)


def sha(raw):
    return hashlib.sha256(raw).digest()


def fixture(pk, u=None):
    u = hashlib.shake_256(b"GF ABI test-only u").digest(128) if u is None else u
    keys = tuple(KeyReference(role, bytes([int(role)]) * 32,
                              sha(pk.encode()) if role == KeyRole.OPENING_ENCRYPTION
                              else bytes([16 + int(role)]) * 32) for role in KEY_ROLE_ORDER)
    cfg = SystemConfiguration(1, 7, b'D' * 32, b'P' * 32, 2_000_000_000,
                              keys[4].key_id, keys[3].key_id)
    origin = b'INSECURE-TEST-ONLY: not a key-origin certificate'
    backend = b'INSECURE-TEST-ONLY: not qualified backend parameters'
    manifest = b'INSECURE-TEST-ONLY: not a full relation manifest'
    binding = ResearchTraceBinding(sha(cfg.encode()), cfg.ctx, cfg.epoch,
                                   cfg.oa_key_id, sha(pk.encode()), cfg.issuer_key_id,
                                   keys[3].public_key_digest, sha(origin))
    pp = ResearchCommonPP(binding, sha(backend), sha(manifest))
    bundle = SystemInitializationBundle(cfg, pp.sha256, ThresholdPolicy(3, 2),
                                        ThresholdPolicy(3, 2), keys)
    holder = b'k' * 32
    h = hashlib.shake_256(b'PQ-RBBC/HOLD' + holder).digest(32)
    x = TraceInputs(b'r' * 32, b's' * 16, cfg.ctx, h)
    c = encrypt_reference(pk, x, ReferenceWitness(u))
    m = ResearchTicketM(pp.sha256, x.ctx, x.sn, x.h, c.payload)
    statement = ResearchIssueStatement(pp.sha256, x.ctx, b'i' * 32, x.rid, b'b' * 72)
    rho = cap.deterministic_randomness(cap.PRODUCTION_PARAMETERS).serialize(cap.PRODUCTION_PARAMETERS)
    w = ResearchIssueWitness(m, b'v' * 72, rho, holder, u)
    return SimpleNamespace(binding=binding, pp=pp, bundle=bundle, statement=statement,
                           m=m, w=w, pk=pk, x=x, origin=origin, backend=backend, manifest=manifest)


def arguments(f):
    return dict(expected_bundle_sha256=sha(f.bundle.encode()),
                initialization_bundle=f.bundle.encode(), common_pp=f.pp.encode(),
                tpk_record=f.pk.encode(), key_origin_evidence=f.origin,
                issue_backend_pp=f.backend, gf_full_relation_manifest=f.manifest,
                statement=f.statement.encode(), ticket_m=f.m.encode(), purpose='research')


def changed_binding_arguments(f, **changes):
    """Re-pin synthetic outer bundle solely to exercise deeper mismatch checks."""
    pp = replace(f.pp, trace_binding=replace(f.binding, **changes))
    bundle = replace(f.bundle, common_parameters_digest=pp.sha256)
    result = arguments(f)
    result.update(common_pp=pp.encode(), initialization_bundle=bundle.encode(),
                  expected_bundle_sha256=sha(bundle.encode()),
                  statement=replace(f.statement, common_pp_sha256=pp.sha256).encode(),
                  ticket_m=replace(f.m, common_pp_sha256=pp.sha256).encode())
    return result
