#!/usr/bin/env python3
"""Fail-closed native import contract for the PQ-RBBC v2.0 fork.

The selected profile is deliberately independent of the unreproduced
Blind-UOV 240-row instance.  It accepts no claim of bit-exact compatibility.
Closure instead requires all seven CAP/GGM/transcript components, zero external
assertions, exact wire binding, tamper rejection, a fork-specific security
proof, and fresh signature-size benchmarking.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field

import pq_rbbc_anemoi_f193 as permutation
import pq_rbbc_anemoi_sponge as sponge


IMPLEMENTATION_VERSION = "2.0"
RELATION_ID = "pq-rbbc-buov-iii-336/cap-hash/v1"
TARGET_FIELD = "GF(2^193)"
REQUIRED_TAMPER_CASES = frozenset(
    {"message", "mask", "cap_randomness", "hash_image"}
)
REQUIRED_NATIVE_COMPONENTS = frozenset(
    {
        "cap_commit",
        "ggm_seed_derivation",
        "ggm_seed_commitments",
        "ggm_seed_expansion",
        "fiat_shamir_hash",
        "consistency_check",
        "message_commitment_hash",
    }
)


def fork_profile_fingerprint() -> str:
    return sponge.profile_fingerprint(permutation.derive_parameters())


def _is_sha256(value: str) -> bool:
    if len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class ForkNativeImportEvidence:
    relation_id: str
    fork_profile_sha256: str
    target_field: str
    generator_source_sha256: str
    parameter_file_sha256: str
    row_stream_sha256: str
    native_rows: int
    external_assertions: int
    witness_independent_topology: bool
    honest_accepts: bool
    tamper_rejections: dict[str, bool] = field(default_factory=dict)
    component_rows: dict[str, int] = field(default_factory=dict)
    circuit_ticket_digest_is_native_message: bool = False
    circuit_mask_is_native_mask: bool = False
    circuit_hash_image_is_native_output: bool = False
    domain_separation_locked: bool = False
    serialization_locked: bool = False
    fork_vectors_verified_independently: bool = False
    cap_unique_witness_reviewed: bool = False
    cap_straightline_extraction_reviewed: bool = False
    fork_security_proof_revalidated: bool = False
    signature_size_rebenchmarked: bool = False
    claims_blind_uov_bit_exact_compatibility: bool = False


@dataclass(frozen=True)
class ClosureAudit:
    closed: bool
    failures: tuple[str, ...]


def audit_fork_import(
    evidence: ForkNativeImportEvidence | None,
) -> ClosureAudit:
    if evidence is None:
        return ClosureAudit(False, ("fork_native_import_evidence_missing",))

    failures: list[str] = []
    if evidence.relation_id != RELATION_ID:
        failures.append("wrong_relation_id")
    if evidence.fork_profile_sha256 != fork_profile_fingerprint():
        failures.append("fork_profile_mismatch")
    if evidence.target_field != TARGET_FIELD:
        failures.append("backend_field_mismatch")
    for label, digest in (
        ("generator_source", evidence.generator_source_sha256),
        ("parameter_file", evidence.parameter_file_sha256),
        ("row_stream", evidence.row_stream_sha256),
    ):
        if not _is_sha256(digest):
            failures.append(f"invalid_{label}_sha256")
    if evidence.native_rows <= 0:
        failures.append("native_rows_missing")
    if evidence.external_assertions != 0:
        failures.append("external_assertions_remain")
    missing_components = REQUIRED_NATIVE_COMPONENTS - evidence.component_rows.keys()
    if missing_components:
        failures.append(
            "missing_native_components:" + ",".join(sorted(missing_components))
        )
    if any(
        evidence.component_rows.get(name, 0) <= 0
        for name in REQUIRED_NATIVE_COMPONENTS
    ):
        failures.append("native_component_rows_missing")
    if sum(evidence.component_rows.values()) > evidence.native_rows:
        failures.append("component_rows_exceed_native_rows")
    for name in (
        "witness_independent_topology",
        "honest_accepts",
        "circuit_ticket_digest_is_native_message",
        "circuit_mask_is_native_mask",
        "circuit_hash_image_is_native_output",
        "domain_separation_locked",
        "serialization_locked",
        "fork_vectors_verified_independently",
        "cap_unique_witness_reviewed",
        "cap_straightline_extraction_reviewed",
        "fork_security_proof_revalidated",
        "signature_size_rebenchmarked",
    ):
        if not getattr(evidence, name):
            failures.append(name)
    if evidence.claims_blind_uov_bit_exact_compatibility:
        failures.append("forbidden_blind_uov_bit_exact_claim")
    missing_tamper_cases = REQUIRED_TAMPER_CASES - evidence.tamper_rejections.keys()
    if missing_tamper_cases:
        failures.append(
            "missing_tamper_cases:" + ",".join(sorted(missing_tamper_cases))
        )
    if not all(
        evidence.tamper_rejections.get(name, False)
        for name in REQUIRED_TAMPER_CASES
    ):
        failures.append("native_tamper_rejection_failed")
    return ClosureAudit(not failures, tuple(failures))


def build_native_profile_manifest() -> dict[str, object]:
    audit = audit_fork_import(None)
    parameters = permutation.derive_parameters()
    return {
        "implementation_version": IMPLEMENTATION_VERSION,
        "status": "independent Anemoi-193/336 fork selected; request hash primitive implemented; full CAP remains external",
        "fork_profile": {
            "name": sponge.PROFILE_NAME,
            "relation_id": RELATION_ID,
            "sponge_relation_id": sponge.PROFILE_RELATION_ID,
            "profile_sha256": sponge.profile_fingerprint(parameters),
            "target_field": TARGET_FIELD,
            "permutation_nonlinear_rows": permutation.NONLINEAR_ROWS,
            "rate_bits": sponge.RATE_BITS,
            "capacity_bits": sponge.CAPACITY_BITS,
            "request_hash_bits": sponge.REQUEST_HASH_BITS,
        },
        "compatibility": {
            "blind_uov_framework_used_as_design_source": True,
            "blind_uov_reported_constraints": permutation.BLIND_UOV_REPORTED_CONSTRAINTS,
            "blind_uov_bit_exact_compatible": False,
            "reported_240_constraint_gap_blocks_fork_engineering": False,
            "paper_security_reduction_automatically_inherited": False,
            "paper_signature_size_automatically_inherited": False,
        },
        "required_native_components": sorted(REQUIRED_NATIVE_COMPONENTS),
        "implemented_primitives": {
            "field_arithmetic": True,
            "anemoi_permutation": True,
            "canonical_sponge": True,
            "request_binding_hash": True,
            "production_cap_commit": False,
            "complete_message_commitment_hash_wiring": False,
        },
        "closure_audit": asdict(audit),
        "claim_boundary": {
            "external_assertions_in_parent_archive": 1,
            "full_cap_hash_implemented": False,
            "fork_security_proof_revalidated": False,
            "signature_size_rebenchmarked": False,
            "production_closed": False,
        },
    }


def main() -> None:
    print(json.dumps(build_native_profile_manifest(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
