#!/usr/bin/env python3
"""Fail-closed native import contract for the PQ-RBBC v2.5 fork.

The selected profile is deliberately independent of the unreproduced
Blind-UOV 240-row instance.  It accepts no claim of bit-exact compatibility.
Closure instead requires all seven CAP/GGM/transcript components, zero external
assertions, exact wire binding, tamper rejection, a fork-specific security
proof, and fresh signature-size benchmarking.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

import pq_rbbc_anemoi_f193 as permutation
import pq_rbbc_anemoi_sponge as sponge
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_native as reduced_native
import pq_rbbc_cap_shard_stream as shard_stream
import pq_rbbc_horner_native as horner_native


IMPLEMENTATION_VERSION = "2.5"
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
        "status": "one 2048-leaf production-shape CAP shard is closed at the streamed row-topology boundary with the full 2048-bit witness, degree-12 mask slices, two points, and 2450-bit tapes; the complete assignment, 4096-leaf shard, full 18-tree relation, and parent wire join remain external",
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
            "cap_relation_id": cap.PROFILE_RELATION_ID,
            "cap_profile_sha256": cap.profile_fingerprint(
                cap.PRODUCTION_PARAMETERS
            ),
            "cap_commitment_bytes": cap.commitment_bytes(
                cap.PRODUCTION_PARAMETERS
            ),
            "cap_production_accounting": cap.production_accounting(),
            "reduced_native_component": {
                "relation_id": reduced_native.PROFILE_RELATION_ID,
                "explicitly_non_secure": True,
                "rows": reduced_native.FROZEN_REDUCED_ROWS,
                "wires": reduced_native.FROZEN_REDUCED_WIRES,
                "xof_calls": reduced_native.FROZEN_REDUCED_XOF_CALLS,
                "anemoi_permutations": reduced_native.FROZEN_REDUCED_PERMUTATIONS,
                "external_assertions": 0,
                "row_stream_sha256": reduced_native.FROZEN_REDUCED_ROW_STREAM_SHA256,
            },
            "extended_2450_native_component": {
                "relation_id": reduced_native.PROFILE_RELATION_ID,
                "explicitly_non_secure": True,
                "production_width_tape_bits": 2_450,
                "rows": reduced_native.FROZEN_EXTENDED_ROWS,
                "wires": reduced_native.FROZEN_EXTENDED_WIRES,
                "xof_calls": reduced_native.FROZEN_EXTENDED_XOF_CALLS,
                "anemoi_permutations": reduced_native.FROZEN_EXTENDED_PERMUTATIONS,
                "external_assertions": 0,
                "row_stream_sha256": reduced_native.FROZEN_EXTENDED_ROW_STREAM_SHA256,
            },
            "production_width_horner_component": {
                "relation_id": horner_native.PROFILE_RELATION_ID,
                "vector_bits": horner_native.PRODUCTION_WITNESS_BITS,
                "coefficients": 11,
                "consistency_points": horner_native.PRODUCTION_CONSISTENCY_POINTS,
                "rows": 2_845,
                "wires": 2_843,
                "multiplication_rows": 20,
                "external_assertions": 0,
                "row_stream_sha256": "0c9d742d44808a20a35838be84a638924dc5b2f9183bba731eefba1cb9069850",
            },
            "horner_2450_native_component": {
                "relation_id": reduced_native.HORNER_PROFILE_RELATION_ID,
                "explicitly_non_secure": True,
                "witness_bits": 386,
                "coefficients": 2,
                "consistency_points": 2,
                "production_width_tape_bits": 2_450,
                "rows": reduced_native.FROZEN_HORNER_ROWS,
                "wires": reduced_native.FROZEN_HORNER_WIRES,
                "horner_calls": 7,
                "multiplication_rows": 14,
                "external_assertions": 0,
                "row_stream_sha256": reduced_native.FROZEN_HORNER_ROW_STREAM_SHA256,
            },
            "production_2048_leaf_shard_component": {
                "relation_id": shard_stream.PROFILE_RELATION_ID,
                "explicitly_non_secure": True,
                "leaves": 2_048,
                "extension_degree": 12,
                "witness_bits": 2_048,
                "coefficients": 11,
                "consistency_points": 2,
                "tape_bits": 2_450,
                "rows": shard_stream.FROZEN_PRODUCTION_ROWS,
                "wires": shard_stream.FROZEN_PRODUCTION_WIRES,
                "nonlinear_rows": shard_stream.FROZEN_PRODUCTION_NONLINEAR_ROWS,
                "linear_rows": shard_stream.FROZEN_PRODUCTION_LINEAR_ROWS,
                "external_assertions": 0,
                "assignment_materialized": False,
                "stream_bytes": shard_stream.FROZEN_PRODUCTION_STREAM_BYTES,
                "row_stream_sha256": shard_stream.FROZEN_PRODUCTION_STREAM_SHA256,
                "wire_spool_bytes": shard_stream.FROZEN_PRODUCTION_SPOOL_BYTES,
                "wire_spool_sha256": shard_stream.FROZEN_PRODUCTION_SPOOL_SHA256,
                "commitment_sha256": shard_stream.FROZEN_PRODUCTION_COMMITMENT_SHA256,
            },
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
            "production_cap_reference_algorithm": True,
            "ggm_seed_tree_reference": True,
            "consistency_hash_reference": True,
            "canonical_cap_serialization": True,
            "cap_to_h_rbbc_byte_join": True,
            "reduced_cap_native_rows_materialized": True,
            "reduced_cap_inter_call_wire_identity": True,
            "reduced_cap_to_h_rbbc_native_wire_join": True,
            "reduced_cap_external_assertions": 0,
            "arbitrary_length_multi_squeeze_native": True,
            "production_width_2450_bit_tape_native": True,
            "extended_2450_cap_native_rows_materialized": True,
            "extended_2450_cap_external_assertions": 0,
            "bit_bound_gf193_multiplication_native": True,
            "generic_multi_coefficient_horner_native": True,
            "production_2048_bit_horner_vector_native": True,
            "two_nonzero_distinct_consistency_points_constrained": True,
            "symbolic_extension_mask_horner_native": True,
            "horner_2450_cap_native_rows_materialized": True,
            "horner_2450_cap_external_assertions": 0,
            "production_2048_leaf_tree_shard_executed": True,
            "production_2048_leaf_tree_shard_stream_digest_frozen": True,
            "production_2048_leaf_tree_shard_wire_topology_closed": True,
            "production_2048_leaf_tree_shard_external_assertions": 0,
            "production_2048_leaf_tree_shard_assignment_materialized": False,
            "production_cap_full_vector_executed": False,
            "production_cap_native_rows_materialized": False,
            "production_cap_inter_call_wire_identity": False,
            "complete_message_commitment_hash_wiring": False,
        },
        "closure_audit": asdict(audit),
        "claim_boundary": {
            "external_assertions_in_parent_archive": 1,
            "full_cap_hash_implemented": False,
            "reference_cap_hash_implemented": True,
            "canonical_cap_bytes_bound_to_h_rbbc": True,
            "reduced_fixture_native_closed": True,
            "reduced_fixture_security_profile": False,
            "extended_2450_fixture_native_closed": True,
            "extended_2450_fixture_security_profile": False,
            "arithmetic_primitive_native_closed": True,
            "horner_2450_fixture_native_closed": True,
            "horner_2450_fixture_security_profile": False,
            "production_multi_squeeze_blocker_closed": True,
            "production_polynomial_hash_gadget_closed": True,
            "production_polynomial_hash_blocker_closed": True,
            "production_2048_bit_cap_integration_closed": True,
            "production_2048_leaf_tree_shard_closed": True,
            "production_2048_leaf_tree_shard_security_profile": False,
            "production_shard_full_assignment_closed": False,
            "fork_security_proof_revalidated": False,
            "signature_size_rebenchmarked": False,
            "production_closed": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(
        build_native_profile_manifest(), indent=2, sort_keys=True
    ) + "\n"
    if args.manifest:
        args.manifest.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
