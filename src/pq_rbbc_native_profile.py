#!/usr/bin/env python3
"""Fail-closed native import contract for the PQ-RBBC v2.25 fork.

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
import pq_rbbc_cap_composer as composer
import pq_rbbc_cap_composer_recovery as composer_recovery
import pq_rbbc_cap_composer_recovery_evidence as recovery_evidence
import pq_rbbc_cap_global_tail as global_tail
import pq_rbbc_cap_global_tail_recovery_evidence as global_tail_recovery_evidence
import pq_rbbc_cap_output_relocation as output_relocation
import pq_rbbc_cap_planned_tree_producer as planned_tree_producer
import pq_rbbc_cap_production_namespace as production_namespace
import pq_rbbc_cap_production_tree2_rebased as production_tree2_rebased
import pq_rbbc_cap_tree2_rebased_recovery_evidence as tree2_rebased_recovery_evidence
import pq_rbbc_cap_tree1_planned_recovery_evidence as tree1_planned_recovery_evidence
import pq_rbbc_cap_tree3_planned_recovery_evidence as tree3_planned_recovery_evidence
import pq_rbbc_cap_tree4_planned_recovery_evidence as tree4_planned_recovery_evidence
import pq_rbbc_cap_tree5_7_batch_recovery_evidence as tree5_7_batch_recovery_evidence
import pq_rbbc_cap_production_split_tail as production_split_tail
import pq_rbbc_cap_production_tree0_producer as production_tree0
import pq_rbbc_cap_production_tree2_producer as production_tree2
import pq_rbbc_cap_split_tail as split_tail
import pq_rbbc_cap_tree_producer as tree_producer
import pq_rbbc_cap_native as reduced_native
import pq_rbbc_cap_shard_assignment as shard_assignment
import pq_rbbc_cap_shard_stream as shard_stream
import pq_rbbc_horner_native as horner_native


IMPLEMENTATION_VERSION = "2.25"
RELATION_ID = "pq-rbbc-buov-iii-336/cap-hash/v1"
TARGET_FIELD = "GF(2^193)"
TREE1_PLANNED_CONTRACT = planned_tree_producer.load_contract(
    planned_tree_producer.TREE1_INDEX
)
TREE3_PLANNED_CONTRACT = planned_tree_producer.load_contract(
    planned_tree_producer.TREE3_INDEX
)
TREE4_PLANNED_CONTRACT = planned_tree_producer.load_contract(
    planned_tree_producer.TREE4_INDEX
)
TREE5_7_PLANNED_CONTRACTS = tuple(
    planned_tree_producer.load_contract(tree_index) for tree_index in (5, 6, 7)
)
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
        "status": "the frozen v2.8 execution cache and v2.9 global-tail archive have been regenerated and revalidated; planned trees 0 through 3 are materialized, and trees 1, 2, and 3 have been fully replayed at their planned offsets; the remaining producers, complete replay, parent join, and security reductions remain external",
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
                "assignment_materialized": True,
                "assignment_format": shard_assignment.ASSIGNMENT_FORMAT,
                "assignment_body_bytes": shard_assignment.FROZEN_PRODUCTION_ASSIGNMENT_BODY_BYTES,
                "assignment_body_sha256": shard_assignment.FROZEN_PRODUCTION_ASSIGNMENT_BODY_SHA256,
                "assignment_archive_bytes": shard_assignment.FROZEN_PRODUCTION_ASSIGNMENT_ARCHIVE_BYTES,
                "assignment_archive_sha256": shard_assignment.FROZEN_PRODUCTION_ASSIGNMENT_ARCHIVE_SHA256,
                "whole_shard_rows_verified": shard_assignment.FROZEN_PRODUCTION_VERIFIED_ROWS,
                "whole_shard_verification_failures": shard_assignment.FROZEN_PRODUCTION_VERIFICATION_FAILURES,
                "stale_witness_probes": shard_assignment.FROZEN_PRODUCTION_STALE_WITNESS_PROBES,
                "stale_witness_probes_rejected": True,
                "stream_bytes": shard_stream.FROZEN_PRODUCTION_STREAM_BYTES,
                "row_stream_sha256": shard_stream.FROZEN_PRODUCTION_STREAM_SHA256,
                "wire_spool_bytes": shard_stream.FROZEN_PRODUCTION_SPOOL_BYTES,
                "wire_spool_sha256": shard_stream.FROZEN_PRODUCTION_SPOOL_SHA256,
                "commitment_sha256": shard_stream.FROZEN_PRODUCTION_COMMITMENT_SHA256,
            },
            "production_4096_leaf_shard_component": {
                "relation_id": shard_stream.PROFILE_RELATION_ID_4096,
                "explicitly_non_secure": True,
                "leaves": 4_096,
                "extension_degree": 13,
                "witness_bits": 2_048,
                "coefficients": 11,
                "consistency_points": 2,
                "tape_bits": 2_450,
                "rows": shard_stream.FROZEN_PRODUCTION_4096_ROWS,
                "wires": shard_stream.FROZEN_PRODUCTION_4096_WIRES,
                "nonlinear_rows": shard_stream.FROZEN_PRODUCTION_4096_NONLINEAR_ROWS,
                "linear_rows": shard_stream.FROZEN_PRODUCTION_4096_LINEAR_ROWS,
                "external_assertions": 0,
                "assignment_materialized": True,
                "assignment_format": shard_assignment.ASSIGNMENT_FORMAT,
                "assignment_body_bytes": shard_assignment.FROZEN_PRODUCTION_4096_ASSIGNMENT_BODY_BYTES,
                "assignment_body_sha256": shard_assignment.FROZEN_PRODUCTION_4096_ASSIGNMENT_BODY_SHA256,
                "assignment_archive_bytes": shard_assignment.FROZEN_PRODUCTION_4096_ASSIGNMENT_ARCHIVE_BYTES,
                "assignment_archive_sha256": shard_assignment.FROZEN_PRODUCTION_4096_ASSIGNMENT_ARCHIVE_SHA256,
                "whole_shard_rows_verified": shard_assignment.FROZEN_PRODUCTION_4096_VERIFIED_ROWS,
                "whole_shard_verification_failures": shard_assignment.FROZEN_PRODUCTION_4096_VERIFICATION_FAILURES,
                "stale_witness_probes": shard_assignment.FROZEN_PRODUCTION_4096_STALE_WITNESS_PROBES,
                "stale_witness_probes_rejected": True,
                "stream_bytes": shard_stream.FROZEN_PRODUCTION_4096_STREAM_BYTES,
                "row_stream_sha256": shard_stream.FROZEN_PRODUCTION_4096_STREAM_SHA256,
                "wire_spool_bytes": shard_stream.FROZEN_PRODUCTION_4096_SPOOL_BYTES,
                "wire_spool_sha256": shard_stream.FROZEN_PRODUCTION_4096_SPOOL_SHA256,
                "commitment_sha256": shard_stream.FROZEN_PRODUCTION_4096_COMMITMENT_SHA256,
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
            "production_2048_leaf_tree_shard_assignment_materialized": True,
            "production_2048_leaf_tree_shard_whole_assignment_verified": True,
            "production_2048_leaf_tree_shard_stale_witness_rejected": True,
            "production_4096_leaf_tree_shard_executed": True,
            "production_4096_leaf_tree_shard_stream_digest_frozen": True,
            "production_4096_leaf_tree_shard_wire_topology_closed": True,
            "production_4096_leaf_tree_shard_external_assertions": 0,
            "production_4096_leaf_tree_shard_assignment_materialized": True,
            "production_4096_leaf_tree_shard_whole_assignment_verified": True,
            "production_4096_leaf_tree_shard_stale_witness_rejected": True,
            "both_production_tree_shard_types_closed_separately": True,
            "production_cap_full_vector_executed": True,
            "canonical_18_tree_link_schedule_closed": True,
            "production_cap_composition_relation_id": composer.RELATION_ID,
            "production_cap_composition_document_sha256": composer.FROZEN_DOCUMENT_SHA256,
            "production_cap_commitment_sha256": composer.FROZEN_COMMITMENT_SHA256,
            "production_cap_request_hash_hex": composer.FROZEN_REQUEST_HASH_HEX,
            "production_cap_xof_trace_sha256": composer.FROZEN_XOF_TRACE_SHA256,
            "production_global_tail_relation_id": global_tail.RELATION_ID,
            "production_global_tail_rows": global_tail.FROZEN_PRODUCTION_ROWS,
            "production_global_tail_wires": global_tail.FROZEN_PRODUCTION_WIRES,
            "production_global_tail_row_stream_sha256": global_tail.FROZEN_PRODUCTION_STREAM_SHA256,
            "production_global_tail_assignment_sha256": global_tail.FROZEN_PRODUCTION_ASSIGNMENT_SHA256,
            "production_global_tail_native_closed": True,
            "production_global_tail_recovery_evidence_relation_id": global_tail_recovery_evidence.RELATION_ID,
            "production_global_tail_recovery_evidence_sha256": global_tail_recovery_evidence.FROZEN_EVIDENCE_SHA256,
            "production_global_tail_recovered_manifest_sha256": global_tail_recovery_evidence.FROZEN_RECOVERED_MANIFEST_SHA256,
            "production_global_tail_archive_regenerated": True,
            "reduced_split_tail_component": {
                "contract_id": split_tail.CONTRACT_ID,
                "canonical_relation_id": split_tail.CANONICAL_RELATION_ID,
                "rows": split_tail.FROZEN_REDUCED_ROWS,
                "wires": split_tail.FROZEN_REDUCED_WIRES,
                "row_stream_sha256": split_tail.FROZEN_REDUCED_STREAM_SHA256,
                "assignment_body_sha256": split_tail.FROZEN_REDUCED_ASSIGNMENT_BODY_SHA256,
                "assignment_archive_sha256": split_tail.FROZEN_REDUCED_ASSIGNMENT_ARCHIVE_SHA256,
                "boundary_wire_probes": 4,
                "external_assertions": 0,
                "explicitly_non_secure": True,
            },
            "production_split_tail_component": {
                "contract_id": production_split_tail.CONTRACT_ID,
                "canonical_relation_id": production_split_tail.SOURCE_RELATION_ID,
                "rows": global_tail.FROZEN_PRODUCTION_ROWS,
                "wires": global_tail.FROZEN_PRODUCTION_WIRES,
                "row_stream_sha256": global_tail.FROZEN_PRODUCTION_STREAM_SHA256,
                "assignment_archive_sha256": global_tail.FROZEN_PRODUCTION_ASSIGNMENT_SHA256,
                "h1_wire_start": production_split_tail.FROZEN_H1_WIRE_START,
                "point_wire_starts": production_split_tail.FROZEN_POINT_WIRE_STARTS,
                "boundary_wire_probes": production_split_tail.FROZEN_BOUNDARY_PROBES,
                "external_assertions": 0,
                "production_profile": True,
            },
            "production_tree0_producer_component": {
                "relation_id": production_tree0.RELATION_ID,
                "tree_index": production_tree0.TREE_INDEX,
                "leaves": production_tree0.LEAVES,
                "extension_degree": production_tree0.EXTENSION_DEGREE,
                "rows": production_tree0.FROZEN_ROWS,
                "local_wires": production_tree0.FROZEN_LOCAL_WIRES,
                "max_wire_id": production_tree0.FROZEN_MAX_WIRE_ID,
                "row_stream_sha256": production_tree0.FROZEN_STREAM_SHA256,
                "assignment_archive_bytes": production_tree0.FROZEN_ASSIGNMENT_BYTES,
                "assignment_archive_sha256": production_tree0.FROZEN_ASSIGNMENT_SHA256,
                "point_wire_starts": production_tree0.GLOBAL_POINT_STARTS,
                "tree_component_sha256": production_tree0.FROZEN_TREE_COMPONENT_SHA256,
                "external_assertions": 0,
                "verification_failures": 0,
                "point_mutation_probes": 3,
            },
            "production_tree2_producer_component": {
                "relation_id": production_tree2.RELATION_ID,
                "tree_index": production_tree2.TREE_INDEX,
                "leaves": production_tree2.LEAVES,
                "extension_degree": production_tree2.EXTENSION_DEGREE,
                "rows": production_tree2.FROZEN_ROWS,
                "local_wires": production_tree2.FROZEN_LOCAL_WIRES,
                "max_wire_id": production_tree2.FROZEN_MAX_WIRE_ID,
                "row_stream_sha256": production_tree2.FROZEN_STREAM_SHA256,
                "assignment_archive_bytes": production_tree2.FROZEN_ASSIGNMENT_BYTES,
                "assignment_archive_sha256": production_tree2.FROZEN_ASSIGNMENT_SHA256,
                "point_wire_starts": production_tree2.GLOBAL_POINT_STARTS,
                "output_wire_starts": production_tree2.FROZEN_OUTPUT_WIRE_STARTS,
                "tree_component_sha256": production_tree2.FROZEN_TREE_COMPONENT_SHA256,
                "external_assertions": 0,
                "verification_failures": 0,
                "point_mutation_probes": 3,
                "stale_witness_probes": 6,
            },
            "production_output_relocation_component": {
                "relation_id": output_relocation.RELATION_ID,
                "representative_tree_indices": output_relocation.TREE_ORDER,
                "relocations": 8,
                "rows": output_relocation.FROZEN_ROWS,
                "wires": output_relocation.FROZEN_WIRES,
                "row_stream_bytes": output_relocation.FROZEN_STREAM_BYTES,
                "row_stream_sha256": output_relocation.FROZEN_STREAM_SHA256,
                "assignment_archive_bytes": output_relocation.FROZEN_ASSIGNMENT_BYTES,
                "assignment_archive_sha256": output_relocation.FROZEN_ASSIGNMENT_SHA256,
                "witness_mutation_probes": 16,
                "configuration_mutation_probes": 6,
                "external_assertions": 0,
                "verification_failures": 0,
                "remaining_tree_instances_not_materialized": 16,
            },
            "production_namespace_component": {
                "relation_id": production_namespace.RELATION_ID,
                "plan_sha256": production_namespace.FROZEN_PLAN_SHA256,
                "tree_order": production_namespace.TREE_ORDER,
                "tree_count": production_namespace.FROZEN_TREE_COUNT,
                "point_wire_starts": production_namespace.POINT_WIRE_STARTS,
                "total_producer_wires": production_namespace.FROZEN_TOTAL_PRODUCER_WIRES,
                "total_producer_rows": production_namespace.FROZEN_TOTAL_PRODUCER_ROWS,
                "total_output_relocation_rows": production_namespace.FROZEN_TOTAL_OUTPUT_RELOCATION_ROWS,
                "planned_composition_rows": production_namespace.FROZEN_PLANNED_COMPOSITION_ROWS,
                "max_wire_id": production_namespace.FROZEN_MAX_PLANNED_WIRE_ID,
                "configuration_mutation_probes": 8,
                "representative_production_rows_replayed_at_planned_offsets": tree2_rebased_recovery_evidence.FROZEN_ROWS,
            },
            "production_composer_recovery_component": {
                "relation_id": composer_recovery.RELATION_ID,
                "checkpoint_format": composer_recovery.CHECKPOINT_FORMAT,
                "contract_sha256": composer_recovery.FROZEN_CONTRACT_SHA256,
                "reduced_execution_sha256": composer_recovery.FROZEN_REDUCED_EXECUTION_SHA256,
                "reduced_final_checkpoint_sha256": composer_recovery.FROZEN_REDUCED_FINAL_CHECKPOINT_SHA256,
                "checkpoint_mutation_probes": 8,
                "evidence_relation_id": recovery_evidence.RELATION_ID,
                "evidence_sha256": recovery_evidence.FROZEN_EVIDENCE_SHA256,
                "production_derivation_levels_checkpointed": recovery_evidence.FROZEN_DERIVATION_LEVELS_CHECKPOINTED,
                "production_derivations_checkpointed": recovery_evidence.FROZEN_DERIVATIONS_CHECKPOINTED,
                "production_seed_nodes_checkpointed": recovery_evidence.FROZEN_SEED_NODES_CHECKPOINTED,
                "production_leaf_outputs_checkpointed": recovery_evidence.FROZEN_LEAF_OUTPUTS_CHECKPOINTED,
                "production_checkpoint_sha256": recovery_evidence.FROZEN_CHECKPOINT_SHA256,
                "production_checkpoint_state_sha256": recovery_evidence.FROZEN_CHECKPOINT_STATE_SHA256,
                "production_execution_cache_bytes": recovery_evidence.FROZEN_EXECUTION_CACHE_BYTES,
                "production_execution_cache_sha256": recovery_evidence.FROZEN_EXECUTION_CACHE_SHA256,
                "production_execution_sha256": recovery_evidence.FROZEN_EXECUTION_SHA256,
                "production_composition_document_sha256": composer.FROZEN_DOCUMENT_SHA256,
                "production_execution_cache_regenerated": True,
                "production_composition_document_revalidated": True,
                "large_artifacts_tracked_in_git": False,
            },
            "production_tree2_planned_offset_component": {
                "relation_id": production_tree2_rebased.RELATION_ID,
                "contract_sha256": production_tree2_rebased.FROZEN_CONTRACT_SHA256,
                "namespace_plan_sha256": production_namespace.FROZEN_PLAN_SHA256,
                "tree_index": production_tree2_rebased.PLANNED_TREE_INDEX,
                "planned_local_wire_start": production_tree2_rebased.PLANNED_LOCAL_WIRE_START,
                "planned_max_wire_id": production_tree2_rebased.PLANNED_MAX_WIRE_ID,
                "planned_rebase_delta": production_tree2_rebased.PLANNED_REBASE_DELTA,
                "planned_output_wire_starts": production_tree2_rebased.PLANNED_OUTPUT_WIRE_STARTS,
                "reduced_fixture_assignment_sha256": production_tree2_rebased.FROZEN_REDUCED_FIXTURE_ASSIGNMENT_SHA256,
                "reduced_fixture_rows": 33_954,
                "reduced_fixture_wires": 23_135,
                "configuration_mutation_probes": 8,
                "evidence_relation_id": tree2_rebased_recovery_evidence.RELATION_ID,
                "evidence_sha256": tree2_rebased_recovery_evidence.FROZEN_EVIDENCE_SHA256,
                "replayed_manifest_sha256": tree2_rebased_recovery_evidence.FROZEN_REPLAY_MANIFEST_SHA256,
                "production_rows_replayed_at_planned_offset": tree2_rebased_recovery_evidence.FROZEN_ROWS,
                "production_local_wires": tree2_rebased_recovery_evidence.FROZEN_WIRES,
                "production_row_stream_sha256": tree2_rebased_recovery_evidence.FROZEN_STREAM_SHA256,
                "production_assignment_bytes": tree2_rebased_recovery_evidence.FROZEN_ARCHIVE_BYTES,
                "production_assignment_sha256": tree2_rebased_recovery_evidence.FROZEN_ARCHIVE_SHA256,
                "production_assignment_body_sha256": tree2_rebased_recovery_evidence.FROZEN_BODY_SHA256,
                "stale_witness_probes": tree2_rebased_recovery_evidence.FROZEN_STANDARD_PROBES,
                "point_mutation_probes": tree2_rebased_recovery_evidence.FROZEN_POINT_PROBES,
                "production_assignment_materialized": True,
                "production_full_replay_closed": True,
                "large_artifacts_tracked_in_git": False,
            },
            "production_tree1_planned_offset_component": {
                "runner_relation_id": planned_tree_producer.RELATION_ID,
                "contract_sha256": planned_tree_producer.FROZEN_TREE1_CONTRACT_SHA256,
                "namespace_plan_sha256": production_namespace.FROZEN_PLAN_SHA256,
                "tree_index": TREE1_PLANNED_CONTRACT.tree_index,
                "planned_local_wire_start": TREE1_PLANNED_CONTRACT.planned_local_wire_start,
                "planned_max_wire_id": TREE1_PLANNED_CONTRACT.planned_max_wire_id,
                "planned_rebase_delta": TREE1_PLANNED_CONTRACT.rebase_delta,
                "planned_output_wire_starts": TREE1_PLANNED_CONTRACT.planned_output_wire_starts,
                "evidence_relation_id": tree1_planned_recovery_evidence.RELATION_ID,
                "evidence_sha256": tree1_planned_recovery_evidence.FROZEN_EVIDENCE_SHA256,
                "replayed_manifest_sha256": tree1_planned_recovery_evidence.FROZEN_REPLAY_MANIFEST_SHA256,
                "production_rows_replayed_at_planned_offset": tree1_planned_recovery_evidence.FROZEN_ROWS,
                "production_local_wires": tree1_planned_recovery_evidence.FROZEN_WIRES,
                "production_row_stream_bytes": tree1_planned_recovery_evidence.FROZEN_STREAM_BYTES,
                "production_row_stream_sha256": tree1_planned_recovery_evidence.FROZEN_STREAM_SHA256,
                "production_assignment_bytes": tree1_planned_recovery_evidence.FROZEN_ARCHIVE_BYTES,
                "production_assignment_sha256": tree1_planned_recovery_evidence.FROZEN_ARCHIVE_SHA256,
                "production_assignment_body_sha256": tree1_planned_recovery_evidence.FROZEN_BODY_SHA256,
                "tree_component_sha256": tree1_planned_recovery_evidence.FROZEN_TREE_COMPONENT_SHA256,
                "stale_witness_probes": tree1_planned_recovery_evidence.FROZEN_STANDARD_PROBES,
                "point_mutation_probes": tree1_planned_recovery_evidence.FROZEN_POINT_PROBES,
                "production_assignment_materialized": True,
                "production_full_replay_closed": True,
                "large_artifacts_tracked_in_git": False,
            },
            "production_tree3_planned_offset_component": {
                "runner_relation_id": planned_tree_producer.RELATION_ID,
                "contract_sha256": planned_tree_producer.FROZEN_TREE3_CONTRACT_SHA256,
                "namespace_plan_sha256": production_namespace.FROZEN_PLAN_SHA256,
                "tree_index": TREE3_PLANNED_CONTRACT.tree_index,
                "planned_local_wire_start": TREE3_PLANNED_CONTRACT.planned_local_wire_start,
                "planned_max_wire_id": TREE3_PLANNED_CONTRACT.planned_max_wire_id,
                "planned_rebase_delta": TREE3_PLANNED_CONTRACT.rebase_delta,
                "planned_output_wire_starts": TREE3_PLANNED_CONTRACT.planned_output_wire_starts,
                "evidence_relation_id": tree3_planned_recovery_evidence.RELATION_ID,
                "evidence_sha256": tree3_planned_recovery_evidence.FROZEN_EVIDENCE_SHA256,
                "replayed_manifest_sha256": tree3_planned_recovery_evidence.FROZEN_REPLAY_MANIFEST_SHA256,
                "production_rows_replayed_at_planned_offset": tree3_planned_recovery_evidence.FROZEN_ROWS,
                "production_local_wires": tree3_planned_recovery_evidence.FROZEN_WIRES,
                "production_row_stream_bytes": tree3_planned_recovery_evidence.FROZEN_STREAM_BYTES,
                "production_row_stream_sha256": tree3_planned_recovery_evidence.FROZEN_STREAM_SHA256,
                "production_assignment_bytes": tree3_planned_recovery_evidence.FROZEN_ARCHIVE_BYTES,
                "production_assignment_sha256": tree3_planned_recovery_evidence.FROZEN_ARCHIVE_SHA256,
                "production_assignment_body_sha256": tree3_planned_recovery_evidence.FROZEN_BODY_SHA256,
                "tree_component_sha256": tree3_planned_recovery_evidence.FROZEN_TREE_COMPONENT_SHA256,
                "stale_witness_probes": tree3_planned_recovery_evidence.FROZEN_STANDARD_PROBES,
                "point_mutation_probes": tree3_planned_recovery_evidence.FROZEN_POINT_PROBES,
                "production_assignment_materialized": True,
                "production_full_replay_closed": True,
                "large_artifacts_tracked_in_git": False,
            },
            "production_tree4_planned_offset_component": {
                "runner_relation_id": planned_tree_producer.RELATION_ID,
                "contract_sha256": planned_tree_producer.FROZEN_TREE4_CONTRACT_SHA256,
                "namespace_plan_sha256": production_namespace.FROZEN_PLAN_SHA256,
                "tree_index": TREE4_PLANNED_CONTRACT.tree_index,
                "planned_local_wire_start": TREE4_PLANNED_CONTRACT.planned_local_wire_start,
                "planned_max_wire_id": TREE4_PLANNED_CONTRACT.planned_max_wire_id,
                "planned_rebase_delta": TREE4_PLANNED_CONTRACT.rebase_delta,
                "planned_output_wire_starts": TREE4_PLANNED_CONTRACT.planned_output_wire_starts,
                "evidence_relation_id": tree4_planned_recovery_evidence.RELATION_ID,
                "evidence_sha256": tree4_planned_recovery_evidence.FROZEN_EVIDENCE_SHA256,
                "replayed_manifest_sha256": tree4_planned_recovery_evidence.FROZEN_REPLAY_MANIFEST_SHA256,
                "production_rows_replayed_at_planned_offset": tree4_planned_recovery_evidence.FROZEN_ROWS,
                "production_local_wires": tree4_planned_recovery_evidence.FROZEN_WIRES,
                "production_row_stream_bytes": tree4_planned_recovery_evidence.FROZEN_STREAM_BYTES,
                "production_row_stream_sha256": tree4_planned_recovery_evidence.FROZEN_STREAM_SHA256,
                "production_assignment_bytes": tree4_planned_recovery_evidence.FROZEN_ARCHIVE_BYTES,
                "production_assignment_sha256": tree4_planned_recovery_evidence.FROZEN_ARCHIVE_SHA256,
                "production_assignment_body_sha256": tree4_planned_recovery_evidence.FROZEN_BODY_SHA256,
                "tree_component_sha256": tree4_planned_recovery_evidence.FROZEN_TREE_COMPONENT_SHA256,
                "stale_witness_probes": tree4_planned_recovery_evidence.FROZEN_STANDARD_PROBES,
                "point_mutation_probes": tree4_planned_recovery_evidence.FROZEN_POINT_PROBES,
                "production_assignment_materialized": True,
                "production_full_replay_closed": True,
                "large_artifacts_tracked_in_git": False,
            },
            "production_tree5_7_batch_planned_offset_component": {
                "runner_relation_id": planned_tree_producer.RELATION_ID,
                "evidence_relation_id": tree5_7_batch_recovery_evidence.RELATION_ID,
                "evidence_sha256": tree5_7_batch_recovery_evidence.FROZEN_EVIDENCE_SHA256,
                "tree_indices": [5, 6, 7],
                "trees": [
                    {
                        "tree_index": contract.tree_index,
                        "contract_sha256": tree5_7_batch_recovery_evidence.FROZEN_TREES[contract.tree_index]["contract_sha256"],
                        "planned_local_wire_start": contract.planned_local_wire_start,
                        "planned_max_wire_id": contract.planned_max_wire_id,
                        "planned_output_wire_starts": contract.planned_output_wire_starts,
                        "replayed_manifest_sha256": tree5_7_batch_recovery_evidence.FROZEN_TREES[contract.tree_index]["replayed_manifest_sha256"],
                        "production_rows_replayed_at_planned_offset": tree5_7_batch_recovery_evidence.FROZEN_ROWS,
                        "production_local_wires": tree5_7_batch_recovery_evidence.FROZEN_WIRES,
                        "production_row_stream_bytes": tree5_7_batch_recovery_evidence.FROZEN_STREAM_BYTES,
                        "production_row_stream_sha256": tree5_7_batch_recovery_evidence.FROZEN_TREES[contract.tree_index]["stream_sha256"],
                        "production_assignment_bytes": tree5_7_batch_recovery_evidence.FROZEN_ARCHIVE_BYTES,
                        "production_assignment_sha256": tree5_7_batch_recovery_evidence.FROZEN_TREES[contract.tree_index]["archive_sha256"],
                        "production_assignment_body_sha256": tree5_7_batch_recovery_evidence.FROZEN_TREES[contract.tree_index]["body_sha256"],
                        "tree_component_sha256": tree5_7_batch_recovery_evidence.FROZEN_TREES[contract.tree_index]["tree_component_sha256"],
                        "stale_witness_probes": tree5_7_batch_recovery_evidence.FROZEN_STANDARD_PROBES,
                        "point_mutation_probes": tree5_7_batch_recovery_evidence.FROZEN_POINT_PROBES,
                        "production_assignment_materialized": True,
                        "production_full_replay_closed": True,
                    }
                    for contract in TREE5_7_PLANNED_CONTRACTS
                ],
                "large_artifacts_tracked_in_git": False,
            },
            "reduced_tree_producer_component": {
                "relation_id": tree_producer.RELATION_ID,
                "tree_count": 2,
                "rows_per_tree": tree_producer.FROZEN_REDUCED_ROWS_PER_TREE,
                "wires_per_tree": tree_producer.FROZEN_REDUCED_WIRES_PER_TREE,
                "row_stream_sha256": tree_producer.FROZEN_REDUCED_STREAM_SHA256,
                "assignment_sha256": tree_producer.FROZEN_REDUCED_ASSIGNMENT_SHA256,
                "stale_witness_probes_per_tree": 6,
                "external_assertions": 0,
                "explicitly_non_secure": True,
            },
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
            "production_shard_full_assignment_closed": True,
            "production_4096_leaf_tree_shard_closed": True,
            "production_4096_leaf_tree_shard_security_profile": False,
            "both_production_tree_shard_types_closed_separately": True,
            "full_18_tree_reference_composition_closed": True,
            "canonical_18_tree_link_schedule_closed": True,
            "production_global_tail_native_closed": True,
            "reduced_split_tail_phase_contract_closed": True,
            "canonical_tail_stream_and_assignment_equivalent": True,
            "h1_and_consistency_point_ports_native_closed": True,
            "tail_phase_a_to_phase_b_wire_identity_closed": True,
            "production_split_tail_materialized": True,
            "production_h1_and_two_consistency_point_ports_native_closed": True,
            "production_tail_phase_a_to_phase_b_wire_identity_closed": True,
            "production_index0_4096_degree13_producer_native_closed": True,
            "production_index0_point_wire_identity_closed": True,
            "production_index0_output_values_match_tail": True,
            "production_index2_2048_degree12_producer_native_closed": True,
            "production_index2_point_wire_identity_closed": True,
            "production_index2_output_values_match_tail": True,
            "production_representative_output_relocation_contract_closed": True,
            "production_index0_all_four_output_relocations_closed": True,
            "production_index2_all_four_output_relocations_closed": True,
            "all_four_output_relocations_closed": True,
            "representative_cross_segment_wire_relation_closed": True,
            "production_18_tree_namespace_plan_closed": True,
            "production_namespace_intervals_nonoverlapping": True,
            "production_global_point_imports_preserved": True,
            "representative_rebase_rule_fixture_verified": True,
            "production_tree2_planned_offset_execution_gate_closed": True,
            "planned_offset_reduced_fixture_replayed": True,
            "production_tree2_rebased_assignment_materialized": True,
            "production_tree2_rebased_full_replay_closed": True,
            "production_tree1_planned_assignment_materialized": True,
            "production_tree1_planned_full_replay_closed": True,
            "production_tree3_planned_assignment_materialized": True,
            "production_tree3_planned_full_replay_closed": True,
            "production_tree4_planned_assignment_materialized": True,
            "production_tree4_planned_full_replay_closed": True,
            "production_tree5_planned_assignment_materialized": True,
            "production_tree5_planned_full_replay_closed": True,
            "production_tree6_planned_assignment_materialized": True,
            "production_tree6_planned_full_replay_closed": True,
            "production_tree7_planned_assignment_materialized": True,
            "production_tree7_planned_full_replay_closed": True,
            "materialized_planned_tree_indices": list(range(8)),
            "materialized_planned_tree_count": 8,
            "remaining_planned_tree_producers_materialized": False,
            "production_composer_checkpoint_recovery_gate_closed": True,
            "reduced_checkpoint_resume_bit_exact": True,
            "production_execution_cache_regenerated": True,
            "production_composition_document_revalidated": True,
            "production_global_tail_archive_regenerated": True,
            "representative_producers_rebased_replayed": True,
            "all_72_output_relocations_closed": False,
            "reduced_tree_producer_segments_native_closed": True,
            "reduced_producer_to_tail_port_values_match": True,
            "reduced_producer_point_wire_identity_closed": False,
            "tree_producer_segments_materialized": False,
            "cross_segment_wire_identity_closed": False,
            "complete_18_tree_assignment_replayed": False,
            "full_18_tree_composition_closed": False,
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
