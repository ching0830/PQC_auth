#!/usr/bin/env python3
"""Read-only v2.33 preflight for an independent unified-tree CAP profile.

The preflight reserves a new namespace and records migration impact, resource
bounds, and exact future command contracts.  It does not implement the new
profile and cannot start a large build, replay, or proving run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_commit as legacy_cap
import pq_rbbc_cap_prove_verify_preflight as v2_32


IMPLEMENTATION_VERSION = "2.33"
FORMAT = "PQRBBC-CAP-UNIFIED-TREE-MIGRATION-PREFLIGHT-1"
REPORT_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-MIGRATION-ENVIRONMENT-1"
RELATION_ID = "pq-rbbc/cap/unified-tree-migration/preflight/v1"
ROOT = Path(__file__).resolve().parents[1]
EXTERNAL_ROOT = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/v2_33_unified_tree_migration"
)

LEGACY_PROFILE_NAME = legacy_cap.PRODUCTION_PARAMETERS.name
LEGACY_PROFILE_FINGERPRINT = legacy_cap.profile_fingerprint(
    legacy_cap.PRODUCTION_PARAMETERS
)
RESERVED_PROFILE_NAME = (
    "PQ-RBBC-CAP-TCitH-III/Anemoi-193-336-Unified-GGM-CANDIDATE-v1"
)
RESERVED_PROFILE_RELATION_ID = (
    "pq-rbbc/cap/tcith-iii/anemoi-193-336/unified-ggm/candidate/v1"
)
RESERVED_COMMITMENT_MAGIC = b"PQRBBC-CAP-UGGM-COMMIT-V1"
RESERVED_PROOF_MAGIC = b"PQRBBC-CAP-UGGM-PROOF-V1"

LOGICAL_REPETITIONS = 18
LARGE_TREE_REPETITIONS = 2
LARGE_TREE_LEAVES = 1 << 12
SMALL_TREE_REPETITIONS = 16
SMALL_TREE_LEAVES = 1 << 11
UNIFIED_LEAVES = (
    LARGE_TREE_REPETITIONS * LARGE_TREE_LEAVES
    + SMALL_TREE_REPETITIONS * SMALL_TREE_LEAVES
)
T_OPEN = 174
EXPLICIT_POW_BITS = 9
TOTAL_POW_BITS = 13.9
TARGET_SECURITY_BITS = 192

MIN_FREE_DISK_BYTES = 80 * (1 << 30)
MIN_AVAILABLE_MEMORY_BYTES = 16 * (1 << 30)
MIN_CPU_CORES = 4

TRACKED_INPUTS = {
    "legacy_cap_source": (
        "src/pq_rbbc_cap_commit.py",
        32_526,
        "be3a2a767561f009acc2a274a85410ae6e02e23abd24145aa1d61883dd2dceee",
    ),
    "legacy_namespace_source": (
        "src/pq_rbbc_cap_production_namespace.py",
        26_130,
        "292a6df8458581a2b00ac5d4f5d7b3fba5ef5cbf88cf3c73fac9a72347a76a27",
    ),
    "v2_29_parent_join_evidence": (
        "artifacts/metadata/parent_join_recovery_v2_29/"
        "pq_rbbc_parent_join_recovery_evidence_v2_29.json",
        5_695,
        "1281afaee1d5d784390ee51c96c66ecc7f486ef4b4b7933590826a708f81b20e",
    ),
    "v2_31_cap_artifact_evidence": (
        "artifacts/metadata/cap_security_qualification_v2_31/"
        "pq_rbbc_cap_security_artifact_evidence_v2_31.json",
        4_720,
        "eb5b1c901b7fd55d2092e71caadf797f8ac510ad857c8199c9f77cd5b6c544e8",
    ),
    "v2_32_frozen_manifest": (
        "manifests/pq_rbbc_cap_prove_verify_preflight_manifest_v2_32.json",
        11_021,
        "d132dd0953a81af2f54d285d6162139880828927a659e95fb1cfbbdd927717aa",
    ),
    "v2_32_preflight_evidence": (
        "artifacts/metadata/cap_prove_verify_preflight_v2_32/"
        "pq_rbbc_cap_prove_verify_preflight_evidence_v2_32.json",
        5_445,
        "0fcba15c45dda36df82606a49a197eb85aa20e8ac38f1c31c557eba639258657",
    ),
    "v2_32_codec_source": (
        "src/pq_rbbc_cap_prove_verify.py",
        9_746,
        "79e7a81a2ed1f67e6fa9afc12613eda71ff32f719be9cdd32e9b575914a03e75",
    ),
    "v2_32_artifact_generator": (
        "src/pq_rbbc_cap_prove_verify_artifacts.py",
        21_981,
        "bf9094240d82192e6876b2e4ec289f4918d8a20d06b45d747ec39b77b46de15c",
    ),
    "v2_32_specification_source": (
        "docs/proof/source/pq_rbbc_cap_prove_verify_spec_v2_32.html",
        9_397,
        "829a5841f100d8a17fd4b774839fc02316abafb9c2923cdbec7c11153dae1aeb",
    ),
}

SOURCE_REQUIREMENTS = {
    "blind_uov_paper": {
        "filename": "blind_uov_eprint_2025_895_revision_2025_10_31.pdf",
        "bytes": 1_595_999,
        "sha256": "7ba2c040fd04823fb0d2aaad5e58348b5ef374726657ff1c0d87d000b4beff95",
        "schema": "pdf",
    },
    "optimized_bavc_paper": {
        "filename": "eprint_2024_490.pdf",
        "bytes": 1_500_374,
        "sha256": "b41c874ea925a65f33984e0789951144dd012380c6e99e53859af53aa9ffe7a4",
        "schema": "pdf",
    },
    "dsd_explanatory_paper": {
        "filename": "eprint_2024_541.pdf",
        "bytes": 859_797,
        "sha256": "ce30ff1d9a49b13211340f4c20d05a4ee76a9f9db1745d3f853102aad0b9837f",
        "schema": "pdf",
    },
    "v2_32_specification_candidate": {
        "filename": "pq_rbbc_cap_prove_verify_spec_v2_32.pdf",
        "bytes": 71_327,
        "sha256": "79dd7a5d9c1a33d6f3a5f247f2143890ff6761d1971f83439f85e0ada84615af",
        "schema": "pdf",
    },
    "v2_32_serialization_candidate": {
        "filename": "pq_rbbc_cap_proof_serialization_v2_32.json",
        "bytes": 3_722,
        "sha256": "b771ebc306937c2c72a419b976c2724e80e839a60e91d58051e253bf916c257e",
        "schema": "PQRBBC-CAP-PROOF-SERIALIZATION-CANDIDATE-1",
    },
    "v2_32_pow_disposition": {
        "filename": "pq_rbbc_cap_pow_security_profile_disposition_v2_32.json",
        "bytes": 2_906,
        "sha256": "034279dd0214eb94d9385d6a81fa4b5f5b50748df4842bb80a24a803973c7552",
        "schema": "PQRBBC-CAP-POW-SECURITY-DISPOSITION-1",
    },
    "v2_32_partial_implementation_evidence": {
        "filename": "pq_rbbc_cap_prove_verify_implementation_evidence_v2_32.json",
        "bytes": 5_519,
        "sha256": "93f4eea2e120e181846d70cffb7340e205a16efdfd13a70db75464a3036b8c75",
        "schema": "PQRBBC-CAP-PROVE-VERIFY-IMPLEMENTATION-EVIDENCE-1",
    },
}

MIGRATION_REQUIREMENTS = {
    "unified_tree_algorithm_specification": {
        "filename": "pq_rbbc_cap_unified_tree_spec_v2_33.pdf",
        "schema": "pdf",
        "purpose": "exact non-power-of-two tree, interleaving, opening, and counter rules",
        "identity_frozen": False,
    },
    "reduced_prototype_evidence": {
        "filename": "pq_rbbc_cap_unified_tree_reduced_evidence_v2_33.json",
        "schema": "PQRBBC-CAP-UNIFIED-TREE-REDUCED-EVIDENCE-1",
        "purpose": "positive, mutation, topology, serialization, opening, and PoW vectors",
        "identity_frozen": False,
    },
    "runner_qualification": {
        "filename": "pq_rbbc_cap_unified_tree_runner_qualification_v2_33.json",
        "schema": "PQRBBC-CAP-UNIFIED-TREE-RUNNER-QUALIFICATION-1",
        "purpose": "fresh-cache, resume, overwrite refusal, and resource behavior",
        "identity_frozen": False,
    },
    "resource_reservation": {
        "filename": "pq_rbbc_cap_unified_tree_resource_reservation_v2_33.json",
        "schema": "PQRBBC-CAP-UNIFIED-TREE-RESOURCE-RESERVATION-1",
        "purpose": "operator-approved disk, memory, CPU, and elapsed-time envelope",
        "identity_frozen": False,
    },
    "independent_design_review": {
        "filename": "pq_rbbc_cap_unified_tree_independent_review_v2_33.json",
        "schema": "PQRBBC-CAP-UNIFIED-TREE-INDEPENDENT-REVIEW-1",
        "purpose": "independent review before production pre-freeze",
        "identity_frozen": False,
    },
}


def canonical_json(document: object) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def document_sha256(document: object) -> str:
    return hashlib.sha256(canonical_json(document)).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identity(path: Path, size: int, digest: str) -> bool:
    return (
        path.is_file()
        and path.stat().st_size == size
        and sha256_file(path) == digest
    )


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} root must be an object")
    return document


def logical_leaf_counts() -> tuple[int, ...]:
    return (LARGE_TREE_LEAVES,) * LARGE_TREE_REPETITIONS + (
        SMALL_TREE_LEAVES,
    ) * SMALL_TREE_REPETITIONS


def unified_leaf_index(repetition: int, position: int) -> int:
    """Return the zero-based interleaved leaf index for a logical vector."""

    counts = logical_leaf_counts()
    if not 0 <= repetition < len(counts):
        raise ValueError("repetition out of range")
    if not 0 <= position < counts[repetition]:
        raise ValueError("position out of range")
    if position < SMALL_TREE_LEAVES:
        return position * LOGICAL_REPETITIONS + repetition
    if repetition >= LARGE_TREE_REPETITIONS:
        raise ValueError("small logical vectors have no upper leaf region")
    return (
        SMALL_TREE_LEAVES * LOGICAL_REPETITIONS
        + (position - SMALL_TREE_LEAVES) * LARGE_TREE_REPETITIONS
        + repetition
    )


def inverse_unified_leaf_index(index: int) -> tuple[int, int]:
    if not 0 <= index < UNIFIED_LEAVES:
        raise ValueError("unified leaf index out of range")
    lower_region = SMALL_TREE_LEAVES * LOGICAL_REPETITIONS
    if index < lower_region:
        position, repetition = divmod(index, LOGICAL_REPETITIONS)
    else:
        position_offset, repetition = divmod(
            index - lower_region, LARGE_TREE_REPETITIONS
        )
        position = SMALL_TREE_LEAVES + position_offset
    return repetition, position


def reserved_profile_descriptor() -> dict[str, object]:
    return {
        "status": "reserved_preflight_candidate_not_implemented",
        "name": RESERVED_PROFILE_NAME,
        "relation_id": RESERVED_PROFILE_RELATION_ID,
        "base_profile": {
            "name": LEGACY_PROFILE_NAME,
            "fingerprint": LEGACY_PROFILE_FINGERPRINT,
            "preserved_unchanged": True,
            "accepted_as_new_profile_evidence": False,
        },
        "field": "GF(2^193)",
        "anemoi_profile_sha256": legacy_cap.sponge.profile_fingerprint(
            legacy_cap.field.derive_parameters()
        ),
        "target_security_bits": TARGET_SECURITY_BITS,
        "logical_repetitions": LOGICAL_REPETITIONS,
        "logical_vector_leaf_counts": list(logical_leaf_counts()),
        "unified_tree": {
            "root_seed_count": 1,
            "leaves": UNIFIED_LEAVES,
            "internal_nodes": UNIFIED_LEAVES - 1,
            "total_nodes": 2 * UNIFIED_LEAVES - 1,
            "heap_internal_indices": [0, UNIFIED_LEAVES - 2],
            "heap_leaf_indices": [UNIFIED_LEAVES - 1, 2 * UNIFIED_LEAVES - 2],
            "children": "left=2*i+1,right=2*i+2",
            "leaf_mapping": (
                "position-major interleaving: all 18 repetitions for positions "
                "0..2047, then repetitions 0..1 for positions 2048..4095"
            ),
            "mapping_index_base": 0,
        },
        "pow": {
            "T_open": T_OPEN,
            "explicit_bits": EXPLICIT_POW_BITS,
            "reported_total_bits": TOTAL_POW_BITS,
            "counter_candidate": "u64le starting at zero without wrap",
            "challenge_bit_slicing_frozen": False,
            "counter_transcript_position_frozen": False,
            "paper_bound_automatically_inherited": False,
        },
        "reserved_serialization": {
            "commitment_magic_hex": RESERVED_COMMITMENT_MAGIC.hex(),
            "proof_magic_hex": RESERVED_PROOF_MAGIC.hex(),
            "legacy_magic_reuse_permitted": False,
            "legacy_profile_fingerprint_reuse_permitted": False,
            "projected_c_r_bytes_if_corrections_unchanged": 5_391,
            "projected_size_is_frozen": False,
            "pi_2_grammar_frozen": False,
        },
        "domain_policy": {
            "all_cap_domains_must_be_new": True,
            "prefix": "PQ-RBBC/v2.33/CAP-UGGM/",
            "legacy_domain_reuse_permitted": False,
        },
    }


def migration_impact_contract() -> dict[str, object]:
    return {
        "preserve_without_modification": [
            "legacy 18-root profile source and fingerprint",
            "all v2.19-v2.32 manifests and portable evidence as historical evidence",
            "ticket lifecycle",
            "pq_sat_auth",
            "top-level system architecture",
        ],
        "reusable_only_after_new_profile_revalidation": [
            "GF(2^193) arithmetic",
            "Anemoi-193/336 permutation and sponge implementation",
            "ticket relation semantics not consuming CAP commitment bytes",
            "raw 1472-bit append-delta concept",
            "v2.32 public-statement logical fields",
        ],
        "must_receive_new_namespace_and_evidence": [
            "unified GGM seed expansion and leaf mapping",
            "leaf commitments and tape derivation domains",
            "CAP h1/h2/h3 transcripts",
            "CAP commitment and proof serialization",
            "opening frontier and T_open validation",
            "proof-of-work counter grinding",
            "Protocol-11 Prove and Verify",
            "straight-line extractor and unique-mask reduction",
        ],
        "must_be_rebuilt_or_replayed": [
            "all CAP tree producer row streams and assignments",
            "CAP output relocation plan",
            "CAP aggregate relation and assignment",
            "parent-bound H_RBBC global tail because c_r bytes/profile change",
            "parent CAP-to-H_RBBC joined relation",
            "incremental BR1CS and full relation identity",
        ],
        "must_not_be_reused_as_new_observation": [
            "tree 0-17 observed stream_bytes",
            "tree 0-17 row-stream digests",
            "tree 0-17 assignment identities",
            "v2.29 589030555-row transcript identity",
            "v2.31 extractor transcript as unified-tree evidence",
        ],
        "claim_boundary": {
            "legacy_evidence_invalidated": False,
            "legacy_evidence_promoted_to_new_profile": False,
            "new_profile_relation_rows_known": False,
            "new_profile_wire_namespace_known": False,
            "new_profile_security_qualified": False,
        },
    }


def resource_estimate() -> dict[str, object]:
    legacy = legacy_cap.production_accounting()
    # The optimized construction samples one root k_0 and applies the PRG at
    # every internal node k_0..k_(L-2), hence exactly L-1 derivations.  The
    # legacy implementation receives each tree's first two children directly
    # and therefore uses leaves-2 derivations per tree.
    unified_seed_derive_calls = UNIFIED_LEAVES - 1
    additional_calls = unified_seed_derive_calls - legacy["seed_derive_calls"]
    projected_additional_rows = (
        additional_calls
        * legacy["seed_derive_permutations_per_call"]
        * legacy_cap.field.NONLINEAR_ROWS
    )
    projected_min_producer_rows = 513_312_336 + projected_additional_rows
    projected_min_combined_rows = 589_030_555 + projected_additional_rows
    pow_probability = 2.0 ** (-TOTAL_POW_BITS)
    return {
        "estimate_kind": "conservative planning estimate, not a frozen execution count",
        "legacy_baseline": {
            "producer_rows": 513_312_336,
            "combined_rows": 589_030_555,
            "tree_assignment_bytes": 9_739_068_204,
            "cap_xof_calls": legacy["total_xof_calls"],
            "cap_anemoi_permutations": legacy["total_anemoi_permutations"],
        },
        "unified_tree_projection": {
            "seed_derive_calls": unified_seed_derive_calls,
            "additional_seed_derive_calls_vs_legacy": additional_calls,
            "projected_min_additional_rows_if_all_other_topology_is_unchanged": (
                projected_additional_rows
            ),
            "projected_min_producer_rows": projected_min_producer_rows,
            "projected_min_combined_rows": projected_min_combined_rows,
            "two_full_replays_projected_min_row_checks": 2
            * projected_min_combined_rows,
            "exact_rows_known": False,
            "exact_wires_known": False,
        },
        "pow_grinding": {
            "reported_total_bits": TOTAL_POW_BITS,
            "success_probability_per_trial": pow_probability,
            "expected_trials": 2.0 ** TOTAL_POW_BITS,
            "p95_trial_upper_quantile": math.ceil(
                math.log(0.05) / math.log(1.0 - pow_probability)
            ),
            "p99_trial_upper_quantile": math.ceil(
                math.log(0.01) / math.log(1.0 - pow_probability)
            ),
            "per_trial_hash_cost_known": False,
        },
        "recommended_execution_envelope": {
            "cpu_cores_minimum": MIN_CPU_CORES,
            "memory_bytes_minimum": MIN_AVAILABLE_MEMORY_BYTES,
            "free_disk_bytes_minimum": MIN_FREE_DISK_BYTES,
            "free_disk_gib_minimum": 80,
            "single_materialized_result_baseline_bytes": 10_940_023_525,
            "elapsed_time_estimate_available": False,
            "elapsed_time_withheld_reason": (
                "reduced unified-tree benchmark and exact pi_2 transcript size are missing"
            ),
        },
        "preflight_envelope": {
            "cpu_cores": 1,
            "peak_memory_mib_upper_bound": 256,
            "elapsed_seconds_upper_bound": 60,
            "relation_rows_replayed": 0,
            "proofs_generated": 0,
        },
    }


def exact_command_contract() -> dict[str, object]:
    root = str(EXTERNAL_ROOT)
    manifest = "manifests/pq_rbbc_cap_unified_tree_migration_manifest_v2_33.json"
    runner = "src/pq_rbbc_cap_unified_tree_runner.py"
    return {
        "read_only_preflight": (
            "PYTHONPATH=src python -u "
            "src/pq_rbbc_cap_unified_tree_migration_preflight.py "
            f"--report {root}/pq_rbbc_cap_unified_tree_environment_v2_33.json "
            "--blind-uov-paper /tmp/pq_rbbc_external_artifacts_rebuilt/"
            "v2_30_fork_security/blind_uov_eprint_2025_895_revision_2025_10_31.pdf "
            "--optimized-bavc-paper /tmp/eprint_2024_490.pdf "
            "--dsd-explanatory-paper /tmp/eprint_2024_541.pdf "
            "--v2-32-specification /tmp/pq_rbbc_external_artifacts_rebuilt/"
            "v2_32_cap_prove_verify/pq_rbbc_cap_prove_verify_spec_v2_32.pdf "
            "--v2-32-serialization /tmp/pq_rbbc_external_artifacts_rebuilt/"
            "v2_32_cap_prove_verify/pq_rbbc_cap_proof_serialization_v2_32.json "
            "--v2-32-pow-disposition /tmp/pq_rbbc_external_artifacts_rebuilt/"
            "v2_32_cap_prove_verify/"
            "pq_rbbc_cap_pow_security_profile_disposition_v2_32.json "
            "--v2-32-implementation-evidence /tmp/"
            "pq_rbbc_external_artifacts_rebuilt/v2_32_cap_prove_verify/"
            "pq_rbbc_cap_prove_verify_implementation_evidence_v2_32.json"
        ),
        "reduced_prototype": {
            "command": (
                f"PYTHONPATH=src python -u {runner} --profile-manifest {manifest} "
                f"--phase reduced --output {root}/reduced --fresh-cache"
            ),
            "executable_now": False,
            "withheld_reason": "runner and reduced profile are not implemented",
        },
        "production_prefreeze": {
            "command": (
                f"PYTHONPATH=src python -u {runner} --profile-manifest {manifest} "
                f"--phase production-prefreeze --output {root}/prefreeze "
                "--fresh-cache --allow-large"
            ),
            "executable_now": False,
            "authorized_now": False,
            "withheld_reason": "reduced prototype, runner qualification, resource reservation, and review are missing",
        },
        "production_frozen_replay": {
            "command": (
                f"PYTHONPATH=src python -u {runner} --profile-manifest {manifest} "
                f"--phase production-frozen-replay --input {root}/prefreeze "
                f"--output {root}/frozen-replay --fresh-cache --allow-large"
            ),
            "executable_now": False,
            "authorized_now": False,
            "withheld_reason": "pre-freeze observation and frozen contract do not exist",
        },
        "aggregate_parent_replay": {
            "command": (
                "PYTHONPATH=src python -u "
                "src/pq_rbbc_cap_unified_tree_aggregate_replay.py "
                f"--profile-manifest {manifest} --input {root}/frozen-replay "
                f"--output {root}/aggregate-parent --fresh-cache --allow-large"
            ),
            "executable_now": False,
            "authorized_now": False,
            "withheld_reason": "new producer, relocation, global-tail, and parent contracts are not frozen",
        },
    }


def claim_boundary() -> dict[str, bool]:
    tracked_ready = not validate_tracked_inputs()
    return {
        "v2_33_read_only_migration_preflight_closed": tracked_ready,
        "unified_tree_namespace_reserved": tracked_ready,
        "migration_impact_contract_frozen": tracked_ready,
        "migration_authorization_recorded": tracked_ready,
        "legacy_18_tree_profile_preserved": tracked_ready,
        "unified_tree_profile_implemented": False,
        "unified_tree_profile_fingerprint_frozen": False,
        "unified_tree_runner_qualified": False,
        "reduced_prototype_verified": False,
        "production_prefreeze_started": False,
        "large_replay_started": False,
        "large_proving_run_started": False,
        "cap_security_qualified": False,
        "fork_security_proof_revalidated": False,
        "production_closed": False,
        "system_architecture_changed": False,
        "ticket_lifecycle_changed": False,
        "pq_sat_auth_changed": False,
    }


def validate_tracked_inputs() -> tuple[str, ...]:
    failures: list[str] = []
    for label, (relative, size, digest) in TRACKED_INPUTS.items():
        if not _identity(ROOT / relative, size, digest):
            failures.append(f"{label}_identity")
    if LEGACY_PROFILE_FINGERPRINT != v2_32.V2_31_PROFILE_FINGERPRINT:
        failures.append("legacy_profile_fingerprint")
    parameters = legacy_cap.PRODUCTION_PARAMETERS
    if (
        parameters.tree_count != LOGICAL_REPETITIONS
        or parameters.leaf_count != UNIFIED_LEAVES
        or parameters.expanded_leaf_counts() != logical_leaf_counts()
    ):
        failures.append("legacy_tree_shape")
    for index in (0, 1, 17, 18, 36_863, 36_864, UNIFIED_LEAVES - 1):
        repetition, position = inverse_unified_leaf_index(index)
        if unified_leaf_index(repetition, position) != index:
            failures.append("unified_leaf_mapping")
            break
    parent = _read_json(ROOT / TRACKED_INPUTS["v2_29_parent_join_evidence"][0])
    source = parent.get("source_execution_semantics", parent.get("result", {}))
    serialized = canonical_json(parent)
    if (
        b"589030555" not in serialized
        or b"1f0113f965a03351b6d62c4801a9d15d0255640282b90215397170b87ad6a514"
        not in serialized
    ):
        failures.append("v2_29_execution_semantics")
    del source
    return tuple(failures)


def build_frozen_manifest() -> dict[str, object]:
    failures = list(validate_tracked_inputs())
    descriptor = reserved_profile_descriptor()
    impact = migration_impact_contract()
    resources = resource_estimate()
    commands = exact_command_contract()
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "authorization_scope": {
            "authorized": True,
            "action": "create an independent unified-tree CAP namespace/profile",
            "legacy_profile_must_be_preserved": True,
            "read_only_migration_preflight_first": True,
            "large_rebuild_requires_safe_preflight": True,
            "large_replay_requires_safe_preflight": True,
            "large_proving_run_authorized": False,
        },
        "tracked_inputs": {
            label: {"path": relative, "bytes": size, "sha256": digest}
            for label, (relative, size, digest) in TRACKED_INPUTS.items()
        },
        "tracked_validation_failures": failures,
        "reserved_profile_descriptor": descriptor,
        "reserved_profile_descriptor_sha256": document_sha256(descriptor),
        "migration_impact_contract": impact,
        "migration_impact_contract_sha256": document_sha256(impact),
        "source_requirements": SOURCE_REQUIREMENTS,
        "migration_requirements": MIGRATION_REQUIREMENTS,
        "resource_estimate": resources,
        "exact_commands": commands,
        "execution_policy": {
            "read_only": True,
            "external_root": str(EXTERNAL_ROOT),
            "legacy_artifacts_read_only": True,
            "other_tree_observed_stream_bytes_reusable": False,
            "large_profile_build_permitted": False,
            "large_replay_permitted": False,
            "large_proving_run_permitted": False,
        },
        "claim_boundary": claim_boundary(),
    }


def _available_memory_bytes() -> int:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return 0
    return 0


def environment_resources(path: Path) -> dict[str, object]:
    disk = shutil.disk_usage(path if path.exists() else path.parent)
    memory = _available_memory_bytes()
    cores = os.cpu_count() or 0
    return {
        "cpu_cores": cores,
        "available_memory_bytes": memory,
        "free_disk_bytes": disk.free,
        "minimums": {
            "cpu_cores": MIN_CPU_CORES,
            "available_memory_bytes": MIN_AVAILABLE_MEMORY_BYTES,
            "free_disk_bytes": MIN_FREE_DISK_BYTES,
        },
        "capacity_check_passed": (
            cores >= MIN_CPU_CORES
            and memory >= MIN_AVAILABLE_MEMORY_BYTES
            and disk.free >= MIN_FREE_DISK_BYTES
        ),
        "capacity_check_is_execution_authorization": False,
    }


def _check_source(path: Path | None, requirement: Mapping[str, object]) -> dict[str, object]:
    if path is None:
        return {"provided": False, "verified": False, "failures": ["not_provided"]}
    failures: list[str] = []
    if path.name != requirement["filename"]:
        failures.append("filename")
    if not path.is_file():
        failures.append("missing")
        return {"provided": True, "verified": False, "failures": failures}
    if path.stat().st_size != requirement["bytes"]:
        failures.append("bytes")
    digest = sha256_file(path)
    if digest != requirement["sha256"]:
        failures.append("sha256")
    schema = requirement["schema"]
    if schema == "pdf":
        with path.open("rb") as stream:
            if stream.read(5) != b"%PDF-":
                failures.append("pdf_header")
    else:
        try:
            document = _read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            failures.append("json")
        else:
            if document.get("format") != schema:
                failures.append("format")
    return {
        "provided": True,
        "verified": not failures,
        "bytes": path.stat().st_size,
        "sha256": digest,
        "failures": failures,
    }


def _check_migration_candidate(
    path: Path | None, requirement: Mapping[str, object]
) -> dict[str, object]:
    if path is None:
        return {
            "provided": False,
            "identity_frozen": False,
            "schema_valid": False,
            "verified": False,
            "failures": ["not_provided"],
        }
    failures: list[str] = []
    schema_valid = True
    if path.name != requirement["filename"]:
        failures.append("filename")
    if not path.is_file():
        failures.append("missing")
        schema_valid = False
    elif requirement["schema"] == "pdf":
        with path.open("rb") as stream:
            schema_valid = stream.read(5) == b"%PDF-"
    else:
        try:
            document = _read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            schema_valid = False
        else:
            schema_valid = document.get("format") == requirement["schema"]
    if not schema_valid:
        failures.append("schema")
    failures.append("identity_not_frozen")
    result: dict[str, object] = {
        "provided": True,
        "identity_frozen": False,
        "schema_valid": schema_valid,
        "verified": False,
        "failures": failures,
    }
    if path.is_file():
        result.update({"bytes": path.stat().st_size, "sha256": sha256_file(path)})
    return result


def build_environment_report(
    sources: Mapping[str, Path | None],
    migration_candidates: Mapping[str, Path | None],
) -> dict[str, object]:
    tracked_failures = list(validate_tracked_inputs())
    source_checks = {
        name: _check_source(sources.get(name), requirement)
        for name, requirement in SOURCE_REQUIREMENTS.items()
    }
    migration_checks = {
        name: _check_migration_candidate(
            migration_candidates.get(name), requirement
        )
        for name, requirement in MIGRATION_REQUIREMENTS.items()
    }
    resources = environment_resources(EXTERNAL_ROOT)
    source_ready = not tracked_failures and all(
        item["verified"] is True for item in source_checks.values()
    )
    blockers = [
        *(f"tracked:{item}" for item in tracked_failures),
        *(f"source:{name}" for name, item in source_checks.items() if not item["verified"]),
        *(f"migration:{name}" for name, item in migration_checks.items() if not item["verified"]),
    ]
    if resources["capacity_check_passed"] is not True:
        blockers.append("environment:capacity")
    return {
        "format": REPORT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "checks": {
            "tracked_inputs": {"verified": not tracked_failures, "failures": tracked_failures},
            "source_artifacts": source_checks,
            "migration_artifacts": migration_checks,
            "resources": resources,
        },
        "blockers": blockers,
        "safe_to_run_read_only_preflight": not tracked_failures,
        "safe_to_author_unified_tree_specification": source_ready,
        "safe_to_implement_reduced_prototype": source_ready,
        "safe_to_start_production_prefreeze": False,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
        "large_profile_build_started": False,
        "large_replay_started": False,
        "large_proving_run_started": False,
        "resource_estimate": resource_estimate(),
        "exact_commands": exact_command_contract(),
        "claim_boundary": claim_boundary(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print-frozen", action="store_true")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--blind-uov-paper", type=Path)
    parser.add_argument("--optimized-bavc-paper", type=Path)
    parser.add_argument("--dsd-explanatory-paper", type=Path)
    parser.add_argument("--v2-32-specification", type=Path)
    parser.add_argument("--v2-32-serialization", type=Path)
    parser.add_argument("--v2-32-pow-disposition", type=Path)
    parser.add_argument("--v2-32-implementation-evidence", type=Path)
    parser.add_argument("--unified-tree-specification", type=Path)
    parser.add_argument("--reduced-prototype-evidence", type=Path)
    parser.add_argument("--runner-qualification", type=Path)
    parser.add_argument("--resource-reservation", type=Path)
    parser.add_argument("--independent-design-review", type=Path)
    args = parser.parse_args()
    if args.print_frozen:
        print(canonical_json(build_frozen_manifest()).decode(), end="")
        return
    if args.report is None:
        parser.error("--report or --print-frozen is required")
    report = build_environment_report(
        {
            "blind_uov_paper": args.blind_uov_paper,
            "optimized_bavc_paper": args.optimized_bavc_paper,
            "dsd_explanatory_paper": args.dsd_explanatory_paper,
            "v2_32_specification_candidate": args.v2_32_specification,
            "v2_32_serialization_candidate": args.v2_32_serialization,
            "v2_32_pow_disposition": args.v2_32_pow_disposition,
            "v2_32_partial_implementation_evidence": args.v2_32_implementation_evidence,
        },
        {
            "unified_tree_algorithm_specification": args.unified_tree_specification,
            "reduced_prototype_evidence": args.reduced_prototype_evidence,
            "runner_qualification": args.runner_qualification,
            "resource_reservation": args.resource_reservation,
            "independent_design_review": args.independent_design_review,
        },
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_bytes(canonical_json(report))
    print(json.dumps({
        "report": str(args.report),
        "safe_to_author_unified_tree_specification": report[
            "safe_to_author_unified_tree_specification"
        ],
        "safe_to_implement_reduced_prototype": report[
            "safe_to_implement_reduced_prototype"
        ],
        "safe_to_start_production_prefreeze": report[
            "safe_to_start_production_prefreeze"
        ],
        "safe_to_start_large_replay": report["safe_to_start_large_replay"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
