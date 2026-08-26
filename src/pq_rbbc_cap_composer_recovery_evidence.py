#!/usr/bin/env python3
"""Seal the completed PQ-RBBC production composer recovery, v2.19.

The v2.18 runner reconstructs trusted local pickle artifacts.  This module
turns one locally verified run into portable, path-free evidence suitable for
Git while keeping the checkpoint and execution cache outside the repository.

Both pickle inputs must be locally generated and trusted.  Identity checks do
not make pickle deserialization safe for hostile or downloaded inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_composer as composer
import pq_rbbc_cap_composer_recovery as recovery
import pq_rbbc_cap_global_tail as global_tail


IMPLEMENTATION_VERSION = "2.19"
EVIDENCE_FORMAT = "PQRBBC-CAP-COMPOSER-RECOVERY-EVIDENCE-1"
RELATION_ID = "pq-rbbc/cap/production-composer-recovery-evidence/v1"
MANIFEST_NAME = "pq_rbbc_cap_composer_recovery_evidence_v2_19.json"

FROZEN_EVIDENCE_SHA256 = (
    "2b36ed1a4fb75e2ddbf826fa39ebd3d9b815a38873c93bd8635f56de2d8ad0f8"
)
FROZEN_CHECKPOINT_BYTES = 19_524_889
FROZEN_CHECKPOINT_SHA256 = (
    "01244778354875ff4f410bb5ca53a486369eb1760872c457f624108fc922279a"
)
FROZEN_CHECKPOINT_STATE_SHA256 = (
    "660c6b34072677abcfbf606c9c3ecc94171eb31e6ea1ebe7d1c418a78e338071"
)
FROZEN_EXECUTION_CACHE_BYTES = 35_509_449
FROZEN_EXECUTION_CACHE_SHA256 = (
    "19b334a893fc839384010de54116f03d50b9f4fbae41e3e24dc21de833907b6e"
)
FROZEN_EXECUTION_SHA256 = (
    "69de49f5ad49f37ec461f2b22cd0bdf5293cb727644db5c23070cbd575efe61c"
)
FROZEN_COMPOSITION_MANIFEST_BYTES = 27_333
FROZEN_DERIVATION_LEVELS_CHECKPOINTED = 182
FROZEN_DERIVATIONS_CHECKPOINTED = 40_924
FROZEN_SEED_NODES_CHECKPOINTED = 40_960
FROZEN_LEAF_OUTPUTS_CHECKPOINTED = 40_960
FROZEN_XOF_TRACE_BYTES = 44_236_358
FROZEN_XOF_CALLS = 122_847


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(document: Mapping[str, object]) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _tree_shapes() -> list[list[int]]:
    return [[4096, 13], [4096, 13], *[[2048, 12] for _ in range(16)]]


def build_frozen_evidence_document() -> dict[str, object]:
    """Return the portable evidence frozen after the completed v2.18 run."""

    return {
        "format": EVIDENCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "source_recovery": {
            "implementation_version": recovery.IMPLEMENTATION_VERSION,
            "relation_id": recovery.RELATION_ID,
            "checkpoint_format": recovery.CHECKPOINT_FORMAT,
            "contract_sha256": recovery.FROZEN_CONTRACT_SHA256,
            "resumed_checkpoint": True,
            "checkpoint_bytes": FROZEN_CHECKPOINT_BYTES,
            "checkpoint_sha256": FROZEN_CHECKPOINT_SHA256,
            "checkpoint_state_sha256": FROZEN_CHECKPOINT_STATE_SHA256,
            "checkpoint_phase": "complete",
            "derivation_levels_checkpointed": FROZEN_DERIVATION_LEVELS_CHECKPOINTED,
            "derivations_checkpointed": FROZEN_DERIVATIONS_CHECKPOINTED,
            "seed_nodes_checkpointed": FROZEN_SEED_NODES_CHECKPOINTED,
            "leaf_outputs_checkpointed": FROZEN_LEAF_OUTPUTS_CHECKPOINTED,
        },
        "production_execution": {
            "profile_sha256": cap.profile_fingerprint(cap.PRODUCTION_PARAMETERS),
            "tree_count": 18,
            "tree_shapes": _tree_shapes(),
            "leaf_count": 40_960,
            "execution_cache_bytes": FROZEN_EXECUTION_CACHE_BYTES,
            "execution_cache_sha256": FROZEN_EXECUTION_CACHE_SHA256,
            "execution_sha256": FROZEN_EXECUTION_SHA256,
            "execution_cache_identity_failures": 0,
            "xof_calls": FROZEN_XOF_CALLS,
            "xof_trace_bytes": FROZEN_XOF_TRACE_BYTES,
            "xof_trace_sha256": composer.FROZEN_XOF_TRACE_SHA256,
            "commitment_bytes": 5_391,
            "commitment_sha256": composer.FROZEN_COMMITMENT_SHA256,
        },
        "composition_document": {
            "format": composer.COMPOSITION_FORMAT,
            "relation_id": composer.RELATION_ID,
            "manifest_bytes": FROZEN_COMPOSITION_MANIFEST_BYTES,
            "document_sha256": composer.FROZEN_DOCUMENT_SHA256,
            "validation_failures": 0,
            "mutation_probes": 5,
            "mutation_probes_rejected": True,
        },
        "artifact_policy": {
            "large_artifacts_tracked_in_git": False,
            "portable_evidence_contains_absolute_paths": False,
            "checkpoint_and_cache_are_trusted_local_pickle": True,
            "untrusted_pickle_must_never_be_loaded": True,
        },
        "claim_boundary": {
            "production_composer_checkpoint_recovery_gate_closed": True,
            "reduced_checkpoint_resume_bit_exact": True,
            "production_execution_cache_regenerated": True,
            "production_composition_document_revalidated": True,
            "production_global_tail_archive_regenerated": False,
            "production_tree2_rebased_assignment_materialized": False,
            "production_tree2_rebased_full_replay_closed": False,
            "representative_producers_rebased_replayed": False,
            "complete_18_tree_assignment_replayed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }


def validate_evidence_document(document: Mapping[str, object]) -> tuple[str, ...]:
    failures: list[str] = []
    expected = build_frozen_evidence_document()
    if document.get("format") != EVIDENCE_FORMAT:
        failures.append("wrong_format")
    if document.get("implementation_version") != IMPLEMENTATION_VERSION:
        failures.append("wrong_implementation_version")
    if document.get("relation_id") != RELATION_ID:
        failures.append("wrong_relation_id")

    for section, failure in (
        ("source_recovery", "source_recovery_identity"),
        ("production_execution", "production_execution_identity"),
        ("composition_document", "composition_document_identity"),
        ("artifact_policy", "artifact_policy"),
        ("claim_boundary", "claim_boundary"),
    ):
        if document.get(section) != expected[section]:
            failures.append(failure)
    return tuple(failures)


def verify_frozen_evidence(path: Path) -> tuple[str, ...]:
    encoded = path.read_bytes()
    failures: list[str] = []
    if FROZEN_EVIDENCE_SHA256 != "TODO":
        if hashlib.sha256(encoded).hexdigest() != FROZEN_EVIDENCE_SHA256:
            failures.append("frozen_evidence_sha256")
    try:
        document = json.loads(encoded)
    except json.JSONDecodeError:
        return tuple(failures + ["invalid_json"])
    if not isinstance(document, dict):
        return tuple(failures + ["evidence_root"])
    failures.extend(validate_evidence_document(document))
    return tuple(dict.fromkeys(failures))


def build_evidence_from_artifacts(
    recovery_manifest_path: Path,
    checkpoint_path: Path,
    execution_cache_path: Path,
    composition_manifest_path: Path,
) -> dict[str, object]:
    """Validate trusted local artifacts and return their portable evidence."""

    recovery_manifest = json.loads(
        recovery_manifest_path.read_text(encoding="utf-8")
    )
    production = recovery_manifest.get("production_recovery", {})
    claims = recovery_manifest.get("claim_boundary", {})
    if not isinstance(production, dict) or production.get("status") != "complete":
        raise ValueError("production recovery manifest is not complete")
    if not isinstance(claims, dict):
        raise ValueError("production recovery claim boundary is missing")

    parameters = cap.PRODUCTION_PARAMETERS
    randomness = cap.deterministic_randomness(
        parameters, composer.FROZEN_RANDOMNESS_LABEL
    )
    checkpoint = recovery.load_checkpoint(checkpoint_path, parameters, randomness)
    if checkpoint.phase != "complete":
        raise ValueError("production recovery checkpoint is not complete")

    frozen_failures = composer.verify_frozen_document(composition_manifest_path)
    if frozen_failures:
        raise ValueError(
            "composition document rejected: " + ",".join(frozen_failures)
        )
    composition_document = json.loads(
        composition_manifest_path.read_text(encoding="utf-8")
    )

    # This loader deserializes pickle.  The caller must supply a trusted local
    # cache produced by the recovery run; identity validation is not a sandbox.
    summary = global_tail._load_production_execution(execution_cache_path)
    execution = summary.execution
    execution_failures = composer.validate_execution_cache_identity(
        summary, parameters, randomness
    )
    trace_bytes, trace_sha256 = composer.xof_trace_digest(execution.xof_calls)
    commitment_sha256 = hashlib.sha256(execution.commitment.encoded).hexdigest()

    exact_checks = {
        "source_implementation_version": recovery_manifest.get("implementation_version")
        == recovery.IMPLEMENTATION_VERSION,
        "contract_sha256": recovery_manifest.get("contract_sha256")
        == recovery.FROZEN_CONTRACT_SHA256,
        "resumed_checkpoint": production.get("resumed_checkpoint") is True,
        "checkpoint_bytes": checkpoint_path.stat().st_size
        == FROZEN_CHECKPOINT_BYTES,
        "checkpoint_sha256": _sha256_file(checkpoint_path)
        == FROZEN_CHECKPOINT_SHA256,
        "checkpoint_state_sha256": checkpoint.state_sha256
        == FROZEN_CHECKPOINT_STATE_SHA256,
        "derivation_levels_checkpointed": sum(
            len({item[0] for item in tree}) for tree in checkpoint.derivations
        )
        == FROZEN_DERIVATION_LEVELS_CHECKPOINTED,
        "derivations_checkpointed": sum(
            len(tree) for tree in checkpoint.derivations
        )
        == FROZEN_DERIVATIONS_CHECKPOINTED,
        "seed_nodes_checkpointed": sum(len(tree) for tree in checkpoint.nodes)
        == FROZEN_SEED_NODES_CHECKPOINTED,
        "leaf_outputs_checkpointed": sum(
            len(tree) for tree in checkpoint.leaf_outputs
        )
        == FROZEN_LEAF_OUTPUTS_CHECKPOINTED,
        "manifest_checkpoint_state_sha256": production.get(
            "checkpoint_state_sha256"
        )
        == FROZEN_CHECKPOINT_STATE_SHA256,
        "execution_cache_bytes": execution_cache_path.stat().st_size
        == FROZEN_EXECUTION_CACHE_BYTES,
        "execution_cache_sha256": _sha256_file(execution_cache_path)
        == FROZEN_EXECUTION_CACHE_SHA256,
        "manifest_execution_cache_sha256": production.get(
            "execution_cache_sha256"
        )
        == FROZEN_EXECUTION_CACHE_SHA256,
        "execution_sha256": recovery.execution_sha256(execution)
        == FROZEN_EXECUTION_SHA256,
        "execution_cache_identity": not execution_failures,
        "tree_shapes": [
            [tree.leaves, tree.extension_degree]
            for tree in execution.tree_polynomials
        ]
        == _tree_shapes(),
        "xof_calls": len(execution.xof_calls) == FROZEN_XOF_CALLS,
        "xof_trace_bytes": trace_bytes == FROZEN_XOF_TRACE_BYTES,
        "xof_trace_sha256": trace_sha256 == composer.FROZEN_XOF_TRACE_SHA256,
        "commitment_bytes": len(execution.commitment.encoded) == 5_391,
        "commitment_sha256": commitment_sha256
        == composer.FROZEN_COMMITMENT_SHA256,
        "composition_manifest_bytes": composition_manifest_path.stat().st_size
        == FROZEN_COMPOSITION_MANIFEST_BYTES,
        "composition_document_sha256": _sha256_file(composition_manifest_path)
        == composer.FROZEN_DOCUMENT_SHA256,
        "manifest_document_sha256": production.get("composition_document_sha256")
        == composer.FROZEN_DOCUMENT_SHA256,
        "composition_mutations": len(composition_document.get("mutation_probes", []))
        == 5
        and all(
            item.get("rejected") is True
            for item in composition_document.get("mutation_probes", [])
        ),
        "cache_claim": claims.get("production_execution_cache_regenerated")
        is True,
        "global_tail_claim": claims.get(
            "production_global_tail_archive_regenerated"
        )
        is False,
        "tree2_claim": claims.get(
            "production_tree2_rebased_assignment_materialized"
        )
        is False,
        "production_claim": claims.get("production_closed") is False,
    }
    failed = [name for name, accepted in exact_checks.items() if not accepted]
    if failed:
        raise ValueError("production recovery evidence rejected: " + ",".join(failed))
    return build_frozen_evidence_document()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--recovery-manifest", type=Path)
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--execution-cache", type=Path)
    parser.add_argument("--composition-manifest", type=Path)
    parser.add_argument("--verify-frozen", type=Path)
    args = parser.parse_args()

    if args.verify_frozen is not None:
        failures = verify_frozen_evidence(args.verify_frozen)
        if failures:
            raise SystemExit("frozen recovery evidence rejected: " + ",".join(failures))
        print("frozen production recovery evidence accepted")
        return

    required = (
        args.manifest,
        args.recovery_manifest,
        args.checkpoint,
        args.execution_cache,
        args.composition_manifest,
    )
    if not all(item is not None for item in required):
        parser.error(
            "--manifest, --recovery-manifest, --checkpoint, --execution-cache, "
            "and --composition-manifest are required"
        )
    document = build_evidence_from_artifacts(
        args.recovery_manifest,
        args.checkpoint,
        args.execution_cache,
        args.composition_manifest,
    )
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_bytes(canonical_json(document))
    print(hashlib.sha256(args.manifest.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
