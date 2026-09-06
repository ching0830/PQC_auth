#!/usr/bin/env python3
"""Seal path-free PQ-RBBC v2.29 parent-join recovery evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_aggregate_preflight as aggregate_preflight
import pq_rbbc_parent_join_preflight as preflight
import pq_rbbc_parent_join_replay as replay


IMPLEMENTATION_VERSION = "2.29"
FORMAT = "PQRBBC-PARENT-JOIN-RECOVERY-EVIDENCE-1"
RELATION_ID = "pq-rbbc/parent-cap-to-h-rbbc-recovery-evidence/v1"
REPLAY_FORMAT = "PQRBBC-PARENT-JOIN-FULL-REPLAY-1"

# Frozen only after the complete replay finished and the canonical manifest was
# independently read back.  These identities make the sealer fail closed on a
# different replay, input set, or ordered transcript.
FROZEN_REPLAY_MANIFEST_BYTES = 5_685
FROZEN_REPLAY_MANIFEST_SHA256 = (
    "055790dffe51781cff2f2f7893931da5550b9d730bec7ae72927a93f9e352a2a"
)
FROZEN_INPUT_IDENTITY = (
    "b92aa6b78d123173574ad00cb337e12877a9615f56605bddfd66236ca263d11a"
)
FROZEN_TRANSCRIPT_SHA256 = (
    "1f0113f965a03351b6d62c4801a9d15d0255640282b90215397170b87ad6a514"
)

FROZEN_RUNNER = (
    71_551,
    "44ef975427f4f76bfcc2463b0576de4a5a25b9469313b596a92ed4e6c5db7ef8",
)
FROZEN_PREFLIGHT = (
    5_731,
    "4e83d260121df7bc9f73f03a3c427f494577cdcabb8808a9e67a2987d137ab78",
)
FROZEN_PREPARATION = (
    4_539,
    "32f246e13f06e956bb4b39262f41b53d83c2874a646b1f9671381520f1ceb852",
)
FROZEN_GLOBAL_MANIFEST = (
    19_794,
    "90acd448e4365d2486320e58411fb1cf5efef116f60781f879592ea8b3c62113",
)
FROZEN_GLOBAL_ASSIGNMENT = (
    1_004_865_028,
    "18b8abf85f6beb19f03738a1ca8765b3f39d1de12474554b4be633c7b4c5fbac",
)
FROZEN_PARENT_ARCHIVE = (
    72_354_912,
    "579c7215ae58d300675a83edc69164127b04a9784e38f5c58b8dd1b810fac598",
)
FROZEN_PARENT_ASSIGNMENT = (
    74_507_694,
    "7405738de269770a2401130872312a6c0a3cb3175c411c1fc377196fdb94bacf",
)
FROZEN_EXECUTION_SEMANTIC_SHA256 = (
    "69de49f5ad49f37ec461f2b22cd0bdf5293cb727644db5c23070cbd575efe61c"
)
ROOT = Path(__file__).resolve().parents[1]


def canonical_json(document: Mapping[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_identity(path: Path, expected: tuple[int, str], label: str) -> None:
    if not path.is_file():
        raise ValueError(f"{label} is missing")
    if path.stat().st_size != expected[0]:
        raise ValueError(f"{label} byte length mismatch")
    if _sha256(path) != expected[1]:
        raise ValueError(f"{label} SHA-256 mismatch")


def claim_boundary() -> dict[str, bool]:
    return {
        "complete_18_tree_assignment_replayed": True,
        "cross_segment_wire_identity_closed": True,
        "parent_bound_global_tail_replayed": True,
        "gf193_parent_lift_replayed": True,
        "parent_cap_to_h_rbbc_join_closed": True,
        "fork_security_proof_revalidated": False,
        "production_closed": False,
        "system_architecture_changed": False,
        "ticket_lifecycle_changed": False,
        "pq_sat_auth_changed": False,
    }


def reconstruct_input_identity() -> str:
    document = {
        "namespace_sha256": aggregate_preflight.NAMESPACE_SHA256,
        "tree_archives": [
            {
                "tree_index": index,
                "sha256": aggregate_preflight.TREE_ARCHIVES[index][1],
            }
            for index in range(18)
        ],
        "global_archive_sha256": FROZEN_GLOBAL_ASSIGNMENT[1],
        "parent_archive_sha256": FROZEN_PARENT_ARCHIVE[1],
        "parent_assignment_sha256": FROZEN_PARENT_ASSIGNMENT[1],
        "execution_semantic_sha256": FROZEN_EXECUTION_SEMANTIC_SHA256,
        "runner_sha256": FROZEN_RUNNER[1],
    }
    return hashlib.sha256(canonical_json(document)).hexdigest()


def validate_replay_document(document: Mapping[str, object]) -> None:
    if not all(
        (
            FROZEN_REPLAY_MANIFEST_BYTES,
            FROZEN_REPLAY_MANIFEST_SHA256,
            FROZEN_INPUT_IDENTITY,
            FROZEN_TRANSCRIPT_SHA256,
        )
    ):
        raise ValueError("v2.29 replay identities are not frozen")
    if document.get("format") != REPLAY_FORMAT:
        raise ValueError("parent replay format mismatch")
    if document.get("implementation_version") != IMPLEMENTATION_VERSION:
        raise ValueError("parent replay version mismatch")
    if document.get("relation_id") != replay.RELATION_ID:
        raise ValueError("parent replay relation mismatch")
    if document.get("input_identity") != FROZEN_INPUT_IDENTITY:
        raise ValueError("parent replay input identity mismatch")
    if document.get("ordered_replay_transcript_sha256") != FROZEN_TRANSCRIPT_SHA256:
        raise ValueError("parent replay transcript identity mismatch")
    if document.get("tree_order") != list(range(18)):
        raise ValueError("parent replay tree order mismatch")
    trees = document.get("tree_results")
    if not isinstance(trees, list) or len(trees) != 18:
        raise ValueError("parent replay tree results are incomplete")
    for index, item in enumerate(trees):
        rows = 51_325_080 if index < 2 else 25_666_386
        if (
            not isinstance(item, dict)
            or item.get("tree_index") != index
            or item.get("rows") != rows
            or item.get("verification_failures") != 0
        ):
            raise ValueError(f"tree {index} replay result mismatch")
        for name in ("row_stream_sha256", "component_sha256"):
            value = item.get(name)
            if not isinstance(value, str) or len(value) != 64:
                raise ValueError(f"tree {index} {name} is malformed")
    if document.get("producer_rows") != 513_312_336:
        raise ValueError("parent replay producer row accounting mismatch")
    if document.get("relocation_rows") != 15_938_520:
        raise ValueError("parent replay relocation row accounting mismatch")
    tail = document.get("global_tail_result")
    if not isinstance(tail, dict) or tail != {
        "message_sha256": preflight.PARENT_BOUND_MESSAGE_SHA256,
        "request_hash_sha256": preflight.PARENT_BOUND_HASH_IMAGE_SHA256,
        "row_stream_sha256": replay.global_tail.FROZEN_PRODUCTION_STREAM_SHA256,
        "rows": replay.global_tail.FROZEN_PRODUCTION_ROWS,
        "verification_failures": 0,
    }:
        raise ValueError("parent-bound global-tail replay mismatch")
    parent = document.get("parent_join_result")
    if not isinstance(parent, dict) or parent != {
        "archive_body_sha256_verified": True,
        "assignment_body_sha256_verified": True,
        "external_assertions": 0,
        "failed_constraints": 0,
        "first_failure": None,
        "join_rows_checked": replay.JOIN_ROWS,
        "rows_checked": replay.PARENT_JOIN_ROWS,
        "satisfied": True,
    }:
        raise ValueError("joined parent replay mismatch")
    if document.get("aggregate_rows_replayed") != replay.AGGREGATE_ROWS:
        raise ValueError("parent replay aggregate row count mismatch")
    if document.get("combined_rows_replayed") != replay.COMBINED_ROWS:
        raise ValueError("parent replay combined row count mismatch")
    if document.get("verification_failures") != 0:
        raise ValueError("parent replay contains verification failures")
    if document.get("external_assertions") != 0:
        raise ValueError("parent replay contains external assertions")
    transcript = {
        "tree_results": trees,
        "relocation_rows": document["relocation_rows"],
        "global_tail_result": tail,
        "parent_join_result": parent,
    }
    if hashlib.sha256(canonical_json(transcript)).hexdigest() != FROZEN_TRANSCRIPT_SHA256:
        raise ValueError("parent replay transcript does not reconstruct")
    if document.get("claim_boundary") != claim_boundary():
        raise ValueError("parent replay claim boundary mismatch")


def seal(
    replay_manifest: Path,
    preflight_manifest: Path,
    preparation_manifest: Path,
    global_manifest: Path,
    global_assignment: Path,
    parent_archive: Path,
    parent_assignment: Path,
    namespace_manifest: Path,
    tree_archives: Mapping[int, Path],
) -> dict[str, object]:
    if sorted(tree_archives) != list(range(18)):
        raise ValueError("exactly tree archives 0 through 17 are required")
    if reconstruct_input_identity() != FROZEN_INPUT_IDENTITY:
        raise ValueError("v2.29 frozen input identity does not reconstruct")
    for path, expected, label in (
        (replay_manifest, (FROZEN_REPLAY_MANIFEST_BYTES, FROZEN_REPLAY_MANIFEST_SHA256), "replay manifest"),
        (preflight_manifest, FROZEN_PREFLIGHT, "preflight manifest"),
        (preparation_manifest, FROZEN_PREPARATION, "preparation manifest"),
        (global_manifest, FROZEN_GLOBAL_MANIFEST, "global-tail manifest"),
        (global_assignment, FROZEN_GLOBAL_ASSIGNMENT, "global-tail assignment"),
        (parent_archive, FROZEN_PARENT_ARCHIVE, "joined parent archive"),
        (parent_assignment, FROZEN_PARENT_ASSIGNMENT, "joined parent assignment"),
        (namespace_manifest, (aggregate_preflight.NAMESPACE_BYTES, aggregate_preflight.NAMESPACE_SHA256), "namespace manifest"),
        (ROOT / preflight.PARENT_RUNNER, FROZEN_RUNNER, "parent join runner"),
    ):
        _require_identity(path, expected, label)
    for index, path in tree_archives.items():
        _require_identity(path, aggregate_preflight.TREE_ARCHIVES[index], f"tree {index} assignment")
    replay_document = json.loads(replay_manifest.read_text())
    validate_replay_document(replay_document)
    if json.loads(preflight_manifest.read_text()) != preflight.build_frozen_manifest():
        raise ValueError("v2.29 frozen preflight content mismatch")
    preparation = json.loads(preparation_manifest.read_text())
    if (
        preparation.get("claim_boundary", {}).get(
            "parent_bound_external_artifacts_verified"
        )
        is not True
        or preparation.get("parent", {}).get("mutation_probes", {}).get(
            "all_required_mutations_rejected"
        )
        is not True
    ):
        raise ValueError("v2.29 preparation gates are incomplete")
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "source_identities": {
            "replay_manifest": {
                "bytes": FROZEN_REPLAY_MANIFEST_BYTES,
                "sha256": FROZEN_REPLAY_MANIFEST_SHA256,
            },
            "preflight_manifest": {
                "bytes": FROZEN_PREFLIGHT[0],
                "sha256": FROZEN_PREFLIGHT[1],
            },
            "preparation_manifest": {
                "bytes": FROZEN_PREPARATION[0],
                "sha256": FROZEN_PREPARATION[1],
            },
            "parent_bound_global_tail_manifest": {
                "bytes": FROZEN_GLOBAL_MANIFEST[0],
                "sha256": FROZEN_GLOBAL_MANIFEST[1],
            },
            "parent_bound_global_tail_assignment": {
                "bytes": FROZEN_GLOBAL_ASSIGNMENT[0],
                "sha256": FROZEN_GLOBAL_ASSIGNMENT[1],
            },
            "joined_parent_archive": {
                "bytes": FROZEN_PARENT_ARCHIVE[0],
                "sha256": FROZEN_PARENT_ARCHIVE[1],
            },
            "joined_parent_assignment": {
                "bytes": FROZEN_PARENT_ASSIGNMENT[0],
                "sha256": FROZEN_PARENT_ASSIGNMENT[1],
            },
            "parent_join_runner": {
                "bytes": FROZEN_RUNNER[0],
                "sha256": FROZEN_RUNNER[1],
            },
            "namespace_manifest": {
                "bytes": aggregate_preflight.NAMESPACE_BYTES,
                "sha256": aggregate_preflight.NAMESPACE_SHA256,
                "plan_sha256": aggregate_preflight.NAMESPACE_PLAN_SHA256,
            },
            "tree_assignments": [
                {
                    "tree_index": index,
                    "bytes": aggregate_preflight.TREE_ARCHIVES[index][0],
                    "sha256": aggregate_preflight.TREE_ARCHIVES[index][1],
                }
                for index in range(18)
            ],
            "trusted_composer_execution_semantic_sha256": FROZEN_EXECUTION_SEMANTIC_SHA256,
        },
        "binding": {
            "message_sha256": preflight.PARENT_BOUND_MESSAGE_SHA256,
            "commitment_sha256": preflight.CAP_COMMITMENT_SHA256,
            "derived_mask_sha256": preflight.PARENT_BOUND_MASK_SHA256,
            "h_rbbc_hash_image_sha256": preflight.PARENT_BOUND_HASH_IMAGE_SHA256,
            "public_y_sha256": preflight.PARENT_BOUND_PUBLIC_Y_SHA256,
        },
        "accounting": {
            "producer_rows": 513_312_336,
            "relocation_rows": 15_938_520,
            "global_tail_rows": replay.global_tail.FROZEN_PRODUCTION_ROWS,
            "aggregate_rows": replay.AGGREGATE_ROWS,
            "parent_internal_rows": replay.PARENT_INTERNAL_ROWS,
            "native_join_rows": replay.JOIN_ROWS,
            "parent_join_rows": replay.PARENT_JOIN_ROWS,
            "combined_rows": replay.COMBINED_ROWS,
            "parent_wire_interval": [replay.PARENT_WIRE_START, replay.PARENT_WIRE_END],
            "verification_failures": 0,
            "external_assertions": 0,
            "ordered_replay_transcript_sha256": FROZEN_TRANSCRIPT_SHA256,
        },
        "mutation_gates": preparation["parent"]["mutation_probes"],
        "artifact_policy": {
            "large_artifacts_tracked_in_git": False,
            "br1cs_or_assignment_tracked_in_git": False,
            "trusted_pickle_cache_tracked_in_git": False,
            "checkpoint_or_resume_state_tracked_in_git": False,
            "logs_tracked_in_git": False,
            "portable_evidence_contains_absolute_paths": False,
        },
        "claim_boundary": claim_boundary(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay-manifest", type=Path, required=True)
    parser.add_argument("--preflight-manifest", type=Path, required=True)
    parser.add_argument("--preparation-manifest", type=Path, required=True)
    parser.add_argument("--global-manifest", type=Path, required=True)
    parser.add_argument("--global-assignment", type=Path, required=True)
    parser.add_argument("--parent-archive", type=Path, required=True)
    parser.add_argument("--parent-assignment", type=Path, required=True)
    parser.add_argument("--namespace-manifest", type=Path, required=True)
    parser.add_argument("--tree-archive", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    trees = aggregate_preflight.parse_tree_archives(args.tree_archive)
    document = seal(
        args.replay_manifest,
        args.preflight_manifest,
        args.preparation_manifest,
        args.global_manifest,
        args.global_assignment,
        args.parent_archive,
        args.parent_assignment,
        args.namespace_manifest,
        trees,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json(document))
    print(_sha256(args.output))


if __name__ == "__main__":
    main()
