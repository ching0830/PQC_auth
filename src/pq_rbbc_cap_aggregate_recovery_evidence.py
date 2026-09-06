#!/usr/bin/env python3
"""Seal path-free PQ-RBBC v2.28 aggregate replay recovery evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_aggregate_preflight as preflight


IMPLEMENTATION_VERSION = "2.28"
FORMAT = "PQRBBC-CAP-AGGREGATE-RECOVERY-EVIDENCE-1"
RELATION_ID = "pq-rbbc/cap/production-aggregate-recovery-evidence/v1"
REPLAY_FORMAT = "PQRBBC-CAP-AGGREGATE-REPLAY-1"
REPLAY_RELATION_ID = "pq-rbbc/cap/production-aggregate-replay/v1"
FROZEN_REPLAY_MANIFEST_BYTES = 5_120
FROZEN_REPLAY_MANIFEST_SHA256 = (
    "495e528901f8f79247861d9da24bc5019a6b938880c5ea6172cda323339c8804"
)
FROZEN_INPUT_IDENTITY = (
    "b26d5e62c75c3d4bf142dc87421b8b8f3d9d3a53c69d89a48a6a3daae9aa6782"
)
FROZEN_TRANSCRIPT_SHA256 = (
    "4cc7215db0d009c26bf3bc8576a984f3bb884528855a8084305ffd0499b7e134"
)
FROZEN_RUNNER_SHA256 = (
    "8b7e28ce1afa9040360bf40b75b5a713b14c122626a7c8e623b502a9efac468b"
)
FROZEN_PREFLIGHT_MANIFEST_SHA256 = (
    "c82b435527efe1d343cc6499b408e53f570bcfa47905597afcae890c6125b915"
)
FROZEN_EXECUTION_SEMANTIC_SHA256 = (
    "69de49f5ad49f37ec461f2b22cd0bdf5293cb727644db5c23070cbd575efe61c"
)
PLANNED_ROWS = 586_057_567
PRODUCER_ROWS = 513_312_336
RELOCATION_ROWS = 15_938_520
GLOBAL_TAIL_ROWS = 56_806_711
GLOBAL_TAIL_STREAM_SHA256 = (
    "c368d41de9e57910803e98284a4ec0a0f45862fa80f3d070a50477f82627c9df"
)
ROOT = Path(__file__).resolve().parents[1]


def canonical_json(document: Mapping[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
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
        "aggregate_archive_identity_precheck_closed": True,
        "aggregate_72_link_value_precheck_closed": True,
        "complete_18_tree_assignment_replayed": True,
        "cross_segment_wire_identity_closed": True,
        "parent_cap_to_h_rbbc_join_closed": False,
        "fork_security_proof_revalidated": False,
        "production_closed": False,
    }


def reconstruct_input_identity() -> str:
    archive_document = {
        "global_archive_sha256": preflight.GLOBAL_ARCHIVE[1],
        "tree_archives": [
            {"tree_index": tree_index, "sha256": preflight.TREE_ARCHIVES[tree_index][1]}
            for tree_index in range(18)
        ],
        "namespace_plan_sha256": preflight.NAMESPACE_PLAN_SHA256,
    }
    archive_identity = hashlib.sha256(canonical_json(archive_document)).hexdigest()
    return hashlib.sha256(canonical_json({
        "archive_identity": archive_identity,
        "runner_sha256": FROZEN_RUNNER_SHA256,
        "execution_semantic_identity": FROZEN_EXECUTION_SEMANTIC_SHA256,
    })).hexdigest()


def validate_replay_document(document: Mapping[str, object]) -> None:
    if document.get("format") != REPLAY_FORMAT:
        raise ValueError("aggregate replay format mismatch")
    if document.get("implementation_version") != IMPLEMENTATION_VERSION:
        raise ValueError("aggregate replay implementation version mismatch")
    if document.get("relation_id") != REPLAY_RELATION_ID:
        raise ValueError("aggregate replay relation mismatch")
    if document.get("input_identity") != FROZEN_INPUT_IDENTITY:
        raise ValueError("aggregate replay input identity mismatch")
    if document.get("ordered_replay_transcript_sha256") != FROZEN_TRANSCRIPT_SHA256:
        raise ValueError("aggregate replay transcript identity mismatch")
    if document.get("tree_order") != list(range(18)):
        raise ValueError("aggregate replay tree order mismatch")
    trees = document.get("tree_results")
    if not isinstance(trees, list) or len(trees) != 18:
        raise ValueError("aggregate replay tree results are incomplete")
    for tree_index, item in enumerate(trees):
        expected_rows = 51_325_080 if tree_index < 2 else 25_666_386
        if not isinstance(item, dict) or item.get("tree_index") != tree_index:
            raise ValueError("aggregate replay tree result order mismatch")
        if item.get("rows") != expected_rows:
            raise ValueError(f"tree {tree_index} replay row count mismatch")
        if item.get("verification_failures") != 0:
            raise ValueError(f"tree {tree_index} replay has failures")
        for name in ("row_stream_sha256", "component_sha256"):
            value = item.get(name)
            if not isinstance(value, str) or len(value) != 64:
                raise ValueError(f"tree {tree_index} {name} is malformed")
    if sum(item["rows"] for item in trees) != PRODUCER_ROWS:
        raise ValueError("aggregate producer row accounting mismatch")
    if document.get("relocation_rows") != RELOCATION_ROWS:
        raise ValueError("aggregate relocation row accounting mismatch")
    tail = document.get("global_tail_result")
    if not isinstance(tail, dict) or tail != {
        "row_stream_sha256": GLOBAL_TAIL_STREAM_SHA256,
        "rows": GLOBAL_TAIL_ROWS,
        "verification_failures": 0,
    }:
        raise ValueError("aggregate global-tail replay mismatch")
    if document.get("rows_replayed") != PLANNED_ROWS:
        raise ValueError("aggregate planned row count mismatch")
    if document.get("verification_failures") != 0:
        raise ValueError("aggregate replay has verification failures")
    transcript = {
        "tree_row_streams": trees,
        "relocation_rows": RELOCATION_ROWS,
        "global_tail_result": tail,
    }
    if hashlib.sha256(canonical_json(transcript)).hexdigest() != FROZEN_TRANSCRIPT_SHA256:
        raise ValueError("aggregate replay transcript does not reconstruct")
    if document.get("claim_boundary") != claim_boundary():
        raise ValueError("aggregate replay claim boundary mismatch")


def seal(
    replay_manifest: Path,
    namespace_manifest: Path,
    preflight_manifest: Path,
    prior_evidence: Path,
    global_archive: Path,
    incremental_br1cs: Path,
    tree_archives: dict[int, Path],
) -> dict[str, object]:
    if sorted(tree_archives) != list(range(18)):
        raise ValueError("exactly tree archives 0 through 17 are required")
    if reconstruct_input_identity() != FROZEN_INPUT_IDENTITY:
        raise ValueError("frozen aggregate input identity does not reconstruct")
    _require_identity(
        replay_manifest,
        (FROZEN_REPLAY_MANIFEST_BYTES, FROZEN_REPLAY_MANIFEST_SHA256),
        "aggregate replay manifest",
    )
    _require_identity(
        namespace_manifest,
        (preflight.NAMESPACE_BYTES, preflight.NAMESPACE_SHA256),
        "namespace manifest",
    )
    _require_identity(
        preflight_manifest,
        (preflight_manifest.stat().st_size, FROZEN_PREFLIGHT_MANIFEST_SHA256),
        "aggregate preflight manifest",
    )
    _require_identity(
        prior_evidence,
        (preflight.PRIOR_EVIDENCE_BYTES, preflight.PRIOR_EVIDENCE_SHA256),
        "prior tree11-17 evidence",
    )
    _require_identity(global_archive, preflight.GLOBAL_ARCHIVE, "global-tail archive")
    _require_identity(
        incremental_br1cs, preflight.INCREMENTAL_BR1CS, "incremental BR1CS"
    )
    _require_identity(
        ROOT / preflight.AGGREGATE_RUNNER,
        ((ROOT / preflight.AGGREGATE_RUNNER).stat().st_size, FROZEN_RUNNER_SHA256),
        "aggregate runner",
    )
    for tree_index, path in tree_archives.items():
        _require_identity(
            path, preflight.TREE_ARCHIVES[tree_index], f"tree {tree_index} archive"
        )
    replay = json.loads(replay_manifest.read_text())
    validate_replay_document(replay)
    frozen_preflight = json.loads(preflight_manifest.read_text())
    if frozen_preflight != preflight.build_frozen_manifest():
        raise ValueError("aggregate preflight manifest content mismatch")
    trees = [dict(item) for item in replay["tree_results"]]
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "source_identities": {
            "aggregate_replay_manifest": {
                "bytes": FROZEN_REPLAY_MANIFEST_BYTES,
                "sha256": FROZEN_REPLAY_MANIFEST_SHA256,
            },
            "aggregate_preflight_manifest": {
                "sha256": FROZEN_PREFLIGHT_MANIFEST_SHA256,
            },
            "aggregate_runner": {"sha256": FROZEN_RUNNER_SHA256},
            "namespace_manifest": {
                "bytes": preflight.NAMESPACE_BYTES,
                "sha256": preflight.NAMESPACE_SHA256,
                "plan_sha256": preflight.NAMESPACE_PLAN_SHA256,
            },
            "prior_tree11_17_evidence": {
                "bytes": preflight.PRIOR_EVIDENCE_BYTES,
                "sha256": preflight.PRIOR_EVIDENCE_SHA256,
            },
            "global_tail_assignment": {
                "bytes": preflight.GLOBAL_ARCHIVE[0],
                "sha256": preflight.GLOBAL_ARCHIVE[1],
            },
            "incremental_br1cs": {
                "bytes": preflight.INCREMENTAL_BR1CS[0],
                "sha256": preflight.INCREMENTAL_BR1CS[1],
            },
            "tree_assignments": [
                {
                    "tree_index": tree_index,
                    "bytes": preflight.TREE_ARCHIVES[tree_index][0],
                    "sha256": preflight.TREE_ARCHIVES[tree_index][1],
                }
                for tree_index in range(18)
            ],
            "trusted_composer_execution_semantic_sha256": (
                FROZEN_EXECUTION_SEMANTIC_SHA256
            ),
        },
        "aggregate_replay": {
            "input_identity": FROZEN_INPUT_IDENTITY,
            "tree_order": list(range(18)),
            "tree_results": trees,
            "producer_rows": PRODUCER_ROWS,
            "relocation_rows": RELOCATION_ROWS,
            "global_tail_rows": GLOBAL_TAIL_ROWS,
            "rows_replayed": PLANNED_ROWS,
            "verification_failures": 0,
            "ordered_replay_transcript_sha256": FROZEN_TRANSCRIPT_SHA256,
        },
        "artifact_policy": {
            "large_artifacts_tracked_in_git": False,
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
    parser.add_argument("--namespace-manifest", type=Path, required=True)
    parser.add_argument("--preflight-manifest", type=Path, required=True)
    parser.add_argument("--prior-evidence", type=Path, required=True)
    parser.add_argument("--global-archive", type=Path, required=True)
    parser.add_argument("--incremental-br1cs", type=Path, required=True)
    parser.add_argument("--tree-archive", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    trees = preflight.parse_tree_archives(args.tree_archive)
    evidence = seal(
        args.replay_manifest,
        args.namespace_manifest,
        args.preflight_manifest,
        args.prior_evidence,
        args.global_archive,
        args.incremental_br1cs,
        trees,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json(evidence))
    print(_sha256(args.output))


if __name__ == "__main__":
    main()
