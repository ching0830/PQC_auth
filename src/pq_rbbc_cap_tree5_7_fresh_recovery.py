#!/usr/bin/env python3
"""Seal a fresh tree-5 through tree-7 rebuild with normalized performance."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_tree5_7_batch_recovery_evidence as historical


FORMAT = "PQRBBC-CAP-TREE5-7-FRESH-RECOVERY-1"
IMPLEMENTATION_VERSION = "2.26"
RELATION_ID = "pq-rbbc/cap/production-tree5-7-fresh-recovery/v1"
TARGETS = (5, 6, 7)
PERFORMANCE_FIELDS = ("generation_seconds", "verification_seconds", "peak_rss_kib")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(document: Mapping[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _tree_evidence(root: Path, tree_index: int) -> dict[str, object]:
    directory = root / f"production_tree{tree_index}_v2_25_batch_planned"
    archive = directory / f"pq_rbbc_production_tree_{tree_index}_producer_v2_25_batch_planned.f193assign"
    manifest = directory / f"pq_rbbc_cap_planned_tree{tree_index}_replayed_manifest_v2_25.json"
    document = json.loads(manifest.read_text(encoding="utf-8"))
    replay = document.get("production_replay")
    frozen = historical.FROZEN_TREES[tree_index]
    if not isinstance(replay, dict):
        raise ValueError(f"tree{tree_index}: replay missing")
    checks = {
        "archive_bytes": archive.stat().st_size == historical.FROZEN_ARCHIVE_BYTES,
        "archive_sha256": _sha256(archive) == frozen["archive_sha256"],
        "contract_sha256": document.get("contract_sha256") == frozen["contract_sha256"],
        "status": replay.get("status") == "complete",
        "rows": replay.get("production_rows_replayed_at_planned_offset") == historical.FROZEN_ROWS,
        "stream_bytes": replay.get("planned_row_stream_bytes") == historical.FROZEN_STREAM_BYTES,
        "stream_sha256": replay.get("planned_row_stream_sha256") == frozen["stream_sha256"],
        "body_sha256": replay.get("planned_assignment_body_sha256") == frozen["body_sha256"],
        "component_sha256": replay.get("tree_component_sha256") == frozen["tree_component_sha256"],
        "failures": replay.get("verification_failures") == 0 and replay.get("external_assertions") == 0,
        "probes": replay.get("stale_witness_probes") == 6 and replay.get("point_mutation_probes") == 3,
        "outputs": isinstance(replay.get("output_matches"), list) and len(replay["output_matches"]) == 4 and all(item.get("exact_value_match") is True for item in replay["output_matches"]),
    }
    if not all(checks.values()):
        raise ValueError(f"tree{tree_index}: " + ",".join(key for key, value in checks.items() if not value))
    return {
        "tree_index": tree_index,
        "historical_replay_manifest_sha256": frozen["replayed_manifest_sha256"],
        "fresh_replay_manifest_sha256": _sha256(manifest),
        "contract_sha256": frozen["contract_sha256"],
        "assignment_sha256": frozen["archive_sha256"],
        "assignment_body_sha256": frozen["body_sha256"],
        "row_stream_bytes": historical.FROZEN_STREAM_BYTES,
        "row_stream_sha256": frozen["stream_sha256"],
        "tree_component_sha256": frozen["tree_component_sha256"],
        "rows": historical.FROZEN_ROWS,
        "outputs_exact": 4,
        "stale_witness_rejections": 6,
        "point_mutation_rejections": 3,
        "environment_measurements": {name: replay.get(name) for name in PERFORMANCE_FIELDS},
    }


def build_evidence(root: Path) -> dict[str, object]:
    trees = [_tree_evidence(root, index) for index in TARGETS]
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "historical_batch_evidence_sha256": historical.FROZEN_EVIDENCE_SHA256,
        "fresh_tree_batch": trees,
        "artifact_policy": {
            "large_artifacts_tracked_in_git": False,
            "trusted_pickle_cache_tracked_in_git": False,
            "portable_evidence_contains_absolute_paths": False,
        },
        "claim_boundary": {
            "fresh_tree5_7_cryptographic_identities_verified": True,
            "historical_performance_reproduced": False,
            "remaining_planned_tree_producers_materialized": False,
            "all_72_output_relocations_closed": False,
            "complete_18_tree_assignment_replayed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "production_closed": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    evidence = build_evidence(args.batch_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json(evidence))
    print(hashlib.sha256(args.output.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
