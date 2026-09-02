#!/usr/bin/env python3
"""Seal path-free bounded recovery evidence for PQ-RBBC v2.27 trees 11--17."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EXPECTED_MANIFESTS = {
    11: "f83b52916da3c2bf0448ade8e859fca0a50284dfd1b9a4684d33c65eb15bda59",
    12: "a4142a567841c6e824cf913ad3b064e9a05db4ca02df6a2485e3dab4f4ecf93b",
    13: "23000f9dbee82a6e8e810c2b03ac87b40038f6cf83e8d55220cf4c2ce9e4513a",
    14: "80382bf0d2a001630fb4167f24a393a094b4515db44a61c6e54032e066a1ef26",
    15: "0315e90986ecce28d3cad15e110ff1d8f9c05f5d5ac0f926a0037422a952b1d5",
    16: "9ee5f95d9c9f215238935c30eaea457edc7af93d43c52099caf33f76c7b698df",
    17: "4ae463d07bc05cbbdaf045c6a64bb4fc9b6f4f860440542ad7f4f35c38d8f251",
}
PRIOR_EVIDENCE_SHA256 = "9a8ad3b2b5af242ef6ee6b33d99035505c1b8a5764d84766ce6d44f9cd00895f"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def claim_boundary() -> dict[str, object]:
    return {
        "materialized_planned_tree_count": 18,
        "materialized_planned_tree_indices": list(range(18)),
        "remaining_planned_tree_producers_materialized": True,
        "all_72_output_relocations_closed": True,
        "complete_18_tree_assignment_replayed": False,
        "cross_segment_wire_identity_closed": False,
        "parent_cap_to_h_rbbc_join_closed": False,
        "fork_security_proof_revalidated": False,
        "production_closed": False,
    }


def seal(paths: list[Path]) -> dict[str, object]:
    if len(paths) != 7:
        raise ValueError("exactly seven frozen manifests are required")
    trees = []
    for path in paths:
        document = json.loads(path.read_text())
        contract = document["contract"]
        replay = document["production_replay"]
        boundary = document["claim_boundary"]
        tree_index = contract["tree_index"]
        exact = all((
            tree_index in EXPECTED_MANIFESTS,
            _sha256(path) == EXPECTED_MANIFESTS.get(tree_index),
            replay["status"] == "complete",
            replay["verification_failures"] == 0,
            replay["external_assertions"] == 0,
            replay["resumed_execution_cache_this_run"] is False,
            len(replay["output_matches"]) == 4,
            all(item["exact_value_match"] for item in replay["output_matches"]),
            replay["stale_witness_probes"] == 6,
            replay["point_mutation_probes"] == 3,
            not document["contract_validation_failures"],
            all(item["rejected"] for item in document["configuration_mutation_probes"]),
            boundary[f"production_tree{tree_index}_planned_assignment_materialized"] is True,
            boundary[f"production_tree{tree_index}_planned_full_replay_closed"] is True,
            boundary["production_closed"] is False,
        ))
        if not exact:
            raise ValueError(f"tree {tree_index} frozen evidence rejected")
        trees.append({
            "tree_index": tree_index,
            "contract_sha256": document["contract_sha256"],
            "planned_local_wire_start": contract["planned_local_wire_start"],
            "planned_max_wire_id": contract["planned_max_wire_id"],
            "planned_output_wire_starts": contract["planned_output_wire_starts"],
            "archive_bytes": replay["planned_assignment_bytes"],
            "archive_sha256": replay["planned_assignment_sha256"],
            "body_sha256": replay["planned_assignment_body_sha256"],
            "row_stream_bytes": replay["planned_row_stream_bytes"],
            "row_stream_sha256": replay["planned_row_stream_sha256"],
            "tree_component_sha256": replay["tree_component_sha256"],
            "rows": replay["production_rows_replayed_at_planned_offset"],
            "output_matches": replay["output_matches"],
            "stale_witness_probes": 6,
            "point_mutation_probes": 3,
            "replay_failures": 0,
            "external_assertions": 0,
            "fresh_cache_replay": True,
            "frozen_manifest_sha256": EXPECTED_MANIFESTS[tree_index],
        })
    if [tree["tree_index"] for tree in trees] != list(range(11, 18)):
        raise ValueError("tree manifests must be ordered 11 through 17")
    return {
        "format": "PQRBBC-CAP-TREE11-17-BOUNDED-RECOVERY-EVIDENCE-1",
        "implementation_version": "2.27",
        "relation_id": "pq-rbbc/cap/production-tree11-17-bounded-recovery-evidence/v1",
        "prior_tree8_10_bounded_evidence": {
            "sha256": PRIOR_EVIDENCE_SHA256,
            "implementation_version": "2.26",
        },
        "production_tree_batch": trees,
        "artifact_policy": {
            "large_artifacts_tracked_in_git": False,
            "trusted_pickle_cache_tracked_in_git": False,
            "resume_state_tracked_in_git": False,
            "portable_evidence_contains_absolute_paths": False,
        },
        "claim_boundary": claim_boundary(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    evidence = seal(args.manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n")
    print(_sha256(args.output))


if __name__ == "__main__":
    main()
