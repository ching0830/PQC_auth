#!/usr/bin/env python3
"""Seal path-free bounded recovery evidence for PQ-RBBC v2.26 trees 8--10."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EXPECTED = {
    8: {
        "manifest": "6e7f4df14772370727940b9367430a8ad37d3eaa4e29a97f174133922c8e69cc",
        "contract": "15277b5065ef5b97dc7919306c3c1044826b98adee3a92f12be9cde5f9623c99",
        "archive": "bf3c1f6ef1fa34b3d5cb9e11d85e65b33a3dbe80c926cf2cd86be291d19c884c",
        "body": "c75cf3f463e3de983b3ffa328d5800d587636b775d2a7b499686bbfe64029e90",
        "stream_bytes": 8_961_160_824,
        "stream": "c6f593afc2afe6393800c26f27203cbc4e1bb3e83cfe57c2ac6cc812553285af",
        "component": "c0037cfb5a06379b463d8430e4b8ffbd114db452814283d2330a3cd57357075b",
    },
    9: {
        "manifest": "f82ce1c1733d30e9c49e69551eeee80698230f01f4857b868764ff51d8f8b806",
        "contract": "cd9c33b29af5472856219bde2541d4029cc747692202463012bae9000f622e34",
        "archive": "6233e0639bfd09b93bfb1967f5a696fad09eadc7ca5e4f2c9df4fc804a015f19",
        "body": "984c0b31481e4d45188e04dae8696fc85feed2c7cb0547bb579c9a17a5fd27e1",
        "stream_bytes": 8_961_160_824,
        "stream": "b8e22f80732b78d8b0a0b02957b91c1b746cb26efe10a4e9d5302e0c8d8960fd",
        "component": "fab97914348c255bed04debc578cd8c9d27ab73d92744c0d5f24aaf5ec4409b0",
    },
    10: {
        "manifest": "8c56f7c426ad1f632af36c0d4e40536ff5726a5875734d7014d0b9c429fb067d",
        "contract": "011d3c249a7d60232074a7f0eb78b34618b097ffcd1c852040fd888263f6e554",
        "archive": "23ad60862f387387aba139a8465891f7ada0fe4da5be8a318177217094c39bd8",
        "body": "7fb1336c70643771f7b98ac4e44ba65f49077aae527c9c90e51a5b5eb80658ed",
        "stream_bytes": 8_986_785_870,
        "stream": "44cf5ff0cdf222d58f1522e06afadccf3ad377ce4893575d1ef8f8317a2f3ba2",
        "component": "0378694c05c5236207cdb5d9c148e75f4d9ab5245787523d9de8739577bc8d89",
    },
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def seal(paths: list[Path]) -> dict[str, object]:
    if len(paths) != 3:
        raise ValueError("exactly three frozen manifests are required")
    trees = []
    for path in paths:
        document = json.loads(path.read_text())
        contract = document["contract"]
        replay = document["production_replay"]
        index = contract["tree_index"]
        expected = EXPECTED.get(index)
        exact = expected is not None and all((
            _sha256(path) == expected["manifest"],
            document["contract_sha256"] == expected["contract"],
            replay["planned_assignment_sha256"] == expected["archive"],
            replay["planned_assignment_body_sha256"] == expected["body"],
            replay["planned_row_stream_bytes"] == expected["stream_bytes"],
            replay["planned_row_stream_sha256"] == expected["stream"],
            replay["tree_component_sha256"] == expected["component"],
            replay["status"] == "complete",
            replay["verification_failures"] == 0,
            replay["external_assertions"] == 0,
            replay["resumed_execution_cache_this_run"] is False,
            len(replay["output_matches"]) == 4,
            all(item["exact_value_match"] for item in replay["output_matches"]),
            replay["stale_witness_probes"] == 6,
            replay["point_mutation_probes"] == 3,
            document["claim_boundary"][f"production_tree{index}_planned_assignment_materialized"] is True,
            document["claim_boundary"][f"production_tree{index}_planned_full_replay_closed"] is True,
            document["claim_boundary"]["production_closed"] is False,
        ))
        if not exact:
            raise ValueError(f"tree {index} frozen evidence rejected")
        trees.append({
            "tree_index": index,
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
            "frozen_manifest_sha256": expected["manifest"],
        })
    if [item["tree_index"] for item in trees] != [8, 9, 10]:
        raise ValueError("tree manifests must be ordered 8, 9, 10")
    return {
        "format": "PQRBBC-CAP-TREE8-10-BOUNDED-RECOVERY-EVIDENCE-1",
        "implementation_version": "2.26",
        "relation_id": "pq-rbbc/cap/production-tree8-10-bounded-recovery-evidence/v1",
        "prior_tree5_7_batch_evidence": {
            "sha256": "0041ea819434e0099d419757fa217fcfa30b810ef391b4a4603d8aee7ad06c72",
            "implementation_version": "2.25",
        },
        "production_tree_batch": trees,
        "artifact_policy": {
            "large_artifacts_tracked_in_git": False,
            "trusted_pickle_cache_tracked_in_git": False,
            "resume_state_tracked_in_git": False,
            "portable_evidence_contains_absolute_paths": False,
        },
        "claim_boundary": {
            "materialized_planned_tree_count": 11,
            "materialized_planned_tree_indices": list(range(11)),
            "remaining_planned_tree_producers_materialized": False,
            "all_72_output_relocations_closed": False,
            "complete_18_tree_assignment_replayed": False,
            "cross_segment_wire_identity_closed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
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
