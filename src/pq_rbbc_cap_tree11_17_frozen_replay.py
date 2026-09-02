#!/usr/bin/env python3
"""Fresh-cache frozen replay for the bounded PQ-RBBC tree 11--17 batch."""

from __future__ import annotations

import argparse
import hashlib
from dataclasses import replace
from pathlib import Path

import pq_rbbc_cap_planned_tree_producer as planned


EXPECTED = {
    11: {
        "stream_bytes": 8_986_785_870,
        "contract": "c01f26fafb0e69b70390163d9ffd7e42603a1ba52584b9b930773b5edce65298",
        "archive": "14be7745a0fe479bbc31b6ee4599ed9ad63a3d6ae108cf73ca885fc7e63c423d",
        "body": "c5a68b12866b9f030b0cf25dcf48d0a14bfc3649391eb3834cb74a85bd28e9b6",
        "stream": "d4911dcf5167768ff9f67d12b6e3552a77ea8f83f2ef23c4b344c0f33e1a1b26",
        "component": "82f59ed653e05aa2212bc30c34ae86e5faf6cacca82fed7d337d736d10aaf042",
    },
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def frozen_contract(tree_index: int) -> planned.PlannedTreeContract:
    expected = EXPECTED[tree_index]
    contract = replace(
        planned.load_contract(tree_index), stream_bytes=expected["stream_bytes"]
    )
    if planned.contract_sha256(contract) != expected["contract"]:
        raise ValueError(f"tree-{tree_index} frozen contract identity mismatch")
    return contract


def run(
    tree_index: int,
    output_directory: Path,
    global_archive: Path,
    global_manifest: Path,
    cache: Path,
) -> dict[str, object]:
    expected = EXPECTED[tree_index]
    archive = output_directory / (
        f"pq_rbbc_production_tree_{tree_index}_producer_"
        f"v2_27_tree{tree_index}_prefreeze.f193assign"
    )
    if _sha256(archive) != expected["archive"]:
        raise ValueError(f"tree-{tree_index} prefreeze archive identity mismatch")
    if cache.exists():
        raise FileExistsError(f"tree-{tree_index} frozen replay requires a fresh cache")
    planned.FROZEN_STREAM_BYTES_BY_TREE[tree_index] = expected["stream_bytes"]
    try:
        result = planned.build_production_tree(
            tree_index,
            output_directory,
            global_archive,
            global_manifest,
            artifact_tag=f"v2_27_tree{tree_index}_prefreeze",
            execution_cache_path=cache,
            workers=8,
            progress=lambda message: print(message, flush=True),
        )
        document = planned.build_replayed_manifest(
            result, tree_index, global_manifest
        )
    finally:
        planned.FROZEN_STREAM_BYTES_BY_TREE.pop(tree_index, None)
    replay = document["production_replay"]
    exact = all((
        replay["status"] == "complete",
        replay["planned_assignment_sha256"] == expected["archive"],
        replay["planned_assignment_body_sha256"] == expected["body"],
        replay["planned_row_stream_bytes"] == expected["stream_bytes"],
        replay["planned_row_stream_sha256"] == expected["stream"],
        replay["tree_component_sha256"] == expected["component"],
        replay["verification_failures"] == 0,
        replay["external_assertions"] == 0,
        len(replay["output_matches"]) == 4,
        all(item["exact_value_match"] for item in replay["output_matches"]),
        replay["stale_witness_probes"] == 6,
        replay["point_mutation_probes"] == 3,
        replay["resumed_execution_cache_this_run"] is False,
    ))
    if not exact:
        raise ValueError(f"tree-{tree_index} frozen replay identity rejected")
    document["implementation_version"] = "2.27"
    boundary = document["claim_boundary"]
    boundary[f"production_tree{tree_index}_planned_assignment_materialized"] = True
    boundary[f"production_tree{tree_index}_planned_full_replay_closed"] = True
    return document


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tree-index", type=int, choices=sorted(EXPECTED), required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--global-archive", type=Path, required=True)
    parser.add_argument("--global-manifest", type=Path, required=True)
    parser.add_argument("--fresh-cache", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    document = run(
        args.tree_index,
        args.output_directory,
        args.global_archive,
        args.global_manifest,
        args.fresh_cache,
    )
    planned._atomic_json(args.manifest, document)
    print(hashlib.sha256(args.manifest.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
