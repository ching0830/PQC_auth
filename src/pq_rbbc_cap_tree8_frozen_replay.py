#!/usr/bin/env python3
"""Second, fresh-cache frozen replay for PQ-RBBC v2.26 tree 8."""

from __future__ import annotations

import argparse
import hashlib
from dataclasses import replace
from pathlib import Path

import pq_rbbc_cap_planned_tree_producer as planned


IMPLEMENTATION_VERSION = "2.26"
TREE_INDEX = 8
FROZEN_STREAM_BYTES = 8_961_160_824
FROZEN_CONTRACT_SHA256 = "15277b5065ef5b97dc7919306c3c1044826b98adee3a92f12be9cde5f9623c99"
FROZEN_PREFREEZE_ARCHIVE_SHA256 = "bf3c1f6ef1fa34b3d5cb9e11d85e65b33a3dbe80c926cf2cd86be291d19c884c"
FROZEN_PREFREEZE_BODY_SHA256 = "c75cf3f463e3de983b3ffa328d5800d587636b775d2a7b499686bbfe64029e90"
FROZEN_STREAM_SHA256 = "c6f593afc2afe6393800c26f27203cbc4e1bb3e83cfe57c2ac6cc812553285af"
FROZEN_TREE_COMPONENT_SHA256 = "c0037cfb5a06379b463d8430e4b8ffbd114db452814283d2330a3cd57357075b"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def frozen_contract() -> planned.PlannedTreeContract:
    contract = replace(planned.load_contract(TREE_INDEX), stream_bytes=FROZEN_STREAM_BYTES)
    if planned.contract_sha256(contract) != FROZEN_CONTRACT_SHA256:
        raise ValueError("tree-8 frozen contract identity mismatch")
    return contract


def run(output_directory: Path, global_archive: Path, global_manifest: Path, cache: Path) -> dict[str, object]:
    archive = output_directory / "pq_rbbc_production_tree_8_producer_v2_26_tree8_prefreeze.f193assign"
    if _sha256(archive) != FROZEN_PREFREEZE_ARCHIVE_SHA256:
        raise ValueError("tree-8 prefreeze archive identity mismatch")
    if cache.exists():
        raise FileExistsError("tree-8 frozen replay requires a fresh cache")
    planned.FROZEN_STREAM_BYTES_BY_TREE[TREE_INDEX] = FROZEN_STREAM_BYTES
    try:
        result = planned.build_production_tree(
            TREE_INDEX,
            output_directory,
            global_archive,
            global_manifest,
            artifact_tag="v2_26_tree8_prefreeze",
            execution_cache_path=cache,
            workers=8,
            progress=lambda message: print(message, flush=True),
        )
        document = planned.build_replayed_manifest(result, TREE_INDEX, global_manifest)
    finally:
        planned.FROZEN_STREAM_BYTES_BY_TREE.pop(TREE_INDEX, None)
    replay = document["production_replay"]
    exact = all((
        replay["status"] == "complete",
        replay["planned_assignment_sha256"] == FROZEN_PREFREEZE_ARCHIVE_SHA256,
        replay["planned_assignment_body_sha256"] == FROZEN_PREFREEZE_BODY_SHA256,
        replay["planned_row_stream_sha256"] == FROZEN_STREAM_SHA256,
        replay["tree_component_sha256"] == FROZEN_TREE_COMPONENT_SHA256,
        replay["verification_failures"] == 0,
        replay["external_assertions"] == 0,
        len(replay["output_matches"]) == 4,
        all(item["exact_value_match"] for item in replay["output_matches"]),
        replay["stale_witness_probes"] == 6,
        replay["point_mutation_probes"] == 3,
        replay["resumed_execution_cache_this_run"] is False,
    ))
    if not exact:
        raise ValueError("tree-8 frozen replay identity rejected")
    document["implementation_version"] = IMPLEMENTATION_VERSION
    document["claim_boundary"]["production_tree8_planned_assignment_materialized"] = True
    document["claim_boundary"]["production_tree8_planned_full_replay_closed"] = True
    return document


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--global-archive", type=Path, required=True)
    parser.add_argument("--global-manifest", type=Path, required=True)
    parser.add_argument("--fresh-cache", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    document = run(args.output_directory, args.global_archive, args.global_manifest, args.fresh_cache)
    planned._atomic_json(args.manifest, document)
    print(hashlib.sha256(args.manifest.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
