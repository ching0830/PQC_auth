#!/usr/bin/env python3
"""Second, fresh-cache frozen replay for PQ-RBBC v2.26 tree 10."""

from __future__ import annotations

import argparse
import hashlib
from dataclasses import replace
from pathlib import Path

import pq_rbbc_cap_planned_tree_producer as planned

TREE_INDEX = 10
FROZEN_STREAM_BYTES = 8_986_785_870
FROZEN_CONTRACT_SHA256 = "011d3c249a7d60232074a7f0eb78b34618b097ffcd1c852040fd888263f6e554"
FROZEN_PREFREEZE_ARCHIVE_SHA256 = "23ad60862f387387aba139a8465891f7ada0fe4da5be8a318177217094c39bd8"
FROZEN_PREFREEZE_BODY_SHA256 = "7fb1336c70643771f7b98ac4e44ba65f49077aae527c9c90e51a5b5eb80658ed"
FROZEN_STREAM_SHA256 = "44cf5ff0cdf222d58f1522e06afadccf3ad377ce4893575d1ef8f8317a2f3ba2"
FROZEN_TREE_COMPONENT_SHA256 = "0378694c05c5236207cdb5d9c148e75f4d9ab5245787523d9de8739577bc8d89"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def frozen_contract() -> planned.PlannedTreeContract:
    contract = replace(planned.load_contract(TREE_INDEX), stream_bytes=FROZEN_STREAM_BYTES)
    if planned.contract_sha256(contract) != FROZEN_CONTRACT_SHA256:
        raise ValueError("tree-10 frozen contract identity mismatch")
    return contract


def run(output_directory: Path, global_archive: Path, global_manifest: Path, cache: Path) -> dict[str, object]:
    archive = output_directory / "pq_rbbc_production_tree_10_producer_v2_26_tree10_prefreeze.f193assign"
    if _sha256(archive) != FROZEN_PREFREEZE_ARCHIVE_SHA256:
        raise ValueError("tree-10 prefreeze archive identity mismatch")
    if cache.exists():
        raise FileExistsError("tree-10 frozen replay requires a fresh cache")
    planned.FROZEN_STREAM_BYTES_BY_TREE[TREE_INDEX] = FROZEN_STREAM_BYTES
    try:
        result = planned.build_production_tree(
            TREE_INDEX, output_directory, global_archive, global_manifest,
            artifact_tag="v2_26_tree10_prefreeze", execution_cache_path=cache,
            workers=8, progress=lambda message: print(message, flush=True),
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
        raise ValueError("tree-10 frozen replay identity rejected")
    document["implementation_version"] = "2.26"
    document["claim_boundary"]["production_tree10_planned_assignment_materialized"] = True
    document["claim_boundary"]["production_tree10_planned_full_replay_closed"] = True
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
