#!/usr/bin/env python3
"""Run the gated pre-freeze/frozen pipeline for PQ-RBBC trees 12--17."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pq_rbbc_cap_planned_tree_producer as planned


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text())


def _gate(document: dict[str, object], tree_index: int, status: str) -> dict[str, object]:
    contract = document["contract"]
    replay = document["production_replay"]
    exact = all((
        contract["tree_index"] == tree_index,
        replay["status"] == status,
        replay["verification_failures"] == 0,
        replay["external_assertions"] == 0,
        replay["resumed_execution_cache_this_run"] is False,
        len(replay["output_matches"]) == 4,
        all(item["exact_value_match"] for item in replay["output_matches"]),
        replay["stale_witness_probes"] == 6,
        replay["point_mutation_probes"] == 3,
        not document["contract_validation_failures"],
        all(item["rejected"] for item in document["configuration_mutation_probes"]),
        document["claim_boundary"]["production_closed"] is False,
    ))
    if not exact:
        raise ValueError(f"tree {tree_index} {status} gate rejected")
    return replay


def _prefreeze(
    tree_index: int,
    directory: Path,
    global_archive: Path,
    global_manifest: Path,
) -> tuple[dict[str, object], Path]:
    manifest = directory / f"pq_rbbc_cap_planned_tree{tree_index}_prefreeze_manifest_v2_27.json"
    if manifest.exists():
        document = _load(manifest)
    else:
        cache = directory / f"tree{tree_index}_prefreeze_execution_cache.pkl"
        if cache.exists():
            raise FileExistsError(f"tree {tree_index} pre-freeze cache exists without a manifest")
        result = planned.build_production_tree(
            tree_index,
            directory,
            global_archive,
            global_manifest,
            artifact_tag=f"v2_27_tree{tree_index}_prefreeze",
            execution_cache_path=cache,
            workers=8,
            progress=lambda message: print(message, flush=True),
        )
        document = planned.build_replayed_manifest(result, tree_index, global_manifest)
        planned._atomic_json(manifest, document)
    replay = _gate(document, tree_index, "prefreeze_complete")
    if document["contract"]["stream_bytes"] is not None:
        raise ValueError(f"tree {tree_index} initial contract reused a stream observation")
    print(f"tree {tree_index} pre-freeze gate complete: {_sha256(manifest)}", flush=True)
    return replay, manifest


def _frozen(
    tree_index: int,
    directory: Path,
    global_archive: Path,
    global_manifest: Path,
    prefreeze: dict[str, object],
) -> Path:
    manifest = directory / f"pq_rbbc_cap_planned_tree{tree_index}_frozen_manifest_v2_27.json"
    if manifest.exists():
        document = _load(manifest)
        replay = _gate(document, tree_index, "complete")
    else:
        cache = directory / f"tree{tree_index}_frozen_fresh_execution_cache.pkl"
        if cache.exists():
            raise FileExistsError(f"tree {tree_index} frozen cache exists without a manifest")
        stream_bytes = prefreeze["planned_row_stream_bytes"]
        contract = replace(planned.load_contract(tree_index), stream_bytes=stream_bytes)
        print(
            f"tree {tree_index} frozen contract: {planned.contract_sha256(contract)} "
            f"stream_bytes={stream_bytes}",
            flush=True,
        )
        planned.FROZEN_STREAM_BYTES_BY_TREE[tree_index] = stream_bytes
        try:
            result = planned.build_production_tree(
                tree_index,
                directory,
                global_archive,
                global_manifest,
                artifact_tag=f"v2_27_tree{tree_index}_prefreeze",
                execution_cache_path=cache,
                workers=8,
                progress=lambda message: print(message, flush=True),
            )
            document = planned.build_replayed_manifest(result, tree_index, global_manifest)
        finally:
            planned.FROZEN_STREAM_BYTES_BY_TREE.pop(tree_index, None)
        replay = _gate(document, tree_index, "complete")
        for name in (
            "planned_assignment_sha256",
            "planned_assignment_body_sha256",
            "planned_row_stream_bytes",
            "planned_row_stream_sha256",
            "tree_component_sha256",
        ):
            if replay[name] != prefreeze[name]:
                raise ValueError(f"tree {tree_index} frozen {name} mismatch")
        document["implementation_version"] = "2.27"
        boundary = document["claim_boundary"]
        boundary[f"production_tree{tree_index}_planned_assignment_materialized"] = True
        boundary[f"production_tree{tree_index}_planned_full_replay_closed"] = True
        planned._atomic_json(manifest, document)
    print(f"tree {tree_index} frozen gate complete: {_sha256(manifest)}", flush=True)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-root", type=Path, required=True)
    parser.add_argument("--global-archive", type=Path, required=True)
    parser.add_argument("--global-manifest", type=Path, required=True)
    parser.add_argument("--first-tree", type=int, default=12, choices=range(12, 18))
    args = parser.parse_args()
    for tree_index in range(args.first_tree, 18):
        directory = args.batch_root / f"tree{tree_index}_prefreeze"
        directory.mkdir(parents=True, exist_ok=True)
        prefreeze, _ = _prefreeze(
            tree_index, directory, args.global_archive, args.global_manifest
        )
        _frozen(tree_index, directory, args.global_archive, args.global_manifest, prefreeze)
    print("trees 12-17 bounded pipeline complete", flush=True)


if __name__ == "__main__":
    main()
