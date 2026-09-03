#!/usr/bin/env python3
"""Checkpointed aggregate verifier for the PQ-RBBC 18-tree composition."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Callable

import pq_rbbc_cap_aggregate_preflight as preflight
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_composer as composer
import pq_rbbc_cap_composer_recovery as composer_recovery
import pq_rbbc_cap_global_tail as global_tail
import pq_rbbc_cap_planned_tree_producer as planned
import pq_rbbc_cap_shard_assignment as assignment
import pq_rbbc_cap_tree_producer as producer


IMPLEMENTATION_VERSION = "2.28"
FORMAT = "PQRBBC-CAP-AGGREGATE-LINK-PRECHECK-1"
RELATION_ID = "pq-rbbc/cap/production-aggregate-link-precheck/v1"
CHECKPOINT_FORMAT = "PQRBBC-CAP-AGGREGATE-LINK-CHECKPOINT-1"
FULL_CHECKPOINT_FORMAT = "PQRBBC-CAP-AGGREGATE-REPLAY-CHECKPOINT-1"
FULL_FORMAT = "PQRBBC-CAP-AGGREGATE-REPLAY-1"
FULL_RELATION_ID = "pq-rbbc/cap/production-aggregate-replay/v1"
PLANNED_ROWS = 586_057_567
PRODUCER_ROWS = 513_312_336
RELOCATION_ROWS = 15_938_520


def canonical_json(document: dict[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def input_identity(tree_paths: dict[int, Path], global_archive: Path) -> str:
    document = {
        "global_archive_sha256": preflight.GLOBAL_ARCHIVE[1],
        "tree_archives": [
            {"tree_index": i, "sha256": preflight.TREE_ARCHIVES[i][1]}
            for i in sorted(tree_paths)
        ],
        "namespace_plan_sha256": preflight.NAMESPACE_PLAN_SHA256,
    }
    return hashlib.sha256(canonical_json(document)).hexdigest()


def _atomic_json(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(canonical_json(document))
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def load_checkpoint(path: Path, identity: str) -> list[int]:
    if not path.exists():
        return []
    document = json.loads(path.read_text())
    if document.get("format") != CHECKPOINT_FORMAT:
        raise ValueError("aggregate checkpoint format mismatch")
    if document.get("input_identity") != identity:
        raise ValueError("aggregate checkpoint input identity mismatch")
    completed = document.get("completed_tree_links")
    if not isinstance(completed, list) or completed != list(range(len(completed))):
        raise ValueError("aggregate checkpoint tree prefix is malformed")
    return completed


def compare_range(
    producer: assignment.AssignmentArchiveReader,
    producer_start: int,
    tail: assignment.AssignmentArchiveReader,
    consumer_start: int,
    bit_length: int,
) -> int:
    for offset in range(bit_length):
        left = producer[producer_start + offset]
        right = tail[consumer_start + offset]
        if left != right:
            raise ValueError(f"relocation value mismatch at bit {offset}")
        if left not in (0, 1):
            raise ValueError(f"relocation wire is not a bit at offset {offset}")
    return bit_length


def validate_static_links(namespace_document: dict[str, object], tail_document: dict[str, object]) -> list[dict[str, object]]:
    plan = namespace_document["plan"]
    ports = {item["port_id"]: item for item in tail_document["ports"]}
    links = []
    for tree in plan["trees"]:
        for output in tree["outputs"]:
            consumer = ports.get(output["port_id"])
            if consumer is None:
                raise ValueError("global-tail consumer port is missing")
            if output["bit_length"] != consumer["bit_length"]:
                raise ValueError("relocation bit length mismatch")
            if output["value_sha256"] != consumer["value_sha256"]:
                raise ValueError("relocation value digest mismatch")
            links.append({
                "tree_index": tree["tree_index"],
                "port_id": output["port_id"],
                "planned_producer_wire_start": output["planned_wire_start"],
                "consumer_wire_start": consumer["consumer_wire_start"],
                "bit_length": output["bit_length"],
                "value_sha256": output["value_sha256"],
            })
    if len(links) != 72:
        raise ValueError("aggregate composition does not contain 72 links")
    return links


def build_link_precheck(
    tree_paths: dict[int, Path],
    global_archive: Path,
    namespace_path: Path,
    global_manifest_path: Path,
    checkpoint_path: Path,
) -> dict[str, object]:
    if sorted(tree_paths) != list(range(18)):
        raise ValueError("all 18 tree archives are required")
    for tree_index, path in tree_paths.items():
        check = preflight._identity(path, preflight.TREE_ARCHIVES[tree_index])
        if not check["verified"]:
            raise ValueError(f"tree {tree_index} archive identity rejected")
    if not preflight._identity(global_archive, preflight.GLOBAL_ARCHIVE)["verified"]:
        raise ValueError("global-tail archive identity rejected")
    namespace_document = json.loads(namespace_path.read_text())
    tail_document = json.loads(global_manifest_path.read_text())
    links = validate_static_links(namespace_document, tail_document)
    identity = input_identity(tree_paths, global_archive)
    completed = load_checkpoint(checkpoint_path, identity)
    tail_expected = planned.tree2._archive_metadata(tail_document)
    results = []
    with assignment.AssignmentArchiveReader(global_archive, expected=tail_expected, verify_body=True) as tail:
        for tree_index in range(18):
            tree_links = [item for item in links if item["tree_index"] == tree_index]
            if tree_index in completed:
                results.extend({**item, "exact_value_match": True, "resumed": True} for item in tree_links)
                continue
            contract = planned.load_contract(tree_index, namespace_path)
            with assignment.AssignmentArchiveReader(tree_paths[tree_index], verify_body=True) as producer:
                for item in tree_links:
                    local_start = item["planned_producer_wire_start"] - contract.planned_local_wire_start + 1
                    matched = compare_range(producer, local_start, tail, item["consumer_wire_start"], item["bit_length"])
                    results.append({
                        **item,
                        "exact_value_match": True,
                        "matched_wire_values": matched,
                        "resumed": False,
                    })
            completed.append(tree_index)
            _atomic_json(checkpoint_path, {
                "format": CHECKPOINT_FORMAT,
                "input_identity": identity,
                "completed_tree_links": completed,
            })
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "input_identity": identity,
        "links": results,
        "claim_boundary": {
            "aggregate_archive_identity_precheck_closed": True,
            "aggregate_72_link_value_precheck_closed": True,
            "complete_18_tree_assignment_replayed": False,
            "cross_segment_wire_identity_closed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }


def _load_full_checkpoint(path: Path, identity: str) -> dict[str, object]:
    if not path.exists():
        return {
            "format": FULL_CHECKPOINT_FORMAT,
            "input_identity": identity,
            "completed_tree_replays": [],
            "tree_results": [],
            "relocations_complete": False,
            "global_tail_complete": False,
        }
    document = json.loads(path.read_text())
    if document.get("format") != FULL_CHECKPOINT_FORMAT:
        raise ValueError("full replay checkpoint format mismatch")
    if document.get("input_identity") != identity:
        raise ValueError("full replay checkpoint input identity mismatch")
    completed = document.get("completed_tree_replays")
    results = document.get("tree_results")
    if (
        not isinstance(completed, list)
        or completed != list(range(len(completed)))
        or not isinstance(results, list)
        or len(results) != len(completed)
    ):
        raise ValueError("full replay checkpoint tree prefix is malformed")
    return document


def _tree_result(
    tree_index: int,
    tree_path: Path,
    global_values: assignment.AssignmentArchiveReader,
    namespace_path: Path,
    cache_directory: Path,
    workers: int,
    progress: Callable[[str], None] | None,
) -> dict[str, object]:
    contract = planned.load_contract(tree_index, namespace_path)
    if planned.contract_failures(contract, contract):
        raise ValueError(f"tree {tree_index} planned contract rejected")
    point_values = tuple(
        planned.tree2._field_from_bits(global_values, start)
        for start in contract.global_point_wire_starts
    )
    randomness, material, component_sha256, _ = planned.build_tree_material(
        contract,
        cache_directory / f"tree{tree_index}_aggregate_execution_cache.pkl",
        point_values,
        workers=workers,
        progress=progress,
    )
    with assignment.AssignmentArchiveReader(tree_path, verify_body=True) as local_reader:
        if local_reader.wires != contract.local_wires:
            raise ValueError(f"tree {tree_index} archive wire count mismatch")
        archived_row_stream_sha256 = local_reader.row_stream_sha256
        local_values = planned.tree2.OffsetAssignment(
            local_reader, contract.planned_local_wire_start, local_reader.wires
        )
        composed = planned.tree2.CompositeAssignment(global_values, local_values)
        summary = producer.build_tree_producer(
            cap.PRODUCTION_PARAMETERS,
            randomness,
            None,
            tree_index,
            producer_material=material,
            external_point_starts=contract.global_point_wire_starts,
            local_wire_start=contract.planned_local_wire_start,
            verification_assignment=composed,
            workers=workers,
            progress=progress,
        )
    if summary.verification_failures:
        raise AssertionError(
            f"tree {tree_index} replay failed first at "
            f"{summary.first_verification_failure}"
        )
    if summary.rows != contract.rows:
        raise AssertionError(f"tree {tree_index} row count mismatch")
    if summary.stream_sha256 != archived_row_stream_sha256:
        raise AssertionError(f"tree {tree_index} row stream mismatch")
    return {
        "tree_index": tree_index,
        "rows": summary.rows,
        "row_stream_sha256": summary.stream_sha256,
        "verification_failures": 0,
        "component_sha256": component_sha256,
    }


def build_full_replay(
    tree_paths: dict[int, Path],
    global_archive: Path,
    namespace_path: Path,
    global_manifest_path: Path,
    trusted_execution_cache: Path,
    checkpoint_directory: Path,
    *,
    workers: int = 8,
    progress: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Replay all frozen rows without constructing a monolithic assignment."""
    if sorted(tree_paths) != list(range(18)):
        raise ValueError("all 18 tree archives are required")
    for tree_index, path in tree_paths.items():
        if not preflight._identity(
            path, preflight.TREE_ARCHIVES[tree_index]
        )["verified"]:
            raise ValueError(f"tree {tree_index} archive identity rejected")
    if not preflight._identity(
        global_archive, preflight.GLOBAL_ARCHIVE
    )["verified"]:
        raise ValueError("global-tail archive identity rejected")
    # This loader rejects caches whose reconstructed execution does not match
    # the deterministic production transcript.  The CLI names the input
    # trusted to make clear that downloaded pickle files are out of scope.
    execution_summary = global_tail._load_production_execution(trusted_execution_cache)
    identity = input_identity(tree_paths, global_archive)
    identity = hashlib.sha256(canonical_json({
        "archive_identity": identity,
        "runner_sha256": _sha256(Path(__file__)),
        "execution_semantic_identity": composer_recovery.execution_sha256(
            execution_summary.execution
        ),
    })).hexdigest()
    checkpoint_path = checkpoint_directory / "aggregate_full_checkpoint_v2_28.json"
    checkpoint = _load_full_checkpoint(checkpoint_path, identity)
    namespace_document = json.loads(namespace_path.read_text())
    tail_document = json.loads(global_manifest_path.read_text())
    links = validate_static_links(namespace_document, tail_document)
    tail_expected = planned.tree2._archive_metadata(tail_document)
    checkpoint_directory.mkdir(parents=True, exist_ok=True)
    with assignment.AssignmentArchiveReader(
        global_archive, expected=tail_expected, verify_body=True
    ) as global_values:
        completed = checkpoint["completed_tree_replays"]
        results = checkpoint["tree_results"]
        for tree_index in range(len(completed), 18):
            if progress:
                progress(f"aggregate replay tree {tree_index}/17")
            results.append(_tree_result(
                tree_index, tree_paths[tree_index], global_values,
                namespace_path, checkpoint_directory, workers, progress,
            ))
            completed.append(tree_index)
            _atomic_json(checkpoint_path, checkpoint)
        if not checkpoint["relocations_complete"]:
            matched = 0
            for tree_index in range(18):
                contract = planned.load_contract(tree_index, namespace_path)
                with assignment.AssignmentArchiveReader(
                    tree_paths[tree_index], verify_body=True
                ) as local_reader:
                    for item in (x for x in links if x["tree_index"] == tree_index):
                        local_start = (
                            item["planned_producer_wire_start"]
                            - contract.planned_local_wire_start + 1
                        )
                        matched += compare_range(
                            local_reader, local_start, global_values,
                            item["consumer_wire_start"], item["bit_length"],
                        )
            if matched != RELOCATION_ROWS:
                raise AssertionError("aggregate relocation row count mismatch")
            checkpoint["relocations_complete"] = True
            checkpoint["relocation_rows"] = matched
            _atomic_json(checkpoint_path, checkpoint)
        if not checkpoint["global_tail_complete"]:
            randomness = cap.deterministic_randomness(
                cap.PRODUCTION_PARAMETERS, composer.FROZEN_RANDOMNESS_LABEL
            )
            tail_summary = global_tail.build_global_tail(
                cap.PRODUCTION_PARAMETERS,
                randomness,
                execution_summary.execution,
                verification_assignment=global_values,
                workers=workers,
                progress=progress,
            )
            if tail_summary.verification_failures:
                raise AssertionError(
                    "global-tail replay failed first at "
                    f"{tail_summary.first_verification_failure}"
                )
            if (
                tail_summary.rows != global_tail.FROZEN_PRODUCTION_ROWS
                or tail_summary.stream_sha256
                != global_tail.FROZEN_PRODUCTION_STREAM_SHA256
            ):
                raise AssertionError("global-tail row stream mismatch")
            checkpoint["global_tail_complete"] = True
            checkpoint["global_tail_result"] = {
                "rows": tail_summary.rows,
                "row_stream_sha256": tail_summary.stream_sha256,
                "verification_failures": 0,
            }
            _atomic_json(checkpoint_path, checkpoint)
    replayed_rows = (
        sum(item["rows"] for item in checkpoint["tree_results"])
        + checkpoint["relocation_rows"]
        + checkpoint["global_tail_result"]["rows"]
    )
    if replayed_rows != PLANNED_ROWS:
        raise AssertionError("planned aggregate row count mismatch")
    transcript = {
        "tree_row_streams": checkpoint["tree_results"],
        "relocation_rows": checkpoint["relocation_rows"],
        "global_tail_result": checkpoint["global_tail_result"],
    }
    return {
        "format": FULL_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": FULL_RELATION_ID,
        "input_identity": identity,
        "ordered_replay_transcript_sha256": hashlib.sha256(
            canonical_json(transcript)
        ).hexdigest(),
        "tree_order": list(range(18)),
        "tree_results": checkpoint["tree_results"],
        "relocation_rows": checkpoint["relocation_rows"],
        "global_tail_result": checkpoint["global_tail_result"],
        "rows_replayed": replayed_rows,
        "verification_failures": 0,
        "claim_boundary": {
            "aggregate_archive_identity_precheck_closed": True,
            "aggregate_72_link_value_precheck_closed": True,
            "complete_18_tree_assignment_replayed": True,
            "cross_segment_wire_identity_closed": True,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace-manifest", type=Path, required=True)
    parser.add_argument("--prior-evidence", type=Path, required=True)
    parser.add_argument("--global-archive", type=Path, required=True)
    parser.add_argument("--incremental-br1cs", type=Path, required=True)
    parser.add_argument("--tree-archive", action="append", default=[])
    parser.add_argument("--checkpoint-directory", type=Path, required=True)
    parser.add_argument("--trusted-composer-execution-cache", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=8)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--link-precheck-only", action="store_true")
    mode.add_argument("--full-row-replay", action="store_true")
    args = parser.parse_args()
    if args.workers != 8:
        parser.error("v2.28 link precheck is frozen to 8 workers")
    if not preflight._identity(args.prior_evidence, (preflight.PRIOR_EVIDENCE_BYTES, preflight.PRIOR_EVIDENCE_SHA256))["verified"]:
        raise SystemExit("prior evidence identity rejected")
    if not preflight._identity(
        args.namespace_manifest,
        (preflight.NAMESPACE_BYTES, preflight.NAMESPACE_SHA256),
    )["verified"]:
        raise SystemExit("namespace manifest identity rejected")
    if not preflight._identity(args.incremental_br1cs, preflight.INCREMENTAL_BR1CS)["verified"]:
        raise SystemExit("incremental BR1CS identity rejected")
    trees = preflight.parse_tree_archives(args.tree_archive)
    if args.full_row_replay:
        if args.trusted_composer_execution_cache is None:
            parser.error(
                "--trusted-composer-execution-cache is required for full replay"
            )
        document = build_full_replay(
            trees, args.global_archive, args.namespace_manifest,
            planned.DEFAULT_GLOBAL_MANIFEST,
            args.trusted_composer_execution_cache,
            args.checkpoint_directory,
            workers=args.workers,
            progress=lambda message: print(message, flush=True),
        )
    else:
        document = build_link_precheck(
            trees, args.global_archive, args.namespace_manifest,
            planned.DEFAULT_GLOBAL_MANIFEST,
            args.checkpoint_directory / "aggregate_link_checkpoint_v2_28.json",
        )
    _atomic_json(args.manifest, document)
    print(_sha256(args.manifest))


if __name__ == "__main__":
    main()
