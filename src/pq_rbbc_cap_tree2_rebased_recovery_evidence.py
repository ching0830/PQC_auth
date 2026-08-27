#!/usr/bin/env python3
"""Seal the completed PQ-RBBC tree-2 planned-offset replay, v2.21.

The v2.17 runner produced and replayed the tree-index-2 assignment at the
frozen v2.16 namespace offset after v2.20 restored the mandatory global-tail
archive.  This module records the result as portable, path-free evidence while
keeping the 486 MB assignment and trusted pickle cache outside Git.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_global_tail_recovery_evidence as global_tail_recovery
import pq_rbbc_cap_production_tree2_rebased as rebased
from pq_rbbc_cap_shard_assignment import (
    ASSIGNMENT_FORMAT,
    ASSIGNMENT_HEADER_BYTES,
    AssignmentArchiveMetadata,
    AssignmentArchiveReader,
)
from pq_rbbc_anemoi_f193 import FIELD_DEGREE, FIELD_ELEMENT_BYTES


IMPLEMENTATION_VERSION = "2.21"
EVIDENCE_FORMAT = "PQRBBC-CAP-TREE2-REBASED-RECOVERY-EVIDENCE-1"
RELATION_ID = "pq-rbbc/cap/production-tree2-rebased-recovery-evidence/v1"
MANIFEST_NAME = "pq_rbbc_cap_tree2_rebased_recovery_evidence_v2_21.json"

FROZEN_EVIDENCE_SHA256 = (
    "3e63ca4c014c5971fadfeed9dc8062fbaa86cec82c732c691695d4c80d5e584f"
)
FROZEN_REPLAY_MANIFEST_SHA256 = (
    "487d32a77122e55f5bc753889aac22764104f0521c5f02e5855676dbf76ba78c"
)
FROZEN_ARCHIVE_BYTES = 486_961_028
FROZEN_ARCHIVE_SHA256 = (
    "2d9932cd09848d70fece5d047206f580ed6efe1e7335ac8ff865947e0662d933"
)
FROZEN_BODY_BYTES = 486_960_900
FROZEN_BODY_SHA256 = (
    "632db9813ef41bb3af1d769189132d072208ca0a58e2810c76b844a39da3b501"
)
FROZEN_ROWS = 25_666_386
FROZEN_WIRES = 19_478_436
FROZEN_STREAM_BYTES = 8_961_160_824
FROZEN_STREAM_SHA256 = (
    "37da12bffb023ae1b92e9d54b4bb34591c2cb1006bdca1aa28d7d2c04fe9770f"
)
FROZEN_FIRST_WIRE = 0
FROZEN_LAST_WIRE = 0
FROZEN_STANDARD_PROBES = 6
FROZEN_POINT_PROBES = 3

FROZEN_OUTPUT_MATCHES = (
    {
        "port_id": "tree[2].leaf-commitments",
        "planned_producer_wire_start": 136_713_057,
        "consumer_wire_start": 3_177_659,
        "bit_length": 790_528,
        "value_sha256": "c27608c4139f15972d445d34015300618abbc953671a3b7ba9c6eefc22e053ac",
        "exact_value_match": True,
    },
    {
        "port_id": "tree[2].p-plain",
        "planned_producer_wire_start": 137_503_585,
        "consumer_wire_start": 3_968_187,
        "bit_length": 2_048,
        "value_sha256": "7388cdc799a2526ad7df179635d1d4dfda400669f58a50f686b3d9be9998d356",
        "exact_value_match": True,
    },
    {
        "port_id": "tree[2].mhat-plain",
        "planned_producer_wire_start": 137_505_633,
        "consumer_wire_start": 3_970_235,
        "bit_length": 386,
        "value_sha256": "a32ffca5ef15845d5254b11dc446b7b44e1ac30c3d5c080f1d2dff25ffe42c29",
        "exact_value_match": True,
    },
    {
        "port_id": "tree[2].xi-masks",
        "planned_producer_wire_start": 137_576_061,
        "consumer_wire_start": 3_970_621,
        "bit_length": 4_632,
        "value_sha256": "a3519ba430a2f7d8ff2599990972a4f28db7e9d1fc260d92527e814bde81a3e5",
        "exact_value_match": True,
    },
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(document: Mapping[str, object]) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _json_contract() -> dict[str, object]:
    return json.loads(json.dumps(asdict(rebased.load_contract())))


def _expected_replay() -> dict[str, object]:
    return {
        "status": "complete",
        "production_rows_replayed_at_planned_offset": FROZEN_ROWS,
        "planned_row_stream_bytes": FROZEN_STREAM_BYTES,
        "planned_row_stream_sha256": FROZEN_STREAM_SHA256,
        "planned_assignment_bytes": FROZEN_ARCHIVE_BYTES,
        "planned_assignment_sha256": FROZEN_ARCHIVE_SHA256,
        "planned_assignment_body_sha256": FROZEN_BODY_SHA256,
        "standalone_assignment_body_sha256": FROZEN_BODY_SHA256,
        "assignment_value_sequence_identical_to_v2_14": True,
        "output_matches": [dict(item) for item in FROZEN_OUTPUT_MATCHES],
        "verification_failures": 0,
        "external_assertions": 0,
        "stale_witness_probes": FROZEN_STANDARD_PROBES,
        "point_mutation_probes": FROZEN_POINT_PROBES,
    }


def _expected_claims() -> dict[str, bool]:
    return {
        "production_tree2_planned_offset_execution_gate_closed": True,
        "planned_offset_reduced_fixture_replayed": True,
        "production_tree2_rebased_assignment_materialized": True,
        "production_tree2_rebased_full_replay_closed": True,
        "representative_producers_rebased_replayed": True,
        "tree_producer_segments_materialized": False,
        "all_72_output_relocations_closed": False,
        "complete_18_tree_assignment_replayed": False,
        "cross_segment_wire_identity_closed": False,
        "parent_cap_to_h_rbbc_join_closed": False,
        "fork_security_proof_revalidated": False,
        "production_closed": False,
    }


def build_frozen_evidence_document() -> dict[str, object]:
    return {
        "format": EVIDENCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "source_global_tail_recovery": {
            "implementation_version": global_tail_recovery.IMPLEMENTATION_VERSION,
            "relation_id": global_tail_recovery.RELATION_ID,
            "evidence_sha256": global_tail_recovery.FROZEN_EVIDENCE_SHA256,
            "archive_sha256": global_tail_recovery.FROZEN_ARCHIVE_SHA256,
        },
        "production_tree2_rebased": {
            "source_implementation_version": rebased.IMPLEMENTATION_VERSION,
            "source_relation_id": rebased.RELATION_ID,
            "contract_sha256": rebased.FROZEN_CONTRACT_SHA256,
            "namespace_plan_sha256": _json_contract()["namespace_plan_sha256"],
            "tree_index": rebased.PLANNED_TREE_INDEX,
            "planned_local_wire_start": rebased.PLANNED_LOCAL_WIRE_START,
            "planned_max_wire_id": rebased.PLANNED_MAX_WIRE_ID,
            "planned_output_wire_starts": list(rebased.PLANNED_OUTPUT_WIRE_STARTS),
            "global_point_wire_starts": list(_json_contract()["global_point_wire_starts"]),
            "rows": FROZEN_ROWS,
            "wires": FROZEN_WIRES,
            "row_stream_bytes": FROZEN_STREAM_BYTES,
            "row_stream_sha256": FROZEN_STREAM_SHA256,
            "archive_bytes": FROZEN_ARCHIVE_BYTES,
            "archive_sha256": FROZEN_ARCHIVE_SHA256,
            "body_bytes": FROZEN_BODY_BYTES,
            "body_sha256": FROZEN_BODY_SHA256,
            "first_wire": FROZEN_FIRST_WIRE,
            "last_wire": FROZEN_LAST_WIRE,
            "output_matches": [dict(item) for item in FROZEN_OUTPUT_MATCHES],
            "external_assertions": 0,
            "replay_failures": 0,
            "stale_witness_probes": FROZEN_STANDARD_PROBES,
            "point_mutation_probes": FROZEN_POINT_PROBES,
            "all_mutation_probes_rejected": True,
        },
        "replayed_manifest": {
            "sha256": FROZEN_REPLAY_MANIFEST_SHA256,
            "status": "complete",
            "contract_validation_failures": 0,
            "configuration_mutation_probes": 8,
            "configuration_mutations_rejected": True,
        },
        "artifact_policy": {
            "large_artifacts_tracked_in_git": False,
            "portable_evidence_contains_absolute_paths": False,
            "archive_format_is_non_executable_binary": True,
            "trusted_pickle_cache_tracked_in_git": False,
        },
        "claim_boundary": {
            "production_execution_cache_regenerated": True,
            "production_composition_document_revalidated": True,
            "production_global_tail_archive_regenerated": True,
            "production_global_tail_native_closed": True,
            **_expected_claims(),
        },
    }


def validate_evidence_document(document: Mapping[str, object]) -> tuple[str, ...]:
    failures: list[str] = []
    expected = build_frozen_evidence_document()
    if document.get("format") != EVIDENCE_FORMAT:
        failures.append("wrong_format")
    if document.get("implementation_version") != IMPLEMENTATION_VERSION:
        failures.append("wrong_implementation_version")
    if document.get("relation_id") != RELATION_ID:
        failures.append("wrong_relation_id")
    for section, failure in (
        ("source_global_tail_recovery", "source_global_tail_recovery_identity"),
        ("production_tree2_rebased", "production_tree2_rebased_identity"),
        ("replayed_manifest", "replayed_manifest_identity"),
        ("artifact_policy", "artifact_policy"),
        ("claim_boundary", "claim_boundary"),
    ):
        if document.get(section) != expected[section]:
            failures.append(failure)
    return tuple(failures)


def verify_frozen_evidence(path: Path) -> tuple[str, ...]:
    encoded = path.read_bytes()
    failures: list[str] = []
    if FROZEN_EVIDENCE_SHA256 != "TODO":
        if hashlib.sha256(encoded).hexdigest() != FROZEN_EVIDENCE_SHA256:
            failures.append("frozen_evidence_sha256")
    try:
        document = json.loads(encoded)
    except json.JSONDecodeError:
        return tuple(failures + ["invalid_json"])
    if not isinstance(document, dict):
        return tuple(failures + ["evidence_root"])
    failures.extend(validate_evidence_document(document))
    return tuple(dict.fromkeys(failures))


def build_evidence_from_artifacts(
    archive_path: Path,
    replayed_manifest_path: Path,
    global_manifest_path: Path,
) -> dict[str, object]:
    replayed = json.loads(replayed_manifest_path.read_text(encoding="utf-8"))
    global_document = json.loads(global_manifest_path.read_text(encoding="utf-8"))
    if not isinstance(replayed, dict) or not isinstance(global_document, dict):
        raise ValueError("tree-2 replay inputs must be JSON objects")

    contract = _json_contract()
    configuration_probes = replayed.get("configuration_mutation_probes")
    exact_checks = {
        "replayed_manifest_sha256": _sha256_file(replayed_manifest_path)
        == FROZEN_REPLAY_MANIFEST_SHA256,
        "implementation_version": replayed.get("implementation_version")
        == rebased.IMPLEMENTATION_VERSION,
        "contract": replayed.get("contract") == contract,
        "contract_sha256": replayed.get("contract_sha256")
        == rebased.FROZEN_CONTRACT_SHA256,
        "contract_validation_failures": replayed.get("contract_validation_failures")
        == [],
        "configuration_mutations": isinstance(configuration_probes, list)
        and len(configuration_probes) == 8
        and all(
            isinstance(probe, dict) and probe.get("rejected") is True
            for probe in configuration_probes
        ),
        "production_replay": replayed.get("production_replay")
        == _expected_replay(),
        "claim_boundary": replayed.get("claim_boundary") == _expected_claims(),
        "global_manifest_sha256": _sha256_file(global_manifest_path)
        == global_tail_recovery.FROZEN_HISTORICAL_MANIFEST_SHA256,
    }

    consumers = {
        str(item.get("port_id")): item
        for item in global_document.get("ports", [])
        if isinstance(item, dict)
    }
    for item in FROZEN_OUTPUT_MATCHES:
        consumer = consumers.get(str(item["port_id"]))
        exact_checks[f"output:{item['port_id']}"] = (
            isinstance(consumer, dict)
            and consumer.get("consumer_wire_start") == item["consumer_wire_start"]
            and consumer.get("bit_length") == item["bit_length"]
            and consumer.get("value_sha256") == item["value_sha256"]
        )

    expected_archive = AssignmentArchiveMetadata(
        ASSIGNMENT_FORMAT,
        ASSIGNMENT_HEADER_BYTES,
        FIELD_DEGREE,
        FIELD_ELEMENT_BYTES,
        FROZEN_WIRES,
        FROZEN_BODY_BYTES,
        FROZEN_BODY_SHA256,
        FROZEN_STREAM_SHA256,
        FROZEN_ARCHIVE_BYTES,
        FROZEN_ARCHIVE_SHA256,
    )
    with AssignmentArchiveReader(
        archive_path, expected=expected_archive, verify_body=True
    ) as archive:
        archive_checks = {
            "archive_bytes": archive_path.stat().st_size == FROZEN_ARCHIVE_BYTES,
            "archive_sha256": _sha256_file(archive_path) == FROZEN_ARCHIVE_SHA256,
            "first_wire": archive[1] == FROZEN_FIRST_WIRE,
            "last_wire": archive[archive.wires] == FROZEN_LAST_WIRE,
        }
    exact_checks.update(archive_checks)
    failed = [name for name, accepted in exact_checks.items() if not accepted]
    if failed:
        raise ValueError("tree-2 rebased recovery evidence rejected: " + ",".join(failed))
    return build_frozen_evidence_document()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--replayed-manifest", type=Path)
    parser.add_argument("--global-manifest", type=Path)
    parser.add_argument("--verify-frozen", type=Path)
    args = parser.parse_args()

    if args.verify_frozen is not None:
        failures = verify_frozen_evidence(args.verify_frozen)
        if failures:
            raise SystemExit("frozen tree-2 evidence rejected: " + ",".join(failures))
        print("frozen production tree-2 rebased recovery evidence accepted")
        return

    required = (
        args.manifest,
        args.archive,
        args.replayed_manifest,
        args.global_manifest,
    )
    if not all(item is not None for item in required):
        parser.error(
            "--manifest, --archive, --replayed-manifest, and --global-manifest "
            "are required"
        )
    document = build_evidence_from_artifacts(
        args.archive,
        args.replayed_manifest,
        args.global_manifest,
    )
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_bytes(canonical_json(document))
    print(hashlib.sha256(args.manifest.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
