#!/usr/bin/env python3
"""Seal the completed PQ-RBBC tree-1 planned-offset replay, v2.22.

The generic planned-offset runner materialized and replayed tree index 1 at
the frozen v2.16 namespace position.  This module records path-free portable
evidence while keeping the 973 MB assignment and trusted pickle caches outside
Git.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_global_tail_recovery_evidence as global_tail_recovery
import pq_rbbc_cap_planned_tree_producer as planned
import pq_rbbc_cap_tree2_rebased_recovery_evidence as tree2_evidence
from pq_rbbc_anemoi_f193 import FIELD_DEGREE, FIELD_ELEMENT_BYTES
from pq_rbbc_cap_shard_assignment import (
    ASSIGNMENT_FORMAT,
    ASSIGNMENT_HEADER_BYTES,
    AssignmentArchiveMetadata,
    AssignmentArchiveReader,
)


IMPLEMENTATION_VERSION = "2.22"
EVIDENCE_FORMAT = "PQRBBC-CAP-TREE1-PLANNED-RECOVERY-EVIDENCE-1"
RELATION_ID = "pq-rbbc/cap/production-tree1-planned-recovery-evidence/v1"
MANIFEST_NAME = "pq_rbbc_cap_tree1_planned_recovery_evidence_v2_22.json"

FROZEN_EVIDENCE_SHA256 = "895c7d47209eb4f1bb3c56f5655ecc89b33b0cc7f1ce0d6e238ab5d9afa34712"
FROZEN_REPLAY_MANIFEST_SHA256 = (
    "1777000ae991d384ee540e32b0d98a42645f494049ff96a20f365ecb08e3d9ce"
)
FROZEN_ARCHIVE_BYTES = 973_845_878
FROZEN_ARCHIVE_SHA256 = (
    "ab75aca6037e47fe38a1364d2c66f90d1a3856da901423b398fa2d8812fa609f"
)
FROZEN_BODY_BYTES = 973_845_750
FROZEN_BODY_SHA256 = (
    "00b175ebf9414e9d7a4bae49de4e0bf7ff568631dc8865f898a3ed084ab6061f"
)
FROZEN_ROWS = 51_325_080
FROZEN_WIRES = 38_953_830
FROZEN_STREAM_BYTES = 18_008_277_115
FROZEN_STREAM_SHA256 = (
    "1a9c11a716cb491517277c6e18c805683d85a75cb2c5306f13db7b7f13d1f516"
)
FROZEN_TREE_COMPONENT_SHA256 = (
    "0db861243dbc72fffb09799ea50c4b770c3cb2a847d4dd66fffc968b91790d81"
)
FROZEN_FIRST_WIRE = 0
FROZEN_LAST_WIRE = 0
FROZEN_STANDARD_PROBES = 6
FROZEN_POINT_PROBES = 3

FROZEN_OUTPUT_MATCHES = (
    {
        "port_id": "tree[1].leaf-commitments",
        "planned_producer_wire_start": 116_373_499,
        "consumer_wire_start": 1_589_151,
        "bit_length": 1_581_056,
        "value_sha256": "1c83e40fa8b2b264559419615eb5563e59f7629ffe67d940adbbd41ae5a8a6ec",
        "exact_value_match": True,
    },
    {
        "port_id": "tree[1].p-plain",
        "planned_producer_wire_start": 117_954_555,
        "consumer_wire_start": 3_170_207,
        "bit_length": 2_048,
        "value_sha256": "f907ac9ab870655e8ade54b497e2794281edd941e890096d9c4072ae69b54d1d",
        "exact_value_match": True,
    },
    {
        "port_id": "tree[1].mhat-plain",
        "planned_producer_wire_start": 117_956_603,
        "consumer_wire_start": 3_172_255,
        "bit_length": 386,
        "value_sha256": "716b361e7b5cde36f9b63b5d61c0cf7cbe6b62de76d105430ced89184868ffae",
        "exact_value_match": True,
    },
    {
        "port_id": "tree[1].xi-masks",
        "planned_producer_wire_start": 118_097_239,
        "consumer_wire_start": 3_172_641,
        "bit_length": 5_018,
        "value_sha256": "da36bc3c9282f03e6f0a80c2b6d969d9a6e0bfa5d3f9f8064720e5dc22334371",
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
    return json.loads(json.dumps(asdict(planned.load_contract(planned.TREE1_INDEX))))


def _expected_replay_values() -> dict[str, object]:
    return {
        "status": "complete",
        "production_rows_replayed_at_planned_offset": FROZEN_ROWS,
        "planned_row_stream_bytes": FROZEN_STREAM_BYTES,
        "planned_row_stream_sha256": FROZEN_STREAM_SHA256,
        "planned_assignment_bytes": FROZEN_ARCHIVE_BYTES,
        "planned_assignment_sha256": FROZEN_ARCHIVE_SHA256,
        "planned_assignment_body_sha256": FROZEN_BODY_SHA256,
        "tree_component_sha256": FROZEN_TREE_COMPONENT_SHA256,
        "output_matches": [dict(item) for item in FROZEN_OUTPUT_MATCHES],
        "verification_failures": 0,
        "external_assertions": 0,
        "stale_witness_probes": FROZEN_STANDARD_PROBES,
        "point_mutation_probes": FROZEN_POINT_PROBES,
    }


def _expected_runner_claims() -> dict[str, bool]:
    return {
        "planned_tree_runner_preflight_closed": True,
        "planned_offset_reduced_fixture_replayed": True,
        "production_tree1_planned_assignment_materialized": True,
        "production_tree1_planned_full_replay_closed": True,
        "remaining_planned_tree_producers_materialized": False,
        "all_72_output_relocations_closed": False,
        "complete_18_tree_assignment_replayed": False,
        "cross_segment_wire_identity_closed": False,
        "parent_cap_to_h_rbbc_join_closed": False,
        "fork_security_proof_revalidated": False,
        "production_closed": False,
    }


def build_frozen_evidence_document() -> dict[str, object]:
    contract = _json_contract()
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
        "prior_tree2_recovery": {
            "implementation_version": tree2_evidence.IMPLEMENTATION_VERSION,
            "relation_id": tree2_evidence.RELATION_ID,
            "evidence_sha256": tree2_evidence.FROZEN_EVIDENCE_SHA256,
            "archive_sha256": tree2_evidence.FROZEN_ARCHIVE_SHA256,
        },
        "production_tree1_planned": {
            "runner_implementation_version": planned.IMPLEMENTATION_VERSION,
            "runner_relation_id": planned.RELATION_ID,
            "producer_relation_id": contract["producer_relation_id"],
            "contract_sha256": planned.FROZEN_TREE1_CONTRACT_SHA256,
            "namespace_plan_sha256": contract["namespace_plan_sha256"],
            "tree_index": planned.TREE1_INDEX,
            "planned_local_wire_start": contract["planned_local_wire_start"],
            "planned_max_wire_id": contract["planned_max_wire_id"],
            "planned_output_wire_starts": contract["planned_output_wire_starts"],
            "global_point_wire_starts": contract["global_point_wire_starts"],
            "rows": FROZEN_ROWS,
            "wires": FROZEN_WIRES,
            "row_stream_bytes": FROZEN_STREAM_BYTES,
            "row_stream_sha256": FROZEN_STREAM_SHA256,
            "tree_component_sha256": FROZEN_TREE_COMPONENT_SHA256,
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
            "configuration_mutation_probes": 10,
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
            "production_tree2_rebased_assignment_materialized": True,
            "production_tree2_rebased_full_replay_closed": True,
            "production_tree1_planned_assignment_materialized": True,
            "production_tree1_planned_full_replay_closed": True,
            "materialized_planned_tree_indices": [0, 1, 2],
            "materialized_planned_tree_count": 3,
            "remaining_planned_tree_producers_materialized": False,
            "all_72_output_relocations_closed": False,
            "complete_18_tree_assignment_replayed": False,
            "cross_segment_wire_identity_closed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }


def validate_evidence_document(document: Mapping[str, object]) -> tuple[str, ...]:
    failures: list[str] = []
    expected = build_frozen_evidence_document()
    for section, failure in (
        ("format", "wrong_format"),
        ("implementation_version", "wrong_implementation_version"),
        ("relation_id", "wrong_relation_id"),
        ("source_global_tail_recovery", "source_global_tail_recovery_identity"),
        ("prior_tree2_recovery", "prior_tree2_recovery_identity"),
        ("production_tree1_planned", "production_tree1_planned_identity"),
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
        raise ValueError("tree-1 replay inputs must be JSON objects")

    contract = _json_contract()
    probes = replayed.get("configuration_mutation_probes")
    replay_values = replayed.get("production_replay")
    runner_claims = replayed.get("claim_boundary")
    exact_checks: dict[str, bool] = {
        "replayed_manifest_sha256": _sha256_file(replayed_manifest_path)
        == FROZEN_REPLAY_MANIFEST_SHA256,
        "implementation_version": replayed.get("implementation_version")
        == planned.IMPLEMENTATION_VERSION,
        "contract": replayed.get("contract") == contract,
        "contract_sha256": replayed.get("contract_sha256")
        == planned.FROZEN_TREE1_CONTRACT_SHA256,
        "contract_validation_failures": replayed.get("contract_validation_failures")
        == [],
        "configuration_mutations": isinstance(probes, list)
        and len(probes) == 10
        and all(
            isinstance(probe, dict) and probe.get("rejected") is True
            for probe in probes
        ),
        "runner_claims": runner_claims == _expected_runner_claims(),
        "global_manifest_sha256": _sha256_file(global_manifest_path)
        == global_tail_recovery.FROZEN_HISTORICAL_MANIFEST_SHA256,
    }
    expected_replay = _expected_replay_values()
    exact_checks.update(
        {
            f"production_replay:{key}": isinstance(replay_values, dict)
            and replay_values.get(key) == value
            for key, value in expected_replay.items()
        }
    )

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
        exact_checks.update(
            {
                "archive_bytes": archive_path.stat().st_size
                == FROZEN_ARCHIVE_BYTES,
                "archive_sha256": _sha256_file(archive_path)
                == FROZEN_ARCHIVE_SHA256,
                "first_wire": archive[1] == FROZEN_FIRST_WIRE,
                "last_wire": archive[archive.wires] == FROZEN_LAST_WIRE,
            }
        )
    failed = [name for name, accepted in exact_checks.items() if not accepted]
    if failed:
        raise ValueError(
            "tree-1 planned recovery evidence rejected: " + ",".join(failed)
        )
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
            raise SystemExit("frozen tree-1 evidence rejected: " + ",".join(failures))
        print("frozen production tree-1 planned recovery evidence accepted")
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
        args.archive, args.replayed_manifest, args.global_manifest
    )
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_bytes(canonical_json(document))
    print(hashlib.sha256(args.manifest.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
