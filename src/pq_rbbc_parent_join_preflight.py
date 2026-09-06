#!/usr/bin/env python3
"""Read-only, fail-closed preflight for the PQ-RBBC v2.29 parent join."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_br1cs as br1cs
import pq_rbbc_reference as reference
import pq_rbbc_trace_kdf_source_transition as trace_kdf_transition


IMPLEMENTATION_VERSION = "2.29"
FORMAT = "PQRBBC-PARENT-JOIN-PREFLIGHT-1"
RELATION_ID = "pq-rbbc/parent-cap-to-h-rbbc-preflight/v1"
PARENT_JOIN_RELATION_ID = "pq-rbbc/parent-cap-to-h-rbbc/v1"
ROOT = Path(__file__).resolve().parents[1]

AGGREGATE_EVIDENCE = (
    8_332,
    "820bc4e7b9e6e4e9c41153b48088089a6f15181a5bc3f99c60e37fe242d4f2a1",
)
INCREMENTAL_BR1CS = (
    49_227_687,
    "77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799",
)
BR1CS_MANIFEST = (
    26_488,
    "e19442b08b4f4a596cf001d057d3e5c016efca938a1a4814661a2691aa054737",
)
ABI_MANIFEST = (
    26_423,
    "9081bbc85b258ea30f2c968db8d3f61160df6c599e71e08ade3c9090d4904a3a",
)
SPLIT_TAIL_EVIDENCE = (
    12_510,
    "ce7ff7bd151833840e7d166c75594700f1a0ddae3258683ffd763952d0102a5c",
)
GLOBAL_TAIL_MANIFEST = (
    23_517,
    "a8667bdfcfa64e3f2498ea4fea806257fdd031f091c21445f7a9c1f27bd705fa",
)
REFERENCE_SOURCE = (
    69_264,
    "4bb9967a56893cf982ffa5189c71f2f50a88a868a1f932f7159dd7613bf80806",
)
BR1CS_SOURCE = (
    53_474,
    "83d9689b635f2ea90cf50ef1f5280f57e138e31bae4dbeb186c97c69f71d2140",
)
TRACE_KDF_SOURCE_TRANSITION_MANIFEST = (
    3_230,
    "3e214be777aa80eb0c94ab1371c911ab578c80ab126c453d7ca66145e1f66d3d",
)
TRACE_KDF_SOURCE_TRANSITION_PATH = (
    ROOT / "manifests/pq_rbbc_trace_kdf_source_transition_manifest_v2_40.json"
)

AGGREGATE_ROWS = 586_057_567
AGGREGATE_MAX_WIRE_ID = 429_757_232
LEGACY_PARENT_ROWS = 2_971_580
LEGACY_PARENT_WIRES = 2_980_304
LEGACY_PARENT_ASSIGNMENT_SHA256 = (
    "7e0a8cb33042c555198f5e8480a0df8c5834152d6280ab24134ac8edc748aee2"
)
CAP_COMMITMENT_SHA256 = (
    "12123e95b1b64d87da7a575dbf803fc53ded9eb9a23b807eeab2cba51dfe5b62"
)

# Exact values of the completed v2.28 aggregate instance.
AGGREGATE_MESSAGE_SHA256 = (
    "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
)
AGGREGATE_MASK_SHA256 = (
    "cd2a8146346df7460e08e63dbf3841e5e89f1de235e2778c3f885fd60459c2ae"
)
AGGREGATE_HASH_IMAGE_SHA256 = (
    "334c47ef8b8fa66d80278388e1ea9b47ab6b6540d558c994d328a1728f9a2bf6"
)

# Exact values of the current deterministic v2.25 parent fixture.
PARENT_MESSAGE_SHA256 = (
    "d270d93873c40df5d4d7fcf651dad7e9653697507bc1a2e70d2651e58f412b78"
)
PARENT_MASK_SHA256 = (
    "3e9b36d0a67531d4fb42490e4662daa0ae3762f6326cc976c7f6eaa52b837b06"
)
PARENT_HASH_IMAGE_SHA256 = (
    "0b472af0678fcf86bbaa8ce8fcd4f4280e088ea516c95692fa2a2c47be60f4aa"
)

PARENT_RUNNER = "src/pq_rbbc_parent_join_replay.py"
PARENT_RUNNER_SHA256 = (
    "44ef975427f4f76bfcc2463b0576de4a5a25b9469313b596a92ed4e6c5db7ef8"
)
PARENT_PREFREEZE = (
    3_514,
    "b6097f9bf795a4084e9bbc3ca2236f63c50aa00080ec007f8af623fcdc34cd37",
)
TRUSTED_EXECUTION_CACHE = (
    35_509_449,
    "4fc980b3408d00418fed15f282a80a2c932b829c002146cc80adb609b3814a38",
)
PARENT_BOUND_MESSAGE_SHA256 = PARENT_MESSAGE_SHA256
PARENT_BOUND_MASK_SHA256 = AGGREGATE_MASK_SHA256
PARENT_BOUND_HASH_IMAGE_SHA256 = (
    "d072c963cb46e3c382b843068525726e90b749e997e598c673a0a41635dcf855"
)
PARENT_BOUND_PUBLIC_Y_SHA256 = (
    "e9b075b1e4990134c535f00db9842c45cd508408859e3d00bbaf3f98784fef68"
)
PARENT_NONCONSTANT_WIRES = 2_980_302
PARENT_WIRE_START = 429_757_233
PARENT_WIRE_END = 432_737_534
NATIVE_JOIN_ROWS = 1_408
JOINED_PARENT_ROWS = 2_972_988
COMBINED_ROWS = 589_030_555


def canonical_json(document: Mapping[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identity(path: Path | None, expected: tuple[int, str]) -> dict[str, object]:
    if path is None:
        return {"provided": False, "verified": False, "failures": ["not_provided"]}
    failures = []
    if not path.is_file():
        failures.append("missing")
    else:
        if path.stat().st_size != expected[0]:
            failures.append("bytes")
        if _sha256(path) != expected[1]:
            failures.append("sha256")
    return {"provided": True, "verified": not failures, "failures": failures}


def _unfrozen_identity(path: Path | None) -> dict[str, object]:
    if path is None:
        return {"provided": False, "verified": False, "failures": ["not_provided"]}
    return {
        "provided": True,
        "verified": False,
        "bytes": path.stat().st_size if path.is_file() else None,
        "sha256": _sha256(path) if path.is_file() else None,
        "failures": ["identity_not_frozen"] if path.is_file() else ["missing"],
    }


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} root must be an object")
    return document


def current_fixture_compatibility() -> dict[str, object]:
    return {
        "message": {
            "aggregate_sha256": AGGREGATE_MESSAGE_SHA256,
            "parent_sha256": PARENT_MESSAGE_SHA256,
            "exact_match": AGGREGATE_MESSAGE_SHA256 == PARENT_MESSAGE_SHA256,
        },
        "derived_mask": {
            "aggregate_sha256": AGGREGATE_MASK_SHA256,
            "parent_sha256": PARENT_MASK_SHA256,
            "exact_match": AGGREGATE_MASK_SHA256 == PARENT_MASK_SHA256,
        },
        "h_rbbc_hash_image": {
            "aggregate_sha256": AGGREGATE_HASH_IMAGE_SHA256,
            "parent_sha256": PARENT_HASH_IMAGE_SHA256,
            "exact_match": AGGREGATE_HASH_IMAGE_SHA256
            == PARENT_HASH_IMAGE_SHA256,
        },
        "all_join_values_match": False,
    }


def validate_source_ports(
    split: Mapping[str, object], tail: Mapping[str, object]
) -> tuple[str, ...]:
    failures: list[str] = []
    ports = {
        item["port_id"]: item
        for item in split.get("phase_contract", {}).get("boundary_ports", [])
        if isinstance(item, dict) and "port_id" in item
    }
    expected_ports = {
        "global.phase-b.commitment": (40_084_506, 43_128, CAP_COMMITMENT_SHA256),
        "global.phase-b.derived-mask": (40_127_634, 576, AGGREGATE_MASK_SHA256),
        "global.phase-b.request-hash": (
            40_194_018,
            576,
            AGGREGATE_HASH_IMAGE_SHA256,
        ),
    }
    for port_id, (wire_start, bit_length, value_sha256) in expected_ports.items():
        port = ports.get(port_id, {})
        if (
            port.get("consumer_wire_start"),
            port.get("bit_length"),
            port.get("value_sha256"),
        ) != (wire_start, bit_length, value_sha256):
            failures.append(f"{port_id}_contract")
    tail_ports = {
        item["port_id"]: item
        for item in tail.get("ports", [])
        if isinstance(item, dict) and "port_id" in item
    }
    message = tail_ports.get("shared.message", {})
    if (
        message.get("consumer_wire_start"),
        message.get("bit_length"),
        message.get("value_sha256"),
    ) != (387, 256, AGGREGATE_MESSAGE_SHA256):
        failures.append("shared.message_contract")
    return tuple(failures)


def validate_tracked_contracts() -> tuple[str, ...]:
    failures: list[str] = []
    tracked = {
        "aggregate_evidence": (
            ROOT
            / "artifacts/metadata/aggregate_recovery_v2_28"
            / "pq_rbbc_cap_aggregate_recovery_evidence_v2_28.json",
            AGGREGATE_EVIDENCE,
        ),
        "br1cs_manifest": (
            ROOT / "manifests/pq_rbbc_br1cs_manifest_v2_25.json",
            BR1CS_MANIFEST,
        ),
        "abi_manifest": (
            ROOT / "manifests/pq_rbbc_blind_uov_abi_manifest_v2_25.json",
            ABI_MANIFEST,
        ),
        "split_tail_evidence": (
            ROOT
            / "artifacts/metadata/production_split_v2_12"
            / "pq_rbbc_cap_production_split_tail_manifest_v2_12.json",
            SPLIT_TAIL_EVIDENCE,
        ),
        "global_tail_manifest": (
            ROOT / "manifests/pq_rbbc_cap_global_tail_manifest_v2_9.json",
            GLOBAL_TAIL_MANIFEST,
        ),
        "reference_source": (ROOT / "src/pq_rbbc_reference.py", REFERENCE_SOURCE),
        "br1cs_source": (ROOT / "src/pq_rbbc_br1cs.py", BR1CS_SOURCE),
    }
    for label, (path, expected) in tracked.items():
        if _identity(path, expected)["verified"]:
            continue
        if label == "reference_source" and not trace_kdf_transition.validate_transition(
            TRACE_KDF_SOURCE_TRANSITION_PATH,
            TRACE_KDF_SOURCE_TRANSITION_MANIFEST,
            ROOT,
        ):
            continue
        failures.append(f"{label}_identity")
    if failures:
        return tuple(failures)

    aggregate = _read_json(tracked["aggregate_evidence"][0])
    if aggregate.get("claim_boundary", {}).get(
        "complete_18_tree_assignment_replayed"
    ) is not True:
        failures.append("aggregate_replay_not_closed")
    if aggregate.get("claim_boundary", {}).get(
        "cross_segment_wire_identity_closed"
    ) is not True:
        failures.append("aggregate_cross_segment_identity_not_closed")

    parent = _read_json(tracked["br1cs_manifest"][0])
    archive = parent.get("archive", {})
    if archive.get("external_assertions") != 1:
        failures.append("legacy_parent_external_assertion_count")
    if archive.get("field") != "F2":
        failures.append("legacy_parent_field")
    if archive.get("total_r1cs_rows") != LEGACY_PARENT_ROWS:
        failures.append("legacy_parent_rows")
    if archive.get("wire_count") != LEGACY_PARENT_WIRES:
        failures.append("legacy_parent_wires")

    abi = _read_json(tracked["abi_manifest"][0])
    if abi.get("fork_profile", {}).get("canonical_cap_commitment_bytes") != 5_391:
        failures.append("canonical_cap_commitment_bytes")

    _, statement, witness, _ = reference.reference_fixture()
    ticket_digest = hashlib.shake_256(
        reference.LABEL_TICKET + statement.payload.encode()
    ).digest(32)
    fixture_digests = {
        "message": hashlib.sha256(ticket_digest).hexdigest(),
        "mask": hashlib.sha256(witness.blind_mask).hexdigest(),
        "hash_image": hashlib.sha256(witness.blind_hash_image).hexdigest(),
    }
    if fixture_digests != {
        "message": PARENT_MESSAGE_SHA256,
        "mask": PARENT_MASK_SHA256,
        "hash_image": PARENT_HASH_IMAGE_SHA256,
    }:
        failures.append("parent_fixture_value_identity")

    split = _read_json(tracked["split_tail_evidence"][0])
    tail = _read_json(tracked["global_tail_manifest"][0])
    failures.extend(validate_source_ports(split, tail))
    return tuple(failures)


def build_frozen_manifest() -> dict[str, object]:
    tracked_failures = list(validate_tracked_contracts())
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "prerequisite": {
            "aggregate_evidence": {
                "bytes": AGGREGATE_EVIDENCE[0],
                "sha256": AGGREGATE_EVIDENCE[1],
                "aggregate_rows": AGGREGATE_ROWS,
                "aggregate_max_wire_id": AGGREGATE_MAX_WIRE_ID,
            },
            "tracked_contract_validation_failures": tracked_failures,
        },
        "legacy_parent": {
            "archive": {
                "bytes": INCREMENTAL_BR1CS[0],
                "sha256": INCREMENTAL_BR1CS[1],
                "field": "F2",
                "rows": LEGACY_PARENT_ROWS,
                "wires": LEGACY_PARENT_WIRES,
                "external_assertions": 1,
                "assignment_sha256": LEGACY_PARENT_ASSIGNMENT_SHA256,
            },
            "external_assertion_id": (
                "native_pq_rbbc_cap_v1_full_18_tree_row_stream_and_h_rbbc_wire_join"
            ),
            "directly_joinable_to_gf193_aggregate": False,
        },
        "join_contract": {
            "relation_id": PARENT_JOIN_RELATION_ID,
            "target_field": "GF(2^193)",
            "message_bits": 256,
            "cap_commitment_bits": 43_128,
            "mask_bits": 576,
            "hash_image_bits": 576,
            "public_target_bits": 576,
            "source_ports": [
                {
                    "port_id": "shared.message",
                    "wire_start": 387,
                    "bit_length": 256,
                    "value_sha256": AGGREGATE_MESSAGE_SHA256,
                },
                {
                    "port_id": "global.phase-b.commitment",
                    "wire_start": 40_084_506,
                    "bit_length": 43_128,
                    "value_sha256": CAP_COMMITMENT_SHA256,
                },
                {
                    "port_id": "global.phase-b.derived-mask",
                    "wire_start": 40_127_634,
                    "bit_length": 576,
                    "value_sha256": AGGREGATE_MASK_SHA256,
                },
                {
                    "port_id": "global.phase-b.request-hash",
                    "wire_start": 40_194_018,
                    "bit_length": 576,
                    "value_sha256": AGGREGATE_HASH_IMAGE_SHA256,
                },
            ],
            "required_parent_destinations": [
                "circuit-produced ticket digest",
                "native H_RBBC commitment input",
                "blind mask witness",
                "blind hash-image witness",
                "public y = mask + hash-image",
            ],
            "planned_join_rows": NATIVE_JOIN_ROWS,
            "planned_parent_rows": JOINED_PARENT_ROWS,
            "planned_combined_rows": COMBINED_ROWS,
            "planned_join_wires": PARENT_NONCONSTANT_WIRES,
            "planned_parent_wire_interval": [PARENT_WIRE_START, PARENT_WIRE_END],
            "target_external_assertions": 0,
        },
        "current_fixture_compatibility": current_fixture_compatibility(),
        "parent_bound_fixture": {
            "ticket_payload_and_lifecycle_unchanged": True,
            "message_sha256": PARENT_BOUND_MESSAGE_SHA256,
            "commitment_sha256": CAP_COMMITMENT_SHA256,
            "derived_mask_sha256": PARENT_BOUND_MASK_SHA256,
            "h_rbbc_hash_image_sha256": PARENT_BOUND_HASH_IMAGE_SHA256,
            "public_y_sha256": PARENT_BOUND_PUBLIC_Y_SHA256,
        },
        "required_external_artifacts": {
            "incremental_parent_br1cs": {
                "bytes": INCREMENTAL_BR1CS[0],
                "sha256": INCREMENTAL_BR1CS[1],
                "legacy_input_only": True,
            },
            "parent_bound_aggregate_evidence": {
                "bytes": None,
                "sha256": None,
                "identity_frozen": False,
            },
            "joined_parent_archive": {
                "bytes": None,
                "sha256": None,
                "identity_frozen": False,
            },
            "joined_parent_assignment": {
                "bytes": None,
                "sha256": None,
                "identity_frozen_after_preparation": False,
            },
            "parent_join_prefreeze": {
                "bytes": PARENT_PREFREEZE[0],
                "sha256": PARENT_PREFREEZE[1],
            },
            "trusted_local_execution_cache": {
                "bytes": TRUSTED_EXECUTION_CACHE[0],
                "sha256": TRUSTED_EXECUTION_CACHE[1],
                "semantic_identity_rechecked_by_runner": True,
            },
            "downloaded_pickle_accepted": False,
        },
        "runner_requirement": {
            "path": PARENT_RUNNER,
            "sha256": PARENT_RUNNER_SHA256,
            "implemented": True,
            "required_features": [
                "lift_parent_boolean_rows_into_gf193_without_mixed_field_aliasing",
                "replace_the_single_external_assertion_with_native_wire_links",
                "bind_ticket_digest_commitment_mask_hash_image_and_public_y",
                "stream_parent_bound_aggregate_and_parent_assignment_read_only",
                "reject_message_commitment_mask_hash_image_and_y_mutations",
                "emit_identity_bound_json_checkpoint_without_pickle",
                "emit_path_free_evidence_with_security_and_production_claims_false",
            ],
        },
        "evidence_requirements": {
            "honest_join_accepts": True,
            "verification_failures": 0,
            "external_assertions": 0,
            "archive_round_trip_verified": True,
            "witness_independent_topology": True,
            "required_mutation_rejections": [
                "message",
                "cap_commitment",
                "derived_mask",
                "h_rbbc_hash_image",
                "public_y",
                "wrong_wire_interval",
                "mixed_field_alias",
                "archive_corruption",
            ],
        },
        "resource_floor": {
            "minimum_available_memory_bytes": 16_000_000_000,
            "minimum_free_disk_bytes": 64_000_000_000,
            "workers": 8,
            "estimated_new_external_bytes": 1_160_000_000,
            "estimated_parent_bound_preparation_seconds": [2_400, 3_300],
            "estimated_full_replay_seconds": [8_000, 12_000],
            "sizing_is_preliminary_until_runtime_completion": True,
        },
        "claim_boundary": {
            "parent_join_preflight_contract_closed": not tracked_failures,
            "v2_28_aggregate_prerequisite_verified": not tracked_failures,
            "parent_bound_aggregate_instance_available": False,
            "parent_join_runner_implemented": True,
            "parent_join_accounting_frozen": True,
            "parent_join_external_artifacts_verified": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
            "system_architecture_changed": False,
            "ticket_lifecycle_changed": False,
            "pq_sat_auth_changed": False,
        },
    }


def _legacy_parent_check(path: Path | None) -> dict[str, object]:
    result = _identity(path, INCREMENTAL_BR1CS)
    if not result["verified"] or path is None:
        return result
    failures: list[str] = []
    with path.open("rb") as stream:
        header = br1cs.read_header(stream)
    if header.total_r1cs_rows != LEGACY_PARENT_ROWS:
        failures.append("header_rows")
    if header.wire_count != LEGACY_PARENT_WIRES:
        failures.append("header_wires")
    if header.external_assertions != 1:
        failures.append("header_external_assertions")
    return {**result, "verified": not failures, "failures": failures, "header": {
        "field": "F2",
        "rows": header.total_r1cs_rows,
        "wires": header.wire_count,
        "external_assertions": header.external_assertions,
    }}


def _parent_prefreeze_check(path: Path | None) -> dict[str, object]:
    result = _identity(path, PARENT_PREFREEZE)
    if not result["verified"] or path is None:
        return result
    document = _read_json(path)
    failures: list[str] = []
    if document.get("format") != "PQRBBC-PARENT-JOIN-PREFREEZE-1":
        failures.append("format")
    if document.get("relation_id") != PARENT_JOIN_RELATION_ID:
        failures.append("relation_id")
    accounting = document.get("accounting", {})
    if not isinstance(accounting, dict) or accounting != {
        "aggregate_max_wire_id": AGGREGATE_MAX_WIRE_ID,
        "aggregate_rows": AGGREGATE_ROWS,
        "combined_rows": COMBINED_ROWS,
        "external_assertions": 0,
        "native_join_rows": NATIVE_JOIN_ROWS,
        "parent_internal_rows": LEGACY_PARENT_ROWS,
        "parent_join_rows": JOINED_PARENT_ROWS,
        "parent_local_wires": LEGACY_PARENT_WIRES,
        "parent_nonconstant_wires": PARENT_NONCONSTANT_WIRES,
        "parent_wire_interval": [PARENT_WIRE_START, PARENT_WIRE_END],
    }:
        failures.append("accounting")
    binding = document.get("binding", {})
    if not isinstance(binding, dict) or binding != {
        "commitment_bytes": 5_391,
        "commitment_sha256": CAP_COMMITMENT_SHA256,
        "derived_mask_sha256": PARENT_BOUND_MASK_SHA256,
        "h_rbbc_hash_image_sha256": PARENT_BOUND_HASH_IMAGE_SHA256,
        "message_sha256": PARENT_BOUND_MESSAGE_SHA256,
        "public_y_sha256": PARENT_BOUND_PUBLIC_Y_SHA256,
    }:
        failures.append("binding")
    round_trip = document.get("round_trip", {})
    if (
        not isinstance(round_trip, dict)
        or round_trip.get("satisfied") is not True
        or round_trip.get("rows_checked") != JOINED_PARENT_ROWS
        or round_trip.get("join_rows_checked") != NATIVE_JOIN_ROWS
        or round_trip.get("failed_constraints") != 0
        or round_trip.get("external_assertions") != 0
    ):
        failures.append("round_trip")
    probes = document.get("mutation_probes", {})
    if (
        not isinstance(probes, dict)
        or probes.get("all_required_mutations_rejected") is not True
    ):
        failures.append("mutation_probes")
    return {**result, "verified": not failures, "failures": failures}


def exact_preparation_command(
    execution_cache: Path, parent_prefreeze: Path
) -> str:
    del parent_prefreeze  # Its identity gates this command; the runner regenerates rows.
    root = "/tmp/pq_rbbc_external_artifacts_rebuilt/v2_29_parent_join"
    return " \\\n".join((
        "PYTHONPATH=src python -u src/pq_rbbc_parent_join_replay.py",
        "  --prepare-parent-bound",
        f"  --trusted-composer-execution-cache {execution_cache}",
        f"  --global-archive {root}/pq_rbbc_parent_bound_global_tail_v2_29.f193assign",
        f"  --global-manifest {root}/pq_rbbc_parent_bound_global_tail_manifest_v2_29.json",
        f"  --parent-archive {root}/pq_rbbc_parent_join_v2_29.gf193",
        f"  --parent-assignment {root}/pq_rbbc_parent_assignment_v2_29.gf193",
        f"  --manifest {root}/pq_rbbc_parent_join_preparation_manifest_v2_29.json",
        "  --workers 8",
    ))


def build_environment_report(
    aggregate_evidence: Path | None,
    incremental_br1cs: Path | None,
    parent_prefreeze: Path | None,
    trusted_execution_cache: Path | None,
    free_disk_bytes: int,
    available_memory_bytes: int,
) -> dict[str, object]:
    runner_path = ROOT / PARENT_RUNNER
    runner_failures = []
    if not runner_path.is_file():
        runner_failures.append("not_implemented")
    elif PARENT_RUNNER_SHA256 is None:
        runner_failures.append("runner_identity_not_frozen")
    elif _sha256(runner_path) != PARENT_RUNNER_SHA256:
        runner_failures.append("runner_sha256")
    static_failures = list(validate_tracked_contracts())
    checks = {
        "tracked_contracts": {
            "verified": not static_failures,
            "failures": static_failures,
        },
        "aggregate_recovery_evidence": _identity(
            aggregate_evidence, AGGREGATE_EVIDENCE
        ),
        "incremental_parent_br1cs": _legacy_parent_check(incremental_br1cs),
        "parent_join_prefreeze": _parent_prefreeze_check(parent_prefreeze),
        "trusted_local_execution_cache": _identity(
            trusted_execution_cache, TRUSTED_EXECUTION_CACHE
        ),
        "parent_join_runner": {
            "provided": runner_path.is_file(),
            "verified": not runner_failures,
            "failures": runner_failures,
        },
        "planned_join_accounting": {
            "verified": True,
            "failures": [],
            "native_join_rows": NATIVE_JOIN_ROWS,
            "parent_join_rows": JOINED_PARENT_ROWS,
            "combined_rows": COMBINED_ROWS,
            "parent_wire_interval": [PARENT_WIRE_START, PARENT_WIRE_END],
        },
        "resources": {
            "verified": (
                free_disk_bytes >= 64_000_000_000
                and available_memory_bytes >= 16_000_000_000
            ),
            "free_disk_bytes": free_disk_bytes,
            "available_memory_bytes": available_memory_bytes,
            "preliminary": False,
        },
    }
    ready = all(item["verified"] for item in checks.values())
    blockers = [name for name, item in checks.items() if not item["verified"]]
    return {
        "format": "PQRBBC-PARENT-JOIN-ENVIRONMENT-PREFLIGHT-1",
        "implementation_version": IMPLEMENTATION_VERSION,
        "checks": checks,
        "blockers": blockers,
        "safe_to_start_large_replay": ready,
        "large_replay_started": False,
        "exact_execution_command": (
            exact_preparation_command(trusted_execution_cache, parent_prefreeze)
            if ready
            and trusted_execution_cache is not None
            and parent_prefreeze is not None
            else None
        ),
        "exact_command_withheld_reason": None if ready else (
            "one or more frozen prerequisite, runner, or resource checks failed"
        ),
        "expected_next_outputs": {
            "parent_bound_global_tail_assignment": "identity frozen after preparation",
            "parent_bound_global_tail_manifest": "identity frozen after preparation",
            "joined_parent_archive": "identity frozen after preparation",
            "joined_parent_assignment": "identity frozen after preparation",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print-frozen", action="store_true")
    parser.add_argument("--write-frozen", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--aggregate-evidence", type=Path)
    parser.add_argument("--incremental-br1cs", type=Path)
    parser.add_argument("--parent-prefreeze", type=Path)
    parser.add_argument("--trusted-composer-execution-cache", type=Path)
    parser.add_argument("--free-disk-bytes", type=int, default=0)
    parser.add_argument("--available-memory-bytes", type=int, default=0)
    args = parser.parse_args()
    if args.print_frozen:
        print(canonical_json(build_frozen_manifest()).decode(), end="")
        return
    if args.write_frozen is not None:
        args.write_frozen.parent.mkdir(parents=True, exist_ok=True)
        args.write_frozen.write_bytes(canonical_json(build_frozen_manifest()))
        print(_sha256(args.write_frozen))
        return
    if args.report is None:
        parser.error("--report, --print-frozen, or --write-frozen is required")
    report = build_environment_report(
        args.aggregate_evidence,
        args.incremental_br1cs,
        args.parent_prefreeze,
        args.trusted_composer_execution_cache,
        args.free_disk_bytes,
        args.available_memory_bytes,
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_bytes(canonical_json(report))
    print(json.dumps({
        "report": str(args.report),
        "safe_to_start_large_replay": report["safe_to_start_large_replay"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
