#!/usr/bin/env python3
"""Read-only CAP576/1472 native-lowering preflight for issuance.

This checkpoint freezes the production child-port ABI and the same-bytes
handoff for the formal 1,036-byte CAP randomness witness ``rho``.  It also
executes a four-leaf, production-width, explicitly insecure/test-only shard
through the existing streaming native lowerer.  It never starts the frozen
18-tree replay, writes an assignment/row archive, or produces ``pi_issue``.

The historical shard engine maps unsupported tree shapes to an old 2,048-leaf
relation name.  This module records that namespace alias as a blocker instead
of promoting the bounded shard to a production relation identity.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from functools import lru_cache
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_production_namespace as namespace
import pq_rbbc_cap_shard_stream as shard
import pq_rbbc_issuance_production_inputs_v1 as production_inputs
import pq_rbbc_issuance_zk_backend_preflight as backend_preflight


IMPLEMENTATION_VERSION = "1.0"
FORMAT = "PQRBBC-ISSUANCE-CAP576-NATIVE-PREFLIGHT-1"
EVIDENCE_FORMAT = "PQRBBC-ISSUANCE-CAP576-NATIVE-PORTABLE-EVIDENCE-1"
RELATION_ID = "pq-rbbc/issuance/cap576-native/preflight/v1"
BOUNDED_RELATION_ID = "pq-rbbc/issuance/cap576-native/4leaf-insecure-test-only/v1"
ROOT = Path(__file__).resolve().parents[1]

DOMAIN_BOUNDED = b"PQ-RBBC/ISSUANCE-CAP576-NATIVE-PREFLIGHT/BOUNDED-SHARD/V1"
PRODUCTION_PROFILE = cap.profile_fingerprint(cap.PRODUCTION_PARAMETERS)
PRODUCTION_RHO_BYTES = len(
    cap.deterministic_randomness(cap.PRODUCTION_PARAMETERS).serialize(
        cap.PRODUCTION_PARAMETERS
    )
)

BOUNDED_CAP576_PARAMETERS = cap.CAPParameters(
    name="PQ-RBBC-ISSUANCE-CAP576-NATIVE-4LEAF-INSECURE-TEST-ONLY",
    security_bits=0,
    mask_bits=576,
    appended_signature_bits=1472,
    degree=2,
    rho=16,
    consistency_points=2,
    tree_specs=(cap.TreeSpec(1, 4),),
    secure_profile=False,
)
BOUNDED_PROFILE = cap.profile_fingerprint(BOUNDED_CAP576_PARAMETERS)
ENGINE_PROFILE_NAME, ENGINE_RELATION_ID = shard.shard_profile(
    BOUNDED_CAP576_PARAMETERS
)


TRACKED_PREREQUISITES = {
    "production_inputs": (
        "src/pq_rbbc_issuance_production_inputs_v1.py",
        40_304,
        "7f57417efcea41bc94f477966dfaf629475b39b0ed1c0a4e389d4de10657357f",
    ),
    "reduced_constraint": (
        "src/pq_rbbc_issuance_reduced_constraint_v1.py",
        41_428,
        "8b6e71119a70f7a9bf78875fb8a93cf86e7ecfbb7e2184e0880977a62e668620",
    ),
    "reduced_constraint_manifest": (
        "manifests/pq_rbbc_issuance_reduced_constraint_manifest_v1.json",
        4_517,
        "15fd88aceadc138b43737b1a5bb665598f406f8377c5a539011a09e23ed78820",
    ),
    "reduced_constraint_evidence": (
        "artifacts/metadata/issuance_reduced_constraint_v1/"
        "pq_rbbc_issuance_reduced_constraint_portable_evidence_v1.json",
        2_200,
        "d0c3d6a235dbe13ca8667f79bd434720e2eb9dcf0352e17d82be3d47ef6fd3fc",
    ),
    "cap_commit": (
        "src/pq_rbbc_cap_commit.py",
        32_526,
        "be3a2a767561f009acc2a274a85410ae6e02e23abd24145aa1d61883dd2dceee",
    ),
    "cap_shard_stream": (
        "src/pq_rbbc_cap_shard_stream.py",
        75_409,
        "c54f34a797022723d029e262b8e0a99cf0461e6499d78cb8e8a5a8f93e56b8a2",
    ),
    "cap_global_tail": (
        "src/pq_rbbc_cap_global_tail.py",
        53_133,
        "09d6806a50412c8a6e2e9fcca9c1111305f597e069c4b20057529dd38351a3dd",
    ),
    "cap_namespace": (
        "src/pq_rbbc_cap_production_namespace.py",
        26_130,
        "292a6df8458581a2b00ac5d4f5d7b3fba5ef5cbf88cf3c73fac9a72347a76a27",
    ),
    "global_tail_manifest": (
        "manifests/pq_rbbc_cap_global_tail_manifest_v2_9.json",
        23_517,
        "a8667bdfcfa64e3f2498ea4fea806257fdd031f091c21445f7a9c1f27bd705fa",
    ),
    "parent_join_preflight_manifest": (
        "manifests/pq_rbbc_parent_join_preflight_manifest_v2_29.json",
        5_731,
        "4e83d260121df7bc9f73f03a3c427f494577cdcabb8808a9e67a2987d137ab78",
    ),
    "parent_join_evidence": (
        "artifacts/metadata/parent_join_recovery_v2_29/"
        "pq_rbbc_parent_join_recovery_evidence_v2_29.json",
        5_695,
        "1281afaee1d5d784390ee51c96c66ecc7f486ef4b4b7933590826a708f81b20e",
    ),
}


FROZEN_BOUNDED = {
    "append_base_sha256": "63ee576118b5f37455a2029a89867397942b23a838da1345e0fb0ad64460120e",
    "assignment_materialized": False,
    "commitment_bytes": 206,
    "commitment_sha256": "159858fc070cdaa92d0358aabf130c01d024046ad3032fe18eadc8ae1888baa9",
    "derived_mask_sha256": "9686727acebd24d4d815fa0d3f3873696f32e5acd301269c2abd7b40804b4550",
    "external_assertions": 0,
    "linear_rows": 20_913,
    "nonlinear_rows": 52_136,
    "request_hash_sha256": "0d360c5512f5ab9e43e2d4d3afe8ff2d55a48d0fe44e22d4d74bc8227a67a613",
    "rows": 73_049,
    "spool_bytes": 77_888,
    "spool_sha256": "fef9327e5de0c7859db5657a80114efdec692a878cd407f6fe1ccbc259ab8e5c",
    "stream_bytes": 46_392_022,
    "stream_sha256": "635c6efaf3aa25d6f2d787450987b08712de5aaacd21f3107a90f5db9599b0cd",
    "verification_failures": 0,
    "wires": 53_032,
    "xof_calls": 14,
}


PRODUCTION_CHILD_PORTS = (
    {
        "port_id": "shared.message",
        "wire_start": 387,
        "bit_length": 256,
        "wire_end": 642,
        "role": "ticket-message input and native parent equality",
    },
    {
        "port_id": "global.phase-b.commitment",
        "wire_start": 40_084_506,
        "bit_length": 43_128,
        "wire_end": 40_127_633,
        "role": "canonical CAP commitment consumed by parent H_RBBC",
    },
    {
        "port_id": "global.phase-b.derived-mask",
        "wire_start": 40_127_634,
        "bit_length": 576,
        "wire_end": 40_128_209,
        "role": "blind-mask witness and native parent equality",
    },
    {
        "port_id": "global.phase-b.append-base",
        "wire_start": 40_128_210,
        "bit_length": 1_472,
        "wire_end": 40_129_681,
        "role": "CAP appended-signature witness; not a parent public input",
    },
    {
        "port_id": "global.phase-b.request-hash",
        "wire_start": 40_194_018,
        "bit_length": 576,
        "wire_end": 40_194_593,
        "role": "H_RBBC image and native parent equality",
    },
)


HISTORICAL_REUSE_ALLOWED = frozenset(
    {
        "topology",
        "wire_intervals",
        "row_accounting",
        "source_identity",
        "implementation_semantics",
    }
)
HISTORICAL_REUSE_FORBIDDEN = frozenset(
    {
        "assignment",
        "witness",
        "private_rho",
        "observed_values",
        "commitment_value",
        "mask_value",
        "request_hash_value",
        "other_tree_observed_stream_bytes",
    }
)


class NativePreflightError(ValueError):
    """A native-lowering input or frozen prerequisite is invalid."""


class ProductionNativeLoweringUnavailable(RuntimeError):
    """Production execution was requested before this gate is qualified."""


def canonical_json(document: object) -> bytes:
    return (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _identity(path: Path) -> dict[str, object]:
    return {
        "filename": path.name,
        "bytes": path.stat().st_size,
        "sha256": _sha256_file(path),
    }


def validate_tracked_prerequisites() -> tuple[str, ...]:
    failures = []
    for name, (relative, expected_bytes, expected_sha256) in TRACKED_PREREQUISITES.items():
        path = ROOT / relative
        if not path.is_file():
            failures.append(f"{name}:missing")
            continue
        if path.stat().st_size != expected_bytes:
            failures.append(f"{name}:bytes")
        if _sha256_file(path) != expected_sha256:
            failures.append(f"{name}:sha256")
    return tuple(failures)


@dataclass(frozen=True)
class RhoSnapshotV1:
    """One immutable copy used for identity, parsing, and all child inputs."""

    raw: bytes
    sha256: str
    profile_fingerprint: str
    randomness: cap.CAPRandomness


def capture_production_rho(raw: bytes) -> RhoSnapshotV1:
    """Copy and strictly parse one production-rho byte string exactly once."""

    if type(raw) is not bytes:
        raise NativePreflightError("production rho must be immutable bytes")
    captured = memoryview(raw).tobytes()
    try:
        backend_preflight.validate_cap_randomness_encoding(captured)
        randomness = production_inputs.decode_cap_randomness(
            cap.PRODUCTION_PARAMETERS, captured
        )
    except (backend_preflight.CanonicalEncodingError, production_inputs.ProductionInputsError) as error:
        raise NativePreflightError(str(error)) from error
    if randomness.serialize(cap.PRODUCTION_PARAMETERS) != captured:
        raise NativePreflightError("noncanonical production rho")
    return RhoSnapshotV1(
        raw=captured,
        sha256=hashlib.sha256(captured).hexdigest(),
        profile_fingerprint=PRODUCTION_PROFILE,
        randomness=randomness,
    )


def production_rho_layout() -> tuple[dict[str, object], ...]:
    magic_end = len(cap.RANDOMNESS_MAGIC)
    layout: list[dict[str, object]] = [
        {"field": "magic", "byte_start": 0, "byte_end_exclusive": magic_end},
        {
            "field": "profile_fingerprint_ascii",
            "byte_start": magic_end,
            "byte_end_exclusive": magic_end + 64,
        },
        {"field": "salt[0]", "byte_start": magic_end + 64, "byte_end_exclusive": magic_end + 89},
        {"field": "salt[1]", "byte_start": magic_end + 89, "byte_end_exclusive": magic_end + 114},
        {"field": "tree_count", "byte_start": magic_end + 114, "byte_end_exclusive": magic_end + 116},
    ]
    roots_start = magic_end + 116
    for tree_index in range(cap.PRODUCTION_PARAMETERS.tree_count):
        start = roots_start + 50 * tree_index
        layout.extend(
            (
                {
                    "field": f"root[{tree_index}][0]",
                    "byte_start": start,
                    "byte_end_exclusive": start + 25,
                },
                {
                    "field": f"root[{tree_index}][1]",
                    "byte_start": start + 25,
                    "byte_end_exclusive": start + 50,
                },
            )
        )
    if layout[-1]["byte_end_exclusive"] != PRODUCTION_RHO_BYTES:
        raise AssertionError("production rho layout length mismatch")
    return tuple(layout)


def historical_reuse_permitted(kind: str) -> bool:
    if kind in HISTORICAL_REUSE_FORBIDDEN:
        return False
    if kind not in HISTORICAL_REUSE_ALLOWED:
        raise NativePreflightError("unrecognized historical reuse class")
    return True


def execute_production_native_lowering(*_args: object, **_kwargs: object) -> None:
    """Fail before decoding rho, reopening paths, or constructing CAP traces."""

    raise ProductionNativeLoweringUnavailable(
        "production CAP576/1472 lowering is not enabled by this preflight"
    )


def _bounded_once(label: bytes) -> tuple[shard.ShardTraceSummary, cap.CAPExecution]:
    parameters = BOUNDED_CAP576_PARAMETERS
    randomness = cap.deterministic_randomness(parameters, DOMAIN_BOUNDED + label)
    message = hashlib.sha256(DOMAIN_BOUNDED + b"/message").digest()
    execution = shard.build_parallel_execution(parameters, randomness, workers=2)
    summary = shard.build_streaming_shard(
        parameters,
        randomness,
        message,
        workers=2,
        execution=execution,
    )
    return summary, execution


def _bounded_observation(
    summary: shard.ShardTraceSummary, execution: cap.CAPExecution
) -> dict[str, object]:
    parameters = summary.parameters
    return {
        "wires": summary.wires,
        "rows": summary.rows,
        "nonlinear_rows": summary.nonlinear_rows,
        "linear_rows": summary.linear_rows,
        "stream_bytes": summary.stream_bytes,
        "stream_sha256": summary.stream_sha256,
        "spool_bytes": summary.spool_bytes,
        "spool_sha256": summary.spool_sha256,
        "xof_calls": summary.xof_calls,
        "commitment_bytes": len(summary.commitment_bytes),
        "commitment_sha256": hashlib.sha256(summary.commitment_bytes).hexdigest(),
        "derived_mask_sha256": hashlib.sha256(
            cap.pack_int(execution.commitment.derived_mask, parameters.mask_bits)
        ).hexdigest(),
        "append_base_sha256": hashlib.sha256(
            cap.pack_int(
                execution.commitment.append_base,
                parameters.appended_signature_bits,
            )
        ).hexdigest(),
        "request_hash_sha256": hashlib.sha256(summary.request_hash_bytes).hexdigest(),
        "assignment_materialized": summary.assignment_materialized,
        "external_assertions": summary.external_assertions,
        "verification_failures": summary.verification_failures,
    }


@lru_cache(maxsize=1)
def bounded_shard_self_check() -> dict[str, object]:
    first_summary, first_execution = _bounded_once(b"/rho-a")
    second_summary, second_execution = _bounded_once(b"/rho-b")
    first = _bounded_observation(first_summary, first_execution)
    second = _bounded_observation(second_summary, second_execution)
    failures = [
        name for name, expected in FROZEN_BOUNDED.items() if first.get(name) != expected
    ]
    shape_invariant = (
        first["stream_sha256"] == second["stream_sha256"]
        and first["spool_sha256"] == second["spool_sha256"]
        and first["rows"] == second["rows"]
        and first["wires"] == second["wires"]
    )
    values_changed = (
        first["commitment_sha256"] != second["commitment_sha256"]
        and first["derived_mask_sha256"] != second["derived_mask_sha256"]
        and first["request_hash_sha256"] != second["request_hash_sha256"]
    )
    return {
        "relation_id": BOUNDED_RELATION_ID,
        "test_only": True,
        "secure_profile": False,
        "production_widths": {
            "mask_bits": BOUNDED_CAP576_PARAMETERS.mask_bits,
            "appended_signature_bits": BOUNDED_CAP576_PARAMETERS.appended_signature_bits,
            "witness_bits": BOUNDED_CAP576_PARAMETERS.witness_bits,
            "random_polynomial_bits": BOUNDED_CAP576_PARAMETERS.random_polynomial_bits,
        },
        "tiny_topology": {
            "trees": 1,
            "leaves": 4,
            "extension_degree": 3,
        },
        "engine_reported_profile_name": ENGINE_PROFILE_NAME,
        "engine_reported_relation_id": ENGINE_RELATION_ID,
        "engine_namespace_alias_detected": ENGINE_RELATION_ID != BOUNDED_RELATION_ID,
        "engine_namespace_production_eligible": False,
        "first_observation": first,
        "witness_independent_topology": shape_invariant,
        "rho_mutation_changes_bound_outputs": values_changed,
        "frozen_mismatches": failures,
        "large_relation_rows_replayed": 0,
        "cryptographic_proofs_generated": 0,
    }


def _is_path_free(value: object) -> bool:
    if isinstance(value, str):
        return not value.startswith(("/", "file:"))
    if isinstance(value, list):
        return all(_is_path_free(item) for item in value)
    if isinstance(value, dict):
        return all(_is_path_free(item) for item in value.values())
    return True


def validate_v2_29_historical_evidence() -> tuple[str, ...]:
    relative = TRACKED_PREREQUISITES["parent_join_evidence"][0]
    path = ROOT / relative
    if not path.is_file():
        return ("parent_join_evidence:missing",)
    failures: list[str] = []
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return (f"parent_join_evidence:parse:{error}",)
    if type(document) is not dict:
        return ("parent_join_evidence:not_object",)
    accounting = document.get("accounting")
    boundary = document.get("claim_boundary")
    policy = document.get("artifact_policy")
    if document.get("format") != "PQRBBC-PARENT-JOIN-RECOVERY-EVIDENCE-1":
        failures.append("parent_join_evidence:format")
    if not isinstance(accounting, Mapping) or accounting.get("combined_rows") != 589_030_555:
        failures.append("parent_join_evidence:combined_rows")
    if not isinstance(accounting, Mapping) or accounting.get("native_join_rows") != 1_408:
        failures.append("parent_join_evidence:native_join_rows")
    if not isinstance(accounting, Mapping) or accounting.get("verification_failures") != 0:
        failures.append("parent_join_evidence:verification_failures")
    if not isinstance(accounting, Mapping) or accounting.get("external_assertions") != 0:
        failures.append("parent_join_evidence:external_assertions")
    if not isinstance(boundary, Mapping) or boundary.get("parent_cap_to_h_rbbc_join_closed") is not True:
        failures.append("parent_join_evidence:parent_join")
    if not isinstance(boundary, Mapping) or boundary.get("production_closed") is not False:
        failures.append("parent_join_evidence:production_claim")
    if not isinstance(policy, Mapping) or any(value is not False for key, value in policy.items() if key != "portable_evidence_contains_absolute_paths"):
        failures.append("parent_join_evidence:artifact_policy")
    if not isinstance(policy, Mapping) or policy.get("portable_evidence_contains_absolute_paths") is not False:
        failures.append("parent_join_evidence:path_claim")
    if not _is_path_free(document):
        failures.append("parent_join_evidence:absolute_path")
    return tuple(failures)


def validate_child_port_contract() -> tuple[str, ...]:
    failures: list[str] = []
    path = ROOT / TRACKED_PREREQUISITES["parent_join_preflight_manifest"][0]
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        frozen = {
            port["port_id"]: (port["wire_start"], port["bit_length"])
            for port in document["join_contract"]["source_ports"]
        }
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        return (f"parent_port_manifest:{error}",)
    expected = {
        port["port_id"]: (port["wire_start"], port["bit_length"])
        for port in PRODUCTION_CHILD_PORTS
        if port["port_id"] != "global.phase-b.append-base"
    }
    if frozen != expected:
        failures.append("parent_port_manifest:intervals")
    ordered = sorted(PRODUCTION_CHILD_PORTS, key=lambda item: int(item["wire_start"]))
    for left, right in zip(ordered, ordered[1:]):
        if int(left["wire_end"]) >= int(right["wire_start"]):
            failures.append("child_ports:overlap")
    if sum(
        int(port["bit_length"])
        for port in PRODUCTION_CHILD_PORTS
        if port["port_id"] in (
            "shared.message",
            "global.phase-b.derived-mask",
            "global.phase-b.request-hash",
        )
    ) != 1_408:
        failures.append("child_ports:native_join_count")
    return tuple(failures)


def read_only_preflight(artifact_root: Path) -> dict[str, object]:
    candidate = production_inputs.evaluate_candidate_set(
        production_inputs.read_candidate_set(artifact_root)
    )
    tracked_failures = list(validate_tracked_prerequisites())
    historical_failures = list(validate_v2_29_historical_evidence())
    port_failures = list(validate_child_port_contract())
    return {
        "format": FORMAT,
        "relation_id": RELATION_ID,
        "read_only": True,
        "production_input_report": candidate,
        "tracked_validation_failures": tracked_failures,
        "historical_evidence_validation_failures": historical_failures,
        "child_port_validation_failures": port_failures,
        "v2_29_reuse_allowed": sorted(HISTORICAL_REUSE_ALLOWED),
        "v2_29_reuse_forbidden": sorted(HISTORICAL_REUSE_FORBIDDEN),
        "formal_rho_runtime_snapshot_present": False,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
        "production_relation_instantiated": False,
        "formal_pi_issue_generated": False,
        "output_created": False,
    }


def build_manifest() -> dict[str, object]:
    bounded = bounded_shard_self_check()
    tracked_failures = list(validate_tracked_prerequisites())
    historical_failures = list(validate_v2_29_historical_evidence())
    port_failures = list(validate_child_port_contract())
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "production_profile": {
            "profile_fingerprint": PRODUCTION_PROFILE,
            "tree_count": cap.PRODUCTION_PARAMETERS.tree_count,
            "tree_specs": [asdict(item) for item in cap.PRODUCTION_PARAMETERS.tree_specs],
            "mask_bits": cap.PRODUCTION_PARAMETERS.mask_bits,
            "appended_signature_bits": cap.PRODUCTION_PARAMETERS.appended_signature_bits,
            "witness_bits": cap.PRODUCTION_PARAMETERS.witness_bits,
            "random_polynomial_bits": cap.PRODUCTION_PARAMETERS.random_polynomial_bits,
            "commitment_bytes": cap.commitment_bytes(cap.PRODUCTION_PARAMETERS),
        },
        "production_rho_handoff": {
            "canonical_bytes": PRODUCTION_RHO_BYTES,
            "profile_fingerprint": PRODUCTION_PROFILE,
            "layout": list(production_rho_layout()),
            "single_immutable_raw_snapshot": True,
            "identity_parse_and_all_child_inputs_use_same_raw": True,
            "future_executor_may_reopen_rho_pathname": False,
            "rho_is_per_issuance_private_witness": True,
            "rho_is_global_external_artifact": False,
            "rho_value_instantiated": False,
        },
        "production_child_ports": {
            "ports": list(PRODUCTION_CHILD_PORTS),
            "native_parent_join_bits": 1_408,
            "fresh_values_required_per_issuance": True,
            "historical_value_digests_are_execution_inputs": False,
        },
        "historical_v2_29_reuse": {
            "evidence_identity": {
                "path": TRACKED_PREREQUISITES["parent_join_evidence"][0],
                "bytes": TRACKED_PREREQUISITES["parent_join_evidence"][1],
                "sha256": TRACKED_PREREQUISITES["parent_join_evidence"][2],
            },
            "allowed": sorted(HISTORICAL_REUSE_ALLOWED),
            "forbidden": sorted(HISTORICAL_REUSE_FORBIDDEN),
            "historical_combined_rows": 589_030_555,
            "historical_native_join_rows": 1_408,
            "historical_fixture_is_fresh_issuance_evidence": False,
        },
        "bounded_native_shard": bounded,
        "namespace_transition": {
            "gate_relation_id": BOUNDED_RELATION_ID,
            "engine_reported_relation_id": ENGINE_RELATION_ID,
            "engine_selector_aliases_unsupported_shape": True,
            "historical_engine_source_modified": False,
            "fresh_production_relation_identity_required": True,
            "production_namespace_qualified": False,
        },
        "external_artifacts": {
            "required": list(production_inputs.REQUIRED_EXTERNAL_ARTIFACTS),
            "installed_in_checkpoint_environment": [],
            "missing": list(production_inputs.REQUIRED_EXTERNAL_ARTIFACTS),
            "trusted_producer_handoff_required": True,
            "writer_quiescence_owner_mode_acl_writable_fd_mount_controls_required": True,
            "independent_review_required": True,
        },
        "resource_estimate": {
            "bounded_observed_rows": FROZEN_BOUNDED["rows"],
            "bounded_observed_stream_bytes": FROZEN_BOUNDED["stream_bytes"],
            "bounded_cpu_cores": 2,
            "bounded_elapsed_seconds_upper_bound": 60,
            "bounded_peak_memory_mib_upper_bound": 128,
            "historical_18_tree_combined_rows": 589_030_555,
            "fresh_18_tree_estimated_seconds": [8_000, 12_000],
            "fresh_18_tree_minimum_memory_bytes": 16_000_000_000,
            "fresh_18_tree_minimum_free_disk_bytes": 64_000_000_000,
            "fresh_estimate_requires_new_reservation": True,
            "other_tree_observed_stream_bytes_used": False,
        },
        "exact_commands": {
            "bounded_self_check": (
                "PYTHONPATH=src python -u src/"
                "pq_rbbc_issuance_cap576_native_preflight_v1.py --self-check"
            ),
            "read_only_external_preflight": (
                "PYTHONPATH=src python -u src/"
                "pq_rbbc_issuance_cap576_native_preflight_v1.py --artifact-root "
                "/ABSOLUTE/PRIVATE/ARTIFACT/ROOT"
            ),
            "targeted_tests": (
                "PYTHONPATH=src python -m unittest "
                "tests.test_pq_rbbc_issuance_cap576_native_preflight_v1 -v"
            ),
            "large_replay": None,
            "large_proving": None,
        },
        "claim_status": {
            "Defined": True,
            "Instantiated": {"bounded_test_only": True, "production": False},
            "Implemented": {"bounded_native_lowering": True, "production": False},
            "Tested": {"bounded_positive_mutation": True, "production": False},
            "Evidence-sealed": {"bounded_metadata": True, "production": False},
            "Proof-closed": False,
            "Production-closed": False,
            "production_child_port_contract_frozen": not port_failures,
            "production_rho_handoff_defined": True,
            "production_rho_instantiated": False,
            "production_namespace_qualified": False,
            "production_relation_instantiated": False,
            "formal_pi_issue_generated": False,
            "qualified_pq_se_backend_integrated": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
        },
        "artifact_policy": {
            "assignment_or_br1cs_created": False,
            "row_archive_created": False,
            "pickle_cache_checkpoint_resume_or_log_created": False,
            "large_proving_output_created": False,
            "historical_files_modified": False,
            "system_architecture_changed": False,
            "ticket_lifecycle_changed": False,
            "pq_sat_auth_changed": False,
        },
        "tracked_prerequisites": {
            name: {"path": path, "bytes": size, "sha256": digest}
            for name, (path, size, digest) in TRACKED_PREREQUISITES.items()
        },
        "tracked_validation_failures": tracked_failures,
        "historical_evidence_validation_failures": historical_failures,
        "child_port_validation_failures": port_failures,
    }


def build_portable_evidence() -> dict[str, object]:
    manifest_path = ROOT / "manifests/pq_rbbc_issuance_cap576_native_preflight_manifest_v1.json"
    manifest_identity = (
        _identity(manifest_path)
        if manifest_path.is_file()
        else {
            "filename": manifest_path.name,
            "bytes": len(canonical_json(build_manifest())),
            "sha256": hashlib.sha256(canonical_json(build_manifest())).hexdigest(),
        }
    )
    bounded = bounded_shard_self_check()
    observation = bounded["first_observation"]
    return {
        "format": EVIDENCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "manifest": manifest_identity,
        "tracked_prerequisites_valid": not validate_tracked_prerequisites(),
        "historical_v2_29_evidence_valid": not validate_v2_29_historical_evidence(),
        "production_child_ports_valid": not validate_child_port_contract(),
        "bounded_native_shard": {
            "relation_id": bounded["relation_id"],
            "test_only": True,
            "rows": observation["rows"],
            "wires": observation["wires"],
            "stream_sha256": observation["stream_sha256"],
            "spool_sha256": observation["spool_sha256"],
            "external_assertions": observation["external_assertions"],
            "verification_failures": observation["verification_failures"],
            "assignment_materialized": observation["assignment_materialized"],
            "witness_independent_topology": bounded["witness_independent_topology"],
            "rho_mutation_changes_bound_outputs": bounded["rho_mutation_changes_bound_outputs"],
            "engine_namespace_production_eligible": False,
        },
        "production_rho_bytes": PRODUCTION_RHO_BYTES,
        "production_rho_value_embedded": False,
        "required_external_artifacts": len(production_inputs.REQUIRED_EXTERNAL_ARTIFACTS),
        "external_artifacts_present": 0,
        "missing_external_artifacts": list(production_inputs.REQUIRED_EXTERNAL_ARTIFACTS),
        "historical_assignment_or_values_reused": False,
        "other_tree_observed_stream_bytes_used": False,
        "large_replay_started": False,
        "large_proving_started": False,
        "formal_pi_issue_generated": False,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
        "Proof-closed": False,
        "Production-closed": False,
        "large_artifacts_embedded": False,
        "portable_evidence_contains_absolute_paths": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--artifact-root", type=Path)
    mode.add_argument("--self-check", action="store_true")
    mode.add_argument("--print-manifest", action="store_true")
    mode.add_argument("--print-evidence", action="store_true")
    args = parser.parse_args()
    if args.artifact_root is not None:
        document = read_only_preflight(args.artifact_root)
    elif args.self_check:
        document = bounded_shard_self_check()
    elif args.print_manifest:
        document = build_manifest()
    else:
        document = build_portable_evidence()
    print(canonical_json(document).decode("ascii"), end="")


if __name__ == "__main__":
    main()
