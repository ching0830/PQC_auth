#!/usr/bin/env python3
"""Read-only v2.34 gate for unified-tree CAP production pre-freeze.

This checker binds the v2.33 reduced portable seal, validates externally
supplied reservation/review candidates, observes local capacity, and remains
fail-closed until a production runner and relation contract are separately
implemented and frozen.  It never builds leaves, assignments, relations, or
proofs and never invokes a replay command.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from typing import Mapping

import pq_rbbc_cap_unified_tree as unified


IMPLEMENTATION_VERSION = "2.34"
FORMAT = "PQRBBC-CAP-UNIFIED-TREE-PRODUCTION-PREFREEZE-CHECKPOINT-1"
REPORT_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-PRODUCTION-PREFREEZE-ENVIRONMENT-1"
RELATION_ID = "pq-rbbc/cap/unified-tree/production-prefreeze/checkpoint/v1"
ROOT = Path(__file__).resolve().parents[1]
EXTERNAL_ROOT = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/v2_34_unified_tree_prefreeze"
)
PRODUCTION_OUTPUT = EXTERNAL_ROOT / "production-prefreeze"

MIN_CPU_CORES = 4
MIN_AVAILABLE_MEMORY_BYTES = 16 * (1 << 30)
MIN_FREE_DISK_BYTES = 80 * (1 << 30)
PROJECTED_MIN_COMBINED_ROWS = 589_054_075
PROJECTED_TWO_REPLAY_ROW_CHECKS = 1_178_108_150

PRODUCTION_PROFILE_FINGERPRINT = unified.profile_fingerprint(
    unified.PRODUCTION_PARAMETERS
)
V2_33_PORTABLE_SEAL = {
    "filename": "pq_rbbc_cap_unified_tree_reduced_portable_evidence_v2_33.json",
    "bytes": 5_894,
    "sha256": "758f101d9e825da2d4315d69d46a48b6c5ef563c49d05633cb3b68cde4fbcdd3",
}

TRACKED_INPUTS = {
    "v2_33_portable_seal": (
        "artifacts/metadata/cap_unified_tree_migration_v2_33/"
        "pq_rbbc_cap_unified_tree_reduced_portable_evidence_v2_33.json",
        5_894,
        "758f101d9e825da2d4315d69d46a48b6c5ef563c49d05633cb3b68cde4fbcdd3",
    ),
    "v2_33_migration_manifest": (
        "manifests/pq_rbbc_cap_unified_tree_migration_manifest_v2_33.json",
        13_990,
        "8686d49f59655f09135d91fc79e236c59bc8d6b582c86a55799a0c13acfad9f5",
    ),
    "unified_tree_implementation": (
        "src/pq_rbbc_cap_unified_tree.py",
        32_068,
        "6be95221ab178704e1257c41ec42066807b5e59acd89a59458dcfd613d4ce1e4",
    ),
    "reduced_runner": (
        "src/pq_rbbc_cap_unified_tree_runner.py",
        23_858,
        "6f126e42420634c2464a6ee8ba3418e2976c8d83c4003bd3db5b5e43a298470e",
    ),
    "exact_specification_source": (
        "docs/proof/source/pq_rbbc_cap_unified_tree_spec_v2_33.html",
        10_648,
        "4e197e6cc4cfe7848af2168a3104fd959621637950a4c2091b3a2834e1e407d9",
    ),
}

SEALED_EXTERNAL_INPUTS = {
    "specification_pdf": {
        "filename": "pq_rbbc_cap_unified_tree_spec_v2_33.pdf",
        "bytes": 140_010,
        "sha256": "2b8f0c241baa4fd509c2e5e7b0c6f2b6c3108f4f44bc55836825b68a150ee1b0",
        "schema": "pdf",
    },
    "reduced_evidence": {
        "filename": "pq_rbbc_cap_unified_tree_reduced_evidence_v2_33.json",
        "bytes": 6_491,
        "sha256": "9074659af8db46cc78c224a9562a4c257214ac3a128062782f898d1b307a65dc",
        "schema": "PQRBBC-CAP-UNIFIED-TREE-REDUCED-EVIDENCE-1",
    },
    "runner_qualification": {
        "filename": "pq_rbbc_cap_unified_tree_runner_qualification_v2_33.json",
        "bytes": 1_210,
        "sha256": "e7bb68fd9c5caea8afbbc6ef133e64ae77b67a68fdf5f7d09850a3980ba9a050",
        "schema": "PQRBBC-CAP-UNIFIED-TREE-RUNNER-QUALIFICATION-1",
    },
    "post_reduced_report": {
        "filename": "pq_rbbc_cap_unified_tree_environment_after_reduced_v2_33.json",
        "bytes": 8_265,
        "sha256": "d517b5c092fb61b79f362b849d91dd119f1166d9aff64a8c3b5b16479e6b6c39",
        "schema": "PQRBBC-CAP-UNIFIED-TREE-MIGRATION-ENVIRONMENT-1",
    },
}

RESOURCE_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-RESOURCE-RESERVATION-1"
REVIEW_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-INDEPENDENT-REVIEW-1"
RESOURCE_FILENAME = "pq_rbbc_cap_unified_tree_resource_reservation_v2_34.json"
REVIEW_FILENAME = "pq_rbbc_cap_unified_tree_independent_review_v2_34.json"
SCHEMA_PATH = (
    ROOT / "schemas/pq_rbbc_cap_unified_tree_resource_reservation_v2_34.schema.json"
)

# A future command contract, not an executable or authorized command in v2.34.
PRODUCTION_PREFREEZE_COMMAND = (
    "PYTHONPATH=src python -u src/pq_rbbc_cap_unified_tree_runner.py "
    "--profile-manifest manifests/"
    "pq_rbbc_cap_unified_tree_production_prefreeze_manifest_v2_34.json "
    "--phase production-prefreeze "
    f"--output {PRODUCTION_OUTPUT} --fresh-cache --allow-large"
)
PRODUCTION_PREFREEZE_COMMAND_SHA256 = hashlib.sha256(
    PRODUCTION_PREFREEZE_COMMAND.encode("ascii")
).hexdigest()

# These are deliberately false.  Changing them requires a later checkpoint
# with a real production implementation and frozen relation evidence.
PRODUCTION_RUNNER_IMPLEMENTED = False
PRODUCTION_RELATION_CONTRACT_FROZEN = False
PRODUCTION_PREFREEZE_EXECUTION_AUTHORIZED = False


def canonical_json(document: object) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def document_sha256(document: object) -> str:
    return hashlib.sha256(canonical_json(document)).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} root must be an object")
    return document


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _exact_keys(
    document: object, required: set[str], label: str
) -> list[str]:
    if not isinstance(document, dict):
        return [f"{label}:not_an_object"]
    actual = set(document)
    failures = [f"{label}:missing:{key}" for key in sorted(required - actual)]
    failures.extend(f"{label}:unknown:{key}" for key in sorted(actual - required))
    return failures


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _canonical_utc(value: object) -> bool:
    if not isinstance(value, str) or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value
    ) is None:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def prefreeze_contract() -> dict[str, object]:
    return {
        "format": "PQRBBC-CAP-UNIFIED-TREE-PRODUCTION-PREFREEZE-CONTRACT-1",
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "profile": {
            "name": unified.PROFILE_NAME,
            "fingerprint": PRODUCTION_PROFILE_FINGERPRINT,
            "namespace_hex": unified.DOMAIN_PREFIX.hex(),
            "logical_leaf_counts": list(
                unified.PRODUCTION_PARAMETERS.logical_leaf_counts
            ),
            "total_leaves": unified.PRODUCTION_PARAMETERS.total_leaves,
            "internal_nodes": unified.PRODUCTION_PARAMETERS.total_leaves - 1,
            "challenge_index_bits": (
                unified.PRODUCTION_PARAMETERS.challenge_index_bits
            ),
            "explicit_pow_bits": unified.PRODUCTION_PARAMETERS.explicit_pow_bits,
            "t_open": unified.PRODUCTION_PARAMETERS.t_open,
        },
        "sealed_predecessor": V2_33_PORTABLE_SEAL,
        "capacity_minimums": {
            "cpu_cores": MIN_CPU_CORES,
            "available_memory_bytes": MIN_AVAILABLE_MEMORY_BYTES,
            "free_disk_bytes": MIN_FREE_DISK_BYTES,
            "wall_clock_seconds": None,
            "wall_clock_reason": (
                "no frozen production runtime estimate; operator must reserve a "
                "positive window and explicitly accept this uncertainty"
            ),
        },
        "projection_not_execution_count": {
            "minimum_combined_rows": PROJECTED_MIN_COMBINED_ROWS,
            "minimum_two_replay_row_checks": PROJECTED_TWO_REPLAY_ROW_CHECKS,
            "exact_rows_known": False,
            "exact_wires_known": False,
        },
        "prospective_command": PRODUCTION_PREFREEZE_COMMAND,
        "prospective_command_sha256": PRODUCTION_PREFREEZE_COMMAND_SHA256,
        "execution_rules": {
            "external_output_only": True,
            "fresh_cache_required": True,
            "existing_output_overwrite_forbidden": True,
            "legacy_18_tree_evidence_read_only": True,
            "other_tree_observed_stream_bytes_reusable": False,
            "assignment_or_br1cs_tracked_in_git": False,
            "pickle_cache_log_or_resume_tracked_in_git": False,
        },
    }


PREFREEZE_CONTRACT_SHA256 = document_sha256(prefreeze_contract())


def resource_reservation_schema() -> dict[str, object]:
    identity_object = {
        "type": "object",
        "additionalProperties": False,
        "required": ["filename", "bytes", "sha256"],
        "properties": {
            "filename": {"const": V2_33_PORTABLE_SEAL["filename"]},
            "bytes": {"const": V2_33_PORTABLE_SEAL["bytes"]},
            "sha256": {"const": V2_33_PORTABLE_SEAL["sha256"]},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://pq-rbbc.invalid/schema/"
            "cap-unified-tree-resource-reservation-v2.34.json"
        ),
        "title": "PQ-RBBC unified-tree production pre-freeze resource reservation",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "format",
            "implementation_version",
            "reservation_id",
            "production_profile_fingerprint",
            "prefreeze_contract_sha256",
            "v2_33_portable_evidence",
            "operator_approval",
            "execution_scope",
            "reserved_resources",
            "claim_boundary",
        ],
        "properties": {
            "format": {"const": RESOURCE_FORMAT},
            "implementation_version": {"const": IMPLEMENTATION_VERSION},
            "reservation_id": {"type": "string", "minLength": 1},
            "production_profile_fingerprint": {
                "const": PRODUCTION_PROFILE_FINGERPRINT
            },
            "prefreeze_contract_sha256": {"const": PREFREEZE_CONTRACT_SHA256},
            "v2_33_portable_evidence": identity_object,
            "operator_approval": {
                "type": "object",
                "additionalProperties": False,
                "required": ["identifier", "role", "approved_at_utc", "approved"],
                "properties": {
                    "identifier": {"type": "string", "minLength": 1},
                    "role": {"type": "string", "minLength": 1},
                    "approved_at_utc": {
                        "type": "string",
                        "pattern": (
                            "^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
                            "[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
                        ),
                    },
                    "approved": {"const": True},
                },
            },
            "execution_scope": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "phase",
                    "external_root",
                    "exact_command_sha256",
                    "fresh_cache_required",
                    "existing_output_overwrite_forbidden",
                    "legacy_evidence_read_only",
                    "other_tree_observed_stream_bytes_reusable",
                ],
                "properties": {
                    "phase": {"const": "production-prefreeze"},
                    "external_root": {"const": str(EXTERNAL_ROOT)},
                    "exact_command_sha256": {
                        "const": PRODUCTION_PREFREEZE_COMMAND_SHA256
                    },
                    "fresh_cache_required": {"const": True},
                    "existing_output_overwrite_forbidden": {"const": True},
                    "legacy_evidence_read_only": {"const": True},
                    "other_tree_observed_stream_bytes_reusable": {"const": False},
                },
            },
            "reserved_resources": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "cpu_cores",
                    "available_memory_bytes",
                    "free_disk_bytes",
                    "wall_clock_seconds",
                    "accepts_elapsed_time_estimate_unavailable",
                    "exclusive_output_directory",
                ],
                "properties": {
                    "cpu_cores": {"type": "integer", "minimum": MIN_CPU_CORES},
                    "available_memory_bytes": {
                        "type": "integer",
                        "minimum": MIN_AVAILABLE_MEMORY_BYTES,
                    },
                    "free_disk_bytes": {
                        "type": "integer",
                        "minimum": MIN_FREE_DISK_BYTES,
                    },
                    "wall_clock_seconds": {"type": "integer", "minimum": 1},
                    "accepts_elapsed_time_estimate_unavailable": {"const": True},
                    "exclusive_output_directory": {"const": True},
                },
            },
            "claim_boundary": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "authorizes_production_prefreeze",
                    "authorizes_frozen_replay",
                    "authorizes_large_proving_run",
                    "grants_security_claim",
                    "production_closed",
                ],
                "properties": {
                    "authorizes_production_prefreeze": {"const": True},
                    "authorizes_frozen_replay": {"const": False},
                    "authorizes_large_proving_run": {"const": False},
                    "grants_security_claim": {"const": False},
                    "production_closed": {"const": False},
                },
            },
        },
    }


def resource_reservation_template() -> dict[str, object]:
    """Return a deliberately unapproved template; never an attestation."""

    return {
        "format": RESOURCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "reservation_id": "REPLACE-WITH-OPERATOR-RESERVATION-ID",
        "production_profile_fingerprint": PRODUCTION_PROFILE_FINGERPRINT,
        "prefreeze_contract_sha256": PREFREEZE_CONTRACT_SHA256,
        "v2_33_portable_evidence": dict(V2_33_PORTABLE_SEAL),
        "operator_approval": {
            "identifier": "REPLACE-WITH-OPERATOR-IDENTITY",
            "role": "REPLACE-WITH-OPERATOR-ROLE",
            "approved_at_utc": "1970-01-01T00:00:00Z",
            "approved": False,
        },
        "execution_scope": {
            "phase": "production-prefreeze",
            "external_root": str(EXTERNAL_ROOT),
            "exact_command_sha256": PRODUCTION_PREFREEZE_COMMAND_SHA256,
            "fresh_cache_required": True,
            "existing_output_overwrite_forbidden": True,
            "legacy_evidence_read_only": True,
            "other_tree_observed_stream_bytes_reusable": False,
        },
        "reserved_resources": {
            "cpu_cores": MIN_CPU_CORES,
            "available_memory_bytes": MIN_AVAILABLE_MEMORY_BYTES,
            "free_disk_bytes": MIN_FREE_DISK_BYTES,
            "wall_clock_seconds": 0,
            "accepts_elapsed_time_estimate_unavailable": False,
            "exclusive_output_directory": True,
        },
        "claim_boundary": {
            "authorizes_production_prefreeze": False,
            "authorizes_frozen_replay": False,
            "authorizes_large_proving_run": False,
            "grants_security_claim": False,
            "production_closed": False,
        },
    }


def independent_review_contract() -> dict[str, object]:
    return {
        "filename": REVIEW_FILENAME,
        "format": REVIEW_FORMAT,
        "must_be_external": True,
        "must_bind": {
            "production_profile_fingerprint": PRODUCTION_PROFILE_FINGERPRINT,
            "prefreeze_contract_sha256": PREFREEZE_CONTRACT_SHA256,
            "v2_33_portable_evidence": V2_33_PORTABLE_SEAL,
        },
        "required_review_scope": [
            "exact unified-tree topology and position-major mapping",
            "domain separation and tuple-injective transcript inputs",
            "commitment and opening canonical serialization",
            "h3 challenge slicing, counter grinding, and T_open",
            "reduced positive and mutation evidence",
            "production pre-freeze command and claim boundary",
        ],
        "required_disposition": "approved_for_production_prefreeze_only",
        "must_not_grant": [
            "frozen replay authorization",
            "large proving authorization",
            "CAP or fork security qualification",
            "production closure",
        ],
    }


def validate_tracked_inputs() -> tuple[str, ...]:
    failures: list[str] = []
    for label, (relative, size, digest) in TRACKED_INPUTS.items():
        path = ROOT / relative
        if not path.is_file():
            failures.append(f"{label}:missing")
        elif path.stat().st_size != size:
            failures.append(f"{label}:size")
        elif sha256_file(path) != digest:
            failures.append(f"{label}:sha256")
    if SCHEMA_PATH.is_file():
        if SCHEMA_PATH.read_bytes() != canonical_json(resource_reservation_schema()):
            failures.append("resource_reservation_schema:content")
    else:
        failures.append("resource_reservation_schema:missing")
    seal_path = ROOT / TRACKED_INPUTS["v2_33_portable_seal"][0]
    if seal_path.is_file():
        try:
            seal = _read_json(seal_path)
        except (OSError, ValueError, json.JSONDecodeError):
            failures.append("v2_33_portable_seal:json")
        else:
            claims = seal.get("claim_boundary", {})
            if (
                seal.get("format")
                != "PQRBBC-CAP-UNIFIED-TREE-REDUCED-PORTABLE-EVIDENCE-1"
                or claims.get("reduced_unified_tree_implemented_and_verified")
                is not True
                or claims.get("production_profile_implemented") is not False
                or claims.get("large_replay_started") is not False
                or claims.get("production_closed") is not False
            ):
                failures.append("v2_33_portable_seal:semantics")
    if PRODUCTION_PROFILE_FINGERPRINT != (
        "c270e4681f23955667a6c0640317e7beccc666d60a0cffb40bfdccfcee811b7a"
    ):
        failures.append("production_profile:fingerprint")
    return tuple(failures)


def _outside_repository(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT.resolve())
    except ValueError:
        return True
    return False


def _check_sealed_external(
    path: Path | None, requirement: Mapping[str, object]
) -> dict[str, object]:
    result: dict[str, object] = {
        "provided": path is not None,
        "verified": False,
        "failures": [],
    }
    failures = result["failures"]
    assert isinstance(failures, list)
    if path is None:
        failures.append("not_provided")
        return result
    if path.name != requirement["filename"]:
        failures.append("filename")
    if not path.is_file():
        failures.append("missing")
        return result
    result["bytes"] = path.stat().st_size
    result["sha256"] = sha256_file(path)
    if result["bytes"] != requirement["bytes"]:
        failures.append("size")
    if result["sha256"] != requirement["sha256"]:
        failures.append("sha256")
    if requirement["schema"] == "pdf":
        if path.read_bytes()[:5] != b"%PDF-":
            failures.append("pdf_magic")
    else:
        try:
            document = _read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            failures.append("json")
        else:
            if document.get("format") != requirement["schema"]:
                failures.append("schema")
    result["verified"] = not failures
    return result


def validate_resource_reservation(document: object) -> tuple[str, ...]:
    top = {
        "format", "implementation_version", "reservation_id",
        "production_profile_fingerprint", "prefreeze_contract_sha256",
        "v2_33_portable_evidence", "operator_approval", "execution_scope",
        "reserved_resources", "claim_boundary",
    }
    failures = _exact_keys(document, top, "root")
    if not isinstance(document, dict):
        return tuple(failures)
    expected_scalars = {
        "format": RESOURCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "production_profile_fingerprint": PRODUCTION_PROFILE_FINGERPRINT,
        "prefreeze_contract_sha256": PREFREEZE_CONTRACT_SHA256,
    }
    for key, expected in expected_scalars.items():
        if document.get(key) != expected:
            failures.append(key)
    if not _nonempty_string(document.get("reservation_id")):
        failures.append("reservation_id")

    identity = document.get("v2_33_portable_evidence")
    failures.extend(_exact_keys(identity, {"filename", "bytes", "sha256"}, "seal"))
    if isinstance(identity, dict):
        for key, expected in V2_33_PORTABLE_SEAL.items():
            if identity.get(key) != expected:
                failures.append(f"seal:{key}")

    approval = document.get("operator_approval")
    failures.extend(_exact_keys(
        approval, {"identifier", "role", "approved_at_utc", "approved"}, "operator"
    ))
    if isinstance(approval, dict):
        if not _nonempty_string(approval.get("identifier")):
            failures.append("operator:identifier")
        if not _nonempty_string(approval.get("role")):
            failures.append("operator:role")
        if not _canonical_utc(approval.get("approved_at_utc")):
            failures.append("operator:approved_at_utc")
        if approval.get("approved") is not True:
            failures.append("operator:approved")

    scope = document.get("execution_scope")
    scope_expected = {
        "phase": "production-prefreeze",
        "external_root": str(EXTERNAL_ROOT),
        "exact_command_sha256": PRODUCTION_PREFREEZE_COMMAND_SHA256,
        "fresh_cache_required": True,
        "existing_output_overwrite_forbidden": True,
        "legacy_evidence_read_only": True,
        "other_tree_observed_stream_bytes_reusable": False,
    }
    failures.extend(_exact_keys(scope, set(scope_expected), "scope"))
    if isinstance(scope, dict):
        for key, expected in scope_expected.items():
            if scope.get(key) != expected:
                failures.append(f"scope:{key}")

    resources = document.get("reserved_resources")
    resource_keys = {
        "cpu_cores", "available_memory_bytes", "free_disk_bytes",
        "wall_clock_seconds", "accepts_elapsed_time_estimate_unavailable",
        "exclusive_output_directory",
    }
    failures.extend(_exact_keys(resources, resource_keys, "resources"))
    if isinstance(resources, dict):
        minimums = {
            "cpu_cores": MIN_CPU_CORES,
            "available_memory_bytes": MIN_AVAILABLE_MEMORY_BYTES,
            "free_disk_bytes": MIN_FREE_DISK_BYTES,
            "wall_clock_seconds": 1,
        }
        for key, minimum in minimums.items():
            value = resources.get(key)
            if not _is_int(value) or value < minimum:
                failures.append(f"resources:{key}")
        for key in (
            "accepts_elapsed_time_estimate_unavailable",
            "exclusive_output_directory",
        ):
            if resources.get(key) is not True:
                failures.append(f"resources:{key}")

    boundary = document.get("claim_boundary")
    boundary_expected = {
        "authorizes_production_prefreeze": True,
        "authorizes_frozen_replay": False,
        "authorizes_large_proving_run": False,
        "grants_security_claim": False,
        "production_closed": False,
    }
    failures.extend(_exact_keys(boundary, set(boundary_expected), "claims"))
    if isinstance(boundary, dict):
        for key, expected in boundary_expected.items():
            if boundary.get(key) is not expected:
                failures.append(f"claims:{key}")
    return tuple(sorted(set(failures)))


def _check_resource(path: Path | None) -> dict[str, object]:
    result: dict[str, object] = {
        "provided": path is not None,
        "schema_valid": False,
        "identity_frozen": False,
        "candidate_acceptable_for_freeze": False,
        "verified": False,
        "failures": [],
    }
    failures = result["failures"]
    assert isinstance(failures, list)
    if path is None:
        failures.append("not_provided")
        return result
    if path.name != RESOURCE_FILENAME:
        failures.append("filename")
    if not _outside_repository(path):
        failures.append("must_be_external")
    if not path.is_file():
        failures.append("missing")
        return result
    result["bytes"] = path.stat().st_size
    result["sha256"] = sha256_file(path)
    try:
        document = _read_json(path)
    except (OSError, ValueError, json.JSONDecodeError):
        failures.append("json")
        return result
    schema_failures = validate_resource_reservation(document)
    if schema_failures:
        failures.extend(f"schema:{failure}" for failure in schema_failures)
    else:
        result["schema_valid"] = True
        result["candidate_acceptable_for_freeze"] = True
        failures.append("identity_not_frozen")
    return result


def validate_independent_review(document: object) -> tuple[str, ...]:
    top = {
        "format", "implementation_version", "review_id", "reviewer",
        "bound_identities", "review_scope", "decision",
    }
    failures = _exact_keys(document, top, "root")
    if not isinstance(document, dict):
        return tuple(failures)
    if document.get("format") != REVIEW_FORMAT:
        failures.append("format")
    if document.get("implementation_version") != IMPLEMENTATION_VERSION:
        failures.append("implementation_version")
    if not _nonempty_string(document.get("review_id")):
        failures.append("review_id")

    reviewer = document.get("reviewer")
    failures.extend(_exact_keys(
        reviewer,
        {"identifier", "affiliation", "independent_of_implementation", "completed_at_utc"},
        "reviewer",
    ))
    if isinstance(reviewer, dict):
        if not _nonempty_string(reviewer.get("identifier")):
            failures.append("reviewer:identifier")
        if not _nonempty_string(reviewer.get("affiliation")):
            failures.append("reviewer:affiliation")
        if reviewer.get("independent_of_implementation") is not True:
            failures.append("reviewer:independence")
        if not _canonical_utc(reviewer.get("completed_at_utc")):
            failures.append("reviewer:completed_at_utc")

    identities = document.get("bound_identities")
    expected_identities = {
        "production_profile_fingerprint": PRODUCTION_PROFILE_FINGERPRINT,
        "prefreeze_contract_sha256": PREFREEZE_CONTRACT_SHA256,
        "v2_33_portable_evidence": V2_33_PORTABLE_SEAL,
    }
    failures.extend(_exact_keys(identities, set(expected_identities), "bindings"))
    if isinstance(identities, dict):
        for key, expected in expected_identities.items():
            if identities.get(key) != expected:
                failures.append(f"bindings:{key}")

    scope = document.get("review_scope")
    required_scope = {
        "tree_topology_and_mapping_reviewed",
        "domains_and_transcripts_reviewed",
        "serialization_reviewed",
        "challenge_pow_and_opening_reviewed",
        "reduced_evidence_reviewed",
        "prefreeze_boundary_reviewed",
    }
    failures.extend(_exact_keys(scope, required_scope, "scope"))
    if isinstance(scope, dict):
        for key in required_scope:
            if scope.get(key) is not True:
                failures.append(f"scope:{key}")

    decision = document.get("decision")
    decision_expected = {
        "disposition": "approved_for_production_prefreeze_only",
        "blocking_findings": [],
        "authorizes_frozen_replay": False,
        "authorizes_large_proving_run": False,
        "grants_security_claim": False,
        "production_closed": False,
    }
    failures.extend(_exact_keys(decision, set(decision_expected), "decision"))
    if isinstance(decision, dict):
        for key, expected in decision_expected.items():
            if decision.get(key) != expected:
                failures.append(f"decision:{key}")
    return tuple(sorted(set(failures)))


def _check_review(path: Path | None) -> dict[str, object]:
    result: dict[str, object] = {
        "provided": path is not None,
        "schema_valid": False,
        "identity_frozen": False,
        "candidate_acceptable_for_freeze": False,
        "verified": False,
        "failures": [],
    }
    failures = result["failures"]
    assert isinstance(failures, list)
    if path is None:
        failures.append("not_provided")
        return result
    if path.name != REVIEW_FILENAME:
        failures.append("filename")
    if not _outside_repository(path):
        failures.append("must_be_external")
    if not path.is_file():
        failures.append("missing")
        return result
    result["bytes"] = path.stat().st_size
    result["sha256"] = sha256_file(path)
    try:
        document = _read_json(path)
    except (OSError, ValueError, json.JSONDecodeError):
        failures.append("json")
        return result
    schema_failures = validate_independent_review(document)
    if schema_failures:
        failures.extend(f"schema:{failure}" for failure in schema_failures)
    else:
        result["schema_valid"] = True
        result["candidate_acceptable_for_freeze"] = True
        failures.append("identity_not_frozen")
    return result


def _available_memory_bytes() -> int:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return 0
    return 0


def environment_resources(path: Path) -> dict[str, object]:
    probe = path
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    disk = shutil.disk_usage(probe)
    cpu = os.cpu_count() or 0
    memory = _available_memory_bytes()
    passed = (
        cpu >= MIN_CPU_CORES
        and memory >= MIN_AVAILABLE_MEMORY_BYTES
        and disk.free >= MIN_FREE_DISK_BYTES
    )
    return {
        "cpu_cores": cpu,
        "available_memory_bytes": memory,
        "free_disk_bytes": disk.free,
        "minimums": {
            "cpu_cores": MIN_CPU_CORES,
            "available_memory_bytes": MIN_AVAILABLE_MEMORY_BYTES,
            "free_disk_bytes": MIN_FREE_DISK_BYTES,
        },
        "capacity_check_passed": passed,
        "capacity_check_is_execution_authorization": False,
    }


def claim_boundary() -> dict[str, bool]:
    return {
        "v2_34_read_only_prefreeze_checker_implemented": True,
        "resource_reservation_schema_frozen": True,
        "v2_33_reduced_portable_seal_bound": True,
        "production_profile_descriptor_fingerprint_frozen": True,
        "production_runner_implemented": PRODUCTION_RUNNER_IMPLEMENTED,
        "production_relation_contract_frozen": PRODUCTION_RELATION_CONTRACT_FROZEN,
        "operator_resource_reservation_frozen": False,
        "independent_review_frozen": False,
        "production_prefreeze_authorized": PRODUCTION_PREFREEZE_EXECUTION_AUTHORIZED,
        "production_prefreeze_started": False,
        "large_replay_started": False,
        "large_proving_run_started": False,
        "cap_security_qualified": False,
        "fork_security_proof_revalidated": False,
        "legacy_18_tree_profile_preserved": True,
        "system_architecture_changed": False,
        "ticket_lifecycle_changed": False,
        "pq_sat_auth_changed": False,
        "production_closed": False,
    }


def exact_commands() -> dict[str, object]:
    return {
        "read_only_checker": (
            "PYTHONPATH=src python -u "
            "src/pq_rbbc_cap_unified_tree_production_prefreeze.py "
            f"--report {EXTERNAL_ROOT}/"
            "pq_rbbc_cap_unified_tree_production_prefreeze_environment_v2_34.json "
            "--specification-pdf /tmp/pq_rbbc_external_artifacts_rebuilt/"
            "v2_33_unified_tree_migration/pq_rbbc_cap_unified_tree_spec_v2_33.pdf "
            "--reduced-evidence /tmp/pq_rbbc_external_artifacts_rebuilt/"
            "v2_33_unified_tree_migration/reduced/"
            "pq_rbbc_cap_unified_tree_reduced_evidence_v2_33.json "
            "--runner-qualification /tmp/pq_rbbc_external_artifacts_rebuilt/"
            "v2_33_unified_tree_migration/reduced/"
            "pq_rbbc_cap_unified_tree_runner_qualification_v2_33.json "
            "--post-reduced-report /tmp/pq_rbbc_external_artifacts_rebuilt/"
            "v2_33_unified_tree_migration/"
            "pq_rbbc_cap_unified_tree_environment_after_reduced_v2_33.json"
        ),
        "resource_reservation_template": (
            "PYTHONPATH=src python -u "
            "src/pq_rbbc_cap_unified_tree_production_prefreeze.py "
            "--print-resource-template"
        ),
        "production_prefreeze": {
            "command": PRODUCTION_PREFREEZE_COMMAND,
            "command_sha256": PRODUCTION_PREFREEZE_COMMAND_SHA256,
            "executable_now": False,
            "authorized_now": False,
            "withheld_reasons": [
                "production runner is not implemented",
                "production relation contract is not frozen",
                "resource reservation identity is not frozen",
                "independent review identity is not frozen",
            ],
        },
        "production_frozen_replay": {
            "command": None,
            "executable_now": False,
            "authorized_now": False,
            "withheld_reason": "production pre-freeze observation does not exist",
        },
        "large_proving_run": {
            "command": None,
            "executable_now": False,
            "authorized_now": False,
            "withheld_reason": "functional pre-freeze cannot grant a security claim",
        },
    }


def build_frozen_manifest() -> dict[str, object]:
    schema = resource_reservation_schema()
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "authorization_scope": {
            "read_only_checker_authorized": True,
            "resource_reservation_schema_authorized": True,
            "production_prefreeze_authorized": False,
            "large_replay_authorized": False,
            "large_proving_run_authorized": False,
        },
        "prefreeze_contract": prefreeze_contract(),
        "prefreeze_contract_sha256": PREFREEZE_CONTRACT_SHA256,
        "resource_reservation": {
            "filename": RESOURCE_FILENAME,
            "schema_path": str(SCHEMA_PATH.relative_to(ROOT)),
            "schema_sha256": document_sha256(schema),
            "external_attestation_required": True,
            "identity_frozen": False,
            "unapproved_template_is_attestation": False,
        },
        "independent_review": independent_review_contract(),
        "tracked_inputs": {
            label: {"path": path, "bytes": size, "sha256": digest}
            for label, (path, size, digest) in TRACKED_INPUTS.items()
        },
        "sealed_external_inputs": SEALED_EXTERNAL_INPUTS,
        "implementation_gate": {
            "production_runner_implemented": PRODUCTION_RUNNER_IMPLEMENTED,
            "production_relation_contract_frozen": PRODUCTION_RELATION_CONTRACT_FROZEN,
            "current_runner_supported_phase": "reduced",
            "production_phase_must_not_be_invoked": True,
        },
        "exact_commands": exact_commands(),
        "claim_boundary": claim_boundary(),
    }


def build_environment_report(
    sealed_paths: Mapping[str, Path | None],
    resource_reservation: Path | None,
    independent_review: Path | None,
    resource_probe: Path = EXTERNAL_ROOT,
) -> dict[str, object]:
    tracked_failures = validate_tracked_inputs()
    sealed_checks = {
        label: _check_sealed_external(sealed_paths.get(label), requirement)
        for label, requirement in SEALED_EXTERNAL_INPUTS.items()
    }
    resource_check = _check_resource(resource_reservation)
    review_check = _check_review(independent_review)
    resources = environment_resources(resource_probe)
    blockers: list[str] = []
    if tracked_failures:
        blockers.append("tracked_inputs")
    blockers.extend(
        f"sealed_external:{label}"
        for label, result in sealed_checks.items()
        if result["verified"] is not True
    )
    if resource_check["verified"] is not True:
        blockers.append("resource_reservation")
    if review_check["verified"] is not True:
        blockers.append("independent_review")
    if resources["capacity_check_passed"] is not True:
        blockers.append("local_capacity")
    if not PRODUCTION_RUNNER_IMPLEMENTED:
        blockers.append("production_runner_not_implemented")
    if not PRODUCTION_RELATION_CONTRACT_FROZEN:
        blockers.append("production_relation_contract_not_frozen")
    if not PRODUCTION_PREFREEZE_EXECUTION_AUTHORIZED:
        blockers.append("production_prefreeze_not_authorized")
    safe = not blockers
    return {
        "format": REPORT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "safe_to_run_read_only_checker": not tracked_failures,
        "safe_to_freeze_resource_reservation_candidate": (
            resource_check["candidate_acceptable_for_freeze"] is True
        ),
        "safe_to_request_independent_review": (
            not tracked_failures
            and all(item["verified"] is True for item in sealed_checks.values())
        ),
        "safe_to_start_production_prefreeze": safe,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
        "production_leaves_expanded": 0,
        "relation_rows_replayed": 0,
        "proofs_generated": 0,
        "blockers": blockers,
        "checks": {
            "tracked_inputs": {
                "verified": not tracked_failures,
                "failures": list(tracked_failures),
            },
            "sealed_external_inputs": sealed_checks,
            "resource_reservation": resource_check,
            "independent_review": review_check,
            "resources": resources,
            "implementation_gate": {
                "production_profile_fingerprint": PRODUCTION_PROFILE_FINGERPRINT,
                "production_runner_implemented": PRODUCTION_RUNNER_IMPLEMENTED,
                "production_relation_contract_frozen": PRODUCTION_RELATION_CONTRACT_FROZEN,
                "production_prefreeze_execution_authorized": (
                    PRODUCTION_PREFREEZE_EXECUTION_AUTHORIZED
                ),
            },
        },
        "prefreeze_contract_sha256": PREFREEZE_CONTRACT_SHA256,
        "resource_reservation_schema_sha256": document_sha256(
            resource_reservation_schema()
        ),
        "claim_boundary": claim_boundary(),
        "exact_commands": exact_commands(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--specification-pdf", type=Path)
    parser.add_argument("--reduced-evidence", type=Path)
    parser.add_argument("--runner-qualification", type=Path)
    parser.add_argument("--post-reduced-report", type=Path)
    parser.add_argument("--resource-reservation", type=Path)
    parser.add_argument("--independent-review", type=Path)
    parser.add_argument("--print-resource-template", action="store_true")
    args = parser.parse_args()
    if args.print_resource_template:
        print(canonical_json(resource_reservation_template()).decode(), end="")
        return
    report = build_environment_report(
        {
            "specification_pdf": args.specification_pdf,
            "reduced_evidence": args.reduced_evidence,
            "runner_qualification": args.runner_qualification,
            "post_reduced_report": args.post_reduced_report,
        },
        args.resource_reservation,
        args.independent_review,
    )
    data = canonical_json(report)
    if args.report is None:
        print(data.decode(), end="")
        return
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_bytes(data)
    print(json.dumps({
        "report": str(args.report),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "safe_to_start_production_prefreeze": report[
            "safe_to_start_production_prefreeze"
        ],
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
