#!/usr/bin/env python3
"""PQ-RBBC v2.39 unified-tree launch identity-set preflight.

This module authors strict external-attestation schemas and deliberately invalid
drafts, validates later operator/reviewer candidates, and binds a launch-manifest
candidate.  It never authorizes or starts production materialization, replay, or
proving.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
from typing import Mapping

import pq_rbbc_cap_unified_tree_streaming_prefreeze as v2_38


IMPLEMENTATION_VERSION = "2.39"
FORMAT = "PQRBBC-CAP-UNIFIED-TREE-LAUNCH-PREFLIGHT-AUTHORING-1"
REPORT_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-LAUNCH-IDENTITY-PREFLIGHT-1"
QUALIFICATION_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-LAUNCH-PREFLIGHT-QUALIFICATION-1"
RELATION_ID = "pq-rbbc/cap/unified-tree/launch-preflight/candidate/v1"

RESOURCE_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-RESOURCE-RESERVATION-3"
REVIEW_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-INDEPENDENT-REVIEW-3"
LAUNCH_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-LAUNCH-MANIFEST-2"

RESOURCE_FILENAME = "pq_rbbc_cap_unified_tree_resource_reservation_v2_39.json"
REVIEW_FILENAME = "pq_rbbc_cap_unified_tree_independent_review_v2_39.json"
LAUNCH_FILENAME = "pq_rbbc_cap_unified_tree_launch_manifest_v2_39.json"
REPORT_FILENAME = "pq_rbbc_cap_unified_tree_launch_preflight_v2_39.json"
QUALIFICATION_FILENAME = (
    "pq_rbbc_cap_unified_tree_launch_preflight_qualification_v2_39.json"
)
RESOURCE_TEMPLATE_FILENAME = (
    "pq_rbbc_cap_unified_tree_resource_reservation_template_v2_39.json"
)
REVIEW_TEMPLATE_FILENAME = (
    "pq_rbbc_cap_unified_tree_independent_review_template_v2_39.json"
)
LAUNCH_TEMPLATE_FILENAME = (
    "pq_rbbc_cap_unified_tree_launch_manifest_template_v2_39.json"
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = (
    ROOT / "manifests/pq_rbbc_cap_unified_tree_launch_preflight_manifest_v2_39.json"
)
RESOURCE_SCHEMA_PATH = (
    ROOT / "schemas/pq_rbbc_cap_unified_tree_resource_reservation_v2_39.schema.json"
)
REVIEW_SCHEMA_PATH = (
    ROOT / "schemas/pq_rbbc_cap_unified_tree_independent_review_v2_39.schema.json"
)
LAUNCH_SCHEMA_PATH = (
    ROOT / "schemas/pq_rbbc_cap_unified_tree_launch_manifest_v2_39.schema.json"
)
V2_38_PORTABLE_PATH = (
    ROOT / "artifacts/metadata/cap_unified_tree_streaming_prefreeze_v2_38/"
    "pq_rbbc_cap_unified_tree_streaming_prefreeze_portable_evidence_v2_38.json"
)
V2_38_PORTABLE_IDENTITY = {
    "filename": V2_38_PORTABLE_PATH.name,
    "bytes": 7_390,
    "sha256": "7f846858350deefa6a6d4df2dec43a852f8e6deb9c55c99e289c2062f822979e",
}
V2_38_MANIFEST_IDENTITY = {
    "filename": v2_38.MANIFEST_PATH.name,
    "bytes": 7_581,
    "sha256": "b601af812865b190e76a7fe22d184f29ee2036dc907a56ad4dcf8da8fbf9a4a4",
}

PRODUCTION_PROFILE_FINGERPRINT = v2_38.PRODUCTION_PROFILE_FINGERPRINT
V2_38_PRODUCTION_COMMAND_SHA256 = v2_38.build_manifest()["exact_commands"][
    "production_prefreeze"
]["sha256"]
EXTERNAL_ROOT = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/"
    "v2_39_unified_tree_launch_preflight"
)
PRODUCTION_OUTPUT = EXTERNAL_ROOT / "production-prefreeze"
PRODUCTION_COMMAND = (
    "PYTHONPATH=src python -u "
    "src/pq_rbbc_cap_unified_tree_launch_preflight.py "
    "--phase production-prefreeze --v2-38-portable "
    "artifacts/metadata/cap_unified_tree_streaming_prefreeze_v2_38/"
    "pq_rbbc_cap_unified_tree_streaming_prefreeze_portable_evidence_v2_38.json "
    f"--resource-reservation {EXTERNAL_ROOT}/{RESOURCE_FILENAME} "
    f"--independent-review {EXTERNAL_ROOT}/{REVIEW_FILENAME} "
    f"--launch-manifest {EXTERNAL_ROOT}/{LAUNCH_FILENAME} "
    f"--output {PRODUCTION_OUTPUT} --fresh-output"
)
PRODUCTION_COMMAND_SHA256 = hashlib.sha256(PRODUCTION_COMMAND.encode()).hexdigest()

MIN_CPU_CORES = 4
MIN_AVAILABLE_MEMORY_BYTES = 16 * (1 << 30)
MIN_FREE_DISK_BYTES = 80 * (1 << 30)


class LaunchPreflightError(RuntimeError):
    """Raised when a v2.39 contract or safe-control-flow check fails."""


def canonical_json(document: object) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def document_sha256(document: object) -> str:
    return hashlib.sha256(canonical_json(document)).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def identity(path: Path) -> dict[str, object]:
    return {"filename": path.name, "bytes": path.stat().st_size, "sha256": sha256_file(path)}


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError("JSON root must be an object")
    return document


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _concrete(value: object) -> bool:
    return _nonempty(value) and not str(value).startswith("REPLACE-WITH-")


def _canonical_utc(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ) == value
    except ValueError:
        return False


def _exact_keys(value: object, expected: set[str], label: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{label}:object"]
    actual = set(value)
    failures = [f"{label}:missing:{key}" for key in sorted(expected - actual)]
    failures.extend(f"{label}:extra:{key}" for key in sorted(actual - expected))
    return failures


def _outside_repository(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT.resolve())
    except ValueError:
        return True
    return False


def _identity_schema(expected: Mapping[str, object] | None = None) -> dict[str, object]:
    properties: dict[str, object] = {
        "filename": {"type": "string", "minLength": 1},
        "bytes": {"type": "integer", "minimum": 1},
        "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    }
    if expected is not None:
        properties = {key: {"const": value} for key, value in expected.items()}
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["filename", "bytes", "sha256"],
        "properties": properties,
    }


def _attestation_schema() -> dict[str, object]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["method", "reference", "authenticity_confirmed"],
        "properties": {
            "method": {
                "enum": ["signed-json", "detached-signature", "organization-record"]
            },
            "reference": {"type": "string", "minLength": 1},
            "authenticity_confirmed": {"const": True},
        },
    }


def resource_reservation_schema() -> dict[str, object]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://pq-rbbc.invalid/schema/cap-unified-tree-resource-reservation-v2.39.json",
        "title": "PQ-RBBC unified-tree operator resource reservation v2.39",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "format", "implementation_version", "reservation_id",
            "production_profile_fingerprint", "v2_38_portable_evidence",
            "operator", "reservation_window", "execution_scope",
            "reserved_resources", "claim_boundary",
        ],
        "properties": {
            "format": {"const": RESOURCE_FORMAT},
            "implementation_version": {"const": IMPLEMENTATION_VERSION},
            "reservation_id": {"type": "string", "minLength": 1},
            "production_profile_fingerprint": {"const": PRODUCTION_PROFILE_FINGERPRINT},
            "v2_38_portable_evidence": _identity_schema(V2_38_PORTABLE_IDENTITY),
            "operator": {
                "type": "object", "additionalProperties": False,
                "required": ["identifier", "role", "approved_at_utc", "approved", "attestation"],
                "properties": {
                    "identifier": {"type": "string", "minLength": 1},
                    "role": {"type": "string", "minLength": 1},
                    "approved_at_utc": {"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"},
                    "approved": {"const": True},
                    "attestation": _attestation_schema(),
                },
            },
            "reservation_window": {
                "type": "object", "additionalProperties": False,
                "required": ["starts_at_utc", "ends_at_utc", "wall_clock_seconds"],
                "properties": {
                    "starts_at_utc": {"type": "string"},
                    "ends_at_utc": {"type": "string"},
                    "wall_clock_seconds": {"type": "integer", "minimum": 1},
                },
            },
            "execution_scope": {
                "type": "object", "additionalProperties": False,
                "required": [
                    "phase", "external_output", "exact_command_sha256",
                    "fresh_cache_required", "existing_output_overwrite_forbidden",
                    "legacy_evidence_read_only", "other_tree_observed_stream_bytes_reusable",
                ],
                "properties": {
                    "phase": {"const": "production-prefreeze"},
                    "external_output": {"const": str(PRODUCTION_OUTPUT)},
                    "exact_command_sha256": {"const": PRODUCTION_COMMAND_SHA256},
                    "fresh_cache_required": {"const": True},
                    "existing_output_overwrite_forbidden": {"const": True},
                    "legacy_evidence_read_only": {"const": True},
                    "other_tree_observed_stream_bytes_reusable": {"const": False},
                },
            },
            "reserved_resources": {
                "type": "object", "additionalProperties": False,
                "required": [
                    "cpu_cores", "available_memory_bytes", "free_disk_bytes",
                    "exclusive_output_directory", "accepts_runtime_estimate_unavailable",
                ],
                "properties": {
                    "cpu_cores": {"type": "integer", "minimum": MIN_CPU_CORES},
                    "available_memory_bytes": {"type": "integer", "minimum": MIN_AVAILABLE_MEMORY_BYTES},
                    "free_disk_bytes": {"type": "integer", "minimum": MIN_FREE_DISK_BYTES},
                    "exclusive_output_directory": {"const": True},
                    "accepts_runtime_estimate_unavailable": {"const": True},
                },
            },
            "claim_boundary": {
                "type": "object", "additionalProperties": False,
                "required": [
                    "authorizes_production_prefreeze", "authorizes_frozen_replay",
                    "authorizes_large_proving_run", "grants_security_claim", "production_closed",
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


REVIEW_SCOPE_KEYS = (
    "unified_profile_and_namespace_reviewed",
    "statement_parent_binding_reviewed",
    "stream_chunk_codec_reviewed",
    "checkpoint_resume_chain_reviewed",
    "relation_and_materialization_boundary_reviewed",
    "command_resource_and_output_policy_reviewed",
    "legacy_non_reuse_and_claim_boundary_reviewed",
)


def independent_review_schema() -> dict[str, object]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://pq-rbbc.invalid/schema/cap-unified-tree-independent-review-v2.39.json",
        "title": "PQ-RBBC unified-tree independent review v2.39",
        "type": "object", "additionalProperties": False,
        "required": [
            "format", "implementation_version", "review_id", "reviewer",
            "bound_identities", "review_scope", "decision",
        ],
        "properties": {
            "format": {"const": REVIEW_FORMAT},
            "implementation_version": {"const": IMPLEMENTATION_VERSION},
            "review_id": {"type": "string", "minLength": 1},
            "reviewer": {
                "type": "object", "additionalProperties": False,
                "required": [
                    "identifier", "affiliation", "independent_of_implementation",
                    "completed_at_utc", "attestation",
                ],
                "properties": {
                    "identifier": {"type": "string", "minLength": 1},
                    "affiliation": {"type": "string", "minLength": 1},
                    "independent_of_implementation": {"const": True},
                    "completed_at_utc": {"type": "string"},
                    "attestation": _attestation_schema(),
                },
            },
            "bound_identities": {
                "type": "object", "additionalProperties": False,
                "required": [
                    "production_profile_fingerprint", "v2_38_portable_evidence",
                    "v2_38_streaming_manifest",
                    "v2_38_predecessor_production_command_sha256",
                    "v2_39_candidate_production_command_sha256",
                ],
                "properties": {
                    "production_profile_fingerprint": {"const": PRODUCTION_PROFILE_FINGERPRINT},
                    "v2_38_portable_evidence": _identity_schema(V2_38_PORTABLE_IDENTITY),
                    "v2_38_streaming_manifest": _identity_schema(V2_38_MANIFEST_IDENTITY),
                    "v2_38_predecessor_production_command_sha256": {"const": V2_38_PRODUCTION_COMMAND_SHA256},
                    "v2_39_candidate_production_command_sha256": {"const": PRODUCTION_COMMAND_SHA256},
                },
            },
            "review_scope": {
                "type": "object", "additionalProperties": False,
                "required": list(REVIEW_SCOPE_KEYS),
                "properties": {key: {"const": True} for key in REVIEW_SCOPE_KEYS},
            },
            "decision": {
                "type": "object", "additionalProperties": False,
                "required": [
                    "disposition", "blocking_findings", "authorizes_frozen_replay",
                    "authorizes_large_proving_run", "grants_security_claim", "production_closed",
                ],
                "properties": {
                    "disposition": {"const": "approved_for_production_prefreeze_only"},
                    "blocking_findings": {"type": "array", "maxItems": 0},
                    "authorizes_frozen_replay": {"const": False},
                    "authorizes_large_proving_run": {"const": False},
                    "grants_security_claim": {"const": False},
                    "production_closed": {"const": False},
                },
            },
        },
    }


def launch_manifest_schema() -> dict[str, object]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://pq-rbbc.invalid/schema/cap-unified-tree-launch-manifest-v2.39.json",
        "title": "PQ-RBBC unified-tree production pre-freeze launch manifest v2.39",
        "type": "object", "additionalProperties": False,
        "required": [
            "format", "implementation_version", "launch_id", "created_at_utc",
            "production_profile_fingerprint", "sealed_predecessor", "attestations",
            "execution", "authorization_boundary",
        ],
        "properties": {
            "format": {"const": LAUNCH_FORMAT},
            "implementation_version": {"const": IMPLEMENTATION_VERSION},
            "launch_id": {"type": "string", "minLength": 1},
            "created_at_utc": {"type": "string"},
            "production_profile_fingerprint": {"const": PRODUCTION_PROFILE_FINGERPRINT},
            "sealed_predecessor": _identity_schema(V2_38_PORTABLE_IDENTITY),
            "attestations": {
                "type": "object", "additionalProperties": False,
                "required": ["resource_reservation", "independent_review"],
                "properties": {
                    "resource_reservation": _identity_schema(),
                    "independent_review": _identity_schema(),
                },
            },
            "execution": {
                "type": "object", "additionalProperties": False,
                "required": [
                    "phase", "command", "command_sha256", "external_output",
                    "fresh_output_required", "existing_output_overwrite_forbidden",
                    "resume_requires_expected_checkpoint_identity",
                ],
                "properties": {
                    "phase": {"const": "production-prefreeze"},
                    "command": {"const": PRODUCTION_COMMAND},
                    "command_sha256": {"const": PRODUCTION_COMMAND_SHA256},
                    "external_output": {"const": str(PRODUCTION_OUTPUT)},
                    "fresh_output_required": {"const": True},
                    "existing_output_overwrite_forbidden": {"const": True},
                    "resume_requires_expected_checkpoint_identity": {"const": True},
                },
            },
            "authorization_boundary": {
                "type": "object", "additionalProperties": False,
                "required": [
                    "production_prefreeze_only", "large_replay_authorized",
                    "large_proving_run_authorized", "security_claim_granted",
                    "production_closed",
                ],
                "properties": {
                    "production_prefreeze_only": {"const": True},
                    "large_replay_authorized": {"const": False},
                    "large_proving_run_authorized": {"const": False},
                    "security_claim_granted": {"const": False},
                    "production_closed": {"const": False},
                },
            },
        },
    }


def _draft_attestation() -> dict[str, object]:
    return {
        "method": "organization-record",
        "reference": "REPLACE-WITH-VERIFIABLE-REFERENCE",
        "authenticity_confirmed": False,
    }


def resource_template() -> dict[str, object]:
    return {
        "format": RESOURCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "reservation_id": "REPLACE-WITH-RESERVATION-ID",
        "production_profile_fingerprint": PRODUCTION_PROFILE_FINGERPRINT,
        "v2_38_portable_evidence": dict(V2_38_PORTABLE_IDENTITY),
        "operator": {
            "identifier": "REPLACE-WITH-OPERATOR-IDENTITY",
            "role": "REPLACE-WITH-OPERATOR-ROLE",
            "approved_at_utc": "1970-01-01T00:00:00Z",
            "approved": False,
            "attestation": _draft_attestation(),
        },
        "reservation_window": {
            "starts_at_utc": "1970-01-01T00:00:00Z",
            "ends_at_utc": "1970-01-01T00:00:00Z",
            "wall_clock_seconds": 0,
        },
        "execution_scope": {
            "phase": "production-prefreeze",
            "external_output": str(PRODUCTION_OUTPUT),
            "exact_command_sha256": PRODUCTION_COMMAND_SHA256,
            "fresh_cache_required": True,
            "existing_output_overwrite_forbidden": True,
            "legacy_evidence_read_only": True,
            "other_tree_observed_stream_bytes_reusable": False,
        },
        "reserved_resources": {
            "cpu_cores": MIN_CPU_CORES,
            "available_memory_bytes": MIN_AVAILABLE_MEMORY_BYTES,
            "free_disk_bytes": MIN_FREE_DISK_BYTES,
            "exclusive_output_directory": True,
            "accepts_runtime_estimate_unavailable": False,
        },
        "claim_boundary": {
            "authorizes_production_prefreeze": False,
            "authorizes_frozen_replay": False,
            "authorizes_large_proving_run": False,
            "grants_security_claim": False,
            "production_closed": False,
        },
    }


def review_template() -> dict[str, object]:
    return {
        "format": REVIEW_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "review_id": "REPLACE-WITH-REVIEW-ID",
        "reviewer": {
            "identifier": "REPLACE-WITH-REVIEWER-IDENTITY",
            "affiliation": "REPLACE-WITH-AFFILIATION",
            "independent_of_implementation": False,
            "completed_at_utc": "1970-01-01T00:00:00Z",
            "attestation": _draft_attestation(),
        },
        "bound_identities": {
            "production_profile_fingerprint": PRODUCTION_PROFILE_FINGERPRINT,
            "v2_38_portable_evidence": dict(V2_38_PORTABLE_IDENTITY),
            "v2_38_streaming_manifest": dict(V2_38_MANIFEST_IDENTITY),
            "v2_38_predecessor_production_command_sha256": V2_38_PRODUCTION_COMMAND_SHA256,
            "v2_39_candidate_production_command_sha256": PRODUCTION_COMMAND_SHA256,
        },
        "review_scope": {key: False for key in REVIEW_SCOPE_KEYS},
        "decision": {
            "disposition": "pending",
            "blocking_findings": ["independent review has not been performed"],
            "authorizes_frozen_replay": False,
            "authorizes_large_proving_run": False,
            "grants_security_claim": False,
            "production_closed": False,
        },
    }


def launch_template() -> dict[str, object]:
    placeholder = {"filename": "NOT-FROZEN", "bytes": 0, "sha256": "0" * 64}
    return {
        "format": LAUNCH_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "launch_id": "REPLACE-WITH-LAUNCH-ID",
        "created_at_utc": "1970-01-01T00:00:00Z",
        "production_profile_fingerprint": PRODUCTION_PROFILE_FINGERPRINT,
        "sealed_predecessor": dict(V2_38_PORTABLE_IDENTITY),
        "attestations": {
            "resource_reservation": dict(placeholder),
            "independent_review": dict(placeholder),
        },
        "execution": {
            "phase": "production-prefreeze",
            "command": PRODUCTION_COMMAND,
            "command_sha256": PRODUCTION_COMMAND_SHA256,
            "external_output": str(PRODUCTION_OUTPUT),
            "fresh_output_required": True,
            "existing_output_overwrite_forbidden": True,
            "resume_requires_expected_checkpoint_identity": True,
        },
        "authorization_boundary": {
            "production_prefreeze_only": False,
            "large_replay_authorized": False,
            "large_proving_run_authorized": False,
            "security_claim_granted": False,
            "production_closed": False,
        },
    }


def _validate_identity(value: object, expected: Mapping[str, object] | None, label: str) -> list[str]:
    failures = _exact_keys(value, {"filename", "bytes", "sha256"}, label)
    if not isinstance(value, dict):
        return failures
    if not _nonempty(value.get("filename")):
        failures.append(f"{label}:filename")
    if not _is_int(value.get("bytes")) or value.get("bytes", 0) < 1:
        failures.append(f"{label}:bytes")
    digest = value.get("sha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        failures.append(f"{label}:sha256")
    if expected is not None:
        for key, wanted in expected.items():
            if value.get(key) != wanted:
                failures.append(f"{label}:{key}:binding")
    return failures


def _validate_attestation(value: object, label: str) -> list[str]:
    failures = _exact_keys(value, {"method", "reference", "authenticity_confirmed"}, label)
    if not isinstance(value, dict):
        return failures
    if value.get("method") not in {"signed-json", "detached-signature", "organization-record"}:
        failures.append(f"{label}:method")
    if not _concrete(value.get("reference")):
        failures.append(f"{label}:reference")
    if value.get("authenticity_confirmed") is not True:
        failures.append(f"{label}:authenticity")
    return failures


def validate_resource(document: object) -> tuple[str, ...]:
    keys = {
        "format", "implementation_version", "reservation_id",
        "production_profile_fingerprint", "v2_38_portable_evidence", "operator",
        "reservation_window", "execution_scope", "reserved_resources", "claim_boundary",
    }
    failures = _exact_keys(document, keys, "root")
    if not isinstance(document, dict):
        return tuple(failures)
    expected = {
        "format": RESOURCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "production_profile_fingerprint": PRODUCTION_PROFILE_FINGERPRINT,
    }
    for key, wanted in expected.items():
        if document.get(key) != wanted:
            failures.append(key)
    if not _concrete(document.get("reservation_id")):
        failures.append("reservation_id")
    failures.extend(_validate_identity(document.get("v2_38_portable_evidence"), V2_38_PORTABLE_IDENTITY, "predecessor"))
    operator = document.get("operator")
    failures.extend(_exact_keys(operator, {"identifier", "role", "approved_at_utc", "approved", "attestation"}, "operator"))
    if isinstance(operator, dict):
        if not _concrete(operator.get("identifier")): failures.append("operator:identifier")
        if not _concrete(operator.get("role")): failures.append("operator:role")
        if not _canonical_utc(operator.get("approved_at_utc")): failures.append("operator:approved_at_utc")
        if operator.get("approved") is not True: failures.append("operator:approved")
        failures.extend(_validate_attestation(operator.get("attestation"), "operator:attestation"))
    window = document.get("reservation_window")
    failures.extend(_exact_keys(window, {"starts_at_utc", "ends_at_utc", "wall_clock_seconds"}, "window"))
    if isinstance(window, dict):
        start, end = window.get("starts_at_utc"), window.get("ends_at_utc")
        if not _canonical_utc(start): failures.append("window:starts_at_utc")
        if not _canonical_utc(end): failures.append("window:ends_at_utc")
        if _canonical_utc(start) and _canonical_utc(end) and str(start) >= str(end): failures.append("window:order")
        if not _is_int(window.get("wall_clock_seconds")) or window.get("wall_clock_seconds", 0) < 1:
            failures.append("window:wall_clock_seconds")
        if _canonical_utc(start) and _canonical_utc(end) and _is_int(window.get("wall_clock_seconds")):
            elapsed = int((
                datetime.strptime(str(end), "%Y-%m-%dT%H:%M:%SZ")
                - datetime.strptime(str(start), "%Y-%m-%dT%H:%M:%SZ")
            ).total_seconds())
            if elapsed != window.get("wall_clock_seconds"):
                failures.append("window:duration")
    scope_expected = {
        "phase": "production-prefreeze", "external_output": str(PRODUCTION_OUTPUT),
        "exact_command_sha256": PRODUCTION_COMMAND_SHA256, "fresh_cache_required": True,
        "existing_output_overwrite_forbidden": True, "legacy_evidence_read_only": True,
        "other_tree_observed_stream_bytes_reusable": False,
    }
    scope = document.get("execution_scope")
    failures.extend(_exact_keys(scope, set(scope_expected), "scope"))
    if isinstance(scope, dict):
        for key, wanted in scope_expected.items():
            if scope.get(key) != wanted: failures.append(f"scope:{key}")
    resources = document.get("reserved_resources")
    minimums = {"cpu_cores": MIN_CPU_CORES, "available_memory_bytes": MIN_AVAILABLE_MEMORY_BYTES, "free_disk_bytes": MIN_FREE_DISK_BYTES}
    resource_keys = set(minimums) | {"exclusive_output_directory", "accepts_runtime_estimate_unavailable"}
    failures.extend(_exact_keys(resources, resource_keys, "resources"))
    if isinstance(resources, dict):
        for key, minimum in minimums.items():
            if not _is_int(resources.get(key)) or resources.get(key, 0) < minimum: failures.append(f"resources:{key}")
        for key in ("exclusive_output_directory", "accepts_runtime_estimate_unavailable"):
            if resources.get(key) is not True: failures.append(f"resources:{key}")
    boundary_expected = {
        "authorizes_production_prefreeze": True, "authorizes_frozen_replay": False,
        "authorizes_large_proving_run": False, "grants_security_claim": False,
        "production_closed": False,
    }
    boundary = document.get("claim_boundary")
    failures.extend(_exact_keys(boundary, set(boundary_expected), "boundary"))
    if isinstance(boundary, dict):
        for key, wanted in boundary_expected.items():
            if boundary.get(key) is not wanted: failures.append(f"boundary:{key}")
    return tuple(sorted(set(failures)))


def validate_review(document: object) -> tuple[str, ...]:
    keys = {"format", "implementation_version", "review_id", "reviewer", "bound_identities", "review_scope", "decision"}
    failures = _exact_keys(document, keys, "root")
    if not isinstance(document, dict): return tuple(failures)
    if document.get("format") != REVIEW_FORMAT: failures.append("format")
    if document.get("implementation_version") != IMPLEMENTATION_VERSION: failures.append("implementation_version")
    if not _concrete(document.get("review_id")): failures.append("review_id")
    reviewer = document.get("reviewer")
    failures.extend(_exact_keys(reviewer, {"identifier", "affiliation", "independent_of_implementation", "completed_at_utc", "attestation"}, "reviewer"))
    if isinstance(reviewer, dict):
        if not _concrete(reviewer.get("identifier")): failures.append("reviewer:identifier")
        if not _concrete(reviewer.get("affiliation")): failures.append("reviewer:affiliation")
        if reviewer.get("independent_of_implementation") is not True: failures.append("reviewer:independence")
        if not _canonical_utc(reviewer.get("completed_at_utc")): failures.append("reviewer:completed_at_utc")
        failures.extend(_validate_attestation(reviewer.get("attestation"), "reviewer:attestation"))
    bindings_expected = {
        "production_profile_fingerprint": PRODUCTION_PROFILE_FINGERPRINT,
        "v2_38_portable_evidence": V2_38_PORTABLE_IDENTITY,
        "v2_38_streaming_manifest": V2_38_MANIFEST_IDENTITY,
        "v2_38_predecessor_production_command_sha256": V2_38_PRODUCTION_COMMAND_SHA256,
        "v2_39_candidate_production_command_sha256": PRODUCTION_COMMAND_SHA256,
    }
    bindings = document.get("bound_identities")
    failures.extend(_exact_keys(bindings, set(bindings_expected), "bindings"))
    if isinstance(bindings, dict):
        for key, wanted in bindings_expected.items():
            if bindings.get(key) != wanted: failures.append(f"bindings:{key}")
    scope = document.get("review_scope")
    failures.extend(_exact_keys(scope, set(REVIEW_SCOPE_KEYS), "scope"))
    if isinstance(scope, dict):
        for key in REVIEW_SCOPE_KEYS:
            if scope.get(key) is not True: failures.append(f"scope:{key}")
    decision_expected = {
        "disposition": "approved_for_production_prefreeze_only", "blocking_findings": [],
        "authorizes_frozen_replay": False, "authorizes_large_proving_run": False,
        "grants_security_claim": False, "production_closed": False,
    }
    decision = document.get("decision")
    failures.extend(_exact_keys(decision, set(decision_expected), "decision"))
    if isinstance(decision, dict):
        for key, wanted in decision_expected.items():
            if decision.get(key) != wanted: failures.append(f"decision:{key}")
    return tuple(sorted(set(failures)))


def validate_launch(document: object, reservation: Mapping[str, object] | None = None, review: Mapping[str, object] | None = None) -> tuple[str, ...]:
    keys = {"format", "implementation_version", "launch_id", "created_at_utc", "production_profile_fingerprint", "sealed_predecessor", "attestations", "execution", "authorization_boundary"}
    failures = _exact_keys(document, keys, "root")
    if not isinstance(document, dict): return tuple(failures)
    expected = {"format": LAUNCH_FORMAT, "implementation_version": IMPLEMENTATION_VERSION, "production_profile_fingerprint": PRODUCTION_PROFILE_FINGERPRINT}
    for key, wanted in expected.items():
        if document.get(key) != wanted: failures.append(key)
    if not _concrete(document.get("launch_id")): failures.append("launch_id")
    if not _canonical_utc(document.get("created_at_utc")): failures.append("created_at_utc")
    failures.extend(_validate_identity(document.get("sealed_predecessor"), V2_38_PORTABLE_IDENTITY, "predecessor"))
    attestations = document.get("attestations")
    failures.extend(_exact_keys(attestations, {"resource_reservation", "independent_review"}, "attestations"))
    if isinstance(attestations, dict):
        failures.extend(_validate_identity(attestations.get("resource_reservation"), reservation, "attestations:resource"))
        failures.extend(_validate_identity(attestations.get("independent_review"), review, "attestations:review"))
    execution_expected = {
        "phase": "production-prefreeze", "command": PRODUCTION_COMMAND,
        "command_sha256": PRODUCTION_COMMAND_SHA256, "external_output": str(PRODUCTION_OUTPUT),
        "fresh_output_required": True, "existing_output_overwrite_forbidden": True,
        "resume_requires_expected_checkpoint_identity": True,
    }
    execution = document.get("execution")
    failures.extend(_exact_keys(execution, set(execution_expected), "execution"))
    if isinstance(execution, dict):
        for key, wanted in execution_expected.items():
            if execution.get(key) != wanted: failures.append(f"execution:{key}")
    boundary_expected = {
        "production_prefreeze_only": True, "large_replay_authorized": False,
        "large_proving_run_authorized": False, "security_claim_granted": False,
        "production_closed": False,
    }
    boundary = document.get("authorization_boundary")
    failures.extend(_exact_keys(boundary, set(boundary_expected), "boundary"))
    if isinstance(boundary, dict):
        for key, wanted in boundary_expected.items():
            if boundary.get(key) is not wanted: failures.append(f"boundary:{key}")
    return tuple(sorted(set(failures)))


def build_launch_manifest(resource_path: Path, review_path: Path, launch_id: str, created_at_utc: str) -> dict[str, object]:
    if not _outside_repository(resource_path) or not _outside_repository(review_path):
        raise LaunchPreflightError("attestations must be external")
    if resource_path.name != RESOURCE_FILENAME or review_path.name != REVIEW_FILENAME:
        raise LaunchPreflightError("attestation filename mismatch")
    resource, review = _read_json(resource_path), _read_json(review_path)
    resource_failures, review_failures = validate_resource(resource), validate_review(review)
    if resource_failures: raise LaunchPreflightError(f"resource reservation invalid: {resource_failures}")
    if review_failures: raise LaunchPreflightError(f"independent review invalid: {review_failures}")
    if not _concrete(launch_id) or not _canonical_utc(created_at_utc):
        raise LaunchPreflightError("launch id and canonical UTC creation time are required")
    if (
        created_at_utc < resource["operator"]["approved_at_utc"]
        or created_at_utc < review["reviewer"]["completed_at_utc"]
    ):
        raise LaunchPreflightError("launch manifest predates an attestation")
    return {
        "format": LAUNCH_FORMAT, "implementation_version": IMPLEMENTATION_VERSION,
        "launch_id": launch_id, "created_at_utc": created_at_utc,
        "production_profile_fingerprint": PRODUCTION_PROFILE_FINGERPRINT,
        "sealed_predecessor": dict(V2_38_PORTABLE_IDENTITY),
        "attestations": {"resource_reservation": identity(resource_path), "independent_review": identity(review_path)},
        "execution": {
            "phase": "production-prefreeze", "command": PRODUCTION_COMMAND,
            "command_sha256": PRODUCTION_COMMAND_SHA256, "external_output": str(PRODUCTION_OUTPUT),
            "fresh_output_required": True, "existing_output_overwrite_forbidden": True,
            "resume_requires_expected_checkpoint_identity": True,
        },
        "authorization_boundary": {
            "production_prefreeze_only": True, "large_replay_authorized": False,
            "large_proving_run_authorized": False, "security_claim_granted": False,
            "production_closed": False,
        },
    }


def _candidate(path: Path | None, expected_filename: str, validator, bindings: tuple[Mapping[str, object] | None, ...] = ()) -> dict[str, object]:
    result: dict[str, object] = {"provided": path is not None, "external": False, "schema_valid": False, "identity_frozen": False, "candidate_acceptable_for_freeze": False, "failures": []}
    failures = result["failures"]
    assert isinstance(failures, list)
    if path is None: failures.append("not_provided"); return result
    if path.name != expected_filename: failures.append("filename")
    if not _outside_repository(path): failures.append("must_be_external")
    else: result["external"] = True
    if not path.is_file(): failures.append("missing"); return result
    result["identity"] = identity(path)
    try: document = _read_json(path)
    except (OSError, ValueError, json.JSONDecodeError): failures.append("json"); return result
    semantic = validator(document, *bindings)
    if semantic: failures.extend(f"schema:{item}" for item in semantic)
    else: result["schema_valid"] = True
    if not failures:
        result["candidate_acceptable_for_freeze"] = True
        failures.append("identity_not_frozen")
    return result


def _available_memory_bytes() -> int:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"): return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError): pass
    return 0


def claim_boundary() -> dict[str, bool]:
    return {
        "v2_39_attestation_schemas_implemented": True,
        "v2_39_deliberately_invalid_templates_implemented": True,
        "v2_39_launch_manifest_generator_implemented": True,
        "v2_39_read_only_identity_preflight_implemented": True,
        "v2_38_portable_seal_bound": True,
        "operator_resource_reservation_frozen": False,
        "independent_review_frozen": False,
        "launch_manifest_frozen": False,
        "production_prefreeze_authorized": False,
        "production_prefreeze_started": False,
        "production_stream_materialized": False,
        "production_checkpoint_materialized": False,
        "production_relation_replayed": False,
        "production_runner_scale_qualified": False,
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
    qualification = (
        "PYTHONPATH=src python -u src/pq_rbbc_cap_unified_tree_launch_preflight.py "
        "--phase qualification --v2-38-portable "
        "artifacts/metadata/cap_unified_tree_streaming_prefreeze_v2_38/"
        "pq_rbbc_cap_unified_tree_streaming_prefreeze_portable_evidence_v2_38.json "
        f"--output {EXTERNAL_ROOT}/qualification --fresh-output"
    )
    preflight = (
        "PYTHONPATH=src python -u src/pq_rbbc_cap_unified_tree_launch_preflight.py "
        "--phase launch-preflight --v2-38-portable "
        "artifacts/metadata/cap_unified_tree_streaming_prefreeze_v2_38/"
        "pq_rbbc_cap_unified_tree_streaming_prefreeze_portable_evidence_v2_38.json "
        f"--resource-reservation {EXTERNAL_ROOT}/{RESOURCE_FILENAME} "
        f"--independent-review {EXTERNAL_ROOT}/{REVIEW_FILENAME} "
        f"--launch-manifest {EXTERNAL_ROOT}/{LAUNCH_FILENAME} "
        f"--output {EXTERNAL_ROOT}/{REPORT_FILENAME} --fresh-output"
    )
    author = (
        "PYTHONPATH=src python -u src/pq_rbbc_cap_unified_tree_launch_preflight.py "
        f"--phase author-launch-manifest --resource-reservation {EXTERNAL_ROOT}/{RESOURCE_FILENAME} "
        f"--independent-review {EXTERNAL_ROOT}/{REVIEW_FILENAME} "
        "--launch-id REPLACE-WITH-LAUNCH-ID --created-at-utc REPLACE-WITH-CANONICAL-UTC "
        f"--output {EXTERNAL_ROOT}/{LAUNCH_FILENAME} --fresh-output"
    )
    return {
        "qualification": {"command": qualification, "sha256": hashlib.sha256(qualification.encode()).hexdigest(), "executable_now": True},
        "launch_preflight": {"command": preflight, "sha256": hashlib.sha256(preflight.encode()).hexdigest(), "executable_now": True, "read_only_except_report": True},
        "author_launch_manifest": {"command": author, "sha256": hashlib.sha256(author.encode()).hexdigest(), "executable_now": False, "withheld_reason": "valid external operator reservation and independent review are absent"},
        "production_prefreeze": {"command": PRODUCTION_COMMAND, "sha256": PRODUCTION_COMMAND_SHA256, "executable_now": False, "authorized_now": False},
        "large_replay": {"command": None, "executable_now": False, "authorized_now": False},
        "large_proving_run": {"command": None, "executable_now": False, "authorized_now": False},
    }


def build_manifest() -> dict[str, object]:
    return {
        "format": FORMAT, "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "sealed_predecessor": dict(V2_38_PORTABLE_IDENTITY),
        "production_profile_fingerprint": PRODUCTION_PROFILE_FINGERPRINT,
        "v2_38_predecessor_production_command_sha256": V2_38_PRODUCTION_COMMAND_SHA256,
        "v2_39_candidate_production_command_sha256": PRODUCTION_COMMAND_SHA256,
        "schemas": {
            "resource_reservation": {"path": str(RESOURCE_SCHEMA_PATH.relative_to(ROOT)), "sha256": document_sha256(resource_reservation_schema())},
            "independent_review": {"path": str(REVIEW_SCHEMA_PATH.relative_to(ROOT)), "sha256": document_sha256(independent_review_schema())},
            "launch_manifest": {"path": str(LAUNCH_SCHEMA_PATH.relative_to(ROOT)), "sha256": document_sha256(launch_manifest_schema())},
        },
        "templates": {
            "resource_reservation": {"filename": RESOURCE_TEMPLATE_FILENAME, "deliberately_schema_invalid": True},
            "independent_review": {"filename": REVIEW_TEMPLATE_FILENAME, "deliberately_schema_invalid": True},
            "launch_manifest": {"filename": LAUNCH_TEMPLATE_FILENAME, "deliberately_schema_invalid": True},
        },
        "minimum_resources": {"cpu_cores": MIN_CPU_CORES, "available_memory_bytes": MIN_AVAILABLE_MEMORY_BYTES, "free_disk_bytes": MIN_FREE_DISK_BYTES, "wall_clock_seconds": None},
        "identity_freeze_policy": {"schema_validity_is_attestation": False, "candidate_identity_is_frozen_by_presence": False, "portable_sealer_must_bind_exact_bytes_and_sha256": True, "external_attestations_must_not_be_fabricated": True},
        "exact_commands": exact_commands(),
        "claim_boundary": claim_boundary(),
    }


def validate_tracked_contracts(manifest_path: Path = MANIFEST_PATH) -> tuple[str, ...]:
    failures: list[str] = []
    if identity(V2_38_PORTABLE_PATH) != V2_38_PORTABLE_IDENTITY: failures.append("v2_38_portable_identity")
    if identity(v2_38.MANIFEST_PATH) != V2_38_MANIFEST_IDENTITY: failures.append("v2_38_manifest_identity")
    expected_files = {
        manifest_path: build_manifest(), RESOURCE_SCHEMA_PATH: resource_reservation_schema(),
        REVIEW_SCHEMA_PATH: independent_review_schema(), LAUNCH_SCHEMA_PATH: launch_manifest_schema(),
    }
    for path, expected in expected_files.items():
        if not path.is_file() or path.read_bytes() != canonical_json(expected): failures.append(path.name)
    return tuple(sorted(failures))


def build_preflight(manifest_path: Path, v2_38_portable: Path, resource_path: Path | None, review_path: Path | None, launch_path: Path | None, capacity_path: Path = Path("/tmp")) -> dict[str, object]:
    tracked_failures = validate_tracked_contracts(manifest_path)
    predecessor_ok = v2_38_portable.is_file() and identity(v2_38_portable) == V2_38_PORTABLE_IDENTITY
    resource = _candidate(resource_path, RESOURCE_FILENAME, validate_resource)
    review = _candidate(review_path, REVIEW_FILENAME, validate_review)
    resource_identity = resource.get("identity") if resource.get("schema_valid") is True else None
    review_identity = review.get("identity") if review.get("schema_valid") is True else None
    launch = _candidate(launch_path, LAUNCH_FILENAME, validate_launch, (resource_identity, review_identity))
    capacity = {
        "cpu_cores": os.cpu_count() or 0,
        "available_memory_bytes": _available_memory_bytes(),
        "free_disk_bytes": shutil.disk_usage(capacity_path).free,
        "minimums_met": False,
        "capacity_is_reservation": False,
        "capacity_is_execution_authorization": False,
    }
    capacity["minimums_met"] = (
        capacity["cpu_cores"] >= MIN_CPU_CORES
        and capacity["available_memory_bytes"] >= MIN_AVAILABLE_MEMORY_BYTES
        and capacity["free_disk_bytes"] >= MIN_FREE_DISK_BYTES
    )
    candidates = {"resource_reservation": resource, "independent_review": review, "launch_manifest": launch}
    freeze_ready = predecessor_ok and not tracked_failures and all(item["candidate_acceptable_for_freeze"] is True for item in candidates.values())
    blockers: list[str] = []
    if tracked_failures: blockers.append("tracked contracts are not exact")
    if not predecessor_ok: blockers.append("v2.38 portable predecessor is missing or invalid")
    for label, status in candidates.items():
        if status["candidate_acceptable_for_freeze"] is not True: blockers.append(f"{label} candidate is missing or invalid")
        blockers.append(f"{label} identity is not frozen")
    if not capacity["minimums_met"]: blockers.append("current host capacity is below the planning minimum")
    blockers.extend([
        "production stream and checkpoint have not been materialized",
        "production runner has not been qualified at scale",
        "explicit production execution authorization is outside v2.39 scope",
    ])
    return {
        "format": REPORT_FORMAT, "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID, "manifest": identity(manifest_path),
        "sealed_predecessor": {"provided": True, "verified": predecessor_ok, "identity": identity(v2_38_portable) if v2_38_portable.is_file() else None},
        "tracked_contracts": {"verified": not tracked_failures, "failures": list(tracked_failures)},
        "external_candidates": candidates, "candidate_identity_set_ready_for_later_freeze": freeze_ready,
        "capacity_observation": capacity, "blockers": blockers,
        "result": {
            "safe_to_run_read_only_preflight": predecessor_ok and not tracked_failures,
            "safe_to_emit_draft_templates": predecessor_ok and not tracked_failures,
            "safe_to_author_launch_manifest_candidate": resource["candidate_acceptable_for_freeze"] is True and review["candidate_acceptable_for_freeze"] is True,
            "safe_to_freeze_launch_identity_set": freeze_ready,
            "safe_to_start_production_prefreeze": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
        },
        "claim_boundary": claim_boundary(),
    }


def qualify(output: Path, v2_38_portable: Path) -> dict[str, object]:
    if not _outside_repository(output): raise LaunchPreflightError("qualification output must be external")
    if output.exists(): raise FileExistsError("qualification output already exists")
    if identity(v2_38_portable) != V2_38_PORTABLE_IDENTITY: raise LaunchPreflightError("v2.38 predecessor identity mismatch")
    output.mkdir(parents=True)
    documents = {
        RESOURCE_TEMPLATE_FILENAME: resource_template(), REVIEW_TEMPLATE_FILENAME: review_template(), LAUNCH_TEMPLATE_FILENAME: launch_template(),
    }
    for filename, document in documents.items(): (output / filename).write_bytes(canonical_json(document))
    report = build_preflight(MANIFEST_PATH, v2_38_portable, None, None, None, output)
    (output / REPORT_FILENAME).write_bytes(canonical_json(report))
    checks = {
        "tracked_contracts_exact": not validate_tracked_contracts(),
        "v2_38_portable_identity_exact": identity(v2_38_portable) == V2_38_PORTABLE_IDENTITY,
        "resource_template_rejected": bool(validate_resource(resource_template())),
        "review_template_rejected": bool(validate_review(review_template())),
        "launch_template_rejected": bool(validate_launch(launch_template())),
        "missing_candidates_fail_closed": report["result"]["safe_to_freeze_launch_identity_set"] is False,
        "production_prefreeze_not_authorized": report["result"]["safe_to_start_production_prefreeze"] is False,
        "large_replay_not_started": report["result"]["safe_to_start_large_replay"] is False,
        "large_proving_not_started": report["result"]["safe_to_start_large_proving_run"] is False,
    }
    qualification = {
        "format": QUALIFICATION_FORMAT, "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID, "manifest": identity(MANIFEST_PATH),
        "sealed_predecessor": dict(V2_38_PORTABLE_IDENTITY),
        "external_outputs": {key: identity(output / key) for key in (*documents, REPORT_FILENAME)},
        "checks": checks,
        "result": {
            "attestation_schemas_qualified": all(checks.values()),
            "real_operator_reservation_present": False,
            "real_independent_review_present": False,
            "launch_manifest_authored": False,
            "launch_identity_set_frozen": False,
            "safe_to_start_production_prefreeze": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
        },
        "observations": {"production_records_materialized": 0, "production_relation_rows_replayed": 0, "assignment_rows": 0, "br1cs_rows": 0, "proofs_generated": 0},
        "claim_boundary": claim_boundary(),
    }
    if not all(checks.values()): raise LaunchPreflightError("v2.39 qualification failed")
    (output / QUALIFICATION_FILENAME).write_bytes(canonical_json(qualification))
    return qualification


def _write_fresh(path: Path, document: object) -> None:
    if not _outside_repository(path): raise LaunchPreflightError("output must be external")
    if path.exists(): raise FileExistsError("output already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(document))


def reject_production(output: Path) -> None:
    if output.exists(): raise FileExistsError("production output already exists")
    raise LaunchPreflightError("v2.39 does not authorize production-prefreeze")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("qualification", "launch-preflight", "author-launch-manifest", "production-prefreeze"), required=True)
    parser.add_argument("--v2-38-portable", type=Path, default=V2_38_PORTABLE_PATH)
    parser.add_argument("--resource-reservation", type=Path)
    parser.add_argument("--independent-review", type=Path)
    parser.add_argument("--launch-manifest", type=Path)
    parser.add_argument("--launch-id")
    parser.add_argument("--created-at-utc")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fresh-output", action="store_true")
    args = parser.parse_args()
    if not args.fresh_output: raise LaunchPreflightError("v2.39 requires --fresh-output")
    if args.phase == "production-prefreeze": reject_production(args.output)
    if args.phase == "qualification":
        document = qualify(args.output, args.v2_38_portable)
    elif args.phase == "launch-preflight":
        document = build_preflight(MANIFEST_PATH, args.v2_38_portable, args.resource_reservation, args.independent_review, args.launch_manifest, args.output.parent)
        _write_fresh(args.output, document)
    else:
        if args.resource_reservation is None or args.independent_review is None:
            raise LaunchPreflightError("both external attestations are required")
        document = build_launch_manifest(args.resource_reservation, args.independent_review, args.launch_id or "", args.created_at_utc or "")
        if args.output.name != LAUNCH_FILENAME: raise LaunchPreflightError("launch manifest filename mismatch")
        _write_fresh(args.output, document)
    print(json.dumps({"phase": args.phase, "output": str(args.output), "result": document.get("result", {}), "safe_to_start_production_prefreeze": False}, sort_keys=True))


if __name__ == "__main__":
    main()
