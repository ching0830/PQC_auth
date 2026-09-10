#!/usr/bin/env python3
"""PQ-RBBC v2.43 reservation/review binding checkpoint.

This module validates an operator approval record, a v2.42-bound resource
reservation, and a later named-human review.  It deliberately has no producer
or production executor: ``production-prefreeze`` always fails closed.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import shlex
import subprocess
from typing import Callable

from pq_rbbc_launch_io_v2_41 import (
    ArtifactRoot,
    MAX_JSON_BYTES,
    Snapshot,
    ValidationError,
    canonical_json,
    exact_path,
    read_snapshot,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_VERSION = "2.43"
TARGET_IMPLEMENTATION_VERSION = "2.42"
FORMAT = "PQRBBC-CAP-UNIFIED-TREE-RESERVATION-BINDING-CHECKPOINT-1"
REPORT_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-RESERVATION-BINDING-REPORT-1"
APPROVAL_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-OPERATOR-APPROVAL-1"
RESOURCE_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-RESOURCE-RESERVATION-5"
REVIEW_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-INDEPENDENT-REVIEW-5"
SUBJECT_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-REVIEW-SUBJECT-2"
RELATION_ID = "pq-rbbc/cap/unified-tree/reservation-binding/v1"

REVIEWED_IMPLEMENTATION_COMMIT = "d6d349020f8ef22e65115130c335ea6db7e337b4"
REVIEWED_IMPLEMENTATION_TREE = "1ce0af92a84aa3e5736e9f49929a37d42301f665"
INTEGRATION_BASELINE_COMMIT = "6f6d8c832c0f90d69d96ffe3abd0dcc8b8c562bb"
PRODUCTION_PROFILE_FINGERPRINT = "c270e4681f23955667a6c0640317e7beccc666d60a0cffb40bfdccfcee811b7a"

EXTERNAL_REVIEW_IDENTITIES = {
    "AI_TECHNICAL_RE_REVIEW_zh-TW.md": {
        "filename": "AI_TECHNICAL_RE_REVIEW_zh-TW.md",
        "bytes": 18055,
        "sha256": "d232d1b5fa50e8c839aa883198c1f3909c003c33fa55eae6a0ea2f7259d36a0c",
    },
    "findings.json": {
        "filename": "findings.json",
        "bytes": 19192,
        "sha256": "a190e31fc0787064d6d1746a56c489776ea0ba26cc7171be738e063eef9b228d",
    },
    "SHA256SUMS.txt": {
        "filename": "SHA256SUMS.txt",
        "bytes": 230169,
        "sha256": "34b7c7b07ed6c8f0a23647f2ec529cba7416492b7add078c8107e5705af4f298",
    },
}

TRACKED_DEPENDENCY_IDENTITIES = {
    "src/pq_rbbc_cap_unified_tree_recovery_v2_42.py": {
        "filename": "pq_rbbc_cap_unified_tree_recovery_v2_42.py",
        "bytes": 18842,
        "sha256": "8830b69869658bc3906afdf04a2c0f96dc273fb51869a97684422b11f8d89f75",
    },
    "src/pq_rbbc_recovery_io_v2_42.py": {
        "filename": "pq_rbbc_recovery_io_v2_42.py",
        "bytes": 3839,
        "sha256": "4213d7228f757a29a77243826b4a09d4506e48399c638338d59649b81f611e3d",
    },
    "src/pq_rbbc_cap_provenance_v2_42.py": {
        "filename": "pq_rbbc_cap_provenance_v2_42.py",
        "bytes": 2960,
        "sha256": "034c03900621e4d814e27c3e4ea468b10084c934ab6f0001bd1765c9f7448247",
    },
    "src/pq_rbbc_launch_io_v2_41.py": {
        "filename": "pq_rbbc_launch_io_v2_41.py",
        "bytes": 10564,
        "sha256": "d7589d22abf251f9d2297455bafccaed34be7900b9e11e68ac037d9ad4c3a061",
    },
    "manifests/pq_rbbc_cap_unified_tree_recovery_manifest_v2_42.json": {
        "filename": "pq_rbbc_cap_unified_tree_recovery_manifest_v2_42.json",
        "bytes": 21531,
        "sha256": "e0474efea9df518983e1e86e9304546c02af84ab315c2462edf4ca236a3e78c1",
    },
    "manifests/pq_rbbc_cap_unified_tree_provenance_v2_42.json": {
        "filename": "pq_rbbc_cap_unified_tree_provenance_v2_42.json",
        "bytes": 2927,
        "sha256": "b407a36027b1fde74414599d74502f4d341de1eb2de93e9110c2416b259dcf13",
    },
    "docs/reviews/PQ_RBBC_v2_42_CORRECTIVE_AI_TECHNICAL_RE_REVIEW_RESULT_zh-TW.md": {
        "filename": "PQ_RBBC_v2_42_CORRECTIVE_AI_TECHNICAL_RE_REVIEW_RESULT_zh-TW.md",
        "bytes": 3882,
        "sha256": "75fd61ed8fa1e3dd9d24dbabdc82fe19f7d178e4681a4c4e457e5c762783dcec",
    },
}

FILENAMES = {
    "approval_record": "pq_rbbc_operator_approval_record_v2_42.json",
    "resource_reservation": "pq_rbbc_cap_unified_tree_resource_reservation_v2_43.json",
    "independent_review": "pq_rbbc_cap_unified_tree_independent_review_v2_43.json",
    "launch_manifest": "pq_rbbc_cap_unified_tree_launch_manifest_v2_43.json",
}
CONTRACT_REVIEW_FILENAMES = {
    "report": "AI_TECHNICAL_REVIEW_zh-TW.md",
    "findings": "findings.json",
    "inventory": "SHA256SUMS.txt",
}
SCHEMA_PATHS = {
    "technical_review_status": ROOT / "schemas/pq_rbbc_cap_unified_tree_contract_technical_review_status_v2_43.schema.json",
    "approval_record": ROOT / "schemas/pq_rbbc_cap_unified_tree_operator_approval_v2_43.schema.json",
    "resource_reservation": ROOT / "schemas/pq_rbbc_cap_unified_tree_resource_reservation_v2_43.schema.json",
    "independent_review": ROOT / "schemas/pq_rbbc_cap_unified_tree_independent_review_v2_43.schema.json",
}
MANIFEST_PATH = ROOT / "manifests/pq_rbbc_cap_unified_tree_reservation_binding_manifest_v2_43.json"
TECHNICAL_REVIEW_STATUS_PATH = ROOT / "manifests/pq_rbbc_cap_unified_tree_contract_technical_review_status_v2_43.json"
SOURCE_PATH = ROOT / "src/pq_rbbc_cap_unified_tree_reservation_binding_v2_43.py"
REPORT_FILENAME = "pq_rbbc_cap_unified_tree_reservation_binding_report_v2_43.json"
Clock = Callable[[], datetime]


def trusted_now() -> datetime:
    return datetime.now(timezone.utc)


def check_now(now: datetime) -> datetime:
    if type(now) is not datetime or now.tzinfo is None or now.utcoffset() != timezone.utc.utcoffset(now):
        raise ValidationError("trusted now must be an aware UTC datetime")
    return now


def _utc(value: str) -> datetime:
    if type(value) is not str or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value) is None:
        raise ValidationError("canonical UTC required")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise ValidationError("invalid UTC calendar time") from error


def strict_equal(value, expected) -> bool:
    if type(value) is not type(expected):
        return False
    if type(expected) is dict:
        return value.keys() == expected.keys() and all(strict_equal(value[key], item) for key, item in expected.items())
    if type(expected) is list:
        return len(value) == len(expected) and all(strict_equal(a, b) for a, b in zip(value, expected))
    return value == expected


def identity(path: Path) -> dict:
    return read_snapshot(path).identity


def _identity_schema(expected=None) -> dict:
    fields = {
        "filename": {"type": "string", "minLength": 1},
        "bytes": {"type": "integer", "minimum": 1},
        "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    }
    if expected is not None:
        for key, value in expected.items():
            fields[key]["const"] = value
    return _object(fields)


def _object(properties: dict) -> dict:
    return {"type": "object", "additionalProperties": False,
            "required": list(properties), "properties": properties}


def _string(*, concrete=False) -> dict:
    result = {"type": "string", "minLength": 1}
    if concrete:
        result["x-concrete"] = True
    return result


def _const(value) -> dict:
    type_name = {dict: "object", list: "array", str: "string", bool: "boolean", int: "integer"}[type(value)]
    return {"type": type_name, "const": value}


def validate_schema(value, schema, label="root") -> tuple[str, ...]:
    """Validate the deliberately small, closed schema vocabulary."""
    failures = []
    types = {"object": dict, "array": list, "string": str, "boolean": bool, "integer": int}
    if "type" in schema and type(value) is not types[schema["type"]]:
        return (label + ":type",)
    if "const" in schema and not strict_equal(value, schema["const"]):
        failures.append(label + ":const")
    if "enum" in schema and not any(strict_equal(value, item) for item in schema["enum"]):
        failures.append(label + ":enum")
    # A whole-object const is already a closed-world exact match.  Schemas
    # carrying such a const intentionally need no redundant child grammar.
    if schema.get("type") == "object" and "properties" in schema:
        properties = schema["properties"]
        failures.extend(label + ":missing:" + key for key in schema["required"] if key not in value)
        failures.extend(label + ":extra:" + key for key in value if key not in properties)
        for key in value.keys() & properties.keys():
            failures.extend(validate_schema(value[key], properties[key], label + ":" + key))
    if schema.get("type") == "array" and len(value) > schema.get("maxItems", len(value)):
        failures.append(label + ":length")
    if type(value) is int and value < schema.get("minimum", value):
        failures.append(label + ":minimum")
    if type(value) is str:
        if len(value) < schema.get("minLength", 0):
            failures.append(label + ":length")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            failures.append(label + ":pattern")
        if schema.get("x-concrete") and (not value.strip() or value.startswith("REPLACE-WITH-")):
            failures.append(label + ":placeholder")
        if schema.get("x-canonical-utc"):
            try:
                _utc(value)
            except ValidationError:
                failures.append(label + ":utc")
    return tuple(sorted(failures))


def contract_source_identity() -> dict:
    return identity(SOURCE_PATH)


def implementation_binding() -> dict:
    return {
        "target_implementation_version": TARGET_IMPLEMENTATION_VERSION,
        "reviewed_implementation_commit": REVIEWED_IMPLEMENTATION_COMMIT,
        "reviewed_implementation_tree": REVIEWED_IMPLEMENTATION_TREE,
        "integration_baseline_commit": INTEGRATION_BASELINE_COMMIT,
        "tracked_dependencies": TRACKED_DEPENDENCY_IDENTITIES,
        "reservation_contract_source": contract_source_identity(),
        "bounded_ai_technical_re_review": {
            "disposition": "passed_no_new_blocking_findings",
            "named_independent_human_approval": False,
            "external_artifacts": EXTERNAL_REVIEW_IDENTITIES,
        },
    }


def locations(root: Path) -> dict[str, str]:
    root = exact_path(root)
    return {kind: str(root / name) for kind, name in FILENAMES.items()}


def production_command(root: Path, review_root: Path, contract_review_root: Path,
                       expected_reviewed_commit: str,
                       expected_reviewed_tree: str) -> str:
    paths = locations(root)
    argv = [
        "python", "-u", "src/pq_rbbc_cap_unified_tree_reservation_binding_v2_43.py",
        "--phase", "production-prefreeze",
        "--trusted-artifact-root", str(exact_path(root)),
        "--trusted-review-root", str(exact_path(review_root)),
        "--trusted-contract-review-root", str(exact_path(contract_review_root)),
        "--expected-reviewed-commit", expected_reviewed_commit,
        "--expected-reviewed-tree", expected_reviewed_tree,
        "--resource-reservation", paths["resource_reservation"],
        "--independent-review", paths["independent_review"],
        "--launch-manifest", paths["launch_manifest"],
        "--output", str(exact_path(root) / "production-prefreeze"),
        "--fresh-output",
    ]
    return "PYTHONPATH=src " + shlex.join(argv)


def command_sha256(root: Path, review_root: Path, contract_review_root: Path,
                   expected_reviewed_commit: str,
                   expected_reviewed_tree: str) -> str:
    return hashlib.sha256(
        production_command(
            root, review_root, contract_review_root,
            expected_reviewed_commit, expected_reviewed_tree,
        ).encode("utf-8")
    ).hexdigest()


def technical_review_status_schema() -> dict:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://pq-rbbc.invalid/schema/cap-unified-tree-contract-technical-review-status-v2.43.json",
        "title": "PQ-RBBC v2.43 reservation-binding technical review status",
        **_object({
            "format": _const("PQRBBC-CAP-UNIFIED-TREE-CONTRACT-TECHNICAL-REVIEW-STATUS-1"),
            "contract_version": _const(CONTRACT_VERSION),
            "reviewed_commit": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
            "reviewed_tree": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
            "completed_at_utc": {**_string(), "x-canonical-utc": True},
            "reviewed_contracts": _object({
                "contract_source": _identity_schema(),
                "manifest": _identity_schema(),
                "schemas": _object({key: _identity_schema() for key in SCHEMA_PATHS}),
            }),
            "external_review_artifacts": _object({
                key: _identity_schema() for key in CONTRACT_REVIEW_FILENAMES
            }),
            "decision": _const({
                "disposition": "passed_no_blocking_findings",
                "blocking_findings": [],
                "is_ai_assisted_technical_review": True,
                "is_named_independent_human_approval": False,
                "authorizes_real_operator_reservation": True,
                "authorizes_production_prefreeze": False,
                "grants_security_claim": False,
            }),
        }),
    }


def approval_schema() -> dict:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://pq-rbbc.invalid/schema/cap-unified-tree-operator-approval-v2.43.json",
        "title": "PQ-RBBC v2.42 operator approval record under v2.43 binding",
        **_object({
            "format": _const(APPROVAL_FORMAT),
            "contract_version": _const(CONTRACT_VERSION),
            "target_implementation_version": _const(TARGET_IMPLEMENTATION_VERSION),
            "reservation_id": _string(concrete=True),
            "launch_batch_id": _string(concrete=True),
            "operator_identifier": _string(concrete=True),
            "operator_role": _string(concrete=True),
            "approved_at_utc": {**_string(), "x-canonical-utc": True},
            "decision": _const({
                "resources_confirmed": True,
                "external_output_control_confirmed": True,
                "accepts_runtime_estimate_unavailable": True,
            }),
            "attestation_boundary": _const({
                "method": "owner-controlled-local-record",
                "same_operator_as_repository_owner": True,
                "cryptographic_signature_verified": False,
                "named_independent_human_review": False,
            }),
        }),
    }


def resource_schema() -> dict:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://pq-rbbc.invalid/schema/cap-unified-tree-resource-reservation-v2.43.json",
        "title": "PQ-RBBC v2.42 operator resource reservation under v2.43 binding",
        **_object({
            "format": _const(RESOURCE_FORMAT),
            "contract_version": _const(CONTRACT_VERSION),
            "target_implementation_version": _const(TARGET_IMPLEMENTATION_VERSION),
            "reservation_id": _string(concrete=True),
            "launch_batch_id": _string(concrete=True),
            "implementation_binding": _const(implementation_binding()),
            "v2_43_contract_technical_review_status": _identity_schema(),
            "production_profile_fingerprint": _const(PRODUCTION_PROFILE_FINGERPRINT),
            "operator": _object({
                "identifier": _string(concrete=True),
                "role": _string(concrete=True),
                "approved_at_utc": {**_string(), "x-canonical-utc": True},
                "approved": _const(True),
                "approval_record": _identity_schema(),
                "attestation": _const({
                    "method": "owner-controlled-local-record",
                    "cryptographic_signature_verified": False,
                }),
            }),
            "reservation_window": _object({
                "starts_at_utc": {**_string(), "x-canonical-utc": True},
                "ends_at_utc": {**_string(), "x-canonical-utc": True},
                "wall_clock_seconds": {"type": "integer", "minimum": 1},
            }),
            "execution_scope": _object({
                "phase": _const("production-prefreeze"),
                "trusted_artifact_root": _string(concrete=True),
                "trusted_review_root": _string(concrete=True),
                "trusted_contract_review_root": _string(concrete=True),
                "expected_reviewed_commit": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
                "expected_reviewed_tree": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
                "external_output": _string(concrete=True),
                "candidate_locations": _object({
                    key: _string(concrete=True)
                    for key in ("resource_reservation", "independent_review", "launch_manifest")
                }),
                "exact_command": _string(concrete=True),
                "exact_command_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "fresh_cache_required": _const(True),
                "existing_output_overwrite_forbidden": _const(True),
                "legacy_evidence_read_only": _const(True),
                "production_implementation_available": _const(False),
                "command_executable_now": _const(False),
            }),
            "reserved_resources": _object({
                "cpu_cores": {"type": "integer", "minimum": 4},
                "available_memory_bytes": {"type": "integer", "minimum": 17179869184},
                "free_disk_bytes": {"type": "integer", "minimum": 85899345920},
                "exclusive_output_directory": _const(True),
                "accepts_runtime_estimate_unavailable": _const(True),
            }),
            "claim_boundary": _const({
                "resources_reserved_for_prospective_prefreeze": True,
                "authorizes_production_prefreeze": False,
                "authorizes_large_replay": False,
                "authorizes_large_proving_run": False,
                "independent_human_review_frozen": False,
                "launch_manifest_frozen": False,
                "grants_security_claim": False,
                "production_closed": False,
            }),
        }),
    }


def review_schema() -> dict:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://pq-rbbc.invalid/schema/cap-unified-tree-independent-review-v2.43.json",
        "title": "PQ-RBBC v2.42 named independent human review under v2.43 binding",
        **_object({
            "format": _const(REVIEW_FORMAT),
            "contract_version": _const(CONTRACT_VERSION),
            "target_implementation_version": _const(TARGET_IMPLEMENTATION_VERSION),
            "review_id": _string(concrete=True),
            "launch_batch_id": _string(concrete=True),
            "implementation_binding": _const(implementation_binding()),
            "review_subject": _object({
                "format": _const(SUBJECT_FORMAT),
                "launch_batch_id": _string(concrete=True),
                "reservation_id": _string(concrete=True),
                "resource_reservation": _identity_schema(),
                "operator_approval_record": _identity_schema(),
                "contract_technical_review_status": _identity_schema(),
                "implementation_binding_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "command_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            }),
            "reviewer": _object({
                "identifier": _string(concrete=True),
                "affiliation": _string(concrete=True),
                "independent_of_operator_and_implementation": _const(True),
                "is_ai_only": _const(False),
                "completed_at_utc": {**_string(), "x-canonical-utc": True},
                "attestation": _object({
                    "method": {"type": "string", "enum": ["signed-json", "detached-signature", "organization-record"]},
                    "reference": _string(concrete=True),
                    "authenticity_confirmed": _const(True),
                }),
            }),
            "review_scope": _const({
                "v2_42_recovery_and_provenance_reviewed": True,
                "reservation_contract_and_schema_reviewed": True,
                "exact_command_resource_output_and_window_reviewed": True,
                "external_review_identity_chain_reviewed": True,
                "claim_boundary_reviewed": True,
            }),
            "decision": _const({
                "disposition": "approved_for_launch_candidate_authoring_only",
                "blocking_findings": [],
                "authorizes_production_prefreeze": False,
                "authorizes_large_replay": False,
                "authorizes_large_proving_run": False,
                "grants_security_claim": False,
                "production_closed": False,
            }),
        }),
    }


def schemas() -> dict[str, dict]:
    return {
        "technical_review_status": technical_review_status_schema(),
        "approval_record": approval_schema(),
        "resource_reservation": resource_schema(),
        "independent_review": review_schema(),
    }


def implementation_binding_sha256() -> str:
    return hashlib.sha256(b"PQRBBC-V243-IMPLEMENTATION-BINDING\x00" + canonical_json(implementation_binding())).hexdigest()


def review_subject(resource: Snapshot, approval: Snapshot, technical_review_status: Snapshot) -> dict:
    document = resource.document()
    return {
        "format": SUBJECT_FORMAT,
        "launch_batch_id": document["launch_batch_id"],
        "reservation_id": document["reservation_id"],
        "resource_reservation": resource.identity,
        "operator_approval_record": approval.identity,
        "contract_technical_review_status": technical_review_status.identity,
        "implementation_binding_sha256": implementation_binding_sha256(),
        "command_sha256": document["execution_scope"]["exact_command_sha256"],
    }


def current_contract_identities() -> dict:
    return {
        "contract_source": contract_source_identity(),
        "manifest": identity(MANIFEST_PATH),
        "schemas": {key: identity(path) for key, path in SCHEMA_PATHS.items()},
    }


def _git(*arguments: str) -> bytes:
    try:
        result = subprocess.run(
            ("git", *arguments), cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ValidationError("trusted Git object lookup failed") from error
    if result.returncode != 0:
        raise ValidationError("trusted Git object lookup rejected")
    return result.stdout


def _git_is_ancestor(ancestor: str, descendant: str) -> bool:
    try:
        result = subprocess.run(
            ("git", "merge-base", "--is-ancestor", ancestor, descendant),
            cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ValidationError("trusted Git ancestry lookup failed") from error
    return result.returncode == 0


def verify_reviewed_git_target(document: dict, expected_commit: str,
                               expected_tree: str) -> tuple[str, ...]:
    """Bind review status to caller-selected Git objects and exact blobs.

    The expected target is trusted operator input, not candidate JSON.  A later
    status-only commit may be HEAD while this target remains the exact commit
    actually inspected by the reviewer.
    """
    failures = []
    if (type(expected_commit) is not str or
            re.fullmatch(r"[0-9a-f]{40}", expected_commit) is None):
        return ("git_target:expected_commit",)
    if (type(expected_tree) is not str or
            re.fullmatch(r"[0-9a-f]{40}", expected_tree) is None):
        return ("git_target:expected_tree",)
    if document["reviewed_commit"] != expected_commit:
        failures.append("git_target:commit_binding")
    if document["reviewed_tree"] != expected_tree:
        failures.append("git_target:tree_binding")
    if failures:
        return tuple(failures)
    try:
        if _git("cat-file", "-t", expected_commit).strip() != b"commit":
            failures.append("git_target:commit_type")
            return tuple(failures)
        actual_tree = _git("rev-parse", "--verify", expected_commit + "^{tree}").strip().decode("ascii")
        if actual_tree != expected_tree:
            failures.append("git_target:tree_mismatch")
            return tuple(failures)
        if _git("cat-file", "-t", expected_tree).strip() != b"tree":
            failures.append("git_target:tree_type")
            return tuple(failures)
        if not _git_is_ancestor(INTEGRATION_BASELINE_COMMIT, expected_commit):
            failures.append("git_target:integration_ancestry")
            return tuple(failures)
        paths = {
            "contract_source": SOURCE_PATH,
            "manifest": MANIFEST_PATH,
            **{"schema:" + key: path for key, path in SCHEMA_PATHS.items()},
        }
        expected_identities = {
            "contract_source": document["reviewed_contracts"]["contract_source"],
            "manifest": document["reviewed_contracts"]["manifest"],
            **{"schema:" + key: value
               for key, value in document["reviewed_contracts"]["schemas"].items()},
        }
        for label, path in paths.items():
            relative = path.relative_to(ROOT).as_posix()
            raw = _git("show", expected_commit + ":" + relative)
            observed = Snapshot(Path(relative), raw).identity
            if not strict_equal(observed, expected_identities[label]):
                failures.append("git_target:blob:" + label)
    except (UnicodeError, ValueError, ValidationError, subprocess.SubprocessError):
        failures.append("git_target:object_lookup")
    return tuple(sorted(failures))


def build_technical_review_status(*, reviewed_commit: str, reviewed_tree: str,
                                  completed_at_utc: str,
                                  report: Snapshot, findings: Snapshot,
                                  inventory: Snapshot) -> dict:
    document = {
        "format": "PQRBBC-CAP-UNIFIED-TREE-CONTRACT-TECHNICAL-REVIEW-STATUS-1",
        "contract_version": CONTRACT_VERSION,
        "reviewed_commit": reviewed_commit,
        "reviewed_tree": reviewed_tree,
        "completed_at_utc": completed_at_utc,
        "reviewed_contracts": current_contract_identities(),
        "external_review_artifacts": {
            "report": report.identity,
            "findings": findings.identity,
            "inventory": inventory.identity,
        },
        "decision": {
            "disposition": "passed_no_blocking_findings",
            "blocking_findings": [],
            "is_ai_assisted_technical_review": True,
            "is_named_independent_human_approval": False,
            "authorizes_real_operator_reservation": True,
            "authorizes_production_prefreeze": False,
            "grants_security_claim": False,
        },
    }
    failures = validate_schema(document, schemas()["technical_review_status"])
    if failures:
        raise ValidationError("technical review status rejected: " + str(failures))
    return document


def build_approval_record(*, reservation_id: str, launch_batch_id: str,
                          operator_identifier: str, operator_role: str,
                          approved_at_utc: str) -> dict:
    document = {
        "format": APPROVAL_FORMAT,
        "contract_version": CONTRACT_VERSION,
        "target_implementation_version": TARGET_IMPLEMENTATION_VERSION,
        "reservation_id": reservation_id,
        "launch_batch_id": launch_batch_id,
        "operator_identifier": operator_identifier,
        "operator_role": operator_role,
        "approved_at_utc": approved_at_utc,
        "decision": {
            "resources_confirmed": True,
            "external_output_control_confirmed": True,
            "accepts_runtime_estimate_unavailable": True,
        },
        "attestation_boundary": {
            "method": "owner-controlled-local-record",
            "same_operator_as_repository_owner": True,
            "cryptographic_signature_verified": False,
            "named_independent_human_review": False,
        },
    }
    failures = validate_approval(document)
    if failures:
        raise ValidationError("operator approval rejected: " + str(failures))
    return document


def build_resource_reservation(*, approval: Snapshot, artifact_root: Path,
                               review_root: Path, contract_review_root: Path,
                               expected_reviewed_commit: str,
                               expected_reviewed_tree: str,
                               starts_at_utc: str,
                               ends_at_utc: str, cpu_cores: int,
                               available_memory_bytes: int,
                               free_disk_bytes: int, clock: Clock = trusted_now) -> dict:
    approval_doc = approval.document()
    approval_failures = validate_approval(approval_doc)
    if approval_failures:
        raise ValidationError("operator approval rejected: " + str(approval_failures))
    root, reviews = exact_path(artifact_root), exact_path(review_root)
    contract_reviews = exact_path(contract_review_root)
    contract_failures = validate_tracked_contracts(reviews)
    if contract_failures:
        raise ValidationError("tracked reservation contracts rejected: " + str(contract_failures))
    ArtifactRoot(root).require_location(approval.location)
    try:
        technical_status = read_snapshot(TECHNICAL_REVIEW_STATUS_PATH)
    except (OSError, ValueError) as error:
        raise ValidationError("v2.43 contract technical review status unavailable") from error
    status_failures = validate_technical_review_status(
        technical_status.document(), contract_reviews, clock(),
        expected_reviewed_commit, expected_reviewed_tree)
    if status_failures:
        raise ValidationError("v2.43 contract technical review status rejected: " + str(status_failures))
    paths = locations(root)
    start, end = _utc(starts_at_utc), _utc(ends_at_utc)
    document = {
        "format": RESOURCE_FORMAT,
        "contract_version": CONTRACT_VERSION,
        "target_implementation_version": TARGET_IMPLEMENTATION_VERSION,
        "reservation_id": approval_doc["reservation_id"],
        "launch_batch_id": approval_doc["launch_batch_id"],
        "implementation_binding": implementation_binding(),
        "v2_43_contract_technical_review_status": technical_status.identity,
        "production_profile_fingerprint": PRODUCTION_PROFILE_FINGERPRINT,
        "operator": {
            "identifier": approval_doc["operator_identifier"],
            "role": approval_doc["operator_role"],
            "approved_at_utc": approval_doc["approved_at_utc"],
            "approved": True,
            "approval_record": approval.identity,
            "attestation": {
                "method": "owner-controlled-local-record",
                "cryptographic_signature_verified": False,
            },
        },
        "reservation_window": {
            "starts_at_utc": starts_at_utc,
            "ends_at_utc": ends_at_utc,
            "wall_clock_seconds": int((end - start).total_seconds()),
        },
        "execution_scope": {
            "phase": "production-prefreeze",
            "trusted_artifact_root": str(root),
            "trusted_review_root": str(reviews),
            "trusted_contract_review_root": str(contract_reviews),
            "expected_reviewed_commit": expected_reviewed_commit,
            "expected_reviewed_tree": expected_reviewed_tree,
            "external_output": str(root / "production-prefreeze"),
            "candidate_locations": {
                key: paths[key]
                for key in ("resource_reservation", "independent_review", "launch_manifest")
            },
            "exact_command": production_command(
                root, reviews, contract_reviews,
                expected_reviewed_commit, expected_reviewed_tree),
            "exact_command_sha256": command_sha256(
                root, reviews, contract_reviews,
                expected_reviewed_commit, expected_reviewed_tree),
            "fresh_cache_required": True,
            "existing_output_overwrite_forbidden": True,
            "legacy_evidence_read_only": True,
            "production_implementation_available": False,
            "command_executable_now": False,
        },
        "reserved_resources": {
            "cpu_cores": cpu_cores,
            "available_memory_bytes": available_memory_bytes,
            "free_disk_bytes": free_disk_bytes,
            "exclusive_output_directory": True,
            "accepts_runtime_estimate_unavailable": True,
        },
        "claim_boundary": {
            "resources_reserved_for_prospective_prefreeze": True,
            "authorizes_production_prefreeze": False,
            "authorizes_large_replay": False,
            "authorizes_large_proving_run": False,
            "independent_human_review_frozen": False,
            "launch_manifest_frozen": False,
            "grants_security_claim": False,
            "production_closed": False,
        },
    }
    failures = validate_resource(
        document, approval, technical_status, root, reviews, contract_reviews, clock(),
        expected_reviewed_commit, expected_reviewed_tree)
    if failures:
        raise ValidationError("resource reservation rejected: " + str(failures))
    return document


def validate_technical_review_status(document: object, contract_review_root: Path,
                                     now: datetime, expected_reviewed_commit: str,
                                     expected_reviewed_tree: str) -> tuple[str, ...]:
    check_now(now)
    failures = list(validate_schema(document, schemas()["technical_review_status"]))
    if failures:
        return tuple(failures)
    try:
        expected_contracts = current_contract_identities()
    except (OSError, ValueError) as error:
        return ("technical_review_status:tracked_contract:" + str(error),)
    if not strict_equal(document["reviewed_contracts"], expected_contracts):
        failures.append("technical_review_status:contract_binding")
    failures.extend(verify_reviewed_git_target(
        document, expected_reviewed_commit, expected_reviewed_tree))
    try:
        store = ArtifactRoot(contract_review_root)
    except (OSError, ValueError) as error:
        return tuple(failures + ["technical_review_status:review_root:" + str(error)])
    for key, filename in CONTRACT_REVIEW_FILENAMES.items():
        expected = document["external_review_artifacts"][key]
        if expected["filename"] != filename:
            failures.append("technical_review_status:filename:" + key)
            continue
        try:
            captured = store.read(store.root / filename)
            if not strict_equal(captured.identity, expected):
                failures.append("technical_review_status:external_identity:" + key)
        except (OSError, ValueError) as error:
            failures.append("technical_review_status:external:" + key + ":" + str(error))
    if _utc(document["completed_at_utc"]) > now:
        failures.append("technical_review_status:future_completion")
    return tuple(sorted(failures))


def validate_approval(document: object) -> tuple[str, ...]:
    return validate_schema(document, schemas()["approval_record"])


def validate_resource(document: object, approval: Snapshot, technical_review_status: Snapshot,
                      artifact_root: Path, review_root: Path,
                      contract_review_root: Path, now: datetime,
                      expected_reviewed_commit: str,
                      expected_reviewed_tree: str) -> tuple[str, ...]:
    check_now(now)
    failures = list(validate_schema(document, schemas()["resource_reservation"]))
    try:
        approval_doc = approval.document()
    except (ValueError, OSError) as error:
        return tuple(failures + ["approval:" + str(error)])
    failures.extend(validate_approval(approval_doc))
    try:
        status_doc = technical_review_status.document()
        failures.extend(validate_technical_review_status(
            status_doc, contract_review_root, now,
            expected_reviewed_commit, expected_reviewed_tree))
    except (ValueError, OSError) as error:
        failures.append("technical_review_status:" + str(error))
    if failures:
        return tuple(failures)
    root = exact_path(artifact_root)
    reviews = exact_path(review_root)
    contract_reviews = exact_path(contract_review_root)
    roots = (root, reviews, contract_reviews)
    if any(a.is_relative_to(b) or b.is_relative_to(a)
           for index, a in enumerate(roots) for b in roots[index + 1:]):
        failures.append("resource:trust_root_separation")
    paths = locations(root)
    scope = document["execution_scope"]
    expected_locations = {key: paths[key] for key in ("resource_reservation", "independent_review", "launch_manifest")}
    expected_scope = {
        "trusted_artifact_root": str(root),
        "trusted_review_root": str(reviews),
        "trusted_contract_review_root": str(contract_reviews),
        "expected_reviewed_commit": expected_reviewed_commit,
        "expected_reviewed_tree": expected_reviewed_tree,
        "external_output": str(root / "production-prefreeze"),
        "candidate_locations": expected_locations,
        "exact_command": production_command(
            root, reviews, contract_reviews,
            expected_reviewed_commit, expected_reviewed_tree),
        "exact_command_sha256": command_sha256(
            root, reviews, contract_reviews,
            expected_reviewed_commit, expected_reviewed_tree),
    }
    if any(not strict_equal(scope[key], value) for key, value in expected_scope.items()):
        failures.append("resource:execution_binding")
    if approval.location != root / FILENAMES["approval_record"]:
        failures.append("resource:approval_location")
    if not strict_equal(document["operator"]["approval_record"], approval.identity):
        failures.append("resource:approval_identity")
    if technical_review_status.location != TECHNICAL_REVIEW_STATUS_PATH:
        failures.append("resource:technical_review_status_location")
    if not strict_equal(
            document["v2_43_contract_technical_review_status"], technical_review_status.identity):
        failures.append("resource:technical_review_status_identity")
    cross = {
        "reservation_id": document["reservation_id"],
        "launch_batch_id": document["launch_batch_id"],
        "operator_identifier": document["operator"]["identifier"],
        "operator_role": document["operator"]["role"],
        "approved_at_utc": document["operator"]["approved_at_utc"],
    }
    if any(not strict_equal(approval_doc[key], value) for key, value in cross.items()):
        failures.append("resource:approval_subject_binding")
    window = document["reservation_window"]
    approved = _utc(document["operator"]["approved_at_utc"])
    start, end = _utc(window["starts_at_utc"]), _utc(window["ends_at_utc"])
    if not approved <= start < end:
        failures.append("resource:approval_window_order")
    if window["wall_clock_seconds"] != int((end - start).total_seconds()):
        failures.append("resource:window_duration")
    if not start <= now < end:
        failures.append("resource:inactive_window")
    return tuple(sorted(failures))


def validate_review(document: object, resource: Snapshot, approval: Snapshot,
                    technical_review_status: Snapshot, artifact_root: Path,
                    review_root: Path, contract_review_root: Path,
                    now: datetime, expected_reviewed_commit: str,
                    expected_reviewed_tree: str) -> tuple[str, ...]:
    resource_failures = validate_resource(
        resource.document(), approval, technical_review_status,
        artifact_root, review_root, contract_review_root, now,
        expected_reviewed_commit, expected_reviewed_tree)
    failures = list(resource_failures) + list(validate_schema(document, schemas()["independent_review"]))
    if failures:
        return tuple(sorted(failures))
    resource_doc = resource.document()
    if not strict_equal(
            document["review_subject"], review_subject(resource, approval, technical_review_status)):
        failures.append("review:subject_binding")
    if document["launch_batch_id"] != resource_doc["launch_batch_id"]:
        failures.append("review:batch_binding")
    if document["reviewer"]["identifier"] == resource_doc["operator"]["identifier"]:
        failures.append("review:reviewer_is_operator")
    completed = _utc(document["reviewer"]["completed_at_utc"])
    approved = _utc(resource_doc["operator"]["approved_at_utc"])
    if not approved <= completed <= now:
        failures.append("review:time_order")
    return tuple(sorted(failures))


def claim_boundary() -> dict:
    return {
        "v2_43_reservation_binding_contract_implemented": True,
        "v2_42_bounded_ai_review_bound": True,
        "operator_resource_reservation_frozen": False,
        "named_independent_human_review_frozen": False,
        "launch_manifest_frozen": False,
        "production_prefreeze_authorized": False,
        "production_prefreeze_started": False,
        "production_stream_materialized": False,
        "production_runner_scale_qualified": False,
        "large_replay_started": False,
        "large_proving_run_started": False,
        "cap_security_qualified": False,
        "fork_security_proof_revalidated": False,
        "production_closed": False,
    }


def build_manifest() -> dict:
    generated = schemas()
    return {
        "format": FORMAT,
        "contract_version": CONTRACT_VERSION,
        "target_implementation_version": TARGET_IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "reviewed_implementation": {
            "commit": REVIEWED_IMPLEMENTATION_COMMIT,
            "tree": REVIEWED_IMPLEMENTATION_TREE,
            "integration_baseline_commit": INTEGRATION_BASELINE_COMMIT,
        },
        "implementation_binding": implementation_binding(),
        "schemas": {
            key: {
                "filename": SCHEMA_PATHS[key].name,
                "bytes": len(canonical_json(schema)),
                "sha256": hashlib.sha256(canonical_json(schema)).hexdigest(),
            }
            for key, schema in generated.items()
        },
        "candidate_filenames": FILENAMES,
        "post_review_status_filename": TECHNICAL_REVIEW_STATUS_PATH.name,
        "io_policy": {
            "max_json_bytes": MAX_JSON_BYTES,
            "canonical_candidate_bytes_required": True,
            "symlinks_forbidden": True,
            "trusted_artifact_and_review_roots_selected_by_caller": True,
            "git_worktree_artifact_roots_forbidden": True,
            "exclusive_publication_required": True,
        },
        "transition": {
            "v2_41_reservation_authorizes_v2_42": False,
            "v2_42_ai_re_review_is_named_human_approval": False,
            "new_v2_42_bound_reservation_required": True,
            "exact_v2_43_contract_review_status_required_before_reservation": True,
            "trusted_expected_reviewed_commit_and_tree_required": True,
            "reviewed_git_objects_and_contract_blobs_verified": True,
            "tracked_contract_failure_closes_all_dependent_gates": True,
            "reviewer_identifier_must_differ_from_operator_identifier": True,
            "reservation_precedes_named_independent_human_review": True,
            "human_review_precedes_launch_candidate": True,
        },
        "current_gates": {
            "safe_to_run_read_only_reservation_preflight": True,
            "safe_to_create_real_reservation_before_contract_review": False,
            "safe_to_start_production_prefreeze": False,
        },
        "prospective_execution": {
            "root_parameterized": True,
            "command_executable_now": False,
            "production_implementation_available": False,
            "a_changed_command_requires_a_new_reservation": True,
        },
        "claim_boundary": claim_boundary(),
    }


def verify_external_review_archive(review_root: Path) -> tuple[str, ...]:
    failures = []
    try:
        store = ArtifactRoot(review_root)
    except (OSError, ValueError) as error:
        return ("review_archive:" + str(error),)
    for filename, expected in EXTERNAL_REVIEW_IDENTITIES.items():
        try:
            captured = store.read(store.root / filename)
            if not strict_equal(captured.identity, expected):
                failures.append("review_archive:identity:" + filename)
        except (OSError, ValueError) as error:
            failures.append("review_archive:" + filename + ":" + str(error))
    return tuple(sorted(failures))


def validate_tracked_repository_contracts() -> tuple[str, ...]:
    failures = []
    expected_documents = {MANIFEST_PATH: build_manifest(), **{
        SCHEMA_PATHS[key]: schema for key, schema in schemas().items()
    }}
    for path, expected in expected_documents.items():
        try:
            captured = read_snapshot(path)
            captured.document()
            if captured.raw != canonical_json(expected):
                failures.append("tracked_contract:" + path.name)
        except (OSError, ValueError) as error:
            failures.append("tracked_contract:" + path.name + ":" + str(error))
    for relative, expected in TRACKED_DEPENDENCY_IDENTITIES.items():
        try:
            if not strict_equal(read_snapshot(ROOT / relative).identity, expected):
                failures.append("tracked_dependency:" + relative)
        except (OSError, ValueError) as error:
            failures.append("tracked_dependency:" + relative + ":" + str(error))
    return tuple(sorted(failures))


def validate_tracked_contracts(review_root: Path) -> tuple[str, ...]:
    return tuple(sorted(
        validate_tracked_repository_contracts() + verify_external_review_archive(review_root)
    ))


def _capture_canonical(store: ArtifactRoot, path: Path, expected: Path) -> Snapshot:
    if exact_path(path) != expected:
        raise ValidationError("candidate exact location mismatch")
    captured = store.read(path)
    document = captured.document()
    if captured.raw != canonical_json(document):
        raise ValidationError("candidate must use canonical JSON bytes")
    return captured


def build_preflight(*, artifact_root: Path, review_root: Path, contract_review_root: Path,
                    expected_reviewed_commit: str, expected_reviewed_tree: str,
                    resource_path: Path | None = None, review_path: Path | None = None,
                    clock: Clock = trusted_now) -> dict:
    contracts = validate_tracked_contracts(review_root)
    now = check_now(clock())
    store = ArtifactRoot(artifact_root)
    statuses = {}
    approval = resource = review = technical_status = None
    try:
        technical_status = read_snapshot(TECHNICAL_REVIEW_STATUS_PATH)
        failures = list(validate_technical_review_status(
            technical_status.document(), contract_review_root, now,
            expected_reviewed_commit, expected_reviewed_tree))
        statuses["technical_review_status"] = {
            "provided": True,
            "identity": technical_status.identity,
            "failures": failures,
        }
    except (OSError, ValueError) as error:
        statuses["technical_review_status"] = {"provided": False, "failures": [str(error)]}
    try:
        approval = _capture_canonical(store, store.root / FILENAMES["approval_record"],
                                      store.root / FILENAMES["approval_record"])
        statuses["approval_record"] = {"provided": True, "identity": approval.identity, "failures": []}
    except (OSError, ValueError) as error:
        statuses["approval_record"] = {"provided": False, "failures": [str(error)]}
    if resource_path is not None:
        failures = []
        try:
            resource = _capture_canonical(store, resource_path, store.root / FILENAMES["resource_reservation"])
            if approval is None or technical_status is None:
                failures.append("approval_or_technical_review_status_unavailable")
            else:
                failures.extend(validate_resource(
                    resource.document(), approval, technical_status, store.root,
                    review_root, contract_review_root, now,
                    expected_reviewed_commit, expected_reviewed_tree))
        except (OSError, ValueError) as error:
            failures.append(str(error))
        statuses["resource_reservation"] = {
            "provided": True,
            "identity": resource.identity if resource is not None else None,
            "failures": failures,
        }
    else:
        statuses["resource_reservation"] = {"provided": False, "failures": ["not_provided"]}
    if review_path is not None:
        failures = []
        try:
            review = _capture_canonical(store, review_path, store.root / FILENAMES["independent_review"])
            if resource is None or approval is None or technical_status is None:
                failures.append("reservation_approval_or_technical_review_status_unavailable")
            else:
                failures.extend(validate_review(
                    review.document(), resource, approval, technical_status,
                    store.root, review_root, contract_review_root, now,
                    expected_reviewed_commit, expected_reviewed_tree))
        except (OSError, ValueError) as error:
            failures.append(str(error))
        statuses["independent_review"] = {
            "provided": True,
            "identity": review.identity if review is not None else None,
            "failures": failures,
        }
    else:
        statuses["independent_review"] = {"provided": False, "failures": ["not_provided"]}
    contracts_ok = not contracts
    if not contracts_ok:
        dependency_failure = "tracked_contracts_or_dependencies_unverified"
        for key in ("technical_review_status", "resource_reservation", "independent_review"):
            statuses[key]["failures"].append(dependency_failure)
    status_ok = (contracts_ok and technical_status is not None and
                 not statuses["technical_review_status"]["failures"])
    resource_ok = (contracts_ok and resource is not None and approval is not None and
                   status_ok and not statuses["resource_reservation"]["failures"])
    review_ok = (contracts_ok and review is not None and resource_ok and
                 not statuses["independent_review"]["failures"])
    return {
        "format": REPORT_FORMAT,
        "contract_version": CONTRACT_VERSION,
        "target_implementation_version": TARGET_IMPLEMENTATION_VERSION,
        "validated_at_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tracked_contracts": {"verified": not contracts, "failures": list(contracts)},
        "external_candidates": statuses,
        "result": {
            "safe_to_run_read_only_reservation_preflight": contracts_ok,
            "v2_43_contract_technical_review_acceptable": status_ok,
            "resource_reservation_acceptable_for_freeze": resource_ok,
            "safe_to_submit_named_independent_human_review": resource_ok,
            "independent_review_acceptable_for_freeze": review_ok,
            "safe_to_author_launch_manifest_candidate": review_ok,
            "safe_to_start_production_prefreeze": False,
        },
        "claim_boundary": claim_boundary(),
        "blockers": [
            "v2.43 reservation-binding checkpoint requires independent technical review",
            "no real v2.42-bound reservation is frozen by this tracked checkpoint",
            "named independent human approval and launch manifest are absent",
            "production implementation and scale qualification remain absent",
        ],
    }


def reject_production(*, artifact_root: Path, review_root: Path, contract_review_root: Path,
                      expected_reviewed_commit: str, expected_reviewed_tree: str,
                      resource_path: Path | None, review_path: Path | None,
                      launch_path: Path | None, output: Path, clock: Clock = trusted_now):
    root = ArtifactRoot(artifact_root).root
    if exact_path(output) != root / "production-prefreeze":
        raise ValidationError("production output location mismatch")
    if launch_path is None or exact_path(launch_path) != root / FILENAMES["launch_manifest"]:
        raise ValidationError("launch manifest exact location mismatch")
    build_preflight(artifact_root=root, review_root=review_root,
                    contract_review_root=contract_review_root,
                    expected_reviewed_commit=expected_reviewed_commit,
                    expected_reviewed_tree=expected_reviewed_tree,
                    resource_path=resource_path, review_path=review_path, clock=clock)
    raise ValidationError("v2.43 is a reservation-binding checkpoint; production-prefreeze is unavailable")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("reservation-preflight", "production-prefreeze"), required=True)
    parser.add_argument("--trusted-artifact-root", type=Path, required=True)
    parser.add_argument("--trusted-review-root", type=Path, required=True)
    parser.add_argument("--trusted-contract-review-root", type=Path, required=True)
    parser.add_argument("--expected-reviewed-commit", required=True)
    parser.add_argument("--expected-reviewed-tree", required=True)
    parser.add_argument("--resource-reservation", type=Path)
    parser.add_argument("--independent-review", type=Path)
    parser.add_argument("--launch-manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fresh-output", action="store_true")
    args = parser.parse_args()
    if not args.fresh_output:
        raise ValidationError("--fresh-output required")
    if args.phase == "production-prefreeze":
        reject_production(
            artifact_root=args.trusted_artifact_root,
            review_root=args.trusted_review_root,
            contract_review_root=args.trusted_contract_review_root,
            expected_reviewed_commit=args.expected_reviewed_commit,
            expected_reviewed_tree=args.expected_reviewed_tree,
            resource_path=args.resource_reservation,
            review_path=args.independent_review,
            launch_path=args.launch_manifest,
            output=args.output,
        )
    if exact_path(args.output) != ArtifactRoot(args.trusted_artifact_root).root / REPORT_FILENAME:
        raise ValidationError("preflight report output location mismatch")
    report = build_preflight(
        artifact_root=args.trusted_artifact_root,
        review_root=args.trusted_review_root,
        contract_review_root=args.trusted_contract_review_root,
        expected_reviewed_commit=args.expected_reviewed_commit,
        expected_reviewed_tree=args.expected_reviewed_tree,
        resource_path=args.resource_reservation,
        review_path=args.independent_review,
    )
    ArtifactRoot(args.trusted_artifact_root).write(args.output, report)
    print(canonical_json({"output": str(args.output), "result": report["result"]}).decode(), end="")


if __name__ == "__main__":
    main()
