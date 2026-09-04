#!/usr/bin/env python3
"""Seal portable evidence for the PQ-RBBC v2.33 migration preflight."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_unified_tree_migration_preflight as preflight


IMPLEMENTATION_VERSION = "2.33"
FORMAT = "PQRBBC-CAP-UNIFIED-TREE-MIGRATION-PREFLIGHT-EVIDENCE-1"
RELATION_ID = "pq-rbbc/cap/unified-tree-migration/preflight-evidence/v1"
ROOT = Path(__file__).resolve().parents[1]

CHECKER = (
    ROOT / "src/pq_rbbc_cap_unified_tree_migration_preflight.py",
    33_644,
    "c9fa10e48936d4a4f2b9d7fed2f2a62ad644f91524ff9092b63c0461cc2e1d0e",
)
MANIFEST = (
    ROOT / "manifests/pq_rbbc_cap_unified_tree_migration_manifest_v2_33.json",
    13_990,
    "8686d49f59655f09135d91fc79e236c59bc8d6b582c86a55799a0c13acfad9f5",
)
INITIAL_REPORT = (
    7_981,
    "c4711956c076cbec96d6d686c5a40c77e303f93bf155566cfb856b2aba876855",
)


def canonical_json(document: Mapping[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_identity(path: Path, size: int, digest: str, label: str) -> None:
    if not path.is_file():
        raise ValueError(f"{label} is missing")
    if path.stat().st_size != size or _sha256(path) != digest:
        raise ValueError(f"{label} identity mismatch")


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} root must be an object")
    return document


def validate_initial_report(path: Path) -> dict[str, object]:
    _require_identity(path, *INITIAL_REPORT, "v2.33 initial environment report")
    report = _read_json(path)
    expected_true = (
        "safe_to_run_read_only_preflight",
        "safe_to_author_unified_tree_specification",
        "safe_to_implement_reduced_prototype",
    )
    expected_false = (
        "safe_to_start_production_prefreeze",
        "safe_to_start_large_replay",
        "safe_to_start_large_proving_run",
        "large_profile_build_started",
        "large_replay_started",
        "large_proving_run_started",
    )
    if (
        report.get("format") != preflight.REPORT_FORMAT
        or report.get("implementation_version") != IMPLEMENTATION_VERSION
        or report.get("relation_id") != preflight.RELATION_ID
        or any(report.get(name) is not True for name in expected_true)
        or any(report.get(name) is not False for name in expected_false)
        or report.get("claim_boundary") != preflight.claim_boundary()
        or report.get("resource_estimate") != preflight.resource_estimate()
        or report.get("exact_commands") != preflight.exact_command_contract()
    ):
        raise ValueError("v2.33 report result or frozen contract mismatch")

    checks = report.get("checks")
    if not isinstance(checks, dict):
        raise ValueError("v2.33 report checks are missing")
    if checks.get("tracked_inputs") != {"verified": True, "failures": []}:
        raise ValueError("v2.33 tracked input result mismatch")

    source_checks = checks.get("source_artifacts")
    if not isinstance(source_checks, dict):
        raise ValueError("v2.33 source checks are missing")
    for name, requirement in preflight.SOURCE_REQUIREMENTS.items():
        observed = source_checks.get(name)
        if observed != {
            "provided": True,
            "bytes": requirement["bytes"],
            "sha256": requirement["sha256"],
            "verified": True,
            "failures": [],
        }:
            raise ValueError(f"v2.33 source {name} result mismatch")

    migration_checks = checks.get("migration_artifacts")
    if not isinstance(migration_checks, dict):
        raise ValueError("v2.33 migration checks are missing")
    for name in preflight.MIGRATION_REQUIREMENTS:
        observed = migration_checks.get(name)
        if observed != {
            "provided": False,
            "identity_frozen": False,
            "schema_valid": False,
            "verified": False,
            "failures": ["not_provided"],
        }:
            raise ValueError(f"v2.33 migration {name} boundary mismatch")
    if report.get("blockers") != [
        f"migration:{name}" for name in preflight.MIGRATION_REQUIREMENTS
    ]:
        raise ValueError("v2.33 blocker set mismatch")

    resource_checks = checks.get("resources")
    if not isinstance(resource_checks, dict):
        raise ValueError("v2.33 resource checks are missing")
    if (
        resource_checks.get("capacity_check_passed") is not True
        or resource_checks.get("capacity_check_is_execution_authorization") is not False
        or resource_checks.get("minimums")
        != {
            "free_disk_bytes": preflight.MIN_FREE_DISK_BYTES,
            "available_memory_bytes": preflight.MIN_AVAILABLE_MEMORY_BYTES,
            "cpu_cores": preflight.MIN_CPU_CORES,
        }
    ):
        raise ValueError("v2.33 resource boundary mismatch")
    return report


def build_evidence(environment_report: Path) -> dict[str, object]:
    _require_identity(*CHECKER, "v2.33 checker")
    _require_identity(*MANIFEST, "v2.33 manifest")
    if preflight.validate_tracked_inputs():
        raise ValueError("v2.33 tracked prerequisites do not validate")
    manifest = _read_json(MANIFEST[0])
    if manifest != preflight.build_frozen_manifest():
        raise ValueError("v2.33 frozen manifest content mismatch")
    report = validate_initial_report(environment_report)
    resources = report["checks"]["resources"]
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "source_identities": {
            "preflight_checker": {
                "name": CHECKER[0].name,
                "bytes": CHECKER[1],
                "sha256": CHECKER[2],
            },
            "frozen_manifest": {
                "name": MANIFEST[0].name,
                "bytes": MANIFEST[1],
                "sha256": MANIFEST[2],
            },
            "initial_environment_report": {
                "name": environment_report.name,
                "bytes": INITIAL_REPORT[0],
                "sha256": INITIAL_REPORT[1],
            },
        },
        "legacy_profile": {
            "name": preflight.LEGACY_PROFILE_NAME,
            "fingerprint": preflight.LEGACY_PROFILE_FINGERPRINT,
            "preserved_unchanged": True,
            "legacy_evidence_overwritten": False,
        },
        "reserved_profile": {
            "name": preflight.RESERVED_PROFILE_NAME,
            "relation_id": preflight.RESERVED_PROFILE_RELATION_ID,
            "descriptor_sha256": manifest["reserved_profile_descriptor_sha256"],
            "implemented": False,
            "profile_fingerprint_frozen": False,
        },
        "migration_impact": {
            "contract_sha256": manifest["migration_impact_contract_sha256"],
            "must_be_rebuilt_or_replayed": manifest["migration_impact_contract"][
                "must_be_rebuilt_or_replayed"
            ],
            "must_not_be_reused_as_new_observation": manifest[
                "migration_impact_contract"
            ]["must_not_be_reused_as_new_observation"],
        },
        "verified_source_artifacts": [
            {
                "name": name,
                "filename": requirement["filename"],
                "bytes": requirement["bytes"],
                "sha256": requirement["sha256"],
            }
            for name, requirement in preflight.SOURCE_REQUIREMENTS.items()
        ],
        "migration_blockers": [
            {
                "name": name,
                "filename": requirement["filename"],
                "schema": requirement["schema"],
                "identity_frozen": False,
            }
            for name, requirement in preflight.MIGRATION_REQUIREMENTS.items()
        ],
        "resource_estimate": manifest["resource_estimate"],
        "observed_capacity": {
            "free_disk_bytes": resources["free_disk_bytes"],
            "available_memory_bytes": resources["available_memory_bytes"],
            "cpu_cores": resources["cpu_cores"],
            "capacity_check_passed": True,
            "is_execution_authorization": False,
        },
        "result": {
            "v2_33_read_only_migration_preflight_closed": True,
            "safe_to_author_unified_tree_specification": True,
            "safe_to_implement_reduced_prototype": True,
            "safe_to_start_production_prefreeze": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
            "large_profile_build_started": False,
            "large_replay_started": False,
            "large_proving_run_started": False,
        },
        "next_gate": {
            "action": (
                "author the exact unified-tree algorithm specification, then "
                "implement and qualify only the reduced prototype"
            ),
            "large_execution_command_status": "withheld_by_frozen_preflight",
            "withheld_reason": (
                "algorithm specification, reduced evidence, runner qualification, "
                "resource reservation, and independent design review are missing"
            ),
        },
        "claim_boundary": preflight.claim_boundary(),
        "artifact_policy": {
            "portable_evidence_contains_absolute_paths": False,
            "legacy_evidence_overwritten": False,
            "other_tree_observed_stream_bytes_reused": False,
            "assignment_or_br1cs_tracked_in_git": False,
            "pickle_cache_or_resume_tracked_in_git": False,
            "logs_tracked_in_git": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment-report", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    data = canonical_json(build_evidence(args.environment_report))
    if args.output is None:
        print(data.decode(), end="")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    print(json.dumps({
        "output": str(args.output),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "safe_to_start_production_prefreeze": False,
        "safe_to_start_large_replay": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
