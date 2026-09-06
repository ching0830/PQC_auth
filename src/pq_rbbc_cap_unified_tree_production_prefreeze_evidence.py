#!/usr/bin/env python3
"""Seal the v2.34 read-only production pre-freeze checkpoint."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_unified_tree_production_prefreeze as preflight


IMPLEMENTATION_VERSION = "2.34"
FORMAT = "PQRBBC-CAP-UNIFIED-TREE-PRODUCTION-PREFREEZE-PORTABLE-EVIDENCE-1"
RELATION_ID = "pq-rbbc/cap/unified-tree/production-prefreeze/portable-evidence/v1"
ROOT = Path(__file__).resolve().parents[1]

TRACKED = {
    "production_prefreeze_checker": (
        ROOT / "src/pq_rbbc_cap_unified_tree_production_prefreeze.py",
        41_709,
        "b09eb31b716535560c5f36ecd2dd865222927e52476bb15c84dbbe774c747450",
    ),
    "resource_reservation_schema": (
        ROOT / "schemas/"
        "pq_rbbc_cap_unified_tree_resource_reservation_v2_34.schema.json",
        3_280,
        "87db532e70dfedf1c79aea828fab24f898a5b6286eff94a2b7706c04a4446d91",
    ),
    "production_prefreeze_manifest": (
        ROOT / "manifests/"
        "pq_rbbc_cap_unified_tree_production_prefreeze_manifest_v2_34.json",
        8_777,
        "5bef89840171011c9072bdea44b28a632b2b21df604b382f33cc6de572397829",
    ),
    "production_prefreeze_tests": (
        ROOT / "tests/test_pq_rbbc_cap_unified_tree_production_prefreeze.py",
        11_767,
        "805795a6ab6f8dde276f3829ad17fb81d6f5db84a6dbae22d38d3c6356389169",
    ),
    "v2_33_reduced_portable_evidence": (
        ROOT / "artifacts/metadata/cap_unified_tree_migration_v2_33/"
        "pq_rbbc_cap_unified_tree_reduced_portable_evidence_v2_33.json",
        5_894,
        "758f101d9e825da2d4315d69d46a48b6c5ef563c49d05633cb3b68cde4fbcdd3",
    ),
}

REPORT_FILENAME = (
    "pq_rbbc_cap_unified_tree_production_prefreeze_environment_v2_34.json"
)
REPORT_BYTES = 5_200
REPORT_SHA256 = "7201c56ee8f04c9095c85ce7cf0c57879011b30704ca1c77f2d2a9ea2c21595f"


def canonical_json(document: Mapping[str, object]) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require(path: Path, size: int, digest: str, label: str) -> None:
    if not path.is_file():
        raise ValueError(f"{label} is missing")
    if path.stat().st_size != size or _sha256(path) != digest:
        raise ValueError(f"{label} identity mismatch")


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} root must be an object")
    return document


def validate_report(document: Mapping[str, object]) -> None:
    checks = document.get("checks", {})
    sealed = checks.get("sealed_external_inputs", {})
    resource = checks.get("resource_reservation", {})
    review = checks.get("independent_review", {})
    implementation = checks.get("implementation_gate", {})
    claims = document.get("claim_boundary", {})
    expected_blockers = [
        "resource_reservation",
        "independent_review",
        "production_runner_not_implemented",
        "production_relation_contract_not_frozen",
        "production_prefreeze_not_authorized",
    ]
    if (
        document.get("format") != preflight.REPORT_FORMAT
        or document.get("relation_id") != preflight.RELATION_ID
        or document.get("safe_to_run_read_only_checker") is not True
        or document.get("safe_to_request_independent_review") is not True
        or document.get("safe_to_start_production_prefreeze") is not False
        or document.get("safe_to_start_large_replay") is not False
        or document.get("safe_to_start_large_proving_run") is not False
        or document.get("production_leaves_expanded") != 0
        or document.get("relation_rows_replayed") != 0
        or document.get("proofs_generated") != 0
        or document.get("blockers") != expected_blockers
        or checks.get("tracked_inputs", {}).get("verified") is not True
        or checks.get("resources", {}).get("capacity_check_passed") is not True
        or document.get("prefreeze_contract_sha256")
        != preflight.PREFREEZE_CONTRACT_SHA256
        or document.get("resource_reservation_schema_sha256")
        != preflight.document_sha256(preflight.resource_reservation_schema())
    ):
        raise ValueError("v2.34 environment report mismatch")
    if set(sealed) != set(preflight.SEALED_EXTERNAL_INPUTS) or not all(
        item.get("verified") is True and item.get("failures") == []
        for item in sealed.values()
    ):
        raise ValueError("sealed v2.33 external inputs mismatch")
    for label, observed in (
        ("resource reservation", resource),
        ("independent review", review),
    ):
        if (
            observed.get("provided") is not False
            or observed.get("identity_frozen") is not False
            or observed.get("verified") is not False
            or observed.get("failures") != ["not_provided"]
        ):
            raise ValueError(f"{label} boundary mismatch")
    for key in (
        "production_runner_implemented",
        "production_relation_contract_frozen",
        "production_prefreeze_execution_authorized",
    ):
        if implementation.get(key) is not False:
            raise ValueError(f"implementation gate expanded: {key}")
    required_true_claims = (
        "v2_34_read_only_prefreeze_checker_implemented",
        "resource_reservation_schema_frozen",
        "v2_33_reduced_portable_seal_bound",
        "production_profile_descriptor_fingerprint_frozen",
        "legacy_18_tree_profile_preserved",
    )
    required_false_claims = (
        "production_runner_implemented",
        "production_relation_contract_frozen",
        "operator_resource_reservation_frozen",
        "independent_review_frozen",
        "production_prefreeze_authorized",
        "production_prefreeze_started",
        "large_replay_started",
        "large_proving_run_started",
        "cap_security_qualified",
        "fork_security_proof_revalidated",
        "system_architecture_changed",
        "ticket_lifecycle_changed",
        "pq_sat_auth_changed",
        "production_closed",
    )
    if any(claims.get(key) is not True for key in required_true_claims):
        raise ValueError("v2.34 completed claim missing")
    if any(claims.get(key) is not False for key in required_false_claims):
        raise ValueError("v2.34 claim expansion")


def build_evidence(report_path: Path) -> dict[str, object]:
    for label, (path, size, digest) in TRACKED.items():
        _require(path, size, digest, label)
    if report_path.name != REPORT_FILENAME:
        raise ValueError("environment report filename mismatch")
    _require(report_path, REPORT_BYTES, REPORT_SHA256, "environment report")
    report = _read_json(report_path)
    validate_report(report)
    resources = report["checks"]["resources"]
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "tracked_identities": {
            label: {"filename": path.name, "bytes": size, "sha256": digest}
            for label, (path, size, digest) in TRACKED.items()
        },
        "external_report_identity": {
            "filename": REPORT_FILENAME,
            "bytes": REPORT_BYTES,
            "sha256": REPORT_SHA256,
        },
        "bound_contracts": {
            "production_profile_fingerprint": (
                preflight.PRODUCTION_PROFILE_FINGERPRINT
            ),
            "prefreeze_contract_sha256": preflight.PREFREEZE_CONTRACT_SHA256,
            "resource_reservation_schema_sha256": (
                preflight.document_sha256(preflight.resource_reservation_schema())
            ),
            "v2_33_reduced_portable_evidence": preflight.V2_33_PORTABLE_SEAL,
            "prospective_production_prefreeze_command_sha256": (
                preflight.PRODUCTION_PREFREEZE_COMMAND_SHA256
            ),
        },
        "environment_observation": {
            "cpu_cores": resources["cpu_cores"],
            "available_memory_bytes": resources["available_memory_bytes"],
            "free_disk_bytes": resources["free_disk_bytes"],
            "capacity_check_passed": resources["capacity_check_passed"],
            "capacity_check_is_execution_authorization": False,
        },
        "missing_external_artifacts": [
            preflight.RESOURCE_FILENAME,
            preflight.REVIEW_FILENAME,
        ],
        "implementation_blockers": [
            "production runner not implemented",
            "production relation contract not frozen",
            "production pre-freeze not authorized",
        ],
        "result": {
            "read_only_checker_implemented_and_verified": True,
            "resource_reservation_schema_frozen": True,
            "v2_33_reduced_portable_seal_bound": True,
            "safe_to_request_independent_review": True,
            "safe_to_start_production_prefreeze": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
        },
        "claim_boundary": report["claim_boundary"],
        "artifact_policy": {
            "portable_evidence_contains_absolute_paths": False,
            "legacy_18_tree_evidence_overwritten": False,
            "other_tree_observed_stream_bytes_reused": False,
            "production_assignment_or_br1cs_created": False,
            "pickle_cache_log_or_resume_tracked_in_git": False,
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
