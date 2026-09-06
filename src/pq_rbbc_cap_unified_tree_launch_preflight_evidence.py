#!/usr/bin/env python3
"""Seal path-free v2.39 launch-preflight qualification evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_unified_tree_launch_preflight as launch


IMPLEMENTATION_VERSION = "2.39"
FORMAT = "PQRBBC-CAP-UNIFIED-TREE-LAUNCH-PREFLIGHT-PORTABLE-EVIDENCE-1"
RELATION_ID = "pq-rbbc/cap/unified-tree/launch-preflight/portable-evidence/v1"
ROOT = Path(__file__).resolve().parents[1]

TRACKED = {
    "launch_preflight_implementation": (
        ROOT / "src/pq_rbbc_cap_unified_tree_launch_preflight.py",
        53_578,
        "e19dc7846da1a42a127c79ac6e6f39b358f98edea92642abfccab41e24eb21cd",
    ),
    "launch_preflight_manifest": (
        launch.MANIFEST_PATH,
        6_462,
        "da2e8a80c2391c218b265414648d2877d840c626b6b669ed8d85343e55f2db51",
    ),
    "resource_reservation_schema": (
        launch.RESOURCE_SCHEMA_PATH,
        3_679,
        "a8234b7c49118f731bb18281f402e39396005f063b49e35050072d9b7bcbee0f",
    ),
    "independent_review_schema": (
        launch.REVIEW_SCHEMA_PATH,
        3_729,
        "55a6b3a1c5e55cb5d0d6efcae05adbdebaa55c0ad800e0da62b92144dc45693d",
    ),
    "launch_manifest_schema": (
        launch.LAUNCH_SCHEMA_PATH,
        3_696,
        "207bcad1f6f09bdfe56925f2c36f6f71b0718cf2942d5bd6f5e1dbf2a627b2ca",
    ),
    "launch_preflight_tests": (
        ROOT / "tests/test_pq_rbbc_cap_unified_tree_launch_preflight.py",
        9_250,
        "ef0c05b8c46fe1ac5b12f1ef8f6a403023405056c400a831151fac6472dbfddd",
    ),
    "v2_38_portable_evidence": (
        launch.V2_38_PORTABLE_PATH,
        launch.V2_38_PORTABLE_IDENTITY["bytes"],
        launch.V2_38_PORTABLE_IDENTITY["sha256"],
    ),
}

EXTERNAL_IDENTITIES = {
    "resource_template": {
        "filename": launch.RESOURCE_TEMPLATE_FILENAME,
        "bytes": 1_624,
        "sha256": "6dabdc0f8af032de269788cfb1508d93934550e34a7037f725990651d28a6cea",
    },
    "review_template": {
        "filename": launch.REVIEW_TEMPLATE_FILENAME,
        "bytes": 1_750,
        "sha256": "c47c5242ea467397ec0b4734c18c1b666b80a62798d4c740ccfabc07d201c70d",
    },
    "launch_template": {
        "filename": launch.LAUNCH_TEMPLATE_FILENAME,
        "bytes": 2_148,
        "sha256": "544044f8a5480e9bbb01ca23ef5664a30fa957687c1607fe39b40f0ba0c2d155",
    },
    "preflight_report": {
        "filename": launch.REPORT_FILENAME,
        "bytes": 3_116,
        "sha256": "33ae0c6163ab5806170b7d82d38c8bc80f3f5515638dc1d143bbbeadd6c23f62",
    },
    "qualification": {
        "filename": launch.QUALIFICATION_FILENAME,
        "bytes": 3_171,
        "sha256": "551da81cd0ac971ecef7fdd5c7304bd12285f96129de1e718b14d49c3488045a",
    },
}


def canonical_json(document: object) -> bytes:
    return launch.canonical_json(document)


def _require(path: Path, expected: Mapping[str, object], label: str) -> None:
    if not path.is_file() or launch.identity(path) != expected:
        raise ValueError(f"{label} identity mismatch")


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} root must be an object")
    return document


def validate_preflight(document: Mapping[str, object]) -> None:
    candidates = document.get("external_candidates", {})
    result = document.get("result", {})
    capacity = document.get("capacity_observation", {})
    expected_result = {
        "safe_to_run_read_only_preflight": True,
        "safe_to_emit_draft_templates": True,
        "safe_to_author_launch_manifest_candidate": False,
        "safe_to_freeze_launch_identity_set": False,
        "safe_to_start_production_prefreeze": False,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
    }
    if (
        document.get("format") != launch.REPORT_FORMAT
        or document.get("implementation_version") != IMPLEMENTATION_VERSION
        or document.get("relation_id") != launch.RELATION_ID
        or document.get("manifest") != launch.identity(launch.MANIFEST_PATH)
        or document.get("sealed_predecessor", {}).get("verified") is not True
        or document.get("tracked_contracts") != {"verified": True, "failures": []}
        or set(candidates) != {"resource_reservation", "independent_review", "launch_manifest"}
        or any(item.get("provided") is not False for item in candidates.values())
        or any(item.get("identity_frozen") is not False for item in candidates.values())
        or document.get("candidate_identity_set_ready_for_later_freeze") is not False
        or len(document.get("blockers", [])) != 9
        or result != expected_result
        or capacity.get("minimums_met") is not True
        or capacity.get("capacity_is_reservation") is not False
        or capacity.get("capacity_is_execution_authorization") is not False
        or document.get("claim_boundary") != launch.claim_boundary()
    ):
        raise ValueError("v2.39 preflight report mismatch")


def validate_qualification(document: Mapping[str, object]) -> None:
    expected_checks = {
        "tracked_contracts_exact": True,
        "v2_38_portable_identity_exact": True,
        "resource_template_rejected": True,
        "review_template_rejected": True,
        "launch_template_rejected": True,
        "missing_candidates_fail_closed": True,
        "production_prefreeze_not_authorized": True,
        "large_replay_not_started": True,
        "large_proving_not_started": True,
    }
    expected_result = {
        "attestation_schemas_qualified": True,
        "real_operator_reservation_present": False,
        "real_independent_review_present": False,
        "launch_manifest_authored": False,
        "launch_identity_set_frozen": False,
        "safe_to_start_production_prefreeze": False,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
    }
    expected_observations = {
        "production_records_materialized": 0,
        "production_relation_rows_replayed": 0,
        "assignment_rows": 0,
        "br1cs_rows": 0,
        "proofs_generated": 0,
    }
    output_map = {
        launch.RESOURCE_TEMPLATE_FILENAME: EXTERNAL_IDENTITIES["resource_template"],
        launch.REVIEW_TEMPLATE_FILENAME: EXTERNAL_IDENTITIES["review_template"],
        launch.LAUNCH_TEMPLATE_FILENAME: EXTERNAL_IDENTITIES["launch_template"],
        launch.REPORT_FILENAME: EXTERNAL_IDENTITIES["preflight_report"],
    }
    if (
        document.get("format") != launch.QUALIFICATION_FORMAT
        or document.get("implementation_version") != IMPLEMENTATION_VERSION
        or document.get("relation_id") != launch.RELATION_ID
        or document.get("manifest") != launch.identity(launch.MANIFEST_PATH)
        or document.get("sealed_predecessor") != launch.V2_38_PORTABLE_IDENTITY
        or document.get("external_outputs") != output_map
        or document.get("checks") != expected_checks
        or document.get("result") != expected_result
        or document.get("observations") != expected_observations
        or document.get("claim_boundary") != launch.claim_boundary()
    ):
        raise ValueError("v2.39 qualification mismatch")


def build_evidence(output_directory: Path) -> dict[str, object]:
    for label, (path, size, digest) in TRACKED.items():
        _require(
            path,
            {"filename": path.name, "bytes": size, "sha256": digest},
            label,
        )
    for label, expected in EXTERNAL_IDENTITIES.items():
        _require(output_directory / str(expected["filename"]), expected, label)
    resource_template = _read_json(output_directory / launch.RESOURCE_TEMPLATE_FILENAME)
    review_template = _read_json(output_directory / launch.REVIEW_TEMPLATE_FILENAME)
    launch_template = _read_json(output_directory / launch.LAUNCH_TEMPLATE_FILENAME)
    if resource_template != launch.resource_template() or not launch.validate_resource(resource_template):
        raise ValueError("resource template is not the deliberately invalid draft")
    if review_template != launch.review_template() or not launch.validate_review(review_template):
        raise ValueError("review template is not the deliberately invalid draft")
    if launch_template != launch.launch_template() or not launch.validate_launch(launch_template):
        raise ValueError("launch template is not the deliberately invalid draft")
    preflight = _read_json(output_directory / launch.REPORT_FILENAME)
    qualification = _read_json(output_directory / launch.QUALIFICATION_FILENAME)
    validate_preflight(preflight)
    validate_qualification(qualification)
    manifest = launch.build_manifest()
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "sealed_predecessor": dict(launch.V2_38_PORTABLE_IDENTITY),
        "tracked_identities": {
            label: {"filename": path.name, "bytes": size, "sha256": digest}
            for label, (path, size, digest) in TRACKED.items()
        },
        "schema_identities": {
            label: {
                "filename": path.name,
                "bytes": size,
                "sha256": digest,
            }
            for label, (path, size, digest) in TRACKED.items()
            if label.endswith("_schema")
        },
        "external_draft_and_report_identities": dict(EXTERNAL_IDENTITIES),
        "bound_commands": {
            "qualification_sha256": manifest["exact_commands"]["qualification"]["sha256"],
            "launch_preflight_sha256": manifest["exact_commands"]["launch_preflight"]["sha256"],
            "author_launch_manifest_sha256": manifest["exact_commands"]["author_launch_manifest"]["sha256"],
            "v2_38_predecessor_production_sha256": launch.V2_38_PRODUCTION_COMMAND_SHA256,
            "v2_39_candidate_production_sha256": launch.PRODUCTION_COMMAND_SHA256,
        },
        "qualification_result": qualification["result"],
        "preflight_result": preflight["result"],
        "capacity_observation": preflight["capacity_observation"],
        "missing_real_external_artifacts": [
            launch.RESOURCE_FILENAME,
            launch.REVIEW_FILENAME,
            launch.LAUNCH_FILENAME,
        ],
        "remaining_blockers": preflight["blockers"],
        "observations": qualification["observations"],
        "static_claim_boundary": launch.claim_boundary(),
        "artifact_policy": {
            "draft_templates_are_attestations": False,
            "external_attestations_fabricated": False,
            "portable_evidence_contains_absolute_paths": False,
            "production_outputs_tracked_in_git": False,
            "other_tree_observed_stream_bytes_reused": False,
            "assignment_or_br1cs_created": False,
            "pickle_cache_log_or_resume_tracked_in_git": False,
            "legacy_18_tree_evidence_overwritten": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qualification-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fresh-output", action="store_true")
    args = parser.parse_args()
    if not args.fresh_output:
        raise ValueError("v2.39 sealer requires --fresh-output")
    if args.output.exists():
        raise FileExistsError("portable evidence output already exists")
    document = build_evidence(args.qualification_directory)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json(document))
    print(json.dumps({
        "output": str(args.output),
        "identity": launch.identity(args.output),
        "attestation_schemas_qualified": True,
        "launch_identity_set_frozen": False,
        "safe_to_start_production_prefreeze": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
