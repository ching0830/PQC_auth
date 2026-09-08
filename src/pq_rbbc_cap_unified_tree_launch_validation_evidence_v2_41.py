#!/usr/bin/env python3
"""Seal only a missing-candidate v2.41 report, never an attestation or freeze."""

import argparse
from datetime import datetime
from pathlib import Path

import pq_rbbc_cap_unified_tree_launch_validation_v2_41 as launch
from pq_rbbc_launch_io_v2_41 import ArtifactRoot, ValidationError, canonical_json, publish_exclusive, read_snapshot


FORMAT = "PQRBBC-CAP-UNIFIED-TREE-LAUNCH-VALIDATION-PORTABLE-EVIDENCE-1"
PORTABLE_PATH = launch.ROOT / (
    "artifacts/metadata/cap_unified_tree_launch_validation_v2_41/"
    "pq_rbbc_cap_unified_tree_launch_validation_portable_evidence_v2_41.json")
SOURCE_PATHS = tuple(launch.ROOT / path for path in (
    "src/pq_rbbc_launch_io_v2_41.py",
    "src/pq_rbbc_cap_unified_tree_launch_validation_v2_41.py",
    "src/pq_rbbc_cap_unified_tree_launch_validation_evidence_v2_41.py",
    "tests/test_pq_rbbc_cap_unified_tree_launch_validation_v2_41.py",
    "tests/test_pq_rbbc_cap_unified_tree_launch_validation_evidence_v2_41.py",
))


def validate_missing_report(document, manifest_identity):
    if type(document) is not dict or type(document.get("validated_at_utc")) is not str:
        raise ValidationError("missing-candidate report required")
    try:
        recorded = launch.check_now(datetime.fromisoformat(document["validated_at_utc"]))
        if recorded.isoformat() != document["validated_at_utc"]:
            raise ValueError("noncanonical report timestamp")
    except ValueError as error:
        raise ValidationError("invalid report timestamp") from error
    # A recorded time here describes a negative historical observation. It is
    # never used as trusted now for accepting a reservation or authorizing work.
    expected = {
        "format": launch.REPORT_FORMAT, "implementation_version": "2.41", "relation_id": launch.RELATION_ID,
        "validated_at_utc": recorded.isoformat(), "manifest": manifest_identity,
        "tracked_contracts": {"verified": True, "failures": []},
        "external_candidates": {kind: {"provided": False, "identity_frozen": False,
                                       "candidate_acceptable_for_freeze": False, "failures": ["not_provided"]}
                                for kind in launch.KINDS},
        "result": {"safe_to_run_read_only_preflight": True, "safe_to_author_launch_manifest_candidate": False,
                   "safe_to_freeze_launch_identity_set": False, "safe_to_start_production_prefreeze": False,
                   "safe_to_start_large_replay": False, "safe_to_start_large_proving_run": False},
        "claim_boundary": launch.claim_boundary(),
        "blockers": ["exact external identities are not frozen", "signer authenticity and independence require external verification",
                     "production stream/checkpoint and scale qualification remain absent", "execution authorization is outside v2.41"],
    }
    if not launch.strict_equal(document, expected):
        raise ValidationError("report is not the exact fail-closed missing-candidate observation")


def build_evidence(report_path: Path, expected_report_identity: dict, *, artifact_root=launch.EXTERNAL_ROOT):
    failures, contracts = launch.contract_snapshots()
    if failures:
        raise ValidationError("evidence requires exact tracked contracts and v2.38 predecessor")
    if launch.validate_schema(expected_report_identity, launch._identity_schema()):
        raise ValidationError("expected report identity must be strict")
    if report_path != artifact_root / launch.REPORT_FILENAME:
        raise ValidationError("exact report location required")
    # No _require(path) followed by parse(path). Identity and parsing share one
    # immutable, bounded read even when the pathname is replaced afterwards.
    snapshot = ArtifactRoot(artifact_root).read(report_path)
    if not launch.strict_equal(snapshot.identity, expected_report_identity):
        raise ValidationError("report identity mismatch")
    report = snapshot.document()
    validate_missing_report(report, contracts[launch.MANIFEST_PATH].identity)
    sources = {path: read_snapshot(path) for path in SOURCE_PATHS}
    return {
        "format": FORMAT, "implementation_version": "2.41",
        "relation_id": "pq-rbbc/cap/unified-tree/launch-validation/portable-evidence/v1",
        "historical_base_commit": launch.HISTORICAL_BASE_COMMIT,
        "historical_identities": {Path(path).name: identity for path, identity in launch.HISTORICAL_IDENTITIES.items()},
        "successor_identities": {path.name: snap.identity for path, snap in sources.items()},
        "manifest": contracts[launch.MANIFEST_PATH].identity,
        "schema_identities": {kind: contracts[path].identity for kind, path in launch.SCHEMA_PATHS.items()},
        "sealed_predecessor": launch.V2_38_PORTABLE_IDENTITY,
        "external_report_identity": snapshot.identity,
        "negative_observation_at_utc": report["validated_at_utc"],
        "preflight_result": report["result"],
        "claim_boundary": launch.claim_boundary(),
        "observations": {"production_records_materialized": 0, "production_relation_rows_replayed": 0,
                         "assignment_rows": 0, "br1cs_rows": 0, "proofs_generated": 0},
        "artifact_policy": {"real_attestations_created": False, "launch_identity_set_frozen": False,
                            "portable_contains_candidate_bytes": False, "portable_contains_absolute_paths": False},
    }


def write_evidence(output: Path, document: dict, *, artifact_root=launch.EXTERNAL_ROOT):
    if output == PORTABLE_PATH:
        publish_exclusive(output, canonical_json(document), external=False)
    else:
        ArtifactRoot(artifact_root).write(output, document)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expected-report-bytes", type=int, required=True)
    parser.add_argument("--expected-report-sha256", required=True)
    parser.add_argument("--trusted-artifact-root", type=Path, default=launch.EXTERNAL_ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fresh-output", action="store_true")
    args = parser.parse_args()
    if not args.fresh_output:
        raise ValidationError("--fresh-output required")
    identity = {"filename": args.report.name, "bytes": args.expected_report_bytes, "sha256": args.expected_report_sha256}
    document = build_evidence(args.report, identity, artifact_root=args.trusted_artifact_root)
    write_evidence(args.output, document, artifact_root=args.trusted_artifact_root)
    print(canonical_json({"output": str(args.output), "launch_identity_set_frozen": False,
                          "safe_to_start_production_prefreeze": False}).decode(), end="")


if __name__ == "__main__":
    main()
