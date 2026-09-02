#!/usr/bin/env python3
"""Fail-closed preflight for the PQ-RBBC v2.26 tree-8 through tree-10 batch.

This module performs only bounded identity and contract checks.  It never
loads pickle, creates an execution cache, or starts a production replay.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_global_tail_recovery_evidence as global_evidence
import pq_rbbc_cap_global_tail_fresh_recovery as global_fresh
import pq_rbbc_cap_planned_tree_producer as planned
import pq_rbbc_cap_tree5_7_batch_recovery_evidence as batch_evidence
import pq_rbbc_cap_tree5_7_fresh_recovery as batch_fresh


IMPLEMENTATION_VERSION = "2.26"
FORMAT = "PQRBBC-CAP-TREE8-10-PREFLIGHT-1"
RELATION_ID = "pq-rbbc/cap/production-tree8-10-batch-preflight/v1"
MANIFEST_NAME = "pq_rbbc_cap_tree8_10_preflight_manifest_v2_26.json"
TARGET_TREES = (8, 9, 10)
INITIAL_CONTRACT_SHA256 = {
    8: "3801f60ab7132fd850a10cf51a5f892624401988dedc64288b0807a34093ba70",
    9: "1d64e086061717099bf1a189c34df22966ca1e67fb17ad74d373d6bdb4f9b1df",
    10: "5d26dd745685f58b3cdfad652b9602cadf1f041d5169c4b5c4f10590cd4948aa",
}
INCREMENTAL_BR1CS_BYTES = 49_227_687
INCREMENTAL_BR1CS_SHA256 = (
    "77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799"
)
GLOBAL_FRESH_EVIDENCE_SHA256 = "658f21b0eaf8c04f04ce2c2c1216563a268e1ea736d9453c4f0e914c76d142f2"
BATCH_FRESH_EVIDENCE_SHA256 = "068a8e64122cca0a833ddf5ecb60a7f1f39bacce1162c7396253cc171b3ef5b0"
FROZEN_MANIFEST_SHA256 = (
    "e74bbed37b385ae584e2c77a0a395ee31661093453526243eb4704d0397b70e5"
)

ROOT = Path(__file__).resolve().parents[1]
GLOBAL_EVIDENCE_PATH = (
    ROOT
    / "artifacts"
    / "metadata"
    / "global_tail_recovery_v2_20"
    / global_evidence.MANIFEST_NAME
)
BATCH_EVIDENCE_PATH = (
    ROOT
    / "artifacts"
    / "metadata"
    / "tree5_7_batch_recovery_v2_25"
    / batch_evidence.MANIFEST_NAME
)
GLOBAL_MANIFEST_PATH = (
    ROOT / "manifests" / "pq_rbbc_cap_global_tail_manifest_v2_9.json"
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


def _contract_document(tree_index: int) -> dict[str, object]:
    contract = planned.load_contract(tree_index)
    digest = planned.contract_sha256(contract)
    failures = list(planned.contract_failures(contract, contract))
    if contract.stream_bytes is not None:
        failures.append("initial_stream_bytes_not_null")
    if digest != INITIAL_CONTRACT_SHA256[tree_index]:
        failures.append("initial_contract_sha256")
    return {
        "tree_index": tree_index,
        "contract_sha256": digest,
        "contract": json.loads(json.dumps(asdict(contract))),
        "contract_validation_failures": failures,
        "formal_target_claims": {
            "assignment_materialized": False,
            "prefreeze_full_replay_closed": False,
            "stream_bytes_frozen": False,
            "fresh_cache_frozen_full_replay_closed": False,
            "four_output_relocations_closed": False,
            "evidence_sealed": False,
        },
    }


def build_frozen_manifest() -> dict[str, object]:
    targets = [_contract_document(tree_index) for tree_index in TARGET_TREES]
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "runner": {
            "implementation_version": planned.IMPLEMENTATION_VERSION,
            "relation_id": planned.RELATION_ID,
            "execution_cache_format": planned.EXECUTION_CACHE_FORMAT,
            "resume_format": planned.RESUME_FORMAT,
        },
        "targets": targets,
        "external_requirements": {
            "global_tail_assignment": {
                "bytes": global_evidence.FROZEN_ARCHIVE_BYTES,
                "sha256": global_evidence.FROZEN_ARCHIVE_SHA256,
            },
            "tree5_7_batch_external_reseal": {
                "required_tree_indices": [5, 6, 7],
                "tracked_evidence_sha256": batch_evidence.FROZEN_EVIDENCE_SHA256,
            },
            "incremental_br1cs": {
                "bytes": INCREMENTAL_BR1CS_BYTES,
                "sha256": INCREMENTAL_BR1CS_SHA256,
            },
            "downloaded_pickle_accepted": False,
        },
        "execution_requirements": {
            "separate_external_directory_per_tree": True,
            "separate_cache_identity_per_tree_and_stage": True,
            "prefreeze_replay_before_stream_freeze": True,
            "fresh_local_cache_for_frozen_replay": True,
            "reuse_archive_read_only_for_frozen_replay": True,
            "required_output_matches_per_tree": 4,
            "required_external_assertions_per_tree": 0,
            "required_stale_witness_rejections_per_tree": 6,
            "required_point_mutation_rejections_per_tree": 3,
            "required_configuration_mutation_rejections_per_tree": 10,
            "other_tree_stream_bytes_may_be_reused": False,
        },
        "claim_boundary": {
            "bounded_preflight_contracts_closed": all(
                not target["contract_validation_failures"] for target in targets
            ),
            "external_execution_artifacts_verified": False,
            "production_tree8_planned_assignment_materialized": False,
            "production_tree8_planned_full_replay_closed": False,
            "production_tree9_planned_assignment_materialized": False,
            "production_tree9_planned_full_replay_closed": False,
            "production_tree10_planned_assignment_materialized": False,
            "production_tree10_planned_full_replay_closed": False,
            "remaining_planned_tree_producers_materialized": False,
            "all_72_output_relocations_closed": False,
            "complete_18_tree_assignment_replayed": False,
            "cross_segment_wire_identity_closed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }


def verify_frozen_manifest(path: Path) -> tuple[str, ...]:
    failures: list[str] = []
    encoded = path.read_bytes()
    if FROZEN_MANIFEST_SHA256 != "TODO":
        if hashlib.sha256(encoded).hexdigest() != FROZEN_MANIFEST_SHA256:
            failures.append("frozen_manifest_sha256")
    try:
        document = json.loads(encoded)
    except json.JSONDecodeError:
        return tuple(failures + ["invalid_json"])
    if document != build_frozen_manifest():
        failures.append("frozen_manifest_identity")
    return tuple(failures)


def _file_identity(path: Path | None, size: int, digest: str) -> dict[str, object]:
    if path is None:
        return {"provided": False, "verified": False, "failures": ["not_provided"]}
    failures: list[str] = []
    if not path.is_file():
        failures.append("missing")
    else:
        if path.stat().st_size != size:
            failures.append("bytes")
        if _sha256_file(path) != digest:
            failures.append("sha256")
    return {"provided": True, "verified": not failures, "failures": failures}


def _fresh_evidence_identity(
    path: Path | None, digest: str, expected_format: str, required_claim: str
) -> dict[str, object]:
    if path is None:
        return {"provided": False, "verified": False, "failures": ["not_provided"]}
    failures: list[str] = []
    if not path.is_file():
        failures.append("missing")
    else:
        if _sha256_file(path) != digest:
            failures.append("sha256")
        try:
            document = _read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            failures.append("json")
        else:
            if document.get("format") != expected_format:
                failures.append("format")
            claims = document.get("claim_boundary")
            if not isinstance(claims, dict) or claims.get(required_claim) is not True:
                failures.append("required_claim")
            if not isinstance(claims, dict) or claims.get("production_closed") is not False:
                failures.append("overclaim")
    return {"provided": True, "verified": not failures, "failures": failures}


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("JSON root is not an object")
    return document


def build_environment_report(
    global_archive: Path | None,
    batch_root: Path | None,
    incremental_br1cs: Path | None,
    global_fresh_evidence: Path | None = None,
    batch_fresh_evidence: Path | None = None,
) -> dict[str, object]:
    checks: dict[str, object] = {
        "frozen_preflight_manifest": {
            "verified": not verify_frozen_manifest(ROOT / "manifests" / MANIFEST_NAME)
        },
        "tracked_global_tail_evidence": {
            "verified": not global_evidence.verify_frozen_evidence(GLOBAL_EVIDENCE_PATH)
        },
        "tracked_tree5_7_batch_evidence": {
            "verified": not batch_evidence.verify_frozen_evidence(BATCH_EVIDENCE_PATH)
        },
        "global_tail_assignment": _file_identity(
            global_archive,
            global_evidence.FROZEN_ARCHIVE_BYTES,
            global_evidence.FROZEN_ARCHIVE_SHA256,
        ),
        "incremental_br1cs": _file_identity(
            incremental_br1cs, INCREMENTAL_BR1CS_BYTES, INCREMENTAL_BR1CS_SHA256
        ),
        "global_tail_fresh_evidence": _fresh_evidence_identity(
            global_fresh_evidence,
            GLOBAL_FRESH_EVIDENCE_SHA256,
            global_fresh.FORMAT,
            "fresh_global_tail_archive_identity_verified",
        ),
        "tree5_7_fresh_evidence": _fresh_evidence_identity(
            batch_fresh_evidence,
            BATCH_FRESH_EVIDENCE_SHA256,
            batch_fresh.FORMAT,
            "fresh_tree5_7_cryptographic_identities_verified",
        ),
    }
    batch_failures: list[str] = []
    if batch_root is None or batch_fresh_evidence is None:
        batch_failures.append("not_provided")
    else:
        try:
            regenerated = batch_fresh.build_evidence(batch_root)
            if regenerated != _read_json(batch_fresh_evidence):
                batch_failures.append("fresh_evidence_identity")
        except (OSError, ValueError, json.JSONDecodeError) as error:
            batch_failures.append(type(error).__name__)
    checks["tree5_7_external_reseal"] = {
        "provided": batch_root is not None,
        "verified": not batch_failures,
        "failures": batch_failures,
    }
    ready = all(
        isinstance(value, dict) and value.get("verified") is True
        for value in checks.values()
    )
    return {
        "format": "PQRBBC-CAP-TREE8-10-ENVIRONMENT-PREFLIGHT-1",
        "implementation_version": IMPLEMENTATION_VERSION,
        "checks": checks,
        "safe_to_start_large_replay": ready,
        "large_replay_started": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-frozen", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--global-archive", type=Path)
    parser.add_argument("--batch-root", type=Path)
    parser.add_argument("--incremental-br1cs", type=Path)
    parser.add_argument("--global-fresh-evidence", type=Path)
    parser.add_argument("--batch-fresh-evidence", type=Path)
    args = parser.parse_args()
    if args.verify_frozen is not None:
        failures = verify_frozen_manifest(args.verify_frozen)
        if failures:
            raise SystemExit("v2.26 preflight manifest rejected: " + ",".join(failures))
        print("v2.26 tree-8 through tree-10 preflight manifest accepted")
        return
    if args.report is None:
        parser.error("--report or --verify-frozen is required")
    report = build_environment_report(
        args.global_archive,
        args.batch_root,
        args.incremental_br1cs,
        args.global_fresh_evidence,
        args.batch_fresh_evidence,
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_bytes(canonical_json(report))
    print(json.dumps({"report": str(args.report), "safe_to_start_large_replay": report["safe_to_start_large_replay"]}, sort_keys=True))


if __name__ == "__main__":
    main()
