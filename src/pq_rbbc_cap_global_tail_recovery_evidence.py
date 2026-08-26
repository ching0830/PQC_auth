#!/usr/bin/env python3
"""Seal the regenerated PQ-RBBC production global-tail archive, v2.20.

Version 2.19 recovered the trusted v2.8 production composer cache.  This
module turns the completed v2.20 regeneration of the frozen v2.9 global-tail
archive into portable, path-free evidence suitable for Git.  The one-gigabyte
assignment archive remains external.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_composer_recovery_evidence as composer_recovery
import pq_rbbc_cap_global_tail as global_tail
from pq_rbbc_cap_shard_assignment import (
    AssignmentArchiveMetadata,
    AssignmentArchiveReader,
)


IMPLEMENTATION_VERSION = "2.20"
EVIDENCE_FORMAT = "PQRBBC-CAP-GLOBAL-TAIL-RECOVERY-EVIDENCE-1"
RELATION_ID = "pq-rbbc/cap/production-global-tail-recovery-evidence/v1"
MANIFEST_NAME = "pq_rbbc_cap_global_tail_recovery_evidence_v2_20.json"

FROZEN_EVIDENCE_SHA256 = (
    "47709b4483871f5d365738eca276700c329d0b2ed2d7a6f4956874dd433a78c4"
)
FROZEN_RECOVERED_MANIFEST_SHA256 = (
    "ef53b43f57dc5a740ab612caa4437f1e47273f645d3a8454c689bc4666a5bb5b"
)
FROZEN_HISTORICAL_MANIFEST_SHA256 = (
    "a8667bdfcfa64e3f2498ea4fea806257fdd031f091c21445f7a9c1f27bd705fa"
)
FROZEN_ARCHIVE_BYTES = 1_004_865_028
FROZEN_ARCHIVE_SHA256 = global_tail.FROZEN_PRODUCTION_ASSIGNMENT_SHA256
FROZEN_BODY_BYTES = 1_004_864_900
FROZEN_BODY_SHA256 = (
    "358266d106a1ac01cacb7c19c9bff1a7da2acceeb580a1d54462f31986cba925"
)
FROZEN_ROWS = global_tail.FROZEN_PRODUCTION_ROWS
FROZEN_WIRES = global_tail.FROZEN_PRODUCTION_WIRES
FROZEN_STREAM_SHA256 = global_tail.FROZEN_PRODUCTION_STREAM_SHA256
FROZEN_GENERATION_SECONDS = 4_152.805588226001
FROZEN_VERIFICATION_SECONDS = 1_445.4420107459955
FROZEN_PEAK_RSS_KIB = 1_569_280
PERFORMANCE_FIELDS = (
    "generation_seconds",
    "verification_seconds",
    "peak_rss_kib",
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


def _security_projection(document: Mapping[str, object]) -> dict[str, object]:
    projected = copy.deepcopy(dict(document))
    trace = projected.get("trace")
    if not isinstance(trace, dict):
        raise ValueError("global-tail manifest trace is missing")
    for field in PERFORMANCE_FIELDS:
        trace.pop(field, None)
    return projected


def build_frozen_evidence_document() -> dict[str, object]:
    """Return the portable evidence frozen after the completed R0-b run."""

    return {
        "format": EVIDENCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "source_cache_recovery": {
            "implementation_version": composer_recovery.IMPLEMENTATION_VERSION,
            "relation_id": composer_recovery.RELATION_ID,
            "evidence_sha256": composer_recovery.FROZEN_EVIDENCE_SHA256,
            "execution_cache_sha256": (
                composer_recovery.FROZEN_EXECUTION_CACHE_SHA256
            ),
            "execution_sha256": composer_recovery.FROZEN_EXECUTION_SHA256,
        },
        "production_global_tail": {
            "source_implementation_version": global_tail.IMPLEMENTATION_VERSION,
            "source_relation_id": global_tail.RELATION_ID,
            "archive_bytes": FROZEN_ARCHIVE_BYTES,
            "archive_sha256": FROZEN_ARCHIVE_SHA256,
            "body_bytes": FROZEN_BODY_BYTES,
            "body_sha256": FROZEN_BODY_SHA256,
            "rows": FROZEN_ROWS,
            "wires": FROZEN_WIRES,
            "row_stream_sha256": FROZEN_STREAM_SHA256,
            "commitment_sha256": (
                global_tail.FROZEN_PRODUCTION_COMMITMENT_SHA256
            ),
            "request_hash_hex": global_tail.FROZEN_PRODUCTION_REQUEST_HASH_HEX,
            "external_assertions": 0,
            "replay_failures": 0,
            "stale_witness_probes": 6,
            "stale_witness_probes_rejected": True,
        },
        "recovered_manifest": {
            "sha256": FROZEN_RECOVERED_MANIFEST_SHA256,
            "historical_manifest_sha256": FROZEN_HISTORICAL_MANIFEST_SHA256,
            "security_fields_match_historical_manifest": True,
            "allowed_environment_measurements": list(PERFORMANCE_FIELDS),
            "generation_seconds": FROZEN_GENERATION_SECONDS,
            "verification_seconds": FROZEN_VERIFICATION_SECONDS,
            "peak_rss_kib": FROZEN_PEAK_RSS_KIB,
        },
        "artifact_policy": {
            "large_artifacts_tracked_in_git": False,
            "portable_evidence_contains_absolute_paths": False,
            "archive_format_is_non_executable_binary": True,
        },
        "claim_boundary": {
            "production_execution_cache_regenerated": True,
            "production_composition_document_revalidated": True,
            "production_global_tail_archive_regenerated": True,
            "production_global_tail_native_closed": True,
            "production_tree2_rebased_assignment_materialized": False,
            "production_tree2_rebased_full_replay_closed": False,
            "representative_producers_rebased_replayed": False,
            "complete_18_tree_assignment_replayed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }


def validate_evidence_document(document: Mapping[str, object]) -> tuple[str, ...]:
    failures: list[str] = []
    expected = build_frozen_evidence_document()
    if document.get("format") != EVIDENCE_FORMAT:
        failures.append("wrong_format")
    if document.get("implementation_version") != IMPLEMENTATION_VERSION:
        failures.append("wrong_implementation_version")
    if document.get("relation_id") != RELATION_ID:
        failures.append("wrong_relation_id")
    for section, failure in (
        ("source_cache_recovery", "source_cache_recovery_identity"),
        ("production_global_tail", "production_global_tail_identity"),
        ("recovered_manifest", "recovered_manifest_identity"),
        ("artifact_policy", "artifact_policy"),
        ("claim_boundary", "claim_boundary"),
    ):
        if document.get(section) != expected[section]:
            failures.append(failure)
    return tuple(failures)


def verify_frozen_evidence(path: Path) -> tuple[str, ...]:
    encoded = path.read_bytes()
    failures: list[str] = []
    if FROZEN_EVIDENCE_SHA256 != "TODO":
        if hashlib.sha256(encoded).hexdigest() != FROZEN_EVIDENCE_SHA256:
            failures.append("frozen_evidence_sha256")
    try:
        document = json.loads(encoded)
    except json.JSONDecodeError:
        return tuple(failures + ["invalid_json"])
    if not isinstance(document, dict):
        return tuple(failures + ["evidence_root"])
    failures.extend(validate_evidence_document(document))
    return tuple(dict.fromkeys(failures))


def build_evidence_from_artifacts(
    archive_path: Path,
    recovered_manifest_path: Path,
    historical_manifest_path: Path,
) -> dict[str, object]:
    """Validate the external archive and return its portable evidence."""

    recovered = json.loads(recovered_manifest_path.read_text(encoding="utf-8"))
    historical = json.loads(historical_manifest_path.read_text(encoding="utf-8"))
    if not isinstance(recovered, dict) or not isinstance(historical, dict):
        raise ValueError("global-tail manifest root must be an object")
    sealed = global_tail.seal_existing_manifest(recovered)
    if sealed != recovered:
        raise ValueError("recovered global-tail manifest is not sealed")
    if _security_projection(recovered) != _security_projection(historical):
        raise ValueError("recovered global-tail security evidence changed")

    archive_section = recovered.get("assignment_archive")
    trace = recovered.get("trace")
    if not isinstance(archive_section, dict) or not isinstance(trace, dict):
        raise ValueError("recovered global-tail evidence is incomplete")
    expected_archive = AssignmentArchiveMetadata(**archive_section)
    with AssignmentArchiveReader(
        archive_path, expected=expected_archive, verify_body=True
    ) as archive:
        archive_checks = {
            "archive_bytes": archive_path.stat().st_size == FROZEN_ARCHIVE_BYTES,
            "archive_sha256": _sha256_file(archive_path) == FROZEN_ARCHIVE_SHA256,
            "body_bytes": archive.body_bytes == FROZEN_BODY_BYTES,
            "body_sha256": archive.body_sha256 == FROZEN_BODY_SHA256,
            "wires": archive.wires == FROZEN_WIRES,
            "row_stream_sha256": archive.row_stream_sha256
            == FROZEN_STREAM_SHA256,
        }

    probes = recovered.get("stale_witness_probes")
    exact_checks = {
        **archive_checks,
        "recovered_manifest_sha256": _sha256_file(recovered_manifest_path)
        == FROZEN_RECOVERED_MANIFEST_SHA256,
        "historical_manifest_sha256": _sha256_file(historical_manifest_path)
        == FROZEN_HISTORICAL_MANIFEST_SHA256,
        "rows": trace.get("rows") == FROZEN_ROWS,
        "external_assertions": trace.get("external_assertions") == 0,
        "verification_failures": trace.get("verification_failures") == 0,
        "generation_seconds": trace.get("generation_seconds")
        == FROZEN_GENERATION_SECONDS,
        "verification_seconds": trace.get("verification_seconds")
        == FROZEN_VERIFICATION_SECONDS,
        "peak_rss_kib": trace.get("peak_rss_kib") == FROZEN_PEAK_RSS_KIB,
        "stale_witness_probes": isinstance(probes, list)
        and len(probes) == 6
        and all(
            isinstance(probe, dict)
            and probe.get("honest_row_satisfied") is True
            and probe.get("stale_row_satisfied") is False
            and probe.get("rejected") is True
            for probe in probes
        ),
    }
    failed = [name for name, accepted in exact_checks.items() if not accepted]
    if failed:
        raise ValueError("global-tail recovery evidence rejected: " + ",".join(failed))
    return build_frozen_evidence_document()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--recovered-manifest", type=Path)
    parser.add_argument("--historical-manifest", type=Path)
    parser.add_argument("--verify-frozen", type=Path)
    args = parser.parse_args()

    if args.verify_frozen is not None:
        failures = verify_frozen_evidence(args.verify_frozen)
        if failures:
            raise SystemExit("frozen global-tail evidence rejected: " + ",".join(failures))
        print("frozen production global-tail recovery evidence accepted")
        return

    required = (
        args.manifest,
        args.archive,
        args.recovered_manifest,
        args.historical_manifest,
    )
    if not all(item is not None for item in required):
        parser.error(
            "--manifest, --archive, --recovered-manifest, and "
            "--historical-manifest are required"
        )
    document = build_evidence_from_artifacts(
        args.archive,
        args.recovered_manifest,
        args.historical_manifest,
    )
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_bytes(canonical_json(document))
    print(hashlib.sha256(args.manifest.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
