#!/usr/bin/env python3
"""Seal a fresh global-tail rebuild without rewriting historical timings."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_global_tail_recovery_evidence as historical
from pq_rbbc_cap_shard_assignment import AssignmentArchiveMetadata, AssignmentArchiveReader


FORMAT = "PQRBBC-CAP-GLOBAL-TAIL-FRESH-RECOVERY-1"
IMPLEMENTATION_VERSION = "2.26"
RELATION_ID = "pq-rbbc/cap/production-global-tail-fresh-recovery/v1"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(document: Mapping[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def build_evidence(archive: Path, rebuilt_manifest: Path, historical_manifest: Path) -> dict[str, object]:
    rebuilt = json.loads(rebuilt_manifest.read_text(encoding="utf-8"))
    frozen = json.loads(historical_manifest.read_text(encoding="utf-8"))
    if historical._security_projection(rebuilt) != historical._security_projection(frozen):
        raise ValueError("fresh global-tail security projection changed")
    archive_section = rebuilt.get("assignment_archive")
    trace = rebuilt.get("trace")
    if not isinstance(archive_section, dict) or not isinstance(trace, dict):
        raise ValueError("fresh global-tail manifest is incomplete")
    expected = AssignmentArchiveMetadata(**archive_section)
    with AssignmentArchiveReader(archive, expected=expected, verify_body=True):
        pass
    checks = {
        "archive_bytes": archive.stat().st_size == historical.FROZEN_ARCHIVE_BYTES,
        "archive_sha256": _sha256(archive) == historical.FROZEN_ARCHIVE_SHA256,
        "body_sha256": archive_section.get("body_sha256") == historical.FROZEN_BODY_SHA256,
        "row_stream_sha256": archive_section.get("row_stream_sha256") == historical.FROZEN_STREAM_SHA256,
        "rows": trace.get("rows") == historical.FROZEN_ROWS,
        "external_assertions": trace.get("external_assertions") == 0,
        "verification_failures": trace.get("verification_failures") == 0,
    }
    if not all(checks.values()):
        raise ValueError("fresh global-tail identity rejected: " + ",".join(k for k, v in checks.items() if not v))
    projection = historical._security_projection(rebuilt)
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "historical_evidence": {
            "sha256": historical.FROZEN_EVIDENCE_SHA256,
            "recovered_manifest_sha256": historical.FROZEN_RECOVERED_MANIFEST_SHA256,
        },
        "fresh_rebuild": {
            "archive_bytes": archive.stat().st_size,
            "archive_sha256": _sha256(archive),
            "manifest_sha256": _sha256(rebuilt_manifest),
            "security_projection_sha256": hashlib.sha256(canonical_json(projection)).hexdigest(),
            **{name: trace[name] for name in historical.PERFORMANCE_FIELDS},
        },
        "claim_boundary": {
            "fresh_global_tail_archive_identity_verified": True,
            "fresh_security_projection_matches_historical": True,
            "historical_performance_reproduced": False,
            "complete_18_tree_assignment_replayed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "production_closed": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--rebuilt-manifest", type=Path, required=True)
    parser.add_argument("--historical-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document = build_evidence(args.archive, args.rebuilt_manifest, args.historical_manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json(document))
    print(hashlib.sha256(args.output.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
