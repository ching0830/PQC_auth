#!/usr/bin/env python3
"""Seal path-free evidence for the bounded PQ-RBBC v2.30 security audit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_fork_security_audit as audit


IMPLEMENTATION_VERSION = "2.30"
FORMAT = "PQRBBC-FORK-SECURITY-AUDIT-EVIDENCE-1"
RELATION_ID = "pq-rbbc/fork-security/audit-evidence/v1"
ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_RELATIVE = (
    "artifacts/metadata/fork_security_audit_v2_30/"
    "pq_rbbc_fork_security_audit_evidence_v2_30.json"
)

AUDIT_GENERATOR_IDENTITY = (
    18_371,
    "8910ee7c424bdb45014ac5c9fedad43974090260f3e254370bbceeaec680ccb3",
)
GENERATED_IDENTITIES = {
    audit.BLINDNESS_REVIEW_FILENAME: (
        3_908,
        "e85753e45abaeed27da5107c7a2a98b538d1b35fb7d2fd706504211e765ee9fc",
    ),
    audit.CAP_REVIEW_FILENAME: (
        3_514,
        "cdb613e07397ed70a12aca2a507550243fa39dc3123b8b1a527d7b0edc631185",
    ),
    audit.AUDIT_MANIFEST_FILENAME: (
        3_054,
        "6db7e6ea5230855b62a69116c4a93d3b11159641088ee716c420afc70f784162",
    ),
    audit.REVIEW_REQUEST_FILENAME: (
        3_223,
        "0a982958a2904068b5464381b374a139483c5893a20fb09259a987a6dde8d6b3",
    ),
    audit.QROM_REVIEW_FILENAME: (
        3_479,
        "e2c6009b0c03331c2606fbf26cec5cab48527692f206dc9dad2ca0b51108054f",
    ),
}
INDEPENDENT_ATTESTATION_FILENAME = (
    "pq_rbbc_fork_security_independent_review_v2_30.json"
)


def canonical_json(document: Mapping[str, object]) -> bytes:
    return audit.canonical_json(document)


def _identity(name: str, expected: tuple[int, str]) -> dict[str, object]:
    return {"name": name, "bytes": expected[0], "sha256": expected[1]}


def validate_packet(external_root: Path) -> None:
    audit.validate_external_sources(external_root)
    audit.require_identity(
        ROOT / "src/pq_rbbc_fork_security_audit.py",
        AUDIT_GENERATOR_IDENTITY,
        "v2.30 audit generator",
    )
    expected_documents = audit.build_documents()
    for name, identity in GENERATED_IDENTITIES.items():
        path = external_root / name
        audit.require_identity(path, identity, name)
        actual = json.loads(path.read_text())
        if actual != expected_documents[name]:
            raise ValueError(f"{name} canonical content mismatch")
        boundary = actual.get("claim_boundary", {})
        if boundary.get("fork_security_proof_revalidated") is not False:
            raise ValueError(f"{name} expands fork-security claim")
        if boundary.get("production_closed") is not False:
            raise ValueError(f"{name} expands production claim")
    manifest = expected_documents[audit.AUDIT_MANIFEST_FILENAME]
    if manifest.get("safe_to_start_independent_review") is not True:
        raise ValueError("review packet is not ready for independent review")
    if manifest.get("safe_to_claim_fork_security_revalidated") is not False:
        raise ValueError("audit manifest expands fork-security claim")
    if (external_root / INDEPENDENT_ATTESTATION_FILENAME).exists():
        raise ValueError(
            "unfrozen independent attestation present; use a later reviewed checkpoint"
        )


def claim_boundary() -> dict[str, bool]:
    return {
        "v2_30_internal_proof_audit_closed": True,
        "v2_30_independent_review_packet_sealed": True,
        "v2_30_independent_review_ready": True,
        "independent_review_attestation_present": False,
        "cap_unique_witness_reviewed": False,
        "cap_straightline_extraction_reviewed": False,
        "qrom_request_binding_reviewed": False,
        "fork_blindness_revalidated": False,
        "fork_one_more_unforgeability_revalidated": False,
        "fork_security_proof_revalidated": False,
        "qualified_pq_se_nizk_backend_selected": False,
        "signature_size_rebenchmarked": False,
        "production_closed": False,
        "system_architecture_changed": False,
        "ticket_lifecycle_changed": False,
        "pq_sat_auth_changed": False,
    }


def build_evidence(external_root: Path) -> dict[str, object]:
    validate_packet(external_root)
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "source_identities": {
            "authoritative_blind_uov_reference": _identity(
                audit.PAPER_FILENAME, audit.PAPER_IDENTITY
            ),
            "fork_security_proof_audit_packet": _identity(
                audit.PROOF_PACKET_FILENAME, audit.PROOF_PACKET_IDENTITY
            ),
            "fork_security_proof_audit_source": _identity(
                Path(audit.PROOF_SOURCE[0]).name,
                (audit.PROOF_SOURCE[1], audit.PROOF_SOURCE[2]),
            ),
            "v2_29_parent_join_evidence": _identity(
                Path(audit.V2_29_EVIDENCE[0]).name,
                (audit.V2_29_EVIDENCE[1], audit.V2_29_EVIDENCE[2]),
            ),
            "v2_30_preflight_manifest": _identity(
                Path(audit.V2_30_PREFLIGHT[0]).name,
                (audit.V2_30_PREFLIGHT[1], audit.V2_30_PREFLIGHT[2]),
            ),
            "fork_security_audit_generator": _identity(
                "pq_rbbc_fork_security_audit.py", AUDIT_GENERATOR_IDENTITY
            ),
            "generated_review_documents": [
                _identity(name, identity)
                for name, identity in sorted(GENERATED_IDENTITIES.items())
            ],
        },
        "source_revision": {
            "report": "IACR ePrint 2025/895",
            "title": "Blinding Post-Quantum Hash-and-Sign Signatures",
            "revision": "2025-10-31",
            "major_revision": True,
            "pages": 47,
        },
        "execution_semantics": {
            "source_checkpoint": "v2.29",
            "input_identity": audit.V2_29_INPUT_IDENTITY,
            "ordered_replay_transcript_sha256": audit.V2_29_TRANSCRIPT_SHA256,
            "combined_rows": 589_030_555,
            "verification_failures": 0,
            "external_assertions": 0,
            "other_tree_observed_stream_bytes_used": False,
        },
        "audit_result": {
            "bounded_internal_gap_analysis_completed": True,
            "packet_ready_for_independent_review": True,
            "independent_review_completed": False,
            "security_claim_promotion_permitted": False,
            "large_replay_required_for_this_checkpoint": False,
            "large_replay_started": False,
        },
        "blocking_findings": [
            "cap_unique_committed_mask_not_revalidated",
            "cap_straightline_extraction_not_revalidated",
            "concrete_qrom_request_binding_not_revalidated",
            "fork_blindness_not_revalidated",
            "fork_one_more_unforgeability_not_revalidated",
            "qualified_pq_se_nizk_backend_missing",
            "independent_review_attestation_missing",
            "fork_signature_size_not_rebenchmarked",
        ],
        "next_gate": {
            "action": "obtain qualified independent cryptographic review",
            "required_attestation_name": INDEPENDENT_ATTESTATION_FILENAME,
            "exact_automated_revalidation_command": None,
            "withheld_reason": (
                "reviewer identity, trust basis, signed findings, and accepted "
                "dispositions do not yet exist and cannot be self-attested"
            ),
        },
        "artifact_policy": {
            "portable_evidence_contains_absolute_paths": False,
            "authoritative_paper_tracked_in_git": False,
            "generated_proof_packet_pdf_tracked_in_git": False,
            "br1cs_or_assignment_tracked_in_git": False,
            "trusted_pickle_cache_tracked_in_git": False,
            "checkpoint_or_resume_state_tracked_in_git": False,
            "logs_tracked_in_git": False,
        },
        "claim_boundary": claim_boundary(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--external-root", type=Path, default=audit.EXTERNAL_ROOT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    data = canonical_json(build_evidence(args.external_root))
    if args.output is None:
        print(data.decode(), end="")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    print(json.dumps({
        "output": str(args.output),
        "bytes": len(data),
        "sha256": audit.sha256_bytes(data),
        "safe_to_start_independent_review": True,
        "safe_to_claim_fork_security_revalidated": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
