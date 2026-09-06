#!/usr/bin/env python3
"""Seal path-free evidence for the authored PQ-RBBC v2.31 CAP candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_security_qualification as qualification


IMPLEMENTATION_VERSION = "2.31"
FORMAT = "PQRBBC-CAP-SECURITY-PROOF-ARTIFACT-EVIDENCE-1"
RELATION_ID = "pq-rbbc/cap-security/proof-artifact-evidence/v1"
ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_RELATIVE = (
    "artifacts/metadata/cap_security_qualification_v2_31/"
    "pq_rbbc_cap_security_artifact_evidence_v2_31.json"
)

CHECKER_IDENTITY = (
    30_031,
    "09162b813bd22c19dc4b16c762fde61217dbfb7c24eac06f01b8814869ce2798",
)
MANIFEST_IDENTITY = (
    11_778,
    "dc143238d9c22d94ace03ee37b1f4ead0b6f0b2f876c7a790fc0b644495326db",
)
ARTIFACT_GENERATOR_IDENTITY = (
    22_923,
    "b70aaa757db2f3b4a330cbc5e3292987b0ab7d8a1cef97790f82b86c5fe72317",
)
EXTRACTOR_SOURCE_IDENTITY = (
    22_275,
    "67d4fb74d1e5ec3d8600ac9da89fa9b04b6ef2bceba104fb75b3b4d8a9de47f6",
)
EXTRACTOR_HTML_IDENTITY = (
    10_367,
    "5b5b663f7f40bcaddb4d641314554c5c8ffe67bdbe541c031e4b04c463df0129",
)
UNIQUE_MASK_HTML_IDENTITY = (
    8_928,
    "b865bbfef5c4f776694eb3a130d8dfeb14686d87e28ea8d04be26376c4637f4d",
)
CANDIDATE_REPORT_IDENTITY = (
    2_907,
    "8b80a6bce2a6022d6f7ea499a2314ddda56fb83ec908a3b26681399404a941cd",
)

TRACKED_INPUTS = {
    "qualification_checker": (
        "src/pq_rbbc_cap_security_qualification.py",
        *CHECKER_IDENTITY,
    ),
    "qualification_manifest": (
        "manifests/pq_rbbc_cap_security_qualification_manifest_v2_31.json",
        *MANIFEST_IDENTITY,
    ),
    "artifact_generator": (
        "src/pq_rbbc_cap_security_artifacts.py",
        *ARTIFACT_GENERATOR_IDENTITY,
    ),
    "extractor_source": (
        "src/pq_rbbc_cap_straightline_extractor.py",
        *EXTRACTOR_SOURCE_IDENTITY,
    ),
    "extractor_specification_source": (
        "docs/proof/source/"
        "pq_rbbc_cap_straightline_extractor_spec_v2_31.html",
        *EXTRACTOR_HTML_IDENTITY,
    ),
    "unique_mask_reduction_source": (
        "docs/proof/source/"
        "pq_rbbc_cap_unique_committed_mask_reduction_v2_31.html",
        *UNIQUE_MASK_HTML_IDENTITY,
    ),
}


def canonical_json(document: Mapping[str, object]) -> bytes:
    return qualification.canonical_json(document)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_identity(
    path: Path, expected: tuple[int, str], label: str
) -> None:
    if not path.is_file():
        raise ValueError(f"{label} is missing")
    if path.stat().st_size != expected[0]:
        raise ValueError(f"{label} byte length mismatch")
    if sha256_file(path) != expected[1]:
        raise ValueError(f"{label} SHA-256 mismatch")


def source_identity(relative: str, size: int, digest: str) -> dict[str, object]:
    require_identity(ROOT / relative, (size, digest), relative)
    return {"name": Path(relative).name, "bytes": size, "sha256": digest}


def candidate_paths(external_root: Path) -> dict[str, Path]:
    return {
        name: external_root / str(requirement["filename"])
        for name, requirement in qualification.EXTERNAL_REQUIREMENTS.items()
        if name != "independent_review_attestation"
    }


def validate_bundle(external_root: Path, environment_report: Path) -> dict[str, object]:
    for relative, size, digest in TRACKED_INPUTS.values():
        require_identity(ROOT / relative, (size, digest), relative)
    require_identity(
        environment_report,
        CANDIDATE_REPORT_IDENTITY,
        "candidate environment report",
    )
    paths = candidate_paths(external_root)
    expected_report = qualification.build_environment_report({
        **paths,
        "independent_review_attestation": (
            external_root
            / str(
                qualification.EXTERNAL_REQUIREMENTS[
                    "independent_review_attestation"
                ]["filename"]
            )
        ),
    })
    report = json.loads(environment_report.read_text())
    if report != expected_report:
        raise ValueError("candidate environment report content mismatch")
    for name in paths:
        check = report["checks"][name]
        if (
            check.get("identity_frozen") is not True
            or check.get("schema_valid") is not True
            or check.get("verified") is not True
            or check.get("failures") != []
        ):
            raise ValueError(f"candidate artifact rejected: {name}")
    if report.get("blockers") != ["independent_review_attestation"]:
        raise ValueError("candidate blocker set mismatch")
    if report.get("proof_candidate_artifacts_verified") is not True:
        raise ValueError("candidate artifact verification not closed")
    if report.get("safe_to_request_independent_review") is not True:
        raise ValueError("independent-review handoff is not ready")
    for name in (
        "safe_to_start_cap_security_qualification",
        "safe_to_claim_cap_security_qualified",
        "safe_to_start_large_replay",
        "large_replay_started",
    ):
        if report.get(name) is not False:
            raise ValueError(f"candidate report expands {name}")

    candidate = json.loads(paths["qualification_evidence"].read_text())
    claims = candidate.get("claim_boundary", {})
    accounting = candidate.get("numeric_advantage_accounting", {})
    records = candidate.get("full_value_oracle_transcript_vectors", {})
    if (
        claims.get("v2_31_cap_proof_candidate_artifacts_authored") is not True
        or claims.get("full_value_production_oracle_vector_exported") is not True
        or claims.get("candidate_extractor_vector_verified") is not True
        or claims.get("cap_security_qualified") is not False
        or claims.get("fork_security_proof_revalidated") is not False
        or accounting.get("mixed_degree_accept_probability_without_pow")
        != "2^-182"
        or accounting.get("fork_pow_implemented") is not False
        or accounting.get("complete_total_bound_available") is not False
        or records.get("record_identity", {}).get("records") != 122_847
        or records.get("digest_only") is not False
    ):
        raise ValueError("candidate evidence claim or accounting mismatch")
    return report


def build_evidence(external_root: Path, environment_report: Path) -> dict[str, object]:
    validate_bundle(external_root, environment_report)
    external = {
        name: {
            "name": requirement["filename"],
            "bytes": requirement["bytes"],
            "sha256": requirement["sha256"],
            "identity_frozen": True,
            "verified": True,
        }
        for name, requirement in qualification.EXTERNAL_REQUIREMENTS.items()
        if name != "independent_review_attestation"
    }
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "tracked_source_identities": {
            label: source_identity(relative, size, digest)
            for label, (relative, size, digest) in TRACKED_INPUTS.items()
        },
        "external_candidate_identities": external,
        "candidate_environment_report": {
            "name": environment_report.name,
            "bytes": CANDIDATE_REPORT_IDENTITY[0],
            "sha256": CANDIDATE_REPORT_IDENTITY[1],
        },
        "production_vector": {
            "profile_fingerprint": (
                "2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38"
            ),
            "xof_calls": 122_847,
            "xof_trace_bytes": 44_236_358,
            "xof_trace_sha256": (
                "ccfa51ec2aee9501483c65023c4a877316eb6dd0557ccd6c42dfdf5f20f2c4e6"
            ),
            "full_value_record_json_bytes": 78_878_128,
            "full_value_record_json_sha256": (
                "226d6f43ed95616c636bc9f91894070830214432134f59aa6f0086f9fccc6b92"
            ),
            "negative_vectors": 10,
            "negative_vectors_rejected": 10,
            "mixed_tree_shapes": [[4096, 13], [4096, 13], *[[2048, 12] for _ in range(16)]],
            "other_tree_observed_stream_bytes_used": False,
        },
        "numeric_finding": {
            "tree_leaf_log2_sum": 200,
            "degree": 2,
            "tree_count": 18,
            "raw_degree_accept_probability_without_pow": "2^-182",
            "target_security_bits": 192,
            "source_paper_pow_bits": "13.9",
            "fork_pow_implemented": False,
            "complete_total_bound_available": False,
        },
        "blocking_findings": [
            "complete_CAP_Prove_Verify_missing",
            "candidate_c2_serialization_not_frozen",
            "NIST_III_Shorter_proof_of_work_missing",
            "raw_mixed_tree_degree_term_below_192_bits",
            "concrete_Anemoi_ROM_QROM_justification_missing",
            "independent_review_attestation_missing",
        ],
        "result": {
            "v2_31_cap_proof_candidate_artifacts_authored": True,
            "proof_candidate_artifact_identities_frozen": True,
            "proof_candidate_artifacts_verified": True,
            "safe_to_request_independent_review": True,
            "independent_review_completed": False,
            "safe_to_start_cap_security_qualification": False,
            "safe_to_claim_cap_security_qualified": False,
            "safe_to_start_large_replay": False,
            "large_replay_started": False,
        },
        "claim_boundary": {
            "candidate_extractor_vector_verified": True,
            "numeric_diagnostic_accounting_completed": True,
            "cap_straightline_extractor_implemented": False,
            "cap_straightline_extraction_reviewed": False,
            "cap_unique_witness_reviewed": False,
            "cap_security_qualified": False,
            "qrom_request_binding_reviewed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
            "system_architecture_changed": False,
            "ticket_lifecycle_changed": False,
            "pq_sat_auth_changed": False,
        },
        "next_gate": {
            "action": "independent cryptographic review and profile disposition",
            "required_attestation": (
                "pq_rbbc_cap_security_independent_review_v2_31.json"
            ),
            "exact_qualification_command": None,
            "withheld_reason": (
                "review and Prove/Verify/PoW profile dispositions do not exist"
            ),
        },
        "artifact_policy": {
            "portable_evidence_contains_absolute_paths": False,
            "external_candidate_json_tracked_in_git": False,
            "external_pdfs_tracked_in_git": False,
            "trusted_pickle_tracked_in_git": False,
            "assignment_or_br1cs_tracked_in_git": False,
            "cache_resume_or_logs_tracked_in_git": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--external-root", type=Path, required=True)
    parser.add_argument("--environment-report", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    data = canonical_json(build_evidence(args.external_root, args.environment_report))
    if args.output is None:
        print(data.decode(), end="")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    print(json.dumps({
        "output": str(args.output),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "proof_candidate_artifacts_verified": True,
        "cap_security_qualified": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
