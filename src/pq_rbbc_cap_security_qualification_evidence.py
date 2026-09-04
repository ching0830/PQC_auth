#!/usr/bin/env python3
"""Seal path-free evidence for the PQ-RBBC v2.31 CAP qualification checkpoint."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_security_qualification as qualification


IMPLEMENTATION_VERSION = "2.31"
FORMAT = "PQRBBC-CAP-SECURITY-QUALIFICATION-EVIDENCE-1"
RELATION_ID = "pq-rbbc/cap-security-qualification-evidence/v1"
ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_RELATIVE = (
    "artifacts/metadata/cap_security_qualification_v2_31/"
    "pq_rbbc_cap_security_qualification_evidence_v2_31.json"
)

CHECKER_IDENTITY = (
    30_031,
    "09162b813bd22c19dc4b16c762fde61217dbfb7c24eac06f01b8814869ce2798",
)
FROZEN_MANIFEST_IDENTITY = (
    11_778,
    "dc143238d9c22d94ace03ee37b1f4ead0b6f0b2f876c7a790fc0b644495326db",
)
INITIAL_ENVIRONMENT_REPORT_IDENTITY = (
    2_703,
    "96a3038b8e05ca277fd37d5f7b78df139172eaaa5ce21ee9b37d0a64c3d428b5",
)
FROZEN_MANIFEST_RELATIVE = (
    "manifests/pq_rbbc_cap_security_qualification_manifest_v2_31.json"
)


def canonical_json(document: Mapping[str, object]) -> bytes:
    return qualification.canonical_json(document)


def _require_identity(
    path: Path, expected: tuple[int, str], label: str
) -> None:
    if not path.is_file():
        raise ValueError(f"{label} is missing")
    if path.stat().st_size != expected[0]:
        raise ValueError(f"{label} byte length mismatch")
    if qualification._sha256(path) != expected[1]:
        raise ValueError(f"{label} SHA-256 mismatch")


def validate_checkpoint(environment_report: Path) -> None:
    _require_identity(
        ROOT / "src/pq_rbbc_cap_security_qualification.py",
        CHECKER_IDENTITY,
        "v2.31 qualification checker",
    )
    manifest_path = ROOT / FROZEN_MANIFEST_RELATIVE
    _require_identity(
        manifest_path,
        FROZEN_MANIFEST_IDENTITY,
        "v2.31 frozen qualification manifest",
    )
    if json.loads(manifest_path.read_text()) != qualification.build_frozen_manifest():
        raise ValueError("v2.31 frozen qualification manifest content mismatch")
    _require_identity(
        environment_report,
        INITIAL_ENVIRONMENT_REPORT_IDENTITY,
        "v2.31 initial environment report",
    )
    report = json.loads(environment_report.read_text())
    if report != qualification.build_environment_report({}):
        raise ValueError("v2.31 initial environment report content mismatch")
    if report.get("safe_to_author_cap_proof_artifacts") is not True:
        raise ValueError("CAP proof authoring is not safe")
    for name in (
        "safe_to_start_cap_security_qualification",
        "safe_to_claim_cap_security_qualified",
        "safe_to_start_large_replay",
        "large_replay_started",
    ):
        if report.get(name) is not False:
            raise ValueError(f"initial report expands {name}")
    if set(report.get("blockers", [])) != set(
        qualification.EXTERNAL_REQUIREMENTS
    ):
        raise ValueError("initial report blocker set mismatch")


def _identity(name: str, expected: tuple[int, str]) -> dict[str, object]:
    return {"name": name, "bytes": expected[0], "sha256": expected[1]}


def build_evidence(environment_report: Path) -> dict[str, object]:
    validate_checkpoint(environment_report)
    claims = qualification.claim_boundary()
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "source_identities": {
            "qualification_checker": _identity(
                "pq_rbbc_cap_security_qualification.py", CHECKER_IDENTITY
            ),
            "frozen_manifest": _identity(
                Path(FROZEN_MANIFEST_RELATIVE).name, FROZEN_MANIFEST_IDENTITY
            ),
            "initial_environment_report": _identity(
                "pq_rbbc_cap_security_environment_v2_31.json",
                INITIAL_ENVIRONMENT_REPORT_IDENTITY,
            ),
            "tracked_prerequisites": {
                label: {
                    "name": Path(relative).name,
                    "bytes": size,
                    "sha256": digest,
                }
                for label, (relative, size, digest) in (
                    qualification.TRACKED_INPUTS.items()
                )
            },
        },
        "frozen_contract_identities": {
            "cap_profile_fingerprint": qualification.cap.profile_fingerprint(
                qualification.cap.PRODUCTION_PARAMETERS
            ),
            "oracle_contract_sha256": qualification.document_sha256(
                qualification.oracle_contract()
            ),
            "admissible_commitment_contract_sha256": (
                qualification.document_sha256(
                    qualification.admissible_commitment_contract()
                )
            ),
            "extractor_contract_sha256": qualification.document_sha256(
                qualification.extractor_contract()
            ),
            "unique_mask_game_contract_sha256": qualification.document_sha256(
                qualification.unique_mask_game_contract()
            ),
        },
        "source_execution_semantics": {
            "v2_29_input_identity": qualification.V2_29_INPUT_IDENTITY,
            "v2_29_ordered_transcript_sha256": (
                qualification.V2_29_TRANSCRIPT_SHA256
            ),
            "v2_29_combined_rows": 589_030_555,
            "v2_29_verification_failures": 0,
            "v2_29_external_assertions": 0,
            "other_tree_observed_stream_bytes_used": False,
        },
        "checkpoint_result": {
            "qualification_contract_closed": claims[
                "v2_31_cap_security_qualification_contract_closed"
            ],
            "oracle_contract_frozen": claims["cap_oracle_contract_frozen"],
            "admissible_commitment_contract_frozen": claims[
                "cap_admissible_commitment_contract_frozen"
            ],
            "extractor_interface_frozen": claims[
                "cap_extractor_interface_frozen"
            ],
            "unique_mask_game_frozen": claims["cap_unique_mask_game_frozen"],
            "proof_candidate_identities_frozen": all(
                requirement["identity_frozen"] is True
                for name, requirement in qualification.EXTERNAL_REQUIREMENTS.items()
                if name != "independent_review_attestation"
            ),
            "safe_to_author_cap_proof_artifacts": True,
            "safe_to_start_cap_security_qualification": False,
            "safe_to_claim_cap_security_qualified": False,
            "safe_to_start_large_replay": False,
            "large_replay_started": False,
        },
        "external_blockers": [
            {
                "name": name,
                "filename": requirement["filename"],
                "identity_frozen": requirement["identity_frozen"],
                **(
                    {
                        "bytes": requirement["bytes"],
                        "sha256": requirement["sha256"],
                    }
                    if requirement["identity_frozen"] is True
                    else {}
                ),
            }
            for name, requirement in qualification.EXTERNAL_REQUIREMENTS.items()
        ],
        "next_gate": {
            "action": "obtain independent CAP cryptographic review",
            "candidate_inventory_command": (
                "PYTHONPATH=src python -u "
                "src/pq_rbbc_cap_security_qualification.py --report "
                "<external-root>/pq_rbbc_cap_security_environment_v2_31.json "
                "--extractor-specification <external-root>/"
                "pq_rbbc_cap_straightline_extractor_spec_v2_31.pdf "
                "--unique-mask-reduction <external-root>/"
                "pq_rbbc_cap_unique_committed_mask_reduction_v2_31.pdf "
                "--qualification-evidence <external-root>/"
                "pq_rbbc_cap_security_qualification_evidence_v2_31.json "
                "--independent-review-attestation <external-root>/"
                "pq_rbbc_cap_security_independent_review_v2_31.json"
            ),
            "exact_qualification_command": None,
            "withheld_reason": (
                "independent review is absent and candidate findings remain blocking"
            ),
        },
        "artifact_policy": {
            "portable_evidence_contains_absolute_paths": False,
            "large_replay_required": False,
            "br1cs_or_assignment_tracked_in_git": False,
            "trusted_pickle_cache_tracked_in_git": False,
            "checkpoint_or_resume_state_tracked_in_git": False,
            "logs_tracked_in_git": False,
        },
        "claim_boundary": claims,
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
        "sha256": qualification.document_sha256(
            json.loads(data.decode())
        ),
        "cap_security_qualified": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
