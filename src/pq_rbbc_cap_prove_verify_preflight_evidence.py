#!/usr/bin/env python3
"""Seal portable evidence for the PQ-RBBC v2.32 read-only preflight."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_prove_verify_preflight as preflight


IMPLEMENTATION_VERSION = "2.32"
FORMAT = "PQRBBC-CAP-PROVE-VERIFY-PREFLIGHT-EVIDENCE-1"
RELATION_ID = "pq-rbbc/cap-prove-verify/preflight-evidence/v1"
ROOT = Path(__file__).resolve().parents[1]

CHECKER = (
    ROOT / "src/pq_rbbc_cap_prove_verify_preflight.py",
    30_829,
    "83a79443c52fdaa6435e9c0ded7b3db0fed724b6a4af8d80134af0445b8976dd",
)
MANIFEST = (
    ROOT / "manifests/pq_rbbc_cap_prove_verify_preflight_manifest_v2_32.json",
    11_021,
    "d132dd0953a81af2f54d285d6162139880828927a659e95fb1cfbbdd927717aa",
)
INITIAL_REPORT = (
    3_340,
    "94ad30300b83b517745e317ed027daffef8fc2c1de1b2f83cd92a9d1485fac86",
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
    _require_identity(path, *INITIAL_REPORT, "v2.32 initial environment report")
    report = _read_json(path)
    if (
        report.get("format") != preflight.REPORT_FORMAT
        or report.get("implementation_version") != IMPLEMENTATION_VERSION
        or report.get("safe_to_run_read_only_preflight") is not True
        or report.get("safe_to_author_v2_32_candidate_artifacts") is not True
        or report.get("safe_to_implement_cap_prove_verify") is not False
        or report.get("safe_to_start_large_relation_replay") is not False
        or report.get("safe_to_start_large_proving_run") is not False
        or report.get("safe_to_claim_cap_security_qualified") is not False
        or report.get("large_replay_started") is not False
        or report.get("large_proving_run_started") is not False
        or report.get("exact_implementation_command") is not None
        or report.get("claim_boundary") != preflight.claim_boundary()
    ):
        raise ValueError("v2.32 report result or claim boundary mismatch")
    checks = report.get("checks", {})
    if (
        not isinstance(checks, dict)
        or checks.get("tracked_inputs")
        != {"verified": True, "failures": []}
        or set(report.get("blockers", [])) != set(preflight.EXTERNAL_REQUIREMENTS)
    ):
        raise ValueError("v2.32 report blocker set mismatch")
    for name in preflight.EXTERNAL_REQUIREMENTS:
        check = checks.get(name, {})
        if (
            not isinstance(check, dict)
            or check.get("provided") is not True
            or check.get("identity_frozen") is not False
            or check.get("schema_valid") is not False
            or check.get("verified") is not False
            or check.get("failures") != ["missing"]
        ):
            raise ValueError(f"v2.32 report {name} boundary mismatch")
    return report


def build_evidence(environment_report: Path) -> dict[str, object]:
    _require_identity(*CHECKER, "v2.32 checker")
    _require_identity(*MANIFEST, "v2.32 manifest")
    if preflight.validate_tracked_inputs():
        raise ValueError("v2.32 tracked prerequisites do not validate")
    manifest = _read_json(MANIFEST[0])
    if manifest != preflight.build_frozen_manifest():
        raise ValueError("v2.32 frozen manifest content mismatch")
    validate_initial_report(environment_report)
    claims = preflight.claim_boundary()
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
        "source_relation": manifest["source_relation"],
        "contract_identities": {
            "statement_contract_sha256": manifest["statement_contract_sha256"],
            "prove_verify_contract_sha256": manifest[
                "prove_verify_contract_sha256"
            ],
            "proof_serialization_contract_sha256": manifest[
                "proof_serialization_contract_sha256"
            ],
            "pow_security_profile_contract_sha256": manifest[
                "pow_security_profile_contract_sha256"
            ],
        },
        "frozen_requirements": {
            "logical_public_inputs": preflight.statement_contract()[
                "logical_public_inputs"
            ],
            "verify_forbidden_inputs": preflight.prove_verify_contract()["Verify"][
                "forbidden_input"
            ],
            "proof_sections": preflight.proof_serialization_contract()["sections"],
            "unfrozen_proof_payloads": preflight.proof_serialization_contract()[
                "unfrozen_payloads"
            ],
            "candidate_c2_is_production_serialization": False,
            "target_security_bits": preflight.TARGET_SECURITY_BITS,
            "raw_degree_security_bits_at_q_H_1": (
                preflight.RAW_DEGREE_SECURITY_BITS
            ),
            "paper_total_pow_bits": preflight.PAPER_TOTAL_POW_BITS,
            "simple_addition_is_complete_bound": False,
            "profile_change_authorized": False,
        },
        "external_blockers": [
            {
                "name": name,
                "filename": requirement["filename"],
                "schema": requirement["schema"],
                "identity_frozen": False,
            }
            for name, requirement in preflight.EXTERNAL_REQUIREMENTS.items()
        ],
        "result": {
            "v2_32_cap_prove_verify_preflight_closed": True,
            "safe_to_author_v2_32_candidate_artifacts": True,
            "safe_to_implement_cap_prove_verify": False,
            "safe_to_start_large_relation_replay": False,
            "safe_to_start_large_proving_run": False,
            "safe_to_claim_cap_security_qualified": False,
            "large_replay_started": False,
            "large_proving_run_started": False,
        },
        "next_gate": {
            "action": (
                "author and independently review complete Prove/Verify, "
                "serialization, and PoW/profile disposition candidates"
            ),
            "exact_candidate_inventory_command": (
                "PYTHONPATH=src python -u "
                "src/pq_rbbc_cap_prove_verify_preflight.py --report "
                "<external-root>/pq_rbbc_cap_prove_verify_environment_v2_32.json "
                "--prove-verify-specification <external-root>/"
                "pq_rbbc_cap_prove_verify_spec_v2_32.pdf "
                "--production-proof-serialization <external-root>/"
                "pq_rbbc_cap_proof_serialization_v2_32.json "
                "--pow-security-profile-disposition <external-root>/"
                "pq_rbbc_cap_pow_security_profile_disposition_v2_32.json "
                "--implementation-evidence <external-root>/"
                "pq_rbbc_cap_prove_verify_implementation_evidence_v2_32.json "
                "--independent-review-attestation <external-root>/"
                "pq_rbbc_cap_prove_verify_independent_review_v2_32.json"
            ),
            "exact_implementation_command": None,
            "withheld_reason": (
                "all five external identities and their security dispositions "
                "remain unfrozen"
            ),
        },
        "resource_estimate": manifest["preflight_resource_estimate"],
        "claim_boundary": claims,
        "artifact_policy": {
            "portable_evidence_contains_absolute_paths": False,
            "large_relation_replay_required": False,
            "large_proving_run_started": False,
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
        "safe_to_implement_cap_prove_verify": False,
        "safe_to_start_large_proving_run": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
