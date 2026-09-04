#!/usr/bin/env python3
"""Seal v2.37 statement-serialization and bounded parent-ABI evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_unified_statement_parent_abi as abi


IMPLEMENTATION_VERSION = "2.37"
FORMAT = "PQRBBC-CAP-UNIFIED-STATEMENT-PARENT-ABI-PORTABLE-EVIDENCE-1"
RELATION_ID = "pq-rbbc/cap/unified-tree/statement-parent-abi/portable-evidence/v1"
ROOT = Path(__file__).resolve().parents[1]

TRACKED = {
    "statement_parent_abi_implementation": (
        ROOT / "src/pq_rbbc_cap_unified_statement_parent_abi.py",
        36_238,
        "334b0668ec1de9370cf3e80d5d72273dca78b78ad623f6f91003c8a2664395a9",
    ),
    "statement_parent_abi_manifest": (
        ROOT / "manifests/pq_rbbc_cap_unified_statement_parent_abi_manifest_v2_37.json",
        4_300,
        "32ae1132a69a1ca97458d53a0efd66891ba2efad771967983319a75d4427ba36",
    ),
    "statement_parent_abi_tests": (
        ROOT / "tests/test_pq_rbbc_cap_unified_statement_parent_abi.py",
        7_759,
        "20717f4128ed9d6f7e82bee8b4d018503d5ac3fc0655e076ef5d978da2959ae8",
    ),
    "v2_36_portable_evidence": (
        ROOT / "artifacts/metadata/cap_unified_tree_bounded_relation_v2_36/"
        "pq_rbbc_cap_unified_tree_bounded_relation_portable_evidence_v2_36.json",
        5_719,
        "660d4c0d9cf36bbb5ecf02dc66d65721e077171de5b1e9c6b010d19871235fad",
    ),
}

PRODUCTION_VECTOR_IDENTITY = {
    "filename": abi.PRODUCTION_VECTOR_FILENAME,
    "bytes": 1_569,
    "sha256": "23f811f1eba9686d8f3fcea20a9d871160ec636c2f462073cf7064a0821c08e6",
}
BOUNDED_VECTOR_IDENTITY = {
    "filename": abi.BOUNDED_VECTOR_FILENAME,
    "bytes": 3_062,
    "sha256": "655e3969695b8015a83b1dad29f98c98b15c2f59d41c3890901bd23da62365ff",
}
RUN_EVIDENCE_IDENTITY = {
    "filename": abi.EVIDENCE_FILENAME,
    "bytes": 2_279,
    "sha256": "77f5c9c175c245233707f7c0f16377047f630633f46d2cd0a167ffb938112a78",
}
QUALIFICATION_IDENTITY = {
    "filename": abi.QUALIFICATION_FILENAME,
    "bytes": 3_163,
    "sha256": "e87d3cf29429ba5b60b1f1bd85e35c386275e7edd7902f779b910282ad840dce",
}


def canonical_json(document: object) -> bytes:
    return abi.canonical_json(document)


def _require(path: Path, expected: Mapping[str, object], label: str) -> None:
    if not path.is_file() or abi.identity(path) != expected:
        raise ValueError(f"{label} identity mismatch")


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} root must be an object")
    return document


def validate_run_evidence(document: Mapping[str, object]) -> None:
    expected_observations = {
        "statement_profiles_serialized": 2,
        "bounded_parent_envelopes_materialized": 1,
        "production_parent_envelopes_materialized": 0,
        "production_leaves_expanded": 0,
        "production_relation_rows": 0,
        "br1cs_rows": 0,
        "proofs_generated": 0,
        "other_tree_observed_stream_bytes_reused": False,
        "v2_29_transcript_reused_as_observation": False,
    }
    if (
        document.get("format") != abi.EVIDENCE_FORMAT
        or document.get("implementation_version") != IMPLEMENTATION_VERSION
        or document.get("relation_id") != abi.RELATION_ID
        or document.get("manifest") != abi.identity(abi.MANIFEST_PATH)
        or document.get("v2_36_portable_evidence") != abi.V2_36_PORTABLE_EVIDENCE
        or document.get("v2_36_checkpoint_payload")
        != abi.V2_36_CHECKPOINT_IDENTITY
        or document.get("production_statement_vector")
        != PRODUCTION_VECTOR_IDENTITY
        or document.get("bounded_parent_input_vector")
        != BOUNDED_VECTOR_IDENTITY
        or document.get("observations") != expected_observations
        or document.get("claim_boundary") != abi.claim_boundary()
    ):
        raise ValueError("v2.37 run evidence mismatch")


def validate_qualification(document: Mapping[str, object]) -> None:
    checks = document.get("checks")
    expected_result = {
        "production_profile_statement_serialization_qualified": True,
        "bounded_parent_input_abi_qualified": True,
        "ticket_mapping_qualified_on_bounded_fixture": True,
        "production_parent_input_qualified": False,
        "safe_to_author_production_streaming_path": True,
        "safe_to_start_production_prefreeze": False,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
    }
    if (
        document.get("format") != abi.QUALIFICATION_FORMAT
        or document.get("implementation_version") != IMPLEMENTATION_VERSION
        or document.get("relation_id") != abi.RELATION_ID
        or document.get("implementation")
        != abi.identity(ROOT / "src/pq_rbbc_cap_unified_statement_parent_abi.py")
        or document.get("manifest") != abi.identity(abi.MANIFEST_PATH)
        or document.get("external_inputs")
        != {"v2_36_checkpoint_payload": abi.V2_36_CHECKPOINT_IDENTITY}
        or document.get("external_outputs")
        != {
            "production_statement_vector": PRODUCTION_VECTOR_IDENTITY,
            "bounded_parent_input_vector": BOUNDED_VECTOR_IDENTITY,
            "run_evidence": RUN_EVIDENCE_IDENTITY,
        }
        or not isinstance(checks, dict)
        or len(checks) != 16
        or not all(value is True for value in checks.values())
        or document.get("result") != expected_result
        or document.get("claim_boundary") != abi.claim_boundary()
    ):
        raise ValueError("v2.37 qualification mismatch")


def build_evidence(
    checkpoint_path: Path,
    production_vector_path: Path,
    bounded_vector_path: Path,
    run_evidence_path: Path,
    qualification_path: Path,
) -> dict[str, object]:
    for label, (path, size, digest) in TRACKED.items():
        _require(
            path,
            {"filename": path.name, "bytes": size, "sha256": digest},
            label,
        )
    for path, expected, label in (
        (production_vector_path, PRODUCTION_VECTOR_IDENTITY, "production vector"),
        (bounded_vector_path, BOUNDED_VECTOR_IDENTITY, "bounded vector"),
        (run_evidence_path, RUN_EVIDENCE_IDENTITY, "run evidence"),
        (qualification_path, QUALIFICATION_IDENTITY, "qualification"),
    ):
        _require(path, expected, label)
    production = _read_json(production_vector_path)
    bounded = _read_json(bounded_vector_path)
    run_evidence = _read_json(run_evidence_path)
    qualification = _read_json(qualification_path)
    abi.validate_production_vector(production)
    c_r = abi.load_bounded_commitment(checkpoint_path)
    abi.validate_bounded_vector(bounded, c_r)
    validate_run_evidence(run_evidence)
    validate_qualification(qualification)
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "tracked_identities": {
            label: {"filename": path.name, "bytes": size, "sha256": digest}
            for label, (path, size, digest) in TRACKED.items()
        },
        "external_identities": {
            "production_statement_vector": PRODUCTION_VECTOR_IDENTITY,
            "bounded_parent_input_vector": BOUNDED_VECTOR_IDENTITY,
            "run_evidence": RUN_EVIDENCE_IDENTITY,
            "qualification": QUALIFICATION_IDENTITY,
            "v2_36_checkpoint_payload": abi.V2_36_CHECKPOINT_IDENTITY,
        },
        "bound_contracts": {
            "v2_36_portable_evidence": abi.V2_36_PORTABLE_EVIDENCE,
            "production_profile_fingerprint": abi.PRODUCTION_PROFILE_FINGERPRINT,
            "bounded_profile_fingerprint": abi.BOUNDED_PROFILE_FINGERPRINT,
            "qualification_command_sha256": abi.build_manifest()["execution_gate"][
                "qualification_command_sha256"
            ],
            "prospective_production_command_sha256": abi.build_manifest()[
                "execution_gate"
            ]["production_command_sha256"],
        },
        "qualified_observation": {
            "production_statement_bytes": production["statement_bytes"],
            "production_statement_sha256": production["statement_sha256"],
            "bounded_statement_bytes": bounded["statement_bytes"],
            "bounded_statement_sha256": bounded["statement_sha256"],
            "bounded_commitment_bytes": bounded["c_r_bytes"],
            "bounded_commitment_sha256": bounded["c_r_sha256"],
            "bounded_parent_input_bytes": bounded["parent_input_bytes"],
            "bounded_parent_input_sha256": bounded["parent_input_sha256"],
            "mutation_probes_rejected": len(qualification["checks"]),
            "production_parent_envelopes_materialized": 0,
            "production_leaves_expanded": 0,
            "production_relation_rows": 0,
            "br1cs_rows": 0,
            "proofs_generated": 0,
        },
        "qualification_result": qualification["result"],
        "static_claim_boundary": abi.claim_boundary(),
        "remaining_launch_blockers": [
            "production unified-tree checkpoint has not been materialized",
            "production parent commitment c_r is absent",
            "production streaming path has not been implemented or qualified",
            "operator resource reservation identity is not frozen",
            "independent review identity is not frozen",
            "production pre-freeze is not authorized",
        ],
        "artifact_policy": {
            "portable_evidence_contains_absolute_paths": False,
            "portable_evidence_contains_private_witness": False,
            "checkpoint_payload_or_resume_state_tracked_in_git": False,
            "legacy_18_tree_evidence_overwritten": False,
            "other_tree_observed_stream_bytes_reused": False,
            "assignment_or_br1cs_created": False,
            "pickle_cache_or_log_tracked_in_git": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint-payload", type=Path, required=True)
    parser.add_argument("--production-vector", type=Path, required=True)
    parser.add_argument("--bounded-vector", type=Path, required=True)
    parser.add_argument("--run-evidence", type=Path, required=True)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    data = canonical_json(
        build_evidence(
            args.checkpoint_payload,
            args.production_vector,
            args.bounded_vector,
            args.run_evidence,
            args.qualification,
        )
    )
    if args.output is None:
        print(data.decode(), end="")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    print(json.dumps({
        "output": str(args.output),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bounded_parent_input_abi_qualified": True,
        "production_parent_input_qualified": False,
        "safe_to_start_production_prefreeze": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
