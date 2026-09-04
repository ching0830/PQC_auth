#!/usr/bin/env python3
"""Read-only, fail-closed PQ-RBBC v2.32 CAP Prove/Verify preflight."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_anemoi_sponge as sponge
import pq_rbbc_blind_uov_abi as abi
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_security_qualification as v2_31


IMPLEMENTATION_VERSION = "2.32"
FORMAT = "PQRBBC-CAP-PROVE-VERIFY-PREFLIGHT-1"
REPORT_FORMAT = "PQRBBC-CAP-PROVE-VERIFY-ENVIRONMENT-1"
RELATION_ID = "pq-rbbc/cap-prove-verify/preflight/v1"
ROOT = Path(__file__).resolve().parents[1]
EXTERNAL_ROOT = "/tmp/pq_rbbc_external_artifacts_rebuilt/v2_32_cap_prove_verify"

PROOF_MAGIC = b"PQRBBC-CAP-PROOF-V1"
PROOF_FORMAT_VERSION = 1
TARGET_SECURITY_BITS = 192
RAW_DEGREE_SECURITY_BITS = 182
PAPER_EXPLICIT_POW_BITS = 9
PAPER_TOTAL_POW_BITS = "13.9"

TRACKED_INPUTS = {
    "v2_31_contract_evidence": (
        "artifacts/metadata/cap_security_qualification_v2_31/"
        "pq_rbbc_cap_security_qualification_evidence_v2_31.json",
        5_606,
        "6a447112809ae999d72a4c6886f353ffa1f38720870364009dc7e8155c29edfd",
    ),
    "v2_31_proof_artifact_evidence": (
        "artifacts/metadata/cap_security_qualification_v2_31/"
        "pq_rbbc_cap_security_artifact_evidence_v2_31.json",
        4_720,
        "eb5b1c901b7fd55d2092e71caadf797f8ac510ad857c8199c9f77cd5b6c544e8",
    ),
    "v2_31_frozen_manifest": (
        "manifests/pq_rbbc_cap_security_qualification_manifest_v2_31.json",
        11_778,
        "dc143238d9c22d94ace03ee37b1f4ead0b6f0b2f876c7a790fc0b644495326db",
    ),
    "v2_31_qualification_checker": (
        "src/pq_rbbc_cap_security_qualification.py",
        30_031,
        "09162b813bd22c19dc4b16c762fde61217dbfb7c24eac06f01b8814869ce2798",
    ),
    "v2_31_candidate_extractor": (
        "src/pq_rbbc_cap_straightline_extractor.py",
        22_275,
        "67d4fb74d1e5ec3d8600ac9da89fa9b04b6ef2bceba104fb75b3b4d8a9de47f6",
    ),
    "blind_uov_abi": (
        "src/pq_rbbc_blind_uov_abi.py",
        47_227,
        "575de440a2477e24e562ceb0f3049a13deff6031f3aa434609b7752b631491a2",
    ),
}

V2_31_PROFILE_FINGERPRINT = (
    "2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38"
)
V2_29_INPUT_IDENTITY = (
    "b92aa6b78d123173574ad00cb337e12877a9615f56605bddfd66236ca263d11a"
)
V2_29_TRANSCRIPT_SHA256 = (
    "1f0113f965a03351b6d62c4801a9d15d0255640282b90215397170b87ad6a514"
)

EXTERNAL_REQUIREMENTS = {
    "prove_verify_specification": {
        "filename": "pq_rbbc_cap_prove_verify_spec_v2_32.pdf",
        "purpose": "complete CAP.Prove/CAP.Verify algorithms and acceptance semantics",
        "identity_frozen": False,
        "schema": "PDF proof artifact",
    },
    "production_proof_serialization": {
        "filename": "pq_rbbc_cap_proof_serialization_v2_32.json",
        "purpose": "canonical production c_r/c_x/PoW/pi_2 byte grammar and parser vectors",
        "identity_frozen": False,
        "schema": "PQRBBC-CAP-PROOF-SERIALIZATION-CANDIDATE-1",
    },
    "pow_security_profile_disposition": {
        "filename": "pq_rbbc_cap_pow_security_profile_disposition_v2_32.json",
        "purpose": "reviewable 192-bit PoW/profile decision and complete concrete bound",
        "identity_frozen": False,
        "schema": "PQRBBC-CAP-POW-SECURITY-DISPOSITION-1",
    },
    "prove_verify_implementation_evidence": {
        "filename": "pq_rbbc_cap_prove_verify_implementation_evidence_v2_32.json",
        "purpose": "end-to-end production proof vectors, mutations, and resource measurements",
        "identity_frozen": False,
        "schema": "PQRBBC-CAP-PROVE-VERIFY-IMPLEMENTATION-EVIDENCE-1",
    },
    "independent_review_attestation": {
        "filename": "pq_rbbc_cap_prove_verify_independent_review_v2_32.json",
        "purpose": "independent review of algorithms, serialization, PoW, and security bound",
        "identity_frozen": False,
        "schema": "PQRBBC-CAP-PROVE-VERIFY-INDEPENDENT-REVIEW-1",
    },
}


def canonical_json(document: Mapping[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def document_sha256(document: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_json(document)).hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identity(path: Path, size: int, digest: str) -> bool:
    return path.is_file() and path.stat().st_size == size and _sha256(path) == digest


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} root must be an object")
    return document


def statement_contract() -> dict[str, object]:
    return {
        "logical_public_inputs": [
            "common parameters",
            "ctx",
            "sid",
            "rid",
            "y",
        ],
        "request_fields_excluding_proof": ["y"],
        "y_bytes": abi.TARGET_BYTES,
        "request_hash_bits": sponge.REQUEST_HASH_BITS,
        "complete_statement_canonical_encoding_required": True,
        "complete_statement_canonical_encoding_available": False,
        "statement_must_not_be_inferred_from_witness": True,
        "proof_must_bind_exact_statement_bytes": True,
    }


def prove_verify_contract() -> dict[str, object]:
    return {
        "Prove": {
            "input": [
                "canonical public statement",
                "private witness satisfying the frozen 589030555-row relation",
                "fresh cryptographic prover randomness",
            ],
            "output": ["canonical production proof bytes"],
            "deterministic_frozen_randomness_is_security_evidence": False,
        },
        "Verify": {
            "input": ["canonical public statement", "canonical production proof bytes"],
            "forbidden_input": ["private witness", "prover randomness", "oracle secret state"],
            "output": ["accept", "reject"],
            "must_reject_noncanonical_proof_before_algebraic_acceptance": True,
        },
        "acceptance_sequence": [
            "parse the complete proof and reject trailing or ambiguous bytes",
            "bind the exact public statement and production profile",
            "recompute every Fiat-Shamir challenge with frozen domain separation",
            "verify the selected proof-of-work rule before accepting openings",
            "verify c_r, c_x, pi_2, all openings, and the degree-2 relation",
            "accept only if every check succeeds",
        ],
        "relation_rows": 589_030_555,
        "relation_verification_failures": 0,
        "relation_external_assertions": 0,
        "v2_29_input_identity": V2_29_INPUT_IDENTITY,
        "v2_29_transcript_sha256": V2_29_TRANSCRIPT_SHA256,
        "implementation_present": False,
    }


def proof_serialization_contract() -> dict[str, object]:
    return {
        "envelope_magic_hex": PROOF_MAGIC.hex(),
        "envelope_version": PROOF_FORMAT_VERSION,
        "integer_encoding": "unsigned little-endian",
        "envelope_grammar": (
            "magic || u16le(version) || profile_fingerprint[32] || "
            "u16le(section_count) || repeated(u16le(section_id) || "
            "u64le(payload_bytes) || payload)"
        ),
        "profile_fingerprint": V2_31_PROFILE_FINGERPRINT,
        "section_count": 4,
        "sections": [
            {"section_id": 1, "name": "c_r", "bytes": 5_391},
            {"section_id": 2, "name": "c_x", "bytes": None},
            {"section_id": 3, "name": "pow_nonce", "bytes": None},
            {"section_id": 4, "name": "pi_2", "bytes": None},
        ],
        "section_order_is_canonical": True,
        "duplicate_or_unknown_sections_rejected": True,
        "trailing_bytes_rejected": True,
        "unused_high_bits_rejected": True,
        "statement_embedded_in_proof": False,
        "statement_bound_by_fiat_shamir_transcript": True,
        "candidate_c2_magic_hex": "5051524242432d4341502d415050454e442d43414e4449444154452d5631",
        "candidate_c2_bytes": 252,
        "candidate_c2_is_production_serialization": False,
        "unfrozen_payloads": ["c_x", "pow_nonce", "pi_2"],
        "production_serialization_complete": False,
    }


def pow_security_profile_contract() -> dict[str, object]:
    return {
        "target_security_bits": TARGET_SECURITY_BITS,
        "baseline_without_pow": {
            "tree_leaf_log2_sum": 200,
            "degree": 2,
            "raw_degree_security_bits_at_q_H_1": RAW_DEGREE_SECURITY_BITS,
            "target_met": False,
        },
        "source_paper_profile": {
            "parameter_set": "NIST III Shorter",
            "explicit_pow_bits": PAPER_EXPLICIT_POW_BITS,
            "total_pow_bits": PAPER_TOTAL_POW_BITS,
            "automatically_inherited_by_fork": False,
        },
        "current_fork": {
            "pow_implemented": False,
            "complete_cap_prove_verify_present": False,
            "complete_rom_bound_available": False,
            "complete_qrom_bound_available": False,
        },
        "permitted_disposition_kinds": [
            "implement_and_validate_paper_compatible_pow",
            "replace_tree_or_degree_profile_and_rebuild_relation",
            "change_security_target_only_with_explicit_project_authorization",
        ],
        "no_disposition_selected_by_preflight": True,
        "simple_addition_of_13_9_bits_is_a_complete_bound": False,
        "required_bound_terms": [
            "degree-test acceptance",
            "hidden-leaf probability",
            "oracle collision and guessing",
            "constraint-sampling soundness",
            "proof-of-work grinding and challenge sampling",
            "multi-target and adaptive-session loss",
            "concrete Anemoi ROM justification",
            "QROM measurement and programming loss",
        ],
        "required_query_budgets_log2": [0, 32, 64, 128],
        "profile_change_invalidates_current_production_shape": True,
        "profile_change_requires_new_namespace_and_replay": True,
        "profile_change_authorized_by_this_preflight": False,
    }


def serialization_candidate_schema() -> dict[str, object]:
    return {
        "format": "PQRBBC-CAP-PROOF-SERIALIZATION-CANDIDATE-1",
        "required_exact_fields": {
            "relation_id": RELATION_ID,
            "statement_contract_sha256": document_sha256(statement_contract()),
            "prove_verify_contract_sha256": document_sha256(prove_verify_contract()),
            "proof_serialization_contract_sha256": document_sha256(
                proof_serialization_contract()
            ),
            "profile_fingerprint": V2_31_PROFILE_FINGERPRINT,
        },
        "required_sections": [
            "field_layout",
            "canonical_parser",
            "fiat_shamir_binding",
            "positive_vectors",
            "negative_vectors",
            "claim_boundary",
        ],
        "required_negative_vectors": [
            "wrong_magic",
            "wrong_version",
            "wrong_profile_fingerprint",
            "reordered_section",
            "duplicate_section",
            "unknown_section",
            "truncated_payload",
            "oversized_payload",
            "trailing_bytes",
            "noncanonical_unused_high_bits",
            "candidate_c2_used_as_production_c_x",
            "changed_statement",
        ],
    }


def pow_disposition_schema() -> dict[str, object]:
    return {
        "format": "PQRBBC-CAP-POW-SECURITY-DISPOSITION-1",
        "required_exact_fields": {
            "relation_id": RELATION_ID,
            "pow_security_profile_contract_sha256": document_sha256(
                pow_security_profile_contract()
            ),
            "target_security_bits": TARGET_SECURITY_BITS,
            "raw_degree_security_bits": RAW_DEGREE_SECURITY_BITS,
        },
        "required_sections": [
            "selected_disposition",
            "parameter_delta",
            "complete_concrete_bound",
            "query_budget_analysis",
            "rom_qrom_scope",
            "implementation_impact",
            "independent_review_binding",
            "claim_boundary",
        ],
        "claim_promotion_requires_complete_bound": True,
        "claim_promotion_requires_independent_review": True,
    }


def implementation_evidence_schema() -> dict[str, object]:
    return {
        "format": "PQRBBC-CAP-PROVE-VERIFY-IMPLEMENTATION-EVIDENCE-1",
        "required_exact_fields": {
            "relation_id": RELATION_ID,
            "profile_fingerprint": V2_31_PROFILE_FINGERPRINT,
            "relation_rows": 589_030_555,
            "relation_transcript_sha256": V2_29_TRANSCRIPT_SHA256,
        },
        "required_sections": [
            "source_identities",
            "prove_vectors",
            "verify_vectors",
            "serialization_vectors",
            "pow_vectors",
            "mutation_vectors",
            "resource_measurements",
            "claim_boundary",
        ],
        "required_mutations": [
            "changed_statement_ctx",
            "changed_statement_sid",
            "changed_statement_rid",
            "changed_statement_y",
            "changed_c_r",
            "changed_c_x",
            "changed_pow_nonce",
            "changed_pi_2",
            "changed_fiat_shamir_challenge",
            "noncanonical_proof",
        ],
    }


def claim_boundary() -> dict[str, bool]:
    ready = not validate_tracked_inputs()
    return {
        "v2_32_cap_prove_verify_preflight_closed": ready,
        "cap_prove_verify_interface_requirements_frozen": ready,
        "production_proof_envelope_requirements_frozen": ready,
        "pow_security_profile_disposition_requirements_frozen": ready,
        "complete_statement_serialization_frozen": False,
        "production_proof_serialization_frozen": False,
        "cap_prove_implemented": False,
        "cap_verify_implemented": False,
        "fork_pow_implemented": False,
        "complete_concrete_security_bound_available": False,
        "cap_security_qualified": False,
        "fork_security_proof_revalidated": False,
        "production_closed": False,
        "system_architecture_changed": False,
        "ticket_lifecycle_changed": False,
        "pq_sat_auth_changed": False,
    }


def validate_tracked_inputs() -> tuple[str, ...]:
    failures: list[str] = []
    for label, (relative, size, digest) in TRACKED_INPUTS.items():
        if not _identity(ROOT / relative, size, digest):
            failures.append(f"{label}_identity")
    if failures:
        return tuple(failures)

    manifest = _read_json(ROOT / TRACKED_INPUTS["v2_31_frozen_manifest"][0])
    if manifest != v2_31.build_frozen_manifest():
        failures.append("v2_31_manifest_content")
    source_semantics = manifest.get("source_execution_semantics", {})
    if (
        not isinstance(source_semantics, dict)
        or source_semantics.get("v2_29_combined_rows") != 589_030_555
        or source_semantics.get("v2_29_verification_failures") != 0
        or source_semantics.get("v2_29_external_assertions") != 0
        or source_semantics.get("v2_29_input_identity") != V2_29_INPUT_IDENTITY
        or source_semantics.get("v2_29_ordered_transcript_sha256")
        != V2_29_TRANSCRIPT_SHA256
        or source_semantics.get("other_tree_observed_stream_bytes_used") is not False
    ):
        failures.append("v2_31_source_execution_semantics")

    artifact_evidence = _read_json(
        ROOT / TRACKED_INPUTS["v2_31_proof_artifact_evidence"][0]
    )
    result = artifact_evidence.get("result", {})
    numeric = artifact_evidence.get("numeric_finding", {})
    blocking = artifact_evidence.get("blocking_findings", [])
    if (
        not isinstance(result, dict)
        or result.get("proof_candidate_artifacts_verified") is not True
        or result.get("safe_to_request_independent_review") is not True
        or result.get("safe_to_start_cap_security_qualification") is not False
        or result.get("safe_to_claim_cap_security_qualified") is not False
        or not isinstance(numeric, dict)
        or numeric.get("raw_degree_accept_probability_without_pow") != "2^-182"
        or numeric.get("target_security_bits") != TARGET_SECURITY_BITS
        or numeric.get("fork_pow_implemented") is not False
    ):
        failures.append("v2_31_proof_artifact_result")
    for blocker in (
        "complete_CAP_Prove_Verify_missing",
        "candidate_c2_serialization_not_frozen",
        "NIST_III_Shorter_proof_of_work_missing",
        "raw_mixed_tree_degree_term_below_192_bits",
        "concrete_Anemoi_ROM_QROM_justification_missing",
        "independent_review_attestation_missing",
    ):
        if blocker not in blocking:
            failures.append(f"v2_31_missing_blocker:{blocker}")

    contract_evidence = _read_json(ROOT / TRACKED_INPUTS["v2_31_contract_evidence"][0])
    contract_result = contract_evidence.get("checkpoint_result", {})
    if (
        not isinstance(contract_result, dict)
        or contract_result.get("safe_to_author_cap_proof_artifacts") is not True
        or contract_result.get("safe_to_start_cap_security_qualification") is not False
        or contract_result.get("safe_to_start_large_replay") is not False
    ):
        failures.append("v2_31_contract_result")

    if (
        cap.profile_fingerprint(cap.PRODUCTION_PARAMETERS)
        != V2_31_PROFILE_FINGERPRINT
        or cap.commitment_bytes(cap.PRODUCTION_PARAMETERS) != 5_391
        or abi.TARGET_BYTES != 72
        or sponge.REQUEST_HASH_BITS != 576
    ):
        failures.append("production_profile_semantics")
    return tuple(failures)


def build_frozen_manifest() -> dict[str, object]:
    failures = list(validate_tracked_inputs())
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "tracked_prerequisites": {
            label: {"path": relative, "bytes": size, "sha256": digest}
            for label, (relative, size, digest) in TRACKED_INPUTS.items()
        },
        "tracked_validation_failures": failures,
        "source_relation": {
            "rows": 589_030_555,
            "verification_failures": 0,
            "external_assertions": 0,
            "v2_29_input_identity": V2_29_INPUT_IDENTITY,
            "v2_29_transcript_sha256": V2_29_TRANSCRIPT_SHA256,
            "profile_fingerprint": V2_31_PROFILE_FINGERPRINT,
            "other_tree_observed_stream_bytes_used": False,
        },
        "statement_contract": statement_contract(),
        "statement_contract_sha256": document_sha256(statement_contract()),
        "prove_verify_contract": prove_verify_contract(),
        "prove_verify_contract_sha256": document_sha256(prove_verify_contract()),
        "proof_serialization_contract": proof_serialization_contract(),
        "proof_serialization_contract_sha256": document_sha256(
            proof_serialization_contract()
        ),
        "pow_security_profile_contract": pow_security_profile_contract(),
        "pow_security_profile_contract_sha256": document_sha256(
            pow_security_profile_contract()
        ),
        "candidate_schemas": {
            "production_proof_serialization": serialization_candidate_schema(),
            "pow_security_profile_disposition": pow_disposition_schema(),
            "prove_verify_implementation_evidence": implementation_evidence_schema(),
        },
        "required_external_artifacts": EXTERNAL_REQUIREMENTS,
        "preflight_resource_estimate": {
            "cpu_cores": 1,
            "peak_memory_mib_upper_bound": 256,
            "elapsed_seconds_upper_bound": 60,
            "relation_rows_replayed": 0,
            "proofs_generated": 0,
        },
        "execution_policy": {
            "read_only_preflight": True,
            "large_relation_replay_required": False,
            "large_relation_replay_permitted": False,
            "large_proving_run_permitted": False,
            "profile_change_permitted": False,
            "external_candidate_directory": EXTERNAL_ROOT,
        },
        "claim_boundary": claim_boundary(),
    }


def _json_schema_for(expected_format: str) -> dict[str, object] | None:
    for schema in (
        serialization_candidate_schema(),
        pow_disposition_schema(),
        implementation_evidence_schema(),
    ):
        if schema["format"] == expected_format:
            return schema
    return None


def _validate_json_candidate(
    path: Path, expected_format: str
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    try:
        document = _read_json(path)
    except (OSError, ValueError, json.JSONDecodeError):
        return False, ["invalid_json"]
    if document.get("format") != expected_format:
        failures.append("format")
    if document.get("implementation_version") != IMPLEMENTATION_VERSION:
        failures.append("implementation_version")

    schema = _json_schema_for(expected_format)
    if schema is not None:
        exact_fields = schema.get("required_exact_fields", {})
        if isinstance(exact_fields, dict):
            for name, value in exact_fields.items():
                if document.get(name) != value:
                    failures.append(f"exact_field:{name}")
        for section in schema.get("required_sections", []):
            if section not in document:
                failures.append(f"missing_section:{section}")
        if expected_format == serialization_candidate_schema()["format"]:
            negatives = document.get("negative_vectors", [])
            expected = set(serialization_candidate_schema()["required_negative_vectors"])
            if (
                not isinstance(negatives, list)
                or {item.get("id") for item in negatives if isinstance(item, dict)}
                != expected
                or any(
                    not isinstance(item, dict) or item.get("rejected") is not True
                    for item in negatives
                )
            ):
                failures.append("negative_vectors")
            claims = document.get("claim_boundary", {})
            if (
                not isinstance(claims, dict)
                or claims.get("candidate_c2_used_as_production_c_x") is not False
                or claims.get("production_proof_serialization_frozen") is not False
            ):
                failures.append("serialization_claim_boundary")
        elif expected_format == pow_disposition_schema()["format"]:
            disposition = document.get("selected_disposition")
            if (
                not isinstance(disposition, dict)
                or disposition.get("kind")
                not in pow_security_profile_contract()["permitted_disposition_kinds"]
            ):
                failures.append("selected_disposition")
            claims = document.get("claim_boundary", {})
            if (
                not isinstance(claims, dict)
                or claims.get("cap_security_qualified") is not False
                or claims.get("independent_review_completed") is not False
            ):
                failures.append("pow_claim_boundary")
        elif expected_format == implementation_evidence_schema()["format"]:
            mutations = document.get("mutation_vectors", [])
            expected = set(implementation_evidence_schema()["required_mutations"])
            if (
                not isinstance(mutations, list)
                or {item.get("id") for item in mutations if isinstance(item, dict)}
                != expected
                or any(
                    not isinstance(item, dict) or item.get("rejected") is not True
                    for item in mutations
                )
            ):
                failures.append("mutation_vectors")
    elif expected_format == "PQRBBC-CAP-PROVE-VERIFY-INDEPENDENT-REVIEW-1":
        for field in (
            "reviewer_identity",
            "independence_statement",
            "review_date",
            "reviewed_artifact_identities",
            "algorithm_findings",
            "serialization_findings",
            "pow_security_findings",
            "dispositions",
            "claim_promotion_authorized",
        ):
            if field not in document:
                failures.append(f"missing_field:{field}")
    return not failures, failures


def _candidate_identity(
    path: Path | None, requirement: Mapping[str, object]
) -> dict[str, object]:
    identity_frozen = requirement.get("identity_frozen") is True
    if path is None:
        return {
            "provided": False,
            "identity_frozen": identity_frozen,
            "schema_valid": False,
            "verified": False,
            "failures": ["not_provided"],
        }
    if not path.is_file():
        return {
            "provided": True,
            "identity_frozen": identity_frozen,
            "schema_valid": False,
            "verified": False,
            "failures": ["missing"],
        }
    schema_valid = True
    schema_failures: list[str] = []
    schema = str(requirement["schema"])
    if schema == "PDF proof artifact":
        with path.open("rb") as stream:
            if stream.read(5) != b"%PDF-":
                schema_valid = False
                schema_failures.append("pdf_header")
    else:
        schema_valid, schema_failures = _validate_json_candidate(path, schema)
    size = path.stat().st_size
    digest = _sha256(path)
    failures: list[str] = []
    if identity_frozen:
        if size != requirement.get("bytes"):
            failures.append("byte_length_mismatch")
        if digest != requirement.get("sha256"):
            failures.append("sha256_mismatch")
    else:
        failures.append("identity_not_frozen")
    if not schema_valid:
        failures.append("schema_invalid")
    return {
        "provided": True,
        "identity_frozen": identity_frozen,
        "schema_valid": schema_valid,
        "schema_failures": schema_failures,
        "verified": identity_frozen and schema_valid and not failures,
        "bytes": size,
        "sha256": digest,
        "failures": failures,
    }


def exact_candidate_inventory_command() -> str:
    options = {
        "prove_verify_specification": "--prove-verify-specification",
        "production_proof_serialization": "--production-proof-serialization",
        "pow_security_profile_disposition": "--pow-security-profile-disposition",
        "prove_verify_implementation_evidence": "--implementation-evidence",
        "independent_review_attestation": "--independent-review-attestation",
    }
    parts = [
        "PYTHONPATH=src python -u src/pq_rbbc_cap_prove_verify_preflight.py",
        f"  --report {EXTERNAL_ROOT}/pq_rbbc_cap_prove_verify_environment_v2_32.json",
    ]
    for name, requirement in EXTERNAL_REQUIREMENTS.items():
        parts.append(f"  {options[name]} {EXTERNAL_ROOT}/{requirement['filename']}")
    return " \\\n".join(parts)


def build_environment_report(
    candidates: Mapping[str, Path | None]
) -> dict[str, object]:
    tracked_failures = list(validate_tracked_inputs())
    checks: dict[str, dict[str, object]] = {
        "tracked_inputs": {
            "verified": not tracked_failures,
            "failures": tracked_failures,
        }
    }
    for name, requirement in EXTERNAL_REQUIREMENTS.items():
        checks[name] = _candidate_identity(candidates.get(name), requirement)
    blockers = [name for name, check in checks.items() if check["verified"] is not True]
    return {
        "format": REPORT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "checks": checks,
        "blockers": blockers,
        "safe_to_run_read_only_preflight": checks["tracked_inputs"]["verified"],
        "safe_to_author_v2_32_candidate_artifacts": checks["tracked_inputs"]["verified"],
        "safe_to_implement_cap_prove_verify": False,
        "safe_to_start_large_relation_replay": False,
        "safe_to_start_large_proving_run": False,
        "safe_to_claim_cap_security_qualified": False,
        "large_replay_started": False,
        "large_proving_run_started": False,
        "exact_candidate_inventory_command": exact_candidate_inventory_command(),
        "exact_implementation_command": None,
        "exact_implementation_command_withheld_reason": (
            "production serialization, PoW/profile disposition, implementation "
            "evidence, and independent review identities are not frozen"
        ),
        "resource_estimate": build_frozen_manifest()["preflight_resource_estimate"],
        "claim_boundary": claim_boundary(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print-frozen", action="store_true")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--prove-verify-specification", type=Path)
    parser.add_argument("--production-proof-serialization", type=Path)
    parser.add_argument("--pow-security-profile-disposition", type=Path)
    parser.add_argument("--implementation-evidence", type=Path)
    parser.add_argument("--independent-review-attestation", type=Path)
    args = parser.parse_args()
    if args.print_frozen:
        print(canonical_json(build_frozen_manifest()).decode(), end="")
        return
    if args.report is None:
        parser.error("--report or --print-frozen is required")
    report = build_environment_report({
        "prove_verify_specification": args.prove_verify_specification,
        "production_proof_serialization": args.production_proof_serialization,
        "pow_security_profile_disposition": args.pow_security_profile_disposition,
        "prove_verify_implementation_evidence": args.implementation_evidence,
        "independent_review_attestation": args.independent_review_attestation,
    })
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_bytes(canonical_json(report))
    print(json.dumps({
        "report": str(args.report),
        "safe_to_run_read_only_preflight": report["safe_to_run_read_only_preflight"],
        "safe_to_implement_cap_prove_verify": report[
            "safe_to_implement_cap_prove_verify"
        ],
        "safe_to_start_large_relation_replay": report[
            "safe_to_start_large_relation_replay"
        ],
        "safe_to_start_large_proving_run": report[
            "safe_to_start_large_proving_run"
        ],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
