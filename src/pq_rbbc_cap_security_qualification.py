#!/usr/bin/env python3
"""Fail-closed PQ-RBBC v2.31 CAP-security qualification checkpoint."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_anemoi_sponge as sponge
import pq_rbbc_cap_commit as cap


IMPLEMENTATION_VERSION = "2.31"
FORMAT = "PQRBBC-CAP-SECURITY-QUALIFICATION-CHECKPOINT-1"
REPORT_FORMAT = "PQRBBC-CAP-SECURITY-QUALIFICATION-ENVIRONMENT-1"
RELATION_ID = "pq-rbbc/cap-security-qualification/v1"
ROOT = Path(__file__).resolve().parents[1]
EXTERNAL_ROOT = "/tmp/pq_rbbc_external_artifacts_rebuilt/v2_31_cap_security"

TRACKED_INPUTS = {
    "v2_30_fork_security_audit_evidence": (
        "artifacts/metadata/fork_security_audit_v2_30/"
        "pq_rbbc_fork_security_audit_evidence_v2_30.json",
        4_491,
        "ab82fe91e2e71cbfdf90bc171b0e62f6be6021365f0870e5878edd8a8496de60",
    ),
    "v2_29_parent_join_evidence": (
        "artifacts/metadata/parent_join_recovery_v2_29/"
        "pq_rbbc_parent_join_recovery_evidence_v2_29.json",
        5_695,
        "1281afaee1d5d784390ee51c96c66ecc7f486ef4b4b7933590826a708f81b20e",
    ),
    "v2_28_aggregate_evidence": (
        "artifacts/metadata/aggregate_recovery_v2_28/"
        "pq_rbbc_cap_aggregate_recovery_evidence_v2_28.json",
        8_332,
        "820bc4e7b9e6e4e9c41153b48088089a6f15181a5bc3f99c60e37fe242d4f2a1",
    ),
    "cap_commit_source": (
        "src/pq_rbbc_cap_commit.py",
        32_526,
        "be3a2a767561f009acc2a274a85410ae6e02e23abd24145aa1d61883dd2dceee",
    ),
    "cap_composer_source": (
        "src/pq_rbbc_cap_composer.py",
        40_011,
        "5f7ee914329ee6c73a5b7e22abb9fa93cf15998874435c5a32e590eae5425351",
    ),
    "cap_global_tail_source": (
        "src/pq_rbbc_cap_global_tail.py",
        53_133,
        "09d6806a50412c8a6e2e9fcca9c1111305f597e069c4b20057529dd38351a3dd",
    ),
    "anemoi_sponge_source": (
        "src/pq_rbbc_anemoi_sponge.py",
        25_336,
        "6d4e604cd937357cd76f9c127fa9fe94392bbc89b1a0b7972196545ab36424ec",
    ),
}

V2_29_INPUT_IDENTITY = (
    "b92aa6b78d123173574ad00cb337e12877a9615f56605bddfd66236ca263d11a"
)
V2_29_TRANSCRIPT_SHA256 = (
    "1f0113f965a03351b6d62c4801a9d15d0255640282b90215397170b87ad6a514"
)
V2_28_TRANSCRIPT_SHA256 = (
    "4cc7215db0d009c26bf3bc8576a984f3bb884528855a8084305ffd0499b7e134"
)

EXTERNAL_REQUIREMENTS = {
    "extractor_specification": {
        "filename": "pq_rbbc_cap_straightline_extractor_spec_v2_31.pdf",
        "purpose": "Definition-10 fork extractor algorithm and ROM transcript model",
        "identity_frozen": True,
        "bytes": 114_907,
        "sha256": "b588f351600161a6c87623b66a39c5f7bfb0e96580a0adff96f8298f1d7baa15",
        "schema": "PDF proof artifact",
    },
    "unique_mask_reduction": {
        "filename": "pq_rbbc_cap_unique_committed_mask_reduction_v2_31.pdf",
        "purpose": "unique-mask game, reduction, bad events, and advantage loss",
        "identity_frozen": True,
        "bytes": 100_724,
        "sha256": "fa94bd262e58cbd5c1218d07d4839a242177537109847e5d63737932e781e370",
        "schema": "PDF proof artifact",
    },
    "qualification_evidence": {
        "filename": "pq_rbbc_cap_security_qualification_evidence_v2_31.json",
        "purpose": "contract-bound extractor vectors and quantitative error accounting",
        "identity_frozen": True,
        "bytes": 78_898_232,
        "sha256": "2009503887da006dd4492baf27c48cc85387fc13a909ef0a75c0bab12418a47d",
        "schema": "PQRBBC-CAP-SECURITY-QUALIFICATION-CANDIDATE-1",
    },
    "independent_review_attestation": {
        "filename": "pq_rbbc_cap_security_independent_review_v2_31.json",
        "purpose": "independent reviewer identity, findings, dispositions, and all digests",
        "identity_frozen": False,
        "schema": "PQRBBC-CAP-SECURITY-INDEPENDENT-REVIEW-1",
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
    return (
        path.is_file()
        and path.stat().st_size == size
        and _sha256(path) == digest
    )


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} root must be an object")
    return document


def validate_tracked_inputs() -> tuple[str, ...]:
    failures: list[str] = []
    for label, (relative, size, digest) in TRACKED_INPUTS.items():
        if not _identity(ROOT / relative, size, digest):
            failures.append(f"{label}_identity")
    if failures:
        return tuple(failures)

    v2_30 = _read_json(ROOT / TRACKED_INPUTS["v2_30_fork_security_audit_evidence"][0])
    audit_result = v2_30.get("audit_result", {})
    audit_claims = v2_30.get("claim_boundary", {})
    audit_blockers = v2_30.get("blocking_findings", [])
    if (
        v2_30.get("implementation_version") != "2.30"
        or v2_30.get("relation_id") != "pq-rbbc/fork-security/audit-evidence/v1"
    ):
        failures.append("v2_30_audit_contract")
    if not isinstance(audit_result, dict) or (
        audit_result.get("bounded_internal_gap_analysis_completed") is not True
        or audit_result.get("packet_ready_for_independent_review") is not True
        or audit_result.get("independent_review_completed") is not False
        or audit_result.get("security_claim_promotion_permitted") is not False
    ):
        failures.append("v2_30_audit_result")
    for name in (
        "cap_unique_witness_reviewed",
        "cap_straightline_extraction_reviewed",
        "fork_security_proof_revalidated",
        "production_closed",
    ):
        if not isinstance(audit_claims, dict) or audit_claims.get(name) is not False:
            failures.append(f"v2_30_{name}_boundary")
    for blocker in (
        "cap_unique_committed_mask_not_revalidated",
        "cap_straightline_extraction_not_revalidated",
        "independent_review_attestation_missing",
    ):
        if blocker not in audit_blockers:
            failures.append(f"v2_30_missing_blocker:{blocker}")

    v2_29 = _read_json(ROOT / TRACKED_INPUTS["v2_29_parent_join_evidence"][0])
    v2_29_claims = v2_29.get("claim_boundary", {})
    accounting = v2_29.get("accounting", {})
    if (
        v2_29.get("implementation_version") != "2.29"
        or not isinstance(v2_29_claims, dict)
        or v2_29_claims.get("parent_cap_to_h_rbbc_join_closed") is not True
        or v2_29_claims.get("fork_security_proof_revalidated") is not False
        or not isinstance(accounting, dict)
        or accounting.get("combined_rows") != 589_030_555
        or accounting.get("verification_failures") != 0
        or accounting.get("external_assertions") != 0
        or accounting.get("ordered_replay_transcript_sha256")
        != V2_29_TRANSCRIPT_SHA256
    ):
        failures.append("v2_29_execution_semantics")

    v2_28 = _read_json(ROOT / TRACKED_INPUTS["v2_28_aggregate_evidence"][0])
    aggregate_replay = v2_28.get("aggregate_replay", {})
    if (
        v2_28.get("implementation_version") != "2.28"
        or not isinstance(aggregate_replay, dict)
        or aggregate_replay.get("ordered_replay_transcript_sha256")
        != V2_28_TRANSCRIPT_SHA256
        or aggregate_replay.get("verification_failures") != 0
        or aggregate_replay.get("rows_replayed") != 586_057_567
    ):
        failures.append("v2_28_aggregate_semantics")

    profile = cap.profile_dict(cap.PRODUCTION_PARAMETERS)
    accounting_now = cap.production_accounting(cap.PRODUCTION_PARAMETERS)
    if cap.profile_fingerprint(cap.PRODUCTION_PARAMETERS) != (
        "2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38"
    ):
        failures.append("cap_profile_fingerprint")
    if (
        profile.get("relation_id") != "pq-rbbc/cap/tcith-iii/anemoi-193-336/v1"
        or profile.get("tree_specs")
        != [{"count": 2, "leaves": 4096}, {"count": 16, "leaves": 2048}]
        or profile.get("tree_extension_degrees") != [13, 13] + [12] * 16
        or profile.get("witness_bits") != 2048
        or profile.get("mask_bits") != 576
        or profile.get("appended_signature_bits") != 1472
        or profile.get("consistency_bits") != 386
        or profile.get("random_polynomial_bits") != 2450
        or accounting_now.get("total_xof_calls") != 122_847
        or accounting_now.get("commitment_bytes") != 5_391
    ):
        failures.append("cap_profile_semantics")
    return tuple(failures)


def oracle_contract() -> dict[str, object]:
    output_bits = {
        "seed_derive": 2 * cap.SEED_BITS,
        "seed_commit": cap.HASH_BITS,
        "tape_expand": cap.PRODUCTION_PARAMETERS.random_polynomial_bits,
        "h1": cap.HASH_BITS,
        "consistency_points": cap.PRODUCTION_PARAMETERS.consistency_bits,
        "h2": cap.HASH_BITS,
    }
    domains = cap.profile_dict(cap.PRODUCTION_PARAMETERS)["domains"]
    return {
        "model": "paper Definition 10 ROM query-response transcript",
        "quantum_transcript_extractor_claimed": False,
        "ordered_query_record": [
            "sequence_index",
            "domain_id",
            "canonical_encoded_input",
            "output_bits",
            "canonical_output",
        ],
        "full_values_required_for_extractor_vectors": True,
        "digest_only_transcript_is_sufficient_for_extraction": False,
        "domain_separation": [
            {
                "id": name,
                "domain_hex": domains[name],
                "output_bits": output_bits[name],
            }
            for name in (
                "seed_derive",
                "seed_commit",
                "tape_expand",
                "h1",
                "consistency_points",
                "h2",
            )
        ],
        "frame_magic_hex": sponge.FRAME_MAGIC.hex(),
        "frame_rule": (
            "magic || u16le(domain_bytes) || domain || u64le(payload_bytes) "
            "|| payload || pad10*1"
        ),
        "transcript_magic_hex": sponge.TRANSCRIPT_MAGIC.hex(),
        "tuple_encoding": (
            "magic || u16le(field_count) || repeated(u64le(field_bytes) || field)"
        ),
        "request_binding_domain_hex": sponge.REQUEST_BINDING_DOMAIN.hex(),
        "request_binding_oracle_is_part_of_cap_extractor_transcript": False,
        "domain_aliasing_permitted": False,
    }


def admissible_commitment_contract() -> dict[str, object]:
    parameters = cap.PRODUCTION_PARAMETERS
    return {
        "commitment_relation_id": cap.PROFILE_RELATION_ID,
        "profile_fingerprint": cap.profile_fingerprint(parameters),
        "canonical_bytes": cap.commitment_bytes(parameters),
        "commitment_magic_hex": cap.COMMITMENT_MAGIC.hex(),
        "strict_parser_required": True,
        "noncanonical_unused_high_bits_rejected": True,
        "tree_count": parameters.tree_count,
        "tree_specs": [
            {"count": 2, "leaves": 4096, "extension_degree": 13},
            {"count": 16, "leaves": 2048, "extension_degree": 12},
        ],
        "witness_sequence": [
            {"prefix": 1, "value": "r", "bits": 576},
            {"prefix": 2, "value": "x", "bits": 1472},
        ],
        "admissible_if": (
            "the commitment prefix can be extended to an accepting final CAP "
            "proof for the frozen degree-2 relation"
        ),
        "current_repository_has_complete_cap_verify": False,
        "functional_assignment_satisfaction_implies_admissibility": False,
        "deterministic_frozen_randomness_is_security_evidence": False,
    }


def extractor_contract() -> dict[str, object]:
    return {
        "paper_anchor": "ePrint 2025/895 Definition 10 and Remarks 2-3",
        "model": "ROM",
        "algorithm_family": ["Ext_1", "Ext_2"],
        "input": [
            "ordered full-value oracle query-response transcript Q_CAP",
            "canonical commitment prefix (c_1,...,c_i)",
        ],
        "forbidden_input": ["statement", "final CAP proof", "secret randomness"],
        "output": {
            "Ext_1": ["r"],
            "Ext_2": ["r", "x"],
        },
        "straight_line": True,
        "rewinding_permitted": False,
        "measurement_of_quantum_queries_addressed_here": False,
        "success_condition": (
            "for every admissible prefix, extracted values extend to the witness "
            "of every accepting relation instance except with epsilon_ext"
        ),
        "required_failure_accounting": [
            "missing decisive oracle query",
            "seed or leaf ambiguity",
            "GGM collision",
            "Fiat-Shamir transcript collision",
            "mixed degree-12/13 interpolation failure",
            "noncanonical commitment",
        ],
        "epsilon_ext_must_be_numeric": True,
        "implemented_by_current_checkpoint": False,
    }


def unique_mask_game_contract() -> dict[str, object]:
    return {
        "game_id": "pq-rbbc/cap/unique-committed-mask/v1",
        "adversary_output": [
            "one canonical admissible c_r",
            "two distinct extracted 576-bit masks r_0 != r_1",
            "supporting Q_CAP transcript",
        ],
        "win_condition": (
            "both masks are consistent with the same admissible first CAP "
            "commitment under the frozen oracle and serialization contracts"
        ),
        "required_reduction_targets": [
            "CAP straight-line extraction failure",
            "domain-separated oracle collision or ambiguity",
            "canonical parser ambiguity",
        ],
        "mixed_tree_profiles_must_be_covered": [
            "2 trees with 4096 leaves and degree 13",
            "16 trees with 2048 leaves and degree 12",
        ],
        "advantage_bound_must_be_numeric": True,
        "proved_by_current_checkpoint": False,
    }


def qualification_candidate_schema() -> dict[str, object]:
    return {
        "format": "PQRBBC-CAP-SECURITY-QUALIFICATION-CANDIDATE-1",
        "implementation_version": IMPLEMENTATION_VERSION,
        "required_exact_fields": {
            "relation_id": RELATION_ID,
            "cap_profile_fingerprint": cap.profile_fingerprint(
                cap.PRODUCTION_PARAMETERS
            ),
            "oracle_contract_sha256": document_sha256(oracle_contract()),
            "admissible_commitment_contract_sha256": document_sha256(
                admissible_commitment_contract()
            ),
            "extractor_contract_sha256": document_sha256(extractor_contract()),
            "unique_mask_game_contract_sha256": document_sha256(
                unique_mask_game_contract()
            ),
        },
        "required_sections": [
            "source_artifact_identities",
            "extractor_algorithms",
            "full_value_oracle_transcript_vectors",
            "unique_mask_reduction",
            "bad_events",
            "numeric_advantage_accounting",
            "mixed_tree_coverage",
            "independent_review_binding",
            "claim_boundary",
        ],
        "required_negative_vectors": [
            "missing_oracle_query",
            "reordered_oracle_query",
            "wrong_domain",
            "wrong_output_width",
            "noncanonical_commitment",
            "changed_4096_leaf_tree",
            "changed_2048_leaf_tree",
            "changed_extension_degree",
            "changed_mask",
            "final_proof_passed_to_extractor",
        ],
        "claim_promotion_requires_all_external_identities_frozen": True,
        "claim_promotion_requires_independent_review": True,
    }


def claim_boundary() -> dict[str, bool]:
    return {
        "v2_31_cap_security_qualification_contract_closed": (
            not validate_tracked_inputs()
        ),
        "cap_oracle_contract_frozen": not validate_tracked_inputs(),
        "cap_admissible_commitment_contract_frozen": not validate_tracked_inputs(),
        "cap_extractor_interface_frozen": not validate_tracked_inputs(),
        "cap_unique_mask_game_frozen": not validate_tracked_inputs(),
        "cap_straightline_extractor_implemented": False,
        "cap_straightline_extraction_reviewed": False,
        "cap_unique_witness_reviewed": False,
        "cap_security_qualified": False,
        "qrom_request_binding_reviewed": False,
        "fork_security_proof_revalidated": False,
        "qualified_pq_se_nizk_backend_selected": False,
        "production_closed": False,
        "system_architecture_changed": False,
        "ticket_lifecycle_changed": False,
        "pq_sat_auth_changed": False,
    }


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
        "source_execution_semantics": {
            "v2_29_input_identity": V2_29_INPUT_IDENTITY,
            "v2_29_ordered_transcript_sha256": V2_29_TRANSCRIPT_SHA256,
            "v2_29_combined_rows": 589_030_555,
            "v2_29_verification_failures": 0,
            "v2_29_external_assertions": 0,
            "v2_28_ordered_transcript_sha256": V2_28_TRANSCRIPT_SHA256,
            "other_tree_observed_stream_bytes_used": False,
        },
        "cap_profile": cap.profile_dict(cap.PRODUCTION_PARAMETERS),
        "production_accounting": cap.production_accounting(
            cap.PRODUCTION_PARAMETERS
        ),
        "oracle_contract": oracle_contract(),
        "oracle_contract_sha256": document_sha256(oracle_contract()),
        "admissible_commitment_contract": admissible_commitment_contract(),
        "admissible_commitment_contract_sha256": document_sha256(
            admissible_commitment_contract()
        ),
        "extractor_contract": extractor_contract(),
        "extractor_contract_sha256": document_sha256(extractor_contract()),
        "unique_mask_game_contract": unique_mask_game_contract(),
        "unique_mask_game_contract_sha256": document_sha256(
            unique_mask_game_contract()
        ),
        "qualification_candidate_schema": qualification_candidate_schema(),
        "required_external_artifacts": EXTERNAL_REQUIREMENTS,
        "execution_policy": {
            "read_only_checkpoint": True,
            "large_replay_required": False,
            "large_replay_permitted": False,
            "proof_claim_promotion_before_identity_freeze": False,
            "proof_claim_promotion_before_independent_review": False,
            "external_candidate_directory": EXTERNAL_ROOT,
        },
        "claim_boundary": claim_boundary(),
    }


def _validate_candidate_json(
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
    if expected_format == qualification_candidate_schema()["format"]:
        required = qualification_candidate_schema()["required_exact_fields"]
        for name, value in required.items():
            if document.get(name) != value:
                failures.append(f"exact_field:{name}")
        for section in qualification_candidate_schema()["required_sections"]:
            if section not in document:
                failures.append(f"missing_section:{section}")
        record_section = document.get("full_value_oracle_transcript_vectors", {})
        record_identity = (
            record_section.get("record_identity", {})
            if isinstance(record_section, dict)
            else {}
        )
        query_counts = (
            record_section.get("query_counts", {})
            if isinstance(record_section, dict)
            else {}
        )
        if (
            not isinstance(record_identity, dict)
            or record_identity.get("records") != 122_847
            or not isinstance(record_identity.get("canonical_json_sha256"), str)
            or record_section.get("digest_only") is not False
        ):
            failures.append("full_value_record_identity")
        if query_counts != {
            "consistency_points": 1,
            "h1": 1,
            "h2": 1,
            "seed_commit": 40_960,
            "seed_derive": 40_924,
            "tape_expand": 40_960,
        }:
            failures.append("query_counts")
        negative_vectors = document.get("required_negative_vectors", [])
        required_negative_ids = set(
            qualification_candidate_schema()["required_negative_vectors"]
        )
        if (
            not isinstance(negative_vectors, list)
            or {item.get("id") for item in negative_vectors if isinstance(item, dict)}
            != required_negative_ids
            or any(
                not isinstance(item, dict) or item.get("rejected") is not True
                for item in negative_vectors
            )
        ):
            failures.append("negative_vectors")
        accounting = document.get("numeric_advantage_accounting", {})
        if (
            not isinstance(accounting, dict)
            or accounting.get("mixed_degree_accept_probability_without_pow")
            != "2^-182"
            or accounting.get("fork_pow_implemented") is not False
            or accounting.get("complete_total_bound_available") is not False
            or accounting.get("target_met_by_raw_tree_schedule_at_q_H_1")
            is not False
        ):
            failures.append("numeric_advantage_accounting")
        review = document.get("independent_review_binding", {})
        if (
            not isinstance(review, dict)
            or review.get("attestation_present") is not False
            or review.get("claim_promotion_authorized") is not False
        ):
            failures.append("independent_review_boundary")
        claims = document.get("claim_boundary", {})
        if not isinstance(claims, dict):
            failures.append("claim_boundary")
        else:
            for name in (
                "cap_straightline_extractor_implemented",
                "cap_straightline_extraction_reviewed",
                "cap_unique_witness_reviewed",
                "cap_security_qualified",
                "paper_parameter_theorem_inherited",
                "qrom_request_binding_reviewed",
                "fork_security_proof_revalidated",
                "production_closed",
                "system_architecture_changed",
                "ticket_lifecycle_changed",
                "pq_sat_auth_changed",
            ):
                if claims.get(name) is not False:
                    failures.append(f"claim_boundary:{name}")
    elif expected_format == "PQRBBC-CAP-SECURITY-INDEPENDENT-REVIEW-1":
        for name in (
            "reviewer_identity",
            "independence_statement",
            "review_date",
            "reviewed_artifact_identities",
            "findings",
            "dispositions",
            "claim_promotion_authorized",
        ):
            if name not in document:
                failures.append(f"missing_field:{name}")
    return not failures, failures


def _candidate_identity(
    path: Path | None, requirement: Mapping[str, object]
) -> dict[str, object]:
    identity_frozen = requirement.get("identity_frozen") is True
    if path is None:
        return {
            "provided": False,
            "identity_frozen": identity_frozen,
            "verified": False,
            "schema_valid": False,
            "failures": ["not_provided"],
        }
    if not path.is_file():
        return {
            "provided": True,
            "identity_frozen": identity_frozen,
            "verified": False,
            "schema_valid": False,
            "failures": ["missing"],
        }
    schema_valid = True
    schema_failures: list[str] = []
    schema = str(requirement["schema"])
    if schema.startswith("PQRBBC-"):
        schema_valid, schema_failures = _validate_candidate_json(path, schema)
    elif schema == "PDF proof artifact":
        with path.open("rb") as stream:
            if stream.read(5) != b"%PDF-":
                schema_valid = False
                schema_failures.append("pdf_header")
    actual_bytes = path.stat().st_size
    actual_sha256 = _sha256(path)
    failures: list[str] = []
    if identity_frozen:
        if actual_bytes != requirement.get("bytes"):
            failures.append("byte_length_mismatch")
        if actual_sha256 != requirement.get("sha256"):
            failures.append("sha256_mismatch")
    else:
        failures.append("identity_not_frozen")
    if not schema_valid:
        failures.append("schema_invalid")
    return {
        "provided": True,
        "identity_frozen": identity_frozen,
        "verified": identity_frozen and schema_valid and not failures,
        "bytes": actual_bytes,
        "sha256": actual_sha256,
        "schema_valid": schema_valid,
        "schema_failures": schema_failures,
        "failures": failures,
    }


def exact_candidate_inventory_command() -> str:
    options = {
        "extractor_specification": "--extractor-specification",
        "unique_mask_reduction": "--unique-mask-reduction",
        "qualification_evidence": "--qualification-evidence",
        "independent_review_attestation": "--independent-review-attestation",
    }
    parts = [
        "PYTHONPATH=src python -u src/pq_rbbc_cap_security_qualification.py",
        f"  --report {EXTERNAL_ROOT}/pq_rbbc_cap_security_environment_v2_31.json",
    ]
    for name, requirement in EXTERNAL_REQUIREMENTS.items():
        parts.append(
            f"  {options[name]} {EXTERNAL_ROOT}/{requirement['filename']}"
        )
    return " \\\n".join(parts)


def build_environment_report(
    candidates: Mapping[str, Path | None],
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
    contract_ready = checks["tracked_inputs"]["verified"] is True
    candidate_artifacts_verified = all(
        checks[name]["verified"] is True
        for name in (
            "extractor_specification",
            "unique_mask_reduction",
            "qualification_evidence",
        )
    )
    return {
        "format": REPORT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "checks": checks,
        "blockers": blockers,
        "safe_to_author_cap_proof_artifacts": contract_ready,
        "proof_candidate_artifacts_verified": candidate_artifacts_verified,
        "safe_to_request_independent_review": candidate_artifacts_verified,
        "safe_to_start_cap_security_qualification": False,
        "safe_to_claim_cap_security_qualified": False,
        "safe_to_start_large_replay": False,
        "large_replay_started": False,
        "exact_candidate_inventory_command": exact_candidate_inventory_command(),
        "exact_qualification_command": None,
        "exact_qualification_command_withheld_reason": (
            "independent review is absent and final Prove/Verify/PoW "
            "findings remain blocking"
        ),
        "claim_boundary": claim_boundary(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print-frozen", action="store_true")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--extractor-specification", type=Path)
    parser.add_argument("--unique-mask-reduction", type=Path)
    parser.add_argument("--qualification-evidence", type=Path)
    parser.add_argument("--independent-review-attestation", type=Path)
    args = parser.parse_args()
    if args.print_frozen:
        print(canonical_json(build_frozen_manifest()).decode(), end="")
        return
    if args.report is None:
        parser.error("--report or --print-frozen is required")
    report = build_environment_report({
        "extractor_specification": args.extractor_specification,
        "unique_mask_reduction": args.unique_mask_reduction,
        "qualification_evidence": args.qualification_evidence,
        "independent_review_attestation": args.independent_review_attestation,
    })
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_bytes(canonical_json(report))
    print(json.dumps({
        "report": str(args.report),
        "safe_to_author_cap_proof_artifacts": report[
            "safe_to_author_cap_proof_artifacts"
        ],
        "safe_to_start_cap_security_qualification": report[
            "safe_to_start_cap_security_qualification"
        ],
        "safe_to_claim_cap_security_qualified": report[
            "safe_to_claim_cap_security_qualified"
        ],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
