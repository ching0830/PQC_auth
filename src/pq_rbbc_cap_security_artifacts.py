#!/usr/bin/env python3
"""Build the external PQ-RBBC v2.31 CAP proof-artifact candidate bundle.

The production vector may reuse only the locally generated, identity-checked
v2.19 execution cache.  Loading any pickle from an untrusted source is unsafe.
The resulting PDFs and large full-value transcript remain external to Git.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from typing import Mapping, Sequence

import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_composer as composer
import pq_rbbc_cap_composer_recovery as recovery
import pq_rbbc_cap_global_tail as global_tail
import pq_rbbc_cap_security_qualification as qualification
import pq_rbbc_cap_straightline_extractor as extractor


IMPLEMENTATION_VERSION = "2.31"
FORMAT = "PQRBBC-CAP-SECURITY-QUALIFICATION-CANDIDATE-1"
RELATION_ID = qualification.RELATION_ID
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXTERNAL_ROOT = Path(qualification.EXTERNAL_ROOT)

PAPER_FILENAME = "blind_uov_eprint_2025_895_revision_2025_10_31.pdf"
EXTRACTOR_PDF_FILENAME = "pq_rbbc_cap_straightline_extractor_spec_v2_31.pdf"
UNIQUE_MASK_PDF_FILENAME = (
    "pq_rbbc_cap_unique_committed_mask_reduction_v2_31.pdf"
)
CANDIDATE_FILENAME = "pq_rbbc_cap_security_qualification_evidence_v2_31.json"

PAPER_IDENTITY = (
    1_595_999,
    "7ba2c040fd04823fb0d2aaad5e58348b5ef374726657ff1c0d87d000b4beff95",
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

TRUSTED_CACHE_IDENTITY = (
    35_509_449,
    "4fc980b3408d00418fed15f282a80a2c932b829c002146cc80adb609b3814a38",
)
FROZEN_EXECUTION_SHA256 = (
    "69de49f5ad49f37ec461f2b22cd0bdf5293cb727644db5c23070cbd575efe61c"
)
FROZEN_XOF_TRACE_BYTES = 44_236_358
FROZEN_XOF_TRACE_SHA256 = composer.FROZEN_XOF_TRACE_SHA256

TRACKED_SOURCES = {
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


def canonical_json(document: object) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def identity(path: Path) -> dict[str, object]:
    return {
        "name": path.name,
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def require_identity(
    path: Path, expected: tuple[int, str], label: str
) -> None:
    if not path.is_file():
        raise ValueError(f"{label} is missing")
    if path.stat().st_size != expected[0]:
        raise ValueError(f"{label} byte length mismatch")
    if sha256_file(path) != expected[1]:
        raise ValueError(f"{label} SHA-256 mismatch")


def validate_tracked_sources() -> None:
    for label, (relative, size, digest) in TRACKED_SOURCES.items():
        require_identity(ROOT / relative, (size, digest), label)
    required = qualification.qualification_candidate_schema()[
        "required_exact_fields"
    ]
    if required["relation_id"] != RELATION_ID:
        raise ValueError("v2.31 qualification relation mismatch")


def validate_pdf(path: Path, expected_name: str, label: str) -> None:
    if path.name != expected_name:
        raise ValueError(f"{label} filename mismatch")
    if not path.is_file() or path.stat().st_size < 1_024:
        raise ValueError(f"{label} is missing or too small")
    with path.open("rb") as stream:
        if stream.read(5) != b"%PDF-":
            raise ValueError(f"{label} does not have a PDF header")


def load_trusted_execution(cache_path: Path) -> cap.CAPExecution:
    """Load a known local pickle only after exact byte identity is checked."""

    require_identity(cache_path, TRUSTED_CACHE_IDENTITY, "trusted local cache")
    summary = global_tail._load_production_execution(cache_path)
    execution = summary.execution
    trace_bytes, trace_digest = composer.xof_trace_digest(execution.xof_calls)
    exact_checks = {
        "execution_sha256": recovery.execution_sha256(execution)
        == FROZEN_EXECUTION_SHA256,
        "xof_trace_bytes": trace_bytes == FROZEN_XOF_TRACE_BYTES,
        "xof_trace_sha256": trace_digest == FROZEN_XOF_TRACE_SHA256,
        "xof_calls": len(execution.xof_calls) == 122_847,
        "commitment_bytes": len(execution.commitment.encoded) == 5_391,
        "commitment_sha256": hashlib.sha256(
            execution.commitment.encoded
        ).hexdigest()
        == composer.FROZEN_COMMITMENT_SHA256,
        "profile": execution.commitment.parameters_fingerprint
        == cap.profile_fingerprint(cap.PRODUCTION_PARAMETERS),
    }
    failures = [name for name, passed in exact_checks.items() if not passed]
    if failures:
        raise ValueError("trusted execution rejected: " + ",".join(failures))
    return execution


def numeric_advantage_accounting() -> dict[str, object]:
    leaf_log2 = 2 * 12 + 16 * 11
    degree = cap.PRODUCTION_PARAMETERS.degree
    tree_count = cap.PRODUCTION_PARAMETERS.tree_count
    degree_log2 = leaf_log2 - tree_count * math.log2(degree)
    if degree_log2 != 182:
        raise AssertionError("unexpected mixed-tree degree exponent")
    budgets = []
    for query_log2 in (0, 32, 64):
        budgets.append({
            "q_H_log2": query_log2,
            "guess_term_negative_log2": 386 - query_log2,
            "collision_term_negative_log2": 387 - 2 * query_log2,
            "missing_leaf_term_negative_log2": leaf_log2 - query_log2,
            "degree_term_negative_log2": int(degree_log2) - query_log2,
            "dominant_listed_term_negative_log2": min(
                386 - query_log2,
                387 - 2 * query_log2,
                leaf_log2 - query_log2,
                int(degree_log2) - query_log2,
            ),
        })
    return {
        "target_security_bits": 192,
        "hash_output_bits": 386,
        "lambda_bits": 193,
        "tree_leaf_log2_sum": leaf_log2,
        "mixed_missing_leaf_probability": "2^-200",
        "degree": degree,
        "tree_count": tree_count,
        "mixed_degree_accept_probability_without_pow": "2^-182",
        "source_paper_pow_bits_for_nist_iii_shorter": "13.9",
        "fork_pow_implemented": False,
        "paper_pow_may_be_added_to_fork_bound": False,
        "two_point_uuh_bound": "(10/(2^193-1))^2",
        "tree_pair_union_factor": 153,
        "diagnostic_terms": {
            "guess": "q_H/2^386",
            "collision": "q_H^2/2^387",
            "missing_leaf": "q_H/2^200",
            "invalid_degree": "q_H/2^182",
            "consistency": "q_H*153*(10/(2^193-1))^2",
        },
        "query_budget_diagnostics": budgets,
        "target_met_by_raw_tree_schedule_at_q_H_1": False,
        "complete_total_bound_available": False,
        "uninstantiated_terms": [
            "final CAP Prove/Verify acceptance",
            "proof-of-work and challenge sampling",
            "constraint-sampling soundness",
            "multi-target and adaptive-session loss",
            "concrete Anemoi-to-ROM justification",
            "QROM measurement and programming",
        ],
    }


def _expect_failure(action, contains: str | None = None) -> dict[str, object]:
    try:
        action()
    except (extractor.ExtractionFailure, TypeError) as error:
        message = str(error)
        if contains is not None and contains not in message:
            raise AssertionError(
                f"negative vector rejected for unexpected reason: {message}"
            ) from error
        return {"rejected": True, "failure": message}
    raise AssertionError("negative vector was accepted")


def _mutate_h1_tree(
    records: Sequence[Mapping[str, object]],
    tree_field_index: int,
    byte_offset: int,
    replacement: bytes,
) -> list[dict[str, object]]:
    mutated = [dict(record) for record in records]
    h1_index = next(
        index
        for index, record in enumerate(mutated)
        if record["domain_id"] == "h1"
    )
    payload = bytes.fromhex(str(mutated[h1_index]["canonical_encoded_input"]))
    fields = list(extractor._decode_transcript(payload))
    component = bytearray(fields[tree_field_index])
    component[byte_offset : byte_offset + len(replacement)] = replacement
    fields[tree_field_index] = bytes(component)
    mutated[h1_index]["canonical_encoded_input"] = (
        extractor.sponge.encode_transcript(fields).hex()
    )
    return mutated


def verify_negative_vectors(
    records: Sequence[Mapping[str, object]],
    c1: bytes,
    expected_r: int,
) -> list[dict[str, object]]:
    parameters = cap.PRODUCTION_PARAMETERS
    vectors: list[tuple[str, dict[str, object]]] = []

    without_h2 = [
        dict(record) for record in records if record["domain_id"] != "h2"
    ]
    vectors.append((
        "missing_oracle_query",
        _expect_failure(
            lambda: extractor.extract_ext1(without_h2, c1, parameters),
            "h2",
        ),
    ))

    reordered = [dict(record) for record in records]
    reordered[0], reordered[1] = reordered[1], reordered[0]
    vectors.append((
        "reordered_oracle_query",
        _expect_failure(
            lambda: extractor.extract_ext1(reordered, c1, parameters),
            "non-contiguous order",
        ),
    ))

    wrong_domain = [dict(record) for record in records]
    h2_index = next(
        index
        for index, record in enumerate(wrong_domain)
        if record["domain_id"] == "h2"
    )
    wrong_domain[h2_index]["domain_id"] = "seed_derive"
    vectors.append((
        "wrong_domain",
        _expect_failure(
            lambda: extractor.extract_ext1(wrong_domain, c1, parameters),
            "h2",
        ),
    ))

    wrong_width = [dict(record) for record in records]
    wrong_width[0]["output_bits"] = int(wrong_width[0]["output_bits"]) - 1
    vectors.append((
        "wrong_output_width",
        _expect_failure(
            lambda: extractor.extract_ext1(wrong_width, c1, parameters),
            "wrong output width",
        ),
    ))

    vectors.append((
        "noncanonical_commitment",
        _expect_failure(
            lambda: extractor.extract_ext1(records, c1 + b"\x00", parameters),
            "trailing bytes",
        ),
    ))

    changed_4096 = _mutate_h1_tree(
        records, 1, 2, (2048).to_bytes(4, "little")
    )
    vectors.append((
        "changed_4096_leaf_tree",
        _expect_failure(
            lambda: extractor.extract_ext1(changed_4096, c1, parameters),
            "wrong leaf count",
        ),
    ))

    changed_2048 = _mutate_h1_tree(
        records, 3, 2, (4096).to_bytes(4, "little")
    )
    vectors.append((
        "changed_2048_leaf_tree",
        _expect_failure(
            lambda: extractor.extract_ext1(changed_2048, c1, parameters),
            "wrong leaf count",
        ),
    ))

    changed_degree = _mutate_h1_tree(
        records, 1, 6, (12).to_bytes(2, "little")
    )
    vectors.append((
        "changed_extension_degree",
        _expect_failure(
            lambda: extractor.extract_ext1(changed_degree, c1, parameters),
            "wrong extension degree",
        ),
    ))

    vectors.append((
        "changed_mask",
        {
            "rejected": expected_r != (expected_r ^ 1),
            "failure": "expected-mask mismatch",
        },
    ))

    vectors.append((
        "final_proof_passed_to_extractor",
        _expect_failure(
            lambda: extractor.extract_ext1(records, c1, parameters, b"proof")
        ),
    ))
    return [
        {"id": vector_id, **result}
        for vector_id, result in vectors
    ]


def build_candidate(
    execution: cap.CAPExecution,
    cache_path: Path,
    paper_path: Path,
    extractor_pdf: Path,
    unique_mask_pdf: Path,
) -> dict[str, object]:
    validate_tracked_sources()
    require_identity(paper_path, PAPER_IDENTITY, "authoritative paper")
    validate_pdf(extractor_pdf, EXTRACTOR_PDF_FILENAME, "extractor PDF")
    validate_pdf(unique_mask_pdf, UNIQUE_MASK_PDF_FILENAME, "unique-mask PDF")

    parameters = cap.PRODUCTION_PARAMETERS
    records = extractor.transcript_records(execution.xof_calls)
    records_identity = {
        "records": len(records),
        "canonical_json_bytes": len(canonical_json(records)),
        "canonical_json_sha256": extractor.document_sha256(records),
    }
    extracted_r = extractor.extract_ext1(
        records, execution.commitment.encoded, parameters
    )
    if extracted_r != execution.commitment.derived_mask:
        raise ValueError("production Ext_1 result mismatch")

    x_bytes = hashlib.shake_256(
        b"PQ-RBBC/v2.31/cap-extractor-candidate-x"
    ).digest((parameters.appended_signature_bits + 7) // 8)
    expected_x = int.from_bytes(x_bytes, "little") & (
        (1 << parameters.appended_signature_bits) - 1
    )
    delta_x = execution.commitment.append_signature(
        expected_x, parameters.appended_signature_bits
    )
    c2 = extractor.serialize_candidate_append(delta_x, parameters)
    parsed_delta = extractor.parse_candidate_append(c2, parameters)
    append_base = execution.commitment.append_base
    ext2_result = (extracted_r, append_base ^ parsed_delta)
    if ext2_result != (extracted_r, expected_x):
        raise ValueError("production Ext_2 append recovery mismatch")

    negative_vectors = verify_negative_vectors(
        records, execution.commitment.encoded, extracted_r
    )
    if not all(item["rejected"] is True for item in negative_vectors):
        raise ValueError("one or more negative vectors did not reject")

    query_counts = Counter(
        str(record["domain_id"]) for record in records
    )
    source_identities = {
        label: {
            "name": Path(relative).name,
            "bytes": size,
            "sha256": digest,
        }
        for label, (relative, size, digest) in TRACKED_SOURCES.items()
    }
    source_identities.update({
        "artifact_generator": identity(Path(__file__)),
        "authoritative_paper": identity(paper_path),
        "extractor_specification_pdf": identity(extractor_pdf),
        "unique_mask_reduction_pdf": identity(unique_mask_pdf),
        "trusted_local_execution_cache": {
            **identity(cache_path),
            "local_pickle": True,
            "must_not_be_tracked_in_git": True,
        },
        "production_execution": {
            "execution_sha256": FROZEN_EXECUTION_SHA256,
            "xof_trace_bytes": FROZEN_XOF_TRACE_BYTES,
            "xof_trace_sha256": FROZEN_XOF_TRACE_SHA256,
            "commitment_sha256": composer.FROZEN_COMMITMENT_SHA256,
        },
    })

    schema = qualification.qualification_candidate_schema()
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        **schema["required_exact_fields"],
        "source_artifact_identities": source_identities,
        "extractor_algorithms": {
            "source_relation_id": extractor.RELATION_ID,
            "model": "classical ROM ordered full-value transcript",
            "Ext_1": {
                "input": ["Q_CAP", "c_1"],
                "output": ["r"],
                "production_vector_verified": True,
            },
            "Ext_2": {
                "input": ["Q_CAP", "c_1", "candidate_c_2"],
                "output": ["r", "x"],
                "production_append_recovery_verified": True,
            },
            "statement_input": False,
            "final_proof_input": False,
            "secret_randomness_input": False,
            "rewinding": False,
            "complete_adversarial_knowledge_soundness_proved": False,
        },
        "full_value_oracle_transcript_vectors": {
            "encoding": qualification.oracle_contract()[
                "ordered_query_record"
            ],
            "digest_only": False,
            "source_xof_trace_sha256": FROZEN_XOF_TRACE_SHA256,
            "record_identity": records_identity,
            "query_counts": dict(sorted(query_counts.items())),
            "production_honest_vector": {
                "profile_fingerprint": cap.profile_fingerprint(parameters),
                "commitment_hex": execution.commitment.encoded.hex(),
                "candidate_c2_hex": c2.hex(),
                "expected_r_hex": cap.pack_int(
                    extracted_r, parameters.mask_bits
                ).hex(),
                "expected_x_hex": cap.pack_int(
                    expected_x, parameters.appended_signature_bits
                ).hex(),
                "Ext_1_verified": True,
                "Ext_2_append_recovery_verified": True,
                "records": records,
            },
        },
        "unique_mask_reduction": {
            "game_id": qualification.unique_mask_game_contract()["game_id"],
            "conditional_bound": (
                "Adv_uw <= 2*Adv_ext + Adv_oracle_collision "
                "+ Adv_serialization_ambiguity"
            ),
            "reduction_status": "specified_but_prerequisites_not_discharged",
            "paper_parameter_theorem_inherited": False,
            "fork_final_proof_and_pow_missing": True,
        },
        "bad_events": [
            "missing decisive h2, h1, seed-commit, or tape query",
            "multiple formatted preimages or conflicting oracle response",
            "two corrected constants collide under the consistency hash",
            "noncanonical serialization or mixed-tree metadata",
            "all trees hide a decisive leaf while a final proof accepts",
            "invalid degree-2 relation passes every challenge",
            "classical transcript assumption is applied to quantum queries",
        ],
        "numeric_advantage_accounting": numeric_advantage_accounting(),
        "mixed_tree_coverage": {
            "production_shapes": [
                [tree.leaves, tree.extension_degree]
                for tree in execution.tree_polynomials
            ],
            "degree_13_tree_count": 2,
            "degree_12_tree_count": 16,
            "all_4096_leaf_commitments_in_full_value_vector": 8_192,
            "all_2048_leaf_commitments_in_full_value_vector": 32_768,
            "all_tree_types_recovered_by_Ext_1": True,
            "other_tree_observed_stream_bytes_used": False,
        },
        "independent_review_binding": {
            "required_attestation": (
                "pq_rbbc_cap_security_independent_review_v2_31.json"
            ),
            "attestation_present": False,
            "reviewer_identity": None,
            "project_self_attestation_permitted": False,
            "claim_promotion_authorized": False,
        },
        "required_negative_vectors": negative_vectors,
        "claim_boundary": {
            "v2_31_cap_proof_candidate_artifacts_authored": True,
            "full_value_production_oracle_vector_exported": True,
            "candidate_extractor_vector_verified": True,
            "numeric_diagnostic_accounting_completed": True,
            "cap_straightline_extractor_implemented": False,
            "cap_straightline_extraction_reviewed": False,
            "cap_unique_witness_reviewed": False,
            "cap_security_qualified": False,
            "paper_parameter_theorem_inherited": False,
            "qrom_request_binding_reviewed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
            "system_architecture_changed": False,
            "ticket_lifecycle_changed": False,
            "pq_sat_auth_changed": False,
        },
    }


def build_estimate() -> dict[str, object]:
    accounting = cap.production_accounting(cap.PRODUCTION_PARAMETERS)
    return {
        "implementation_version": IMPLEMENTATION_VERSION,
        "operation": "reuse verified local CAP execution and export full values",
        "large_row_replay": False,
        "expected_oracle_records": accounting["total_xof_calls"],
        "source_xof_trace_bytes": FROZEN_XOF_TRACE_BYTES,
        "expected_commitment_bytes": accounting["commitment_bytes"],
        "external_output_only": True,
        "trusted_pickle_will_be_committed": False,
        "qualification_claim_after_generation": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--estimate", action="store_true")
    parser.add_argument("--trusted-execution-cache", type=Path)
    parser.add_argument("--paper", type=Path)
    parser.add_argument("--extractor-pdf", type=Path)
    parser.add_argument("--unique-mask-pdf", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--allow-trusted-local-pickle",
        action="store_true",
        help="acknowledge that the exact local cache was generated in this workspace",
    )
    args = parser.parse_args()
    if args.estimate:
        print(json.dumps(build_estimate(), sort_keys=True))
        return
    required = (
        args.trusted_execution_cache,
        args.paper,
        args.extractor_pdf,
        args.unique_mask_pdf,
        args.output,
    )
    if any(value is None for value in required):
        parser.error(
            "generation requires --trusted-execution-cache, --paper, "
            "--extractor-pdf, --unique-mask-pdf, and --output"
        )
    if not args.allow_trusted_local_pickle:
        parser.error("refusing to load pickle without explicit local-trust acknowledgement")
    execution = load_trusted_execution(args.trusted_execution_cache)
    candidate = build_candidate(
        execution,
        args.trusted_execution_cache,
        args.paper,
        args.extractor_pdf,
        args.unique_mask_pdf,
    )
    encoded = canonical_json(candidate)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encoded)
    print(json.dumps({
        "output": str(args.output),
        "bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "full_value_records": 122_847,
        "cap_security_qualified": False,
        "independent_review_attestation_present": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
