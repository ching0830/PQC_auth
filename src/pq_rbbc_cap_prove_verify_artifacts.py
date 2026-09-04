#!/usr/bin/env python3
"""Generate the bounded v2.32 CAP Prove/Verify candidate artifacts.

The generator emits three review inputs: serialization vectors, a PoW/profile
disposition, and partial implementation evidence.  It does not emit an
independent-review attestation and never runs the 589,030,555-row relation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Callable

import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_prove_verify as implementation
import pq_rbbc_cap_prove_verify_preflight as preflight


IMPLEMENTATION_VERSION = "2.32"
DEFAULT_OUTPUT = Path(preflight.EXTERNAL_ROOT)
SERIALIZATION_FILENAME = "pq_rbbc_cap_proof_serialization_v2_32.json"
DISPOSITION_FILENAME = "pq_rbbc_cap_pow_security_profile_disposition_v2_32.json"
IMPLEMENTATION_FILENAME = "pq_rbbc_cap_prove_verify_implementation_evidence_v2_32.json"
SPECIFICATION_FILENAME = "pq_rbbc_cap_prove_verify_spec_v2_32.pdf"

BLIND_UOV_PAPER = (
    "blind_uov_eprint_2025_895_revision_2025_10_31.pdf",
    1_595_999,
    "7ba2c040fd04823fb0d2aaad5e58348b5ef374726657ff1c0d87d000b4beff95",
)
BAVC_PAPER = (
    "eprint_2024_490.pdf",
    1_500_374,
    "b41c874ea925a65f33984e0789951144dd012380c6e99e53859af53aa9ffe7a4",
)
DSD_PAPER = (
    "eprint_2024_541.pdf",
    859_797,
    "ce30ff1d9a49b13211340f4c20d05a4ee76a9f9db1745d3f853102aad0b9837f",
)


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
        "filename": path.name,
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def require_identity(path: Path, expected: tuple[str, int, str]) -> None:
    name, size, digest = expected
    if path.name != name or not path.is_file():
        raise ValueError(f"missing source artifact {name}")
    if path.stat().st_size != size or sha256_file(path) != digest:
        raise ValueError(f"source artifact identity mismatch: {name}")


def fixture() -> tuple[
    implementation.CAPStatement, implementation.CAPProofEnvelope
]:
    parameters = cap.PRODUCTION_PARAMETERS
    c_r = cap.serialize_commitment(
        parameters,
        (1, 2),
        3,
        4,
        (0,) * (parameters.tree_count - 1),
        (0,) * (parameters.tree_count - 1),
    )
    statement = implementation.CAPStatement(
        bytes.fromhex(implementation.PROFILE_FINGERPRINT),
        bytes(range(32)),
        bytes(range(32, 64)),
        bytes(range(64, 96)),
        bytes(range(72)),
    )
    proof = implementation.CAPProofEnvelope(
        c_r,
        hashlib.shake_256(b"v2.32-candidate-c-x").digest(
            implementation.C_X_BYTES
        ),
        (7).to_bytes(implementation.POW_NONCE_BYTES, "little"),
        b"PQRBBC-PI2-CANDIDATE-NOT-AN-ACCEPTING-PROOF",
    )
    return statement, proof


def _expect_codec_rejection(
    vector_id: str, action: Callable[[], object], layer: str = "canonical_parser"
) -> dict[str, object]:
    try:
        action()
    except implementation.CAPCodecError as error:
        return {
            "id": vector_id,
            "rejected": True,
            "rejection_layer": layer,
            "failure": str(error),
        }
    raise AssertionError(f"negative vector accepted: {vector_id}")


def _expect_verify_rejection(
    vector_id: str, statement: bytes, proof: bytes
) -> dict[str, object]:
    result = implementation.verify(statement, proof)
    if result.accepted:
        raise AssertionError(f"negative vector accepted: {vector_id}")
    return {
        "id": vector_id,
        "rejected": True,
        "rejection_layer": (
            "canonical_parser"
            if any(item.startswith(("statement:", "proof:")) for item in result.failures)
            else "fail_closed_backend_unavailable"
        ),
        "failures": list(result.failures),
        "binding_evidence": False,
    }


def serialization_negatives(
    statement: implementation.CAPStatement,
    proof: implementation.CAPProofEnvelope,
) -> list[dict[str, object]]:
    encoded = proof.encode()
    header = len(implementation.PROOF_MAGIC)
    first_id = header + 2 + 32 + 2
    first_length = first_id + 2

    wrong_magic = bytearray(encoded)
    wrong_magic[0] ^= 1
    wrong_version = bytearray(encoded)
    wrong_version[header] ^= 1
    wrong_profile = bytearray(encoded)
    wrong_profile[header + 2] ^= 1
    reordered = bytearray(encoded)
    reordered[first_id : first_id + 2] = (2).to_bytes(2, "little")
    duplicate = bytearray(encoded)
    duplicate[first_id : first_id + 2] = (2).to_bytes(2, "little")
    unknown = bytearray(encoded)
    unknown[first_id : first_id + 2] = (99).to_bytes(2, "little")
    oversized = bytearray(encoded)
    oversized[first_length : first_length + 8] = (1 << 63).to_bytes(8, "little")
    noncanonical = bytearray(proof.c_r)
    # First salt element follows magic/version/profile; bit 193 is forbidden.
    salt_offset = len(cap.COMMITMENT_MAGIC) + 2 + 32
    noncanonical[salt_offset + 24] |= 0x80
    candidate_c2 = (
        b"PQRBBC-CAP-APPEND-CANDIDATE-V1"
        + (1).to_bytes(2, "little")
        + bytes.fromhex(implementation.PROFILE_FINGERPRINT)
        + cap.PRODUCTION_PARAMETERS.appended_signature_bits.to_bytes(4, "little")
        + proof.c_x
    )

    vectors = [
        _expect_codec_rejection(
            "wrong_magic",
            lambda: implementation.CAPProofEnvelope.decode(bytes(wrong_magic)),
        ),
        _expect_codec_rejection(
            "wrong_version",
            lambda: implementation.CAPProofEnvelope.decode(bytes(wrong_version)),
        ),
        _expect_codec_rejection(
            "wrong_profile_fingerprint",
            lambda: implementation.CAPProofEnvelope.decode(bytes(wrong_profile)),
        ),
        _expect_codec_rejection(
            "reordered_section",
            lambda: implementation.CAPProofEnvelope.decode(bytes(reordered)),
        ),
        _expect_codec_rejection(
            "duplicate_section",
            lambda: implementation.CAPProofEnvelope.decode(bytes(duplicate)),
        ),
        _expect_codec_rejection(
            "unknown_section",
            lambda: implementation.CAPProofEnvelope.decode(bytes(unknown)),
        ),
        _expect_codec_rejection(
            "truncated_payload",
            lambda: implementation.CAPProofEnvelope.decode(encoded[:-1]),
        ),
        _expect_codec_rejection(
            "oversized_payload",
            lambda: implementation.CAPProofEnvelope.decode(bytes(oversized)),
        ),
        _expect_codec_rejection(
            "trailing_bytes",
            lambda: implementation.CAPProofEnvelope.decode(encoded + b"\x00"),
        ),
        _expect_codec_rejection(
            "noncanonical_unused_high_bits",
            lambda: implementation.CAPProofEnvelope(
                bytes(noncanonical),
                proof.c_x,
                proof.pow_nonce,
                proof.pi_2,
            ).encode(),
        ),
        _expect_codec_rejection(
            "candidate_c2_used_as_production_c_x",
            lambda: implementation.CAPProofEnvelope(
                proof.c_r,
                candidate_c2,
                proof.pow_nonce,
                proof.pi_2,
            ).encode(),
        ),
    ]
    changed_statement = implementation.CAPStatement(
        statement.common_parameters_digest,
        bytes([statement.ctx[0] ^ 1]) + statement.ctx[1:],
        statement.sid,
        statement.rid,
        statement.y,
    )
    vectors.append(
        _expect_verify_rejection(
            "changed_statement", changed_statement.encode(), encoded
        )
    )
    return vectors


def mutation_vectors(
    statement: implementation.CAPStatement,
    proof: implementation.CAPProofEnvelope,
) -> list[dict[str, object]]:
    vectors: list[dict[str, object]] = []
    fields = {
        "changed_statement_ctx": "ctx",
        "changed_statement_sid": "sid",
        "changed_statement_rid": "rid",
        "changed_statement_y": "y",
    }
    for vector_id, field_name in fields.items():
        values = {
            "common_parameters_digest": statement.common_parameters_digest,
            "ctx": statement.ctx,
            "sid": statement.sid,
            "rid": statement.rid,
            "y": statement.y,
        }
        value = values[field_name]
        values[field_name] = bytes([value[0] ^ 1]) + value[1:]
        mutated = implementation.CAPStatement(**values)
        vectors.append(
            _expect_verify_rejection(vector_id, mutated.encode(), proof.encode())
        )

    for vector_id, proof_field in (
        ("changed_c_r", "c_r"),
        ("changed_c_x", "c_x"),
        ("changed_pow_nonce", "pow_nonce"),
        ("changed_pi_2", "pi_2"),
        ("changed_fiat_shamir_challenge", "pi_2"),
    ):
        values = {
            "c_r": proof.c_r,
            "c_x": proof.c_x,
            "pow_nonce": proof.pow_nonce,
            "pi_2": proof.pi_2,
        }
        value = values[proof_field]
        values[proof_field] = bytes([value[0] ^ 1]) + value[1:]
        try:
            mutated_bytes = implementation.CAPProofEnvelope(**values).encode()
        except implementation.CAPCodecError as error:
            vectors.append({
                "id": vector_id,
                "rejected": True,
                "rejection_layer": "canonical_parser",
                "failures": [str(error)],
                "binding_evidence": False,
            })
        else:
            vectors.append(
                _expect_verify_rejection(
                    vector_id, statement.encode(), mutated_bytes
                )
            )
    vectors.append(
        _expect_verify_rejection(
            "noncanonical_proof", statement.encode(), proof.encode() + b"\x00"
        )
    )
    return vectors


def build_serialization_candidate() -> dict[str, object]:
    statement, proof = fixture()
    statement_bytes = statement.encode()
    proof_bytes = proof.encode()
    schema = preflight.serialization_candidate_schema()
    return {
        "format": schema["format"],
        "implementation_version": IMPLEMENTATION_VERSION,
        **schema["required_exact_fields"],
        "field_layout": {
            "statement": {
                "magic_hex": implementation.STATEMENT_MAGIC.hex(),
                "version": implementation.STATEMENT_VERSION,
                "profile_fingerprint_bytes": 32,
                "fields": [
                    {"id": field_id, "name": name, "bytes": size}
                    for field_id, name, size in implementation.STATEMENT_FIELDS
                ],
            },
            "proof": {
                "magic_hex": implementation.PROOF_MAGIC.hex(),
                "version": implementation.PROOF_VERSION,
                "sections": [
                    {"id": 1, "name": "c_r", "bytes": implementation.C_R_BYTES},
                    {"id": 2, "name": "c_x", "bytes": implementation.C_X_BYTES},
                    {"id": 3, "name": "pow_nonce", "bytes": implementation.POW_NONCE_BYTES},
                    {"id": 4, "name": "pi_2", "bytes": None},
                ],
                "integer_encoding": "unsigned little-endian",
            },
        },
        "canonical_parser": {
            "implemented": True,
            "c_r_inner_parser": "frozen v2.31 production CAP commitment parser",
            "pi_2_inner_parser_implemented": False,
            "complete_production_parser": False,
            "trailing_bytes_rejected": True,
        },
        "fiat_shamir_binding": {
            "statement_bytes_are_canonical": True,
            "statement_binding_implemented": False,
            "challenge_derivation_implemented": False,
            "reason": "Protocol-11 h3 input and unified-GGM counter placement are not implemented",
        },
        "positive_vectors": [{
            "id": "candidate_outer_round_trip",
            "statement_bytes": len(statement_bytes),
            "statement_sha256": hashlib.sha256(statement_bytes).hexdigest(),
            "proof_bytes": len(proof_bytes),
            "proof_sha256": hashlib.sha256(proof_bytes).hexdigest(),
            "round_trip": implementation.CAPProofEnvelope.decode(proof_bytes) == proof,
            "accepting_cap_proof": False,
        }],
        "negative_vectors": serialization_negatives(statement, proof),
        "claim_boundary": {
            "candidate_c2_used_as_production_c_x": False,
            "outer_envelope_codec_implemented": True,
            "complete_pi_2_serialization_frozen": False,
            "production_proof_serialization_frozen": False,
            "production_proof_verified": False,
        },
    }


def build_pow_disposition() -> dict[str, object]:
    schema = preflight.pow_disposition_schema()
    budgets = []
    for query_bits in (0, 32, 64, 128):
        budgets.append({
            "q_H_log2": query_bits,
            "raw_degree_term_negative_log2": 182 - query_bits,
            "target_192_met_by_listed_raw_degree_term": 182 - query_bits >= 192,
            "complete_total_bound_available": False,
        })
    return {
        "format": schema["format"],
        "implementation_version": IMPLEMENTATION_VERSION,
        **schema["required_exact_fields"],
        "selected_disposition": {
            "kind": "implement_and_validate_paper_compatible_pow",
            "status": "selected_but_not_executable_under_current_architecture_guard",
            "reason": (
                "paper-compatible grinding requires the optimized unified BAVC/GGM tree; "
                "the fork commits with 18 independent trees"
            ),
        },
        "parameter_delta": {
            "current_tree_roots": 18,
            "current_total_leaves": 40_960,
            "paper_optimized_tree_roots": 1,
            "tree_groups": [
                {"count": 2, "leaves": 4_096},
                {"count": 16, "leaves": 2_048},
            ],
            "T_open": 174,
            "explicit_pow_bits": 9,
            "reported_total_pow_bits": "13.9",
            "current_profile_can_inherit_values_without_rebuild": False,
        },
        "complete_concrete_bound": {
            "available": False,
            "raw_degree_accept_probability_without_pow": "2^-182",
            "simple_addition_of_reported_pow_bits_permitted": False,
            "missing_terms": preflight.pow_security_profile_contract()[
                "required_bound_terms"
            ],
        },
        "query_budget_analysis": budgets,
        "rom_qrom_scope": {
            "paper_algorithm_anchor": (
                "ePrint 2024/490 Section 4: ctr is included in the final FS hash; "
                "decode the first lambda-w bits, require the remaining w bits zero, "
                "and retry if the unified BAVC opening exceeds T_open"
            ),
            "fork_anemoi_rom_justification_complete": False,
            "fork_qrom_reprogramming_bound_complete": False,
            "quantum_query_transcript_extractor_claimed": False,
        },
        "implementation_impact": {
            "system_architecture_changed_by_v2_32": False,
            "profile_changed_by_v2_32": False,
            "implementation_attempted": False,
            "required_future_change": (
                "new CAP namespace/profile with unified-tree commitment and a full replay, "
                "or separately authorized replacement parameters"
            ),
        },
        "independent_review_binding": {
            "attestation_present": False,
            "claim_promotion_authorized": False,
            "project_self_attestation_permitted": False,
        },
        "claim_boundary": {
            "fork_pow_implemented": False,
            "complete_concrete_security_bound_available": False,
            "cap_security_qualified": False,
            "independent_review_completed": False,
            "production_closed": False,
        },
    }


def build_implementation_evidence(
    source_paths: dict[str, Path],
) -> dict[str, object]:
    statement, proof = fixture()
    statement_bytes = statement.encode()
    proof_bytes = proof.encode()
    parsed_statement = implementation.CAPStatement.decode(statement_bytes)
    parsed_proof = implementation.CAPProofEnvelope.decode(proof_bytes)
    verify_result = implementation.verify(statement_bytes, proof_bytes)
    schema = preflight.implementation_evidence_schema()
    return {
        "format": schema["format"],
        "implementation_version": IMPLEMENTATION_VERSION,
        **schema["required_exact_fields"],
        "source_identities": {
            name: identity(path) for name, path in sorted(source_paths.items())
        },
        "prove_vectors": [{
            "id": "production_prover_unavailable",
            "proof_generated": False,
            "expected_failure": (
                "unified-GGM opening, counter grinding, and Protocol-11 response are missing"
            ),
        }],
        "verify_vectors": [{
            "id": "canonical_nonproof_fails_closed",
            "statement_parsed": parsed_statement == statement,
            "proof_outer_envelope_parsed": parsed_proof == proof,
            "accepted": verify_result.accepted,
            "failures": list(verify_result.failures),
            "accepting_production_vector": False,
        }],
        "serialization_vectors": [{
            "statement_bytes": len(statement_bytes),
            "statement_sha256": hashlib.sha256(statement_bytes).hexdigest(),
            "proof_bytes": len(proof_bytes),
            "proof_sha256": hashlib.sha256(proof_bytes).hexdigest(),
            "pi_2_inner_serialization_complete": False,
        }],
        "pow_vectors": [{
            "id": "paper_compatible_pow_unavailable",
            "executed": False,
            "verified": False,
            "synthetic_leading_zero_nonce_substituted": False,
        }],
        "mutation_vectors": mutation_vectors(statement, proof),
        "resource_measurements": {
            "measured_operation": "codec round-trip and fail-closed verify only",
            "elapsed_seconds_upper_bound": 1,
            "cpu_cores": 1,
            "relation_rows_replayed": 0,
            "proofs_generated": 0,
            "large_replay_started": False,
            "large_proving_run_started": False,
        },
        "claim_boundary": {
            "statement_candidate_codec_implemented": True,
            "outer_envelope_codec_implemented": True,
            "cap_prove_implemented": False,
            "cap_verify_implemented": False,
            "fork_pow_implemented": False,
            "all_mutations_algebraically_rejected": False,
            "complete_production_proof_vector_present": False,
            "implementation_evidence_complete": False,
            "system_architecture_changed": False,
            "ticket_lifecycle_changed": False,
            "pq_sat_auth_changed": False,
            "production_closed": False,
        },
    }


def write_artifacts(
    output: Path,
    blind_uov_paper: Path,
    bavc_paper: Path,
    dsd_paper: Path,
    specification: Path,
) -> dict[str, dict[str, object]]:
    require_identity(blind_uov_paper, BLIND_UOV_PAPER)
    require_identity(bavc_paper, BAVC_PAPER)
    require_identity(dsd_paper, DSD_PAPER)
    if specification.name != SPECIFICATION_FILENAME:
        raise ValueError("wrong specification filename")
    if not specification.is_file() or specification.read_bytes()[:5] != b"%PDF-":
        raise ValueError("specification PDF is missing or invalid")

    output.mkdir(parents=True, exist_ok=True)
    source_paths = {
        "implementation": preflight.ROOT / "src/pq_rbbc_cap_prove_verify.py",
        "implementation_tests": preflight.ROOT / "tests/test_pq_rbbc_cap_prove_verify.py",
        "artifact_generator": preflight.ROOT / "src/pq_rbbc_cap_prove_verify_artifacts.py",
        "preflight": preflight.ROOT / "src/pq_rbbc_cap_prove_verify_preflight.py",
        "blind_uov_paper": blind_uov_paper,
        "optimized_bavc_paper": bavc_paper,
        "dsd_explanatory_paper": dsd_paper,
        "specification": specification,
    }
    documents = {
        SERIALIZATION_FILENAME: build_serialization_candidate(),
        DISPOSITION_FILENAME: build_pow_disposition(),
        IMPLEMENTATION_FILENAME: build_implementation_evidence(source_paths),
    }
    for filename, document in documents.items():
        (output / filename).write_bytes(canonical_json(document))
    destination_spec = output / SPECIFICATION_FILENAME
    if specification.resolve() != destination_spec.resolve():
        destination_spec.write_bytes(specification.read_bytes())
    return {
        path.name: identity(path)
        for path in (
            destination_spec,
            output / SERIALIZATION_FILENAME,
            output / DISPOSITION_FILENAME,
            output / IMPLEMENTATION_FILENAME,
        )
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--blind-uov-paper", type=Path, required=True)
    parser.add_argument("--bavc-paper", type=Path, required=True)
    parser.add_argument("--dsd-paper", type=Path, required=True)
    parser.add_argument("--specification", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(write_artifacts(
        args.output,
        args.blind_uov_paper,
        args.bavc_paper,
        args.dsd_paper,
        args.specification,
    ), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
