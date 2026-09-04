#!/usr/bin/env python3
"""Candidate ROM straight-line extractor for the PQ-RBBC CAP commitment.

The extractor consumes only the ordered, full-value CAP oracle transcript and
the canonical commitment prefix.  It deliberately has no statement or final
proof parameter.  This is executable review material for v2.31, not a security
claim: the repository still lacks the final CAP Prove/Verify protocol needed
to establish that every accepted commitment is admissible.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Mapping, Sequence

import pq_rbbc_anemoi_sponge as sponge
import pq_rbbc_cap_commit as cap


IMPLEMENTATION_VERSION = "2.31"
RELATION_ID = "pq-rbbc/cap/straightline-extractor-candidate/v1"
APPEND_MAGIC = b"PQRBBC-CAP-APPEND-CANDIDATE-V1"

DOMAIN_BY_ID = {
    "seed_derive": cap.DOMAIN_SEED_DERIVE,
    "seed_commit": cap.DOMAIN_SEED_COMMIT,
    "tape_expand": cap.DOMAIN_TAPE_EXPAND,
    "h1": cap.DOMAIN_H1,
    "consistency_points": cap.DOMAIN_CONSISTENCY_POINTS,
    "h2": cap.DOMAIN_H2,
}
ID_BY_DOMAIN = {value: key for key, value in DOMAIN_BY_ID.items()}


class ExtractionFailure(ValueError):
    """Raised when the candidate extractor must fail closed."""


@dataclass(frozen=True)
class ParsedCommitment:
    salt: tuple[int, int]
    h2: int
    alpha: int
    delta_p: tuple[int, ...]
    delta_mhat: tuple[int, ...]


@dataclass(frozen=True)
class ParsedQuery:
    sequence_index: int
    domain_id: str
    fields: tuple[bytes, ...]
    output_bits: int
    output: int


def canonical_json(document: object) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def document_sha256(document: object) -> str:
    return hashlib.sha256(canonical_json(document)).hexdigest()


def _unpack_canonical(value: bytes, bits: int, label: str) -> int:
    if len(value) != (bits + 7) // 8:
        raise ExtractionFailure(f"{label}: wrong byte length")
    result = int.from_bytes(value, "little")
    if result >= 1 << bits:
        raise ExtractionFailure(f"{label}: noncanonical unused high bits")
    return result


def _decode_transcript(payload: bytes) -> tuple[bytes, ...]:
    if not payload.startswith(sponge.TRANSCRIPT_MAGIC):
        raise ExtractionFailure("oracle input: wrong transcript magic")
    offset = len(sponge.TRANSCRIPT_MAGIC)
    if len(payload) < offset + 2:
        raise ExtractionFailure("oracle input: truncated field count")
    field_count = int.from_bytes(payload[offset : offset + 2], "little")
    offset += 2
    fields: list[bytes] = []
    for _ in range(field_count):
        if len(payload) < offset + 8:
            raise ExtractionFailure("oracle input: truncated field length")
        length = int.from_bytes(payload[offset : offset + 8], "little")
        offset += 8
        if len(payload) < offset + length:
            raise ExtractionFailure("oracle input: truncated field")
        fields.append(payload[offset : offset + length])
        offset += length
    if offset != len(payload):
        raise ExtractionFailure("oracle input: trailing bytes")
    result = tuple(fields)
    if sponge.encode_transcript(result) != payload:
        raise ExtractionFailure("oracle input: noncanonical tuple encoding")
    return result


def transcript_records(calls: Sequence[cap.XOFCall]) -> list[dict[str, object]]:
    """Export every query with full input and output values, without labels."""

    records: list[dict[str, object]] = []
    for sequence_index, call in enumerate(calls):
        try:
            domain_id = ID_BY_DOMAIN[call.domain]
        except KeyError as error:
            raise ExtractionFailure("unknown CAP oracle domain") from error
        records.append({
            "sequence_index": sequence_index,
            "domain_id": domain_id,
            "canonical_encoded_input": call.payload.hex(),
            "output_bits": call.output_bits,
            "canonical_output": cap.pack_int(
                call.output, call.output_bits
            ).hex(),
        })
    return records


def parse_transcript(
    records: Sequence[Mapping[str, object]],
) -> tuple[ParsedQuery, ...]:
    expected_widths = {
        "seed_derive": 2 * cap.SEED_BITS,
        "seed_commit": cap.HASH_BITS,
        "tape_expand": cap.PRODUCTION_PARAMETERS.random_polynomial_bits,
        "h1": cap.HASH_BITS,
        "consistency_points": cap.PRODUCTION_PARAMETERS.consistency_bits,
        "h2": cap.HASH_BITS,
    }
    reduced_tape_bits = cap.REDUCED_TEST_PARAMETERS.random_polynomial_bits
    reduced_consistency_bits = cap.REDUCED_TEST_PARAMETERS.consistency_bits
    parsed: list[ParsedQuery] = []
    seen_inputs: dict[tuple[str, bytes, int], int] = {}
    exact_keys = {
        "sequence_index",
        "domain_id",
        "canonical_encoded_input",
        "output_bits",
        "canonical_output",
    }
    for expected_index, record in enumerate(records):
        if set(record) != exact_keys:
            raise ExtractionFailure("oracle record: wrong field set")
        if record["sequence_index"] != expected_index:
            raise ExtractionFailure("oracle record: non-contiguous order")
        domain_id = record["domain_id"]
        if not isinstance(domain_id, str) or domain_id not in DOMAIN_BY_ID:
            raise ExtractionFailure("oracle record: unknown domain")
        output_bits = record["output_bits"]
        if not isinstance(output_bits, int):
            raise ExtractionFailure("oracle record: non-integer output width")
        permitted_widths = {expected_widths[domain_id]}
        if domain_id == "tape_expand":
            permitted_widths.add(reduced_tape_bits)
        if domain_id == "consistency_points":
            permitted_widths.add(reduced_consistency_bits)
        if output_bits not in permitted_widths:
            raise ExtractionFailure("oracle record: wrong output width")
        encoded_input = record["canonical_encoded_input"]
        encoded_output = record["canonical_output"]
        if not isinstance(encoded_input, str) or not isinstance(encoded_output, str):
            raise ExtractionFailure("oracle record: values must be hex strings")
        try:
            payload = bytes.fromhex(encoded_input)
            output_bytes = bytes.fromhex(encoded_output)
        except ValueError as error:
            raise ExtractionFailure("oracle record: invalid hex") from error
        if payload.hex() != encoded_input or output_bytes.hex() != encoded_output:
            raise ExtractionFailure("oracle record: noncanonical hex")
        fields = _decode_transcript(payload)
        output = _unpack_canonical(output_bytes, output_bits, "oracle output")
        key = (domain_id, payload, output_bits)
        previous = seen_inputs.get(key)
        if previous is not None and previous != output:
            raise ExtractionFailure("oracle record: conflicting repeated query")
        seen_inputs[key] = output
        parsed.append(
            ParsedQuery(expected_index, domain_id, fields, output_bits, output)
        )
    return tuple(parsed)


def parse_commitment(
    encoded: bytes, parameters: cap.CAPParameters
) -> ParsedCommitment:
    offset = 0

    def take(length: int, label: str) -> bytes:
        nonlocal offset
        if len(encoded) < offset + length:
            raise ExtractionFailure(f"commitment: truncated {label}")
        value = encoded[offset : offset + length]
        offset += length
        return value

    if take(len(cap.COMMITMENT_MAGIC), "magic") != cap.COMMITMENT_MAGIC:
        raise ExtractionFailure("commitment: wrong magic")
    if int.from_bytes(take(2, "version"), "little") != 1:
        raise ExtractionFailure("commitment: wrong version")
    fingerprint = take(32, "profile fingerprint").hex()
    if fingerprint != cap.profile_fingerprint(parameters):
        raise ExtractionFailure("commitment: wrong profile fingerprint")
    salt = (
        _unpack_canonical(
            take(cap.field.FIELD_ELEMENT_BYTES, "salt[0]"),
            cap.SEED_BITS,
            "salt[0]",
        ),
        _unpack_canonical(
            take(cap.field.FIELD_ELEMENT_BYTES, "salt[1]"),
            cap.SEED_BITS,
            "salt[1]",
        ),
    )
    h2 = _unpack_canonical(
        take((cap.HASH_BITS + 7) // 8, "h2"), cap.HASH_BITS, "h2"
    )
    correction_length = int.from_bytes(take(4, "correction length"), "little")
    corrections = take(correction_length, "corrections")
    if offset != len(encoded):
        raise ExtractionFailure("commitment: trailing bytes")

    alpha_bytes = (parameters.consistency_bits + 7) // 8
    witness_bytes = (parameters.witness_bits + 7) // 8
    expected_length = alpha_bytes + (parameters.tree_count - 1) * (
        witness_bytes + alpha_bytes
    )
    if correction_length != expected_length:
        raise ExtractionFailure("commitment: wrong correction length")
    correction_offset = 0

    def correction(bits: int, label: str) -> int:
        nonlocal correction_offset
        size = (bits + 7) // 8
        value = corrections[correction_offset : correction_offset + size]
        correction_offset += size
        return _unpack_canonical(value, bits, label)

    alpha = correction(parameters.consistency_bits, "alpha")
    delta_p: list[int] = []
    delta_mhat: list[int] = []
    for tree_index in range(1, parameters.tree_count):
        delta_p.append(
            correction(parameters.witness_bits, f"delta_p[{tree_index}]")
        )
        delta_mhat.append(
            correction(
                parameters.consistency_bits,
                f"delta_mhat[{tree_index}]",
            )
        )
    if correction_offset != len(corrections):
        raise ExtractionFailure("commitment: correction parser mismatch")
    return ParsedCommitment(salt, h2, alpha, tuple(delta_p), tuple(delta_mhat))


def _parse_tree_component(
    component: bytes,
    expected_index: int,
    expected_leaves: int,
    expected_degree: int,
) -> tuple[tuple[int, int], ...]:
    header_bytes = 8
    commitment_bytes = 2 * cap.field.FIELD_ELEMENT_BYTES
    if len(component) != header_bytes + expected_leaves * commitment_bytes:
        raise ExtractionFailure(f"tree[{expected_index}]: wrong component length")
    if int.from_bytes(component[0:2], "little") != expected_index:
        raise ExtractionFailure(f"tree[{expected_index}]: wrong index")
    if int.from_bytes(component[2:6], "little") != expected_leaves:
        raise ExtractionFailure(f"tree[{expected_index}]: wrong leaf count")
    if int.from_bytes(component[6:8], "little") != expected_degree:
        raise ExtractionFailure(f"tree[{expected_index}]: wrong extension degree")
    result: list[tuple[int, int]] = []
    offset = header_bytes
    for leaf_index in range(1, expected_leaves + 1):
        left = _unpack_canonical(
            component[offset : offset + cap.field.FIELD_ELEMENT_BYTES],
            cap.SEED_BITS,
            f"tree[{expected_index}].commit[{leaf_index}].left",
        )
        offset += cap.field.FIELD_ELEMENT_BYTES
        right = _unpack_canonical(
            component[offset : offset + cap.field.FIELD_ELEMENT_BYTES],
            cap.SEED_BITS,
            f"tree[{expected_index}].commit[{leaf_index}].right",
        )
        offset += cap.field.FIELD_ELEMENT_BYTES
        result.append((left, right))
    return tuple(result)


def _query_indexes(
    queries: Sequence[ParsedQuery],
) -> tuple[
    dict[tuple[str, int], list[ParsedQuery]],
    dict[tuple[str, tuple[bytes, ...]], list[ParsedQuery]],
]:
    by_output: dict[tuple[str, int], list[ParsedQuery]] = {}
    by_input: dict[tuple[str, tuple[bytes, ...]], list[ParsedQuery]] = {}
    for query in queries:
        by_output.setdefault((query.domain_id, query.output), []).append(query)
        by_input.setdefault((query.domain_id, query.fields), []).append(query)
    return by_output, by_input


def _unique_output_preimage(
    by_output: Mapping[tuple[str, int], Sequence[ParsedQuery]],
    domain_id: str,
    output: int,
    label: str,
) -> ParsedQuery:
    matches = by_output.get((domain_id, output), ())
    if len(matches) != 1:
        raise ExtractionFailure(f"{label}: expected one oracle preimage")
    return matches[0]


def _unique_input_query(
    by_input: Mapping[
        tuple[str, tuple[bytes, ...]], Sequence[ParsedQuery]
    ],
    domain_id: str,
    fields: tuple[bytes, ...],
    label: str,
) -> ParsedQuery:
    matches = by_input.get((domain_id, fields), ())
    if len(matches) != 1:
        raise ExtractionFailure(f"{label}: expected one oracle query")
    return matches[0]


def _recover_plain(
    by_output: Mapping[tuple[str, int], Sequence[ParsedQuery]],
    by_input: Mapping[
        tuple[str, tuple[bytes, ...]], Sequence[ParsedQuery]
    ],
    parsed_commitment: ParsedCommitment,
    commitments: Sequence[tuple[int, int]],
    tree_index: int,
    parameters: cap.CAPParameters,
) -> tuple[int, tuple[int, ...]] | None:
    salt_field = cap.hash_bytes(
        parsed_commitment.salt[0]
        | (parsed_commitment.salt[1] << cap.SEED_BITS)
    )
    plain = 0
    tapes: list[int] = []
    for leaf_index, (left, right) in enumerate(commitments, start=1):
        committed_seed = left | (right << cap.SEED_BITS)
        matches = by_output.get(("seed_commit", committed_seed), ())
        if not matches:
            return None
        if len(matches) != 1:
            raise ExtractionFailure(
                f"tree[{tree_index}].leaf[{leaf_index}]: ambiguous seed preimage"
            )
        query = matches[0]
        meta = cap._meta(tree_index, 0, leaf_index)
        if len(query.fields) != 3 or query.fields[0] != salt_field:
            raise ExtractionFailure(
                f"tree[{tree_index}].leaf[{leaf_index}]: wrong seed framing"
            )
        if query.fields[2] != meta:
            raise ExtractionFailure(
                f"tree[{tree_index}].leaf[{leaf_index}]: wrong leaf metadata"
            )
        seed = _unpack_canonical(
            query.fields[1], cap.SEED_BITS, f"tree[{tree_index}].seed"
        )
        tape_query = _unique_input_query(
            by_input,
            "tape_expand",
            (cap.field_bytes(seed), meta),
            f"tree[{tree_index}].leaf[{leaf_index}].tape",
        )
        if tape_query.output_bits != parameters.random_polynomial_bits:
            raise ExtractionFailure(f"tree[{tree_index}]: wrong tape width")
        plain ^= tape_query.output
        tapes.append(tape_query.output)
    return plain, tuple(tapes)


def _extract_witness(
    records: Sequence[Mapping[str, object]],
    commitment: bytes,
    parameters: cap.CAPParameters,
) -> int:
    parsed_commitment = parse_commitment(commitment, parameters)
    queries = parse_transcript(records)
    by_output, by_input = _query_indexes(queries)
    h2_query = _unique_output_preimage(
        by_output, "h2", parsed_commitment.h2, "h2"
    )
    if len(h2_query.fields) != parameters.tree_count + 1:
        raise ExtractionFailure("h2: wrong field count")
    h1 = _unpack_canonical(h2_query.fields[0], cap.HASH_BITS, "h1 digest")
    h1_query = _unique_output_preimage(by_output, "h1", h1, "h1")
    if len(h1_query.fields) != parameters.tree_count + 2:
        raise ExtractionFailure("h1: wrong field count")
    fingerprint = bytes.fromhex(cap.profile_fingerprint(parameters))
    if h1_query.fields[0] != fingerprint:
        raise ExtractionFailure("h1: wrong profile fingerprint")
    expected_corrections = cap._correction_component(
        parsed_commitment.delta_p,
        parsed_commitment.delta_mhat,
        parameters,
    )
    if h1_query.fields[-1] != expected_corrections:
        raise ExtractionFailure("h1: correction data disagrees with commitment")

    point_query = _unique_input_query(
        by_input,
        "consistency_points",
        (cap.hash_bytes(h1), fingerprint),
        "consistency points",
    )
    if point_query.output_bits != parameters.consistency_bits:
        raise ExtractionFailure("consistency points: wrong output width")
    points = tuple(
        (point_query.output >> (index * cap.field.FIELD_DEGREE))
        & cap.field.FIELD_MASK
        for index in range(parameters.consistency_points)
    )
    if any(point == 0 for point in points) or len(set(points)) != len(points):
        raise ExtractionFailure("consistency points: degenerate output")

    leaf_counts = parameters.expanded_leaf_counts()
    extension_degrees = parameters.expanded_extension_degrees()
    tree_commitments = tuple(
        _parse_tree_component(
            h1_query.fields[tree_index + 1],
            tree_index,
            leaves,
            extension_degree,
        )
        for tree_index, (leaves, extension_degree) in enumerate(
            zip(leaf_counts, extension_degrees)
        )
    )
    candidates: list[int] = []
    complete_by_shape: dict[tuple[int, int], int] = {}
    witness_mask = (1 << parameters.witness_bits) - 1
    consistency_mask = (1 << parameters.consistency_bits) - 1
    mhat_shift = parameters.witness_bits + (
        parameters.degree - 1
    ) * parameters.rho
    for tree_index, (leaves, extension_degree, commitments) in enumerate(
        zip(leaf_counts, extension_degrees, tree_commitments)
    ):
        recovered = _recover_plain(
            by_output,
            by_input,
            parsed_commitment,
            commitments,
            tree_index,
            parameters,
        )
        if recovered is None:
            continue
        plain, tapes = recovered
        complete_by_shape[(leaves, extension_degree)] = (
            complete_by_shape.get((leaves, extension_degree), 0) + 1
        )
        p_plain = plain & witness_mask
        mhat_plain = (plain >> mhat_shift) & consistency_mask
        if tree_index:
            p_plain ^= parsed_commitment.delta_p[tree_index - 1]
            mhat_plain ^= parsed_commitment.delta_mhat[tree_index - 1]
        alpha = cap._linear_hash_vector(
            p_plain, parameters.witness_bits, points
        ) ^ mhat_plain
        if alpha != parsed_commitment.alpha:
            continue

        masks = [0] * parameters.random_polynomial_bits
        inverse_points = tuple(
            cap.gf2m_inv(leaf_index, extension_degree)
            for leaf_index in range(1, leaves + 1)
        )
        for tape, inverse in zip(tapes, inverse_points):
            set_bits = tape
            while set_bits:
                low_bit = set_bits & -set_bits
                coordinate = low_bit.bit_length() - 1
                masks[coordinate] ^= inverse
                set_bits ^= low_bit
        raw_p_masks = masks[: parameters.witness_bits]
        raw_mhat_masks = masks[
            mhat_shift : mhat_shift + parameters.consistency_bits
        ]
        hashed_masks = cap._linear_hash_masks(
            raw_p_masks,
            parameters.witness_bits,
            extension_degree,
            points,
        )
        xi_masks = tuple(
            left ^ right
            for left, right in zip(hashed_masks, raw_mhat_masks)
        )
        expected_xi = cap._xi_component(
            parsed_commitment.alpha,
            xi_masks,
            parameters.consistency_bits,
            extension_degree,
        )
        if h2_query.fields[tree_index + 1] != expected_xi:
            continue
        candidates.append(p_plain)

    if not candidates:
        raise ExtractionFailure("no complete consistent tree candidate")
    unique_candidates = set(candidates)
    if len(unique_candidates) != 1:
        raise ExtractionFailure("multiple distinct consistent witnesses")
    if parameters is cap.PRODUCTION_PARAMETERS:
        expected_shapes = {(4096, 13), (2048, 12)}
        if not expected_shapes.issubset(complete_by_shape):
            raise ExtractionFailure("production mixed-tree coverage incomplete")
    return unique_candidates.pop()


def extract_ext1(
    records: Sequence[Mapping[str, object]],
    c1: bytes,
    parameters: cap.CAPParameters = cap.PRODUCTION_PARAMETERS,
) -> int:
    witness = _extract_witness(records, c1, parameters)
    return witness & ((1 << parameters.mask_bits) - 1)


def serialize_candidate_append(
    delta_x: int, parameters: cap.CAPParameters
) -> bytes:
    if not 0 <= delta_x < 1 << parameters.appended_signature_bits:
        raise ValueError("append delta does not fit")
    return (
        APPEND_MAGIC
        + (1).to_bytes(2, "little")
        + bytes.fromhex(cap.profile_fingerprint(parameters))
        + parameters.appended_signature_bits.to_bytes(4, "little")
        + cap.pack_int(delta_x, parameters.appended_signature_bits)
    )


def parse_candidate_append(encoded: bytes, parameters: cap.CAPParameters) -> int:
    expected_length = (
        len(APPEND_MAGIC)
        + 2
        + 32
        + 4
        + (parameters.appended_signature_bits + 7) // 8
    )
    if len(encoded) != expected_length:
        raise ExtractionFailure("append: wrong byte length")
    offset = len(APPEND_MAGIC)
    if encoded[:offset] != APPEND_MAGIC:
        raise ExtractionFailure("append: wrong magic")
    if int.from_bytes(encoded[offset : offset + 2], "little") != 1:
        raise ExtractionFailure("append: wrong version")
    offset += 2
    if encoded[offset : offset + 32].hex() != cap.profile_fingerprint(parameters):
        raise ExtractionFailure("append: wrong profile fingerprint")
    offset += 32
    bits = int.from_bytes(encoded[offset : offset + 4], "little")
    offset += 4
    if bits != parameters.appended_signature_bits:
        raise ExtractionFailure("append: wrong bit width")
    return _unpack_canonical(encoded[offset:], bits, "append delta")


def extract_ext2(
    records: Sequence[Mapping[str, object]],
    c1: bytes,
    c2: bytes,
    parameters: cap.CAPParameters = cap.PRODUCTION_PARAMETERS,
) -> tuple[int, int]:
    witness = _extract_witness(records, c1, parameters)
    r = witness & ((1 << parameters.mask_bits) - 1)
    append_base = (
        witness >> parameters.mask_bits
    ) & ((1 << parameters.appended_signature_bits) - 1)
    delta_x = parse_candidate_append(c2, parameters)
    return r, append_base ^ delta_x
