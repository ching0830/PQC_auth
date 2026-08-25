#!/usr/bin/env python3
"""Reference CAP.Commit core for the independent PQ-RBBC v2.8 fork.

This module instantiates the *initial commitment* part of Protocols 8--10 in
ePrint 2025/895, but under an independently named and serialized profile.  It
does not claim bit-exact Blind-UOV compatibility.  The production parameter
shape is the paper's NIST-III/Shorter TCitH topology: two 4096-leaf trees and
sixteen 2048-leaf trees, committing an upper-bound witness of 576 + 1472 =
2048 bits.

The implementation covers salted GGM seed derivation, leaf commitments, tape
expansion, random degree-one polynomial coefficients, cross-repetition
corrections, the masked polynomial consistency digest, canonical commitment
serialization, derivation of the 576-bit mask, and the later signature append
delta.  All symmetric calls use the v2.0 Anemoi-193/336 sponge with explicit
domains and injective tuple framing.

The full production instance requires more than one hundred thousand XOF
calls and is intentionally not executed by the default test suite.  A reduced,
explicitly non-secure topology exercises the same code paths and freezes test
vectors.  Production closure remains false until the full native row stream
and inter-call wire identities are materialized and independently reviewed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_anemoi_sponge as sponge


IMPLEMENTATION_VERSION = "2.8"
PROFILE_NAME = "PQ-RBBC-CAP-TCitH-III/Anemoi-193-336-v1"
PROFILE_RELATION_ID = "pq-rbbc/cap/tcith-iii/anemoi-193-336/v1"
COMMITMENT_MAGIC = b"PQRBBC-CAP-COMMIT-V1"
RANDOMNESS_MAGIC = b"PQRBBC-CAP-RANDOM-V1"

DOMAIN_SEED_DERIVE = b"PQ-RBBC/v2.1/CAP/seed-derive"
DOMAIN_SEED_COMMIT = b"PQ-RBBC/v2.1/CAP/seed-commit"
DOMAIN_TAPE_EXPAND = b"PQ-RBBC/v2.1/CAP/tape-expand"
DOMAIN_H1 = b"PQ-RBBC/v2.1/CAP/h1"
DOMAIN_CONSISTENCY_POINTS = b"PQ-RBBC/v2.1/CAP/H-points"
DOMAIN_H2 = b"PQ-RBBC/v2.1/CAP/h2"

SEED_BITS = field.FIELD_DEGREE
HASH_BITS = 2 * field.FIELD_DEGREE
HASH_BYTES = (HASH_BITS + 7) // 8
CONSISTENCY_POINTS = 2
CONSISTENCY_BITS = CONSISTENCY_POINTS * field.FIELD_DEGREE


@dataclass(frozen=True)
class TreeSpec:
    count: int
    leaves: int

    @property
    def extension_degree(self) -> int:
        # Protocol 8 needs N distinct nonzero evaluation points.  For N=2^k,
        # degree k is one element short, so the safe minimum is k+1.
        return math.ceil(math.log2(self.leaves + 1))


@dataclass(frozen=True)
class CAPParameters:
    name: str
    security_bits: int
    mask_bits: int
    appended_signature_bits: int
    degree: int
    rho: int
    consistency_points: int
    tree_specs: tuple[TreeSpec, ...]
    secure_profile: bool

    @property
    def witness_bits(self) -> int:
        return self.mask_bits + self.appended_signature_bits

    @property
    def consistency_bits(self) -> int:
        return self.consistency_points * field.FIELD_DEGREE

    @property
    def random_polynomial_bits(self) -> int:
        return (
            self.witness_bits
            + (self.degree - 1) * self.rho
            + self.consistency_bits
        )

    @property
    def tree_count(self) -> int:
        return sum(spec.count for spec in self.tree_specs)

    @property
    def leaf_count(self) -> int:
        return sum(spec.count * spec.leaves for spec in self.tree_specs)

    def expanded_leaf_counts(self) -> tuple[int, ...]:
        return tuple(
            leaves
            for spec in self.tree_specs
            for leaves in (spec.leaves,) * spec.count
        )

    def expanded_extension_degrees(self) -> tuple[int, ...]:
        return tuple(
            spec.extension_degree
            for spec in self.tree_specs
            for _ in range(spec.count)
        )


PRODUCTION_PARAMETERS = CAPParameters(
    name=PROFILE_NAME,
    security_bits=192,
    mask_bits=576,
    appended_signature_bits=1472,
    degree=2,
    # max(ceil(192/13), ceil(192/12)) for the mixed safe extension degrees.
    rho=16,
    consistency_points=CONSISTENCY_POINTS,
    tree_specs=(TreeSpec(2, 1 << 12), TreeSpec(16, 1 << 11)),
    secure_profile=True,
)

REDUCED_TEST_PARAMETERS = CAPParameters(
    name="PQ-RBBC-CAP-REDUCED-TEST-ONLY",
    security_bits=0,
    mask_bits=32,
    appended_signature_bits=32,
    degree=2,
    rho=2,
    consistency_points=1,
    tree_specs=(TreeSpec(2, 4),),
    secure_profile=False,
)

# Lexicographically first irreducible binary polynomials found for the safe
# extension degrees.  Integers encode polynomial coefficients LSB-first.
EXTENSION_MODULI = {
    3: 0b1011,                  # x^3 + x + 1 (reduced test profile)
    12: 0x1009,                # x^12 + x^3 + 1
    13: 0x201B,                # x^13 + x^4 + x^3 + x + 1
}


def bits_to_int(bits: Sequence[int]) -> int:
    value = 0
    for index, bit in enumerate(bits):
        if bit not in (0, 1):
            raise ValueError("non-binary value")
        value |= bit << index
    return value


def int_to_bits(value: int, bit_length: int) -> tuple[int, ...]:
    if value < 0 or value >= 1 << bit_length:
        raise ValueError("integer does not fit the declared bit length")
    return tuple((value >> index) & 1 for index in range(bit_length))


def pack_int(value: int, bit_length: int) -> bytes:
    return value.to_bytes((bit_length + 7) // 8, "little")


def field_bytes(value: int) -> bytes:
    if value < 0 or value > field.FIELD_MASK:
        raise ValueError("non-canonical GF(2^193) element")
    return value.to_bytes(field.FIELD_ELEMENT_BYTES, "little")


def hash_bytes(value: int, bit_length: int = HASH_BITS) -> bytes:
    return pack_int(value, bit_length)


def _meta(tree_index: int, level_or_leaf: int, node_index: int) -> bytes:
    if not 0 <= tree_index < 1 << 16:
        raise ValueError("tree index out of range")
    if not 0 <= level_or_leaf < 1 << 16:
        raise ValueError("level/leaf parameter out of range")
    if not 0 <= node_index < 1 << 32:
        raise ValueError("node index out of range")
    return (
        tree_index.to_bytes(2, "little")
        + level_or_leaf.to_bytes(2, "little")
        + node_index.to_bytes(4, "little")
    )


@dataclass(frozen=True)
class XOFCall:
    label: str
    domain: bytes
    fields: tuple[bytes, ...]
    output_bits: int
    output: int

    @property
    def payload(self) -> bytes:
        return sponge.encode_transcript(self.fields)


class XOFRecorder:
    def __init__(self) -> None:
        self.calls: list[XOFCall] = []

    def call(
        self,
        label: str,
        domain: bytes,
        components: Sequence[bytes],
        output_bits: int,
    ) -> int:
        output_bytes = (output_bits + 7) // 8
        payload = sponge.encode_transcript(tuple(components))
        raw = sponge.evaluate_sponge(domain, payload, output_bytes)
        output = int.from_bytes(raw, "little") & ((1 << output_bits) - 1)
        self.calls.append(
            XOFCall(label, domain, tuple(components), output_bits, output)
        )
        return output


def _gf2m_reduce(value: int, degree: int, modulus: int) -> int:
    while value.bit_length() - 1 >= degree:
        value ^= modulus << (value.bit_length() - 1 - degree)
    return value


def gf2m_mul(left: int, right: int, degree: int) -> int:
    modulus = EXTENSION_MODULI[degree]
    if not 0 <= left < 1 << degree or not 0 <= right < 1 << degree:
        raise ValueError("extension-field operand out of range")
    product = 0
    multiplier = right
    shift = 0
    while multiplier:
        if multiplier & 1:
            product ^= left << shift
        multiplier >>= 1
        shift += 1
    return _gf2m_reduce(product, degree, modulus)


def gf2m_inv(value: int, degree: int) -> int:
    if value == 0:
        raise ZeroDivisionError("zero evaluation point")
    modulus = EXTENSION_MODULI[degree]
    u, v = value, modulus
    g_u, g_v = 1, 0
    while u != 1:
        shift = u.bit_length() - v.bit_length()
        if shift < 0:
            u, v = v, u
            g_u, g_v = g_v, g_u
            shift = -shift
        u ^= v << shift
        g_u ^= g_v << shift
    return _gf2m_reduce(g_u, degree, modulus)


def expand_tree(
    salt: tuple[int, int],
    roots: tuple[int, int],
    tree_index: int,
    leaves: int,
    recorder: XOFRecorder,
) -> tuple[int, ...]:
    if leaves < 2 or leaves & (leaves - 1):
        raise ValueError("tree must have a power-of-two leaf count >= 2")
    nodes = list(roots)
    level = 2
    while len(nodes) < leaves:
        children: list[int] = []
        for node_index, parent in enumerate(nodes, start=1):
            output = recorder.call(
                f"tree[{tree_index}].derive[{level},{node_index}]",
                DOMAIN_SEED_DERIVE,
                (
                    hash_bytes(salt[0] | (salt[1] << SEED_BITS)),
                    field_bytes(parent),
                    _meta(tree_index, level, node_index),
                ),
                2 * SEED_BITS,
            )
            children.extend((output & field.FIELD_MASK, output >> SEED_BITS))
        nodes = children
        level += 1
    return tuple(nodes)


def seed_commit(
    salt: tuple[int, int],
    seed: int,
    tree_index: int,
    leaf_index: int,
    recorder: XOFRecorder,
) -> tuple[int, int]:
    output = recorder.call(
        f"tree[{tree_index}].leaf[{leaf_index}].commit",
        DOMAIN_SEED_COMMIT,
        (
            hash_bytes(salt[0] | (salt[1] << SEED_BITS)),
            field_bytes(seed),
            _meta(tree_index, 0, leaf_index),
        ),
        HASH_BITS,
    )
    return output & field.FIELD_MASK, output >> field.FIELD_DEGREE


def expand_tape(
    seed: int,
    tree_index: int,
    leaf_index: int,
    tape_bits: int,
    recorder: XOFRecorder,
) -> int:
    return recorder.call(
        f"tree[{tree_index}].leaf[{leaf_index}].tape",
        DOMAIN_TAPE_EXPAND,
        (field_bytes(seed), _meta(tree_index, 0, leaf_index)),
        tape_bits,
    )


@dataclass(frozen=True)
class CAPRandomness:
    salt: tuple[int, int]
    roots: tuple[tuple[int, int], ...]

    def serialize(self, parameters: CAPParameters) -> bytes:
        if len(self.roots) != parameters.tree_count:
            raise ValueError("wrong number of root pairs")
        payload = bytearray(RANDOMNESS_MAGIC)
        payload.extend(profile_fingerprint(parameters).encode("ascii"))
        payload.extend(field_bytes(self.salt[0]))
        payload.extend(field_bytes(self.salt[1]))
        payload.extend(parameters.tree_count.to_bytes(2, "little"))
        for left, right in self.roots:
            payload.extend(field_bytes(left))
            payload.extend(field_bytes(right))
        return bytes(payload)


def deterministic_randomness(
    parameters: CAPParameters,
    label: bytes = b"PQ-RBBC/v2.1/frozen-cap-randomness",
) -> CAPRandomness:
    count = 2 + 2 * parameters.tree_count
    raw = hashlib.shake_256(label + profile_fingerprint(parameters).encode()).digest(
        count * field.FIELD_ELEMENT_BYTES
    )
    values = []
    for index in range(count):
        chunk = raw[
            index * field.FIELD_ELEMENT_BYTES :
            (index + 1) * field.FIELD_ELEMENT_BYTES
        ]
        values.append(int.from_bytes(chunk, "little") & field.FIELD_MASK)
    return CAPRandomness(
        salt=(values[0], values[1]),
        roots=tuple(
            (values[2 + 2 * index], values[3 + 2 * index])
            for index in range(parameters.tree_count)
        ),
    )


@dataclass(frozen=True)
class TreePolynomial:
    leaves: int
    extension_degree: int
    commitments: tuple[tuple[int, int], ...]
    plain: int
    masks: tuple[int, ...]


@dataclass(frozen=True)
class CAPCommitment:
    parameters_fingerprint: str
    salt: tuple[int, int]
    h1: int
    h2: int
    alpha: int
    delta_p: tuple[int, ...]
    delta_mhat: tuple[int, ...]
    derived_mask: int
    append_base: int
    encoded: bytes

    def append_signature(self, signature: int, signature_bits: int) -> int:
        if signature < 0 or signature >= 1 << signature_bits:
            raise ValueError("signature witness does not fit")
        return signature ^ self.append_base

    def recover_appended_signature(self, delta: int) -> int:
        return delta ^ self.append_base


@dataclass(frozen=True)
class CAPExecution:
    commitment: CAPCommitment
    tree_polynomials: tuple[TreePolynomial, ...]
    xof_calls: tuple[XOFCall, ...]


def _tree_component(
    tree_index: int,
    polynomial: TreePolynomial,
) -> bytes:
    payload = bytearray()
    payload.extend(tree_index.to_bytes(2, "little"))
    payload.extend(polynomial.leaves.to_bytes(4, "little"))
    payload.extend(polynomial.extension_degree.to_bytes(2, "little"))
    for left, right in polynomial.commitments:
        payload.extend(field_bytes(left))
        payload.extend(field_bytes(right))
    return bytes(payload)


def _correction_component(
    delta_p: Sequence[int],
    delta_mhat: Sequence[int],
    parameters: CAPParameters,
) -> bytes:
    bits = bytearray()
    for left, right in zip(delta_p, delta_mhat):
        bits.extend(pack_int(left, parameters.witness_bits))
        bits.extend(pack_int(right, parameters.consistency_bits))
    return (
        len(delta_p).to_bytes(2, "little")
        + parameters.witness_bits.to_bytes(4, "little")
        + parameters.consistency_bits.to_bytes(4, "little")
        + bytes(bits)
    )


def _poly_hash(vector: int, vector_bits: int, point: int) -> int:
    coefficients = []
    for offset in range(0, vector_bits, field.FIELD_DEGREE):
        take = min(field.FIELD_DEGREE, vector_bits - offset)
        coefficients.append((vector >> offset) & ((1 << take) - 1))
    result = 0
    for coefficient in reversed(coefficients):
        result = field.fmul(result, point) ^ coefficient
    return result


def _linear_hash_vector(vector: int, vector_bits: int, points: Sequence[int]) -> int:
    return sum(
        _poly_hash(vector, vector_bits, point) << (index * field.FIELD_DEGREE)
        for index, point in enumerate(points)
    )


def _linear_hash_masks(
    masks: Sequence[int],
    vector_bits: int,
    extension_degree: int,
    points: Sequence[int],
) -> tuple[int, ...]:
    output_bits = len(points) * field.FIELD_DEGREE
    result = [0] * output_bits
    for extension_bit in range(extension_degree):
        bit_slice = sum(
            ((mask >> extension_bit) & 1) << index
            for index, mask in enumerate(masks[:vector_bits])
        )
        hashed = _linear_hash_vector(bit_slice, vector_bits, points)
        for output_bit in range(output_bits):
            result[output_bit] |= ((hashed >> output_bit) & 1) << extension_bit
    return tuple(result)


def _xi_component(
    alpha: int,
    xi_masks: Sequence[int],
    consistency_bits: int,
    extension_degree: int,
) -> bytes:
    packed_masks = sum(
        mask << (index * extension_degree)
        for index, mask in enumerate(xi_masks)
    )
    return (
        consistency_bits.to_bytes(4, "little")
        + extension_degree.to_bytes(2, "little")
        + pack_int(alpha, consistency_bits)
        + pack_int(packed_masks, consistency_bits * extension_degree)
    )


def serialize_commitment(
    parameters: CAPParameters,
    salt: tuple[int, int],
    h2: int,
    alpha: int,
    delta_p: Sequence[int],
    delta_mhat: Sequence[int],
) -> bytes:
    corrections = bytearray(pack_int(alpha, parameters.consistency_bits))
    for left, right in zip(delta_p, delta_mhat):
        corrections.extend(pack_int(left, parameters.witness_bits))
        corrections.extend(pack_int(right, parameters.consistency_bits))
    result = bytearray(COMMITMENT_MAGIC)
    result.extend((1).to_bytes(2, "little"))
    result.extend(bytes.fromhex(profile_fingerprint(parameters)))
    result.extend(field_bytes(salt[0]))
    result.extend(field_bytes(salt[1]))
    result.extend(hash_bytes(h2))
    result.extend(len(corrections).to_bytes(4, "little"))
    result.extend(corrections)
    return bytes(result)


def execute_cap_commit(
    parameters: CAPParameters,
    randomness: CAPRandomness,
    *,
    allow_large: bool = False,
) -> CAPExecution:
    if parameters.secure_profile and not allow_large:
        raise RuntimeError(
            "production topology is intentionally opt-in; use allow_large=True"
        )
    if parameters.consistency_points not in (1, 2):
        raise ValueError("this implementation supports one or two consistency points")
    if len(randomness.roots) != parameters.tree_count:
        raise ValueError("wrong number of CAP root pairs")

    recorder = XOFRecorder()
    polynomials: list[TreePolynomial] = []
    leaf_counts = parameters.expanded_leaf_counts()
    extension_degrees = parameters.expanded_extension_degrees()
    for tree_index, (leaves, extension_degree, roots) in enumerate(
        zip(leaf_counts, extension_degrees, randomness.roots)
    ):
        leaf_seeds = expand_tree(
            randomness.salt, roots, tree_index, leaves, recorder
        )
        commitments: list[tuple[int, int]] = []
        plain = 0
        masks = [0] * parameters.random_polynomial_bits
        for leaf_index, seed in enumerate(leaf_seeds, start=1):
            commitments.append(
                seed_commit(
                    randomness.salt,
                    seed,
                    tree_index,
                    leaf_index,
                    recorder,
                )
            )
            tape = expand_tape(
                seed,
                tree_index,
                leaf_index,
                parameters.random_polynomial_bits,
                recorder,
            )
            plain ^= tape
            inverse_point = gf2m_inv(leaf_index, extension_degree)
            set_bits = tape
            while set_bits:
                low_bit = set_bits & -set_bits
                coordinate = low_bit.bit_length() - 1
                masks[coordinate] ^= inverse_point
                set_bits ^= low_bit
        polynomials.append(
            TreePolynomial(
                leaves,
                extension_degree,
                tuple(commitments),
                plain,
                tuple(masks),
            )
        )

    witness_mask = (1 << parameters.witness_bits) - 1
    consistency_mask = (1 << parameters.consistency_bits) - 1
    p_plain = tuple(poly.plain & witness_mask for poly in polynomials)
    mhat_shift = parameters.witness_bits + (parameters.degree - 1) * parameters.rho
    mhat_plain = tuple(
        (poly.plain >> mhat_shift) & consistency_mask
        for poly in polynomials
    )
    delta_p = tuple(p_plain[0] ^ value for value in p_plain[1:])
    delta_mhat = tuple(mhat_plain[0] ^ value for value in mhat_plain[1:])

    h1_fields = [bytes.fromhex(profile_fingerprint(parameters))]
    h1_fields.extend(
        _tree_component(index, polynomial)
        for index, polynomial in enumerate(polynomials)
    )
    h1_fields.append(
        _correction_component(delta_p, delta_mhat, parameters)
    )
    h1 = recorder.call("h1", DOMAIN_H1, h1_fields, HASH_BITS)
    point_bits = recorder.call(
        "consistency-points",
        DOMAIN_CONSISTENCY_POINTS,
        (hash_bytes(h1), bytes.fromhex(profile_fingerprint(parameters))),
        parameters.consistency_points * field.FIELD_DEGREE,
    )
    points = tuple(
        (point_bits >> (index * field.FIELD_DEGREE)) & field.FIELD_MASK
        for index in range(parameters.consistency_points)
    )
    if any(point == 0 for point in points) or len(set(points)) != len(points):
        raise RuntimeError("degenerate consistency points; resample CAP randomness")

    alpha = (
        _linear_hash_vector(
            p_plain[0], parameters.witness_bits, points
        )
        ^ mhat_plain[0]
    )
    xi_components: list[bytes] = []
    for polynomial in polynomials:
        p_masks = polynomial.masks[: parameters.witness_bits]
        mhat_masks = polynomial.masks[
            mhat_shift : mhat_shift + parameters.consistency_bits
        ]
        hashed_masks = _linear_hash_masks(
            p_masks,
            parameters.witness_bits,
            polynomial.extension_degree,
            points,
        )
        xi_masks = tuple(
            left ^ right for left, right in zip(hashed_masks, mhat_masks)
        )
        xi_components.append(
            _xi_component(
                alpha,
                xi_masks,
                parameters.consistency_bits,
                polynomial.extension_degree,
            )
        )

    h2 = recorder.call(
        "h2",
        DOMAIN_H2,
        (hash_bytes(h1), *xi_components),
        HASH_BITS,
    )
    encoded = serialize_commitment(
        parameters,
        randomness.salt,
        h2,
        alpha,
        delta_p,
        delta_mhat,
    )
    derived_mask = p_plain[0] & ((1 << parameters.mask_bits) - 1)
    append_base = (
        p_plain[0] >> parameters.mask_bits
    ) & ((1 << parameters.appended_signature_bits) - 1)
    return CAPExecution(
        CAPCommitment(
            profile_fingerprint(parameters),
            randomness.salt,
            h1,
            h2,
            alpha,
            delta_p,
            delta_mhat,
            derived_mask,
            append_base,
            encoded,
        ),
        tuple(polynomials),
        tuple(recorder.calls),
    )


def profile_dict(parameters: CAPParameters) -> dict[str, object]:
    return {
        "name": parameters.name,
        "relation_id": PROFILE_RELATION_ID,
        "security_bits": parameters.security_bits,
        "field": "GF(2^193)",
        "field_modulus_exponents": list(field.CONWAY_EXPONENTS),
        "anemoi_sponge_profile_sha256": sponge.profile_fingerprint(
            field.derive_parameters()
        ),
        "seed_bits": SEED_BITS,
        "hash_bits": HASH_BITS,
        "mask_bits": parameters.mask_bits,
        "appended_signature_bits": parameters.appended_signature_bits,
        "witness_bits": parameters.witness_bits,
        "degree": parameters.degree,
        "rho": parameters.rho,
        "consistency_points": parameters.consistency_points,
        "consistency_bits": parameters.consistency_bits,
        "random_polynomial_bits": parameters.random_polynomial_bits,
        "tree_specs": [asdict(spec) for spec in parameters.tree_specs],
        "tree_extension_degrees": list(parameters.expanded_extension_degrees()),
        "tree_count": parameters.tree_count,
        "leaf_count": parameters.leaf_count,
        "extension_moduli": {
            str(degree): hex(EXTENSION_MODULI[degree])
            for degree in sorted(set(parameters.expanded_extension_degrees()))
        },
        "domains": {
            "seed_derive": DOMAIN_SEED_DERIVE.hex(),
            "seed_commit": DOMAIN_SEED_COMMIT.hex(),
            "tape_expand": DOMAIN_TAPE_EXPAND.hex(),
            "h1": DOMAIN_H1.hex(),
            "consistency_points": DOMAIN_CONSISTENCY_POINTS.hex(),
            "h2": DOMAIN_H2.hex(),
        },
        "serialization": {
            "commitment_magic_hex": COMMITMENT_MAGIC.hex(),
            "field_elements": "25-byte little-endian, unused high seven bits zero",
            "bit_vectors": "coefficient/index order, LSB-first, zero-padded final byte",
            "corrections": "alpha || repeated(delta_P || delta_Mhat)",
        },
        "secure_profile": parameters.secure_profile,
        "blind_uov_bit_exact_compatible": False,
    }


def profile_fingerprint(parameters: CAPParameters) -> str:
    encoded = json.dumps(
        profile_dict(parameters), sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def commitment_bytes(parameters: CAPParameters) -> int:
    # serialize_commitment() byte-aligns alpha and every delta value
    # separately.  Rounding the concatenated bit count once undercounts mixed
    # widths (by 13 bytes for the 18-tree production profile).
    corrections = (
        (parameters.consistency_bits + 7) // 8
        + (parameters.tree_count - 1)
        * (
            (parameters.witness_bits + 7) // 8
            + (parameters.consistency_bits + 7) // 8
        )
    )
    return (
        len(COMMITMENT_MAGIC)
        + 2
        + 32
        + 2 * field.FIELD_ELEMENT_BYTES
        + HASH_BYTES
        + 4
        + corrections
    )


def _encoded_transcript_bytes(field_lengths: Sequence[int]) -> int:
    return len(sponge.TRANSCRIPT_MAGIC) + 2 + sum(8 + length for length in field_lengths)


def _sponge_permutations(domain: bytes, payload_bytes: int, output_bits: int) -> int:
    header_bytes = len(sponge.FRAME_MAGIC) + 2 + len(domain) + 8
    absorbed_bits = (header_bytes + payload_bytes) * 8
    absorbed_blocks = (absorbed_bits + 2 + sponge.RATE_BITS - 1) // sponge.RATE_BITS
    squeezed_blocks = (output_bits + sponge.RATE_BITS - 1) // sponge.RATE_BITS
    return absorbed_blocks + max(0, squeezed_blocks - 1)


def production_accounting(parameters: CAPParameters = PRODUCTION_PARAMETERS) -> dict[str, int]:
    leaf_counts = parameters.expanded_leaf_counts()
    mus = parameters.expanded_extension_degrees()
    derive_calls = sum(leaves - 2 for leaves in leaf_counts)
    leaf_calls = sum(leaf_counts)

    salt_bytes = HASH_BYTES
    derive_payload = _encoded_transcript_bytes((salt_bytes, field.FIELD_ELEMENT_BYTES, 8))
    commit_payload = derive_payload
    tape_payload = _encoded_transcript_bytes((field.FIELD_ELEMENT_BYTES, 8))
    derive_per_call = _sponge_permutations(
        DOMAIN_SEED_DERIVE, derive_payload, 2 * SEED_BITS
    )
    commit_per_call = _sponge_permutations(
        DOMAIN_SEED_COMMIT, commit_payload, HASH_BITS
    )
    tape_per_call = _sponge_permutations(
        DOMAIN_TAPE_EXPAND, tape_payload, parameters.random_polynomial_bits
    )

    tree_component_lengths = [
        2 + 4 + 2 + leaves * 2 * field.FIELD_ELEMENT_BYTES
        for leaves in leaf_counts
    ]
    correction_component_length = (
        2 + 4 + 4
        + (parameters.tree_count - 1)
        * (
            (parameters.witness_bits + 7) // 8
            + (parameters.consistency_bits + 7) // 8
        )
    )
    h1_payload = _encoded_transcript_bytes(
        (32, *tree_component_lengths, correction_component_length)
    )
    h1_permutations = _sponge_permutations(DOMAIN_H1, h1_payload, HASH_BITS)
    points_payload = _encoded_transcript_bytes((HASH_BYTES, 32))
    points_permutations = _sponge_permutations(
        DOMAIN_CONSISTENCY_POINTS,
        points_payload,
        parameters.consistency_bits,
    )
    xi_lengths = [
        4 + 2
        + (parameters.consistency_bits + 7) // 8
        + (parameters.consistency_bits * mu + 7) // 8
        for mu in mus
    ]
    h2_payload = _encoded_transcript_bytes((HASH_BYTES, *xi_lengths))
    h2_permutations = _sponge_permutations(DOMAIN_H2, h2_payload, HASH_BITS)

    total_xof_calls = derive_calls + 2 * leaf_calls + 3
    total_permutations = (
        derive_calls * derive_per_call
        + leaf_calls * commit_per_call
        + leaf_calls * tape_per_call
        + h1_permutations
        + points_permutations
        + h2_permutations
    )
    return {
        "tree_count": parameters.tree_count,
        "leaf_count": parameters.leaf_count,
        "seed_derive_calls": derive_calls,
        "seed_commit_calls": leaf_calls,
        "tape_expand_calls": leaf_calls,
        "transcript_xof_calls": 3,
        "total_xof_calls": total_xof_calls,
        "seed_derive_permutations_per_call": derive_per_call,
        "seed_commit_permutations_per_call": commit_per_call,
        "tape_expand_permutations_per_call": tape_per_call,
        "h1_permutations": h1_permutations,
        "consistency_point_permutations": points_permutations,
        "h2_permutations": h2_permutations,
        "total_anemoi_permutations": total_permutations,
        "permutation_nonlinear_rows": total_permutations * field.NONLINEAR_ROWS,
        "commitment_bytes": commitment_bytes(parameters),
    }


def build_manifest(reduced_execution: CAPExecution | None = None) -> dict[str, object]:
    production = production_accounting()
    manifest: dict[str, object] = {
        "implementation_version": IMPLEMENTATION_VERSION,
        "paper_source": {
            "url": "https://eprint.iacr.org/2025/895",
            "revision": "2025-10-31",
            "source_algorithms": ["Protocol 8", "Protocol 9", "Protocol 10"],
            "paper_reports_executable_generator": False,
        },
        "profile": profile_dict(PRODUCTION_PARAMETERS),
        "profile_fingerprint": profile_fingerprint(PRODUCTION_PARAMETERS),
        "production_accounting": production,
        "implemented": {
            "canonical_randomness_serialization": True,
            "ggm_seed_derivation_reference": True,
            "leaf_seed_commitment_reference": True,
            "leaf_tape_expansion_reference": True,
            "random_polynomial_coefficients": True,
            "cross_repetition_corrections": True,
            "masked_consistency_digest": True,
            "canonical_commitment_serialization": True,
            "mask_derived_from_cap_randomness": True,
            "append_signature_delta": True,
            "full_production_native_rows_materialized": False,
            "inter_call_wire_identity_proved": False,
            "parent_archive_external_assertion_removed": False,
        },
        "claim_boundary": {
            "blind_uov_bit_exact_compatible": False,
            "paper_security_reduction_automatically_inherited": False,
            "paper_signature_size_automatically_inherited": False,
            # This primitive manifest deliberately contains only the reduced
            # execution below.  The production execution evidence lives in
            # pq_rbbc_cap_composition_manifest_v2_8.json, whose canonical
            # document also commits to every ordered XOF call.
            "full_18_tree_vector_executed_in_this_manifest": False,
            "linked_composer_manifest_required_for_full_vector_evidence": True,
            "fork_specific_cap_extraction_proof_complete": False,
            "production_closed": False,
        },
    }
    if reduced_execution is not None:
        commitment = reduced_execution.commitment
        manifest["reduced_test_vector"] = {
            "explicitly_non_secure": True,
            "parameters": profile_dict(REDUCED_TEST_PARAMETERS),
            "profile_fingerprint": profile_fingerprint(REDUCED_TEST_PARAMETERS),
            "commitment_bytes": len(commitment.encoded),
            "commitment_sha256": hashlib.sha256(commitment.encoded).hexdigest(),
            "commitment_hex": commitment.encoded.hex(),
            "h1_hex": hash_bytes(commitment.h1).hex(),
            "h2_hex": hash_bytes(commitment.h2).hex(),
            "derived_mask_hex": pack_int(
                commitment.derived_mask, REDUCED_TEST_PARAMETERS.mask_bits
            ).hex(),
            "xof_calls": len(reduced_execution.xof_calls),
        }
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument(
        "--production",
        action="store_true",
        help="execute the very large production topology (not used in regression)",
    )
    args = parser.parse_args()

    if args.production:
        execution = execute_cap_commit(
            PRODUCTION_PARAMETERS,
            deterministic_randomness(PRODUCTION_PARAMETERS),
            allow_large=True,
        )
        manifest = build_manifest()
        manifest["production_execution"] = {
            "commitment_sha256": hashlib.sha256(
                execution.commitment.encoded
            ).hexdigest(),
            "commitment_bytes": len(execution.commitment.encoded),
            "xof_calls": len(execution.xof_calls),
        }
    else:
        reduced = execute_cap_commit(
            REDUCED_TEST_PARAMETERS,
            deterministic_randomness(REDUCED_TEST_PARAMETERS),
        )
        manifest = build_manifest(reduced)
    encoded = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if args.manifest:
        args.manifest.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
