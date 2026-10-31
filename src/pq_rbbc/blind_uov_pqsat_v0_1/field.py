"""Research-only binary-extension-field arithmetic for Blind-UOV/CAP v0.1.

The four extension fields and their canonical encodings are taken directly
from the exact frozen concrete profile.  Multiplication uses polynomial-basis
carryless ``shift/XOR`` arithmetic with reduction by the profile modulus; it
never uses ordinary integer multiplication modulo that modulus.

This implementation is intentionally not constant-time and is not qualified
for production cryptography.
"""

from __future__ import annotations

from typing import Final

from .parameters import FieldId, FieldSpec, load_profile_manifest, validate_profile


_PROFILE: Final = load_profile_manifest()
validate_profile(_PROFILE)

_EXTENSION_FIELDS: Final = frozenset(
    {
        FieldId.GF_2_8,
        FieldId.GF_2_11,
        FieldId.GF_2_12,
        FieldId.GF_2_64,
    }
)


def _field_spec(field_id: FieldId) -> FieldSpec:
    if type(field_id) is not FieldId:
        raise TypeError("field_id must be exactly FieldId")
    if field_id not in _EXTENSION_FIELDS:
        raise ValueError("field_id is not a supported extension field")
    spec = _PROFILE.field(field_id)
    if type(spec) is not FieldSpec:
        raise ValueError("profile returned a noncanonical field specification")
    return spec


def _element(spec: FieldSpec, value: int, name: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{name} must be exactly int; bool is forbidden")
    if not 0 <= value < spec.element_upper_bound:
        raise ValueError(f"{name} is outside the canonical {spec.field_id.value} range")
    return value


def _multiply(spec: FieldSpec, left: int, right: int) -> int:
    """Bit-serial carryless multiply with reduction after every x shift."""

    result = 0
    multiplicand = left
    multiplier = right
    top_coefficient = 1 << (spec.degree - 1)
    modulus = spec.irreducible_polynomial_integer

    for _ in range(spec.degree):
        if multiplier & 1:
            result ^= multiplicand
        multiplier >>= 1

        carry = multiplicand & top_coefficient
        multiplicand <<= 1
        if carry:
            # ``modulus`` includes x^degree, so this XOR both cancels that
            # coefficient and applies the canonical lower reduction terms.
            multiplicand ^= modulus

    return result


def gf_mul(field_id: FieldId, left: int, right: int) -> int:
    """Multiply two canonical elements of one frozen extension field."""

    spec = _field_spec(field_id)
    canonical_left = _element(spec, left, "left")
    canonical_right = _element(spec, right, "right")
    return _multiply(spec, canonical_left, canonical_right)


def gf_inv(field_id: FieldId, value: int) -> int:
    """Invert one nonzero canonical extension-field element.

    This is an ordinary field inverse.  In particular, zero and the separate
    evaluation-domain infinity sentinel are rejected rather than assigned a
    special result.  The implementation is research-only and not constant
    time, matching the rest of this module.
    """

    spec = _field_spec(field_id)
    canonical_value = _element(spec, value, "value")
    if canonical_value == 0:
        raise ValueError("zero has no field inverse")

    result = 1
    base = canonical_value
    exponent = spec.element_upper_bound - 2
    while exponent:
        if exponent & 1:
            result = _multiply(spec, result, base)
        base = _multiply(spec, base, base)
        exponent >>= 1
    return result


def encode_element(field_id: FieldId, value: int) -> bytes:
    """Encode one canonical field element as fixed-width little-endian bytes."""

    spec = _field_spec(field_id)
    canonical_value = _element(spec, value, "value")
    return canonical_value.to_bytes(spec.encoded_bytes, "little")


def decode_element(field_id: FieldId, encoded: bytes) -> int:
    """Decode one exact, canonical fixed-width little-endian field element."""

    spec = _field_spec(field_id)
    if type(encoded) is not bytes:
        raise TypeError("encoded must be exactly bytes")
    if len(encoded) != spec.encoded_bytes:
        raise ValueError("encoded field element has the wrong length")
    value = int.from_bytes(encoded, "little")
    return _element(spec, value, "encoded value")


def consistency_hash(
    vector_2048: bytes, points: tuple[int, int, int, int]
) -> bytes:
    """Evaluate the 32-coefficient GF(2^64) consistency polynomial four times.

    ``vector_2048`` is interpreted LSB-first as 32 consecutive 8-byte
    little-endian coefficients.  Results are returned in point order as four
    canonical 8-byte little-endian elements.
    """

    if type(vector_2048) is not bytes:
        raise TypeError("vector_2048 must be exactly bytes")
    if len(vector_2048) != 256:
        raise ValueError("vector_2048 must contain exactly 2048 bits")
    if type(points) is not tuple:
        raise TypeError("points must be exactly tuple")
    if len(points) != 4:
        raise ValueError("points must contain exactly four elements")

    spec = _field_spec(FieldId.GF_2_64)
    canonical_points = tuple(
        _element(spec, point, f"points[{index}]")
        for index, point in enumerate(points)
    )
    coefficients = tuple(
        int.from_bytes(vector_2048[offset : offset + 8], "little")
        for offset in range(0, len(vector_2048), 8)
    )

    output = bytearray()
    for point in canonical_points:
        accumulator = 0
        for coefficient in reversed(coefficients):
            accumulator = _multiply(spec, accumulator, point) ^ coefficient
        output.extend(accumulator.to_bytes(spec.encoded_bytes, "little"))
    return bytes(output)


__all__ = (
    "consistency_hash",
    "decode_element",
    "encode_element",
    "gf_inv",
    "gf_mul",
)
