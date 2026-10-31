"""Executable Blind-UOV CAP relation for the PQ-SAT v0.1 profile.

This module owns only the shared relation algebra used by future prover and
verifier implementations.  It does not construct a tree, search a nonce,
produce ``pi_2``, or accept a CAP proof.  The implementation is research-only
and is not constant-time.

The UOV map is always an explicit member of :class:`CAPStatement`.  The
576 Boolean constraints are lifted coefficient-by-coefficient from the fixed
GF(256) polynomial basis into the selected TCitH extension field; extension
coordinates are never truncated or reduced to Boolean values.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .consistency import XiPolynomial, XiPolynomials
from .evaluation import FiniteEvaluationPoint, LinearPolynomial
from .field import consistency_hash, gf_inv
from .parameters import FieldId
from .uov import (
    CPK_BYTES,
    DENSE_BYTES,
    M,
    MONOMIAL_COUNT,
    N,
    UOVPublicMap,
    uov_relation_holds,
)


_REPETITIONS: Final = 18
_WITNESS_BITS: Final = 2048
_R_BITS: Final = 576
_Z_BITS: Final = 1472
_R_BYTES: Final = 72
_Z_BYTES: Final = 184
_WITNESS_BYTES: Final = 256
_CONSTRAINTS: Final = 576
_CONSISTENCY_ELEMENTS: Final = 256
_CORRECTIONS: Final = 17
_CORRECTION_DATA_BYTES: Final = 4928

_FIELD_PARAMETERS: Final = {
    FieldId.GF_2_11: (11, 0x805, 18),
    FieldId.GF_2_12: (12, 0x1009, 16),
}


class RelationError(ValueError):
    """A controlled rejection at the executable-relation boundary."""


def _require_bytes(value: object, length: int, name: str) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{name} must be exact bytes")
    if len(value) != length:
        raise RelationError(f"{name} must be exactly {length} bytes")
    return value


def _require_field(field_id: object) -> FieldId:
    if type(field_id) is not FieldId:
        raise TypeError("field_id must be exactly FieldId")
    if field_id not in _FIELD_PARAMETERS:
        raise RelationError("field_id must be GF(2^11) or GF(2^12)")
    return field_id


def _field_parameters(field_id: FieldId) -> tuple[int, int, int]:
    return _FIELD_PARAMETERS[_require_field(field_id)]


def _require_element(field_id: FieldId, value: object, name: str) -> int:
    degree, _modulus, _rho = _field_parameters(field_id)
    if type(value) is not int:
        raise TypeError(f"{name} must be an exact int; bool is forbidden")
    if not 0 <= value < 1 << degree:
        raise RelationError(f"{name} is outside the canonical field range")
    return value


def _raw_mul(degree: int, modulus: int, left: int, right: int) -> int:
    """Multiply already-validated elements in a polynomial-basis field."""

    result = 0
    multiplicand = left
    multiplier = right
    top = 1 << (degree - 1)
    while multiplier:
        if multiplier & 1:
            result ^= multiplicand
        multiplier >>= 1
        carry = multiplicand & top
        multiplicand <<= 1
        if carry:
            multiplicand ^= modulus
    return result


def _gf256_mul(left: int, right: int) -> int:
    return _raw_mul(8, 0x11B, left, right)


def _gf256_coefficient_masks() -> tuple[tuple[int, ...], ...]:
    """Return the eight F2-linear output masks for multiplication by c."""

    coefficients: list[tuple[int, ...]] = []
    for coefficient in range(256):
        output_masks = [0] * 8
        for input_bit in range(8):
            image = _gf256_mul(coefficient, 1 << input_bit)
            for output_bit in range(8):
                if (image >> output_bit) & 1:
                    output_masks[output_bit] |= 1 << input_bit
        coefficients.append(tuple(output_masks))
    return tuple(coefficients)


_GF256_COEFFICIENT_MASKS: Final = _gf256_coefficient_masks()


def _validate_public_map(public_map: object) -> UOVPublicMap:
    if type(public_map) is not UOVPublicMap:
        raise TypeError("public_map must be exactly UOVPublicMap")
    _require_bytes(public_map.canonical_cpk, CPK_BYTES, "public_map.canonical_cpk")
    _require_bytes(public_map.public_map_digest, 32, "public_map.public_map_digest")
    _require_bytes(
        public_map.dense_coefficients,
        DENSE_BYTES,
        "public_map.dense_coefficients",
    )
    return public_map


@dataclass(frozen=True, slots=True)
class CAPStatement:
    """The explicit issuer map and 104-byte public statement core."""

    public_map: UOVPublicMap
    ctx: bytes
    u: bytes

    def __post_init__(self) -> None:
        _validate_public_map(self.public_map)
        _require_bytes(self.ctx, 32, "ctx")
        _require_bytes(self.u, M, "u")


@dataclass(frozen=True, slots=True)
class CAPWitness:
    """The fixed ``r || z`` CAP witness."""

    r: bytes
    z: bytes

    def __post_init__(self) -> None:
        _require_bytes(self.r, _R_BYTES, "r")
        _require_bytes(self.z, _Z_BYTES, "z")


def _validate_linear_polynomial(
    polynomial: object,
    field_id: FieldId,
    name: str,
) -> LinearPolynomial:
    if type(polynomial) is not LinearPolynomial:
        raise TypeError(f"{name} must be exactly LinearPolynomial")
    if type(polynomial.field_id) is not FieldId:
        raise TypeError(f"{name}.field_id must be exactly FieldId")
    if polynomial.field_id is not field_id:
        raise RelationError(f"{name} has the wrong field")
    _require_element(field_id, polynomial.mask, f"{name}.mask")
    _require_element(field_id, polynomial.plain, f"{name}.plain")
    return polynomial


def _validate_polynomial_tuple(
    value: object,
    length: int,
    field_id: FieldId,
    name: str,
) -> tuple[LinearPolynomial, ...]:
    if type(value) is not tuple:
        raise TypeError(f"{name} must be an exact tuple")
    if len(value) != length:
        raise RelationError(f"{name} must contain exactly {length} polynomials")
    for index, polynomial in enumerate(value):
        _validate_linear_polynomial(polynomial, field_id, f"{name}[{index}]")
    return value


@dataclass(frozen=True, slots=True)
class RepetitionPolynomials:
    """The three degree-one vector-polynomial families for one repetition."""

    witness_polynomials: tuple[LinearPolynomial, ...]
    relation_masks: tuple[LinearPolynomial, ...]
    consistency_masks: tuple[LinearPolynomial, ...]

    def __post_init__(self) -> None:
        if type(self.witness_polynomials) is not tuple:
            raise TypeError("witness_polynomials must be an exact tuple")
        if len(self.witness_polynomials) != _WITNESS_BITS:
            raise RelationError("witness_polynomials must contain exactly 2048 entries")
        first = self.witness_polynomials[0]
        if type(first) is not LinearPolynomial:
            raise TypeError("witness_polynomials[0] must be exactly LinearPolynomial")
        field_id = _require_field(first.field_id)
        _degree, _modulus, rho = _field_parameters(field_id)
        _validate_polynomial_tuple(
            self.witness_polynomials,
            _WITNESS_BITS,
            field_id,
            "witness_polynomials",
        )
        _validate_polynomial_tuple(
            self.relation_masks,
            rho,
            field_id,
            "relation_masks",
        )
        _validate_polynomial_tuple(
            self.consistency_masks,
            _CONSISTENCY_ELEMENTS,
            field_id,
            "consistency_masks",
        )


@dataclass(frozen=True, slots=True)
class RepetitionCorrection:
    """Protocol-9 constant corrections for one non-base repetition."""

    delta_p: bytes
    delta_mhat: bytes

    def __post_init__(self) -> None:
        _require_bytes(self.delta_p, _WITNESS_BYTES, "delta_p")
        _require_bytes(self.delta_mhat, 32, "delta_mhat")


@dataclass(frozen=True, slots=True)
class CorrectionData:
    """The exact 4,928-byte correction-data payload inside ``c_r``."""

    alpha_prime: bytes
    corrections: tuple[RepetitionCorrection, ...]

    def __post_init__(self) -> None:
        _require_bytes(self.alpha_prime, 32, "alpha_prime")
        if type(self.corrections) is not tuple:
            raise TypeError("corrections must be an exact tuple")
        if len(self.corrections) != _CORRECTIONS:
            raise RelationError("corrections must contain exactly 17 entries")
        for index, correction in enumerate(self.corrections):
            if type(correction) is not RepetitionCorrection:
                raise TypeError(
                    f"corrections[{index}] must be exactly RepetitionCorrection"
                )


def _validate_field_vector(
    value: object,
    length: int,
    field_id: FieldId,
    name: str,
) -> tuple[int, ...]:
    if type(value) is not tuple:
        raise TypeError(f"{name} must be an exact tuple")
    if len(value) != length:
        raise RelationError(f"{name} must contain exactly {length} elements")
    for index, element in enumerate(value):
        _require_element(field_id, element, f"{name}[{index}]")
    return value


@dataclass(frozen=True, slots=True)
class ConstraintPolynomials:
    """All 576 lifted degree-two relation polynomials."""

    field_id: FieldId
    constant: tuple[int, ...]
    linear: tuple[int, ...]
    quadratic: tuple[int, ...]

    def __post_init__(self) -> None:
        field_id = _require_field(self.field_id)
        _validate_field_vector(self.constant, _CONSTRAINTS, field_id, "constant")
        _validate_field_vector(self.linear, _CONSTRAINTS, field_id, "linear")
        _validate_field_vector(
            self.quadratic, _CONSTRAINTS, field_id, "quadratic"
        )


@dataclass(frozen=True, slots=True)
class QPolynomials:
    """The constant ``q`` and degree-zero ``Qbar`` values for one repetition."""

    field_id: FieldId
    q: tuple[int, ...]
    qbar: tuple[int, ...]

    def __post_init__(self) -> None:
        field_id = _require_field(self.field_id)
        _degree, _modulus, rho = _field_parameters(field_id)
        _validate_field_vector(self.q, rho, field_id, "q")
        _validate_field_vector(self.qbar, rho, field_id, "qbar")


def _require_statement(statement: object) -> CAPStatement:
    if type(statement) is not CAPStatement:
        raise TypeError("statement must be exactly CAPStatement")
    _validate_public_map(statement.public_map)
    _require_bytes(statement.ctx, 32, "statement.ctx")
    _require_bytes(statement.u, M, "statement.u")
    return statement


def _require_witness(witness: object) -> CAPWitness:
    if type(witness) is not CAPWitness:
        raise TypeError("witness must be exactly CAPWitness")
    _require_bytes(witness.r, _R_BYTES, "witness.r")
    _require_bytes(witness.z, _Z_BYTES, "witness.z")
    return witness


def _repetition_field(repetition: RepetitionPolynomials) -> FieldId:
    if type(repetition) is not RepetitionPolynomials:
        raise TypeError("repetition must be exactly RepetitionPolynomials")
    if type(repetition.witness_polynomials) is not tuple or not repetition.witness_polynomials:
        raise RelationError("repetition witness-polynomial shape is invalid")
    field_id = _require_field(repetition.witness_polynomials[0].field_id)
    _degree, _modulus, rho = _field_parameters(field_id)
    _validate_polynomial_tuple(
        repetition.witness_polynomials,
        _WITNESS_BITS,
        field_id,
        "witness_polynomials",
    )
    _validate_polynomial_tuple(
        repetition.relation_masks,
        rho,
        field_id,
        "relation_masks",
    )
    _validate_polynomial_tuple(
        repetition.consistency_masks,
        _CONSISTENCY_ELEMENTS,
        field_id,
        "consistency_masks",
    )
    return field_id


def _expected_repetition_field(index: int) -> FieldId:
    return FieldId.GF_2_12 if index < 2 else FieldId.GF_2_11


def _validate_repetitions(
    repetitions: object,
) -> tuple[RepetitionPolynomials, ...]:
    if type(repetitions) is not tuple:
        raise TypeError("repetitions must be an exact tuple")
    if len(repetitions) != _REPETITIONS:
        raise RelationError("repetitions must contain exactly 18 entries")
    for index, repetition in enumerate(repetitions):
        if type(repetition) is not RepetitionPolynomials:
            raise TypeError(
                f"repetitions[{index}] must be exactly RepetitionPolynomials"
            )
        if _repetition_field(repetition) is not _expected_repetition_field(index):
            raise RelationError(f"repetitions[{index}] has the wrong profile field")
    return repetitions


def _bits_to_bytes(bits: tuple[int, ...], name: str) -> bytes:
    if type(bits) is not tuple:
        raise TypeError(f"{name} must be an exact tuple")
    if len(bits) % 8:
        raise RelationError(f"{name} must be byte-aligned")
    encoded = bytearray(len(bits) // 8)
    for index, bit in enumerate(bits):
        if type(bit) is not int:
            raise TypeError(f"{name}[{index}] must be an exact int")
        if bit not in (0, 1):
            raise RelationError(f"{name}[{index}] must be a base-field bit")
        encoded[index // 8] |= bit << (index % 8)
    return bytes(encoded)


def _bytes_to_bits(encoded: bytes) -> tuple[int, ...]:
    return tuple(
        (byte >> bit) & 1
        for byte in encoded
        for bit in range(8)
    )


def witness_bytes(witness: CAPWitness) -> bytes:
    """Return the canonical 256-byte ``r || z`` witness."""

    checked = _require_witness(witness)
    return checked.r + checked.z


def witness_bits(witness: CAPWitness) -> tuple[int, ...]:
    """Return all 2,048 logical bits in byte-local LSB-first order."""

    return _bytes_to_bits(witness_bytes(witness))


def relation_holds(statement: CAPStatement, witness: CAPWitness) -> bool:
    """Evaluate the ordinary explicit-map Blind-UOV relation."""

    checked_statement = _require_statement(statement)
    checked_witness = _require_witness(witness)
    return uov_relation_holds(
        checked_statement.public_map,
        checked_statement.ctx,
        checked_statement.u,
        checked_witness.r,
        checked_witness.z,
    )


def correct_repetitions(
    repetitions: tuple[RepetitionPolynomials, ...],
) -> tuple[
    tuple[RepetitionPolynomials, ...],
    tuple[RepetitionCorrection, ...],
]:
    """Apply Protocol-9 P/Mhat constant correction using repetition zero."""

    checked = _validate_repetitions(repetitions)
    base = checked[0]
    base_p = tuple(polynomial.plain for polynomial in base.witness_polynomials)
    base_mhat = tuple(
        polynomial.plain for polynomial in base.consistency_masks
    )
    _bits_to_bytes(base_p, "base P constants")
    _bits_to_bytes(base_mhat, "base Mhat constants")

    corrected: list[RepetitionPolynomials] = [base]
    corrections: list[RepetitionCorrection] = []
    for repetition_index, repetition in enumerate(checked[1:], start=1):
        field_id = _repetition_field(repetition)
        current_p = tuple(
            polynomial.plain for polynomial in repetition.witness_polynomials
        )
        current_mhat = tuple(
            polynomial.plain for polynomial in repetition.consistency_masks
        )
        _bits_to_bytes(current_p, f"repetition {repetition_index} P constants")
        _bits_to_bytes(
            current_mhat,
            f"repetition {repetition_index} Mhat constants",
        )
        delta_p_bits = tuple(
            left ^ right for left, right in zip(base_p, current_p, strict=True)
        )
        delta_mhat_bits = tuple(
            left ^ right
            for left, right in zip(base_mhat, current_mhat, strict=True)
        )
        correction = RepetitionCorrection(
            _bits_to_bytes(delta_p_bits, "delta_p"),
            _bits_to_bytes(delta_mhat_bits, "delta_mhat"),
        )
        corrections.append(correction)
        corrected.append(
            RepetitionPolynomials(
                witness_polynomials=tuple(
                    LinearPolynomial(
                        field_id,
                        polynomial.mask,
                        polynomial.plain ^ delta,
                    )
                    for polynomial, delta in zip(
                        repetition.witness_polynomials,
                        delta_p_bits,
                        strict=True,
                    )
                ),
                relation_masks=repetition.relation_masks,
                consistency_masks=tuple(
                    LinearPolynomial(
                        field_id,
                        polynomial.mask,
                        polynomial.plain ^ delta,
                    )
                    for polynomial, delta in zip(
                        repetition.consistency_masks,
                        delta_mhat_bits,
                        strict=True,
                    )
                ),
            )
        )
    return tuple(corrected), tuple(corrections)


def encode_correction_data(data: CorrectionData) -> bytes:
    """Encode ``alpha_prime || (delta_P || delta_Mhat)[1..17]``."""

    if type(data) is not CorrectionData:
        raise TypeError("data must be exactly CorrectionData")
    _require_bytes(data.alpha_prime, 32, "alpha_prime")
    if type(data.corrections) is not tuple or len(data.corrections) != _CORRECTIONS:
        raise RelationError("corrections must contain exactly 17 entries")
    pieces = [data.alpha_prime]
    for index, correction in enumerate(data.corrections):
        if type(correction) is not RepetitionCorrection:
            raise TypeError(
                f"corrections[{index}] must be exactly RepetitionCorrection"
            )
        pieces.extend(
            (
                _require_bytes(correction.delta_p, 256, "delta_p"),
                _require_bytes(correction.delta_mhat, 32, "delta_mhat"),
            )
        )
    encoded = b"".join(pieces)
    if len(encoded) != _CORRECTION_DATA_BYTES:
        raise AssertionError("unreachable correction-data length")
    return encoded


def decode_correction_data(encoded: bytes) -> CorrectionData:
    """Decode exactly one canonical 4,928-byte correction payload."""

    checked = _require_bytes(encoded, _CORRECTION_DATA_BYTES, "encoded")
    corrections: list[RepetitionCorrection] = []
    offset = 32
    for _index in range(_CORRECTIONS):
        corrections.append(
            RepetitionCorrection(
                checked[offset : offset + 256],
                checked[offset + 256 : offset + 288],
            )
        )
        offset += 288
    if offset != len(checked):
        raise AssertionError("unreachable correction-data parse length")
    return CorrectionData(checked[:32], tuple(corrections))


def derive_r_and_delta_z(
    corrected_base: RepetitionPolynomials,
    z: bytes,
) -> tuple[bytes, bytes]:
    """Derive ``r`` and ``delta_z`` from corrected repetition-zero P(0)."""

    field_id = _repetition_field(corrected_base)
    if field_id is not FieldId.GF_2_12:
        raise RelationError("corrected_base must be a group-0 repetition")
    requested_z = _require_bytes(z, _Z_BYTES, "z")
    random_witness = _bits_to_bytes(
        tuple(
            polynomial.plain
            for polynomial in corrected_base.witness_polynomials
        ),
        "corrected_base P constants",
    )
    r = random_witness[:_R_BYTES]
    random_z = random_witness[_R_BYTES:]
    delta_z = bytes(
        left ^ right
        for left, right in zip(random_z, requested_z, strict=True)
    )
    return r, delta_z


def apply_delta_z(
    corrected: RepetitionPolynomials,
    delta_z: bytes,
) -> RepetitionPolynomials:
    """Apply the fixed ``zero_r || delta_z`` correction only to P(0)."""

    field_id = _repetition_field(corrected)
    correction_bits = (0,) * _R_BITS + _bytes_to_bits(
        _require_bytes(delta_z, _Z_BYTES, "delta_z")
    )
    plain_bits = tuple(
        polynomial.plain for polynomial in corrected.witness_polynomials
    )
    _bits_to_bytes(plain_bits, "corrected P constants")
    return RepetitionPolynomials(
        witness_polynomials=tuple(
            LinearPolynomial(
                field_id,
                polynomial.mask,
                polynomial.plain ^ correction,
            )
            for polynomial, correction in zip(
                corrected.witness_polynomials,
                correction_bits,
                strict=True,
            )
        ),
        relation_masks=corrected.relation_masks,
        consistency_masks=corrected.consistency_masks,
    )


def _lifted_gf256_product(
    degree: int,
    modulus: int,
    left: tuple[int, ...],
    right: tuple[int, ...],
) -> tuple[int, ...]:
    """Multiply two GF(256) basis vectors after scalar extension to K."""

    product = [0] * 15
    for left_index, left_value in enumerate(left):
        if left_value == 0:
            continue
        for right_index, right_value in enumerate(right):
            if right_value:
                product[left_index + right_index] ^= _raw_mul(
                    degree, modulus, left_value, right_value
                )
    # x^8 = x^4 + x^3 + x + 1 for x^8+x^4+x^3+x+1.
    for power in range(14, 7, -1):
        coefficient = product[power]
        if coefficient:
            product[power - 4] ^= coefficient
            product[power - 5] ^= coefficient
            product[power - 7] ^= coefficient
            product[power - 8] ^= coefficient
    return tuple(product[:8])


def _subset_xors(elements: tuple[int, ...]) -> list[int]:
    table = [0] * 256
    for mask in range(1, 256):
        least = mask & -mask
        table[mask] = table[mask ^ least] ^ elements[least.bit_length() - 1]
    return table


def evaluate_lifted_constraints(
    statement: CAPStatement,
    field_id: FieldId,
    witness_values: tuple[int, ...],
) -> tuple[int, ...]:
    """Evaluate all 576 scalar-extended F2 constraints over one TCitH field."""

    checked_statement = _require_statement(statement)
    checked_field = _require_field(field_id)
    values = _validate_field_vector(
        witness_values,
        _WITNESS_BITS,
        checked_field,
        "witness_values",
    )
    degree, modulus, _rho = _field_parameters(checked_field)

    constraints = [0] * _CONSTRAINTS
    for equation in range(M):
        public_byte = checked_statement.u[equation]
        for bit in range(8):
            coordinate = equation * 8 + bit
            constraints[coordinate] = values[coordinate] ^ (
                (public_byte >> bit) & 1
            )

    z_offset = _R_BITS
    z_vectors = tuple(
        values[z_offset + variable * 8 : z_offset + (variable + 1) * 8]
        for variable in range(N)
    )
    dense = checked_statement.public_map.dense_coefficients
    monomial = 0
    for first in range(N):
        left = z_vectors[first]
        for second in range(first, N):
            product = _lifted_gf256_product(
                degree,
                modulus,
                left,
                z_vectors[second],
            )
            subset_xors = _subset_xors(product)
            for equation in range(M):
                coefficient = dense[equation * MONOMIAL_COUNT + monomial]
                masks = _GF256_COEFFICIENT_MASKS[coefficient]
                base = equation * 8
                constraints[base] ^= subset_xors[masks[0]]
                constraints[base + 1] ^= subset_xors[masks[1]]
                constraints[base + 2] ^= subset_xors[masks[2]]
                constraints[base + 3] ^= subset_xors[masks[3]]
                constraints[base + 4] ^= subset_xors[masks[4]]
                constraints[base + 5] ^= subset_xors[masks[5]]
                constraints[base + 6] ^= subset_xors[masks[6]]
                constraints[base + 7] ^= subset_xors[masks[7]]
            monomial += 1
    if monomial != MONOMIAL_COUNT:
        raise AssertionError("unreachable UOV monomial count")
    return tuple(constraints)


def _validate_consistency_points(
    points: object,
) -> tuple[int, int, int, int]:
    if type(points) is not tuple:
        raise TypeError("points must be an exact tuple")
    if len(points) != 4:
        raise RelationError("points must contain exactly four elements")
    for index, point in enumerate(points):
        if type(point) is not int:
            raise TypeError(f"points[{index}] must be an exact int")
        if not 0 <= point < 1 << 64:
            raise RelationError(f"points[{index}] is outside GF(2^64)")
    return points


def build_consistency_polynomials(
    repetitions: tuple[RepetitionPolynomials, ...],
    points: tuple[int, int, int, int],
) -> XiPolynomials:
    """Build all Protocol-9 ``xi(X)=H(P'(X))+Mhat'(X)`` polynomials."""

    checked_repetitions = _validate_repetitions(repetitions)
    checked_points = _validate_consistency_points(points)
    output: list[XiPolynomial] = []
    expected_constant: bytes | None = None

    for repetition_index, repetition in enumerate(checked_repetitions):
        field_id = _repetition_field(repetition)
        degree, _modulus, _rho = _field_parameters(field_id)
        p_constant = _bits_to_bytes(
            tuple(
                polynomial.plain
                for polynomial in repetition.witness_polynomials
            ),
            f"repetitions[{repetition_index}] P constants",
        )
        mhat_constant = _bits_to_bytes(
            tuple(
                polynomial.plain
                for polynomial in repetition.consistency_masks
            ),
            f"repetitions[{repetition_index}] Mhat constants",
        )
        hashed_constant = consistency_hash(p_constant, checked_points)
        constant = bytes(
            left ^ right
            for left, right in zip(
                hashed_constant,
                mhat_constant,
                strict=True,
            )
        )
        if expected_constant is None:
            expected_constant = constant
        elif constant != expected_constant:
            raise RelationError("xi constant coefficients are not identical")

        linear = [
            polynomial.mask for polynomial in repetition.consistency_masks
        ]
        for coefficient_bit in range(degree):
            plane = bytearray(_WITNESS_BYTES)
            for index, polynomial in enumerate(repetition.witness_polynomials):
                plane[index // 8] |= (
                    (polynomial.mask >> coefficient_bit) & 1
                ) << (index % 8)
            hashed_plane = consistency_hash(bytes(plane), checked_points)
            for output_index in range(_CONSISTENCY_ELEMENTS):
                if (hashed_plane[output_index // 8] >> (output_index % 8)) & 1:
                    linear[output_index] ^= 1 << coefficient_bit
        output.append(XiPolynomial(constant, tuple(linear)))
    return tuple(output)


def _evaluate_polynomials_at(
    polynomials: tuple[LinearPolynomial, ...],
    field_id: FieldId,
    point: int,
) -> tuple[int, ...]:
    degree, modulus, _rho = _field_parameters(field_id)
    return tuple(
        polynomial.plain
        ^ _raw_mul(degree, modulus, polynomial.mask, point)
        for polynomial in polynomials
    )


def build_constraint_polynomials(
    statement: CAPStatement,
    witness_polynomials: tuple[LinearPolynomial, ...],
) -> ConstraintPolynomials:
    """Interpolate every lifted relation constraint as ``c+lX+qX^2``."""

    checked_statement = _require_statement(statement)
    if type(witness_polynomials) is not tuple:
        raise TypeError("witness_polynomials must be an exact tuple")
    if len(witness_polynomials) != _WITNESS_BITS:
        raise RelationError("witness_polynomials must contain exactly 2048 entries")
    first = witness_polynomials[0]
    if type(first) is not LinearPolynomial:
        raise TypeError("witness_polynomials[0] must be exactly LinearPolynomial")
    field_id = _require_field(first.field_id)
    checked_polynomials = _validate_polynomial_tuple(
        witness_polynomials,
        _WITNESS_BITS,
        field_id,
        "witness_polynomials",
    )
    degree, modulus, _rho = _field_parameters(field_id)

    point_two = 2
    at_zero = evaluate_lifted_constraints(
        checked_statement,
        field_id,
        _evaluate_polynomials_at(checked_polynomials, field_id, 0),
    )
    at_one = evaluate_lifted_constraints(
        checked_statement,
        field_id,
        _evaluate_polynomials_at(checked_polynomials, field_id, 1),
    )
    at_two = evaluate_lifted_constraints(
        checked_statement,
        field_id,
        _evaluate_polynomials_at(checked_polynomials, field_id, point_two),
    )

    denominator = _raw_mul(degree, modulus, point_two, point_two) ^ point_two
    inverse_denominator = gf_inv(field_id, denominator)
    linear: list[int] = []
    quadratic: list[int] = []
    for constant, value_one, value_two in zip(
        at_zero,
        at_one,
        at_two,
        strict=True,
    ):
        linear_plus_quadratic = value_one ^ constant
        numerator = (
            value_two
            ^ constant
            ^ _raw_mul(
                degree,
                modulus,
                point_two,
                linear_plus_quadratic,
            )
        )
        quadratic_coefficient = _raw_mul(
            degree,
            modulus,
            numerator,
            inverse_denominator,
        )
        quadratic.append(quadratic_coefficient)
        linear.append(linear_plus_quadratic ^ quadratic_coefficient)
    return ConstraintPolynomials(
        field_id,
        at_zero,
        tuple(linear),
        tuple(quadratic),
    )


def _validate_gammas(
    gammas: object,
    field_id: FieldId,
) -> tuple[tuple[int, ...], ...]:
    _degree, _modulus, rho = _field_parameters(field_id)
    if type(gammas) is not tuple:
        raise TypeError("gammas must be an exact tuple")
    if len(gammas) != rho:
        raise RelationError(f"gammas must contain exactly {rho} rows")
    for row_index, row in enumerate(gammas):
        if type(row) is not tuple:
            raise TypeError(f"gammas[{row_index}] must be an exact tuple")
        if len(row) != _CONSTRAINTS:
            raise RelationError(
                f"gammas[{row_index}] must contain exactly 576 elements"
            )
        for column_index, element in enumerate(row):
            _require_element(
                field_id,
                element,
                f"gammas[{row_index}][{column_index}]",
            )
    return gammas


def build_q_and_qbar(
    statement: CAPStatement,
    polynomials: RepetitionPolynomials,
    gammas: tuple[tuple[int, ...], ...],
) -> QPolynomials:
    """Build Protocol-11 ``q`` and degree-zero ``Qbar`` coefficients."""

    checked_statement = _require_statement(statement)
    field_id = _repetition_field(polynomials)
    checked_gammas = _validate_gammas(gammas, field_id)
    constraints = build_constraint_polynomials(
        checked_statement,
        polynomials.witness_polynomials,
    )
    if any(constraints.constant):
        raise RelationError("witness does not satisfy the CAP relation")

    degree, modulus, rho = _field_parameters(field_id)
    q: list[int] = []
    qbar: list[int] = []
    for k in range(rho):
        g_linear = 0
        g_quadratic = 0
        for gamma, linear_coefficient, quadratic_coefficient in zip(
            checked_gammas[k],
            constraints.linear,
            constraints.quadratic,
            strict=True,
        ):
            if gamma:
                g_linear ^= _raw_mul(
                    degree,
                    modulus,
                    gamma,
                    linear_coefficient,
                )
                g_quadratic ^= _raw_mul(
                    degree,
                    modulus,
                    gamma,
                    quadratic_coefficient,
                )
        mask_polynomial = polynomials.relation_masks[k]
        q.append(mask_polynomial.plain ^ g_linear)
        qbar.append(mask_polynomial.mask ^ g_quadratic)
    return QPolynomials(field_id, tuple(q), tuple(qbar))


def reconstruct_opened_q(
    statement: CAPStatement,
    point: FiniteEvaluationPoint,
    witness_values: tuple[int, ...],
    relation_mask_values: tuple[int, ...],
    qbar: tuple[int, ...],
    gammas: tuple[tuple[int, ...], ...],
) -> tuple[int, ...]:
    """Reconstruct the h3-bound ``q`` values at one finite nonzero opening."""

    checked_statement = _require_statement(statement)
    if type(point) is not FiniteEvaluationPoint:
        raise TypeError("point must be exactly FiniteEvaluationPoint")
    field_id = _require_field(point.field_id)
    x = _require_element(field_id, point.value, "point.value")
    if x == 0:
        raise RelationError("finite opening point must be nonzero")
    _degree, _modulus, rho = _field_parameters(field_id)
    checked_witness_values = _validate_field_vector(
        witness_values,
        _WITNESS_BITS,
        field_id,
        "witness_values",
    )
    checked_masks = _validate_field_vector(
        relation_mask_values,
        rho,
        field_id,
        "relation_mask_values",
    )
    checked_qbar = _validate_field_vector(qbar, rho, field_id, "qbar")
    checked_gammas = _validate_gammas(gammas, field_id)
    constraints = evaluate_lifted_constraints(
        checked_statement,
        field_id,
        checked_witness_values,
    )

    degree, modulus, _rho = _field_parameters(field_id)
    inverse_x = gf_inv(field_id, x)
    reconstructed: list[int] = []
    for k in range(rho):
        # Protocol 11 evaluates X*M(X)+G(X).  ``relation_mask_values`` is
        # M(x), so the explicit x factor must be applied here; omitting it
        # would contradict both the polynomial identity and q=m0+g1.
        right = _raw_mul(degree, modulus, x, checked_masks[k])
        for gamma, constraint in zip(
            checked_gammas[k],
            constraints,
            strict=True,
        ):
            if gamma:
                right ^= _raw_mul(degree, modulus, gamma, constraint)
        reconstructed.append(
            _raw_mul(degree, modulus, inverse_x, right)
            ^ _raw_mul(degree, modulus, x, checked_qbar[k])
        )
    return tuple(reconstructed)


__all__ = (
    "CAPStatement",
    "CAPWitness",
    "ConstraintPolynomials",
    "CorrectionData",
    "QPolynomials",
    "RelationError",
    "RepetitionCorrection",
    "RepetitionPolynomials",
    "apply_delta_z",
    "build_consistency_polynomials",
    "build_constraint_polynomials",
    "build_q_and_qbar",
    "correct_repetitions",
    "decode_correction_data",
    "derive_r_and_delta_z",
    "encode_correction_data",
    "evaluate_lifted_constraints",
    "reconstruct_opened_q",
    "relation_holds",
    "witness_bits",
    "witness_bytes",
)
