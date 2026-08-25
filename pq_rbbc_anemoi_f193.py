#!/usr/bin/env python3
"""Source-pinned Anemoi component probe over GF(2^193) for PQ-RBBC v1.9.

This module implements the public ``anemoi-hash`` Sage construction at commit
3e86ff0cafa54839709b2fa2de0e75d7dd2db464 for the concrete tuple

    q = 2^193, n_cols = 4, security_level = 192, alpha = 3.

It also lowers the characteristic-two closed-Flystel verification equations to
ordinary rank-one rows over GF(2^193).  The resulting 336 nonlinear rows verify
one 14-round upstream-main permutation.  Eight additional linear-output rows
bind the final state.

This is deliberately *not* labelled the Blind-UOV CAP hash.  ePrint 2025/895
reports 240 constraints for its level-III Anemoi permutation but does not ship
the corresponding bit-exact parameter file or constraint generator.  The
public upstream round rule yields 14 rounds, while the Anemoi paper's explicit
characteristic-two formula yields 15.  Neither count gives 240 under the direct
six-row closed-Flystel lowering.  The manifest therefore records a fail-closed
parameter gap instead of silently inventing a production instance.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence


IMPLEMENTATION_VERSION = "1.9"
COMPONENT_RELATION_ID = "anemoi/upstream-main/gf2-193/state-8/v1"
UPSTREAM_REPOSITORY = "https://github.com/anemoi-hash/anemoi-hash"
UPSTREAM_COMMIT = "3e86ff0cafa54839709b2fa2de0e75d7dd2db464"
UPSTREAM_SOURCE_SHA256 = (
    "d170bef2a32382e6d644ac3500ca150506cbd543d95d4efe5bbaf550f753941c"
)

FIELD_DEGREE = 193
FIELD_ORDER = 1 << FIELD_DEGREE
FIELD_MASK = FIELD_ORDER - 1
CONWAY_EXPONENTS = (193, 8, 7, 6, 5, 4, 2, 1, 0)
MODULUS_POLYNOMIAL = sum(1 << exponent for exponent in CONWAY_EXPONENTS)
REDUCTION_POLYNOMIAL = MODULUS_POLYNOMIAL ^ FIELD_ORDER
FIELD_ELEMENT_BYTES = (FIELD_DEGREE + 7) // 8


def _build_reduction_tables() -> tuple[tuple[int, ...], ...]:
    """Precompute byte-wise reductions of degrees 193 through 385."""

    basis: list[int] = []
    current = REDUCTION_POLYNOMIAL
    for _ in range(FIELD_DEGREE):
        basis.append(current)
        current <<= 1
        if current & FIELD_ORDER:
            current ^= MODULUS_POLYNOMIAL
    tables: list[tuple[int, ...]] = []
    for byte_position in range((FIELD_DEGREE + 7) // 8):
        entries: list[int] = []
        for byte in range(256):
            reduced = 0
            for bit in range(8):
                index = 8 * byte_position + bit
                if index < FIELD_DEGREE and ((byte >> bit) & 1):
                    reduced ^= basis[index]
            entries.append(reduced)
        tables.append(tuple(entries))
    return tuple(tables)


_REDUCTION_BYTE_TABLES = _build_reduction_tables()
_SQUARE_BYTE_TABLE = tuple(
    sum(((byte >> bit) & 1) << (2 * bit) for bit in range(8))
    for byte in range(256)
)

SECURITY_LEVEL = 192
N_COLS = 4
STATE_ELEMENTS = 2 * N_COLS
ALPHA = 3
QUAD = 3
UPSTREAM_ROUNDS = 14
PAPER_CHARACTERISTIC_TWO_ROUNDS = 15
BLIND_UOV_REPORTED_CONSTRAINTS = 240
ROWS_PER_BINARY_FLYSTEL = 6
NONLINEAR_ROWS = UPSTREAM_ROUNDS * N_COLS * ROWS_PER_BINARY_FLYSTEL
OUTPUT_BINDING_ROWS = STATE_ELEMENTS
TOTAL_ROWS = NONLINEAR_ROWS + OUTPUT_BINDING_ROWS

PI_0 = int(
    "1415926535897932384626433832795028841971693993751058209749445923"
    "078164062862089986280348253421170679"
)
PI_1 = int(
    "8214808651328230664709384460955058223172535940812848111745028410"
    "270193852110555964462294895493038196"
)


def fadd(left: int, right: int) -> int:
    """Addition in the polynomial basis of GF(2^193)."""

    return left ^ right


def fmul(left: int, right: int) -> int:
    """Carry-less multiplication reduced by the degree-193 Conway polynomial."""

    if left < 0 or left > FIELD_MASK or right < 0 or right > FIELD_MASK:
        raise ValueError("field element outside canonical 193-bit representation")
    # Four-bit comb multiplication uses only 49 Python-level iterations for a
    # 193-bit operand.  Reduction is then handled in 25 byte-table lookups.
    partials = [0] * 16
    for nibble in range(1, 16):
        partial = 0
        for bit in range(4):
            if (nibble >> bit) & 1:
                partial ^= left << bit
        partials[nibble] = partial
    product = 0
    multiplier = right
    shift = 0
    while multiplier:
        product ^= partials[multiplier & 0xF] << shift
        multiplier >>= 4
        shift += 4
    return _freduce(product)


def fsquare(value: int) -> int:
    """Frobenius square using byte interleaving and frozen reduction tables."""

    if value < 0 or value > FIELD_MASK:
        raise ValueError("field element outside canonical 193-bit representation")
    expanded = 0
    byte_position = 0
    remaining = value
    while remaining:
        expanded ^= _SQUARE_BYTE_TABLE[remaining & 0xFF] << (16 * byte_position)
        remaining >>= 8
        byte_position += 1
    return _freduce(expanded)


def fpow(base: int, exponent: int) -> int:
    if exponent < 0:
        return fpow(finv(base), -exponent)
    result = 1
    factor = base
    power = exponent
    while power:
        if power & 1:
            result = fmul(result, factor)
        factor = fsquare(factor)
        power >>= 1
    return result


def _freduce(value: int) -> int:
    """Reduce a binary polynomial modulo the frozen degree-193 modulus."""

    if value < 0:
        raise ValueError("cannot reduce a negative polynomial")
    # The byte tables cover products and squares up to degree 385.  Retain a
    # generic prefix for extended-Euclid intermediates that happen to be wider.
    while value.bit_length() - 1 >= 2 * FIELD_DEGREE:
        shift = value.bit_length() - 1 - FIELD_DEGREE
        value ^= MODULUS_POLYNOMIAL << shift
    reduced = value & FIELD_MASK
    high = value >> FIELD_DEGREE
    byte_position = 0
    while high:
        reduced ^= _REDUCTION_BYTE_TABLES[byte_position][high & 0xFF]
        high >>= 8
        byte_position += 1
    return reduced


def fcuberoot(value: int) -> int:
    """Return the unique cube root in GF(2^193) with a short addition chain.

    Since ``3^{-1} mod (2^193-1) = 1 + 2^2 + ... + 2^192``, a direct binary
    exponentiation needs 96 multiplications.  The divide-and-conquer recurrence
    for the geometric sum needs only logarithmically many multiplications while
    preserving the same exponent.
    """

    if value < 0 or value > FIELD_MASK:
        raise ValueError("field element outside canonical 193-bit representation")

    def fourth_power_repeated(element: int, count: int) -> int:
        for _ in range(count):
            element = fsquare(fsquare(element))
        return element

    def geometric_sum_power(terms: int) -> int:
        if terms == 1:
            return value
        half = terms // 2
        lower = geometric_sum_power(half)
        if terms % 2 == 0:
            return fmul(lower, fourth_power_repeated(lower, half))
        extended = fmul(
            lower,
            fourth_power_repeated(value, half),
        )
        return fmul(lower, fourth_power_repeated(extended, half))

    return geometric_sum_power((FIELD_DEGREE + 1) // 2)


def finv(value: int) -> int:
    """Invert with binary-polynomial extended Euclid.

    This is mathematically identical to exponentiation by ``2^193 - 2`` but
    avoids hundreds of carry-less field multiplications per inverse.  The
    faster implementation matters for CAP seed trees, which invoke the frozen
    Anemoi permutation many thousands of times.
    """

    if value == 0:
        raise ZeroDivisionError("zero has no multiplicative inverse")
    if value < 0 or value > FIELD_MASK:
        raise ValueError("field element outside canonical 193-bit representation")

    u = value
    v = MODULUS_POLYNOMIAL
    g_u = 1
    g_v = 0
    while u != 1:
        shift = u.bit_length() - v.bit_length()
        if shift < 0:
            u, v = v, u
            g_u, g_v = g_v, g_u
            shift = -shift
        u ^= v << shift
        g_u ^= g_v << shift
    return _freduce(g_u)


def fhex(value: int) -> str:
    if value < 0 or value > FIELD_MASK:
        raise ValueError("field element outside canonical range")
    return value.to_bytes(FIELD_ELEMENT_BYTES, "big").hex()


def upstream_round_count(security_level: int, n_cols: int, alpha: int) -> int:
    """Exact ``get_n_rounds`` rule in the pinned upstream Sage source."""

    kappa = {3: 1, 5: 2, 7: 4, 9: 7, 11: 9}
    if alpha not in kappa:
        raise ValueError("unsupported alpha for upstream round rule")
    rounds_for_attack = 0
    complexity = 0
    while complexity < 1 << security_level:
        rounds_for_attack += 1
        complexity = math.comb(
            4 * n_cols * rounds_for_attack + kappa[alpha],
            2 * n_cols * rounds_for_attack,
        ) ** 2
    return max(8, rounds_for_attack + 2 + min(5, n_cols + 1))


def paper_characteristic_two_round_count(
    security_level: int, n_cols: int
) -> int:
    """Equation (2) plus Estimate 1 in the Anemoi paper, with omega=2."""

    rounds_for_attack = 0
    complexity = 0
    while complexity < 1 << security_level:
        rounds_for_attack += 1
        complexity = (
            n_cols
            * rounds_for_attack
            * 9 ** (2 * n_cols * rounds_for_attack)
        )
    return max(8, rounds_for_attack + 2 + min(5, n_cols + 1))


def m4(vector: Sequence[int], coefficient: int) -> list[int]:
    if len(vector) != 4:
        raise ValueError("M_4 requires four field elements")
    value = list(vector)
    value[0] ^= value[1]
    value[2] ^= value[3]
    value[3] ^= fmul(coefficient, value[0])
    value[1] = fmul(coefficient, value[1] ^ value[2])
    value[0] ^= value[1]
    value[2] ^= fmul(coefficient, value[3])
    value[1] ^= value[2]
    value[3] ^= value[0]
    return value


def _determinant(matrix: Sequence[Sequence[int]]) -> int:
    size = len(matrix)
    if size == 0:
        return 1
    if any(len(row) != size for row in matrix):
        raise ValueError("determinant requires a square matrix")
    result = 0
    # Signs disappear in characteristic two.
    for permutation in itertools.permutations(range(size)):
        product = 1
        for row, column in enumerate(permutation):
            product = fmul(product, matrix[row][column])
        result ^= product
    return result


def is_mds(matrix: Sequence[Sequence[int]]) -> bool:
    size = len(matrix)
    if size < 2 or any(len(row) != size for row in matrix):
        return False
    for minor_size in range(1, size + 1):
        for rows in itertools.combinations(range(size), minor_size):
            for columns in itertools.combinations(range(size), minor_size):
                minor = [[matrix[row][column] for column in columns] for row in rows]
                if _determinant(minor) == 0:
                    return False
    return True


def derive_mds() -> tuple[int, tuple[tuple[int, ...], ...]]:
    """Replicate upstream ``get_mds`` for four columns."""

    generator = 2  # Root of the primitive Conway polynomial.
    coefficient = 1
    for exponent in itertools.count(1):
        coefficient = fmul(coefficient, generator)
        transformed_basis = []
        for index in range(N_COLS):
            basis = [0] * N_COLS
            basis[index] = 1
            transformed_basis.append(m4(basis, coefficient))
        matrix = tuple(
            tuple(transformed_basis[column][row] for column in range(N_COLS))
            for row in range(N_COLS)
        )
        if is_mds(matrix):
            return exponent, matrix


def matrix_vector(
    matrix: Sequence[Sequence[int]], vector: Sequence[int]
) -> list[int]:
    if not matrix or len(matrix[0]) != len(vector):
        raise ValueError("matrix/vector dimension mismatch")
    result: list[int] = []
    for row in matrix:
        value = 0
        for coefficient, element in zip(row, vector):
            value ^= fmul(coefficient, element)
        result.append(value)
    return result


@dataclass(frozen=True)
class AnemoiParameters:
    rounds: int
    mds_generator_exponent: int
    mds_matrix: tuple[tuple[int, ...], ...]
    round_constants_c: tuple[tuple[int, ...], ...]
    round_constants_d: tuple[tuple[int, ...], ...]
    beta: int
    delta: int
    alpha_inverse: int

    def canonical_dict(self) -> dict[str, object]:
        return {
            "alpha": ALPHA,
            "alpha_inverse": str(self.alpha_inverse),
            "beta": fhex(self.beta),
            "conway_exponents": list(CONWAY_EXPONENTS),
            "delta": fhex(self.delta),
            "field": "GF(2^193)",
            "mds_generator_exponent": self.mds_generator_exponent,
            "mds_matrix": [
                [fhex(element) for element in row] for row in self.mds_matrix
            ],
            "n_cols": N_COLS,
            "quad": QUAD,
            "round_constants_c": [
                [fhex(element) for element in row]
                for row in self.round_constants_c
            ],
            "round_constants_d": [
                [fhex(element) for element in row]
                for row in self.round_constants_d
            ],
            "rounds": self.rounds,
            "security_level": SECURITY_LEVEL,
            "state_elements": STATE_ELEMENTS,
            "upstream_commit": UPSTREAM_COMMIT,
            "upstream_source_sha256": UPSTREAM_SOURCE_SHA256,
        }

    def fingerprint(self) -> str:
        payload = json.dumps(
            self.canonical_dict(), sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        return hashlib.sha256(payload).hexdigest()


def derive_parameters(rounds: int = UPSTREAM_ROUNDS) -> AnemoiParameters:
    if rounds <= 0:
        raise ValueError("round count must be positive")
    mds_exponent, mds_matrix = derive_mds()
    generator = 2
    delta = finv(generator)
    alpha_inverse = pow(ALPHA, -1, FIELD_ORDER - 1)
    pi_0 = PI_0 % FIELD_ORDER
    pi_1 = PI_1 % FIELD_ORDER
    constants_c: list[tuple[int, ...]] = []
    constants_d: list[tuple[int, ...]] = []
    for round_index in range(rounds):
        pi_0_r = fpow(pi_0, round_index)
        row_c: list[int] = []
        row_d: list[int] = []
        for column in range(N_COLS):
            pi_1_i = fpow(pi_1, column)
            power_alpha = fpow(pi_0_r ^ pi_1_i, ALPHA)
            row_c.append(
                fmul(generator, fpow(pi_0_r, 2)) ^ power_alpha
            )
            row_d.append(
                fmul(generator, fpow(pi_1_i, 2)) ^ power_alpha ^ delta
            )
        constants_c.append(tuple(row_c))
        constants_d.append(tuple(row_d))
    return AnemoiParameters(
        rounds=rounds,
        mds_generator_exponent=mds_exponent,
        mds_matrix=mds_matrix,
        round_constants_c=tuple(constants_c),
        round_constants_d=tuple(constants_d),
        beta=generator,
        delta=delta,
        alpha_inverse=alpha_inverse,
    )


def linear_layer(
    x: Sequence[int], y: Sequence[int], parameters: AnemoiParameters
) -> tuple[list[int], list[int]]:
    x_value = matrix_vector(parameters.mds_matrix, x)
    y_value = matrix_vector(parameters.mds_matrix, list(y[1:]) + [y[0]])
    y_value = [left ^ right for left, right in zip(y_value, x_value)]
    x_value = [left ^ right for left, right in zip(x_value, y_value)]
    return x_value, y_value


def evaluate_sbox(
    x: int, y: int, parameters: AnemoiParameters
) -> tuple[int, int]:
    x_value = x ^ fmul(parameters.beta, fpow(y, QUAD))
    y_value = y ^ fcuberoot(x_value)
    x_value ^= fmul(parameters.beta, fpow(y_value, QUAD)) ^ parameters.delta
    return x_value, y_value


def evaluate_permutation(
    state: Sequence[int], parameters: AnemoiParameters
) -> tuple[int, ...]:
    if len(state) != STATE_ELEMENTS:
        raise ValueError("Anemoi state must contain eight field elements")
    if any(value < 0 or value > FIELD_MASK for value in state):
        raise ValueError("state element outside GF(2^193)")
    x = list(state[:N_COLS])
    y = list(state[N_COLS:])
    for round_index in range(parameters.rounds):
        x = [
            value ^ parameters.round_constants_c[round_index][column]
            for column, value in enumerate(x)
        ]
        y = [
            value ^ parameters.round_constants_d[round_index][column]
            for column, value in enumerate(y)
        ]
        x, y = linear_layer(x, y, parameters)
        for column in range(N_COLS):
            x[column], y[column] = evaluate_sbox(
                x[column], y[column], parameters
            )
    x, y = linear_layer(x, y, parameters)
    return tuple(x + y)


@dataclass(frozen=True)
class LinearForm:
    terms: tuple[tuple[int, int], ...] = ()
    constant: int = 0

    @staticmethod
    def wire(wire_id: int, coefficient: int = 1) -> "LinearForm":
        return LinearForm(((wire_id, coefficient),), 0)

    @staticmethod
    def const(value: int) -> "LinearForm":
        return LinearForm((), value)

    def add(self, other: "LinearForm") -> "LinearForm":
        coefficients: dict[int, int] = {}
        for wire_id, coefficient in self.terms + other.terms:
            coefficients[wire_id] = coefficients.get(wire_id, 0) ^ coefficient
        return LinearForm(
            tuple(
                (wire_id, coefficient)
                for wire_id, coefficient in sorted(coefficients.items())
                if coefficient
            ),
            self.constant ^ other.constant,
        )

    def scale(self, coefficient: int) -> "LinearForm":
        return LinearForm(
            tuple(
                (wire_id, fmul(coefficient, value))
                for wire_id, value in self.terms
                if fmul(coefficient, value)
            ),
            fmul(coefficient, self.constant),
        )

    def evaluate(self, assignment: Mapping[int, int]) -> int:
        value = self.constant
        for wire_id, coefficient in self.terms:
            value ^= fmul(coefficient, assignment[wire_id])
        return value

    def canonical_dict(self) -> dict[str, object]:
        return {
            "constant": fhex(self.constant),
            "terms": [
                [wire_id, fhex(coefficient)]
                for wire_id, coefficient in self.terms
            ],
        }


def add_forms(*forms: LinearForm) -> LinearForm:
    result = LinearForm()
    for form in forms:
        result = result.add(form)
    return result


def matrix_forms(
    matrix: Sequence[Sequence[int]], vector: Sequence[LinearForm]
) -> list[LinearForm]:
    result: list[LinearForm] = []
    for row in matrix:
        result.append(
            add_forms(
                *(form.scale(coefficient) for coefficient, form in zip(row, vector))
            )
        )
    return result


def linear_layer_forms(
    x: Sequence[LinearForm],
    y: Sequence[LinearForm],
    parameters: AnemoiParameters,
) -> tuple[list[LinearForm], list[LinearForm]]:
    x_value = matrix_forms(parameters.mds_matrix, x)
    y_value = matrix_forms(parameters.mds_matrix, list(y[1:]) + [y[0]])
    y_value = [left.add(right) for left, right in zip(y_value, x_value)]
    x_value = [left.add(right) for left, right in zip(x_value, y_value)]
    return x_value, y_value


@dataclass(frozen=True)
class RankOneRow:
    label: str
    left: LinearForm
    right: LinearForm
    output: LinearForm

    def satisfied(self, assignment: Mapping[int, int]) -> bool:
        return fmul(
            self.left.evaluate(assignment), self.right.evaluate(assignment)
        ) == self.output.evaluate(assignment)

    def canonical_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "left": self.left.canonical_dict(),
            "output": self.output.canonical_dict(),
            "right": self.right.canonical_dict(),
        }


@dataclass(frozen=True)
class NativeTrace:
    rows: tuple[RankOneRow, ...]
    assignment: dict[int, int]
    input_wires: tuple[int, ...]
    output_wires: tuple[int, ...]
    wire_labels: dict[int, str]
    output_state: tuple[int, ...]
    nonlinear_rows: int
    output_binding_rows: int

    def failed_rows(self, assignment: Mapping[int, int] | None = None) -> list[str]:
        values = self.assignment if assignment is None else assignment
        return [row.label for row in self.rows if not row.satisfied(values)]


class NativeRowBuilder:
    def __init__(self) -> None:
        self.next_wire = 1
        self.assignment: dict[int, int] = {}
        self.wire_labels: dict[int, str] = {}
        self.rows: list[RankOneRow] = []

    def new_wire(self, value: int, label: str) -> LinearForm:
        wire_id = self.next_wire
        self.next_wire += 1
        self.assignment[wire_id] = value
        self.wire_labels[wire_id] = label
        return LinearForm.wire(wire_id)

    def row(
        self, label: str, left: LinearForm, right: LinearForm, output: LinearForm
    ) -> None:
        self.rows.append(RankOneRow(label, left, right, output))


def _form_value(form: LinearForm, builder: NativeRowBuilder) -> int:
    return form.evaluate(builder.assignment)


def build_native_trace(
    state: Sequence[int], parameters: AnemoiParameters
) -> NativeTrace:
    if len(state) != STATE_ELEMENTS:
        raise ValueError("Anemoi state must contain eight field elements")
    builder = NativeRowBuilder()
    inputs = [
        builder.new_wire(value, f"input[{index}]")
        for index, value in enumerate(state)
    ]
    input_wires = tuple(form.terms[0][0] for form in inputs)
    x = inputs[:N_COLS]
    y = inputs[N_COLS:]
    beta_inverse = finv(parameters.beta)

    for round_index in range(parameters.rounds):
        x = [
            form.add(LinearForm.const(parameters.round_constants_c[round_index][column]))
            for column, form in enumerate(x)
        ]
        y = [
            form.add(LinearForm.const(parameters.round_constants_d[round_index][column]))
            for column, form in enumerate(y)
        ]
        x, y = linear_layer_forms(x, y, parameters)

        next_x: list[LinearForm] = []
        next_y: list[LinearForm] = []
        for column in range(N_COLS):
            x_value = _form_value(x[column], builder)
            y_value = _form_value(y[column], builder)
            u_value, v_value = evaluate_sbox(x_value, y_value, parameters)
            u = builder.new_wire(u_value, f"r{round_index}.u[{column}]")
            v = builder.new_wire(v_value, f"r{round_index}.v[{column}]")
            w = y[column].add(v)
            w_value = y_value ^ v_value
            w2 = builder.new_wire(
                fmul(w_value, w_value), f"r{round_index}.w2[{column}]"
            )
            y2 = builder.new_wire(
                fmul(y_value, y_value), f"r{round_index}.y2[{column}]"
            )
            y3 = builder.new_wire(
                fpow(y_value, 3), f"r{round_index}.y3[{column}]"
            )
            v2 = builder.new_wire(
                fmul(v_value, v_value), f"r{round_index}.v2[{column}]"
            )
            prefix = f"r{round_index}.c{column}"
            builder.row(f"{prefix}.w2", w, w, w2)
            builder.row(f"{prefix}.y2", y[column], y[column], y2)
            builder.row(f"{prefix}.y3", y2, y[column], y3)
            builder.row(
                f"{prefix}.closed_x",
                w2,
                w,
                x[column].add(y3.scale(parameters.beta)),
            )
            builder.row(f"{prefix}.v2", v, v, v2)
            builder.row(
                f"{prefix}.closed_u",
                v2,
                v,
                add_forms(
                    u,
                    x[column],
                    y3.scale(parameters.beta),
                    LinearForm.const(parameters.delta),
                ).scale(beta_inverse),
            )
            next_x.append(u)
            next_y.append(v)
        x, y = next_x, next_y

    x, y = linear_layer_forms(x, y, parameters)
    expected_output = tuple(
        _form_value(form, builder) for form in list(x) + list(y)
    )
    direct_output = evaluate_permutation(state, parameters)
    if expected_output != direct_output:
        raise AssertionError("symbolic and direct Anemoi evaluations disagree")

    output_forms = [
        builder.new_wire(value, f"output[{index}]")
        for index, value in enumerate(expected_output)
    ]
    output_wires = tuple(form.terms[0][0] for form in output_forms)
    for index, (output, expression) in enumerate(
        zip(output_forms, list(x) + list(y))
    ):
        builder.row(
            f"output[{index}]",
            output.add(expression),
            LinearForm.const(1),
            LinearForm.const(0),
        )

    trace = NativeTrace(
        rows=tuple(builder.rows),
        assignment=dict(builder.assignment),
        input_wires=input_wires,
        output_wires=output_wires,
        wire_labels=dict(builder.wire_labels),
        output_state=expected_output,
        nonlinear_rows=parameters.rounds * N_COLS * ROWS_PER_BINARY_FLYSTEL,
        output_binding_rows=STATE_ELEMENTS,
    )
    if len(trace.rows) != trace.nonlinear_rows + trace.output_binding_rows:
        raise AssertionError("native row accounting mismatch")
    return trace


def serialize_row_stream(
    trace: NativeTrace, parameters: AnemoiParameters
) -> bytes:
    document = {
        "format": "F193-R1CS-JSON-1",
        "input_wires": list(trace.input_wires),
        "output_wires": list(trace.output_wires),
        "parameter_fingerprint": parameters.fingerprint(),
        "relation_id": COMPONENT_RELATION_ID,
        "rows": [row.canonical_dict() for row in trace.rows],
    }
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def _source_pin_status(path: Path | None) -> tuple[bool, str | None]:
    if path is None:
        return False, None
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest == UPSTREAM_SOURCE_SHA256, digest


def build_manifest(
    trace: NativeTrace,
    parameters: AnemoiParameters,
    upstream_source_path: Path | None = None,
) -> dict[str, object]:
    row_stream = serialize_row_stream(trace, parameters)
    source_verified, observed_source_hash = _source_pin_status(
        upstream_source_path
    )
    zero_state = (0,) * STATE_ELEMENTS
    sequential_state = tuple(range(1, STATE_ELEMENTS + 1))
    return {
        "implementation_version": IMPLEMENTATION_VERSION,
        "component_relation_id": COMPONENT_RELATION_ID,
        "field": {
            "name": "GF(2^193)",
            "basis": "polynomial",
            "canonical_element_bytes": FIELD_ELEMENT_BYTES,
            "conway_polynomial_exponents": list(CONWAY_EXPONENTS),
            "modulus_hex": hex(MODULUS_POLYNOMIAL),
            "source": "Frank Luebeck Conway polynomial database f_{2,193}",
        },
        "upstream_pin": {
            "repository": UPSTREAM_REPOSITORY,
            "commit": UPSTREAM_COMMIT,
            "anemoi_sage_sha256": UPSTREAM_SOURCE_SHA256,
            "observed_source_sha256": observed_source_hash,
            "source_pin_verified_locally": source_verified,
        },
        "parameters": parameters.canonical_dict(),
        "parameter_fingerprint": parameters.fingerprint(),
        "row_stream": {
            "format": "F193-R1CS-JSON-1",
            "sha256": hashlib.sha256(row_stream).hexdigest(),
            "wires": len(trace.assignment),
            "nonlinear_rows": trace.nonlinear_rows,
            "output_binding_rows": trace.output_binding_rows,
            "total_rows": len(trace.rows),
            "honest_failures": trace.failed_rows(),
            "witness_independent_topology": True,
        },
        "regression_vectors": {
            "status": "generated by this implementation; Sage cross-check still required",
            "zero_input_output": [
                fhex(value) for value in evaluate_permutation(zero_state, parameters)
            ],
            "sequential_input_output": [
                fhex(value)
                for value in evaluate_permutation(sequential_state, parameters)
            ],
            "independent_sage_vectors_verified": False,
        },
        "public_artifact_gap": {
            "blind_uov_reported_constraints": BLIND_UOV_REPORTED_CONSTRAINTS,
            "upstream_main_round_rule": upstream_round_count(
                SECURITY_LEVEL, N_COLS, ALPHA
            ),
            "anemoi_paper_characteristic_two_round_rule": paper_characteristic_two_round_count(
                SECURITY_LEVEL, N_COLS
            ),
            "direct_closed_flystel_rows_for_upstream_main": NONLINEAR_ROWS,
            "direct_closed_flystel_rows_for_paper_round_rule": (
                PAPER_CHARACTERISTIC_TWO_ROUNDS
                * N_COLS
                * ROWS_PER_BINARY_FLYSTEL
            ),
            "bit_exact_blind_uov_parameter_file_published": False,
            "reported_count_reproduced": False,
            "gap_resolved": False,
        },
        "claim_boundary": {
            "gf2_193_arithmetic_implemented": True,
            "upstream_main_permutation_implemented": True,
            "rank_one_rows_evaluated": True,
            "blind_uov_cap_commit_implemented": False,
            "blind_uov_cap_hash_implemented": False,
            "blind_uov_bit_exact_match": False,
            "production_closed": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--upstream-source", type=Path)
    args = parser.parse_args()

    if upstream_round_count(SECURITY_LEVEL, N_COLS, ALPHA) != UPSTREAM_ROUNDS:
        raise AssertionError("pinned upstream round derivation changed")
    if (
        paper_characteristic_two_round_count(SECURITY_LEVEL, N_COLS)
        != PAPER_CHARACTERISTIC_TWO_ROUNDS
    ):
        raise AssertionError("paper characteristic-two round derivation changed")

    parameters = derive_parameters()
    trace = build_native_trace((0,) * STATE_ELEMENTS, parameters)
    if trace.failed_rows():
        raise AssertionError("honest native trace failed")
    row_stream = serialize_row_stream(trace, parameters)
    manifest = build_manifest(trace, parameters, args.upstream_source)
    if args.output:
        args.output.write_bytes(row_stream)
    if args.manifest:
        args.manifest.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if not args.output and not args.manifest:
        print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
