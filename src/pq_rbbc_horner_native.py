#!/usr/bin/env python3
"""Native GF(2^193) multiplication and polynomial hashing for PQ-RBBC v2.4.

The rank-one backend already works over GF(2^193), so one variable-by-variable
field multiplication is one native row.  A usable CAP gadget additionally
needs binary input packing, binary output decomposition, and constraints that
the transcript-derived evaluation points are nonzero and pairwise distinct.

This module provides both a standalone bit-bound multiplication fixture and a
generic Horner lowering.  The frozen Horner fixture evaluates the eleven field
coefficients of a 2,048-bit vector at two transcript-derived points.  It is an
independent arithmetic component, not a complete production CAP execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping, Sequence

import pq_rbbc_anemoi_f193 as field


IMPLEMENTATION_VERSION = "2.4"
PROFILE_NAME = "PQ-RBBC-GF193-HORNER-v1"
PROFILE_RELATION_ID = "pq-rbbc/gf2-193/horner/v1"
ROW_FORMAT = "F193-R1CS-JSON-1"
PRODUCTION_WITNESS_BITS = 2_048
PRODUCTION_CONSISTENCY_POINTS = 2


BitForm = field.LinearForm
Bits = tuple[BitForm, ...]


def _wire_id(form: BitForm) -> int:
    if len(form.terms) != 1 or form.terms[0][1] != 1 or form.constant:
        raise ValueError("expected a canonical wire form")
    return form.terms[0][0]


def _allocate_bits(
    builder: field.NativeRowBuilder,
    value: int,
    bit_length: int,
    prefix: str,
) -> Bits:
    if value < 0 or value >= 1 << bit_length:
        raise ValueError("value does not fit declared bit length")
    result: list[BitForm] = []
    for index in range(bit_length):
        form = builder.new_wire(
            (value >> index) & 1,
            f"{prefix}.bit[{index}]",
        )
        builder.row(
            f"{prefix}.bit[{index}].bit",
            form,
            form.add(BitForm.const(1)),
            BitForm.const(0),
        )
        result.append(form)
    return tuple(result)


def pack_field_form(bits: Sequence[BitForm]) -> BitForm:
    """Pack at most 193 LSB-first binary coefficients into one field form."""

    if not bits or len(bits) > field.FIELD_DEGREE:
        raise ValueError("field packing requires 1..193 bits")
    return field.add_forms(
        *(form.scale(1 << index) for index, form in enumerate(bits))
    )


def split_coefficient_forms(vector_bits: Sequence[BitForm]) -> tuple[BitForm, ...]:
    if not vector_bits:
        raise ValueError("polynomial vector must be nonempty")
    return tuple(
        pack_field_form(vector_bits[offset : offset + field.FIELD_DEGREE])
        for offset in range(0, len(vector_bits), field.FIELD_DEGREE)
    )


def _decompose_field_form(
    builder: field.NativeRowBuilder,
    source: BitForm,
    prefix: str,
) -> Bits:
    value = source.evaluate(builder.assignment)
    result = _allocate_bits(builder, value, field.FIELD_DEGREE, prefix)
    builder.row(
        f"{prefix}.pack",
        source.add(pack_field_form(result)),
        BitForm.const(1),
        BitForm.const(0),
    )
    return result


def constrain_nonzero_distinct_points(
    builder: field.NativeRowBuilder,
    point_bits: Sequence[Sequence[BitForm]],
    prefix: str,
) -> int:
    """Constrain every point nonzero and every pair distinct using inverses."""

    if not point_bits:
        raise ValueError("at least one evaluation point is required")
    point_forms = []
    for index, bits in enumerate(point_bits):
        if len(bits) != field.FIELD_DEGREE:
            raise ValueError("evaluation points must contain 193 bits")
        form = pack_field_form(bits)
        value = form.evaluate(builder.assignment)
        if value == 0:
            raise ValueError("evaluation point must be nonzero")
        inverse = builder.new_wire(
            field.finv(value), f"{prefix}.point[{index}].inverse"
        )
        builder.row(
            f"{prefix}.point[{index}].nonzero",
            form,
            inverse,
            BitForm.const(1),
        )
        point_forms.append(form)

    rows = len(point_forms)
    for left in range(len(point_forms)):
        for right in range(left + 1, len(point_forms)):
            difference = point_forms[left].add(point_forms[right])
            value = difference.evaluate(builder.assignment)
            if value == 0:
                raise ValueError("evaluation points must be pairwise distinct")
            inverse = builder.new_wire(
                field.finv(value),
                f"{prefix}.difference[{left},{right}].inverse",
            )
            builder.row(
                f"{prefix}.difference[{left},{right}].nonzero",
                difference,
                inverse,
                BitForm.const(1),
            )
            rows += 1
    return rows


@dataclass(frozen=True)
class HornerLoweringAccounting:
    coefficients: int
    points: int
    multiplication_rows: int
    point_validation_rows: int
    output_bitness_rows: int
    output_pack_rows: int


def lower_polynomial_hash(
    builder: field.NativeRowBuilder,
    vector_bits: Sequence[BitForm],
    point_bits: Sequence[Sequence[BitForm]],
    prefix: str,
    *,
    validate_points: bool = True,
) -> tuple[Bits, HornerLoweringAccounting]:
    """Lower polynomial evaluation to native rows on an existing builder."""

    coefficients = split_coefficient_forms(vector_bits)
    points = tuple(tuple(bits) for bits in point_bits)
    if not points:
        raise ValueError("at least one evaluation point is required")
    if any(len(bits) != field.FIELD_DEGREE for bits in points):
        raise ValueError("each evaluation point must contain 193 bits")

    validation_rows = (
        constrain_nonzero_distinct_points(builder, points, f"{prefix}.validate")
        if validate_points
        else 0
    )
    output: list[BitForm] = []
    multiplication_rows = 0
    for point_index, bits in enumerate(points):
        point = pack_field_form(bits)
        accumulator = coefficients[-1]
        for coefficient_index in range(len(coefficients) - 2, -1, -1):
            product_value = field.fmul(
                accumulator.evaluate(builder.assignment),
                point.evaluate(builder.assignment),
            )
            product = builder.new_wire(
                product_value,
                f"{prefix}.point[{point_index}].mul[{coefficient_index}]",
            )
            builder.row(
                f"{prefix}.point[{point_index}].mul[{coefficient_index}]",
                accumulator,
                point,
                product,
            )
            multiplication_rows += 1
            accumulator = product.add(coefficients[coefficient_index])
        output.extend(
            _decompose_field_form(
                builder,
                accumulator,
                f"{prefix}.point[{point_index}].output",
            )
        )

    accounting = HornerLoweringAccounting(
        coefficients=len(coefficients),
        points=len(points),
        multiplication_rows=multiplication_rows,
        point_validation_rows=validation_rows,
        output_bitness_rows=len(points) * field.FIELD_DEGREE,
        output_pack_rows=len(points),
    )
    return tuple(output), accounting


def evaluate_polynomial_hash(
    vector: int,
    vector_bits: int,
    points: Sequence[int],
) -> tuple[int, ...]:
    if vector_bits <= 0 or vector < 0 or vector >= 1 << vector_bits:
        raise ValueError("invalid polynomial vector")
    coefficients = [
        (vector >> offset)
        & ((1 << min(field.FIELD_DEGREE, vector_bits - offset)) - 1)
        for offset in range(0, vector_bits, field.FIELD_DEGREE)
    ]
    result: list[int] = []
    for point in points:
        if point <= 0 or point > field.FIELD_MASK:
            raise ValueError("invalid evaluation point")
        accumulator = coefficients[-1]
        for coefficient in reversed(coefficients[:-1]):
            accumulator = field.fmul(accumulator, point) ^ coefficient
        result.append(accumulator)
    return tuple(result)


@dataclass(frozen=True)
class MultiplicationTrace:
    rows: tuple[field.RankOneRow, ...]
    assignment: dict[int, int]
    wire_labels: dict[int, str]
    left_bit_wires: tuple[int, ...]
    right_bit_wires: tuple[int, ...]
    output_bit_wires: tuple[int, ...]
    output: int
    multiplication_rows: int
    input_bitness_rows: int
    output_bitness_rows: int
    output_pack_rows: int

    def failed_rows(self, assignment: Mapping[int, int] | None = None) -> list[str]:
        values = self.assignment if assignment is None else assignment
        return [row.label for row in self.rows if not row.satisfied(values)]


def build_multiplication_trace(left: int, right: int) -> MultiplicationTrace:
    if left < 0 or left > field.FIELD_MASK or right < 0 or right > field.FIELD_MASK:
        raise ValueError("field operand is not canonical")
    builder = field.NativeRowBuilder()
    left_bits = _allocate_bits(builder, left, field.FIELD_DEGREE, "left")
    right_bits = _allocate_bits(builder, right, field.FIELD_DEGREE, "right")
    left_form = pack_field_form(left_bits)
    right_form = pack_field_form(right_bits)
    product_value = field.fmul(left, right)
    product = builder.new_wire(product_value, "product")
    builder.row("product.mul", left_form, right_form, product)
    output_bits = _decompose_field_form(builder, product, "output")
    trace = MultiplicationTrace(
        rows=tuple(builder.rows),
        assignment=dict(builder.assignment),
        wire_labels=dict(builder.wire_labels),
        left_bit_wires=tuple(_wire_id(form) for form in left_bits),
        right_bit_wires=tuple(_wire_id(form) for form in right_bits),
        output_bit_wires=tuple(_wire_id(form) for form in output_bits),
        output=product_value,
        multiplication_rows=1,
        input_bitness_rows=2 * field.FIELD_DEGREE,
        output_bitness_rows=field.FIELD_DEGREE,
        output_pack_rows=1,
    )
    if trace.failed_rows():
        raise AssertionError("honest multiplication trace failed")
    return trace


@dataclass(frozen=True)
class HornerTrace:
    rows: tuple[field.RankOneRow, ...]
    assignment: dict[int, int]
    wire_labels: dict[int, str]
    vector_bit_wires: tuple[int, ...]
    point_bit_wires: tuple[tuple[int, ...], ...]
    output_bit_wires: tuple[int, ...]
    vector_bits: int
    points: tuple[int, ...]
    output_fields: tuple[int, ...]
    output_bytes: bytes
    accounting: HornerLoweringAccounting
    input_bitness_rows: int
    external_assertions: int

    def failed_rows(self, assignment: Mapping[int, int] | None = None) -> list[str]:
        values = self.assignment if assignment is None else assignment
        return [row.label for row in self.rows if not row.satisfied(values)]

    @property
    def nonlinear_rows(self) -> int:
        return (
            self.input_bitness_rows
            + self.accounting.multiplication_rows
            + self.accounting.point_validation_rows
            + self.accounting.output_bitness_rows
        )

    @property
    def linear_rows(self) -> int:
        return len(self.rows) - self.nonlinear_rows


def build_horner_trace(
    vector: int,
    vector_bits: int,
    points: Sequence[int],
) -> HornerTrace:
    if vector_bits <= 0 or vector < 0 or vector >= 1 << vector_bits:
        raise ValueError("invalid polynomial vector")
    if not points or any(point <= 0 or point > field.FIELD_MASK for point in points):
        raise ValueError("invalid evaluation points")
    if len(set(points)) != len(points):
        raise ValueError("evaluation points must be distinct")

    builder = field.NativeRowBuilder()
    vector_forms = _allocate_bits(builder, vector, vector_bits, "vector")
    point_forms = tuple(
        _allocate_bits(builder, point, field.FIELD_DEGREE, f"point[{index}]")
        for index, point in enumerate(points)
    )
    output_forms, accounting = lower_polynomial_hash(
        builder,
        vector_forms,
        point_forms,
        "horner",
    )
    direct = evaluate_polynomial_hash(vector, vector_bits, points)
    output_value = sum(
        form.evaluate(builder.assignment) << index
        for index, form in enumerate(output_forms)
    )
    output_bytes = output_value.to_bytes((len(output_forms) + 7) // 8, "little")
    constrained = tuple(
        (output_value >> (index * field.FIELD_DEGREE)) & field.FIELD_MASK
        for index in range(len(points))
    )
    if constrained != direct:
        raise AssertionError("constrained and direct Horner outputs disagree")

    trace = HornerTrace(
        rows=tuple(builder.rows),
        assignment=dict(builder.assignment),
        wire_labels=dict(builder.wire_labels),
        vector_bit_wires=tuple(_wire_id(form) for form in vector_forms),
        point_bit_wires=tuple(
            tuple(_wire_id(form) for form in item) for item in point_forms
        ),
        output_bit_wires=tuple(_wire_id(form) for form in output_forms),
        vector_bits=vector_bits,
        points=tuple(points),
        output_fields=direct,
        output_bytes=output_bytes,
        accounting=accounting,
        input_bitness_rows=vector_bits + len(points) * field.FIELD_DEGREE,
        external_assertions=0,
    )
    if trace.failed_rows():
        raise AssertionError("honest Horner trace failed")
    return trace


def serialize_multiplication_row_stream(trace: MultiplicationTrace) -> bytes:
    document = {
        "format": ROW_FORMAT,
        "left_bit_wires": list(trace.left_bit_wires),
        "output_bit_wires": list(trace.output_bit_wires),
        "profile_name": PROFILE_NAME,
        "relation_id": PROFILE_RELATION_ID + "/multiplication",
        "right_bit_wires": list(trace.right_bit_wires),
        "rows": [row.canonical_dict() for row in trace.rows],
    }
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def serialize_horner_row_stream(trace: HornerTrace) -> bytes:
    document = {
        "format": ROW_FORMAT,
        "output_bit_wires": list(trace.output_bit_wires),
        "point_bit_wires": [list(item) for item in trace.point_bit_wires],
        "profile_name": PROFILE_NAME,
        "relation_id": PROFILE_RELATION_ID,
        "rows": [row.canonical_dict() for row in trace.rows],
        "vector_bit_wires": list(trace.vector_bit_wires),
        "vector_bits": trace.vector_bits,
    }
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def frozen_horner_fixture() -> tuple[int, tuple[int, int]]:
    vector = int.from_bytes(
        hashlib.shake_256(b"PQ-RBBC/v2.4/horner/vector").digest(256),
        "little",
    )
    raw = hashlib.shake_256(b"PQ-RBBC/v2.4/horner/points").digest(
        2 * field.FIELD_ELEMENT_BYTES
    )
    point_0 = int.from_bytes(raw[: field.FIELD_ELEMENT_BYTES], "little") & field.FIELD_MASK
    point_1 = int.from_bytes(raw[field.FIELD_ELEMENT_BYTES :], "little") & field.FIELD_MASK
    if point_0 == 0 or point_1 == 0 or point_0 == point_1:
        raise AssertionError("frozen Horner points are degenerate")
    return vector, (point_0, point_1)


def frozen_multiplication_fixture() -> tuple[int, int]:
    left = int.from_bytes(
        hashlib.sha256(b"PQ-RBBC/v2.4/multiplication/left").digest(), "little"
    ) & field.FIELD_MASK
    right = int.from_bytes(
        hashlib.sha256(b"PQ-RBBC/v2.4/multiplication/right").digest(), "little"
    ) & field.FIELD_MASK
    return left, right


def build_manifest(
    multiplication: MultiplicationTrace,
    horner: HornerTrace,
) -> dict[str, object]:
    multiplication_stream = serialize_multiplication_row_stream(multiplication)
    horner_stream = serialize_horner_row_stream(horner)
    return {
        "implementation_version": IMPLEMENTATION_VERSION,
        "profile": {
            "name": PROFILE_NAME,
            "relation_id": PROFILE_RELATION_ID,
            "field": "GF(2^193)",
            "modulus_exponents": list(field.CONWAY_EXPONENTS),
            "coefficient_order": "193-bit LSB-first polynomial-basis chunks",
            "evaluation": "Horner from highest coefficient to lowest",
        },
        "multiplication_fixture": {
            "wires": len(multiplication.assignment),
            "rows": len(multiplication.rows),
            "multiplication_rows": multiplication.multiplication_rows,
            "input_bitness_rows": multiplication.input_bitness_rows,
            "output_bitness_rows": multiplication.output_bitness_rows,
            "output_pack_rows": multiplication.output_pack_rows,
            "output_hex": field.fhex(multiplication.output),
            "row_stream_bytes": len(multiplication_stream),
            "row_stream_sha256": hashlib.sha256(multiplication_stream).hexdigest(),
            "honest_failures": multiplication.failed_rows(),
        },
        "horner_fixture": {
            "vector_bits": horner.vector_bits,
            "coefficients": horner.accounting.coefficients,
            "points": horner.accounting.points,
            "wires": len(horner.assignment),
            "rows": len(horner.rows),
            "nonlinear_rows": horner.nonlinear_rows,
            "linear_rows": horner.linear_rows,
            "accounting": asdict(horner.accounting),
            "external_assertions": horner.external_assertions,
            "output_hex": horner.output_bytes.hex(),
            "output_sha256": hashlib.sha256(horner.output_bytes).hexdigest(),
            "row_stream_bytes": len(horner_stream),
            "row_stream_sha256": hashlib.sha256(horner_stream).hexdigest(),
            "honest_failures": horner.failed_rows(),
            "witness_independent_topology_for_fixed_widths": True,
        },
        "implemented": {
            "bit_bound_field_multiplication": True,
            "generic_multi_coefficient_horner": True,
            "production_2048_bit_eleven_coefficient_vector": True,
            "two_nonzero_distinct_points_constrained": True,
            "binary_output_decomposition": True,
            "callbacks_or_external_assertions": False,
            "full_production_cap_execution": False,
        },
        "claim_boundary": {
            "arithmetic_primitive_closed": True,
            "production_cap_closed": False,
            "remaining": [
                "integrate the full 2048-bit vector in a production tree shard",
                "execute the full 18-tree production relation",
                "complete fork-specific extraction and security proofs",
            ],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()

    vector, points = frozen_horner_fixture()
    left, right = frozen_multiplication_fixture()
    multiplication = build_multiplication_trace(left, right)
    horner = build_horner_trace(
        vector,
        PRODUCTION_WITNESS_BITS,
        points,
    )
    manifest = build_manifest(multiplication, horner)
    if args.output:
        args.output.write_bytes(serialize_horner_row_stream(horner))
    if args.manifest:
        args.manifest.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if not args.output and not args.manifest:
        print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
