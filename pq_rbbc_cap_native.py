#!/usr/bin/env python3
"""Zero-callback native lowering for PQ-RBBC CAP test profiles.

Version 2.3 lowers every XOF call made by the explicitly non-secure reduced
and 2450-bit multi-squeeze fixtures into the frozen Anemoi-193/336 rank-one
relation.  It also
materializes all salted GGM links, leaf commitment/tape links, corrections,
consistency transcript bytes, the canonical CAP commitment, and the final
``H_RBBC(message, c_r)`` byte join as ordinary rows.

Both test witnesses are only 64 bits, so their polynomial hash has one
GF(2^193) coefficient.  All non-XOF CAP algebra is consequently linear in this
checkpoint.  The production 2,048-bit witness needs additional native field
multiplication rows and a full 18-tree streaming execution; this module rejects
that topology rather than claiming production closure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping, Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_anemoi_sponge as sponge
import pq_rbbc_cap_commit as cap


IMPLEMENTATION_VERSION = "2.3"
PROFILE_NAME = "PQ-RBBC-CAP-REDUCED-NATIVE/Anemoi-193-336-v1"
PROFILE_RELATION_ID = "pq-rbbc/cap/reduced-native/anemoi-193-336/v1"
ROW_FORMAT = "F193-R1CS-JSON-1"

FROZEN_REDUCED_WIRES = 59_602
FROZEN_REDUCED_ROWS = 88_282
FROZEN_REDUCED_NONLINEAR_ROWS = 58_462
FROZEN_REDUCED_LINEAR_ROWS = 29_820
FROZEN_REDUCED_XOF_CALLS = 24
FROZEN_REDUCED_PERMUTATIONS = 57
FROZEN_REDUCED_ROW_STREAM_BYTES = 51_845_969
FROZEN_REDUCED_ROW_STREAM_SHA256 = (
    "f6a6a0b65e6de16f7bb1d6b42302a12b004befa62b629d252861e2c986917263"
)
FROZEN_EXTENDED_WIRES = 85_034
FROZEN_EXTENDED_ROWS = 113_802
FROZEN_EXTENDED_NONLINEAR_ROWS = 83_510
FROZEN_EXTENDED_LINEAR_ROWS = 30_292
FROZEN_EXTENDED_XOF_CALLS = 24
FROZEN_EXTENDED_PERMUTATIONS = 81
FROZEN_EXTENDED_ROW_STREAM_BYTES = 69_273_394
FROZEN_EXTENDED_ROW_STREAM_SHA256 = (
    "98222b0cafeb944184e3939a878d1e3fb3af05d10c9795ef0701c87f95462855"
)

# This fixture keeps the one-coefficient 64-bit witness and the tiny two-tree
# topology, but stretches the unused degree-one rho region so each leaf tape
# has exactly the production width: 64 + 2193 + 193 = 2450 bits.  It isolates
# multi-squeeze correctness without pretending to exercise the production
# polynomial hash or production tree count.
EXTENDED_MULTISQUEEZE_TEST_PARAMETERS = cap.CAPParameters(
    name="PQ-RBBC-CAP-EXTENDED-2450-TEST-ONLY",
    security_bits=0,
    mask_bits=32,
    appended_signature_bits=32,
    degree=2,
    rho=2_193,
    consistency_points=1,
    tree_specs=(cap.TreeSpec(2, 4),),
    secure_profile=False,
)


BitForm = field.LinearForm
Bits = tuple[BitForm, ...]


def _wire_id(form: BitForm) -> int:
    if len(form.terms) != 1 or form.terms[0][1] != 1 or form.constant:
        raise ValueError("expected a canonical wire form")
    return form.terms[0][0]


def _remap_form(form: BitForm, mapping: Mapping[int, int]) -> BitForm:
    return BitForm(
        tuple((mapping[wire_id], coefficient) for wire_id, coefficient in form.terms),
        form.constant,
    )


def _constant_bits(data: bytes) -> Bits:
    return tuple(
        BitForm.const((byte >> bit) & 1)
        for byte in data
        for bit in range(8)
    )


def _constant_int_bits(value: int, bit_length: int) -> Bits:
    if value < 0 or value >= 1 << bit_length:
        raise ValueError("constant does not fit declared bit length")
    return tuple(BitForm.const((value >> index) & 1) for index in range(bit_length))


def _allocate_bits(
    builder: field.NativeRowBuilder,
    value: int,
    bit_length: int,
    prefix: str,
) -> Bits:
    if value < 0 or value >= 1 << bit_length:
        raise ValueError("input does not fit declared bit length")
    forms: list[BitForm] = []
    for index in range(bit_length):
        form = builder.new_wire((value >> index) & 1, f"{prefix}[{index}]")
        builder.row(
            f"{prefix}[{index}].bit",
            form,
            form.add(BitForm.const(1)),
            BitForm.const(0),
        )
        forms.append(form)
    return tuple(forms)


def _publish_bits(
    builder: field.NativeRowBuilder,
    expected: Sequence[BitForm],
    prefix: str,
) -> Bits:
    forms: list[BitForm] = []
    for index, source in enumerate(expected):
        value = source.evaluate(builder.assignment)
        if value not in (0, 1):
            raise AssertionError("published source is not binary")
        form = builder.new_wire(value, f"{prefix}[{index}]")
        builder.row(
            f"{prefix}[{index}].bit",
            form,
            form.add(BitForm.const(1)),
            BitForm.const(0),
        )
        builder.row(
            f"{prefix}[{index}].link",
            form.add(source),
            BitForm.const(1),
            BitForm.const(0),
        )
        forms.append(form)
    return tuple(forms)


def _xor_bits(*vectors: Sequence[BitForm]) -> Bits:
    if not vectors:
        return ()
    length = len(vectors[0])
    if any(len(vector) != length for vector in vectors):
        raise ValueError("xor vector width mismatch")
    return tuple(
        field.add_forms(*(vector[index] for vector in vectors))
        for index in range(length)
    )


def _zero_extend(bits: Sequence[BitForm], bit_length: int) -> Bits:
    if len(bits) > bit_length:
        raise ValueError("cannot zero-extend to a smaller width")
    return tuple(bits) + (BitForm.const(0),) * (bit_length - len(bits))


def _pad_to_byte(bits: Sequence[BitForm]) -> Bits:
    padded = ((len(bits) + 7) // 8) * 8
    return _zero_extend(bits, padded)


def _field_bytes_bits(bits: Sequence[BitForm]) -> Bits:
    if len(bits) != field.FIELD_DEGREE:
        raise ValueError("field serialization needs 193 bits")
    return _zero_extend(bits, field.FIELD_ELEMENT_BYTES * 8)


def _hash_bytes_bits(bits: Sequence[BitForm]) -> Bits:
    if len(bits) != cap.HASH_BITS:
        raise ValueError("hash serialization needs 386 bits")
    return _zero_extend(bits, cap.HASH_BYTES * 8)


def _bits_value(bits: Sequence[BitForm], assignment: Mapping[int, int]) -> int:
    value = 0
    for index, form in enumerate(bits):
        bit = form.evaluate(assignment)
        if bit not in (0, 1):
            raise AssertionError("symbolic bit form is not binary")
        value |= bit << index
    return value


def _bits_bytes(bits: Sequence[BitForm], assignment: Mapping[int, int]) -> bytes:
    if len(bits) % 8:
        raise ValueError("byte serialization is not aligned")
    return _bits_value(bits, assignment).to_bytes(len(bits) // 8, "little")


def _encode_transcript_bits(fields: Sequence[Sequence[BitForm]]) -> Bits:
    if len(fields) > 0xFFFF:
        raise ValueError("too many transcript fields")
    encoded: list[BitForm] = list(_constant_bits(sponge.TRANSCRIPT_MAGIC))
    encoded.extend(_constant_bits(len(fields).to_bytes(2, "little")))
    for item in fields:
        if len(item) % 8:
            raise ValueError("transcript field is not byte aligned")
        byte_length = len(item) // 8
        encoded.extend(_constant_bits(byte_length.to_bytes(8, "little")))
        encoded.extend(item)
    return tuple(encoded)


@dataclass(frozen=True)
class NativeXOFAccounting:
    calls: int = 0
    permutations: int = 0
    permutation_rows: int = 0
    payload_bitness_rows: int = 0
    output_bitness_rows: int = 0
    internal_linear_rows: int = 0
    source_link_rows: int = 0

    def add(self, other: "NativeXOFAccounting") -> "NativeXOFAccounting":
        return NativeXOFAccounting(
            **{
                key: getattr(self, key) + getattr(other, key)
                for key in self.__dataclass_fields__
            }
        )


def _append_sponge_trace(
    builder: field.NativeRowBuilder,
    trace: sponge.SpongeTrace,
    prefix: str,
) -> tuple[Bits, Bits]:
    mapping: dict[int, int] = {}
    for old_wire_id in sorted(trace.assignment):
        new_form = builder.new_wire(
            trace.assignment[old_wire_id],
            f"{prefix}.{trace.wire_labels[old_wire_id]}",
        )
        mapping[old_wire_id] = _wire_id(new_form)
    for row in trace.rows:
        builder.row(
            f"{prefix}.{row.label}",
            _remap_form(row.left, mapping),
            _remap_form(row.right, mapping),
            _remap_form(row.output, mapping),
        )
    return (
        tuple(BitForm.wire(mapping[wire_id]) for wire_id in trace.payload_bit_wires),
        tuple(BitForm.wire(mapping[wire_id]) for wire_id in trace.output_bit_wires),
    )


def _lower_xof_call(
    builder: field.NativeRowBuilder,
    call: cap.XOFCall,
    source_fields: Sequence[Sequence[BitForm]],
    parameters: field.AnemoiParameters,
    call_index: int,
) -> tuple[Bits, NativeXOFAccounting]:
    concrete_fields = tuple(
        _bits_bytes(item, builder.assignment) for item in source_fields
    )
    if concrete_fields != call.fields:
        raise AssertionError(f"symbolic fields disagree for {call.label}")
    source_payload = _encode_transcript_bits(source_fields)
    if _bits_bytes(source_payload, builder.assignment) != call.payload:
        raise AssertionError(f"symbolic transcript disagrees for {call.label}")

    trace = sponge.build_sponge_trace(
        call.domain,
        call.payload,
        parameters,
        output_bits=call.output_bits,
    )
    prefix = f"xof[{call_index}].{call.label}"
    payload_forms, output_forms = _append_sponge_trace(builder, trace, prefix)
    if len(payload_forms) != len(source_payload):
        raise AssertionError("native payload width mismatch")
    for bit_index, (payload_form, source_form) in enumerate(
        zip(payload_forms, source_payload)
    ):
        builder.row(
            f"{prefix}.payload[{bit_index}].source",
            payload_form.add(source_form),
            BitForm.const(1),
            BitForm.const(0),
        )
    output_value = _bits_value(output_forms, builder.assignment)
    if output_value != call.output:
        raise AssertionError(f"native XOF output disagrees for {call.label}")
    accounting = NativeXOFAccounting(
        calls=1,
        permutations=trace.permutation_nonlinear_rows // field.NONLINEAR_ROWS,
        permutation_rows=trace.permutation_nonlinear_rows,
        payload_bitness_rows=trace.input_bitness_rows,
        output_bitness_rows=trace.output_bitness_rows,
        internal_linear_rows=trace.linear_rows,
        source_link_rows=len(payload_forms),
    )
    return output_forms, accounting


class _CallCursor:
    def __init__(self, calls: Sequence[cap.XOFCall]) -> None:
        self.calls = calls
        self.index = 0

    def take(self, label: str) -> tuple[int, cap.XOFCall]:
        if self.index >= len(self.calls):
            raise AssertionError("native replay requested too many XOF calls")
        index = self.index
        call = self.calls[index]
        self.index += 1
        if call.label != label:
            raise AssertionError(
                f"XOF replay order mismatch: expected {label}, got {call.label}"
            )
        return index, call


@dataclass(frozen=True)
class _SymbolicTree:
    plain: Bits
    masks: tuple[Bits, ...]
    commitments: tuple[Bits, ...]


def _meta(tree_index: int, level_or_leaf: int, node_index: int) -> bytes:
    return (
        tree_index.to_bytes(2, "little")
        + level_or_leaf.to_bytes(2, "little")
        + node_index.to_bytes(4, "little")
    )


def _tree_component_bits(
    tree_index: int,
    leaves: int,
    extension_degree: int,
    commitments: Sequence[Bits],
) -> Bits:
    result: list[BitForm] = list(
        _constant_bits(
            tree_index.to_bytes(2, "little")
            + leaves.to_bytes(4, "little")
            + extension_degree.to_bytes(2, "little")
        )
    )
    for commitment in commitments:
        if len(commitment) != cap.HASH_BITS:
            raise ValueError("leaf commitment width mismatch")
        result.extend(_field_bytes_bits(commitment[: field.FIELD_DEGREE]))
        result.extend(_field_bytes_bits(commitment[field.FIELD_DEGREE :]))
    return tuple(result)


def _correction_component_bits(
    delta_p: Sequence[Bits],
    delta_mhat: Sequence[Bits],
    parameters: cap.CAPParameters,
) -> Bits:
    if len(delta_p) != len(delta_mhat):
        raise ValueError("correction vector count mismatch")
    result: list[BitForm] = list(
        _constant_bits(
            len(delta_p).to_bytes(2, "little")
            + parameters.witness_bits.to_bytes(4, "little")
            + parameters.consistency_bits.to_bytes(4, "little")
        )
    )
    for p_bits, mhat_bits in zip(delta_p, delta_mhat):
        result.extend(_pad_to_byte(p_bits))
        result.extend(_pad_to_byte(mhat_bits))
    return tuple(result)


def _xi_component_bits(
    alpha: Bits,
    xi_masks: Sequence[Bits],
    consistency_bits: int,
    extension_degree: int,
) -> Bits:
    if len(alpha) != consistency_bits or len(xi_masks) != consistency_bits:
        raise ValueError("xi width mismatch")
    if any(len(mask) != extension_degree for mask in xi_masks):
        raise ValueError("xi extension width mismatch")
    packed_masks = tuple(
        bit
        for mask in xi_masks
        for bit in mask
    )
    return (
        _constant_bits(
            consistency_bits.to_bytes(4, "little")
            + extension_degree.to_bytes(2, "little")
        )
        + _pad_to_byte(alpha)
        + _pad_to_byte(packed_masks)
    )


def _serialize_commitment_bits(
    parameters: cap.CAPParameters,
    salt: tuple[Bits, Bits],
    h2: Bits,
    alpha: Bits,
    delta_p: Sequence[Bits],
    delta_mhat: Sequence[Bits],
) -> Bits:
    corrections: list[BitForm] = list(_pad_to_byte(alpha))
    for p_bits, mhat_bits in zip(delta_p, delta_mhat):
        corrections.extend(_pad_to_byte(p_bits))
        corrections.extend(_pad_to_byte(mhat_bits))
    result: list[BitForm] = list(
        _constant_bits(cap.COMMITMENT_MAGIC + (1).to_bytes(2, "little"))
    )
    result.extend(_constant_bits(bytes.fromhex(cap.profile_fingerprint(parameters))))
    result.extend(_field_bytes_bits(salt[0]))
    result.extend(_field_bytes_bits(salt[1]))
    result.extend(_hash_bytes_bits(h2))
    result.extend(_constant_bits((len(corrections) // 8).to_bytes(4, "little")))
    result.extend(corrections)
    return tuple(result)


@dataclass(frozen=True)
class ReducedNativeCAPTrace:
    cap_parameters: cap.CAPParameters
    rows: tuple[field.RankOneRow, ...]
    assignment: dict[int, int]
    wire_labels: dict[int, str]
    randomness_bit_wires: tuple[int, ...]
    message_bit_wires: tuple[int, ...]
    derived_mask_bit_wires: tuple[int, ...]
    append_base_bit_wires: tuple[int, ...]
    commitment_bit_wires: tuple[int, ...]
    request_hash_bit_wires: tuple[int, ...]
    commitment_bytes: bytes
    request_hash_bytes: bytes
    xof_accounting: NativeXOFAccounting
    input_output_bitness_rows: int
    boundary_link_rows: int
    external_assertions: int

    def failed_rows(self, assignment: Mapping[int, int] | None = None) -> list[str]:
        values = self.assignment if assignment is None else assignment
        return [row.label for row in self.rows if not row.satisfied(values)]

    @property
    def nonlinear_rows(self) -> int:
        return (
            self.xof_accounting.permutation_rows
            + self.xof_accounting.payload_bitness_rows
            + self.xof_accounting.output_bitness_rows
            + self.input_output_bitness_rows
        )

    @property
    def linear_rows(self) -> int:
        return len(self.rows) - self.nonlinear_rows


def build_native_cap_trace(
    randomness: cap.CAPRandomness | None = None,
    message: bytes = bytes(32),
    parameters: cap.CAPParameters = cap.REDUCED_TEST_PARAMETERS,
) -> ReducedNativeCAPTrace:
    """Materialize one frozen non-secure CAP fixture and H_RBBC wire join."""

    supported = (
        cap.REDUCED_TEST_PARAMETERS,
        EXTENDED_MULTISQUEEZE_TEST_PARAMETERS,
    )
    if parameters.secure_profile or parameters not in supported:
        raise ValueError("only the frozen reduced and extended test profiles are native-lowered")
    if parameters.witness_bits > field.FIELD_DEGREE:
        raise ValueError("multi-coefficient polynomial hash is not lowered yet")
    if parameters.consistency_points != 1:
        raise ValueError("test-profile lowering requires one consistency point")
    if len(message) != 32:
        raise ValueError("H_RBBC fixture message must be 32 bytes")
    randomness = randomness or cap.deterministic_randomness(parameters)
    execution = cap.execute_cap_commit(parameters, randomness)
    parameters_f193 = field.derive_parameters()
    builder = field.NativeRowBuilder()

    salt = (
        _allocate_bits(builder, randomness.salt[0], field.FIELD_DEGREE, "input.salt[0]"),
        _allocate_bits(builder, randomness.salt[1], field.FIELD_DEGREE, "input.salt[1]"),
    )
    root_bits: list[tuple[Bits, Bits]] = []
    for tree_index, (left, right) in enumerate(randomness.roots):
        root_bits.append(
            (
                _allocate_bits(
                    builder, left, field.FIELD_DEGREE, f"input.root[{tree_index}][0]"
                ),
                _allocate_bits(
                    builder, right, field.FIELD_DEGREE, f"input.root[{tree_index}][1]"
                ),
            )
        )
    message_bits = _allocate_bits(
        builder,
        int.from_bytes(message, "little"),
        len(message) * 8,
        "input.message",
    )
    randomness_forms = salt[0] + salt[1] + tuple(
        form for pair in root_bits for root in pair for form in root
    )
    cursor = _CallCursor(execution.xof_calls)
    accounting = NativeXOFAccounting()
    salt_bytes = _pad_to_byte(salt[0] + salt[1])
    symbolic_trees: list[_SymbolicTree] = []

    for tree_index, (leaves, extension_degree, roots) in enumerate(
        zip(
            parameters.expanded_leaf_counts(),
            parameters.expanded_extension_degrees(),
            root_bits,
        )
    ):
        nodes: list[Bits] = list(roots)
        level = 2
        while len(nodes) < leaves:
            children: list[Bits] = []
            for node_index, parent in enumerate(nodes, start=1):
                label = f"tree[{tree_index}].derive[{level},{node_index}]"
                call_index, call = cursor.take(label)
                output, item = _lower_xof_call(
                    builder,
                    call,
                    (
                        salt_bytes,
                        _field_bytes_bits(parent),
                        _constant_bits(_meta(tree_index, level, node_index)),
                    ),
                    parameters_f193,
                    call_index,
                )
                accounting = accounting.add(item)
                children.extend(
                    (
                        output[: field.FIELD_DEGREE],
                        output[field.FIELD_DEGREE :],
                    )
                )
            nodes = children
            level += 1

        commitments: list[Bits] = []
        tapes: list[Bits] = []
        for leaf_index, seed in enumerate(nodes, start=1):
            commit_label = f"tree[{tree_index}].leaf[{leaf_index}].commit"
            call_index, call = cursor.take(commit_label)
            commitment, item = _lower_xof_call(
                builder,
                call,
                (
                    salt_bytes,
                    _field_bytes_bits(seed),
                    _constant_bits(_meta(tree_index, 0, leaf_index)),
                ),
                parameters_f193,
                call_index,
            )
            accounting = accounting.add(item)
            commitments.append(commitment)

            tape_label = f"tree[{tree_index}].leaf[{leaf_index}].tape"
            call_index, call = cursor.take(tape_label)
            tape, item = _lower_xof_call(
                builder,
                call,
                (
                    _field_bytes_bits(seed),
                    _constant_bits(_meta(tree_index, 0, leaf_index)),
                ),
                parameters_f193,
                call_index,
            )
            accounting = accounting.add(item)
            tapes.append(tape)

        plain = _xor_bits(*tapes)
        masks: list[Bits] = []
        for coordinate in range(parameters.random_polynomial_bits):
            coefficients = [BitForm.const(0)] * extension_degree
            for leaf_index, tape in enumerate(tapes, start=1):
                inverse = cap.gf2m_inv(leaf_index, extension_degree)
                for extension_bit in range(extension_degree):
                    if (inverse >> extension_bit) & 1:
                        coefficients[extension_bit] = coefficients[
                            extension_bit
                        ].add(tape[coordinate])
            masks.append(tuple(coefficients))

        concrete_polynomial = execution.tree_polynomials[tree_index]
        if _bits_value(plain, builder.assignment) != concrete_polynomial.plain:
            raise AssertionError("symbolic tape xor disagrees")
        for symbolic_mask, concrete_mask in zip(masks, concrete_polynomial.masks):
            if _bits_value(symbolic_mask, builder.assignment) != concrete_mask:
                raise AssertionError("symbolic mask coefficient disagrees")
        symbolic_trees.append(
            _SymbolicTree(plain, tuple(masks), tuple(commitments))
        )

    p_plain = tuple(
        tree.plain[: parameters.witness_bits] for tree in symbolic_trees
    )
    mhat_shift = parameters.witness_bits + (parameters.degree - 1) * parameters.rho
    mhat_plain = tuple(
        tree.plain[mhat_shift : mhat_shift + parameters.consistency_bits]
        for tree in symbolic_trees
    )
    delta_p = tuple(_xor_bits(p_plain[0], item) for item in p_plain[1:])
    delta_mhat = tuple(
        _xor_bits(mhat_plain[0], item) for item in mhat_plain[1:]
    )

    h1_fields: list[Bits] = [
        _constant_bits(bytes.fromhex(cap.profile_fingerprint(parameters)))
    ]
    for tree_index, (tree, leaves, extension_degree) in enumerate(
        zip(
            symbolic_trees,
            parameters.expanded_leaf_counts(),
            parameters.expanded_extension_degrees(),
        )
    ):
        h1_fields.append(
            _tree_component_bits(
                tree_index,
                leaves,
                extension_degree,
                tree.commitments,
            )
        )
    h1_fields.append(
        _correction_component_bits(delta_p, delta_mhat, parameters)
    )
    call_index, call = cursor.take("h1")
    h1, item = _lower_xof_call(
        builder, call, h1_fields, parameters_f193, call_index
    )
    accounting = accounting.add(item)

    call_index, call = cursor.take("consistency-points")
    points, item = _lower_xof_call(
        builder,
        call,
        (
            _hash_bytes_bits(h1),
            _constant_bits(bytes.fromhex(cap.profile_fingerprint(parameters))),
        ),
        parameters_f193,
        call_index,
    )
    accounting = accounting.add(item)
    if len(points) != field.FIELD_DEGREE:
        raise AssertionError("reduced profile must have one consistency point")

    # The reduced 64-bit P vector occupies one GF(2^193) coefficient, so its
    # polynomial hash is P itself and is independent of the evaluation point.
    if parameters.witness_bits > field.FIELD_DEGREE:
        raise ValueError("multi-coefficient polynomial hash is not lowered yet")
    alpha = _xor_bits(
        _zero_extend(p_plain[0], parameters.consistency_bits),
        mhat_plain[0],
    )
    xi_components: list[Bits] = []
    for tree, extension_degree in zip(
        symbolic_trees, parameters.expanded_extension_degrees()
    ):
        p_masks = tree.masks[: parameters.witness_bits]
        mhat_masks = tree.masks[
            mhat_shift : mhat_shift + parameters.consistency_bits
        ]
        hashed_masks = tuple(p_masks) + tuple(
            (BitForm.const(0),) * extension_degree
            for _ in range(parameters.consistency_bits - parameters.witness_bits)
        )
        xi_masks = tuple(
            _xor_bits(left, right)
            for left, right in zip(hashed_masks, mhat_masks)
        )
        xi_components.append(
            _xi_component_bits(
                alpha,
                xi_masks,
                parameters.consistency_bits,
                extension_degree,
            )
        )

    call_index, call = cursor.take("h2")
    h2, item = _lower_xof_call(
        builder,
        call,
        (_hash_bytes_bits(h1), *xi_components),
        parameters_f193,
        call_index,
    )
    accounting = accounting.add(item)
    if cursor.index != len(cursor.calls):
        raise AssertionError("native replay did not consume all CAP XOF calls")

    commitment_expected = _serialize_commitment_bits(
        parameters, salt, h2, alpha, delta_p, delta_mhat
    )
    if _bits_bytes(commitment_expected, builder.assignment) != execution.commitment.encoded:
        raise AssertionError("symbolic canonical commitment disagrees")
    commitment = _publish_bits(
        builder, commitment_expected, "output.commitment"
    )
    derived_mask = _publish_bits(
        builder,
        p_plain[0][: parameters.mask_bits],
        "output.derived_mask",
    )
    append_base = _publish_bits(
        builder,
        p_plain[0][
            parameters.mask_bits : parameters.mask_bits
            + parameters.appended_signature_bits
        ],
        "output.append_base",
    )

    request_payload = sponge.encode_transcript(
        (message, execution.commitment.encoded)
    )
    request_call = cap.XOFCall(
        "request-binding",
        sponge.REQUEST_BINDING_DOMAIN,
        (message, execution.commitment.encoded),
        sponge.REQUEST_HASH_BITS,
        int.from_bytes(
            sponge.evaluate_sponge(
                sponge.REQUEST_BINDING_DOMAIN,
                request_payload,
                sponge.REQUEST_HASH_BYTES,
            ),
            "little",
        ),
    )
    request_hash, item = _lower_xof_call(
        builder,
        request_call,
        (message_bits, commitment),
        parameters_f193,
        len(execution.xof_calls),
    )
    accounting = accounting.add(item)
    request_hash_bytes = _bits_bytes(request_hash, builder.assignment)
    direct_request_hash = sponge.hash_request_binding(
        message, execution.commitment.encoded
    )
    if request_hash_bytes != direct_request_hash:
        raise AssertionError("native CAP-to-H_RBBC join disagrees")

    randomness_wires = tuple(_wire_id(form) for form in randomness_forms)
    message_wires = tuple(_wire_id(form) for form in message_bits)
    mask_wires = tuple(_wire_id(form) for form in derived_mask)
    append_wires = tuple(_wire_id(form) for form in append_base)
    commitment_wires = tuple(_wire_id(form) for form in commitment)
    request_hash_wires = tuple(_wire_id(form) for form in request_hash)
    input_output_bitness_rows = (
        len(randomness_wires)
        + len(message_wires)
        + len(mask_wires)
        + len(append_wires)
        + len(commitment_wires)
    )
    boundary_link_rows = len(mask_wires) + len(append_wires) + len(commitment_wires)
    trace = ReducedNativeCAPTrace(
        cap_parameters=parameters,
        rows=tuple(builder.rows),
        assignment=dict(builder.assignment),
        wire_labels=dict(builder.wire_labels),
        randomness_bit_wires=randomness_wires,
        message_bit_wires=message_wires,
        derived_mask_bit_wires=mask_wires,
        append_base_bit_wires=append_wires,
        commitment_bit_wires=commitment_wires,
        request_hash_bit_wires=request_hash_wires,
        commitment_bytes=execution.commitment.encoded,
        request_hash_bytes=request_hash_bytes,
        xof_accounting=accounting,
        input_output_bitness_rows=input_output_bitness_rows,
        boundary_link_rows=boundary_link_rows,
        external_assertions=0,
    )
    if trace.failed_rows():
        raise AssertionError("honest native CAP test trace failed")
    return trace


def build_reduced_native_trace(
    randomness: cap.CAPRandomness | None = None,
    message: bytes = bytes(32),
    parameters: cap.CAPParameters = cap.REDUCED_TEST_PARAMETERS,
) -> ReducedNativeCAPTrace:
    """Backward-compatible entry point for the native CAP test fixtures."""

    return build_native_cap_trace(randomness, message, parameters)


def serialize_row_stream(trace: ReducedNativeCAPTrace) -> bytes:
    document = {
        "cap_profile_fingerprint": cap.profile_fingerprint(
            trace.cap_parameters
        ),
        "commitment_bit_wires": list(trace.commitment_bit_wires),
        "derived_mask_bit_wires": list(trace.derived_mask_bit_wires),
        "external_assertions": trace.external_assertions,
        "format": ROW_FORMAT,
        "message_bit_wires": list(trace.message_bit_wires),
        "profile_name": PROFILE_NAME,
        "relation_id": PROFILE_RELATION_ID,
        "request_hash_bit_wires": list(trace.request_hash_bit_wires),
        "rows": [row.canonical_dict() for row in trace.rows],
        "sponge_profile_fingerprint": sponge.profile_fingerprint(
            field.derive_parameters()
        ),
    }
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def build_manifest(trace: ReducedNativeCAPTrace) -> dict[str, object]:
    row_stream = serialize_row_stream(trace)
    return {
        "implementation_version": IMPLEMENTATION_VERSION,
        "profile": {
            "name": PROFILE_NAME,
            "relation_id": PROFILE_RELATION_ID,
            "field": "GF(2^193)",
            "cap_profile_fingerprint": cap.profile_fingerprint(
                trace.cap_parameters
            ),
            "sponge_profile_fingerprint": sponge.profile_fingerprint(
                field.derive_parameters()
            ),
            "fixture_parameter_name": trace.cap_parameters.name,
            "explicitly_non_secure_reduced_profile": (
                trace.cap_parameters == cap.REDUCED_TEST_PARAMETERS
            ),
            "explicitly_non_secure_test_profile": (
                not trace.cap_parameters.secure_profile
            ),
        },
        "trace": {
            "wires": len(trace.assignment),
            "rows": len(trace.rows),
            "nonlinear_rows": trace.nonlinear_rows,
            "linear_rows": trace.linear_rows,
            "external_assertions": trace.external_assertions,
            "xof_accounting": asdict(trace.xof_accounting),
            "input_output_bitness_rows": trace.input_output_bitness_rows,
            "boundary_link_rows": trace.boundary_link_rows,
            "row_stream_bytes": len(row_stream),
            "row_stream_sha256": hashlib.sha256(row_stream).hexdigest(),
            "honest_failures": trace.failed_rows(),
        },
        "frozen_vector": {
            "commitment_bytes": len(trace.commitment_bytes),
            "commitment_sha256": hashlib.sha256(
                trace.commitment_bytes
            ).hexdigest(),
            "request_hash_hex": trace.request_hash_bytes.hex(),
        },
        "implemented": {
            "all_reduced_cap_xof_calls_native": True,
            "all_selected_fixture_xof_calls_native": True,
            "multi_block_xof_squeeze_native": True,
            "production_width_2450_bit_tape_native": True,
            "salted_ggm_links_native": True,
            "leaf_commitment_and_tape_links_native": True,
            "corrections_and_consistency_bytes_native": True,
            "canonical_commitment_output_wires_native": True,
            "exact_cap_to_h_rbbc_wire_join_native": True,
            "callbacks_or_external_assertions": False,
            "witness_independent_topology_for_fixed_profile": True,
            "full_production_vector_executed": False,
            "full_production_native_rows_materialized": False,
        },
        "claim_boundary": {
            "reduced_fixture_native_closed": (
                trace.cap_parameters == cap.REDUCED_TEST_PARAMETERS
                and trace.external_assertions == 0
            ),
            "extended_multisqueeze_fixture_native_closed": (
                trace.cap_parameters == EXTENDED_MULTISQUEEZE_TEST_PARAMETERS
                and trace.external_assertions == 0
            ),
            "production_closed": False,
            "production_blockers": [
                "multi-coefficient GF(2^193) polynomial hash rows",
                "full 18-tree streaming execution and row-stream digest",
                "fork-specific CAP extraction and security proof",
            ],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument(
        "--fixture",
        choices=("reduced", "extended-2450"),
        default="reduced",
    )
    args = parser.parse_args()
    parameters = (
        cap.REDUCED_TEST_PARAMETERS
        if args.fixture == "reduced"
        else EXTENDED_MULTISQUEEZE_TEST_PARAMETERS
    )
    trace = build_native_cap_trace(parameters=parameters)
    row_stream = serialize_row_stream(trace)
    manifest = build_manifest(trace)
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
