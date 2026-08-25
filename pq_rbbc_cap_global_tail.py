#!/usr/bin/env python3
"""Shared native CAP transcript tail for the PQ-RBBC v2.9 checkpoint.

Version 2.8 executed the canonical mixed 18-tree reference vector but did not
materialize one native relation.  This module lowers the unique global part of
that relation: the tree commitment and consistency ports feed one H1, one pair
of consistency points, seventeen correction equations, one shared alpha,
eighteen xi components, one H2, one canonical commitment serialization, and
one request-binding hash.

The input ports are ordinary bit-constrained native wires and every global-tail
row is replayable against a fixed-width assignment archive.  The producer side
of those ports (tree-local GGM, tape, and mask-Horner segments) remains a
separate obligation.  Therefore this closes the shared-tail native component,
not the complete 18-tree native composition or parent issuance join.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pickle
import resource
import struct
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterable, Iterator, Mapping, Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_anemoi_sponge as sponge
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_composer as composer
import pq_rbbc_cap_shard_assignment as assignment
import pq_rbbc_cap_shard_stream as shard


IMPLEMENTATION_VERSION = "2.9"
RELATION_ID = "pq-rbbc/cap/production-global-tail/v1"
STREAM_FORMAT = "PQRBBC-F193-R1CS-BINARY-1"
STREAM_MAGIC = b"PQRBBC-F193-R1CS-BINARY-V1"
FROZEN_REQUEST_MESSAGE = bytes(32)

# Frozen only after an actual production assignment generation and replay.
FROZEN_PRODUCTION_STREAM_SHA256 = (
    "c368d41de9e57910803e98284a4ec0a0f45862fa80f3d070a50477f82627c9df"
)
FROZEN_PRODUCTION_ASSIGNMENT_SHA256 = (
    "946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1"
)
FROZEN_PRODUCTION_ROWS = 56_806_711
FROZEN_PRODUCTION_WIRES = 40_194_596
FROZEN_PRODUCTION_COMMITMENT_SHA256 = (
    "12123e95b1b64d87da7a575dbf803fc53ded9eb9a23b807eeab2cba51dfe5b62"
)
FROZEN_PRODUCTION_REQUEST_HASH_HEX = (
    "3f9ec0aeab100e4ebef8046068851874f08fcda6daa2e42178dd559f55e38a31"
    "da28af9ccd0653bb4ca574ec8264cce1f3c024c97e858e2c877bba7968c039dc"
    "61f516dfed995ba3"
)


BitForm = field.LinearForm


@dataclass(frozen=True)
class BinaryStreamGroup:
    name: str
    rows: int
    bytes: int
    sha256: str


def _encode_form(form: BitForm) -> bytes:
    encoded = bytearray()
    encoded.extend(form.constant.to_bytes(field.FIELD_ELEMENT_BYTES, "little"))
    encoded.extend(len(form.terms).to_bytes(4, "little"))
    for wire, coefficient in form.terms:
        encoded.extend(wire.to_bytes(8, "little"))
        encoded.extend(
            coefficient.to_bytes(field.FIELD_ELEMENT_BYTES, "little")
        )
    return bytes(encoded)


class BinaryRowSink:
    """Exact row generator with compact canonical hashing and no row list."""

    def __init__(
        self,
        header: Mapping[str, object],
        *,
        assignment_writer: shard.AssignmentWriter | None = None,
        verification_assignment: Mapping[int, int] | None = None,
        capture_labels: Iterable[str] = (),
    ) -> None:
        self.next_wire = 1
        self.rows = 0
        self.nonlinear_rows = 0
        self.linear_rows = 0
        self.bytes = 0
        self._digest = hashlib.sha256()
        self._group_name: str | None = None
        self._group_digest: hashlib._Hash | None = None
        self._group_rows = 0
        self._group_bytes = 0
        self.groups: list[BinaryStreamGroup] = []
        self.assignment_writer = assignment_writer
        self.verification_assignment = verification_assignment
        self.verification_failures = 0
        self.first_verification_failure: str | None = None
        self.capture_labels = frozenset(capture_labels)
        self.captured_rows: dict[str, field.RankOneRow] = {}
        payload = json.dumps(
            {"kind": "header", **dict(header)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        self._record(b"H" + STREAM_MAGIC + payload, count_row=False)

    @property
    def wire_count(self) -> int:
        return self.next_wire - 1

    def allocate(
        self,
        count: int = 1,
        *,
        values: Sequence[int] | None = None,
        encoded_values: bytes | None = None,
    ) -> int:
        if count <= 0:
            raise ValueError("wire allocation must be positive")
        if values is not None and encoded_values is not None:
            raise ValueError("assignment values have two representations")
        if values is not None and len(values) != count:
            raise ValueError("assignment value count mismatch")
        if encoded_values is not None and len(encoded_values) != (
            count * field.FIELD_ELEMENT_BYTES
        ):
            raise ValueError("encoded assignment width mismatch")
        if self.assignment_writer is not None:
            if values is None and encoded_values is None:
                raise ValueError("assignment-backed allocation lacks values")
            if values is not None:
                self.assignment_writer.append_values(values)
            else:
                self.assignment_writer.append_encoded(encoded_values or b"", count)
        start = self.next_wire
        self.next_wire += count
        return start

    def _record(self, payload: bytes, *, count_row: bool) -> None:
        encoded = len(payload).to_bytes(4, "little") + payload
        self._digest.update(encoded)
        self.bytes += len(encoded)
        if self._group_digest is not None:
            self._group_digest.update(encoded)
            self._group_bytes += len(encoded)
            if count_row:
                self._group_rows += 1

    def start_group(self, name: str) -> None:
        if self._group_name is not None:
            raise RuntimeError("row groups cannot nest")
        self._group_name = name
        self._group_digest = hashlib.sha256()
        self._group_rows = 0
        self._group_bytes = 0

    def finish_group(self) -> None:
        if self._group_name is None or self._group_digest is None:
            raise RuntimeError("no active row group")
        self.groups.append(
            BinaryStreamGroup(
                self._group_name,
                self._group_rows,
                self._group_bytes,
                self._group_digest.hexdigest(),
            )
        )
        self._group_name = None
        self._group_digest = None
        self._group_rows = 0
        self._group_bytes = 0

    def row(
        self,
        label: str,
        left: BitForm,
        right: BitForm,
        output: BitForm,
        *,
        nonlinear: bool,
    ) -> None:
        row = field.RankOneRow(label, left, right, output)
        if label in self.capture_labels:
            self.captured_rows[label] = row
        if self.verification_assignment is not None and not shard._row_satisfied_fast(
            row, self.verification_assignment
        ):
            self.verification_failures += 1
            if self.first_verification_failure is None:
                self.first_verification_failure = label
        label_bytes = label.encode("utf-8")
        payload = bytearray(b"R")
        payload.extend((1 if nonlinear else 0).to_bytes(1, "little"))
        payload.extend(len(label_bytes).to_bytes(4, "little"))
        payload.extend(label_bytes)
        payload.extend(_encode_form(left))
        payload.extend(_encode_form(right))
        payload.extend(_encode_form(output))
        self._record(bytes(payload), count_row=True)
        self.rows += 1
        if nonlinear:
            self.nonlinear_rows += 1
        else:
            self.linear_rows += 1

    def bitness(self, label: str, wire_id: int) -> None:
        form = BitForm.wire(wire_id)
        self.row(
            label,
            form,
            form.add(BitForm.const(1)),
            BitForm.const(0),
            nonlinear=True,
        )

    def linear_zero(self, label: str, form: BitForm) -> None:
        self.row(
            label,
            form,
            BitForm.const(1),
            BitForm.const(0),
            nonlinear=False,
        )

    def finish(self, trailer: Mapping[str, object]) -> tuple[int, str]:
        if self._group_name is not None:
            raise RuntimeError("active row group at stream finalization")
        payload = json.dumps(
            {"kind": "trailer", **dict(trailer)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        self._record(b"T" + payload, count_row=False)
        return self.bytes, self._digest.hexdigest()


class MemoryAssignment(Mapping[int, int], shard.AssignmentWriter):
    def __init__(self) -> None:
        self.values: list[int] = []

    def append_values(self, values: Sequence[int]) -> None:
        self.values.extend(values)

    def append_encoded(self, encoded: bytes, count: int) -> None:
        if len(encoded) != count * field.FIELD_ELEMENT_BYTES:
            raise ValueError("encoded assignment width mismatch")
        for offset in range(0, len(encoded), field.FIELD_ELEMENT_BYTES):
            self.values.append(
                int.from_bytes(
                    encoded[offset : offset + field.FIELD_ELEMENT_BYTES], "little"
                )
            )

    def __getitem__(self, wire: int) -> int:
        if not 1 <= wire <= len(self.values):
            raise KeyError(wire)
        return self.values[wire - 1]

    def __iter__(self) -> Iterator[int]:
        return iter(range(1, len(self.values) + 1))

    def __len__(self) -> int:
        return len(self.values)


@dataclass(frozen=True)
class TailMaterial:
    p_plain: tuple[int, ...]
    mhat_plain: tuple[int, ...]
    delta_p: tuple[int, ...]
    delta_mhat: tuple[int, ...]
    points: tuple[int, ...]
    alpha: int
    xi_masks: tuple[tuple[int, ...], ...]
    global_calls: tuple[cap.XOFCall, ...]
    request_call: cap.XOFCall


@dataclass(frozen=True)
class TailPort:
    port_id: str
    producer_segment: str
    consumer_wire_start: int
    bit_length: int
    value_sha256: str


@dataclass(frozen=True)
class GlobalTailSummary:
    parameters: cap.CAPParameters
    stream_bytes: int
    stream_sha256: str
    wires: int
    rows: int
    nonlinear_rows: int
    linear_rows: int
    groups: tuple[BinaryStreamGroup, ...]
    sponge_accounting: shard.SpongeAccounting
    ports: tuple[TailPort, ...]
    commitment_bytes: bytes
    request_hash_bytes: bytes
    assignment_materialized: bool
    external_assertions: int
    verification_failures: int
    first_verification_failure: str | None
    wall_seconds: float
    peak_rss_kib: int


@dataclass(frozen=True)
class GlobalTailAssignmentResult:
    generated: GlobalTailSummary
    verified: GlobalTailSummary
    archive: assignment.AssignmentArchiveMetadata
    tamper_probes: tuple[assignment.TamperProbe, ...]
    generation_seconds: float
    verification_seconds: float


def _bits(value: int, length: int) -> tuple[int, ...]:
    return tuple((value >> bit) & 1 for bit in range(length))


def _bits_digest(value: int, length: int) -> str:
    encoded = value.to_bytes((length + 7) // 8, "little")
    return hashlib.sha256(encoded).hexdigest()


def _global_calls(execution: cap.CAPExecution) -> tuple[cap.XOFCall, ...]:
    calls = execution.xof_calls[-3:]
    if tuple(item.label for item in calls) != (
        "h1",
        "consistency-points",
        "h2",
    ):
        raise ValueError("execution does not end in the canonical global calls")
    return calls


def derive_tail_material(
    parameters: cap.CAPParameters,
    execution: cap.CAPExecution,
    message: bytes,
) -> TailMaterial:
    if len(execution.tree_polynomials) != parameters.tree_count:
        raise ValueError("execution tree count mismatch")
    if execution.commitment.parameters_fingerprint != cap.profile_fingerprint(
        parameters
    ):
        raise ValueError("execution profile mismatch")
    if len(message) != 32:
        raise ValueError("request message must be 32 bytes")
    calls = _global_calls(execution)
    witness_mask = (1 << parameters.witness_bits) - 1
    consistency_mask = (1 << parameters.consistency_bits) - 1
    mhat_shift = parameters.witness_bits + (parameters.degree - 1) * parameters.rho
    p_plain = tuple(
        poly.plain & witness_mask for poly in execution.tree_polynomials
    )
    mhat_plain = tuple(
        (poly.plain >> mhat_shift) & consistency_mask
        for poly in execution.tree_polynomials
    )
    delta_p = tuple(p_plain[0] ^ value for value in p_plain[1:])
    delta_mhat = tuple(mhat_plain[0] ^ value for value in mhat_plain[1:])
    if delta_p != execution.commitment.delta_p:
        raise ValueError("execution delta-P mismatch")
    if delta_mhat != execution.commitment.delta_mhat:
        raise ValueError("execution delta-Mhat mismatch")
    points_output = calls[1].output
    points = tuple(
        (points_output >> (index * field.FIELD_DEGREE)) & field.FIELD_MASK
        for index in range(parameters.consistency_points)
    )
    alpha = cap._linear_hash_vector(p_plain[0], parameters.witness_bits, points)
    alpha ^= mhat_plain[0]
    if alpha != execution.commitment.alpha:
        raise ValueError("execution alpha mismatch")
    xi_masks: list[tuple[int, ...]] = []
    for poly in execution.tree_polynomials:
        p_masks = poly.masks[: parameters.witness_bits]
        mhat_masks = poly.masks[
            mhat_shift : mhat_shift + parameters.consistency_bits
        ]
        hashed = cap._linear_hash_masks(
            p_masks,
            parameters.witness_bits,
            poly.extension_degree,
            points,
        )
        xi_masks.append(
            tuple(left ^ right for left, right in zip(hashed, mhat_masks))
        )
    expected_h2_fields = (
        cap.hash_bytes(calls[0].output),
        *(
            cap._xi_component(
                alpha,
                masks,
                parameters.consistency_bits,
                poly.extension_degree,
            )
            for masks, poly in zip(xi_masks, execution.tree_polynomials)
        ),
    )
    if calls[2].fields != expected_h2_fields:
        raise ValueError("execution H2 field order mismatch")
    request_output = int.from_bytes(
        sponge.hash_request_binding(message, execution.commitment.encoded), "little"
    )
    request_call = cap.XOFCall(
        "request-binding",
        sponge.REQUEST_BINDING_DOMAIN,
        (message, execution.commitment.encoded),
        sponge.REQUEST_HASH_BITS,
        request_output,
    )
    return TailMaterial(
        p_plain,
        mhat_plain,
        delta_p,
        delta_mhat,
        points,
        alpha,
        tuple(xi_masks),
        calls,
        request_call,
    )


def _allocate_bits(
    sink: BinaryRowSink,
    value: int,
    length: int,
    prefix: str,
) -> int:
    return shard._allocate_input_bits(sink, length, prefix, value)


def _xor_source(left: int, right: int, length: int) -> shard.BitSource:
    return shard.BitSource(
        length,
        lambda: (
            BitForm.wire(left + bit).add(BitForm.wire(right + bit))
            for bit in range(length)
        ),
    )


def _decompose_form(
    sink: BinaryRowSink,
    form: BitForm,
    value: int,
    prefix: str,
) -> int:
    start = sink.allocate(field.FIELD_DEGREE, values=_bits(value, field.FIELD_DEGREE))
    for bit in range(field.FIELD_DEGREE):
        sink.bitness(f"{prefix}.bit[{bit}].bit", start + bit)
    packed = form.add(
        BitForm(
            tuple((start + bit, 1 << bit) for bit in range(field.FIELD_DEGREE)),
            0,
        )
    )
    sink.linear_zero(f"{prefix}.pack", packed)
    return start


def _tree_component_source(
    tree_index: int,
    leaves: int,
    extension_degree: int,
    commitment_starts: Sequence[tuple[int, int]],
) -> shard.BitSource:
    def generate() -> Iterator[BitForm]:
        yield from shard.source_constant(
            tree_index.to_bytes(2, "little")
            + leaves.to_bytes(4, "little")
            + extension_degree.to_bytes(2, "little")
        )
        for left, right in commitment_starts:
            yield from shard.source_field_bytes(left)
            yield from shard.source_field_bytes(right)

    return shard.BitSource(
        (8 + 2 * leaves * field.FIELD_ELEMENT_BYTES) * 8,
        generate,
    )


def _field_data_bit_offset(
    lengths: Sequence[int], field_index: int, inner_byte: int = 0
) -> int:
    byte_offset = len(sponge.TRANSCRIPT_MAGIC) + 2
    byte_offset += sum(8 + length for length in lengths[:field_index])
    byte_offset += 8 + inner_byte
    return byte_offset * 8


def capture_labels(
    parameters: cap.CAPParameters,
    execution: cap.CAPExecution,
) -> tuple[str, ...]:
    h1, _, h2 = _global_calls(execution)
    h1_lengths = tuple(len(value) for value in h1.fields)
    h2_lengths = tuple(len(value) for value in h2.fields)
    tree_commitment_bit = _field_data_bit_offset(h1_lengths, 1, 8)
    correction_bit = _field_data_bit_offset(
        h1_lengths, parameters.tree_count + 1, 10
    )
    xi_bit = _field_data_bit_offset(
        h2_lengths,
        1,
        6 + ((parameters.consistency_bits + 7) // 8),
    )
    return (
        f"xof[0].h1.payload[{tree_commitment_bit}].source",
        f"xof[0].h1.payload[{correction_bit}].source",
        "alpha.output[0].pack",
        f"xof[2].h2.payload[{xi_bit}].source",
        "output.commitment[0].link",
        "xof[3].request-binding.digest.lane[0].pack",
    )


def build_global_tail(
    parameters: cap.CAPParameters,
    randomness: cap.CAPRandomness,
    execution: cap.CAPExecution,
    message: bytes = FROZEN_REQUEST_MESSAGE,
    *,
    workers: int = 1,
    assignment_writer: shard.AssignmentWriter | None = None,
    verification_assignment: Mapping[int, int] | None = None,
    capture_rows: Iterable[str] = (),
    captured_rows_output: dict[str, field.RankOneRow] | None = None,
    progress: Callable[[str], None] | None = None,
) -> GlobalTailSummary:
    started = time.perf_counter()
    material = derive_tail_material(parameters, execution, message)
    header = {
        "cap_profile_fingerprint": cap.profile_fingerprint(parameters),
        "field": "GF(2^193)",
        "format": STREAM_FORMAT,
        "relation_id": RELATION_ID,
        "tree_count": parameters.tree_count,
    }
    sink = BinaryRowSink(
        header,
        assignment_writer=assignment_writer,
        verification_assignment=verification_assignment,
        capture_labels=capture_rows,
    )
    all_calls = material.global_calls + (material.request_call,)
    witness_pool = (
        None
        if assignment_writer is None
        else shard.OrderedSpongeWitnessPool(all_calls, max(1, workers))
    )
    lowerer = shard.StreamingSpongeLowerer(sink, witness_pool)
    accounting = shard.SpongeAccounting()
    ports: list[TailPort] = []

    sink.start_group("global-input-ports")
    salt_starts = (
        _allocate_bits(sink, randomness.salt[0], field.FIELD_DEGREE, "input.salt[0]"),
        _allocate_bits(sink, randomness.salt[1], field.FIELD_DEGREE, "input.salt[1]"),
    )
    message_start = _allocate_bits(
        sink, int.from_bytes(message, "little"), len(message) * 8, "input.message"
    )
    ports.append(
        TailPort(
            "shared.salt",
            "shared-inputs",
            salt_starts[0],
            2 * field.FIELD_DEGREE,
            hashlib.sha256(
                cap.field_bytes(randomness.salt[0])
                + cap.field_bytes(randomness.salt[1])
            ).hexdigest(),
        )
    )
    ports.append(
        TailPort(
            "shared.message",
            "shared-inputs",
            message_start,
            len(message) * 8,
            hashlib.sha256(message).hexdigest(),
        )
    )
    commitment_ports: list[tuple[tuple[int, int], ...]] = []
    p_starts: list[int] = []
    mhat_starts: list[int] = []
    xi_starts: list[int] = []
    for tree_index, (poly, p_value, mhat_value, xi_values) in enumerate(
        zip(
            execution.tree_polynomials,
            material.p_plain,
            material.mhat_plain,
            material.xi_masks,
        )
    ):
        tree_commitments: list[tuple[int, int]] = []
        first_commitment_start = sink.next_wire
        commitment_bytes = bytearray()
        for leaf_index, (left, right) in enumerate(poly.commitments, start=1):
            left_start = _allocate_bits(
                sink,
                left,
                field.FIELD_DEGREE,
                f"input.tree[{tree_index}].commitment[{leaf_index}].left",
            )
            right_start = _allocate_bits(
                sink,
                right,
                field.FIELD_DEGREE,
                f"input.tree[{tree_index}].commitment[{leaf_index}].right",
            )
            tree_commitments.append((left_start, right_start))
            commitment_bytes.extend(cap.field_bytes(left))
            commitment_bytes.extend(cap.field_bytes(right))
        commitment_ports.append(tuple(tree_commitments))
        ports.append(
            TailPort(
                f"tree[{tree_index}].leaf-commitments",
                f"tree-pre[{tree_index}]",
                first_commitment_start,
                len(poly.commitments) * 2 * field.FIELD_DEGREE,
                hashlib.sha256(commitment_bytes).hexdigest(),
            )
        )
        p_start = _allocate_bits(
            sink,
            p_value,
            parameters.witness_bits,
            f"input.tree[{tree_index}].p-plain",
        )
        mhat_start = _allocate_bits(
            sink,
            mhat_value,
            parameters.consistency_bits,
            f"input.tree[{tree_index}].mhat-plain",
        )
        p_starts.append(p_start)
        mhat_starts.append(mhat_start)
        ports.append(
            TailPort(
                f"tree[{tree_index}].p-plain",
                f"tree-pre[{tree_index}]",
                p_start,
                parameters.witness_bits,
                _bits_digest(p_value, parameters.witness_bits),
            )
        )
        ports.append(
            TailPort(
                f"tree[{tree_index}].mhat-plain",
                f"tree-pre[{tree_index}]",
                mhat_start,
                parameters.consistency_bits,
                _bits_digest(mhat_value, parameters.consistency_bits),
            )
        )
        extension_degree = poly.extension_degree
        xi_flat = sum(
            bit << (coordinate * extension_degree + extension_bit)
            for coordinate, value in enumerate(xi_values)
            for extension_bit, bit in enumerate(_bits(value, extension_degree))
        )
        xi_width = parameters.consistency_bits * extension_degree
        xi_start = _allocate_bits(
            sink,
            xi_flat,
            xi_width,
            f"input.tree[{tree_index}].xi-masks",
        )
        xi_starts.append(xi_start)
        ports.append(
            TailPort(
                f"tree[{tree_index}].xi-masks",
                f"tree-post[{tree_index}]",
                xi_start,
                xi_width,
                _bits_digest(xi_flat, xi_width),
            )
        )
        if progress is not None:
            progress(
                f"input ports tree {tree_index + 1}/{parameters.tree_count}: "
                f"{poly.leaves:,} commitments"
            )
    sink.finish_group()

    delta_p_sources = tuple(
        _xor_source(p_starts[0], p_starts[index], parameters.witness_bits)
        for index in range(1, parameters.tree_count)
    )
    delta_mhat_sources = tuple(
        _xor_source(
            mhat_starts[0], mhat_starts[index], parameters.consistency_bits
        )
        for index in range(1, parameters.tree_count)
    )
    correction_source = shard.source_concat(
        shard.source_constant(
            (parameters.tree_count - 1).to_bytes(2, "little")
            + parameters.witness_bits.to_bytes(4, "little")
            + parameters.consistency_bits.to_bytes(4, "little")
        ),
        *tuple(
            item
            for p_source, mhat_source in zip(
                delta_p_sources, delta_mhat_sources
            )
            for item in (
                shard.source_pad_to_byte(p_source),
                shard.source_pad_to_byte(mhat_source),
            )
        ),
    )
    profile_source = shard.source_constant(
        bytes.fromhex(cap.profile_fingerprint(parameters))
    )
    tree_sources = tuple(
        _tree_component_source(
            index,
            poly.leaves,
            poly.extension_degree,
            commitment_ports[index],
        )
        for index, poly in enumerate(execution.tree_polynomials)
    )

    sink.start_group("h1-corrections-and-points")
    h1 = lowerer.lower(
        material.global_calls[0],
        (profile_source, *tree_sources, correction_source),
        0,
    )
    accounting = accounting.add(h1.accounting)
    h1_start = h1.output_wires[0]
    point_call = lowerer.lower(
        material.global_calls[1],
        (shard.source_hash_bytes(h1_start), profile_source),
        1,
    )
    accounting = accounting.add(point_call.accounting)
    point_starts = tuple(
        point_call.output_wires[index * field.FIELD_DEGREE]
        for index in range(parameters.consistency_points)
    )
    shard._point_validation(
        sink, point_starts, material.points, "consistency.validate"
    )
    sink.finish_group()

    sink.start_group("shared-alpha")
    alpha_forms, alpha_values = shard._horner_leaf(
        sink,
        tuple(p_starts[0] + bit for bit in range(parameters.witness_bits)),
        material.p_plain[0],
        point_starts,
        material.points,
        0,
    )
    alpha_output_starts = tuple(
        _decompose_form(
            sink,
            form,
            value,
            f"alpha.output[{index}]",
        )
        for index, (form, value) in enumerate(zip(alpha_forms, alpha_values))
    )

    def alpha_bits() -> Iterator[BitForm]:
        for coordinate in range(parameters.consistency_bits):
            point = coordinate // field.FIELD_DEGREE
            bit = coordinate % field.FIELD_DEGREE
            yield BitForm.wire(alpha_output_starts[point] + bit).add(
                BitForm.wire(mhat_starts[0] + coordinate)
            )

    alpha_source = shard.BitSource(parameters.consistency_bits, alpha_bits)
    sink.finish_group()

    xi_sources: list[shard.BitSource] = []
    for tree_index, poly in enumerate(execution.tree_polynomials):
        xi_sources.append(
            shard.source_concat(
                shard.source_constant(
                    parameters.consistency_bits.to_bytes(4, "little")
                    + poly.extension_degree.to_bytes(2, "little")
                ),
                shard.source_pad_to_byte(alpha_source),
                shard.source_pad_to_byte(
                    shard.source_wires(
                        xi_starts[tree_index],
                        parameters.consistency_bits * poly.extension_degree,
                    )
                ),
            )
        )

    sink.start_group("h2-commitment-and-request")
    h2 = lowerer.lower(
        material.global_calls[2],
        (shard.source_hash_bytes(h1_start), *xi_sources),
        2,
    )
    accounting = accounting.add(h2.accounting)
    h2_start = h2.output_wires[0]
    correction_bytes = (parameters.consistency_bits + 7) // 8
    correction_bytes += (parameters.tree_count - 1) * (
        (parameters.witness_bits + 7) // 8
        + (parameters.consistency_bits + 7) // 8
    )
    commitment_source = shard.source_concat(
        shard.source_constant(cap.COMMITMENT_MAGIC + (1).to_bytes(2, "little")),
        profile_source,
        shard.source_field_bytes(salt_starts[0]),
        shard.source_field_bytes(salt_starts[1]),
        shard.source_hash_bytes(h2_start),
        shard.source_constant(correction_bytes.to_bytes(4, "little")),
        shard.source_pad_to_byte(alpha_source),
        *tuple(
            item
            for p_source, mhat_source in zip(
                delta_p_sources, delta_mhat_sources
            )
            for item in (
                shard.source_pad_to_byte(p_source),
                shard.source_pad_to_byte(mhat_source),
            )
        ),
    )
    if commitment_source.bit_length != len(execution.commitment.encoded) * 8:
        raise AssertionError("canonical production commitment width mismatch")
    commitment_start = shard._publish_source(
        sink,
        commitment_source,
        tuple(
            (byte >> bit) & 1
            for byte in execution.commitment.encoded
            for bit in range(8)
        ),
        "output.commitment",
    )
    mask_source = shard.source_wires(p_starts[0], parameters.mask_bits)
    mask_start = shard._publish_source(
        sink,
        mask_source,
        _bits(execution.commitment.derived_mask, parameters.mask_bits),
        "output.derived-mask",
    )
    append_source = shard.source_wires(
        p_starts[0] + parameters.mask_bits,
        parameters.appended_signature_bits,
    )
    append_start = shard._publish_source(
        sink,
        append_source,
        _bits(execution.commitment.append_base, parameters.appended_signature_bits),
        "output.append-base",
    )
    request = lowerer.lower(
        material.request_call,
        (
            shard.source_wires(message_start, len(message) * 8),
            shard.source_wires(
                commitment_start, len(execution.commitment.encoded) * 8
            ),
        ),
        3,
    )
    accounting = accounting.add(request.accounting)
    request_start = request.output_wires[0]
    sink.finish_group()
    if witness_pool is not None:
        witness_pool.close()

    trailer = {
        "append_base": [append_start, parameters.appended_signature_bits],
        "commitment": [commitment_start, len(execution.commitment.encoded) * 8],
        "derived_mask": [mask_start, parameters.mask_bits],
        "external_assertions": 0,
        "request_hash": [request_start, sponge.REQUEST_HASH_BITS],
        "rows": sink.rows,
        "wires": sink.wire_count,
    }
    stream_bytes, stream_sha256 = sink.finish(trailer)
    if captured_rows_output is not None:
        captured_rows_output.update(sink.captured_rows)
    request_hash = material.request_call.output.to_bytes(
        sponge.REQUEST_HASH_BYTES, "little"
    )
    if request_hash != sponge.hash_request_binding(
        message, execution.commitment.encoded
    ):
        raise AssertionError("request hash output mismatch")
    return GlobalTailSummary(
        parameters,
        stream_bytes,
        stream_sha256,
        sink.wire_count,
        sink.rows,
        sink.nonlinear_rows,
        sink.linear_rows,
        tuple(sink.groups),
        accounting,
        tuple(ports),
        execution.commitment.encoded,
        request_hash,
        assignment_writer is not None,
        0,
        sink.verification_failures,
        sink.first_verification_failure,
        time.perf_counter() - started,
        resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    )


def run_tamper_probes(
    values: Mapping[int, int],
    rows: Mapping[str, field.RankOneRow],
    labels: Sequence[str],
) -> tuple[assignment.TamperProbe, ...]:
    return assignment.run_tamper_probes(values, rows, labels)


def build_in_memory_global_tail(
    parameters: cap.CAPParameters,
    randomness: cap.CAPRandomness,
    execution: cap.CAPExecution,
    message: bytes = FROZEN_REQUEST_MESSAGE,
) -> tuple[
    GlobalTailSummary,
    GlobalTailSummary,
    tuple[assignment.TamperProbe, ...],
]:
    labels = capture_labels(parameters, execution)
    captured: dict[str, field.RankOneRow] = {}
    values = MemoryAssignment()
    generated = build_global_tail(
        parameters,
        randomness,
        execution,
        message,
        assignment_writer=values,
        capture_rows=labels,
        captured_rows_output=captured,
    )
    verified = build_global_tail(
        parameters,
        randomness,
        execution,
        message,
        verification_assignment=values,
    )
    probes = run_tamper_probes(values, captured, labels)
    return generated, verified, probes


def build_assignment_backed_global_tail(
    archive_path: Path,
    parameters: cap.CAPParameters,
    randomness: cap.CAPRandomness,
    execution: cap.CAPExecution,
    message: bytes = FROZEN_REQUEST_MESSAGE,
    *,
    workers: int = 1,
    replace: bool = False,
    progress: Callable[[str], None] | None = None,
) -> GlobalTailAssignmentResult:
    labels = capture_labels(parameters, execution)
    captured: dict[str, field.RankOneRow] = {}
    writer = assignment.AssignmentArchiveWriter(archive_path, replace=replace)
    generation_started = time.perf_counter()
    try:
        generated = build_global_tail(
            parameters,
            randomness,
            execution,
            message,
            workers=workers,
            assignment_writer=writer,
            capture_rows=labels,
            captured_rows_output=captured,
            progress=progress,
        )
        archive = writer.finish(generated.wires, generated.stream_sha256)
    except BaseException:
        writer.abort()
        raise
    generation_seconds = time.perf_counter() - generation_started
    verification_started = time.perf_counter()
    with assignment.AssignmentArchiveReader(
        archive_path, expected=archive, verify_body=True
    ) as values:
        verified = build_global_tail(
            parameters,
            randomness,
            execution,
            message,
            workers=1,
            verification_assignment=values,
            progress=progress,
        )
        if verified.verification_failures:
            raise AssertionError(
                "global-tail assignment failed first at "
                f"{verified.first_verification_failure}"
            )
        if (
            verified.rows != generated.rows
            or verified.wires != generated.wires
            or verified.stream_sha256 != generated.stream_sha256
        ):
            raise AssertionError("global-tail replay topology mismatch")
        probes = run_tamper_probes(values, captured, labels)
    verification_seconds = time.perf_counter() - verification_started
    if not all(probe.rejected for probe in probes):
        raise AssertionError("a global-tail stale-witness probe was accepted")
    return GlobalTailAssignmentResult(
        generated,
        verified,
        archive,
        probes,
        generation_seconds,
        verification_seconds,
    )


def build_manifest(result: GlobalTailAssignmentResult) -> dict[str, object]:
    summary = result.generated
    is_production = summary.parameters == cap.PRODUCTION_PARAMETERS
    frozen_matches = (
        not is_production
        or (
            bool(FROZEN_PRODUCTION_STREAM_SHA256)
            and bool(FROZEN_PRODUCTION_ASSIGNMENT_SHA256)
            and summary.stream_sha256 == FROZEN_PRODUCTION_STREAM_SHA256
            and result.archive.archive_sha256
            == FROZEN_PRODUCTION_ASSIGNMENT_SHA256
            and summary.rows == FROZEN_PRODUCTION_ROWS
            and summary.wires == FROZEN_PRODUCTION_WIRES
        )
    )
    return {
        "implementation_version": IMPLEMENTATION_VERSION,
        "profile": {
            "relation_id": RELATION_ID,
            "stream_format": STREAM_FORMAT,
            "assignment_format": assignment.ASSIGNMENT_FORMAT,
            "cap_profile_fingerprint": cap.profile_fingerprint(
                summary.parameters
            ),
            "tree_count": summary.parameters.tree_count,
            "production_profile": is_production,
        },
        "trace": {
            "wires": summary.wires,
            "rows": summary.rows,
            "nonlinear_rows": summary.nonlinear_rows,
            "linear_rows": summary.linear_rows,
            "stream_bytes": summary.stream_bytes,
            "stream_sha256": summary.stream_sha256,
            "groups": [asdict(group) for group in summary.groups],
            "sponge_accounting": asdict(summary.sponge_accounting),
            "external_assertions": summary.external_assertions,
            "verification_failures": result.verified.verification_failures,
            "generation_seconds": result.generation_seconds,
            "verification_seconds": result.verification_seconds,
            "peak_rss_kib": summary.peak_rss_kib,
        },
        "assignment_archive": asdict(result.archive),
        "ports": [asdict(port) for port in summary.ports],
        "outputs": {
            "commitment_bytes": len(summary.commitment_bytes),
            "commitment_sha256": hashlib.sha256(
                summary.commitment_bytes
            ).hexdigest(),
            "request_hash_hex": summary.request_hash_bytes.hex(),
        },
        "stale_witness_probes": [
            asdict(probe) for probe in result.tamper_probes
        ],
        "claim_boundary": {
            "production_global_tail_native_closed": (
                is_production
                and frozen_matches
                and summary.external_assertions == 0
                and result.verified.verification_failures == 0
                and all(probe.rejected for probe in result.tamper_probes)
            ),
            "global_tail_ports_are_native_bit_constrained": True,
            "tree_producer_segments_materialized": False,
            "cross_segment_wire_identity_closed": False,
            "complete_18_tree_assignment_replayed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }


def seal_existing_manifest(document: dict[str, object]) -> dict[str, object]:
    """Revalidate and seal a completed production manifest.

    The initial production run is intentionally fail-closed because its row,
    wire, stream, and assignment digests are not known until the canonical
    execution has completed.  Once those values are frozen in this module,
    this function permits sealing the already-generated evidence without
    regenerating the very large assignment archive.  Every security-relevant
    field is checked before the single native-tail claim is changed to true.
    """

    if not (
        FROZEN_PRODUCTION_STREAM_SHA256
        and FROZEN_PRODUCTION_ASSIGNMENT_SHA256
        and FROZEN_PRODUCTION_ROWS > 0
        and FROZEN_PRODUCTION_WIRES > 0
    ):
        raise ValueError("production global-tail constants are not frozen")

    profile = document.get("profile")
    trace = document.get("trace")
    archive = document.get("assignment_archive")
    outputs = document.get("outputs")
    probes = document.get("stale_witness_probes")
    boundary = document.get("claim_boundary")
    if not all(
        isinstance(section, dict)
        for section in (profile, trace, archive, outputs, boundary)
    ) or not isinstance(probes, list):
        raise ValueError("malformed production global-tail manifest")

    expected = {
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "stream_format": STREAM_FORMAT,
        "assignment_format": assignment.ASSIGNMENT_FORMAT,
        "cap_profile_fingerprint": cap.profile_fingerprint(
            cap.PRODUCTION_PARAMETERS
        ),
        "tree_count": cap.PRODUCTION_PARAMETERS.tree_count,
        "production_profile": True,
        "rows": FROZEN_PRODUCTION_ROWS,
        "wires": FROZEN_PRODUCTION_WIRES,
        "stream_sha256": FROZEN_PRODUCTION_STREAM_SHA256,
        "archive_sha256": FROZEN_PRODUCTION_ASSIGNMENT_SHA256,
        "commitment_bytes": cap.commitment_bytes(cap.PRODUCTION_PARAMETERS),
        "commitment_sha256": FROZEN_PRODUCTION_COMMITMENT_SHA256,
        "request_hash_hex": FROZEN_PRODUCTION_REQUEST_HASH_HEX,
    }
    observed = {
        "implementation_version": document.get("implementation_version"),
        "relation_id": profile.get("relation_id"),
        "stream_format": profile.get("stream_format"),
        "assignment_format": profile.get("assignment_format"),
        "cap_profile_fingerprint": profile.get("cap_profile_fingerprint"),
        "tree_count": profile.get("tree_count"),
        "production_profile": profile.get("production_profile"),
        "rows": trace.get("rows"),
        "wires": trace.get("wires"),
        "stream_sha256": trace.get("stream_sha256"),
        "archive_sha256": archive.get("archive_sha256"),
        "commitment_bytes": outputs.get("commitment_bytes"),
        "commitment_sha256": outputs.get("commitment_sha256"),
        "request_hash_hex": outputs.get("request_hash_hex"),
    }
    mismatches = [
        key for key, value in expected.items() if observed.get(key) != value
    ]
    if mismatches:
        raise ValueError(
            "production global-tail manifest mismatch: "
            + ",".join(mismatches)
        )

    if trace.get("external_assertions") != 0:
        raise ValueError("production global-tail manifest has external assertions")
    if trace.get("verification_failures") != 0:
        raise ValueError("production global-tail replay was not clean")
    if len(probes) != 6 or not all(
        isinstance(probe, dict) and probe.get("rejected") is True
        for probe in probes
    ):
        raise ValueError("production global-tail stale-witness probes incomplete")
    required_boundary = {
        "global_tail_ports_are_native_bit_constrained": True,
        "tree_producer_segments_materialized": False,
        "cross_segment_wire_identity_closed": False,
        "complete_18_tree_assignment_replayed": False,
        "parent_cap_to_h_rbbc_join_closed": False,
        "fork_security_proof_revalidated": False,
        "production_closed": False,
    }
    boundary_mismatches = [
        key
        for key, value in required_boundary.items()
        if boundary.get(key) is not value
    ]
    if boundary_mismatches:
        raise ValueError(
            "production global-tail claim boundary mismatch: "
            + ",".join(boundary_mismatches)
        )

    # Copy only the dictionaries that are mutated so callers retain their
    # original object and can compare the unsealed and sealed evidence.
    sealed = dict(document)
    sealed_boundary = dict(boundary)
    sealed_boundary["production_global_tail_native_closed"] = True
    sealed["claim_boundary"] = sealed_boundary
    return sealed


def seal_manifest_file(path: Path) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("global-tail manifest root must be an object")
    sealed = seal_existing_manifest(document)
    path.write_text(
        json.dumps(sealed, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _load_production_execution(path: Path) -> composer.ParallelExecutionSummary:
    class ComposerCacheUnpickler(pickle.Unpickler):
        def find_class(self, module: str, name: str):
            # The trusted cache was produced by executing the composer as a
            # script, so its dataclass was recorded under ``__main__``.
            if module == "__main__" and name == "ParallelExecutionSummary":
                return composer.ParallelExecutionSummary
            return super().find_class(module, name)

    with path.open("rb") as stream:
        summary = ComposerCacheUnpickler(stream).load()
    if not isinstance(summary, composer.ParallelExecutionSummary):
        raise ValueError("production execution cache type mismatch")
    randomness = cap.deterministic_randomness(
        cap.PRODUCTION_PARAMETERS, composer.FROZEN_RANDOMNESS_LABEL
    )
    failures = composer.validate_execution_cache_identity(
        summary, cap.PRODUCTION_PARAMETERS, randomness
    )
    if failures:
        raise ValueError("production execution cache rejected: " + ",".join(failures))
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument(
        "--seal-existing",
        type=Path,
        help="revalidate and seal an existing production manifest",
    )
    parser.add_argument(
        "--fixture", choices=("reduced", "production"), default="reduced"
    )
    parser.add_argument("--execution-cache", type=Path)
    parser.add_argument(
        "--workers", type=int, default=max(1, min(8, os.cpu_count() or 1))
    )
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    if args.seal_existing is not None:
        if args.archive is not None or args.manifest is not None:
            parser.error("--seal-existing cannot be combined with --archive/--manifest")
        seal_manifest_file(args.seal_existing)
        print(
            json.dumps(
                {"sealed_manifest": str(args.seal_existing)}, sort_keys=True
            )
        )
        return
    if args.archive is None or args.manifest is None:
        parser.error("--archive and --manifest are required for generation")
    if args.fixture == "production":
        if args.execution_cache is None:
            parser.error("--execution-cache is required for production")
        cached = _load_production_execution(args.execution_cache)
        parameters = cap.PRODUCTION_PARAMETERS
        randomness = cap.deterministic_randomness(
            parameters, composer.FROZEN_RANDOMNESS_LABEL
        )
        execution = cached.execution
    else:
        parameters = cap.REDUCED_TEST_PARAMETERS
        randomness = cap.deterministic_randomness(parameters)
        execution = cap.execute_cap_commit(parameters, randomness)
    result = build_assignment_backed_global_tail(
        args.archive,
        parameters,
        randomness,
        execution,
        workers=args.workers,
        replace=args.replace,
        progress=lambda message: print(message, flush=True),
    )
    args.manifest.write_text(
        json.dumps(build_manifest(result), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "archive": str(args.archive),
                "archive_sha256": result.archive.archive_sha256,
                "manifest": str(args.manifest),
                "rows": result.generated.rows,
                "stream_sha256": result.generated.stream_sha256,
                "wires": result.generated.wires,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
