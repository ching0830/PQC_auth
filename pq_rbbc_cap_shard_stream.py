#!/usr/bin/env python3
"""Bounded-memory production-tree shard for the PQ-RBBC v2.5 checkpoint.

This module materializes the topology of one real 2^11-leaf production CAP
tree with the full 2,048-bit witness, two consistency points, degree-12 leaf
extension field, and 2,450-bit tapes.  Rows are validated by frozen local
templates and serialized directly into a SHA-256 sink; the multi-gigabyte
expanded JSON stream and its complete assignment are deliberately not kept.

The construction uses linearity to avoid materializing 2,450 coordinate masks:
each leaf's 2,048 tape bits are evaluated in 11-coefficient Horner form, then
the two field outputs are accumulated into the plain hash and the twelve
extension-bit mask hashes.  Raw witness and M-hat wire identifiers live in a
compact temporary binary spool and are reread only when their wide linear
forms are needed.

This is a non-secure one-tree shard and not a production issuance proof.  Its
purpose is to close the production-shape engineering boundary before the full
18-tree run and parent-archive import.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
import resource
import struct
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterable, Iterator, Mapping, Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_anemoi_sponge as sponge
import pq_rbbc_cap_commit as cap


IMPLEMENTATION_VERSION = "2.5"
PROFILE_NAME = "PQ-RBBC-CAP-PRODUCTION-TREE-SHARD-2048-v1"
PROFILE_RELATION_ID = "pq-rbbc/cap/production-tree-shard-2048/v1"
STREAM_FORMAT = "F193-R1CS-NDJSON-SHA256-1"
SPOOL_FORMAT = "PQRBBC-WIRE-SPOOL-U64LE-1"

FROZEN_PRODUCTION_WIRES = 19_903_324
FROZEN_PRODUCTION_ROWS = 26_126_283
FROZEN_PRODUCTION_NONLINEAR_ROWS = 19_509_254
FROZEN_PRODUCTION_LINEAR_ROWS = 6_617_029
FROZEN_PRODUCTION_STREAM_BYTES = 18_869_935_441
FROZEN_PRODUCTION_STREAM_SHA256 = (
    "2cfc3641a94635af35dfa5494c61e74a416ef2fb446975cd417891d244943dfc"
)
FROZEN_PRODUCTION_SPOOL_BYTES = 39_878_656
FROZEN_PRODUCTION_SPOOL_SHA256 = (
    "87960a5803e2663a40b3c0bda1611840806e649f3927c238bd63bdce08812f49"
)
FROZEN_PRODUCTION_COMMITMENT_SHA256 = (
    "14fab7548083411124176bb8e094628fe6d20347cd78929573b76ab2cd3e757a"
)
FROZEN_PRODUCTION_REQUEST_HASH_HEX = (
    "148316172737069cf7b6b54e28da3ae48a41ce3c3d7fa6f61f67d67b96d3d851"
    "89ec1f860f733d7bb050ea1b77566f1cebaf52b212d00c6128918225e8a20719"
    "b76b303ac2ee073a"
)


PRODUCTION_TREE_SHARD_PARAMETERS = cap.CAPParameters(
    name="PQ-RBBC-CAP-PRODUCTION-TREE-SHARD-2048-TEST-ONLY",
    security_bits=0,
    mask_bits=576,
    appended_signature_bits=1_472,
    degree=2,
    rho=16,
    consistency_points=2,
    tree_specs=(cap.TreeSpec(1, 1 << 11),),
    secure_profile=False,
)

PROBE_PARAMETERS = cap.CAPParameters(
    name="PQ-RBBC-CAP-STREAM-PROBE-4-TEST-ONLY",
    security_bits=0,
    mask_bits=193,
    appended_signature_bits=193,
    degree=2,
    rho=2,
    consistency_points=2,
    tree_specs=(cap.TreeSpec(1, 4),),
    secure_profile=False,
)


BitForm = field.LinearForm


def _wire_id(form: BitForm) -> int:
    if len(form.terms) != 1 or form.terms[0][1] != 1 or form.constant:
        raise ValueError("expected a canonical wire form")
    return form.terms[0][0]


def _constant_bits(data: bytes) -> tuple[BitForm, ...]:
    return tuple(
        BitForm.const((byte >> bit) & 1)
        for byte in data
        for bit in range(8)
    )


@dataclass(frozen=True)
class BitSource:
    bit_length: int
    factory: Callable[[], Iterator[BitForm]]

    def __iter__(self) -> Iterator[BitForm]:
        iterator = self.factory()
        count = 0
        for form in iterator:
            count += 1
            yield form
        if count != self.bit_length:
            raise AssertionError(
                f"bit source emitted {count}, expected {self.bit_length}"
            )


def source_forms(forms: Sequence[BitForm]) -> BitSource:
    frozen = tuple(forms)
    return BitSource(len(frozen), lambda: iter(frozen))


def source_wires(start: int, count: int) -> BitSource:
    return BitSource(
        count,
        lambda: (BitForm.wire(start + index) for index in range(count)),
    )


def source_constant(data: bytes) -> BitSource:
    frozen = _constant_bits(data)
    return source_forms(frozen)


def source_zero_bits(count: int) -> BitSource:
    return BitSource(
        count,
        lambda: (BitForm.const(0) for _ in range(count)),
    )


def source_concat(*items: BitSource) -> BitSource:
    frozen = tuple(items)

    def generate() -> Iterator[BitForm]:
        for item in frozen:
            yield from item

    return BitSource(sum(item.bit_length for item in frozen), generate)


def source_pad_to_byte(item: BitSource) -> BitSource:
    padded = ((item.bit_length + 7) // 8) * 8
    return source_concat(item, source_zero_bits(padded - item.bit_length))


def source_field_bytes(start: int) -> BitSource:
    return source_concat(
        source_wires(start, field.FIELD_DEGREE),
        source_zero_bits(field.FIELD_ELEMENT_BYTES * 8 - field.FIELD_DEGREE),
    )


def source_hash_bytes(start: int) -> BitSource:
    return source_concat(
        source_wires(start, cap.HASH_BITS),
        source_zero_bits(cap.HASH_BYTES * 8 - cap.HASH_BITS),
    )


def encoded_transcript_source(fields: Sequence[BitSource]) -> BitSource:
    frozen = tuple(fields)
    if any(item.bit_length % 8 for item in frozen):
        raise ValueError("transcript sources must be byte aligned")
    pieces: list[BitSource] = [
        source_constant(sponge.TRANSCRIPT_MAGIC),
        source_constant(len(frozen).to_bytes(2, "little")),
    ]
    for item in frozen:
        pieces.append(
            source_constant((item.bit_length // 8).to_bytes(8, "little"))
        )
        pieces.append(item)
    return source_concat(*pieces)


@dataclass(frozen=True)
class StreamGroup:
    name: str
    rows: int
    bytes: int
    sha256: str


class StreamingRowSink:
    """Canonical NDJSON row hasher with no retained row list."""

    def __init__(self, header: Mapping[str, object]) -> None:
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
        self.groups: list[StreamGroup] = []
        self._write_record({"kind": "header", **dict(header)}, count_row=False)

    @property
    def wire_count(self) -> int:
        return self.next_wire - 1

    def allocate(self, count: int = 1) -> int:
        if count <= 0:
            raise ValueError("wire allocation must be positive")
        start = self.next_wire
        self.next_wire += count
        return start

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
            StreamGroup(
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

    def _write_record(
        self, document: Mapping[str, object], *, count_row: bool
    ) -> None:
        encoded = (
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        self._digest.update(encoded)
        self.bytes += len(encoded)
        if self._group_digest is not None:
            self._group_digest.update(encoded)
            self._group_bytes += len(encoded)
            if count_row:
                self._group_rows += 1

    def row(
        self,
        label: str,
        left: BitForm,
        right: BitForm,
        output: BitForm,
        *,
        nonlinear: bool,
    ) -> None:
        document = {
            "kind": "row",
            "label": label,
            "left": left.canonical_dict(),
            "output": output.canonical_dict(),
            "right": right.canonical_dict(),
        }
        self._write_record(document, count_row=True)
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
        self._write_record({"kind": "trailer", **dict(trailer)}, count_row=False)
        return self.bytes, self._digest.hexdigest()


@dataclass(frozen=True)
class SpongeAccounting:
    calls: int = 0
    permutations: int = 0
    permutation_rows: int = 0
    payload_bitness_rows: int = 0
    output_bitness_rows: int = 0
    linear_rows: int = 0
    source_link_rows: int = 0

    def add(self, other: "SpongeAccounting") -> "SpongeAccounting":
        return SpongeAccounting(
            **{
                name: getattr(self, name) + getattr(other, name)
                for name in self.__dataclass_fields__
            }
        )


@dataclass(frozen=True)
class LoweredSpongeCall:
    output_wires: tuple[int, ...]
    accounting: SpongeAccounting


class StreamingSpongeLowerer:
    def __init__(self, sink: StreamingRowSink) -> None:
        self.sink = sink
        self.parameters = field.derive_parameters()
        self.permutation_template = field.build_native_trace(
            (0,) * field.STATE_ELEMENTS,
            self.parameters,
        )
        if self.permutation_template.failed_rows():
            raise AssertionError("frozen permutation template is unsatisfied")

    @staticmethod
    def _remap_form(form: BitForm, base: int) -> BitForm:
        return BitForm(
            tuple(
                (base + wire_id - 1, coefficient)
                for wire_id, coefficient in form.terms
            ),
            form.constant,
        )

    def _instantiate_permutation(
        self, prefix: str
    ) -> tuple[tuple[int, ...], tuple[int, ...]]:
        template = self.permutation_template
        base = self.sink.allocate(len(template.assignment))
        for index, row in enumerate(template.rows):
            self.sink.row(
                f"{prefix}.{row.label}",
                self._remap_form(row.left, base),
                self._remap_form(row.right, base),
                self._remap_form(row.output, base),
                nonlinear=index < template.nonlinear_rows,
            )
        return (
            tuple(base + wire_id - 1 for wire_id in template.input_wires),
            tuple(base + wire_id - 1 for wire_id in template.output_wires),
        )

    @staticmethod
    def _frame_bit(
        absolute_index: int,
        header_bits: Sequence[int],
        payload_start: int,
        payload_bits: int,
        framed_bits: int,
    ) -> tuple[int | None, int]:
        header_length = len(header_bits)
        if absolute_index < header_length:
            return None, header_bits[absolute_index]
        payload_index = absolute_index - header_length
        if payload_index < payload_bits:
            return payload_start + payload_index, 0
        if absolute_index == header_length + payload_bits:
            return None, 1
        if absolute_index == framed_bits - 1:
            return None, 1
        return None, 0

    def lower(
        self,
        call: cap.XOFCall,
        source_fields: Sequence[BitSource],
        call_index: int,
    ) -> LoweredSpongeCall:
        source_payload = encoded_transcript_source(source_fields)
        payload_bytes = len(call.payload)
        if source_payload.bit_length != payload_bytes * 8:
            raise AssertionError(f"source payload width mismatch for {call.label}")

        payload_bits = payload_bytes * 8
        payload_start = self.sink.allocate(payload_bits)
        prefix = f"xof[{call_index}].{call.label}"
        for index in range(payload_bits):
            self.sink.bitness(
                f"{prefix}.payload[{index}].bit", payload_start + index
            )

        header = (
            sponge.FRAME_MAGIC
            + len(call.domain).to_bytes(2, "little")
            + call.domain
            + payload_bytes.to_bytes(8, "little")
        )
        header_bits = sponge.bytes_to_bits_lsb(header)
        unpadded_bits = len(header_bits) + payload_bits
        framed_bits = (
            (unpadded_bits + 2 + sponge.RATE_BITS - 1) // sponge.RATE_BITS
        ) * sponge.RATE_BITS
        absorbed_blocks = framed_bits // sponge.RATE_BITS

        previous_outputs: tuple[int, ...] | None = None
        linear_rows = 0
        for block_index in range(absorbed_blocks):
            lane_wires: list[int] = []
            for lane in range(sponge.RATE_ELEMENTS):
                lane_wire = self.sink.allocate()
                lane_wires.append(lane_wire)
                terms: list[tuple[int, int]] = [(lane_wire, 1)]
                constant = 0
                for bit in range(field.FIELD_DEGREE):
                    absolute = (
                        block_index * sponge.RATE_BITS
                        + lane * field.FIELD_DEGREE
                        + bit
                    )
                    wire_id, value = self._frame_bit(
                        absolute,
                        header_bits,
                        payload_start,
                        payload_bits,
                        framed_bits,
                    )
                    if wire_id is not None:
                        terms.append((wire_id, 1 << bit))
                    elif value:
                        constant ^= 1 << bit
                self.sink.linear_zero(
                    f"{prefix}.block[{block_index}].lane[{lane}].pack",
                    BitForm(tuple(sorted(terms)), constant),
                )
                linear_rows += 1

            inputs, outputs = self._instantiate_permutation(
                f"{prefix}.perm[{block_index}]"
            )
            for lane, input_wire in enumerate(inputs):
                terms = [(input_wire, 1)]
                if previous_outputs is not None:
                    terms.append((previous_outputs[lane], 1))
                if lane < sponge.RATE_ELEMENTS:
                    terms.append((lane_wires[lane], 1))
                self.sink.linear_zero(
                    f"{prefix}.perm[{block_index}].input[{lane}].link",
                    BitForm(tuple(sorted(terms)), 0),
                )
                linear_rows += 1
            previous_outputs = outputs

        if previous_outputs is None:
            raise AssertionError("sponge absorbed no blocks")

        current_outputs = previous_outputs
        remaining = call.output_bits
        squeeze_block = 0
        exposed: list[int] = []
        output_bitness_rows = 0
        squeeze_permutations = 0
        while remaining:
            if squeeze_block:
                inputs, current_outputs = self._instantiate_permutation(
                    f"{prefix}.squeeze[{squeeze_block}].perm"
                )
                squeeze_permutations += 1
                for lane, input_wire in enumerate(inputs):
                    self.sink.linear_zero(
                        f"{prefix}.squeeze[{squeeze_block}].input[{lane}].link",
                        BitForm(
                            tuple(
                                sorted(
                                    (
                                        (input_wire, 1),
                                        (previous_outputs[lane], 1),
                                    )
                                )
                            ),
                            0,
                        ),
                    )
                    linear_rows += 1
                previous_outputs = current_outputs

            block_bits = min(sponge.RATE_BITS, remaining)
            elements = (block_bits + field.FIELD_DEGREE - 1) // field.FIELD_DEGREE
            for lane in range(elements):
                label_prefix = (
                    f"{prefix}.digest.lane[{lane}]"
                    if squeeze_block == 0
                    else f"{prefix}.digest.block[{squeeze_block}].lane[{lane}]"
                )
                bit_start = self.sink.allocate(field.FIELD_DEGREE)
                for bit in range(field.FIELD_DEGREE):
                    self.sink.bitness(
                        f"{label_prefix}.bit[{bit}].bit", bit_start + bit
                    )
                output_bitness_rows += field.FIELD_DEGREE
                packed_terms = [(current_outputs[lane], 1)] + [
                    (bit_start + bit, 1 << bit)
                    for bit in range(field.FIELD_DEGREE)
                ]
                self.sink.linear_zero(
                    f"{label_prefix}.pack",
                    BitForm(tuple(sorted(packed_terms)), 0),
                )
                linear_rows += 1
                take = min(
                    field.FIELD_DEGREE,
                    block_bits - lane * field.FIELD_DEGREE,
                )
                exposed.extend(bit_start + bit for bit in range(take))
            remaining -= block_bits
            squeeze_block += 1

        source_count = 0
        for index, source_form in enumerate(source_payload):
            self.sink.linear_zero(
                f"{prefix}.payload[{index}].source",
                BitForm.wire(payload_start + index).add(source_form),
            )
            source_count += 1
        if source_count != payload_bits:
            raise AssertionError("source-link count mismatch")
        linear_rows += source_count

        permutations = absorbed_blocks + squeeze_permutations
        return LoweredSpongeCall(
            tuple(exposed),
            SpongeAccounting(
                calls=1,
                permutations=permutations,
                permutation_rows=permutations * field.NONLINEAR_ROWS,
                payload_bitness_rows=payload_bits,
                output_bitness_rows=output_bitness_rows,
                linear_rows=linear_rows
                + permutations * field.OUTPUT_BINDING_ROWS,
                source_link_rows=source_count,
            ),
        )


def _xof_output(domain: bytes, fields: tuple[bytes, ...], output_bits: int) -> int:
    payload = sponge.encode_transcript(fields)
    output_bytes = (output_bits + 7) // 8
    raw = sponge.evaluate_sponge(domain, payload, output_bytes)
    return int.from_bytes(raw, "little") & ((1 << output_bits) - 1)


def _derive_task(task: tuple[int, int, tuple[int, int]]) -> int:
    tree_index, level, payload = task
    node_index, parent, salt = payload
    fields = (
        cap.hash_bytes(salt[0] | (salt[1] << cap.SEED_BITS)),
        cap.field_bytes(parent),
        cap._meta(tree_index, level, node_index),
    )
    return _xof_output(cap.DOMAIN_SEED_DERIVE, fields, 2 * cap.SEED_BITS)


def _leaf_task(
    task: tuple[int, int, int, tuple[int, int], int]
) -> tuple[int, int]:
    tree_index, leaf_index, seed, salt, tape_bits = task
    metadata = cap._meta(tree_index, 0, leaf_index)
    commit = _xof_output(
        cap.DOMAIN_SEED_COMMIT,
        (
            cap.hash_bytes(salt[0] | (salt[1] << cap.SEED_BITS)),
            cap.field_bytes(seed),
            metadata,
        ),
        cap.HASH_BITS,
    )
    tape = _xof_output(
        cap.DOMAIN_TAPE_EXPAND,
        (cap.field_bytes(seed), metadata),
        tape_bits,
    )
    return commit, tape


def _parallel_map(
    function: Callable[[object], object],
    tasks: Sequence[object],
    workers: int,
    progress: Callable[[int, int], None] | None = None,
) -> list[object]:
    total = len(tasks)
    output: list[object] = []
    if workers <= 1:
        iterator = map(function, tasks)
    else:
        executor = ProcessPoolExecutor(max_workers=workers)
        iterator = executor.map(function, tasks, chunksize=4)
    try:
        for completed, item in enumerate(iterator, start=1):
            output.append(item)
            if progress is not None and (completed % 128 == 0 or completed == total):
                progress(completed, total)
    finally:
        if workers > 1:
            executor.shutdown()
    return output


def build_parallel_execution(
    parameters: cap.CAPParameters,
    randomness: cap.CAPRandomness,
    *,
    workers: int = 1,
    progress: Callable[[str], None] | None = None,
) -> cap.CAPExecution:
    """Build a one-tree CAP reference while parallelizing independent XOFs."""

    if parameters.tree_count != 1:
        raise ValueError("streaming shard requires exactly one tree")
    if len(randomness.roots) != 1:
        raise ValueError("wrong shard root count")
    leaves = parameters.expanded_leaf_counts()[0]
    extension_degree = parameters.expanded_extension_degrees()[0]
    nodes = list(randomness.roots[0])
    calls: list[cap.XOFCall] = []
    level = 2
    while len(nodes) < leaves:
        tasks = [
            (0, level, (node_index, parent, randomness.salt))
            for node_index, parent in enumerate(nodes, start=1)
        ]
        outputs = _parallel_map(_derive_task, tasks, workers)
        children: list[int] = []
        for node_index, (parent, output) in enumerate(
            zip(nodes, outputs), start=1
        ):
            fields = (
                cap.hash_bytes(
                    randomness.salt[0]
                    | (randomness.salt[1] << cap.SEED_BITS)
                ),
                cap.field_bytes(parent),
                cap._meta(0, level, node_index),
            )
            calls.append(
                cap.XOFCall(
                    f"tree[0].derive[{level},{node_index}]",
                    cap.DOMAIN_SEED_DERIVE,
                    fields,
                    2 * cap.SEED_BITS,
                    int(output),
                )
            )
            children.extend(
                (
                    int(output) & field.FIELD_MASK,
                    int(output) >> cap.SEED_BITS,
                )
            )
        nodes = children
        if progress is not None:
            progress(f"reference derive level {level}: {len(nodes)} nodes")
        level += 1

    leaf_tasks = [
        (0, leaf_index, seed, randomness.salt, parameters.random_polynomial_bits)
        for leaf_index, seed in enumerate(nodes, start=1)
    ]
    leaf_outputs = _parallel_map(
        _leaf_task,
        leaf_tasks,
        workers,
        (
            None
            if progress is None
            else lambda completed, total: progress(
                f"reference leaf XOFs: {completed}/{total}"
            )
        ),
    )
    commitments: list[tuple[int, int]] = []
    tapes: list[int] = []
    plain = 0
    masks = [0] * parameters.random_polynomial_bits
    for leaf_index, (seed, result) in enumerate(
        zip(nodes, leaf_outputs), start=1
    ):
        commit, tape = (int(result[0]), int(result[1]))
        metadata = cap._meta(0, 0, leaf_index)
        commit_fields = (
            cap.hash_bytes(
                randomness.salt[0]
                | (randomness.salt[1] << cap.SEED_BITS)
            ),
            cap.field_bytes(seed),
            metadata,
        )
        tape_fields = (cap.field_bytes(seed), metadata)
        calls.append(
            cap.XOFCall(
                f"tree[0].leaf[{leaf_index}].commit",
                cap.DOMAIN_SEED_COMMIT,
                commit_fields,
                cap.HASH_BITS,
                commit,
            )
        )
        calls.append(
            cap.XOFCall(
                f"tree[0].leaf[{leaf_index}].tape",
                cap.DOMAIN_TAPE_EXPAND,
                tape_fields,
                parameters.random_polynomial_bits,
                tape,
            )
        )
        commitments.append(
            (commit & field.FIELD_MASK, commit >> field.FIELD_DEGREE)
        )
        tapes.append(tape)
        plain ^= tape
        inverse = cap.gf2m_inv(leaf_index, extension_degree)
        set_bits = tape
        while set_bits:
            low_bit = set_bits & -set_bits
            masks[low_bit.bit_length() - 1] ^= inverse
            set_bits ^= low_bit

    polynomial = cap.TreePolynomial(
        leaves,
        extension_degree,
        tuple(commitments),
        plain,
        tuple(masks),
    )
    profile = bytes.fromhex(cap.profile_fingerprint(parameters))
    h1_fields = (
        profile,
        cap._tree_component(0, polynomial),
        cap._correction_component((), (), parameters),
    )
    h1 = _xof_output(cap.DOMAIN_H1, h1_fields, cap.HASH_BITS)
    calls.append(cap.XOFCall("h1", cap.DOMAIN_H1, h1_fields, cap.HASH_BITS, h1))
    point_fields = (cap.hash_bytes(h1), profile)
    point_output = _xof_output(
        cap.DOMAIN_CONSISTENCY_POINTS,
        point_fields,
        parameters.consistency_bits,
    )
    calls.append(
        cap.XOFCall(
            "consistency-points",
            cap.DOMAIN_CONSISTENCY_POINTS,
            point_fields,
            parameters.consistency_bits,
            point_output,
        )
    )
    points = tuple(
        (point_output >> (index * field.FIELD_DEGREE)) & field.FIELD_MASK
        for index in range(parameters.consistency_points)
    )
    if any(point == 0 for point in points) or len(set(points)) != len(points):
        raise RuntimeError("degenerate consistency points")

    witness_mask = (1 << parameters.witness_bits) - 1
    consistency_mask = (1 << parameters.consistency_bits) - 1
    p_plain = plain & witness_mask
    mhat_shift = (
        parameters.witness_bits + (parameters.degree - 1) * parameters.rho
    )
    mhat_plain = (plain >> mhat_shift) & consistency_mask
    alpha = cap._linear_hash_vector(
        p_plain,
        parameters.witness_bits,
        points,
    ) ^ mhat_plain
    p_masks = polynomial.masks[: parameters.witness_bits]
    mhat_masks = polynomial.masks[
        mhat_shift : mhat_shift + parameters.consistency_bits
    ]
    hashed_masks = cap._linear_hash_masks(
        p_masks,
        parameters.witness_bits,
        extension_degree,
        points,
    )
    xi_masks = tuple(
        left ^ right for left, right in zip(hashed_masks, mhat_masks)
    )
    xi_component = cap._xi_component(
        alpha,
        xi_masks,
        parameters.consistency_bits,
        extension_degree,
    )
    h2_fields = (cap.hash_bytes(h1), xi_component)
    h2 = _xof_output(cap.DOMAIN_H2, h2_fields, cap.HASH_BITS)
    calls.append(cap.XOFCall("h2", cap.DOMAIN_H2, h2_fields, cap.HASH_BITS, h2))
    encoded = cap.serialize_commitment(
        parameters,
        randomness.salt,
        h2,
        alpha,
        (),
        (),
    )
    commitment = cap.CAPCommitment(
        cap.profile_fingerprint(parameters),
        randomness.salt,
        h1,
        h2,
        alpha,
        (),
        (),
        p_plain & ((1 << parameters.mask_bits) - 1),
        (p_plain >> parameters.mask_bits)
        & ((1 << parameters.appended_signature_bits) - 1),
        encoded,
    )
    return cap.CAPExecution(commitment, (polynomial,), tuple(calls))


class CallCursor:
    def __init__(self, calls: Sequence[cap.XOFCall]) -> None:
        self.calls = calls
        self.index = 0

    def take(self, label: str) -> tuple[int, cap.XOFCall]:
        if self.index >= len(self.calls):
            raise AssertionError("XOF cursor exhausted")
        index = self.index
        item = self.calls[index]
        self.index += 1
        if item.label != label:
            raise AssertionError(f"expected {label}, got {item.label}")
        return index, item


class WireSpool:
    def __init__(self, record_wires: int) -> None:
        self.record_wires = record_wires
        self._file = tempfile.NamedTemporaryFile(
            prefix="pq-rbbc-shard-spool-", suffix=".bin", delete=False
        )
        self.path = Path(self._file.name)
        self.records = 0
        self.digest = hashlib.sha256()

    def append(self, wire_ids: Sequence[int]) -> None:
        if len(wire_ids) != self.record_wires:
            raise ValueError("wire spool record width mismatch")
        packed = struct.pack("<" + "Q" * len(wire_ids), *wire_ids)
        self._file.write(packed)
        self.digest.update(packed)
        self.records += 1

    def close_writer(self) -> None:
        self._file.flush()
        os.fsync(self._file.fileno())
        self._file.close()

    def open_reader(self) -> "WireSpoolReader":
        self.close_writer()
        return WireSpoolReader(
            self.path,
            self.records,
            self.record_wires,
            self.digest.hexdigest(),
        )


class WireSpoolReader:
    def __init__(
        self,
        path: Path,
        records: int,
        record_wires: int,
        sha256: str,
    ) -> None:
        self.path = path
        self.records = records
        self.record_wires = record_wires
        self.sha256 = sha256
        self._file = path.open("rb")
        self._map = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)

    @property
    def bytes(self) -> int:
        return self.records * self.record_wires * 8

    def record(self, index: int) -> tuple[int, ...]:
        if not 0 <= index < self.records:
            raise IndexError(index)
        offset = index * self.record_wires * 8
        return struct.unpack_from(
            "<" + "Q" * self.record_wires,
            self._map,
            offset,
        )

    def wire(self, record: int, coordinate: int) -> int:
        offset = (record * self.record_wires + coordinate) * 8
        return struct.unpack_from("<Q", self._map, offset)[0]

    def close(self) -> None:
        self._map.close()
        self._file.close()
        self.path.unlink(missing_ok=True)


@dataclass(frozen=True)
class HornerShardAccounting:
    leaf_calls: int
    multiplication_rows: int
    aggregate_rows: int
    point_validation_rows: int
    output_bitness_rows: int
    output_pack_rows: int


@dataclass(frozen=True)
class ShardTraceSummary:
    parameters: cap.CAPParameters
    stream_bytes: int
    stream_sha256: str
    wires: int
    rows: int
    nonlinear_rows: int
    linear_rows: int
    sponge_accounting: SpongeAccounting
    horner_accounting: HornerShardAccounting
    groups: tuple[StreamGroup, ...]
    xof_calls: int
    commitment_bytes: bytes
    request_hash_bytes: bytes
    spool_bytes: int
    spool_sha256: str
    wall_seconds: float
    peak_rss_kib: int
    assignment_materialized: bool
    external_assertions: int


def _allocate_input_bits(
    sink: StreamingRowSink,
    bit_length: int,
    prefix: str,
) -> int:
    start = sink.allocate(bit_length)
    for index in range(bit_length):
        sink.bitness(f"{prefix}[{index}].bit", start + index)
    return start


def _point_validation(
    sink: StreamingRowSink,
    point_starts: Sequence[int],
    prefix: str,
) -> int:
    forms = [
        BitForm(
            tuple(
                (start + bit, 1 << bit)
                for bit in range(field.FIELD_DEGREE)
            ),
            0,
        )
        for start in point_starts
    ]
    rows = 0
    for index, form in enumerate(forms):
        inverse = sink.allocate()
        sink.row(
            f"{prefix}.point[{index}].nonzero",
            form,
            BitForm.wire(inverse),
            BitForm.const(1),
            nonlinear=True,
        )
        rows += 1
    for left in range(len(forms)):
        for right in range(left + 1, len(forms)):
            inverse = sink.allocate()
            sink.row(
                f"{prefix}.difference[{left},{right}].nonzero",
                forms[left].add(forms[right]),
                BitForm.wire(inverse),
                BitForm.const(1),
                nonlinear=True,
            )
            rows += 1
    return rows


def _pack_coefficient(ids: Sequence[int]) -> BitForm:
    return BitForm(
        tuple((wire_id, 1 << bit) for bit, wire_id in enumerate(ids)),
        0,
    )


def _horner_leaf(
    sink: StreamingRowSink,
    witness_ids: Sequence[int],
    point_starts: Sequence[int],
    leaf_index: int,
) -> tuple[BitForm, ...]:
    coefficients = tuple(
        _pack_coefficient(
            witness_ids[offset : offset + field.FIELD_DEGREE]
        )
        for offset in range(0, len(witness_ids), field.FIELD_DEGREE)
    )
    point_forms = tuple(
        BitForm(
            tuple(
                (start + bit, 1 << bit)
                for bit in range(field.FIELD_DEGREE)
            ),
            0,
        )
        for start in point_starts
    )
    outputs: list[BitForm] = []
    for point_index, point in enumerate(point_forms):
        accumulator = coefficients[-1]
        for coefficient_index in range(len(coefficients) - 2, -1, -1):
            product = sink.allocate()
            sink.row(
                (
                    f"horner.leaf[{leaf_index}].point[{point_index}]"
                    f".mul[{coefficient_index}]"
                ),
                accumulator,
                point,
                BitForm.wire(product),
                nonlinear=True,
            )
            accumulator = BitForm.wire(product).add(
                coefficients[coefficient_index]
            )
        outputs.append(accumulator)
    return tuple(outputs)


def _aggregate_form(
    sink: StreamingRowSink,
    current_wire: int | None,
    item: BitForm,
    label: str,
) -> int:
    output = sink.allocate()
    terms = item.add(BitForm.wire(output))
    if current_wire is not None:
        terms = terms.add(BitForm.wire(current_wire))
    sink.linear_zero(label, terms)
    return output


def _decompose_field(
    sink: StreamingRowSink,
    source_wire: int,
    prefix: str,
) -> int:
    start = sink.allocate(field.FIELD_DEGREE)
    for bit in range(field.FIELD_DEGREE):
        sink.bitness(f"{prefix}.bit[{bit}].bit", start + bit)
    terms = [(source_wire, 1)] + [
        (start + bit, 1 << bit) for bit in range(field.FIELD_DEGREE)
    ]
    sink.linear_zero(f"{prefix}.pack", BitForm(tuple(sorted(terms)), 0))
    return start


def _wide_plain_form(
    spool: WireSpoolReader,
    coordinate: int,
) -> BitForm:
    return BitForm(
        tuple((spool.wire(leaf, coordinate), 1) for leaf in range(spool.records)),
        0,
    )


def _wide_mask_form(
    spool: WireSpoolReader,
    coordinate: int,
    selected_leaves: Sequence[int],
) -> BitForm:
    return BitForm(
        tuple((spool.wire(leaf, coordinate), 1) for leaf in selected_leaves),
        0,
    )


def _publish_source(
    sink: StreamingRowSink,
    source: BitSource,
    prefix: str,
) -> int:
    start = sink.allocate(source.bit_length)
    for index, form in enumerate(source):
        sink.bitness(f"{prefix}[{index}].bit", start + index)
        sink.linear_zero(
            f"{prefix}[{index}].link",
            BitForm.wire(start + index).add(form),
        )
    return start


def build_streaming_shard(
    parameters: cap.CAPParameters = PRODUCTION_TREE_SHARD_PARAMETERS,
    randomness: cap.CAPRandomness | None = None,
    message: bytes = bytes(32),
    *,
    workers: int = 1,
    execution: cap.CAPExecution | None = None,
    progress: Callable[[str], None] | None = None,
) -> ShardTraceSummary:
    if parameters.tree_count != 1:
        raise ValueError("streaming shard supports exactly one tree")
    if parameters.consistency_points != 2:
        raise ValueError("streaming shard requires two consistency points")
    if len(message) != 32:
        raise ValueError("request message must be 32 bytes")
    leaves = parameters.expanded_leaf_counts()[0]
    extension_degree = parameters.expanded_extension_degrees()[0]
    randomness = randomness or cap.deterministic_randomness(parameters)
    started = time.perf_counter()
    execution = execution or build_parallel_execution(
        parameters, randomness, workers=workers, progress=progress
    )
    if progress is not None:
        progress(f"reference execution complete: {len(execution.xof_calls)} CAP XOF calls")
    reference_calls = execution.xof_calls
    cursor = CallCursor(reference_calls)

    header = {
        "cap_profile_fingerprint": cap.profile_fingerprint(parameters),
        "field": "GF(2^193)",
        "format": STREAM_FORMAT,
        "profile_name": PROFILE_NAME,
        "relation_id": PROFILE_RELATION_ID,
        "sponge_profile_fingerprint": sponge.profile_fingerprint(
            field.derive_parameters()
        ),
    }
    sink = StreamingRowSink(header)
    lowerer = StreamingSpongeLowerer(sink)
    sponge_accounting = SpongeAccounting()

    sink.start_group("inputs")
    salt_0 = _allocate_input_bits(sink, field.FIELD_DEGREE, "input.salt[0]")
    salt_1 = _allocate_input_bits(sink, field.FIELD_DEGREE, "input.salt[1]")
    root_0 = _allocate_input_bits(sink, field.FIELD_DEGREE, "input.root[0]")
    root_1 = _allocate_input_bits(sink, field.FIELD_DEGREE, "input.root[1]")
    message_start = _allocate_input_bits(sink, 256, "input.message")
    sink.finish_group()

    salt_source = source_pad_to_byte(
        source_concat(
            source_wires(salt_0, field.FIELD_DEGREE),
            source_wires(salt_1, field.FIELD_DEGREE),
        )
    )
    nodes = [(root_0, randomness.roots[0][0]), (root_1, randomness.roots[0][1])]
    level = 2
    sink.start_group("ggm-derive")
    while len(nodes) < leaves:
        children: list[tuple[int, int]] = []
        for node_index, (parent_start, _) in enumerate(nodes, start=1):
            label = f"tree[0].derive[{level},{node_index}]"
            call_index, call = cursor.take(label)
            lowered = lowerer.lower(
                call,
                (
                    salt_source,
                    source_field_bytes(parent_start),
                    source_constant(cap._meta(0, level, node_index)),
                ),
                call_index,
            )
            sponge_accounting = sponge_accounting.add(lowered.accounting)
            output = lowered.output_wires
            children.extend(
                (
                    (output[0], call.output & field.FIELD_MASK),
                    (output[field.FIELD_DEGREE], call.output >> field.FIELD_DEGREE),
                )
            )
        nodes = children
        if progress is not None:
            progress(f"stream derive level {level}: {len(nodes)} nodes")
        level += 1
    sink.finish_group()

    witness_bits = parameters.witness_bits
    mhat_shift = witness_bits + (parameters.degree - 1) * parameters.rho
    selected_output_positions = tuple(range(witness_bits)) + tuple(
        range(mhat_shift, mhat_shift + parameters.consistency_bits)
    )
    spool_writer = WireSpool(len(selected_output_positions))
    commitments: list[tuple[int, int]] = []
    sink.start_group("leaf-commit-and-tape")
    for leaf_index, (seed_start, _) in enumerate(nodes, start=1):
        metadata = source_constant(cap._meta(0, 0, leaf_index))
        commit_index, commit_call = cursor.take(
            f"tree[0].leaf[{leaf_index}].commit"
        )
        commit = lowerer.lower(
            commit_call,
            (salt_source, source_field_bytes(seed_start), metadata),
            commit_index,
        )
        sponge_accounting = sponge_accounting.add(commit.accounting)
        commitments.append(
            (commit.output_wires[0], commit.output_wires[field.FIELD_DEGREE])
        )

        tape_index, tape_call = cursor.take(
            f"tree[0].leaf[{leaf_index}].tape"
        )
        tape = lowerer.lower(
            tape_call,
            (source_field_bytes(seed_start), metadata),
            tape_index,
        )
        sponge_accounting = sponge_accounting.add(tape.accounting)
        spool_writer.append(
            tuple(tape.output_wires[index] for index in selected_output_positions)
        )
        if progress is not None and (leaf_index % 128 == 0 or leaf_index == leaves):
            progress(f"stream leaf XOFs: {leaf_index}/{leaves}")
    sink.finish_group()
    spool = spool_writer.open_reader()
    if spool.records != leaves:
        raise AssertionError("wire spool leaf count mismatch")

    sink.start_group("h1-and-points")

    def tree_component_bits() -> Iterator[BitForm]:
        yield from source_constant(
            (0).to_bytes(2, "little")
            + leaves.to_bytes(4, "little")
            + extension_degree.to_bytes(2, "little")
        )
        for left_start, right_start in commitments:
            yield from source_field_bytes(left_start)
            yield from source_field_bytes(right_start)

    tree_component = BitSource(
        (8 + 2 * leaves * field.FIELD_ELEMENT_BYTES) * 8,
        tree_component_bits,
    )
    correction_component = source_constant(
        (0).to_bytes(2, "little")
        + witness_bits.to_bytes(4, "little")
        + parameters.consistency_bits.to_bytes(4, "little")
    )
    h1_index, h1_call = cursor.take("h1")
    h1 = lowerer.lower(
        h1_call,
        (
            source_constant(bytes.fromhex(cap.profile_fingerprint(parameters))),
            tree_component,
            correction_component,
        ),
        h1_index,
    )
    sponge_accounting = sponge_accounting.add(h1.accounting)
    h1_start = h1.output_wires[0]

    points_index, points_call = cursor.take("consistency-points")
    points = lowerer.lower(
        points_call,
        (
            source_hash_bytes(h1_start),
            source_constant(bytes.fromhex(cap.profile_fingerprint(parameters))),
        ),
        points_index,
    )
    sponge_accounting = sponge_accounting.add(points.accounting)
    point_starts = (
        points.output_wires[0],
        points.output_wires[field.FIELD_DEGREE],
    )
    point_validation_rows = _point_validation(
        sink, point_starts, "consistency.validate"
    )
    sink.finish_group()

    selected_by_extension = tuple(
        tuple(
            leaf_index - 1
            for leaf_index in range(1, leaves + 1)
            if (
                cap.gf2m_inv(leaf_index, extension_degree) >> extension_bit
            )
            & 1
        )
        for extension_bit in range(extension_degree)
    )
    sink.start_group("leaf-horner-and-field-aggregation")
    plain_accumulators: list[int | None] = [None, None]
    mask_accumulators: list[list[int | None]] = [
        [None, None] for _ in range(extension_degree)
    ]
    multiplication_rows = 0
    aggregate_rows = 0
    for leaf in range(leaves):
        record = spool.record(leaf)
        witness_ids = record[:witness_bits]
        outputs = _horner_leaf(
            sink, witness_ids, point_starts, leaf + 1
        )
        coefficient_count = (
            len(witness_ids) + field.FIELD_DEGREE - 1
        ) // field.FIELD_DEGREE
        multiplication_rows += len(outputs) * (coefficient_count - 1)
        inverse = cap.gf2m_inv(leaf + 1, extension_degree)
        for point_index, item in enumerate(outputs):
            plain_accumulators[point_index] = _aggregate_form(
                sink,
                plain_accumulators[point_index],
                item,
                f"aggregate.plain.leaf[{leaf + 1}].point[{point_index}]",
            )
            aggregate_rows += 1
            for extension_bit in range(extension_degree):
                if (inverse >> extension_bit) & 1:
                    mask_accumulators[extension_bit][point_index] = _aggregate_form(
                        sink,
                        mask_accumulators[extension_bit][point_index],
                        item,
                        (
                            f"aggregate.mask[{extension_bit}].leaf[{leaf + 1}]"
                            f".point[{point_index}]"
                        ),
                    )
                    aggregate_rows += 1
        if progress is not None and ((leaf + 1) % 128 == 0 or leaf + 1 == leaves):
            progress(f"stream Horner leaves: {leaf + 1}/{leaves}")

    if any(item is None for item in plain_accumulators):
        raise AssertionError("plain Horner accumulator missing")
    if any(item is None for row in mask_accumulators for item in row):
        raise AssertionError("mask Horner accumulator missing")
    plain_output_starts = tuple(
        _decompose_field(
            sink,
            int(plain_accumulators[point]),
            f"consistency.plain.point[{point}].output",
        )
        for point in range(2)
    )
    mask_output_starts = tuple(
        tuple(
            _decompose_field(
                sink,
                int(mask_accumulators[extension_bit][point]),
                (
                    f"consistency.mask[{extension_bit}]"
                    f".point[{point}].output"
                ),
            )
            for point in range(2)
        )
        for extension_bit in range(extension_degree)
    )
    sink.finish_group()

    output_bitness_rows = (
        (1 + extension_degree)
        * parameters.consistency_points
        * field.FIELD_DEGREE
    )
    output_pack_rows = (1 + extension_degree) * parameters.consistency_points
    horner_accounting = HornerShardAccounting(
        leaf_calls=leaves,
        multiplication_rows=multiplication_rows,
        aggregate_rows=aggregate_rows,
        point_validation_rows=point_validation_rows,
        output_bitness_rows=output_bitness_rows,
        output_pack_rows=output_pack_rows,
    )

    tail_offset = witness_bits

    def plain_tail_form(coordinate: int) -> BitForm:
        return _wide_plain_form(spool, tail_offset + coordinate)

    def mask_tail_form(extension_bit: int, coordinate: int) -> BitForm:
        return _wide_mask_form(
            spool,
            tail_offset + coordinate,
            selected_by_extension[extension_bit],
        )

    def alpha_bits() -> Iterator[BitForm]:
        for coordinate in range(parameters.consistency_bits):
            point = coordinate // field.FIELD_DEGREE
            bit = coordinate % field.FIELD_DEGREE
            yield BitForm.wire(plain_output_starts[point] + bit).add(
                plain_tail_form(coordinate)
            )

    alpha_source = BitSource(parameters.consistency_bits, alpha_bits)

    def xi_mask_bits() -> Iterator[BitForm]:
        for coordinate in range(parameters.consistency_bits):
            point = coordinate // field.FIELD_DEGREE
            bit = coordinate % field.FIELD_DEGREE
            for extension_bit in range(extension_degree):
                yield BitForm.wire(
                    mask_output_starts[extension_bit][point] + bit
                ).add(mask_tail_form(extension_bit, coordinate))

    xi_masks_source = BitSource(
        parameters.consistency_bits * extension_degree,
        xi_mask_bits,
    )
    xi_component = source_concat(
        source_constant(
            parameters.consistency_bits.to_bytes(4, "little")
            + extension_degree.to_bytes(2, "little")
        ),
        source_pad_to_byte(alpha_source),
        source_pad_to_byte(xi_masks_source),
    )

    sink.start_group("h2-commitment-and-request-binding")
    h2_index, h2_call = cursor.take("h2")
    h2 = lowerer.lower(
        h2_call,
        (source_hash_bytes(h1_start), xi_component),
        h2_index,
    )
    sponge_accounting = sponge_accounting.add(h2.accounting)
    h2_start = h2.output_wires[0]
    if cursor.index != len(reference_calls):
        raise AssertionError("unconsumed CAP XOF calls")

    commitment_source = source_concat(
        source_constant(cap.COMMITMENT_MAGIC + (1).to_bytes(2, "little")),
        source_constant(bytes.fromhex(cap.profile_fingerprint(parameters))),
        source_field_bytes(salt_0),
        source_field_bytes(salt_1),
        source_hash_bytes(h2_start),
        source_constant(
            ((parameters.consistency_bits + 7) // 8).to_bytes(4, "little")
        ),
        source_pad_to_byte(alpha_source),
    )
    if commitment_source.bit_length // 8 != len(execution.commitment.encoded):
        raise AssertionError("canonical commitment source length mismatch")
    commitment_start = _publish_source(
        sink, commitment_source, "output.commitment"
    )

    def plain_witness_source(offset: int, length: int) -> BitSource:
        return BitSource(
            length,
            lambda: (
                _wide_plain_form(spool, offset + coordinate)
                for coordinate in range(length)
            ),
        )

    mask_start = _publish_source(
        sink,
        plain_witness_source(0, parameters.mask_bits),
        "output.derived_mask",
    )
    append_start = _publish_source(
        sink,
        plain_witness_source(
            parameters.mask_bits, parameters.appended_signature_bits
        ),
        "output.append_base",
    )

    request_payload = sponge.encode_transcript(
        (message, execution.commitment.encoded)
    )
    request_output = int.from_bytes(
        sponge.evaluate_sponge(
            sponge.REQUEST_BINDING_DOMAIN,
            request_payload,
            sponge.REQUEST_HASH_BYTES,
        ),
        "little",
    )
    request_call = cap.XOFCall(
        "request-binding",
        sponge.REQUEST_BINDING_DOMAIN,
        (message, execution.commitment.encoded),
        sponge.REQUEST_HASH_BITS,
        request_output,
    )
    request = lowerer.lower(
        request_call,
        (
            source_wires(message_start, 256),
            source_wires(commitment_start, commitment_source.bit_length),
        ),
        len(reference_calls),
    )
    sponge_accounting = sponge_accounting.add(request.accounting)
    request_start = request.output_wires[0]
    sink.finish_group()

    trailer = {
        "append_base": [append_start, parameters.appended_signature_bits],
        "commitment": [commitment_start, commitment_source.bit_length],
        "derived_mask": [mask_start, parameters.mask_bits],
        "external_assertions": 0,
        "request_hash": [request_start, sponge.REQUEST_HASH_BITS],
        "rows": sink.rows,
        "wires": sink.wire_count,
    }
    stream_bytes, stream_sha256 = sink.finish(trailer)
    request_hash_bytes = request_output.to_bytes(
        sponge.REQUEST_HASH_BYTES, "little"
    )
    if request_hash_bytes != sponge.hash_request_binding(
        message, execution.commitment.encoded
    ):
        raise AssertionError("request-binding reference mismatch")
    if execution.commitment.derived_mask.bit_length() > parameters.mask_bits:
        raise AssertionError("reference mask width mismatch")
    elapsed = time.perf_counter() - started
    peak_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    summary = ShardTraceSummary(
        parameters,
        stream_bytes,
        stream_sha256,
        sink.wire_count,
        sink.rows,
        sink.nonlinear_rows,
        sink.linear_rows,
        sponge_accounting,
        horner_accounting,
        tuple(sink.groups),
        sponge_accounting.calls,
        execution.commitment.encoded,
        request_hash_bytes,
        spool.bytes,
        spool.sha256,
        elapsed,
        peak_rss,
        False,
        0,
    )
    spool.close()
    if progress is not None:
        progress(
            f"stream complete: {summary.rows} rows, {summary.stream_bytes} bytes"
        )
    return summary


def build_manifest(summary: ShardTraceSummary) -> dict[str, object]:
    parameters = summary.parameters
    return {
        "implementation_version": IMPLEMENTATION_VERSION,
        "profile": {
            "name": PROFILE_NAME,
            "relation_id": PROFILE_RELATION_ID,
            "field": "GF(2^193)",
            "stream_format": STREAM_FORMAT,
            "spool_format": SPOOL_FORMAT,
            "cap_profile_fingerprint": cap.profile_fingerprint(parameters),
            "fixture_parameter_name": parameters.name,
            "explicitly_non_secure_one_tree_shard": True,
            "leaves": parameters.leaf_count,
            "extension_degree": parameters.expanded_extension_degrees()[0],
            "witness_bits": parameters.witness_bits,
            "coefficients": (
                parameters.witness_bits + field.FIELD_DEGREE - 1
            )
            // field.FIELD_DEGREE,
            "consistency_points": parameters.consistency_points,
            "tape_bits": parameters.random_polynomial_bits,
        },
        "trace": {
            "wires": summary.wires,
            "rows": summary.rows,
            "nonlinear_rows": summary.nonlinear_rows,
            "linear_rows": summary.linear_rows,
            "external_assertions": summary.external_assertions,
            "assignment_materialized": summary.assignment_materialized,
            "stream_bytes": summary.stream_bytes,
            "stream_sha256": summary.stream_sha256,
            "sponge_accounting": asdict(summary.sponge_accounting),
            "horner_accounting": asdict(summary.horner_accounting),
            "groups": [asdict(group) for group in summary.groups],
            "xof_calls": summary.xof_calls,
            "spool_bytes": summary.spool_bytes,
            "spool_sha256": summary.spool_sha256,
            "wall_seconds": summary.wall_seconds,
            "peak_rss_kib": summary.peak_rss_kib,
        },
        "frozen_vector": {
            "commitment_bytes": len(summary.commitment_bytes),
            "commitment_sha256": hashlib.sha256(
                summary.commitment_bytes
            ).hexdigest(),
            "request_hash_hex": summary.request_hash_bytes.hex(),
        },
        "implemented": {
            "real_2048_leaf_production_tree_shape": (
                parameters.leaf_count == 1 << 11
            ),
            "full_2048_bit_eleven_coefficient_witness": (
                parameters.witness_bits == 2_048
            ),
            "two_consistency_points": parameters.consistency_points == 2,
            "degree_12_extension_mask_slices": (
                parameters.expanded_extension_degrees() == (12,)
            ),
            "production_width_2450_bit_tapes": (
                parameters.random_polynomial_bits == 2_450
            ),
            "streamed_expanded_row_digest": True,
            "bounded_memory_wire_spool": True,
            "callbacks_or_external_assertions": False,
            "full_assignment_archive_materialized": False,
            "full_18_tree_relation": False,
        },
        "claim_boundary": {
            "production_tree_shard_topology_closed": (
                parameters.leaf_count == 1 << 11
                and summary.external_assertions == 0
            ),
            "production_closed": False,
            "remaining": [
                "materialize or backend-link a complete shard witness assignment",
                "add the 4096-leaf degree-13 shard",
                "compose all 18 production trees",
                "replace the parent archive external assertion",
                "complete fork-specific extraction and security proofs",
                "qualify the post-quantum proof backend and benchmark signatures",
            ],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--fixture", choices=("probe", "production"), default="probe")
    parser.add_argument("--workers", type=int, default=max(1, min(8, os.cpu_count() or 1)))
    args = parser.parse_args()
    parameters = (
        PROBE_PARAMETERS
        if args.fixture == "probe"
        else PRODUCTION_TREE_SHARD_PARAMETERS
    )
    summary = build_streaming_shard(
        parameters,
        workers=args.workers,
        progress=lambda message: print(message, flush=True),
    )
    manifest = build_manifest(summary)
    encoded = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if args.manifest:
        args.manifest.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
