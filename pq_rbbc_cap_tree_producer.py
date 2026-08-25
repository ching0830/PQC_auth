#!/usr/bin/env python3
"""Position-sensitive native CAP tree producers for PQ-RBBC v2.13.

The v2.9 shared global tail consumes four ports from every production tree:
leaf commitments, the plain witness polynomial, the plain consistency tail,
and the extension-field xi masks.  This module materializes the producer side
of exactly that ABI without duplicating H1, H2, commitment serialization, or
request binding.

A producer accepts the shared salt, one tree's roots, and the two global
consistency points.  It constrains the tree-local GGM derivation, leaf
commitments, tape expansion, wide XORs, and Horner evaluation, then publishes
four contiguous bit-constrained output ports whose IDs, widths, and value
digests match the v2.9 tail consumer ports.

The reduced two-tree checkpoint proves the segmentation architecture with
assignment generation, complete replay, and stale-witness probes.  Version
2.13 also exposes a production-segment entry point: callers may provide one
position-sensitive tree polynomial/call schedule, import the two global point
wire ranges without local copies, and allocate local wires after a frozen
relation.  The complete 18-tree replay and the parent join remain separate
fail-closed obligations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterable, Iterator, Mapping, Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_global_tail as tail
import pq_rbbc_cap_shard_assignment as assignment
import pq_rbbc_cap_shard_stream as shard


IMPLEMENTATION_VERSION = "2.13"
RELATION_ID = "pq-rbbc/cap/tree-producer-segment/v1"
STREAM_FORMAT = tail.STREAM_FORMAT
FROZEN_MESSAGE = bytes(32)
FROZEN_REDUCED_ROWS_PER_TREE = 34_148
FROZEN_REDUCED_WIRES_PER_TREE = 23_329
FROZEN_REDUCED_ARCHIVE_BYTES_PER_TREE = 583_353
FROZEN_REDUCED_STREAM_SHA256 = (
    "ff5ad52cd7d39777023b8ded3e4f8fcfd1e840172ac210e59d996232c9613da1",
    "fe0bcd20c92c58406bd86a0251b22ce92fabb781c3c132c7b407b7d9542f5eb7",
)
FROZEN_REDUCED_ASSIGNMENT_SHA256 = (
    "5413f331c706184dc7546c262c8541ee812aec4a1c3a5ba029fdd4f0a9bd6db0",
    "a165562be53216f89137efbc1c6b4d70cb5cb8145232d937f89f2781b29c947c",
)


BitForm = field.LinearForm


@dataclass(frozen=True)
class ProducerPort:
    port_id: str
    direction: str
    phase: str
    wire_start: int
    bit_length: int
    value_sha256: str


@dataclass(frozen=True)
class ProducerSummary:
    parameters: cap.CAPParameters
    tree_index: int
    leaves: int
    extension_degree: int
    stream_bytes: int
    stream_sha256: str
    wires: int
    rows: int
    nonlinear_rows: int
    linear_rows: int
    groups: tuple[tail.BinaryStreamGroup, ...]
    sponge_accounting: shard.SpongeAccounting
    horner_accounting: shard.HornerShardAccounting
    ports: tuple[ProducerPort, ...]
    assignment_materialized: bool
    external_assertions: int
    verification_failures: int
    first_verification_failure: str | None
    wall_seconds: float
    peak_rss_kib: int
    local_wire_start: int = 1
    max_wire_id: int = 0
    imported_point_wires: tuple[int, ...] = ()


@dataclass(frozen=True)
class TreeProducerMaterial:
    """All position-sensitive values needed by one producer-only relation."""

    tree_index: int
    polynomial: cap.TreePolynomial
    point_values: tuple[int, ...]
    p_plain: int
    mhat_plain: int
    xi_masks: tuple[int, ...]
    calls: tuple[cap.XOFCall, ...]


@dataclass(frozen=True)
class ProducerAssignmentResult:
    generated: ProducerSummary
    verified: ProducerSummary
    archive: assignment.AssignmentArchiveMetadata
    tamper_probes: tuple[assignment.TamperProbe, ...]
    generation_seconds: float
    verification_seconds: float


@dataclass(frozen=True)
class PortMatch:
    port_id: str
    producer_tree_index: int
    producer_wire_start: int
    consumer_wire_start: int
    bit_length: int
    value_sha256: str
    exact_value_match: bool
    exact_wire_identity: bool


def _bits(value: int, length: int) -> tuple[int, ...]:
    return tuple((value >> index) & 1 for index in range(length))


def _bits_digest(value: int, length: int) -> str:
    return hashlib.sha256(
        value.to_bytes((length + 7) // 8, "little")
    ).hexdigest()


def _field_tuple_digest(values: Sequence[int]) -> str:
    return hashlib.sha256(
        b"".join(cap.field_bytes(value) for value in values)
    ).hexdigest()


def _tree_calls(
    execution: cap.CAPExecution, tree_index: int
) -> tuple[cap.XOFCall, ...]:
    prefix = f"tree[{tree_index}]."
    calls = tuple(
        call for call in execution.xof_calls if call.label.startswith(prefix)
    )
    if not calls:
        raise ValueError(f"execution has no calls for tree {tree_index}")
    return calls


def material_from_execution(
    parameters: cap.CAPParameters,
    execution: cap.CAPExecution,
    tree_index: int,
    message: bytes = FROZEN_MESSAGE,
) -> TreeProducerMaterial:
    material = tail.derive_tail_material(parameters, execution, message)
    return TreeProducerMaterial(
        tree_index,
        execution.tree_polynomials[tree_index],
        material.points,
        material.p_plain[tree_index],
        material.mhat_plain[tree_index],
        material.xi_masks[tree_index],
        _tree_calls(execution, tree_index),
    )


def material_from_local_tree(
    parameters: cap.CAPParameters,
    tree_index: int,
    polynomial: cap.TreePolynomial,
    point_values: Sequence[int],
    calls: Sequence[cap.XOFCall],
) -> TreeProducerMaterial:
    """Derive producer outputs without constructing the other 17 trees."""

    if len(point_values) != parameters.consistency_points:
        raise ValueError("producer point count mismatch")
    if any(point == 0 for point in point_values):
        raise ValueError("producer consistency points must be nonzero")
    if len(set(point_values)) != len(point_values):
        raise ValueError("producer consistency points must be distinct")
    leaves = parameters.expanded_leaf_counts()[tree_index]
    extension_degree = parameters.expanded_extension_degrees()[tree_index]
    if (polynomial.leaves, polynomial.extension_degree) != (
        leaves,
        extension_degree,
    ):
        raise ValueError("producer polynomial shape mismatch")
    prefix = f"tree[{tree_index}]."
    local_calls = tuple(calls)
    if not local_calls or any(
        not call.label.startswith(prefix) for call in local_calls
    ):
        raise ValueError("producer call schedule is not tree-local")
    witness_mask = (1 << parameters.witness_bits) - 1
    consistency_mask = (1 << parameters.consistency_bits) - 1
    mhat_shift = (
        parameters.witness_bits + (parameters.degree - 1) * parameters.rho
    )
    p_plain = polynomial.plain & witness_mask
    mhat_plain = (polynomial.plain >> mhat_shift) & consistency_mask
    hashed = cap._linear_hash_masks(
        polynomial.masks[: parameters.witness_bits],
        parameters.witness_bits,
        extension_degree,
        tuple(point_values),
    )
    mhat_masks = polynomial.masks[
        mhat_shift : mhat_shift + parameters.consistency_bits
    ]
    xi_masks = tuple(left ^ right for left, right in zip(hashed, mhat_masks))
    return TreeProducerMaterial(
        tree_index,
        polynomial,
        tuple(point_values),
        p_plain,
        mhat_plain,
        xi_masks,
        local_calls,
    )


def _flatten_xi(values: Sequence[int], extension_degree: int) -> int:
    return sum(
        bit << (coordinate * extension_degree + extension_bit)
        for coordinate, value in enumerate(values)
        for extension_bit, bit in enumerate(_bits(value, extension_degree))
    )


def capture_labels(
    parameters: cap.CAPParameters,
    execution: cap.CAPExecution,
    tree_index: int,
) -> tuple[str, ...]:
    return capture_material_labels(
        parameters,
        material_from_execution(parameters, execution, tree_index),
    )


def capture_material_labels(
    parameters: cap.CAPParameters,
    material: TreeProducerMaterial,
) -> tuple[str, ...]:
    tree_index = material.tree_index
    poly = material.polynomial
    leaves = poly.leaves
    first_tape_call = leaves - 1
    prefix = f"output.tree[{tree_index}]"
    return (
        (
            f"xof[0].tree[{tree_index}].derive[2,1]"
            f".payload[{(len(shard.sponge.TRANSCRIPT_MAGIC) + 2 + 8) * 8}]"
            ".source"
        ),
        (
            f"xof[{first_tape_call}].tree[{tree_index}].leaf[1].tape"
            ".digest.lane[0].pack"
        ),
        f"{prefix}.leaf-commitments[0].link",
        f"{prefix}.p-plain[0].link",
        f"{prefix}.mhat-plain[0].link",
        f"{prefix}.xi-masks[0].link",
    )


def build_tree_producer(
    parameters: cap.CAPParameters,
    randomness: cap.CAPRandomness,
    execution: cap.CAPExecution | None,
    tree_index: int,
    message: bytes = FROZEN_MESSAGE,
    *,
    producer_material: TreeProducerMaterial | None = None,
    external_point_starts: Sequence[int] | None = None,
    local_wire_start: int = 1,
    workers: int = 1,
    assignment_writer: shard.AssignmentWriter | None = None,
    verification_assignment: Mapping[int, int] | None = None,
    capture_rows: Iterable[str] = (),
    captured_rows_output: dict[str, field.RankOneRow] | None = None,
    progress: Callable[[str], None] | None = None,
) -> ProducerSummary:
    """Build one actual profile-position tree producer.

    The execution and randomness normally belong to the complete multi-tree
    profile.  A production segment may instead pass ``producer_material`` and
    import the already-constrained global point wires directly.
    """

    if not 0 <= tree_index < parameters.tree_count:
        raise ValueError("tree index outside profile")
    if len(randomness.roots) != parameters.tree_count:
        raise ValueError("randomness tree count mismatch")
    if len(message) != 32:
        raise ValueError("request message must be 32 bytes")
    if parameters.consistency_points <= 0:
        raise ValueError("tree producer requires consistency points")
    if producer_material is None:
        if execution is None:
            raise ValueError("tree producer requires execution or local material")
        if len(execution.tree_polynomials) != parameters.tree_count:
            raise ValueError("execution tree count mismatch")
        if execution.commitment.parameters_fingerprint != cap.profile_fingerprint(
            parameters
        ):
            raise ValueError("execution profile mismatch")
        producer_material = material_from_execution(
            parameters, execution, tree_index, message
        )
    elif producer_material.tree_index != tree_index:
        raise ValueError("producer material tree index mismatch")
    if external_point_starts is not None:
        if len(external_point_starts) != parameters.consistency_points:
            raise ValueError("external point wire count mismatch")
        if any(start <= 0 for start in external_point_starts):
            raise ValueError("external point wires must be positive")
    if local_wire_start <= 0:
        raise ValueError("local producer wire start must be positive")

    started = time.perf_counter()
    poly = producer_material.polynomial
    leaves = poly.leaves
    extension_degree = poly.extension_degree
    point_values = producer_material.point_values
    calls = producer_material.calls
    cursor = shard.CallCursor(calls)
    witness_pool = (
        None
        if assignment_writer is None
        else shard.OrderedSpongeWitnessPool(calls, max(1, workers))
    )
    header = {
        "cap_profile_fingerprint": cap.profile_fingerprint(parameters),
        "field": "GF(2^193)",
        "format": STREAM_FORMAT,
        "relation_id": RELATION_ID,
        "tree_index": tree_index,
        "leaves": leaves,
        "extension_degree": extension_degree,
    }
    if local_wire_start != 1 or external_point_starts is not None:
        header.update(
            {
                "local_wire_start": local_wire_start,
                "imported_point_wires": list(external_point_starts or ()),
            }
        )
    sink = tail.BinaryRowSink(
        header,
        initial_wire=local_wire_start,
        assignment_writer=assignment_writer,
        verification_assignment=verification_assignment,
        capture_labels=capture_rows,
    )
    lowerer = shard.StreamingSpongeLowerer(sink, witness_pool)
    sponge_accounting = shard.SpongeAccounting()
    ports: list[ProducerPort] = []
    spool: shard.WireSpoolReader | None = None

    try:
        sink.start_group("producer-inputs")
        salt_0 = shard._allocate_input_bits(
            sink, field.FIELD_DEGREE, "input.salt[0]", randomness.salt[0]
        )
        salt_1 = shard._allocate_input_bits(
            sink, field.FIELD_DEGREE, "input.salt[1]", randomness.salt[1]
        )
        ports.append(
            ProducerPort(
                "shared.salt",
                "input",
                "tree-pre",
                salt_0,
                2 * field.FIELD_DEGREE,
                _field_tuple_digest(randomness.salt),
            )
        )
        roots = randomness.roots[tree_index]
        if len(roots) != 2:
            raise ValueError("tree producer currently requires two roots")
        root_0 = shard._allocate_input_bits(
            sink,
            field.FIELD_DEGREE,
            f"input.tree[{tree_index}].root[0]",
            roots[0],
        )
        root_1 = shard._allocate_input_bits(
            sink,
            field.FIELD_DEGREE,
            f"input.tree[{tree_index}].root[1]",
            roots[1],
        )
        ports.append(
            ProducerPort(
                f"tree[{tree_index}].roots",
                "input",
                "tree-pre",
                root_0,
                2 * field.FIELD_DEGREE,
                _field_tuple_digest(roots),
            )
        )
        point_starts = (
            tuple(external_point_starts)
            if external_point_starts is not None
            else tuple(
                shard._allocate_input_bits(
                    sink,
                    field.FIELD_DEGREE,
                    f"input.consistency-point[{point_index}]",
                    point_value,
                )
                for point_index, point_value in enumerate(point_values)
            )
        )
        if any(
            right != left + field.FIELD_DEGREE
            for left, right in zip(point_starts, point_starts[1:])
        ):
            raise ValueError("producer point wire ranges must be contiguous")
        ports.append(
            ProducerPort(
                "global.consistency-points",
                "input",
                "tree-post",
                point_starts[0],
                parameters.consistency_points * field.FIELD_DEGREE,
                _field_tuple_digest(point_values),
            )
        )
        point_validation_rows = (
            0
            if external_point_starts is not None
            else shard._point_validation(
                sink,
                point_starts,
                point_values,
                f"tree[{tree_index}].consistency.validate",
            )
        )
        sink.finish_group()

        salt_source = shard.source_pad_to_byte(
            shard.source_concat(
                shard.source_wires(salt_0, field.FIELD_DEGREE),
                shard.source_wires(salt_1, field.FIELD_DEGREE),
            )
        )
        nodes = [(root_0, roots[0]), (root_1, roots[1])]
        level = 2
        sink.start_group("tree-pre-ggm-derive")
        while len(nodes) < leaves:
            children: list[tuple[int, int]] = []
            for node_index, (parent_start, _) in enumerate(nodes, start=1):
                label = f"tree[{tree_index}].derive[{level},{node_index}]"
                call_index, call = cursor.take(label)
                lowered = lowerer.lower(
                    call,
                    (
                        salt_source,
                        shard.source_field_bytes(parent_start),
                        shard.source_constant(
                            cap._meta(tree_index, level, node_index)
                        ),
                    ),
                    call_index,
                )
                sponge_accounting = sponge_accounting.add(lowered.accounting)
                children.extend(
                    (
                        (
                            lowered.output_wires[0],
                            call.output & field.FIELD_MASK,
                        ),
                        (
                            lowered.output_wires[field.FIELD_DEGREE],
                            call.output >> field.FIELD_DEGREE,
                        ),
                    )
                )
            nodes = children
            level += 1
        sink.finish_group()

        witness_bits = parameters.witness_bits
        mhat_shift = witness_bits + (parameters.degree - 1) * parameters.rho
        selected_positions = tuple(range(witness_bits)) + tuple(
            range(mhat_shift, mhat_shift + parameters.consistency_bits)
        )
        spool_writer = shard.WireSpool(len(selected_positions))
        commitment_sources: list[shard.BitSource] = []
        tape_values: list[int] = []
        sink.start_group("tree-pre-leaf-commit-and-tape")
        for leaf_index, (seed_start, _) in enumerate(nodes, start=1):
            metadata = shard.source_constant(
                cap._meta(tree_index, 0, leaf_index)
            )
            commit_index, commit_call = cursor.take(
                f"tree[{tree_index}].leaf[{leaf_index}].commit"
            )
            commit = lowerer.lower(
                commit_call,
                (salt_source, shard.source_field_bytes(seed_start), metadata),
                commit_index,
            )
            sponge_accounting = sponge_accounting.add(commit.accounting)
            commitment_sources.append(
                shard.source_wires(commit.output_wires[0], 2 * field.FIELD_DEGREE)
            )
            tape_index, tape_call = cursor.take(
                f"tree[{tree_index}].leaf[{leaf_index}].tape"
            )
            tape = lowerer.lower(
                tape_call,
                (shard.source_field_bytes(seed_start), metadata),
                tape_index,
            )
            sponge_accounting = sponge_accounting.add(tape.accounting)
            spool_writer.append(
                tuple(tape.output_wires[index] for index in selected_positions)
            )
            tape_values.append(tape_call.output)
            if progress is not None and (
                leaf_index % 128 == 0 or leaf_index == leaves
            ):
                progress(
                    f"tree {tree_index} producer leaf XOFs: "
                    f"{leaf_index}/{leaves}"
                )
        sink.finish_group()
        if cursor.index != len(calls):
            raise AssertionError("unconsumed tree-local XOF calls")
        spool = spool_writer.open_reader()
        if spool.records != leaves:
            raise AssertionError("tree producer spool leaf count mismatch")

        def plain_source(offset: int, length: int) -> shard.BitSource:
            return shard.BitSource(
                length,
                lambda: (
                    shard._wide_plain_form(spool, offset + coordinate)
                    for coordinate in range(length)
                ),
            )

        sink.start_group("tree-pre-output-ports")
        commitment_values = tuple(
            bit
            for left, right in poly.commitments
            for value in (left, right)
            for bit in _bits(value, field.FIELD_DEGREE)
        )
        commitment_start = shard._publish_source(
            sink,
            shard.source_concat(*commitment_sources),
            commitment_values,
            f"output.tree[{tree_index}].leaf-commitments",
        )
        commitment_encoded = b"".join(
            cap.field_bytes(value)
            for pair in poly.commitments
            for value in pair
        )
        ports.append(
            ProducerPort(
                f"tree[{tree_index}].leaf-commitments",
                "output",
                "tree-pre",
                commitment_start,
                len(commitment_values),
                hashlib.sha256(commitment_encoded).hexdigest(),
            )
        )
        p_value = producer_material.p_plain
        p_start = shard._publish_source(
            sink,
            plain_source(0, witness_bits),
            _bits(p_value, witness_bits),
            f"output.tree[{tree_index}].p-plain",
        )
        ports.append(
            ProducerPort(
                f"tree[{tree_index}].p-plain",
                "output",
                "tree-pre",
                p_start,
                witness_bits,
                _bits_digest(p_value, witness_bits),
            )
        )
        mhat_value = producer_material.mhat_plain
        mhat_start = shard._publish_source(
            sink,
            plain_source(witness_bits, parameters.consistency_bits),
            _bits(mhat_value, parameters.consistency_bits),
            f"output.tree[{tree_index}].mhat-plain",
        )
        ports.append(
            ProducerPort(
                f"tree[{tree_index}].mhat-plain",
                "output",
                "tree-pre",
                mhat_start,
                parameters.consistency_bits,
                _bits_digest(mhat_value, parameters.consistency_bits),
            )
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
        sink.start_group("tree-post-horner")
        mask_accumulators: list[list[int | None]] = [
            [None] * parameters.consistency_points
            for _ in range(extension_degree)
        ]
        mask_values: list[list[int | None]] = [
            [None] * parameters.consistency_points
            for _ in range(extension_degree)
        ]
        multiplication_rows = 0
        aggregate_rows = 0
        for leaf in range(leaves):
            record = spool.record(leaf)
            witness_ids = record[:witness_bits]
            outputs, output_values = shard._horner_leaf(
                sink,
                witness_ids,
                tape_values[leaf] & ((1 << witness_bits) - 1),
                point_starts,
                point_values,
                leaf + 1,
            )
            coefficient_count = (
                len(witness_ids) + field.FIELD_DEGREE - 1
            ) // field.FIELD_DEGREE
            multiplication_rows += len(outputs) * (coefficient_count - 1)
            inverse = cap.gf2m_inv(leaf + 1, extension_degree)
            for point_index, (item, item_value) in enumerate(
                zip(outputs, output_values)
            ):
                for extension_bit in range(extension_degree):
                    if (inverse >> extension_bit) & 1:
                        (
                            mask_accumulators[extension_bit][point_index],
                            mask_values[extension_bit][point_index],
                        ) = shard._aggregate_form(
                            sink,
                            mask_accumulators[extension_bit][point_index],
                            mask_values[extension_bit][point_index],
                            item,
                            item_value,
                            (
                                f"tree[{tree_index}].aggregate.mask"
                                f"[{extension_bit}].leaf[{leaf + 1}]"
                                f".point[{point_index}]"
                            ),
                        )
                        aggregate_rows += 1
        if any(item is None for row in mask_accumulators for item in row):
            raise AssertionError("tree producer mask accumulator missing")
        if any(item is None for row in mask_values for item in row):
            raise AssertionError("tree producer mask value missing")
        mask_output_starts = tuple(
            tuple(
                shard._decompose_field(
                    sink,
                    int(mask_accumulators[extension_bit][point]),
                    int(mask_values[extension_bit][point]),
                    (
                        f"tree[{tree_index}].consistency.mask[{extension_bit}]"
                        f".point[{point}].output"
                    ),
                )
                for point in range(parameters.consistency_points)
            )
            for extension_bit in range(extension_degree)
        )
        sink.finish_group()

        tail_offset = witness_bits

        def mask_tail_form(extension_bit: int, coordinate: int) -> BitForm:
            return shard._wide_mask_form(
                spool,
                tail_offset + coordinate,
                selected_by_extension[extension_bit],
            )

        def xi_forms() -> Iterator[BitForm]:
            for coordinate in range(parameters.consistency_bits):
                point = coordinate // field.FIELD_DEGREE
                bit = coordinate % field.FIELD_DEGREE
                for extension_bit in range(extension_degree):
                    yield BitForm.wire(
                        mask_output_starts[extension_bit][point] + bit
                    ).add(mask_tail_form(extension_bit, coordinate))

        xi_values = producer_material.xi_masks
        xi_flat = _flatten_xi(xi_values, extension_degree)
        xi_width = parameters.consistency_bits * extension_degree
        sink.start_group("tree-post-output-port")
        xi_start = shard._publish_source(
            sink,
            shard.BitSource(xi_width, xi_forms),
            _bits(xi_flat, xi_width),
            f"output.tree[{tree_index}].xi-masks",
        )
        ports.append(
            ProducerPort(
                f"tree[{tree_index}].xi-masks",
                "output",
                "tree-post",
                xi_start,
                xi_width,
                _bits_digest(xi_flat, xi_width),
            )
        )
        sink.finish_group()

        output_bitness_rows = (
            extension_degree
            * parameters.consistency_points
            * field.FIELD_DEGREE
        )
        output_pack_rows = extension_degree * parameters.consistency_points
        horner_accounting = shard.HornerShardAccounting(
            leaves,
            multiplication_rows,
            aggregate_rows,
            point_validation_rows,
            output_bitness_rows,
            output_pack_rows,
        )
        trailer = {
            "external_assertions": 0,
            "output_ports": [
                {
                    "port_id": port.port_id,
                    "wire_start": port.wire_start,
                    "bit_length": port.bit_length,
                }
                for port in ports
                if port.direction == "output"
            ],
            "rows": sink.rows,
            "tree_index": tree_index,
            "wires": sink.allocated_wires,
        }
        if local_wire_start != 1 or external_point_starts is not None:
            trailer.update(
                {
                    "local_wire_start": local_wire_start,
                    "max_wire_id": sink.wire_count,
                    "imported_point_wires": list(external_point_starts or ()),
                }
            )
        stream_bytes, stream_sha256 = sink.finish(trailer)
        if captured_rows_output is not None:
            captured_rows_output.update(sink.captured_rows)
        return ProducerSummary(
            parameters,
            tree_index,
            leaves,
            extension_degree,
            stream_bytes,
            stream_sha256,
            sink.allocated_wires,
            sink.rows,
            sink.nonlinear_rows,
            sink.linear_rows,
            tuple(sink.groups),
            sponge_accounting,
            horner_accounting,
            tuple(ports),
            assignment_writer is not None,
            0,
            sink.verification_failures,
            sink.first_verification_failure,
            time.perf_counter() - started,
            resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            local_wire_start,
            sink.wire_count,
            tuple(external_point_starts or ()),
        )
    finally:
        if witness_pool is not None:
            witness_pool.close()
        if spool is not None:
            spool.close()


def build_in_memory_tree_producer(
    parameters: cap.CAPParameters,
    randomness: cap.CAPRandomness,
    execution: cap.CAPExecution,
    tree_index: int,
) -> tuple[
    ProducerSummary,
    ProducerSummary,
    tuple[assignment.TamperProbe, ...],
]:
    labels = capture_labels(parameters, execution, tree_index)
    captured: dict[str, field.RankOneRow] = {}
    values = tail.MemoryAssignment()
    generated = build_tree_producer(
        parameters,
        randomness,
        execution,
        tree_index,
        assignment_writer=values,
        capture_rows=labels,
        captured_rows_output=captured,
    )
    verified = build_tree_producer(
        parameters,
        randomness,
        execution,
        tree_index,
        verification_assignment=values,
    )
    probes = assignment.run_tamper_probes(values, captured, labels)
    return generated, verified, probes


def build_assignment_backed_tree_producer(
    archive_path: Path,
    parameters: cap.CAPParameters,
    randomness: cap.CAPRandomness,
    execution: cap.CAPExecution,
    tree_index: int,
    *,
    workers: int = 1,
    replace: bool = False,
    progress: Callable[[str], None] | None = None,
) -> ProducerAssignmentResult:
    labels = capture_labels(parameters, execution, tree_index)
    captured: dict[str, field.RankOneRow] = {}
    writer = assignment.AssignmentArchiveWriter(archive_path, replace=replace)
    generation_started = time.perf_counter()
    try:
        generated = build_tree_producer(
            parameters,
            randomness,
            execution,
            tree_index,
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
        verified = build_tree_producer(
            parameters,
            randomness,
            execution,
            tree_index,
            verification_assignment=values,
        )
        if verified.verification_failures:
            raise AssertionError(
                "tree producer replay failed first at "
                f"{verified.first_verification_failure}"
            )
        if (
            verified.rows != generated.rows
            or verified.wires != generated.wires
            or verified.stream_sha256 != generated.stream_sha256
        ):
            raise AssertionError("tree producer replay topology mismatch")
        probes = assignment.run_tamper_probes(values, captured, labels)
    if not all(probe.rejected for probe in probes):
        raise AssertionError("a tree producer stale-witness probe was accepted")
    return ProducerAssignmentResult(
        generated,
        verified,
        archive,
        probes,
        generation_seconds,
        time.perf_counter() - verification_started,
    )


def match_tail_ports(
    producers: Sequence[ProducerSummary],
    tail_summary: tail.GlobalTailSummary,
) -> tuple[PortMatch, ...]:
    consumer = {port.port_id: port for port in tail_summary.ports}
    matches: list[PortMatch] = []
    seen: set[str] = set()
    for producer in producers:
        for port in producer.ports:
            if port.direction != "output":
                continue
            if port.port_id in seen:
                raise ValueError(f"duplicate producer port {port.port_id}")
            seen.add(port.port_id)
            target = consumer.get(port.port_id)
            if target is None:
                raise ValueError(f"tail consumer port missing: {port.port_id}")
            exact_value = (
                port.bit_length == target.bit_length
                and port.value_sha256 == target.value_sha256
            )
            matches.append(
                PortMatch(
                    port.port_id,
                    producer.tree_index,
                    port.wire_start,
                    target.consumer_wire_start,
                    port.bit_length,
                    port.value_sha256,
                    exact_value,
                    False,
                )
            )
    expected = {
        port.port_id
        for port in tail_summary.ports
        if port.port_id.startswith("tree[")
    }
    if seen != expected:
        missing = sorted(expected - seen)
        extra = sorted(seen - expected)
        raise ValueError(f"producer/tail port set mismatch: {missing=}, {extra=}")
    return tuple(matches)


def build_reduced_checkpoint() -> tuple[
    tuple[ProducerSummary, ...],
    tail.GlobalTailSummary,
    tuple[PortMatch, ...],
]:
    parameters = cap.REDUCED_TEST_PARAMETERS
    randomness = cap.deterministic_randomness(parameters)
    execution = cap.execute_cap_commit(parameters, randomness)
    producers = tuple(
        build_in_memory_tree_producer(
            parameters, randomness, execution, tree_index
        )[0]
        for tree_index in range(parameters.tree_count)
    )
    tail_summary = tail.build_in_memory_global_tail(
        parameters, randomness, execution
    )[0]
    matches = match_tail_ports(producers, tail_summary)
    return producers, tail_summary, matches


def build_manifest(
    results: Sequence[ProducerAssignmentResult],
    tail_summary: tail.GlobalTailSummary,
    matches: Sequence[PortMatch],
) -> dict[str, object]:
    if not results:
        raise ValueError("producer checkpoint requires at least one result")
    parameters = results[0].generated.parameters
    reduced = parameters == cap.REDUCED_TEST_PARAMETERS
    all_replay_clean = all(
        result.verified.verification_failures == 0 for result in results
    )
    all_probes_rejected = all(
        probe.rejected
        for result in results
        for probe in result.tamper_probes
    )
    all_values_match = bool(matches) and all(
        item.exact_value_match for item in matches
    )
    frozen_reduced_matches = reduced and all(
        result.generated.tree_index < len(FROZEN_REDUCED_STREAM_SHA256)
        and result.generated.rows == FROZEN_REDUCED_ROWS_PER_TREE
        and result.generated.wires == FROZEN_REDUCED_WIRES_PER_TREE
        and result.generated.stream_sha256
        == FROZEN_REDUCED_STREAM_SHA256[result.generated.tree_index]
        and result.archive.archive_bytes
        == FROZEN_REDUCED_ARCHIVE_BYTES_PER_TREE
        and result.archive.archive_sha256
        == FROZEN_REDUCED_ASSIGNMENT_SHA256[result.generated.tree_index]
        for result in results
    )
    return {
        "implementation_version": IMPLEMENTATION_VERSION,
        "profile": {
            "relation_id": RELATION_ID,
            "stream_format": STREAM_FORMAT,
            "assignment_format": assignment.ASSIGNMENT_FORMAT,
            "cap_profile_fingerprint": cap.profile_fingerprint(parameters),
            "tree_count": parameters.tree_count,
            "reduced_test_profile": reduced,
        },
        "producer_segments": [
            {
                "tree_index": result.generated.tree_index,
                "leaves": result.generated.leaves,
                "extension_degree": result.generated.extension_degree,
                "trace": {
                    "rows": result.generated.rows,
                    "wires": result.generated.wires,
                    "nonlinear_rows": result.generated.nonlinear_rows,
                    "linear_rows": result.generated.linear_rows,
                    "stream_bytes": result.generated.stream_bytes,
                    "stream_sha256": result.generated.stream_sha256,
                    "external_assertions": result.generated.external_assertions,
                    "verification_failures": result.verified.verification_failures,
                    "groups": [
                        asdict(group) for group in result.generated.groups
                    ],
                    "sponge_accounting": asdict(
                        result.generated.sponge_accounting
                    ),
                    "horner_accounting": asdict(
                        result.generated.horner_accounting
                    ),
                },
                "ports": [asdict(port) for port in result.generated.ports],
                "assignment_archive": asdict(result.archive),
                "stale_witness_probes": [
                    asdict(probe) for probe in result.tamper_probes
                ],
                "generation_seconds": result.generation_seconds,
                "verification_seconds": result.verification_seconds,
            }
            for result in results
        ],
        "tail_consumer": {
            "relation_id": tail.RELATION_ID,
            "stream_sha256": tail_summary.stream_sha256,
            "rows": tail_summary.rows,
            "wires": tail_summary.wires,
        },
        "port_matches": [asdict(item) for item in matches],
        "claim_boundary": {
            "reduced_tree_producer_segments_native_closed": (
                reduced
                and len(results) == parameters.tree_count
                and frozen_reduced_matches
                and all_replay_clean
                and all_probes_rejected
            ),
            "producer_to_tail_port_values_match": all_values_match,
            "producer_output_ports_are_native_bit_constrained": True,
            "global_points_are_explicit_producer_inputs": True,
            "production_tree_producer_segments_materialized": False,
            "point_wire_identity_to_global_tail_closed": False,
            "cross_segment_wire_identity_closed": False,
            "complete_18_tree_assignment_replayed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    parameters = cap.REDUCED_TEST_PARAMETERS
    randomness = cap.deterministic_randomness(parameters)
    execution = cap.execute_cap_commit(parameters, randomness)
    args.output_directory.mkdir(parents=True, exist_ok=True)
    results: list[ProducerAssignmentResult] = []
    for tree_index in range(parameters.tree_count):
        result = build_assignment_backed_tree_producer(
            args.output_directory
            / f"pq_rbbc_tree_producer_reduced_tree_{tree_index}_v2_10.f193assign",
            parameters,
            randomness,
            execution,
            tree_index,
            workers=args.workers,
            replace=args.replace,
            progress=lambda message: print(message, flush=True),
        )
        results.append(result)
    tail_summary = tail.build_in_memory_global_tail(
        parameters, randomness, execution
    )[0]
    matches = match_tail_ports(
        tuple(result.generated for result in results), tail_summary
    )
    manifest = build_manifest(results, tail_summary, matches)
    manifest_path = (
        args.output_directory
        / "pq_rbbc_tree_producer_reduced_manifest_v2_10.json"
    )
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "manifest": str(manifest_path),
                "port_matches": len(matches),
                "producer_segments": len(results),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
