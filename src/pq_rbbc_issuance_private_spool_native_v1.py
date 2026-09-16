"""Bounded INSECURE-TEST-ONLY tree emitter with explicit private-spool handoff.

Mechanically derived from the unchanged bounded multi-tree native emitter.
Only spool storage/capture and the yielded post-stage input contract differ.
Native rows and stream encoding remain exact. Still a live single-caller
coroutine, NOT a full-session restart or durable-resume implementation.
"""
from __future__ import annotations
from collections.abc import Generator

import pq_rbbc_cap_tree_producer as legacy_tree
import pq_rbbc_issuance_bounded_multitree_native_v1 as predecessor
import pq_rbbc_issuance_private_spool_codec_v1 as codec

def _iter_tree_spool_native_insecure_test_only(
    parameters: legacy_tree.cap.CAPParameters,
    randomness: legacy_tree.cap.CAPRandomness,
    execution: legacy_tree.cap.CAPExecution | None,
    tree_index: int,
    message: bytes = legacy_tree.FROZEN_MESSAGE,
    *,
    sink_factory,
    spool_context,
    producer_material: legacy_tree.TreeProducerMaterial | None = None,
    external_point_starts: legacy_tree.Sequence[int] | None = None,
    local_wire_start: int = 1,
    workers: int = 1,
    assignment_writer: legacy_tree.shard.AssignmentWriter | None = None,
    verification_assignment: legacy_tree.Mapping[int, int] | None = None,
    capture_rows: legacy_tree.Iterable[str] = (),
    captured_rows_output: dict[str, legacy_tree.field.RankOneRow] | None = None,
    progress: legacy_tree.Callable[[str], None] | None = None,
) -> Generator[tuple, tuple, legacy_tree.ProducerSummary]:
    """Private bounded coroutine; no production or durable resume API."""
    predecessor._require_bounded(parameters)
    if type(spool_context) is not codec.Context or spool_context.tree_index != tree_index or spool_context.pre_start != local_wire_start:
        raise codec.SpoolError("tree spool context mismatch before output")
    predecessor._require_bounded_execution(execution)
    if producer_material is not None:
        raise ValueError("external producer material is not a bounded fixture input")

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
        if execution.commitment.parameters_fingerprint != legacy_tree.cap.profile_fingerprint(
            parameters
        ):
            raise ValueError("execution profile mismatch")
        producer_material = legacy_tree.material_from_execution(
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

    started = legacy_tree.time.perf_counter()
    poly = producer_material.polynomial
    leaves = poly.leaves
    extension_degree = poly.extension_degree
    point_values = producer_material.point_values
    calls = producer_material.calls
    cursor = legacy_tree.shard.CallCursor(calls)
    witness_pool = (
        None
        if assignment_writer is None
        else legacy_tree.shard.OrderedSpongeWitnessPool(calls, max(1, workers))
    )
    header = {
        "cap_profile_fingerprint": legacy_tree.cap.profile_fingerprint(parameters),
        "field": "GF(2^193)",
        "format": legacy_tree.STREAM_FORMAT,
        "relation_id": legacy_tree.RELATION_ID,
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
    sink = sink_factory(
        header,
        initial_wire=local_wire_start,
        assignment_writer=assignment_writer,
        verification_assignment=verification_assignment,
        capture_labels=capture_rows,
    )
    lowerer = legacy_tree.shard.StreamingSpongeLowerer(sink, witness_pool)
    sponge_accounting = legacy_tree.shard.SpongeAccounting()
    ports: list[legacy_tree.ProducerPort] = []
    spool: legacy_tree.shard.WireSpoolReader | None = None

    try:
        sink.start_group("producer-inputs")
        salt_0 = legacy_tree.shard._allocate_input_bits(
            sink, legacy_tree.field.FIELD_DEGREE, "input.salt[0]", randomness.salt[0]
        )
        salt_1 = legacy_tree.shard._allocate_input_bits(
            sink, legacy_tree.field.FIELD_DEGREE, "input.salt[1]", randomness.salt[1]
        )
        ports.append(
            legacy_tree.ProducerPort(
                "shared.salt",
                "input",
                "tree-pre",
                salt_0,
                2 * legacy_tree.field.FIELD_DEGREE,
                legacy_tree._field_tuple_digest(randomness.salt),
            )
        )
        roots = randomness.roots[tree_index]
        if len(roots) != 2:
            raise ValueError("tree producer currently requires two roots")
        root_0 = legacy_tree.shard._allocate_input_bits(
            sink,
            legacy_tree.field.FIELD_DEGREE,
            f"input.tree[{tree_index}].root[0]",
            roots[0],
        )
        root_1 = legacy_tree.shard._allocate_input_bits(
            sink,
            legacy_tree.field.FIELD_DEGREE,
            f"input.tree[{tree_index}].root[1]",
            roots[1],
        )
        ports.append(
            legacy_tree.ProducerPort(
                f"tree[{tree_index}].roots",
                "input",
                "tree-pre",
                root_0,
                2 * legacy_tree.field.FIELD_DEGREE,
                legacy_tree._field_tuple_digest(roots),
            )
        )
        point_starts = (
            tuple(external_point_starts)
            if external_point_starts is not None
            else tuple(
                legacy_tree.shard._allocate_input_bits(
                    sink,
                    legacy_tree.field.FIELD_DEGREE,
                    f"input.consistency-point[{point_index}]",
                    point_value,
                )
                for point_index, point_value in enumerate(point_values)
            )
        )
        if any(
            right != left + legacy_tree.field.FIELD_DEGREE
            for left, right in zip(point_starts, point_starts[1:])
        ):
            raise ValueError("producer point wire ranges must be contiguous")
        ports.append(
            legacy_tree.ProducerPort(
                "global.consistency-points",
                "input",
                "tree-post",
                point_starts[0],
                parameters.consistency_points * legacy_tree.field.FIELD_DEGREE,
                legacy_tree._field_tuple_digest(point_values),
            )
        )
        point_validation_rows = (
            0
            if external_point_starts is not None
            else legacy_tree.shard._point_validation(
                sink,
                point_starts,
                point_values,
                f"tree[{tree_index}].consistency.validate",
            )
        )
        sink.finish_group()

        salt_source = legacy_tree.shard.source_pad_to_byte(
            legacy_tree.shard.source_concat(
                legacy_tree.shard.source_wires(salt_0, legacy_tree.field.FIELD_DEGREE),
                legacy_tree.shard.source_wires(salt_1, legacy_tree.field.FIELD_DEGREE),
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
                        legacy_tree.shard.source_field_bytes(parent_start),
                        legacy_tree.shard.source_constant(
                            legacy_tree.cap._meta(tree_index, level, node_index)
                        ),
                    ),
                    call_index,
                )
                sponge_accounting = sponge_accounting.add(lowered.accounting)
                children.extend(
                    (
                        (
                            lowered.output_wires[0],
                            call.output & legacy_tree.field.FIELD_MASK,
                        ),
                        (
                            lowered.output_wires[legacy_tree.field.FIELD_DEGREE],
                            call.output >> legacy_tree.field.FIELD_DEGREE,
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
        spool_writer = codec.BoundedMemoryWireSpoolInsecureTestOnly(len(selected_positions))
        commitment_sources: list[legacy_tree.shard.BitSource] = []
        tape_values: list[int] = []
        sink.start_group("tree-pre-leaf-commit-and-tape")
        for leaf_index, (seed_start, _) in enumerate(nodes, start=1):
            metadata = legacy_tree.shard.source_constant(
                legacy_tree.cap._meta(tree_index, 0, leaf_index)
            )
            commit_index, commit_call = cursor.take(
                f"tree[{tree_index}].leaf[{leaf_index}].commit"
            )
            commit = lowerer.lower(
                commit_call,
                (salt_source, legacy_tree.shard.source_field_bytes(seed_start), metadata),
                commit_index,
            )
            sponge_accounting = sponge_accounting.add(commit.accounting)
            commitment_sources.append(
                legacy_tree.shard.source_wires(commit.output_wires[0], 2 * legacy_tree.field.FIELD_DEGREE)
            )
            tape_index, tape_call = cursor.take(
                f"tree[{tree_index}].leaf[{leaf_index}].tape"
            )
            tape = lowerer.lower(
                tape_call,
                (legacy_tree.shard.source_field_bytes(seed_start), metadata),
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

        def plain_source(offset: int, length: int) -> legacy_tree.shard.BitSource:
            return legacy_tree.shard.BitSource(
                length,
                lambda: (
                    legacy_tree.shard._wide_plain_form(spool, offset + coordinate)
                    for coordinate in range(length)
                ),
            )

        sink.start_group("tree-pre-output-ports")
        commitment_values = tuple(
            bit
            for left, right in poly.commitments
            for value in (left, right)
            for bit in legacy_tree._bits(value, legacy_tree.field.FIELD_DEGREE)
        )
        commitment_start = legacy_tree.shard._publish_source(
            sink,
            legacy_tree.shard.source_concat(*commitment_sources),
            commitment_values,
            f"output.tree[{tree_index}].leaf-commitments",
        )
        commitment_encoded = b"".join(
            legacy_tree.cap.field_bytes(value)
            for pair in poly.commitments
            for value in pair
        )
        ports.append(
            legacy_tree.ProducerPort(
                f"tree[{tree_index}].leaf-commitments",
                "output",
                "tree-pre",
                commitment_start,
                len(commitment_values),
                legacy_tree.hashlib.sha256(commitment_encoded).hexdigest(),
            )
        )
        p_value = producer_material.p_plain
        p_start = legacy_tree.shard._publish_source(
            sink,
            plain_source(0, witness_bits),
            legacy_tree._bits(p_value, witness_bits),
            f"output.tree[{tree_index}].p-plain",
        )
        ports.append(
            legacy_tree.ProducerPort(
                f"tree[{tree_index}].p-plain",
                "output",
                "tree-pre",
                p_start,
                witness_bits,
                legacy_tree._bits_digest(p_value, witness_bits),
            )
        )
        mhat_value = producer_material.mhat_plain
        mhat_start = legacy_tree.shard._publish_source(
            sink,
            plain_source(witness_bits, parameters.consistency_bits),
            legacy_tree._bits(mhat_value, parameters.consistency_bits),
            f"output.tree[{tree_index}].mhat-plain",
        )
        ports.append(
            legacy_tree.ProducerPort(
                f"tree[{tree_index}].mhat-plain",
                "output",
                "tree-pre",
                mhat_start,
                parameters.consistency_bits,
                legacy_tree._bits_digest(mhat_value, parameters.consistency_bits),
            )
        )
        sink.finish_group()

        if spool_context.pre_end != sink.next_wire:
            raise codec.SpoolError("spool pre-end differs from actual emitter cursor")
        captured_raw = codec.encode_insecure_test_only(
            spool_context, spool, tape_values, producer_material.xi_masks)
        captured_sha256 = codec.sha256(captured_raw)
        spool.close()
        spool = None
        del spool_writer, tape_values, producer_material
        point_starts, point_values, captured_snapshot = yield (
            "tree-pre", tuple(ports), sink.next_wire, captured_raw
        )
        del captured_raw
        # Post-stage private inputs come ONLY from the accepted raw snapshot.
        # No frame/pickle/hash-state restoration and no pathname reopen.
        spool = codec.decode_snapshot_insecure_test_only(
            captured_snapshot, expected_bytes=codec.SPOOL_BYTES,
            expected_sha256=captured_sha256, context=spool_context)
        tape_values = spool.tape_values
        xi_values = spool.xi_masks
        selected_by_extension = tuple(
            tuple(
                leaf_index - 1
                for leaf_index in range(1, leaves + 1)
                if (
                    legacy_tree.cap.gf2m_inv(leaf_index, extension_degree) >> extension_bit
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
            outputs, output_values = legacy_tree.shard._horner_leaf(
                sink,
                witness_ids,
                tape_values[leaf] & ((1 << witness_bits) - 1),
                point_starts,
                point_values,
                leaf + 1,
            )
            coefficient_count = (
                len(witness_ids) + legacy_tree.field.FIELD_DEGREE - 1
            ) // legacy_tree.field.FIELD_DEGREE
            multiplication_rows += len(outputs) * (coefficient_count - 1)
            inverse = legacy_tree.cap.gf2m_inv(leaf + 1, extension_degree)
            for point_index, (item, item_value) in enumerate(
                zip(outputs, output_values)
            ):
                for extension_bit in range(extension_degree):
                    if (inverse >> extension_bit) & 1:
                        (
                            mask_accumulators[extension_bit][point_index],
                            mask_values[extension_bit][point_index],
                        ) = legacy_tree.shard._aggregate_form(
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
                legacy_tree.shard._decompose_field(
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

        def mask_tail_form(extension_bit: int, coordinate: int) -> legacy_tree.BitForm:
            return legacy_tree.shard._wide_mask_form(
                spool,
                tail_offset + coordinate,
                selected_by_extension[extension_bit],
            )

        def xi_forms() -> legacy_tree.Iterator[legacy_tree.BitForm]:
            for coordinate in range(parameters.consistency_bits):
                point = coordinate // legacy_tree.field.FIELD_DEGREE
                bit = coordinate % legacy_tree.field.FIELD_DEGREE
                for extension_bit in range(extension_degree):
                    yield legacy_tree.BitForm.wire(
                        mask_output_starts[extension_bit][point] + bit
                    ).add(mask_tail_form(extension_bit, coordinate))

        xi_flat = legacy_tree._flatten_xi(xi_values, extension_degree)
        xi_width = parameters.consistency_bits * extension_degree
        sink.start_group("tree-post-output-port")
        xi_start = legacy_tree.shard._publish_source(
            sink,
            legacy_tree.shard.BitSource(xi_width, xi_forms),
            legacy_tree._bits(xi_flat, xi_width),
            f"output.tree[{tree_index}].xi-masks",
        )
        ports.append(
            legacy_tree.ProducerPort(
                f"tree[{tree_index}].xi-masks",
                "output",
                "tree-post",
                xi_start,
                xi_width,
                legacy_tree._bits_digest(xi_flat, xi_width),
            )
        )
        sink.finish_group()

        output_bitness_rows = (
            extension_degree
            * parameters.consistency_points
            * legacy_tree.field.FIELD_DEGREE
        )
        output_pack_rows = extension_degree * parameters.consistency_points
        horner_accounting = legacy_tree.shard.HornerShardAccounting(
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
        return legacy_tree.ProducerSummary(
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
            legacy_tree.time.perf_counter() - started,
            legacy_tree.resource.getrusage(legacy_tree.resource.RUSAGE_SELF).ru_maxrss,
            local_wire_start,
            sink.wire_count,
            tuple(external_point_starts or ()),
        )
    finally:
        if witness_pool is not None:
            witness_pool.close()
        if spool is not None:
            spool.close()
