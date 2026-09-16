"""Bounded-only suspended native emitters, mechanically derived at authoring.

Provenance: unchanged legacy tree/global-tail algorithms; only sink injection
and explicit yield boundaries are added. No dynamic AST/exec at runtime.
These are PRIVATE adapter internals, not production entrypoints or durable
independently resumable producers. Public gate enforces the 4+4-leaf fixture.
"""
from __future__ import annotations
import pq_rbbc_cap_tree_producer as legacy_tree
import pq_rbbc_cap_global_tail as legacy_tail
from dataclasses import replace
from collections.abc import Generator

PARAMETERS = replace(
    legacy_tree.cap.PRODUCTION_PARAMETERS,
    name="PQ-RBBC issuance 4+4-leaf INSECURE-TEST-ONLY native adapter v1",
    security_bits=0, secure_profile=False,
    tree_specs=(legacy_tree.cap.TreeSpec(2, 4),),
)


def _require_bounded(parameters):
    if (type(parameters) is not legacy_tree.cap.CAPParameters
            or legacy_tree.cap.profile_fingerprint(parameters)
            != legacy_tree.cap.profile_fingerprint(PARAMETERS)):
        raise ValueError("only the exact 4+4-leaf INSECURE-TEST-ONLY profile is permitted")


def _require_bounded_execution(execution):
    if (type(execution) is not legacy_tree.cap.CAPExecution
            or len(execution.tree_polynomials) != 2
            or len(execution.xof_calls) != 23
            or any(p.leaves != 4 or p.extension_degree != 3 or len(p.commitments) != 4
                   for p in execution.tree_polynomials)):
        raise ValueError("only the bounded two-tree execution is permitted")

def _iter_tree_native_insecure_test_only(
    parameters: legacy_tree.cap.CAPParameters,
    randomness: legacy_tree.cap.CAPRandomness,
    execution: legacy_tree.cap.CAPExecution | None,
    tree_index: int,
    message: bytes = legacy_tree.FROZEN_MESSAGE,
    *,
    sink_factory,
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
    _require_bounded(parameters)
    _require_bounded_execution(execution)
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
        spool_writer = legacy_tree.shard.WireSpool(len(selected_positions))
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

        point_starts, point_values = yield (
            "tree-pre", tuple(ports), sink.next_wire
        )
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

        xi_values = producer_material.xi_masks
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

def _iter_tail_native_insecure_test_only(
    parameters: legacy_tail.cap.CAPParameters,
    randomness: legacy_tail.cap.CAPRandomness,
    execution: legacy_tail.cap.CAPExecution,
    message: bytes = legacy_tail.FROZEN_REQUEST_MESSAGE,
    *,
    sink_factory,
    workers: int = 1,
    assignment_writer: legacy_tail.shard.AssignmentWriter | None = None,
    verification_assignment: legacy_tail.Mapping[int, int] | None = None,
    capture_rows: legacy_tail.Iterable[str] = (),
    captured_rows_output: dict[str, legacy_tail.field.RankOneRow] | None = None,
    split_contract_output: list[legacy_tail.TailSplitContract] | None = None,
    progress: legacy_tail.Callable[[str], None] | None = None,
) -> Generator[tuple, None, legacy_tail.GlobalTailSummary]:
    _require_bounded(parameters)
    _require_bounded_execution(execution)
    started = legacy_tail.time.perf_counter()
    material = legacy_tail.derive_tail_material(parameters, execution, message)
    header = {
        "cap_profile_fingerprint": legacy_tail.cap.profile_fingerprint(parameters),
        "field": "GF(2^193)",
        "format": legacy_tail.STREAM_FORMAT,
        "relation_id": legacy_tail.RELATION_ID,
        "tree_count": parameters.tree_count,
    }
    sink = sink_factory(
        header,
        assignment_writer=assignment_writer,
        verification_assignment=verification_assignment,
        capture_labels=capture_rows,
    )
    all_calls = material.global_calls + (material.request_call,)
    witness_pool = (
        None
        if assignment_writer is None
        else legacy_tail.shard.OrderedSpongeWitnessPool(all_calls, max(1, workers))
    )
    lowerer = legacy_tail.shard.StreamingSpongeLowerer(sink, witness_pool)
    accounting = legacy_tail.shard.SpongeAccounting()
    ports: list[legacy_tail.TailPort] = []
    phase_boundary_ports: list[legacy_tail.TailPort] = []

    sink.start_group("global-input-ports")
    salt_starts = (
        legacy_tail._allocate_bits(sink, randomness.salt[0], legacy_tail.field.FIELD_DEGREE, "input.salt[0]"),
        legacy_tail._allocate_bits(sink, randomness.salt[1], legacy_tail.field.FIELD_DEGREE, "input.salt[1]"),
    )
    message_start = legacy_tail._allocate_bits(
        sink, int.from_bytes(message, "little"), len(message) * 8, "input.message"
    )
    ports.append(
        legacy_tail.TailPort(
            "shared.salt",
            "shared-inputs",
            salt_starts[0],
            2 * legacy_tail.field.FIELD_DEGREE,
            legacy_tail.hashlib.sha256(
                legacy_tail.cap.field_bytes(randomness.salt[0])
                + legacy_tail.cap.field_bytes(randomness.salt[1])
            ).hexdigest(),
        )
    )
    ports.append(
        legacy_tail.TailPort(
            "shared.message",
            "shared-inputs",
            message_start,
            len(message) * 8,
            legacy_tail.hashlib.sha256(message).hexdigest(),
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
            left_start = legacy_tail._allocate_bits(
                sink,
                left,
                legacy_tail.field.FIELD_DEGREE,
                f"input.tree[{tree_index}].commitment[{leaf_index}].left",
            )
            right_start = legacy_tail._allocate_bits(
                sink,
                right,
                legacy_tail.field.FIELD_DEGREE,
                f"input.tree[{tree_index}].commitment[{leaf_index}].right",
            )
            tree_commitments.append((left_start, right_start))
            commitment_bytes.extend(legacy_tail.cap.field_bytes(left))
            commitment_bytes.extend(legacy_tail.cap.field_bytes(right))
        commitment_ports.append(tuple(tree_commitments))
        ports.append(
            legacy_tail.TailPort(
                f"tree[{tree_index}].leaf-commitments",
                f"tree-pre[{tree_index}]",
                first_commitment_start,
                len(poly.commitments) * 2 * legacy_tail.field.FIELD_DEGREE,
                legacy_tail.hashlib.sha256(commitment_bytes).hexdigest(),
            )
        )
        p_start = legacy_tail._allocate_bits(
            sink,
            p_value,
            parameters.witness_bits,
            f"input.tree[{tree_index}].p-plain",
        )
        mhat_start = legacy_tail._allocate_bits(
            sink,
            mhat_value,
            parameters.consistency_bits,
            f"input.tree[{tree_index}].mhat-plain",
        )
        p_starts.append(p_start)
        mhat_starts.append(mhat_start)
        ports.append(
            legacy_tail.TailPort(
                f"tree[{tree_index}].p-plain",
                f"tree-pre[{tree_index}]",
                p_start,
                parameters.witness_bits,
                legacy_tail._bits_digest(p_value, parameters.witness_bits),
            )
        )
        ports.append(
            legacy_tail.TailPort(
                f"tree[{tree_index}].mhat-plain",
                f"tree-pre[{tree_index}]",
                mhat_start,
                parameters.consistency_bits,
                legacy_tail._bits_digest(mhat_value, parameters.consistency_bits),
            )
        )
        extension_degree = poly.extension_degree
        xi_flat = sum(
            bit << (coordinate * extension_degree + extension_bit)
            for coordinate, value in enumerate(xi_values)
            for extension_bit, bit in enumerate(legacy_tail._bits(value, extension_degree))
        )
        xi_width = parameters.consistency_bits * extension_degree
        xi_start = legacy_tail._allocate_bits(
            sink,
            xi_flat,
            xi_width,
            f"input.tree[{tree_index}].xi-masks",
        )
        xi_starts.append(xi_start)
        ports.append(
            legacy_tail.TailPort(
                f"tree[{tree_index}].xi-masks",
                f"tree-post[{tree_index}]",
                xi_start,
                xi_width,
                legacy_tail._bits_digest(xi_flat, xi_width),
            )
        )
        if progress is not None:
            progress(
                f"input ports tree {tree_index + 1}/{parameters.tree_count}: "
                f"{poly.leaves:,} commitments"
            )
    sink.finish_group()
    input_prelude_row_end = sink.rows
    input_prelude_wire_end = sink.next_wire
    yield ("tail-inputs", tuple(ports), sink.next_wire)

    delta_p_sources = tuple(
        legacy_tail._xor_source(p_starts[0], p_starts[index], parameters.witness_bits)
        for index in range(1, parameters.tree_count)
    )
    delta_mhat_sources = tuple(
        legacy_tail._xor_source(
            mhat_starts[0], mhat_starts[index], parameters.consistency_bits
        )
        for index in range(1, parameters.tree_count)
    )
    correction_source = legacy_tail.shard.source_concat(
        legacy_tail.shard.source_constant(
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
                legacy_tail.shard.source_pad_to_byte(p_source),
                legacy_tail.shard.source_pad_to_byte(mhat_source),
            )
        ),
    )
    profile_source = legacy_tail.shard.source_constant(
        bytes.fromhex(legacy_tail.cap.profile_fingerprint(parameters))
    )
    tree_sources = tuple(
        legacy_tail._tree_component_source(
            index,
            poly.leaves,
            poly.extension_degree,
            commitment_ports[index],
        )
        for index, poly in enumerate(execution.tree_polynomials)
    )

    phase_a_row_start = sink.rows
    phase_a_wire_start = sink.next_wire
    sink.start_group("h1-corrections-and-points")
    h1 = lowerer.lower(
        material.global_calls[0],
        (profile_source, *tree_sources, correction_source),
        0,
    )
    accounting = accounting.add(h1.accounting)
    h1_start = h1.output_wires[0]
    if h1.output_wires != tuple(
        range(h1_start, h1_start + material.global_calls[0].output_bits)
    ):
        raise AssertionError("H1 output wires are not contiguous")
    phase_boundary_ports.append(
        legacy_tail.TailPort(
            "global.phase-a.h1",
            "global-tail-phase-a",
            h1_start,
            material.global_calls[0].output_bits,
            legacy_tail._bits_digest(
                material.global_calls[0].output,
                material.global_calls[0].output_bits,
            ),
        )
    )
    point_call = lowerer.lower(
        material.global_calls[1],
        (legacy_tail.shard.source_hash_bytes(h1_start), profile_source),
        1,
    )
    accounting = accounting.add(point_call.accounting)
    point_starts = tuple(
        point_call.output_wires[index * legacy_tail.field.FIELD_DEGREE]
        for index in range(parameters.consistency_points)
    )
    if point_call.output_wires != tuple(
        range(
            point_starts[0],
            point_starts[0]
            + parameters.consistency_points * legacy_tail.field.FIELD_DEGREE,
        )
    ):
        raise AssertionError("consistency-point output wires are not contiguous")
    packed_points = sum(
        value << (index * legacy_tail.field.FIELD_DEGREE)
        for index, value in enumerate(material.points)
    )
    phase_boundary_ports.append(
        legacy_tail.TailPort(
            "global.phase-a.consistency-points",
            "global-tail-phase-a",
            point_starts[0],
            parameters.consistency_points * legacy_tail.field.FIELD_DEGREE,
            legacy_tail._bits_digest(
                packed_points,
                parameters.consistency_points * legacy_tail.field.FIELD_DEGREE,
            ),
        )
    )
    legacy_tail.shard._point_validation(
        sink, point_starts, material.points, "consistency.validate"
    )
    sink.finish_group()
    phase_a_row_end = sink.rows
    phase_a_wire_end = sink.next_wire
    yield ("global-a", tuple(phase_boundary_ports), sink.next_wire)

    phase_b_row_start = sink.rows
    phase_b_wire_start = sink.next_wire
    sink.start_group("shared-alpha")
    alpha_forms, alpha_values = legacy_tail.shard._horner_leaf(
        sink,
        tuple(p_starts[0] + bit for bit in range(parameters.witness_bits)),
        material.p_plain[0],
        point_starts,
        material.points,
        0,
    )
    alpha_output_starts = tuple(
        legacy_tail._decompose_form(
            sink,
            form,
            value,
            f"alpha.output[{index}]",
        )
        for index, (form, value) in enumerate(zip(alpha_forms, alpha_values))
    )

    def alpha_bits() -> legacy_tail.Iterator[legacy_tail.BitForm]:
        for coordinate in range(parameters.consistency_bits):
            point = coordinate // legacy_tail.field.FIELD_DEGREE
            bit = coordinate % legacy_tail.field.FIELD_DEGREE
            yield legacy_tail.BitForm.wire(alpha_output_starts[point] + bit).add(
                legacy_tail.BitForm.wire(mhat_starts[0] + coordinate)
            )

    alpha_source = legacy_tail.shard.BitSource(parameters.consistency_bits, alpha_bits)
    sink.finish_group()

    xi_sources: list[legacy_tail.shard.BitSource] = []
    for tree_index, poly in enumerate(execution.tree_polynomials):
        xi_sources.append(
            legacy_tail.shard.source_concat(
                legacy_tail.shard.source_constant(
                    parameters.consistency_bits.to_bytes(4, "little")
                    + poly.extension_degree.to_bytes(2, "little")
                ),
                legacy_tail.shard.source_pad_to_byte(alpha_source),
                legacy_tail.shard.source_pad_to_byte(
                    legacy_tail.shard.source_wires(
                        xi_starts[tree_index],
                        parameters.consistency_bits * poly.extension_degree,
                    )
                ),
            )
        )

    sink.start_group("h2-commitment-and-request")
    h2 = lowerer.lower(
        material.global_calls[2],
        (legacy_tail.shard.source_hash_bytes(h1_start), *xi_sources),
        2,
    )
    accounting = accounting.add(h2.accounting)
    h2_start = h2.output_wires[0]
    correction_bytes = (parameters.consistency_bits + 7) // 8
    correction_bytes += (parameters.tree_count - 1) * (
        (parameters.witness_bits + 7) // 8
        + (parameters.consistency_bits + 7) // 8
    )
    commitment_source = legacy_tail.shard.source_concat(
        legacy_tail.shard.source_constant(legacy_tail.cap.COMMITMENT_MAGIC + (1).to_bytes(2, "little")),
        profile_source,
        legacy_tail.shard.source_field_bytes(salt_starts[0]),
        legacy_tail.shard.source_field_bytes(salt_starts[1]),
        legacy_tail.shard.source_hash_bytes(h2_start),
        legacy_tail.shard.source_constant(correction_bytes.to_bytes(4, "little")),
        legacy_tail.shard.source_pad_to_byte(alpha_source),
        *tuple(
            item
            for p_source, mhat_source in zip(
                delta_p_sources, delta_mhat_sources
            )
            for item in (
                legacy_tail.shard.source_pad_to_byte(p_source),
                legacy_tail.shard.source_pad_to_byte(mhat_source),
            )
        ),
    )
    if commitment_source.bit_length != len(execution.commitment.encoded) * 8:
        raise AssertionError("canonical production commitment width mismatch")
    commitment_start = legacy_tail.shard._publish_source(
        sink,
        commitment_source,
        tuple(
            (byte >> bit) & 1
            for byte in execution.commitment.encoded
            for bit in range(8)
        ),
        "output.commitment",
    )
    mask_source = legacy_tail.shard.source_wires(p_starts[0], parameters.mask_bits)
    mask_start = legacy_tail.shard._publish_source(
        sink,
        mask_source,
        legacy_tail._bits(execution.commitment.derived_mask, parameters.mask_bits),
        "output.derived-mask",
    )
    append_source = legacy_tail.shard.source_wires(
        p_starts[0] + parameters.mask_bits,
        parameters.appended_signature_bits,
    )
    append_start = legacy_tail.shard._publish_source(
        sink,
        append_source,
        legacy_tail._bits(execution.commitment.append_base, parameters.appended_signature_bits),
        "output.append-base",
    )
    request = lowerer.lower(
        material.request_call,
        (
            legacy_tail.shard.source_wires(message_start, len(message) * 8),
            legacy_tail.shard.source_wires(
                commitment_start, len(execution.commitment.encoded) * 8
            ),
        ),
        3,
    )
    accounting = accounting.add(request.accounting)
    request_start = request.output_wires[0]
    sink.finish_group()
    phase_b_row_end = sink.rows
    phase_b_wire_end = sink.next_wire
    if witness_pool is not None:
        witness_pool.close()

    phase_boundary_ports.extend(
        (
            legacy_tail.TailPort(
                "global.phase-b.commitment",
                "global-tail-phase-b",
                commitment_start,
                len(execution.commitment.encoded) * 8,
                legacy_tail.hashlib.sha256(execution.commitment.encoded).hexdigest(),
            ),
            legacy_tail.TailPort(
                "global.phase-b.derived-mask",
                "global-tail-phase-b",
                mask_start,
                parameters.mask_bits,
                legacy_tail._bits_digest(execution.commitment.derived_mask, parameters.mask_bits),
            ),
            legacy_tail.TailPort(
                "global.phase-b.append-base",
                "global-tail-phase-b",
                append_start,
                parameters.appended_signature_bits,
                legacy_tail._bits_digest(
                    execution.commitment.append_base,
                    parameters.appended_signature_bits,
                ),
            ),
            legacy_tail.TailPort(
                "global.phase-b.request-hash",
                "global-tail-phase-b",
                request_start,
                legacy_tail.sponge.REQUEST_HASH_BITS,
                legacy_tail._bits_digest(material.request_call.output, legacy_tail.sponge.REQUEST_HASH_BITS),
            ),
        )
    )
    if split_contract_output is not None:
        phase_a_inputs = tuple(
            port.port_id
            for port in ports
            if port.port_id.endswith(
                (".leaf-commitments", ".p-plain", ".mhat-plain")
            )
        )
        phase_b_inputs = (
            "shared.salt",
            "shared.message",
            *tuple(
                port.port_id
                for port in ports
                if port.port_id.endswith((".p-plain", ".mhat-plain", ".xi-masks"))
            ),
            "global.phase-a.h1",
            "global.phase-a.consistency-points",
        )
        split_contract_output.clear()
        split_contract_output.append(
            legacy_tail.TailSplitContract(
                legacy_tail.RELATION_ID,
                0,
                input_prelude_row_end,
                1,
                input_prelude_wire_end,
                (
                    legacy_tail.TailPhase(
                        "global-tail-phase-a",
                        phase_a_row_start,
                        phase_a_row_end,
                        phase_a_wire_start,
                        phase_a_wire_end,
                        phase_a_inputs,
                        (
                            "global.phase-a.h1",
                            "global.phase-a.consistency-points",
                        ),
                    ),
                    legacy_tail.TailPhase(
                        "global-tail-phase-b",
                        phase_b_row_start,
                        phase_b_row_end,
                        phase_b_wire_start,
                        phase_b_wire_end,
                        phase_b_inputs,
                        (
                            "global.phase-b.commitment",
                            "global.phase-b.derived-mask",
                            "global.phase-b.append-base",
                            "global.phase-b.request-hash",
                        ),
                    ),
                ),
                tuple(phase_boundary_ports),
                True,
            )
        )

    trailer = {
        "append_base": [append_start, parameters.appended_signature_bits],
        "commitment": [commitment_start, len(execution.commitment.encoded) * 8],
        "derived_mask": [mask_start, parameters.mask_bits],
        "external_assertions": 0,
        "request_hash": [request_start, legacy_tail.sponge.REQUEST_HASH_BITS],
        "rows": sink.rows,
        "wires": sink.wire_count,
    }
    stream_bytes, stream_sha256 = sink.finish(trailer)
    if captured_rows_output is not None:
        captured_rows_output.update(sink.captured_rows)
    request_hash = material.request_call.output.to_bytes(
        legacy_tail.sponge.REQUEST_HASH_BYTES, "little"
    )
    if request_hash != legacy_tail.sponge.hash_request_binding(
        message, execution.commitment.encoded
    ):
        raise AssertionError("request hash output mismatch")
    return legacy_tail.GlobalTailSummary(
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
        legacy_tail.time.perf_counter() - started,
        legacy_tail.resource.getrusage(legacy_tail.resource.RUSAGE_SELF).ru_maxrss,
    )
