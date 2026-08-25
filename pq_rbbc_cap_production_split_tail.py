#!/usr/bin/env python3
"""Archive-driven production Phase-A/Phase-B observer for PQ-RBBC.

The v2.9 production assignment was already generated and fully replayed, but
the exact Phase-A/Phase-B ranges were not recorded at that checkpoint.  This
v2.12 observer reuses those frozen bytes.  It builds a witness-independent
topology fixture with the production shapes, replays the unchanged canonical
row generator against the v2.9 assignment, records the split contract, and
tests the exact H1, two consistency-point, commitment, and request-hash wires.

The topology fixture supplies only payload lengths and public shape constants;
its values are not evidence.  All satisfiability and mutation evidence comes
from the frozen 1,004,865,028-byte assignment.  Tree-producer relocation and
the complete 18-tree join remain separate fail-closed obligations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import resource
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Mapping, Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_anemoi_sponge as sponge
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_global_tail as tail
import pq_rbbc_cap_shard_assignment as assignment
import pq_rbbc_cap_shard_stream as shard


IMPLEMENTATION_VERSION = "2.12"
CONTRACT_ID = "pq-rbbc/cap/production-global-tail-phase-contract/v1"
SOURCE_RELATION_ID = tail.RELATION_ID
FROZEN_SOURCE_MANIFEST_SHA256 = (
    "a8667bdfcfa64e3f2498ea4fea806257fdd031f091c21445f7a9c1f27bd705fa"
)
FROZEN_ASSIGNMENT_BODY_SHA256 = (
    "358266d106a1ac01cacb7c19c9bff1a7da2acceeb580a1d54462f31986cba925"
)
FROZEN_ASSIGNMENT_BODY_BYTES = 1_004_864_900
FROZEN_BOUNDARY_PROBES = 5

# Frozen after archive-driven replay against the v2.9 production assignment.
FROZEN_INPUT_ROWS = 15_939_162
FROZEN_PHASE_A_ROWS = 40_436_279
FROZEN_PHASE_B_ROWS = 431_270
FROZEN_INPUT_WIRES = 15_939_162
FROZEN_PHASE_A_WIRES = 24_006_899
FROZEN_PHASE_B_WIRES = 248_535
FROZEN_H1_WIRE_START = 39_943_623
FROZEN_POINT_WIRE_STARTS = (39_945_673, 39_945_866)
FROZEN_COMMITMENT_WIRE_START = 40_084_506
FROZEN_REQUEST_HASH_WIRE_START = 40_194_018


@dataclass(frozen=True)
class SpongeCallLayout:
    label: str
    payload_bytes: int
    payload_bits: int
    absorbed_blocks: int
    output_elements: int
    wires: int
    rows: int
    output_wire_offset: int


@dataclass(frozen=True)
class ProductionTailLayout:
    input_rows: int
    input_wires: int
    phase_a_rows: int
    phase_a_wires: int
    phase_b_rows: int
    phase_b_wires: int
    phase_a_row_start: int
    phase_a_row_end: int
    phase_a_wire_start: int
    phase_a_wire_end: int
    phase_b_row_start: int
    phase_b_row_end: int
    phase_b_wire_start: int
    phase_b_wire_end: int
    h1_wire_start: int
    point_wire_starts: tuple[int, ...]
    point_inverse_wires: tuple[int, ...]
    point_difference_inverse_wire: int
    h2_call_wire_start: int
    h2_payload_wire_start: int
    h2_h1_payload_bit: int
    h2_wire_start: int
    commitment_wire_start: int
    derived_mask_wire_start: int
    append_base_wire_start: int
    request_call_wire_start: int
    request_hash_wire_start: int
    request_last_state_wire: int
    h1: SpongeCallLayout
    points: SpongeCallLayout
    h2: SpongeCallLayout
    request: SpongeCallLayout

    @property
    def rows(self) -> int:
        return self.phase_b_row_end

    @property
    def wires(self) -> int:
        return self.phase_b_wire_end - 1


@dataclass(frozen=True)
class BoundaryWireProbe:
    label: str
    port_id: str
    wire: int
    honest_row_satisfied: bool
    stale_row_satisfied: bool
    rejected: bool


@dataclass(frozen=True)
class ProductionSplitResult:
    summary: tail.GlobalTailSummary
    contract: tail.TailSplitContract
    archive: assignment.AssignmentArchiveMetadata
    source_manifest_sha256: str
    archive_sha256: str
    layout: ProductionTailLayout
    boundary_probes: tuple[BoundaryWireProbe, ...]
    commitment_bytes: bytes
    request_hash_bytes: bytes
    replay_seconds: float


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(8 * 1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _payload_bytes(field_lengths: Sequence[int]) -> int:
    return len(sponge.TRANSCRIPT_MAGIC) + 2 + sum(
        8 + length for length in field_lengths
    )


def _sponge_layout(
    label: str,
    domain: bytes,
    field_lengths: Sequence[int],
    output_bits: int,
) -> SpongeCallLayout:
    if output_bits > sponge.RATE_BITS:
        raise ValueError("v2.12 layout calculator expects one squeeze block")
    payload_bytes = _payload_bytes(field_lengths)
    payload_bits = payload_bytes * 8
    header_bytes = len(sponge.FRAME_MAGIC) + 2 + len(domain) + 8
    absorbed_blocks = math.ceil(
        (header_bytes * 8 + payload_bits + 2) / sponge.RATE_BITS
    )
    output_elements = math.ceil(output_bits / field.FIELD_DEGREE)
    permutation_wires = len(
        field.build_native_trace(
            (0,) * field.STATE_ELEMENTS,
            field.derive_parameters(),
        ).assignment
    )
    if permutation_wires != 352:
        raise AssertionError("native permutation assignment width changed")
    block_wires = sponge.RATE_ELEMENTS + permutation_wires
    block_rows = (
        sponge.RATE_ELEMENTS + field.TOTAL_ROWS + field.STATE_ELEMENTS
    )
    output_wire_offset = payload_bits + absorbed_blocks * block_wires
    wires = output_wire_offset + output_elements * field.FIELD_DEGREE
    rows = (
        2 * payload_bits
        + absorbed_blocks * block_rows
        + output_elements * (field.FIELD_DEGREE + 1)
    )
    return SpongeCallLayout(
        label,
        payload_bytes,
        payload_bits,
        absorbed_blocks,
        output_elements,
        wires,
        rows,
        output_wire_offset,
    )


def build_production_layout() -> ProductionTailLayout:
    parameters = cap.PRODUCTION_PARAMETERS
    leaf_counts = parameters.expanded_leaf_counts()
    degrees = parameters.expanded_extension_degrees()
    profile_bytes = len(bytes.fromhex(cap.profile_fingerprint(parameters)))
    witness_bytes = math.ceil(parameters.witness_bits / 8)
    consistency_bytes = math.ceil(parameters.consistency_bits / 8)
    h1_lengths = (
        profile_bytes,
        *(8 + 2 * leaves * field.FIELD_ELEMENT_BYTES for leaves in leaf_counts),
        10
        + (parameters.tree_count - 1)
        * (witness_bytes + consistency_bytes),
    )
    point_lengths = (cap.HASH_BYTES, profile_bytes)
    h2_lengths = (
        cap.HASH_BYTES,
        *(
            6
            + consistency_bytes
            + math.ceil(parameters.consistency_bits * degree / 8)
            for degree in degrees
        ),
    )
    commitment_bytes = cap.commitment_bytes(parameters)
    request_lengths = (32, commitment_bytes)
    h1 = _sponge_layout("h1", cap.DOMAIN_H1, h1_lengths, cap.HASH_BITS)
    points = _sponge_layout(
        "consistency-points",
        cap.DOMAIN_CONSISTENCY_POINTS,
        point_lengths,
        parameters.consistency_bits,
    )
    h2 = _sponge_layout("h2", cap.DOMAIN_H2, h2_lengths, cap.HASH_BITS)
    request = _sponge_layout(
        "request-binding",
        sponge.REQUEST_BINDING_DOMAIN,
        request_lengths,
        sponge.REQUEST_HASH_BITS,
    )

    input_wires = 2 * field.FIELD_DEGREE + 32 * 8
    input_wires += sum(
        2 * leaves * field.FIELD_DEGREE
        + parameters.witness_bits
        + parameters.consistency_bits
        + parameters.consistency_bits * degree
        for leaves, degree in zip(leaf_counts, degrees)
    )
    point_validation_wires = parameters.consistency_points + math.comb(
        parameters.consistency_points, 2
    )
    phase_a_wires = h1.wires + points.wires + point_validation_wires
    phase_a_rows = h1.rows + points.rows + point_validation_wires

    coefficient_count = math.ceil(parameters.witness_bits / field.FIELD_DEGREE)
    alpha_multiplications = parameters.consistency_points * (
        coefficient_count - 1
    )
    alpha_wires = (
        alpha_multiplications
        + parameters.consistency_points * field.FIELD_DEGREE
    )
    alpha_rows = alpha_multiplications + parameters.consistency_points * (
        field.FIELD_DEGREE + 1
    )
    published_bits = (
        commitment_bytes * 8
        + parameters.mask_bits
        + parameters.appended_signature_bits
    )
    phase_b_wires = alpha_wires + h2.wires + published_bits + request.wires
    phase_b_rows = alpha_rows + h2.rows + 2 * published_bits + request.rows

    phase_a_row_start = input_wires
    phase_a_row_end = phase_a_row_start + phase_a_rows
    phase_b_row_start = phase_a_row_end
    phase_b_row_end = phase_b_row_start + phase_b_rows
    phase_a_wire_start = 1 + input_wires
    phase_a_wire_end = phase_a_wire_start + phase_a_wires
    phase_b_wire_start = phase_a_wire_end
    phase_b_wire_end = phase_b_wire_start + phase_b_wires

    h1_wire_start = phase_a_wire_start + h1.output_wire_offset
    point_call_wire_start = phase_a_wire_start + h1.wires
    point_wire_start = point_call_wire_start + points.output_wire_offset
    point_wire_starts = tuple(
        point_wire_start + index * field.FIELD_DEGREE
        for index in range(parameters.consistency_points)
    )
    validation_wire_start = point_call_wire_start + points.wires
    point_inverse_wires = tuple(
        validation_wire_start + index
        for index in range(parameters.consistency_points)
    )
    difference_inverse_wire = (
        validation_wire_start + parameters.consistency_points
    )

    h2_call_wire_start = phase_b_wire_start + alpha_wires
    h2_wire_start = h2_call_wire_start + h2.output_wire_offset
    commitment_wire_start = h2_call_wire_start + h2.wires
    derived_mask_wire_start = commitment_wire_start + commitment_bytes * 8
    append_base_wire_start = derived_mask_wire_start + parameters.mask_bits
    request_call_wire_start = (
        append_base_wire_start + parameters.appended_signature_bits
    )
    request_hash_wire_start = request_call_wire_start + request.output_wire_offset
    last_permutation_base = (
        request_call_wire_start
        + request.payload_bits
        + (request.absorbed_blocks - 1) * (sponge.RATE_ELEMENTS + 352)
        + sponge.RATE_ELEMENTS
    )
    template = field.build_native_trace(
        (0,) * field.STATE_ELEMENTS,
        field.derive_parameters(),
    )
    request_last_state_wire = last_permutation_base + template.output_wires[0] - 1
    return ProductionTailLayout(
        input_wires,
        input_wires,
        phase_a_rows,
        phase_a_wires,
        phase_b_rows,
        phase_b_wires,
        phase_a_row_start,
        phase_a_row_end,
        phase_a_wire_start,
        phase_a_wire_end,
        phase_b_row_start,
        phase_b_row_end,
        phase_b_wire_start,
        phase_b_wire_end,
        h1_wire_start,
        point_wire_starts,
        point_inverse_wires,
        difference_inverse_wire,
        h2_call_wire_start,
        h2_call_wire_start,
        tail._field_data_bit_offset(h2_lengths, 0, 0),
        h2_wire_start,
        commitment_wire_start,
        derived_mask_wire_start,
        append_base_wire_start,
        request_call_wire_start,
        request_hash_wire_start,
        request_last_state_wire,
        h1,
        points,
        h2,
        request,
    )


def _topology_execution(
    parameters: cap.CAPParameters,
) -> tuple[cap.CAPRandomness, cap.CAPExecution]:
    """Return a self-consistent shape fixture whose values are non-evidence."""

    salt = (0, 0)
    leaf_counts = parameters.expanded_leaf_counts()
    degrees = parameters.expanded_extension_degrees()
    polynomials = tuple(
        cap.TreePolynomial(
            leaves,
            degree,
            ((0, 0),) * leaves,
            0,
            (0,) * parameters.random_polynomial_bits,
        )
        for leaves, degree in zip(leaf_counts, degrees)
    )
    profile = bytes.fromhex(cap.profile_fingerprint(parameters))
    zero_deltas = (0,) * (parameters.tree_count - 1)
    h1_fields = (
        profile,
        *(cap._tree_component(index, poly) for index, poly in enumerate(polynomials)),
        cap._correction_component(zero_deltas, zero_deltas, parameters),
    )
    h1 = 0
    points = tuple(range(1, parameters.consistency_points + 1))
    point_output = sum(
        value << (index * field.FIELD_DEGREE)
        for index, value in enumerate(points)
    )
    alpha = 0
    xi_masks = (0,) * parameters.consistency_bits
    h2_fields = (
        cap.hash_bytes(h1),
        *(
            cap._xi_component(
                alpha,
                xi_masks,
                parameters.consistency_bits,
                degree,
            )
            for degree in degrees
        ),
    )
    h2 = 0
    encoded = cap.serialize_commitment(
        parameters,
        salt,
        h2,
        alpha,
        zero_deltas,
        zero_deltas,
    )
    commitment = cap.CAPCommitment(
        cap.profile_fingerprint(parameters),
        salt,
        h1,
        h2,
        alpha,
        zero_deltas,
        zero_deltas,
        0,
        0,
        encoded,
    )
    calls = (
        cap.XOFCall("h1", cap.DOMAIN_H1, h1_fields, cap.HASH_BITS, h1),
        cap.XOFCall(
            "consistency-points",
            cap.DOMAIN_CONSISTENCY_POINTS,
            (cap.hash_bytes(h1), profile),
            parameters.consistency_bits,
            point_output,
        ),
        cap.XOFCall("h2", cap.DOMAIN_H2, h2_fields, cap.HASH_BITS, h2),
    )
    randomness = cap.CAPRandomness(salt, ((0, 0),) * parameters.tree_count)
    return randomness, cap.CAPExecution(commitment, polynomials, calls)


def _source_archive_metadata(document: Mapping[str, object]) -> assignment.AssignmentArchiveMetadata:
    archive = document.get("assignment_archive")
    if not isinstance(archive, dict):
        raise ValueError("source manifest lacks assignment metadata")
    return assignment.AssignmentArchiveMetadata(
        str(archive["format"]),
        int(archive["header_bytes"]),
        int(archive["field_degree"]),
        int(archive["value_bytes"]),
        int(archive["wires"]),
        int(archive["body_bytes"]),
        str(archive["body_sha256"]),
        str(archive["row_stream_sha256"]),
        int(archive["archive_bytes"]),
        str(archive["archive_sha256"]),
    )


def _validate_layout_against_source(
    layout: ProductionTailLayout,
    source: Mapping[str, object],
) -> None:
    trace = source.get("trace")
    if not isinstance(trace, dict):
        raise ValueError("source manifest lacks trace evidence")
    if layout.rows != trace.get("rows") or layout.wires != trace.get("wires"):
        raise ValueError("production split layout does not partition frozen trace")
    groups = trace.get("groups")
    expected_groups = (
        ("global-input-ports", layout.input_rows),
        ("h1-corrections-and-points", layout.phase_a_rows),
        ("shared-alpha", 408),
        ("h2-commitment-and-request", layout.phase_b_rows - 408),
    )
    if not isinstance(groups, list) or tuple(
        (group.get("name"), group.get("rows"))
        for group in groups
        if isinstance(group, dict)
    ) != expected_groups:
        raise ValueError("production split group schedule mismatch")
    frozen = (
        layout.input_rows == FROZEN_INPUT_ROWS,
        layout.phase_a_rows == FROZEN_PHASE_A_ROWS,
        layout.phase_b_rows == FROZEN_PHASE_B_ROWS,
        layout.input_wires == FROZEN_INPUT_WIRES,
        layout.phase_a_wires == FROZEN_PHASE_A_WIRES,
        layout.phase_b_wires == FROZEN_PHASE_B_WIRES,
        layout.h1_wire_start == FROZEN_H1_WIRE_START,
        layout.point_wire_starts == FROZEN_POINT_WIRE_STARTS,
        layout.commitment_wire_start == FROZEN_COMMITMENT_WIRE_START,
        layout.request_hash_wire_start == FROZEN_REQUEST_HASH_WIRE_START,
    )
    if not all(frozen):
        raise ValueError("production split layout differs from frozen v2.12 values")


def _packed_bits(values: Mapping[int, int], start: int, length: int) -> bytes:
    packed = bytearray(math.ceil(length / 8))
    for index in range(length):
        bit = values[start + index]
        if bit not in (0, 1):
            raise ValueError(f"wire {start + index} is not a bit")
        packed[index // 8] |= bit << (index % 8)
    return bytes(packed)


def _actualize_contract(
    contract: tail.TailSplitContract,
    values: Mapping[int, int],
) -> tail.TailSplitContract:
    ports = tuple(
        replace(
            port,
            value_sha256=hashlib.sha256(
                _packed_bits(values, port.consumer_wire_start, port.bit_length)
            ).hexdigest(),
        )
        for port in contract.boundary_ports
    )
    return replace(contract, boundary_ports=ports)


def _wire_occurs(row: field.RankOneRow, wire: int) -> bool:
    return any(
        term_wire == wire
        for form in (row.left, row.right, row.output)
        for term_wire, _ in form.terms
    )


def _probe(
    values: Mapping[int, int],
    row: field.RankOneRow,
    port_id: str,
    wire: int,
) -> BoundaryWireProbe:
    if not _wire_occurs(row, wire):
        raise AssertionError(f"wire {wire} is absent from {row.label}")
    honest = shard._row_satisfied_fast(row, values)
    stale = shard._row_satisfied_fast(
        row,
        assignment.StaleAssignment(values, wire, values[wire] ^ 1),
    )
    return BoundaryWireProbe(row.label, port_id, wire, honest, stale, honest and not stale)


def _capture_labels(execution: cap.CAPExecution) -> tuple[str, ...]:
    _, _, h2 = tail._global_calls(execution)
    h2_lengths = tuple(len(value) for value in h2.fields)
    h1_payload_bit = tail._field_data_bit_offset(h2_lengths, 0, 0)
    return (
        "consistency.validate.point[0].nonzero",
        "consistency.validate.point[1].nonzero",
        f"xof[2].h2.payload[{h1_payload_bit}].source",
        "output.commitment[0].link",
        "xof[3].request-binding.digest.lane[0].pack",
    )


def materialize_production_split(
    archive_path: Path,
    source_manifest_path: Path,
    *,
    progress=None,
) -> ProductionSplitResult:
    source_bytes = source_manifest_path.read_bytes()
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    if source_sha256 != FROZEN_SOURCE_MANIFEST_SHA256:
        raise ValueError("production source manifest SHA-256 mismatch")
    source = json.loads(source_bytes)
    if not isinstance(source, dict):
        raise ValueError("production source manifest root must be an object")
    tail.seal_existing_manifest(source)
    layout = build_production_layout()
    _validate_layout_against_source(layout, source)
    expected_archive = _source_archive_metadata(source)
    if (
        expected_archive.archive_sha256 != tail.FROZEN_PRODUCTION_ASSIGNMENT_SHA256
        or expected_archive.body_sha256 != FROZEN_ASSIGNMENT_BODY_SHA256
        or expected_archive.body_bytes != FROZEN_ASSIGNMENT_BODY_BYTES
    ):
        raise ValueError("source assignment identity is not the frozen production archive")
    archive_sha256 = _sha256_file(archive_path)
    if archive_sha256 != expected_archive.archive_sha256:
        raise ValueError("production assignment archive SHA-256 mismatch")

    randomness, execution = _topology_execution(cap.PRODUCTION_PARAMETERS)
    labels = _capture_labels(execution)
    captured: dict[str, field.RankOneRow] = {}
    contracts: list[tail.TailSplitContract] = []
    replay_started = time.perf_counter()
    with assignment.AssignmentArchiveReader(
        archive_path,
        expected=expected_archive,
        verify_body=True,
    ) as values:
        summary = tail.build_global_tail(
            cap.PRODUCTION_PARAMETERS,
            randomness,
            execution,
            verification_assignment=values,
            capture_rows=labels,
            captured_rows_output=captured,
            split_contract_output=contracts,
            progress=progress,
        )
        if len(contracts) != 1:
            raise AssertionError("production observer emitted the wrong contract count")
        contract = _actualize_contract(contracts[0], values)
        point_port = next(
            port
            for port in contract.boundary_ports
            if port.port_id == "global.phase-a.consistency-points"
        )
        probes = (
            _probe(
                values,
                captured[labels[0]],
                "global.phase-a.consistency-point[0]",
                point_port.consumer_wire_start,
            ),
            _probe(
                values,
                captured[labels[1]],
                "global.phase-a.consistency-point[1]",
                point_port.consumer_wire_start + field.FIELD_DEGREE,
            ),
            _probe(
                values,
                captured[labels[2]],
                "global.phase-a.h1",
                layout.h1_wire_start,
            ),
            _probe(
                values,
                captured[labels[3]],
                "global.phase-b.commitment",
                layout.commitment_wire_start,
            ),
            _probe(
                values,
                captured[labels[4]],
                "global.phase-b.request-hash",
                layout.request_hash_wire_start,
            ),
        )
        commitment = _packed_bits(
            values,
            layout.commitment_wire_start,
            cap.commitment_bytes(cap.PRODUCTION_PARAMETERS) * 8,
        )
        request_hash = _packed_bits(
            values,
            layout.request_hash_wire_start,
            sponge.REQUEST_HASH_BITS,
        )
    replay_seconds = time.perf_counter() - replay_started

    trace = source["trace"]
    source_groups = tuple(
        (group["name"], group["rows"], group["bytes"], group["sha256"])
        for group in trace["groups"]
    )
    replay_groups = tuple(
        (group.name, group.rows, group.bytes, group.sha256)
        for group in summary.groups
    )
    if (
        summary.rows != tail.FROZEN_PRODUCTION_ROWS
        or summary.wires != tail.FROZEN_PRODUCTION_WIRES
        or summary.stream_sha256 != tail.FROZEN_PRODUCTION_STREAM_SHA256
        or summary.verification_failures != 0
        or summary.external_assertions != 0
        or replay_groups != source_groups
    ):
        raise AssertionError("production archive-driven observer replay diverged")
    if (
        hashlib.sha256(commitment).hexdigest()
        != tail.FROZEN_PRODUCTION_COMMITMENT_SHA256
        or request_hash.hex() != tail.FROZEN_PRODUCTION_REQUEST_HASH_HEX
    ):
        raise AssertionError("production output wires differ from frozen evidence")
    if not all(probe.rejected for probe in probes):
        raise AssertionError("a production split boundary mutation was accepted")
    phase_a, phase_b = contract.phases
    if (
        phase_a.row_start != layout.phase_a_row_start
        or phase_a.row_end != layout.phase_a_row_end
        or phase_a.wire_start != layout.phase_a_wire_start
        or phase_a.wire_end != layout.phase_a_wire_end
        or phase_b.row_start != layout.phase_b_row_start
        or phase_b.row_end != layout.phase_b_row_end
        or phase_b.wire_start != layout.phase_b_wire_start
        or phase_b.wire_end != layout.phase_b_wire_end
    ):
        raise AssertionError("observed production split ranges changed")
    return ProductionSplitResult(
        summary,
        contract,
        expected_archive,
        source_sha256,
        archive_sha256,
        layout,
        probes,
        commitment,
        request_hash,
        replay_seconds,
    )


def build_manifest(result: ProductionSplitResult) -> dict[str, object]:
    replay_closed = (
        result.summary.rows == tail.FROZEN_PRODUCTION_ROWS
        and result.summary.wires == tail.FROZEN_PRODUCTION_WIRES
        and result.summary.stream_sha256 == tail.FROZEN_PRODUCTION_STREAM_SHA256
        and result.summary.verification_failures == 0
        and result.summary.external_assertions == 0
        and result.archive_sha256 == tail.FROZEN_PRODUCTION_ASSIGNMENT_SHA256
        and result.source_manifest_sha256 == FROZEN_SOURCE_MANIFEST_SHA256
        and len(result.boundary_probes) == FROZEN_BOUNDARY_PROBES
        and all(probe.rejected for probe in result.boundary_probes)
        and result.contract.phase_a_to_phase_b_wire_identity
    )
    return {
        "implementation_version": IMPLEMENTATION_VERSION,
        "profile": {
            "contract_id": CONTRACT_ID,
            "canonical_relation_id": SOURCE_RELATION_ID,
            "cap_profile_fingerprint": cap.profile_fingerprint(
                cap.PRODUCTION_PARAMETERS
            ),
            "tree_count": cap.PRODUCTION_PARAMETERS.tree_count,
            "production_profile": True,
            "topology_fixture_values_are_evidence": False,
            "assignment_values_are_evidence": True,
        },
        "source_evidence": {
            "manifest_sha256": result.source_manifest_sha256,
            "assignment_archive_sha256": result.archive_sha256,
            "assignment_body_sha256": result.archive.body_sha256,
            "row_stream_sha256": result.summary.stream_sha256,
        },
        "trace": {
            "rows": result.summary.rows,
            "wires": result.summary.wires,
            "nonlinear_rows": result.summary.nonlinear_rows,
            "linear_rows": result.summary.linear_rows,
            "stream_bytes": result.summary.stream_bytes,
            "stream_sha256": result.summary.stream_sha256,
            "groups": [asdict(group) for group in result.summary.groups],
            "verification_failures": result.summary.verification_failures,
            "external_assertions": result.summary.external_assertions,
            "replay_seconds": result.replay_seconds,
            "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        },
        "phase_contract": asdict(result.contract),
        "layout_accounting": asdict(result.layout),
        "boundary_wire_probes": [
            asdict(probe) for probe in result.boundary_probes
        ],
        "outputs": {
            "commitment_bytes": len(result.commitment_bytes),
            "commitment_sha256": hashlib.sha256(
                result.commitment_bytes
            ).hexdigest(),
            "request_hash_hex": result.request_hash_bytes.hex(),
        },
        "claim_boundary": {
            "production_global_tail_native_closed": replay_closed,
            "production_split_tail_materialized": replay_closed,
            "production_h1_and_two_consistency_point_ports_native_closed": replay_closed,
            "production_tail_phase_a_to_phase_b_wire_identity_closed": replay_closed,
            "producer_point_wire_identity_closed": False,
            "production_tree_producer_segments_materialized": False,
            "complete_18_tree_assignment_replayed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    result = materialize_production_split(
        args.archive,
        args.source_manifest,
        progress=lambda message: print(message, flush=True),
    )
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(
        json.dumps(build_manifest(result), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "manifest": str(args.manifest),
                "rows": result.summary.rows,
                "wires": result.summary.wires,
                "stream_sha256": result.summary.stream_sha256,
                "verification_failures": result.summary.verification_failures,
                "boundary_probes_rejected": sum(
                    probe.rejected for probe in result.boundary_probes
                ),
                "replay_seconds": result.replay_seconds,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
