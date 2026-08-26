#!/usr/bin/env python3
"""Representative production output-relocation contract for PQ-RBBC v2.15.

The v2.13 and v2.14 producer checkpoints proved the two production tree
shapes separately and showed that their four output values equal the frozen
global-tail consumer values.  This module closes the missing *relocation*
relation for those representatives.  It imports the sealed producer ranges,
maps them into a compact canonical assignment, and emits one native linear
equality row for every source/destination bit pair.

This is deliberately not the complete 18-tree composition.  Tree indices 0
and 2 are representative position-sensitive instances; the other sixteen
producer instances, the parent join, and the cryptographic reductions remain
outside this relation.
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
from typing import Iterator, Mapping, Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_cap_global_tail as tail
import pq_rbbc_cap_production_tree0_producer as tree0
import pq_rbbc_cap_production_tree2_producer as tree2
import pq_rbbc_cap_shard_assignment as assignment
import pq_rbbc_cap_shard_stream as shard


IMPLEMENTATION_VERSION = "2.15"
RELATION_ID = "pq-rbbc/cap/representative-output-relocation/v1"
ASSIGNMENT_NAME = "pq_rbbc_representative_output_relocation_v2_15.f193assign"
MANIFEST_NAME = "pq_rbbc_cap_output_relocation_manifest_v2_15.json"
PORT_SUFFIXES = ("leaf-commitments", "p-plain", "mhat-plain", "xi-masks")
TREE_ORDER = (0, 2)
CHUNK_BITS = 65_536

# Frozen after the first archive generation and independent replay.
FROZEN_ROWS = 2_386_102
FROZEN_WIRES = 4_772_204
FROZEN_STREAM_BYTES = 496_519_444
FROZEN_STREAM_SHA256 = (
    "e81c1ce1aa07aae32ea166adea7c35a3b19f949c471fc17bdd5434dffe1dbeb0"
)
FROZEN_ASSIGNMENT_BYTES = 119_305_228
FROZEN_ASSIGNMENT_SHA256 = (
    "2f30c4d3d39e86e017dc9f8f78d20dfaf0a1fa40b99da56593d55297a7aa0b5c"
)


@dataclass(frozen=True)
class RelocationEvidence:
    port_id: str
    tree_index: int
    producer_relation_id: str
    producer_assignment_sha256: str
    producer_row_stream_sha256: str
    producer_wire_start: int
    consumer_wire_start: int
    bit_length: int
    value_sha256: str
    source_slice_mode: str


@dataclass(frozen=True)
class RelocationPort:
    port_id: str
    tree_index: int
    producer_relation_id: str
    producer_assignment_sha256: str
    producer_row_stream_sha256: str
    producer_wire_start: int
    consumer_wire_start: int
    bit_length: int
    value_sha256: str
    source_slice_mode: str
    canonical_source_wire_start: int
    canonical_destination_wire_start: int
    equality_rows: int
    equality_row_stream_bytes: int
    equality_row_stream_sha256: str


@dataclass(frozen=True)
class RelocationTrace:
    rows: int
    wires: int
    linear_rows: int
    nonlinear_rows: int
    stream_bytes: int
    stream_sha256: str
    external_assertions: int
    verification_failures: int
    first_verification_failure: str | None


@dataclass(frozen=True)
class MutationProbe:
    port_id: str
    mutation: str
    wire: int
    honest_row_satisfied: bool
    stale_row_satisfied: bool
    rejected: bool


@dataclass(frozen=True)
class ConfigurationProbe:
    mutation: str
    failures: tuple[str, ...]
    rejected: bool


@dataclass(frozen=True)
class RelocationResult:
    evidence: tuple[RelocationEvidence, ...]
    ports: tuple[RelocationPort, ...]
    trace: RelocationTrace
    archive: assignment.AssignmentArchiveMetadata
    mutation_probes: tuple[MutationProbe, ...]
    configuration_probes: tuple[ConfigurationProbe, ...]
    generation_seconds: float
    verification_seconds: float


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path} is not a JSON object")
    return document


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _archive_metadata(document: Mapping[str, object]) -> assignment.AssignmentArchiveMetadata:
    item = document.get("assignment_archive")
    if not isinstance(item, dict):
        raise ValueError("manifest lacks assignment_archive")
    return assignment.AssignmentArchiveMetadata(**item)


def _tail_ports(document: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    items = document.get("ports")
    if not isinstance(items, list):
        raise ValueError("global-tail manifest lacks ports")
    return {
        str(item["port_id"]): item
        for item in items
        if isinstance(item, dict)
    }


def _output_matches(document: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    items = document.get("output_matches")
    if not isinstance(items, list):
        raise ValueError("producer manifest lacks output_matches")
    return {
        str(item["port_id"]): item
        for item in items
        if isinstance(item, dict)
    }


def _profile(document: Mapping[str, object]) -> Mapping[str, object]:
    item = document.get("profile")
    if not isinstance(item, dict):
        raise ValueError("producer manifest lacks profile")
    return item


def _is_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def load_evidence(
    tail_manifest_path: Path,
    tree0_manifest_path: Path,
    tree2_manifest_path: Path,
) -> tuple[RelocationEvidence, ...]:
    tail_manifest = _read_json(tail_manifest_path)
    producer_documents = {
        0: _read_json(tree0_manifest_path),
        2: _read_json(tree2_manifest_path),
    }
    expected = {
        0: {
            "relation_id": tree0.RELATION_ID,
            "assignment_sha256": tree0.FROZEN_ASSIGNMENT_SHA256,
            "row_stream_sha256": tree0.FROZEN_STREAM_SHA256,
            "wire_starts": tree0.FROZEN_OUTPUT_WIRE_STARTS,
        },
        2: {
            "relation_id": tree2.RELATION_ID,
            "assignment_sha256": tree2.FROZEN_ASSIGNMENT_SHA256,
            "row_stream_sha256": tree2.FROZEN_STREAM_SHA256,
            "wire_starts": tree2.FROZEN_OUTPUT_WIRE_STARTS,
        },
    }
    consumers = _tail_ports(tail_manifest)
    evidence: list[RelocationEvidence] = []
    for tree_index in TREE_ORDER:
        document = producer_documents[tree_index]
        profile = _profile(document)
        archive = _archive_metadata(document)
        frozen = expected[tree_index]
        if profile.get("tree_index") != tree_index:
            raise ValueError(f"tree {tree_index} producer position mismatch")
        if profile.get("relation_id") != frozen["relation_id"]:
            raise ValueError(f"tree {tree_index} producer relation mismatch")
        if archive.archive_sha256 != frozen["assignment_sha256"]:
            raise ValueError(f"tree {tree_index} producer assignment mismatch")
        if archive.row_stream_sha256 != frozen["row_stream_sha256"]:
            raise ValueError(f"tree {tree_index} producer row stream mismatch")
        matches = _output_matches(document)
        for ordinal, suffix in enumerate(PORT_SUFFIXES):
            port_id = f"tree[{tree_index}].{suffix}"
            producer = matches.get(port_id)
            consumer = consumers.get(port_id)
            if producer is None or consumer is None:
                raise ValueError(f"missing relocation port {port_id}")
            if not producer.get("exact_value_match"):
                raise ValueError(f"producer value match is not sealed: {port_id}")
            if producer.get("exact_wire_identity"):
                raise ValueError(f"pre-relocation producer unexpectedly reuses consumer wire: {port_id}")
            item = RelocationEvidence(
                port_id=port_id,
                tree_index=tree_index,
                producer_relation_id=str(profile["relation_id"]),
                producer_assignment_sha256=archive.archive_sha256,
                producer_row_stream_sha256=archive.row_stream_sha256,
                producer_wire_start=int(producer["producer_wire_start"]),
                consumer_wire_start=int(producer["consumer_wire_start"]),
                bit_length=int(producer["bit_length"]),
                value_sha256=str(producer["value_sha256"]),
                source_slice_mode=(
                    "sealed-producer-output-digest"
                    if tree_index == 0
                    else "direct-producer-archive-slice"
                ),
            )
            if item.producer_wire_start != frozen["wire_starts"][ordinal]:
                raise ValueError(f"wrong producer source range: {port_id}")
            if (
                item.consumer_wire_start != int(consumer["consumer_wire_start"])
                or item.bit_length != int(consumer["bit_length"])
                or item.value_sha256 != str(consumer["value_sha256"])
            ):
                raise ValueError(f"producer/consumer relocation evidence mismatch: {port_id}")
            evidence.append(item)
    failures = evidence_failures(tuple(evidence), tuple(evidence))
    if failures:
        raise AssertionError(f"canonical relocation evidence is invalid: {failures}")
    return tuple(evidence)


def evidence_failures(
    candidate: Sequence[RelocationEvidence],
    canonical: Sequence[RelocationEvidence],
) -> tuple[str, ...]:
    failures: list[str] = []
    if len(candidate) != 8:
        failures.append("wrong_relocation_count")
        return tuple(failures)
    expected_ids = tuple(
        f"tree[{tree_index}].{suffix}"
        for tree_index in TREE_ORDER
        for suffix in PORT_SUFFIXES
    )
    if tuple(item.port_id for item in candidate) != expected_ids:
        failures.append("wrong_port_order")
    for index, item in enumerate(candidate):
        if item.bit_length <= 0:
            failures.append(f"invalid_bit_length:{item.port_id}")
        if not _is_sha256(item.value_sha256):
            failures.append(f"invalid_value_sha256:{item.port_id}")
        if not _is_sha256(item.producer_assignment_sha256):
            failures.append(f"invalid_assignment_sha256:{item.port_id}")
        if not _is_sha256(item.producer_row_stream_sha256):
            failures.append(f"invalid_row_stream_sha256:{item.port_id}")
        if index < len(canonical) and item != canonical[index]:
            failures.append(f"not_canonical:{item.port_id}")
    source_ranges = sorted(
        (item.producer_wire_start, item.producer_wire_start + item.bit_length)
        for item in candidate
    )
    destination_ranges = sorted(
        (item.consumer_wire_start, item.consumer_wire_start + item.bit_length)
        for item in candidate
    )
    if any(left[1] > right[0] for left, right in zip(source_ranges, source_ranges[1:])):
        failures.append("overlapping_source_ranges")
    if any(left[1] > right[0] for left, right in zip(destination_ranges, destination_ranges[1:])):
        failures.append("overlapping_destination_ranges")
    return tuple(dict.fromkeys(failures))


def _configuration_probes(
    canonical: tuple[RelocationEvidence, ...],
) -> tuple[ConfigurationProbe, ...]:
    mutations: list[tuple[str, tuple[RelocationEvidence, ...]]] = []
    first = canonical[0]
    mutations.append(("wrong-source-range", (replace(first, producer_wire_start=first.producer_wire_start + 1),) + canonical[1:]))
    mutations.append(("wrong-destination-range", (replace(first, consumer_wire_start=first.consumer_wire_start + 1),) + canonical[1:]))
    mutations.append(("wrong-bit-length", (replace(first, bit_length=first.bit_length - 1),) + canonical[1:]))
    mutations.append(("wrong-value-digest", (replace(first, value_sha256="00" * 32),) + canonical[1:]))
    mutations.append(("wrong-producer-archive", (replace(first, producer_assignment_sha256="11" * 32),) + canonical[1:]))
    mutations.append(("wrong-port-order", (canonical[1], canonical[0]) + canonical[2:]))
    result: list[ConfigurationProbe] = []
    for name, candidate in mutations:
        failures = evidence_failures(candidate, canonical)
        result.append(ConfigurationProbe(name, failures, bool(failures)))
    return tuple(result)


def _bit_range_digest(
    values: Mapping[int, int], start: int, length: int, port_id: str
) -> str:
    if port_id.endswith(".leaf-commitments"):
        if length % field.FIELD_DEGREE:
            raise ValueError("leaf-commitment range is not field aligned")
        digest = hashlib.sha256()
        for field_offset in range(0, length, field.FIELD_DEGREE):
            element = 0
            for bit in range(field.FIELD_DEGREE):
                value = values[start + field_offset + bit]
                if value not in (0, 1):
                    raise ValueError(
                        f"wire {start + field_offset + bit} is not binary"
                    )
                element |= value << bit
            digest.update(element.to_bytes(field.FIELD_ELEMENT_BYTES, "little"))
        return digest.hexdigest()
    packed = bytearray(math.ceil(length / 8))
    for index in range(length):
        value = values[start + index]
        if value not in (0, 1):
            raise ValueError(f"wire {start + index} is not binary")
        packed[index // 8] |= value << (index % 8)
    return hashlib.sha256(packed).hexdigest()


def _bit_chunks(
    values: Mapping[int, int], start: int, length: int
) -> Iterator[tuple[int, ...]]:
    offset = 0
    while offset < length:
        count = min(CHUNK_BITS, length - offset)
        chunk = tuple(values[start + offset + index] for index in range(count))
        if any(value not in (0, 1) for value in chunk):
            raise ValueError(f"non-binary relocation source at {start + offset}")
        yield chunk
        offset += count


def _allocate_range(
    sink: tail.BinaryRowSink,
    values: Mapping[int, int] | None,
    original_start: int,
    length: int,
) -> int:
    canonical_start = sink.next_wire
    if values is None:
        sink.allocate(length)
        return canonical_start
    for chunk in _bit_chunks(values, original_start, length):
        sink.allocate(len(chunk), values=chunk)
    return canonical_start


def _header(evidence: Sequence[RelocationEvidence]) -> dict[str, object]:
    return {
        "format": tail.STREAM_FORMAT,
        "field": "GF(2^193)",
        "relation_id": RELATION_ID,
        "implementation_version": IMPLEMENTATION_VERSION,
        "semantics": "(producer_bit + consumer_bit) * 1 = 0",
        "relocations": [asdict(item) for item in evidence],
    }


def _emit_relation(
    evidence: Sequence[RelocationEvidence],
    *,
    source_values: Mapping[int, Mapping[int, int]] | None = None,
    destination_values: Mapping[int, int] | None = None,
    assignment_writer: shard.AssignmentWriter | None = None,
    verification_assignment: Mapping[int, int] | None = None,
    capture_labels: Sequence[str] = (),
) -> tuple[RelocationTrace, tuple[RelocationPort, ...], dict[str, field.RankOneRow]]:
    sink = tail.BinaryRowSink(
        _header(evidence),
        assignment_writer=assignment_writer,
        verification_assignment=verification_assignment,
        capture_labels=capture_labels,
    )
    slots: list[tuple[RelocationEvidence, int, int]] = []
    for item in evidence:
        source = None if source_values is None else source_values[item.tree_index]
        source_start = _allocate_range(
            sink, source, item.producer_wire_start, item.bit_length
        )
        destination_start = _allocate_range(
            sink, destination_values, item.consumer_wire_start, item.bit_length
        )
        slots.append((item, source_start, destination_start))

    for item, source_start, destination_start in slots:
        sink.start_group(item.port_id)
        for bit in range(item.bit_length):
            sink.linear_zero(
                f"relocate.{item.port_id}.bit[{bit}]",
                field.LinearForm.wire(source_start + bit).add(
                    field.LinearForm.wire(destination_start + bit)
                ),
            )
        sink.finish_group()
    stream_bytes, stream_sha256 = sink.finish(
        {
            "rows": sink.rows,
            "wires": sink.allocated_wires,
            "external_assertions": 0,
        }
    )
    groups = {group.name: group for group in sink.groups}
    ports = tuple(
        RelocationPort(
            **asdict(item),
            canonical_source_wire_start=source_start,
            canonical_destination_wire_start=destination_start,
            equality_rows=item.bit_length,
            equality_row_stream_bytes=groups[item.port_id].bytes,
            equality_row_stream_sha256=groups[item.port_id].sha256,
        )
        for item, source_start, destination_start in slots
    )
    trace = RelocationTrace(
        rows=sink.rows,
        wires=sink.allocated_wires,
        linear_rows=sink.linear_rows,
        nonlinear_rows=sink.nonlinear_rows,
        stream_bytes=stream_bytes,
        stream_sha256=stream_sha256,
        external_assertions=0,
        verification_failures=sink.verification_failures,
        first_verification_failure=sink.first_verification_failure,
    )
    return trace, ports, dict(sink.captured_rows)


def _mutation_probes(
    values: Mapping[int, int],
    ports: Sequence[RelocationPort],
    captured: Mapping[str, field.RankOneRow],
) -> tuple[MutationProbe, ...]:
    probes: list[MutationProbe] = []
    for port in ports:
        label = f"relocate.{port.port_id}.bit[0]"
        row = captured[label]
        honest = shard._row_satisfied_fast(row, values)
        for mutation, wire in (
            ("flip-producer-source", port.canonical_source_wire_start),
            ("flip-tail-destination", port.canonical_destination_wire_start),
        ):
            stale = assignment.StaleAssignment(values, wire, values[wire] ^ 1)
            stale_satisfied = shard._row_satisfied_fast(row, stale)
            probes.append(
                MutationProbe(
                    port.port_id,
                    mutation,
                    wire,
                    honest,
                    stale_satisfied,
                    honest and not stale_satisfied,
                )
            )
    return tuple(probes)


def _metadata_from_reader(
    path: Path, reader: assignment.AssignmentArchiveReader
) -> assignment.AssignmentArchiveMetadata:
    return assignment.AssignmentArchiveMetadata(
        assignment.ASSIGNMENT_FORMAT,
        assignment.ASSIGNMENT_HEADER_BYTES,
        field.FIELD_DEGREE,
        field.FIELD_ELEMENT_BYTES,
        reader.wires,
        reader.body_bytes,
        reader.body_sha256,
        reader.row_stream_sha256,
        path.stat().st_size,
        _sha256_file(path),
    )


def build_relocation_contract(
    output_directory: Path,
    global_archive_path: Path,
    global_manifest_path: Path,
    tree0_manifest_path: Path,
    tree2_archive_path: Path,
    tree2_manifest_path: Path,
    *,
    replace_archive: bool = False,
) -> RelocationResult:
    output_directory.mkdir(parents=True, exist_ok=True)
    archive_path = output_directory / ASSIGNMENT_NAME
    evidence = load_evidence(
        global_manifest_path, tree0_manifest_path, tree2_manifest_path
    )
    config_probes = _configuration_probes(evidence)
    if not all(probe.rejected for probe in config_probes):
        raise AssertionError("a relocation configuration mutation was accepted")

    global_manifest = _read_json(global_manifest_path)
    tree2_manifest = _read_json(tree2_manifest_path)
    expected_global = _archive_metadata(global_manifest)
    expected_tree2 = _archive_metadata(tree2_manifest)
    if expected_global.archive_sha256 != tail.FROZEN_PRODUCTION_ASSIGNMENT_SHA256:
        raise ValueError("global-tail archive is not the frozen production assignment")
    if expected_tree2.archive_sha256 != tree2.FROZEN_ASSIGNMENT_SHA256:
        raise ValueError("tree-2 archive is not the frozen production assignment")

    generation_seconds = 0.0
    generated_trace: RelocationTrace | None = None
    with assignment.AssignmentArchiveReader(
        global_archive_path, expected=expected_global, verify_body=True
    ) as global_values, assignment.AssignmentArchiveReader(
        tree2_archive_path, expected=expected_tree2, verify_body=True
    ) as tree2_local_reader:
        tree2_values = tree2.OffsetAssignment(
            tree2_local_reader, tree2.LOCAL_WIRE_START, expected_tree2.wires
        )
        source_values: dict[int, Mapping[int, int]] = {
            # v2.13 already replayed this source archive.  Its large body need
            # not be restored: the sealed output digest is reconstructed from
            # the independently replayed tail range.
            0: global_values,
            2: tree2_values,
        }
        for item in evidence:
            source_start = (
                item.consumer_wire_start
                if item.tree_index == 0
                else item.producer_wire_start
            )
            source = global_values if item.tree_index == 0 else tree2_values
            if _bit_range_digest(
                source, source_start, item.bit_length, item.port_id
            ) != item.value_sha256:
                raise ValueError(f"producer output digest mismatch: {item.port_id}")
            if _bit_range_digest(
                global_values,
                item.consumer_wire_start,
                item.bit_length,
                item.port_id,
            ) != item.value_sha256:
                raise ValueError(f"global-tail consumer digest mismatch: {item.port_id}")

        if replace_archive and archive_path.exists():
            archive_path.unlink()
        if not archive_path.exists():
            writer = assignment.AssignmentArchiveWriter(archive_path)
            started = time.perf_counter()
            try:
                # Tree 0's source slot is reconstructed from its proven-equal
                # tail range; tree 2 is read directly from its producer archive.
                generation_sources = {
                    0: _ConsumerRangeAdapter(global_values, evidence),
                    2: tree2_values,
                }
                generated_trace, _, _ = _emit_relation(
                    evidence,
                    source_values=generation_sources,
                    destination_values=global_values,
                    assignment_writer=writer,
                )
                archive = writer.finish(
                    generated_trace.wires, generated_trace.stream_sha256
                )
            except BaseException:
                writer.abort()
                raise
            generation_seconds = time.perf_counter() - started
        else:
            with assignment.AssignmentArchiveReader(
                archive_path, verify_body=True
            ) as existing:
                archive = _metadata_from_reader(archive_path, existing)

    capture_labels = tuple(
        f"relocate.{item.port_id}.bit[0]" for item in evidence
    )
    verification_started = time.perf_counter()
    with assignment.AssignmentArchiveReader(
        archive_path, expected=archive, verify_body=True
    ) as values:
        verified_trace, ports, captured = _emit_relation(
            evidence,
            verification_assignment=values,
            capture_labels=capture_labels,
        )
        probes = _mutation_probes(values, ports, captured)
    verification_seconds = time.perf_counter() - verification_started
    if verified_trace.verification_failures:
        raise AssertionError(
            f"relocation replay failed at {verified_trace.first_verification_failure}"
        )
    if archive.row_stream_sha256 != verified_trace.stream_sha256:
        raise AssertionError("relocation row-stream identity mismatch")
    if generated_trace is not None and generated_trace != verified_trace:
        raise AssertionError("generated and replayed relocation traces differ")
    if not all(probe.rejected for probe in probes):
        raise AssertionError("a relocation witness mutation was accepted")
    return RelocationResult(
        evidence,
        ports,
        verified_trace,
        archive,
        probes,
        config_probes,
        generation_seconds,
        verification_seconds,
    )


class _ConsumerRangeAdapter(Mapping[int, int]):
    """Expose sealed tree-0 source wire IDs through their equal tail ranges."""

    def __init__(
        self,
        global_values: Mapping[int, int],
        evidence: Sequence[RelocationEvidence],
    ) -> None:
        self.global_values = global_values
        self.ranges = tuple(
            item for item in evidence if item.tree_index == 0
        )

    def __getitem__(self, wire: int) -> int:
        for item in self.ranges:
            offset = wire - item.producer_wire_start
            if 0 <= offset < item.bit_length:
                return self.global_values[item.consumer_wire_start + offset]
        raise KeyError(wire)

    def __iter__(self) -> Iterator[int]:
        for item in self.ranges:
            yield from range(
                item.producer_wire_start,
                item.producer_wire_start + item.bit_length,
            )

    def __len__(self) -> int:
        return sum(item.bit_length for item in self.ranges)


def build_manifest(result: RelocationResult) -> dict[str, object]:
    frozen = (
        result.trace.rows == FROZEN_ROWS
        and result.trace.wires == FROZEN_WIRES
        and result.trace.stream_bytes == FROZEN_STREAM_BYTES
        and result.trace.stream_sha256 == FROZEN_STREAM_SHA256
        and result.archive.archive_bytes == FROZEN_ASSIGNMENT_BYTES
        and result.archive.archive_sha256 == FROZEN_ASSIGNMENT_SHA256
    )
    replay_closed = (
        frozen
        and result.trace.linear_rows == result.trace.rows
        and result.trace.nonlinear_rows == 0
        and result.trace.external_assertions == 0
        and result.trace.verification_failures == 0
        and len(result.ports) == 8
        and sum(port.equality_rows for port in result.ports) == result.trace.rows
        and all(probe.rejected for probe in result.mutation_probes)
        and all(probe.rejected for probe in result.configuration_probes)
    )
    tree0_closed = replay_closed and all(
        port.tree_index != 0 or port.equality_rows == port.bit_length
        for port in result.ports
    )
    tree2_closed = replay_closed and all(
        port.tree_index != 2 or port.equality_rows == port.bit_length
        for port in result.ports
    )
    return {
        "implementation_version": IMPLEMENTATION_VERSION,
        "profile": {
            "relation_id": RELATION_ID,
            "field": "GF(2^193)",
            "assignment_format": assignment.ASSIGNMENT_FORMAT,
            "representative_tree_indices": list(TREE_ORDER),
            "remaining_tree_instances_not_materialized": 16,
            "full_tree0_assignment_restored_for_v2_15": False,
            "tree0_source_import": "sealed v2.13 producer output digest plus independently replayed tail value",
            "tree2_source_import": "direct v2.14 producer archive slice",
        },
        "trace": asdict(result.trace),
        "assignment_archive": asdict(result.archive),
        "relocations": [asdict(port) for port in result.ports],
        "mutation_probes": [asdict(probe) for probe in result.mutation_probes],
        "configuration_mutation_probes": [
            asdict(probe) for probe in result.configuration_probes
        ],
        "execution": {
            "generation_seconds": result.generation_seconds,
            "verification_seconds": result.verification_seconds,
            "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        },
        "claim_boundary": {
            "production_representative_output_relocation_contract_closed": replay_closed,
            "production_index0_all_four_output_relocations_closed": tree0_closed,
            "production_index2_all_four_output_relocations_closed": tree2_closed,
            "all_four_output_relocations_closed": tree0_closed and tree2_closed,
            "representative_cross_segment_wire_relation_closed": replay_closed,
            "tree_producer_segments_materialized": False,
            "complete_18_tree_assignment_replayed": False,
            "cross_segment_wire_identity_closed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "cap_unique_witness_reviewed": False,
            "cap_straightline_extraction_reviewed": False,
            "fork_blindness_proved": False,
            "one_more_unforgeability_proved": False,
            "se_nizk_qrom_reduction_complete": False,
            "fork_security_proof_revalidated": False,
            "signature_size_rebenchmarked": False,
            "production_closed": False,
        },
    }


def _atomic_json(path: Path, document: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--global-archive", type=Path, required=True)
    parser.add_argument("--global-manifest", type=Path, required=True)
    parser.add_argument("--tree0-manifest", type=Path, required=True)
    parser.add_argument("--tree2-archive", type=Path, required=True)
    parser.add_argument("--tree2-manifest", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--replace-archive", action="store_true")
    args = parser.parse_args()
    result = build_relocation_contract(
        args.output_directory,
        args.global_archive,
        args.global_manifest,
        args.tree0_manifest,
        args.tree2_archive,
        args.tree2_manifest,
        replace_archive=args.replace_archive,
    )
    manifest = build_manifest(result)
    _atomic_json(args.manifest, manifest)
    print(
        json.dumps(
            {
                "archive": str(args.output_directory / ASSIGNMENT_NAME),
                "manifest": str(args.manifest),
                "rows": result.trace.rows,
                "wires": result.trace.wires,
                "stream_bytes": result.trace.stream_bytes,
                "stream_sha256": result.trace.stream_sha256,
                "assignment_sha256": result.archive.archive_sha256,
                "verification_failures": result.trace.verification_failures,
                "mutations_rejected": sum(
                    probe.rejected for probe in result.mutation_probes
                ),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
