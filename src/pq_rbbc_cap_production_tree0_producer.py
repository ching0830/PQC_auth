#!/usr/bin/env python3
"""Checkpointable production tree-index-0 producer for PQ-RBBC v2.13.

This module materializes the first actual mixed-profile producer: tree index 0,
4,096 leaves, and extension degree 13.  It imports the two already-constrained
production consistency-point ranges by their exact global-tail wire IDs.  No
local point copy, H1, H2, commitment serializer, or request tail is emitted.

The expensive tree-local reference execution is checkpointed after every GGM
level and every leaf batch.  Assignment generation uses a resumable fixed-width
writer: an interrupted prefix remains on disk, is byte-checked while the row
generator restores its canonical state, and is extended rather than discarded.
Generation and replay are separate sealed stages so an interruption after
generation never repeats witness materialization.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pickle
import resource
import time
from collections.abc import Iterator, Mapping, Sequence
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_composer as composer
import pq_rbbc_cap_global_tail as tail
import pq_rbbc_cap_shard_assignment as assignment
import pq_rbbc_cap_shard_stream as shard
import pq_rbbc_cap_tree_producer as producer


IMPLEMENTATION_VERSION = "2.13"
RELATION_ID = "pq-rbbc/cap/production-tree-producer-index-0/v1"
TREE_INDEX = 0
LEAVES = 1 << 12
EXTENSION_DEGREE = 13
GLOBAL_POINT_STARTS = (39_945_673, 39_945_866)
LOCAL_WIRE_START = tail.FROZEN_PRODUCTION_WIRES + 1
FROZEN_TREE_COMPONENT_SHA256 = (
    "1f780036168c0560a2cb7e7f994f8cd5c6bf60860bd387658b777bc976a8f33e"
)
FROZEN_ROWS = 51_325_080
FROZEN_LOCAL_WIRES = 38_953_830
FROZEN_MAX_WIRE_ID = 79_148_426
FROZEN_STREAM_BYTES = 18_008_277_110
FROZEN_STREAM_SHA256 = (
    "496f5279f914d72b15864414f1a548089236de1e14cdde3a8d360c28a21ca43e"
)
FROZEN_ASSIGNMENT_BYTES = 973_845_878
FROZEN_ASSIGNMENT_SHA256 = (
    "213fa3c90b62db64436ec8e7dd7ee5a6e0ec6b546ae4fa02b3cbfb50fdf502db"
)
FROZEN_POINT_VALUE_SHA256 = (
    "eda567ca99c39229b5da8d526d23a36885230dddb33f6dbeb9e034c15d28e251"
)
FROZEN_OUTPUT_WIRE_STARTS = (77_419_669, 79_000_725, 79_002_773, 79_143_409)
EXECUTION_CACHE_FORMAT = "PQRBBC-PRODUCTION-TREE-CACHE-1"
CHECKPOINT_BATCH_LEAVES = 128


@dataclass(frozen=True)
class PointMutationProbe:
    label: str
    mutation: str
    wire: int
    honest_row_satisfied: bool
    stale_row_satisfied: bool
    rejected: bool


@dataclass(frozen=True)
class ProductionTree0Result:
    summary: producer.ProducerSummary
    archive: assignment.AssignmentArchiveMetadata
    tree_component_sha256: str
    global_point_values: tuple[int, ...]
    standard_probes: tuple[assignment.TamperProbe, ...]
    point_probes: tuple[PointMutationProbe, ...]
    generation_seconds: float
    verification_seconds: float
    resumed_execution_cache: bool
    resumed_assignment_prefix_wires: int


def _atomic_pickle(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as stream:
        pickle.dump(value, stream, protocol=pickle.HIGHEST_PROTOCOL)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def _atomic_json(path: Path, value: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with temporary.open("rb") as stream:
        os.fsync(stream.fileno())
    temporary.replace(path)


def _randomness_digest(randomness: cap.CAPRandomness) -> str:
    return hashlib.sha256(
        randomness.serialize(cap.PRODUCTION_PARAMETERS)
    ).hexdigest()


def _new_execution_checkpoint(randomness: cap.CAPRandomness) -> dict[str, object]:
    return {
        "format": EXECUTION_CACHE_FORMAT,
        "profile_fingerprint": cap.profile_fingerprint(cap.PRODUCTION_PARAMETERS),
        "randomness_sha256": _randomness_digest(randomness),
        "tree_index": TREE_INDEX,
        "next_level": 2,
        "nodes": tuple(randomness.roots[TREE_INDEX]),
        "derivations": tuple(),
        "leaf_outputs": tuple(),
        "phase": "derive",
    }


def _load_execution_checkpoint(
    path: Path, randomness: cap.CAPRandomness
) -> tuple[dict[str, object], bool]:
    if not path.exists():
        return _new_execution_checkpoint(randomness), False
    with path.open("rb") as stream:
        value = pickle.load(stream)
    if not isinstance(value, dict):
        raise ValueError("production tree execution checkpoint type mismatch")
    expected = _new_execution_checkpoint(randomness)
    for key in (
        "format",
        "profile_fingerprint",
        "randomness_sha256",
        "tree_index",
    ):
        if value.get(key) != expected[key]:
            raise ValueError(f"production tree execution checkpoint mismatch: {key}")
    nodes = value.get("nodes")
    derivations = value.get("derivations")
    leaf_outputs = value.get("leaf_outputs")
    if not isinstance(nodes, tuple) or not isinstance(derivations, tuple):
        raise ValueError("production tree execution checkpoint is malformed")
    if not isinstance(leaf_outputs, tuple) or len(leaf_outputs) > LEAVES:
        raise ValueError("production tree leaf checkpoint is malformed")
    return value, True


def _map_tasks(
    function: Callable[[object], object],
    tasks: Sequence[object],
    workers: int,
) -> list[object]:
    if workers <= 1:
        return list(map(function, tasks))
    with ProcessPoolExecutor(max_workers=workers) as executor:
        return list(executor.map(function, tasks, chunksize=8))


def build_tree0_material(
    checkpoint_path: Path,
    point_values: Sequence[int],
    *,
    workers: int = 1,
    progress: Callable[[str], None] | None = None,
) -> tuple[cap.CAPRandomness, producer.TreeProducerMaterial, str, bool]:
    """Build or resume the real tree-0 XOF outputs and polynomial."""

    parameters = cap.PRODUCTION_PARAMETERS
    randomness = cap.deterministic_randomness(
        parameters, composer.FROZEN_RANDOMNESS_LABEL
    )
    state, resumed = _load_execution_checkpoint(checkpoint_path, randomness)
    nodes = list(state["nodes"])
    derivations = list(state["derivations"])
    next_level = int(state["next_level"])

    while len(nodes) < LEAVES:
        tasks = [
            (TREE_INDEX, next_level, index, parent, randomness.salt)
            for index, parent in enumerate(nodes, start=1)
        ]
        outputs = _map_tasks(composer._derive_task, tasks, max(1, workers))
        children: list[int] = []
        for index, (parent, output) in enumerate(
            zip(nodes, outputs, strict=True), start=1
        ):
            output = int(output)
            derivations.append((next_level, index, parent, output))
            children.extend((output & field.FIELD_MASK, output >> cap.SEED_BITS))
        nodes = children
        next_level += 1
        state.update(
            {
                "next_level": next_level,
                "nodes": tuple(nodes),
                "derivations": tuple(derivations),
                "phase": "derive" if len(nodes) < LEAVES else "leaves",
            }
        )
        _atomic_pickle(checkpoint_path, state)
        if progress is not None:
            progress(f"tree 0 execution checkpoint: {len(nodes)}/{LEAVES} seeds")

    leaf_outputs = list(state["leaf_outputs"])
    while len(leaf_outputs) < LEAVES:
        start = len(leaf_outputs)
        end = min(LEAVES, start + CHECKPOINT_BATCH_LEAVES)
        tasks = [
            (
                TREE_INDEX,
                index + 1,
                nodes[index],
                randomness.salt,
                parameters.random_polynomial_bits,
            )
            for index in range(start, end)
        ]
        leaf_outputs.extend(
            tuple(item) for item in _map_tasks(composer._leaf_task, tasks, max(1, workers))
        )
        state.update(
            {
                "leaf_outputs": tuple(leaf_outputs),
                "phase": "complete" if end == LEAVES else "leaves",
            }
        )
        _atomic_pickle(checkpoint_path, state)
        if progress is not None:
            progress(f"tree 0 execution checkpoint: {end}/{LEAVES} leaves")

    polynomial = composer._aggregate_tree_task(
        (LEAVES, EXTENSION_DEGREE, parameters.random_polynomial_bits, tuple(leaf_outputs))
    )
    derivation_sets: list[Sequence[tuple[int, int, int, int]]] = [
        tuple() for _ in range(parameters.tree_count)
    ]
    seed_sets: list[Sequence[int]] = [tuple() for _ in range(parameters.tree_count)]
    output_sets: list[Sequence[tuple[int, int]]] = [
        tuple() for _ in range(parameters.tree_count)
    ]
    derivation_sets[TREE_INDEX] = tuple(derivations)
    seed_sets[TREE_INDEX] = tuple(nodes)
    output_sets[TREE_INDEX] = tuple(leaf_outputs)
    calls = composer._canonical_tree_calls(
        parameters, randomness, derivation_sets, seed_sets, output_sets
    )
    tree_component_sha256 = hashlib.sha256(
        cap._tree_component(TREE_INDEX, polynomial)
    ).hexdigest()
    if tree_component_sha256 != FROZEN_TREE_COMPONENT_SHA256:
        raise AssertionError("tree-0 component disagrees with frozen v2.8 execution")
    material = producer.material_from_local_tree(
        parameters, TREE_INDEX, polynomial, tuple(point_values), calls
    )
    return randomness, material, tree_component_sha256, resumed


class ResumableAssignmentArchiveWriter(shard.AssignmentWriter):
    """A prefix-preserving writer for the standard fixed-width archive."""

    def __init__(self, path: Path, *, replace: bool = False) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if replace and path.exists():
            path.unlink()
        if path.exists():
            self._file = path.open("r+b")
            size = path.stat().st_size
            if size < assignment.ASSIGNMENT_HEADER_BYTES:
                raise ValueError("resumable assignment prefix is truncated")
            body_bytes = size - assignment.ASSIGNMENT_HEADER_BYTES
            if body_bytes % field.FIELD_ELEMENT_BYTES:
                raise ValueError("resumable assignment prefix is misaligned")
            self.existing_wires = body_bytes // field.FIELD_ELEMENT_BYTES
        else:
            self._file = path.open("x+b")
            self._file.write(bytes(assignment.ASSIGNMENT_HEADER_BYTES))
            self._file.flush()
            os.fsync(self._file.fileno())
            self.existing_wires = 0
        self.wires = 0
        self.closed = False

    def _append(self, encoded: bytes, count: int) -> None:
        if self.closed:
            raise RuntimeError("resumable assignment writer is closed")
        if len(encoded) != count * field.FIELD_ELEMENT_BYTES:
            raise ValueError("resumable assignment append width mismatch")
        start = self.wires
        overlap = max(0, min(count, self.existing_wires - start))
        if overlap:
            self._file.seek(
                assignment.ASSIGNMENT_HEADER_BYTES
                + start * field.FIELD_ELEMENT_BYTES
            )
            expected = self._file.read(overlap * field.FIELD_ELEMENT_BYTES)
            if expected != encoded[: len(expected)]:
                raise ValueError("resumable assignment prefix value mismatch")
        remainder = encoded[overlap * field.FIELD_ELEMENT_BYTES :]
        if remainder:
            self._file.seek(0, os.SEEK_END)
            self._file.write(remainder)
        self.wires += count

    def append_values(self, values: Sequence[int]) -> None:
        encoded = bytearray()
        for value in values:
            if not 0 <= value <= field.FIELD_MASK:
                raise ValueError("non-canonical GF(2^193) assignment value")
            encoded.extend(value.to_bytes(field.FIELD_ELEMENT_BYTES, "little"))
        self._append(bytes(encoded), len(values))

    def append_encoded(self, encoded: bytes, count: int) -> None:
        self._append(encoded, count)

    def finish(
        self, expected_wires: int, row_stream_sha256: str
    ) -> assignment.AssignmentArchiveMetadata:
        if self.wires != expected_wires:
            raise AssertionError("resumable assignment wire count mismatch")
        self._file.flush()
        os.fsync(self._file.fileno())
        body_bytes = expected_wires * field.FIELD_ELEMENT_BYTES
        if self.path.stat().st_size != assignment.ASSIGNMENT_HEADER_BYTES + body_bytes:
            raise AssertionError("resumable assignment body size mismatch")
        body_digest = hashlib.sha256()
        self._file.seek(assignment.ASSIGNMENT_HEADER_BYTES)
        while True:
            chunk = self._file.read(8 * 1024 * 1024)
            if not chunk:
                break
            body_digest.update(chunk)
        body_sha256 = body_digest.hexdigest()
        header = assignment.ASSIGNMENT_HEADER.pack(
            assignment.ASSIGNMENT_MAGIC,
            assignment.ASSIGNMENT_VERSION,
            field.FIELD_DEGREE,
            field.FIELD_ELEMENT_BYTES,
            expected_wires,
            body_bytes,
            bytes.fromhex(body_sha256),
            bytes.fromhex(row_stream_sha256),
            bytes(8),
        )
        self._file.seek(0)
        self._file.write(header)
        self._file.flush()
        os.fsync(self._file.fileno())
        self._file.close()
        self.closed = True
        archive_bytes = assignment.ASSIGNMENT_HEADER_BYTES + body_bytes
        return assignment.AssignmentArchiveMetadata(
            assignment.ASSIGNMENT_FORMAT,
            assignment.ASSIGNMENT_HEADER_BYTES,
            field.FIELD_DEGREE,
            field.FIELD_ELEMENT_BYTES,
            expected_wires,
            body_bytes,
            body_sha256,
            row_stream_sha256,
            archive_bytes,
            assignment._hash_file(self.path),
        )

    def abort(self) -> None:
        if not self.closed:
            self._file.flush()
            os.fsync(self._file.fileno())
            self._file.close()
            self.closed = True


class OffsetAssignment(Mapping[int, int]):
    def __init__(
        self,
        values: Mapping[int, int],
        wire_start: int,
        wire_count: int,
    ) -> None:
        self.values = values
        self.wire_start = wire_start
        self.wire_count = wire_count
        self.wire_end = wire_start + wire_count

    def __getitem__(self, wire: int) -> int:
        if not self.wire_start <= wire < self.wire_end:
            raise KeyError(wire)
        return self.values[wire - self.wire_start + 1]

    def __iter__(self) -> Iterator[int]:
        return iter(range(self.wire_start, self.wire_end))

    def __len__(self) -> int:
        return self.wire_count


class CompositeAssignment(Mapping[int, int]):
    def __init__(self, global_values: Mapping[int, int], local_values: OffsetAssignment):
        if len(global_values) >= local_values.wire_start:
            raise ValueError("global and local assignment ranges overlap")
        self.global_values = global_values
        self.local_values = local_values

    def __getitem__(self, wire: int) -> int:
        if 1 <= wire <= len(self.global_values):
            return self.global_values[wire]
        return self.local_values[wire]

    def __iter__(self) -> Iterator[int]:
        yield from self.global_values
        yield from self.local_values

    def __len__(self) -> int:
        return len(self.global_values) + len(self.local_values)


class OverlayAssignment(Mapping[int, int]):
    def __init__(self, base: Mapping[int, int], overrides: Mapping[int, int]) -> None:
        self.base = base
        self.overrides = dict(overrides)

    def __getitem__(self, wire: int) -> int:
        return self.overrides.get(wire, self.base[wire])

    def __iter__(self) -> Iterator[int]:
        return iter(self.base)

    def __len__(self) -> int:
        return len(self.base)


def _archive_metadata(document: Mapping[str, object]) -> assignment.AssignmentArchiveMetadata:
    archive = document.get("assignment_archive")
    if not isinstance(archive, dict):
        raise ValueError("global-tail manifest lacks assignment metadata")
    return assignment.AssignmentArchiveMetadata(**archive)


def _field_from_bits(values: Mapping[int, int], start: int) -> int:
    result = 0
    for bit in range(field.FIELD_DEGREE):
        value = values[start + bit]
        if value not in (0, 1):
            raise ValueError("global point wire is not binary")
        result |= value << bit
    return result


def validate_point_imports(
    point_starts: Sequence[int], local_wire_start: int = LOCAL_WIRE_START
) -> tuple[str, ...]:
    failures: list[str] = []
    if tuple(point_starts) != GLOBAL_POINT_STARTS:
        failures.append("wrong_point_relocation")
    if len(point_starts) != 2 or (
        len(point_starts) == 2
        and point_starts[1] != point_starts[0] + field.FIELD_DEGREE
    ):
        failures.append("noncontiguous_point_ranges")
    if any(start >= local_wire_start for start in point_starts):
        failures.append("point_import_overlaps_local_wires")
    return tuple(failures)


def _point_probe(
    assignment_values: Mapping[int, int],
    row: field.RankOneRow,
    mutation: str,
    wire: int,
    stale_values: Mapping[int, int],
) -> PointMutationProbe:
    occurs = any(
        item_wire == wire
        for form in (row.left, row.right, row.output)
        for item_wire, _ in form.terms
    )
    if not occurs:
        raise AssertionError(f"point wire {wire} is absent from {row.label}")
    honest = shard._row_satisfied_fast(row, assignment_values)
    stale = shard._row_satisfied_fast(row, stale_values)
    return PointMutationProbe(row.label, mutation, wire, honest, stale, honest and not stale)


def _run_point_probes(
    values: Mapping[int, int], captured: Mapping[str, field.RankOneRow]
) -> tuple[PointMutationProbe, ...]:
    labels = (
        "horner.leaf[1].point[0].mul[9]",
        "horner.leaf[1].point[1].mul[9]",
    )
    probes: list[PointMutationProbe] = []
    for label, start in zip(labels, GLOBAL_POINT_STARTS, strict=True):
        row = captured[label]
        stale = assignment.StaleAssignment(values, start, values[start] ^ 1)
        probes.append(_point_probe(values, row, "flip-imported-point", start, stale))
    swap = {
        GLOBAL_POINT_STARTS[0] + bit: values[GLOBAL_POINT_STARTS[1] + bit]
        for bit in range(field.FIELD_DEGREE)
    }
    swap.update(
        {
            GLOBAL_POINT_STARTS[1] + bit: values[GLOBAL_POINT_STARTS[0] + bit]
            for bit in range(field.FIELD_DEGREE)
        }
    )
    probes.append(
        _point_probe(
            values,
            captured[labels[0]],
            "swap-imported-points",
            GLOBAL_POINT_STARTS[0],
            OverlayAssignment(values, swap),
        )
    )
    return tuple(probes)


def _complete_archive_metadata(
    archive_path: Path,
) -> assignment.AssignmentArchiveMetadata | None:
    if not archive_path.exists():
        return None
    try:
        with assignment.AssignmentArchiveReader(
            archive_path, verify_body=True
        ) as reader:
            return assignment.AssignmentArchiveMetadata(
                assignment.ASSIGNMENT_FORMAT,
                assignment.ASSIGNMENT_HEADER_BYTES,
                field.FIELD_DEGREE,
                field.FIELD_ELEMENT_BYTES,
                reader.wires,
                reader.body_bytes,
                reader.body_sha256,
                reader.row_stream_sha256,
                archive_path.stat().st_size,
                assignment._hash_file(archive_path),
            )
    except ValueError:
        return None


def build_production_tree0(
    output_directory: Path,
    global_archive_path: Path,
    global_manifest_path: Path,
    *,
    workers: int = 1,
    replace: bool = False,
    progress: Callable[[str], None] | None = None,
) -> ProductionTree0Result:
    output_directory.mkdir(parents=True, exist_ok=True)
    archive_path = output_directory / "pq_rbbc_production_tree_0_producer_v2_13.f193assign"
    execution_cache_path = output_directory / "tree_0_execution_checkpoint_v2_13.pkl"
    stage_path = output_directory / "tree_0_resume_state_v2_13.json"
    source_manifest = json.loads(global_manifest_path.read_text(encoding="utf-8"))
    expected_global = _archive_metadata(source_manifest)
    if expected_global.archive_sha256 != tail.FROZEN_PRODUCTION_ASSIGNMENT_SHA256:
        raise ValueError("global-tail assignment identity is not frozen v2.9")
    if validate_point_imports(GLOBAL_POINT_STARTS):
        raise AssertionError("frozen point import contract is invalid")

    with assignment.AssignmentArchiveReader(
        global_archive_path, expected=expected_global, verify_body=True
    ) as global_values:
        point_values = tuple(
            _field_from_bits(global_values, start) for start in GLOBAL_POINT_STARTS
        )
        randomness, material, component_sha, resumed_cache = build_tree0_material(
            execution_cache_path,
            point_values,
            workers=workers,
            progress=progress,
        )
        labels = producer.capture_material_labels(cap.PRODUCTION_PARAMETERS, material)
        point_labels = (
            "horner.leaf[1].point[0].mul[9]",
            "horner.leaf[1].point[1].mul[9]",
        )
        archive = None if replace else _complete_archive_metadata(archive_path)
        resumed_prefix = 0
        generation_seconds = 0.0
        if archive is None:
            writer = ResumableAssignmentArchiveWriter(archive_path, replace=replace)
            resumed_prefix = writer.existing_wires
            started = time.perf_counter()
            try:
                generated = producer.build_tree_producer(
                    cap.PRODUCTION_PARAMETERS,
                    randomness,
                    None,
                    TREE_INDEX,
                    producer_material=material,
                    external_point_starts=GLOBAL_POINT_STARTS,
                    local_wire_start=LOCAL_WIRE_START,
                    workers=workers,
                    assignment_writer=writer,
                    progress=progress,
                )
                archive = writer.finish(generated.wires, generated.stream_sha256)
            except BaseException:
                writer.abort()
                _atomic_json(
                    stage_path,
                    {
                        "format": "PQRBBC-PRODUCTION-PRODUCER-RESUME-1",
                        "stage": "assignment-prefix-preserved",
                        "archive_path": str(archive_path),
                        "prefix_bytes": archive_path.stat().st_size,
                        "execution_cache": str(execution_cache_path),
                    },
                )
                raise
            generation_seconds = time.perf_counter() - started
            _atomic_json(
                stage_path,
                {
                    "format": "PQRBBC-PRODUCTION-PRODUCER-RESUME-1",
                    "stage": "assignment-generated",
                    "archive_sha256": archive.archive_sha256,
                    "archive_wires": archive.wires,
                    "execution_cache": str(execution_cache_path),
                },
            )
        if archive is None:
            raise AssertionError("producer archive metadata is missing")

        captured: dict[str, field.RankOneRow] = {}
        verification_started = time.perf_counter()
        with assignment.AssignmentArchiveReader(
            archive_path, expected=archive, verify_body=True
        ) as local_reader:
            local_values = OffsetAssignment(
                local_reader, LOCAL_WIRE_START, archive.wires
            )
            composed = CompositeAssignment(global_values, local_values)
            verified = producer.build_tree_producer(
                cap.PRODUCTION_PARAMETERS,
                randomness,
                None,
                TREE_INDEX,
                producer_material=material,
                external_point_starts=GLOBAL_POINT_STARTS,
                local_wire_start=LOCAL_WIRE_START,
                verification_assignment=composed,
                capture_rows=labels + point_labels,
                captured_rows_output=captured,
                progress=progress,
            )
            if verified.verification_failures:
                raise AssertionError(
                    "production tree-0 replay failed first at "
                    f"{verified.first_verification_failure}"
                )
            if (
                verified.wires != archive.wires
                or verified.stream_sha256 != archive.row_stream_sha256
            ):
                raise AssertionError("production tree-0 replay topology mismatch")
            standard_probes = assignment.run_tamper_probes(
                composed, captured, labels
            )
            point_probes = _run_point_probes(composed, captured)
        verification_seconds = time.perf_counter() - verification_started
    if not all(probe.rejected for probe in standard_probes):
        raise AssertionError("a production tree-0 producer probe was accepted")
    if not all(probe.rejected for probe in point_probes):
        raise AssertionError("a production point-wire probe was accepted")
    _atomic_json(
        stage_path,
        {
            "format": "PQRBBC-PRODUCTION-PRODUCER-RESUME-1",
            "stage": "complete",
            "archive_sha256": archive.archive_sha256,
            "row_stream_sha256": archive.row_stream_sha256,
            "verification_failures": verified.verification_failures,
        },
    )
    return ProductionTree0Result(
        verified,
        archive,
        component_sha,
        point_values,
        standard_probes,
        point_probes,
        generation_seconds,
        verification_seconds,
        resumed_cache,
        resumed_prefix,
    )


def _tail_ports(document: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    ports = document.get("ports")
    if not isinstance(ports, list):
        raise ValueError("global-tail manifest lacks ports")
    return {
        str(item["port_id"]): item
        for item in ports
        if isinstance(item, dict)
    }


def build_manifest(
    result: ProductionTree0Result,
    global_manifest_path: Path,
) -> dict[str, object]:
    source = json.loads(global_manifest_path.read_text(encoding="utf-8"))
    consumers = _tail_ports(source)
    output_matches: list[dict[str, object]] = []
    for port in result.summary.ports:
        if port.direction != "output":
            continue
        consumer = consumers.get(port.port_id)
        if consumer is None:
            raise ValueError(f"production tail port missing: {port.port_id}")
        output_matches.append(
            {
                "port_id": port.port_id,
                "producer_wire_start": port.wire_start,
                "consumer_wire_start": consumer["consumer_wire_start"],
                "bit_length": port.bit_length,
                "value_sha256": port.value_sha256,
                "exact_value_match": (
                    port.bit_length == consumer["bit_length"]
                    and port.value_sha256 == consumer["value_sha256"]
                ),
                "exact_wire_identity": False,
            }
        )
    all_outputs_match = len(output_matches) == 4 and all(
        bool(item["exact_value_match"]) for item in output_matches
    )
    point_identity = (
        result.summary.imported_point_wires == GLOBAL_POINT_STARTS
        and not validate_point_imports(result.summary.imported_point_wires)
        and all(probe.rejected for probe in result.point_probes)
    )
    native_closed = (
        result.summary.tree_index == TREE_INDEX
        and result.summary.leaves == LEAVES
        and result.summary.extension_degree == EXTENSION_DEGREE
        and result.summary.verification_failures == 0
        and result.summary.external_assertions == 0
        and result.summary.rows == FROZEN_ROWS
        and result.summary.wires == FROZEN_LOCAL_WIRES
        and result.summary.max_wire_id == FROZEN_MAX_WIRE_ID
        and result.summary.stream_bytes == FROZEN_STREAM_BYTES
        and result.summary.stream_sha256 == FROZEN_STREAM_SHA256
        and result.archive.archive_bytes == FROZEN_ASSIGNMENT_BYTES
        and result.archive.archive_sha256 == FROZEN_ASSIGNMENT_SHA256
        and result.tree_component_sha256 == FROZEN_TREE_COMPONENT_SHA256
        and producer._field_tuple_digest(result.global_point_values)
        == FROZEN_POINT_VALUE_SHA256
        and tuple(
            port.wire_start
            for port in result.summary.ports
            if port.direction == "output"
        )
        == FROZEN_OUTPUT_WIRE_STARTS
        and all(probe.rejected for probe in result.standard_probes)
        and all_outputs_match
        and point_identity
    )
    return {
        "implementation_version": IMPLEMENTATION_VERSION,
        "profile": {
            "relation_id": RELATION_ID,
            "cap_profile_fingerprint": cap.profile_fingerprint(
                cap.PRODUCTION_PARAMETERS
            ),
            "tree_index": TREE_INDEX,
            "leaves": LEAVES,
            "extension_degree": EXTENSION_DEGREE,
            "assignment_format": assignment.ASSIGNMENT_FORMAT,
            "resume_format": "PQRBBC-PRODUCTION-PRODUCER-RESUME-1",
        },
        "trace": {
            "rows": result.summary.rows,
            "local_wires": result.summary.wires,
            "local_wire_start": result.summary.local_wire_start,
            "max_wire_id": result.summary.max_wire_id,
            "nonlinear_rows": result.summary.nonlinear_rows,
            "linear_rows": result.summary.linear_rows,
            "stream_bytes": result.summary.stream_bytes,
            "stream_sha256": result.summary.stream_sha256,
            "external_assertions": result.summary.external_assertions,
            "verification_failures": result.summary.verification_failures,
            "groups": [asdict(group) for group in result.summary.groups],
            "sponge_accounting": asdict(result.summary.sponge_accounting),
            "horner_accounting": asdict(result.summary.horner_accounting),
            "generation_seconds": result.generation_seconds,
            "verification_seconds": result.verification_seconds,
            "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        },
        "tree_component": {
            "sha256": result.tree_component_sha256,
            "matches_frozen_v2_8_full_profile_execution": (
                result.tree_component_sha256 == FROZEN_TREE_COMPONENT_SHA256
            ),
        },
        "point_import": {
            "wire_starts": list(GLOBAL_POINT_STARTS),
            "bit_length_each": field.FIELD_DEGREE,
            "local_copy_allocated": False,
            "source_relation_id": tail.RELATION_ID,
            "source_assignment_sha256": tail.FROZEN_PRODUCTION_ASSIGNMENT_SHA256,
            "value_sha256": producer._field_tuple_digest(result.global_point_values),
            "mutations": [asdict(probe) for probe in result.point_probes],
        },
        "producer_ports": [asdict(port) for port in result.summary.ports],
        "output_matches": output_matches,
        "assignment_archive": asdict(result.archive),
        "stale_witness_probes": [
            asdict(probe) for probe in result.standard_probes
        ],
        "resume_evidence": {
            "execution_cache_checkpointed_per_ggm_level": True,
            "execution_cache_checkpointed_every_leaf_batch": CHECKPOINT_BATCH_LEAVES,
            "assignment_prefix_preserved_on_interruption": True,
            "generation_and_replay_separate_stages": True,
            "resumed_execution_cache_this_run": result.resumed_execution_cache,
            "resumed_assignment_prefix_wires_this_run": (
                result.resumed_assignment_prefix_wires
            ),
        },
        "claim_boundary": {
            "production_index0_4096_degree13_producer_native_closed": native_closed,
            "production_index0_point_wire_identity_closed": point_identity,
            "production_index0_output_values_match_tail": all_outputs_match,
            "production_tree_producer_segments_materialized": False,
            "producer_point_wire_identity_closed": False,
            "production_index2_2048_degree12_producer_native_closed": False,
            "all_four_output_relocations_closed": False,
            "complete_18_tree_assignment_replayed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--global-archive", type=Path, required=True)
    parser.add_argument("--global-manifest", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=max(1, min(8, os.cpu_count() or 1)))
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    result = build_production_tree0(
        args.output_directory,
        args.global_archive,
        args.global_manifest,
        workers=args.workers,
        replace=args.replace,
        progress=lambda message: print(message, flush=True),
    )
    manifest = build_manifest(result, args.global_manifest)
    _atomic_json(args.manifest, manifest)
    print(
        json.dumps(
            {
                "archive": str(
                    args.output_directory
                    / "pq_rbbc_production_tree_0_producer_v2_13.f193assign"
                ),
                "manifest": str(args.manifest),
                "rows": result.summary.rows,
                "local_wires": result.summary.wires,
                "verification_failures": result.summary.verification_failures,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
