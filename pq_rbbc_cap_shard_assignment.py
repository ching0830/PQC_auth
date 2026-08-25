#!/usr/bin/env python3
"""Assignment-backed verifier for the PQ-RBBC production-tree shards.

The v2.5 shard froze the complete row topology without retaining roughly
twenty million Python integers.  This module closes the next engineering
boundary: every wire is written as one canonical 25-byte GF(2^193) element,
the archive is memory-mapped, and the unchanged row generator is replayed
against that assignment.  Selected exact rows are also checked after a
single stale value is injected.

This remains a non-secure, one-tree shard.  It is not the 18-tree issuance
relation and it is not a post-quantum proof backend.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
import struct
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_anemoi_sponge as sponge
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_shard_stream as shard


IMPLEMENTATION_VERSION = "2.7"
ASSIGNMENT_FORMAT = "PQRBBC-F193-ASSIGNMENT-LE25-1"
ASSIGNMENT_MAGIC = b"PQRBBC-F193-ASSIGNMENT-V1"
ASSIGNMENT_HEADER = struct.Struct("<32sHHIQQ32s32s8s")
ASSIGNMENT_HEADER_BYTES = ASSIGNMENT_HEADER.size
ASSIGNMENT_VERSION = 1
ASSIGNMENT_BUFFER_BYTES = 8 * 1024 * 1024

FROZEN_PRODUCTION_ASSIGNMENT_BODY_BYTES = 497_583_100
FROZEN_PRODUCTION_ASSIGNMENT_BODY_SHA256 = (
    "e16ca6a9228f9f13901d0e0228751010fa25889ed02a7291aaceebe69590843a"
)
FROZEN_PRODUCTION_ASSIGNMENT_ARCHIVE_BYTES = 497_583_228
FROZEN_PRODUCTION_ASSIGNMENT_ARCHIVE_SHA256 = (
    "6df38b0cadc2390ea953511ed20c1c22668f85f63a0519965f2d5a78b44d0095"
)
FROZEN_PRODUCTION_VERIFIED_ROWS = shard.FROZEN_PRODUCTION_ROWS
FROZEN_PRODUCTION_VERIFICATION_FAILURES = 0
FROZEN_PRODUCTION_STALE_WITNESS_PROBES = 5

FROZEN_PRODUCTION_4096_ASSIGNMENT_BODY_BYTES = 994_739_100
FROZEN_PRODUCTION_4096_ASSIGNMENT_BODY_SHA256 = (
    "e61fc4fec72b302a0eaf83680044242c5cc87aedc79db23fec6d681e55f04947"
)
FROZEN_PRODUCTION_4096_ASSIGNMENT_ARCHIVE_BYTES = 994_739_228
FROZEN_PRODUCTION_4096_ASSIGNMENT_ARCHIVE_SHA256 = (
    "e4dea88f7f47849cd858d3ba2d5110bd1893efb1ac4544a8b2cb8a0e7fa87aa1"
)
FROZEN_PRODUCTION_4096_VERIFIED_ROWS = shard.FROZEN_PRODUCTION_4096_ROWS
FROZEN_PRODUCTION_4096_VERIFICATION_FAILURES = 0
FROZEN_PRODUCTION_4096_STALE_WITNESS_PROBES = 5


@dataclass(frozen=True)
class AssignmentArchiveMetadata:
    format: str
    header_bytes: int
    field_degree: int
    value_bytes: int
    wires: int
    body_bytes: int
    body_sha256: str
    row_stream_sha256: str
    archive_bytes: int
    archive_sha256: str


@dataclass(frozen=True)
class TamperProbe:
    label: str
    wire: int
    original_value_hex: str
    stale_value_hex: str
    honest_row_satisfied: bool
    stale_row_satisfied: bool
    rejected: bool


@dataclass(frozen=True)
class AssignmentBackedShardResult:
    generated: shard.ShardTraceSummary
    verified: shard.ShardTraceSummary
    archive: AssignmentArchiveMetadata
    tamper_probes: tuple[TamperProbe, ...]
    generation_seconds: float
    verification_seconds: float


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            block = source.read(ASSIGNMENT_BUFFER_BYTES)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


class AssignmentArchiveWriter:
    """Append-only fixed-width archive writer implementing shard.AssignmentWriter."""

    def __init__(self, path: Path, *, replace: bool = False) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = path.open("w+b" if replace else "x+b")
        self._file.write(bytes(ASSIGNMENT_HEADER_BYTES))
        self._buffer = bytearray()
        self._body_digest = hashlib.sha256()
        self.wires = 0
        self.body_bytes = 0
        self.closed = False

    def _append(self, encoded: bytes, count: int) -> None:
        if self.closed:
            raise RuntimeError("assignment archive writer is closed")
        expected = count * field.FIELD_ELEMENT_BYTES
        if len(encoded) != expected:
            raise ValueError("assignment archive append width mismatch")
        self._body_digest.update(encoded)
        self._buffer.extend(encoded)
        self.wires += count
        self.body_bytes += len(encoded)
        if len(self._buffer) >= ASSIGNMENT_BUFFER_BYTES:
            self._flush_buffer()

    def append_values(self, values: Sequence[int]) -> None:
        encoded = bytearray()
        for value in values:
            if not 0 <= value <= field.FIELD_MASK:
                raise ValueError("non-canonical GF(2^193) assignment value")
            encoded.extend(value.to_bytes(field.FIELD_ELEMENT_BYTES, "little"))
        self._append(bytes(encoded), len(values))

    def append_encoded(self, encoded: bytes, count: int) -> None:
        self._append(encoded, count)

    def _flush_buffer(self) -> None:
        if self._buffer:
            self._file.write(self._buffer)
            self._buffer.clear()

    def finish(
        self,
        expected_wires: int,
        row_stream_sha256: str,
    ) -> AssignmentArchiveMetadata:
        if self.closed:
            raise RuntimeError("assignment archive writer already closed")
        if self.wires != expected_wires:
            raise AssertionError(
                f"assignment has {self.wires} wires, expected {expected_wires}"
            )
        if len(row_stream_sha256) != 64:
            raise ValueError("row stream SHA-256 must be hexadecimal")
        self._flush_buffer()
        if self.body_bytes != self.wires * field.FIELD_ELEMENT_BYTES:
            raise AssertionError("assignment body size mismatch")
        body_sha256 = self._body_digest.hexdigest()
        header = ASSIGNMENT_HEADER.pack(
            ASSIGNMENT_MAGIC,
            ASSIGNMENT_VERSION,
            field.FIELD_DEGREE,
            field.FIELD_ELEMENT_BYTES,
            self.wires,
            self.body_bytes,
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
        archive_bytes = ASSIGNMENT_HEADER_BYTES + self.body_bytes
        if self.path.stat().st_size != archive_bytes:
            raise AssertionError("assignment archive file size mismatch")
        return AssignmentArchiveMetadata(
            ASSIGNMENT_FORMAT,
            ASSIGNMENT_HEADER_BYTES,
            field.FIELD_DEGREE,
            field.FIELD_ELEMENT_BYTES,
            self.wires,
            self.body_bytes,
            body_sha256,
            row_stream_sha256,
            archive_bytes,
            _hash_file(self.path),
        )

    def abort(self) -> None:
        if not self.closed:
            self._file.close()
            self.closed = True
        self.path.unlink(missing_ok=True)


class AssignmentArchiveReader(Mapping[int, int]):
    """Read-only one-based wire mapping backed by mmap."""

    def __init__(
        self,
        path: Path,
        *,
        expected: AssignmentArchiveMetadata | None = None,
        verify_body: bool = True,
    ) -> None:
        self.path = path
        self._file = path.open("rb")
        encoded_header = self._file.read(ASSIGNMENT_HEADER_BYTES)
        if len(encoded_header) != ASSIGNMENT_HEADER_BYTES:
            self._file.close()
            raise ValueError("truncated assignment archive header")
        (
            magic,
            version,
            degree,
            value_bytes,
            wires,
            body_bytes,
            body_digest,
            row_digest,
            reserved,
        ) = ASSIGNMENT_HEADER.unpack(encoded_header)
        if magic.rstrip(b"\x00") != ASSIGNMENT_MAGIC:
            self._file.close()
            raise ValueError("assignment archive magic mismatch")
        if (
            version != ASSIGNMENT_VERSION
            or degree != field.FIELD_DEGREE
            or value_bytes != field.FIELD_ELEMENT_BYTES
            or reserved != bytes(8)
        ):
            self._file.close()
            raise ValueError("unsupported assignment archive profile")
        if body_bytes != wires * value_bytes:
            self._file.close()
            raise ValueError("assignment archive body width mismatch")
        if path.stat().st_size != ASSIGNMENT_HEADER_BYTES + body_bytes:
            self._file.close()
            raise ValueError("assignment archive file size mismatch")
        self.wires = wires
        self.body_bytes = body_bytes
        self.body_sha256 = body_digest.hex()
        self.row_stream_sha256 = row_digest.hex()
        if expected is not None:
            if (
                expected.wires != self.wires
                or expected.body_bytes != self.body_bytes
                or expected.body_sha256 != self.body_sha256
                or expected.row_stream_sha256 != self.row_stream_sha256
            ):
                self._file.close()
                raise ValueError("assignment archive metadata mismatch")
        self._map = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        if verify_body:
            digest = hashlib.sha256()
            view = memoryview(self._map)
            try:
                start = ASSIGNMENT_HEADER_BYTES
                while start < len(view):
                    end = min(len(view), start + ASSIGNMENT_BUFFER_BYTES)
                    digest.update(view[start:end])
                    start = end
            finally:
                view.release()
            if digest.hexdigest() != self.body_sha256:
                self.close()
                raise ValueError("assignment archive body digest mismatch")

    def __getitem__(self, wire: int) -> int:
        if not 1 <= wire <= self.wires:
            raise KeyError(wire)
        offset = ASSIGNMENT_HEADER_BYTES + (
            wire - 1
        ) * field.FIELD_ELEMENT_BYTES
        value = int.from_bytes(
            self._map[offset : offset + field.FIELD_ELEMENT_BYTES], "little"
        )
        if value > field.FIELD_MASK:
            raise ValueError(f"wire {wire} has a non-canonical field value")
        return value

    def __iter__(self):
        return iter(range(1, self.wires + 1))

    def __len__(self) -> int:
        return self.wires

    def close(self) -> None:
        if hasattr(self, "_map"):
            self._map.close()
            del self._map
        self._file.close()

    def __enter__(self) -> "AssignmentArchiveReader":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


class StaleAssignment(Mapping[int, int]):
    def __init__(self, base: Mapping[int, int], wire: int, value: int) -> None:
        self.base = base
        self.wire = wire
        self.value = value

    def __getitem__(self, wire: int) -> int:
        return self.value if wire == self.wire else self.base[wire]

    def __iter__(self):
        return iter(self.base)

    def __len__(self) -> int:
        return len(self.base)


def capture_labels(parameters: cap.CAPParameters, reference_calls: int) -> tuple[str, ...]:
    leaves = parameters.expanded_leaf_counts()[0]
    salt_payload_bit = (len(sponge.TRANSCRIPT_MAGIC) + 2 + 8) * 8
    coefficient_count = (
        parameters.witness_bits + field.FIELD_DEGREE - 1
    ) // field.FIELD_DEGREE
    return (
        (
            "xof[0].tree[0].derive[2,1]"
            f".payload[{salt_payload_bit}].source"
        ),
        (
            f"xof[{leaves - 1}].tree[0].leaf[1].tape"
            ".digest.lane[0].pack"
        ),
        f"horner.leaf[1].point[0].mul[{coefficient_count - 2}]",
        "output.commitment[0].link",
        (
            f"xof[{reference_calls}].request-binding"
            ".digest.lane[0].pack"
        ),
    )


def _tamper_wire(row: field.RankOneRow) -> int:
    for form in (row.output, row.left, row.right):
        if form.terms:
            return form.terms[0][0]
    raise AssertionError("captured row has no wire")


def run_tamper_probes(
    assignment: Mapping[int, int],
    rows: Mapping[str, field.RankOneRow],
    labels: Sequence[str],
) -> tuple[TamperProbe, ...]:
    probes: list[TamperProbe] = []
    for label in labels:
        if label not in rows:
            raise AssertionError(f"capture label was not emitted: {label}")
        row = rows[label]
        wire = _tamper_wire(row)
        original = assignment[wire]
        stale = original ^ 1
        honest_satisfied = shard._row_satisfied_fast(row, assignment)
        stale_satisfied = shard._row_satisfied_fast(
            row, StaleAssignment(assignment, wire, stale)
        )
        probes.append(
            TamperProbe(
                label,
                wire,
                original.to_bytes(field.FIELD_ELEMENT_BYTES, "little").hex(),
                stale.to_bytes(field.FIELD_ELEMENT_BYTES, "little").hex(),
                honest_satisfied,
                stale_satisfied,
                honest_satisfied and not stale_satisfied,
            )
        )
    return tuple(probes)


def build_assignment_backed_shard(
    archive_path: Path,
    parameters: cap.CAPParameters = shard.PRODUCTION_TREE_SHARD_PARAMETERS,
    randomness: cap.CAPRandomness | None = None,
    message: bytes = bytes(32),
    *,
    workers: int = 1,
    execution: cap.CAPExecution | None = None,
    progress: Callable[[str], None] | None = None,
    replace: bool = False,
) -> AssignmentBackedShardResult:
    randomness = randomness or cap.deterministic_randomness(parameters)
    execution = execution or shard.build_parallel_execution(
        parameters, randomness, workers=workers, progress=progress
    )
    labels = capture_labels(parameters, len(execution.xof_calls))
    captured: dict[str, field.RankOneRow] = {}
    writer = AssignmentArchiveWriter(archive_path, replace=replace)
    generation_started = time.perf_counter()
    try:
        generated = shard.build_streaming_shard(
            parameters,
            randomness,
            message,
            workers=workers,
            execution=execution,
            progress=progress,
            assignment_writer=writer,
            capture_labels=labels,
            captured_rows_output=captured,
        )
        archive = writer.finish(generated.wires, generated.stream_sha256)
    except BaseException:
        writer.abort()
        raise
    generation_seconds = time.perf_counter() - generation_started
    if progress is not None:
        progress(
            f"assignment archive complete: {archive.wires} wires, "
            f"{archive.archive_bytes} bytes"
        )

    verification_started = time.perf_counter()
    with AssignmentArchiveReader(
        archive_path, expected=archive, verify_body=True
    ) as assignment:
        verified = shard.build_streaming_shard(
            parameters,
            randomness,
            message,
            workers=1,
            execution=execution,
            progress=progress,
            verification_assignment=assignment,
        )
        if verified.verification_failures:
            raise AssertionError(
                "assignment verification failed first at "
                f"{verified.first_verification_failure}"
            )
        if (
            verified.wires != generated.wires
            or verified.rows != generated.rows
            or verified.stream_sha256 != generated.stream_sha256
        ):
            raise AssertionError("verification replay topology mismatch")
        tamper_probes = run_tamper_probes(assignment, captured, labels)
    verification_seconds = time.perf_counter() - verification_started
    if not all(probe.rejected for probe in tamper_probes):
        raise AssertionError("a stale-witness probe was accepted")
    if progress is not None:
        progress(
            f"assignment verification complete: {verified.rows} rows, "
            f"{verified.verification_failures} failures"
        )
    return AssignmentBackedShardResult(
        generated,
        verified,
        archive,
        tamper_probes,
        generation_seconds,
        verification_seconds,
    )


def build_manifest(result: AssignmentBackedShardResult) -> dict[str, object]:
    generated = result.generated
    verified = result.verified
    parameters = generated.parameters
    base = shard.build_manifest(generated)
    base["implementation_version"] = IMPLEMENTATION_VERSION
    base["profile"]["assignment_format"] = ASSIGNMENT_FORMAT
    base["trace"]["assignment_materialized"] = True
    base["trace"]["generation_seconds"] = result.generation_seconds
    base["trace"]["verification_seconds"] = result.verification_seconds
    base["assignment_archive"] = asdict(result.archive)
    base["whole_shard_verification"] = {
        "mode": "mmap fixed-width assignment replay",
        "rows_checked": verified.rows,
        "wires_loaded": verified.wires,
        "failures": verified.verification_failures,
        "first_failure": verified.first_verification_failure,
        "row_stream_sha256": verified.stream_sha256,
        "topology_matches_generation": (
            verified.stream_sha256 == generated.stream_sha256
        ),
    }
    base["stale_witness_probes"] = [
        asdict(probe) for probe in result.tamper_probes
    ]
    base["implemented"].update(
        {
            "full_assignment_archive_materialized": True,
            "whole_shard_assignment_verified": (
                verified.verification_failures == 0
                and verified.rows == generated.rows
            ),
            "stale_witness_probes_rejected": all(
                probe.rejected for probe in result.tamper_probes
            ),
        }
    )
    base["claim_boundary"]["production_tree_shard_assignment_closed"] = (
        (
            (
                parameters.expanded_leaf_counts() == (1 << 11,)
                and parameters.expanded_extension_degrees() == (12,)
            )
            or (
                parameters.expanded_leaf_counts() == (1 << 12,)
                and parameters.expanded_extension_degrees() == (13,)
            )
        )
        and generated.assignment_materialized
        and verified.verification_failures == 0
        and all(probe.rejected for probe in result.tamper_probes)
    )
    base["claim_boundary"]["production_2048_degree_12_assignment_closed"] = (
        parameters.expanded_leaf_counts() == (1 << 11,)
        and parameters.expanded_extension_degrees() == (12,)
        and base["claim_boundary"]["production_tree_shard_assignment_closed"]
    )
    base["claim_boundary"]["production_4096_degree_13_assignment_closed"] = (
        parameters.expanded_leaf_counts() == (1 << 12,)
        and parameters.expanded_extension_degrees() == (13,)
        and base["claim_boundary"]["production_tree_shard_assignment_closed"]
    )
    base["claim_boundary"]["remaining"] = [
        "compose all 18 production trees",
        "replace the parent archive external assertion",
        "complete fork-specific extraction and security proofs",
        "qualify the post-quantum proof backend and benchmark signatures",
    ]
    return base


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument(
        "--fixture",
        choices=("probe", "production", "production4096"),
        default="probe",
    )
    parser.add_argument(
        "--workers", type=int, default=max(1, min(8, os.cpu_count() or 1))
    )
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    parameters = {
        "probe": shard.PROBE_PARAMETERS,
        "production": shard.PRODUCTION_TREE_SHARD_PARAMETERS,
        "production4096": shard.PRODUCTION_TREE_SHARD_4096_PARAMETERS,
    }[args.fixture]
    result = build_assignment_backed_shard(
        args.archive,
        parameters,
        workers=args.workers,
        replace=args.replace,
        progress=lambda message: print(message, flush=True),
    )
    encoded = json.dumps(build_manifest(result), indent=2, sort_keys=True) + "\n"
    if args.manifest:
        args.manifest.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
