#!/usr/bin/env python3
"""GF(2^193) parent CAP-to-H_RBBC join replay for PQ-RBBC v2.29.

The parent circuit remains the executable v2.20 issuance relation.  This
module changes neither its ticket payload nor its lifecycle.  It builds a
production-CAP-bound fixture, lifts every Boolean parent row into the native
characteristic-two field, rebases only the parent's non-constant wires after
the frozen v2.28 aggregate namespace, and replaces the one legacy external
assertion with exact wire equalities.

Large relation and assignment archives are execution artifacts.  They are
written only to caller-selected paths and are not portable evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
import struct
import tempfile
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import BinaryIO, Mapping, Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_anemoi_sponge as sponge
import pq_rbbc_blind_uov_abi as blind_uov
import pq_rbbc_cap_aggregate_preflight as aggregate_preflight
import pq_rbbc_cap_aggregate_replay as aggregate_replay
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_composer as composer
import pq_rbbc_cap_composer_recovery as composer_recovery
import pq_rbbc_cap_global_tail as global_tail
import pq_rbbc_cap_planned_tree_producer as planned
import pq_rbbc_cap_shard_assignment as shard_assignment
import pq_rbbc_reference as reference


IMPLEMENTATION_VERSION = "2.29"
RELATION_ID = "pq-rbbc/parent-cap-to-h-rbbc/v1"
ARCHIVE_FORMAT = "PQRBBC-PARENT-JOIN-GF193-1"
ASSIGNMENT_FORMAT = "PQRBBC-PARENT-SEGMENT-ASSIGNMENT-GF193-1"

AGGREGATE_ROWS = 586_057_567
AGGREGATE_MAX_WIRE_ID = 429_757_232
PARENT_LOCAL_WIRES = 2_980_304
PARENT_INTERNAL_ROWS = 2_971_580
PARENT_NONCONSTANT_WIRES = PARENT_LOCAL_WIRES - 2
PARENT_WIRE_START = AGGREGATE_MAX_WIRE_ID + 1
PARENT_WIRE_END = PARENT_WIRE_START + PARENT_NONCONSTANT_WIRES - 1
MESSAGE_BITS = 256
MASK_BITS = 576
HASH_IMAGE_BITS = 576
JOIN_ROWS = MESSAGE_BITS + MASK_BITS + HASH_IMAGE_BITS
PARENT_JOIN_ROWS = PARENT_INTERNAL_ROWS + JOIN_ROWS
COMBINED_ROWS = AGGREGATE_ROWS + PARENT_JOIN_ROWS

MESSAGE_WIRE_START = 387
COMMITMENT_WIRE_START = 40_084_506
COMMITMENT_BITS = 43_128
MASK_WIRE_START = 40_127_634
HASH_IMAGE_WIRE_START = 40_194_018
EXTERNAL_ASSERTION_ID = (
    "native_pq_rbbc_cap_v1_full_18_tree_row_stream_and_h_rbbc_wire_join"
)

TAG_INPUT = 1
TAG_LINEAR_DEFINITION = 2
TAG_MULTIPLICATION = 3
TAG_LINEAR_ASSERTION = 4
TAG_KECCAK_PERMUTATION = 5
TAG_JOIN_ASSERTION = 6
VISIBILITY_PUBLIC = 0
VISIBILITY_SECRET = 1
KIND_AND = 0
KIND_BITNESS = 1
PORT_MESSAGE = 0
PORT_MASK = 1
PORT_HASH_IMAGE = 2

ARCHIVE_MAGIC = b"PQRBBC-PARENT-JOIN-GF193-V1"
ARCHIVE_VERSION = 1
# magic, version, degree, fourteen uint64 values, two digests, reserved.
ARCHIVE_HEADER = struct.Struct("<32sHH" + "Q" * 14 + "32s32s8s")
ASSIGNMENT_MAGIC = b"PQRBBC-PARENT-ASSIGN-GF193-V1"
ASSIGNMENT_VERSION = 1
ASSIGNMENT_HEADER = struct.Struct("<32sHHIQQQQ32s32s8s")
BUFFER_BYTES = 8 * 1024 * 1024


def canonical_json(document: Mapping[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(BUFFER_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _encode_uvarint(value: int) -> bytes:
    if value < 0:
        raise ValueError("unsigned varint cannot encode a negative value")
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _append_ids(record: bytearray, identifiers: Sequence[int]) -> None:
    record.extend(_encode_uvarint(len(identifiers)))
    for identifier in identifiers:
        record.extend(_encode_uvarint(identifier))


class JoinArchiveError(ValueError):
    """The joined parent archive or assignment is malformed."""


class _BodyWriter:
    def __init__(self, handle: BinaryIO) -> None:
        self.handle = handle
        self.buffer = bytearray()
        self.hasher = hashlib.sha256()
        self.length = 0

    def write(self, data: bytes | bytearray) -> None:
        self.buffer.extend(data)
        if len(self.buffer) >= BUFFER_BYTES:
            self.flush()

    def flush(self) -> None:
        if not self.buffer:
            return
        chunk = bytes(self.buffer)
        self.handle.write(chunk)
        self.hasher.update(chunk)
        self.length += len(chunk)
        self.buffer.clear()


@dataclass(frozen=True)
class SourcePort:
    port_id: str
    wire_start: int
    value: bytes

    @property
    def bit_length(self) -> int:
        return len(self.value) * 8

    def bits(self) -> tuple[int, ...]:
        return tuple((byte >> bit) & 1 for byte in self.value for bit in range(8))


@dataclass(frozen=True)
class ParentBoundFixture:
    matrix: reference.SystematicParityCheck
    statement: reference.IssueStatement
    witness: reference.IssueWitness
    adapter: "ExactProductionCAPAdapter"
    message: bytes
    commitment: bytes
    mask: bytes
    hash_image: bytes


class ExactProductionCAPAdapter:
    """Exact adapter used only to validate the pre-lowering parent fixture."""

    name = "PQ-RBBC-v2.29-EXACT-PRODUCTION-CAP-BOUND"

    def __init__(self, message: bytes, commitment: cap.CAPCommitment) -> None:
        state = blind_uov.request_from_production_cap(message, commitment)
        self.message = message
        self.mask = state.mask
        self.hash_image_value = state.hash_image
        self.request = state.request

    def create(
        self, message: bytes, mask: bytes, cap_randomness: bytes
    ) -> blind_uov.BlindUOVRequest:
        if message != self.message or mask != self.mask or len(cap_randomness) != 32:
            raise ValueError("parent fixture is not bound to the exact production CAP")
        return self.request

    def hash_image(
        self, message: bytes, mask: bytes, cap_randomness: bytes
    ) -> bytes:
        if message != self.message or mask != self.mask or len(cap_randomness) != 32:
            raise ValueError("parent fixture is not bound to the exact production CAP")
        return self.hash_image_value

    def verify_cap_hash(
        self,
        message: bytes,
        mask: bytes,
        cap_randomness: bytes,
        hash_image: bytes,
    ) -> bool:
        return (
            message == self.message
            and mask == self.mask
            and len(cap_randomness) == 32
            and hash_image == self.hash_image_value
        )

    def verify(
        self,
        request: blind_uov.BlindUOVRequest,
        message: bytes,
        mask: bytes,
        cap_randomness: bytes,
    ) -> bool:
        return request == self.request and self.verify_cap_hash(
            message, mask, cap_randomness, self.hash_image_value
        )


def build_parent_bound_fixture(execution: cap.CAPExecution) -> ParentBoundFixture:
    """Keep the reference ticket intact and bind its digest to production CAP."""

    matrix, base_statement, base_witness, _ = reference.reference_fixture()
    message = hashlib.shake_256(
        reference.LABEL_TICKET + base_statement.payload.encode()
    ).digest(32)
    adapter = ExactProductionCAPAdapter(message, execution.commitment)
    statement = replace(base_statement, blind_request=adapter.request)
    witness = replace(
        base_witness,
        blind_mask=adapter.mask,
        blind_hash_image=adapter.hash_image_value,
    )
    result = reference.verify_relation(matrix, statement, witness, adapter)
    if not result.ok:
        raise AssertionError("parent-bound fixture rejected: " + ",".join(result.failures))
    return ParentBoundFixture(
        matrix,
        statement,
        witness,
        adapter,
        message,
        execution.commitment.encoded,
        adapter.mask,
        adapter.hash_image_value,
    )


def source_ports(fixture: ParentBoundFixture) -> tuple[SourcePort, ...]:
    return (
        SourcePort("shared.message", MESSAGE_WIRE_START, fixture.message),
        SourcePort(
            "global.phase-b.commitment", COMMITMENT_WIRE_START, fixture.commitment
        ),
        SourcePort("global.phase-b.derived-mask", MASK_WIRE_START, fixture.mask),
        SourcePort(
            "global.phase-b.request-hash", HASH_IMAGE_WIRE_START, fixture.hash_image
        ),
    )


def source_assignment(ports: Sequence[SourcePort]) -> dict[int, int]:
    values: dict[int, int] = {}
    for port in ports:
        for offset, value in enumerate(port.bits()):
            wire = port.wire_start + offset
            if wire in values and values[wire] != value:
                raise ValueError("source port intervals overlap inconsistently")
            values[wire] = value
    return values


@dataclass(frozen=True)
class JoinArchiveMetadata:
    format: str
    field: str
    aggregate_max_wire_id: int
    parent_wire_start: int
    parent_wire_end: int
    parent_local_wires: int
    public_inputs: int
    secret_inputs: int
    linear_definitions: int
    linear_assertions: int
    nonlinear_constraints: int
    join_rows: int
    parent_join_rows: int
    external_assertions: int
    keccak_permutations: int
    body_bytes: int
    body_sha256: str
    archive_bytes: int
    archive_sha256: str


@dataclass(frozen=True)
class ParentAssignmentMetadata:
    format: str
    field: str
    value_bytes: int
    parent_wire_start: int
    parent_wire_end: int
    wires: int
    body_bytes: int
    body_sha256: str
    row_stream_sha256: str
    archive_bytes: int
    archive_sha256: str


@dataclass(frozen=True)
class JoinedParentResult:
    report: reference.CircuitReport
    archive: JoinArchiveMetadata
    assignment: ParentAssignmentMetadata
    parent_destination_intervals: dict[str, tuple[int, int]]


def _normalize_linear(
    identifiers: Sequence[int], constant: int
) -> tuple[tuple[int, ...], int]:
    mapped: list[int] = []
    folded = constant & 1
    for identifier in identifiers:
        if identifier == 0:
            continue
        if identifier == 1:
            folded ^= 1
            continue
        if not 2 <= identifier < PARENT_LOCAL_WIRES:
            raise JoinArchiveError(f"parent local wire {identifier} is out of range")
        mapped.append(PARENT_WIRE_START + identifier - 2)
    return tuple(mapped), folded


def _map_nonconstant(identifier: int) -> int:
    if not 2 <= identifier < PARENT_LOCAL_WIRES:
        raise JoinArchiveError(
            f"multiplication uses unsupported constant/out-of-range wire {identifier}"
        )
    return PARENT_WIRE_START + identifier - 2


def _map_multiplicand(identifier: int) -> int:
    # Zero and one are inline constant references in multiplication records;
    # all allocated parent wires live above the aggregate namespace.
    if identifier in (0, 1):
        return identifier
    return _map_nonconstant(identifier)


class GF193ParentJoinSink(reference.CountingSink):
    """Stream the rebased parent relation and its segment assignment."""

    def __init__(
        self,
        archive_path: Path,
        assignment_path: Path,
        ports: Sequence[SourcePort],
    ) -> None:
        super().__init__()
        self.archive_path = archive_path
        self.assignment_path = assignment_path
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        assignment_path.parent.mkdir(parents=True, exist_ok=True)
        self._archive_handle = archive_path.open("x+b")
        self._archive_handle.write(bytes(ARCHIVE_HEADER.size))
        self._body = _BodyWriter(self._archive_handle)
        self._assignment_handle = assignment_path.open("x+b")
        self._assignment_handle.write(bytes(ASSIGNMENT_HEADER.size))
        self._assignment_body = _BodyWriter(self._assignment_handle)
        self._next_local = 2
        self._ticket_hash_wires: list[reference.Wire] = []
        self._named_inputs: dict[str, list[reference.Wire]] = {
            "blind_request.y": [],
            "witness.blind_mask": [],
            "witness.blind_hash_image": [],
        }
        self._ports = {port.port_id: port for port in ports}
        self.join_rows = 0
        self._finalized = False

    def _record_new_wire(self, block: str, wire: reference.Wire) -> None:
        if wire.identifier != self._next_local:
            raise JoinArchiveError(
                f"wire allocation is not sequential: {wire.identifier} != {self._next_local}"
            )
        if wire.value not in (0, 1):
            raise JoinArchiveError("parent wire is not Boolean")
        self._next_local += 1
        self._assignment_body.write(
            wire.value.to_bytes(field.FIELD_ELEMENT_BYTES, "little")
        )

    def capture_ticket_digest(self, wires: Sequence[reference.Wire]) -> None:
        if self._ticket_hash_wires:
            raise JoinArchiveError("ticket digest wires were captured twice")
        if len(wires) != MESSAGE_BITS:
            raise JoinArchiveError("ticket digest wire width changed")
        self._ticket_hash_wires = list(wires)

    def input(
        self, block: str, wire: reference.Wire, visibility: str, name: str
    ) -> None:
        super().input(block, wire, visibility, name)
        self._record_new_wire(block, wire)
        for prefix, wires in self._named_inputs.items():
            if name.startswith(prefix + "["):
                wires.append(wire)
                break
        visibility_code = {
            "public": VISIBILITY_PUBLIC,
            "secret": VISIBILITY_SECRET,
        }.get(visibility)
        if visibility_code is None:
            raise JoinArchiveError("unknown parent input visibility")
        record = bytearray((TAG_INPUT,))
        record.extend(_encode_uvarint(_map_nonconstant(wire.identifier)))
        record.append(visibility_code)
        self._body.write(record)

    def linear_definition(
        self,
        block: str,
        output: reference.Wire,
        inputs: Sequence[int],
        constant: int,
    ) -> None:
        super().linear_definition(block, output, inputs, constant)
        self._record_new_wire(block, output)
        mapped, folded = _normalize_linear(inputs, constant)
        record = bytearray((TAG_LINEAR_DEFINITION,))
        record.extend(_encode_uvarint(_map_nonconstant(output.identifier)))
        record.append(folded)
        _append_ids(record, mapped)
        self._body.write(record)

    def multiplication(
        self,
        block: str,
        left: reference.Wire,
        right: reference.Wire,
        output: reference.Wire,
        kind: str,
    ) -> None:
        super().multiplication(block, left, right, output, kind)
        self._record_new_wire(block, output)
        kind_code = {"and": KIND_AND, "bitness": KIND_BITNESS}.get(kind)
        if kind_code is None:
            raise JoinArchiveError("unknown parent multiplication kind")
        record = bytearray((TAG_MULTIPLICATION,))
        record.extend(_encode_uvarint(_map_multiplicand(left.identifier)))
        record.extend(_encode_uvarint(_map_multiplicand(right.identifier)))
        record.extend(_encode_uvarint(_map_nonconstant(output.identifier)))
        record.append(kind_code)
        self._body.write(record)

    def linear_assertion(
        self,
        block: str,
        inputs: Sequence[int],
        constant: int,
        satisfied: bool,
    ) -> None:
        super().linear_assertion(block, inputs, constant, satisfied)
        mapped, folded = _normalize_linear(inputs, constant)
        record = bytearray((TAG_LINEAR_ASSERTION, folded))
        _append_ids(record, mapped)
        self._body.write(record)

    def keccak_permutation(self, block: str) -> None:
        super().keccak_permutation(block)
        self._body.write(bytes((TAG_KECCAK_PERMUTATION,)))

    def _link(
        self,
        block: str,
        parent_wires: Sequence[reference.Wire],
        port_id: str,
        port_code: int,
    ) -> None:
        port = self._ports.get(port_id)
        if port is None:
            raise JoinArchiveError(f"missing source port {port_id}")
        bits = port.bits()
        if len(parent_wires) != len(bits):
            raise JoinArchiveError(f"{port_id} join width mismatch")
        stats = self._stats(block)
        for offset, (parent_wire, source_value) in enumerate(zip(parent_wires, bits)):
            satisfied = parent_wire.value == source_value
            stats.linear_assertions += 1
            if not satisfied:
                stats.failed_assertions += 1
            record = bytearray((TAG_JOIN_ASSERTION, port_code))
            record.extend(_encode_uvarint(_map_nonconstant(parent_wire.identifier)))
            record.extend(_encode_uvarint(port.wire_start + offset))
            self._body.write(record)
            self.join_rows += 1

    def external_assertion(self, block: str, name: str, satisfied: bool) -> None:
        if name != EXTERNAL_ASSERTION_ID:
            raise JoinArchiveError("unexpected parent external assertion")
        if not satisfied:
            raise JoinArchiveError("parent-bound adapter rejected honest fixture")
        if len(self._ticket_hash_wires) != MESSAGE_BITS:
            raise JoinArchiveError("ticket digest wires were not captured")
        ticket = self._ticket_hash_wires
        if reference.wire_bytes(ticket) != self._ports["shared.message"].value:
            raise JoinArchiveError("captured ticket digest does not match source message")
        y = self._named_inputs["blind_request.y"]
        mask = self._named_inputs["witness.blind_mask"]
        image = self._named_inputs["witness.blind_hash_image"]
        if not (len(y) == len(mask) == len(image) == MASK_BITS):
            raise JoinArchiveError("parent Blind-UOV input capture is incomplete")
        self._link(block, ticket, "shared.message", PORT_MESSAGE)
        self._link(block, mask, "global.phase-b.derived-mask", PORT_MASK)
        self._link(
            block, image, "global.phase-b.request-hash", PORT_HASH_IMAGE
        )

    def finalize(self, report: reference.CircuitReport) -> JoinedParentResult:
        if self._finalized:
            raise JoinArchiveError("joined parent sink already finalized")
        if report.wire_count != self._next_local:
            raise JoinArchiveError("parent report wire count mismatch")
        if report.wire_count != PARENT_LOCAL_WIRES:
            raise JoinArchiveError("parent local wire count changed")
        if self.join_rows != JOIN_ROWS:
            raise JoinArchiveError("native join row count changed")
        linear_definitions = sum(x.linear_definitions for x in self.blocks.values())
        linear_assertions = sum(x.linear_assertions for x in self.blocks.values())
        nonlinear = sum(x.nonlinear_constraints for x in self.blocks.values())
        keccak = sum(x.keccak_permutations for x in self.blocks.values())
        total_rows = linear_definitions + linear_assertions + nonlinear
        if total_rows != PARENT_JOIN_ROWS:
            raise JoinArchiveError(f"joined parent rows changed: {total_rows}")
        if self.external_assertions != 0 or report.external_assertions != 0:
            raise JoinArchiveError("parent external assertion was not eliminated")

        self._body.flush()
        self._assignment_body.flush()
        body_sha = self._body.hasher.digest()
        assignment_body_sha = self._assignment_body.hasher.digest()
        assignment_wires = PARENT_NONCONSTANT_WIRES
        assignment_body_bytes = assignment_wires * field.FIELD_ELEMENT_BYTES
        if self._assignment_body.length != assignment_body_bytes:
            raise JoinArchiveError("parent segment assignment width mismatch")
        archive_header = ARCHIVE_HEADER.pack(
            ARCHIVE_MAGIC,
            ARCHIVE_VERSION,
            field.FIELD_DEGREE,
            AGGREGATE_MAX_WIRE_ID,
            PARENT_WIRE_START,
            PARENT_WIRE_END,
            PARENT_LOCAL_WIRES,
            self.public_inputs,
            self.secret_inputs,
            linear_definitions,
            linear_assertions,
            nonlinear,
            self.join_rows,
            total_rows,
            self.external_assertions,
            keccak,
            self._body.length,
            body_sha,
            assignment_body_sha,
            bytes(8),
        )
        self._archive_handle.seek(0)
        self._archive_handle.write(archive_header)
        self._archive_handle.flush()
        os.fsync(self._archive_handle.fileno())
        self._archive_handle.close()
        assignment_header = ASSIGNMENT_HEADER.pack(
            ASSIGNMENT_MAGIC,
            ASSIGNMENT_VERSION,
            field.FIELD_DEGREE,
            field.FIELD_ELEMENT_BYTES,
            PARENT_WIRE_START,
            PARENT_WIRE_END,
            assignment_wires,
            assignment_body_bytes,
            assignment_body_sha,
            body_sha,
            bytes(8),
        )
        self._assignment_handle.seek(0)
        self._assignment_handle.write(assignment_header)
        self._assignment_handle.flush()
        os.fsync(self._assignment_handle.fileno())
        self._assignment_handle.close()
        self._finalized = True
        archive_metadata = JoinArchiveMetadata(
            ARCHIVE_FORMAT,
            "GF(2^193)",
            AGGREGATE_MAX_WIRE_ID,
            PARENT_WIRE_START,
            PARENT_WIRE_END,
            PARENT_LOCAL_WIRES,
            self.public_inputs,
            self.secret_inputs,
            linear_definitions,
            linear_assertions,
            nonlinear,
            self.join_rows,
            total_rows,
            self.external_assertions,
            keccak,
            self._body.length,
            body_sha.hex(),
            self.archive_path.stat().st_size,
            _sha256(self.archive_path),
        )
        assignment_metadata = ParentAssignmentMetadata(
            ASSIGNMENT_FORMAT,
            "GF(2^193)",
            field.FIELD_ELEMENT_BYTES,
            PARENT_WIRE_START,
            PARENT_WIRE_END,
            assignment_wires,
            assignment_body_bytes,
            assignment_body_sha.hex(),
            body_sha.hex(),
            self.assignment_path.stat().st_size,
            _sha256(self.assignment_path),
        )
        destinations: dict[str, tuple[int, int]] = {}
        for name, wires in self._named_inputs.items():
            mapped = tuple(_map_nonconstant(wire.identifier) for wire in wires)
            if not mapped or mapped != tuple(range(mapped[0], mapped[0] + len(mapped))):
                raise JoinArchiveError(f"{name} parent destination is not contiguous")
            destinations[name] = (mapped[0], len(mapped))
        return JoinedParentResult(
            report, archive_metadata, assignment_metadata, destinations
        )

    def close(self) -> None:
        if not self._archive_handle.closed:
            self._archive_handle.close()
        if not self._assignment_handle.closed:
            self._assignment_handle.close()


class ParentAssignmentReader(Mapping[int, int]):
    def __init__(self, path: Path, *, verify_body: bool = True) -> None:
        self.path = path
        self._file = path.open("rb")
        raw = self._file.read(ASSIGNMENT_HEADER.size)
        if len(raw) != ASSIGNMENT_HEADER.size:
            self._file.close()
            raise JoinArchiveError("truncated parent assignment header")
        (
            magic,
            version,
            degree,
            value_bytes,
            self.parent_start,
            self.parent_end,
            self.wires,
            self.body_bytes,
            body_digest,
            self.row_stream_digest,
            reserved,
        ) = ASSIGNMENT_HEADER.unpack(raw)
        if (
            magic.rstrip(b"\0") != ASSIGNMENT_MAGIC
            or version != ASSIGNMENT_VERSION
            or degree != field.FIELD_DEGREE
            or value_bytes != field.FIELD_ELEMENT_BYTES
            or reserved != bytes(8)
        ):
            self._file.close()
            raise JoinArchiveError("unsupported parent assignment profile")
        if (
            self.parent_start != PARENT_WIRE_START
            or self.parent_end != PARENT_WIRE_END
            or self.wires != PARENT_NONCONSTANT_WIRES
            or self.body_bytes != self.wires * field.FIELD_ELEMENT_BYTES
            or path.stat().st_size != ASSIGNMENT_HEADER.size + self.body_bytes
        ):
            self._file.close()
            raise JoinArchiveError("parent assignment interval/length mismatch")
        self.body_sha256 = body_digest.hex()
        self._map = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        if verify_body:
            digest = hashlib.sha256()
            view = memoryview(self._map)
            try:
                start = ASSIGNMENT_HEADER.size
                while start < len(view):
                    end = min(len(view), start + BUFFER_BYTES)
                    digest.update(view[start:end])
                    start = end
            finally:
                view.release()
            if digest.hexdigest() != self.body_sha256:
                self.close()
                raise JoinArchiveError("parent assignment body digest mismatch")

    def __getitem__(self, wire: int) -> int:
        if not self.parent_start <= wire <= self.parent_end:
            raise KeyError(wire)
        offset = ASSIGNMENT_HEADER.size + (
            wire - self.parent_start
        ) * field.FIELD_ELEMENT_BYTES
        value = int.from_bytes(
            self._map[offset : offset + field.FIELD_ELEMENT_BYTES], "little"
        )
        if value not in (0, 1):
            raise JoinArchiveError(f"parent wire {wire} is not canonically Boolean")
        return value

    def __iter__(self):
        return iter(range(self.parent_start, self.parent_end + 1))

    def __len__(self) -> int:
        return self.wires

    def close(self) -> None:
        if hasattr(self, "_map"):
            self._map.close()
            del self._map
        self._file.close()

    def __enter__(self) -> "ParentAssignmentReader":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


class _HashingReader:
    def __init__(self, handle: BinaryIO, limit: int) -> None:
        self.handle = handle
        self.limit = limit
        self.consumed = 0
        self.hasher = hashlib.sha256()

    def read(self, length: int) -> bytes:
        if length < 0 or self.consumed + length > self.limit:
            raise JoinArchiveError("record exceeds joined archive body")
        data = self.handle.read(length)
        if len(data) != length:
            raise JoinArchiveError("truncated joined archive body")
        self.consumed += length
        self.hasher.update(data)
        return data


def _read_uvarint(reader: _HashingReader) -> int:
    value = 0
    shift = 0
    for _ in range(10):
        byte = reader.read(1)[0]
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value
        shift += 7
    raise JoinArchiveError("overlong unsigned varint")


def _read_ids(reader: _HashingReader) -> list[int]:
    count = _read_uvarint(reader)
    if count > 10_000_000:
        raise JoinArchiveError("unreasonable joined linear-form arity")
    return [_read_uvarint(reader) for _ in range(count)]


@dataclass(frozen=True)
class EvaluationResult:
    satisfied: bool
    rows_checked: int
    failed_constraints: int
    first_failure: str | None
    join_rows_checked: int
    external_assertions: int
    archive_body_sha256_verified: bool
    assignment_body_sha256_verified: bool


def evaluate_join_archive(
    archive_path: Path,
    assignment_path: Path,
    aggregate_values: Mapping[int, int],
    *,
    parent_overrides: Mapping[int, int] | None = None,
) -> EvaluationResult:
    """Independently parse and evaluate every lifted parent and join row."""

    with archive_path.open("rb") as handle, ParentAssignmentReader(
        assignment_path, verify_body=True
    ) as parent:
        raw = handle.read(ARCHIVE_HEADER.size)
        if len(raw) != ARCHIVE_HEADER.size:
            raise JoinArchiveError("truncated joined archive header")
        unpacked = ARCHIVE_HEADER.unpack(raw)
        magic, version, degree = unpacked[:3]
        counts = unpacked[3:17]
        body_digest, assignment_digest, reserved = unpacked[17:]
        if (
            magic.rstrip(b"\0") != ARCHIVE_MAGIC
            or version != ARCHIVE_VERSION
            or degree != field.FIELD_DEGREE
            or reserved != bytes(8)
        ):
            raise JoinArchiveError("unsupported joined parent archive profile")
        (
            aggregate_max,
            parent_start,
            parent_end,
            parent_local_wires,
            public_inputs,
            secret_inputs,
            linear_definitions,
            linear_assertions,
            nonlinear_constraints,
            join_rows,
            total_rows,
            external_assertions,
            keccak_permutations,
            body_bytes,
        ) = counts
        if (
            aggregate_max != AGGREGATE_MAX_WIRE_ID
            or parent_start != PARENT_WIRE_START
            or parent_end != PARENT_WIRE_END
            or parent_local_wires != PARENT_LOCAL_WIRES
            or join_rows != JOIN_ROWS
            or total_rows != PARENT_JOIN_ROWS
            or external_assertions != 0
            or assignment_digest.hex() != parent.body_sha256
            or parent.row_stream_digest.hex() != body_digest.hex()
            or archive_path.stat().st_size != ARCHIVE_HEADER.size + body_bytes
        ):
            raise JoinArchiveError("joined parent header contract mismatch")
        reader = _HashingReader(handle, body_bytes)
        record_count = (
            public_inputs
            + secret_inputs
            + linear_definitions
            + linear_assertions
            + nonlinear_constraints
            + keccak_permutations
        )
        next_wire = PARENT_WIRE_START
        observed_public = observed_secret = 0
        observed_definitions = observed_assertions = observed_nonlinear = 0
        observed_keccak = observed_join = 0
        rows_checked = failed = 0
        first_failure: str | None = None
        parent_overrides = parent_overrides or {}

        def fail(label: str) -> None:
            nonlocal failed, first_failure
            failed += 1
            if first_failure is None:
                first_failure = label

        def require_parent_prior(identifier: int) -> None:
            if not PARENT_WIRE_START <= identifier < next_wire:
                raise JoinArchiveError(
                    f"parent wire {identifier} is not prior to {next_wire}"
                )

        def parent_value(identifier: int) -> int:
            value = parent_overrides.get(identifier, parent[identifier])
            if value not in (0, 1):
                raise JoinArchiveError(
                    f"parent wire {identifier} is not a Boolean GF(2^193) embedding"
                )
            return value

        def multiplicand(identifier: int) -> int:
            if identifier in (0, 1):
                return identifier
            require_parent_prior(identifier)
            return parent_value(identifier)

        for record_index in range(record_count):
            tag = reader.read(1)[0]
            if tag == TAG_INPUT:
                output = _read_uvarint(reader)
                visibility = reader.read(1)[0]
                if output != next_wire:
                    raise JoinArchiveError("joined input allocation is not sequential")
                next_wire += 1
                if visibility == VISIBILITY_PUBLIC:
                    observed_public += 1
                elif visibility == VISIBILITY_SECRET:
                    observed_secret += 1
                else:
                    raise JoinArchiveError("unknown joined input visibility")
            elif tag == TAG_LINEAR_DEFINITION:
                output = _read_uvarint(reader)
                constant = reader.read(1)[0]
                inputs = _read_ids(reader)
                if output != next_wire or constant not in (0, 1):
                    raise JoinArchiveError("malformed joined linear definition")
                value = constant
                for identifier in inputs:
                    require_parent_prior(identifier)
                    value ^= parent_value(identifier)
                if parent_value(output) != value:
                    fail(f"linear_definition[{record_index}]")
                next_wire += 1
                observed_definitions += 1
                rows_checked += 1
            elif tag == TAG_MULTIPLICATION:
                left = _read_uvarint(reader)
                right = _read_uvarint(reader)
                output = _read_uvarint(reader)
                kind = reader.read(1)[0]
                if output != next_wire or kind not in (KIND_AND, KIND_BITNESS):
                    raise JoinArchiveError("malformed joined multiplication")
                if multiplicand(left) * multiplicand(right) != parent_value(output):
                    fail(f"multiplication[{record_index}]")
                next_wire += 1
                observed_nonlinear += 1
                rows_checked += 1
            elif tag == TAG_LINEAR_ASSERTION:
                constant = reader.read(1)[0]
                inputs = _read_ids(reader)
                if constant not in (0, 1):
                    raise JoinArchiveError("joined assertion constant is not a bit")
                value = constant
                for identifier in inputs:
                    require_parent_prior(identifier)
                    value ^= parent_value(identifier)
                if value:
                    fail(f"linear_assertion[{record_index}]")
                observed_assertions += 1
                rows_checked += 1
            elif tag == TAG_JOIN_ASSERTION:
                port_code = reader.read(1)[0]
                parent_wire = _read_uvarint(reader)
                source_wire = _read_uvarint(reader)
                require_parent_prior(parent_wire)
                if port_code not in (PORT_MESSAGE, PORT_MASK, PORT_HASH_IMAGE):
                    raise JoinArchiveError("unknown native join port code")
                if not 1 <= source_wire <= AGGREGATE_MAX_WIRE_ID:
                    raise JoinArchiveError("native join source is outside aggregate")
                source_value = aggregate_values[source_wire]
                if source_value not in (0, 1):
                    raise JoinArchiveError("native join source is not a bit")
                if parent_value(parent_wire) != source_value:
                    fail(f"join_assertion[{port_code},{source_wire}]")
                observed_assertions += 1
                observed_join += 1
                rows_checked += 1
            elif tag == TAG_KECCAK_PERMUTATION:
                observed_keccak += 1
            else:
                raise JoinArchiveError(f"unknown joined record tag {tag}")
        if reader.consumed != body_bytes or handle.read(1):
            raise JoinArchiveError("joined archive body length mismatch")
        if reader.hasher.digest() != body_digest:
            raise JoinArchiveError("joined archive body digest mismatch")
        observed = (
            observed_public,
            observed_secret,
            observed_definitions,
            observed_assertions,
            observed_nonlinear,
            observed_join,
            observed_keccak,
        )
        declared = (
            public_inputs,
            secret_inputs,
            linear_definitions,
            linear_assertions,
            nonlinear_constraints,
            join_rows,
            keccak_permutations,
        )
        if observed != declared:
            raise JoinArchiveError(f"joined record counts {observed} != {declared}")
        if next_wire != PARENT_WIRE_END + 1 or rows_checked != total_rows:
            raise JoinArchiveError("joined row/wire accounting mismatch")
        return EvaluationResult(
            failed == 0,
            rows_checked,
            failed,
            first_failure,
            observed_join,
            external_assertions,
            True,
            True,
        )


def lower_parent_join(
    archive_path: Path,
    assignment_path: Path,
    fixture: ParentBoundFixture,
) -> JoinedParentResult:
    sink = GF193ParentJoinSink(archive_path, assignment_path, source_ports(fixture))
    original_shake256_wires = reference.shake256_wires

    def capture_shake256_wires(
        builder: reference.Char2CircuitBuilder,
        message: Sequence[reference.Wire],
        output_bytes: int,
    ) -> list[reference.Wire]:
        wires = original_shake256_wires(builder, message, output_bytes)
        if builder.block == "ticket_hash":
            sink.capture_ticket_digest(wires)
        return wires

    reference.shake256_wires = capture_shake256_wires
    try:
        report = reference.generate_issue_circuit(
            fixture.matrix,
            fixture.statement,
            fixture.witness,
            fixture.adapter,
            sink=sink,
        )
        result = sink.finalize(report)
    except BaseException:
        sink.close()
        archive_path.unlink(missing_ok=True)
        assignment_path.unlink(missing_ok=True)
        raise
    finally:
        reference.shake256_wires = original_shake256_wires
    return result


def build_prefreeze_manifest(
    fixture: ParentBoundFixture,
    result: JoinedParentResult,
    evaluation: EvaluationResult,
    mutation_probes: Mapping[str, object] | None = None,
) -> dict[str, object]:
    return {
        "format": "PQRBBC-PARENT-JOIN-PREFREEZE-1",
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "binding": {
            "message_sha256": hashlib.sha256(fixture.message).hexdigest(),
            "commitment_bytes": len(fixture.commitment),
            "commitment_sha256": hashlib.sha256(fixture.commitment).hexdigest(),
            "derived_mask_sha256": hashlib.sha256(fixture.mask).hexdigest(),
            "h_rbbc_hash_image_sha256": hashlib.sha256(
                fixture.hash_image
            ).hexdigest(),
            "public_y_sha256": hashlib.sha256(
                fixture.statement.blind_request.masked_target
            ).hexdigest(),
        },
        "accounting": {
            "aggregate_rows": AGGREGATE_ROWS,
            "aggregate_max_wire_id": AGGREGATE_MAX_WIRE_ID,
            "parent_local_wires": PARENT_LOCAL_WIRES,
            "parent_nonconstant_wires": PARENT_NONCONSTANT_WIRES,
            "parent_wire_interval": [PARENT_WIRE_START, PARENT_WIRE_END],
            "parent_internal_rows": PARENT_INTERNAL_ROWS,
            "native_join_rows": JOIN_ROWS,
            "parent_join_rows": PARENT_JOIN_ROWS,
            "combined_rows": COMBINED_ROWS,
            "external_assertions": 0,
        },
        "joined_parent_archive": asdict(result.archive),
        "joined_parent_assignment": asdict(result.assignment),
        "parent_destination_intervals": {
            name: list(interval)
            for name, interval in sorted(result.parent_destination_intervals.items())
        },
        "round_trip": asdict(evaluation),
        "mutation_probes": dict(mutation_probes or {}),
        "claim_boundary": {
            "parent_bound_fixture_closed": True,
            "gf193_parent_lift_structurally_closed": True,
            "joined_parent_archive_round_trip_verified": evaluation.satisfied,
            "full_parent_bound_aggregate_replayed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
            "system_architecture_changed": False,
            "ticket_lifecycle_changed": False,
            "pq_sat_auth_changed": False,
        },
    }


class _StaleSource(Mapping[int, int]):
    def __init__(self, base: Mapping[int, int], changes: Mapping[int, int]) -> None:
        self.base = base
        self.changes = changes

    def __getitem__(self, wire: int) -> int:
        return self.changes.get(wire, self.base[wire])

    def __iter__(self):
        return iter(self.base)

    def __len__(self) -> int:
        return len(self.base)


def run_mutation_probes(
    archive_path: Path,
    assignment_path: Path,
    fixture: ParentBoundFixture,
    destinations: Mapping[str, tuple[int, int]],
) -> dict[str, object]:
    """Reject exact source, parent, namespace, field, and archive mutations."""

    ports = source_ports(fixture)
    honest_source = source_assignment(ports)
    probes: dict[str, object] = {}
    for label, wire in (
        ("message", MESSAGE_WIRE_START),
        ("derived_mask", MASK_WIRE_START),
        ("h_rbbc_hash_image", HASH_IMAGE_WIRE_START),
    ):
        stale = _StaleSource(honest_source, {wire: honest_source[wire] ^ 1})
        result = evaluate_join_archive(archive_path, assignment_path, stale)
        probes[label] = {
            "rejected": not result.satisfied,
            "failed_constraints": result.failed_constraints,
            "first_failure": result.first_failure,
        }

    y_wire = destinations["blind_request.y"][0]
    with ParentAssignmentReader(assignment_path) as parent:
        y_stale = {y_wire: parent[y_wire] ^ 1}
    result = evaluate_join_archive(
        archive_path,
        assignment_path,
        honest_source,
        parent_overrides=y_stale,
    )
    probes["public_y"] = {
        "rejected": not result.satisfied,
        "failed_constraints": result.failed_constraints,
        "first_failure": result.first_failure,
    }

    changed_commitment = bytes((fixture.commitment[0] ^ 1,)) + fixture.commitment[1:]
    changed_hash = sponge.hash_request_binding(fixture.message, changed_commitment)
    changed_source = dict(honest_source)
    changed_source.update(
        source_assignment(
            (
                SourcePort(
                    "global.phase-b.commitment",
                    COMMITMENT_WIRE_START,
                    changed_commitment,
                ),
                SourcePort(
                    "global.phase-b.request-hash",
                    HASH_IMAGE_WIRE_START,
                    changed_hash,
                ),
            )
        )
    )
    result = evaluate_join_archive(archive_path, assignment_path, changed_source)
    probes["cap_commitment"] = {
        "h_rbbc_output_changed": changed_hash != fixture.hash_image,
        "rejected": changed_hash != fixture.hash_image and not result.satisfied,
        "failed_constraints": result.failed_constraints,
        "first_failure": result.first_failure,
    }

    try:
        evaluate_join_archive(
            archive_path,
            assignment_path,
            honest_source,
            parent_overrides={y_wire: 2},
        )
    except JoinArchiveError:
        mixed_field_rejected = True
    else:
        mixed_field_rejected = False
    probes["mixed_field_alias"] = {"rejected": mixed_field_rejected}

    wrong_interval_rejected = not (
        PARENT_WIRE_START <= AGGREGATE_MAX_WIRE_ID
        or PARENT_WIRE_END - PARENT_WIRE_START + 1 != PARENT_NONCONSTANT_WIRES
    )
    probes["wrong_wire_interval"] = {"rejected": wrong_interval_rejected}

    with tempfile.TemporaryDirectory(prefix="pq-rbbc-v2-29-corrupt-") as directory:
        corrupt = Path(directory) / "corrupt.gf193"
        raw_header = bytearray(archive_path.read_bytes()[: ARCHIVE_HEADER.size])
        raw_header[0] ^= 1
        corrupt.write_bytes(raw_header)
        try:
            evaluate_join_archive(corrupt, assignment_path, honest_source)
        except JoinArchiveError:
            corruption_rejected = True
        else:
            corruption_rejected = False
    probes["archive_corruption"] = {"rejected": corruption_rejected}
    probes["all_required_mutations_rejected"] = all(
        isinstance(value, dict) and value.get("rejected") is True
        for name, value in probes.items()
        if name != "all_required_mutations_rejected"
    )
    return probes


def build_parent_bound_tail_manifest(
    result: global_tail.GlobalTailAssignmentResult,
    fixture: ParentBoundFixture,
) -> dict[str, object]:
    summary = result.generated
    if (
        summary.parameters != cap.PRODUCTION_PARAMETERS
        or summary.rows != global_tail.FROZEN_PRODUCTION_ROWS
        or summary.wires != global_tail.FROZEN_PRODUCTION_WIRES
        or summary.stream_sha256 != global_tail.FROZEN_PRODUCTION_STREAM_SHA256
        or summary.external_assertions != 0
        or result.verified.verification_failures != 0
        or not all(probe.rejected for probe in result.tamper_probes)
        or summary.commitment_bytes != fixture.commitment
        or summary.request_hash_bytes != fixture.hash_image
    ):
        raise AssertionError("parent-bound global-tail production gate failed")
    ports = {port.port_id: port for port in summary.ports}
    expected_ports = {
        "shared.message": (MESSAGE_WIRE_START, fixture.message),
    }
    for port_id, (wire_start, value) in expected_ports.items():
        port = ports.get(port_id)
        if (
            port is None
            or port.consumer_wire_start != wire_start
            or port.bit_length != len(value) * 8
            or port.value_sha256 != hashlib.sha256(value).hexdigest()
        ):
            raise AssertionError(f"parent-bound global-tail port rejected: {port_id}")
    return {
        "format": "PQRBBC-PARENT-BOUND-GLOBAL-TAIL-1",
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": global_tail.RELATION_ID,
        "profile": {
            "cap_profile_fingerprint": cap.profile_fingerprint(
                cap.PRODUCTION_PARAMETERS
            ),
            "field": "GF(2^193)",
            "tree_count": cap.PRODUCTION_PARAMETERS.tree_count,
            "assignment_format": shard_assignment.ASSIGNMENT_FORMAT,
            "row_stream_format": global_tail.STREAM_FORMAT,
        },
        "binding": {
            "message_sha256": hashlib.sha256(fixture.message).hexdigest(),
            "commitment_sha256": hashlib.sha256(fixture.commitment).hexdigest(),
            "derived_mask_sha256": hashlib.sha256(fixture.mask).hexdigest(),
            "h_rbbc_hash_image_sha256": hashlib.sha256(
                fixture.hash_image
            ).hexdigest(),
        },
        "trace": {
            "rows": summary.rows,
            "wires": summary.wires,
            "nonlinear_rows": summary.nonlinear_rows,
            "linear_rows": summary.linear_rows,
            "stream_bytes": summary.stream_bytes,
            "stream_sha256": summary.stream_sha256,
            "external_assertions": summary.external_assertions,
            "verification_failures": result.verified.verification_failures,
            "generation_seconds": result.generation_seconds,
            "verification_seconds": result.verification_seconds,
            "peak_rss_kib": summary.peak_rss_kib,
            "groups": [asdict(group) for group in summary.groups],
            "sponge_accounting": asdict(summary.sponge_accounting),
        },
        "assignment_archive": asdict(result.archive),
        "ports": [asdict(port) for port in summary.ports]
        + [
            {
                "port_id": "global.phase-b.commitment",
                "producer_segment": "global-tail-phase-b",
                "consumer_wire_start": COMMITMENT_WIRE_START,
                "bit_length": COMMITMENT_BITS,
                "value_sha256": hashlib.sha256(fixture.commitment).hexdigest(),
            },
            {
                "port_id": "global.phase-b.derived-mask",
                "producer_segment": "global-tail-phase-b",
                "consumer_wire_start": MASK_WIRE_START,
                "bit_length": MASK_BITS,
                "value_sha256": hashlib.sha256(fixture.mask).hexdigest(),
            },
            {
                "port_id": "global.phase-b.request-hash",
                "producer_segment": "global-tail-phase-b",
                "consumer_wire_start": HASH_IMAGE_WIRE_START,
                "bit_length": HASH_IMAGE_BITS,
                "value_sha256": hashlib.sha256(fixture.hash_image).hexdigest(),
            },
        ],
        "outputs": {
            "commitment_bytes": len(fixture.commitment),
            "commitment_sha256": hashlib.sha256(fixture.commitment).hexdigest(),
            "request_hash_hex": fixture.hash_image.hex(),
        },
        "stale_witness_probes": [asdict(probe) for probe in result.tamper_probes],
        "claim_boundary": {
            "parent_bound_global_tail_native_closed": True,
            "global_tail_ports_are_native_bit_constrained": True,
            "complete_18_tree_assignment_replayed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }


def verify_existing_parent_bound_global_tail(
    archive_path: Path,
    execution: cap.CAPExecution,
    fixture: ParentBoundFixture,
    *,
    workers: int,
) -> global_tail.GlobalTailAssignmentResult:
    """Fully verify a completed archive whose manifest was not yet written."""

    labels = global_tail.capture_labels(cap.PRODUCTION_PARAMETERS, execution)
    captured: dict[str, field.RankOneRow] = {}
    started = time.perf_counter()
    with shard_assignment.AssignmentArchiveReader(
        archive_path, verify_body=True
    ) as values:
        metadata = shard_assignment.AssignmentArchiveMetadata(
            shard_assignment.ASSIGNMENT_FORMAT,
            shard_assignment.ASSIGNMENT_HEADER_BYTES,
            field.FIELD_DEGREE,
            field.FIELD_ELEMENT_BYTES,
            values.wires,
            values.body_bytes,
            values.body_sha256,
            values.row_stream_sha256,
            archive_path.stat().st_size,
            _sha256(archive_path),
        )
        summary = global_tail.build_global_tail(
            cap.PRODUCTION_PARAMETERS,
            cap.deterministic_randomness(
                cap.PRODUCTION_PARAMETERS, composer.FROZEN_RANDOMNESS_LABEL
            ),
            execution,
            fixture.message,
            workers=workers,
            verification_assignment=values,
            capture_rows=labels,
            captured_rows_output=captured,
            progress=lambda message: print(message, flush=True),
        )
        probes = shard_assignment.run_tamper_probes(
            values, captured, labels
        )
    elapsed = time.perf_counter() - started
    if summary.verification_failures or not all(probe.rejected for probe in probes):
        raise AssertionError("existing parent-bound global-tail verification failed")
    return global_tail.GlobalTailAssignmentResult(
        summary, summary, metadata, probes, 0.0, elapsed
    )


def prepare_parent_bound_artifacts(
    execution: cap.CAPExecution,
    global_archive_path: Path,
    global_manifest_path: Path,
    parent_archive_path: Path,
    parent_assignment_path: Path,
    preparation_manifest_path: Path,
    *,
    workers: int,
    replace_outputs: bool,
    reuse_global_tail: bool,
) -> dict[str, object]:
    fixture = build_parent_bound_fixture(execution)
    randomness = cap.deterministic_randomness(
        cap.PRODUCTION_PARAMETERS, composer.FROZEN_RANDOMNESS_LABEL
    )
    if reuse_global_tail:
        tail_result = verify_existing_parent_bound_global_tail(
            global_archive_path, execution, fixture, workers=workers
        )
    else:
        tail_result = global_tail.build_assignment_backed_global_tail(
            global_archive_path,
            cap.PRODUCTION_PARAMETERS,
            randomness,
            execution,
            fixture.message,
            workers=workers,
            replace=replace_outputs,
            progress=lambda message: print(message, flush=True),
        )
    tail_document = build_parent_bound_tail_manifest(tail_result, fixture)
    global_manifest_path.parent.mkdir(parents=True, exist_ok=True)
    global_manifest_path.write_bytes(canonical_json(tail_document))
    for path in (parent_archive_path, parent_assignment_path):
        if path.exists():
            if not replace_outputs:
                raise FileExistsError(path)
            path.unlink()
    parent_result = lower_parent_join(
        parent_archive_path, parent_assignment_path, fixture
    )
    with shard_assignment.AssignmentArchiveReader(
        global_archive_path, expected=tail_result.archive, verify_body=True
    ) as global_values:
        evaluation = evaluate_join_archive(
            parent_archive_path, parent_assignment_path, global_values
        )
    if not evaluation.satisfied:
        raise AssertionError("parent join rejected parent-bound global-tail archive")
    probes = run_mutation_probes(
        parent_archive_path,
        parent_assignment_path,
        fixture,
        parent_result.parent_destination_intervals,
    )
    if probes["all_required_mutations_rejected"] is not True:
        raise AssertionError("parent-bound preparation mutation gate failed")
    document = {
        "format": "PQRBBC-PARENT-JOIN-PREPARATION-1",
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "execution_semantic_sha256": composer_recovery.execution_sha256(execution),
        "global_tail_manifest": {
            "bytes": global_manifest_path.stat().st_size,
            "sha256": _sha256(global_manifest_path),
        },
        "global_tail_assignment": asdict(tail_result.archive),
        "parent": build_prefreeze_manifest(
            fixture, parent_result, evaluation, probes
        ),
        "claim_boundary": {
            "parent_bound_external_artifacts_verified": True,
            "safe_to_start_large_replay": True,
            "large_replay_started": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }
    preparation_manifest_path.parent.mkdir(parents=True, exist_ok=True)
    preparation_manifest_path.write_bytes(canonical_json(document))
    return document


def _atomic_json(path: Path, document: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(canonical_json(document))
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def _parent_replay_identity(
    tree_paths: Mapping[int, Path],
    global_archive: Path,
    parent_archive: Path,
    parent_assignment: Path,
    execution: cap.CAPExecution,
) -> str:
    document = {
        "namespace_sha256": aggregate_preflight.NAMESPACE_SHA256,
        "tree_archives": [
            {
                "tree_index": index,
                "sha256": aggregate_preflight.TREE_ARCHIVES[index][1],
            }
            for index in sorted(tree_paths)
        ],
        "global_archive_sha256": _sha256(global_archive),
        "parent_archive_sha256": _sha256(parent_archive),
        "parent_assignment_sha256": _sha256(parent_assignment),
        "execution_semantic_sha256": composer_recovery.execution_sha256(execution),
        "runner_sha256": _sha256(Path(__file__)),
    }
    return hashlib.sha256(canonical_json(document)).hexdigest()


def _new_full_checkpoint(identity: str) -> dict[str, object]:
    return {
        "format": "PQRBBC-PARENT-JOIN-REPLAY-CHECKPOINT-1",
        "input_identity": identity,
        "completed_tree_replays": [],
        "tree_results": [],
        "relocations_complete": False,
        "global_tail_complete": False,
        "parent_join_complete": False,
    }


def _load_full_checkpoint(path: Path, identity: str) -> dict[str, object]:
    if not path.exists():
        return _new_full_checkpoint(identity)
    document = json.loads(path.read_text())
    if (
        document.get("format") != "PQRBBC-PARENT-JOIN-REPLAY-CHECKPOINT-1"
        or document.get("input_identity") != identity
    ):
        raise ValueError("v2.29 replay checkpoint identity mismatch")
    completed = document.get("completed_tree_replays")
    results = document.get("tree_results")
    if (
        not isinstance(completed, list)
        or completed != list(range(len(completed)))
        or not isinstance(results, list)
        or len(results) != len(completed)
    ):
        raise ValueError("v2.29 replay checkpoint prefix is malformed")
    return document


def _validate_tail_document(
    path: Path, archive_path: Path, fixture: ParentBoundFixture
) -> tuple[dict[str, object], shard_assignment.AssignmentArchiveMetadata]:
    document = json.loads(path.read_text())
    if (
        document.get("format") != "PQRBBC-PARENT-BOUND-GLOBAL-TAIL-1"
        or document.get("implementation_version") != IMPLEMENTATION_VERSION
        or document.get("relation_id") != global_tail.RELATION_ID
    ):
        raise ValueError("parent-bound global-tail manifest profile mismatch")
    trace = document.get("trace", {})
    binding = document.get("binding", {})
    if (
        trace.get("rows") != global_tail.FROZEN_PRODUCTION_ROWS
        or trace.get("wires") != global_tail.FROZEN_PRODUCTION_WIRES
        or trace.get("stream_sha256")
        != global_tail.FROZEN_PRODUCTION_STREAM_SHA256
        or trace.get("external_assertions") != 0
        or trace.get("verification_failures") != 0
        or binding.get("message_sha256")
        != hashlib.sha256(fixture.message).hexdigest()
        or binding.get("commitment_sha256")
        != hashlib.sha256(fixture.commitment).hexdigest()
        or binding.get("derived_mask_sha256")
        != hashlib.sha256(fixture.mask).hexdigest()
        or binding.get("h_rbbc_hash_image_sha256")
        != hashlib.sha256(fixture.hash_image).hexdigest()
    ):
        raise ValueError("parent-bound global-tail manifest binding mismatch")
    archive = document.get("assignment_archive")
    if not isinstance(archive, dict):
        raise ValueError("parent-bound global-tail assignment metadata missing")
    metadata = shard_assignment.AssignmentArchiveMetadata(**archive)
    if (
        metadata.archive_bytes != archive_path.stat().st_size
        or metadata.archive_sha256 != _sha256(archive_path)
    ):
        raise ValueError("parent-bound global-tail archive identity mismatch")
    return document, metadata


def build_full_parent_join_replay(
    tree_paths: dict[int, Path],
    global_archive_path: Path,
    global_manifest_path: Path,
    namespace_path: Path,
    trusted_execution_cache: Path,
    parent_archive_path: Path,
    parent_assignment_path: Path,
    checkpoint_directory: Path,
    *,
    workers: int,
) -> dict[str, object]:
    """Replay all aggregate rows and the joined parent against one instance."""

    if sorted(tree_paths) != list(range(18)):
        raise ValueError("exactly tree archives 0 through 17 are required")
    if not aggregate_preflight._identity(
        namespace_path,
        (aggregate_preflight.NAMESPACE_BYTES, aggregate_preflight.NAMESPACE_SHA256),
    )["verified"]:
        raise ValueError("v2.29 namespace manifest identity rejected")
    for tree_index, path in tree_paths.items():
        if not aggregate_preflight._identity(
            path, aggregate_preflight.TREE_ARCHIVES[tree_index]
        )["verified"]:
            raise ValueError(f"tree {tree_index} archive identity rejected")
    execution = global_tail._load_production_execution(
        trusted_execution_cache
    ).execution
    fixture = build_parent_bound_fixture(execution)
    tail_document, tail_metadata = _validate_tail_document(
        global_manifest_path, global_archive_path, fixture
    )
    identity = _parent_replay_identity(
        tree_paths,
        global_archive_path,
        parent_archive_path,
        parent_assignment_path,
        execution,
    )
    checkpoint_directory.mkdir(parents=True, exist_ok=True)
    checkpoint_path = checkpoint_directory / "parent_join_full_checkpoint_v2_29.json"
    checkpoint = _load_full_checkpoint(checkpoint_path, identity)
    namespace_document = json.loads(namespace_path.read_text())
    links = aggregate_replay.validate_static_links(
        namespace_document, tail_document
    )
    with shard_assignment.AssignmentArchiveReader(
        global_archive_path, expected=tail_metadata, verify_body=True
    ) as global_values:
        completed = checkpoint["completed_tree_replays"]
        results = checkpoint["tree_results"]
        for tree_index in range(len(completed), 18):
            print(f"v2.29 aggregate replay tree {tree_index}/17", flush=True)
            results.append(
                aggregate_replay._tree_result(
                    tree_index,
                    tree_paths[tree_index],
                    global_values,
                    namespace_path,
                    checkpoint_directory,
                    workers,
                    lambda message: print(message, flush=True),
                )
            )
            completed.append(tree_index)
            _atomic_json(checkpoint_path, checkpoint)
        if not checkpoint["relocations_complete"]:
            matched = 0
            for tree_index in range(18):
                contract = planned.load_contract(tree_index, namespace_path)
                with shard_assignment.AssignmentArchiveReader(
                    tree_paths[tree_index], verify_body=True
                ) as local_reader:
                    for item in (
                        link for link in links if link["tree_index"] == tree_index
                    ):
                        local_start = (
                            item["planned_producer_wire_start"]
                            - contract.planned_local_wire_start
                            + 1
                        )
                        matched += aggregate_replay.compare_range(
                            local_reader,
                            local_start,
                            global_values,
                            item["consumer_wire_start"],
                            item["bit_length"],
                        )
            if matched != aggregate_replay.RELOCATION_ROWS:
                raise AssertionError("v2.29 relocation row count mismatch")
            checkpoint["relocations_complete"] = True
            checkpoint["relocation_rows"] = matched
            _atomic_json(checkpoint_path, checkpoint)
        if not checkpoint["global_tail_complete"]:
            randomness = cap.deterministic_randomness(
                cap.PRODUCTION_PARAMETERS, composer.FROZEN_RANDOMNESS_LABEL
            )
            tail = global_tail.build_global_tail(
                cap.PRODUCTION_PARAMETERS,
                randomness,
                execution,
                fixture.message,
                verification_assignment=global_values,
                workers=workers,
                progress=lambda message: print(message, flush=True),
            )
            if (
                tail.verification_failures
                or tail.rows != global_tail.FROZEN_PRODUCTION_ROWS
                or tail.wires != global_tail.FROZEN_PRODUCTION_WIRES
                or tail.stream_sha256 != global_tail.FROZEN_PRODUCTION_STREAM_SHA256
                or tail.request_hash_bytes != fixture.hash_image
            ):
                raise AssertionError("v2.29 parent-bound global-tail replay failed")
            checkpoint["global_tail_complete"] = True
            checkpoint["global_tail_result"] = {
                "rows": tail.rows,
                "row_stream_sha256": tail.stream_sha256,
                "verification_failures": 0,
                "message_sha256": hashlib.sha256(fixture.message).hexdigest(),
                "request_hash_sha256": hashlib.sha256(fixture.hash_image).hexdigest(),
            }
            _atomic_json(checkpoint_path, checkpoint)
        if not checkpoint["parent_join_complete"]:
            parent_evaluation = evaluate_join_archive(
                parent_archive_path, parent_assignment_path, global_values
            )
            if not parent_evaluation.satisfied:
                raise AssertionError("v2.29 joined parent replay failed")
            checkpoint["parent_join_complete"] = True
            checkpoint["parent_join_result"] = asdict(parent_evaluation)
            _atomic_json(checkpoint_path, checkpoint)
    producer_rows = sum(item["rows"] for item in checkpoint["tree_results"])
    aggregate_rows = (
        producer_rows
        + checkpoint["relocation_rows"]
        + checkpoint["global_tail_result"]["rows"]
    )
    combined_rows = aggregate_rows + checkpoint["parent_join_result"]["rows_checked"]
    if aggregate_rows != AGGREGATE_ROWS or combined_rows != COMBINED_ROWS:
        raise AssertionError("v2.29 combined row accounting mismatch")
    transcript = {
        "tree_results": checkpoint["tree_results"],
        "relocation_rows": checkpoint["relocation_rows"],
        "global_tail_result": checkpoint["global_tail_result"],
        "parent_join_result": checkpoint["parent_join_result"],
    }
    return {
        "format": "PQRBBC-PARENT-JOIN-FULL-REPLAY-1",
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "input_identity": identity,
        "ordered_replay_transcript_sha256": hashlib.sha256(
            canonical_json(transcript)
        ).hexdigest(),
        "tree_order": list(range(18)),
        "tree_results": checkpoint["tree_results"],
        "producer_rows": producer_rows,
        "relocation_rows": checkpoint["relocation_rows"],
        "global_tail_result": checkpoint["global_tail_result"],
        "aggregate_rows_replayed": aggregate_rows,
        "parent_join_result": checkpoint["parent_join_result"],
        "combined_rows_replayed": combined_rows,
        "verification_failures": 0,
        "external_assertions": 0,
        "claim_boundary": {
            "complete_18_tree_assignment_replayed": True,
            "cross_segment_wire_identity_closed": True,
            "parent_bound_global_tail_replayed": True,
            "gf193_parent_lift_replayed": True,
            "parent_cap_to_h_rbbc_join_closed": True,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
            "system_architecture_changed": False,
            "ticket_lifecycle_changed": False,
            "pq_sat_auth_changed": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trusted-composer-execution-cache", type=Path, required=True)
    parser.add_argument("--parent-archive", type=Path, required=True)
    parser.add_argument("--parent-assignment", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--global-archive", type=Path)
    parser.add_argument("--global-manifest", type=Path)
    parser.add_argument("--namespace-manifest", type=Path)
    parser.add_argument("--checkpoint-directory", type=Path)
    parser.add_argument("--tree-archive", action="append", default=[])
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--replace", action="store_true")
    parser.add_argument("--reuse-global-tail", action="store_true")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--prepare-parent-bound", action="store_true")
    mode.add_argument("--full-row-replay", action="store_true")
    args = parser.parse_args()
    if args.workers != 8:
        parser.error("v2.29 production replay is frozen to 8 workers")
    if args.prepare_parent_bound:
        if args.global_archive is None or args.global_manifest is None:
            parser.error("--prepare-parent-bound requires --global-archive and --global-manifest")
        execution = global_tail._load_production_execution(
            args.trusted_composer_execution_cache
        ).execution
        prepare_parent_bound_artifacts(
            execution,
            args.global_archive,
            args.global_manifest,
            args.parent_archive,
            args.parent_assignment,
            args.manifest,
            workers=args.workers,
            replace_outputs=args.replace,
            reuse_global_tail=args.reuse_global_tail,
        )
    elif args.full_row_replay:
        if args.reuse_global_tail:
            parser.error("--reuse-global-tail applies only to --prepare-parent-bound")
        if (
            args.global_archive is None
            or args.global_manifest is None
            or args.namespace_manifest is None
            or args.checkpoint_directory is None
        ):
            parser.error(
                "--full-row-replay requires global archive/manifest, namespace, and checkpoint directory"
            )
        trees = aggregate_preflight.parse_tree_archives(args.tree_archive)
        document = build_full_parent_join_replay(
            trees,
            args.global_archive,
            args.global_manifest,
            args.namespace_manifest,
            args.trusted_composer_execution_cache,
            args.parent_archive,
            args.parent_assignment,
            args.checkpoint_directory,
            workers=args.workers,
        )
        if args.manifest.exists() and not args.replace:
            parser.error(f"output exists: {args.manifest}")
        _atomic_json(args.manifest, document)
    else:
        if args.reuse_global_tail:
            parser.error("--reuse-global-tail requires --prepare-parent-bound")
        for path in (args.parent_archive, args.parent_assignment, args.manifest):
            if path.exists():
                if not args.replace:
                    parser.error(f"output exists: {path}")
                path.unlink()
        execution = global_tail._load_production_execution(
            args.trusted_composer_execution_cache
        ).execution
        fixture = build_parent_bound_fixture(execution)
        result = lower_parent_join(
            args.parent_archive, args.parent_assignment, fixture
        )
        evaluation = evaluate_join_archive(
            args.parent_archive,
            args.parent_assignment,
            source_assignment(source_ports(fixture)),
        )
        if not evaluation.satisfied:
            raise SystemExit("joined parent round-trip failed")
        probes = run_mutation_probes(
            args.parent_archive,
            args.parent_assignment,
            fixture,
            result.parent_destination_intervals,
        )
        if probes["all_required_mutations_rejected"] is not True:
            raise SystemExit("a required joined-parent mutation was accepted")
        document = build_prefreeze_manifest(fixture, result, evaluation, probes)
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_bytes(canonical_json(document))
    print(_sha256(args.manifest))


if __name__ == "__main__":
    main()
