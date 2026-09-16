"""Bounded INSECURE-TEST-ONLY private tree spool; never a production codec.

The binary body is secret input, NOT portable evidence. Identity and decoding
consume one immutable Snapshot.raw. This module does not publish files, restore
Python frames/hash states, or establish writer quiescence or durability.
"""
from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct

import pq_rbbc_cap_commit as cap
import pq_rbbc_issuance_bounded_multitree_native_v1 as predecessor
import pq_rbbc_launch_io_v2_41 as io

FORMAT = "PQRBBC-ISSUANCE-PRIVATE-SPOOL-HANDOFF-1"
RELATION_ID = "pq-rbbc/issuance/private-spool/multitree-4plus4-insecure-test-only/v1"
MAGIC = b"PQRBBC/ISSUANCE/PRIVATE-SPOOL/INSECURE-TEST-ONLY\x00"
VERSION = 1
LEAVES = 4
WITNESS_BITS = 2048
MHAT_BITS = 386
MHAT_SHIFT = 2064
RECORD_WIRES = WITNESS_BITS + MHAT_BITS
PACKED_BYTES = (RECORD_WIRES + 7) // 8
XI_BITS = MHAT_BITS * 3
XI_BYTES = (XI_BITS + 7) // 8
HEADER = struct.Struct("<H32s32s32sBQQHHH")
WIRE_RECORD = struct.Struct("<" + "Q" * RECORD_WIRES)
RECORD_BYTES = WIRE_RECORD.size + PACKED_BYTES
BODY_OFFSET = len(MAGIC) + HEADER.size
SPOOL_BYTES = BODY_OFFSET + LEAVES * RECORD_BYTES + XI_BYTES
PROFILE = cap.profile_fingerprint(predecessor.PARAMETERS)


class SpoolError(io.ValidationError):
    """Identity, canonical encoding, tree ownership or private value rejection."""


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def hex_digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise SpoolError("canonical lowercase SHA-256 required")
    return bytes.fromhex(value)


@dataclass(frozen=True)
class Context:
    tree_index: int
    pre_start: int
    pre_end: int
    plan_sha256: str
    invocation_sha256: str

    def __post_init__(self):
        if (type(self.tree_index) is not int or self.tree_index not in (0, 1)
                or type(self.pre_start) is not int or type(self.pre_end) is not int
                or not 1 <= self.pre_start < self.pre_end <= 200001):
            raise SpoolError("bounded owner context")
        hex_digest(self.plan_sha256)
        hex_digest(self.invocation_sha256)

    def header(self):
        return MAGIC + HEADER.pack(VERSION, hex_digest(PROFILE), hex_digest(self.plan_sha256),
                                   hex_digest(self.invocation_sha256), self.tree_index,
                                   self.pre_start, self.pre_end, LEAVES, RECORD_WIRES, XI_BITS)


class BoundedMemoryWireSpoolInsecureTestOnly:
    """Native producer scratch storage; exactly four immutable wire records."""
    def __init__(self, record_wires):
        if type(record_wires) is not int or record_wires != RECORD_WIRES:
            raise SpoolError("bounded spool record width")
        self.record_wires = record_wires
        self._records = []
        self._sealed = False

    @property
    def records(self):
        return len(self._records)

    def append(self, wire_ids):
        record = tuple(wire_ids)
        if self._sealed or self.records >= LEAVES or len(record) != RECORD_WIRES:
            raise SpoolError("bounded spool size or sealed writer")
        if any(type(w) is not int or not 0 < w <= 200000 for w in record):
            raise SpoolError("noncanonical wire ID")
        self._records.append(record)

    def open_reader(self):
        if self.records != LEAVES:
            raise SpoolError("incomplete spool")
        self._records = tuple(self._records)
        self._sealed = True
        return self

    def record(self, index):
        if type(index) is not int or not 0 <= index < self.records:
            raise SpoolError("record index")
        return self._records[index]

    def wire(self, record, coordinate):
        if type(coordinate) is not int or not 0 <= coordinate < RECORD_WIRES:
            raise SpoolError("coordinate")
        return self.record(record)[coordinate]

    def close(self):
        # No FD, pathname, mmap, publication, or durability promise.
        pass


def encode_insecure_test_only(context, spool, tape_values, xi_masks):
    if type(context) is not Context or spool.records != LEAVES or len(tape_values) != LEAVES:
        raise SpoolError("bounded tree input shape")
    if len(xi_masks) != MHAT_BITS or any(type(v) is not int or not 0 <= v < 8 for v in xi_masks):
        raise SpoolError("xi extension encoding")
    raw = bytearray(context.header())
    for leaf in range(LEAVES):
        value = tape_values[leaf]
        if type(value) is not int or not 0 <= value < 1 << 2450:
            raise SpoolError("noncanonical tape value")
        selected = (value & ((1 << WITNESS_BITS) - 1)) | (
            ((value >> MHAT_SHIFT) & ((1 << MHAT_BITS) - 1)) << WITNESS_BITS)
        record = spool.record(leaf)
        if len(record) != RECORD_WIRES or any(type(w) is not int or not 0 < w <= 200000 for w in record):
            raise SpoolError("noncanonical wire record")
        raw.extend(WIRE_RECORD.pack(*record))
        raw.extend(selected.to_bytes(PACKED_BYTES, "little"))
    xi = sum(value << (i * 3) for i, value in enumerate(xi_masks))
    raw.extend(xi.to_bytes(XI_BYTES, "little"))
    result = bytes(raw)
    # Structural checks apply to the encoder too; the caller additionally
    # binds selected bits to the real assignment before adopting a handoff.
    reader = TreeSpoolSnapshotInsecureTestOnly(io.Snapshot(Path("/memory/spool.bin"), result), context)
    reader.validate()
    return result


@dataclass(frozen=True)
class TreeSpoolSnapshotInsecureTestOnly:
    snapshot: io.Snapshot
    context: Context

    @property
    def records(self):
        return LEAVES

    @property
    def record_wires(self):
        return RECORD_WIRES

    def record(self, index):
        if type(index) is not int or not 0 <= index < LEAVES:
            raise SpoolError("record index")
        return WIRE_RECORD.unpack_from(self.snapshot.raw, BODY_OFFSET + index * RECORD_BYTES)

    def selected_value(self, index):
        self.record(index)  # validate index before slicing
        offset = BODY_OFFSET + index * RECORD_BYTES + WIRE_RECORD.size
        return int.from_bytes(self.snapshot.raw[offset:offset + PACKED_BYTES], "little")

    def wire(self, record, coordinate):
        if type(coordinate) is not int or not 0 <= coordinate < RECORD_WIRES:
            raise SpoolError("coordinate")
        return self.record(record)[coordinate]

    @property
    def tape_values(self):
        # Only the witness portion is consumed by the native Horner stage.
        return tuple(self.selected_value(i) & ((1 << WITNESS_BITS) - 1) for i in range(LEAVES))

    @property
    def xi_masks(self):
        value = int.from_bytes(self.snapshot.raw[-XI_BYTES:], "little")
        return tuple((value >> (i * 3)) & 7 for i in range(MHAT_BITS))

    def validate(self):
        if type(self.snapshot) is not io.Snapshot or type(self.context) is not Context:
            raise SpoolError("immutable snapshot and bounded context required")
        raw = self.snapshot.raw
        if len(raw) != SPOOL_BYTES or raw[:BODY_OFFSET] != self.context.header():
            raise SpoolError("spool length/version/domain/profile/invocation/owner mismatch")
        seen = set()
        for leaf in range(LEAVES):
            record = self.record(leaf)
            if any(not self.context.pre_start <= wire < self.context.pre_end or wire in seen for wire in record):
                raise SpoolError("wrong owner, future wire, or duplicated leaf wire")
            if len(set(record)) != RECORD_WIRES:
                raise SpoolError("duplicated wire within record")
            seen.update(record)
            if self.selected_value(leaf) >> RECORD_WIRES:
                raise SpoolError("nonzero packed padding")
        if int.from_bytes(raw[-XI_BYTES:], "little") >> XI_BITS:
            raise SpoolError("nonzero xi padding")
        return self

    def assert_values(self, values):
        self.validate()
        for leaf in range(LEAVES):
            selected = self.selected_value(leaf)
            for coordinate, wire in enumerate(self.record(leaf)):
                if wire not in values or values[wire] != (selected >> coordinate) & 1:
                    raise SpoolError("spool wire/value differs from captured native assignment")

    def close(self):
        pass


def decode_snapshot_insecure_test_only(snapshot, *, expected_bytes, expected_sha256, context):
    # Trust pin is supplied out of band, never learned by parsing this body.
    hex_digest(expected_sha256)
    if (type(snapshot) is not io.Snapshot or type(expected_bytes) is not int
            or expected_bytes != SPOOL_BYTES or len(snapshot.raw) != expected_bytes
            or sha256(snapshot.raw) != expected_sha256):
        raise SpoolError("external spool identity mismatch before decode")
    return TreeSpoolSnapshotInsecureTestOnly(snapshot, context).validate()
