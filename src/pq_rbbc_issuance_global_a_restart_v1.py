#!/usr/bin/env python3
"""Bounded independently invocable global-A fragment and private restart.

The only executable profile is the two-tree/four-leaf INSECURE-TEST-ONLY
fixture.  A live authoring helper captures the six tree-pre output ports and
the raw-verified ordinal-0-to-2 adapter receipt prefix.  The independent consumer uses only that immutable
CandidateSet; it does not replay tree-pre or restore a Python generator/hash
object.  Private output publication is exclusive and append-only below a
caller-provisioned artifact root.  Production remains unavailable.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import MappingProxyType
from typing import Mapping, Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_global_tail as tail
import pq_rbbc_cap_shard_stream as shard
import pq_rbbc_issuance_bounded_multitree_adapter_v1 as base
import pq_rbbc_issuance_global_tail_continuation_preflight_v1 as preflight_gate
import pq_rbbc_issuance_private_spool_handoff_v1 as handoff
import pq_rbbc_issuance_production_inputs_v1 as production_inputs
import pq_rbbc_launch_io_v2_41 as io
import pq_rbbc_recovery_io_v2_42 as disk


ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION_VERSION = "1.1"
FORMAT = "PQRBBC-ISSUANCE-GLOBAL-A-RESTART-1"
RELATION_ID = (
    "pq-rbbc/issuance/global-a-restart/"
    "multitree-4plus4-insecure-test-only/v1"
)
MODE = "INSECURE-TEST-ONLY"
TREE_PRE_RESULT_FORMAT = FORMAT + "-TREE-PRE-RESULT"
HANDOFF_FORMAT = FORMAT + "-TREE-PRE-HANDOFF"
FRAGMENT_STREAM_FORMAT = FORMAT + "-FRAGMENT-STREAM"
FRAGMENT_RECEIPT_FORMAT = FORMAT + "-FRAGMENT-RECEIPT"
PRIVATE_RESULT_FORMAT = FORMAT + "-PRIVATE-RESULT"
CHECKPOINT_FORMAT = FORMAT + "-CHECKPOINT"
DOMAIN_ROWS = b"PQ-RBBC/ISSUANCE/GLOBAL-A-RESTART/ROWS/V1"
DOMAIN_ASSIGNMENT = b"PQ-RBBC/ISSUANCE/GLOBAL-A-RESTART/ASSIGNMENT/V1"
PROFILE_FINGERPRINT = preflight_gate.PROFILE_FINGERPRINT
PLAN_SHA256 = preflight_gate.PLAN_SHA256
INVOCATION_SHA256 = preflight_gate.INVOCATION_SHA256
PHASE_A_INTERVAL = (10_915, 23_094)
PHASE_A_ROWS = 19_671
POINT_STARTS = (22_705, 22_898)
H1_PORT = (20_655, cap.HASH_BITS)
POINT_PORT = (POINT_STARTS[0], base.PARAMETERS.consistency_bits)

HANDOFF_NAME = "tree-pre-handoff.private.json"
TREE_PRE_RESULT_NAMES = (
    "tree-0.pre-result.private.json",
    "tree-1.pre-result.private.json",
)
ADAPTER_RECEIPT_NAMES = tuple(
    f"adapter-receipt-{index:04d}.private.json" for index in range(3)
)
INPUT_NAMES = (
    HANDOFF_NAME,
    *TREE_PRE_RESULT_NAMES,
    *ADAPTER_RECEIPT_NAMES,
)
INPUT_DIRECTORY = "inputs"
RESULT_DIRECTORY = "results"
JOURNAL_DIRECTORY = "journal"
PLAN_NAME = "0000-publication-plan.private.json"
INPUTS_COMMITTED_NAME = "0001-inputs-committed.private.json"
RESULT_COMMITTED_NAME = "0002-result-committed.private.json"
COMPLETE_NAME = "complete.private.json"
JOURNAL_NAMES = (
    PLAN_NAME,
    INPUTS_COMMITTED_NAME,
    RESULT_COMMITTED_NAME,
    COMPLETE_NAME,
)
PRIVATE_RESULT_NAME = "global-a-result.private.json"
POINT_NAME = handoff.POINT_NAME
FRAGMENT_RECEIPT_NAME = "global-a-fragment-receipt.private.json"
RESULT_NAMES = (PRIVATE_RESULT_NAME, POINT_NAME, FRAGMENT_RECEIPT_NAME)
HANDOFF_LIMIT = 16 * 1024
TREE_PRE_RESULT_LIMIT = 32 * 1024
ADAPTER_RECEIPT_LIMIT = 16 * 1024
PRIVATE_RESULT_LIMIT = 1 << 20
POINT_LIMIT = handoff.POINT_LIMIT
FRAGMENT_RECEIPT_LIMIT = 32 * 1024
CHECKPOINT_LIMIT = 32 * 1024
VALUE_ENCODING = "12179xf193-little-endian-hex"
STOP_BOUNDARIES = frozenset(
    {
        "inputs",
        "result-payload",
        "points",
        "result-receipt",
        "result-checkpoint",
        "complete",
    }
)
MANIFEST_PATH = "manifests/pq_rbbc_issuance_global_a_restart_manifest_v1.json"
EVIDENCE_PATH = (
    "artifacts/metadata/issuance_global_a_restart_v1/"
    "pq_rbbc_issuance_global_a_restart_portable_evidence_v1.json"
)
PREDECESSOR_PINS = {
    "src/pq_rbbc_issuance_global_tail_continuation_preflight_v1.py": (
        33_491,
        "9b413e836bb166dac0b39f7dcaa5b90c347228fc06b49926a16d0af5757b65a2",
    ),
    "tests/test_pq_rbbc_issuance_global_tail_continuation_preflight_v1.py": (
        11_635,
        "7ede36136cb4e5fdf1cbd1bf729247539646fb293e3c0da54c96a69775d0a8c1",
    ),
    preflight_gate.MANIFEST_PATH: (
        15_021,
        "efb3214747e956b41bb88a895021483cab8808ad7cf1ea336cffc6bc03bb4c10",
    ),
    preflight_gate.EVIDENCE_PATH: (
        3_600,
        "0dd9b0ac1dbe364683a4a60625aeed49dfe79cd19111e7ec0c42d31b79a165b9",
    ),
}


TREE_PRE_PORTS = (
    (
        ("tree[0].leaf-commitments", 76_721, 643, 1_544),
        ("tree[0].p-plain", 78_265, 2_187, 2_048),
        ("tree[0].mhat-plain", 80_313, 4_235, 386),
    ),
    (
        ("tree[1].leaf-commitments", 115_995, 5_779, 1_544),
        ("tree[1].p-plain", 117_539, 7_323, 2_048),
        ("tree[1].mhat-plain", 119_587, 9_371, 386),
    ),
)
EXPECTED_STAGES = ("bind-inputs", "tree-pre[0]", "tree-pre[1]")
EXPECTED_STAGE_ROWS = (12_970, 54_070, 54_070)
EXPECTED_TOTAL_ROWS = (12_970, 67_040, 121_110)
EXPECTED_CURSORS = (
    {"anchors": 123_799, "tail": 10_915, "tree[0]": 43_837, "tree[1]": 83_111},
    {"anchors": 123_799, "tail": 10_915, "tree[0]": 80_699, "tree[1]": 83_111},
    {"anchors": 123_799, "tail": 10_915, "tree[0]": 80_699, "tree[1]": 119_973},
)
EXPECTED_RELOCATIONS = (
    (),
    (
        "tree[0].leaf-commitments",
        "tree[0].p-plain",
        "tree[0].mhat-plain",
    ),
    (
        "tree[0].leaf-commitments",
        "tree[0].p-plain",
        "tree[0].mhat-plain",
        "tree[1].leaf-commitments",
        "tree[1].p-plain",
        "tree[1].mhat-plain",
    ),
)


class GlobalARestartError(ValueError):
    """A tree-pre handoff, Phase-A result, or restart state was rejected."""


class ProductionUnavailable(RuntimeError):
    """This checkpoint intentionally exposes no production executor."""


@dataclass(frozen=True)
class TreePreCandidateSetInsecureTestOnly:
    handoff: io.Snapshot
    tree_results: tuple[io.Snapshot, io.Snapshot]
    receipts: tuple[io.Snapshot, io.Snapshot, io.Snapshot]

    def __post_init__(self) -> None:
        if (
            type(self.tree_results) is not tuple
            or len(self.tree_results) != 2
            or type(self.receipts) is not tuple
            or len(self.receipts) != 3
        ):
            raise GlobalARestartError("exact tuple-shaped CandidateSet required")
        snapshots = (self.handoff, *self.tree_results, *self.receipts)
        if any(type(snapshot) is not io.Snapshot for snapshot in snapshots):
            raise GlobalARestartError("immutable six-snapshot CandidateSet required")


@dataclass(frozen=True)
class DecodedTreePreCandidateSetInsecureTestOnly:
    handoff: Mapping[str, object]
    tree_results: tuple[Mapping[str, object], Mapping[str, object]]
    receipts: tuple[Mapping[str, object], Mapping[str, object], Mapping[str, object]]
    values: Mapping[int, int]


@dataclass(frozen=True)
class GlobalAResultInsecureTestOnly:
    summary: Mapping[str, object]
    owned_values: tuple[int, ...]
    h1: int
    points: tuple[int, ...]
    point_snapshot: io.Snapshot
    receipt: io.Snapshot


@dataclass(frozen=True)
class PublishedGlobalAResultInsecureTestOnly:
    owned_values: tuple[int, ...]
    h1: int
    points: tuple[int, ...]
    result: io.Snapshot
    point_snapshot: io.Snapshot
    receipt: io.Snapshot
    complete_checkpoint: io.Snapshot


def canonical_json(document: object) -> bytes:
    return io.canonical_json(document)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _is_int(value: object) -> bool:
    return type(value) is int


def _digest(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise GlobalARestartError(label + " must be a lowercase SHA-256")
    return value


def _exact(value: object, fields: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise GlobalARestartError(label + " closed schema mismatch")
    return value


def _snapshot(name: str, raw: bytes) -> io.Snapshot:
    return io.Snapshot(Path("/in-memory-insecure-test-only") / name, raw)


def _identity(snapshot: io.Snapshot, name: str, limit: int) -> dict[str, object]:
    if (
        type(snapshot) is not io.Snapshot
        or snapshot.location.name != name
        or not 0 < len(snapshot.raw) <= limit
    ):
        raise GlobalARestartError("snapshot type/name/size mismatch: " + name)
    return snapshot.identity


def _identity_document(
    value: object, *, filename: str, limit: int
) -> dict[str, object]:
    current = _exact(value, {"filename", "bytes", "sha256"}, "artifact identity")
    if (
        current["filename"] != filename
        or not _is_int(current["bytes"])
        or not 0 < int(current["bytes"]) <= limit
    ):
        raise GlobalARestartError("artifact identity name/size mismatch: " + filename)
    _digest(current["sha256"], "artifact identity")
    return current


def _pack_bits(values: Sequence[int]) -> bytes:
    if any(value not in (0, 1) for value in values):
        raise GlobalARestartError("port contains a non-bit value")
    raw = bytearray((len(values) + 7) // 8)
    for index, value in enumerate(values):
        raw[index // 8] |= value << (index % 8)
    return bytes(raw)


def _decode_bits(value: object, width: int) -> tuple[int, ...]:
    expected_bytes = (width + 7) // 8
    if (
        type(value) is not str
        or len(value) != expected_bytes * 2
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise GlobalARestartError("canonical packed port encoding required")
    raw = bytes.fromhex(value)
    if int.from_bytes(raw, "little") >> width:
        raise GlobalARestartError("nonzero packed port padding")
    return tuple((raw[index // 8] >> (index % 8)) & 1 for index in range(width))


def _producer_value_digest(port_id: str, bits: Sequence[int]) -> str:
    if port_id.endswith(".leaf-commitments"):
        if len(bits) % field.FIELD_DEGREE:
            raise GlobalARestartError("commitment field width")
        encoded = b"".join(
            cap.field_bytes(
                sum(
                    bits[offset + bit] << bit
                    for bit in range(field.FIELD_DEGREE)
                )
            )
            for offset in range(0, len(bits), field.FIELD_DEGREE)
        )
        return sha256(encoded)
    return sha256(_pack_bits(bits))


def _private_assignment_digest(values: Sequence[int]) -> str:
    digest = hashlib.sha256(DOMAIN_ASSIGNMENT)
    for value in values:
        if not _is_int(value) or not 0 <= value < field.FIELD_ORDER:
            raise GlobalARestartError("noncanonical F193 assignment value")
        digest.update(value.to_bytes(field.FIELD_ELEMENT_BYTES, "little"))
    return digest.hexdigest()


def _encode_values(values: Sequence[int]) -> str:
    _private_assignment_digest(values)
    return b"".join(
        value.to_bytes(field.FIELD_ELEMENT_BYTES, "little") for value in values
    ).hex()


def _decode_values(value: object) -> tuple[int, ...]:
    count = PHASE_A_INTERVAL[1] - PHASE_A_INTERVAL[0]
    if (
        type(value) is not str
        or len(value) != count * field.FIELD_ELEMENT_BYTES * 2
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise GlobalARestartError("private Phase-A result value encoding")
    raw = bytes.fromhex(value)
    values = tuple(
        int.from_bytes(raw[offset : offset + field.FIELD_ELEMENT_BYTES], "little")
        for offset in range(0, len(raw), field.FIELD_ELEMENT_BYTES)
    )
    if any(item >= field.FIELD_ORDER for item in values):
        raise GlobalARestartError("noncanonical F193 value in Phase-A result")
    return values


def validate_prerequisites() -> None:
    failures = preflight_gate.validate_prerequisites()
    if failures:
        raise GlobalARestartError("preflight predecessor is not valid: " + ",".join(failures))
    for path, (expected_bytes, expected_sha256) in PREDECESSOR_PINS.items():
        snapshot = io.read_snapshot(ROOT / path)
        if (len(snapshot.raw), sha256(snapshot.raw)) != (
            expected_bytes,
            expected_sha256,
        ):
            raise GlobalARestartError("predecessor identity drift: " + path)


def _receipt_snapshot(raw: bytes, ordinal: int) -> io.Snapshot:
    return _snapshot(ADAPTER_RECEIPT_NAMES[ordinal], raw)


def _validate_adapter_receipts(
    snapshots: Sequence[io.Snapshot], invocation_sha256: str
) -> tuple[Mapping[str, object], Mapping[str, object], Mapping[str, object]]:
    if len(snapshots) != 3:
        raise GlobalARestartError("exact three-receipt prefix required")
    documents = []
    previous = None
    for ordinal, (snapshot, name) in enumerate(zip(snapshots, ADAPTER_RECEIPT_NAMES)):
        _identity(snapshot, name, ADAPTER_RECEIPT_LIMIT)
        if snapshot.identity != preflight_gate.VERIFIED_RECEIPT_PREFIX_IDENTITIES[ordinal]:
            raise GlobalARestartError("frozen receipt-prefix raw identity mismatch")
        try:
            current = snapshot.document()
        except io.ValidationError as error:
            raise GlobalARestartError("adapter receipt is not strict canonical JSON") from error
        current = _exact(
            current,
            {
                "format",
                "relation_id",
                "profile_fingerprint",
                "plan_sha256",
                "invocation_sha256",
                "ordinal",
                "stage_id",
                "previous_receipt_sha256",
                "rows",
                "total_rows",
                "owner_cursors",
                "relocation_ports",
                "native_binding_rows_sha256",
                "point_snapshot_sha256",
                "native_prefix_identities",
                "production",
                "durable_resume",
            },
            "adapter receipt",
        )
        prefixes = current["native_prefix_identities"]
        expected_owners = ("anchors", "tail", *tuple(f"tree[{i}]" for i in range(ordinal)))
        if type(prefixes) is not dict or set(prefixes) != set(expected_owners):
            raise GlobalARestartError("adapter native-prefix owner set")
        for digest in prefixes.values():
            _digest(digest, "native prefix")
        _digest(current["native_binding_rows_sha256"], "native binding rows")
        if (
            current["format"] != base.FORMAT + "-RECEIPT"
            or current["relation_id"] != base.RELATION_ID
            or current["profile_fingerprint"] != PROFILE_FINGERPRINT
            or current["plan_sha256"] != PLAN_SHA256
            or current["invocation_sha256"] != invocation_sha256
            or current["ordinal"] != ordinal
            or current["stage_id"] != EXPECTED_STAGES[ordinal]
            or current["previous_receipt_sha256"] != previous
            or current["rows"] != EXPECTED_STAGE_ROWS[ordinal]
            or current["total_rows"] != EXPECTED_TOTAL_ROWS[ordinal]
            or current["owner_cursors"] != EXPECTED_CURSORS[ordinal]
            or current["relocation_ports"] != list(EXPECTED_RELOCATIONS[ordinal])
            or current["point_snapshot_sha256"] is not None
            or current["production"] is not False
            or current["durable_resume"] is not False
            or canonical_json(current) != snapshot.raw
        ):
            raise GlobalARestartError("adapter receipt version/domain/stage/binding drift")
        previous = snapshot.identity["sha256"]
        documents.append(MappingProxyType(dict(current)))
    return tuple(documents)  # type: ignore[return-value]


def build_tree_pre_candidates_insecure_test_only(
    session: handoff.HandoffSessionInsecureTestOnly,
) -> TreePreCandidateSetInsecureTestOnly:
    """Capture the exact two-tree prefix after tree-pre[1], before global-A."""

    if (
        not isinstance(session, handoff.HandoffSessionInsecureTestOnly)
        or session.closed
        or session.failed
        or session.position != 3
        or len(session.receipts) != 3
        or tuple(session.relocation_ports) != EXPECTED_RELOCATIONS[-1]
    ):
        raise GlobalARestartError("tree-pre CandidateSet requires exact live prefix")
    receipts = tuple(_receipt_snapshot(raw, index) for index, raw in enumerate(session.receipts))
    receipt_documents = _validate_adapter_receipts(receipts, session.reference.invocation_digest)
    result_snapshots = []
    target_map = {port.port_id: port for port in session.reference.tail_summary.ports}
    for tree_index, expected_ports in enumerate(TREE_PRE_PORTS):
        source_map = {
            port.port_id: port for port in session.ports[f"tree-pre[{tree_index}]"]
            if port.direction == "output"
        }
        port_documents = []
        for port_id, source_start, target_start, width in expected_ports:
            source = source_map.get(port_id)
            target = target_map.get(port_id)
            if (
                source is None
                or target is None
                or source.wire_start != source_start
                or target.consumer_wire_start != target_start
                or source.bit_length != width
                or target.bit_length != width
            ):
                raise GlobalARestartError("live tree-pre port layout drift: " + port_id)
            source_values = tuple(session.values[source_start + bit] for bit in range(width))
            target_values = tuple(session.values[target_start + bit] for bit in range(width))
            if source_values != target_values:
                raise GlobalARestartError("source-to-target relocation value mismatch")
            packed = _pack_bits(source_values)
            if _producer_value_digest(port_id, source_values) != source.value_sha256:
                raise GlobalARestartError("producer port digest differs from captured values")
            port_documents.append(
                {
                    "port_id": port_id,
                    "source_wire_start": source_start,
                    "target_wire_start": target_start,
                    "bit_length": width,
                    "packed_bits_hex": packed.hex(),
                    "packed_bits_sha256": sha256(packed),
                    "producer_value_sha256": source.value_sha256,
                    "native_equality_bound": True,
                }
            )
        owner = f"tree[{tree_index}]"
        spool = session.spool_snapshots[tree_index]
        if type(spool) is not io.Snapshot:
            raise GlobalARestartError("tree-pre private spool identity missing")
        document = {
            "format": TREE_PRE_RESULT_FORMAT,
            "implementation_version": IMPLEMENTATION_VERSION,
            "mode": MODE,
            "relation_id": RELATION_ID,
            "source_relation_id": base.RELATION_ID,
            "profile_fingerprint": PROFILE_FINGERPRINT,
            "plan_sha256": PLAN_SHA256,
            "invocation_sha256": session.reference.invocation_digest,
            "tree_index": tree_index,
            "stage_id": f"tree-pre[{tree_index}]",
            "ready_after_stage": "tree-pre[1]",
            "pre_interval": list(io.strict_json(session.reference.plan_raw)["trees"][tree_index]["pre"]),
            "ports": port_documents,
            "private_spool_identity": spool.identity,
            "producer_receipt_sha256": receipts[tree_index + 1].identity["sha256"],
            "verified_receipt_prefix_ordinals": [0, 1, 2],
            "verified_receipt_prefix_identities": [item.identity for item in receipts],
            "all_declared_receipt_snapshots_raw_validated": True,
            "full_execution_receipt_chain_verified": False,
            "native_prefix_sha256": receipt_documents[-1]["native_prefix_identities"][owner],
            "native_binding_rows_sha256": receipt_documents[-1]["native_binding_rows_sha256"],
            "private_payload": True,
            "production": False,
        }
        raw = canonical_json(document)
        if len(raw) > TREE_PRE_RESULT_LIMIT:
            raise GlobalARestartError("tree-pre result exceeds byte bound")
        result_snapshots.append(_snapshot(TREE_PRE_RESULT_NAMES[tree_index], raw))
    handoff_document = {
        "format": HANDOFF_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "source_relation_id": base.RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "plan_sha256": PLAN_SHA256,
        "invocation_sha256": session.reference.invocation_digest,
        "stage_id": "tree-pre[1]",
        "next_stage": "global-a",
        "tree_results": [snapshot.identity for snapshot in result_snapshots],
        "adapter_receipts": [snapshot.identity for snapshot in receipts],
        "verified_receipt_prefix_ordinals": [0, 1, 2],
        "all_declared_receipt_snapshots_raw_validated": True,
        "full_execution_receipt_chain_verified": False,
        "relocation_ports": list(EXPECTED_RELOCATIONS[-1]),
        "future_consumer_uses_same_snapshots": True,
        "pathname_reopen_permitted": False,
        "metadata_proves_no_writer": False,
        "private_payload_embedded": False,
        "production": False,
        "durable_resume": False,
    }
    handoff_snapshot = _snapshot(HANDOFF_NAME, canonical_json(handoff_document))
    if len(handoff_snapshot.raw) > HANDOFF_LIMIT:
        raise GlobalARestartError("tree-pre handoff exceeds byte bound")
    candidates = TreePreCandidateSetInsecureTestOnly(
        handoff_snapshot,
        tuple(result_snapshots),  # type: ignore[arg-type]
        receipts,  # type: ignore[arg-type]
    )
    decode_tree_pre_candidates_insecure_test_only(
        candidates, expected_handoff_sha256=sha256(handoff_snapshot.raw)
    )
    return candidates


def _handoff_document(
    candidates: TreePreCandidateSetInsecureTestOnly,
    expected_handoff_sha256: str,
) -> dict[str, object]:
    _digest(expected_handoff_sha256, "external tree-pre handoff digest")
    _identity(candidates.handoff, HANDOFF_NAME, HANDOFF_LIMIT)
    if sha256(candidates.handoff.raw) != expected_handoff_sha256:
        raise GlobalARestartError("tree-pre handoff digest rejected before dependencies")
    try:
        current = candidates.handoff.document()
    except io.ValidationError as error:
        raise GlobalARestartError("tree-pre handoff is not strict canonical JSON") from error
    current = _exact(
        current,
        {
            "format",
            "implementation_version",
            "mode",
            "relation_id",
            "source_relation_id",
            "profile_fingerprint",
            "plan_sha256",
            "invocation_sha256",
            "stage_id",
            "next_stage",
            "tree_results",
            "adapter_receipts",
            "verified_receipt_prefix_ordinals",
            "all_declared_receipt_snapshots_raw_validated",
            "full_execution_receipt_chain_verified",
            "relocation_ports",
            "future_consumer_uses_same_snapshots",
            "pathname_reopen_permitted",
            "metadata_proves_no_writer",
            "private_payload_embedded",
            "production",
            "durable_resume",
        },
        "tree-pre handoff",
    )
    _digest(current["invocation_sha256"], "tree-pre invocation")
    tree_identities = current["tree_results"]
    receipt_identities = current["adapter_receipts"]
    if type(tree_identities) is not list or len(tree_identities) != 2:
        raise GlobalARestartError("tree-pre result inventory")
    if type(receipt_identities) is not list or len(receipt_identities) != 3:
        raise GlobalARestartError("adapter receipt inventory")
    for index, identity in enumerate(tree_identities):
        _identity_document(
            identity, filename=TREE_PRE_RESULT_NAMES[index], limit=TREE_PRE_RESULT_LIMIT
        )
    for index, identity in enumerate(receipt_identities):
        _identity_document(
            identity, filename=ADAPTER_RECEIPT_NAMES[index], limit=ADAPTER_RECEIPT_LIMIT
        )
    if (
        current["format"] != HANDOFF_FORMAT
        or current["implementation_version"] != IMPLEMENTATION_VERSION
        or current["mode"] != MODE
        or current["relation_id"] != RELATION_ID
        or current["source_relation_id"] != base.RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["plan_sha256"] != PLAN_SHA256
        or current["invocation_sha256"] != INVOCATION_SHA256
        or current["stage_id"] != "tree-pre[1]"
        or current["next_stage"] != "global-a"
        or current["verified_receipt_prefix_ordinals"] != [0, 1, 2]
        or current["all_declared_receipt_snapshots_raw_validated"] is not True
        or current["full_execution_receipt_chain_verified"] is not False
        or current["relocation_ports"] != list(EXPECTED_RELOCATIONS[-1])
        or current["future_consumer_uses_same_snapshots"] is not True
        or current["pathname_reopen_permitted"] is not False
        or current["metadata_proves_no_writer"] is not False
        or current["private_payload_embedded"] is not False
        or current["production"] is not False
        or current["durable_resume"] is not False
        or canonical_json(current) != candidates.handoff.raw
    ):
        raise GlobalARestartError("tree-pre handoff domain, stage or claim mismatch")
    return current


def _tree_result_document(
    snapshot: io.Snapshot,
    *,
    tree_index: int,
    identity: Mapping[str, object],
    handoff_document: Mapping[str, object],
    receipt_documents: Sequence[Mapping[str, object]],
    receipt_snapshots: Sequence[io.Snapshot],
) -> tuple[Mapping[str, object], dict[int, int]]:
    _identity(snapshot, TREE_PRE_RESULT_NAMES[tree_index], TREE_PRE_RESULT_LIMIT)
    if snapshot.identity != identity:
        raise GlobalARestartError("tree-pre result identity mismatch")
    try:
        current = snapshot.document()
    except io.ValidationError as error:
        raise GlobalARestartError("tree-pre result is not strict canonical JSON") from error
    current = _exact(
        current,
        {
            "format",
            "implementation_version",
            "mode",
            "relation_id",
            "source_relation_id",
            "profile_fingerprint",
            "plan_sha256",
            "invocation_sha256",
            "tree_index",
            "stage_id",
            "ready_after_stage",
            "pre_interval",
            "ports",
            "private_spool_identity",
            "producer_receipt_sha256",
            "verified_receipt_prefix_ordinals",
            "verified_receipt_prefix_identities",
            "all_declared_receipt_snapshots_raw_validated",
            "full_execution_receipt_chain_verified",
            "native_prefix_sha256",
            "native_binding_rows_sha256",
            "private_payload",
            "production",
        },
        "tree-pre result",
    )
    ports = current["ports"]
    if type(ports) is not list or len(ports) != 3:
        raise GlobalARestartError("exact three tree-pre output ports required")
    values: dict[int, int] = {}
    for value, expected in zip(ports, TREE_PRE_PORTS[tree_index]):
        port = _exact(
            value,
            {
                "port_id",
                "source_wire_start",
                "target_wire_start",
                "bit_length",
                "packed_bits_hex",
                "packed_bits_sha256",
                "producer_value_sha256",
                "native_equality_bound",
            },
            "tree-pre port",
        )
        port_id, source_start, target_start, width = expected
        bits = _decode_bits(port["packed_bits_hex"], width)
        packed = _pack_bits(bits)
        for digest in (port["packed_bits_sha256"], port["producer_value_sha256"]):
            _digest(digest, "tree-pre port digest")
        if (
            port["port_id"] != port_id
            or port["source_wire_start"] != source_start
            or port["target_wire_start"] != target_start
            or port["bit_length"] != width
            or port["packed_bits_sha256"] != sha256(packed)
            or port["producer_value_sha256"] != _producer_value_digest(port_id, bits)
            or port["native_equality_bound"] is not True
        ):
            raise GlobalARestartError("tree-pre port layout, value or digest mismatch")
        for offset, bit in enumerate(bits):
            wire = target_start + offset
            if wire in values:
                raise GlobalARestartError("tree-pre target wire alias")
            values[wire] = bit
    plan_tree = preflight_gate.EXPECTED_PLAN["trees"][tree_index]
    receipt_identities = [snapshot.identity for snapshot in receipt_snapshots]
    spool_identity = _identity_document(
        current["private_spool_identity"],
        filename=handoff.SPOOL_NAMES[tree_index],
        limit=handoff.codec.SPOOL_BYTES,
    )
    if spool_identity["bytes"] != handoff.codec.SPOOL_BYTES:
        raise GlobalARestartError("tree-pre private spool exact byte size")
    final_receipt = receipt_documents[-1]
    if (
        current["format"] != TREE_PRE_RESULT_FORMAT
        or current["implementation_version"] != IMPLEMENTATION_VERSION
        or current["mode"] != MODE
        or current["relation_id"] != RELATION_ID
        or current["source_relation_id"] != base.RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["plan_sha256"] != PLAN_SHA256
        or current["invocation_sha256"] != handoff_document["invocation_sha256"]
        or current["tree_index"] != tree_index
        or current["stage_id"] != f"tree-pre[{tree_index}]"
        or current["ready_after_stage"] != "tree-pre[1]"
        or current["pre_interval"] != plan_tree["pre"]
        or current["producer_receipt_sha256"]
        != receipt_identities[tree_index + 1]["sha256"]
        or current["verified_receipt_prefix_ordinals"] != [0, 1, 2]
        or current["verified_receipt_prefix_identities"] != receipt_identities
        or current["all_declared_receipt_snapshots_raw_validated"] is not True
        or current["full_execution_receipt_chain_verified"] is not False
        or current["native_prefix_sha256"]
        != final_receipt["native_prefix_identities"][f"tree[{tree_index}]"]
        or current["native_binding_rows_sha256"]
        != final_receipt["native_binding_rows_sha256"]
        or current["private_payload"] is not True
        or current["production"] is not False
        or canonical_json(current) != snapshot.raw
    ):
        raise GlobalARestartError("tree-pre result domain, chain, prefix or claim mismatch")
    return MappingProxyType(dict(current)), values


def decode_tree_pre_candidates_insecure_test_only(
    candidates: TreePreCandidateSetInsecureTestOnly,
    *,
    expected_handoff_sha256: str,
) -> DecodedTreePreCandidateSetInsecureTestOnly:
    if type(candidates) is not TreePreCandidateSetInsecureTestOnly:
        raise GlobalARestartError("exact immutable CandidateSet type required")
    handoff_document = _handoff_document(candidates, expected_handoff_sha256)
    invocation = str(handoff_document["invocation_sha256"])
    receipt_documents = _validate_adapter_receipts(candidates.receipts, invocation)
    for actual, expected in zip(candidates.receipts, handoff_document["adapter_receipts"]):
        if actual.identity != expected:
            raise GlobalARestartError("adapter receipt CandidateSet identity mismatch")
    tree_documents = []
    values: dict[int, int] = {}
    for index, (snapshot, identity) in enumerate(
        zip(candidates.tree_results, handoff_document["tree_results"])
    ):
        document, imported = _tree_result_document(
            snapshot,
            tree_index=index,
            identity=identity,
            handoff_document=handoff_document,
            receipt_documents=receipt_documents,
            receipt_snapshots=candidates.receipts,
        )
        if values.keys() & imported.keys():
            raise GlobalARestartError("tree-pre imported target intervals overlap")
        values.update(imported)
        tree_documents.append(document)
    expected_wires = {
        target + offset
        for tree_ports in TREE_PRE_PORTS
        for _, _, target, width in tree_ports
        for offset in range(width)
    }
    if set(values) != expected_wires:
        raise GlobalARestartError("Phase-A import wire inventory mismatch")
    return DecodedTreePreCandidateSetInsecureTestOnly(
        MappingProxyType(dict(handoff_document)),
        tuple(tree_documents),  # type: ignore[arg-type]
        receipt_documents,
        MappingProxyType(dict(values)),
    )


def _port_integer(document: Mapping[str, object], suffix: str) -> int:
    port = next(item for item in document["ports"] if item["port_id"].endswith(suffix))
    bits = _decode_bits(port["packed_bits_hex"], int(port["bit_length"]))
    return sum(bit << index for index, bit in enumerate(bits))


def _commitments(document: Mapping[str, object]) -> tuple[tuple[int, int], ...]:
    port = next(item for item in document["ports"] if item["port_id"].endswith("leaf-commitments"))
    bits = _decode_bits(port["packed_bits_hex"], int(port["bit_length"]))
    elements = tuple(
        sum(bits[offset + bit] << bit for bit in range(field.FIELD_DEGREE))
        for offset in range(0, len(bits), field.FIELD_DEGREE)
    )
    return tuple(zip(elements[::2], elements[1::2]))


class _PhaseASink(tail.BinaryRowSink):
    def __init__(self, values: dict[int, int], imported_wires: frozenset[int]) -> None:
        self.values = values
        self.imported_wires = imported_wires
        self.referenced_imports: set[int] = set()
        self.row_semantics = hashlib.sha256(DOMAIN_ROWS)
        super().__init__(
            {
                "format": FRAGMENT_STREAM_FORMAT,
                "relation_id": RELATION_ID,
                "profile_fingerprint": PROFILE_FINGERPRINT,
                "stage_id": "global-a",
                "wire_interval": list(PHASE_A_INTERVAL),
            },
            initial_wire=PHASE_A_INTERVAL[0],
            assignment_writer=base._Writer(values, PHASE_A_INTERVAL[0]),
        )

    def allocate(self, count: int = 1, **kwargs: object) -> int:
        if self.next_wire + count > PHASE_A_INTERVAL[1]:
            raise GlobalARestartError("Phase-A allocation exceeds reserved interval")
        return super().allocate(count, **kwargs)

    def row(
        self,
        label: str,
        left: field.LinearForm,
        right: field.LinearForm,
        output: field.LinearForm,
        *,
        nonlinear: bool,
    ) -> None:
        row = field.RankOneRow(label, left, right, output)
        for form in (left, right, output):
            for wire, _ in form.terms:
                if wire in self.imported_wires:
                    self.referenced_imports.add(wire)
                elif not PHASE_A_INTERVAL[0] <= wire < self.next_wire:
                    raise GlobalARestartError("Phase-A row used undeclared or future wire")
                if wire not in self.values:
                    raise GlobalARestartError("Phase-A row used wire without captured value")
        if not shard._row_satisfied_fast(row, self.values):
            raise GlobalARestartError("Phase-A native row failed: " + label)
        record = canonical_json(
            {
                "label": label,
                "left": left.canonical_dict(),
                "right": right.canonical_dict(),
                "output": output.canonical_dict(),
                "nonlinear": nonlinear,
            }
        )
        self.row_semantics.update(len(record).to_bytes(8, "little"))
        self.row_semantics.update(record)
        super().row(label, left, right, output, nonlinear=nonlinear)


def _global_a_calls(
    decoded: DecodedTreePreCandidateSetInsecureTestOnly,
) -> tuple[cap.XOFCall, cap.XOFCall]:
    parameters = base.PARAMETERS
    profile = bytes.fromhex(PROFILE_FINGERPRINT)
    p_values = tuple(_port_integer(document, ".p-plain") for document in decoded.tree_results)
    mhat_values = tuple(_port_integer(document, ".mhat-plain") for document in decoded.tree_results)
    polynomials = tuple(
        cap.TreePolynomial(4, 3, _commitments(document), 0, ())
        for document in decoded.tree_results
    )
    delta_p = (p_values[0] ^ p_values[1],)
    delta_mhat = (mhat_values[0] ^ mhat_values[1],)
    recorder = cap.XOFRecorder()
    h1 = recorder.call(
        "h1",
        cap.DOMAIN_H1,
        (
            profile,
            *(cap._tree_component(index, poly) for index, poly in enumerate(polynomials)),
            cap._correction_component(delta_p, delta_mhat, parameters),
        ),
        cap.HASH_BITS,
    )
    recorder.call(
        "consistency-points",
        cap.DOMAIN_CONSISTENCY_POINTS,
        (cap.hash_bytes(h1), profile),
        parameters.consistency_bits,
    )
    return tuple(recorder.calls)  # type: ignore[return-value]


def execute_global_a_insecure_test_only(
    candidates: TreePreCandidateSetInsecureTestOnly,
    *,
    expected_handoff_sha256: str,
) -> GlobalAResultInsecureTestOnly:
    """Run only Phase-A rows from the immutable tree-pre CandidateSet."""

    decoded = decode_tree_pre_candidates_insecure_test_only(
        candidates, expected_handoff_sha256=expected_handoff_sha256
    )
    values = dict(decoded.values)
    imported = frozenset(values)
    calls = _global_a_calls(decoded)
    points_output = calls[1].output
    point_values = tuple(
        (points_output >> (index * field.FIELD_DEGREE)) & field.FIELD_MASK
        for index in range(base.PARAMETERS.consistency_points)
    )
    sink = _PhaseASink(values, imported)
    pool = shard.OrderedSpongeWitnessPool(calls, 1)
    lowerer = shard.StreamingSpongeLowerer(sink, pool)
    accounting = shard.SpongeAccounting()
    try:
        commitment_starts = []
        for tree_ports in TREE_PRE_PORTS:
            start = tree_ports[0][2]
            commitment_starts.append(
                tuple(
                    (start + leaf * 2 * field.FIELD_DEGREE, start + (leaf * 2 + 1) * field.FIELD_DEGREE)
                    for leaf in range(4)
                )
            )
        p_starts = tuple(tree_ports[1][2] for tree_ports in TREE_PRE_PORTS)
        mhat_starts = tuple(tree_ports[2][2] for tree_ports in TREE_PRE_PORTS)
        correction_source = shard.source_concat(
            shard.source_constant(
                (1).to_bytes(2, "little")
                + base.PARAMETERS.witness_bits.to_bytes(4, "little")
                + base.PARAMETERS.consistency_bits.to_bytes(4, "little")
            ),
            shard.source_pad_to_byte(
                tail._xor_source(p_starts[0], p_starts[1], base.PARAMETERS.witness_bits)
            ),
            shard.source_pad_to_byte(
                tail._xor_source(
                    mhat_starts[0], mhat_starts[1], base.PARAMETERS.consistency_bits
                )
            ),
        )
        profile_source = shard.source_constant(bytes.fromhex(PROFILE_FINGERPRINT))
        tree_sources = tuple(
            tail._tree_component_source(index, 4, 3, commitment_starts[index])
            for index in range(2)
        )
        sink.start_group("h1-corrections-and-points")
        h1 = lowerer.lower(
            calls[0], (profile_source, *tree_sources, correction_source), 0
        )
        accounting = accounting.add(h1.accounting)
        if h1.output_wires != tuple(range(H1_PORT[0], H1_PORT[0] + H1_PORT[1])):
            raise GlobalARestartError("Phase-A H1 output layout drift")
        points = lowerer.lower(
            calls[1], (shard.source_hash_bytes(H1_PORT[0]), profile_source), 1
        )
        accounting = accounting.add(points.accounting)
        expected_point_wires = tuple(
            range(POINT_PORT[0], POINT_PORT[0] + POINT_PORT[1])
        )
        if points.output_wires != expected_point_wires:
            raise GlobalARestartError("Phase-A point output layout drift")
        shard._point_validation(sink, POINT_STARTS, point_values, "consistency.validate")
        sink.finish_group()
    finally:
        pool.close()
    if sink.next_wire != PHASE_A_INTERVAL[1] or sink.rows != PHASE_A_ROWS:
        raise GlobalARestartError("Phase-A final cursor or row count drift")
    if sink.referenced_imports != set(imported):
        raise GlobalARestartError("Phase-A did not consume every declared import wire")
    trailer = {
        "external_assertions": 0,
        "output_ports": [
            {"port_id": "global.phase-a.h1", "wire_start": H1_PORT[0], "bit_length": H1_PORT[1]},
            {"port_id": "global.phase-a.consistency-points", "wire_start": POINT_PORT[0], "bit_length": POINT_PORT[1]},
        ],
        "rows": sink.rows,
        "wire_interval": list(PHASE_A_INTERVAL),
        "wires": sink.allocated_wires,
    }
    stream_bytes, stream_sha = sink.finish(trailer)
    owned_values = tuple(values[wire] for wire in range(*PHASE_A_INTERVAL))
    h1_value = calls[0].output
    point_raw = canonical_json(
        {
            "format": base.FORMAT + "-POINT-PORT",
            "relation_id": base.RELATION_ID,
            "profile_fingerprint": PROFILE_FINGERPRINT,
            "invocation_sha256": decoded.handoff["invocation_sha256"],
            "plan_sha256": PLAN_SHA256,
            "producer": "global-a",
            "consumers": ["tree-post[0]", "tree-post[1]", "global-b"],
            "wire_starts": list(POINT_STARTS),
            "field_bits": field.FIELD_DEGREE,
            "values": list(point_values),
        }
    )
    point_snapshot = _snapshot(POINT_NAME, point_raw)
    groups = [
        {"name": group.name, "rows": group.rows, "bytes": group.bytes, "sha256": group.sha256}
        for group in sink.groups
    ]
    summary = {
        "format": FRAGMENT_STREAM_FORMAT,
        "relation_id": RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "stage_id": "global-a",
        "row_interval": [10_914, 30_585],
        "wire_interval": list(PHASE_A_INTERVAL),
        "rows": sink.rows,
        "nonlinear_rows": sink.nonlinear_rows,
        "linear_rows": sink.linear_rows,
        "allocated_wires": sink.allocated_wires,
        "imported_unique_wires": len(imported),
        "referenced_import_wires": len(sink.referenced_imports),
        "groups": groups,
        "sponge_accounting": {
            name: getattr(accounting, name)
            for name in accounting.__dataclass_fields__
        },
        "fragment_stream_bytes": stream_bytes,
        "fragment_stream_sha256": stream_sha,
        "row_semantics_sha256": sink.row_semantics.hexdigest(),
        "h1_sha256": tail._bits_digest(h1_value, cap.HASH_BITS),
        "point_snapshot_sha256": point_snapshot.identity["sha256"],
        "all_rows_satisfied": True,
        "external_assertions": 0,
        "full_assignment_materialized": False,
        "assignment_published": False,
        "private_owned_assignment_sha256": _private_assignment_digest(owned_values),
        "tree_pre_replayed": False,
        "production": False,
    }
    receipt_document = {
        "format": FRAGMENT_RECEIPT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "plan_sha256": PLAN_SHA256,
        "invocation_sha256": decoded.handoff["invocation_sha256"],
        "stage_id": "global-a",
        "previous_receipt_sha256": candidates.receipts[-1].identity["sha256"],
        "verified_receipt_prefix_ordinals": [0, 1, 2],
        "verified_receipt_prefix_identities": [
            snapshot.identity for snapshot in candidates.receipts
        ],
        "all_declared_receipt_snapshots_raw_validated": True,
        "full_execution_receipt_chain_verified": False,
        "tree_pre_handoff_sha256": expected_handoff_sha256,
        "tree_pre_result_sha256": [snapshot.identity["sha256"] for snapshot in candidates.tree_results],
        "summary": summary,
        "state_boundary": {
            "serialized": [
                "tree-pre CandidateSet identities and port values",
                "absolute Phase-A owned values",
                "ordered group identities",
                "row-semantics digest",
                "point snapshot",
                "raw-verified ordinal-0-to-2 receipt prefix",
            ],
            "not_serialized": list(preflight_gate.build_contract()["not_serialized_state"]),
            "tree_pre_replay_permitted": False,
            "legacy_hash_state_restored": False,
        },
        "durable_resume": False,
        "production": False,
    }
    receipt = _snapshot(FRAGMENT_RECEIPT_NAME, canonical_json(receipt_document))
    if len(receipt.raw) > FRAGMENT_RECEIPT_LIMIT:
        raise GlobalARestartError("Phase-A receipt exceeds byte bound")
    return GlobalAResultInsecureTestOnly(
        MappingProxyType(summary), owned_values, h1_value, point_values, point_snapshot, receipt
    )


def _private_result_document(result: GlobalAResultInsecureTestOnly, handoff_sha256: str) -> dict[str, object]:
    return {
        "format": PRIVATE_RESULT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "plan_sha256": PLAN_SHA256,
        "invocation_sha256": INVOCATION_SHA256,
        "stage_id": "global-a",
        "tree_pre_handoff_sha256": handoff_sha256,
        "wire_interval": list(PHASE_A_INTERVAL),
        "value_encoding": VALUE_ENCODING,
        "value_count": len(result.owned_values),
        "owned_values_hex": _encode_values(result.owned_values),
        "private_owned_assignment_sha256": result.summary["private_owned_assignment_sha256"],
        "h1": {
            "wire_start": H1_PORT[0],
            "bit_length": H1_PORT[1],
            "value_sha256": result.summary["h1_sha256"],
        },
        "points": {
            "wire_starts": list(POINT_STARTS),
            "bit_length": POINT_PORT[1],
            "snapshot_sha256": result.point_snapshot.identity["sha256"],
        },
        "source_receipt_sha256": result.receipt.identity["sha256"],
        "private_payload": True,
        "production": False,
    }


def _expected_result_snapshots(
    result: GlobalAResultInsecureTestOnly,
    handoff_sha256: str,
) -> tuple[io.Snapshot, io.Snapshot, io.Snapshot]:
    private = _snapshot(PRIVATE_RESULT_NAME, canonical_json(_private_result_document(result, handoff_sha256)))
    if len(private.raw) > PRIVATE_RESULT_LIMIT:
        raise GlobalARestartError("private Phase-A result exceeds byte bound")
    _identity(result.point_snapshot, POINT_NAME, POINT_LIMIT)
    _identity(result.receipt, FRAGMENT_RECEIPT_NAME, FRAGMENT_RECEIPT_LIMIT)
    return private, result.point_snapshot, result.receipt


def _validate_fragment_receipt(
    snapshot: io.Snapshot,
    *,
    expected_identity: Mapping[str, object],
    candidates: TreePreCandidateSetInsecureTestOnly,
    handoff_sha256: str,
) -> Mapping[str, object]:
    _identity(snapshot, FRAGMENT_RECEIPT_NAME, FRAGMENT_RECEIPT_LIMIT)
    if snapshot.identity != expected_identity:
        raise GlobalARestartError("Phase-A fragment receipt identity mismatch")
    try:
        current = snapshot.document()
    except io.ValidationError as error:
        raise GlobalARestartError("Phase-A receipt is not strict canonical JSON") from error
    current = _exact(
        current,
        {
            "format",
            "implementation_version",
            "mode",
            "relation_id",
            "profile_fingerprint",
            "plan_sha256",
            "invocation_sha256",
            "stage_id",
            "previous_receipt_sha256",
            "verified_receipt_prefix_ordinals",
            "verified_receipt_prefix_identities",
            "all_declared_receipt_snapshots_raw_validated",
            "full_execution_receipt_chain_verified",
            "tree_pre_handoff_sha256",
            "tree_pre_result_sha256",
            "summary",
            "state_boundary",
            "durable_resume",
            "production",
        },
        "Phase-A receipt",
    )
    summary = _exact(
        current["summary"],
        {
            "format",
            "relation_id",
            "profile_fingerprint",
            "stage_id",
            "row_interval",
            "wire_interval",
            "rows",
            "nonlinear_rows",
            "linear_rows",
            "allocated_wires",
            "imported_unique_wires",
            "referenced_import_wires",
            "groups",
            "sponge_accounting",
            "fragment_stream_bytes",
            "fragment_stream_sha256",
            "row_semantics_sha256",
            "h1_sha256",
            "point_snapshot_sha256",
            "all_rows_satisfied",
            "external_assertions",
            "full_assignment_materialized",
            "assignment_published",
            "private_owned_assignment_sha256",
            "tree_pre_replayed",
            "production",
        },
        "Phase-A receipt summary",
    )
    groups = summary["groups"]
    if type(groups) is not list or len(groups) != 1:
        raise GlobalARestartError("Phase-A receipt group inventory")
    group = _exact(groups[0], {"name", "rows", "bytes", "sha256"}, "Phase-A group")
    _digest(group["sha256"], "Phase-A group digest")
    accounting = _exact(
        summary["sponge_accounting"],
        set(shard.SpongeAccounting.__dataclass_fields__),
        "Phase-A sponge accounting",
    )
    if any(not _is_int(value) or value < 0 for value in accounting.values()):
        raise GlobalARestartError("Phase-A sponge accounting values")
    state_boundary = _exact(
        current["state_boundary"],
        {
            "serialized",
            "not_serialized",
            "tree_pre_replay_permitted",
            "legacy_hash_state_restored",
        },
        "Phase-A state boundary",
    )
    for name in (
        "fragment_stream_sha256",
        "row_semantics_sha256",
        "h1_sha256",
        "point_snapshot_sha256",
        "private_owned_assignment_sha256",
    ):
        _digest(summary.get(name), "Phase-A summary digest")
    if (
        current["format"] != FRAGMENT_RECEIPT_FORMAT
        or current["implementation_version"] != IMPLEMENTATION_VERSION
        or current["mode"] != MODE
        or current["relation_id"] != RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["plan_sha256"] != PLAN_SHA256
        or current["invocation_sha256"] != INVOCATION_SHA256
        or current["stage_id"] != "global-a"
        or current["previous_receipt_sha256"] != candidates.receipts[-1].identity["sha256"]
        or current["verified_receipt_prefix_ordinals"] != [0, 1, 2]
        or current["verified_receipt_prefix_identities"]
        != [snapshot.identity for snapshot in candidates.receipts]
        or current["all_declared_receipt_snapshots_raw_validated"] is not True
        or current["full_execution_receipt_chain_verified"] is not False
        or current["tree_pre_handoff_sha256"] != handoff_sha256
        or current["tree_pre_result_sha256"]
        != [item.identity["sha256"] for item in candidates.tree_results]
        or summary["format"] != FRAGMENT_STREAM_FORMAT
        or summary["relation_id"] != RELATION_ID
        or summary["profile_fingerprint"] != PROFILE_FINGERPRINT
        or summary["stage_id"] != "global-a"
        or summary["row_interval"] != [10_914, 30_585]
        or summary.get("rows") != PHASE_A_ROWS
        or summary.get("wire_interval") != list(PHASE_A_INTERVAL)
        or summary["nonlinear_rows"] + summary["linear_rows"] != PHASE_A_ROWS
        or summary["allocated_wires"] != PHASE_A_INTERVAL[1] - PHASE_A_INTERVAL[0]
        or summary["imported_unique_wires"] != 7_956
        or summary["referenced_import_wires"] != 7_956
        or group["name"] != "h1-corrections-and-points"
        or group["rows"] != PHASE_A_ROWS
        or summary["fragment_stream_bytes"] <= 0
        or summary.get("all_rows_satisfied") is not True
        or summary["external_assertions"] != 0
        or summary["full_assignment_materialized"] is not False
        or summary["assignment_published"] is not False
        or summary.get("tree_pre_replayed") is not False
        or summary.get("production") is not False
        or state_boundary["serialized"]
        != [
            "tree-pre CandidateSet identities and port values",
            "absolute Phase-A owned values",
            "ordered group identities",
            "row-semantics digest",
            "point snapshot",
            "raw-verified ordinal-0-to-2 receipt prefix",
        ]
        or state_boundary["not_serialized"]
        != list(preflight_gate.build_contract()["not_serialized_state"])
        or state_boundary["tree_pre_replay_permitted"] is not False
        or state_boundary["legacy_hash_state_restored"] is not False
        or current["durable_resume"] is not False
        or current["production"] is not False
        or canonical_json(current) != snapshot.raw
    ):
        raise GlobalARestartError("Phase-A receipt domain, dependency or claim mismatch")
    return MappingProxyType(dict(current))


def _validate_points(
    snapshot: io.Snapshot,
    *,
    expected_identity: Mapping[str, object],
) -> tuple[int, ...]:
    _identity(snapshot, POINT_NAME, POINT_LIMIT)
    if snapshot.identity != expected_identity:
        raise GlobalARestartError("Phase-A point snapshot identity mismatch")
    try:
        current = snapshot.document()
    except io.ValidationError as error:
        raise GlobalARestartError("point snapshot is not strict canonical JSON") from error
    expected_fields = {
        "format",
        "relation_id",
        "profile_fingerprint",
        "invocation_sha256",
        "plan_sha256",
        "producer",
        "consumers",
        "wire_starts",
        "field_bits",
        "values",
    }
    current = _exact(current, expected_fields, "point snapshot")
    values = current["values"]
    if (
        type(values) is not list
        or len(values) != 2
        or any(not _is_int(value) or not 0 < int(value) < field.FIELD_ORDER for value in values)
        or values[0] == values[1]
    ):
        raise GlobalARestartError("point values are not two unique nonzero F193 elements")
    if (
        current["format"] != base.FORMAT + "-POINT-PORT"
        or current["relation_id"] != base.RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["invocation_sha256"] != INVOCATION_SHA256
        or current["plan_sha256"] != PLAN_SHA256
        or current["producer"] != "global-a"
        or current["consumers"] != ["tree-post[0]", "tree-post[1]", "global-b"]
        or current["wire_starts"] != list(POINT_STARTS)
        or current["field_bits"] != field.FIELD_DEGREE
        or canonical_json(current) != snapshot.raw
    ):
        raise GlobalARestartError("point snapshot domain, layout or consumer mismatch")
    return tuple(int(value) for value in values)


def _validate_private_result(
    snapshot: io.Snapshot,
    *,
    expected_identity: Mapping[str, object],
    point_snapshot: io.Snapshot,
    receipt_snapshot: io.Snapshot,
    receipt_document: Mapping[str, object],
    handoff_sha256: str,
) -> tuple[tuple[int, ...], int, tuple[int, ...]]:
    _identity(snapshot, PRIVATE_RESULT_NAME, PRIVATE_RESULT_LIMIT)
    if snapshot.identity != expected_identity:
        raise GlobalARestartError("private Phase-A result identity mismatch")
    try:
        current = snapshot.document()
    except io.ValidationError as error:
        raise GlobalARestartError("private Phase-A result is not strict canonical JSON") from error
    current = _exact(
        current,
        {
            "format",
            "implementation_version",
            "mode",
            "relation_id",
            "profile_fingerprint",
            "plan_sha256",
            "invocation_sha256",
            "stage_id",
            "tree_pre_handoff_sha256",
            "wire_interval",
            "value_encoding",
            "value_count",
            "owned_values_hex",
            "private_owned_assignment_sha256",
            "h1",
            "points",
            "source_receipt_sha256",
            "private_payload",
            "production",
        },
        "private Phase-A result",
    )
    h1_doc = _exact(current["h1"], {"wire_start", "bit_length", "value_sha256"}, "H1 output")
    point_doc = _exact(current["points"], {"wire_starts", "bit_length", "snapshot_sha256"}, "point output")
    values = _decode_values(current["owned_values_hex"])
    h1_offset = H1_PORT[0] - PHASE_A_INTERVAL[0]
    h1_bits = values[h1_offset : h1_offset + H1_PORT[1]]
    if any(value not in (0, 1) for value in h1_bits):
        raise GlobalARestartError("H1 output slice is not bits")
    h1 = sum(value << bit for bit, value in enumerate(h1_bits))
    points = _validate_points(point_snapshot, expected_identity=point_snapshot.identity)
    point_values_from_assignment = []
    for start in POINT_STARTS:
        offset = start - PHASE_A_INTERVAL[0]
        bits = values[offset : offset + field.FIELD_DEGREE]
        if any(value not in (0, 1) for value in bits):
            raise GlobalARestartError("point output slice is not bits")
        point_values_from_assignment.append(sum(value << bit for bit, value in enumerate(bits)))
    summary = receipt_document["summary"]
    for digest in (
        current["private_owned_assignment_sha256"],
        h1_doc["value_sha256"],
        point_doc["snapshot_sha256"],
        current["source_receipt_sha256"],
    ):
        _digest(digest, "private Phase-A result digest")
    if (
        current["format"] != PRIVATE_RESULT_FORMAT
        or current["implementation_version"] != IMPLEMENTATION_VERSION
        or current["mode"] != MODE
        or current["relation_id"] != RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["plan_sha256"] != PLAN_SHA256
        or current["invocation_sha256"] != INVOCATION_SHA256
        or current["stage_id"] != "global-a"
        or current["tree_pre_handoff_sha256"] != handoff_sha256
        or current["wire_interval"] != list(PHASE_A_INTERVAL)
        or current["value_encoding"] != VALUE_ENCODING
        or current["value_count"] != len(values)
        or current["private_owned_assignment_sha256"] != _private_assignment_digest(values)
        or current["private_owned_assignment_sha256"] != summary["private_owned_assignment_sha256"]
        or h1_doc != {
            "wire_start": H1_PORT[0],
            "bit_length": H1_PORT[1],
            "value_sha256": tail._bits_digest(h1, cap.HASH_BITS),
        }
        or h1_doc["value_sha256"] != summary["h1_sha256"]
        or point_doc != {
            "wire_starts": list(POINT_STARTS),
            "bit_length": POINT_PORT[1],
            "snapshot_sha256": point_snapshot.identity["sha256"],
        }
        or point_doc["snapshot_sha256"] != summary["point_snapshot_sha256"]
        or tuple(point_values_from_assignment) != points
        or current["source_receipt_sha256"] != receipt_snapshot.identity["sha256"]
        or current["private_payload"] is not True
        or current["production"] is not False
        or canonical_json(current) != snapshot.raw
    ):
        raise GlobalARestartError("private Phase-A result binding, values or claim mismatch")
    return values, h1, points


def _input_snapshots(
    candidates: TreePreCandidateSetInsecureTestOnly,
) -> tuple[io.Snapshot, ...]:
    return (candidates.handoff, *candidates.tree_results, *candidates.receipts)


def _input_limits() -> tuple[int, ...]:
    return (
        HANDOFF_LIMIT,
        TREE_PRE_RESULT_LIMIT,
        TREE_PRE_RESULT_LIMIT,
        ADAPTER_RECEIPT_LIMIT,
        ADAPTER_RECEIPT_LIMIT,
        ADAPTER_RECEIPT_LIMIT,
    )


def _plan_document(
    candidates: TreePreCandidateSetInsecureTestOnly, *, expected_handoff_sha256: str
) -> dict[str, object]:
    decoded = decode_tree_pre_candidates_insecure_test_only(
        candidates, expected_handoff_sha256=expected_handoff_sha256
    )
    return {
        "format": CHECKPOINT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "plan_sha256": PLAN_SHA256,
        "invocation_sha256": decoded.handoff["invocation_sha256"],
        "stage_id": "publication-plan",
        "ordinal": 0,
        "previous_checkpoint_sha256": None,
        "tree_pre_handoff_sha256": expected_handoff_sha256,
        "input_identities": [snapshot.identity for snapshot in _input_snapshots(candidates)],
        "next_stage": "inputs-committed",
        "complete": False,
        "production": False,
    }


def _validate_plan(snapshot: io.Snapshot) -> dict[str, object]:
    _identity(snapshot, PLAN_NAME, CHECKPOINT_LIMIT)
    try:
        current = snapshot.document()
    except io.ValidationError as error:
        raise GlobalARestartError("publication plan is not strict canonical JSON") from error
    current = _exact(
        current,
        {
            "format",
            "implementation_version",
            "mode",
            "relation_id",
            "profile_fingerprint",
            "plan_sha256",
            "invocation_sha256",
            "stage_id",
            "ordinal",
            "previous_checkpoint_sha256",
            "tree_pre_handoff_sha256",
            "input_identities",
            "next_stage",
            "complete",
            "production",
        },
        "publication plan",
    )
    _digest(current["tree_pre_handoff_sha256"], "publication handoff")
    identities = current["input_identities"]
    if type(identities) is not list or len(identities) != len(INPUT_NAMES):
        raise GlobalARestartError("publication input inventory")
    for identity, name, limit in zip(identities, INPUT_NAMES, _input_limits()):
        _identity_document(identity, filename=name, limit=limit)
    if (
        current["format"] != CHECKPOINT_FORMAT
        or current["implementation_version"] != IMPLEMENTATION_VERSION
        or current["mode"] != MODE
        or current["relation_id"] != RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["plan_sha256"] != PLAN_SHA256
        or current["invocation_sha256"] != INVOCATION_SHA256
        or current["stage_id"] != "publication-plan"
        or current["ordinal"] != 0
        or current["previous_checkpoint_sha256"] is not None
        or current["next_stage"] != "inputs-committed"
        or current["complete"] is not False
        or current["production"] is not False
        or canonical_json(current) != snapshot.raw
    ):
        raise GlobalARestartError("publication plan domain, stage or claim mismatch")
    return current


def _checkpoint_document(
    stage_id: str,
    ordinal: int,
    previous: io.Snapshot,
    plan: io.Snapshot,
    *,
    inputs: Sequence[Mapping[str, object]],
    outputs: Sequence[Mapping[str, object]],
    complete: bool,
) -> dict[str, object]:
    return {
        "format": CHECKPOINT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "plan_sha256": PLAN_SHA256,
        "invocation_sha256": INVOCATION_SHA256,
        "stage_id": stage_id,
        "ordinal": ordinal,
        "previous_checkpoint_sha256": previous.identity["sha256"],
        "publication_plan_sha256": plan.identity["sha256"],
        "input_identities": list(inputs),
        "output_identities": list(outputs),
        "next_stage": None if complete else (
            "result-committed" if stage_id == "inputs-committed" else "complete"
        ),
        "complete": complete,
        "production": False,
    }


def _require_checkpoint(
    snapshot: io.Snapshot, expected: Mapping[str, object], name: str
) -> dict[str, object]:
    _identity(snapshot, name, CHECKPOINT_LIMIT)
    try:
        current = snapshot.document()
    except io.ValidationError as error:
        raise GlobalARestartError("checkpoint is not strict canonical JSON: " + name) from error
    if current != expected or canonical_json(current) != snapshot.raw:
        raise GlobalARestartError("checkpoint chain, inventory or claim mismatch: " + name)
    return current


def _names(path: Path) -> set[str]:
    with io.directory_fd(path, external=True) as descriptor:
        names = set(os.listdir(descriptor))
        io._same_directory(path, descriptor, external=True)
        return names


def _journal_shape(names: set[str]) -> tuple[str, ...]:
    if not names or names - set(JOURNAL_NAMES):
        raise GlobalARestartError("unknown or empty Phase-A publication journal")
    ordered = tuple(name for name in JOURNAL_NAMES if name in names)
    if ordered != JOURNAL_NAMES[: len(ordered)]:
        raise GlobalARestartError("Phase-A journal is not a contiguous prefix")
    return ordered


def latest_checkpoint(output: Path, *, artifact_root: Path) -> io.Snapshot:
    root = io.ArtifactRoot(artifact_root)
    root.require_location(output / JOURNAL_DIRECTORY / COMPLETE_NAME)
    ordered = _journal_shape(_names(output / JOURNAL_DIRECTORY))
    return disk.read(output / JOURNAL_DIRECTORY / ordered[-1])


def _capture_journal(output: Path, latest: io.Snapshot | None = None) -> dict[str, io.Snapshot]:
    ordered = _journal_shape(_names(output / JOURNAL_DIRECTORY))
    captured = {}
    for name in ordered:
        path = output / JOURNAL_DIRECTORY / name
        captured[name] = latest if latest is not None and latest.location == path else disk.read(path)
    return captured


def _load_candidates(
    output: Path, plan_document: Mapping[str, object]
) -> TreePreCandidateSetInsecureTestOnly:
    present = _names(output / INPUT_DIRECTORY)
    if present - set(INPUT_NAMES):
        raise GlobalARestartError("unknown private Phase-A input artifact")
    if present != set(INPUT_NAMES):
        raise GlobalARestartError("private Phase-A input publication is incomplete")
    snapshots = []
    for name, expected, limit in zip(INPUT_NAMES, plan_document["input_identities"], _input_limits()):
        snapshot = disk.read(output / INPUT_DIRECTORY / name)
        if _identity(snapshot, name, limit) != expected:
            raise GlobalARestartError("published Phase-A input identity mismatch: " + name)
        snapshots.append(snapshot)
    candidates = TreePreCandidateSetInsecureTestOnly(
        snapshots[0], tuple(snapshots[1:3]), tuple(snapshots[3:6])
    )
    decode_tree_pre_candidates_insecure_test_only(
        candidates,
        expected_handoff_sha256=str(plan_document["tree_pre_handoff_sha256"]),
    )
    return candidates


def _validate_published_results(
    output: Path,
    *,
    identities: Sequence[Mapping[str, object]],
    candidates: TreePreCandidateSetInsecureTestOnly,
    handoff_sha256: str,
    captured: Mapping[str, io.Snapshot] | None = None,
) -> PublishedGlobalAResultInsecureTestOnly:
    if len(identities) != 3:
        raise GlobalARestartError("exact three Phase-A output identities required")
    limits = (PRIVATE_RESULT_LIMIT, POINT_LIMIT, FRAGMENT_RECEIPT_LIMIT)
    snapshots = []
    captured = {} if captured is None else captured
    for name, identity, limit in zip(RESULT_NAMES, identities, limits):
        _identity_document(identity, filename=name, limit=limit)
        snapshot = captured.get(name) or disk.read(output / RESULT_DIRECTORY / name)
        if snapshot.location != output / RESULT_DIRECTORY / name or snapshot.identity != identity:
            raise GlobalARestartError("published Phase-A output pathname or identity mismatch")
        snapshots.append(snapshot)
    private, points, receipt = snapshots
    receipt_document = _validate_fragment_receipt(
        receipt,
        expected_identity=identities[2],
        candidates=candidates,
        handoff_sha256=handoff_sha256,
    )
    point_values = _validate_points(points, expected_identity=identities[1])
    values, h1, private_points = _validate_private_result(
        private,
        expected_identity=identities[0],
        point_snapshot=points,
        receipt_snapshot=receipt,
        receipt_document=receipt_document,
        handoff_sha256=handoff_sha256,
    )
    if point_values != private_points:
        raise GlobalARestartError("point output differs across published artifacts")
    return PublishedGlobalAResultInsecureTestOnly(
        values, h1, point_values, private, points, receipt, _snapshot(COMPLETE_NAME, b"{}\n")
    )


def _stop(stop_after: str | None, boundary: str) -> bool:
    return stop_after == boundary


def run_bounded_global_a(
    output: Path,
    *,
    artifact_root: Path,
    fresh_candidates: TreePreCandidateSetInsecureTestOnly | None = None,
    expected_handoff_sha256: str | None = None,
    fresh_output: bool = False,
    resume: bool = False,
    expected_checkpoint_sha256: str | None = None,
    stop_after: str | None = None,
) -> PublishedGlobalAResultInsecureTestOnly | None:
    """Publish or resume the bounded private Global-A workflow."""

    validate_prerequisites()
    if type(fresh_output) is not bool or type(resume) is not bool or fresh_output == resume:
        raise GlobalARestartError("select exactly one of fresh_output or resume")
    if stop_after is not None and stop_after not in STOP_BOUNDARIES:
        raise GlobalARestartError("unknown Global-A stop boundary")
    expected_plan_raw = None
    source_snapshots = None
    if fresh_output:
        if (
            type(fresh_candidates) is not TreePreCandidateSetInsecureTestOnly
            or expected_handoff_sha256 is None
            or expected_checkpoint_sha256 is not None
        ):
            raise GlobalARestartError("fresh Global-A publication requires CandidateSet and digest")
        plan_document = _plan_document(
            fresh_candidates, expected_handoff_sha256=expected_handoff_sha256
        )
        expected_plan_raw = canonical_json(plan_document)
        source_snapshots = _input_snapshots(fresh_candidates)
    else:
        if fresh_candidates is not None or expected_handoff_sha256 is not None:
            raise GlobalARestartError("resume accepts no live CandidateSet or handoff override")
        _digest(expected_checkpoint_sha256, "external restart checkpoint")

    with disk.locked_output(output, artifact_root, fresh=fresh_output) as output_fd:
        if fresh_output:
            for name in (INPUT_DIRECTORY, RESULT_DIRECTORY, JOURNAL_DIRECTORY):
                os.mkdir(name, mode=0o700, dir_fd=output_fd)
            os.fsync(output_fd)
            disk.publish(output / JOURNAL_DIRECTORY / PLAN_NAME, expected_plan_raw)
            for snapshot in source_snapshots:
                disk.publish(output / INPUT_DIRECTORY / snapshot.location.name, snapshot.raw)
        with io.directory_fd(output / INPUT_DIRECTORY, external=True) as input_fd, \
                io.directory_fd(output / RESULT_DIRECTORY, external=True) as result_fd, \
                io.directory_fd(output / JOURNAL_DIRECTORY, external=True) as journal_fd:
            latest = None
            if resume:
                latest = latest_checkpoint(output, artifact_root=artifact_root)
                if latest.identity["sha256"] != expected_checkpoint_sha256:
                    raise GlobalARestartError("restart checkpoint identity mismatch or stale digest")
            journal = _capture_journal(output, latest)
            plan = journal[PLAN_NAME]
            plan_document = _validate_plan(plan)
            if expected_plan_raw is not None and plan.raw != expected_plan_raw:
                raise GlobalARestartError("fresh publication plan differs from CandidateSet")
            candidates = _load_candidates(output, plan_document)
            input_identities = plan_document["input_identities"]
            inputs_document = _checkpoint_document(
                "inputs-committed",
                1,
                plan,
                plan,
                inputs=input_identities,
                outputs=(),
                complete=False,
            )
            inputs_raw = canonical_json(inputs_document)
            inputs_expected = _snapshot(INPUTS_COMMITTED_NAME, inputs_raw)
            if INPUTS_COMMITTED_NAME in journal:
                _require_checkpoint(journal[INPUTS_COMMITTED_NAME], inputs_document, INPUTS_COMMITTED_NAME)
            elif len(journal) != 1:
                raise GlobalARestartError("journal gap before inputs-committed")
            result_names = _names(output / RESULT_DIRECTORY)
            if result_names - set(RESULT_NAMES):
                raise GlobalARestartError("unknown private Phase-A result artifact")
            expected_prefix = tuple(name for name in RESULT_NAMES if name in result_names)
            if set(expected_prefix) != result_names or expected_prefix != RESULT_NAMES[: len(expected_prefix)]:
                raise GlobalARestartError("Phase-A output publication is not a contiguous prefix")
            if INPUTS_COMMITTED_NAME not in journal and result_names:
                raise GlobalARestartError("Phase-A output exists before restartable input boundary")
            disk.sync_directory(output / INPUT_DIRECTORY, input_fd)
            disk.sync_directory(output / RESULT_DIRECTORY, result_fd)
            disk.sync_directory(output / JOURNAL_DIRECTORY, journal_fd)
            disk.sync_directory(output, output_fd)
            if INPUTS_COMMITTED_NAME not in journal:
                disk.publish(output / JOURNAL_DIRECTORY / INPUTS_COMMITTED_NAME, inputs_raw)
                journal[INPUTS_COMMITTED_NAME] = inputs_expected
            inputs_checkpoint = journal[INPUTS_COMMITTED_NAME]
            if _stop(stop_after, "inputs"):
                return None

            if RESULT_COMMITTED_NAME in journal:
                result_checkpoint_document = journal[RESULT_COMMITTED_NAME].document()
                identities = result_checkpoint_document.get("output_identities")
                published = _validate_published_results(
                    output,
                    identities=identities,
                    candidates=candidates,
                    handoff_sha256=str(plan_document["tree_pre_handoff_sha256"]),
                )
            else:
                result = execute_global_a_insecure_test_only(
                    candidates,
                    expected_handoff_sha256=str(plan_document["tree_pre_handoff_sha256"]),
                )
                expected_outputs = _expected_result_snapshots(
                    result, str(plan_document["tree_pre_handoff_sha256"])
                )
                captured = {}
                for index, (name, expected) in enumerate(zip(RESULT_NAMES, expected_outputs)):
                    if name in result_names:
                        actual = disk.read(output / RESULT_DIRECTORY / name)
                        if actual.raw != expected.raw:
                            raise GlobalARestartError("existing Phase-A output orphan differs: " + name)
                        captured[name] = actual
                        disk.sync_directory(output / RESULT_DIRECTORY, result_fd)
                    else:
                        disk.publish(output / RESULT_DIRECTORY / name, expected.raw)
                        result_names.add(name)
                        captured[name] = io.Snapshot(output / RESULT_DIRECTORY / name, expected.raw)
                    boundary = ("result-payload", "points", "result-receipt")[index]
                    if _stop(stop_after, boundary):
                        return None
                identities = [snapshot.identity for snapshot in expected_outputs]
                published = _validate_published_results(
                    output,
                    identities=identities,
                    candidates=candidates,
                    handoff_sha256=str(plan_document["tree_pre_handoff_sha256"]),
                    captured=captured,
                )
                result_document = _checkpoint_document(
                    "result-committed",
                    2,
                    inputs_checkpoint,
                    plan,
                    inputs=input_identities,
                    outputs=identities,
                    complete=False,
                )
                result_raw = canonical_json(result_document)
                disk.publish(output / JOURNAL_DIRECTORY / RESULT_COMMITTED_NAME, result_raw)
                journal[RESULT_COMMITTED_NAME] = _snapshot(RESULT_COMMITTED_NAME, result_raw)
            result_checkpoint = journal[RESULT_COMMITTED_NAME]
            result_checkpoint_expected = _checkpoint_document(
                "result-committed",
                2,
                inputs_checkpoint,
                plan,
                inputs=input_identities,
                outputs=identities,
                complete=False,
            )
            _require_checkpoint(result_checkpoint, result_checkpoint_expected, RESULT_COMMITTED_NAME)
            if _stop(stop_after, "result-checkpoint"):
                return None

            complete_document = _checkpoint_document(
                "complete",
                3,
                result_checkpoint,
                plan,
                inputs=input_identities,
                outputs=identities,
                complete=True,
            )
            complete_raw = canonical_json(complete_document)
            if COMPLETE_NAME in journal:
                _require_checkpoint(journal[COMPLETE_NAME], complete_document, COMPLETE_NAME)
            else:
                disk.publish(output / JOURNAL_DIRECTORY / COMPLETE_NAME, complete_raw)
                journal[COMPLETE_NAME] = _snapshot(COMPLETE_NAME, complete_raw)
            published = PublishedGlobalAResultInsecureTestOnly(
                published.owned_values,
                published.h1,
                published.points,
                published.result,
                published.point_snapshot,
                published.receipt,
                journal[COMPLETE_NAME],
            )
            if _stop(stop_after, "complete") or stop_after is None:
                return published
    raise GlobalARestartError("unreachable Global-A restart state")


def capture_completed_result(
    output: Path, *, artifact_root: Path, expected_complete_sha256: str
) -> PublishedGlobalAResultInsecureTestOnly:
    _digest(expected_complete_sha256, "external complete checkpoint")
    latest = latest_checkpoint(output, artifact_root=artifact_root)
    if latest.location.name != COMPLETE_NAME or latest.identity["sha256"] != expected_complete_sha256:
        raise GlobalARestartError("complete checkpoint identity mismatch")
    journal = _capture_journal(output, latest)
    plan = journal[PLAN_NAME]
    plan_document = _validate_plan(plan)
    candidates = _load_candidates(output, plan_document)
    inputs_document = _checkpoint_document(
        "inputs-committed",
        1,
        plan,
        plan,
        inputs=plan_document["input_identities"],
        outputs=(),
        complete=False,
    )
    _require_checkpoint(journal[INPUTS_COMMITTED_NAME], inputs_document, INPUTS_COMMITTED_NAME)
    result_document = journal[RESULT_COMMITTED_NAME].document()
    expected_result = _checkpoint_document(
        "result-committed",
        2,
        journal[INPUTS_COMMITTED_NAME],
        plan,
        inputs=plan_document["input_identities"],
        outputs=result_document.get("output_identities", ()),
        complete=False,
    )
    _require_checkpoint(journal[RESULT_COMMITTED_NAME], expected_result, RESULT_COMMITTED_NAME)
    complete_document = _checkpoint_document(
        "complete",
        3,
        journal[RESULT_COMMITTED_NAME],
        plan,
        inputs=plan_document["input_identities"],
        outputs=result_document["output_identities"],
        complete=True,
    )
    _require_checkpoint(latest, complete_document, COMPLETE_NAME)
    published = _validate_published_results(
        output,
        identities=result_document["output_identities"],
        candidates=candidates,
        handoff_sha256=str(plan_document["tree_pre_handoff_sha256"]),
    )
    return PublishedGlobalAResultInsecureTestOnly(
        published.owned_values,
        published.h1,
        published.points,
        published.result,
        published.point_snapshot,
        published.receipt,
        latest,
    )


def execute_production(*_args: object, **_kwargs: object) -> None:
    raise ProductionUnavailable(
        "bounded Global-A restart is test-only; production refused before I/O"
    )


def preflight() -> dict[str, object]:
    validate_prerequisites()
    return {
        "format": FORMAT,
        "relation_id": RELATION_ID,
        "read_only_preflight_passed": True,
        "independent_global_a_consumer_implemented": True,
        "tree_pre_output_candidate_set_implemented": True,
        "private_append_only_global_a_publication_implemented": True,
        "restartable_boundary": "inputs-committed",
        "verified_receipt_prefix_ordinals": [0, 1, 2],
        "all_declared_receipt_snapshots_raw_validated": True,
        "receipt_prefix_links_verified": True,
        "scheduler_receipt_suffix_overlap_ordinal": 2,
        "full_execution_receipt_chain_verified": False,
        "global_b_consumer_implemented": False,
        "global_b_same_invocation_candidate_set_implemented": False,
        "global_tail_continuation_implemented": False,
        "production_durable_resume_implemented": False,
        "safe_to_run_bounded_insecure_test_only": True,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
        "production_rows_replayed": 0,
        "proofs_generated": 0,
        "missing_production_artifacts": list(production_inputs.REQUIRED_EXTERNAL_ARTIFACTS),
        "production_execution_command": None,
        "large_replay_command": None,
        "large_proving_command": None,
        "Proof-closed": False,
        "Production-closed": False,
    }


@lru_cache(maxsize=1)
def bounded_self_check() -> dict[str, object]:
    session = handoff.HandoffSessionInsecureTestOnly()
    try:
        session.run_to("tree-pre[1]")
        candidates = build_tree_pre_candidates_insecure_test_only(session)
        handoff_sha = sha256(candidates.handoff.raw)
        independent = execute_global_a_insecure_test_only(
            candidates, expected_handoff_sha256=handoff_sha
        )
        session.run_to("global-a")
        live_values = tuple(session.values[wire] for wire in range(*PHASE_A_INTERVAL))
        if live_values != independent.owned_values or session.point_snapshot.raw != independent.point_snapshot.raw:
            raise GlobalARestartError("independent Phase-A differs from live native prefix")
        with TemporaryDirectory(prefix="pq-rbbc-global-a-restart-self-check-") as directory:
            root = Path(directory)
            output = root / "global-a"
            run_bounded_global_a(
                output,
                artifact_root=root,
                fresh_candidates=candidates,
                expected_handoff_sha256=handoff_sha,
                fresh_output=True,
                stop_after="inputs",
            )
            checkpoint = latest_checkpoint(output, artifact_root=root)
            restarted = run_bounded_global_a(
                output,
                artifact_root=root,
                resume=True,
                expected_checkpoint_sha256=checkpoint.identity["sha256"],
            )
            captured = capture_completed_result(
                output,
                artifact_root=root,
                expected_complete_sha256=restarted.complete_checkpoint.identity["sha256"],
            )
            if captured.owned_values != independent.owned_values:
                raise GlobalARestartError("published/restarted Phase-A values differ")
        return {
            "format": FORMAT,
            "relation_id": RELATION_ID,
            "mode": MODE,
            "tree_pre_handoff_identity": candidates.handoff.identity,
            "tree_pre_result_identities": [item.identity for item in candidates.tree_results],
            "adapter_receipt_identities": [item.identity for item in candidates.receipts],
            "verified_receipt_prefix_ordinals": [0, 1, 2],
            "all_declared_receipt_snapshots_raw_validated": True,
            "receipt_prefix_links_verified": True,
            "scheduler_receipt_suffix_overlap_ordinal": 2,
            "full_execution_receipt_chain_verified": False,
            "phase_a_rows": independent.summary["rows"],
            "phase_a_allocated_wires": len(independent.owned_values),
            "phase_a_fragment_stream_sha256": independent.summary["fragment_stream_sha256"],
            "phase_a_row_semantics_sha256": independent.summary["row_semantics_sha256"],
            "phase_a_private_assignment_sha256": independent.summary["private_owned_assignment_sha256"],
            "point_snapshot_identity": independent.point_snapshot.identity,
            "fragment_receipt_identity": independent.receipt.identity,
            "private_result_identity": restarted.result.identity,
            "complete_checkpoint_identity": restarted.complete_checkpoint.identity,
            "independent_matches_live_native_phase_a": True,
            "completed_result_consumed_without_phase_a_replay": True,
            "tree_pre_replayed_by_independent_consumer": False,
            "full_assignment_materialized": False,
            "private_payload_embedded_in_portable_evidence": False,
            "other_tree_observed_stream_bytes_used": False,
            "production_rows_replayed": 0,
            "proofs_generated": 0,
            "Proof-closed": False,
            "Production-closed": False,
        }
    finally:
        session.close()


def build_manifest() -> dict[str, object]:
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "implementation_identities": {
            path: io.read_snapshot(ROOT / path).identity
            for path in (
                "src/pq_rbbc_issuance_global_a_restart_v1.py",
                "tests/test_pq_rbbc_issuance_global_a_restart_v1.py",
            )
        },
        "predecessor_identities": {
            path: {"bytes": size, "sha256": digest}
            for path, (size, digest) in PREDECESSOR_PINS.items()
        },
        "bounded_qualification": bounded_self_check(),
        "preflight": preflight(),
        "publication_contract": {
            "input_names": list(INPUT_NAMES),
            "result_names": list(RESULT_NAMES),
            "journal_names": list(JOURNAL_NAMES),
            "restartable_boundary": "inputs-committed",
            "exclusive_create_never_overwrite": True,
            "caller_supplies_exact_resume_checkpoint_sha256": True,
            "same_raw_for_identity_parse_binding_and_consumer": True,
            "pathname_reopen_after_capture_permitted": False,
            "metadata_proves_no_writer": False,
            "trusted_producer_handoff_and_writer_quiescence_external": True,
            "verified_receipt_prefix_ordinals": [0, 1, 2],
            "all_declared_receipt_snapshots_raw_validated": True,
            "full_execution_receipt_chain_verified": False,
        },
        "claim_status": {
            "Defined": True,
            "Instantiated": "two-tree-4plus4-insecure-test-only",
            "Implemented": "independent-global-a-and-private-append-only-restart",
            "Tested": "bounded-positive-negative-mutation-and-restart",
            "Evidence-sealed": "metadata-only",
            "Proof-closed": False,
            "Production-closed": False,
            "global_b_consumer_implemented": False,
            "global_tail_continuation_implemented": False,
            "production_legacy18_provider_implemented": False,
            "qualified_pq_se_backend_integrated": False,
            "formal_pi_issue_generated": False,
            "full_execution_receipt_chain_verified": False,
            "global_b_same_invocation_candidate_set_implemented": False,
        },
        "resource_budget": {
            "phase_a_rows": PHASE_A_ROWS,
            "phase_a_owned_values": PHASE_A_INTERVAL[1] - PHASE_A_INTERVAL[0],
            "private_result_max_bytes": PRIVATE_RESULT_LIMIT,
            "planned_memory_mib": 512,
            "planned_seconds": 180,
            "production_estimate": None,
            "other_tree_observed_stream_bytes_used": False,
        },
        "artifact_policy": {
            "assignment_br1cs_or_row_archive_created": False,
            "pickle_cache_or_log_created": False,
            "private_result_committed": False,
            "portable_evidence_contains_private_values": False,
            "large_replay_or_proving_output_created": False,
            "system_architecture_ticket_lifecycle_or_pq_sat_auth_changed": False,
        },
        "exact_commands": {
            "read_only": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_global_a_restart_v1.py",
            "bounded": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_global_a_restart_v1.py --self-check",
            "targeted": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_global_a_restart_v1 -v",
            "production": None,
            "large_replay": None,
            "large_proving": None,
        },
    }


def build_portable_evidence() -> dict[str, object]:
    manifest_raw = canonical_json(build_manifest())
    qualification = bounded_self_check()
    return {
        "format": FORMAT + "-PORTABLE-EVIDENCE",
        "relation_id": RELATION_ID,
        "manifest": {
            "filename": Path(MANIFEST_PATH).name,
            "bytes": len(manifest_raw),
            "sha256": sha256(manifest_raw),
        },
        "bounded_qualification": qualification,
        "private_tree_pre_values_phase_a_values_or_assignment_embedded": False,
        "portable_evidence_contains_absolute_paths": False,
        "other_tree_observed_stream_bytes_used": False,
        "verified_receipt_prefix_ordinals": [0, 1, 2],
        "all_declared_receipt_snapshots_raw_validated": True,
        "scheduler_receipt_suffix_overlap_ordinal": 2,
        "full_execution_receipt_chain_verified": False,
        "global_b_same_invocation_candidate_set_implemented": False,
        "large_replay_started": False,
        "large_proving_started": False,
        "formal_pi_issue_generated": False,
        "Proof-closed": False,
        "Production-closed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-check", action="store_true")
    arguments = parser.parse_args()
    report = bounded_self_check() if arguments.self_check else preflight()
    print(canonical_json(report).decode("ascii"), end="")


if __name__ == "__main__":
    main()
