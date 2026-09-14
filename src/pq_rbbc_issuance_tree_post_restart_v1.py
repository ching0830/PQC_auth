#!/usr/bin/env python3
"""Bounded private tree-post publication and restart checkpoint.

Only the two-tree/four-leaf INSECURE-TEST-ONLY relation is executable.  The
publisher uses exclusive, append-only files below a caller-provisioned private
artifact root.  A restart consumes the exact published snapshots and an
externally supplied checkpoint SHA-256; it does not retain or reconstruct the
producer's Python generator frame.

The qualified restart boundary begins only after the inputs-committed journal
entry exists.  A death while the private input set is incomplete fails closed
and requires a new trusted publication root.  This module does not claim that
flock, stat metadata, fsync, or ordinary filesystem permissions exclude a
malicious writer with equivalent authority.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Mapping, Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_cap_tree_producer as tree
import pq_rbbc_issuance_bounded_multitree_adapter_v1 as base
import pq_rbbc_issuance_private_spool_codec_v1 as codec
import pq_rbbc_issuance_private_spool_handoff_v1 as handoff
import pq_rbbc_issuance_tree_post_continuation_v1 as continuation
import pq_rbbc_launch_io_v2_41 as io
import pq_rbbc_recovery_io_v2_42 as disk


ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION_VERSION = "1.0"
FORMAT = "PQRBBC-ISSUANCE-TREE-POST-RESTART-1"
RELATION_ID = (
    "pq-rbbc/issuance/tree-post-restart/"
    "one-tree-4leaf-insecure-test-only/v1"
)
MODE = "INSECURE-TEST-ONLY"
INPUT_DIRECTORY = "inputs"
RESULT_DIRECTORY = "results"
JOURNAL_DIRECTORY = "journal"
PLAN_NAME = "0000-publication-plan.private.json"
INPUTS_COMMITTED_NAME = "0001-inputs-committed.private.json"
RESULT_COMMITTED_NAME = "0002-result-committed.private.json"
COMPLETE_NAME = "complete.private.json"
RESULT_NAMES = (
    "tree-0.post-result.private.json",
    "tree-1.post-result.private.json",
)
RECEIPT_NAMES = (
    "tree-0.post-receipt.private.json",
    "tree-1.post-receipt.private.json",
)
RESULT_FORMAT = "PQRBBC-ISSUANCE-TREE-POST-PRIVATE-RESULT-1"
RESULT_LIMIT = 256 * 1024
CHECKPOINT_LIMIT = 32 * 1024
RESULT_VALUE_ENCODING = "2412xf193-little-endian-hex"
JOURNAL_NAMES = (
    PLAN_NAME,
    INPUTS_COMMITTED_NAME,
    RESULT_COMMITTED_NAME,
    COMPLETE_NAME,
)
STOP_BOUNDARIES = frozenset(
    {"inputs", "result-payload", "result-receipt", "result-checkpoint", "complete"}
)
MANIFEST_PATH = "manifests/pq_rbbc_issuance_tree_post_restart_manifest_v1.json"
EVIDENCE_PATH = (
    "artifacts/metadata/issuance_tree_post_restart_v1/"
    "pq_rbbc_issuance_tree_post_restart_portable_evidence_v1.json"
)
PREDECESSOR_PINS = {
    "src/pq_rbbc_issuance_tree_post_continuation_v1.py": (
        59_398,
        "c604f3c9c0019b6f95ac7faa6c6c21d73cace894602797e1ab08b29cf452f8b0",
    ),
    "tests/test_pq_rbbc_issuance_tree_post_continuation_v1.py": (
        19_627,
        "1ffc076f4d82b0a2126d3d6dd9a6752fdb5aa4eaf297d092f0ce049b1246d473",
    ),
    continuation.MANIFEST_PATH: (
        8_733,
        "be861dedf84074d31cfeda3e48ffbab80a270f685c4b3076cbc81ef0cd028a75",
    ),
    continuation.EVIDENCE_PATH: (
        3_249,
        "fd2b14ff298d7643d3f7f4c5f90aa6c851decca2f37034cb8baeae6944292541",
    ),
    "src/pq_rbbc_recovery_io_v2_42.py": (
        3_839,
        "4213d7228f757a29a77243826b4a09d4506e48399c638338d59649b81f611e3d",
    ),
}


class RestartError(ValueError):
    """A private publication, checkpoint, or restart was rejected."""


class ProductionUnavailable(RuntimeError):
    """This bounded checkpoint intentionally has no production API."""


@dataclass(frozen=True)
class PublishedTreePostResultInsecureTestOnly:
    tree_index: int
    owned_values: tuple[int, ...]
    output_port: tree.ProducerPort
    result: io.Snapshot
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
        raise RestartError(label + " must be a lowercase SHA-256")
    return value


def _exact(value: object, fields: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise RestartError(label + " closed schema mismatch")
    return value


def _snapshot(name: str, raw: bytes) -> io.Snapshot:
    return io.Snapshot(Path("/in-memory-insecure-test-only") / name, raw)


def _identity(snapshot: io.Snapshot, name: str, limit: int) -> dict[str, object]:
    if (
        type(snapshot) is not io.Snapshot
        or snapshot.location.name != name
        or not 0 < len(snapshot.raw) <= limit
    ):
        raise RestartError("snapshot name/type/size mismatch: " + name)
    return snapshot.identity


def _identity_document(
    value: object, *, name: str, limit: int, exact_bytes: int | None = None
) -> dict[str, object]:
    current = _exact(value, {"filename", "bytes", "sha256"}, "artifact identity")
    if (
        current["filename"] != name
        or not _is_int(current["bytes"])
        or not 0 < int(current["bytes"]) <= limit
        or exact_bytes is not None
        and current["bytes"] != exact_bytes
    ):
        raise RestartError("artifact identity name or size mismatch: " + name)
    _digest(current["sha256"], "artifact identity")
    return current


def _input_names(tree_index: int) -> tuple[str, ...]:
    if not _is_int(tree_index) or tree_index not in (0, 1):
        raise RestartError("bounded tree index must be 0 or 1")
    return (
        handoff.HANDOFF_NAME,
        *handoff.SPOOL_NAMES,
        handoff.POINT_NAME,
        handoff.RECEIPT_NAME,
        continuation.CONTINUATION_NAMES[tree_index],
    )


def _input_limits(tree_index: int) -> tuple[int, ...]:
    _input_names(tree_index)
    return (
        handoff.HANDOFF_LIMIT,
        codec.SPOOL_BYTES,
        codec.SPOOL_BYTES,
        handoff.POINT_LIMIT,
        handoff.RECEIPT_LIMIT,
        continuation.CONTINUATION_LIMIT,
    )


def _input_snapshots(
    invocation: continuation.TreePostInvocationInsecureTestOnly,
) -> tuple[io.Snapshot, ...]:
    index = invocation.continuation.document().get("tree_index")
    if not _is_int(index) or index not in (0, 1):
        raise RestartError("continuation does not select a bounded tree")
    snapshots = (
        invocation.candidates.handoff,
        *invocation.candidates.spools,
        invocation.candidates.points,
        invocation.candidates.receipt,
        invocation.continuation,
    )
    for snapshot, name, limit in zip(snapshots, _input_names(index), _input_limits(index)):
        _identity(snapshot, name, limit)
    return snapshots


def validate_prerequisites() -> None:
    continuation.validate_prerequisites()
    for path, (size, digest) in PREDECESSOR_PINS.items():
        captured = io.read_snapshot(ROOT / path)
        if captured.identity["bytes"] != size:
            raise RestartError("tracked predecessor size drift: " + path)
        if digest and captured.identity["sha256"] != digest:
            raise RestartError("tracked predecessor digest drift: " + path)


def _plan_document(
    invocation: continuation.TreePostInvocationInsecureTestOnly,
    *,
    expected_handoff_sha256: str,
    expected_continuation_sha256: str,
) -> dict[str, object]:
    _digest(expected_handoff_sha256, "handoff digest")
    _digest(expected_continuation_sha256, "continuation digest")
    decoded = continuation._continuation_document(
        invocation,
        expected_handoff_sha256=expected_handoff_sha256,
        expected_continuation_sha256=expected_continuation_sha256,
    )
    index = int(decoded.document["tree_index"])
    inputs = _input_snapshots(invocation)
    return {
        "format": FORMAT + "-PUBLICATION-PLAN",
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "source_relation_id": continuation.RELATION_ID,
        "profile_fingerprint": continuation.PROFILE_FINGERPRINT,
        "tree_index": index,
        "stage": "publication-plan",
        "ordinal": 0,
        "previous_checkpoint_sha256": None,
        "input_identities": [snapshot.identity for snapshot in inputs],
        "handoff_sha256": expected_handoff_sha256,
        "continuation_sha256": expected_continuation_sha256,
        "post_interval": list(continuation.TREE_CONTRACTS[index]["post"]),
        "restartable_boundary_reached": False,
        "complete": False,
        "production": False,
    }


def _validate_plan(snapshot: io.Snapshot) -> dict[str, object]:
    _identity(snapshot, PLAN_NAME, CHECKPOINT_LIMIT)
    try:
        document = snapshot.document()
    except io.ValidationError as error:
        raise RestartError("publication plan is not strict canonical JSON") from error
    current = _exact(
        document,
        {
            "format",
            "implementation_version",
            "mode",
            "relation_id",
            "source_relation_id",
            "profile_fingerprint",
            "tree_index",
            "stage",
            "ordinal",
            "previous_checkpoint_sha256",
            "input_identities",
            "handoff_sha256",
            "continuation_sha256",
            "post_interval",
            "restartable_boundary_reached",
            "complete",
            "production",
        },
        "publication plan",
    )
    index = current["tree_index"]
    if not _is_int(index) or index not in (0, 1):
        raise RestartError("publication plan tree index")
    names = _input_names(index)
    limits = _input_limits(index)
    identities = current["input_identities"]
    if type(identities) is not list or len(identities) != len(names):
        raise RestartError("publication plan input inventory")
    parsed = []
    for identity, name, limit in zip(identities, names, limits):
        exact_bytes = codec.SPOOL_BYTES if name in handoff.SPOOL_NAMES else None
        parsed.append(
            _identity_document(identity, name=name, limit=limit, exact_bytes=exact_bytes)
        )
    _digest(current["handoff_sha256"], "publication plan handoff digest")
    _digest(current["continuation_sha256"], "publication plan continuation digest")
    if (
        current["format"] != FORMAT + "-PUBLICATION-PLAN"
        or current["implementation_version"] != IMPLEMENTATION_VERSION
        or current["mode"] != MODE
        or current["relation_id"] != RELATION_ID
        or current["source_relation_id"] != continuation.RELATION_ID
        or current["profile_fingerprint"] != continuation.PROFILE_FINGERPRINT
        or current["stage"] != "publication-plan"
        or current["ordinal"] != 0
        or current["previous_checkpoint_sha256"] is not None
        or current["post_interval"]
        != list(continuation.TREE_CONTRACTS[index]["post"])
        or current["handoff_sha256"] != parsed[0]["sha256"]
        or current["continuation_sha256"] != parsed[-1]["sha256"]
        or current["restartable_boundary_reached"] is not False
        or current["complete"] is not False
        or current["production"] is not False
        or canonical_json(current) != snapshot.raw
    ):
        raise RestartError("publication plan domain, chain, or claim mismatch")
    return current


def _inputs_checkpoint_document(
    plan: io.Snapshot, plan_document: Mapping[str, object]
) -> dict[str, object]:
    return {
        "format": FORMAT + "-INPUTS-COMMITTED",
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "tree_index": plan_document["tree_index"],
        "stage": "inputs-committed",
        "ordinal": 1,
        "previous_checkpoint_sha256": plan.identity["sha256"],
        "publication_plan": plan.identity,
        "input_identities": plan_document["input_identities"],
        "restartable_boundary_reached": True,
        "complete": False,
        "production": False,
    }


def _result_checkpoint_document(
    plan: io.Snapshot,
    inputs_checkpoint: io.Snapshot,
    result: io.Snapshot,
    receipt: io.Snapshot,
    tree_index: int,
) -> dict[str, object]:
    return {
        "format": FORMAT + "-RESULT-COMMITTED",
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "tree_index": tree_index,
        "stage": "result-committed",
        "ordinal": 2,
        "previous_checkpoint_sha256": inputs_checkpoint.identity["sha256"],
        "publication_plan": plan.identity,
        "inputs_checkpoint": inputs_checkpoint.identity,
        "result_identities": {"private_result": result.identity, "receipt": receipt.identity},
        "restartable_boundary_reached": True,
        "complete": False,
        "production": False,
    }


def _complete_document(
    plan: io.Snapshot,
    inputs_checkpoint: io.Snapshot,
    result_checkpoint: io.Snapshot,
    result: io.Snapshot,
    receipt: io.Snapshot,
    tree_index: int,
) -> dict[str, object]:
    return {
        "format": FORMAT + "-COMPLETE",
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "tree_index": tree_index,
        "stage": "complete",
        "ordinal": 3,
        "previous_checkpoint_sha256": result_checkpoint.identity["sha256"],
        "publication_plan": plan.identity,
        "inputs_checkpoint": inputs_checkpoint.identity,
        "result_checkpoint": result_checkpoint.identity,
        "result_identities": {"private_result": result.identity, "receipt": receipt.identity},
        "restartable_boundary_reached": True,
        "complete": True,
        "production": False,
    }


def _require_exact_document(
    snapshot: io.Snapshot, expected: Mapping[str, object], name: str
) -> io.Snapshot:
    _identity(snapshot, name, CHECKPOINT_LIMIT)
    try:
        snapshot.document()
    except io.ValidationError as error:
        raise RestartError("checkpoint is not strict canonical JSON: " + name) from error
    if snapshot.raw != canonical_json(expected):
        raise RestartError("checkpoint chain or exact bytes mismatch: " + name)
    return snapshot


def _encode_values(values: Sequence[int]) -> str:
    if (
        type(values) not in (tuple, list)
        or len(values) != 2_412
        or any(not _is_int(value) or not 0 <= value < field.FIELD_ORDER for value in values)
    ):
        raise RestartError("private result requires 2,412 canonical F193 values")
    return b"".join(
        int(value).to_bytes(field.FIELD_ELEMENT_BYTES, "little") for value in values
    ).hex()


def _decode_values(value: object) -> tuple[int, ...]:
    expected_hex = 2_412 * field.FIELD_ELEMENT_BYTES * 2
    if (
        type(value) is not str
        or len(value) != expected_hex
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RestartError("private result value encoding")
    raw = bytes.fromhex(value)
    values = tuple(
        int.from_bytes(raw[offset : offset + field.FIELD_ELEMENT_BYTES], "little")
        for offset in range(0, len(raw), field.FIELD_ELEMENT_BYTES)
    )
    if any(item >= field.FIELD_ORDER for item in values):
        raise RestartError("noncanonical F193 value in private result")
    return values


def _private_result_document(
    result: continuation.TreePostResultInsecureTestOnly,
    continuation_document: Mapping[str, object],
) -> dict[str, object]:
    index = result.tree_index
    contract = continuation.TREE_CONTRACTS[index]
    return {
        "format": RESULT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "source_relation_id": continuation.RELATION_ID,
        "profile_fingerprint": continuation.PROFILE_FINGERPRINT,
        "tree_index": index,
        "stage": f"tree-post[{index}]",
        "continuation_sha256": sha256(canonical_json(continuation_document)),
        "handoff_sha256": continuation_document["dependencies"]["handoff"]["sha256"],
        "post_interval": list(contract["post"]),
        "value_encoding": RESULT_VALUE_ENCODING,
        "value_count": len(result.owned_values),
        "owned_values_hex": _encode_values(result.owned_values),
        "private_owned_assignment_sha256": result.summary[
            "private_owned_assignment_sha256"
        ],
        "output_port": dict(result.summary["output_port"]),
        "source_receipt_sha256": sha256(result.receipt.raw),
        "private_payload": True,
        "production": False,
    }


def _validate_private_result(
    snapshot: io.Snapshot,
    *,
    expected_identity: Mapping[str, object],
    receipt_document: Mapping[str, object],
    continuation_document: Mapping[str, object],
) -> tuple[tuple[int, ...], tree.ProducerPort]:
    index = continuation_document["tree_index"]
    if not _is_int(index) or index not in (0, 1):
        raise RestartError("private result continuation tree index")
    _identity(snapshot, RESULT_NAMES[index], RESULT_LIMIT)
    if snapshot.identity != expected_identity:
        raise RestartError("private result external identity mismatch")
    try:
        document = snapshot.document()
    except io.ValidationError as error:
        raise RestartError("private result is not strict canonical JSON") from error
    current = _exact(
        document,
        {
            "format",
            "implementation_version",
            "mode",
            "relation_id",
            "source_relation_id",
            "profile_fingerprint",
            "tree_index",
            "stage",
            "continuation_sha256",
            "handoff_sha256",
            "post_interval",
            "value_encoding",
            "value_count",
            "owned_values_hex",
            "private_owned_assignment_sha256",
            "output_port",
            "source_receipt_sha256",
            "private_payload",
            "production",
        },
        "private tree-post result",
    )
    output = _exact(
        current["output_port"],
        {"port_id", "wire_start", "bit_length", "value_sha256"},
        "private result output port",
    )
    for digest in (
        current["continuation_sha256"],
        current["handoff_sha256"],
        current["private_owned_assignment_sha256"],
        current["source_receipt_sha256"],
        output["value_sha256"],
    ):
        _digest(digest, "private result digest")
    values = _decode_values(current["owned_values_hex"])
    contract = continuation.TREE_CONTRACTS[index]
    summary = receipt_document["summary"]
    expected_output = summary["output_port"]
    output_start, output_width = contract["output"]
    post_start = contract["post"][0]
    offset = output_start - post_start
    output_values = values[offset : offset + output_width]
    if len(output_values) != output_width or any(value not in (0, 1) for value in output_values):
        raise RestartError("private result output slice is not canonical bits")
    output_integer = sum(value << bit for bit, value in enumerate(output_values))
    if (
        current["format"] != RESULT_FORMAT
        or current["implementation_version"] != IMPLEMENTATION_VERSION
        or current["mode"] != MODE
        or current["relation_id"] != RELATION_ID
        or current["source_relation_id"] != continuation.RELATION_ID
        or current["profile_fingerprint"] != continuation.PROFILE_FINGERPRINT
        or current["tree_index"] != index
        or current["stage"] != f"tree-post[{index}]"
        or current["continuation_sha256"]
        != sha256(canonical_json(continuation_document))
        or current["handoff_sha256"]
        != continuation_document["dependencies"]["handoff"]["sha256"]
        or current["post_interval"] != list(contract["post"])
        or current["value_encoding"] != RESULT_VALUE_ENCODING
        or current["value_count"] != 2_412
        or continuation._private_assignment_digest(values)
        != current["private_owned_assignment_sha256"]
        or current["private_owned_assignment_sha256"]
        != summary["private_owned_assignment_sha256"]
        or output != expected_output
        or tree._bits_digest(output_integer, output_width) != output["value_sha256"]
        or current["source_receipt_sha256"]
        != sha256(canonical_json(receipt_document))
        or current["private_payload"] is not True
        or current["production"] is not False
        or canonical_json(current) != snapshot.raw
    ):
        raise RestartError("private result binding, assignment, output, or claim mismatch")
    port = tree.ProducerPort(
        str(output["port_id"]),
        "output",
        "tree-post",
        int(output["wire_start"]),
        int(output["bit_length"]),
        str(output["value_sha256"]),
    )
    return values, port


def _names(path: Path) -> set[str]:
    with io.directory_fd(path, external=True) as descriptor:
        names = set(os.listdir(descriptor))
        io._same_directory(path, descriptor, external=True)
        return names


def _journal_shape(names: set[str]) -> tuple[str, ...]:
    if not names or names - set(JOURNAL_NAMES):
        raise RestartError("unknown or empty private publication journal")
    ordered = tuple(name for name in JOURNAL_NAMES if name in names)
    if ordered != JOURNAL_NAMES[: len(ordered)]:
        raise RestartError("private publication journal is not a contiguous prefix")
    return ordered


def latest_checkpoint(output: Path, *, artifact_root: Path) -> io.Snapshot:
    root = io.ArtifactRoot(artifact_root)
    root.require_location(output / JOURNAL_DIRECTORY / COMPLETE_NAME)
    ordered = _journal_shape(_names(output / JOURNAL_DIRECTORY))
    return disk.read(output / JOURNAL_DIRECTORY / ordered[-1])


def _capture_journal(
    output: Path, latest: io.Snapshot | None = None
) -> dict[str, io.Snapshot]:
    ordered = _journal_shape(_names(output / JOURNAL_DIRECTORY))
    captured: dict[str, io.Snapshot] = {}
    for name in ordered:
        path = output / JOURNAL_DIRECTORY / name
        if latest is not None and latest.location == path:
            captured[name] = latest
        else:
            captured[name] = disk.read(path)
    return captured


def _load_inputs(
    output: Path, plan_document: Mapping[str, object]
) -> continuation.TreePostInvocationInsecureTestOnly:
    index = int(plan_document["tree_index"])
    names = _input_names(index)
    present = _names(output / INPUT_DIRECTORY)
    if present - set(names):
        raise RestartError("unknown private input artifact")
    if present != set(names):
        raise RestartError(
            "private input publication is incomplete; use a new trusted publication root"
        )
    snapshots = []
    for name, expected, limit in zip(
        names, plan_document["input_identities"], _input_limits(index)
    ):
        captured = disk.read(output / INPUT_DIRECTORY / name)
        if _identity(captured, name, limit) != expected:
            raise RestartError("published private input identity mismatch: " + name)
        snapshots.append(captured)
    candidates = handoff.CandidateSet(
        snapshots[0], tuple(snapshots[1:3]), snapshots[3], snapshots[4]
    )
    invocation = continuation.TreePostInvocationInsecureTestOnly(candidates, snapshots[5])
    continuation._continuation_document(
        invocation,
        expected_handoff_sha256=str(plan_document["handoff_sha256"]),
        expected_continuation_sha256=str(plan_document["continuation_sha256"]),
    )
    return invocation


def _compute_result(
    invocation: continuation.TreePostInvocationInsecureTestOnly,
    plan_document: Mapping[str, object],
) -> continuation.TreePostResultInsecureTestOnly:
    return continuation.execute_tree_post_insecure_test_only(
        invocation,
        expected_handoff_sha256=str(plan_document["handoff_sha256"]),
        expected_continuation_sha256=str(plan_document["continuation_sha256"]),
    )


def _expected_result_snapshots(
    result: continuation.TreePostResultInsecureTestOnly,
    invocation: continuation.TreePostInvocationInsecureTestOnly,
) -> tuple[io.Snapshot, io.Snapshot, Mapping[str, object]]:
    continuation_document = invocation.continuation.document()
    result_raw = canonical_json(_private_result_document(result, continuation_document))
    if len(result_raw) > RESULT_LIMIT:
        raise RestartError("private tree-post result exceeds byte bound")
    result_snapshot = _snapshot(RESULT_NAMES[result.tree_index], result_raw)
    receipt_snapshot = _snapshot(RECEIPT_NAMES[result.tree_index], result.receipt.raw)
    receipt_document = continuation.validate_tree_post_receipt(
        receipt_snapshot,
        expected_sha256=sha256(receipt_snapshot.raw),
        continuation=continuation_document,
    )
    _validate_private_result(
        result_snapshot,
        expected_identity=result_snapshot.identity,
        receipt_document=receipt_document,
        continuation_document=continuation_document,
    )
    return result_snapshot, receipt_snapshot, receipt_document


def _validate_result_pair(
    output: Path,
    expected_result: io.Snapshot,
    expected_receipt: io.Snapshot,
    continuation_document: Mapping[str, object],
    *,
    captured_result: io.Snapshot | None = None,
    captured_receipt: io.Snapshot | None = None,
) -> tuple[io.Snapshot, io.Snapshot, tuple[int, ...], tree.ProducerPort]:
    index = int(continuation_document["tree_index"])
    result_path = output / RESULT_DIRECTORY / RESULT_NAMES[index]
    receipt_path = output / RESULT_DIRECTORY / RECEIPT_NAMES[index]
    result_snapshot = captured_result or disk.read(result_path)
    receipt_snapshot = captured_receipt or disk.read(receipt_path)
    if result_snapshot.location != result_path or receipt_snapshot.location != receipt_path:
        raise RestartError("captured result pathname mismatch")
    if result_snapshot.raw != expected_result.raw or receipt_snapshot.raw != expected_receipt.raw:
        raise RestartError("published result or receipt differs from recomputed bytes")
    receipt_document = continuation.validate_tree_post_receipt(
        receipt_snapshot,
        expected_sha256=expected_receipt.identity["sha256"],
        continuation=continuation_document,
    )
    values, output_port = _validate_private_result(
        result_snapshot,
        expected_identity=expected_result.identity,
        receipt_document=receipt_document,
        continuation_document=continuation_document,
    )
    return result_snapshot, receipt_snapshot, values, output_port


def _stop(stop_after: str | None, boundary: str) -> bool:
    return stop_after == boundary


def run_bounded_tree_post(
    output: Path,
    *,
    artifact_root: Path,
    fresh_invocation: continuation.TreePostInvocationInsecureTestOnly | None = None,
    expected_handoff_sha256: str | None = None,
    expected_continuation_sha256: str | None = None,
    fresh_output: bool = False,
    resume: bool = False,
    expected_checkpoint_sha256: str | None = None,
    stop_after: str | None = None,
) -> PublishedTreePostResultInsecureTestOnly | None:
    """Publish or resume one bounded private tree-post workflow.

    Resume authenticates the latest journal snapshot with the caller-provided
    digest before reading any private input or starting relation computation.
    """
    validate_prerequisites()
    if type(fresh_output) is not bool or type(resume) is not bool or fresh_output == resume:
        raise RestartError("select exactly one of fresh_output or resume")
    if stop_after is not None and stop_after not in STOP_BOUNDARIES:
        raise RestartError("unknown bounded stop boundary")
    expected_plan_raw = None
    source_snapshots: tuple[io.Snapshot, ...] | None = None
    if fresh_output:
        if (
            type(fresh_invocation) is not continuation.TreePostInvocationInsecureTestOnly
            or expected_handoff_sha256 is None
            or expected_continuation_sha256 is None
            or expected_checkpoint_sha256 is not None
        ):
            raise RestartError("fresh publication requires invocation and exact source digests")
        plan_document = _plan_document(
            fresh_invocation,
            expected_handoff_sha256=expected_handoff_sha256,
            expected_continuation_sha256=expected_continuation_sha256,
        )
        expected_plan_raw = canonical_json(plan_document)
        source_snapshots = _input_snapshots(fresh_invocation)
    else:
        if (
            fresh_invocation is not None
            or expected_handoff_sha256 is not None
            or expected_continuation_sha256 is not None
        ):
            raise RestartError("resume accepts no live invocation or source digest override")
        _digest(expected_checkpoint_sha256, "external restart checkpoint digest")

    with disk.locked_output(output, artifact_root, fresh=fresh_output) as output_fd:
        if fresh_output:
            for name in (INPUT_DIRECTORY, RESULT_DIRECTORY, JOURNAL_DIRECTORY):
                os.mkdir(name, mode=0o700, dir_fd=output_fd)
            os.fsync(output_fd)
            disk.publish(
                output / JOURNAL_DIRECTORY / PLAN_NAME,
                expected_plan_raw,
            )
            for snapshot in source_snapshots:
                disk.publish(output / INPUT_DIRECTORY / snapshot.location.name, snapshot.raw)
        with io.directory_fd(output / INPUT_DIRECTORY, external=True) as input_fd, \
                io.directory_fd(output / RESULT_DIRECTORY, external=True) as result_fd, \
                io.directory_fd(output / JOURNAL_DIRECTORY, external=True) as journal_fd:
            latest = None
            if resume:
                latest = latest_checkpoint(output, artifact_root=artifact_root)
                if latest.identity["sha256"] != expected_checkpoint_sha256:
                    raise RestartError(
                        "restart checkpoint identity mismatch (including stale digest)"
                    )
            journal = _capture_journal(output, latest)
            plan = journal[PLAN_NAME]
            plan_document = _validate_plan(plan)
            if expected_plan_raw is not None and plan.raw != expected_plan_raw:
                raise RestartError("fresh publication plan differs from validated source")
            invocation = _load_inputs(output, plan_document)
            inputs_document = _inputs_checkpoint_document(plan, plan_document)
            inputs_raw = canonical_json(inputs_document)
            inputs_expected = _snapshot(INPUTS_COMMITTED_NAME, inputs_raw)
            if INPUTS_COMMITTED_NAME in journal:
                _require_exact_document(
                    journal[INPUTS_COMMITTED_NAME], inputs_document, INPUTS_COMMITTED_NAME
                )
            elif len(journal) != 1:
                raise RestartError("journal gap before inputs-committed")
            result_names = _names(output / RESULT_DIRECTORY)
            allowed_result_names = {
                RESULT_NAMES[int(plan_document["tree_index"])],
                RECEIPT_NAMES[int(plan_document["tree_index"])],
            }
            if result_names - allowed_result_names:
                raise RestartError("unknown private result artifact")
            if INPUTS_COMMITTED_NAME not in journal and result_names:
                raise RestartError("result exists before restartable input boundary")
            if (
                RESULT_COMMITTED_NAME in journal
                and result_names != allowed_result_names
            ):
                raise RestartError("committed result artifact is missing")
            # Validate every existing durable object before any new publication.
            disk.sync_directory(output / INPUT_DIRECTORY, input_fd)
            disk.sync_directory(output / RESULT_DIRECTORY, result_fd)
            disk.sync_directory(output / JOURNAL_DIRECTORY, journal_fd)
            disk.sync_directory(output, output_fd)
            if INPUTS_COMMITTED_NAME not in journal:
                disk.publish(
                    output / JOURNAL_DIRECTORY / INPUTS_COMMITTED_NAME, inputs_raw
                )
                journal[INPUTS_COMMITTED_NAME] = inputs_expected
            inputs_checkpoint = journal[INPUTS_COMMITTED_NAME]
            if _stop(stop_after, "inputs"):
                return None

            result = _compute_result(invocation, plan_document)
            expected_result, expected_receipt, _ = _expected_result_snapshots(
                result, invocation
            )
            result_name = expected_result.location.name
            receipt_name = expected_receipt.location.name
            if receipt_name in result_names and result_name not in result_names:
                raise RestartError("receipt exists without private result")
            if result_name in result_names:
                captured_result = disk.read(output / RESULT_DIRECTORY / result_name)
                if captured_result.raw != expected_result.raw:
                    raise RestartError("existing private result orphan differs")
                disk.sync_directory(output / RESULT_DIRECTORY, result_fd)
            else:
                disk.publish(output / RESULT_DIRECTORY / result_name, expected_result.raw)
                result_names.add(result_name)
                captured_result = io.Snapshot(
                    output / RESULT_DIRECTORY / result_name, expected_result.raw
                )
            if _stop(stop_after, "result-payload"):
                return None
            if receipt_name in result_names:
                captured_receipt = disk.read(output / RESULT_DIRECTORY / receipt_name)
                if captured_receipt.raw != expected_receipt.raw:
                    raise RestartError("existing receipt orphan differs")
                disk.sync_directory(output / RESULT_DIRECTORY, result_fd)
            else:
                disk.publish(output / RESULT_DIRECTORY / receipt_name, expected_receipt.raw)
                result_names.add(receipt_name)
                captured_receipt = io.Snapshot(
                    output / RESULT_DIRECTORY / receipt_name, expected_receipt.raw
                )
            if _stop(stop_after, "result-receipt"):
                return None
            result_document = _result_checkpoint_document(
                plan,
                inputs_checkpoint,
                expected_result,
                expected_receipt,
                int(plan_document["tree_index"]),
            )
            result_raw = canonical_json(result_document)
            result_checkpoint_expected = _snapshot(RESULT_COMMITTED_NAME, result_raw)
            if RESULT_COMMITTED_NAME in journal:
                _require_exact_document(
                    journal[RESULT_COMMITTED_NAME], result_document, RESULT_COMMITTED_NAME
                )
            else:
                if COMPLETE_NAME in journal:
                    raise RestartError("complete checkpoint precedes result checkpoint")
                disk.publish(
                    output / JOURNAL_DIRECTORY / RESULT_COMMITTED_NAME, result_raw
                )
                journal[RESULT_COMMITTED_NAME] = result_checkpoint_expected
            result_checkpoint = journal[RESULT_COMMITTED_NAME]
            if _stop(stop_after, "result-checkpoint"):
                return None
            complete_document = _complete_document(
                plan,
                inputs_checkpoint,
                result_checkpoint,
                expected_result,
                expected_receipt,
                int(plan_document["tree_index"]),
            )
            complete_raw = canonical_json(complete_document)
            complete_expected = _snapshot(COMPLETE_NAME, complete_raw)
            if COMPLETE_NAME in journal:
                _require_exact_document(journal[COMPLETE_NAME], complete_document, COMPLETE_NAME)
            else:
                disk.publish(output / JOURNAL_DIRECTORY / COMPLETE_NAME, complete_raw)
                journal[COMPLETE_NAME] = complete_expected
            if _stop(stop_after, "complete") or stop_after is None:
                result_snapshot, receipt_snapshot, values, output_port = _validate_result_pair(
                    output,
                    expected_result,
                    expected_receipt,
                    invocation.continuation.document(),
                    captured_result=captured_result,
                    captured_receipt=captured_receipt,
                )
                return PublishedTreePostResultInsecureTestOnly(
                    int(plan_document["tree_index"]),
                    values,
                    output_port,
                    result_snapshot,
                    receipt_snapshot,
                    journal[COMPLETE_NAME],
                )
    raise RestartError("unreachable bounded restart state")


def capture_completed_result(
    output: Path,
    *,
    artifact_root: Path,
    expected_complete_sha256: str,
) -> PublishedTreePostResultInsecureTestOnly:
    """Read a completed result without replaying tree-post or reopening a snapshot."""
    _digest(expected_complete_sha256, "external complete checkpoint digest")
    latest = latest_checkpoint(output, artifact_root=artifact_root)
    if latest.location.name != COMPLETE_NAME or latest.identity["sha256"] != expected_complete_sha256:
        raise RestartError("complete checkpoint identity mismatch")
    journal = _capture_journal(output, latest)
    if tuple(journal) != JOURNAL_NAMES:
        raise RestartError("completed journal is incomplete")
    plan = journal[PLAN_NAME]
    plan_document = _validate_plan(plan)
    invocation = _load_inputs(output, plan_document)
    inputs_document = _inputs_checkpoint_document(plan, plan_document)
    inputs_checkpoint = _require_exact_document(
        journal[INPUTS_COMMITTED_NAME], inputs_document, INPUTS_COMMITTED_NAME
    )
    index = int(plan_document["tree_index"])
    result_checkpoint = journal[RESULT_COMMITTED_NAME]
    # The externally pinned chain authenticates these identities before payload parsing.
    result_checkpoint_document = result_checkpoint.document()
    result_identities = _exact(
        result_checkpoint_document.get("result_identities"),
        {"private_result", "receipt"},
        "result identities",
    )
    private_identity = _identity_document(
        result_identities["private_result"], name=RESULT_NAMES[index], limit=RESULT_LIMIT
    )
    receipt_identity = _identity_document(
        result_identities["receipt"],
        name=RECEIPT_NAMES[index],
        limit=continuation.RECEIPT_LIMIT,
    )
    expected_result_document = _result_checkpoint_document(
        plan,
        inputs_checkpoint,
        _snapshot(RESULT_NAMES[index], b"x"),
        _snapshot(RECEIPT_NAMES[index], b"x"),
        index,
    )
    expected_result_document["result_identities"] = result_identities
    _require_exact_document(
        result_checkpoint, expected_result_document, RESULT_COMMITTED_NAME
    )
    complete_document = _complete_document(
        plan,
        inputs_checkpoint,
        result_checkpoint,
        _snapshot(RESULT_NAMES[index], b"x"),
        _snapshot(RECEIPT_NAMES[index], b"x"),
        index,
    )
    complete_document["result_identities"] = result_identities
    complete = _require_exact_document(latest, complete_document, COMPLETE_NAME)
    receipt_snapshot = disk.read(output / RESULT_DIRECTORY / RECEIPT_NAMES[index])
    if receipt_snapshot.identity != receipt_identity:
        raise RestartError("published receipt identity mismatch")
    continuation_document = invocation.continuation.document()
    receipt_document = continuation.validate_tree_post_receipt(
        receipt_snapshot,
        expected_sha256=str(receipt_identity["sha256"]),
        continuation=continuation_document,
    )
    result_snapshot = disk.read(output / RESULT_DIRECTORY / RESULT_NAMES[index])
    values, output_port = _validate_private_result(
        result_snapshot,
        expected_identity=private_identity,
        receipt_document=receipt_document,
        continuation_document=continuation_document,
    )
    return PublishedTreePostResultInsecureTestOnly(
        index, values, output_port, result_snapshot, receipt_snapshot, complete
    )


def _file_bytes(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


@lru_cache(maxsize=1)
def bounded_self_check() -> dict[str, object]:
    validate_prerequisites()
    session = handoff.HandoffSessionInsecureTestOnly()
    try:
        session.run_to("global-a")
        candidates = session.export_candidates()
        handoff_sha = sha256(candidates.handoff.raw)
        session.accept_handoff(candidates, expected_handoff_sha256=handoff_sha)
        selected = continuation.build_continuation_snapshots(session)[0]
        invocation = continuation.TreePostInvocationInsecureTestOnly(candidates, selected)
        continuation_sha = sha256(selected.raw)
        with TemporaryDirectory(prefix="pq-rbbc-tree-post-restart-") as temporary:
            artifact_root = Path(temporary)
            reference_root = artifact_root / "reference"
            restarted_root = artifact_root / "restarted"
            reference = run_bounded_tree_post(
                reference_root,
                artifact_root=artifact_root,
                fresh_invocation=invocation,
                expected_handoff_sha256=handoff_sha,
                expected_continuation_sha256=continuation_sha,
                fresh_output=True,
            )
            run_bounded_tree_post(
                restarted_root,
                artifact_root=artifact_root,
                fresh_invocation=invocation,
                expected_handoff_sha256=handoff_sha,
                expected_continuation_sha256=continuation_sha,
                fresh_output=True,
                stop_after="inputs",
            )
            checkpoint = latest_checkpoint(restarted_root, artifact_root=artifact_root)
            restarted = run_bounded_tree_post(
                restarted_root,
                artifact_root=artifact_root,
                resume=True,
                expected_checkpoint_sha256=checkpoint.identity["sha256"],
            )
            if reference is None or restarted is None:
                raise RestartError("bounded self-check did not complete")
            if _file_bytes(reference_root) != _file_bytes(restarted_root):
                raise RestartError("fresh and restarted private artifacts differ")
            captured = capture_completed_result(
                restarted_root,
                artifact_root=artifact_root,
                expected_complete_sha256=restarted.complete_checkpoint.identity["sha256"],
            )
            if (
                captured.owned_values != restarted.owned_values
                or captured.output_port != restarted.output_port
            ):
                raise RestartError("read-only completed-result capture differs")
            journal = _capture_journal(restarted_root)
            result = {
                "format": FORMAT,
                "relation_id": RELATION_ID,
                "mode": MODE,
                "tree_index": 0,
                "input_artifact_count": 6,
                "tree_post_rows": 3_576,
                "tree_post_allocated_wires": 2_412,
                "private_result_identity": restarted.result.identity,
                "receipt_identity": restarted.receipt.identity,
                "journal_identities": [journal[name].identity for name in JOURNAL_NAMES],
                "output_port": {
                    "port_id": restarted.output_port.port_id,
                    "wire_start": restarted.output_port.wire_start,
                    "bit_length": restarted.output_port.bit_length,
                    "value_sha256": restarted.output_port.value_sha256,
                },
                "fresh_and_restart_artifacts_identical": True,
                "completed_result_consumed_without_tree_post_replay": True,
                "restartable_boundary": "inputs-committed",
                "exclusive_append_only_publication": True,
                "controlled_process_death_boundaries_qualified_by_tests": [
                    "after-result-payload-publication",
                    "after-result-receipt-publication",
                    "after-result-checkpoint-publication",
                    "after-complete-checkpoint-publication",
                ],
                "incomplete_input_publication_recoverable": False,
                "full_session_restore_implemented": False,
                "global_tail_continuation_implemented": False,
                "production_durable_resume_implemented": False,
                "private_payload_embedded_in_portable_evidence": False,
                "other_tree_observed_stream_bytes_used": False,
                "production_rows_replayed": 0,
                "proofs_generated": 0,
                "Proof-closed": False,
                "Production-closed": False,
            }
            return result
    finally:
        session.close()


def execute_production(*_args: object, **_kwargs: object) -> None:
    raise ProductionUnavailable(
        "bounded private tree-post restart is test-only; production refused before I/O"
    )


def preflight() -> dict[str, object]:
    validate_prerequisites()
    return {
        "format": FORMAT,
        "relation_id": RELATION_ID,
        "read_only_preflight_passed": True,
        "safe_to_run_bounded_insecure_test_only": True,
        "private_append_only_publication_implemented": True,
        "bounded_process_restart_implemented": True,
        "bounded_controlled_crash_recovery_tested": True,
        "restartable_boundary": "inputs-committed",
        "incomplete_input_publication_recoverable": False,
        "full_session_restore_implemented": False,
        "global_tail_continuation_implemented": False,
        "production_durable_resume_implemented": False,
        "production_execution_command": None,
        "large_replay_command": None,
        "large_proving_command": None,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
        "production_rows_replayed": 0,
        "proofs_generated": 0,
        "Proof-closed": False,
        "Production-closed": False,
        "external_inventory_scope": "not provisioned",
        "missing_production_artifacts": list(base.prefreeze.inputs.REQUIRED_EXTERNAL_ARTIFACTS),
        "blockers": list(base.prefreeze.BLOCKERS),
    }


def build_manifest() -> dict[str, object]:
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "implementation_identities": {
            path: io.read_snapshot(ROOT / path).identity
            for path in (
                "src/pq_rbbc_issuance_tree_post_restart_v1.py",
                "tests/test_pq_rbbc_issuance_tree_post_restart_v1.py",
            )
        },
        "predecessor_identities": {
            path: {"bytes": size, "sha256": digest}
            for path, (size, digest) in PREDECESSOR_PINS.items()
        },
        "publication_contract": {
            "directories": [INPUT_DIRECTORY, RESULT_DIRECTORY, JOURNAL_DIRECTORY],
            "journal_names": list(JOURNAL_NAMES),
            "result_names": list(RESULT_NAMES),
            "receipt_names": list(RECEIPT_NAMES),
            "restartable_boundary": "inputs-committed",
            "exclusive_create_never_overwrite": True,
            "caller_supplies_exact_resume_checkpoint_sha256": True,
            "future_consumer_uses_captured_completed_snapshots": True,
            "pathname_reopen_after_capture_permitted": False,
            "incomplete_input_publication_recoverable": False,
        },
        "bounded_qualification": bounded_self_check(),
        "preflight": preflight(),
        "resource_budget": {
            "max_wires": base.MAX_WIRES,
            "max_rows": base.MAX_ROWS,
            "private_result_max_bytes": RESULT_LIMIT,
            "checkpoint_max_bytes": CHECKPOINT_LIMIT,
            "planned_memory_mib": 512,
            "planned_seconds": 240,
            "production_estimate": None,
        },
        "claim_status": {
            "Defined": True,
            "Instantiated": "one-tree-4leaf-insecure-test-only",
            "Implemented": "private-append-only-tree-post-restart",
            "Tested": "bounded-restart-and-controlled-process-death",
            "Evidence-sealed": "metadata-only",
            "Proof-closed": False,
            "Production-closed": False,
            "full_session_restore_implemented": False,
            "global_tail_continuation_implemented": False,
            "production_durable_resume_implemented": False,
            "production_legacy18_provider_implemented": False,
            "qualified_pq_se_backend_integrated": False,
            "formal_pi_issue_generated": False,
        },
        "exact_commands": {
            "read_only": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_tree_post_restart_v1.py",
            "bounded": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_tree_post_restart_v1.py --self-check",
            "targeted": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_tree_post_restart_v1 -v",
            "production": None,
            "large_replay": None,
            "large_proving": None,
        },
    }


def build_portable_evidence() -> dict[str, object]:
    manifest_raw = canonical_json(build_manifest())
    return {
        "format": FORMAT + "-PORTABLE-EVIDENCE",
        "bounded_qualification": bounded_self_check(),
        "manifest": {
            "filename": Path(MANIFEST_PATH).name,
            "bytes": len(manifest_raw),
            "sha256": sha256(manifest_raw),
        },
        "private_continuation_spool_result_assignment_or_receipt_embedded": False,
        "production_execution_started": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-check", action="store_true")
    arguments = parser.parse_args()
    report = bounded_self_check() if arguments.self_check else preflight()
    print(canonical_json(report).decode("ascii"), end="")


if __name__ == "__main__":
    main()
