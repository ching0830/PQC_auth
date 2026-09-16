#!/usr/bin/env python3
"""Independent bounded fragment producers for the issuance CAP relation.

This module is deliberately limited to the production-width, four-leaf,
insecure test-only profile frozen by ``pq_rbbc_issuance_split_lowerer_v1``.
Each producer consumes an explicit, identity-bound import state and starts at
the absolute next-wire value exported by its predecessor.  Runtime artifacts
contain private fixture state and therefore remain external.  No assignment,
BR1CS, row archive, proof, or production execution is produced here.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
from typing import Callable, Iterator, Mapping, Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_anemoi_sponge as sponge
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_shard_stream as shard
import pq_rbbc_issuance_split_lowerer_v1 as predecessor
import pq_rbbc_issuance_split_runner_v1 as split
import pq_rbbc_launch_io_v2_41 as launch_io
import pq_rbbc_recovery_io_v2_42 as recovery_io


IMPLEMENTATION_VERSION = "1.0"
FORMAT = "PQRBBC-ISSUANCE-FRAGMENT-PRODUCERS-CHECKPOINT-1"
STATE_FORMAT = "PQRBBC-ISSUANCE-FRAGMENT-PORT-STATE-1"
ARTIFACT_FORMAT = "PQRBBC-ISSUANCE-FRAGMENT-ARTIFACT-1"
RECEIPT_FORMAT = "PQRBBC-ISSUANCE-FRAGMENT-RECEIPT-1"
COMPLETE_FORMAT = "PQRBBC-ISSUANCE-FRAGMENT-COMPLETE-1"
EVIDENCE_FORMAT = "PQRBBC-ISSUANCE-FRAGMENT-PRODUCERS-PORTABLE-EVIDENCE-1"
BOUNDED_RELATION_ID = (
    "pq-rbbc/issuance/cap576-native/fragment-producers-4leaf-insecure-test-only/v1"
)
PRODUCTION_RELATION_ID = predecessor.PRODUCTION_RELATION_ID
ROOT = Path(__file__).resolve().parents[1]
PARAMETERS = predecessor.PARAMETERS
PROFILE_FINGERPRINT = predecessor.PROFILE_FINGERPRINT
FRAGMENT_ORDER = predecessor.FRAGMENT_ORDER
FRAGMENT_GROUPS = {
    "input-binding": ("inputs",),
    "tree-pre[0]": ("ggm-derive", "leaf-commit-and-tape"),
    "global-tail-phase-a": ("h1-and-points",),
    "tree-post[0]": ("leaf-horner-and-field-aggregation",),
    "global-tail-phase-b": ("h2-commitment-and-request-binding",),
}
FRAGMENT_CONSUMERS = {
    FRAGMENT_ORDER[index]: (
        FRAGMENT_ORDER[index + 1] if index + 1 < len(FRAGMENT_ORDER) else "complete"
    )
    for index in range(len(FRAGMENT_ORDER))
}
DOMAIN_PORT = b"PQ-RBBC/ISSUANCE/FRAGMENT-PRODUCER/PORT/V1"
DOMAIN_ARTIFACT = b"PQ-RBBC/ISSUANCE/FRAGMENT-PRODUCER/ARTIFACT/V1"
DOMAIN_RECEIPT = b"PQ-RBBC/ISSUANCE/FRAGMENT-PRODUCER/RECEIPT/V1"
GENESIS_FILENAME = "receipt-000.json"
COMPLETE_FILENAME = "complete.json"

FROZEN_BOUNDED = {
    **predecessor.FROZEN_BOUNDED,
    "fragment_order": list(FRAGMENT_ORDER),
}
FROZEN_NEXT_WIRE = (1_029, 33_141, 39_372, 41_020, 53_033)
FROZEN_PUBLICATION = {
    "export_port_identities": [
        "bb492cf59d12f418853b90618104a5a54aa46f948557a0dc1feeb0fd7169f0dd",
        "bebe08a5c019b6464f8f49a628e5da885c3ee25752ebbd25cb368ebe000f989a",
        "1c1a1aa47aaf430e3e79727d2c4988981d7b88ab047dfe36701e6731612465ce",
        "689745ec8cda0f478b9a781eded34ffa0120ff998fdb9d4807c03a6f6013acce",
        "deecf46b9a216ebd65b6425a0c03760a2cc337a485bd22aedd36cff9ae44fe7e",
    ],
    "fragment_artifact_sha256": [
        "cbaa51bc410f3ae224a337a7a56241537d96731e9fb1ce9f5252e459d197a5d1",
        "96684a6b8f1db1e4004daca7dd048f3a8bf1fe258b4511fce11ff72e19a30a6c",
        "dc4c5468b9535ac68f66af23d6b0e3c2278c513575f9fc60f270cf40d86e4c7a",
        "3f6fb72f3093108512f462c958e6ccb41b38836c9c3df51a385d6763774f94c4",
        "ad444861e8c782359a0f79c7fdb419a80c21282446111d262f3a11fd35fc728c",
    ],
    "fragment_artifact_bytes": [1_989, 62_256, 62_520, 62_625, 2_421],
    "final_receipt_sha256": "044e75a7c835a542ae9162947a1887dab2996a5baddb58efff3a243c81fdbead",
    "final_receipt_bytes": 1_009,
    "runtime_file_count": 12,
}

TRACKED_PREREQUISITES = {
    "split_lowerer_source": (
        "src/pq_rbbc_issuance_split_lowerer_v1.py",
        58_756,
        "3ea2787c24aabf66e1ec6b41f4831fba79aad615e35b235d0b1a73e39424051d",
    ),
    "split_lowerer_manifest": (
        "manifests/pq_rbbc_issuance_split_lowerer_manifest_v1.json",
        6_048,
        "ea0b9e889bc0c69643506363c4852518749578d05e60da481798c05676f3c084",
    ),
    "split_lowerer_evidence": (
        "artifacts/metadata/issuance_split_lowerer_v1/"
        "pq_rbbc_issuance_split_lowerer_portable_evidence_v1.json",
        2_502,
        "1ee9a00a96cd617c2540772e505b90f8d9873804084813ac6f31a694235bc7fc",
    ),
    "native_shard_source": predecessor.TRACKED_PREREQUISITES["native_shard_source"],
    "recovery_io_source": predecessor.TRACKED_PREREQUISITES["recovery_io_source"],
}


class FragmentProducerError(ValueError):
    """A fragment import, row emission, or receipt chain is invalid."""


class ProductionFragmentProducersUnavailable(RuntimeError):
    """Production fragment materialization is not implemented or authorized."""


class ControlledInterruption(RuntimeError):
    """Test-only interruption after an append-only artifact publication."""


def canonical_json(document: object) -> bytes:
    return launch_io.canonical_json(document)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _exact(document: object, fields: set[str], label: str) -> dict[str, object]:
    if type(document) is not dict or set(document) != fields:
        raise FragmentProducerError(f"{label} fields are not canonical")
    return document


def _strict_json(raw: bytes, label: str) -> dict[str, object]:
    try:
        return launch_io.strict_json(raw)
    except launch_io.ValidationError as error:
        raise FragmentProducerError(f"{label} is not strict canonical JSON") from error


def _raw_identity(filename: str, raw: bytes) -> dict[str, object]:
    return {"filename": filename, "bytes": len(raw), "sha256": _sha256(raw)}


def validate_tracked_prerequisites() -> tuple[str, ...]:
    failures = []
    for name, (relative, size, digest) in TRACKED_PREREQUISITES.items():
        path = ROOT / relative
        if not path.is_file():
            failures.append(f"{name}:missing")
        elif path.stat().st_size != size:
            failures.append(f"{name}:bytes")
        elif _sha256_file(path) != digest:
            failures.append(f"{name}:sha256")
    return tuple(failures)


@dataclass(frozen=True)
class ProducerContext:
    bundle: predecessor.CompletedStageBundle
    execution: cap.CAPExecution
    calls: tuple[cap.XOFCall, ...]
    capsule_sha256: str


@dataclass(frozen=True)
class ProducerResult:
    fragment: predecessor.RelationFragment
    summary: dict[str, object]
    export_state: dict[str, object]


class _ProducerSink(shard.StreamingRowSink):
    """Row sink for one fragment with a frozen absolute wire start."""

    def __init__(self, fragment_id: str, next_wire: int) -> None:
        super().__init__(
            {
                "format": "PQRBBC-ISSUANCE-FRAGMENT-INTERNAL-SINK-1",
                "relation_id": BOUNDED_RELATION_ID,
                "fragment_id": fragment_id,
            }
        )
        if type(next_wire) is not int or next_wire < 1:
            raise FragmentProducerError("fragment next_wire is invalid")
        self.next_wire = next_wire
        self.fragment_id = fragment_id
        self.captured: list[predecessor.CapturedRow] = []
        self.allocations: list[tuple[int, int]] = []

    def allocate(self, count: int = 1, **kwargs: object) -> int:
        start = super().allocate(count, **kwargs)
        if self._group_name not in FRAGMENT_GROUPS[self.fragment_id]:
            raise FragmentProducerError("allocation escaped fragment groups")
        self.allocations.append((start, start + count - 1))
        return start

    def row(
        self,
        label: str,
        left: field.LinearForm,
        right: field.LinearForm,
        output: field.LinearForm,
        *,
        nonlinear: bool,
    ) -> None:
        group = self._group_name
        if group not in FRAGMENT_GROUPS[self.fragment_id]:
            raise FragmentProducerError("row escaped fragment groups")
        self.captured.append(
            predecessor.CapturedRow(
                str(group), field.RankOneRow(label, left, right, output), nonlinear
            )
        )
        super().row(label, left, right, output, nonlinear=nonlinear)

    def result_fragment(self) -> predecessor.RelationFragment:
        if self._group_name is not None:
            raise FragmentProducerError("fragment group remains active")
        groups = tuple(item.name for item in self.groups)
        if groups != FRAGMENT_GROUPS[self.fragment_id]:
            raise FragmentProducerError("fragment group order changed")
        return predecessor.RelationFragment(
            self.fragment_id,
            groups,
            tuple(self.captured),
            predecessor._coalesce(self.allocations),
        )


class _MemorySpool:
    def __init__(self, records: Sequence[Sequence[int]]) -> None:
        if not records or not records[0]:
            raise FragmentProducerError("wire spool is empty")
        width = len(records[0])
        if any(len(item) != width for item in records):
            raise FragmentProducerError("wire spool record width mismatch")
        self._records = tuple(tuple(int(wire) for wire in item) for item in records)
        if any(wire < 1 for item in self._records for wire in item):
            raise FragmentProducerError("wire spool contains an invalid wire")
        self.records = len(self._records)
        self.record_wires = width
        packed = b"".join(
            struct.pack("<" + "Q" * width, *item) for item in self._records
        )
        self.bytes = len(packed)
        self.sha256 = _sha256(packed)

    def record(self, index: int) -> tuple[int, ...]:
        return self._records[index]

    def wire(self, record: int, coordinate: int) -> int:
        return self._records[record][coordinate]


def _context_from_capsule(
    bundle: predecessor.CompletedStageBundle,
    capsule_raw: bytes,
    *,
    expected_capsule_sha256: str,
) -> ProducerContext:
    execution = predecessor.decode_capsule(
        capsule_raw, bundle, expected_capsule_sha256=expected_capsule_sha256
    )
    request_payload = sponge.encode_transcript(
        (bundle.invocation.ticket_message, execution.commitment.encoded)
    )
    request_output = int.from_bytes(
        sponge.evaluate_sponge(
            sponge.REQUEST_BINDING_DOMAIN,
            request_payload,
            sponge.REQUEST_HASH_BYTES,
        ),
        "little",
    )
    request_call = cap.XOFCall(
        "request-binding",
        sponge.REQUEST_BINDING_DOMAIN,
        (bundle.invocation.ticket_message, execution.commitment.encoded),
        sponge.REQUEST_HASH_BITS,
        request_output,
    )
    calls = tuple(execution.xof_calls) + (request_call,)
    if len(calls) != 14:
        raise FragmentProducerError("bounded XOF schedule length changed")
    return ProducerContext(bundle, execution, calls, expected_capsule_sha256)


def _call(context: ProducerContext, index: int, label: str) -> cap.XOFCall:
    try:
        item = context.calls[index]
    except IndexError as error:
        raise FragmentProducerError("XOF schedule is incomplete") from error
    if item.label != label:
        raise FragmentProducerError(f"XOF schedule expected {label}, got {item.label}")
    return item


def _state_unsigned(state: Mapping[str, object]) -> dict[str, object]:
    return {key: value for key, value in state.items() if key != "port_identity_sha256"}


def _make_state(
    context: ProducerContext,
    producer_fragment: str,
    next_wire: int,
    body: Mapping[str, object],
) -> dict[str, object]:
    state: dict[str, object] = {
        "format": STATE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": BOUNDED_RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "invocation_sha256": context.bundle.invocation.invocation_sha256,
        "capsule_sha256": context.capsule_sha256,
        "producer_fragment": producer_fragment,
        "consumer_fragment": FRAGMENT_CONSUMERS[producer_fragment],
        "next_wire": next_wire,
        "body": dict(body),
    }
    state["port_identity_sha256"] = _sha256(
        DOMAIN_PORT + canonical_json(state)
    )
    return state


_STATE_FIELDS = {
    "format",
    "implementation_version",
    "relation_id",
    "profile_fingerprint",
    "invocation_sha256",
    "capsule_sha256",
    "producer_fragment",
    "consumer_fragment",
    "next_wire",
    "body",
    "port_identity_sha256",
}


def _validate_state(
    context: ProducerContext,
    state: object,
    *,
    producer_fragment: str,
    consumer_fragment: str,
    expected_identity: str,
) -> dict[str, object]:
    document = _exact(state, _STATE_FIELDS, "fragment port state")
    expected = {
        "format": STATE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": BOUNDED_RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "invocation_sha256": context.bundle.invocation.invocation_sha256,
        "capsule_sha256": context.capsule_sha256,
        "producer_fragment": producer_fragment,
        "consumer_fragment": consumer_fragment,
    }
    for name, value in expected.items():
        if document[name] != value:
            raise FragmentProducerError(f"fragment port {name} mismatch")
    identity = document["port_identity_sha256"]
    if not _is_sha256(expected_identity) or identity != expected_identity:
        raise FragmentProducerError("fragment import port identity mismatch")
    computed = _sha256(DOMAIN_PORT + canonical_json(_state_unsigned(document)))
    if identity != computed:
        raise FragmentProducerError("fragment port state digest mismatch")
    if type(document["next_wire"]) is not int or int(document["next_wire"]) < 1:
        raise FragmentProducerError("fragment port next_wire is invalid")
    if type(document["body"]) is not dict:
        raise FragmentProducerError("fragment port body is invalid")
    return document


def _fragment_summary(fragment: predecessor.RelationFragment) -> dict[str, object]:
    digest = hashlib.sha256(predecessor.DOMAIN_FRAGMENT)
    header = canonical_json(
        {
            "format": predecessor.FRAGMENT_STREAM_FORMAT,
            "relation_id": predecessor.BOUNDED_RELATION_ID,
            "profile_fingerprint": PROFILE_FINGERPRINT,
            "fragment_id": fragment.fragment_id,
            "groups": list(fragment.groups),
        }
    )
    digest.update(header)
    stream_bytes = len(header)
    for item in fragment.rows:
        raw = predecessor._row_record(item)
        digest.update(raw)
        stream_bytes += len(raw)
    owned = {
        wire
        for start, end in fragment.allocated_intervals
        for wire in range(start, end + 1)
    }
    referenced = {
        wire
        for item in fragment.rows
        for form in (item.row.left, item.row.right, item.row.output)
        for wire, _ in form.terms
    }
    return {
        "fragment_id": fragment.fragment_id,
        "groups": list(fragment.groups),
        "rows": len(fragment.rows),
        "nonlinear_rows": sum(item.nonlinear for item in fragment.rows),
        "linear_rows": sum(not item.nonlinear for item in fragment.rows),
        "allocated_wire_intervals": [list(item) for item in fragment.allocated_intervals],
        "allocated_wires": len(owned),
        "import_wire_count": len(referenced - owned),
        "stream_bytes": stream_bytes,
        "stream_sha256": digest.hexdigest(),
        "assignment_materialized": False,
        "row_archive_materialized": False,
        "external_assertions": 0,
    }


def _finish_result(
    context: ProducerContext,
    sink: _ProducerSink,
    body: Mapping[str, object],
) -> ProducerResult:
    fragment = sink.result_fragment()
    summary = _fragment_summary(fragment)
    expected_rows = predecessor.FROZEN_BOUNDED["fragment_rows"][fragment.fragment_id]
    expected_sha = predecessor.FROZEN_BOUNDED["fragment_stream_sha256"][
        fragment.fragment_id
    ]
    ordinal = FRAGMENT_ORDER.index(fragment.fragment_id)
    if summary["rows"] != expected_rows or summary["stream_sha256"] != expected_sha:
        raise FragmentProducerError("independent fragment differs from frozen split")
    if sink.next_wire != FROZEN_NEXT_WIRE[ordinal]:
        raise FragmentProducerError("independent fragment next-wire boundary changed")
    state = _make_state(context, fragment.fragment_id, sink.next_wire, body)
    return ProducerResult(fragment, summary, state)


_INPUT_BODY_FIELDS = {"salt_starts", "root_starts", "message_start"}
_TREE_PRE_BODY_FIELDS = _INPUT_BODY_FIELDS | {
    "commitment_starts",
    "spool_record_wires",
    "spool_records",
    "spool_bytes",
    "spool_sha256",
    "tape_values_hex",
}
_GLOBAL_A_BODY_FIELDS = _TREE_PRE_BODY_FIELDS | {
    "h1_start",
    "point_starts",
    "point_values_hex",
    "point_port_identity_sha256",
}
_TREE_POST_BODY_FIELDS = _GLOBAL_A_BODY_FIELDS | {
    "plain_output_starts",
    "mask_output_starts",
}


def _input_body(body: object) -> dict[str, object]:
    return _exact(body, _INPUT_BODY_FIELDS, "input-binding port body")


def _tree_pre_body(body: object) -> dict[str, object]:
    return _exact(
        body,
        _TREE_PRE_BODY_FIELDS,
        "tree-pre port body",
    )


def _global_a_body(body: object) -> dict[str, object]:
    return _exact(
        body,
        _GLOBAL_A_BODY_FIELDS,
        "global-A port body",
    )


def _tree_post_body(body: object) -> dict[str, object]:
    return _exact(
        body,
        _TREE_POST_BODY_FIELDS,
        "tree-post port body",
    )


_GLOBAL_B_BODY_FIELDS = {
    "commitment_start",
    "commitment_bits",
    "derived_mask_start",
    "derived_mask_bits",
    "append_base_start",
    "append_base_bits",
    "request_hash_start",
    "request_hash_bits",
    "commitment_sha256",
    "request_hash_sha256",
}


def _global_b_body(body: object) -> dict[str, object]:
    return _exact(body, _GLOBAL_B_BODY_FIELDS, "global-B port body")


_BODY_VALIDATORS = (
    _input_body,
    _tree_pre_body,
    _global_a_body,
    _tree_post_body,
    _global_b_body,
)


def _int_list(value: object, count: int, label: str) -> tuple[int, ...]:
    if type(value) is not list or len(value) != count:
        raise FragmentProducerError(f"{label} width mismatch")
    if any(type(item) is not int or item < 1 for item in value):
        raise FragmentProducerError(f"{label} contains invalid wire IDs")
    return tuple(value)


def _decode_hex_int(value: object, bits: int, label: str) -> int:
    try:
        return predecessor._int_from_hex(value, bits, label)
    except predecessor.SplitLowererError as error:
        raise FragmentProducerError(str(error)) from error


def produce_input_binding(context: ProducerContext) -> ProducerResult:
    sink = _ProducerSink("input-binding", 1)
    randomness = cap.CAPRandomness(
        context.bundle.invocation.rho.randomness.salt,
        (context.bundle.invocation.rho.randomness.roots[0],),
    )
    sink.start_group("inputs")
    salt_starts = (
        shard._allocate_input_bits(
            sink, field.FIELD_DEGREE, "input.salt[0]", randomness.salt[0]
        ),
        shard._allocate_input_bits(
            sink, field.FIELD_DEGREE, "input.salt[1]", randomness.salt[1]
        ),
    )
    root_starts = (
        shard._allocate_input_bits(
            sink, field.FIELD_DEGREE, "input.root[0]", randomness.roots[0][0]
        ),
        shard._allocate_input_bits(
            sink, field.FIELD_DEGREE, "input.root[1]", randomness.roots[0][1]
        ),
    )
    message_start = shard._allocate_input_bits(
        sink,
        256,
        "input.message",
        int.from_bytes(context.bundle.invocation.ticket_message, "little"),
    )
    sink.finish_group()
    return _finish_result(
        context,
        sink,
        {
            "salt_starts": list(salt_starts),
            "root_starts": list(root_starts),
            "message_start": message_start,
        },
    )


def produce_tree_pre(
    context: ProducerContext,
    import_state: Mapping[str, object],
    *,
    expected_import_identity: str,
) -> ProducerResult:
    state = _validate_state(
        context,
        import_state,
        producer_fragment="input-binding",
        consumer_fragment="tree-pre[0]",
        expected_identity=expected_import_identity,
    )
    body = _input_body(state["body"])
    salt_starts = _int_list(body["salt_starts"], 2, "salt_starts")
    root_starts = _int_list(body["root_starts"], 2, "root_starts")
    message_start = _int_list([body["message_start"]], 1, "message_start")[0]
    sink = _ProducerSink("tree-pre[0]", int(state["next_wire"]))
    lowerer = shard.StreamingSpongeLowerer(sink)
    salt_source = shard.source_pad_to_byte(
        shard.source_concat(
            shard.source_wires(salt_starts[0], field.FIELD_DEGREE),
            shard.source_wires(salt_starts[1], field.FIELD_DEGREE),
        )
    )
    randomness = cap.CAPRandomness(
        context.bundle.invocation.rho.randomness.salt,
        (context.bundle.invocation.rho.randomness.roots[0],),
    )
    nodes = [
        (root_starts[0], randomness.roots[0][0]),
        (root_starts[1], randomness.roots[0][1]),
    ]
    leaves = PARAMETERS.expanded_leaf_counts()[0]
    level = 2
    call_index = 0
    sink.start_group("ggm-derive")
    while len(nodes) < leaves:
        children: list[tuple[int, int]] = []
        for node_index, (parent_start, _) in enumerate(nodes, start=1):
            label = f"tree[0].derive[{level},{node_index}]"
            call = _call(context, call_index, label)
            lowered = lowerer.lower(
                call,
                (
                    salt_source,
                    shard.source_field_bytes(parent_start),
                    shard.source_constant(cap._meta(0, level, node_index)),
                ),
                call_index,
            )
            children.extend(
                (
                    (lowered.output_wires[0], call.output & field.FIELD_MASK),
                    (
                        lowered.output_wires[field.FIELD_DEGREE],
                        call.output >> field.FIELD_DEGREE,
                    ),
                )
            )
            call_index += 1
        nodes = children
        level += 1
    sink.finish_group()

    witness_bits = PARAMETERS.witness_bits
    mhat_shift = witness_bits + (PARAMETERS.degree - 1) * PARAMETERS.rho
    selected = tuple(range(witness_bits)) + tuple(
        range(mhat_shift, mhat_shift + PARAMETERS.consistency_bits)
    )
    commitments: list[list[int]] = []
    records: list[list[int]] = []
    tape_values: list[int] = []
    sink.start_group("leaf-commit-and-tape")
    for leaf_index, (seed_start, _) in enumerate(nodes, start=1):
        metadata = shard.source_constant(cap._meta(0, 0, leaf_index))
        commit_label = f"tree[0].leaf[{leaf_index}].commit"
        commit_call = _call(context, call_index, commit_label)
        commit = lowerer.lower(
            commit_call,
            (salt_source, shard.source_field_bytes(seed_start), metadata),
            call_index,
        )
        commitments.append(
            [commit.output_wires[0], commit.output_wires[field.FIELD_DEGREE]]
        )
        call_index += 1
        tape_label = f"tree[0].leaf[{leaf_index}].tape"
        tape_call = _call(context, call_index, tape_label)
        tape = lowerer.lower(
            tape_call,
            (shard.source_field_bytes(seed_start), metadata),
            call_index,
        )
        records.append([tape.output_wires[index] for index in selected])
        tape_values.append(tape_call.output)
        call_index += 1
    sink.finish_group()
    if call_index != 10:
        raise FragmentProducerError("tree-pre XOF schedule boundary changed")
    spool = _MemorySpool(records)
    tape_bytes = (PARAMETERS.random_polynomial_bits + 7) // 8
    next_body = {
        **body,
        "commitment_starts": commitments,
        "spool_record_wires": spool.record_wires,
        "spool_records": records,
        "spool_bytes": spool.bytes,
        "spool_sha256": spool.sha256,
        "tape_values_hex": [
            item.to_bytes(tape_bytes, "little").hex() for item in tape_values
        ],
    }
    return _finish_result(context, sink, next_body)


def produce_global_a(
    context: ProducerContext,
    import_state: Mapping[str, object],
    *,
    expected_import_identity: str,
) -> ProducerResult:
    state = _validate_state(
        context,
        import_state,
        producer_fragment="tree-pre[0]",
        consumer_fragment="global-tail-phase-a",
        expected_identity=expected_import_identity,
    )
    body = _tree_pre_body(state["body"])
    commitments_raw = body["commitment_starts"]
    if type(commitments_raw) is not list or len(commitments_raw) != 4:
        raise FragmentProducerError("commitment wire list width mismatch")
    commitments = tuple(
        _int_list(item, 2, "commitment wire pair") for item in commitments_raw
    )
    sink = _ProducerSink("global-tail-phase-a", int(state["next_wire"]))
    lowerer = shard.StreamingSpongeLowerer(sink)
    leaves = PARAMETERS.expanded_leaf_counts()[0]
    extension_degree = PARAMETERS.expanded_extension_degrees()[0]

    def tree_component_bits() -> Iterator[field.LinearForm]:
        yield from shard.source_constant(
            (0).to_bytes(2, "little")
            + leaves.to_bytes(4, "little")
            + extension_degree.to_bytes(2, "little")
        )
        for left_start, right_start in commitments:
            yield from shard.source_field_bytes(left_start)
            yield from shard.source_field_bytes(right_start)

    tree_component = shard.BitSource(
        (8 + 2 * leaves * field.FIELD_ELEMENT_BYTES) * 8,
        tree_component_bits,
    )
    correction_component = shard.source_constant(
        (0).to_bytes(2, "little")
        + PARAMETERS.witness_bits.to_bytes(4, "little")
        + PARAMETERS.consistency_bits.to_bytes(4, "little")
    )
    sink.start_group("h1-and-points")
    h1_call = _call(context, 10, "h1")
    h1 = lowerer.lower(
        h1_call,
        (
            shard.source_constant(bytes.fromhex(cap.profile_fingerprint(PARAMETERS))),
            tree_component,
            correction_component,
        ),
        10,
    )
    h1_start = h1.output_wires[0]
    points_call = _call(context, 11, "consistency-points")
    points = lowerer.lower(
        points_call,
        (
            shard.source_hash_bytes(h1_start),
            shard.source_constant(bytes.fromhex(cap.profile_fingerprint(PARAMETERS))),
        ),
        11,
    )
    point_starts = (
        points.output_wires[0],
        points.output_wires[field.FIELD_DEGREE],
    )
    point_values = tuple(
        (points_call.output >> (index * field.FIELD_DEGREE)) & field.FIELD_MASK
        for index in range(PARAMETERS.consistency_points)
    )
    shard._point_validation(sink, point_starts, point_values, "consistency.validate")
    sink.finish_group()
    points_raw = points_call.output.to_bytes(
        (PARAMETERS.consistency_bits + 7) // 8, "little"
    )
    point_port = {
        "port_id": "global.phase-a.consistency-points.native-wires",
        "producer_fragment": "global-tail-phase-a",
        "consumer_fragment": "tree-post[0]",
        "bit_length": PARAMETERS.consistency_bits,
        "wire_start": point_starts[0],
        "wire_end": point_starts[-1] + field.FIELD_DEGREE - 1,
        "wire_ids_contiguous": point_starts[1] == point_starts[0] + field.FIELD_DEGREE,
        "wire_ids_sha256": _sha256(
            canonical_json(list(range(point_starts[0], point_starts[-1] + field.FIELD_DEGREE)))
        ),
        "value_sha256": _sha256(points_raw),
        "tree_pre_consumes_port": False,
        "tree_post_consumes_every_wire": True,
    }
    point_port_identity = _sha256(
        predecessor.DOMAIN_POINT_PORT + canonical_json(point_port)
    )
    if point_port_identity != predecessor.FROZEN_BOUNDED["point_port_identity_sha256"]:
        raise FragmentProducerError("global-A point port identity changed")
    point_width = (field.FIELD_DEGREE + 7) // 8
    next_body = {
        **body,
        "h1_start": h1_start,
        "point_starts": list(point_starts),
        "point_values_hex": [
            item.to_bytes(point_width, "little").hex() for item in point_values
        ],
        "point_port_identity_sha256": point_port_identity,
    }
    return _finish_result(context, sink, next_body)


def _validated_spool(body: Mapping[str, object]) -> _MemorySpool:
    records_raw = body["spool_records"]
    if type(records_raw) is not list or len(records_raw) != 4:
        raise FragmentProducerError("wire spool record count mismatch")
    if type(body["spool_record_wires"]) is not int:
        raise FragmentProducerError("wire spool width is invalid")
    width = int(body["spool_record_wires"])
    records = tuple(_int_list(item, width, "wire spool record") for item in records_raw)
    spool = _MemorySpool(records)
    if spool.bytes != body["spool_bytes"] or spool.sha256 != body["spool_sha256"]:
        raise FragmentProducerError("wire spool identity mismatch")
    return spool


def produce_tree_post(
    context: ProducerContext,
    import_state: Mapping[str, object],
    *,
    expected_import_identity: str,
) -> ProducerResult:
    state = _validate_state(
        context,
        import_state,
        producer_fragment="global-tail-phase-a",
        consumer_fragment="tree-post[0]",
        expected_identity=expected_import_identity,
    )
    body = _global_a_body(state["body"])
    if body["point_port_identity_sha256"] != predecessor.FROZEN_BOUNDED[
        "point_port_identity_sha256"
    ]:
        raise FragmentProducerError("tree-post point port identity mismatch")
    point_starts = _int_list(body["point_starts"], 2, "point_starts")
    if point_starts[1] != point_starts[0] + field.FIELD_DEGREE:
        raise FragmentProducerError("point wire port is not contiguous")
    values_raw = body["point_values_hex"]
    if type(values_raw) is not list or len(values_raw) != 2:
        raise FragmentProducerError("point value width mismatch")
    point_values = tuple(
        _decode_hex_int(item, field.FIELD_DEGREE, "point value") for item in values_raw
    )
    tapes_raw = body["tape_values_hex"]
    if type(tapes_raw) is not list or len(tapes_raw) != 4:
        raise FragmentProducerError("tape value count mismatch")
    tape_values = tuple(
        _decode_hex_int(item, PARAMETERS.random_polynomial_bits, "tape value")
        for item in tapes_raw
    )
    spool = _validated_spool(body)
    sink = _ProducerSink("tree-post[0]", int(state["next_wire"]))
    extension_degree = PARAMETERS.expanded_extension_degrees()[0]
    selected_by_extension = tuple(
        tuple(
            leaf_index - 1
            for leaf_index in range(1, spool.records + 1)
            if (cap.gf2m_inv(leaf_index, extension_degree) >> extension_bit) & 1
        )
        for extension_bit in range(extension_degree)
    )
    sink.start_group("leaf-horner-and-field-aggregation")
    plain_accumulators: list[int | None] = [None, None]
    plain_values: list[int | None] = [None, None]
    mask_accumulators: list[list[int | None]] = [
        [None, None] for _ in range(extension_degree)
    ]
    mask_values: list[list[int | None]] = [
        [None, None] for _ in range(extension_degree)
    ]
    for leaf in range(spool.records):
        witness_ids = spool.record(leaf)[: PARAMETERS.witness_bits]
        outputs, output_values = shard._horner_leaf(
            sink,
            witness_ids,
            tape_values[leaf] & ((1 << PARAMETERS.witness_bits) - 1),
            point_starts,
            point_values,
            leaf + 1,
        )
        inverse = cap.gf2m_inv(leaf + 1, extension_degree)
        for point_index, (item, item_value) in enumerate(zip(outputs, output_values)):
            plain_accumulators[point_index], plain_values[point_index] = shard._aggregate_form(
                sink,
                plain_accumulators[point_index],
                plain_values[point_index],
                item,
                item_value,
                f"aggregate.plain.leaf[{leaf + 1}].point[{point_index}]",
            )
            for extension_bit in range(extension_degree):
                if (inverse >> extension_bit) & 1:
                    (
                        mask_accumulators[extension_bit][point_index],
                        mask_values[extension_bit][point_index],
                    ) = shard._aggregate_form(
                        sink,
                        mask_accumulators[extension_bit][point_index],
                        mask_values[extension_bit][point_index],
                        item,
                        item_value,
                        f"aggregate.mask[{extension_bit}].leaf[{leaf + 1}].point[{point_index}]",
                    )
    if any(item is None for item in plain_accumulators + plain_values):
        raise FragmentProducerError("plain Horner accumulator is missing")
    if any(item is None for row in mask_accumulators + mask_values for item in row):
        raise FragmentProducerError("mask Horner accumulator is missing")
    plain_output_starts = tuple(
        shard._decompose_field(
            sink,
            int(plain_accumulators[point]),
            int(plain_values[point]),
            f"consistency.plain.point[{point}].output",
        )
        for point in range(2)
    )
    mask_output_starts = tuple(
        tuple(
            shard._decompose_field(
                sink,
                int(mask_accumulators[extension_bit][point]),
                int(mask_values[extension_bit][point]),
                f"consistency.mask[{extension_bit}].point[{point}].output",
            )
            for point in range(2)
        )
        for extension_bit in range(extension_degree)
    )
    sink.finish_group()
    return _finish_result(
        context,
        sink,
        {
            **body,
            "plain_output_starts": list(plain_output_starts),
            "mask_output_starts": [list(item) for item in mask_output_starts],
        },
    )


def produce_global_b(
    context: ProducerContext,
    import_state: Mapping[str, object],
    *,
    expected_import_identity: str,
) -> ProducerResult:
    state = _validate_state(
        context,
        import_state,
        producer_fragment="tree-post[0]",
        consumer_fragment="global-tail-phase-b",
        expected_identity=expected_import_identity,
    )
    body = _tree_post_body(state["body"])
    salt_starts = _int_list(body["salt_starts"], 2, "salt_starts")
    message_start = _int_list([body["message_start"]], 1, "message_start")[0]
    h1_start = _int_list([body["h1_start"]], 1, "h1_start")[0]
    plain_output_starts = _int_list(
        body["plain_output_starts"], 2, "plain_output_starts"
    )
    masks_raw = body["mask_output_starts"]
    extension_degree = PARAMETERS.expanded_extension_degrees()[0]
    if type(masks_raw) is not list or len(masks_raw) != extension_degree:
        raise FragmentProducerError("mask output group width mismatch")
    mask_output_starts = tuple(
        _int_list(item, 2, "mask output pair") for item in masks_raw
    )
    spool = _validated_spool(body)
    selected_by_extension = tuple(
        tuple(
            leaf_index - 1
            for leaf_index in range(1, spool.records + 1)
            if (cap.gf2m_inv(leaf_index, extension_degree) >> extension_bit) & 1
        )
        for extension_bit in range(extension_degree)
    )
    tail_offset = PARAMETERS.witness_bits

    def plain_tail_form(coordinate: int) -> field.LinearForm:
        return shard._wide_plain_form(spool, tail_offset + coordinate)

    def mask_tail_form(extension_bit: int, coordinate: int) -> field.LinearForm:
        return shard._wide_mask_form(
            spool, tail_offset + coordinate, selected_by_extension[extension_bit]
        )

    def alpha_bits() -> Iterator[field.LinearForm]:
        for coordinate in range(PARAMETERS.consistency_bits):
            point = coordinate // field.FIELD_DEGREE
            bit = coordinate % field.FIELD_DEGREE
            yield field.LinearForm.wire(plain_output_starts[point] + bit).add(
                plain_tail_form(coordinate)
            )

    alpha_source = shard.BitSource(PARAMETERS.consistency_bits, alpha_bits)

    def xi_mask_bits() -> Iterator[field.LinearForm]:
        for coordinate in range(PARAMETERS.consistency_bits):
            point = coordinate // field.FIELD_DEGREE
            bit = coordinate % field.FIELD_DEGREE
            for extension_bit in range(extension_degree):
                yield field.LinearForm.wire(
                    mask_output_starts[extension_bit][point] + bit
                ).add(mask_tail_form(extension_bit, coordinate))

    xi_masks_source = shard.BitSource(
        PARAMETERS.consistency_bits * extension_degree, xi_mask_bits
    )
    xi_component = shard.source_concat(
        shard.source_constant(
            PARAMETERS.consistency_bits.to_bytes(4, "little")
            + extension_degree.to_bytes(2, "little")
        ),
        shard.source_pad_to_byte(alpha_source),
        shard.source_pad_to_byte(xi_masks_source),
    )
    sink = _ProducerSink("global-tail-phase-b", int(state["next_wire"]))
    lowerer = shard.StreamingSpongeLowerer(sink)
    sink.start_group("h2-commitment-and-request-binding")
    h2_call = _call(context, 12, "h2")
    h2 = lowerer.lower(
        h2_call, (shard.source_hash_bytes(h1_start), xi_component), 12
    )
    h2_start = h2.output_wires[0]
    commitment_source = shard.source_concat(
        shard.source_constant(cap.COMMITMENT_MAGIC + (1).to_bytes(2, "little")),
        shard.source_constant(bytes.fromhex(cap.profile_fingerprint(PARAMETERS))),
        shard.source_field_bytes(salt_starts[0]),
        shard.source_field_bytes(salt_starts[1]),
        shard.source_hash_bytes(h2_start),
        shard.source_constant(
            ((PARAMETERS.consistency_bits + 7) // 8).to_bytes(4, "little")
        ),
        shard.source_pad_to_byte(alpha_source),
    )
    if commitment_source.bit_length // 8 != len(context.execution.commitment.encoded):
        raise FragmentProducerError("commitment source length changed")
    commitment_start = shard._publish_source(
        sink,
        commitment_source,
        tuple(
            (byte >> bit) & 1
            for byte in context.execution.commitment.encoded
            for bit in range(8)
        ),
        "output.commitment",
    )

    def plain_witness_source(offset: int, length: int) -> shard.BitSource:
        return shard.BitSource(
            length,
            lambda: (
                shard._wide_plain_form(spool, offset + coordinate)
                for coordinate in range(length)
            ),
        )

    mask_start = shard._publish_source(
        sink,
        plain_witness_source(0, PARAMETERS.mask_bits),
        tuple(
            (context.execution.commitment.derived_mask >> bit) & 1
            for bit in range(PARAMETERS.mask_bits)
        ),
        "output.derived_mask",
    )
    append_start = shard._publish_source(
        sink,
        plain_witness_source(PARAMETERS.mask_bits, PARAMETERS.appended_signature_bits),
        tuple(
            (context.execution.commitment.append_base >> bit) & 1
            for bit in range(PARAMETERS.appended_signature_bits)
        ),
        "output.append_base",
    )
    request_call = _call(context, 13, "request-binding")
    request = lowerer.lower(
        request_call,
        (
            shard.source_wires(message_start, 256),
            shard.source_wires(commitment_start, commitment_source.bit_length),
        ),
        13,
    )
    request_start = request.output_wires[0]
    sink.finish_group()
    request_bytes = request_call.output.to_bytes(sponge.REQUEST_HASH_BYTES, "little")
    if request_bytes != sponge.hash_request_binding(
        context.bundle.invocation.ticket_message, context.execution.commitment.encoded
    ):
        raise FragmentProducerError("request-binding reference mismatch")
    return _finish_result(
        context,
        sink,
        {
            "commitment_start": commitment_start,
            "commitment_bits": commitment_source.bit_length,
            "derived_mask_start": mask_start,
            "derived_mask_bits": PARAMETERS.mask_bits,
            "append_base_start": append_start,
            "append_base_bits": PARAMETERS.appended_signature_bits,
            "request_hash_start": request_start,
            "request_hash_bits": sponge.REQUEST_HASH_BITS,
            "commitment_sha256": _sha256(context.execution.commitment.encoded),
            "request_hash_sha256": _sha256(request_bytes),
        },
    )


ProducerFunction = Callable[..., ProducerResult]
PRODUCER_FUNCTIONS: tuple[ProducerFunction, ...] = (
    produce_input_binding,
    produce_tree_pre,
    produce_global_a,
    produce_tree_post,
    produce_global_b,
)


def produce_sequence(context: ProducerContext) -> tuple[ProducerResult, ...]:
    results: list[ProducerResult] = []
    current: dict[str, object] | None = None
    for ordinal, function in enumerate(PRODUCER_FUNCTIONS):
        if ordinal == 0:
            result = function(context)
        else:
            assert current is not None
            result = function(
                context,
                current,
                expected_import_identity=str(current["port_identity_sha256"]),
            )
        results.append(result)
        current = result.export_state
    return tuple(results)


def fragment_filename(ordinal: int) -> str:
    if not 0 <= ordinal < len(FRAGMENT_ORDER):
        raise FragmentProducerError("fragment ordinal outside bounded plan")
    return f"fragment-{ordinal:03d}.json"


def receipt_filename(completed_count: int) -> str:
    if not 0 <= completed_count <= len(FRAGMENT_ORDER):
        raise FragmentProducerError("receipt count outside bounded plan")
    return f"receipt-{completed_count:03d}.json"


def _allowed_names() -> set[str]:
    return {
        COMPLETE_FILENAME,
        *(fragment_filename(index) for index in range(len(FRAGMENT_ORDER))),
        *(receipt_filename(index) for index in range(len(FRAGMENT_ORDER) + 1)),
    }


def _inventory_names(output_fd: int) -> set[str]:
    names = set(os.listdir(output_fd))
    unknown = names - _allowed_names()
    if unknown:
        raise FragmentProducerError(
            "fragment output contains unknown entries: " + ", ".join(sorted(unknown))
        )
    return names


def _artifact_document(
    context: ProducerContext,
    ordinal: int,
    result: ProducerResult,
    *,
    previous_receipt_sha256: str,
    import_port_identity_sha256: str | None,
) -> dict[str, object]:
    document: dict[str, object] = {
        "format": ARTIFACT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": BOUNDED_RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "invocation_sha256": context.bundle.invocation.invocation_sha256,
        "capsule_sha256": context.capsule_sha256,
        "split_final_receipt_sha256": context.bundle.final_receipt_sha256,
        "ordinal": ordinal,
        "fragment_id": FRAGMENT_ORDER[ordinal],
        "previous_receipt_sha256": previous_receipt_sha256,
        "import_port_identity_sha256": import_port_identity_sha256,
        "fragment_summary": result.summary,
        "export_state": result.export_state,
        "private_runtime_state_embedded": True,
        "row_archive_embedded": False,
        "assignment_embedded": False,
    }
    document["artifact_binding_sha256"] = _sha256(
        DOMAIN_ARTIFACT + canonical_json(document)
    )
    return document


_ARTIFACT_FIELDS = {
    "format",
    "implementation_version",
    "relation_id",
    "profile_fingerprint",
    "invocation_sha256",
    "capsule_sha256",
    "split_final_receipt_sha256",
    "ordinal",
    "fragment_id",
    "previous_receipt_sha256",
    "import_port_identity_sha256",
    "fragment_summary",
    "export_state",
    "private_runtime_state_embedded",
    "row_archive_embedded",
    "assignment_embedded",
    "artifact_binding_sha256",
}


def _validate_fragment_summary(document: object, ordinal: int) -> dict[str, object]:
    summary = _exact(
        document,
        {
            "fragment_id",
            "groups",
            "rows",
            "nonlinear_rows",
            "linear_rows",
            "allocated_wire_intervals",
            "allocated_wires",
            "import_wire_count",
            "stream_bytes",
            "stream_sha256",
            "assignment_materialized",
            "row_archive_materialized",
            "external_assertions",
        },
        "fragment summary",
    )
    fragment_id = FRAGMENT_ORDER[ordinal]
    if summary["fragment_id"] != fragment_id:
        raise FragmentProducerError("fragment summary ID mismatch")
    if summary["groups"] != list(FRAGMENT_GROUPS[fragment_id]):
        raise FragmentProducerError("fragment summary groups mismatch")
    if summary["rows"] != predecessor.FROZEN_BOUNDED["fragment_rows"][fragment_id]:
        raise FragmentProducerError("fragment summary row count mismatch")
    if summary["stream_sha256"] != predecessor.FROZEN_BOUNDED[
        "fragment_stream_sha256"
    ][fragment_id]:
        raise FragmentProducerError("fragment summary stream identity mismatch")
    if summary["nonlinear_rows"] + summary["linear_rows"] != summary["rows"]:
        raise FragmentProducerError("fragment summary row accounting mismatch")
    if (
        summary["assignment_materialized"] is not False
        or summary["row_archive_materialized"] is not False
        or summary["external_assertions"] != 0
    ):
        raise FragmentProducerError("fragment summary exceeds bounded claim")
    intervals = summary["allocated_wire_intervals"]
    if type(intervals) is not list or not intervals:
        raise FragmentProducerError("fragment allocation intervals are invalid")
    previous_end = 0
    allocated = 0
    for item in intervals:
        if (
            type(item) is not list
            or len(item) != 2
            or any(type(value) is not int for value in item)
            or item[0] < 1
            or item[1] < item[0]
            or item[0] <= previous_end
        ):
            raise FragmentProducerError("fragment allocation interval is invalid")
        previous_end = item[1]
        allocated += item[1] - item[0] + 1
    if summary["allocated_wires"] != allocated:
        raise FragmentProducerError("fragment allocated wire count mismatch")
    for name in ("import_wire_count", "stream_bytes"):
        if type(summary[name]) is not int or int(summary[name]) < 0:
            raise FragmentProducerError(f"fragment summary {name} is invalid")
    if not _is_sha256(summary["stream_sha256"]):
        raise FragmentProducerError("fragment stream digest is invalid")
    return summary


def _validate_artifact_document(
    context: ProducerContext,
    document: object,
    *,
    ordinal: int,
    previous_receipt_sha256: str,
    import_port_identity_sha256: str | None,
) -> dict[str, object]:
    artifact = _exact(document, _ARTIFACT_FIELDS, "fragment artifact")
    expected = {
        "format": ARTIFACT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": BOUNDED_RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "invocation_sha256": context.bundle.invocation.invocation_sha256,
        "capsule_sha256": context.capsule_sha256,
        "split_final_receipt_sha256": context.bundle.final_receipt_sha256,
        "ordinal": ordinal,
        "fragment_id": FRAGMENT_ORDER[ordinal],
        "previous_receipt_sha256": previous_receipt_sha256,
        "import_port_identity_sha256": import_port_identity_sha256,
        "private_runtime_state_embedded": True,
        "row_archive_embedded": False,
        "assignment_embedded": False,
    }
    for name, value in expected.items():
        if artifact[name] != value:
            raise FragmentProducerError(f"fragment artifact {name} mismatch")
    _validate_fragment_summary(artifact["fragment_summary"], ordinal)
    state = _validate_state(
        context,
        artifact["export_state"],
        producer_fragment=FRAGMENT_ORDER[ordinal],
        consumer_fragment=FRAGMENT_CONSUMERS[FRAGMENT_ORDER[ordinal]],
        expected_identity=str(artifact["export_state"].get("port_identity_sha256", ""))
        if type(artifact["export_state"]) is dict
        else "",
    )
    _BODY_VALIDATORS[ordinal](state["body"])
    if state["next_wire"] != FROZEN_NEXT_WIRE[ordinal]:
        raise FragmentProducerError("fragment artifact next-wire boundary mismatch")
    unsigned = {key: value for key, value in artifact.items() if key != "artifact_binding_sha256"}
    if artifact["artifact_binding_sha256"] != _sha256(
        DOMAIN_ARTIFACT + canonical_json(unsigned)
    ):
        raise FragmentProducerError("fragment artifact binding mismatch")
    return state


def _receipt_document(
    context: ProducerContext,
    completed_count: int,
    *,
    artifact_identity: Mapping[str, object] | None,
    export_port_identity_sha256: str | None,
    previous_receipt_sha256: str | None,
) -> dict[str, object]:
    document: dict[str, object] = {
        "format": RECEIPT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": BOUNDED_RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "invocation_sha256": context.bundle.invocation.invocation_sha256,
        "capsule_sha256": context.capsule_sha256,
        "split_final_receipt_sha256": context.bundle.final_receipt_sha256,
        "completed_count": completed_count,
        "fragment_id": None if completed_count == 0 else FRAGMENT_ORDER[completed_count - 1],
        "artifact_identity": None if artifact_identity is None else dict(artifact_identity),
        "export_port_identity_sha256": export_port_identity_sha256,
        "previous_receipt_sha256": previous_receipt_sha256,
    }
    document["receipt_binding_sha256"] = _sha256(
        DOMAIN_RECEIPT + canonical_json(document)
    )
    return document


_RECEIPT_FIELDS = {
    "format",
    "implementation_version",
    "relation_id",
    "profile_fingerprint",
    "invocation_sha256",
    "capsule_sha256",
    "split_final_receipt_sha256",
    "completed_count",
    "fragment_id",
    "artifact_identity",
    "export_port_identity_sha256",
    "previous_receipt_sha256",
    "receipt_binding_sha256",
}


def _validate_raw_identity(
    document: object, expected: Mapping[str, object], label: str
) -> None:
    identity = _exact(document, {"filename", "bytes", "sha256"}, label)
    if identity != dict(expected):
        raise FragmentProducerError(f"{label} mismatch")
    if (
        type(identity["filename"]) is not str
        or type(identity["bytes"]) is not int
        or int(identity["bytes"]) <= 0
        or not _is_sha256(identity["sha256"])
    ):
        raise FragmentProducerError(f"{label} is invalid")


def _validate_receipt_document(
    context: ProducerContext,
    document: object,
    *,
    completed_count: int,
    artifact_identity: Mapping[str, object] | None,
    export_port_identity_sha256: str | None,
    previous_receipt_sha256: str | None,
) -> None:
    receipt = _exact(document, _RECEIPT_FIELDS, "fragment receipt")
    expected = _receipt_document(
        context,
        completed_count,
        artifact_identity=artifact_identity,
        export_port_identity_sha256=export_port_identity_sha256,
        previous_receipt_sha256=previous_receipt_sha256,
    )
    if receipt != expected:
        raise FragmentProducerError("fragment receipt content mismatch")


def _complete_document(
    context: ProducerContext,
    fragment_identities: Sequence[Mapping[str, object]],
    receipt_identities: Sequence[Mapping[str, object]],
    final_state: Mapping[str, object],
) -> dict[str, object]:
    return {
        "format": COMPLETE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": "INSECURE-TEST-ONLY",
        "relation_id": BOUNDED_RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "invocation_sha256": context.bundle.invocation.invocation_sha256,
        "capsule_sha256": context.capsule_sha256,
        "split_final_receipt_sha256": context.bundle.final_receipt_sha256,
        "fragment_order": list(FRAGMENT_ORDER),
        "fragment_identities": [dict(item) for item in fragment_identities],
        "receipt_identities": [dict(item) for item in receipt_identities],
        "final_export_port_identity_sha256": final_state["port_identity_sha256"],
        "merged_rows": predecessor.FROZEN_BOUNDED["merged_rows"],
        "merged_wires": predecessor.FROZEN_BOUNDED["merged_wires"],
        "existing_monolithic_stream_sha256": predecessor.FROZEN_BOUNDED[
            "merged_stream_sha256"
        ],
        "assignment_materialized": False,
        "row_archive_materialized": False,
        "full_i3_relation_replayed": False,
        "large_relation_rows_replayed": 0,
        "cryptographic_proofs_generated": 0,
        "production": False,
    }


def _invoke_producer(
    ordinal: int,
    context: ProducerContext,
    import_state: Mapping[str, object] | None,
) -> ProducerResult:
    function = PRODUCER_FUNCTIONS[ordinal]
    if ordinal == 0:
        if import_state is not None:
            raise FragmentProducerError("input-binding cannot consume an import")
        return function(context)
    if import_state is None:
        raise FragmentProducerError("fragment import state is missing")
    return function(
        context,
        import_state,
        expected_import_identity=str(import_state["port_identity_sha256"]),
    )


def execute_production_fragment_producers(*_args: object, **_kwargs: object) -> None:
    raise ProductionFragmentProducersUnavailable(
        "production fragment producers are unavailable; no artifact was read or created"
    )


def run_bounded_fragment_producers(
    bundle: predecessor.CompletedStageBundle,
    capsule_raw: bytes,
    output: Path,
    *,
    artifact_root: Path,
    expected_capsule_sha256: str,
    fresh_output: bool = False,
    resume: bool = False,
    expected_checkpoint_sha256: str | None = None,
    stop_after_fragments: int | None = None,
    interrupt_after_fragment: int | None = None,
) -> dict[str, object] | None:
    if fresh_output == resume:
        raise FragmentProducerError("select exactly one of fresh_output or resume")
    if not _is_sha256(expected_capsule_sha256) or _sha256(capsule_raw) != expected_capsule_sha256:
        raise FragmentProducerError("capsule digest mismatch")
    if resume and not _is_sha256(expected_checkpoint_sha256):
        raise FragmentProducerError("resume requires exact latest receipt SHA-256")
    if fresh_output and expected_checkpoint_sha256 is not None:
        raise FragmentProducerError("fresh output cannot take a checkpoint identity")
    if stop_after_fragments is not None and not 0 <= stop_after_fragments <= len(FRAGMENT_ORDER):
        raise FragmentProducerError("stop_after_fragments outside bounded plan")
    if interrupt_after_fragment is not None and not 0 <= interrupt_after_fragment < len(
        FRAGMENT_ORDER
    ):
        raise FragmentProducerError("interrupt_after_fragment outside bounded plan")

    prebuilt_context = (
        _context_from_capsule(
            bundle, capsule_raw, expected_capsule_sha256=expected_capsule_sha256
        )
        if fresh_output
        else None
    )
    with recovery_io.locked_output(output, artifact_root, fresh=fresh_output) as output_fd:
        names = _inventory_names(output_fd)
        snapshots: dict[str, launch_io.Snapshot] = {}
        if fresh_output:
            if names:
                raise FragmentProducerError("fresh fragment output is not empty")
            assert prebuilt_context is not None
            context = prebuilt_context
            genesis_raw = canonical_json(
                _receipt_document(
                    context,
                    0,
                    artifact_identity=None,
                    export_port_identity_sha256=None,
                    previous_receipt_sha256=None,
                )
            )
            recovery_io.publish(output / GENESIS_FILENAME, genesis_raw)
            snapshots[GENESIS_FILENAME] = launch_io.Snapshot(
                output / GENESIS_FILENAME, genesis_raw
            )
            names.add(GENESIS_FILENAME)
            if stop_after_fragments == 0:
                return None
        else:
            receipt_indices = [
                index
                for index in range(len(FRAGMENT_ORDER) + 1)
                if receipt_filename(index) in names
            ]
            if not receipt_indices:
                raise FragmentProducerError("resume output has no receipt")
            latest_name = receipt_filename(max(receipt_indices))
            # This caller-supplied digest is checked under the directory lock
            # before capsule parsing, producer invocation, or any other read.
            latest = recovery_io.read(output / latest_name)
            snapshots[latest_name] = latest
            if latest.identity["sha256"] != expected_checkpoint_sha256:
                raise FragmentProducerError("latest fragment receipt digest mismatch")
            context = _context_from_capsule(
                bundle, capsule_raw, expected_capsule_sha256=expected_capsule_sha256
            )

        names = _inventory_names(output_fd)
        receipt_indices = [
            index
            for index in range(len(FRAGMENT_ORDER) + 1)
            if receipt_filename(index) in names
        ]
        if receipt_indices != list(range(max(receipt_indices) + 1)):
            raise FragmentProducerError("fragment receipts are not a contiguous prefix")
        completed_count = max(receipt_indices)
        fragment_indices = [
            index
            for index in range(len(FRAGMENT_ORDER))
            if fragment_filename(index) in names
        ]
        permitted = set(range(completed_count))
        if completed_count < len(FRAGMENT_ORDER):
            permitted.add(completed_count)
        if set(fragment_indices) - permitted:
            raise FragmentProducerError("fragment artifacts are not prefix plus one orphan")
        if not set(range(completed_count)).issubset(fragment_indices):
            raise FragmentProducerError("fragment receipt refers to a missing artifact")
        if COMPLETE_FILENAME in names and completed_count != len(FRAGMENT_ORDER):
            raise FragmentProducerError("premature fragment complete document")

        previous_receipt_sha256: str | None = None
        current_state: dict[str, object] | None = None
        fragment_identities: list[dict[str, object]] = []
        receipt_identities: list[dict[str, object]] = []
        for receipt_index in range(completed_count + 1):
            receipt_name = receipt_filename(receipt_index)
            receipt_snapshot = snapshots.get(receipt_name)
            if receipt_snapshot is None:
                receipt_snapshot = recovery_io.read(output / receipt_name)
                snapshots[receipt_name] = receipt_snapshot
            artifact_identity: dict[str, object] | None = None
            export_identity: str | None = None
            if receipt_index:
                ordinal = receipt_index - 1
                artifact_name = fragment_filename(ordinal)
                artifact_snapshot = snapshots.get(artifact_name)
                if artifact_snapshot is None:
                    artifact_snapshot = recovery_io.read(output / artifact_name)
                    snapshots[artifact_name] = artifact_snapshot
                assert previous_receipt_sha256 is not None
                import_identity = (
                    None
                    if current_state is None
                    else str(current_state["port_identity_sha256"])
                )
                current_state = _validate_artifact_document(
                    context,
                    _strict_json(artifact_snapshot.raw, "fragment artifact"),
                    ordinal=ordinal,
                    previous_receipt_sha256=previous_receipt_sha256,
                    import_port_identity_sha256=import_identity,
                )
                artifact_identity = artifact_snapshot.identity
                export_identity = str(current_state["port_identity_sha256"])
                fragment_identities.append(artifact_identity)
            _validate_receipt_document(
                context,
                _strict_json(receipt_snapshot.raw, "fragment receipt"),
                completed_count=receipt_index,
                artifact_identity=artifact_identity,
                export_port_identity_sha256=export_identity,
                previous_receipt_sha256=previous_receipt_sha256,
            )
            receipt_identities.append(receipt_snapshot.identity)
            previous_receipt_sha256 = str(receipt_snapshot.identity["sha256"])

        orphan_snapshot: launch_io.Snapshot | None = None
        if (
            completed_count < len(FRAGMENT_ORDER)
            and fragment_filename(completed_count) in names
        ):
            orphan_name = fragment_filename(completed_count)
            orphan_snapshot = recovery_io.read(output / orphan_name)
            assert previous_receipt_sha256 is not None
            _validate_artifact_document(
                context,
                _strict_json(orphan_snapshot.raw, "orphan fragment artifact"),
                ordinal=completed_count,
                previous_receipt_sha256=previous_receipt_sha256,
                import_port_identity_sha256=(
                    None
                    if current_state is None
                    else str(current_state["port_identity_sha256"])
                ),
            )
            snapshots[orphan_name] = orphan_snapshot

        for ordinal in range(completed_count, len(FRAGMENT_ORDER)):
            assert previous_receipt_sha256 is not None
            result = _invoke_producer(ordinal, context, current_state)
            import_identity = (
                None
                if current_state is None
                else str(current_state["port_identity_sha256"])
            )
            artifact_name = fragment_filename(ordinal)
            artifact_raw = canonical_json(
                _artifact_document(
                    context,
                    ordinal,
                    result,
                    previous_receipt_sha256=previous_receipt_sha256,
                    import_port_identity_sha256=import_identity,
                )
            )
            if artifact_name in names:
                artifact_snapshot = snapshots.get(artifact_name)
                if artifact_snapshot is None:
                    artifact_snapshot = recovery_io.read(output / artifact_name)
                if artifact_snapshot.raw != artifact_raw:
                    raise FragmentProducerError(
                        "orphan fragment bytes differ from independent recomputation"
                    )
                recovery_io.sync_directory(output, output_fd)
            else:
                recovery_io.publish(output / artifact_name, artifact_raw)
                artifact_snapshot = launch_io.Snapshot(
                    output / artifact_name, artifact_raw
                )
                names.add(artifact_name)
            if interrupt_after_fragment == ordinal:
                raise ControlledInterruption(
                    f"controlled interruption after {FRAGMENT_ORDER[ordinal]} artifact"
                )
            fragment_identity = artifact_snapshot.identity
            receipt_name = receipt_filename(ordinal + 1)
            receipt_raw = canonical_json(
                _receipt_document(
                    context,
                    ordinal + 1,
                    artifact_identity=fragment_identity,
                    export_port_identity_sha256=str(
                        result.export_state["port_identity_sha256"]
                    ),
                    previous_receipt_sha256=previous_receipt_sha256,
                )
            )
            recovery_io.publish(output / receipt_name, receipt_raw)
            receipt_snapshot = launch_io.Snapshot(output / receipt_name, receipt_raw)
            fragment_identities.append(fragment_identity)
            receipt_identities.append(receipt_snapshot.identity)
            previous_receipt_sha256 = str(receipt_snapshot.identity["sha256"])
            current_state = result.export_state
            names.add(receipt_name)
            orphan_snapshot = None
            if stop_after_fragments == ordinal + 1:
                return None

        if current_state is None:
            raise FragmentProducerError("completed fragment chain has no final state")
        complete = _complete_document(
            context, fragment_identities, receipt_identities, current_state
        )
        complete_raw = canonical_json(complete)
        if COMPLETE_FILENAME in names:
            snapshot = recovery_io.read(output / COMPLETE_FILENAME)
            if snapshot.raw != complete_raw:
                raise FragmentProducerError("fragment complete bytes changed")
        else:
            recovery_io.publish(output / COMPLETE_FILENAME, complete_raw)
        return complete


def latest_receipt(output: Path, *, artifact_root: Path) -> launch_io.Snapshot:
    with recovery_io.locked_output(output, artifact_root, fresh=False) as output_fd:
        names = _inventory_names(output_fd)
        indices = [
            index
            for index in range(len(FRAGMENT_ORDER) + 1)
            if receipt_filename(index) in names
        ]
        if not indices:
            raise FragmentProducerError("fragment output has no receipt")
        return recovery_io.read(output / receipt_filename(max(indices)))


def _snapshot_tree(output: Path) -> dict[str, bytes]:
    return {item.name: item.read_bytes() for item in sorted(output.iterdir())}


def _fixture_bytes() -> tuple[bytes, bytes]:
    return predecessor._fixture_bytes()


@lru_cache(maxsize=1)
def bounded_self_check() -> dict[str, object]:
    statement_raw, witness_raw = _fixture_bytes()
    with TemporaryDirectory(prefix="pq-rbbc-fragment-producers-") as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        stages = root / "stages"
        split.run_bounded_split(
            statement_raw,
            witness_raw,
            stages,
            artifact_root=root,
            fresh_output=True,
        )
        split_latest = split.latest_receipt(stages, artifact_root=root)
        bundle = predecessor.load_completed_stage_bundle(
            statement_raw,
            witness_raw,
            stages,
            artifact_root=root,
            expected_checkpoint_sha256=str(split_latest.identity["sha256"]),
        )
        capsule_raw, execution = predecessor.build_fresh_capsule(bundle)
        capsule_sha256 = _sha256(capsule_raw)
        context = _context_from_capsule(
            bundle, capsule_raw, expected_capsule_sha256=capsule_sha256
        )
        independent = produce_sequence(context)
        monolithic_summary, monolithic_rows, monolithic_allocations = (
            predecessor._capture_existing_monolithic(bundle, execution)
        )
        monolithic_fragments = predecessor.build_fragments(
            monolithic_rows, monolithic_allocations
        )
        predecessor.verify_exact_merge(
            monolithic_rows, tuple(item.fragment for item in independent)
        )
        independent_rows_equal = all(
            independent[index].fragment == monolithic_fragments[index]
            for index in range(len(FRAGMENT_ORDER))
        )

        output = root / "fragments"
        counts = [0] * len(FRAGMENT_ORDER)
        originals = PRODUCER_FUNCTIONS

        def counted(index: int, function: ProducerFunction) -> ProducerFunction:
            def wrapper(*args: object, **kwargs: object) -> ProducerResult:
                counts[index] += 1
                return function(*args, **kwargs)

            return wrapper

        counted_functions = tuple(
            counted(index, function) for index, function in enumerate(originals)
        )
        globals()["PRODUCER_FUNCTIONS"] = counted_functions
        interrupted = False
        try:
            try:
                run_bounded_fragment_producers(
                    bundle,
                    capsule_raw,
                    output,
                    artifact_root=root,
                    expected_capsule_sha256=capsule_sha256,
                    fresh_output=True,
                    interrupt_after_fragment=2,
                )
            except ControlledInterruption:
                interrupted = True
            orphan = output / fragment_filename(2)
            orphan_identity_before = launch_io.Snapshot(
                orphan, orphan.read_bytes()
            ).identity
            orphan_inode_before = orphan.stat().st_ino
            checkpoint = latest_receipt(output, artifact_root=root)
            completed_before_resume = tuple(counts)
            complete = run_bounded_fragment_producers(
                bundle,
                capsule_raw,
                output,
                artifact_root=root,
                expected_capsule_sha256=capsule_sha256,
                resume=True,
                expected_checkpoint_sha256=str(checkpoint.identity["sha256"]),
            )
        finally:
            globals()["PRODUCER_FUNCTIONS"] = originals
        assert complete is not None
        orphan_identity_after = launch_io.Snapshot(
            orphan, orphan.read_bytes()
        ).identity
        orphan_inode_after = orphan.stat().st_ino
        final_receipt = latest_receipt(output, artifact_root=root)
        runtime_tree = _snapshot_tree(output)
        artifacts = [
            launch_io.Snapshot(
                output / fragment_filename(index),
                runtime_tree[fragment_filename(index)],
            ).identity
            for index in range(len(FRAGMENT_ORDER))
        ]
        export_ports = [
            _strict_json(runtime_tree[fragment_filename(index)], "fragment artifact")[
                "export_state"
            ]["port_identity_sha256"]
            for index in range(len(FRAGMENT_ORDER))
        ]
        no_completed_rerun = (
            completed_before_resume[:2] == (1, 1)
            and tuple(counts[:2]) == (1, 1)
            and counts[2] == 2
            and tuple(counts[3:]) == (1, 1)
        )
        wrong_checkpoint_before_context = False
        original_context_builder = globals()["_context_from_capsule"]

        def context_guard(*_args: object, **_kwargs: object) -> ProducerContext:
            raise AssertionError("wrong checkpoint reached capsule decoding")

        globals()["_context_from_capsule"] = context_guard
        try:
            try:
                run_bounded_fragment_producers(
                    bundle,
                    capsule_raw,
                    output,
                    artifact_root=root,
                    expected_capsule_sha256=capsule_sha256,
                    resume=True,
                    expected_checkpoint_sha256="0" * 64,
                )
            except FragmentProducerError:
                wrong_checkpoint_before_context = True
        finally:
            globals()["_context_from_capsule"] = original_context_builder

    fragment_rows = {
        item.fragment.fragment_id: item.summary["rows"] for item in independent
    }
    fragment_streams = {
        item.fragment.fragment_id: item.summary["stream_sha256"]
        for item in independent
    }
    frozen_mismatches = []
    if fragment_rows != predecessor.FROZEN_BOUNDED["fragment_rows"]:
        frozen_mismatches.append("fragment_rows")
    if fragment_streams != predecessor.FROZEN_BOUNDED["fragment_stream_sha256"]:
        frozen_mismatches.append("fragment_stream_sha256")
    if monolithic_summary.rows != predecessor.FROZEN_BOUNDED["merged_rows"]:
        frozen_mismatches.append("merged_rows")
    if monolithic_summary.wires != predecessor.FROZEN_BOUNDED["merged_wires"]:
        frozen_mismatches.append("merged_wires")
    if monolithic_summary.stream_sha256 != predecessor.FROZEN_BOUNDED[
        "merged_stream_sha256"
    ]:
        frozen_mismatches.append("merged_stream_sha256")
    if export_ports != FROZEN_PUBLICATION["export_port_identities"]:
        frozen_mismatches.append("export_port_identities")
    if [item["sha256"] for item in artifacts] != FROZEN_PUBLICATION[
        "fragment_artifact_sha256"
    ]:
        frozen_mismatches.append("fragment_artifact_sha256")
    if [item["bytes"] for item in artifacts] != FROZEN_PUBLICATION[
        "fragment_artifact_bytes"
    ]:
        frozen_mismatches.append("fragment_artifact_bytes")
    if final_receipt.identity["sha256"] != FROZEN_PUBLICATION[
        "final_receipt_sha256"
    ]:
        frozen_mismatches.append("final_receipt_sha256")
    if final_receipt.identity["bytes"] != FROZEN_PUBLICATION["final_receipt_bytes"]:
        frozen_mismatches.append("final_receipt_bytes")
    if len(runtime_tree) != FROZEN_PUBLICATION["runtime_file_count"]:
        frozen_mismatches.append("runtime_file_count")
    return {
        "mode": "INSECURE-TEST-ONLY",
        "capsule_sha256": capsule_sha256,
        "fragment_order": list(FRAGMENT_ORDER),
        "fragment_rows": fragment_rows,
        "fragment_stream_sha256": fragment_streams,
        "fragment_artifact_identities": artifacts,
        "export_port_identities": export_ports,
        "independent_fragments_row_by_row_equal_to_existing_monolithic": independent_rows_equal,
        "merged_rows": sum(int(item.summary["rows"]) for item in independent),
        "merged_wires": int(independent[-1].export_state["next_wire"]) - 1,
        "existing_monolithic_stream_sha256": monolithic_summary.stream_sha256,
        "controlled_interruption_observed": interrupted,
        "orphan_identity_preserved": orphan_identity_before == orphan_identity_after,
        "orphan_inode_preserved": orphan_inode_before == orphan_inode_after,
        "completed_producers_not_rerun_on_resume": no_completed_rerun,
        "orphan_next_producer_recomputed_once": counts[2] == 2,
        "producer_invocation_counts_across_interrupt_resume": counts,
        "wrong_checkpoint_rejected_before_capsule_parse_or_producer": wrong_checkpoint_before_context,
        "final_receipt_identity": final_receipt.identity,
        "runtime_file_count": len(runtime_tree),
        "runtime_private_state_external_only": True,
        "verification_failures": 0,
        "external_assertions": 0,
        "assignment_materialized": False,
        "row_archive_materialized": False,
        "full_i3_relation_replayed": False,
        "large_relation_rows_replayed": 0,
        "cryptographic_proofs_generated": 0,
        "frozen_mismatches": frozen_mismatches,
    }


def build_manifest() -> dict[str, object]:
    bounded = bounded_self_check()
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "production_relation_id": PRODUCTION_RELATION_ID,
        "bounded_relation_id": BOUNDED_RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "protocol_location": "issuance relation I3 / CAP.Commit child",
        "producer_contract": {
            "order": list(FRAGMENT_ORDER),
            "groups": {key: list(value) for key, value in FRAGMENT_GROUPS.items()},
            "independently_invocable_bounded_producers": True,
            "absolute_wire_namespace_preserved": True,
            "explicit_import_port_identity_required": True,
            "private_export_state_is_external_only": True,
            "row_archive_published": False,
            "assignment_published": False,
            "production_stage_count": None,
            "production_intervals": None,
        },
        "publication_contract": {
            "file_count": 12,
            "genesis_receipts": 1,
            "fragment_artifacts": 5,
            "stage_receipts": 5,
            "complete_documents": 1,
            "single_open_single_bounded_read": True,
            "immutable_snapshot_raw_for_identity_parse_and_validation": True,
            "metadata_is_best_effort_mutation_signal_only": True,
            "metadata_proves_no_concurrent_writer": False,
            "exclusive_no_replace_publication": True,
            "completed_producers_reexecuted_on_resume": False,
            "single_next_orphan_recomputed_before_adoption": True,
            "future_executor_must_consume_candidate_set_snapshots": True,
            "future_executor_may_reopen_candidate_pathnames": False,
            "trusted_writer_quiescence_and_filesystem_are_external_prerequisites": True,
        },
        "bounded_qualification": bounded,
        "external_artifacts": {
            "required": list(
                predecessor.child.production_inputs.REQUIRED_EXTERNAL_ARTIFACTS
            ),
            "installed_by_this_checkpoint": False,
            "runtime_fragment_artifacts_are_private_external_outputs": True,
        },
        "resource_estimate": {
            "bounded_topology": "one tree / four leaves / production widths / insecure test-only",
            "historical_production_rows": 589_030_555,
            "historical_minimum_memory_bytes": 16_000_000_000,
            "historical_minimum_free_disk_bytes": 64_000_000_000,
            "historical_estimated_seconds": [8_000, 12_000],
            "new_production_reservation_obtained": False,
        },
        "exact_commands": {
            "bounded_self_check": (
                "PYTHONPATH=src python -u "
                "src/pq_rbbc_issuance_fragment_producers_v1.py --self-check"
            ),
            "read_only_external_inventory": (
                "PYTHONPATH=src python -u "
                "src/pq_rbbc_issuance_fragment_producers_v1.py "
                "--artifact-root /ABSOLUTE/PRIVATE/ARTIFACT/ROOT"
            ),
            "targeted_tests": (
                "PYTHONPATH=src python -m unittest "
                "tests.test_pq_rbbc_issuance_fragment_producers_v1 -v"
            ),
            "production_execution": None,
            "large_replay": None,
            "large_proving": None,
        },
        "claim_status": {
            "Defined": True,
            "Instantiated": {"bounded_test_only": True, "production": False},
            "Implemented": {
                "bounded_independent_fragment_producers": True,
                "bounded_append_only_publisher": True,
                "bounded_exact_resume": True,
                "production_fragment_producers": False,
            },
            "Tested": {"bounded": True, "production": False},
            "Evidence-sealed": {"bounded_metadata": True, "production": False},
            "Proof-closed": False,
            "Production-closed": False,
            "formal_pi_issue_generated": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
        },
        "artifact_policy": {
            "private_runtime_state_tracked": False,
            "row_archive_created": False,
            "assignment_materialized": False,
            "assignment_br1cs_pickle_cache_checkpoint_resume_log_tracked": False,
            "historical_source_modified": False,
            "other_tree_observed_stream_bytes_used": False,
            "system_architecture_changed": False,
            "ticket_lifecycle_changed": False,
            "pq_sat_auth_changed": False,
        },
        "tracked_prerequisites": {
            name: {"path": path, "bytes": size, "sha256": digest}
            for name, (path, size, digest) in TRACKED_PREREQUISITES.items()
        },
        "tracked_validation_failures": list(validate_tracked_prerequisites()),
    }


def build_portable_evidence() -> dict[str, object]:
    manifest_path = (
        ROOT / "manifests/pq_rbbc_issuance_fragment_producers_manifest_v1.json"
    )
    manifest_identity = (
        {
            "filename": manifest_path.name,
            "bytes": manifest_path.stat().st_size,
            "sha256": _sha256_file(manifest_path),
        }
        if manifest_path.is_file()
        else _raw_identity(manifest_path.name, canonical_json(build_manifest()))
    )
    return {
        "format": EVIDENCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "production_relation_id": PRODUCTION_RELATION_ID,
        "bounded_relation_id": BOUNDED_RELATION_ID,
        "manifest": manifest_identity,
        "tracked_prerequisites_valid": not validate_tracked_prerequisites(),
        "bounded_qualification": bounded_self_check(),
        "private_runtime_state_embedded": False,
        "fragment_artifacts_embedded": False,
        "row_archive_embedded": False,
        "assignment_embedded": False,
        "absolute_paths_embedded": False,
        "production_execution_started": False,
        "large_replay_started": False,
        "large_proving_started": False,
        "formal_pi_issue_generated": False,
        "other_tree_observed_stream_bytes_used": False,
        "Proof-closed": False,
        "Production-closed": False,
    }


def external_inventory_preflight(artifact_root: Path) -> dict[str, object]:
    report = predecessor.external_inventory_preflight(artifact_root)
    return {
        "format": FORMAT,
        "production_relation_id": PRODUCTION_RELATION_ID,
        "predecessor_report": report,
        "tracked_prerequisites_valid": not validate_tracked_prerequisites(),
        "production_fragment_producers_implemented": False,
        "production_output_created": False,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-check", action="store_true")
    mode.add_argument("--print-manifest", action="store_true")
    mode.add_argument("--print-evidence", action="store_true")
    mode.add_argument("--artifact-root", type=Path)
    args = parser.parse_args()
    if args.self_check:
        document = bounded_self_check()
    elif args.print_manifest:
        document = build_manifest()
    elif args.print_evidence:
        document = build_portable_evidence()
    else:
        document = external_inventory_preflight(args.artifact_root)
    print(canonical_json(document).decode("ascii"), end="")


if __name__ == "__main__":
    main()
