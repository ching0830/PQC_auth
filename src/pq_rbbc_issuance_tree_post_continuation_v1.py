#!/usr/bin/env python3
"""Bounded independently invocable tree-post continuation checkpoint.

The production-shaped widths are preserved, but the only executable profile is
the two-tree, four-leaf, degree-three INSECURE-TEST-ONLY fixture.  A consumer
uses captured private-spool, point, two-receipt suffix, and continuation bytes.  It never
restores a Python generator or hashlib object and never reopens a pathname.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from functools import lru_cache
import hashlib
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_cap_global_tail as tail
import pq_rbbc_cap_shard_stream as shard
import pq_rbbc_cap_tree_producer as tree
import pq_rbbc_issuance_bounded_multitree_adapter_v1 as base
import pq_rbbc_issuance_private_spool_codec_v1 as codec
import pq_rbbc_issuance_private_spool_handoff_v1 as predecessor
import pq_rbbc_launch_io_v2_41 as io


ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION_VERSION = "1.1"
FORMAT = "PQRBBC-ISSUANCE-TREE-POST-CONTINUATION-1"
RECEIPT_FORMAT = "PQRBBC-ISSUANCE-TREE-POST-FRAGMENT-RECEIPT-1"
FRAGMENT_STREAM_FORMAT = "PQRBBC-F193-R1CS-TREE-POST-FRAGMENT-1"
RELATION_ID = (
    "pq-rbbc/issuance/tree-post-continuation/"
    "multitree-4plus4-insecure-test-only/v1"
)
CONTINUATION_NAMES = (
    "tree-0.post-continuation.private.json",
    "tree-1.post-continuation.private.json",
)
CONTINUATION_LIMIT = 16_384
RECEIPT_LIMIT = 16_384
PRIOR_RECEIPT_NAME = "tree-pre-1.private-receipt.json"
RECEIPT_SUFFIX_NAMES = (PRIOR_RECEIPT_NAME, predecessor.RECEIPT_NAME)
DOMAIN_COMPOSITION = b"PQ-RBBC/ISSUANCE/TREE-POST-COMPOSITION/V1"
DOMAIN_ASSIGNMENT = b"PQ-RBBC/ISSUANCE/TREE-POST-PRIVATE-ASSIGNMENT/V1"
PLAN_SHA256 = base.FROZEN["plan_sha256"]
PROFILE_FINGERPRINT = codec.PROFILE
POINT_STARTS = (22_705, 22_898)
TREE_CONTRACTS = (
    {"pre": (43_837, 80_699), "post": (80_699, 83_111), "output": (81_953, 1_158)},
    {"pre": (83_111, 119_973), "post": (119_973, 122_385), "output": (121_227, 1_158)},
)
GLOBAL_A_CURSORS = {
    "anchors": 123_799,
    "tail": 23_094,
    "tree[0]": 80_699,
    "tree[1]": 119_973,
}
TREE_PRE_1_CURSORS = {
    "anchors": 123_799,
    "tail": 10_915,
    "tree[0]": 80_699,
    "tree[1]": 119_973,
}
PRE_GROUPS = (
    "producer-inputs",
    "tree-pre-ggm-derive",
    "tree-pre-leaf-commit-and-tape",
    "tree-pre-output-ports",
)
POST_GROUPS = ("tree-post-horner", "tree-post-output-port")
EXPECTED_PRE_GROUP_DOCUMENTS = (
    (
        {"name": "producer-inputs", "rows": 772, "bytes": 145_468,
         "sha256": "405961e321dcc1c8cc08d23344904c1772bd5c092f0d0ba44b071e50b19cae35"},
        {"name": "tree-pre-ggm-derive", "rows": 6_296, "bytes": 1_826_014,
         "sha256": "bfe458c7f1ebd1bbe3070269504095dec67b29c52ca22ccabb88496d27c19d33"},
        {"name": "tree-pre-leaf-commit-and-tape", "rows": 34_296, "bytes": 11_003_840,
         "sha256": "1897e8d38797e227e4d3385428e28193adcb84137eaed55a9706c64c93c5f35c"},
        {"name": "tree-pre-output-ports", "rows": 7_956, "bytes": 1_821_040,
         "sha256": "42333207bb25fde5397a5eabd754be0a88d849fc02b6e4093366a6c945487214"},
    ),
    (
        {"name": "producer-inputs", "rows": 772, "bytes": 145_468,
         "sha256": "ec62ae10c0837c0e65632b08a496615cf260cc94a8c6d7499466a8e2794609ec"},
        {"name": "tree-pre-ggm-derive", "rows": 6_296, "bytes": 1_826_014,
         "sha256": "18b16766799103f7138d29a4dd7ee8e820352342547399991623ef0de841447a"},
        {"name": "tree-pre-leaf-commit-and-tape", "rows": 34_296, "bytes": 11_003_840,
         "sha256": "33a9bea832c7252d836cd5e0c1d607d716fba2a3fa35378882555b046fc40d2e"},
        {"name": "tree-pre-output-ports", "rows": 7_956, "bytes": 1_821_040,
         "sha256": "05507815a7acf5279d2d66b576016d838cdf8cd3a5c7378192fdbf29c9ffde4a"},
    ),
)
EXPECTED_POST_GROUP_DOCUMENTS = (
    (
        {"name": "tree-post-horner", "rows": 1_260, "bytes": 1_412_154,
         "sha256": "0cd4964fe8ed21d97d461aea5f54aeed20ce6f5c96a96da8af56d4e494e8ae25"},
        {"name": "tree-post-output-port", "rows": 2_316, "bytes": 554_778,
         "sha256": "eac21f3081195333354235dfb859e87d42e11e4bcea27ba30adb19b8558c2316"},
    ),
    (
        {"name": "tree-post-horner", "rows": 1_260, "bytes": 1_412_154,
         "sha256": "659c8e4e65143494e731e4bd6e2c1dac6b12c86362b0b3e39be91636a241ea99"},
        {"name": "tree-post-output-port", "rows": 2_316, "bytes": 554_778,
         "sha256": "35d4108c1423b59b962c44336cd9788cb20cc6cedaca4af64ba8e156e57b44e8"},
    ),
)
PRE_RELOCATIONS = (
    "tree[0].leaf-commitments",
    "tree[0].p-plain",
    "tree[0].mhat-plain",
    "tree[1].leaf-commitments",
    "tree[1].p-plain",
    "tree[1].mhat-plain",
)
SERIALIZED_STATE = (
    "tree_index",
    "absolute_pre_and_post_intervals",
    "owner_cursor",
    "ordered_pre_group_identities",
    "native_prefix_commitment",
    "verified_two_entry_receipt_suffix_identities",
    "private_spool_snapshot_identity",
    "global_a_point_snapshot_identity",
    "ordinal_2_receipt_identity",
    "ordinal_3_global_a_receipt_identity",
    "selected_pre_wire_values",
    "point_wire_values",
    "tree_post_output_port_layout",
)
NOT_SERIALIZED_STATE = (
    "python_generator_frame",
    "allocator_mutable_object",
    "full_assignment",
    "tree_sink_hash_internal_state",
    "tail_generator_frame",
    "tail_sink_hash_internal_state",
    "native_binding_hash_internal_state",
    "global_tail_continuation_state",
)
MANIFEST_PATH = "manifests/pq_rbbc_issuance_tree_post_continuation_manifest_v1.json"
EVIDENCE_PATH = (
    "artifacts/metadata/issuance_tree_post_continuation_v1/"
    "pq_rbbc_issuance_tree_post_continuation_portable_evidence_v1.json"
)
PREDECESSOR_PINS = {
    "src/pq_rbbc_issuance_private_spool_codec_v1.py": (
        8_958,
        "5f3ae559554de28a6dc28175dbb45116a62e08afcc331fc3cc76def8592459ea",
    ),
    "src/pq_rbbc_issuance_private_spool_native_v1.py": (
        23_455,
        "92377d4a694f51d9c8b1a424e4185aa1a5ac3a352de17c40ff2700a2f479d8fe",
    ),
    "src/pq_rbbc_issuance_private_spool_handoff_v1.py": (
        19_843,
        "fad685ff01b026d0f82140a29843f54fb93b0cb5092643e61aa99891e0e73d98",
    ),
    "tests/test_pq_rbbc_issuance_private_spool_handoff_v1.py": (
        16_661,
        "b65a22e9887ea826c3dc988b5a9f3e8fdbe202ef0d7ea28581eb69a9b1366979",
    ),
    predecessor.MANIFEST_PATH: (
        8_521,
        "10ed0e3b1fe25855d44cbfbde6ae125506afcee3c33a2741d34ad88690b196a8",
    ),
    predecessor.EVIDENCE_PATH: (
        3_497,
        "da285f2958687d8b93381eacf5e80d5e4cbc16407564c9371f08dfa17572e802",
    ),
}


FROZEN: dict[str, object] = {
    "verified_receipt_suffix_identities": [
        {
            "bytes": 1_306,
            "filename": PRIOR_RECEIPT_NAME,
            "sha256": "29a0768e66e15ec989a0b44c98c500688618ec96683b7a171725670d6e14c523",
        },
        {
            "bytes": 1_365,
            "filename": predecessor.RECEIPT_NAME,
            "sha256": "0573e1b7fb340fcffce9d6cc6f90b3e2c4c2e43e00b6faa59ad528d0f0f427dc",
        },
    ],
    "full_receipt_chain_verified": False,
    "continuation_identities": [
        {
            "bytes": 3_829,
            "filename": CONTINUATION_NAMES[0],
            "sha256": "d68382b393f66e6fcd1374985aa2f70d9d39c7a092756ac9bd954810bbba2bc9",
        },
        {
            "bytes": 3_835,
            "filename": CONTINUATION_NAMES[1],
            "sha256": "d2f6bcaad813ae59ebd200512d37fbaae8afcdc604b534009f8d84949c6bdc72",
        },
    ],
    "tree_post_receipt_identities": [
        {
            "bytes": 2_821,
            "filename": "tree-0.post-receipt.private.json",
            "sha256": "1097dee376f9e3a338362e6b74168f3e1e7ac8f772df13408fe0da785b45203c",
        },
        {
            "bytes": 2_824,
            "filename": "tree-1.post-receipt.private.json",
            "sha256": "99fd35afa855c184c4dfe482067bb8e77f921cab8a84673ad1b7650ef380a970",
        },
    ],
    "tree_post_rows": [3_576, 3_576],
    "tree_post_allocated_wires": [2_412, 2_412],
    "tree_post_fragment_stream_sha256": [
        "c650222f753db29f782effef037d47872c218c3871355b676b722130b501f54e",
        "a5797cb75ccb3072f29c7fe1b6e2c9ea619183524600e6c3d5647cc5837a1347",
    ],
    "tree_post_row_semantics_sha256": [
        "710f3c3b6d46789a6fe45096feed24ad7fca92f7127386b33787c704ea74a6fd",
        "9b822898e4bc5945e3e9b83b4364bac1baa354d06542f1e8635751c384505457",
    ],
    "total_standalone_rows_checked": 7_152,
}


class ContinuationError(ValueError):
    """A continuation, dependency, wire import, or fragment row is invalid."""


class ProductionUnavailable(RuntimeError):
    """This checkpoint intentionally has no production entry point."""


def canonical_json(document: object) -> bytes:
    return io.canonical_json(document)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _is_int(value: object) -> bool:
    return type(value) is int


def _exact(document: object, fields: set[str], label: str) -> dict[str, object]:
    if type(document) is not dict or set(document) != fields:
        raise ContinuationError(f"{label} fields are not closed-world canonical")
    return document


def _digest(value: object, label: str) -> str:
    try:
        codec.hex_digest(value)
    except (TypeError, ValueError, codec.SpoolError) as error:
        raise ContinuationError(f"{label} is not canonical SHA-256") from error
    return str(value)


def _snapshot_identity(
    snapshot: io.Snapshot, *, filename: str, limit: int, label: str
) -> dict[str, object]:
    if (
        type(snapshot) is not io.Snapshot
        or snapshot.location.name != filename
        or not 0 < len(snapshot.raw) <= limit
    ):
        raise ContinuationError(f"{label} snapshot filename or bound mismatch")
    return snapshot.identity


def _identity_document(value: object, *, filename: str, bytes_: int | None = None) -> dict[str, object]:
    document = _exact(value, {"filename", "bytes", "sha256"}, "snapshot identity")
    if (
        document["filename"] != filename
        or not _is_int(document["bytes"])
        or int(document["bytes"]) <= 0
        or (bytes_ is not None and document["bytes"] != bytes_)
    ):
        raise ContinuationError("snapshot identity name or byte length mismatch")
    _digest(document["sha256"], "snapshot identity")
    return document


def _group_document(group: tail.BinaryStreamGroup) -> dict[str, object]:
    return {
        "name": group.name,
        "rows": group.rows,
        "bytes": group.bytes,
        "sha256": group.sha256,
    }


def _validate_groups(value: object, expected_names: Sequence[str], label: str) -> tuple[dict[str, object], ...]:
    if type(value) is not list or len(value) != len(expected_names):
        raise ContinuationError(f"{label} group count mismatch")
    result: list[dict[str, object]] = []
    for index, (item, expected_name) in enumerate(zip(value, expected_names)):
        group = _exact(item, {"name", "rows", "bytes", "sha256"}, f"{label}[{index}]")
        if (
            group["name"] != expected_name
            or not _is_int(group["rows"])
            or int(group["rows"]) <= 0
            or not _is_int(group["bytes"])
            or int(group["bytes"]) <= 0
        ):
            raise ContinuationError(f"{label}[{index}] shape mismatch")
        _digest(group["sha256"], f"{label}[{index}]")
        result.append(group)
    return tuple(result)


def validate_prerequisites() -> None:
    predecessor.validate_prerequisites()
    for path, expected in PREDECESSOR_PINS.items():
        snapshot = io.read_snapshot(ROOT / path)
        if (len(snapshot.raw), sha256(snapshot.raw)) != expected:
            raise ContinuationError("predecessor identity drift: " + path)


def _points_document(snapshot: io.Snapshot, handoff: Mapping[str, object]) -> dict[str, object]:
    _snapshot_identity(
        snapshot, filename=predecessor.POINT_NAME, limit=predecessor.POINT_LIMIT, label="points"
    )
    try:
        document = snapshot.document()
    except io.ValidationError as error:
        raise ContinuationError("points are not strict canonical JSON") from error
    current = _exact(
        document,
        {
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
        },
        "point snapshot",
    )
    values = current["values"]
    if (
        current["format"] != base.FORMAT + "-POINT-PORT"
        or current["relation_id"] != base.RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["invocation_sha256"] != handoff["invocation_sha256"]
        or current["plan_sha256"] != PLAN_SHA256
        or current["producer"] != "global-a"
        or current["consumers"] != ["tree-post[0]", "tree-post[1]", "global-b"]
        or current["wire_starts"] != list(POINT_STARTS)
        or current["field_bits"] != field.FIELD_DEGREE
        or type(values) is not list
        or len(values) != 2
        or any(not _is_int(item) or not 0 < item <= field.FIELD_MASK for item in values)
        or values[0] == values[1]
    ):
        raise ContinuationError("point snapshot domain, layout, or values mismatch")
    if canonical_json(current) != snapshot.raw:
        raise ContinuationError("point snapshot is not canonical")
    return current


_BASE_RECEIPT_FIELDS = {
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
}


def _receipt_document(
    snapshot: io.Snapshot,
    handoff: Mapping[str, object],
    *,
    ordinal: int,
) -> dict[str, object]:
    if ordinal == 2:
        filename = PRIOR_RECEIPT_NAME
        stage_id = "tree-pre[1]"
        rows = 54_070
        total_rows = 121_110
        cursors = TREE_PRE_1_CURSORS
        point_snapshot_sha256 = None
        label = "ordinal-2 tree-pre receipt"
    elif ordinal == 3:
        filename = predecessor.RECEIPT_NAME
        stage_id = "global-a"
        rows = 19_671
        total_rows = 140_781
        cursors = GLOBAL_A_CURSORS
        point_snapshot_sha256 = handoff["points"]["sha256"]
        label = "ordinal-3 global-A receipt"
    else:  # pragma: no cover - private caller invariant
        raise ContinuationError("receipt suffix ordinal must be 2 or 3")
    _snapshot_identity(
        snapshot,
        filename=filename,
        limit=predecessor.RECEIPT_LIMIT,
        label=label,
    )
    try:
        document = snapshot.document()
    except io.ValidationError as error:
        raise ContinuationError(label + " is not strict canonical JSON") from error
    current = _exact(document, _BASE_RECEIPT_FIELDS, label)
    prefixes = current["native_prefix_identities"]
    if type(prefixes) is not dict or set(prefixes) != set(cursors):
        raise ContinuationError(label + " native prefix inventory mismatch")
    for name, value in prefixes.items():
        _digest(value, label + " prefix " + name)
    _digest(current["previous_receipt_sha256"], label + " previous receipt")
    _digest(current["native_binding_rows_sha256"], label + " binding rows")
    if (
        current["format"] != base.FORMAT + "-RECEIPT"
        or current["relation_id"] != base.RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["plan_sha256"] != PLAN_SHA256
        or current["invocation_sha256"] != handoff["invocation_sha256"]
        or current["ordinal"] != ordinal
        or current["stage_id"] != stage_id
        or current["rows"] != rows
        or current["total_rows"] != total_rows
        or current["owner_cursors"] != cursors
        or current["relocation_ports"] != list(PRE_RELOCATIONS)
        or current["point_snapshot_sha256"] != point_snapshot_sha256
        or current["production"] is not False
        or current["durable_resume"] is not False
        or canonical_json(current) != snapshot.raw
    ):
        raise ContinuationError(label + " binding or stage mismatch")
    return current


def _verified_receipt_suffix_documents(
    snapshots: tuple[io.Snapshot, io.Snapshot],
    handoff: Mapping[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    if type(snapshots) is not tuple or len(snapshots) != 2:
        raise ContinuationError("exact ordinal 2-to-3 receipt snapshot suffix required")
    ordinal_2 = _receipt_document(snapshots[0], handoff, ordinal=2)
    ordinal_3 = _receipt_document(snapshots[1], handoff, ordinal=3)
    if ordinal_3["previous_receipt_sha256"] != sha256(snapshots[0].raw):
        raise ContinuationError("ordinal-3 receipt does not link to captured ordinal-2 raw")
    return ordinal_2, ordinal_3


@dataclass(frozen=True)
class TreePostInvocationInsecureTestOnly:
    candidates: predecessor.CandidateSet
    continuation: io.Snapshot
    receipt_suffix: tuple[io.Snapshot, io.Snapshot]

    def __post_init__(self) -> None:
        if (
            type(self.candidates) is not predecessor.CandidateSet
            or type(self.continuation) is not io.Snapshot
            or type(self.receipt_suffix) is not tuple
            or len(self.receipt_suffix) != 2
            or any(type(snapshot) is not io.Snapshot for snapshot in self.receipt_suffix)
            or self.receipt_suffix[1] is not self.candidates.receipt
        ):
            raise ContinuationError("immutable candidate set and continuation snapshot required")


@dataclass(frozen=True)
class DecodedContinuationInsecureTestOnly:
    document: Mapping[str, object]
    handoff: Mapping[str, object]
    points: Mapping[str, object]
    ordinal_2_receipt: Mapping[str, object]
    global_a_receipt: Mapping[str, object]
    spool: codec.TreeSpoolSnapshotInsecureTestOnly


@dataclass(frozen=True)
class TreePostResultInsecureTestOnly:
    tree_index: int
    summary: Mapping[str, object]
    output_port: tree.ProducerPort
    owned_values: tuple[int, ...]
    receipt: io.Snapshot


def _continuation_document(
    invocation: TreePostInvocationInsecureTestOnly,
    *,
    expected_handoff_sha256: str,
    expected_continuation_sha256: str,
) -> DecodedContinuationInsecureTestOnly:
    _digest(expected_continuation_sha256, "external continuation digest")
    snapshot = invocation.continuation
    if sha256(snapshot.raw) != expected_continuation_sha256:
        raise ContinuationError("external continuation digest rejected before parsing")
    try:
        handoff = predecessor._handoff_document(
            invocation.candidates.handoff, expected_handoff_sha256
        )
    except (codec.SpoolError, io.ValidationError) as error:
        raise ContinuationError("private handoff rejected") from error
    try:
        predecessor._check_identity(
            invocation.candidates.points,
            handoff["points"],
            predecessor.POINT_NAME,
            predecessor.POINT_LIMIT,
        )
        predecessor._check_identity(
            invocation.candidates.receipt,
            handoff["receipt"],
            predecessor.RECEIPT_NAME,
            predecessor.RECEIPT_LIMIT,
        )
    except codec.SpoolError as error:
        raise ContinuationError("handoff dependency identity rejected") from error
    ordinal_2_receipt, global_a_receipt = _verified_receipt_suffix_documents(
        invocation.receipt_suffix, handoff
    )
    try:
        document = snapshot.document()
    except io.ValidationError as error:
        raise ContinuationError("continuation is not strict canonical JSON") from error
    fields = {
        "format",
        "implementation_version",
        "mode",
        "relation_id",
        "predecessor_relation_id",
        "profile_fingerprint",
        "plan_sha256",
        "invocation_sha256",
        "tree_index",
        "producer_stage",
        "ready_after_stage",
        "consumer_stage",
        "pre_interval",
        "post_interval",
        "owner_cursor",
        "native_prefix_rows",
        "native_prefix_bytes",
        "native_prefix_sha256",
        "pre_groups",
        "verified_receipt_suffix",
        "dependencies",
        "import_contract",
        "output_contract",
        "composition_boundary",
        "state_inventory",
        "private_values_embedded",
        "production",
        "durable_resume",
    }
    current = _exact(document, fields, "tree-post continuation")
    index = current["tree_index"]
    if not _is_int(index) or index not in (0, 1):
        raise ContinuationError("continuation tree index mismatch")
    index = int(index)
    contract = TREE_CONTRACTS[index]
    if snapshot.location.name != CONTINUATION_NAMES[index] or len(snapshot.raw) > CONTINUATION_LIMIT:
        raise ContinuationError("continuation filename or byte bound mismatch")
    groups = _validate_groups(current["pre_groups"], PRE_GROUPS, "pre groups")
    suffix = current["verified_receipt_suffix"]
    if type(suffix) is not list or len(suffix) != 2:
        raise ContinuationError("exact ordinal 2-to-3 receipt suffix required")
    dependencies = _exact(
        current["dependencies"],
        {"handoff", "private_spool", "points", "ordinal_2_receipt", "global_a_receipt"},
        "continuation dependencies",
    )
    expected_dependencies = {
        "handoff": invocation.candidates.handoff.identity,
        "private_spool": invocation.candidates.spools[index].identity,
        "points": invocation.candidates.points.identity,
        "ordinal_2_receipt": invocation.receipt_suffix[0].identity,
        "global_a_receipt": invocation.candidates.receipt.identity,
    }
    for name, expected in expected_dependencies.items():
        actual = _identity_document(
            dependencies[name], filename=expected["filename"], bytes_=expected["bytes"]
        )
        if actual != expected:
            raise ContinuationError("continuation dependency identity mismatch: " + name)
    for suffix_index, expected in enumerate(
        (invocation.receipt_suffix[0].identity, invocation.receipt_suffix[1].identity)
    ):
        actual = _identity_document(
            suffix[suffix_index], filename=expected["filename"], bytes_=expected["bytes"]
        )
        if actual != expected:
            raise ContinuationError("verified receipt suffix identity mismatch")
    import_contract = _exact(
        current["import_contract"],
        {
            "selected_spool_wire_count",
            "point_wire_count",
            "point_wire_starts",
            "allowed_sources",
            "all_other_pre_wires_forbidden",
        },
        "import contract",
    )
    output_contract = _exact(
        current["output_contract"],
        {"port_id", "wire_start", "bit_length", "end_exclusive"},
        "output contract",
    )
    composition = _exact(
        current["composition_boundary"],
        {
            "verification",
            "prefix_digest_is_commitment_not_restorable_hash_state",
            "legacy_stream_hash_continuation_supported",
            "tree_pre_replay_permitted",
        },
        "composition boundary",
    )
    inventory = _exact(
        current["state_inventory"], {"serialized", "not_serialized"}, "state inventory"
    )
    expected_output = contract["output"]
    owner = f"tree[{index}]"
    if (
        current["format"] != FORMAT
        or current["implementation_version"] != IMPLEMENTATION_VERSION
        or current["mode"] != "INSECURE-TEST-ONLY"
        or current["relation_id"] != RELATION_ID
        or current["predecessor_relation_id"] != predecessor.RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["plan_sha256"] != PLAN_SHA256
        or current["invocation_sha256"] != handoff["invocation_sha256"]
        or current["producer_stage"] != f"tree-pre[{index}]"
        or current["ready_after_stage"] != "global-a"
        or current["consumer_stage"] != f"tree-post[{index}]"
        or current["pre_interval"] != list(contract["pre"])
        or current["post_interval"] != list(contract["post"])
        or current["owner_cursor"] != contract["pre"][1]
        or current["native_prefix_rows"] != 49_320
        or not _is_int(current["native_prefix_bytes"])
        or int(current["native_prefix_bytes"]) <= 0
        or current["native_prefix_sha256"] != (
            global_a_receipt["native_prefix_identities"][owner]
        )
        or groups != EXPECTED_PRE_GROUP_DOCUMENTS[index]
        or import_contract
        != {
            "selected_spool_wire_count": codec.LEAVES * codec.RECORD_WIRES,
            "point_wire_count": 2 * field.FIELD_DEGREE,
            "point_wire_starts": list(POINT_STARTS),
            "allowed_sources": ["private-spool", "global-a-points", "tree-post-owned"],
            "all_other_pre_wires_forbidden": True,
        }
        or output_contract
        != {
            "port_id": f"tree[{index}].xi-masks",
            "wire_start": expected_output[0],
            "bit_length": expected_output[1],
            "end_exclusive": expected_output[0] + expected_output[1],
        }
        or composition
        != {
            "verification": "ordered-group-identities+absolute-wire-interval+verified-receipt-suffix-2-to-3",
            "prefix_digest_is_commitment_not_restorable_hash_state": True,
            "legacy_stream_hash_continuation_supported": False,
            "tree_pre_replay_permitted": False,
        }
        or inventory != {"serialized": list(SERIALIZED_STATE), "not_serialized": list(NOT_SERIALIZED_STATE)}
        or current["private_values_embedded"] is not False
        or current["production"] is not False
        or current["durable_resume"] is not False
        or canonical_json(current) != snapshot.raw
    ):
        raise ContinuationError("continuation domain, cursor, dependency, or claim mismatch")
    points = _points_document(invocation.candidates.points, handoff)
    spool_identity = handoff["spools"][index]
    try:
        predecessor._check_identity(
            invocation.candidates.spools[index],
            spool_identity,
            predecessor.SPOOL_NAMES[index],
            codec.SPOOL_BYTES,
        )
        spool = codec.decode_snapshot_insecure_test_only(
            invocation.candidates.spools[index],
            expected_bytes=spool_identity["bytes"],
            expected_sha256=spool_identity["sha256"],
            context=codec.Context(
                index,
                contract["pre"][0],
                contract["pre"][1],
                PLAN_SHA256,
                str(handoff["invocation_sha256"]),
            ),
        )
    except codec.SpoolError as error:
        raise ContinuationError("private spool rejected") from error
    return DecodedContinuationInsecureTestOnly(
        MappingProxyType(dict(current)),
        MappingProxyType(dict(handoff)),
        MappingProxyType(dict(points)),
        MappingProxyType(dict(ordinal_2_receipt)),
        MappingProxyType(dict(global_a_receipt)),
        spool,
    )


def build_verified_receipt_suffix_snapshots(
    session: predecessor.HandoffSessionInsecureTestOnly,
) -> tuple[io.Snapshot, io.Snapshot]:
    """Capture exactly the receipt raws this checkpoint can verify (ordinals 2 and 3)."""
    if (
        not isinstance(session, predecessor.HandoffSessionInsecureTestOnly)
        or session.closed
        or session.failed
        or session.position != 4
        or session.accepted_handoff is None
        or len(session.receipts) != 4
    ):
        raise ContinuationError("receipt suffix requires accepted exact global-A live prefix")
    ordinal_2 = io.Snapshot(
        Path("/in-memory-insecure-test-only") / PRIOR_RECEIPT_NAME,
        session.receipts[2],
    )
    ordinal_3 = session.accepted_handoff.candidates.receipt
    handoff = session.accepted_handoff.candidates.handoff.document()
    _verified_receipt_suffix_documents((ordinal_2, ordinal_3), handoff)
    return ordinal_2, ordinal_3


def build_continuation_snapshots(
    session: predecessor.HandoffSessionInsecureTestOnly,
) -> tuple[io.Snapshot, io.Snapshot]:
    """Export two metadata continuations after the live producer verified spools.

    This authoring helper needs the old live session.  The consumer below does
    not.  The resulting bytes contain identities and state inventory, not the
    private spool or a restorable generator/hash object.
    """
    if (
        not isinstance(session, predecessor.HandoffSessionInsecureTestOnly)
        or session.closed
        or session.failed
        or session.position != 4
        or session.accepted_handoff is None
    ):
        raise ContinuationError("continuation requires accepted exact global-A live prefix")
    candidates = session.accepted_handoff.candidates
    receipt_suffix = build_verified_receipt_suffix_snapshots(session)
    _, receipt = _verified_receipt_suffix_documents(
        receipt_suffix, candidates.handoff.document()
    )
    snapshots: list[io.Snapshot] = []
    for index, contract in enumerate(TREE_CONTRACTS):
        owner = f"tree[{index}]"
        sink = session.sinks[owner]
        reader = session.accepted_handoff.readers[index]
        reader.assert_values(session.values)
        groups = [_group_document(item) for item in sink.groups]
        if tuple(item["name"] for item in groups) != PRE_GROUPS:
            raise ContinuationError("live pre group boundary changed")
        document = {
            "format": FORMAT,
            "implementation_version": IMPLEMENTATION_VERSION,
            "mode": "INSECURE-TEST-ONLY",
            "relation_id": RELATION_ID,
            "predecessor_relation_id": predecessor.RELATION_ID,
            "profile_fingerprint": PROFILE_FINGERPRINT,
            "plan_sha256": PLAN_SHA256,
            "invocation_sha256": session.reference.invocation_digest,
            "tree_index": index,
            "producer_stage": f"tree-pre[{index}]",
            "ready_after_stage": "global-a",
            "consumer_stage": f"tree-post[{index}]",
            "pre_interval": list(contract["pre"]),
            "post_interval": list(contract["post"]),
            "owner_cursor": session.allocator.cursors[owner],
            "native_prefix_rows": sink.rows,
            "native_prefix_bytes": sink.bytes,
            "native_prefix_sha256": sink._digest.copy().hexdigest(),
            "pre_groups": groups,
            "verified_receipt_suffix": [item.identity for item in receipt_suffix],
            "dependencies": {
                "handoff": candidates.handoff.identity,
                "private_spool": candidates.spools[index].identity,
                "points": candidates.points.identity,
                "ordinal_2_receipt": receipt_suffix[0].identity,
                "global_a_receipt": candidates.receipt.identity,
            },
            "import_contract": {
                "selected_spool_wire_count": codec.LEAVES * codec.RECORD_WIRES,
                "point_wire_count": 2 * field.FIELD_DEGREE,
                "point_wire_starts": list(POINT_STARTS),
                "allowed_sources": ["private-spool", "global-a-points", "tree-post-owned"],
                "all_other_pre_wires_forbidden": True,
            },
            "output_contract": {
                "port_id": f"tree[{index}].xi-masks",
                "wire_start": contract["output"][0],
                "bit_length": contract["output"][1],
                "end_exclusive": contract["output"][0] + contract["output"][1],
            },
            "composition_boundary": {
                "verification": "ordered-group-identities+absolute-wire-interval+verified-receipt-suffix-2-to-3",
                "prefix_digest_is_commitment_not_restorable_hash_state": True,
                "legacy_stream_hash_continuation_supported": False,
                "tree_pre_replay_permitted": False,
            },
            "state_inventory": {
                "serialized": list(SERIALIZED_STATE),
                "not_serialized": list(NOT_SERIALIZED_STATE),
            },
            "private_values_embedded": False,
            "production": False,
            "durable_resume": False,
        }
        if receipt["native_prefix_identities"][owner] != document["native_prefix_sha256"]:
            raise ContinuationError("live native prefix differs from global-A receipt")
        snapshots.append(
            io.Snapshot(
                Path("/in-memory-insecure-test-only") / CONTINUATION_NAMES[index],
                canonical_json(document),
            )
        )
    return tuple(snapshots)  # type: ignore[return-value]


def capture_tree_post_invocation(
    root: Path,
    tree_index: int,
    *,
    expected_handoff_sha256: str,
    expected_continuation_sha256: str,
) -> TreePostInvocationInsecureTestOnly:
    """Single-capture fixed names; execution consumes only returned snapshots."""
    if not _is_int(tree_index) or tree_index not in (0, 1):
        raise ContinuationError("bounded tree index must be 0 or 1")
    _digest(expected_continuation_sha256, "external continuation digest")
    root = io.exact_path(root)
    continuation = io.read_snapshot(
        root / CONTINUATION_NAMES[tree_index], external=True
    )
    if sha256(continuation.raw) != expected_continuation_sha256:
        raise ContinuationError("external continuation digest rejected before dependency reads")
    candidates = predecessor.capture_candidates(
        root, expected_handoff_sha256=expected_handoff_sha256
    )
    ordinal_2_receipt = io.read_snapshot(root / PRIOR_RECEIPT_NAME, external=True)
    invocation = TreePostInvocationInsecureTestOnly(
        candidates,
        continuation,
        (ordinal_2_receipt, candidates.receipt),
    )
    _continuation_document(
        invocation,
        expected_handoff_sha256=expected_handoff_sha256,
        expected_continuation_sha256=expected_continuation_sha256,
    )
    return invocation


class _PostSink(tail.BinaryRowSink):
    """Fresh fragment sink with exact absolute cursor and declared imports."""

    def __init__(
        self,
        tree_index: int,
        post_interval: tuple[int, int],
        values: dict[int, int],
        imported_wires: frozenset[int],
    ) -> None:
        self.tree_index = tree_index
        self.post_interval = post_interval
        self.values = values
        self.imported_wires = imported_wires
        self.referenced_imports: set[int] = set()
        self.row_semantics = hashlib.sha256(DOMAIN_COMPOSITION + b"ROWS")
        super().__init__(
            {
                "format": FRAGMENT_STREAM_FORMAT,
                "relation_id": RELATION_ID,
                "profile_fingerprint": PROFILE_FINGERPRINT,
                "tree_index": tree_index,
                "stage_id": f"tree-post[{tree_index}]",
                "post_interval": list(post_interval),
            },
            initial_wire=post_interval[0],
            assignment_writer=base._Writer(values, post_interval[0]),
        )

    def allocate(self, count: int = 1, **kwargs: object) -> int:
        if self.next_wire + count > self.post_interval[1]:
            raise ContinuationError("tree-post allocation exceeds reserved interval")
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
                elif not self.post_interval[0] <= wire < self.next_wire:
                    raise ContinuationError("tree-post row used undeclared or future wire")
                if wire not in self.values:
                    raise ContinuationError("tree-post row used wire without captured value")
        if not shard._row_satisfied_fast(row, self.values):
            raise ContinuationError("tree-post native row failed: " + label)
        record = canonical_json(
            {"label": label, "left": left.canonical_dict(), "right": right.canonical_dict(),
             "output": output.canonical_dict(), "nonlinear": nonlinear}
        )
        self.row_semantics.update(len(record).to_bytes(8, "little"))
        self.row_semantics.update(record)
        super().row(label, left, right, output, nonlinear=nonlinear)


def _import_values(
    decoded: DecodedContinuationInsecureTestOnly,
) -> tuple[dict[int, int], frozenset[int]]:
    values: dict[int, int] = {}
    spool = decoded.spool
    for leaf in range(codec.LEAVES):
        selected = spool.selected_value(leaf)
        for coordinate, wire in enumerate(spool.record(leaf)):
            if wire in values:
                raise ContinuationError("private spool import aliases a wire")
            values[wire] = (selected >> coordinate) & 1
    point_values = decoded.points["values"]
    for start, point in zip(POINT_STARTS, point_values):
        for bit in range(field.FIELD_DEGREE):
            wire = start + bit
            if wire in values:
                raise ContinuationError("point import aliases private spool wire")
            values[wire] = (int(point) >> bit) & 1
    return values, frozenset(values)


def _private_assignment_digest(values: Sequence[int]) -> str:
    digest = hashlib.sha256(DOMAIN_ASSIGNMENT)
    for value in values:
        digest.update(int(value).to_bytes(field.FIELD_ELEMENT_BYTES, "little"))
    return digest.hexdigest()


def execute_tree_post_insecure_test_only(
    invocation: TreePostInvocationInsecureTestOnly,
    *,
    expected_handoff_sha256: str,
    expected_continuation_sha256: str,
) -> TreePostResultInsecureTestOnly:
    """Execute one tree-post from immutable snapshots, without a live session."""
    decoded = _continuation_document(
        invocation,
        expected_handoff_sha256=expected_handoff_sha256,
        expected_continuation_sha256=expected_continuation_sha256,
    )
    index = int(decoded.document["tree_index"])
    contract = TREE_CONTRACTS[index]
    values, imported = _import_values(decoded)
    sink = _PostSink(index, contract["post"], values, imported)
    parameters = base.PARAMETERS
    spool = decoded.spool
    point_values = tuple(int(item) for item in decoded.points["values"])
    extension_degree = parameters.expanded_extension_degrees()[index]
    selected_by_extension = tuple(
        tuple(
            leaf_index - 1
            for leaf_index in range(1, codec.LEAVES + 1)
            if (tree.cap.gf2m_inv(leaf_index, extension_degree) >> extension_bit) & 1
        )
        for extension_bit in range(extension_degree)
    )
    sink.start_group("tree-post-horner")
    mask_accumulators: list[list[int | None]] = [
        [None] * parameters.consistency_points for _ in range(extension_degree)
    ]
    mask_values: list[list[int | None]] = [
        [None] * parameters.consistency_points for _ in range(extension_degree)
    ]
    multiplication_rows = 0
    aggregate_rows = 0
    for leaf in range(codec.LEAVES):
        witness_ids = spool.record(leaf)[: parameters.witness_bits]
        outputs, output_values = shard._horner_leaf(
            sink,
            witness_ids,
            spool.tape_values[leaf],
            POINT_STARTS,
            point_values,
            leaf + 1,
        )
        coefficient_count = (
            len(witness_ids) + field.FIELD_DEGREE - 1
        ) // field.FIELD_DEGREE
        multiplication_rows += len(outputs) * (coefficient_count - 1)
        inverse = tree.cap.gf2m_inv(leaf + 1, extension_degree)
        for point_index, (item, item_value) in enumerate(zip(outputs, output_values)):
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
                        (
                            f"tree[{index}].aggregate.mask[{extension_bit}]"
                            f".leaf[{leaf + 1}].point[{point_index}]"
                        ),
                    )
                    aggregate_rows += 1
    if any(item is None for row in mask_accumulators + mask_values for item in row):
        raise ContinuationError("tree-post mask accumulator is incomplete")
    mask_output_starts = tuple(
        tuple(
            shard._decompose_field(
                sink,
                int(mask_accumulators[extension_bit][point]),
                int(mask_values[extension_bit][point]),
                f"tree[{index}].consistency.mask[{extension_bit}].point[{point}].output",
            )
            for point in range(parameters.consistency_points)
        )
        for extension_bit in range(extension_degree)
    )
    sink.finish_group()

    tail_offset = parameters.witness_bits

    def mask_tail_form(extension_bit: int, coordinate: int) -> field.LinearForm:
        return shard._wide_mask_form(
            spool,
            tail_offset + coordinate,
            selected_by_extension[extension_bit],
        )

    def xi_forms():
        for coordinate in range(parameters.consistency_bits):
            point = coordinate // field.FIELD_DEGREE
            bit = coordinate % field.FIELD_DEGREE
            for extension_bit in range(extension_degree):
                yield field.LinearForm.wire(
                    mask_output_starts[extension_bit][point] + bit
                ).add(mask_tail_form(extension_bit, coordinate))

    xi_flat = tree._flatten_xi(spool.xi_masks, extension_degree)
    xi_width = parameters.consistency_bits * extension_degree
    sink.start_group("tree-post-output-port")
    xi_start = shard._publish_source(
        sink,
        shard.BitSource(xi_width, xi_forms),
        base.bits(xi_flat, xi_width),
        f"output.tree[{index}].xi-masks",
    )
    sink.finish_group()
    if (xi_start, xi_width) != contract["output"] or sink.next_wire != contract["post"][1]:
        raise ContinuationError("tree-post output layout or final cursor drift")
    output_port = tree.ProducerPort(
        f"tree[{index}].xi-masks",
        "output",
        "tree-post",
        xi_start,
        xi_width,
        tree._bits_digest(xi_flat, xi_width),
    )
    groups = [_group_document(item) for item in sink.groups]
    trailer = {
        "external_assertions": 0,
        "output_ports": [
            {"port_id": output_port.port_id, "wire_start": xi_start, "bit_length": xi_width}
        ],
        "rows": sink.rows,
        "tree_index": index,
        "local_wire_start": contract["post"][0],
        "max_wire_id": sink.wire_count,
        "imported_point_wires": list(POINT_STARTS),
        "wires": sink.allocated_wires,
    }
    stream_bytes, stream_sha = sink.finish(trailer)
    owned_values = tuple(values[wire] for wire in range(*contract["post"]))
    summary = {
        "format": FRAGMENT_STREAM_FORMAT,
        "relation_id": RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "tree_index": index,
        "stage_id": f"tree-post[{index}]",
        "post_interval": list(contract["post"]),
        "rows": sink.rows,
        "nonlinear_rows": sink.nonlinear_rows,
        "linear_rows": sink.linear_rows,
        "allocated_wires": sink.allocated_wires,
        "imported_unique_wires": len(imported),
        "referenced_import_wires": len(sink.referenced_imports),
        "groups": groups,
        "fragment_stream_bytes": stream_bytes,
        "fragment_stream_sha256": stream_sha,
        "row_semantics_sha256": sink.row_semantics.hexdigest(),
        "output_port": {
            "port_id": output_port.port_id,
            "wire_start": output_port.wire_start,
            "bit_length": output_port.bit_length,
            "value_sha256": output_port.value_sha256,
        },
        "multiplication_rows": multiplication_rows,
        "aggregate_rows": aggregate_rows,
        "all_rows_satisfied": True,
        "external_assertions": 0,
        "post_fragment_assignment_values_in_memory": len(owned_values),
        "full_assignment_materialized": False,
        "assignment_published": False,
        "private_owned_assignment_sha256": _private_assignment_digest(owned_values),
        "production": False,
    }
    receipt_document = {
        "format": RECEIPT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": "INSECURE-TEST-ONLY",
        "relation_id": RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "plan_sha256": PLAN_SHA256,
        "invocation_sha256": decoded.document["invocation_sha256"],
        "tree_index": index,
        "stage_id": f"tree-post[{index}]",
        "previous_receipt_sha256": invocation.candidates.receipt.identity["sha256"],
        "continuation_sha256": expected_continuation_sha256,
        "handoff_sha256": expected_handoff_sha256,
        "dependency_sha256": {
            "private_spool": invocation.candidates.spools[index].identity["sha256"],
            "points": invocation.candidates.points.identity["sha256"],
            "global_a_receipt": invocation.candidates.receipt.identity["sha256"],
        },
        "summary": summary,
        "composition_boundary": decoded.document["composition_boundary"],
        "full_session_restore": False,
        "durable_resume": False,
        "production": False,
    }
    receipt_raw = canonical_json(receipt_document)
    if len(receipt_raw) > RECEIPT_LIMIT:
        raise ContinuationError("tree-post result receipt exceeds bound")
    receipt_snapshot = io.Snapshot(
        Path("/in-memory-insecure-test-only") / f"tree-{index}.post-receipt.private.json",
        receipt_raw,
    )
    return TreePostResultInsecureTestOnly(
        index,
        MappingProxyType(summary),
        output_port,
        owned_values,
        receipt_snapshot,
    )


def validate_tree_post_receipt(
    snapshot: io.Snapshot,
    *,
    expected_sha256: str,
    continuation: Mapping[str, object],
) -> dict[str, object]:
    _digest(expected_sha256, "external tree-post receipt digest")
    if type(snapshot) is not io.Snapshot or len(snapshot.raw) > RECEIPT_LIMIT or sha256(snapshot.raw) != expected_sha256:
        raise ContinuationError("tree-post receipt external identity mismatch")
    try:
        document = snapshot.document()
    except io.ValidationError as error:
        raise ContinuationError("tree-post receipt is not strict canonical JSON") from error
    current = _exact(
        document,
        {
            "format",
            "implementation_version",
            "mode",
            "relation_id",
            "profile_fingerprint",
            "plan_sha256",
            "invocation_sha256",
            "tree_index",
            "stage_id",
            "previous_receipt_sha256",
            "continuation_sha256",
            "handoff_sha256",
            "dependency_sha256",
            "summary",
            "composition_boundary",
            "full_session_restore",
            "durable_resume",
            "production",
        },
        "tree-post receipt",
    )
    index = continuation["tree_index"]
    if not _is_int(index) or index not in (0, 1):
        raise ContinuationError("receipt continuation tree index mismatch")
    index = int(index)
    contract = TREE_CONTRACTS[index]
    summary = _exact(
        current["summary"],
        {
            "format",
            "relation_id",
            "profile_fingerprint",
            "tree_index",
            "stage_id",
            "post_interval",
            "rows",
            "nonlinear_rows",
            "linear_rows",
            "allocated_wires",
            "imported_unique_wires",
            "referenced_import_wires",
            "groups",
            "fragment_stream_bytes",
            "fragment_stream_sha256",
            "row_semantics_sha256",
            "output_port",
            "multiplication_rows",
            "aggregate_rows",
            "all_rows_satisfied",
            "external_assertions",
            "post_fragment_assignment_values_in_memory",
            "full_assignment_materialized",
            "assignment_published",
            "private_owned_assignment_sha256",
            "production",
        },
        "tree-post summary",
    )
    groups = _validate_groups(summary["groups"], POST_GROUPS, "tree-post groups")
    output = _exact(
        summary["output_port"],
        {"port_id", "wire_start", "bit_length", "value_sha256"},
        "tree-post output port",
    )
    for name in (
        "fragment_stream_sha256",
        "row_semantics_sha256",
        "private_owned_assignment_sha256",
    ):
        _digest(summary[name], "tree-post summary " + name)
    _digest(output["value_sha256"], "tree-post output value")
    dependencies = _exact(
        current["dependency_sha256"],
        {"private_spool", "points", "global_a_receipt"},
        "tree-post receipt dependencies",
    )
    for name, value in dependencies.items():
        _digest(value, "tree-post dependency " + name)
    continuation_dependencies = continuation["dependencies"]
    if type(continuation_dependencies) is not dict:
        raise ContinuationError("continuation dependencies missing from receipt validation")
    expected_dependency_digests = {
        "private_spool": continuation_dependencies["private_spool"]["sha256"],
        "points": continuation_dependencies["points"]["sha256"],
        "global_a_receipt": continuation_dependencies["global_a_receipt"]["sha256"],
    }
    if (
        summary["format"] != FRAGMENT_STREAM_FORMAT
        or summary["relation_id"] != RELATION_ID
        or summary["profile_fingerprint"] != PROFILE_FINGERPRINT
        or summary["tree_index"] != index
        or summary["stage_id"] != f"tree-post[{index}]"
        or summary["post_interval"] != list(contract["post"])
        or summary["rows"] != 3_576
        or summary["nonlinear_rows"] != 2_396
        or summary["linear_rows"] != 1_180
        or summary["allocated_wires"] != 2_412
        or summary["imported_unique_wires"] != 10_122
        or summary["referenced_import_wires"] != 10_122
        or groups != EXPECTED_POST_GROUP_DOCUMENTS[index]
        or sum(int(group["rows"]) for group in groups) != summary["rows"]
        or not _is_int(summary["fragment_stream_bytes"])
        or int(summary["fragment_stream_bytes"]) <= 0
        or summary["fragment_stream_sha256"]
        != FROZEN["tree_post_fragment_stream_sha256"][index]
        or summary["row_semantics_sha256"]
        != FROZEN["tree_post_row_semantics_sha256"][index]
        or output["port_id"] != f"tree[{index}].xi-masks"
        or (output["wire_start"], output["bit_length"]) != contract["output"]
        or summary["multiplication_rows"] != 80
        or summary["aggregate_rows"] != 16
        or summary["all_rows_satisfied"] is not True
        or summary["external_assertions"] != 0
        or summary["post_fragment_assignment_values_in_memory"] != 2_412
        or summary["full_assignment_materialized"] is not False
        or summary["assignment_published"] is not False
        or summary["production"] is not False
        or dependencies != expected_dependency_digests
    ):
        raise ContinuationError("tree-post summary, output, or dependency mismatch")
    if (
        current["format"] != RECEIPT_FORMAT
        or current["implementation_version"] != IMPLEMENTATION_VERSION
        or current["mode"] != "INSECURE-TEST-ONLY"
        or current["relation_id"] != RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["plan_sha256"] != PLAN_SHA256
        or current["invocation_sha256"] != continuation["invocation_sha256"]
        or current["tree_index"] != index
        or current["stage_id"] != f"tree-post[{index}]"
        or current["previous_receipt_sha256"]
        != continuation_dependencies["global_a_receipt"]["sha256"]
        or current["continuation_sha256"] != sha256(canonical_json(continuation))
        or current["handoff_sha256"] != continuation_dependencies["handoff"]["sha256"]
        or current["composition_boundary"] != continuation["composition_boundary"]
        or current["full_session_restore"] is not False
        or current["durable_resume"] is not False
        or current["production"] is not False
        or canonical_json(current) != snapshot.raw
    ):
        raise ContinuationError("tree-post receipt domain, continuation, or claim mismatch")
    return current


def _live_group_documents(
    session: predecessor.HandoffSessionInsecureTestOnly, index: int
) -> list[dict[str, object]]:
    return [_group_document(item) for item in session.sinks[f"tree[{index}]"].groups[-2:]]


@lru_cache(maxsize=1)
def bounded_self_check() -> dict[str, object]:
    validate_prerequisites()
    session = predecessor.HandoffSessionInsecureTestOnly()
    try:
        session.run_to("global-a")
        candidates = session.export_candidates()
        handoff_sha = sha256(candidates.handoff.raw)
        session.accept_handoff(candidates, expected_handoff_sha256=handoff_sha)
        receipt_suffix = build_verified_receipt_suffix_snapshots(session)
        continuations = build_continuation_snapshots(session)
        results = []
        for index, continuation in enumerate(continuations):
            invocation = TreePostInvocationInsecureTestOnly(
                candidates, continuation, receipt_suffix
            )
            result = execute_tree_post_insecure_test_only(
                invocation,
                expected_handoff_sha256=handoff_sha,
                expected_continuation_sha256=sha256(continuation.raw),
            )
            results.append(result)
        for index, result in enumerate(results):
            session.run_to(f"tree-post[{index}]")
            contract = TREE_CONTRACTS[index]
            live_owned = tuple(session.values[wire] for wire in range(*contract["post"]))
            live_output = next(
                port
                for port in session.summaries[f"tree[{index}]"].ports
                if port.port_id == f"tree[{index}].xi-masks"
            )
            if (
                live_owned != result.owned_values
                or live_output != result.output_port
                or _live_group_documents(session, index) != result.summary["groups"]
            ):
                raise ContinuationError("standalone tree-post differs from live native emitter")
            decoded_continuation = continuations[index].document()
            validate_tree_post_receipt(
                result.receipt,
                expected_sha256=sha256(result.receipt.raw),
                continuation=decoded_continuation,
            )
        evidence = {
            "format": FORMAT,
            "relation_id": RELATION_ID,
            "mode": "INSECURE-TEST-ONLY",
            "plan_sha256": PLAN_SHA256,
            "invocation_sha256": session.reference.invocation_digest,
            "tree_count": 2,
            "continuation_identities": [item.identity for item in continuations],
            "tree_post_receipt_identities": [item.receipt.identity for item in results],
            "tree_post_rows": [item.summary["rows"] for item in results],
            "tree_post_allocated_wires": [item.summary["allocated_wires"] for item in results],
            "tree_post_group_identities": [item.summary["groups"] for item in results],
            "tree_post_output_ports": [item.summary["output_port"] for item in results],
            "tree_post_fragment_stream_sha256": [
                item.summary["fragment_stream_sha256"] for item in results
            ],
            "tree_post_row_semantics_sha256": [
                item.summary["row_semantics_sha256"] for item in results
            ],
            "total_standalone_rows_checked": sum(int(item.summary["rows"]) for item in results),
            "selected_spool_import_wires_per_tree": codec.LEAVES * codec.RECORD_WIRES,
            "point_import_wires_per_tree": 2 * field.FIELD_DEGREE,
            "verified_receipt_suffix_ordinals": [2, 3],
            "verified_receipt_suffix_identities": [
                snapshot.identity for snapshot in receipt_suffix
            ],
            "full_receipt_chain_verified": False,
            "same_snapshot_raw_for_identity_parse_binding_and_consumer": True,
            "standalone_matches_live_native_groups_outputs_and_assignment": True,
            "tree_pre_replayed_by_standalone_consumer": False,
            "legacy_stream_hash_state_restored": False,
            "full_session_restore_implemented": False,
            "durable_resume_implemented": False,
            "private_payload_embedded": False,
            "other_tree_observed_stream_bytes_used": False,
            "production_rows_replayed": 0,
            "proofs_generated": 0,
            "Proof-closed": False,
            "Production-closed": False,
        }
        if any(evidence.get(key) != value for key, value in FROZEN.items()):
            raise ContinuationError("bounded frozen continuation evidence drift")
        return evidence
    finally:
        session.close()


def execute_production(*_args: object, **_kwargs: object) -> None:
    raise ProductionUnavailable(
        "bounded tree-post continuation is test-only; production refused before I/O"
    )


def preflight() -> dict[str, object]:
    validate_prerequisites()
    return {
        "format": FORMAT,
        "relation_id": RELATION_ID,
        "read_only_preflight_passed": True,
        "safe_to_run_bounded_insecure_test_only": True,
        "independently_invocable_tree_post_implemented": True,
        "explicit_continuation_contract_implemented": True,
        "verified_receipt_suffix_ordinals": [2, 3],
        "full_receipt_chain_verified": False,
        "full_session_restore_implemented": False,
        "durable_resume_implemented": False,
        "private_publication_implemented": False,
        "global_tail_continuation_implemented": False,
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
                "src/pq_rbbc_issuance_tree_post_continuation_v1.py",
                "tests/test_pq_rbbc_issuance_tree_post_continuation_v1.py",
            )
        },
        "predecessor_identities": {
            path: {"bytes": size, "sha256": digest}
            for path, (size, digest) in PREDECESSOR_PINS.items()
        },
        "continuation_contract": {
            "filenames": list(CONTINUATION_NAMES),
            "max_bytes": CONTINUATION_LIMIT,
            "tree_contracts": [
                {name: list(value) for name, value in contract.items()}
                for contract in TREE_CONTRACTS
            ],
            "point_wire_starts": list(POINT_STARTS),
            "serialized_state": list(SERIALIZED_STATE),
            "not_serialized_state": list(NOT_SERIALIZED_STATE),
            "composition_verification": "ordered-group-identities+absolute-wire-interval+verified-receipt-suffix-2-to-3",
            "receipt_contract": {
                "verified_ordinals": [2, 3],
                "verified_link": "ordinal-2-raw-sha256-to-ordinal-3-previous_receipt_sha256",
                "full_chain_verified": False,
                "earlier_receipt_digests_trusted_or_declared": False,
            },
            "legacy_stream_hash_state_restorable": False,
        },
        "bounded_qualification": bounded_self_check(),
        "preflight": preflight(),
        "snapshot_contract": {
            "single_open_single_bounded_read": True,
            "same_raw_for_identity_parse_binding_and_consumer": True,
            "same_capture_batch_includes_all_declared_receipt_snapshots": True,
            "future_executor_consumes_same_candidate_set_snapshots": True,
            "candidate_pathname_reopen_permitted": False,
            "metadata_proves_no_writer": False,
            "trusted_producer_handoff_and_writer_quiescence_external": True,
        },
        "resource_budget": {
            "max_wires": base.MAX_WIRES,
            "max_rows": base.MAX_ROWS,
            "planned_memory_mib": 512,
            "planned_seconds": 180,
            "continuation_max_bytes_each": CONTINUATION_LIMIT,
            "production_estimate": None,
        },
        "claim_status": {
            "Defined": True,
            "Instantiated": "bounded-insecure-test-only",
            "Implemented": "independently-invocable-tree-post-and-explicit-continuation",
            "Tested": "bounded",
            "Evidence-sealed": "metadata-only",
            "Proof-closed": False,
            "Production-closed": False,
            "full_session_restore_implemented": False,
            "durable_resume_implemented": False,
            "production_legacy18_provider_implemented": False,
            "qualified_pq_se_backend_integrated": False,
            "formal_pi_issue_generated": False,
        },
        "exact_commands": {
            "read_only": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_tree_post_continuation_v1.py",
            "bounded": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_tree_post_continuation_v1.py --self-check",
            "targeted": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_tree_post_continuation_v1 -v",
            "production": None,
            "large_replay": None,
            "large_proving": None,
        },
    }


def build_portable_evidence() -> dict[str, object]:
    raw = canonical_json(build_manifest())
    return {
        "format": FORMAT + "-PORTABLE-EVIDENCE",
        "bounded_qualification": bounded_self_check(),
        "manifest": {
            "filename": Path(MANIFEST_PATH).name,
            "bytes": len(raw),
            "sha256": sha256(raw),
        },
        "private_continuation_spool_assignment_or_receipt_embedded": False,
        "production_execution_started": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    report = bounded_self_check() if args.self_check else preflight()
    print(canonical_json(report).decode("ascii"), end="")


if __name__ == "__main__":
    main()
