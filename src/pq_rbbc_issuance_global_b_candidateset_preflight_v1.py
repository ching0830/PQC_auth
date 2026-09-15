#!/usr/bin/env python3
"""Read-only bounded Global-B same-invocation CandidateSet preflight.

The only instantiated profile is the two-tree/four-leaf
``INSECURE-TEST-ONLY`` fixture.  This module aggregates already captured
Global-A and scheduler results.  It never reopens their pathnames, emits
Global-B constraints, publishes private state, or exposes a production API.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Sequence

import pq_rbbc_issuance_bounded_multitree_adapter_v1 as base
import pq_rbbc_issuance_global_a_restart_v1 as global_a
import pq_rbbc_issuance_multitree_restart_scheduler_v1 as scheduler
import pq_rbbc_issuance_private_spool_handoff_v1 as spool_handoff
import pq_rbbc_issuance_tree_post_continuation_v1 as continuation
import pq_rbbc_issuance_tree_post_restart_v1 as restart
import pq_rbbc_launch_io_v2_41 as io


ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION_VERSION = "1.0"
FORMAT = "PQRBBC-ISSUANCE-GLOBAL-B-CANDIDATESET-PREFLIGHT-1"
RELATION_ID = (
    "pq-rbbc/issuance/global-b-candidateset-preflight/"
    "multitree-4plus4-insecure-test-only/v1"
)
MODE = "INSECURE-TEST-ONLY"
HANDOFF_FORMAT = FORMAT + "-HANDOFF"
SHARED_INPUTS_FORMAT = FORMAT + "-SHARED-INPUTS"
RELOCATION_FORMAT = FORMAT + "-RELOCATION-CANDIDATE"
HANDOFF_NAME = "global-b-candidateset.private.json"
SHARED_INPUTS_NAME = "global-b-shared-inputs.private.json"
HANDOFF_LIMIT = 64 * 1024
SHARED_INPUTS_LIMIT = 8 * 1024
RELOCATION_LIMIT = 8 * 1024
DOMAIN_VALUE = b"PQ-RBBC/ISSUANCE/GLOBAL-B-CANDIDATESET/VALUE/V1"
PROFILE_FINGERPRINT = global_a.PROFILE_FINGERPRINT
PLAN_SHA256 = global_a.PLAN_SHA256
INVOCATION_SHA256 = global_a.INVOCATION_SHA256
GLOBAL_B_INTERVAL = (23_094, 43_837)
GLOBAL_B_ROWS = 35_494

MANIFEST_PATH = "manifests/pq_rbbc_issuance_global_b_candidateset_preflight_manifest_v1.json"
EVIDENCE_PATH = (
    "artifacts/metadata/issuance_global_b_candidateset_preflight_v1/"
    "pq_rbbc_issuance_global_b_candidateset_preflight_portable_evidence_v1.json"
)

PREDECESSOR_PINS = {
    "src/pq_rbbc_issuance_global_a_restart_v1.py": (
        92_081,
        "1e6b786d25aa8abac2c022c9c98ae821c595b9bd68704177388a8f8edbf9a516",
    ),
    "tests/test_pq_rbbc_issuance_global_a_restart_v1.py": (
        22_162,
        "54778889c1672ba7be1744328fa6ff78f46e3d283210ebe7bde706a4ec25b173",
    ),
    global_a.MANIFEST_PATH: (
        7_975,
        "3dd46b4add3df9808ef1fef40bffa6b90ccc3e2f3404edcad0a597a6a5a9c8a8",
    ),
    global_a.EVIDENCE_PATH: (
        3_570,
        "674562c2da6469570417bbc80b837ed98a7aac66c65796c7597eefa955188c70",
    ),
    "src/pq_rbbc_issuance_multitree_restart_scheduler_v1.py": (
        54_862,
        "3bb999b414f810dd799e8b84c88fd83e2a7d14ee5ff687eb13b56a1aba01f50b",
    ),
    "tests/test_pq_rbbc_issuance_multitree_restart_scheduler_v1.py": (
        32_850,
        "df4ec76604e757cc4960da5e93fa885ab11e77725475f0ecefc45493287e652b",
    ),
    scheduler.MANIFEST_PATH: (
        17_155,
        "98de9e5ecfe99cd9592d870504c2e4d05cf3f4648b856a873c4b5e2c0c7b8045",
    ),
    scheduler.EVIDENCE_PATH: (
        4_529,
        "67235d27db2f0b19fac60f89ecb7d0b406613737344a01cf7a32e0750d5f5dd6",
    ),
}

TREE_PRE_IDENTITIES = {
    "handoff": {
        "filename": global_a.HANDOFF_NAME,
        "bytes": 1_813,
        "sha256": "61592d73c78e25f010e2e771687d7e13dac02903c84b93008de7b20e7a09baf8",
    },
    "results": [
        {
            "filename": global_a.TREE_PRE_RESULT_NAMES[0],
            "bytes": 3_734,
            "sha256": "cd89d9b530b7d698e25f4b847fd3e88b6880e8604d1a8ad51b474495aed59cd4",
        },
        {
            "filename": global_a.TREE_PRE_RESULT_NAMES[1],
            "bytes": 3_739,
            "sha256": "bd71797c230119453dd95162eb693085de26ba0ccf971eb16f720d91ae6b4f9b",
        },
    ],
}

GLOBAL_A_IDENTITIES = {
    "result": {
        "filename": global_a.PRIVATE_RESULT_NAME,
        "bytes": 610_153,
        "sha256": "38c66f6e14daeda8eeecc708d03a49e54312e665187cdbd9635e50b2247cb623",
    },
    "points": {
        "filename": global_a.POINT_NAME,
        "bytes": 662,
        "sha256": "43eceeec2f4b9cda18bc96014bebbaed319e0e7a8a8c04a710a6950828826009",
    },
    "receipt": {
        "filename": global_a.FRAGMENT_RECEIPT_NAME,
        "bytes": 3_435,
        "sha256": "33a8813edcecf71c0e67bb3b5cb4579dc2a4269f2c6ede8b2392a91a475d6fdc",
    },
    "complete": {
        "filename": global_a.COMPLETE_NAME,
        "bytes": 2_001,
        "sha256": "c5ab55bf862c276db732ad4cb0ff0785d8898d9e142d7fc54d5ef48539974b96",
    },
}

SCHEDULER_IDENTITIES = {
    "plan": {
        "filename": scheduler.PLAN_NAME,
        "bytes": 7_249,
        "sha256": "8c29fff552b2ac8027dc99f592f99f4f31fb5fc195665fbc279fe61a71959100",
    },
    "complete": {
        "filename": scheduler.COMPLETE_NAME,
        "bytes": 1_359,
        "sha256": "ec6fbd094286066d90ef610776ac055dd3afab3a6ac20015aaa303ea3a334b4b",
    },
}

ADAPTER_RECEIPT_IDENTITIES = (
    *tuple(global_a.preflight_gate.VERIFIED_RECEIPT_PREFIX_IDENTITIES),
    scheduler.RECEIPT_SUFFIX_IDENTITIES[1],
)

RELOCATION_SPECS = (
    ("shared.salt", 1, 386, "shared", None, "salt"),
    ("shared.message", 387, 256, "shared", None, "message"),
    ("tree[0].p-plain", 2_187, 2_048, "tree-pre", 78_265, None),
    ("tree[0].mhat-plain", 4_235, 386, "tree-pre", 80_313, None),
    ("tree[0].xi-masks", 4_621, 1_158, "tree-post", 81_953, None),
    ("tree[1].p-plain", 7_323, 2_048, "tree-pre", 117_539, None),
    ("tree[1].mhat-plain", 9_371, 386, "tree-pre", 119_587, None),
    ("tree[1].xi-masks", 9_757, 1_158, "tree-post", 121_227, None),
)
RELOCATION_NAMES = tuple(
    f"global-b-relocation-{index:02d}.private.json"
    for index in range(len(RELOCATION_SPECS))
)

# Filled from the deterministic bounded fixture after source/test identities are frozen.
FROZEN = {
    "candidate_handoff_identity": {
        "filename": HANDOFF_NAME,
        "bytes": 5_656,
        "sha256": "ba284499e8f704840c33ed9b9aaadb86c17e3b4524e02266b4055201ba8b0df3",
    },
    "shared_inputs_identity": {
        "filename": SHARED_INPUTS_NAME,
        "bytes": 1_083,
        "sha256": "b169c3ab2417e5d8b70fbce10d44a902ae4a852c2ea8acdd011168af9b1be1da",
    },
    "relocation_candidate_identities": [
        {"filename": RELOCATION_NAMES[0], "bytes": 1_222, "sha256": "54a6320c2cddda669bfad7f2ad24c7b34dd4c50d551fd5e9eb1910f3f305fc6c"},
        {"filename": RELOCATION_NAMES[1], "bytes": 1_196, "sha256": "61953e21ed17cf5f5f4bbedaa6b4e0f26c5e3cf857bacc5c33d394d70b68a62d"},
        {"filename": RELOCATION_NAMES[2], "bytes": 1_640, "sha256": "8719223bfce05f11f040806cd5301c6a73bfd9f57d9574665bdf311b2f97b225"},
        {"filename": RELOCATION_NAMES[3], "bytes": 1_228, "sha256": "16a3181c19b30929ea4fa1064705174f4bcd3489559714f7dfaf2915d70658a5"},
        {"filename": RELOCATION_NAMES[4], "bytes": 1_423, "sha256": "2b1a3b8076d07ba2f56f3c70c6b7df62698775185246131ced301d87f1f5bbd6"},
        {"filename": RELOCATION_NAMES[5], "bytes": 1_641, "sha256": "4068c4decbce046ca2e039a6ce7bd55c40450e12e9bc5dd3abb232bfdfa22192"},
        {"filename": RELOCATION_NAMES[6], "bytes": 1_229, "sha256": "2a1fdb03d977ad6c9a7d23c0518ad3bbd2bfb398cf8b58db452b97dacf5a6cdb"},
        {"filename": RELOCATION_NAMES[7], "bytes": 1_424, "sha256": "3c28192dc090f9ba1ca884c4232560321188ee6f76e8230d5b195ba9e648d82a"},
    ],
    "candidate_snapshot_identity_count": 32,
    "relocation_candidate_count": 8,
    "global_b_rows_replayed": 0,
    "global_b_constraints_emitted": 0,
    "native_relocation_equalities_executed": 0,
    "full_execution_receipt_chain_verified": False,
}


class GlobalBCandidateSetError(ValueError):
    """A Global-B aggregate candidate or its contract was rejected."""


class ProductionUnavailable(RuntimeError):
    """This checkpoint intentionally exposes no production executor."""


@dataclass(frozen=True)
class GlobalBCandidateSetInsecureTestOnly:
    handoff: io.Snapshot
    shared_inputs: io.Snapshot
    tree_pre: global_a.TreePreCandidateSetInsecureTestOnly
    global_a_result: global_a.PublishedGlobalAResultInsecureTestOnly
    continuations: tuple[io.Snapshot, io.Snapshot]
    adapter_receipt_prefix: tuple[io.Snapshot, io.Snapshot, io.Snapshot]
    scheduler_receipt_suffix: tuple[io.Snapshot, io.Snapshot]
    schedule: scheduler.SchedulerResultInsecureTestOnly
    relocations: tuple[io.Snapshot, ...]

    def __post_init__(self) -> None:
        if (
            type(self.handoff) is not io.Snapshot
            or type(self.shared_inputs) is not io.Snapshot
            or type(self.tree_pre) is not global_a.TreePreCandidateSetInsecureTestOnly
            or type(self.global_a_result)
            is not global_a.PublishedGlobalAResultInsecureTestOnly
            or type(self.schedule) is not scheduler.SchedulerResultInsecureTestOnly
            or type(self.continuations) is not tuple
            or len(self.continuations) != 2
            or type(self.adapter_receipt_prefix) is not tuple
            or len(self.adapter_receipt_prefix) != 3
            or type(self.scheduler_receipt_suffix) is not tuple
            or len(self.scheduler_receipt_suffix) != 2
            or type(self.relocations) is not tuple
            or len(self.relocations) != 8
            or any(
                type(snapshot) is not io.Snapshot
                for snapshot in (
                    self.handoff,
                    self.shared_inputs,
                    *self.continuations,
                    *self.adapter_receipt_prefix,
                    *self.scheduler_receipt_suffix,
                    *self.relocations,
                )
            )
        ):
            raise GlobalBCandidateSetError("exact immutable aggregate CandidateSet required")


@dataclass(frozen=True)
class DecodedGlobalBCandidateSetInsecureTestOnly:
    handoff: Mapping[str, object]
    shared_inputs: Mapping[str, tuple[int, ...]]
    target_values: Mapping[int, int]
    global_a_values: tuple[int, ...]
    tree_post_values: tuple[tuple[int, ...], tuple[int, ...]]


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
        raise GlobalBCandidateSetError(label + " must be a lowercase SHA-256")
    return value


def _exact(value: object, fields: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise GlobalBCandidateSetError(label + " closed schema mismatch")
    return value


def _snapshot(name: str, raw: bytes, limit: int) -> io.Snapshot:
    if type(raw) is not bytes or not 0 < len(raw) <= limit:
        raise GlobalBCandidateSetError("snapshot byte bound: " + name)
    return io.Snapshot(Path("/in-memory-insecure-test-only") / name, raw)


def _identity(snapshot: io.Snapshot, name: str, limit: int) -> dict[str, object]:
    if (
        type(snapshot) is not io.Snapshot
        or snapshot.location.name != name
        or not 0 < len(snapshot.raw) <= limit
    ):
        raise GlobalBCandidateSetError("snapshot name/type/size mismatch: " + name)
    return snapshot.identity


def _identity_document(value: object, label: str) -> dict[str, object]:
    current = _exact(value, {"filename", "bytes", "sha256"}, label)
    if (
        type(current["filename"]) is not str
        or not current["filename"]
        or "/" in current["filename"]
        or not _is_int(current["bytes"])
        or not 0 < int(current["bytes"]) <= 1 << 20
    ):
        raise GlobalBCandidateSetError(label + " invalid filename or byte count")
    _digest(current["sha256"], label)
    return current


def _pack_bits(bits: Sequence[int]) -> bytes:
    if any(value not in (0, 1) for value in bits):
        raise GlobalBCandidateSetError("non-binary relocation value")
    packed = bytearray((len(bits) + 7) // 8)
    for index, value in enumerate(bits):
        packed[index // 8] |= int(value) << (index % 8)
    return bytes(packed)


def _decode_bits(value: object, width: int) -> tuple[int, ...]:
    if type(value) is not str or len(value) != 2 * ((width + 7) // 8):
        raise GlobalBCandidateSetError("packed bit length mismatch")
    try:
        packed = bytes.fromhex(value)
    except ValueError as error:
        raise GlobalBCandidateSetError("packed bits are not lowercase hex") from error
    if packed.hex() != value:
        raise GlobalBCandidateSetError("packed bits require lowercase hex")
    bits = tuple((packed[index // 8] >> (index % 8)) & 1 for index in range(width))
    if width % 8 and packed[-1] >> (width % 8):
        raise GlobalBCandidateSetError("nonzero packed padding bits")
    return bits


def _value_digest(port_id: str, packed: bytes) -> str:
    encoded = port_id.encode("ascii")
    return sha256(
        DOMAIN_VALUE
        + len(encoded).to_bytes(2, "big")
        + encoded
        + len(packed).to_bytes(4, "big")
        + packed
    )


def validate_prerequisites() -> None:
    global_a.validate_prerequisites()
    scheduler.validate_prerequisites()
    for path, (expected_bytes, expected_sha256) in PREDECESSOR_PINS.items():
        snapshot = io.read_snapshot(ROOT / path)
        if (len(snapshot.raw), sha256(snapshot.raw)) != (
            expected_bytes,
            expected_sha256,
        ):
            raise GlobalBCandidateSetError("predecessor identity drift: " + path)


def _require_identity(
    snapshot: io.Snapshot,
    expected: Mapping[str, object],
    *,
    limit: int = 1 << 20,
) -> None:
    if _identity(snapshot, str(expected["filename"]), limit) != expected:
        raise GlobalBCandidateSetError(
            "frozen predecessor snapshot identity mismatch: " + str(expected["filename"])
        )


def _validate_ordinal_three(
    snapshot: io.Snapshot, ordinal_two: io.Snapshot, point_snapshot: io.Snapshot
) -> Mapping[str, object]:
    _require_identity(snapshot, ADAPTER_RECEIPT_IDENTITIES[3], limit=global_a.ADAPTER_RECEIPT_LIMIT)
    try:
        current = snapshot.document()
    except io.ValidationError as error:
        raise GlobalBCandidateSetError("ordinal-3 receipt is not strict canonical JSON") from error
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
        "ordinal-3 adapter receipt",
    )
    _digest(current["native_binding_rows_sha256"], "ordinal-3 native binding")
    prefixes = current["native_prefix_identities"]
    if type(prefixes) is not dict or set(prefixes) != {
        "anchors",
        "tail",
        "tree[0]",
        "tree[1]",
    }:
        raise GlobalBCandidateSetError("ordinal-3 native prefix inventory")
    for digest in prefixes.values():
        _digest(digest, "ordinal-3 native prefix")
    if (
        current["format"] != base.FORMAT + "-RECEIPT"
        or current["relation_id"] != base.RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["plan_sha256"] != PLAN_SHA256
        or current["invocation_sha256"] != INVOCATION_SHA256
        or current["ordinal"] != 3
        or current["stage_id"] != "global-a"
        or current["previous_receipt_sha256"] != sha256(ordinal_two.raw)
        or current["rows"] != global_a.PHASE_A_ROWS
        or current["total_rows"] != 140_781
        or current["relocation_ports"] != list(global_a.EXPECTED_RELOCATIONS[-1])
        or current["point_snapshot_sha256"] != point_snapshot.identity["sha256"]
        or current["production"] is not False
        or current["durable_resume"] is not False
        or canonical_json(current) != snapshot.raw
    ):
        raise GlobalBCandidateSetError("ordinal-3 receipt domain, stage, link, or claim drift")
    return MappingProxyType(dict(current))


def _validate_predecessors(
    candidate: GlobalBCandidateSetInsecureTestOnly,
) -> tuple[
    global_a.DecodedTreePreCandidateSetInsecureTestOnly,
    tuple[int, ...],
    tuple[tuple[int, ...], tuple[int, ...]],
]:
    tree_pre = candidate.tree_pre
    _require_identity(tree_pre.handoff, TREE_PRE_IDENTITIES["handoff"], limit=global_a.HANDOFF_LIMIT)
    for snapshot, expected in zip(tree_pre.tree_results, TREE_PRE_IDENTITIES["results"]):
        _require_identity(snapshot, expected, limit=global_a.TREE_PRE_RESULT_LIMIT)
    for index in range(3):
        if tree_pre.receipts[index].raw != candidate.adapter_receipt_prefix[index].raw:
            raise GlobalBCandidateSetError("Global-A receipt prefix does not reuse aggregate raw")
        _require_identity(
            candidate.adapter_receipt_prefix[index],
            ADAPTER_RECEIPT_IDENTITIES[index],
            limit=global_a.ADAPTER_RECEIPT_LIMIT,
        )
    decoded_tree_pre = global_a.decode_tree_pre_candidates_insecure_test_only(
        tree_pre,
        expected_handoff_sha256=str(TREE_PRE_IDENTITIES["handoff"]["sha256"]),
    )

    published = candidate.global_a_result
    for snapshot, expected, limit in (
        (published.result, GLOBAL_A_IDENTITIES["result"], global_a.PRIVATE_RESULT_LIMIT),
        (published.point_snapshot, GLOBAL_A_IDENTITIES["points"], global_a.POINT_LIMIT),
        (published.receipt, GLOBAL_A_IDENTITIES["receipt"], global_a.FRAGMENT_RECEIPT_LIMIT),
        (published.complete_checkpoint, GLOBAL_A_IDENTITIES["complete"], global_a.CHECKPOINT_LIMIT),
    ):
        _require_identity(snapshot, expected, limit=limit)
    receipt_document = global_a._validate_fragment_receipt(
        published.receipt,
        expected_identity=GLOBAL_A_IDENTITIES["receipt"],
        candidates=tree_pre,
        handoff_sha256=str(TREE_PRE_IDENTITIES["handoff"]["sha256"]),
    )
    global_a_values, h1, points = global_a._validate_private_result(
        published.result,
        expected_identity=GLOBAL_A_IDENTITIES["result"],
        point_snapshot=published.point_snapshot,
        receipt_snapshot=published.receipt,
        receipt_document=receipt_document,
        handoff_sha256=str(TREE_PRE_IDENTITIES["handoff"]["sha256"]),
    )
    if (
        tuple(published.owned_values) != global_a_values
        or published.h1 != h1
        or tuple(published.points) != points
        or receipt_document["previous_receipt_sha256"]
        != candidate.adapter_receipt_prefix[2].identity["sha256"]
    ):
        raise GlobalBCandidateSetError("Global-A decoded values or receipt fork mismatch")

    if candidate.adapter_receipt_prefix[2].raw != tree_pre.receipts[2].raw:
        raise GlobalBCandidateSetError("ordinal-2 Global-A overlap raw mismatch")
    if (
        candidate.adapter_receipt_prefix[2].raw
        != candidate.scheduler_receipt_suffix[0].raw
        or candidate.adapter_receipt_prefix[2].identity["bytes"]
        != candidate.scheduler_receipt_suffix[0].identity["bytes"]
        or candidate.adapter_receipt_prefix[2].identity["sha256"]
        != candidate.scheduler_receipt_suffix[0].identity["sha256"]
    ):
        raise GlobalBCandidateSetError("ordinal-2 prefix/suffix raw overlap mismatch")
    _require_identity(
        candidate.scheduler_receipt_suffix[0],
        scheduler.RECEIPT_SUFFIX_IDENTITIES[0],
        limit=global_a.ADAPTER_RECEIPT_LIMIT,
    )
    _require_identity(
        candidate.scheduler_receipt_suffix[1],
        scheduler.RECEIPT_SUFFIX_IDENTITIES[1],
        limit=global_a.ADAPTER_RECEIPT_LIMIT,
    )
    ordinal_three = _validate_ordinal_three(
        candidate.scheduler_receipt_suffix[1],
        candidate.scheduler_receipt_suffix[0],
        published.point_snapshot,
    )
    if ordinal_three["rows"] != receipt_document["summary"]["rows"]:
        raise GlobalBCandidateSetError("parallel Global-A receipt row count mismatch")

    schedule = candidate.schedule
    _require_identity(schedule.execution_plan, SCHEDULER_IDENTITIES["plan"], limit=scheduler.CHECKPOINT_LIMIT)
    _require_identity(schedule.complete_checkpoint, SCHEDULER_IDENTITIES["complete"], limit=scheduler.CHECKPOINT_LIMIT)
    plan = scheduler._validate_plan(schedule.execution_plan)
    if (
        type(schedule.ordered_results) is not tuple
        or len(schedule.ordered_results) != 2
        or schedule.adopted_orphan_tree_indices != ()
        or plan["ordered_tree_indices"] != [0, 1]
    ):
        raise GlobalBCandidateSetError("scheduler order or completed capture mismatch")

    if type(candidate.continuations) is not tuple or len(candidate.continuations) != 2:
        raise GlobalBCandidateSetError("exact two continuation raws required")
    tree_post_values = []
    for index, (snapshot, result, descriptor) in enumerate(
        zip(candidate.continuations, schedule.ordered_results, plan["trees"])
    ):
        _require_identity(snapshot, scheduler.CONTINUATION_IDENTITIES[index], limit=continuation.CONTINUATION_LIMIT)
        try:
            continuation_document = snapshot.document()
        except io.ValidationError as error:
            raise GlobalBCandidateSetError("continuation is not strict canonical JSON") from error
        if (
            continuation_document.get("tree_index") != index
            or continuation_document.get("profile_fingerprint") != PROFILE_FINGERPRINT
            or continuation_document.get("plan_sha256") != PLAN_SHA256
            or continuation_document.get("invocation_sha256") != INVOCATION_SHA256
            or continuation_document.get("dependencies", {}).get("points")
            != published.point_snapshot.identity
            or continuation_document.get("verified_receipt_suffix")
            != [
                candidate.scheduler_receipt_suffix[0].identity,
                candidate.scheduler_receipt_suffix[1].identity,
            ]
            or canonical_json(continuation_document) != snapshot.raw
        ):
            raise GlobalBCandidateSetError("continuation domain, points, or receipt overlap mismatch")
        _require_identity(result.result, scheduler.EXPECTED_PRIVATE_RESULTS[index], limit=restart.RESULT_LIMIT)
        _require_identity(result.receipt, scheduler.EXPECTED_RECEIPTS[index], limit=continuation.RECEIPT_LIMIT)
        _require_identity(
            result.complete_checkpoint,
            scheduler.EXPECTED_CHILD_CHECKPOINT_CHAINS[index][-1],
            limit=restart.CHECKPOINT_LIMIT,
        )
        tree_receipt = continuation.validate_tree_post_receipt(
            result.receipt,
            expected_sha256=str(scheduler.EXPECTED_RECEIPTS[index]["sha256"]),
            continuation=continuation_document,
        )
        values, port = restart._validate_private_result(
            result.result,
            expected_identity=scheduler.EXPECTED_PRIVATE_RESULTS[index],
            receipt_document=tree_receipt,
            continuation_document=continuation_document,
        )
        scheduler._validate_child_result(result, descriptor)
        if (
            result.tree_index != index
            or tuple(result.owned_values) != values
            or result.output_port != port
            or tree_receipt["previous_receipt_sha256"]
            != candidate.scheduler_receipt_suffix[1].identity["sha256"]
        ):
            raise GlobalBCandidateSetError("tree-post result values, order, or receipt branch mismatch")
        tree_post_values.append(values)
    return decoded_tree_pre, global_a_values, tuple(tree_post_values)  # type: ignore[return-value]


def _shared_inputs_snapshot() -> io.Snapshot:
    reference = base.build_reference_insecure_test_only(0)
    salt = reference.randomness.salt[0] | reference.randomness.salt[1] << 193
    values = (
        ("salt", 1, tuple(base.bits(salt, 386))),
        (
            "message",
            387,
            tuple(base.bits(int.from_bytes(reference.invocation.ticket_message, "little"), 256)),
        ),
    )
    fields = []
    for field_id, target_start, bits in values:
        packed = _pack_bits(bits)
        fields.append(
            {
                "field_id": field_id,
                "target_wire_start": target_start,
                "bit_length": len(bits),
                "packed_bits_hex": packed.hex(),
                "packed_bits_sha256": sha256(packed),
            }
        )
    document = {
        "format": SHARED_INPUTS_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "plan_sha256": PLAN_SHA256,
        "invocation_sha256": INVOCATION_SHA256,
        "stage_id": "global-b-prelude",
        "fields": fields,
        "private_payload": True,
        "production": False,
    }
    return _snapshot(SHARED_INPUTS_NAME, canonical_json(document), SHARED_INPUTS_LIMIT)


def _shared_inputs_document(snapshot: io.Snapshot) -> Mapping[str, tuple[int, ...]]:
    _require_identity(
        snapshot,
        FROZEN["shared_inputs_identity"],
        limit=SHARED_INPUTS_LIMIT,
    )
    try:
        current = snapshot.document()
    except io.ValidationError as error:
        raise GlobalBCandidateSetError("shared inputs are not strict canonical JSON") from error
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
            "fields",
            "private_payload",
            "production",
        },
        "shared input snapshot",
    )
    if type(current["fields"]) is not list or len(current["fields"]) != 2:
        raise GlobalBCandidateSetError("exact salt/message shared inputs required")
    decoded = {}
    for value, expected in zip(current["fields"], (("salt", 1, 386), ("message", 387, 256))):
        field = _exact(
            value,
            {
                "field_id",
                "target_wire_start",
                "bit_length",
                "packed_bits_hex",
                "packed_bits_sha256",
            },
            "shared input field",
        )
        field_id, start, width = expected
        bits = _decode_bits(field["packed_bits_hex"], width)
        packed = _pack_bits(bits)
        _digest(field["packed_bits_sha256"], "shared input bits")
        if (
            field["field_id"] != field_id
            or field["target_wire_start"] != start
            or field["bit_length"] != width
            or field["packed_bits_sha256"] != sha256(packed)
        ):
            raise GlobalBCandidateSetError("shared input layout or value digest mismatch")
        decoded[field_id] = bits
    if (
        current["format"] != SHARED_INPUTS_FORMAT
        or current["implementation_version"] != IMPLEMENTATION_VERSION
        or current["mode"] != MODE
        or current["relation_id"] != RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["plan_sha256"] != PLAN_SHA256
        or current["invocation_sha256"] != INVOCATION_SHA256
        or current["stage_id"] != "global-b-prelude"
        or current["private_payload"] is not True
        or current["production"] is not False
        or canonical_json(current) != snapshot.raw
    ):
        raise GlobalBCandidateSetError("shared input domain, invocation, or claim mismatch")
    return MappingProxyType(decoded)


def _source_bits(
    spec: tuple[str, int, int, str, int | None, str | None],
    *,
    shared: Mapping[str, tuple[int, ...]],
    decoded_tree_pre: global_a.DecodedTreePreCandidateSetInsecureTestOnly,
    tree_post_values: Sequence[tuple[int, ...]],
) -> tuple[tuple[int, ...], Mapping[str, object]]:
    port_id, target_start, width, role, source_start, source_field = spec
    if role == "shared":
        bits = shared[str(source_field)]
        source_identity: Mapping[str, object] = {"role": role}
    elif role == "tree-pre":
        index = int(port_id[5])
        bits = tuple(decoded_tree_pre.values[target_start + offset] for offset in range(width))
        source_identity = TREE_PRE_IDENTITIES["results"][index]
    elif role == "tree-post":
        index = int(port_id[5])
        post_start = continuation.TREE_CONTRACTS[index]["post"][0]
        offset = int(source_start) - post_start
        bits = tuple(tree_post_values[index][offset : offset + width])
        source_identity = scheduler.EXPECTED_PRIVATE_RESULTS[index]
    else:  # pragma: no cover - frozen table
        raise GlobalBCandidateSetError("unknown relocation source role")
    if len(bits) != width:
        raise GlobalBCandidateSetError("relocation source width mismatch")
    return bits, source_identity


def _relocation_snapshot(
    index: int,
    spec: tuple[str, int, int, str, int | None, str | None],
    bits: Sequence[int],
    source_identity: Mapping[str, object],
) -> io.Snapshot:
    port_id, target_start, width, role, source_start, source_field = spec
    packed = _pack_bits(bits)
    document = {
        "format": RELOCATION_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "plan_sha256": PLAN_SHA256,
        "invocation_sha256": INVOCATION_SHA256,
        "ordinal": index,
        "port_id": port_id,
        "source_role": role,
        "source_snapshot": dict(source_identity),
        "source_wire_start": source_start,
        "source_field": source_field,
        "target_wire_start": target_start,
        "bit_length": width,
        "packed_bits_hex": packed.hex(),
        "packed_bits_sha256": sha256(packed),
        "value_binding_sha256": _value_digest(port_id, packed),
        "host_value_binding_checked": True,
        "native_equality_required": True,
        "native_equality_executed": False,
        "production": False,
    }
    return _snapshot(RELOCATION_NAMES[index], canonical_json(document), RELOCATION_LIMIT)


def _handoff_snapshot(
    *,
    shared_inputs: io.Snapshot,
    tree_pre: global_a.TreePreCandidateSetInsecureTestOnly,
    global_a_result: global_a.PublishedGlobalAResultInsecureTestOnly,
    continuations: Sequence[io.Snapshot],
    adapter_receipt_prefix: Sequence[io.Snapshot],
    scheduler_receipt_suffix: Sequence[io.Snapshot],
    schedule: scheduler.SchedulerResultInsecureTestOnly,
    relocations: Sequence[io.Snapshot],
) -> io.Snapshot:
    document = {
        "format": HANDOFF_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "plan_sha256": PLAN_SHA256,
        "invocation_sha256": INVOCATION_SHA256,
        "stage_id": "global-b-candidateset",
        "next_stage": "global-b",
        "shared_inputs": shared_inputs.identity,
        "tree_pre": {
            "handoff": tree_pre.handoff.identity,
            "results": [snapshot.identity for snapshot in tree_pre.tree_results],
        },
        "global_a": {
            "result": global_a_result.result.identity,
            "points": global_a_result.point_snapshot.identity,
            "receipt": global_a_result.receipt.identity,
            "complete": global_a_result.complete_checkpoint.identity,
        },
        "continuations": [snapshot.identity for snapshot in continuations],
        "adapter_receipt_prefix": [
            snapshot.identity for snapshot in adapter_receipt_prefix
        ],
        "scheduler_receipt_suffix": [
            snapshot.identity for snapshot in scheduler_receipt_suffix
        ],
        "scheduler": {
            "plan": schedule.execution_plan.identity,
            "complete": schedule.complete_checkpoint.identity,
            "ordered_results": [
                {
                    "tree_index": result.tree_index,
                    "result": result.result.identity,
                    "receipt": result.receipt.identity,
                    "complete": result.complete_checkpoint.identity,
                }
                for result in schedule.ordered_results
            ],
        },
        "relocation_candidates": [snapshot.identity for snapshot in relocations],
        "adapter_receipt_prefix_ordinals_verified": [0, 1, 2, 3],
        "tree_post_receipt_branches_verified": [0, 1],
        "same_points_raw_verified": True,
        "same_invocation_profile_plan_verified": True,
        "all_candidate_identity_parse_and_binding_use_same_raw": True,
        "future_executor_must_consume_same_snapshots": True,
        "candidate_pathname_reopen_permitted": False,
        "metadata_proves_no_writer": False,
        "global_b_native_equalities_executed": False,
        "global_b_constraints_replayed": False,
        "full_execution_receipt_chain_verified": False,
        "private_payload": True,
        "production": False,
    }
    return _snapshot(HANDOFF_NAME, canonical_json(document), HANDOFF_LIMIT)


def build_candidate_set_insecure_test_only(
    *,
    tree_pre: global_a.TreePreCandidateSetInsecureTestOnly,
    global_a_result: global_a.PublishedGlobalAResultInsecureTestOnly,
    continuations: tuple[io.Snapshot, io.Snapshot],
    adapter_receipt_prefix: tuple[io.Snapshot, io.Snapshot, io.Snapshot],
    scheduler_receipt_suffix: tuple[io.Snapshot, io.Snapshot],
    schedule: scheduler.SchedulerResultInsecureTestOnly,
) -> GlobalBCandidateSetInsecureTestOnly:
    """Aggregate already captured predecessor snapshots without pathname access."""
    validate_prerequisites()
    provisional = GlobalBCandidateSetInsecureTestOnly(
        _snapshot(HANDOFF_NAME, b"{}\n", HANDOFF_LIMIT),
        _shared_inputs_snapshot(),
        tree_pre,
        global_a_result,
        continuations,
        adapter_receipt_prefix,
        scheduler_receipt_suffix,
        schedule,
        tuple(_snapshot(name, b"{}\n", RELOCATION_LIMIT) for name in RELOCATION_NAMES),
    )
    decoded_tree_pre, _, tree_post_values = _validate_predecessors(provisional)
    shared = _shared_inputs_document(provisional.shared_inputs)
    relocations = []
    for index, spec in enumerate(RELOCATION_SPECS):
        bits, source_identity = _source_bits(
            spec,
            shared=shared,
            decoded_tree_pre=decoded_tree_pre,
            tree_post_values=tree_post_values,
        )
        if spec[3] == "shared":
            source_identity = provisional.shared_inputs.identity
        relocations.append(_relocation_snapshot(index, spec, bits, source_identity))
    handoff = _handoff_snapshot(
        shared_inputs=provisional.shared_inputs,
        tree_pre=tree_pre,
        global_a_result=global_a_result,
        continuations=continuations,
        adapter_receipt_prefix=adapter_receipt_prefix,
        scheduler_receipt_suffix=scheduler_receipt_suffix,
        schedule=schedule,
        relocations=relocations,
    )
    candidate = GlobalBCandidateSetInsecureTestOnly(
        handoff,
        provisional.shared_inputs,
        tree_pre,
        global_a_result,
        continuations,
        adapter_receipt_prefix,
        scheduler_receipt_suffix,
        schedule,
        tuple(relocations),
    )
    validate_candidate_set_insecure_test_only(
        candidate, expected_handoff_sha256=handoff.identity["sha256"]
    )
    return candidate


def _handoff_document(
    candidate: GlobalBCandidateSetInsecureTestOnly, expected_handoff_sha256: str
) -> dict[str, object]:
    _digest(expected_handoff_sha256, "external Global-B CandidateSet handoff")
    _identity(candidate.handoff, HANDOFF_NAME, HANDOFF_LIMIT)
    if candidate.handoff.identity["sha256"] != expected_handoff_sha256:
        raise GlobalBCandidateSetError("handoff digest rejected before dependencies")
    try:
        current = candidate.handoff.document()
    except io.ValidationError as error:
        raise GlobalBCandidateSetError("handoff is not strict canonical JSON") from error
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
            "next_stage",
            "shared_inputs",
            "tree_pre",
            "global_a",
            "continuations",
            "adapter_receipt_prefix",
            "scheduler_receipt_suffix",
            "scheduler",
            "relocation_candidates",
            "adapter_receipt_prefix_ordinals_verified",
            "tree_post_receipt_branches_verified",
            "same_points_raw_verified",
            "same_invocation_profile_plan_verified",
            "all_candidate_identity_parse_and_binding_use_same_raw",
            "future_executor_must_consume_same_snapshots",
            "candidate_pathname_reopen_permitted",
            "metadata_proves_no_writer",
            "global_b_native_equalities_executed",
            "global_b_constraints_replayed",
            "full_execution_receipt_chain_verified",
            "private_payload",
            "production",
        },
        "Global-B CandidateSet handoff",
    )
    if (
        current["format"] != HANDOFF_FORMAT
        or current["implementation_version"] != IMPLEMENTATION_VERSION
        or current["mode"] != MODE
        or current["relation_id"] != RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["plan_sha256"] != PLAN_SHA256
        or current["invocation_sha256"] != INVOCATION_SHA256
        or current["stage_id"] != "global-b-candidateset"
        or current["next_stage"] != "global-b"
        or current["adapter_receipt_prefix_ordinals_verified"] != [0, 1, 2, 3]
        or current["tree_post_receipt_branches_verified"] != [0, 1]
        or current["same_points_raw_verified"] is not True
        or current["same_invocation_profile_plan_verified"] is not True
        or current["all_candidate_identity_parse_and_binding_use_same_raw"] is not True
        or current["future_executor_must_consume_same_snapshots"] is not True
        or current["candidate_pathname_reopen_permitted"] is not False
        or current["metadata_proves_no_writer"] is not False
        or current["global_b_native_equalities_executed"] is not False
        or current["global_b_constraints_replayed"] is not False
        or current["full_execution_receipt_chain_verified"] is not False
        or current["private_payload"] is not True
        or current["production"] is not False
        or canonical_json(current) != candidate.handoff.raw
    ):
        raise GlobalBCandidateSetError("handoff domain, order, or claim mismatch")
    return current


def _check_handoff_inventory(
    candidate: GlobalBCandidateSetInsecureTestOnly, handoff: Mapping[str, object]
) -> None:
    tree_pre = _exact(handoff["tree_pre"], {"handoff", "results"}, "tree-pre inventory")
    global_a_inventory = _exact(
        handoff["global_a"], {"result", "points", "receipt", "complete"}, "Global-A inventory"
    )
    scheduler_inventory = _exact(
        handoff["scheduler"], {"plan", "complete", "ordered_results"}, "scheduler inventory"
    )
    actual_pairs = (
        (candidate.shared_inputs, handoff["shared_inputs"]),
        (candidate.tree_pre.handoff, tree_pre["handoff"]),
        (candidate.global_a_result.result, global_a_inventory["result"]),
        (candidate.global_a_result.point_snapshot, global_a_inventory["points"]),
        (candidate.global_a_result.receipt, global_a_inventory["receipt"]),
        (candidate.global_a_result.complete_checkpoint, global_a_inventory["complete"]),
        (candidate.schedule.execution_plan, scheduler_inventory["plan"]),
        (candidate.schedule.complete_checkpoint, scheduler_inventory["complete"]),
    )
    for snapshot, identity in actual_pairs:
        if snapshot.identity != _identity_document(identity, "handoff identity"):
            raise GlobalBCandidateSetError("handoff dependency identity mismatch")
    lists = (
        (candidate.tree_pre.tree_results, tree_pre["results"], "tree-pre results"),
        (candidate.continuations, handoff["continuations"], "continuations"),
        (
            candidate.adapter_receipt_prefix,
            handoff["adapter_receipt_prefix"],
            "adapter receipt prefix",
        ),
        (
            candidate.scheduler_receipt_suffix,
            handoff["scheduler_receipt_suffix"],
            "scheduler receipt suffix",
        ),
        (candidate.relocations, handoff["relocation_candidates"], "relocations"),
    )
    for snapshots, identities, label in lists:
        if type(identities) is not list or len(identities) != len(snapshots):
            raise GlobalBCandidateSetError(label + " inventory length")
        for snapshot, identity in zip(snapshots, identities):
            if snapshot.identity != _identity_document(identity, label + " identity"):
                raise GlobalBCandidateSetError(label + " identity mismatch")
    ordered = scheduler_inventory["ordered_results"]
    if type(ordered) is not list or len(ordered) != 2:
        raise GlobalBCandidateSetError("scheduler ordered result inventory")
    for index, (entry, result) in enumerate(zip(ordered, candidate.schedule.ordered_results)):
        current = _exact(entry, {"tree_index", "result", "receipt", "complete"}, "tree result inventory")
        if (
            current["tree_index"] != index
            or current["result"] != result.result.identity
            or current["receipt"] != result.receipt.identity
            or current["complete"] != result.complete_checkpoint.identity
        ):
            raise GlobalBCandidateSetError("scheduler result order or identity mismatch")


def _validate_relocations(
    candidate: GlobalBCandidateSetInsecureTestOnly,
    *,
    shared: Mapping[str, tuple[int, ...]],
    decoded_tree_pre: global_a.DecodedTreePreCandidateSetInsecureTestOnly,
    tree_post_values: Sequence[tuple[int, ...]],
) -> Mapping[int, int]:
    target_values: dict[int, int] = {}
    for index, (snapshot, spec, expected_name) in enumerate(
        zip(candidate.relocations, RELOCATION_SPECS, RELOCATION_NAMES)
    ):
        _identity(snapshot, expected_name, RELOCATION_LIMIT)
        try:
            current = snapshot.document()
        except io.ValidationError as error:
            raise GlobalBCandidateSetError("relocation is not strict canonical JSON") from error
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
                "ordinal",
                "port_id",
                "source_role",
                "source_snapshot",
                "source_wire_start",
                "source_field",
                "target_wire_start",
                "bit_length",
                "packed_bits_hex",
                "packed_bits_sha256",
                "value_binding_sha256",
                "host_value_binding_checked",
                "native_equality_required",
                "native_equality_executed",
                "production",
            },
            "relocation candidate",
        )
        port_id, target_start, width, role, source_start, source_field = spec
        bits = _decode_bits(current["packed_bits_hex"], width)
        packed = _pack_bits(bits)
        source_bits, source_identity = _source_bits(
            spec,
            shared=shared,
            decoded_tree_pre=decoded_tree_pre,
            tree_post_values=tree_post_values,
        )
        if role == "shared":
            source_identity = candidate.shared_inputs.identity
        if (
            current["format"] != RELOCATION_FORMAT
            or current["implementation_version"] != IMPLEMENTATION_VERSION
            or current["mode"] != MODE
            or current["relation_id"] != RELATION_ID
            or current["profile_fingerprint"] != PROFILE_FINGERPRINT
            or current["plan_sha256"] != PLAN_SHA256
            or current["invocation_sha256"] != INVOCATION_SHA256
            or current["ordinal"] != index
            or current["port_id"] != port_id
            or current["source_role"] != role
            or current["source_snapshot"] != source_identity
            or current["source_wire_start"] != source_start
            or current["source_field"] != source_field
            or current["target_wire_start"] != target_start
            or current["bit_length"] != width
            or current["packed_bits_sha256"] != sha256(packed)
            or current["value_binding_sha256"] != _value_digest(port_id, packed)
            or bits != source_bits
            or current["host_value_binding_checked"] is not True
            or current["native_equality_required"] is not True
            or current["native_equality_executed"] is not False
            or current["production"] is not False
            or canonical_json(current) != snapshot.raw
        ):
            raise GlobalBCandidateSetError("relocation source, target, value, order, or claim mismatch")
        for offset, bit in enumerate(bits):
            wire = target_start + offset
            if wire in target_values:
                raise GlobalBCandidateSetError("relocation target overlap")
            target_values[wire] = bit
    if len(target_values) != sum(spec[2] for spec in RELOCATION_SPECS):
        raise GlobalBCandidateSetError("relocation target coverage mismatch")
    return MappingProxyType(target_values)


def validate_candidate_set_insecure_test_only(
    candidate: GlobalBCandidateSetInsecureTestOnly,
    *,
    expected_handoff_sha256: str,
) -> DecodedGlobalBCandidateSetInsecureTestOnly:
    """Validate one immutable aggregate; no pathname is opened by this function."""
    if type(candidate) is not GlobalBCandidateSetInsecureTestOnly:
        raise GlobalBCandidateSetError("exact Global-B CandidateSet type required")
    handoff = _handoff_document(candidate, expected_handoff_sha256)
    _check_handoff_inventory(candidate, handoff)
    decoded_tree_pre, global_a_values, tree_post_values = _validate_predecessors(candidate)
    shared = _shared_inputs_document(candidate.shared_inputs)
    target_values = _validate_relocations(
        candidate,
        shared=shared,
        decoded_tree_pre=decoded_tree_pre,
        tree_post_values=tree_post_values,
    )
    return DecodedGlobalBCandidateSetInsecureTestOnly(
        MappingProxyType(dict(handoff)),
        shared,
        target_values,
        global_a_values,
        tree_post_values,
    )


def candidate_evidence(
    candidate: GlobalBCandidateSetInsecureTestOnly,
) -> dict[str, object]:
    decoded = validate_candidate_set_insecure_test_only(
        candidate, expected_handoff_sha256=candidate.handoff.identity["sha256"]
    )
    return {
        "format": FORMAT,
        "relation_id": RELATION_ID,
        "mode": MODE,
        "candidate_handoff_identity": candidate.handoff.identity,
        "shared_inputs_identity": candidate.shared_inputs.identity,
        "relocation_candidate_identities": [item.identity for item in candidate.relocations],
        "candidate_snapshot_identity_count": 32,
        "relocation_candidate_count": len(candidate.relocations),
        "relocation_target_value_count": len(decoded.target_values),
        "global_a_owned_values": len(decoded.global_a_values),
        "tree_post_owned_values": [len(values) for values in decoded.tree_post_values],
        "adapter_receipt_prefix_ordinals_verified": [0, 1, 2, 3],
        "tree_post_receipt_branches_verified": [0, 1],
        "same_points_raw_verified": True,
        "same_invocation_profile_plan_verified": True,
        "all_candidate_identity_parse_and_binding_use_same_raw": True,
        "future_executor_must_consume_same_snapshots": True,
        "candidate_pathname_reopen_permitted": False,
        "metadata_proves_no_writer": False,
        "global_b_rows_replayed": 0,
        "global_b_constraints_emitted": 0,
        "native_relocation_equalities_executed": 0,
        "full_execution_receipt_chain_verified": False,
        "global_b_consumer_implemented": False,
        "private_payload_embedded": False,
        "production": False,
    }


def execute_production(*_args: object, **_kwargs: object) -> None:
    raise ProductionUnavailable(
        "Global-B CandidateSet preflight is test-only; production refused before I/O"
    )


def preflight() -> dict[str, object]:
    validate_prerequisites()
    return {
        "format": FORMAT,
        "relation_id": RELATION_ID,
        "read_only_preflight_passed": True,
        "candidate_contract_defined": True,
        "bounded_candidate_fixture_frozen": FROZEN["candidate_handoff_identity"]["bytes"] > 0,
        "same_invocation_profile_plan_required": True,
        "same_points_raw_required": True,
        "adapter_receipt_prefix_ordinals_required": [0, 1, 2, 3],
        "tree_post_receipt_branches_required": [0, 1],
        "relocation_candidates_required": 8,
        "future_executor_must_consume_same_snapshots": True,
        "candidate_pathname_reopen_permitted": False,
        "unified_path_capture_api_implemented": False,
        "global_b_consumer_implemented": False,
        "global_b_constraints_replayed": False,
        "full_execution_receipt_chain_verified": False,
        "safe_to_implement_bounded_global_b_consumer": True,
        "safe_to_execute_bounded_global_b": False,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
        "production_execution_command": None,
        "large_replay_command": None,
        "large_proving_command": None,
        "production_rows_replayed": 0,
        "proofs_generated": 0,
        "Proof-closed": False,
        "Production-closed": False,
        "formal_pi_issue_generated": False,
        "production_legacy18_provider_implemented": False,
        "missing_production_artifacts": list(
            global_a.production_inputs.REQUIRED_EXTERNAL_ARTIFACTS
        ),
        "blockers": [
            "unified single-capture filesystem handoff for both completed roots is not implemented",
            "eight native relocation equality rowsets are defined but not emitted or replayed",
            "independently invocable Global-B consumer and private publication are not implemented",
            "adapter receipts and two tree-post receipts form a branch, not one linear execution chain",
            "production mixed degree-12/13 legacy18 provider is not qualified",
            "fresh parent I1-I5 composition and qualified PQ simulation-extractable backend are absent",
            "production artifacts, independent review, reservation, and large-run authorization are absent",
            "trusted producer handoff, writer quiescence, owner/mode/ACL, writable FDs, and mount controls are external",
        ],
    }


def build_manifest() -> dict[str, object]:
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "mode": MODE,
        "implementation_identities": {
            path: io.read_snapshot(ROOT / path).identity
            for path in (
                "src/pq_rbbc_issuance_global_b_candidateset_preflight_v1.py",
                "tests/test_pq_rbbc_issuance_global_b_candidateset_preflight_v1.py",
            )
        },
        "predecessor_identities": {
            path: {"bytes": size, "sha256": digest}
            for path, (size, digest) in PREDECESSOR_PINS.items()
        },
        "frozen_bounded_candidate": FROZEN,
        "contract": {
            "global_b_wire_interval": list(GLOBAL_B_INTERVAL),
            "global_b_rows_planned": GLOBAL_B_ROWS,
            "relocations": [
                {
                    "ordinal": index,
                    "port_id": spec[0],
                    "target_wire_start": spec[1],
                    "bit_length": spec[2],
                    "source_role": spec[3],
                    "source_wire_start": spec[4],
                    "source_field": spec[5],
                }
                for index, spec in enumerate(RELOCATION_SPECS)
            ],
            "same_raw_for_identity_parse_binding_and_future_consumption": True,
            "single_open_single_bounded_read_required_from_future_capture_api": True,
            "candidate_pathname_reopen_permitted": False,
            "metadata_proves_no_writer": False,
            "trusted_handoff_and_writer_quiescence_external": True,
            "adapter_receipt_prefix_is_not_full_execution_chain": True,
            "native_equality_executed": False,
        },
        "claim_status": {
            "Defined": True,
            "Instantiated": "two-tree-4plus4-insecure-test-only",
            "Implemented": "read-only-aggregate-candidateset-validator",
            "Tested": "bounded-positive-negative-mutation-precompute",
            "Evidence-sealed": "metadata-only",
            "Proof-closed": False,
            "Production-closed": False,
            "global_b_consumer_implemented": False,
            "global_b_constraints_replayed": False,
            "full_execution_receipt_chain_verified": False,
            "production_legacy18_provider_implemented": False,
            "formal_pi_issue_generated": False,
            "qualified_pq_se_backend_integrated": False,
        },
        "artifact_policy": {
            "private_snapshot_or_witness_embedded": False,
            "assignment_br1cs_cache_checkpoint_resume_or_log_created": False,
            "large_replay_or_proving_output_created": False,
            "system_architecture_ticket_lifecycle_or_pq_sat_auth_changed": False,
        },
        "resource_budget": {
            "read_only_checker_seconds_upper_bound": 10,
            "read_only_checker_memory_mib_upper_bound": 128,
            "global_b_rows_executed": 0,
            "production_estimate": None,
        },
        "exact_commands": {
            "read_only": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_global_b_candidateset_preflight_v1.py",
            "targeted": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_global_b_candidateset_preflight_v1 -v",
            "bounded_global_b": None,
            "production": None,
            "large_replay": None,
            "large_proving": None,
        },
        "preflight": preflight(),
    }


def build_portable_evidence() -> dict[str, object]:
    manifest_raw = canonical_json(build_manifest())
    return {
        "format": FORMAT + "-PORTABLE-EVIDENCE",
        "relation_id": RELATION_ID,
        "manifest": {
            "filename": Path(MANIFEST_PATH).name,
            "bytes": len(manifest_raw),
            "sha256": sha256(manifest_raw),
        },
        "bounded_candidate": FROZEN,
        "read_only_preflight": preflight(),
        "private_candidate_raw_or_values_embedded": False,
        "absolute_paths_embedded": False,
        "global_b_constraints_replayed": False,
        "production_rows_replayed": 0,
        "proofs_generated": 0,
        "Proof-closed": False,
        "Production-closed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    print(canonical_json(preflight()).decode("ascii"), end="")


if __name__ == "__main__":
    main()
