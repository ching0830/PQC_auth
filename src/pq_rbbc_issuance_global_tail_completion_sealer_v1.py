#!/usr/bin/env python3
"""Bounded Global-tail completion sealer and parent-input CandidateSet.

This module consumes the already validated immutable Global-B CandidateSet and
the finding-free bounded Global-B publication.  It validates the same captured
snapshot raws, constructs one canonical private parent-input snapshot, and
seals a fixed 36-role inventory.  It emits no relation rows and exposes no
production executor.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from functools import lru_cache
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from types import MappingProxyType
from typing import Mapping, Sequence

import pq_rbbc_issuance_global_b_candidateset_preflight_v1 as candidateset
import pq_rbbc_issuance_global_b_restart_v1 as global_b
import pq_rbbc_launch_io_v2_41 as io


ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION_VERSION = "1.0"
FORMAT = "PQRBBC-ISSUANCE-GLOBAL-TAIL-COMPLETION-SEALER-1"
RELATION_ID = (
    "pq-rbbc/issuance/global-tail-completion-sealer/"
    "multitree-4plus4-insecure-test-only/v1"
)
MODE = "INSECURE-TEST-ONLY"
HANDOFF_FORMAT = FORMAT + "-HANDOFF"
PARENT_INPUT_FORMAT = FORMAT + "-PARENT-INPUT"
HANDOFF_NAME = "global-tail-completion-handoff.private.json"
PARENT_INPUT_NAME = "global-tail-parent-input.private.json"
HANDOFF_LIMIT = 64 * 1024
PARENT_INPUT_LIMIT = 8 * 1024
PROFILE_FINGERPRINT = global_b.PROFILE_FINGERPRINT
PLAN_SHA256 = global_b.PLAN_SHA256
INVOCATION_SHA256 = global_b.INVOCATION_SHA256
DOMAIN_INVENTORY = b"PQ-RBBC/ISSUANCE/GLOBAL-TAIL-COMPLETION/INVENTORY/V1"

GLOBAL_A_ROWS = 19_671
TREE_POST_ROWS = (3_576, 3_576)
NATIVE_RELOCATION_ROWS = 7_826
GLOBAL_B_ROWS = 35_494
SOURCE_ROWS_CHECKED = (
    GLOBAL_A_ROWS
    + sum(TREE_POST_ROWS)
    + NATIVE_RELOCATION_ROWS
    + GLOBAL_B_ROWS
)

MANIFEST_PATH = (
    "manifests/pq_rbbc_issuance_global_tail_completion_sealer_manifest_v1.json"
)
EVIDENCE_PATH = (
    "artifacts/metadata/issuance_global_tail_completion_sealer_v1/"
    "pq_rbbc_issuance_global_tail_completion_sealer_portable_evidence_v1.json"
)

PREDECESSOR_PINS = {
    "src/pq_rbbc_issuance_global_b_restart_v1.py": (
        88_375,
        "9811713e8e2f447b87cee03e683464fd8a9c283f89bfefa4f5e804945324f4e7",
    ),
    "tests/test_pq_rbbc_issuance_global_b_restart_v1.py": (
        19_582,
        "3a9fc30f793c074daa36f6438f75c6e7415b3452996ac7a435bca78e6a968192",
    ),
    global_b.MANIFEST_PATH: (
        5_611,
        "130966bffb46f1b8ac12aa71ecd67f07ab8227b347c43c73a43766d407484254",
    ),
    global_b.EVIDENCE_PATH: (
        3_970,
        "5ee98672052b72e91901dfce25683eb204f230b960f9a5a9bf5acc376b5a18da",
    ),
    "docs/artifacts/PQ_RBBC_ISSUANCE_GLOBAL_B_RESTART_V1_zh-TW.md": (
        7_626,
        "910bee86ff5d35d3667e09c527c07e252e5ec14e38e323963049b9c84fac1588",
    ),
}

SNAPSHOT_ROLE_ORDER = (
    "candidate-handoff",
    "shared-inputs",
    "tree-pre-handoff",
    "tree-pre-result-0",
    "tree-pre-result-1",
    "adapter-receipt-0",
    "adapter-receipt-1",
    "adapter-receipt-2",
    "global-a-result",
    "global-a-points",
    "global-a-receipt",
    "global-a-complete",
    "continuation-0",
    "continuation-1",
    "scheduler-receipt-2",
    "scheduler-receipt-3",
    "scheduler-plan",
    "scheduler-complete",
    "tree-post-0-result",
    "tree-post-0-receipt",
    "tree-post-0-complete",
    "tree-post-1-result",
    "tree-post-1-receipt",
    "tree-post-1-complete",
    "relocation-0",
    "relocation-1",
    "relocation-2",
    "relocation-3",
    "relocation-4",
    "relocation-5",
    "relocation-6",
    "relocation-7",
    "global-b-result",
    "global-b-receipt",
    "global-b-complete",
    "parent-input",
)

SOURCE_IDENTITIES = {
    "candidate_handoff": dict(global_b.FROZEN["candidate_handoff_identity"]),
    "global_b_result": dict(global_b.FROZEN["private_result_identity"]),
    "global_b_receipt": dict(global_b.FROZEN["fragment_receipt_identity"]),
    "global_b_complete": dict(global_b.FROZEN["complete_checkpoint_identity"]),
}

SOURCE_COMPLETE_LINKS = {
    "previous_checkpoint_sha256": (
        "bd45374446c16a4c7321895f13855a1776f916c9815780dd3314e97712853229"
    ),
    "publication_plan_sha256": (
        "27c87d3d8f319a053727ea0464a7d9b0f75f51fc14d7c0c9e657cbd4b2f84e36"
    ),
}

# Filled after the deterministic bounded fixture and implementation identities
# are stable.  These values are metadata only and contain no private raws.
FROZEN = {
    "completion_handoff_identity": {
        "filename": HANDOFF_NAME,
        "bytes": 9_110,
        "sha256": "e81c3b3aa5d7ffc60a00fc61ce9a8063ed3a4f88d591f482ca0e8c8836b1a521",
    },
    "parent_input_identity": {
        "filename": PARENT_INPUT_NAME,
        "bytes": 2_623,
        "sha256": "97c97f163736965b04fac4636b27ab21245ff51a7bb9d240b55f2cba432eda59",
    },
    "snapshot_inventory_sha256": (
        "d10c05b6808b447ebe492b50aea0703bb232d28c91524367c582df734c95ce5f"
    ),
    "snapshot_roles": 36,
    "reviewed_source_snapshots": 35,
    "source_rows_already_checked": SOURCE_ROWS_CHECKED,
    "rows_replayed_by_sealer": 0,
    "parent_constraints_replayed": 0,
    "full_execution_receipt_chain_verified": False,
}


class GlobalTailCompletionError(ValueError):
    """A completion candidate, source snapshot, or parent input was rejected."""


class ProductionUnavailable(RuntimeError):
    """This bounded checkpoint intentionally exposes no production API."""


@dataclass(frozen=True)
class GlobalTailParentCandidateSetInsecureTestOnly:
    handoff: io.Snapshot
    parent_input: io.Snapshot
    source_candidate: candidateset.GlobalBCandidateSetInsecureTestOnly
    global_b_result: global_b.PublishedGlobalBResultInsecureTestOnly

    def __post_init__(self) -> None:
        if (
            type(self.handoff) is not io.Snapshot
            or type(self.parent_input) is not io.Snapshot
            or type(self.source_candidate)
            is not candidateset.GlobalBCandidateSetInsecureTestOnly
            or type(self.global_b_result)
            is not global_b.PublishedGlobalBResultInsecureTestOnly
        ):
            raise GlobalTailCompletionError(
                "exact immutable Global-tail parent CandidateSet required"
            )


@dataclass(frozen=True)
class DecodedGlobalTailParentCandidateSetInsecureTestOnly:
    handoff: Mapping[str, object]
    parent_input: Mapping[str, object]
    snapshot_identities: tuple[Mapping[str, object], ...]
    c_r: bytes
    request_hash: bytes


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
        raise GlobalTailCompletionError(label + " must be a lowercase SHA-256")
    return value


def _exact(value: object, fields: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise GlobalTailCompletionError(label + " closed schema mismatch")
    return value


def _freeze_json(value: object) -> object:
    """Detach and recursively freeze a validated JSON value for consumers."""
    if type(value) is dict:
        return MappingProxyType(
            {str(key): _freeze_json(item) for key, item in value.items()}
        )
    if type(value) is list:
        return tuple(_freeze_json(item) for item in value)
    return value


def _require_exact_int(value: object, expected: int, label: str) -> None:
    if not _is_int(value) or value != expected:
        raise GlobalTailCompletionError(label + " exact integer mismatch")


def _require_exact_int_list(
    value: object, expected: Sequence[int], label: str
) -> None:
    if (
        type(value) is not list
        or len(value) != len(expected)
        or any(not _is_int(item) for item in value)
        or value != list(expected)
    ):
        raise GlobalTailCompletionError(label + " exact integer list mismatch")


def _snapshot(name: str, raw: bytes, limit: int) -> io.Snapshot:
    if type(raw) is not bytes or not 0 < len(raw) <= limit:
        raise GlobalTailCompletionError("snapshot byte bound: " + name)
    return io.Snapshot(Path("/in-memory-insecure-test-only") / name, raw)


def _identity(snapshot: io.Snapshot, name: str, limit: int) -> dict[str, object]:
    if (
        type(snapshot) is not io.Snapshot
        or snapshot.location.name != name
        or not 0 < len(snapshot.raw) <= limit
    ):
        raise GlobalTailCompletionError("snapshot name/type/size mismatch: " + name)
    return snapshot.identity


def _identity_document(value: object, label: str) -> dict[str, object]:
    current = _exact(value, {"filename", "bytes", "sha256"}, label)
    if (
        type(current["filename"]) is not str
        or not current["filename"]
        or "/" in current["filename"]
        or not _is_int(current["bytes"])
        or not 0 < current["bytes"] <= global_b.INPUT_LIMIT
    ):
        raise GlobalTailCompletionError(label + " invalid identity")
    _digest(current["sha256"], label)
    return current


def _require_identity(
    snapshot: io.Snapshot, expected: Mapping[str, object], *, limit: int
) -> None:
    if _identity(snapshot, str(expected["filename"]), limit) != expected:
        raise GlobalTailCompletionError(
            "frozen source snapshot identity mismatch: " + str(expected["filename"])
        )


def validate_prerequisites() -> None:
    global_b.validate_prerequisites()
    for path, (expected_bytes, expected_sha256) in PREDECESSOR_PINS.items():
        snapshot = io.read_snapshot(ROOT / path)
        if (len(snapshot.raw), sha256(snapshot.raw)) != (
            expected_bytes,
            expected_sha256,
        ):
            raise GlobalTailCompletionError("predecessor identity drift: " + path)


def _decode_lower_hex(value: object, expected_bytes: int, label: str) -> bytes:
    if type(value) is not str or len(value) != 2 * expected_bytes:
        raise GlobalTailCompletionError(label + " encoded length mismatch")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise GlobalTailCompletionError(label + " is not lowercase hex") from error
    if raw.hex() != value:
        raise GlobalTailCompletionError(label + " requires lowercase hex")
    return raw


def _validate_complete_checkpoint(
    snapshot: io.Snapshot,
    source_candidate: candidateset.GlobalBCandidateSetInsecureTestOnly,
    published: global_b.PublishedGlobalBResultInsecureTestOnly,
) -> Mapping[str, object]:
    _require_identity(
        snapshot,
        SOURCE_IDENTITIES["global_b_complete"],
        limit=global_b.CHECKPOINT_LIMIT,
    )
    try:
        current = snapshot.document()
    except io.ValidationError as error:
        raise GlobalTailCompletionError(
            "Global-B complete checkpoint is not strict canonical JSON"
        ) from error
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
            "publication_plan_sha256",
            "input_inventory",
            "output_identities",
            "next_stage",
            "complete",
            "production",
        },
        "Global-B complete checkpoint",
    )
    inventory = global_b._validate_input_inventory(current["input_inventory"])
    expected_inventory = global_b._input_inventory(source_candidate)
    outputs = current["output_identities"]
    if type(outputs) is not list or len(outputs) != 2:
        raise GlobalTailCompletionError("Global-B complete output inventory")
    for identity in outputs:
        _identity_document(identity, "Global-B complete output identity")
    _require_exact_int(current["ordinal"], 3, "Global-B complete ordinal")
    if (
        current["format"] != global_b.CHECKPOINT_FORMAT
        or current["implementation_version"] != global_b.IMPLEMENTATION_VERSION
        or current["mode"] != global_b.MODE
        or current["relation_id"] != global_b.RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["plan_sha256"] != PLAN_SHA256
        or current["invocation_sha256"] != INVOCATION_SHA256
        or current["stage_id"] != "complete"
        or current["previous_checkpoint_sha256"]
        != SOURCE_COMPLETE_LINKS["previous_checkpoint_sha256"]
        or current["publication_plan_sha256"]
        != SOURCE_COMPLETE_LINKS["publication_plan_sha256"]
        or inventory != expected_inventory
        or outputs != [published.result.identity, published.receipt.identity]
        or current["next_stage"] is not None
        or current["complete"] is not True
        or current["production"] is not False
        or canonical_json(current) != snapshot.raw
    ):
        raise GlobalTailCompletionError(
            "Global-B complete domain, inventory, link, or claim mismatch"
        )
    return MappingProxyType(dict(current))


def _validate_sources(
    source_candidate: candidateset.GlobalBCandidateSetInsecureTestOnly,
    published: global_b.PublishedGlobalBResultInsecureTestOnly,
) -> tuple[bytes, bytes]:
    if (
        type(source_candidate) is not candidateset.GlobalBCandidateSetInsecureTestOnly
        or type(published) is not global_b.PublishedGlobalBResultInsecureTestOnly
    ):
        raise GlobalTailCompletionError("exact reviewed Global-B sources required")
    _require_identity(
        source_candidate.handoff,
        SOURCE_IDENTITIES["candidate_handoff"],
        limit=candidateset.HANDOFF_LIMIT,
    )
    candidateset.validate_candidate_set_insecure_test_only(
        source_candidate,
        expected_handoff_sha256=str(
            SOURCE_IDENTITIES["candidate_handoff"]["sha256"]
        ),
    )
    _require_identity(
        published.result,
        SOURCE_IDENTITIES["global_b_result"],
        limit=global_b.PRIVATE_RESULT_LIMIT,
    )
    _require_identity(
        published.receipt,
        SOURCE_IDENTITIES["global_b_receipt"],
        limit=global_b.FRAGMENT_RECEIPT_LIMIT,
    )
    receipt_document = global_b._validate_fragment_receipt(
        published.receipt,
        expected_identity=SOURCE_IDENTITIES["global_b_receipt"],
        handoff_sha256=str(SOURCE_IDENTITIES["candidate_handoff"]["sha256"]),
    )
    values, commitment, request_hash = global_b._validate_private_result(
        published.result,
        expected_identity=SOURCE_IDENTITIES["global_b_result"],
        receipt_snapshot=published.receipt,
        receipt_document=receipt_document,
        handoff_sha256=str(SOURCE_IDENTITIES["candidate_handoff"]["sha256"]),
    )
    if (
        type(published.owned_values) is not tuple
        or any(not _is_int(value) for value in published.owned_values)
        or tuple(published.owned_values) != values
        or type(published.commitment) is not bytes
        or published.commitment != commitment
        or type(published.request_hash) is not bytes
        or published.request_hash != request_hash
    ):
        raise GlobalTailCompletionError(
            "published Global-B object differs from its immutable snapshots"
        )
    _validate_complete_checkpoint(
        published.complete_checkpoint, source_candidate, published
    )
    return commitment, request_hash


def _parent_input_snapshot(
    source_candidate: candidateset.GlobalBCandidateSetInsecureTestOnly,
    published: global_b.PublishedGlobalBResultInsecureTestOnly,
    commitment: bytes,
    request_hash: bytes,
) -> io.Snapshot:
    document = {
        "format": PARENT_INPUT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "plan_sha256": PLAN_SHA256,
        "invocation_sha256": INVOCATION_SHA256,
        "stage_id": "global-tail-parent-input",
        "next_stage": "fresh-parent-i1-i5-candidateset",
        "source_candidate_handoff_sha256": source_candidate.handoff.identity["sha256"],
        "source_global_b_result_sha256": published.result.identity["sha256"],
        "source_global_b_receipt_sha256": published.receipt.identity["sha256"],
        "source_global_b_complete_sha256": published.complete_checkpoint.identity[
            "sha256"
        ],
        "c_r_encoding": "511-byte-canonical-cap-commitment",
        "c_r_bytes": len(commitment),
        "c_r_hex": commitment.hex(),
        "c_r_sha256": sha256(commitment),
        "request_hash_encoding": "72-byte-little-endian-binary-vector",
        "request_hash_bytes": len(request_hash),
        "request_hash_hex": request_hash.hex(),
        "request_hash_sha256": sha256(request_hash),
        "future_parent_must_consume_same_snapshot": True,
        "parent_constraints_replayed": 0,
        "private_payload": True,
        "production": False,
    }
    return _snapshot(
        PARENT_INPUT_NAME, canonical_json(document), PARENT_INPUT_LIMIT
    )


def _validate_parent_input(
    snapshot: io.Snapshot,
    source_candidate: candidateset.GlobalBCandidateSetInsecureTestOnly,
    published: global_b.PublishedGlobalBResultInsecureTestOnly,
    commitment: bytes,
    request_hash: bytes,
) -> Mapping[str, object]:
    _identity(snapshot, PARENT_INPUT_NAME, PARENT_INPUT_LIMIT)
    try:
        current = snapshot.document()
    except io.ValidationError as error:
        raise GlobalTailCompletionError(
            "parent input is not strict canonical JSON"
        ) from error
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
            "source_candidate_handoff_sha256",
            "source_global_b_result_sha256",
            "source_global_b_receipt_sha256",
            "source_global_b_complete_sha256",
            "c_r_encoding",
            "c_r_bytes",
            "c_r_hex",
            "c_r_sha256",
            "request_hash_encoding",
            "request_hash_bytes",
            "request_hash_hex",
            "request_hash_sha256",
            "future_parent_must_consume_same_snapshot",
            "parent_constraints_replayed",
            "private_payload",
            "production",
        },
        "parent input",
    )
    _require_exact_int(current["c_r_bytes"], 511, "parent c_r bytes")
    _require_exact_int(
        current["request_hash_bytes"], 72, "parent request-hash bytes"
    )
    _require_exact_int(
        current["parent_constraints_replayed"], 0, "parent replay claim"
    )
    decoded_commitment = _decode_lower_hex(current["c_r_hex"], 511, "parent c_r")
    decoded_request_hash = _decode_lower_hex(
        current["request_hash_hex"], 72, "parent request hash"
    )
    for field in (
        "source_candidate_handoff_sha256",
        "source_global_b_result_sha256",
        "source_global_b_receipt_sha256",
        "source_global_b_complete_sha256",
        "c_r_sha256",
        "request_hash_sha256",
    ):
        _digest(current[field], "parent input " + field)
    if (
        current["format"] != PARENT_INPUT_FORMAT
        or current["implementation_version"] != IMPLEMENTATION_VERSION
        or current["mode"] != MODE
        or current["relation_id"] != RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["plan_sha256"] != PLAN_SHA256
        or current["invocation_sha256"] != INVOCATION_SHA256
        or current["stage_id"] != "global-tail-parent-input"
        or current["next_stage"] != "fresh-parent-i1-i5-candidateset"
        or current["source_candidate_handoff_sha256"]
        != source_candidate.handoff.identity["sha256"]
        or current["source_global_b_result_sha256"]
        != published.result.identity["sha256"]
        or current["source_global_b_receipt_sha256"]
        != published.receipt.identity["sha256"]
        or current["source_global_b_complete_sha256"]
        != published.complete_checkpoint.identity["sha256"]
        or current["c_r_encoding"] != "511-byte-canonical-cap-commitment"
        or decoded_commitment != commitment
        or current["c_r_sha256"] != sha256(commitment)
        or current["request_hash_encoding"]
        != "72-byte-little-endian-binary-vector"
        or decoded_request_hash != request_hash
        or current["request_hash_sha256"] != sha256(request_hash)
        or current["future_parent_must_consume_same_snapshot"] is not True
        or current["private_payload"] is not True
        or current["production"] is not False
        or canonical_json(current) != snapshot.raw
    ):
        raise GlobalTailCompletionError(
            "parent input source, output, domain, or claim mismatch"
        )
    return MappingProxyType(dict(current))


def _snapshot_roles(
    source_candidate: candidateset.GlobalBCandidateSetInsecureTestOnly,
    published: global_b.PublishedGlobalBResultInsecureTestOnly,
    parent_input: io.Snapshot,
) -> tuple[tuple[str, io.Snapshot], ...]:
    roles = list(global_b._candidate_roles(source_candidate))
    roles.extend(
        (
            ("global-b-result", published.result),
            ("global-b-receipt", published.receipt),
            ("global-b-complete", published.complete_checkpoint),
            ("parent-input", parent_input),
        )
    )
    frozen = tuple(roles)
    if tuple(role for role, _ in frozen) != SNAPSHOT_ROLE_ORDER:
        raise GlobalTailCompletionError("canonical 36-role completion order required")
    return frozen


def _inventory_document(
    roles: Sequence[tuple[str, io.Snapshot]],
) -> list[dict[str, object]]:
    return [
        {
            "ordinal": index,
            "role": role,
            "snapshot_identity": snapshot.identity,
        }
        for index, (role, snapshot) in enumerate(roles)
    ]


def _inventory_digest(inventory: Sequence[Mapping[str, object]]) -> str:
    raw = canonical_json(list(inventory))
    return sha256(DOMAIN_INVENTORY + len(raw).to_bytes(8, "big") + raw)


def _handoff_snapshot(
    source_candidate: candidateset.GlobalBCandidateSetInsecureTestOnly,
    published: global_b.PublishedGlobalBResultInsecureTestOnly,
    parent_input: io.Snapshot,
) -> io.Snapshot:
    roles = _snapshot_roles(source_candidate, published, parent_input)
    inventory = _inventory_document(roles)
    document = {
        "format": HANDOFF_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "plan_sha256": PLAN_SHA256,
        "invocation_sha256": INVOCATION_SHA256,
        "stage_id": "global-tail-complete",
        "next_stage": "fresh-parent-i1-i5-candidateset",
        "source_candidate_handoff_sha256": source_candidate.handoff.identity["sha256"],
        "global_b_complete_checkpoint_identity": published.complete_checkpoint.identity,
        "parent_input_identity": parent_input.identity,
        "snapshot_inventory": inventory,
        "snapshot_inventory_sha256": _inventory_digest(inventory),
        "receipt_graph": {
            "kind": "ordinal-chain-with-two-tree-post-branches-and-global-b-terminal",
            "adapter_receipt_ordinals": [0, 1, 2, 3],
            "tree_post_branches": [0, 1],
            "ordinal_2_overlap_sha256": source_candidate.adapter_receipt_prefix[
                2
            ].identity["sha256"],
            "global_b_terminal_receipt": published.receipt.identity,
            "full_execution_receipt_chain_verified": False,
        },
        "source_execution_summary": {
            "global_a_rows": GLOBAL_A_ROWS,
            "tree_post_rows": list(TREE_POST_ROWS),
            "native_relocation_rows": NATIVE_RELOCATION_ROWS,
            "global_b_rows": GLOBAL_B_ROWS,
            "source_rows_already_checked": SOURCE_ROWS_CHECKED,
            "rows_replayed_by_sealer": 0,
            "parent_constraints_replayed": 0,
        },
        "all_identity_parse_binding_use_same_raw": True,
        "future_parent_must_consume_same_snapshots": True,
        "candidate_pathname_reopen_permitted": False,
        "metadata_proves_no_writer": False,
        "private_payload": True,
        "production": False,
    }
    return _snapshot(HANDOFF_NAME, canonical_json(document), HANDOFF_LIMIT)


def _validate_inventory(value: object) -> list[dict[str, object]]:
    if type(value) is not list or len(value) != len(SNAPSHOT_ROLE_ORDER):
        raise GlobalTailCompletionError("completion snapshot inventory length")
    result = []
    seen_roles: set[str] = set()
    for index, item in enumerate(value):
        current = _exact(
            item,
            {"ordinal", "role", "snapshot_identity"},
            "completion snapshot descriptor",
        )
        _require_exact_int(current["ordinal"], index, "completion snapshot ordinal")
        if (
            type(current["role"]) is not str
            or current["role"] != SNAPSHOT_ROLE_ORDER[index]
            or current["role"] in seen_roles
        ):
            raise GlobalTailCompletionError("completion snapshot role order")
        _identity_document(
            current["snapshot_identity"], "completion snapshot identity"
        )
        seen_roles.add(current["role"])
        result.append(current)
    return result


def _handoff_document(
    snapshot: io.Snapshot, expected_handoff_sha256: str
) -> Mapping[str, object]:
    _digest(expected_handoff_sha256, "external completion handoff")
    _identity(snapshot, HANDOFF_NAME, HANDOFF_LIMIT)
    if snapshot.identity["sha256"] != expected_handoff_sha256:
        raise GlobalTailCompletionError("handoff digest rejected before dependencies")
    try:
        current = snapshot.document()
    except io.ValidationError as error:
        raise GlobalTailCompletionError(
            "completion handoff is not strict canonical JSON"
        ) from error
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
            "source_candidate_handoff_sha256",
            "global_b_complete_checkpoint_identity",
            "parent_input_identity",
            "snapshot_inventory",
            "snapshot_inventory_sha256",
            "receipt_graph",
            "source_execution_summary",
            "all_identity_parse_binding_use_same_raw",
            "future_parent_must_consume_same_snapshots",
            "candidate_pathname_reopen_permitted",
            "metadata_proves_no_writer",
            "private_payload",
            "production",
        },
        "completion handoff",
    )
    inventory = _validate_inventory(current["snapshot_inventory"])
    _digest(current["source_candidate_handoff_sha256"], "source handoff")
    _digest(current["snapshot_inventory_sha256"], "snapshot inventory")
    _identity_document(
        current["global_b_complete_checkpoint_identity"],
        "Global-B complete identity",
    )
    _identity_document(current["parent_input_identity"], "parent-input identity")
    graph = _exact(
        current["receipt_graph"],
        {
            "kind",
            "adapter_receipt_ordinals",
            "tree_post_branches",
            "ordinal_2_overlap_sha256",
            "global_b_terminal_receipt",
            "full_execution_receipt_chain_verified",
        },
        "completion receipt graph",
    )
    _require_exact_int_list(
        graph["adapter_receipt_ordinals"], (0, 1, 2, 3), "receipt ordinals"
    )
    _require_exact_int_list(
        graph["tree_post_branches"], (0, 1), "tree-post branches"
    )
    _digest(graph["ordinal_2_overlap_sha256"], "ordinal-2 overlap")
    _identity_document(
        graph["global_b_terminal_receipt"], "Global-B terminal receipt"
    )
    summary = _exact(
        current["source_execution_summary"],
        {
            "global_a_rows",
            "tree_post_rows",
            "native_relocation_rows",
            "global_b_rows",
            "source_rows_already_checked",
            "rows_replayed_by_sealer",
            "parent_constraints_replayed",
        },
        "source execution summary",
    )
    _require_exact_int(summary["global_a_rows"], GLOBAL_A_ROWS, "Global-A rows")
    _require_exact_int_list(summary["tree_post_rows"], TREE_POST_ROWS, "tree-post rows")
    _require_exact_int(
        summary["native_relocation_rows"],
        NATIVE_RELOCATION_ROWS,
        "native relocation rows",
    )
    _require_exact_int(summary["global_b_rows"], GLOBAL_B_ROWS, "Global-B rows")
    _require_exact_int(
        summary["source_rows_already_checked"],
        SOURCE_ROWS_CHECKED,
        "source rows already checked",
    )
    _require_exact_int(summary["rows_replayed_by_sealer"], 0, "sealer replay rows")
    _require_exact_int(
        summary["parent_constraints_replayed"], 0, "parent replay rows"
    )
    if (
        current["format"] != HANDOFF_FORMAT
        or current["implementation_version"] != IMPLEMENTATION_VERSION
        or current["mode"] != MODE
        or current["relation_id"] != RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["plan_sha256"] != PLAN_SHA256
        or current["invocation_sha256"] != INVOCATION_SHA256
        or current["stage_id"] != "global-tail-complete"
        or current["next_stage"] != "fresh-parent-i1-i5-candidateset"
        or current["snapshot_inventory_sha256"] != _inventory_digest(inventory)
        or graph["kind"]
        != "ordinal-chain-with-two-tree-post-branches-and-global-b-terminal"
        or graph["full_execution_receipt_chain_verified"] is not False
        or current["all_identity_parse_binding_use_same_raw"] is not True
        or current["future_parent_must_consume_same_snapshots"] is not True
        or current["candidate_pathname_reopen_permitted"] is not False
        or current["metadata_proves_no_writer"] is not False
        or current["private_payload"] is not True
        or current["production"] is not False
        or canonical_json(current) != snapshot.raw
    ):
        raise GlobalTailCompletionError(
            "completion handoff domain, graph, inventory, or claim mismatch"
        )
    return MappingProxyType(dict(current))


def _check_handoff_inventory(
    candidate: GlobalTailParentCandidateSetInsecureTestOnly,
    handoff: Mapping[str, object],
) -> tuple[Mapping[str, object], ...]:
    roles = _snapshot_roles(
        candidate.source_candidate,
        candidate.global_b_result,
        candidate.parent_input,
    )
    inventory = _validate_inventory(handoff["snapshot_inventory"])
    identities = []
    for (expected_role, snapshot), descriptor in zip(roles, inventory):
        if (
            descriptor["role"] != expected_role
            or descriptor["snapshot_identity"] != snapshot.identity
        ):
            raise GlobalTailCompletionError(
                "completion handoff role or snapshot identity mismatch"
            )
        identities.append(MappingProxyType(dict(snapshot.identity)))
    return tuple(identities)


def _check_handoff_bindings(
    candidate: GlobalTailParentCandidateSetInsecureTestOnly,
    handoff: Mapping[str, object],
) -> None:
    graph = handoff["receipt_graph"]
    if (
        handoff["source_candidate_handoff_sha256"]
        != candidate.source_candidate.handoff.identity["sha256"]
        or handoff["global_b_complete_checkpoint_identity"]
        != candidate.global_b_result.complete_checkpoint.identity
        or handoff["parent_input_identity"] != candidate.parent_input.identity
        or graph["ordinal_2_overlap_sha256"]
        != candidate.source_candidate.adapter_receipt_prefix[2].identity["sha256"]
        or graph["global_b_terminal_receipt"]
        != candidate.global_b_result.receipt.identity
    ):
        raise GlobalTailCompletionError(
            "completion handoff source, graph, or parent binding mismatch"
        )


def build_parent_candidate_set_insecure_test_only(
    *,
    source_candidate: candidateset.GlobalBCandidateSetInsecureTestOnly,
    global_b_result: global_b.PublishedGlobalBResultInsecureTestOnly,
) -> GlobalTailParentCandidateSetInsecureTestOnly:
    """Build the bounded candidate in memory without reopening source paths."""
    validate_prerequisites()
    commitment, request_hash = _validate_sources(source_candidate, global_b_result)
    parent_input = _parent_input_snapshot(
        source_candidate,
        global_b_result,
        commitment,
        request_hash,
    )
    _validate_parent_input(
        parent_input,
        source_candidate,
        global_b_result,
        commitment,
        request_hash,
    )
    handoff = _handoff_snapshot(source_candidate, global_b_result, parent_input)
    candidate = GlobalTailParentCandidateSetInsecureTestOnly(
        handoff, parent_input, source_candidate, global_b_result
    )
    validate_parent_candidate_set_insecure_test_only(
        candidate, expected_handoff_sha256=handoff.identity["sha256"]
    )
    return candidate


def validate_parent_candidate_set_insecure_test_only(
    candidate: GlobalTailParentCandidateSetInsecureTestOnly,
    *,
    expected_handoff_sha256: str,
) -> DecodedGlobalTailParentCandidateSetInsecureTestOnly:
    """Validate captured raws only; no pathname is opened and no row is replayed."""
    if type(candidate) is not GlobalTailParentCandidateSetInsecureTestOnly:
        raise GlobalTailCompletionError("exact parent CandidateSet type required")
    handoff = _handoff_document(candidate.handoff, expected_handoff_sha256)
    identities = _check_handoff_inventory(candidate, handoff)
    commitment, request_hash = _validate_sources(
        candidate.source_candidate, candidate.global_b_result
    )
    parent_input = _validate_parent_input(
        candidate.parent_input,
        candidate.source_candidate,
        candidate.global_b_result,
        commitment,
        request_hash,
    )
    _check_handoff_bindings(candidate, handoff)
    return DecodedGlobalTailParentCandidateSetInsecureTestOnly(
        _freeze_json(dict(handoff)),
        _freeze_json(dict(parent_input)),
        identities,
        commitment,
        request_hash,
    )


def candidate_evidence(
    candidate: GlobalTailParentCandidateSetInsecureTestOnly,
) -> dict[str, object]:
    decoded = validate_parent_candidate_set_insecure_test_only(
        candidate, expected_handoff_sha256=candidate.handoff.identity["sha256"]
    )
    return {
        "format": FORMAT,
        "relation_id": RELATION_ID,
        "mode": MODE,
        "completion_handoff_identity": candidate.handoff.identity,
        "parent_input_identity": candidate.parent_input.identity,
        "source_candidate_handoff_identity": candidate.source_candidate.handoff.identity,
        "source_global_b_result_identity": candidate.global_b_result.result.identity,
        "source_global_b_receipt_identity": candidate.global_b_result.receipt.identity,
        "source_global_b_complete_identity": candidate.global_b_result.complete_checkpoint.identity,
        "snapshot_inventory_sha256": decoded.handoff["snapshot_inventory_sha256"],
        "snapshot_roles": len(decoded.snapshot_identities),
        "reviewed_source_snapshots": len(decoded.snapshot_identities) - 1,
        "source_rows_already_checked": SOURCE_ROWS_CHECKED,
        "rows_replayed_by_sealer": 0,
        "parent_constraints_replayed": 0,
        "c_r_sha256": sha256(decoded.c_r),
        "request_hash_sha256": sha256(decoded.request_hash),
        "same_invocation_profile_plan_verified": True,
        "all_identity_parse_binding_use_same_raw": True,
        "future_parent_must_consume_same_snapshots": True,
        "candidate_pathname_reopen_permitted": False,
        "terminal_checkpoint_exact_identity_and_declared_links_checked": True,
        "full_filesystem_journal_recaptured": False,
        "receipt_graph_kind": decoded.handoff["receipt_graph"]["kind"],
        "full_execution_receipt_chain_verified": False,
        "private_snapshot_raws_embedded": False,
        "private_parent_input_embedded": False,
        "production": False,
    }


def execute_production(*_args: object, **_kwargs: object) -> None:
    raise ProductionUnavailable(
        "bounded completion sealer is test-only; production refused before I/O"
    )


def preflight() -> dict[str, object]:
    validate_prerequisites()
    return {
        "format": FORMAT,
        "relation_id": RELATION_ID,
        "read_only_preflight_passed": True,
        "global_b_finding_free_successor_pinned": True,
        "bounded_completion_sealer_implemented": True,
        "parent_input_candidate_contract_defined": True,
        "canonical_snapshot_roles": len(SNAPSHOT_ROLE_ORDER),
        "same_invocation_profile_plan_required": True,
        "future_parent_must_consume_same_snapshots": True,
        "candidate_pathname_reopen_permitted": False,
        "full_filesystem_journal_recaptured": False,
        "full_execution_receipt_chain_verified": False,
        "rows_replayed_by_sealer": 0,
        "parent_constraints_replayed": 0,
        "fresh_parent_i1_i5_composition_implemented": False,
        "safe_to_start_parent_relation_replay": False,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
        "production_execution_command": None,
        "large_replay_command": None,
        "large_proving_command": None,
        "production_rows_replayed": 0,
        "proofs_generated": 0,
        "formal_pi_issue_generated": False,
        "production_legacy18_provider_implemented": False,
        "Proof-closed": False,
        "Production-closed": False,
        "blockers": [
            "completion-sealer exact commit requires finding-free independent re-review",
            "fresh parent I1-I5 CandidateSet and relation consumer are not implemented",
            "receipt evidence is a branch graph, not one linear execution chain",
            "production mixed degree-12/13 legacy18 provider is not qualified",
            "qualified PQ simulation-extractable backend and formal pi_issue are absent",
            "production artifacts, review, reservation, authorization, and large-run qualification are absent",
            "trusted handoff, writer quiescence, permissions, writable FDs, and mount controls are external",
        ],
    }


def _fixture_candidate_insecure_test_only() -> tuple[
    object,
    TemporaryDirectory[str],
    GlobalTailParentCandidateSetInsecureTestOnly,
]:
    """Authoring-only deterministic fixture; never used by the validator."""
    session, temporary, source_candidate = (
        global_b._fixture_candidate_insecure_test_only()
    )
    root = Path(temporary.name)
    published = global_b.run_bounded_global_b(
        root / "global-b",
        artifact_root=root,
        fresh_candidate=source_candidate,
        expected_handoff_sha256=source_candidate.handoff.identity["sha256"],
        fresh_output=True,
    )
    if published is None:
        session.close()
        temporary.cleanup()
        raise GlobalTailCompletionError("bounded Global-B fixture did not complete")
    candidate = build_parent_candidate_set_insecure_test_only(
        source_candidate=source_candidate,
        global_b_result=published,
    )
    return session, temporary, candidate


@lru_cache(maxsize=1)
def bounded_self_check() -> dict[str, object]:
    session, temporary, candidate = _fixture_candidate_insecure_test_only()
    try:
        evidence = candidate_evidence(candidate)
        expected = {
            "completion_handoff_identity": FROZEN["completion_handoff_identity"],
            "parent_input_identity": FROZEN["parent_input_identity"],
            "snapshot_inventory_sha256": FROZEN["snapshot_inventory_sha256"],
            "snapshot_roles": FROZEN["snapshot_roles"],
            "reviewed_source_snapshots": FROZEN["reviewed_source_snapshots"],
            "source_rows_already_checked": FROZEN["source_rows_already_checked"],
            "rows_replayed_by_sealer": FROZEN["rows_replayed_by_sealer"],
            "parent_constraints_replayed": FROZEN["parent_constraints_replayed"],
            "full_execution_receipt_chain_verified": FROZEN[
                "full_execution_receipt_chain_verified"
            ],
        }
        if FROZEN["completion_handoff_identity"]["bytes"]:
            for key, value in expected.items():
                if evidence[key] != value:
                    raise GlobalTailCompletionError(
                        "frozen bounded completion evidence drift: " + key
                    )
        return evidence
    finally:
        session.close()
        temporary.cleanup()


def build_manifest() -> dict[str, object]:
    qualification = bounded_self_check()
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "mode": MODE,
        "implementation_identities": {
            path: io.read_snapshot(ROOT / path).identity
            for path in (
                "src/pq_rbbc_issuance_global_tail_completion_sealer_v1.py",
                "tests/test_pq_rbbc_issuance_global_tail_completion_sealer_v1.py",
            )
        },
        "predecessor_identities": {
            path: {"bytes": size, "sha256": digest}
            for path, (size, digest) in PREDECESSOR_PINS.items()
        },
        "frozen_bounded_qualification": qualification,
        "contract": {
            "snapshot_role_order": list(SNAPSHOT_ROLE_ORDER),
            "reviewed_source_snapshots": 35,
            "parent_input_snapshots": 1,
            "source_rows_already_checked": SOURCE_ROWS_CHECKED,
            "rows_replayed_by_sealer": 0,
            "parent_constraints_replayed": 0,
            "same_raw_for_identity_parse_binding_and_future_consumption": True,
            "candidate_pathname_reopen_permitted": False,
            "terminal_checkpoint_exact_identity_and_declared_links_checked": True,
            "full_filesystem_journal_recaptured": False,
            "receipt_graph_is_not_linear_full_execution_chain": True,
            "metadata_proves_no_writer": False,
            "trusted_handoff_and_writer_quiescence_external": True,
        },
        "claim_status": {
            "Defined": True,
            "Instantiated": "two-tree-4plus4-insecure-test-only",
            "Implemented": "bounded-completion-sealer-and-parent-input-candidateset",
            "Tested": "positive-negative-mutation-wrong-domain-order-binding-precompute",
            "Evidence-sealed": "metadata-only",
            "Proof-closed": False,
            "Production-closed": False,
            "fresh_parent_i1_i5_composition_implemented": False,
            "parent_constraints_replayed": 0,
            "full_execution_receipt_chain_verified": False,
            "production_legacy18_provider_implemented": False,
            "formal_pi_issue_generated": False,
            "qualified_pq_se_backend_integrated": False,
        },
        "artifact_policy": {
            "private_snapshot_or_parent_input_embedded": False,
            "assignment_br1cs_cache_checkpoint_resume_or_log_created": False,
            "large_replay_or_proving_output_created": False,
            "other_tree_observed_stream_bytes_used": False,
            "historical_v238_v239_rewritten": False,
            "system_architecture_ticket_lifecycle_or_pq_sat_auth_changed": False,
        },
        "resource_budget": {
            "bounded_source_rows_already_checked": SOURCE_ROWS_CHECKED,
            "new_relation_rows": 0,
            "expected_wall_seconds_upper_bound": 120,
            "expected_peak_rss_mib_upper_bound": 1024,
            "production_estimate": None,
        },
        "exact_commands": {
            "read_only": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_global_tail_completion_sealer_v1.py",
            "bounded": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_global_tail_completion_sealer_v1.py --bounded-self-check",
            "targeted": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_global_tail_completion_sealer_v1 -v",
            "parent_replay": None,
            "production": None,
            "large_replay": None,
            "large_proving": None,
        },
        "preflight": preflight(),
    }


def build_portable_evidence() -> dict[str, object]:
    manifest = build_manifest()
    manifest_raw = canonical_json(manifest)
    return {
        "format": FORMAT + "-PORTABLE-EVIDENCE",
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "mode": MODE,
        "manifest": {
            "filename": Path(MANIFEST_PATH).name,
            "bytes": len(manifest_raw),
            "sha256": sha256(manifest_raw),
        },
        "implementation_identities": manifest["implementation_identities"],
        "predecessor_identities": manifest["predecessor_identities"],
        "bounded_qualification": manifest["frozen_bounded_qualification"],
        "claim_status": manifest["claim_status"],
        "portable_metadata_only": True,
        "private_snapshot_raws_embedded": False,
        "private_parent_input_embedded": False,
        "absolute_paths_embedded": False,
        "assignment_br1cs_cache_checkpoint_resume_or_log_embedded": False,
        "production_rows_replayed": 0,
        "proofs_generated": 0,
        "formal_pi_issue_generated": False,
        "full_execution_receipt_chain_verified": False,
        "Proof-closed": False,
        "Production-closed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bounded-self-check", action="store_true")
    arguments = parser.parse_args()
    report = {"preflight": preflight()}
    if arguments.bounded_self_check:
        report["bounded"] = bounded_self_check()
    print(canonical_json(report).decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
