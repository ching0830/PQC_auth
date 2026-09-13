#!/usr/bin/env python3
"""Bounded native constraint-stream split lowerer for issuance CAP.

This checkpoint classifies the existing production-width, one-tree, four-leaf
insecure test-only native shard into dependency-ordered relation fragments.  A
fresh run creates a canonical private lowering capsule from already validated
split-runner stage snapshots.  Resume consumes the same captured stage bytes
and an externally pinned capsule digest without invoking the upstream value
stage builder again.

The existing shard source and its row order are not changed.  No assignment or
row archive is materialized, and production execution always fails closed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import threading
from tempfile import TemporaryDirectory
from typing import Mapping, Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_anemoi_sponge as sponge
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_shard_stream as shard
import pq_rbbc_issuance_cap_child_executor_v1 as child
import pq_rbbc_issuance_split_runner_v1 as split
import pq_rbbc_launch_io_v2_41 as launch_io
import pq_rbbc_recovery_io_v2_42 as recovery_io


IMPLEMENTATION_VERSION = "1.0"
FORMAT = "PQRBBC-ISSUANCE-SPLIT-LOWERER-CHECKPOINT-1"
EVIDENCE_FORMAT = "PQRBBC-ISSUANCE-SPLIT-LOWERER-PORTABLE-EVIDENCE-1"
CAPSULE_FORMAT = "PQRBBC-ISSUANCE-SPLIT-LOWERING-CAPSULE-1"
FRAGMENT_STREAM_FORMAT = "PQRBBC-F193-R1CS-FRAGMENT-NDJSON-1"
PRODUCTION_RELATION_ID = split.PRODUCTION_RELATION_ID
BOUNDED_RELATION_ID = (
    "pq-rbbc/issuance/cap576-native/split-lowerer-4leaf-insecure-test-only/v1"
)
ROOT = Path(__file__).resolve().parents[1]

PARAMETERS = split.PARAMETERS
PROFILE_FINGERPRINT = split.PROFILE_FINGERPRINT
FRAGMENT_ORDER = (
    "input-binding",
    "tree-pre[0]",
    "global-tail-phase-a",
    "tree-post[0]",
    "global-tail-phase-b",
)
GROUP_TO_FRAGMENT = {
    "inputs": "input-binding",
    "ggm-derive": "tree-pre[0]",
    "leaf-commit-and-tape": "tree-pre[0]",
    "h1-and-points": "global-tail-phase-a",
    "leaf-horner-and-field-aggregation": "tree-post[0]",
    "h2-commitment-and-request-binding": "global-tail-phase-b",
}
DOMAIN_FRAGMENT = b"PQ-RBBC/ISSUANCE-SPLIT-LOWERER/FRAGMENT/V1"
DOMAIN_POINT_PORT = b"PQ-RBBC/ISSUANCE-SPLIT-LOWERER/GLOBAL-A-POINT-PORT/V1"

FROZEN_BOUNDED: dict[str, object] = {
    "capsule_sha256": "ddd2535955669e38d90c962d44790598e9430ed1eeb21474d47e6d587bfac3d7",
    "fragment_rows": {
        "input-binding": 1_028,
        "tree-pre[0]": 40_592,
        "global-tail-phase-a": 9_555,
        "tree-post[0]": 1_656,
        "global-tail-phase-b": 20_218,
    },
    "fragment_stream_sha256": {
        "input-binding": "8070a80460e352168c780e826506fa980b4093e9485a7f7bdd5fffea6ee49faf",
        "tree-pre[0]": "316cad3b0e2b4801d71b6ff888766b8e29e3cc9c8f7a396a238ec85766c4a546",
        "global-tail-phase-a": "fb1f3b63ef393c77cfeb9b3ca52ca3c3fb55bf6c1380db908d4e63e88b4cfa7a",
        "tree-post[0]": "97f93cd769cfd79cf33bec3d05f5294711762946945df862acbc37fbd814a3c6",
        "global-tail-phase-b": "d5c0d942b24f603ecbe603206ee3c665f55f83f1118618c9a98d97e0019dfac8",
    },
    "point_port_identity_sha256": "6408b990cd7e49a09fd4019178834f5e93df5700289f270fe9f81e38fcbfd421",
    "merged_rows": 73_049,
    "merged_wires": 53_032,
    "merged_stream_sha256": "635c6efaf3aa25d6f2d787450987b08712de5aaacd21f3107a90f5db9599b0cd",
}

TRACKED_PREREQUISITES = {
    "split_runner_source": (
        "src/pq_rbbc_issuance_split_runner_v1.py",
        59_823,
        "228aa95776d03d2a15b8f71edd5c923b8817f030d8d0244b895c1714295c7e65",
    ),
    "split_runner_manifest": (
        "manifests/pq_rbbc_issuance_split_runner_manifest_v1.json",
        8_334,
        "6031d3cc949b0202ba6eb35fcad6688dee864d6a7971d4381c94c5b29a3b0b84",
    ),
    "split_runner_evidence": (
        "artifacts/metadata/issuance_split_runner_v1/"
        "pq_rbbc_issuance_split_runner_portable_evidence_v1.json",
        2_243,
        "6d65c0808a32b6871a8b07559a81911368306c55c238a3040a10857be72abbd5",
    ),
    "native_shard_source": (
        "src/pq_rbbc_cap_shard_stream.py",
        75_409,
        "c54f34a797022723d029e262b8e0a99cf0461e6499d78cb8e8a5a8f93e56b8a2",
    ),
    "native_preflight_source": (
        "src/pq_rbbc_issuance_cap576_native_preflight_v1.py",
        30_536,
        "19da6b2cbc5e03e6d34c5c6da4910af7391fdef20a3abe981fbbabb6f10dee06",
    ),
    "recovery_io_source": (
        "src/pq_rbbc_recovery_io_v2_42.py",
        3_839,
        "4213d7228f757a29a77243826b4a09d4506e48399c638338d59649b81f611e3d",
    ),
}


class SplitLowererError(ValueError):
    """A bounded stage bundle, capsule, or fragment contract is invalid."""


class ProductionSplitLowererUnavailable(RuntimeError):
    """Production native split lowering is not implemented or authorized."""


def canonical_json(document: object) -> bytes:
    return launch_io.canonical_json(document)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_sha256(value: object) -> bool:
    if type(value) is not str or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _exact(document: object, fields: set[str], label: str) -> dict[str, object]:
    if type(document) is not dict or set(document) != fields:
        raise SplitLowererError(f"{label} fields are not closed-world canonical")
    return document


def _strict_json(raw: bytes, label: str) -> dict[str, object]:
    try:
        return launch_io.strict_json(raw)
    except launch_io.ValidationError as error:
        raise SplitLowererError(f"{label}: {error}") from error


def _hex_bits(value: object, bit_length: int, label: str) -> bytes:
    if type(value) is not str:
        raise SplitLowererError(f"{label} is not canonical hex")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise SplitLowererError(f"{label} is not canonical hex") from error
    if value != raw.hex() or len(raw) != (bit_length + 7) // 8:
        raise SplitLowererError(f"{label} has wrong canonical width")
    unused = len(raw) * 8 - bit_length
    if unused and raw[-1] >> (8 - unused):
        raise SplitLowererError(f"{label} has nonzero unused high bits")
    return raw


def _int_from_hex(value: object, bit_length: int, label: str) -> int:
    return int.from_bytes(_hex_bits(value, bit_length, label), "little")


def _unpack_vector(raw: bytes, count: int, bit_length: int) -> tuple[int, ...]:
    value = int.from_bytes(raw, "little")
    mask = (1 << bit_length) - 1
    result = tuple((value >> (index * bit_length)) & mask for index in range(count))
    if value >> (count * bit_length):
        raise SplitLowererError("packed vector has noncanonical high bits")
    return result


def _raw_identity(filename: str, raw: bytes) -> dict[str, object]:
    return {"filename": filename, "bytes": len(raw), "sha256": _sha256(raw)}


def validate_tracked_prerequisites() -> tuple[str, ...]:
    failures: list[str] = []
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
class CompletedStageBundle:
    """Captured immutable stage bytes; later parsing never reopens pathnames."""

    invocation: child.InvocationSnapshotV1
    stage_raws: tuple[bytes, ...]
    stage_identities: tuple[dict[str, object], ...]
    receipt_raws: tuple[bytes, ...]
    receipt_identities: tuple[dict[str, object], ...]
    complete_raw: bytes
    final_receipt_sha256: str

    def stage_documents(self) -> tuple[dict[str, object], ...]:
        return tuple(
            _strict_json(raw, f"captured stage {index}")
            for index, raw in enumerate(self.stage_raws)
        )


def _stage_ports(
    ordinal: int,
    document: Mapping[str, object],
    invocation: child.InvocationSnapshotV1,
    previous_payloads: Sequence[Mapping[str, object]],
) -> tuple[split.PortValue, ...]:
    payload = document["payload"]
    if type(payload) is not dict:
        raise SplitLowererError("stage payload is not an object")
    stage_id = split.STAGE_ORDER[ordinal]
    if stage_id == "bind-invocation":
        current = _exact(
            payload,
            {
                "statement_sha256",
                "witness_sha256",
                "rho_snapshot_sha256",
                "ticket_message_sha256",
                "same_immutable_rho_raw",
            },
            "bind payload",
        )
        expected = {
            "statement_sha256": _sha256(invocation.statement_raw),
            "witness_sha256": _sha256(invocation.witness_raw),
            "rho_snapshot_sha256": invocation.rho.sha256,
            "ticket_message_sha256": _sha256(invocation.ticket_message),
            "same_immutable_rho_raw": True,
        }
        if current != expected:
            raise SplitLowererError("bind payload differs from captured invocation")
        return (
            split.PortValue(
                "invocation.identity", 256, bytes.fromhex(invocation.invocation_sha256)
            ),
        )
    if stage_id == "tree-pre[0]":
        current = _exact(
            payload,
            {
                "tree_index",
                "leaves",
                "extension_degree",
                "commitments_hex",
                "plain_hex",
                "masks_hex",
                "xof_call_count",
                "xof_schedule_sha256",
            },
            "tree-pre payload",
        )
        if (
            current["tree_index"] != 0
            or current["leaves"] != 4
            or current["extension_degree"] != 3
            or current["xof_call_count"] != 10
            or not _is_sha256(current["xof_schedule_sha256"])
        ):
            raise SplitLowererError("tree-pre payload shape mismatch")
        commitments = _hex_bits(current["commitments_hex"], 4 * cap.HASH_BITS, "commitments")
        plain = _hex_bits(current["plain_hex"], PARAMETERS.random_polynomial_bits, "plain")
        masks = _hex_bits(
            current["masks_hex"],
            PARAMETERS.random_polynomial_bits * 3,
            "masks",
        )
        plain_value = int.from_bytes(plain, "little")
        mhat_shift = PARAMETERS.witness_bits + (PARAMETERS.degree - 1) * PARAMETERS.rho
        p_raw = cap.pack_int(
            plain_value & ((1 << PARAMETERS.witness_bits) - 1),
            PARAMETERS.witness_bits,
        )
        mhat_raw = cap.pack_int(
            (plain_value >> mhat_shift) & ((1 << PARAMETERS.consistency_bits) - 1),
            PARAMETERS.consistency_bits,
        )
        # The complete mask vector is a private payload needed by tree-post,
        # not a public output port of the production plan.
        if len(masks) == 0:
            raise AssertionError("bounded mask payload unexpectedly empty")
        return (
            split.PortValue("tree[0].leaf-commitments", 4 * cap.HASH_BITS, commitments),
            split.PortValue("tree[0].p-plain", PARAMETERS.witness_bits, p_raw),
            split.PortValue("tree[0].mhat-plain", PARAMETERS.consistency_bits, mhat_raw),
        )
    if stage_id == "global-tail-phase-a":
        current = _exact(
            payload,
            {
                "h1_hex",
                "points_hex",
                "alpha_hex",
                "delta_p_hex",
                "delta_mhat_hex",
                "xof_call_count",
                "xof_schedule_sha256",
            },
            "global-A payload",
        )
        if (
            current["delta_p_hex"] != []
            or current["delta_mhat_hex"] != []
            or current["xof_call_count"] != 2
            or not _is_sha256(current["xof_schedule_sha256"])
        ):
            raise SplitLowererError("global-A payload shape mismatch")
        h1 = _hex_bits(current["h1_hex"], cap.HASH_BITS, "h1")
        points = _hex_bits(current["points_hex"], PARAMETERS.consistency_bits, "points")
        alpha = _hex_bits(current["alpha_hex"], PARAMETERS.consistency_bits, "alpha")
        point_values = _unpack_vector(points, PARAMETERS.consistency_points, field.FIELD_DEGREE)
        if any(value == 0 for value in point_values) or len(set(point_values)) != len(point_values):
            raise SplitLowererError("global-A points are degenerate")
        return (
            split.PortValue("global.phase-a.h1", cap.HASH_BITS, h1),
            split.PortValue("global.phase-a.consistency-points", PARAMETERS.consistency_bits, points),
            split.PortValue("global.phase-a.alpha", PARAMETERS.consistency_bits, alpha),
        )
    if stage_id == "tree-post[0]":
        current = _exact(
            payload,
            {
                "tree_index",
                "consistency_points_sha256",
                "xi_masks_hex",
                "xi_count",
                "extension_degree",
            },
            "tree-post payload",
        )
        if len(previous_payloads) < 3:
            raise SplitLowererError("tree-post lacks captured global-A predecessor")
        global_a = previous_payloads[2]
        points = _hex_bits(global_a["points_hex"], PARAMETERS.consistency_bits, "points")
        if (
            current["tree_index"] != 0
            or current["xi_count"] != PARAMETERS.consistency_bits
            or current["extension_degree"] != 3
            or current["consistency_points_sha256"] != _sha256(points)
        ):
            raise SplitLowererError("tree-post payload dependency mismatch")
        xi = _hex_bits(
            current["xi_masks_hex"], PARAMETERS.consistency_bits * 3, "xi masks"
        )
        return (
            split.PortValue("tree[0].xi-masks", PARAMETERS.consistency_bits * 3, xi),
        )
    if stage_id == "global-tail-phase-b":
        current = _exact(
            payload,
            {
                "h2_hex",
                "commitment_hex",
                "derived_mask_hex",
                "append_base_hex",
                "request_hash_hex",
                "xof_schedule_sha256",
                "split_matches_direct_reference",
            },
            "global-B payload",
        )
        if (
            current["split_matches_direct_reference"] is not True
            or not _is_sha256(current["xof_schedule_sha256"])
        ):
            raise SplitLowererError("global-B payload contract mismatch")
        _hex_bits(current["h2_hex"], cap.HASH_BITS, "h2")
        commitment = _hex_bits(current["commitment_hex"], 206 * 8, "commitment")
        mask = _hex_bits(current["derived_mask_hex"], PARAMETERS.mask_bits, "derived mask")
        append = _hex_bits(
            current["append_base_hex"], PARAMETERS.appended_signature_bits, "append base"
        )
        request = _hex_bits(current["request_hash_hex"], sponge.REQUEST_HASH_BITS, "request hash")
        return (
            split.PortValue("global.phase-b.commitment", len(commitment) * 8, commitment),
            split.PortValue("global.phase-b.derived-mask", PARAMETERS.mask_bits, mask),
            split.PortValue(
                "global.phase-b.append-base", PARAMETERS.appended_signature_bits, append
            ),
            split.PortValue("global.phase-b.request-hash", sponge.REQUEST_HASH_BITS, request),
        )
    if stage_id == "final-seal":
        current = _exact(
            payload,
            {
                "global_b_payload_sha256",
                "commitment_sha256",
                "request_hash_sha256",
                "split_matches_direct_reference",
                "formal_mask_matches_bounded_derived_mask",
                "full_i3_relation_claimed",
                "constraint_stream_split_lowered",
                "production_execution_started",
            },
            "final payload",
        )
        if len(previous_payloads) < 5:
            raise SplitLowererError("final payload lacks global-B predecessor")
        global_b = previous_payloads[4]
        commitment = _hex_bits(global_b["commitment_hex"], 206 * 8, "commitment")
        request = _hex_bits(global_b["request_hash_hex"], sponge.REQUEST_HASH_BITS, "request hash")
        if current != {
            "global_b_payload_sha256": _sha256(canonical_json(global_b)),
            "commitment_sha256": _sha256(commitment),
            "request_hash_sha256": _sha256(request),
            "split_matches_direct_reference": True,
            "formal_mask_matches_bounded_derived_mask": False,
            "full_i3_relation_claimed": False,
            "constraint_stream_split_lowered": False,
            "production_execution_started": False,
        }:
            raise SplitLowererError("final payload claim or dependency mismatch")
        return (
            split.PortValue(
                "split-run.final", 256, bytes.fromhex(str(current["global_b_payload_sha256"]))
            ),
        )
    raise AssertionError("unhandled bounded stage")


def _validate_stage_structural(
    raw: bytes,
    *,
    ordinal: int,
    invocation: child.InvocationSnapshotV1,
    previous_receipt_sha256: str,
    previous_payloads: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    document = _strict_json(raw, f"stage {ordinal}")
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
            "ordinal",
            "stage_id",
            "previous_receipt_sha256",
            "payload_encoding",
            "payload_bytes",
            "payload_sha256",
            "payload",
            "output_identity",
            "private_test_fixture_material",
            "production",
        },
        "stage artifact",
    )
    stage_id = split.STAGE_ORDER[ordinal]
    if (
        current["format"] != split.STAGE_FORMAT
        or current["implementation_version"] != split.IMPLEMENTATION_VERSION
        or current["mode"] != "INSECURE-TEST-ONLY"
        or current["relation_id"] != split.BOUNDED_RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["plan_sha256"] != split.plan_sha256()
        or current["invocation_sha256"] != invocation.invocation_sha256
        or current["ordinal"] != ordinal
        or current["stage_id"] != stage_id
        or current["previous_receipt_sha256"] != previous_receipt_sha256
        or current["payload_encoding"] != "canonical-json-object/v1"
        or current["production"] is not False
    ):
        raise SplitLowererError("stage execution-domain binding mismatch")
    expected_private = stage_id in (
        "tree-pre[0]",
        "global-tail-phase-a",
        "tree-post[0]",
        "global-tail-phase-b",
    )
    if current["private_test_fixture_material"] is not expected_private:
        raise SplitLowererError("stage private-material marker mismatch")
    payload_raw = canonical_json(current["payload"])
    if current["payload_bytes"] != len(payload_raw) or current["payload_sha256"] != _sha256(payload_raw):
        raise SplitLowererError("stage payload identity mismatch")
    ports = _stage_ports(ordinal, current, invocation, previous_payloads)
    try:
        output = child.StageOutputIdentityV1.decode_for(
            canonical_json(current["output_identity"]),
            relation_id=split.BOUNDED_RELATION_ID,
            profile_fingerprint=PROFILE_FINGERPRINT,
            plan_sha256=split.plan_sha256(),
            invocation_sha256=invocation.invocation_sha256,
            stage_id=stage_id,
        )
    except child.ChildExecutorError as error:
        raise SplitLowererError(str(error)) from error
    expected_outputs = tuple(
        (port.port_id, port.bit_length, _sha256(port.raw)) for port in ports
    )
    if (
        output.rows != 0
        or output.wires != 0
        or output.stream_bytes != 0
        or output.stream_sha256 != _sha256(b"")
        or output.outputs != expected_outputs
        or output.assignment_materialized
        or output.external_assertions != 0
        or output.verification_failures != 0
    ):
        raise SplitLowererError("stage output identity does not bind payload ports")
    return current


def validate_completed_stage_snapshots(
    invocation: child.InvocationSnapshotV1,
    snapshots: Mapping[str, launch_io.Snapshot],
    *,
    expected_checkpoint_sha256: str,
) -> CompletedStageBundle:
    if not _is_sha256(expected_checkpoint_sha256):
        raise SplitLowererError("exact final receipt SHA-256 is required")
    expected_names = split._allowed_names()
    if set(snapshots) != expected_names:
        raise SplitLowererError("completed stage snapshot set is not closed-world exact")
    final_name = split.receipt_filename(len(split.STAGE_ORDER))
    if snapshots[final_name].identity["sha256"] != expected_checkpoint_sha256:
        raise SplitLowererError("final receipt external checkpoint mismatch")

    receipt_raws: list[bytes] = []
    receipt_identities: list[dict[str, object]] = []
    stage_raws: list[bytes] = []
    stage_identities: list[dict[str, object]] = []
    payloads: list[Mapping[str, object]] = []

    genesis = snapshots[split.receipt_filename(0)]
    genesis_document = _strict_json(genesis.raw, "genesis receipt")
    if genesis_document != split._genesis_receipt(invocation.invocation_sha256):
        raise SplitLowererError("genesis receipt mismatch")
    receipt_raws.append(genesis.raw)
    receipt_identities.append(genesis.identity)
    previous_receipt_sha256 = str(genesis.identity["sha256"])

    for ordinal in range(len(split.STAGE_ORDER)):
        stage_name = split.stage_filename(ordinal)
        stage_snapshot = snapshots[stage_name]
        stage_document = _validate_stage_structural(
            stage_snapshot.raw,
            ordinal=ordinal,
            invocation=invocation,
            previous_receipt_sha256=previous_receipt_sha256,
            previous_payloads=payloads,
        )
        stage_raws.append(stage_snapshot.raw)
        stage_identities.append(stage_snapshot.identity)
        payloads.append(stage_document["payload"])

        receipt_name = split.receipt_filename(ordinal + 1)
        receipt_snapshot = snapshots[receipt_name]
        receipt_document = _strict_json(receipt_snapshot.raw, f"receipt {ordinal + 1}")
        expected_receipt = split._receipt(
            invocation.invocation_sha256,
            ordinal + 1,
            stage_snapshot.identity,
            previous_receipt_sha256,
        )
        if receipt_document != expected_receipt:
            raise SplitLowererError("stage receipt chain mismatch")
        receipt_raws.append(receipt_snapshot.raw)
        receipt_identities.append(receipt_snapshot.identity)
        previous_receipt_sha256 = str(receipt_snapshot.identity["sha256"])

    expected_complete = split._complete_document(
        invocation.invocation_sha256, stage_identities, receipt_identities
    )
    complete_snapshot = snapshots[split.COMPLETE_FILENAME]
    if _strict_json(complete_snapshot.raw, "complete document") != expected_complete:
        raise SplitLowererError("complete document mismatch")
    return CompletedStageBundle(
        invocation,
        tuple(stage_raws),
        tuple(stage_identities),
        tuple(receipt_raws),
        tuple(receipt_identities),
        complete_snapshot.raw,
        previous_receipt_sha256,
    )


def load_completed_stage_bundle(
    statement_raw: bytes,
    witness_raw: bytes,
    output: Path,
    *,
    artifact_root: Path,
    expected_checkpoint_sha256: str,
) -> CompletedStageBundle:
    if not _is_sha256(expected_checkpoint_sha256):
        raise SplitLowererError("exact final receipt SHA-256 is required")
    invocation = child.capture_invocation(statement_raw, witness_raw)
    with recovery_io.locked_output(output, artifact_root, fresh=False) as output_fd:
        names = split._inventory_names(output_fd)
        final_name = split.receipt_filename(len(split.STAGE_ORDER))
        # The externally supplied digest is checked under the directory lock
        # before any other stage or capsule is read.
        final_snapshot = recovery_io.read(output / final_name)
        if final_snapshot.identity["sha256"] != expected_checkpoint_sha256:
            raise SplitLowererError("final receipt external checkpoint mismatch")
        snapshots = {final_name: final_snapshot}
        for name in sorted(names - {final_name}):
            snapshots[name] = recovery_io.read(output / name)
    return validate_completed_stage_snapshots(
        invocation,
        snapshots,
        expected_checkpoint_sha256=expected_checkpoint_sha256,
    )


def _call_document(call: cap.XOFCall) -> dict[str, object]:
    return {
        "label": call.label,
        "domain_hex": call.domain.hex(),
        "fields_hex": [item.hex() for item in call.fields],
        "output_bits": call.output_bits,
        "output_hex": cap.pack_int(call.output, call.output_bits).hex(),
    }


def _decode_call(document: object, index: int) -> cap.XOFCall:
    current = _exact(
        document,
        {"label", "domain_hex", "fields_hex", "output_bits", "output_hex"},
        f"capsule call {index}",
    )
    if type(current["label"]) is not str or not current["label"]:
        raise SplitLowererError("capsule call label is invalid")
    if type(current["output_bits"]) is not int or current["output_bits"] <= 0:
        raise SplitLowererError("capsule call output width is invalid")
    if type(current["fields_hex"]) is not list or not current["fields_hex"]:
        raise SplitLowererError("capsule call fields are invalid")
    domain = _hex_bits(current["domain_hex"], len(str(current["domain_hex"])) * 4, "call domain")
    fields: list[bytes] = []
    for field_index, value in enumerate(current["fields_hex"]):
        if type(value) is not str:
            raise SplitLowererError("capsule call field is not hex")
        try:
            raw = bytes.fromhex(value)
        except ValueError as error:
            raise SplitLowererError("capsule call field is not hex") from error
        if value != raw.hex():
            raise SplitLowererError("capsule call field is noncanonical")
        fields.append(raw)
    output_bits = int(current["output_bits"])
    output = _int_from_hex(current["output_hex"], output_bits, "call output")
    return cap.XOFCall(str(current["label"]), domain, tuple(fields), output_bits, output)


def _stage_payloads(bundle: CompletedStageBundle) -> tuple[dict[str, object], ...]:
    return tuple(document["payload"] for document in bundle.stage_documents())


def _polynomial_from_payload(payload: Mapping[str, object]) -> cap.TreePolynomial:
    commitment_values = _unpack_vector(
        _hex_bits(payload["commitments_hex"], 4 * cap.HASH_BITS, "commitments"),
        8,
        field.FIELD_DEGREE,
    )
    commitments = tuple(
        (commitment_values[index], commitment_values[index + 1])
        for index in range(0, len(commitment_values), 2)
    )
    masks = _unpack_vector(
        _hex_bits(
            payload["masks_hex"], PARAMETERS.random_polynomial_bits * 3, "masks"
        ),
        PARAMETERS.random_polynomial_bits,
        3,
    )
    return cap.TreePolynomial(
        4,
        3,
        commitments,
        _int_from_hex(payload["plain_hex"], PARAMETERS.random_polynomial_bits, "plain"),
        masks,
    )


def _commitment_from_payloads(
    global_a: Mapping[str, object], global_b: Mapping[str, object]
) -> cap.CAPCommitment:
    return cap.CAPCommitment(
        PROFILE_FINGERPRINT,
        (
            0,
            0,
        ),
        _int_from_hex(global_a["h1_hex"], cap.HASH_BITS, "h1"),
        _int_from_hex(global_b["h2_hex"], cap.HASH_BITS, "h2"),
        _int_from_hex(global_a["alpha_hex"], PARAMETERS.consistency_bits, "alpha"),
        (),
        (),
        _int_from_hex(global_b["derived_mask_hex"], PARAMETERS.mask_bits, "derived mask"),
        _int_from_hex(
            global_b["append_base_hex"], PARAMETERS.appended_signature_bits, "append base"
        ),
        _hex_bits(global_b["commitment_hex"], 206 * 8, "commitment"),
    )


def _execution_from_bundle_and_calls(
    bundle: CompletedStageBundle, calls: Sequence[cap.XOFCall]
) -> cap.CAPExecution:
    payloads = _stage_payloads(bundle)
    tree_pre = payloads[1]
    global_a = payloads[2]
    global_b = payloads[4]
    commitment = _commitment_from_payloads(global_a, global_b)
    # Salt is an invocation input and must not be selected by the stage payload.
    commitment = cap.CAPCommitment(
        commitment.parameters_fingerprint,
        bundle.invocation.rho.randomness.salt,
        commitment.h1,
        commitment.h2,
        commitment.alpha,
        commitment.delta_p,
        commitment.delta_mhat,
        commitment.derived_mask,
        commitment.append_base,
        commitment.encoded,
    )
    return cap.CAPExecution(commitment, (_polynomial_from_payload(tree_pre),), tuple(calls))


def _validate_execution_against_bundle(
    bundle: CompletedStageBundle, execution: cap.CAPExecution
) -> None:
    payloads = _stage_payloads(bundle)
    if len(execution.xof_calls) != 13:
        raise SplitLowererError("capsule XOF schedule length mismatch")
    if split._schedule_sha256(execution.xof_calls[:10]) != payloads[1]["xof_schedule_sha256"]:
        raise SplitLowererError("capsule tree-pre XOF schedule mismatch")
    if split._schedule_sha256(execution.xof_calls[10:12]) != payloads[2]["xof_schedule_sha256"]:
        raise SplitLowererError("capsule global-A XOF schedule mismatch")
    if split._schedule_sha256(execution.xof_calls[12:]) != payloads[4]["xof_schedule_sha256"]:
        raise SplitLowererError("capsule global-B XOF schedule mismatch")
    expected_labels = tuple(
        [f"tree[0].derive[2,{index}]" for index in (1, 2)]
        + [
            label
            for leaf in range(1, 5)
            for label in (
                f"tree[0].leaf[{leaf}].commit",
                f"tree[0].leaf[{leaf}].tape",
            )
        ]
        + ["h1", "consistency-points", "h2"]
    )
    if tuple(call.label for call in execution.xof_calls) != expected_labels:
        raise SplitLowererError("capsule XOF call ordering mismatch")
    if execution.tree_polynomials != (_polynomial_from_payload(payloads[1]),):
        raise SplitLowererError("capsule tree polynomial mismatch")
    if execution.commitment.encoded != _hex_bits(payloads[4]["commitment_hex"], 206 * 8, "commitment"):
        raise SplitLowererError("capsule commitment bytes mismatch")
    if execution.commitment.h1 != _int_from_hex(payloads[2]["h1_hex"], cap.HASH_BITS, "h1"):
        raise SplitLowererError("capsule h1 mismatch")
    if execution.commitment.h2 != _int_from_hex(payloads[4]["h2_hex"], cap.HASH_BITS, "h2"):
        raise SplitLowererError("capsule h2 mismatch")


def build_fresh_capsule(bundle: CompletedStageBundle) -> tuple[bytes, cap.CAPExecution]:
    randomness = cap.CAPRandomness(
        bundle.invocation.rho.randomness.salt,
        (bundle.invocation.rho.randomness.roots[0],),
    )
    execution = shard.build_parallel_execution(PARAMETERS, randomness, workers=1)
    _validate_execution_against_bundle(bundle, execution)
    document = {
        "format": CAPSULE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": "INSECURE-TEST-ONLY",
        "relation_id": BOUNDED_RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "split_plan_sha256": split.plan_sha256(),
        "invocation_sha256": bundle.invocation.invocation_sha256,
        "final_receipt_sha256": bundle.final_receipt_sha256,
        "stage_payload_sha256": [
            _sha256(canonical_json(document["payload"]))
            for document in bundle.stage_documents()
        ],
        "xof_calls": [_call_document(call) for call in execution.xof_calls],
        "private_test_fixture_material": True,
        "assignment_materialized": False,
        "production": False,
    }
    return canonical_json(document), execution


def decode_capsule(
    raw: bytes,
    bundle: CompletedStageBundle,
    *,
    expected_capsule_sha256: str,
) -> cap.CAPExecution:
    # Digest comparison precedes parsing or any native lowering.
    if not _is_sha256(expected_capsule_sha256) or _sha256(raw) != expected_capsule_sha256:
        raise SplitLowererError("lowering capsule external checkpoint mismatch")
    document = _strict_json(raw, "lowering capsule")
    current = _exact(
        document,
        {
            "format",
            "implementation_version",
            "mode",
            "relation_id",
            "profile_fingerprint",
            "split_plan_sha256",
            "invocation_sha256",
            "final_receipt_sha256",
            "stage_payload_sha256",
            "xof_calls",
            "private_test_fixture_material",
            "assignment_materialized",
            "production",
        },
        "lowering capsule",
    )
    expected_payloads = [
        _sha256(canonical_json(item["payload"])) for item in bundle.stage_documents()
    ]
    if (
        current["format"] != CAPSULE_FORMAT
        or current["implementation_version"] != IMPLEMENTATION_VERSION
        or current["mode"] != "INSECURE-TEST-ONLY"
        or current["relation_id"] != BOUNDED_RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["split_plan_sha256"] != split.plan_sha256()
        or current["invocation_sha256"] != bundle.invocation.invocation_sha256
        or current["final_receipt_sha256"] != bundle.final_receipt_sha256
        or current["stage_payload_sha256"] != expected_payloads
        or current["private_test_fixture_material"] is not True
        or current["assignment_materialized"] is not False
        or current["production"] is not False
        or type(current["xof_calls"]) is not list
    ):
        raise SplitLowererError("lowering capsule execution-domain binding mismatch")
    calls = tuple(_decode_call(item, index) for index, item in enumerate(current["xof_calls"]))
    execution = _execution_from_bundle_and_calls(bundle, calls)
    _validate_execution_against_bundle(bundle, execution)
    if canonical_json(current) != raw:
        raise SplitLowererError("lowering capsule is noncanonical")
    return execution


@dataclass(frozen=True)
class CapturedRow:
    group: str
    row: field.RankOneRow
    nonlinear: bool


@dataclass(frozen=True)
class RelationFragment:
    fragment_id: str
    groups: tuple[str, ...]
    rows: tuple[CapturedRow, ...]
    allocated_intervals: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class LoweringResult:
    report: dict[str, object]
    capsule_raw: bytes


_CAPTURE_LOCK = threading.Lock()


def _coalesce(intervals: Sequence[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    result: list[list[int]] = []
    for start, end in sorted(intervals):
        if not result or start != result[-1][1] + 1:
            result.append([start, end])
        else:
            result[-1][1] = end
    return tuple((start, end) for start, end in result)


def _capture_existing_monolithic(
    bundle: CompletedStageBundle,
    execution: cap.CAPExecution,
) -> tuple[shard.ShardTraceSummary, tuple[CapturedRow, ...], dict[str, tuple[tuple[int, int], ...]]]:
    captured: list[CapturedRow] = []
    allocations: dict[str, list[tuple[int, int]]] = {name: [] for name in GROUP_TO_FRAGMENT}
    original = shard.StreamingRowSink

    class CapturingSink(original):
        def allocate(self, count: int = 1, **kwargs: object) -> int:
            start = super().allocate(count, **kwargs)
            group = self._group_name
            if group is None or group not in GROUP_TO_FRAGMENT:
                raise SplitLowererError("wire allocation occurred outside frozen row groups")
            allocations[group].append((start, start + count - 1))
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
            if group is None or group not in GROUP_TO_FRAGMENT:
                raise SplitLowererError("row emitted outside frozen row groups")
            captured.append(
                CapturedRow(group, field.RankOneRow(label, left, right, output), nonlinear)
            )
            super().row(label, left, right, output, nonlinear=nonlinear)

    randomness = cap.CAPRandomness(
        bundle.invocation.rho.randomness.salt,
        (bundle.invocation.rho.randomness.roots[0],),
    )
    with _CAPTURE_LOCK:
        shard.StreamingRowSink = CapturingSink
        try:
            summary = shard.build_streaming_shard(
                PARAMETERS,
                randomness,
                bundle.invocation.ticket_message,
                workers=1,
                execution=execution,
            )
        finally:
            shard.StreamingRowSink = original
    return (
        summary,
        tuple(captured),
        {name: _coalesce(items) for name, items in allocations.items()},
    )


def build_fragments(
    rows: Sequence[CapturedRow],
    allocations: Mapping[str, tuple[tuple[int, int], ...]],
) -> tuple[RelationFragment, ...]:
    result = []
    for fragment_id in FRAGMENT_ORDER:
        groups = tuple(name for name, owner in GROUP_TO_FRAGMENT.items() if owner == fragment_id)
        fragment_rows = tuple(item for item in rows if item.group in groups)
        intervals = _coalesce(
            tuple(interval for group in groups for interval in allocations[group])
        )
        if not fragment_rows or not intervals:
            raise SplitLowererError(f"empty relation fragment: {fragment_id}")
        result.append(RelationFragment(fragment_id, groups, fragment_rows, intervals))
    return tuple(result)


def verify_exact_merge(
    monolithic: Sequence[CapturedRow], fragments: Sequence[RelationFragment]
) -> None:
    if tuple(fragment.fragment_id for fragment in fragments) != FRAGMENT_ORDER:
        raise SplitLowererError("fragment order mismatch")
    merged = tuple(item for fragment in fragments for item in fragment.rows)
    if merged != tuple(monolithic):
        raise SplitLowererError("merged fragments differ row-by-row from monolithic emission")


def _row_record(item: CapturedRow) -> bytes:
    return canonical_json({"kind": "row", **item.row.canonical_dict()})


def _fragment_summary(
    fragment: RelationFragment,
    all_fragments: Sequence[RelationFragment],
) -> dict[str, object]:
    digest = hashlib.sha256(DOMAIN_FRAGMENT)
    header = canonical_json(
        {
            "format": FRAGMENT_STREAM_FORMAT,
            "relation_id": BOUNDED_RELATION_ID,
            "profile_fingerprint": PROFILE_FINGERPRINT,
            "fragment_id": fragment.fragment_id,
            "groups": list(fragment.groups),
        }
    )
    digest.update(header)
    stream_bytes = len(header)
    for item in fragment.rows:
        raw = _row_record(item)
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
    later_rows = tuple(
        item
        for candidate in all_fragments[
            tuple(item.fragment_id for item in all_fragments).index(fragment.fragment_id) + 1 :
        ]
        for item in candidate.rows
    )
    later_referenced = {
        wire
        for item in later_rows
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
        "export_wire_count": len(owned & later_referenced),
        "stream_bytes": stream_bytes,
        "stream_sha256": digest.hexdigest(),
        "assignment_materialized": False,
        "external_assertions": 0,
    }


def _point_port(
    rows: Sequence[CapturedRow], fragments: Sequence[RelationFragment], bundle: CompletedStageBundle
) -> dict[str, object]:
    point_rows = [
        item
        for item in rows
        if item.group == "h1-and-points"
        and ".consistency-points.digest.lane[" in item.row.label
        and item.row.label.endswith("].bit")
    ]
    point_wires: list[int] = []
    for item in point_rows:
        form = item.row.left
        if len(form.terms) != 1 or form.terms[0][1] != 1 or form.constant != 0:
            raise SplitLowererError("global-A point bitness row is not canonical")
        point_wires.append(form.terms[0][0])
    if len(point_wires) != PARAMETERS.consistency_bits or len(set(point_wires)) != len(point_wires):
        raise SplitLowererError("global-A point wire width mismatch")
    tree_post = next(item for item in fragments if item.fragment_id == "tree-post[0]")
    tree_post_refs = {
        wire
        for item in tree_post.rows
        for form in (item.row.left, item.row.right, item.row.output)
        for wire, _ in form.terms
    }
    if not set(point_wires).issubset(tree_post_refs):
        raise SplitLowererError("tree-post does not consume every global-A point wire")
    tree_pre = next(item for item in fragments if item.fragment_id == "tree-pre[0]")
    tree_pre_refs = {
        wire
        for item in tree_pre.rows
        for form in (item.row.left, item.row.right, item.row.output)
        for wire, _ in form.terms
    }
    if set(point_wires) & tree_pre_refs:
        raise SplitLowererError("tree-pre illegally consumes global-A point wires")
    payloads = _stage_payloads(bundle)
    points_raw = _hex_bits(payloads[2]["points_hex"], PARAMETERS.consistency_bits, "points")
    port_document = {
        "port_id": "global.phase-a.consistency-points.native-wires",
        "producer_fragment": "global-tail-phase-a",
        "consumer_fragment": "tree-post[0]",
        "bit_length": PARAMETERS.consistency_bits,
        "wire_start": point_wires[0],
        "wire_end": point_wires[-1],
        "wire_ids_contiguous": point_wires == list(range(point_wires[0], point_wires[-1] + 1)),
        "wire_ids_sha256": _sha256(canonical_json(point_wires)),
        "value_sha256": _sha256(points_raw),
        "tree_pre_consumes_port": False,
        "tree_post_consumes_every_wire": True,
    }
    port_document["port_identity_sha256"] = _sha256(
        DOMAIN_POINT_PORT + canonical_json(port_document)
    )
    return port_document


def lower_from_capsule(
    bundle: CompletedStageBundle,
    capsule_raw: bytes,
    *,
    expected_capsule_sha256: str,
    value_stage_execution_performed: bool = False,
) -> LoweringResult:
    execution = decode_capsule(
        capsule_raw, bundle, expected_capsule_sha256=expected_capsule_sha256
    )
    summary, rows, allocations = _capture_existing_monolithic(bundle, execution)
    fragments = build_fragments(rows, allocations)
    verify_exact_merge(rows, fragments)
    fragment_summaries = tuple(
        _fragment_summary(fragment, fragments) for fragment in fragments
    )
    if sum(int(item["rows"]) for item in fragment_summaries) != summary.rows:
        raise SplitLowererError("fragment row accounting does not sum to monolithic rows")
    if sum(int(item["nonlinear_rows"]) for item in fragment_summaries) != summary.nonlinear_rows:
        raise SplitLowererError("fragment nonlinear accounting mismatch")
    point_port = _point_port(rows, fragments, bundle)
    report = {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": "INSECURE-TEST-ONLY",
        "relation_id": BOUNDED_RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "invocation_sha256": bundle.invocation.invocation_sha256,
        "split_final_receipt_sha256": bundle.final_receipt_sha256,
        "capsule_sha256": _sha256(capsule_raw),
        "fragment_order": list(FRAGMENT_ORDER),
        "fragments": list(fragment_summaries),
        "global_a_point_port": point_port,
        "merged_row_by_row_equal_to_existing_monolithic_emission": True,
        "merged_rows": summary.rows,
        "merged_wires": summary.wires,
        "merged_nonlinear_rows": summary.nonlinear_rows,
        "merged_linear_rows": summary.linear_rows,
        "existing_monolithic_stream_bytes": summary.stream_bytes,
        "existing_monolithic_stream_sha256": summary.stream_sha256,
        "existing_monolithic_spool_bytes": summary.spool_bytes,
        "existing_monolithic_spool_sha256": summary.spool_sha256,
        "commitment_sha256": _sha256(summary.commitment_bytes),
        "request_hash_sha256": _sha256(summary.request_hash_bytes),
        "verification_failures": summary.verification_failures,
        "external_assertions": summary.external_assertions,
        "value_stage_execution_performed": value_stage_execution_performed,
        "upstream_split_stage_builder_reexecuted": False,
        "row_archive_materialized": False,
        "assignment_materialized": summary.assignment_materialized,
        "full_i3_relation_replayed": False,
        "large_relation_rows_replayed": 0,
        "cryptographic_proofs_generated": 0,
        "production": False,
    }
    return LoweringResult(report, capsule_raw)


def fresh_lower(
    bundle: CompletedStageBundle,
) -> LoweringResult:
    capsule_raw, _ = build_fresh_capsule(bundle)
    return lower_from_capsule(
        bundle,
        capsule_raw,
        expected_capsule_sha256=_sha256(capsule_raw),
        value_stage_execution_performed=True,
    )


def execute_production_split_lowerer(*_args: object, **_kwargs: object) -> None:
    raise ProductionSplitLowererUnavailable(
        "production native split lowerer is unavailable; no artifact was read or created"
    )


def _fixture_bytes() -> tuple[bytes, bytes]:
    return split._fixture_bytes()


@lru_cache(maxsize=1)
def bounded_self_check() -> dict[str, object]:
    statement_raw, witness_raw = _fixture_bytes()
    with TemporaryDirectory(prefix="pq-rbbc-split-lowerer-") as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        stage_output = root / "stages"
        split.run_bounded_split(
            statement_raw,
            witness_raw,
            stage_output,
            artifact_root=root,
            fresh_output=True,
        )
        latest = split.latest_receipt(stage_output, artifact_root=root)
        bundle = load_completed_stage_bundle(
            statement_raw,
            witness_raw,
            stage_output,
            artifact_root=root,
            expected_checkpoint_sha256=str(latest.identity["sha256"]),
        )
        fresh = fresh_lower(bundle)
        capsule_sha256 = _sha256(fresh.capsule_raw)

        original_parallel = shard.build_parallel_execution
        original_stage_builder = split.build_stage_computations
        shard.build_parallel_execution = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("resume re-executed CAP value stage")
        )
        split.build_stage_computations = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("resume re-executed split stage builder")
        )
        try:
            resumed = lower_from_capsule(
                bundle,
                fresh.capsule_raw,
                expected_capsule_sha256=capsule_sha256,
                value_stage_execution_performed=False,
            )
        finally:
            shard.build_parallel_execution = original_parallel
            split.build_stage_computations = original_stage_builder

        stable_keys = tuple(
            key for key in fresh.report if key != "value_stage_execution_performed"
        )
        fresh_resume_identical = all(
            fresh.report[key] == resumed.report[key] for key in stable_keys
        )
        wrong_capsule_checkpoint_rejected = False
        try:
            lower_from_capsule(
                bundle,
                b"not-json\n",
                expected_capsule_sha256="0" * 64,
            )
        except SplitLowererError:
            wrong_capsule_checkpoint_rejected = True

    observed = {
        "capsule_sha256": capsule_sha256,
        "fragment_rows": {
            item["fragment_id"]: item["rows"] for item in fresh.report["fragments"]
        },
        "fragment_stream_sha256": {
            item["fragment_id"]: item["stream_sha256"]
            for item in fresh.report["fragments"]
        },
        "point_port_identity_sha256": fresh.report["global_a_point_port"][
            "port_identity_sha256"
        ],
        "merged_rows": fresh.report["merged_rows"],
        "merged_wires": fresh.report["merged_wires"],
        "merged_stream_sha256": fresh.report["existing_monolithic_stream_sha256"],
    }
    frozen_mismatches = [
        name for name, expected in FROZEN_BOUNDED.items() if observed.get(name) != expected
    ]
    return {
        **observed,
        "fragment_order": fresh.report["fragment_order"],
        "merged_row_by_row_equal": fresh.report[
            "merged_row_by_row_equal_to_existing_monolithic_emission"
        ],
        "global_a_point_bits": fresh.report["global_a_point_port"]["bit_length"],
        "global_a_point_wires_contiguous": fresh.report["global_a_point_port"][
            "wire_ids_contiguous"
        ],
        "tree_pre_does_not_consume_global_points": not fresh.report[
            "global_a_point_port"
        ]["tree_pre_consumes_port"],
        "tree_post_consumes_every_global_point_wire": fresh.report[
            "global_a_point_port"
        ]["tree_post_consumes_every_wire"],
        "fresh_resume_identical": fresh_resume_identical,
        "resume_value_stage_execution_performed": resumed.report[
            "value_stage_execution_performed"
        ],
        "resume_upstream_split_stage_builder_reexecuted": resumed.report[
            "upstream_split_stage_builder_reexecuted"
        ],
        "wrong_capsule_checkpoint_rejected_before_parse": wrong_capsule_checkpoint_rejected,
        "verification_failures": fresh.report["verification_failures"],
        "external_assertions": fresh.report["external_assertions"],
        "assignment_materialized": fresh.report["assignment_materialized"],
        "row_archive_materialized": fresh.report["row_archive_materialized"],
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
        "fragment_contract": {
            "order": list(FRAGMENT_ORDER),
            "group_to_fragment": GROUP_TO_FRAGMENT,
            "absolute_wire_ids_preserved": True,
            "merged_row_by_row_comparison_required": True,
            "global_a_point_wire_handoff_frozen": True,
            "tree_pre_consumes_global_points": False,
            "tree_post_consumes_global_points": True,
        },
        "resume_contract": {
            "single_captured_stage_snapshot_set": True,
            "external_final_receipt_sha256_required": True,
            "external_capsule_sha256_required": True,
            "capsule_contains_private_test_fixture_material": True,
            "capsule_tracked_in_git": False,
            "upstream_completed_value_stages_reexecuted_on_resume": False,
            "native_witness_computation_eliminated": False,
        },
        "bounded_qualification": bounded,
        "external_artifacts": {
            "required": list(child.production_inputs.REQUIRED_EXTERNAL_ARTIFACTS),
            "installed_by_this_checkpoint": False,
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
                "src/pq_rbbc_issuance_split_lowerer_v1.py --self-check"
            ),
            "read_only_external_inventory": (
                "PYTHONPATH=src python -u "
                "src/pq_rbbc_issuance_split_lowerer_v1.py "
                "--artifact-root /ABSOLUTE/PRIVATE/ARTIFACT/ROOT"
            ),
            "targeted_tests": (
                "PYTHONPATH=src python -m unittest "
                "tests.test_pq_rbbc_issuance_split_lowerer_v1 -v"
            ),
            "production_execution": None,
            "large_replay": None,
            "large_proving": None,
        },
        "claim_status": {
            "Defined": True,
            "Instantiated": {"bounded_test_only": True, "production": False},
            "Implemented": {
                "bounded_native_fragment_lowerer": True,
                "bounded_capsule_resume": True,
                "production_native_split_lowerer": False,
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
            "capsule_is_private_external_runtime_input": True,
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
    manifest_path = ROOT / "manifests/pq_rbbc_issuance_split_lowerer_manifest_v1.json"
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
        "private_capsule_embedded": False,
        "stage_payload_embedded": False,
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
    report = split.external_inventory_preflight(artifact_root)
    return {
        "format": FORMAT,
        "production_relation_id": PRODUCTION_RELATION_ID,
        "predecessor_report": report,
        "tracked_prerequisites_valid": not validate_tracked_prerequisites(),
        "production_native_split_lowerer_implemented": False,
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
