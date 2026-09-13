#!/usr/bin/env python3
"""Bounded split CAP runner and append-only stage-output publisher.

The runner executes the CAP value computation in the actual dependency order:
tree-pre, global phase A, tree-post, and global phase B.  A Linux-only external
publisher writes each bounded test-only stage and receipt exactly once.  Resume
accepts only an externally supplied digest of the latest immutable receipt and
then validates every captured artifact against the same invocation.

This module does not implement the production constraint-stream split lowerer.
Production execution always refuses before creating an output directory.  The
bounded output contains private fixture material and is an untracked external
runtime artifact; portable evidence includes only identities and observations.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Mapping, Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_anemoi_sponge as sponge
import pq_rbbc_cap_commit as cap
import pq_rbbc_issuance_cap_child_executor_v1 as predecessor
import pq_rbbc_launch_io_v2_41 as launch_io
import pq_rbbc_recovery_io_v2_42 as recovery_io


IMPLEMENTATION_VERSION = "1.0"
FORMAT = "PQRBBC-ISSUANCE-SPLIT-RUNNER-CHECKPOINT-1"
EVIDENCE_FORMAT = "PQRBBC-ISSUANCE-SPLIT-RUNNER-PORTABLE-EVIDENCE-1"
STAGE_FORMAT = "PQRBBC-ISSUANCE-SPLIT-STAGE-ARTIFACT-1"
RECEIPT_FORMAT = "PQRBBC-ISSUANCE-SPLIT-STAGE-RECEIPT-1"
COMPLETE_FORMAT = "PQRBBC-ISSUANCE-SPLIT-RUN-COMPLETE-1"
PRODUCTION_RELATION_ID = predecessor.PRODUCTION_RELATION_ID
BOUNDED_RELATION_ID = (
    "pq-rbbc/issuance/cap576-native/split-runner-4leaf-insecure-test-only/v1"
)
ROOT = Path(__file__).resolve().parents[1]

PARAMETERS = predecessor.BOUNDED_PARAMETERS
PROFILE_FINGERPRINT = cap.profile_fingerprint(PARAMETERS)
STAGE_ORDER = (
    "bind-invocation",
    "tree-pre[0]",
    "global-tail-phase-a",
    "tree-post[0]",
    "global-tail-phase-b",
    "final-seal",
)

DOMAIN_PLAN = b"PQ-RBBC/ISSUANCE-SPLIT-RUNNER/PLAN/V1"
DOMAIN_SCHEDULE = b"PQ-RBBC/ISSUANCE-SPLIT-RUNNER/XOF-SCHEDULE/V1"
DOMAIN_RECEIPT = b"PQ-RBBC/ISSUANCE-SPLIT-RUNNER/RECEIPT/V1"
DOMAIN_COMPLETE = b"PQ-RBBC/ISSUANCE-SPLIT-RUNNER/COMPLETE/V1"

GENESIS_FILENAME = "receipt-000.json"
COMPLETE_FILENAME = "complete.json"

FROZEN_PLAN_SHA256 = (
    "5655cbb5f751618fa3acf0a7839ebd540103fcfd037f0ae43aec5fc595d442b6"
)
FROZEN_COMPLETE_SHA256 = (
    "34d1aecd0358b37c57ff11d81eb5422ef3ef73606c6b05f72a8b10e7f6e16c07"
)
FROZEN_FINAL_RECEIPT_SHA256 = (
    "56fce4aa4606faf155cc66ac4dd8993540fd0a64854fdd39cb490f6fe63db4af"
)
FROZEN_TREE_PRE_STAGE_SHA256 = (
    "fafcdfa05aea090491fa220489cfb2319e9dc166e30d924bb68599006c4d7b3a"
)
FROZEN_GLOBAL_B_STAGE_SHA256 = (
    "42ab676600d7d8a52528be5f4a10f7a9112dd2815d8f0fec9cb2f6c9e0b90ee6"
)

TRACKED_PREREQUISITES = {
    "child_executor_source": (
        "src/pq_rbbc_issuance_cap_child_executor_v1.py",
        51_223,
        "930e98f647a7539f9124515931df979cbfe8fb10c4ecda731e6987fcbd15033c",
    ),
    "child_executor_manifest": (
        "manifests/pq_rbbc_issuance_cap_child_executor_manifest_v1.json",
        35_544,
        "72ca9390f78c03d31bf4e45e25da3a5cf821d31259782df95e54a3e7c2d4d5e4",
    ),
    "child_executor_evidence": (
        "artifacts/metadata/issuance_cap_child_executor_v1/"
        "pq_rbbc_issuance_cap_child_executor_portable_evidence_v1.json",
        3_163,
        "96c6c6732a11126435c2b6dd94a2e5788a1177a60e4754ff76c1d3187f3787c3",
    ),
    "recovery_io_source": (
        "src/pq_rbbc_recovery_io_v2_42.py",
        3_839,
        "4213d7228f757a29a77243826b4a09d4506e48399c638338d59649b81f611e3d",
    ),
    "snapshot_io_source": (
        "src/pq_rbbc_launch_io_v2_41.py",
        10_564,
        "d7589d22abf251f9d2297455bafccaed34be7900b9e11e68ac037d9ad4c3a061",
    ),
    "cap_source": (
        "src/pq_rbbc_cap_commit.py",
        32_526,
        "be3a2a767561f009acc2a274a85410ae6e02e23abd24145aa1d61883dd2dceee",
    ),
    "sponge_source": (
        "src/pq_rbbc_anemoi_sponge.py",
        25_336,
        "6d4e604cd937357cd76f9c127fa9fe94392bbc89b1a0b7972196545ab36424ec",
    ),
}


class SplitRunnerError(ValueError):
    """A bounded stage, receipt, or resume identity is invalid."""


class ProductionSplitRunnerUnavailable(RuntimeError):
    """Production split lowering is not implemented or authorized."""


class ControlledInterruption(RuntimeError):
    """Test-only interruption after a durable stage receipt."""


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


def _identity(path: Path) -> dict[str, object]:
    return {
        "filename": path.name,
        "bytes": path.stat().st_size,
        "sha256": _sha256_file(path),
    }


def _raw_identity(filename: str, raw: bytes) -> dict[str, object]:
    return {"filename": filename, "bytes": len(raw), "sha256": _sha256(raw)}


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
        raise SplitRunnerError(f"{label} fields are not closed-world canonical")
    return document


def _strict_json(raw: bytes, label: str) -> dict[str, object]:
    try:
        return launch_io.strict_json(raw)
    except launch_io.ValidationError as error:
        raise SplitRunnerError(f"{label}: {error}") from error


def _hash_tuple(domain: bytes, values: Sequence[bytes]) -> str:
    digest = hashlib.sha256(domain)
    for value in values:
        digest.update(len(value).to_bytes(8, "little"))
        digest.update(value)
    return digest.hexdigest()


def validate_tracked_prerequisites() -> tuple[str, ...]:
    failures = []
    for name, (relative, expected_bytes, expected_sha256) in TRACKED_PREREQUISITES.items():
        path = ROOT / relative
        if not path.is_file():
            failures.append(f"{name}:missing")
            continue
        if path.stat().st_size != expected_bytes:
            failures.append(f"{name}:bytes")
        if _sha256_file(path) != expected_sha256:
            failures.append(f"{name}:sha256")
    return tuple(failures)


def build_plan() -> dict[str, object]:
    return {
        "format": "PQRBBC-ISSUANCE-SPLIT-RUNNER-PLAN-1",
        "relation_id": BOUNDED_RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "stage_order": list(STAGE_ORDER),
        "stage_dependencies": [
            {
                "ordinal": ordinal,
                "stage_id": stage_id,
                "depends_on": [] if ordinal == 0 else [STAGE_ORDER[ordinal - 1]],
            }
            for ordinal, stage_id in enumerate(STAGE_ORDER)
        ],
        "tree_count": 1,
        "leaves": 4,
        "production_widths": {
            "mask_bits": PARAMETERS.mask_bits,
            "appended_signature_bits": PARAMETERS.appended_signature_bits,
            "witness_bits": PARAMETERS.witness_bits,
            "random_polynomial_bits": PARAMETERS.random_polynomial_bits,
        },
        "value_layer_split_execution": True,
        "constraint_stream_split_lowering": False,
        "production": False,
    }


def plan_sha256() -> str:
    return _sha256(DOMAIN_PLAN + canonical_json(build_plan()))


def validate_plan() -> tuple[str, ...]:
    failures = []
    plan = build_plan()
    if len(STAGE_ORDER) != 6 or len(set(STAGE_ORDER)) != 6:
        failures.append("stage_order")
    if plan["profile_fingerprint"] != predecessor.BOUNDED_PROFILE:
        failures.append("profile")
    if plan["leaves"] != 4 or plan["tree_count"] != 1:
        failures.append("topology")
    if FROZEN_PLAN_SHA256 and plan_sha256() != FROZEN_PLAN_SHA256:
        failures.append("plan_sha256")
    return tuple(failures)


@dataclass(frozen=True)
class PortValue:
    port_id: str
    bit_length: int
    raw: bytes

    def __post_init__(self) -> None:
        if not self.port_id or self.bit_length <= 0 or type(self.raw) is not bytes:
            raise SplitRunnerError("invalid stage port value")
        if len(self.raw) != (self.bit_length + 7) // 8:
            raise SplitRunnerError("stage port byte width mismatch")
        unused = len(self.raw) * 8 - self.bit_length
        if unused and self.raw[-1] >> (8 - unused):
            raise SplitRunnerError("noncanonical high bits in stage port")


@dataclass(frozen=True)
class StageComputation:
    stage_id: str
    payload: dict[str, object]
    ports: tuple[PortValue, ...]


@dataclass(frozen=True)
class TreePreValue:
    polynomial: cap.TreePolynomial
    calls: tuple[cap.XOFCall, ...]


@dataclass(frozen=True)
class GlobalAValue:
    p_plain: tuple[int, ...]
    mhat_plain: tuple[int, ...]
    delta_p: tuple[int, ...]
    delta_mhat: tuple[int, ...]
    h1: int
    points_output: int
    points: tuple[int, ...]
    alpha: int
    calls: tuple[cap.XOFCall, ...]


@dataclass(frozen=True)
class TreePostValue:
    xi_masks: tuple[int, ...]


@dataclass(frozen=True)
class GlobalBValue:
    commitment: cap.CAPCommitment
    request_hash: bytes
    call: cap.XOFCall


def _schedule_sha256(calls: Sequence[cap.XOFCall]) -> str:
    document = [
        {
            "label": call.label,
            "domain_hex": call.domain.hex(),
            "field_sha256": [_sha256(value) for value in call.fields],
            "output_bits": call.output_bits,
            "output_sha256": _sha256(cap.pack_int(call.output, call.output_bits)),
        }
        for call in calls
    ]
    return _sha256(DOMAIN_SCHEDULE + canonical_json(document))


def _pack_vector(values: Sequence[int], bit_length: int) -> bytes:
    packed = 0
    for index, value in enumerate(values):
        if value < 0 or value >= 1 << bit_length:
            raise SplitRunnerError("vector element exceeds canonical bit width")
        packed |= value << (index * bit_length)
    return cap.pack_int(packed, len(values) * bit_length)


def _build_tree_pre(
    randomness: cap.CAPRandomness,
) -> tuple[TreePreValue, StageComputation]:
    tree_index = 0
    leaves = PARAMETERS.expanded_leaf_counts()[tree_index]
    extension_degree = PARAMETERS.expanded_extension_degrees()[tree_index]
    recorder = cap.XOFRecorder()
    leaf_seeds = cap.expand_tree(
        randomness.salt,
        randomness.roots[tree_index],
        tree_index,
        leaves,
        recorder,
    )
    commitments = []
    plain = 0
    masks = [0] * PARAMETERS.random_polynomial_bits
    for leaf_index, seed in enumerate(leaf_seeds, start=1):
        commitments.append(
            cap.seed_commit(randomness.salt, seed, tree_index, leaf_index, recorder)
        )
        tape = cap.expand_tape(
            seed,
            tree_index,
            leaf_index,
            PARAMETERS.random_polynomial_bits,
            recorder,
        )
        plain ^= tape
        inverse = cap.gf2m_inv(leaf_index, extension_degree)
        set_bits = tape
        while set_bits:
            low_bit = set_bits & -set_bits
            masks[low_bit.bit_length() - 1] ^= inverse
            set_bits ^= low_bit
    polynomial = cap.TreePolynomial(
        leaves,
        extension_degree,
        tuple(commitments),
        plain,
        tuple(masks),
    )
    witness_mask = (1 << PARAMETERS.witness_bits) - 1
    consistency_mask = (1 << PARAMETERS.consistency_bits) - 1
    mhat_shift = PARAMETERS.witness_bits + (PARAMETERS.degree - 1) * PARAMETERS.rho
    p_plain = plain & witness_mask
    mhat_plain = (plain >> mhat_shift) & consistency_mask
    commitment_raw = _pack_vector(
        tuple(value for pair in commitments for value in pair),
        field.FIELD_DEGREE,
    )
    p_raw = cap.pack_int(p_plain, PARAMETERS.witness_bits)
    mhat_raw = cap.pack_int(mhat_plain, PARAMETERS.consistency_bits)
    mask_raw = _pack_vector(masks, extension_degree)
    calls = tuple(recorder.calls)
    payload = {
        "tree_index": tree_index,
        "leaves": leaves,
        "extension_degree": extension_degree,
        "commitments_hex": commitment_raw.hex(),
        "plain_hex": cap.pack_int(plain, PARAMETERS.random_polynomial_bits).hex(),
        "masks_hex": mask_raw.hex(),
        "xof_call_count": len(calls),
        "xof_schedule_sha256": _schedule_sha256(calls),
    }
    computation = StageComputation(
        "tree-pre[0]",
        payload,
        (
            PortValue("tree[0].leaf-commitments", leaves * cap.HASH_BITS, commitment_raw),
            PortValue("tree[0].p-plain", PARAMETERS.witness_bits, p_raw),
            PortValue("tree[0].mhat-plain", PARAMETERS.consistency_bits, mhat_raw),
        ),
    )
    return TreePreValue(polynomial, calls), computation


def _build_global_a(
    tree_pre: TreePreValue,
) -> tuple[GlobalAValue, StageComputation]:
    polynomial = tree_pre.polynomial
    witness_mask = (1 << PARAMETERS.witness_bits) - 1
    consistency_mask = (1 << PARAMETERS.consistency_bits) - 1
    mhat_shift = PARAMETERS.witness_bits + (PARAMETERS.degree - 1) * PARAMETERS.rho
    p_plain = (polynomial.plain & witness_mask,)
    mhat_plain = ((polynomial.plain >> mhat_shift) & consistency_mask,)
    delta_p: tuple[int, ...] = ()
    delta_mhat: tuple[int, ...] = ()
    recorder = cap.XOFRecorder()
    h1 = recorder.call(
        "h1",
        cap.DOMAIN_H1,
        (
            bytes.fromhex(PROFILE_FINGERPRINT),
            cap._tree_component(0, polynomial),
            cap._correction_component(delta_p, delta_mhat, PARAMETERS),
        ),
        cap.HASH_BITS,
    )
    points_output = recorder.call(
        "consistency-points",
        cap.DOMAIN_CONSISTENCY_POINTS,
        (cap.hash_bytes(h1), bytes.fromhex(PROFILE_FINGERPRINT)),
        PARAMETERS.consistency_points * field.FIELD_DEGREE,
    )
    points = tuple(
        (points_output >> (index * field.FIELD_DEGREE)) & field.FIELD_MASK
        for index in range(PARAMETERS.consistency_points)
    )
    if any(point == 0 for point in points) or len(set(points)) != len(points):
        raise SplitRunnerError("degenerate bounded consistency points")
    alpha = cap._linear_hash_vector(p_plain[0], PARAMETERS.witness_bits, points)
    alpha ^= mhat_plain[0]
    calls = tuple(recorder.calls)
    points_raw = _pack_vector(points, field.FIELD_DEGREE)
    payload = {
        "h1_hex": cap.hash_bytes(h1).hex(),
        "points_hex": points_raw.hex(),
        "alpha_hex": cap.pack_int(alpha, PARAMETERS.consistency_bits).hex(),
        "delta_p_hex": [],
        "delta_mhat_hex": [],
        "xof_call_count": len(calls),
        "xof_schedule_sha256": _schedule_sha256(calls),
    }
    computation = StageComputation(
        "global-tail-phase-a",
        payload,
        (
            PortValue("global.phase-a.h1", cap.HASH_BITS, cap.hash_bytes(h1)),
            PortValue(
                "global.phase-a.consistency-points",
                PARAMETERS.consistency_points * field.FIELD_DEGREE,
                points_raw,
            ),
            PortValue(
                "global.phase-a.alpha",
                PARAMETERS.consistency_bits,
                cap.pack_int(alpha, PARAMETERS.consistency_bits),
            ),
        ),
    )
    return (
        GlobalAValue(
            p_plain,
            mhat_plain,
            delta_p,
            delta_mhat,
            h1,
            points_output,
            points,
            alpha,
            calls,
        ),
        computation,
    )


def _build_tree_post(
    tree_pre: TreePreValue,
    global_a: GlobalAValue,
) -> tuple[TreePostValue, StageComputation]:
    polynomial = tree_pre.polynomial
    mhat_shift = PARAMETERS.witness_bits + (PARAMETERS.degree - 1) * PARAMETERS.rho
    hashed = cap._linear_hash_masks(
        polynomial.masks[: PARAMETERS.witness_bits],
        PARAMETERS.witness_bits,
        polynomial.extension_degree,
        global_a.points,
    )
    mhat_masks = polynomial.masks[
        mhat_shift : mhat_shift + PARAMETERS.consistency_bits
    ]
    xi_masks = tuple(left ^ right for left, right in zip(hashed, mhat_masks))
    xi_raw = _pack_vector(xi_masks, polynomial.extension_degree)
    payload = {
        "tree_index": 0,
        "consistency_points_sha256": _sha256(
            _pack_vector(global_a.points, field.FIELD_DEGREE)
        ),
        "xi_masks_hex": xi_raw.hex(),
        "xi_count": len(xi_masks),
        "extension_degree": polynomial.extension_degree,
    }
    return (
        TreePostValue(xi_masks),
        StageComputation(
            "tree-post[0]",
            payload,
            (
                PortValue(
                    "tree[0].xi-masks",
                    PARAMETERS.consistency_bits * polynomial.extension_degree,
                    xi_raw,
                ),
            ),
        ),
    )


def _build_global_b(
    invocation: predecessor.InvocationSnapshotV1,
    randomness: cap.CAPRandomness,
    tree_pre: TreePreValue,
    global_a: GlobalAValue,
    tree_post: TreePostValue,
) -> tuple[GlobalBValue, StageComputation]:
    polynomial = tree_pre.polynomial
    recorder = cap.XOFRecorder()
    h2 = recorder.call(
        "h2",
        cap.DOMAIN_H2,
        (
            cap.hash_bytes(global_a.h1),
            cap._xi_component(
                global_a.alpha,
                tree_post.xi_masks,
                PARAMETERS.consistency_bits,
                polynomial.extension_degree,
            ),
        ),
        cap.HASH_BITS,
    )
    encoded = cap.serialize_commitment(
        PARAMETERS,
        randomness.salt,
        h2,
        global_a.alpha,
        global_a.delta_p,
        global_a.delta_mhat,
    )
    derived_mask = global_a.p_plain[0] & ((1 << PARAMETERS.mask_bits) - 1)
    append_base = (global_a.p_plain[0] >> PARAMETERS.mask_bits) & (
        (1 << PARAMETERS.appended_signature_bits) - 1
    )
    commitment = cap.CAPCommitment(
        PROFILE_FINGERPRINT,
        randomness.salt,
        global_a.h1,
        h2,
        global_a.alpha,
        global_a.delta_p,
        global_a.delta_mhat,
        derived_mask,
        append_base,
        encoded,
    )
    request_hash = sponge.hash_request_binding(invocation.ticket_message, encoded)
    direct = cap.execute_cap_commit(PARAMETERS, randomness)
    if direct.tree_polynomials != (polynomial,) or direct.commitment != commitment:
        raise SplitRunnerError("split CAP result differs from direct reference")
    direct_request = sponge.hash_request_binding(
        invocation.ticket_message, direct.commitment.encoded
    )
    if direct_request != request_hash:
        raise SplitRunnerError("split request binding differs from direct reference")
    mask_raw = cap.pack_int(derived_mask, PARAMETERS.mask_bits)
    append_raw = cap.pack_int(append_base, PARAMETERS.appended_signature_bits)
    payload = {
        "h2_hex": cap.hash_bytes(h2).hex(),
        "commitment_hex": encoded.hex(),
        "derived_mask_hex": mask_raw.hex(),
        "append_base_hex": append_raw.hex(),
        "request_hash_hex": request_hash.hex(),
        "xof_schedule_sha256": _schedule_sha256(tuple(recorder.calls)),
        "split_matches_direct_reference": True,
    }
    return (
        GlobalBValue(commitment, request_hash, recorder.calls[0]),
        StageComputation(
            "global-tail-phase-b",
            payload,
            (
                PortValue("global.phase-b.commitment", len(encoded) * 8, encoded),
                PortValue("global.phase-b.derived-mask", PARAMETERS.mask_bits, mask_raw),
                PortValue(
                    "global.phase-b.append-base",
                    PARAMETERS.appended_signature_bits,
                    append_raw,
                ),
                PortValue(
                    "global.phase-b.request-hash",
                    sponge.REQUEST_HASH_BITS,
                    request_hash,
                ),
            ),
        ),
    )


def build_stage_computations(
    statement_raw: bytes,
    witness_raw: bytes,
) -> tuple[predecessor.InvocationSnapshotV1, tuple[StageComputation, ...]]:
    invocation = predecessor.capture_invocation(statement_raw, witness_raw)
    randomness = cap.CAPRandomness(
        invocation.rho.randomness.salt,
        (invocation.rho.randomness.roots[0],),
    )
    tree_pre, tree_pre_computation = _build_tree_pre(randomness)
    global_a, global_a_computation = _build_global_a(tree_pre)
    tree_post, tree_post_computation = _build_tree_post(tree_pre, global_a)
    global_b, global_b_computation = _build_global_b(
        invocation, randomness, tree_pre, global_a, tree_post
    )
    bind_payload = {
        "statement_sha256": _sha256(invocation.statement_raw),
        "witness_sha256": _sha256(invocation.witness_raw),
        "rho_snapshot_sha256": invocation.rho.sha256,
        "ticket_message_sha256": _sha256(invocation.ticket_message),
        "same_immutable_rho_raw": True,
    }
    bind = StageComputation(
        "bind-invocation",
        bind_payload,
        (
            PortValue(
                "invocation.identity",
                256,
                bytes.fromhex(invocation.invocation_sha256),
            ),
        ),
    )
    global_b_digest = _sha256(canonical_json(global_b_computation.payload))
    final_payload = {
        "global_b_payload_sha256": global_b_digest,
        "commitment_sha256": _sha256(global_b.commitment.encoded),
        "request_hash_sha256": _sha256(global_b.request_hash),
        "split_matches_direct_reference": True,
        "formal_mask_matches_bounded_derived_mask": (
            invocation.witness.blind_mask
            == cap.pack_int(global_b.commitment.derived_mask, PARAMETERS.mask_bits)
        ),
        "full_i3_relation_claimed": False,
        "constraint_stream_split_lowered": False,
        "production_execution_started": False,
    }
    final = StageComputation(
        "final-seal",
        final_payload,
        (PortValue("split-run.final", 256, bytes.fromhex(global_b_digest)),),
    )
    computations = (
        bind,
        tree_pre_computation,
        global_a_computation,
        tree_post_computation,
        global_b_computation,
        final,
    )
    if tuple(item.stage_id for item in computations) != STAGE_ORDER:
        raise AssertionError("split computation stage order drift")
    return invocation, computations


def stage_filename(ordinal: int) -> str:
    if not 0 <= ordinal < len(STAGE_ORDER):
        raise SplitRunnerError("stage ordinal outside bounded plan")
    return f"stage-{ordinal:03d}.json"


def receipt_filename(completed_count: int) -> str:
    if not 0 <= completed_count <= len(STAGE_ORDER):
        raise SplitRunnerError("receipt count outside bounded plan")
    return f"receipt-{completed_count:03d}.json"


def _genesis_receipt(invocation_sha256: str) -> dict[str, object]:
    core = {
        "format": RECEIPT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": BOUNDED_RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "plan_sha256": plan_sha256(),
        "invocation_sha256": invocation_sha256,
        "completed_count": 0,
        "stage_id": None,
        "stage_artifact": None,
        "previous_receipt_sha256": None,
    }
    core["receipt_chain_sha256"] = _sha256(
        DOMAIN_RECEIPT + canonical_json(core)
    )
    return core


def _receipt(
    invocation_sha256: str,
    completed_count: int,
    stage_identity: Mapping[str, object],
    previous_receipt_sha256: str,
) -> dict[str, object]:
    core = {
        "format": RECEIPT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": BOUNDED_RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "plan_sha256": plan_sha256(),
        "invocation_sha256": invocation_sha256,
        "completed_count": completed_count,
        "stage_id": STAGE_ORDER[completed_count - 1],
        "stage_artifact": dict(stage_identity),
        "previous_receipt_sha256": previous_receipt_sha256,
    }
    core["receipt_chain_sha256"] = _hash_tuple(
        DOMAIN_RECEIPT,
        (
            bytes.fromhex(previous_receipt_sha256),
            completed_count.to_bytes(4, "little"),
            bytes.fromhex(str(stage_identity["sha256"])),
        ),
    )
    return core


def _validate_identity(
    identity: object, expected_filename: str, label: str
) -> dict[str, object]:
    current = _exact(identity, {"filename", "bytes", "sha256"}, label)
    if (
        current["filename"] != expected_filename
        or type(current["bytes"]) is not int
        or current["bytes"] <= 0
        or not _is_sha256(current["sha256"])
    ):
        raise SplitRunnerError(f"invalid {label} identity")
    return current


def _validate_receipt_document(
    document: object,
    *,
    invocation_sha256: str,
    completed_count: int,
    expected_stage_identity: Mapping[str, object] | None,
    previous_receipt_sha256: str | None,
) -> None:
    current = _exact(
        document,
        {
            "format",
            "implementation_version",
            "relation_id",
            "profile_fingerprint",
            "plan_sha256",
            "invocation_sha256",
            "completed_count",
            "stage_id",
            "stage_artifact",
            "previous_receipt_sha256",
            "receipt_chain_sha256",
        },
        "stage receipt",
    )
    if (
        current["format"] != RECEIPT_FORMAT
        or current["implementation_version"] != IMPLEMENTATION_VERSION
        or current["relation_id"] != BOUNDED_RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["plan_sha256"] != plan_sha256()
        or current["invocation_sha256"] != invocation_sha256
        or current["completed_count"] != completed_count
    ):
        raise SplitRunnerError("stage receipt execution identity mismatch")
    if completed_count == 0:
        if (
            current["stage_id"] is not None
            or current["stage_artifact"] is not None
            or current["previous_receipt_sha256"] is not None
        ):
            raise SplitRunnerError("genesis receipt is malformed")
        expected = _genesis_receipt(invocation_sha256)
    else:
        if expected_stage_identity is None or previous_receipt_sha256 is None:
            raise AssertionError("receipt validation expectation missing")
        if current["stage_id"] != STAGE_ORDER[completed_count - 1]:
            raise SplitRunnerError("stage receipt order mismatch")
        identity = _validate_identity(
            current["stage_artifact"],
            stage_filename(completed_count - 1),
            "stage artifact",
        )
        if identity != dict(expected_stage_identity):
            raise SplitRunnerError("stage receipt artifact identity mismatch")
        if current["previous_receipt_sha256"] != previous_receipt_sha256:
            raise SplitRunnerError("stage receipt chain predecessor mismatch")
        expected = _receipt(
            invocation_sha256,
            completed_count,
            expected_stage_identity,
            previous_receipt_sha256,
        )
    if current != expected:
        raise SplitRunnerError("stage receipt chain mismatch")


def _output_identity(
    invocation_sha256: str,
    computation: StageComputation,
) -> predecessor.StageOutputIdentityV1:
    return predecessor.StageOutputIdentityV1(
        relation_id=BOUNDED_RELATION_ID,
        profile_fingerprint=PROFILE_FINGERPRINT,
        plan_sha256=plan_sha256(),
        invocation_sha256=invocation_sha256,
        stage_id=computation.stage_id,
        rows=0,
        wires=0,
        stream_bytes=0,
        stream_sha256=_sha256(b""),
        outputs=tuple(
            (port.port_id, port.bit_length, _sha256(port.raw))
            for port in computation.ports
        ),
        assignment_materialized=False,
        external_assertions=0,
        verification_failures=0,
    )


def _stage_artifact(
    invocation_sha256: str,
    ordinal: int,
    computation: StageComputation,
    previous_receipt_sha256: str,
) -> dict[str, object]:
    if computation.stage_id != STAGE_ORDER[ordinal]:
        raise SplitRunnerError("stage computation order mismatch")
    payload_raw = canonical_json(computation.payload)
    output_identity = _output_identity(invocation_sha256, computation)
    return {
        "format": STAGE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": "INSECURE-TEST-ONLY",
        "relation_id": BOUNDED_RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "plan_sha256": plan_sha256(),
        "invocation_sha256": invocation_sha256,
        "ordinal": ordinal,
        "stage_id": computation.stage_id,
        "previous_receipt_sha256": previous_receipt_sha256,
        "payload_encoding": "canonical-json-object/v1",
        "payload_bytes": len(payload_raw),
        "payload_sha256": _sha256(payload_raw),
        "payload": computation.payload,
        "output_identity": output_identity.document(),
        "private_test_fixture_material": computation.stage_id
        in ("tree-pre[0]", "global-tail-phase-a", "tree-post[0]", "global-tail-phase-b"),
        "production": False,
    }


def _validate_stage_document(
    document: object,
    *,
    invocation_sha256: str,
    ordinal: int,
    computation: StageComputation,
    previous_receipt_sha256: str,
) -> None:
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
    expected = _stage_artifact(
        invocation_sha256, ordinal, computation, previous_receipt_sha256
    )
    if current != expected:
        raise SplitRunnerError("stage artifact differs from deterministic computation")
    payload_raw = canonical_json(current["payload"])
    if (
        current["payload_bytes"] != len(payload_raw)
        or current["payload_sha256"] != _sha256(payload_raw)
    ):
        raise SplitRunnerError("stage payload identity mismatch")
    output_raw = canonical_json(current["output_identity"])
    expected_output = _output_identity(invocation_sha256, computation)
    predecessor.StageOutputIdentityV1.decode_for(
        output_raw,
        relation_id=BOUNDED_RELATION_ID,
        profile_fingerprint=PROFILE_FINGERPRINT,
        plan_sha256=plan_sha256(),
        invocation_sha256=invocation_sha256,
        stage_id=STAGE_ORDER[ordinal],
    )
    if output_raw != expected_output.encode():
        raise SplitRunnerError("stage output identity differs from computation")


def _complete_document(
    invocation_sha256: str,
    stage_identities: Sequence[Mapping[str, object]],
    receipt_identities: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    if len(stage_identities) != len(STAGE_ORDER):
        raise SplitRunnerError("complete document requires all stages")
    if len(receipt_identities) != len(STAGE_ORDER) + 1:
        raise SplitRunnerError("complete document requires genesis and all receipts")
    result = {
        "format": COMPLETE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": "INSECURE-TEST-ONLY",
        "relation_id": BOUNDED_RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "plan_sha256": plan_sha256(),
        "invocation_sha256": invocation_sha256,
        "completed_stage_count": len(STAGE_ORDER),
        "stage_artifacts": [dict(item) for item in stage_identities],
        "receipts": [dict(item) for item in receipt_identities],
        "final_receipt_sha256": receipt_identities[-1]["sha256"],
        "split_matches_direct_reference": True,
        "constraint_stream_split_lowered": False,
        "formal_i3_relation_replayed": False,
        "assignment_materialized": False,
        "cryptographic_proofs_generated": 0,
        "production_execution_started": False,
    }
    result["result_sha256"] = _sha256(
        DOMAIN_COMPLETE + canonical_json(result)
    )
    return result


def _validate_complete_document(
    document: object,
    expected: Mapping[str, object],
) -> None:
    current = _exact(document, set(expected), "complete document")
    if current != dict(expected):
        raise SplitRunnerError("complete document identity mismatch")


def _allowed_names() -> set[str]:
    return {
        COMPLETE_FILENAME,
        *(stage_filename(index) for index in range(len(STAGE_ORDER))),
        *(receipt_filename(index) for index in range(len(STAGE_ORDER) + 1)),
    }


def _inventory_names(output_fd: int) -> set[str]:
    names = set(os.listdir(output_fd))
    unknown = names - _allowed_names()
    if unknown:
        raise SplitRunnerError("unknown output entry: " + sorted(unknown)[0])
    return names


def latest_receipt(output: Path, *, artifact_root: Path) -> launch_io.Snapshot:
    root = launch_io.ArtifactRoot(artifact_root)
    location = root.require_location(output)
    with launch_io.directory_fd(location, external=True) as output_fd:
        names = _inventory_names(output_fd)
        indices = [
            index
            for index in range(len(STAGE_ORDER) + 1)
            if receipt_filename(index) in names
        ]
        if not indices:
            raise SplitRunnerError("output has no stage receipt")
        return recovery_io.read(location / receipt_filename(max(indices)))


def execute_production_split_runner(*_args: object, **_kwargs: object) -> None:
    raise ProductionSplitRunnerUnavailable(
        "production split constraint lowerer is unavailable; no output was created"
    )


def run_bounded_split(
    statement_raw: bytes,
    witness_raw: bytes,
    output: Path,
    *,
    artifact_root: Path,
    fresh_output: bool = False,
    resume: bool = False,
    expected_checkpoint_sha256: str | None = None,
    stop_after_stages: int | None = None,
) -> dict[str, object] | None:
    if fresh_output == resume:
        raise SplitRunnerError("select exactly one of fresh_output or resume")
    if stop_after_stages is not None and not 0 <= stop_after_stages <= len(STAGE_ORDER):
        raise SplitRunnerError("stop_after_stages outside bounded plan")
    if resume and not _is_sha256(expected_checkpoint_sha256):
        raise SplitRunnerError("resume requires exact latest receipt SHA-256")
    if fresh_output and expected_checkpoint_sha256 is not None:
        raise SplitRunnerError("fresh output cannot take a checkpoint identity")

    invocation = predecessor.capture_invocation(statement_raw, witness_raw)
    with recovery_io.locked_output(output, artifact_root, fresh=fresh_output) as output_fd:
        names = _inventory_names(output_fd)
        if fresh_output and names:
            raise SplitRunnerError("fresh output directory is not empty")

        snapshots: dict[str, launch_io.Snapshot] = {}
        if fresh_output:
            genesis_raw = canonical_json(_genesis_receipt(invocation.invocation_sha256))
            recovery_io.publish(output / GENESIS_FILENAME, genesis_raw)
            names.add(GENESIS_FILENAME)
            snapshots[GENESIS_FILENAME] = launch_io.Snapshot(
                output / GENESIS_FILENAME, genesis_raw
            )
            if stop_after_stages == 0:
                return None
        else:
            receipt_indices = [
                index
                for index in range(len(STAGE_ORDER) + 1)
                if receipt_filename(index) in names
            ]
            if not receipt_indices:
                raise SplitRunnerError("resume output has no receipt")
            latest_index = max(receipt_indices)
            latest_name = receipt_filename(latest_index)
            # The external digest is checked under the output lock before any
            # CAP stage recomputation or other artifact read.
            latest_snapshot = recovery_io.read(output / latest_name)
            snapshots[latest_name] = latest_snapshot
            if latest_snapshot.identity["sha256"] != expected_checkpoint_sha256:
                raise SplitRunnerError("latest receipt digest mismatch")

        _, computations = build_stage_computations(statement_raw, witness_raw)
        names = _inventory_names(output_fd)
        receipt_indices = [
            index
            for index in range(len(STAGE_ORDER) + 1)
            if receipt_filename(index) in names
        ]
        if receipt_indices != list(range(max(receipt_indices) + 1)):
            raise SplitRunnerError("receipts are not a contiguous prefix")
        completed_count = max(receipt_indices)
        stage_indices = [
            index
            for index in range(len(STAGE_ORDER))
            if stage_filename(index) in names
        ]
        permitted_stage_indices = set(range(completed_count))
        permitted_stage_indices.add(completed_count)
        if set(stage_indices) - permitted_stage_indices:
            raise SplitRunnerError("stage artifacts are not a valid prefix plus orphan")
        if not set(range(completed_count)).issubset(stage_indices):
            raise SplitRunnerError("receipt refers to a missing stage artifact")
        if COMPLETE_FILENAME in names and completed_count != len(STAGE_ORDER):
            raise SplitRunnerError("premature complete document")

        previous_receipt_sha256: str | None = None
        stage_identities: list[dict[str, object]] = []
        receipt_identities: list[dict[str, object]] = []
        for receipt_index in range(completed_count + 1):
            receipt_name = receipt_filename(receipt_index)
            snapshot = snapshots.get(receipt_name)
            if snapshot is None:
                snapshot = recovery_io.read(output / receipt_name)
                snapshots[receipt_name] = snapshot
            if receipt_index == 0:
                _validate_receipt_document(
                    _strict_json(snapshot.raw, "genesis receipt"),
                    invocation_sha256=invocation.invocation_sha256,
                    completed_count=0,
                    expected_stage_identity=None,
                    previous_receipt_sha256=None,
                )
            else:
                stage_name = stage_filename(receipt_index - 1)
                stage_snapshot = snapshots.get(stage_name)
                if stage_snapshot is None:
                    stage_snapshot = recovery_io.read(output / stage_name)
                    snapshots[stage_name] = stage_snapshot
                assert previous_receipt_sha256 is not None
                _validate_stage_document(
                    _strict_json(stage_snapshot.raw, "stage artifact"),
                    invocation_sha256=invocation.invocation_sha256,
                    ordinal=receipt_index - 1,
                    computation=computations[receipt_index - 1],
                    previous_receipt_sha256=previous_receipt_sha256,
                )
                stage_identity = stage_snapshot.identity
                _validate_receipt_document(
                    _strict_json(snapshot.raw, "stage receipt"),
                    invocation_sha256=invocation.invocation_sha256,
                    completed_count=receipt_index,
                    expected_stage_identity=stage_identity,
                    previous_receipt_sha256=previous_receipt_sha256,
                )
                stage_identities.append(stage_identity)
            receipt_identities.append(snapshot.identity)
            previous_receipt_sha256 = snapshot.identity["sha256"]

        if completed_count < len(STAGE_ORDER) and stage_filename(completed_count) in names:
            orphan_name = stage_filename(completed_count)
            orphan = recovery_io.read(output / orphan_name)
            assert previous_receipt_sha256 is not None
            _validate_stage_document(
                _strict_json(orphan.raw, "orphan stage artifact"),
                invocation_sha256=invocation.invocation_sha256,
                ordinal=completed_count,
                computation=computations[completed_count],
                previous_receipt_sha256=previous_receipt_sha256,
            )
            snapshots[orphan_name] = orphan

        for ordinal in range(completed_count, len(STAGE_ORDER)):
            assert previous_receipt_sha256 is not None
            stage_name = stage_filename(ordinal)
            stage_raw = canonical_json(
                _stage_artifact(
                    invocation.invocation_sha256,
                    ordinal,
                    computations[ordinal],
                    previous_receipt_sha256,
                )
            )
            if stage_name in names:
                stage_snapshot = snapshots.get(stage_name)
                if stage_snapshot is None:
                    stage_snapshot = recovery_io.read(output / stage_name)
                if stage_snapshot.raw != stage_raw:
                    raise SplitRunnerError("orphan stage bytes differ from recomputation")
            else:
                recovery_io.publish(output / stage_name, stage_raw)
                stage_snapshot = launch_io.Snapshot(output / stage_name, stage_raw)
                names.add(stage_name)
            stage_identity = stage_snapshot.identity
            stage_identities.append(stage_identity)
            receipt_name = receipt_filename(ordinal + 1)
            receipt_raw = canonical_json(
                _receipt(
                    invocation.invocation_sha256,
                    ordinal + 1,
                    stage_identity,
                    previous_receipt_sha256,
                )
            )
            recovery_io.publish(output / receipt_name, receipt_raw)
            receipt_snapshot = launch_io.Snapshot(output / receipt_name, receipt_raw)
            receipt_identities.append(receipt_snapshot.identity)
            previous_receipt_sha256 = receipt_snapshot.identity["sha256"]
            names.add(receipt_name)
            if stop_after_stages == ordinal + 1:
                return None

        complete = _complete_document(
            invocation.invocation_sha256,
            stage_identities,
            receipt_identities,
        )
        complete_raw = canonical_json(complete)
        if COMPLETE_FILENAME in names:
            complete_snapshot = recovery_io.read(output / COMPLETE_FILENAME)
            _validate_complete_document(
                _strict_json(complete_snapshot.raw, "complete document"), complete
            )
            if complete_snapshot.raw != complete_raw:
                raise SplitRunnerError("complete bytes differ from deterministic result")
        else:
            recovery_io.publish(output / COMPLETE_FILENAME, complete_raw)
        return complete


def _fixture_bytes() -> tuple[bytes, bytes]:
    fixture = predecessor.issuance_relation.fixture()
    return fixture.statement, fixture.witness


def _snapshot_tree(output: Path) -> dict[str, bytes]:
    return {
        path.name: path.read_bytes()
        for path in output.iterdir()
        if path.is_file()
    }


@lru_cache(maxsize=1)
def bounded_self_check() -> dict[str, object]:
    statement_raw, witness_raw = _fixture_bytes()
    with TemporaryDirectory(prefix="pq-rbbc-issuance-split-runner-") as directory:
        root = Path(directory)
        reference_output = root / "reference"
        resumed_output = root / "resumed"
        mutation_output = root / "mutation"
        wrong_invocation_output = root / "wrong-invocation"

        reference = run_bounded_split(
            statement_raw,
            witness_raw,
            reference_output,
            artifact_root=root,
            fresh_output=True,
        )
        assert reference is not None
        run_bounded_split(
            statement_raw,
            witness_raw,
            resumed_output,
            artifact_root=root,
            fresh_output=True,
            stop_after_stages=3,
        )
        checkpoint = latest_receipt(resumed_output, artifact_root=root)
        resumed = run_bounded_split(
            statement_raw,
            witness_raw,
            resumed_output,
            artifact_root=root,
            resume=True,
            expected_checkpoint_sha256=str(checkpoint.identity["sha256"]),
        )
        assert resumed is not None

        run_bounded_split(
            statement_raw,
            witness_raw,
            mutation_output,
            artifact_root=root,
            fresh_output=True,
            stop_after_stages=2,
        )
        mutation_checkpoint = latest_receipt(mutation_output, artifact_root=root)
        mutated_path = mutation_output / stage_filename(0)
        mutated_document = json.loads(mutated_path.read_bytes())
        mutated_document["payload_sha256"] = "0" * 64
        mutated_path.write_bytes(canonical_json(mutated_document))
        before_failed_resume = _snapshot_tree(mutation_output)
        mutation_rejected = False
        try:
            run_bounded_split(
                statement_raw,
                witness_raw,
                mutation_output,
                artifact_root=root,
                resume=True,
                expected_checkpoint_sha256=str(
                    mutation_checkpoint.identity["sha256"]
                ),
            )
        except SplitRunnerError:
            mutation_rejected = True
        failed_resume_created_no_output = (
            before_failed_resume == _snapshot_tree(mutation_output)
        )

        run_bounded_split(
            statement_raw,
            witness_raw,
            wrong_invocation_output,
            artifact_root=root,
            fresh_output=True,
            stop_after_stages=1,
        )
        wrong_checkpoint = latest_receipt(
            wrong_invocation_output, artifact_root=root
        )
        invocation = predecessor.capture_invocation(statement_raw, witness_raw)
        wrong_statement = replace(
            invocation.statement,
            beta=bytes([invocation.statement.beta[0] ^ 1])
            + invocation.statement.beta[1:],
        ).encode()
        wrong_invocation_rejected = False
        try:
            run_bounded_split(
                wrong_statement,
                witness_raw,
                wrong_invocation_output,
                artifact_root=root,
                resume=True,
                expected_checkpoint_sha256=str(wrong_checkpoint.identity["sha256"]),
            )
        except SplitRunnerError:
            wrong_invocation_rejected = True

        existing_output_rejected = False
        try:
            run_bounded_split(
                statement_raw,
                witness_raw,
                reference_output,
                artifact_root=root,
                fresh_output=True,
            )
        except FileExistsError:
            existing_output_rejected = True

        production_refused = False
        try:
            execute_production_split_runner(object())
        except ProductionSplitRunnerUnavailable:
            production_refused = True

        reference_bytes = _snapshot_tree(reference_output)
        resumed_bytes = _snapshot_tree(resumed_output)
        complete_raw = reference_bytes[COMPLETE_FILENAME]
        final_receipt_raw = reference_bytes[receipt_filename(len(STAGE_ORDER))]
        tree_pre_raw = reference_bytes[stage_filename(1)]
        global_b_raw = reference_bytes[stage_filename(4)]
        result = {
            "relation_id": BOUNDED_RELATION_ID,
            "test_only": True,
            "stage_order": list(STAGE_ORDER),
            "plan_sha256": plan_sha256(),
            "durable_file_count": len(reference_bytes),
            "fresh_and_resume_byte_identical": reference_bytes == resumed_bytes,
            "complete_sha256": _sha256(complete_raw),
            "final_receipt_sha256": _sha256(final_receipt_raw),
            "tree_pre_stage_sha256": _sha256(tree_pre_raw),
            "global_b_stage_sha256": _sha256(global_b_raw),
            "split_matches_direct_reference": reference[
                "split_matches_direct_reference"
            ],
            "mutation_rejected": mutation_rejected,
            "failed_resume_created_no_output": failed_resume_created_no_output,
            "wrong_invocation_rejected": wrong_invocation_rejected,
            "existing_output_rejected": existing_output_rejected,
            "production_refused_before_output": production_refused,
            "value_layer_split_execution": True,
            "constraint_stream_split_lowered": False,
            "formal_i3_relation_replayed": False,
            "large_relation_rows_replayed": 0,
            "assignment_materialized": False,
            "cryptographic_proofs_generated": 0,
        }
        result["frozen_mismatches"] = [
            label
            for label, observed, frozen in (
                ("plan", result["plan_sha256"], FROZEN_PLAN_SHA256),
                ("complete", result["complete_sha256"], FROZEN_COMPLETE_SHA256),
                (
                    "final_receipt",
                    result["final_receipt_sha256"],
                    FROZEN_FINAL_RECEIPT_SHA256,
                ),
                (
                    "tree_pre_stage",
                    result["tree_pre_stage_sha256"],
                    FROZEN_TREE_PRE_STAGE_SHA256,
                ),
                (
                    "global_b_stage",
                    result["global_b_stage_sha256"],
                    FROZEN_GLOBAL_B_STAGE_SHA256,
                ),
            )
            if frozen and observed != frozen
        ]
        return result


def build_manifest() -> dict[str, object]:
    bounded = bounded_self_check()
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "production_relation_id": PRODUCTION_RELATION_ID,
        "bounded_relation_id": BOUNDED_RELATION_ID,
        "predecessor_production_plan_sha256": predecessor.production_plan_sha256(),
        "bounded_plan": build_plan(),
        "bounded_plan_sha256": plan_sha256(),
        "split_contract": {
            "tree_pre_consumes_global_points": False,
            "global_a_consumes_all_tree_pre_outputs": True,
            "tree_post_consumes_global_a_points": True,
            "global_b_consumes_all_tree_post_outputs": True,
            "split_result_compared_to_direct_cap_reference": True,
            "constraint_stream_split_lowering_implemented": False,
            "production_runner_implemented": False,
            "production_output_identities_instantiated": False,
            "historical_values_or_assignments_reused": False,
            "other_tree_observed_stream_bytes_used": False,
        },
        "publisher_contract": {
            "implementation": "pq_rbbc_recovery_io_v2_42",
            "linux_only": True,
            "trusted_external_root_required": True,
            "output_directory_direct_child_of_root": True,
            "cooperative_exclusive_directory_lock": True,
            "stage_publication": "O_TMPFILE+fsync+linkat-if-absent+directory-fsync",
            "overwrite_or_replace_permitted": False,
            "genesis_receipt": GENESIS_FILENAME,
            "immutable_stage_files": [
                stage_filename(index) for index in range(len(STAGE_ORDER))
            ],
            "append_only_receipts": [
                receipt_filename(index) for index in range(len(STAGE_ORDER) + 1)
            ],
            "complete_file": COMPLETE_FILENAME,
            "resume_requires_external_latest_receipt_sha256": True,
            "latest_receipt_checked_under_lock_before_recomputation": True,
            "one_captured_raw_per_artifact_validation": True,
            "one_exact_orphan_stage_may_be_recomputed_and_adopted": True,
            "unknown_gap_missing_or_mutated_artifacts_fail_closed": True,
            "pickle_permitted": False,
        },
        "filesystem_assumptions": {
            "trusted_producer_handoff_required": True,
            "writer_quiescence_required": True,
            "owner_mode_acl_writable_fd_mount_controls_external": True,
            "flock_excludes_malicious_same_credential_writer": False,
            "metadata_proves_no_concurrent_writer": False,
            "physical_power_loss_qualified": False,
            "kernel_crash_or_remount_qualified": False,
            "production_scale_qualified": False,
        },
        "bounded_qualification": bounded,
        "external_artifacts": {
            "required": list(predecessor.production_inputs.REQUIRED_EXTERNAL_ARTIFACTS),
            "present": [],
            "missing": list(predecessor.production_inputs.REQUIRED_EXTERNAL_ARTIFACTS),
            "trusted_handoff_completed": False,
            "independent_review_completed": False,
            "resource_reservation_completed": False,
            "large_run_authorized": False,
        },
        "resource_estimate": {
            "bounded_cpu_cores": 1,
            "bounded_elapsed_seconds_upper_bound": 60,
            "bounded_output_bytes_upper_bound": 131_072,
            "historical_18_tree_combined_rows": 589_030_555,
            "fresh_18_tree_estimated_seconds": [8_000, 12_000],
            "fresh_18_tree_minimum_memory_bytes": 16_000_000_000,
            "fresh_18_tree_minimum_free_disk_bytes": 64_000_000_000,
            "fresh_estimate_requires_new_reservation": True,
        },
        "exact_commands": {
            "bounded_self_check": (
                "PYTHONPATH=src python -u src/"
                "pq_rbbc_issuance_split_runner_v1.py --self-check"
            ),
            "read_only_external_preflight": (
                "PYTHONPATH=src python -u src/"
                "pq_rbbc_issuance_split_runner_v1.py --artifact-root "
                "/ABSOLUTE/PRIVATE/ARTIFACT/ROOT"
            ),
            "targeted_tests": (
                "PYTHONPATH=src python -m unittest "
                "tests.test_pq_rbbc_issuance_split_runner_v1 -v"
            ),
            "production_execution": None,
            "large_replay": None,
            "large_proving": None,
        },
        "claim_status": {
            "Defined": True,
            "Instantiated": {"bounded_test_only": True, "production": False},
            "Implemented": {
                "bounded_value_split_runner": True,
                "bounded_atomic_publisher": True,
                "production_constraint_split_runner": False,
            },
            "Tested": {
                "bounded_value_and_publication": True,
                "production": False,
            },
            "Evidence-sealed": {"bounded_metadata": True, "production": False},
            "Proof-closed": False,
            "Production-closed": False,
            "formal_pi_issue_generated": False,
            "qualified_pq_se_backend_integrated": False,
            "safe_to_materialize_production_cache": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
        },
        "artifact_policy": {
            "bounded_runtime_outputs_are_temporary_external_artifacts": True,
            "runtime_output_contains_private_fixture_material": True,
            "runtime_output_tracked_in_git": False,
            "assignment_br1cs_pickle_cache_checkpoint_resume_log_tracked": False,
            "large_artifacts_embedded": False,
            "historical_files_modified": False,
            "system_architecture_changed": False,
            "ticket_lifecycle_changed": False,
            "pq_sat_auth_changed": False,
        },
        "tracked_prerequisites": {
            name: {"path": path, "bytes": size, "sha256": digest}
            for name, (path, size, digest) in TRACKED_PREREQUISITES.items()
        },
        "tracked_validation_failures": list(validate_tracked_prerequisites()),
        "plan_validation_failures": list(validate_plan()),
    }


def build_portable_evidence() -> dict[str, object]:
    manifest_path = ROOT / "manifests/pq_rbbc_issuance_split_runner_manifest_v1.json"
    if manifest_path.is_file():
        manifest_identity = _identity(manifest_path)
    else:
        raw = canonical_json(build_manifest())
        manifest_identity = _raw_identity(manifest_path.name, raw)
    bounded = bounded_self_check()
    return {
        "format": EVIDENCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "production_relation_id": PRODUCTION_RELATION_ID,
        "bounded_relation_id": BOUNDED_RELATION_ID,
        "manifest": manifest_identity,
        "tracked_prerequisites_valid": not validate_tracked_prerequisites(),
        "plan_valid": not validate_plan(),
        "bounded_qualification": bounded,
        "temporary_runtime_output_embedded": False,
        "private_stage_payload_embedded": False,
        "absolute_paths_embedded": False,
        "production_constraint_stream_split_lowered": False,
        "production_output_identity_instantiated": False,
        "production_execution_started": False,
        "large_replay_started": False,
        "large_proving_started": False,
        "formal_pi_issue_generated": False,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
        "Proof-closed": False,
        "Production-closed": False,
        "historical_values_or_assignments_reused": False,
        "other_tree_observed_stream_bytes_used": False,
    }


def external_inventory_preflight(artifact_root: Path) -> dict[str, object]:
    report = predecessor.external_inventory_preflight(artifact_root)
    return {
        "format": FORMAT,
        "production_relation_id": PRODUCTION_RELATION_ID,
        "predecessor_report": report,
        "split_plan_valid": not validate_plan(),
        "production_constraint_split_runner_implemented": False,
        "production_output_created": False,
        "safe_to_materialize_production_cache": False,
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
