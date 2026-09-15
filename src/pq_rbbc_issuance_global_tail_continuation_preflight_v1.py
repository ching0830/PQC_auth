#!/usr/bin/env python3
"""Read-only preflight for restartable bounded issuance global-tail A/B.

This module derives the two-tree/four-leaf tail layout arithmetically from the
canonical transcript framing.  It validates tracked predecessor identities and
freezes the data that a future independently invocable Phase-A/Phase-B consumer
must receive.  It does not construct a CAP execution, lower a row, materialize
an assignment, reopen a captured candidate pathname, or publish private state.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from functools import lru_cache
import hashlib
import math
from pathlib import Path
from typing import Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_anemoi_sponge as sponge
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_global_tail as tail
import pq_rbbc_issuance_bounded_multitree_adapter_v1 as adapter
import pq_rbbc_issuance_bounded_multitree_native_v1 as native
import pq_rbbc_issuance_multitree_restart_scheduler_v1 as scheduler
import pq_rbbc_issuance_production_inputs_v1 as production_inputs
import pq_rbbc_launch_io_v2_41 as io


ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION_VERSION = "1.1"
FORMAT = "PQRBBC-ISSUANCE-GLOBAL-TAIL-CONTINUATION-PREFLIGHT-1"
CONTRACT_FORMAT = FORMAT + "-CONTRACT"
RELATION_ID = (
    "pq-rbbc/issuance/global-tail-continuation/"
    "multitree-4plus4-insecure-test-only/preflight/v1"
)
SOURCE_RELATION_ID = tail.RELATION_ID
ADAPTER_RELATION_ID = adapter.RELATION_ID
PROFILE_FINGERPRINT = (
    "520980f7518de0c8a22e9fcb66f3d3af1eb4ef50c2df9136b6df873d9f524356"
)
PLAN_SHA256 = "729418cf1f9400b729ea02798547d260bf508bb775819456193a4e9270087c84"
INVOCATION_SHA256 = (
    "ff4936ffb4e2de756ceeb9812101ec8f37f354f547f5303cbb73407e70cf5765"
)
POINT_SNAPSHOT_SHA256 = (
    "43eceeec2f4b9cda18bc96014bebbaed319e0e7a8a8c04a710a6950828826009"
)
VERIFIED_RECEIPT_PREFIX_IDENTITIES = (
    {
        "filename": "adapter-receipt-0000.private.json",
        "bytes": 957,
        "sha256": "39b44f41680d521649328daa8991dd210072c3b7a973395808a12481d68f566a",
    },
    {
        "filename": "adapter-receipt-0001.private.json",
        "bytes": 1_161,
        "sha256": "c9e5f3fabb701255e6777d7fbfcb0294306761dab94948bd036ec2f75c85ed45",
    },
    {
        "filename": "adapter-receipt-0002.private.json",
        "bytes": 1_306,
        "sha256": "29a0768e66e15ec989a0b44c98c500688618ec96683b7a171725670d6e14c523",
    },
)
MANIFEST_PATH = (
    "manifests/pq_rbbc_issuance_global_tail_continuation_preflight_manifest_v1.json"
)
EVIDENCE_PATH = (
    "artifacts/metadata/issuance_global_tail_continuation_preflight_v1/"
    "pq_rbbc_issuance_global_tail_continuation_preflight_portable_evidence_v1.json"
)
CONTRACT_MAX_BYTES = 64 * 1024


PREDECESSOR_PINS = {
    "src/pq_rbbc_cap_global_tail.py": (
        53_133,
        "09d6806a50412c8a6e2e9fcca9c1111305f597e069c4b20057529dd38351a3dd",
    ),
    "src/pq_rbbc_issuance_bounded_multitree_native_v1.py": (
        43_914,
        "91cc8729d4d1acb229404a39a25cd739c8aba9fa5ee007c00bbdc6864aba9a7e",
    ),
    "src/pq_rbbc_issuance_bounded_multitree_adapter_v1.py": (
        29_064,
        "a9aae19c0a03ecf620a6196d3be9b3f848c82dba88262ae0872cfcd7be0ed4d7",
    ),
    adapter.MANIFEST_PATH: (
        6_290,
        "aac661c6d32fee9991b8ceb1e28384b9f68df85bfcbdf79e6fa1997feec9db3e",
    ),
    "src/pq_rbbc_issuance_tree_post_continuation_v1.py": (
        64_057,
        "40147e14f1d14db87d4ec2fd223de1037695c3b7a1ed5a0fac3041fc50005bc3",
    ),
    "tests/test_pq_rbbc_issuance_tree_post_continuation_v1.py": (
        28_444,
        "d96a4fad476e39740b4896b8e056b4a931a89d164274935f6419936432a20aad",
    ),
    "src/pq_rbbc_issuance_tree_post_restart_v1.py": (
        51_763,
        "96876c8060971dfafdb5c844f83055af48b5d67357705a561755d8bebb20473e",
    ),
    "tests/test_pq_rbbc_issuance_tree_post_restart_v1.py": (
        24_086,
        "ad10d878ff5cf79d0f05c40a8261c1f34073162cbcafc5392a9bd6c5e06ec593",
    ),
    "manifests/pq_rbbc_issuance_tree_post_continuation_manifest_v1.json": (
        9_540,
        "5de22b1a9cb931b1571e69c4cb2d70a4b99e1efe71f978fcc2ada90e2a566857",
    ),
    "manifests/pq_rbbc_issuance_tree_post_restart_manifest_v1.json": (
        7_559,
        "ec87e2d3b42f6c2982596ef48060fd94bb2656fc7e7aec864bdecb21f28c8321",
    ),
    "artifacts/metadata/issuance_tree_post_continuation_v1/"
    "pq_rbbc_issuance_tree_post_continuation_portable_evidence_v1.json": (
        3_635,
        "3638c786d90af28e5b286c3da3854823324801cc387bfb57589c7d69bbcb7bbe",
    ),
    "artifacts/metadata/issuance_tree_post_restart_v1/"
    "pq_rbbc_issuance_tree_post_restart_portable_evidence_v1.json": (
        2_526,
        "682b064316f06bb08d0db10e03e41d85394d823de1978915f801486e850de45f",
    ),
    "src/pq_rbbc_issuance_multitree_restart_scheduler_v1.py": (
        54_862,
        "3bb999b414f810dd799e8b84c88fd83e2a7d14ee5ff687eb13b56a1aba01f50b",
    ),
    "tests/test_pq_rbbc_issuance_multitree_restart_scheduler_v1.py": (
        32_850,
        "df4ec76604e757cc4960da5e93fa885ab11e77725475f0ecefc45493287e652b",
    ),
    "manifests/pq_rbbc_issuance_multitree_restart_scheduler_v1.json": (
        17_155,
        "98de9e5ecfe99cd9592d870504c2e4d05cf3f4648b856a873c4b5e2c0c7b8045",
    ),
    "artifacts/metadata/issuance_multitree_restart_scheduler_v1/"
    "pq_rbbc_issuance_multitree_restart_scheduler_v1.json": (
        4_529,
        "67235d27db2f0b19fac60f89ecb7d0b406613737344a01cf7a32e0750d5f5dd6",
    ),
}


EXPECTED_PLAN = {
    "anchors": [122_385, 123_799],
    "durable_resume": False,
    "format": adapter.FORMAT,
    "global_a": [10_915, 23_094],
    "global_b": [23_094, 43_837],
    "max_rows": 300_000,
    "max_wires": 200_000,
    "point_starts": [22_705, 22_898],
    "production": False,
    "profile_fingerprint": PROFILE_FINGERPRINT,
    "relation_id": ADAPTER_RELATION_ID,
    "stage_order": list(adapter.ORDER),
    "tail_inputs": [1, 10_915],
    "trees": [
        {"index": 0, "post": [80_699, 83_111], "pre": [43_837, 80_699]},
        {"index": 1, "post": [119_973, 122_385], "pre": [83_111, 119_973]},
    ],
}


class PreflightError(ValueError):
    """A tracked identity or continuation contract was rejected."""


class ContinuationUnavailable(RuntimeError):
    """No independently invocable continuation executor exists in this gate."""


@dataclass(frozen=True)
class SpongeLayout:
    wires: int
    rows: int
    output_wire_offset: int


@dataclass(frozen=True)
class TailLayout:
    input_rows: int
    input_wire_start: int
    input_wire_end: int
    phase_a_row_start: int
    phase_a_row_end: int
    phase_a_wire_start: int
    phase_a_wire_end: int
    phase_b_row_start: int
    phase_b_row_end: int
    phase_b_wire_start: int
    phase_b_wire_end: int
    h1_wire_start: int
    point_wire_starts: tuple[int, ...]
    h2_wire_start: int
    commitment_wire_start: int
    derived_mask_wire_start: int
    append_base_wire_start: int
    request_hash_wire_start: int


def canonical_json(document: object) -> bytes:
    return io.canonical_json(document)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _payload_bytes(field_lengths: Sequence[int]) -> int:
    return len(sponge.TRANSCRIPT_MAGIC) + 2 + sum(8 + length for length in field_lengths)


def _sponge_layout(
    domain: bytes, field_lengths: Sequence[int], output_bits: int
) -> SpongeLayout:
    if output_bits > sponge.RATE_BITS:
        raise PreflightError("bounded layout expects one squeeze block")
    payload_bits = _payload_bytes(field_lengths) * 8
    header_bytes = len(sponge.FRAME_MAGIC) + 2 + len(domain) + 8
    absorbed_blocks = math.ceil((header_bytes * 8 + payload_bits + 2) / sponge.RATE_BITS)
    output_elements = math.ceil(output_bits / field.FIELD_DEGREE)
    permutation_wires = len(
        field.build_native_trace(
            (0,) * field.STATE_ELEMENTS, field.derive_parameters()
        ).assignment
    )
    if permutation_wires != 352:
        raise PreflightError("native permutation layout drift")
    block_wires = sponge.RATE_ELEMENTS + permutation_wires
    block_rows = sponge.RATE_ELEMENTS + field.TOTAL_ROWS + field.STATE_ELEMENTS
    output_wire_offset = payload_bits + absorbed_blocks * block_wires
    return SpongeLayout(
        wires=output_wire_offset + output_elements * field.FIELD_DEGREE,
        rows=(
            2 * payload_bits
            + absorbed_blocks * block_rows
            + output_elements * (field.FIELD_DEGREE + 1)
        ),
        output_wire_offset=output_wire_offset,
    )


@lru_cache(maxsize=1)
def derive_tail_layout() -> TailLayout:
    """Derive shape only; no CAP execution, witness, sink, or row emission."""

    parameters = native.PARAMETERS
    leaf_counts = parameters.expanded_leaf_counts()
    degrees = parameters.expanded_extension_degrees()
    profile_bytes = len(bytes.fromhex(cap.profile_fingerprint(parameters)))
    witness_bytes = math.ceil(parameters.witness_bits / 8)
    consistency_bytes = math.ceil(parameters.consistency_bits / 8)
    h1_lengths = (
        profile_bytes,
        *(8 + 2 * leaves * field.FIELD_ELEMENT_BYTES for leaves in leaf_counts),
        10
        + (parameters.tree_count - 1)
        * (witness_bytes + consistency_bytes),
    )
    point_lengths = (cap.HASH_BYTES, profile_bytes)
    h2_lengths = (
        cap.HASH_BYTES,
        *(
            6
            + consistency_bytes
            + math.ceil(parameters.consistency_bits * degree / 8)
            for degree in degrees
        ),
    )
    commitment_bytes = cap.commitment_bytes(parameters)
    request_lengths = (32, commitment_bytes)
    h1 = _sponge_layout(cap.DOMAIN_H1, h1_lengths, cap.HASH_BITS)
    points = _sponge_layout(
        cap.DOMAIN_CONSISTENCY_POINTS, point_lengths, parameters.consistency_bits
    )
    h2 = _sponge_layout(cap.DOMAIN_H2, h2_lengths, cap.HASH_BITS)
    request = _sponge_layout(
        sponge.REQUEST_BINDING_DOMAIN, request_lengths, sponge.REQUEST_HASH_BITS
    )

    input_wires = 2 * field.FIELD_DEGREE + 32 * 8
    input_wires += sum(
        2 * leaves * field.FIELD_DEGREE
        + parameters.witness_bits
        + parameters.consistency_bits
        + parameters.consistency_bits * degree
        for leaves, degree in zip(leaf_counts, degrees)
    )
    point_validation_wires = parameters.consistency_points + math.comb(
        parameters.consistency_points, 2
    )
    phase_a_wire_start = 1 + input_wires
    phase_a_wire_end = (
        phase_a_wire_start + h1.wires + points.wires + point_validation_wires
    )
    phase_a_row_start = input_wires
    phase_a_row_end = (
        phase_a_row_start + h1.rows + points.rows + point_validation_wires
    )

    coefficient_count = math.ceil(parameters.witness_bits / field.FIELD_DEGREE)
    alpha_multiplications = parameters.consistency_points * (coefficient_count - 1)
    alpha_wires = (
        alpha_multiplications + parameters.consistency_points * field.FIELD_DEGREE
    )
    alpha_rows = alpha_multiplications + parameters.consistency_points * (
        field.FIELD_DEGREE + 1
    )
    published_bits = (
        commitment_bytes * 8
        + parameters.mask_bits
        + parameters.appended_signature_bits
    )
    phase_b_wire_start = phase_a_wire_end
    h2_call_wire_start = phase_b_wire_start + alpha_wires
    commitment_wire_start = h2_call_wire_start + h2.wires
    derived_mask_wire_start = commitment_wire_start + commitment_bytes * 8
    append_base_wire_start = derived_mask_wire_start + parameters.mask_bits
    request_call_wire_start = append_base_wire_start + parameters.appended_signature_bits
    phase_b_wire_end = request_call_wire_start + request.wires
    phase_b_row_start = phase_a_row_end
    phase_b_row_end = (
        phase_b_row_start
        + alpha_rows
        + h2.rows
        + 2 * published_bits
        + request.rows
    )
    point_wire_start = phase_a_wire_start + h1.wires + points.output_wire_offset
    return TailLayout(
        input_rows=input_wires,
        input_wire_start=1,
        input_wire_end=phase_a_wire_start,
        phase_a_row_start=phase_a_row_start,
        phase_a_row_end=phase_a_row_end,
        phase_a_wire_start=phase_a_wire_start,
        phase_a_wire_end=phase_a_wire_end,
        phase_b_row_start=phase_b_row_start,
        phase_b_row_end=phase_b_row_end,
        phase_b_wire_start=phase_b_wire_start,
        phase_b_wire_end=phase_b_wire_end,
        h1_wire_start=phase_a_wire_start + h1.output_wire_offset,
        point_wire_starts=tuple(
            point_wire_start + index * field.FIELD_DEGREE
            for index in range(parameters.consistency_points)
        ),
        h2_wire_start=h2_call_wire_start + h2.output_wire_offset,
        commitment_wire_start=commitment_wire_start,
        derived_mask_wire_start=derived_mask_wire_start,
        append_base_wire_start=append_base_wire_start,
        request_hash_wire_start=request_call_wire_start + request.output_wire_offset,
    )


def _port(
    port_id: str,
    producer: str,
    start: int,
    width: int,
    consumers: Sequence[str],
) -> dict[str, object]:
    return {
        "port_id": port_id,
        "producer": producer,
        "wire_start": start,
        "wire_end_exclusive": start + width,
        "bit_length": width,
        "consumers": list(consumers),
    }


def tail_input_ports() -> tuple[dict[str, object], ...]:
    p = native.PARAMETERS
    result = [
        _port("shared.salt", "shared-inputs", 1, 386, ("global-b",)),
        _port("shared.message", "shared-inputs", 387, 256, ("global-b",)),
    ]
    cursor = 643
    for index, (leaves, degree) in enumerate(
        zip(p.expanded_leaf_counts(), p.expanded_extension_degrees())
    ):
        widths = (
            ("leaf-commitments", 2 * leaves * field.FIELD_DEGREE, "global-a"),
            ("p-plain", p.witness_bits, "global-a+global-b"),
            ("mhat-plain", p.consistency_bits, "global-a+global-b"),
            ("xi-masks", p.consistency_bits * degree, "global-b"),
        )
        for suffix, width, consumers in widths:
            producer = f"tree-{'post' if suffix == 'xi-masks' else 'pre'}[{index}]"
            result.append(
                _port(
                    f"tree[{index}].{suffix}",
                    producer,
                    cursor,
                    width,
                    tuple(consumers.split("+")),
                )
            )
            cursor += width
    if cursor != derive_tail_layout().input_wire_end:
        raise PreflightError("tail input port partition drift")
    return tuple(result)


def boundary_ports() -> tuple[dict[str, object], ...]:
    layout = derive_tail_layout()
    p = native.PARAMETERS
    return (
        _port(
            "global.phase-a.h1",
            "global-a",
            layout.h1_wire_start,
            cap.HASH_BITS,
            ("global-b",),
        ),
        _port(
            "global.phase-a.consistency-points",
            "global-a",
            layout.point_wire_starts[0],
            p.consistency_bits,
            ("tree-post[0]", "tree-post[1]", "global-b"),
        ),
        _port(
            "global.phase-b.commitment",
            "global-b",
            layout.commitment_wire_start,
            cap.commitment_bytes(p) * 8,
            ("parent",),
        ),
        _port(
            "global.phase-b.derived-mask",
            "global-b",
            layout.derived_mask_wire_start,
            p.mask_bits,
            ("parent",),
        ),
        _port(
            "global.phase-b.append-base",
            "global-b",
            layout.append_base_wire_start,
            p.appended_signature_bits,
            ("issuance-signature-flow",),
        ),
        _port(
            "global.phase-b.request-hash",
            "global-b",
            layout.request_hash_wire_start,
            sponge.REQUEST_HASH_BITS,
            ("parent",),
        ),
    )


def build_contract() -> dict[str, object]:
    layout = derive_tail_layout()
    input_ports = tail_input_ports()
    boundaries = boundary_ports()
    phase_a_inputs = [
        port["port_id"]
        for port in input_ports
        if "global-a" in port["consumers"]
    ]
    phase_b_inputs = ["shared.salt", "shared.message"]
    phase_b_inputs.extend(
        port["port_id"]
        for port in input_ports
        if port["port_id"].endswith((".p-plain", ".mhat-plain", ".xi-masks"))
    )
    phase_b_inputs.extend(
        ("global.phase-a.h1", "global.phase-a.consistency-points")
    )
    return {
        "format": CONTRACT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "source_relation_id": SOURCE_RELATION_ID,
        "adapter_relation_id": ADAPTER_RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "plan_sha256": PLAN_SHA256,
        "fixture_invocation_sha256": INVOCATION_SHA256,
        "mode": "INSECURE-TEST-ONLY",
        "tree_count": 2,
        "tree_shapes": [
            {"index": 0, "leaves": 4, "extension_degree": 3},
            {"index": 1, "leaves": 4, "extension_degree": 3},
        ],
        "input_ports": list(input_ports),
        "boundary_ports": list(boundaries),
        "phases": [
            {
                "stage_id": "global-a",
                "row_interval": [layout.phase_a_row_start, layout.phase_a_row_end],
                "wire_interval": [layout.phase_a_wire_start, layout.phase_a_wire_end],
                "input_port_ids": phase_a_inputs,
                "output_port_ids": [
                    "global.phase-a.h1",
                    "global.phase-a.consistency-points",
                ],
                "standalone_consumer_implemented": False,
            },
            {
                "stage_id": "global-b",
                "row_interval": [layout.phase_b_row_start, layout.phase_b_row_end],
                "wire_interval": [layout.phase_b_wire_start, layout.phase_b_wire_end],
                "input_port_ids": phase_b_inputs,
                "output_port_ids": [
                    "global.phase-b.commitment",
                    "global.phase-b.derived-mask",
                    "global.phase-b.append-base",
                    "global.phase-b.request-hash",
                ],
                "standalone_consumer_implemented": False,
            },
        ],
        "full_import_intervals": {
            "global-a": [[643, 4_621], [5_779, 9_757]],
            "global-b": [[1, 10_915], [10_915, 23_094]],
        },
        "relocation_contract": {
            "pre_ports_before_global_a": 6,
            "xi_ports_before_global_b": 2,
            "total_ports_before_global_b": 8,
            "source_and_target_values_must_be_bound_by_native_equalities": True,
            "hash_only_binding_permitted": False,
        },
        "continuation_snapshot_contract": {
            "single_open_single_bounded_read": True,
            "same_raw_for_identity_parse_binding_and_consumer": True,
            "candidate_pathname_reopen_permitted": False,
            "future_executor_consumes_same_candidate_set_snapshots": True,
            "metadata_proves_no_writer": False,
            "trusted_producer_handoff_and_writer_quiescence_external": True,
            "canonical_field_encoding": "F193-LE25",
            "unknown_version_domain_trailing_bytes_rejected": True,
            "global_a_result_owned_wire_interval": [10_915, 23_094],
            "global_a_result_owned_value_count": 12_179,
            "global_b_tail_input_wire_interval": [1, 10_915],
            "global_b_phase_a_wire_interval": [10_915, 23_094],
            "global_b_result_owned_wire_interval": [23_094, 43_837],
            "global_b_result_owned_value_count": 20_743,
            "ordered_group_identities_required": True,
            "row_semantics_digest_required": True,
            "global_a_verified_receipt_prefix_ordinals": [0, 1, 2],
            "global_a_verified_receipt_prefix_identities": list(
                VERIFIED_RECEIPT_PREFIX_IDENTITIES
            ),
            "all_declared_receipt_snapshots_require_raw_validation": True,
            "receipt_link_validation_uses_predecessor_snapshot_raw_sha256": True,
            "full_execution_receipt_chain_verified": False,
            "source_to_target_relocation_receipts_required": True,
        },
        "serial_fan_in_contract": {
            "ordered_predecessors": [
                "global-a-complete",
                "multitree-scheduler-complete",
            ],
            "scheduler_implementation_version": scheduler.IMPLEMENTATION_VERSION,
            "scheduler_ordered_tree_indices": list(scheduler.ORDERED_TREE_INDICES),
            "scheduler_verified_receipt_suffix_ordinals": [2, 3],
            "scheduler_verified_receipt_suffix_identities": list(
                scheduler.RECEIPT_SUFFIX_IDENTITIES
            ),
            "shared_overlap_ordinal": 2,
            "shared_overlap_raw_identity_required": True,
            "phase_a_points_raw_identity_matches_scheduler_handoff_required": True,
            "same_invocation_profile_and_plan_required": True,
            "consumer_must_use_captured_completed_snapshots": True,
            "candidate_pathname_reopen_permitted": False,
            "global_b_candidate_set_implemented": False,
        },
        "not_serialized_state": [
            "python_generator_frame",
            "allocator_mutable_object",
            "full_assignment",
            "tail_sink_hash_internal_state",
            "native_binding_hash_internal_state",
            "ordered_sponge_witness_pool",
            "open_file_descriptors_or_locks",
        ],
        "phase_a_to_phase_b_wire_identity": True,
        "production": False,
        "durable_resume_implemented": False,
    }


def validate_contract_bytes(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not 0 < len(raw) <= CONTRACT_MAX_BYTES:
        raise PreflightError("contract byte bound")
    try:
        document = io.strict_json(raw)
    except io.ValidationError as error:
        raise PreflightError("strict canonical contract rejected") from error
    if document != build_contract():
        raise PreflightError("contract version, domain, interval or schema mismatch")
    return document


def _adapter_manifest() -> dict[str, object]:
    snapshot = io.read_snapshot(ROOT / adapter.MANIFEST_PATH)
    try:
        document = snapshot.document()
    except io.ValidationError as error:
        raise PreflightError("adapter manifest is not canonical JSON") from error
    if document.get("plan") != EXPECTED_PLAN:
        raise PreflightError("adapter plan drift")
    qualification = document.get("bounded_qualification")
    if not isinstance(qualification, dict):
        raise PreflightError("adapter qualification missing")
    required = {
        "plan_sha256": PLAN_SHA256,
        "invocation_sha256": INVOCATION_SHA256,
        "point_snapshot_sha256": POINT_SNAPSHOT_SHA256,
        "relocation_port_count": 8,
        "other_tree_observed_stream_bytes_used": False,
        "Production-closed": False,
        "Proof-closed": False,
    }
    if any(qualification.get(key) != value for key, value in required.items()):
        raise PreflightError("adapter qualification boundary drift")
    return document


def _scheduler_manifest() -> dict[str, object]:
    snapshot = io.read_snapshot(ROOT / scheduler.MANIFEST_PATH)
    try:
        document = snapshot.document()
    except io.ValidationError as error:
        raise PreflightError("scheduler manifest is not canonical JSON") from error
    plan = document.get("execution_plan")
    claims = document.get("claim_status")
    if not isinstance(plan, dict) or not isinstance(claims, dict):
        raise PreflightError("scheduler plan or claims missing")
    receipt = plan.get("receipt_contract")
    if (
        document.get("implementation_version") != "1.2"
        or not isinstance(receipt, dict)
        or receipt.get("verified_suffix_ordinals") != [2, 3]
        or receipt.get("verified_receipt_suffix_identities")
        != list(scheduler.RECEIPT_SUFFIX_IDENTITIES)
        or receipt.get("full_receipt_chain_verified") is not False
        or claims.get("Production-closed") is not False
        or claims.get("Proof-closed") is not False
    ):
        raise PreflightError("scheduler receipt or claim boundary drift")
    if {
        key: scheduler.RECEIPT_SUFFIX_IDENTITIES[0][key]
        for key in ("bytes", "sha256")
    } != {
        key: VERIFIED_RECEIPT_PREFIX_IDENTITIES[2][key]
        for key in ("bytes", "sha256")
    }:
        raise PreflightError("Global-A/scheduler ordinal-2 raw identity mismatch")
    return document


def validate_prerequisites() -> tuple[str, ...]:
    failures: list[str] = []
    for path, (expected_bytes, expected_sha256) in PREDECESSOR_PINS.items():
        try:
            snapshot = io.read_snapshot(ROOT / path)
        except (OSError, io.ValidationError):
            failures.append(path + ":missing-or-unreadable")
            continue
        if len(snapshot.raw) != expected_bytes:
            failures.append(path + ":bytes")
        if sha256(snapshot.raw) != expected_sha256:
            failures.append(path + ":sha256")
    if failures:
        return tuple(failures)
    try:
        _adapter_manifest()
        _scheduler_manifest()
        validate_contract_bytes(canonical_json(build_contract()))
    except PreflightError as error:
        failures.append(str(error))
    return tuple(failures)


def execute_bounded_global_tail_continuation(*_args: object, **_kwargs: object) -> None:
    raise ContinuationUnavailable(
        "read-only preflight; independent global-A/global-B consumers are not implemented"
    )


def execute_production(*_args: object, **_kwargs: object) -> None:
    raise ContinuationUnavailable(
        "production global-tail continuation is not enabled by this bounded preflight"
    )


def preflight() -> dict[str, object]:
    failures = validate_prerequisites()
    layout = derive_tail_layout()
    blockers = [
        "ordered tree-pre completed-result publication is not implemented",
        "independently invocable global-A consumer and private result publication are not implemented",
        "Global-A complete and two tree-post completed results are not yet aggregated into one same-invocation CandidateSet",
        "the Global-A ordinal-0-to-2 raw prefix and scheduler ordinal-2-to-3 raw suffix overlap is defined but not yet consumed by a Global-B CandidateSet",
        "tail-prelude source-to-target relocation snapshot and native equality receipt are not implemented",
        "independently invocable global-B consumer and private result publication are not implemented",
        "production 18-tree namespace/provider and all 72 relocations are not qualified",
        "fresh parent I1-I5 composition and qualified PQ simulation-extractable backend are absent",
        "production external artifacts, independent review, reservation and explicit large-run authorization are absent",
        "trusted producer handoff, writer quiescence, owner/mode/ACL, existing writable FDs and mount controls are external",
    ]
    return {
        "format": FORMAT,
        "relation_id": RELATION_ID,
        "read_only_preflight_passed": not failures,
        "validation_failures": list(failures),
        "phase_a_contract_defined": True,
        "phase_b_contract_defined": True,
        "global_a_verified_receipt_prefix_ordinals": [0, 1, 2],
        "scheduler_verified_receipt_suffix_ordinals": [2, 3],
        "receipt_prefix_suffix_overlap_ordinal": 2,
        "full_execution_receipt_chain_verified": False,
        "global_b_same_invocation_fan_in_defined": True,
        "global_b_same_invocation_candidate_set_implemented": False,
        "phase_a_rows": layout.phase_a_row_end - layout.phase_a_row_start,
        "phase_b_rows": layout.phase_b_row_end - layout.phase_b_row_start,
        "bounded_rows_planned": layout.phase_b_row_end - layout.phase_a_row_start,
        "bounded_rows_replayed": 0,
        "production_rows_replayed": 0,
        "proofs_generated": 0,
        "independent_global_a_consumer_implemented": False,
        "independent_global_b_consumer_implemented": False,
        "global_tail_continuation_implemented": False,
        "safe_to_implement_next_bounded_gate": not failures,
        "safe_to_execute_bounded_continuation": False,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
        "production_execution_command": None,
        "large_replay_command": None,
        "large_proving_command": None,
        "external_inventory_scope": "not provisioned",
        "missing_production_artifacts": list(
            production_inputs.REQUIRED_EXTERNAL_ARTIFACTS
        ),
        "blockers": blockers,
        "Proof-closed": False,
        "Production-closed": False,
    }


def build_manifest() -> dict[str, object]:
    layout = derive_tail_layout()
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "implementation_identities": {
            path: io.read_snapshot(ROOT / path).identity
            for path in (
                "src/pq_rbbc_issuance_global_tail_continuation_preflight_v1.py",
                "tests/test_pq_rbbc_issuance_global_tail_continuation_preflight_v1.py",
            )
        },
        "predecessor_identities": {
            path: {"bytes": size, "sha256": digest}
            for path, (size, digest) in PREDECESSOR_PINS.items()
        },
        "contract": build_contract(),
        "layout": asdict(layout),
        "preflight": preflight(),
        "resource_budget": {
            "read_only_checker_seconds_upper_bound": 10,
            "read_only_checker_memory_mib_upper_bound": 64,
            "future_bounded_phase_a_rows": 19_671,
            "future_bounded_phase_b_rows": 35_494,
            "future_bounded_total_rows": 55_165,
            "future_bounded_memory_mib_upper_bound": 512,
            "future_bounded_seconds_upper_bound": 180,
            "production_estimate": None,
            "other_tree_observed_stream_bytes_used": False,
        },
        "claim_status": {
            "Defined": True,
            "Instantiated": False,
            "Implemented": "read-only-layout-and-continuation-contract-checker",
            "Tested": "static-positive-negative-mutation-only",
            "Evidence-sealed": "metadata-only",
            "Proof-closed": False,
            "Production-closed": False,
            "global_tail_continuation_implemented": False,
            "production_legacy18_provider_implemented": False,
            "qualified_pq_se_backend_integrated": False,
            "formal_pi_issue_generated": False,
            "full_execution_receipt_chain_verified": False,
            "global_b_same_invocation_candidate_set_implemented": False,
        },
        "artifact_policy": {
            "assignment_br1cs_or_row_archive_created": False,
            "pickle_cache_checkpoint_resume_log_created": False,
            "private_snapshot_or_witness_embedded": False,
            "large_replay_or_proving_output_created": False,
            "system_architecture_ticket_lifecycle_or_pq_sat_auth_changed": False,
        },
        "exact_commands": {
            "read_only": (
                "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python "
                "src/pq_rbbc_issuance_global_tail_continuation_preflight_v1.py"
            ),
            "targeted": (
                "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest "
                "tests.test_pq_rbbc_issuance_global_tail_continuation_preflight_v1 -v"
            ),
            "bounded_continuation": None,
            "production": None,
            "large_replay": None,
            "large_proving": None,
        },
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
        "contract_sha256": sha256(canonical_json(build_contract())),
        "read_only_preflight": preflight(),
        "portable_evidence_contains_absolute_paths": False,
        "private_values_or_assignment_embedded": False,
        "other_tree_observed_stream_bytes_used": False,
        "global_a_verified_receipt_prefix_ordinals": [0, 1, 2],
        "scheduler_verified_receipt_suffix_ordinals": [2, 3],
        "receipt_prefix_suffix_overlap_ordinal": 2,
        "full_execution_receipt_chain_verified": False,
        "global_b_same_invocation_candidate_set_implemented": False,
        "bounded_continuation_started": False,
        "large_replay_started": False,
        "large_proving_started": False,
        "formal_pi_issue_generated": False,
        "Proof-closed": False,
        "Production-closed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    print(canonical_json(preflight()).decode("ascii"), end="")


if __name__ == "__main__":
    main()
