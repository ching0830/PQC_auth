#!/usr/bin/env python3
"""Bounded independently invocable Global-B consumer and private restart.

Only the frozen two-tree/four-leaf ``INSECURE-TEST-ONLY`` fixture is
executable.  The consumer accepts one already validated immutable Global-B
CandidateSet, checks eight native relocation equality rowsets, and replays
only the 35,494 Phase-B rows.  It does not reopen predecessor pathnames or
replay tree-pre, Global-A, or tree-post.  Production remains unavailable.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import hashlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import MappingProxyType
from typing import Mapping, Sequence
from unittest.mock import patch

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_anemoi_sponge as sponge
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_global_tail as tail
import pq_rbbc_cap_shard_stream as shard
import pq_rbbc_issuance_bounded_multitree_adapter_v1 as base
import pq_rbbc_issuance_global_a_restart_v1 as global_a
import pq_rbbc_issuance_global_b_candidateset_preflight_v1 as candidateset
import pq_rbbc_issuance_multitree_restart_scheduler_v1 as scheduler
import pq_rbbc_issuance_private_spool_handoff_v1 as spool_handoff
import pq_rbbc_issuance_tree_post_continuation_v1 as continuation
import pq_rbbc_issuance_tree_post_restart_v1 as tree_restart
import pq_rbbc_launch_io_v2_41 as io
import pq_rbbc_recovery_io_v2_42 as disk


ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION_VERSION = "1.0"
FORMAT = "PQRBBC-ISSUANCE-GLOBAL-B-RESTART-1"
RELATION_ID = (
    "pq-rbbc/issuance/global-b-restart/"
    "multitree-4plus4-insecure-test-only/v1"
)
MODE = "INSECURE-TEST-ONLY"
FRAGMENT_STREAM_FORMAT = FORMAT + "-FRAGMENT-STREAM"
FRAGMENT_RECEIPT_FORMAT = FORMAT + "-FRAGMENT-RECEIPT"
PRIVATE_RESULT_FORMAT = FORMAT + "-PRIVATE-RESULT"
CHECKPOINT_FORMAT = FORMAT + "-CHECKPOINT"
PROFILE_FINGERPRINT = candidateset.PROFILE_FINGERPRINT
PLAN_SHA256 = candidateset.PLAN_SHA256
INVOCATION_SHA256 = candidateset.INVOCATION_SHA256
PHASE_B_INTERVAL = candidateset.GLOBAL_B_INTERVAL
PHASE_B_ROWS = candidateset.GLOBAL_B_ROWS
RELOCATION_ROWS = sum(spec[2] for spec in candidateset.RELOCATION_SPECS)
DOMAIN_ROWS = b"PQ-RBBC/ISSUANCE/GLOBAL-B-RESTART/ROWS/V1"
DOMAIN_ASSIGNMENT = b"PQ-RBBC/ISSUANCE/GLOBAL-B-RESTART/ASSIGNMENT/V1"
DOMAIN_BINDING = b"PQ-RBBC/ISSUANCE/GLOBAL-B-RESTART/BINDING/V1"

# Canonical producer-side source locations.  The two shared fields were
# allocated in the frozen adapter anchor interval; the remaining locations
# are already explicit in the CandidateSet relocation table.
SOURCE_STARTS = (123_799, 124_957, 78_265, 80_313, 81_953, 117_539, 119_587, 121_227)
H1_PORT = global_a.H1_PORT
POINT_STARTS = global_a.POINT_STARTS

PRIVATE_RESULT_NAME = "global-b-result.private.json"
FRAGMENT_RECEIPT_NAME = "global-b-fragment-receipt.private.json"
RESULT_NAMES = (PRIVATE_RESULT_NAME, FRAGMENT_RECEIPT_NAME)
PRIVATE_RESULT_LIMIT = 2 << 20
FRAGMENT_RECEIPT_LIMIT = 48 * 1024
CHECKPOINT_LIMIT = 64 * 1024
INPUT_LIMIT = 2 << 20
VALUE_ENCODING = "20743xf193-little-endian-hex"

INPUT_DIRECTORY = "inputs"
RESULT_DIRECTORY = "results"
JOURNAL_DIRECTORY = "journal"
PLAN_NAME = "0000-publication-plan.private.json"
INPUTS_COMMITTED_NAME = "0001-inputs-committed.private.json"
RESULT_COMMITTED_NAME = "0002-result-committed.private.json"
COMPLETE_NAME = "complete.private.json"
JOURNAL_NAMES = (PLAN_NAME, INPUTS_COMMITTED_NAME, RESULT_COMMITTED_NAME, COMPLETE_NAME)
STOP_BOUNDARIES = frozenset(
    {"inputs", "result-payload", "result-receipt", "result-checkpoint", "complete"}
)

MANIFEST_PATH = "manifests/pq_rbbc_issuance_global_b_restart_manifest_v1.json"
EVIDENCE_PATH = (
    "artifacts/metadata/issuance_global_b_restart_v1/"
    "pq_rbbc_issuance_global_b_restart_portable_evidence_v1.json"
)
PREDECESSOR_PINS = {
    "src/pq_rbbc_issuance_global_b_candidateset_preflight_v1.py": (
        58_869,
        "c6f482f022d13174633ac7612852b652febd3fb3c6d6f3feb0cc4142a2a79177",
    ),
    "tests/test_pq_rbbc_issuance_global_b_candidateset_preflight_v1.py": (
        24_757,
        "7cb4234b54de13afd61557d380be165c7fbb02c94daba8205adee3acb3d8bfdd",
    ),
    candidateset.MANIFEST_PATH: (
        9_096,
        "bd43cbb7f3c261b9303e2b19ca317d0e170d84bbf639d9fef365a95cf9ca1eb2",
    ),
    candidateset.EVIDENCE_PATH: (
        4_578,
        "d814043725349e588f73c1155893dfa37d1ca16f8ae17ac471fd34e56d097390",
    ),
    "src/pq_rbbc_recovery_io_v2_42.py": (
        3_839,
        "4213d7228f757a29a77243826b4a09d4506e48399c638338d59649b81f611e3d",
    ),
}

SUMMARY_FIELDS = {
    "format",
    "relation_id",
    "profile_fingerprint",
    "stage_id",
    "wire_interval",
    "relocation_rowsets",
    "relocation_rows",
    "phase_b_rows",
    "total_rows_checked",
    "nonlinear_rows",
    "linear_rows",
    "allocated_wires",
    "candidate_snapshot_identity_count",
    "candidate_handoff_sha256",
    "referenced_import_wires",
    "groups",
    "sponge_accounting",
    "fragment_stream_bytes",
    "fragment_stream_sha256",
    "row_semantics_sha256",
    "native_binding_rows_sha256",
    "private_owned_assignment_sha256",
    "output_ports",
    "commitment_sha256",
    "request_hash_sha256",
    "all_rows_satisfied",
    "external_assertions",
    "candidate_pathname_reopened",
    "tree_pre_replayed",
    "global_a_replayed",
    "tree_post_replayed",
    "full_execution_receipt_chain_verified",
    "production",
}
FROZEN = {
    "candidate_handoff_identity": dict(candidateset.FROZEN["candidate_handoff_identity"]),
    "relocation_rowsets": 8,
    "relocation_rows": 7_826,
    "phase_b_rows": 35_494,
    "total_rows_checked": 43_320,
    "nonlinear_rows": 20_483,
    "linear_rows": 22_837,
    "allocated_wires": 20_743,
    "referenced_import_wires": 16_424,
    "fragment_stream_bytes": 10_618_923,
    "fragment_stream_sha256": "2dac6be9e7f27d7fb172f521308fefae43049991c8f9076cbbd9dd33a4a3b8e0",
    "row_semantics_sha256": "fed7d639326472ed92b6a5db7c2eb5fc69efb28f44b5e0c253ec8443d4ec24e2",
    "native_binding_rows_sha256": "97407a5a428290d77517ff633a9aa5cfc9cd1a3072a9be52a140be5da31514e1",
    "private_owned_assignment_sha256": "f3927f1398a82e8403a5a65d2fd975722b002060a7af019d62860f16d109707a",
    "commitment_sha256": "778d6dc3526c29b24fd18f0a5e6d24b29ef0f429e3c532d1816f2e4f3815fc4e",
    "request_hash_sha256": "1724a62d61710ed6e4ec3bb0664df2192249bbc1472f0f88b916d55b07e5b863",
    "output_ports": {
        "commitment": [29_982, 4_088],
        "derived_mask": [34_070, 576],
        "append_base": [34_646, 1_472],
        "request_hash": [43_258, 576],
    },
    "groups": [
        {
            "name": "native-relocation-equalities",
            "rows": 7_826,
            "bytes": 1_546_086,
            "sha256": "b7d2106c0f9fbe3f1225fefdb3b810d4bd48d22d7ac7f7a07aad16ea94a93e88",
        },
        {
            "name": "shared-alpha",
            "rows": 408,
            "bytes": 352_886,
            "sha256": "229eeabecaa20291c33bb187a27f8bac2782547c2abe2c1b9319d9616ceaef0b",
        },
        {
            "name": "h2-commitment-and-request",
            "rows": 35_086,
            "bytes": 8_719_370,
            "sha256": "943d1a60a592ee60eba1e50fe76e090943e0e46727ed1941b25944bd196d5689",
        },
    ],
    "sponge_accounting": {
        "calls": 2,
        "permutations": 13,
        "permutation_rows": 4_368,
        "payload_bitness_rows": 8_608,
        "output_bitness_rows": 965,
        "linear_rows": 8_873,
        "source_link_rows": 8_608,
    },
    "private_result_identity": {
        "filename": PRIVATE_RESULT_NAME,
        "bytes": 1_039_596,
        "sha256": "f25145053700d3b651fc78d081a7dc92d099bd521f6df4747a177f90509c4984",
    },
    "fragment_receipt_identity": {
        "filename": FRAGMENT_RECEIPT_NAME,
        "bytes": 2_969,
        "sha256": "8d5253ba2c96269de2ead30d085bf005747bf2d7efad56fe32f3c6e938655a4e",
    },
    "complete_checkpoint_identity": {
        "filename": COMPLETE_NAME,
        "bytes": 9_265,
        "sha256": "fa4e29c19774e39a78aeddfd80203d582eae99f392770edba04e2ff041079525",
    },
}


class GlobalBRestartError(ValueError):
    """A CandidateSet, Phase-B row, private result, or restart was rejected."""


class ProductionUnavailable(RuntimeError):
    """This bounded checkpoint intentionally exposes no production API."""


@dataclass(frozen=True)
class GlobalBResultInsecureTestOnly:
    summary: Mapping[str, object]
    owned_values: tuple[int, ...]
    commitment: bytes
    request_hash: bytes
    receipt: io.Snapshot


@dataclass(frozen=True)
class PublishedGlobalBResultInsecureTestOnly:
    owned_values: tuple[int, ...]
    commitment: bytes
    request_hash: bytes
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
        raise GlobalBRestartError(label + " must be a lowercase SHA-256")
    return value


def _exact(value: object, fields: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise GlobalBRestartError(label + " closed schema mismatch")
    return value


def _snapshot(name: str, raw: bytes, limit: int = CHECKPOINT_LIMIT) -> io.Snapshot:
    if type(raw) is not bytes or not 0 < len(raw) <= limit:
        raise GlobalBRestartError("snapshot byte bound: " + name)
    return io.Snapshot(Path("/in-memory-insecure-test-only") / name, raw)


def _identity(snapshot: io.Snapshot, name: str, limit: int) -> dict[str, object]:
    if (
        type(snapshot) is not io.Snapshot
        or snapshot.location.name != name
        or not 0 < len(snapshot.raw) <= limit
    ):
        raise GlobalBRestartError("snapshot name/type/size mismatch: " + name)
    return snapshot.identity


def _identity_document(value: object, label: str) -> dict[str, object]:
    current = _exact(value, {"filename", "bytes", "sha256"}, label)
    if (
        type(current["filename"]) is not str
        or not current["filename"]
        or "/" in current["filename"]
        or not _is_int(current["bytes"])
        or not 0 < int(current["bytes"]) <= INPUT_LIMIT
    ):
        raise GlobalBRestartError(label + " invalid identity")
    _digest(current["sha256"], label)
    return current


def _pack_integer(values: Mapping[int, int], start: int, width: int) -> int:
    bits = []
    for wire in range(start, start + width):
        value = values.get(wire)
        if not _is_int(value) or value not in (0, 1):
            raise GlobalBRestartError("missing or non-binary imported bit")
        bits.append(value)
    return sum(value << bit for bit, value in enumerate(bits))


def _encode_values(values: Sequence[int]) -> str:
    if any(not _is_int(value) or not 0 <= value <= field.FIELD_MASK for value in values):
        raise GlobalBRestartError("private assignment contains non-field value")
    return b"".join(value.to_bytes(field.FIELD_ELEMENT_BYTES, "little") for value in values).hex()


def _decode_values(value: object) -> tuple[int, ...]:
    if type(value) is not str or len(value) % (2 * field.FIELD_ELEMENT_BYTES):
        raise GlobalBRestartError("private assignment encoding width")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise GlobalBRestartError("private assignment is not lowercase hex") from error
    if raw.hex() != value:
        raise GlobalBRestartError("private assignment requires lowercase hex")
    values = tuple(
        int.from_bytes(raw[offset : offset + field.FIELD_ELEMENT_BYTES], "little")
        for offset in range(0, len(raw), field.FIELD_ELEMENT_BYTES)
    )
    if any(item > field.FIELD_MASK for item in values):
        raise GlobalBRestartError("private assignment contains non-canonical field value")
    return values


def _assignment_digest(values: Sequence[int]) -> str:
    digest = hashlib.sha256(DOMAIN_ASSIGNMENT)
    digest.update(len(values).to_bytes(8, "big"))
    for value in values:
        digest.update(value.to_bytes(field.FIELD_ELEMENT_BYTES, "little"))
    return digest.hexdigest()


def validate_prerequisites() -> None:
    candidateset.validate_prerequisites()
    for path, (expected_bytes, expected_sha256) in PREDECESSOR_PINS.items():
        snapshot = io.read_snapshot(ROOT / path)
        if (len(snapshot.raw), sha256(snapshot.raw)) != (expected_bytes, expected_sha256):
            raise GlobalBRestartError("predecessor identity drift: " + path)


class _GlobalBSink(tail.BinaryRowSink):
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
                "stage_id": "global-b",
                "wire_interval": list(PHASE_B_INTERVAL),
            },
            initial_wire=PHASE_B_INTERVAL[0],
            assignment_writer=base._Writer(values, PHASE_B_INTERVAL[0]),
        )

    def allocate(self, count: int = 1, **kwargs: object) -> int:
        if self.next_wire + count > PHASE_B_INTERVAL[1]:
            raise GlobalBRestartError("Phase-B allocation exceeds reserved interval")
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
                elif not PHASE_B_INTERVAL[0] <= wire < self.next_wire:
                    raise GlobalBRestartError("Phase-B row used undeclared or future wire")
                if wire not in self.values:
                    raise GlobalBRestartError("Phase-B row used wire without captured value")
        if not shard._row_satisfied_fast(row, self.values):
            raise GlobalBRestartError("Global-B native row failed: " + label)
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


def _source_values(
    candidate: candidateset.GlobalBCandidateSetInsecureTestOnly,
    decoded: candidateset.DecodedGlobalBCandidateSetInsecureTestOnly,
) -> dict[int, int]:
    tree_pre_documents = tuple(snapshot.document() for snapshot in candidate.tree_pre.tree_results)
    result: dict[int, int] = {}
    for index, (spec, source_start) in enumerate(zip(candidateset.RELOCATION_SPECS, SOURCE_STARTS)):
        port_id, _, width, source_role, declared_source_start, source_field = spec
        if source_role == "shared":
            bits = decoded.shared_inputs[source_field]
        elif source_role == "tree-pre":
            tree_index = int(port_id[5])
            port = next(
                item
                for item in tree_pre_documents[tree_index]["ports"]
                if item["port_id"] == port_id
            )
            if port["source_wire_start"] != declared_source_start:
                raise GlobalBRestartError("tree-pre source locator drift")
            bits = global_a._decode_bits(port["packed_bits_hex"], width)
        elif source_role == "tree-post":
            tree_index = int(port_id[5])
            post_start = continuation.TREE_CONTRACTS[tree_index]["post"][0]
            offset = int(declared_source_start) - post_start
            bits = candidate.schedule.ordered_results[tree_index].owned_values[
                offset : offset + width
            ]
        else:  # pragma: no cover - frozen table
            raise GlobalBRestartError("unknown relocation source role")
        if len(bits) != width:
            raise GlobalBRestartError("relocation source width mismatch")
        for offset, bit in enumerate(bits):
            wire = source_start + offset
            if wire in result or not _is_int(bit) or bit not in (0, 1):
                raise GlobalBRestartError("relocation source overlap or non-binary value")
            result[wire] = bit
    return result


def _phase_b_material(
    decoded: candidateset.DecodedGlobalBCandidateSetInsecureTestOnly,
    values: Mapping[int, int],
) -> tuple[
    tuple[cap.XOFCall, cap.XOFCall],
    tuple[int, int],
    tuple[int, int],
    tuple[int, int],
    tuple[tuple[int, ...], tuple[int, ...]],
    int,
    bytes,
    int,
    int,
]:
    parameters = base.PARAMETERS
    salt_packed = sum(bit << index for index, bit in enumerate(decoded.shared_inputs["salt"]))
    salt = (salt_packed & field.FIELD_MASK, salt_packed >> field.FIELD_DEGREE)
    message_integer = sum(
        bit << index for index, bit in enumerate(decoded.shared_inputs["message"])
    )
    message = message_integer.to_bytes(32, "little")
    p_values = tuple(
        _pack_integer(values, spec[1], spec[2])
        for spec in (candidateset.RELOCATION_SPECS[2], candidateset.RELOCATION_SPECS[5])
    )
    mhat_values = tuple(
        _pack_integer(values, spec[1], spec[2])
        for spec in (candidateset.RELOCATION_SPECS[3], candidateset.RELOCATION_SPECS[6])
    )
    xi_flat = tuple(
        _pack_integer(values, spec[1], spec[2])
        for spec in (candidateset.RELOCATION_SPECS[4], candidateset.RELOCATION_SPECS[7])
    )
    xi_values = tuple(
        tuple(
            flat >> (coordinate * 3) & 0b111
            for coordinate in range(parameters.consistency_bits)
        )
        for flat in xi_flat
    )
    h1 = _pack_integer(values, H1_PORT[0], H1_PORT[1])
    points = tuple(
        _pack_integer(values, start, field.FIELD_DEGREE) for start in POINT_STARTS
    )
    alpha = cap._linear_hash_vector(p_values[0], parameters.witness_bits, points) ^ mhat_values[0]
    recorder = cap.XOFRecorder()
    h2 = recorder.call(
        "h2",
        cap.DOMAIN_H2,
        (
            cap.hash_bytes(h1),
            *(cap._xi_component(alpha, xi, parameters.consistency_bits, 3) for xi in xi_values),
        ),
        cap.HASH_BITS,
    )
    delta_p = (p_values[0] ^ p_values[1],)
    delta_mhat = (mhat_values[0] ^ mhat_values[1],)
    commitment = cap.serialize_commitment(parameters, salt, h2, alpha, delta_p, delta_mhat)
    derived_mask = p_values[0] & ((1 << parameters.mask_bits) - 1)
    append_base = (p_values[0] >> parameters.mask_bits) & (
        (1 << parameters.appended_signature_bits) - 1
    )
    request_output = int.from_bytes(sponge.hash_request_binding(message, commitment), "little")
    request_call = cap.XOFCall(
        "request-binding",
        sponge.REQUEST_BINDING_DOMAIN,
        (message, commitment),
        sponge.REQUEST_HASH_BITS,
        request_output,
    )
    return (
        (recorder.calls[0], request_call),
        p_values,
        mhat_values,
        points,
        xi_values,  # type: ignore[return-value]
        alpha,
        commitment,
        derived_mask,
        append_base,
    )


def execute_global_b_insecure_test_only(
    candidate: candidateset.GlobalBCandidateSetInsecureTestOnly,
    *,
    expected_handoff_sha256: str,
) -> GlobalBResultInsecureTestOnly:
    """Validate one immutable CandidateSet, then replay only Global-B."""

    decoded = candidateset.validate_candidate_set_insecure_test_only(
        candidate, expected_handoff_sha256=expected_handoff_sha256
    )
    values = dict(decoded.target_values)
    values.update(
        {global_a.PHASE_A_INTERVAL[0] + index: value
         for index, value in enumerate(decoded.global_a_values)}
    )
    # The preceding expression is intentionally checked rather than trusted:
    # Phase-A owns [10_915, 23_094), exactly 12,179 wires.
    if min(values) != 1 or any(
        values.get(global_a.PHASE_A_INTERVAL[0] + index) != value
        for index, value in enumerate(decoded.global_a_values)
    ):
        raise GlobalBRestartError("Global-A absolute import layout mismatch")
    sources = _source_values(candidate, decoded)
    if set(values).intersection(sources):
        raise GlobalBRestartError("producer source namespace overlaps Global-B imports")
    values.update(sources)
    imported = frozenset(values)
    calls, p_values, mhat_values, points, _, _, commitment, derived_mask, append_base = (
        _phase_b_material(decoded, values)
    )
    sink = _GlobalBSink(values, imported)

    sink.start_group("native-relocation-equalities")
    binding_digest = hashlib.sha256(DOMAIN_BINDING)
    for ordinal, (spec, source_start) in enumerate(
        zip(candidateset.RELOCATION_SPECS, SOURCE_STARTS)
    ):
        port_id, target_start, width, _, _, _ = spec
        for offset in range(width):
            label = f"relocation[{ordinal}].{port_id}[{offset}]"
            form = field.LinearForm.wire(source_start + offset).add(
                field.LinearForm.wire(target_start + offset)
            )
            sink.linear_zero(label, form)
            encoded = canonical_json(
                {"label": label, "source": source_start + offset, "target": target_start + offset}
            )
            binding_digest.update(len(encoded).to_bytes(8, "little"))
            binding_digest.update(encoded)
    sink.finish_group()
    if sink.rows != RELOCATION_ROWS:
        raise GlobalBRestartError("native relocation row count drift")

    pool = shard.OrderedSpongeWitnessPool(calls, 1)
    lowerer = shard.StreamingSpongeLowerer(sink, pool)
    accounting = shard.SpongeAccounting()
    try:
        p_starts = (candidateset.RELOCATION_SPECS[2][1], candidateset.RELOCATION_SPECS[5][1])
        mhat_starts = (candidateset.RELOCATION_SPECS[3][1], candidateset.RELOCATION_SPECS[6][1])
        xi_starts = (candidateset.RELOCATION_SPECS[4][1], candidateset.RELOCATION_SPECS[7][1])

        sink.start_group("shared-alpha")
        alpha_forms, alpha_values = shard._horner_leaf(
            sink,
            tuple(p_starts[0] + bit for bit in range(base.PARAMETERS.witness_bits)),
            p_values[0],
            POINT_STARTS,
            points,
            0,
        )
        alpha_output_starts = tuple(
            tail._decompose_form(sink, form, value, f"alpha.output[{index}]")
            for index, (form, value) in enumerate(zip(alpha_forms, alpha_values))
        )

        def alpha_bits():
            for coordinate in range(base.PARAMETERS.consistency_bits):
                point = coordinate // field.FIELD_DEGREE
                bit = coordinate % field.FIELD_DEGREE
                yield field.LinearForm.wire(alpha_output_starts[point] + bit).add(
                    field.LinearForm.wire(mhat_starts[0] + coordinate)
                )

        alpha_source = shard.BitSource(base.PARAMETERS.consistency_bits, alpha_bits)
        sink.finish_group()

        xi_sources = tuple(
            shard.source_concat(
                shard.source_constant(
                    base.PARAMETERS.consistency_bits.to_bytes(4, "little")
                    + (3).to_bytes(2, "little")
                ),
                shard.source_pad_to_byte(alpha_source),
                shard.source_pad_to_byte(
                    shard.source_wires(
                        xi_starts[index], base.PARAMETERS.consistency_bits * 3
                    )
                ),
            )
            for index in range(2)
        )
        sink.start_group("h2-commitment-and-request")
        h2 = lowerer.lower(
            calls[0], (shard.source_hash_bytes(H1_PORT[0]), *xi_sources), 2
        )
        accounting = accounting.add(h2.accounting)
        h2_start = h2.output_wires[0]
        correction_bytes = (base.PARAMETERS.consistency_bits + 7) // 8
        correction_bytes += (
            (base.PARAMETERS.witness_bits + 7) // 8
            + (base.PARAMETERS.consistency_bits + 7) // 8
        )
        profile_source = shard.source_constant(bytes.fromhex(PROFILE_FINGERPRINT))
        delta_p_source = tail._xor_source(
            p_starts[0], p_starts[1], base.PARAMETERS.witness_bits
        )
        delta_mhat_source = tail._xor_source(
            mhat_starts[0], mhat_starts[1], base.PARAMETERS.consistency_bits
        )
        commitment_source = shard.source_concat(
            shard.source_constant(cap.COMMITMENT_MAGIC + (1).to_bytes(2, "little")),
            profile_source,
            shard.source_field_bytes(1),
            shard.source_field_bytes(1 + field.FIELD_DEGREE),
            shard.source_hash_bytes(h2_start),
            shard.source_constant(correction_bytes.to_bytes(4, "little")),
            shard.source_pad_to_byte(alpha_source),
            shard.source_pad_to_byte(delta_p_source),
            shard.source_pad_to_byte(delta_mhat_source),
        )
        if commitment_source.bit_length != len(commitment) * 8:
            raise GlobalBRestartError("canonical commitment source width drift")
        commitment_start = shard._publish_source(
            sink,
            commitment_source,
            tuple((byte >> bit) & 1 for byte in commitment for bit in range(8)),
            "output.commitment",
        )
        mask_start = shard._publish_source(
            sink,
            shard.source_wires(p_starts[0], base.PARAMETERS.mask_bits),
            tail._bits(derived_mask, base.PARAMETERS.mask_bits),
            "output.derived-mask",
        )
        append_start = shard._publish_source(
            sink,
            shard.source_wires(
                p_starts[0] + base.PARAMETERS.mask_bits,
                base.PARAMETERS.appended_signature_bits,
            ),
            tail._bits(append_base, base.PARAMETERS.appended_signature_bits),
            "output.append-base",
        )
        request = lowerer.lower(
            calls[1],
            (
                shard.source_wires(387, 256),
                shard.source_wires(commitment_start, len(commitment) * 8),
            ),
            3,
        )
        accounting = accounting.add(request.accounting)
        request_start = request.output_wires[0]
        sink.finish_group()
    finally:
        pool.close()

    if sink.next_wire != PHASE_B_INTERVAL[1]:
        raise GlobalBRestartError("Phase-B final wire cursor drift")
    if sink.rows - RELOCATION_ROWS != PHASE_B_ROWS:
        raise GlobalBRestartError("Phase-B constraint count drift")
    required_imports = set(decoded.target_values) | set(sources)
    required_imports.update(range(H1_PORT[0], H1_PORT[0] + H1_PORT[1]))
    for start in POINT_STARTS:
        required_imports.update(range(start, start + field.FIELD_DEGREE))
    if not required_imports <= sink.referenced_imports:
        raise GlobalBRestartError("Global-B did not consume every required import")
    request_hash = calls[1].output.to_bytes(sponge.REQUEST_HASH_BYTES, "little")
    message = sum(
        bit << index for index, bit in enumerate(decoded.shared_inputs["message"])
    ).to_bytes(32, "little")
    if request_hash != sponge.hash_request_binding(message, commitment):
        raise GlobalBRestartError("request-binding output mismatch")

    trailer = {
        "relocation_rows": RELOCATION_ROWS,
        "phase_b_rows": PHASE_B_ROWS,
        "rows": sink.rows,
        "wire_interval": list(PHASE_B_INTERVAL),
        "commitment": [commitment_start, len(commitment) * 8],
        "derived_mask": [mask_start, base.PARAMETERS.mask_bits],
        "append_base": [append_start, base.PARAMETERS.appended_signature_bits],
        "request_hash": [request_start, sponge.REQUEST_HASH_BITS],
        "external_assertions": 0,
    }
    stream_bytes, stream_sha = sink.finish(trailer)
    owned_values = tuple(values[wire] for wire in range(*PHASE_B_INTERVAL))
    groups = [
        {"name": group.name, "rows": group.rows, "bytes": group.bytes, "sha256": group.sha256}
        for group in sink.groups
    ]
    summary = {
        "format": FRAGMENT_STREAM_FORMAT,
        "relation_id": RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "stage_id": "global-b",
        "wire_interval": list(PHASE_B_INTERVAL),
        "relocation_rowsets": len(candidateset.RELOCATION_SPECS),
        "relocation_rows": RELOCATION_ROWS,
        "phase_b_rows": PHASE_B_ROWS,
        "total_rows_checked": sink.rows,
        "nonlinear_rows": sink.nonlinear_rows,
        "linear_rows": sink.linear_rows,
        "allocated_wires": sink.allocated_wires,
        "candidate_snapshot_identity_count": 32,
        "candidate_handoff_sha256": expected_handoff_sha256,
        "referenced_import_wires": len(sink.referenced_imports),
        "groups": groups,
        "sponge_accounting": {
            name: getattr(accounting, name) for name in accounting.__dataclass_fields__
        },
        "fragment_stream_bytes": stream_bytes,
        "fragment_stream_sha256": stream_sha,
        "row_semantics_sha256": sink.row_semantics.hexdigest(),
        "native_binding_rows_sha256": binding_digest.hexdigest(),
        "private_owned_assignment_sha256": _assignment_digest(owned_values),
        "output_ports": {
            "commitment": [commitment_start, len(commitment) * 8],
            "derived_mask": [mask_start, base.PARAMETERS.mask_bits],
            "append_base": [append_start, base.PARAMETERS.appended_signature_bits],
            "request_hash": [request_start, sponge.REQUEST_HASH_BITS],
        },
        "commitment_sha256": sha256(commitment),
        "request_hash_sha256": sha256(request_hash),
        "all_rows_satisfied": True,
        "external_assertions": 0,
        "candidate_pathname_reopened": False,
        "tree_pre_replayed": False,
        "global_a_replayed": False,
        "tree_post_replayed": False,
        "full_execution_receipt_chain_verified": False,
        "production": False,
    }
    receipt_document = {
        "format": FRAGMENT_RECEIPT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "plan_sha256": PLAN_SHA256,
        "invocation_sha256": INVOCATION_SHA256,
        "stage_id": "global-b",
        "candidate_handoff_sha256": expected_handoff_sha256,
        "candidate_snapshot_identity_count": 32,
        "verified_adapter_receipt_ordinals": [0, 1, 2, 3],
        "verified_tree_post_receipt_branches": [0, 1],
        "summary": summary,
        "full_execution_receipt_chain_verified": False,
        "durable_resume": False,
        "production": False,
    }
    receipt = _snapshot(
        FRAGMENT_RECEIPT_NAME,
        canonical_json(receipt_document),
        FRAGMENT_RECEIPT_LIMIT,
    )
    _validate_fragment_receipt(
        receipt,
        expected_identity=receipt.identity,
        handoff_sha256=expected_handoff_sha256,
    )
    return GlobalBResultInsecureTestOnly(
        MappingProxyType(summary), owned_values, commitment, request_hash, receipt
    )


def _candidate_roles(
    candidate: candidateset.GlobalBCandidateSetInsecureTestOnly,
) -> tuple[tuple[str, io.Snapshot], ...]:
    roles: list[tuple[str, io.Snapshot]] = [
        ("candidate-handoff", candidate.handoff),
        ("shared-inputs", candidate.shared_inputs),
        ("tree-pre-handoff", candidate.tree_pre.handoff),
    ]
    roles.extend(
        (f"tree-pre-result-{index}", snapshot)
        for index, snapshot in enumerate(candidate.tree_pre.tree_results)
    )
    roles.extend(
        (f"adapter-receipt-{index}", snapshot)
        for index, snapshot in enumerate(candidate.tree_pre.receipts)
    )
    roles.extend(
        (
            ("global-a-result", candidate.global_a_result.result),
            ("global-a-points", candidate.global_a_result.point_snapshot),
            ("global-a-receipt", candidate.global_a_result.receipt),
            ("global-a-complete", candidate.global_a_result.complete_checkpoint),
        )
    )
    roles.extend(
        (f"continuation-{index}", snapshot)
        for index, snapshot in enumerate(candidate.continuations)
    )
    roles.extend(
        (f"scheduler-receipt-{index + 2}", snapshot)
        for index, snapshot in enumerate(candidate.scheduler_receipt_suffix)
    )
    roles.extend(
        (
            ("scheduler-plan", candidate.schedule.execution_plan),
            ("scheduler-complete", candidate.schedule.complete_checkpoint),
        )
    )
    for index, result in enumerate(candidate.schedule.ordered_results):
        roles.extend(
            (
                (f"tree-post-{index}-result", result.result),
                (f"tree-post-{index}-receipt", result.receipt),
                (f"tree-post-{index}-complete", result.complete_checkpoint),
            )
        )
    roles.extend(
        (f"relocation-{index}", snapshot)
        for index, snapshot in enumerate(candidate.relocations)
    )
    frozen = tuple(roles)
    if len(frozen) != 32 or len({role for role, _ in frozen}) != 32:
        raise GlobalBRestartError("exact 32-role CandidateSet inventory required")
    return frozen


def _storage_name(index: int, role: str) -> str:
    if type(index) is not int or not 0 <= index < 32:
        raise GlobalBRestartError("input storage ordinal")
    if type(role) is not str or not role or any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in role
    ):
        raise GlobalBRestartError("input role is not a canonical token")
    return f"input-{index:02d}-{role}.private.json"


def _input_inventory(
    candidate: candidateset.GlobalBCandidateSetInsecureTestOnly,
) -> list[dict[str, object]]:
    return [
        {
            "ordinal": index,
            "role": role,
            "storage_filename": _storage_name(index, role),
            "snapshot_identity": snapshot.identity,
        }
        for index, (role, snapshot) in enumerate(_candidate_roles(candidate))
    ]


def _validate_input_inventory(value: object) -> list[dict[str, object]]:
    if type(value) is not list or len(value) != 32:
        raise GlobalBRestartError("publication input inventory length")
    result = []
    seen_roles: set[str] = set()
    seen_names: set[str] = set()
    for index, item in enumerate(value):
        current = _exact(
            item,
            {"ordinal", "role", "storage_filename", "snapshot_identity"},
            "publication input descriptor",
        )
        if not _is_int(current["ordinal"]) or current["ordinal"] != index:
            raise GlobalBRestartError("publication input ordinal")
        role = current["role"]
        name = current["storage_filename"]
        if (
            type(role) is not str
            or type(name) is not str
            or name != _storage_name(index, role)
            or role in seen_roles
            or name in seen_names
        ):
            raise GlobalBRestartError("publication input role or filename")
        _identity_document(current["snapshot_identity"], "publication input identity")
        seen_roles.add(role)
        seen_names.add(name)
        result.append(current)
    return result


def _plan_document(
    candidate: candidateset.GlobalBCandidateSetInsecureTestOnly,
    *,
    expected_handoff_sha256: str,
) -> dict[str, object]:
    candidateset.validate_candidate_set_insecure_test_only(
        candidate, expected_handoff_sha256=expected_handoff_sha256
    )
    return {
        "format": CHECKPOINT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "plan_sha256": PLAN_SHA256,
        "invocation_sha256": INVOCATION_SHA256,
        "stage_id": "publication-plan",
        "ordinal": 0,
        "previous_checkpoint_sha256": None,
        "candidate_handoff_sha256": expected_handoff_sha256,
        "input_inventory": _input_inventory(candidate),
        "next_stage": "inputs-committed",
        "complete": False,
        "production": False,
    }


def _validate_plan(snapshot: io.Snapshot) -> dict[str, object]:
    _identity(snapshot, PLAN_NAME, CHECKPOINT_LIMIT)
    try:
        current = snapshot.document()
    except io.ValidationError as error:
        raise GlobalBRestartError("publication plan is not strict canonical JSON") from error
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
            "candidate_handoff_sha256",
            "input_inventory",
            "next_stage",
            "complete",
            "production",
        },
        "publication plan",
    )
    _digest(current["candidate_handoff_sha256"], "publication CandidateSet handoff")
    _validate_input_inventory(current["input_inventory"])
    if (
        current["format"] != CHECKPOINT_FORMAT
        or current["implementation_version"] != IMPLEMENTATION_VERSION
        or current["mode"] != MODE
        or current["relation_id"] != RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["plan_sha256"] != PLAN_SHA256
        or current["invocation_sha256"] != INVOCATION_SHA256
        or current["stage_id"] != "publication-plan"
        or not _is_int(current["ordinal"])
        or current["ordinal"] != 0
        or current["previous_checkpoint_sha256"] is not None
        or current["next_stage"] != "inputs-committed"
        or current["complete"] is not False
        or current["production"] is not False
        or canonical_json(current) != snapshot.raw
    ):
        raise GlobalBRestartError("publication plan domain, stage, or claim mismatch")
    return current


def _captured_original(
    stored: io.Snapshot, descriptor: Mapping[str, object]
) -> io.Snapshot:
    identity = _identity_document(descriptor["snapshot_identity"], "captured input identity")
    if (
        stored.location.name != descriptor["storage_filename"]
        or len(stored.raw) != identity["bytes"]
        or sha256(stored.raw) != identity["sha256"]
    ):
        raise GlobalBRestartError("captured input bytes or storage pathname mismatch")
    return io.Snapshot(
        Path("/captured-private-candidateset") / str(identity["filename"]),
        stored.raw,
    )


def _rebuild_candidate(
    snapshots: Mapping[str, io.Snapshot], expected_handoff_sha256: str
) -> candidateset.GlobalBCandidateSetInsecureTestOnly:
    tree_pre = global_a.TreePreCandidateSetInsecureTestOnly(
        snapshots["tree-pre-handoff"],
        (snapshots["tree-pre-result-0"], snapshots["tree-pre-result-1"]),
        (
            snapshots["adapter-receipt-0"],
            snapshots["adapter-receipt-1"],
            snapshots["adapter-receipt-2"],
        ),
    )
    global_a_receipt = snapshots["global-a-receipt"]
    global_a_points = snapshots["global-a-points"]
    global_a_receipt_document = global_a._validate_fragment_receipt(
        global_a_receipt,
        expected_identity=global_a_receipt.identity,
        candidates=tree_pre,
        handoff_sha256=tree_pre.handoff.identity["sha256"],
    )
    global_a_values, h1, points = global_a._validate_private_result(
        snapshots["global-a-result"],
        expected_identity=snapshots["global-a-result"].identity,
        point_snapshot=global_a_points,
        receipt_snapshot=global_a_receipt,
        receipt_document=global_a_receipt_document,
        handoff_sha256=tree_pre.handoff.identity["sha256"],
    )
    published_global_a = global_a.PublishedGlobalAResultInsecureTestOnly(
        global_a_values,
        h1,
        points,
        snapshots["global-a-result"],
        global_a_points,
        global_a_receipt,
        snapshots["global-a-complete"],
    )
    continuations = (snapshots["continuation-0"], snapshots["continuation-1"])
    receipt_suffix = (
        snapshots["scheduler-receipt-2"],
        snapshots["scheduler-receipt-3"],
    )
    execution_plan = snapshots["scheduler-plan"]
    plan_document = scheduler._validate_plan(execution_plan)
    ordered_results = []
    for index, continuation_snapshot in enumerate(continuations):
        continuation_document = continuation_snapshot.document()
        result_snapshot = snapshots[f"tree-post-{index}-result"]
        receipt_snapshot = snapshots[f"tree-post-{index}-receipt"]
        receipt_document = continuation.validate_tree_post_receipt(
            receipt_snapshot,
            expected_sha256=receipt_snapshot.identity["sha256"],
            continuation=continuation_document,
        )
        values, output_port = tree_restart._validate_private_result(
            result_snapshot,
            expected_identity=result_snapshot.identity,
            receipt_document=receipt_document,
            continuation_document=continuation_document,
        )
        result = tree_restart.PublishedTreePostResultInsecureTestOnly(
            index,
            values,
            output_port,
            result_snapshot,
            receipt_snapshot,
            snapshots[f"tree-post-{index}-complete"],
        )
        scheduler._validate_child_result(result, plan_document["trees"][index])
        ordered_results.append(result)
    schedule = scheduler.SchedulerResultInsecureTestOnly(
        tuple(ordered_results),
        execution_plan,
        snapshots["scheduler-complete"],
        (),
    )
    candidate = candidateset.GlobalBCandidateSetInsecureTestOnly(
        snapshots["candidate-handoff"],
        snapshots["shared-inputs"],
        tree_pre,
        published_global_a,
        continuations,
        tree_pre.receipts,
        receipt_suffix,
        schedule,
        tuple(snapshots[f"relocation-{index}"] for index in range(8)),
    )
    candidateset.validate_candidate_set_insecure_test_only(
        candidate, expected_handoff_sha256=expected_handoff_sha256
    )
    return candidate


def _load_candidate(
    output: Path, plan_document: Mapping[str, object]
) -> candidateset.GlobalBCandidateSetInsecureTestOnly:
    inventory = _validate_input_inventory(plan_document["input_inventory"])
    expected_names = {str(item["storage_filename"]) for item in inventory}
    present = _names(output / INPUT_DIRECTORY)
    if present != expected_names:
        raise GlobalBRestartError(
            "private CandidateSet publication is incomplete or contains unknown files"
        )
    snapshots = {}
    for descriptor in inventory:
        stored = disk.read(output / INPUT_DIRECTORY / str(descriptor["storage_filename"]))
        snapshots[str(descriptor["role"])] = _captured_original(stored, descriptor)
    return _rebuild_candidate(
        MappingProxyType(snapshots), str(plan_document["candidate_handoff_sha256"])
    )


def _private_result_document(
    result: GlobalBResultInsecureTestOnly, handoff_sha256: str
) -> dict[str, object]:
    return {
        "format": PRIVATE_RESULT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "plan_sha256": PLAN_SHA256,
        "invocation_sha256": INVOCATION_SHA256,
        "stage_id": "global-b",
        "candidate_handoff_sha256": handoff_sha256,
        "wire_interval": list(PHASE_B_INTERVAL),
        "value_encoding": VALUE_ENCODING,
        "value_count": len(result.owned_values),
        "owned_values_hex": _encode_values(result.owned_values),
        "private_owned_assignment_sha256": result.summary[
            "private_owned_assignment_sha256"
        ],
        "output_ports": result.summary["output_ports"],
        "commitment_hex": result.commitment.hex(),
        "commitment_sha256": result.summary["commitment_sha256"],
        "request_hash_hex": result.request_hash.hex(),
        "request_hash_sha256": result.summary["request_hash_sha256"],
        "source_receipt_sha256": result.receipt.identity["sha256"],
        "private_payload": True,
        "production": False,
    }


def _validate_fragment_receipt(
    snapshot: io.Snapshot,
    *,
    expected_identity: Mapping[str, object],
    handoff_sha256: str,
) -> Mapping[str, object]:
    _identity(snapshot, FRAGMENT_RECEIPT_NAME, FRAGMENT_RECEIPT_LIMIT)
    if snapshot.identity != expected_identity:
        raise GlobalBRestartError("fragment receipt external identity mismatch")
    try:
        current = snapshot.document()
    except io.ValidationError as error:
        raise GlobalBRestartError("fragment receipt is not strict canonical JSON") from error
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
            "candidate_handoff_sha256",
            "candidate_snapshot_identity_count",
            "verified_adapter_receipt_ordinals",
            "verified_tree_post_receipt_branches",
            "summary",
            "full_execution_receipt_chain_verified",
            "durable_resume",
            "production",
        },
        "fragment receipt",
    )
    summary = _exact(current["summary"], SUMMARY_FIELDS, "fragment receipt summary")
    for key in (
        "fragment_stream_sha256",
        "row_semantics_sha256",
        "native_binding_rows_sha256",
        "private_owned_assignment_sha256",
        "commitment_sha256",
        "request_hash_sha256",
    ):
        _digest(summary.get(key), "fragment receipt " + key)
    integer_claims = {
        "relocation_rowsets": 8,
        "relocation_rows": RELOCATION_ROWS,
        "phase_b_rows": PHASE_B_ROWS,
        "total_rows_checked": RELOCATION_ROWS + PHASE_B_ROWS,
        "allocated_wires": PHASE_B_INTERVAL[1] - PHASE_B_INTERVAL[0],
        "candidate_snapshot_identity_count": 32,
    }
    if any(
        not _is_int(summary.get(key)) or summary.get(key) != expected
        for key, expected in integer_claims.items()
    ):
        raise GlobalBRestartError("fragment receipt integer claim mismatch")
    for key in (
        "relocation_rowsets",
        "relocation_rows",
        "phase_b_rows",
        "total_rows_checked",
        "nonlinear_rows",
        "linear_rows",
        "allocated_wires",
        "referenced_import_wires",
        "fragment_stream_bytes",
        "fragment_stream_sha256",
        "row_semantics_sha256",
        "native_binding_rows_sha256",
        "private_owned_assignment_sha256",
        "commitment_sha256",
        "request_hash_sha256",
        "output_ports",
        "groups",
        "sponge_accounting",
    ):
        if summary.get(key) != FROZEN[key]:
            raise GlobalBRestartError("fragment receipt frozen summary drift: " + key)
    ordinal_claim = current["verified_adapter_receipt_ordinals"]
    branch_claim = current["verified_tree_post_receipt_branches"]
    if (
        current["format"] != FRAGMENT_RECEIPT_FORMAT
        or current["implementation_version"] != IMPLEMENTATION_VERSION
        or current["mode"] != MODE
        or current["relation_id"] != RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["plan_sha256"] != PLAN_SHA256
        or current["invocation_sha256"] != INVOCATION_SHA256
        or current["stage_id"] != "global-b"
        or current["candidate_handoff_sha256"] != handoff_sha256
        or handoff_sha256 != FROZEN["candidate_handoff_identity"]["sha256"]
        or not _is_int(current["candidate_snapshot_identity_count"])
        or current["candidate_snapshot_identity_count"] != 32
        or type(ordinal_claim) is not list
        or ordinal_claim != [0, 1, 2, 3]
        or any(not _is_int(item) for item in ordinal_claim)
        or type(branch_claim) is not list
        or branch_claim != [0, 1]
        or any(not _is_int(item) for item in branch_claim)
        or summary.get("format") != FRAGMENT_STREAM_FORMAT
        or summary.get("relation_id") != RELATION_ID
        or summary.get("profile_fingerprint") != PROFILE_FINGERPRINT
        or summary.get("stage_id") != "global-b"
        or summary.get("wire_interval") != list(PHASE_B_INTERVAL)
        or summary.get("candidate_handoff_sha256") != handoff_sha256
        or not _is_int(summary.get("external_assertions"))
        or summary.get("external_assertions") != 0
        or summary.get("all_rows_satisfied") is not True
        or summary.get("candidate_pathname_reopened") is not False
        or summary.get("tree_pre_replayed") is not False
        or summary.get("global_a_replayed") is not False
        or summary.get("tree_post_replayed") is not False
        or summary.get("full_execution_receipt_chain_verified") is not False
        or summary.get("production") is not False
        or current["full_execution_receipt_chain_verified"] is not False
        or current["durable_resume"] is not False
        or current["production"] is not False
        or canonical_json(current) != snapshot.raw
    ):
        raise GlobalBRestartError("fragment receipt domain, dependency, or claim mismatch")
    return MappingProxyType(dict(current))


def _validate_private_result(
    snapshot: io.Snapshot,
    *,
    expected_identity: Mapping[str, object],
    receipt_snapshot: io.Snapshot,
    receipt_document: Mapping[str, object],
    handoff_sha256: str,
) -> tuple[tuple[int, ...], bytes, bytes]:
    _identity(snapshot, PRIVATE_RESULT_NAME, PRIVATE_RESULT_LIMIT)
    if snapshot.identity != expected_identity:
        raise GlobalBRestartError("private result external identity mismatch")
    try:
        current = snapshot.document()
    except io.ValidationError as error:
        raise GlobalBRestartError("private result is not strict canonical JSON") from error
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
            "candidate_handoff_sha256",
            "wire_interval",
            "value_encoding",
            "value_count",
            "owned_values_hex",
            "private_owned_assignment_sha256",
            "output_ports",
            "commitment_hex",
            "commitment_sha256",
            "request_hash_hex",
            "request_hash_sha256",
            "source_receipt_sha256",
            "private_payload",
            "production",
        },
        "private result",
    )
    values = _decode_values(current["owned_values_hex"])
    try:
        commitment = bytes.fromhex(str(current["commitment_hex"]))
        request_hash = bytes.fromhex(str(current["request_hash_hex"]))
    except ValueError as error:
        raise GlobalBRestartError("private result output encoding") from error
    if commitment.hex() != current["commitment_hex"] or request_hash.hex() != current["request_hash_hex"]:
        raise GlobalBRestartError("private result outputs require lowercase hex")
    summary = receipt_document["summary"]
    ports = current["output_ports"]
    if type(ports) is not dict or set(ports) != {
        "commitment", "derived_mask", "append_base", "request_hash"
    }:
        raise GlobalBRestartError("private result output port inventory")
    for name, pair in ports.items():
        if (
            type(pair) is not list
            or len(pair) != 2
            or any(not _is_int(item) for item in pair)
            or not PHASE_B_INTERVAL[0] <= pair[0]
            or pair[0] + pair[1] > PHASE_B_INTERVAL[1]
            or pair[1] <= 0
        ):
            raise GlobalBRestartError("private result output port layout: " + name)
    def output_bytes(name: str) -> bytes:
        start, width = ports[name]
        offset = start - PHASE_B_INTERVAL[0]
        bits = values[offset : offset + width]
        if len(bits) != width or any(bit not in (0, 1) for bit in bits):
            raise GlobalBRestartError("private result output is not binary: " + name)
        integer = sum(bit << index for index, bit in enumerate(bits))
        return integer.to_bytes((width + 7) // 8, "little")
    if (
        current["format"] != PRIVATE_RESULT_FORMAT
        or current["implementation_version"] != IMPLEMENTATION_VERSION
        or current["mode"] != MODE
        or current["relation_id"] != RELATION_ID
        or current["profile_fingerprint"] != PROFILE_FINGERPRINT
        or current["plan_sha256"] != PLAN_SHA256
        or current["invocation_sha256"] != INVOCATION_SHA256
        or current["stage_id"] != "global-b"
        or current["candidate_handoff_sha256"] != handoff_sha256
        or current["wire_interval"] != list(PHASE_B_INTERVAL)
        or current["value_encoding"] != VALUE_ENCODING
        or not _is_int(current["value_count"])
        or current["value_count"] != len(values)
        or len(values) != PHASE_B_INTERVAL[1] - PHASE_B_INTERVAL[0]
        or current["private_owned_assignment_sha256"] != _assignment_digest(values)
        or current["private_owned_assignment_sha256"] != summary["private_owned_assignment_sha256"]
        or current["output_ports"] != summary["output_ports"]
        or output_bytes("commitment") != commitment
        or output_bytes("request_hash") != request_hash
        or current["commitment_sha256"] != sha256(commitment)
        or current["commitment_sha256"] != summary["commitment_sha256"]
        or current["request_hash_sha256"] != sha256(request_hash)
        or current["request_hash_sha256"] != summary["request_hash_sha256"]
        or current["source_receipt_sha256"] != receipt_snapshot.identity["sha256"]
        or current["private_payload"] is not True
        or current["production"] is not False
        or canonical_json(current) != snapshot.raw
    ):
        raise GlobalBRestartError("private result binding, values, outputs, or claim mismatch")
    return values, commitment, request_hash


def _expected_result_snapshots(
    result: GlobalBResultInsecureTestOnly, handoff_sha256: str
) -> tuple[io.Snapshot, io.Snapshot]:
    private = _snapshot(
        PRIVATE_RESULT_NAME,
        canonical_json(_private_result_document(result, handoff_sha256)),
        PRIVATE_RESULT_LIMIT,
    )
    _validate_fragment_receipt(
        result.receipt,
        expected_identity=result.receipt.identity,
        handoff_sha256=handoff_sha256,
    )
    return private, result.receipt


def _checkpoint_document(
    stage_id: str,
    ordinal: int,
    previous: io.Snapshot,
    plan: io.Snapshot,
    *,
    input_inventory: Sequence[Mapping[str, object]],
    output_identities: Sequence[Mapping[str, object]],
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
        "input_inventory": list(input_inventory),
        "output_identities": list(output_identities),
        "next_stage": None if complete else (
            "result-committed" if stage_id == "inputs-committed" else "complete"
        ),
        "complete": complete,
        "production": False,
    }


def _require_checkpoint(
    snapshot: io.Snapshot, expected: Mapping[str, object], name: str
) -> Mapping[str, object]:
    _identity(snapshot, name, CHECKPOINT_LIMIT)
    try:
        current = snapshot.document()
    except io.ValidationError as error:
        raise GlobalBRestartError("checkpoint is not strict canonical JSON: " + name) from error
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
        "publication checkpoint",
    )
    _validate_input_inventory(current["input_inventory"])
    outputs = current["output_identities"]
    if type(outputs) is not list or len(outputs) not in (0, 2):
        raise GlobalBRestartError("checkpoint output inventory length")
    for identity in outputs:
        _identity_document(identity, "checkpoint output identity")
    if (
        not _is_int(current["ordinal"])
        or type(current["complete"]) is not bool
        or current["production"] is not False
    ):
        raise GlobalBRestartError("checkpoint numeric or boolean type mismatch")
    _digest(current["previous_checkpoint_sha256"], "checkpoint previous link")
    _digest(current["publication_plan_sha256"], "checkpoint plan link")
    if current != expected or canonical_json(current) != snapshot.raw:
        raise GlobalBRestartError("checkpoint chain, inventory, or claim mismatch: " + name)
    return MappingProxyType(dict(current))


def _names(path: Path) -> set[str]:
    with io.directory_fd(path, external=True) as descriptor:
        names = set(os.listdir(descriptor))
        io._same_directory(path, descriptor, external=True)
        return names


def _journal_shape(names: set[str]) -> tuple[str, ...]:
    if not names or names - set(JOURNAL_NAMES):
        raise GlobalBRestartError("unknown or empty Global-B publication journal")
    ordered = tuple(name for name in JOURNAL_NAMES if name in names)
    if ordered != JOURNAL_NAMES[: len(ordered)]:
        raise GlobalBRestartError("Global-B journal is not a contiguous prefix")
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
    result = {}
    for name in ordered:
        path = output / JOURNAL_DIRECTORY / name
        result[name] = latest if latest is not None and latest.location == path else disk.read(path)
    return result


def _validate_published_results(
    output: Path,
    *,
    identities: Sequence[Mapping[str, object]],
    handoff_sha256: str,
    captured: Mapping[str, io.Snapshot] | None = None,
) -> PublishedGlobalBResultInsecureTestOnly:
    if type(identities) not in (list, tuple) or len(identities) != 2:
        raise GlobalBRestartError("exact two Global-B output identities required")
    captured = {} if captured is None else captured
    limits = (PRIVATE_RESULT_LIMIT, FRAGMENT_RECEIPT_LIMIT)
    snapshots = []
    for name, identity, limit in zip(RESULT_NAMES, identities, limits):
        _identity_document(identity, "Global-B output identity")
        snapshot = captured.get(name) or disk.read(output / RESULT_DIRECTORY / name)
        if (
            snapshot.location != output / RESULT_DIRECTORY / name
            or snapshot.identity != identity
            or len(snapshot.raw) > limit
        ):
            raise GlobalBRestartError("published Global-B output pathname or identity mismatch")
        snapshots.append(snapshot)
    private, receipt = snapshots
    receipt_document = _validate_fragment_receipt(
        receipt,
        expected_identity=identities[1],
        handoff_sha256=handoff_sha256,
    )
    values, commitment, request_hash = _validate_private_result(
        private,
        expected_identity=identities[0],
        receipt_snapshot=receipt,
        receipt_document=receipt_document,
        handoff_sha256=handoff_sha256,
    )
    return PublishedGlobalBResultInsecureTestOnly(
        values,
        commitment,
        request_hash,
        private,
        receipt,
        _snapshot(COMPLETE_NAME, b"{}\n"),
    )


def _stop(stop_after: str | None, boundary: str) -> bool:
    return stop_after == boundary


def run_bounded_global_b(
    output: Path,
    *,
    artifact_root: Path,
    fresh_candidate: candidateset.GlobalBCandidateSetInsecureTestOnly | None = None,
    expected_handoff_sha256: str | None = None,
    fresh_output: bool = False,
    resume: bool = False,
    expected_checkpoint_sha256: str | None = None,
    stop_after: str | None = None,
) -> PublishedGlobalBResultInsecureTestOnly | None:
    """Publish or resume the bounded private Global-B workflow."""

    validate_prerequisites()
    if type(fresh_output) is not bool or type(resume) is not bool or fresh_output == resume:
        raise GlobalBRestartError("select exactly one of fresh_output or resume")
    if stop_after is not None and stop_after not in STOP_BOUNDARIES:
        raise GlobalBRestartError("unknown Global-B stop boundary")
    expected_plan_raw = None
    source_roles = None
    if fresh_output:
        if (
            type(fresh_candidate) is not candidateset.GlobalBCandidateSetInsecureTestOnly
            or type(expected_handoff_sha256) is not str
            or expected_checkpoint_sha256 is not None
        ):
            raise GlobalBRestartError("fresh publication requires CandidateSet and exact digest")
        # All CandidateSet validation occurs before output creation.
        plan_document = _plan_document(
            fresh_candidate, expected_handoff_sha256=expected_handoff_sha256
        )
        expected_plan_raw = canonical_json(plan_document)
        source_roles = _candidate_roles(fresh_candidate)
    else:
        if fresh_candidate is not None or expected_handoff_sha256 is not None:
            raise GlobalBRestartError("resume accepts no live CandidateSet or handoff override")
        _digest(expected_checkpoint_sha256, "external restart checkpoint")

    with disk.locked_output(output, artifact_root, fresh=fresh_output) as output_fd:
        if fresh_output:
            for name in (INPUT_DIRECTORY, RESULT_DIRECTORY, JOURNAL_DIRECTORY):
                os.mkdir(name, mode=0o700, dir_fd=output_fd)
            os.fsync(output_fd)
            disk.publish(output / JOURNAL_DIRECTORY / PLAN_NAME, expected_plan_raw)
            for index, (role, snapshot) in enumerate(source_roles):
                disk.publish(
                    output / INPUT_DIRECTORY / _storage_name(index, role), snapshot.raw
                )
        with io.directory_fd(output / INPUT_DIRECTORY, external=True) as input_fd, \
                io.directory_fd(output / RESULT_DIRECTORY, external=True) as result_fd, \
                io.directory_fd(output / JOURNAL_DIRECTORY, external=True) as journal_fd:
            latest = None
            if resume:
                latest = latest_checkpoint(output, artifact_root=artifact_root)
                if latest.identity["sha256"] != expected_checkpoint_sha256:
                    raise GlobalBRestartError("restart checkpoint identity mismatch or stale digest")
            journal = _capture_journal(output, latest)
            plan = journal[PLAN_NAME]
            plan_document = _validate_plan(plan)
            if expected_plan_raw is not None and plan.raw != expected_plan_raw:
                raise GlobalBRestartError("fresh publication plan differs from CandidateSet")
            candidate = _load_candidate(output, plan_document)
            input_inventory = plan_document["input_inventory"]
            inputs_document = _checkpoint_document(
                "inputs-committed",
                1,
                plan,
                plan,
                input_inventory=input_inventory,
                output_identities=(),
                complete=False,
            )
            inputs_raw = canonical_json(inputs_document)
            if INPUTS_COMMITTED_NAME in journal:
                _require_checkpoint(
                    journal[INPUTS_COMMITTED_NAME], inputs_document, INPUTS_COMMITTED_NAME
                )
            elif len(journal) != 1:
                raise GlobalBRestartError("journal gap before inputs-committed")
            result_names = _names(output / RESULT_DIRECTORY)
            if result_names - set(RESULT_NAMES):
                raise GlobalBRestartError("unknown private Global-B output artifact")
            expected_prefix = tuple(name for name in RESULT_NAMES if name in result_names)
            if set(expected_prefix) != result_names or expected_prefix != RESULT_NAMES[: len(expected_prefix)]:
                raise GlobalBRestartError("Global-B output publication is not a contiguous prefix")
            if INPUTS_COMMITTED_NAME not in journal and result_names:
                raise GlobalBRestartError("Global-B output exists before restartable input boundary")
            disk.sync_directory(output / INPUT_DIRECTORY, input_fd)
            disk.sync_directory(output / RESULT_DIRECTORY, result_fd)
            disk.sync_directory(output / JOURNAL_DIRECTORY, journal_fd)
            disk.sync_directory(output, output_fd)
            if INPUTS_COMMITTED_NAME not in journal:
                disk.publish(output / JOURNAL_DIRECTORY / INPUTS_COMMITTED_NAME, inputs_raw)
                journal[INPUTS_COMMITTED_NAME] = io.Snapshot(
                    output / JOURNAL_DIRECTORY / INPUTS_COMMITTED_NAME, inputs_raw
                )
            inputs_checkpoint = journal[INPUTS_COMMITTED_NAME]
            if _stop(stop_after, "inputs"):
                return None

            if RESULT_COMMITTED_NAME in journal:
                result_document = journal[RESULT_COMMITTED_NAME].document()
                identities = result_document.get("output_identities")
                published = _validate_published_results(
                    output,
                    identities=identities,
                    handoff_sha256=str(plan_document["candidate_handoff_sha256"]),
                )
            else:
                result = execute_global_b_insecure_test_only(
                    candidate,
                    expected_handoff_sha256=str(plan_document["candidate_handoff_sha256"]),
                )
                expected_outputs = _expected_result_snapshots(
                    result, str(plan_document["candidate_handoff_sha256"])
                )
                captured = {}
                for index, (name, expected) in enumerate(zip(RESULT_NAMES, expected_outputs)):
                    if name in result_names:
                        actual = disk.read(output / RESULT_DIRECTORY / name)
                        if actual.raw != expected.raw:
                            raise GlobalBRestartError("existing Global-B output orphan differs: " + name)
                        captured[name] = actual
                        disk.sync_directory(output / RESULT_DIRECTORY, result_fd)
                    else:
                        disk.publish(output / RESULT_DIRECTORY / name, expected.raw)
                        result_names.add(name)
                        captured[name] = io.Snapshot(output / RESULT_DIRECTORY / name, expected.raw)
                    boundary = ("result-payload", "result-receipt")[index]
                    if _stop(stop_after, boundary):
                        return None
                identities = [snapshot.identity for snapshot in expected_outputs]
                published = _validate_published_results(
                    output,
                    identities=identities,
                    handoff_sha256=str(plan_document["candidate_handoff_sha256"]),
                    captured=captured,
                )
                result_checkpoint_document = _checkpoint_document(
                    "result-committed",
                    2,
                    inputs_checkpoint,
                    plan,
                    input_inventory=input_inventory,
                    output_identities=identities,
                    complete=False,
                )
                result_raw = canonical_json(result_checkpoint_document)
                disk.publish(output / JOURNAL_DIRECTORY / RESULT_COMMITTED_NAME, result_raw)
                journal[RESULT_COMMITTED_NAME] = io.Snapshot(
                    output / JOURNAL_DIRECTORY / RESULT_COMMITTED_NAME, result_raw
                )
            result_checkpoint = journal[RESULT_COMMITTED_NAME]
            expected_result_checkpoint = _checkpoint_document(
                "result-committed",
                2,
                inputs_checkpoint,
                plan,
                input_inventory=input_inventory,
                output_identities=identities,
                complete=False,
            )
            _require_checkpoint(
                result_checkpoint, expected_result_checkpoint, RESULT_COMMITTED_NAME
            )
            if _stop(stop_after, "result-checkpoint"):
                return None
            complete_document = _checkpoint_document(
                "complete",
                3,
                result_checkpoint,
                plan,
                input_inventory=input_inventory,
                output_identities=identities,
                complete=True,
            )
            complete_raw = canonical_json(complete_document)
            if COMPLETE_NAME in journal:
                _require_checkpoint(journal[COMPLETE_NAME], complete_document, COMPLETE_NAME)
            else:
                disk.publish(output / JOURNAL_DIRECTORY / COMPLETE_NAME, complete_raw)
                journal[COMPLETE_NAME] = io.Snapshot(
                    output / JOURNAL_DIRECTORY / COMPLETE_NAME, complete_raw
                )
            published = PublishedGlobalBResultInsecureTestOnly(
                published.owned_values,
                published.commitment,
                published.request_hash,
                published.result,
                published.receipt,
                journal[COMPLETE_NAME],
            )
            if _stop(stop_after, "complete") or stop_after is None:
                return published
    raise GlobalBRestartError("unreachable Global-B restart state")


def capture_completed_result(
    output: Path,
    *,
    artifact_root: Path,
    expected_complete_sha256: str,
) -> PublishedGlobalBResultInsecureTestOnly:
    _digest(expected_complete_sha256, "external complete checkpoint")
    latest = latest_checkpoint(output, artifact_root=artifact_root)
    if latest.location.name != COMPLETE_NAME or latest.identity["sha256"] != expected_complete_sha256:
        raise GlobalBRestartError("complete checkpoint identity mismatch")
    journal = _capture_journal(output, latest)
    if tuple(journal) != JOURNAL_NAMES:
        raise GlobalBRestartError("completed Global-B journal is incomplete")
    plan = journal[PLAN_NAME]
    plan_document = _validate_plan(plan)
    _load_candidate(output, plan_document)
    inputs_document = _checkpoint_document(
        "inputs-committed",
        1,
        plan,
        plan,
        input_inventory=plan_document["input_inventory"],
        output_identities=(),
        complete=False,
    )
    _require_checkpoint(journal[INPUTS_COMMITTED_NAME], inputs_document, INPUTS_COMMITTED_NAME)
    result_document = journal[RESULT_COMMITTED_NAME].document()
    identities = result_document.get("output_identities")
    expected_result = _checkpoint_document(
        "result-committed",
        2,
        journal[INPUTS_COMMITTED_NAME],
        plan,
        input_inventory=plan_document["input_inventory"],
        output_identities=identities,
        complete=False,
    )
    _require_checkpoint(journal[RESULT_COMMITTED_NAME], expected_result, RESULT_COMMITTED_NAME)
    complete_document = _checkpoint_document(
        "complete",
        3,
        journal[RESULT_COMMITTED_NAME],
        plan,
        input_inventory=plan_document["input_inventory"],
        output_identities=identities,
        complete=True,
    )
    _require_checkpoint(latest, complete_document, COMPLETE_NAME)
    published = _validate_published_results(
        output,
        identities=identities,
        handoff_sha256=str(plan_document["candidate_handoff_sha256"]),
    )
    return PublishedGlobalBResultInsecureTestOnly(
        published.owned_values,
        published.commitment,
        published.request_hash,
        published.result,
        published.receipt,
        latest,
    )


def execute_production(*_args: object, **_kwargs: object) -> None:
    raise ProductionUnavailable(
        "bounded Global-B restart is test-only; production refused before I/O"
    )


def preflight() -> dict[str, object]:
    validate_prerequisites()
    return {
        "format": FORMAT,
        "relation_id": RELATION_ID,
        "read_only_preflight_passed": True,
        "candidate_contract_consumed": True,
        "independent_global_b_consumer_implemented": True,
        "native_relocation_rowsets_executed": 8,
        "native_relocation_rows_executed": RELOCATION_ROWS,
        "global_b_constraints_replayed": PHASE_B_ROWS,
        "private_append_only_publication_implemented": True,
        "restart_implemented": True,
        "restartable_boundary": "inputs-committed",
        "candidate_snapshot_roles_published": 32,
        "candidate_pathname_reopen_permitted": False,
        "full_execution_receipt_chain_verified": False,
        "full_global_tail_single_receipt_implemented": False,
        "safe_to_run_bounded_insecure_test_only": True,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
        "production_rows_replayed": 0,
        "proofs_generated": 0,
        "formal_pi_issue_generated": False,
        "production_legacy18_provider_implemented": False,
        "Proof-closed": False,
        "Production-closed": False,
    }


def _fixture_candidate_insecure_test_only() -> tuple[
    spool_handoff.HandoffSessionInsecureTestOnly,
    TemporaryDirectory,
    candidateset.GlobalBCandidateSetInsecureTestOnly,
]:
    """Authoring-only fixture builder; never called by the consumer."""
    temporary = TemporaryDirectory(prefix="pq-rbbc-global-b-restart-fixture-")
    root = Path(temporary.name)
    session = spool_handoff.HandoffSessionInsecureTestOnly()
    session.run_to("tree-pre[1]")
    tree_pre = global_a.build_tree_pre_candidates_insecure_test_only(session)
    handoff_sha = tree_pre.handoff.identity["sha256"]
    global_a_computed = global_a.execute_global_a_insecure_test_only(
        tree_pre, expected_handoff_sha256=handoff_sha
    )
    session.run_to("global-a")
    spool_candidates = session.export_candidates()
    session.accept_handoff(
        spool_candidates, expected_handoff_sha256=spool_candidates.handoff.identity["sha256"]
    )
    suffix = continuation.build_verified_receipt_suffix_snapshots(session)
    continuations = continuation.build_continuation_snapshots(session)
    invocations = tuple(
        continuation.TreePostInvocationInsecureTestOnly(spool_candidates, item, suffix)
        for item in continuations
    )
    tree_post_computed = tuple(
        continuation.execute_tree_post_insecure_test_only(
            invocation,
            expected_handoff_sha256=scheduler.HANDOFF_IDENTITY["sha256"],
            expected_continuation_sha256=scheduler.CONTINUATION_IDENTITIES[index]["sha256"],
        )
        for index, invocation in enumerate(invocations)
    )
    global_a_output = root / "global-a"
    with patch.object(global_a, "execute_global_a_insecure_test_only", return_value=global_a_computed):
        completed_global_a = global_a.run_bounded_global_a(
            global_a_output,
            artifact_root=root,
            fresh_candidates=tree_pre,
            expected_handoff_sha256=handoff_sha,
            fresh_output=True,
        )
    published_global_a = global_a.capture_completed_result(
        global_a_output,
        artifact_root=root,
        expected_complete_sha256=completed_global_a.complete_checkpoint.identity["sha256"],
    )

    def cached_compute(_invocation, plan_document):
        return tree_post_computed[int(plan_document["tree_index"])]

    scheduler_output = root / "scheduler"
    with patch.object(tree_restart, "_compute_result", side_effect=cached_compute):
        completed_schedule = scheduler.run_bounded_scheduler(
            scheduler_output,
            artifact_root=root,
            fresh_invocations=invocations,
            fresh_output=True,
        )
    schedule = scheduler.capture_completed_schedule(
        scheduler_output,
        artifact_root=root,
        expected_complete_sha256=completed_schedule.complete_checkpoint.identity["sha256"],
    )
    candidate = candidateset.build_candidate_set_insecure_test_only(
        tree_pre=tree_pre,
        global_a_result=published_global_a,
        continuations=continuations,
        adapter_receipt_prefix=tree_pre.receipts,
        scheduler_receipt_suffix=suffix,
        schedule=schedule,
    )
    return session, temporary, candidate


@lru_cache(maxsize=1)
def bounded_self_check() -> dict[str, object]:
    session, temporary, candidate = _fixture_candidate_insecure_test_only()
    try:
        result = execute_global_b_insecure_test_only(
            candidate, expected_handoff_sha256=candidate.handoff.identity["sha256"]
        )
        reference = base.build_reference_insecure_test_only(0)
        if (
            result.commitment != reference.execution.commitment.encoded
            or result.request_hash != reference.tail_summary.request_hash_bytes
        ):
            raise GlobalBRestartError("independent Global-B outputs differ from frozen reference")
        for key in (
            "relocation_rowsets",
            "relocation_rows",
            "phase_b_rows",
            "total_rows_checked",
            "nonlinear_rows",
            "linear_rows",
            "allocated_wires",
            "referenced_import_wires",
            "fragment_stream_bytes",
            "fragment_stream_sha256",
            "row_semantics_sha256",
            "native_binding_rows_sha256",
            "private_owned_assignment_sha256",
            "commitment_sha256",
            "request_hash_sha256",
            "output_ports",
            "groups",
            "sponge_accounting",
        ):
            if result.summary[key] != FROZEN[key]:
                raise GlobalBRestartError("frozen bounded qualification drift: " + key)
        root = Path(temporary.name)
        output = root / "global-b"
        run_bounded_global_b(
            output,
            artifact_root=root,
            fresh_candidate=candidate,
            expected_handoff_sha256=candidate.handoff.identity["sha256"],
            fresh_output=True,
            stop_after="inputs",
        )
        checkpoint = latest_checkpoint(output, artifact_root=root)
        published = run_bounded_global_b(
            output,
            artifact_root=root,
            resume=True,
            expected_checkpoint_sha256=checkpoint.identity["sha256"],
        )
        captured = capture_completed_result(
            output,
            artifact_root=root,
            expected_complete_sha256=published.complete_checkpoint.identity["sha256"],
        )
        if captured.owned_values != result.owned_values:
            raise GlobalBRestartError("published Global-B assignment drift")
        evidence = {
            "candidate_handoff_identity": candidate.handoff.identity,
            "relocation_rowsets": result.summary["relocation_rowsets"],
            "relocation_rows": result.summary["relocation_rows"],
            "phase_b_rows": result.summary["phase_b_rows"],
            "total_rows_checked": result.summary["total_rows_checked"],
            "allocated_wires": result.summary["allocated_wires"],
            "fragment_stream_bytes": result.summary["fragment_stream_bytes"],
            "fragment_stream_sha256": result.summary["fragment_stream_sha256"],
            "row_semantics_sha256": result.summary["row_semantics_sha256"],
            "native_binding_rows_sha256": result.summary["native_binding_rows_sha256"],
            "private_owned_assignment_sha256": result.summary["private_owned_assignment_sha256"],
            "commitment_sha256": result.summary["commitment_sha256"],
            "request_hash_sha256": result.summary["request_hash_sha256"],
            "all_rows_satisfied": result.summary["all_rows_satisfied"],
            "private_result_identity": published.result.identity,
            "fragment_receipt_identity": published.receipt.identity,
            "complete_checkpoint_identity": published.complete_checkpoint.identity,
            "fresh_restart_and_completed_capture_checked": True,
            "candidate_pathname_reopened": False,
            "production": False,
        }
        for key, value in FROZEN.items():
            if key in evidence and evidence[key] != value:
                raise GlobalBRestartError("frozen bounded qualification drift: " + key)
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
                "src/pq_rbbc_issuance_global_b_restart_v1.py",
                "tests/test_pq_rbbc_issuance_global_b_restart_v1.py",
            )
        },
        "predecessor_identities": {
            path: {"bytes": size, "sha256": digest}
            for path, (size, digest) in PREDECESSOR_PINS.items()
        },
        "frozen_bounded_qualification": qualification,
        "contract": {
            "candidate_snapshot_roles": 32,
            "global_b_wire_interval": list(PHASE_B_INTERVAL),
            "native_relocation_rowsets": 8,
            "native_relocation_rows": RELOCATION_ROWS,
            "phase_b_rows": PHASE_B_ROWS,
            "total_rows_checked": RELOCATION_ROWS + PHASE_B_ROWS,
            "same_immutable_snapshot_raws_consumed": True,
            "candidate_pathname_reopen_permitted": False,
            "predecessor_stage_replay_permitted": False,
            "private_append_only_publication": True,
            "restartable_boundary": "inputs-committed",
            "externally_pinned_checkpoint_required": True,
            "full_execution_receipt_chain_verified": False,
        },
        "claim_status": {
            "Defined": True,
            "Instantiated": "two-tree-4plus4-insecure-test-only",
            "Implemented": "bounded-global-b-consumer-and-private-restart",
            "Tested": "positive-negative-mutation-orphan-restart-capture",
            "Evidence-sealed": "metadata-only",
            "Proof-closed": False,
            "Production-closed": False,
            "global_b_constraints_replayed": PHASE_B_ROWS,
            "global_b_production_constraints_replayed": 0,
            "full_global_tail_single_receipt_implemented": False,
            "production_legacy18_provider_implemented": False,
            "formal_pi_issue_generated": False,
            "qualified_pq_se_backend_integrated": False,
        },
        "artifact_policy": {
            "private_candidate_or_assignment_embedded": False,
            "assignment_br1cs_cache_checkpoint_resume_or_log_committed": False,
            "large_replay_or_proving_output_created": False,
            "other_tree_observed_stream_bytes_used": False,
            "historical_v238_v239_rewritten": False,
            "system_architecture_ticket_lifecycle_or_pq_sat_auth_changed": False,
        },
        "resource_budget": {
            "bounded_rows": RELOCATION_ROWS + PHASE_B_ROWS,
            "bounded_owned_wires": PHASE_B_INTERVAL[1] - PHASE_B_INTERVAL[0],
            "expected_wall_seconds_upper_bound": 120,
            "expected_peak_rss_mib_upper_bound": 1024,
            "production_estimate": None,
        },
        "exact_commands": {
            "bounded": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_global_b_restart_v1.py",
            "targeted": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_global_b_restart_v1 -v",
            "full": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v",
            "production": None,
            "large_replay": None,
            "large_proving": None,
        },
    }


def build_portable_evidence() -> dict[str, object]:
    manifest = build_manifest()
    return {
        "format": FORMAT + "-PORTABLE-EVIDENCE",
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "mode": MODE,
        "implementation_identities": manifest["implementation_identities"],
        "predecessor_identities": manifest["predecessor_identities"],
        "bounded_qualification": manifest["frozen_bounded_qualification"],
        "claim_status": manifest["claim_status"],
        "portable_metadata_only": True,
        "private_snapshot_raws_embedded": False,
        "private_assignment_embedded": False,
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
    import json

    print(json.dumps({"preflight": preflight(), "bounded": bounded_self_check()}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
