#!/usr/bin/env python3
"""Phase-A/Phase-B wire contract for the canonical PQ-RBBC global tail.

Version 2.10 produced tree-local values that matched the v2.9 tail consumer
ports, but the global consistency points were still merely copied into each
producer as equal values.  This v2.11 checkpoint exposes the actual H1 digest
and consistency-point wires at a logical Phase-A/Phase-B boundary inside the
unchanged canonical tail relation.

The split is deliberately non-invasive: the input prelude, Phase A, and Phase
B are half-open row/wire ranges of the same relation and the same assignment.
There is no serialization, reallocation, or hash-only link between phases.
The reduced checkpoint independently regenerates the canonical and observed
assignments, compares their exact row streams and assignment-body digests,
replays every row from disk, and mutates exact boundary wires.  Production
split materialization, producer-to-point relocation, and the complete 18-tree
composition remain fail-closed obligations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping, Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_global_tail as tail
import pq_rbbc_cap_shard_assignment as assignment
import pq_rbbc_cap_shard_stream as shard


IMPLEMENTATION_VERSION = "2.11"
CONTRACT_ID = "pq-rbbc/cap/global-tail-phase-contract/v1"
CANONICAL_RELATION_ID = tail.RELATION_ID
FROZEN_MESSAGE = bytes(32)

# Frozen after the reduced assignment has been generated and replayed.
FROZEN_REDUCED_ROWS = 36_801
FROZEN_REDUCED_WIRES = 24_992
FROZEN_REDUCED_STREAM_SHA256 = (
    "4d2f53ba3a039a9c88cd7dd0b7e0e19ad4f7e39d5db2bce67af19ee09302c6fa"
)
FROZEN_REDUCED_ASSIGNMENT_BODY_SHA256 = (
    "ea4165dd32323a0ecf34cd21d7515571fdd6682f857266c0f3608aa1a4fd703c"
)
FROZEN_REDUCED_ASSIGNMENT_ARCHIVE_SHA256 = (
    "0915410fac94d6ab8ae9dcab487af7d8aca98aa187c6960e3472e77db990edc0"
)
FROZEN_REDUCED_ASSIGNMENT_ARCHIVE_BYTES = 624_928


@dataclass(frozen=True)
class BoundaryWireProbe:
    label: str
    port_id: str
    wire: int
    honest_row_satisfied: bool
    stale_row_satisfied: bool
    rejected: bool


@dataclass(frozen=True)
class SplitEquivalence:
    rows_equal: bool
    wires_equal: bool
    stream_sha256_equal: bool
    input_ports_equal: bool
    commitment_equal: bool
    request_hash_equal: bool
    assignment_body_sha256_equal: bool

    @property
    def exact(self) -> bool:
        return all(asdict(self).values())


@dataclass(frozen=True)
class SplitTailAssignmentResult:
    canonical: tail.GlobalTailSummary
    generated: tail.GlobalTailSummary
    verified: tail.GlobalTailSummary
    contract: tail.TailSplitContract
    verified_contract: tail.TailSplitContract
    archive: assignment.AssignmentArchiveMetadata
    canonical_assignment_body_sha256: str
    equivalence: SplitEquivalence
    boundary_probes: tuple[BoundaryWireProbe, ...]
    canonical_generation_seconds: float
    split_generation_seconds: float
    verification_seconds: float


def _assignment_body_sha256(values: Sequence[int]) -> str:
    digest = hashlib.sha256()
    for value in values:
        if not 0 <= value <= field.FIELD_MASK:
            raise ValueError("non-canonical assignment value")
        digest.update(value.to_bytes(field.FIELD_ELEMENT_BYTES, "little"))
    return digest.hexdigest()


def _h2_h1_source_label(execution: cap.CAPExecution) -> str:
    _, _, h2 = tail._global_calls(execution)
    h2_lengths = tuple(len(value) for value in h2.fields)
    payload_bit = tail._field_data_bit_offset(h2_lengths, 0, 0)
    return f"xof[2].h2.payload[{payload_bit}].source"


def capture_labels(execution: cap.CAPExecution) -> tuple[str, ...]:
    return (
        "consistency.validate.point[0].nonzero",
        _h2_h1_source_label(execution),
        "output.commitment[0].link",
        "xof[3].request-binding.digest.lane[0].pack",
    )


def _port_map(contract: tail.TailSplitContract) -> dict[str, tail.TailPort]:
    mapped = {port.port_id: port for port in contract.boundary_ports}
    if len(mapped) != len(contract.boundary_ports):
        raise ValueError("duplicate split-tail boundary port")
    return mapped


def _validate_contract(
    summary: tail.GlobalTailSummary,
    contract: tail.TailSplitContract,
) -> None:
    if contract.canonical_relation_id != tail.RELATION_ID:
        raise ValueError("split contract targets the wrong canonical relation")
    if len(contract.phases) != 2:
        raise ValueError("split contract must contain exactly two phases")
    phase_a, phase_b = contract.phases
    if (
        phase_a.phase_id != "global-tail-phase-a"
        or phase_b.phase_id != "global-tail-phase-b"
    ):
        raise ValueError("split phase order mismatch")
    if not (
        contract.input_prelude_row_start == 0
        and contract.input_prelude_row_end == phase_a.row_start
        and phase_a.row_end == phase_b.row_start
        and phase_b.row_end == summary.rows
    ):
        raise ValueError("split row ranges do not partition the canonical tail")
    if not (
        contract.input_prelude_wire_start == 1
        and contract.input_prelude_wire_end == phase_a.wire_start
        and phase_a.wire_end == phase_b.wire_start
        and phase_b.wire_end == summary.wires + 1
    ):
        raise ValueError("split wire ranges do not partition the canonical tail")
    ports = _port_map(contract)
    expected_ids = {
        "global.phase-a.h1",
        "global.phase-a.consistency-points",
        "global.phase-b.commitment",
        "global.phase-b.derived-mask",
        "global.phase-b.append-base",
        "global.phase-b.request-hash",
    }
    if set(ports) != expected_ids:
        raise ValueError("split boundary port set mismatch")
    for port_id in phase_a.output_port_ids:
        port = ports[port_id]
        if not phase_a.wire_start <= port.consumer_wire_start:
            raise ValueError("Phase-A port starts before Phase A")
        if port.consumer_wire_start + port.bit_length > phase_a.wire_end:
            raise ValueError("Phase-A port escapes its wire range")
    for port_id in phase_b.output_port_ids:
        port = ports[port_id]
        if not phase_b.wire_start <= port.consumer_wire_start:
            raise ValueError("Phase-B port starts before Phase B")
        if port.consumer_wire_start + port.bit_length > phase_b.wire_end:
            raise ValueError("Phase-B port escapes its wire range")
    if not contract.phase_a_to_phase_b_wire_identity:
        raise ValueError("split contract does not retain boundary wire identity")
    if "global.phase-a.h1" not in phase_b.input_port_ids:
        raise ValueError("Phase B does not consume the Phase-A H1 port")
    if "global.phase-a.consistency-points" not in phase_b.input_port_ids:
        raise ValueError("Phase B does not consume the Phase-A point port")


def _wire_occurs(row: field.RankOneRow, wire: int) -> bool:
    return any(
        term_wire == wire
        for form in (row.left, row.right, row.output)
        for term_wire, _ in form.terms
    )


def _probe_boundary_wire(
    values: Mapping[int, int],
    row: field.RankOneRow,
    port_id: str,
    wire: int,
) -> BoundaryWireProbe:
    if not _wire_occurs(row, wire):
        raise AssertionError(f"boundary wire {wire} is absent from {row.label}")
    honest = shard._row_satisfied_fast(row, values)
    stale_values = assignment.StaleAssignment(values, wire, values[wire] ^ 1)
    stale = shard._row_satisfied_fast(row, stale_values)
    return BoundaryWireProbe(row.label, port_id, wire, honest, stale, honest and not stale)


def _run_boundary_probes(
    values: Mapping[int, int],
    rows: Mapping[str, field.RankOneRow],
    labels: Sequence[str],
    contract: tail.TailSplitContract,
) -> tuple[BoundaryWireProbe, ...]:
    ports = _port_map(contract)
    port_ids = (
        "global.phase-a.consistency-points",
        "global.phase-a.h1",
        "global.phase-b.commitment",
        "global.phase-b.request-hash",
    )
    probes: list[BoundaryWireProbe] = []
    for label, port_id in zip(labels, port_ids):
        if label not in rows:
            raise AssertionError(f"boundary capture label was not emitted: {label}")
        port = ports[port_id]
        probes.append(
            _probe_boundary_wire(
                values,
                rows[label],
                port_id,
                port.consumer_wire_start,
            )
        )
    return tuple(probes)


def build_assignment_backed_split_tail(
    archive_path: Path,
    parameters: cap.CAPParameters,
    randomness: cap.CAPRandomness,
    execution: cap.CAPExecution,
    message: bytes = FROZEN_MESSAGE,
    *,
    workers: int = 1,
    replace: bool = False,
) -> SplitTailAssignmentResult:
    """Materialize, replay, and compare the split view to canonical bytes."""

    labels = capture_labels(execution)

    canonical_started = time.perf_counter()
    canonical_values = tail.MemoryAssignment()
    canonical = tail.build_global_tail(
        parameters,
        randomness,
        execution,
        message,
        workers=workers,
        assignment_writer=canonical_values,
    )
    canonical_assignment_body_sha256 = _assignment_body_sha256(
        canonical_values.values
    )
    del canonical_values
    canonical_generation_seconds = time.perf_counter() - canonical_started

    contracts: list[tail.TailSplitContract] = []
    captured: dict[str, field.RankOneRow] = {}
    writer = assignment.AssignmentArchiveWriter(archive_path, replace=replace)
    split_started = time.perf_counter()
    try:
        generated = tail.build_global_tail(
            parameters,
            randomness,
            execution,
            message,
            workers=workers,
            assignment_writer=writer,
            capture_rows=labels,
            captured_rows_output=captured,
            split_contract_output=contracts,
        )
        archive = writer.finish(generated.wires, generated.stream_sha256)
    except BaseException:
        writer.abort()
        raise
    split_generation_seconds = time.perf_counter() - split_started
    if len(contracts) != 1:
        raise AssertionError("split generation did not emit one contract")
    contract = contracts[0]
    _validate_contract(generated, contract)

    verified_contracts: list[tail.TailSplitContract] = []
    verification_started = time.perf_counter()
    with assignment.AssignmentArchiveReader(
        archive_path, expected=archive, verify_body=True
    ) as values:
        verified = tail.build_global_tail(
            parameters,
            randomness,
            execution,
            message,
            verification_assignment=values,
            split_contract_output=verified_contracts,
        )
        if len(verified_contracts) != 1:
            raise AssertionError("split replay did not emit one contract")
        verified_contract = verified_contracts[0]
        _validate_contract(verified, verified_contract)
        if verified.verification_failures:
            raise AssertionError(
                "split-tail replay failed first at "
                f"{verified.first_verification_failure}"
            )
        probes = _run_boundary_probes(values, captured, labels, contract)
    verification_seconds = time.perf_counter() - verification_started

    equivalence = SplitEquivalence(
        canonical.rows == generated.rows == verified.rows,
        canonical.wires == generated.wires == verified.wires,
        canonical.stream_sha256
        == generated.stream_sha256
        == verified.stream_sha256,
        canonical.ports == generated.ports == verified.ports,
        canonical.commitment_bytes
        == generated.commitment_bytes
        == verified.commitment_bytes,
        canonical.request_hash_bytes
        == generated.request_hash_bytes
        == verified.request_hash_bytes,
        canonical_assignment_body_sha256 == archive.body_sha256,
    )
    if not equivalence.exact:
        raise AssertionError("split-tail differs from the canonical relation")
    if contract != verified_contract:
        raise AssertionError("split-tail contract changed during replay")
    if not all(probe.rejected for probe in probes):
        raise AssertionError("a split-tail boundary mutation was accepted")
    return SplitTailAssignmentResult(
        canonical,
        generated,
        verified,
        contract,
        verified_contract,
        archive,
        canonical_assignment_body_sha256,
        equivalence,
        probes,
        canonical_generation_seconds,
        split_generation_seconds,
        verification_seconds,
    )


def build_manifest(result: SplitTailAssignmentResult) -> dict[str, object]:
    summary = result.generated
    reduced = summary.parameters == cap.REDUCED_TEST_PARAMETERS
    frozen_reduced_matches = (
        reduced
        and bool(FROZEN_REDUCED_STREAM_SHA256)
        and bool(FROZEN_REDUCED_ASSIGNMENT_BODY_SHA256)
        and bool(FROZEN_REDUCED_ASSIGNMENT_ARCHIVE_SHA256)
        and summary.rows == FROZEN_REDUCED_ROWS
        and summary.wires == FROZEN_REDUCED_WIRES
        and summary.stream_sha256 == FROZEN_REDUCED_STREAM_SHA256
        and result.archive.body_sha256
        == FROZEN_REDUCED_ASSIGNMENT_BODY_SHA256
        and result.archive.archive_sha256
        == FROZEN_REDUCED_ASSIGNMENT_ARCHIVE_SHA256
        and result.archive.archive_bytes
        == FROZEN_REDUCED_ASSIGNMENT_ARCHIVE_BYTES
    )
    replay_clean = result.verified.verification_failures == 0
    probes_rejected = bool(result.boundary_probes) and all(
        probe.rejected for probe in result.boundary_probes
    )
    contract_closed = (
        frozen_reduced_matches
        and replay_clean
        and result.equivalence.exact
        and result.contract == result.verified_contract
        and result.contract.phase_a_to_phase_b_wire_identity
        and probes_rejected
    )
    return {
        "implementation_version": IMPLEMENTATION_VERSION,
        "profile": {
            "contract_id": CONTRACT_ID,
            "canonical_relation_id": CANONICAL_RELATION_ID,
            "stream_format": tail.STREAM_FORMAT,
            "assignment_format": assignment.ASSIGNMENT_FORMAT,
            "cap_profile_fingerprint": cap.profile_fingerprint(
                summary.parameters
            ),
            "tree_count": summary.parameters.tree_count,
            "reduced_test_profile": reduced,
        },
        "canonical_equivalence": {
            **asdict(result.equivalence),
            "exact": result.equivalence.exact,
            "canonical_stream_sha256": result.canonical.stream_sha256,
            "split_stream_sha256": result.generated.stream_sha256,
            "canonical_assignment_body_sha256": (
                result.canonical_assignment_body_sha256
            ),
            "split_assignment_body_sha256": result.archive.body_sha256,
        },
        "trace": {
            "rows": summary.rows,
            "wires": summary.wires,
            "nonlinear_rows": summary.nonlinear_rows,
            "linear_rows": summary.linear_rows,
            "stream_bytes": summary.stream_bytes,
            "stream_sha256": summary.stream_sha256,
            "groups": [asdict(group) for group in summary.groups],
            "external_assertions": summary.external_assertions,
            "verification_failures": result.verified.verification_failures,
            "canonical_generation_seconds": (
                result.canonical_generation_seconds
            ),
            "split_generation_seconds": result.split_generation_seconds,
            "verification_seconds": result.verification_seconds,
            "peak_rss_kib": resource.getrusage(
                resource.RUSAGE_SELF
            ).ru_maxrss,
        },
        "phase_contract": asdict(result.contract),
        "assignment_archive": asdict(result.archive),
        "boundary_wire_probes": [
            asdict(probe) for probe in result.boundary_probes
        ],
        "claim_boundary": {
            "reduced_split_tail_phase_contract_closed": contract_closed,
            "canonical_tail_stream_and_assignment_equivalent": (
                result.equivalence.exact
            ),
            "h1_and_consistency_point_ports_native_closed": contract_closed,
            "tail_phase_a_to_phase_b_wire_identity_closed": contract_closed,
            "production_split_tail_materialized": False,
            "producer_point_wire_identity_closed": False,
            "production_tree_producer_segments_materialized": False,
            "complete_18_tree_assignment_replayed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()

    parameters = cap.REDUCED_TEST_PARAMETERS
    randomness = cap.deterministic_randomness(parameters)
    execution = cap.execute_cap_commit(parameters, randomness)
    result = build_assignment_backed_split_tail(
        args.archive,
        parameters,
        randomness,
        execution,
        workers=max(1, args.workers),
        replace=args.replace,
    )
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(
        json.dumps(build_manifest(result), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "archive": str(args.archive),
                "manifest": str(args.manifest),
                "rows": result.generated.rows,
                "wires": result.generated.wires,
                "stream_sha256": result.generated.stream_sha256,
                "assignment_body_sha256": result.archive.body_sha256,
                "assignment_archive_sha256": result.archive.archive_sha256,
                "boundary_probes_rejected": sum(
                    probe.rejected for probe in result.boundary_probes
                ),
                "canonical_equivalence": result.equivalence.exact,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
