#!/usr/bin/env python3
"""Planned-offset execution gate for the PQ-RBBC tree-2 producer, v2.17.

Version 2.16 froze tree index 2 at local wire start 118,102,257.  This module
binds that plan to the sealed v2.14 standalone producer and exposes the exact
checkpoint/resume entry point for a production replay.  A reduced instance is
executed at two offsets to exercise the real producer generator and prove that
allocation-order values, row counts, accounting, labels, coefficients, and
imported point IDs are invariant under the permitted wire shift.

The reduced replay is engineering evidence only.  The production replay claims
remain false until the separately distributed v2.9 global-tail assignment and
tree-2 artifacts are restored (or regenerated) and all 25,666,386 rows are
replayed at the planned offset.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Mapping, Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_global_tail as tail
import pq_rbbc_cap_production_namespace as namespace
import pq_rbbc_cap_production_tree2_producer as standalone
import pq_rbbc_cap_shard_assignment as assignment
import pq_rbbc_cap_tree_producer as producer


IMPLEMENTATION_VERSION = "2.17"
RELATION_ID = "pq-rbbc/cap/production-tree2-planned-offset/v1"
MANIFEST_NAME = "pq_rbbc_cap_production_tree2_rebased_manifest_v2_17.json"
ARTIFACT_TAG = "v2_17_rebased"
ARCHIVE_NAME = f"pq_rbbc_production_tree_2_producer_{ARTIFACT_TAG}.f193assign"
CHECKPOINT_NAME = f"tree_2_execution_checkpoint_{ARTIFACT_TAG}.pkl"
STAGE_NAME = f"tree_2_resume_state_{ARTIFACT_TAG}.json"

PLANNED_TREE_INDEX = 2
PLANNED_LOCAL_WIRE_START = 118_102_257
PLANNED_MAX_WIRE_ID = 137_580_692
PLANNED_REBASE_DELTA = 77_907_660
PLANNED_OUTPUT_WIRE_STARTS = (
    136_713_057,
    137_503_585,
    137_505_633,
    137_576_061,
)

FROZEN_CONTRACT_SHA256 = (
    "4d89e4dafc771801cf53db398f63e125b509d243bafd911882279ac7a9a8a3ea"
)
FROZEN_REDUCED_FIXTURE_ASSIGNMENT_SHA256 = (
    "693f553098bbcef948ad384902a594fcf517d607e7354d140ea4307c1b85e017"
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_NAMESPACE_MANIFEST = (
    ROOT / "manifests" / namespace.MANIFEST_NAME
)
DEFAULT_STANDALONE_MANIFEST = (
    ROOT
    / "artifacts"
    / "metadata"
    / "production_tree2_v2_14"
    / "pq_rbbc_cap_production_tree2_manifest_v2_14.json"
)
DEFAULT_GLOBAL_MANIFEST = (
    ROOT / "manifests" / "pq_rbbc_cap_global_tail_manifest_v2_9.json"
)


@dataclass(frozen=True)
class PlannedReplayContract:
    relation_id: str
    namespace_relation_id: str
    namespace_plan_sha256: str
    tree_index: int
    leaves: int
    extension_degree: int
    standalone_relation_id: str
    standalone_local_wire_start: int
    standalone_max_wire_id: int
    standalone_output_wire_starts: tuple[int, ...]
    standalone_row_stream_sha256: str
    standalone_assignment_sha256: str
    standalone_assignment_body_sha256: str
    planned_local_wire_start: int
    planned_max_wire_id: int
    planned_rebase_delta: int
    planned_output_wire_starts: tuple[int, ...]
    global_point_wire_starts: tuple[int, ...]
    local_wires: int
    rows: int
    nonlinear_rows: int
    linear_rows: int
    assignment_bytes: int


@dataclass(frozen=True)
class ReducedOffsetFixtureEvidence:
    tree_index: int
    canonical_local_wire_start: int
    planned_local_wire_start: int
    rebase_delta: int
    rows: int
    wires: int
    nonlinear_rows: int
    linear_rows: int
    imported_point_wire_starts: tuple[int, ...]
    assignment_value_sha256: str
    assignment_values_identical: bool
    row_count_and_accounting_identical: bool
    port_values_identical: bool
    local_port_ids_shifted_exactly: bool
    point_wire_ids_preserved: bool
    captured_rows_rebase_exact: bool
    planned_replay_failures: int
    stale_witness_probes: int
    stale_witness_probes_rejected: bool
    fixture_is_not_production_replay_evidence: bool


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path} is not a JSON object")
    return document


def _is_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _tree_from_namespace(document: Mapping[str, object]) -> Mapping[str, object]:
    if document.get("plan_sha256") != namespace.FROZEN_PLAN_SHA256:
        raise ValueError("namespace plan digest is not frozen v2.16")
    boundary = document.get("claim_boundary")
    if not isinstance(boundary, dict) or not boundary.get(
        "production_18_tree_namespace_plan_closed"
    ):
        raise ValueError("namespace manifest does not close the planning gate")
    plan = document.get("plan")
    if not isinstance(plan, dict):
        raise ValueError("namespace manifest lacks plan")
    trees = plan.get("trees")
    if not isinstance(trees, list) or len(trees) != namespace.FROZEN_TREE_COUNT:
        raise ValueError("namespace manifest has wrong tree count")
    item = trees[PLANNED_TREE_INDEX]
    if not isinstance(item, dict) or item.get("tree_index") != PLANNED_TREE_INDEX:
        raise ValueError("namespace tree-2 position is malformed")
    return item


def load_contract(
    namespace_manifest_path: Path = DEFAULT_NAMESPACE_MANIFEST,
    standalone_manifest_path: Path = DEFAULT_STANDALONE_MANIFEST,
) -> PlannedReplayContract:
    namespace_document = _read_json(namespace_manifest_path)
    standalone_document = _read_json(standalone_manifest_path)
    tree = _tree_from_namespace(namespace_document)
    profile = standalone_document.get("profile")
    trace = standalone_document.get("trace")
    archive = standalone_document.get("assignment_archive")
    output_matches = standalone_document.get("output_matches")
    if not isinstance(profile, dict) or not isinstance(trace, dict):
        raise ValueError("standalone tree-2 manifest lacks profile or trace")
    if not isinstance(archive, dict) or not isinstance(output_matches, list):
        raise ValueError("standalone tree-2 manifest lacks archive or outputs")
    if profile.get("relation_id") != standalone.RELATION_ID:
        raise ValueError("standalone tree-2 relation identity mismatch")
    if archive.get("archive_sha256") != standalone.FROZEN_ASSIGNMENT_SHA256:
        raise ValueError("standalone tree-2 assignment identity mismatch")
    if trace.get("stream_sha256") != standalone.FROZEN_STREAM_SHA256:
        raise ValueError("standalone tree-2 row-stream identity mismatch")
    standalone_outputs = tuple(
        int(item["producer_wire_start"])
        for item in output_matches
        if isinstance(item, dict)
    )
    planned_outputs_raw = tree.get("outputs")
    if not isinstance(planned_outputs_raw, list):
        raise ValueError("namespace tree-2 outputs are malformed")
    planned_outputs = tuple(
        int(item["planned_wire_start"])
        for item in planned_outputs_raw
        if isinstance(item, dict)
    )
    return PlannedReplayContract(
        relation_id=RELATION_ID,
        namespace_relation_id=namespace.RELATION_ID,
        namespace_plan_sha256=str(namespace_document["plan_sha256"]),
        tree_index=int(tree["tree_index"]),
        leaves=int(tree["leaves"]),
        extension_degree=int(tree["extension_degree"]),
        standalone_relation_id=str(profile["relation_id"]),
        standalone_local_wire_start=int(trace["local_wire_start"]),
        standalone_max_wire_id=int(trace["max_wire_id"]),
        standalone_output_wire_starts=standalone_outputs,
        standalone_row_stream_sha256=str(trace["stream_sha256"]),
        standalone_assignment_sha256=str(archive["archive_sha256"]),
        standalone_assignment_body_sha256=str(archive["body_sha256"]),
        planned_local_wire_start=int(tree["planned_wire_start"]),
        planned_max_wire_id=int(tree["planned_wire_end"]),
        planned_rebase_delta=int(tree["rebase_delta"]),
        planned_output_wire_starts=planned_outputs,
        global_point_wire_starts=namespace.POINT_WIRE_STARTS,
        local_wires=int(tree["local_wires"]),
        rows=int(tree["producer_rows"]),
        nonlinear_rows=int(trace["nonlinear_rows"]),
        linear_rows=int(trace["linear_rows"]),
        assignment_bytes=int(archive["archive_bytes"]),
    )


def contract_sha256(contract: PlannedReplayContract) -> str:
    encoded = json.dumps(
        asdict(contract), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def contract_failures(
    contract: PlannedReplayContract,
    canonical: PlannedReplayContract,
) -> tuple[str, ...]:
    failures: list[str] = []
    for name in contract.__dataclass_fields__:
        if getattr(contract, name) != getattr(canonical, name):
            failures.append(f"wrong_{name}")
    if contract.planned_local_wire_start != (
        contract.standalone_local_wire_start + contract.planned_rebase_delta
    ):
        failures.append("inconsistent_rebase_delta")
    if contract.planned_max_wire_id != (
        contract.planned_local_wire_start + contract.local_wires - 1
    ):
        failures.append("inconsistent_planned_interval")
    if contract.standalone_max_wire_id != (
        contract.standalone_local_wire_start + contract.local_wires - 1
    ):
        failures.append("inconsistent_standalone_interval")
    if tuple(
        start + contract.planned_rebase_delta
        for start in contract.standalone_output_wire_starts
    ) != contract.planned_output_wire_starts:
        failures.append("inconsistent_output_rebase")
    if contract.rows != contract.nonlinear_rows + contract.linear_rows:
        failures.append("inconsistent_row_accounting")
    for label, digest in (
        ("namespace_plan", contract.namespace_plan_sha256),
        ("standalone_stream", contract.standalone_row_stream_sha256),
        ("standalone_assignment", contract.standalone_assignment_sha256),
        ("standalone_body", contract.standalone_assignment_body_sha256),
    ):
        if not _is_sha256(digest):
            failures.append(f"invalid_{label}_digest")
    if standalone.validate_point_imports(
        contract.global_point_wire_starts, contract.planned_local_wire_start
    ):
        failures.append("invalid_point_imports")
    if contract.planned_max_wire_id > namespace.MAX_WIRE_ID:
        failures.append("wire_integer_overflow")
    return tuple(dict.fromkeys(failures))


def _configuration_probes(
    canonical: PlannedReplayContract,
) -> tuple[dict[str, object], ...]:
    mutations = (
        ("wrong-namespace-digest", replace(canonical, namespace_plan_sha256="00" * 32)),
        ("wrong-local-start", replace(canonical, planned_local_wire_start=PLANNED_LOCAL_WIRE_START + 1)),
        ("wrong-max-wire", replace(canonical, planned_max_wire_id=PLANNED_MAX_WIRE_ID + 1)),
        ("wrong-output-start", replace(canonical, planned_output_wire_starts=(PLANNED_OUTPUT_WIRE_STARTS[0] + 1, *PLANNED_OUTPUT_WIRE_STARTS[1:]))),
        ("wrong-point-range", replace(canonical, global_point_wire_starts=(namespace.POINT_WIRE_STARTS[0] + 1, namespace.POINT_WIRE_STARTS[1]))),
        ("wrong-row-count", replace(canonical, rows=canonical.rows + 1)),
        ("wrong-wire-count", replace(canonical, local_wires=canonical.local_wires + 1)),
        ("wrong-standalone-assignment", replace(canonical, standalone_assignment_sha256="11" * 32)),
    )
    return tuple(
        {
            "mutation": label,
            "failures": list(contract_failures(candidate, canonical)),
            "rejected": bool(contract_failures(candidate, canonical)),
        }
        for label, candidate in mutations
    )


def _value_sequence_sha256(values: Sequence[int]) -> str:
    digest = hashlib.sha256()
    for value in values:
        digest.update(value.to_bytes(field.FIELD_ELEMENT_BYTES, "little"))
    return digest.hexdigest()


def _shift_form(
    form: field.LinearForm,
    canonical_start: int,
    planned_start: int,
    local_wires: int,
    point_starts: Sequence[int],
) -> field.LinearForm:
    canonical_end = canonical_start + local_wires

    def shift(wire: int) -> int:
        if canonical_start <= wire < canonical_end:
            return planned_start + wire - canonical_start
        if any(start <= wire < start + field.FIELD_DEGREE for start in point_starts):
            return wire
        raise ValueError(f"fixture row references unexpected wire {wire}")

    return field.LinearForm(
        tuple((shift(wire), coefficient) for wire, coefficient in form.terms),
        form.constant,
    )


def _shift_row(
    row: field.RankOneRow,
    canonical_start: int,
    planned_start: int,
    local_wires: int,
    point_starts: Sequence[int],
) -> field.RankOneRow:
    return field.RankOneRow(
        row.label,
        _shift_form(row.left, canonical_start, planned_start, local_wires, point_starts),
        _shift_form(row.right, canonical_start, planned_start, local_wires, point_starts),
        _shift_form(row.output, canonical_start, planned_start, local_wires, point_starts),
    )


def run_reduced_offset_fixture() -> ReducedOffsetFixtureEvidence:
    parameters = cap.REDUCED_TEST_PARAMETERS
    randomness = cap.deterministic_randomness(parameters)
    execution = cap.execute_cap_commit(parameters, randomness)
    tree_index = 1
    material = producer.material_from_execution(
        parameters, execution, tree_index
    )
    point_starts = (1,)
    canonical_start = 1_000
    planned_start = 100_000
    labels = producer.capture_material_labels(parameters, material)

    canonical_values = tail.MemoryAssignment()
    canonical_rows: dict[str, field.RankOneRow] = {}
    canonical = producer.build_tree_producer(
        parameters,
        randomness,
        execution,
        tree_index,
        producer_material=material,
        external_point_starts=point_starts,
        local_wire_start=canonical_start,
        assignment_writer=canonical_values,
        capture_rows=labels,
        captured_rows_output=canonical_rows,
    )
    planned_values = tail.MemoryAssignment()
    planned_rows: dict[str, field.RankOneRow] = {}
    planned = producer.build_tree_producer(
        parameters,
        randomness,
        execution,
        tree_index,
        producer_material=material,
        external_point_starts=point_starts,
        local_wire_start=planned_start,
        assignment_writer=planned_values,
        capture_rows=labels,
        captured_rows_output=planned_rows,
    )

    point_value = material.point_values[0]
    global_values = {
        point_starts[0] + bit: (point_value >> bit) & 1
        for bit in range(field.FIELD_DEGREE)
    }
    local_values = standalone.OffsetAssignment(
        planned_values, planned_start, planned.wires
    )
    composed = standalone.CompositeAssignment(global_values, local_values)
    verified_rows: dict[str, field.RankOneRow] = {}
    verified = producer.build_tree_producer(
        parameters,
        randomness,
        execution,
        tree_index,
        producer_material=material,
        external_point_starts=point_starts,
        local_wire_start=planned_start,
        verification_assignment=composed,
        capture_rows=labels,
        captured_rows_output=verified_rows,
    )
    probes = assignment.run_tamper_probes(composed, verified_rows, labels)

    canonical_ports = {item.port_id: item for item in canonical.ports}
    planned_ports = {item.port_id: item for item in planned.ports}
    local_port_ids = tuple(
        port_id
        for port_id in canonical_ports
        if port_id != "global.consistency-points"
    )
    captured_exact = all(
        _shift_row(
            canonical_rows[label],
            canonical_start,
            planned_start,
            canonical.wires,
            point_starts,
        ) == planned_rows[label]
        for label in labels
    )
    value_sha = _value_sequence_sha256(canonical_values.values)
    return ReducedOffsetFixtureEvidence(
        tree_index=tree_index,
        canonical_local_wire_start=canonical_start,
        planned_local_wire_start=planned_start,
        rebase_delta=planned_start - canonical_start,
        rows=canonical.rows,
        wires=canonical.wires,
        nonlinear_rows=canonical.nonlinear_rows,
        linear_rows=canonical.linear_rows,
        imported_point_wire_starts=point_starts,
        assignment_value_sha256=value_sha,
        assignment_values_identical=(
            canonical_values.values == planned_values.values
            and value_sha == _value_sequence_sha256(planned_values.values)
        ),
        row_count_and_accounting_identical=(
            (canonical.rows, canonical.wires, canonical.nonlinear_rows, canonical.linear_rows)
            == (planned.rows, planned.wires, planned.nonlinear_rows, planned.linear_rows)
            and tuple((group.name, group.rows) for group in canonical.groups)
            == tuple((group.name, group.rows) for group in planned.groups)
            and canonical.sponge_accounting == planned.sponge_accounting
            and canonical.horner_accounting == planned.horner_accounting
        ),
        port_values_identical=all(
            canonical_ports[port_id].value_sha256 == planned_ports[port_id].value_sha256
            and canonical_ports[port_id].bit_length == planned_ports[port_id].bit_length
            for port_id in canonical_ports
        ),
        local_port_ids_shifted_exactly=all(
            planned_ports[port_id].wire_start
            == canonical_ports[port_id].wire_start + planned_start - canonical_start
            for port_id in local_port_ids
        ),
        point_wire_ids_preserved=(
            canonical_ports["global.consistency-points"].wire_start
            == planned_ports["global.consistency-points"].wire_start
            == point_starts[0]
        ),
        captured_rows_rebase_exact=captured_exact,
        planned_replay_failures=verified.verification_failures,
        stale_witness_probes=len(probes),
        stale_witness_probes_rejected=all(probe.rejected for probe in probes),
        fixture_is_not_production_replay_evidence=True,
    )


def build_preflight_manifest(
    namespace_manifest_path: Path = DEFAULT_NAMESPACE_MANIFEST,
    standalone_manifest_path: Path = DEFAULT_STANDALONE_MANIFEST,
) -> dict[str, object]:
    contract = load_contract(namespace_manifest_path, standalone_manifest_path)
    failures = contract_failures(contract, contract)
    probes = _configuration_probes(contract)
    fixture = run_reduced_offset_fixture()
    contract_digest = contract_sha256(contract)
    fixture_closed = all(
        (
            fixture.assignment_values_identical,
            fixture.row_count_and_accounting_identical,
            fixture.port_values_identical,
            fixture.local_port_ids_shifted_exactly,
            fixture.point_wire_ids_preserved,
            fixture.captured_rows_rebase_exact,
            fixture.planned_replay_failures == 0,
            fixture.stale_witness_probes == 6,
            fixture.stale_witness_probes_rejected,
            fixture.assignment_value_sha256
            == FROZEN_REDUCED_FIXTURE_ASSIGNMENT_SHA256,
        )
    )
    gate_closed = (
        not failures
        and contract_digest == FROZEN_CONTRACT_SHA256
        and all(item["rejected"] for item in probes)
        and fixture_closed
    )
    return {
        "implementation_version": IMPLEMENTATION_VERSION,
        "profile": {
            "relation_id": RELATION_ID,
            "tree_index": PLANNED_TREE_INDEX,
            "artifact_tag": ARTIFACT_TAG,
            "archive_name": ARCHIVE_NAME,
            "checkpoint_name": CHECKPOINT_NAME,
            "stage_name": STAGE_NAME,
        },
        "contract_sha256": contract_digest,
        "contract": asdict(contract),
        "contract_validation_failures": list(failures),
        "configuration_mutation_probes": list(probes),
        "reduced_offset_fixture": asdict(fixture),
        "production_replay": {
            "status": "not_materialized",
            "production_rows_replayed_at_planned_offset": 0,
            "required_global_tail_assignment_sha256": tail.FROZEN_PRODUCTION_ASSIGNMENT_SHA256,
            "required_standalone_tree2_assignment_sha256": standalone.FROZEN_ASSIGNMENT_SHA256,
            "required_standalone_tree2_row_stream_sha256": standalone.FROZEN_STREAM_SHA256,
            "planned_row_stream_sha256": None,
            "planned_assignment_sha256": None,
            "planned_assignment_body_sha256": None,
            "external_artifacts_tracked_in_git": False,
        },
        "claim_boundary": {
            "production_tree2_planned_offset_execution_gate_closed": gate_closed,
            "planned_offset_reduced_fixture_replayed": fixture_closed,
            "production_tree2_rebased_assignment_materialized": False,
            "production_tree2_rebased_full_replay_closed": False,
            "representative_producers_rebased_replayed": False,
            "tree_producer_segments_materialized": False,
            "all_72_output_relocations_closed": False,
            "complete_18_tree_assignment_replayed": False,
            "cross_segment_wire_identity_closed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }


def run_production_replay(
    output_directory: Path,
    global_archive_path: Path,
    global_manifest_path: Path = DEFAULT_GLOBAL_MANIFEST,
    *,
    execution_cache_path: Path | None = None,
    workers: int = 1,
    replace: bool = False,
    progress: object = None,
) -> standalone.ProductionTree2Result:
    contract = load_contract()
    failures = contract_failures(contract, contract)
    if failures or contract_sha256(contract) != FROZEN_CONTRACT_SHA256:
        raise ValueError("planned replay contract is not frozen")
    callback = progress if callable(progress) else None
    return standalone.build_production_tree2(
        output_directory,
        global_archive_path,
        global_manifest_path,
        local_wire_start=contract.planned_local_wire_start,
        artifact_tag=ARTIFACT_TAG,
        execution_cache_path=execution_cache_path,
        workers=workers,
        replace=replace,
        progress=callback,
    )


def build_replayed_manifest(
    result: standalone.ProductionTree2Result,
    global_manifest_path: Path = DEFAULT_GLOBAL_MANIFEST,
    standalone_manifest_path: Path = DEFAULT_STANDALONE_MANIFEST,
) -> dict[str, object]:
    preflight = build_preflight_manifest()
    contract = PlannedReplayContract(**preflight["contract"])
    global_document = _read_json(global_manifest_path)
    standalone_document = _read_json(standalone_manifest_path)
    consumers = {
        str(item["port_id"]): item
        for item in global_document.get("ports", [])
        if isinstance(item, dict)
    }
    source_trace = standalone_document["trace"]
    source_archive = standalone_document["assignment_archive"]
    output_ports = tuple(
        item for item in result.summary.ports if item.direction == "output"
    )
    output_matches = tuple(
        {
            "port_id": item.port_id,
            "planned_producer_wire_start": item.wire_start,
            "consumer_wire_start": int(consumers[item.port_id]["consumer_wire_start"]),
            "bit_length": item.bit_length,
            "value_sha256": item.value_sha256,
            "exact_value_match": (
                item.bit_length == int(consumers[item.port_id]["bit_length"])
                and item.value_sha256 == consumers[item.port_id]["value_sha256"]
            ),
        }
        for item in output_ports
    )
    replay_closed = all(
        (
            preflight["claim_boundary"]["production_tree2_planned_offset_execution_gate_closed"],
            result.summary.tree_index == contract.tree_index,
            result.summary.local_wire_start == contract.planned_local_wire_start,
            result.summary.max_wire_id == contract.planned_max_wire_id,
            result.summary.wires == contract.local_wires,
            result.summary.rows == contract.rows,
            result.summary.nonlinear_rows == contract.nonlinear_rows,
            result.summary.linear_rows == contract.linear_rows,
            result.summary.external_assertions == 0,
            result.summary.verification_failures == 0,
            tuple(item.wire_start for item in output_ports)
            == contract.planned_output_wire_starts,
            all(item["exact_value_match"] for item in output_matches),
            result.summary.imported_point_wires == contract.global_point_wire_starts,
            result.archive.wires == contract.local_wires,
            result.archive.archive_bytes == contract.assignment_bytes,
            result.archive.body_sha256 == contract.standalone_assignment_body_sha256,
            result.archive.archive_sha256 != contract.standalone_assignment_sha256,
            result.archive.row_stream_sha256 != contract.standalone_row_stream_sha256,
            result.tree_component_sha256 == standalone.FROZEN_TREE_COMPONENT_SHA256,
            producer._field_tuple_digest(result.global_point_values)
            == standalone.FROZEN_POINT_VALUE_SHA256,
            all(probe.rejected for probe in result.standard_probes),
            all(probe.rejected for probe in result.point_probes),
            tuple((item.name, item.rows) for item in result.summary.groups)
            == tuple((item["name"], item["rows"]) for item in source_trace["groups"]),
            asdict(result.summary.sponge_accounting) == source_trace["sponge_accounting"],
            asdict(result.summary.horner_accounting) == source_trace["horner_accounting"],
            source_archive["body_sha256"] == contract.standalone_assignment_body_sha256,
        )
    )
    preflight["production_replay"] = {
        "status": "complete" if replay_closed else "rejected",
        "production_rows_replayed_at_planned_offset": result.summary.rows,
        "planned_row_stream_bytes": result.summary.stream_bytes,
        "planned_row_stream_sha256": result.summary.stream_sha256,
        "planned_assignment_bytes": result.archive.archive_bytes,
        "planned_assignment_sha256": result.archive.archive_sha256,
        "planned_assignment_body_sha256": result.archive.body_sha256,
        "standalone_assignment_body_sha256": contract.standalone_assignment_body_sha256,
        "assignment_value_sequence_identical_to_v2_14": (
            result.archive.body_sha256 == contract.standalone_assignment_body_sha256
        ),
        "output_matches": list(output_matches),
        "verification_failures": result.summary.verification_failures,
        "external_assertions": result.summary.external_assertions,
        "stale_witness_probes": len(result.standard_probes),
        "point_mutation_probes": len(result.point_probes),
    }
    preflight["claim_boundary"].update(
        {
            "production_tree2_rebased_assignment_materialized": replay_closed,
            "production_tree2_rebased_full_replay_closed": replay_closed,
            "representative_producers_rebased_replayed": replay_closed,
        }
    )
    return preflight


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path)
    parser.add_argument("--global-archive", type=Path)
    parser.add_argument("--global-manifest", type=Path, default=DEFAULT_GLOBAL_MANIFEST)
    parser.add_argument("--execution-cache", type=Path)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    if (args.output_directory is None) != (args.global_archive is None):
        parser.error("--output-directory and --global-archive must be provided together")
    if args.output_directory is None:
        document = build_preflight_manifest()
    else:
        result = run_production_replay(
            args.output_directory,
            args.global_archive,
            args.global_manifest,
            execution_cache_path=args.execution_cache,
            workers=args.workers,
            replace=args.replace,
            progress=lambda message: print(message, flush=True),
        )
        document = build_replayed_manifest(result, args.global_manifest)
    args.manifest.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "manifest": str(args.manifest),
                "production_replay_status": document["production_replay"]["status"],
                "planned_offset_gate_closed": document["claim_boundary"][
                    "production_tree2_planned_offset_execution_gate_closed"
                ],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
