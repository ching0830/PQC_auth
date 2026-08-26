#!/usr/bin/env python3
"""Fail-closed 18-tree production wire namespace plan for PQ-RBBC v2.16.

The v2.13 and v2.14 producer relations deliberately used the same standalone
local interval after the frozen v2.9 global tail.  That is safe for separate
replays but cannot be used for a complete composition.  This module assigns a
deterministic, non-overlapping interval to every production tree position and
defines the only permitted remapping of producer rows:

* producer-local wires move by the tree's planned offset;
* the two frozen global consistency-point ranges keep their exact wire IDs;
* every other external wire is rejected.

This checkpoint freezes metadata and a remapping rule.  It does not claim that
the two representative multi-gigabyte producers have been replayed at their
planned offsets, that the other sixteen producers exist, or that the parent
relation is joined.
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
import pq_rbbc_cap_production_tree0_producer as tree0
import pq_rbbc_cap_production_tree2_producer as tree2


IMPLEMENTATION_VERSION = "2.16"
RELATION_ID = "pq-rbbc/cap/production-namespace-plan/v1"
MANIFEST_NAME = "pq_rbbc_cap_production_namespace_manifest_v2_16.json"
TREE_ORDER = tuple(range(18))
REPRESENTATIVE_TREE_INDICES = (0, 2)
POINT_WIRE_STARTS = (39_945_673, 39_945_866)
PORT_SUFFIXES = ("leaf-commitments", "p-plain", "mhat-plain", "xi-masks")
MAX_WIRE_ID = (1 << 64) - 1

FROZEN_TREE_COUNT = 18
FROZEN_TOTAL_PRODUCER_WIRES = 389_562_636
FROZEN_TOTAL_PRODUCER_ROWS = 513_312_336
FROZEN_TOTAL_OUTPUT_RELOCATION_ROWS = 15_938_520
FROZEN_PLANNED_COMPOSITION_ROWS = 586_057_567
FROZEN_MAX_PLANNED_WIRE_ID = 429_757_232
# Set after canonical manifest generation; validation treats any drift as open.
FROZEN_PLAN_SHA256 = (
    "810f9feb69df61dd9672d90fe74fcec54c3b28bd126013981aeceb1e9e156c4f"
)

DEFAULT_TAIL_MANIFEST = (
    Path(__file__).resolve().parents[1]
    / "manifests"
    / "pq_rbbc_cap_global_tail_manifest_v2_9.json"
)


@dataclass(frozen=True)
class WireInterval:
    owner: str
    start: int
    wires: int

    @property
    def end(self) -> int:
        return self.start + self.wires - 1


@dataclass(frozen=True)
class PointImport:
    point_index: int
    wire_start: int
    bit_length: int

    @property
    def wire_end(self) -> int:
        return self.wire_start + self.bit_length - 1


@dataclass(frozen=True)
class OutputPortPlan:
    port_id: str
    phase: str
    standalone_wire_start: int
    planned_wire_start: int
    consumer_wire_start: int
    bit_length: int
    value_sha256: str
    producer_value_digest_verified: bool

    @property
    def planned_wire_end(self) -> int:
        return self.planned_wire_start + self.bit_length - 1

    @property
    def consumer_wire_end(self) -> int:
        return self.consumer_wire_start + self.bit_length - 1


@dataclass(frozen=True)
class TreeNamespace:
    tree_index: int
    leaves: int
    extension_degree: int
    producer_relation_id: str
    standalone_wire_start: int
    local_wires: int
    producer_rows: int
    planned_wire_start: int
    planned_wire_end: int
    rebase_delta: int
    standalone_replay_sealed: bool
    source_row_stream_sha256: str | None
    source_assignment_sha256: str | None
    outputs: tuple[OutputPortPlan, ...]


@dataclass(frozen=True)
class ProductionNamespacePlan:
    relation_id: str
    tree_order: tuple[int, ...]
    tail_interval: WireInterval
    point_imports: tuple[PointImport, ...]
    trees: tuple[TreeNamespace, ...]
    total_producer_wires: int
    total_producer_rows: int
    total_output_relocation_rows: int
    planned_composition_rows: int
    max_wire_id: int


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path} is not a JSON object")
    return document


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _tail_ports(document: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    ports = document.get("ports")
    if not isinstance(ports, list):
        raise ValueError("global-tail manifest lacks ports")
    result = {
        str(item["port_id"]): item
        for item in ports
        if isinstance(item, dict) and "port_id" in item
    }
    if len(result) != len(ports):
        raise ValueError("global-tail ports are malformed or duplicated")
    return result


def _validate_tail_manifest(document: Mapping[str, object]) -> None:
    profile = document.get("profile")
    trace = document.get("trace")
    archive = document.get("assignment_archive")
    if not isinstance(profile, dict) or not isinstance(trace, dict):
        raise ValueError("global-tail manifest lacks profile or trace")
    if not isinstance(archive, dict):
        raise ValueError("global-tail manifest lacks assignment archive")
    failures: list[str] = []
    if profile.get("relation_id") != tail.RELATION_ID:
        failures.append("wrong_tail_relation")
    if profile.get("tree_count") != FROZEN_TREE_COUNT:
        failures.append("wrong_tail_tree_count")
    if trace.get("wires") != tail.FROZEN_PRODUCTION_WIRES:
        failures.append("wrong_tail_wire_count")
    if trace.get("rows") != tail.FROZEN_PRODUCTION_ROWS:
        failures.append("wrong_tail_row_count")
    if trace.get("stream_sha256") != tail.FROZEN_PRODUCTION_STREAM_SHA256:
        failures.append("wrong_tail_row_stream")
    if archive.get("archive_sha256") != tail.FROZEN_PRODUCTION_ASSIGNMENT_SHA256:
        failures.append("wrong_tail_assignment")
    if failures:
        raise ValueError(";".join(failures))


def _shape(tree_index: int) -> tuple[int, int, int, int, tuple[int, ...]]:
    if tree_index < 2:
        return (
            tree0.LEAVES,
            tree0.EXTENSION_DEGREE,
            tree0.FROZEN_LOCAL_WIRES,
            tree0.FROZEN_ROWS,
            tree0.FROZEN_OUTPUT_WIRE_STARTS,
        )
    return (
        tree2.LEAVES,
        tree2.EXTENSION_DEGREE,
        tree2.FROZEN_LOCAL_WIRES,
        tree2.FROZEN_ROWS,
        tree2.FROZEN_OUTPUT_WIRE_STARTS,
    )


def _producer_relation_id(tree_index: int) -> str:
    return f"pq-rbbc/cap/production-tree-producer-index-{tree_index}/v1"


def _build_unchecked(document: Mapping[str, object]) -> ProductionNamespacePlan:
    _validate_tail_manifest(document)
    ports = _tail_ports(document)
    expected_leaves = cap.PRODUCTION_PARAMETERS.expanded_leaf_counts()
    expected_degrees = cap.PRODUCTION_PARAMETERS.expanded_extension_degrees()
    canonical_start = tail.FROZEN_PRODUCTION_WIRES + 1
    planned_start = canonical_start
    trees: list[TreeNamespace] = []
    relocation_rows = 0

    for tree_index in TREE_ORDER:
        leaves, degree, local_wires, producer_rows, standalone_outputs = _shape(
            tree_index
        )
        if (leaves, degree) != (
            expected_leaves[tree_index],
            expected_degrees[tree_index],
        ):
            raise AssertionError("frozen producer shape disagrees with CAP profile")
        planned_end = planned_start + local_wires - 1
        output_plans: list[OutputPortPlan] = []
        for ordinal, suffix in enumerate(PORT_SUFFIXES):
            port_id = f"tree[{tree_index}].{suffix}"
            consumer = ports.get(port_id)
            if consumer is None:
                raise ValueError(f"global-tail manifest lacks {port_id}")
            standalone_output = standalone_outputs[ordinal]
            bit_length = int(consumer["bit_length"])
            output_plans.append(
                OutputPortPlan(
                    port_id=port_id,
                    phase="tree-post" if suffix == "xi-masks" else "tree-pre",
                    standalone_wire_start=standalone_output,
                    planned_wire_start=(
                        planned_start + standalone_output - canonical_start
                    ),
                    consumer_wire_start=int(consumer["consumer_wire_start"]),
                    bit_length=bit_length,
                    value_sha256=str(consumer["value_sha256"]),
                    producer_value_digest_verified=(
                        tree_index in REPRESENTATIVE_TREE_INDICES
                    ),
                )
            )
            relocation_rows += bit_length

        representative = tree_index in REPRESENTATIVE_TREE_INDICES
        if tree_index == 0:
            stream_sha = tree0.FROZEN_STREAM_SHA256
            assignment_sha = tree0.FROZEN_ASSIGNMENT_SHA256
        elif tree_index == 2:
            stream_sha = tree2.FROZEN_STREAM_SHA256
            assignment_sha = tree2.FROZEN_ASSIGNMENT_SHA256
        else:
            stream_sha = None
            assignment_sha = None
        trees.append(
            TreeNamespace(
                tree_index=tree_index,
                leaves=leaves,
                extension_degree=degree,
                producer_relation_id=_producer_relation_id(tree_index),
                standalone_wire_start=canonical_start,
                local_wires=local_wires,
                producer_rows=producer_rows,
                planned_wire_start=planned_start,
                planned_wire_end=planned_end,
                rebase_delta=planned_start - canonical_start,
                standalone_replay_sealed=representative,
                source_row_stream_sha256=stream_sha,
                source_assignment_sha256=assignment_sha,
                outputs=tuple(output_plans),
            )
        )
        planned_start = planned_end + 1

    producer_wires = sum(item.local_wires for item in trees)
    producer_rows = sum(item.producer_rows for item in trees)
    return ProductionNamespacePlan(
        relation_id=RELATION_ID,
        tree_order=TREE_ORDER,
        tail_interval=WireInterval(
            "production-global-tail", 1, tail.FROZEN_PRODUCTION_WIRES
        ),
        point_imports=tuple(
            PointImport(index, start, field.FIELD_DEGREE)
            for index, start in enumerate(POINT_WIRE_STARTS)
        ),
        trees=tuple(trees),
        total_producer_wires=producer_wires,
        total_producer_rows=producer_rows,
        total_output_relocation_rows=relocation_rows,
        planned_composition_rows=(
            tail.FROZEN_PRODUCTION_ROWS + producer_rows + relocation_rows
        ),
        max_wire_id=planned_start - 1,
    )


def _overlaps(left_start: int, left_end: int, right_start: int, right_end: int) -> bool:
    return left_start <= right_end and right_start <= left_end


def validate_plan(
    plan: ProductionNamespacePlan,
    tail_document: Mapping[str, object],
) -> tuple[str, ...]:
    """Return every detected deviation from the canonical frozen plan."""

    failures: list[str] = []
    try:
        expected = _build_unchecked(tail_document)
    except (KeyError, TypeError, ValueError) as error:
        return (f"invalid_tail_manifest:{error}",)

    if plan.relation_id != RELATION_ID:
        failures.append("wrong_relation_id")
    if plan.tree_order != TREE_ORDER:
        failures.append("wrong_tree_order")
    if len(plan.trees) != FROZEN_TREE_COUNT:
        failures.append("wrong_tree_count")
    if plan.point_imports != expected.point_imports:
        failures.append("wrong_point_ranges")
    if plan.tail_interval != expected.tail_interval:
        failures.append("wrong_tail_interval")
    for item in plan.point_imports:
        if not (
            plan.tail_interval.start <= item.wire_start
            and item.wire_end <= plan.tail_interval.end
        ):
            failures.append(f"point_outside_tail:{item.point_index}")

    intervals: list[WireInterval] = [plan.tail_interval]
    for ordinal, tree in enumerate(plan.trees):
        if ordinal >= len(expected.trees):
            break
        canonical = expected.trees[ordinal]
        prefix = f"tree[{ordinal}]"
        if tree.tree_index != ordinal:
            failures.append(f"wrong_tree_position:{ordinal}")
        if (tree.leaves, tree.extension_degree) != (
            canonical.leaves,
            canonical.extension_degree,
        ):
            failures.append(f"wrong_shape:{prefix}")
        for attribute in (
            "producer_relation_id",
            "standalone_wire_start",
            "local_wires",
            "producer_rows",
            "planned_wire_start",
            "planned_wire_end",
            "rebase_delta",
            "standalone_replay_sealed",
            "source_row_stream_sha256",
            "source_assignment_sha256",
        ):
            if getattr(tree, attribute) != getattr(canonical, attribute):
                failures.append(f"wrong_{attribute}:{prefix}")
        if tree.planned_wire_end != tree.planned_wire_start + tree.local_wires - 1:
            failures.append(f"inconsistent_interval:{prefix}")
        if tree.rebase_delta != tree.planned_wire_start - tree.standalone_wire_start:
            failures.append(f"inconsistent_rebase_delta:{prefix}")
        if tree.outputs != canonical.outputs:
            failures.append(f"wrong_output_ports:{prefix}")
        if tuple(port.port_id for port in tree.outputs) != tuple(
            f"tree[{ordinal}].{suffix}" for suffix in PORT_SUFFIXES
        ):
            failures.append(f"wrong_output_order:{prefix}")
        for port in tree.outputs:
            if not (
                tree.planned_wire_start
                <= port.planned_wire_start
                <= port.planned_wire_end
                <= tree.planned_wire_end
            ):
                failures.append(f"output_outside_tree:{port.port_id}")
            if not _is_sha256(port.value_sha256):
                failures.append(f"invalid_output_digest:{port.port_id}")
        intervals.append(
            WireInterval(prefix, tree.planned_wire_start, tree.local_wires)
        )

    for left_index, left in enumerate(intervals):
        if left.start <= 0 or left.wires <= 0 or left.end > MAX_WIRE_ID:
            failures.append(f"wire_integer_overflow:{left.owner}")
        for right in intervals[left_index + 1 :]:
            if _overlaps(left.start, left.end, right.start, right.end):
                failures.append(f"overlapping_intervals:{left.owner}:{right.owner}")

    planned_outputs = [port for tree in plan.trees for port in tree.outputs]
    consumer_outputs = [port for tree in plan.trees for port in tree.outputs]
    for index, left in enumerate(planned_outputs):
        for right in planned_outputs[index + 1 :]:
            if _overlaps(
                left.planned_wire_start,
                left.planned_wire_end,
                right.planned_wire_start,
                right.planned_wire_end,
            ):
                failures.append(
                    f"overlapping_producer_outputs:{left.port_id}:{right.port_id}"
                )
    for index, left in enumerate(consumer_outputs):
        for right in consumer_outputs[index + 1 :]:
            if _overlaps(
                left.consumer_wire_start,
                left.consumer_wire_end,
                right.consumer_wire_start,
                right.consumer_wire_end,
            ):
                failures.append(
                    f"overlapping_tail_outputs:{left.port_id}:{right.port_id}"
                )

    for attribute, frozen in (
        ("total_producer_wires", FROZEN_TOTAL_PRODUCER_WIRES),
        ("total_producer_rows", FROZEN_TOTAL_PRODUCER_ROWS),
        ("total_output_relocation_rows", FROZEN_TOTAL_OUTPUT_RELOCATION_ROWS),
        ("planned_composition_rows", FROZEN_PLANNED_COMPOSITION_ROWS),
        ("max_wire_id", FROZEN_MAX_PLANNED_WIRE_ID),
    ):
        if getattr(plan, attribute) != frozen:
            failures.append(f"wrong_{attribute}")
    return tuple(dict.fromkeys(failures))


def build_plan(tail_manifest_path: Path = DEFAULT_TAIL_MANIFEST) -> ProductionNamespacePlan:
    document = _read_json(tail_manifest_path)
    plan = _build_unchecked(document)
    failures = validate_plan(plan, document)
    if failures:
        raise ValueError("invalid production namespace plan: " + ";".join(failures))
    return plan


def plan_sha256(plan: ProductionNamespacePlan) -> str:
    encoded = json.dumps(
        asdict(plan), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def rebase_wire(tree: TreeNamespace, wire_id: int) -> int:
    """Map one standalone producer wire, preserving only frozen point imports."""

    local_end = tree.standalone_wire_start + tree.local_wires - 1
    if tree.standalone_wire_start <= wire_id <= local_end:
        rebased = tree.planned_wire_start + wire_id - tree.standalone_wire_start
        if rebased > MAX_WIRE_ID:
            raise OverflowError("rebased wire exceeds unsigned 64-bit range")
        return rebased
    for start in POINT_WIRE_STARTS:
        if start <= wire_id < start + field.FIELD_DEGREE:
            return wire_id
    raise ValueError(
        f"wire {wire_id} is neither tree-local nor a frozen point import"
    )


def rebase_form(tree: TreeNamespace, form: field.LinearForm) -> field.LinearForm:
    return field.LinearForm(
        tuple(
            (rebase_wire(tree, wire_id), coefficient)
            for wire_id, coefficient in form.terms
        ),
        form.constant,
    )


def rebase_row(tree: TreeNamespace, row: field.RankOneRow) -> field.RankOneRow:
    return field.RankOneRow(
        row.label,
        rebase_form(tree, row.left),
        rebase_form(tree, row.right),
        rebase_form(tree, row.output),
    )


def _row_shape(row: field.RankOneRow) -> tuple[object, ...]:
    return (
        row.label,
        row.left.constant,
        tuple(coefficient for _, coefficient in row.left.terms),
        row.right.constant,
        tuple(coefficient for _, coefficient in row.right.terms),
        row.output.constant,
        tuple(coefficient for _, coefficient in row.output.terms),
    )


def _fixture_evidence(tree: TreeNamespace) -> dict[str, object]:
    local = tree.standalone_wire_start
    point = POINT_WIRE_STARTS[0]
    values = {local: 5, local + 1: 7, local + 2: 2, point: 3}
    product = field.fmul(values[local] ^ values[point], values[local + 1])
    values[local + 3] = product
    rows = (
        field.RankOneRow(
            "namespace-fixture.linear",
            field.LinearForm(((local, 1), (local + 1, 1))),
            field.LinearForm.const(1),
            field.LinearForm.wire(local + 2),
        ),
        field.RankOneRow(
            "namespace-fixture.nonlinear",
            field.LinearForm(((point, 1), (local, 1))),
            field.LinearForm.wire(local + 1),
            field.LinearForm.wire(local + 3),
        ),
    )
    rebased_rows = tuple(rebase_row(tree, row) for row in rows)
    rebased_values = {rebase_wire(tree, wire): value for wire, value in values.items()}
    return {
        "tree_index": tree.tree_index,
        "fixture_rows": len(rows),
        "production_rows_replayed_at_planned_offset": 0,
        "row_count_preserved": len(rows) == len(rebased_rows),
        "labels_constants_and_coefficients_preserved": all(
            _row_shape(left) == _row_shape(right)
            for left, right in zip(rows, rebased_rows, strict=True)
        ),
        "honest_relation_values_preserved": all(
            row.satisfied(values) and rebased.satisfied(rebased_values)
            for row, rebased in zip(rows, rebased_rows, strict=True)
        ),
        "point_wire_ids_preserved": all(
            rebase_wire(tree, start) == start for start in POINT_WIRE_STARTS
        ),
        "local_wire_ids_changed": tree.rebase_delta != 0,
        "fixture_is_not_production_replay_evidence": True,
    }


def _configuration_probes(
    plan: ProductionNamespacePlan,
    document: Mapping[str, object],
) -> list[dict[str, object]]:
    mutations: list[tuple[str, ProductionNamespacePlan]] = []
    swapped = list(plan.trees)
    swapped[0], swapped[1] = swapped[1], swapped[0]
    mutations.append(("wrong-tree-order", replace(plan, trees=tuple(swapped))))
    trees = list(plan.trees)
    trees[2] = replace(trees[2], leaves=trees[2].leaves + 1)
    mutations.append(("wrong-shape", replace(plan, trees=tuple(trees))))
    points = list(plan.point_imports)
    points[0] = replace(points[0], wire_start=points[0].wire_start + 1)
    mutations.append(("wrong-point-range", replace(plan, point_imports=tuple(points))))
    trees = list(plan.trees)
    trees[1] = replace(
        trees[1],
        planned_wire_start=trees[0].planned_wire_start,
        planned_wire_end=trees[0].planned_wire_start + trees[1].local_wires - 1,
        rebase_delta=trees[0].planned_wire_start - trees[1].standalone_wire_start,
    )
    mutations.append(("overlapping-tree-interval", replace(plan, trees=tuple(trees))))
    trees = list(plan.trees)
    outputs = list(trees[0].outputs)
    outputs[1] = replace(
        outputs[1], planned_wire_start=outputs[0].planned_wire_start
    )
    trees[0] = replace(trees[0], outputs=tuple(outputs))
    mutations.append(("overlapping-output-range", replace(plan, trees=tuple(trees))))
    trees = list(plan.trees)
    outputs = list(trees[0].outputs)
    outputs[0] = replace(
        outputs[0], consumer_wire_start=outputs[0].consumer_wire_start + 1
    )
    trees[0] = replace(trees[0], outputs=tuple(outputs))
    mutations.append(("wrong-tail-consumer-range", replace(plan, trees=tuple(trees))))
    trees = list(plan.trees)
    trees[-1] = replace(
        trees[-1],
        planned_wire_start=MAX_WIRE_ID,
        planned_wire_end=MAX_WIRE_ID + trees[-1].local_wires - 1,
        rebase_delta=MAX_WIRE_ID - trees[-1].standalone_wire_start,
    )
    mutations.append(("wire-integer-overflow", replace(plan, trees=tuple(trees))))
    trees = list(plan.trees)
    outputs = list(trees[3].outputs)
    outputs[0] = replace(outputs[0], value_sha256="00" * 32)
    trees[3] = replace(trees[3], outputs=tuple(outputs))
    mutations.append(("wrong-value-digest", replace(plan, trees=tuple(trees))))

    return [
        {
            "mutation": name,
            "failures": list(validate_plan(candidate, document)),
            "rejected": bool(validate_plan(candidate, document)),
        }
        for name, candidate in mutations
    ]


def build_manifest(
    tail_manifest_path: Path = DEFAULT_TAIL_MANIFEST,
) -> dict[str, object]:
    document = _read_json(tail_manifest_path)
    plan = _build_unchecked(document)
    failures = validate_plan(plan, document)
    digest = plan_sha256(plan)
    fixture = [_fixture_evidence(plan.trees[index]) for index in REPRESENTATIVE_TREE_INDICES]
    probes = _configuration_probes(plan, document)
    plan_closed = (
        not failures
        and digest == FROZEN_PLAN_SHA256
        and all(item["rejected"] for item in probes)
    )
    return {
        "implementation_version": IMPLEMENTATION_VERSION,
        "profile": {
            "relation_id": RELATION_ID,
            "field": "GF(2^193)",
            "tree_count": FROZEN_TREE_COUNT,
            "tree_order": list(TREE_ORDER),
            "representative_tree_indices": list(REPRESENTATIVE_TREE_INDICES),
            "source_tail_relation_id": tail.RELATION_ID,
            "source_tail_assignment_sha256": tail.FROZEN_PRODUCTION_ASSIGNMENT_SHA256,
            "source_tail_manifest_sha256": _sha256_file(tail_manifest_path),
        },
        "plan_sha256": digest,
        "plan": asdict(plan),
        "validation_failures": list(failures),
        "representative_rebase_fixture": fixture,
        "configuration_mutation_probes": probes,
        "claim_boundary": {
            "production_18_tree_namespace_plan_closed": plan_closed,
            "production_namespace_intervals_nonoverlapping": plan_closed,
            "production_global_point_imports_preserved": plan_closed,
            "representative_rebase_rule_fixture_verified": all(
                item["row_count_preserved"]
                and item["labels_constants_and_coefficients_preserved"]
                and item["honest_relation_values_preserved"]
                and item["point_wire_ids_preserved"]
                for item in fixture
            ),
            "representative_producers_rebased_replayed": False,
            "tree_producer_segments_materialized": False,
            "all_72_output_relocations_closed": False,
            "complete_18_tree_assignment_replayed": False,
            "cross_segment_wire_identity_closed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "cap_unique_witness_reviewed": False,
            "cap_straightline_extraction_reviewed": False,
            "fork_blindness_proved": False,
            "one_more_unforgeability_proved": False,
            "se_nizk_qrom_reduction_complete": False,
            "fork_security_proof_revalidated": False,
            "signature_size_rebenchmarked": False,
            "production_closed": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tail-manifest", type=Path, default=DEFAULT_TAIL_MANIFEST)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(
        build_manifest(args.tail_manifest), indent=2, sort_keys=True
    ) + "\n"
    if args.manifest:
        args.manifest.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
