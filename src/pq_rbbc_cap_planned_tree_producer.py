#!/usr/bin/env python3
"""Checkpointable planned-offset production tree runner for PQ-RBBC v2.23.

The v2.13 tree-0 and v2.14/v2.17 tree-2 programs remain frozen.  This module
generalizes their execution pattern without modifying either historical
implementation.  A run is derived only from the frozen v2.16 namespace plan;
its checkpoint is sealed to the selected tree, planned interval, output
locations, global-tail identity, deterministic randomness, and imported point
values.  Assignment generation preserves and byte-checks an interrupted
prefix, while full replay and mutation probes remain a separate stage.

Pickle checkpoints are trusted local files only.  Never load a checkpoint
obtained from an untrusted source.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pickle
import resource
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass, replace
from pathlib import Path

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_composer as composer
import pq_rbbc_cap_global_tail as tail
import pq_rbbc_cap_production_namespace as namespace
import pq_rbbc_cap_production_tree0_producer as tree0
import pq_rbbc_cap_production_tree2_producer as tree2
import pq_rbbc_cap_production_tree2_rebased as tree2_rebased
import pq_rbbc_cap_shard_assignment as assignment
import pq_rbbc_cap_tree_producer as producer


IMPLEMENTATION_VERSION = "2.23"
RELATION_ID = "pq-rbbc/cap/planned-offset-tree-runner/v1"
EXECUTION_CACHE_FORMAT = "PQRBBC-PLANNED-TREE-CACHE-1"
RESUME_FORMAT = "PQRBBC-PLANNED-TREE-RESUME-1"
ARTIFACT_TAG = "v2_23_planned"
MANIFEST_NAME = "pq_rbbc_cap_planned_tree3_manifest_v2_23.json"
CHECKPOINT_BATCH_LEAVES = 128
MAX_WIRE_ID = (1 << 64) - 1
TREE1_INDEX = 1
TREE3_INDEX = 3
DEFAULT_TREE_INDEX = TREE3_INDEX
FROZEN_TREE1_CONTRACT_SHA256 = (
    "69aeb8e5deda83a2ff4f2e58a87990564b8aa42bcb3b65719749ebc54958f723"
)
FROZEN_TREE3_CONTRACT_SHA256 = (
    "680a89d31e2f566b0f08f68f095643ca7642c600c124ba98b860b40e3e01481a"
)
FROZEN_CONTRACT_SHA256_BY_TREE = {
    TREE1_INDEX: FROZEN_TREE1_CONTRACT_SHA256,
    TREE3_INDEX: FROZEN_TREE3_CONTRACT_SHA256,
}
FROZEN_STREAM_BYTES_BY_TREE = {
    0: tree0.FROZEN_STREAM_BYTES,
    1: 18_008_277_115,
    2: tree2.FROZEN_STREAM_BYTES,
    3: 8_961_160_824,
}

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_NAMESPACE_MANIFEST = ROOT / "manifests" / namespace.MANIFEST_NAME
DEFAULT_GLOBAL_MANIFEST = ROOT / "manifests" / "pq_rbbc_cap_global_tail_manifest_v2_9.json"


@dataclass(frozen=True)
class PlannedTreeContract:
    runner_relation_id: str
    namespace_relation_id: str
    namespace_plan_sha256: str
    producer_relation_id: str
    tree_index: int
    leaves: int
    extension_degree: int
    standalone_local_wire_start: int
    planned_local_wire_start: int
    planned_max_wire_id: int
    rebase_delta: int
    planned_output_wire_starts: tuple[int, ...]
    global_point_wire_starts: tuple[int, ...]
    local_wires: int
    rows: int
    nonlinear_rows: int
    linear_rows: int
    stream_bytes: int | None
    assignment_bytes: int
    source_global_assignment_sha256: str


@dataclass(frozen=True)
class PlannedTreeResult:
    summary: producer.ProducerSummary
    archive: assignment.AssignmentArchiveMetadata
    tree_component_sha256: str
    global_point_values: tuple[int, ...]
    standard_probes: tuple[assignment.TamperProbe, ...]
    point_probes: tuple[tree2.PointMutationProbe, ...]
    generation_seconds: float
    verification_seconds: float
    resumed_execution_cache: bool
    resumed_assignment_prefix_wires: int


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path} is not a JSON object")
    return document


def _shape_accounting(tree_index: int, leaves: int) -> tuple[int, int, int | None]:
    if leaves == tree0.LEAVES:
        return (
            38_212_470,
            13_112_610,
            FROZEN_STREAM_BYTES_BY_TREE.get(tree_index),
        )
    if leaves == tree2.LEAVES:
        return (
            19_110_002,
            6_556_384,
            FROZEN_STREAM_BYTES_BY_TREE.get(tree_index),
        )
    raise ValueError(f"unsupported production tree shape: {leaves} leaves")


def _tree_from_manifest(
    tree_index: int, namespace_manifest_path: Path
) -> Mapping[str, object]:
    document = _read_json(namespace_manifest_path)
    if document.get("plan_sha256") != namespace.FROZEN_PLAN_SHA256:
        raise ValueError("namespace plan digest is not frozen v2.16")
    boundary = document.get("claim_boundary")
    if not isinstance(boundary, dict) or not boundary.get(
        "production_18_tree_namespace_plan_closed"
    ):
        raise ValueError("namespace planning gate is not closed")
    plan = document.get("plan")
    if not isinstance(plan, dict):
        raise ValueError("namespace manifest lacks plan")
    trees = plan.get("trees")
    if not isinstance(trees, list) or len(trees) != namespace.FROZEN_TREE_COUNT:
        raise ValueError("namespace manifest has wrong tree count")
    if not 0 <= tree_index < len(trees):
        raise ValueError("tree index is outside the frozen namespace")
    tree = trees[tree_index]
    if not isinstance(tree, dict) or tree.get("tree_index") != tree_index:
        raise ValueError("namespace tree position is malformed")
    return tree


def load_contract(
    tree_index: int,
    namespace_manifest_path: Path = DEFAULT_NAMESPACE_MANIFEST,
) -> PlannedTreeContract:
    tree = _tree_from_manifest(tree_index, namespace_manifest_path)
    outputs = tree.get("outputs")
    if not isinstance(outputs, list) or len(outputs) != 4:
        raise ValueError("namespace tree outputs are malformed")
    nonlinear_rows, linear_rows, stream_bytes = _shape_accounting(
        tree_index, int(tree["leaves"])
    )
    local_wires = int(tree["local_wires"])
    return PlannedTreeContract(
        runner_relation_id=RELATION_ID,
        namespace_relation_id=namespace.RELATION_ID,
        namespace_plan_sha256=namespace.FROZEN_PLAN_SHA256,
        producer_relation_id=str(tree["producer_relation_id"]),
        tree_index=int(tree["tree_index"]),
        leaves=int(tree["leaves"]),
        extension_degree=int(tree["extension_degree"]),
        standalone_local_wire_start=int(tree["standalone_wire_start"]),
        planned_local_wire_start=int(tree["planned_wire_start"]),
        planned_max_wire_id=int(tree["planned_wire_end"]),
        rebase_delta=int(tree["rebase_delta"]),
        planned_output_wire_starts=tuple(
            int(item["planned_wire_start"])
            for item in outputs
            if isinstance(item, dict)
        ),
        global_point_wire_starts=namespace.POINT_WIRE_STARTS,
        local_wires=local_wires,
        rows=int(tree["producer_rows"]),
        nonlinear_rows=nonlinear_rows,
        linear_rows=linear_rows,
        stream_bytes=stream_bytes,
        assignment_bytes=(
            assignment.ASSIGNMENT_HEADER_BYTES
            + local_wires * field.FIELD_ELEMENT_BYTES
        ),
        source_global_assignment_sha256=tail.FROZEN_PRODUCTION_ASSIGNMENT_SHA256,
    )


def contract_sha256(contract: PlannedTreeContract) -> str:
    encoded = json.dumps(
        asdict(contract), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def contract_failures(
    contract: PlannedTreeContract,
    canonical: PlannedTreeContract,
) -> tuple[str, ...]:
    failures: list[str] = []
    for name in contract.__dataclass_fields__:
        if getattr(contract, name) != getattr(canonical, name):
            failures.append(f"wrong_{name}")
    if contract.producer_relation_id != (
        f"pq-rbbc/cap/production-tree-producer-index-{contract.tree_index}/v1"
    ):
        failures.append("inconsistent_producer_relation")
    parameters = cap.PRODUCTION_PARAMETERS
    if (contract.leaves, contract.extension_degree) != (
        parameters.expanded_leaf_counts()[contract.tree_index],
        parameters.expanded_extension_degrees()[contract.tree_index],
    ):
        failures.append("inconsistent_tree_shape")
    if contract.planned_local_wire_start != (
        contract.standalone_local_wire_start + contract.rebase_delta
    ):
        failures.append("inconsistent_rebase_delta")
    if contract.planned_max_wire_id != (
        contract.planned_local_wire_start + contract.local_wires - 1
    ):
        failures.append("inconsistent_planned_interval")
    if contract.rows != contract.nonlinear_rows + contract.linear_rows:
        failures.append("inconsistent_row_accounting")
    if contract.assignment_bytes != (
        assignment.ASSIGNMENT_HEADER_BYTES
        + contract.local_wires * field.FIELD_ELEMENT_BYTES
    ):
        failures.append("inconsistent_assignment_size")
    if contract.stream_bytes is not None and contract.stream_bytes <= 0:
        failures.append("invalid_frozen_stream_size")
    expected_outputs = (
        tree0.FROZEN_OUTPUT_WIRE_STARTS
        if contract.leaves == tree0.LEAVES
        else tree2.FROZEN_OUTPUT_WIRE_STARTS
    )
    expected_outputs = tuple(
        item + contract.rebase_delta for item in expected_outputs
    )
    if contract.planned_output_wire_starts != expected_outputs:
        failures.append("inconsistent_output_rebase")
    if tuple(contract.global_point_wire_starts) != namespace.POINT_WIRE_STARTS:
        failures.append("wrong_global_point_ranges")
    if any(
        start + field.FIELD_DEGREE > contract.planned_local_wire_start
        for start in contract.global_point_wire_starts
    ):
        failures.append("point_import_overlaps_local_wires")
    if contract.planned_max_wire_id > MAX_WIRE_ID:
        failures.append("wire_integer_overflow")
    return tuple(dict.fromkeys(failures))


def _configuration_probes(
    canonical: PlannedTreeContract,
) -> tuple[dict[str, object], ...]:
    mutations = (
        ("wrong-tree-index", replace(canonical, tree_index=(canonical.tree_index + 1) % 18)),
        ("wrong-namespace-digest", replace(canonical, namespace_plan_sha256="00" * 32)),
        ("wrong-relation", replace(canonical, producer_relation_id="wrong/relation")),
        ("wrong-local-start", replace(canonical, planned_local_wire_start=canonical.planned_local_wire_start + 1)),
        ("wrong-max-wire", replace(canonical, planned_max_wire_id=canonical.planned_max_wire_id + 1)),
        ("wrong-output-start", replace(canonical, planned_output_wire_starts=(canonical.planned_output_wire_starts[0] + 1, *canonical.planned_output_wire_starts[1:]))),
        ("wrong-point-range", replace(canonical, global_point_wire_starts=(canonical.global_point_wire_starts[0] + 1, canonical.global_point_wire_starts[1]))),
        ("wrong-row-count", replace(canonical, rows=canonical.rows + 1)),
        ("wrong-wire-count", replace(canonical, local_wires=canonical.local_wires + 1)),
        ("wrong-global-assignment", replace(canonical, source_global_assignment_sha256="11" * 32)),
    )
    return tuple(
        {
            "mutation": label,
            "failures": list(contract_failures(candidate, canonical)),
            "rejected": bool(contract_failures(candidate, canonical)),
        }
        for label, candidate in mutations
    )


def _randomness_digest(randomness: cap.CAPRandomness) -> str:
    return hashlib.sha256(
        randomness.serialize(cap.PRODUCTION_PARAMETERS)
    ).hexdigest()


def _checkpoint_identity(
    contract: PlannedTreeContract,
    randomness: cap.CAPRandomness,
    point_values: Sequence[int],
) -> dict[str, object]:
    return {
        "format": EXECUTION_CACHE_FORMAT,
        "runner_relation_id": RELATION_ID,
        "producer_relation_id": contract.producer_relation_id,
        "namespace_plan_sha256": contract.namespace_plan_sha256,
        "contract_sha256": contract_sha256(contract),
        "profile_fingerprint": cap.profile_fingerprint(cap.PRODUCTION_PARAMETERS),
        "randomness_label": composer.FROZEN_RANDOMNESS_LABEL,
        "randomness_sha256": _randomness_digest(randomness),
        "source_assignment_sha256": contract.source_global_assignment_sha256,
        "point_value_sha256": producer._field_tuple_digest(tuple(point_values)),
        "tree_index": contract.tree_index,
        "leaves": contract.leaves,
        "extension_degree": contract.extension_degree,
        "planned_local_wire_start": contract.planned_local_wire_start,
        "planned_max_wire_id": contract.planned_max_wire_id,
        "planned_output_wire_starts": contract.planned_output_wire_starts,
    }


def _new_execution_checkpoint(
    contract: PlannedTreeContract,
    randomness: cap.CAPRandomness,
    point_values: Sequence[int],
) -> dict[str, object]:
    return {
        **_checkpoint_identity(contract, randomness, point_values),
        "next_level": 2,
        "nodes": tuple(randomness.roots[contract.tree_index]),
        "derivations": tuple(),
        "leaf_outputs": tuple(),
        "phase": "derive",
    }


def _load_execution_checkpoint(
    path: Path,
    contract: PlannedTreeContract,
    randomness: cap.CAPRandomness,
    point_values: Sequence[int],
) -> tuple[dict[str, object], bool]:
    if not path.exists():
        return _new_execution_checkpoint(contract, randomness, point_values), False
    with path.open("rb") as stream:
        value = pickle.load(stream)
    if not isinstance(value, dict):
        raise ValueError("planned tree execution checkpoint type mismatch")
    expected = _checkpoint_identity(contract, randomness, point_values)
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise ValueError(f"planned tree execution checkpoint mismatch: {key}")
    nodes = value.get("nodes")
    derivations = value.get("derivations")
    leaf_outputs = value.get("leaf_outputs")
    if not isinstance(nodes, tuple) or not isinstance(derivations, tuple):
        raise ValueError("planned tree execution checkpoint is malformed")
    if not nodes or len(nodes) > contract.leaves or len(nodes) & (len(nodes) - 1):
        raise ValueError("planned tree seed checkpoint is malformed")
    if not isinstance(leaf_outputs, tuple) or len(leaf_outputs) > contract.leaves:
        raise ValueError("planned tree leaf checkpoint is malformed")
    return value, True


def _atomic_pickle(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as stream:
        pickle.dump(value, stream, protocol=pickle.HIGHEST_PROTOCOL)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def _atomic_json(path: Path, value: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with temporary.open("rb") as stream:
        os.fsync(stream.fileno())
    temporary.replace(path)


def _map_tasks(
    function: Callable[[object], object],
    tasks: Sequence[object],
    workers: int,
) -> list[object]:
    if workers <= 1:
        return list(map(function, tasks))
    with ProcessPoolExecutor(max_workers=workers) as executor:
        return list(executor.map(function, tasks, chunksize=8))


def build_tree_material(
    contract: PlannedTreeContract,
    checkpoint_path: Path,
    point_values: Sequence[int],
    *,
    workers: int = 1,
    progress: Callable[[str], None] | None = None,
) -> tuple[cap.CAPRandomness, producer.TreeProducerMaterial, str, bool]:
    parameters = cap.PRODUCTION_PARAMETERS
    randomness = cap.deterministic_randomness(
        parameters, composer.FROZEN_RANDOMNESS_LABEL
    )
    state, resumed = _load_execution_checkpoint(
        checkpoint_path, contract, randomness, point_values
    )
    nodes = list(state["nodes"])
    derivations = list(state["derivations"])
    next_level = int(state["next_level"])

    while len(nodes) < contract.leaves:
        tasks = [
            (contract.tree_index, next_level, index, parent, randomness.salt)
            for index, parent in enumerate(nodes, start=1)
        ]
        outputs = _map_tasks(composer._derive_task, tasks, max(1, workers))
        children: list[int] = []
        for index, (parent, output) in enumerate(
            zip(nodes, outputs, strict=True), start=1
        ):
            output = int(output)
            derivations.append((next_level, index, parent, output))
            children.extend((output & field.FIELD_MASK, output >> cap.SEED_BITS))
        nodes = children
        next_level += 1
        state.update(
            {
                "next_level": next_level,
                "nodes": tuple(nodes),
                "derivations": tuple(derivations),
                "phase": "derive" if len(nodes) < contract.leaves else "leaves",
            }
        )
        _atomic_pickle(checkpoint_path, state)
        if progress is not None:
            progress(
                f"tree {contract.tree_index} execution checkpoint: "
                f"{len(nodes)}/{contract.leaves} seeds"
            )

    leaf_outputs = list(state["leaf_outputs"])
    while len(leaf_outputs) < contract.leaves:
        start = len(leaf_outputs)
        end = min(contract.leaves, start + CHECKPOINT_BATCH_LEAVES)
        tasks = [
            (
                contract.tree_index,
                index + 1,
                nodes[index],
                randomness.salt,
                parameters.random_polynomial_bits,
            )
            for index in range(start, end)
        ]
        leaf_outputs.extend(
            tuple(item)
            for item in _map_tasks(composer._leaf_task, tasks, max(1, workers))
        )
        state.update(
            {
                "leaf_outputs": tuple(leaf_outputs),
                "phase": "complete" if end == contract.leaves else "leaves",
            }
        )
        _atomic_pickle(checkpoint_path, state)
        if progress is not None:
            progress(
                f"tree {contract.tree_index} execution checkpoint: "
                f"{end}/{contract.leaves} leaves"
            )

    polynomial = composer._aggregate_tree_task(
        (
            contract.leaves,
            contract.extension_degree,
            parameters.random_polynomial_bits,
            tuple(leaf_outputs),
        )
    )
    derivation_sets: list[Sequence[tuple[int, int, int, int]]] = [
        tuple() for _ in range(parameters.tree_count)
    ]
    seed_sets: list[Sequence[int]] = [tuple() for _ in range(parameters.tree_count)]
    output_sets: list[Sequence[tuple[int, int]]] = [
        tuple() for _ in range(parameters.tree_count)
    ]
    derivation_sets[contract.tree_index] = tuple(derivations)
    seed_sets[contract.tree_index] = tuple(nodes)
    output_sets[contract.tree_index] = tuple(leaf_outputs)
    calls = composer._canonical_tree_calls(
        parameters, randomness, derivation_sets, seed_sets, output_sets
    )
    component_sha256 = hashlib.sha256(
        cap._tree_component(contract.tree_index, polynomial)
    ).hexdigest()
    if contract.tree_index == 0 and component_sha256 != tree0.FROZEN_TREE_COMPONENT_SHA256:
        raise AssertionError("generic runner changed frozen tree-0 execution")
    if contract.tree_index == 2 and component_sha256 != tree2.FROZEN_TREE_COMPONENT_SHA256:
        raise AssertionError("generic runner changed frozen tree-2 execution")
    material = producer.material_from_local_tree(
        parameters,
        contract.tree_index,
        polynomial,
        tuple(point_values),
        calls,
    )
    return randomness, material, component_sha256, resumed


def validate_point_imports(contract: PlannedTreeContract) -> tuple[str, ...]:
    failures: list[str] = []
    if contract.global_point_wire_starts != namespace.POINT_WIRE_STARTS:
        failures.append("wrong_point_relocation")
    if len(contract.global_point_wire_starts) != 2 or (
        contract.global_point_wire_starts[1]
        != contract.global_point_wire_starts[0] + field.FIELD_DEGREE
    ):
        failures.append("noncontiguous_point_ranges")
    if any(
        start + field.FIELD_DEGREE > contract.planned_local_wire_start
        for start in contract.global_point_wire_starts
    ):
        failures.append("point_import_overlaps_local_wires")
    return tuple(failures)


def _run_point_probes(
    values: Mapping[int, int],
    captured: Mapping[str, field.RankOneRow],
    point_starts: Sequence[int],
) -> tuple[tree2.PointMutationProbe, ...]:
    labels = (
        "horner.leaf[1].point[0].mul[9]",
        "horner.leaf[1].point[1].mul[9]",
    )
    probes: list[tree2.PointMutationProbe] = []
    for label, start in zip(labels, point_starts, strict=True):
        stale = assignment.StaleAssignment(values, start, values[start] ^ 1)
        probes.append(tree2._point_probe(values, captured[label], "flip-imported-point", start, stale))
    swap = {
        point_starts[0] + bit: values[point_starts[1] + bit]
        for bit in range(field.FIELD_DEGREE)
    }
    swap.update(
        {
            point_starts[1] + bit: values[point_starts[0] + bit]
            for bit in range(field.FIELD_DEGREE)
        }
    )
    probes.append(
        tree2._point_probe(
            values,
            captured[labels[0]],
            "swap-imported-points",
            point_starts[0],
            tree2.OverlayAssignment(values, swap),
        )
    )
    return tuple(probes)


def _artifact_paths(
    output_directory: Path, tree_index: int, artifact_tag: str
) -> tuple[Path, Path, Path]:
    if not artifact_tag or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
        for character in artifact_tag
    ):
        raise ValueError("artifact tag must be a non-empty filesystem-safe token")
    return (
        output_directory
        / f"pq_rbbc_production_tree_{tree_index}_producer_{artifact_tag}.f193assign",
        output_directory / f"tree_{tree_index}_execution_checkpoint_{artifact_tag}.pkl",
        output_directory / f"tree_{tree_index}_resume_state_{artifact_tag}.json",
    )


def build_production_tree(
    tree_index: int,
    output_directory: Path,
    global_archive_path: Path,
    global_manifest_path: Path = DEFAULT_GLOBAL_MANIFEST,
    *,
    namespace_manifest_path: Path = DEFAULT_NAMESPACE_MANIFEST,
    artifact_tag: str = ARTIFACT_TAG,
    execution_cache_path: Path | None = None,
    workers: int = 1,
    replace_archive: bool = False,
    progress: Callable[[str], None] | None = None,
) -> PlannedTreeResult:
    contract = load_contract(tree_index, namespace_manifest_path)
    if contract_failures(contract, contract):
        raise ValueError("planned tree contract is invalid")
    frozen_contract_sha256 = FROZEN_CONTRACT_SHA256_BY_TREE.get(tree_index)
    if (
        frozen_contract_sha256 is not None
        and contract_sha256(contract) != frozen_contract_sha256
    ):
        raise ValueError(
            f"tree-{tree_index} planned contract is not frozen "
            f"v{IMPLEMENTATION_VERSION}"
        )
    point_failures = validate_point_imports(contract)
    if point_failures:
        raise ValueError("planned point import contract rejected: " + ",".join(point_failures))

    output_directory.mkdir(parents=True, exist_ok=True)
    archive_path, default_cache_path, stage_path = _artifact_paths(
        output_directory, tree_index, artifact_tag
    )
    if execution_cache_path is None:
        execution_cache_path = default_cache_path
    source_manifest = _read_json(global_manifest_path)
    expected_global = tree2._archive_metadata(source_manifest)
    if expected_global.archive_sha256 != contract.source_global_assignment_sha256:
        raise ValueError("global-tail assignment identity is not frozen v2.9")

    with assignment.AssignmentArchiveReader(
        global_archive_path, expected=expected_global, verify_body=True
    ) as global_values:
        point_values = tuple(
            tree2._field_from_bits(global_values, start)
            for start in contract.global_point_wire_starts
        )
        randomness, material, component_sha, resumed_cache = build_tree_material(
            contract,
            execution_cache_path,
            point_values,
            workers=workers,
            progress=progress,
        )
        labels = producer.capture_material_labels(cap.PRODUCTION_PARAMETERS, material)
        point_labels = (
            "horner.leaf[1].point[0].mul[9]",
            "horner.leaf[1].point[1].mul[9]",
        )
        archive = None if replace_archive else tree2._complete_archive_metadata(archive_path)
        resumed_prefix = 0
        generation_seconds = 0.0
        if archive is None:
            writer = tree2.ResumableAssignmentArchiveWriter(
                archive_path, replace=replace_archive
            )
            resumed_prefix = writer.existing_wires
            started = time.perf_counter()
            try:
                generated = producer.build_tree_producer(
                    cap.PRODUCTION_PARAMETERS,
                    randomness,
                    None,
                    contract.tree_index,
                    producer_material=material,
                    external_point_starts=contract.global_point_wire_starts,
                    local_wire_start=contract.planned_local_wire_start,
                    workers=workers,
                    assignment_writer=writer,
                    progress=progress,
                )
                archive = writer.finish(generated.wires, generated.stream_sha256)
            except BaseException:
                writer.abort()
                _atomic_json(
                    stage_path,
                    {
                        "format": RESUME_FORMAT,
                        "stage": "assignment-prefix-preserved",
                        "contract_sha256": contract_sha256(contract),
                        "tree_index": contract.tree_index,
                        "planned_local_wire_start": contract.planned_local_wire_start,
                        "archive_path": str(archive_path),
                        "prefix_bytes": archive_path.stat().st_size,
                        "execution_cache": str(execution_cache_path),
                    },
                )
                raise
            generation_seconds = time.perf_counter() - started
            _atomic_json(
                stage_path,
                {
                    "format": RESUME_FORMAT,
                    "stage": "assignment-generated",
                    "contract_sha256": contract_sha256(contract),
                    "tree_index": contract.tree_index,
                    "planned_local_wire_start": contract.planned_local_wire_start,
                    "archive_sha256": archive.archive_sha256,
                    "archive_wires": archive.wires,
                    "execution_cache": str(execution_cache_path),
                },
            )
        if archive is None:
            raise AssertionError("planned producer archive metadata is missing")

        captured: dict[str, field.RankOneRow] = {}
        verification_started = time.perf_counter()
        with assignment.AssignmentArchiveReader(
            archive_path, expected=archive, verify_body=True
        ) as local_reader:
            local_values = tree2.OffsetAssignment(
                local_reader, contract.planned_local_wire_start, archive.wires
            )
            composed = tree2.CompositeAssignment(global_values, local_values)
            verified = producer.build_tree_producer(
                cap.PRODUCTION_PARAMETERS,
                randomness,
                None,
                contract.tree_index,
                producer_material=material,
                external_point_starts=contract.global_point_wire_starts,
                local_wire_start=contract.planned_local_wire_start,
                verification_assignment=composed,
                capture_rows=labels + point_labels,
                captured_rows_output=captured,
                progress=progress,
            )
            if verified.verification_failures:
                raise AssertionError(
                    f"planned tree-{tree_index} replay failed first at "
                    f"{verified.first_verification_failure}"
                )
            if verified.wires != archive.wires or verified.stream_sha256 != archive.row_stream_sha256:
                raise AssertionError("planned tree replay topology mismatch")
            standard_probes = assignment.run_tamper_probes(composed, captured, labels)
            point_probes = _run_point_probes(
                composed, captured, contract.global_point_wire_starts
            )
        verification_seconds = time.perf_counter() - verification_started

    if not all(item.rejected for item in standard_probes):
        raise AssertionError("a planned tree stale-witness probe was accepted")
    if not all(item.rejected for item in point_probes):
        raise AssertionError("a planned tree point-wire probe was accepted")
    _atomic_json(
        stage_path,
        {
            "format": RESUME_FORMAT,
            "stage": "complete",
            "contract_sha256": contract_sha256(contract),
            "tree_index": contract.tree_index,
            "planned_local_wire_start": contract.planned_local_wire_start,
            "archive_sha256": archive.archive_sha256,
            "row_stream_sha256": archive.row_stream_sha256,
            "verification_failures": verified.verification_failures,
        },
    )
    return PlannedTreeResult(
        verified,
        archive,
        component_sha,
        point_values,
        standard_probes,
        point_probes,
        generation_seconds,
        verification_seconds,
        resumed_cache,
        resumed_prefix,
    )


def _tail_ports(document: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    ports = document.get("ports")
    if not isinstance(ports, list):
        raise ValueError("global-tail manifest lacks ports")
    return {
        str(item["port_id"]): item for item in ports if isinstance(item, dict)
    }


def build_preflight_manifest(
    tree_index: int = DEFAULT_TREE_INDEX,
    namespace_manifest_path: Path = DEFAULT_NAMESPACE_MANIFEST,
) -> dict[str, object]:
    contract = load_contract(tree_index, namespace_manifest_path)
    failures = contract_failures(contract, contract)
    probes = _configuration_probes(contract)
    fixture = tree2_rebased.run_reduced_offset_fixture()
    fixture_closed = all(
        (
            fixture.assignment_values_identical,
            fixture.row_count_and_accounting_identical,
            fixture.port_values_identical,
            fixture.local_port_ids_shifted_exactly,
            fixture.point_wire_ids_preserved,
            fixture.captured_rows_rebase_exact,
            fixture.planned_replay_failures == 0,
            fixture.stale_witness_probes_rejected,
        )
    )
    digest = contract_sha256(contract)
    expected_contract_sha256 = FROZEN_CONTRACT_SHA256_BY_TREE.get(tree_index)
    frozen_contract = (
        expected_contract_sha256 is None or digest == expected_contract_sha256
    )
    preflight_closed = (
        not failures
        and frozen_contract
        and all(item["rejected"] for item in probes)
        and fixture_closed
    )
    return {
        "implementation_version": IMPLEMENTATION_VERSION,
        "profile": {
            "relation_id": RELATION_ID,
            "tree_index": tree_index,
            "artifact_tag": ARTIFACT_TAG,
            "assignment_format": assignment.ASSIGNMENT_FORMAT,
            "execution_cache_format": EXECUTION_CACHE_FORMAT,
            "resume_format": RESUME_FORMAT,
        },
        "contract_sha256": digest,
        "contract": asdict(contract),
        "contract_validation_failures": list(failures),
        "configuration_mutation_probes": list(probes),
        "reduced_offset_fixture": asdict(fixture),
        "production_replay": {
            "status": "not_materialized",
            "production_rows_replayed_at_planned_offset": 0,
            "required_global_tail_assignment_sha256": tail.FROZEN_PRODUCTION_ASSIGNMENT_SHA256,
            "planned_row_stream_sha256": None,
            "planned_assignment_sha256": None,
            "planned_assignment_body_sha256": None,
            "tree_component_sha256": None,
            "external_artifacts_tracked_in_git": False,
        },
        "claim_boundary": {
            "planned_tree_runner_preflight_closed": preflight_closed,
            "planned_offset_reduced_fixture_replayed": fixture_closed,
            "target_tree_index": tree_index,
            "production_tree1_planned_assignment_materialized": False,
            "production_tree1_planned_full_replay_closed": False,
            "production_tree3_planned_assignment_materialized": False,
            "production_tree3_planned_full_replay_closed": False,
            "remaining_planned_tree_producers_materialized": False,
            "all_72_output_relocations_closed": False,
            "complete_18_tree_assignment_replayed": False,
            "cross_segment_wire_identity_closed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }


def build_replayed_manifest(
    result: PlannedTreeResult,
    tree_index: int,
    global_manifest_path: Path = DEFAULT_GLOBAL_MANIFEST,
    namespace_manifest_path: Path = DEFAULT_NAMESPACE_MANIFEST,
) -> dict[str, object]:
    document = build_preflight_manifest(tree_index, namespace_manifest_path)
    contract = PlannedTreeContract(**document["contract"])
    consumers = _tail_ports(_read_json(global_manifest_path))
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
            document["claim_boundary"]["planned_tree_runner_preflight_closed"],
            result.summary.tree_index == contract.tree_index,
            result.summary.leaves == contract.leaves,
            result.summary.extension_degree == contract.extension_degree,
            result.summary.local_wire_start == contract.planned_local_wire_start,
            result.summary.max_wire_id == contract.planned_max_wire_id,
            result.summary.wires == contract.local_wires,
            result.summary.rows == contract.rows,
            result.summary.nonlinear_rows == contract.nonlinear_rows,
            result.summary.linear_rows == contract.linear_rows,
            contract.stream_bytes is None
            or result.summary.stream_bytes == contract.stream_bytes,
            result.summary.external_assertions == 0,
            result.summary.verification_failures == 0,
            tuple(item.wire_start for item in output_ports)
            == contract.planned_output_wire_starts,
            len(output_matches) == 4,
            all(item["exact_value_match"] for item in output_matches),
            result.summary.imported_point_wires == contract.global_point_wire_starts,
            result.archive.wires == contract.local_wires,
            result.archive.archive_bytes == contract.assignment_bytes,
            result.archive.body_bytes
            == contract.local_wires * field.FIELD_ELEMENT_BYTES,
            result.archive.row_stream_sha256 == result.summary.stream_sha256,
            producer._field_tuple_digest(result.global_point_values)
            == tree0.FROZEN_POINT_VALUE_SHA256,
            len(result.standard_probes) == 6,
            all(item.rejected for item in result.standard_probes),
            len(result.point_probes) == 3,
            all(item.rejected for item in result.point_probes),
        )
    )
    document["production_replay"] = {
        "status": "complete" if replay_closed else "rejected",
        "production_rows_replayed_at_planned_offset": result.summary.rows,
        "planned_row_stream_bytes": result.summary.stream_bytes,
        "planned_row_stream_sha256": result.summary.stream_sha256,
        "planned_assignment_bytes": result.archive.archive_bytes,
        "planned_assignment_sha256": result.archive.archive_sha256,
        "planned_assignment_body_sha256": result.archive.body_sha256,
        "tree_component_sha256": result.tree_component_sha256,
        "output_matches": list(output_matches),
        "verification_failures": result.summary.verification_failures,
        "external_assertions": result.summary.external_assertions,
        "stale_witness_probes": len(result.standard_probes),
        "point_mutation_probes": len(result.point_probes),
        "generation_seconds": result.generation_seconds,
        "verification_seconds": result.verification_seconds,
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "resumed_execution_cache_this_run": result.resumed_execution_cache,
        "resumed_assignment_prefix_wires_this_run": result.resumed_assignment_prefix_wires,
    }
    if tree_index == TREE1_INDEX:
        document["claim_boundary"].update(
            {
                "production_tree1_planned_assignment_materialized": replay_closed,
                "production_tree1_planned_full_replay_closed": replay_closed,
            }
        )
    if tree_index == TREE3_INDEX:
        document["claim_boundary"].update(
            {
                "production_tree3_planned_assignment_materialized": replay_closed,
                "production_tree3_planned_full_replay_closed": replay_closed,
            }
        )
    return document


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tree-index", type=int, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--namespace-manifest", type=Path, default=DEFAULT_NAMESPACE_MANIFEST)
    parser.add_argument("--output-directory", type=Path)
    parser.add_argument("--global-archive", type=Path)
    parser.add_argument("--global-manifest", type=Path, default=DEFAULT_GLOBAL_MANIFEST)
    parser.add_argument("--execution-cache", type=Path)
    parser.add_argument("--artifact-tag", default=ARTIFACT_TAG)
    parser.add_argument("--workers", type=int, default=max(1, min(8, os.cpu_count() or 1)))
    parser.add_argument("--replace-archive", action="store_true")
    args = parser.parse_args()
    if (args.output_directory is None) != (args.global_archive is None):
        parser.error("--output-directory and --global-archive must be provided together")
    if args.output_directory is None:
        document = build_preflight_manifest(args.tree_index, args.namespace_manifest)
    else:
        result = build_production_tree(
            args.tree_index,
            args.output_directory,
            args.global_archive,
            args.global_manifest,
            namespace_manifest_path=args.namespace_manifest,
            artifact_tag=args.artifact_tag,
            execution_cache_path=args.execution_cache,
            workers=args.workers,
            replace_archive=args.replace_archive,
            progress=lambda message: print(message, flush=True),
        )
        document = build_replayed_manifest(
            result,
            args.tree_index,
            args.global_manifest,
            args.namespace_manifest,
        )
    _atomic_json(args.manifest, document)
    print(
        json.dumps(
            {
                "manifest": str(args.manifest),
                "tree_index": args.tree_index,
                "production_replay_status": document["production_replay"]["status"],
                "preflight_closed": document["claim_boundary"]["planned_tree_runner_preflight_closed"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
