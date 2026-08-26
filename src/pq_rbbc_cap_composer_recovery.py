#!/usr/bin/env python3
"""Checkpoint/resume recovery path for the PQ-RBBC production composer, v2.18.

The frozen v2.8 composer produces the trusted execution cache required to
reconstruct the separately distributed v2.9 global-tail assignment.  Its
canonical implementation checkpoints only after the complete 18-tree run.
This module preserves the same task functions and canonical serialization, but
atomically checkpoints every completed derivation level and leaf batch.

The tracked v2.18 evidence executes only the reduced profile and proves that an
interrupted/resumed run is bit-exact with the original composer.  Production
artifact claims remain false until the full production run is materialized and
its v2.8 document identity is independently revalidated.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pickle
import resource
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable, Mapping, Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_composer as composer


IMPLEMENTATION_VERSION = "2.18"
RELATION_ID = "pq-rbbc/cap/production-composer-recovery/v1"
CHECKPOINT_FORMAT = "PQRBBC-CAP-COMPOSER-CHECKPOINT-1"
MANIFEST_NAME = "pq_rbbc_cap_composer_recovery_manifest_v2_18.json"
DEFAULT_LEAF_BATCH = 128

FROZEN_CONTRACT_SHA256 = (
    "e5b0f0d188f4540f58c328d2c40296971bb5f1cb81cec35ef512df2aaaa61578"
)
FROZEN_REDUCED_EXECUTION_SHA256 = (
    "c29f87dcf144a2a3d303daf26ac3665eb09d5e241f8941123d2052a5c18d21a1"
)
FROZEN_REDUCED_FINAL_CHECKPOINT_SHA256 = (
    "926614ffc0862fab816c410314a6ec8769b8ac0bc97848210585a715829ce544"
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FROZEN_COMPOSITION_MANIFEST = (
    ROOT / "manifests" / "pq_rbbc_cap_composition_manifest_v2_8.json"
)


class CheckpointPause(RuntimeError):
    """Intentional interruption raised only after an atomic checkpoint."""


@dataclass(frozen=True)
class RecoveryContract:
    relation_id: str
    checkpoint_format: str
    source_relation_id: str
    source_document_sha256: str
    source_commitment_sha256: str
    source_xof_trace_sha256: str
    production_profile_sha256: str
    production_tree_count: int
    production_tree_shapes: tuple[tuple[int, int], ...]
    checkpoint_bound_to_profile: bool
    checkpoint_bound_to_randomness: bool
    checkpoint_state_integrity_digest: bool
    derivation_level_atomicity: bool
    leaf_batch_atomicity: bool
    canonical_tree_and_leaf_order: bool


@dataclass(frozen=True)
class ExecutionCheckpoint:
    format: str
    relation_id: str
    profile_sha256: str
    randomness_sha256: str
    tree_shapes: tuple[tuple[int, int], ...]
    random_polynomial_bits: int
    phase: str
    next_level: int
    nodes: tuple[tuple[int, ...], ...]
    derivations: tuple[tuple[tuple[int, int, int, int], ...], ...]
    leaf_outputs: tuple[tuple[tuple[int, int], ...], ...]
    state_sha256: str


@dataclass(frozen=True)
class CheckpointedExecutionResult:
    summary: composer.ParallelExecutionSummary
    resumed_checkpoint: bool
    checkpoints_written: int
    checkpoint_state_sha256: str


@dataclass(frozen=True)
class ReducedRecoveryEvidence:
    tree_count: int
    tree_shapes: tuple[tuple[int, int], ...]
    leaf_batch: int
    interruption_after_checkpoints: int
    resume_observed: bool
    checkpoints_written_after_resume: int
    direct_execution_sha256: str
    resumed_execution_sha256: str
    execution_bit_exact: bool
    final_checkpoint_phase: str
    final_checkpoint_sha256: str
    execution_cache_validation_failures: int
    checkpoint_mutation_probes: int
    checkpoint_mutation_probes_rejected: bool
    fixture_is_not_production_execution_evidence: bool


def _tree_shapes(parameters: cap.CAPParameters) -> tuple[tuple[int, int], ...]:
    return tuple(
        zip(
            parameters.expanded_leaf_counts(),
            parameters.expanded_extension_degrees(),
        )
    )


def _randomness_sha256(randomness: cap.CAPRandomness) -> str:
    digest = hashlib.sha256()
    digest.update(b"PQRBBC-CAP-RANDOMNESS-1\x00")
    for value in randomness.salt:
        digest.update(value.to_bytes(field.FIELD_ELEMENT_BYTES, "little"))
    digest.update(len(randomness.roots).to_bytes(8, "little"))
    for roots in randomness.roots:
        digest.update(len(roots).to_bytes(8, "little"))
        for value in roots:
            digest.update(value.to_bytes(field.FIELD_ELEMENT_BYTES, "little"))
    return digest.hexdigest()


def _new_checkpoint(
    parameters: cap.CAPParameters,
    randomness: cap.CAPRandomness,
) -> ExecutionCheckpoint:
    return ExecutionCheckpoint(
        format=CHECKPOINT_FORMAT,
        relation_id=RELATION_ID,
        profile_sha256=cap.profile_fingerprint(parameters),
        randomness_sha256=_randomness_sha256(randomness),
        tree_shapes=_tree_shapes(parameters),
        random_polynomial_bits=parameters.random_polynomial_bits,
        phase="derive",
        next_level=2,
        nodes=tuple(tuple(pair) for pair in randomness.roots),
        derivations=tuple(tuple() for _ in range(parameters.tree_count)),
        leaf_outputs=tuple(tuple() for _ in range(parameters.tree_count)),
        state_sha256="",
    )


def _update_sized(digest: "hashlib._Hash", value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "little"))
    digest.update(value)


def checkpoint_state_sha256(checkpoint: ExecutionCheckpoint) -> str:
    """Hash every checkpoint field except the digest itself."""

    digest = hashlib.sha256()
    for value in (
        checkpoint.format.encode("ascii"),
        checkpoint.relation_id.encode("ascii"),
        checkpoint.profile_sha256.encode("ascii"),
        checkpoint.randomness_sha256.encode("ascii"),
        checkpoint.phase.encode("ascii"),
    ):
        _update_sized(digest, value)
    digest.update(checkpoint.random_polynomial_bits.to_bytes(8, "little"))
    digest.update(checkpoint.next_level.to_bytes(8, "little"))
    digest.update(len(checkpoint.tree_shapes).to_bytes(8, "little"))
    for leaves, degree in checkpoint.tree_shapes:
        digest.update(leaves.to_bytes(8, "little"))
        digest.update(degree.to_bytes(8, "little"))
    for values in checkpoint.nodes:
        digest.update(len(values).to_bytes(8, "little"))
        for value in values:
            digest.update(value.to_bytes(field.FIELD_ELEMENT_BYTES, "little"))
    seed_pair_bytes = (2 * cap.SEED_BITS + 7) // 8
    for values in checkpoint.derivations:
        digest.update(len(values).to_bytes(8, "little"))
        for level, node_index, parent, output in values:
            digest.update(level.to_bytes(8, "little"))
            digest.update(node_index.to_bytes(8, "little"))
            digest.update(parent.to_bytes(field.FIELD_ELEMENT_BYTES, "little"))
            digest.update(output.to_bytes(seed_pair_bytes, "little"))
    commitment_bytes = (cap.HASH_BITS + 7) // 8
    tape_bytes = (checkpoint.random_polynomial_bits + 7) // 8
    for values in checkpoint.leaf_outputs:
        digest.update(len(values).to_bytes(8, "little"))
        for commitment, tape in values:
            digest.update(commitment.to_bytes(commitment_bytes, "little"))
            digest.update(tape.to_bytes(tape_bytes, "little"))
    return digest.hexdigest()


def _sealed(checkpoint: ExecutionCheckpoint) -> ExecutionCheckpoint:
    return replace(
        checkpoint,
        state_sha256=checkpoint_state_sha256(replace(checkpoint, state_sha256="")),
    )


def _is_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def checkpoint_failures(
    checkpoint: ExecutionCheckpoint,
    parameters: cap.CAPParameters,
    randomness: cap.CAPRandomness,
) -> tuple[str, ...]:
    failures: list[str] = []
    expected_shapes = _tree_shapes(parameters)
    if checkpoint.format != CHECKPOINT_FORMAT:
        failures.append("wrong_format")
    if checkpoint.relation_id != RELATION_ID:
        failures.append("wrong_relation_id")
    if checkpoint.profile_sha256 != cap.profile_fingerprint(parameters):
        failures.append("wrong_profile")
    if checkpoint.randomness_sha256 != _randomness_sha256(randomness):
        failures.append("wrong_randomness")
    if checkpoint.tree_shapes != expected_shapes:
        failures.append("wrong_tree_shapes")
    if checkpoint.random_polynomial_bits != parameters.random_polynomial_bits:
        failures.append("wrong_random_polynomial_bits")
    if checkpoint.phase not in ("derive", "leaves", "complete"):
        failures.append("wrong_phase")
    if not _is_sha256(checkpoint.state_sha256) or checkpoint.state_sha256 != (
        checkpoint_state_sha256(replace(checkpoint, state_sha256=""))
    ):
        failures.append("checkpoint_state_digest")

    tree_count = parameters.tree_count
    if not (
        len(checkpoint.nodes)
        == len(checkpoint.derivations)
        == len(checkpoint.leaf_outputs)
        == tree_count
    ):
        failures.append("wrong_tree_vector_count")
        return tuple(dict.fromkeys(failures))

    leaves_per_tree = parameters.expanded_leaf_counts()
    max_level = max(leaves.bit_length() - 1 for leaves in leaves_per_tree)
    if not 2 <= checkpoint.next_level <= max_level + 1:
        failures.append("wrong_next_level")
    prefix_open = False
    all_leaves_complete = True
    all_seeds_complete = True
    for tree_index, leaves in enumerate(leaves_per_tree):
        nodes = checkpoint.nodes[tree_index]
        derivations = checkpoint.derivations[tree_index]
        outputs = checkpoint.leaf_outputs[tree_index]
        if 2 <= checkpoint.next_level <= max_level + 1:
            expected_nodes = min(leaves, 1 << (checkpoint.next_level - 1))
            if len(nodes) != expected_nodes:
                failures.append(f"tree_{tree_index}_node_count")
        if len(derivations) != max(0, len(nodes) - 2):
            failures.append(f"tree_{tree_index}_derivation_count")
        if len(nodes) != leaves:
            all_seeds_complete = False
        if len(outputs) > leaves:
            failures.append(f"tree_{tree_index}_leaf_overflow")
        if len(outputs) != leaves:
            all_leaves_complete = False
        if prefix_open and outputs:
            failures.append("noncanonical_leaf_tree_order")
        if len(outputs) < leaves:
            prefix_open = True
        if any(not 0 <= value <= field.FIELD_MASK for value in nodes):
            failures.append(f"tree_{tree_index}_noncanonical_seed")
        if any(
            level < 2
            or node_index <= 0
            or not 0 <= parent <= field.FIELD_MASK
            or not 0 <= output < (1 << (2 * cap.SEED_BITS))
            for level, node_index, parent, output in derivations
        ):
            failures.append(f"tree_{tree_index}_noncanonical_derivation")
        if any(
            not 0 <= commitment < (1 << cap.HASH_BITS)
            or not 0 <= tape < (1 << parameters.random_polynomial_bits)
            for commitment, tape in outputs
        ):
            failures.append(f"tree_{tree_index}_noncanonical_leaf_output")

    if checkpoint.phase == "derive":
        if all_seeds_complete or any(checkpoint.leaf_outputs):
            failures.append("derive_phase_state")
    elif not all_seeds_complete or checkpoint.next_level != max_level + 1:
        failures.append("leaf_phase_seed_state")
    if checkpoint.phase == "leaves" and all_leaves_complete:
        failures.append("leaves_phase_complete")
    if checkpoint.phase == "complete" and not all_leaves_complete:
        failures.append("complete_phase_incomplete")
    return tuple(dict.fromkeys(failures))


def _checkpoint_from_mapping(value: Mapping[str, object]) -> ExecutionCheckpoint:
    return ExecutionCheckpoint(
        format=str(value["format"]),
        relation_id=str(value["relation_id"]),
        profile_sha256=str(value["profile_sha256"]),
        randomness_sha256=str(value["randomness_sha256"]),
        tree_shapes=tuple(tuple(item) for item in value["tree_shapes"]),
        random_polynomial_bits=int(value["random_polynomial_bits"]),
        phase=str(value["phase"]),
        next_level=int(value["next_level"]),
        nodes=tuple(tuple(item) for item in value["nodes"]),
        derivations=tuple(
            tuple(tuple(item) for item in tree) for tree in value["derivations"]
        ),
        leaf_outputs=tuple(
            tuple(tuple(item) for item in tree) for tree in value["leaf_outputs"]
        ),
        state_sha256=str(value["state_sha256"]),
    )


def load_checkpoint(
    path: Path,
    parameters: cap.CAPParameters,
    randomness: cap.CAPRandomness,
) -> ExecutionCheckpoint:
    with path.open("rb") as stream:
        value = pickle.load(stream)
    if not isinstance(value, dict):
        raise ValueError("composer recovery checkpoint root is not a mapping")
    try:
        checkpoint = _checkpoint_from_mapping(value)
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("composer recovery checkpoint is malformed") from error
    failures = checkpoint_failures(checkpoint, parameters, randomness)
    if failures:
        raise ValueError("composer recovery checkpoint rejected: " + ",".join(failures))
    return checkpoint


def _atomic_checkpoint(path: Path, checkpoint: ExecutionCheckpoint) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as stream:
        pickle.dump(asdict(checkpoint), stream, protocol=pickle.HIGHEST_PROTOCOL)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _map_tasks(
    executor: ProcessPoolExecutor | None,
    function: Callable[[object], object],
    tasks: Sequence[object],
) -> list[object]:
    if executor is None:
        return list(map(function, tasks))
    return list(executor.map(function, tasks, chunksize=8))


def build_checkpointed_execution(
    parameters: cap.CAPParameters,
    randomness: cap.CAPRandomness,
    checkpoint_path: Path,
    *,
    workers: int = 1,
    leaf_batch: int = DEFAULT_LEAF_BATCH,
    replace_checkpoint: bool = False,
    stop_after_checkpoints: int | None = None,
    progress: Callable[[str], None] | None = None,
) -> CheckpointedExecutionResult:
    """Build the canonical execution, atomically resuming the saved prefix."""

    if parameters.consistency_points not in (1, 2):
        raise ValueError("only one or two consistency points are supported")
    if len(randomness.roots) != parameters.tree_count:
        raise ValueError("wrong number of CAP root pairs")
    if leaf_batch <= 0:
        raise ValueError("leaf batch must be positive")
    if stop_after_checkpoints is not None and stop_after_checkpoints <= 0:
        raise ValueError("stop-after-checkpoints must be positive")
    if replace_checkpoint and checkpoint_path.exists():
        checkpoint_path.unlink()
    resumed = checkpoint_path.exists()
    checkpoint = (
        load_checkpoint(checkpoint_path, parameters, randomness)
        if resumed
        else _sealed(_new_checkpoint(parameters, randomness))
    )
    started = time.perf_counter()
    checkpoints_written = 0

    def persist(value: ExecutionCheckpoint, message: str) -> ExecutionCheckpoint:
        nonlocal checkpoints_written
        value = _sealed(value)
        _atomic_checkpoint(checkpoint_path, value)
        checkpoints_written += 1
        if progress is not None:
            progress(message)
        if (
            stop_after_checkpoints is not None
            and checkpoints_written >= stop_after_checkpoints
        ):
            raise CheckpointPause(message)
        return value

    leaves_per_tree = parameters.expanded_leaf_counts()
    degrees = parameters.expanded_extension_degrees()
    workers = max(1, workers)
    executor = ProcessPoolExecutor(max_workers=workers) if workers > 1 else None
    try:
        while checkpoint.phase == "derive":
            level = checkpoint.next_level
            nodes = [list(item) for item in checkpoint.nodes]
            derivations = [list(item) for item in checkpoint.derivations]
            tasks: list[tuple[int, int, int, int, tuple[int, int]]] = []
            spans: list[tuple[int, int, int]] = []
            for tree_index, leaves in enumerate(leaves_per_tree):
                if len(nodes[tree_index]) >= leaves:
                    continue
                start = len(tasks)
                tasks.extend(
                    (
                        tree_index,
                        level,
                        node_index,
                        parent,
                        randomness.salt,
                    )
                    for node_index, parent in enumerate(
                        nodes[tree_index], start=1
                    )
                )
                spans.append((tree_index, start, len(tasks)))
            if not tasks:
                checkpoint = persist(
                    replace(checkpoint, phase="leaves"),
                    "derivation phase complete",
                )
                continue
            outputs = _map_tasks(executor, composer._derive_task, tasks)
            for tree_index, start, end in spans:
                parents = nodes[tree_index]
                children: list[int] = []
                for node_index, (parent, output) in enumerate(
                    zip(parents, outputs[start:end], strict=True), start=1
                ):
                    output = int(output)
                    derivations[tree_index].append(
                        (level, node_index, parent, output)
                    )
                    children.extend(
                        (output & field.FIELD_MASK, output >> cap.SEED_BITS)
                    )
                nodes[tree_index] = children
            all_complete = all(
                len(nodes[index]) == leaves
                for index, leaves in enumerate(leaves_per_tree)
            )
            checkpoint = persist(
                replace(
                    checkpoint,
                    phase="leaves" if all_complete else "derive",
                    next_level=level + 1,
                    nodes=tuple(tuple(item) for item in nodes),
                    derivations=tuple(tuple(item) for item in derivations),
                ),
                f"derive level {level}: {len(tasks):,} calls",
            )

        while checkpoint.phase == "leaves":
            tree_index = next(
                index
                for index, leaves in enumerate(leaves_per_tree)
                if len(checkpoint.leaf_outputs[index]) < leaves
            )
            outputs = [list(item) for item in checkpoint.leaf_outputs]
            start = len(outputs[tree_index])
            end = min(leaves_per_tree[tree_index], start + leaf_batch)
            tasks = [
                (
                    tree_index,
                    leaf_index + 1,
                    checkpoint.nodes[tree_index][leaf_index],
                    randomness.salt,
                    parameters.random_polynomial_bits,
                )
                for leaf_index in range(start, end)
            ]
            outputs[tree_index].extend(
                tuple(item)
                for item in _map_tasks(executor, composer._leaf_task, tasks)
            )
            all_complete = all(
                len(outputs[index]) == leaves
                for index, leaves in enumerate(leaves_per_tree)
            )
            checkpoint = persist(
                replace(
                    checkpoint,
                    phase="complete" if all_complete else "leaves",
                    leaf_outputs=tuple(tuple(item) for item in outputs),
                ),
                f"tree {tree_index} leaf checkpoint: {end}/{leaves_per_tree[tree_index]}",
            )

        aggregate_tasks = tuple(
            (
                leaves,
                degree,
                parameters.random_polynomial_bits,
                checkpoint.leaf_outputs[index],
            )
            for index, (leaves, degree) in enumerate(
                zip(leaves_per_tree, degrees)
            )
        )
        if progress is not None:
            progress(f"aggregate {parameters.tree_count} tree polynomials")
        polynomials = _map_tasks(
            executor, composer._aggregate_tree_task, aggregate_tasks
        )
    finally:
        if executor is not None:
            executor.shutdown()

    if progress is not None:
        progress("serialize canonical tree calls and global transcript")
    tree_calls = composer._canonical_tree_calls(
        parameters,
        randomness,
        checkpoint.derivations,
        checkpoint.nodes,
        checkpoint.leaf_outputs,
    )
    execution = composer._finish_execution(
        parameters, randomness, polynomials, tree_calls
    )
    summary = composer.ParallelExecutionSummary(
        execution,
        time.perf_counter() - started,
        resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    )
    failures = composer.validate_execution_cache_identity(
        summary, parameters, randomness
    )
    if failures:
        raise AssertionError("recovered execution rejected: " + ",".join(failures))
    return CheckpointedExecutionResult(
        summary,
        resumed,
        checkpoints_written,
        checkpoint.state_sha256,
    )


def execution_sha256(execution: cap.CAPExecution) -> str:
    """Compact canonical identity for reduced or production CAP executions."""

    trace_bytes, trace_sha256 = composer.xof_trace_digest(execution.xof_calls)
    document = {
        "profile_sha256": execution.commitment.parameters_fingerprint,
        "tree_shapes": [
            [item.leaves, item.extension_degree]
            for item in execution.tree_polynomials
        ],
        "tree_components": [
            hashlib.sha256(cap._tree_component(index, item)).hexdigest()
            for index, item in enumerate(execution.tree_polynomials)
        ],
        "commitment_sha256": hashlib.sha256(
            execution.commitment.encoded
        ).hexdigest(),
        "xof_calls": len(execution.xof_calls),
        "xof_trace_bytes": trace_bytes,
        "xof_trace_sha256": trace_sha256,
    }
    encoded = json.dumps(
        document, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_contract() -> RecoveryContract:
    parameters = cap.PRODUCTION_PARAMETERS
    return RecoveryContract(
        relation_id=RELATION_ID,
        checkpoint_format=CHECKPOINT_FORMAT,
        source_relation_id=composer.RELATION_ID,
        source_document_sha256=composer.FROZEN_DOCUMENT_SHA256,
        source_commitment_sha256=composer.FROZEN_COMMITMENT_SHA256,
        source_xof_trace_sha256=composer.FROZEN_XOF_TRACE_SHA256,
        production_profile_sha256=cap.profile_fingerprint(parameters),
        production_tree_count=parameters.tree_count,
        production_tree_shapes=_tree_shapes(parameters),
        checkpoint_bound_to_profile=True,
        checkpoint_bound_to_randomness=True,
        checkpoint_state_integrity_digest=True,
        derivation_level_atomicity=True,
        leaf_batch_atomicity=True,
        canonical_tree_and_leaf_order=True,
    )


def contract_sha256(contract: RecoveryContract) -> str:
    encoded = json.dumps(
        asdict(contract), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _mutation_probes(
    checkpoint: ExecutionCheckpoint,
    parameters: cap.CAPParameters,
    randomness: cap.CAPRandomness,
) -> tuple[dict[str, object], ...]:
    def reseal(value: ExecutionCheckpoint) -> ExecutionCheckpoint:
        return _sealed(replace(value, state_sha256=""))

    nodes = list(checkpoint.nodes)
    nodes[0] = nodes[0][:-1]
    outputs = list(checkpoint.leaf_outputs)
    outputs[0] = (*outputs[0], outputs[0][-1])
    mutations = (
        ("wrong-format", reseal(replace(checkpoint, format="wrong"))),
        ("wrong-relation", reseal(replace(checkpoint, relation_id="wrong"))),
        ("wrong-profile", reseal(replace(checkpoint, profile_sha256="00" * 32))),
        ("wrong-randomness", reseal(replace(checkpoint, randomness_sha256="11" * 32))),
        ("wrong-tree-shape", reseal(replace(checkpoint, tree_shapes=((1, 1), *checkpoint.tree_shapes[1:])))),
        ("wrong-node-count", reseal(replace(checkpoint, nodes=tuple(nodes)))),
        ("leaf-overflow", reseal(replace(checkpoint, leaf_outputs=tuple(outputs)))),
        ("wrong-state-digest", replace(checkpoint, state_sha256="22" * 32)),
    )
    return tuple(
        {
            "mutation": label,
            "failures": list(
                checkpoint_failures(candidate, parameters, randomness)
            ),
            "rejected": bool(
                checkpoint_failures(candidate, parameters, randomness)
            ),
        }
        for label, candidate in mutations
    )


def run_reduced_recovery_fixture() -> tuple[
    ReducedRecoveryEvidence, tuple[dict[str, object], ...]
]:
    parameters = cap.REDUCED_TEST_PARAMETERS
    randomness = cap.deterministic_randomness(parameters)
    direct = composer.build_parallel_execution(parameters, randomness, workers=1)
    with TemporaryDirectory(prefix="pq-rbbc-composer-recovery-") as directory:
        checkpoint_path = Path(directory) / "execution.checkpoint.pkl"
        try:
            build_checkpointed_execution(
                parameters,
                randomness,
                checkpoint_path,
                workers=1,
                leaf_batch=2,
                stop_after_checkpoints=1,
            )
        except CheckpointPause:
            pass
        else:
            raise AssertionError("reduced recovery fixture did not interrupt")
        resumed = build_checkpointed_execution(
            parameters,
            randomness,
            checkpoint_path,
            workers=1,
            leaf_batch=2,
        )
        final_checkpoint = load_checkpoint(
            checkpoint_path, parameters, randomness
        )
        probes = _mutation_probes(final_checkpoint, parameters, randomness)
    direct_digest = execution_sha256(direct.execution)
    resumed_digest = execution_sha256(resumed.summary.execution)
    evidence = ReducedRecoveryEvidence(
        tree_count=parameters.tree_count,
        tree_shapes=_tree_shapes(parameters),
        leaf_batch=2,
        interruption_after_checkpoints=1,
        resume_observed=resumed.resumed_checkpoint,
        checkpoints_written_after_resume=resumed.checkpoints_written,
        direct_execution_sha256=direct_digest,
        resumed_execution_sha256=resumed_digest,
        execution_bit_exact=(
            resumed.summary.execution == direct.execution
            and resumed_digest == direct_digest
        ),
        final_checkpoint_phase=final_checkpoint.phase,
        final_checkpoint_sha256=final_checkpoint.state_sha256,
        execution_cache_validation_failures=len(
            composer.validate_execution_cache_identity(
                resumed.summary, parameters, randomness
            )
        ),
        checkpoint_mutation_probes=len(probes),
        checkpoint_mutation_probes_rejected=all(
            item["rejected"] for item in probes
        ),
        fixture_is_not_production_execution_evidence=True,
    )
    return evidence, probes


def build_preflight_manifest() -> dict[str, object]:
    contract = build_contract()
    evidence, probes = run_reduced_recovery_fixture()
    gate_closed = all(
        (
            contract_sha256(contract) == FROZEN_CONTRACT_SHA256,
            evidence.direct_execution_sha256
            == FROZEN_REDUCED_EXECUTION_SHA256,
            evidence.resumed_execution_sha256
            == FROZEN_REDUCED_EXECUTION_SHA256,
            evidence.final_checkpoint_sha256
            == FROZEN_REDUCED_FINAL_CHECKPOINT_SHA256,
            evidence.execution_bit_exact,
            evidence.resume_observed,
            evidence.final_checkpoint_phase == "complete",
            evidence.execution_cache_validation_failures == 0,
            evidence.checkpoint_mutation_probes == 8,
            evidence.checkpoint_mutation_probes_rejected,
        )
    )
    return {
        "implementation_version": IMPLEMENTATION_VERSION,
        "contract_sha256": contract_sha256(contract),
        "contract": asdict(contract),
        "reduced_recovery_fixture": asdict(evidence),
        "checkpoint_mutation_probes": list(probes),
        "production_recovery": {
            "status": "not_started",
            "production_derivation_levels_checkpointed": 0,
            "production_leaf_outputs_checkpointed": 0,
            "production_execution_cache_regenerated": False,
            "production_composition_document_revalidated": False,
            "production_global_tail_archive_regenerated": False,
            "production_tree2_rebased_archive_regenerated": False,
        },
        "claim_boundary": {
            "production_composer_checkpoint_recovery_gate_closed": gate_closed,
            "reduced_checkpoint_resume_bit_exact": gate_closed,
            "production_execution_cache_regenerated": False,
            "production_global_tail_archive_regenerated": False,
            "production_tree2_rebased_assignment_materialized": False,
            "production_tree2_rebased_full_replay_closed": False,
            "representative_producers_rebased_replayed": False,
            "complete_18_tree_assignment_replayed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }


def _atomic_pickle(path: Path, value: object, *, replace_output: bool) -> None:
    if path.exists() and not replace_output:
        raise FileExistsError(f"refusing to replace {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as stream:
        pickle.dump(value, stream, protocol=pickle.HIGHEST_PROTOCOL)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _atomic_bytes(path: Path, encoded: bytes, *, replace_output: bool) -> None:
    if path.exists() and not replace_output:
        raise FileExistsError(f"refusing to replace {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def run_production_recovery(
    checkpoint_path: Path,
    execution_cache_path: Path,
    composition_manifest_path: Path,
    *,
    workers: int,
    leaf_batch: int,
    replace_checkpoint: bool,
    replace_outputs: bool,
    progress: Callable[[str], None] | None,
) -> dict[str, object]:
    for path in (execution_cache_path, composition_manifest_path):
        if path.exists() and not replace_outputs:
            raise FileExistsError(f"refusing to replace {path}")
    preflight = build_preflight_manifest()
    if not preflight["claim_boundary"][
        "production_composer_checkpoint_recovery_gate_closed"
    ]:
        raise ValueError("composer recovery preflight gate is not frozen")
    parameters = cap.PRODUCTION_PARAMETERS
    randomness = cap.deterministic_randomness(
        parameters, composer.FROZEN_RANDOMNESS_LABEL
    )
    result = build_checkpointed_execution(
        parameters,
        randomness,
        checkpoint_path,
        workers=workers,
        leaf_batch=leaf_batch,
        replace_checkpoint=replace_checkpoint,
        progress=progress,
    )
    document = composer.build_linked_document(result.summary, randomness)
    failures = composer.validate_linked_document(
        document, execution=result.summary.execution
    )
    if failures:
        raise ValueError("recovered composition rejected: " + ",".join(failures))
    document["mutation_probes"] = composer.mutation_probes(
        document, result.summary.execution
    )
    encoded = composer.canonical_json(document)
    document_sha256 = hashlib.sha256(encoded).hexdigest()
    if document_sha256 != composer.FROZEN_DOCUMENT_SHA256:
        raise ValueError("recovered composition document identity mismatch")
    _atomic_bytes(
        composition_manifest_path,
        encoded,
        replace_output=replace_outputs,
    )
    _atomic_pickle(
        execution_cache_path,
        result.summary,
        replace_output=replace_outputs,
    )
    preflight["production_recovery"] = {
        "status": "complete",
        "checkpoint_path": str(checkpoint_path),
        "checkpoint_bytes": checkpoint_path.stat().st_size,
        "checkpoint_state_sha256": result.checkpoint_state_sha256,
        "execution_cache_path": str(execution_cache_path),
        "execution_cache_bytes": execution_cache_path.stat().st_size,
        "execution_cache_sha256": _sha256_file(execution_cache_path),
        "composition_manifest_path": str(composition_manifest_path),
        "composition_document_sha256": document_sha256,
        "resumed_checkpoint": result.resumed_checkpoint,
        "checkpoints_written_this_run": result.checkpoints_written,
        "production_execution_cache_regenerated": True,
        "production_composition_document_revalidated": True,
        "production_global_tail_archive_regenerated": False,
        "production_tree2_rebased_archive_regenerated": False,
    }
    preflight["claim_boundary"]["production_execution_cache_regenerated"] = True
    return preflight


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--execution-cache", type=Path)
    parser.add_argument("--composition-manifest", type=Path)
    parser.add_argument("--workers", type=int, default=max(1, min(8, os.cpu_count() or 1)))
    parser.add_argument("--leaf-batch", type=int, default=DEFAULT_LEAF_BATCH)
    parser.add_argument("--replace-checkpoint", action="store_true")
    parser.add_argument("--replace-outputs", action="store_true")
    args = parser.parse_args()
    production_arguments = (
        args.checkpoint,
        args.execution_cache,
        args.composition_manifest,
    )
    if any(item is not None for item in production_arguments) and not all(
        item is not None for item in production_arguments
    ):
        parser.error(
            "--checkpoint, --execution-cache, and --composition-manifest "
            "must be supplied together"
        )
    if args.checkpoint is None:
        document = build_preflight_manifest()
    else:
        document = run_production_recovery(
            args.checkpoint,
            args.execution_cache,
            args.composition_manifest,
            workers=args.workers,
            leaf_batch=args.leaf_batch,
            replace_checkpoint=args.replace_checkpoint,
            replace_outputs=args.replace_outputs,
            progress=lambda message: print(message, flush=True),
        )
    args.manifest.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "manifest": str(args.manifest),
                "production_recovery_status": document["production_recovery"][
                    "status"
                ],
                "checkpoint_gate_closed": document["claim_boundary"][
                    "production_composer_checkpoint_recovery_gate_closed"
                ],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
