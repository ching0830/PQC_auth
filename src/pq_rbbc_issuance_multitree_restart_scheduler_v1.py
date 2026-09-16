#!/usr/bin/env python3
"""Bounded multi-tree scheduler over the one-tree restart API.

Only tree indices 0 and 1 of the four-leaf, degree-three
INSECURE-TEST-ONLY fixture are executable.  Every tree has a distinct direct-
child output directory, one-tree journal, input/result-root identity, and fresh
cache identity.  The scheduler never evaluates or rewrites the tree-post
relation: execution and completed-result capture go exclusively through the
existing one-tree restart API.

The scheduler journal is append-only and plan ordered.  Worker completion order
is deliberately not serialized.  No global-tail continuation, parent output,
production legacy18 provider, or production durability claim is provided.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import MappingProxyType
from typing import Mapping, Sequence

import pq_rbbc_cap_tree_producer as tree
import pq_rbbc_issuance_private_spool_handoff_v1 as handoff
import pq_rbbc_issuance_tree_post_continuation_v1 as continuation
import pq_rbbc_issuance_tree_post_restart_v1 as restart
import pq_rbbc_launch_io_v2_41 as io
import pq_rbbc_recovery_io_v2_42 as disk


ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION_VERSION = "1.2"
FORMAT = "PQRBBC-ISSUANCE-MULTITREE-RESTART-SCHEDULER-1"
PLAN_FORMAT = FORMAT + "-EXECUTION-PLAN"
RELATION_ID = (
    "pq-rbbc/issuance/multitree-restart-scheduler/"
    "tree0-tree1-4leaf-insecure-test-only/v1"
)
MODE = "INSECURE-TEST-ONLY"
ORDERED_TREE_INDICES = (0, 1)
SCHEDULING_MODES = ("sequential", "bounded-parallel")
CONCURRENCY_LIMIT = 2
SCHEDULER_JOURNAL_DIRECTORY = "scheduler-journal"
PLAN_NAME = "0000-execution-plan.private.json"
INPUTS_COMMITTED_NAME = "0001-tree-inputs-committed.private.json"
TREE_CHECKPOINT_NAMES = (
    "0002-tree-0-result-committed.private.json",
    "0003-tree-1-result-committed.private.json",
)
COMPLETE_NAME = "complete.private.json"
SCHEDULER_JOURNAL_NAMES = (
    PLAN_NAME,
    INPUTS_COMMITTED_NAME,
    *TREE_CHECKPOINT_NAMES,
    COMPLETE_NAME,
)
CHECKPOINT_LIMIT = 64 * 1024
DOMAIN_PLAN = b"PQ-RBBC/ISSUANCE/MULTITREE-RESTART-SCHEDULER/PLAN/V1"
DOMAIN_INPUT_ROOT = b"PQ-RBBC/ISSUANCE/MULTITREE-RESTART-SCHEDULER/INPUT-ROOT/V1"
DOMAIN_RESULT_ROOT = b"PQ-RBBC/ISSUANCE/MULTITREE-RESTART-SCHEDULER/RESULT-ROOT/V1"
DOMAIN_CACHE = b"PQ-RBBC/ISSUANCE/MULTITREE-RESTART-SCHEDULER/FRESH-CACHE/V1"
MANIFEST_PATH = (
    "manifests/pq_rbbc_issuance_multitree_restart_scheduler_v1.json"
)
EVIDENCE_PATH = (
    "artifacts/metadata/issuance_multitree_restart_scheduler_v1/"
    "pq_rbbc_issuance_multitree_restart_scheduler_v1.json"
)

PREDECESSOR_PINS = {
    "src/pq_rbbc_issuance_tree_post_restart_v1.py": (
        51_763,
        "96876c8060971dfafdb5c844f83055af48b5d67357705a561755d8bebb20473e",
    ),
    "tests/test_pq_rbbc_issuance_tree_post_restart_v1.py": (
        24_086,
        "ad10d878ff5cf79d0f05c40a8261c1f34073162cbcafc5392a9bd6c5e06ec593",
    ),
    restart.MANIFEST_PATH: (
        7_559,
        "ec87e2d3b42f6c2982596ef48060fd94bb2656fc7e7aec864bdecb21f28c8321",
    ),
    restart.EVIDENCE_PATH: (
        2_526,
        "682b064316f06bb08d0db10e03e41d85394d823de1978915f801486e850de45f",
    ),
}

HANDOFF_IDENTITY = {
    "filename": handoff.HANDOFF_NAME,
    "bytes": 1_035,
    "sha256": "ff95140fe4fc0a34ab41360553ae7bdb0f3bb93b2c1537f5742810da572d0c8d",
}
CONTINUATION_IDENTITIES = (
    {
        "filename": continuation.CONTINUATION_NAMES[0],
        "bytes": 3_829,
        "sha256": "d68382b393f66e6fcd1374985aa2f70d9d39c7a092756ac9bd954810bbba2bc9",
    },
    {
        "filename": continuation.CONTINUATION_NAMES[1],
        "bytes": 3_835,
        "sha256": "d2f6bcaad813ae59ebd200512d37fbaae8afcdc604b534009f8d84949c6bdc72",
    },
)
RECEIPT_SUFFIX_IDENTITIES = (
    {
        "filename": continuation.PRIOR_RECEIPT_NAME,
        "bytes": 1_306,
        "sha256": "29a0768e66e15ec989a0b44c98c500688618ec96683b7a171725670d6e14c523",
    },
    {
        "filename": handoff.RECEIPT_NAME,
        "bytes": 1_365,
        "sha256": "0573e1b7fb340fcffce9d6cc6f90b3e2c4c2e43e00b6faa59ad528d0f0f427dc",
    },
)
EXPECTED_PRIVATE_RESULTS = (
    {
        "filename": restart.RESULT_NAMES[0],
        "bytes": 121_721,
        "sha256": "c250a462e1202c90a52fbf879270bd1a9d18592cfe1903be36a66f9b352a507c",
    },
    {
        "filename": restart.RESULT_NAMES[1],
        "bytes": 121_724,
        "sha256": "613a8516075fc38582d0d197832d980ed65a552f3b02bbdbe602c040f3c892ff",
    },
)
EXPECTED_RECEIPTS = (
    {
        "filename": restart.RECEIPT_NAMES[0],
        "bytes": 2_821,
        "sha256": "1097dee376f9e3a338362e6b74168f3e1e7ac8f772df13408fe0da785b45203c",
    },
    {
        "filename": restart.RECEIPT_NAMES[1],
        "bytes": 2_824,
        "sha256": "99fd35afa855c184c4dfe482067bb8e77f921cab8a84673ad1b7650ef380a970",
    },
)
EXPECTED_CHILD_CHECKPOINT_CHAINS = (
    (
        {
            "filename": restart.PLAN_NAME,
            "bytes": 1_709,
            "sha256": "72f97271f5383f13dfc939b2e9f418a478d3b4b767abadcb51c663df61f1b8da",
        },
        {
            "filename": restart.INPUTS_COMMITTED_NAME,
            "bytes": 1_534,
            "sha256": "e136e95d7607a4e2a15bd6c5cd6192ab93e0b2e753231ea0cd0264decd073359",
        },
        {
            "filename": restart.RESULT_COMMITTED_NAME,
            "bytes": 1_076,
            "sha256": "33c22ef8592a23a1823a01247f84bdbd485224b1f5ceb53cbdba5d4c34abb5d8",
        },
        {
            "filename": restart.COMPLETE_NAME,
            "bytes": 1_218,
            "sha256": "fe2ebf511ad1c6c21a7d823c7b8990de41df1a08e93a6eed40ad3b226b11e1fb",
        },
    ),
    (
        {
            "filename": restart.PLAN_NAME,
            "bytes": 1_711,
            "sha256": "d4818580196665561a0c37307e826c63aa1e03a83ace87664579da13528dfcbe",
        },
        {
            "filename": restart.INPUTS_COMMITTED_NAME,
            "bytes": 1_534,
            "sha256": "1f9f9348a8e7eb665f5a98e4a44088c76c29e01bbbe46e4d29cf126c9dd76838",
        },
        {
            "filename": restart.RESULT_COMMITTED_NAME,
            "bytes": 1_076,
            "sha256": "92df150b66b75120e90ee6f001a29d95d35cdfd21930bc0beda5fdb8970facad",
        },
        {
            "filename": restart.COMPLETE_NAME,
            "bytes": 1_218,
            "sha256": "9c227c3628a36b1175984b108c19d5c66d873c9ddbf3f6b52b7d9981b92dfd1a",
        },
    ),
)
EXPECTED_OUTPUT_PORTS = (
    {
        "port_id": "tree[0].xi-masks",
        "wire_start": 81_953,
        "bit_length": 1_158,
        "value_sha256": "656b0e3b5581173be60d6c4ac9708305e62d042ebbd498931db5c738fc6a4bb1",
    },
    {
        "port_id": "tree[1].xi-masks",
        "wire_start": 121_227,
        "bit_length": 1_158,
        "value_sha256": "6b08050b295a420c497ccaa0dacc5da2a4b220331fe804170ec9e9df524fdb32",
    },
)


class SchedulerError(ValueError):
    """A plan, scheduler checkpoint, child result, or schedule was rejected."""


class ProductionUnavailable(RuntimeError):
    """This bounded scheduler intentionally exposes no production execution."""


@dataclass(frozen=True)
class SchedulerResultInsecureTestOnly:
    ordered_results: tuple[restart.PublishedTreePostResultInsecureTestOnly, ...]
    execution_plan: io.Snapshot
    complete_checkpoint: io.Snapshot
    adopted_orphan_tree_indices: tuple[int, ...]


def canonical_json(document: object) -> bytes:
    return io.canonical_json(document)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _domain_digest(domain: bytes, document: object) -> str:
    return sha256(domain + len(domain).to_bytes(2, "big") + canonical_json(document))


def _is_int(value: object) -> bool:
    return type(value) is int


def _digest(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SchedulerError(label + " must be a lowercase SHA-256")
    return value


def _snapshot(name: str, raw: bytes) -> io.Snapshot:
    if type(raw) is not bytes or not 0 < len(raw) <= CHECKPOINT_LIMIT:
        raise SchedulerError("scheduler checkpoint byte bound")
    return io.Snapshot(Path("/in-memory-insecure-test-only") / name, raw)


def _root_identities(index: int) -> tuple[str, str, str]:
    input_root = _domain_digest(
        DOMAIN_INPUT_ROOT,
        {
            "relation_id": RELATION_ID,
            "tree_index": index,
            "handoff": HANDOFF_IDENTITY,
            "continuation": CONTINUATION_IDENTITIES[index],
            "verified_receipt_suffix": list(RECEIPT_SUFFIX_IDENTITIES),
        },
    )
    result_root = _domain_digest(
        DOMAIN_RESULT_ROOT,
        {
            "relation_id": RELATION_ID,
            "tree_index": index,
            "private_input_root_identity_sha256": input_root,
            "private_result": EXPECTED_PRIVATE_RESULTS[index],
            "receipt": EXPECTED_RECEIPTS[index],
            "complete_checkpoint": EXPECTED_CHILD_CHECKPOINT_CHAINS[index][-1],
            "output_port": EXPECTED_OUTPUT_PORTS[index],
        },
    )
    cache = _domain_digest(
        DOMAIN_CACHE,
        {
            "relation_id": RELATION_ID,
            "tree_index": index,
            "private_input_root_identity_sha256": input_root,
            "continuation_sha256": CONTINUATION_IDENTITIES[index]["sha256"],
        },
    )
    return input_root, result_root, cache


def _tree_descriptor(index: int) -> dict[str, object]:
    input_root, result_root, cache = _root_identities(index)
    return {
        "tree_index": index,
        "order_position": index,
        "output_directory_suffix": f".tree-{index}",
        "source_restart_relation_id": restart.RELATION_ID,
        "handoff_identity": HANDOFF_IDENTITY,
        "continuation_identity": CONTINUATION_IDENTITIES[index],
        "verified_receipt_suffix_identities": list(RECEIPT_SUFFIX_IDENTITIES),
        "private_input_root_identity_sha256": input_root,
        "private_result_root_identity_sha256": result_root,
        "fresh_cache_identity_sha256": cache,
        "fresh_cache_required": True,
        "writable_cache_materialized": False,
        "resume_state_scope": f"tree-{index}-output/journal",
        "observed_stream_bytes": None,
        "output_port": EXPECTED_OUTPUT_PORTS[index],
        "expected_private_result_identity": EXPECTED_PRIVATE_RESULTS[index],
        "expected_receipt_identity": EXPECTED_RECEIPTS[index],
        "dependency_checkpoint_chain": [
            {
                "role": role,
                "identity": identity,
            }
            for role, identity in zip(
                (
                    "one-tree-publication-plan",
                    "one-tree-inputs-committed",
                    "one-tree-result-committed",
                    "one-tree-complete",
                ),
                EXPECTED_CHILD_CHECKPOINT_CHAINS[index],
            )
        ],
    }


EXECUTION_PLAN_DOCUMENT: dict[str, object] = {
    "format": PLAN_FORMAT,
    "implementation_version": IMPLEMENTATION_VERSION,
    "plan_version": 1,
    "execution_domain_hex": DOMAIN_PLAN.hex(),
    "mode": MODE,
    "relation_id": RELATION_ID,
    "source_restart_relation_id": restart.RELATION_ID,
    "profile_fingerprint": continuation.PROFILE_FINGERPRINT,
    "ordered_tree_indices": list(ORDERED_TREE_INDICES),
    "receipt_contract": {
        "verified_suffix_ordinals": [2, 3],
        "verified_receipt_suffix_identities": list(RECEIPT_SUFFIX_IDENTITIES),
        "verified_link": "ordinal-2-raw-sha256-to-ordinal-3-previous_receipt_sha256",
        "full_receipt_chain_verified": False,
    },
    "trees": [_tree_descriptor(index) for index in ORDERED_TREE_INDICES],
    "dependency_order": [
        "execution-plan",
        "all-tree-inputs-committed",
        "tree-results-in-plan-order",
        "scheduler-complete",
    ],
    "checkpoint_chain": list(SCHEDULER_JOURNAL_NAMES),
    "scheduling": {
        "allowed_modes": list(SCHEDULING_MODES),
        "concurrency_limit": CONCURRENCY_LIMIT,
        "result_order": "execution-plan-order-not-worker-completion-order",
    },
    "resource_budget": {
        "per_tree_max_rows": 300_000,
        "per_tree_max_wires": 200_000,
        "per_tree_private_result_max_bytes": restart.RESULT_LIMIT,
        "per_tree_planned_memory_mib": 512,
        "per_tree_planned_seconds": 240,
        "parallel_memory_ceiling_mib": 1_024,
        "scheduler_checkpoint_max_bytes": CHECKPOINT_LIMIT,
        "production_estimate": None,
    },
    "isolation": {
        "independent_output_directory_per_tree": True,
        "independent_journal_per_tree": True,
        "distinct_fresh_cache_identity_per_tree": True,
        "shared_writable_cache_permitted": False,
        "shared_resume_state_permitted": False,
        "shared_observed_stream_bytes_permitted": False,
    },
    "outputs": {
        "ordered_tree_post_results_only": True,
        "global_tail_output_created": False,
        "parent_output_created": False,
    },
    "production": False,
}


def execution_plan_snapshot() -> io.Snapshot:
    return _snapshot(PLAN_NAME, canonical_json(EXECUTION_PLAN_DOCUMENT))


def _inputs_checkpoint_document(plan: io.Snapshot) -> dict[str, object]:
    return {
        "format": FORMAT + "-TREE-INPUTS-COMMITTED",
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "stage": "all-tree-inputs-committed",
        "ordinal": 1,
        "previous_checkpoint_sha256": plan.identity["sha256"],
        "execution_plan": plan.identity,
        "ordered_tree_input_checkpoints": [
            {
                "tree_index": descriptor["tree_index"],
                "private_input_root_identity_sha256": descriptor[
                    "private_input_root_identity_sha256"
                ],
                "fresh_cache_identity_sha256": descriptor[
                    "fresh_cache_identity_sha256"
                ],
                "checkpoint": descriptor["dependency_checkpoint_chain"][1][
                    "identity"
                ],
            }
            for descriptor in EXECUTION_PLAN_DOCUMENT["trees"]
        ],
        "restartable_boundary_reached": True,
        "complete": False,
        "production": False,
    }


def _tree_checkpoint_document(
    position: int, previous: io.Snapshot, plan: io.Snapshot
) -> dict[str, object]:
    descriptor = EXECUTION_PLAN_DOCUMENT["trees"][position]
    return {
        "format": FORMAT + "-TREE-RESULT-COMMITTED",
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "stage": f"tree-result[{position}]",
        "ordinal": position + 2,
        "previous_checkpoint_sha256": previous.identity["sha256"],
        "execution_plan_sha256": plan.identity["sha256"],
        "order_position": position,
        "tree_index": descriptor["tree_index"],
        "private_input_root_identity_sha256": descriptor[
            "private_input_root_identity_sha256"
        ],
        "private_result_root_identity_sha256": descriptor[
            "private_result_root_identity_sha256"
        ],
        "fresh_cache_identity_sha256": descriptor["fresh_cache_identity_sha256"],
        "child_complete_checkpoint": descriptor["dependency_checkpoint_chain"][3][
            "identity"
        ],
        "private_result_identity": descriptor["expected_private_result_identity"],
        "receipt_identity": descriptor["expected_receipt_identity"],
        "output_port": descriptor["output_port"],
        "completion_order_serialized": False,
        "global_tail_output_created": False,
        "parent_output_created": False,
        "complete": False,
        "production": False,
    }


def _expected_scheduler_journal() -> tuple[io.Snapshot, ...]:
    plan = execution_plan_snapshot()
    snapshots = [plan]
    inputs = _snapshot(
        INPUTS_COMMITTED_NAME, canonical_json(_inputs_checkpoint_document(plan))
    )
    snapshots.append(inputs)
    previous = inputs
    for position, name in enumerate(TREE_CHECKPOINT_NAMES):
        checkpoint = _snapshot(
            name, canonical_json(_tree_checkpoint_document(position, previous, plan))
        )
        snapshots.append(checkpoint)
        previous = checkpoint
    complete_document = {
        "format": FORMAT + "-COMPLETE",
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "stage": "scheduler-complete",
        "ordinal": 4,
        "previous_checkpoint_sha256": previous.identity["sha256"],
        "execution_plan": plan.identity,
        "ordered_tree_result_checkpoints": [
            snapshots[position + 2].identity
            for position in range(len(ORDERED_TREE_INDICES))
        ],
        "ordered_tree_indices": list(ORDERED_TREE_INDICES),
        "ordered_private_result_root_identities": [
            descriptor["private_result_root_identity_sha256"]
            for descriptor in EXECUTION_PLAN_DOCUMENT["trees"]
        ],
        "result_order": "execution-plan-order-not-worker-completion-order",
        "global_tail_continuation_implemented": False,
        "global_tail_output_created": False,
        "parent_output_created": False,
        "production_legacy18_provider_implemented": False,
        "production_durable_resume_implemented": False,
        "complete": True,
        "production": False,
    }
    snapshots.append(_snapshot(COMPLETE_NAME, canonical_json(complete_document)))
    return tuple(snapshots)


EXPECTED_SCHEDULER_JOURNAL = _expected_scheduler_journal()
FROZEN = {
    "execution_plan_identity": EXPECTED_SCHEDULER_JOURNAL[0].identity,
    "scheduler_complete_checkpoint_identity": EXPECTED_SCHEDULER_JOURNAL[-1].identity,
    "ordered_tree_indices": list(ORDERED_TREE_INDICES),
    "private_result_identities": list(EXPECTED_PRIVATE_RESULTS),
    "child_complete_checkpoint_identities": [
        chain[-1] for chain in EXPECTED_CHILD_CHECKPOINT_CHAINS
    ],
    "sequential_parallel_artifacts_byte_identical": True,
    "sequential_parallel_ordered_results_byte_identical": True,
    "result_order_matches_plan": True,
    "completed_child_dependency_durability_order_qualified_by_tests": True,
    "closed_world_parent_and_child_inventories_qualified_by_tests": True,
    "verified_receipt_suffix_ordinals": [2, 3],
    "full_receipt_chain_verified": False,
    "receipt_suffix_validation_before_scheduler_publication": True,
}


def validate_prerequisites() -> None:
    restart.validate_prerequisites()
    for path, (size, digest) in PREDECESSOR_PINS.items():
        snapshot = io.read_snapshot(ROOT / path)
        if (len(snapshot.raw), sha256(snapshot.raw)) != (size, digest):
            raise SchedulerError("one-tree predecessor identity drift: " + path)


def _validate_invocations(
    invocations: Sequence[continuation.TreePostInvocationInsecureTestOnly],
) -> tuple[continuation.TreePostInvocationInsecureTestOnly, ...]:
    if type(invocations) not in (tuple, list) or len(invocations) != 2:
        raise SchedulerError("exactly two ordered bounded tree invocations required")
    checked = []
    for position, invocation in enumerate(invocations):
        if type(invocation) is not continuation.TreePostInvocationInsecureTestOnly:
            raise SchedulerError("one-tree restart invocation type required")
        if invocation.candidates.handoff.identity != HANDOFF_IDENTITY:
            raise SchedulerError("bounded handoff identity mismatch")
        if invocation.continuation.identity != CONTINUATION_IDENTITIES[position]:
            raise SchedulerError("continuation identity or tree order mismatch")
        if tuple(snapshot.identity for snapshot in invocation.receipt_suffix) != (
            RECEIPT_SUFFIX_IDENTITIES
        ):
            raise SchedulerError("verified receipt suffix identity mismatch")
        try:
            continuation._continuation_document(
                invocation,
                expected_handoff_sha256=HANDOFF_IDENTITY["sha256"],
                expected_continuation_sha256=CONTINUATION_IDENTITIES[position][
                    "sha256"
                ],
            )
        except continuation.ContinuationError as error:
            raise SchedulerError(
                "tree continuation or verified receipt suffix rejected"
            ) from error
        checked.append(invocation)
    if len({item["sha256"] for item in CONTINUATION_IDENTITIES}) != 2:
        raise SchedulerError("continuation identities must be distinct")
    cache_identities = {
        descriptor["fresh_cache_identity_sha256"]
        for descriptor in EXECUTION_PLAN_DOCUMENT["trees"]
    }
    if len(cache_identities) != 2:
        raise SchedulerError("fresh cache identities must be distinct")
    return tuple(checked)


def build_execution_plan(
    invocations: Sequence[continuation.TreePostInvocationInsecureTestOnly],
) -> io.Snapshot:
    """Validate the two immutable one-tree inputs and return the frozen plan."""
    _validate_invocations(invocations)
    return execution_plan_snapshot()


def _validate_plan(snapshot: io.Snapshot) -> dict[str, object]:
    expected = execution_plan_snapshot()
    if (
        type(snapshot) is not io.Snapshot
        or snapshot.location.name != PLAN_NAME
        or snapshot.raw != expected.raw
    ):
        raise SchedulerError("canonical execution plan identity or bytes mismatch")
    try:
        document = snapshot.document()
    except io.ValidationError as error:
        raise SchedulerError("execution plan is not strict canonical JSON") from error
    return document


def _names(path: Path) -> set[str]:
    with io.directory_fd(path, external=True) as descriptor:
        names = set(os.listdir(descriptor))
        io._same_directory(path, descriptor, external=True)
        return names


def _journal_shape(names: set[str]) -> tuple[str, ...]:
    if not names or names - set(SCHEDULER_JOURNAL_NAMES):
        raise SchedulerError("unknown or empty scheduler journal")
    ordered = tuple(name for name in SCHEDULER_JOURNAL_NAMES if name in names)
    if ordered != SCHEDULER_JOURNAL_NAMES[: len(ordered)]:
        raise SchedulerError("scheduler journal is not a contiguous checkpoint prefix")
    return ordered


def latest_scheduler_checkpoint(
    output: Path, *, artifact_root: Path
) -> io.Snapshot:
    root = io.ArtifactRoot(artifact_root)
    output = root.require_location(output)
    if output.parent != root.root:
        raise SchedulerError("scheduler output must be a direct child of trusted root")
    root.require_location(output / SCHEDULER_JOURNAL_DIRECTORY / COMPLETE_NAME)
    ordered = _journal_shape(_names(output / SCHEDULER_JOURNAL_DIRECTORY))
    return disk.read(output / SCHEDULER_JOURNAL_DIRECTORY / ordered[-1])


def _capture_scheduler_journal(
    output: Path, latest: io.Snapshot | None = None
) -> dict[str, io.Snapshot]:
    ordered = _journal_shape(_names(output / SCHEDULER_JOURNAL_DIRECTORY))
    captured = {}
    for name in ordered:
        path = output / SCHEDULER_JOURNAL_DIRECTORY / name
        captured[name] = latest if latest is not None and latest.location == path else disk.read(path)
    return captured


def _validate_scheduler_journal(
    journal: Mapping[str, io.Snapshot], *, require_restartable: bool
) -> tuple[io.Snapshot, ...]:
    ordered = tuple(journal)
    if require_restartable and len(ordered) < 2:
        raise SchedulerError(
            "incomplete multi-tree input publication; use a new trusted scheduler root"
        )
    expected = EXPECTED_SCHEDULER_JOURNAL[: len(ordered)]
    if ordered != tuple(item.location.name for item in expected):
        raise SchedulerError("scheduler checkpoint order mismatch")
    for actual, wanted in zip(journal.values(), expected):
        if actual.location.name != wanted.location.name or actual.raw != wanted.raw:
            raise SchedulerError("scheduler checkpoint chain or exact bytes mismatch")
        try:
            actual.document()
        except io.ValidationError as error:
            raise SchedulerError("scheduler checkpoint is not canonical") from error
    return expected


def _tree_output(output: Path, index: int) -> Path:
    return output.with_name(output.name + f".tree-{index}")


def _validate_scheduler_output_inventory(output: Path) -> None:
    if _names(output) != {SCHEDULER_JOURNAL_DIRECTORY}:
        raise SchedulerError("unknown or missing scheduler output component")


def _scoped_tree_output_names(output: Path, artifact_root: Path) -> set[str]:
    prefix = output.name + ".tree-"
    return {name for name in _names(artifact_root) if name.startswith(prefix)}


def _validate_tree_output_inventory(
    output: Path, artifact_root: Path, *, require_all: bool
) -> None:
    expected = {_tree_output(output, index).name for index in ORDERED_TREE_INDICES}
    actual = _scoped_tree_output_names(output, artifact_root)
    if actual - expected:
        raise SchedulerError("unknown tree output directory")
    if require_all and actual != expected:
        raise SchedulerError("missing tree output directory after inputs checkpoint")


def _validate_child_result(
    result: restart.PublishedTreePostResultInsecureTestOnly,
    descriptor: Mapping[str, object],
) -> None:
    index = int(descriptor["tree_index"])
    output = {
        "port_id": result.output_port.port_id,
        "wire_start": result.output_port.wire_start,
        "bit_length": result.output_port.bit_length,
        "value_sha256": result.output_port.value_sha256,
    }
    result_root = _domain_digest(
        DOMAIN_RESULT_ROOT,
        {
            "relation_id": RELATION_ID,
            "tree_index": index,
            "private_input_root_identity_sha256": descriptor[
                "private_input_root_identity_sha256"
            ],
            "private_result": result.result.identity,
            "receipt": result.receipt.identity,
            "complete_checkpoint": result.complete_checkpoint.identity,
            "output_port": output,
        },
    )
    if (
        result.tree_index != index
        or result.result.identity != descriptor["expected_private_result_identity"]
        or result.receipt.identity != descriptor["expected_receipt_identity"]
        or result.complete_checkpoint.identity
        != descriptor["dependency_checkpoint_chain"][3]["identity"]
        or output != descriptor["output_port"]
        or result_root != descriptor["private_result_root_identity_sha256"]
    ):
        raise SchedulerError("one-tree result or private result-root identity mismatch")


def _validate_child_root_inventory(child: Path) -> None:
    if _names(child) != {
        restart.INPUT_DIRECTORY,
        restart.RESULT_DIRECTORY,
        restart.JOURNAL_DIRECTORY,
    }:
        raise SchedulerError("unknown or missing one-tree output component")


def _validate_completed_child_inventory(child: Path, index: int) -> None:
    _validate_child_root_inventory(child)
    if _names(child / restart.RESULT_DIRECTORY) != {
        restart.RESULT_NAMES[index],
        restart.RECEIPT_NAMES[index],
    }:
        raise SchedulerError("missing or unknown completed one-tree result")


def _sync_completed_child_dependencies(child: Path, artifact_root: Path) -> None:
    """Make validated child dependencies durable before a parent checkpoint."""
    with (
        io.directory_fd(child / restart.INPUT_DIRECTORY, external=True) as input_fd,
        io.directory_fd(child / restart.RESULT_DIRECTORY, external=True) as result_fd,
        io.directory_fd(child / restart.JOURNAL_DIRECTORY, external=True) as journal_fd,
        io.directory_fd(child, external=True) as child_fd,
        io.directory_fd(artifact_root, external=True) as root_fd,
    ):
        disk.sync_directory(child / restart.INPUT_DIRECTORY, input_fd)
        disk.sync_directory(child / restart.RESULT_DIRECTORY, result_fd)
        disk.sync_directory(child / restart.JOURNAL_DIRECTORY, journal_fd)
        disk.sync_directory(child, child_fd)
        disk.sync_directory(artifact_root, root_fd)


def _complete_or_adopt_tree(
    output: Path,
    artifact_root: Path,
    descriptor: Mapping[str, object],
) -> tuple[restart.PublishedTreePostResultInsecureTestOnly, bool]:
    index = int(descriptor["tree_index"])
    child = _tree_output(output, index)
    _validate_child_root_inventory(child)
    latest = restart.latest_checkpoint(child, artifact_root=artifact_root)
    chain = descriptor["dependency_checkpoint_chain"]
    allowed = [item["identity"]["sha256"] for item in chain]
    if latest.identity["sha256"] not in allowed:
        raise SchedulerError("stale, wrong, or unknown one-tree checkpoint")
    complete_sha = chain[-1]["identity"]["sha256"]
    adopted = latest.identity["sha256"] == complete_sha
    if adopted:
        _validate_completed_child_inventory(child, index)
        result = restart.capture_completed_result(
            child,
            artifact_root=artifact_root,
            expected_complete_sha256=complete_sha,
        )
    else:
        result = restart.run_bounded_tree_post(
            child,
            artifact_root=artifact_root,
            resume=True,
            expected_checkpoint_sha256=latest.identity["sha256"],
        )
        if result is None:
            raise SchedulerError("one-tree restart did not complete")
    _validate_child_result(result, descriptor)
    _validate_completed_child_inventory(child, index)
    _sync_completed_child_dependencies(child, artifact_root)
    return result, adopted


def _publish_expected_checkpoint(output: Path, expected: io.Snapshot) -> io.Snapshot:
    path = output / SCHEDULER_JOURNAL_DIRECTORY / expected.location.name
    try:
        existing = disk.read(path)
    except FileNotFoundError:
        disk.publish(path, expected.raw)
        return io.Snapshot(path, expected.raw)
    if existing.raw != expected.raw:
        raise SchedulerError("existing scheduler checkpoint differs from exact plan chain")
    with io.directory_fd(path.parent, external=True) as descriptor:
        disk.sync_directory(path.parent, descriptor)
    return existing


def _initialize_tree_inputs(
    output: Path,
    artifact_root: Path,
    invocations: Sequence[continuation.TreePostInvocationInsecureTestOnly],
) -> None:
    for position, invocation in enumerate(invocations):
        descriptor = EXECUTION_PLAN_DOCUMENT["trees"][position]
        child = _tree_output(output, position)
        restart.run_bounded_tree_post(
            child,
            artifact_root=artifact_root,
            fresh_invocation=invocation,
            expected_handoff_sha256=HANDOFF_IDENTITY["sha256"],
            expected_continuation_sha256=CONTINUATION_IDENTITIES[position]["sha256"],
            fresh_output=True,
            stop_after="inputs",
        )
        latest = restart.latest_checkpoint(child, artifact_root=artifact_root)
        if latest.identity != descriptor["dependency_checkpoint_chain"][1]["identity"]:
            raise SchedulerError("one-tree inputs checkpoint differs from execution plan")


def _ordered_results_bytes(
    results: Sequence[restart.PublishedTreePostResultInsecureTestOnly],
) -> tuple[tuple[bytes, bytes, bytes], ...]:
    return tuple(
        (item.result.raw, item.receipt.raw, item.complete_checkpoint.raw)
        for item in results
    )


def run_bounded_scheduler(
    output: Path,
    *,
    artifact_root: Path,
    fresh_invocations: Sequence[
        continuation.TreePostInvocationInsecureTestOnly
    ] | None = None,
    fresh_output: bool = False,
    resume: bool = False,
    expected_checkpoint_sha256: str | None = None,
    scheduling_mode: str = "sequential",
    stop_after_inputs: bool = False,
    stop_after_child_tree: int | None = None,
    stop_after_tree_checkpoint: int | None = None,
) -> SchedulerResultInsecureTestOnly | None:
    """Run or resume the bounded scheduler through the one-tree restart API.

    ``stop_after_*`` controls bounded crash-window tests.  A resumable caller
    supplies the exact latest scheduler checkpoint digest; that digest is
    checked before any tree output, input, journal, or relation work is read.
    """
    validate_prerequisites()
    if type(fresh_output) is not bool or type(resume) is not bool or fresh_output == resume:
        raise SchedulerError("select exactly one of fresh_output or resume")
    if scheduling_mode not in SCHEDULING_MODES:
        raise SchedulerError("unknown scheduling mode")
    if type(stop_after_inputs) is not bool:
        raise SchedulerError("stop_after_inputs must be bool")
    for label, value in (
        ("stop_after_child_tree", stop_after_child_tree),
        ("stop_after_tree_checkpoint", stop_after_tree_checkpoint),
    ):
        if value is not None and (not _is_int(value) or value not in ORDERED_TREE_INDICES):
            raise SchedulerError(label + " must select tree 0 or 1")
    if stop_after_child_tree is not None and scheduling_mode != "sequential":
        raise SchedulerError("child-before-parent stop is sequential-only")
    if fresh_output:
        if expected_checkpoint_sha256 is not None or fresh_invocations is None:
            raise SchedulerError("fresh scheduling requires ordered invocations only")
        invocations = _validate_invocations(fresh_invocations)
        plan = execution_plan_snapshot()
    else:
        if fresh_invocations is not None or stop_after_inputs:
            raise SchedulerError("resume accepts no live invocation or fresh-input stop")
        _digest(expected_checkpoint_sha256, "external scheduler checkpoint")
        invocations = ()
        plan = execution_plan_snapshot()

    output = io.exact_path(output)
    artifact_root = io.exact_path(artifact_root)
    with disk.locked_output(output, artifact_root, fresh=fresh_output) as output_fd:
        if fresh_output:
            os.mkdir(SCHEDULER_JOURNAL_DIRECTORY, mode=0o700, dir_fd=output_fd)
            os.fsync(output_fd)
            disk.publish(
                output / SCHEDULER_JOURNAL_DIRECTORY / PLAN_NAME,
                plan.raw,
            )
            _initialize_tree_inputs(output, artifact_root, invocations)
            _validate_tree_output_inventory(output, artifact_root, require_all=True)
            _publish_expected_checkpoint(output, EXPECTED_SCHEDULER_JOURNAL[1])

        latest = None
        if resume:
            latest = latest_scheduler_checkpoint(output, artifact_root=artifact_root)
            if latest.identity["sha256"] != expected_checkpoint_sha256:
                raise SchedulerError(
                    "scheduler checkpoint identity mismatch (including stale digest)"
                )
        _validate_scheduler_output_inventory(output)
        journal = _capture_scheduler_journal(output, latest)
        expected_prefix = _validate_scheduler_journal(
            journal, require_restartable=True
        )
        _validate_plan(journal[PLAN_NAME])
        _validate_tree_output_inventory(output, artifact_root, require_all=True)
        if stop_after_inputs:
            return None

        completed_count = min(
            len(ORDERED_TREE_INDICES), max(0, len(expected_prefix) - 2)
        )
        results: dict[int, restart.PublishedTreePostResultInsecureTestOnly] = {}
        adopted: list[int] = []

        for position in range(completed_count):
            descriptor = EXECUTION_PLAN_DOCUMENT["trees"][position]
            result, _ = _complete_or_adopt_tree(output, artifact_root, descriptor)
            results[position] = result

        pending_positions = list(range(completed_count, len(ORDERED_TREE_INDICES)))
        if scheduling_mode == "bounded-parallel" and pending_positions:
            if len(pending_positions) > CONCURRENCY_LIMIT:
                raise SchedulerError("execution plan concurrency limit exceeded")
            completed_workers = {}
            with ThreadPoolExecutor(max_workers=CONCURRENCY_LIMIT) as executor:
                futures = {
                    executor.submit(
                        _complete_or_adopt_tree,
                        output,
                        artifact_root,
                        EXECUTION_PLAN_DOCUMENT["trees"][position],
                    ): position
                    for position in pending_positions
                }
                for future in as_completed(futures):
                    position = futures[future]
                    completed_workers[position] = future.result()
            for position in pending_positions:
                result, was_adopted = completed_workers[position]
                results[position] = result
                if was_adopted:
                    adopted.append(position)
        else:
            for position in pending_positions:
                result, was_adopted = _complete_or_adopt_tree(
                    output,
                    artifact_root,
                    EXECUTION_PLAN_DOCUMENT["trees"][position],
                )
                results[position] = result
                if was_adopted:
                    adopted.append(position)
                if stop_after_child_tree == position:
                    return None

                # Sequential scheduling commits each completed tree before
                # starting the next one.  This is the qualified boundary where
                # tree 0 is complete while tree 1 remains at inputs-committed.
                checkpoint = _publish_expected_checkpoint(
                    output, EXPECTED_SCHEDULER_JOURNAL[position + 2]
                )
                journal[checkpoint.location.name] = checkpoint
                if stop_after_tree_checkpoint == position:
                    return None

        # Parent checkpoints are always published in plan order, never worker
        # completion order.  Existing prefix entries were validated above.
        if scheduling_mode == "bounded-parallel":
            for position in pending_positions:
                checkpoint = _publish_expected_checkpoint(
                    output, EXPECTED_SCHEDULER_JOURNAL[position + 2]
                )
                journal[checkpoint.location.name] = checkpoint
                if stop_after_tree_checkpoint == position:
                    return None

        complete = _publish_expected_checkpoint(
            output, EXPECTED_SCHEDULER_JOURNAL[-1]
        )
        journal[COMPLETE_NAME] = complete
        _validate_scheduler_journal(journal, require_restartable=True)
        ordered_results = tuple(results[position] for position in ORDERED_TREE_INDICES)
        if tuple(item.tree_index for item in ordered_results) != ORDERED_TREE_INDICES:
            raise SchedulerError("result ordering differs from execution plan")
        with io.directory_fd(artifact_root, external=True) as root_fd, \
                io.directory_fd(
                    output / SCHEDULER_JOURNAL_DIRECTORY, external=True
                ) as journal_fd:
            disk.sync_directory(
                output / SCHEDULER_JOURNAL_DIRECTORY, journal_fd
            )
            disk.sync_directory(output, output_fd)
            disk.sync_directory(artifact_root, root_fd)
        return SchedulerResultInsecureTestOnly(
            ordered_results,
            journal[PLAN_NAME],
            complete,
            tuple(adopted),
        )


def capture_completed_schedule(
    output: Path,
    *,
    artifact_root: Path,
    expected_complete_sha256: str,
) -> SchedulerResultInsecureTestOnly:
    """Capture all completed children in plan order without tree replay."""
    _digest(expected_complete_sha256, "external scheduler complete checkpoint")
    latest = latest_scheduler_checkpoint(output, artifact_root=artifact_root)
    if (
        latest.location.name != COMPLETE_NAME
        or latest.identity["sha256"] != expected_complete_sha256
    ):
        raise SchedulerError("scheduler complete checkpoint identity mismatch")
    _validate_scheduler_output_inventory(output)
    journal = _capture_scheduler_journal(output, latest)
    if tuple(journal) != SCHEDULER_JOURNAL_NAMES:
        raise SchedulerError("completed scheduler journal is incomplete")
    _validate_scheduler_journal(journal, require_restartable=True)
    _validate_tree_output_inventory(output, artifact_root, require_all=True)
    results = []
    for descriptor in EXECUTION_PLAN_DOCUMENT["trees"]:
        index = int(descriptor["tree_index"])
        child = _tree_output(output, index)
        _validate_completed_child_inventory(child, index)
        result = restart.capture_completed_result(
            child,
            artifact_root=artifact_root,
            expected_complete_sha256=descriptor["dependency_checkpoint_chain"][3][
                "identity"
            ]["sha256"],
        )
        _validate_child_result(result, descriptor)
        results.append(result)
    return SchedulerResultInsecureTestOnly(
        tuple(results), journal[PLAN_NAME], latest, ()
    )


def _scoped_file_bytes(root: Path, output_name: str) -> dict[str, bytes]:
    result = {}
    for entry in root.iterdir():
        if entry.name != output_name and not entry.name.startswith(output_name + ".tree-"):
            continue
        for path in entry.rglob("*"):
            if path.is_file():
                result[str(path.relative_to(root))] = path.read_bytes()
    return result


def _fixture_invocations() -> tuple[
    handoff.HandoffSessionInsecureTestOnly,
    tuple[continuation.TreePostInvocationInsecureTestOnly, ...],
]:
    session = handoff.HandoffSessionInsecureTestOnly()
    session.run_to("global-a")
    candidates = session.export_candidates()
    handoff_sha = sha256(candidates.handoff.raw)
    session.accept_handoff(candidates, expected_handoff_sha256=handoff_sha)
    receipt_suffix = continuation.build_verified_receipt_suffix_snapshots(session)
    continuations = continuation.build_continuation_snapshots(session)
    invocations = tuple(
        continuation.TreePostInvocationInsecureTestOnly(
            candidates, item, receipt_suffix
        )
        for item in continuations
    )
    _validate_invocations(invocations)
    return session, invocations


@lru_cache(maxsize=1)
def bounded_self_check() -> dict[str, object]:
    validate_prerequisites()
    session, invocations = _fixture_invocations()
    try:
        plan = build_execution_plan(invocations)
        with TemporaryDirectory(prefix="pq-rbbc-multitree-scheduler-") as temporary:
            base = Path(temporary)
            sequential_root = base / "sequential-root"
            parallel_root = base / "parallel-root"
            sequential_root.mkdir(mode=0o700)
            parallel_root.mkdir(mode=0o700)
            sequential = run_bounded_scheduler(
                sequential_root / "scheduler",
                artifact_root=sequential_root,
                fresh_invocations=invocations,
                fresh_output=True,
                scheduling_mode="sequential",
            )
            parallel = run_bounded_scheduler(
                parallel_root / "scheduler",
                artifact_root=parallel_root,
                fresh_invocations=invocations,
                fresh_output=True,
                scheduling_mode="bounded-parallel",
            )
            if sequential is None or parallel is None:
                raise SchedulerError("bounded scheduler self-check did not complete")
            sequential_files = _scoped_file_bytes(sequential_root, "scheduler")
            parallel_files = _scoped_file_bytes(parallel_root, "scheduler")
            if sequential_files != parallel_files:
                raise SchedulerError("sequential and parallel private artifacts differ")
            if _ordered_results_bytes(sequential.ordered_results) != _ordered_results_bytes(
                parallel.ordered_results
            ):
                raise SchedulerError("sequential and parallel ordered results differ")
            captured = capture_completed_schedule(
                parallel_root / "scheduler",
                artifact_root=parallel_root,
                expected_complete_sha256=parallel.complete_checkpoint.identity["sha256"],
            )
            if _ordered_results_bytes(captured.ordered_results) != _ordered_results_bytes(
                parallel.ordered_results
            ):
                raise SchedulerError("completed schedule capture changed ordered results")
            evidence = {
                "format": FORMAT,
                "relation_id": RELATION_ID,
                "mode": MODE,
                "execution_plan_identity": plan.identity,
                "ordered_tree_indices": list(ORDERED_TREE_INDICES),
                "continuation_identities": list(CONTINUATION_IDENTITIES),
                "verified_receipt_suffix_ordinals": [2, 3],
                "verified_receipt_suffix_identities": list(
                    RECEIPT_SUFFIX_IDENTITIES
                ),
                "full_receipt_chain_verified": False,
                "receipt_suffix_validation_before_scheduler_publication": True,
                "private_input_root_identities": [
                    descriptor["private_input_root_identity_sha256"]
                    for descriptor in EXECUTION_PLAN_DOCUMENT["trees"]
                ],
                "private_result_root_identities": [
                    descriptor["private_result_root_identity_sha256"]
                    for descriptor in EXECUTION_PLAN_DOCUMENT["trees"]
                ],
                "fresh_cache_identities": [
                    descriptor["fresh_cache_identity_sha256"]
                    for descriptor in EXECUTION_PLAN_DOCUMENT["trees"]
                ],
                "private_result_identities": [
                    item.result.identity for item in sequential.ordered_results
                ],
                "child_complete_checkpoint_identities": [
                    item.complete_checkpoint.identity
                    for item in sequential.ordered_results
                ],
                "scheduler_complete_checkpoint_identity": sequential.complete_checkpoint.identity,
                "output_ports": [
                    {
                        "port_id": item.output_port.port_id,
                        "wire_start": item.output_port.wire_start,
                        "bit_length": item.output_port.bit_length,
                        "value_sha256": item.output_port.value_sha256,
                    }
                    for item in sequential.ordered_results
                ],
                "tree_post_rows": [3_576, 3_576],
                "tree_post_allocated_wires": [2_412, 2_412],
                "scheduling_modes_qualified": list(SCHEDULING_MODES),
                "concurrency_limit": CONCURRENCY_LIMIT,
                "sequential_parallel_artifacts_byte_identical": True,
                "sequential_parallel_ordered_results_byte_identical": True,
                "result_order_matches_plan": True,
                "completed_schedule_captured_without_tree_post_replay": True,
                "independent_output_directories": True,
                "independent_tree_journals": True,
                "distinct_fresh_cache_identities": True,
                "shared_writable_cache": False,
                "shared_resume_state": False,
                "other_tree_observed_stream_bytes_used": False,
                "exact_orphan_adoption_qualified_by_tests": True,
                "completed_child_dependency_durability_order_qualified_by_tests": True,
                "closed_world_parent_and_child_inventories_qualified_by_tests": True,
                "repeated_resume_idempotence_qualified_by_tests": True,
                "competing_scheduler_rejection_qualified_by_tests": True,
                "global_tail_continuation_implemented": False,
                "global_tail_output_created": False,
                "parent_output_created": False,
                "production_legacy18_provider_implemented": False,
                "production_durable_resume_implemented": False,
                "qualified_pq_se_backend_integrated": False,
                "formal_pi_issue_generated": False,
                "private_input_or_result_bytes_embedded": False,
                "production_rows_replayed": 0,
                "proofs_generated": 0,
                "safe_to_start_large_replay": False,
                "safe_to_start_large_proving_run": False,
                "Proof-closed": False,
                "Production-closed": False,
            }
            for key, expected in FROZEN.items():
                if evidence.get(key) != expected:
                    raise SchedulerError("frozen bounded scheduler evidence drift: " + key)
            return evidence
    finally:
        session.close()


def execute_production(*_args: object, **_kwargs: object) -> None:
    raise ProductionUnavailable(
        "bounded multi-tree restart scheduler is test-only; production refused before I/O"
    )


def preflight() -> dict[str, object]:
    validate_prerequisites()
    return {
        "format": FORMAT,
        "relation_id": RELATION_ID,
        "read_only_preflight_passed": True,
        "safe_to_run_bounded_insecure_test_only": True,
        "canonical_execution_plan_defined": True,
        "bounded_multitree_scheduler_implemented": True,
        "ordered_tree_indices": list(ORDERED_TREE_INDICES),
        "verified_receipt_suffix_ordinals": [2, 3],
        "full_receipt_chain_verified": False,
        "receipt_suffix_validation_before_scheduler_publication": True,
        "concurrency_limit": CONCURRENCY_LIMIT,
        "global_tail_continuation_implemented": False,
        "production_legacy18_provider_implemented": False,
        "production_durable_resume_implemented": False,
        "qualified_pq_se_backend_integrated": False,
        "formal_pi_issue_generated": False,
        "production_execution_command": None,
        "large_replay_command": None,
        "large_proving_command": None,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
        "production_rows_replayed": 0,
        "proofs_generated": 0,
        "Proof-closed": False,
        "Production-closed": False,
        "external_inventory_scope": "not provisioned",
        "missing_production_artifacts": list(
            continuation.base.prefreeze.inputs.REQUIRED_EXTERNAL_ARTIFACTS
        ),
        "blockers": [
            "global-tail phase A/B independent continuation and consumer are not implemented",
            "fresh production legacy18 tree inputs and mixed degree-12/13 scheduler are not qualified",
            *list(continuation.base.prefreeze.BLOCKERS),
        ],
    }


def build_manifest() -> dict[str, object]:
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "implementation_identities": {
            path: io.read_snapshot(ROOT / path).identity
            for path in (
                "src/pq_rbbc_issuance_multitree_restart_scheduler_v1.py",
                "tests/test_pq_rbbc_issuance_multitree_restart_scheduler_v1.py",
            )
        },
        "predecessor_identities": {
            path: {"bytes": size, "sha256": digest}
            for path, (size, digest) in PREDECESSOR_PINS.items()
        },
        "execution_plan": EXECUTION_PLAN_DOCUMENT,
        "execution_plan_identity": execution_plan_snapshot().identity,
        "scheduler_checkpoint_identities": [
            item.identity for item in EXPECTED_SCHEDULER_JOURNAL
        ],
        "bounded_qualification": bounded_self_check(),
        "preflight": preflight(),
        "artifact_policy": {
            "metadata_only_portable_evidence": True,
            "private_input_or_result_bytes_embedded": False,
            "assignment_or_br1cs_tracked": False,
            "pickle_cache_checkpoint_resume_or_log_tracked": False,
            "runtime_tree_outputs_are_external_private_artifacts": True,
            "historical_v2_38_v2_39_files_modified": False,
        },
        "claim_status": {
            "Defined": True,
            "Instantiated": "tree0-tree1-4leaf-insecure-test-only",
            "Implemented": "bounded-sequential-and-parallel-restart-scheduler",
            "Tested": "bounded-crash-restart-concurrency-and-mutation",
            "Evidence-sealed": "metadata-only",
            "global_tail_continuation_implemented": False,
            "production_legacy18_provider_implemented": False,
            "production_durable_resume_implemented": False,
            "qualified_pq_se_backend_integrated": False,
            "formal_pi_issue_generated": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
            "Proof-closed": False,
            "Production-closed": False,
        },
        "exact_commands": {
            "read_only": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_multitree_restart_scheduler_v1.py",
            "bounded": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_multitree_restart_scheduler_v1.py --self-check",
            "targeted": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_multitree_restart_scheduler_v1 -v",
            "production": None,
            "large_replay": None,
            "large_proving": None,
        },
    }


def build_portable_evidence() -> dict[str, object]:
    manifest_raw = canonical_json(build_manifest())
    return {
        "format": FORMAT + "-PORTABLE-EVIDENCE",
        "bounded_qualification": bounded_self_check(),
        "manifest": {
            "filename": Path(MANIFEST_PATH).name,
            "bytes": len(manifest_raw),
            "sha256": sha256(manifest_raw),
        },
        "private_continuation_spool_result_assignment_or_receipt_embedded": False,
        "scheduler_or_tree_checkpoint_resume_state_embedded": False,
        "production_execution_started": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-check", action="store_true")
    arguments = parser.parse_args()
    report = bounded_self_check() if arguments.self_check else preflight()
    print(canonical_json(report).decode("ascii"), end="")


if __name__ == "__main__":
    main()
