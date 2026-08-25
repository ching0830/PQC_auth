#!/usr/bin/env python3
"""Canonical 18-tree CAP composition checkpoint for PQ-RBBC v2.8.

The two production tree shapes already have independently frozen native row
streams and complete assignment replays.  This module performs the next
strictly narrower step: execute the actual mixed 18-tree CAP profile, bind
each tree position to the matching frozen shard evidence, and serialize the
cross-tree corrections and global Fiat--Shamir transcript into one canonical
linked document.

The linked document is not a monolithic R1CS assignment.  Its aggregate shard
counts are explicitly named a *template envelope*: the one-tree fixtures each
contain their own transcript tail, so adding their row counts is an engineering
upper bound rather than the exact row count of a deduplicated 18-tree circuit.
Consequently this module closes the full production reference-vector and
canonical composition-schedule boundaries, but leaves the native global-tail
wire join, one-piece assignment replay, parent join, and security reduction
fail-closed.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import pickle
import resource
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_anemoi_sponge as sponge
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_shard_assignment as assignment
import pq_rbbc_cap_shard_stream as shard


IMPLEMENTATION_VERSION = "2.8"
COMPOSITION_FORMAT = "PQRBBC-CAP-LINKED-18-1"
TRACE_FORMAT = "PQRBBC-CAP-XOF-TRACE-1"
RELATION_ID = "pq-rbbc/cap/linked-production-18/v1"
FROZEN_RANDOMNESS_LABEL = b"PQ-RBBC/v2.8/frozen-production-cap-randomness"
FROZEN_REQUEST_MESSAGE = bytes(32)

# Patched after the production run.  Empty values keep development tests
# fail-closed until a real full-profile artifact has been generated.
FROZEN_DOCUMENT_SHA256 = (
    "a7ef7eb4689d84c686074308d0d167e1567ab84578d66b5ad004970940ea0163"
)
FROZEN_COMMITMENT_SHA256 = (
    "12123e95b1b64d87da7a575dbf803fc53ded9eb9a23b807eeab2cba51dfe5b62"
)
FROZEN_REQUEST_HASH_HEX = (
    "3f9ec0aeab100e4ebef8046068851874f08fcda6daa2e42178dd559f55e38a31"
    "da28af9ccd0653bb4ca574ec8264cce1f3c024c97e858e2c877bba7968c039dc"
    "61f516dfed995ba3"
)
FROZEN_XOF_TRACE_SHA256 = (
    "ccfa51ec2aee9501483c65023c4a877316eb6dd0557ccd6c42dfdf5f20f2c4e6"
)


@dataclass(frozen=True)
class ShardTemplate:
    leaves: int
    extension_degree: int
    relation_id: str
    rows: int
    wires: int
    nonlinear_rows: int
    linear_rows: int
    stream_bytes: int
    row_stream_sha256: str
    assignment_archive_bytes: int
    assignment_archive_sha256: str
    verified_rows: int
    verification_failures: int


@dataclass(frozen=True)
class ParallelExecutionSummary:
    execution: cap.CAPExecution
    wall_seconds: float
    peak_rss_kib: int


def _template_for(leaves: int, extension_degree: int) -> ShardTemplate:
    if (leaves, extension_degree) == (2_048, 12):
        return ShardTemplate(
            leaves,
            extension_degree,
            shard.PROFILE_RELATION_ID_2048,
            shard.FROZEN_PRODUCTION_ROWS,
            shard.FROZEN_PRODUCTION_WIRES,
            shard.FROZEN_PRODUCTION_NONLINEAR_ROWS,
            shard.FROZEN_PRODUCTION_LINEAR_ROWS,
            shard.FROZEN_PRODUCTION_STREAM_BYTES,
            shard.FROZEN_PRODUCTION_STREAM_SHA256,
            assignment.FROZEN_PRODUCTION_ASSIGNMENT_ARCHIVE_BYTES,
            assignment.FROZEN_PRODUCTION_ASSIGNMENT_ARCHIVE_SHA256,
            assignment.FROZEN_PRODUCTION_VERIFIED_ROWS,
            assignment.FROZEN_PRODUCTION_VERIFICATION_FAILURES,
        )
    if (leaves, extension_degree) == (4_096, 13):
        return ShardTemplate(
            leaves,
            extension_degree,
            shard.PROFILE_RELATION_ID_4096,
            shard.FROZEN_PRODUCTION_4096_ROWS,
            shard.FROZEN_PRODUCTION_4096_WIRES,
            shard.FROZEN_PRODUCTION_4096_NONLINEAR_ROWS,
            shard.FROZEN_PRODUCTION_4096_LINEAR_ROWS,
            shard.FROZEN_PRODUCTION_4096_STREAM_BYTES,
            shard.FROZEN_PRODUCTION_4096_STREAM_SHA256,
            assignment.FROZEN_PRODUCTION_4096_ASSIGNMENT_ARCHIVE_BYTES,
            assignment.FROZEN_PRODUCTION_4096_ASSIGNMENT_ARCHIVE_SHA256,
            assignment.FROZEN_PRODUCTION_4096_VERIFIED_ROWS,
            assignment.FROZEN_PRODUCTION_4096_VERIFICATION_FAILURES,
        )
    raise ValueError(f"no frozen shard evidence for {(leaves, extension_degree)}")


def _xof_output(domain: bytes, fields: Sequence[bytes], output_bits: int) -> int:
    payload = sponge.encode_transcript(fields)
    raw = sponge.evaluate_sponge(domain, payload, (output_bits + 7) // 8)
    return int.from_bytes(raw, "little") & ((1 << output_bits) - 1)


def _derive_task(task: tuple[int, int, int, int, tuple[int, int]]) -> int:
    tree_index, level, node_index, parent, salt = task
    fields = (
        cap.hash_bytes(salt[0] | (salt[1] << cap.SEED_BITS)),
        cap.field_bytes(parent),
        cap._meta(tree_index, level, node_index),
    )
    return _xof_output(cap.DOMAIN_SEED_DERIVE, fields, 2 * cap.SEED_BITS)


def _leaf_task(
    task: tuple[int, int, int, tuple[int, int], int],
) -> tuple[int, int]:
    tree_index, leaf_index, seed, salt, tape_bits = task
    metadata = cap._meta(tree_index, 0, leaf_index)
    commitment = _xof_output(
        cap.DOMAIN_SEED_COMMIT,
        (
            cap.hash_bytes(salt[0] | (salt[1] << cap.SEED_BITS)),
            cap.field_bytes(seed),
            metadata,
        ),
        cap.HASH_BITS,
    )
    tape = _xof_output(
        cap.DOMAIN_TAPE_EXPAND,
        (cap.field_bytes(seed), metadata),
        tape_bits,
    )
    return commitment, tape


def _aggregate_tree_task(
    task: tuple[int, int, int, tuple[tuple[int, int], ...]],
) -> cap.TreePolynomial:
    leaves, extension_degree, random_polynomial_bits, outputs = task
    commitments: list[tuple[int, int]] = []
    plain = 0
    masks = [0] * random_polynomial_bits
    for leaf_index, (commitment, tape) in enumerate(outputs, start=1):
        commitments.append(
            (commitment & field.FIELD_MASK, commitment >> field.FIELD_DEGREE)
        )
        plain ^= tape
        inverse = cap.gf2m_inv(leaf_index, extension_degree)
        set_bits = tape
        while set_bits:
            low_bit = set_bits & -set_bits
            masks[low_bit.bit_length() - 1] ^= inverse
            set_bits ^= low_bit
    return cap.TreePolynomial(
        leaves,
        extension_degree,
        tuple(commitments),
        plain,
        tuple(masks),
    )


def _canonical_tree_calls(
    parameters: cap.CAPParameters,
    randomness: cap.CAPRandomness,
    derivations: Sequence[Sequence[tuple[int, int, int, int]]],
    leaf_seeds: Sequence[Sequence[int]],
    leaf_outputs: Sequence[Sequence[tuple[int, int]]],
) -> tuple[cap.XOFCall, ...]:
    calls: list[cap.XOFCall] = []
    salt_field = cap.hash_bytes(
        randomness.salt[0] | (randomness.salt[1] << cap.SEED_BITS)
    )
    for tree_index in range(parameters.tree_count):
        for level, node_index, parent, output in derivations[tree_index]:
            calls.append(
                cap.XOFCall(
                    f"tree[{tree_index}].derive[{level},{node_index}]",
                    cap.DOMAIN_SEED_DERIVE,
                    (
                        salt_field,
                        cap.field_bytes(parent),
                        cap._meta(tree_index, level, node_index),
                    ),
                    2 * cap.SEED_BITS,
                    output,
                )
            )
        for leaf_index, (seed, (commitment, tape)) in enumerate(
            zip(leaf_seeds[tree_index], leaf_outputs[tree_index]), start=1
        ):
            metadata = cap._meta(tree_index, 0, leaf_index)
            calls.append(
                cap.XOFCall(
                    f"tree[{tree_index}].leaf[{leaf_index}].commit",
                    cap.DOMAIN_SEED_COMMIT,
                    (salt_field, cap.field_bytes(seed), metadata),
                    cap.HASH_BITS,
                    commitment,
                )
            )
            calls.append(
                cap.XOFCall(
                    f"tree[{tree_index}].leaf[{leaf_index}].tape",
                    cap.DOMAIN_TAPE_EXPAND,
                    (cap.field_bytes(seed), metadata),
                    parameters.random_polynomial_bits,
                    tape,
                )
            )
    return tuple(calls)


def _finish_execution(
    parameters: cap.CAPParameters,
    randomness: cap.CAPRandomness,
    polynomials: Sequence[cap.TreePolynomial],
    tree_calls: Sequence[cap.XOFCall],
) -> cap.CAPExecution:
    witness_mask = (1 << parameters.witness_bits) - 1
    consistency_mask = (1 << parameters.consistency_bits) - 1
    p_plain = tuple(poly.plain & witness_mask for poly in polynomials)
    mhat_shift = parameters.witness_bits + (parameters.degree - 1) * parameters.rho
    mhat_plain = tuple(
        (poly.plain >> mhat_shift) & consistency_mask for poly in polynomials
    )
    delta_p = tuple(p_plain[0] ^ value for value in p_plain[1:])
    delta_mhat = tuple(mhat_plain[0] ^ value for value in mhat_plain[1:])

    recorder = cap.XOFRecorder()
    profile = bytes.fromhex(cap.profile_fingerprint(parameters))
    h1_fields: list[bytes] = [profile]
    h1_fields.extend(
        cap._tree_component(index, polynomial)
        for index, polynomial in enumerate(polynomials)
    )
    h1_fields.append(cap._correction_component(delta_p, delta_mhat, parameters))
    h1 = recorder.call("h1", cap.DOMAIN_H1, h1_fields, cap.HASH_BITS)
    point_bits = recorder.call(
        "consistency-points",
        cap.DOMAIN_CONSISTENCY_POINTS,
        (cap.hash_bytes(h1), profile),
        parameters.consistency_bits,
    )
    points = tuple(
        (point_bits >> (index * field.FIELD_DEGREE)) & field.FIELD_MASK
        for index in range(parameters.consistency_points)
    )
    if any(point == 0 for point in points) or len(set(points)) != len(points):
        raise RuntimeError("degenerate consistency points")

    alpha = cap._linear_hash_vector(p_plain[0], parameters.witness_bits, points) ^ mhat_plain[0]
    xi_components: list[bytes] = []
    for polynomial in polynomials:
        p_masks = polynomial.masks[: parameters.witness_bits]
        mhat_masks = polynomial.masks[
            mhat_shift : mhat_shift + parameters.consistency_bits
        ]
        hashed_masks = cap._linear_hash_masks(
            p_masks,
            parameters.witness_bits,
            polynomial.extension_degree,
            points,
        )
        xi_masks = tuple(left ^ right for left, right in zip(hashed_masks, mhat_masks))
        xi_components.append(
            cap._xi_component(
                alpha,
                xi_masks,
                parameters.consistency_bits,
                polynomial.extension_degree,
            )
        )
    h2 = recorder.call(
        "h2", cap.DOMAIN_H2, (cap.hash_bytes(h1), *xi_components), cap.HASH_BITS
    )
    encoded = cap.serialize_commitment(
        parameters, randomness.salt, h2, alpha, delta_p, delta_mhat
    )
    commitment = cap.CAPCommitment(
        cap.profile_fingerprint(parameters),
        randomness.salt,
        h1,
        h2,
        alpha,
        delta_p,
        delta_mhat,
        p_plain[0] & ((1 << parameters.mask_bits) - 1),
        (p_plain[0] >> parameters.mask_bits)
        & ((1 << parameters.appended_signature_bits) - 1),
        encoded,
    )
    return cap.CAPExecution(
        commitment,
        tuple(polynomials),
        tuple(tree_calls) + tuple(recorder.calls),
    )


def build_parallel_execution(
    parameters: cap.CAPParameters,
    randomness: cap.CAPRandomness,
    *,
    workers: int = 1,
    progress: Callable[[str], None] | None = None,
) -> ParallelExecutionSummary:
    """Execute any supported CAP profile with XOF and aggregation parallelism."""

    if parameters.consistency_points not in (1, 2):
        raise ValueError("only one or two consistency points are supported")
    if len(randomness.roots) != parameters.tree_count:
        raise ValueError("wrong number of CAP root pairs")
    started = time.perf_counter()
    leaves_per_tree = parameters.expanded_leaf_counts()
    degrees = parameters.expanded_extension_degrees()
    nodes: list[list[int]] = [list(pair) for pair in randomness.roots]
    derivations: list[list[tuple[int, int, int, int]]] = [
        [] for _ in range(parameters.tree_count)
    ]
    workers = max(1, workers)

    executor = ProcessPoolExecutor(max_workers=workers) if workers > 1 else None
    try:
        max_level = max(leaves.bit_length() - 1 for leaves in leaves_per_tree)
        for level in range(2, max_level + 1):
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
                    for node_index, parent in enumerate(nodes[tree_index], start=1)
                )
                spans.append((tree_index, start, len(tasks)))
            if not tasks:
                continue
            if executor is None:
                outputs = list(map(_derive_task, tasks))
            else:
                outputs = list(executor.map(_derive_task, tasks, chunksize=8))
            for tree_index, start, end in spans:
                parents = nodes[tree_index]
                children: list[int] = []
                for node_index, (parent, output) in enumerate(
                    zip(parents, outputs[start:end]), start=1
                ):
                    derivations[tree_index].append(
                        (level, node_index, parent, output)
                    )
                    children.extend(
                        (output & field.FIELD_MASK, output >> cap.SEED_BITS)
                    )
                nodes[tree_index] = children
            if progress is not None:
                progress(f"derive level {level}: {len(tasks):,} calls")

        leaf_tasks: list[tuple[int, int, int, tuple[int, int], int]] = []
        leaf_spans: list[tuple[int, int, int]] = []
        for tree_index, seeds in enumerate(nodes):
            start = len(leaf_tasks)
            leaf_tasks.extend(
                (
                    tree_index,
                    leaf_index,
                    seed,
                    randomness.salt,
                    parameters.random_polynomial_bits,
                )
                for leaf_index, seed in enumerate(seeds, start=1)
            )
            leaf_spans.append((tree_index, start, len(leaf_tasks)))
        if progress is not None:
            progress(f"leaf XOF batch: {len(leaf_tasks):,} leaves")
        if executor is None:
            flat_leaf_outputs = list(map(_leaf_task, leaf_tasks))
        else:
            flat_leaf_outputs = list(executor.map(_leaf_task, leaf_tasks, chunksize=8))
        leaf_outputs: list[tuple[tuple[int, int], ...]] = [tuple()] * parameters.tree_count
        for tree_index, start, end in leaf_spans:
            leaf_outputs[tree_index] = tuple(flat_leaf_outputs[start:end])

        aggregate_tasks = tuple(
            (leaves, degree, parameters.random_polynomial_bits, leaf_outputs[index])
            for index, (leaves, degree) in enumerate(zip(leaves_per_tree, degrees))
        )
        if progress is not None:
            progress("aggregate 18 tree polynomials")
        if executor is None:
            polynomials = list(map(_aggregate_tree_task, aggregate_tasks))
        else:
            polynomials = list(executor.map(_aggregate_tree_task, aggregate_tasks))
    finally:
        if executor is not None:
            executor.shutdown()

    if progress is not None:
        progress("serialize canonical tree calls and global transcript")
    tree_calls = _canonical_tree_calls(
        parameters, randomness, derivations, nodes, leaf_outputs
    )
    execution = _finish_execution(parameters, randomness, polynomials, tree_calls)
    return ParallelExecutionSummary(
        execution,
        time.perf_counter() - started,
        resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    )


def validate_execution_cache_identity(
    summary: ParallelExecutionSummary,
    parameters: cap.CAPParameters,
    randomness: cap.CAPRandomness,
) -> tuple[str, ...]:
    """Bind a trusted cache to the requested profile, salt, roots, and shape."""

    failures: list[str] = []
    execution = summary.execution
    if execution.commitment.parameters_fingerprint != cap.profile_fingerprint(parameters):
        failures.append("cache_profile")
    if execution.commitment.salt != randomness.salt:
        failures.append("cache_salt")
    expected_shape = tuple(
        zip(parameters.expanded_leaf_counts(), parameters.expanded_extension_degrees())
    )
    actual_shape = tuple(
        (tree.leaves, tree.extension_degree) for tree in execution.tree_polynomials
    )
    if actual_shape != expected_shape:
        failures.append("cache_tree_shape")
    calls = {call.label: call for call in execution.xof_calls}
    salt_field = cap.hash_bytes(
        randomness.salt[0] | (randomness.salt[1] << cap.SEED_BITS)
    )
    for tree_index, roots in enumerate(randomness.roots):
        for node_index, root in enumerate(roots, start=1):
            label = f"tree[{tree_index}].derive[2,{node_index}]"
            call = calls.get(label)
            expected_fields = (
                salt_field,
                cap.field_bytes(root),
                cap._meta(tree_index, 2, node_index),
            )
            if call is None or call.domain != cap.DOMAIN_SEED_DERIVE or call.fields != expected_fields:
                failures.append(f"cache_root_{tree_index}_{node_index}")
    return tuple(failures)


def _hash_parts(parts: Iterable[bytes]) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    for part in parts:
        digest.update(part)
        size += len(part)
    return size, digest.hexdigest()


def xof_trace_digest(calls: Sequence[cap.XOFCall]) -> tuple[int, str]:
    def parts() -> Iterable[bytes]:
        yield TRACE_FORMAT.encode("ascii") + b"\x00"
        for call in calls:
            for item in (
                call.label.encode("utf-8"),
                call.domain,
                call.payload,
                call.output_bits.to_bytes(8, "little"),
                cap.pack_int(call.output, call.output_bits),
            ):
                yield len(item).to_bytes(8, "little")
                yield item

    return _hash_parts(parts())


def _tree_links(execution: cap.CAPExecution) -> tuple[dict[str, object], ...]:
    row_offset = 0
    wire_offset = 0
    links: list[dict[str, object]] = []
    for index, polynomial in enumerate(execution.tree_polynomials):
        template = _template_for(polynomial.leaves, polynomial.extension_degree)
        component = cap._tree_component(index, polynomial)
        item = {
            "tree_index": index,
            "leaves": polynomial.leaves,
            "extension_degree": polynomial.extension_degree,
            "tree_component_bytes": len(component),
            "tree_component_sha256": hashlib.sha256(component).hexdigest(),
            "template_row_offset": row_offset,
            "template_wire_offset": wire_offset,
            "template": asdict(template),
        }
        links.append(item)
        row_offset += template.rows
        wire_offset += template.wires
    return tuple(links)


def canonical_json(document: dict[str, object]) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def build_linked_document(
    summary: ParallelExecutionSummary,
    randomness: cap.CAPRandomness,
    *,
    request_message: bytes = FROZEN_REQUEST_MESSAGE,
    randomness_label: bytes = FROZEN_RANDOMNESS_LABEL,
) -> dict[str, object]:
    parameters = cap.PRODUCTION_PARAMETERS
    execution = summary.execution
    if len(execution.tree_polynomials) != parameters.tree_count:
        raise ValueError("linked production document requires exactly 18 trees")
    expected_shape = tuple(
        zip(parameters.expanded_leaf_counts(), parameters.expanded_extension_degrees())
    )
    actual_shape = tuple(
        (tree.leaves, tree.extension_degree) for tree in execution.tree_polynomials
    )
    if actual_shape != expected_shape:
        raise ValueError("execution tree order does not match the production profile")

    tree_links = _tree_links(execution)
    correction = cap._correction_component(
        execution.commitment.delta_p,
        execution.commitment.delta_mhat,
        parameters,
    )
    trace_bytes, trace_sha256 = xof_trace_digest(execution.xof_calls)
    randomness_bytes = randomness.serialize(parameters)
    request_hash = sponge.hash_request_binding(
        request_message, execution.commitment.encoded
    )
    request_payload_bytes = cap._encoded_transcript_bytes(
        (len(request_message), len(execution.commitment.encoded))
    )
    request_permutations = cap._sponge_permutations(
        sponge.REQUEST_BINDING_DOMAIN,
        request_payload_bytes,
        sponge.REQUEST_HASH_BITS,
    )
    envelope = {
        "rows": sum(item["template"]["rows"] for item in tree_links),
        "wires": sum(item["template"]["wires"] for item in tree_links),
        "nonlinear_rows": sum(
            item["template"]["nonlinear_rows"] for item in tree_links
        ),
        "linear_rows": sum(
            item["template"]["linear_rows"] for item in tree_links
        ),
        "virtual_stream_bytes": sum(
            item["template"]["stream_bytes"] for item in tree_links
        ),
        "assignment_archive_bytes": sum(
            item["template"]["assignment_archive_bytes"] for item in tree_links
        ),
        "semantics": "sum of 18 verified one-tree fixture envelopes; not a deduplicated monolithic circuit count",
    }
    return {
        "format": COMPOSITION_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "profile": {
            "name": parameters.name,
            "profile_sha256": cap.profile_fingerprint(parameters),
            "tree_count": parameters.tree_count,
            "leaf_count": parameters.leaf_count,
            "tree_order": "profile order: 2x4096/degree-13, then 16x2048/degree-12",
            "commitment_bytes": cap.commitment_bytes(parameters),
        },
        "randomness": {
            "derivation_label_hex": randomness_label.hex(),
            "serialized_bytes": len(randomness_bytes),
            "serialized_sha256": hashlib.sha256(randomness_bytes).hexdigest(),
        },
        "tree_links": list(tree_links),
        "cross_tree_corrections": {
            "count": len(execution.commitment.delta_p),
            "component_bytes": len(correction),
            "component_sha256": hashlib.sha256(correction).hexdigest(),
            "delta_p_hex": [
                cap.pack_int(value, parameters.witness_bits).hex()
                for value in execution.commitment.delta_p
            ],
            "delta_mhat_hex": [
                cap.pack_int(value, parameters.consistency_bits).hex()
                for value in execution.commitment.delta_mhat
            ],
        },
        "global_transcript": {
            "xof_calls": len(execution.xof_calls),
            "xof_trace_scope": "CAP calls only; request binding is accounted separately",
            "xof_trace_bytes": trace_bytes,
            "xof_trace_sha256": trace_sha256,
            "h1_hex": cap.hash_bytes(execution.commitment.h1).hex(),
            "h2_hex": cap.hash_bytes(execution.commitment.h2).hex(),
            "alpha_hex": cap.pack_int(
                execution.commitment.alpha, parameters.consistency_bits
            ).hex(),
            "commitment_bytes": len(execution.commitment.encoded),
            "commitment_sha256": hashlib.sha256(
                execution.commitment.encoded
            ).hexdigest(),
            "request_message_bytes": len(request_message),
            "request_message_sha256": hashlib.sha256(request_message).hexdigest(),
            "request_hash_hex": request_hash.hex(),
            "request_binding_xof_calls": 1,
            "request_binding_payload_bytes": request_payload_bytes,
            "request_binding_permutations": request_permutations,
            "total_xof_calls_including_request_binding": len(execution.xof_calls) + 1,
            "total_anemoi_permutations_including_request_binding": (
                cap.production_accounting(parameters)["total_anemoi_permutations"]
                + request_permutations
            ),
            "total_permutation_nonlinear_rows_including_request_binding": (
                cap.production_accounting(parameters)["permutation_nonlinear_rows"]
                + request_permutations * field.NONLINEAR_ROWS
            ),
        },
        "production_accounting": cap.production_accounting(parameters),
        "template_envelope": envelope,
        # Runtime measurements are intentionally excluded so rerunning the
        # same vector yields byte-identical canonical JSON.
        "execution": {"whole_full_profile_reference_executed": True},
        "claim_boundary": {
            "full_production_reference_vector_closed": True,
            "canonical_18_tree_link_schedule_closed": True,
            "both_constituent_shard_assignments_previously_verified": True,
            "native_global_transcript_tail_materialized": False,
            "monolithic_18_tree_assignment_verified": False,
            "parent_archive_wire_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }


def validate_linked_document(
    document: dict[str, object],
    *,
    execution: cap.CAPExecution | None = None,
    request_message: bytes = FROZEN_REQUEST_MESSAGE,
) -> tuple[str, ...]:
    failures: list[str] = []
    parameters = cap.PRODUCTION_PARAMETERS
    if document.get("format") != COMPOSITION_FORMAT:
        failures.append("wrong_format")
    if document.get("relation_id") != RELATION_ID:
        failures.append("wrong_relation_id")
    profile = document.get("profile", {})
    if not isinstance(profile, dict) or profile.get("profile_sha256") != cap.profile_fingerprint(parameters):
        failures.append("wrong_profile")
    links = document.get("tree_links")
    expected_shape = tuple(
        zip(parameters.expanded_leaf_counts(), parameters.expanded_extension_degrees())
    )
    if not isinstance(links, list) or len(links) != parameters.tree_count:
        failures.append("wrong_tree_count")
        links = []
    row_offset = 0
    wire_offset = 0
    for index, shape in enumerate(expected_shape):
        if index >= len(links) or not isinstance(links[index], dict):
            failures.append(f"tree_{index}_missing")
            continue
        link = links[index]
        expected_template = asdict(_template_for(*shape))
        if (
            link.get("tree_index") != index
            or (link.get("leaves"), link.get("extension_degree")) != shape
        ):
            failures.append(f"tree_{index}_order")
        if link.get("template") != expected_template:
            failures.append(f"tree_{index}_template")
        if link.get("template_row_offset") != row_offset:
            failures.append(f"tree_{index}_row_offset")
        if link.get("template_wire_offset") != wire_offset:
            failures.append(f"tree_{index}_wire_offset")
        row_offset += expected_template["rows"]
        wire_offset += expected_template["wires"]
    corrections = document.get("cross_tree_corrections", {})
    if not isinstance(corrections, dict) or corrections.get("count") != 17:
        failures.append("wrong_correction_count")
    else:
        try:
            if (
                len(corrections["delta_p_hex"]) != 17
                or len(corrections["delta_mhat_hex"]) != 17
            ):
                failures.append("correction_vector_length")
            delta_p = tuple(int.from_bytes(bytes.fromhex(value), "little") for value in corrections["delta_p_hex"])
            delta_mhat = tuple(int.from_bytes(bytes.fromhex(value), "little") for value in corrections["delta_mhat_hex"])
            component = cap._correction_component(delta_p, delta_mhat, parameters)
            if hashlib.sha256(component).hexdigest() != corrections.get("component_sha256"):
                failures.append("correction_digest")
            if len(component) != corrections.get("component_bytes"):
                failures.append("correction_bytes")
        except (KeyError, TypeError, ValueError):
            failures.append("correction_encoding")
    transcript = document.get("global_transcript", {})
    if not isinstance(transcript, dict):
        failures.append("missing_global_transcript")
    else:
        if transcript.get("xof_calls") != cap.production_accounting()["total_xof_calls"]:
            failures.append("wrong_xof_call_count")
        if transcript.get("commitment_bytes") != cap.commitment_bytes(parameters):
            failures.append("wrong_commitment_bytes")
        if transcript.get("request_message_sha256") != hashlib.sha256(request_message).hexdigest():
            failures.append("request_message_digest")
        expected_payload_bytes = cap._encoded_transcript_bytes(
            (len(request_message), cap.commitment_bytes(parameters))
        )
        expected_request_permutations = cap._sponge_permutations(
            sponge.REQUEST_BINDING_DOMAIN,
            expected_payload_bytes,
            sponge.REQUEST_HASH_BITS,
        )
        if transcript.get("request_binding_xof_calls") != 1:
            failures.append("request_binding_xof_calls")
        if transcript.get("request_binding_payload_bytes") != expected_payload_bytes:
            failures.append("request_binding_payload_bytes")
        if transcript.get("request_binding_permutations") != expected_request_permutations:
            failures.append("request_binding_permutations")
        if transcript.get("total_xof_calls_including_request_binding") != cap.production_accounting()["total_xof_calls"] + 1:
            failures.append("total_xof_calls_including_request_binding")
        if transcript.get("total_anemoi_permutations_including_request_binding") != cap.production_accounting()["total_anemoi_permutations"] + expected_request_permutations:
            failures.append("total_anemoi_permutations_including_request_binding")
        if transcript.get("total_permutation_nonlinear_rows_including_request_binding") != cap.production_accounting()["permutation_nonlinear_rows"] + expected_request_permutations * field.NONLINEAR_ROWS:
            failures.append("total_permutation_nonlinear_rows_including_request_binding")
    envelope = document.get("template_envelope", {})
    if not isinstance(envelope, dict) or envelope.get("rows") != row_offset or envelope.get("wires") != wire_offset:
        failures.append("template_envelope")

    if execution is not None:
        if len(execution.tree_polynomials) != 18:
            failures.append("execution_tree_count")
        else:
            for index, polynomial in enumerate(execution.tree_polynomials):
                component = cap._tree_component(index, polynomial)
                if index >= len(links) or hashlib.sha256(component).hexdigest() != links[index].get("tree_component_sha256"):
                    failures.append(f"tree_{index}_component_digest")
        expected_correction = cap._correction_component(
            execution.commitment.delta_p,
            execution.commitment.delta_mhat,
            parameters,
        )
        if not isinstance(corrections, dict) or hashlib.sha256(expected_correction).hexdigest() != corrections.get("component_sha256"):
            failures.append("execution_correction_digest")
        trace_bytes, trace_sha = xof_trace_digest(execution.xof_calls)
        expected_request = sponge.hash_request_binding(request_message, execution.commitment.encoded)
        checks = {
            "xof_trace_bytes": trace_bytes,
            "xof_trace_sha256": trace_sha,
            "h1_hex": cap.hash_bytes(execution.commitment.h1).hex(),
            "h2_hex": cap.hash_bytes(execution.commitment.h2).hex(),
            "alpha_hex": cap.pack_int(execution.commitment.alpha, parameters.consistency_bits).hex(),
            "commitment_bytes": len(execution.commitment.encoded),
            "commitment_sha256": hashlib.sha256(execution.commitment.encoded).hexdigest(),
            "request_hash_hex": expected_request.hex(),
        }
        if isinstance(transcript, dict):
            for key, value in checks.items():
                if transcript.get(key) != value:
                    failures.append(f"execution_{key}")
    return tuple(failures)


def mutation_probes(
    document: dict[str, object], execution: cap.CAPExecution
) -> list[dict[str, object]]:
    mutations: list[tuple[str, Callable[[dict[str, object]], None]]] = []

    def swap_trees(value: dict[str, object]) -> None:
        value["tree_links"][0], value["tree_links"][1] = value["tree_links"][1], value["tree_links"][0]

    def change_template(value: dict[str, object]) -> None:
        value["tree_links"][2]["template"]["row_stream_sha256"] = "00" * 32

    def change_correction(value: dict[str, object]) -> None:
        encoded = bytearray.fromhex(value["cross_tree_corrections"]["delta_p_hex"][0])
        encoded[0] ^= 1
        value["cross_tree_corrections"]["delta_p_hex"][0] = encoded.hex()

    def change_commitment(value: dict[str, object]) -> None:
        value["global_transcript"]["commitment_sha256"] = "00" * 32

    def change_request(value: dict[str, object]) -> None:
        value["global_transcript"]["request_message_sha256"] = "11" * 32

    mutations.extend(
        (
            ("tree-order", swap_trees),
            ("shard-template", change_template),
            ("cross-tree-correction", change_correction),
            ("commitment", change_commitment),
            ("request-message", change_request),
        )
    )
    results: list[dict[str, object]] = []
    for label, mutate in mutations:
        changed = copy.deepcopy(document)
        mutate(changed)
        failures = validate_linked_document(changed, execution=execution)
        results.append(
            {"label": label, "rejected": bool(failures), "failures": list(failures)}
        )
    return results


def verify_frozen_document(path: Path) -> tuple[str, ...]:
    encoded = path.read_bytes()
    failures: list[str] = []
    if FROZEN_DOCUMENT_SHA256 and hashlib.sha256(encoded).hexdigest() != FROZEN_DOCUMENT_SHA256:
        failures.append("frozen_document_sha256")
    try:
        document = json.loads(encoded)
    except json.JSONDecodeError:
        return tuple(failures + ["invalid_json"])
    failures.extend(validate_linked_document(document))
    transcript = document.get("global_transcript", {})
    for key, expected in (
        ("commitment_sha256", FROZEN_COMMITMENT_SHA256),
        ("request_hash_hex", FROZEN_REQUEST_HASH_HEX),
        ("xof_trace_sha256", FROZEN_XOF_TRACE_SHA256),
    ):
        if expected and transcript.get(key) != expected:
            failures.append(f"frozen_{key}")
    return tuple(failures)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--workers", type=int, default=max(1, min(8, os.cpu_count() or 1)))
    parser.add_argument("--verify-frozen", type=Path)
    parser.add_argument(
        "--normalize-existing",
        type=Path,
        help="remove non-canonical runtime measurements from an existing document",
    )
    parser.add_argument(
        "--execution-cache",
        type=Path,
        help="write a trusted local pickle after the expensive execution",
    )
    parser.add_argument(
        "--resume-execution-cache",
        type=Path,
        help="resume document construction from a trusted local pickle",
    )
    args = parser.parse_args()
    if args.normalize_existing:
        document = json.loads(args.normalize_existing.read_text(encoding="utf-8"))
        document["execution"] = {"whole_full_profile_reference_executed": True}
        args.normalize_existing.write_bytes(canonical_json(document))
        print(hashlib.sha256(args.normalize_existing.read_bytes()).hexdigest())
        return
    if args.verify_frozen:
        failures = verify_frozen_document(args.verify_frozen)
        if failures:
            raise SystemExit("frozen document rejected: " + ",".join(failures))
        print("frozen linked document accepted")
        return
    if args.manifest is None:
        parser.error("--manifest is required unless --verify-frozen is used")
    parameters = cap.PRODUCTION_PARAMETERS
    randomness = cap.deterministic_randomness(parameters, FROZEN_RANDOMNESS_LABEL)
    if args.resume_execution_cache:
        with args.resume_execution_cache.open("rb") as stream:
            summary = pickle.load(stream)
        if not isinstance(summary, ParallelExecutionSummary):
            raise SystemExit("execution cache type mismatch")
        cache_failures = validate_execution_cache_identity(
            summary, parameters, randomness
        )
        if cache_failures:
            raise SystemExit(
                "execution cache identity mismatch: " + ",".join(cache_failures)
            )
    else:
        summary = build_parallel_execution(
            parameters,
            randomness,
            workers=args.workers,
            progress=lambda message: print(message, file=sys.stderr, flush=True),
        )
    if args.execution_cache:
        with args.execution_cache.open("wb") as stream:
            pickle.dump(summary, stream, protocol=pickle.HIGHEST_PROTOCOL)
        print(
            f"execution cache: {args.execution_cache}",
            file=sys.stderr,
            flush=True,
        )
    document = build_linked_document(summary, randomness)
    # Preserve the expensive vector even if a later validator uncovers an
    # accounting or document-format bug.  A successful run overwrites this
    # candidate with the probe-augmented canonical artifact.
    args.manifest.write_bytes(canonical_json(document))
    failures = validate_linked_document(document, execution=summary.execution)
    if failures:
        raise SystemExit("linked document rejected: " + ",".join(failures))
    document["mutation_probes"] = mutation_probes(document, summary.execution)
    args.manifest.write_bytes(canonical_json(document))
    print(
        json.dumps(
            {
                "manifest": str(args.manifest),
                "sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
                "commitment_sha256": document["global_transcript"]["commitment_sha256"],
                "request_hash_hex": document["global_transcript"]["request_hash_hex"],
                "xof_trace_sha256": document["global_transcript"]["xof_trace_sha256"],
                "wall_seconds": summary.wall_seconds,
                "peak_rss_kib": summary.peak_rss_kib,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
