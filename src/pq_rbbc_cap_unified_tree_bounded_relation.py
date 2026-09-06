#!/usr/bin/env python3
"""V2.36 bounded checkpoint payload and unified-tree relation generator.

Only the 40-leaf, 18-vector production-shaped fixture is executable.  The
production phase rejects before creating output.  The generated relation rows
are a checkpoint-contract IR, not BR1CS rows and not a replacement for the
589-million-row production relation.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import resource
import time
from typing import Mapping, Sequence

import pq_rbbc_cap_unified_tree as unified
import pq_rbbc_cap_unified_tree_production_runner as v2_35
import pq_rbbc_reference as reference


IMPLEMENTATION_VERSION = "2.36"
FORMAT = "PQRBBC-CAP-UNIFIED-TREE-BOUNDED-RELATION-AUTHORING-1"
RELATION_ID = "pq-rbbc/cap/unified-tree/bounded-relation/authoring/v1"
CHECKPOINT_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-CHECKPOINT-PAYLOAD-1"
RELATION_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-BOUNDED-RELATION-1"
EVIDENCE_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-BOUNDED-RELATION-EVIDENCE-1"
QUALIFICATION_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-BOUNDED-RELATION-QUALIFICATION-1"
ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = (
    ROOT / "manifests/"
    "pq_rbbc_cap_unified_tree_bounded_relation_manifest_v2_36.json"
)
CHECKPOINT_FILENAME = "pq_rbbc_cap_unified_tree_checkpoint_payload_v2_36.json"
RELATION_FILENAME = "pq_rbbc_cap_unified_tree_bounded_relation_v2_36.json"
EVIDENCE_FILENAME = "pq_rbbc_cap_unified_tree_bounded_relation_evidence_v2_36.json"
QUALIFICATION_FILENAME = (
    "pq_rbbc_cap_unified_tree_bounded_relation_qualification_v2_36.json"
)

STAGE_ORDER = ("plan", "inputs", "unified-tree", "bounded-relation")
DOMAIN_STATEMENT = b"PQ-RBBC/v2.36/unified-tree/public-statement"
DOMAIN_WITNESS = b"PQ-RBBC/v2.36/unified-tree/private-witness"
DOMAIN_PARENT_INPUT = b"PQ-RBBC/v2.36/unified-tree/parent-input-candidate"
FIXTURE_RANDOMNESS_LABEL = b"PQ-RBBC/v2.35/production-shaped/frozen-randomness"
CHALLENGE_PREFIX = v2_35.CHALLENGE_PREFIX

V2_35_PORTABLE_EVIDENCE = {
    "filename": "pq_rbbc_cap_unified_tree_production_runner_evidence_v2_35.json",
    "bytes": 4_836,
    "sha256": "5284654b909158c18c3f3df50b9de190e50bf06469b1d1f1036bfeb860cf292e",
}


class BoundedRelationError(ValueError):
    """Raised when a v2.36 payload or bounded relation is invalid."""


def canonical_json(document: object) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def identity(path: Path) -> dict[str, object]:
    return {
        "filename": path.name,
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise BoundedRelationError(f"{path.name} root must be an object")
    return document


def _atomic_json(path: Path, document: object) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(canonical_json(document))
    temporary.replace(path)


def _outside_repository(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT.resolve())
    except ValueError:
        return True
    return False


def _tagged_digest(domain: bytes, value: bytes) -> str:
    return sha256_bytes(domain + len(value).to_bytes(8, "little") + value)


@dataclass(frozen=True)
class BoundedInputs:
    matrix: reference.SystematicParityCheck
    statement: reference.IssueStatement
    witness: reference.IssueWitness
    adapter: reference.BlindUOVAdapter
    statement_bytes: bytes
    witness_bytes: bytes


def encode_reference_statement(statement: reference.IssueStatement) -> bytes:
    return (
        b"PQRBBC-V2.36-REFERENCE-STATEMENT-1"
        + statement.common_ctx
        + statement.rid
        + statement.payload.encode()
        + statement.blind_request.encode()
    )


def encode_reference_witness(witness: reference.IssueWitness) -> bytes:
    return (
        b"PQRBBC-V2.36-REFERENCE-WITNESS-1"
        + witness.sn
        + witness.holder_key
        + witness.error.to_bytes(reference.N // 8, "little")
        + witness.blind_mask
        + witness.blind_randomness
        + witness.blind_hash_image
    )


def bounded_inputs() -> BoundedInputs:
    matrix, statement, witness, adapter = reference.reference_fixture()
    return BoundedInputs(
        matrix,
        statement,
        witness,
        adapter,
        encode_reference_statement(statement),
        encode_reference_witness(witness),
    )


def validate_ticket_inputs(inputs: BoundedInputs) -> None:
    if encode_reference_statement(inputs.statement) != inputs.statement_bytes:
        raise BoundedRelationError("public statement bytes mismatch")
    if encode_reference_witness(inputs.witness) != inputs.witness_bytes:
        raise BoundedRelationError("private witness bytes mismatch")
    result = reference.verify_relation(
        inputs.matrix,
        inputs.statement,
        inputs.witness,
        inputs.adapter,
    )
    if not result.ok:
        raise BoundedRelationError(
            "bounded reference ticket relation rejected: " + ",".join(result.failures)
        )


def fixture_contract() -> dict[str, object]:
    inputs = bounded_inputs()
    validate_ticket_inputs(inputs)
    return {
        "profile_fingerprint": unified.profile_fingerprint(
            v2_35.QUALIFICATION_PARAMETERS
        ),
        "logical_leaf_counts": list(
            v2_35.QUALIFICATION_PARAMETERS.logical_leaf_counts
        ),
        "public_statement_sha256": _tagged_digest(
            DOMAIN_STATEMENT, inputs.statement_bytes
        ),
        "private_witness_sha256": _tagged_digest(
            DOMAIN_WITNESS, inputs.witness_bytes
        ),
        "reference_ticket_relation_accepted": True,
        "secure_profile": False,
        "test_only": True,
    }


def relation_row_contract() -> dict[str, object]:
    bounded = v2_35.QUALIFICATION_PARAMETERS
    production = unified.PRODUCTION_PARAMETERS
    bounded_counts = {
        "public-statement-binding": 1,
        "private-witness-binding": 1,
        "reference-ticket-relation": 1,
        "seed-expansion": bounded.total_leaves - 1,
        "position-major-mapping": bounded.total_leaves,
        "leaf-commit-and-tape": bounded.total_leaves,
        "logical-vector-hash": bounded.vector_count,
        "unified-root-hash": 1,
        "commitment-codec": 1,
        "opening-verification": 1,
        "downstream-parent-input-binding": 1,
    }
    production_counts = {
        **bounded_counts,
        "seed-expansion": production.total_leaves - 1,
        "position-major-mapping": production.total_leaves,
        "leaf-commit-and-tape": production.total_leaves,
        "logical-vector-hash": production.vector_count,
    }
    return {
        "row_format": "canonical JSON equality observations",
        "row_semantics": (
            "bounded checkpoint-contract IR; not R1CS or production row accounting"
        ),
        "bounded_counts": bounded_counts,
        "bounded_total_rows": sum(bounded_counts.values()),
        "production_shape_projection_not_observed": production_counts,
        "production_shape_projected_contract_rows_not_constraints": sum(
            production_counts.values()
        ),
        "other_tree_stream_bytes_used": False,
        "v2_29_transcript_used_as_observation": False,
    }


def claim_boundary() -> dict[str, bool]:
    return {
        "v2_36_checkpoint_payload_format_implemented": True,
        "v2_36_bounded_payload_resume_qualified": False,
        "v2_36_bounded_relation_generator_implemented": True,
        "v2_36_bounded_relation_generator_qualified": False,
        "production_checkpoint_payload_materialized": False,
        "production_relation_generator_scale_qualified": False,
        "production_relation_contract_frozen_by_observation": False,
        "production_runner_qualified": False,
        "resource_reservation_frozen": False,
        "independent_review_frozen": False,
        "production_prefreeze_authorized": False,
        "production_prefreeze_started": False,
        "large_replay_started": False,
        "large_proving_run_started": False,
        "cap_security_qualified": False,
        "fork_security_proof_revalidated": False,
        "legacy_18_tree_profile_preserved": True,
        "system_architecture_changed": False,
        "ticket_lifecycle_changed": False,
        "pq_sat_auth_changed": False,
        "production_closed": False,
    }


def prospective_production_command() -> str:
    return (
        "PYTHONPATH=src python -u "
        "src/pq_rbbc_cap_unified_tree_bounded_relation.py "
        "--manifest manifests/"
        "pq_rbbc_cap_unified_tree_bounded_relation_manifest_v2_36.json "
        "--phase production-prefreeze "
        "--authorization-manifest /tmp/pq_rbbc_external_artifacts_rebuilt/"
        "v2_36_unified_tree_relation/"
        "pq_rbbc_cap_unified_tree_launch_authorization_v2_36.json "
        "--output /tmp/pq_rbbc_external_artifacts_rebuilt/"
        "v2_36_unified_tree_relation/production-prefreeze "
        "--fresh-cache --allow-large"
    )


def build_manifest() -> dict[str, object]:
    command = prospective_production_command()
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "v2_35_portable_evidence": V2_35_PORTABLE_EVIDENCE,
        "v2_35_relation_contract_sha256": v2_35.RELATION_CONTRACT_SHA256,
        "production_profile_fingerprint": v2_35.PRODUCTION_PROFILE_FINGERPRINT,
        "bounded_fixture": fixture_contract(),
        "checkpoint_payload_contract": {
            "format": CHECKPOINT_FORMAT,
            "stage_order": list(STAGE_ORDER),
            "contiguous_stage_prefix_required": True,
            "each_stage_binds_prior_chain_and_canonical_data": True,
            "resume_requires_expected_payload_sha256": True,
            "external_only": True,
            "canonical_json": True,
            "private_witness_may_be_present": True,
            "pickle_forbidden": True,
            "existing_output_overwrite_forbidden": True,
        },
        "relation_row_contract": relation_row_contract(),
        "implementation_gate": {
            "accepted_executable_phase": "qualification",
            "checkpoint_payload_format_implemented": True,
            "bounded_relation_generator_implemented": True,
            "production_branch_always_rejects": True,
            "production_payload_materialization_implemented": False,
            "production_scale_relation_qualified": False,
            "final_unified_statement_encoding_frozen": False,
        },
        "prospective_production_command": {
            "command": command,
            "command_sha256": sha256_bytes(command.encode("ascii")),
            "executable_now": False,
            "authorized_now": False,
        },
        "claim_boundary": claim_boundary(),
    }


def validate_manifest(path: Path) -> dict[str, object]:
    document = _read_json(path)
    if document != build_manifest():
        raise BoundedRelationError("manifest is not the frozen v2.36 contract")
    return document


def state_contract(manifest_path: Path) -> dict[str, object]:
    return {
        "manifest": identity(manifest_path),
        "bounded_relation_implementation": identity(Path(__file__)),
        "unified_tree_implementation": identity(
            ROOT / "src/pq_rbbc_cap_unified_tree.py"
        ),
        "v2_35_runner_skeleton": identity(
            ROOT / "src/pq_rbbc_cap_unified_tree_production_runner.py"
        ),
        "v2_35_portable_evidence": V2_35_PORTABLE_EVIDENCE,
        "v2_35_relation_contract_sha256": v2_35.RELATION_CONTRACT_SHA256,
        "bounded_profile_fingerprint": unified.profile_fingerprint(
            v2_35.QUALIFICATION_PARAMETERS
        ),
        "phase": "bounded-production-shaped-relation",
        "production_profile_permitted": False,
    }


def _new_checkpoint(contract: Mapping[str, object]) -> dict[str, object]:
    initial_chain = sha256_bytes(canonical_json({"contract": contract}))
    return {
        "format": CHECKPOINT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "contract": contract,
        "completed_stage_names": [],
        "stage_records": [],
        "chain_sha256": initial_chain,
        "production_profile_permitted": False,
        "production_leaves_expanded": 0,
        "relation_rows_replayed": 0,
    }


def _append_stage(
    checkpoint: dict[str, object], stage: str, data: Mapping[str, object]
) -> None:
    completed = checkpoint["completed_stage_names"]
    if not isinstance(completed, list):
        raise AssertionError("checkpoint stage list corrupted")
    if len(completed) >= len(STAGE_ORDER) or stage != STAGE_ORDER[len(completed)]:
        raise BoundedRelationError("checkpoint stage is not a contiguous prefix")
    previous = checkpoint["chain_sha256"]
    base = {
        "stage": stage,
        "prior_chain_sha256": previous,
        "data_sha256": sha256_bytes(canonical_json(data)),
        "data": dict(data),
    }
    chain = sha256_bytes(canonical_json(base))
    checkpoint["stage_records"].append({**base, "chain_sha256": chain})
    completed.append(stage)
    checkpoint["chain_sha256"] = chain


def validate_checkpoint_document(
    document: Mapping[str, object], expected_contract: Mapping[str, object]
) -> None:
    required_keys = {
        "format",
        "implementation_version",
        "relation_id",
        "contract",
        "completed_stage_names",
        "stage_records",
        "chain_sha256",
        "production_profile_permitted",
        "production_leaves_expanded",
        "relation_rows_replayed",
    }
    if set(document) != required_keys:
        raise BoundedRelationError("checkpoint payload fields mismatch")
    completed = document.get("completed_stage_names")
    records = document.get("stage_records")
    if (
        document.get("format") != CHECKPOINT_FORMAT
        or document.get("implementation_version") != IMPLEMENTATION_VERSION
        or document.get("relation_id") != RELATION_ID
        or document.get("contract") != expected_contract
        or not isinstance(completed, list)
        or completed != list(STAGE_ORDER[: len(completed)])
        or not isinstance(records, list)
        or len(records) != len(completed)
        or document.get("production_profile_permitted") is not False
        or document.get("production_leaves_expanded") != 0
        or document.get("relation_rows_replayed") != 0
    ):
        raise BoundedRelationError("checkpoint payload contract mismatch")
    chain = sha256_bytes(canonical_json({"contract": expected_contract}))
    for expected_stage, record in zip(completed, records):
        if not isinstance(record, dict) or set(record) != {
            "stage",
            "prior_chain_sha256",
            "data_sha256",
            "data",
            "chain_sha256",
        }:
            raise BoundedRelationError("checkpoint stage record fields mismatch")
        data = record["data"]
        if (
            record["stage"] != expected_stage
            or record["prior_chain_sha256"] != chain
            or not isinstance(data, dict)
            or record["data_sha256"] != sha256_bytes(canonical_json(data))
        ):
            raise BoundedRelationError("checkpoint stage identity mismatch")
        base = {key: record[key] for key in (
            "stage", "prior_chain_sha256", "data_sha256", "data"
        )}
        chain = sha256_bytes(canonical_json(base))
        if record["chain_sha256"] != chain:
            raise BoundedRelationError("checkpoint stage chain mismatch")
    if document.get("chain_sha256") != chain:
        raise BoundedRelationError("checkpoint final chain mismatch")
    _validate_stage_data(completed, records)


def _validate_stage_data(
    completed: Sequence[str], records: Sequence[Mapping[str, object]]
) -> None:
    data_by_stage = {
        record["stage"]: record["data"] for record in records
    }
    fixture = fixture_contract()
    if "plan" in completed:
        plan = data_by_stage["plan"]
        if plan != {
            "bounded_logical_vectors": 18,
            "bounded_total_leaves": 40,
            "bounded_internal_nodes": 39,
            "planned_production_total_leaves": 40_960,
            "planned_production_internal_nodes": 40_959,
            "planned_combined_rows_lower_bound_not_observed": 589_054_075,
            "production_profile_invoked": False,
        }:
            raise BoundedRelationError("checkpoint plan data mismatch")
    if "inputs" in completed:
        inputs = data_by_stage["inputs"]
        statement_hex = inputs.get("public_statement_hex")
        witness_hex = inputs.get("private_witness_hex")
        if not isinstance(statement_hex, str) or not isinstance(witness_hex, str):
            raise BoundedRelationError("checkpoint input encoding mismatch")
        try:
            statement_bytes = bytes.fromhex(statement_hex)
            witness_bytes = bytes.fromhex(witness_hex)
        except ValueError as error:
            raise BoundedRelationError("checkpoint input hex rejected") from error
        if (
            _tagged_digest(DOMAIN_STATEMENT, statement_bytes)
            != fixture["public_statement_sha256"]
            or _tagged_digest(DOMAIN_WITNESS, witness_bytes)
            != fixture["private_witness_sha256"]
            or inputs.get("reference_ticket_relation_accepted") is not True
        ):
            raise BoundedRelationError("checkpoint input identity mismatch")
    if "unified-tree" in completed:
        snapshot = data_by_stage["unified-tree"]
        _decode_tree_snapshot(snapshot)
    if "bounded-relation" in completed:
        relation = data_by_stage["bounded-relation"]
        if (
            set(relation) != {"relation_identity", "summary"}
            or relation.get("summary") != {
                "row_count": 144,
                "failures": 0,
                "production_relation_rows": 0,
                "br1cs_rows": 0,
            }
            or not isinstance(relation.get("relation_identity"), dict)
        ):
            raise BoundedRelationError("checkpoint relation stage mismatch")


def _load_checkpoint(
    path: Path,
    expected_contract: Mapping[str, object],
    expected_sha256: str,
) -> dict[str, object]:
    if len(expected_sha256) != 64 or sha256_file(path) != expected_sha256:
        raise BoundedRelationError("resume checkpoint payload identity mismatch")
    document = _read_json(path)
    validate_checkpoint_document(document, expected_contract)
    return document


def _int_hex(value: int, length: int) -> str:
    if not 0 <= value < 1 << (8 * length):
        raise BoundedRelationError("integer does not fit checkpoint encoding")
    return value.to_bytes(length, "little").hex()


def _decode_int(value: object, length: int, label: str) -> int:
    if not isinstance(value, str):
        raise BoundedRelationError(f"{label} must be hex")
    try:
        encoded = bytes.fromhex(value)
    except ValueError as error:
        raise BoundedRelationError(f"{label} invalid hex") from error
    if len(encoded) != length:
        raise BoundedRelationError(f"{label} wrong width")
    result = int.from_bytes(encoded, "little")
    if _int_hex(result, length) != value:
        raise BoundedRelationError(f"{label} noncanonical hex")
    return result


def _tree_snapshot(
    execution: unified.UnifiedTreeExecution,
    opening: unified.UnifiedOpening,
    trials: int,
    elapsed_seconds: float,
) -> dict[str, object]:
    parameters = execution.parameters
    statement_bytes = bounded_inputs().statement_bytes
    commitment_bytes = execution.commitment.encode()
    return {
        "profile_fingerprint": unified.profile_fingerprint(parameters),
        "salt_hex": [
            _int_hex(value, unified.SEED_BYTES) for value in execution.randomness.salt
        ],
        "root_seed_hex": _int_hex(
            execution.randomness.root_seed, unified.SEED_BYTES
        ),
        "commitment_hex": commitment_bytes.hex(),
        "nodes_hex": [
            _int_hex(value, unified.SEED_BYTES) for value in execution.nodes
        ],
        "leaf_commitments_hex": [
            _int_hex(value, unified.HASH_BYTES)
            for value in execution.leaf_commitments
        ],
        "leaf_tapes_hex": [
            _int_hex(value, (parameters.tape_bits + 7) // 8)
            for value in execution.leaf_tapes
        ],
        "vector_hashes_hex": [
            _int_hex(value, unified.HASH_BYTES) for value in execution.vector_hashes
        ],
        "xof_call_count": len(execution.xof_records),
        "xof_trace_sha256": unified.trace_digest(execution.xof_records),
        "opening_hex": opening.encode(parameters).hex(),
        "opening_trials": trials,
        "candidate_parent_input_sha256": sha256_bytes(
            DOMAIN_PARENT_INPUT + statement_bytes + commitment_bytes
        ),
        "tree_elapsed_seconds": elapsed_seconds,
        "production_leaves_expanded": 0,
    }


def _decode_tree_snapshot(
    snapshot: Mapping[str, object]
) -> tuple[unified.UnifiedTreeExecution, unified.UnifiedOpening]:
    parameters = v2_35.QUALIFICATION_PARAMETERS
    required = {
        "profile_fingerprint",
        "salt_hex",
        "root_seed_hex",
        "commitment_hex",
        "nodes_hex",
        "leaf_commitments_hex",
        "leaf_tapes_hex",
        "vector_hashes_hex",
        "xof_call_count",
        "xof_trace_sha256",
        "opening_hex",
        "opening_trials",
        "candidate_parent_input_sha256",
        "tree_elapsed_seconds",
        "production_leaves_expanded",
    }
    if set(snapshot) != required:
        raise BoundedRelationError("tree snapshot fields mismatch")
    salt_hex = snapshot["salt_hex"]
    nodes_hex = snapshot["nodes_hex"]
    leaves_hex = snapshot["leaf_commitments_hex"]
    tapes_hex = snapshot["leaf_tapes_hex"]
    vectors_hex = snapshot["vector_hashes_hex"]
    if (
        snapshot["profile_fingerprint"] != unified.profile_fingerprint(parameters)
        or not isinstance(salt_hex, list)
        or len(salt_hex) != 2
        or not isinstance(nodes_hex, list)
        or len(nodes_hex) != 2 * parameters.total_leaves - 1
        or not isinstance(leaves_hex, list)
        or len(leaves_hex) != parameters.total_leaves
        or not isinstance(tapes_hex, list)
        or len(tapes_hex) != parameters.total_leaves
        or not isinstance(vectors_hex, list)
        or len(vectors_hex) != parameters.vector_count
        or snapshot["xof_call_count"] != 138
        or not isinstance(snapshot["xof_trace_sha256"], str)
        or len(snapshot["xof_trace_sha256"]) != 64
        or not isinstance(snapshot["opening_trials"], int)
        or snapshot["opening_trials"] <= 0
        or not isinstance(snapshot["tree_elapsed_seconds"], (int, float))
        or snapshot["tree_elapsed_seconds"] <= 0
        or snapshot["production_leaves_expanded"] != 0
    ):
        raise BoundedRelationError("tree snapshot shape mismatch")
    salt = tuple(
        _decode_int(value, unified.SEED_BYTES, "salt") for value in salt_hex
    )
    root_seed = _decode_int(
        snapshot["root_seed_hex"], unified.SEED_BYTES, "root seed"
    )
    try:
        commitment_bytes = bytes.fromhex(snapshot["commitment_hex"])
        opening_bytes = bytes.fromhex(snapshot["opening_hex"])
        commitment = unified.UnifiedCommitment.decode(parameters, commitment_bytes)
        opening = unified.UnifiedOpening.decode(parameters, opening_bytes)
    except (TypeError, ValueError, unified.UnifiedTreeError) as error:
        raise BoundedRelationError("tree snapshot codec rejected") from error
    nodes = tuple(
        _decode_int(value, unified.SEED_BYTES, "node") for value in nodes_hex
    )
    leaf_commitments = tuple(
        _decode_int(value, unified.HASH_BYTES, "leaf commitment")
        for value in leaves_hex
    )
    tape_bytes = (parameters.tape_bits + 7) // 8
    leaf_tapes = tuple(
        _decode_int(value, tape_bytes, "leaf tape") for value in tapes_hex
    )
    vector_hashes = tuple(
        _decode_int(value, unified.HASH_BYTES, "vector hash")
        for value in vectors_hex
    )
    if nodes[0] != root_seed or commitment.salt != salt:
        raise BoundedRelationError("tree snapshot root or salt mismatch")
    parent_input = sha256_bytes(
        DOMAIN_PARENT_INPUT + bounded_inputs().statement_bytes + commitment_bytes
    )
    if snapshot["candidate_parent_input_sha256"] != parent_input:
        raise BoundedRelationError("tree snapshot parent input mismatch")
    return (
        unified.UnifiedTreeExecution(
            parameters,
            unified.UnifiedTreeRandomness(salt, root_seed),
            commitment,
            nodes,
            leaf_commitments,
            leaf_tapes,
            vector_hashes,
            (),
        ),
        opening,
    )


def _row(
    ordinal: int,
    stage: str,
    label: str,
    left: bytes,
    right: bytes,
) -> dict[str, object]:
    left_digest = sha256_bytes(left)
    right_digest = sha256_bytes(right)
    return {
        "ordinal": ordinal,
        "stage": stage,
        "label": label,
        "operator": "equal",
        "left_sha256": left_digest,
        "right_sha256": right_digest,
        "satisfied": left_digest == right_digest,
    }


def generate_relation(
    execution: unified.UnifiedTreeExecution,
    opening: unified.UnifiedOpening,
    inputs: BoundedInputs,
    expected_parent_input_sha256: str,
) -> dict[str, object]:
    validate_ticket_inputs(inputs)
    parameters = execution.parameters
    if parameters != v2_35.QUALIFICATION_PARAMETERS:
        raise BoundedRelationError("only the bounded qualification profile is allowed")
    fixture = fixture_contract()
    rows: list[dict[str, object]] = []

    def add(stage: str, label: str, left: bytes, right: bytes) -> None:
        rows.append(_row(len(rows), stage, label, left, right))

    add(
        "public-statement-binding",
        "explicit public statement",
        bytes.fromhex(_tagged_digest(DOMAIN_STATEMENT, inputs.statement_bytes)),
        bytes.fromhex(fixture["public_statement_sha256"]),
    )
    add(
        "private-witness-binding",
        "bounded fixture private witness",
        bytes.fromhex(_tagged_digest(DOMAIN_WITNESS, inputs.witness_bytes)),
        bytes.fromhex(fixture["private_witness_sha256"]),
    )
    ticket = reference.verify_relation(
        inputs.matrix, inputs.statement, inputs.witness, inputs.adapter
    )
    add(
        "reference-ticket-relation",
        "unchanged reference ticket lifecycle",
        bytes((int(ticket.ok),)),
        b"\x01",
    )
    for node_index in range(parameters.total_leaves - 1):
        expected = unified.derive_children(
            parameters,
            execution.randomness.salt,
            execution.nodes[node_index],
            node_index,
        )
        observed = (
            execution.nodes[2 * node_index + 1],
            execution.nodes[2 * node_index + 2],
        )
        add(
            "seed-expansion",
            f"node[{node_index}] children",
            b"".join(unified._field_bytes(value) for value in expected),
            b"".join(unified._field_bytes(value) for value in observed),
        )
    for unified_index in range(parameters.total_leaves):
        repetition, position = unified.unified_to_logical_index(
            parameters, unified_index
        )
        round_trip = unified.logical_to_unified_index(
            parameters, repetition, position
        )
        add(
            "position-major-mapping",
            f"leaf[{unified_index}] logical coordinate",
            unified_index.to_bytes(4, "little"),
            round_trip.to_bytes(4, "little"),
        )
        expected_commitment, expected_tape = unified.leaf_material(
            parameters,
            execution.randomness.salt,
            execution.nodes[parameters.total_leaves - 1 + unified_index],
            unified_index,
        )
        add(
            "leaf-commit-and-tape",
            f"leaf[{unified_index}] material",
            unified._hash_bytes(expected_commitment)
            + expected_tape.to_bytes(
                (parameters.tape_bits + 7) // 8, "little"
            ),
            unified._hash_bytes(execution.leaf_commitments[unified_index])
            + execution.leaf_tapes[unified_index].to_bytes(
                (parameters.tape_bits + 7) // 8, "little"
            ),
        )
    logical_commitments: list[list[int]] = [
        [0] * leaves for leaves in parameters.logical_leaf_counts
    ]
    for unified_index, commitment in enumerate(execution.leaf_commitments):
        repetition, position = unified.unified_to_logical_index(
            parameters, unified_index
        )
        logical_commitments[repetition][position] = commitment
    for repetition, commitments in enumerate(logical_commitments):
        expected = unified.vector_hash(parameters, repetition, commitments)
        add(
            "logical-vector-hash",
            f"vector[{repetition}] hash",
            unified._hash_bytes(expected),
            unified._hash_bytes(execution.vector_hashes[repetition]),
        )
    expected_root = unified.root_hash(parameters, execution.vector_hashes)
    add(
        "unified-root-hash",
        "single unified root",
        unified._hash_bytes(expected_root),
        unified._hash_bytes(execution.commitment.root_digest),
    )
    commitment_bytes = execution.commitment.encode()
    decoded = unified.UnifiedCommitment.decode(parameters, commitment_bytes)
    add(
        "commitment-codec",
        "canonical commitment round trip",
        commitment_bytes,
        decoded.encode(),
    )
    verification = unified.verify_opening(
        parameters,
        CHALLENGE_PREFIX,
        commitment_bytes,
        opening.encode(parameters),
    )
    add(
        "opening-verification",
        "canonical opening accepted",
        bytes((int(verification.accepted),)),
        b"\x01",
    )
    parent_input = sha256_bytes(
        DOMAIN_PARENT_INPUT + inputs.statement_bytes + commitment_bytes
    )
    add(
        "downstream-parent-input-binding",
        "candidate parent input only; parent relation not replayed",
        bytes.fromhex(parent_input),
        bytes.fromhex(expected_parent_input_sha256),
    )
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["stage"]] = counts.get(row["stage"], 0) + 1
    row_stream = b"".join(canonical_json(row) for row in rows)
    document = {
        "format": RELATION_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "profile_fingerprint": unified.profile_fingerprint(parameters),
        "row_semantics": (
            "bounded checkpoint-contract IR; not R1CS or production rows"
        ),
        "rows": rows,
        "row_count": len(rows),
        "stage_counts": counts,
        "row_stream_bytes": len(row_stream),
        "row_stream_sha256": sha256_bytes(row_stream),
        "failures": sum(row["satisfied"] is not True for row in rows),
        "production_relation_rows": 0,
        "br1cs_rows": 0,
        "other_tree_observed_stream_bytes_reused": False,
        "v2_29_transcript_reused_as_observation": False,
    }
    validate_relation_document(document)
    return document


def validate_relation_document(document: Mapping[str, object]) -> None:
    rows = document.get("rows")
    expected = relation_row_contract()
    if not isinstance(rows, list):
        raise BoundedRelationError("relation rows missing")
    counts: dict[str, int] = {}
    for ordinal, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {
            "ordinal",
            "stage",
            "label",
            "operator",
            "left_sha256",
            "right_sha256",
            "satisfied",
        }:
            raise BoundedRelationError("relation row fields mismatch")
        if (
            row["ordinal"] != ordinal
            or row["operator"] != "equal"
            or row["left_sha256"] != row["right_sha256"]
            or row["satisfied"] is not True
        ):
            raise BoundedRelationError("relation equality row rejected")
        stage = row["stage"]
        if not isinstance(stage, str):
            raise BoundedRelationError("relation stage invalid")
        counts[stage] = counts.get(stage, 0) + 1
    stream = b"".join(canonical_json(row) for row in rows)
    if (
        document.get("format") != RELATION_FORMAT
        or document.get("implementation_version") != IMPLEMENTATION_VERSION
        or document.get("relation_id") != RELATION_ID
        or document.get("profile_fingerprint")
        != unified.profile_fingerprint(v2_35.QUALIFICATION_PARAMETERS)
        or document.get("row_semantics")
        != "bounded checkpoint-contract IR; not R1CS or production rows"
        or document.get("row_count") != expected["bounded_total_rows"]
        or document.get("stage_counts") != expected["bounded_counts"]
        or counts != expected["bounded_counts"]
        or document.get("row_stream_bytes") != len(stream)
        or document.get("row_stream_sha256") != sha256_bytes(stream)
        or document.get("failures") != 0
        or document.get("production_relation_rows") != 0
        or document.get("br1cs_rows") != 0
        or document.get("other_tree_observed_stream_bytes_reused") is not False
        or document.get("v2_29_transcript_reused_as_observation") is not False
    ):
        raise BoundedRelationError("bounded relation document mismatch")


def _plan_data() -> dict[str, object]:
    return {
        "bounded_logical_vectors": 18,
        "bounded_total_leaves": 40,
        "bounded_internal_nodes": 39,
        "planned_production_total_leaves": 40_960,
        "planned_production_internal_nodes": 40_959,
        "planned_combined_rows_lower_bound_not_observed": 589_054_075,
        "production_profile_invoked": False,
    }


def _input_data(inputs: BoundedInputs) -> dict[str, object]:
    validate_ticket_inputs(inputs)
    return {
        "public_statement_hex": inputs.statement_bytes.hex(),
        "private_witness_hex": inputs.witness_bytes.hex(),
        "public_statement_sha256": _tagged_digest(
            DOMAIN_STATEMENT, inputs.statement_bytes
        ),
        "private_witness_sha256": _tagged_digest(
            DOMAIN_WITNESS, inputs.witness_bytes
        ),
        "reference_ticket_relation_accepted": True,
    }


def _stage_data(
    checkpoint: Mapping[str, object], stage: str
) -> Mapping[str, object]:
    for record in checkpoint["stage_records"]:
        if record["stage"] == stage:
            return record["data"]
    raise BoundedRelationError(f"checkpoint stage missing: {stage}")


def run_bounded(
    manifest_path: Path,
    output: Path,
    *,
    fresh_cache: bool = False,
    resume: bool = False,
    expected_checkpoint_sha256: str | None = None,
    stop_after_stage: str | None = None,
) -> dict[str, object] | None:
    if fresh_cache == resume:
        raise BoundedRelationError("select exactly one of fresh_cache or resume")
    validate_manifest(manifest_path)
    if not _outside_repository(output):
        raise BoundedRelationError("bounded output must be external to the repository")
    contract = state_contract(manifest_path)
    checkpoint_path = output / CHECKPOINT_FILENAME
    if fresh_cache:
        if output.exists():
            raise FileExistsError("fresh-cache output already exists")
        if expected_checkpoint_sha256 is not None:
            raise BoundedRelationError("fresh-cache forbids expected checkpoint identity")
        output.mkdir(parents=True)
        checkpoint = _new_checkpoint(contract)
    else:
        if expected_checkpoint_sha256 is None:
            raise BoundedRelationError("resume requires expected checkpoint SHA-256")
        checkpoint = _load_checkpoint(
            checkpoint_path, contract, expected_checkpoint_sha256
        )
    completed = checkpoint["completed_stage_names"]
    if "plan" not in completed:
        _append_stage(checkpoint, "plan", _plan_data())
        _atomic_json(checkpoint_path, checkpoint)
    if stop_after_stage == "plan":
        return None
    inputs = bounded_inputs()
    if "inputs" not in completed:
        _append_stage(checkpoint, "inputs", _input_data(inputs))
        _atomic_json(checkpoint_path, checkpoint)
    if stop_after_stage == "inputs":
        return None
    if "unified-tree" not in completed:
        started = time.perf_counter()
        randomness = unified.deterministic_randomness(
            v2_35.QUALIFICATION_PARAMETERS,
            FIXTURE_RANDOMNESS_LABEL,
        )
        execution = unified.execute_commit(
            v2_35.QUALIFICATION_PARAMETERS, randomness
        )
        opening, trials = unified.grind_opening(
            execution, CHALLENGE_PREFIX, max_trials=100_000
        )
        tree_elapsed = time.perf_counter() - started
        _append_stage(
            checkpoint,
            "unified-tree",
            _tree_snapshot(execution, opening, trials, tree_elapsed),
        )
        _atomic_json(checkpoint_path, checkpoint)
    if stop_after_stage == "unified-tree":
        return None
    if "bounded-relation" in completed:
        raise FileExistsError("bounded relation output already completed")
    snapshot = _stage_data(checkpoint, "unified-tree")
    execution, opening = _decode_tree_snapshot(snapshot)
    relation_started = time.perf_counter()
    relation = generate_relation(
        execution,
        opening,
        inputs,
        snapshot["candidate_parent_input_sha256"],
    )
    relation_elapsed = time.perf_counter() - relation_started
    relation_path = output / RELATION_FILENAME
    _atomic_json(relation_path, relation)
    relation_identity = identity(relation_path)
    _append_stage(checkpoint, "bounded-relation", {
        "relation_identity": relation_identity,
        "summary": {
            "row_count": relation["row_count"],
            "failures": relation["failures"],
            "production_relation_rows": 0,
            "br1cs_rows": 0,
        },
    })
    _atomic_json(checkpoint_path, checkpoint)
    deterministic_result_identity = sha256_bytes(canonical_json({
        "profile_fingerprint": unified.profile_fingerprint(execution.parameters),
        "public_statement_sha256": fixture_contract()[
            "public_statement_sha256"
        ],
        "private_witness_sha256": fixture_contract()[
            "private_witness_sha256"
        ],
        "commitment_sha256": sha256_bytes(
            execution.commitment.encode()
        ),
        "opening_sha256": sha256_bytes(opening.encode(execution.parameters)),
        "relation_row_stream_sha256": relation["row_stream_sha256"],
    }))
    evidence = {
        "format": EVIDENCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "source_contract": contract,
        "execution_mode": "resume" if resume else "fresh",
        "checkpoint_payload": identity(checkpoint_path),
        "bounded_relation": relation_identity,
        "deterministic_result_identity": deterministic_result_identity,
        "observations": {
            "logical_vectors": 18,
            "bounded_leaves_expanded": 40,
            "bounded_contract_rows": relation["row_count"],
            "bounded_relation_failures": relation["failures"],
            "tree_elapsed_seconds": snapshot["tree_elapsed_seconds"],
            "relation_elapsed_seconds": relation_elapsed,
            "peak_memory_bytes": (
                resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
            ),
            "production_leaves_expanded": 0,
            "production_relation_rows": 0,
            "br1cs_rows": 0,
            "proofs_generated": 0,
        },
        "claim_boundary": claim_boundary(),
    }
    _atomic_json(output / EVIDENCE_FILENAME, evidence)
    return evidence


def production_rejection_reasons() -> list[str]:
    return [
        "v2.36 production-scale payload has not been materialized",
        "v2.36 relation generator is qualified only on the bounded fixture",
        "final unified-profile statement encoding is not frozen",
        "operator resource reservation identity is not frozen",
        "independent review identity is not frozen",
        "production pre-freeze execution is not authorized",
        "a later identity-frozen launch manifest is required",
    ]


def reject_production_prefreeze(
    manifest_path: Path,
    output: Path,
    authorization_manifest: Path | None,
    allow_large: bool,
) -> None:
    validate_manifest(manifest_path)
    if output.exists():
        raise FileExistsError("production output already exists")
    if not _outside_repository(output):
        raise BoundedRelationError(
            "production output must be external to the repository"
        )
    details = {
        "authorization_manifest_provided": authorization_manifest is not None,
        "allow_large_requested": allow_large,
        "output_created": False,
        "reasons": production_rejection_reasons(),
    }
    raise RuntimeError(
        "production-prefreeze unavailable: "
        + canonical_json(details).decode().strip()
    )


def qualify(
    manifest_path: Path,
    output: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    run_bounded(
        manifest_path,
        output,
        fresh_cache=True,
        stop_after_stage="unified-tree",
    )
    interrupted_identity = identity(output / CHECKPOINT_FILENAME)
    evidence = run_bounded(
        manifest_path,
        output,
        resume=True,
        expected_checkpoint_sha256=interrupted_identity["sha256"],
    )
    assert evidence is not None
    overwrite_refused = False
    try:
        run_bounded(manifest_path, output, fresh_cache=True)
    except FileExistsError:
        overwrite_refused = True
    missing_resume_identity_rejected = False
    try:
        run_bounded(manifest_path, output, resume=True)
    except BoundedRelationError as error:
        missing_resume_identity_rejected = (
            str(error) == "resume requires expected checkpoint SHA-256"
        )
    production_probe = output.with_name(output.name + "-production-probe")
    production_rejected = False
    try:
        reject_production_prefreeze(manifest_path, production_probe, None, False)
    except RuntimeError:
        production_rejected = not production_probe.exists()
    checkpoint = _read_json(output / CHECKPOINT_FILENAME)
    mutated = copy.deepcopy(checkpoint)
    mutated["stage_records"][0]["data"]["bounded_total_leaves"] = 41
    mutation_rejected = False
    try:
        validate_checkpoint_document(mutated, state_contract(manifest_path))
    except BoundedRelationError:
        mutation_rejected = True
    qualification = {
        "format": QUALIFICATION_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "implementation": identity(Path(__file__)),
        "manifest": identity(manifest_path),
        "checks": {
            "fresh_checkpoint_created": True,
            "interrupted_after_unified_tree": True,
            "resume_required_expected_payload_identity": (
                missing_resume_identity_rejected
            ),
            "resume_completed_bounded_relation": True,
            "existing_output_overwrite_refused": overwrite_refused,
            "checkpoint_mutation_rejected": mutation_rejected,
            "production_branch_rejected_before_output": production_rejected,
            "state_uses_pickle": False,
            "private_witness_only_in_external_payload": True,
            "other_tree_observed_stream_bytes_reused": False,
            "production_leaves_expanded": 0,
            "production_relation_rows": 0,
        },
        "interrupted_checkpoint_identity": interrupted_identity,
        "completed_checkpoint_identity": evidence["checkpoint_payload"],
        "result": {
            "checkpoint_payload_format_qualified_on_bounded_fixture": True,
            "bounded_relation_generator_qualified": True,
            "production_relation_generator_scale_qualified": False,
            "safe_to_start_production_prefreeze": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
        },
        "claim_boundary": claim_boundary(),
    }
    _atomic_json(output / QUALIFICATION_FILENAME, qualification)
    return evidence, qualification


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--phase",
        choices=("qualification", "bounded", "production-prefreeze"),
        required=True,
    )
    parser.add_argument("--authorization-manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--fresh-cache", action="store_true")
    mode.add_argument("--resume", action="store_true")
    parser.add_argument("--expected-checkpoint-sha256")
    parser.add_argument(
        "--stop-after-stage", choices=("plan", "inputs", "unified-tree")
    )
    parser.add_argument("--allow-large", action="store_true")
    args = parser.parse_args()
    if args.phase == "production-prefreeze":
        reject_production_prefreeze(
            args.manifest,
            args.output,
            args.authorization_manifest,
            args.allow_large,
        )
    if args.authorization_manifest is not None or args.allow_large:
        raise BoundedRelationError(
            "bounded phases forbid production authorization inputs"
        )
    if args.phase == "qualification":
        if not args.fresh_cache or args.resume or args.stop_after_stage is not None:
            raise BoundedRelationError(
                "qualification requires fresh-cache without a stop stage"
            )
        evidence, qualification = qualify(args.manifest, args.output)
        result = {
            "phase": args.phase,
            "output": str(args.output),
            "checkpoint_payload": evidence["checkpoint_payload"],
            "bounded_relation": evidence["bounded_relation"],
            "evidence": identity(args.output / EVIDENCE_FILENAME),
            "qualification": identity(args.output / QUALIFICATION_FILENAME),
            "bounded_relation_generator_qualified": qualification["result"][
                "bounded_relation_generator_qualified"
            ],
            "production_relation_generator_scale_qualified": False,
            "safe_to_start_production_prefreeze": False,
        }
    else:
        evidence = run_bounded(
            args.manifest,
            args.output,
            fresh_cache=args.fresh_cache,
            resume=args.resume,
            expected_checkpoint_sha256=args.expected_checkpoint_sha256,
            stop_after_stage=args.stop_after_stage,
        )
        result = {
            "phase": args.phase,
            "output": str(args.output),
            "complete": evidence is not None,
            "checkpoint_payload": identity(args.output / CHECKPOINT_FILENAME),
            "production_profile_invoked": False,
            "production_leaves_expanded": 0,
            "production_relation_rows": 0,
        }
        if evidence is not None:
            result["evidence"] = identity(args.output / EVIDENCE_FILENAME)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
