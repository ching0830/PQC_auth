#!/usr/bin/env python3
"""V2.38 bounded streaming materializer and read-only launch preflight.

The record/chunk/checkpoint machinery is executable only against the v2.36
40-leaf checkpoint and the v2.37 bounded parent-input vector.  The production
layout is frozen as a plan, but the production branch always rejects before
creating output.  No legacy tree observation is accepted as unified-profile
evidence.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
from typing import Callable, Mapping, Sequence

import pq_rbbc_cap_unified_statement_parent_abi as abi
import pq_rbbc_cap_unified_tree as unified
import pq_rbbc_cap_unified_tree_bounded_relation as v2_36
import pq_rbbc_cap_unified_tree_production_runner as v2_35


IMPLEMENTATION_VERSION = "2.38"
FORMAT = "PQRBBC-CAP-UNIFIED-TREE-STREAMING-PREFREEZE-AUTHORING-1"
RELATION_ID = "pq-rbbc/cap/unified-tree/streaming-prefreeze/candidate/v1"
ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = (
    ROOT / "manifests/pq_rbbc_cap_unified_tree_streaming_prefreeze_manifest_v2_38.json"
)

STREAM_MAGIC = b"PQRBBC-CAP-UGGM-STREAM-CHUNK-V1"
STREAM_VERSION = 1
CHECKPOINT_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-STREAM-CHECKPOINT-1"
INDEX_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-STREAM-INDEX-1"
EVIDENCE_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-STREAM-EVIDENCE-1"
QUALIFICATION_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-STREAM-QUALIFICATION-1"
PREFLIGHT_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-LAUNCH-PREFLIGHT-1"

CHECKPOINT_FILENAME = "pq_rbbc_cap_unified_tree_stream_checkpoint_v2_38.json"
INDEX_FILENAME = "pq_rbbc_cap_unified_tree_stream_index_v2_38.json"
EVIDENCE_FILENAME = "pq_rbbc_cap_unified_tree_stream_evidence_v2_38.json"
QUALIFICATION_FILENAME = (
    "pq_rbbc_cap_unified_tree_stream_qualification_v2_38.json"
)
PREFLIGHT_FILENAME = "pq_rbbc_cap_unified_tree_launch_preflight_v2_38.json"
CHUNK_DIRECTORY = "chunks"

V2_37_PORTABLE_EVIDENCE = {
    "filename": "pq_rbbc_cap_unified_statement_parent_abi_portable_evidence_v2_37.json",
    "bytes": 5_188,
    "sha256": "672c27f8ed0bfc567d3080c9645c079d9009ce7ff815957c9384dc0246b3c8b7",
}
V2_37_BOUNDED_VECTOR_IDENTITY = {
    "filename": abi.BOUNDED_VECTOR_FILENAME,
    "bytes": 3_062,
    "sha256": "655e3969695b8015a83b1dad29f98c98b15c2f59d41c3890901bd23da62365ff",
}
V2_36_CHECKPOINT_IDENTITY = dict(abi.V2_36_CHECKPOINT_IDENTITY)

PRODUCTION_PROFILE_FINGERPRINT = abi.PRODUCTION_PROFILE_FINGERPRINT
BOUNDED_PROFILE_FINGERPRINT = abi.BOUNDED_PROFILE_FINGERPRINT
BOUNDED_RECORDS_PER_CHUNK = 16
PRODUCTION_RECORDS_PER_CHUNK = 1_024

STAGES = (
    (1, "tree-nodes"),
    (2, "leaf-commitments"),
    (3, "leaf-tapes"),
    (4, "logical-vector-hashes"),
    (5, "unified-commitment"),
    (6, "parent-input"),
)
STAGE_BY_ID = {stage_id: name for stage_id, name in STAGES}
STAGE_ID = {name: stage_id for stage_id, name in STAGES}

RESOURCE_RESERVATION_FILENAME = (
    "pq_rbbc_cap_unified_tree_resource_reservation_v2_38.json"
)
INDEPENDENT_REVIEW_FILENAME = (
    "pq_rbbc_cap_unified_tree_independent_review_v2_38.json"
)
LAUNCH_MANIFEST_FILENAME = "pq_rbbc_cap_unified_tree_launch_manifest_v2_38.json"
RESOURCE_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-RESOURCE-RESERVATION-2"
REVIEW_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-INDEPENDENT-REVIEW-2"
LAUNCH_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-LAUNCH-MANIFEST-1"

MIN_CPU_CORES = 4
MIN_AVAILABLE_MEMORY_BYTES = 16 * (1 << 30)
MIN_FREE_DISK_BYTES = 80 * (1 << 30)
MIN_COMBINED_ROWS_NOT_OBSERVED = 589_054_075
MIN_TWO_REPLAY_ROW_CHECKS_NOT_OBSERVED = 1_178_108_150


class StreamingPrefreezeError(ValueError):
    """Raised when a v2.38 stream, checkpoint, or preflight is invalid."""


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
        raise StreamingPrefreezeError(f"{path.name} root must be an object")
    return document


def _atomic_json(path: Path, document: object) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(canonical_json(document))
    temporary.replace(path)


def _atomic_bytes(path: Path, data: bytes) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(path)


def _outside_repository(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT.resolve())
    except ValueError:
        return True
    return False


def _read_bytes(
    encoded: bytes, offset: int, length: int, label: str
) -> tuple[bytes, int]:
    if length < 0 or offset + length > len(encoded):
        raise StreamingPrefreezeError(f"{label} truncated")
    return encoded[offset : offset + length], offset + length


def _read_uint(
    encoded: bytes, offset: int, width: int, label: str
) -> tuple[int, int]:
    value, offset = _read_bytes(encoded, offset, width, label)
    return int.from_bytes(value, "little"), offset


@dataclass(frozen=True)
class StreamRecord:
    stage: str
    item_index: int
    payload: bytes

    def __post_init__(self) -> None:
        if self.stage not in STAGE_ID:
            raise StreamingPrefreezeError("unknown stream stage")
        if self.item_index < 0:
            raise StreamingPrefreezeError("negative stream item index")
        if not self.payload:
            raise StreamingPrefreezeError("empty stream payload")


@dataclass(frozen=True)
class StreamChunk:
    ordinal: int
    stage: str
    first_item_index: int
    records: tuple[StreamRecord, ...]

    def encode(self, profile_fingerprint: str) -> bytes:
        if profile_fingerprint not in (
            PRODUCTION_PROFILE_FINGERPRINT,
            BOUNDED_PROFILE_FINGERPRINT,
        ):
            raise StreamingPrefreezeError("unsupported stream profile")
        if not self.records or len(self.records) > PRODUCTION_RECORDS_PER_CHUNK:
            raise StreamingPrefreezeError("invalid stream chunk record count")
        expected_indices = tuple(
            range(self.first_item_index, self.first_item_index + len(self.records))
        )
        if any(record.stage != self.stage for record in self.records):
            raise StreamingPrefreezeError("mixed stream chunk stages")
        if tuple(record.item_index for record in self.records) != expected_indices:
            raise StreamingPrefreezeError("noncontiguous stream item indices")
        result = bytearray(STREAM_MAGIC)
        result.extend(STREAM_VERSION.to_bytes(2, "little"))
        result.extend(bytes.fromhex(profile_fingerprint))
        result.extend(self.ordinal.to_bytes(4, "little"))
        result.extend(STAGE_ID[self.stage].to_bytes(2, "little"))
        result.extend(self.first_item_index.to_bytes(8, "little"))
        result.extend(len(self.records).to_bytes(4, "little"))
        for record in self.records:
            result.extend(len(record.payload).to_bytes(4, "little"))
            result.extend(record.payload)
        return bytes(result)

    @classmethod
    def decode(
        cls,
        encoded: bytes,
        expected_profile_fingerprint: str,
        expected_payload_bytes: int,
    ) -> "StreamChunk":
        offset = 0
        magic, offset = _read_bytes(encoded, offset, len(STREAM_MAGIC), "magic")
        if magic != STREAM_MAGIC:
            raise StreamingPrefreezeError("wrong stream chunk magic")
        version, offset = _read_uint(encoded, offset, 2, "version")
        if version != STREAM_VERSION:
            raise StreamingPrefreezeError("wrong stream chunk version")
        fingerprint, offset = _read_bytes(encoded, offset, 32, "profile")
        if fingerprint.hex() != expected_profile_fingerprint:
            raise StreamingPrefreezeError("wrong stream chunk profile")
        ordinal, offset = _read_uint(encoded, offset, 4, "ordinal")
        stage_id, offset = _read_uint(encoded, offset, 2, "stage")
        if stage_id not in STAGE_BY_ID:
            raise StreamingPrefreezeError("unknown stream chunk stage")
        stage = STAGE_BY_ID[stage_id]
        first_item, offset = _read_uint(encoded, offset, 8, "first item")
        count, offset = _read_uint(encoded, offset, 4, "record count")
        if count == 0 or count > PRODUCTION_RECORDS_PER_CHUNK:
            raise StreamingPrefreezeError("invalid stream chunk record count")
        records: list[StreamRecord] = []
        for item_index in range(first_item, first_item + count):
            length, offset = _read_uint(encoded, offset, 4, "payload length")
            if length != expected_payload_bytes:
                raise StreamingPrefreezeError("wrong stream record payload width")
            payload, offset = _read_bytes(encoded, offset, length, "payload")
            records.append(StreamRecord(stage, item_index, payload))
        if offset != len(encoded):
            raise StreamingPrefreezeError("stream chunk trailing bytes")
        chunk = cls(ordinal, stage, first_item, tuple(records))
        if chunk.encode(expected_profile_fingerprint) != encoded:
            raise StreamingPrefreezeError("noncanonical stream chunk")
        return chunk


def _payload_widths(parameters: unified.UnifiedTreeParameters) -> dict[str, int]:
    return {
        "tree-nodes": unified.SEED_BYTES,
        "leaf-commitments": unified.HASH_BYTES,
        "leaf-tapes": (parameters.tape_bits + 7) // 8,
        "logical-vector-hashes": unified.HASH_BYTES,
        "unified-commitment": (
            len(unified.COMMITMENT_MAGIC)
            + 2
            + 32
            + 2 * unified.SEED_BYTES
            + unified.HASH_BYTES
        ),
        "parent-input": 643,
    }


def _stage_counts(parameters: unified.UnifiedTreeParameters) -> dict[str, int]:
    return {
        "tree-nodes": 2 * parameters.total_leaves - 1,
        "leaf-commitments": parameters.total_leaves,
        "leaf-tapes": parameters.total_leaves,
        "logical-vector-hashes": parameters.vector_count,
        "unified-commitment": 1,
        "parent-input": 1,
    }


def _layout(
    parameters: unified.UnifiedTreeParameters, records_per_chunk: int
) -> dict[str, object]:
    counts = _stage_counts(parameters)
    widths = _payload_widths(parameters)
    chunks = {
        stage: math.ceil(counts[stage] / records_per_chunk)
        for _, stage in STAGES
    }
    return {
        "profile_fingerprint": unified.profile_fingerprint(parameters),
        "records_per_chunk": records_per_chunk,
        "stage_order": [stage for _, stage in STAGES],
        "stage_record_counts": counts,
        "stage_payload_bytes": widths,
        "total_records": sum(counts.values()),
        "total_payload_bytes": sum(counts[key] * widths[key] for key in counts),
        "stage_chunk_counts": chunks,
        "total_chunks": sum(chunks.values()),
    }


def production_layout() -> dict[str, object]:
    return _layout(unified.PRODUCTION_PARAMETERS, PRODUCTION_RECORDS_PER_CHUNK)


def bounded_layout() -> dict[str, object]:
    return _layout(v2_35.QUALIFICATION_PARAMETERS, BOUNDED_RECORDS_PER_CHUNK)


def claim_boundary() -> dict[str, bool]:
    return {
        "v2_38_stream_chunk_codec_implemented": True,
        "v2_38_external_checkpoint_resume_implemented": True,
        "v2_38_bounded_stream_materializer_qualified": False,
        "v2_38_read_only_launch_preflight_implemented": True,
        "production_stream_layout_frozen_as_plan": True,
        "production_stream_materialized": False,
        "production_checkpoint_materialized": False,
        "production_parent_input_materialized": False,
        "production_relation_replayed": False,
        "production_runner_scale_qualified": False,
        "operator_resource_reservation_frozen": False,
        "independent_review_frozen": False,
        "launch_manifest_frozen": False,
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


def exact_qualification_command() -> str:
    return (
        "PYTHONPATH=src python -u "
        "src/pq_rbbc_cap_unified_tree_streaming_prefreeze.py "
        "--manifest manifests/"
        "pq_rbbc_cap_unified_tree_streaming_prefreeze_manifest_v2_38.json "
        "--phase qualification "
        "--checkpoint-payload /tmp/pq_rbbc_external_artifacts_rebuilt/"
        "v2_36_unified_tree_relation/qualification/"
        "pq_rbbc_cap_unified_tree_checkpoint_payload_v2_36.json "
        "--bounded-parent-vector /tmp/pq_rbbc_external_artifacts_rebuilt/"
        "v2_37_unified_statement_parent_abi/qualification/"
        "pq_rbbc_cap_unified_parent_input_bounded_vector_v2_37.json "
        "--output /tmp/pq_rbbc_external_artifacts_rebuilt/"
        "v2_38_unified_tree_streaming/qualification --fresh-output"
    )


def exact_launch_preflight_command() -> str:
    return (
        "PYTHONPATH=src python -u "
        "src/pq_rbbc_cap_unified_tree_streaming_prefreeze.py "
        "--manifest manifests/"
        "pq_rbbc_cap_unified_tree_streaming_prefreeze_manifest_v2_38.json "
        "--phase launch-preflight "
        "--bounded-qualification /tmp/pq_rbbc_external_artifacts_rebuilt/"
        "v2_38_unified_tree_streaming/qualification/"
        "pq_rbbc_cap_unified_tree_stream_qualification_v2_38.json "
        "--resource-reservation /tmp/pq_rbbc_external_artifacts_rebuilt/"
        "v2_38_unified_tree_streaming/"
        "pq_rbbc_cap_unified_tree_resource_reservation_v2_38.json "
        "--independent-review /tmp/pq_rbbc_external_artifacts_rebuilt/"
        "v2_38_unified_tree_streaming/"
        "pq_rbbc_cap_unified_tree_independent_review_v2_38.json "
        "--launch-manifest /tmp/pq_rbbc_external_artifacts_rebuilt/"
        "v2_38_unified_tree_streaming/"
        "pq_rbbc_cap_unified_tree_launch_manifest_v2_38.json "
        "--output /tmp/pq_rbbc_external_artifacts_rebuilt/"
        "v2_38_unified_tree_streaming/launch-preflight.json --fresh-output"
    )


def prospective_production_command() -> str:
    return (
        "PYTHONPATH=src python -u "
        "src/pq_rbbc_cap_unified_tree_streaming_prefreeze.py "
        "--manifest manifests/"
        "pq_rbbc_cap_unified_tree_streaming_prefreeze_manifest_v2_38.json "
        "--phase production-prefreeze "
        "--resource-reservation /tmp/pq_rbbc_external_artifacts_rebuilt/"
        "v2_38_unified_tree_streaming/"
        "pq_rbbc_cap_unified_tree_resource_reservation_v2_38.json "
        "--independent-review /tmp/pq_rbbc_external_artifacts_rebuilt/"
        "v2_38_unified_tree_streaming/"
        "pq_rbbc_cap_unified_tree_independent_review_v2_38.json "
        "--launch-manifest /tmp/pq_rbbc_external_artifacts_rebuilt/"
        "v2_38_unified_tree_streaming/"
        "pq_rbbc_cap_unified_tree_launch_manifest_v2_38.json "
        "--output /tmp/pq_rbbc_external_artifacts_rebuilt/"
        "v2_38_unified_tree_streaming/production-prefreeze "
        "--fresh-output --allow-large"
    )


def build_manifest() -> dict[str, object]:
    qualification = exact_qualification_command()
    preflight = exact_launch_preflight_command()
    production = prospective_production_command()
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "sealed_predecessor": V2_37_PORTABLE_EVIDENCE,
        "source_inputs": {
            "v2_36_checkpoint_payload": V2_36_CHECKPOINT_IDENTITY,
            "v2_37_bounded_parent_vector": V2_37_BOUNDED_VECTOR_IDENTITY,
            "other_tree_observed_stream_bytes_reused": False,
            "v2_29_transcript_reused_as_observation": False,
        },
        "chunk_contract": {
            "magic_hex": STREAM_MAGIC.hex(),
            "version": STREAM_VERSION,
            "integer_encoding": "unsigned little-endian",
            "stage_order": [stage for _, stage in STAGES],
            "profile_bound": True,
            "contiguous_item_indices": True,
            "trailing_bytes_forbidden": True,
            "each_checkpoint_record_binds_chunk_identity_and_prior_chain": True,
            "resume_requires_expected_checkpoint_sha256": True,
            "external_output_only": True,
            "existing_output_overwrite_forbidden": True,
            "pickle_forbidden": True,
        },
        "bounded_layout": bounded_layout(),
        "production_layout_plan_not_observation": production_layout(),
        "resource_estimate": {
            "production_raw_stream_payload_bytes": production_layout()[
                "total_payload_bytes"
            ],
            "minimum_cpu_cores": MIN_CPU_CORES,
            "minimum_available_memory_bytes": MIN_AVAILABLE_MEMORY_BYTES,
            "minimum_free_disk_bytes": MIN_FREE_DISK_BYTES,
            "minimum_combined_rows_not_observed": MIN_COMBINED_ROWS_NOT_OBSERVED,
            "minimum_two_replay_row_checks_not_observed": (
                MIN_TWO_REPLAY_ROW_CHECKS_NOT_OBSERVED
            ),
            "wall_clock_seconds": None,
            "bounded_runtime_must_not_be_linearly_extrapolated": True,
        },
        "required_external_artifacts": {
            "resource_reservation": {
                "filename": RESOURCE_RESERVATION_FILENAME,
                "format": RESOURCE_FORMAT,
                "identity_frozen": False,
            },
            "independent_review": {
                "filename": INDEPENDENT_REVIEW_FILENAME,
                "format": REVIEW_FORMAT,
                "identity_frozen": False,
            },
            "launch_manifest": {
                "filename": LAUNCH_MANIFEST_FILENAME,
                "format": LAUNCH_FORMAT,
                "identity_frozen": False,
            },
        },
        "exact_commands": {
            "qualification": {
                "command": qualification,
                "sha256": sha256_bytes(qualification.encode("ascii")),
                "executable_now": True,
            },
            "launch_preflight": {
                "command": preflight,
                "sha256": sha256_bytes(preflight.encode("ascii")),
                "executable_now": True,
                "read_only_except_report": True,
            },
            "production_prefreeze": {
                "command": production,
                "sha256": sha256_bytes(production.encode("ascii")),
                "executable_now": False,
                "authorized_now": False,
            },
        },
        "claim_boundary": claim_boundary(),
    }


def validate_manifest(path: Path) -> dict[str, object]:
    document = _read_json(path)
    if document != build_manifest():
        raise StreamingPrefreezeError("manifest is not the frozen v2.38 contract")
    portable = (
        ROOT
        / "artifacts/metadata/cap_unified_statement_parent_abi_v2_37/"
        "pq_rbbc_cap_unified_statement_parent_abi_portable_evidence_v2_37.json"
    )
    if not portable.is_file() or identity(portable) != V2_37_PORTABLE_EVIDENCE:
        raise StreamingPrefreezeError("v2.37 portable evidence identity mismatch")
    return document


def _load_bounded_inputs(
    checkpoint_path: Path, bounded_parent_vector_path: Path
) -> tuple[unified.UnifiedTreeExecution, bytes, bytes]:
    if identity(checkpoint_path) != V2_36_CHECKPOINT_IDENTITY:
        raise StreamingPrefreezeError("v2.36 checkpoint identity mismatch")
    checkpoint = _read_json(checkpoint_path)
    v2_36.validate_checkpoint_document(
        checkpoint, v2_36.state_contract(v2_36.MANIFEST_PATH)
    )
    snapshot = v2_36._stage_data(checkpoint, "unified-tree")
    execution, _ = v2_36._decode_tree_snapshot(snapshot)
    if identity(bounded_parent_vector_path) != V2_37_BOUNDED_VECTOR_IDENTITY:
        raise StreamingPrefreezeError("v2.37 bounded parent vector identity mismatch")
    vector = _read_json(bounded_parent_vector_path)
    c_r = execution.commitment.encode()
    abi.validate_bounded_vector(vector, c_r)
    try:
        parent_input = bytes.fromhex(vector["parent_input_hex"])
    except (KeyError, TypeError, ValueError) as error:
        raise StreamingPrefreezeError("bounded parent vector encoding rejected") from error
    parent = abi.UnifiedParentInput.decode(
        parent_input,
        expected_profile_fingerprint=BOUNDED_PROFILE_FINGERPRINT,
    )
    abi.validate_bounded_parent_mapping(parent, c_r)
    return execution, c_r, parent_input


def bounded_records(
    checkpoint_path: Path, bounded_parent_vector_path: Path
) -> tuple[StreamRecord, ...]:
    execution, c_r, parent_input = _load_bounded_inputs(
        checkpoint_path, bounded_parent_vector_path
    )
    records: list[StreamRecord] = []
    for index, value in enumerate(execution.nodes):
        records.append(StreamRecord("tree-nodes", index, unified._field_bytes(value)))
    for index, value in enumerate(execution.leaf_commitments):
        records.append(
            StreamRecord("leaf-commitments", index, unified._hash_bytes(value))
        )
    tape_bytes = (execution.parameters.tape_bits + 7) // 8
    for index, value in enumerate(execution.leaf_tapes):
        records.append(
            StreamRecord("leaf-tapes", index, value.to_bytes(tape_bytes, "little"))
        )
    for index, value in enumerate(execution.vector_hashes):
        records.append(
            StreamRecord("logical-vector-hashes", index, unified._hash_bytes(value))
        )
    records.append(StreamRecord("unified-commitment", 0, c_r))
    records.append(StreamRecord("parent-input", 0, parent_input))
    expected = bounded_layout()
    if len(records) != expected["total_records"]:
        raise AssertionError("bounded stream record count changed")
    return tuple(records)


def make_chunks(
    records: Sequence[StreamRecord], records_per_chunk: int
) -> tuple[StreamChunk, ...]:
    chunks: list[StreamChunk] = []
    offset = 0
    ordinal = 0
    for _, stage in STAGES:
        stage_records: list[StreamRecord] = []
        while offset < len(records) and records[offset].stage == stage:
            stage_records.append(records[offset])
            offset += 1
        if not stage_records:
            raise StreamingPrefreezeError(f"missing stream stage: {stage}")
        for start in range(0, len(stage_records), records_per_chunk):
            group = tuple(stage_records[start : start + records_per_chunk])
            chunks.append(StreamChunk(ordinal, stage, group[0].item_index, group))
            ordinal += 1
    if offset != len(records):
        raise StreamingPrefreezeError("stream records are not in canonical stage order")
    return tuple(chunks)


def chunk_filename(chunk: StreamChunk) -> str:
    last = chunk.first_item_index + len(chunk.records) - 1
    return (
        f"{chunk.ordinal:04d}-{chunk.stage}-"
        f"{chunk.first_item_index:08d}-{last:08d}.bin"
    )


def state_contract(
    manifest_path: Path, checkpoint_path: Path, bounded_parent_vector_path: Path
) -> dict[str, object]:
    return {
        "manifest": identity(manifest_path),
        "v2_36_checkpoint_payload": identity(checkpoint_path),
        "v2_37_bounded_parent_vector": identity(bounded_parent_vector_path),
        "v2_37_portable_evidence": V2_37_PORTABLE_EVIDENCE,
        "profile_fingerprint": BOUNDED_PROFILE_FINGERPRINT,
        "layout": bounded_layout(),
        "production_profile_permitted": False,
    }


def _new_checkpoint(contract: Mapping[str, object]) -> dict[str, object]:
    chain = sha256_bytes(canonical_json({"contract": contract}))
    return {
        "format": CHECKPOINT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "contract": dict(contract),
        "completed_chunk_count": 0,
        "chunk_records": [],
        "chain_sha256": chain,
        "complete": False,
        "production_profile_permitted": False,
        "production_records_materialized": 0,
        "production_relation_rows_replayed": 0,
    }


def _append_checkpoint_chunk(
    checkpoint: dict[str, object], chunk: StreamChunk, chunk_path: Path
) -> None:
    expected_ordinal = checkpoint["completed_chunk_count"]
    if chunk.ordinal != expected_ordinal:
        raise StreamingPrefreezeError("checkpoint chunk prefix is not contiguous")
    base = {
        "ordinal": chunk.ordinal,
        "stage": chunk.stage,
        "first_item_index": chunk.first_item_index,
        "record_count": len(chunk.records),
        "payload_bytes": sum(len(record.payload) for record in chunk.records),
        "chunk_identity": identity(chunk_path),
        "prior_chain_sha256": checkpoint["chain_sha256"],
    }
    chain = sha256_bytes(canonical_json(base))
    checkpoint["chunk_records"].append({**base, "chain_sha256": chain})
    checkpoint["completed_chunk_count"] = expected_ordinal + 1
    checkpoint["chain_sha256"] = chain


def validate_checkpoint_document(
    document: Mapping[str, object],
    contract: Mapping[str, object],
    output: Path,
    expected_chunks: Sequence[StreamChunk],
) -> None:
    required = {
        "format",
        "implementation_version",
        "relation_id",
        "contract",
        "completed_chunk_count",
        "chunk_records",
        "chain_sha256",
        "complete",
        "production_profile_permitted",
        "production_records_materialized",
        "production_relation_rows_replayed",
    }
    records = document.get("chunk_records")
    completed = document.get("completed_chunk_count")
    if (
        set(document) != required
        or document.get("format") != CHECKPOINT_FORMAT
        or document.get("implementation_version") != IMPLEMENTATION_VERSION
        or document.get("relation_id") != RELATION_ID
        or document.get("contract") != contract
        or not isinstance(completed, int)
        or isinstance(completed, bool)
        or not 0 <= completed <= len(expected_chunks)
        or not isinstance(records, list)
        or len(records) != completed
        or document.get("complete") is not (completed == len(expected_chunks))
        or document.get("production_profile_permitted") is not False
        or document.get("production_records_materialized") != 0
        or document.get("production_relation_rows_replayed") != 0
    ):
        raise StreamingPrefreezeError("stream checkpoint contract mismatch")
    chain = sha256_bytes(canonical_json({"contract": contract}))
    widths = _payload_widths(v2_35.QUALIFICATION_PARAMETERS)
    for ordinal, (record, chunk) in enumerate(zip(records, expected_chunks)):
        if not isinstance(record, dict) or set(record) != {
            "ordinal",
            "stage",
            "first_item_index",
            "record_count",
            "payload_bytes",
            "chunk_identity",
            "prior_chain_sha256",
            "chain_sha256",
        }:
            raise StreamingPrefreezeError("stream checkpoint record fields mismatch")
        path = output / CHUNK_DIRECTORY / chunk_filename(chunk)
        expected_identity = identity(path) if path.is_file() else None
        base = {key: record[key] for key in record if key != "chain_sha256"}
        if (
            record["ordinal"] != ordinal
            or record["stage"] != chunk.stage
            or record["first_item_index"] != chunk.first_item_index
            or record["record_count"] != len(chunk.records)
            or record["payload_bytes"]
            != sum(len(item.payload) for item in chunk.records)
            or record["chunk_identity"] != expected_identity
            or record["prior_chain_sha256"] != chain
        ):
            raise StreamingPrefreezeError("stream checkpoint chunk identity mismatch")
        encoded = path.read_bytes()
        decoded = StreamChunk.decode(
            encoded, BOUNDED_PROFILE_FINGERPRINT, widths[chunk.stage]
        )
        if decoded != chunk:
            raise StreamingPrefreezeError("stream checkpoint chunk content mismatch")
        chain = sha256_bytes(canonical_json(base))
        if record["chain_sha256"] != chain:
            raise StreamingPrefreezeError("stream checkpoint chain mismatch")
    if document.get("chain_sha256") != chain:
        raise StreamingPrefreezeError("stream checkpoint final chain mismatch")


def _build_index(
    checkpoint: Mapping[str, object], chunks: Sequence[StreamChunk]
) -> dict[str, object]:
    records = checkpoint["chunk_records"]
    return {
        "format": INDEX_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "profile_fingerprint": BOUNDED_PROFILE_FINGERPRINT,
        "layout": bounded_layout(),
        "checkpoint_chain_sha256": checkpoint["chain_sha256"],
        "chunk_identities": [record["chunk_identity"] for record in records],
        "chunk_identity_stream_sha256": sha256_bytes(
            b"".join(
                bytes.fromhex(record["chunk_identity"]["sha256"])
                for record in records
            )
        ),
        "total_chunk_file_bytes": sum(
            record["chunk_identity"]["bytes"] for record in records
        ),
        "bounded_records_materialized": sum(len(chunk.records) for chunk in chunks),
        "production_records_materialized": 0,
        "production_relation_rows_replayed": 0,
    }


def validate_index_document(
    document: Mapping[str, object],
    checkpoint: Mapping[str, object],
    chunks: Sequence[StreamChunk],
) -> None:
    if document != _build_index(checkpoint, chunks):
        raise StreamingPrefreezeError("stream index mismatch")


def run_bounded_stream(
    manifest_path: Path,
    checkpoint_input_path: Path,
    bounded_parent_vector_path: Path,
    output: Path,
    *,
    fresh_output: bool = False,
    resume: bool = False,
    expected_checkpoint_sha256: str | None = None,
    stop_after_chunks: int | None = None,
) -> dict[str, object] | None:
    if fresh_output == resume:
        raise StreamingPrefreezeError("select exactly one of fresh-output or resume")
    validate_manifest(manifest_path)
    if not _outside_repository(output):
        raise StreamingPrefreezeError("stream output must be external")
    records = bounded_records(checkpoint_input_path, bounded_parent_vector_path)
    chunks = make_chunks(records, BOUNDED_RECORDS_PER_CHUNK)
    contract = state_contract(
        manifest_path, checkpoint_input_path, bounded_parent_vector_path
    )
    checkpoint_path = output / CHECKPOINT_FILENAME
    if fresh_output:
        if output.exists():
            raise FileExistsError("fresh-output directory already exists")
        if expected_checkpoint_sha256 is not None:
            raise StreamingPrefreezeError(
                "fresh-output forbids expected checkpoint identity"
            )
        (output / CHUNK_DIRECTORY).mkdir(parents=True)
        checkpoint = _new_checkpoint(contract)
        _atomic_json(checkpoint_path, checkpoint)
    else:
        if expected_checkpoint_sha256 is None:
            raise StreamingPrefreezeError(
                "resume requires expected checkpoint SHA-256"
            )
        if identity(checkpoint_path)["sha256"] != expected_checkpoint_sha256:
            raise StreamingPrefreezeError("resume checkpoint identity mismatch")
        checkpoint = _read_json(checkpoint_path)
        validate_checkpoint_document(checkpoint, contract, output, chunks)
        if checkpoint["complete"] is True:
            raise FileExistsError("stream checkpoint already complete")
    start = checkpoint["completed_chunk_count"]
    target = len(chunks) if stop_after_chunks is None else stop_after_chunks
    if not isinstance(target, int) or not start < target <= len(chunks):
        raise StreamingPrefreezeError("invalid stop-after-chunks boundary")
    for chunk in chunks[start:target]:
        data = chunk.encode(BOUNDED_PROFILE_FINGERPRINT)
        path = output / CHUNK_DIRECTORY / chunk_filename(chunk)
        if path.exists():
            raise FileExistsError("stream chunk already exists")
        _atomic_bytes(path, data)
        _append_checkpoint_chunk(checkpoint, chunk, path)
        _atomic_json(checkpoint_path, checkpoint)
    if target < len(chunks):
        return None
    checkpoint["complete"] = True
    _atomic_json(checkpoint_path, checkpoint)
    validate_checkpoint_document(checkpoint, contract, output, chunks)
    index = _build_index(checkpoint, chunks)
    index_path = output / INDEX_FILENAME
    _atomic_json(index_path, index)
    validate_index_document(_read_json(index_path), checkpoint, chunks)
    deterministic_result = sha256_bytes(canonical_json({
        "profile_fingerprint": BOUNDED_PROFILE_FINGERPRINT,
        "checkpoint_chain_sha256": checkpoint["chain_sha256"],
        "chunk_identity_stream_sha256": index["chunk_identity_stream_sha256"],
        "bounded_parent_input_sha256": sha256_bytes(records[-1].payload),
    }))
    evidence = {
        "format": EVIDENCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "execution_mode": "resume" if resume else "fresh",
        "manifest": identity(manifest_path),
        "v2_36_checkpoint_payload": identity(checkpoint_input_path),
        "v2_37_bounded_parent_vector": identity(bounded_parent_vector_path),
        "stream_checkpoint": identity(checkpoint_path),
        "stream_index": identity(index_path),
        "deterministic_result_identity": deterministic_result,
        "observations": {
            "bounded_chunks_materialized": len(chunks),
            "bounded_records_materialized": len(records),
            "bounded_payload_bytes": bounded_layout()["total_payload_bytes"],
            "bounded_chunk_file_bytes": index["total_chunk_file_bytes"],
            "production_records_materialized": 0,
            "production_leaves_expanded": 0,
            "production_relation_rows_replayed": 0,
            "br1cs_rows": 0,
            "proofs_generated": 0,
            "other_tree_observed_stream_bytes_reused": False,
            "v2_29_transcript_reused_as_observation": False,
        },
        "claim_boundary": claim_boundary(),
    }
    _atomic_json(output / EVIDENCE_FILENAME, evidence)
    return evidence


def _available_memory_bytes() -> int:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _candidate_status(
    path: Path | None, expected_filename: str, expected_format: str
) -> dict[str, object]:
    result: dict[str, object] = {
        "provided": path is not None,
        "filename_valid": False,
        "format_valid": False,
        "external": False,
        "identity_frozen": False,
        "candidate_acceptable_for_later_freeze": False,
        "failures": [],
    }
    failures = result["failures"]
    assert isinstance(failures, list)
    if path is None:
        failures.append("not_provided")
        return result
    if path.name == expected_filename:
        result["filename_valid"] = True
    else:
        failures.append("filename")
    if _outside_repository(path):
        result["external"] = True
    else:
        failures.append("must_be_external")
    if not path.is_file():
        failures.append("missing")
        return result
    result["identity"] = identity(path)
    try:
        document = _read_json(path)
    except (OSError, ValueError, json.JSONDecodeError):
        failures.append("json")
        return result
    if document.get("format") == expected_format:
        result["format_valid"] = True
    else:
        failures.append("format")
    if not failures:
        result["candidate_acceptable_for_later_freeze"] = True
        failures.append("identity_not_frozen")
    return result


def build_launch_preflight(
    manifest_path: Path,
    bounded_qualification_path: Path | None,
    resource_reservation_path: Path | None,
    independent_review_path: Path | None,
    launch_manifest_path: Path | None,
    capacity_path: Path = Path("/tmp"),
) -> dict[str, object]:
    validate_manifest(manifest_path)
    qualification_status = {
        "provided": bounded_qualification_path is not None,
        "verified": False,
        "identity": None,
        "failures": [],
    }
    qualification_failures = qualification_status["failures"]
    assert isinstance(qualification_failures, list)
    if bounded_qualification_path is None:
        qualification_failures.append("not_provided")
    elif not bounded_qualification_path.is_file():
        qualification_failures.append("missing")
    else:
        qualification_status["identity"] = identity(bounded_qualification_path)
        try:
            document = _read_json(bounded_qualification_path)
        except (OSError, ValueError, json.JSONDecodeError):
            qualification_failures.append("json")
        else:
            result = document.get("result", {})
            if (
                document.get("format") == QUALIFICATION_FORMAT
                and result.get("bounded_stream_materializer_qualified") is True
                and result.get("production_stream_materialized") is False
                and result.get("safe_to_start_production_prefreeze") is False
            ):
                qualification_status["verified"] = True
            else:
                qualification_failures.append("semantics")
    candidates = {
        "resource_reservation": _candidate_status(
            resource_reservation_path,
            RESOURCE_RESERVATION_FILENAME,
            RESOURCE_FORMAT,
        ),
        "independent_review": _candidate_status(
            independent_review_path,
            INDEPENDENT_REVIEW_FILENAME,
            REVIEW_FORMAT,
        ),
        "launch_manifest": _candidate_status(
            launch_manifest_path,
            LAUNCH_MANIFEST_FILENAME,
            LAUNCH_FORMAT,
        ),
    }
    cpu = os.cpu_count() or 0
    memory = _available_memory_bytes()
    disk = shutil.disk_usage(capacity_path).free
    capacity = {
        "cpu_cores": cpu,
        "available_memory_bytes": memory,
        "free_disk_bytes": disk,
        "minimums_met": (
            cpu >= MIN_CPU_CORES
            and memory >= MIN_AVAILABLE_MEMORY_BYTES
            and disk >= MIN_FREE_DISK_BYTES
        ),
        "capacity_is_authorization": False,
    }
    blockers: list[str] = []
    if not qualification_status["verified"]:
        blockers.append("bounded streaming qualification is missing or invalid")
    for label, status in candidates.items():
        if status["candidate_acceptable_for_later_freeze"] is not True:
            blockers.append(f"{label} candidate is missing or invalid")
        blockers.append(f"{label} identity is not frozen")
    if not capacity["minimums_met"]:
        blockers.append("current host capacity is below the planning minimum")
    blockers.extend([
        "production stream and checkpoint have not been materialized",
        "production runner has not been qualified at scale",
        "explicit production pre-freeze authorization is absent",
    ])
    return {
        "format": PREFLIGHT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "manifest": identity(manifest_path),
        "sealed_predecessor": V2_37_PORTABLE_EVIDENCE,
        "bounded_qualification": qualification_status,
        "external_candidates": candidates,
        "capacity_observation": capacity,
        "resource_estimate": build_manifest()["resource_estimate"],
        "production_command": build_manifest()["exact_commands"][
            "production_prefreeze"
        ],
        "blockers": blockers,
        "result": {
            "safe_to_run_read_only_preflight": True,
            "safe_to_request_resource_reservation": True,
            "safe_to_request_independent_review": True,
            "safe_to_freeze_launch_manifest": False,
            "safe_to_start_production_prefreeze": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
        },
        "claim_boundary": claim_boundary(),
    }


def _expect_rejected(action: Callable[[], object]) -> bool:
    try:
        action()
    except (StreamingPrefreezeError, FileExistsError, RuntimeError):
        return True
    return False


def qualify(
    manifest_path: Path,
    checkpoint_input_path: Path,
    bounded_parent_vector_path: Path,
    output: Path,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    records = bounded_records(checkpoint_input_path, bounded_parent_vector_path)
    chunks = make_chunks(records, BOUNDED_RECORDS_PER_CHUNK)
    stop_after = 7
    run_bounded_stream(
        manifest_path,
        checkpoint_input_path,
        bounded_parent_vector_path,
        output,
        fresh_output=True,
        stop_after_chunks=stop_after,
    )
    interrupted = identity(output / CHECKPOINT_FILENAME)
    evidence = run_bounded_stream(
        manifest_path,
        checkpoint_input_path,
        bounded_parent_vector_path,
        output,
        resume=True,
        expected_checkpoint_sha256=interrupted["sha256"],
    )
    assert evidence is not None
    checkpoint = _read_json(output / CHECKPOINT_FILENAME)
    contract = state_contract(
        manifest_path, checkpoint_input_path, bounded_parent_vector_path
    )
    mutated = copy.deepcopy(checkpoint)
    mutated["chunk_records"][0]["payload_bytes"] += 1
    wrong_checkpoint_rejected = _expect_rejected(
        lambda: validate_checkpoint_document(mutated, contract, output, chunks)
    )
    first_chunk_path = output / CHUNK_DIRECTORY / chunk_filename(chunks[0])
    first_chunk = first_chunk_path.read_bytes()
    wrong_chunk = b"X" + first_chunk[1:]
    wrong_chunk_rejected = _expect_rejected(
        lambda: StreamChunk.decode(
            wrong_chunk,
            BOUNDED_PROFILE_FINGERPRINT,
            _payload_widths(v2_35.QUALIFICATION_PARAMETERS)[chunks[0].stage],
        )
    )
    overwrite_rejected = _expect_rejected(
        lambda: run_bounded_stream(
            manifest_path,
            checkpoint_input_path,
            bounded_parent_vector_path,
            output,
            fresh_output=True,
        )
    )
    missing_resume_identity_rejected = _expect_rejected(
        lambda: run_bounded_stream(
            manifest_path,
            checkpoint_input_path,
            bounded_parent_vector_path,
            output,
            resume=True,
        )
    )
    production_probe = output.with_name(output.name + "-production-probe")
    production_rejected = _expect_rejected(
        lambda: reject_production_prefreeze(
            manifest_path, production_probe, None, None, None, True
        )
    ) and not production_probe.exists()
    qualification = {
        "format": QUALIFICATION_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "implementation": identity(Path(__file__)),
        "manifest": identity(manifest_path),
        "external_inputs": {
            "v2_36_checkpoint_payload": identity(checkpoint_input_path),
            "v2_37_bounded_parent_vector": identity(bounded_parent_vector_path),
        },
        "external_outputs": {
            "completed_checkpoint": evidence["stream_checkpoint"],
            "stream_index": evidence["stream_index"],
            "run_evidence": identity(output / EVIDENCE_FILENAME),
        },
        "interrupted_checkpoint_identity": interrupted,
        "checks": {
            "fresh_stream_started": True,
            "interrupted_after_exact_chunk_prefix": True,
            "resume_bound_to_expected_checkpoint_identity": True,
            "resume_completed_exact_stream": True,
            "checkpoint_mutation_rejected": wrong_checkpoint_rejected,
            "chunk_mutation_rejected": wrong_chunk_rejected,
            "existing_output_overwrite_rejected": overwrite_rejected,
            "missing_resume_identity_rejected": missing_resume_identity_rejected,
            "production_branch_rejected_before_output": production_rejected,
            "bounded_parent_input_is_final_stream_record": (
                records[-1].stage == "parent-input"
            ),
            "state_is_canonical_json_not_pickle": True,
            "other_tree_observed_stream_bytes_not_reused": True,
            "production_records_materialized": 0,
            "production_relation_rows_replayed": 0,
        },
        "result": {
            "stream_chunk_codec_qualified": True,
            "external_checkpoint_resume_qualified": True,
            "bounded_stream_materializer_qualified": True,
            "production_stream_materialized": False,
            "production_runner_scale_qualified": False,
            "safe_to_start_production_prefreeze": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
        },
        "claim_boundary": claim_boundary(),
    }
    zero_checks = {
        "production_records_materialized",
        "production_relation_rows_replayed",
    }
    failed_checks = [
        name
        for name, value in qualification["checks"].items()
        if (
            (name in zero_checks and (type(value) is not int or value != 0))
            or (name not in zero_checks and value is not True)
        )
    ]
    if failed_checks:
        raise StreamingPrefreezeError(
            "stream qualification checks failed: " + ",".join(failed_checks)
        )
    qualification_path = output / QUALIFICATION_FILENAME
    _atomic_json(qualification_path, qualification)
    preflight = build_launch_preflight(
        manifest_path, qualification_path, None, None, None
    )
    _atomic_json(output / PREFLIGHT_FILENAME, preflight)
    return evidence, qualification, preflight


def reject_production_prefreeze(
    manifest_path: Path,
    output: Path,
    resource_reservation_path: Path | None,
    independent_review_path: Path | None,
    launch_manifest_path: Path | None,
    allow_large: bool,
) -> None:
    validate_manifest(manifest_path)
    if output.exists():
        raise FileExistsError("production output already exists")
    if not _outside_repository(output):
        raise StreamingPrefreezeError("production output must be external")
    details = {
        "resource_reservation_provided": resource_reservation_path is not None,
        "independent_review_provided": independent_review_path is not None,
        "launch_manifest_provided": launch_manifest_path is not None,
        "allow_large_requested": allow_large,
        "output_created": False,
        "reasons": [
            "v2.38 qualifies streaming mechanics only on the bounded fixture",
            "production stream and checkpoint are not materialized",
            "production runner is not qualified at scale",
            "resource, review, and launch identities are not frozen",
            "production pre-freeze is not authorized",
        ],
    }
    raise RuntimeError(
        "production-prefreeze unavailable: "
        + canonical_json(details).decode().strip()
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--phase",
        choices=("qualification", "launch-preflight", "production-prefreeze"),
        required=True,
    )
    parser.add_argument("--checkpoint-payload", type=Path)
    parser.add_argument("--bounded-parent-vector", type=Path)
    parser.add_argument("--bounded-qualification", type=Path)
    parser.add_argument("--resource-reservation", type=Path)
    parser.add_argument("--independent-review", type=Path)
    parser.add_argument("--launch-manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fresh-output", action="store_true")
    parser.add_argument("--allow-large", action="store_true")
    args = parser.parse_args()
    if not args.fresh_output:
        raise StreamingPrefreezeError("v2.38 requires --fresh-output")
    if args.phase == "production-prefreeze":
        reject_production_prefreeze(
            args.manifest,
            args.output,
            args.resource_reservation,
            args.independent_review,
            args.launch_manifest,
            args.allow_large,
        )
    if args.allow_large:
        raise StreamingPrefreezeError("non-production phases forbid --allow-large")
    if args.phase == "launch-preflight":
        if args.output.exists():
            raise FileExistsError("preflight report already exists")
        if not _outside_repository(args.output):
            raise StreamingPrefreezeError("preflight report must be external")
        report = build_launch_preflight(
            args.manifest,
            args.bounded_qualification,
            args.resource_reservation,
            args.independent_review,
            args.launch_manifest,
            args.output.parent,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        _atomic_json(args.output, report)
        print(canonical_json({
            "phase": args.phase,
            "report": identity(args.output),
            "result": report["result"],
        }).decode(), end="")
        return
    if args.checkpoint_payload is None or args.bounded_parent_vector is None:
        raise StreamingPrefreezeError(
            "qualification requires checkpoint payload and bounded parent vector"
        )
    evidence, qualification, preflight = qualify(
        args.manifest,
        args.checkpoint_payload,
        args.bounded_parent_vector,
        args.output,
    )
    print(canonical_json({
        "phase": args.phase,
        "output": str(args.output),
        "stream_checkpoint": evidence["stream_checkpoint"],
        "stream_index": evidence["stream_index"],
        "evidence": identity(args.output / EVIDENCE_FILENAME),
        "qualification": identity(args.output / QUALIFICATION_FILENAME),
        "launch_preflight": identity(args.output / PREFLIGHT_FILENAME),
        "bounded_stream_materializer_qualified": qualification["result"][
            "bounded_stream_materializer_qualified"
        ],
        "safe_to_start_production_prefreeze": preflight["result"][
            "safe_to_start_production_prefreeze"
        ],
    }).decode(), end="")


if __name__ == "__main__":
    main()
