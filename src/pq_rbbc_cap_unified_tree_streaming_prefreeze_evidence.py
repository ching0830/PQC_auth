#!/usr/bin/env python3
"""Seal v2.38 bounded stream and read-only launch-preflight evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_unified_tree_streaming_prefreeze as streaming


IMPLEMENTATION_VERSION = "2.38"
FORMAT = "PQRBBC-CAP-UNIFIED-TREE-STREAMING-PREFREEZE-PORTABLE-EVIDENCE-1"
RELATION_ID = "pq-rbbc/cap/unified-tree/streaming-prefreeze/portable-evidence/v1"
ROOT = Path(__file__).resolve().parents[1]

TRACKED = {
    "streaming_prefreeze_implementation": (
        ROOT / "src/pq_rbbc_cap_unified_tree_streaming_prefreeze.py",
        51_495,
        "027eb529dea4e2868989a5d76073085724f1232e84695a7344daf3efc6043bb0",
    ),
    "streaming_prefreeze_manifest": (
        ROOT / "manifests/pq_rbbc_cap_unified_tree_streaming_prefreeze_manifest_v2_38.json",
        7_581,
        "b601af812865b190e76a7fe22d184f29ee2036dc907a56ad4dcf8da8fbf9a4a4",
    ),
    "streaming_prefreeze_tests": (
        ROOT / "tests/test_pq_rbbc_cap_unified_tree_streaming_prefreeze.py",
        9_314,
        "bc2097e7d128d07c78a28f9aa182a83da0051d504d2e9793fd3035372518f33e",
    ),
    "v2_37_portable_evidence": (
        ROOT / "artifacts/metadata/cap_unified_statement_parent_abi_v2_37/"
        "pq_rbbc_cap_unified_statement_parent_abi_portable_evidence_v2_37.json",
        5_188,
        "672c27f8ed0bfc567d3080c9645c079d9009ce7ff815957c9384dc0246b3c8b7",
    ),
}

CHECKPOINT_IDENTITY = {
    "filename": streaming.CHECKPOINT_FILENAME,
    "bytes": 8_495,
    "sha256": "b5ef245fb1af0a08e983f6ab49b3353f0cbbe708c808db90661f9fdec079f805",
}
INDEX_IDENTITY = {
    "filename": streaming.INDEX_FILENAME,
    "bytes": 3_505,
    "sha256": "22814bb97f94a89f6283b7aa4722260201364c01f7600b70577a334ab61d7b88",
}
RUN_EVIDENCE_IDENTITY = {
    "filename": streaming.EVIDENCE_FILENAME,
    "bytes": 2_530,
    "sha256": "e7e27f8e03717a98691352b6a676075ece08955338fff5760749a025381a15cc",
}
QUALIFICATION_IDENTITY = {
    "filename": streaming.QUALIFICATION_FILENAME,
    "bytes": 3_527,
    "sha256": "812d49a04b86a3311db743678604e3c00a5b80cd48f9c524243cc83a78baf185",
}
PREFLIGHT_IDENTITY = {
    "filename": streaming.PREFLIGHT_FILENAME,
    "bytes": 4_555,
    "sha256": "e88bfc3d3512ded3f6559cc90525eec1ed4f79b0d52959a5f04a3c6b82750e8c",
}
INTERRUPTED_CHECKPOINT_IDENTITY = {
    "filename": streaming.CHECKPOINT_FILENAME,
    "bytes": 5_041,
    "sha256": "dd30629ce8a9b64e9d4e8175dffe9421d33173fd321d2a7e6fc9019e737eb517",
}
DETERMINISTIC_RESULT_IDENTITY = (
    "87edb3d69ca6bba3dbcedb553db7dc3ce8c98be4954df5315a6dd1d57b3479c8"
)
CHUNK_IDENTITY_STREAM_SHA256 = (
    "b3ee7d5659380d629b1baece4dedf8aa3342beba16d0c5cae765e842161c5c11"
)


def canonical_json(document: object) -> bytes:
    return streaming.canonical_json(document)


def _require(path: Path, expected: Mapping[str, object], label: str) -> None:
    if not path.is_file() or streaming.identity(path) != expected:
        raise ValueError(f"{label} identity mismatch")


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} root must be an object")
    return document


def validate_run_evidence(document: Mapping[str, object]) -> None:
    expected_observations = {
        "bounded_chunks_materialized": 15,
        "bounded_records_materialized": 179,
        "bounded_payload_bytes": 5_938,
        "bounded_chunk_file_bytes": 7_899,
        "production_records_materialized": 0,
        "production_leaves_expanded": 0,
        "production_relation_rows_replayed": 0,
        "br1cs_rows": 0,
        "proofs_generated": 0,
        "other_tree_observed_stream_bytes_reused": False,
        "v2_29_transcript_reused_as_observation": False,
    }
    if (
        document.get("format") != streaming.EVIDENCE_FORMAT
        or document.get("implementation_version") != IMPLEMENTATION_VERSION
        or document.get("relation_id") != streaming.RELATION_ID
        or document.get("execution_mode") != "resume"
        or document.get("manifest") != streaming.identity(streaming.MANIFEST_PATH)
        or document.get("v2_36_checkpoint_payload")
        != streaming.V2_36_CHECKPOINT_IDENTITY
        or document.get("v2_37_bounded_parent_vector")
        != streaming.V2_37_BOUNDED_VECTOR_IDENTITY
        or document.get("stream_checkpoint") != CHECKPOINT_IDENTITY
        or document.get("stream_index") != INDEX_IDENTITY
        or document.get("deterministic_result_identity")
        != DETERMINISTIC_RESULT_IDENTITY
        or document.get("observations") != expected_observations
        or document.get("claim_boundary") != streaming.claim_boundary()
    ):
        raise ValueError("v2.38 run evidence mismatch")


def validate_qualification(document: Mapping[str, object]) -> None:
    expected_checks = {
        "fresh_stream_started": True,
        "interrupted_after_exact_chunk_prefix": True,
        "resume_bound_to_expected_checkpoint_identity": True,
        "resume_completed_exact_stream": True,
        "checkpoint_mutation_rejected": True,
        "chunk_mutation_rejected": True,
        "existing_output_overwrite_rejected": True,
        "missing_resume_identity_rejected": True,
        "production_branch_rejected_before_output": True,
        "bounded_parent_input_is_final_stream_record": True,
        "state_is_canonical_json_not_pickle": True,
        "other_tree_observed_stream_bytes_not_reused": True,
        "production_records_materialized": 0,
        "production_relation_rows_replayed": 0,
    }
    expected_result = {
        "stream_chunk_codec_qualified": True,
        "external_checkpoint_resume_qualified": True,
        "bounded_stream_materializer_qualified": True,
        "production_stream_materialized": False,
        "production_runner_scale_qualified": False,
        "safe_to_start_production_prefreeze": False,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
    }
    if (
        document.get("format") != streaming.QUALIFICATION_FORMAT
        or document.get("implementation_version") != IMPLEMENTATION_VERSION
        or document.get("relation_id") != streaming.RELATION_ID
        or document.get("implementation")
        != streaming.identity(
            ROOT / "src/pq_rbbc_cap_unified_tree_streaming_prefreeze.py"
        )
        or document.get("manifest") != streaming.identity(streaming.MANIFEST_PATH)
        or document.get("external_inputs")
        != {
            "v2_36_checkpoint_payload": streaming.V2_36_CHECKPOINT_IDENTITY,
            "v2_37_bounded_parent_vector": (
                streaming.V2_37_BOUNDED_VECTOR_IDENTITY
            ),
        }
        or document.get("external_outputs")
        != {
            "completed_checkpoint": CHECKPOINT_IDENTITY,
            "stream_index": INDEX_IDENTITY,
            "run_evidence": RUN_EVIDENCE_IDENTITY,
        }
        or document.get("interrupted_checkpoint_identity")
        != INTERRUPTED_CHECKPOINT_IDENTITY
        or document.get("checks") != expected_checks
        or document.get("result") != expected_result
        or document.get("claim_boundary") != streaming.claim_boundary()
    ):
        raise ValueError("v2.38 qualification mismatch")


def validate_preflight(document: Mapping[str, object]) -> None:
    candidates = document.get("external_candidates", {})
    capacity = document.get("capacity_observation", {})
    result = document.get("result", {})
    if (
        document.get("format") != streaming.PREFLIGHT_FORMAT
        or document.get("implementation_version") != IMPLEMENTATION_VERSION
        or document.get("relation_id") != streaming.RELATION_ID
        or document.get("manifest") != streaming.identity(streaming.MANIFEST_PATH)
        or document.get("sealed_predecessor")
        != streaming.V2_37_PORTABLE_EVIDENCE
        or document.get("bounded_qualification", {}).get("verified") is not True
        or set(candidates)
        != {"resource_reservation", "independent_review", "launch_manifest"}
        or any(status.get("provided") is not False for status in candidates.values())
        or any(status.get("identity_frozen") is not False for status in candidates.values())
        or not isinstance(capacity.get("cpu_cores"), int)
        or capacity.get("cpu_cores", 0) < streaming.MIN_CPU_CORES
        or not isinstance(capacity.get("available_memory_bytes"), int)
        or capacity.get("available_memory_bytes", 0)
        < streaming.MIN_AVAILABLE_MEMORY_BYTES
        or not isinstance(capacity.get("free_disk_bytes"), int)
        or capacity.get("free_disk_bytes", 0) < streaming.MIN_FREE_DISK_BYTES
        or capacity.get("minimums_met") is not True
        or capacity.get("capacity_is_authorization") is not False
        or len(document.get("blockers", [])) != 9
        or result
        != {
            "safe_to_run_read_only_preflight": True,
            "safe_to_request_resource_reservation": True,
            "safe_to_request_independent_review": True,
            "safe_to_freeze_launch_manifest": False,
            "safe_to_start_production_prefreeze": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
        }
        or document.get("claim_boundary") != streaming.claim_boundary()
    ):
        raise ValueError("v2.38 launch preflight mismatch")


def build_evidence(
    checkpoint_input_path: Path,
    bounded_parent_vector_path: Path,
    output_directory: Path,
) -> dict[str, object]:
    for label, (path, size, digest) in TRACKED.items():
        _require(
            path,
            {"filename": path.name, "bytes": size, "sha256": digest},
            label,
        )
    paths = {
        "completed_checkpoint": output_directory / streaming.CHECKPOINT_FILENAME,
        "stream_index": output_directory / streaming.INDEX_FILENAME,
        "run_evidence": output_directory / streaming.EVIDENCE_FILENAME,
        "qualification": output_directory / streaming.QUALIFICATION_FILENAME,
        "launch_preflight": output_directory / streaming.PREFLIGHT_FILENAME,
    }
    expected = {
        "completed_checkpoint": CHECKPOINT_IDENTITY,
        "stream_index": INDEX_IDENTITY,
        "run_evidence": RUN_EVIDENCE_IDENTITY,
        "qualification": QUALIFICATION_IDENTITY,
        "launch_preflight": PREFLIGHT_IDENTITY,
    }
    for label, path in paths.items():
        _require(path, expected[label], label)
    records = streaming.bounded_records(
        checkpoint_input_path, bounded_parent_vector_path
    )
    chunks = streaming.make_chunks(records, streaming.BOUNDED_RECORDS_PER_CHUNK)
    checkpoint = _read_json(paths["completed_checkpoint"])
    contract = streaming.state_contract(
        streaming.MANIFEST_PATH,
        checkpoint_input_path,
        bounded_parent_vector_path,
    )
    streaming.validate_checkpoint_document(
        checkpoint, contract, output_directory, chunks
    )
    index = _read_json(paths["stream_index"])
    streaming.validate_index_document(index, checkpoint, chunks)
    run_evidence = _read_json(paths["run_evidence"])
    qualification = _read_json(paths["qualification"])
    preflight = _read_json(paths["launch_preflight"])
    validate_run_evidence(run_evidence)
    validate_qualification(qualification)
    validate_preflight(preflight)
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "tracked_identities": {
            label: {"filename": path.name, "bytes": size, "sha256": digest}
            for label, (path, size, digest) in TRACKED.items()
        },
        "external_input_identities": {
            "v2_36_checkpoint_payload": streaming.V2_36_CHECKPOINT_IDENTITY,
            "v2_37_bounded_parent_vector": (
                streaming.V2_37_BOUNDED_VECTOR_IDENTITY
            ),
        },
        "external_output_identities": {
            **expected,
            "interrupted_checkpoint": INTERRUPTED_CHECKPOINT_IDENTITY,
        },
        "bound_contracts": {
            "v2_37_portable_evidence": streaming.V2_37_PORTABLE_EVIDENCE,
            "bounded_profile_fingerprint": streaming.BOUNDED_PROFILE_FINGERPRINT,
            "production_profile_fingerprint": streaming.PRODUCTION_PROFILE_FINGERPRINT,
            "qualification_command_sha256": streaming.build_manifest()[
                "exact_commands"
            ]["qualification"]["sha256"],
            "launch_preflight_command_sha256": streaming.build_manifest()[
                "exact_commands"
            ]["launch_preflight"]["sha256"],
            "prospective_production_command_sha256": streaming.build_manifest()[
                "exact_commands"
            ]["production_prefreeze"]["sha256"],
        },
        "bounded_observation": {
            "deterministic_result_identity": DETERMINISTIC_RESULT_IDENTITY,
            "chunk_count": 15,
            "record_count": 179,
            "payload_bytes": 5_938,
            "chunk_file_bytes": 7_899,
            "chunk_identity_stream_sha256": CHUNK_IDENTITY_STREAM_SHA256,
            "production_records_materialized": 0,
            "production_relation_rows_replayed": 0,
            "br1cs_rows": 0,
            "proofs_generated": 0,
        },
        "production_plan_not_observation": streaming.production_layout(),
        "resource_estimate": streaming.build_manifest()["resource_estimate"],
        "capacity_observation": preflight["capacity_observation"],
        "qualification_result": qualification["result"],
        "preflight_result": preflight["result"],
        "remaining_launch_blockers": preflight["blockers"],
        "static_claim_boundary": streaming.claim_boundary(),
        "artifact_policy": {
            "portable_evidence_contains_absolute_paths": False,
            "portable_evidence_contains_private_stream_payloads": False,
            "stream_chunks_or_checkpoint_tracked_in_git": False,
            "legacy_18_tree_evidence_overwritten": False,
            "other_tree_observed_stream_bytes_reused": False,
            "assignment_or_br1cs_created": False,
            "pickle_cache_or_log_tracked_in_git": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint-payload", type=Path, required=True)
    parser.add_argument("--bounded-parent-vector", type=Path, required=True)
    parser.add_argument("--qualification-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    data = canonical_json(build_evidence(
        args.checkpoint_payload,
        args.bounded_parent_vector,
        args.qualification_directory,
    ))
    if args.output is None:
        print(data.decode(), end="")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    print(json.dumps({
        "output": str(args.output),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bounded_stream_materializer_qualified": True,
        "safe_to_start_production_prefreeze": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
