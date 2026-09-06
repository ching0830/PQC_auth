#!/usr/bin/env python3
"""Seal the v2.36 bounded checkpoint-payload and relation qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_unified_tree_bounded_relation as bounded


IMPLEMENTATION_VERSION = "2.36"
FORMAT = "PQRBBC-CAP-UNIFIED-TREE-BOUNDED-RELATION-PORTABLE-EVIDENCE-1"
RELATION_ID = "pq-rbbc/cap/unified-tree/bounded-relation/portable-evidence/v1"
ROOT = Path(__file__).resolve().parents[1]

TRACKED = {
    "unified_tree_implementation": (
        ROOT / "src/pq_rbbc_cap_unified_tree.py",
        32_068,
        "6be95221ab178704e1257c41ec42066807b5e59acd89a59458dcfd613d4ce1e4",
    ),
    "v2_35_production_runner_skeleton": (
        ROOT / "src/pq_rbbc_cap_unified_tree_production_runner.py",
        25_541,
        "05328e30a6a17283c2329867c00601aea5894c18b6e9a0d49e98c48e5e8ffeee",
    ),
    "bounded_relation_implementation": (
        ROOT / "src/pq_rbbc_cap_unified_tree_bounded_relation.py",
        48_372,
        "c69bce3063045f6f468993e7b940d7d3c1277859e75ca546a13325d497a374a7",
    ),
    "bounded_relation_manifest": (
        ROOT / "manifests/"
        "pq_rbbc_cap_unified_tree_bounded_relation_manifest_v2_36.json",
        4_283,
        "5cc01d28b5cc4ed4c4520b8257d0dc0e159777242c85d24f42325e2f68bb72f4",
    ),
    "bounded_relation_tests": (
        ROOT / "tests/test_pq_rbbc_cap_unified_tree_bounded_relation.py",
        8_172,
        "e173c71292babd7dd527bb817d41c9b85fdf3a5f62c76c3cac21686e166a9947",
    ),
    "bounded_relation_evidence_tests": (
        ROOT / "tests/"
        "test_pq_rbbc_cap_unified_tree_bounded_relation_evidence.py",
        3_359,
        "9b58f9705f364cb0683e91d9dfacf11ad24165e1d4967234f2bb98b1778dae86",
    ),
    "v2_35_portable_evidence": (
        ROOT / "artifacts/metadata/cap_unified_tree_production_runner_v2_35/"
        "pq_rbbc_cap_unified_tree_production_runner_evidence_v2_35.json",
        4_836,
        "5284654b909158c18c3f3df50b9de190e50bf06469b1d1f1036bfeb860cf292e",
    ),
}

CHECKPOINT_IDENTITY = {
    "filename": bounded.CHECKPOINT_FILENAME,
    "bytes": 21_530,
    "sha256": "a605d18efa8f23eec3c89da1e4497ddff2c29790c0ea3cb0b7017808cfa39a17",
}
RELATION_IDENTITY = {
    "filename": bounded.RELATION_FILENAME,
    "bytes": 40_542,
    "sha256": "38798e22796af846206e8234fbb15e0ed243c3e0722e363980bf655df9a375cc",
}
RUN_EVIDENCE_IDENTITY = {
    "filename": bounded.EVIDENCE_FILENAME,
    "bytes": 3_042,
    "sha256": "2347a9b02f8a55f7b1a4880093bc2f0974df47a828e7b429af7b7c8e75069dc3",
}
QUALIFICATION_IDENTITY = {
    "filename": bounded.QUALIFICATION_FILENAME,
    "bytes": 2_534,
    "sha256": "d97cc7543d2c917ad83073fc621bc056f6d06650184e3ae97fcec1040989b280",
}
INTERRUPTED_CHECKPOINT_IDENTITY = {
    "filename": bounded.CHECKPOINT_FILENAME,
    "bytes": 20_959,
    "sha256": "88ef0b5584a090ffcc18e36d58333742027545c34e1d4261172f9d1e1df85024",
}
DETERMINISTIC_RESULT_IDENTITY = (
    "10331098958ad60c3433ff0be8c81a22d1d4575a7840eecb924d70cf4bfd8226"
)
ROW_STREAM_SHA256 = (
    "d59afc7818dd945150206e33ded77e39851876227035bbdb59e2ce23697e80c9"
)


def canonical_json(document: Mapping[str, object]) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require(path: Path, expected: Mapping[str, object], label: str) -> None:
    if not path.is_file():
        raise ValueError(f"{label} is missing")
    if (
        path.name != expected["filename"]
        or path.stat().st_size != expected["bytes"]
        or _sha256(path) != expected["sha256"]
    ):
        raise ValueError(f"{label} identity mismatch")


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} root must be an object")
    return document


def validate_run_evidence(document: Mapping[str, object]) -> None:
    observations = document.get("observations", {})
    if (
        document.get("format") != bounded.EVIDENCE_FORMAT
        or document.get("implementation_version") != IMPLEMENTATION_VERSION
        or document.get("relation_id") != bounded.RELATION_ID
        or document.get("source_contract")
        != bounded.state_contract(bounded.MANIFEST_PATH)
        or document.get("execution_mode") != "resume"
        or document.get("checkpoint_payload") != CHECKPOINT_IDENTITY
        or document.get("bounded_relation") != RELATION_IDENTITY
        or document.get("deterministic_result_identity")
        != DETERMINISTIC_RESULT_IDENTITY
        or document.get("claim_boundary") != bounded.claim_boundary()
        or observations.get("logical_vectors") != 18
        or observations.get("bounded_leaves_expanded") != 40
        or observations.get("bounded_contract_rows") != 144
        or observations.get("bounded_relation_failures") != 0
        or observations.get("production_leaves_expanded") != 0
        or observations.get("production_relation_rows") != 0
        or observations.get("br1cs_rows") != 0
        or observations.get("proofs_generated") != 0
        or not isinstance(observations.get("tree_elapsed_seconds"), (int, float))
        or observations.get("tree_elapsed_seconds", 0) <= 0
        or not isinstance(
            observations.get("relation_elapsed_seconds"), (int, float)
        )
        or observations.get("relation_elapsed_seconds", 0) <= 0
        or not isinstance(observations.get("peak_memory_bytes"), int)
        or observations.get("peak_memory_bytes", 0) <= 0
    ):
        raise ValueError("v2.36 run evidence mismatch")


def validate_qualification(document: Mapping[str, object]) -> None:
    expected_checks = {
        "fresh_checkpoint_created": True,
        "interrupted_after_unified_tree": True,
        "resume_required_expected_payload_identity": True,
        "resume_completed_bounded_relation": True,
        "existing_output_overwrite_refused": True,
        "checkpoint_mutation_rejected": True,
        "production_branch_rejected_before_output": True,
        "state_uses_pickle": False,
        "private_witness_only_in_external_payload": True,
        "other_tree_observed_stream_bytes_reused": False,
        "production_leaves_expanded": 0,
        "production_relation_rows": 0,
    }
    expected_result = {
        "checkpoint_payload_format_qualified_on_bounded_fixture": True,
        "bounded_relation_generator_qualified": True,
        "production_relation_generator_scale_qualified": False,
        "safe_to_start_production_prefreeze": False,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
    }
    if (
        document.get("format") != bounded.QUALIFICATION_FORMAT
        or document.get("implementation_version") != IMPLEMENTATION_VERSION
        or document.get("relation_id") != bounded.RELATION_ID
        or document.get("implementation")
        != bounded.identity(
            ROOT / "src/pq_rbbc_cap_unified_tree_bounded_relation.py"
        )
        or document.get("manifest") != bounded.identity(bounded.MANIFEST_PATH)
        or document.get("checks") != expected_checks
        or document.get("interrupted_checkpoint_identity")
        != INTERRUPTED_CHECKPOINT_IDENTITY
        or document.get("completed_checkpoint_identity") != CHECKPOINT_IDENTITY
        or document.get("result") != expected_result
        or document.get("claim_boundary") != bounded.claim_boundary()
    ):
        raise ValueError("v2.36 qualification mismatch")


def build_evidence(
    checkpoint_path: Path,
    relation_path: Path,
    run_evidence_path: Path,
    qualification_path: Path,
) -> dict[str, object]:
    for label, (path, size, digest) in TRACKED.items():
        _require(path, {
            "filename": path.name,
            "bytes": size,
            "sha256": digest,
        }, label)
    for path, expected, label in (
        (checkpoint_path, CHECKPOINT_IDENTITY, "checkpoint payload"),
        (relation_path, RELATION_IDENTITY, "bounded relation"),
        (run_evidence_path, RUN_EVIDENCE_IDENTITY, "run evidence"),
        (qualification_path, QUALIFICATION_IDENTITY, "qualification"),
    ):
        _require(path, expected, label)
    checkpoint = _read_json(checkpoint_path)
    relation = _read_json(relation_path)
    run_evidence = _read_json(run_evidence_path)
    qualification = _read_json(qualification_path)
    bounded.validate_checkpoint_document(
        checkpoint, bounded.state_contract(bounded.MANIFEST_PATH)
    )
    bounded.validate_relation_document(relation)
    validate_run_evidence(run_evidence)
    validate_qualification(qualification)
    observations = run_evidence["observations"]
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "tracked_identities": {
            label: {"filename": path.name, "bytes": size, "sha256": digest}
            for label, (path, size, digest) in TRACKED.items()
        },
        "external_identities": {
            "completed_checkpoint_payload": CHECKPOINT_IDENTITY,
            "bounded_relation": RELATION_IDENTITY,
            "run_evidence": RUN_EVIDENCE_IDENTITY,
            "qualification": QUALIFICATION_IDENTITY,
            "interrupted_checkpoint_payload": INTERRUPTED_CHECKPOINT_IDENTITY,
        },
        "bound_contracts": {
            "v2_35_portable_evidence": bounded.V2_35_PORTABLE_EVIDENCE,
            "v2_35_relation_contract_sha256": (
                bounded.v2_35.RELATION_CONTRACT_SHA256
            ),
            "production_profile_fingerprint": (
                bounded.v2_35.PRODUCTION_PROFILE_FINGERPRINT
            ),
            "bounded_profile_fingerprint": (
                bounded.fixture_contract()["profile_fingerprint"]
            ),
            "public_statement_sha256": (
                bounded.fixture_contract()["public_statement_sha256"]
            ),
            "private_witness_sha256": (
                bounded.fixture_contract()["private_witness_sha256"]
            ),
            "prospective_production_command_sha256": (
                bounded.build_manifest()["prospective_production_command"][
                    "command_sha256"
                ]
            ),
        },
        "bounded_observation": {
            "deterministic_result_identity": DETERMINISTIC_RESULT_IDENTITY,
            "row_count": 144,
            "row_stream_bytes": relation["row_stream_bytes"],
            "row_stream_sha256": ROW_STREAM_SHA256,
            "failures": 0,
            "logical_vectors": 18,
            "leaves_expanded": 40,
            "tree_elapsed_seconds": observations["tree_elapsed_seconds"],
            "relation_elapsed_seconds": observations[
                "relation_elapsed_seconds"
            ],
            "peak_memory_bytes": observations["peak_memory_bytes"],
            "production_leaves_expanded": 0,
            "production_relation_rows": 0,
            "br1cs_rows": 0,
            "proofs_generated": 0,
        },
        "qualification_result": qualification["result"],
        "static_claim_boundary": bounded.claim_boundary(),
        "remaining_launch_blockers": bounded.production_rejection_reasons(),
        "artifact_policy": {
            "portable_evidence_contains_absolute_paths": False,
            "portable_evidence_contains_private_witness": False,
            "checkpoint_payload_or_resume_state_tracked_in_git": False,
            "legacy_18_tree_evidence_overwritten": False,
            "other_tree_observed_stream_bytes_reused": False,
            "assignment_or_br1cs_created": False,
            "pickle_cache_or_log_tracked_in_git": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint-payload", type=Path, required=True)
    parser.add_argument("--bounded-relation", type=Path, required=True)
    parser.add_argument("--run-evidence", type=Path, required=True)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    data = canonical_json(build_evidence(
        args.checkpoint_payload,
        args.bounded_relation,
        args.run_evidence,
        args.qualification,
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
        "bounded_relation_generator_qualified": True,
        "production_relation_generator_scale_qualified": False,
        "safe_to_start_production_prefreeze": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
