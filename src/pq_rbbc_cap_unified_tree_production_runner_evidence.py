#!/usr/bin/env python3
"""Seal the bounded v2.35 unified-tree production-runner authoring checkpoint."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_unified_tree as unified
import pq_rbbc_cap_unified_tree_production_runner as runner


IMPLEMENTATION_VERSION = "2.35"
FORMAT = "PQRBBC-CAP-UNIFIED-TREE-PRODUCTION-RUNNER-PORTABLE-EVIDENCE-1"
RELATION_ID = "pq-rbbc/cap/unified-tree/production-runner/portable-evidence/v1"
ROOT = Path(__file__).resolve().parents[1]

TRACKED = {
    "unified_tree_implementation": (
        ROOT / "src/pq_rbbc_cap_unified_tree.py",
        32_068,
        "6be95221ab178704e1257c41ec42066807b5e59acd89a59458dcfd613d4ce1e4",
    ),
    "production_runner_skeleton": (
        ROOT / "src/pq_rbbc_cap_unified_tree_production_runner.py",
        25_541,
        "05328e30a6a17283c2329867c00601aea5894c18b6e9a0d49e98c48e5e8ffeee",
    ),
    "production_runner_manifest": (
        ROOT / "manifests/"
        "pq_rbbc_cap_unified_tree_production_runner_manifest_v2_35.json",
        7_000,
        "e995d3e2db48008550ee15de89ce58ca2b574a8142a9cc39f96010d2a44c9bf0",
    ),
    "production_runner_tests": (
        ROOT / "tests/test_pq_rbbc_cap_unified_tree_production_runner.py",
        8_236,
        "c3f02e03e36da623fad03b9ee26a33000d93decd7a235a6babb231b8bbbe4a4b",
    ),
    "production_runner_evidence_tests": (
        ROOT / "tests/"
        "test_pq_rbbc_cap_unified_tree_production_runner_evidence.py",
        3_385,
        "dff43a57fea95a45c0a7f084589372016a32614a2f8675ac7f656aa46046d839",
    ),
    "v2_34_production_prefreeze_portable_evidence": (
        ROOT / "artifacts/metadata/cap_unified_tree_production_prefreeze_v2_34/"
        "pq_rbbc_cap_unified_tree_production_prefreeze_evidence_v2_34.json",
        3_816,
        "7778bdad550baa31e530c739e916e14d5e5ce4738846c64f2c0729b663a9e341",
    ),
}

RUN_EVIDENCE_IDENTITY = {
    "filename": runner.EVIDENCE_FILENAME,
    "bytes": 5_506,
    "sha256": "f17a82f67785612b040301893852eb72ee46eabe21e93dd017fc69d8599e3659",
}
QUALIFICATION_IDENTITY = {
    "filename": runner.QUALIFICATION_FILENAME,
    "bytes": 1_867,
    "sha256": "f124f9b27d5c6b6a82ff717ddf148ef683c43a0cc4e16ff47961cc7ba6e59329",
}
DETERMINISTIC_RESULT_IDENTITY = (
    "5075ebcbabb7cfa95a459f27a21bf2a0db11b7ef0f7ec69e30a4414f0c3a2a0f"
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
    stages = document.get("stages")
    resources = document.get("resource_measurements", {})
    if not isinstance(stages, list) or len(stages) != 4:
        raise ValueError("v2.35 stage sequence mismatch")
    by_name = {
        stage.get("stage"): stage
        for stage in stages
        if isinstance(stage, dict)
    }
    plan = by_name.get("plan", {})
    commit = by_name.get("commit", {})
    opening = by_name.get("opening", {})
    verify = by_name.get("verify", {})
    if (
        document.get("format") != runner.EVIDENCE_FORMAT
        or document.get("implementation_version") != IMPLEMENTATION_VERSION
        or document.get("relation_id") != runner.RELATION_ID
        or document.get("source_identities")
        != runner.state_contract(runner.MANIFEST_PATH)
        or document.get("qualification_profile")
        != unified.profile_contract(runner.QUALIFICATION_PARAMETERS)
        or document.get("production_shape_invariants") != {
            "logical_vector_count": 18,
            "two_large_vectors": True,
            "sixteen_small_vectors": True,
            "large_to_small_leaf_ratio": 2,
            "position_major_mapping": True,
            "single_root": True,
        }
        or [stage.get("stage") for stage in stages]
        != ["plan", "commit", "opening", "verify"]
        or document.get("deterministic_result_identity")
        != DETERMINISTIC_RESULT_IDENTITY
        or runner.deterministic_result_identity(stages)
        != DETERMINISTIC_RESULT_IDENTITY
        or document.get("claim_boundary") != runner.claim_boundary()
    ):
        raise ValueError("v2.35 run evidence contract mismatch")
    if (
        plan.get("logical_vector_count") != 18
        or plan.get("logical_leaf_counts") != [4, 4] + [2] * 16
        or plan.get("total_leaves") != 40
        or plan.get("internal_nodes") != 39
        or plan.get("position_major_mapping_bijective") is not True
        or plan.get("production_leaves") != 0
        or plan.get("relation_rows") != 0
        or commit.get("leaf_count") != 40
        or commit.get("node_count") != 79
        or commit.get("xof_call_count") != 138
        or commit.get("profile_fingerprint")
        != runner.build_manifest()["qualification_profile_fingerprint"]
        or opening.get("counter") != 4
        or opening.get("trials") != 5
        or opening.get("frontier_count") != 12
        or opening.get("opening_bytes") != 1_456
        or verify.get("accepted") is not True
        or verify.get("failures") != []
        or verify.get("opened_leaf_count") != 22
        or verify.get("hidden_leaf_count") != 18
    ):
        raise ValueError("v2.35 bounded execution observation mismatch")
    if (
        resources.get("qualification_leaves_expanded") != 40
        or resources.get("production_leaves_expanded") != 0
        or resources.get("relation_rows_replayed") != 0
        or resources.get("proofs_generated") != 0
        or not isinstance(resources.get("elapsed_seconds"), (int, float))
        or resources.get("elapsed_seconds", 0) <= 0
        or not isinstance(resources.get("peak_memory_bytes"), int)
        or resources.get("peak_memory_bytes", 0) <= 0
    ):
        raise ValueError("v2.35 bounded resource observation mismatch")


def validate_qualification(document: Mapping[str, object]) -> None:
    expected_checks = {
        "fresh_qualification_completed": True,
        "interrupted_after_plan": True,
        "resume_state_identity_revalidated": True,
        "resumed_result_matches_fresh_result": True,
        "existing_output_overwrite_refused": True,
        "production_branch_rejected_before_output": True,
        "state_uses_pickle": False,
        "logical_vector_count": 18,
        "production_leaves_expanded": 0,
        "relation_rows_replayed": 0,
    }
    expected_result = {
        "runner_skeleton_qualified": True,
        "production_runner_qualified": False,
        "safe_to_start_production_prefreeze": False,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
    }
    if (
        document.get("format") != runner.QUALIFICATION_FORMAT
        or document.get("implementation_version") != IMPLEMENTATION_VERSION
        or document.get("relation_id") != runner.RELATION_ID
        or document.get("runner")
        != runner.identity(
            ROOT / "src/pq_rbbc_cap_unified_tree_production_runner.py"
        )
        or document.get("profile_manifest") != runner.identity(runner.MANIFEST_PATH)
        or document.get("checks") != expected_checks
        or document.get("result") != expected_result
        or document.get("claim_boundary") != runner.claim_boundary()
    ):
        raise ValueError("v2.35 runner qualification mismatch")


def build_evidence(
    run_evidence_path: Path,
    qualification_path: Path,
) -> dict[str, object]:
    for label, (path, size, digest) in TRACKED.items():
        _require(path, {
            "filename": path.name,
            "bytes": size,
            "sha256": digest,
        }, label)
    _require(run_evidence_path, RUN_EVIDENCE_IDENTITY, "run evidence")
    _require(qualification_path, QUALIFICATION_IDENTITY, "runner qualification")
    run_evidence = _read_json(run_evidence_path)
    qualification = _read_json(qualification_path)
    validate_run_evidence(run_evidence)
    validate_qualification(qualification)
    stages = {stage["stage"]: stage for stage in run_evidence["stages"]}
    resources = run_evidence["resource_measurements"]
    command = runner.prospective_production_command()
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "tracked_identities": {
            label: {"filename": path.name, "bytes": size, "sha256": digest}
            for label, (path, size, digest) in TRACKED.items()
        },
        "external_identities": {
            "production_shaped_run_evidence": RUN_EVIDENCE_IDENTITY,
            "runner_qualification": QUALIFICATION_IDENTITY,
        },
        "bound_contracts": {
            "production_profile_fingerprint": (
                runner.PRODUCTION_PROFILE_FINGERPRINT
            ),
            "qualification_profile_fingerprint": (
                runner.build_manifest()["qualification_profile_fingerprint"]
            ),
            "relation_contract_sha256": runner.RELATION_CONTRACT_SHA256,
            "v2_34_portable_evidence": runner.V2_34_PORTABLE_EVIDENCE,
            "prospective_production_command_sha256": (
                runner.sha256_bytes(command.encode("ascii"))
            ),
        },
        "bounded_observation": {
            "deterministic_result_identity": DETERMINISTIC_RESULT_IDENTITY,
            "logical_vector_count": 18,
            "qualification_leaves_expanded": 40,
            "commitment_bytes": stages["commit"]["commitment_bytes"],
            "commitment_sha256": stages["commit"]["commitment_sha256"],
            "opening_bytes": stages["opening"]["opening_bytes"],
            "opening_sha256": stages["opening"]["opening_sha256"],
            "grinding_counter": stages["opening"]["counter"],
            "grinding_trials": stages["opening"]["trials"],
            "elapsed_seconds": resources["elapsed_seconds"],
            "peak_memory_bytes": resources["peak_memory_bytes"],
            "production_leaves_expanded": 0,
            "relation_rows_replayed": 0,
            "proofs_generated": 0,
        },
        "implementation_status": {
            "relation_contract_authored": True,
            "runner_skeleton_implemented": True,
            "production_shaped_fixture_qualified": True,
            "production_checkpoint_payload_implemented": False,
            "production_relation_generator_implemented": False,
            "production_runner_qualified": False,
        },
        "remaining_launch_blockers": runner.production_rejection_reasons(),
        "result": qualification["result"],
        "claim_boundary": runner.claim_boundary(),
        "artifact_policy": {
            "portable_evidence_contains_absolute_paths": False,
            "legacy_18_tree_evidence_overwritten": False,
            "other_tree_observed_stream_bytes_reused": False,
            "production_assignment_or_br1cs_created": False,
            "pickle_cache_log_or_resume_tracked_in_git": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-evidence", type=Path, required=True)
    parser.add_argument("--runner-qualification", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    data = canonical_json(build_evidence(
        args.run_evidence,
        args.runner_qualification,
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
        "runner_skeleton_qualified": True,
        "production_runner_qualified": False,
        "safe_to_start_production_prefreeze": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
