#!/usr/bin/env python3
"""Seal v2.33 unified-tree specification and reduced-run evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_unified_tree as unified
import pq_rbbc_cap_unified_tree_migration_preflight as preflight
import pq_rbbc_cap_unified_tree_runner as runner


IMPLEMENTATION_VERSION = "2.33"
FORMAT = "PQRBBC-CAP-UNIFIED-TREE-REDUCED-PORTABLE-EVIDENCE-1"
RELATION_ID = "pq-rbbc/cap/unified-tree/reduced-portable-evidence/v1"
ROOT = Path(__file__).resolve().parents[1]

TRACKED = {
    "unified_tree_implementation": (
        ROOT / "src/pq_rbbc_cap_unified_tree.py",
        32_068,
        "6be95221ab178704e1257c41ec42066807b5e59acd89a59458dcfd613d4ce1e4",
    ),
    "reduced_runner": (
        ROOT / "src/pq_rbbc_cap_unified_tree_runner.py",
        23_858,
        "6f126e42420634c2464a6ee8ba3418e2976c8d83c4003bd3db5b5e43a298470e",
    ),
    "specification_source": (
        ROOT / "docs/proof/source/pq_rbbc_cap_unified_tree_spec_v2_33.html",
        10_648,
        "4e197e6cc4cfe7848af2168a3104fd959621637950a4c2091b3a2834e1e407d9",
    ),
    "migration_manifest": (
        ROOT / "manifests/pq_rbbc_cap_unified_tree_migration_manifest_v2_33.json",
        13_990,
        "8686d49f59655f09135d91fc79e236c59bc8d6b582c86a55799a0c13acfad9f5",
    ),
}

EXTERNAL = {
    "specification_pdf": (
        "pq_rbbc_cap_unified_tree_spec_v2_33.pdf",
        140_010,
        "2b8f0c241baa4fd509c2e5e7b0c6f2b6c3108f4f44bc55836825b68a150ee1b0",
    ),
    "reduced_evidence": (
        runner.EVIDENCE_FILENAME,
        6_491,
        "9074659af8db46cc78c224a9562a4c257214ac3a128062782f898d1b307a65dc",
    ),
    "runner_qualification": (
        runner.QUALIFICATION_FILENAME,
        1_210,
        "e7bb68fd9c5caea8afbbc6ef133e64ae77b67a68fdf5f7d09850a3980ba9a050",
    ),
    "post_reduced_report": (
        "pq_rbbc_cap_unified_tree_environment_after_reduced_v2_33.json",
        8_265,
        "d517b5c092fb61b79f362b849d91dd119f1166d9aff64a8c3b5b16479e6b6c39",
    ),
}


def canonical_json(document: Mapping[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require(path: Path, size: int, digest: str, label: str) -> None:
    if not path.is_file():
        raise ValueError(f"{label} is missing")
    if path.stat().st_size != size or _sha256(path) != digest:
        raise ValueError(f"{label} identity mismatch")


def _json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} root must be an object")
    return document


def _validate_reduced_evidence(path: Path) -> dict[str, object]:
    document = _json(path)
    positive = document.get("positive_vector", {})
    mutations = document.get("mutation_vectors", [])
    claims = document.get("claim_boundary", {})
    expected_mutations = {
        "changed_challenge_prefix",
        "wrong_commitment_magic",
        "trailing_opening_bytes",
        "changed_h3",
        "changed_hidden_position",
        "nonzero_explicit_pow_bits",
        "frontier_exceeds_t_open",
        "changed_frontier_seed",
        "changed_hidden_commitment",
    }
    if (
        document.get("format") != runner.EVIDENCE_FORMAT
        or document.get("relation_id") != unified.RELATION_ID
        or document.get("profile_fingerprint")
        != unified.profile_fingerprint(unified.REDUCED_TEST_PARAMETERS)
        or positive.get("commit", {}).get("internal_nodes_expanded") != 11
        or positive.get("commit", {}).get("leaf_count") != 12
        or positive.get("opening", {}).get("counter") != 11
        or positive.get("opening", {}).get("trials") != 12
        or positive.get("opening", {}).get("frontier_nodes") != [4, 6, 7]
        or positive.get("verify", {}).get("accepted") is not True
        or positive.get("verify", {}).get("failures") != []
        or {item.get("id") for item in mutations} != expected_mutations
        or not all(item.get("rejected") is True for item in mutations)
        or document.get("mutation_summary")
        != {"total": 9, "rejected": 9, "accepted": 0}
        or claims.get("exact_unified_tree_algorithm_implemented_for_reduced_profile")
        is not True
        or claims.get("reduced_positive_vector_verified") is not True
        or claims.get("reduced_mutations_rejected") is not True
    ):
        raise ValueError("reduced evidence result mismatch")
    for name in (
        "production_profile_implemented",
        "production_profile_fingerprint_frozen",
        "production_prefreeze_started",
        "large_replay_started",
        "large_proving_run_started",
        "cap_security_qualified",
        "fork_security_proof_revalidated",
        "production_closed",
        "system_architecture_changed",
        "ticket_lifecycle_changed",
        "pq_sat_auth_changed",
    ):
        if claims.get(name) is not False:
            raise ValueError(f"reduced evidence claim expansion: {name}")
    return document


def _validate_runner_qualification(path: Path) -> dict[str, object]:
    document = _json(path)
    checks = document.get("checks", {})
    result = document.get("result", {})
    required_true = (
        "fresh_cache_completed",
        "interrupted_after_commit",
        "resume_state_identity_revalidated",
        "resumed_result_matches_fresh_result",
        "existing_output_overwrite_refused",
    )
    if (
        document.get("format") != runner.QUALIFICATION_FORMAT
        or any(checks.get(name) is not True for name in required_true)
        or checks.get("resume_uses_pickle") is not False
        or checks.get("production_profile_invoked") is not False
        or checks.get("relation_rows_replayed") != 0
        or result.get("reduced_runner_qualified") is not True
        or result.get("production_runner_qualified") is not False
        or result.get("safe_to_start_production_prefreeze") is not False
        or result.get("safe_to_start_large_replay") is not False
    ):
        raise ValueError("runner qualification mismatch")
    return document


def _validate_report(path: Path) -> dict[str, object]:
    document = _json(path)
    migration = document.get("checks", {}).get("migration_artifacts", {})
    supplied = {
        "unified_tree_algorithm_specification": EXTERNAL["specification_pdf"],
        "reduced_prototype_evidence": EXTERNAL["reduced_evidence"],
        "runner_qualification": EXTERNAL["runner_qualification"],
    }
    if (
        document.get("format") != preflight.REPORT_FORMAT
        or document.get("safe_to_author_unified_tree_specification") is not True
        or document.get("safe_to_implement_reduced_prototype") is not True
        or document.get("safe_to_start_production_prefreeze") is not False
        or document.get("safe_to_start_large_replay") is not False
        or document.get("safe_to_start_large_proving_run") is not False
        or document.get("large_profile_build_started") is not False
        or document.get("large_replay_started") is not False
        or document.get("large_proving_run_started") is not False
    ):
        raise ValueError("post-reduced preflight result mismatch")
    for name, (_, size, digest) in supplied.items():
        observed = migration.get(name, {})
        if (
            observed.get("provided") is not True
            or observed.get("schema_valid") is not True
            or observed.get("identity_frozen") is not False
            or observed.get("verified") is not False
            or observed.get("failures") != ["identity_not_frozen"]
            or observed.get("bytes") != size
            or observed.get("sha256") != digest
        ):
            raise ValueError(f"post-reduced candidate mismatch: {name}")
    for name in ("resource_reservation", "independent_design_review"):
        observed = migration.get(name, {})
        if observed.get("provided") is not False or observed.get("failures") != ["not_provided"]:
            raise ValueError(f"post-reduced missing boundary mismatch: {name}")
    return document


def build_evidence(
    specification_pdf: Path,
    reduced_evidence: Path,
    runner_qualification: Path,
    post_reduced_report: Path,
) -> dict[str, object]:
    for label, (path, size, digest) in TRACKED.items():
        _require(path, size, digest, label)
    supplied_paths = {
        "specification_pdf": specification_pdf,
        "reduced_evidence": reduced_evidence,
        "runner_qualification": runner_qualification,
        "post_reduced_report": post_reduced_report,
    }
    for label, path in supplied_paths.items():
        filename, size, digest = EXTERNAL[label]
        if path.name != filename:
            raise ValueError(f"{label} filename mismatch")
        _require(path, size, digest, label)
    if specification_pdf.read_bytes()[:5] != b"%PDF-":
        raise ValueError("specification is not a PDF")
    reduced = _validate_reduced_evidence(reduced_evidence)
    qualification = _validate_runner_qualification(runner_qualification)
    report = _validate_report(post_reduced_report)
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "tracked_source_identities": {
            label: {"filename": path.name, "bytes": size, "sha256": digest}
            for label, (path, size, digest) in TRACKED.items()
        },
        "external_artifact_identities": {
            label: {"filename": filename, "bytes": size, "sha256": digest}
            for label, (filename, size, digest) in EXTERNAL.items()
        },
        "profile": {
            "production_candidate_name": unified.PROFILE_NAME,
            "production_candidate_fingerprint_frozen": False,
            "reduced_profile_name": unified.REDUCED_PROFILE_NAME,
            "reduced_profile_fingerprint": reduced["profile_fingerprint"],
            "legacy_18_tree_profile_preserved": True,
        },
        "specification": {
            "exact_candidate_algorithm_authored": True,
            "single_root_seed": True,
            "production_total_leaves": 40_960,
            "production_internal_nodes_and_seed_derivations": 40_959,
            "position_major_mapping": True,
            "challenge_index_bits": 200,
            "explicit_pow_bits": 9,
            "t_open": 174,
            "independent_reviewed": False,
        },
        "reduced_execution": {
            "positive_vector": reduced["positive_vector"],
            "pow_and_opening_validation": reduced["pow_and_opening_validation"],
            "mutation_summary": reduced["mutation_summary"],
            "resource_measurements": reduced["resource_measurements"],
        },
        "runner_qualification": qualification["checks"],
        "post_reduced_preflight": {
            "specification_candidate_schema_valid": True,
            "reduced_evidence_candidate_schema_valid": True,
            "runner_qualification_candidate_schema_valid": True,
            "candidate_identities_frozen_by_this_portable_seal": True,
            "safe_to_start_production_prefreeze": report[
                "safe_to_start_production_prefreeze"
            ],
            "safe_to_start_large_replay": report["safe_to_start_large_replay"],
            "safe_to_start_large_proving_run": report[
                "safe_to_start_large_proving_run"
            ],
        },
        "remaining_blockers": [
            "operator-approved resource reservation",
            "independent design and cryptographic review",
            "a subsequent read-only pre-freeze checker that binds this seal",
        ],
        "claim_boundary": {
            "exact_unified_tree_specification_authored": True,
            "reduced_unified_tree_implemented_and_verified": True,
            "reduced_runner_qualified": True,
            "production_profile_implemented": False,
            "production_profile_fingerprint_frozen": False,
            "production_prefreeze_started": False,
            "large_replay_started": False,
            "large_proving_run_started": False,
            "cap_security_qualified": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
            "system_architecture_changed": False,
            "ticket_lifecycle_changed": False,
            "pq_sat_auth_changed": False,
        },
        "artifact_policy": {
            "portable_evidence_contains_absolute_paths": False,
            "legacy_evidence_overwritten": False,
            "other_tree_observed_stream_bytes_reused": False,
            "assignment_or_br1cs_tracked_in_git": False,
            "pickle_cache_or_resume_tracked_in_git": False,
            "logs_tracked_in_git": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--specification-pdf", type=Path, required=True)
    parser.add_argument("--reduced-evidence", type=Path, required=True)
    parser.add_argument("--runner-qualification", type=Path, required=True)
    parser.add_argument("--post-reduced-report", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    data = canonical_json(build_evidence(
        args.specification_pdf,
        args.reduced_evidence,
        args.runner_qualification,
        args.post_reduced_report,
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
        "safe_to_start_production_prefreeze": False,
        "safe_to_start_large_replay": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
