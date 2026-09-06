#!/usr/bin/env python3
"""Bounded v2.35 authoring skeleton for a unified-tree production runner.

The executable production branch is intentionally fail-closed.  The only
executable branch is an 18-vector, 40-leaf production-shaped qualification
fixture.  No production tree, relation, assignment, BR1CS, or proof can be
created by this checkpoint.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import resource
import time
from typing import Mapping

import pq_rbbc_cap_unified_tree as unified


IMPLEMENTATION_VERSION = "2.35"
FORMAT = "PQRBBC-CAP-UNIFIED-TREE-PRODUCTION-RUNNER-AUTHORING-1"
RELATION_ID = "pq-rbbc/cap/unified-tree/production-runner/authoring/v1"
RELATION_CONTRACT_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-RELATION-CONTRACT-1"
STATE_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-PRODUCTION-SHAPED-STATE-1"
EVIDENCE_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-PRODUCTION-SHAPED-EVIDENCE-1"
QUALIFICATION_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-PRODUCTION-RUNNER-QUALIFICATION-1"
ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = (
    ROOT / "manifests/"
    "pq_rbbc_cap_unified_tree_production_runner_manifest_v2_35.json"
)
STATE_FILENAME = "pq_rbbc_cap_unified_tree_production_shaped_state_v2_35.json"
EVIDENCE_FILENAME = "pq_rbbc_cap_unified_tree_production_shaped_evidence_v2_35.json"
QUALIFICATION_FILENAME = (
    "pq_rbbc_cap_unified_tree_production_runner_qualification_v2_35.json"
)
CHALLENGE_PREFIX = b"PQ-RBBC/v2.35/production-shaped/challenge-prefix"

PRODUCTION_PROFILE_FINGERPRINT = unified.profile_fingerprint(
    unified.PRODUCTION_PARAMETERS
)
V2_34_PORTABLE_EVIDENCE = {
    "filename": "pq_rbbc_cap_unified_tree_production_prefreeze_evidence_v2_34.json",
    "bytes": 3_816,
    "sha256": "7778bdad550baa31e530c739e916e14d5e5ce4738846c64f2c0729b663a9e341",
}

QUALIFICATION_PARAMETERS = unified.UnifiedTreeParameters(
    name="PQ-RBBC-CAP-UNIFIED-GGM-PRODUCTION-SHAPED-18V-TEST-ONLY-v1",
    logical_leaf_counts=(4, 4) + (2,) * 16,
    tape_bits=64,
    t_open=18,
    explicit_pow_bits=2,
    target_security_bits=0,
    secure_profile=False,
)


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
        raise ValueError(f"{path.name} root must be an object")
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


def relation_contract() -> dict[str, object]:
    parameters = unified.PRODUCTION_PARAMETERS
    return {
        "format": RELATION_CONTRACT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": (
            "pq-rbbc/cap/tcith-iii/anemoi-193-336/"
            "unified-ggm/production-relation/candidate/v1"
        ),
        "profile": {
            "name": parameters.name,
            "fingerprint": PRODUCTION_PROFILE_FINGERPRINT,
            "logical_leaf_counts": list(parameters.logical_leaf_counts),
            "root_seed_count": 1,
            "total_leaves": parameters.total_leaves,
            "internal_nodes": parameters.total_leaves - 1,
            "challenge_index_bits": parameters.challenge_index_bits,
            "explicit_pow_bits": parameters.explicit_pow_bits,
            "t_open": parameters.t_open,
        },
        "input_contract": {
            "public_statement": (
                "canonical v2.32 logical statement; final unified-profile byte "
                "encoding remains to be frozen"
            ),
            "private_witness": (
                "ticket relation witness plus fresh unified CAP randomness"
            ),
            "statement_must_not_be_inferred_from_witness": True,
            "legacy_assignment_is_input": False,
        },
        "ordered_stages": [
            {
                "id": "seed-expansion",
                "count": parameters.total_leaves - 1,
                "domain_hex": unified.DOMAIN_SEED_DERIVE.hex(),
                "observed_rows": None,
                "observed_stream_bytes": None,
            },
            {
                "id": "leaf-commit-and-tape",
                "count": parameters.total_leaves,
                "domains_hex": [
                    unified.DOMAIN_SEED_COMMIT.hex(),
                    unified.DOMAIN_TAPE_EXPAND.hex(),
                ],
                "observed_rows": None,
                "observed_stream_bytes": None,
            },
            {
                "id": "logical-vector-hashes",
                "count": parameters.vector_count,
                "domain_hex": unified.DOMAIN_VECTOR_HASH.hex(),
                "observed_rows": None,
                "observed_stream_bytes": None,
            },
            {
                "id": "unified-root-hash",
                "count": 1,
                "domain_hex": unified.DOMAIN_ROOT_HASH.hex(),
                "observed_rows": None,
                "observed_stream_bytes": None,
            },
            {
                "id": "cap-relation-and-parent-binding",
                "count": 1,
                "requires_rebuilt_relocation_aggregate_global_tail_parent": True,
                "observed_rows": None,
                "observed_stream_bytes": None,
            },
        ],
        "pre_freeze_observations": {
            "combined_rows": None,
            "wire_count": None,
            "row_stream_bytes": None,
            "row_stream_sha256": None,
            "assignment_bytes": None,
            "assignment_sha256": None,
            "commitment_bytes": None,
            "opening_bytes": None,
            "elapsed_seconds": None,
            "peak_memory_bytes": None,
        },
        "planning_lower_bounds_not_observations": {
            "combined_rows": 589_054_075,
            "two_full_replay_row_checks": 1_178_108_150,
        },
        "must_be_new_profile_evidence": [
            "unified producer row stream and assignment",
            "output relocation",
            "aggregate relation",
            "parent-bound global tail",
            "CAP-to-H_RBBC parent join",
            "incremental BR1CS and full relation identity",
        ],
        "forbidden_as_new_observations": [
            "tree 0-17 observed stream_bytes",
            "tree 0-17 row-stream digests",
            "tree 0-17 assignment identities",
            "v2.29 589030555-row transcript identity",
        ],
        "state_machine": [
            "launch-gate-validated",
            "fresh-output-reserved",
            "seed-expansion",
            "leaf-commit-and-tape",
            "logical-vector-hashes",
            "unified-root-hash",
            "relation-and-parent-rebuild",
            "pre-freeze-evidence",
        ],
        "resume_requirements": {
            "external_state_only": True,
            "canonical_json_metadata": True,
            "pickle_forbidden": True,
            "each_stage_binds_all_input_and_prefix_identities": True,
            "production_checkpoint_payload_format_implemented": False,
        },
        "status": "authored_not_implemented_not_observed",
    }


RELATION_CONTRACT_SHA256 = sha256_bytes(canonical_json(relation_contract()))


def prospective_production_command() -> str:
    return (
        "PYTHONPATH=src python -u "
        "src/pq_rbbc_cap_unified_tree_production_runner.py "
        "--profile-manifest manifests/"
        "pq_rbbc_cap_unified_tree_production_runner_manifest_v2_35.json "
        "--phase production-prefreeze "
        "--authorization-manifest /tmp/pq_rbbc_external_artifacts_rebuilt/"
        "v2_35_unified_tree_runner/"
        "pq_rbbc_cap_unified_tree_launch_authorization_v2_35.json "
        "--output /tmp/pq_rbbc_external_artifacts_rebuilt/"
        "v2_35_unified_tree_runner/production-prefreeze "
        "--fresh-cache --allow-large"
    )


def claim_boundary() -> dict[str, bool]:
    return {
        "v2_35_relation_contract_authored": True,
        "v2_35_runner_skeleton_implemented": True,
        "production_shaped_qualification_fixture_implemented": True,
        "production_profile_implemented": False,
        "production_checkpoint_payload_implemented": False,
        "production_runner_qualified": False,
        "production_relation_contract_frozen_by_observation": False,
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


def build_manifest() -> dict[str, object]:
    command = prospective_production_command()
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "authorization_scope": {
            "runner_skeleton_and_bounded_fixture_authorized": True,
            "production_prefreeze_authorized": False,
            "large_replay_authorized": False,
            "large_proving_run_authorized": False,
        },
        "v2_34_portable_evidence": V2_34_PORTABLE_EVIDENCE,
        "relation_contract": relation_contract(),
        "relation_contract_sha256": RELATION_CONTRACT_SHA256,
        "qualification_profile": unified.profile_contract(
            QUALIFICATION_PARAMETERS
        ),
        "qualification_profile_fingerprint": unified.profile_fingerprint(
            QUALIFICATION_PARAMETERS
        ),
        "implementation_gate": {
            "production_branch_always_rejects": True,
            "accepted_executable_phase": "qualification",
            "production_checkpoint_payload_implemented": False,
            "production_relation_generator_implemented": False,
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
    expected = build_manifest()
    if document != expected:
        raise ValueError("profile manifest is not the frozen v2.35 authoring contract")
    return document


def state_contract(profile_manifest: Path) -> dict[str, object]:
    return {
        "profile_manifest": identity(profile_manifest),
        "unified_tree_implementation": identity(
            ROOT / "src/pq_rbbc_cap_unified_tree.py"
        ),
        "production_runner_skeleton": identity(
            ROOT / "src/pq_rbbc_cap_unified_tree_production_runner.py"
        ),
        "v2_34_portable_evidence": V2_34_PORTABLE_EVIDENCE,
        "relation_contract_sha256": RELATION_CONTRACT_SHA256,
        "qualification_profile_fingerprint": unified.profile_fingerprint(
            QUALIFICATION_PARAMETERS
        ),
        "challenge_prefix_sha256": sha256_bytes(CHALLENGE_PREFIX),
        "phase": "production-shaped-qualification",
        "production_profile_permitted": False,
    }


def plan_stage() -> dict[str, object]:
    parameters = QUALIFICATION_PARAMETERS
    return {
        "stage": "plan",
        "logical_vector_count": parameters.vector_count,
        "logical_leaf_counts": list(parameters.logical_leaf_counts),
        "large_to_small_leaf_ratio": 2,
        "total_leaves": parameters.total_leaves,
        "internal_nodes": parameters.total_leaves - 1,
        "position_major_mapping_bijective": all(
            unified.unified_to_logical_index(
                parameters,
                unified.logical_to_unified_index(parameters, repetition, position),
            ) == (repetition, position)
            for repetition, leaves in enumerate(parameters.logical_leaf_counts)
            for position in range(leaves)
        ),
        "production_leaves": 0,
        "relation_rows": 0,
    }


def _commit_stage(execution: unified.UnifiedTreeExecution) -> dict[str, object]:
    encoded = execution.commitment.encode()
    parameters = execution.parameters
    return {
        "stage": "commit",
        "profile_fingerprint": unified.profile_fingerprint(parameters),
        "root_seed_sha256": sha256_bytes(
            unified._field_bytes(execution.randomness.root_seed)
        ),
        "commitment_bytes": len(encoded),
        "commitment_sha256": sha256_bytes(encoded),
        "root_digest_hex": unified._hash_bytes(
            execution.commitment.root_digest
        ).hex(),
        "node_count": len(execution.nodes),
        "leaf_count": parameters.total_leaves,
        "xof_call_count": len(execution.xof_records),
        "xof_trace_sha256": unified.trace_digest(execution.xof_records),
    }


def _opening_stage(
    opening: unified.UnifiedOpening, trials: int
) -> dict[str, object]:
    encoded = opening.encode(QUALIFICATION_PARAMETERS)
    _, explicit = unified.decode_challenge(QUALIFICATION_PARAMETERS, opening.h3)
    return {
        "stage": "opening",
        "counter": opening.counter,
        "trials": trials,
        "h3_hex": unified._hash_bytes(opening.h3).hex(),
        "hidden_positions": list(opening.hidden_positions),
        "frontier_nodes": [item.node_index for item in opening.frontier],
        "frontier_count": len(opening.frontier),
        "explicit_pow_value": explicit,
        "opening_bytes": len(encoded),
        "opening_sha256": sha256_bytes(encoded),
    }


def deterministic_result_identity(stages: list[dict[str, object]]) -> str:
    return sha256_bytes(canonical_json(stages))


def _load_state(
    path: Path, expected_contract: Mapping[str, object]
) -> list[dict[str, object]]:
    document = _read_json(path)
    if (
        document.get("format") != STATE_FORMAT
        or document.get("contract") != expected_contract
        or not isinstance(document.get("stages"), list)
    ):
        raise ValueError("resume state identity mismatch")
    return list(document["stages"])


def _save_state(
    output: Path,
    contract: Mapping[str, object],
    stages: list[dict[str, object]],
) -> None:
    _atomic_json(output / STATE_FILENAME, {
        "format": STATE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "contract": contract,
        "completed_stage_names": [item["stage"] for item in stages],
        "stages": stages,
    })


def run_qualification(
    profile_manifest: Path,
    output: Path,
    *,
    fresh_cache: bool = False,
    resume: bool = False,
    stop_after_plan: bool = False,
) -> dict[str, object] | None:
    if fresh_cache == resume:
        raise ValueError("select exactly one of fresh_cache or resume")
    validate_manifest(profile_manifest)
    if not _outside_repository(output):
        raise ValueError("qualification output must be external to the repository")
    contract = state_contract(profile_manifest)
    state_path = output / STATE_FILENAME
    if fresh_cache:
        if output.exists():
            raise FileExistsError("fresh-cache output already exists")
        output.mkdir(parents=True)
        previous: list[dict[str, object]] = []
    else:
        if not state_path.is_file():
            raise FileNotFoundError("resume state is missing")
        previous = _load_state(state_path, contract)

    plan = plan_stage()
    if previous and previous[0] != plan:
        raise ValueError("resume plan stage mismatch")
    stages = [plan]
    _save_state(output, contract, stages)
    if stop_after_plan:
        return None

    started = time.perf_counter()
    randomness = unified.deterministic_randomness(
        QUALIFICATION_PARAMETERS,
        b"PQ-RBBC/v2.35/production-shaped/frozen-randomness",
    )
    execution = unified.execute_commit(QUALIFICATION_PARAMETERS, randomness)
    commit = _commit_stage(execution)
    stages.append(commit)
    opening, trials = unified.grind_opening(
        execution, CHALLENGE_PREFIX, max_trials=100_000
    )
    opening_stage = _opening_stage(opening, trials)
    stages.append(opening_stage)
    verification = unified.verify_opening(
        QUALIFICATION_PARAMETERS,
        CHALLENGE_PREFIX,
        execution.commitment.encode(),
        opening.encode(QUALIFICATION_PARAMETERS),
    )
    if not verification.accepted:
        raise RuntimeError(
            f"production-shaped opening rejected: {verification.failures}"
        )
    verify = {
        "stage": "verify",
        "accepted": True,
        "failures": [],
        "opened_leaf_count": verification.opened_leaf_count,
        "hidden_leaf_count": verification.hidden_leaf_count,
        "opened_tape_sha256": verification.opened_tape_sha256,
    }
    stages.append(verify)
    if len(previous) > 1 and previous != stages[: len(previous)]:
        raise ValueError("resume completed-stage mismatch")
    _save_state(output, contract, stages)
    evidence = {
        "format": EVIDENCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "source_identities": contract,
        "qualification_profile": unified.profile_contract(
            QUALIFICATION_PARAMETERS
        ),
        "production_shape_invariants": {
            "logical_vector_count": 18,
            "two_large_vectors": True,
            "sixteen_small_vectors": True,
            "large_to_small_leaf_ratio": 2,
            "position_major_mapping": True,
            "single_root": True,
        },
        "stages": stages,
        "deterministic_result_identity": deterministic_result_identity(stages),
        "resource_measurements": {
            "elapsed_seconds": time.perf_counter() - started,
            "peak_memory_bytes": (
                resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
            ),
            "qualification_leaves_expanded": (
                QUALIFICATION_PARAMETERS.total_leaves
            ),
            "production_leaves_expanded": 0,
            "relation_rows_replayed": 0,
            "proofs_generated": 0,
        },
        "claim_boundary": claim_boundary(),
    }
    _atomic_json(output / EVIDENCE_FILENAME, evidence)
    return evidence


def production_rejection_reasons() -> list[str]:
    return [
        "v2.35 production checkpoint payload is not implemented",
        "v2.35 production relation generator is not implemented",
        "operator resource reservation identity is not frozen",
        "independent review identity is not frozen",
        "production pre-freeze execution is not authorized",
        "a later identity-frozen launch manifest is required",
    ]


def reject_production_prefreeze(
    profile_manifest: Path,
    output: Path,
    authorization_manifest: Path | None,
    allow_large: bool,
) -> None:
    validate_manifest(profile_manifest)
    if output.exists():
        raise FileExistsError("production output already exists")
    if not _outside_repository(output):
        raise ValueError("production output must be external to the repository")
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


def qualify_runner(
    profile_manifest: Path,
    main_output: Path,
    main_evidence: Mapping[str, object],
) -> dict[str, object]:
    resume_output = main_output.with_name(
        main_output.name + "-resume-qualification"
    )
    run_qualification(
        profile_manifest,
        resume_output,
        fresh_cache=True,
        stop_after_plan=True,
    )
    resumed = run_qualification(
        profile_manifest,
        resume_output,
        resume=True,
    )
    assert resumed is not None
    overwrite_refused = False
    try:
        run_qualification(profile_manifest, main_output, fresh_cache=True)
    except FileExistsError:
        overwrite_refused = True
    rejected_before_output = False
    rejected_output = main_output.with_name(
        main_output.name + "-production-rejection-probe"
    )
    try:
        reject_production_prefreeze(
            profile_manifest, rejected_output, None, False
        )
    except RuntimeError:
        rejected_before_output = not rejected_output.exists()
    main_identity = main_evidence["deterministic_result_identity"]
    resumed_identity = resumed["deterministic_result_identity"]
    qualification = {
        "format": QUALIFICATION_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "runner": identity(
            ROOT / "src/pq_rbbc_cap_unified_tree_production_runner.py"
        ),
        "profile_manifest": identity(profile_manifest),
        "checks": {
            "fresh_qualification_completed": True,
            "interrupted_after_plan": True,
            "resume_state_identity_revalidated": True,
            "resumed_result_matches_fresh_result": (
                main_identity == resumed_identity
            ),
            "existing_output_overwrite_refused": overwrite_refused,
            "production_branch_rejected_before_output": rejected_before_output,
            "state_uses_pickle": False,
            "logical_vector_count": 18,
            "production_leaves_expanded": 0,
            "relation_rows_replayed": 0,
        },
        "result": {
            "runner_skeleton_qualified": all((
                main_identity == resumed_identity,
                overwrite_refused,
                rejected_before_output,
            )),
            "production_runner_qualified": False,
            "safe_to_start_production_prefreeze": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
        },
        "claim_boundary": claim_boundary(),
    }
    _atomic_json(main_output / QUALIFICATION_FILENAME, qualification)
    return qualification


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile-manifest", type=Path, required=True)
    parser.add_argument(
        "--phase", choices=("qualification", "production-prefreeze"), required=True
    )
    parser.add_argument("--authorization-manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--fresh-cache", action="store_true")
    mode.add_argument("--resume", action="store_true")
    parser.add_argument("--allow-large", action="store_true")
    parser.add_argument("--stop-after-plan", action="store_true")
    parser.add_argument("--skip-runner-qualification", action="store_true")
    args = parser.parse_args()
    if args.phase == "production-prefreeze":
        reject_production_prefreeze(
            args.profile_manifest,
            args.output,
            args.authorization_manifest,
            args.allow_large,
        )
    if args.authorization_manifest is not None or args.allow_large:
        raise ValueError("qualification phase forbids production authorization inputs")
    evidence = run_qualification(
        args.profile_manifest,
        args.output,
        fresh_cache=args.fresh_cache,
        resume=args.resume,
        stop_after_plan=args.stop_after_plan,
    )
    result: dict[str, object] = {
        "phase": args.phase,
        "output": str(args.output),
        "complete": evidence is not None,
        "production_profile_invoked": False,
        "production_leaves_expanded": 0,
        "relation_rows_replayed": 0,
        "large_replay_started": False,
    }
    if evidence is not None:
        result["evidence"] = identity(args.output / EVIDENCE_FILENAME)
        if args.fresh_cache and not args.skip_runner_qualification:
            qualification = qualify_runner(
                args.profile_manifest, args.output, evidence
            )
            result["qualification"] = identity(
                args.output / QUALIFICATION_FILENAME
            )
            result["runner_skeleton_qualified"] = qualification[
                "result"
            ]["runner_skeleton_qualified"]
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
