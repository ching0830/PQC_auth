#!/usr/bin/env python3
"""Run and qualify only the bounded v2.33 unified-tree CAP prototype."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
from pathlib import Path
import resource
import time
from typing import Callable

import pq_rbbc_cap_unified_tree as unified


IMPLEMENTATION_VERSION = "2.33"
STATE_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-REDUCED-STATE-1"
EVIDENCE_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-REDUCED-EVIDENCE-1"
QUALIFICATION_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-RUNNER-QUALIFICATION-1"
EVIDENCE_FILENAME = "pq_rbbc_cap_unified_tree_reduced_evidence_v2_33.json"
QUALIFICATION_FILENAME = "pq_rbbc_cap_unified_tree_runner_qualification_v2_33.json"
STATE_FILENAME = "pq_rbbc_cap_unified_tree_reduced_state_v2_33.json"
CHALLENGE_PREFIX = b"PQ-RBBC/v2.33/reduced/challenge-prefix"
ROOT = Path(__file__).resolve().parents[1]


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


def _write_json(path: Path, document: object) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(canonical_json(document))
    temporary.replace(path)


def validate_manifest(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError("profile manifest root must be an object")
    descriptor = document.get("reserved_profile_descriptor")
    if not isinstance(descriptor, dict):
        raise ValueError("profile manifest descriptor is missing")
    expected = unified.PRODUCTION_PARAMETERS
    expected_mapping = (
        "position-major interleaving: all 18 repetitions for positions "
        "0..2047, then repetitions 0..1 for positions 2048..4095"
    )
    if (
        document.get("format")
        != "PQRBBC-CAP-UNIFIED-TREE-MIGRATION-PREFLIGHT-1"
        or descriptor.get("name") != unified.PROFILE_NAME
        or descriptor.get("relation_id") != unified.RELATION_ID
        or tuple(descriptor.get("logical_vector_leaf_counts", ()))
        != expected.logical_leaf_counts
        or descriptor.get("unified_tree", {}).get("root_seed_count") != 1
        or descriptor.get("unified_tree", {}).get("leaves") != expected.total_leaves
        or descriptor.get("unified_tree", {}).get("leaf_mapping") != expected_mapping
        or descriptor.get("pow", {}).get("T_open") != expected.t_open
        or descriptor.get("pow", {}).get("explicit_bits")
        != expected.explicit_pow_bits
        or descriptor.get("domain_policy", {}).get("prefix")
        != unified.DOMAIN_PREFIX.decode()
        or document.get("execution_policy", {}).get("large_profile_build_permitted")
        is not False
    ):
        raise ValueError("profile manifest does not match the v2.33 reservation")
    return document


def _state_contract(profile_manifest: Path) -> dict[str, object]:
    implementation = ROOT / "src/pq_rbbc_cap_unified_tree.py"
    runner = ROOT / "src/pq_rbbc_cap_unified_tree_runner.py"
    return {
        "profile_manifest": identity(profile_manifest),
        "implementation": identity(implementation),
        "runner": identity(runner),
        "reduced_profile_fingerprint": unified.profile_fingerprint(
            unified.REDUCED_TEST_PARAMETERS
        ),
        "challenge_prefix_sha256": sha256_bytes(CHALLENGE_PREFIX),
        "phase": "reduced",
        "large_profile_permitted": False,
    }


def _commit_stage(
    execution: unified.UnifiedTreeExecution,
) -> dict[str, object]:
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
        "internal_nodes_expanded": parameters.total_leaves - 1,
        "leaf_count": parameters.total_leaves,
        "logical_leaf_counts": list(parameters.logical_leaf_counts),
        "xof_call_count": len(execution.xof_records),
        "xof_trace_sha256": unified.trace_digest(execution.xof_records),
    }


def _opening_stage(
    parameters: unified.UnifiedTreeParameters,
    opening: unified.UnifiedOpening,
    trials: int,
) -> dict[str, object]:
    encoded = opening.encode(parameters)
    _, explicit = unified.decode_challenge(parameters, opening.h3)
    return {
        "stage": "opening",
        "counter": opening.counter,
        "trials": trials,
        "h3_hex": unified._hash_bytes(opening.h3).hex(),
        "hidden_positions": list(opening.hidden_positions),
        "hidden_commitments_sha256": sha256_bytes(
            b"".join(unified._hash_bytes(item) for item in opening.hidden_commitments)
        ),
        "frontier_nodes": [node.node_index for node in opening.frontier],
        "frontier_count": len(opening.frontier),
        "t_open": parameters.t_open,
        "explicit_pow_value": explicit,
        "explicit_pow_bits": parameters.explicit_pow_bits,
        "opening_bytes": len(encoded),
        "opening_sha256": sha256_bytes(encoded),
    }


def _verify_stage(verification: unified.OpeningVerification) -> dict[str, object]:
    return {
        "stage": "verify",
        "accepted": verification.accepted,
        "failures": list(verification.failures),
        "opened_leaf_count": verification.opened_leaf_count,
        "hidden_leaf_count": verification.hidden_leaf_count,
        "opened_tape_sha256": verification.opened_tape_sha256,
    }


def _expect_rejection(
    vector_id: str,
    action: Callable[[], unified.OpeningVerification],
) -> dict[str, object]:
    try:
        result = action()
    except (unified.UnifiedTreeError, ValueError) as error:
        return {
            "id": vector_id,
            "rejected": True,
            "layer": "canonical_codec",
            "failures": [str(error)],
        }
    if result.accepted:
        raise AssertionError(f"mutation vector accepted: {vector_id}")
    return {
        "id": vector_id,
        "rejected": True,
        "layer": "opening_verifier",
        "failures": list(result.failures),
    }


def mutation_vectors(
    execution: unified.UnifiedTreeExecution,
    opening: unified.UnifiedOpening,
) -> list[dict[str, object]]:
    parameters = execution.parameters
    commitment_bytes = execution.commitment.encode()
    opening_bytes = opening.encode(parameters)
    vectors: list[dict[str, object]] = []

    vectors.append(_expect_rejection(
        "changed_challenge_prefix",
        lambda: unified.verify_opening(
            parameters,
            b"X" + CHALLENGE_PREFIX[1:],
            commitment_bytes,
            opening_bytes,
        ),
    ))
    wrong_commitment_magic = bytes([commitment_bytes[0] ^ 1]) + commitment_bytes[1:]
    vectors.append(_expect_rejection(
        "wrong_commitment_magic",
        lambda: unified.verify_opening(
            parameters, CHALLENGE_PREFIX, wrong_commitment_magic, opening_bytes
        ),
    ))
    vectors.append(_expect_rejection(
        "trailing_opening_bytes",
        lambda: unified.verify_opening(
            parameters, CHALLENGE_PREFIX, commitment_bytes, opening_bytes + b"\x00"
        ),
    ))
    changed_h3 = dataclasses.replace(opening, h3=opening.h3 ^ 1)
    vectors.append(_expect_rejection(
        "changed_h3",
        lambda: unified.verify_opening(
            parameters,
            CHALLENGE_PREFIX,
            commitment_bytes,
            changed_h3.encode(parameters),
        ),
    ))
    changed_position = dataclasses.replace(
        opening,
        hidden_positions=(
            (opening.hidden_positions[0] + 1)
            % parameters.logical_leaf_counts[0],
            *opening.hidden_positions[1:],
        ),
    )
    vectors.append(_expect_rejection(
        "changed_hidden_position",
        lambda: unified.verify_opening(
            parameters,
            CHALLENGE_PREFIX,
            commitment_bytes,
            changed_position.encode(parameters),
        ),
    ))

    bad_pow = next(
        candidate
        for counter in range(opening.counter + 64)
        for candidate in (unified.opening_candidate(execution, CHALLENGE_PREFIX, counter),)
        if len(candidate.frontier) <= parameters.t_open
        and unified.decode_challenge(parameters, candidate.h3)[1] != 0
    )
    vectors.append(_expect_rejection(
        "nonzero_explicit_pow_bits",
        lambda: unified.verify_opening(
            parameters,
            CHALLENGE_PREFIX,
            commitment_bytes,
            bad_pow.encode(parameters),
        ),
    ))
    bad_frontier = next(
        candidate
        for counter in range(opening.counter + 64)
        for candidate in (unified.opening_candidate(execution, CHALLENGE_PREFIX, counter),)
        if len(candidate.frontier) > parameters.t_open
    )
    try:
        bad_frontier.encode(parameters)
    except unified.UnifiedTreeError as error:
        vectors.append({
            "id": "frontier_exceeds_t_open",
            "rejected": True,
            "layer": "canonical_codec",
            "failures": [str(error)],
        })
    else:
        raise AssertionError("oversized frontier serialized")

    changed_seed = dataclasses.replace(
        opening,
        frontier=(
            dataclasses.replace(opening.frontier[0], seed=opening.frontier[0].seed ^ 1),
            *opening.frontier[1:],
        ),
    )
    vectors.append(_expect_rejection(
        "changed_frontier_seed",
        lambda: unified.verify_opening(
            parameters,
            CHALLENGE_PREFIX,
            commitment_bytes,
            changed_seed.encode(parameters),
        ),
    ))
    changed_hidden_commitment = dataclasses.replace(
        opening,
        hidden_commitments=(
            opening.hidden_commitments[0] ^ 1,
            *opening.hidden_commitments[1:],
        ),
    )
    vectors.append(_expect_rejection(
        "changed_hidden_commitment",
        lambda: unified.verify_opening(
            parameters,
            CHALLENGE_PREFIX,
            commitment_bytes,
            changed_hidden_commitment.encode(parameters),
        ),
    ))
    return vectors


def frontier_distribution(
    parameters: unified.UnifiedTreeParameters,
) -> dict[str, int]:
    if parameters is not unified.REDUCED_TEST_PARAMETERS:
        raise ValueError("exhaustive distribution is reduced-only")
    counts: dict[int, int] = {}
    for first in range(parameters.logical_leaf_counts[0]):
        for second in range(parameters.logical_leaf_counts[1]):
            for third in range(parameters.logical_leaf_counts[2]):
                for fourth in range(parameters.logical_leaf_counts[3]):
                    size = len(unified.canonical_frontier_indices(
                        parameters, (first, second, third, fourth)
                    ))
                    counts[size] = counts.get(size, 0) + 1
    return {str(size): count for size, count in sorted(counts.items())}


def deterministic_result_identity(
    commit_stage: dict[str, object],
    opening_stage: dict[str, object],
    verify_stage: dict[str, object],
) -> str:
    return sha256_bytes(canonical_json({
        "commit": commit_stage,
        "opening": opening_stage,
        "verify": verify_stage,
    }))


def build_reduced_evidence(
    state_contract: dict[str, object],
    commit_stage: dict[str, object],
    opening_stage: dict[str, object],
    verify_stage: dict[str, object],
    mutations: list[dict[str, object]],
    elapsed_seconds: float,
    peak_memory_bytes: int,
) -> dict[str, object]:
    parameters = unified.REDUCED_TEST_PARAMETERS
    distribution = frontier_distribution(parameters)
    accepted_index_tuples = sum(
        count for size, count in ((int(k), v) for k, v in distribution.items())
        if size <= parameters.t_open
    )
    total_index_tuples = math_prod(parameters.logical_leaf_counts)
    return {
        "format": EVIDENCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": unified.RELATION_ID,
        "profile": unified.profile_contract(parameters),
        "profile_fingerprint": unified.profile_fingerprint(parameters),
        "source_identities": state_contract,
        "single_root_topology": {
            "root_seed_count": 1,
            "total_leaves": parameters.total_leaves,
            "internal_nodes": parameters.total_leaves - 1,
            "total_nodes": 2 * parameters.total_leaves - 1,
            "seed_derive_calls": parameters.total_leaves - 1,
            "logical_mapping_bijective": True,
        },
        "positive_vector": {
            "commit": commit_stage,
            "opening": opening_stage,
            "verify": verify_stage,
            "deterministic_result_identity": deterministic_result_identity(
                commit_stage, opening_stage, verify_stage
            ),
        },
        "pow_and_opening_validation": {
            "frontier_distribution": distribution,
            "accepted_index_tuples_at_t_open": accepted_index_tuples,
            "total_index_tuples": total_index_tuples,
            "opening_acceptance_probability_before_explicit_bits": (
                accepted_index_tuples / total_index_tuples
            ),
            "explicit_bits_enforced": True,
            "t_open_enforced": True,
            "counter_is_u64le": True,
            "counter_starts_at_zero": True,
        },
        "mutation_vectors": mutations,
        "mutation_summary": {
            "total": len(mutations),
            "rejected": sum(item["rejected"] is True for item in mutations),
            "accepted": sum(item["rejected"] is not True for item in mutations),
        },
        "resource_measurements": {
            "elapsed_seconds": elapsed_seconds,
            "peak_memory_bytes": peak_memory_bytes,
            "relation_rows_replayed": 0,
            "proofs_generated": 0,
            "production_leaves_expanded": 0,
        },
        "claim_boundary": {
            "exact_unified_tree_algorithm_implemented_for_reduced_profile": True,
            "reduced_positive_vector_verified": verify_stage["accepted"] is True,
            "reduced_mutations_rejected": all(
                item["rejected"] is True for item in mutations
            ),
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
            "legacy_evidence_overwritten": False,
            "other_tree_observed_stream_bytes_reused": False,
            "assignment_or_br1cs_created": False,
            "cache_is_external_json_only": True,
            "pickle_created": False,
            "log_created": False,
        },
    }


def math_prod(values: tuple[int, ...]) -> int:
    result = 1
    for value in values:
        result *= value
    return result


def _load_state(path: Path, expected_contract: dict[str, object]) -> dict[str, object]:
    document = json.loads(path.read_text())
    if (
        not isinstance(document, dict)
        or document.get("format") != STATE_FORMAT
        or document.get("contract") != expected_contract
        or not isinstance(document.get("stages"), list)
    ):
        raise ValueError("resume state identity mismatch")
    return document


def _save_state(
    output: Path,
    contract: dict[str, object],
    stages: list[dict[str, object]],
) -> None:
    _write_json(output / STATE_FILENAME, {
        "format": STATE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "contract": contract,
        "completed_stage_names": [item["stage"] for item in stages],
        "stages": stages,
    })


def run_reduced(
    profile_manifest: Path,
    output: Path,
    *,
    fresh_cache: bool = False,
    resume: bool = False,
    stop_after: str | None = None,
    include_mutations: bool = True,
) -> dict[str, object] | None:
    if fresh_cache == resume:
        raise ValueError("select exactly one of fresh_cache or resume")
    validate_manifest(profile_manifest)
    contract = _state_contract(profile_manifest)
    state_path = output / STATE_FILENAME
    if fresh_cache:
        if output.exists():
            raise FileExistsError("fresh-cache output already exists")
        output.mkdir(parents=True)
        previous_stages: list[dict[str, object]] = []
    else:
        if not state_path.is_file():
            raise FileNotFoundError("resume state is missing")
        previous_stages = list(_load_state(state_path, contract)["stages"])

    started = time.perf_counter()
    parameters = unified.REDUCED_TEST_PARAMETERS
    randomness = unified.deterministic_randomness(parameters)
    execution = unified.execute_commit(parameters, randomness)
    commit_stage = _commit_stage(execution)
    stages = [commit_stage]
    if previous_stages:
        if previous_stages[0] != commit_stage:
            raise ValueError("resume commit stage mismatch")
    _save_state(output, contract, stages)
    if stop_after == "commit":
        return None

    opening, trials = unified.grind_opening(execution, CHALLENGE_PREFIX)
    opening_stage = _opening_stage(parameters, opening, trials)
    stages.append(opening_stage)
    if len(previous_stages) >= 2 and previous_stages[1] != opening_stage:
        raise ValueError("resume opening stage mismatch")
    _save_state(output, contract, stages)
    if stop_after == "opening":
        return None

    verification = unified.verify_opening(
        parameters,
        CHALLENGE_PREFIX,
        execution.commitment.encode(),
        opening.encode(parameters),
    )
    if not verification.accepted:
        raise RuntimeError(f"reduced positive vector rejected: {verification.failures}")
    verify_stage = _verify_stage(verification)
    stages.append(verify_stage)
    if len(previous_stages) >= 3 and previous_stages[2] != verify_stage:
        raise ValueError("resume verify stage mismatch")
    _save_state(output, contract, stages)
    mutations = mutation_vectors(execution, opening) if include_mutations else []
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    elapsed = time.perf_counter() - started
    evidence = build_reduced_evidence(
        contract,
        commit_stage,
        opening_stage,
        verify_stage,
        mutations,
        elapsed,
        peak,
    )
    _write_json(output / EVIDENCE_FILENAME, evidence)
    return evidence


def qualify_runner(
    profile_manifest: Path,
    main_output: Path,
    main_evidence: dict[str, object],
) -> dict[str, object]:
    qualification_output = main_output.with_name(main_output.name + "-resume-qualification")
    run_reduced(
        profile_manifest,
        qualification_output,
        fresh_cache=True,
        stop_after="commit",
        include_mutations=False,
    )
    resumed = run_reduced(
        profile_manifest,
        qualification_output,
        resume=True,
        include_mutations=False,
    )
    assert resumed is not None
    overwrite_refused = False
    try:
        run_reduced(
            profile_manifest,
            qualification_output,
            fresh_cache=True,
            include_mutations=False,
        )
    except FileExistsError:
        overwrite_refused = True
    main_identity = main_evidence["positive_vector"]["deterministic_result_identity"]
    resumed_identity = resumed["positive_vector"]["deterministic_result_identity"]
    qualification = {
        "format": QUALIFICATION_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": unified.RELATION_ID,
        "runner": identity(ROOT / "src/pq_rbbc_cap_unified_tree_runner.py"),
        "profile_manifest": identity(profile_manifest),
        "reduced_profile_fingerprint": unified.profile_fingerprint(
            unified.REDUCED_TEST_PARAMETERS
        ),
        "checks": {
            "fresh_cache_completed": True,
            "interrupted_after_commit": True,
            "resume_state_identity_revalidated": True,
            "resumed_result_matches_fresh_result": main_identity == resumed_identity,
            "existing_output_overwrite_refused": overwrite_refused,
            "resume_uses_pickle": False,
            "production_profile_invoked": False,
            "relation_rows_replayed": 0,
        },
        "result": {
            "reduced_runner_qualified": (
                main_identity == resumed_identity and overwrite_refused
            ),
            "production_runner_qualified": False,
            "safe_to_start_production_prefreeze": False,
            "safe_to_start_large_replay": False,
        },
        "artifact_policy": {
            "state_format": STATE_FORMAT,
            "state_is_external": True,
            "state_is_json_not_pickle": True,
            "state_or_cache_tracked_in_git": False,
        },
    }
    _write_json(main_output / QUALIFICATION_FILENAME, qualification)
    return qualification


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile-manifest", type=Path, required=True)
    parser.add_argument("--phase", choices=("reduced",), required=True)
    parser.add_argument("--output", type=Path, required=True)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--fresh-cache", action="store_true")
    modes.add_argument("--resume", action="store_true")
    parser.add_argument("--stop-after", choices=("commit", "opening"))
    parser.add_argument("--skip-runner-qualification", action="store_true")
    args = parser.parse_args()
    evidence = run_reduced(
        args.profile_manifest,
        args.output,
        fresh_cache=args.fresh_cache,
        resume=args.resume,
        stop_after=args.stop_after,
    )
    result: dict[str, object] = {
        "phase": args.phase,
        "output": str(args.output),
        "complete": evidence is not None,
        "production_profile_invoked": False,
        "large_replay_started": False,
    }
    if evidence is not None:
        result["evidence"] = identity(args.output / EVIDENCE_FILENAME)
        if args.fresh_cache and not args.skip_runner_qualification:
            qualification = qualify_runner(args.profile_manifest, args.output, evidence)
            result["runner_qualification"] = identity(
                args.output / QUALIFICATION_FILENAME
            )
            result["reduced_runner_qualified"] = qualification["result"][
                "reduced_runner_qualified"
            ]
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
