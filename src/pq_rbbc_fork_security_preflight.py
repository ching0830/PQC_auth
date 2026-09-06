#!/usr/bin/env python3
"""Read-only, fail-closed preflight for PQ-RBBC v2.30 fork security."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_trace_kdf_source_transition as trace_kdf_transition


IMPLEMENTATION_VERSION = "2.30"
FORMAT = "PQRBBC-FORK-SECURITY-PREFLIGHT-1"
REPORT_FORMAT = "PQRBBC-FORK-SECURITY-ENVIRONMENT-PREFLIGHT-1"
RELATION_ID = "pq-rbbc/fork-security-preflight/v1"
ROOT = Path(__file__).resolve().parents[1]

V2_29_EVIDENCE = (
    5_695,
    "1281afaee1d5d784390ee51c96c66ecc7f486ef4b4b7933590826a708f81b20e",
)
NATIVE_PROFILE_SOURCE = (
    45_087,
    "ce40b157c89c204d057babeb0796ebf6c5eb5c879d55644ce1822d5f8443bd5e",
)
NATIVE_PROFILE_MANIFEST = (
    33_558,
    "5a83b74adffe4e706c2e6c95b82079793a533112a33118b5badb0f99ab276936",
)
BLIND_UOV_ABI_SOURCE = (
    47_227,
    "575de440a2477e24e562ceb0f3049a13deff6031f3aa434609b7752b631491a2",
)
BLIND_UOV_ABI_MANIFEST = (
    26_423,
    "9081bbc85b258ea30f2c968db8d3f61160df6c599e71e08ade3c9090d4904a3a",
)
BLIND_UOV_NATIVE_SOURCE = (
    9_164,
    "8ae0782b0b38a5a9da7e5700ad854875a6a5d7ed2869e84338b74b6b8a48094e",
)
PROOF_SOURCE = (
    148_253,
    "c4babfd2070cec9f825d8e6d3692c29b248249a89bf41381258fb1b46827c997",
)
PROOF_PDF = (
    617_710,
    "42ad8b2061505a285309806091d9e392b4c3e130379cd9bbab44052c9d01f55c",
)
TRACE_KDF_SOURCE_TRANSITION_MANIFEST = (
    3_230,
    "3e214be777aa80eb0c94ab1371c911ab578c80ab126c453d7ca66145e1f66d3d",
)
TRACE_KDF_SOURCE_TRANSITION_PATH = (
    ROOT / "manifests/pq_rbbc_trace_kdf_source_transition_manifest_v2_40.json"
)

V2_29_RELATION_ID = "pq-rbbc/parent-cap-to-h-rbbc-recovery-evidence/v1"
V2_29_INPUT_IDENTITY = (
    "b92aa6b78d123173574ad00cb337e12877a9615f56605bddfd66236ca263d11a"
)
V2_29_TRANSCRIPT_SHA256 = (
    "1f0113f965a03351b6d62c4801a9d15d0255640282b90215397170b87ad6a514"
)
V2_29_COMBINED_ROWS = 589_030_555

EXTERNAL_ROOT = "/tmp/pq_rbbc_external_artifacts_rebuilt/v2_30_fork_security"
EXTERNAL_REQUIREMENTS = {
    "blind_uov_reference": {
        "filename": "blind_uov_eprint_2025_895_revision_2025_10_31.pdf",
        "purpose": "source framework, games, oracle model, and protocol transcript",
        "identity_frozen": False,
    },
    "fork_proof_packet": {
        "filename": "pq_rbbc_buov_336_fork_security_argument_v2_30.pdf",
        "purpose": "fork-specific blindness and one-more-unforgeability reductions",
        "identity_frozen": False,
    },
    "cap_extraction_review": {
        "filename": "pq_rbbc_cap_unique_mask_straightline_extraction_review_v2_30.json",
        "purpose": "CAP unique-mask and straight-line extraction review",
        "identity_frozen": False,
    },
    "qrom_request_binding_review": {
        "filename": "pq_rbbc_qrom_request_binding_review_v2_30.json",
        "purpose": "QROM cross-message request-binding theorem and query accounting review",
        "identity_frozen": False,
    },
    "blindness_one_more_review": {
        "filename": "pq_rbbc_blindness_one_more_review_v2_30.json",
        "purpose": "independent review of fork blindness and one-more games",
        "identity_frozen": False,
    },
    "independent_review_attestation": {
        "filename": "pq_rbbc_fork_security_independent_review_v2_30.json",
        "purpose": "review scope, findings, reviewer identity, and artifact digests",
        "identity_frozen": False,
    },
}

TRACKED_INPUTS = {
    "v2_29_parent_join_evidence": (
        "artifacts/metadata/parent_join_recovery_v2_29/"
        "pq_rbbc_parent_join_recovery_evidence_v2_29.json",
        V2_29_EVIDENCE,
    ),
    "native_profile_source": (
        "src/pq_rbbc_native_profile.py",
        NATIVE_PROFILE_SOURCE,
    ),
    "native_profile_manifest": (
        "manifests/pq_rbbc_native_profile_manifest_v2_25.json",
        NATIVE_PROFILE_MANIFEST,
    ),
    "blind_uov_abi_source": (
        "src/pq_rbbc_blind_uov_abi.py",
        BLIND_UOV_ABI_SOURCE,
    ),
    "blind_uov_abi_manifest": (
        "manifests/pq_rbbc_blind_uov_abi_manifest_v2_25.json",
        BLIND_UOV_ABI_MANIFEST,
    ),
    "blind_uov_native_source": (
        "src/pq_rbbc_blind_uov_native.py",
        BLIND_UOV_NATIVE_SOURCE,
    ),
    "conditional_proof_source": (
        "docs/proof/source/pq_rbbc_sgtd_core_proof_v1.tex",
        PROOF_SOURCE,
    ),
    "conditional_proof_pdf": (
        "docs/proof/releases/pq_rbbc_sgtd_core_proof_v2_13.pdf",
        PROOF_PDF,
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


def _identity(path: Path | None, expected: tuple[int, str]) -> dict[str, object]:
    if path is None:
        return {"provided": False, "verified": False, "failures": ["not_provided"]}
    failures: list[str] = []
    if not path.is_file():
        failures.append("missing")
    else:
        if path.stat().st_size != expected[0]:
            failures.append("bytes")
        if _sha256(path) != expected[1]:
            failures.append("sha256")
    return {"provided": True, "verified": not failures, "failures": failures}


def _candidate_identity(path: Path | None) -> dict[str, object]:
    if path is None:
        return {"provided": False, "verified": False, "failures": ["not_provided"]}
    if not path.is_file():
        return {"provided": True, "verified": False, "failures": ["missing"]}
    return {
        "provided": True,
        "verified": False,
        "bytes": path.stat().st_size,
        "sha256": _sha256(path),
        "failures": ["identity_not_frozen"],
    }


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} root must be an object")
    return document


def validate_tracked_inputs() -> tuple[str, ...]:
    failures: list[str] = []
    for label, (relative, expected) in TRACKED_INPUTS.items():
        if _identity(ROOT / relative, expected)["verified"]:
            continue
        if (
            label == "conditional_proof_source"
            and not trace_kdf_transition.validate_transition(
                TRACE_KDF_SOURCE_TRANSITION_PATH,
                TRACE_KDF_SOURCE_TRANSITION_MANIFEST,
                ROOT,
            )
        ):
            continue
        failures.append(f"{label}_identity")
    if failures:
        return tuple(failures)

    evidence = _read_json(ROOT / TRACKED_INPUTS["v2_29_parent_join_evidence"][0])
    claims = evidence.get("claim_boundary", {})
    accounting = evidence.get("accounting", {})
    if (
        evidence.get("implementation_version") != "2.29"
        or evidence.get("relation_id") != V2_29_RELATION_ID
    ):
        failures.append("v2_29_evidence_contract")
    for name in (
        "complete_18_tree_assignment_replayed",
        "cross_segment_wire_identity_closed",
        "parent_bound_global_tail_replayed",
        "gf193_parent_lift_replayed",
        "parent_cap_to_h_rbbc_join_closed",
    ):
        if not isinstance(claims, dict) or claims.get(name) is not True:
            failures.append(f"v2_29_{name}")
    for name in (
        "fork_security_proof_revalidated",
        "production_closed",
        "system_architecture_changed",
        "ticket_lifecycle_changed",
        "pq_sat_auth_changed",
    ):
        if not isinstance(claims, dict) or claims.get(name) is not False:
            failures.append(f"v2_29_{name}_boundary")
    if not isinstance(accounting, dict) or (
        accounting.get("combined_rows") != V2_29_COMBINED_ROWS
        or accounting.get("verification_failures") != 0
        or accounting.get("external_assertions") != 0
        or accounting.get("ordered_replay_transcript_sha256")
        != V2_29_TRANSCRIPT_SHA256
    ):
        failures.append("v2_29_accounting")

    native = _read_json(ROOT / TRACKED_INPUTS["native_profile_manifest"][0])
    compatibility = native.get("compatibility", {})
    native_claims = native.get("claim_boundary", {})
    if native.get("implementation_version") != "2.25":
        failures.append("native_profile_baseline_version")
    if (
        not isinstance(compatibility, dict)
        or compatibility.get("blind_uov_bit_exact_compatible") is not False
        or compatibility.get("paper_security_reduction_automatically_inherited")
        is not False
    ):
        failures.append("native_profile_compatibility_boundary")
    if (
        not isinstance(native_claims, dict)
        or native_claims.get("fork_security_proof_revalidated") is not False
        or native_claims.get("production_closed") is not False
    ):
        failures.append("native_profile_security_boundary")
    if native.get("closure_audit") != {
        "closed": False,
        "failures": ["fork_native_import_evidence_missing"],
    }:
        failures.append("native_profile_closure_audit")

    abi = _read_json(ROOT / TRACKED_INPUTS["blind_uov_abi_manifest"][0])
    abi_profile = abi.get("fork_profile", {})
    if abi.get("implementation_version") != "2.25":
        failures.append("blind_uov_abi_baseline_version")
    if (
        not isinstance(abi_profile, dict)
        or abi_profile.get("blind_uov_bit_exact_compatible") is not False
        or abi_profile.get("paper_security_reduction_revalidated") is not False
        or abi_profile.get("paper_signature_size_rebenchmarked") is not False
    ):
        failures.append("blind_uov_abi_security_boundary")

    proof_text = " ".join(
        (ROOT / TRACKED_INPUTS["conditional_proof_source"][0]).read_text().split()
    )
    required_markers = (
        "None of its concrete security or size results transfers automatically",
        "QROM cross-message request binding",
        "CAP commitment has straightline extraction and a unique committed mask",
        "fork blindness and one-more",
        "fork-specific blindness/one-more-unforgeability proof",
        "Not yet instantiated",
    )
    for marker in required_markers:
        if marker not in proof_text:
            failures.append("proof_source_marker:" + marker)
    return tuple(failures)


def proof_obligations() -> list[dict[str, object]]:
    return [
        {
            "id": "cap.unique_committed_mask",
            "status": "open",
            "required_evidence": "game, extractor interface, bad event, and independent review",
        },
        {
            "id": "cap.straightline_extraction",
            "status": "open",
            "required_evidence": "straight-line extractor for every admissible commitment",
        },
        {
            "id": "request_binding.qrom_cross_message",
            "status": "open",
            "required_evidence": "domain-separated oracle model, adaptive-query accounting, and concrete-to-ideal boundary",
        },
        {
            "id": "fork.honest_protocol_signer_blindness",
            "status": "open",
            "required_evidence": "fork transcript game preserving hidden m, r, rho, and c_r",
        },
        {
            "id": "fork.one_more_unforgeability",
            "status": "open",
            "required_evidence": "completed-session accounting and reduction for the PQ-RBBC-BUOV-336 fork",
        },
        {
            "id": "augmented_issuance.composition",
            "status": "open",
            "required_evidence": "reduction from the final v2.29 request relation without inheriting paper claims",
        },
        {
            "id": "independent_review",
            "status": "open",
            "required_evidence": "review packet bound to every proof and semantics digest",
        },
    ]


def build_frozen_manifest() -> dict[str, object]:
    tracked_failures = list(validate_tracked_inputs())
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "tracked_prerequisites": {
            label: {"path": relative, "bytes": expected[0], "sha256": expected[1]}
            for label, (relative, expected) in TRACKED_INPUTS.items()
        },
        "tracked_validation_failures": tracked_failures,
        "final_execution_semantics": {
            "source_checkpoint": "v2.29",
            "input_identity": V2_29_INPUT_IDENTITY,
            "ordered_replay_transcript_sha256": V2_29_TRANSCRIPT_SHA256,
            "combined_rows": V2_29_COMBINED_ROWS,
            "verification_failures": 0,
            "external_assertions": 0,
            "ticket_payload_and_lifecycle_unchanged": True,
            "request_is_exactly_public_y": True,
            "message_mask_commitment_hash_image_and_y_bound": True,
        },
        "baseline_status": {
            "blind_uov_is_design_source_only": True,
            "blind_uov_bit_exact_compatible": False,
            "paper_security_reduction_automatically_inherited": False,
            "paper_signature_size_automatically_inherited": False,
            "conditional_proof_source_release": "v2.13",
            "native_profile_manifest_version": "2.25",
            "blind_uov_abi_manifest_version": "2.25",
            "baselines_require_v2_29_semantics_refresh": True,
        },
        "proof_scope": {
            "fork_profile": "PQ-RBBC-BUOV-III/Anemoi-193-336 experimental fork",
            "target_request_bits": 576,
            "request_relation": "c_r = CAP.Commit(r; rho) and y = r + H_RBBC(m, c_r)",
            "public_request_fields": ["y"],
            "hidden_state": ["m", "r", "rho", "c_r"],
            "required_games": [
                "honest-protocol signer blindness",
                "one-more unforgeability",
                "QROM cross-message request binding",
                "CAP unique committed mask",
                "CAP straight-line extraction",
            ],
            "required_qrom_bound": "Adv_xmsg <= Adv_CAP_uw + Adv_CAP_ext + O(q^3 / 2^576)",
            "conditional_se_nizk_dependency": True,
            "security_parameter_and_query_budget_must_be_explicit": True,
        },
        "proof_obligations": proof_obligations(),
        "required_external_artifacts": EXTERNAL_REQUIREMENTS,
        "evidence_requirements": {
            "canonical_game_definitions": True,
            "all_reduction_algorithms_explicit": True,
            "oracle_programming_and_measurement_steps_explicit": True,
            "abort_events_and_advantage_loss_accounted": True,
            "adaptive_concurrent_session_model_explicit": True,
            "domain_separation_and_serialization_bound_to_v2_29": True,
            "proof_packet_digests_bound_by_independent_review": True,
            "unresolved_assumptions_remain_machine_readable": True,
            "functional_replay_is_not_accepted_as_security_evidence": True,
        },
        "execution_policy": {
            "read_only_preflight": True,
            "large_replay_permitted": False,
            "proof_revalidation_permitted_before_external_identity_freeze": False,
            "claim_promotion_permitted_before_independent_review": False,
            "external_candidate_inventory_directory": EXTERNAL_ROOT,
        },
        "claim_boundary": {
            "fork_security_preflight_contract_closed": not tracked_failures,
            "v2_29_final_semantics_prerequisite_verified": not tracked_failures,
            "read_only_gap_analysis_safe": not tracked_failures,
            "external_security_artifacts_frozen": False,
            "cap_unique_witness_reviewed": False,
            "cap_straightline_extraction_reviewed": False,
            "qrom_request_binding_reviewed": False,
            "fork_blindness_revalidated": False,
            "fork_one_more_unforgeability_revalidated": False,
            "fork_security_proof_revalidated": False,
            "qualified_pq_se_nizk_backend_selected": False,
            "signature_size_rebenchmarked": False,
            "production_closed": False,
            "system_architecture_changed": False,
            "ticket_lifecycle_changed": False,
            "pq_sat_auth_changed": False,
        },
    }


def exact_candidate_inventory_command() -> str:
    args = [
        "PYTHONPATH=src python -u src/pq_rbbc_fork_security_preflight.py",
        f"  --report {EXTERNAL_ROOT}/pq_rbbc_fork_security_environment_preflight_v2_30.json",
    ]
    option_names = {
        "blind_uov_reference": "--blind-uov-reference",
        "fork_proof_packet": "--fork-proof-packet",
        "cap_extraction_review": "--cap-extraction-review",
        "qrom_request_binding_review": "--qrom-request-binding-review",
        "blindness_one_more_review": "--blindness-one-more-review",
        "independent_review_attestation": "--independent-review-attestation",
    }
    for name, requirement in EXTERNAL_REQUIREMENTS.items():
        args.append(
            f"  {option_names[name]} {EXTERNAL_ROOT}/{requirement['filename']}"
        )
    return " \\\n".join(args)


def build_environment_report(
    candidates: Mapping[str, Path | None],
) -> dict[str, object]:
    static_failures = list(validate_tracked_inputs())
    checks: dict[str, dict[str, object]] = {
        "tracked_inputs": {
            "verified": not static_failures,
            "failures": static_failures,
        }
    }
    for name in EXTERNAL_REQUIREMENTS:
        checks[name] = _candidate_identity(candidates.get(name))
    gap_analysis_safe = checks["tracked_inputs"]["verified"] is True
    external_frozen = all(
        checks[name]["verified"] is True for name in EXTERNAL_REQUIREMENTS
    )
    ready = gap_analysis_safe and external_frozen
    blockers = [name for name, item in checks.items() if item["verified"] is not True]
    return {
        "format": REPORT_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "checks": checks,
        "blockers": blockers,
        "safe_to_continue_read_only_gap_analysis": gap_analysis_safe,
        "safe_to_start_fork_security_revalidation": ready,
        "safe_to_claim_fork_security_revalidated": False,
        "safe_to_start_large_replay": False,
        "large_replay_started": False,
        "proof_revalidation_started": False,
        "exact_candidate_inventory_command": exact_candidate_inventory_command(),
        "exact_revalidation_command": None,
        "exact_revalidation_command_withheld_reason": (
            "external proof inputs have no frozen identities and independent review is absent"
        ),
        "claim_boundary": build_frozen_manifest()["claim_boundary"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print-frozen", action="store_true")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--blind-uov-reference", type=Path)
    parser.add_argument("--fork-proof-packet", type=Path)
    parser.add_argument("--cap-extraction-review", type=Path)
    parser.add_argument("--qrom-request-binding-review", type=Path)
    parser.add_argument("--blindness-one-more-review", type=Path)
    parser.add_argument("--independent-review-attestation", type=Path)
    args = parser.parse_args()
    if args.print_frozen:
        print(canonical_json(build_frozen_manifest()).decode(), end="")
        return
    if args.report is None:
        parser.error("--report or --print-frozen is required")
    candidates = {
        "blind_uov_reference": args.blind_uov_reference,
        "fork_proof_packet": args.fork_proof_packet,
        "cap_extraction_review": args.cap_extraction_review,
        "qrom_request_binding_review": args.qrom_request_binding_review,
        "blindness_one_more_review": args.blindness_one_more_review,
        "independent_review_attestation": args.independent_review_attestation,
    }
    report = build_environment_report(candidates)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_bytes(canonical_json(report))
    print(json.dumps({
        "report": str(args.report),
        "safe_to_continue_read_only_gap_analysis": report[
            "safe_to_continue_read_only_gap_analysis"
        ],
        "safe_to_start_fork_security_revalidation": report[
            "safe_to_start_fork_security_revalidation"
        ],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
