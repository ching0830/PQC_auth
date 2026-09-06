#!/usr/bin/env python3
"""Build the fail-closed PQ-RBBC v2.30 fork-security review packet."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping


IMPLEMENTATION_VERSION = "2.30"
EXTERNAL_ROOT = Path("/tmp/pq_rbbc_external_artifacts_rebuilt/v2_30_fork_security")
ROOT = Path(__file__).resolve().parents[1]

PAPER_FILENAME = "blind_uov_eprint_2025_895_revision_2025_10_31.pdf"
PROOF_PACKET_FILENAME = "pq_rbbc_buov_336_fork_security_argument_v2_30.pdf"
CAP_REVIEW_FILENAME = (
    "pq_rbbc_cap_unique_mask_straightline_extraction_review_v2_30.json"
)
QROM_REVIEW_FILENAME = "pq_rbbc_qrom_request_binding_review_v2_30.json"
BLINDNESS_REVIEW_FILENAME = "pq_rbbc_blindness_one_more_review_v2_30.json"
REVIEW_REQUEST_FILENAME = "pq_rbbc_fork_security_independent_review_request_v2_30.json"
AUDIT_MANIFEST_FILENAME = "pq_rbbc_fork_security_audit_manifest_v2_30.json"

PAPER_IDENTITY = (
    1_595_999,
    "7ba2c040fd04823fb0d2aaad5e58348b5ef374726657ff1c0d87d000b4beff95",
)
PROOF_PACKET_IDENTITY = (
    123_065,
    "b855dd450f9672bfb4540599078d76a2331a6aa26d50c880c59b0a7f5a72691b",
)
PROOF_SOURCE = (
    "docs/proof/source/pq_rbbc_fork_security_audit_v2_30.html",
    13_144,
    "d8d5f2acb5fac80cc4e6ae358da55d89593f889be7bbbf5fbe4e23264c85ff56",
)
V2_29_EVIDENCE = (
    "artifacts/metadata/parent_join_recovery_v2_29/"
    "pq_rbbc_parent_join_recovery_evidence_v2_29.json",
    5_695,
    "1281afaee1d5d784390ee51c96c66ecc7f486ef4b4b7933590826a708f81b20e",
)
V2_30_PREFLIGHT = (
    "manifests/pq_rbbc_fork_security_preflight_manifest_v2_30.json",
    6_677,
    "a57610c347491b47e70b73f991d5af7f30b7d317fd096860b770b532d4c8aac7",
)
V2_29_INPUT_IDENTITY = (
    "b92aa6b78d123173574ad00cb337e12877a9615f56605bddfd66236ca263d11a"
)
V2_29_TRANSCRIPT_SHA256 = (
    "1f0113f965a03351b6d62c4801a9d15d0255640282b90215397170b87ad6a514"
)


def canonical_json(document: Mapping[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_identity(path: Path, expected: tuple[int, str], label: str) -> None:
    if not path.is_file():
        raise ValueError(f"{label} is missing")
    if path.stat().st_size != expected[0]:
        raise ValueError(f"{label} byte length mismatch")
    if sha256_file(path) != expected[1]:
        raise ValueError(f"{label} SHA-256 mismatch")


def tracked_identity(relative: str, size: int, digest: str) -> dict[str, object]:
    require_identity(ROOT / relative, (size, digest), relative)
    return {"name": Path(relative).name, "bytes": size, "sha256": digest}


def common_inputs() -> dict[str, object]:
    return {
        "authoritative_reference": {
            "name": PAPER_FILENAME,
            "report": "IACR ePrint 2025/895",
            "revision": "2025-10-31",
            "bytes": PAPER_IDENTITY[0],
            "sha256": PAPER_IDENTITY[1],
        },
        "proof_audit_packet": {
            "name": PROOF_PACKET_FILENAME,
            "bytes": PROOF_PACKET_IDENTITY[0],
            "sha256": PROOF_PACKET_IDENTITY[1],
        },
        "proof_audit_source": tracked_identity(*PROOF_SOURCE),
        "v2_29_parent_join_evidence": tracked_identity(*V2_29_EVIDENCE),
        "v2_30_preflight_manifest": tracked_identity(*V2_30_PREFLIGHT),
        "v2_29_input_identity": V2_29_INPUT_IDENTITY,
        "v2_29_ordered_transcript_sha256": V2_29_TRANSCRIPT_SHA256,
        "v2_29_combined_rows": 589_030_555,
        "v2_29_verification_failures": 0,
        "v2_29_external_assertions": 0,
    }


def reviewer_boundary() -> dict[str, object]:
    return {
        "review_kind": "internal_fail_closed_gap_analysis",
        "reviewer_independent_of_project": False,
        "cryptographic_peer_review": False,
        "may_promote_security_claims": False,
    }


def claim_boundary() -> dict[str, bool]:
    return {
        "internal_proof_audit_completed": True,
        "independent_review_packet_prepared": True,
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
    }


def build_cap_review() -> dict[str, object]:
    return {
        "format": "PQRBBC-FORK-SECURITY-CAP-GAP-REVIEW-1",
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": "pq-rbbc/fork-security/cap-gap-review/v1",
        "reviewer_boundary": reviewer_boundary(),
        "inputs": common_inputs(),
        "paper_requirements": {
            "anchor": "Definition 10 and Remarks 2-3, pages 8-9",
            "extractor_input": "oracle query-response set and commitment prefix",
            "extractor_does_not_take_final_proof": True,
            "unique_witness_is_required": True,
            "zero_knowledge_is_required_for_blindness": True,
        },
        "fork_evidence": {
            "canonical_cap_commitment_bytes": 5_391,
            "production_tree_count": 18,
            "complete_assignment_replayed": True,
            "parent_join_closed": True,
            "functional_mutation_rejections_recorded": True,
            "native_module_is_import_contract_not_tcih_implementation": True,
            "test_adapter_is_native_blind_uov": False,
            "functional_replay_is_security_evidence": False,
        },
        "findings": [
            {
                "id": "CAP-01",
                "severity": "blocking",
                "result": "not_discharged",
                "reason": "no fork extractor over the exact Anemoi oracle transcript is implemented or formally specified",
            },
            {
                "id": "CAP-02",
                "severity": "blocking",
                "result": "not_discharged",
                "reason": "no unique-committed-mask advantage bound is supplied for the exact 18-tree fork",
            },
            {
                "id": "CAP-03",
                "severity": "blocking",
                "result": "not_discharged",
                "reason": "assignment replay and stale-witness rejection establish functional consistency only",
            },
            {
                "id": "CAP-04",
                "severity": "blocking",
                "result": "not_discharged",
                "reason": "no independent cryptographic review is present",
            },
        ],
        "verdict": {
            "internal_gap_analysis_complete": True,
            "cap_unique_witness_obligation_discharged": False,
            "cap_straightline_extraction_obligation_discharged": False,
            "safe_to_promote_cap_claims": False,
        },
        "claim_boundary": claim_boundary(),
    }


def build_qrom_review() -> dict[str, object]:
    return {
        "format": "PQRBBC-FORK-SECURITY-QROM-GAP-REVIEW-1",
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": "pq-rbbc/fork-security/qrom-request-binding-gap-review/v1",
        "reviewer_boundary": reviewer_boundary(),
        "inputs": common_inputs(),
        "game": {
            "map": "J_m(r,rho)=r+H_RBBC(m,CAP.Commit(r;rho))",
            "public_target_bits": 576,
            "public_request_data_fields": ["y"],
            "protocol_request_also_contains": ["pi_issue replacing paper pi_1"],
            "hidden_state": ["m", "r", "rho", "c_r"],
            "conditional_bound": "Adv_xmsg <= Adv_CAP_uw + Adv_CAP_ext + O(q_H^3/2^576)",
            "generic_quantum_collision_scale_bits": 192,
        },
        "established_inputs": {
            "domain_separated_serialization_bound_to_v2_29": True,
            "exact_parent_wire_join_replayed": True,
            "other_tree_observed_stream_bytes_used": False,
        },
        "findings": [
            {
                "id": "QROM-01",
                "severity": "blocking",
                "result": "conditional_only",
                "reason": "CAP unique-witness and extraction bad-event terms are not discharged",
            },
            {
                "id": "QROM-02",
                "severity": "blocking",
                "result": "conditional_only",
                "reason": "no concrete-to-ideal justification treats the exact Anemoi-193/336 construction as an independent quantum random oracle",
            },
            {
                "id": "QROM-03",
                "severity": "blocking",
                "result": "conditional_only",
                "reason": "q_H remains symbolic; no accepted deployment query budget is frozen",
            },
            {
                "id": "QROM-04",
                "severity": "blocking",
                "result": "not_independently_reviewed",
                "reason": "oracle programming, measurement, and abort accounting require independent cryptographic review",
            },
        ],
        "verdict": {
            "internal_gap_analysis_complete": True,
            "ideal_qrom_statement_present": True,
            "concrete_qrom_obligation_discharged": False,
            "safe_to_promote_qrom_request_binding_claim": False,
        },
        "claim_boundary": claim_boundary(),
    }


def build_blindness_one_more_review() -> dict[str, object]:
    return {
        "format": "PQRBBC-FORK-SECURITY-BLINDNESS-ONE-MORE-GAP-REVIEW-1",
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": "pq-rbbc/fork-security/blindness-one-more-gap-review/v1",
        "reviewer_boundary": reviewer_boundary(),
        "inputs": common_inputs(),
        "paper_reduction_map": {
            "one_more_stage_1": {
                "anchor": "Theorem 1, pages 14-16",
                "bound": "Adv_USIG <= Adv_HS_SIG + Adv_KS_CAP",
            },
            "one_more_stage_2": {
                "anchor": "Theorem 2, pages 16-18",
                "bound": "Adv_BSIG <= Adv_USIG + Adv_KS_NIZK",
            },
            "blindness": {
                "anchor": "Theorem 3, page 18",
                "bound": "Adv_BLIND <= Adv_ZK_NIZK + Adv_ZK_CAP + Adv_PRG",
            },
            "fork_request": "(y,pi_issue), where y is the only request data field and pi_issue replaces only paper pi_1",
            "fork_final_signature_intent": ["c_r", "c_x", "pi_2"],
        },
        "findings": [
            {
                "id": "FORK-01",
                "severity": "blocking",
                "result": "not_discharged",
                "reason": "no complete reviewed fork signer, unblinding finalizer, and verifier implementation is frozen",
            },
            {
                "id": "FORK-02",
                "severity": "blocking",
                "result": "not_discharged",
                "reason": "no qualified post-quantum zero-knowledge and straight-line/simulation-extractable pi_issue backend is selected",
            },
            {
                "id": "FORK-03",
                "severity": "blocking",
                "result": "not_discharged",
                "reason": "fork CAP extraction and zero-knowledge assumptions are not established",
            },
            {
                "id": "FORK-04",
                "severity": "blocking",
                "result": "not_discharged",
                "reason": "uniform independent 576-bit mask sampling is not evidenced by deterministic replay fixtures",
            },
            {
                "id": "FORK-05",
                "severity": "blocking",
                "result": "not_discharged",
                "reason": "paper security and 11,644-byte signature figures do not automatically transfer to the non-bit-exact fork",
            },
            {
                "id": "FORK-06",
                "severity": "blocking",
                "result": "not_independently_reviewed",
                "reason": "no independent reviewer attestation binds the reductions and exact fork semantics",
            },
        ],
        "verdict": {
            "internal_gap_analysis_complete": True,
            "fork_blindness_obligation_discharged": False,
            "fork_one_more_obligation_discharged": False,
            "paper_security_reduction_inherited": False,
            "paper_signature_size_inherited": False,
            "safe_to_promote_fork_security_claim": False,
        },
        "claim_boundary": claim_boundary(),
    }


def artifact_identity(name: str, document: Mapping[str, object]) -> dict[str, object]:
    data = canonical_json(document)
    return {"name": name, "bytes": len(data), "sha256": sha256_bytes(data)}


def build_review_request(
    cap_review: Mapping[str, object],
    qrom_review: Mapping[str, object],
    blindness_review: Mapping[str, object],
) -> dict[str, object]:
    return {
        "format": "PQRBBC-FORK-SECURITY-INDEPENDENT-REVIEW-REQUEST-1",
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": "pq-rbbc/fork-security/independent-review-request/v1",
        "review_requested": True,
        "independent_review_completed": False,
        "attestation_present": False,
        "reviewer_identity": None,
        "inputs": common_inputs(),
        "internal_gap_reviews": [
            artifact_identity(CAP_REVIEW_FILENAME, cap_review),
            artifact_identity(QROM_REVIEW_FILENAME, qrom_review),
            artifact_identity(BLINDNESS_REVIEW_FILENAME, blindness_review),
        ],
        "required_review_outputs": {
            "reviewer_name_and_affiliation": True,
            "independence_statement": True,
            "review_date": True,
            "all_input_digests_repeated": True,
            "cap_unique_mask_disposition": True,
            "cap_straightline_extractor_disposition": True,
            "qrom_oracle_and_query_accounting_disposition": True,
            "blindness_reduction_disposition": True,
            "one_more_reduction_disposition": True,
            "augmented_issuance_composition_disposition": True,
            "unresolved_assumptions_and_findings": True,
            "claim_promotion_authorized": True,
        },
        "acceptance_rule": (
            "No security claim may be promoted unless a qualified independent "
            "reviewer supplies a separate attestation bound to every listed digest "
            "and explicitly discharges every blocking obligation."
        ),
        "claim_boundary": claim_boundary(),
    }


def build_documents() -> dict[str, dict[str, object]]:
    cap_review = build_cap_review()
    qrom_review = build_qrom_review()
    blindness_review = build_blindness_one_more_review()
    request = build_review_request(cap_review, qrom_review, blindness_review)
    documents = {
        CAP_REVIEW_FILENAME: cap_review,
        QROM_REVIEW_FILENAME: qrom_review,
        BLINDNESS_REVIEW_FILENAME: blindness_review,
        REVIEW_REQUEST_FILENAME: request,
    }
    manifest = {
        "format": "PQRBBC-FORK-SECURITY-AUDIT-MANIFEST-1",
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": "pq-rbbc/fork-security/audit-manifest/v1",
        "inputs": common_inputs(),
        "generated_documents": [
            artifact_identity(name, document)
            for name, document in sorted(documents.items())
        ],
        "blockers": [
            "cap_unique_committed_mask_not_revalidated",
            "cap_straightline_extraction_not_revalidated",
            "concrete_qrom_request_binding_not_revalidated",
            "fork_blindness_not_revalidated",
            "fork_one_more_unforgeability_not_revalidated",
            "qualified_pq_se_nizk_backend_missing",
            "independent_review_attestation_missing",
            "fork_signature_size_not_rebenchmarked",
        ],
        "safe_to_start_independent_review": True,
        "safe_to_claim_fork_security_revalidated": False,
        "safe_to_start_large_replay": False,
        "large_replay_started": False,
        "claim_boundary": claim_boundary(),
    }
    documents[AUDIT_MANIFEST_FILENAME] = manifest
    return documents


def validate_external_sources(external_root: Path) -> None:
    require_identity(external_root / PAPER_FILENAME, PAPER_IDENTITY, "Blind-UOV PDF")
    require_identity(
        external_root / PROOF_PACKET_FILENAME,
        PROOF_PACKET_IDENTITY,
        "fork-security proof-audit packet",
    )


def write_documents(external_root: Path) -> dict[str, object]:
    validate_external_sources(external_root)
    documents = build_documents()
    external_root.mkdir(parents=True, exist_ok=True)
    outputs = []
    for name, document in sorted(documents.items()):
        data = canonical_json(document)
        path = external_root / name
        path.write_bytes(data)
        outputs.append({"name": name, "bytes": len(data), "sha256": sha256_bytes(data)})
    return {
        "external_root": str(external_root),
        "outputs": outputs,
        "safe_to_start_independent_review": True,
        "safe_to_claim_fork_security_revalidated": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--external-root", type=Path, default=EXTERNAL_ROOT)
    parser.add_argument("--print", dest="print_name", choices=[
        CAP_REVIEW_FILENAME,
        QROM_REVIEW_FILENAME,
        BLINDNESS_REVIEW_FILENAME,
        REVIEW_REQUEST_FILENAME,
        AUDIT_MANIFEST_FILENAME,
    ])
    args = parser.parse_args()
    validate_external_sources(args.external_root)
    if args.print_name:
        print(canonical_json(build_documents()[args.print_name]).decode(), end="")
        return
    print(json.dumps(write_documents(args.external_root), sort_keys=True))


if __name__ == "__main__":
    main()
