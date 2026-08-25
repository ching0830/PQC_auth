#!/usr/bin/env python3
"""Native Blind-UOV-III import contract for the PQ-RBBC v1.9 core.

This module freezes the paper-level parameters and defines the evidence that a
real TCitH/Anemoi constraint import must provide before the issuance relation
may be labelled *closed*.  It is intentionally not a TCitH implementation.

The contract closes a dangerous engineering gap: a Boolean callback or an
``external_assertion`` is not an R1CS relation.  A future importer must provide
a deterministic row stream over GF(2^193), bind the circuit-produced ticket
digest to ``H_BUOV(m, CAP.Commit(r; rho))``, and pass independent tamper tests.
The audit performed here is structural; it cannot replace cryptographic review
of the imported implementation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field

import pq_rbbc_anemoi_f193 as anemoi_f193


RELATION_ID = "blind-uov-iii/cap-hash/v1"
TARGET_FIELD = "GF(2^193)"
REQUIRED_TAMPER_CASES = frozenset(
    {"message", "mask", "cap_randomness", "hash_image"}
)
REQUIRED_NATIVE_COMPONENTS = frozenset(
    {
        "cap_commit",
        "ggm_seed_derivation",
        "ggm_seed_commitments",
        "ggm_seed_expansion",
        "fiat_shamir_hash",
        "consistency_check",
        "message_commitment_hash",
    }
)


def _is_sha256(value: str) -> bool:
    if len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class BlindUOVIIIPaperProfile:
    """Values stated by ePrint 2025/895 for NIST-III/Shorter/TCitH."""

    revision: str = "2025-10-31"
    security_parameter_bits: int = 192
    n_r_bits: int = 576
    n_x_bits: int = 1472
    cap_witness_bits: int = 2048
    cap_degree: int = 2
    cap_parallel_repetitions: int = 18
    tree_groups: tuple[tuple[int, int], ...] = ((2, 4096), (16, 2048))
    opened_seeds_upper_bound: int = 174
    explicit_pow_bits: int = 9
    total_pow_bits: float = 13.9
    anemoi_field_degree: int = 193
    anemoi_state_elements: int = 8
    anemoi_constraints_per_permutation: int = 240
    public_key_kilobytes: float = 189.2
    final_signature_bytes: int = 11644
    level_iii_nizk_cost_reported_by_paper: bool = False

    def __post_init__(self) -> None:
        if self.cap_witness_bits != self.n_r_bits + self.n_x_bits:
            raise ValueError("CAP witness width must equal n_r + n_x")
        if sum(count for count, _ in self.tree_groups) != self.cap_parallel_repetitions:
            raise ValueError("tree-group counts must sum to tau")
        if self.anemoi_field_degree != self.security_parameter_bits + 1:
            raise ValueError("paper's Anemoi field degree must be lambda + 1")

    def fingerprint(self) -> str:
        encoded = json.dumps(
            asdict(self), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


PAPER_PROFILE = BlindUOVIIIPaperProfile()


@dataclass(frozen=True)
class NativeImportEvidence:
    """Machine-checkable metadata emitted by a future native row generator."""

    relation_id: str
    profile_sha256: str
    target_field: str
    generator_source_sha256: str
    parameter_file_sha256: str
    row_stream_sha256: str
    native_rows: int
    external_assertions: int
    witness_independent_topology: bool
    honest_accepts: bool
    tamper_rejections: dict[str, bool] = field(default_factory=dict)
    component_rows: dict[str, int] = field(default_factory=dict)
    circuit_ticket_digest_is_native_message: bool = False
    circuit_mask_is_native_mask: bool = False
    circuit_hash_image_is_native_output: bool = False
    domain_separation_locked: bool = False
    serialization_locked: bool = False
    anemoi_test_vectors_verified: bool = False
    cap_unique_witness_reviewed: bool = False
    cap_straightline_extraction_reviewed: bool = False
    blind_uov_parameter_gap_resolved: bool = False
    blind_uov_bit_exact_match: bool = False


@dataclass(frozen=True)
class ClosureAudit:
    closed: bool
    failures: tuple[str, ...]


def audit_native_import(evidence: NativeImportEvidence | None) -> ClosureAudit:
    """Reject every incomplete or under-specified native integration."""

    if evidence is None:
        return ClosureAudit(False, ("native_import_evidence_missing",))

    failures: list[str] = []
    if evidence.relation_id != RELATION_ID:
        failures.append("wrong_relation_id")
    if evidence.profile_sha256 != PAPER_PROFILE.fingerprint():
        failures.append("paper_profile_mismatch")
    if evidence.target_field != TARGET_FIELD:
        failures.append("backend_field_mismatch")
    for label, digest in (
        ("generator_source", evidence.generator_source_sha256),
        ("parameter_file", evidence.parameter_file_sha256),
        ("row_stream", evidence.row_stream_sha256),
    ):
        if not _is_sha256(digest):
            failures.append(f"invalid_{label}_sha256")
    if evidence.native_rows <= 0:
        failures.append("native_rows_missing")
    if evidence.external_assertions != 0:
        failures.append("external_assertions_remain")
    missing_components = REQUIRED_NATIVE_COMPONENTS - evidence.component_rows.keys()
    if missing_components:
        failures.append(
            "missing_native_components:" + ",".join(sorted(missing_components))
        )
    if any(
        evidence.component_rows.get(name, 0) <= 0
        for name in REQUIRED_NATIVE_COMPONENTS
    ):
        failures.append("native_component_rows_missing")
    if sum(evidence.component_rows.values()) > evidence.native_rows:
        failures.append("component_rows_exceed_native_rows")
    for name in (
        "witness_independent_topology",
        "honest_accepts",
        "circuit_ticket_digest_is_native_message",
        "circuit_mask_is_native_mask",
        "circuit_hash_image_is_native_output",
        "domain_separation_locked",
        "serialization_locked",
        "anemoi_test_vectors_verified",
        "cap_unique_witness_reviewed",
        "cap_straightline_extraction_reviewed",
        "blind_uov_parameter_gap_resolved",
        "blind_uov_bit_exact_match",
    ):
        if not getattr(evidence, name):
            failures.append(name)
    missing_tamper_cases = REQUIRED_TAMPER_CASES - evidence.tamper_rejections.keys()
    if missing_tamper_cases:
        failures.append(
            "missing_tamper_cases:" + ",".join(sorted(missing_tamper_cases))
        )
    if not all(
        evidence.tamper_rejections.get(name, False)
        for name in REQUIRED_TAMPER_CASES
    ):
        failures.append("native_tamper_rejection_failed")
    return ClosureAudit(not failures, tuple(failures))


def build_native_import_manifest() -> dict[str, object]:
    audit = audit_native_import(None)
    return {
        "implementation_version": "1.9",
        "status": "GF(2^193) Anemoi component rows implemented; bit-exact Blind-UOV CAP parameters remain unavailable",
        "paper_anchor": {
            "report": "IACR ePrint 2025/895",
            "revision": PAPER_PROFILE.revision,
            "locations": ["Protocols 3-4", "Protocols 8-10", "Tables 2 and 4"],
        },
        "paper_profile": asdict(PAPER_PROFILE),
        "paper_profile_sha256": PAPER_PROFILE.fingerprint(),
        "relation_contract": {
            "relation_id": RELATION_ID,
            "target_field": TARGET_FIELD,
            "internal_parent_relation": "y = r + hash_image",
            "native_subrelation": "hash_image = H_BUOV(m, CAP.Commit(r; rho))",
            "message_source": "circuit-produced H_ticket(Encode(M)) wires",
            "test_nonce_is_native_cap_randomness": False,
            "required_native_components": sorted(REQUIRED_NATIVE_COMPONENTS),
        },
        "anemoi_component_probe": {
            "relation_id": anemoi_f193.COMPONENT_RELATION_ID,
            "upstream_commit": anemoi_f193.UPSTREAM_COMMIT,
            "upstream_source_sha256": anemoi_f193.UPSTREAM_SOURCE_SHA256,
            "field_modulus_exponents": list(anemoi_f193.CONWAY_EXPONENTS),
            "upstream_main_rounds": anemoi_f193.UPSTREAM_ROUNDS,
            "anemoi_paper_characteristic_two_rounds": anemoi_f193.PAPER_CHARACTERISTIC_TWO_ROUNDS,
            "blind_uov_reported_constraints": anemoi_f193.BLIND_UOV_REPORTED_CONSTRAINTS,
            "direct_upstream_main_nonlinear_rows": anemoi_f193.NONLINEAR_ROWS,
            "component_is_complete_cap_hash": False,
            "parameter_gap_resolved": False,
        },
        "closure_audit": asdict(audit),
        "claim_boundary": {
            "contract_validator_is_cryptographic_proof": False,
            "paper_supplies_executable_constraint_generator": False,
            "current_f2_archive_is_native_anemoi_field": False,
            "gf2_193_anemoi_component_rows_exist": True,
            "reported_240_constraint_instance_reproduced": False,
            "production_closed": False,
        },
    }


def main() -> None:
    print(json.dumps(build_native_import_manifest(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
