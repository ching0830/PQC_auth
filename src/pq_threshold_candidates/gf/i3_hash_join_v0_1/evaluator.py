"""Bounded host consumer for an unverified, private legacy18 CAP candidate.

The extra candidate is NOT part of the frozen GF statement/witness encoding.
No CAP execution, rho-to-commitment relation or CAP-derived mask is checked.
Even a matching beta is only MATCHED_UNVERIFIED_CAP, never complete I3.
"""

from dataclasses import dataclass
from enum import Enum

import pq_rbbc_anemoi_sponge as h_rbbc
import pq_rbbc_cap_commit as cap
from pq_rbbc_cap_straightline_extractor import ExtractionFailure, parse_commitment

from ...contracts import ContractError, Unsupported, fixed_bytes
from ..partial_issuance_v0_1 import (
    ResearchPartialCheckStatus as P, ResearchPartialIssuanceEvaluation,
    evaluate_partial_issuance_research,
)
from ..research_abi_v0_1.codecs import (
    CAP_PROFILE_SHA256, H_RBBC_PROFILE_SHA256,
    ResearchIssueStatement, ResearchIssueWitness,
)


class ResearchI3HashStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_EVALUATED = "not_evaluated"
    COMPUTED_UNVERIFIED_CAP = "computed_unverified_cap"
    MATCHED_UNVERIFIED_CAP = "matched_unverified_cap"
    OPEN = "open"
    ERROR = "error"

    def __bool__(self):
        raise TypeError("Compare the I3 candidate status explicitly; it is not acceptance")


S = ResearchI3HashStatus
_CHECK_NAMES = (
    "CAP_candidate_codecs", "CAP_salt_binding", "I2_H_RBBC_consumer",
    "I3_beta_equation", "CAP_rho_execution", "CAP_mask_derivation",
)
_BINDING_NAMES = (
    "P0_statement_pp", "P0_ticket_pp", "P0_trace_key", "I1_statement_ctx", "I1_ticket_ctx",
)


@dataclass(frozen=True, repr=False)
class ResearchI3HashEvaluation:
    """Status-only diagnostic with no credential or private-value export."""

    partial: ResearchPartialIssuanceEvaluation
    checks: tuple[tuple[str, ResearchI3HashStatus], ...]

    def __post_init__(self):
        if (type(self.partial) is not ResearchPartialIssuanceEvaluation
                or type(self.checks) is not tuple
                or any(type(row) is not tuple or len(row) != 2 for row in self.checks)
                or any(type(row[0]) is not str or type(row[1]) is not S for row in self.checks)
                or tuple(row[0] for row in self.checks) != _CHECK_NAMES):
            raise ContractError("noncanonical I3 candidate diagnostic")
        if any(self.status(name) is not S.OPEN for name in ("CAP_rho_execution", "CAP_mask_derivation")):
            raise ContractError("CAP execution and derived-mask checks must remain OPEN")
        if self.status("I2_H_RBBC_consumer") not in (S.COMPUTED_UNVERIFIED_CAP, S.NOT_EVALUATED, S.ERROR):
            raise ContractError("hash consumer has only an unverified CAP candidate")
        if self.status("I3_beta_equation") not in (S.MATCHED_UNVERIFIED_CAP, S.FAILED, S.NOT_EVALUATED):
            raise ContractError("candidate beta equation cannot establish I3")

    def status(self, name: str) -> ResearchI3HashStatus:
        for label, status in self.checks:
            if name == label:
                return status
        raise ContractError("unknown I3 candidate check name")

    @property
    def unresolved(self) -> tuple[str, ...]:
        return ("CAP_candidate_origin", "CAP_rho_execution", "CAP_mask_derivation") + self.partial.unresolved

    @property
    def full_I3_verified(self) -> bool:
        return False

    @property
    def full_relation_verified(self) -> bool:
        return False

    @property
    def authentication_verified(self) -> bool:
        return False

    @property
    def production_qualified(self) -> bool:
        return False

    def __bool__(self):
        raise TypeError("An unverified CAP candidate match is not I3 acceptance")

    def __repr__(self):
        return "ResearchI3HashEvaluation(research_only=True, full_I3_verified=False)"


def _check_profiles():
    if (cap.profile_fingerprint(cap.PRODUCTION_PARAMETERS) != CAP_PROFILE_SHA256.hex()
            or cap.commitment_bytes(cap.PRODUCTION_PARAMETERS) != 5391
            or h_rbbc.profile_fingerprint(cap.field.derive_parameters()) != H_RBBC_PROFILE_SHA256.hex()):
        raise Unsupported("available CAP/H_RBBC profiles do not match the frozen GF research ABI")


def _parse_candidate(raw):
    fixed_bytes(raw, 5391, "private legacy18 CAP commitment candidate")
    try:
        parsed = parse_commitment(raw, cap.PRODUCTION_PARAMETERS)
        canonical = cap.serialize_commitment(
            cap.PRODUCTION_PARAMETERS, parsed.salt, parsed.h2, parsed.alpha,
            parsed.delta_p, parsed.delta_mhat,
        )
    except ExtractionFailure:
        raise ContractError("noncanonical legacy18 CAP commitment candidate") from None
    if canonical != raw:
        raise ContractError("alternate legacy18 CAP commitment encoding")
    return parsed


def evaluate_i3_hash_candidate_research(
    *, common_pp: bytes, tpk_record: bytes, statement: bytes, witness: bytes,
    cap_commitment_candidate: bytes, purpose: str = "production",
) -> ResearchI3HashEvaluation:
    """Compute beta == r XOR H_RBBC(d_M, candidate), leaving CAP origin OPEN.

All five inputs are immutable bytes. The candidate is a PRIVATE research input,
not a new proof, public statement field, or trusted CAP output. Production fails
before parsing. Candidate grammar errors also precede partial cryptography.
Binding failures, partial computation errors and unequal salts skip H_RBBC.
Ordinary I4/I5 mismatches still allow an independent candidate hash diagnostic.
No sampler, CAP executor, external I/O, callback, certificate or proof is used.
"""
    if type(purpose) is not str or purpose not in ("research", "production"):
        raise ContractError("unknown I3 candidate purpose")
    if purpose == "production":
        raise Unsupported("GF I3 hash consumer has no CAP-origin or production acceptance")
    _check_profiles()
    candidate = _parse_candidate(cap_commitment_candidate)
    partial = evaluate_partial_issuance_research(
        common_pp=common_pp, tpk_record=tpk_record, statement=statement, witness=witness,
        purpose="research",
    )
    checks = {name: S.NOT_EVALUATED for name in _CHECK_NAMES}
    checks.update(CAP_candidate_codecs=S.PASSED, CAP_rho_execution=S.OPEN, CAP_mask_derivation=S.OPEN)

    def result():
        return ResearchI3HashEvaluation(partial, tuple((name, checks[name]) for name in _CHECK_NAMES))

    if (any(partial.status(name) is not P.PASSED for name in _BINDING_NAMES)
            or partial.status("I2_digest") is not P.COMPUTED_UNJOINED
            or partial.errored_checks):
        return result()

    # Re-decode the same already checked immutable packets. This does not accept
    # a caller-created diagnostic as authority, nor join native circuit wires.
    x = ResearchIssueStatement.decode(statement)
    w = ResearchIssueWitness.decode(witness)
    rho_salts = tuple(int.from_bytes(w.cap_randomness[i:i + 25], "little") for i in (84, 109))
    if candidate.salt != rho_salts:
        checks["CAP_salt_binding"] = S.FAILED
        return result()
    checks["CAP_salt_binding"] = S.PASSED
    try:
        # Same full-M hash semantics as the partial evaluator; its legacy I2
        # status remains computed_unjoined because no complete CAP/I3 is proven.
        digest = fixed_bytes(w.ticket_m.d_M, 32, "private full M digest")
        image = fixed_bytes(h_rbbc.hash_request_binding(digest, cap_commitment_candidate), 72, "H_RBBC image")
    except Exception:
        checks["I2_H_RBBC_consumer"] = S.ERROR
        return result()
    checks["I2_H_RBBC_consumer"] = S.COMPUTED_UNVERIFIED_CAP
    expected_beta = bytes(left ^ right for left, right in zip(w.blind_mask, image))
    checks["I3_beta_equation"] = S.MATCHED_UNVERIFIED_CAP if expected_beta == x.beta else S.FAILED
    return result()
