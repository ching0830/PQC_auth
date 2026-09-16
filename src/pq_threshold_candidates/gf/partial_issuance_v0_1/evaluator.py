"""Partial host evaluation of the frozen GF research issuance ABI.

The caller supplies private witness bytes. There is no authenticated bundle,
CAP computation, origin certificate verifier, native constraint or proof here.
I2 is computed but unjoined; I3 stays OPEN. No complete acceptance is returned.
"""

from dataclasses import dataclass
from enum import Enum
import hashlib

from ...contracts import ContractError, Unsupported, fixed_bytes
from ..reference import ReferencePublicKey, check_encryption_relation_reference
from ..research_abi_v0_1 import (
    ResearchCommonPP, ResearchIssueStatement, ResearchIssueWitness,
    public_key_record_sha256_research,
)


class ResearchPartialCheckStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_EVALUATED = "not_evaluated"
    COMPUTED_UNJOINED = "computed_unjoined"
    OPEN = "open"
    ERROR = "error"

    def __bool__(self):
        raise TypeError("Compare a partial check status explicitly; it is not an acceptance boolean")


_CHECK_NAMES = (
    "P1_codecs", "P0_statement_pp", "P0_ticket_pp", "P0_trace_key",
    "I1_statement_ctx", "I1_ticket_ctx", "I2_digest", "I3", "I4", "I5",
)
_UNRESOLVED = (
    "I2_to_I3_join", "I3_CAP_H_RBBC", "configuration_authentication",
    "key_origin_certification", "backend_qualification", "native_constraints",
    "proof_verification", "issuer_identity_session_authorization",
    "witness_freshness", "threshold_cryptography",
)
S = ResearchPartialCheckStatus


@dataclass(frozen=True, repr=False)
class ResearchPartialIssuanceEvaluation:
    """Only status labels; never a credential, full accept, or witness export."""

    checks: tuple[tuple[str, ResearchPartialCheckStatus], ...]

    def __post_init__(self):
        if (type(self.checks) is not tuple
                or any(type(row) is not tuple or len(row) != 2 for row in self.checks)
                or tuple(row[0] for row in self.checks) != _CHECK_NAMES
                or any(type(row[1]) is not S for row in self.checks)):
            raise ContractError("noncanonical partial evaluation statuses")
        if self.status("I3") is not S.OPEN:
            raise ContractError("I3 must remain OPEN")
        if self.status("I2_digest") not in (S.COMPUTED_UNJOINED, S.NOT_EVALUATED, S.ERROR):
            raise ContractError("I2 has no verified consumer in this partial evaluator")

    def status(self, name: str) -> ResearchPartialCheckStatus:
        for label, status in self.checks:
            if name == label:
                return status
        raise ContractError("unknown partial check name")

    @property
    def failed_checks(self) -> tuple[str, ...]:
        return tuple(name for name, status in self.checks if status is S.FAILED)

    @property
    def errored_checks(self) -> tuple[str, ...]:
        return tuple(name for name, status in self.checks if status is S.ERROR)

    @property
    def unresolved(self) -> tuple[str, ...]:
        return _UNRESOLVED

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
        raise TypeError("Partial research evaluation cannot be used as an acceptance boolean")

    def __repr__(self):
        return "ResearchPartialIssuanceEvaluation(research_only=True, full_relation_verified=False)"


def _result(checks):
    return ResearchPartialIssuanceEvaluation(tuple((name, checks[name]) for name in _CHECK_NAMES))


def evaluate_partial_issuance_research(
    *, common_pp: bytes, tpk_record: bytes, statement: bytes, witness: bytes,
    purpose: str = "production",
) -> ResearchPartialIssuanceEvaluation:
    """Check local self-consistency and reference I4/I5 under explicit opt-in.

    Structural errors raise ContractError. Binding failures skip I2/I4/I5.
    I2 is only computed, with no I3 consumer; its private digest is not returned.
    Ordinary I4 mismatch still permits diagnostic I5 evaluation, using M.h.
    Unexpected computation errors yield ERROR without exposing exception text.
    The caller can replace a whole consistent setup: authentication is OPEN.
    """
    if type(purpose) is not str or purpose not in ("production", "research"):
        raise ContractError("unknown partial-evaluation purpose")
    if purpose == "production":
        raise Unsupported("GF partial witness evaluation has no full relation or production acceptance")

    # Parsers require exact immutable bytes. All later uses refer to these
    # captured inputs; no I/O, callback, sampler or secret-key input is involved.
    pp = ResearchCommonPP.decode(common_pp)
    key_digest = public_key_record_sha256_research(tpk_record)
    x = ResearchIssueStatement.decode(statement)
    w = ResearchIssueWitness.decode(witness)
    m = w.ticket_m
    pp_digest = hashlib.sha256(common_pp).digest()
    binding = pp.trace_binding
    checks = {name: S.NOT_EVALUATED for name in _CHECK_NAMES}
    checks.update(P1_codecs=S.PASSED, I3=S.OPEN)
    for name, left, right in (
        ("P0_statement_pp", x.common_pp_sha256, pp_digest),
        ("P0_ticket_pp", m.common_pp_sha256, pp_digest),
        ("P0_trace_key", key_digest, binding.tpk_record_sha256),
        ("I1_statement_ctx", x.ctx, binding.ctx),
        ("I1_ticket_ctx", m.ctx, x.ctx),
    ):
        checks[name] = S.PASSED if left == right else S.FAILED
    if any(status is S.FAILED for status in checks.values()):
        return _result(checks)

    try:
        # No public expected digest exists in this ABI. Computing this value
        # alone cannot establish I2's native constraints or its I3 linkage.
        fixed_bytes(m.d_M, 32, "I2 digest")
    except Exception:
        checks["I2_digest"] = S.ERROR
        return _result(checks)
    checks["I2_digest"] = S.COMPUTED_UNJOINED

    try:
        expected_h = hashlib.shake_256(b"PQ-RBBC/HOLD" + w.holder_key).digest(32)
        fixed_bytes(expected_h, 32, "I4 digest")
    except Exception:
        checks["I4"] = S.ERROR
        return _result(checks)
    checks["I4"] = S.PASSED if expected_h == m.h else S.FAILED

    try:
        # Decode the very same canonical record already hashed above. I5 uses
        # M.h rather than substituting the freshly calculated holder hash.
        key = ReferencePublicKey.decode(tpk_record)
        valid = check_encryption_relation_reference(
            key, m.trace_inputs_research(x.rid), m.ciphertext_research(), w.trace_witness_research(),
        )
    except Exception:
        checks["I5"] = S.ERROR
    else:
        checks["I5"] = S.PASSED if valid is True else S.FAILED if valid is False else S.ERROR
    return _result(checks)
