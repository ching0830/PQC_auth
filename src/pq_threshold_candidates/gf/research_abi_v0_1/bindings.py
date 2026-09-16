"""Byte identity checks against an external research pin, never authentication.

No signature/evidence/proof verifier or threshold backend is called. Opaque
artifact identity checks do not validate their provenance or cryptography.
"""

from dataclasses import dataclass
import hashlib

from pq_rbbc.contracts.system import (
    ContractError as SystemContractError, KeyRole, SystemInitializationBundle,
)

from ...contracts import ContractError, Unsupported
from .codecs import (
    ResearchCommonPP, ResearchIssueStatement, ResearchTicketM,
    public_key_record_sha256_research, require_digest,
)


class ResearchBindingMismatch(ContractError):
    """A non-secret field label identifies the inconsistent binding."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(f"research binding mismatch: {code}")


@dataclass(frozen=True, repr=False)
class ResearchBindingMatch:
    """Diagnostic only; not a trusted ticket, authorization, or verifier result."""

    initialization_bundle_sha256: bytes
    common_pp_sha256: bytes
    tpk_record_sha256: bytes

    def __post_init__(self):
        for name in ("initialization_bundle_sha256", "common_pp_sha256", "tpk_record_sha256"):
            require_digest(getattr(self, name), name)

    @property
    def authentication_verified(self) -> bool:
        return False

    @property
    def production_qualified(self) -> bool:
        return False

    def __bool__(self):
        raise TypeError("ResearchBindingMatch is diagnostic, not an acceptance boolean")

    def __repr__(self):
        return "ResearchBindingMatch(identity_only=True, authentication_verified=False)"


def _match(actual: bytes | int, expected: bytes | int, code: str) -> None:
    if actual != expected:
        raise ResearchBindingMismatch(code)


def _bounded_bytes(value: bytes, maximum: int, label: str) -> None:
    if type(value) is not bytes or not 0 < len(value) <= maximum:
        raise ContractError(f"{label} requires bounded, nonempty immutable bytes")


def check_key_pp_bindings_research(
    *, expected_bundle_sha256: bytes, initialization_bundle: bytes,
    common_pp: bytes, tpk_record: bytes, key_origin_evidence: bytes,
    issue_backend_pp: bytes, gf_full_relation_manifest: bytes,
    statement: bytes, ticket_m: bytes, purpose: str = "production",
) -> ResearchBindingMatch:
    """Match captured bytes under an explicitly supplied research bundle pin.

    Caller must opt into purpose='research'. The supplied pin is a test/input
    assumption, not a verified trust anchor. Even self-consistent bogus opaque
    evidence can match: certification and proof qualification remain OPEN.
    M is private to this local harness; this is NOT witness-free VerifyIssue.
    """
    if type(purpose) is not str or purpose not in ("production", "research"):
        raise ContractError("unknown binding-check purpose")
    if purpose == "production":
        raise Unsupported("GF authentication, key-origin, full relation and production binding are OPEN")

    require_digest(expected_bundle_sha256, "expected bundle SHA-256")
    _bounded_bytes(initialization_bundle, 1 << 16, "initialization bundle")
    # Exact immutable bytes are hashed, parsed, and consumed; no path re-opening.
    bundle_digest = hashlib.sha256(initialization_bundle).digest()
    _match(bundle_digest, expected_bundle_sha256, "initialization_bundle_sha256")
    try:
        bundle = SystemInitializationBundle.decode(initialization_bundle)
    except SystemContractError as error:
        raise ContractError("noncanonical initialization bundle") from error
    parameters = ResearchCommonPP.decode(common_pp)
    pp_digest = hashlib.sha256(common_pp).digest()
    _match(pp_digest, bundle.common_parameters_digest, "common_pp_sha256")
    binding = parameters.trace_binding
    configuration = bundle.configuration
    _match(binding.configuration_sha256, hashlib.sha256(configuration.encode()).digest(), "configuration_sha256")
    _match(binding.ctx, bundle.ctx, "binding_ctx")
    _match(binding.epoch, configuration.epoch, "epoch")
    opening_key = bundle.key_for(KeyRole.OPENING_ENCRYPTION)
    issuer_key = bundle.key_for(KeyRole.ISSUER_VERIFICATION)
    _match(binding.oa_key_id, opening_key.key_id, "oa_key_id")
    _match(binding.issuer_key_id, issuer_key.key_id, "issuer_key_id")
    _match(binding.issuer_public_key_sha256, issuer_key.public_key_digest, "issuer_public_key_sha256")
    key_digest = public_key_record_sha256_research(tpk_record)
    _match(key_digest, binding.tpk_record_sha256, "tpk_record_sha256")
    _match(key_digest, opening_key.public_key_digest, "bundle_tpk_record_sha256")

    for raw, expected, name in (
        (key_origin_evidence, binding.key_origin_evidence_sha256, "key_origin_evidence_sha256"),
        (issue_backend_pp, parameters.issue_backend_pp_sha256, "issue_backend_pp_sha256"),
        (gf_full_relation_manifest, parameters.gf_full_relation_manifest_sha256, "gf_full_relation_manifest_sha256"),
    ):
        _bounded_bytes(raw, 1 << 20, name)
        _match(hashlib.sha256(raw).digest(), expected, name)

    x = ResearchIssueStatement.decode(statement)
    m = ResearchTicketM.decode(ticket_m)
    _match(x.common_pp_sha256, pp_digest, "statement_common_pp_sha256")
    _match(m.common_pp_sha256, pp_digest, "ticket_common_pp_sha256")
    _match(x.ctx, bundle.ctx, "statement_ctx")
    _match(m.ctx, x.ctx, "ticket_ctx")
    return ResearchBindingMatch(bundle_digest, pp_digest, key_digest)
