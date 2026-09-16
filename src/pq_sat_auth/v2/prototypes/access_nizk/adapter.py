"""Canonical request adapter for the experimental access proof.

The verifier supplies the authenticated profile/parameter digests and the
holder hash extracted from an already verified ticket.  The request-core
digest and holder-binding tag always come from the exact request object; no
prover-supplied alternate statement is accepted by this adapter.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

from ...access import (
    ProofLimitsV2,
    SuiteLimitsV2,
    REFERENCE_SUITE_REGISTRY,
    AccessRequestV2,
    derive_request_core_digest,
)
from ...proof import (
    AccessProofStatementV2,
    AccessProofWitnessV2,
)
from .mpcith import MPCITHAccessNIZKBackendV01
from .parameters import (
    BENCHMARK_PARAMETERS_V01,
    PROOF_SUITE_ID,
)


EXPERIMENTAL_PROOF_LIMITS_V01 = ProofLimitsV2(
    proof_suite_id=PROOF_SUITE_ID,
    max_access_nizk_bytes=BENCHMARK_PARAMETERS_V01.proof_bytes,
)
EXPERIMENTAL_PROOF_REGISTRY_V01: Mapping[int, ProofLimitsV2] = MappingProxyType(
    {PROOF_SUITE_ID: EXPERIMENTAL_PROOF_LIMITS_V01}
)


def build_verifier_owned_statement_v01(
    *,
    backend: MPCITHAccessNIZKBackendV01,
    access_profile_digest: bytes,
    authenticated_access_pp_digest: bytes,
    verified_ticket_holder_hash: bytes,
    request: AccessRequestV2,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
    proof_registry: Mapping[
        int, ProofLimitsV2
    ] = EXPERIMENTAL_PROOF_REGISTRY_V01,
) -> AccessProofStatementV2:
    """Rebuild exact ``x_access`` from verifier-owned inputs."""

    if not isinstance(backend, MPCITHAccessNIZKBackendV01):
        raise TypeError("backend must be MPCITHAccessNIZKBackendV01")
    if not isinstance(request, AccessRequestV2):
        raise TypeError("request must be AccessRequestV2")
    if request.proof_suite_id != backend.proof_suite_id:
        raise ValueError("request proof suite does not match backend")
    if authenticated_access_pp_digest != backend.parameters.digest:
        raise ValueError("authenticated access_pp_digest does not match parameters")
    return AccessProofStatementV2(
        access_profile_digest=access_profile_digest,
        access_pp_digest=authenticated_access_pp_digest,
        holder_hash=verified_ticket_holder_hash,
        request_core_digest=derive_request_core_digest(
            request,
            suite_registry,
            proof_registry,
        ),
        holder_binding_tag=request.holder_binding_tag,
    )


def prove_request_v01(
    *,
    backend: MPCITHAccessNIZKBackendV01,
    access_profile_digest: bytes,
    authenticated_access_pp_digest: bytes,
    verified_ticket_holder_hash: bytes,
    request: AccessRequestV2,
    holder_secret: bytes,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
    proof_registry: Mapping[
        int, ProofLimitsV2
    ] = EXPERIMENTAL_PROOF_REGISTRY_V01,
) -> bytes:
    """Generate a proof for an exact request core and witness input."""

    statement = build_verifier_owned_statement_v01(
        backend=backend,
        access_profile_digest=access_profile_digest,
        authenticated_access_pp_digest=authenticated_access_pp_digest,
        verified_ticket_holder_hash=verified_ticket_holder_hash,
        request=request,
        suite_registry=suite_registry,
        proof_registry=proof_registry,
    )
    return backend.prove(statement, AccessProofWitnessV2(holder_secret))


def verify_request_v01(
    *,
    backend: MPCITHAccessNIZKBackendV01,
    access_profile_digest: bytes,
    authenticated_access_pp_digest: bytes,
    verified_ticket_holder_hash: bytes,
    request: AccessRequestV2,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
    proof_registry: Mapping[
        int, ProofLimitsV2
    ] = EXPERIMENTAL_PROOF_REGISTRY_V01,
) -> bool:
    """Verify ``request.access_nizk`` against the reconstructed statement."""

    try:
        statement = build_verifier_owned_statement_v01(
            backend=backend,
            access_profile_digest=access_profile_digest,
            authenticated_access_pp_digest=authenticated_access_pp_digest,
            verified_ticket_holder_hash=verified_ticket_holder_hash,
            request=request,
            suite_registry=suite_registry,
            proof_registry=proof_registry,
        )
    except Exception:
        return False
    return backend.verify(statement, request.access_nizk)
