"""Abstract cryptographic contracts for satellite access v0.2.

No class in this module implements a cryptographic primitive.  Concrete
production implementations require a separately versioned suite, evidence,
and review; callers must fail closed while only the test-only suite exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .access import REFERENCE_PROOF_SUITE_ID, REFERENCE_SUITE_ID
from .proof import AccessProofStatementV2, AccessProofWitnessV2


class ProductionBackendUnavailable(RuntimeError):
    """Raised when a test-only or mismatched backend reaches a production gate."""


@dataclass(frozen=True)
class SessionKeysV2:
    server_finished_key: bytes
    client_finished_key: bytes
    application_key: bytes
    exporter_key: bytes

    def __post_init__(self) -> None:
        for name in (
            "server_finished_key",
            "client_finished_key",
            "application_key",
            "exporter_key",
        ):
            value = getattr(self, name)
            if not isinstance(value, bytes):
                raise TypeError(f"{name} must be bytes")
            if not value:
                raise ValueError(f"{name} must not be empty")


@runtime_checkable
class AccessNIZKBackendV2(Protocol):
    """Proof backend for the exact ``R_access`` statement encoding."""

    proof_suite_id: int
    production_ready: bool

    def prove(
        self,
        statement: AccessProofStatementV2,
        witness: AccessProofWitnessV2,
    ) -> bytes: ...

    def verify(
        self,
        statement: AccessProofStatementV2,
        proof: bytes,
    ) -> bool: ...


@runtime_checkable
class PQKEMBackendV2(Protocol):
    """Ephemeral-client KEM operations selected by an access suite."""

    suite_id: int
    production_ready: bool

    def validate_public_key(self, public_key: bytes) -> bool: ...

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]: ...

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes: ...


@runtime_checkable
class FGSAuthenticationBackendV2(Protocol):
    """Identity authentication distinct from KEM key confirmation."""

    suite_id: int
    production_ready: bool

    def authenticate(self, signing_key: object, message: bytes) -> bytes: ...

    def verify(
        self,
        verification_key: object,
        message: bytes,
        authenticator: bytes,
    ) -> bool: ...


@runtime_checkable
class KeyScheduleBackendV2(Protocol):
    """Domain-separated KDF and Finished contract for one suite."""

    suite_id: int
    production_ready: bool

    def derive_session_keys(
        self,
        shared_secret: bytes,
        transcript_digest: bytes,
        schedule_context: bytes,
    ) -> SessionKeysV2: ...

    def server_finished(
        self,
        key: bytes,
        transcript_digest: bytes,
        fgs_authenticator_digest: bytes,
    ) -> bytes: ...

    def client_finished(self, key: bytes, response_digest: bytes) -> bytes: ...

    def verify_finished(
        self,
        key: bytes,
        input_digest: bytes,
        confirmation: bytes,
    ) -> bool: ...


def require_production_backend(
    backend: object,
    *,
    expected_suite_id: int,
    proof_backend: bool = False,
) -> None:
    """Fail closed unless a backend explicitly matches a non-test suite.

    This structural guard does not certify the truth of ``production_ready``;
    suite registration, evidence, and independent review remain separate gates.
    """

    if isinstance(expected_suite_id, bool) or not isinstance(expected_suite_id, int):
        raise TypeError("expected_suite_id must be an integer")
    if not 0 <= expected_suite_id < (1 << 16):
        raise ValueError("expected_suite_id does not fit uint16")
    test_only_id = (
        REFERENCE_PROOF_SUITE_ID if proof_backend else REFERENCE_SUITE_ID
    )
    if expected_suite_id == test_only_id:
        raise ProductionBackendUnavailable("test-only suite cannot enter production")
    identifier_name = "proof_suite_id" if proof_backend else "suite_id"
    if getattr(backend, identifier_name, None) != expected_suite_id:
        raise ProductionBackendUnavailable("backend suite identifier mismatch")
    if getattr(backend, "production_ready", False) is not True:
        raise ProductionBackendUnavailable("backend is not production-ready")
