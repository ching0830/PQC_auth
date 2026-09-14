"""Direct evaluator for the v0.2 holder-possession access relation.

This is an executable relation oracle, not a zero-knowledge proof system.  It
must not be used as a production access-NIZK verifier.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from .access import DIGEST_BYTES, AccessRequestV2, derive_request_core_digest
from .framing import ProtocolEncodingError


HOLDER_SECRET_BYTES = 32
HOLDER_HASH_LABEL = b"PQ-RBBC/HOLD"
HOLDER_BINDING_LABEL = b"PQ-SAT/ACCESS-HOLDER-BIND/v2"
STATEMENT_MAGIC = b"PQSAT-X2"
STATEMENT_VERSION = 2
STATEMENT_HEADER = struct.Struct(">8sH")
STATEMENT_BYTES = STATEMENT_HEADER.size + (5 * DIGEST_BYTES)
PRODUCTION_READY = False


def _fixed_bytes(value: bytes, size: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    return value


def derive_holder_hash(holder_secret: bytes) -> bytes:
    """Compute the ticket payload's canonical ``h = H_hold(k_hold)``."""

    secret = _fixed_bytes(
        holder_secret,
        HOLDER_SECRET_BYTES,
        "holder_secret",
    )
    return hashlib.shake_256(HOLDER_HASH_LABEL + secret).digest(DIGEST_BYTES)


def derive_holder_binding_tag(
    holder_secret: bytes,
    request_core_digest: bytes,
) -> bytes:
    """Bind holder-secret possession to one exact AccessRequestV2 core."""

    secret = _fixed_bytes(
        holder_secret,
        HOLDER_SECRET_BYTES,
        "holder_secret",
    )
    core_digest = _fixed_bytes(
        request_core_digest,
        DIGEST_BYTES,
        "request_core_digest",
    )
    return hashlib.shake_256(
        HOLDER_BINDING_LABEL + secret + core_digest
    ).digest(DIGEST_BYTES)


@dataclass(frozen=True)
class AccessProofStatementV2:
    access_profile_digest: bytes
    access_pp_digest: bytes
    holder_hash: bytes
    request_core_digest: bytes
    holder_binding_tag: bytes

    def __post_init__(self) -> None:
        for name in (
            "access_profile_digest",
            "access_pp_digest",
            "holder_hash",
            "request_core_digest",
            "holder_binding_tag",
        ):
            _fixed_bytes(getattr(self, name), DIGEST_BYTES, name)

    def encode(self) -> bytes:
        return STATEMENT_HEADER.pack(STATEMENT_MAGIC, STATEMENT_VERSION) + b"".join(
            (
                self.access_profile_digest,
                self.access_pp_digest,
                self.holder_hash,
                self.request_core_digest,
                self.holder_binding_tag,
            )
        )

    @classmethod
    def decode(cls, encoded: bytes) -> "AccessProofStatementV2":
        if not isinstance(encoded, bytes):
            raise TypeError("encoded statement must be bytes")
        if len(encoded) != STATEMENT_BYTES:
            raise ProtocolEncodingError("access proof statement length mismatch")
        magic, version = STATEMENT_HEADER.unpack_from(encoded)
        if magic != STATEMENT_MAGIC:
            raise ProtocolEncodingError("access proof statement magic mismatch")
        if version != STATEMENT_VERSION:
            raise ProtocolEncodingError("unsupported access proof statement version")
        offset = STATEMENT_HEADER.size
        fields = []
        for _ in range(5):
            fields.append(encoded[offset : offset + DIGEST_BYTES])
            offset += DIGEST_BYTES
        return cls(*fields)


@dataclass(frozen=True)
class AccessProofWitnessV2:
    holder_secret: bytes

    def __post_init__(self) -> None:
        _fixed_bytes(
            self.holder_secret,
            HOLDER_SECRET_BYTES,
            "holder_secret",
        )


@dataclass(frozen=True)
class AccessRelationResultV2:
    accepted: bool
    failures: tuple[str, ...]


def build_access_statement(
    *,
    access_profile_digest: bytes,
    access_pp_digest: bytes,
    holder_hash: bytes,
    request: AccessRequestV2,
) -> AccessProofStatementV2:
    """Build the verifier-owned statement from configuration and exact M1."""

    if not isinstance(request, AccessRequestV2):
        raise TypeError("request must be AccessRequestV2")
    return AccessProofStatementV2(
        access_profile_digest=access_profile_digest,
        access_pp_digest=access_pp_digest,
        holder_hash=holder_hash,
        request_core_digest=derive_request_core_digest(request),
        holder_binding_tag=request.holder_binding_tag,
    )


def evaluate_access_relation(
    statement: AccessProofStatementV2,
    witness: AccessProofWitnessV2,
) -> AccessRelationResultV2:
    """Evaluate ``R_access`` and report each failed equality."""

    if not isinstance(statement, AccessProofStatementV2):
        raise TypeError("statement must be AccessProofStatementV2")
    if not isinstance(witness, AccessProofWitnessV2):
        raise TypeError("witness must be AccessProofWitnessV2")
    failures: list[str] = []
    if derive_holder_hash(witness.holder_secret) != statement.holder_hash:
        failures.append("holder_hash")
    if (
        derive_holder_binding_tag(
            witness.holder_secret,
            statement.request_core_digest,
        )
        != statement.holder_binding_tag
    ):
        failures.append("holder_binding_tag")
    return AccessRelationResultV2(
        accepted=not failures,
        failures=tuple(failures),
    )
