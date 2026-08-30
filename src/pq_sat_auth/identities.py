"""Canonical one-time ticket-use identities for system profile v0.1."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


CONTEXT_BYTES = 32
SERIAL_BYTES = 16
DIGEST_BYTES = 32
USE_KEY_LABEL = b"PQ-SAT/USE-KEY/v1"


def _fixed_bytes(value: bytes, size: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    return value


def derive_use_key(ctx: bytes, serial: bytes, ticket_digest: bytes) -> bytes:
    """Derive the 32-byte replay-store key defined by the v0.1 spec."""

    canonical_ctx = _fixed_bytes(ctx, CONTEXT_BYTES, "ctx")
    canonical_serial = _fixed_bytes(serial, SERIAL_BYTES, "serial")
    canonical_digest = _fixed_bytes(
        ticket_digest,
        DIGEST_BYTES,
        "ticket_digest",
    )
    return hashlib.shake_256(
        USE_KEY_LABEL + canonical_ctx + canonical_serial + canonical_digest
    ).digest(DIGEST_BYTES)


@dataclass(frozen=True)
class TicketUseIdentity:
    """The exact RBBC-derived values indexed by the replay store."""

    ctx: bytes
    serial: bytes
    ticket_digest: bytes

    def __post_init__(self) -> None:
        _fixed_bytes(self.ctx, CONTEXT_BYTES, "ctx")
        _fixed_bytes(self.serial, SERIAL_BYTES, "serial")
        _fixed_bytes(self.ticket_digest, DIGEST_BYTES, "ticket_digest")

    @property
    def use_key(self) -> bytes:
        return derive_use_key(self.ctx, self.serial, self.ticket_digest)
