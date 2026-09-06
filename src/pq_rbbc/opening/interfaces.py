"""Abstract cryptographic, clock, and replay boundaries for conditional opening."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from pq_rbbc.contracts.system import (
    CONTEXT_BYTES,
    KEY_ID_BYTES,
    KeyReference,
    KeyRole,
)
from pq_rbbc.opening.request import CASE_ID_BYTES, DIGEST_BYTES

if TYPE_CHECKING:
    from pq_rbbc.opening.shares import OpenShare


SERIAL_BYTES = 16
MEMBER_ID_BYTES = 32
IDENTITY_BYTES = 32
MAX_TRACE_CIPHERTEXT_BYTES = 1 << 20
MAX_SHARE_VALUE_BYTES = 1 << 20
MAX_SHARE_AUTHENTICATION_BYTES = 1 << 16


class OpeningInterfaceError(ValueError):
    """Raised when an abstract backend crosses the boundary with invalid data."""


def _fixed(value: bytes, length: int, label: str, *, nonzero: bool = True) -> None:
    if not isinstance(value, bytes) or len(value) != length:
        raise OpeningInterfaceError(f"{label} must be exactly {length} bytes")
    if nonzero and value == bytes(length):
        raise OpeningInterfaceError(f"{label} must not be all zero")


@dataclass(frozen=True)
class TicketView:
    """Trusted output of a successful full-ticket verification backend."""

    ticket_digest: bytes
    ctx: bytes
    visible_serial: bytes
    trace_ciphertext: bytes
    issuer_key_id: bytes

    def validate(self) -> None:
        _fixed(self.ticket_digest, DIGEST_BYTES, "ticket_digest")
        _fixed(self.ctx, CONTEXT_BYTES, "ticket ctx", nonzero=False)
        _fixed(self.visible_serial, SERIAL_BYTES, "visible serial")
        if not isinstance(self.trace_ciphertext, bytes) or not (
            0 < len(self.trace_ciphertext) <= MAX_TRACE_CIPHERTEXT_BYTES
        ):
            raise OpeningInterfaceError("trace ciphertext length is outside bounds")
        _fixed(self.issuer_key_id, KEY_ID_BYTES, "issuer_key_id")


class TicketVerifier(Protocol):
    """Strictly parse and fully authenticate canonical ticket bytes.

    Returning ``None`` means rejection.  A real implementation must validate
    the complete ticket, including its issuer authentication; this prototype
    deliberately does not implement that cryptography.
    """

    def verify(self, canonical_ticket: bytes) -> TicketView | None: ...


class OpeningAuthorizationVerifier(Protocol):
    """Verify one case authorization under the supplied role-separated key."""

    def verify(
        self,
        key: KeyReference,
        message: bytes,
        authentication: bytes,
    ) -> bool: ...


class Clock(Protocol):
    def now(self) -> int: ...


@dataclass(frozen=True)
class ReplayReservation:
    replay_key: bytes
    token: bytes

    def validate(self) -> None:
        _fixed(self.replay_key, DIGEST_BYTES, "replay key")
        if not isinstance(self.token, bytes) or not self.token:
            raise OpeningInterfaceError("replay token must be non-empty bytes")


class OpeningReplayStore(Protocol):
    """Atomic replay reservation boundary.

    ``begin`` atomically creates an in-progress reservation and returns its
    unforgeable token, or returns ``None`` when the key is already in progress
    or committed.  ``commit`` atomically makes it permanently consumed.
    ``abort`` may release only the exact still-in-progress token.

    A backend failure must never make a possibly committed key fresh.  A crash
    after begin therefore leaves the key in-progress (fail closed) until a
    backend-specific, audited recovery policy resolves it.  The service commits
    before returning a share, so crashes after commit can lose availability but
    cannot emit an unrecorded share.
    """

    def begin(self, replay_key: bytes) -> ReplayReservation | None: ...

    def commit(self, reservation: ReplayReservation) -> None: ...

    def abort(self, reservation: ReplayReservation) -> None: ...


@dataclass(frozen=True)
class ThresholdOpeningContext:
    """Only gate-validated input supplied to one OA member backend."""

    member_id: bytes
    opening_key: KeyReference
    epoch: int
    request_digest: bytes
    ticket_digest: bytes
    case_id: bytes
    trace_ciphertext: bytes

    def validate(self) -> None:
        _fixed(self.member_id, MEMBER_ID_BYTES, "member_id")
        self.opening_key.validate()
        if self.opening_key.role is not KeyRole.OPENING_ENCRYPTION:
            raise OpeningInterfaceError("threshold context has wrong key role")
        if (
            not isinstance(self.epoch, int)
            or isinstance(self.epoch, bool)
            or not 0 <= self.epoch < (1 << 64)
        ):
            raise OpeningInterfaceError("threshold context epoch is outside u64")
        _fixed(self.request_digest, DIGEST_BYTES, "request_digest")
        _fixed(self.ticket_digest, DIGEST_BYTES, "ticket_digest")
        _fixed(self.case_id, CASE_ID_BYTES, "case_id")
        if not isinstance(self.trace_ciphertext, bytes) or not (
            0 < len(self.trace_ciphertext) <= MAX_TRACE_CIPHERTEXT_BYTES
        ):
            raise OpeningInterfaceError("trace ciphertext length is outside bounds")


@dataclass(frozen=True)
class ThresholdShareMaterial:
    """Opaque backend output; no threshold cryptography is implemented here."""

    share_value: bytes
    authentication: bytes

    def validate(self) -> None:
        if not isinstance(self.share_value, bytes) or not (
            0 < len(self.share_value) <= MAX_SHARE_VALUE_BYTES
        ):
            raise OpeningInterfaceError("share value length is outside bounds")
        if not isinstance(self.authentication, bytes) or not (
            0 < len(self.authentication) <= MAX_SHARE_AUTHENTICATION_BYTES
        ):
            raise OpeningInterfaceError("share authentication length is outside bounds")


class ThresholdShareBackend(Protocol):
    """Private OA-member boundary; it has no arbitrary-ciphertext entry point."""

    def create_share(
        self, context: ThresholdOpeningContext
    ) -> ThresholdShareMaterial: ...


class ShareVerifier(Protocol):
    def verify(
        self,
        opening_key: KeyReference,
        message: bytes,
        authentication: bytes,
    ) -> bool: ...


@dataclass(frozen=True)
class DecodedTrace:
    identity: bytes
    serial: bytes
    authentication_material: bytes

    def validate(self) -> None:
        _fixed(self.identity, IDENTITY_BYTES, "decoded identity", nonzero=False)
        _fixed(self.serial, SERIAL_BYTES, "decoded serial")
        if (
            not isinstance(self.authentication_material, bytes)
            or not self.authentication_material
        ):
            raise OpeningInterfaceError(
                "trace authentication material must be non-empty"
            )


class ThresholdReconstructionBackend(Protocol):
    """Abstract threshold Niederreiter reconstruction/decoding boundary."""

    def reconstruct(
        self,
        ticket: TicketView,
        shares: tuple["OpenShare", ...],
    ) -> DecodedTrace: ...


class TraceAuthenticationVerifier(Protocol):
    """Validate the reconstructed trace DEM authentication after decoding."""

    def verify(self, ticket: TicketView, decoded: DecodedTrace) -> bool: ...
