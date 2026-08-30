"""Test-only linearizable reference store for one-time ticket consumption.

The in-memory lock gives process-local linearizability for executable state
machine tests.  It is neither durable nor distributed and MUST NOT be treated
as a production FGS replay backend.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum

from .identities import TicketUseIdentity


ATTEMPT_ID_BYTES = 32
TRANSCRIPT_DIGEST_BYTES = 32
SESSION_ID_BYTES = 32
RESPONSE_DIGEST_BYTES = 32
MAX_SEALED_RESPONSE_BYTES = 1_048_576


class ReplayStoreError(RuntimeError):
    """Base class for fail-closed replay-store errors."""


class IdentityConflict(ReplayStoreError):
    """A serial or digest is already bound to another use identity."""


class TicketUnavailable(ReplayStoreError):
    """A different attempt has reserved or consumed this ticket."""


class ReservationNotFound(ReplayStoreError):
    """No matching reservation exists for commit or abort."""


class InvalidTransition(ReplayStoreError):
    """The requested transition would weaken one-time semantics."""


class ReserveDisposition(Enum):
    NEW = "new"
    EXISTING_RESERVATION = "existing_reservation"
    EXISTING_CONSUMPTION = "existing_consumption"


def _fixed_bytes(value: bytes, size: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    return value


def _timestamp(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


@dataclass(frozen=True)
class Reservation:
    identity: TicketUseIdentity
    attempt_id: bytes
    transcript_digest: bytes
    reserved_at: int
    lease_deadline: int

    def __post_init__(self) -> None:
        if not isinstance(self.identity, TicketUseIdentity):
            raise TypeError("identity must be a TicketUseIdentity")
        _fixed_bytes(self.attempt_id, ATTEMPT_ID_BYTES, "attempt_id")
        _fixed_bytes(
            self.transcript_digest,
            TRANSCRIPT_DIGEST_BYTES,
            "transcript_digest",
        )
        _timestamp(self.reserved_at, "reserved_at")
        _timestamp(self.lease_deadline, "lease_deadline")
        if self.lease_deadline <= self.reserved_at:
            raise ValueError("lease_deadline must follow reserved_at")


@dataclass(frozen=True)
class Consumption:
    identity: TicketUseIdentity
    attempt_id: bytes
    transcript_digest: bytes
    session_id: bytes
    response_digest: bytes
    sealed_response: bytes
    consumed_at: int
    retention_deadline: int

    def __post_init__(self) -> None:
        if not isinstance(self.identity, TicketUseIdentity):
            raise TypeError("identity must be a TicketUseIdentity")
        _fixed_bytes(self.attempt_id, ATTEMPT_ID_BYTES, "attempt_id")
        _fixed_bytes(
            self.transcript_digest,
            TRANSCRIPT_DIGEST_BYTES,
            "transcript_digest",
        )
        _fixed_bytes(self.session_id, SESSION_ID_BYTES, "session_id")
        _fixed_bytes(
            self.response_digest,
            RESPONSE_DIGEST_BYTES,
            "response_digest",
        )
        if not isinstance(self.sealed_response, bytes):
            raise TypeError("sealed_response must be bytes")
        if len(self.sealed_response) > MAX_SEALED_RESPONSE_BYTES:
            raise ValueError("sealed_response exceeds reference-store maximum")
        _timestamp(self.consumed_at, "consumed_at")
        _timestamp(self.retention_deadline, "retention_deadline")
        if self.retention_deadline < self.consumed_at:
            raise ValueError("retention_deadline precedes consumed_at")


UseRecord = Reservation | Consumption


@dataclass(frozen=True)
class ReserveResult:
    disposition: ReserveDisposition
    record: UseRecord


class InMemoryLinearizableReplayStore:
    """Thread-safe executable model of the v0.1 replay state machine.

    ``production_ready`` is intentionally false.  A production backend must
    provide durable, cross-process and cross-FGS linearizable transactions.
    """

    production_ready = False

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[bytes, UseRecord] = {}
        self._digest_index: dict[tuple[bytes, bytes], bytes] = {}
        self._serial_index: dict[tuple[bytes, bytes], bytes] = {}

    def _check_identity_bindings(self, identity: TicketUseIdentity) -> bytes:
        use_key = identity.use_key
        digest_binding = self._digest_index.get(
            (identity.ctx, identity.ticket_digest)
        )
        serial_binding = self._serial_index.get((identity.ctx, identity.serial))
        if digest_binding is not None and digest_binding != use_key:
            raise IdentityConflict("ticket digest is bound to another serial")
        if serial_binding is not None and serial_binding != use_key:
            raise IdentityConflict("ticket serial is bound to another digest")
        existing = self._records.get(use_key)
        if existing is not None and existing.identity != identity:
            raise IdentityConflict("use-key collision or inconsistent identity")
        return use_key

    def _bind_identity(self, identity: TicketUseIdentity, use_key: bytes) -> None:
        self._digest_index[(identity.ctx, identity.ticket_digest)] = use_key
        self._serial_index[(identity.ctx, identity.serial)] = use_key

    def reserve(
        self,
        identity: TicketUseIdentity,
        *,
        attempt_id: bytes,
        transcript_digest: bytes,
        reserved_at: int,
        lease_deadline: int,
    ) -> ReserveResult:
        """Atomically reserve a validated ticket for one authenticated attempt."""

        candidate = Reservation(
            identity=identity,
            attempt_id=attempt_id,
            transcript_digest=transcript_digest,
            reserved_at=reserved_at,
            lease_deadline=lease_deadline,
        )
        with self._lock:
            use_key = self._check_identity_bindings(identity)
            existing = self._records.get(use_key)
            if existing is None:
                self._bind_identity(identity, use_key)
                self._records[use_key] = candidate
                return ReserveResult(ReserveDisposition.NEW, candidate)
            if (
                existing.attempt_id == candidate.attempt_id
                and existing.transcript_digest == candidate.transcript_digest
            ):
                disposition = (
                    ReserveDisposition.EXISTING_RESERVATION
                    if isinstance(existing, Reservation)
                    else ReserveDisposition.EXISTING_CONSUMPTION
                )
                return ReserveResult(disposition, existing)
            raise TicketUnavailable("ticket belongs to another access attempt")

    def commit(
        self,
        identity: TicketUseIdentity,
        *,
        attempt_id: bytes,
        transcript_digest: bytes,
        session_id: bytes,
        response_digest: bytes,
        sealed_response: bytes,
        consumed_at: int,
        retention_deadline: int,
    ) -> Consumption:
        """Atomically commit the unique session and its idempotent response."""

        candidate = Consumption(
            identity=identity,
            attempt_id=attempt_id,
            transcript_digest=transcript_digest,
            session_id=session_id,
            response_digest=response_digest,
            sealed_response=sealed_response,
            consumed_at=consumed_at,
            retention_deadline=retention_deadline,
        )
        with self._lock:
            use_key = self._check_identity_bindings(identity)
            existing = self._records.get(use_key)
            if existing is None:
                raise ReservationNotFound("cannot commit an unreserved ticket")
            if isinstance(existing, Consumption):
                if existing == candidate:
                    return existing
                raise InvalidTransition("consumed ticket cannot change session")
            if (
                existing.attempt_id != candidate.attempt_id
                or existing.transcript_digest != candidate.transcript_digest
            ):
                raise ReservationNotFound("reservation belongs to another attempt")
            self._records[use_key] = candidate
            return candidate

    def abort(
        self,
        identity: TicketUseIdentity,
        *,
        attempt_id: bytes,
        transcript_digest: bytes,
    ) -> None:
        """Release a reservation only after the caller proves no commit exists."""

        canonical_attempt = _fixed_bytes(
            attempt_id,
            ATTEMPT_ID_BYTES,
            "attempt_id",
        )
        canonical_transcript = _fixed_bytes(
            transcript_digest,
            TRANSCRIPT_DIGEST_BYTES,
            "transcript_digest",
        )
        with self._lock:
            use_key = self._check_identity_bindings(identity)
            existing = self._records.get(use_key)
            if existing is None:
                raise ReservationNotFound("cannot abort an unreserved ticket")
            if isinstance(existing, Consumption):
                raise InvalidTransition("consumed ticket cannot be released")
            if (
                existing.attempt_id != canonical_attempt
                or existing.transcript_digest != canonical_transcript
            ):
                raise ReservationNotFound("reservation belongs to another attempt")
            del self._records[use_key]
            self._digest_index.pop((identity.ctx, identity.ticket_digest), None)
            self._serial_index.pop((identity.ctx, identity.serial), None)

    def lookup(self, identity: TicketUseIdentity) -> UseRecord | None:
        """Return the immutable record for an exact identity, if any."""

        with self._lock:
            use_key = self._check_identity_bindings(identity)
            return self._records.get(use_key)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)
