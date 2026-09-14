"""Process-local reference state machine for one-time access v0.2.

The lock makes transitions linearizable only inside one Python process.  The
model is not durable or distributed and therefore is never a production FGS
replay backend.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from enum import Enum

from pq_sat_auth.identities import TicketUseIdentity
from pq_sat_auth.replay import (
    IdentityConflict,
    InvalidTransition,
    ReservationNotFound,
    TicketUnavailable,
)


DIGEST_BYTES = 32
SESSION_ID_BYTES = 32
MAX_SEALED_RESPONSE_BYTES = 1_048_576
MAX_SEALED_SESSION_STATE_BYTES = 1_048_576


def _fixed_bytes(value: bytes, size: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    return value


def _bounded_bytes(value: bytes, maximum: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if not value:
        raise ValueError(f"{name} must not be empty")
    if len(value) > maximum:
        raise ValueError(f"{name} exceeds reference-store maximum")
    return value


def _timestamp(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


class ReserveDispositionV2(Enum):
    NEW = "new"
    EXISTING_RESERVATION = "existing_reservation"
    EXISTING_GRANT = "existing_grant"


class GrantStateV2(Enum):
    CONSUMED_PENDING_CONFIRM = "consumed_pending_confirm"
    CONSUMED_ACTIVE = "consumed_active"
    CONSUMED_EXPIRED = "consumed_expired"


@dataclass(frozen=True)
class ReservationV2:
    identity: TicketUseIdentity
    attempt_id: bytes
    request_digest: bytes
    serving_context_digest: bytes
    reserved_at: int
    lease_deadline: int
    revocation_generation: int

    def __post_init__(self) -> None:
        if not isinstance(self.identity, TicketUseIdentity):
            raise TypeError("identity must be a TicketUseIdentity")
        _fixed_bytes(self.attempt_id, DIGEST_BYTES, "attempt_id")
        _fixed_bytes(self.request_digest, DIGEST_BYTES, "request_digest")
        _fixed_bytes(
            self.serving_context_digest,
            DIGEST_BYTES,
            "serving_context_digest",
        )
        _timestamp(self.reserved_at, "reserved_at")
        _timestamp(self.lease_deadline, "lease_deadline")
        _timestamp(self.revocation_generation, "revocation_generation")
        if self.lease_deadline <= self.reserved_at:
            raise ValueError("lease_deadline must follow reserved_at")


@dataclass(frozen=True)
class GrantRecordV2:
    state: GrantStateV2
    identity: TicketUseIdentity
    attempt_id: bytes
    request_digest: bytes
    transcript_digest: bytes
    session_id: bytes
    response_digest: bytes
    sealed_response: bytes
    sealed_session_state: bytes
    serving_context_digest: bytes
    fgs_id: bytes
    revocation_generation: int
    consumed_at: int
    activation_deadline: int
    session_expiry: int
    retention_deadline: int
    client_confirmation_digest: bytes | None = None
    activated_at: int | None = None
    expired_at: int | None = None
    expiry_reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.state, GrantStateV2):
            raise TypeError("state must be a GrantStateV2")
        if not isinstance(self.identity, TicketUseIdentity):
            raise TypeError("identity must be a TicketUseIdentity")
        for name in (
            "attempt_id",
            "request_digest",
            "transcript_digest",
            "response_digest",
            "serving_context_digest",
            "fgs_id",
        ):
            _fixed_bytes(getattr(self, name), DIGEST_BYTES, name)
        _fixed_bytes(self.session_id, SESSION_ID_BYTES, "session_id")
        _bounded_bytes(
            self.sealed_response,
            MAX_SEALED_RESPONSE_BYTES,
            "sealed_response",
        )
        _bounded_bytes(
            self.sealed_session_state,
            MAX_SEALED_SESSION_STATE_BYTES,
            "sealed_session_state",
        )
        _timestamp(self.revocation_generation, "revocation_generation")
        for name in (
            "consumed_at",
            "activation_deadline",
            "session_expiry",
            "retention_deadline",
        ):
            _timestamp(getattr(self, name), name)
        if self.activation_deadline <= self.consumed_at:
            raise ValueError("activation_deadline must follow consumed_at")
        if self.session_expiry < self.activation_deadline:
            raise ValueError("session_expiry precedes activation_deadline")
        if self.retention_deadline < self.session_expiry:
            raise ValueError("retention_deadline precedes session_expiry")

        if self.state is GrantStateV2.CONSUMED_PENDING_CONFIRM:
            if any(
                value is not None
                for value in (
                    self.client_confirmation_digest,
                    self.activated_at,
                    self.expired_at,
                    self.expiry_reason,
                )
            ):
                raise ValueError("pending grant contains terminal state fields")
        elif self.state is GrantStateV2.CONSUMED_ACTIVE:
            if self.client_confirmation_digest is None or self.activated_at is None:
                raise ValueError("active grant lacks client confirmation")
            _fixed_bytes(
                self.client_confirmation_digest,
                DIGEST_BYTES,
                "client_confirmation_digest",
            )
            _timestamp(self.activated_at, "activated_at")
            if self.activated_at > self.activation_deadline:
                raise ValueError("activated_at follows activation_deadline")
            if self.expired_at is not None or self.expiry_reason is not None:
                raise ValueError("active grant contains expiry fields")
        else:
            if self.expired_at is None or not self.expiry_reason:
                raise ValueError("expired grant lacks expiry evidence")
            _timestamp(self.expired_at, "expired_at")
            if self.client_confirmation_digest is not None:
                _fixed_bytes(
                    self.client_confirmation_digest,
                    DIGEST_BYTES,
                    "client_confirmation_digest",
                )
            if self.activated_at is not None:
                _timestamp(self.activated_at, "activated_at")


@dataclass(frozen=True)
class ReservationAbortEvidenceV2:
    """Opaque reference evidence required before RESERVED can be released."""

    no_grant_digest: bytes
    no_publication_digest: bytes
    fencing_digest: bytes

    def __post_init__(self) -> None:
        _fixed_bytes(self.no_grant_digest, DIGEST_BYTES, "no_grant_digest")
        _fixed_bytes(
            self.no_publication_digest,
            DIGEST_BYTES,
            "no_publication_digest",
        )
        _fixed_bytes(self.fencing_digest, DIGEST_BYTES, "fencing_digest")


UseRecordV2 = ReservationV2 | GrantRecordV2


@dataclass(frozen=True)
class ReserveResultV2:
    disposition: ReserveDispositionV2
    record: UseRecordV2


def _commit_identity(record: GrantRecordV2) -> tuple[object, ...]:
    """Return fields fixed by the unique CommitGrant operation."""

    return (
        record.identity,
        record.attempt_id,
        record.request_digest,
        record.transcript_digest,
        record.session_id,
        record.response_digest,
        record.sealed_response,
        record.sealed_session_state,
        record.serving_context_digest,
        record.fgs_id,
        record.revocation_generation,
        record.consumed_at,
        record.activation_deadline,
        record.session_expiry,
        record.retention_deadline,
    )


class InMemoryLinearizableReplayStoreV2:
    """Thread-safe executable v0.2 state model; never production-ready."""

    production_ready = False
    durable = False
    distributed = False

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[bytes, UseRecordV2] = {}
        self._digest_index: dict[tuple[bytes, bytes], bytes] = {}
        self._serial_index: dict[tuple[bytes, bytes], bytes] = {}

    def _check_identity_bindings(self, identity: TicketUseIdentity) -> bytes:
        if not isinstance(identity, TicketUseIdentity):
            raise TypeError("identity must be a TicketUseIdentity")
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
        request_digest: bytes,
        serving_context_digest: bytes,
        reserved_at: int,
        lease_deadline: int,
        revocation_generation: int,
    ) -> ReserveResultV2:
        """Atomically reserve a fully validated M1 for one exact attempt."""

        candidate = ReservationV2(
            identity=identity,
            attempt_id=attempt_id,
            request_digest=request_digest,
            serving_context_digest=serving_context_digest,
            reserved_at=reserved_at,
            lease_deadline=lease_deadline,
            revocation_generation=revocation_generation,
        )
        with self._lock:
            use_key = self._check_identity_bindings(identity)
            existing = self._records.get(use_key)
            if existing is None:
                self._bind_identity(identity, use_key)
                self._records[use_key] = candidate
                return ReserveResultV2(ReserveDispositionV2.NEW, candidate)
            if (
                existing.attempt_id == candidate.attempt_id
                and existing.request_digest == candidate.request_digest
            ):
                disposition = (
                    ReserveDispositionV2.EXISTING_RESERVATION
                    if isinstance(existing, ReservationV2)
                    else ReserveDispositionV2.EXISTING_GRANT
                )
                return ReserveResultV2(disposition, existing)
            raise TicketUnavailable("ticket belongs to another access attempt")

    def commit_grant(
        self,
        identity: TicketUseIdentity,
        *,
        attempt_id: bytes,
        request_digest: bytes,
        transcript_digest: bytes,
        session_id: bytes,
        response_digest: bytes,
        sealed_response: bytes,
        sealed_session_state: bytes,
        serving_context_digest: bytes,
        fgs_id: bytes,
        revocation_generation: int,
        consumed_at: int,
        activation_deadline: int,
        session_expiry: int,
        retention_deadline: int,
    ) -> GrantRecordV2:
        """Commit the unique M2/session before the response may be published."""

        candidate = GrantRecordV2(
            state=GrantStateV2.CONSUMED_PENDING_CONFIRM,
            identity=identity,
            attempt_id=attempt_id,
            request_digest=request_digest,
            transcript_digest=transcript_digest,
            session_id=session_id,
            response_digest=response_digest,
            sealed_response=sealed_response,
            sealed_session_state=sealed_session_state,
            serving_context_digest=serving_context_digest,
            fgs_id=fgs_id,
            revocation_generation=revocation_generation,
            consumed_at=consumed_at,
            activation_deadline=activation_deadline,
            session_expiry=session_expiry,
            retention_deadline=retention_deadline,
        )
        with self._lock:
            use_key = self._check_identity_bindings(identity)
            existing = self._records.get(use_key)
            if existing is None:
                raise ReservationNotFound("cannot commit an unreserved ticket")
            if isinstance(existing, GrantRecordV2):
                if _commit_identity(existing) == _commit_identity(candidate):
                    return existing
                raise InvalidTransition("consumed ticket cannot change grant")
            if (
                existing.attempt_id != candidate.attempt_id
                or existing.request_digest != candidate.request_digest
                or existing.serving_context_digest
                != candidate.serving_context_digest
                or existing.revocation_generation
                != candidate.revocation_generation
            ):
                raise ReservationNotFound("reservation belongs to another request")
            if candidate.consumed_at < existing.reserved_at:
                raise InvalidTransition("grant predates reservation")
            if candidate.consumed_at > existing.lease_deadline:
                raise InvalidTransition("reservation lease expired before commit")
            self._records[use_key] = candidate
            return candidate

    def activate(
        self,
        identity: TicketUseIdentity,
        *,
        attempt_id: bytes,
        request_digest: bytes,
        session_id: bytes,
        response_digest: bytes,
        client_confirmation_digest: bytes,
        activated_at: int,
    ) -> GrantRecordV2:
        """Atomically activate the exact pending session after Finished checks."""

        canonical_attempt = _fixed_bytes(attempt_id, DIGEST_BYTES, "attempt_id")
        canonical_request = _fixed_bytes(
            request_digest,
            DIGEST_BYTES,
            "request_digest",
        )
        canonical_session = _fixed_bytes(
            session_id,
            SESSION_ID_BYTES,
            "session_id",
        )
        canonical_response = _fixed_bytes(
            response_digest,
            DIGEST_BYTES,
            "response_digest",
        )
        canonical_confirmation = _fixed_bytes(
            client_confirmation_digest,
            DIGEST_BYTES,
            "client_confirmation_digest",
        )
        canonical_time = _timestamp(activated_at, "activated_at")
        with self._lock:
            use_key = self._check_identity_bindings(identity)
            existing = self._records.get(use_key)
            if existing is None or isinstance(existing, ReservationV2):
                raise ReservationNotFound("no committed grant exists")
            expected = (
                existing.attempt_id,
                existing.request_digest,
                existing.session_id,
                existing.response_digest,
            )
            actual = (
                canonical_attempt,
                canonical_request,
                canonical_session,
                canonical_response,
            )
            if actual != expected:
                raise InvalidTransition("activation belongs to another grant")
            if existing.state is GrantStateV2.CONSUMED_EXPIRED:
                raise InvalidTransition("expired grant cannot activate")
            if existing.state is GrantStateV2.CONSUMED_ACTIVE:
                if existing.client_confirmation_digest != canonical_confirmation:
                    raise InvalidTransition("active grant confirmation cannot change")
                return existing
            if canonical_time > existing.activation_deadline:
                raise InvalidTransition("activation deadline has passed")
            active = replace(
                existing,
                state=GrantStateV2.CONSUMED_ACTIVE,
                client_confirmation_digest=canonical_confirmation,
                activated_at=canonical_time,
            )
            self._records[use_key] = active
            return active

    def expire(
        self,
        identity: TicketUseIdentity,
        *,
        expired_at: int,
        reason: str,
    ) -> GrantRecordV2:
        """Move pending/active state to consumed-expired without releasing it."""

        canonical_time = _timestamp(expired_at, "expired_at")
        if not isinstance(reason, str):
            raise TypeError("reason must be str")
        if not reason:
            raise ValueError("reason must not be empty")
        with self._lock:
            use_key = self._check_identity_bindings(identity)
            existing = self._records.get(use_key)
            if existing is None or isinstance(existing, ReservationV2):
                raise InvalidTransition("only a committed grant may expire")
            if existing.state is GrantStateV2.CONSUMED_EXPIRED:
                return existing
            deadline = (
                existing.activation_deadline
                if existing.state is GrantStateV2.CONSUMED_PENDING_CONFIRM
                else existing.session_expiry
            )
            if canonical_time <= deadline:
                raise InvalidTransition("grant deadline has not passed")
            expired = replace(
                existing,
                state=GrantStateV2.CONSUMED_EXPIRED,
                expired_at=canonical_time,
                expiry_reason=reason,
            )
            self._records[use_key] = expired
            return expired

    def terminate(
        self,
        identity: TicketUseIdentity,
        *,
        terminated_at: int,
        reason: str,
    ) -> GrantRecordV2:
        """Terminate a committed session early without releasing its ticket."""

        canonical_time = _timestamp(terminated_at, "terminated_at")
        if not isinstance(reason, str):
            raise TypeError("reason must be str")
        if not reason:
            raise ValueError("reason must not be empty")
        with self._lock:
            use_key = self._check_identity_bindings(identity)
            existing = self._records.get(use_key)
            if existing is None or isinstance(existing, ReservationV2):
                raise InvalidTransition("only a committed grant may terminate")
            if existing.state is GrantStateV2.CONSUMED_EXPIRED:
                return existing
            earliest = (
                existing.consumed_at
                if existing.state is GrantStateV2.CONSUMED_PENDING_CONFIRM
                else existing.activated_at
            )
            if earliest is None or canonical_time < earliest:
                raise InvalidTransition("termination predates committed state")
            expired = replace(
                existing,
                state=GrantStateV2.CONSUMED_EXPIRED,
                expired_at=canonical_time,
                expiry_reason=reason,
            )
            self._records[use_key] = expired
            return expired

    def abort_reservation(
        self,
        identity: TicketUseIdentity,
        *,
        attempt_id: bytes,
        request_digest: bytes,
        evidence: ReservationAbortEvidenceV2,
    ) -> None:
        """Release RESERVED only with caller-supplied bounded recovery evidence.

        The reference model validates evidence shape, not its real-world truth.
        A production backend must prove grant absence, publication absence, and
        worker fencing in its own transactional failure model.
        """

        canonical_attempt = _fixed_bytes(attempt_id, DIGEST_BYTES, "attempt_id")
        canonical_request = _fixed_bytes(
            request_digest,
            DIGEST_BYTES,
            "request_digest",
        )
        if not isinstance(evidence, ReservationAbortEvidenceV2):
            raise TypeError("evidence must be ReservationAbortEvidenceV2")
        with self._lock:
            use_key = self._check_identity_bindings(identity)
            existing = self._records.get(use_key)
            if existing is None:
                raise ReservationNotFound("cannot abort an unreserved ticket")
            if isinstance(existing, GrantRecordV2):
                raise InvalidTransition("consumed ticket cannot be released")
            if (
                existing.attempt_id != canonical_attempt
                or existing.request_digest != canonical_request
            ):
                raise ReservationNotFound("reservation belongs to another request")
            del self._records[use_key]
            self._digest_index.pop((identity.ctx, identity.ticket_digest), None)
            self._serial_index.pop((identity.ctx, identity.serial), None)

    def lookup(self, identity: TicketUseIdentity) -> UseRecordV2 | None:
        """Return the immutable record for an exact identity, if present."""

        with self._lock:
            use_key = self._check_identity_bindings(identity)
            return self._records.get(use_key)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)
