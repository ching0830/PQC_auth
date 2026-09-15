"""Process-local reference state machine for one-time access v0.2.

The lock makes transitions linearizable only inside one Python process.  The
model is not durable or distributed and therefore is never a production FGS
replay backend.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
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
U64_MAX = (1 << 64) - 1
RESERVATION_ABORT_NO_GRANT_LABEL = (
    b"PQ-SAT/RESERVATION-ABORT/NO-GRANT/v0.2\x00"
)
RESERVATION_ABORT_NO_PUBLICATION_LABEL = (
    b"PQ-SAT/RESERVATION-ABORT/NO-PUBLICATION-BEFORE-COMMIT/v0.2\x00"
)
RESERVATION_ABORT_FENCING_LABEL = (
    b"PQ-SAT/RESERVATION-ABORT/FENCING/v0.2\x00"
)
RESERVATION_ABORT_EVIDENCE_LABEL = (
    b"PQ-SAT/RESERVATION-ABORT/EVIDENCE/v0.2\x00"
)


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


def _uint64(value: int, name: str) -> int:
    canonical = _timestamp(value, name)
    if canonical > U64_MAX:
        raise ValueError(f"{name} does not fit uint64")
    return canonical


class ReserveDispositionV2(Enum):
    NEW = "new"
    EXISTING_RESERVATION = "existing_reservation"
    EXISTING_GRANT = "existing_grant"


class GrantStateV2(Enum):
    CONSUMED_PENDING_CONFIRM = "consumed_pending_confirm"
    CONSUMED_ACTIVE = "consumed_active"
    CONSUMED_EXPIRED = "consumed_expired"


class ActivateDispositionV2(Enum):
    NEW = "new"
    EXISTING_ACTIVE = "existing_active"


@dataclass(frozen=True)
class ReservationV2:
    identity: TicketUseIdentity
    attempt_id: bytes
    request_digest: bytes
    serving_context_digest: bytes
    reserved_at: int
    lease_deadline: int
    revocation_generation: int
    fencing_generation: int

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
        _uint64(self.fencing_generation, "fencing_generation")
        if self.fencing_generation == 0:
            raise ValueError("fencing_generation must be positive")
        if self.lease_deadline <= self.reserved_at:
            raise ValueError("lease_deadline must follow reserved_at")


@dataclass(frozen=True)
class FencedReservationV2(ReservationV2):
    """Internal tombstone that prevents stale-worker ABA commits."""

    fenced_at: int
    abort_evidence_digest: bytes

    def __post_init__(self) -> None:
        super().__post_init__()
        _timestamp(self.fenced_at, "fenced_at")
        if self.fenced_at <= self.lease_deadline:
            raise ValueError("fenced_at must follow lease_deadline")
        _fixed_bytes(
            self.abort_evidence_digest,
            DIGEST_BYTES,
            "abort_evidence_digest",
        )


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
    """Canonical bounded evidence for an expired reservation observation."""

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


def _reservation_abort_payload(
    reservation: ReservationV2,
    observed_at: int,
) -> bytes:
    if not isinstance(reservation, ReservationV2) or isinstance(
        reservation,
        FencedReservationV2,
    ):
        raise TypeError("reservation must be an active ReservationV2")
    canonical_time = _uint64(observed_at, "abort observed_at")
    return b"".join(
        (
            reservation.identity.use_key,
            reservation.identity.ctx,
            reservation.identity.serial,
            reservation.identity.ticket_digest,
            reservation.attempt_id,
            reservation.request_digest,
            reservation.serving_context_digest,
            struct.pack(
                ">QQQQ",
                _uint64(reservation.reserved_at, "reserved_at"),
                _uint64(reservation.lease_deadline, "lease_deadline"),
                _uint64(
                    reservation.revocation_generation,
                    "revocation_generation",
                ),
                reservation.fencing_generation,
            ),
            struct.pack(">Q", canonical_time),
        )
    )


def derive_reservation_abort_evidence_v2(
    reservation: ReservationV2,
    observed_at: int,
) -> ReservationAbortEvidenceV2:
    """Bind recovery evidence to one exact expired reservation observation."""

    payload = _reservation_abort_payload(reservation, observed_at)
    return ReservationAbortEvidenceV2(
        hashlib.shake_256(
            RESERVATION_ABORT_NO_GRANT_LABEL + payload
        ).digest(DIGEST_BYTES),
        hashlib.shake_256(
            RESERVATION_ABORT_NO_PUBLICATION_LABEL + payload
        ).digest(DIGEST_BYTES),
        hashlib.shake_256(
            RESERVATION_ABORT_FENCING_LABEL + payload
        ).digest(DIGEST_BYTES),
    )


def reservation_abort_evidence_digest_v2(
    evidence: ReservationAbortEvidenceV2,
) -> bytes:
    if not isinstance(evidence, ReservationAbortEvidenceV2):
        raise TypeError("evidence must be ReservationAbortEvidenceV2")
    return hashlib.shake_256(
        RESERVATION_ABORT_EVIDENCE_LABEL
        + evidence.no_grant_digest
        + evidence.no_publication_digest
        + evidence.fencing_digest
    ).digest(DIGEST_BYTES)


def _verify_reservation_abort_evidence(
    reservation: ReservationV2,
    observed_at: int,
    evidence: ReservationAbortEvidenceV2,
) -> None:
    expected = derive_reservation_abort_evidence_v2(reservation, observed_at)
    comparisons = (
        (evidence.no_grant_digest, expected.no_grant_digest),
        (evidence.no_publication_digest, expected.no_publication_digest),
        (evidence.fencing_digest, expected.fencing_digest),
    )
    if not all(
        hmac.compare_digest(actual, wanted)
        for actual, wanted in comparisons
    ):
        raise InvalidTransition("reservation abort evidence mismatch")


UseRecordV2 = ReservationV2 | FencedReservationV2 | GrantRecordV2


@dataclass(frozen=True)
class ReserveResultV2:
    disposition: ReserveDispositionV2
    record: UseRecordV2


@dataclass(frozen=True)
class ActivateResultV2:
    disposition: ActivateDispositionV2
    record: GrantRecordV2


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
        self._session_index: dict[bytes, bytes] = {}

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
            fencing_generation=1,
        )
        with self._lock:
            use_key = self._check_identity_bindings(identity)
            existing = self._records.get(use_key)
            if existing is None:
                self._bind_identity(identity, use_key)
                self._records[use_key] = candidate
                return ReserveResultV2(ReserveDispositionV2.NEW, candidate)
            if isinstance(existing, FencedReservationV2):
                if existing.fencing_generation >= U64_MAX:
                    raise InvalidTransition(
                        "reservation fencing generation exhausted"
                    )
                candidate = replace(
                    candidate,
                    fencing_generation=existing.fencing_generation + 1,
                )
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
        fencing_generation: int,
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
        canonical_fencing_generation = _uint64(
            fencing_generation,
            "fencing_generation",
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
            if isinstance(existing, FencedReservationV2):
                raise ReservationNotFound("reservation worker has been fenced")
            session_binding = self._session_index.get(candidate.session_id)
            if session_binding is not None and session_binding != use_key:
                raise IdentityConflict("session ID belongs to another ticket")
            if (
                existing.attempt_id != candidate.attempt_id
                or existing.request_digest != candidate.request_digest
                or existing.fencing_generation != canonical_fencing_generation
                or existing.serving_context_digest
                != candidate.serving_context_digest
                or existing.revocation_generation
                > candidate.revocation_generation
            ):
                raise ReservationNotFound("reservation belongs to another request")
            if candidate.consumed_at < existing.reserved_at:
                raise InvalidTransition("grant predates reservation")
            if candidate.consumed_at > existing.lease_deadline:
                raise InvalidTransition("reservation lease expired before commit")
            self._records[use_key] = candidate
            self._session_index[candidate.session_id] = use_key
            return candidate

    def activate_session(
        self,
        identity: TicketUseIdentity,
        *,
        attempt_id: bytes,
        request_digest: bytes,
        session_id: bytes,
        response_digest: bytes,
        client_confirmation_digest: bytes,
        activated_at: int,
    ) -> ActivateResultV2:
        """Atomically activate and report whether this call won the transition."""

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
                return ActivateResultV2(
                    ActivateDispositionV2.EXISTING_ACTIVE,
                    existing,
                )
            if canonical_time > existing.activation_deadline:
                raise InvalidTransition("activation deadline has passed")
            active = replace(
                existing,
                state=GrantStateV2.CONSUMED_ACTIVE,
                client_confirmation_digest=canonical_confirmation,
                activated_at=canonical_time,
            )
            self._records[use_key] = active
            return ActivateResultV2(ActivateDispositionV2.NEW, active)

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
        """Backward-compatible record-only activation API."""

        return self.activate_session(
            identity,
            attempt_id=attempt_id,
            request_digest=request_digest,
            session_id=session_id,
            response_digest=response_digest,
            client_confirmation_digest=client_confirmation_digest,
            activated_at=activated_at,
        ).record

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
        fencing_generation: int,
        attempt_id: bytes,
        request_digest: bytes,
        observed_at: int,
        evidence: ReservationAbortEvidenceV2,
    ) -> FencedReservationV2:
        """Fence and release one exact expired reservation.

        The evidence binds one store observation; publication absence additionally
        relies on all M2 release passing through the commit-before-return processor.
        """

        canonical_attempt = _fixed_bytes(attempt_id, DIGEST_BYTES, "attempt_id")
        canonical_request = _fixed_bytes(
            request_digest,
            DIGEST_BYTES,
            "request_digest",
        )
        canonical_fencing_generation = _uint64(
            fencing_generation,
            "fencing_generation",
        )
        canonical_time = _uint64(observed_at, "abort observed_at")
        if not isinstance(evidence, ReservationAbortEvidenceV2):
            raise TypeError("evidence must be ReservationAbortEvidenceV2")
        with self._lock:
            use_key = self._check_identity_bindings(identity)
            existing = self._records.get(use_key)
            if existing is None:
                raise ReservationNotFound("cannot abort an unreserved ticket")
            if isinstance(existing, GrantRecordV2):
                raise InvalidTransition("consumed ticket cannot be released")
            if isinstance(existing, FencedReservationV2):
                raise ReservationNotFound("reservation is already fenced")
            if (
                existing.attempt_id != canonical_attempt
                or existing.request_digest != canonical_request
                or existing.fencing_generation != canonical_fencing_generation
            ):
                raise ReservationNotFound("reservation belongs to another request")
            if canonical_time <= existing.lease_deadline:
                raise InvalidTransition("reservation lease has not expired")
            _verify_reservation_abort_evidence(
                existing,
                canonical_time,
                evidence,
            )
            if existing.fencing_generation >= U64_MAX:
                raise InvalidTransition("reservation fencing generation exhausted")
            fenced = FencedReservationV2(
                identity=existing.identity,
                attempt_id=existing.attempt_id,
                request_digest=existing.request_digest,
                serving_context_digest=existing.serving_context_digest,
                reserved_at=existing.reserved_at,
                lease_deadline=existing.lease_deadline,
                revocation_generation=existing.revocation_generation,
                fencing_generation=existing.fencing_generation + 1,
                fenced_at=canonical_time,
                abort_evidence_digest=reservation_abort_evidence_digest_v2(
                    evidence
                ),
            )
            self._records[use_key] = fenced
            return fenced

    def lookup(self, identity: TicketUseIdentity) -> UseRecordV2 | None:
        """Return the immutable record for an exact identity, if present."""

        with self._lock:
            use_key = self._check_identity_bindings(identity)
            record = self._records.get(use_key)
            return None if isinstance(record, FencedReservationV2) else record

    def lookup_reservation_fence(
        self,
        identity: TicketUseIdentity,
    ) -> FencedReservationV2 | None:
        """Return the internal recovery tombstone for audit/restart tests."""

        with self._lock:
            use_key = self._check_identity_bindings(identity)
            record = self._records.get(use_key)
            return record if isinstance(record, FencedReservationV2) else None

    def expired_reservations(
        self,
        *,
        observed_at: int,
        limit: int = 1_000,
    ) -> tuple[ReservationV2, ...]:
        """List a bounded snapshot of expired active reservations."""

        canonical_time = _uint64(observed_at, "scan observed_at")
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("reservation scan limit must be an integer")
        if not 1 <= limit <= 10_000:
            raise ValueError("reservation scan limit is outside bounds")
        with self._lock:
            candidates = tuple(
                record
                for _, record in sorted(self._records.items())
                if isinstance(record, ReservationV2)
                and not isinstance(record, FencedReservationV2)
                and record.lease_deadline < canonical_time
            )
            return candidates[:limit]

    def lookup_session(self, session_id: bytes) -> GrantRecordV2 | None:
        """Return the immutable committed record for an exact session ID."""

        canonical_session = _fixed_bytes(
            session_id,
            SESSION_ID_BYTES,
            "session_id",
        )
        with self._lock:
            use_key = self._session_index.get(canonical_session)
            if use_key is None:
                return None
            record = self._records.get(use_key)
            if not isinstance(record, GrantRecordV2):
                raise InvalidTransition("session index has no committed grant")
            if record.session_id != canonical_session:
                raise IdentityConflict("session index binding mismatch")
            return record

    def __len__(self) -> int:
        with self._lock:
            return sum(
                not isinstance(record, FencedReservationV2)
                for record in self._records.values()
            )
