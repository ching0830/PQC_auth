"""Reference FGS grant construction after successful v0.2 pure checks.

The processor consumes only ``ValidatedAccessRequestV2`` and publishes no
response until ``commit_grant`` succeeds.  It deliberately remains a bounded,
process-local orchestration checkpoint: concrete cryptography, protected
response/session recovery, durable replay state, and a revocation/store atomic
transaction remain explicit backends.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, replace
from enum import Enum
from typing import Mapping, Protocol

from pq_sat_auth.identities import TicketUseIdentity

from .access import (
    DIGEST_BYTES,
    REFERENCE_PROOF_SUITE_REGISTRY,
    REFERENCE_SUITE_REGISTRY,
    SESSION_ID_BYTES,
    AccessAcceptV2,
    ChannelBindingMode,
    ProofLimitsV2,
    SuiteLimitsV2,
    decode_access_accept,
    derive_attempt_id,
    derive_request_core_digest,
    derive_request_digest,
    derive_response_digest,
    derive_transcript_digest,
    encode_access_accept,
    encode_access_request,
    validate_response_binding,
)
from .backends import (
    FGSAuthenticationBackendV2,
    KeyScheduleBackendV2,
    PQKEMBackendV2,
    SessionKeysV2,
)
from .processor import (
    AccessClockV2,
    AccessRevocationQueryV2,
    AccessRevocationSnapshotV2,
    AuthenticatedRevocationProviderV2,
    ChannelBindingPolicyV2,
    ValidatedAccessRequestV2,
)
from .proof import build_access_statement
from .replay import (
    GrantRecordV2,
    GrantStateV2,
    ReservationV2,
    ReserveDispositionV2,
    ReserveResultV2,
)


U64_MAX = (1 << 64) - 1
FGS_AUTH_LABEL = b"PQ-SAT/FGS-AUTH/v2"
KEY_SCHEDULE_CONTEXT_LABEL = b"PQ-SAT/KDF-CONTEXT/v2"
PRODUCTION_READY = False


def _u64(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value <= U64_MAX:
        raise ValueError(f"{name} does not fit uint64")
    return value


def _fixed(
    value: bytes,
    size: int,
    name: str,
    *,
    nonzero: bool = False,
) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    if nonzero and value == bytes(size):
        raise ValueError(f"{name} must not be all zero")
    return value


def _opaque(value: bytes, name: str) -> bytes:
    if not isinstance(value, bytes) or not value:
        raise ValueError(f"{name} must be non-empty bytes")
    return value


def _add_u64(left: int, right: int, name: str) -> int:
    first = _u64(left, f"{name} base")
    second = _u64(right, f"{name} delta")
    if first > U64_MAX - second:
        raise ValueError(f"{name} overflows uint64")
    return first + second


@dataclass(frozen=True)
class FGSAuthenticationKeyHandleV2:
    """Role-separated private handle paired with its configured public ID."""

    key_id: bytes
    private_handle: object

    def validate(self) -> None:
        _fixed(self.key_id, DIGEST_BYTES, "FGS authentication key ID", nonzero=True)
        if self.private_handle is None:
            raise TypeError("FGS authentication private handle is unavailable")


@dataclass(frozen=True)
class PendingSessionStateV2:
    """Secret material handed only to a protected session-state backend."""

    suite_id: int
    identity: TicketUseIdentity
    system_config_digest: bytes
    acceptance_domain_digest: bytes
    request_digest: bytes
    attempt_id: bytes
    transcript_digest: bytes
    response_digest: bytes
    session_id: bytes
    activation_deadline: int
    session_expiry: int
    client_finished_key: bytes
    application_key: bytes
    exporter_key: bytes

    def validate(self) -> None:
        if isinstance(self.suite_id, bool) or not isinstance(self.suite_id, int):
            raise TypeError("suite_id must be an integer")
        if not 0 <= self.suite_id < (1 << 16):
            raise ValueError("suite_id does not fit uint16")
        if not isinstance(self.identity, TicketUseIdentity):
            raise TypeError("identity must be a TicketUseIdentity")
        for name in (
            "system_config_digest",
            "acceptance_domain_digest",
            "request_digest",
            "attempt_id",
            "transcript_digest",
            "response_digest",
            "session_id",
        ):
            _fixed(getattr(self, name), DIGEST_BYTES, name)
        _u64(self.activation_deadline, "activation_deadline")
        _u64(self.session_expiry, "session_expiry")
        if self.activation_deadline > self.session_expiry:
            raise ValueError("activation deadline follows session expiry")
        for name in (
            "client_finished_key",
            "application_key",
            "exporter_key",
        ):
            _opaque(getattr(self, name), name)


class SessionIdentifierSourceV2(Protocol):
    """CSPRNG-backed source in a real deployment; deterministic only in tests."""

    def new_session_id(self) -> bytes: ...


class GrantRecoveryBackendV2(Protocol):
    """Protect exact response recovery and pending session secret state."""

    production_ready: bool

    def seal_response(
        self,
        response: bytes,
        *,
        response_digest: bytes,
    ) -> bytes: ...

    def recover_response(
        self,
        sealed_response: bytes,
        *,
        response_digest: bytes,
    ) -> bytes: ...

    def seal_session_state(self, state: PendingSessionStateV2) -> bytes: ...


class GrantReplayStoreV2(Protocol):
    """Minimum one-time state API required by the grant processor."""

    production_ready: bool
    durable: bool
    distributed: bool

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
    ) -> ReserveResultV2: ...

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
    ) -> GrantRecordV2: ...


class GrantDispositionV2(Enum):
    NEW_GRANT = "new_grant"
    EXISTING_GRANT = "existing_grant"
    EXISTING_RESERVATION = "existing_reservation"
    EXISTING_EXPIRED = "existing_expired"
    REJECTED = "rejected"
    RECOVERY_REQUIRED = "recovery_required"


@dataclass(frozen=True)
class GrantProcessResultV2:
    accepted: bool
    disposition: GrantDispositionV2
    failures: tuple[str, ...]
    response_bytes: bytes | None
    record: GrantRecordV2 | None
    reservation_held: bool


def encode_key_schedule_context(
    validated: ValidatedAccessRequestV2,
    *,
    session_id: bytes,
) -> bytes:
    """Freeze fixed-width suite and role context supplied to the KDF backend."""

    if not isinstance(validated, ValidatedAccessRequestV2):
        raise TypeError("validated must be ValidatedAccessRequestV2")
    request = validated.request
    configuration = validated.configuration
    _fixed(session_id, SESSION_ID_BYTES, "session_id", nonzero=True)
    return b"".join(
        (
            KEY_SCHEDULE_CONTEXT_LABEL,
            struct.pack(
                ">HHQH",
                configuration.access_protocol_version,
                request.suite_id,
                request.epoch,
                int(request.channel_binding_mode),
            ),
            configuration.system_config_digest,
            configuration.initialization_configuration_digest,
            configuration.access_profile_digest,
            configuration.access_pp_digest,
            configuration.acceptance_domain_digest,
            request.ctx,
            request.target_fgs_id,
            request.fgs_auth_key_id,
            request.serving_context_digest,
            request.authorization_digest,
            request.channel_binding_digest,
            validated.request_digest,
            validated.attempt_id,
            session_id,
        )
    )


def _authenticator_digest(authenticator: bytes) -> bytes:
    return hashlib.shake_256(_opaque(authenticator, "FGS authenticator")).digest(
        DIGEST_BYTES
    )


class FGSGrantProcessorV2:
    """Build and commit one exact M2 from a pure-check result.

    A returned response is publication-ready only in the narrow state-machine
    sense that the supplied store accepted ``CommitGrant`` first.  The class
    does not make the store durable or the cryptographic backends production
    qualified.
    """

    production_ready = False

    def __init__(
        self,
        *,
        replay_store: GrantReplayStoreV2,
        clock: AccessClockV2,
        revocation_provider: AuthenticatedRevocationProviderV2,
        kem_backend: PQKEMBackendV2,
        authentication_backend: FGSAuthenticationBackendV2,
        authentication_key: FGSAuthenticationKeyHandleV2,
        key_schedule_backend: KeyScheduleBackendV2,
        session_identifier_source: SessionIdentifierSourceV2,
        recovery_backend: GrantRecoveryBackendV2,
        suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
        proof_registry: Mapping[
            int, ProofLimitsV2
        ] = REFERENCE_PROOF_SUITE_REGISTRY,
    ) -> None:
        self._replay_store = replay_store
        self._clock = clock
        self._revocation_provider = revocation_provider
        self._kem_backend = kem_backend
        self._authentication_backend = authentication_backend
        self._authentication_key = authentication_key
        self._key_schedule_backend = key_schedule_backend
        self._session_identifier_source = session_identifier_source
        self._recovery_backend = recovery_backend
        self._suite_registry = suite_registry
        self._proof_registry = proof_registry

    @staticmethod
    def _reject(failure: str) -> GrantProcessResultV2:
        return GrantProcessResultV2(
            False,
            GrantDispositionV2.REJECTED,
            (failure,),
            None,
            None,
            False,
        )

    @staticmethod
    def _recovery_required(failure: str) -> GrantProcessResultV2:
        return GrantProcessResultV2(
            False,
            GrantDispositionV2.RECOVERY_REQUIRED,
            (failure,),
            None,
            None,
            True,
        )

    def _now(self, phase: str) -> int:
        value = self._clock.now()
        return _u64(value, f"{phase} time")

    def _validate_handoff(self, validated: ValidatedAccessRequestV2) -> None:
        if not isinstance(validated, ValidatedAccessRequestV2):
            raise TypeError("validated input has the wrong type")
        configuration = validated.configuration
        ticket = validated.ticket
        request = validated.request
        configuration.validate()
        ticket.validate()
        exact_bindings = (
            (request.system_config_digest, configuration.system_config_digest),
            (request.ctx, configuration.ctx),
            (request.epoch, configuration.epoch),
            (request.target_fgs_id, configuration.fgs_id),
            (request.fgs_auth_key_id, configuration.fgs_auth_key_id),
            (
                request.serving_context_digest,
                configuration.serving_context_digest,
            ),
            (request.authorization_digest, configuration.authorization_digest),
            (ticket.ctx, request.ctx),
            (
                ticket.system_config_digest,
                configuration.initialization_configuration_digest,
            ),
            (
                ticket.issuer_key_id,
                configuration.issuer_verification_key_id,
            ),
        )
        if any(actual != expected for actual, expected in exact_bindings):
            raise ValueError("validated configuration binding mismatch")
        if request.suite_id not in configuration.allowed_suite_ids:
            raise ValueError("validated access suite is not authorized")
        if request.proof_suite_id not in configuration.allowed_proof_suite_ids:
            raise ValueError("validated proof suite is not authorized")
        if (
            configuration.channel_binding_policy
            is ChannelBindingPolicyV2.NONE_ONLY
            and request.channel_binding_mode is not ChannelBindingMode.NONE
        ):
            raise ValueError("validated channel mode is not authorized")
        if (
            configuration.channel_binding_policy
            is ChannelBindingPolicyV2.REQUIRE_AUTHENTICATED_EXPORTER
            and request.channel_binding_mode
            is not ChannelBindingMode.AUTHENTICATED_EXPORTER
        ):
            raise ValueError("validated request lacks required channel binding")
        if encode_access_request(
            request,
            self._suite_registry,
            self._proof_registry,
        ) != validated.request_bytes:
            raise ValueError("validated request bytes mismatch")
        request_core_digest = derive_request_core_digest(
            request,
            self._suite_registry,
            self._proof_registry,
        )
        request_digest = derive_request_digest(
            request,
            self._suite_registry,
            self._proof_registry,
        )
        if request_core_digest != validated.request_core_digest:
            raise ValueError("validated request core digest mismatch")
        if request_digest != validated.request_digest:
            raise ValueError("validated request digest mismatch")
        identity = TicketUseIdentity(
            ctx=ticket.ctx,
            serial=ticket.visible_serial,
            ticket_digest=ticket.payload_digest,
        )
        if identity != validated.identity:
            raise ValueError("validated ticket-use identity mismatch")
        if derive_attempt_id(identity.use_key, request_digest) != validated.attempt_id:
            raise ValueError("validated attempt identifier mismatch")
        if build_access_statement(
            access_profile_digest=configuration.access_profile_digest,
            access_pp_digest=configuration.access_pp_digest,
            holder_hash=ticket.holder_hash,
            request=request,
        ) != validated.access_statement:
            raise ValueError("validated access statement mismatch")
        revocation_query = AccessRevocationQueryV2(
            system_config_digest=request.system_config_digest,
            initialization_configuration_digest=(
                configuration.initialization_configuration_digest
            ),
            acceptance_domain_digest=configuration.acceptance_domain_digest,
            ctx=ticket.ctx,
            epoch=request.epoch,
            fgs_id=request.target_fgs_id,
            fgs_auth_key_id=request.fgs_auth_key_id,
            issuer_key_id=ticket.issuer_key_id,
            payload_digest=ticket.payload_digest,
            visible_serial=ticket.visible_serial,
            holder_hash=ticket.holder_hash,
        )
        if revocation_query != validated.revocation_query:
            raise ValueError("validated revocation query mismatch")
        if validated.revocation_generation < configuration.minimum_revocation_generation:
            raise ValueError("validated revocation generation is stale")
        _u64(validated.checked_at, "pure-check time")

    @staticmethod
    def _check_current_time(
        validated: ValidatedAccessRequestV2,
        now: int,
        *,
        enforce_handoff_age: bool,
    ) -> None:
        configuration = validated.configuration
        ticket = validated.ticket
        if now < validated.checked_at:
            raise ValueError("trusted clock moved before pure-check time")
        if (
            enforce_handoff_age
            and now - validated.checked_at
            > configuration.pure_check_max_age_seconds
        ):
            raise ValueError("pure-check result is stale")
        if not configuration.valid_from <= now < configuration.valid_until:
            raise ValueError("access configuration is inactive")
        if now >= ticket.expires_at:
            raise ValueError("ticket expired before grant commit")

    @staticmethod
    def _validate_backend_suites(
        validated: ValidatedAccessRequestV2,
        kem_backend: PQKEMBackendV2,
        authentication_backend: FGSAuthenticationBackendV2,
        key_schedule_backend: KeyScheduleBackendV2,
        authentication_key: FGSAuthenticationKeyHandleV2,
    ) -> None:
        suite_id = validated.request.suite_id
        for name, backend in (
            ("KEM", kem_backend),
            ("FGS authentication", authentication_backend),
            ("key schedule", key_schedule_backend),
        ):
            if getattr(backend, "suite_id", None) != suite_id:
                raise ValueError(f"{name} backend suite mismatch")
        authentication_key.validate()
        if authentication_key.key_id != validated.request.fgs_auth_key_id:
            raise ValueError("FGS authentication key handle mismatch")

    def _recover_existing(
        self,
        validated: ValidatedAccessRequestV2,
        record: GrantRecordV2,
    ) -> GrantProcessResultV2:
        if record.state is GrantStateV2.CONSUMED_EXPIRED:
            return GrantProcessResultV2(
                False,
                GrantDispositionV2.EXISTING_EXPIRED,
                ("grant_expired",),
                None,
                record,
                False,
            )
        expected = (
            validated.identity,
            validated.attempt_id,
            validated.request_digest,
            validated.request.serving_context_digest,
            validated.request.target_fgs_id,
        )
        actual = (
            record.identity,
            record.attempt_id,
            record.request_digest,
            record.serving_context_digest,
            record.fgs_id,
        )
        if actual != expected:
            return self._reject("stored_grant_binding_mismatch")
        try:
            response_bytes = self._recovery_backend.recover_response(
                record.sealed_response,
                response_digest=record.response_digest,
            )
            _opaque(response_bytes, "recovered response")
            response = decode_access_accept(response_bytes, self._suite_registry)
            if encode_access_accept(response, self._suite_registry) != response_bytes:
                raise ValueError("recovered response is non-canonical")
            validate_response_binding(
                validated.request,
                response,
                use_key=validated.identity.use_key,
                suite_registry=self._suite_registry,
                proof_registry=self._proof_registry,
            )
            if derive_response_digest(response, self._suite_registry) != record.response_digest:
                raise ValueError("recovered response digest mismatch")
            if (
                derive_transcript_digest(response, self._suite_registry)
                != record.transcript_digest
            ):
                raise ValueError("recovered transcript digest mismatch")
            if (
                response.session_id,
                response.activation_deadline,
                response.session_expiry,
            ) != (
                record.session_id,
                record.activation_deadline,
                record.session_expiry,
            ):
                raise ValueError("recovered response state mismatch")
        except Exception as error:
            return self._reject(f"response_recovery:{type(error).__name__}")
        return GrantProcessResultV2(
            True,
            GrantDispositionV2.EXISTING_GRANT,
            (),
            response_bytes,
            record,
            False,
        )

    def process(
        self,
        validated: ValidatedAccessRequestV2,
    ) -> GrantProcessResultV2:
        """Reserve, construct, seal, and commit one exact AccessAcceptV2."""

        try:
            self._validate_handoff(validated)
            reserve_now = self._now("reserve")
            self._check_current_time(
                validated,
                reserve_now,
                enforce_handoff_age=True,
            )
            lease_deadline = min(
                _add_u64(
                    reserve_now,
                    validated.configuration.reservation_lease_seconds,
                    "reservation lease",
                ),
                validated.configuration.valid_until,
                validated.ticket.expires_at,
            )
            if lease_deadline <= reserve_now:
                raise ValueError("no live reservation interval remains")
        except Exception as error:
            return self._reject(f"validated_handoff:{type(error).__name__}")

        try:
            reservation = self._replay_store.reserve(
                validated.identity,
                attempt_id=validated.attempt_id,
                request_digest=validated.request_digest,
                serving_context_digest=(
                    validated.request.serving_context_digest
                ),
                reserved_at=reserve_now,
                lease_deadline=lease_deadline,
                revocation_generation=validated.revocation_generation,
            )
        except Exception as error:
            return self._reject(f"reserve_backend:{type(error).__name__}")
        if not isinstance(reservation, ReserveResultV2):
            return self._reject("reserve_backend_output")
        if reservation.disposition is ReserveDispositionV2.EXISTING_GRANT:
            if not isinstance(reservation.record, GrantRecordV2):
                return self._reject("stored_grant_type_mismatch")
            return self._recover_existing(validated, reservation.record)
        if reservation.disposition is ReserveDispositionV2.EXISTING_RESERVATION:
            if not isinstance(reservation.record, ReservationV2):
                return self._reject("stored_reservation_type_mismatch")
            expected = (
                validated.identity,
                validated.attempt_id,
                validated.request_digest,
                validated.request.serving_context_digest,
            )
            actual = (
                reservation.record.identity,
                reservation.record.attempt_id,
                reservation.record.request_digest,
                reservation.record.serving_context_digest,
            )
            if actual != expected:
                return self._reject("stored_reservation_binding_mismatch")
            return GrantProcessResultV2(
                False,
                GrantDispositionV2.EXISTING_RESERVATION,
                ("same_attempt_in_progress",),
                None,
                None,
                True,
            )
        if reservation.disposition is not ReserveDispositionV2.NEW:
            return self._recovery_required("unknown_reservation_disposition")
        if not isinstance(reservation.record, ReservationV2):
            return self._recovery_required("new_reservation_type_mismatch")
        expected_new = (
            validated.identity,
            validated.attempt_id,
            validated.request_digest,
            validated.request.serving_context_digest,
            reserve_now,
            lease_deadline,
            validated.revocation_generation,
        )
        actual_new = (
            reservation.record.identity,
            reservation.record.attempt_id,
            reservation.record.request_digest,
            reservation.record.serving_context_digest,
            reservation.record.reserved_at,
            reservation.record.lease_deadline,
            reservation.record.revocation_generation,
        )
        if actual_new != expected_new:
            return self._recovery_required("new_reservation_binding_mismatch")

        try:
            self._validate_backend_suites(
                validated,
                self._kem_backend,
                self._authentication_backend,
                self._key_schedule_backend,
                self._authentication_key,
            )
            encapsulation = self._kem_backend.encapsulate(
                validated.request.ue_kem_epk
            )
            if not isinstance(encapsulation, tuple) or len(encapsulation) != 2:
                raise TypeError("KEM encapsulation output must be a pair")
            kem_ciphertext, shared_secret = encapsulation
            _opaque(kem_ciphertext, "KEM ciphertext")
            _opaque(shared_secret, "KEM shared secret")
            session_id = self._session_identifier_source.new_session_id()
            _fixed(session_id, SESSION_ID_BYTES, "session_id", nonzero=True)

            build_now = self._now("grant build")
            self._check_current_time(
                validated,
                build_now,
                enforce_handoff_age=False,
            )
            if build_now > lease_deadline:
                raise ValueError("reservation lease expired during grant build")
            session_expiry = min(
                _add_u64(
                    build_now,
                    validated.configuration.session_lifetime_seconds,
                    "session lifetime",
                ),
                validated.configuration.valid_until,
                validated.ticket.expires_at,
            )
            activation_deadline = min(
                _add_u64(
                    build_now,
                    validated.configuration.activation_window_seconds,
                    "activation window",
                ),
                session_expiry,
            )
            if activation_deadline <= build_now:
                raise ValueError("no activation interval remains")

            response_core = AccessAcceptV2(
                suite_id=validated.request.suite_id,
                system_config_digest=validated.request.system_config_digest,
                ctx=validated.request.ctx,
                epoch=validated.request.epoch,
                fgs_id=validated.request.target_fgs_id,
                fgs_auth_key_id=validated.request.fgs_auth_key_id,
                request_digest=validated.request_digest,
                attempt_id=validated.attempt_id,
                session_id=session_id,
                serving_context_digest=(
                    validated.request.serving_context_digest
                ),
                session_expiry=session_expiry,
                activation_deadline=activation_deadline,
                kem_ciphertext_to_ue=kem_ciphertext,
                fgs_authenticator=b"\x00",
                server_key_confirmation=b"\x00",
            )
            transcript_digest = derive_transcript_digest(
                response_core,
                self._suite_registry,
            )
            schedule_context = encode_key_schedule_context(
                validated,
                session_id=session_id,
            )
            session_keys = self._key_schedule_backend.derive_session_keys(
                shared_secret,
                transcript_digest,
                schedule_context,
            )
            if not isinstance(session_keys, SessionKeysV2):
                raise TypeError("key schedule returned the wrong type")
            authenticator = self._authentication_backend.authenticate(
                self._authentication_key.private_handle,
                FGS_AUTH_LABEL + transcript_digest,
            )
            _opaque(authenticator, "FGS authenticator")
            server_finished = self._key_schedule_backend.server_finished(
                session_keys.server_finished_key,
                transcript_digest,
                _authenticator_digest(authenticator),
            )
            _opaque(server_finished, "server key confirmation")
            response = replace(
                response_core,
                fgs_authenticator=authenticator,
                server_key_confirmation=server_finished,
            )
            response_bytes = encode_access_accept(
                response,
                self._suite_registry,
            )
            response_digest = derive_response_digest(
                response,
                self._suite_registry,
            )

            commit_now = self._now("pre-commit")
            self._check_current_time(
                validated,
                commit_now,
                enforce_handoff_age=False,
            )
            if commit_now > lease_deadline:
                raise ValueError("reservation lease expired before commit")
            if commit_now >= activation_deadline:
                raise ValueError("activation deadline reached before commit")

            revocation = self._revocation_provider.snapshot(
                validated.revocation_query
            )
            if not isinstance(revocation, AccessRevocationSnapshotV2):
                raise TypeError("revocation provider returned the wrong type")
            revocation.validate()
            if revocation.query_digest != validated.revocation_query.digest:
                raise ValueError("pre-commit revocation query mismatch")
            if revocation.generation < max(
                validated.revocation_generation,
                validated.configuration.minimum_revocation_generation,
            ):
                raise ValueError("pre-commit revocation generation is stale")
            if not revocation.effective_at <= commit_now < revocation.valid_until:
                raise ValueError("pre-commit revocation snapshot is inactive")
            if revocation.revoked:
                raise ValueError("access was revoked before commit")

            retention_deadline = _add_u64(
                _add_u64(
                    max(validated.ticket.expires_at, session_expiry),
                    validated.configuration.maximum_clock_skew_seconds,
                    "retention clock skew",
                ),
                validated.configuration.replay_retention_grace_seconds,
                "retention grace",
            )
            pending_state = PendingSessionStateV2(
                suite_id=validated.request.suite_id,
                identity=validated.identity,
                system_config_digest=validated.request.system_config_digest,
                acceptance_domain_digest=(
                    validated.configuration.acceptance_domain_digest
                ),
                request_digest=validated.request_digest,
                attempt_id=validated.attempt_id,
                transcript_digest=transcript_digest,
                response_digest=response_digest,
                session_id=session_id,
                activation_deadline=activation_deadline,
                session_expiry=session_expiry,
                client_finished_key=session_keys.client_finished_key,
                application_key=session_keys.application_key,
                exporter_key=session_keys.exporter_key,
            )
            pending_state.validate()
            sealed_response = self._recovery_backend.seal_response(
                response_bytes,
                response_digest=response_digest,
            )
            sealed_session_state = self._recovery_backend.seal_session_state(
                pending_state
            )
            _opaque(sealed_response, "sealed response")
            _opaque(sealed_session_state, "sealed session state")
        except Exception as error:
            return self._recovery_required(f"grant_build:{type(error).__name__}")

        try:
            record = self._replay_store.commit_grant(
                validated.identity,
                attempt_id=validated.attempt_id,
                request_digest=validated.request_digest,
                transcript_digest=transcript_digest,
                session_id=session_id,
                response_digest=response_digest,
                sealed_response=sealed_response,
                sealed_session_state=sealed_session_state,
                serving_context_digest=(
                    validated.request.serving_context_digest
                ),
                fgs_id=validated.request.target_fgs_id,
                revocation_generation=revocation.generation,
                consumed_at=commit_now,
                activation_deadline=activation_deadline,
                session_expiry=session_expiry,
                retention_deadline=retention_deadline,
            )
            if not isinstance(record, GrantRecordV2):
                raise TypeError("commit backend returned the wrong type")
            expected = (
                validated.identity,
                validated.attempt_id,
                validated.request_digest,
                transcript_digest,
                session_id,
                response_digest,
                sealed_response,
                sealed_session_state,
                validated.request.serving_context_digest,
                validated.request.target_fgs_id,
                revocation.generation,
                commit_now,
                activation_deadline,
                session_expiry,
                retention_deadline,
            )
            actual = (
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
            if actual != expected:
                raise ValueError("commit backend changed the grant identity")
        except Exception as error:
            return self._recovery_required(f"commit_backend:{type(error).__name__}")

        return GrantProcessResultV2(
            True,
            GrantDispositionV2.NEW_GRANT,
            (),
            response_bytes,
            record,
            False,
        )


def fgs_grant_processor_manifest() -> dict[str, object]:
    """Return path-free machine metadata for this bounded checkpoint."""

    return {
        "format": "PQ-SAT-FGS-GRANT-PROCESSOR-v0.2",
        "access_protocol_version": 2,
        "processing_order": [
            "validated_handoff_recheck",
            "reserve",
            "exact_existing_grant_recovery_or_pending",
            "kem_encapsulation_and_session_id",
            "response_core_and_transcript",
            "key_schedule_fgs_authentication_server_finished",
            "pre_commit_revocation_recheck",
            "response_and_session_state_protection",
            "commit_grant",
            "return_response_after_commit",
        ],
        "claim_boundary": {
            "pure_check_output_integrated": True,
            "reserve_before_expensive_grant_construction": True,
            "same_attempt_retry_avoids_second_kem": True,
            "pre_commit_revocation_recheck_implemented": True,
            "response_returned_only_after_commit": True,
            "session_activation_implemented": False,
            "atomic_revocation_and_commit_implemented": False,
            "durable_or_distributed_store_implemented": False,
            "production_response_protection_instantiated": False,
            "production_session_state_protection_instantiated": False,
            "production_pq_ake_instantiated": False,
            "production_ready": False,
            "proof_closed": False,
        },
    }
