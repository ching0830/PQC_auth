"""Fail-closed UE processing of an AccessAcceptV2 response."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Protocol

from pq_rbbc.contracts.system import KeyRole
from pq_rbbc.tickets.verification import CanonicalTicket
from pq_sat_auth.identities import TicketUseIdentity

from .access import (
    DIGEST_BYTES,
    REFERENCE_PROOF_SUITE_REGISTRY,
    REFERENCE_SUITE_REGISTRY,
    SESSION_ID_BYTES,
    AccessAcceptV2,
    AccessRequestV2,
    ChannelBindingMode,
    ProofLimitsV2,
    SessionActivateV2,
    SuiteLimitsV2,
    decode_access_accept,
    decode_access_request,
    derive_attempt_id,
    derive_request_digest,
    derive_response_digest,
    derive_transcript_digest,
    encode_access_accept,
    encode_access_request,
    encode_session_activate,
    validate_response_binding,
)
from .backends import (
    FGSAuthenticationBackendV2,
    KeyScheduleBackendV2,
    PQKEMBackendV2,
    SessionKeysV2,
)
from .grant import (
    FGS_AUTH_LABEL,
    derive_fgs_authenticator_digest,
    encode_key_schedule_context_fields,
)
from .processor import (
    AccessClockV2,
    AccessConfigurationSnapshotV2,
    AuthenticatedAccessConfigurationProviderV2,
    ChannelBindingPolicyV2,
)


U64_MAX = (1 << 64) - 1
FGS_KEY_QUERY_LABEL = b"PQ-SAT/UE-FGS-KEY-QUERY/v2"
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
    base = _u64(left, f"{name} base")
    delta = _u64(right, f"{name} delta")
    if base > U64_MAX - delta:
        raise ValueError(f"{name} overflows uint64")
    return base + delta


@dataclass(frozen=True)
class UEAccessAttemptStateV2:
    """Protected wallet input retained before transmitting exact M1 bytes."""

    request_bytes: bytes
    configuration: AccessConfigurationSnapshotV2
    request_digest: bytes
    attempt_id: bytes
    ticket_expires_at: int
    created_at: int
    ue_kem_secret_key: bytes

    def validate(self) -> None:
        _opaque(self.request_bytes, "request_bytes")
        if not isinstance(self.configuration, AccessConfigurationSnapshotV2):
            raise TypeError("configuration has the wrong type")
        self.configuration.validate()
        _fixed(self.request_digest, DIGEST_BYTES, "request_digest")
        _fixed(self.attempt_id, DIGEST_BYTES, "attempt_id")
        _u64(self.ticket_expires_at, "ticket_expires_at")
        _u64(self.created_at, "created_at")
        if self.created_at >= self.ticket_expires_at:
            raise ValueError("wallet attempt was created after ticket expiry")
        if not (
            self.configuration.valid_from
            <= self.created_at
            < self.configuration.valid_until
        ):
            raise ValueError("wallet attempt was created outside configuration")
        _opaque(self.ue_kem_secret_key, "UE KEM secret key")


@dataclass(frozen=True)
class FGSVerificationKeyQueryV2:
    suite_id: int
    system_config_digest: bytes
    acceptance_domain_digest: bytes
    epoch: int
    fgs_id: bytes
    fgs_auth_key_id: bytes

    def encode(self) -> bytes:
        if isinstance(self.suite_id, bool) or not isinstance(self.suite_id, int):
            raise TypeError("suite_id must be an integer")
        if not 0 <= self.suite_id < (1 << 16):
            raise ValueError("suite_id does not fit uint16")
        _u64(self.epoch, "epoch")
        for name in (
            "system_config_digest",
            "acceptance_domain_digest",
            "fgs_id",
            "fgs_auth_key_id",
        ):
            _fixed(getattr(self, name), DIGEST_BYTES, name, nonzero=True)
        return b"".join(
            (
                struct.pack(">HQ", self.suite_id, self.epoch),
                self.system_config_digest,
                self.acceptance_domain_digest,
                self.fgs_id,
                self.fgs_auth_key_id,
            )
        )

    @property
    def digest(self) -> bytes:
        return hashlib.shake_256(
            FGS_KEY_QUERY_LABEL + self.encode()
        ).digest(DIGEST_BYTES)


@dataclass(frozen=True)
class FGSVerificationKeySnapshotV2:
    """Query-bound output of the UE's authenticated FGS key provider."""

    query_digest: bytes
    valid_from: int
    valid_until: int
    revoked: bool
    verification_key: object

    def validate(self) -> None:
        _fixed(self.query_digest, DIGEST_BYTES, "FGS key query digest")
        _u64(self.valid_from, "FGS key valid_from")
        _u64(self.valid_until, "FGS key valid_until")
        if self.valid_from >= self.valid_until:
            raise ValueError("FGS key validity interval is empty")
        if type(self.revoked) is not bool:
            raise TypeError("FGS key revoked flag must be bool")
        if self.verification_key is None:
            raise TypeError("FGS verification key is unavailable")


class AuthenticatedFGSVerificationKeyProviderV2(Protocol):
    def resolve(
        self,
        query: FGSVerificationKeyQueryV2,
    ) -> FGSVerificationKeySnapshotV2 | None: ...


@dataclass(frozen=True)
class UEAcceptedSessionV2:
    """UE-local session material released only after authentic M2 Finished."""

    suite_id: int
    identity: TicketUseIdentity
    system_config_digest: bytes
    acceptance_domain_digest: bytes
    request_digest: bytes
    attempt_id: bytes
    transcript_digest: bytes
    response_digest: bytes
    session_id: bytes
    accepted_at: int
    activation_deadline: int
    session_expiry: int
    activation: SessionActivateV2
    activation_bytes: bytes
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
        ):
            _fixed(getattr(self, name), DIGEST_BYTES, name)
        _fixed(self.session_id, SESSION_ID_BYTES, "session_id", nonzero=True)
        _u64(self.accepted_at, "accepted_at")
        _u64(self.activation_deadline, "activation_deadline")
        _u64(self.session_expiry, "session_expiry")
        if self.accepted_at > self.activation_deadline:
            raise ValueError("UE acceptance follows activation deadline")
        if self.activation_deadline > self.session_expiry:
            raise ValueError("activation deadline follows session expiry")
        if not isinstance(self.activation, SessionActivateV2):
            raise TypeError("activation has the wrong type")
        _opaque(self.activation_bytes, "activation_bytes")
        activation_bindings = (
            (self.activation.suite_id, self.suite_id),
            (self.activation.request_digest, self.request_digest),
            (self.activation.attempt_id, self.attempt_id),
            (self.activation.session_id, self.session_id),
            (self.activation.response_digest, self.response_digest),
        )
        if any(actual != expected for actual, expected in activation_bindings):
            raise ValueError("activation and accepted session differ")
        for name in ("application_key", "exporter_key"):
            _opaque(getattr(self, name), name)


class UEResponseDispositionV2(Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"


@dataclass(frozen=True)
class UEResponseProcessResultV2:
    accepted: bool
    disposition: UEResponseDispositionV2
    failures: tuple[str, ...]
    response: AccessAcceptV2 | None
    session: UEAcceptedSessionV2 | None


class UEAccessAcceptProcessorV2:
    """Authenticate M2, derive the UE session, and construct client Finished."""

    production_ready = False

    def __init__(
        self,
        *,
        configuration_provider: AuthenticatedAccessConfigurationProviderV2,
        fgs_key_provider: AuthenticatedFGSVerificationKeyProviderV2,
        clock: AccessClockV2,
        kem_backend: PQKEMBackendV2,
        authentication_backend: FGSAuthenticationBackendV2,
        key_schedule_backend: KeyScheduleBackendV2,
        suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
        proof_registry: Mapping[
            int, ProofLimitsV2
        ] = REFERENCE_PROOF_SUITE_REGISTRY,
    ) -> None:
        self._configuration_provider = configuration_provider
        self._fgs_key_provider = fgs_key_provider
        self._clock = clock
        self._kem_backend = kem_backend
        self._authentication_backend = authentication_backend
        self._key_schedule_backend = key_schedule_backend
        self._suite_registry = suite_registry
        self._proof_registry = proof_registry

    @staticmethod
    def _reject(failure: str) -> UEResponseProcessResultV2:
        return UEResponseProcessResultV2(
            False,
            UEResponseDispositionV2.REJECTED,
            (failure,),
            None,
            None,
        )

    def _load_attempt(
        self,
        state: UEAccessAttemptStateV2,
    ) -> tuple[
        AccessRequestV2,
        CanonicalTicket,
        TicketUseIdentity,
        bytes,
        bytes,
    ]:
        if not isinstance(state, UEAccessAttemptStateV2):
            raise TypeError("attempt state has the wrong type")
        state.validate()
        request = decode_access_request(
            state.request_bytes,
            self._suite_registry,
            self._proof_registry,
        )
        if (
            encode_access_request(
                request,
                self._suite_registry,
                self._proof_registry,
            )
            != state.request_bytes
        ):
            raise ValueError("wallet request is non-canonical")
        ticket = CanonicalTicket.decode(request.ticket)
        if ticket.encode() != request.ticket:
            raise ValueError("wallet ticket is non-canonical")
        if ticket.signing_role is not KeyRole.ISSUER_VERIFICATION:
            raise ValueError("wallet ticket has the wrong signing role")
        identity = TicketUseIdentity(
            ctx=ticket.payload.ctx,
            serial=ticket.payload.sn,
            ticket_digest=ticket.payload_digest,
        )
        if identity.ctx != request.ctx:
            raise ValueError("wallet ticket context differs from request")
        request_digest = derive_request_digest(
            request,
            self._suite_registry,
            self._proof_registry,
        )
        attempt_id = derive_attempt_id(identity.use_key, request_digest)
        if (
            request_digest != state.request_digest
            or attempt_id != state.attempt_id
        ):
            raise ValueError("wallet request identities are inconsistent")
        return request, ticket, identity, request_digest, attempt_id

    @staticmethod
    def _validate_configuration_binding(
        request: AccessRequestV2,
        ticket: CanonicalTicket,
        configuration: AccessConfigurationSnapshotV2,
    ) -> None:
        bindings = (
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
            (ticket.issuer_key_id, configuration.issuer_verification_key_id),
        )
        if any(actual != expected for actual, expected in bindings):
            raise ValueError("wallet request and configuration differ")
        if request.suite_id not in configuration.allowed_suite_ids:
            raise ValueError("access suite is not authorized")
        if request.proof_suite_id not in configuration.allowed_proof_suite_ids:
            raise ValueError("access proof suite is not authorized")
        if (
            configuration.channel_binding_policy
            is ChannelBindingPolicyV2.NONE_ONLY
            and request.channel_binding_mode is not ChannelBindingMode.NONE
        ):
            raise ValueError("wallet channel mode is not authorized")
        if (
            configuration.channel_binding_policy
            is ChannelBindingPolicyV2.REQUIRE_AUTHENTICATED_EXPORTER
            and request.channel_binding_mode
            is not ChannelBindingMode.AUTHENTICATED_EXPORTER
        ):
            raise ValueError("wallet request lacks required channel binding")

    @staticmethod
    def _validate_time(
        state: UEAccessAttemptStateV2,
        response: AccessAcceptV2,
        now: int,
    ) -> None:
        configuration = state.configuration
        _u64(now, "UE acceptance time")
        if not configuration.valid_from <= now < configuration.valid_until:
            raise ValueError("access configuration is inactive")
        if now >= state.ticket_expires_at:
            raise ValueError("ticket expired before UE acceptance")
        if now > response.activation_deadline:
            raise ValueError("activation deadline expired before UE acceptance")
        if now > response.session_expiry:
            raise ValueError("session expired before UE acceptance")
        if response.session_expiry > min(
            configuration.valid_until,
            state.ticket_expires_at,
        ):
            raise ValueError("response session exceeds authenticated validity")
        activation_limit = _add_u64(
            _add_u64(
                now,
                configuration.activation_window_seconds,
                "UE activation window",
            ),
            configuration.maximum_clock_skew_seconds,
            "UE activation clock skew",
        )
        session_limit = _add_u64(
            _add_u64(
                now,
                configuration.session_lifetime_seconds,
                "UE session lifetime",
            ),
            configuration.maximum_clock_skew_seconds,
            "UE session clock skew",
        )
        if response.activation_deadline > activation_limit:
            raise ValueError("response activation window exceeds policy")
        if response.session_expiry > session_limit:
            raise ValueError("response session lifetime exceeds policy")

    @staticmethod
    def _key_query(
        request: AccessRequestV2,
        configuration: AccessConfigurationSnapshotV2,
    ) -> FGSVerificationKeyQueryV2:
        return FGSVerificationKeyQueryV2(
            suite_id=request.suite_id,
            system_config_digest=configuration.system_config_digest,
            acceptance_domain_digest=(
                configuration.acceptance_domain_digest
            ),
            epoch=request.epoch,
            fgs_id=request.target_fgs_id,
            fgs_auth_key_id=request.fgs_auth_key_id,
        )

    def process(
        self,
        encoded_response: bytes,
        attempt_state: UEAccessAttemptStateV2,
    ) -> UEResponseProcessResultV2:
        try:
            response = decode_access_accept(
                encoded_response,
                self._suite_registry,
            )
            if (
                encode_access_accept(response, self._suite_registry)
                != encoded_response
            ):
                raise ValueError("response is non-canonical")
        except Exception as error:
            return self._reject(f"response_encoding:{type(error).__name__}")

        try:
            (
                request,
                ticket,
                identity,
                request_digest,
                attempt_id,
            ) = self._load_attempt(attempt_state)
        except Exception as error:
            return self._reject(f"wallet_state:{type(error).__name__}")

        try:
            configuration = self._configuration_provider.resolve(
                request.system_config_digest
            )
        except Exception as error:
            return self._reject(f"configuration_backend:{type(error).__name__}")
        if not isinstance(configuration, AccessConfigurationSnapshotV2):
            return self._reject("configuration_unavailable")
        try:
            configuration.validate()
            if configuration != attempt_state.configuration:
                raise ValueError("current configuration differs from wallet state")
            self._validate_configuration_binding(
                request,
                ticket,
                configuration,
            )
            validate_response_binding(
                request,
                response,
                use_key=identity.use_key,
                suite_registry=self._suite_registry,
                proof_registry=self._proof_registry,
            )
        except Exception as error:
            return self._reject(f"response_binding:{type(error).__name__}")

        try:
            now = self._clock.now()
            self._validate_time(attempt_state, response, now)
        except Exception as error:
            return self._reject(f"acceptance_time:{type(error).__name__}")

        query = self._key_query(request, configuration)
        try:
            key_snapshot = self._fgs_key_provider.resolve(query)
        except Exception as error:
            return self._reject(f"fgs_key_backend:{type(error).__name__}")
        if not isinstance(key_snapshot, FGSVerificationKeySnapshotV2):
            return self._reject("fgs_key_unavailable")
        try:
            key_snapshot.validate()
        except Exception as error:
            return self._reject(f"fgs_key_snapshot:{type(error).__name__}")
        if key_snapshot.query_digest != query.digest:
            return self._reject("fgs_key_query_mismatch")
        if not key_snapshot.valid_from <= now < key_snapshot.valid_until:
            return self._reject("fgs_key_inactive")
        if key_snapshot.revoked:
            return self._reject("fgs_key_revoked")

        suite_id = response.suite_id
        for name, backend in (
            ("KEM", self._kem_backend),
            ("FGS authentication", self._authentication_backend),
            ("key schedule", self._key_schedule_backend),
        ):
            if getattr(backend, "suite_id", None) != suite_id:
                return self._reject(f"{name.lower().replace(' ', '_')}_suite_mismatch")

        transcript_digest = derive_transcript_digest(
            response,
            self._suite_registry,
        )
        try:
            authentication_ok = self._authentication_backend.verify(
                key_snapshot.verification_key,
                FGS_AUTH_LABEL + transcript_digest,
                response.fgs_authenticator,
            )
        except Exception as error:
            return self._reject(f"fgs_authentication:{type(error).__name__}")
        if authentication_ok is not True:
            return self._reject("fgs_authentication_invalid")

        try:
            shared_secret = self._kem_backend.decapsulate(
                attempt_state.ue_kem_secret_key,
                response.kem_ciphertext_to_ue,
            )
            _opaque(shared_secret, "KEM shared secret")
            schedule_context = encode_key_schedule_context_fields(
                request,
                configuration,
                request_digest=request_digest,
                attempt_id=attempt_id,
                session_id=response.session_id,
            )
            session_keys = self._key_schedule_backend.derive_session_keys(
                shared_secret,
                transcript_digest,
                schedule_context,
            )
            if not isinstance(session_keys, SessionKeysV2):
                raise TypeError("key schedule returned the wrong type")
        except Exception as error:
            return self._reject(f"session_keys:{type(error).__name__}")

        try:
            server_finished_ok = (
                self._key_schedule_backend.verify_server_finished(
                    session_keys.server_finished_key,
                    transcript_digest,
                    derive_fgs_authenticator_digest(
                        response.fgs_authenticator
                    ),
                    response.server_key_confirmation,
                )
            )
        except Exception as error:
            return self._reject(f"server_finished:{type(error).__name__}")
        if server_finished_ok is not True:
            return self._reject("server_finished_invalid")

        try:
            response_digest = derive_response_digest(
                response,
                self._suite_registry,
            )
            client_finished = self._key_schedule_backend.client_finished(
                session_keys.client_finished_key,
                response_digest,
            )
            _opaque(client_finished, "client Finished")
            activation = SessionActivateV2(
                suite_id=response.suite_id,
                request_digest=request_digest,
                attempt_id=attempt_id,
                session_id=response.session_id,
                response_digest=response_digest,
                client_key_confirmation=client_finished,
            )
            activation_bytes = encode_session_activate(
                activation,
                self._suite_registry,
            )
            session = UEAcceptedSessionV2(
                suite_id=response.suite_id,
                identity=identity,
                system_config_digest=configuration.system_config_digest,
                acceptance_domain_digest=(
                    configuration.acceptance_domain_digest
                ),
                request_digest=request_digest,
                attempt_id=attempt_id,
                transcript_digest=transcript_digest,
                response_digest=response_digest,
                session_id=response.session_id,
                accepted_at=now,
                activation_deadline=response.activation_deadline,
                session_expiry=response.session_expiry,
                activation=activation,
                activation_bytes=activation_bytes,
                application_key=session_keys.application_key,
                exporter_key=session_keys.exporter_key,
            )
            session.validate()
            if encode_session_activate(
                session.activation,
                self._suite_registry,
            ) != session.activation_bytes:
                raise ValueError("activation output is non-canonical")
        except Exception as error:
            return self._reject(f"activation_output:{type(error).__name__}")

        return UEResponseProcessResultV2(
            True,
            UEResponseDispositionV2.ACCEPTED,
            (),
            response,
            session,
        )


def ue_access_accept_processor_manifest() -> dict[str, object]:
    return {
        "format": "PQ-SAT-UE-ACCESS-ACCEPT-PROCESSOR-v0.2",
        "access_protocol_version": 2,
        "processing_order": [
            "canonical_access_accept",
            "protected_wallet_attempt_and_exact_m1",
            "authenticated_current_configuration",
            "response_request_and_policy_binding",
            "trusted_acceptance_time",
            "query_bound_fgs_verification_key",
            "fgs_authentication_before_decapsulation",
            "kem_decapsulation_and_shared_kdf_context",
            "server_finished",
            "client_finished_and_session_activate",
            "release_ue_session_material",
        ],
        "fgs_key_query_domain": FGS_KEY_QUERY_LABEL.decode("ascii"),
        "claim_boundary": {
            "exact_wallet_request_revalidated": True,
            "authenticated_configuration_boundary_implemented": True,
            "query_bound_fgs_key_boundary_implemented": True,
            "fgs_authentication_precedes_kem_decapsulation": True,
            "server_finished_boundary_implemented": True,
            "client_finished_generation_implemented": True,
            "session_activate_output_implemented": True,
            "durable_wallet_transition_implemented": False,
            "production_fgs_key_distribution_instantiated": False,
            "production_pq_ake_instantiated": False,
            "secure_key_erasure_implemented": False,
            "first_protected_application_record_implemented": False,
            "production_ready": False,
            "proof_closed": False,
        },
    }
