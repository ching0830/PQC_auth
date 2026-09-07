"""Bounded one-time access admission for PQ-RBBC system profile v0.1.

This control-plane prototype composes the existing canonical access objects,
the real stateless ``VerifyTicket`` contract, and an atomic ticket-use store.
Cryptographic challenge cookies, holder authentication, PQ AKE confirmation,
and session preparation remain explicit backend boundaries.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping, Protocol

from pq_rbbc.contracts.system import KeyReference, SystemInitializationBundle
from pq_rbbc.governance.system_init import (
    ConfigurationAuthenticationVerifier,
    verify_initialization,
)
from pq_rbbc.tickets.verification import (
    CanonicalTicket,
    TicketAuthenticationVerifier,
    TicketClock,
    verify_ticket,
)

from .access import (
    DIGEST_BYTES,
    AccessAcceptV1,
    AccessChallengeV1,
    AccessFinishV1,
    AccessInitV1,
    ServingContextV1,
    SuiteLimits,
    access_accept_digest,
    access_challenge_digest,
    access_init_digest,
    access_transcript_digest,
    decode_access_accept,
    decode_access_challenge,
    decode_access_finish,
    decode_access_init,
    derive_attempt_id,
    encode_access_accept,
    encode_access_challenge,
    encode_access_finish,
    encode_access_init,
)
from .identities import TicketUseIdentity
from .replay import (
    Consumption,
    Reservation,
    ReserveDisposition,
    ReserveResult,
    RevocationSnapshot,
)


PUBLIC_ACCESS_REJECTION = "access_rejected"
PUBLIC_ACCESS_PENDING = "access_pending"
MAX_U64 = (1 << 64) - 1
PARENT_VERIFY_TICKET_OPENING_INTEGRATION_COMMIT = (
    "ecab1d9919d8627fb96fc986008a961a82a37df8"
)


def _uint64(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value <= MAX_U64:
        raise ValueError(f"{name} is outside u64")
    return value


def _fixed(value: bytes, length: int, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != length:
        raise ValueError(f"{name} must be exactly {length} bytes")
    return value


class ChallengeCookieVerifier(Protocol):
    """Authenticate an FGS challenge and all fields of the initiating flow."""

    def verify(
        self,
        init: AccessInitV1,
        challenge: AccessChallengeV1,
        now: int,
    ) -> bool: ...


class HolderAuthenticationVerifier(Protocol):
    """Verify possession of the secret bound by the ticket's holder hash."""

    def verify(
        self,
        holder_hash: bytes,
        ticket_payload_digest: bytes,
        ctx: bytes,
        serving_context_digest: bytes,
        transcript_digest: bytes,
        authenticator: bytes,
    ) -> bool: ...


class UEKeyConfirmationVerifier(Protocol):
    """Verify UE-side AKE confirmation over the complete access transcript."""

    def verify(
        self,
        ticket_payload_digest: bytes,
        ctx: bytes,
        serving_context_digest: bytes,
        transcript_digest: bytes,
        ue_key_share: bytes,
        fgs_key_share: bytes,
        confirmation: bytes,
    ) -> bool: ...


class AccessPolicyVerifier(Protocol):
    """Pure resource/policy admission performed before ticket reservation."""

    def authorize(
        self,
        bundle: SystemInitializationBundle,
        serving_context: ServingContextV1,
        identity: TicketUseIdentity,
        attempt_id: bytes,
        transcript_digest: bytes,
    ) -> bool: ...


class OneTimeAccessStore(Protocol):
    """Serializable revocation and one-time consumption boundary.

    ``reserve`` and ``commit`` must compare ``revocation_generation`` with the
    authoritative registry while executing the state transition atomically.
    A backend exception or indeterminate commit must fail closed.
    """

    def snapshot_revocation(
        self, identity: TicketUseIdentity
    ) -> RevocationSnapshot: ...

    def reserve(
        self,
        identity: TicketUseIdentity,
        *,
        attempt_id: bytes,
        transcript_digest: bytes,
        reserved_at: int,
        lease_deadline: int,
        revocation_generation: int,
    ) -> ReserveResult: ...

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
        revocation_generation: int,
    ) -> Consumption: ...


@dataclass(frozen=True)
class SessionPreparationContext:
    identity: TicketUseIdentity
    attempt_id: bytes
    transcript_digest: bytes
    serving_context_digest: bytes
    ue_key_share: bytes
    fgs_key_share: bytes
    now: int
    configuration_expiry: int

    def validate(self) -> None:
        if not isinstance(self.identity, TicketUseIdentity):
            raise TypeError("identity must be a TicketUseIdentity")
        _fixed(self.attempt_id, DIGEST_BYTES, "attempt_id")
        _fixed(self.transcript_digest, DIGEST_BYTES, "transcript_digest")
        _fixed(
            self.serving_context_digest,
            DIGEST_BYTES,
            "serving_context_digest",
        )
        if not isinstance(self.ue_key_share, bytes) or not self.ue_key_share:
            raise ValueError("ue_key_share must be non-empty bytes")
        if not isinstance(self.fgs_key_share, bytes) or not self.fgs_key_share:
            raise ValueError("fgs_key_share must be non-empty bytes")
        _uint64(self.now, "now")
        _uint64(self.configuration_expiry, "configuration_expiry")
        if self.configuration_expiry <= self.now:
            raise ValueError("configuration is expired")


@dataclass(frozen=True)
class PreparedAccessSession:
    """Inert session material; preparing it must not activate a session."""

    session_id: bytes
    session_expiry: int
    fgs_key_confirmation: bytes

    def validate(self, *, now: int, configuration_expiry: int) -> None:
        _fixed(self.session_id, DIGEST_BYTES, "session_id")
        if self.session_id == bytes(DIGEST_BYTES):
            raise ValueError("session_id must not be all zero")
        _uint64(self.session_expiry, "session_expiry")
        if not now < self.session_expiry <= configuration_expiry:
            raise ValueError("session expiry is outside the accepted window")
        if (
            not isinstance(self.fgs_key_confirmation, bytes)
            or not self.fgs_key_confirmation
        ):
            raise ValueError("fgs_key_confirmation must be non-empty bytes")


class AccessSessionPreparationBackend(Protocol):
    """Prepare inert response material without activating external state.

    Session activation is represented only by the store's atomic ``commit``.
    Implementations that create externally effective state in ``prepare`` do
    not satisfy this interface.
    """

    def prepare(self, context: SessionPreparationContext) -> PreparedAccessSession: ...


class AdmissionDisposition(Enum):
    ACCEPTED = "accepted"
    IDEMPOTENT_RETRY = "idempotent_retry"
    PENDING = "pending"
    REJECTED = "rejected"


@dataclass(frozen=True)
class AccessAdmissionOutcome:
    disposition: AdmissionDisposition
    public_failure: str | None
    audit_reason: str | None
    response: bytes | None
    attempt_id: bytes | None
    use_key: bytes | None

    @property
    def accepted(self) -> bool:
        return self.disposition in (
            AdmissionDisposition.ACCEPTED,
            AdmissionDisposition.IDEMPOTENT_RETRY,
        )


@dataclass(frozen=True)
class _SnapshotClock:
    timestamp: int

    def now(self) -> int:
        return self.timestamp


class OneTimeAccessAdmissionService:
    """FGS-side finish admission with strict one-time state transitions."""

    def __init__(
        self,
        *,
        authenticated_initialization: bytes,
        trusted_configuration_key: KeyReference,
        initialization_verifier: ConfigurationAuthenticationVerifier,
        ticket_verifier: TicketAuthenticationVerifier,
        clock: TicketClock,
        serving_context: ServingContextV1,
        suite_registry: Mapping[int, SuiteLimits],
        cookie_verifier: ChallengeCookieVerifier,
        holder_verifier: HolderAuthenticationVerifier,
        key_confirmation_verifier: UEKeyConfirmationVerifier,
        policy_verifier: AccessPolicyVerifier,
        store: OneTimeAccessStore,
        session_backend: AccessSessionPreparationBackend,
        reservation_lease: int,
        maximum_clock_skew: int,
        replay_grace: int,
    ) -> None:
        if not isinstance(authenticated_initialization, bytes):
            raise TypeError("authenticated_initialization must be bytes")
        if not isinstance(trusted_configuration_key, KeyReference):
            raise TypeError("trusted_configuration_key must be a KeyReference")
        trusted_configuration_key.validate()
        if not isinstance(serving_context, ServingContextV1):
            raise TypeError("serving_context must be a ServingContextV1")
        if not isinstance(suite_registry, Mapping) or not suite_registry:
            raise ValueError("suite_registry must be a non-empty mapping")
        lease = _uint64(reservation_lease, "reservation_lease")
        if lease == 0:
            raise ValueError("reservation_lease must be nonzero")
        self._maximum_clock_skew = _uint64(
            maximum_clock_skew, "maximum_clock_skew"
        )
        self._replay_grace = _uint64(replay_grace, "replay_grace")
        self._authenticated_initialization = authenticated_initialization
        self._trusted_configuration_key = trusted_configuration_key
        self._initialization_verifier = initialization_verifier
        self._ticket_verifier = ticket_verifier
        self._clock = clock
        self._serving_context = serving_context
        self._suite_registry = MappingProxyType(dict(suite_registry))
        self._cookie_verifier = cookie_verifier
        self._holder_verifier = holder_verifier
        self._key_confirmation_verifier = key_confirmation_verifier
        self._policy_verifier = policy_verifier
        self._store = store
        self._session_backend = session_backend
        self._reservation_lease = lease

    @staticmethod
    def _reject(
        audit_reason: str,
        *,
        attempt_id: bytes | None = None,
        use_key: bytes | None = None,
    ) -> AccessAdmissionOutcome:
        return AccessAdmissionOutcome(
            AdmissionDisposition.REJECTED,
            PUBLIC_ACCESS_REJECTION,
            audit_reason,
            None,
            attempt_id,
            use_key,
        )

    @staticmethod
    def _pending(attempt_id: bytes, use_key: bytes) -> AccessAdmissionOutcome:
        return AccessAdmissionOutcome(
            AdmissionDisposition.PENDING,
            PUBLIC_ACCESS_PENDING,
            "same_attempt_reserved",
            None,
            attempt_id,
            use_key,
        )

    def _recover_consumption(
        self,
        consumption: Consumption,
        *,
        suite_id: int,
        serving_context_digest: bytes,
        now: int,
        configuration_expiry: int,
    ) -> AccessAdmissionOutcome:
        try:
            response = decode_access_accept(
                consumption.sealed_response,
                self._suite_registry,
            )
            if (
                response.suite_id != suite_id
                or response.attempt_id != consumption.attempt_id
                or response.session_id != consumption.session_id
                or response.serving_context_digest != serving_context_digest
                or access_accept_digest(response) != consumption.response_digest
                or response.session_expiry <= now
                or response.session_expiry > configuration_expiry
                or not response.fgs_key_confirmation
            ):
                raise ValueError("stored response binding mismatch")
        except Exception as error:
            return self._reject(
                f"store_integrity:{type(error).__name__}",
                attempt_id=consumption.attempt_id,
                use_key=consumption.identity.use_key,
            )
        return AccessAdmissionOutcome(
            AdmissionDisposition.IDEMPOTENT_RETRY,
            None,
            None,
            consumption.sealed_response,
            consumption.attempt_id,
            consumption.identity.use_key,
        )

    def admit(
        self,
        encoded_init: bytes,
        encoded_challenge: bytes,
        encoded_finish: bytes,
    ) -> AccessAdmissionOutcome:
        """Validate one complete flow, then atomically reserve and consume it."""

        # 1. Strictly parse every canonical access object before state access.
        try:
            init = decode_access_init(encoded_init, self._suite_registry)
            challenge = decode_access_challenge(
                encoded_challenge, self._suite_registry
            )
            finish = decode_access_finish(encoded_finish, self._suite_registry)
        except Exception as error:
            return self._reject(f"access_encoding:{type(error).__name__}")

        # 2. Authenticate configuration against the caller-pinned FAC anchor.
        initialization = verify_initialization(
            self._authenticated_initialization,
            self._trusted_configuration_key,
            self._initialization_verifier,
        )
        if not initialization.accepted or initialization.bundle is None:
            return self._reject("initialization_invalid")
        bundle = initialization.bundle

        # 3. Freeze one trusted time value for every check in this operation.
        try:
            now = _uint64(self._clock.now(), "admission time")
        except Exception as error:
            return self._reject(f"clock_backend:{type(error).__name__}")

        # 4. Bind the configured serving context and complete access flow.
        configuration = bundle.configuration
        if (
            self._serving_context.epoch != configuration.epoch
            or self._serving_context.policy_digest != configuration.policy_digest
            or init.ctx != bundle.ctx
            or init.serving_context_digest != self._serving_context.digest
        ):
            return self._reject("serving_context_mismatch")
        if not now < challenge.challenge_expiry <= configuration.expiry_bucket:
            return self._reject("challenge_expired_or_outside_configuration")
        try:
            transcript_digest = access_transcript_digest(init, challenge, finish)
        except Exception as error:
            return self._reject(f"access_binding:{type(error).__name__}")

        # 5. Run the real stateless VerifyTicket contract before consumption.
        verification = verify_ticket(
            self._authenticated_initialization,
            init.ticket,
            trusted_configuration_key=self._trusted_configuration_key,
            initialization_verifier=self._initialization_verifier,
            ticket_verifier=self._ticket_verifier,
            clock=_SnapshotClock(now),
        )
        if (
            not verification.accepted
            or verification.ticket is None
            or verification.payload_digest is None
        ):
            return self._reject("ticket_invalid")
        ticket_view = verification.ticket
        payload_digest = verification.payload_digest
        try:
            ticket = CanonicalTicket.decode(init.ticket)
            if (
                ticket.payload_digest != payload_digest
                or ticket_view.ctx != init.ctx
                or ticket_view.visible_serial != ticket.payload.sn
            ):
                raise ValueError("verified ticket identity mismatch")
            identity = TicketUseIdentity(
                ctx=ticket.payload.ctx,
                serial=ticket.payload.sn,
                ticket_digest=payload_digest,
            )
            attempt_id = derive_attempt_id(
                payload_digest,
                init.serving_context_digest,
                init.ue_nonce,
                challenge.fgs_nonce,
                init.attempt_nonce,
                transcript_digest,
            )
        except Exception as error:
            return self._reject(f"ticket_identity:{type(error).__name__}")

        # 6. Snapshot revocation before expensive holder/AKE validation.
        try:
            revocation = self._store.snapshot_revocation(identity)
            if not isinstance(revocation, RevocationSnapshot):
                raise TypeError("wrong revocation snapshot type")
            if revocation.revoked:
                return self._reject(
                    "ticket_revoked",
                    attempt_id=attempt_id,
                    use_key=identity.use_key,
                )
        except Exception as error:
            return self._reject(
                f"revocation_store:{type(error).__name__}",
                attempt_id=attempt_id,
                use_key=identity.use_key,
            )

        # 7. Complete all pure authentication and policy checks before reserve.
        try:
            if self._cookie_verifier.verify(init, challenge, now) is not True:
                return self._reject(
                    "challenge_cookie_invalid",
                    attempt_id=attempt_id,
                    use_key=identity.use_key,
                )
        except Exception as error:
            return self._reject(
                f"challenge_cookie_backend:{type(error).__name__}",
                attempt_id=attempt_id,
                use_key=identity.use_key,
            )
        try:
            holder_valid = self._holder_verifier.verify(
                ticket.payload.holder_hash,
                payload_digest,
                ticket.payload.ctx,
                init.serving_context_digest,
                transcript_digest,
                finish.holder_authenticator,
            )
        except Exception as error:
            return self._reject(
                f"holder_backend:{type(error).__name__}",
                attempt_id=attempt_id,
                use_key=identity.use_key,
            )
        if holder_valid is not True:
            return self._reject(
                "holder_authentication_invalid",
                attempt_id=attempt_id,
                use_key=identity.use_key,
            )
        try:
            confirmation_valid = self._key_confirmation_verifier.verify(
                payload_digest,
                ticket.payload.ctx,
                init.serving_context_digest,
                transcript_digest,
                init.ue_key_share,
                challenge.fgs_key_share,
                finish.ue_key_confirmation,
            )
        except Exception as error:
            return self._reject(
                f"key_confirmation_backend:{type(error).__name__}",
                attempt_id=attempt_id,
                use_key=identity.use_key,
            )
        if confirmation_valid is not True:
            return self._reject(
                "key_confirmation_invalid",
                attempt_id=attempt_id,
                use_key=identity.use_key,
            )
        try:
            policy_valid = self._policy_verifier.authorize(
                bundle,
                self._serving_context,
                identity,
                attempt_id,
                transcript_digest,
            )
        except Exception as error:
            return self._reject(
                f"policy_backend:{type(error).__name__}",
                attempt_id=attempt_id,
                use_key=identity.use_key,
            )
        if policy_valid is not True:
            return self._reject(
                "policy_rejected",
                attempt_id=attempt_id,
                use_key=identity.use_key,
            )

        # 8. Atomically arbitrate the ticket and recheck revocation generation.
        try:
            lease_deadline = now + self._reservation_lease
            if lease_deadline > MAX_U64:
                raise ValueError("reservation lease overflows u64")
            reservation = self._store.reserve(
                identity,
                attempt_id=attempt_id,
                transcript_digest=transcript_digest,
                reserved_at=now,
                lease_deadline=lease_deadline,
                revocation_generation=revocation.generation,
            )
            if not isinstance(reservation, ReserveResult):
                raise TypeError("wrong reserve result type")
            if (
                reservation.record.identity != identity
                or reservation.record.attempt_id != attempt_id
                or reservation.record.transcript_digest != transcript_digest
            ):
                raise ValueError("reserve result binding mismatch")
        except Exception as error:
            return self._reject(
                f"reserve_store:{type(error).__name__}",
                attempt_id=attempt_id,
                use_key=identity.use_key,
            )

        if reservation.disposition is ReserveDisposition.EXISTING_RESERVATION:
            if not isinstance(reservation.record, Reservation):
                return self._reject(
                    "store_integrity:wrong_reservation_type",
                    attempt_id=attempt_id,
                    use_key=identity.use_key,
                )
            return self._pending(attempt_id, identity.use_key)
        if reservation.disposition is ReserveDisposition.EXISTING_CONSUMPTION:
            if not isinstance(reservation.record, Consumption):
                return self._reject(
                    "store_integrity:wrong_consumption_type",
                    attempt_id=attempt_id,
                    use_key=identity.use_key,
                )
            return self._recover_consumption(
                reservation.record,
                suite_id=init.suite_id,
                serving_context_digest=init.serving_context_digest,
                now=now,
                configuration_expiry=configuration.expiry_bucket,
            )
        if (
            reservation.disposition is not ReserveDisposition.NEW
            or not isinstance(reservation.record, Reservation)
        ):
            return self._reject(
                "store_integrity:unknown_reserve_disposition",
                attempt_id=attempt_id,
                use_key=identity.use_key,
            )

        # 9. Prepare inert session material.  Failure deliberately leaves the
        # reservation in place; automatic abort cannot prove no commit/effect.
        context = SessionPreparationContext(
            identity=identity,
            attempt_id=attempt_id,
            transcript_digest=transcript_digest,
            serving_context_digest=init.serving_context_digest,
            ue_key_share=init.ue_key_share,
            fgs_key_share=challenge.fgs_key_share,
            now=now,
            configuration_expiry=configuration.expiry_bucket,
        )
        try:
            context.validate()
            prepared = self._session_backend.prepare(context)
            if not isinstance(prepared, PreparedAccessSession):
                raise TypeError("wrong prepared session type")
            prepared.validate(
                now=now,
                configuration_expiry=configuration.expiry_bucket,
            )
            accept = AccessAcceptV1(
                suite_id=init.suite_id,
                attempt_id=attempt_id,
                session_id=prepared.session_id,
                serving_context_digest=init.serving_context_digest,
                session_expiry=prepared.session_expiry,
                fgs_key_confirmation=prepared.fgs_key_confirmation,
            )
            response = encode_access_accept(accept, self._suite_registry)
            response_digest = access_accept_digest(accept)
        except Exception as error:
            return self._reject(
                f"session_preparation:{type(error).__name__}",
                attempt_id=attempt_id,
                use_key=identity.use_key,
            )

        # 10. Commit session identity, response, consumption, and a second
        # revocation-generation check in one store durability boundary.
        try:
            retention_deadline = (
                configuration.expiry_bucket
                + self._maximum_clock_skew
                + self._replay_grace
            )
            if retention_deadline > MAX_U64:
                raise ValueError("retention deadline overflows u64")
            consumption = self._store.commit(
                identity,
                attempt_id=attempt_id,
                transcript_digest=transcript_digest,
                session_id=prepared.session_id,
                response_digest=response_digest,
                sealed_response=response,
                consumed_at=now,
                retention_deadline=retention_deadline,
                revocation_generation=revocation.generation,
            )
            if (
                not isinstance(consumption, Consumption)
                or consumption.identity != identity
                or consumption.attempt_id != attempt_id
                or consumption.transcript_digest != transcript_digest
                or consumption.session_id != prepared.session_id
                or consumption.response_digest != response_digest
                or consumption.sealed_response != response
            ):
                raise ValueError("commit result binding mismatch")
        except Exception as error:
            return self._reject(
                f"commit_store:{type(error).__name__}",
                attempt_id=attempt_id,
                use_key=identity.use_key,
            )

        return AccessAdmissionOutcome(
            AdmissionDisposition.ACCEPTED,
            None,
            None,
            response,
            attempt_id,
            identity.use_key,
        )


def one_time_access_admission_manifest(
    init: AccessInitV1,
    challenge: AccessChallengeV1,
    finish: AccessFinishV1,
    ticket_payload_digest: bytes,
    accepted_response: bytes,
    *,
    suite_registry: Mapping[int, SuiteLimits],
) -> dict[str, object]:
    """Return deterministic identities and a conservative checkpoint boundary."""

    ticket = CanonicalTicket.decode(init.ticket)
    transcript_digest = access_transcript_digest(init, challenge, finish)
    identity = TicketUseIdentity(
        ctx=ticket.payload.ctx,
        serial=ticket.payload.sn,
        ticket_digest=_fixed(
            ticket_payload_digest,
            DIGEST_BYTES,
            "ticket_payload_digest",
        ),
    )
    attempt_id = derive_attempt_id(
        identity.ticket_digest,
        init.serving_context_digest,
        init.ue_nonce,
        challenge.fgs_nonce,
        init.attempt_nonce,
        transcript_digest,
    )
    response = decode_access_accept(accepted_response, suite_registry)
    if response.attempt_id != attempt_id:
        raise ValueError("accepted response has the wrong attempt identity")
    init_bytes = encode_access_init(init, suite_registry)
    challenge_bytes = encode_access_challenge(challenge, suite_registry)
    finish_bytes = encode_access_finish(finish, suite_registry)
    return {
        "format": "PQSAT-ONE-TIME-ACCESS-ADMISSION-CHECKPOINT-1",
        "system_profile": "0.1",
        "parent_verify_ticket_opening_integration_commit": (
            PARENT_VERIFY_TICKET_OPENING_INTEGRATION_COMMIT
        ),
        "suite_id": init.suite_id,
        "access_objects": {
            "init_bytes": len(init_bytes),
            "init_sha256": hashlib.sha256(init_bytes).hexdigest(),
            "init_digest": access_init_digest(init).hex(),
            "challenge_bytes": len(challenge_bytes),
            "challenge_sha256": hashlib.sha256(challenge_bytes).hexdigest(),
            "challenge_digest": access_challenge_digest(challenge).hex(),
            "finish_bytes": len(finish_bytes),
            "finish_sha256": hashlib.sha256(finish_bytes).hexdigest(),
            "transcript_digest": transcript_digest.hex(),
        },
        "ticket_identity": {
            "payload_digest": identity.ticket_digest.hex(),
            "visible_serial": identity.serial.hex(),
            "ctx": identity.ctx.hex(),
            "use_key": identity.use_key.hex(),
        },
        "attempt_id": attempt_id.hex(),
        "accepted_response": {
            "bytes": len(accepted_response),
            "sha256": hashlib.sha256(accepted_response).hexdigest(),
            "response_digest": access_accept_digest(response).hex(),
            "session_id": response.session_id.hex(),
        },
        "validation_order": [
            "strict_access_object_parsing",
            "authenticated_initialization_and_pinned_trust_anchor",
            "trusted_time_and_serving_context",
            "stateless_verify_ticket",
            "payload_digest_serial_and_use_key",
            "revocation_snapshot",
            "challenge_cookie",
            "holder_authentication",
            "ue_key_confirmation",
            "pure_policy_admission",
            "atomic_reserve_with_revocation_generation",
            "inert_session_preparation",
            "atomic_commit_with_revocation_generation",
            "response_release",
        ],
        "claim_boundary": {
            "real_verify_ticket_integrated": True,
            "payload_identity_used_for_consumption": True,
            "atomic_one_time_control_flow_implemented": True,
            "same_attempt_response_recovery_implemented": True,
            "process_local_revocation_generation_model_implemented": True,
            "test_only_suite_is_cryptographic": False,
            "production_holder_authentication_implemented": False,
            "production_pq_ake_implemented": False,
            "durable_or_distributed_store_implemented": False,
            "revocation_distribution_implemented": False,
            "external_session_activation_implemented": False,
            "handover_implemented": False,
            "cross_fgs_strictly_one_use_proven": False,
            "production_access_admission_complete": False,
        },
    }
