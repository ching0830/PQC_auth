"""Fail-closed SessionActivateV2 processor for the reference access profile."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Mapping, Protocol

from pq_sat_auth.identities import TicketUseIdentity

from .access import (
    DIGEST_BYTES,
    REFERENCE_SUITE_REGISTRY,
    AccessAcceptV2,
    SessionActivateV2,
    SuiteLimitsV2,
    decode_access_accept,
    decode_session_activate,
    derive_activation_digest,
    derive_response_digest,
    derive_transcript_digest,
    encode_access_accept,
    encode_session_activate,
    validate_activation_binding,
)
from .backends import KeyScheduleBackendV2
from .grant import GrantRecoveryBackendV2, PendingSessionStateV2
from .processor import AccessClockV2
from .replay import (
    ActivateDispositionV2,
    ActivateResultV2,
    GrantRecordV2,
    GrantStateV2,
)


U64_MAX = (1 << 64) - 1
ACTIVATION_REVOCATION_QUERY_LABEL = (
    b"PQ-SAT/ACTIVATION-REVOCATION-QUERY/v2"
)
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


@dataclass(frozen=True)
class ActivationRevocationQueryV2:
    suite_id: int
    system_config_digest: bytes
    acceptance_domain_digest: bytes
    ctx: bytes
    ticket_use_key: bytes
    original_revocation_query_digest: bytes
    fgs_id: bytes
    fgs_auth_key_id: bytes
    request_digest: bytes
    response_digest: bytes
    session_id: bytes

    def encode(self) -> bytes:
        if isinstance(self.suite_id, bool) or not isinstance(self.suite_id, int):
            raise TypeError("suite_id must be an integer")
        if not 0 <= self.suite_id < (1 << 16):
            raise ValueError("suite_id does not fit uint16")
        for name in (
            "system_config_digest",
            "acceptance_domain_digest",
            "ctx",
            "ticket_use_key",
            "original_revocation_query_digest",
            "fgs_id",
            "fgs_auth_key_id",
            "request_digest",
            "response_digest",
            "session_id",
        ):
            _fixed(getattr(self, name), DIGEST_BYTES, name)
        return struct.pack(">H", self.suite_id) + b"".join(
            (
                self.system_config_digest,
                self.acceptance_domain_digest,
                self.ctx,
                self.ticket_use_key,
                self.original_revocation_query_digest,
                self.fgs_id,
                self.fgs_auth_key_id,
                self.request_digest,
                self.response_digest,
                self.session_id,
            )
        )

    @property
    def digest(self) -> bytes:
        return hashlib.shake_256(
            ACTIVATION_REVOCATION_QUERY_LABEL + self.encode()
        ).digest(DIGEST_BYTES)


@dataclass(frozen=True)
class ActivationRevocationSnapshotV2:
    query_digest: bytes
    generation: int
    effective_at: int
    valid_until: int
    configuration_revoked: bool = False
    fgs_key_revoked: bool = False
    ticket_revoked: bool = False
    session_revoked: bool = False

    def validate(self) -> None:
        _fixed(self.query_digest, DIGEST_BYTES, "revocation query digest")
        _u64(self.generation, "revocation generation")
        _u64(self.effective_at, "revocation effective_at")
        _u64(self.valid_until, "revocation valid_until")
        if self.effective_at >= self.valid_until:
            raise ValueError("revocation validity interval is empty")
        for name in (
            "configuration_revoked",
            "fgs_key_revoked",
            "ticket_revoked",
            "session_revoked",
        ):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be bool")

    @property
    def revoked(self) -> bool:
        return any(
            (
                self.configuration_revoked,
                self.fgs_key_revoked,
                self.ticket_revoked,
                self.session_revoked,
            )
        )


def derive_activation_revocation_query_v2(
    response: AccessAcceptV2,
    record: GrantRecordV2,
    state: PendingSessionStateV2,
) -> ActivationRevocationQueryV2:
    """Derive the exact query shared by grant registration and activation."""

    query = ActivationRevocationQueryV2(
        suite_id=response.suite_id,
        system_config_digest=response.system_config_digest,
        acceptance_domain_digest=state.acceptance_domain_digest,
        ctx=record.identity.ctx,
        ticket_use_key=record.identity.use_key,
        original_revocation_query_digest=state.revocation_query.digest,
        fgs_id=response.fgs_id,
        fgs_auth_key_id=response.fgs_auth_key_id,
        request_digest=record.request_digest,
        response_digest=record.response_digest,
        session_id=record.session_id,
    )
    query.encode()
    return query


class AuthenticatedActivationRevocationProviderV2(Protocol):
    def snapshot(
        self,
        query: ActivationRevocationQueryV2,
    ) -> ActivationRevocationSnapshotV2: ...


class ActivationReplayStoreV2(Protocol):
    production_ready: bool
    durable: bool
    distributed: bool

    def lookup_session(self, session_id: bytes) -> GrantRecordV2 | None: ...

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
    ) -> ActivateResultV2: ...


@dataclass(frozen=True)
class ActivationCommitRequestV2:
    """Validated values handed to the final activation commit boundary."""

    identity: TicketUseIdentity
    attempt_id: bytes
    request_digest: bytes
    session_id: bytes
    response_digest: bytes
    client_confirmation_digest: bytes
    activated_at: int
    revocation_query: ActivationRevocationQueryV2 | None = None
    revocation_snapshot: ActivationRevocationSnapshotV2 | None = None

    def validate(self) -> None:
        if not isinstance(self.identity, TicketUseIdentity):
            raise TypeError("identity must be a TicketUseIdentity")
        for name in (
            "attempt_id",
            "request_digest",
            "session_id",
            "response_digest",
            "client_confirmation_digest",
        ):
            _fixed(getattr(self, name), DIGEST_BYTES, name)
        _u64(self.activated_at, "activated_at")
        if (self.revocation_query is None) != (
            self.revocation_snapshot is None
        ):
            raise ValueError(
                "revocation query and snapshot must be provided together"
            )
        if self.revocation_query is not None:
            if not isinstance(
                self.revocation_query,
                ActivationRevocationQueryV2,
            ):
                raise TypeError(
                    "revocation_query must be an ActivationRevocationQueryV2"
                )
            self.revocation_query.encode()
            if not isinstance(
                self.revocation_snapshot,
                ActivationRevocationSnapshotV2,
            ):
                raise TypeError(
                    "revocation_snapshot must be an "
                    "ActivationRevocationSnapshotV2"
                )
            self.revocation_snapshot.validate()
            if (
                self.revocation_snapshot.query_digest
                != self.revocation_query.digest
            ):
                raise ValueError("revocation snapshot and query differ")


class ActivationDispositionV2(Enum):
    ACTIVATED = "activated"
    ALREADY_ACTIVE = "already_active"
    REJECTED = "rejected"
    COMMIT_UNCERTAIN = "commit_uncertain"


@dataclass(frozen=True)
class ActivatedSessionCapabilityV2:
    """Secret capability released only after successful store activation."""

    identity: TicketUseIdentity
    system_config_digest: bytes
    acceptance_domain_digest: bytes
    session_id: bytes
    response_digest: bytes
    activated_at: int
    session_expiry: int
    application_key: bytes
    exporter_key: bytes

    def validate(self) -> None:
        if not isinstance(self.identity, TicketUseIdentity):
            raise TypeError("identity must be a TicketUseIdentity")
        for name in (
            "system_config_digest",
            "acceptance_domain_digest",
            "session_id",
            "response_digest",
        ):
            _fixed(getattr(self, name), DIGEST_BYTES, name)
        _u64(self.activated_at, "activated_at")
        _u64(self.session_expiry, "session_expiry")
        if self.activated_at > self.session_expiry:
            raise ValueError("activation follows session expiry")
        for name in ("application_key", "exporter_key"):
            value = getattr(self, name)
            if not isinstance(value, bytes) or not value:
                raise ValueError(f"{name} must be non-empty bytes")


@dataclass(frozen=True)
class ActivationProcessResultV2:
    accepted: bool
    disposition: ActivationDispositionV2
    failures: tuple[str, ...]
    record: GrantRecordV2 | None
    capability: ActivatedSessionCapabilityV2 | None


class FGSActivationProcessorV2:
    """Verify explicit client Finished and atomically activate one session."""

    production_ready = False

    def __init__(
        self,
        *,
        replay_store: ActivationReplayStoreV2,
        clock: AccessClockV2,
        revocation_provider: AuthenticatedActivationRevocationProviderV2,
        key_schedule_backend: KeyScheduleBackendV2,
        recovery_backend: GrantRecoveryBackendV2,
        suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
    ) -> None:
        self._replay_store = replay_store
        self._clock = clock
        self._revocation_provider = revocation_provider
        self._key_schedule_backend = key_schedule_backend
        self._recovery_backend = recovery_backend
        self._suite_registry = suite_registry

    @property
    def replay_store(self) -> ActivationReplayStoreV2:
        """Expose the bound store identity for composed atomic backends."""

        return self._replay_store

    @staticmethod
    def _reject(failure: str) -> ActivationProcessResultV2:
        return ActivationProcessResultV2(
            False,
            ActivationDispositionV2.REJECTED,
            (failure,),
            None,
            None,
        )

    @staticmethod
    def _uncertain(failure: str) -> ActivationProcessResultV2:
        return ActivationProcessResultV2(
            False,
            ActivationDispositionV2.COMMIT_UNCERTAIN,
            (failure,),
            None,
            None,
        )

    def _recover_and_validate(
        self,
        activation: SessionActivateV2,
        record: GrantRecordV2,
    ) -> tuple[AccessAcceptV2, PendingSessionStateV2]:
        response_bytes = self._recovery_backend.recover_response(
            record.sealed_response,
            response_digest=record.response_digest,
        )
        if not isinstance(response_bytes, bytes) or not response_bytes:
            raise TypeError("recovered response must be non-empty bytes")
        response = decode_access_accept(response_bytes, self._suite_registry)
        if encode_access_accept(response, self._suite_registry) != response_bytes:
            raise ValueError("recovered response is non-canonical")
        if derive_response_digest(response, self._suite_registry) != record.response_digest:
            raise ValueError("recovered response digest mismatch")
        if derive_transcript_digest(response, self._suite_registry) != record.transcript_digest:
            raise ValueError("recovered transcript digest mismatch")
        response_record = (
            response.ctx,
            response.fgs_id,
            response.request_digest,
            response.attempt_id,
            response.session_id,
            response.serving_context_digest,
            response.activation_deadline,
            response.session_expiry,
        )
        stored_record = (
            record.identity.ctx,
            record.fgs_id,
            record.request_digest,
            record.attempt_id,
            record.session_id,
            record.serving_context_digest,
            record.activation_deadline,
            record.session_expiry,
        )
        if response_record != stored_record:
            raise ValueError("recovered response and grant record differ")
        validate_activation_binding(
            response,
            activation,
            suite_registry=self._suite_registry,
        )

        state = self._recovery_backend.recover_session_state(
            record.sealed_session_state,
            session_id=record.session_id,
            response_digest=record.response_digest,
        )
        if not isinstance(state, PendingSessionStateV2):
            raise TypeError("recovered session state has the wrong type")
        state.validate()
        session_record = (
            state.suite_id,
            state.identity,
            state.system_config_digest,
            state.request_digest,
            state.attempt_id,
            state.transcript_digest,
            state.response_digest,
            state.session_id,
            state.activation_deadline,
            state.session_expiry,
        )
        expected_session = (
            response.suite_id,
            record.identity,
            response.system_config_digest,
            record.request_digest,
            record.attempt_id,
            record.transcript_digest,
            record.response_digest,
            record.session_id,
            record.activation_deadline,
            record.session_expiry,
        )
        if session_record != expected_session:
            raise ValueError("recovered session state and record differ")
        query = state.revocation_query
        if (
            query.system_config_digest,
            query.acceptance_domain_digest,
            query.ctx,
            query.fgs_id,
            query.fgs_auth_key_id,
            query.payload_digest,
            query.visible_serial,
        ) != (
            response.system_config_digest,
            state.acceptance_domain_digest,
            record.identity.ctx,
            response.fgs_id,
            response.fgs_auth_key_id,
            record.identity.ticket_digest,
            record.identity.serial,
        ):
            raise ValueError("recovered revocation query and session differ")
        return response, state

    @staticmethod
    def _activation_revocation_query(
        response: AccessAcceptV2,
        record: GrantRecordV2,
        state: PendingSessionStateV2,
    ) -> ActivationRevocationQueryV2:
        return derive_activation_revocation_query_v2(response, record, state)

    def process(
        self,
        encoded_activation: bytes,
        *,
        pre_activate_check: Callable[[ActivatedSessionCapabilityV2], bool]
        | None = None,
        activation_committer: Callable[
            [ActivationCommitRequestV2], ActivateResultV2
        ]
        | None = None,
    ) -> ActivationProcessResultV2:
        """Validate and activate one session.

        The optional check is for pure authenticated-record validation.  It
        receives candidate key material and must return the literal ``True``
        before the store transition.  It must not perform application side
        effects.  A composed store may supply ``activation_committer`` to
        include additional durable state in the same transaction; its object
        identity is checked by the caller that composes the processor.
        """

        try:
            activation = decode_session_activate(
                encoded_activation,
                self._suite_registry,
            )
            if (
                encode_session_activate(activation, self._suite_registry)
                != encoded_activation
            ):
                raise ValueError("activation is non-canonical")
        except Exception as error:
            return self._reject(f"activation_encoding:{type(error).__name__}")

        try:
            record = self._replay_store.lookup_session(activation.session_id)
        except Exception as error:
            return self._reject(f"session_lookup:{type(error).__name__}")
        if not isinstance(record, GrantRecordV2):
            return self._reject("session_not_found")
        if record.state is GrantStateV2.CONSUMED_EXPIRED:
            return self._reject("session_expired")
        was_active = record.state is GrantStateV2.CONSUMED_ACTIVE

        try:
            response, state = self._recover_and_validate(activation, record)
        except Exception as error:
            return self._reject(f"session_recovery:{type(error).__name__}")

        try:
            now = self._clock.now()
            _u64(now, "activation time")
        except Exception as error:
            return self._reject(f"clock_backend:{type(error).__name__}")
        if was_active:
            if now > record.session_expiry:
                return self._reject("active_session_expired")
        elif now > record.activation_deadline:
            return self._reject("activation_deadline_expired")

        query = self._activation_revocation_query(response, record, state)
        try:
            revocation = self._revocation_provider.snapshot(query)
        except Exception as error:
            return self._reject(
                f"activation_revocation_backend:{type(error).__name__}"
            )
        if not isinstance(revocation, ActivationRevocationSnapshotV2):
            return self._reject("activation_revocation_snapshot_unavailable")
        try:
            revocation.validate()
        except Exception as error:
            return self._reject(
                f"activation_revocation_snapshot:{type(error).__name__}"
            )
        if revocation.query_digest != query.digest:
            return self._reject("activation_revocation_query_mismatch")
        if revocation.generation < record.revocation_generation:
            return self._reject("activation_revocation_generation_stale")
        if not revocation.effective_at <= now < revocation.valid_until:
            return self._reject("activation_revocation_snapshot_inactive")
        if revocation.revoked:
            return self._reject("activation_revoked")

        if (
            getattr(self._key_schedule_backend, "suite_id", None)
            != activation.suite_id
        ):
            return self._reject("key_schedule_suite_mismatch")
        try:
            confirmation_ok = self._key_schedule_backend.verify_finished(
                state.client_finished_key,
                record.response_digest,
                activation.client_key_confirmation,
            )
        except Exception as error:
            return self._reject(
                f"client_finished_backend:{type(error).__name__}"
            )
        if confirmation_ok is not True:
            return self._reject("client_finished_invalid")

        candidate_capability = ActivatedSessionCapabilityV2(
            identity=record.identity,
            system_config_digest=state.system_config_digest,
            acceptance_domain_digest=state.acceptance_domain_digest,
            session_id=record.session_id,
            response_digest=record.response_digest,
            activated_at=(record.activated_at if was_active else now),
            session_expiry=record.session_expiry,
            application_key=state.application_key,
            exporter_key=state.exporter_key,
        )
        try:
            candidate_capability.validate()
        except Exception as error:
            return self._reject(
                f"pre_activation_capability:{type(error).__name__}"
            )
        if pre_activate_check is not None:
            try:
                checked = pre_activate_check(candidate_capability)
            except Exception as error:
                return self._reject(
                    f"pre_activation_check:{type(error).__name__}"
                )
            if checked is not True:
                return self._reject("pre_activation_check_failed")

        confirmation_digest = derive_activation_digest(
            activation,
            self._suite_registry,
        )
        try:
            commit_request = ActivationCommitRequestV2(
                identity=record.identity,
                attempt_id=record.attempt_id,
                request_digest=record.request_digest,
                session_id=record.session_id,
                response_digest=record.response_digest,
                client_confirmation_digest=confirmation_digest,
                activated_at=now,
                revocation_query=query,
                revocation_snapshot=revocation,
            )
            commit_request.validate()
            activation_result = (
                self._replay_store.activate_session(
                    commit_request.identity,
                    attempt_id=commit_request.attempt_id,
                    request_digest=commit_request.request_digest,
                    session_id=commit_request.session_id,
                    response_digest=commit_request.response_digest,
                    client_confirmation_digest=(
                        commit_request.client_confirmation_digest
                    ),
                    activated_at=commit_request.activated_at,
                )
                if activation_committer is None
                else activation_committer(commit_request)
            )
            if not isinstance(activation_result, ActivateResultV2):
                raise TypeError("activation backend returned the wrong type")
            if activation_result.disposition not in (
                ActivateDispositionV2.NEW,
                ActivateDispositionV2.EXISTING_ACTIVE,
            ):
                raise ValueError("activation backend returned an unknown disposition")
            if (
                was_active
                and activation_result.disposition
                is not ActivateDispositionV2.EXISTING_ACTIVE
            ):
                raise ValueError("active retry was reported as a new transition")
            active = activation_result.record
            if not isinstance(active, GrantRecordV2):
                raise TypeError("activation backend returned the wrong type")
            if active.state is not GrantStateV2.CONSUMED_ACTIVE:
                raise ValueError("activation backend did not return active state")
            expected_grant = (
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
            actual_grant = (
                active.identity,
                active.attempt_id,
                active.request_digest,
                active.transcript_digest,
                active.session_id,
                active.response_digest,
                active.sealed_response,
                active.sealed_session_state,
                active.serving_context_digest,
                active.fgs_id,
                active.revocation_generation,
                active.consumed_at,
                active.activation_deadline,
                active.session_expiry,
                active.retention_deadline,
            )
            if actual_grant != expected_grant:
                raise ValueError("activation backend changed committed grant")
            if active.client_confirmation_digest != confirmation_digest:
                raise ValueError("activation backend changed confirmation")
            if active.expired_at is not None or active.expiry_reason is not None:
                raise ValueError("activation backend returned expiry evidence")
            if (
                activation_result.disposition is ActivateDispositionV2.NEW
                and active.activated_at != now
            ):
                raise ValueError("activation backend changed activation time")
        except Exception as error:
            return self._uncertain(f"activate_backend:{type(error).__name__}")

        capability = ActivatedSessionCapabilityV2(
            identity=record.identity,
            system_config_digest=state.system_config_digest,
            acceptance_domain_digest=state.acceptance_domain_digest,
            session_id=record.session_id,
            response_digest=record.response_digest,
            activated_at=active.activated_at,
            session_expiry=record.session_expiry,
            application_key=state.application_key,
            exporter_key=state.exporter_key,
        )
        try:
            capability.validate()
        except Exception as error:
            return self._uncertain(f"capability_output:{type(error).__name__}")
        return ActivationProcessResultV2(
            True,
            (
                ActivationDispositionV2.ACTIVATED
                if activation_result.disposition
                is ActivateDispositionV2.NEW
                else ActivationDispositionV2.ALREADY_ACTIVE
            ),
            (),
            active,
            capability,
        )


def fgs_activation_processor_manifest() -> dict[str, object]:
    return {
        "format": "PQ-SAT-FGS-ACTIVATION-PROCESSOR-v0.2",
        "access_protocol_version": 2,
        "processing_order": [
            "canonical_session_activate",
            "session_index_lookup",
            "exact_response_and_session_state_recovery",
            "activation_binding_and_deadline",
            "query_bound_activation_revocation",
            "client_finished",
            "optional_pure_pre_activation_check",
            "atomic_activate_or_composed_commit",
            "release_capability_after_activate",
        ],
        "activation_revocation_query_domain": (
            ACTIVATION_REVOCATION_QUERY_LABEL.decode("ascii")
        ),
        "claim_boundary": {
            "unique_session_index_implemented": True,
            "client_finished_boundary_implemented": True,
            "pre_activation_check_hook_implemented": True,
            "composed_activation_commit_hook_implemented": True,
            "activation_revocation_boundary_implemented": True,
            "revocation_context_in_commit_request_implemented": True,
            "capability_released_only_after_activate": True,
            "explicit_session_activate_frame_implemented": True,
            "first_protected_application_record_implemented": False,
            "atomic_revocation_and_activation_implemented": False,
            "durable_or_distributed_store_implemented": False,
            "production_session_state_protection_instantiated": False,
            "production_pq_ake_instantiated": False,
            "production_ready": False,
            "proof_closed": False,
        },
    }
