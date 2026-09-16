"""Fail-closed pure-check processor for satellite access v0.2.

The processor stops immediately before the authoritative replay-store
``Reserve`` operation.  It never creates a reservation, KEM ciphertext,
session, response, or application side effect.  Cryptographic and deployment
services remain explicit trusted boundaries and every boundary must return an
unambiguous success value.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import IntEnum
from typing import Mapping, Protocol

from pq_rbbc.contracts.system import KeyReference
from pq_rbbc.governance.system_init import ConfigurationAuthenticationVerifier
from pq_rbbc.governance.system_init import AuthenticatedSystemInitialization
from pq_rbbc.tickets.verification import (
    CanonicalTicket,
    TicketAuthenticationVerifier,
    verify_ticket,
)
from pq_sat_auth.identities import TicketUseIdentity

from .access import (
    ATTEMPT_NONCE_BYTES,
    CONTEXT_BYTES,
    DIGEST_BYTES,
    NONCE_BYTES,
    REFERENCE_PROOF_SUITE_REGISTRY,
    REFERENCE_SUITE_REGISTRY,
    AccessRequestV2,
    ChannelBindingMode,
    ProofLimitsV2,
    SuiteLimitsV2,
    decode_access_request,
    derive_attempt_id,
    derive_request_core_digest,
    derive_request_digest,
    encode_access_request,
)
from .backends import AccessNIZKBackendV2, PQKEMBackendV2
from .proof import AccessProofStatementV2, build_access_statement


U64_MAX = (1 << 64) - 1
SERIAL_BYTES = 16
REVOCATION_QUERY_LABEL = b"PQ-SAT/ACCESS-REVOCATION-QUERY/v2"
PRODUCTION_READY = False


class ChannelBindingPolicyV2(IntEnum):
    """Authenticated configuration policy for the request channel mode."""

    NONE_ONLY = 0
    OPTIONAL_AUTHENTICATED_EXPORTER = 1
    REQUIRE_AUTHENTICATED_EXPORTER = 2


def _uint64(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value <= U64_MAX:
        raise ValueError(f"{name} does not fit uint64")
    return value


def _fixed(value: bytes, size: int, name: str, *, nonzero: bool = False) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    if nonzero and value == bytes(size):
        raise ValueError(f"{name} must not be all zero")
    return value


def _suite_ids(value: tuple[int, ...], name: str) -> tuple[int, ...]:
    if not isinstance(value, tuple) or not value:
        raise TypeError(f"{name} must be a non-empty tuple")
    for suite_id in value:
        if isinstance(suite_id, bool) or not isinstance(suite_id, int):
            raise TypeError(f"{name} entries must be integers")
        if not 0 <= suite_id < (1 << 16):
            raise ValueError(f"{name} entry does not fit uint16")
    if tuple(sorted(set(value))) != value:
        raise ValueError(f"{name} must be unique and increasing")
    return value


@dataclass(frozen=True)
class AccessConfigurationSnapshotV2:
    """Trusted output of an authenticated access-configuration provider.

    The current system-initialization v0.1 ABI has no FGS authentication role
    or access-suite extension.  Consequently the provider is an explicit
    boundary: it must authenticate these fields before returning the snapshot.
    """

    system_config_digest: bytes
    initialization_configuration_digest: bytes
    access_protocol_version: int
    ctx: bytes
    epoch: int
    valid_from: int
    valid_until: int
    freshness_window_seconds: int
    maximum_clock_skew_seconds: int
    pure_check_max_age_seconds: int
    reservation_lease_seconds: int
    activation_window_seconds: int
    session_lifetime_seconds: int
    replay_retention_grace_seconds: int
    access_profile_digest: bytes
    access_pp_digest: bytes
    fgs_id: bytes
    fgs_auth_key_id: bytes
    issuer_verification_key_id: bytes
    serving_context_digest: bytes
    authorization_digest: bytes
    acceptance_domain_digest: bytes
    allowed_suite_ids: tuple[int, ...]
    allowed_proof_suite_ids: tuple[int, ...]
    channel_binding_policy: ChannelBindingPolicyV2
    minimum_revocation_generation: int

    def validate(self) -> None:
        for name in (
            "system_config_digest",
            "initialization_configuration_digest",
            "access_profile_digest",
            "access_pp_digest",
            "fgs_id",
            "fgs_auth_key_id",
            "issuer_verification_key_id",
            "serving_context_digest",
            "authorization_digest",
            "acceptance_domain_digest",
        ):
            _fixed(getattr(self, name), DIGEST_BYTES, name, nonzero=True)
        _fixed(self.ctx, CONTEXT_BYTES, "ctx")
        _uint64(self.access_protocol_version, "access_protocol_version")
        if self.access_protocol_version != 2:
            raise ValueError("unsupported access_protocol_version")
        for name in (
            "epoch",
            "valid_from",
            "valid_until",
            "freshness_window_seconds",
            "maximum_clock_skew_seconds",
            "pure_check_max_age_seconds",
            "reservation_lease_seconds",
            "activation_window_seconds",
            "session_lifetime_seconds",
            "replay_retention_grace_seconds",
            "minimum_revocation_generation",
        ):
            _uint64(getattr(self, name), name)
        if self.valid_from >= self.valid_until:
            raise ValueError("configuration validity interval is empty")
        if self.freshness_window_seconds == 0:
            raise ValueError("freshness_window_seconds must be positive")
        for name in (
            "pure_check_max_age_seconds",
            "reservation_lease_seconds",
            "activation_window_seconds",
            "session_lifetime_seconds",
        ):
            if getattr(self, name) == 0:
                raise ValueError(f"{name} must be positive")
        if self.session_lifetime_seconds < self.activation_window_seconds:
            raise ValueError(
                "session_lifetime_seconds precedes activation window"
            )
        _suite_ids(self.allowed_suite_ids, "allowed_suite_ids")
        _suite_ids(self.allowed_proof_suite_ids, "allowed_proof_suite_ids")
        if not isinstance(self.channel_binding_policy, ChannelBindingPolicyV2):
            raise TypeError(
                "channel_binding_policy must be a ChannelBindingPolicyV2"
            )


class AuthenticatedAccessConfigurationProviderV2(Protocol):
    """Resolve an exact, already-authenticated access configuration."""

    def resolve(
        self, system_config_digest: bytes
    ) -> AccessConfigurationSnapshotV2 | None: ...


class AccessClockV2(Protocol):
    """Trusted clock sampled once for the complete pure-check operation."""

    def now(self) -> int: ...


@dataclass(frozen=True)
class VerifiedAccessTicketV2:
    """Access-relevant output derived from a successful stable VerifyTicket."""

    system_config_digest: bytes
    canonical_ticket_digest: bytes
    payload_digest: bytes
    ctx: bytes
    visible_serial: bytes
    holder_hash: bytes
    issuer_key_id: bytes
    expires_at: int

    def validate(self) -> None:
        _fixed(
            self.system_config_digest,
            DIGEST_BYTES,
            "ticket system_config_digest",
            nonzero=True,
        )
        _fixed(
            self.canonical_ticket_digest,
            DIGEST_BYTES,
            "canonical_ticket_digest",
        )
        _fixed(self.payload_digest, DIGEST_BYTES, "payload_digest")
        _fixed(self.ctx, CONTEXT_BYTES, "ticket ctx")
        _fixed(
            self.visible_serial,
            SERIAL_BYTES,
            "visible_serial",
            nonzero=True,
        )
        _fixed(self.holder_hash, DIGEST_BYTES, "holder_hash")
        _fixed(
            self.issuer_key_id,
            DIGEST_BYTES,
            "issuer_key_id",
            nonzero=True,
        )
        _uint64(self.expires_at, "ticket expires_at")


class AccessTicketVerifierV2(Protocol):
    """Stable VerifyTicket adapter with access-relevant trusted outputs."""

    def verify(
        self, canonical_ticket: bytes, *, now: int
    ) -> VerifiedAccessTicketV2 | None: ...


class _CapturedClock:
    def __init__(self, now: int) -> None:
        self._now = _uint64(now, "captured ticket time")

    def now(self) -> int:
        return self._now


class SystemAccessTicketVerifierV2:
    """Connect the FGS processor to the stable PQ-RBBC VerifyTicket contract.

    ``verify_ticket`` supplies the authenticated ticket view and canonical
    payload digest.  A second strict decode of the same immutable input only
    exposes the holder hash required by ``R_access``; all shared fields are
    compared before the result crosses this adapter.
    """

    def __init__(
        self,
        *,
        authenticated_initialization: bytes,
        trusted_configuration_key: KeyReference,
        initialization_verifier: ConfigurationAuthenticationVerifier,
        ticket_verifier: TicketAuthenticationVerifier,
    ) -> None:
        if not isinstance(authenticated_initialization, bytes):
            raise TypeError("authenticated_initialization must be bytes")
        self._authenticated_initialization = authenticated_initialization
        self._trusted_configuration_key = trusted_configuration_key
        self._initialization_verifier = initialization_verifier
        self._ticket_verifier = ticket_verifier

    def verify(
        self, canonical_ticket: bytes, *, now: int
    ) -> VerifiedAccessTicketV2 | None:
        outcome = verify_ticket(
            self._authenticated_initialization,
            canonical_ticket,
            trusted_configuration_key=self._trusted_configuration_key,
            initialization_verifier=self._initialization_verifier,
            ticket_verifier=self._ticket_verifier,
            clock=_CapturedClock(now),
        )
        if (
            outcome.accepted is not True
            or outcome.ticket is None
            or outcome.payload_digest is None
        ):
            return None
        try:
            parsed = CanonicalTicket.decode(canonical_ticket)
            initialization = AuthenticatedSystemInitialization.decode(
                self._authenticated_initialization
            )
            view = outcome.ticket
            expected = (
                parsed.canonical_digest,
                parsed.payload_digest,
                parsed.payload.ctx,
                parsed.payload.sn,
                parsed.issuer_key_id,
                parsed.trace_ciphertext,
            )
            actual = (
                view.ticket_digest,
                outcome.payload_digest,
                view.ctx,
                view.visible_serial,
                view.issuer_key_id,
                view.trace_ciphertext,
            )
            if actual != expected:
                return None
            verified = VerifiedAccessTicketV2(
                system_config_digest=hashlib.sha256(
                    initialization.bundle.configuration.encode()
                ).digest(),
                canonical_ticket_digest=parsed.canonical_digest,
                payload_digest=parsed.payload_digest,
                ctx=parsed.payload.ctx,
                visible_serial=parsed.payload.sn,
                holder_hash=parsed.payload.holder_hash,
                issuer_key_id=parsed.issuer_key_id,
                expires_at=initialization.bundle.configuration.expiry_bucket,
            )
            verified.validate()
        except Exception:
            return None
        return verified


@dataclass(frozen=True)
class AccessRevocationQueryV2:
    system_config_digest: bytes
    initialization_configuration_digest: bytes
    acceptance_domain_digest: bytes
    ctx: bytes
    epoch: int
    fgs_id: bytes
    fgs_auth_key_id: bytes
    issuer_key_id: bytes
    payload_digest: bytes
    visible_serial: bytes
    holder_hash: bytes

    def encode(self) -> bytes:
        for name in (
            "system_config_digest",
            "initialization_configuration_digest",
            "acceptance_domain_digest",
            "fgs_id",
            "fgs_auth_key_id",
            "issuer_key_id",
            "payload_digest",
            "holder_hash",
        ):
            _fixed(getattr(self, name), DIGEST_BYTES, name)
        _fixed(self.ctx, CONTEXT_BYTES, "ctx")
        _uint64(self.epoch, "epoch")
        _fixed(self.visible_serial, SERIAL_BYTES, "visible_serial")
        return b"".join(
            (
                self.system_config_digest,
                self.initialization_configuration_digest,
                self.acceptance_domain_digest,
                self.ctx,
                self.epoch.to_bytes(8, "big"),
                self.fgs_id,
                self.fgs_auth_key_id,
                self.issuer_key_id,
                self.payload_digest,
                self.visible_serial,
                self.holder_hash,
            )
        )

    @property
    def digest(self) -> bytes:
        return hashlib.shake_256(
            REVOCATION_QUERY_LABEL + self.encode()
        ).digest(DIGEST_BYTES)


@dataclass(frozen=True)
class AccessRevocationSnapshotV2:
    """Bounded, query-bound output of a trusted revocation provider."""

    query_digest: bytes
    generation: int
    effective_at: int
    valid_until: int
    configuration_revoked: bool = False
    fgs_key_revoked: bool = False
    issuer_key_revoked: bool = False
    ticket_revoked: bool = False
    serial_revoked: bool = False
    holder_revoked: bool = False

    def validate(self) -> None:
        _fixed(self.query_digest, DIGEST_BYTES, "revocation query_digest")
        _uint64(self.generation, "revocation generation")
        _uint64(self.effective_at, "revocation effective_at")
        _uint64(self.valid_until, "revocation valid_until")
        if self.effective_at >= self.valid_until:
            raise ValueError("revocation validity interval is empty")
        for name in (
            "configuration_revoked",
            "fgs_key_revoked",
            "issuer_key_revoked",
            "ticket_revoked",
            "serial_revoked",
            "holder_revoked",
        ):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be bool")

    @property
    def revoked(self) -> bool:
        return any(
            (
                self.configuration_revoked,
                self.fgs_key_revoked,
                self.issuer_key_revoked,
                self.ticket_revoked,
                self.serial_revoked,
                self.holder_revoked,
            )
        )


class AuthenticatedRevocationProviderV2(Protocol):
    """Return the current authenticated snapshot for an exact query."""

    def snapshot(
        self, query: AccessRevocationQueryV2
    ) -> AccessRevocationSnapshotV2: ...


class ChannelBindingVerifierV2(Protocol):
    """Connection-local verifier for an authenticated lower-layer exporter."""

    def verify_authenticated_exporter(self, claimed_digest: bytes) -> bool: ...


class PureAdmissionPolicyV2(Protocol):
    """Pure resource/policy gate that must not create a session or side effect."""

    def admit(
        self,
        request: AccessRequestV2,
        ticket: VerifiedAccessTicketV2,
        *,
        checked_at: int,
    ) -> bool: ...


@dataclass(frozen=True)
class ValidatedAccessRequestV2:
    """Complete trusted output passed to the later Reserve operation."""

    request_bytes: bytes
    request: AccessRequestV2
    configuration: AccessConfigurationSnapshotV2
    ticket: VerifiedAccessTicketV2
    identity: TicketUseIdentity
    access_statement: AccessProofStatementV2
    request_core_digest: bytes
    request_digest: bytes
    attempt_id: bytes
    revocation_query: AccessRevocationQueryV2
    revocation_generation: int
    checked_at: int


@dataclass(frozen=True)
class PureCheckResultV2:
    accepted: bool
    failures: tuple[str, ...]
    validated: ValidatedAccessRequestV2 | None


class FGSPureCheckProcessorV2:
    """Execute every v0.2 pure check and stop before replay-state mutation."""

    production_ready = False

    def __init__(
        self,
        *,
        configuration_provider: AuthenticatedAccessConfigurationProviderV2,
        clock: AccessClockV2,
        ticket_verifier: AccessTicketVerifierV2,
        revocation_provider: AuthenticatedRevocationProviderV2,
        access_nizk_backend: AccessNIZKBackendV2,
        kem_backend: PQKEMBackendV2,
        admission_policy: PureAdmissionPolicyV2,
        channel_binding_verifier: ChannelBindingVerifierV2 | None = None,
        suite_registry: Mapping[
            int, SuiteLimitsV2
        ] = REFERENCE_SUITE_REGISTRY,
        proof_registry: Mapping[
            int, ProofLimitsV2
        ] = REFERENCE_PROOF_SUITE_REGISTRY,
    ) -> None:
        self._configuration_provider = configuration_provider
        self._clock = clock
        self._ticket_verifier = ticket_verifier
        self._revocation_provider = revocation_provider
        self._access_nizk_backend = access_nizk_backend
        self._kem_backend = kem_backend
        self._admission_policy = admission_policy
        self._channel_binding_verifier = channel_binding_verifier
        self._suite_registry = suite_registry
        self._proof_registry = proof_registry

    @staticmethod
    def _reject(failure: str) -> PureCheckResultV2:
        return PureCheckResultV2(False, (failure,), None)

    def _configuration_checks(
        self,
        request: AccessRequestV2,
        configuration: AccessConfigurationSnapshotV2,
    ) -> str | None:
        exact_bindings = (
            (
                request.system_config_digest,
                configuration.system_config_digest,
                "configuration_digest_mismatch",
            ),
            (request.ctx, configuration.ctx, "configuration_ctx_mismatch"),
            (request.epoch, configuration.epoch, "configuration_epoch_mismatch"),
            (request.target_fgs_id, configuration.fgs_id, "target_fgs_mismatch"),
            (
                request.fgs_auth_key_id,
                configuration.fgs_auth_key_id,
                "fgs_auth_key_mismatch",
            ),
            (
                request.serving_context_digest,
                configuration.serving_context_digest,
                "serving_context_mismatch",
            ),
            (
                request.authorization_digest,
                configuration.authorization_digest,
                "authorization_mismatch",
            ),
        )
        for actual, expected, failure in exact_bindings:
            if actual != expected:
                return failure
        if request.suite_id not in configuration.allowed_suite_ids:
            return "access_suite_not_authorized"
        if request.proof_suite_id not in configuration.allowed_proof_suite_ids:
            return "proof_suite_not_authorized"
        policy = configuration.channel_binding_policy
        if (
            policy is ChannelBindingPolicyV2.NONE_ONLY
            and request.channel_binding_mode is not ChannelBindingMode.NONE
        ):
            return "channel_binding_mode_not_authorized"
        if (
            policy is ChannelBindingPolicyV2.REQUIRE_AUTHENTICATED_EXPORTER
            and request.channel_binding_mode
            is not ChannelBindingMode.AUTHENTICATED_EXPORTER
        ):
            return "channel_binding_required"
        return None

    def process(self, encoded_request: bytes) -> PureCheckResultV2:
        """Validate exact M1 bytes without mutating replay or session state."""

        try:
            request = decode_access_request(
                encoded_request,
                self._suite_registry,
                self._proof_registry,
            )
            if (
                encode_access_request(
                    request,
                    self._suite_registry,
                    self._proof_registry,
                )
                != encoded_request
            ):
                return self._reject("request_noncanonical")
        except Exception as error:
            return self._reject(f"request_encoding:{type(error).__name__}")

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
        except Exception as error:
            return self._reject(f"configuration_invalid:{type(error).__name__}")
        failure = self._configuration_checks(request, configuration)
        if failure is not None:
            return self._reject(failure)

        try:
            now = self._clock.now()
            _uint64(now, "access verification time")
        except Exception as error:
            return self._reject(f"clock_backend:{type(error).__name__}")
        if not configuration.valid_from <= now < configuration.valid_until:
            return self._reject("configuration_inactive")
        if request.client_time > min(
            U64_MAX,
            now + configuration.maximum_clock_skew_seconds,
        ):
            return self._reject("client_time_in_future")
        if (
            request.client_time + configuration.freshness_window_seconds
            < now
        ):
            return self._reject("client_time_stale")
        # A receiver can enforce the exact wire length and reject the all-zero
        # sentinel, but it cannot infer RNG quality or entropy from one value.
        # Entropy remains a UE-generation and deployment-validation obligation.
        if request.ue_nonce == bytes(NONCE_BYTES):
            return self._reject("ue_nonce_zero")
        if request.attempt_nonce == bytes(ATTEMPT_NONCE_BYTES):
            return self._reject("attempt_nonce_zero")

        if request.channel_binding_mode is ChannelBindingMode.AUTHENTICATED_EXPORTER:
            if self._channel_binding_verifier is None:
                return self._reject("channel_binding_backend_unavailable")
            try:
                channel_ok = (
                    self._channel_binding_verifier.verify_authenticated_exporter(
                        request.channel_binding_digest
                    )
                )
            except Exception as error:
                return self._reject(
                    f"channel_binding_backend:{type(error).__name__}"
                )
            if channel_ok is not True:
                return self._reject("channel_binding_invalid")

        try:
            ticket = self._ticket_verifier.verify(request.ticket, now=now)
        except Exception as error:
            return self._reject(f"verify_ticket_backend:{type(error).__name__}")
        if not isinstance(ticket, VerifiedAccessTicketV2):
            return self._reject("verify_ticket_rejected")
        try:
            ticket.validate()
        except Exception as error:
            return self._reject(f"verify_ticket_output:{type(error).__name__}")
        if ticket.ctx != request.ctx:
            return self._reject("ticket_ctx_mismatch")
        if (
            ticket.system_config_digest
            != configuration.initialization_configuration_digest
        ):
            return self._reject("ticket_configuration_mismatch")
        if ticket.issuer_key_id != configuration.issuer_verification_key_id:
            return self._reject("ticket_issuer_key_mismatch")

        identity = TicketUseIdentity(
            ctx=ticket.ctx,
            serial=ticket.visible_serial,
            ticket_digest=ticket.payload_digest,
        )
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
        attempt_id = derive_attempt_id(identity.use_key, request_digest)

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
        try:
            revocation = self._revocation_provider.snapshot(revocation_query)
        except Exception as error:
            return self._reject(f"revocation_backend:{type(error).__name__}")
        if not isinstance(revocation, AccessRevocationSnapshotV2):
            return self._reject("revocation_snapshot_unavailable")
        try:
            revocation.validate()
        except Exception as error:
            return self._reject(f"revocation_snapshot_invalid:{type(error).__name__}")
        if revocation.query_digest != revocation_query.digest:
            return self._reject("revocation_query_mismatch")
        if revocation.generation < configuration.minimum_revocation_generation:
            return self._reject("revocation_generation_stale")
        if not revocation.effective_at <= now < revocation.valid_until:
            return self._reject("revocation_snapshot_inactive")
        if revocation.revoked:
            return self._reject("revoked")

        access_statement = build_access_statement(
            access_profile_digest=configuration.access_profile_digest,
            access_pp_digest=configuration.access_pp_digest,
            holder_hash=ticket.holder_hash,
            request=request,
        )
        if (
            getattr(self._access_nizk_backend, "proof_suite_id", None)
            != request.proof_suite_id
        ):
            return self._reject("access_nizk_backend_suite_mismatch")
        try:
            proof_ok = self._access_nizk_backend.verify(
                access_statement,
                request.access_nizk,
            )
        except Exception as error:
            return self._reject(f"access_nizk_backend:{type(error).__name__}")
        if proof_ok is not True:
            return self._reject("access_nizk_invalid")

        if getattr(self._kem_backend, "suite_id", None) != request.suite_id:
            return self._reject("kem_backend_suite_mismatch")
        try:
            kem_key_ok = self._kem_backend.validate_public_key(request.ue_kem_epk)
        except Exception as error:
            return self._reject(f"kem_backend:{type(error).__name__}")
        if kem_key_ok is not True:
            return self._reject("ue_kem_public_key_invalid")

        try:
            admitted = self._admission_policy.admit(
                request,
                ticket,
                checked_at=now,
            )
        except Exception as error:
            return self._reject(f"admission_backend:{type(error).__name__}")
        if admitted is not True:
            return self._reject("admission_rejected")

        return PureCheckResultV2(
            True,
            (),
            ValidatedAccessRequestV2(
                request_bytes=encoded_request,
                request=request,
                configuration=configuration,
                ticket=ticket,
                identity=identity,
                access_statement=access_statement,
                request_core_digest=request_core_digest,
                request_digest=request_digest,
                attempt_id=attempt_id,
                revocation_query=revocation_query,
                revocation_generation=revocation.generation,
                checked_at=now,
            ),
        )


def fgs_pure_check_manifest() -> dict[str, object]:
    """Return path-free machine metadata for this bounded checkpoint."""

    return {
        "format": "PQ-SAT-FGS-PURE-CHECK-PROCESSOR-v0.2",
        "access_protocol_version": 2,
        "processing_order": [
            "canonical_request",
            "authenticated_configuration",
            "trusted_time_and_freshness",
            "channel_binding",
            "stable_verify_ticket",
            "ticket_identity_and_request_digests",
            "query_bound_revocation_snapshot",
            "access_nizk",
            "ue_kem_public_key",
            "pure_admission",
            "validated_request_for_reserve",
        ],
        "ticket_consumption_identity": (
            "ctx || visible_serial || payload_digest_d_M"
        ),
        "revocation_query_domain": REVOCATION_QUERY_LABEL.decode("ascii"),
        "claim_boundary": {
            "stable_verify_ticket_contract_integrated": True,
            "single_captured_time_used_for_ticket_and_access_checks": True,
            "configuration_boundary_implemented": True,
            "revocation_boundary_implemented": True,
            "channel_binding_boundary_implemented": True,
            "access_nizk_boundary_implemented": True,
            "kem_public_key_validation_boundary_implemented": True,
            "pure_admission_boundary_implemented": True,
            "processor_mutates_replay_state": False,
            "production_access_configuration_authenticated": False,
            "production_verify_ticket_backend_instantiated": False,
            "production_access_nizk_instantiated": False,
            "production_pq_ake_instantiated": False,
            "durable_or_distributed_replay_store_implemented": False,
            "production_ready": False,
            "proof_closed": False,
        },
    }
