"""UE-side durable wallet contracts for satellite access v0.2.

This module defines the state transition and release ordering.  Persistence,
record protection, and device security are supplied by separate backends.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Mapping, Protocol

from .access import (
    DIGEST_BYTES,
    REFERENCE_PROOF_SUITE_REGISTRY,
    REFERENCE_SUITE_REGISTRY,
    AccessAcceptV2,
    ProofLimitsV2,
    SuiteLimitsV2,
    decode_access_accept,
    derive_response_digest,
    derive_transcript_digest,
    encode_access_accept,
    encode_session_activate,
    validate_response_binding,
)
from .processor import AccessClockV2
from .ue import (
    UEAccessAcceptProcessorV2,
    UEAccessAttemptStateV2,
    UEAcceptedSessionV2,
    UEResponseProcessResultV2,
    validate_ue_acceptance_time,
    validate_ue_access_attempt,
)


PRODUCTION_READY = False


def _fixed(value: bytes, size: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    return value


def _u64(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value < (1 << 64):
        raise ValueError(f"{name} does not fit uint64")
    return value


class UEWalletStateV2(IntEnum):
    PREPARED = 1
    ACCEPTED_PENDING_ACTIVATION = 2


@dataclass(frozen=True)
class UEWalletRecordV2:
    """Exact recoverable UE state for one spendable ticket attempt."""

    state: UEWalletStateV2
    revision: int
    attempt: UEAccessAttemptStateV2
    response_bytes: bytes | None = None
    session: UEAcceptedSessionV2 | None = None

    @property
    def use_key(self) -> bytes:
        return self.derive_use_key()

    def derive_use_key(
        self,
        *,
        suite_registry: Mapping[
            int, SuiteLimitsV2
        ] = REFERENCE_SUITE_REGISTRY,
        proof_registry: Mapping[
            int, ProofLimitsV2
        ] = REFERENCE_PROOF_SUITE_REGISTRY,
    ) -> bytes:
        return validate_ue_access_attempt(
            self.attempt,
            suite_registry=suite_registry,
            proof_registry=proof_registry,
        ).identity.use_key

    def validate(
        self,
        *,
        suite_registry: Mapping[
            int, SuiteLimitsV2
        ] = REFERENCE_SUITE_REGISTRY,
        proof_registry: Mapping[
            int, ProofLimitsV2
        ] = REFERENCE_PROOF_SUITE_REGISTRY,
    ) -> None:
        if not isinstance(self.state, UEWalletStateV2):
            raise TypeError("wallet state has the wrong type")
        if isinstance(self.revision, bool) or not isinstance(self.revision, int):
            raise TypeError("wallet revision must be an integer")
        validated = validate_ue_access_attempt(
            self.attempt,
            suite_registry=suite_registry,
            proof_registry=proof_registry,
        )
        expected_revision = {
            UEWalletStateV2.PREPARED: 1,
            UEWalletStateV2.ACCEPTED_PENDING_ACTIVATION: 2,
        }[self.state]
        if self.revision != expected_revision:
            raise ValueError("wallet state has the wrong revision")

        if self.state is UEWalletStateV2.PREPARED:
            if self.response_bytes is not None or self.session is not None:
                raise ValueError("prepared wallet record contains session output")
            return

        if not isinstance(self.response_bytes, bytes) or not self.response_bytes:
            raise ValueError("accepted wallet record lacks exact response bytes")
        if not isinstance(self.session, UEAcceptedSessionV2):
            raise TypeError("accepted wallet record lacks a session")
        response = decode_access_accept(self.response_bytes, suite_registry)
        if encode_access_accept(response, suite_registry) != self.response_bytes:
            raise ValueError("wallet response is non-canonical")
        validate_response_binding(
            validated.request,
            response,
            use_key=validated.identity.use_key,
            suite_registry=suite_registry,
            proof_registry=proof_registry,
        )
        self.session.validate()
        session_bindings = (
            (self.session.suite_id, response.suite_id),
            (self.session.identity, validated.identity),
            (
                self.session.system_config_digest,
                self.attempt.configuration.system_config_digest,
            ),
            (
                self.session.acceptance_domain_digest,
                self.attempt.configuration.acceptance_domain_digest,
            ),
            (self.session.request_digest, validated.request_digest),
            (self.session.attempt_id, validated.attempt_id),
            (
                self.session.transcript_digest,
                derive_transcript_digest(response, suite_registry),
            ),
            (
                self.session.response_digest,
                derive_response_digest(response, suite_registry),
            ),
            (self.session.session_id, response.session_id),
            (self.session.activation_deadline, response.activation_deadline),
            (self.session.session_expiry, response.session_expiry),
        )
        if any(actual != expected for actual, expected in session_bindings):
            raise ValueError("wallet response and accepted session differ")
        if self.session.accepted_at < self.attempt.created_at:
            raise ValueError("session predates wallet attempt")
        validate_ue_acceptance_time(
            self.attempt,
            response,
            self.session.accepted_at,
        )
        if (
            encode_session_activate(self.session.activation, suite_registry)
            != self.session.activation_bytes
        ):
            raise ValueError("wallet activation is non-canonical")


class UEWalletTransitionKindV2(Enum):
    CREATED = "created"
    EXISTING = "existing"


@dataclass(frozen=True)
class UEWalletTransitionV2:
    kind: UEWalletTransitionKindV2
    record: UEWalletRecordV2

    def validate(self) -> None:
        if not isinstance(self.kind, UEWalletTransitionKindV2):
            raise TypeError("wallet transition kind has the wrong type")
        if not isinstance(self.record, UEWalletRecordV2):
            raise TypeError("wallet transition record has the wrong type")
        self.record.validate()


class UEWalletStoreV2(Protocol):
    def prepare(
        self,
        attempt: UEAccessAttemptStateV2,
    ) -> UEWalletTransitionV2: ...

    def load(self, use_key: bytes) -> UEWalletRecordV2 | None: ...

    def accept(
        self,
        attempt: UEAccessAttemptStateV2,
        response_bytes: bytes,
        session: UEAcceptedSessionV2,
    ) -> UEWalletTransitionV2: ...


class UEWalletProcessDispositionV2(Enum):
    ACCEPTED_NEW = "accepted_new"
    ACCEPTED_RECOVERED = "accepted_recovered"
    REJECTED = "rejected"
    COMMIT_UNCERTAIN = "commit_uncertain"


@dataclass(frozen=True)
class UEWalletProcessResultV2:
    accepted: bool
    disposition: UEWalletProcessDispositionV2
    failures: tuple[str, ...]
    response: AccessAcceptV2 | None
    session: UEAcceptedSessionV2 | None


class UEWalletAccessProcessorV2:
    """Release a UE session only after an exact wallet transition commits."""

    production_ready = False

    def __init__(
        self,
        *,
        wallet: UEWalletStoreV2,
        response_processor: UEAccessAcceptProcessorV2,
        clock: AccessClockV2,
        suite_registry: Mapping[
            int, SuiteLimitsV2
        ] = REFERENCE_SUITE_REGISTRY,
    ) -> None:
        self._wallet = wallet
        self._response_processor = response_processor
        self._clock = clock
        self._suite_registry = suite_registry

    @staticmethod
    def _reject(failure: str) -> UEWalletProcessResultV2:
        return UEWalletProcessResultV2(
            False,
            UEWalletProcessDispositionV2.REJECTED,
            (failure,),
            None,
            None,
        )

    @staticmethod
    def _uncertain(failure: str) -> UEWalletProcessResultV2:
        return UEWalletProcessResultV2(
            False,
            UEWalletProcessDispositionV2.COMMIT_UNCERTAIN,
            (failure,),
            None,
            None,
        )

    def _recover(
        self,
        record: UEWalletRecordV2,
        encoded_response: bytes,
    ) -> UEWalletProcessResultV2:
        if record.response_bytes != encoded_response or record.session is None:
            return self._reject("wallet_response_mismatch")
        try:
            now = self._clock.now()
            _u64(now, "wallet recovery time")
        except Exception as error:
            return self._reject(f"wallet_clock:{type(error).__name__}")
        if now > record.session.activation_deadline:
            return self._reject("wallet_activation_deadline_expired")
        if now > record.session.session_expiry:
            return self._reject("wallet_session_expired")
        try:
            response = decode_access_accept(
                record.response_bytes,
                self._suite_registry,
            )
        except Exception as error:
            return self._reject(f"wallet_response:{type(error).__name__}")
        return UEWalletProcessResultV2(
            True,
            UEWalletProcessDispositionV2.ACCEPTED_RECOVERED,
            (),
            response,
            record.session,
        )

    def process(
        self,
        use_key: bytes,
        encoded_response: bytes,
    ) -> UEWalletProcessResultV2:
        try:
            canonical_use_key = _fixed(use_key, DIGEST_BYTES, "use_key")
            if not isinstance(encoded_response, bytes) or not encoded_response:
                raise ValueError("encoded response must be non-empty bytes")
            record = self._wallet.load(canonical_use_key)
            if record is None:
                return self._reject("wallet_attempt_unavailable")
            if not isinstance(record, UEWalletRecordV2):
                raise TypeError("wallet returned the wrong record type")
            record.validate()
            if record.use_key != canonical_use_key:
                raise ValueError("wallet record use key mismatch")
        except Exception as error:
            return self._reject(f"wallet_load:{type(error).__name__}")

        if record.state is UEWalletStateV2.ACCEPTED_PENDING_ACTIVATION:
            return self._recover(record, encoded_response)
        if record.state is not UEWalletStateV2.PREPARED:
            return self._reject("wallet_state_unsupported")

        try:
            processed = self._response_processor.process(
                encoded_response,
                record.attempt,
            )
        except Exception as error:
            return self._reject(
                f"response_processor_backend:{type(error).__name__}"
            )
        if not isinstance(processed, UEResponseProcessResultV2):
            return self._reject("response_processor_output:TypeError")
        if processed.accepted is not True or processed.session is None:
            failure = processed.failures[0] if processed.failures else "unknown"
            return self._reject(f"response_processor:{failure}")

        try:
            transition = self._wallet.accept(
                record.attempt,
                encoded_response,
                processed.session,
            )
        except Exception as error:
            return self._uncertain(f"wallet_commit:{type(error).__name__}")
        try:
            if not isinstance(transition, UEWalletTransitionV2):
                raise TypeError("wallet returned the wrong transition type")
            transition.validate()
            committed = self._wallet.load(canonical_use_key)
            if not isinstance(committed, UEWalletRecordV2):
                raise TypeError("committed wallet record is unavailable")
            committed.validate()
            if (
                committed.state
                is not UEWalletStateV2.ACCEPTED_PENDING_ACTIVATION
                or committed.attempt != record.attempt
                or committed.response_bytes != encoded_response
                or committed.session != processed.session
                or committed.use_key != canonical_use_key
                or transition.record != committed
            ):
                raise ValueError("wallet commit output mismatch")
        except Exception as error:
            return self._uncertain(f"wallet_commit_output:{type(error).__name__}")

        disposition = (
            UEWalletProcessDispositionV2.ACCEPTED_NEW
            if transition.kind is UEWalletTransitionKindV2.CREATED
            else UEWalletProcessDispositionV2.ACCEPTED_RECOVERED
        )
        return UEWalletProcessResultV2(
            True,
            disposition,
            (),
            processed.response,
            committed.session,
        )


def ue_wallet_checkpoint_manifest() -> dict[str, object]:
    return {
        "format": "PQ-SAT-UE-WALLET-CHECKPOINT-v0.2",
        "access_protocol_version": 2,
        "states": [state.name for state in UEWalletStateV2],
        "transitions": [
            "absent_to_prepared",
            "prepared_to_accepted_pending_activation",
            "exact_prepare_retry_returns_existing",
            "exact_accept_retry_returns_existing",
        ],
        "release_order": [
            "load_and_validate_protected_attempt",
            "verify_access_accept",
            "atomic_wallet_accept_commit",
            "validate_committed_exact_output",
            "release_ue_session_material",
        ],
        "claim_boundary": {
            "durable_sqlite_reference_store_implemented": True,
            "exact_m1_restart_recovery_implemented": True,
            "idempotent_accept_transition_implemented": True,
            "release_after_commit_implemented": True,
            "record_protection_backend_boundary_implemented": True,
            "production_record_protection_instantiated": False,
            "rollback_protection_implemented": False,
            "secure_key_erasure_implemented": False,
            "physical_power_loss_tested": False,
            "distributed_wallet_implemented": False,
            "first_protected_application_record_implemented": False,
            "production_ready": False,
            "proof_closed": False,
        },
    }
