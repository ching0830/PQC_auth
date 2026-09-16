"""Authenticated executor and trusted-clock boundary for reconciliation.

This module removes raw executor identifiers from the gated runner API.  It
does not instantiate an operator credential scheme or a trusted clock; those
remain injected, explicitly qualified backend responsibilities.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Protocol

from .reconciliation import (
    DIGEST_BYTES,
    ReservationReconciliationCoordinatorV2,
    ReservationReconciliationInvocationV2,
    ReservationReconciliationPolicyV2,
)
from .reconciliation_lease import (
    LeaseFencedResumableReconciliationJournalV2,
    LeaseFencedResumableReconciliationRunnerV2,
    ReconciliationExecutionLeasePolicyV2,
)
from .reconciliation_resume import (
    ResumableReconciliationDispositionV2,
    ResumableReconciliationResultV2,
)


EXECUTION_SCOPE_FORMAT = "PQ-SAT/FGS-RECONCILIATION-EXECUTION-SCOPE/v0.2"
EXECUTOR_AUTHORIZATION_FORMAT = (
    "PQ-SAT/FGS-RECONCILIATION-EXECUTOR-AUTHORIZATION/v0.2"
)
EXECUTOR_CREDENTIAL_FORMAT = (
    "PQ-SAT/FGS-RECONCILIATION-EXECUTOR-CREDENTIAL/v0.2"
)
SCOPE_DIGEST_DOMAIN = b"PQ-SAT/FGS-RECONCILIATION-SCOPE-DIGEST/v0.2"
OWNER_ID_DOMAIN = b"PQ-SAT/FGS-RECONCILIATION-OWNER-ID/v0.2"
CREDENTIAL_AUTHENTICATION_DOMAIN = (
    b"PQ-SAT/FGS-RECONCILIATION-EXECUTOR-AUTH/v0.2"
)
MAX_SCOPE_BYTES = 4_096
MAX_AUTHORIZATION_BYTES = 4_096
MAX_CREDENTIAL_BYTES = 1 << 20
MAX_AUTHENTICATION_BYTES = 1 << 19
SQLITE_INT64_MAX = (1 << 63) - 1
UINT64_MAX = (1 << 64) - 1
PRODUCTION_READY = False


def _fixed(value: bytes, size: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    return value


def _identifier(value: bytes, name: str) -> bytes:
    identifier = _fixed(value, DIGEST_BYTES, name)
    if identifier == bytes(DIGEST_BYTES):
        raise ValueError(f"{name} must not be all zero")
    return identifier


def _int64(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value <= SQLITE_INT64_MAX:
        raise ValueError(f"{name} is outside SQLite int64")
    return value


def _uint64(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value <= UINT64_MAX:
        raise ValueError(f"{name} is outside uint64")
    return value


def _hex(value: bytes, name: str) -> str:
    return _identifier(value, name).hex()


def _unhex(value: object, name: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a hex string")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{name} is not hexadecimal") from error
    if decoded.hex() != value:
        raise ValueError(f"{name} is not canonical lowercase hex")
    return _identifier(decoded, name)


def _canonical_json(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _decode_object(encoded: bytes, maximum: int, name: str) -> dict[str, object]:
    if not isinstance(encoded, bytes):
        raise TypeError(f"{name} must be bytes")
    if not 0 < len(encoded) <= maximum:
        raise ValueError(f"{name} is empty or exceeds its bound")
    try:
        value = json.loads(encoded.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{name} is not canonical JSON") from error
    if not isinstance(value, dict) or not all(
        isinstance(key, str) for key in value
    ):
        raise TypeError(f"{name} must be a string-keyed object")
    return value


@dataclass(frozen=True)
class ReconciliationExecutionScopeV2:
    """Verifier-owned identities defining one authorized execution domain."""

    system_context_digest: bytes
    replay_store_id: bytes
    reconciliation_journal_id: bytes
    clock_id: bytes
    credential_verifier_id: bytes
    batch_limit: int
    minimum_stale_seconds: int
    lease_seconds: int
    renewal_margin_seconds: int

    def __post_init__(self) -> None:
        for name in (
            "system_context_digest",
            "replay_store_id",
            "reconciliation_journal_id",
            "clock_id",
            "credential_verifier_id",
        ):
            _identifier(getattr(self, name), name)
        ReconciliationExecutionLeasePolicyV2(
            self.lease_seconds,
            self.renewal_margin_seconds,
        )
        ReservationReconciliationPolicyV2(
            self.batch_limit,
            self.minimum_stale_seconds,
        )

    @property
    def lease_policy(self) -> ReconciliationExecutionLeasePolicyV2:
        return ReconciliationExecutionLeasePolicyV2(
            self.lease_seconds,
            self.renewal_margin_seconds,
        )

    @property
    def reconciliation_policy(self) -> ReservationReconciliationPolicyV2:
        return ReservationReconciliationPolicyV2(
            self.batch_limit,
            self.minimum_stale_seconds,
        )

    @property
    def digest(self) -> bytes:
        return hashlib.shake_256(
            SCOPE_DIGEST_DOMAIN + encode_reconciliation_execution_scope(self)
        ).digest(DIGEST_BYTES)


def encode_reconciliation_execution_scope(
    scope: ReconciliationExecutionScopeV2,
) -> bytes:
    if not isinstance(scope, ReconciliationExecutionScopeV2):
        raise TypeError("execution scope has the wrong type")
    encoded = _canonical_json(
        {
            "batch_limit": scope.batch_limit,
            "clock_id": _hex(scope.clock_id, "clock_id"),
            "credential_verifier_id": _hex(
                scope.credential_verifier_id,
                "credential_verifier_id",
            ),
            "format": EXECUTION_SCOPE_FORMAT,
            "lease_seconds": scope.lease_seconds,
            "minimum_stale_seconds": scope.minimum_stale_seconds,
            "reconciliation_journal_id": _hex(
                scope.reconciliation_journal_id,
                "reconciliation_journal_id",
            ),
            "renewal_margin_seconds": scope.renewal_margin_seconds,
            "replay_store_id": _hex(scope.replay_store_id, "replay_store_id"),
            "system_context_digest": _hex(
                scope.system_context_digest,
                "system_context_digest",
            ),
        }
    )
    if len(encoded) > MAX_SCOPE_BYTES:
        raise ValueError("encoded execution scope exceeds its bound")
    return encoded


def decode_reconciliation_execution_scope(
    encoded: bytes,
) -> ReconciliationExecutionScopeV2:
    value = _decode_object(encoded, MAX_SCOPE_BYTES, "execution scope")
    expected = {
        "batch_limit",
        "clock_id",
        "credential_verifier_id",
        "format",
        "lease_seconds",
        "minimum_stale_seconds",
        "reconciliation_journal_id",
        "renewal_margin_seconds",
        "replay_store_id",
        "system_context_digest",
    }
    if set(value) != expected:
        raise ValueError("execution scope has unknown or missing fields")
    if value["format"] != EXECUTION_SCOPE_FORMAT:
        raise ValueError("execution scope format is unknown")
    scope = ReconciliationExecutionScopeV2(
        system_context_digest=_unhex(
            value["system_context_digest"],
            "system_context_digest",
        ),
        replay_store_id=_unhex(value["replay_store_id"], "replay_store_id"),
        reconciliation_journal_id=_unhex(
            value["reconciliation_journal_id"],
            "reconciliation_journal_id",
        ),
        clock_id=_unhex(value["clock_id"], "clock_id"),
        credential_verifier_id=_unhex(
            value["credential_verifier_id"],
            "credential_verifier_id",
        ),
        batch_limit=_uint64(value["batch_limit"], "batch_limit"),
        minimum_stale_seconds=_uint64(
            value["minimum_stale_seconds"],
            "minimum_stale_seconds",
        ),
        lease_seconds=_int64(value["lease_seconds"], "lease_seconds"),
        renewal_margin_seconds=_int64(
            value["renewal_margin_seconds"],
            "renewal_margin_seconds",
        ),
    )
    if encode_reconciliation_execution_scope(scope) != encoded:
        raise ValueError("execution scope encoding is not canonical")
    return scope


@dataclass(frozen=True)
class ReconciliationExecutorAuthorizationV2:
    invocation_id: bytes
    execution_scope_digest: bytes
    operator_id: bytes
    executor_instance_id: bytes
    credential_id: bytes
    not_before: int
    not_after: int

    def __post_init__(self) -> None:
        for name in (
            "invocation_id",
            "execution_scope_digest",
            "operator_id",
            "executor_instance_id",
            "credential_id",
        ):
            _identifier(getattr(self, name), name)
        not_before = _int64(self.not_before, "not_before")
        not_after = _int64(self.not_after, "not_after")
        if not_after <= not_before:
            raise ValueError("authorization validity interval is empty")

    @property
    def owner_id(self) -> bytes:
        return hashlib.shake_256(
            OWNER_ID_DOMAIN + encode_reconciliation_executor_authorization(self)
        ).digest(DIGEST_BYTES)


def encode_reconciliation_executor_authorization(
    authorization: ReconciliationExecutorAuthorizationV2,
) -> bytes:
    if not isinstance(authorization, ReconciliationExecutorAuthorizationV2):
        raise TypeError("executor authorization has the wrong type")
    encoded = _canonical_json(
        {
            "credential_id": _hex(authorization.credential_id, "credential_id"),
            "execution_scope_digest": _hex(
                authorization.execution_scope_digest,
                "execution_scope_digest",
            ),
            "executor_instance_id": _hex(
                authorization.executor_instance_id,
                "executor_instance_id",
            ),
            "format": EXECUTOR_AUTHORIZATION_FORMAT,
            "invocation_id": _hex(authorization.invocation_id, "invocation_id"),
            "not_after": authorization.not_after,
            "not_before": authorization.not_before,
            "operator_id": _hex(authorization.operator_id, "operator_id"),
        }
    )
    if len(encoded) > MAX_AUTHORIZATION_BYTES:
        raise ValueError("encoded executor authorization exceeds its bound")
    return encoded


def decode_reconciliation_executor_authorization(
    encoded: bytes,
) -> ReconciliationExecutorAuthorizationV2:
    value = _decode_object(
        encoded,
        MAX_AUTHORIZATION_BYTES,
        "executor authorization",
    )
    expected = {
        "credential_id",
        "execution_scope_digest",
        "executor_instance_id",
        "format",
        "invocation_id",
        "not_after",
        "not_before",
        "operator_id",
    }
    if set(value) != expected:
        raise ValueError("executor authorization has unknown or missing fields")
    if value["format"] != EXECUTOR_AUTHORIZATION_FORMAT:
        raise ValueError("executor authorization format is unknown")
    authorization = ReconciliationExecutorAuthorizationV2(
        invocation_id=_unhex(value["invocation_id"], "invocation_id"),
        execution_scope_digest=_unhex(
            value["execution_scope_digest"],
            "execution_scope_digest",
        ),
        operator_id=_unhex(value["operator_id"], "operator_id"),
        executor_instance_id=_unhex(
            value["executor_instance_id"],
            "executor_instance_id",
        ),
        credential_id=_unhex(value["credential_id"], "credential_id"),
        not_before=_int64(value["not_before"], "not_before"),
        not_after=_int64(value["not_after"], "not_after"),
    )
    if encode_reconciliation_executor_authorization(authorization) != encoded:
        raise ValueError("executor authorization encoding is not canonical")
    return authorization


@dataclass(frozen=True)
class AuthenticatedReconciliationExecutorV2:
    authorization: ReconciliationExecutorAuthorizationV2
    authentication: bytes

    def __post_init__(self) -> None:
        if not isinstance(
            self.authorization,
            ReconciliationExecutorAuthorizationV2,
        ):
            raise TypeError("executor authorization has the wrong type")
        if not isinstance(self.authentication, bytes):
            raise TypeError("executor authentication must be bytes")
        if not 0 < len(self.authentication) <= MAX_AUTHENTICATION_BYTES:
            raise ValueError("executor authentication length is outside bounds")

    @property
    def authentication_message(self) -> bytes:
        return CREDENTIAL_AUTHENTICATION_DOMAIN + (
            encode_reconciliation_executor_authorization(self.authorization)
        )


def encode_authenticated_reconciliation_executor(
    credential: AuthenticatedReconciliationExecutorV2,
) -> bytes:
    if not isinstance(credential, AuthenticatedReconciliationExecutorV2):
        raise TypeError("executor credential has the wrong type")
    encoded = _canonical_json(
        {
            "authentication": credential.authentication.hex(),
            "authorization": encode_reconciliation_executor_authorization(
                credential.authorization
            ).hex(),
            "format": EXECUTOR_CREDENTIAL_FORMAT,
        }
    )
    if len(encoded) > MAX_CREDENTIAL_BYTES:
        raise ValueError("encoded executor credential exceeds its bound")
    return encoded


def decode_authenticated_reconciliation_executor(
    encoded: bytes,
) -> AuthenticatedReconciliationExecutorV2:
    value = _decode_object(encoded, MAX_CREDENTIAL_BYTES, "executor credential")
    if set(value) != {"authentication", "authorization", "format"}:
        raise ValueError("executor credential has unknown or missing fields")
    if value["format"] != EXECUTOR_CREDENTIAL_FORMAT:
        raise ValueError("executor credential format is unknown")
    authentication_value = value["authentication"]
    authorization_value = value["authorization"]
    if not isinstance(authentication_value, str) or not isinstance(
        authorization_value,
        str,
    ):
        raise TypeError("executor credential byte fields must be hex strings")
    try:
        authentication = bytes.fromhex(authentication_value)
        authorization_bytes = bytes.fromhex(authorization_value)
    except ValueError as error:
        raise ValueError("executor credential byte field is not hexadecimal") from error
    if (
        authentication.hex() != authentication_value
        or authorization_bytes.hex() != authorization_value
    ):
        raise ValueError("executor credential hex is not canonical lowercase")
    credential = AuthenticatedReconciliationExecutorV2(
        authorization=decode_reconciliation_executor_authorization(
            authorization_bytes
        ),
        authentication=authentication,
    )
    if encode_authenticated_reconciliation_executor(credential) != encoded:
        raise ValueError("executor credential encoding is not canonical")
    return credential


class ReconciliationExecutorCredentialVerifierV2(Protocol):
    verifier_id: bytes
    production_ready: bool

    def verify(self, message: bytes, authentication: bytes) -> bool: ...


class TrustedReconciliationLeaseClockV2(Protocol):
    clock_id: bytes
    production_ready: bool

    def now(self) -> int: ...


class _AuthorizedLeaseClockV2:
    """Reuse the authentication-time sample and police every later sample."""

    def __init__(
        self,
        *,
        inner: TrustedReconciliationLeaseClockV2,
        authorization: ReconciliationExecutorAuthorizationV2,
        first_observation: int,
    ) -> None:
        self._inner = inner
        self._authorization = authorization
        self._next_observation: int | None = first_observation
        self._last_observation: int | None = None

    def now(self) -> int:
        if self._next_observation is None:
            try:
                observed_at = _int64(self._inner.now(), "trusted lease clock")
            except Exception as error:
                raise RuntimeError(
                    f"trusted clock failed: {type(error).__name__}"
                ) from error
        else:
            observed_at = self._next_observation
            self._next_observation = None
        if (
            self._last_observation is not None
            and observed_at < self._last_observation
        ):
            raise RuntimeError("trusted lease clock moved backwards")
        if not (
            self._authorization.not_before
            <= observed_at
            < self._authorization.not_after
        ):
            raise RuntimeError("executor authorization is not currently valid")
        self._last_observation = observed_at
        return observed_at


class CredentialedLeaseFencedResumableReconciliationRunnerV2:
    """Authenticate an executor and clock domain before entering the lease runner."""

    production_ready = False

    def __init__(
        self,
        *,
        coordinator: ReservationReconciliationCoordinatorV2,
        journal: LeaseFencedResumableReconciliationJournalV2,
        execution_scope: ReconciliationExecutionScopeV2,
        trusted_clock: TrustedReconciliationLeaseClockV2,
        credential_verifier: ReconciliationExecutorCredentialVerifierV2,
        encoded_executor_credential: bytes,
    ) -> None:
        if not isinstance(execution_scope, ReconciliationExecutionScopeV2):
            raise TypeError("execution_scope has the wrong type")
        if not isinstance(encoded_executor_credential, bytes):
            raise TypeError("encoded_executor_credential must be bytes")
        self._coordinator = coordinator
        self._journal = journal
        self._scope = execution_scope
        self._clock = trusted_clock
        self._verifier = credential_verifier
        self._credential_bytes = encoded_executor_credential

    @staticmethod
    def _rejected(failure: str) -> ResumableReconciliationResultV2:
        return ResumableReconciliationResultV2(
            ResumableReconciliationDispositionV2.REJECTED,
            None,
            (failure,),
        )

    def _establish_context(
        self,
        invocation: ReservationReconciliationInvocationV2,
    ) -> tuple[
        ReconciliationExecutorAuthorizationV2,
        _AuthorizedLeaseClockV2,
    ]:
        clock_id = _identifier(
            getattr(self._clock, "clock_id", None),
            "trusted clock_id",
        )
        verifier_id = _identifier(
            getattr(self._verifier, "verifier_id", None),
            "credential verifier_id",
        )
        if clock_id != self._scope.clock_id:
            raise ValueError("trusted clock identity does not match scope")
        if verifier_id != self._scope.credential_verifier_id:
            raise ValueError("credential verifier identity does not match scope")
        if getattr(self._coordinator, "policy", None) != (
            self._scope.reconciliation_policy
        ):
            raise ValueError("reconciliation policy does not match scope")
        if getattr(self._clock, "production_ready", False) is not True:
            raise ValueError("trusted clock backend is not production-ready")
        if getattr(self._verifier, "production_ready", False) is not True:
            raise ValueError("credential verifier is not production-ready")
        credential = decode_authenticated_reconciliation_executor(
            self._credential_bytes
        )
        authorization = credential.authorization
        if authorization.invocation_id != invocation.invocation_id:
            raise ValueError("executor authorization invocation mismatch")
        if authorization.execution_scope_digest != self._scope.digest:
            raise ValueError("executor authorization scope mismatch")
        try:
            observed_at = _int64(self._clock.now(), "trusted lease clock")
        except Exception as error:
            raise RuntimeError(
                f"trusted clock failed: {type(error).__name__}"
            ) from error
        if not authorization.not_before <= observed_at < authorization.not_after:
            raise ValueError("executor authorization is not currently valid")
        try:
            accepted = self._verifier.verify(
                credential.authentication_message,
                credential.authentication,
            )
        except Exception as error:
            raise RuntimeError(
                f"credential verification failed: {type(error).__name__}"
            ) from error
        if accepted is not True:
            raise ValueError("executor credential authentication is invalid")
        return authorization, _AuthorizedLeaseClockV2(
            inner=self._clock,
            authorization=authorization,
            first_observation=observed_at,
        )

    def run_once(
        self,
        invocation: ReservationReconciliationInvocationV2,
    ) -> ResumableReconciliationResultV2:
        if not isinstance(invocation, ReservationReconciliationInvocationV2):
            raise TypeError("invocation has the wrong type")
        try:
            authorization, clock = self._establish_context(invocation)
        except Exception as error:
            return self._rejected(
                f"execution_context:{type(error).__name__}"
            )
        return LeaseFencedResumableReconciliationRunnerV2(
            coordinator=self._coordinator,
            journal=self._journal,
            lease_clock=clock,
            owner_id=authorization.owner_id,
            lease_policy=self._scope.lease_policy,
        ).run_once(invocation)


def reconciliation_execution_context_manifest() -> dict[str, object]:
    return {
        "format": "PQ-SAT-FGS-RECONCILIATION-EXECUTION-CONTEXT-v0.2",
        "processing_order": [
            "validate_pinned_clock_and_verifier_identities",
            "require_structurally_production_ready_backends",
            "strictly_decode_executor_credential",
            "bind_authorization_to_invocation_and_execution_scope",
            "sample_trusted_clock_and_check_authorization_interval",
            "verify_exact_domain_separated_executor_authorization",
            "derive_owner_id_from_authenticated_authorization",
            "recheck_clock_monotonicity_and_authorization_on_each_lease_sample",
            "enter_lease_fenced_resumable_runner",
        ],
        "claim_boundary": {
            "canonical_execution_scope_implemented": True,
            "canonical_executor_authorization_implemented": True,
            "canonical_executor_credential_envelope_implemented": True,
            "credential_checked_before_journal_or_replay_mutation": True,
            "authorization_bound_to_invocation_scope_and_validity": True,
            "clock_and_verifier_identities_pinned": True,
            "reconciliation_policy_pinned": True,
            "owner_id_derived_from_authenticated_authorization": True,
            "authorization_validity_rechecked_on_each_lease_clock_sample": True,
            "per_runner_clock_rollback_rejected": True,
            "backend_readiness_gate_implemented": True,
            "concrete_operator_credential_scheme_instantiated": False,
            "trusted_clock_backend_instantiated": False,
            "authenticated_execution_scope_provider_instantiated": False,
            "actual_store_and_journal_identity_attested": False,
            "backend_self_assertion_independently_certified": False,
            "unique_live_executor_credential_enforced": False,
            "credential_revocation_or_replay_store_implemented": False,
            "cross_process_or_reboot_clock_rollback_detection": False,
            "automatic_background_scheduler_implemented": False,
            "physical_power_loss_tested": False,
            "production_ready": False,
        },
    }
