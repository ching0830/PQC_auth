"""Single-host execution lease for resumable reconciliation.

The lease fences journal progress and receipt writes.  It does not make the
separate replay and journal databases atomic, and it is not a distributed
consensus lease.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from .reconciliation import (
    DIGEST_BYTES,
    ReservationReconciliationCoordinatorV2,
    ReservationReconciliationInvocationV2,
    ReservationReconciliationPolicyV2,
    ReservationReconciliationRunResultV2,
)
from .reconciliation_audit import (
    ReconciliationAuditIntentV2,
    ReconciliationAuditIntentWriteResultV2,
    ReconciliationAuditReceiptWriteResultV2,
)
from .reconciliation_resume import (
    ReconciliationPlanWriteResultV2,
    ReconciliationProgressV2,
    ReconciliationProgressWriteResultV2,
    ResumableJournaledReservationReconciliationRunnerV2,
    ResumableReconciliationJournalV2,
    ResumableReconciliationResultV2,
)


LEASE_FORMAT = "PQ-SAT/FGS-RECONCILIATION-EXECUTION-LEASE/v0.2"
MAX_LEASE_BYTES = 2_048
MAX_LEASE_SECONDS = 86_400
SQLITE_INT64_MAX = (1 << 63) - 1
PRODUCTION_READY = False


def _fixed(value: bytes, size: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    return value


def _int64(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value <= SQLITE_INT64_MAX:
        raise ValueError(f"{name} is outside SQLite int64")
    return value


def _hex(value: bytes, name: str) -> str:
    return _fixed(value, DIGEST_BYTES, name).hex()


def _unhex(value: object, name: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a hex string")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{name} is not hexadecimal") from error
    if decoded.hex() != value:
        raise ValueError(f"{name} is not canonical lowercase hex")
    return _fixed(decoded, DIGEST_BYTES, name)


@dataclass(frozen=True)
class ReconciliationExecutionLeasePolicyV2:
    lease_seconds: int
    renewal_margin_seconds: int

    def __post_init__(self) -> None:
        lease_seconds = _int64(self.lease_seconds, "lease_seconds")
        margin = _int64(
            self.renewal_margin_seconds,
            "renewal_margin_seconds",
        )
        if not 1 <= lease_seconds <= MAX_LEASE_SECONDS:
            raise ValueError("lease_seconds is outside bounds")
        if margin >= lease_seconds:
            raise ValueError("renewal margin must be smaller than lease")


@dataclass(frozen=True)
class ReconciliationExecutionLeaseV2:
    invocation_id: bytes
    owner_id: bytes
    lease_generation: int
    acquired_at: int
    lease_deadline: int
    lease_seconds: int
    renewal_margin_seconds: int

    def __post_init__(self) -> None:
        _fixed(self.invocation_id, DIGEST_BYTES, "lease invocation_id")
        _fixed(self.owner_id, DIGEST_BYTES, "lease owner_id")
        generation = _int64(self.lease_generation, "lease_generation")
        if generation == 0:
            raise ValueError("lease_generation must be positive")
        acquired_at = _int64(self.acquired_at, "lease acquired_at")
        deadline = _int64(self.lease_deadline, "lease_deadline")
        policy = ReconciliationExecutionLeasePolicyV2(
            self.lease_seconds,
            self.renewal_margin_seconds,
        )
        if acquired_at > SQLITE_INT64_MAX - policy.lease_seconds:
            raise ValueError("lease deadline overflows SQLite int64")
        if deadline != acquired_at + policy.lease_seconds:
            raise ValueError("lease deadline does not match policy")

    @property
    def policy(self) -> ReconciliationExecutionLeasePolicyV2:
        return ReconciliationExecutionLeasePolicyV2(
            self.lease_seconds,
            self.renewal_margin_seconds,
        )


def encode_reconciliation_execution_lease(
    lease: ReconciliationExecutionLeaseV2,
) -> bytes:
    if not isinstance(lease, ReconciliationExecutionLeaseV2):
        raise TypeError("lease has the wrong type")
    encoded = json.dumps(
        {
            "acquired_at": lease.acquired_at,
            "format": LEASE_FORMAT,
            "invocation_id": _hex(lease.invocation_id, "invocation_id"),
            "lease_deadline": lease.lease_deadline,
            "lease_generation": lease.lease_generation,
            "lease_seconds": lease.lease_seconds,
            "owner_id": _hex(lease.owner_id, "owner_id"),
            "renewal_margin_seconds": lease.renewal_margin_seconds,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    if len(encoded) > MAX_LEASE_BYTES:
        raise ValueError("encoded lease exceeds its bound")
    return encoded


def decode_reconciliation_execution_lease(
    encoded: bytes,
) -> ReconciliationExecutionLeaseV2:
    if not isinstance(encoded, bytes):
        raise TypeError("encoded lease must be bytes")
    if not 0 < len(encoded) <= MAX_LEASE_BYTES:
        raise ValueError("encoded lease is empty or exceeds its bound")
    try:
        value = json.loads(encoded.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("lease is not canonical JSON") from error
    if not isinstance(value, dict) or set(value) != {
        "acquired_at",
        "format",
        "invocation_id",
        "lease_deadline",
        "lease_generation",
        "lease_seconds",
        "owner_id",
        "renewal_margin_seconds",
    }:
        raise ValueError("lease has unknown or missing fields")
    if value["format"] != LEASE_FORMAT:
        raise ValueError("lease format is unknown")
    lease = ReconciliationExecutionLeaseV2(
        invocation_id=_unhex(value["invocation_id"], "invocation_id"),
        owner_id=_unhex(value["owner_id"], "owner_id"),
        lease_generation=_int64(
            value["lease_generation"],
            "lease_generation",
        ),
        acquired_at=_int64(value["acquired_at"], "acquired_at"),
        lease_deadline=_int64(value["lease_deadline"], "lease_deadline"),
        lease_seconds=_int64(value["lease_seconds"], "lease_seconds"),
        renewal_margin_seconds=_int64(
            value["renewal_margin_seconds"],
            "renewal_margin_seconds",
        ),
    )
    if encode_reconciliation_execution_lease(lease) != encoded:
        raise ValueError("lease encoding is not canonical")
    return lease


class ReconciliationLeaseAcquireDispositionV2(Enum):
    NEW = "new"
    EXISTING = "existing"
    TAKEOVER = "takeover"
    HELD_BY_PEER = "held_by_peer"
    TERMINAL = "terminal"


@dataclass(frozen=True)
class ReconciliationLeaseAcquireResultV2:
    disposition: ReconciliationLeaseAcquireDispositionV2
    lease: ReconciliationExecutionLeaseV2 | None

    @property
    def acquired(self) -> bool:
        return self.disposition in (
            ReconciliationLeaseAcquireDispositionV2.NEW,
            ReconciliationLeaseAcquireDispositionV2.EXISTING,
            ReconciliationLeaseAcquireDispositionV2.TAKEOVER,
        )

    def __post_init__(self) -> None:
        if not isinstance(
            self.disposition,
            ReconciliationLeaseAcquireDispositionV2,
        ):
            raise TypeError("lease acquire disposition has the wrong type")
        if self.lease is not None and not isinstance(
            self.lease,
            ReconciliationExecutionLeaseV2,
        ):
            raise TypeError("lease acquire value has the wrong type")
        if self.acquired != (self.lease is not None):
            raise ValueError("lease acquire fields disagree")


class ReconciliationLeaseUnavailable(RuntimeError):
    pass


class ReconciliationLeaseClockV2(Protocol):
    def now(self) -> int: ...


class LeaseFencedResumableReconciliationJournalV2(
    ResumableReconciliationJournalV2,
    Protocol,
):
    def acquire_execution_lease(
        self,
        *,
        invocation_id: bytes,
        owner_id: bytes,
        observed_at: int,
        policy: ReconciliationExecutionLeasePolicyV2,
    ) -> ReconciliationLeaseAcquireResultV2: ...

    def renew_execution_lease(
        self,
        lease: ReconciliationExecutionLeaseV2,
        *,
        observed_at: int,
    ) -> ReconciliationExecutionLeaseV2: ...

    def assert_execution_lease(
        self,
        lease: ReconciliationExecutionLeaseV2,
        *,
        observed_at: int,
    ) -> None: ...

    def append_progress_under_lease(
        self,
        progress: ReconciliationProgressV2,
        *,
        lease: ReconciliationExecutionLeaseV2,
        observed_at: int,
    ) -> ReconciliationProgressWriteResultV2: ...

    def append_receipt_under_lease(
        self,
        receipt: ReservationReconciliationRunResultV2,
        *,
        lease: ReconciliationExecutionLeaseV2,
        observed_at: int,
    ) -> ReconciliationAuditReceiptWriteResultV2: ...


class _ExecutionLeaseSessionV2:
    def __init__(
        self,
        *,
        journal: LeaseFencedResumableReconciliationJournalV2,
        clock: ReconciliationLeaseClockV2,
        owner_id: bytes,
        policy: ReconciliationExecutionLeasePolicyV2,
        invocation_id: bytes,
    ) -> None:
        self.journal = journal
        self.clock = clock
        self.owner_id = _fixed(owner_id, DIGEST_BYTES, "owner_id")
        self.policy = policy
        self.invocation_id = _fixed(
            invocation_id,
            DIGEST_BYTES,
            "invocation_id",
        )
        self.lease: ReconciliationExecutionLeaseV2 | None = None
        self.last_observed_at: int | None = None

    def _now(self) -> int:
        try:
            observed_at = _int64(self.clock.now(), "lease clock")
        except Exception as error:
            raise ReconciliationLeaseUnavailable(
                f"lease clock failed: {type(error).__name__}"
            ) from error
        if (
            self.last_observed_at is not None
            and observed_at < self.last_observed_at
        ):
            raise ReconciliationLeaseUnavailable("lease clock moved backwards")
        self.last_observed_at = observed_at
        return observed_at

    def _acquire(self, observed_at: int) -> ReconciliationExecutionLeaseV2:
        try:
            result = self.journal.acquire_execution_lease(
                invocation_id=self.invocation_id,
                owner_id=self.owner_id,
                observed_at=observed_at,
                policy=self.policy,
            )
        except Exception as error:
            raise ReconciliationLeaseUnavailable(
                f"lease acquisition failed: {type(error).__name__}"
            ) from error
        if not isinstance(result, ReconciliationLeaseAcquireResultV2):
            raise ReconciliationLeaseUnavailable("lease acquisition type mismatch")
        if not result.acquired or result.lease is None:
            raise ReconciliationLeaseUnavailable(
                f"lease unavailable: {result.disposition.value}"
            )
        lease = result.lease
        if (
            lease.invocation_id != self.invocation_id
            or lease.owner_id != self.owner_id
            or lease.policy != self.policy
            or not lease.acquired_at <= observed_at < lease.lease_deadline
        ):
            raise ReconciliationLeaseUnavailable(
                "lease acquisition binding mismatch"
            )
        if (
            result.disposition
            in (
                ReconciliationLeaseAcquireDispositionV2.NEW,
                ReconciliationLeaseAcquireDispositionV2.TAKEOVER,
            )
            and lease.acquired_at != observed_at
        ):
            raise ReconciliationLeaseUnavailable(
                "new lease observation mismatch"
            )
        try:
            self.journal.assert_execution_lease(
                lease,
                observed_at=observed_at,
            )
        except Exception as error:
            raise ReconciliationLeaseUnavailable(
                f"lease acquisition readback failed: {type(error).__name__}"
            ) from error
        self.lease = lease
        return lease

    def ensure(self) -> tuple[ReconciliationExecutionLeaseV2, int]:
        observed_at = self._now()
        lease = self.lease
        if lease is None:
            return self._acquire(observed_at), observed_at
        if observed_at < lease.acquired_at:
            raise ReconciliationLeaseUnavailable("lease clock moved backwards")
        if observed_at >= lease.lease_deadline:
            return self._acquire(observed_at), observed_at
        remaining = lease.lease_deadline - observed_at
        if remaining <= lease.renewal_margin_seconds:
            try:
                renewed = self.journal.renew_execution_lease(
                    lease,
                    observed_at=observed_at,
                )
            except Exception as error:
                raise ReconciliationLeaseUnavailable(
                    f"lease renewal failed: {type(error).__name__}"
                ) from error
            if (
                not isinstance(renewed, ReconciliationExecutionLeaseV2)
                or renewed.invocation_id != lease.invocation_id
                or renewed.owner_id != lease.owner_id
                or renewed.policy != lease.policy
                or renewed.lease_generation != lease.lease_generation + 1
                or renewed.acquired_at != observed_at
            ):
                raise ReconciliationLeaseUnavailable(
                    "lease renewal binding mismatch"
                )
            try:
                self.journal.assert_execution_lease(
                    renewed,
                    observed_at=observed_at,
                )
            except Exception as error:
                raise ReconciliationLeaseUnavailable(
                    f"lease renewal readback failed: {type(error).__name__}"
                ) from error
            self.lease = renewed
            return renewed, observed_at
        try:
            self.journal.assert_execution_lease(
                lease,
                observed_at=observed_at,
            )
        except Exception as error:
            raise ReconciliationLeaseUnavailable(
                f"lease assertion failed: {type(error).__name__}"
            ) from error
        return lease, observed_at


class _LeaseGuardedCoordinatorV2:
    def __init__(
        self,
        inner: ReservationReconciliationCoordinatorV2,
        session: _ExecutionLeaseSessionV2,
    ) -> None:
        self.inner = inner
        self.session = session

    @property
    def policy(self) -> ReservationReconciliationPolicyV2:
        return self.inner.policy

    def prepare_run(self, invocation: ReservationReconciliationInvocationV2):
        return self.inner.prepare_run(invocation)

    def reconcile_plan_item(self, plan, item_index):
        self.session.ensure()
        return self.inner.reconcile_plan_item(plan, item_index)

    def finalize_plan(self, plan, items):
        return self.inner.finalize_plan(plan, items)


class _LeaseGuardedJournalV2:
    def __init__(
        self,
        inner: LeaseFencedResumableReconciliationJournalV2,
        session: _ExecutionLeaseSessionV2,
    ) -> None:
        self.inner = inner
        self.session = session

    def load_intent(self, invocation_id):
        return self.inner.load_intent(invocation_id)

    def begin_intent(self, intent: ReconciliationAuditIntentV2):
        return self.inner.begin_intent(intent)

    def load_plan(self, invocation_id):
        return self.inner.load_plan(invocation_id)

    def append_plan(self, plan):
        return self.inner.append_plan(plan)

    def load_progress(self, invocation_id):
        return self.inner.load_progress(invocation_id)

    def append_progress(self, progress: ReconciliationProgressV2):
        lease, observed_at = self.session.ensure()
        return self.inner.append_progress_under_lease(
            progress,
            lease=lease,
            observed_at=observed_at,
        )

    def load_receipt(self, invocation_id):
        return self.inner.load_receipt(invocation_id)

    def append_receipt(self, receipt: ReservationReconciliationRunResultV2):
        lease, observed_at = self.session.ensure()
        return self.inner.append_receipt_under_lease(
            receipt,
            lease=lease,
            observed_at=observed_at,
        )


class LeaseFencedResumableReconciliationRunnerV2:
    """Run the resumable profile with lease-fenced terminal writes."""

    production_ready = False

    def __init__(
        self,
        *,
        coordinator: ReservationReconciliationCoordinatorV2,
        journal: LeaseFencedResumableReconciliationJournalV2,
        lease_clock: ReconciliationLeaseClockV2,
        owner_id: bytes,
        lease_policy: ReconciliationExecutionLeasePolicyV2,
    ) -> None:
        if not isinstance(lease_policy, ReconciliationExecutionLeasePolicyV2):
            raise TypeError("lease_policy has the wrong type")
        self._coordinator = coordinator
        self._journal = journal
        self._clock = lease_clock
        self._owner_id = _fixed(owner_id, DIGEST_BYTES, "owner_id")
        self._lease_policy = lease_policy

    def run_once(
        self,
        invocation: ReservationReconciliationInvocationV2,
    ) -> ResumableReconciliationResultV2:
        if not isinstance(invocation, ReservationReconciliationInvocationV2):
            raise TypeError("invocation has the wrong type")
        session = _ExecutionLeaseSessionV2(
            journal=self._journal,
            clock=self._clock,
            owner_id=self._owner_id,
            policy=self._lease_policy,
            invocation_id=invocation.invocation_id,
        )
        coordinator = _LeaseGuardedCoordinatorV2(
            self._coordinator,
            session,
        )
        journal = _LeaseGuardedJournalV2(self._journal, session)
        return ResumableJournaledReservationReconciliationRunnerV2(
            coordinator=coordinator,  # type: ignore[arg-type]
            journal=journal,
        ).run_once(invocation)


def reconciliation_execution_lease_manifest() -> dict[str, object]:
    return {
        "format": "PQ-SAT-FGS-RECONCILIATION-EXECUTION-LEASE-v0.2",
        "processing_order": [
            "establish_resumable_intent",
            "acquire_or_recover_single_host_lease",
            "persist_exact_plan_before_replay_mutation",
            "assert_or_renew_lease_before_each_item",
            "execute_exact_plan_item",
            "atomically_assert_lease_and_append_progress",
            "atomically_assert_lease_and_append_receipt",
            "fence_stale_executor_after_takeover",
        ],
        "claim_boundary": {
            "distinct_owner_single_host_cross_process_lease": True,
            "immutable_generation_fencing": True,
            "bounded_expiry_takeover": True,
            "renewal_before_expiry": True,
            "progress_append_atomically_lease_fenced": True,
            "receipt_append_atomically_lease_fenced": True,
            "stale_executor_journal_writes_rejected": True,
            "unique_owner_id_enforced": False,
            "replay_mutation_and_journal_atomic": False,
            "stale_executor_replay_call_prevented_after_lease_loss": False,
            "distributed_consensus_lease": False,
            "production_clock_instantiated": False,
            "operator_authentication_instantiated": False,
            "automatic_background_scheduler_implemented": False,
            "physical_power_loss_tested": False,
            "rollback_resistance": False,
            "production_ready": False,
        },
    }
