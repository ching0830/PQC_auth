"""Explicit bounded coordinator for expired FGS reservations.

This module deliberately provides no background scheduler and no production
operator-authentication or clock implementation.  It composes the replay
store's scan, evidence, fencing, and read-back primitives into one conservative
reference operation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from pq_sat_auth.identities import TicketUseIdentity
from pq_sat_auth.replay import InvalidTransition, ReservationNotFound

from .replay import (
    FencedReservationV2,
    ReservationAbortEvidenceV2,
    ReservationV2,
    U64_MAX,
    derive_reservation_abort_evidence_v2,
    reservation_abort_evidence_digest_v2,
)


DIGEST_BYTES = 32
MAX_RECONCILIATION_BATCH = 10_000
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
    if not 0 <= value <= U64_MAX:
        raise ValueError(f"{name} is outside uint64")
    return value


class ReconciliationClockV2(Protocol):
    """Clock boundary sampled exactly once by each explicit invocation."""

    def now(self) -> int: ...


class ReservationReconciliationStoreV2(Protocol):
    """Required subset of the FGS replay store recovery API."""

    def expired_reservations(
        self,
        *,
        observed_at: int,
        limit: int,
    ) -> tuple[ReservationV2, ...]: ...

    def abort_reservation(
        self,
        identity: TicketUseIdentity,
        *,
        fencing_generation: int,
        attempt_id: bytes,
        request_digest: bytes,
        observed_at: int,
        evidence: ReservationAbortEvidenceV2,
    ) -> FencedReservationV2: ...

    def lookup_reservation_fence(
        self,
        identity: TicketUseIdentity,
    ) -> FencedReservationV2 | None: ...


@dataclass(frozen=True)
class ReservationReconciliationPolicyV2:
    batch_limit: int
    minimum_stale_seconds: int

    def __post_init__(self) -> None:
        if isinstance(self.batch_limit, bool) or not isinstance(
            self.batch_limit,
            int,
        ):
            raise TypeError("reconciliation batch_limit must be an integer")
        if not 1 <= self.batch_limit <= MAX_RECONCILIATION_BATCH:
            raise ValueError("reconciliation batch_limit is outside bounds")
        _u64(self.minimum_stale_seconds, "minimum_stale_seconds")


@dataclass(frozen=True)
class ReservationReconciliationInvocationV2:
    invocation_id: bytes

    def __post_init__(self) -> None:
        _fixed(self.invocation_id, DIGEST_BYTES, "invocation_id")


class ReconciliationRunDispositionV2(Enum):
    COMPLETED = "completed"
    REJECTED = "rejected"
    HALTED = "halted"


class ReconciliationItemDispositionV2(Enum):
    FENCED = "fenced"
    FENCED_RECOVERED = "fenced_recovered"
    FENCED_BY_PEER = "fenced_by_peer"
    NOT_RECONCILED = "not_reconciled"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class ReservationReconciliationItemResultV2:
    use_key: bytes
    attempt_id: bytes
    prior_fencing_generation: int
    fence_generation: int | None
    disposition: ReconciliationItemDispositionV2
    detail: str | None

    def __post_init__(self) -> None:
        _fixed(self.use_key, DIGEST_BYTES, "item use_key")
        _fixed(self.attempt_id, DIGEST_BYTES, "item attempt_id")
        _u64(self.prior_fencing_generation, "prior_fencing_generation")
        if self.prior_fencing_generation == 0:
            raise ValueError("prior_fencing_generation must be positive")
        if self.fence_generation is not None:
            _u64(self.fence_generation, "fence_generation")
            if self.fence_generation == 0:
                raise ValueError("fence_generation must be positive")
        if not isinstance(self.disposition, ReconciliationItemDispositionV2):
            raise TypeError("item disposition has the wrong type")
        if self.detail is not None and (
            not isinstance(self.detail, str) or not self.detail
        ):
            raise ValueError("item detail must be a non-empty string or None")


@dataclass(frozen=True)
class ReservationReconciliationRunResultV2:
    accepted: bool
    disposition: ReconciliationRunDispositionV2
    invocation_id: bytes
    observed_at: int | None
    scan_cutoff: int | None
    scanned_count: int
    items: tuple[ReservationReconciliationItemResultV2, ...]
    failures: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.accepted, bool):
            raise TypeError("accepted must be a boolean")
        _fixed(self.invocation_id, DIGEST_BYTES, "result invocation_id")
        if not isinstance(self.disposition, ReconciliationRunDispositionV2):
            raise TypeError("run disposition has the wrong type")
        if self.observed_at is not None:
            _u64(self.observed_at, "result observed_at")
        if self.scan_cutoff is not None:
            _u64(self.scan_cutoff, "result scan_cutoff")
        if isinstance(self.scanned_count, bool) or not isinstance(
            self.scanned_count,
            int,
        ):
            raise TypeError("scanned_count must be an integer")
        if not 0 <= self.scanned_count <= MAX_RECONCILIATION_BATCH:
            raise ValueError("scanned_count is outside bounds")
        if not isinstance(self.items, tuple) or not all(
            isinstance(item, ReservationReconciliationItemResultV2)
            for item in self.items
        ):
            raise TypeError("items must be reconciliation item results")
        if len(self.items) > self.scanned_count:
            raise ValueError("item count exceeds scanned_count")
        if not isinstance(self.failures, tuple) or not all(
            isinstance(failure, str) and failure for failure in self.failures
        ):
            raise TypeError("failures must be non-empty strings")
        if len(self.failures) > 1:
            raise ValueError("run result has too many failures")
        if self.accepted != (
            self.disposition is ReconciliationRunDispositionV2.COMPLETED
        ):
            raise ValueError("accepted and disposition disagree")
        if self.accepted == bool(self.failures):
            raise ValueError("run completion and failures disagree")
        if (self.observed_at is None) != (self.scan_cutoff is None):
            raise ValueError("observed_at and scan_cutoff presence disagree")
        if (
            self.observed_at is not None
            and self.scan_cutoff is not None
            and self.scan_cutoff > self.observed_at
        ):
            raise ValueError("scan_cutoff follows observed_at")
        if len({item.use_key for item in self.items}) != len(self.items):
            raise ValueError("run result contains duplicate items")


@dataclass(frozen=True)
class ReservationReconciliationPlanV2:
    """Immutable candidate snapshot for one resumable reconciliation run."""

    invocation_id: bytes
    observed_at: int
    scan_cutoff: int
    batch_limit: int
    minimum_stale_seconds: int
    candidates: tuple[ReservationV2, ...]

    def __post_init__(self) -> None:
        _fixed(self.invocation_id, DIGEST_BYTES, "plan invocation_id")
        _u64(self.observed_at, "plan observed_at")
        _u64(self.scan_cutoff, "plan scan_cutoff")
        policy = ReservationReconciliationPolicyV2(
            self.batch_limit,
            self.minimum_stale_seconds,
        )
        if self.scan_cutoff != max(
            0,
            self.observed_at - policy.minimum_stale_seconds,
        ):
            raise ValueError("plan cutoff does not match its policy")
        if not isinstance(self.candidates, tuple):
            raise TypeError("plan candidates must be a tuple")
        if len(self.candidates) > policy.batch_limit:
            raise ValueError("plan candidates exceed batch_limit")
        seen: set[bytes] = set()
        for candidate in self.candidates:
            if not isinstance(candidate, ReservationV2) or isinstance(
                candidate,
                FencedReservationV2,
            ):
                raise TypeError("plan contains a non-active reservation")
            if candidate.lease_deadline >= self.scan_cutoff:
                raise ValueError("plan contains an ineligible reservation")
            if candidate.identity.use_key in seen:
                raise ValueError("plan contains a duplicate reservation")
            seen.add(candidate.identity.use_key)


def _same_reservation_fields(
    fence: FencedReservationV2,
    reservation: ReservationV2,
) -> bool:
    return (
        fence.identity == reservation.identity
        and fence.attempt_id == reservation.attempt_id
        and fence.request_digest == reservation.request_digest
        and fence.serving_context_digest == reservation.serving_context_digest
        and fence.reserved_at == reservation.reserved_at
        and fence.lease_deadline == reservation.lease_deadline
        and fence.revocation_generation == reservation.revocation_generation
        and fence.fencing_generation == reservation.fencing_generation + 1
    )


def _expected_fence(
    reservation: ReservationV2,
    observed_at: int,
    evidence: ReservationAbortEvidenceV2,
) -> FencedReservationV2:
    if reservation.fencing_generation >= U64_MAX:
        raise ValueError("reservation fencing generation exhausted")
    return FencedReservationV2(
        identity=reservation.identity,
        attempt_id=reservation.attempt_id,
        request_digest=reservation.request_digest,
        serving_context_digest=reservation.serving_context_digest,
        reserved_at=reservation.reserved_at,
        lease_deadline=reservation.lease_deadline,
        revocation_generation=reservation.revocation_generation,
        fencing_generation=reservation.fencing_generation + 1,
        fenced_at=observed_at,
        abort_evidence_digest=reservation_abort_evidence_digest_v2(evidence),
    )


class ReservationReconciliationCoordinatorV2:
    """Run one explicit, bounded, fail-closed reconciliation pass."""

    production_ready = False

    def __init__(
        self,
        *,
        store: ReservationReconciliationStoreV2,
        clock: ReconciliationClockV2,
        policy: ReservationReconciliationPolicyV2,
    ) -> None:
        if not isinstance(policy, ReservationReconciliationPolicyV2):
            raise TypeError("policy must be ReservationReconciliationPolicyV2")
        self._store = store
        self._clock = clock
        self._policy = policy

    @property
    def policy(self) -> ReservationReconciliationPolicyV2:
        return self._policy

    @staticmethod
    def _run_result(
        invocation: ReservationReconciliationInvocationV2,
        disposition: ReconciliationRunDispositionV2,
        *,
        observed_at: int | None,
        scan_cutoff: int | None,
        scanned_count: int,
        items: list[ReservationReconciliationItemResultV2],
        failure: str | None = None,
    ) -> ReservationReconciliationRunResultV2:
        return ReservationReconciliationRunResultV2(
            accepted=disposition is ReconciliationRunDispositionV2.COMPLETED,
            disposition=disposition,
            invocation_id=invocation.invocation_id,
            observed_at=observed_at,
            scan_cutoff=scan_cutoff,
            scanned_count=scanned_count,
            items=tuple(items),
            failures=() if failure is None else (failure,),
        )

    @staticmethod
    def _item(
        reservation: ReservationV2,
        disposition: ReconciliationItemDispositionV2,
        *,
        fence_generation: int | None = None,
        detail: str | None = None,
    ) -> ReservationReconciliationItemResultV2:
        return ReservationReconciliationItemResultV2(
            use_key=reservation.identity.use_key,
            attempt_id=reservation.attempt_id,
            prior_fencing_generation=reservation.fencing_generation,
            fence_generation=fence_generation,
            disposition=disposition,
            detail=detail,
        )

    @staticmethod
    def _validate_scan(
        candidates: object,
        *,
        cutoff: int,
        limit: int,
    ) -> tuple[ReservationV2, ...]:
        if not isinstance(candidates, tuple):
            raise TypeError("replay scan must return a tuple")
        if len(candidates) > limit:
            raise ValueError("replay scan exceeded the requested limit")
        seen: set[bytes] = set()
        for candidate in candidates:
            if not isinstance(candidate, ReservationV2) or isinstance(
                candidate,
                FencedReservationV2,
            ):
                raise TypeError("replay scan returned a non-active reservation")
            if candidate.lease_deadline >= cutoff:
                raise ValueError("replay scan returned an ineligible reservation")
            if candidate.identity.use_key in seen:
                raise ValueError("replay scan returned a duplicate reservation")
            seen.add(candidate.identity.use_key)
        return candidates

    def _read_back_fence(
        self,
        reservation: ReservationV2,
        expected: FencedReservationV2,
    ) -> tuple[ReconciliationItemDispositionV2 | None, str | None]:
        try:
            fence = self._store.lookup_reservation_fence(reservation.identity)
        except Exception as error:
            return None, f"fence_readback:{type(error).__name__}"
        if fence is None:
            return None, None
        if not isinstance(fence, FencedReservationV2):
            return None, "fence_readback:TypeError"
        if not _same_reservation_fields(fence, reservation):
            return None, "fence_readback:binding_mismatch"
        peer_evidence = derive_reservation_abort_evidence_v2(
            reservation,
            fence.fenced_at,
        )
        if fence.abort_evidence_digest != reservation_abort_evidence_digest_v2(
            peer_evidence
        ):
            return None, "fence_readback:evidence_mismatch"
        if fence == expected:
            return ReconciliationItemDispositionV2.FENCED_RECOVERED, None
        return ReconciliationItemDispositionV2.FENCED_BY_PEER, None

    def prepare_run(
        self,
        invocation: ReservationReconciliationInvocationV2,
    ) -> ReservationReconciliationPlanV2 | ReservationReconciliationRunResultV2:
        """Sample and scan without mutating replay state."""

        if not isinstance(invocation, ReservationReconciliationInvocationV2):
            raise TypeError(
                "invocation must be ReservationReconciliationInvocationV2"
            )
        try:
            observed_at = _u64(self._clock.now(), "reconciliation time")
        except Exception as error:
            return self._run_result(
                invocation,
                ReconciliationRunDispositionV2.REJECTED,
                observed_at=None,
                scan_cutoff=None,
                scanned_count=0,
                items=[],
                failure=f"clock_backend:{type(error).__name__}",
            )
        scan_cutoff = max(
            0,
            observed_at - self._policy.minimum_stale_seconds,
        )
        try:
            candidates = self._validate_scan(
                self._store.expired_reservations(
                    observed_at=scan_cutoff,
                    limit=self._policy.batch_limit,
                ),
                cutoff=scan_cutoff,
                limit=self._policy.batch_limit,
            )
        except Exception as error:
            return self._run_result(
                invocation,
                ReconciliationRunDispositionV2.REJECTED,
                observed_at=observed_at,
                scan_cutoff=scan_cutoff,
                scanned_count=0,
                items=[],
                failure=f"replay_scan:{type(error).__name__}",
            )
        return ReservationReconciliationPlanV2(
            invocation_id=invocation.invocation_id,
            observed_at=observed_at,
            scan_cutoff=scan_cutoff,
            batch_limit=self._policy.batch_limit,
            minimum_stale_seconds=self._policy.minimum_stale_seconds,
            candidates=candidates,
        )

    def reconcile_plan_item(
        self,
        plan: ReservationReconciliationPlanV2,
        item_index: int,
    ) -> ReservationReconciliationItemResultV2:
        """Execute one exact plan item; safe retry relies on fence read-back."""

        if not isinstance(plan, ReservationReconciliationPlanV2):
            raise TypeError("plan has the wrong type")
        if (
            plan.batch_limit != self._policy.batch_limit
            or plan.minimum_stale_seconds != self._policy.minimum_stale_seconds
        ):
            raise ValueError("plan policy does not match coordinator policy")
        if isinstance(item_index, bool) or not isinstance(item_index, int):
            raise TypeError("item_index must be an integer")
        if not 0 <= item_index < len(plan.candidates):
            raise ValueError("item_index is outside the plan")
        reservation = plan.candidates[item_index]
        try:
            evidence = derive_reservation_abort_evidence_v2(
                reservation,
                plan.observed_at,
            )
            expected = _expected_fence(
                reservation,
                plan.observed_at,
                evidence,
            )
        except Exception as error:
            return self._item(
                reservation,
                ReconciliationItemDispositionV2.UNRESOLVED,
                detail=f"candidate:{type(error).__name__}",
            )

        abort_error: Exception | None = None
        returned: FencedReservationV2 | None = None
        try:
            returned = self._store.abort_reservation(
                reservation.identity,
                fencing_generation=reservation.fencing_generation,
                attempt_id=reservation.attempt_id,
                request_digest=reservation.request_digest,
                observed_at=plan.observed_at,
                evidence=evidence,
            )
        except Exception as error:
            abort_error = error

        readback_disposition, readback_error = self._read_back_fence(
            reservation,
            expected,
        )
        if readback_error is not None:
            return self._item(
                reservation,
                ReconciliationItemDispositionV2.UNRESOLVED,
                detail=readback_error,
            )
        if readback_disposition is not None:
            disposition = readback_disposition
            if abort_error is None and returned == expected:
                disposition = ReconciliationItemDispositionV2.FENCED
            return self._item(
                reservation,
                disposition,
                fence_generation=reservation.fencing_generation + 1,
                detail=(
                    None
                    if abort_error is None
                    else f"abort_ack:{type(abort_error).__name__}"
                ),
            )
        if abort_error is None:
            detail = (
                "abort_output:mismatch"
                if returned != expected
                else "fence_readback:missing"
            )
            return self._item(
                reservation,
                ReconciliationItemDispositionV2.UNRESOLVED,
                detail=detail,
            )
        if isinstance(abort_error, (ReservationNotFound, InvalidTransition)):
            return self._item(
                reservation,
                ReconciliationItemDispositionV2.NOT_RECONCILED,
                detail=f"abort_race:{type(abort_error).__name__}",
            )
        return self._item(
            reservation,
            ReconciliationItemDispositionV2.UNRESOLVED,
            detail=f"abort_backend:{type(abort_error).__name__}",
        )

    @classmethod
    def finalize_plan(
        cls,
        plan: ReservationReconciliationPlanV2,
        items: tuple[ReservationReconciliationItemResultV2, ...],
    ) -> ReservationReconciliationRunResultV2:
        """Bind a terminal contiguous item prefix to its immutable plan."""

        if not isinstance(plan, ReservationReconciliationPlanV2):
            raise TypeError("plan has the wrong type")
        if not isinstance(items, tuple):
            raise TypeError("plan items must be a tuple")
        if len(items) > len(plan.candidates):
            raise ValueError("plan result contains too many items")
        for index, item in enumerate(items):
            if not isinstance(item, ReservationReconciliationItemResultV2):
                raise TypeError("plan result contains a non-item")
            candidate = plan.candidates[index]
            if (
                item.use_key != candidate.identity.use_key
                or item.attempt_id != candidate.attempt_id
                or item.prior_fencing_generation
                != candidate.fencing_generation
            ):
                raise ValueError("plan result item does not match candidate")
            fenced = item.disposition in (
                ReconciliationItemDispositionV2.FENCED,
                ReconciliationItemDispositionV2.FENCED_RECOVERED,
                ReconciliationItemDispositionV2.FENCED_BY_PEER,
            )
            if fenced:
                if (
                    candidate.fencing_generation >= U64_MAX
                    or item.fence_generation
                    != candidate.fencing_generation + 1
                ):
                    raise ValueError(
                        "fenced plan result has the wrong generation"
                    )
            elif item.fence_generation is not None:
                raise ValueError(
                    "non-fenced plan result contains a fence generation"
                )
            if (
                item.disposition
                in (
                    ReconciliationItemDispositionV2.NOT_RECONCILED,
                    ReconciliationItemDispositionV2.UNRESOLVED,
                )
                and item.detail is None
            ):
                raise ValueError("non-success plan result has no detail")
            if (
                item.disposition is ReconciliationItemDispositionV2.UNRESOLVED
                and index != len(items) - 1
            ):
                raise ValueError("unresolved plan item must terminate progress")
        invocation = ReservationReconciliationInvocationV2(plan.invocation_id)
        if items and (
            items[-1].disposition is ReconciliationItemDispositionV2.UNRESOLVED
        ):
            detail = items[-1].detail
            if detail is None:
                raise ValueError("unresolved plan item has no failure detail")
            return cls._run_result(
                invocation,
                ReconciliationRunDispositionV2.HALTED,
                observed_at=plan.observed_at,
                scan_cutoff=plan.scan_cutoff,
                scanned_count=len(plan.candidates),
                items=list(items),
                failure=detail,
            )
        if len(items) != len(plan.candidates):
            raise ValueError("non-terminal plan progress cannot be finalized")
        return cls._run_result(
            invocation,
            ReconciliationRunDispositionV2.COMPLETED,
            observed_at=plan.observed_at,
            scan_cutoff=plan.scan_cutoff,
            scanned_count=len(plan.candidates),
            items=list(items),
        )

    def run_once(
        self,
        invocation: ReservationReconciliationInvocationV2,
    ) -> ReservationReconciliationRunResultV2:
        prepared = self.prepare_run(invocation)
        if isinstance(prepared, ReservationReconciliationRunResultV2):
            return prepared
        items: list[ReservationReconciliationItemResultV2] = []
        for index in range(len(prepared.candidates)):
            item = self.reconcile_plan_item(prepared, index)
            items.append(item)
            if item.disposition is ReconciliationItemDispositionV2.UNRESOLVED:
                break
        return self.finalize_plan(prepared, tuple(items))


def reservation_reconciliation_manifest() -> dict[str, object]:
    return {
        "format": "PQ-SAT-FGS-RESERVATION-RECONCILIATION-v0.2",
        "processing_order": [
            "validate_explicit_invocation",
            "sample_clock_once",
            "apply_minimum_stale_policy",
            "bounded_expired_reservation_scan",
            "freeze_immutable_candidate_plan",
            "derive_exact_abort_evidence",
            "atomic_fence_rotation",
            "fence_readback",
            "classify_race_or_halt_on_uncertainty",
        ],
        "claim_boundary": {
            "explicit_one_shot_invocation_required": True,
            "single_clock_sample_per_run": True,
            "minimum_stale_policy_enforced": True,
            "bounded_batch_enforced": True,
            "scan_output_validated": True,
            "prepare_execute_finalize_api": True,
            "exact_abort_evidence_derived": True,
            "post_abort_fence_readback_required": True,
            "lost_ack_fence_recovery_available": True,
            "state_change_races_do_not_release_ticket": True,
            "unexpected_backend_failure_halts_batch": True,
            "automatic_background_scheduler_implemented": False,
            "operator_authentication_instantiated": False,
            "production_clock_instantiated": False,
            "persistent_invocation_audit_log_implemented": False,
            "distributed_coordination_implemented": False,
            "production_ready": False,
        },
    }
