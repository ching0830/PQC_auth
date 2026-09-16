from __future__ import annotations

import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from pq_sat_auth.replay import InvalidTransition
from pq_sat_auth.v2.reconciliation import (
    MAX_RECONCILIATION_BATCH,
    ReconciliationItemDispositionV2,
    ReconciliationRunDispositionV2,
    ReservationReconciliationCoordinatorV2,
    ReservationReconciliationInvocationV2,
    ReservationReconciliationPolicyV2,
    reservation_reconciliation_manifest,
)
from pq_sat_auth.v2.replay import (
    FencedReservationV2,
    InMemoryLinearizableReplayStoreV2,
    ReservationV2,
    U64_MAX,
    derive_reservation_abort_evidence_v2,
)
from pq_sat_auth.v2.storage.sqlite_replay import SQLiteFGSReplayStoreV2
from tests.system.test_pq_sat_auth_replay_v2 import fixed, identity
from tests.system.test_pq_sat_auth_sqlite_replay_v2 import (
    ReplayProtectionTestBackend,
)


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = (
    ROOT
    / "manifests"
    / "pq_sat_auth_fgs_reservation_reconciliation_v0_2.json"
)


class FixedClock:
    def __init__(self, value: int = 250, *, broken: bool = False) -> None:
        self.value = value
        self.broken = broken
        self.calls = 0

    def now(self) -> int:
        self.calls += 1
        if self.broken:
            raise OSError("test clock unavailable")
        return self.value


class DelegatingStore:
    def __init__(self, inner) -> None:
        self.inner = inner
        self.scan_calls = 0
        self.abort_calls = 0

    def expired_reservations(self, *, observed_at: int, limit: int):
        self.scan_calls += 1
        return self.inner.expired_reservations(
            observed_at=observed_at,
            limit=limit,
        )

    def abort_reservation(self, identity_value, **arguments):
        self.abort_calls += 1
        return self.inner.abort_reservation(identity_value, **arguments)

    def lookup_reservation_fence(self, identity_value):
        return self.inner.lookup_reservation_fence(identity_value)


class ScanFailureStore(DelegatingStore):
    def expired_reservations(self, *, observed_at: int, limit: int):
        del observed_at, limit
        self.scan_calls += 1
        raise OSError("test scan unavailable")


class ScanOutputStore(DelegatingStore):
    def __init__(self, inner, transform) -> None:
        super().__init__(inner)
        self.transform = transform

    def expired_reservations(self, *, observed_at: int, limit: int):
        candidates = super().expired_reservations(
            observed_at=observed_at,
            limit=limit,
        )
        return self.transform(candidates)


class StateChangedStore(DelegatingStore):
    def abort_reservation(self, identity_value, **arguments):
        del identity_value, arguments
        self.abort_calls += 1
        raise InvalidTransition("test state changed")


class LostAcknowledgementStore(DelegatingStore):
    def abort_reservation(self, identity_value, **arguments):
        self.abort_calls += 1
        self.inner.abort_reservation(identity_value, **arguments)
        raise OSError("test acknowledgement lost")


class PeerFenceStore(DelegatingStore):
    def abort_reservation(self, identity_value, **arguments):
        self.abort_calls += 1
        reservation = self.inner.lookup(identity_value)
        assert isinstance(reservation, ReservationV2)
        peer_time = arguments["observed_at"] - 1
        self.inner.abort_reservation(
            identity_value,
            fencing_generation=reservation.fencing_generation,
            attempt_id=reservation.attempt_id,
            request_digest=reservation.request_digest,
            observed_at=peer_time,
            evidence=derive_reservation_abort_evidence_v2(
                reservation,
                peer_time,
            ),
        )
        raise InvalidTransition("test peer won")


class AbortFailureStore(DelegatingStore):
    def abort_reservation(self, identity_value, **arguments):
        del identity_value, arguments
        self.abort_calls += 1
        raise OSError("test abort unavailable")


class MissingReadbackStore(DelegatingStore):
    def lookup_reservation_fence(self, identity_value):
        del identity_value
        return None


class MutatedReadbackStore(DelegatingStore):
    def lookup_reservation_fence(self, identity_value):
        fence = self.inner.lookup_reservation_fence(identity_value)
        assert fence is not None
        return replace(fence, attempt_id=fixed(99))


class MutatedAbortOutputStore(DelegatingStore):
    def abort_reservation(self, identity_value, **arguments):
        self.abort_calls += 1
        fence = self.inner.abort_reservation(identity_value, **arguments)
        return replace(fence, abort_evidence_digest=fixed(99))


class SynchronizedScanStore(DelegatingStore):
    def __init__(self, inner) -> None:
        super().__init__(inner)
        self.barrier = threading.Barrier(2)

    def expired_reservations(self, *, observed_at: int, limit: int):
        candidates = super().expired_reservations(
            observed_at=observed_at,
            limit=limit,
        )
        self.barrier.wait(10)
        return candidates


class ReconciliationFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryLinearizableReplayStoreV2()
        self.clock = FixedClock()
        self.policy = ReservationReconciliationPolicyV2(
            batch_limit=10,
            minimum_stale_seconds=20,
        )
        self.invocation = ReservationReconciliationInvocationV2(fixed(90))

    @staticmethod
    def reserve(store, value: int = 1, deadline: int = 200):
        selected = identity(ctx=value, serial=value + 20, digest=value + 40)
        result = store.reserve(
            selected,
            attempt_id=fixed(value + 60),
            request_digest=fixed(value + 80),
            serving_context_digest=fixed(6),
            reserved_at=100,
            lease_deadline=deadline,
            revocation_generation=7,
        )
        return result.record

    def coordinator(self, *, store=None, clock=None, policy=None):
        return ReservationReconciliationCoordinatorV2(
            store=self.store if store is None else store,
            clock=self.clock if clock is None else clock,
            policy=self.policy if policy is None else policy,
        )


class ReconciliationContractTests(ReconciliationFixture):
    def test_manifest_matches_implementation(self) -> None:
        self.assertEqual(
            json.loads(MANIFEST.read_text(encoding="utf-8")),
            reservation_reconciliation_manifest(),
        )

    def test_manifest_keeps_operational_and_production_boundaries_false(self) -> None:
        claims = reservation_reconciliation_manifest()["claim_boundary"]
        self.assertFalse(
            claims["automatic_background_scheduler_implemented"]
        )
        self.assertFalse(claims["operator_authentication_instantiated"])
        self.assertFalse(claims["production_clock_instantiated"])
        self.assertFalse(claims["persistent_invocation_audit_log_implemented"])
        self.assertFalse(claims["distributed_coordination_implemented"])
        self.assertFalse(claims["production_ready"])
        self.assertFalse(ReservationReconciliationCoordinatorV2.production_ready)

    def test_invocation_and_policy_are_strict_and_bounded(self) -> None:
        with self.assertRaises(TypeError):
            ReservationReconciliationInvocationV2("bad")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            ReservationReconciliationInvocationV2(b"")
        for limit in (0, MAX_RECONCILIATION_BATCH + 1):
            with self.assertRaises(ValueError):
                ReservationReconciliationPolicyV2(limit, 0)
        with self.assertRaises(TypeError):
            ReservationReconciliationPolicyV2(True, 0)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            ReservationReconciliationPolicyV2(1, True)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            ReservationReconciliationPolicyV2(1, -1)
        with self.assertRaises(TypeError):
            self.coordinator().run_once(object())  # type: ignore[arg-type]

    def test_successful_run_samples_clock_once_and_reads_back_fence(self) -> None:
        reservation = self.reserve(self.store)
        result = self.coordinator().run_once(self.invocation)

        self.assertTrue(result.accepted)
        self.assertIs(result.disposition, ReconciliationRunDispositionV2.COMPLETED)
        self.assertEqual(result.invocation_id, self.invocation.invocation_id)
        self.assertEqual(result.observed_at, 250)
        self.assertEqual(result.scan_cutoff, 230)
        self.assertEqual(result.scanned_count, 1)
        self.assertEqual(self.clock.calls, 1)
        self.assertEqual(
            result.items[0].disposition,
            ReconciliationItemDispositionV2.FENCED,
        )
        self.assertEqual(result.items[0].prior_fencing_generation, 1)
        self.assertEqual(result.items[0].fence_generation, 2)
        self.assertIsNone(self.store.lookup(reservation.identity))
        fence = self.store.lookup_reservation_fence(reservation.identity)
        assert fence is not None
        self.assertEqual(fence.fencing_generation, 2)

        replay = self.coordinator().run_once(self.invocation)
        self.assertTrue(replay.accepted)
        self.assertEqual(replay.scanned_count, 0)
        self.assertEqual(replay.items, ())

    def test_minimum_stale_boundary_is_enforced_by_scan_cutoff(self) -> None:
        self.reserve(self.store)
        at_boundary = self.coordinator(
            clock=FixedClock(230),
            policy=ReservationReconciliationPolicyV2(10, 30),
        ).run_once(self.invocation)
        self.assertTrue(at_boundary.accepted)
        self.assertEqual(at_boundary.scan_cutoff, 200)
        self.assertEqual(at_boundary.scanned_count, 0)

        after_boundary = self.coordinator(
            clock=FixedClock(231),
            policy=ReservationReconciliationPolicyV2(10, 30),
        ).run_once(self.invocation)
        self.assertTrue(after_boundary.accepted)
        self.assertEqual(after_boundary.scan_cutoff, 201)
        self.assertEqual(after_boundary.scanned_count, 1)

    def test_batch_limit_is_enforced_and_remaining_work_is_retryable(self) -> None:
        for value in (1, 2, 3):
            self.reserve(self.store, value)
        policy = ReservationReconciliationPolicyV2(2, 0)
        first = self.coordinator(policy=policy).run_once(self.invocation)
        self.assertTrue(first.accepted)
        self.assertEqual(first.scanned_count, 2)
        second = self.coordinator(policy=policy).run_once(
            ReservationReconciliationInvocationV2(fixed(91))
        )
        self.assertTrue(second.accepted)
        self.assertEqual(second.scanned_count, 1)
        self.assertEqual(len(self.store), 0)

    def test_clock_failure_rejects_before_scan(self) -> None:
        wrapped = DelegatingStore(self.store)
        result = self.coordinator(
            store=wrapped,
            clock=FixedClock(broken=True),
        ).run_once(self.invocation)
        self.assertFalse(result.accepted)
        self.assertIs(result.disposition, ReconciliationRunDispositionV2.REJECTED)
        self.assertEqual(result.failures, ("clock_backend:OSError",))
        self.assertEqual(wrapped.scan_calls, 0)

    def test_noncanonical_clock_outputs_reject_before_scan(self) -> None:
        for value, error_name in (
            (True, "TypeError"),
            (-1, "ValueError"),
            (U64_MAX + 1, "ValueError"),
        ):
            with self.subTest(value=value):
                wrapped = DelegatingStore(self.store)
                result = self.coordinator(
                    store=wrapped,
                    clock=FixedClock(value),
                ).run_once(self.invocation)
                self.assertFalse(result.accepted)
                self.assertEqual(
                    result.failures,
                    (f"clock_backend:{error_name}",),
                )
                self.assertEqual(wrapped.scan_calls, 0)

    def test_scan_failure_rejects_without_abort(self) -> None:
        wrapped = ScanFailureStore(self.store)
        result = self.coordinator(store=wrapped).run_once(self.invocation)
        self.assertFalse(result.accepted)
        self.assertEqual(result.failures, ("replay_scan:OSError",))
        self.assertEqual(wrapped.abort_calls, 0)

    def test_scan_output_shape_count_eligibility_and_uniqueness_are_checked(self) -> None:
        reservation = self.reserve(self.store)
        second = self.reserve(self.store, 2)
        cases = (
            lambda values: list(values),
            lambda values: (values[0], values[0]),
            lambda values: (replace(values[0], lease_deadline=230),),
            lambda values: values + (second,),
            lambda values: (object(),),
        )
        for transform in cases:
            with self.subTest(transform=transform):
                wrapped = ScanOutputStore(self.store, transform)
                result = self.coordinator(
                    store=wrapped,
                    policy=ReservationReconciliationPolicyV2(1, 20),
                ).run_once(self.invocation)
                self.assertFalse(result.accepted)
                self.assertIs(
                    result.disposition,
                    ReconciliationRunDispositionV2.REJECTED,
                )
                self.assertTrue(result.failures[0].startswith("replay_scan:"))
                self.assertEqual(wrapped.abort_calls, 0)
        self.assertEqual(self.store.lookup(reservation.identity), reservation)


class ReconciliationFailureTests(ReconciliationFixture):
    def test_expected_state_change_is_recorded_without_releasing_reservation(self) -> None:
        reservation = self.reserve(self.store)
        wrapped = StateChangedStore(self.store)
        result = self.coordinator(store=wrapped).run_once(self.invocation)

        self.assertTrue(result.accepted)
        self.assertEqual(
            result.items[0].disposition,
            ReconciliationItemDispositionV2.NOT_RECONCILED,
        )
        self.assertEqual(
            result.items[0].detail,
            "abort_race:InvalidTransition",
        )
        self.assertEqual(self.store.lookup(reservation.identity), reservation)

    def test_lost_abort_acknowledgement_is_recovered_by_exact_readback(self) -> None:
        self.reserve(self.store)
        wrapped = LostAcknowledgementStore(self.store)
        result = self.coordinator(store=wrapped).run_once(self.invocation)

        self.assertTrue(result.accepted)
        self.assertEqual(
            result.items[0].disposition,
            ReconciliationItemDispositionV2.FENCED_RECOVERED,
        )
        self.assertEqual(result.items[0].detail, "abort_ack:OSError")

    def test_equivalent_peer_fence_is_verified_with_peer_observation_time(self) -> None:
        self.reserve(self.store)
        result = self.coordinator(store=PeerFenceStore(self.store)).run_once(
            self.invocation
        )
        self.assertTrue(result.accepted)
        self.assertEqual(
            result.items[0].disposition,
            ReconciliationItemDispositionV2.FENCED_BY_PEER,
        )

    def test_mutated_abort_output_can_recover_from_exact_store_readback(self) -> None:
        self.reserve(self.store)
        result = self.coordinator(
            store=MutatedAbortOutputStore(self.store)
        ).run_once(self.invocation)
        self.assertTrue(result.accepted)
        self.assertEqual(
            result.items[0].disposition,
            ReconciliationItemDispositionV2.FENCED_RECOVERED,
        )

    def test_missing_or_mutated_readback_halts_batch(self) -> None:
        for wrapper_type, failure in (
            (MissingReadbackStore, "fence_readback:missing"),
            (MutatedReadbackStore, "fence_readback:binding_mismatch"),
        ):
            with self.subTest(wrapper=wrapper_type.__name__):
                store = InMemoryLinearizableReplayStoreV2()
                self.reserve(store)
                result = self.coordinator(store=wrapper_type(store)).run_once(
                    self.invocation
                )
                self.assertFalse(result.accepted)
                self.assertIs(
                    result.disposition,
                    ReconciliationRunDispositionV2.HALTED,
                )
                self.assertEqual(result.failures, (failure,))
                self.assertEqual(
                    result.items[0].disposition,
                    ReconciliationItemDispositionV2.UNRESOLVED,
                )

    def test_unexpected_abort_failure_halts_before_later_candidates(self) -> None:
        self.reserve(self.store)
        self.reserve(self.store, 2)
        wrapped = AbortFailureStore(self.store)
        result = self.coordinator(store=wrapped).run_once(self.invocation)
        self.assertFalse(result.accepted)
        self.assertIs(result.disposition, ReconciliationRunDispositionV2.HALTED)
        self.assertEqual(result.failures, ("abort_backend:OSError",))
        self.assertEqual(wrapped.abort_calls, 1)
        self.assertEqual(len(self.store), 2)

    def test_two_explicit_coordinators_accept_one_fence_identity(self) -> None:
        self.reserve(self.store)
        wrapped = SynchronizedScanStore(self.store)

        def run(value: int):
            return self.coordinator(
                store=wrapped,
                clock=FixedClock(250),
            ).run_once(ReservationReconciliationInvocationV2(fixed(value)))

        with ThreadPoolExecutor(max_workers=2) as executor:
            first_future = executor.submit(run, 91)
            second_future = executor.submit(run, 92)
            results = (
                first_future.result(timeout=10),
                second_future.result(timeout=10),
            )
        self.assertTrue(all(result.accepted for result in results))
        self.assertEqual(
            {
                result.items[0].disposition
                for result in results
            },
            {
                ReconciliationItemDispositionV2.FENCED,
                ReconciliationItemDispositionV2.FENCED_RECOVERED,
            },
        )
        self.assertEqual(
            {result.items[0].fence_generation for result in results},
            {2},
        )


class SQLiteReconciliationIntegrationTests(ReconciliationFixture):
    def test_fence_survives_restart_after_coordinator_readback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "replay.sqlite3"
            store = SQLiteFGSReplayStoreV2(
                path,
                ReplayProtectionTestBackend(),
            )
            reservation = self.reserve(store)
            result = self.coordinator(store=store).run_once(self.invocation)
            self.assertTrue(result.accepted)
            self.assertEqual(
                result.items[0].disposition,
                ReconciliationItemDispositionV2.FENCED,
            )

            restarted = SQLiteFGSReplayStoreV2(
                path,
                ReplayProtectionTestBackend(),
            )
            self.assertIsNone(restarted.lookup(reservation.identity))
            fence = restarted.lookup_reservation_fence(reservation.identity)
            assert isinstance(fence, FencedReservationV2)
            self.assertEqual(fence.fencing_generation, 2)


if __name__ == "__main__":
    unittest.main()
