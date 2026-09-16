from __future__ import annotations

import json
import unittest
from dataclasses import replace
from pathlib import Path

from pq_sat_auth.v2.reconciliation_context import (
    CREDENTIAL_AUTHENTICATION_DOMAIN,
    AuthenticatedReconciliationExecutorV2,
    CredentialedLeaseFencedResumableReconciliationRunnerV2,
    ReconciliationExecutionScopeV2,
    ReconciliationExecutorAuthorizationV2,
    decode_authenticated_reconciliation_executor,
    decode_reconciliation_execution_scope,
    decode_reconciliation_executor_authorization,
    encode_authenticated_reconciliation_executor,
    encode_reconciliation_execution_scope,
    encode_reconciliation_executor_authorization,
    reconciliation_execution_context_manifest,
)
from pq_sat_auth.v2.reconciliation_resume import (
    ResumableReconciliationDispositionV2,
)
from tests.system.test_pq_sat_auth_reconciliation_lease_v2 import (
    LeaseFixture,
    reserve,
)
from tests.system.test_pq_sat_auth_replay_v2 import fixed


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = (
    ROOT
    / "manifests"
    / "pq_sat_auth_fgs_reconciliation_execution_context_v0_2.json"
)


class ReadyClock:
    production_ready = True

    def __init__(self, clock_id: bytes, *values: int) -> None:
        self.clock_id = clock_id
        self._values = iter(values or (100,))
        self._last = values[-1] if values else 100
        self.broken = False

    def now(self) -> int:
        if self.broken:
            raise OSError("clock unavailable")
        try:
            self._last = next(self._values)
        except StopIteration:
            pass
        return self._last


class CredentialVerifier:
    production_ready = True

    def __init__(self, verifier_id: bytes) -> None:
        self.verifier_id = verifier_id
        self.accepted: object = True
        self.broken = False
        self.expected_message: bytes | None = None
        self.expected_authentication: bytes | None = None
        self.calls: list[tuple[bytes, bytes]] = []

    def verify(self, message: bytes, authentication: bytes) -> bool:
        self.calls.append((message, authentication))
        if self.broken:
            raise OSError("verifier unavailable")
        if self.expected_message is not None and message != self.expected_message:
            return False
        if (
            self.expected_authentication is not None
            and authentication != self.expected_authentication
        ):
            return False
        return self.accepted  # type: ignore[return-value]


class ExecutionContextCodecTests(unittest.TestCase):
    def scope(self) -> ReconciliationExecutionScopeV2:
        return ReconciliationExecutionScopeV2(
            system_context_digest=fixed(1),
            replay_store_id=fixed(2),
            reconciliation_journal_id=fixed(3),
            clock_id=fixed(4),
            credential_verifier_id=fixed(5),
            batch_limit=10,
            minimum_stale_seconds=20,
            lease_seconds=10,
            renewal_margin_seconds=2,
        )

    def authorization(self) -> ReconciliationExecutorAuthorizationV2:
        return ReconciliationExecutorAuthorizationV2(
            invocation_id=fixed(6),
            execution_scope_digest=self.scope().digest,
            operator_id=fixed(7),
            executor_instance_id=fixed(8),
            credential_id=fixed(9),
            not_before=90,
            not_after=200,
        )

    def test_scope_round_trip_digest_and_strict_encoding(self) -> None:
        scope = self.scope()
        encoded = encode_reconciliation_execution_scope(scope)
        self.assertEqual(decode_reconciliation_execution_scope(encoded), scope)
        self.assertEqual(scope.digest, self.scope().digest)
        self.assertNotEqual(
            scope.digest,
            replace(scope, replay_store_id=fixed(10)).digest,
        )
        with self.assertRaises(ValueError):
            decode_reconciliation_execution_scope(encoded + b" ")
        value = json.loads(encoded.decode("ascii"))
        value["clock_id"] = "AA" * 32
        with self.assertRaises(ValueError):
            decode_reconciliation_execution_scope(
                json.dumps(
                    value,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
            )

    def test_authorization_round_trip_and_owner_derivation(self) -> None:
        authorization = self.authorization()
        encoded = encode_reconciliation_executor_authorization(authorization)
        self.assertEqual(
            decode_reconciliation_executor_authorization(encoded),
            authorization,
        )
        self.assertEqual(authorization.owner_id, self.authorization().owner_id)
        self.assertNotEqual(
            authorization.owner_id,
            replace(authorization, executor_instance_id=fixed(10)).owner_id,
        )
        with self.assertRaises(ValueError):
            ReconciliationExecutorAuthorizationV2(
                invocation_id=fixed(6),
                execution_scope_digest=self.scope().digest,
                operator_id=fixed(7),
                executor_instance_id=fixed(8),
                credential_id=fixed(9),
                not_before=100,
                not_after=100,
            )

    def test_credential_round_trip_and_exact_authentication_message(self) -> None:
        credential = AuthenticatedReconciliationExecutorV2(
            self.authorization(),
            b"credential-signature",
        )
        encoded = encode_authenticated_reconciliation_executor(credential)
        self.assertEqual(
            decode_authenticated_reconciliation_executor(encoded),
            credential,
        )
        self.assertEqual(
            credential.authentication_message,
            CREDENTIAL_AUTHENTICATION_DOMAIN
            + encode_reconciliation_executor_authorization(
                credential.authorization
            ),
        )
        with self.assertRaises(ValueError):
            decode_authenticated_reconciliation_executor(encoded + b"\n")
        value = json.loads(encoded.decode("ascii"))
        value["authentication"] = value["authentication"].upper()
        with self.assertRaises(ValueError):
            decode_authenticated_reconciliation_executor(
                json.dumps(
                    value,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
            )

    def test_identifiers_and_validity_are_bounded(self) -> None:
        with self.assertRaises(ValueError):
            replace(self.scope(), clock_id=bytes(32))
        with self.assertRaises(TypeError):
            replace(self.scope(), lease_seconds=True)
        with self.assertRaises(ValueError):
            AuthenticatedReconciliationExecutorV2(
                self.authorization(),
                b"",
            )

    def test_manifest_matches_and_preserves_claim_boundary(self) -> None:
        self.assertEqual(
            json.loads(MANIFEST.read_text(encoding="utf-8")),
            reconciliation_execution_context_manifest(),
        )
        claims = reconciliation_execution_context_manifest()["claim_boundary"]
        self.assertTrue(claims["owner_id_derived_from_authenticated_authorization"])
        self.assertTrue(claims["backend_readiness_gate_implemented"])
        self.assertTrue(claims["reconciliation_policy_pinned"])
        self.assertFalse(
            claims["authenticated_execution_scope_provider_instantiated"]
        )
        self.assertFalse(claims["actual_store_and_journal_identity_attested"])
        self.assertFalse(claims["trusted_clock_backend_instantiated"])
        self.assertFalse(claims["unique_live_executor_credential_enforced"])
        self.assertFalse(claims["production_ready"])


class CredentialedRunnerTests(LeaseFixture):
    def setUp(self) -> None:
        super().setUp()
        self.clock_id = fixed(201)
        self.verifier_id = fixed(202)
        self.scope = ReconciliationExecutionScopeV2(
            system_context_digest=fixed(203),
            replay_store_id=fixed(204),
            reconciliation_journal_id=fixed(205),
            clock_id=self.clock_id,
            credential_verifier_id=self.verifier_id,
            batch_limit=self.policy.batch_limit,
            minimum_stale_seconds=self.policy.minimum_stale_seconds,
            lease_seconds=10,
            renewal_margin_seconds=2,
        )
        self.authorization = ReconciliationExecutorAuthorizationV2(
            invocation_id=self.invocation.invocation_id,
            execution_scope_digest=self.scope.digest,
            operator_id=fixed(206),
            executor_instance_id=fixed(207),
            credential_id=fixed(208),
            not_before=90,
            not_after=200,
        )
        self.credential = AuthenticatedReconciliationExecutorV2(
            self.authorization,
            b"test-authentication",
        )
        self.verifier = CredentialVerifier(self.verifier_id)
        self.verifier.expected_message = self.credential.authentication_message
        self.verifier.expected_authentication = self.credential.authentication

    def runner(
        self,
        *,
        clock=None,
        verifier=None,
        scope=None,
        credential=None,
    ) -> CredentialedLeaseFencedResumableReconciliationRunnerV2:
        return CredentialedLeaseFencedResumableReconciliationRunnerV2(
            coordinator=self.coordinator,
            journal=self.journal,
            execution_scope=self.scope if scope is None else scope,
            trusted_clock=(
                ReadyClock(self.clock_id, 100, 101, 102)
                if clock is None
                else clock
            ),
            credential_verifier=(
                self.verifier if verifier is None else verifier
            ),
            encoded_executor_credential=encode_authenticated_reconciliation_executor(
                self.credential if credential is None else credential
            ),
        )

    def assert_no_execution_mutation(self) -> None:
        self.assertEqual(self.journal.counts(), (0, 0, 0, 0))
        self.assertEqual(self.journal.lease_count(), 0)

    def test_happy_path_derives_owner_and_verifies_exact_message(self) -> None:
        reserve(self.replay)
        result = self.runner().run_once(self.invocation)
        self.assertTrue(result.recorded)
        lease = self.journal.load_execution_lease(self.invocation.invocation_id)
        assert lease is not None
        self.assertEqual(lease.owner_id, self.authorization.owner_id)
        self.assertEqual(
            self.verifier.calls,
            [
                (
                    self.credential.authentication_message,
                    self.credential.authentication,
                )
            ],
        )

    def test_bad_credential_and_backend_failure_precede_all_mutation(self) -> None:
        reservation = reserve(self.replay)
        self.verifier.accepted = False
        rejected = self.runner().run_once(self.invocation)
        self.assertIs(
            rejected.disposition,
            ResumableReconciliationDispositionV2.REJECTED,
        )
        self.assert_no_execution_mutation()
        self.assertIsNotNone(self.replay.lookup(reservation.identity))

        self.verifier.broken = True
        rejected = self.runner().run_once(self.invocation)
        self.assertFalse(rejected.recorded)
        self.assert_no_execution_mutation()
        self.assertIsNotNone(self.replay.lookup(reservation.identity))

    def test_non_boolean_verifier_success_is_rejected(self) -> None:
        reserve(self.replay)
        self.verifier.accepted = 1
        result = self.runner().run_once(self.invocation)
        self.assertFalse(result.recorded)
        self.assert_no_execution_mutation()

    def test_authentication_mutation_is_rejected_before_mutation(self) -> None:
        reservation = reserve(self.replay)
        mutated = replace(self.credential, authentication=b"mutated-authentication")
        result = self.runner(credential=mutated).run_once(self.invocation)
        self.assertFalse(result.recorded)
        self.assert_no_execution_mutation()
        self.assertIsNotNone(self.replay.lookup(reservation.identity))

    def test_invocation_scope_and_encoding_mismatch_precede_mutation(self) -> None:
        reservation = reserve(self.replay)
        wrong_invocation = replace(self.authorization, invocation_id=fixed(209))
        result = self.runner(
            credential=AuthenticatedReconciliationExecutorV2(
                wrong_invocation,
                b"test-authentication",
            )
        ).run_once(self.invocation)
        self.assertFalse(result.recorded)
        self.assertEqual(self.verifier.calls, [])
        self.assert_no_execution_mutation()

        wrong_scope = replace(
            self.authorization,
            execution_scope_digest=fixed(210),
        )
        result = self.runner(
            credential=AuthenticatedReconciliationExecutorV2(
                wrong_scope,
                b"test-authentication",
            )
        ).run_once(self.invocation)
        self.assertFalse(result.recorded)
        self.assertEqual(self.verifier.calls, [])
        self.assert_no_execution_mutation()
        self.assertIsNotNone(self.replay.lookup(reservation.identity))

    def test_clock_and_verifier_identity_are_pinned(self) -> None:
        reserve(self.replay)
        result = self.runner(
            clock=ReadyClock(fixed(211), 100),
        ).run_once(self.invocation)
        self.assertFalse(result.recorded)
        self.assert_no_execution_mutation()
        wrong_verifier = CredentialVerifier(fixed(212))
        result = self.runner(verifier=wrong_verifier).run_once(self.invocation)
        self.assertFalse(result.recorded)
        self.assert_no_execution_mutation()

    def test_reconciliation_policy_is_pinned_before_mutation(self) -> None:
        reservation = reserve(self.replay)
        result = self.runner(
            scope=replace(self.scope, batch_limit=self.scope.batch_limit - 1),
        ).run_once(self.invocation)
        self.assertFalse(result.recorded)
        self.assertEqual(self.verifier.calls, [])
        self.assert_no_execution_mutation()
        self.assertIsNotNone(self.replay.lookup(reservation.identity))

    def test_unready_backends_and_initial_clock_failure_fail_closed(self) -> None:
        reserve(self.replay)
        clock = ReadyClock(self.clock_id, 100)
        clock.production_ready = False
        result = self.runner(clock=clock).run_once(self.invocation)
        self.assertFalse(result.recorded)
        self.assert_no_execution_mutation()

        verifier = CredentialVerifier(self.verifier_id)
        verifier.production_ready = False
        result = self.runner(verifier=verifier).run_once(self.invocation)
        self.assertFalse(result.recorded)
        self.assert_no_execution_mutation()

        broken_clock = ReadyClock(self.clock_id, 100)
        broken_clock.broken = True
        result = self.runner(clock=broken_clock).run_once(self.invocation)
        self.assertFalse(result.recorded)
        self.assert_no_execution_mutation()

    def test_not_before_and_exact_expiry_reject_before_mutation(self) -> None:
        reserve(self.replay)
        for observed_at in (89, 200):
            with self.subTest(observed_at=observed_at):
                result = self.runner(
                    clock=ReadyClock(self.clock_id, observed_at),
                ).run_once(self.invocation)
                self.assertFalse(result.recorded)
                self.assert_no_execution_mutation()

    def test_expiry_is_rechecked_on_later_lease_sample(self) -> None:
        reservation = reserve(self.replay)
        result = self.runner(
            clock=ReadyClock(self.clock_id, 100, 200),
        ).run_once(self.invocation)
        self.assertIs(
            result.disposition,
            ResumableReconciliationDispositionV2.AUDIT_UNCERTAIN,
        )
        self.assertEqual(self.journal.counts(), (1, 1, 0, 0))
        self.assertEqual(self.journal.lease_count(), 1)
        self.assertIsNone(self.replay.lookup(reservation.identity))

    def test_clock_rollback_is_rechecked_on_later_lease_sample(self) -> None:
        reserve(self.replay)
        result = self.runner(
            clock=ReadyClock(self.clock_id, 100, 99),
        ).run_once(self.invocation)
        self.assertIs(
            result.disposition,
            ResumableReconciliationDispositionV2.AUDIT_UNCERTAIN,
        )
        self.assertEqual(self.journal.counts(), (1, 1, 0, 0))

    def test_terminal_retry_still_requires_current_credential(self) -> None:
        reserve(self.replay)
        self.assertTrue(self.runner().run_once(self.invocation).recorded)
        before = self.journal.counts()
        expired = self.runner(
            clock=ReadyClock(self.clock_id, 200),
        ).run_once(self.invocation)
        self.assertFalse(expired.recorded)
        self.assertEqual(self.journal.counts(), before)


if __name__ == "__main__":
    unittest.main()
