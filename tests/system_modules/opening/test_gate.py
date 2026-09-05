#!/usr/bin/env python3
"""Validation-order, authorization, replay, and failure-boundary tests."""

from __future__ import annotations

import unittest
from dataclasses import replace

from pq_rbbc.contracts.system import KeyRole

from tests.system_modules.opening._fixtures import (
    DigestAuthorizationVerifier,
    FixedClock,
    FixedTicketVerifier,
    FixtureShareBackend,
    MemoryReplayStore,
    fixed_bytes,
    reference_request,
    service,
)


class OpenShareGateTests(unittest.TestCase):
    def test_honest_gated_request_accepts_with_opening_authorization_role(self) -> None:
        opener, _ticket, authorization, replay, backend = service()
        outcome = opener.open_share(reference_request().encode())
        self.assertTrue(outcome.accepted, outcome.failure)
        self.assertIsNotNone(outcome.share)
        self.assertEqual(authorization.roles, [KeyRole.OPENING_AUTHORIZATION])
        self.assertEqual(backend.calls, 1)
        self.assertEqual(replay.commit_calls, 1)

    def test_invalid_ticket_never_touches_threshold_backend(self) -> None:
        backend = FixtureShareBackend()
        opener, *_rest = service(
            ticket_verifier=FixedTicketVerifier(reject=True), backend=backend
        )
        outcome = opener.open_share(reference_request().encode())
        self.assertEqual(outcome.failure, "ticket_invalid")
        self.assertEqual(backend.calls, 0)

    def test_invalid_authorization_never_touches_threshold_backend(self) -> None:
        backend = FixtureShareBackend()
        opener, *_rest = service(
            authorization_verifier=DigestAuthorizationVerifier(reject=True),
            backend=backend,
        )
        outcome = opener.open_share(reference_request().encode())
        self.assertEqual(outcome.failure, "authorization_invalid")
        self.assertEqual(backend.calls, 0)

    def test_wrong_ctx_rejects_before_authorization_and_backend(self) -> None:
        request = replace(reference_request(), ctx=fixed_bytes(b"wrong-ctx"))
        opener, _ticket, authorization, _replay, backend = service()
        outcome = opener.open_share(request.encode())
        self.assertEqual(outcome.failure, "ctx_mismatch")
        self.assertEqual(authorization.calls, 0)
        self.assertEqual(backend.calls, 0)

    def test_wrong_epoch_rejects_before_authorization_and_backend(self) -> None:
        request = reference_request()
        candidate = replace(request, epoch=request.epoch + 1)
        opener, _ticket, authorization, _replay, backend = service()
        outcome = opener.open_share(candidate.encode())
        self.assertEqual(outcome.failure, "epoch_mismatch")
        self.assertEqual(authorization.calls, 0)
        self.assertEqual(backend.calls, 0)

    def test_mutated_case_evidence_purpose_expiry_and_nonce_reject(self) -> None:
        request = reference_request()
        mutations = {
            "case": replace(request, case_id=fixed_bytes(b"wrong-case")),
            "evidence": replace(
                request, evidence_digest=fixed_bytes(b"wrong-evidence")
            ),
            "purpose": replace(request, purpose="unbound-purpose"),
            "expiry": replace(request, expiry=request.expiry - 1),
            "nonce": replace(request, request_nonce=fixed_bytes(b"wrong-nonce")),
        }
        for name, candidate in mutations.items():
            with self.subTest(name=name):
                opener, _ticket, _authorization, _replay, backend = service()
                outcome = opener.open_share(candidate.encode())
                self.assertEqual(outcome.failure, "authorization_invalid")
                self.assertEqual(backend.calls, 0)

    def test_expired_authorization_rejects_even_when_signature_is_valid(self) -> None:
        request = reference_request()
        opener, _ticket, _authorization, _replay, backend = service(
            clock=FixedClock(request.expiry)
        )
        outcome = opener.open_share(request.encode())
        self.assertEqual(outcome.failure, "authorization_expired")
        self.assertEqual(backend.calls, 0)

    def test_wrong_opening_or_authorization_key_id_rejects(self) -> None:
        request = reference_request()
        cases = {
            "opening": replace(
                request, opening_key_id=fixed_bytes(b"wrong-opening-key")
            ),
            "authorization": replace(
                request,
                authorization_key_id=fixed_bytes(b"wrong-authorization-key"),
            ),
        }
        for name, candidate in cases.items():
            with self.subTest(name=name):
                opener, _ticket, authorization, _replay, backend = service()
                outcome = opener.open_share(candidate.encode())
                self.assertIn("key_id_mismatch", outcome.failure or "")
                self.assertEqual(authorization.calls, 0)
                self.assertEqual(backend.calls, 0)

    def test_ticket_digest_mismatch_rejects_before_authorization(self) -> None:
        class WrongDigestTicketVerifier(FixedTicketVerifier):
            def verify(self, canonical_ticket: bytes):
                ticket = super().verify(canonical_ticket)
                assert ticket is not None
                return replace(
                    ticket, ticket_digest=fixed_bytes(b"wrong-ticket-digest")
                )

        opener, _ticket, authorization, _replay, backend = service(
            ticket_verifier=WrongDigestTicketVerifier()
        )
        outcome = opener.open_share(reference_request().encode())
        self.assertEqual(outcome.failure, "ticket_digest_mismatch")
        self.assertEqual(authorization.calls, 0)
        self.assertEqual(backend.calls, 0)

    def test_request_replay_rejects_without_second_backend_call(self) -> None:
        replay = MemoryReplayStore()
        backend = FixtureShareBackend()
        opener, *_rest = service(replay_store=replay, backend=backend)
        encoded = reference_request().encode()
        self.assertTrue(opener.open_share(encoded).accepted)
        second = opener.open_share(encoded)
        self.assertEqual(second.failure, "request_replay")
        self.assertEqual(backend.calls, 1)

    def test_in_progress_parallel_reservation_is_treated_as_replay(self) -> None:
        request = reference_request()
        replay = MemoryReplayStore()
        reservation = replay.begin(request.replay_key)
        self.assertIsNotNone(reservation)
        backend = FixtureShareBackend()
        opener, *_rest = service(replay_store=replay, backend=backend)
        outcome = opener.open_share(request.encode())
        self.assertEqual(outcome.failure, "request_replay")
        self.assertEqual(backend.calls, 0)

    def test_backend_exceptions_fail_closed_and_preserve_call_order(self) -> None:
        class BrokenConfigurationVerifier:
            def verify(self, *_args: object) -> bool:
                raise RuntimeError("test initialization failure")

        scenarios = (
            (
                "initialization",
                {"configuration_verifier": BrokenConfigurationVerifier()},
            ),
            ("ticket_backend", {"ticket_verifier": FixedTicketVerifier(broken=True)}),
            (
                "authorization_backend",
                {"authorization_verifier": DigestAuthorizationVerifier(broken=True)},
            ),
        )
        for expected, kwargs in scenarios:
            with self.subTest(expected=expected):
                backend = FixtureShareBackend()
                opener, *_rest = service(backend=backend, **kwargs)
                outcome = opener.open_share(reference_request().encode())
                self.assertTrue((outcome.failure or "").startswith(expected))
                self.assertIsNone(outcome.share)
                self.assertEqual(backend.calls, 0)

    def test_replay_and_threshold_failures_fail_closed(self) -> None:
        replay = MemoryReplayStore()
        replay.break_begin = True
        backend = FixtureShareBackend()
        opener, *_rest = service(replay_store=replay, backend=backend)
        outcome = opener.open_share(reference_request().encode())
        self.assertTrue((outcome.failure or "").startswith("replay_begin_backend"))
        self.assertEqual(backend.calls, 0)

        replay = MemoryReplayStore()
        backend = FixtureShareBackend(broken=True)
        opener, *_rest = service(replay_store=replay, backend=backend)
        outcome = opener.open_share(reference_request().encode())
        self.assertTrue((outcome.failure or "").startswith("threshold_backend"))
        self.assertEqual(backend.calls, 1)
        self.assertEqual(replay.abort_calls, 1)
        self.assertNotIn(reference_request().replay_key, replay.states)

    def test_commit_failure_emits_no_share_and_does_not_abort(self) -> None:
        replay = MemoryReplayStore()
        replay.break_commit = True
        opener, *_rest = service(replay_store=replay)
        outcome = opener.open_share(reference_request().encode())
        self.assertTrue((outcome.failure or "").startswith("replay_commit_backend"))
        self.assertIsNone(outcome.share)
        self.assertEqual(replay.abort_calls, 0)
        self.assertEqual(
            replay.states[reference_request().replay_key][0], "in_progress"
        )


if __name__ == "__main__":
    unittest.main()
