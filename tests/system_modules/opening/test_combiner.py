#!/usr/bin/env python3
"""Threshold combiner consistency and post-reconstruction checks."""

from __future__ import annotations

import unittest
from dataclasses import replace

from pq_rbbc.opening.combiner import OpeningCombiner

from tests.system_modules.opening._fixtures import (
    DigestShareVerifier,
    FixtureReconstructionBackend,
    FixtureTraceAuthenticationVerifier,
    VISIBLE_SERIAL,
    fixed_bytes,
    honest_share,
    reference_bundle,
    reference_ticket_view,
    resign_share,
)


def encoded_honest_shares() -> list[bytes]:
    return [honest_share(index).encode() for index in range(1, 6)]


def combiner(
    *,
    reconstruction: FixtureReconstructionBackend | None = None,
    trace_authentication: FixtureTraceAuthenticationVerifier | None = None,
) -> tuple[OpeningCombiner, FixtureReconstructionBackend]:
    reconstruction = reconstruction or FixtureReconstructionBackend()
    return (
        OpeningCombiner(
            bundle=reference_bundle(),
            share_verifier=DigestShareVerifier(),
            reconstruction_backend=reconstruction,
            trace_authentication_verifier=trace_authentication
            or FixtureTraceAuthenticationVerifier(),
        ),
        reconstruction,
    )


class OpeningCombinerTests(unittest.TestCase):
    def test_honest_threshold_reconstruction_accepts(self) -> None:
        instance, reconstruction = combiner()
        outcome = instance.combine(reference_ticket_view(), encoded_honest_shares())
        self.assertTrue(outcome.accepted, outcome.failure)
        self.assertEqual(outcome.decoded.serial, VISIBLE_SERIAL)
        self.assertEqual(reconstruction.calls, 1)

    def test_duplicate_member_and_fewer_than_threshold_reject(self) -> None:
        shares = encoded_honest_shares()
        instance, reconstruction = combiner()
        duplicate = [shares[0], shares[0], *shares[2:]]
        self.assertEqual(
            instance.combine(reference_ticket_view(), duplicate).failure,
            "duplicate_member",
        )
        self.assertEqual(
            instance.combine(reference_ticket_view(), shares[:4]).failure,
            "fewer_than_threshold",
        )
        self.assertEqual(reconstruction.calls, 0)

    def test_mixed_request_ticket_epoch_key_and_case_reject(self) -> None:
        original = [honest_share(index) for index in range(1, 6)]
        mutations = {
            "mixed_request": replace(
                original[-1], request_digest=fixed_bytes(b"other-request")
            ),
            "mixed_ticket": replace(
                original[-1], ticket_digest=fixed_bytes(b"other-ticket")
            ),
            "mixed_epoch": replace(original[-1], epoch=original[-1].epoch + 1),
            "mixed_opening_key": replace(
                original[-1], opening_key_id=fixed_bytes(b"other-opening-key")
            ),
            "mixed_case": replace(
                original[-1], case_id=fixed_bytes(b"other-case")
            ),
        }
        for expected, mutation in mutations.items():
            with self.subTest(expected=expected):
                shares = [*original[:-1], resign_share(mutation)]
                instance, reconstruction = combiner()
                outcome = instance.combine(
                    reference_ticket_view(), [share.encode() for share in shares]
                )
                self.assertEqual(outcome.failure, expected)
                self.assertEqual(reconstruction.calls, 0)

    def test_consistently_wrong_key_and_stale_epoch_reject(self) -> None:
        originals = [honest_share(index) for index in range(1, 6)]
        cases = {
            "wrong_opening_key": [
                resign_share(
                    replace(share, opening_key_id=fixed_bytes(b"wrong-opening-key"))
                )
                for share in originals
            ],
            "stale_epoch": [
                resign_share(replace(share, epoch=share.epoch - 1))
                for share in originals
            ],
        }
        for expected, shares in cases.items():
            with self.subTest(expected=expected):
                instance, reconstruction = combiner()
                outcome = instance.combine(
                    reference_ticket_view(), [share.encode() for share in shares]
                )
                self.assertEqual(outcome.failure, expected)
                self.assertEqual(reconstruction.calls, 0)

    def test_invalid_share_rejects_before_reconstruction(self) -> None:
        shares = [honest_share(index) for index in range(1, 6)]
        shares[-1] = replace(shares[-1], authentication=fixed_bytes(b"bad-proof"))
        instance, reconstruction = combiner()
        outcome = instance.combine(
            reference_ticket_view(), [share.encode() for share in shares]
        )
        self.assertEqual(outcome.failure, "invalid_share")
        self.assertEqual(reconstruction.calls, 0)

    def test_share_verifier_exception_fails_closed(self) -> None:
        class BrokenShareVerifier:
            def verify(self, *_args: object) -> bool:
                raise RuntimeError("test share verifier failure")

        reconstruction = FixtureReconstructionBackend()
        instance = OpeningCombiner(
            bundle=reference_bundle(),
            share_verifier=BrokenShareVerifier(),
            reconstruction_backend=reconstruction,
            trace_authentication_verifier=FixtureTraceAuthenticationVerifier(),
        )
        outcome = instance.combine(reference_ticket_view(), encoded_honest_shares())
        self.assertTrue(
            (outcome.failure or "").startswith("share_verifier_backend")
        )
        self.assertEqual(reconstruction.calls, 0)

    def test_serial_mismatch_rejects_after_trace_authentication(self) -> None:
        reconstruction = FixtureReconstructionBackend(
            serial=fixed_bytes(b"wrong-serial")[:16]
        )
        instance, _backend = combiner(reconstruction=reconstruction)
        outcome = instance.combine(reference_ticket_view(), encoded_honest_shares())
        self.assertEqual(outcome.failure, "serial_mismatch")
        self.assertIsNone(outcome.decoded)

    def test_trace_authentication_and_backend_exceptions_fail_closed(self) -> None:
        instance, _backend = combiner(
            trace_authentication=FixtureTraceAuthenticationVerifier(reject=True)
        )
        outcome = instance.combine(reference_ticket_view(), encoded_honest_shares())
        self.assertEqual(outcome.failure, "trace_authentication_invalid")

        instance, _backend = combiner(
            reconstruction=FixtureReconstructionBackend(broken=True)
        )
        outcome = instance.combine(reference_ticket_view(), encoded_honest_shares())
        self.assertTrue((outcome.failure or "").startswith("reconstruction_backend"))

        instance, _backend = combiner(
            trace_authentication=FixtureTraceAuthenticationVerifier(broken=True)
        )
        outcome = instance.combine(reference_ticket_view(), encoded_honest_shares())
        self.assertTrue(
            (outcome.failure or "").startswith("trace_authentication_backend")
        )


if __name__ == "__main__":
    unittest.main()
