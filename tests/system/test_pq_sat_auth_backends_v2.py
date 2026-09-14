from __future__ import annotations

import unittest

from pq_sat_auth.v2.access import REFERENCE_PROOF_SUITE_ID, REFERENCE_SUITE_ID
from pq_sat_auth.v2.backends import (
    ProductionBackendUnavailable,
    SessionKeysV2,
    require_production_backend,
)


class BackendStub:
    def __init__(
        self,
        suite_id: int,
        production_ready: bool,
        *,
        proof_backend: bool = False,
    ) -> None:
        if proof_backend:
            self.proof_suite_id = suite_id
        else:
            self.suite_id = suite_id
        self.production_ready = production_ready


class BackendBoundaryV2Tests(unittest.TestCase):
    def test_reference_suites_cannot_cross_production_gate(self) -> None:
        for suite_id, proof_backend in (
            (REFERENCE_SUITE_ID, False),
            (REFERENCE_PROOF_SUITE_ID, True),
        ):
            with self.subTest(proof_backend=proof_backend):
                with self.assertRaises(ProductionBackendUnavailable):
                    require_production_backend(
                        BackendStub(
                            suite_id,
                            True,
                            proof_backend=proof_backend,
                        ),
                        expected_suite_id=suite_id,
                        proof_backend=proof_backend,
                    )

    def test_gate_rejects_mismatch_and_false_readiness(self) -> None:
        with self.assertRaises(ProductionBackendUnavailable):
            require_production_backend(
                BackendStub(7, True),
                expected_suite_id=8,
            )
        with self.assertRaises(ProductionBackendUnavailable):
            require_production_backend(
                BackendStub(8, False),
                expected_suite_id=8,
            )
        require_production_backend(
            BackendStub(8, True),
            expected_suite_id=8,
        )

    def test_session_keys_require_nonempty_bytes(self) -> None:
        keys = SessionKeysV2(b"s", b"c", b"a", b"e")
        self.assertEqual(keys.application_key, b"a")
        with self.assertRaises(ValueError):
            SessionKeysV2(b"", b"c", b"a", b"e")
        with self.assertRaises(TypeError):
            SessionKeysV2(b"s", b"c", b"a", "e")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
