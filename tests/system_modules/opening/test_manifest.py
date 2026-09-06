#!/usr/bin/env python3
"""Frozen conditional-opening checkpoint vector and claim-boundary tests."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from pq_rbbc.opening.gate import conditional_opening_manifest

from tests.system_modules.opening._fixtures import honest_share, reference_request


ROOT = Path(__file__).resolve().parents[3]
FROZEN_MANIFEST = (
    ROOT / "manifests" / "pq_rbbc_conditional_opening_gate_v0_1.json"
)


class ConditionalOpeningManifestTests(unittest.TestCase):
    def test_exact_deterministic_vector_and_conservative_claims(self) -> None:
        generated = conditional_opening_manifest(reference_request(), honest_share(1))
        self.assertEqual(generated, json.loads(FROZEN_MANIFEST.read_text()))
        self.assertEqual(generated["request"]["bytes"], 441)
        self.assertEqual(generated["share"]["bytes"], 303)
        self.assertEqual(
            generated["request"]["request_digest"],
            "df66fe26ed8220de539c090ed47480eb45ac12b539fd40035adba52285121c28",
        )
        claims = generated["claim_boundary"]
        self.assertFalse(claims["full_verify_ticket_implemented"])
        self.assertFalse(claims["oa_dkg_implemented"])
        self.assertFalse(claims["robust_threshold_decoder_implemented"])
        self.assertFalse(claims["production_opening_implemented"])
        blockers = generated["integration_blockers"]
        self.assertTrue(blockers["trace_kdf_80_byte_split_order_unresolved"])
        self.assertTrue(blockers["ciphertext_decoding_kept_behind_backend_boundary"])


if __name__ == "__main__":
    unittest.main()
