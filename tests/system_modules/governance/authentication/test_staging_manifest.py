from __future__ import annotations

import json
import unittest
from pathlib import Path

from pq_rbbc.governance.authentication import (
    MLDSA65_PUBLIC_KEY_DER_BYTES,
    MLDSA65_SIGNATURE_BYTES,
    MLDSA65_STAGING_PROFILE,
    SYSTEM_GOVERNANCE_MLDSA_CONTEXT,
    TRUST_REGISTRY_FILENAME,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
MANIFEST_PATH = (
    REPOSITORY_ROOT
    / "manifests/system_governance/fac_authentication_mldsa65_staging_v1.json"
)


class StagingManifestTests(unittest.TestCase):
    def test_manifest_matches_implemented_profile_and_claim_boundary(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_bytes())
        authentication = manifest["authentication"]
        claims = manifest["claim_boundary"]
        registry = manifest["trust_registry"]

        self.assertEqual(authentication["profile"], MLDSA65_STAGING_PROFILE)
        self.assertEqual(
            authentication["application_context_ascii"],
            SYSTEM_GOVERNANCE_MLDSA_CONTEXT.decode("ascii"),
        )
        self.assertEqual(
            authentication["public_key_size_bytes"],
            MLDSA65_PUBLIC_KEY_DER_BYTES,
        )
        self.assertEqual(
            authentication["signature_size_bytes"], MLDSA65_SIGNATURE_BYTES
        )
        self.assertEqual(registry["filename"], TRUST_REGISTRY_FILENAME)
        self.assertFalse(registry["secret_key_bytes_allowed"])
        self.assertTrue(claims["ordinary_mldsa65_real_positive_tested"])
        self.assertTrue(claims["full_bundle_authentication_implemented"])
        self.assertTrue(claims["issuer_grant_authentication_implemented"])
        self.assertFalse(claims["fac_threshold_signature_implemented"])
        self.assertFalse(claims["fac_dkg_implemented"])
        self.assertFalse(claims["fips_140_validated_module_claimed"])
        self.assertFalse(claims["production_closed"])
        self.assertFalse(claims["proof_closed"])


if __name__ == "__main__":
    unittest.main()
