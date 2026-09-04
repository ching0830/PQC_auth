import unittest
from pathlib import Path
from unittest import mock

import pq_rbbc_cap_security_artifact_evidence as evidence


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_PATH = ROOT / evidence.EVIDENCE_RELATIVE
EXTERNAL_ROOT = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/v2_31_cap_security"
)
EXTERNAL_REPORT = (
    EXTERNAL_ROOT / "pq_rbbc_cap_security_environment_with_candidates_v2_31.json"
)


class CAPSecurityArtifactEvidenceTests(unittest.TestCase):
    def test_portable_evidence_matches_generator(self) -> None:
        with mock.patch.object(evidence, "validate_bundle"):
            generated = evidence.build_evidence(EXTERNAL_ROOT, EXTERNAL_REPORT)
        self.assertEqual(EVIDENCE_PATH.read_bytes(), evidence.canonical_json(generated))
        self.assertNotIn(b"/tmp/", evidence.canonical_json(generated))

    def test_claims_remain_fail_closed(self) -> None:
        with mock.patch.object(evidence, "validate_bundle"):
            document = evidence.build_evidence(EXTERNAL_ROOT, EXTERNAL_REPORT)
        self.assertTrue(
            document["result"]["proof_candidate_artifacts_verified"]
        )
        self.assertTrue(document["result"]["safe_to_request_independent_review"])
        self.assertFalse(document["result"]["independent_review_completed"])
        self.assertFalse(
            document["result"]["safe_to_start_cap_security_qualification"]
        )
        self.assertFalse(document["claim_boundary"]["cap_security_qualified"])
        self.assertFalse(
            document["claim_boundary"]["fork_security_proof_revalidated"]
        )

    @unittest.skipUnless(
        EXTERNAL_REPORT.is_file(),
        "external v2.31 candidate report is not installed",
    )
    def test_external_bundle_revalidates(self) -> None:
        report = evidence.validate_bundle(EXTERNAL_ROOT, EXTERNAL_REPORT)
        self.assertEqual(report["blockers"], ["independent_review_attestation"])


if __name__ == "__main__":
    unittest.main()
