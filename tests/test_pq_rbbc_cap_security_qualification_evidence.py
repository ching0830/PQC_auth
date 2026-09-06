import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pq_rbbc_cap_security_qualification as qualification
import pq_rbbc_cap_security_qualification_evidence as evidence


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_PATH = ROOT / evidence.EVIDENCE_RELATIVE


class CAPSecurityQualificationEvidenceTests(unittest.TestCase):
    def test_portable_evidence_matches_generator(self) -> None:
        with mock.patch.object(evidence, "validate_checkpoint"):
            generated = evidence.build_evidence(Path("unused"))
        self.assertEqual(
            EVIDENCE_PATH.read_bytes(), evidence.canonical_json(generated)
        )
        self.assertNotIn("/tmp/", json.dumps(generated, sort_keys=True))

    def test_checkpoint_does_not_promote_security(self) -> None:
        with mock.patch.object(evidence, "validate_checkpoint"):
            document = evidence.build_evidence(Path("unused"))
        result = document["checkpoint_result"]
        self.assertTrue(result["qualification_contract_closed"])
        self.assertTrue(result["extractor_interface_frozen"])
        self.assertFalse(result["safe_to_start_cap_security_qualification"])
        self.assertFalse(result["safe_to_claim_cap_security_qualified"])
        self.assertFalse(result["safe_to_start_large_replay"])
        self.assertFalse(document["claim_boundary"]["cap_security_qualified"])
        self.assertFalse(
            document["claim_boundary"]["fork_security_proof_revalidated"]
        )

    def test_candidate_identities_are_frozen_but_review_is_not(self) -> None:
        with mock.patch.object(evidence, "validate_checkpoint"):
            document = evidence.build_evidence(Path("unused"))
        blockers = document["external_blockers"]
        self.assertEqual(
            {item["name"] for item in blockers},
            set(qualification.EXTERNAL_REQUIREMENTS),
        )
        by_name = {item["name"]: item for item in blockers}
        for name in (
            "extractor_specification",
            "unique_mask_reduction",
            "qualification_evidence",
        ):
            self.assertTrue(by_name[name]["identity_frozen"])
            self.assertIn("bytes", by_name[name])
            self.assertIn("sha256", by_name[name])
        self.assertFalse(
            by_name["independent_review_attestation"]["identity_frozen"]
        )

    def test_report_claim_expansion_is_rejected(self) -> None:
        report = qualification.build_environment_report({})
        report["safe_to_claim_cap_security_qualified"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_bytes(qualification.canonical_json(report))
            with mock.patch.object(evidence, "_require_identity"):
                with self.assertRaisesRegex(ValueError, "content mismatch"):
                    evidence.validate_checkpoint(path)

    def test_manifest_claim_expansion_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            manifest = qualification.build_frozen_manifest()
            manifest["claim_boundary"]["cap_security_qualified"] = True
            path.write_bytes(qualification.canonical_json(manifest))
            with mock.patch.object(evidence, "_require_identity"):
                with mock.patch.object(
                    evidence,
                    "FROZEN_MANIFEST_RELATIVE",
                    str(path),
                ):
                    with self.assertRaisesRegex(ValueError, "content mismatch"):
                        evidence.validate_checkpoint(Path("unused"))


if __name__ == "__main__":
    unittest.main()
