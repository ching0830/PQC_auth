import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pq_rbbc_fork_security_audit as audit
import pq_rbbc_fork_security_audit_evidence as evidence


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_PATH = ROOT / evidence.EVIDENCE_RELATIVE


class ForkSecurityAuditEvidenceTests(unittest.TestCase):
    def test_frozen_packet_seals(self) -> None:
        with mock.patch.object(evidence, "validate_packet"):
            document = evidence.build_evidence(Path("unused"))
        self.assertTrue(document["audit_result"]["packet_ready_for_independent_review"])
        self.assertFalse(document["audit_result"]["independent_review_completed"])

    def test_portable_evidence_matches_generator(self) -> None:
        document = json.loads(EVIDENCE_PATH.read_text())
        with mock.patch.object(evidence, "validate_packet"):
            generated = evidence.build_evidence(Path("unused"))
        self.assertEqual(EVIDENCE_PATH.read_bytes(), evidence.canonical_json(generated))
        self.assertNotIn("/tmp/", json.dumps(document, sort_keys=True))
        self.assertFalse(
            document["artifact_policy"]["portable_evidence_contains_absolute_paths"]
        )

    def test_claim_boundary_does_not_promote_security(self) -> None:
        claims = evidence.claim_boundary()
        self.assertTrue(claims["v2_30_internal_proof_audit_closed"])
        self.assertTrue(claims["v2_30_independent_review_ready"])
        for name in (
            "independent_review_attestation_present",
            "cap_unique_witness_reviewed",
            "cap_straightline_extraction_reviewed",
            "qrom_request_binding_reviewed",
            "fork_blindness_revalidated",
            "fork_one_more_unforgeability_revalidated",
            "fork_security_proof_revalidated",
            "production_closed",
        ):
            self.assertFalse(claims[name], name)

    def test_unfrozen_attestation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            documents = audit.build_documents()
            for name in evidence.GENERATED_IDENTITIES:
                (root / name).write_bytes(audit.canonical_json(documents[name]))
            (root / evidence.INDEPENDENT_ATTESTATION_FILENAME).write_text("{}")
            with mock.patch.object(audit, "validate_external_sources"):
                with mock.patch.object(audit, "require_identity"):
                    with self.assertRaisesRegex(
                        ValueError, "unfrozen independent attestation"
                    ):
                        evidence.validate_packet(root)

    def test_changed_frozen_review_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in evidence.GENERATED_IDENTITIES:
                (root / name).write_text("{}")
            with mock.patch.object(audit, "validate_external_sources"):
                with mock.patch.object(
                    audit,
                    "require_identity",
                    side_effect=ValueError("CAP review SHA-256 mismatch"),
                ):
                    with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                        evidence.validate_packet(root)


if __name__ == "__main__":
    unittest.main()
