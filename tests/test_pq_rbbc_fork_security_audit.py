import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import pq_rbbc_fork_security_audit as audit


ROOT = Path(__file__).resolve().parents[1]


class ForkSecurityAuditTests(unittest.TestCase):
    def test_tracked_sources_have_frozen_identities(self) -> None:
        for relative, size, digest in (
            audit.PROOF_SOURCE,
            audit.V2_29_EVIDENCE,
            audit.V2_30_PREFLIGHT,
        ):
            path = ROOT / relative
            self.assertEqual(path.stat().st_size, size)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_documents_are_deterministic_and_path_free(self) -> None:
        first = audit.build_documents()
        second = audit.build_documents()
        self.assertEqual(first, second)
        encoded = json.dumps(first, sort_keys=True)
        self.assertNotIn("/tmp/", encoded)
        self.assertNotIn(str(ROOT), encoded)

    def test_generated_document_identities_reconstruct(self) -> None:
        documents = audit.build_documents()
        manifest = documents[audit.AUDIT_MANIFEST_FILENAME]
        expected = {
            item["name"]: (item["bytes"], item["sha256"])
            for item in manifest["generated_documents"]
        }
        for name, document in documents.items():
            if name == audit.AUDIT_MANIFEST_FILENAME:
                continue
            data = audit.canonical_json(document)
            self.assertEqual(
                expected[name],
                (len(data), hashlib.sha256(data).hexdigest()),
            )

    def test_reviews_fail_closed(self) -> None:
        documents = audit.build_documents()
        for name in (
            audit.CAP_REVIEW_FILENAME,
            audit.QROM_REVIEW_FILENAME,
            audit.BLINDNESS_REVIEW_FILENAME,
        ):
            document = documents[name]
            self.assertFalse(
                document["reviewer_boundary"]["reviewer_independent_of_project"]
            )
            self.assertFalse(
                document["reviewer_boundary"]["may_promote_security_claims"]
            )
            self.assertFalse(
                document["claim_boundary"]["fork_security_proof_revalidated"]
            )

    def test_review_request_is_not_an_attestation(self) -> None:
        request = audit.build_documents()[audit.REVIEW_REQUEST_FILENAME]
        self.assertTrue(request["review_requested"])
        self.assertFalse(request["independent_review_completed"])
        self.assertFalse(request["attestation_present"])
        self.assertIsNone(request["reviewer_identity"])

    def test_manifest_allows_review_but_not_security_claim(self) -> None:
        manifest = audit.build_documents()[audit.AUDIT_MANIFEST_FILENAME]
        self.assertTrue(manifest["safe_to_start_independent_review"])
        self.assertFalse(manifest["safe_to_claim_fork_security_revalidated"])
        self.assertFalse(manifest["safe_to_start_large_replay"])
        self.assertFalse(manifest["large_replay_started"])

    def test_mutated_external_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate"
            path.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "byte length mismatch"):
                audit.require_identity(path, (8, "00" * 32), "candidate")


if __name__ == "__main__":
    unittest.main()
