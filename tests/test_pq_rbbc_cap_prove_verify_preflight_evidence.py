import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pq_rbbc_cap_prove_verify_preflight_evidence as evidence


ROOT = Path(__file__).resolve().parents[1]
REPORT = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/v2_32_cap_prove_verify/"
    "pq_rbbc_cap_prove_verify_environment_v2_32.json"
)
SEALED = (
    ROOT
    / "artifacts/metadata/cap_prove_verify_preflight_v2_32/"
    "pq_rbbc_cap_prove_verify_preflight_evidence_v2_32.json"
)


class CAPProveVerifyPreflightEvidenceTests(unittest.TestCase):
    def test_portable_evidence_matches_generator(self) -> None:
        if not REPORT.is_file():
            self.skipTest("external v2.32 initial report is not installed")
        self.assertEqual(
            SEALED.read_bytes(),
            evidence.canonical_json(evidence.build_evidence(REPORT)),
        )

    def test_portable_evidence_is_path_free_and_fail_closed(self) -> None:
        document = json.loads(SEALED.read_text())
        encoded = SEALED.read_bytes()
        self.assertNotIn(b"/tmp/", encoded)
        self.assertNotIn(b"/home/", encoded)
        self.assertTrue(document["result"]["v2_32_cap_prove_verify_preflight_closed"])
        for name in (
            "safe_to_implement_cap_prove_verify",
            "safe_to_start_large_relation_replay",
            "safe_to_start_large_proving_run",
            "safe_to_claim_cap_security_qualified",
            "large_replay_started",
            "large_proving_run_started",
        ):
            self.assertFalse(document["result"][name], name)
        self.assertIsNone(document["next_gate"]["exact_implementation_command"])

    def test_claim_expansion_is_rejected(self) -> None:
        if not REPORT.is_file():
            self.skipTest("external v2.32 initial report is not installed")
        original = json.loads(REPORT.read_text())
        original["safe_to_implement_cap_prove_verify"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / REPORT.name
            path.write_text(json.dumps(original, sort_keys=True, separators=(",", ":")) + "\n")
            with patch.object(
                evidence,
                "INITIAL_REPORT",
                (path.stat().st_size, evidence._sha256(path)),
            ):
                with self.assertRaisesRegex(ValueError, "result or claim boundary"):
                    evidence.build_evidence(path)

    def test_missing_candidate_boundary_is_rejected(self) -> None:
        if not REPORT.is_file():
            self.skipTest("external v2.32 initial report is not installed")
        original = json.loads(REPORT.read_text())
        original["checks"]["production_proof_serialization"]["failures"] = []
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / REPORT.name
            path.write_text(json.dumps(original, sort_keys=True, separators=(",", ":")) + "\n")
            with patch.object(
                evidence,
                "INITIAL_REPORT",
                (path.stat().st_size, evidence._sha256(path)),
            ):
                with self.assertRaisesRegex(ValueError, "boundary mismatch"):
                    evidence.build_evidence(path)


if __name__ == "__main__":
    unittest.main()
