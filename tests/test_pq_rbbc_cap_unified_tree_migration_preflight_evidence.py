import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pq_rbbc_cap_unified_tree_migration_preflight_evidence as evidence


ROOT = Path(__file__).resolve().parents[1]
REPORT = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/v2_33_unified_tree_migration/"
    "pq_rbbc_cap_unified_tree_environment_v2_33.json"
)
SEALED = (
    ROOT
    / "artifacts/metadata/cap_unified_tree_migration_v2_33/"
    "pq_rbbc_cap_unified_tree_migration_preflight_evidence_v2_33.json"
)


class UnifiedTreeMigrationPreflightEvidenceTests(unittest.TestCase):
    def test_portable_evidence_matches_generator(self) -> None:
        if not REPORT.is_file():
            self.skipTest("external v2.33 initial report is not installed")
        self.assertEqual(
            SEALED.read_bytes(),
            evidence.canonical_json(evidence.build_evidence(REPORT)),
        )

    def test_portable_evidence_is_path_free_and_fail_closed(self) -> None:
        document = json.loads(SEALED.read_text())
        encoded = SEALED.read_bytes()
        self.assertNotIn(b"/tmp/", encoded)
        self.assertNotIn(b"/home/", encoded)
        self.assertTrue(document["result"]["v2_33_read_only_migration_preflight_closed"])
        self.assertTrue(document["result"]["safe_to_implement_reduced_prototype"])
        for name in (
            "safe_to_start_production_prefreeze",
            "safe_to_start_large_replay",
            "safe_to_start_large_proving_run",
            "large_profile_build_started",
            "large_replay_started",
            "large_proving_run_started",
        ):
            self.assertFalse(document["result"][name], name)
        self.assertFalse(document["observed_capacity"]["is_execution_authorization"])

    def test_claim_expansion_is_rejected(self) -> None:
        if not REPORT.is_file():
            self.skipTest("external v2.33 initial report is not installed")
        original = json.loads(REPORT.read_text())
        original["safe_to_start_large_replay"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / REPORT.name
            path.write_text(json.dumps(original, sort_keys=True, separators=(",", ":")) + "\n")
            with patch.object(
                evidence,
                "INITIAL_REPORT",
                (path.stat().st_size, evidence._sha256(path)),
            ):
                with self.assertRaisesRegex(ValueError, "result or frozen contract"):
                    evidence.build_evidence(path)

    def test_missing_migration_boundary_is_rejected(self) -> None:
        if not REPORT.is_file():
            self.skipTest("external v2.33 initial report is not installed")
        original = json.loads(REPORT.read_text())
        original["checks"]["migration_artifacts"]["runner_qualification"][
            "failures"
        ] = []
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
