import copy
import json
from pathlib import Path
import tempfile
import unittest

import pq_rbbc_cap_unified_tree_production_prefreeze as preflight
import pq_rbbc_cap_unified_tree_production_prefreeze_evidence as evidence


ROOT = Path(__file__).resolve().parents[1]
REPORT = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/v2_34_unified_tree_prefreeze/"
    "pq_rbbc_cap_unified_tree_production_prefreeze_environment_v2_34.json"
)
PORTABLE = (
    ROOT / "artifacts/metadata/cap_unified_tree_production_prefreeze_v2_34/"
    "pq_rbbc_cap_unified_tree_production_prefreeze_evidence_v2_34.json"
)


class UnifiedTreeProductionPrefreezeEvidenceTests(unittest.TestCase):
    def test_current_report_builds_path_free_evidence(self) -> None:
        document = evidence.build_evidence(REPORT)
        self.assertEqual(document["format"], evidence.FORMAT)
        self.assertEqual(
            document["bound_contracts"]["production_profile_fingerprint"],
            preflight.PRODUCTION_PROFILE_FINGERPRINT,
        )
        self.assertTrue(
            document["result"]["read_only_checker_implemented_and_verified"]
        )
        self.assertFalse(
            document["result"]["safe_to_start_production_prefreeze"]
        )
        self.assertFalse(document["result"]["safe_to_start_large_replay"])
        encoded = evidence.canonical_json(document)
        self.assertNotIn(b"/tmp/", encoded)
        self.assertNotIn(str(ROOT).encode(), encoded)

    def test_report_semantic_mutations_reject(self) -> None:
        original = json.loads(REPORT.read_text())
        mutations = {
            "prefreeze_true": ("safe_to_start_production_prefreeze", True),
            "row_replay": ("relation_rows_replayed", 1),
            "missing_blocker": ("blockers", original["blockers"][:-1]),
        }
        for name, (key, value) in mutations.items():
            with self.subTest(name=name):
                document = copy.deepcopy(original)
                document[key] = value
                with self.assertRaises(ValueError):
                    evidence.validate_report(document)

    def test_portable_file_matches_generator(self) -> None:
        self.assertEqual(
            PORTABLE.read_bytes(),
            evidence.canonical_json(evidence.build_evidence(REPORT)),
        )


if __name__ == "__main__":
    unittest.main()
