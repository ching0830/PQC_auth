import copy
import json
from pathlib import Path
import tempfile
import unittest

import pq_rbbc_cap_unified_tree_launch_preflight as launch
import pq_rbbc_cap_unified_tree_launch_preflight_evidence as evidence


ROOT = Path(__file__).resolve().parents[1]
EXTERNAL = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/"
    "v2_39_unified_tree_launch_preflight/qualification"
)
PORTABLE = (
    ROOT / "artifacts/metadata/cap_unified_tree_launch_preflight_v2_39/"
    "pq_rbbc_cap_unified_tree_launch_preflight_portable_evidence_v2_39.json"
)


class UnifiedTreeLaunchPreflightEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = evidence.build_evidence(EXTERNAL)

    def test_portable_evidence_is_path_free_and_has_no_attestations(self) -> None:
        encoded = evidence.canonical_json(self.document)
        self.assertNotIn(b"/tmp/", encoded)
        self.assertNotIn(str(ROOT).encode(), encoded)
        self.assertFalse(
            self.document["artifact_policy"]["external_attestations_fabricated"]
        )
        self.assertEqual(len(self.document["missing_real_external_artifacts"]), 3)

    def test_qualification_and_preflight_are_fail_closed(self) -> None:
        qualification = self.document["qualification_result"]
        preflight = self.document["preflight_result"]
        self.assertTrue(qualification["attestation_schemas_qualified"])
        self.assertFalse(qualification["real_operator_reservation_present"])
        self.assertFalse(qualification["real_independent_review_present"])
        self.assertFalse(preflight["safe_to_freeze_launch_identity_set"])
        self.assertFalse(preflight["safe_to_start_production_prefreeze"])
        self.assertFalse(preflight["safe_to_start_large_replay"])

    def test_semantic_mutations_reject(self) -> None:
        report = json.loads((EXTERNAL / launch.REPORT_FILENAME).read_text())
        changed = copy.deepcopy(report)
        changed["result"]["safe_to_start_production_prefreeze"] = True
        with self.assertRaises(ValueError):
            evidence.validate_preflight(changed)
        qualification = json.loads(
            (EXTERNAL / launch.QUALIFICATION_FILENAME).read_text()
        )
        changed = copy.deepcopy(qualification)
        changed["result"]["launch_identity_set_frozen"] = True
        with self.assertRaises(ValueError):
            evidence.validate_qualification(changed)

    def test_external_identity_mutation_rejects(self) -> None:
        expected = evidence.EXTERNAL_IDENTITIES["qualification"]
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / launch.QUALIFICATION_FILENAME
            changed.write_bytes(
                (EXTERNAL / launch.QUALIFICATION_FILENAME).read_bytes() + b" "
            )
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                evidence._require(changed, expected, "qualification")

    def test_portable_file_matches_generator(self) -> None:
        self.assertEqual(PORTABLE.read_bytes(), evidence.canonical_json(self.document))


if __name__ == "__main__":
    unittest.main()
