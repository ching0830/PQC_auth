import copy
import json
from pathlib import Path
import tempfile
import unittest

import pq_rbbc_cap_unified_tree_production_runner as runner
import pq_rbbc_cap_unified_tree_production_runner_evidence as evidence


ROOT = Path(__file__).resolve().parents[1]
EXTERNAL = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/v2_35_unified_tree_runner/qualification"
)
RUN_EVIDENCE = EXTERNAL / runner.EVIDENCE_FILENAME
QUALIFICATION = EXTERNAL / runner.QUALIFICATION_FILENAME
PORTABLE = (
    ROOT / "artifacts/metadata/cap_unified_tree_production_runner_v2_35/"
    "pq_rbbc_cap_unified_tree_production_runner_evidence_v2_35.json"
)


class UnifiedTreeProductionRunnerEvidenceTests(unittest.TestCase):
    def test_current_external_outputs_build_path_free_evidence(self) -> None:
        document = evidence.build_evidence(RUN_EVIDENCE, QUALIFICATION)
        self.assertEqual(document["format"], evidence.FORMAT)
        self.assertEqual(
            document["bound_contracts"]["relation_contract_sha256"],
            runner.RELATION_CONTRACT_SHA256,
        )
        self.assertTrue(document["result"]["runner_skeleton_qualified"])
        self.assertFalse(document["result"]["production_runner_qualified"])
        self.assertFalse(
            document["result"]["safe_to_start_production_prefreeze"]
        )
        encoded = evidence.canonical_json(document)
        self.assertNotIn(b"/tmp/", encoded)
        self.assertNotIn(str(ROOT).encode(), encoded)

    def test_external_semantic_mutations_reject(self) -> None:
        run_document = json.loads(RUN_EVIDENCE.read_text())
        mutations = {
            "production_leaf": (
                ("resource_measurements", "production_leaves_expanded"),
                1,
            ),
            "production_profile": (
                ("claim_boundary", "production_profile_implemented"),
                True,
            ),
            "changed_result": (
                ("deterministic_result_identity",),
                "00" * 32,
            ),
        }
        for name, (path, value) in mutations.items():
            with self.subTest(name=name):
                document = copy.deepcopy(run_document)
                target = document
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(ValueError):
                    evidence.validate_run_evidence(document)

        qualification = json.loads(QUALIFICATION.read_text())
        qualification["result"]["production_runner_qualified"] = True
        with self.assertRaises(ValueError):
            evidence.validate_qualification(qualification)

    def test_external_identity_mutation_rejects_before_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / RUN_EVIDENCE.name
            changed.write_bytes(RUN_EVIDENCE.read_bytes() + b" ")
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                evidence.build_evidence(changed, QUALIFICATION)

    def test_portable_file_matches_generator(self) -> None:
        self.assertEqual(
            PORTABLE.read_bytes(),
            evidence.canonical_json(
                evidence.build_evidence(RUN_EVIDENCE, QUALIFICATION)
            ),
        )


if __name__ == "__main__":
    unittest.main()
