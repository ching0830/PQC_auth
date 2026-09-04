import copy
import json
from pathlib import Path
import tempfile
import unittest

import pq_rbbc_cap_unified_tree_bounded_relation as bounded
import pq_rbbc_cap_unified_tree_bounded_relation_evidence as evidence


ROOT = Path(__file__).resolve().parents[1]
EXTERNAL = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/"
    "v2_36_unified_tree_relation/qualification"
)
CHECKPOINT = EXTERNAL / bounded.CHECKPOINT_FILENAME
RELATION = EXTERNAL / bounded.RELATION_FILENAME
RUN_EVIDENCE = EXTERNAL / bounded.EVIDENCE_FILENAME
QUALIFICATION = EXTERNAL / bounded.QUALIFICATION_FILENAME
PORTABLE = (
    ROOT / "artifacts/metadata/cap_unified_tree_bounded_relation_v2_36/"
    "pq_rbbc_cap_unified_tree_bounded_relation_portable_evidence_v2_36.json"
)


class UnifiedTreeBoundedRelationEvidenceTests(unittest.TestCase):
    def test_current_outputs_build_path_free_portable_evidence(self) -> None:
        document = evidence.build_evidence(
            CHECKPOINT, RELATION, RUN_EVIDENCE, QUALIFICATION
        )
        self.assertEqual(document["format"], evidence.FORMAT)
        self.assertTrue(
            document["qualification_result"][
                "checkpoint_payload_format_qualified_on_bounded_fixture"
            ]
        )
        self.assertTrue(
            document["qualification_result"][
                "bounded_relation_generator_qualified"
            ]
        )
        self.assertFalse(
            document["qualification_result"][
                "production_relation_generator_scale_qualified"
            ]
        )
        self.assertFalse(
            document["qualification_result"][
                "safe_to_start_production_prefreeze"
            ]
        )
        encoded = evidence.canonical_json(document)
        self.assertNotIn(b"/tmp/", encoded)
        self.assertNotIn(str(ROOT).encode(), encoded)
        self.assertNotIn(b"private_witness_hex", encoded)

    def test_semantic_mutations_fail_closed(self) -> None:
        run_document = json.loads(RUN_EVIDENCE.read_text())
        changed_run = copy.deepcopy(run_document)
        changed_run["observations"]["production_relation_rows"] = 1
        with self.assertRaises(ValueError):
            evidence.validate_run_evidence(changed_run)

        qualification = json.loads(QUALIFICATION.read_text())
        changed_qualification = copy.deepcopy(qualification)
        changed_qualification["result"][
            "production_relation_generator_scale_qualified"
        ] = True
        with self.assertRaises(ValueError):
            evidence.validate_qualification(changed_qualification)

    def test_external_identity_mutation_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / RELATION.name
            changed.write_bytes(RELATION.read_bytes() + b" ")
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                evidence.build_evidence(
                    CHECKPOINT, changed, RUN_EVIDENCE, QUALIFICATION
                )

    def test_portable_file_matches_generator(self) -> None:
        self.assertEqual(
            PORTABLE.read_bytes(),
            evidence.canonical_json(evidence.build_evidence(
                CHECKPOINT, RELATION, RUN_EVIDENCE, QUALIFICATION
            )),
        )


if __name__ == "__main__":
    unittest.main()
