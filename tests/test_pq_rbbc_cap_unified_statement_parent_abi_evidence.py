import copy
import json
from pathlib import Path
import tempfile
import unittest

import pq_rbbc_cap_unified_statement_parent_abi as abi
import pq_rbbc_cap_unified_statement_parent_abi_evidence as evidence


ROOT = Path(__file__).resolve().parents[1]
CHECKPOINT = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/"
    "v2_36_unified_tree_relation/qualification/"
    "pq_rbbc_cap_unified_tree_checkpoint_payload_v2_36.json"
)
EXTERNAL = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/"
    "v2_37_unified_statement_parent_abi/qualification"
)
PRODUCTION = EXTERNAL / abi.PRODUCTION_VECTOR_FILENAME
BOUNDED = EXTERNAL / abi.BOUNDED_VECTOR_FILENAME
RUN_EVIDENCE = EXTERNAL / abi.EVIDENCE_FILENAME
QUALIFICATION = EXTERNAL / abi.QUALIFICATION_FILENAME
PORTABLE = (
    ROOT / "artifacts/metadata/cap_unified_statement_parent_abi_v2_37/"
    "pq_rbbc_cap_unified_statement_parent_abi_portable_evidence_v2_37.json"
)


class UnifiedStatementParentABIEvidenceTests(unittest.TestCase):
    def test_current_outputs_build_path_free_portable_evidence(self) -> None:
        document = evidence.build_evidence(
            CHECKPOINT, PRODUCTION, BOUNDED, RUN_EVIDENCE, QUALIFICATION
        )
        result = document["qualification_result"]
        self.assertTrue(result["production_profile_statement_serialization_qualified"])
        self.assertTrue(result["bounded_parent_input_abi_qualified"])
        self.assertTrue(result["safe_to_author_production_streaming_path"])
        self.assertFalse(result["production_parent_input_qualified"])
        self.assertFalse(result["safe_to_start_production_prefreeze"])
        encoded = evidence.canonical_json(document)
        self.assertNotIn(b"/tmp/", encoded)
        self.assertNotIn(str(ROOT).encode(), encoded)
        self.assertNotIn(b"private_witness_hex", encoded)
        self.assertNotIn(b"public_statement_hex", encoded)

    def test_semantic_mutations_fail_closed(self) -> None:
        run_document = json.loads(RUN_EVIDENCE.read_text())
        changed_run = copy.deepcopy(run_document)
        changed_run["observations"]["production_leaves_expanded"] = 1
        with self.assertRaises(ValueError):
            evidence.validate_run_evidence(changed_run)

        qualification = json.loads(QUALIFICATION.read_text())
        changed_qualification = copy.deepcopy(qualification)
        changed_qualification["result"]["production_parent_input_qualified"] = True
        with self.assertRaises(ValueError):
            evidence.validate_qualification(changed_qualification)

    def test_external_identity_mutation_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / PRODUCTION.name
            changed.write_bytes(PRODUCTION.read_bytes() + b" ")
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                evidence.build_evidence(
                    CHECKPOINT, changed, BOUNDED, RUN_EVIDENCE, QUALIFICATION
                )

    def test_portable_file_matches_generator(self) -> None:
        self.assertEqual(
            PORTABLE.read_bytes(),
            evidence.canonical_json(
                evidence.build_evidence(
                    CHECKPOINT,
                    PRODUCTION,
                    BOUNDED,
                    RUN_EVIDENCE,
                    QUALIFICATION,
                )
            ),
        )


if __name__ == "__main__":
    unittest.main()
