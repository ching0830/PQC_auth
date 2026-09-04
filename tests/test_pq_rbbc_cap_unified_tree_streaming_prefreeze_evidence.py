import copy
import json
from pathlib import Path
import tempfile
import unittest

import pq_rbbc_cap_unified_tree_streaming_prefreeze as streaming
import pq_rbbc_cap_unified_tree_streaming_prefreeze_evidence as evidence


ROOT = Path(__file__).resolve().parents[1]
CHECKPOINT_INPUT = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/"
    "v2_36_unified_tree_relation/qualification/"
    "pq_rbbc_cap_unified_tree_checkpoint_payload_v2_36.json"
)
PARENT_VECTOR = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/"
    "v2_37_unified_statement_parent_abi/qualification/"
    "pq_rbbc_cap_unified_parent_input_bounded_vector_v2_37.json"
)
EXTERNAL = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/"
    "v2_38_unified_tree_streaming/qualification"
)
PORTABLE = (
    ROOT / "artifacts/metadata/cap_unified_tree_streaming_prefreeze_v2_38/"
    "pq_rbbc_cap_unified_tree_streaming_prefreeze_portable_evidence_v2_38.json"
)


class UnifiedTreeStreamingPrefreezeEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = evidence.build_evidence(
            CHECKPOINT_INPUT, PARENT_VECTOR, EXTERNAL
        )

    def test_portable_evidence_is_path_free_and_bounded(self) -> None:
        encoded = evidence.canonical_json(self.document)
        self.assertNotIn(b"/tmp/", encoded)
        self.assertNotIn(str(ROOT).encode(), encoded)
        self.assertNotIn(b"private_witness_hex", encoded)
        self.assertNotIn(b"parent_input_hex", encoded)
        self.assertEqual(self.document["bounded_observation"]["record_count"], 179)
        self.assertEqual(
            self.document["bounded_observation"]["production_records_materialized"],
            0,
        )

    def test_qualification_and_preflight_remain_fail_closed(self) -> None:
        qualification = self.document["qualification_result"]
        preflight = self.document["preflight_result"]
        self.assertTrue(qualification["bounded_stream_materializer_qualified"])
        self.assertFalse(qualification["production_stream_materialized"])
        self.assertTrue(preflight["safe_to_request_resource_reservation"])
        self.assertFalse(preflight["safe_to_freeze_launch_manifest"])
        self.assertFalse(preflight["safe_to_start_production_prefreeze"])
        self.assertFalse(preflight["safe_to_start_large_replay"])

    def test_semantic_mutations_fail_closed(self) -> None:
        run = json.loads((EXTERNAL / streaming.EVIDENCE_FILENAME).read_text())
        changed_run = copy.deepcopy(run)
        changed_run["observations"]["production_records_materialized"] = 1
        with self.assertRaises(ValueError):
            evidence.validate_run_evidence(changed_run)

        qualification = json.loads(
            (EXTERNAL / streaming.QUALIFICATION_FILENAME).read_text()
        )
        changed_qualification = copy.deepcopy(qualification)
        changed_qualification["result"]["production_stream_materialized"] = True
        with self.assertRaises(ValueError):
            evidence.validate_qualification(changed_qualification)

        preflight = json.loads((EXTERNAL / streaming.PREFLIGHT_FILENAME).read_text())
        changed_preflight = copy.deepcopy(preflight)
        changed_preflight["result"]["safe_to_start_production_prefreeze"] = True
        with self.assertRaises(ValueError):
            evidence.validate_preflight(changed_preflight)

    def test_external_identity_mutation_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / streaming.INDEX_FILENAME
            changed.write_bytes(
                (EXTERNAL / streaming.INDEX_FILENAME).read_bytes() + b" "
            )
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                evidence._require(changed, evidence.INDEX_IDENTITY, "stream index")

    def test_portable_file_matches_generator(self) -> None:
        self.assertEqual(
            PORTABLE.read_bytes(), evidence.canonical_json(self.document)
        )


if __name__ == "__main__":
    unittest.main()
