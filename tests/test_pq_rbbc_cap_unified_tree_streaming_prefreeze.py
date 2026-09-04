import copy
import json
from pathlib import Path
import tempfile
import unittest

import pq_rbbc_cap_unified_tree_production_runner as v2_35
import pq_rbbc_cap_unified_tree_streaming_prefreeze as streaming


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = (
    ROOT
    / "manifests/pq_rbbc_cap_unified_tree_streaming_prefreeze_manifest_v2_38.json"
)
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


class UnifiedTreeStreamingPrefreezeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.records = streaming.bounded_records(CHECKPOINT_INPUT, PARENT_VECTOR)
        cls.chunks = streaming.make_chunks(
            cls.records, streaming.BOUNDED_RECORDS_PER_CHUNK
        )

    def test_manifest_and_layouts_are_exact(self) -> None:
        self.assertEqual(
            MANIFEST.read_bytes(), streaming.canonical_json(streaming.build_manifest())
        )
        document = streaming.validate_manifest(MANIFEST)
        bounded = document["bounded_layout"]
        production = document["production_layout_plan_not_observation"]
        self.assertEqual(bounded["total_records"], 179)
        self.assertEqual(bounded["total_chunks"], 15)
        self.assertEqual(bounded["total_payload_bytes"], 5_938)
        self.assertEqual(production["total_records"], 163_859)
        self.assertEqual(production["total_chunks"], 163)
        self.assertEqual(production["total_payload_bytes"], 16_631_418)
        self.assertFalse(
            document["exact_commands"]["production_prefreeze"]["executable_now"]
        )

    def test_stream_chunk_codec_is_profile_bound_and_strict(self) -> None:
        chunk = self.chunks[0]
        encoded = chunk.encode(streaming.BOUNDED_PROFILE_FINGERPRINT)
        decoded = streaming.StreamChunk.decode(
            encoded,
            streaming.BOUNDED_PROFILE_FINGERPRINT,
            streaming._payload_widths(v2_35.QUALIFICATION_PARAMETERS)[chunk.stage],
        )
        self.assertEqual(decoded, chunk)
        for changed in (
            b"X" + encoded[1:],
            encoded + b"\x00",
        ):
            with self.assertRaises(streaming.StreamingPrefreezeError):
                streaming.StreamChunk.decode(
                    changed,
                    streaming.BOUNDED_PROFILE_FINGERPRINT,
                    streaming._payload_widths(v2_35.QUALIFICATION_PARAMETERS)[
                        chunk.stage
                    ],
                )
        with self.assertRaises(streaming.StreamingPrefreezeError):
            streaming.StreamChunk.decode(
                encoded,
                streaming.PRODUCTION_PROFILE_FINGERPRINT,
                streaming._payload_widths(v2_35.QUALIFICATION_PARAMETERS)[chunk.stage],
            )

    def test_external_checkpoint_index_and_stream_are_exact(self) -> None:
        identities = {
            streaming.CHECKPOINT_FILENAME: {
                "filename": streaming.CHECKPOINT_FILENAME,
                "bytes": 8_495,
                "sha256": "b5ef245fb1af0a08e983f6ab49b3353f0cbbe708c808db90661f9fdec079f805",
            },
            streaming.INDEX_FILENAME: {
                "filename": streaming.INDEX_FILENAME,
                "bytes": 3_505,
                "sha256": "22814bb97f94a89f6283b7aa4722260201364c01f7600b70577a334ab61d7b88",
            },
            streaming.EVIDENCE_FILENAME: {
                "filename": streaming.EVIDENCE_FILENAME,
                "bytes": 2_530,
                "sha256": "e7e27f8e03717a98691352b6a676075ece08955338fff5760749a025381a15cc",
            },
            streaming.QUALIFICATION_FILENAME: {
                "filename": streaming.QUALIFICATION_FILENAME,
                "bytes": 3_527,
                "sha256": "812d49a04b86a3311db743678604e3c00a5b80cd48f9c524243cc83a78baf185",
            },
            streaming.PREFLIGHT_FILENAME: {
                "filename": streaming.PREFLIGHT_FILENAME,
                "bytes": 4_555,
                "sha256": "e88bfc3d3512ded3f6559cc90525eec1ed4f79b0d52959a5f04a3c6b82750e8c",
            },
        }
        for filename, expected in identities.items():
            self.assertEqual(streaming.identity(EXTERNAL / filename), expected)
        checkpoint = json.loads((EXTERNAL / streaming.CHECKPOINT_FILENAME).read_text())
        contract = streaming.state_contract(
            MANIFEST, CHECKPOINT_INPUT, PARENT_VECTOR
        )
        streaming.validate_checkpoint_document(
            checkpoint, contract, EXTERNAL, self.chunks
        )
        index = json.loads((EXTERNAL / streaming.INDEX_FILENAME).read_text())
        streaming.validate_index_document(index, checkpoint, self.chunks)
        self.assertTrue(checkpoint["complete"])
        self.assertEqual(checkpoint["completed_chunk_count"], 15)
        self.assertEqual(index["bounded_records_materialized"], 179)
        self.assertEqual(index["production_records_materialized"], 0)
        self.assertEqual(len(list((EXTERNAL / streaming.CHUNK_DIRECTORY).iterdir())), 15)
        self.assertEqual(index["total_chunk_file_bytes"], 7_899)

    def test_checkpoint_and_chunk_identity_mutations_fail_closed(self) -> None:
        checkpoint = json.loads((EXTERNAL / streaming.CHECKPOINT_FILENAME).read_text())
        changed = copy.deepcopy(checkpoint)
        changed["chunk_records"][4]["chunk_identity"]["sha256"] = "00" * 32
        with self.assertRaises(streaming.StreamingPrefreezeError):
            streaming.validate_checkpoint_document(
                changed,
                streaming.state_contract(MANIFEST, CHECKPOINT_INPUT, PARENT_VECTOR),
                EXTERNAL,
                self.chunks,
            )

    def test_qualification_and_missing_artifact_preflight_are_fail_closed(self) -> None:
        qualification = json.loads(
            (EXTERNAL / streaming.QUALIFICATION_FILENAME).read_text()
        )
        self.assertEqual(
            qualification["interrupted_checkpoint_identity"],
            {
                "filename": streaming.CHECKPOINT_FILENAME,
                "bytes": 5_041,
                "sha256": "dd30629ce8a9b64e9d4e8175dffe9421d33173fd321d2a7e6fc9019e737eb517",
            },
        )
        self.assertTrue(all(
            value is True
            for key, value in qualification["checks"].items()
            if key not in {
                "production_records_materialized",
                "production_relation_rows_replayed",
            }
        ))
        self.assertEqual(qualification["checks"]["production_records_materialized"], 0)
        self.assertTrue(
            qualification["result"]["bounded_stream_materializer_qualified"]
        )
        preflight = json.loads((EXTERNAL / streaming.PREFLIGHT_FILENAME).read_text())
        self.assertTrue(preflight["capacity_observation"]["minimums_met"])
        self.assertEqual(len(preflight["blockers"]), 9)
        self.assertTrue(preflight["result"]["safe_to_run_read_only_preflight"])
        self.assertFalse(preflight["result"]["safe_to_freeze_launch_manifest"])
        self.assertFalse(preflight["result"]["safe_to_start_production_prefreeze"])
        self.assertFalse(preflight["result"]["safe_to_start_large_replay"])

    def test_production_branch_rejects_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "must-not-exist"
            with self.assertRaisesRegex(RuntimeError, "production-prefreeze unavailable"):
                streaming.reject_production_prefreeze(
                    MANIFEST, output, None, None, None, True
                )
            self.assertFalse(output.exists())

    def test_static_claims_do_not_promote_bounded_observation(self) -> None:
        claims = streaming.claim_boundary()
        self.assertTrue(claims["v2_38_stream_chunk_codec_implemented"])
        self.assertTrue(claims["v2_38_external_checkpoint_resume_implemented"])
        self.assertTrue(claims["production_stream_layout_frozen_as_plan"])
        for name in (
            "v2_38_bounded_stream_materializer_qualified",
            "production_stream_materialized",
            "production_checkpoint_materialized",
            "production_parent_input_materialized",
            "production_relation_replayed",
            "production_runner_scale_qualified",
            "operator_resource_reservation_frozen",
            "independent_review_frozen",
            "launch_manifest_frozen",
            "production_prefreeze_authorized",
            "production_prefreeze_started",
            "large_replay_started",
            "large_proving_run_started",
            "system_architecture_changed",
            "ticket_lifecycle_changed",
            "pq_sat_auth_changed",
            "production_closed",
        ):
            self.assertFalse(claims[name], name)


if __name__ == "__main__":
    unittest.main()
