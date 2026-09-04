import copy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

import pq_rbbc_cap_unified_tree_bounded_relation as bounded


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = (
    ROOT / "manifests/"
    "pq_rbbc_cap_unified_tree_bounded_relation_manifest_v2_36.json"
)
EXTERNAL = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/"
    "v2_36_unified_tree_relation/qualification"
)
CHECKPOINT = EXTERNAL / bounded.CHECKPOINT_FILENAME
RELATION = EXTERNAL / bounded.RELATION_FILENAME
EVIDENCE = EXTERNAL / bounded.EVIDENCE_FILENAME
QUALIFICATION = EXTERNAL / bounded.QUALIFICATION_FILENAME


class UnifiedTreeBoundedRelationTests(unittest.TestCase):
    def test_manifest_and_row_contract_are_frozen(self) -> None:
        self.assertEqual(
            MANIFEST.read_bytes(), bounded.canonical_json(bounded.build_manifest())
        )
        document = bounded.validate_manifest(MANIFEST)
        contract = document["relation_row_contract"]
        self.assertEqual(contract["bounded_total_rows"], 144)
        self.assertEqual(
            contract["production_shape_projected_contract_rows_not_constraints"],
            122_904,
        )
        self.assertIn("not R1CS", contract["row_semantics"])
        self.assertFalse(contract["other_tree_stream_bytes_used"])
        self.assertFalse(contract["v2_29_transcript_used_as_observation"])

    def test_current_checkpoint_payload_is_exact_and_valid(self) -> None:
        self.assertEqual(
            bounded.identity(CHECKPOINT),
            {
                "filename": bounded.CHECKPOINT_FILENAME,
                "bytes": 21_530,
                "sha256": (
                    "a605d18efa8f23eec3c89da1e4497ddff2c29790c0ea3cb0b7017808cfa39a17"
                ),
            },
        )
        document = json.loads(CHECKPOINT.read_text())
        bounded.validate_checkpoint_document(
            document, bounded.state_contract(MANIFEST)
        )
        self.assertEqual(document["completed_stage_names"], list(bounded.STAGE_ORDER))
        self.assertFalse(document["production_profile_permitted"])
        self.assertEqual(document["production_leaves_expanded"], 0)
        self.assertEqual(document["relation_rows_replayed"], 0)

    def test_current_bounded_relation_is_exact_and_satisfied(self) -> None:
        self.assertEqual(
            bounded.identity(RELATION),
            {
                "filename": bounded.RELATION_FILENAME,
                "bytes": 40_542,
                "sha256": (
                    "38798e22796af846206e8234fbb15e0ed243c3e0722e363980bf655df9a375cc"
                ),
            },
        )
        document = json.loads(RELATION.read_text())
        bounded.validate_relation_document(document)
        self.assertEqual(document["row_count"], 144)
        self.assertEqual(document["failures"], 0)
        self.assertEqual(document["production_relation_rows"], 0)
        self.assertEqual(document["br1cs_rows"], 0)
        self.assertEqual(
            document["row_stream_sha256"],
            "d59afc7818dd945150206e33ded77e39851876227035bbdb59e2ce23697e80c9",
        )

    def test_external_evidence_and_qualification_are_bounded(self) -> None:
        self.assertEqual(
            bounded.identity(EVIDENCE),
            {
                "filename": bounded.EVIDENCE_FILENAME,
                "bytes": 3_042,
                "sha256": (
                    "2347a9b02f8a55f7b1a4880093bc2f0974df47a828e7b429af7b7c8e75069dc3"
                ),
            },
        )
        self.assertEqual(
            bounded.identity(QUALIFICATION),
            {
                "filename": bounded.QUALIFICATION_FILENAME,
                "bytes": 2_534,
                "sha256": (
                    "d97cc7543d2c917ad83073fc621bc056f6d06650184e3ae97fcec1040989b280"
                ),
            },
        )
        evidence = json.loads(EVIDENCE.read_text())
        qualification = json.loads(QUALIFICATION.read_text())
        self.assertEqual(
            evidence["deterministic_result_identity"],
            "10331098958ad60c3433ff0be8c81a22d1d4575a7840eecb924d70cf4bfd8226",
        )
        self.assertEqual(evidence["observations"]["bounded_contract_rows"], 144)
        self.assertEqual(evidence["observations"]["production_relation_rows"], 0)
        for name in (
            "fresh_checkpoint_created",
            "interrupted_after_unified_tree",
            "resume_required_expected_payload_identity",
            "resume_completed_bounded_relation",
            "existing_output_overwrite_refused",
            "checkpoint_mutation_rejected",
            "production_branch_rejected_before_output",
        ):
            self.assertTrue(qualification["checks"][name], name)
        self.assertTrue(
            qualification["result"]["bounded_relation_generator_qualified"]
        )
        self.assertFalse(
            qualification["result"][
                "production_relation_generator_scale_qualified"
            ]
        )
        self.assertFalse(
            qualification["result"]["safe_to_start_production_prefreeze"]
        )

    def test_checkpoint_and_relation_mutations_fail_closed(self) -> None:
        checkpoint = json.loads(CHECKPOINT.read_text())
        changed_checkpoint = copy.deepcopy(checkpoint)
        changed_checkpoint["stage_records"][2]["data"][
            "production_leaves_expanded"
        ] = 1
        with self.assertRaises(bounded.BoundedRelationError):
            bounded.validate_checkpoint_document(
                changed_checkpoint, bounded.state_contract(MANIFEST)
            )

        relation = json.loads(RELATION.read_text())
        changed_relation = copy.deepcopy(relation)
        changed_relation["rows"][0]["right_sha256"] = "00" * 32
        with self.assertRaises(bounded.BoundedRelationError):
            bounded.validate_relation_document(changed_relation)

    def test_ticket_witness_mutation_rejects_without_tree_execution(self) -> None:
        inputs = bounded.bounded_inputs()
        changed_witness = replace(
            inputs.witness,
            error=inputs.witness.error ^ 1,
        )
        changed = replace(inputs, witness=changed_witness)
        with self.assertRaises(bounded.BoundedRelationError):
            bounded.validate_ticket_inputs(changed)

    def test_production_branch_rejects_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "must-not-exist"
            with self.assertRaisesRegex(RuntimeError, "production-prefreeze unavailable"):
                bounded.reject_production_prefreeze(
                    MANIFEST,
                    output,
                    Path(directory) / "not-an-authorization.json",
                    True,
                )
            self.assertFalse(output.exists())

    def test_static_claims_do_not_preclaim_external_qualification(self) -> None:
        claims = bounded.claim_boundary()
        self.assertTrue(claims["v2_36_checkpoint_payload_format_implemented"])
        self.assertTrue(claims["v2_36_bounded_relation_generator_implemented"])
        self.assertFalse(claims["v2_36_bounded_payload_resume_qualified"])
        self.assertFalse(claims["v2_36_bounded_relation_generator_qualified"])
        for key in (
            "production_checkpoint_payload_materialized",
            "production_relation_generator_scale_qualified",
            "production_relation_contract_frozen_by_observation",
            "production_runner_qualified",
            "resource_reservation_frozen",
            "independent_review_frozen",
            "production_prefreeze_authorized",
            "production_prefreeze_started",
            "large_replay_started",
            "large_proving_run_started",
            "cap_security_qualified",
            "fork_security_proof_revalidated",
            "system_architecture_changed",
            "ticket_lifecycle_changed",
            "pq_sat_auth_changed",
            "production_closed",
        ):
            self.assertFalse(claims[key], key)


if __name__ == "__main__":
    unittest.main()
