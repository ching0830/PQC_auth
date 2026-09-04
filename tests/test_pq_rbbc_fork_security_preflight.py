import tempfile
import unittest
from pathlib import Path

import pq_rbbc_fork_security_preflight as preflight


ROOT = Path(__file__).resolve().parents[1]


class ForkSecurityPreflightTests(unittest.TestCase):
    def test_frozen_manifest_matches_generator(self) -> None:
        path = ROOT / "manifests/pq_rbbc_fork_security_preflight_manifest_v2_30.json"
        self.assertEqual(
            path.read_bytes(), preflight.canonical_json(preflight.build_frozen_manifest())
        )

    def test_tracked_prerequisites_are_exact(self) -> None:
        self.assertEqual(preflight.validate_tracked_inputs(), ())

    def test_preflight_closes_only_the_read_only_gap_analysis(self) -> None:
        document = preflight.build_frozen_manifest()
        claims = document["claim_boundary"]
        self.assertTrue(claims["fork_security_preflight_contract_closed"])
        self.assertTrue(claims["v2_29_final_semantics_prerequisite_verified"])
        self.assertTrue(claims["read_only_gap_analysis_safe"])
        for name in (
            "external_security_artifacts_frozen",
            "cap_unique_witness_reviewed",
            "cap_straightline_extraction_reviewed",
            "qrom_request_binding_reviewed",
            "fork_blindness_revalidated",
            "fork_one_more_unforgeability_revalidated",
            "fork_security_proof_revalidated",
            "qualified_pq_se_nizk_backend_selected",
            "signature_size_rebenchmarked",
            "production_closed",
        ):
            self.assertFalse(claims[name], name)

    def test_v2_29_final_semantics_are_frozen(self) -> None:
        semantics = preflight.build_frozen_manifest()["final_execution_semantics"]
        self.assertEqual(semantics["combined_rows"], 589_030_555)
        self.assertEqual(semantics["verification_failures"], 0)
        self.assertEqual(semantics["external_assertions"], 0)
        self.assertTrue(semantics["ticket_payload_and_lifecycle_unchanged"])
        self.assertTrue(semantics["request_is_exactly_public_y"])

    def test_required_proof_obligations_are_explicit(self) -> None:
        identifiers = {item["id"] for item in preflight.proof_obligations()}
        self.assertEqual(
            identifiers,
            {
                "cap.unique_committed_mask",
                "cap.straightline_extraction",
                "request_binding.qrom_cross_message",
                "fork.honest_protocol_signer_blindness",
                "fork.one_more_unforgeability",
                "augmented_issuance.composition",
                "independent_review",
            },
        )
        self.assertTrue(
            all(item["status"] == "open" for item in preflight.proof_obligations())
        )

    def test_missing_external_artifacts_fail_closed(self) -> None:
        report = preflight.build_environment_report({})
        self.assertTrue(report["safe_to_continue_read_only_gap_analysis"])
        self.assertFalse(report["safe_to_start_fork_security_revalidation"])
        self.assertFalse(report["safe_to_claim_fork_security_revalidated"])
        self.assertFalse(report["safe_to_start_large_replay"])
        self.assertFalse(report["large_replay_started"])
        self.assertIsNone(report["exact_revalidation_command"])
        self.assertEqual(
            set(report["blockers"]), set(preflight.EXTERNAL_REQUIREMENTS)
        )

    def test_unfrozen_candidate_is_never_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.pdf"
            path.write_bytes(b"candidate")
            result = preflight._candidate_identity(path)
            self.assertTrue(result["provided"])
            self.assertFalse(result["verified"])
            self.assertEqual(result["failures"], ["identity_not_frozen"])
            self.assertEqual(result["bytes"], 9)

    def test_exact_inventory_command_names_every_required_artifact(self) -> None:
        command = preflight.exact_candidate_inventory_command()
        for requirement in preflight.EXTERNAL_REQUIREMENTS.values():
            self.assertIn(requirement["filename"], command)
        self.assertIn("--report", command)
        self.assertNotIn("--full-row-replay", command)

    def test_baseline_forbids_automatic_paper_claims(self) -> None:
        baseline = preflight.build_frozen_manifest()["baseline_status"]
        self.assertFalse(baseline["blind_uov_bit_exact_compatible"])
        self.assertFalse(baseline["paper_security_reduction_automatically_inherited"])
        self.assertFalse(baseline["paper_signature_size_automatically_inherited"])
        self.assertTrue(baseline["baselines_require_v2_29_semantics_refresh"])


if __name__ == "__main__":
    unittest.main()
