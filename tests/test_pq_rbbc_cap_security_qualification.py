import json
import tempfile
import unittest
from pathlib import Path

import pq_rbbc_cap_security_qualification as qualification


ROOT = Path(__file__).resolve().parents[1]


class CAPSecurityQualificationTests(unittest.TestCase):
    def test_frozen_manifest_matches_generator(self) -> None:
        path = (
            ROOT
            / "manifests/pq_rbbc_cap_security_qualification_manifest_v2_31.json"
        )
        self.assertEqual(
            path.read_bytes(),
            qualification.canonical_json(qualification.build_frozen_manifest()),
        )

    def test_tracked_prerequisites_are_exact(self) -> None:
        self.assertEqual(qualification.validate_tracked_inputs(), ())

    def test_oracle_contract_freezes_every_cap_domain(self) -> None:
        contract = qualification.oracle_contract()
        self.assertEqual(
            [item["id"] for item in contract["domain_separation"]],
            [
                "seed_derive",
                "seed_commit",
                "tape_expand",
                "h1",
                "consistency_points",
                "h2",
            ],
        )
        self.assertFalse(contract["quantum_transcript_extractor_claimed"])
        self.assertFalse(
            contract["request_binding_oracle_is_part_of_cap_extractor_transcript"]
        )
        self.assertFalse(contract["digest_only_transcript_is_sufficient_for_extraction"])

    def test_extractor_is_straight_line_and_does_not_take_proof(self) -> None:
        contract = qualification.extractor_contract()
        self.assertEqual(contract["algorithm_family"], ["Ext_1", "Ext_2"])
        self.assertTrue(contract["straight_line"])
        self.assertFalse(contract["rewinding_permitted"])
        self.assertIn("final CAP proof", contract["forbidden_input"])
        self.assertEqual(contract["output"]["Ext_1"], ["r"])
        self.assertEqual(contract["output"]["Ext_2"], ["r", "x"])

    def test_mixed_production_profile_is_exact(self) -> None:
        manifest = qualification.build_frozen_manifest()
        profile = manifest["cap_profile"]
        accounting = manifest["production_accounting"]
        self.assertEqual(
            profile["tree_specs"],
            [{"count": 2, "leaves": 4096}, {"count": 16, "leaves": 2048}],
        )
        self.assertEqual(profile["tree_extension_degrees"], [13, 13] + [12] * 16)
        self.assertEqual(profile["witness_bits"], 2048)
        self.assertEqual(accounting["total_xof_calls"], 122_847)
        self.assertEqual(accounting["commitment_bytes"], 5_391)

    def test_checkpoint_closes_contract_not_security(self) -> None:
        claims = qualification.claim_boundary()
        for name in (
            "v2_31_cap_security_qualification_contract_closed",
            "cap_oracle_contract_frozen",
            "cap_admissible_commitment_contract_frozen",
            "cap_extractor_interface_frozen",
            "cap_unique_mask_game_frozen",
        ):
            self.assertTrue(claims[name], name)
        for name in (
            "cap_straightline_extractor_implemented",
            "cap_straightline_extraction_reviewed",
            "cap_unique_witness_reviewed",
            "cap_security_qualified",
            "qrom_request_binding_reviewed",
            "fork_security_proof_revalidated",
            "production_closed",
        ):
            self.assertFalse(claims[name], name)

    def test_missing_external_artifacts_fail_closed(self) -> None:
        report = qualification.build_environment_report({})
        self.assertTrue(report["safe_to_author_cap_proof_artifacts"])
        self.assertFalse(report["proof_candidate_artifacts_verified"])
        self.assertFalse(report["safe_to_request_independent_review"])
        self.assertFalse(report["safe_to_start_cap_security_qualification"])
        self.assertFalse(report["safe_to_claim_cap_security_qualified"])
        self.assertFalse(report["safe_to_start_large_replay"])
        self.assertFalse(report["large_replay_started"])
        self.assertEqual(
            set(report["blockers"]),
            set(qualification.EXTERNAL_REQUIREMENTS),
        )

    def test_well_formed_candidates_remain_untrusted_until_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            extractor = root / "extractor.pdf"
            reduction = root / "reduction.pdf"
            extractor.write_bytes(b"%PDF-1.7\ncandidate extractor")
            reduction.write_bytes(b"%PDF-1.7\ncandidate reduction")

            schema = qualification.qualification_candidate_schema()
            candidate = {
                "format": schema["format"],
                "implementation_version": qualification.IMPLEMENTATION_VERSION,
                **schema["required_exact_fields"],
            }
            for section in schema["required_sections"]:
                candidate.setdefault(section, {})
            candidate["full_value_oracle_transcript_vectors"] = {
                "digest_only": False,
                "record_identity": {
                    "records": 122_847,
                    "canonical_json_sha256": "00" * 32,
                },
                "query_counts": {
                    "consistency_points": 1,
                    "h1": 1,
                    "h2": 1,
                    "seed_commit": 40_960,
                    "seed_derive": 40_924,
                    "tape_expand": 40_960,
                },
            }
            candidate["required_negative_vectors"] = [
                {"id": name, "rejected": True}
                for name in schema["required_negative_vectors"]
            ]
            candidate["numeric_advantage_accounting"] = {
                "mixed_degree_accept_probability_without_pow": "2^-182",
                "fork_pow_implemented": False,
                "complete_total_bound_available": False,
                "target_met_by_raw_tree_schedule_at_q_H_1": False,
            }
            candidate["independent_review_binding"] = {
                "attestation_present": False,
                "claim_promotion_authorized": False,
            }
            candidate["claim_boundary"] = {
                name: False
                for name in (
                    "cap_straightline_extractor_implemented",
                    "cap_straightline_extraction_reviewed",
                    "cap_unique_witness_reviewed",
                    "cap_security_qualified",
                    "paper_parameter_theorem_inherited",
                    "qrom_request_binding_reviewed",
                    "fork_security_proof_revalidated",
                    "production_closed",
                    "system_architecture_changed",
                    "ticket_lifecycle_changed",
                    "pq_sat_auth_changed",
                )
            }
            candidate_path = root / "candidate.json"
            candidate_path.write_text(json.dumps(candidate))

            review = {
                "format": "PQRBBC-CAP-SECURITY-INDEPENDENT-REVIEW-1",
                "implementation_version": qualification.IMPLEMENTATION_VERSION,
            }
            for name in (
                "reviewer_identity",
                "independence_statement",
                "review_date",
                "reviewed_artifact_identities",
                "findings",
                "dispositions",
                "claim_promotion_authorized",
            ):
                review[name] = False
            review_path = root / "review.json"
            review_path.write_text(json.dumps(review))

            report = qualification.build_environment_report({
                "extractor_specification": extractor,
                "unique_mask_reduction": reduction,
                "qualification_evidence": candidate_path,
                "independent_review_attestation": review_path,
            })
            for name in qualification.EXTERNAL_REQUIREMENTS:
                self.assertTrue(report["checks"][name]["provided"])
                self.assertTrue(
                    report["checks"][name]["schema_valid"],
                    (name, report["checks"][name]),
                )
                self.assertFalse(report["checks"][name]["verified"])
                if name == "independent_review_attestation":
                    self.assertEqual(
                        report["checks"][name]["failures"],
                        ["identity_not_frozen"],
                    )
                else:
                    self.assertIn(
                        "sha256_mismatch", report["checks"][name]["failures"]
                    )
            self.assertFalse(report["safe_to_start_cap_security_qualification"])

    def test_frozen_candidate_artifacts_leave_only_independent_review(self) -> None:
        root = Path(qualification.EXTERNAL_ROOT)
        paths = {
            "extractor_specification": (
                root / "pq_rbbc_cap_straightline_extractor_spec_v2_31.pdf"
            ),
            "unique_mask_reduction": (
                root
                / "pq_rbbc_cap_unique_committed_mask_reduction_v2_31.pdf"
            ),
            "qualification_evidence": (
                root / "pq_rbbc_cap_security_qualification_evidence_v2_31.json"
            ),
        }
        if not all(path.is_file() for path in paths.values()):
            self.skipTest("external v2.31 CAP proof candidates are not installed")
        report = qualification.build_environment_report(paths)
        for name in paths:
            self.assertTrue(report["checks"][name]["identity_frozen"])
            self.assertTrue(report["checks"][name]["schema_valid"])
            self.assertTrue(report["checks"][name]["verified"])
            self.assertEqual(report["checks"][name]["failures"], [])
        self.assertEqual(report["blockers"], ["independent_review_attestation"])
        self.assertTrue(report["proof_candidate_artifacts_verified"])
        self.assertTrue(report["safe_to_request_independent_review"])
        self.assertFalse(report["safe_to_start_cap_security_qualification"])
        self.assertFalse(report["safe_to_claim_cap_security_qualified"])

    def test_invalid_candidate_schema_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text("{}")
            result = qualification._candidate_identity(
                path,
                qualification.EXTERNAL_REQUIREMENTS["qualification_evidence"],
            )
            self.assertFalse(result["schema_valid"])
            self.assertIn("format", result["schema_failures"])
            self.assertFalse(result["verified"])

    def test_exact_inventory_command_has_no_large_replay(self) -> None:
        command = qualification.exact_candidate_inventory_command()
        for requirement in qualification.EXTERNAL_REQUIREMENTS.values():
            self.assertIn(requirement["filename"], command)
        self.assertNotIn("full-row-replay", command)
        self.assertNotIn("assignment", command)


if __name__ == "__main__":
    unittest.main()
