import json
import tempfile
import unittest
from pathlib import Path

import pq_rbbc_cap_prove_verify_preflight as preflight


ROOT = Path(__file__).resolve().parents[1]


class CAPProveVerifyPreflightTests(unittest.TestCase):
    def test_frozen_manifest_matches_generator(self) -> None:
        path = ROOT / "manifests/pq_rbbc_cap_prove_verify_preflight_manifest_v2_32.json"
        self.assertEqual(
            path.read_bytes(),
            preflight.canonical_json(preflight.build_frozen_manifest()),
        )

    def test_tracked_v2_31_prerequisites_are_exact(self) -> None:
        self.assertEqual(preflight.validate_tracked_inputs(), ())

    def test_prove_and_verify_inputs_are_separated(self) -> None:
        contract = preflight.prove_verify_contract()
        self.assertIn("private witness", contract["Prove"]["input"][1])
        self.assertEqual(
            contract["Verify"]["input"],
            ["canonical public statement", "canonical production proof bytes"],
        )
        self.assertIn("private witness", contract["Verify"]["forbidden_input"])
        self.assertFalse(contract["implementation_present"])

    def test_public_statement_contract_is_exact_and_incomplete(self) -> None:
        contract = preflight.statement_contract()
        self.assertEqual(
            contract["logical_public_inputs"],
            ["common parameters", "ctx", "sid", "rid", "y"],
        )
        self.assertEqual(contract["request_fields_excluding_proof"], ["y"])
        self.assertEqual(contract["y_bytes"], 72)
        self.assertFalse(contract["complete_statement_canonical_encoding_available"])

    def test_production_envelope_is_frozen_without_promoting_payloads(self) -> None:
        contract = preflight.proof_serialization_contract()
        self.assertEqual(bytes.fromhex(contract["envelope_magic_hex"]), preflight.PROOF_MAGIC)
        self.assertEqual(contract["section_count"], 4)
        self.assertEqual(
            [section["name"] for section in contract["sections"]],
            ["c_r", "c_x", "pow_nonce", "pi_2"],
        )
        self.assertEqual(contract["sections"][0]["bytes"], 5_391)
        self.assertEqual(contract["unfrozen_payloads"], ["c_x", "pow_nonce", "pi_2"])
        self.assertFalse(contract["candidate_c2_is_production_serialization"])
        self.assertFalse(contract["production_serialization_complete"])

    def test_pow_profile_disposition_is_fail_closed(self) -> None:
        contract = preflight.pow_security_profile_contract()
        baseline = contract["baseline_without_pow"]
        self.assertEqual(baseline["raw_degree_security_bits_at_q_H_1"], 182)
        self.assertFalse(baseline["target_met"])
        self.assertEqual(contract["target_security_bits"], 192)
        self.assertEqual(contract["source_paper_profile"]["total_pow_bits"], "13.9")
        self.assertFalse(contract["simple_addition_of_13_9_bits_is_a_complete_bound"])
        self.assertTrue(contract["profile_change_requires_new_namespace_and_replay"])
        self.assertFalse(contract["profile_change_authorized_by_this_preflight"])

    def test_checkpoint_closes_only_preflight_requirements(self) -> None:
        claims = preflight.claim_boundary()
        for name in (
            "v2_32_cap_prove_verify_preflight_closed",
            "cap_prove_verify_interface_requirements_frozen",
            "production_proof_envelope_requirements_frozen",
            "pow_security_profile_disposition_requirements_frozen",
        ):
            self.assertTrue(claims[name], name)
        for name in (
            "complete_statement_serialization_frozen",
            "production_proof_serialization_frozen",
            "cap_prove_implemented",
            "cap_verify_implemented",
            "fork_pow_implemented",
            "complete_concrete_security_bound_available",
            "cap_security_qualified",
            "fork_security_proof_revalidated",
            "production_closed",
            "system_architecture_changed",
            "ticket_lifecycle_changed",
            "pq_sat_auth_changed",
        ):
            self.assertFalse(claims[name], name)

    def test_missing_external_artifacts_only_emit_preflight_report(self) -> None:
        report = preflight.build_environment_report({})
        self.assertTrue(report["safe_to_run_read_only_preflight"])
        self.assertTrue(report["safe_to_author_v2_32_candidate_artifacts"])
        self.assertFalse(report["safe_to_implement_cap_prove_verify"])
        self.assertFalse(report["safe_to_start_large_relation_replay"])
        self.assertFalse(report["safe_to_start_large_proving_run"])
        self.assertFalse(report["safe_to_claim_cap_security_qualified"])
        self.assertFalse(report["large_replay_started"])
        self.assertFalse(report["large_proving_run_started"])
        self.assertIsNone(report["exact_implementation_command"])
        self.assertEqual(set(report["blockers"]), set(preflight.EXTERNAL_REQUIREMENTS))

    @staticmethod
    def _candidate(schema: dict[str, object]) -> dict[str, object]:
        candidate = {
            "format": schema["format"],
            "implementation_version": preflight.IMPLEMENTATION_VERSION,
            **schema["required_exact_fields"],
        }
        for section in schema["required_sections"]:
            candidate.setdefault(section, {})
        return candidate

    def test_schema_valid_candidates_remain_untrusted_until_identity_freeze(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = root / "spec.pdf"
            spec.write_bytes(b"%PDF-1.7\ncandidate")

            serialization = self._candidate(preflight.serialization_candidate_schema())
            serialization["negative_vectors"] = [
                {"id": name, "rejected": True}
                for name in preflight.serialization_candidate_schema()[
                    "required_negative_vectors"
                ]
            ]
            serialization["claim_boundary"] = {
                "candidate_c2_used_as_production_c_x": False,
                "production_proof_serialization_frozen": False,
            }
            serialization_path = root / "serialization.json"
            serialization_path.write_text(json.dumps(serialization))

            disposition = self._candidate(preflight.pow_disposition_schema())
            disposition["selected_disposition"] = {
                "kind": "implement_and_validate_paper_compatible_pow"
            }
            disposition["claim_boundary"] = {
                "cap_security_qualified": False,
                "independent_review_completed": False,
            }
            disposition_path = root / "disposition.json"
            disposition_path.write_text(json.dumps(disposition))

            implementation = self._candidate(preflight.implementation_evidence_schema())
            implementation["mutation_vectors"] = [
                {"id": name, "rejected": True}
                for name in preflight.implementation_evidence_schema()[
                    "required_mutations"
                ]
            ]
            implementation_path = root / "implementation.json"
            implementation_path.write_text(json.dumps(implementation))

            review = {
                "format": "PQRBBC-CAP-PROVE-VERIFY-INDEPENDENT-REVIEW-1",
                "implementation_version": preflight.IMPLEMENTATION_VERSION,
            }
            for field in (
                "reviewer_identity",
                "independence_statement",
                "review_date",
                "reviewed_artifact_identities",
                "algorithm_findings",
                "serialization_findings",
                "pow_security_findings",
                "dispositions",
                "claim_promotion_authorized",
            ):
                review[field] = False
            review_path = root / "review.json"
            review_path.write_text(json.dumps(review))

            report = preflight.build_environment_report({
                "prove_verify_specification": spec,
                "production_proof_serialization": serialization_path,
                "pow_security_profile_disposition": disposition_path,
                "prove_verify_implementation_evidence": implementation_path,
                "independent_review_attestation": review_path,
            })
            for name in preflight.EXTERNAL_REQUIREMENTS:
                self.assertTrue(report["checks"][name]["schema_valid"], name)
                self.assertFalse(report["checks"][name]["identity_frozen"], name)
                self.assertFalse(report["checks"][name]["verified"], name)
                self.assertEqual(
                    report["checks"][name]["failures"],
                    ["identity_not_frozen"],
                )
            self.assertFalse(report["safe_to_implement_cap_prove_verify"])

    def test_candidate_c2_promotion_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            schema = preflight.serialization_candidate_schema()
            candidate = self._candidate(schema)
            candidate["negative_vectors"] = [
                {"id": name, "rejected": True}
                for name in schema["required_negative_vectors"]
            ]
            candidate["claim_boundary"] = {
                "candidate_c2_used_as_production_c_x": True,
                "production_proof_serialization_frozen": False,
            }
            path = Path(directory) / "serialization.json"
            path.write_text(json.dumps(candidate))
            valid, failures = preflight._validate_json_candidate(
                path, schema["format"]
            )
            self.assertFalse(valid)
            self.assertIn("serialization_claim_boundary", failures)

    def test_exact_inventory_command_is_bounded(self) -> None:
        command = preflight.exact_candidate_inventory_command()
        for requirement in preflight.EXTERNAL_REQUIREMENTS.values():
            self.assertIn(requirement["filename"], command)
        for forbidden in ("full-row-replay", "allow-large", "assignment", "prove --"):
            self.assertNotIn(forbidden, command)

    def test_preflight_resource_estimate_has_no_replay(self) -> None:
        estimate = preflight.build_frozen_manifest()["preflight_resource_estimate"]
        self.assertEqual(estimate["cpu_cores"], 1)
        self.assertEqual(estimate["relation_rows_replayed"], 0)
        self.assertEqual(estimate["proofs_generated"], 0)


if __name__ == "__main__":
    unittest.main()
