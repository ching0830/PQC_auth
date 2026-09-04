import unittest

import pq_rbbc_cap_prove_verify_artifacts as artifacts
import pq_rbbc_cap_prove_verify_preflight as preflight


class CAPProveVerifyArtifactTests(unittest.TestCase):
    def test_serialization_candidate_matches_preflight_schema(self) -> None:
        document = artifacts.build_serialization_candidate()
        schema = preflight.serialization_candidate_schema()
        self.assertEqual(document["format"], schema["format"])
        for name, value in schema["required_exact_fields"].items():
            self.assertEqual(document[name], value)
        self.assertEqual(
            {item["id"] for item in document["negative_vectors"]},
            set(schema["required_negative_vectors"]),
        )
        self.assertTrue(document["canonical_parser"]["implemented"])
        self.assertFalse(document["canonical_parser"]["complete_production_parser"])
        self.assertFalse(
            document["claim_boundary"]["production_proof_serialization_frozen"]
        )

    def test_pow_disposition_records_required_architecture_gap(self) -> None:
        document = artifacts.build_pow_disposition()
        schema = preflight.pow_disposition_schema()
        self.assertEqual(document["format"], schema["format"])
        self.assertEqual(
            document["selected_disposition"]["kind"],
            "implement_and_validate_paper_compatible_pow",
        )
        self.assertEqual(document["parameter_delta"]["current_tree_roots"], 18)
        self.assertEqual(document["parameter_delta"]["paper_optimized_tree_roots"], 1)
        self.assertFalse(document["complete_concrete_bound"]["available"])
        self.assertFalse(document["claim_boundary"]["fork_pow_implemented"])
        self.assertFalse(document["claim_boundary"]["cap_security_qualified"])

    def test_partial_implementation_evidence_is_honest(self) -> None:
        document = artifacts.build_implementation_evidence({
            "implementation": preflight.ROOT / "src/pq_rbbc_cap_prove_verify.py",
        })
        schema = preflight.implementation_evidence_schema()
        self.assertEqual(
            {item["id"] for item in document["mutation_vectors"]},
            set(schema["required_mutations"]),
        )
        self.assertFalse(document["verify_vectors"][0]["accepted"])
        self.assertFalse(document["pow_vectors"][0]["executed"])
        self.assertFalse(document["claim_boundary"]["cap_prove_implemented"])
        self.assertFalse(document["claim_boundary"]["cap_verify_implemented"])
        self.assertFalse(
            document["claim_boundary"]["all_mutations_algebraically_rejected"]
        )
        self.assertEqual(
            document["resource_measurements"]["relation_rows_replayed"], 0
        )


if __name__ == "__main__":
    unittest.main()
