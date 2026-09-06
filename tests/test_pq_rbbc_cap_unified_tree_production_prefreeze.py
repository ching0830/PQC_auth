import copy
import json
from pathlib import Path
import tempfile
import unittest

import pq_rbbc_cap_unified_tree_production_prefreeze as preflight


ROOT = Path(__file__).resolve().parents[1]
V2_33_EXTERNAL = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/v2_33_unified_tree_migration"
)


def valid_resource_reservation() -> dict[str, object]:
    document = preflight.resource_reservation_template()
    document["reservation_id"] = "operator-reservation-test"
    document["operator_approval"] = {
        "identifier": "test-operator",
        "role": "capacity-owner",
        "approved_at_utc": "2026-09-05T00:00:00Z",
        "approved": True,
    }
    document["reserved_resources"] = {
        "cpu_cores": preflight.MIN_CPU_CORES,
        "available_memory_bytes": preflight.MIN_AVAILABLE_MEMORY_BYTES,
        "free_disk_bytes": preflight.MIN_FREE_DISK_BYTES,
        "wall_clock_seconds": 86_400,
        "accepts_elapsed_time_estimate_unavailable": True,
        "exclusive_output_directory": True,
    }
    document["claim_boundary"]["authorizes_production_prefreeze"] = True
    return document


def valid_review() -> dict[str, object]:
    return {
        "format": preflight.REVIEW_FORMAT,
        "implementation_version": preflight.IMPLEMENTATION_VERSION,
        "review_id": "independent-review-test",
        "reviewer": {
            "identifier": "test-reviewer",
            "affiliation": "independent-test-fixture",
            "independent_of_implementation": True,
            "completed_at_utc": "2026-09-05T00:00:00Z",
        },
        "bound_identities": {
            "production_profile_fingerprint": (
                preflight.PRODUCTION_PROFILE_FINGERPRINT
            ),
            "prefreeze_contract_sha256": preflight.PREFREEZE_CONTRACT_SHA256,
            "v2_33_portable_evidence": dict(preflight.V2_33_PORTABLE_SEAL),
        },
        "review_scope": {
            "tree_topology_and_mapping_reviewed": True,
            "domains_and_transcripts_reviewed": True,
            "serialization_reviewed": True,
            "challenge_pow_and_opening_reviewed": True,
            "reduced_evidence_reviewed": True,
            "prefreeze_boundary_reviewed": True,
        },
        "decision": {
            "disposition": "approved_for_production_prefreeze_only",
            "blocking_findings": [],
            "authorizes_frozen_replay": False,
            "authorizes_large_proving_run": False,
            "grants_security_claim": False,
            "production_closed": False,
        },
    }


class UnifiedTreeProductionPrefreezeTests(unittest.TestCase):
    def test_v2_33_seal_and_production_descriptor_are_exact(self) -> None:
        self.assertEqual(preflight.validate_tracked_inputs(), ())
        self.assertEqual(
            preflight.PRODUCTION_PROFILE_FINGERPRINT,
            "c270e4681f23955667a6c0640317e7beccc666d60a0cffb40bfdccfcee811b7a",
        )
        contract = preflight.prefreeze_contract()
        self.assertEqual(contract["profile"]["total_leaves"], 40_960)
        self.assertEqual(contract["profile"]["internal_nodes"], 40_959)
        self.assertEqual(contract["profile"]["challenge_index_bits"], 200)
        self.assertEqual(contract["profile"]["t_open"], 174)
        self.assertFalse(
            contract["execution_rules"][
                "other_tree_observed_stream_bytes_reusable"
            ]
        )

    def test_resource_schema_is_frozen_and_template_is_not_approval(self) -> None:
        self.assertEqual(
            preflight.SCHEMA_PATH.read_bytes(),
            preflight.canonical_json(preflight.resource_reservation_schema()),
        )
        schema = preflight.resource_reservation_schema()
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            schema["properties"]["production_profile_fingerprint"]["const"],
            preflight.PRODUCTION_PROFILE_FINGERPRINT,
        )
        failures = preflight.validate_resource_reservation(
            preflight.resource_reservation_template()
        )
        self.assertIn("operator:approved", failures)
        self.assertIn("resources:wall_clock_seconds", failures)
        self.assertIn("resources:accepts_elapsed_time_estimate_unavailable", failures)
        self.assertIn("claims:authorizes_production_prefreeze", failures)

    def test_valid_resource_reservation_and_fail_closed_mutations(self) -> None:
        valid = valid_resource_reservation()
        self.assertEqual(preflight.validate_resource_reservation(valid), ())
        mutations = {
            "changed_profile": (
                ("production_profile_fingerprint",), "00" * 32
            ),
            "changed_contract": (("prefreeze_contract_sha256",), "11" * 32),
            "too_few_cores": (("reserved_resources", "cpu_cores"), 3),
            "too_little_memory": (
                ("reserved_resources", "available_memory_bytes"),
                preflight.MIN_AVAILABLE_MEMORY_BYTES - 1,
            ),
            "too_little_disk": (
                ("reserved_resources", "free_disk_bytes"),
                preflight.MIN_FREE_DISK_BYTES - 1,
            ),
            "reuse_old_stream": (
                ("execution_scope", "other_tree_observed_stream_bytes_reusable"),
                True,
            ),
            "authorizes_replay": (
                ("claim_boundary", "authorizes_frozen_replay"), True
            ),
            "unknown_field": (("unknown",), True),
        }
        for name, (keys, value) in mutations.items():
            with self.subTest(name=name):
                document = copy.deepcopy(valid)
                target = document
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
                self.assertTrue(
                    preflight.validate_resource_reservation(document), name
                )

    def test_independent_review_contract_and_mutations(self) -> None:
        valid = valid_review()
        self.assertEqual(preflight.validate_independent_review(valid), ())
        mutations = {
            "not_independent": (
                ("reviewer", "independent_of_implementation"), False
            ),
            "changed_binding": (
                ("bound_identities", "prefreeze_contract_sha256"), "22" * 32
            ),
            "missing_scope": (
                ("review_scope", "serialization_reviewed"), False
            ),
            "blocking_finding": (
                ("decision", "blocking_findings"), ["unresolved"]
            ),
            "security_claim": (("decision", "grants_security_claim"), True),
        }
        for name, (keys, value) in mutations.items():
            with self.subTest(name=name):
                document = copy.deepcopy(valid)
                target = document
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
                self.assertTrue(preflight.validate_independent_review(document), name)

    def test_valid_external_candidates_are_not_self_freezing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            resource = base / preflight.RESOURCE_FILENAME
            review = base / preflight.REVIEW_FILENAME
            resource.write_bytes(preflight.canonical_json(valid_resource_reservation()))
            review.write_bytes(preflight.canonical_json(valid_review()))
            resource_check = preflight._check_resource(resource)
            review_check = preflight._check_review(review)
            for observed in (resource_check, review_check):
                self.assertTrue(observed["schema_valid"])
                self.assertTrue(observed["candidate_acceptable_for_freeze"])
                self.assertFalse(observed["identity_frozen"])
                self.assertFalse(observed["verified"])
                self.assertEqual(observed["failures"], ["identity_not_frozen"])

    def test_current_external_inventory_is_bound_but_gate_remains_closed(self) -> None:
        paths = {
            "specification_pdf": (
                V2_33_EXTERNAL / "pq_rbbc_cap_unified_tree_spec_v2_33.pdf"
            ),
            "reduced_evidence": (
                V2_33_EXTERNAL / "reduced/"
                "pq_rbbc_cap_unified_tree_reduced_evidence_v2_33.json"
            ),
            "runner_qualification": (
                V2_33_EXTERNAL / "reduced/"
                "pq_rbbc_cap_unified_tree_runner_qualification_v2_33.json"
            ),
            "post_reduced_report": (
                V2_33_EXTERNAL /
                "pq_rbbc_cap_unified_tree_environment_after_reduced_v2_33.json"
            ),
        }
        report = preflight.build_environment_report(paths, None, None)
        self.assertTrue(report["safe_to_run_read_only_checker"])
        self.assertTrue(report["safe_to_request_independent_review"])
        self.assertTrue(all(
            item["verified"]
            for item in report["checks"]["sealed_external_inputs"].values()
        ))
        self.assertFalse(report["safe_to_start_production_prefreeze"])
        self.assertFalse(report["safe_to_start_large_replay"])
        self.assertFalse(report["safe_to_start_large_proving_run"])
        self.assertEqual(report["production_leaves_expanded"], 0)
        self.assertEqual(report["relation_rows_replayed"], 0)
        self.assertEqual(report["proofs_generated"], 0)
        self.assertIn("resource_reservation", report["blockers"])
        self.assertIn("independent_review", report["blockers"])
        self.assertIn("production_runner_not_implemented", report["blockers"])
        self.assertIn(
            "production_relation_contract_not_frozen", report["blockers"]
        )
        self.assertIn("production_prefreeze_not_authorized", report["blockers"])

    def test_even_schema_valid_candidates_cannot_bypass_implementation_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            resource = base / preflight.RESOURCE_FILENAME
            review = base / preflight.REVIEW_FILENAME
            resource.write_bytes(preflight.canonical_json(valid_resource_reservation()))
            review.write_bytes(preflight.canonical_json(valid_review()))
            report = preflight.build_environment_report({}, resource, review)
            self.assertTrue(report["safe_to_freeze_resource_reservation_candidate"])
            self.assertFalse(report["safe_to_start_production_prefreeze"])
            self.assertIn("production_runner_not_implemented", report["blockers"])

    def test_exact_commands_do_not_authorize_execution(self) -> None:
        commands = preflight.exact_commands()
        self.assertIn("--report", commands["read_only_checker"])
        self.assertIn("--print-resource-template", commands["resource_reservation_template"])
        production = commands["production_prefreeze"]
        self.assertFalse(production["executable_now"])
        self.assertFalse(production["authorized_now"])
        self.assertIn("--fresh-cache", production["command"])
        self.assertIn("--allow-large", production["command"])
        self.assertIsNone(commands["production_frozen_replay"]["command"])
        self.assertIsNone(commands["large_proving_run"]["command"])

    def test_frozen_manifest_matches_generator(self) -> None:
        path = (
            ROOT / "manifests/"
            "pq_rbbc_cap_unified_tree_production_prefreeze_manifest_v2_34.json"
        )
        self.assertEqual(
            path.read_bytes(),
            preflight.canonical_json(preflight.build_frozen_manifest()),
        )


if __name__ == "__main__":
    unittest.main()
