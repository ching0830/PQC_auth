import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import pq_rbbc_cap_unified_tree_launch_preflight as launch


ROOT = Path(__file__).resolve().parents[1]


def valid_resource() -> dict[str, object]:
    document = launch.resource_template()
    document["reservation_id"] = "operator-reservation-001"
    document["operator"] = {
        "identifier": "operator-001",
        "role": "production-operator",
        "approved_at_utc": "2026-09-05T12:00:00Z",
        "approved": True,
        "attestation": {
            "method": "organization-record",
            "reference": "change-control/001",
            "authenticity_confirmed": True,
        },
    }
    document["reservation_window"] = {
        "starts_at_utc": "2026-09-06T00:00:00Z",
        "ends_at_utc": "2026-09-07T00:00:00Z",
        "wall_clock_seconds": 86_400,
    }
    document["reserved_resources"]["accepts_runtime_estimate_unavailable"] = True
    document["claim_boundary"]["authorizes_production_prefreeze"] = True
    return document


def valid_review() -> dict[str, object]:
    document = launch.review_template()
    document["review_id"] = "independent-review-001"
    document["reviewer"] = {
        "identifier": "reviewer-001",
        "affiliation": "independent-lab",
        "independent_of_implementation": True,
        "completed_at_utc": "2026-09-05T13:00:00Z",
        "attestation": {
            "method": "detached-signature",
            "reference": "review-signature/001",
            "authenticity_confirmed": True,
        },
    }
    document["review_scope"] = {key: True for key in launch.REVIEW_SCOPE_KEYS}
    document["decision"] = {
        "disposition": "approved_for_production_prefreeze_only",
        "blocking_findings": [],
        "authorizes_frozen_replay": False,
        "authorizes_large_proving_run": False,
        "grants_security_claim": False,
        "production_closed": False,
    }
    return document


class UnifiedTreeLaunchPreflightTests(unittest.TestCase):
    def test_tracked_manifest_and_schemas_are_exact(self) -> None:
        self.assertEqual(launch.validate_tracked_contracts(), ())
        self.assertEqual(
            launch.MANIFEST_PATH.read_bytes(),
            launch.canonical_json(launch.build_manifest()),
        )
        for path, document in (
            (launch.RESOURCE_SCHEMA_PATH, launch.resource_reservation_schema()),
            (launch.REVIEW_SCHEMA_PATH, launch.independent_review_schema()),
            (launch.LAUNCH_SCHEMA_PATH, launch.launch_manifest_schema()),
        ):
            self.assertEqual(path.read_bytes(), launch.canonical_json(document))

    def test_draft_templates_are_deliberately_invalid(self) -> None:
        self.assertTrue(launch.validate_resource(launch.resource_template()))
        self.assertTrue(launch.validate_review(launch.review_template()))
        self.assertTrue(launch.validate_launch(launch.launch_template()))
        self.assertFalse(launch.resource_template()["operator"]["approved"])
        self.assertFalse(
            launch.review_template()["reviewer"]["independent_of_implementation"]
        )

    def test_valid_candidate_contracts_and_launch_binding(self) -> None:
        self.assertEqual(launch.validate_resource(valid_resource()), ())
        self.assertEqual(launch.validate_review(valid_review()), ())
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            resource = base / launch.RESOURCE_FILENAME
            review = base / launch.REVIEW_FILENAME
            resource.write_bytes(launch.canonical_json(valid_resource()))
            review.write_bytes(launch.canonical_json(valid_review()))
            document = launch.build_launch_manifest(
                resource, review, "launch-001", "2026-09-05T14:00:00Z"
            )
            self.assertEqual(
                launch.validate_launch(
                    document, launch.identity(resource), launch.identity(review)
                ),
                (),
            )
            self.assertEqual(
                document["execution"]["command_sha256"],
                launch.PRODUCTION_COMMAND_SHA256,
            )
            self.assertFalse(
                document["authorization_boundary"]["large_replay_authorized"]
            )

    def test_candidate_mutations_fail_closed(self) -> None:
        resource = valid_resource()
        resource["execution_scope"]["other_tree_observed_stream_bytes_reusable"] = True
        self.assertIn("scope:other_tree_observed_stream_bytes_reusable", launch.validate_resource(resource))
        resource = valid_resource()
        resource["reservation_window"]["wall_clock_seconds"] = 1
        self.assertIn("window:duration", launch.validate_resource(resource))
        review = valid_review()
        review["decision"]["grants_security_claim"] = True
        self.assertIn("decision:grants_security_claim", launch.validate_review(review))
        candidate = launch.launch_template()
        candidate["authorization_boundary"]["production_prefreeze_only"] = True
        candidate["authorization_boundary"]["large_replay_authorized"] = True
        self.assertIn("boundary:large_replay_authorized", launch.validate_launch(candidate))

    def test_missing_candidate_preflight_is_fail_closed(self) -> None:
        report = launch.build_preflight(
            launch.MANIFEST_PATH,
            launch.V2_38_PORTABLE_PATH,
            None,
            None,
            None,
        )
        self.assertTrue(report["result"]["safe_to_run_read_only_preflight"])
        self.assertFalse(report["result"]["safe_to_author_launch_manifest_candidate"])
        self.assertFalse(report["result"]["safe_to_freeze_launch_identity_set"])
        self.assertFalse(report["result"]["safe_to_start_production_prefreeze"])
        self.assertFalse(report["result"]["safe_to_start_large_replay"])

    def test_valid_candidates_only_prepare_identity_freeze(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            resource = base / launch.RESOURCE_FILENAME
            review = base / launch.REVIEW_FILENAME
            manifest = base / launch.LAUNCH_FILENAME
            resource.write_bytes(launch.canonical_json(valid_resource()))
            review.write_bytes(launch.canonical_json(valid_review()))
            manifest.write_bytes(
                launch.canonical_json(
                    launch.build_launch_manifest(
                        resource, review, "launch-001", "2026-09-05T14:00:00Z"
                    )
                )
            )
            report = launch.build_preflight(
                launch.MANIFEST_PATH,
                launch.V2_38_PORTABLE_PATH,
                resource,
                review,
                manifest,
                base,
            )
            self.assertTrue(report["candidate_identity_set_ready_for_later_freeze"])
            self.assertTrue(report["result"]["safe_to_freeze_launch_identity_set"])
            self.assertFalse(report["result"]["safe_to_start_production_prefreeze"])
            self.assertTrue(all(
                item["identity_frozen"] is False
                for item in report["external_candidates"].values()
            ))

    def test_production_branch_rejects_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "must-not-exist"
            with self.assertRaisesRegex(
                launch.LaunchPreflightError, "does not authorize"
            ):
                launch.reject_production(output)
            self.assertFalse(output.exists())

    def test_commands_and_claim_boundary_are_fail_closed(self) -> None:
        commands = launch.exact_commands()
        for name in ("qualification", "launch_preflight", "author_launch_manifest"):
            self.assertEqual(
                hashlib.sha256(commands[name]["command"].encode()).hexdigest(),
                commands[name]["sha256"],
            )
        self.assertFalse(commands["production_prefreeze"]["executable_now"])
        self.assertIn(launch.RESOURCE_FILENAME, commands["production_prefreeze"]["command"])
        self.assertIn(launch.REVIEW_FILENAME, commands["production_prefreeze"]["command"])
        self.assertIn(launch.LAUNCH_FILENAME, commands["production_prefreeze"]["command"])
        self.assertEqual(
            launch.build_manifest()["v2_38_predecessor_production_command_sha256"],
            "79da988d8cb17fe23a5e9f263da9bc0f11514f0a36280918278d485176b45c57",
        )
        claims = launch.claim_boundary()
        self.assertTrue(claims["v2_39_attestation_schemas_implemented"])
        for key in (
            "operator_resource_reservation_frozen",
            "independent_review_frozen",
            "launch_manifest_frozen",
            "production_prefreeze_authorized",
            "production_prefreeze_started",
            "large_replay_started",
            "large_proving_run_started",
            "cap_security_qualified",
            "production_closed",
        ):
            self.assertFalse(claims[key], key)


if __name__ == "__main__":
    unittest.main()
