import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pq_rbbc_cap_unified_tree_reservation_binding_v2_43 as subject
from pq_rbbc_launch_io_v2_41 import ArtifactRoot, Snapshot, ValidationError, canonical_json


NOW = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
APPROVED = "2026-09-10T10:00:00Z"
START = "2026-09-10T11:00:00Z"
END = "2026-09-17T11:00:00Z"
EXPECTED_REVIEWED_COMMIT = "1" * 40
EXPECTED_REVIEWED_TREE = "2" * 40


def approval_document():
    return {
        "format": subject.APPROVAL_FORMAT,
        "contract_version": subject.CONTRACT_VERSION,
        "target_implementation_version": subject.TARGET_IMPLEMENTATION_VERSION,
        "reservation_id": "PQRBBC-V242-RES-20260910-001",
        "launch_batch_id": "PQRBBC-V242-PREFREEZE-20260910-001",
        "operator_identifier": "operator-under-test",
        "operator_role": "repository owner and sole host operator",
        "approved_at_utc": APPROVED,
        "decision": {
            "resources_confirmed": True,
            "external_output_control_confirmed": True,
            "accepts_runtime_estimate_unavailable": True,
        },
        "attestation_boundary": {
            "method": "owner-controlled-local-record",
            "same_operator_as_repository_owner": True,
            "cryptographic_signature_verified": False,
            "named_independent_human_review": False,
        },
    }


def resource_document(root: Path, review_root: Path, contract_review_root: Path,
                      approval: Snapshot, technical_status: Snapshot):
    paths = subject.locations(root)
    return {
        "format": subject.RESOURCE_FORMAT,
        "contract_version": subject.CONTRACT_VERSION,
        "target_implementation_version": subject.TARGET_IMPLEMENTATION_VERSION,
        "reservation_id": "PQRBBC-V242-RES-20260910-001",
        "launch_batch_id": "PQRBBC-V242-PREFREEZE-20260910-001",
        "implementation_binding": subject.implementation_binding(),
        "v2_43_contract_technical_review_status": technical_status.identity,
        "production_profile_fingerprint": subject.PRODUCTION_PROFILE_FINGERPRINT,
        "operator": {
            "identifier": "operator-under-test",
            "role": "repository owner and sole host operator",
            "approved_at_utc": APPROVED,
            "approved": True,
            "approval_record": approval.identity,
            "attestation": {
                "method": "owner-controlled-local-record",
                "cryptographic_signature_verified": False,
            },
        },
        "reservation_window": {
            "starts_at_utc": START,
            "ends_at_utc": END,
            "wall_clock_seconds": 604800,
        },
        "execution_scope": {
            "phase": "production-prefreeze",
            "trusted_artifact_root": str(root),
            "trusted_review_root": str(review_root),
            "trusted_contract_review_root": str(contract_review_root),
            "expected_reviewed_commit": EXPECTED_REVIEWED_COMMIT,
            "expected_reviewed_tree": EXPECTED_REVIEWED_TREE,
            "external_output": str(root / "production-prefreeze"),
            "candidate_locations": {
                key: paths[key]
                for key in ("resource_reservation", "independent_review", "launch_manifest")
            },
            "exact_command": subject.production_command(
                root, review_root, contract_review_root,
                EXPECTED_REVIEWED_COMMIT, EXPECTED_REVIEWED_TREE),
            "exact_command_sha256": subject.command_sha256(
                root, review_root, contract_review_root,
                EXPECTED_REVIEWED_COMMIT, EXPECTED_REVIEWED_TREE),
            "fresh_cache_required": True,
            "existing_output_overwrite_forbidden": True,
            "legacy_evidence_read_only": True,
            "production_implementation_available": False,
            "command_executable_now": False,
        },
        "reserved_resources": {
            "cpu_cores": 4,
            "available_memory_bytes": 17179869184,
            "free_disk_bytes": 85899345920,
            "exclusive_output_directory": True,
            "accepts_runtime_estimate_unavailable": True,
        },
        "claim_boundary": {
            "resources_reserved_for_prospective_prefreeze": True,
            "authorizes_production_prefreeze": False,
            "authorizes_large_replay": False,
            "authorizes_large_proving_run": False,
            "independent_human_review_frozen": False,
            "launch_manifest_frozen": False,
            "grants_security_claim": False,
            "production_closed": False,
        },
    }


def review_document(resource: Snapshot, approval: Snapshot, technical_status: Snapshot):
    return {
        "format": subject.REVIEW_FORMAT,
        "contract_version": subject.CONTRACT_VERSION,
        "target_implementation_version": subject.TARGET_IMPLEMENTATION_VERSION,
        "review_id": "PQRBBC-V242-REVIEW-20260910-001",
        "launch_batch_id": "PQRBBC-V242-PREFREEZE-20260910-001",
        "implementation_binding": subject.implementation_binding(),
        "review_subject": subject.review_subject(resource, approval, technical_status),
        "reviewer": {
            "identifier": "named-human-reviewer",
            "affiliation": "independent-review-organization",
            "independent_of_operator_and_implementation": True,
            "is_ai_only": False,
            "completed_at_utc": "2026-09-10T11:30:00Z",
            "attestation": {
                "method": "organization-record",
                "reference": "review-record-001",
                "authenticity_confirmed": True,
            },
        },
        "review_scope": {
            "v2_42_recovery_and_provenance_reviewed": True,
            "reservation_contract_and_schema_reviewed": True,
            "exact_command_resource_output_and_window_reviewed": True,
            "external_review_identity_chain_reviewed": True,
            "claim_boundary_reviewed": True,
        },
        "decision": {
            "disposition": "approved_for_launch_candidate_authoring_only",
            "blocking_findings": [],
            "authorizes_production_prefreeze": False,
            "authorizes_large_replay": False,
            "authorizes_large_proving_run": False,
            "grants_security_claim": False,
            "production_closed": False,
        },
    }


class ReservationBindingV243Tests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pq-rbbc-v243-test-")
        base = Path(self.temporary.name)
        os.chmod(base, 0o700)
        self.root = base / "artifacts"
        self.review_root = base / "reviews"
        self.contract_review_root = base / "contract-reviews"
        self.root.mkdir(mode=0o700)
        self.review_root.mkdir(mode=0o700)
        self.contract_review_root.mkdir(mode=0o700)
        contract_review_raw = {
            "report": b"synthetic technical review report\n",
            "findings": canonical_json({"blocking_findings": []}),
            "inventory": b"synthetic inventory\n",
        }
        contract_reviews = {}
        for key, filename in subject.CONTRACT_REVIEW_FILENAMES.items():
            path = self.contract_review_root / filename
            path.write_bytes(contract_review_raw[key])
            contract_reviews[key] = ArtifactRoot(self.contract_review_root).read(path)
        status_doc = subject.build_technical_review_status(
            reviewed_commit=EXPECTED_REVIEWED_COMMIT,
            reviewed_tree=EXPECTED_REVIEWED_TREE,
            completed_at_utc="2026-09-10T09:00:00Z",
            **contract_reviews,
        )
        self.technical_status = Snapshot(
            subject.TECHNICAL_REVIEW_STATUS_PATH, canonical_json(status_doc))
        approval_path = self.root / subject.FILENAMES["approval_record"]
        approval_path.write_bytes(canonical_json(approval_document()))
        self.approval = ArtifactRoot(self.root).read(approval_path)
        self.resource_doc = resource_document(
            self.root, self.review_root, self.contract_review_root,
            self.approval, self.technical_status)
        self.resource_path = self.root / subject.FILENAMES["resource_reservation"]
        self.resource_path.write_bytes(canonical_json(self.resource_doc))
        self.resource = ArtifactRoot(self.root).read(self.resource_path)
        self.review_doc = review_document(
            self.resource, self.approval, self.technical_status)

    def tearDown(self):
        self.temporary.cleanup()

    def validate_resource(self, document, *, approval=None, technical_status=None,
                          root=None, review_root=None, contract_review_root=None,
                          now=NOW):
        with patch.object(subject, "verify_reviewed_git_target", return_value=()):
            return subject.validate_resource(
                document,
                approval or self.approval,
                technical_status or self.technical_status,
                root or self.root,
                review_root or self.review_root,
                contract_review_root or self.contract_review_root,
                now,
                EXPECTED_REVIEWED_COMMIT,
                EXPECTED_REVIEWED_TREE,
            )

    def validate_review(self, document, *, now=NOW):
        with patch.object(subject, "verify_reviewed_git_target", return_value=()):
            return subject.validate_review(
                document, self.resource, self.approval, self.technical_status,
                self.root, self.review_root, self.contract_review_root, now,
                EXPECTED_REVIEWED_COMMIT, EXPECTED_REVIEWED_TREE)

    def validate_status(self, document, *, now=NOW):
        with patch.object(subject, "verify_reviewed_git_target", return_value=()):
            return subject.validate_technical_review_status(
                document, self.contract_review_root, now,
                EXPECTED_REVIEWED_COMMIT, EXPECTED_REVIEWED_TREE)

    def test_tracked_repository_contracts_match_generated_contracts(self):
        self.assertEqual((), subject.validate_tracked_repository_contracts())

    def test_schema_and_manifest_claims_remain_fail_closed(self):
        manifest = subject.build_manifest()
        self.assertFalse(manifest["current_gates"]["safe_to_create_real_reservation_before_contract_review"])
        self.assertFalse(manifest["current_gates"]["safe_to_start_production_prefreeze"])
        self.assertFalse(manifest["prospective_execution"]["command_executable_now"])
        self.assertFalse(subject.claim_boundary()["production_prefreeze_authorized"])

    def test_resource_and_named_human_review_positive(self):
        self.assertEqual((), self.validate_status(self.technical_status.document()))
        self.assertEqual((), self.validate_resource(self.resource_doc))
        self.assertEqual((), self.validate_review(self.review_doc))

    def test_technical_review_status_contract_and_archive_mutations_reject(self):
        document = self.technical_status.document()
        document["reviewed_contracts"]["contract_source"]["sha256"] = "0" * 64
        self.assertIn("technical_review_status:contract_binding",
                      self.validate_status(document))
        document = self.technical_status.document()
        document["external_review_artifacts"]["report"]["sha256"] = "0" * 64
        self.assertIn("technical_review_status:external_identity:report",
                      self.validate_status(document))

    def test_technical_review_status_future_completion_rejects(self):
        document = self.technical_status.document()
        document["completed_at_utc"] = "2026-09-10T13:00:00Z"
        self.assertIn("technical_review_status:future_completion",
                      self.validate_status(document))

    def test_technical_review_status_binds_real_expected_git_objects_and_blobs(self):
        document = self.technical_status.document()

        def fake_git(*arguments):
            if arguments[:2] == ("cat-file", "-t"):
                return (b"commit\n" if arguments[2] == EXPECTED_REVIEWED_COMMIT
                        else b"tree\n")
            if arguments[:2] == ("rev-parse", "--verify"):
                return (EXPECTED_REVIEWED_TREE + "\n").encode("ascii")
            if arguments[0] == "show":
                relative = arguments[1].split(":", 1)[1]
                return (subject.ROOT / relative).read_bytes()
            self.fail("unexpected Git query: " + repr(arguments))

        with patch.object(subject, "_git", side_effect=fake_git), \
                patch.object(subject, "_git_is_ancestor", return_value=True):
            self.assertEqual((), subject.verify_reviewed_git_target(
                document, EXPECTED_REVIEWED_COMMIT, EXPECTED_REVIEWED_TREE))

        self.assertIn("git_target:commit_binding", subject.verify_reviewed_git_target(
            document, "3" * 40, EXPECTED_REVIEWED_TREE))
        self.assertIn("git_target:tree_binding", subject.verify_reviewed_git_target(
            document, EXPECTED_REVIEWED_COMMIT, "3" * 40))
        with patch.object(subject, "_git", side_effect=ValidationError("missing")):
            self.assertIn("git_target:object_lookup", subject.verify_reviewed_git_target(
                document, EXPECTED_REVIEWED_COMMIT, EXPECTED_REVIEWED_TREE))

    def test_resource_builder_blocks_before_tracked_review_status_exists(self):
        with self.assertRaisesRegex(
                ValidationError, "contract technical review status unavailable"):
            subject.build_resource_reservation(
                approval=self.approval,
                artifact_root=self.root,
                review_root=Path("/home/ucheng0830/pq_rbbc_runtime/v2_42_review"),
                contract_review_root=self.contract_review_root,
                expected_reviewed_commit=EXPECTED_REVIEWED_COMMIT,
                expected_reviewed_tree=EXPECTED_REVIEWED_TREE,
                starts_at_utc=START,
                ends_at_utc=END,
                cpu_cores=4,
                available_memory_bytes=17179869184,
                free_disk_bytes=85899345920,
                clock=lambda: NOW,
            )

    def test_bounded_builders_reproduce_valid_documents(self):
        approval = subject.build_approval_record(
            reservation_id="PQRBBC-V242-RES-20260910-001",
            launch_batch_id="PQRBBC-V242-PREFREEZE-20260910-001",
            operator_identifier="operator-under-test",
            operator_role="repository owner and sole host operator",
            approved_at_utc=APPROVED,
        )
        self.assertEqual(approval_document(), approval)
        status_path = Path(self.temporary.name) / subject.TECHNICAL_REVIEW_STATUS_PATH.name
        status_path.write_bytes(self.technical_status.raw)
        with patch.object(subject, "TECHNICAL_REVIEW_STATUS_PATH", status_path), \
                patch.object(subject, "validate_tracked_contracts", return_value=()), \
                patch.object(subject, "verify_reviewed_git_target", return_value=()):
            resource = subject.build_resource_reservation(
                approval=self.approval,
                artifact_root=self.root,
                review_root=Path("/home/ucheng0830/pq_rbbc_runtime/v2_42_review"),
                contract_review_root=self.contract_review_root,
                expected_reviewed_commit=EXPECTED_REVIEWED_COMMIT,
                expected_reviewed_tree=EXPECTED_REVIEWED_TREE,
                starts_at_utc=START,
                ends_at_utc=END,
                cpu_cores=4,
                available_memory_bytes=17179869184,
                free_disk_bytes=85899345920,
                clock=lambda: NOW,
            )
        expected = resource_document(
            self.root, Path("/home/ucheng0830/pq_rbbc_runtime/v2_42_review"),
            self.contract_review_root, self.approval,
            Snapshot(status_path, self.technical_status.raw))
        self.assertEqual(expected, resource)

    def test_resource_binds_reviewed_commit_tree_and_sources(self):
        mutations = []
        for path, value in (
            (("reviewed_implementation_commit",), "0" * 40),
            (("reviewed_implementation_tree",), "0" * 40),
            (("integration_baseline_commit",), "0" * 40),
            (("tracked_dependencies", "src/pq_rbbc_cap_unified_tree_recovery_v2_42.py", "sha256"), "0" * 64),
            (("bounded_ai_technical_re_review", "external_artifacts", "findings.json", "sha256"), "0" * 64),
        ):
            document = copy.deepcopy(self.resource_doc)
            target = document["implementation_binding"]
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            mutations.append(document)
        for document in mutations:
            with self.subTest(document=document["implementation_binding"]):
                self.assertTrue(self.validate_resource(document))

    def test_resource_rejects_command_root_output_and_location_mutations(self):
        paths = (
            ("trusted_artifact_root", "/tmp/wrong"),
            ("trusted_review_root", "/tmp/wrong"),
            ("external_output", str(self.root / "wrong")),
            ("exact_command", "false"),
            ("exact_command_sha256", "0" * 64),
        )
        for key, value in paths:
            document = copy.deepcopy(self.resource_doc)
            document["execution_scope"][key] = value
            with self.subTest(key=key):
                self.assertIn("resource:execution_binding", self.validate_resource(document))
        document = copy.deepcopy(self.resource_doc)
        document["execution_scope"]["candidate_locations"]["independent_review"] = "/tmp/wrong"
        self.assertIn("resource:execution_binding", self.validate_resource(document))

    def test_artifact_and_review_roots_must_be_disjoint(self):
        document = resource_document(
            self.root, self.root, self.contract_review_root,
            self.approval, self.technical_status)
        self.assertIn("resource:trust_root_separation", self.validate_resource(
            document, review_root=self.root))

    def test_resource_rejects_weak_resources_and_type_confusion(self):
        cases = (("cpu_cores", 3), ("available_memory_bytes", 17179869183),
                 ("free_disk_bytes", 85899345919), ("cpu_cores", True),
                 ("cpu_cores", 4.0))
        for key, value in cases:
            document = copy.deepcopy(self.resource_doc)
            document["reserved_resources"][key] = value
            with self.subTest(key=key, value=value):
                self.assertTrue(self.validate_resource(document))

    def test_resource_rejects_approval_identity_and_subject_mutations(self):
        document = copy.deepcopy(self.resource_doc)
        document["operator"]["approval_record"]["sha256"] = "0" * 64
        self.assertIn("resource:approval_identity", self.validate_resource(document))
        wrong = approval_document()
        wrong["reservation_id"] = "different"
        snapshot = Snapshot(self.approval.location, canonical_json(wrong))
        self.assertIn("resource:approval_subject_binding", self.validate_resource(
            self.resource_doc, approval=snapshot))

    def test_resource_rejects_bad_or_inactive_window(self):
        document = copy.deepcopy(self.resource_doc)
        document["reservation_window"]["wall_clock_seconds"] = 1
        self.assertIn("resource:window_duration", self.validate_resource(document))
        after = datetime(2026, 9, 18, tzinfo=timezone.utc)
        self.assertIn("resource:inactive_window", self.validate_resource(
            self.resource_doc, now=after))

    def test_unknown_fields_and_placeholders_are_rejected(self):
        document = copy.deepcopy(self.resource_doc)
        document["unexpected"] = True
        self.assertTrue(self.validate_resource(document))
        document = copy.deepcopy(self.resource_doc)
        document["reservation_id"] = "REPLACE-WITH-ID"
        self.assertTrue(self.validate_resource(document))

    def test_review_must_be_named_human_and_exactly_bound(self):
        document = copy.deepcopy(self.review_doc)
        document["reviewer"]["is_ai_only"] = True
        self.assertTrue(self.validate_review(document))
        document = copy.deepcopy(self.review_doc)
        document["review_subject"]["resource_reservation"]["sha256"] = "0" * 64
        self.assertIn("review:subject_binding", self.validate_review(document))

    def test_review_time_order_is_enforced(self):
        document = copy.deepcopy(self.review_doc)
        document["reviewer"]["completed_at_utc"] = "2026-09-10T09:00:00Z"
        self.assertIn("review:time_order", self.validate_review(document))

    def test_review_rejects_operator_as_reviewer(self):
        document = copy.deepcopy(self.review_doc)
        document["reviewer"]["identifier"] = self.resource_doc["operator"]["identifier"]
        self.assertIn("review:reviewer_is_operator", self.validate_review(document))

    def test_operator_as_reviewer_closes_review_and_launch_gates(self):
        document = copy.deepcopy(self.review_doc)
        document["reviewer"]["identifier"] = self.resource_doc["operator"]["identifier"]
        review_path = self.root / subject.FILENAMES["independent_review"]
        review_path.write_bytes(canonical_json(document))
        status_path = Path(self.temporary.name) / subject.TECHNICAL_REVIEW_STATUS_PATH.name
        status_path.write_bytes(self.technical_status.raw)
        with patch.object(subject, "TECHNICAL_REVIEW_STATUS_PATH", status_path), \
                patch.object(subject, "validate_tracked_contracts", return_value=()), \
                patch.object(subject, "verify_reviewed_git_target", return_value=()):
            report = subject.build_preflight(
                artifact_root=self.root,
                review_root=self.review_root,
                contract_review_root=self.contract_review_root,
                expected_reviewed_commit=EXPECTED_REVIEWED_COMMIT,
                expected_reviewed_tree=EXPECTED_REVIEWED_TREE,
                resource_path=self.resource_path,
                review_path=review_path,
                clock=lambda: NOW,
            )
        self.assertIn(
            "review:reviewer_is_operator",
            report["external_candidates"]["independent_review"]["failures"])
        self.assertFalse(report["result"]["independent_review_acceptable_for_freeze"])
        self.assertFalse(report["result"]["safe_to_author_launch_manifest_candidate"])

    def test_noncanonical_candidate_bytes_are_rejected(self):
        path = self.root / subject.FILENAMES["independent_review"]
        path.write_text(json.dumps(self.review_doc, indent=2), encoding="utf-8")
        with self.assertRaises(ValidationError):
            subject._capture_canonical(ArtifactRoot(self.root), path, path)

    def test_external_archive_missing_fails_closed(self):
        failures = subject.verify_external_review_archive(self.review_root)
        self.assertEqual(3, len(failures))

    def test_contract_or_archive_failure_closes_every_downstream_gate(self):
        review_path = self.root / subject.FILENAMES["independent_review"]
        review_path.write_bytes(canonical_json(self.review_doc))
        status_path = Path(self.temporary.name) / subject.TECHNICAL_REVIEW_STATUS_PATH.name
        status_path.write_bytes(self.technical_status.raw)
        injected_failures = [
            "review_archive:identity:" + filename
            for filename in subject.EXTERNAL_REVIEW_IDENTITIES
        ] + [
            "tracked_dependency:" + relative
            for relative in subject.TRACKED_DEPENDENCY_IDENTITIES
        ]
        for injected_failure in injected_failures:
            with self.subTest(injected_failure=injected_failure), \
                    patch.object(subject, "TECHNICAL_REVIEW_STATUS_PATH", status_path), \
                    patch.object(subject, "validate_tracked_contracts",
                                 return_value=(injected_failure,)), \
                    patch.object(subject, "verify_reviewed_git_target", return_value=()):
                report = subject.build_preflight(
                    artifact_root=self.root,
                    review_root=self.review_root,
                    contract_review_root=self.contract_review_root,
                    expected_reviewed_commit=EXPECTED_REVIEWED_COMMIT,
                    expected_reviewed_tree=EXPECTED_REVIEWED_TREE,
                    resource_path=self.resource_path,
                    review_path=review_path,
                    clock=lambda: NOW,
                )
            self.assertFalse(report["tracked_contracts"]["verified"])
            for gate in (
                    "safe_to_run_read_only_reservation_preflight",
                    "v2_43_contract_technical_review_acceptable",
                    "resource_reservation_acceptable_for_freeze",
                    "safe_to_submit_named_independent_human_review",
                    "independent_review_acceptable_for_freeze",
                    "safe_to_author_launch_manifest_candidate"):
                self.assertFalse(report["result"][gate])
            for candidate in (
                    "technical_review_status", "resource_reservation", "independent_review"):
                self.assertIn(
                    "tracked_contracts_or_dependencies_unverified",
                    report["external_candidates"][candidate]["failures"])

    def test_production_always_rejects(self):
        with self.assertRaisesRegex(ValidationError, "production-prefreeze is unavailable"):
            subject.reject_production(
                artifact_root=self.root,
                review_root=self.review_root,
                contract_review_root=self.contract_review_root,
                expected_reviewed_commit=EXPECTED_REVIEWED_COMMIT,
                expected_reviewed_tree=EXPECTED_REVIEWED_TREE,
                resource_path=self.resource_path,
                review_path=None,
                launch_path=self.root / subject.FILENAMES["launch_manifest"],
                output=self.root / "production-prefreeze",
                clock=lambda: NOW,
            )

    def test_cli_preflight_report_location_is_exact(self):
        argv = [
            "reservation-binding-v2.43",
            "--phase", "reservation-preflight",
            "--trusted-artifact-root", str(self.root),
            "--trusted-review-root", str(self.review_root),
            "--trusted-contract-review-root", str(self.contract_review_root),
            "--expected-reviewed-commit", EXPECTED_REVIEWED_COMMIT,
            "--expected-reviewed-tree", EXPECTED_REVIEWED_TREE,
            "--output", str(self.root / "wrong.json"),
            "--fresh-output",
        ]
        with patch("sys.argv", argv), self.assertRaisesRegex(
                ValidationError, "preflight report output location mismatch"):
            subject.main()


class ExternalReviewArchiveV243Tests(unittest.TestCase):
    def test_operator_archive_when_installed(self):
        root = Path("/home/ucheng0830/pq_rbbc_runtime/v2_42_review")
        if not root.is_dir():
            self.skipTest("optional exact operator review archive is not installed")
        self.assertEqual((), subject.verify_external_review_archive(root))

    def test_candidate_preflight_when_operator_archive_is_installed(self):
        review_root = Path("/home/ucheng0830/pq_rbbc_runtime/v2_42_review")
        if not review_root.is_dir():
            self.skipTest("optional exact operator review archive is not installed")
        with tempfile.TemporaryDirectory(prefix="pq-rbbc-v243-preflight-") as temporary:
            base = Path(temporary)
            os.chmod(base, 0o700)
            root = base / "artifacts"
            contract_review_root = base / "contract-review"
            root.mkdir(mode=0o700)
            contract_review_root.mkdir(mode=0o700)
            raw = {
                "report": b"synthetic technical review report\n",
                "findings": canonical_json({"blocking_findings": []}),
                "inventory": b"synthetic inventory\n",
            }
            snapshots = {}
            for key, filename in subject.CONTRACT_REVIEW_FILENAMES.items():
                path = contract_review_root / filename
                path.write_bytes(raw[key])
                snapshots[key] = ArtifactRoot(contract_review_root).read(path)
            status_doc = subject.build_technical_review_status(
                reviewed_commit=EXPECTED_REVIEWED_COMMIT,
                reviewed_tree=EXPECTED_REVIEWED_TREE,
                completed_at_utc="2026-09-10T09:00:00Z",
                **snapshots,
            )
            status_path = base / subject.TECHNICAL_REVIEW_STATUS_PATH.name
            status_path.write_bytes(canonical_json(status_doc))
            status = Snapshot(status_path, canonical_json(status_doc))
            approval_path = root / subject.FILENAMES["approval_record"]
            approval_path.write_bytes(canonical_json(approval_document()))
            approval = ArtifactRoot(root).read(approval_path)
            resource = resource_document(
                root, review_root, contract_review_root, approval, status)
            resource_path = root / subject.FILENAMES["resource_reservation"]
            resource_path.write_bytes(canonical_json(resource))
            resource_snapshot = ArtifactRoot(root).read(resource_path)
            review_path = root / subject.FILENAMES["independent_review"]
            review_path.write_bytes(canonical_json(
                review_document(resource_snapshot, approval, status)))
            with patch.object(subject, "TECHNICAL_REVIEW_STATUS_PATH", status_path), \
                    patch.object(subject, "verify_reviewed_git_target", return_value=()):
                report = subject.build_preflight(
                    artifact_root=root,
                    review_root=review_root,
                    contract_review_root=contract_review_root,
                    expected_reviewed_commit=EXPECTED_REVIEWED_COMMIT,
                    expected_reviewed_tree=EXPECTED_REVIEWED_TREE,
                    resource_path=resource_path,
                    review_path=review_path,
                    clock=lambda: NOW,
                )
            self.assertTrue(report["tracked_contracts"]["verified"])
            self.assertTrue(report["result"]["v2_43_contract_technical_review_acceptable"])
            self.assertTrue(report["result"]["resource_reservation_acceptable_for_freeze"])
            self.assertTrue(report["result"]["independent_review_acceptable_for_freeze"])
            self.assertTrue(report["result"]["safe_to_author_launch_manifest_candidate"])
            self.assertFalse(report["result"]["safe_to_start_production_prefreeze"])


if __name__ == "__main__":
    unittest.main()
