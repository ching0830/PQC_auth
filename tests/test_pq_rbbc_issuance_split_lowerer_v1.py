#!/usr/bin/env python3
"""Regression tests for the bounded issuance native split lowerer."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_issuance_split_lowerer_v1 as gate
import pq_rbbc_issuance_split_runner_v1 as split
import pq_rbbc_launch_io_v2_41 as launch_io


ROOT = Path(__file__).resolve().parents[1]


class BoundedFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="pq-rbbc-lowerer-test-")
        cls.root = Path(cls.temporary.name)
        os.chmod(cls.root, 0o700)
        cls.output = cls.root / "stages"
        cls.statement_raw, cls.witness_raw = gate._fixture_bytes()
        split.run_bounded_split(
            cls.statement_raw,
            cls.witness_raw,
            cls.output,
            artifact_root=cls.root,
            fresh_output=True,
        )
        cls.latest = split.latest_receipt(cls.output, artifact_root=cls.root)
        cls.bundle = gate.load_completed_stage_bundle(
            cls.statement_raw,
            cls.witness_raw,
            cls.output,
            artifact_root=cls.root,
            expected_checkpoint_sha256=str(cls.latest.identity["sha256"]),
        )
        cls.capsule_raw, cls.execution = gate.build_fresh_capsule(cls.bundle)
        cls.capsule_sha256 = hashlib.sha256(cls.capsule_raw).hexdigest()
        cls.result = gate.lower_from_capsule(
            cls.bundle,
            cls.capsule_raw,
            expected_capsule_sha256=cls.capsule_sha256,
        )
        cls.summary, cls.rows, cls.allocations = gate._capture_existing_monolithic(
            cls.bundle, cls.execution
        )
        cls.fragments = gate.build_fragments(cls.rows, cls.allocations)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @classmethod
    def snapshot_map(cls) -> dict[str, launch_io.Snapshot]:
        result = {
            split.stage_filename(index): launch_io.Snapshot(
                cls.output / split.stage_filename(index), cls.bundle.stage_raws[index]
            )
            for index in range(len(split.STAGE_ORDER))
        }
        result.update(
            {
                split.receipt_filename(index): launch_io.Snapshot(
                    cls.output / split.receipt_filename(index),
                    cls.bundle.receipt_raws[index],
                )
                for index in range(len(split.STAGE_ORDER) + 1)
            }
        )
        result[split.COMPLETE_FILENAME] = launch_io.Snapshot(
            cls.output / split.COMPLETE_FILENAME, cls.bundle.complete_raw
        )
        return result


class FragmentLoweringTests(BoundedFixture):
    def test_fragments_sum_to_exact_existing_monolithic_accounting(self) -> None:
        report = self.result.report
        self.assertEqual(report["merged_rows"], 73_049)
        self.assertEqual(report["merged_wires"], 53_032)
        self.assertEqual(report["merged_nonlinear_rows"], 52_136)
        self.assertEqual(report["merged_linear_rows"], 20_913)
        self.assertEqual(
            report["existing_monolithic_stream_sha256"],
            "635c6efaf3aa25d6f2d787450987b08712de5aaacd21f3107a90f5db9599b0cd",
        )
        self.assertEqual(sum(item["rows"] for item in report["fragments"]), 73_049)
        self.assertFalse(report["assignment_materialized"])
        self.assertFalse(report["row_archive_materialized"])
        self.assertEqual(report["external_assertions"], 0)

    def test_fragment_order_and_frozen_identities_are_exact(self) -> None:
        report = self.result.report
        self.assertEqual(tuple(report["fragment_order"]), gate.FRAGMENT_ORDER)
        self.assertEqual(
            {item["fragment_id"]: item["rows"] for item in report["fragments"]},
            gate.FROZEN_BOUNDED["fragment_rows"],
        )
        self.assertEqual(
            {item["fragment_id"]: item["stream_sha256"] for item in report["fragments"]},
            gate.FROZEN_BOUNDED["fragment_stream_sha256"],
        )
        self.assertTrue(report["merged_row_by_row_equal_to_existing_monolithic_emission"])

    def test_global_a_point_wire_handoff_is_exact(self) -> None:
        port = self.result.report["global_a_point_port"]
        self.assertEqual(port["bit_length"], 386)
        self.assertTrue(port["wire_ids_contiguous"])
        self.assertFalse(port["tree_pre_consumes_port"])
        self.assertTrue(port["tree_post_consumes_every_wire"])
        self.assertEqual(
            port["port_identity_sha256"],
            gate.FROZEN_BOUNDED["point_port_identity_sha256"],
        )

    def test_reordered_or_mutated_fragment_fails_row_by_row_merge(self) -> None:
        with self.assertRaises(gate.SplitLowererError):
            gate.verify_exact_merge(self.rows, tuple(reversed(self.fragments)))
        changed_row = replace(
            self.fragments[1].rows[0],
            row=replace(
                self.fragments[1].rows[0].row,
                output=field.LinearForm.const(1),
            ),
        )
        changed_fragment = replace(
            self.fragments[1],
            rows=(changed_row,) + self.fragments[1].rows[1:],
        )
        changed = (
            self.fragments[0],
            changed_fragment,
            *self.fragments[2:],
        )
        with self.assertRaises(gate.SplitLowererError):
            gate.verify_exact_merge(self.rows, changed)

    def test_production_entry_refuses_before_stage_read_or_lowering(self) -> None:
        with patch.object(
            gate.recovery_io,
            "read",
            side_effect=AssertionError("production read a stage artifact"),
        ), patch.object(
            gate.shard,
            "build_streaming_shard",
            side_effect=AssertionError("production started lowering"),
        ):
            with self.assertRaises(gate.ProductionSplitLowererUnavailable):
                gate.execute_production_split_lowerer(object())


class ResumeAndCapsuleTests(BoundedFixture):
    def test_resume_uses_captured_bytes_without_upstream_value_stage_rerun(self) -> None:
        with patch.object(
            gate.split,
            "build_stage_computations",
            side_effect=AssertionError("split value stages reran"),
        ), patch.object(
            gate.shard,
            "build_parallel_execution",
            side_effect=AssertionError("CAP value execution reran"),
        ), patch.object(
            gate.recovery_io,
            "read",
            side_effect=AssertionError("captured pathname was reopened"),
        ):
            resumed = gate.lower_from_capsule(
                self.bundle,
                self.capsule_raw,
                expected_capsule_sha256=self.capsule_sha256,
            )
        self.assertEqual(resumed.report, self.result.report)
        self.assertFalse(resumed.report["upstream_split_stage_builder_reexecuted"])

    def test_wrong_capsule_checkpoint_rejects_before_parse_or_lowering(self) -> None:
        with patch.object(
            gate,
            "_strict_json",
            side_effect=AssertionError("wrong-checkpoint capsule was parsed"),
        ), patch.object(
            gate,
            "_capture_existing_monolithic",
            side_effect=AssertionError("wrong-checkpoint capsule was lowered"),
        ):
            with self.assertRaises(gate.SplitLowererError):
                gate.lower_from_capsule(
                    self.bundle,
                    b"not-json\n",
                    expected_capsule_sha256="0" * 64,
                )

    def test_capsule_wrong_version_unknown_field_and_trailing_reject(self) -> None:
        original = json.loads(self.capsule_raw)
        cases = []
        wrong_version = dict(original)
        wrong_version["implementation_version"] = "2.0"
        cases.append(gate.canonical_json(wrong_version))
        unknown = dict(original)
        unknown["alternate"] = True
        cases.append(gate.canonical_json(unknown))
        cases.append(self.capsule_raw + b"{}\n")
        for raw in cases:
            with self.subTest(raw=raw[-24:]):
                with self.assertRaises(gate.SplitLowererError):
                    gate.decode_capsule(
                        raw,
                        self.bundle,
                        expected_capsule_sha256=hashlib.sha256(raw).hexdigest(),
                    )

    def test_capsule_wrong_domain_and_output_reject(self) -> None:
        for field_name in ("domain_hex", "output_hex"):
            document = json.loads(self.capsule_raw)
            value = document["xof_calls"][0][field_name]
            document["xof_calls"][0][field_name] = (
                ("00" if value[:2] != "00" else "01") + value[2:]
            )
            raw = gate.canonical_json(document)
            with self.subTest(field_name=field_name):
                with self.assertRaises(gate.SplitLowererError):
                    gate.decode_capsule(
                        raw,
                        self.bundle,
                        expected_capsule_sha256=hashlib.sha256(raw).hexdigest(),
                    )

    def test_capsule_wrong_invocation_and_final_receipt_reject(self) -> None:
        for field_name in ("invocation_sha256", "final_receipt_sha256"):
            document = json.loads(self.capsule_raw)
            document[field_name] = "0" * 64
            raw = gate.canonical_json(document)
            with self.subTest(field_name=field_name):
                with self.assertRaises(gate.SplitLowererError):
                    gate.decode_capsule(
                        raw,
                        self.bundle,
                        expected_capsule_sha256=hashlib.sha256(raw).hexdigest(),
                    )


class StageSnapshotTests(BoundedFixture):
    def test_missing_and_trailing_stage_snapshots_reject(self) -> None:
        missing = self.snapshot_map()
        del missing[split.stage_filename(2)]
        with self.assertRaises(gate.SplitLowererError):
            gate.validate_completed_stage_snapshots(
                self.bundle.invocation,
                missing,
                expected_checkpoint_sha256=self.bundle.final_receipt_sha256,
            )

        trailing = self.snapshot_map()
        name = split.stage_filename(2)
        trailing[name] = launch_io.Snapshot(
            trailing[name].location, trailing[name].raw + b"{}\n"
        )
        with self.assertRaises(gate.SplitLowererError):
            gate.validate_completed_stage_snapshots(
                self.bundle.invocation,
                trailing,
                expected_checkpoint_sha256=self.bundle.final_receipt_sha256,
            )

    def test_stage_payload_mutation_cannot_cross_stale_receipt_chain(self) -> None:
        snapshots = self.snapshot_map()
        name = split.stage_filename(2)
        document = json.loads(snapshots[name].raw)
        points = document["payload"]["points_hex"]
        document["payload"]["points_hex"] = (
            ("00" if points[:2] != "00" else "01") + points[2:]
        )
        payload_raw = gate.canonical_json(document["payload"])
        document["payload_bytes"] = len(payload_raw)
        document["payload_sha256"] = hashlib.sha256(payload_raw).hexdigest()
        mutated = gate.canonical_json(document)
        snapshots[name] = launch_io.Snapshot(snapshots[name].location, mutated)
        with self.assertRaises(gate.SplitLowererError):
            gate.validate_completed_stage_snapshots(
                self.bundle.invocation,
                snapshots,
                expected_checkpoint_sha256=self.bundle.final_receipt_sha256,
            )

    def test_wrong_final_checkpoint_rejects_before_other_stage_reads(self) -> None:
        read_count = 0
        original = gate.recovery_io.read

        def counted(path: Path) -> launch_io.Snapshot:
            nonlocal read_count
            read_count += 1
            return original(path)

        with patch.object(gate.recovery_io, "read", side_effect=counted), patch.object(
            gate.shard,
            "build_parallel_execution",
            side_effect=AssertionError("wrong checkpoint started value execution"),
        ):
            with self.assertRaises(gate.SplitLowererError):
                gate.load_completed_stage_bundle(
                    self.statement_raw,
                    self.witness_raw,
                    self.output,
                    artifact_root=self.root,
                    expected_checkpoint_sha256="0" * 64,
                )
        self.assertEqual(read_count, 1)


class CheckpointEvidenceTests(unittest.TestCase):
    def test_bounded_self_check_is_frozen_and_fail_closed(self) -> None:
        report = gate.bounded_self_check()
        self.assertEqual(report["frozen_mismatches"], [])
        self.assertTrue(report["merged_row_by_row_equal"])
        self.assertTrue(report["fresh_resume_identical"])
        self.assertFalse(report["resume_value_stage_execution_performed"])
        self.assertFalse(report["resume_upstream_split_stage_builder_reexecuted"])
        self.assertFalse(report["assignment_materialized"])
        self.assertFalse(report["row_archive_materialized"])
        self.assertFalse(report["full_i3_relation_replayed"])
        self.assertEqual(report["large_relation_rows_replayed"], 0)
        self.assertEqual(report["cryptographic_proofs_generated"], 0)

    def test_manifest_claims_and_commands_remain_production_closed(self) -> None:
        manifest = gate.build_manifest()
        claims = manifest["claim_status"]
        self.assertTrue(claims["Implemented"]["bounded_native_fragment_lowerer"])
        self.assertFalse(claims["Implemented"]["production_native_split_lowerer"])
        self.assertFalse(claims["Proof-closed"])
        self.assertFalse(claims["Production-closed"])
        self.assertFalse(claims["safe_to_start_large_replay"])
        self.assertIsNone(manifest["exact_commands"]["production_execution"])
        self.assertIsNone(manifest["exact_commands"]["large_replay"])
        self.assertIsNone(manifest["exact_commands"]["large_proving"])
        self.assertFalse(manifest["artifact_policy"]["other_tree_observed_stream_bytes_used"])

    def test_external_inventory_is_read_only_and_still_missing_five(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pq-rbbc-lowerer-preflight-") as directory:
            root = Path(directory)
            before = tuple(root.iterdir())
            report = gate.external_inventory_preflight(root)
            after = tuple(root.iterdir())
        self.assertEqual(before, after)
        missing = report["predecessor_report"]["predecessor_report"][
            "predecessor_report"
        ]["production_input_report"]["missing_artifacts"]
        self.assertEqual(
            missing,
            list(gate.child.production_inputs.REQUIRED_EXTERNAL_ARTIFACTS),
        )
        self.assertFalse(report["production_output_created"])
        self.assertFalse(report["safe_to_start_large_replay"])

    def test_tracked_prerequisites_and_generated_files_are_exact(self) -> None:
        self.assertEqual(gate.validate_tracked_prerequisites(), ())
        manifest_path = ROOT / "manifests/pq_rbbc_issuance_split_lowerer_manifest_v1.json"
        evidence_path = ROOT / (
            "artifacts/metadata/issuance_split_lowerer_v1/"
            "pq_rbbc_issuance_split_lowerer_portable_evidence_v1.json"
        )
        self.assertEqual(manifest_path.read_bytes(), gate.canonical_json(gate.build_manifest()))
        self.assertEqual(
            evidence_path.read_bytes(), gate.canonical_json(gate.build_portable_evidence())
        )
        evidence = json.loads(evidence_path.read_text(encoding="ascii"))
        self.assertFalse(evidence["private_capsule_embedded"])
        self.assertFalse(evidence["stage_payload_embedded"])
        self.assertFalse(evidence["row_archive_embedded"])
        self.assertFalse(evidence["assignment_embedded"])
        self.assertFalse(evidence["production_execution_started"])


if __name__ == "__main__":
    unittest.main()
