#!/usr/bin/env python3
"""Regression tests for bounded independently invocable fragment producers."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pq_rbbc_issuance_fragment_producers_v1 as gate
import pq_rbbc_issuance_split_lowerer_v1 as predecessor
import pq_rbbc_issuance_split_runner_v1 as split
import pq_rbbc_launch_io_v2_41 as launch_io


ROOT = Path(__file__).resolve().parents[1]


class BoundedFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(
            prefix="pq-rbbc-fragment-producer-test-"
        )
        cls.root = Path(cls.temporary.name)
        os.chmod(cls.root, 0o700)
        cls.stages = cls.root / "stages"
        cls.statement_raw, cls.witness_raw = gate._fixture_bytes()
        split.run_bounded_split(
            cls.statement_raw,
            cls.witness_raw,
            cls.stages,
            artifact_root=cls.root,
            fresh_output=True,
        )
        latest = split.latest_receipt(cls.stages, artifact_root=cls.root)
        cls.bundle = predecessor.load_completed_stage_bundle(
            cls.statement_raw,
            cls.witness_raw,
            cls.stages,
            artifact_root=cls.root,
            expected_checkpoint_sha256=str(latest.identity["sha256"]),
        )
        cls.capsule_raw, cls.execution = predecessor.build_fresh_capsule(cls.bundle)
        cls.capsule_sha256 = hashlib.sha256(cls.capsule_raw).hexdigest()
        cls.context = gate._context_from_capsule(
            cls.bundle,
            cls.capsule_raw,
            expected_capsule_sha256=cls.capsule_sha256,
        )
        cls.results = gate.produce_sequence(cls.context)
        cls.monolithic_summary, cls.monolithic_rows, allocations = (
            predecessor._capture_existing_monolithic(cls.bundle, cls.execution)
        )
        cls.monolithic_fragments = predecessor.build_fragments(
            cls.monolithic_rows, allocations
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def new_output(self, label: str) -> Path:
        return self.root / label

    def start_partial(self, label: str, count: int) -> Path:
        output = self.new_output(label)
        gate.run_bounded_fragment_producers(
            self.bundle,
            self.capsule_raw,
            output,
            artifact_root=self.root,
            expected_capsule_sha256=self.capsule_sha256,
            fresh_output=True,
            stop_after_fragments=count,
        )
        return output


class IndependentProducerTests(BoundedFixture):
    def test_each_producer_is_independently_invocable_and_exact(self) -> None:
        state = None
        observed = []
        for ordinal, function in enumerate(gate.PRODUCER_FUNCTIONS):
            if ordinal == 0:
                result = function(self.context)
            else:
                assert state is not None
                result = function(
                    self.context,
                    state,
                    expected_import_identity=state["port_identity_sha256"],
                )
            observed.append(result)
            state = result.export_state
        self.assertEqual(
            tuple(item.fragment for item in observed), self.monolithic_fragments
        )
        predecessor.verify_exact_merge(
            self.monolithic_rows, tuple(item.fragment for item in observed)
        )
        self.assertEqual(sum(item.summary["rows"] for item in observed), 73_049)
        self.assertEqual(state["next_wire"] - 1, 53_032)

    def test_frozen_fragment_identities_and_global_point_port_are_preserved(self) -> None:
        self.assertEqual(
            {item.fragment.fragment_id: item.summary["stream_sha256"] for item in self.results},
            predecessor.FROZEN_BOUNDED["fragment_stream_sha256"],
        )
        global_a = self.results[2].export_state
        self.assertEqual(
            global_a["body"]["point_port_identity_sha256"],
            predecessor.FROZEN_BOUNDED["point_port_identity_sha256"],
        )

    def test_wrong_import_identity_rejects_before_fragment_lowering(self) -> None:
        with patch.object(
            gate.shard,
            "StreamingSpongeLowerer",
            side_effect=AssertionError("wrong import started lowering"),
        ):
            with self.assertRaises(gate.FragmentProducerError):
                gate.produce_tree_pre(
                    self.context,
                    self.results[0].export_state,
                    expected_import_identity="0" * 64,
                )

    def test_mutated_unknown_version_domain_and_state_digest_reject(self) -> None:
        original = self.results[0].export_state
        cases = []
        for name, value in (
            ("implementation_version", "2.0"),
            ("relation_id", "wrong-domain"),
            ("port_identity_sha256", "0" * 64),
        ):
            changed = deepcopy(original)
            changed[name] = value
            cases.append(changed)
        unknown = deepcopy(original)
        unknown["alternate"] = True
        cases.append(unknown)
        mutated_body = deepcopy(original)
        mutated_body["body"]["message_start"] += 1
        cases.append(mutated_body)
        for state in cases:
            with self.subTest(keys=tuple(state)):
                with self.assertRaises(gate.FragmentProducerError):
                    gate.produce_tree_pre(
                        self.context,
                        state,
                        expected_import_identity=str(
                            state.get("port_identity_sha256", "")
                        ),
                    )

    def test_production_refuses_before_read_lowering_or_output(self) -> None:
        missing = self.root / "production-must-not-exist"
        with patch.object(
            gate.recovery_io,
            "read",
            side_effect=AssertionError("production read an artifact"),
        ), patch.object(
            gate,
            "_invoke_producer",
            side_effect=AssertionError("production invoked a producer"),
        ):
            with self.assertRaises(gate.ProductionFragmentProducersUnavailable):
                gate.execute_production_fragment_producers(missing)
        self.assertFalse(missing.exists())


class PublicationResumeTests(BoundedFixture):
    def test_controlled_orphan_is_recomputed_and_adopted_without_rerun(self) -> None:
        output = self.new_output("orphan-resume")
        counts = [0] * len(gate.FRAGMENT_ORDER)
        original = gate.PRODUCER_FUNCTIONS

        def counted(index, function):
            def wrapper(*args, **kwargs):
                counts[index] += 1
                return function(*args, **kwargs)

            return wrapper

        wrappers = tuple(counted(index, function) for index, function in enumerate(original))
        with patch.object(gate, "PRODUCER_FUNCTIONS", wrappers):
            with self.assertRaises(gate.ControlledInterruption):
                gate.run_bounded_fragment_producers(
                    self.bundle,
                    self.capsule_raw,
                    output,
                    artifact_root=self.root,
                    expected_capsule_sha256=self.capsule_sha256,
                    fresh_output=True,
                    interrupt_after_fragment=2,
                )
            orphan = output / gate.fragment_filename(2)
            before = (orphan.stat().st_ino, orphan.read_bytes())
            checkpoint = gate.latest_receipt(output, artifact_root=self.root)
            complete = gate.run_bounded_fragment_producers(
                self.bundle,
                self.capsule_raw,
                output,
                artifact_root=self.root,
                expected_capsule_sha256=self.capsule_sha256,
                resume=True,
                expected_checkpoint_sha256=checkpoint.identity["sha256"],
            )
        self.assertIsNotNone(complete)
        self.assertEqual(counts, [1, 1, 2, 1, 1])
        self.assertEqual(before, (orphan.stat().st_ino, orphan.read_bytes()))
        self.assertEqual(len(tuple(output.iterdir())), 12)

    def test_completed_resume_reuses_all_bytes_and_inodes(self) -> None:
        output = self.new_output("complete-resume")
        gate.run_bounded_fragment_producers(
            self.bundle,
            self.capsule_raw,
            output,
            artifact_root=self.root,
            expected_capsule_sha256=self.capsule_sha256,
            fresh_output=True,
        )
        before = {
            item.name: (item.stat().st_ino, item.read_bytes()) for item in output.iterdir()
        }
        checkpoint = gate.latest_receipt(output, artifact_root=self.root)
        guards = tuple(
            (
                lambda *_args, name=name, **_kwargs: (_ for _ in ()).throw(
                    AssertionError(f"completed producer reran: {name}")
                )
            )
            for name in gate.FRAGMENT_ORDER
        )
        with patch.object(gate, "PRODUCER_FUNCTIONS", guards):
            result = gate.run_bounded_fragment_producers(
                self.bundle,
                self.capsule_raw,
                output,
                artifact_root=self.root,
                expected_capsule_sha256=self.capsule_sha256,
                resume=True,
                expected_checkpoint_sha256=checkpoint.identity["sha256"],
            )
        after = {
            item.name: (item.stat().st_ino, item.read_bytes()) for item in output.iterdir()
        }
        self.assertEqual(before, after)
        self.assertEqual(result["merged_rows"], 73_049)

    def test_wrong_checkpoint_rejects_before_capsule_parse_or_producer(self) -> None:
        output = self.start_partial("wrong-checkpoint", 1)
        reads = 0
        original_read = gate.recovery_io.read

        def counted_read(path):
            nonlocal reads
            reads += 1
            return original_read(path)

        with patch.object(gate.recovery_io, "read", side_effect=counted_read), patch.object(
            gate,
            "_context_from_capsule",
            side_effect=AssertionError("wrong checkpoint parsed capsule"),
        ), patch.object(
            gate,
            "_invoke_producer",
            side_effect=AssertionError("wrong checkpoint invoked producer"),
        ):
            with self.assertRaises(gate.FragmentProducerError):
                gate.run_bounded_fragment_producers(
                    self.bundle,
                    self.capsule_raw,
                    output,
                    artifact_root=self.root,
                    expected_capsule_sha256=self.capsule_sha256,
                    resume=True,
                    expected_checkpoint_sha256="0" * 64,
                )
        self.assertEqual(reads, 1)

    def test_unknown_gap_and_missing_artifact_fail_closed(self) -> None:
        unknown = self.start_partial("unknown-entry", 1)
        (unknown / "unexpected.json").write_bytes(b"{}\n")
        checkpoint = gate.latest_receipt  # inventory itself must reject unknown
        with self.assertRaises(gate.FragmentProducerError):
            checkpoint(unknown, artifact_root=self.root)

        gap = self.start_partial("gap-entry", 1)
        (gap / gate.fragment_filename(3)).write_bytes(
            (gap / gate.fragment_filename(0)).read_bytes()
        )
        latest = gate.latest_receipt(gap, artifact_root=self.root)
        with self.assertRaises(gate.FragmentProducerError):
            gate.run_bounded_fragment_producers(
                self.bundle,
                self.capsule_raw,
                gap,
                artifact_root=self.root,
                expected_capsule_sha256=self.capsule_sha256,
                resume=True,
                expected_checkpoint_sha256=latest.identity["sha256"],
            )

        missing = self.start_partial("missing-entry", 1)
        os.unlink(missing / gate.fragment_filename(0))
        latest = gate.latest_receipt(missing, artifact_root=self.root)
        with self.assertRaises(gate.FragmentProducerError):
            gate.run_bounded_fragment_producers(
                self.bundle,
                self.capsule_raw,
                missing,
                artifact_root=self.root,
                expected_capsule_sha256=self.capsule_sha256,
                resume=True,
                expected_checkpoint_sha256=latest.identity["sha256"],
            )

    def test_trailing_or_mutated_completed_artifact_rejects(self) -> None:
        for suffix, mutation in (
            ("trailing", lambda raw: raw + b"{}\n"),
            (
                "mutation",
                lambda raw: raw.replace(b'"rows":1028', b'"rows":1029', 1),
            ),
        ):
            with self.subTest(suffix=suffix):
                output = self.start_partial(f"bad-{suffix}", 1)
                artifact = output / gate.fragment_filename(0)
                artifact.write_bytes(mutation(artifact.read_bytes()))
                checkpoint = gate.latest_receipt(output, artifact_root=self.root)
                with self.assertRaises(gate.FragmentProducerError):
                    gate.run_bounded_fragment_producers(
                        self.bundle,
                        self.capsule_raw,
                        output,
                        artifact_root=self.root,
                        expected_capsule_sha256=self.capsule_sha256,
                        resume=True,
                        expected_checkpoint_sha256=checkpoint.identity["sha256"],
                    )


class EvidenceTests(unittest.TestCase):
    def test_self_check_closes_only_bounded_producer_gate(self) -> None:
        report = gate.bounded_self_check()
        self.assertEqual(report["frozen_mismatches"], [])
        self.assertTrue(
            report["independent_fragments_row_by_row_equal_to_existing_monolithic"]
        )
        self.assertTrue(report["completed_producers_not_rerun_on_resume"])
        self.assertTrue(report["orphan_identity_preserved"])
        self.assertTrue(report["orphan_inode_preserved"])
        self.assertEqual(
            report["producer_invocation_counts_across_interrupt_resume"],
            [1, 1, 2, 1, 1],
        )
        self.assertFalse(report["assignment_materialized"])
        self.assertFalse(report["row_archive_materialized"])
        self.assertFalse(report["full_i3_relation_replayed"])
        self.assertEqual(report["cryptographic_proofs_generated"], 0)

    def test_manifest_claims_and_large_commands_fail_closed(self) -> None:
        manifest = gate.build_manifest()
        claims = manifest["claim_status"]
        self.assertTrue(claims["Implemented"]["bounded_independent_fragment_producers"])
        self.assertFalse(claims["Implemented"]["production_fragment_producers"])
        self.assertFalse(claims["Proof-closed"])
        self.assertFalse(claims["Production-closed"])
        self.assertFalse(claims["safe_to_start_large_replay"])
        self.assertIsNone(manifest["exact_commands"]["production_execution"])
        self.assertIsNone(manifest["exact_commands"]["large_replay"])
        self.assertIsNone(manifest["exact_commands"]["large_proving"])
        self.assertFalse(
            manifest["publication_contract"]["metadata_proves_no_concurrent_writer"]
        )
        self.assertFalse(
            manifest["artifact_policy"]["other_tree_observed_stream_bytes_used"]
        )

    def test_external_inventory_is_read_only_and_missing_five(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="pq-rbbc-fragment-producer-preflight-"
        ) as directory:
            root = Path(directory)
            before = tuple(root.iterdir())
            report = gate.external_inventory_preflight(root)
            after = tuple(root.iterdir())
        self.assertEqual(before, after)
        missing = report["predecessor_report"]["predecessor_report"][
            "predecessor_report"
        ]["predecessor_report"]["production_input_report"]["missing_artifacts"]
        self.assertEqual(
            missing,
            list(predecessor.child.production_inputs.REQUIRED_EXTERNAL_ARTIFACTS),
        )
        self.assertFalse(report["production_output_created"])
        self.assertFalse(report["safe_to_start_large_replay"])

    def test_tracked_prerequisites_and_generated_files_are_exact(self) -> None:
        self.assertEqual(gate.validate_tracked_prerequisites(), ())
        manifest_path = (
            ROOT / "manifests/pq_rbbc_issuance_fragment_producers_manifest_v1.json"
        )
        evidence_path = ROOT / (
            "artifacts/metadata/issuance_fragment_producers_v1/"
            "pq_rbbc_issuance_fragment_producers_portable_evidence_v1.json"
        )
        self.assertEqual(manifest_path.read_bytes(), gate.canonical_json(gate.build_manifest()))
        self.assertEqual(
            evidence_path.read_bytes(), gate.canonical_json(gate.build_portable_evidence())
        )
        evidence = json.loads(evidence_path.read_text(encoding="ascii"))
        self.assertFalse(evidence["private_runtime_state_embedded"])
        self.assertFalse(evidence["fragment_artifacts_embedded"])
        self.assertFalse(evidence["row_archive_embedded"])
        self.assertFalse(evidence["assignment_embedded"])
        self.assertFalse(evidence["production_execution_started"])


if __name__ == "__main__":
    unittest.main()
