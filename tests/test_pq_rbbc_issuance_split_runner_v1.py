from __future__ import annotations

import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pq_rbbc_cap_commit as cap
import pq_rbbc_issuance_split_runner_v1 as gate
import pq_rbbc_launch_io_v2_41 as launch_io


ROOT = Path(__file__).resolve().parents[1]


class SimulatedCrash(RuntimeError):
    pass


def competing_fresh_runner(
    root: str,
    output: str,
    statement_raw: bytes,
    witness_raw: bytes,
    queue: multiprocessing.Queue,
) -> None:
    try:
        gate.run_bounded_split(
            statement_raw,
            witness_raw,
            Path(output),
            artifact_root=Path(root),
            fresh_output=True,
        )
        queue.put("created")
    except (FileExistsError, launch_io.ValidationError):
        queue.put("exists")
    except Exception as error:  # pragma: no cover - returned to parent for diagnosis
        queue.put(f"error:{type(error).__name__}:{error}")


def snapshot_tree(output: Path) -> dict[str, bytes]:
    return {
        path.name: path.read_bytes()
        for path in output.iterdir()
        if path.is_file()
    }


class SplitValueExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.statement_raw, cls.witness_raw = gate._fixture_bytes()
        cls.invocation = gate.predecessor.capture_invocation(
            cls.statement_raw, cls.witness_raw
        )
        cls.randomness = cap.CAPRandomness(
            cls.invocation.rho.randomness.salt,
            (cls.invocation.rho.randomness.roots[0],),
        )
        cls.invocation_from_split, cls.computations = gate.build_stage_computations(
            cls.statement_raw, cls.witness_raw
        )

    def test_plan_and_prerequisites_are_frozen(self) -> None:
        self.assertEqual(gate.validate_plan(), ())
        self.assertEqual(gate.validate_tracked_prerequisites(), ())
        self.assertEqual(gate.plan_sha256(), gate.FROZEN_PLAN_SHA256)
        self.assertEqual(
            tuple(stage["stage_id"] for stage in gate.build_plan()["stage_dependencies"]),
            gate.STAGE_ORDER,
        )

    def test_tree_pre_never_consumes_global_points(self) -> None:
        with patch.object(
            cap,
            "_linear_hash_masks",
            side_effect=AssertionError("tree-pre consumed global points"),
        ), patch.object(
            cap,
            "_linear_hash_vector",
            side_effect=AssertionError("tree-pre consumed global points"),
        ):
            tree_pre, computation = gate._build_tree_pre(self.randomness)
        self.assertEqual(computation.stage_id, "tree-pre[0]")
        self.assertTrue(
            all(call.label.startswith("tree[0].") for call in tree_pre.calls)
        )
        self.assertEqual(
            [port.port_id for port in computation.ports],
            [
                "tree[0].leaf-commitments",
                "tree[0].p-plain",
                "tree[0].mhat-plain",
            ],
        )

    def test_global_a_then_tree_post_dependency_is_explicit(self) -> None:
        tree_pre, _ = gate._build_tree_pre(self.randomness)
        global_a, global_computation = gate._build_global_a(tree_pre)
        self.assertEqual(
            [call.label for call in global_a.calls],
            ["h1", "consistency-points"],
        )
        self.assertEqual(global_computation.stage_id, "global-tail-phase-a")
        tree_post, post_computation = gate._build_tree_post(tree_pre, global_a)
        self.assertEqual(post_computation.stage_id, "tree-post[0]")
        self.assertEqual(len(tree_post.xi_masks), gate.PARAMETERS.consistency_bits)
        self.assertEqual(
            post_computation.payload["consistency_points_sha256"],
            gate._sha256(gate._pack_vector(global_a.points, gate.field.FIELD_DEGREE)),
        )

    def test_global_b_matches_direct_cap_reference(self) -> None:
        final = self.computations[-1].payload
        global_b = self.computations[4]
        self.assertTrue(global_b.payload["split_matches_direct_reference"])
        self.assertTrue(final["split_matches_direct_reference"])
        self.assertFalse(final["formal_mask_matches_bounded_derived_mask"])
        self.assertFalse(final["full_i3_relation_claimed"])
        self.assertFalse(final["constraint_stream_split_lowered"])

    def test_ports_use_canonical_bit_widths(self) -> None:
        for computation in self.computations:
            for port in computation.ports:
                self.assertEqual(len(port.raw), (port.bit_length + 7) // 8)
                unused = len(port.raw) * 8 - port.bit_length
                if unused:
                    self.assertEqual(port.raw[-1] >> (8 - unused), 0)

    def test_stage_codec_rejects_wrong_domain_mutation_and_trailing(self) -> None:
        genesis = gate.canonical_json(
            gate._genesis_receipt(self.invocation.invocation_sha256)
        )
        previous = gate._sha256(genesis)
        document = gate._stage_artifact(
            self.invocation.invocation_sha256,
            0,
            self.computations[0],
            previous,
        )
        raw = gate.canonical_json(document)
        parsed = gate._strict_json(raw, "stage")
        gate._validate_stage_document(
            parsed,
            invocation_sha256=self.invocation.invocation_sha256,
            ordinal=0,
            computation=self.computations[0],
            previous_receipt_sha256=previous,
        )
        mutated = dict(document)
        mutated["relation_id"] = "wrong-domain"
        with self.assertRaises(gate.SplitRunnerError):
            gate._validate_stage_document(
                mutated,
                invocation_sha256=self.invocation.invocation_sha256,
                ordinal=0,
                computation=self.computations[0],
                previous_receipt_sha256=previous,
            )
        with self.assertRaises(gate.SplitRunnerError):
            gate._strict_json(raw + b"\x00", "stage")
        mutated = dict(document)
        mutated["extra"] = 1
        with self.assertRaises(gate.SplitRunnerError):
            gate._validate_stage_document(
                mutated,
                invocation_sha256=self.invocation.invocation_sha256,
                ordinal=0,
                computation=self.computations[0],
                previous_receipt_sha256=previous,
            )


class PublisherRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.statement_raw, cls.witness_raw = gate._fixture_bytes()
        cls.reference_temp = tempfile.TemporaryDirectory(
            prefix="pq-rbbc-split-reference-"
        )
        cls.reference_root = Path(cls.reference_temp.name)
        cls.reference_output = cls.reference_root / "output"
        cls.reference_result = gate.run_bounded_split(
            cls.statement_raw,
            cls.witness_raw,
            cls.reference_output,
            artifact_root=cls.reference_root,
            fresh_output=True,
        )
        cls.reference_files = snapshot_tree(cls.reference_output)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.reference_temp.cleanup()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="pq-rbbc-split-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "output"

    def latest(self) -> launch_io.Snapshot:
        return gate.latest_receipt(self.output, artifact_root=self.root)

    def resume(self, **kwargs: object) -> dict[str, object] | None:
        expected = kwargs.pop(
            "expected_checkpoint_sha256", self.latest().identity["sha256"]
        )
        return gate.run_bounded_split(
            self.statement_raw,
            self.witness_raw,
            self.output,
            artifact_root=self.root,
            resume=True,
            expected_checkpoint_sha256=str(expected),
            **kwargs,
        )

    def test_fresh_controlled_resume_and_repeated_resume_are_identical(self) -> None:
        self.assertIsNone(
            gate.run_bounded_split(
                self.statement_raw,
                self.witness_raw,
                self.output,
                artifact_root=self.root,
                fresh_output=True,
                stop_after_stages=3,
            )
        )
        result = self.resume()
        self.assertEqual(result, self.reference_result)
        self.assertEqual(snapshot_tree(self.output), self.reference_files)
        inodes = {path.name: path.stat().st_ino for path in self.output.iterdir()}
        self.assertEqual(self.resume(), self.reference_result)
        self.assertEqual(snapshot_tree(self.output), self.reference_files)
        self.assertEqual(
            {path.name: path.stat().st_ino for path in self.output.iterdir()}, inodes
        )

    def test_crash_after_stage_link_adopts_exact_orphan_without_replacement(self) -> None:
        original_publish = gate.recovery_io.publish

        def crash_after_publish(path: Path, raw: bytes) -> None:
            original_publish(path, raw)
            if path.name == gate.stage_filename(2):
                raise SimulatedCrash(path.name)

        with patch.object(
            gate.recovery_io, "publish", side_effect=crash_after_publish
        ), self.assertRaises(SimulatedCrash):
            gate.run_bounded_split(
                self.statement_raw,
                self.witness_raw,
                self.output,
                artifact_root=self.root,
                fresh_output=True,
            )
        orphan = self.output / gate.stage_filename(2)
        before = (orphan.read_bytes(), orphan.stat().st_ino)
        result = self.resume()
        self.assertEqual(result, self.reference_result)
        self.assertEqual((orphan.read_bytes(), orphan.stat().st_ino), before)
        self.assertEqual(snapshot_tree(self.output), self.reference_files)

    def test_wrong_external_checkpoint_rejects_before_recomputation(self) -> None:
        gate.run_bounded_split(
            self.statement_raw,
            self.witness_raw,
            self.output,
            artifact_root=self.root,
            fresh_output=True,
            stop_after_stages=1,
        )
        before = snapshot_tree(self.output)
        with patch.object(
            gate,
            "build_stage_computations",
            side_effect=AssertionError("recomputed before external digest check"),
        ):
            with self.assertRaises(gate.SplitRunnerError):
                self.resume(expected_checkpoint_sha256="0" * 64)
        self.assertEqual(snapshot_tree(self.output), before)

    def test_mutated_and_trailing_stage_fail_closed_without_new_output(self) -> None:
        for mutation in ("semantic", "trailing"):
            with self.subTest(mutation=mutation):
                output = self.root / mutation
                gate.run_bounded_split(
                    self.statement_raw,
                    self.witness_raw,
                    output,
                    artifact_root=self.root,
                    fresh_output=True,
                    stop_after_stages=2,
                )
                checkpoint = gate.latest_receipt(output, artifact_root=self.root)
                path = output / gate.stage_filename(0)
                if mutation == "semantic":
                    document = json.loads(path.read_bytes())
                    document["payload_sha256"] = "0" * 64
                    path.write_bytes(gate.canonical_json(document))
                else:
                    path.write_bytes(path.read_bytes() + b"\x00")
                before = snapshot_tree(output)
                with self.assertRaises(gate.SplitRunnerError):
                    gate.run_bounded_split(
                        self.statement_raw,
                        self.witness_raw,
                        output,
                        artifact_root=self.root,
                        resume=True,
                        expected_checkpoint_sha256=str(
                            checkpoint.identity["sha256"]
                        ),
                    )
                self.assertEqual(snapshot_tree(output), before)

    def test_unknown_gap_and_missing_artifacts_fail_closed(self) -> None:
        for case in ("unknown", "gap", "missing"):
            with self.subTest(case=case):
                output = self.root / case
                gate.run_bounded_split(
                    self.statement_raw,
                    self.witness_raw,
                    output,
                    artifact_root=self.root,
                    fresh_output=True,
                    stop_after_stages=1,
                )
                if case == "unknown":
                    (output / "foreign.json").write_bytes(b"{}\n")
                elif case == "gap":
                    os.rename(
                        output / gate.receipt_filename(1),
                        output / gate.receipt_filename(2),
                    )
                else:
                    (output / gate.stage_filename(0)).unlink()
                before = snapshot_tree(output)
                if case == "unknown":
                    with self.assertRaises(gate.SplitRunnerError):
                        gate.latest_receipt(output, artifact_root=self.root)
                else:
                    checkpoint = gate.latest_receipt(output, artifact_root=self.root)
                    with self.assertRaises(gate.SplitRunnerError):
                        gate.run_bounded_split(
                            self.statement_raw,
                            self.witness_raw,
                            output,
                            artifact_root=self.root,
                            resume=True,
                            expected_checkpoint_sha256=str(
                                checkpoint.identity["sha256"]
                            ),
                        )
                self.assertEqual(snapshot_tree(output), before)

    def test_dangling_stage_symlink_rejects_without_following(self) -> None:
        gate.run_bounded_split(
            self.statement_raw,
            self.witness_raw,
            self.output,
            artifact_root=self.root,
            fresh_output=True,
            stop_after_stages=0,
        )
        (self.output / gate.stage_filename(0)).symlink_to(self.root / "missing")
        checkpoint = self.latest()
        with self.assertRaises((OSError, launch_io.ValidationError)):
            self.resume(expected_checkpoint_sha256=checkpoint.identity["sha256"])
        self.assertFalse((self.root / "missing").exists())

    def test_two_process_fresh_race_has_exactly_one_winner(self) -> None:
        context = multiprocessing.get_context("fork")
        queue = context.Queue()
        processes = [
            context.Process(
                target=competing_fresh_runner,
                args=(
                    str(self.root),
                    str(self.output),
                    self.statement_raw,
                    self.witness_raw,
                    queue,
                ),
            )
            for _ in range(2)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(30)
            self.assertEqual(process.exitcode, 0)
        results = sorted(queue.get(timeout=2) for _ in processes)
        self.assertEqual(results, ["created", "exists"])
        self.assertEqual(snapshot_tree(self.output), self.reference_files)

    def test_existing_output_and_production_entry_refuse_before_publication(self) -> None:
        gate.run_bounded_split(
            self.statement_raw,
            self.witness_raw,
            self.output,
            artifact_root=self.root,
            fresh_output=True,
        )
        before = snapshot_tree(self.output)
        with self.assertRaises(FileExistsError):
            gate.run_bounded_split(
                self.statement_raw,
                self.witness_raw,
                self.output,
                artifact_root=self.root,
                fresh_output=True,
            )
        self.assertEqual(snapshot_tree(self.output), before)
        with patch.object(
            gate.recovery_io,
            "locked_output",
            side_effect=AssertionError("production touched output"),
        ):
            with self.assertRaises(gate.ProductionSplitRunnerUnavailable):
                gate.execute_production_split_runner(object())


class CheckpointEvidenceTests(unittest.TestCase):
    def test_bounded_self_check_and_claim_boundary(self) -> None:
        report = gate.bounded_self_check()
        self.assertEqual(report["frozen_mismatches"], [])
        self.assertEqual(report["durable_file_count"], 14)
        self.assertTrue(report["fresh_and_resume_byte_identical"])
        self.assertTrue(report["split_matches_direct_reference"])
        self.assertTrue(report["mutation_rejected"])
        self.assertTrue(report["failed_resume_created_no_output"])
        self.assertTrue(report["wrong_invocation_rejected"])
        self.assertTrue(report["existing_output_rejected"])
        self.assertTrue(report["production_refused_before_output"])
        self.assertFalse(report["constraint_stream_split_lowered"])
        self.assertEqual(report["large_relation_rows_replayed"], 0)
        self.assertFalse(report["assignment_materialized"])
        self.assertEqual(report["cryptographic_proofs_generated"], 0)

    def test_manifest_is_fail_closed_and_commands_do_not_authorize_large_run(self) -> None:
        manifest = gate.build_manifest()
        claims = manifest["claim_status"]
        self.assertTrue(claims["Implemented"]["bounded_value_split_runner"])
        self.assertTrue(claims["Implemented"]["bounded_atomic_publisher"])
        self.assertFalse(
            claims["Implemented"]["production_constraint_split_runner"]
        )
        self.assertFalse(claims["Proof-closed"])
        self.assertFalse(claims["Production-closed"])
        self.assertFalse(claims["safe_to_materialize_production_cache"])
        self.assertFalse(claims["safe_to_start_large_replay"])
        self.assertIsNone(manifest["exact_commands"]["production_execution"])
        self.assertIsNone(manifest["exact_commands"]["large_replay"])
        self.assertIsNone(manifest["exact_commands"]["large_proving"])

    def test_external_inventory_is_read_only_and_missing_five(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pq-rbbc-split-preflight-") as directory:
            root = Path(directory)
            before = tuple(root.iterdir())
            report = gate.external_inventory_preflight(root)
            after = tuple(root.iterdir())
        self.assertEqual(before, after)
        missing = report["predecessor_report"]["predecessor_report"][
            "production_input_report"
        ]["missing_artifacts"]
        self.assertEqual(
            missing,
            list(gate.predecessor.production_inputs.REQUIRED_EXTERNAL_ARTIFACTS),
        )
        self.assertFalse(report["production_output_created"])
        self.assertFalse(report["safe_to_start_large_replay"])
        self.assertFalse(report["safe_to_start_large_proving_run"])

    def test_tracked_manifest_and_evidence_match_generators(self) -> None:
        manifest_path = ROOT / "manifests/pq_rbbc_issuance_split_runner_manifest_v1.json"
        evidence_path = ROOT / (
            "artifacts/metadata/issuance_split_runner_v1/"
            "pq_rbbc_issuance_split_runner_portable_evidence_v1.json"
        )
        self.assertEqual(
            manifest_path.read_bytes(), gate.canonical_json(gate.build_manifest())
        )
        self.assertEqual(
            evidence_path.read_bytes(), gate.canonical_json(gate.build_portable_evidence())
        )
        evidence = json.loads(evidence_path.read_text(encoding="ascii"))
        self.assertFalse(evidence["private_stage_payload_embedded"])
        self.assertFalse(evidence["absolute_paths_embedded"])
        self.assertFalse(evidence["production_execution_started"])
        self.assertFalse(evidence["large_replay_started"])
        self.assertFalse(evidence["large_proving_started"])
        self.assertFalse(evidence["other_tree_observed_stream_bytes_used"])


if __name__ == "__main__":
    unittest.main()
