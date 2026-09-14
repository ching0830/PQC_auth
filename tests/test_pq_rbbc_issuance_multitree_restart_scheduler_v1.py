from dataclasses import FrozenInstanceError, replace
import errno
import hashlib
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from unittest.mock import patch

import pq_rbbc_cap_unified_tree_launch_validation_v2_41 as historical
import pq_rbbc_issuance_multitree_restart_scheduler_v1 as gate
import pq_rbbc_issuance_private_spool_handoff_v1 as handoff
import pq_rbbc_issuance_tree_post_continuation_v1 as continuation
import pq_rbbc_issuance_tree_post_restart_v1 as restart
import pq_rbbc_launch_io_v2_41 as io
import pq_rbbc_recovery_io_v2_42 as disk


class MultitreeRestartSchedulerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.session = handoff.HandoffSessionInsecureTestOnly()
        cls.session.run_to("global-a")
        cls.candidates = cls.session.export_candidates()
        handoff_sha = gate.sha256(cls.candidates.handoff.raw)
        cls.session.accept_handoff(
            cls.candidates, expected_handoff_sha256=handoff_sha
        )
        cls.continuations = continuation.build_continuation_snapshots(cls.session)
        cls.invocations = tuple(
            continuation.TreePostInvocationInsecureTestOnly(
                cls.candidates, continuation_snapshot
            )
            for continuation_snapshot in cls.continuations
        )
        cls.cached_results = tuple(
            continuation.execute_tree_post_insecure_test_only(
                invocation,
                expected_handoff_sha256=gate.HANDOFF_IDENTITY["sha256"],
                expected_continuation_sha256=gate.CONTINUATION_IDENTITIES[index][
                    "sha256"
                ],
            )
            for index, invocation in enumerate(cls.invocations)
        )

    @classmethod
    def tearDownClass(cls):
        cls.session.close()

    def setUp(self):
        self.temporary = TemporaryDirectory(
            prefix="pq-rbbc-multitree-scheduler-test-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "scheduler"

    def cached_compute(self, _invocation, plan_document):
        return self.cached_results[int(plan_document["tree_index"])]

    def run_cached(self, **kwargs):
        with patch.object(
            restart, "_compute_result", side_effect=self.cached_compute
        ):
            return gate.run_bounded_scheduler(
                self.output,
                artifact_root=self.root,
                **kwargs,
            )

    def fresh_cached(self, **kwargs):
        return self.run_cached(
            fresh_invocations=self.invocations,
            fresh_output=True,
            **kwargs,
        )

    def resume_cached(self, **kwargs):
        digest = kwargs.pop(
            "expected_checkpoint_sha256",
            gate.latest_scheduler_checkpoint(
                self.output, artifact_root=self.root
            ).identity["sha256"],
        )
        return self.run_cached(
            resume=True,
            expected_checkpoint_sha256=digest,
            **kwargs,
        )

    def files(self):
        return gate._scoped_file_bytes(self.root, self.output.name)

    def copy_completed(self, name):
        source_root = self.root / (name + "-source-root")
        source_root.mkdir(mode=0o700)
        source_output = source_root / "scheduler"
        with patch.object(
            restart, "_compute_result", side_effect=self.cached_compute
        ):
            gate.run_bounded_scheduler(
                source_output,
                artifact_root=source_root,
                fresh_invocations=self.invocations,
                fresh_output=True,
            )
        target_root = self.root / (name + "-root")
        target_root.mkdir(mode=0o700)
        for source in source_root.iterdir():
            target_name = source.name.replace("scheduler", name, 1)
            shutil.copytree(source, target_root / target_name)
        return target_root, target_root / name

    def test_bounded_self_check_sequential_parallel_identity_and_claims(self):
        evidence = gate.bounded_self_check()
        for key, expected in gate.FROZEN.items():
            self.assertEqual(evidence[key], expected)
        self.assertEqual(evidence["ordered_tree_indices"], [0, 1])
        self.assertEqual(evidence["tree_post_rows"], [3_576, 3_576])
        self.assertTrue(evidence["sequential_parallel_artifacts_byte_identical"])
        self.assertTrue(
            evidence["sequential_parallel_ordered_results_byte_identical"]
        )
        self.assertTrue(evidence["result_order_matches_plan"])
        self.assertTrue(evidence["independent_output_directories"])
        self.assertTrue(evidence["independent_tree_journals"])
        self.assertTrue(evidence["distinct_fresh_cache_identities"])
        self.assertFalse(evidence["shared_writable_cache"])
        self.assertFalse(evidence["shared_resume_state"])
        self.assertFalse(evidence["other_tree_observed_stream_bytes_used"])
        for claim in (
            "global_tail_continuation_implemented",
            "production_legacy18_provider_implemented",
            "production_durable_resume_implemented",
            "qualified_pq_se_backend_integrated",
            "formal_pi_issue_generated",
            "safe_to_start_large_replay",
            "safe_to_start_large_proving_run",
            "Proof-closed",
            "Production-closed",
        ):
            self.assertFalse(evidence[claim], claim)

    def test_execution_plan_is_canonical_versioned_domain_separated_and_closed(self):
        plan = gate.build_execution_plan(self.invocations)
        document = plan.document()
        self.assertEqual(document["format"], gate.PLAN_FORMAT)
        self.assertEqual(document["plan_version"], 1)
        self.assertEqual(document["execution_domain_hex"], gate.DOMAIN_PLAN.hex())
        self.assertEqual(document["ordered_tree_indices"], [0, 1])
        self.assertEqual(document["scheduling"]["concurrency_limit"], 2)
        self.assertEqual(
            document["scheduling"]["result_order"],
            "execution-plan-order-not-worker-completion-order",
        )
        caches = [item["fresh_cache_identity_sha256"] for item in document["trees"]]
        inputs = [
            item["private_input_root_identity_sha256"] for item in document["trees"]
        ]
        results = [
            item["private_result_root_identity_sha256"] for item in document["trees"]
        ]
        self.assertEqual(len(set(caches)), 2)
        self.assertEqual(len(set(inputs)), 2)
        self.assertEqual(len(set(results)), 2)
        self.assertEqual(
            [item["output_port"] for item in document["trees"]],
            list(gate.EXPECTED_OUTPUT_PORTS),
        )
        self.assertTrue(
            all(item["observed_stream_bytes"] is None for item in document["trees"])
        )
        self.assertFalse(document["outputs"]["global_tail_output_created"])
        self.assertFalse(document["outputs"]["parent_output_created"])

    def test_plan_mutation_wrong_order_cache_alias_and_noncanonical_bytes_refuse(self):
        original = gate.execution_plan_snapshot()
        mutations = []
        document = original.document()
        document["implementation_version"] = "1.0"
        mutations.append(gate.canonical_json(document))
        document = original.document()
        document["ordered_tree_indices"] = [1, 0]
        mutations.append(gate.canonical_json(document))
        document = original.document()
        document["trees"] = list(reversed(document["trees"]))
        mutations.append(gate.canonical_json(document))
        document = original.document()
        document["trees"][1]["fresh_cache_identity_sha256"] = document["trees"][0][
            "fresh_cache_identity_sha256"
        ]
        mutations.append(gate.canonical_json(document))
        document = original.document()
        document["unknown"] = None
        mutations.append(gate.canonical_json(document))
        mutations.extend(
            (
                original.raw + b"\n",
                original.raw.replace(
                    b'"production":false',
                    b'"production":false,"production":false',
                    1,
                ),
            )
        )
        for index, raw in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(gate.SchedulerError):
                gate._validate_plan(replace(original, raw=raw))
        with self.assertRaises(gate.SchedulerError):
            gate.build_execution_plan(tuple(reversed(self.invocations)))

    def test_parallel_reverse_completion_still_publishes_plan_order(self):
        sequential_root = self.root / "sequential-root"
        parallel_root = self.root / "parallel-root"
        sequential_root.mkdir(mode=0o700)
        parallel_root.mkdir(mode=0o700)
        with patch.object(
            restart, "_compute_result", side_effect=self.cached_compute
        ):
            sequential = gate.run_bounded_scheduler(
                sequential_root / "scheduler",
                artifact_root=sequential_root,
                fresh_invocations=self.invocations,
                fresh_output=True,
                scheduling_mode="sequential",
            )
        original = gate._complete_or_adopt_tree
        completion_order = []
        guard = threading.Lock()

        def reverse_completion(output, artifact_root, descriptor):
            if descriptor["tree_index"] == 0:
                time.sleep(0.15)
            result = original(output, artifact_root, descriptor)
            with guard:
                completion_order.append(descriptor["tree_index"])
            return result

        with patch.object(
            restart, "_compute_result", side_effect=self.cached_compute
        ), patch.object(
            gate, "_complete_or_adopt_tree", side_effect=reverse_completion
        ):
            parallel = gate.run_bounded_scheduler(
                parallel_root / "scheduler",
                artifact_root=parallel_root,
                fresh_invocations=self.invocations,
                fresh_output=True,
                scheduling_mode="bounded-parallel",
            )
        self.assertEqual(completion_order, [1, 0])
        self.assertEqual(
            [item.tree_index for item in sequential.ordered_results], [0, 1]
        )
        self.assertEqual(
            [item.tree_index for item in parallel.ordered_results], [0, 1]
        )
        self.assertEqual(
            gate._scoped_file_bytes(sequential_root, "scheduler"),
            gate._scoped_file_bytes(parallel_root, "scheduler"),
        )

    def test_one_tree_complete_other_pending_restart_and_repeated_resume(self):
        self.fresh_cached(
            scheduling_mode="sequential", stop_after_tree_checkpoint=0
        )
        parent = gate.latest_scheduler_checkpoint(
            self.output, artifact_root=self.root
        )
        self.assertEqual(parent.location.name, gate.TREE_CHECKPOINT_NAMES[0])
        tree0 = restart.latest_checkpoint(
            gate._tree_output(self.output, 0), artifact_root=self.root
        )
        tree1 = restart.latest_checkpoint(
            gate._tree_output(self.output, 1), artifact_root=self.root
        )
        self.assertEqual(tree0.location.name, restart.COMPLETE_NAME)
        self.assertEqual(tree1.location.name, restart.INPUTS_COMMITTED_NAME)
        resumed = self.resume_cached(scheduling_mode="bounded-parallel")
        self.assertEqual([item.tree_index for item in resumed.ordered_results], [0, 1])
        before = self.files()
        with patch.object(
            restart,
            "run_bounded_tree_post",
            side_effect=AssertionError("completed schedule must not replay tree-post"),
        ):
            repeated = gate.run_bounded_scheduler(
                self.output,
                artifact_root=self.root,
                resume=True,
                expected_checkpoint_sha256=resumed.complete_checkpoint.identity[
                    "sha256"
                ],
                scheduling_mode="sequential",
            )
        self.assertEqual(before, self.files())
        self.assertEqual(
            repeated.complete_checkpoint.raw, resumed.complete_checkpoint.raw
        )

    def test_exact_complete_orphan_is_adopted_without_recompute(self):
        self.fresh_cached(
            scheduling_mode="sequential", stop_after_child_tree=0
        )
        self.assertEqual(
            gate.latest_scheduler_checkpoint(
                self.output, artifact_root=self.root
            ).location.name,
            gate.INPUTS_COMMITTED_NAME,
        )
        self.assertEqual(
            restart.latest_checkpoint(
                gate._tree_output(self.output, 0), artifact_root=self.root
            ).location.name,
            restart.COMPLETE_NAME,
        )
        computed = []

        def only_tree_one(_invocation, plan_document):
            computed.append(plan_document["tree_index"])
            if plan_document["tree_index"] != 1:
                raise AssertionError("exact tree-0 orphan was recomputed")
            return self.cached_results[1]

        with patch.object(restart, "_compute_result", side_effect=only_tree_one):
            resumed = gate.run_bounded_scheduler(
                self.output,
                artifact_root=self.root,
                resume=True,
                expected_checkpoint_sha256=gate.latest_scheduler_checkpoint(
                    self.output, artifact_root=self.root
                ).identity["sha256"],
            )
        self.assertEqual(computed, [1])
        self.assertEqual(resumed.adopted_orphan_tree_indices, (0,))

    def test_completed_child_dependencies_sync_before_parent_checkpoint(self):
        self.fresh_cached(scheduling_mode="sequential", stop_after_child_tree=0)
        child = gate._tree_output(self.output, 0)
        events = []
        original_sync = disk.sync_directory
        original_publish = disk.publish

        def record_sync(path, descriptor):
            events.append(("sync", Path(path)))
            return original_sync(path, descriptor)

        def record_publish(path, raw):
            events.append(("publish", Path(path)))
            return original_publish(path, raw)

        with patch.object(
            disk, "sync_directory", side_effect=record_sync
        ), patch.object(disk, "publish", side_effect=record_publish):
            resumed = self.resume_cached(scheduling_mode="sequential")

        parent_checkpoint = (
            self.output
            / gate.SCHEDULER_JOURNAL_DIRECTORY
            / gate.TREE_CHECKPOINT_NAMES[0]
        )
        parent_position = events.index(("publish", parent_checkpoint))
        expected_dependencies = (
            child / restart.INPUT_DIRECTORY,
            child / restart.RESULT_DIRECTORY,
            child / restart.JOURNAL_DIRECTORY,
            child,
            self.root,
        )
        sync_positions = [
            events.index(("sync", dependency))
            for dependency in expected_dependencies
        ]
        self.assertEqual(sync_positions, sorted(sync_positions))
        self.assertTrue(all(position < parent_position for position in sync_positions))
        self.assertEqual(resumed.adopted_orphan_tree_indices, (0,))

    def test_child_durability_eio_refuses_parent_then_exact_retry_succeeds(self):
        self.fresh_cached(scheduling_mode="sequential", stop_after_child_tree=0)
        child = gate._tree_output(self.output, 0)
        parent = gate.latest_scheduler_checkpoint(
            self.output, artifact_root=self.root
        )
        before = self.files()
        original_sync = disk.sync_directory
        injected = False

        def fail_once(path, descriptor):
            nonlocal injected
            if not injected and Path(path) == child / restart.RESULT_DIRECTORY:
                injected = True
                raise OSError(errno.EIO, "injected child durability failure")
            return original_sync(path, descriptor)

        with patch.object(
            disk, "sync_directory", side_effect=fail_once
        ), self.assertRaises(OSError) as raised:
            self.resume_cached(
                scheduling_mode="sequential",
                expected_checkpoint_sha256=parent.identity["sha256"],
            )
        self.assertEqual(raised.exception.errno, errno.EIO)
        self.assertEqual(before, self.files())
        self.assertEqual(
            gate.latest_scheduler_checkpoint(
                self.output, artifact_root=self.root
            ).location.name,
            gate.INPUTS_COMMITTED_NAME,
        )
        resumed = self.resume_cached(scheduling_mode="sequential")
        self.assertEqual(resumed.adopted_orphan_tree_indices, (0,))

    def test_unknown_child_root_component_refuses_before_relation_or_parent_commit(self):
        self.fresh_cached(stop_after_inputs=True)
        parent = gate.latest_scheduler_checkpoint(
            self.output, artifact_root=self.root
        )
        child = gate._tree_output(self.output, 0)
        (child / "unknown-component").write_bytes(b"unexpected")
        with patch.object(
            restart,
            "run_bounded_tree_post",
            side_effect=AssertionError("relation work preceded child inventory"),
        ), self.assertRaisesRegex(gate.SchedulerError, "one-tree output component"):
            gate.run_bounded_scheduler(
                self.output,
                artifact_root=self.root,
                resume=True,
                expected_checkpoint_sha256=parent.identity["sha256"],
            )
        self.assertEqual(
            gate.latest_scheduler_checkpoint(
                self.output, artifact_root=self.root
            ).identity,
            parent.identity,
        )

    def test_unknown_parent_component_refuses_resume_and_completed_capture(self):
        completed = self.fresh_cached()
        (self.output / "unknown-component").write_bytes(b"unexpected")
        digest = completed.complete_checkpoint.identity["sha256"]
        with patch.object(
            restart,
            "latest_checkpoint",
            side_effect=AssertionError("child read preceded parent inventory"),
        ):
            with self.assertRaisesRegex(
                gate.SchedulerError, "scheduler output component"
            ):
                gate.run_bounded_scheduler(
                    self.output,
                    artifact_root=self.root,
                    resume=True,
                    expected_checkpoint_sha256=digest,
                )
            with self.assertRaisesRegex(
                gate.SchedulerError, "scheduler output component"
            ):
                gate.capture_completed_schedule(
                    self.output,
                    artifact_root=self.root,
                    expected_complete_sha256=digest,
                )

    def test_completed_capture_requires_direct_child_scheduler_output(self):
        completed = self.fresh_cached()
        nested = self.root / "nested"
        nested.mkdir(mode=0o700)
        for source in (
            self.output,
            gate._tree_output(self.output, 0),
            gate._tree_output(self.output, 1),
        ):
            shutil.copytree(source, nested / source.name)
        with self.assertRaisesRegex(gate.SchedulerError, "direct child"):
            gate.capture_completed_schedule(
                nested / self.output.name,
                artifact_root=self.root,
                expected_complete_sha256=completed.complete_checkpoint.identity[
                    "sha256"
                ],
            )

    def test_competing_scheduler_is_rejected_by_parent_output_lock(self):
        self.fresh_cached(stop_after_inputs=True)
        checkpoint = gate.latest_scheduler_checkpoint(
            self.output, artifact_root=self.root
        )
        with disk.locked_output(self.output, self.root, fresh=False):
            with self.assertRaisesRegex(io.ValidationError, "another bounded writer"):
                self.resume_cached(
                    expected_checkpoint_sha256=checkpoint.identity["sha256"]
                )

    def test_wrong_and_stale_scheduler_checkpoint_reject_before_tree_io(self):
        self.fresh_cached(stop_after_inputs=True)
        old = gate.latest_scheduler_checkpoint(
            self.output, artifact_root=self.root
        ).identity["sha256"]
        with patch.object(
            restart,
            "latest_checkpoint",
            side_effect=AssertionError("tree read before parent digest"),
        ):
            for digest in (None, "0" * 64, "A" * 64, 7):
                with self.subTest(digest=digest), self.assertRaises(
                    gate.SchedulerError
                ):
                    gate.run_bounded_scheduler(
                        self.output,
                        artifact_root=self.root,
                        resume=True,
                        expected_checkpoint_sha256=digest,
                    )
        self.resume_cached(stop_after_tree_checkpoint=0)
        with patch.object(
            restart,
            "latest_checkpoint",
            side_effect=AssertionError("tree read before stale digest rejection"),
        ), self.assertRaisesRegex(gate.SchedulerError, "stale digest"):
            gate.run_bounded_scheduler(
                self.output,
                artifact_root=self.root,
                resume=True,
                expected_checkpoint_sha256=old,
            )

    def test_missing_gapped_unknown_and_reordered_results_refuse_without_mutation(self):
        cases = (
            "missing-tree-output",
            "missing-result",
            "unknown-result",
            "unknown-tree",
            "journal-gap",
            "reordered-results",
        )
        for ordinal, case in enumerate(cases):
            with self.subTest(case=case):
                root, output = self.copy_completed(f"case-{ordinal}")
                if case == "missing-tree-output":
                    shutil.rmtree(gate._tree_output(output, 1))
                elif case == "missing-result":
                    (
                        gate._tree_output(output, 1)
                        / restart.RESULT_DIRECTORY
                        / restart.RESULT_NAMES[1]
                    ).unlink()
                elif case == "unknown-result":
                    (
                        gate._tree_output(output, 1)
                        / restart.RESULT_DIRECTORY
                        / "tree-unknown.post-result.private.json"
                    ).write_bytes(b"unknown")
                elif case == "unknown-tree":
                    (root / (output.name + ".tree-2")).mkdir(mode=0o700)
                elif case == "journal-gap":
                    (
                        output
                        / gate.SCHEDULER_JOURNAL_DIRECTORY
                        / gate.TREE_CHECKPOINT_NAMES[0]
                    ).unlink()
                else:
                    path = (
                        output
                        / gate.SCHEDULER_JOURNAL_DIRECTORY
                        / gate.COMPLETE_NAME
                    )
                    snapshot = io.read_snapshot(path, external=True)
                    document = snapshot.document()
                    document["ordered_tree_indices"] = [1, 0]
                    path.write_bytes(gate.canonical_json(document))
                before = gate._scoped_file_bytes(root, output.name)
                latest_path = (
                    output
                    / gate.SCHEDULER_JOURNAL_DIRECTORY
                    / gate.COMPLETE_NAME
                )
                digest = gate.sha256(latest_path.read_bytes())
                with self.assertRaises(
                    (gate.SchedulerError, io.ValidationError, FileNotFoundError)
                ):
                    gate.capture_completed_schedule(
                        output,
                        artifact_root=root,
                        expected_complete_sha256=digest,
                    )
                self.assertEqual(before, gate._scoped_file_bytes(root, output.name))

    def test_wrong_child_checkpoint_rejects_without_relation_compute(self):
        self.fresh_cached(stop_after_inputs=True)
        path = (
            gate._tree_output(self.output, 0)
            / restart.JOURNAL_DIRECTORY
            / restart.INPUTS_COMMITTED_NAME
        )
        snapshot = io.read_snapshot(path, external=True)
        document = snapshot.document()
        document["implementation_version"] = "2.0"
        path.write_bytes(gate.canonical_json(document))
        with patch.object(
            restart, "run_bounded_tree_post", side_effect=AssertionError("compute")
        ), self.assertRaises(gate.SchedulerError):
            gate.run_bounded_scheduler(
                self.output,
                artifact_root=self.root,
                resume=True,
                expected_checkpoint_sha256=gate.latest_scheduler_checkpoint(
                    self.output, artifact_root=self.root
                ).identity["sha256"],
            )

    def test_scheduler_uses_one_tree_api_and_never_calls_relation_directly(self):
        with patch.object(
            continuation,
            "execute_tree_post_insecure_test_only",
            side_effect=AssertionError("scheduler called tree-post relation directly"),
        ), patch.object(
            restart, "_compute_result", side_effect=self.cached_compute
        ):
            result = gate.run_bounded_scheduler(
                self.output,
                artifact_root=self.root,
                fresh_invocations=self.invocations,
                fresh_output=True,
                scheduling_mode="bounded-parallel",
            )
        self.assertEqual([item.tree_index for item in result.ordered_results], [0, 1])
        self.assertFalse(
            gate.EXECUTION_PLAN_DOCUMENT["outputs"]["global_tail_output_created"]
        )
        self.assertFalse(
            gate.EXECUTION_PLAN_DOCUMENT["outputs"]["parent_output_created"]
        )

    def test_production_refuses_before_io_and_preflight_preserves_false_claims(self):
        forbidden = self.root / "must-not-exist"
        with patch.object(
            io, "read_snapshot", side_effect=AssertionError("read")
        ), patch.object(
            disk, "locked_output", side_effect=AssertionError("write")
        ), self.assertRaises(gate.ProductionUnavailable):
            gate.execute_production(output=forbidden)
        self.assertFalse(forbidden.exists())
        report = gate.preflight()
        for claim in (
            "global_tail_continuation_implemented",
            "production_legacy18_provider_implemented",
            "production_durable_resume_implemented",
            "qualified_pq_se_backend_integrated",
            "formal_pi_issue_generated",
            "safe_to_start_large_replay",
            "safe_to_start_large_proving_run",
            "Proof-closed",
            "Production-closed",
        ):
            self.assertFalse(report[claim], claim)
        self.assertIsNone(report["production_execution_command"])
        self.assertEqual(len(report["missing_production_artifacts"]), 5)

    def test_result_is_immutable_and_portable_evidence_contains_no_private_bytes(self):
        completed = self.fresh_cached()
        with self.assertRaises(FrozenInstanceError):
            completed.ordered_results = ()
        evidence = gate.bounded_self_check()
        raw = gate.canonical_json(evidence)
        for result in completed.ordered_results:
            self.assertNotIn(result.result.raw, raw)
            self.assertNotIn(result.receipt.raw, raw)
        self.assertNotIn(self.candidates.spools[0].raw, raw)
        self.assertFalse(evidence["private_input_or_result_bytes_embedded"])

    def test_historical_v238_v239_identities_unchanged(self):
        self.assertEqual(len(historical.HISTORICAL_IDENTITIES), 19)
        for relative, expected in historical.HISTORICAL_IDENTITIES.items():
            raw = (gate.ROOT / relative).read_bytes()
            self.assertEqual(len(raw), expected["bytes"], relative)
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(), expected["sha256"], relative
            )

    def test_manifest_and_portable_evidence_are_exact_metadata_only(self):
        evidence = gate.bounded_self_check()
        with patch.object(gate, "bounded_self_check", return_value=evidence):
            for path, document in (
                (gate.MANIFEST_PATH, gate.build_manifest()),
                (gate.EVIDENCE_PATH, gate.build_portable_evidence()),
            ):
                raw = (gate.ROOT / path).read_bytes()
                self.assertEqual(raw, gate.canonical_json(document))
                io.strict_json(raw)
                self.assertNotIn(str(gate.ROOT).encode(), raw)
                self.assertNotIn(self.candidates.spools[0].raw, raw)
                for result in self.cached_results:
                    private_raw = b"".join(
                        value.to_bytes(25, "little")
                        for value in result.owned_values
                    )
                    self.assertNotIn(private_raw, raw)


if __name__ == "__main__":
    unittest.main()
