from dataclasses import FrozenInstanceError
import hashlib
import multiprocessing
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import pq_rbbc_cap_unified_tree_launch_validation_v2_41 as historical
import pq_rbbc_issuance_private_spool_handoff_v1 as handoff
import pq_rbbc_issuance_tree_post_continuation_v1 as continuation
import pq_rbbc_issuance_tree_post_restart_v1 as gate
import pq_rbbc_launch_io_v2_41 as io
import pq_rbbc_recovery_io_v2_42 as disk


CACHED_RESULT = None


def resume_worker(output, artifact_root, checkpoint_sha256, queue):
    try:
        result = gate.run_bounded_tree_post(
            Path(output),
            artifact_root=Path(artifact_root),
            resume=True,
            expected_checkpoint_sha256=checkpoint_sha256,
        )
        queue.put(
            (
                "ok",
                result.complete_checkpoint.identity["sha256"],
                result.output_port.value_sha256,
            )
        )
    except BaseException as error:  # pragma: no cover - child diagnostic
        queue.put(("error", type(error).__name__, str(error)))


def crash_after_publish_worker(output, artifact_root, checkpoint_sha256, target):
    original = disk.publish

    def publish(path, raw):
        original(path, raw)
        if path.name == target:
            os._exit(73)

    with patch.object(gate, "_compute_result", return_value=CACHED_RESULT), patch.object(
        disk, "publish", side_effect=publish
    ):
        gate.run_bounded_tree_post(
            Path(output),
            artifact_root=Path(artifact_root),
            resume=True,
            expected_checkpoint_sha256=checkpoint_sha256,
        )


class TreePostRestartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global CACHED_RESULT
        session = handoff.HandoffSessionInsecureTestOnly()
        try:
            session.run_to("global-a")
            cls.candidates = session.export_candidates()
            cls.handoff_sha = gate.sha256(cls.candidates.handoff.raw)
            session.accept_handoff(
                cls.candidates, expected_handoff_sha256=cls.handoff_sha
            )
            cls.continuation = continuation.build_continuation_snapshots(session)[0]
            cls.continuation_sha = gate.sha256(cls.continuation.raw)
        finally:
            session.close()
        cls.invocation = continuation.TreePostInvocationInsecureTestOnly(
            cls.candidates, cls.continuation
        )
        cls.cached_result = continuation.execute_tree_post_insecure_test_only(
            cls.invocation,
            expected_handoff_sha256=cls.handoff_sha,
            expected_continuation_sha256=cls.continuation_sha,
        )
        CACHED_RESULT = cls.cached_result

    def setUp(self):
        self.temporary = TemporaryDirectory(prefix="pq-rbbc-tree-post-restart-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "tree-post"

    def fresh(self, *, stop_after="inputs"):
        return gate.run_bounded_tree_post(
            self.output,
            artifact_root=self.root,
            fresh_invocation=self.invocation,
            expected_handoff_sha256=self.handoff_sha,
            expected_continuation_sha256=self.continuation_sha,
            fresh_output=True,
            stop_after=stop_after,
        )

    def latest(self):
        return gate.latest_checkpoint(self.output, artifact_root=self.root)

    def resume(self, **kwargs):
        digest = kwargs.pop("expected_checkpoint_sha256", self.latest().identity["sha256"])
        return gate.run_bounded_tree_post(
            self.output,
            artifact_root=self.root,
            resume=True,
            expected_checkpoint_sha256=digest,
            **kwargs,
        )

    def complete_cached(self):
        with patch.object(gate, "_compute_result", return_value=self.cached_result):
            return self.fresh(stop_after=None)

    def files(self):
        return {
            str(path.relative_to(self.output)): path.read_bytes()
            for path in self.output.rglob("*")
            if path.is_file()
        }

    def test_bounded_self_check_and_claim_boundary(self):
        evidence = gate.bounded_self_check()
        self.assertTrue(evidence["fresh_and_restart_artifacts_identical"])
        self.assertTrue(evidence["completed_result_consumed_without_tree_post_replay"])
        self.assertEqual(evidence["restartable_boundary"], "inputs-committed")
        self.assertEqual(evidence["tree_post_rows"], 3_576)
        self.assertEqual(evidence["tree_post_allocated_wires"], 2_412)
        self.assertFalse(evidence["incomplete_input_publication_recoverable"])
        self.assertFalse(evidence["production_durable_resume_implemented"])
        self.assertFalse(evidence["Proof-closed"])
        self.assertFalse(evidence["Production-closed"])

    def test_fresh_and_restart_are_byte_identical_and_idempotent(self):
        reference = self.root / "reference"
        with patch.object(gate, "_compute_result", return_value=self.cached_result):
            expected = gate.run_bounded_tree_post(
                reference,
                artifact_root=self.root,
                fresh_invocation=self.invocation,
                expected_handoff_sha256=self.handoff_sha,
                expected_continuation_sha256=self.continuation_sha,
                fresh_output=True,
            )
            self.fresh()
            actual = self.resume()
            before = self.files()
            repeated = self.resume()
        reference_files = {
            str(path.relative_to(reference)): path.read_bytes()
            for path in reference.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, reference_files)
        self.assertEqual(actual.result.raw, expected.result.raw)
        self.assertEqual(repeated.complete_checkpoint.raw, actual.complete_checkpoint.raw)
        self.assertEqual(before, self.files())

    def test_real_new_process_resumes_without_live_invocation(self):
        self.fresh()
        checkpoint = self.latest()
        context = multiprocessing.get_context("fork")
        queue = context.Queue()
        process = context.Process(
            target=resume_worker,
            args=(str(self.output), str(self.root), checkpoint.identity["sha256"], queue),
        )
        process.start()
        process.join(30)
        if process.is_alive():
            process.kill()
            process.join()
            self.fail("restart child timed out")
        self.assertEqual(process.exitcode, 0)
        message = queue.get(timeout=2)
        self.assertEqual(message[0], "ok", message)
        self.assertEqual(message[2], self.cached_result.output_port.value_sha256)
        self.assertEqual(self.latest().location.name, gate.COMPLETE_NAME)

    def test_real_process_death_after_each_result_publication_recovers(self):
        context = multiprocessing.get_context("fork")
        targets = (
            gate.RESULT_NAMES[0],
            gate.RECEIPT_NAMES[0],
            gate.RESULT_COMMITTED_NAME,
            gate.COMPLETE_NAME,
        )
        for index, target in enumerate(targets):
            with self.subTest(target=target):
                self.output = self.root / f"fault-{index}"
                self.fresh()
                checkpoint_sha = self.latest().identity["sha256"]
                process = context.Process(
                    target=crash_after_publish_worker,
                    args=(str(self.output), str(self.root), checkpoint_sha, target),
                )
                process.start()
                process.join(20)
                if process.is_alive():
                    process.kill()
                    process.join()
                    self.fail("fault-injection child timed out")
                self.assertEqual(process.exitcode, 73)
                with patch.object(gate, "_compute_result", return_value=self.cached_result):
                    result = self.resume()
                self.assertEqual(result.owned_values, self.cached_result.owned_values)
                self.assertEqual(self.latest().location.name, gate.COMPLETE_NAME)

    def test_wrong_or_stale_checkpoint_digest_rejects_before_inputs_or_compute(self):
        self.fresh()
        old = self.latest().identity["sha256"]
        with patch.object(gate, "_load_inputs", side_effect=AssertionError("input read")), patch.object(
            gate, "_compute_result", side_effect=AssertionError("compute")
        ):
            for digest in (None, "0" * 64, "A" * 64, 7):
                with self.subTest(digest=digest), self.assertRaises(gate.RestartError):
                    self.resume(expected_checkpoint_sha256=digest)
        with patch.object(gate, "_compute_result", return_value=self.cached_result):
            self.resume(stop_after="result-checkpoint")
        with patch.object(gate, "_load_inputs", side_effect=AssertionError("input read")), patch.object(
            gate, "_compute_result", side_effect=AssertionError("compute")
        ), self.assertRaisesRegex(gate.RestartError, "stale digest"):
            self.resume(expected_checkpoint_sha256=old)

    def test_incomplete_input_publication_fails_closed_without_mutation(self):
        original = disk.publish
        count = 0

        def interrupt(path, raw):
            nonlocal count
            if path.parent.name == gate.INPUT_DIRECTORY:
                count += 1
                if count == 3:
                    raise OSError("controlled input publication interruption")
            return original(path, raw)

        with patch.object(disk, "publish", side_effect=interrupt), self.assertRaises(OSError):
            self.fresh()
        before = self.files()
        self.assertEqual(self.latest().location.name, gate.PLAN_NAME)
        with self.assertRaisesRegex(gate.RestartError, "incomplete"):
            self.resume()
        self.assertEqual(before, self.files())

    def test_unknown_missing_and_gapped_artifacts_refuse(self):
        cases = (
            "unknown-input",
            "missing-input",
            "unknown-result",
            "journal-gap",
            "missing-committed-result",
        )
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                self.output = self.root / f"inventory-{index}"
                self.fresh()
                if case == "unknown-input":
                    (self.output / gate.INPUT_DIRECTORY / "foreign.bin").write_bytes(b"x")
                elif case == "missing-input":
                    (self.output / gate.INPUT_DIRECTORY / handoff.POINT_NAME).unlink()
                elif case == "unknown-result":
                    (self.output / gate.RESULT_DIRECTORY / "foreign.bin").write_bytes(b"x")
                elif case == "journal-gap":
                    with patch.object(
                        gate, "_compute_result", return_value=self.cached_result
                    ):
                        self.resume()
                    (self.output / gate.JOURNAL_DIRECTORY / gate.INPUTS_COMMITTED_NAME).unlink()
                else:
                    with patch.object(
                        gate, "_compute_result", return_value=self.cached_result
                    ):
                        self.resume()
                    (self.output / gate.RESULT_DIRECTORY / gate.RESULT_NAMES[0]).unlink()
                before = self.files()
                with self.assertRaises((gate.RestartError, io.ValidationError)):
                    self.resume()
                self.assertEqual(before, self.files())

    def test_checkpoint_wrong_version_claim_duplicate_and_trailing_refuse(self):
        variants = []
        self.fresh()
        checkpoint = self.latest()
        document = checkpoint.document()
        document["implementation_version"] = "2.0"
        variants.append(gate.canonical_json(document))
        document = checkpoint.document()
        document["production"] = True
        variants.append(gate.canonical_json(document))
        variants.extend(
            (
                checkpoint.raw + b"\n",
                checkpoint.raw.replace(
                    b'"production":false',
                    b'"production":false,"production":false',
                ),
            )
        )
        for index, raw in enumerate(variants):
            with self.subTest(variant=index):
                self.output = self.root / f"checkpoint-{index}"
                self.fresh()
                path = self.output / gate.JOURNAL_DIRECTORY / gate.INPUTS_COMMITTED_NAME
                path.write_bytes(raw)
                before = self.files()
                with self.assertRaises((gate.RestartError, io.ValidationError)):
                    self.resume(expected_checkpoint_sha256=gate.sha256(raw))
                self.assertEqual(before, self.files())

    def test_mutated_result_or_receipt_orphan_never_overwritten(self):
        for index, boundary in enumerate(("result-payload", "result-receipt")):
            with self.subTest(boundary=boundary):
                self.output = self.root / f"orphan-{index}"
                self.fresh()
                with patch.object(gate, "_compute_result", return_value=self.cached_result):
                    self.resume(stop_after=boundary)
                name = gate.RESULT_NAMES[0] if index == 0 else gate.RECEIPT_NAMES[0]
                path = self.output / gate.RESULT_DIRECTORY / name
                changed = path.read_bytes()[:-1] + b"X"
                path.write_bytes(changed)
                before = self.files()
                with patch.object(gate, "_compute_result", return_value=self.cached_result), self.assertRaises(
                    gate.RestartError
                ):
                    self.resume()
                self.assertEqual(path.read_bytes(), changed)
                self.assertEqual(before, self.files())

    def test_private_result_mutations_and_trailing_bytes_refuse_completed_capture(self):
        variants = []
        complete = self.complete_cached()
        path = self.output / gate.RESULT_DIRECTORY / gate.RESULT_NAMES[0]
        snapshot = io.read_snapshot(path, external=True)
        document = snapshot.document()
        document["implementation_version"] = "2.0"
        variants.append(gate.canonical_json(document))
        document = snapshot.document()
        document["owned_values_hex"] = "0" + document["owned_values_hex"][1:]
        variants.append(gate.canonical_json(document))
        document = snapshot.document()
        document["production"] = True
        variants.append(gate.canonical_json(document))
        variants.append(snapshot.raw + b"\n")
        for index, raw in enumerate(variants):
            with self.subTest(variant=index):
                path.write_bytes(raw)
                with self.assertRaises((gate.RestartError, io.ValidationError)):
                    gate.capture_completed_result(
                        self.output,
                        artifact_root=self.root,
                        expected_complete_sha256=complete.complete_checkpoint.identity[
                            "sha256"
                        ],
                    )
                path.write_bytes(snapshot.raw)

    def test_capture_uses_one_immutable_raw_even_if_path_changes_after_read(self):
        complete = self.complete_cached()
        original = disk.read
        reads = []

        def mutate_after_capture(path):
            snapshot = original(path)
            reads.append(path)
            if path.name == gate.RESULT_NAMES[0]:
                path.write_bytes(b'{"changed":true}\n')
            return snapshot

        with patch.object(disk, "read", side_effect=mutate_after_capture):
            captured = gate.capture_completed_result(
                self.output,
                artifact_root=self.root,
                expected_complete_sha256=complete.complete_checkpoint.identity["sha256"],
            )
        self.assertEqual(captured.owned_values, self.cached_result.owned_values)
        self.assertEqual(reads.count(self.output / gate.RESULT_DIRECTORY / gate.RESULT_NAMES[0]), 1)
        self.assertNotEqual(
            (self.output / gate.RESULT_DIRECTORY / gate.RESULT_NAMES[0]).read_bytes(),
            captured.result.raw,
        )

    def test_competing_result_is_not_overwritten_and_lock_rejects_second_writer(self):
        self.fresh()
        path = self.output / gate.RESULT_DIRECTORY / gate.RESULT_NAMES[0]
        path.write_bytes(b"competing writer")
        with patch.object(gate, "_compute_result", return_value=self.cached_result), self.assertRaises(
            gate.RestartError
        ):
            self.resume()
        self.assertEqual(path.read_bytes(), b"competing writer")
        with disk.locked_output(self.output, self.root, fresh=False):
            with self.assertRaisesRegex(io.ValidationError, "another bounded writer"):
                self.resume()

    def test_production_refuses_before_io_and_preflight_is_read_only(self):
        forbidden = self.root / "must-not-exist"
        with patch.object(io, "read_snapshot", side_effect=AssertionError("read")), patch.object(
            disk, "locked_output", side_effect=AssertionError("output")
        ), self.assertRaises(gate.ProductionUnavailable):
            gate.execute_production(output=forbidden)
        self.assertFalse(forbidden.exists())
        report = gate.preflight()
        self.assertTrue(report["private_append_only_publication_implemented"])
        self.assertTrue(report["bounded_process_restart_implemented"])
        self.assertFalse(report["production_durable_resume_implemented"])
        self.assertFalse(report["safe_to_start_large_replay"])
        self.assertEqual(len(report["missing_production_artifacts"]), 5)

    def test_private_results_are_immutable_and_not_in_portable_evidence(self):
        complete = self.complete_cached()
        with self.assertRaises(FrozenInstanceError):
            complete.tree_index = 1
        evidence = gate.bounded_self_check()
        portable = gate.canonical_json(evidence)
        self.assertNotIn(self.candidates.spools[0].raw, portable)
        self.assertNotIn(complete.result.raw, portable)
        self.assertFalse(evidence["private_payload_embedded_in_portable_evidence"])

    def test_historical_v238_v239_identities_unchanged(self):
        self.assertEqual(len(historical.HISTORICAL_IDENTITIES), 19)
        for relative, expected in historical.HISTORICAL_IDENTITIES.items():
            raw = (gate.ROOT / relative).read_bytes()
            self.assertEqual(len(raw), expected["bytes"], relative)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), expected["sha256"], relative)

    def test_manifest_and_portable_evidence_are_exact_and_private_free(self):
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


if __name__ == "__main__":
    unittest.main()
