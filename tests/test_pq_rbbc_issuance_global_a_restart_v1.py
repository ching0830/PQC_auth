from dataclasses import FrozenInstanceError, replace
import hashlib
import multiprocessing
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import pq_rbbc_cap_unified_tree_launch_validation_v2_41 as historical
import pq_rbbc_issuance_global_a_restart_v1 as gate
import pq_rbbc_issuance_private_spool_handoff_v1 as handoff
import pq_rbbc_launch_io_v2_41 as io
import pq_rbbc_recovery_io_v2_42 as disk


def resume_worker(output, artifact_root, checkpoint_sha256, queue):
    try:
        result = gate.run_bounded_global_a(
            Path(output),
            artifact_root=Path(artifact_root),
            resume=True,
            expected_checkpoint_sha256=checkpoint_sha256,
        )
        queue.put(("ok", result.complete_checkpoint.identity["sha256"]))
    except BaseException as error:  # pragma: no cover - child diagnostic
        queue.put(("error", type(error).__name__, str(error)))


class GlobalARestartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        session = handoff.HandoffSessionInsecureTestOnly()
        try:
            session.run_to("tree-pre[1]")
            cls.candidates = gate.build_tree_pre_candidates_insecure_test_only(session)
            cls.handoff_sha = gate.sha256(cls.candidates.handoff.raw)
            cls.result = gate.execute_global_a_insecure_test_only(
                cls.candidates, expected_handoff_sha256=cls.handoff_sha
            )
            session.run_to("global-a")
            cls.live_values = tuple(
                session.values[wire] for wire in range(*gate.PHASE_A_INTERVAL)
            )
            cls.live_points = session.point_snapshot.raw
        finally:
            session.close()

    def setUp(self):
        self.temporary = TemporaryDirectory(prefix="pq-rbbc-global-a-restart-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "global-a"

    def fresh(self, *, stop_after="inputs"):
        return gate.run_bounded_global_a(
            self.output,
            artifact_root=self.root,
            fresh_candidates=self.candidates,
            expected_handoff_sha256=self.handoff_sha,
            fresh_output=True,
            stop_after=stop_after,
        )

    def latest(self):
        return gate.latest_checkpoint(self.output, artifact_root=self.root)

    def resume(self, **kwargs):
        digest = kwargs.pop(
            "expected_checkpoint_sha256", self.latest().identity["sha256"]
        )
        return gate.run_bounded_global_a(
            self.output,
            artifact_root=self.root,
            resume=True,
            expected_checkpoint_sha256=digest,
            **kwargs,
        )

    def complete_cached(self):
        with patch.object(
            gate, "execute_global_a_insecure_test_only", return_value=self.result
        ):
            return self.fresh(stop_after=None)

    def files(self):
        return {
            str(path.relative_to(self.output)): path.read_bytes()
            for path in self.output.rglob("*")
            if path.is_file()
        }

    def repinned_receipt_candidate(self, ordinal, mutate):
        receipts = list(self.candidates.receipts)
        document = receipts[ordinal].document()
        mutate(document)
        receipts[ordinal] = replace(
            receipts[ordinal], raw=gate.canonical_json(document)
        )
        receipt_identities = [item.identity for item in receipts]
        tree_results = []
        for tree_index, snapshot in enumerate(self.candidates.tree_results):
            tree_document = snapshot.document()
            tree_document["verified_receipt_prefix_identities"] = receipt_identities
            if ordinal == tree_index + 1:
                tree_document["producer_receipt_sha256"] = receipt_identities[ordinal][
                    "sha256"
                ]
            tree_results.append(
                replace(snapshot, raw=gate.canonical_json(tree_document))
            )
        handoff_document = self.candidates.handoff.document()
        handoff_document["adapter_receipts"] = receipt_identities
        handoff_document["tree_results"] = [item.identity for item in tree_results]
        changed_handoff = replace(
            self.candidates.handoff, raw=gate.canonical_json(handoff_document)
        )
        return (
            gate.TreePreCandidateSetInsecureTestOnly(
                changed_handoff, tuple(tree_results), tuple(receipts)
            ),
            tuple(receipt_identities),
        )

    def test_frozen_phase_a_matches_live_native_prefix(self):
        self.assertEqual(self.result.owned_values, self.live_values)
        self.assertEqual(self.result.point_snapshot.raw, self.live_points)
        self.assertEqual(self.result.summary["rows"], 19_671)
        self.assertEqual(self.result.summary["allocated_wires"], 12_179)
        self.assertEqual(
            self.result.summary["fragment_stream_sha256"],
            "66f5d7c5222e5c8c1fb302bdecbe63731a99e7241c023d0ee273042b47e3a275",
        )
        self.assertEqual(
            self.result.summary["row_semantics_sha256"],
            "eb2f198f93fb8c0ec2b9a6aebfa0be82db608276031736fd57477dbd454432ac",
        )
        self.assertEqual(
            self.result.point_snapshot.identity["sha256"],
            "43eceeec2f4b9cda18bc96014bebbaed319e0e7a8a8c04a710a6950828826009",
        )
        self.assertFalse(self.result.summary["tree_pre_replayed"])
        self.assertFalse(self.result.summary["full_assignment_materialized"])

    def test_candidate_set_is_exact_immutable_and_binds_all_six_ports(self):
        decoded = gate.decode_tree_pre_candidates_insecure_test_only(
            self.candidates, expected_handoff_sha256=self.handoff_sha
        )
        self.assertEqual(len(decoded.values), 7_956)
        expected = {
            target + offset
            for tree_ports in gate.TREE_PRE_PORTS
            for _, _, target, width in tree_ports
            for offset in range(width)
        }
        self.assertEqual(set(decoded.values), expected)
        self.assertEqual(len(self.candidates.receipts), 3)
        self.assertEqual(decoded.handoff["verified_receipt_prefix_ordinals"], [0, 1, 2])
        self.assertTrue(decoded.handoff["all_declared_receipt_snapshots_raw_validated"])
        self.assertFalse(decoded.handoff["full_execution_receipt_chain_verified"])
        with self.assertRaises(FrozenInstanceError):
            self.candidates.handoff = self.candidates.handoff
        with self.assertRaises(gate.GlobalARestartError):
            replace(self.candidates, receipts=list(self.candidates.receipts))

    def test_each_receipt_prefix_ordinal_repin_still_rejects_semantic_mutation(self):
        for ordinal in range(3):
            changed, identities = self.repinned_receipt_candidate(
                ordinal,
                lambda document: document.__setitem__(
                    "stage_id", str(document["stage_id"]) + "-wrong"
                ),
            )
            with self.subTest(ordinal=ordinal), patch.object(
                gate.preflight_gate,
                "VERIFIED_RECEIPT_PREFIX_IDENTITIES",
                identities,
            ), self.assertRaises(gate.GlobalARestartError):
                gate.decode_tree_pre_candidates_insecure_test_only(
                    changed,
                    expected_handoff_sha256=gate.sha256(changed.handoff.raw),
                )

    def test_repinned_receipt_prefix_broken_link_rejects(self):
        changed, identities = self.repinned_receipt_candidate(
            2,
            lambda document: document.__setitem__(
                "previous_receipt_sha256", "0" * 64
            ),
        )
        with patch.object(
            gate.preflight_gate,
            "VERIFIED_RECEIPT_PREFIX_IDENTITIES",
            identities,
        ), self.assertRaises(gate.GlobalARestartError):
            gate.decode_tree_pre_candidates_insecure_test_only(
                changed,
                expected_handoff_sha256=gate.sha256(changed.handoff.raw),
            )

    def test_identity_version_domain_port_and_trailing_mutations_reject(self):
        with patch.object(
            io.Snapshot, "document", side_effect=AssertionError("parse")
        ), self.assertRaisesRegex(gate.GlobalARestartError, "before dependencies"):
            gate.decode_tree_pre_candidates_insecure_test_only(
                self.candidates, expected_handoff_sha256="0" * 64
            )

        for key, value in (
            ("format", gate.HANDOFF_FORMAT + "-WRONG"),
            ("relation_id", "pq-rbbc/wrong-domain/v1"),
            ("invocation_sha256", "1" * 64),
        ):
            handoff_document = self.candidates.handoff.document()
            handoff_document[key] = value
            changed_handoff = replace(
                self.candidates.handoff, raw=gate.canonical_json(handoff_document)
            )
            changed = replace(self.candidates, handoff=changed_handoff)
            with self.subTest(key=key), self.assertRaises(gate.GlobalARestartError):
                gate.decode_tree_pre_candidates_insecure_test_only(
                    changed,
                    expected_handoff_sha256=gate.sha256(changed_handoff.raw),
                )

        tree_document = self.candidates.tree_results[0].document()
        packed = tree_document["ports"][0]["packed_bits_hex"]
        tree_document["ports"][0]["packed_bits_hex"] = (
            ("1" if packed[0] == "0" else "0") + packed[1:]
        )
        changed_tree = replace(
            self.candidates.tree_results[0], raw=gate.canonical_json(tree_document)
        )
        handoff_document = self.candidates.handoff.document()
        handoff_document["tree_results"][0] = changed_tree.identity
        changed_handoff = replace(
            self.candidates.handoff, raw=gate.canonical_json(handoff_document)
        )
        changed = replace(
            self.candidates,
            handoff=changed_handoff,
            tree_results=(changed_tree, self.candidates.tree_results[1]),
        )
        with self.assertRaises(gate.GlobalARestartError):
            gate.decode_tree_pre_candidates_insecure_test_only(
                changed, expected_handoff_sha256=gate.sha256(changed_handoff.raw)
            )

        trailing = replace(
            self.candidates.handoff, raw=self.candidates.handoff.raw + b"\n"
        )
        with self.assertRaises((gate.GlobalARestartError, io.ValidationError)):
            gate.decode_tree_pre_candidates_insecure_test_only(
                replace(self.candidates, handoff=trailing),
                expected_handoff_sha256=gate.sha256(trailing.raw),
            )

    def test_fragment_receipt_closed_schema_version_domain_and_trailing(self):
        variants = []
        for key, value in (
            ("implementation_version", "2.0"),
            ("relation_id", "pq-rbbc/wrong-domain/v1"),
            ("production", True),
            ("full_execution_receipt_chain_verified", True),
        ):
            document = self.result.receipt.document()
            document[key] = value
            variants.append(gate.canonical_json(document))
        document = self.result.receipt.document()
        document["summary"]["unknown"] = True
        variants.append(gate.canonical_json(document))
        variants.append(self.result.receipt.raw + b"\n")
        for index, raw in enumerate(variants):
            changed = replace(self.result.receipt, raw=raw)
            with self.subTest(index=index), self.assertRaises(
                (gate.GlobalARestartError, io.ValidationError)
            ):
                gate._validate_fragment_receipt(
                    changed,
                    expected_identity=changed.identity,
                    candidates=self.candidates,
                    handoff_sha256=self.handoff_sha,
                )

    def test_independent_consumer_does_not_run_tree_pre_or_reopen_paths(self):
        with patch.object(
            handoff.HandoffSessionInsecureTestOnly,
            "run_to",
            side_effect=AssertionError("tree-pre replay"),
        ), patch.object(
            io, "read_snapshot", side_effect=AssertionError("pathname reopen")
        ):
            actual = gate.execute_global_a_insecure_test_only(
                self.candidates, expected_handoff_sha256=self.handoff_sha
            )
        self.assertEqual(actual.owned_values, self.result.owned_values)
        self.assertEqual(actual.receipt.raw, self.result.receipt.raw)

    def test_fresh_restart_and_repeat_are_byte_identical(self):
        reference = self.root / "reference"
        with patch.object(
            gate, "execute_global_a_insecure_test_only", return_value=self.result
        ):
            expected = gate.run_bounded_global_a(
                reference,
                artifact_root=self.root,
                fresh_candidates=self.candidates,
                expected_handoff_sha256=self.handoff_sha,
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

    def test_each_append_only_output_boundary_resumes(self):
        boundaries = ("result-payload", "points", "result-receipt", "result-checkpoint")
        for index, boundary in enumerate(boundaries):
            with self.subTest(boundary=boundary):
                self.output = self.root / f"boundary-{index}"
                self.fresh()
                with patch.object(
                    gate, "execute_global_a_insecure_test_only", return_value=self.result
                ):
                    self.resume(stop_after=boundary)
                    before = self.files()
                    completed = self.resume()
                self.assertEqual(completed.owned_values, self.result.owned_values)
                self.assertEqual(self.latest().location.name, gate.COMPLETE_NAME)
                for name, raw in before.items():
                    self.assertEqual((self.output / name).read_bytes(), raw)

    def test_real_new_process_resumes_without_live_candidate_set(self):
        self.fresh()
        checkpoint = self.latest()
        context = multiprocessing.get_context("fork")
        queue = context.Queue()
        process = context.Process(
            target=resume_worker,
            args=(
                str(self.output),
                str(self.root),
                checkpoint.identity["sha256"],
                queue,
            ),
        )
        process.start()
        process.join(60)
        if process.is_alive():
            process.kill()
            process.join()
            self.fail("Global-A restart child timed out")
        self.assertEqual(process.exitcode, 0)
        message = queue.get(timeout=2)
        self.assertEqual(message[0], "ok", message)
        self.assertEqual(self.latest().location.name, gate.COMPLETE_NAME)

    def test_wrong_stale_checkpoint_and_competing_output_fail_closed(self):
        self.fresh()
        checkpoint = self.latest()
        with patch.object(
            gate, "_load_candidates", side_effect=AssertionError("input read")
        ), patch.object(
            gate,
            "execute_global_a_insecure_test_only",
            side_effect=AssertionError("compute"),
        ):
            for digest in (None, "0" * 64, "A" * 64, 7):
                with self.subTest(digest=digest), self.assertRaises(
                    gate.GlobalARestartError
                ):
                    self.resume(expected_checkpoint_sha256=digest)
        competing = self.output / gate.RESULT_DIRECTORY / gate.PRIVATE_RESULT_NAME
        competing.write_bytes(b"competing-writer")
        before = self.files()
        with patch.object(
            gate, "execute_global_a_insecure_test_only", return_value=self.result
        ), self.assertRaises(gate.GlobalARestartError):
            self.resume(expected_checkpoint_sha256=checkpoint.identity["sha256"])
        self.assertEqual(before, self.files())

    def test_checkpoint_and_completed_result_mutations_refuse_without_overwrite(self):
        self.fresh()
        checkpoint_path = (
            self.output / gate.JOURNAL_DIRECTORY / gate.INPUTS_COMMITTED_NAME
        )
        raw = checkpoint_path.read_bytes() + b"\n"
        checkpoint_path.write_bytes(raw)
        before = self.files()
        with self.assertRaises((gate.GlobalARestartError, io.ValidationError)):
            self.resume(expected_checkpoint_sha256=gate.sha256(raw))
        self.assertEqual(before, self.files())

        self.output = self.root / "complete-mutation"
        complete = self.complete_cached()
        result_path = self.output / gate.RESULT_DIRECTORY / gate.PRIVATE_RESULT_NAME
        original = result_path.read_bytes()
        result_path.write_bytes(original[:-1] + b"X")
        with self.assertRaises((gate.GlobalARestartError, io.ValidationError)):
            gate.capture_completed_result(
                self.output,
                artifact_root=self.root,
                expected_complete_sha256=complete.complete_checkpoint.identity["sha256"],
            )
        self.assertEqual(result_path.read_bytes(), original[:-1] + b"X")

    def test_completed_capture_consumes_same_snapshot_after_path_changes(self):
        complete = self.complete_cached()
        original_read = disk.read
        reads = []

        def mutate_after_capture(path):
            snapshot = original_read(path)
            reads.append(path)
            if path.name == gate.PRIVATE_RESULT_NAME:
                path.write_bytes(b'{"changed":true}\n')
            return snapshot

        with patch.object(disk, "read", side_effect=mutate_after_capture):
            captured = gate.capture_completed_result(
                self.output,
                artifact_root=self.root,
                expected_complete_sha256=complete.complete_checkpoint.identity["sha256"],
            )
        self.assertEqual(captured.owned_values, self.result.owned_values)
        path = self.output / gate.RESULT_DIRECTORY / gate.PRIVATE_RESULT_NAME
        self.assertEqual(reads.count(path), 1)
        self.assertNotEqual(path.read_bytes(), captured.result.raw)

    def test_production_refuses_before_io_and_claims_stay_closed(self):
        forbidden = self.root / "must-not-exist"
        with patch.object(
            gate, "validate_prerequisites", side_effect=AssertionError("preflight")
        ), patch.object(
            disk, "locked_output", side_effect=AssertionError("output")
        ), self.assertRaises(gate.ProductionUnavailable):
            gate.execute_production(output=forbidden)
        self.assertFalse(forbidden.exists())
        report = gate.preflight()
        self.assertTrue(report["independent_global_a_consumer_implemented"])
        self.assertEqual(report["verified_receipt_prefix_ordinals"], [0, 1, 2])
        self.assertTrue(report["all_declared_receipt_snapshots_raw_validated"])
        self.assertTrue(report["receipt_prefix_links_verified"])
        self.assertEqual(report["scheduler_receipt_suffix_overlap_ordinal"], 2)
        self.assertFalse(report["full_execution_receipt_chain_verified"])
        self.assertFalse(report["global_b_consumer_implemented"])
        self.assertFalse(report["global_b_same_invocation_candidate_set_implemented"])
        self.assertFalse(report["global_tail_continuation_implemented"])
        self.assertFalse(report["safe_to_start_large_replay"])
        self.assertFalse(report["Proof-closed"])
        self.assertFalse(report["Production-closed"])
        self.assertEqual(len(report["missing_production_artifacts"]), 5)

    def test_historical_v238_v239_identities_unchanged(self):
        self.assertEqual(len(historical.HISTORICAL_IDENTITIES), 19)
        for relative, expected in historical.HISTORICAL_IDENTITIES.items():
            raw = (gate.ROOT / relative).read_bytes()
            self.assertEqual(len(raw), expected["bytes"], relative)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), expected["sha256"], relative)

    def test_manifest_and_portable_evidence_are_exact_and_private_free(self):
        evidence = gate.bounded_self_check()
        with patch.object(gate, "bounded_self_check", return_value=evidence):
            for relative, document in (
                (gate.MANIFEST_PATH, gate.build_manifest()),
                (gate.EVIDENCE_PATH, gate.build_portable_evidence()),
            ):
                raw = (gate.ROOT / relative).read_bytes()
                self.assertEqual(raw, gate.canonical_json(document))
                io.strict_json(raw)
                self.assertNotIn(str(gate.ROOT).encode(), raw)
                self.assertNotIn(self.candidates.tree_results[0].raw, raw)
                self.assertNotIn(self.result.owned_values[0].to_bytes(25, "little"), raw)
        manifest = gate.build_manifest()
        self.assertEqual(manifest["implementation_version"], "1.1")
        self.assertEqual(
            manifest["publication_contract"]["verified_receipt_prefix_ordinals"],
            [0, 1, 2],
        )
        self.assertTrue(
            manifest["publication_contract"][
                "all_declared_receipt_snapshots_raw_validated"
            ]
        )
        self.assertFalse(
            manifest["claim_status"]["full_execution_receipt_chain_verified"]
        )
        self.assertFalse(
            manifest["claim_status"][
                "global_b_same_invocation_candidate_set_implemented"
            ]
        )


if __name__ == "__main__":
    unittest.main()
