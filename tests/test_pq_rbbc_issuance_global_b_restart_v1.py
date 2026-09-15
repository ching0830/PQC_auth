from dataclasses import replace
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import pq_rbbc_cap_unified_tree_launch_validation_v2_41 as historical
import pq_rbbc_issuance_bounded_multitree_adapter_v1 as base
import pq_rbbc_issuance_global_b_restart_v1 as gate
import pq_rbbc_launch_io_v2_41 as io


class GlobalBRestartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.session, cls.fixture_temporary, cls.candidate = (
            gate._fixture_candidate_insecure_test_only()
        )
        cls.handoff_sha256 = cls.candidate.handoff.identity["sha256"]
        cls.computed = gate.execute_global_b_insecure_test_only(
            cls.candidate, expected_handoff_sha256=cls.handoff_sha256
        )

    @classmethod
    def tearDownClass(cls):
        cls.session.close()
        cls.fixture_temporary.cleanup()

    def setUp(self):
        self.temporary = TemporaryDirectory(prefix="pq-rbbc-global-b-restart-test-")
        self.root = Path(self.temporary.name)
        self.output = self.root / "global-b"

    def tearDown(self):
        self.temporary.cleanup()

    def fresh(self, *, stop_after=None):
        return gate.run_bounded_global_b(
            self.output,
            artifact_root=self.root,
            fresh_candidate=self.candidate,
            expected_handoff_sha256=self.handoff_sha256,
            fresh_output=True,
            stop_after=stop_after,
        )

    def test_independent_consumer_executes_exact_row_contract(self):
        result = self.computed
        self.assertEqual(result.summary["relocation_rowsets"], 8)
        self.assertEqual(result.summary["relocation_rows"], 7_826)
        self.assertEqual(result.summary["phase_b_rows"], 35_494)
        self.assertEqual(result.summary["total_rows_checked"], 43_320)
        self.assertEqual(result.summary["allocated_wires"], 20_743)
        self.assertTrue(result.summary["all_rows_satisfied"])
        self.assertFalse(result.summary["candidate_pathname_reopened"])
        self.assertFalse(result.summary["full_execution_receipt_chain_verified"])

    def test_outputs_equal_unchanged_monolithic_reference(self):
        reference = base.build_reference_insecure_test_only(0)
        self.assertEqual(self.computed.commitment, reference.execution.commitment.encoded)
        self.assertEqual(self.computed.request_hash, reference.tail_summary.request_hash_bytes)
        self.assertEqual(self.computed.summary["commitment_sha256"], gate.FROZEN["commitment_sha256"])
        self.assertEqual(self.computed.summary["request_hash_sha256"], gate.FROZEN["request_hash_sha256"])

    def test_consumer_uses_captured_raws_without_pathname_reopen_or_reference_rebuild(self):
        with patch.object(gate.disk, "read", side_effect=AssertionError("pathname reopened")), \
                patch.object(base, "build_reference_insecure_test_only", side_effect=AssertionError("reference rebuilt")):
            result = gate.execute_global_b_insecure_test_only(
                self.candidate, expected_handoff_sha256=self.handoff_sha256
            )
        self.assertEqual(result.owned_values, self.computed.owned_values)

    def test_wrong_handoff_rejects_before_row_emission(self):
        with patch.object(gate, "_GlobalBSink", side_effect=AssertionError("rows emitted")), \
                self.assertRaises(Exception):
            gate.execute_global_b_insecure_test_only(
                self.candidate, expected_handoff_sha256="0" * 64
            )

    def test_native_equality_rejects_source_repin(self):
        original = gate._source_values

        def changed(candidate, decoded):
            values = original(candidate, decoded)
            values[gate.SOURCE_STARTS[0]] ^= 1
            return values

        with patch.object(gate, "_source_values", side_effect=changed), \
                self.assertRaisesRegex(gate.GlobalBRestartError, "native row failed"):
            gate.execute_global_b_insecure_test_only(
                self.candidate, expected_handoff_sha256=self.handoff_sha256
            )

    def test_native_equality_rejects_target_repin_after_validation(self):
        decoded = gate.candidateset.validate_candidate_set_insecure_test_only(
            self.candidate, expected_handoff_sha256=self.handoff_sha256
        )
        targets = dict(decoded.target_values)
        targets[gate.candidateset.RELOCATION_SPECS[7][1]] ^= 1
        changed = replace(decoded, target_values=targets)
        with patch.object(
            gate.candidateset,
            "validate_candidate_set_insecure_test_only",
            return_value=changed,
        ), self.assertRaisesRegex(gate.GlobalBRestartError, "native row failed"):
            gate.execute_global_b_insecure_test_only(
                self.candidate, expected_handoff_sha256=self.handoff_sha256
            )

    def test_invalid_candidate_fails_before_output_creation(self):
        bad_shared = replace(self.candidate.shared_inputs, raw=b"{}\n")
        bad = replace(self.candidate, shared_inputs=bad_shared)
        with self.assertRaises(Exception):
            gate.run_bounded_global_b(
                self.output,
                artifact_root=self.root,
                fresh_candidate=bad,
                expected_handoff_sha256=self.handoff_sha256,
                fresh_output=True,
            )
        self.assertFalse(self.output.exists())

    def test_wrong_external_digest_fails_before_output_creation(self):
        with self.assertRaises(Exception):
            gate.run_bounded_global_b(
                self.output,
                artifact_root=self.root,
                fresh_candidate=self.candidate,
                expected_handoff_sha256="0" * 64,
                fresh_output=True,
            )
        self.assertFalse(self.output.exists())

    def test_fresh_restart_completed_capture_and_repeated_resume(self):
        self.assertIsNone(self.fresh(stop_after="inputs"))
        checkpoint = gate.latest_checkpoint(self.output, artifact_root=self.root)
        self.assertEqual(checkpoint.location.name, gate.INPUTS_COMMITTED_NAME)
        first = gate.run_bounded_global_b(
            self.output,
            artifact_root=self.root,
            resume=True,
            expected_checkpoint_sha256=checkpoint.identity["sha256"],
        )
        captured = gate.capture_completed_result(
            self.output,
            artifact_root=self.root,
            expected_complete_sha256=first.complete_checkpoint.identity["sha256"],
        )
        repeated = gate.run_bounded_global_b(
            self.output,
            artifact_root=self.root,
            resume=True,
            expected_checkpoint_sha256=first.complete_checkpoint.identity["sha256"],
        )
        self.assertEqual(captured.owned_values, self.computed.owned_values)
        self.assertEqual(first.result.raw, repeated.result.raw)
        self.assertEqual(first.receipt.raw, repeated.receipt.raw)
        self.assertEqual(first.complete_checkpoint.raw, repeated.complete_checkpoint.raw)

    def test_exact_result_orphan_is_adopted(self):
        self.assertIsNone(self.fresh(stop_after="result-payload"))
        checkpoint = gate.latest_checkpoint(self.output, artifact_root=self.root)
        self.assertEqual(checkpoint.location.name, gate.INPUTS_COMMITTED_NAME)
        completed = gate.run_bounded_global_b(
            self.output,
            artifact_root=self.root,
            resume=True,
            expected_checkpoint_sha256=checkpoint.identity["sha256"],
        )
        self.assertEqual(completed.result.identity, gate.FROZEN["private_result_identity"])

    def test_mutated_result_orphan_fails_closed(self):
        self.assertIsNone(self.fresh(stop_after="result-payload"))
        result_path = self.output / gate.RESULT_DIRECTORY / gate.PRIVATE_RESULT_NAME
        raw = result_path.read_bytes()
        result_path.write_bytes(raw[:-2] + b"0\n")
        checkpoint = gate.latest_checkpoint(self.output, artifact_root=self.root)
        with self.assertRaises(gate.GlobalBRestartError):
            gate.run_bounded_global_b(
                self.output,
                artifact_root=self.root,
                resume=True,
                expected_checkpoint_sha256=checkpoint.identity["sha256"],
            )
        self.assertNotIn(gate.RESULT_COMMITTED_NAME, {
            path.name for path in (self.output / gate.JOURNAL_DIRECTORY).iterdir()
        })

    def test_mutated_published_input_rejects_before_compute(self):
        self.assertIsNone(self.fresh(stop_after="inputs"))
        plan = gate.disk.read(self.output / gate.JOURNAL_DIRECTORY / gate.PLAN_NAME).document()
        name = plan["input_inventory"][0]["storage_filename"]
        path = self.output / gate.INPUT_DIRECTORY / name
        path.write_bytes(path.read_bytes() + b" ")
        checkpoint = gate.latest_checkpoint(self.output, artifact_root=self.root)
        with patch.object(
            gate, "execute_global_b_insecure_test_only", side_effect=AssertionError("computed")
        ), self.assertRaises(gate.GlobalBRestartError):
            gate.run_bounded_global_b(
                self.output,
                artifact_root=self.root,
                resume=True,
                expected_checkpoint_sha256=checkpoint.identity["sha256"],
            )

    def test_stale_restart_digest_rejects(self):
        self.assertIsNone(self.fresh(stop_after="inputs"))
        with self.assertRaises(gate.GlobalBRestartError):
            gate.run_bounded_global_b(
                self.output,
                artifact_root=self.root,
                resume=True,
                expected_checkpoint_sha256="0" * 64,
            )

    def test_receipt_mutation_and_trailing_bytes_reject(self):
        receipt = self.computed.receipt
        document = receipt.document()
        document["summary"]["phase_b_rows"] += 1
        mutated = io.Snapshot(receipt.location, gate.canonical_json(document))
        with self.assertRaises(gate.GlobalBRestartError):
            gate._validate_fragment_receipt(
                mutated,
                expected_identity=mutated.identity,
                handoff_sha256=self.handoff_sha256,
            )
        trailing = replace(receipt, raw=receipt.raw + b" ")
        with self.assertRaises(gate.GlobalBRestartError):
            gate._validate_fragment_receipt(
                trailing,
                expected_identity=trailing.identity,
                handoff_sha256=self.handoff_sha256,
            )

    def test_boolean_output_port_rejects(self):
        private, receipt = gate._expected_result_snapshots(
            self.computed, self.handoff_sha256
        )
        receipt_document = gate._validate_fragment_receipt(
            receipt,
            expected_identity=receipt.identity,
            handoff_sha256=self.handoff_sha256,
        )
        document = private.document()
        document["output_ports"]["commitment"][0] = True
        mutated = io.Snapshot(private.location, gate.canonical_json(document))
        with self.assertRaises(gate.GlobalBRestartError):
            gate._validate_private_result(
                mutated,
                expected_identity=mutated.identity,
                receipt_snapshot=receipt,
                receipt_document=receipt_document,
                handoff_sha256=self.handoff_sha256,
            )

    def test_boolean_plan_and_checkpoint_ordinals_reject(self):
        plan_document = gate._plan_document(
            self.candidate, expected_handoff_sha256=self.handoff_sha256
        )
        plan_document["input_inventory"][0]["ordinal"] = False
        plan = gate._snapshot(
            gate.PLAN_NAME, gate.canonical_json(plan_document), gate.CHECKPOINT_LIMIT
        )
        with self.assertRaises(gate.GlobalBRestartError):
            gate._validate_plan(plan)

        good_plan_document = gate._plan_document(
            self.candidate, expected_handoff_sha256=self.handoff_sha256
        )
        good_plan = gate._snapshot(
            gate.PLAN_NAME,
            gate.canonical_json(good_plan_document),
            gate.CHECKPOINT_LIMIT,
        )
        expected = gate._checkpoint_document(
            "inputs-committed",
            1,
            good_plan,
            good_plan,
            input_inventory=good_plan_document["input_inventory"],
            output_identities=(),
            complete=False,
        )
        mutated = dict(expected)
        mutated["ordinal"] = True
        checkpoint = gate._snapshot(
            gate.INPUTS_COMMITTED_NAME,
            gate.canonical_json(mutated),
            gate.CHECKPOINT_LIMIT,
        )
        with self.assertRaises(gate.GlobalBRestartError):
            gate._require_checkpoint(checkpoint, expected, gate.INPUTS_COMMITTED_NAME)

    def test_production_refuses_before_io_and_claims_stay_closed(self):
        with patch.object(
            gate.disk, "locked_output", side_effect=AssertionError("production I/O")
        ), self.assertRaises(gate.ProductionUnavailable):
            gate.execute_production(output=self.output)
        self.assertFalse(self.output.exists())
        report = gate.preflight()
        self.assertTrue(report["independent_global_b_consumer_implemented"])
        self.assertTrue(report["private_append_only_publication_implemented"])
        self.assertEqual(report["global_b_constraints_replayed"], 35_494)
        self.assertFalse(report["full_execution_receipt_chain_verified"])
        self.assertFalse(report["safe_to_start_large_replay"])
        self.assertFalse(report["Proof-closed"])
        self.assertFalse(report["Production-closed"])

    def test_historical_v238_v239_identities_unchanged(self):
        self.assertEqual(len(historical.HISTORICAL_IDENTITIES), 19)
        for relative, expected in historical.HISTORICAL_IDENTITIES.items():
            raw = (gate.ROOT / relative).read_bytes()
            self.assertEqual(len(raw), expected["bytes"], relative)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), expected["sha256"], relative)

    def test_manifest_and_portable_evidence_are_exact_and_private_free(self):
        manifest = gate.build_manifest()
        evidence = gate.build_portable_evidence()
        for relative, document in (
            (gate.MANIFEST_PATH, manifest),
            (gate.EVIDENCE_PATH, evidence),
        ):
            raw = (gate.ROOT / relative).read_bytes()
            self.assertEqual(raw, gate.canonical_json(document))
            io.strict_json(raw)
            self.assertNotIn(str(gate.ROOT).encode(), raw)
            self.assertNotIn(b"owned_values_hex", raw)
            self.assertNotIn(b"commitment_hex", raw)
        self.assertFalse(evidence["private_snapshot_raws_embedded"])
        self.assertFalse(evidence["private_assignment_embedded"])


if __name__ == "__main__":
    unittest.main()
