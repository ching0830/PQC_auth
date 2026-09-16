from copy import deepcopy
from dataclasses import replace
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import pq_rbbc_issuance_bounded_multitree_adapter_v1 as gate
import pq_rbbc_issuance_bounded_multitree_native_v1 as native
import pq_rbbc_launch_io_v2_41 as io


class BoundedMultitreeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.session = gate.BoundedSessionInsecureTestOnly()
        cls.session.run_to()
        cls.reference = cls.session.reference
        cls.evidence = cls.session.evidence()

    @classmethod
    def tearDownClass(cls):
        cls.session.close()

    def snapshot(self, document):
        return io.Snapshot(Path("/in-memory-insecure-test-only/test.json"), gate.canonical_json(document))

    def test_frozen_rows_wires_and_three_independent_streams(self):
        for key, expected in gate.FROZEN.items():
            self.assertEqual(self.evidence[key], expected)
        self.assertEqual(self.evidence["stage_rows"], [12970, 54070, 54070, 19671, 4734, 4734, 35494, 0, 0])
        self.assertEqual(self.evidence["native_streams"]["tail"]["stream_sha256"],
                         "3cc4120442e28ee903f3f251c6727ad97bfdbcf5adcf10d157ab5dfb818b3fa2")
        self.assertEqual(self.evidence["native_streams"]["tree[0]"]["stream_sha256"],
                         "e46733ff6019346257cff533bd85a367535c47008db6fc7997032bbfec8bb440")
        self.assertEqual(self.evidence["native_streams"]["tree[1]"]["stream_sha256"],
                         "cdf7d394e3cf36e286f54350c34d8241912839adfd5b1e18d82e94ec3c1bf32a")
        self.assertEqual(self.evidence["verification_failures"], 0)

    def test_multitree_corrections_are_nonzero_and_native_bound(self):
        material = gate.tail.derive_tail_material(gate.PARAMETERS, self.reference.execution,
                                                self.reference.invocation.ticket_message)
        commitment = self.reference.execution.commitment
        self.assertNotEqual(commitment.delta_p[0], 0)
        self.assertNotEqual(commitment.delta_mhat[0], 0)
        self.assertEqual(commitment.delta_p[0], material.p_plain[0] ^ material.p_plain[1])
        self.assertEqual(commitment.delta_mhat[0], material.mhat_plain[0] ^ material.mhat_plain[1])
        for suffix in ("p-plain", "mhat-plain"):
            port = next(p for p in self.reference.tail_summary.ports if p.port_id == "tree[1]." + suffix)
            row = next(r for r in self.session.correction_rows if any(
                w == port.consumer_wire_start for w, _ in r.left.terms + r.right.terms + r.output.terms))
            stale = dict(self.session.values)
            stale[port.consumer_wire_start] ^= 1
            self.assertFalse(gate.shard._row_satisfied_fast(row, stale))

    def test_every_relocation_and_salt_root_message_binding_rejects_stale_bits(self):
        self.assertEqual(len(self.session.relocation_ports), 8)
        prefixes = ["binding.tail.salt", "binding.tail.message", "binding.tree[0].salt",
                    "binding.tree[0].roots", "binding.tree[1].salt", "binding.tree[1].roots"]
        prefixes += ["relocation." + name for name in self.session.relocation_ports]
        for prefix in prefixes:
            with self.subTest(prefix=prefix):
                row = next(r for r in self.session.binding_rows if r.label == prefix + "[0]")
                stale = dict(self.session.values)
                stale[row.left.terms[0][0]] ^= 1
                self.assertFalse(gate.shard._row_satisfied_fast(row, stale))
        with self.assertRaises(TypeError):
            self.session.values[1] = 0

    def test_binding_digest_commits_equations_not_only_counts(self):
        def fingerprint(rows):
            h = hashlib.sha256(gate.DOMAIN + b"NATIVE-BINDING-ROWS")
            for row in rows:
                for raw in (row.label.encode(), gate.tail._encode_form(row.left),
                            gate.tail._encode_form(row.right), gate.tail._encode_form(row.output)):
                    h.update(len(raw).to_bytes(8, "little"))
                    h.update(raw)
            return h.hexdigest()
        self.assertEqual(fingerprint(self.session.binding_rows), self.evidence["native_binding_rows_sha256"])
        changed = list(self.session.binding_rows)
        changed[0] = replace(changed[0], left=changed[0].left.add(gate.field.LinearForm.wire(2)))
        self.assertNotEqual(fingerprint(changed), self.evidence["native_binding_rows_sha256"])

    def test_per_owner_cursor_rejects_other_owner_reorder_and_overflow(self):
        plan = self.reference.plan
        allocator = gate.PerOwnerAllocator(plan)
        tree0 = plan["trees"][0]
        allocator.allocate("tree[0]", tree0["pre"][0], tree0["pre"][1] - tree0["pre"][0])
        with self.assertRaises(gate.AdapterError):
            allocator.allocate("tree[0]", plan["global_a"][1], 1)
        with self.assertRaises(gate.AdapterError):
            allocator.allocate("tree[1]", tree0["pre"][1], 1)
        with self.assertRaises(gate.AdapterError):
            allocator.allocate("tree[0]", tree0["pre"][1], gate.MAX_WIRES)
        with self.assertRaises(gate.AdapterError):
            allocator.allocate("tree[0]", tree0["pre"][1], True)
        allocator.allocate("tree[0]", tree0["post"][0], tree0["post"][1] - tree0["post"][0])
        for field in ("pre", "post"):
            changed = deepcopy(plan)
            changed["trees"][1][field][0 if field == "pre" else 1] += 1
            with self.assertRaises(gate.AdapterError):
                gate.PerOwnerAllocator(changed)

    def test_point_raw_identity_parse_binding_and_wrong_domain(self):
        original = self.session.point_snapshot
        starts, values = self.session.validate_point_snapshot(original)
        self.assertEqual(list(starts), self.reference.plan["point_starts"])
        self.assertEqual(starts[1] - starts[0], 193)
        self.assertTrue(all(0 < v < 1 << 193 for v in values))
        for key, value in (("format", "wrong-version"), ("relation_id", "wrong-domain"),
                           ("invocation_sha256", "0" * 64), ("plan_sha256", "0" * 64),
                           ("wire_starts", list(reversed(starts))), ("field_bits", True),
                           ("values", [values[0] ^ 1, values[1]])):
            with self.subTest(key=key):
                doc = original.document()
                doc[key] = value
                with self.assertRaises(gate.AdapterError):
                    self.session.validate_point_snapshot(self.snapshot(doc))
        with self.assertRaises(io.ValidationError):
            self.session.validate_point_snapshot(replace(original, raw=original.raw + b"\n"))
        with patch.object(io, "read_snapshot", side_effect=AssertionError("path reopen")):
            self.session.validate_point_snapshot(original)

    def test_receipt_positive_version_statement_domain_trailing_and_replay(self):
        original = io.Snapshot(Path("/in-memory-insecure-test-only/receipt.json"), self.session.receipts[3])
        self.assertEqual(self.session.validate_receipt(original, 3)["stage_id"], "global-a")
        for key, value in (("format", "v2"), ("relation_id", "another-domain"),
                           ("invocation_sha256", "f" * 64), ("ordinal", True),
                           ("previous_receipt_sha256", "0" * 64), ("production", True)):
            doc = original.document()
            doc[key] = value
            with self.subTest(key=key), self.assertRaises(gate.AdapterError):
                self.session.validate_receipt(self.snapshot(doc), 3)
        with self.assertRaises(io.ValidationError):
            self.session.validate_receipt(replace(original, raw=original.raw + b"\x00"), 3)
        with self.assertRaises(gate.AdapterError):
            self.session.step("final-seal", expected_previous_receipt_sha256=None)

    def test_in_process_pause_preserves_pre_cursors_and_rejects_before_recompute(self):
        session = gate.BoundedSessionInsecureTestOnly()
        try:
            session.run_to("global-a")
            cursors = dict(session.allocator.cursors)
            rows = session.rows
            expected = hashlib.sha256(session.receipts[-1]).hexdigest()
            with patch.object(session, "_advance", side_effect=AssertionError("must not recompute")):
                with self.assertRaises(gate.AdapterError):
                    session.step("tree-post[0]", expected_previous_receipt_sha256="0" * 64)
                with self.assertRaises(gate.AdapterError):
                    session.step("tree-post[1]", expected_previous_receipt_sha256=expected)
                mutated = session.point_snapshot.document()
                mutated["wire_starts"] = [1, 194]
                with self.assertRaises(gate.AdapterError):
                    session.step("tree-post[0]", expected_previous_receipt_sha256=expected,
                                 point_snapshot=self.snapshot(mutated))
            self.assertEqual(rows, session.rows)
            self.assertEqual(cursors, session.allocator.cursors)
            session.run_to()
            self.assertEqual(session.evidence(), self.evidence)
        finally:
            session.close()

    def test_unallocated_and_global_point_imports_rejected_in_pre(self):
        session = gate.BoundedSessionInsecureTestOnly()
        try:
            session.run_to("bind-inputs")
            sink = session.sinks["tail"]
            # Both a future global point and another owner's allocated anchor
            # are forbidden unless explicitly declared as a stage import.
            for wire in (self.reference.plan["point_starts"][0], session.anchors["salt"]):
                form = gate.field.LinearForm.wire(wire)
                with self.assertRaises(gate.AdapterError):
                    sink.row("forbidden", form, gate.field.LinearForm.const(0),
                             gate.field.LinearForm.const(0), nonlinear=False)
        finally:
            session.close()

    def test_variant_changes_invocation_and_outputs_but_not_topology(self):
        other = gate.build_reference_insecure_test_only(1)
        self.assertEqual(other.plan_raw, self.reference.plan_raw)
        self.assertNotEqual(other.invocation_digest, self.reference.invocation_digest)
        self.assertNotEqual(other.execution.commitment.encoded, self.reference.execution.commitment.encoded)
        self.assertEqual([s.stream_sha256 for s in other.trees], [s.stream_sha256 for s in self.reference.trees])
        for invalid in (True, -1, 2, "0"):
            with self.assertRaises(gate.AdapterError):
                gate.build_reference_insecure_test_only(invalid)

    def test_all_production_entries_refuse_before_fixture_or_output(self):
        with TemporaryDirectory() as temp:
            output = Path(temp) / "must-not-exist"
            with patch.object(gate, "build_reference_insecure_test_only", side_effect=AssertionError("fixture")), \
                    patch.object(Path, "mkdir", side_effect=AssertionError("mkdir")):
                with self.assertRaises(gate.ProductionUnavailable):
                    gate.execute_production(object(), output=output)
            self.assertFalse(output.exists())
        for function, args in ((native._iter_tail_native_insecure_test_only, ()),
                               (native._iter_tree_native_insecure_test_only, (0,))):
            gen = function(gate.cap.PRODUCTION_PARAMETERS, None, None, *args,
                           sink_factory=lambda *a, **k: self.fail("sink opened"))
            with self.assertRaises(ValueError):
                next(gen)

    def test_budget_and_failure_close_session(self):
        session = gate.BoundedSessionInsecureTestOnly()
        try:
            with patch.object(gate, "MAX_ROWS", 1):
                with self.assertRaises(gate.AdapterError):
                    session.step("bind-inputs", expected_previous_receipt_sha256=None)
            self.assertTrue(session.failed)
            self.assertTrue(session.closed)
            self.assertEqual(session.receipts, [])
        finally:
            session.close()

    def test_manifest_evidence_exact_and_conservative(self):
        # Reuse this independently completed run; production is never permitted.
        with patch.object(gate, "bounded_self_check", return_value=self.evidence):
            for path, value in ((gate.MANIFEST_PATH, gate.build_manifest()),
                                (gate.EVIDENCE_PATH, gate.build_portable_evidence())):
                raw = (gate.ROOT / path).read_bytes()
                self.assertEqual(raw, gate.canonical_json(value))
                self.assertNotIn(str(gate.ROOT).encode(), raw)
                io.strict_json(raw)
        self.assertFalse(self.evidence["formal_I1_I5_replayed"])
        self.assertFalse(self.evidence["durable_resume_implemented"])
        self.assertFalse(self.evidence["production_mixed_degree_12_13_qualified"])
        self.assertFalse(self.evidence["Production-closed"])


if __name__ == "__main__":
    unittest.main()
