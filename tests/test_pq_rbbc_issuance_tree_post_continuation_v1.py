from dataclasses import FrozenInstanceError, replace
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import pq_rbbc_cap_unified_tree_launch_validation_v2_41 as historical
import pq_rbbc_issuance_private_spool_codec_v1 as codec
import pq_rbbc_issuance_private_spool_handoff_v1 as predecessor
import pq_rbbc_issuance_tree_post_continuation_v1 as gate
import pq_rbbc_launch_io_v2_41 as io


class TreePostContinuationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.session = predecessor.HandoffSessionInsecureTestOnly()
        cls.session.run_to("global-a")
        cls.candidates = cls.session.export_candidates()
        cls.handoff_sha = gate.sha256(cls.candidates.handoff.raw)
        cls.session.accept_handoff(
            cls.candidates, expected_handoff_sha256=cls.handoff_sha
        )
        cls.receipt_suffix = gate.build_verified_receipt_suffix_snapshots(cls.session)
        cls.continuations = gate.build_continuation_snapshots(cls.session)
        cls.results = tuple(
            gate.execute_tree_post_insecure_test_only(
                gate.TreePostInvocationInsecureTestOnly(
                    cls.candidates, continuation, cls.receipt_suffix
                ),
                expected_handoff_sha256=cls.handoff_sha,
                expected_continuation_sha256=gate.sha256(continuation.raw),
            )
            for continuation in cls.continuations
        )

    @classmethod
    def tearDownClass(cls):
        cls.session.close()

    def invocation(self, index=0, *, candidates=None, continuation=None):
        return gate.TreePostInvocationInsecureTestOnly(
            self.candidates if candidates is None else candidates,
            self.continuations[index] if continuation is None else continuation,
            self.receipt_suffix,
        )

    def execute(self, index=0, *, invocation=None, continuation_sha=None):
        return gate.execute_tree_post_insecure_test_only(
            self.invocation(index) if invocation is None else invocation,
            expected_handoff_sha256=self.handoff_sha,
            expected_continuation_sha256=(
                gate.sha256(self.continuations[index].raw)
                if continuation_sha is None
                else continuation_sha
            ),
        )

    def rebound_receipt_invocation(self, index, ordinal_2_raw, ordinal_3_raw):
        ordinal_2 = (
            self.receipt_suffix[0]
            if ordinal_2_raw == self.receipt_suffix[0].raw
            else replace(self.receipt_suffix[0], raw=ordinal_2_raw)
        )
        ordinal_3 = (
            self.receipt_suffix[1]
            if ordinal_3_raw == self.receipt_suffix[1].raw
            else replace(self.receipt_suffix[1], raw=ordinal_3_raw)
        )
        candidates = self.candidates
        if ordinal_3.raw != candidates.receipt.raw:
            handoff_document = candidates.handoff.document()
            handoff_document["receipt"] = ordinal_3.identity
            changed_handoff = replace(
                candidates.handoff, raw=gate.canonical_json(handoff_document)
            )
            candidates = replace(
                candidates, handoff=changed_handoff, receipt=ordinal_3
            )
        continuation_document = self.continuations[index].document()
        continuation_document["dependencies"]["handoff"] = candidates.handoff.identity
        continuation_document["dependencies"]["ordinal_2_receipt"] = ordinal_2.identity
        continuation_document["dependencies"]["global_a_receipt"] = ordinal_3.identity
        continuation_document["verified_receipt_suffix"] = [
            ordinal_2.identity,
            ordinal_3.identity,
        ]
        changed_continuation = replace(
            self.continuations[index],
            raw=gate.canonical_json(continuation_document),
        )
        return (
            gate.TreePostInvocationInsecureTestOnly(
                candidates, changed_continuation, (ordinal_2, ordinal_3)
            ),
            gate.sha256(candidates.handoff.raw),
            gate.sha256(changed_continuation.raw),
        )

    def write_invocation(self, root):
        for snapshot in (
            self.candidates.handoff,
            *self.candidates.spools,
            self.candidates.points,
            *self.receipt_suffix,
            *self.continuations,
        ):
            (root / snapshot.location.name).write_bytes(snapshot.raw)

    def test_frozen_bounded_evidence_and_exact_output_contract(self):
        evidence = gate.bounded_self_check()
        for key, expected in gate.FROZEN.items():
            self.assertEqual(evidence[key], expected)
        self.assertTrue(
            evidence["standalone_matches_live_native_groups_outputs_and_assignment"]
        )
        self.assertFalse(evidence["tree_pre_replayed_by_standalone_consumer"])
        self.assertFalse(evidence["legacy_stream_hash_state_restored"])
        self.assertFalse(evidence["full_session_restore_implemented"])
        self.assertFalse(evidence["durable_resume_implemented"])
        self.assertFalse(evidence["Production-closed"])
        for index, result in enumerate(self.results):
            contract = gate.TREE_CONTRACTS[index]
            self.assertEqual(result.summary["rows"], 3_576)
            self.assertEqual(result.summary["allocated_wires"], 2_412)
            self.assertEqual(result.summary["referenced_import_wires"], 10_122)
            self.assertEqual(
                (result.output_port.wire_start, result.output_port.bit_length),
                contract["output"],
            )
            self.assertEqual(len(result.owned_values), 2_412)
            self.assertFalse(result.summary["full_assignment_materialized"])
            self.assertFalse(result.summary["assignment_published"])

    def test_continuation_inventory_is_explicit_and_not_a_hash_state(self):
        for index, continuation in enumerate(self.continuations):
            document = continuation.document()
            self.assertEqual(document["tree_index"], index)
            self.assertEqual(document["owner_cursor"], gate.TREE_CONTRACTS[index]["pre"][1])
            self.assertEqual(
                document["state_inventory"],
                {
                    "serialized": list(gate.SERIALIZED_STATE),
                    "not_serialized": list(gate.NOT_SERIALIZED_STATE),
                },
            )
            self.assertTrue(
                document["composition_boundary"][
                    "prefix_digest_is_commitment_not_restorable_hash_state"
                ]
            )
            self.assertFalse(
                document["composition_boundary"]["legacy_stream_hash_continuation_supported"]
            )
            self.assertFalse(document["composition_boundary"]["tree_pre_replay_permitted"])
            self.assertEqual(document["verified_receipt_suffix"], [
                snapshot.identity for snapshot in self.receipt_suffix
            ])
            self.assertNotIn("receipt_chain_sha256", document)
            self.assertFalse(document["private_values_embedded"])
            self.assertNotIn(self.candidates.spools[index].raw, continuation.raw)

    def test_standalone_consumer_does_not_use_live_session_reopen_or_tree_pre(self):
        with patch.object(
            predecessor,
            "HandoffSessionInsecureTestOnly",
            side_effect=AssertionError("live session"),
        ), patch.object(
            predecessor.native,
            "_iter_tree_spool_native_insecure_test_only",
            side_effect=AssertionError("tree-pre generator"),
        ), patch.object(
            predecessor.base.cap,
            "execute_cap_commit",
            side_effect=AssertionError("CAP reconstruction"),
        ), patch.object(io, "read_snapshot", side_effect=AssertionError("pathname reopen")):
            result = self.execute(0)
        self.assertEqual(result.receipt.raw, self.results[0].receipt.raw)

    def test_fixed_name_single_capture_then_pathname_change_cannot_replace_raw(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_invocation(root)
            continuation_sha = gate.sha256(self.continuations[0].raw)
            with patch.object(io, "read_snapshot", wraps=io.read_snapshot) as read:
                invocation = gate.capture_tree_post_invocation(
                    root,
                    0,
                    expected_handoff_sha256=self.handoff_sha,
                    expected_continuation_sha256=continuation_sha,
                )
            self.assertEqual(
                [call.args[0].name for call in read.call_args_list],
                [
                    gate.CONTINUATION_NAMES[0],
                    predecessor.HANDOFF_NAME,
                    *predecessor.SPOOL_NAMES,
                    predecessor.POINT_NAME,
                    predecessor.RECEIPT_NAME,
                    gate.PRIOR_RECEIPT_NAME,
                ],
            )
            path = root / predecessor.SPOOL_NAMES[0]
            changed = bytearray(path.read_bytes())
            changed[codec.BODY_OFFSET + codec.WIRE_RECORD.size] ^= 1
            path.write_bytes(bytes(changed))
            with patch.object(io, "read_snapshot", side_effect=AssertionError("reopen")):
                result = gate.execute_tree_post_insecure_test_only(
                    invocation,
                    expected_handoff_sha256=self.handoff_sha,
                    expected_continuation_sha256=continuation_sha,
                )
            self.assertEqual(result.receipt.raw, self.results[0].receipt.raw)
            self.assertNotEqual(path.read_bytes(), invocation.candidates.spools[0].raw)

    def test_continuation_digest_rejects_before_parse_or_dependencies(self):
        with patch.object(
            io.Snapshot, "document", side_effect=AssertionError("parse")
        ), patch.object(
            predecessor, "_handoff_document", side_effect=AssertionError("dependency")
        ), patch.object(gate, "_PostSink", side_effect=AssertionError("compute")):
            with self.assertRaises(gate.ContinuationError):
                self.execute(0, continuation_sha="0" * 64)
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_invocation(root)
            with patch.object(io, "read_snapshot", wraps=io.read_snapshot) as read:
                with self.assertRaises(gate.ContinuationError):
                    gate.capture_tree_post_invocation(
                        root,
                        0,
                        expected_handoff_sha256=self.handoff_sha,
                        expected_continuation_sha256="0" * 64,
                    )
            self.assertEqual(read.call_count, 1)

    def test_continuation_schema_domain_cursor_and_claim_mutations_refuse_precompute(self):
        original = self.continuations[0]
        cases = (
            ("format", "unknown"),
            ("implementation_version", "2.0"),
            ("relation_id", "wrong-domain"),
            ("tree_index", 1),
            ("owner_cursor", True),
            ("pre_interval", [43_838, 80_699]),
            ("post_interval", [80_699, 83_112]),
            ("native_prefix_sha256", "0" * 64),
            ("verified_receipt_suffix", [{"filename": "wrong", "bytes": 1, "sha256": "0" * 64}] * 2),
            ("production", True),
            ("durable_resume", 0),
            ("unknown", None),
        )
        for key, value in cases:
            document = original.document()
            document[key] = value
            changed = replace(original, raw=gate.canonical_json(document))
            with self.subTest(key=key), patch.object(
                gate, "_PostSink", side_effect=AssertionError("compute")
            ), self.assertRaises(gate.ContinuationError):
                self.execute(
                    0,
                    invocation=self.invocation(0, continuation=changed),
                    continuation_sha=gate.sha256(changed.raw),
                )
        for raw in (
            original.raw + b"\n",
            original.raw.replace(b'"production":false', b'"production":false,"production":false'),
        ):
            changed = replace(original, raw=raw)
            with patch.object(
                gate, "_PostSink", side_effect=AssertionError("compute")
            ), self.assertRaises(gate.ContinuationError):
                self.execute(
                    0,
                    invocation=self.invocation(0, continuation=changed),
                    continuation_sha=gate.sha256(raw),
                )

    def test_nested_continuation_contract_mutations_refuse(self):
        original = self.continuations[0]
        mutations = []
        document = original.document()
        document["dependencies"]["points"]["sha256"] = "0" * 64
        mutations.append(document)
        document = original.document()
        document["import_contract"]["point_wire_count"] = 385
        mutations.append(document)
        document = original.document()
        document["output_contract"]["wire_start"] += 1
        mutations.append(document)
        document = original.document()
        document["composition_boundary"]["legacy_stream_hash_continuation_supported"] = True
        mutations.append(document)
        document = original.document()
        document["state_inventory"]["not_serialized"] = []
        mutations.append(document)
        document = original.document()
        document["pre_groups"][0]["rows"] += 1
        mutations.append(document)
        for document in mutations:
            changed = replace(original, raw=gate.canonical_json(document))
            with patch.object(
                gate, "_PostSink", side_effect=AssertionError("compute")
            ), self.assertRaises(gate.ContinuationError):
                self.execute(
                    0,
                    invocation=self.invocation(0, continuation=changed),
                    continuation_sha=gate.sha256(changed.raw),
                )

    def test_legacy_four_entry_chain_each_repinned_index_refuses_precompute(self):
        legacy = ["1" * 64, "2" * 64, "3" * 64, "4" * 64]
        for tree_index in (0, 1):
            for chain_index in range(4):
                document = self.continuations[tree_index].document()
                changed_chain = list(legacy)
                changed_chain[chain_index] = str(chain_index) * 64
                document["receipt_chain_sha256"] = changed_chain
                changed = replace(
                    self.continuations[tree_index], raw=gate.canonical_json(document)
                )
                invocation = gate.TreePostInvocationInsecureTestOnly(
                    self.candidates, changed, self.receipt_suffix
                )
                with self.subTest(tree=tree_index, chain_index=chain_index), patch.object(
                    gate, "_PostSink", side_effect=AssertionError("compute")
                ), self.assertRaises(gate.ContinuationError):
                    gate.execute_tree_post_insecure_test_only(
                        invocation,
                        expected_handoff_sha256=self.handoff_sha,
                        expected_continuation_sha256=gate.sha256(changed.raw),
                    )

    def test_receipt_suffix_stage_ordinal_invocation_and_link_refuse_precompute(self):
        mutations = []
        document = self.receipt_suffix[0].document()
        document["ordinal"] = 1
        mutations.append((gate.canonical_json(document), self.receipt_suffix[1].raw, "ordinal-2"))
        document = self.receipt_suffix[0].document()
        document["stage_id"] = "tree-pre[0]"
        mutations.append((gate.canonical_json(document), self.receipt_suffix[1].raw, "stage-2"))
        document = self.receipt_suffix[0].document()
        document["invocation_sha256"] = "0" * 64
        mutations.append((gate.canonical_json(document), self.receipt_suffix[1].raw, "invocation-2"))
        document = self.receipt_suffix[1].document()
        document["ordinal"] = 2
        mutations.append((self.receipt_suffix[0].raw, gate.canonical_json(document), "ordinal-3"))
        document = self.receipt_suffix[1].document()
        document["stage_id"] = "global-b"
        mutations.append((self.receipt_suffix[0].raw, gate.canonical_json(document), "stage-3"))
        document = self.receipt_suffix[1].document()
        document["invocation_sha256"] = "0" * 64
        mutations.append((self.receipt_suffix[0].raw, gate.canonical_json(document), "invocation-3"))
        document = self.receipt_suffix[1].document()
        document["previous_receipt_sha256"] = "0" * 64
        mutations.append((self.receipt_suffix[0].raw, gate.canonical_json(document), "broken-link"))
        for tree_index in (0, 1):
            for ordinal_2_raw, ordinal_3_raw, label in mutations:
                invocation, handoff_sha, continuation_sha = self.rebound_receipt_invocation(
                    tree_index, ordinal_2_raw, ordinal_3_raw
                )
                with self.subTest(tree=tree_index, mutation=label), patch.object(
                    gate, "_PostSink", side_effect=AssertionError("compute")
                ), self.assertRaises(gate.ContinuationError):
                    gate.execute_tree_post_insecure_test_only(
                        invocation,
                        expected_handoff_sha256=handoff_sha,
                        expected_continuation_sha256=continuation_sha,
                    )

    def test_receipt_suffix_swap_gap_duplicate_and_trailing_refuse(self):
        with self.assertRaises(gate.ContinuationError):
            gate.TreePostInvocationInsecureTestOnly(
                self.candidates,
                self.continuations[0],
                tuple(reversed(self.receipt_suffix)),
            )
        with self.assertRaises(gate.ContinuationError):
            gate.TreePostInvocationInsecureTestOnly(
                self.candidates,
                self.continuations[0],
                (self.receipt_suffix[0],),
            )
        malformed = (
            (self.receipt_suffix[0].raw + b"\n", self.receipt_suffix[1].raw),
            (
                self.receipt_suffix[0].raw.replace(
                    b'"production":false',
                    b'"production":false,"production":false',
                ),
                self.receipt_suffix[1].raw,
            ),
            (self.receipt_suffix[0].raw, self.receipt_suffix[1].raw + b"\n"),
            (
                self.receipt_suffix[0].raw,
                self.receipt_suffix[1].raw.replace(
                    b'"production":false',
                    b'"production":false,"production":false',
                ),
            ),
        )
        for ordinal_2_raw, ordinal_3_raw in malformed:
            invocation, handoff_sha, continuation_sha = self.rebound_receipt_invocation(
                0, ordinal_2_raw, ordinal_3_raw
            )
            with patch.object(
                gate, "_PostSink", side_effect=AssertionError("compute")
            ), self.assertRaises(gate.ContinuationError):
                gate.execute_tree_post_insecure_test_only(
                    invocation,
                    expected_handoff_sha256=handoff_sha,
                    expected_continuation_sha256=continuation_sha,
                )

    def test_captured_receipt_raw_remains_authoritative_after_pathname_changes(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_invocation(root)
            invocation = gate.capture_tree_post_invocation(
                root,
                1,
                expected_handoff_sha256=self.handoff_sha,
                expected_continuation_sha256=gate.sha256(self.continuations[1].raw),
            )
            (root / gate.PRIOR_RECEIPT_NAME).write_bytes(b'{"replaced":true}')
            (root / predecessor.RECEIPT_NAME).write_bytes(b'{"replaced":true}')
            with patch.object(io, "read_snapshot", side_effect=AssertionError("reopen")):
                result = gate.execute_tree_post_insecure_test_only(
                    invocation,
                    expected_handoff_sha256=self.handoff_sha,
                    expected_continuation_sha256=gate.sha256(self.continuations[1].raw),
                )
            self.assertEqual(result.receipt.raw, self.results[1].receipt.raw)

    def test_handoff_dependency_mutations_cannot_be_rebound_by_continuation(self):
        candidates = self.candidates
        mutations = (
            replace(
                candidates,
                points=replace(candidates.points, raw=candidates.points.raw + b"\n"),
            ),
            replace(
                candidates,
                receipt=replace(candidates.receipt, raw=candidates.receipt.raw + b"\n"),
            ),
            replace(candidates, spools=tuple(reversed(candidates.spools))),
        )
        for changed_candidates in mutations:
            with patch.object(
                gate, "_PostSink", side_effect=AssertionError("compute")
            ), self.assertRaises(gate.ContinuationError):
                self.execute(
                    0,
                    invocation=self.invocation(0, candidates=changed_candidates),
                )

    def test_spool_wrong_wire_value_and_point_value_refuse(self):
        spool_raw = bytearray(self.candidates.spools[0].raw)
        spool_raw[codec.BODY_OFFSET + codec.WIRE_RECORD.size] ^= 1
        changed_spool = replace(self.candidates.spools[0], raw=bytes(spool_raw))
        changed_candidates = replace(
            self.candidates,
            spools=(changed_spool, self.candidates.spools[1]),
        )
        with self.assertRaises(gate.ContinuationError):
            self.execute(0, invocation=self.invocation(0, candidates=changed_candidates))
        point_document = self.candidates.points.document()
        point_document["values"][0] = 0
        changed_points = replace(
            self.candidates.points, raw=gate.canonical_json(point_document)
        )
        with self.assertRaises(gate.ContinuationError):
            self.execute(
                0,
                invocation=self.invocation(
                    0, candidates=replace(self.candidates, points=changed_points)
                ),
            )

    def test_result_receipt_strict_validation_and_mutations(self):
        result = self.results[0]
        continuation = self.continuations[0].document()
        parsed = gate.validate_tree_post_receipt(
            result.receipt,
            expected_sha256=gate.sha256(result.receipt.raw),
            continuation=continuation,
        )
        self.assertEqual(parsed["summary"], dict(result.summary))
        cases = []
        document = result.receipt.document()
        document["format"] = "unknown"
        cases.append(document)
        document = result.receipt.document()
        document["summary"]["rows"] = 3_575
        cases.append(document)
        document = result.receipt.document()
        document["summary"]["output_port"]["wire_start"] += 1
        cases.append(document)
        document = result.receipt.document()
        document["dependency_sha256"]["points"] = "0" * 64
        cases.append(document)
        document = result.receipt.document()
        document["production"] = True
        cases.append(document)
        document = result.receipt.document()
        document["unknown"] = None
        cases.append(document)
        for document in cases:
            raw = gate.canonical_json(document)
            with self.assertRaises(gate.ContinuationError):
                gate.validate_tree_post_receipt(
                    replace(result.receipt, raw=raw),
                    expected_sha256=gate.sha256(raw),
                    continuation=continuation,
                )
        for raw in (result.receipt.raw + b"\n", b""):
            with self.assertRaises(gate.ContinuationError):
                gate.validate_tree_post_receipt(
                    replace(result.receipt, raw=raw),
                    expected_sha256=gate.sha256(raw),
                    continuation=continuation,
                )

    def test_second_private_fixture_changes_values_not_row_contract(self):
        session = predecessor.HandoffSessionInsecureTestOnly(variant=1)
        try:
            session.run_to("global-a")
            candidates = session.export_candidates()
            handoff_sha = gate.sha256(candidates.handoff.raw)
            session.accept_handoff(candidates, expected_handoff_sha256=handoff_sha)
            receipt_suffix = gate.build_verified_receipt_suffix_snapshots(session)
            continuation = gate.build_continuation_snapshots(session)[0]
            result = gate.execute_tree_post_insecure_test_only(
                gate.TreePostInvocationInsecureTestOnly(
                    candidates, continuation, receipt_suffix
                ),
                expected_handoff_sha256=handoff_sha,
                expected_continuation_sha256=gate.sha256(continuation.raw),
            )
        finally:
            session.close()
        self.assertEqual(result.summary["groups"], self.results[0].summary["groups"])
        self.assertNotEqual(
            result.output_port.value_sha256, self.results[0].output_port.value_sha256
        )
        self.assertNotEqual(result.owned_values, self.results[0].owned_values)

    def test_immutable_results_and_no_private_payload_in_evidence(self):
        with self.assertRaises(FrozenInstanceError):
            self.results[0].tree_index = 1
        with self.assertRaises(TypeError):
            self.results[0].summary["rows"] = 0
        evidence = gate.bounded_self_check()
        raw = gate.canonical_json(evidence)
        self.assertNotIn(self.candidates.spools[0].raw, raw)
        private_raw = b"".join(
            value.to_bytes(25, "little") for value in self.results[0].owned_values
        )
        self.assertNotIn(private_raw, raw)
        self.assertFalse(evidence["private_payload_embedded"])

    def test_production_and_readonly_preflight_fail_closed_without_output(self):
        with TemporaryDirectory() as temp:
            output = Path(temp) / "must-not-exist"
            with patch.object(io, "read_snapshot", side_effect=AssertionError("read")), patch.object(
                Path, "mkdir", side_effect=AssertionError("mkdir")
            ):
                with self.assertRaises(gate.ProductionUnavailable):
                    gate.execute_production(object(), output=output)
            self.assertFalse(output.exists())
        with patch.object(
            predecessor,
            "HandoffSessionInsecureTestOnly",
            side_effect=AssertionError("fixture"),
        ):
            report = gate.preflight()
        self.assertTrue(report["independently_invocable_tree_post_implemented"])
        self.assertFalse(report["full_session_restore_implemented"])
        self.assertFalse(report["global_tail_continuation_implemented"])
        self.assertFalse(report["safe_to_start_large_replay"])
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
