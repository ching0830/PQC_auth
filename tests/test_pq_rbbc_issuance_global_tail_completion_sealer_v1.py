from dataclasses import FrozenInstanceError, replace
import hashlib
import unittest
from unittest.mock import patch

import pq_rbbc_cap_unified_tree_launch_validation_v2_41 as historical
import pq_rbbc_issuance_global_tail_completion_sealer_v1 as gate
import pq_rbbc_launch_io_v2_41 as io


class GlobalTailCompletionSealerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.session, cls.temporary, cls.candidate = (
            gate._fixture_candidate_insecure_test_only()
        )
        cls.handoff_sha256 = cls.candidate.handoff.identity["sha256"]
        cls.decoded = gate.validate_parent_candidate_set_insecure_test_only(
            cls.candidate,
            expected_handoff_sha256=cls.handoff_sha256,
        )

    @classmethod
    def tearDownClass(cls):
        cls.session.close()
        cls.temporary.cleanup()

    def validate(self, candidate=None, expected_handoff_sha256=None):
        candidate = self.candidate if candidate is None else candidate
        digest = (
            candidate.handoff.identity["sha256"]
            if expected_handoff_sha256 is None
            else expected_handoff_sha256
        )
        return gate.validate_parent_candidate_set_insecure_test_only(
            candidate,
            expected_handoff_sha256=digest,
        )

    def mutate_snapshot(self, snapshot, mutate, *, suffix=b""):
        document = snapshot.document()
        mutate(document)
        return replace(snapshot, raw=gate.canonical_json(document) + suffix)

    def repin_handoff(self, candidate):
        handoff = gate._handoff_snapshot(
            candidate.source_candidate,
            candidate.global_b_result,
            candidate.parent_input,
        )
        return replace(candidate, handoff=handoff)

    def test_positive_exact_parent_input_and_completion_inventory(self):
        decoded = self.decoded
        evidence = gate.candidate_evidence(self.candidate)
        self.assertEqual(
            tuple(item["role"] for item in decoded.handoff["snapshot_inventory"]),
            gate.SNAPSHOT_ROLE_ORDER,
        )
        self.assertEqual(len(decoded.snapshot_identities), 36)
        self.assertEqual(decoded.c_r, self.candidate.global_b_result.commitment)
        self.assertEqual(
            decoded.request_hash, self.candidate.global_b_result.request_hash
        )
        self.assertEqual(evidence["source_rows_already_checked"], 70_143)
        self.assertEqual(evidence["rows_replayed_by_sealer"], 0)
        self.assertEqual(evidence["parent_constraints_replayed"], 0)
        self.assertEqual(
            evidence["receipt_graph_kind"],
            "ordinal-chain-with-two-tree-post-branches-and-global-b-terminal",
        )
        self.assertFalse(evidence["full_execution_receipt_chain_verified"])
        self.assertFalse(evidence["production"])

    def test_candidate_and_decoded_views_are_immutable(self):
        with self.assertRaises(FrozenInstanceError):
            self.candidate.parent_input = self.candidate.handoff
        with self.assertRaises(TypeError):
            self.decoded.handoff["production"] = True
        with self.assertRaises(TypeError):
            self.decoded.parent_input["c_r_bytes"] = 0
        with self.assertRaises(TypeError):
            self.decoded.snapshot_identities[0]["bytes"] = 0
        with self.assertRaises(TypeError):
            self.decoded.handoff["receipt_graph"]["kind"] = "mutated"
        with self.assertRaises(TypeError):
            self.decoded.handoff["snapshot_inventory"][0]["role"] = "mutated"

    def test_external_handoff_digest_rejects_before_dependencies(self):
        for digest in ("0" * 64, "A" * 64, None, 1):
            with self.subTest(digest=digest), patch.object(
                gate,
                "_check_handoff_inventory",
                side_effect=AssertionError("dependent snapshot accessed"),
            ), self.assertRaises(gate.GlobalTailCompletionError):
                gate.validate_parent_candidate_set_insecure_test_only(
                    self.candidate,
                    expected_handoff_sha256=digest,
                )

    def test_validator_consumes_captured_raws_without_pathname_reopen_or_compute(self):
        with patch.object(
            gate.io,
            "read_snapshot",
            side_effect=AssertionError("pathname reopened"),
        ), patch.object(
            gate.global_b.disk,
            "read",
            side_effect=AssertionError("pathname reopened"),
        ), patch.object(
            gate.global_b,
            "execute_global_b_insecure_test_only",
            side_effect=AssertionError("Global-B recomputed"),
        ):
            decoded = self.validate()
        self.assertEqual(decoded.c_r, self.candidate.global_b_result.commitment)

    def test_fixed_role_order_and_exact_integer_ordinals_reject_repinning(self):
        variants = []
        swapped = self.candidate.handoff.document()
        inventory = swapped["snapshot_inventory"]
        inventory[0], inventory[1] = inventory[1], inventory[0]
        inventory[0]["ordinal"] = 0
        inventory[1]["ordinal"] = 1
        swapped["snapshot_inventory_sha256"] = gate._inventory_digest(inventory)
        variants.append(swapped)

        boolean_ordinal = self.candidate.handoff.document()
        boolean_ordinal["snapshot_inventory"][0]["ordinal"] = False
        boolean_ordinal["snapshot_inventory_sha256"] = gate._inventory_digest(
            boolean_ordinal["snapshot_inventory"]
        )
        variants.append(boolean_ordinal)

        duplicate = self.candidate.handoff.document()
        duplicate["snapshot_inventory"].append(
            duplicate["snapshot_inventory"][-1]
        )
        duplicate["snapshot_inventory_sha256"] = gate._inventory_digest(
            duplicate["snapshot_inventory"]
        )
        variants.append(duplicate)

        for index, document in enumerate(variants):
            handoff = replace(
                self.candidate.handoff, raw=gate.canonical_json(document)
            )
            changed = replace(self.candidate, handoff=handoff)
            with self.subTest(index=index), self.assertRaises(
                gate.GlobalTailCompletionError
            ):
                self.validate(changed)

    def test_handoff_domain_graph_claim_and_encoding_mutations_reject(self):
        mutations = (
            lambda document: document.__setitem__("implementation_version", "2.0"),
            lambda document: document.__setitem__("relation_id", "wrong-domain"),
            lambda document: document.__setitem__("invocation_sha256", "0" * 64),
            lambda document: document.__setitem__("production", True),
            lambda document: document.__setitem__(
                "future_parent_must_consume_same_snapshots", False
            ),
            lambda document: document["receipt_graph"].__setitem__(
                "adapter_receipt_ordinals", [False, True, 2, 3]
            ),
            lambda document: document["receipt_graph"].__setitem__(
                "tree_post_branches", [1, 0]
            ),
            lambda document: document["receipt_graph"].__setitem__(
                "full_execution_receipt_chain_verified", True
            ),
            lambda document: document["source_execution_summary"].__setitem__(
                "rows_replayed_by_sealer", True
            ),
        )
        for index, mutate in enumerate(mutations):
            handoff = self.mutate_snapshot(self.candidate.handoff, mutate)
            with self.subTest(index=index), self.assertRaises(
                gate.GlobalTailCompletionError
            ):
                self.validate(replace(self.candidate, handoff=handoff))

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
            self.assertNotIn(self.candidate.handoff.raw, raw)
            self.assertNotIn(self.candidate.parent_input.raw, raw)
            self.assertNotIn(b'"c_r_hex"', raw)
            self.assertNotIn(b'"request_hash_hex"', raw)
        self.assertEqual(
            manifest["frozen_bounded_qualification"],
            gate.candidate_evidence(self.candidate),
        )
        self.assertFalse(evidence["private_snapshot_raws_embedded"])
        self.assertFalse(evidence["private_parent_input_embedded"])
        self.assertFalse(manifest["claim_status"]["Proof-closed"])
        self.assertFalse(manifest["claim_status"]["Production-closed"])

        trailing = replace(
            self.candidate.handoff, raw=self.candidate.handoff.raw + b"\n"
        )
        duplicate = replace(
            self.candidate.handoff,
            raw=self.candidate.handoff.raw.replace(
                b'{"all_identity_parse_binding_use_same_raw":',
                b'{"production":false,"all_identity_parse_binding_use_same_raw":',
                1,
            ),
        )
        for label, handoff in (("trailing", trailing), ("duplicate", duplicate)):
            with self.subTest(label=label), self.assertRaises(
                (gate.GlobalTailCompletionError, io.ValidationError)
            ):
                self.validate(replace(self.candidate, handoff=handoff))

    def test_parent_input_domain_binding_bool_and_trailing_mutations_reject(self):
        mutations = (
            lambda document: document.__setitem__("implementation_version", "2.0"),
            lambda document: document.__setitem__("relation_id", "wrong-domain"),
            lambda document: document.__setitem__(
                "source_global_b_result_sha256", "0" * 64
            ),
            lambda document: document.__setitem__("c_r_bytes", True),
            lambda document: document.__setitem__("c_r_sha256", "0" * 64),
            lambda document: document.__setitem__("request_hash_bytes", False),
            lambda document: document.__setitem__("request_hash_sha256", "0" * 64),
            lambda document: document.__setitem__(
                "future_parent_must_consume_same_snapshot", False
            ),
            lambda document: document.__setitem__("parent_constraints_replayed", True),
            lambda document: document.__setitem__("production", True),
        )
        for index, mutate in enumerate(mutations):
            parent_input = self.mutate_snapshot(self.candidate.parent_input, mutate)
            changed = self.repin_handoff(
                replace(self.candidate, parent_input=parent_input)
            )
            with self.subTest(index=index), self.assertRaises(
                gate.GlobalTailCompletionError
            ):
                self.validate(changed)

        parent_input = replace(
            self.candidate.parent_input,
            raw=self.candidate.parent_input.raw + b" ",
        )
        changed = self.repin_handoff(
            replace(self.candidate, parent_input=parent_input)
        )
        with self.assertRaises((gate.GlobalTailCompletionError, io.ValidationError)):
            self.validate(changed)

    def test_parent_commitment_and_request_bytes_cannot_be_replaced_after_capture(self):
        for field in ("c_r_hex", "request_hash_hex"):
            parent_input = self.mutate_snapshot(
                self.candidate.parent_input,
                lambda document, field=field: document.__setitem__(
                    field,
                    ("0" if document[field][0] != "0" else "1")
                    + document[field][1:],
                ),
            )
            changed = self.repin_handoff(
                replace(self.candidate, parent_input=parent_input)
            )
            with self.subTest(field=field), self.assertRaises(
                gate.GlobalTailCompletionError
            ):
                self.validate(changed)

    def test_source_result_receipt_complete_and_candidateset_repin_reject(self):
        variants = []

        result = replace(
            self.candidate.global_b_result.result,
            raw=self.candidate.global_b_result.result.raw[:-1] + b" ",
        )
        published = replace(self.candidate.global_b_result, result=result)
        variants.append(replace(self.candidate, global_b_result=published))

        receipt = self.mutate_snapshot(
            self.candidate.global_b_result.receipt,
            lambda document: document.__setitem__("implementation_version", "2.0"),
        )
        published = replace(self.candidate.global_b_result, receipt=receipt)
        variants.append(replace(self.candidate, global_b_result=published))

        complete = self.mutate_snapshot(
            self.candidate.global_b_result.complete_checkpoint,
            lambda document: document.__setitem__(
                "previous_checkpoint_sha256", "0" * 64
            ),
        )
        published = replace(
            self.candidate.global_b_result, complete_checkpoint=complete
        )
        variants.append(replace(self.candidate, global_b_result=published))

        source_handoff = replace(
            self.candidate.source_candidate.handoff,
            raw=self.candidate.source_candidate.handoff.raw + b" ",
        )
        source_candidate = replace(
            self.candidate.source_candidate, handoff=source_handoff
        )
        variants.append(replace(self.candidate, source_candidate=source_candidate))

        for index, variant in enumerate(variants):
            changed = self.repin_handoff(variant)
            with self.subTest(index=index), self.assertRaises(
                (gate.GlobalTailCompletionError, io.ValidationError)
            ):
                self.validate(changed)

    def test_terminal_checkpoint_ordinal_inventory_and_outputs_are_exact(self):
        mutations = (
            lambda document: document.__setitem__("ordinal", True),
            lambda document: document.__setitem__("stage_id", "result-committed"),
            lambda document: document.__setitem__("complete", False),
            lambda document: document["output_identities"].reverse(),
            lambda document: document["input_inventory"].reverse(),
        )
        for index, mutate in enumerate(mutations):
            complete = self.mutate_snapshot(
                self.candidate.global_b_result.complete_checkpoint, mutate
            )
            published = replace(
                self.candidate.global_b_result, complete_checkpoint=complete
            )
            changed = self.repin_handoff(
                replace(self.candidate, global_b_result=published)
            )
            with self.subTest(index=index), self.assertRaises(
                gate.GlobalTailCompletionError
            ):
                self.validate(changed)

    def test_production_refuses_before_io_and_claims_stay_closed(self):
        with patch.object(
            gate,
            "validate_prerequisites",
            side_effect=AssertionError("production I/O"),
        ), self.assertRaises(gate.ProductionUnavailable):
            gate.execute_production(output="must-not-be-created")
        report = gate.preflight()
        self.assertTrue(report["bounded_completion_sealer_implemented"])
        self.assertTrue(report["parent_input_candidate_contract_defined"])
        self.assertFalse(report["fresh_parent_i1_i5_composition_implemented"])
        self.assertFalse(report["safe_to_start_parent_relation_replay"])
        self.assertFalse(report["safe_to_start_large_replay"])
        self.assertFalse(report["formal_pi_issue_generated"])
        self.assertFalse(report["production_legacy18_provider_implemented"])
        self.assertFalse(report["Proof-closed"])
        self.assertFalse(report["Production-closed"])

    def test_frozen_self_check_and_historical_identities(self):
        evidence = gate.bounded_self_check()
        for key, expected in gate.FROZEN.items():
            self.assertEqual(evidence[key], expected, key)
        self.assertEqual(len(historical.HISTORICAL_IDENTITIES), 19)
        for relative, expected in historical.HISTORICAL_IDENTITIES.items():
            raw = (gate.ROOT / relative).read_bytes()
            self.assertEqual(len(raw), expected["bytes"], relative)
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(), expected["sha256"], relative
            )


if __name__ == "__main__":
    unittest.main()
