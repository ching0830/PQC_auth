from dataclasses import FrozenInstanceError, replace
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import pq_rbbc_cap_unified_tree_launch_validation_v2_41 as historical
import pq_rbbc_issuance_bounded_multitree_adapter_v1 as base
import pq_rbbc_issuance_global_a_restart_v1 as global_a
import pq_rbbc_issuance_global_b_candidateset_preflight_v1 as gate
import pq_rbbc_issuance_multitree_restart_scheduler_v1 as scheduler
import pq_rbbc_issuance_private_spool_handoff_v1 as spool_handoff
import pq_rbbc_issuance_tree_post_continuation_v1 as continuation
import pq_rbbc_issuance_tree_post_restart_v1 as restart
import pq_rbbc_launch_io_v2_41 as io


class GlobalBCandidateSetPreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = TemporaryDirectory(prefix="pq-rbbc-global-b-candidateset-")
        cls.root = Path(cls.temporary.name)
        cls.session = spool_handoff.HandoffSessionInsecureTestOnly()
        cls.session.run_to("tree-pre[1]")
        cls.tree_pre = global_a.build_tree_pre_candidates_insecure_test_only(cls.session)
        cls.tree_pre_handoff_sha256 = cls.tree_pre.handoff.identity["sha256"]
        cls.global_a_computed = global_a.execute_global_a_insecure_test_only(
            cls.tree_pre,
            expected_handoff_sha256=cls.tree_pre_handoff_sha256,
        )

        cls.session.run_to("global-a")
        cls.spool_candidates = cls.session.export_candidates()
        cls.session.accept_handoff(
            cls.spool_candidates,
            expected_handoff_sha256=cls.spool_candidates.handoff.identity["sha256"],
        )
        cls.scheduler_receipt_suffix = continuation.build_verified_receipt_suffix_snapshots(
            cls.session
        )
        cls.continuations = continuation.build_continuation_snapshots(cls.session)
        cls.invocations = tuple(
            continuation.TreePostInvocationInsecureTestOnly(
                cls.spool_candidates,
                continuation_snapshot,
                cls.scheduler_receipt_suffix,
            )
            for continuation_snapshot in cls.continuations
        )
        cls.tree_post_computed = tuple(
            continuation.execute_tree_post_insecure_test_only(
                invocation,
                expected_handoff_sha256=scheduler.HANDOFF_IDENTITY["sha256"],
                expected_continuation_sha256=scheduler.CONTINUATION_IDENTITIES[index][
                    "sha256"
                ],
            )
            for index, invocation in enumerate(cls.invocations)
        )

        cls.global_a_output = cls.root / "global-a"
        with patch.object(
            global_a,
            "execute_global_a_insecure_test_only",
            return_value=cls.global_a_computed,
        ):
            completed_global_a = global_a.run_bounded_global_a(
                cls.global_a_output,
                artifact_root=cls.root,
                fresh_candidates=cls.tree_pre,
                expected_handoff_sha256=cls.tree_pre_handoff_sha256,
                fresh_output=True,
            )
        cls.global_a_result = global_a.capture_completed_result(
            cls.global_a_output,
            artifact_root=cls.root,
            expected_complete_sha256=completed_global_a.complete_checkpoint.identity[
                "sha256"
            ],
        )

        def cached_compute(_invocation, plan_document):
            return cls.tree_post_computed[int(plan_document["tree_index"])]

        cls.scheduler_output = cls.root / "scheduler"
        with patch.object(restart, "_compute_result", side_effect=cached_compute):
            completed_schedule = scheduler.run_bounded_scheduler(
                cls.scheduler_output,
                artifact_root=cls.root,
                fresh_invocations=cls.invocations,
                fresh_output=True,
            )
        cls.schedule = scheduler.capture_completed_schedule(
            cls.scheduler_output,
            artifact_root=cls.root,
            expected_complete_sha256=completed_schedule.complete_checkpoint.identity[
                "sha256"
            ],
        )
        cls.candidate = gate.build_candidate_set_insecure_test_only(
            tree_pre=cls.tree_pre,
            global_a_result=cls.global_a_result,
            continuations=cls.continuations,
            adapter_receipt_prefix=cls.tree_pre.receipts,
            scheduler_receipt_suffix=cls.scheduler_receipt_suffix,
            schedule=cls.schedule,
        )
        cls.handoff_sha256 = cls.candidate.handoff.identity["sha256"]

    @classmethod
    def tearDownClass(cls):
        cls.session.close()
        cls.temporary.cleanup()

    def validate(self, candidate=None):
        candidate = self.candidate if candidate is None else candidate
        return gate.validate_candidate_set_insecure_test_only(
            candidate,
            expected_handoff_sha256=candidate.handoff.identity["sha256"],
        )

    def repin_handoff(self, candidate):
        handoff = gate._handoff_snapshot(
            shared_inputs=candidate.shared_inputs,
            tree_pre=candidate.tree_pre,
            global_a_result=candidate.global_a_result,
            continuations=candidate.continuations,
            adapter_receipt_prefix=candidate.adapter_receipt_prefix,
            scheduler_receipt_suffix=candidate.scheduler_receipt_suffix,
            schedule=candidate.schedule,
            relocations=candidate.relocations,
        )
        return replace(candidate, handoff=handoff)

    def mutate_snapshot(self, snapshot, mutate, *, raw_suffix=b""):
        document = snapshot.document()
        mutate(document)
        return replace(snapshot, raw=gate.canonical_json(document) + raw_suffix)

    def test_positive_same_invocation_candidate_set(self):
        decoded = self.validate()
        evidence = gate.candidate_evidence(self.candidate)
        self.assertEqual(len(decoded.global_a_values), 12_179)
        self.assertEqual([len(values) for values in decoded.tree_post_values], [2_412, 2_412])
        self.assertEqual(len(decoded.target_values), 7_826)
        self.assertEqual(evidence["candidate_snapshot_identity_count"], 32)
        self.assertEqual(evidence["relocation_candidate_count"], 8)
        self.assertEqual(evidence["adapter_receipt_prefix_ordinals_verified"], [0, 1, 2, 3])
        self.assertEqual(evidence["tree_post_receipt_branches_verified"], [0, 1])
        self.assertTrue(evidence["same_points_raw_verified"])
        self.assertTrue(evidence["same_invocation_profile_plan_verified"])
        self.assertFalse(evidence["global_b_constraints_emitted"])
        self.assertFalse(evidence["full_execution_receipt_chain_verified"])

    def test_ordinal_two_raw_overlap_allows_distinct_filenames(self):
        prefix = self.candidate.adapter_receipt_prefix[2]
        suffix = self.candidate.scheduler_receipt_suffix[0]
        self.assertEqual(prefix.raw, suffix.raw)
        self.assertEqual(prefix.identity["bytes"], suffix.identity["bytes"])
        self.assertEqual(prefix.identity["sha256"], suffix.identity["sha256"])
        self.assertNotEqual(prefix.identity["filename"], suffix.identity["filename"])
        ordinal_three = self.candidate.scheduler_receipt_suffix[1].document()
        self.assertEqual(ordinal_three["previous_receipt_sha256"], prefix.identity["sha256"])

    def test_candidate_and_decoded_views_are_frozen(self):
        decoded = self.validate()
        with self.assertRaises(FrozenInstanceError):
            self.candidate.handoff = self.candidate.shared_inputs
        with self.assertRaises(TypeError):
            decoded.target_values[1] = 0
        with self.assertRaises(TypeError):
            decoded.shared_inputs["salt"] = ()

    def test_wrong_external_handoff_digest_rejects_before_dependencies(self):
        with patch.object(
            gate,
            "_check_handoff_inventory",
            side_effect=AssertionError("dependent snapshot accessed"),
        ):
            for digest in ("0" * 64, "A" * 64, None, 7):
                with self.subTest(digest=digest), self.assertRaises(
                    gate.GlobalBCandidateSetError
                ):
                    gate.validate_candidate_set_insecure_test_only(
                        self.candidate,
                        expected_handoff_sha256=digest,
                    )

    def test_shared_input_version_domain_value_and_trailing_mutations_reject(self):
        mutations = (
            lambda document: document.__setitem__("implementation_version", "2.0"),
            lambda document: document.__setitem__("invocation_sha256", "0" * 64),
            lambda document: document["fields"][0].__setitem__("target_wire_start", 2),
            lambda document: document["fields"][1].__setitem__("packed_bits_sha256", "0" * 64),
            lambda document: document.__setitem__("production", True),
        )
        for index, mutate in enumerate(mutations):
            changed = self.mutate_snapshot(self.candidate.shared_inputs, mutate)
            candidate = self.repin_handoff(replace(self.candidate, shared_inputs=changed))
            with self.subTest(index=index), self.assertRaises(
                gate.GlobalBCandidateSetError
            ):
                self.validate(candidate)
        changed = replace(
            self.candidate.shared_inputs,
            raw=self.candidate.shared_inputs.raw + b"\n",
        )
        candidate = self.repin_handoff(replace(self.candidate, shared_inputs=changed))
        with self.assertRaises((gate.GlobalBCandidateSetError, io.ValidationError)):
            self.validate(candidate)

    def test_duplicate_shared_input_key_rejects(self):
        raw = self.candidate.shared_inputs.raw
        duplicate = raw.replace(b'{"fields":', b'{"fields":[],"fields":', 1)
        changed = replace(self.candidate.shared_inputs, raw=duplicate)
        candidate = self.repin_handoff(replace(self.candidate, shared_inputs=changed))
        with self.assertRaises((gate.GlobalBCandidateSetError, io.ValidationError)):
            self.validate(candidate)

    def test_each_relocation_re_pinned_mutation_rejects(self):
        for index in range(8):
            relocations = list(self.candidate.relocations)
            relocations[index] = self.mutate_snapshot(
                relocations[index],
                lambda document: document.__setitem__(
                    "target_wire_start", int(document["target_wire_start"]) + 1
                ),
            )
            candidate = self.repin_handoff(
                replace(self.candidate, relocations=tuple(relocations))
            )
            with self.subTest(index=index), self.assertRaises(
                gate.GlobalBCandidateSetError
            ):
                self.validate(candidate)

    def test_relocation_swap_gap_wrong_claim_version_domain_and_trailing_reject(self):
        variants = []
        swapped = list(self.candidate.relocations)
        swapped[0], swapped[1] = swapped[1], swapped[0]
        variants.append(replace(self.candidate, relocations=tuple(swapped)))
        mutations = (
            lambda document: document.__setitem__("ordinal", 7),
            lambda document: document.__setitem__("implementation_version", "2.0"),
            lambda document: document.__setitem__("relation_id", "wrong-domain"),
            lambda document: document.__setitem__("native_equality_executed", True),
            lambda document: document.__setitem__("host_value_binding_checked", False),
        )
        for mutate in mutations:
            relocations = list(self.candidate.relocations)
            relocations[0] = self.mutate_snapshot(relocations[0], mutate)
            variants.append(replace(self.candidate, relocations=tuple(relocations)))
        relocations = list(self.candidate.relocations)
        relocations[0] = replace(relocations[0], raw=relocations[0].raw + b"\n")
        variants.append(replace(self.candidate, relocations=tuple(relocations)))
        for index, candidate in enumerate(variants):
            candidate = self.repin_handoff(candidate)
            with self.subTest(index=index), self.assertRaises(
                (gate.GlobalBCandidateSetError, io.ValidationError)
            ):
                self.validate(candidate)

    def test_wrong_prefix_suffix_overlap_and_broken_link_reject(self):
        suffix = list(self.candidate.scheduler_receipt_suffix)
        suffix[0] = replace(suffix[0], raw=suffix[0].raw.replace(b'"ordinal":2', b'"ordinal":1'))
        candidate = self.repin_handoff(
            replace(self.candidate, scheduler_receipt_suffix=tuple(suffix))
        )
        with self.assertRaises(gate.GlobalBCandidateSetError):
            self.validate(candidate)

        suffix = list(self.candidate.scheduler_receipt_suffix)
        suffix[1] = self.mutate_snapshot(
            suffix[1],
            lambda document: document.__setitem__("previous_receipt_sha256", "0" * 64),
        )
        candidate = self.repin_handoff(
            replace(self.candidate, scheduler_receipt_suffix=tuple(suffix))
        )
        with self.assertRaises(gate.GlobalBCandidateSetError):
            self.validate(candidate)

    def test_global_a_values_scheduler_order_and_points_mutations_reject(self):
        changed_values = (self.candidate.global_a_result.owned_values[0] ^ 1,) + tuple(
            self.candidate.global_a_result.owned_values[1:]
        )
        changed_global_a = replace(
            self.candidate.global_a_result, owned_values=changed_values
        )
        candidate = self.repin_handoff(
            replace(self.candidate, global_a_result=changed_global_a)
        )
        with self.assertRaises(gate.GlobalBCandidateSetError):
            self.validate(candidate)

        changed_schedule = replace(
            self.candidate.schedule,
            ordered_results=tuple(reversed(self.candidate.schedule.ordered_results)),
        )
        candidate = self.repin_handoff(
            replace(self.candidate, schedule=changed_schedule)
        )
        with self.assertRaises(gate.GlobalBCandidateSetError):
            self.validate(candidate)

        changed_points = self.mutate_snapshot(
            self.candidate.global_a_result.point_snapshot,
            lambda document: document["values"].__setitem__(
                0, int(document["values"][0]) ^ 1
            ),
        )
        changed_global_a = replace(
            self.candidate.global_a_result, point_snapshot=changed_points
        )
        candidate = self.repin_handoff(
            replace(self.candidate, global_a_result=changed_global_a)
        )
        with self.assertRaises(gate.GlobalBCandidateSetError):
            self.validate(candidate)

    def test_handoff_unknown_missing_wrong_claim_and_trailing_reject_precompute(self):
        variants = []
        document = self.candidate.handoff.document()
        document["unknown"] = True
        variants.append(gate.canonical_json(document))
        document = self.candidate.handoff.document()
        del document["scheduler"]
        variants.append(gate.canonical_json(document))
        document = self.candidate.handoff.document()
        document["global_b_constraints_replayed"] = True
        variants.append(gate.canonical_json(document))
        variants.append(self.candidate.handoff.raw + b"\n")
        for index, raw in enumerate(variants):
            candidate = replace(
                self.candidate,
                handoff=replace(self.candidate.handoff, raw=raw),
            )
            with patch.object(
                gate,
                "_validate_predecessors",
                side_effect=AssertionError("predecessor validation reached"),
            ), self.subTest(index=index), self.assertRaises(
                (gate.GlobalBCandidateSetError, io.ValidationError)
            ):
                self.validate(candidate)

    def test_captured_snapshots_remain_authoritative_after_path_changes(self):
        result_path = (
            self.global_a_output
            / global_a.RESULT_DIRECTORY
            / global_a.PRIVATE_RESULT_NAME
        )
        scheduler_plan_path = (
            self.scheduler_output
            / scheduler.SCHEDULER_JOURNAL_DIRECTORY
            / scheduler.PLAN_NAME
        )
        originals = (result_path.read_bytes(), scheduler_plan_path.read_bytes())
        try:
            result_path.write_bytes(b'{"changed":true}\n')
            scheduler_plan_path.write_bytes(b'{"changed":true}\n')
            with patch.object(
                io,
                "read_snapshot",
                side_effect=AssertionError("pathname reopen"),
            ):
                decoded = self.validate()
            self.assertEqual(len(decoded.global_a_values), 12_179)
            self.assertNotEqual(result_path.read_bytes(), self.candidate.global_a_result.result.raw)
            self.assertNotEqual(
                scheduler_plan_path.read_bytes(), self.candidate.schedule.execution_plan.raw
            )
        finally:
            result_path.write_bytes(originals[0])
            scheduler_plan_path.write_bytes(originals[1])

    def test_validation_does_not_emit_constraints_or_create_output(self):
        forbidden = self.root / "must-not-exist"
        with patch.object(
            base,
            "build_reference_insecure_test_only",
            side_effect=AssertionError("reference relation construction"),
        ), patch.object(
            restart,
            "run_bounded_tree_post",
            side_effect=AssertionError("tree-post execution"),
        ):
            self.validate()
        self.assertFalse(forbidden.exists())

    def test_production_refuses_before_io_and_claims_stay_closed(self):
        forbidden = self.root / "production-output"
        with patch.object(
            gate,
            "validate_prerequisites",
            side_effect=AssertionError("preflight I/O"),
        ), self.assertRaises(gate.ProductionUnavailable):
            gate.execute_production(output=forbidden)
        self.assertFalse(forbidden.exists())
        report = gate.preflight()
        self.assertTrue(report["candidate_contract_defined"])
        self.assertTrue(report["safe_to_implement_bounded_global_b_consumer"])
        self.assertFalse(report["unified_path_capture_api_implemented"])
        self.assertFalse(report["global_b_consumer_implemented"])
        self.assertFalse(report["global_b_constraints_replayed"])
        self.assertFalse(report["full_execution_receipt_chain_verified"])
        self.assertFalse(report["safe_to_execute_bounded_global_b"])
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
            self.assertNotIn(self.candidate.shared_inputs.raw, raw)
            self.assertNotIn(self.candidate.global_a_result.result.raw, raw)
            self.assertNotIn(self.candidate.schedule.ordered_results[0].result.raw, raw)
        self.assertEqual(
            manifest["frozen_bounded_candidate"],
            {
                key: gate.candidate_evidence(self.candidate)[key]
                for key in gate.FROZEN
            },
        )
        self.assertFalse(manifest["claim_status"]["global_b_consumer_implemented"])
        self.assertFalse(manifest["claim_status"]["global_b_constraints_replayed"])
        self.assertFalse(manifest["claim_status"]["Production-closed"])


if __name__ == "__main__":
    unittest.main()
