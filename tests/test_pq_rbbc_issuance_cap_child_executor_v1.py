from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import pq_rbbc_cap_commit as cap
import pq_rbbc_issuance_cap_child_executor_v1 as gate
import pq_rbbc_issuance_production_inputs_v1 as production_inputs


ROOT = Path(__file__).resolve().parents[1]


class ProductionPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = gate.build_production_execution_plan()

    def test_exact_split_dependency_order(self) -> None:
        self.assertEqual(len(gate.PRODUCTION_STAGE_ORDER), 42)
        self.assertEqual(
            gate.PRODUCTION_STAGE_ORDER[:2],
            ("validate-snapshots", "bind-invocation"),
        )
        self.assertEqual(gate.PRODUCTION_STAGE_ORDER[2:20], tuple(
            f"tree-pre[{index}]" for index in range(18)
        ))
        self.assertEqual(gate.PRODUCTION_STAGE_ORDER[20], "global-tail-phase-a")
        self.assertEqual(gate.PRODUCTION_STAGE_ORDER[21:39], tuple(
            f"tree-post[{index}]" for index in range(18)
        ))
        self.assertEqual(
            gate.PRODUCTION_STAGE_ORDER[-3:],
            ("global-tail-phase-b", "parent-native-join", "final-seal"),
        )
        for ordinal, stage in enumerate(self.plan["stages"]):
            self.assertEqual(stage["ordinal"], ordinal)
            expected = [] if ordinal == 0 else [gate.PRODUCTION_STAGE_ORDER[ordinal - 1]]
            self.assertEqual(stage["depends_on"], expected)

    def test_all_tree_contracts_are_fresh_and_have_four_outputs(self) -> None:
        contracts = self.plan["tree_contracts"]
        self.assertEqual(len(contracts), cap.PRODUCTION_PARAMETERS.tree_count)
        for index, contract in enumerate(contracts):
            self.assertEqual(contract["tree_index"], index)
            expected_leaves = 4_096 if index < 2 else 2_048
            self.assertEqual(contract["leaves"], expected_leaves)
            self.assertEqual(contract["extension_degree"], expected_leaves.bit_length())
            self.assertEqual(len(contract["outputs"]), 4)
            self.assertEqual(
                [output["phase"] for output in contract["outputs"]],
                ["tree-pre", "tree-pre", "tree-pre", "tree-post"],
            )
            self.assertTrue(
                all(output["fresh_value_sha256"] is None for output in contract["outputs"])
            )
            self.assertIsNone(contract["observed_row_stream_bytes"])
            self.assertIsNone(contract["observed_row_stream_sha256"])
            self.assertIsNone(contract["assignment_identity"])
            self.assertFalse(contract["historical_value_digest_reused"])
            self.assertFalse(contract["historical_assignment_reused"])

    def test_rho_byte_ranges_are_exact_and_nonoverlapping(self) -> None:
        ranges = [
            interval
            for contract in self.plan["tree_contracts"]
            for interval in contract["rho_root_byte_intervals"]
        ]
        self.assertEqual(ranges[0]["byte_start"], 136)
        self.assertEqual(ranges[-1]["byte_end_exclusive"], 1_036)
        self.assertTrue(
            all(
                left["byte_end_exclusive"] == right["byte_start"]
                for left, right in zip(ranges, ranges[1:])
            )
        )

    def test_production_plan_and_prerequisites_match_frozen_identities(self) -> None:
        self.assertEqual(gate.validate_production_plan(), ())
        self.assertEqual(gate.validate_tracked_prerequisites(), ())
        self.assertEqual(
            gate.production_plan_sha256(), gate.FROZEN_PRODUCTION_PLAN_SHA256
        )
        self.assertFalse(self.plan["legacy_monolithic_tree_runner_directly_usable"])
        self.assertTrue(self.plan["fresh_split_pre_post_executor_required"])
        self.assertFalse(self.plan["other_tree_observed_stream_bytes_used"])


class InvocationAndPreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.invocation = gate._fixture_invocation()

    def test_invocation_owns_exact_statement_witness_and_rho_bytes(self) -> None:
        invocation = self.invocation
        self.assertEqual(len(invocation.rho.raw), 1_036)
        self.assertIsNot(invocation.statement_raw, invocation.statement.encode())
        self.assertEqual(invocation.statement_raw, invocation.statement.encode())
        self.assertEqual(invocation.witness_raw, invocation.witness.encode())
        self.assertEqual(
            invocation.rho.raw,
            invocation.witness.cap_randomness,
        )

    def test_trailing_wrong_context_and_wrong_abi_reject(self) -> None:
        invocation = self.invocation
        with self.assertRaises(gate.ChildExecutorError):
            gate.capture_invocation(
                invocation.statement_raw + b"\x00", invocation.witness_raw
            )
        wrong_context = replace(
            invocation.statement,
            ctx=bytes([invocation.statement.ctx[0] ^ 1]) + invocation.statement.ctx[1:],
        ).encode()
        with self.assertRaises(gate.ChildExecutorError):
            gate.capture_invocation(wrong_context, invocation.witness_raw)
        wrong_abi = replace(
            invocation.statement, abi_profile_digest=bytes(32)
        ).encode()
        with self.assertRaises(gate.ChildExecutorError):
            gate.capture_invocation(wrong_abi, invocation.witness_raw)

    def test_preflight_consumes_candidate_snapshots_without_path_reads(self) -> None:
        candidates = production_inputs.CandidateSet(root=Path("/never-open"))
        with patch.object(
            production_inputs,
            "read_candidate_set",
            side_effect=AssertionError("candidate pathname reopened"),
        ), patch.object(
            gate.launch_io.ArtifactRoot,
            "read",
            side_effect=AssertionError("candidate pathname reopened"),
        ):
            report = gate.production_invocation_preflight(candidates, self.invocation)
        self.assertTrue(report["same_candidate_snapshots_consumed"])
        self.assertTrue(report["same_rho_snapshot_consumed"])
        self.assertFalse(report["candidate_pathnames_reopened"])
        self.assertFalse(report["rho_pathname_reopened"])
        self.assertFalse(report["safe_to_materialize_production_cache"])
        self.assertFalse(report["safe_to_start_large_replay"])
        self.assertFalse(report["output_created"])

    def test_production_refuses_before_child_or_output_construction(self) -> None:
        with patch.object(
            gate.shard,
            "build_streaming_shard",
            side_effect=AssertionError("must refuse before trace"),
        ), patch.object(
            gate.StageOutputIdentityV1,
            "encode",
            side_effect=AssertionError("must refuse before output"),
        ):
            with self.assertRaises(gate.ProductionChildExecutorUnavailable):
                gate.execute_production_child(object(), object())


class BoundedExecutorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.invocation = gate._fixture_invocation()
        cls.result = gate.bounded_executor_self_check()
        cls.interrupted = gate.run_bounded(
            cls.invocation, stop_after="bind-invocation"
        )

    def test_native_child_is_frozen_and_assignment_free(self) -> None:
        observation = self.result["native_observation"]
        self.assertEqual(self.result["frozen_mismatches"], [])
        self.assertEqual(observation["rows"], 73_049)
        self.assertEqual(observation["wires"], 53_032)
        self.assertEqual(observation["external_assertions"], 0)
        self.assertEqual(observation["verification_failures"], 0)
        self.assertFalse(observation["assignment_materialized"])
        self.assertFalse(observation["engine_namespace_production_eligible"])

    def test_fresh_resume_and_negative_cases_pass(self) -> None:
        self.assertTrue(self.result["fresh_and_resume_identical"])
        self.assertTrue(self.result["state_mutation_rejected"])
        self.assertTrue(self.result["trailing_bytes_rejected"])
        self.assertTrue(self.result["wrong_invocation_rejected"])
        self.assertTrue(self.result["production_refused_before_output_or_trace"])
        self.assertEqual(
            self.result["fresh_state_sha256"], gate.FROZEN_BOUNDED_STATE_SHA256
        )
        self.assertEqual(
            self.result["fresh_result_sha256"], gate.FROZEN_BOUNDED_RESULT_SHA256
        )
        self.assertEqual(
            self.result["output_identity_sha256"],
            gate.FROZEN_BOUNDED_OUTPUT_IDENTITY_SHA256,
        )

    def test_state_is_canonical_prefix_and_rejects_wrong_cache_identity(self) -> None:
        cache_identity = gate._bounded_cache_identity(self.invocation)
        records = gate.decode_state(self.interrupted.state_raw, cache_identity)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["stage_id"], "bind-invocation")
        changed = dict(cache_identity)
        changed["statement_sha256"] = "0" * 64
        with self.assertRaises(gate.ChildExecutorError):
            gate.decode_state(self.interrupted.state_raw, changed)

    def test_state_rejects_noncontiguous_and_unknown_stage(self) -> None:
        cache_identity = gate._bounded_cache_identity(self.invocation)
        document = json.loads(self.interrupted.state_raw)
        document["completed_stage_ids"] = ["native-shard"]
        with self.assertRaises(gate.ChildExecutorError):
            gate.decode_state(gate.canonical_json(document), cache_identity)
        with self.assertRaises(gate.ChildExecutorError):
            gate.run_bounded(self.invocation, stop_after="unknown")

    def test_output_identity_codec_rejects_mutation_and_trailing_bytes(self) -> None:
        run = gate.run_bounded(self.invocation)
        assert run.evidence is not None
        raw = gate.canonical_json(run.evidence["output_identity"])
        decoded = gate.StageOutputIdentityV1.decode(raw)
        self.assertEqual(decoded.encode(), raw)
        self.assertEqual(
            gate.StageOutputIdentityV1.decode_for(
                raw,
                relation_id=gate.BOUNDED_RELATION_ID,
                profile_fingerprint=gate.BOUNDED_PROFILE,
                plan_sha256=decoded.plan_sha256,
                invocation_sha256=self.invocation.invocation_sha256,
                stage_id="bind-child-outputs",
            ),
            decoded,
        )
        document = json.loads(raw)
        document["relation_id"] = "wrong-domain"
        mutated = gate.canonical_json(document)
        with self.assertRaises(gate.ChildExecutorError):
            gate.StageOutputIdentityV1.decode_for(
                mutated,
                relation_id=gate.BOUNDED_RELATION_ID,
                profile_fingerprint=gate.BOUNDED_PROFILE,
                plan_sha256=decoded.plan_sha256,
                invocation_sha256=self.invocation.invocation_sha256,
                stage_id="bind-child-outputs",
            )
        with self.assertRaises(gate.ChildExecutorError):
            gate.StageOutputIdentityV1.decode(raw + b"\x00")
        document = json.loads(raw)
        document["unknown"] = 1
        with self.assertRaises(gate.ChildExecutorError):
            gate.StageOutputIdentityV1.decode(gate.canonical_json(document))

    def test_bounded_child_does_not_claim_full_i3_or_proof(self) -> None:
        self.assertFalse(self.result["formal_mask_matches_bounded_derived_mask"])
        self.assertFalse(self.result["full_i3_relation_claimed"])
        self.assertEqual(self.result["large_relation_rows_replayed"], 0)
        self.assertEqual(self.result["cryptographic_proofs_generated"], 0)
        self.assertFalse(self.result["assignment_or_row_archive_materialized"])


class ManifestAndEvidenceTests(unittest.TestCase):
    def test_manifest_keeps_production_and_security_claims_false(self) -> None:
        manifest = gate.build_manifest()
        claims = manifest["claim_status"]
        self.assertTrue(claims["Defined"])
        self.assertTrue(claims["Implemented"]["bounded_staged_executor"])
        self.assertFalse(claims["Implemented"]["production"])
        self.assertFalse(claims["Proof-closed"])
        self.assertFalse(claims["Production-closed"])
        self.assertFalse(claims["formal_pi_issue_generated"])
        self.assertFalse(claims["qualified_pq_se_backend_integrated"])
        self.assertIsNone(manifest["exact_commands"]["production_execution"])
        self.assertIsNone(manifest["exact_commands"]["large_replay"])
        self.assertIsNone(manifest["exact_commands"]["large_proving"])

    def test_external_inventory_is_read_only_and_missing_five(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            before = tuple(root.iterdir())
            report = gate.external_inventory_preflight(root)
            after = tuple(root.iterdir())
        self.assertEqual(before, after)
        self.assertFalse(report["safe_to_materialize_production_cache"])
        self.assertFalse(report["safe_to_start_large_replay"])
        self.assertFalse(report["safe_to_start_large_proving_run"])

    def test_tracked_manifest_and_evidence_are_canonical_and_path_free(self) -> None:
        manifest_path = ROOT / (
            "manifests/pq_rbbc_issuance_cap_child_executor_manifest_v1.json"
        )
        evidence_path = ROOT / (
            "artifacts/metadata/issuance_cap_child_executor_v1/"
            "pq_rbbc_issuance_cap_child_executor_portable_evidence_v1.json"
        )
        self.assertEqual(
            manifest_path.read_bytes(), gate.canonical_json(gate.build_manifest())
        )
        self.assertEqual(
            evidence_path.read_bytes(), gate.canonical_json(gate.build_portable_evidence())
        )
        evidence = json.loads(evidence_path.read_text(encoding="ascii"))
        self.assertFalse(evidence["portable_evidence_contains_absolute_paths"])
        self.assertFalse(evidence["historical_assignment_or_values_reused"])
        self.assertFalse(evidence["other_tree_observed_stream_bytes_used"])
        self.assertFalse(evidence["production_execution_started"])
        self.assertFalse(evidence["large_replay_started"])
        self.assertFalse(evidence["large_proving_started"])


if __name__ == "__main__":
    unittest.main()
