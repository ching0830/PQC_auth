from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import pq_rbbc_issuance_global_tail_continuation_preflight_v1 as gate


ROOT = Path(__file__).resolve().parents[1]


class StaticTailLayoutTests(unittest.TestCase):
    def test_exact_bounded_partition_and_boundary_wires(self) -> None:
        layout = gate.derive_tail_layout()
        self.assertEqual(
            (
                layout.input_wire_start,
                layout.input_wire_end,
                layout.phase_a_wire_start,
                layout.phase_a_wire_end,
                layout.phase_b_wire_start,
                layout.phase_b_wire_end,
            ),
            (1, 10_915, 10_915, 23_094, 23_094, 43_837),
        )
        self.assertEqual(
            (
                layout.input_rows,
                layout.phase_a_row_start,
                layout.phase_a_row_end,
                layout.phase_b_row_start,
                layout.phase_b_row_end,
            ),
            (10_914, 10_914, 30_585, 30_585, 66_079),
        )
        self.assertEqual(layout.h1_wire_start, 20_655)
        self.assertEqual(layout.point_wire_starts, (22_705, 22_898))
        self.assertEqual(layout.h2_wire_start, 29_596)
        self.assertEqual(layout.commitment_wire_start, 29_982)
        self.assertEqual(layout.derived_mask_wire_start, 34_070)
        self.assertEqual(layout.append_base_wire_start, 34_646)
        self.assertEqual(layout.request_hash_wire_start, 43_258)

    def test_input_ports_are_ordered_contiguous_and_match_prelude(self) -> None:
        ports = gate.tail_input_ports()
        self.assertEqual(len(ports), 10)
        self.assertEqual(ports[0]["wire_start"], 1)
        self.assertEqual(ports[-1]["wire_end_exclusive"], 10_915)
        self.assertTrue(
            all(
                left["wire_end_exclusive"] == right["wire_start"]
                for left, right in zip(ports, ports[1:])
            )
        )
        expected = {
            "shared.salt": (1, 386),
            "shared.message": (387, 256),
            "tree[0].leaf-commitments": (643, 1_544),
            "tree[0].p-plain": (2_187, 2_048),
            "tree[0].mhat-plain": (4_235, 386),
            "tree[0].xi-masks": (4_621, 1_158),
            "tree[1].leaf-commitments": (5_779, 1_544),
            "tree[1].p-plain": (7_323, 2_048),
            "tree[1].mhat-plain": (9_371, 386),
            "tree[1].xi-masks": (9_757, 1_158),
        }
        self.assertEqual(
            {
                port["port_id"]: (port["wire_start"], port["bit_length"])
                for port in ports
            },
            expected,
        )

    def test_phase_outputs_and_fan_in_are_exact(self) -> None:
        ports = {port["port_id"]: port for port in gate.boundary_ports()}
        self.assertEqual(
            {
                name: (port["wire_start"], port["bit_length"])
                for name, port in ports.items()
            },
            {
                "global.phase-a.h1": (20_655, 386),
                "global.phase-a.consistency-points": (22_705, 386),
                "global.phase-b.commitment": (29_982, 4_088),
                "global.phase-b.derived-mask": (34_070, 576),
                "global.phase-b.append-base": (34_646, 1_472),
                "global.phase-b.request-hash": (43_258, 576),
            },
        )
        contract = gate.build_contract()
        phase_a, phase_b = contract["phases"]
        self.assertEqual(len(phase_a["input_port_ids"]), 6)
        self.assertEqual(len(phase_b["input_port_ids"]), 10)
        self.assertEqual(
            contract["relocation_contract"],
            {
                "pre_ports_before_global_a": 6,
                "xi_ports_before_global_b": 2,
                "total_ports_before_global_b": 8,
                "source_and_target_values_must_be_bound_by_native_equalities": True,
                "hash_only_binding_permitted": False,
            },
        )
        snapshots = contract["continuation_snapshot_contract"]
        self.assertNotIn("receipt_chain_required", snapshots)
        self.assertEqual(
            snapshots["global_a_verified_receipt_prefix_ordinals"], [0, 1, 2]
        )
        self.assertEqual(
            snapshots["global_a_verified_receipt_prefix_identities"],
            list(gate.VERIFIED_RECEIPT_PREFIX_IDENTITIES),
        )
        self.assertTrue(
            snapshots["all_declared_receipt_snapshots_require_raw_validation"]
        )
        self.assertFalse(snapshots["full_execution_receipt_chain_verified"])
        fan_in = contract["serial_fan_in_contract"]
        self.assertEqual(fan_in["shared_overlap_ordinal"], 2)
        self.assertEqual(
            {
                key: fan_in["scheduler_verified_receipt_suffix_identities"][0][key]
                for key in ("bytes", "sha256")
            },
            {
                key: gate.VERIFIED_RECEIPT_PREFIX_IDENTITIES[2][key]
                for key in ("bytes", "sha256")
            },
        )
        self.assertFalse(fan_in["global_b_candidate_set_implemented"])


class ContractEncodingTests(unittest.TestCase):
    def test_canonical_contract_round_trip(self) -> None:
        expected = gate.build_contract()
        raw = gate.canonical_json(expected)
        self.assertEqual(gate.validate_contract_bytes(raw), expected)
        self.assertLessEqual(len(raw), gate.CONTRACT_MAX_BYTES)

    def test_wrong_version_domain_interval_and_unknown_field_reject(self) -> None:
        cases = []
        for path, value in (
            (("format",), gate.CONTRACT_FORMAT + "-WRONG"),
            (("relation_id",), "pq-rbbc/wrong-domain/v1"),
            (("plan_sha256",), "0" * 64),
            (("phases", 0, "wire_interval"), [10_916, 23_094]),
        ):
            document = deepcopy(gate.build_contract())
            target = document
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            cases.append(gate.canonical_json(document))
        unknown = deepcopy(gate.build_contract())
        unknown["future"] = True
        cases.append(gate.canonical_json(unknown))
        for raw in cases:
            with self.subTest(raw=raw[:80]), self.assertRaises(gate.PreflightError):
                gate.validate_contract_bytes(raw)

    def test_trailing_duplicate_noncanonical_and_oversize_reject(self) -> None:
        raw = gate.canonical_json(gate.build_contract())
        candidates = (
            raw + b"\x00",
            raw[:-1] + b" \n",
            b'{"format":"x","format":"y"}\n',
            b"x" * (gate.CONTRACT_MAX_BYTES + 1),
            bytearray(raw),
        )
        for candidate in candidates:
            with self.subTest(length=len(candidate)), self.assertRaises(
                gate.PreflightError
            ):
                gate.validate_contract_bytes(candidate)  # type: ignore[arg-type]


class ReadOnlyPreflightTests(unittest.TestCase):
    def test_tracked_predecessors_and_adapter_plan_match(self) -> None:
        self.assertEqual(gate.validate_prerequisites(), ())
        manifest = gate._adapter_manifest()
        self.assertEqual(manifest["plan"], gate.EXPECTED_PLAN)
        scheduler_manifest = gate._scheduler_manifest()
        self.assertEqual(scheduler_manifest["implementation_version"], "1.2")

    def test_preflight_separates_implementation_from_execution(self) -> None:
        report = gate.preflight()
        self.assertTrue(report["read_only_preflight_passed"])
        self.assertTrue(report["phase_a_contract_defined"])
        self.assertTrue(report["phase_b_contract_defined"])
        self.assertEqual(report["global_a_verified_receipt_prefix_ordinals"], [0, 1, 2])
        self.assertEqual(report["scheduler_verified_receipt_suffix_ordinals"], [2, 3])
        self.assertEqual(report["receipt_prefix_suffix_overlap_ordinal"], 2)
        self.assertFalse(report["full_execution_receipt_chain_verified"])
        self.assertTrue(report["global_b_same_invocation_fan_in_defined"])
        self.assertFalse(report["global_b_same_invocation_candidate_set_implemented"])
        self.assertTrue(report["safe_to_implement_next_bounded_gate"])
        self.assertFalse(report["independent_global_a_consumer_implemented"])
        self.assertFalse(report["independent_global_b_consumer_implemented"])
        self.assertFalse(report["safe_to_execute_bounded_continuation"])
        self.assertFalse(report["safe_to_start_large_replay"])
        self.assertFalse(report["safe_to_start_large_proving_run"])
        self.assertEqual(report["bounded_rows_replayed"], 0)
        self.assertEqual(report["proofs_generated"], 0)
        self.assertEqual(len(report["missing_production_artifacts"]), 5)

    def test_execution_entrypoints_refuse_before_relation_construction(self) -> None:
        with patch.object(
            gate.adapter, "build_reference_insecure_test_only", side_effect=AssertionError
        ), patch.object(
            gate.native,
            "_iter_tail_native_insecure_test_only",
            side_effect=AssertionError,
        ):
            with self.assertRaises(gate.ContinuationUnavailable):
                gate.execute_bounded_global_tail_continuation(object())
            with self.assertRaises(gate.ContinuationUnavailable):
                gate.execute_production(object())

    def test_snapshot_contract_keeps_filesystem_claim_bounded(self) -> None:
        snapshot = gate.build_contract()["continuation_snapshot_contract"]
        self.assertTrue(snapshot["single_open_single_bounded_read"])
        self.assertTrue(snapshot["same_raw_for_identity_parse_binding_and_consumer"])
        self.assertFalse(snapshot["candidate_pathname_reopen_permitted"])
        self.assertFalse(snapshot["metadata_proves_no_writer"])
        self.assertTrue(snapshot["trusted_producer_handoff_and_writer_quiescence_external"])

    def test_manifest_and_evidence_are_canonical_and_claim_closed(self) -> None:
        manifest_path = ROOT / gate.MANIFEST_PATH
        evidence_path = ROOT / gate.EVIDENCE_PATH
        self.assertEqual(manifest_path.read_bytes(), gate.canonical_json(gate.build_manifest()))
        self.assertEqual(
            evidence_path.read_bytes(), gate.canonical_json(gate.build_portable_evidence())
        )
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
        claims = manifest["claim_status"]
        self.assertTrue(claims["Defined"])
        self.assertFalse(claims["Instantiated"])
        self.assertFalse(claims["global_tail_continuation_implemented"])
        self.assertFalse(claims["Proof-closed"])
        self.assertFalse(claims["Production-closed"])
        self.assertFalse(claims["full_execution_receipt_chain_verified"])
        self.assertFalse(claims["global_b_same_invocation_candidate_set_implemented"])
        commands = manifest["exact_commands"]
        self.assertIsNone(commands["bounded_continuation"])
        self.assertIsNone(commands["large_replay"])
        self.assertIsNone(commands["large_proving"])
        self.assertFalse(
            manifest["resource_budget"]["other_tree_observed_stream_bytes_used"]
        )
        evidence = json.loads(evidence_path.read_text(encoding="ascii"))
        self.assertFalse(evidence["private_values_or_assignment_embedded"])
        self.assertFalse(evidence["bounded_continuation_started"])
        self.assertFalse(evidence["large_replay_started"])
        self.assertFalse(evidence["large_proving_started"])


if __name__ == "__main__":
    unittest.main()
