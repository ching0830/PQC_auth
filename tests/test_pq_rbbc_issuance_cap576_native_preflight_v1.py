from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_production_namespace as namespace
import pq_rbbc_issuance_cap576_native_preflight_v1 as gate
import pq_rbbc_issuance_production_inputs_v1 as production_inputs


ROOT = Path(__file__).resolve().parents[1]


class ProductionRhoContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.randomness = cap.deterministic_randomness(
            cap.PRODUCTION_PARAMETERS,
            b"PQ-RBBC/ISSUANCE-CAP576-NATIVE-PREFLIGHT/TEST-RHO/V1",
        )
        cls.raw = cls.randomness.serialize(cap.PRODUCTION_PARAMETERS)

    def test_exact_width_profile_and_round_trip(self) -> None:
        snapshot = gate.capture_production_rho(self.raw)
        self.assertEqual(len(snapshot.raw), 1_036)
        self.assertEqual(snapshot.raw, self.raw)
        self.assertEqual(snapshot.randomness, self.randomness)
        self.assertEqual(snapshot.profile_fingerprint, gate.PRODUCTION_PROFILE)
        self.assertEqual(snapshot.sha256, hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(
            snapshot.randomness.serialize(cap.PRODUCTION_PARAMETERS), snapshot.raw
        )

    def test_snapshot_is_immutable_and_owns_one_copy(self) -> None:
        snapshot = gate.capture_production_rho(self.raw)
        self.assertIsNot(snapshot.raw, self.raw)
        with self.assertRaises(FrozenInstanceError):
            snapshot.raw = b""  # type: ignore[misc]
        with self.assertRaises(gate.NativePreflightError):
            gate.capture_production_rho(bytearray(self.raw))  # type: ignore[arg-type]

    def test_wrong_magic_profile_length_and_trailing_reject(self) -> None:
        magic = bytearray(self.raw)
        magic[0] ^= 1
        profile = bytearray(self.raw)
        profile[len(cap.RANDOMNESS_MAGIC)] ^= 1
        cases = (bytes(magic), bytes(profile), self.raw[:-1], self.raw + b"\x00")
        for candidate in cases:
            with self.subTest(length=len(candidate)):
                with self.assertRaises(gate.NativePreflightError):
                    gate.capture_production_rho(candidate)

    def test_wrong_tree_count_and_noncanonical_field_reject(self) -> None:
        layout = {item["field"]: item for item in gate.production_rho_layout()}
        count = bytearray(self.raw)
        count[int(layout["tree_count"]["byte_start"])] ^= 1
        field_value = bytearray(self.raw)
        field_value[int(layout["root[0][0]"]["byte_end_exclusive"]) - 1] |= 0x80
        for candidate in (bytes(count), bytes(field_value)):
            with self.assertRaises(gate.NativePreflightError):
                gate.capture_production_rho(candidate)

    def test_layout_is_closed_contiguous_and_exact(self) -> None:
        layout = gate.production_rho_layout()
        self.assertEqual(layout[0]["byte_start"], 0)
        self.assertEqual(layout[-1]["byte_end_exclusive"], gate.PRODUCTION_RHO_BYTES)
        self.assertEqual(len(layout), 5 + 2 * cap.PRODUCTION_PARAMETERS.tree_count)
        self.assertTrue(
            all(
                left["byte_end_exclusive"] == right["byte_start"]
                for left, right in zip(layout, layout[1:])
            )
        )


class PortAndHistoricalReuseTests(unittest.TestCase):
    def test_child_port_intervals_and_native_join_count(self) -> None:
        self.assertEqual(gate.validate_child_port_contract(), ())
        ports = {item["port_id"]: item for item in gate.PRODUCTION_CHILD_PORTS}
        self.assertEqual(ports["shared.message"]["wire_start"], 387)
        self.assertEqual(
            ports["global.phase-b.commitment"]["wire_start"], 40_084_506
        )
        self.assertEqual(
            ports["global.phase-b.derived-mask"]["wire_start"], 40_127_634
        )
        self.assertEqual(
            ports["global.phase-b.append-base"]["wire_start"], 40_128_210
        )
        self.assertEqual(
            ports["global.phase-b.request-hash"]["wire_start"], 40_194_018
        )
        self.assertEqual(
            sum(
                ports[name]["bit_length"]
                for name in (
                    "shared.message",
                    "global.phase-b.derived-mask",
                    "global.phase-b.request-hash",
                )
            ),
            1_408,
        )

    def test_namespace_accounting_matches_historical_plan(self) -> None:
        manifest = gate.build_manifest()
        reuse = manifest["historical_v2_29_reuse"]
        resources = manifest["resource_estimate"]
        self.assertEqual(namespace.FROZEN_PLANNED_COMPOSITION_ROWS, 586_057_567)
        self.assertEqual(reuse["historical_combined_rows"], 589_030_555)
        self.assertEqual(resources["historical_18_tree_combined_rows"], 589_030_555)
        self.assertFalse(reuse["historical_fixture_is_fresh_issuance_evidence"])

    def test_historical_evidence_identity_and_claim_boundary(self) -> None:
        self.assertEqual(gate.validate_v2_29_historical_evidence(), ())
        self.assertEqual(gate.validate_tracked_prerequisites(), ())

    def test_reuse_allowlist_refuses_values_assignments_and_stream_bytes(self) -> None:
        for kind in gate.HISTORICAL_REUSE_ALLOWED:
            self.assertTrue(gate.historical_reuse_permitted(kind))
        for kind in gate.HISTORICAL_REUSE_FORBIDDEN:
            self.assertFalse(gate.historical_reuse_permitted(kind))
        with self.assertRaises(gate.NativePreflightError):
            gate.historical_reuse_permitted("future-unknown-class")


class BoundedNativeShardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = gate.bounded_shard_self_check()

    def test_production_widths_with_tiny_explicitly_insecure_topology(self) -> None:
        self.assertEqual(
            self.result["production_widths"],
            {
                "mask_bits": 576,
                "appended_signature_bits": 1472,
                "witness_bits": 2048,
                "random_polynomial_bits": 2450,
            },
        )
        self.assertEqual(
            self.result["tiny_topology"],
            {"trees": 1, "leaves": 4, "extension_degree": 3},
        )
        self.assertTrue(self.result["test_only"])
        self.assertFalse(self.result["secure_profile"])

    def test_frozen_observation_has_no_external_assertion_or_assignment(self) -> None:
        self.assertEqual(self.result["frozen_mismatches"], [])
        self.assertEqual(self.result["first_observation"], gate.FROZEN_BOUNDED)
        self.assertEqual(self.result["large_relation_rows_replayed"], 0)
        self.assertEqual(self.result["cryptographic_proofs_generated"], 0)

    def test_rho_mutation_preserves_shape_but_changes_outputs(self) -> None:
        self.assertTrue(self.result["witness_independent_topology"])
        self.assertTrue(self.result["rho_mutation_changes_bound_outputs"])

    def test_legacy_engine_namespace_alias_is_not_promoted(self) -> None:
        self.assertTrue(self.result["engine_namespace_alias_detected"])
        self.assertEqual(
            self.result["engine_reported_relation_id"],
            "pq-rbbc/cap/production-tree-shard-2048/v1",
        )
        self.assertNotEqual(
            self.result["engine_reported_relation_id"], gate.BOUNDED_RELATION_ID
        )
        self.assertFalse(self.result["engine_namespace_production_eligible"])

    def test_production_refuses_before_decode_or_trace_construction(self) -> None:
        with patch.object(
            production_inputs, "decode_cap_randomness", side_effect=AssertionError
        ), patch.object(gate.shard, "build_streaming_shard", side_effect=AssertionError):
            with self.assertRaises(gate.ProductionNativeLoweringUnavailable):
                gate.execute_production_native_lowering(object(), object())


class ReadOnlyPreflightAndEvidenceTests(unittest.TestCase):
    def test_empty_external_root_reports_exact_five_missing_and_no_output(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            before = tuple(root.iterdir())
            report = gate.read_only_preflight(root)
            after = tuple(root.iterdir())
        self.assertEqual(before, after)
        self.assertEqual(
            report["production_input_report"]["missing_artifacts"],
            list(production_inputs.REQUIRED_EXTERNAL_ARTIFACTS),
        )
        self.assertFalse(report["safe_to_start_large_replay"])
        self.assertFalse(report["safe_to_start_large_proving_run"])
        self.assertFalse(report["formal_pi_issue_generated"])
        self.assertFalse(report["output_created"])

    def test_manifest_keeps_all_production_and_security_claims_false(self) -> None:
        manifest = gate.build_manifest()
        claims = manifest["claim_status"]
        self.assertTrue(claims["Defined"])
        self.assertTrue(claims["Implemented"]["bounded_native_lowering"])
        self.assertFalse(claims["Implemented"]["production"])
        self.assertFalse(claims["Proof-closed"])
        self.assertFalse(claims["Production-closed"])
        self.assertFalse(claims["qualified_pq_se_backend_integrated"])
        self.assertFalse(claims["formal_pi_issue_generated"])
        self.assertIsNone(manifest["exact_commands"]["large_replay"])
        self.assertIsNone(manifest["exact_commands"]["large_proving"])
        self.assertFalse(
            manifest["resource_estimate"]["other_tree_observed_stream_bytes_used"]
        )

    def test_manifest_and_portable_evidence_are_canonical_and_path_free(self) -> None:
        manifest_path = (
            ROOT / "manifests/pq_rbbc_issuance_cap576_native_preflight_manifest_v1.json"
        )
        evidence_path = (
            ROOT
            / "artifacts/metadata/issuance_cap576_native_preflight_v1/"
            "pq_rbbc_issuance_cap576_native_preflight_portable_evidence_v1.json"
        )
        self.assertEqual(manifest_path.read_bytes(), gate.canonical_json(gate.build_manifest()))
        self.assertEqual(
            evidence_path.read_bytes(), gate.canonical_json(gate.build_portable_evidence())
        )
        evidence = json.loads(evidence_path.read_text(encoding="ascii"))
        self.assertFalse(evidence["portable_evidence_contains_absolute_paths"])
        self.assertFalse(evidence["historical_assignment_or_values_reused"])
        self.assertFalse(evidence["other_tree_observed_stream_bytes_used"])
        self.assertFalse(evidence["large_replay_started"])
        self.assertFalse(evidence["large_proving_started"])


if __name__ == "__main__":
    unittest.main()
