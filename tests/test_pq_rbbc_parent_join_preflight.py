import copy
import json
import tempfile
import unittest
from pathlib import Path

import pq_rbbc_parent_join_preflight as preflight


ROOT = Path(__file__).resolve().parents[1]


class ParentJoinPreflightTests(unittest.TestCase):
    def test_frozen_manifest_matches_generator(self) -> None:
        path = ROOT / "manifests/pq_rbbc_parent_join_preflight_manifest_v2_29.json"
        self.assertEqual(path.read_bytes(), preflight.canonical_json(
            preflight.build_frozen_manifest()
        ))

    def test_tracked_contracts_are_exact(self) -> None:
        self.assertEqual(preflight.validate_tracked_contracts(), ())

    def test_frozen_contract_is_fail_closed(self) -> None:
        document = preflight.build_frozen_manifest()
        self.assertEqual(document["join_contract"]["planned_join_rows"], 1_408)
        self.assertEqual(
            document["join_contract"]["planned_join_wires"], 2_980_302
        )
        self.assertEqual(
            document["join_contract"]["planned_parent_wire_interval"],
            [429_757_233, 432_737_534],
        )
        self.assertEqual(document["legacy_parent"]["archive"]["external_assertions"], 1)
        claims = document["claim_boundary"]
        self.assertTrue(claims["parent_join_preflight_contract_closed"])
        self.assertTrue(claims["v2_28_aggregate_prerequisite_verified"])
        self.assertTrue(claims["parent_join_runner_implemented"])
        self.assertTrue(claims["parent_join_accounting_frozen"])
        self.assertFalse(claims["parent_cap_to_h_rbbc_join_closed"])
        self.assertFalse(claims["fork_security_proof_revalidated"])
        self.assertFalse(claims["production_closed"])

    def test_current_parent_fixture_is_not_aggregate_bound(self) -> None:
        compatibility = preflight.current_fixture_compatibility()
        self.assertFalse(compatibility["all_join_values_match"])
        for name in ("message", "derived_mask", "h_rbbc_hash_image"):
            self.assertFalse(compatibility[name]["exact_match"], name)

    def test_source_port_mutation_is_rejected(self) -> None:
        split = json.loads((
            ROOT
            / "artifacts/metadata/production_split_v2_12"
            / "pq_rbbc_cap_production_split_tail_manifest_v2_12.json"
        ).read_text())
        tail = json.loads((
            ROOT / "manifests/pq_rbbc_cap_global_tail_manifest_v2_9.json"
        ).read_text())
        self.assertEqual(preflight.validate_source_ports(split, tail), ())
        changed = copy.deepcopy(split)
        changed["phase_contract"]["boundary_ports"][2]["bit_length"] += 1
        self.assertIn(
            "global.phase-b.commitment_contract",
            preflight.validate_source_ports(changed, tail),
        )

    def test_missing_artifacts_do_not_start_replay(self) -> None:
        report = preflight.build_environment_report(
            None, None, None, None, 128_000_000_000, 32_000_000_000
        )
        self.assertFalse(report["safe_to_start_large_replay"])
        self.assertFalse(report["large_replay_started"])
        self.assertIsNone(report["exact_execution_command"])
        self.assertIn("parent_join_prefreeze", report["blockers"])
        self.assertIn("trusted_local_execution_cache", report["blockers"])

    def test_unfrozen_artifact_is_never_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate"
            path.write_bytes(b"candidate")
            result = preflight._unfrozen_identity(path)
            self.assertFalse(result["verified"])
            self.assertEqual(result["failures"], ["identity_not_frozen"])


if __name__ == "__main__":
    unittest.main()
