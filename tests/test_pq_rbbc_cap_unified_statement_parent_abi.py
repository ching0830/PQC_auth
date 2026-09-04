import copy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

import pq_rbbc_cap_prove_verify as legacy
import pq_rbbc_cap_unified_statement_parent_abi as abi


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = (
    ROOT / "manifests/pq_rbbc_cap_unified_statement_parent_abi_manifest_v2_37.json"
)
EXTERNAL = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/"
    "v2_37_unified_statement_parent_abi/qualification"
)
CHECKPOINT = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/"
    "v2_36_unified_tree_relation/qualification/"
    "pq_rbbc_cap_unified_tree_checkpoint_payload_v2_36.json"
)


class UnifiedStatementParentABITests(unittest.TestCase):
    def test_manifest_is_exact_and_separate_from_legacy_profile(self) -> None:
        self.assertEqual(MANIFEST.read_bytes(), abi.canonical_json(abi.build_manifest()))
        document = abi.validate_manifest(MANIFEST)
        self.assertTrue(document["namespace"]["legacy_18_tree_profile_preserved"])
        self.assertFalse(
            document["namespace"]["legacy_v2_32_statement_codec_overwritten"]
        )
        self.assertNotEqual(legacy.PROFILE_FINGERPRINT, abi.PRODUCTION_PROFILE_FINGERPRINT)

    def test_statement_profiles_round_trip_and_cross_decode_rejects(self) -> None:
        for fingerprint in (
            abi.PRODUCTION_PROFILE_FINGERPRINT,
            abi.BOUNDED_PROFILE_FINGERPRINT,
        ):
            statement = abi.fixture_statement(fingerprint)
            encoded = statement.encode()
            self.assertEqual(
                abi.UnifiedCAPStatement.decode(
                    encoded, expected_profile_fingerprint=fingerprint
                ),
                statement,
            )
            other = (
                abi.BOUNDED_PROFILE_FINGERPRINT
                if fingerprint == abi.PRODUCTION_PROFILE_FINGERPRINT
                else abi.PRODUCTION_PROFILE_FINGERPRINT
            )
            with self.assertRaises(abi.UnifiedStatementABIError):
                abi.UnifiedCAPStatement.decode(
                    encoded, expected_profile_fingerprint=other
                )

    def test_bounded_parent_maps_exact_ticket_and_checkpoint_commitment(self) -> None:
        c_r = abi.load_bounded_commitment(CHECKPOINT)
        statement = abi.fixture_statement(abi.BOUNDED_PROFILE_FINGERPRINT)
        parent = abi.UnifiedParentInput.create(
            abi.BOUNDED_PROFILE_FINGERPRINT,
            statement.encode(),
            c_r,
            abi.fixture_ticket_message(),
        )
        abi.validate_bounded_parent_mapping(parent, c_r)
        self.assertEqual(abi.UnifiedParentInput.decode(parent.encode()), parent)
        changed_ticket = bytes([parent.ticket_message[0] ^ 1]) + parent.ticket_message[1:]
        rebound = abi.UnifiedParentInput.create(
            parent.profile_fingerprint, parent.statement, parent.c_r, changed_ticket
        )
        with self.assertRaises(abi.UnifiedStatementABIError):
            abi.validate_bounded_parent_mapping(rebound, c_r)

    def test_all_qualification_mutations_reject(self) -> None:
        c_r = abi.load_bounded_commitment(CHECKPOINT)
        statement = abi.fixture_statement(abi.BOUNDED_PROFILE_FINGERPRINT)
        parent = abi.UnifiedParentInput.create(
            abi.BOUNDED_PROFILE_FINGERPRINT,
            statement.encode(),
            c_r,
            abi.fixture_ticket_message(),
        )
        checks = abi.mutation_checks(statement, parent)
        self.assertEqual(len(checks), 16)
        self.assertTrue(all(checks.values()))

    def test_external_artifacts_are_exact_and_bounded(self) -> None:
        identities = {
            abi.PRODUCTION_VECTOR_FILENAME: {
                "filename": abi.PRODUCTION_VECTOR_FILENAME,
                "bytes": 1_569,
                "sha256": "23f811f1eba9686d8f3fcea20a9d871160ec636c2f462073cf7064a0821c08e6",
            },
            abi.BOUNDED_VECTOR_FILENAME: {
                "filename": abi.BOUNDED_VECTOR_FILENAME,
                "bytes": 3_062,
                "sha256": "655e3969695b8015a83b1dad29f98c98b15c2f59d41c3890901bd23da62365ff",
            },
            abi.EVIDENCE_FILENAME: {
                "filename": abi.EVIDENCE_FILENAME,
                "bytes": 2_279,
                "sha256": "77f5c9c175c245233707f7c0f16377047f630633f46d2cd0a167ffb938112a78",
            },
            abi.QUALIFICATION_FILENAME: {
                "filename": abi.QUALIFICATION_FILENAME,
                "bytes": 3_163,
                "sha256": "e87d3cf29429ba5b60b1f1bd85e35c386275e7edd7902f779b910282ad840dce",
            },
        }
        for filename, expected in identities.items():
            self.assertEqual(abi.identity(EXTERNAL / filename), expected)
        production = json.loads((EXTERNAL / abi.PRODUCTION_VECTOR_FILENAME).read_text())
        bounded = json.loads((EXTERNAL / abi.BOUNDED_VECTOR_FILENAME).read_text())
        evidence = json.loads((EXTERNAL / abi.EVIDENCE_FILENAME).read_text())
        qualification = json.loads(
            (EXTERNAL / abi.QUALIFICATION_FILENAME).read_text()
        )
        abi.validate_production_vector(production)
        abi.validate_bounded_vector(bounded, abi.load_bounded_commitment(CHECKPOINT))
        self.assertTrue(production["test_vector_only"])
        self.assertFalse(production["production_tree_executed"])
        self.assertTrue(bounded["bounded_fixture_only"])
        self.assertFalse(bounded["production_observation"])
        self.assertEqual(evidence["observations"]["production_leaves_expanded"], 0)
        self.assertTrue(all(qualification["checks"].values()))
        self.assertTrue(
            qualification["result"]["bounded_parent_input_abi_qualified"]
        )
        for gate in (
            "production_parent_input_qualified",
            "safe_to_start_production_prefreeze",
            "safe_to_start_large_replay",
            "safe_to_start_large_proving_run",
        ):
            self.assertFalse(qualification["result"][gate], gate)

    def test_vector_and_claim_mutations_fail_closed(self) -> None:
        production = json.loads((EXTERNAL / abi.PRODUCTION_VECTOR_FILENAME).read_text())
        changed = copy.deepcopy(production)
        changed["logical_fields"]["rid"] = "00" * 32
        with self.assertRaises(abi.UnifiedStatementABIError):
            abi.validate_production_vector(changed)
        claims = abi.claim_boundary()
        self.assertTrue(claims["v2_37_unified_statement_codec_implemented"])
        self.assertTrue(claims["v2_37_parent_input_abi_implemented"])
        self.assertFalse(claims["v2_37_bounded_parent_input_qualified"])
        for name in (
            "production_parent_commitment_materialized",
            "production_parent_envelope_materialized",
            "production_parent_join_replayed",
            "production_prefreeze_authorized",
            "production_prefreeze_started",
            "large_replay_started",
            "large_proving_run_started",
            "system_architecture_changed",
            "ticket_lifecycle_changed",
            "pq_sat_auth_changed",
            "production_closed",
        ):
            self.assertFalse(claims[name], name)

    def test_production_branch_rejects_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "must-not-exist"
            with self.assertRaisesRegex(RuntimeError, "production-prefreeze unavailable"):
                abi.reject_production_prefreeze(
                    MANIFEST, Path(directory) / "missing-checkpoint.json", output
                )
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
