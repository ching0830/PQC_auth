import shutil
import tempfile
import unittest
from pathlib import Path

import pq_rbbc_trace_kdf_source_transition as transition


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/pq_rbbc_trace_kdf_source_transition_manifest_v2_40.json"


class TraceKDFSourceTransitionTests(unittest.TestCase):
    def test_frozen_manifest_matches_generator(self) -> None:
        self.assertEqual(
            MANIFEST.read_bytes(),
            transition.canonical_json(transition.build_transition_manifest()),
        )

    def test_current_tree_is_exact_canonical_successor(self) -> None:
        self.assertEqual(transition.validate_current_tree(ROOT), ())

    def test_historical_and_canonical_identities_are_distinct(self) -> None:
        for label in transition.CANONICAL_IDENTITIES:
            with self.subTest(label=label):
                historical = transition.HISTORICAL_IDENTITIES[label]
                canonical = transition.CANONICAL_IDENTITIES[label]
                self.assertNotEqual(historical["sha256"], canonical["sha256"])
                self.assertNotEqual(historical["bytes"], canonical["bytes"])

    def test_unknown_source_identity_is_rejected(self) -> None:
        expected = transition.CANONICAL_IDENTITIES["reference_source"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pq_rbbc_reference.py"
            path.write_bytes((ROOT / str(expected["path"])).read_bytes() + b"\n")
            self.assertFalse(transition.identity_matches(path, expected))

    def test_one_mutated_successor_invalidates_the_complete_transition(self) -> None:
        expected_manifest = (MANIFEST.stat().st_size, transition._sha256(MANIFEST))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for expected in transition.CANONICAL_IDENTITIES.values():
                relative = Path(str(expected["path"]))
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            reference_source = root / str(
                transition.CANONICAL_IDENTITIES["reference_source"]["path"]
            )
            reference_source.write_bytes(reference_source.read_bytes() + b"\n")
            failures = transition.validate_transition(
                MANIFEST, expected_manifest, root
            )
        self.assertEqual(failures, ("reference_source_identity",))

    def test_transition_contract_is_fail_closed_and_conservative(self) -> None:
        document = transition.build_transition_manifest()
        split = document["canonical_split"]
        self.assertEqual(split["ordering"], "Z = P || K_mac")
        self.assertEqual(split["pad"]["offset"], [0, 48])
        self.assertEqual(split["mac_key"]["offset"], [48, 80])
        claims = document["claim_boundary"]
        self.assertTrue(claims["source_transition_contract_closed"])
        self.assertTrue(claims["canonical_trace_kdf_split_implemented_and_tested"])
        self.assertFalse(claims["historical_v2_29_v2_30_evidence_rewritten"])
        self.assertFalse(claims["production_opening_implemented"])
        self.assertFalse(claims["qualified_pq_se_nizk_backend_selected"])
        self.assertFalse(claims["fork_security_proof_revalidated"])
        self.assertFalse(claims["production_closed"])

    def test_manifest_mutation_is_rejected(self) -> None:
        expected = (MANIFEST.stat().st_size, transition._sha256(MANIFEST))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / MANIFEST.name
            path.write_bytes(MANIFEST.read_bytes() + b" ")
            failures = transition.validate_transition(path, expected, ROOT)
        self.assertIn("transition_manifest_identity", failures)


if __name__ == "__main__":
    unittest.main()
