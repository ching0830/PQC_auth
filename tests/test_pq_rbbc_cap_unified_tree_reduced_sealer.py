import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pq_rbbc_cap_unified_tree_reduced_sealer as sealer


ROOT = Path(__file__).resolve().parents[1]
EXTERNAL_ROOT = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/v2_33_unified_tree_migration"
)
ARGS = (
    EXTERNAL_ROOT / "pq_rbbc_cap_unified_tree_spec_v2_33.pdf",
    EXTERNAL_ROOT / "reduced/pq_rbbc_cap_unified_tree_reduced_evidence_v2_33.json",
    EXTERNAL_ROOT / "reduced/pq_rbbc_cap_unified_tree_runner_qualification_v2_33.json",
    EXTERNAL_ROOT / "pq_rbbc_cap_unified_tree_environment_after_reduced_v2_33.json",
)
SEALED = (
    ROOT
    / "artifacts/metadata/cap_unified_tree_migration_v2_33/"
    "pq_rbbc_cap_unified_tree_reduced_portable_evidence_v2_33.json"
)


class UnifiedTreeReducedSealerTests(unittest.TestCase):
    def test_portable_evidence_matches_generator(self) -> None:
        if not all(path.is_file() for path in ARGS):
            self.skipTest("external v2.33 reduced artifacts are not installed")
        self.assertEqual(
            SEALED.read_bytes(), sealer.canonical_json(sealer.build_evidence(*ARGS))
        )

    def test_portable_evidence_is_path_free_and_bounded(self) -> None:
        document = json.loads(SEALED.read_text())
        encoded = SEALED.read_bytes()
        self.assertNotIn(b"/tmp/", encoded)
        self.assertNotIn(b"/home/", encoded)
        claims = document["claim_boundary"]
        self.assertTrue(claims["exact_unified_tree_specification_authored"])
        self.assertTrue(claims["reduced_unified_tree_implemented_and_verified"])
        self.assertTrue(claims["reduced_runner_qualified"])
        for name in (
            "production_profile_implemented",
            "production_prefreeze_started",
            "large_replay_started",
            "large_proving_run_started",
            "cap_security_qualified",
            "production_closed",
        ):
            self.assertFalse(claims[name], name)

    def test_mutated_reduced_evidence_is_rejected(self) -> None:
        if not all(path.is_file() for path in ARGS):
            self.skipTest("external v2.33 reduced artifacts are not installed")
        original = json.loads(ARGS[1].read_text())
        original["mutation_vectors"][0]["rejected"] = False
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ARGS[1].name
            path.write_text(json.dumps(original, sort_keys=True, separators=(",", ":")) + "\n")
            replacement = (
                path.name,
                path.stat().st_size,
                sealer._sha256(path),
            )
            external = dict(sealer.EXTERNAL)
            external["reduced_evidence"] = replacement
            with patch.object(sealer, "EXTERNAL", external):
                with self.assertRaisesRegex(ValueError, "result mismatch"):
                    sealer.build_evidence(ARGS[0], path, ARGS[2], ARGS[3])


if __name__ == "__main__":
    unittest.main()
