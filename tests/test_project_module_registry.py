import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "manifests" / "project_module_registry_v0_1.json"
EXPECTED_SLUGS = {"system", "issuance", "opening", "access", "lifecycle", "threshold", "evaluation"}
STATUS_FIELDS = {"defined", "implemented", "tested", "evidence_sealed", "proof_closed", "production_closed"}


class ProjectModuleRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY.read_bytes())

    def test_closed_top_level_contract(self) -> None:
        self.assertEqual(set(self.registry), {"schema", "version", "source_checkpoints", "status_fields", "modules"})
        self.assertEqual(self.registry["schema"], "pqc-auth/project-module-registry/v1")
        self.assertEqual(self.registry["version"], 1)
        self.assertEqual(set(self.registry["status_fields"]), STATUS_FIELDS)

    def test_modules_are_unique_and_complete(self) -> None:
        modules = self.registry["modules"]
        slugs = [module["slug"] for module in modules]
        self.assertEqual(set(slugs), EXPECTED_SLUGS)
        self.assertEqual(len(slugs), len(set(slugs)))
        expected_fields = {"slug", "architecture_ids", "entry_document", "source_paths", "test_paths", "status"}
        for module in modules:
            self.assertEqual(set(module), expected_fields)

    def test_all_registered_paths_exist_inside_repository(self) -> None:
        for module in self.registry["modules"]:
            paths = [module["entry_document"], *module["source_paths"], *module["test_paths"]]
            for value in paths:
                path = Path(value)
                self.assertFalse(path.is_absolute(), value)
                self.assertNotIn("..", path.parts, value)
                self.assertTrue((ROOT / path).exists(), value)

    def test_claim_boundary_is_explicit_and_conservative(self) -> None:
        for module in self.registry["modules"]:
            status = module["status"]
            self.assertEqual(set(status), STATUS_FIELDS)
            self.assertTrue(all(isinstance(value, bool) for value in status.values()))
            self.assertFalse(status["production_closed"], module["slug"])

    def test_checkpoint_identities_are_full_lowercase_hex(self) -> None:
        for name, commit in self.registry["source_checkpoints"].items():
            with self.subTest(name=name):
                self.assertEqual(len(commit), 40)
                self.assertEqual(commit, commit.lower())
                self.assertTrue(all(character in "0123456789abcdef" for character in commit))


if __name__ == "__main__":
    unittest.main()
