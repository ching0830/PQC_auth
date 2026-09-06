import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs/proof/source/pq_rbbc_cap_unified_tree_spec_v2_33.html"


class UnifiedTreeSpecificationTests(unittest.TestCase):
    def test_specification_freezes_required_algorithms_and_boundaries(self) -> None:
        text = SPEC.read_text()
        for required in (
            "π(α,i)",
            "40,959",
            "PQRBBC-CAP-UGGM-COMMIT-V1",
            "PQRBBC-CAP-UGGM-OPEN-V1",
            "LSB-first",
            "T<sub>open</sub>",
            "Canonical minimal frontier",
            "Verify algorithm",
            "Production parameters are present",
        ):
            self.assertIn(required, text)
        self.assertIn("does not modify or replace the legacy 18-root profile", text)
        self.assertIn("does not authorize production", text)


if __name__ == "__main__":
    unittest.main()
