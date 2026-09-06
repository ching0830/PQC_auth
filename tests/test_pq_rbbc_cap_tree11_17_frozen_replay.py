import unittest

import pq_rbbc_cap_planned_tree_producer as planned
import pq_rbbc_cap_tree11_17_frozen_replay as frozen


class Tree11To17FrozenReplayTests(unittest.TestCase):
    def test_tree11_contract_uses_only_tree11_observation(self) -> None:
        contract = frozen.frozen_contract(11)
        self.assertEqual(contract.tree_index, 11)
        self.assertEqual(contract.stream_bytes, 8_986_785_870)
        self.assertEqual(
            planned.contract_sha256(contract), frozen.EXPECTED[11]["contract"]
        )

    def test_import_does_not_mutate_global_frozen_map(self) -> None:
        for tree_index in range(11, 18):
            self.assertNotIn(tree_index, planned.FROZEN_STREAM_BYTES_BY_TREE)


if __name__ == "__main__":
    unittest.main()
