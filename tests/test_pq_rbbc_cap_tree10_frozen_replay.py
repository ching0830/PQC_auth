import unittest

import pq_rbbc_cap_tree10_frozen_replay as frozen
import pq_rbbc_cap_planned_tree_producer as planned


class Tree10FrozenReplayTests(unittest.TestCase):
    def test_frozen_contract_uses_only_tree10_observation(self) -> None:
        contract = frozen.frozen_contract()
        self.assertEqual(contract.tree_index, 10)
        self.assertEqual(contract.stream_bytes, 8_986_785_870)
        self.assertEqual(planned.contract_sha256(contract), frozen.FROZEN_CONTRACT_SHA256)

    def test_global_frozen_map_is_not_modified_by_import(self) -> None:
        self.assertNotIn(10, planned.FROZEN_STREAM_BYTES_BY_TREE)
        self.assertEqual(planned.FROZEN_STREAM_BYTES_BY_TREE[7], 8_961_160_824)


if __name__ == "__main__":
    unittest.main()
