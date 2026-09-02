import unittest

import pq_rbbc_cap_tree9_frozen_replay as frozen
import pq_rbbc_cap_planned_tree_producer as planned


class Tree9FrozenReplayTests(unittest.TestCase):
    def test_frozen_contract_uses_tree9_observation(self) -> None:
        contract = frozen.frozen_contract()
        self.assertEqual(contract.tree_index, 9)
        self.assertEqual(contract.stream_bytes, 8_961_160_824)
        self.assertEqual(planned.contract_sha256(contract), frozen.FROZEN_CONTRACT_SHA256)

    def test_other_tree_observations_are_not_changed(self) -> None:
        self.assertNotIn(9, planned.FROZEN_STREAM_BYTES_BY_TREE)
        self.assertNotIn(8, planned.FROZEN_STREAM_BYTES_BY_TREE)
        self.assertEqual(planned.FROZEN_STREAM_BYTES_BY_TREE[7], 8_961_160_824)


if __name__ == "__main__":
    unittest.main()
