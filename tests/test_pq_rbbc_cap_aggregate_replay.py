import copy
import json
import tempfile
import unittest
from pathlib import Path

import pq_rbbc_cap_aggregate_replay as replay


ROOT = Path(__file__).resolve().parents[1]


class AggregateReplayTests(unittest.TestCase):
    def test_static_namespace_has_exact_72_links(self) -> None:
        namespace = json.loads((ROOT / "manifests/pq_rbbc_cap_production_namespace_manifest_v2_16.json").read_text())
        tail = json.loads((ROOT / "manifests/pq_rbbc_cap_global_tail_manifest_v2_9.json").read_text())
        links = replay.validate_static_links(namespace, tail)
        self.assertEqual(len(links), 72)
        self.assertEqual([item["tree_index"] for item in links[::4]], list(range(18)))

    def test_static_link_mutation_is_rejected(self) -> None:
        namespace = json.loads((ROOT / "manifests/pq_rbbc_cap_production_namespace_manifest_v2_16.json").read_text())
        tail = json.loads((ROOT / "manifests/pq_rbbc_cap_global_tail_manifest_v2_9.json").read_text())
        changed = copy.deepcopy(tail)
        changed["ports"][4]["value_sha256"] = "00" * 32
        with self.assertRaises(ValueError):
            replay.validate_static_links(namespace, changed)

    def test_checkpoint_rejects_wrong_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            path.write_text(json.dumps({"format": replay.CHECKPOINT_FORMAT, "input_identity": "wrong", "completed_tree_links": []}))
            with self.assertRaises(ValueError):
                replay.load_checkpoint(path, "right")

    def test_checkpoint_requires_contiguous_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            path.write_text(json.dumps({"format": replay.CHECKPOINT_FORMAT, "input_identity": "x", "completed_tree_links": [0, 2]}))
            with self.assertRaises(ValueError):
                replay.load_checkpoint(path, "x")

    def test_full_checkpoint_rejects_wrong_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            path.write_text(json.dumps({
                "format": replay.FULL_CHECKPOINT_FORMAT,
                "input_identity": "wrong",
                "completed_tree_replays": [],
                "tree_results": [],
                "relocations_complete": False,
                "global_tail_complete": False,
            }))
            with self.assertRaises(ValueError):
                replay._load_full_checkpoint(path, "right")

    def test_full_checkpoint_requires_matching_result_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            path.write_text(json.dumps({
                "format": replay.FULL_CHECKPOINT_FORMAT,
                "input_identity": "x",
                "completed_tree_replays": [0],
                "tree_results": [],
                "relocations_complete": False,
                "global_tail_complete": False,
            }))
            with self.assertRaises(ValueError):
                replay._load_full_checkpoint(path, "x")

    def test_full_checkpoint_starts_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = replay._load_full_checkpoint(
                Path(directory) / "missing.json", "identity"
            )
            self.assertEqual(checkpoint["completed_tree_replays"], [])
            self.assertFalse(checkpoint["relocations_complete"])
            self.assertFalse(checkpoint["global_tail_complete"])


if __name__ == "__main__":
    unittest.main()
