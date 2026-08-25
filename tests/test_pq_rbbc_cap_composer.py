#!/usr/bin/env python3
"""Regression tests for the PQ-RBBC v2.8 18-tree linked composer."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_composer as composer


class CAPComposerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.parameters = cap.REDUCED_TEST_PARAMETERS
        cls.randomness = cap.deterministic_randomness(cls.parameters)
        cls.reference = cap.execute_cap_commit(cls.parameters, cls.randomness)

    def test_parallel_executor_matches_direct_reference(self) -> None:
        summary = composer.build_parallel_execution(
            self.parameters, self.randomness, workers=2
        )
        parallel = summary.execution
        self.assertEqual(parallel, self.reference)
        self.assertEqual(
            composer.validate_execution_cache_identity(
                summary, self.parameters, self.randomness
            ),
            (),
        )

    def test_production_schedule_and_template_offsets_are_exact(self) -> None:
        params = cap.PRODUCTION_PARAMETERS
        shapes = tuple(
            zip(params.expanded_leaf_counts(), params.expanded_extension_degrees())
        )
        self.assertEqual(shapes, ((4096, 13),) * 2 + ((2048, 12),) * 16)
        templates = [composer._template_for(*shape) for shape in shapes]
        self.assertTrue(all(item.verification_failures == 0 for item in templates))
        self.assertEqual(sum(item.rows for item in templates), 522_469_530)
        self.assertEqual(sum(item.wires for item in templates), 398_032_312)
        self.assertEqual(sum(item.nonlinear_rows for item in templates), 390_142_528)
        self.assertEqual(sum(item.linear_rows for item in templates), 132_327_002)
        self.assertEqual(sum(item.stream_bytes for item in templates), 377_830_939_120)
        self.assertEqual(
            sum(item.assignment_archive_bytes for item in templates),
            9_950_810_104,
        )

    def test_trace_digest_is_order_and_output_sensitive(self) -> None:
        size, digest = composer.xof_trace_digest(self.reference.xof_calls)
        swapped = list(self.reference.xof_calls)
        swapped[0], swapped[1] = swapped[1], swapped[0]
        changed = list(self.reference.xof_calls)
        changed[0] = cap.XOFCall(
            changed[0].label,
            changed[0].domain,
            changed[0].fields,
            changed[0].output_bits,
            changed[0].output ^ 1,
        )
        self.assertGreater(size, 0)
        self.assertNotEqual(digest, composer.xof_trace_digest(swapped)[1])
        self.assertNotEqual(digest, composer.xof_trace_digest(changed)[1])

    def test_canonical_json_is_stable_and_mutation_sensitive(self) -> None:
        document = {"z": [2, 1], "a": {"b": True}}
        encoded = composer.canonical_json(document)
        self.assertEqual(encoded, b'{"a":{"b":true},"z":[2,1]}\n')
        changed = copy.deepcopy(document)
        changed["z"][0] ^= 1
        self.assertNotEqual(
            hashlib.sha256(encoded).digest(),
            hashlib.sha256(composer.canonical_json(changed)).digest(),
        )

    def test_frozen_document_when_present_is_fail_closed(self) -> None:
        path = (
            Path(__file__).resolve().parents[1]
            / "manifests"
            / "pq_rbbc_cap_composition_manifest_v2_8.json"
        )
        if not path.exists():
            self.skipTest("production composition vector has not been generated")
        self.assertEqual(composer.verify_frozen_document(path), ())
        document = json.loads(path.read_text(encoding="utf-8"))
        document["tree_links"][0]["tree_index"] = 9
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / "changed.json"
            changed.write_bytes(composer.canonical_json(document))
            self.assertTrue(composer.verify_frozen_document(changed))


if __name__ == "__main__":
    unittest.main(verbosity=2)
