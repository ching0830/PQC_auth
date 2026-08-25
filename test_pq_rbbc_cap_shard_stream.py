#!/usr/bin/env python3
"""Regression tests for the bounded-memory v2.5 production-tree shard."""

from __future__ import annotations

import dataclasses
import json
import unittest
from pathlib import Path

import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_shard_stream as shard


class StreamingShardProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.parameters = shard.PROBE_PARAMETERS
        cls.randomness = cap.deterministic_randomness(cls.parameters)
        cls.reference = cap.execute_cap_commit(cls.parameters, cls.randomness)
        cls.parallel = shard.build_parallel_execution(
            cls.parameters, cls.randomness, workers=2
        )
        cls.summary = shard.build_streaming_shard(
            cls.parameters,
            cls.randomness,
            bytes(32),
            workers=2,
            execution=cls.parallel,
        )
        cls.manifest = shard.build_manifest(cls.summary)

    def test_parallel_reference_is_exact(self) -> None:
        self.assertEqual(self.parallel, self.reference)

    def test_frozen_probe_stream(self) -> None:
        self.assertEqual(self.summary.rows, 60_629)
        self.assertEqual(self.summary.wires, 42_306)
        self.assertEqual(self.summary.nonlinear_rows, 41_538)
        self.assertEqual(self.summary.linear_rows, 19_091)
        self.assertEqual(self.summary.external_assertions, 0)
        self.assertFalse(self.summary.assignment_materialized)
        self.assertEqual(self.summary.stream_bytes, 36_774_847)
        self.assertEqual(
            self.summary.stream_sha256,
            "1aacab02946d723494199b8f5c9a35cc01c5c1142eb21442d4d1ab8b2a394521",
        )
        self.assertEqual(self.summary.spool_bytes, 24_704)
        self.assertEqual(
            self.summary.spool_sha256,
            "85ba61b3845b938c75c560c878f52090414f506d187f6d74b45ad72cd987f82b",
        )

    def test_probe_accounting_is_exact(self) -> None:
        sponge = self.summary.sponge_accounting
        self.assertEqual(sponge.calls, 14)
        self.assertEqual(sponge.permutations, 38)
        self.assertEqual(sponge.permutation_rows, 12_768)
        self.assertEqual(sponge.payload_bitness_rows, 16_240)
        self.assertEqual(sponge.output_bitness_rows, 7_913)
        self.assertEqual(sponge.source_link_rows, 16_240)
        horner = self.summary.horner_accounting
        self.assertEqual(horner.leaf_calls, 4)
        self.assertEqual(horner.multiplication_rows, 8)
        self.assertEqual(horner.aggregate_rows, 24)
        self.assertEqual(horner.point_validation_rows, 3)
        self.assertEqual(horner.output_bitness_rows, 1_544)
        self.assertEqual(horner.output_pack_rows, 8)

    def test_probe_vector_is_frozen(self) -> None:
        vector = self.manifest["frozen_vector"]
        self.assertEqual(vector["commitment_bytes"], 206)
        self.assertEqual(
            vector["commitment_sha256"],
            "657cd78178e95ceeef34066c7bac7e7ab26f66170483cca0f1a1ea013df97173",
        )
        self.assertEqual(
            vector["request_hash_hex"],
            "ec129e5a588803c0439f12a2e28ebffa24cceac93415027f053eb4c526c95662"
            "91e60b867d5ad9421d57689857a200bd37c1c05c285092ce330f5ad79abb1307"
            "fb1c13a47a4405e7",
        )

    def test_local_permutation_template_rejects_tamper(self) -> None:
        sink = shard.StreamingRowSink({"test": "tamper"})
        lowerer = shard.StreamingSpongeLowerer(sink)
        trace = lowerer.permutation_template
        assignment = dict(trace.assignment)
        assignment[trace.input_wires[0]] ^= 1
        self.assertTrue(trace.failed_rows(assignment))

    def test_stream_topology_is_witness_independent(self) -> None:
        roots = list(self.randomness.roots)
        roots[0] = (roots[0][0] ^ 1, roots[0][1])
        changed_randomness = dataclasses.replace(
            self.randomness,
            salt=(self.randomness.salt[0] ^ 1, self.randomness.salt[1]),
            roots=tuple(roots),
        )
        changed_execution = shard.build_parallel_execution(
            self.parameters, changed_randomness, workers=2
        )
        changed = shard.build_streaming_shard(
            self.parameters,
            changed_randomness,
            bytes([0xA5]) * 32,
            workers=2,
            execution=changed_execution,
        )
        self.assertEqual(changed.stream_sha256, self.summary.stream_sha256)
        self.assertEqual(changed.spool_sha256, self.summary.spool_sha256)
        self.assertNotEqual(changed.commitment_bytes, self.summary.commitment_bytes)
        self.assertNotEqual(changed.request_hash_bytes, self.summary.request_hash_bytes)

    def test_manifest_is_fail_closed(self) -> None:
        implemented = self.manifest["implemented"]
        boundary = self.manifest["claim_boundary"]
        self.assertTrue(implemented["streamed_expanded_row_digest"])
        self.assertTrue(implemented["bounded_memory_wire_spool"])
        self.assertFalse(implemented["callbacks_or_external_assertions"])
        self.assertFalse(implemented["full_assignment_archive_materialized"])
        self.assertFalse(boundary["production_tree_shard_topology_closed"])
        self.assertFalse(boundary["production_closed"])


class ProductionShardParameterTests(unittest.TestCase):
    def test_exact_production_tree_shape(self) -> None:
        parameters = shard.PRODUCTION_TREE_SHARD_PARAMETERS
        self.assertFalse(parameters.secure_profile)
        self.assertEqual(parameters.tree_count, 1)
        self.assertEqual(parameters.leaf_count, 2_048)
        self.assertEqual(parameters.expanded_extension_degrees(), (12,))
        self.assertEqual(parameters.witness_bits, 2_048)
        self.assertEqual(parameters.consistency_points, 2)
        self.assertEqual(parameters.random_polynomial_bits, 2_450)
        self.assertEqual(
            (parameters.witness_bits + 192) // 193,
            11,
        )

    def test_wrong_tree_count_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            shard.build_parallel_execution(
                cap.REDUCED_TEST_PARAMETERS,
                cap.deterministic_randomness(cap.REDUCED_TEST_PARAMETERS),
            )

    def test_exact_4096_production_tree_shape_and_identity(self) -> None:
        parameters = shard.PRODUCTION_TREE_SHARD_4096_PARAMETERS
        self.assertFalse(parameters.secure_profile)
        self.assertEqual(parameters.tree_count, 1)
        self.assertEqual(parameters.leaf_count, 4_096)
        self.assertEqual(parameters.expanded_extension_degrees(), (13,))
        self.assertEqual(parameters.witness_bits, 2_048)
        self.assertEqual(parameters.consistency_points, 2)
        self.assertEqual(parameters.random_polynomial_bits, 2_450)
        self.assertEqual(
            shard.shard_profile(parameters),
            (shard.PROFILE_NAME_4096, shard.PROFILE_RELATION_ID_4096),
        )

    def test_2048_profile_identity_is_backward_compatible(self) -> None:
        self.assertEqual(
            shard.shard_profile(shard.PRODUCTION_TREE_SHARD_PARAMETERS),
            (shard.PROFILE_NAME, shard.PROFILE_RELATION_ID),
        )

    def test_frozen_production_manifest(self) -> None:
        path = Path(__file__).with_name(
            "pq_rbbc_cap_shard_stream_manifest_v2_5.json"
        )
        manifest = json.loads(path.read_text(encoding="utf-8"))
        trace = manifest["trace"]
        vector = manifest["frozen_vector"]
        self.assertEqual(trace["wires"], shard.FROZEN_PRODUCTION_WIRES)
        self.assertEqual(trace["rows"], shard.FROZEN_PRODUCTION_ROWS)
        self.assertEqual(
            trace["nonlinear_rows"], shard.FROZEN_PRODUCTION_NONLINEAR_ROWS
        )
        self.assertEqual(
            trace["linear_rows"], shard.FROZEN_PRODUCTION_LINEAR_ROWS
        )
        self.assertEqual(
            trace["stream_bytes"], shard.FROZEN_PRODUCTION_STREAM_BYTES
        )
        self.assertEqual(
            trace["stream_sha256"], shard.FROZEN_PRODUCTION_STREAM_SHA256
        )
        self.assertEqual(
            trace["spool_bytes"], shard.FROZEN_PRODUCTION_SPOOL_BYTES
        )
        self.assertEqual(
            trace["spool_sha256"], shard.FROZEN_PRODUCTION_SPOOL_SHA256
        )
        self.assertEqual(
            vector["commitment_sha256"],
            shard.FROZEN_PRODUCTION_COMMITMENT_SHA256,
        )
        self.assertEqual(
            vector["request_hash_hex"],
            shard.FROZEN_PRODUCTION_REQUEST_HASH_HEX,
        )
        self.assertEqual(sum(group["rows"] for group in trace["groups"]), trace["rows"])
        self.assertEqual(
            trace["linear_rows"] + trace["nonlinear_rows"], trace["rows"]
        )
        self.assertLess(trace["peak_rss_kib"], 256 * 1024)
        self.assertTrue(
            manifest["claim_boundary"]["production_tree_shard_topology_closed"]
        )
        self.assertFalse(manifest["claim_boundary"]["production_closed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
