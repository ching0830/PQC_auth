#!/usr/bin/env python3
"""Regression tests for the PQ-RBBC v2.9 shared native CAP tail."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import pq_rbbc_anemoi_sponge as sponge
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_global_tail as tail


class GlobalTailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.parameters = cap.REDUCED_TEST_PARAMETERS
        cls.randomness = cap.deterministic_randomness(cls.parameters)
        cls.execution = cap.execute_cap_commit(cls.parameters, cls.randomness)

    def test_tail_material_matches_reference(self) -> None:
        material = tail.derive_tail_material(
            self.parameters, self.execution, bytes(32)
        )
        self.assertEqual(material.delta_p, self.execution.commitment.delta_p)
        self.assertEqual(
            material.delta_mhat, self.execution.commitment.delta_mhat
        )
        self.assertEqual(material.alpha, self.execution.commitment.alpha)
        self.assertEqual(
            material.request_call.output.to_bytes(
                sponge.REQUEST_HASH_BYTES, "little"
            ),
            sponge.hash_request_binding(
                bytes(32), self.execution.commitment.encoded
            ),
        )

    def test_in_memory_generation_replay_and_mutations(self) -> None:
        generated, verified, probes = tail.build_in_memory_global_tail(
            self.parameters, self.randomness, self.execution
        )
        self.assertEqual(generated.rows, verified.rows)
        self.assertEqual(generated.wires, verified.wires)
        self.assertEqual(generated.stream_sha256, verified.stream_sha256)
        self.assertEqual(verified.verification_failures, 0)
        self.assertEqual(generated.external_assertions, 0)
        self.assertEqual(len(probes), 6)
        self.assertTrue(all(probe.rejected for probe in probes))
        self.assertEqual(
            hashlib.sha256(generated.commitment_bytes).hexdigest(),
            hashlib.sha256(self.execution.commitment.encoded).hexdigest(),
        )

    def test_port_order_and_width_are_exact(self) -> None:
        generated, _, _ = tail.build_in_memory_global_tail(
            self.parameters, self.randomness, self.execution
        )
        ports = {port.port_id: port for port in generated.ports}
        self.assertEqual(ports["shared.salt"].bit_length, 386)
        self.assertEqual(ports["shared.message"].bit_length, 256)
        for tree_index, poly in enumerate(self.execution.tree_polynomials):
            self.assertEqual(
                ports[f"tree[{tree_index}].leaf-commitments"].bit_length,
                poly.leaves * 2 * 193,
            )
            self.assertEqual(
                ports[f"tree[{tree_index}].p-plain"].bit_length,
                self.parameters.witness_bits,
            )
            self.assertEqual(
                ports[f"tree[{tree_index}].mhat-plain"].bit_length,
                self.parameters.consistency_bits,
            )
            self.assertEqual(
                ports[f"tree[{tree_index}].xi-masks"].bit_length,
                self.parameters.consistency_bits * poly.extension_degree,
            )

    def test_disk_archive_replays_and_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "tail.f193assign"
            result = tail.build_assignment_backed_global_tail(
                archive,
                self.parameters,
                self.randomness,
                self.execution,
            )
            manifest = tail.build_manifest(result)
        self.assertEqual(result.verified.verification_failures, 0)
        self.assertTrue(
            manifest["claim_boundary"][
                "global_tail_ports_are_native_bit_constrained"
            ]
        )
        self.assertFalse(
            manifest["claim_boundary"]["tree_producer_segments_materialized"]
        )
        self.assertFalse(
            manifest["claim_boundary"]["cross_segment_wire_identity_closed"]
        )
        self.assertFalse(manifest["claim_boundary"]["production_closed"])

    def test_binary_stream_is_witness_independent(self) -> None:
        generated, _, _ = tail.build_in_memory_global_tail(
            self.parameters, self.randomness, self.execution
        )
        changed_randomness = cap.CAPRandomness(
            (
                self.randomness.salt[0] ^ 1,
                self.randomness.salt[1],
            ),
            self.randomness.roots,
        )
        changed_execution = cap.execute_cap_commit(
            self.parameters, changed_randomness
        )
        changed, _, _ = tail.build_in_memory_global_tail(
            self.parameters, changed_randomness, changed_execution
        )
        # Witness values may change, but the binary relation topology does not.
        self.assertEqual(generated.stream_sha256, changed.stream_sha256)

    def test_existing_manifest_seal_is_exact_and_fail_closed(self) -> None:
        document = {
            "implementation_version": tail.IMPLEMENTATION_VERSION,
            "profile": {
                "relation_id": tail.RELATION_ID,
                "stream_format": tail.STREAM_FORMAT,
                "assignment_format": tail.assignment.ASSIGNMENT_FORMAT,
                "cap_profile_fingerprint": tail.cap.profile_fingerprint(
                    tail.cap.PRODUCTION_PARAMETERS
                ),
                "tree_count": tail.cap.PRODUCTION_PARAMETERS.tree_count,
                "production_profile": True,
            },
            "trace": {
                "rows": 123,
                "wires": 456,
                "stream_sha256": "11" * 32,
                "external_assertions": 0,
                "verification_failures": 0,
            },
            "assignment_archive": {"archive_sha256": "22" * 32},
            "outputs": {
                "commitment_bytes": tail.cap.commitment_bytes(
                    tail.cap.PRODUCTION_PARAMETERS
                ),
                "commitment_sha256": tail.FROZEN_PRODUCTION_COMMITMENT_SHA256,
                "request_hash_hex": tail.FROZEN_PRODUCTION_REQUEST_HASH_HEX,
            },
            "stale_witness_probes": [
                {"rejected": True} for _ in range(6)
            ],
            "claim_boundary": {
                "production_global_tail_native_closed": False,
                "global_tail_ports_are_native_bit_constrained": True,
                "tree_producer_segments_materialized": False,
                "cross_segment_wire_identity_closed": False,
                "complete_18_tree_assignment_replayed": False,
                "parent_cap_to_h_rbbc_join_closed": False,
                "fork_security_proof_revalidated": False,
                "production_closed": False,
            },
        }
        frozen = (
            mock.patch.object(tail, "FROZEN_PRODUCTION_STREAM_SHA256", "11" * 32),
            mock.patch.object(
                tail, "FROZEN_PRODUCTION_ASSIGNMENT_SHA256", "22" * 32
            ),
            mock.patch.object(tail, "FROZEN_PRODUCTION_ROWS", 123),
            mock.patch.object(tail, "FROZEN_PRODUCTION_WIRES", 456),
        )
        with frozen[0], frozen[1], frozen[2], frozen[3]:
            sealed = tail.seal_existing_manifest(document)
            self.assertTrue(
                sealed["claim_boundary"][
                    "production_global_tail_native_closed"
                ]
            )
            document["trace"]["rows"] += 1
            with self.assertRaisesRegex(ValueError, "rows"):
                tail.seal_existing_manifest(document)


if __name__ == "__main__":
    unittest.main(verbosity=2)
