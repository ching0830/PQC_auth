#!/usr/bin/env python3
"""Regression tests for the PQ-RBBC v2.11 split global-tail contract."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_global_tail as tail
import pq_rbbc_cap_split_tail as split


class SplitGlobalTailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.parameters = cap.REDUCED_TEST_PARAMETERS
        cls.randomness = cap.deterministic_randomness(cls.parameters)
        cls.execution = cap.execute_cap_commit(cls.parameters, cls.randomness)
        cls.temporary = tempfile.TemporaryDirectory()
        cls.archive_path = (
            Path(cls.temporary.name) / "split-tail-v2-11.f193assign"
        )
        cls.result = split.build_assignment_backed_split_tail(
            cls.archive_path,
            cls.parameters,
            cls.randomness,
            cls.execution,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_exact_canonical_stream_and_assignment_equivalence(self) -> None:
        result = self.result
        self.assertTrue(result.equivalence.exact)
        self.assertEqual(result.canonical.rows, split.FROZEN_REDUCED_ROWS)
        self.assertEqual(result.canonical.wires, split.FROZEN_REDUCED_WIRES)
        self.assertEqual(
            result.canonical.stream_sha256,
            split.FROZEN_REDUCED_STREAM_SHA256,
        )
        self.assertEqual(
            result.archive.body_sha256,
            split.FROZEN_REDUCED_ASSIGNMENT_BODY_SHA256,
        )
        self.assertEqual(
            result.canonical_assignment_body_sha256,
            result.archive.body_sha256,
        )

    def test_phase_ranges_partition_every_row_and_wire(self) -> None:
        contract = self.result.contract
        phase_a, phase_b = contract.phases
        self.assertEqual(
            (
                contract.input_prelude_row_start,
                contract.input_prelude_row_end,
                phase_a.row_start,
                phase_a.row_end,
                phase_b.row_start,
                phase_b.row_end,
            ),
            (0, 5_402, 5_402, 19_813, 19_813, 36_801),
        )
        self.assertEqual(
            (
                contract.input_prelude_wire_start,
                contract.input_prelude_wire_end,
                phase_a.wire_start,
                phase_a.wire_end,
                phase_b.wire_start,
                phase_b.wire_end,
            ),
            (1, 5_403, 5_403, 14_499, 14_499, 24_993),
        )

    def test_h1_and_point_ports_are_exact_native_wires(self) -> None:
        ports = {
            port.port_id: port for port in self.result.contract.boundary_ports
        }
        self.assertEqual(
            (
                ports["global.phase-a.h1"].consumer_wire_start,
                ports["global.phase-a.h1"].bit_length,
            ),
            (12_255, 386),
        )
        self.assertEqual(
            (
                ports[
                    "global.phase-a.consistency-points"
                ].consumer_wire_start,
                ports["global.phase-a.consistency-points"].bit_length,
            ),
            (14_305, 193),
        )
        phase_b = self.result.contract.phases[1]
        self.assertIn("global.phase-a.h1", phase_b.input_port_ids)
        self.assertIn(
            "global.phase-a.consistency-points", phase_b.input_port_ids
        )
        self.assertTrue(
            self.result.contract.phase_a_to_phase_b_wire_identity
        )

    def test_boundary_wire_mutations_are_rejected(self) -> None:
        probes = self.result.boundary_probes
        self.assertEqual(len(probes), 4)
        self.assertEqual(
            tuple(probe.port_id for probe in probes),
            (
                "global.phase-a.consistency-points",
                "global.phase-a.h1",
                "global.phase-b.commitment",
                "global.phase-b.request-hash",
            ),
        )
        self.assertTrue(all(probe.honest_row_satisfied for probe in probes))
        self.assertTrue(all(probe.rejected for probe in probes))

    def test_replay_contract_is_identical(self) -> None:
        self.assertEqual(self.result.verified.verification_failures, 0)
        self.assertEqual(self.result.contract, self.result.verified_contract)
        self.assertEqual(
            self.result.generated.stream_sha256,
            self.result.verified.stream_sha256,
        )

    def test_manifest_closes_only_the_reduced_tail_boundary(self) -> None:
        manifest = split.build_manifest(self.result)
        boundary = manifest["claim_boundary"]
        self.assertTrue(
            boundary["reduced_split_tail_phase_contract_closed"]
        )
        self.assertTrue(
            boundary["canonical_tail_stream_and_assignment_equivalent"]
        )
        self.assertTrue(
            boundary["h1_and_consistency_point_ports_native_closed"]
        )
        self.assertTrue(
            boundary["tail_phase_a_to_phase_b_wire_identity_closed"]
        )
        self.assertFalse(boundary["production_split_tail_materialized"])
        self.assertFalse(boundary["producer_point_wire_identity_closed"])
        self.assertFalse(boundary["production_closed"])
        with mock.patch.object(split, "FROZEN_REDUCED_ROWS", 1):
            changed = split.build_manifest(self.result)["claim_boundary"]
        self.assertFalse(changed["reduced_split_tail_phase_contract_closed"])
        self.assertFalse(changed["h1_and_consistency_point_ports_native_closed"])
        self.assertFalse(
            changed["tail_phase_a_to_phase_b_wire_identity_closed"]
        )

    def test_split_topology_is_witness_independent(self) -> None:
        changed_randomness = cap.CAPRandomness(
            (self.randomness.salt[0] ^ 1, self.randomness.salt[1]),
            self.randomness.roots,
        )
        changed_execution = cap.execute_cap_commit(
            self.parameters, changed_randomness
        )
        changed_contracts: list[tail.TailSplitContract] = []
        changed = tail.build_global_tail(
            self.parameters,
            changed_randomness,
            changed_execution,
            split_contract_output=changed_contracts,
        )
        self.assertEqual(changed.stream_sha256, split.FROZEN_REDUCED_STREAM_SHA256)
        self.assertEqual(len(changed_contracts), 1)
        observed = changed_contracts[0]
        expected = self.result.contract
        self.assertEqual(observed.phases, expected.phases)
        self.assertEqual(
            tuple(
                (port.port_id, port.consumer_wire_start, port.bit_length)
                for port in observed.boundary_ports
            ),
            tuple(
                (port.port_id, port.consumer_wire_start, port.bit_length)
                for port in expected.boundary_ports
            ),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
