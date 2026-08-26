#!/usr/bin/env python3
"""Regression tests for the PQ-RBBC v2.15 representative relocations."""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

import pq_rbbc_cap_output_relocation as relocation
import pq_rbbc_cap_shard_assignment as assignment


TEST_ROOT = Path(__file__).resolve().parent
ROOT = TEST_ROOT.parent
ARTIFACT_ROOT = Path(os.environ.get("PQRBBC_ARTIFACT_ROOT", ROOT))
OUTPUT = ARTIFACT_ROOT / "output_relocation_v2_15"
MANIFEST_PATH = ROOT / "manifests" / relocation.MANIFEST_NAME
ARCHIVE_PATH = OUTPUT / relocation.ASSIGNMENT_NAME
TAIL_MANIFEST_PATH = ROOT / "manifests" / "pq_rbbc_cap_global_tail_manifest_v2_9.json"
TREE0_MANIFEST_PATH = (
    ROOT
    / "artifacts"
    / "metadata"
    / "production_tree0_v2_13"
    / "pq_rbbc_cap_production_tree0_manifest_v2_13.json"
)
TREE2_MANIFEST_PATH = (
    ROOT
    / "artifacts"
    / "metadata"
    / "production_tree2_v2_14"
    / "pq_rbbc_cap_production_tree2_manifest_v2_14.json"
)


class OutputRelocationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_frozen_trace_and_archive_identity(self) -> None:
        trace = self.manifest["trace"]
        archive = self.manifest["assignment_archive"]
        self.assertEqual(trace["rows"], relocation.FROZEN_ROWS)
        self.assertEqual(trace["wires"], relocation.FROZEN_WIRES)
        self.assertEqual(trace["linear_rows"], relocation.FROZEN_ROWS)
        self.assertEqual(trace["nonlinear_rows"], 0)
        self.assertEqual(trace["stream_bytes"], relocation.FROZEN_STREAM_BYTES)
        self.assertEqual(trace["stream_sha256"], relocation.FROZEN_STREAM_SHA256)
        self.assertEqual(trace["verification_failures"], 0)
        self.assertEqual(trace["external_assertions"], 0)
        self.assertEqual(
            archive["archive_bytes"], relocation.FROZEN_ASSIGNMENT_BYTES
        )
        self.assertEqual(
            archive["archive_sha256"], relocation.FROZEN_ASSIGNMENT_SHA256
        )
        if ARCHIVE_PATH.exists():
            self.assertEqual(
                relocation._sha256_file(ARCHIVE_PATH),
                relocation.FROZEN_ASSIGNMENT_SHA256,
            )

    def test_all_eight_ranges_and_row_groups_are_sealed(self) -> None:
        ports = self.manifest["relocations"]
        self.assertEqual(len(ports), 8)
        self.assertEqual(
            tuple(port["port_id"] for port in ports),
            tuple(
                f"tree[{tree_index}].{suffix}"
                for tree_index in relocation.TREE_ORDER
                for suffix in relocation.PORT_SUFFIXES
            ),
        )
        self.assertEqual(
            sum(port["bit_length"] for port in ports), relocation.FROZEN_ROWS
        )
        self.assertTrue(
            all(port["equality_rows"] == port["bit_length"] for port in ports)
        )
        self.assertTrue(
            all(
                len(port["equality_row_stream_sha256"]) == 64
                and port["equality_row_stream_bytes"] > 0
                for port in ports
            )
        )
        self.assertEqual(
            tuple(port["producer_wire_start"] for port in ports[:4]),
            (77_419_669, 79_000_725, 79_002_773, 79_143_409),
        )
        self.assertEqual(
            tuple(port["producer_wire_start"] for port in ports[4:]),
            (58_805_397, 59_595_925, 59_597_973, 59_668_401),
        )
        self.assertEqual(
            tuple(port["consumer_wire_start"] for port in ports[:4]),
            (643, 1_581_699, 1_583_747, 1_584_133),
        )
        self.assertEqual(
            tuple(port["consumer_wire_start"] for port in ports[4:]),
            (3_177_659, 3_968_187, 3_970_235, 3_970_621),
        )

    def test_assignment_samples_satisfy_every_relocation_boundary(self) -> None:
        if not ARCHIVE_PATH.exists():
            self.skipTest("external v2.15 relocation assignment is not installed")
        ports = self.manifest["relocations"]
        with assignment.AssignmentArchiveReader(
            ARCHIVE_PATH, verify_body=True
        ) as values:
            self.assertEqual(values.wires, relocation.FROZEN_WIRES)
            self.assertEqual(
                values.row_stream_sha256, relocation.FROZEN_STREAM_SHA256
            )
            for port in ports:
                for offset in (0, port["bit_length"] // 2, port["bit_length"] - 1):
                    self.assertEqual(
                        values[port["canonical_source_wire_start"] + offset],
                        values[port["canonical_destination_wire_start"] + offset],
                        port["port_id"],
                    )

    def test_witness_and_configuration_mutations_all_reject(self) -> None:
        witness = self.manifest["mutation_probes"]
        configuration = self.manifest["configuration_mutation_probes"]
        self.assertEqual(len(witness), 16)
        self.assertEqual(len(configuration), 6)
        self.assertTrue(all(item["honest_row_satisfied"] for item in witness))
        self.assertTrue(all(not item["stale_row_satisfied"] for item in witness))
        self.assertTrue(all(item["rejected"] for item in witness))
        self.assertTrue(all(item["rejected"] for item in configuration))
        self.assertTrue(all(item["failures"] for item in configuration))

    def test_fail_closed_evidence_loader_rejects_noncanonical_variants(self) -> None:
        evidence = relocation.load_evidence(
            TAIL_MANIFEST_PATH,
            TREE0_MANIFEST_PATH,
            TREE2_MANIFEST_PATH,
        )
        self.assertEqual(relocation.evidence_failures(evidence, evidence), ())
        probes = relocation._configuration_probes(evidence)
        self.assertEqual(len(probes), 6)
        self.assertTrue(all(probe.rejected for probe in probes))

    def test_claim_boundary_is_aggressive_but_not_overstated(self) -> None:
        claims = self.manifest["claim_boundary"]
        for name in (
            "production_representative_output_relocation_contract_closed",
            "production_index0_all_four_output_relocations_closed",
            "production_index2_all_four_output_relocations_closed",
            "all_four_output_relocations_closed",
            "representative_cross_segment_wire_relation_closed",
        ):
            self.assertTrue(claims[name], name)
        for name in (
            "tree_producer_segments_materialized",
            "complete_18_tree_assignment_replayed",
            "cross_segment_wire_identity_closed",
            "parent_cap_to_h_rbbc_join_closed",
            "cap_unique_witness_reviewed",
            "cap_straightline_extraction_reviewed",
            "fork_blindness_proved",
            "one_more_unforgeability_proved",
            "se_nizk_qrom_reduction_complete",
            "fork_security_proof_revalidated",
            "signature_size_rebenchmarked",
            "production_closed",
        ):
            self.assertFalse(claims[name], name)

    def test_tree0_restoration_boundary_is_explicit(self) -> None:
        profile = self.manifest["profile"]
        self.assertFalse(profile["full_tree0_assignment_restored_for_v2_15"])
        self.assertEqual(profile["remaining_tree_instances_not_materialized"], 16)
        self.assertIn("sealed v2.13", profile["tree0_source_import"])
        self.assertIn("direct v2.14", profile["tree2_source_import"])


if __name__ == "__main__":
    unittest.main()
