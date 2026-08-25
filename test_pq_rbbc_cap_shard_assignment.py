#!/usr/bin/env python3
"""Regression tests for the v2.6 assignment-backed shard verifier."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

import pq_rbbc_cap_shard_assignment as assignment
import pq_rbbc_cap_shard_stream as shard


class AssignmentBackedProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(
            prefix="pq-rbbc-assignment-test-"
        )
        cls.archive_path = Path(cls.temporary.name) / "probe.f193assign"
        cls.result = assignment.build_assignment_backed_shard(
            cls.archive_path,
            shard.PROBE_PARAMETERS,
            workers=2,
        )
        cls.manifest = assignment.build_manifest(cls.result)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_probe_archive_is_frozen(self) -> None:
        archive = self.result.archive
        self.assertEqual(archive.header_bytes, 128)
        self.assertEqual(archive.field_degree, 193)
        self.assertEqual(archive.value_bytes, 25)
        self.assertEqual(archive.wires, 42_306)
        self.assertEqual(archive.body_bytes, 1_057_650)
        self.assertEqual(archive.archive_bytes, 1_057_778)
        self.assertEqual(
            archive.body_sha256,
            "d0d1f91fe7f7c5a43d588daa8528060b86c0cec588a17467e443073bcf27ca1a",
        )
        self.assertEqual(
            archive.archive_sha256,
            "660fdeda7208a6e674794780abead4bfe15dc2eabfbcd9d081c810662b9ea7c8",
        )

    def test_whole_probe_assignment_is_satisfied(self) -> None:
        generated = self.result.generated
        verified = self.result.verified
        self.assertTrue(generated.assignment_materialized)
        self.assertEqual(verified.verification_failures, 0)
        self.assertIsNone(verified.first_verification_failure)
        self.assertEqual(verified.rows, 60_629)
        self.assertEqual(verified.wires, 42_306)
        self.assertEqual(verified.stream_sha256, generated.stream_sha256)

    def test_archive_reader_is_one_based_and_exact(self) -> None:
        with assignment.AssignmentArchiveReader(
            self.archive_path,
            expected=self.result.archive,
        ) as reader:
            self.assertEqual(len(reader), 42_306)
            self.assertIn(reader[1], (0, 1))
            self.assertIn(reader[42_306], (0, 1))
            with self.assertRaises(KeyError):
                _ = reader[0]
            with self.assertRaises(KeyError):
                _ = reader[42_307]

    def test_all_five_stale_witness_probes_are_rejected(self) -> None:
        probes = self.result.tamper_probes
        self.assertEqual(len(probes), 5)
        self.assertTrue(all(probe.honest_row_satisfied for probe in probes))
        self.assertTrue(all(not probe.stale_row_satisfied for probe in probes))
        self.assertTrue(all(probe.rejected for probe in probes))
        self.assertTrue(any("derive" in probe.label for probe in probes))
        self.assertTrue(any("tape" in probe.label for probe in probes))
        self.assertTrue(any("horner" in probe.label for probe in probes))
        self.assertTrue(any("commitment" in probe.label for probe in probes))
        self.assertTrue(any("request-binding" in probe.label for probe in probes))

    def test_body_digest_rejects_corruption(self) -> None:
        corrupt = Path(self.temporary.name) / "corrupt.f193assign"
        shutil.copyfile(self.archive_path, corrupt)
        with corrupt.open("r+b") as target:
            target.seek(assignment.ASSIGNMENT_HEADER_BYTES + 17)
            original = target.read(1)
            target.seek(assignment.ASSIGNMENT_HEADER_BYTES + 17)
            target.write(bytes((original[0] ^ 1,)))
        with self.assertRaisesRegex(ValueError, "body digest mismatch"):
            assignment.AssignmentArchiveReader(corrupt)

    def test_manifest_remains_fail_closed(self) -> None:
        implemented = self.manifest["implemented"]
        boundary = self.manifest["claim_boundary"]
        self.assertTrue(implemented["full_assignment_archive_materialized"])
        self.assertTrue(implemented["whole_shard_assignment_verified"])
        self.assertTrue(implemented["stale_witness_probes_rejected"])
        self.assertFalse(boundary["production_tree_shard_assignment_closed"])
        self.assertFalse(boundary["production_closed"])


class ProductionAssignmentManifestTests(unittest.TestCase):
    def test_frozen_production_assignment_manifest(self) -> None:
        path = Path(__file__).with_name(
            "pq_rbbc_cap_shard_assignment_manifest_v2_6.json"
        )
        if not path.exists():
            self.skipTest("v2.6 production assignment vector not frozen yet")
        manifest = json.loads(path.read_text(encoding="utf-8"))
        trace = manifest["trace"]
        archive = manifest["assignment_archive"]
        verification = manifest["whole_shard_verification"]
        self.assertEqual(trace["wires"], shard.FROZEN_PRODUCTION_WIRES)
        self.assertEqual(trace["rows"], shard.FROZEN_PRODUCTION_ROWS)
        self.assertEqual(
            trace["stream_sha256"], shard.FROZEN_PRODUCTION_STREAM_SHA256
        )
        self.assertEqual(archive["wires"], trace["wires"])
        self.assertEqual(archive["body_bytes"], trace["wires"] * 25)
        self.assertEqual(archive["archive_bytes"], archive["body_bytes"] + 128)
        self.assertEqual(
            archive["body_sha256"],
            assignment.FROZEN_PRODUCTION_ASSIGNMENT_BODY_SHA256,
        )
        self.assertEqual(
            archive["archive_sha256"],
            assignment.FROZEN_PRODUCTION_ASSIGNMENT_ARCHIVE_SHA256,
        )
        self.assertEqual(archive["row_stream_sha256"], trace["stream_sha256"])
        self.assertEqual(verification["rows_checked"], trace["rows"])
        self.assertEqual(verification["failures"], 0)
        self.assertTrue(verification["topology_matches_generation"])
        self.assertEqual(len(manifest["stale_witness_probes"]), 5)
        self.assertTrue(
            all(item["rejected"] for item in manifest["stale_witness_probes"])
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "production_tree_shard_assignment_closed"
            ]
        )
        self.assertFalse(manifest["claim_boundary"]["production_closed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
