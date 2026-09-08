"""Missing-candidate evidence and CLI regression; all candidates are synthetic."""

import copy
from datetime import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import pq_rbbc_cap_unified_tree_launch_validation_v2_41 as L
import pq_rbbc_cap_unified_tree_launch_validation_evidence_v2_41 as E
import pq_rbbc_launch_io_v2_41 as IO
from tests.test_pq_rbbc_cap_unified_tree_launch_validation_v2_41 import NOW, CREATED, synthetic_resource, synthetic_review


class EvidenceV241Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pq-rbbc-v241-evidence-TEST-ONLY-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / L.REPORT_FILENAME
        self.report = L.build_preflight(clock=lambda: NOW)
        IO.ArtifactRoot(self.root).write(self.path, self.report)
        self.identity = IO.ArtifactRoot(self.root).read(self.path).identity

    def build(self, expected=None):
        return E.build_evidence(self.path, self.identity if expected is None else expected, artifact_root=self.root)

    def test_f1_evidence_positive_single_read_and_path_free(self):
        real_read, reads = IO.ArtifactRoot.read, []
        def once(store, path):
            reads.append(path)
            return real_read(store, path)
        with patch.object(IO.ArtifactRoot, "read", once):
            document = self.build()
        self.assertEqual(reads, [self.path])
        raw = IO.canonical_json(document)
        self.assertNotIn(b"/tmp/", raw)
        self.assertNotIn(b"/home/", raw)
        self.assertEqual(document["external_report_identity"], self.identity)
        self.assertFalse(document["preflight_result"]["safe_to_freeze_launch_identity_set"])

    def test_f1_evidence_replacement_keeps_validated_snapshot_identity(self):
        real_read = IO.ArtifactRoot.read
        def swap(store, path):
            snap = real_read(store, path)
            self.path.write_bytes(b"MUTATED-AFTER-CAPTURE")
            return snap
        with patch.object(IO.ArtifactRoot, "read", swap):
            document = self.build()
        self.assertEqual(document["external_report_identity"], self.identity)
        with self.assertRaises(IO.ValidationError): self.build()

    def test_f1_evidence_rejects_bad_snapshot_even_if_replacement_is_good(self):
        bad = copy.deepcopy(self.report)
        bad["result"]["safe_to_start_production_prefreeze"] = True
        raw = IO.canonical_json(bad)
        expected = IO.Snapshot(self.path, raw).identity
        self.path.write_bytes(raw)
        real_read = IO.ArtifactRoot.read
        def swap(store, path):
            snap = real_read(store, path)
            self.path.write_bytes(IO.canonical_json(self.report))
            return snap
        with patch.object(IO.ArtifactRoot, "read", swap):
            with self.assertRaises(IO.ValidationError): self.build(expected)

    def test_f3_evidence_rejects_noncanonical_and_duplicate_report(self):
        for raw in (IO.canonical_json(self.report) + b" ", IO.canonical_json(self.report).replace(b'{', b'{"format":"bad",', 1)):
            self.path.write_bytes(raw)
            expected = IO.Snapshot(self.path, raw).identity
            with self.assertRaises(IO.ValidationError): self.build(expected)

    def test_f4_evidence_rejects_numeric_claims_and_identity_sizes(self):
        for value in (True, float(self.identity["bytes"])):
            expected = dict(self.identity, bytes=value)
            with self.assertRaises(IO.ValidationError): self.build(expected)
        for value in (0, 0.0, True):
            doc = copy.deepcopy(self.report)
            doc["result"]["safe_to_start_production_prefreeze"] = value
            with self.assertRaises(IO.ValidationError): E.validate_missing_report(doc, self.report["manifest"])
        doc = copy.deepcopy(self.report)
        doc["manifest"]["bytes"] = float(doc["manifest"]["bytes"])
        with self.assertRaises(IO.ValidationError): E.validate_missing_report(doc, self.report["manifest"])

    def test_f7_evidence_same_exclusive_publication_and_symlink_guards(self):
        doc = self.build()
        output = self.root / "dummy-portable.json"
        E.write_evidence(output, doc, artifact_root=self.root)
        with self.assertRaises(FileExistsError): E.write_evidence(output, doc, artifact_root=self.root)
        output.unlink()
        target = self.root / "must-not-exist"
        output.symlink_to(target)
        with self.assertRaises(FileExistsError): E.write_evidence(output, doc, artifact_root=self.root)
        self.assertFalse(target.exists())

    def test_f8_evidence_requires_exact_contracts(self):
        with patch.object(L, "contract_snapshots", return_value=(("mutated",), {})):
            with self.assertRaises(IO.ValidationError): self.build()

    def test_portable_rebuild_matches_if_tracked(self):
        # Reconstruct only the negative missing-input report at its recorded
        # observation time. No dependency on an installed external report.
        if not E.PORTABLE_PATH.exists():
            self.skipTest("v2.41 portable evidence has not yet been authored")
        doc = IO.strict_json(E.PORTABLE_PATH.read_bytes())
        recorded = datetime.fromisoformat(doc["negative_observation_at_utc"])
        report = L.build_preflight(clock=lambda: recorded)
        self.path.write_bytes(IO.canonical_json(report))
        actual = E.build_evidence(self.path, doc["external_report_identity"], artifact_root=self.root)
        self.assertEqual(IO.canonical_json(actual), E.PORTABLE_PATH.read_bytes())

    def cli(self, *args):
        return subprocess.run([sys.executable, str(L.ROOT / "src/pq_rbbc_cap_unified_tree_launch_validation_v2_41.py"), *args],
                              cwd=L.ROOT, env={**os.environ, "PYTHONPATH": "src", "PYTHONDONTWRITEBYTECODE": "1"},
                              text=True, capture_output=True, timeout=20)

    def test_cli_missing_predecessor_author_refuses_before_output(self):
        resource, review = (self.root / L.FILENAMES[k] for k in L.KINDS[:2])
        resource.write_bytes(IO.canonical_json(synthetic_resource(self.root)))
        review.write_bytes(IO.canonical_json(synthetic_review(self.root, IO.ArtifactRoot(self.root).read(resource))))
        output = self.root / L.FILENAMES["launch_manifest"]
        result = self.cli("--phase", "author-launch-manifest", "--trusted-artifact-root", str(self.root),
                          "--v2-38-portable", str(self.root / "missing"), "--resource-reservation", str(resource),
                          "--independent-review", str(review), "--launch-id", "TEST-ONLY", "--created-at-utc", CREATED,
                          "--output", str(output), "--fresh-output")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("authoring requires exact tracked contracts", result.stderr)
        self.assertFalse(output.exists())

    def test_cli_production_refuses_and_has_no_caller_now_option(self):
        output = self.root / "production-prefreeze"
        result = self.cli("--phase", "production-prefreeze", "--trusted-artifact-root", str(self.root),
                          "--output", str(output), "--fresh-output")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not authorize", result.stderr)
        self.assertFalse(output.exists())
        result = self.cli("--phase", "launch-preflight", "--output", str(output), "--fresh-output", "--now", CREATED)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrecognized arguments", result.stderr)

    def test_cli_missing_candidates_reports_false_and_refuses_overwrite(self):
        output = self.root / "dummy-cli-report.json"
        args = ("--phase", "launch-preflight", "--trusted-artifact-root", str(self.root), "--output", str(output), "--fresh-output")
        result = self.cli(*args)
        self.assertEqual(result.returncode, 0, result.stderr)
        raw = output.read_bytes()
        self.assertFalse(IO.strict_json(raw)["result"]["safe_to_freeze_launch_identity_set"])
        self.assertNotEqual(self.cli(*args).returncode, 0)
        self.assertEqual(output.read_bytes(), raw)


if __name__ == "__main__":
    unittest.main()
