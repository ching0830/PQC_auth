from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pq_rbbc_cap_provenance_v2_42 as p
import pq_rbbc_cap_unified_tree_recovery_v2_42 as r
import pq_rbbc_launch_io_v2_41 as io


class ProvenanceV242Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="pq-rbbc-v242-papers-")
        cls.root = Path(cls.temp.name)
        cls.document = io.read_snapshot(r.PROVENANCE_PATH).document()
        originals = {"bavc": Path("/tmp/eprint_2024_490.pdf"),
                     "generic_tcith": Path("/tmp/eprint_2024_541.pdf"),
                     "blind_uov": Path("/tmp/pq_rbbc_external_artifacts_rebuilt/v2_30_fork_security/blind_uov_eprint_2025_895_revision_2025_10_31.pdf")}
        cls.paths = {}
        for source, path in originals.items():
            # No deserialization: untrusted bytes must match the frozen PDF first.
            raw = path.read_bytes()
            p.validate_pdf(io.Snapshot(path, raw), source)
            cls.paths[source] = cls.root / path.name
            cls.paths[source].write_bytes(raw)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_cr02_source_roles_revisions_and_tables_are_distinct(self):
        sources = self.document["sources"]
        self.assertEqual(sources["bavc"]["report"], "2024/490")
        self.assertEqual(sources["bavc"]["revision_date"], "2025-03-31")
        self.assertEqual(sources["generic_tcith"]["report"], "2024/541")
        self.assertEqual(sources["generic_tcith"]["revision_date"], "2024-11-08")
        self.assertEqual(sources["generic_tcith"]["table"], 7)
        self.assertIs(sources["generic_tcith"]["is_blind_uov_parameter_table"], False)
        self.assertEqual(sources["blind_uov"]["report"], "2025/895")
        self.assertEqual(sources["blind_uov"]["revision_date"], "2025-10-31")
        self.assertEqual(sources["blind_uov"]["cap_parameters_table"], 2)
        self.assertEqual(sources["blind_uov"]["performance_table"], 4)

    def test_cap_row_matches_unchanged_implementation_parameters(self):
        row = self.document["selected_cap_parameters"]
        actual = r.old.unified.PRODUCTION_PARAMETERS
        self.assertEqual(row["tau"], actual.vector_count)
        self.assertEqual((row["n_1"],) * row["tau_1"] + (row["n_2"],) * row["tau_2"], actual.logical_leaf_counts)
        self.assertEqual(row["t_open"], actual.t_open)
        self.assertEqual(row["explicit_pow_bits"], actual.explicit_pow_bits)
        self.assertEqual(row["paper_total_work_bits_decimal"], "13.9")
        self.assertIs(self.document["parameter_values_changed"], False)
        self.assertIs(self.document["fork_security_proof_revalidated"], False)

    def test_three_exact_pdf_revisions_pass_byte_and_sha_verification(self):
        for source, path in self.paths.items():
            with self.subTest(source=source):
                snapshot = p.capture_pdf(path, artifact_root=self.root)
                self.assertEqual(p.validate_pdf(snapshot, source), self.document["sources"][source]["pdf_identity"])

    def test_wrong_role_truncated_mutated_and_alternate_revision_rejected(self):
        path = self.paths["blind_uov"]
        snapshot = p.capture_pdf(path, artifact_root=self.root)
        for raw in (snapshot.raw[:-1], snapshot.raw + b"\n", snapshot.raw[:-1] + bytes([snapshot.raw[-1] ^ 1])):
            with self.assertRaises(io.ValidationError):
                p.validate_pdf(io.Snapshot(path, raw), "blind_uov")
        with self.assertRaises(io.ValidationError):
            p.validate_pdf(snapshot, "generic_tcith")
        with self.assertRaises(io.ValidationError):
            p.validate_pdf(snapshot, "unknown")

    def test_erratum_mutation_cannot_relabel_a_source_or_table(self):
        original = io.read_snapshot
        for source, field, value in (("blind_uov", "cap_parameters_table", 7),
                                     ("blind_uov", "revision_date", "2025-05-19"),
                                     ("generic_tcith", "is_blind_uov_parameter_table", True)):
            document = original(r.PROVENANCE_PATH).document()
            document["sources"][source][field] = value
            def swapped(path, **kwargs):
                return io.Snapshot(path, io.canonical_json(document)) if path == r.PROVENANCE_PATH else original(path, **kwargs)
            with patch.object(io, "read_snapshot", side_effect=swapped), self.assertRaises(io.ValidationError):
                r.validate_contracts()

    def test_pdf_symlink_size_limit_and_outside_root_rejected(self):
        link = self.root / "symlink.pdf"
        link.symlink_to(self.paths["bavc"])
        try:
            with self.assertRaises(OSError):
                p.capture_pdf(link, artifact_root=self.root)
        finally:
            link.unlink()
        large = self.root / "oversized.pdf"
        with large.open("wb") as handle:
            handle.truncate(p.MAX_PDF_BYTES + 1)
        with self.assertRaises(io.ValidationError):
            p.capture_pdf(large, artifact_root=self.root)
        with self.assertRaises(io.ValidationError):
            p.capture_pdf(Path("/tmp/eprint_2024_490.pdf"), artifact_root=self.root)

    def test_pdf_validation_consumes_captured_bytes_after_path_mutation(self):
        path = self.paths["bavc"]
        snapshot = p.capture_pdf(path, artifact_root=self.root)
        try:
            path.write_bytes(b"different future pathname content")
            self.assertEqual(p.validate_pdf(snapshot, "bavc"), snapshot.identity)
            with self.assertRaises(io.ValidationError):
                p.validate_pdf(p.capture_pdf(path, artifact_root=self.root), "bavc")
        finally:
            path.write_bytes(snapshot.raw)

    def test_provenance_hash_and_semantics_use_one_captured_document(self):
        original = io.read_snapshot
        captures = []
        def replace_on_second_read(path, **kwargs):
            snapshot = original(path, **kwargs)
            if path == r.PROVENANCE_PATH:
                captures.append(snapshot)
                if len(captures) > 1:
                    changed = snapshot.document()
                    changed["sources"]["blind_uov"]["pdf_identity"]["sha256"] = "0" * 64
                    return io.Snapshot(path, io.canonical_json(changed))
            return snapshot
        pdf = p.capture_pdf(self.paths["blind_uov"], artifact_root=self.root)
        with patch.object(io, "read_snapshot", side_effect=replace_on_second_read):
            self.assertEqual(p.validate_pdf(pdf, "blind_uov"), pdf.identity)
        self.assertEqual(len(captures), 1)

    def test_sealed_v233_and_historical_authorizations_are_not_rewritten(self):
        manifest = r.validate_contracts().document()
        spec = self.document["superseded_citation_only"]
        self.assertEqual(io.read_snapshot(r.ROOT / spec["path"]).identity, spec["identity"])
        self.assertIs(manifest["transition"]["v2_41_reservation_authorizes_v2_42"], False)
        self.assertIs(manifest["transition"]["v2_41_launch_authorizes_v2_42"], False)
        # Private operator records are checked by the external preservation audit,
        # not prerequisites for running a public repository unit test.
        self.assertEqual(len(manifest["historical_rejected_v2_41_external"]), 2)
        self.assertTrue(all(v is False for v in manifest["current_gates"].values()))


if __name__ == "__main__":
    unittest.main()
