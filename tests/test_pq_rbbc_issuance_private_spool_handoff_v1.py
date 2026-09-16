from dataclasses import FrozenInstanceError, replace
import os
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import pq_rbbc_issuance_private_spool_codec_v1 as codec
import pq_rbbc_issuance_private_spool_handoff_v1 as gate
import pq_rbbc_issuance_private_spool_native_v1 as native
import pq_rbbc_launch_io_v2_41 as io


class PrivateSpoolHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.session = gate.HandoffSessionInsecureTestOnly()
        cls.session.run_to("global-a")
        cls.candidates = cls.session.export_candidates()
        cls.pin = codec.sha256(cls.candidates.handoff.raw)
        cls.accepted = cls.session.accept_handoff(cls.candidates, expected_handoff_sha256=cls.pin)
        cls.session.run_to()
        cls.evidence = cls.session.handoff_evidence()

    @classmethod
    def tearDownClass(cls):
        cls.session.close()

    def decode(self, raw, index=0, context=None):
        return codec.decode_snapshot_insecure_test_only(
            replace(self.candidates.spools[index], raw=raw), expected_bytes=codec.SPOOL_BYTES,
            expected_sha256=codec.sha256(raw), context=context or self.session.context(index))

    def write_candidates(self, root, candidates=None):
        candidates = self.candidates if candidates is None else candidates
        for snap in (candidates.handoff, *candidates.spools, candidates.points, candidates.receipt):
            (root / snap.location.name).write_bytes(snap.raw)

    def test_binary_roundtrip_and_exact_private_layout(self):
        self.assertEqual(codec.SPOOL_BYTES, 79423)
        self.assertEqual(codec.BODY_OFFSET, 170)
        self.assertEqual(codec.RECORD_BYTES, 19777)
        for reader in self.accepted.readers:
            tapes = tuple((reader.selected_value(i) & ((1 << 2048) - 1)) |
                          ((reader.selected_value(i) >> 2048) << 2064) for i in range(4))
            raw = codec.encode_insecure_test_only(reader.context, reader, tapes, reader.xi_masks)
            self.assertEqual(raw, reader.snapshot.raw)
            self.assertEqual(len(reader.xi_masks), 386)
            reader.assert_values(self.session.values)
            self.assertEqual(self.decode(raw, reader.context.tree_index).record(0), reader.record(0))

    def test_frozen_native_and_handoff_evidence(self):
        for key, expected in gate.FROZEN.items():
            self.assertEqual(self.evidence[key], expected)
        for key, expected in gate.base.FROZEN.items():
            self.assertEqual(self.evidence["native_qualification"][key], expected)
        self.assertFalse(self.evidence["full_session_restore_implemented"])
        self.assertFalse(self.evidence["durable_resume_implemented"])
        self.assertFalse(self.evidence["Production-closed"])
        self.assertEqual(self.evidence["native_qualification"]["relocation_port_count"], 8)

    def test_wrong_header_version_profile_statement_tree_and_length(self):
        raw = self.candidates.spools[0].raw
        offsets = (0, len(codec.MAGIC), len(codec.MAGIC) + 2,
                   len(codec.MAGIC) + 34, len(codec.MAGIC) + 66,
                   len(codec.MAGIC) + 98, codec.BODY_OFFSET - 1)
        for offset in offsets:
            changed = bytearray(raw)
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(codec.SpoolError):
                self.decode(bytes(changed))
        for changed in (raw[:-1], raw + b"\x00", raw + b"\n", b""):
            with self.assertRaises(codec.SpoolError):
                self.decode(changed)
        for context in (self.session.context(1), replace(self.session.context(0), invocation_sha256="0" * 64),
                        replace(self.session.context(0), plan_sha256="0" * 64)):
            with self.assertRaises(codec.SpoolError):
                self.decode(raw, context=context)

    def test_bad_wire_alias_future_owner_and_nonzero_padding(self):
        raw = self.candidates.spools[0].raw
        first = self.accepted.readers[0].record(0)[0]
        cases = [(codec.BODY_OFFSET, 0), (codec.BODY_OFFSET, self.session.context(0).pre_end),
                 (codec.BODY_OFFSET, self.session.context(1).pre_start),
                 (codec.BODY_OFFSET + 8, first),
                 (codec.BODY_OFFSET + codec.RECORD_BYTES, first)]
        for offset, wire in cases:
            changed = bytearray(raw)
            struct.pack_into("<Q", changed, offset, wire)
            with self.subTest(offset=offset, wire=wire), self.assertRaises(codec.SpoolError):
                self.decode(bytes(changed))
        for offset in (codec.BODY_OFFSET + codec.RECORD_BYTES - 1, len(raw) - 1):
            changed = bytearray(raw)
            changed[offset] |= 0x80
            with self.assertRaises(codec.SpoolError):
                self.decode(bytes(changed))

    def test_identity_precedes_decode_and_selected_bits_bind_assignment(self):
        raw = bytearray(self.candidates.spools[0].raw)
        raw[codec.BODY_OFFSET + codec.WIRE_RECORD.size] ^= 1
        mutated = replace(self.candidates.spools[0], raw=bytes(raw))
        with patch.object(codec.TreeSpoolSnapshotInsecureTestOnly, "validate", side_effect=AssertionError("decode")):
            with self.assertRaises(codec.SpoolError):
                codec.decode_snapshot_insecure_test_only(mutated, expected_bytes=codec.SPOOL_BYTES,
                    expected_sha256=self.candidates.spools[0].identity["sha256"], context=self.session.context(0))
        # A parser accepting an out-of-band re-pinned shape is NOT proof of its
        # relation. The actual adoption path also checks every selected bit.
        reader = self.decode(bytes(raw))
        with self.assertRaises(codec.SpoolError):
            reader.assert_values(self.session.values)

    def test_immutable_types_and_bounded_scratch_writer(self):
        reader = self.accepted.readers[0]
        with self.assertRaises(FrozenInstanceError):
            reader.context = self.session.context(1)
        with self.assertRaises(io.ValidationError):
            io.Snapshot(Path("/memory/x"), bytearray(reader.snapshot.raw))
        with self.assertRaises(codec.SpoolError):
            replace(self.candidates, spools=list(self.candidates.spools))
        for invalid in (True, -1, 4, "0"):
            with self.assertRaises(codec.SpoolError):
                reader.record(invalid)
        for invalid in (True, -1, codec.RECORD_WIRES):
            with self.assertRaises(codec.SpoolError):
                reader.wire(0, invalid)
        with self.assertRaises(codec.SpoolError):
            codec.BoundedMemoryWireSpoolInsecureTestOnly(True)
        spool = codec.BoundedMemoryWireSpoolInsecureTestOnly(codec.RECORD_WIRES)
        with self.assertRaises(codec.SpoolError):
            spool.open_reader()
        for i in range(4):
            spool.append(reader.record(i))
        spool.open_reader()
        with self.assertRaises(codec.SpoolError):
            spool.append(reader.record(0))

    def test_capture_once_with_fixed_names_and_identity_first(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_candidates(root)
            with patch.object(io, "read_snapshot", wraps=io.read_snapshot) as read:
                candidates = gate.capture_candidates(root, expected_handoff_sha256=self.pin)
            self.assertEqual([call.args[0].name for call in read.call_args_list],
                             [gate.HANDOFF_NAME, *gate.SPOOL_NAMES, gate.POINT_NAME, gate.RECEIPT_NAME])
            self.assertEqual(candidates.spools[0].raw, self.candidates.spools[0].raw)
            with patch.object(io.Snapshot, "document", side_effect=AssertionError("parse")), \
                    patch.object(io, "read_snapshot", wraps=io.read_snapshot) as read:
                with self.assertRaises(codec.SpoolError):
                    gate.capture_candidates(root, expected_handoff_sha256="0" * 64)
                self.assertEqual(read.call_count, 1)
            with patch.object(io, "read_snapshot", side_effect=AssertionError("read")):
                with self.assertRaises(codec.SpoolError):
                    gate.capture_candidates(root, expected_handoff_sha256="not-a-digest")

    def test_handoff_schema_mutations_and_artifact_identity_refuse(self):
        original = self.candidates.handoff
        cases = (("format", "unknown-version"), ("relation_id", "wrong-domain"),
                 ("next_stage", "tree-post[1]"), ("production", True), ("durable_resume", 0),
                 ("spools", list(reversed(original.document()["spools"]))), ("unknown", None))
        for key, value in cases:
            doc = original.document()
            doc[key] = value
            snap = replace(original, raw=io.canonical_json(doc))
            with self.subTest(key=key), self.assertRaises(codec.SpoolError):
                gate._handoff_document(snap, codec.sha256(snap.raw))
        for raw in (original.raw + b"\n", original.raw.replace(b'"production":false', b'"production":false,"production":false')):
            with self.assertRaises(io.ValidationError):
                gate._handoff_document(replace(original, raw=raw), codec.sha256(raw))
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_candidates(root)
            target = root / gate.SPOOL_NAMES[0]
            target.write_bytes(target.read_bytes() + b"\x00")
            with self.assertRaises(codec.SpoolError):
                gate.capture_candidates(root, expected_handoff_sha256=self.pin)
            target.unlink()
            target.symlink_to(root / gate.SPOOL_NAMES[1])
            with self.assertRaises((io.ValidationError, OSError)):
                gate.capture_candidates(root, expected_handoff_sha256=self.pin)

    def test_adoption_rejections_then_inplace_snapshot_consumption(self):
        session = gate.HandoffSessionInsecureTestOnly()
        try:
            session.run_to("global-a")
            candidates = session.export_candidates()
            pin = codec.sha256(candidates.handoff.raw)
            rows, cursors = session.rows, dict(session.allocator.cursors)
            with patch.object(session, "_advance", side_effect=AssertionError("compute")):
                with self.assertRaises(codec.SpoolError):
                    session.run_to("tree-post[0]")
                for key, value in (("invocation_sha256", "0" * 64), ("plan_sha256", "0" * 64)):
                    doc = candidates.handoff.document()
                    doc[key] = value
                    changed = replace(candidates, handoff=replace(candidates.handoff, raw=io.canonical_json(doc)))
                    with self.assertRaises(codec.SpoolError):
                        session.accept_handoff(changed, expected_handoff_sha256=codec.sha256(changed.handoff.raw))
                for changed in (replace(candidates, spools=tuple(reversed(candidates.spools))),
                                replace(candidates, receipt=replace(candidates.receipt, raw=candidates.receipt.raw + b"\x00")),
                                replace(candidates, points=replace(candidates.points, raw=candidates.points.raw + b"\n"))):
                    with self.assertRaises(codec.SpoolError):
                        session.accept_handoff(changed, expected_handoff_sha256=pin)
            self.assertEqual((session.rows, session.allocator.cursors), (rows, cursors))
            self.assertIsNone(session.accepted_handoff)
            with TemporaryDirectory() as temp:
                root = Path(temp)
                self.write_candidates(root, candidates)
                path = root / gate.SPOOL_NAMES[0]
                before = path.stat()
                later = bytearray(path.read_bytes())
                later[codec.BODY_OFFSET + codec.WIRE_RECORD.size] ^= 1
                later = bytes(later)
                real_fdopen, real_fstat, real_stat = os.fdopen, os.fstat, os.stat
                reads = []

                class ControlledReader:
                    def __init__(self, handle): self.handle = handle
                    def __enter__(self): self.handle.__enter__(); return self
                    def __exit__(self, *args): return self.handle.__exit__(*args)
                    def fileno(self): return self.handle.fileno()
                    def read(self, limit):
                        raw = self.handle.read(limit)
                        if real_fstat(self.fileno()).st_ino == before.st_ino:
                            reads.append(limit)
                            # Old bytes are fully captured first; same-inode,
                            # same-length rewrite with deliberately stale signals.
                            path.write_bytes(later)
                        return raw

                def stale_fstat(fd):
                    actual = real_fstat(fd)
                    return before if actual.st_ino == before.st_ino else actual

                def stale_stat(name, *args, **kwargs):
                    actual = real_stat(name, *args, **kwargs)
                    return before if actual.st_ino == before.st_ino else actual

                with patch.object(os, "fdopen", side_effect=lambda *a, **k: ControlledReader(real_fdopen(*a, **k))), \
                        patch.object(os, "fstat", side_effect=stale_fstat), patch.object(os, "stat", side_effect=stale_stat):
                    captured = gate.capture_candidates(root, expected_handoff_sha256=pin)
                self.assertEqual(reads, [io.MAX_JSON_BYTES + 1])
                self.assertEqual(path.stat().st_ino, before.st_ino)
                self.assertEqual(path.read_bytes(), later)
                self.assertEqual(captured.spools[0].raw, candidates.spools[0].raw)
                with patch.object(io, "read_snapshot", side_effect=AssertionError("pathname reopen")), \
                        patch.object(gate.base.cap, "execute_cap_commit", side_effect=AssertionError("CAP reconstruction")):
                    accepted = session.accept_handoff(captured, expected_handoff_sha256=pin)
                    self.assertIs(accepted.readers[0].snapshot, captured.spools[0])
                    with patch.object(gate.base.shard, "_sponge_assignment_blob", side_effect=AssertionError("tree pre rerun")):
                        session.run_to("tree-post[1]")
                    session.run_to()
                self.assertEqual(session.handoff_evidence(), self.evidence)
                with self.assertRaises(codec.SpoolError):
                    session.accept_handoff(captured, expected_handoff_sha256=pin)
        finally:
            session.close()

    def test_production_and_readonly_preflight_do_not_construct_or_publish(self):
        with TemporaryDirectory() as temp:
            output = Path(temp) / "must-not-exist"
            with patch.object(gate, "HandoffSessionInsecureTestOnly", side_effect=AssertionError("fixture")), \
                    patch.object(io, "read_snapshot", side_effect=AssertionError("read")), \
                    patch.object(Path, "mkdir", side_effect=AssertionError("mkdir")):
                with self.assertRaises(gate.base.ProductionUnavailable):
                    gate.execute_production(object(), output=output)
            self.assertFalse(output.exists())
        with patch.object(gate, "HandoffSessionInsecureTestOnly", side_effect=AssertionError("fixture")):
            report = gate.preflight()
        self.assertTrue(report["read_only_preflight_passed"])
        self.assertFalse(report["safe_to_start_large_replay"])
        self.assertEqual(len(report["missing_production_artifacts"]), 5)
        gen = native._iter_tree_spool_native_insecure_test_only(
            gate.base.cap.PRODUCTION_PARAMETERS, None, None, 0, spool_context=None,
            sink_factory=lambda *a, **k: self.fail("sink opened"))
        with self.assertRaises(ValueError): next(gen)

    def test_manifest_and_portable_metadata_are_exact_and_private_free(self):
        with patch.object(gate, "bounded_self_check", return_value=self.evidence):
            for path, doc in ((gate.MANIFEST_PATH, gate.build_manifest()),
                              (gate.EVIDENCE_PATH, gate.build_portable_evidence())):
                raw = (gate.ROOT / path).read_bytes()
                self.assertEqual(raw, io.canonical_json(doc))
                io.strict_json(raw)
                self.assertNotIn(str(gate.ROOT).encode(), raw)
                self.assertNotIn(self.candidates.spools[0].raw, raw)


if __name__ == "__main__":
    unittest.main()
