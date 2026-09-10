from dataclasses import replace
from functools import lru_cache
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import pq_rbbc_cap_unified_tree_recovery_v2_42 as r
import pq_rbbc_launch_io_v2_41 as io
import pq_rbbc_recovery_io_v2_42 as disk


class SimulatedCrash(Exception):
    pass


def competing_publisher(path, queue):
    try:
        disk.publish(path, b"complete publication\n")
        queue.put("created")
    except FileExistsError:
        queue.put("exists")


class RecoveryV242Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory(prefix="pq-rbbc-v242-inputs-")
        cls.input_root = Path(cls.fixture.name)
        external = Path("/tmp/pq_rbbc_external_artifacts_rebuilt")
        paths = (
            external / "v2_36_unified_tree_relation/qualification" / r.old.V2_36_CHECKPOINT_IDENTITY["filename"],
            external / "v2_37_unified_statement_parent_abi/qualification" / r.old.V2_37_BOUNDED_VECTOR_IDENTITY["filename"],
        )
        cls.inputs = []
        for path, expected in zip(paths, (r.old.V2_36_CHECKPOINT_IDENTITY, r.old.V2_37_BOUNDED_VECTOR_IDENTITY)):
            snapshot = io.read_snapshot(path)
            if snapshot.identity != expected:
                raise AssertionError("installed bounded fixture differs from frozen identity")
            target = cls.input_root / path.name
            target.write_bytes(snapshot.raw)
            cls.inputs.append(target)
        # Cache only immutable, identity-checked fixtures. Real parser, journal,
        # writer, resume validation and publication run for every fault injection.
        cls.cached_chunks = staticmethod(lru_cache(maxsize=8)(r.bounded_chunks))
        cls.chunks = cls.cached_chunks(*(io.read_snapshot(p) for p in cls.inputs))

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pq-rbbc-v242-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.out = self.root / "bounded"
        self.addCleanup(patch.stopall)
        patch.object(r, "bounded_chunks", side_effect=self.cached_chunks).start()

    def run_stream(self, output=None, **kwargs):
        return r.run_bounded_stream(*self.inputs, output or self.out,
                                    artifact_root=self.root, input_root=self.input_root, **kwargs)

    def latest(self, output=None):
        return r.latest_checkpoint(output or self.out, artifact_root=self.root)

    def resume(self, output=None, **kwargs):
        expected = kwargs.pop("expected_checkpoint_sha256", self.latest(output).identity["sha256"])
        return self.run_stream(output, resume=True, expected_checkpoint_sha256=expected, **kwargs)

    def crash_before(self, name):
        original = disk.publish
        def publish(path, raw):
            if path.name == name:
                raise SimulatedCrash(name)
            return original(path, raw)
        with patch.object(disk, "publish", side_effect=publish), self.assertRaises(SimulatedCrash):
            self.run_stream(fresh_output=True)

    def snapshot_files(self, output=None):
        return {str(p.relative_to(output or self.out)): p.read_bytes()
                for p in (output or self.out).rglob("*") if p.is_file()}

    def test_fresh_and_controlled_resume_have_identical_bytes(self):
        fresh = self.root / "fresh"
        expected = self.run_stream(fresh, fresh_output=True)
        self.assertIsNone(self.run_stream(fresh_output=True, stop_after_chunks=7))
        result = self.resume()
        self.assertEqual(result, expected)
        self.assertEqual(self.snapshot_files(), self.snapshot_files(fresh))
        self.assertEqual(result["bounded_records_materialized"], 179)
        self.assertEqual(result["bounded_chunks_materialized"], 15)

    def test_cr01_window_a_exact_orphan_is_recomputed_and_adopted(self):
        self.crash_before(r.prefix_name(1))
        self.assertEqual(self.latest().document()["completed_chunk_count"], 0)
        path = self.out / r.CHUNK_DIRECTORY / r.old.chunk_filename(self.chunks[0])
        before = (path.read_bytes(), path.stat().st_ino)
        self.resume()
        self.assertEqual(before, (path.read_bytes(), path.stat().st_ino))

    def test_cr01_window_b_all_chunks_complete_false_finalizes(self):
        self.crash_before(r.COMPLETE_FILENAME)
        last = self.latest()
        self.assertEqual(last.document()["completed_chunk_count"], 15)
        self.assertIs(last.document()["complete"], False)
        before = self.snapshot_files()
        self.resume()
        for name, raw in before.items():
            self.assertEqual((self.out / name).read_bytes(), raw)
        self.assertIs(self.latest().document()["complete"], True)

    def test_every_durable_publication_boundary_recovers_identically(self):
        expected_out = self.root / "reference"
        self.run_stream(expected_out, fresh_output=True)
        reference = self.snapshot_files(expected_out)
        # Prefix 0 is the first resumable identity. After that every chunk,
        # prefix, complete checkpoint, index and evidence boundary is exercised.
        boundaries = ([r.old.chunk_filename(c) for c in self.chunks]
                      + [r.prefix_name(i) for i in range(1, 16)]
                      + [r.COMPLETE_FILENAME, r.INDEX_FILENAME, r.EVIDENCE_FILENAME])
        for i, name in enumerate(boundaries):
            with self.subTest(boundary=name):
                self.out = self.root / f"fault-{i}"
                self.crash_before(name)
                self.resume()
                self.assertEqual(self.snapshot_files(), reference)

    def test_corrupted_orphan_bytes_sha_ordinal_stage_fail_closed(self):
        raw = self.chunks[0].encode(r.old.BOUNDED_PROFILE_FINGERPRINT)
        ordinal = replace(self.chunks[0], ordinal=1).encode(r.old.BOUNDED_PROFILE_FINGERPRINT)
        stage = bytearray(raw)
        offset = len(r.old.STREAM_MAGIC) + 2 + 32 + 4
        stage[offset:offset + 2] = (2).to_bytes(2, "little")
        variants = [raw[:-1], raw + b"X", raw[:-1] + bytes([raw[-1] ^ 1]), ordinal, bytes(stage)]
        for i, bad in enumerate(variants):
            with self.subTest(mutation=i):
                self.out = self.root / f"corrupt-{i}"
                self.crash_before(r.prefix_name(1))
                path = self.out / r.CHUNK_DIRECTORY / r.old.chunk_filename(self.chunks[0])
                path.write_bytes(bad)
                before = self.snapshot_files()
                with self.assertRaises((io.ValidationError, r.old.StreamingPrefreezeError)):
                    self.resume()
                self.assertEqual(self.snapshot_files(), before)

    def test_unknown_missing_gapped_and_multiple_orphans_rejected(self):
        for case in ("unknown", "gap", "multiple", "missing"):
            with self.subTest(case=case):
                self.out = self.root / case
                self.run_stream(fresh_output=True, stop_after_chunks=1 if case == "missing" else 0)
                folder = self.out / r.CHUNK_DIRECTORY
                if case == "unknown":
                    (folder / "foreign.bin").write_bytes(b"unknown")
                elif case == "missing":
                    (folder / r.old.chunk_filename(self.chunks[0])).unlink()
                else:
                    selected = [self.chunks[1]] if case == "gap" else self.chunks[:2]
                    for chunk in selected:
                        (folder / r.old.chunk_filename(chunk)).write_bytes(chunk.encode(r.old.BOUNDED_PROFILE_FINGERPRINT))
                before = self.snapshot_files()
                with self.assertRaises(io.ValidationError):
                    self.resume()
                self.assertEqual(self.snapshot_files(), before)

    def test_repeated_resume_is_byte_and_inode_idempotent(self):
        expected = self.run_stream(fresh_output=True)
        before = self.snapshot_files()
        inodes = {p: p.stat().st_ino for p in self.out.rglob("*")}
        for _ in range(3):
            self.assertEqual(self.resume(), expected)
        self.assertEqual(self.snapshot_files(), before)
        self.assertTrue(all(p.stat().st_ino == inode for p, inode in inodes.items()))

    def test_finalization_missing_index_or_evidence_is_idempotent(self):
        for name in (r.INDEX_FILENAME, r.EVIDENCE_FILENAME):
            with self.subTest(boundary=name):
                self.out = self.root / name
                self.crash_before(name)
                self.assertIs(self.latest().document()["complete"], True)
                expected = self.resume()
                self.assertEqual(self.resume(), expected)

    def test_corrupt_final_or_premature_complete_never_overwritten(self):
        for name in (r.INDEX_FILENAME, r.EVIDENCE_FILENAME, r.COMPLETE_FILENAME):
            with self.subTest(name=name):
                self.out = self.root / name
                self.run_stream(fresh_output=True)
                path = (self.out / r.JOURNAL_DIRECTORY if name == r.COMPLETE_FILENAME else self.out) / name
                path.write_bytes(b'{"invalid":true}\n')
                before = self.snapshot_files()
                with self.assertRaises(io.ValidationError):
                    self.resume()
                self.assertEqual(self.snapshot_files(), before)
        self.out = self.root / "premature"
        self.run_stream(fresh_output=True, stop_after_chunks=0)
        (self.out / r.JOURNAL_DIRECTORY / r.COMPLETE_FILENAME).write_bytes(self.latest().raw)
        with self.assertRaises(io.ValidationError):
            self.resume()

    def test_checkpoint_mutations_strict_types_and_chain(self):
        mutations = (
            lambda d: d.update(complete=0), lambda d: d.update(completed_chunk_count=True),
            lambda d: d.update(production_records_materialized=False),
            lambda d: d.update(chain_sha256="0" * 64),
            lambda d: d.update(previous_checkpoint_sha256="0" * 64),
            lambda d: d["chunk_records"][0]["chunk_identity"].update(bytes=1.0),
            lambda d: d["chunk_records"][0].update(ordinal=True),
            lambda d: d.update(extra="unrecognized"),
        )
        for i, mutate in enumerate(mutations):
            with self.subTest(mutation=i):
                self.out = self.root / f"checkpoint-{i}"
                self.run_stream(fresh_output=True, stop_after_chunks=1)
                last = self.latest()
                document = last.document()
                mutate(document)
                last.location.write_bytes(io.canonical_json(document))
                before = self.snapshot_files()
                with self.assertRaises(io.ValidationError):
                    self.resume()  # even a correct external hash cannot bless invalid semantics
                self.assertEqual(before, self.snapshot_files())

    def test_duplicate_noncanonical_utf8_and_trailing_checkpoint_rejected(self):
        self.run_stream(fresh_output=True, stop_after_chunks=0)
        last = self.latest()
        for raw in (last.raw + b"\n", last.raw.replace(b'"complete":false', b'"complete":false,"complete":false'), b'\xff{}\n'):
            last.location.write_bytes(raw)
            with self.assertRaises(io.ValidationError):
                self.resume()

    def test_missing_wrong_and_stale_external_digest_rejected(self):
        self.run_stream(fresh_output=True, stop_after_chunks=1)
        old = self.latest().identity["sha256"]
        for bad in (None, "0" * 64, "A" * 64, 123):
            with self.assertRaises(io.ValidationError):
                self.run_stream(resume=True, expected_checkpoint_sha256=bad)
        self.resume(stop_after_chunks=2)
        with self.assertRaises(io.ValidationError):
            self.resume(expected_checkpoint_sha256=old)

    def test_chunk_symlink_dangling_hardlink_and_fifo_rejected(self):
        for case in ("symlink", "dangling", "hardlink", "fifo"):
            with self.subTest(case=case):
                self.out = self.root / case
                self.run_stream(fresh_output=True, stop_after_chunks=0)
                path = self.out / r.CHUNK_DIRECTORY / r.old.chunk_filename(self.chunks[0])
                target = self.root / f"target-{case}"
                if case != "dangling":
                    target.write_bytes(self.chunks[0].encode(r.old.BOUNDED_PROFILE_FINGERPRINT))
                if case in ("symlink", "dangling"):
                    path.symlink_to(target)
                elif case == "hardlink":
                    os.link(target, path)
                else:
                    os.mkfifo(path)
                with self.assertRaises((io.ValidationError, OSError)):
                    self.resume()

    def test_fresh_output_root_boundaries_and_overwrite_refusal(self):
        for bad in (r.ROOT / "forbidden", self.root / "nested" / "forbidden"):
            with self.assertRaises((io.ValidationError, OSError)):
                self.run_stream(bad, fresh_output=True)
            self.assertFalse(bad.exists())
        self.run_stream(fresh_output=True, stop_after_chunks=0)
        before = self.snapshot_files()
        with self.assertRaises(FileExistsError):
            self.run_stream(fresh_output=True)
        self.assertEqual(before, self.snapshot_files())

    def test_exact_input_identities_checked_before_parse_or_output(self):
        a, b = (io.read_snapshot(p) for p in self.inputs)
        for changed in (a.raw + b"\n", b'{"approved":true}\n', b"\xff"):
            with self.assertRaises(io.ValidationError):
                self.cached_chunks(io.Snapshot(a.location, changed), b)
        with self.assertRaises(io.ValidationError):
            self.cached_chunks(io.Snapshot(a.location.with_name("same-bytes-other-name.json"), a.raw), b)
        self.assertFalse(self.out.exists())

    def test_tracked_contract_and_predecessor_mutations_reject_before_output(self):
        original = io.read_snapshot
        for path in (r.MANIFEST_PATH, r.PROVENANCE_PATH,
                     r.ROOT / "src/pq_rbbc_cap_unified_tree_streaming_prefreeze.py",
                     r.ROOT / "artifacts/metadata/cap_unified_tree_streaming_prefreeze_v2_38/pq_rbbc_cap_unified_tree_streaming_prefreeze_portable_evidence_v2_38.json"):
            def changed(candidate, **kwargs):
                snap = original(candidate, **kwargs)
                return io.Snapshot(snap.location, snap.raw + b"\n") if candidate == path else snap
            with self.subTest(path=path), patch.object(io, "read_snapshot", side_effect=changed):
                with self.assertRaises(io.ValidationError):
                    self.run_stream(fresh_output=True)
            self.assertFalse(self.out.exists())

    def test_v238_checkpoint_namespace_cannot_be_adopted_in_place(self):
        self.run_stream(fresh_output=True, stop_after_chunks=0)
        latest = self.latest()
        changed = latest.document()
        changed.update(implementation_version="2.38", format=r.old.CHECKPOINT_FORMAT)
        latest.location.write_bytes(io.canonical_json(changed))
        with self.assertRaises(io.ValidationError):
            self.resume()

    def test_existing_journal_gap_unknown_and_changed_old_prefix_rejected(self):
        for case in ("gap", "unknown", "old-prefix"):
            with self.subTest(case=case):
                self.out = self.root / case
                self.run_stream(fresh_output=True, stop_after_chunks=2)
                journal = self.out / r.JOURNAL_DIRECTORY
                if case == "gap":
                    (journal / r.prefix_name(1)).unlink()
                elif case == "unknown":
                    (journal / "unrecognized.json").write_bytes(b"{}\n")
                else:
                    (journal / r.prefix_name(0)).write_bytes(b"{}\n")
                with self.assertRaises(io.ValidationError):
                    self.resume()

    def test_corrupted_orphan_cannot_be_rescued_by_post_capture_replacement(self):
        self.crash_before(r.prefix_name(1))
        path = self.out / r.CHUNK_DIRECTORY / r.old.chunk_filename(self.chunks[0])
        correct = path.read_bytes()
        path.write_bytes(correct[:-1] + bytes([correct[-1] ^ 1]))
        original = disk.read
        def swap(candidate):
            snapshot = original(candidate)
            if candidate == path:
                path.write_bytes(correct)
            return snapshot
        with patch.object(disk, "read", side_effect=swap), self.assertRaises(io.ValidationError):
            self.resume()
        self.assertEqual(self.latest().document()["completed_chunk_count"], 0)

    def test_competing_chunk_publication_never_overwritten(self):
        original = disk.publish
        def race(path, raw):
            if path.suffix == ".bin":
                path.write_bytes(b"competing writer")
            return original(path, raw)
        with patch.object(disk, "publish", side_effect=race), self.assertRaises(FileExistsError):
            self.run_stream(fresh_output=True)
        self.assertEqual(self.latest().document()["completed_chunk_count"], 0)
        self.assertEqual(next((self.out / r.CHUNK_DIRECTORY).iterdir()).read_bytes(), b"competing writer")

    def test_orphan_mutation_between_inventory_and_adoption_rejected(self):
        self.crash_before(r.prefix_name(1))
        path = self.out / r.CHUNK_DIRECTORY / r.old.chunk_filename(self.chunks[0])
        original = disk.read
        def mutate_after_capture(candidate):
            snapshot = original(candidate)
            if candidate == path:
                path.write_bytes(snapshot.raw[:-1] + bytes([snapshot.raw[-1] ^ 1]))
            return snapshot
        with patch.object(disk, "read", side_effect=mutate_after_capture), self.assertRaises(io.ValidationError):
            self.resume()
        self.assertEqual(self.latest().document()["completed_chunk_count"], 0)

    def test_unknown_chunk_introduced_before_finalization_rejected(self):
        original = disk.publish
        def interfere(path, raw):
            original(path, raw)
            if path.name == r.prefix_name(15):
                (self.out / r.CHUNK_DIRECTORY / "unknown.bin").write_bytes(b"foreign")
        with patch.object(disk, "publish", side_effect=interfere), self.assertRaises(io.ValidationError):
            self.run_stream(fresh_output=True)
        self.assertFalse((self.out / r.JOURNAL_DIRECTORY / r.COMPLETE_FILENAME).exists())

    def test_second_writer_is_rejected_by_output_lock(self):
        self.run_stream(fresh_output=True, stop_after_chunks=0)
        before = self.snapshot_files()
        with disk.locked_output(self.out, self.root, fresh=False):
            with self.assertRaisesRegex(io.ValidationError, "another bounded writer"):
                self.resume()
        self.assertEqual(before, self.snapshot_files())

    def test_real_process_death_at_both_reported_windows_releases_lock(self):
        context = multiprocessing.get_context("fork")
        for name in (r.prefix_name(1), r.COMPLETE_FILENAME):
            with self.subTest(window=name):
                self.out = self.root / name
                def worker():
                    original = disk.publish
                    def crash(path, raw):
                        if path.name == name:
                            os._exit(73)
                        return original(path, raw)
                    with patch.object(disk, "publish", side_effect=crash):
                        self.run_stream(fresh_output=True)
                process = context.Process(target=worker)
                process.start()
                process.join(15)
                if process.is_alive():
                    process.kill()
                    process.join()
                    self.fail("fault-injection child timed out")
                self.assertEqual(process.exitcode, 73)
                self.resume()
                self.assertTrue(self.latest().document()["complete"])

    def test_production_api_and_cli_reject_before_any_output(self):
        with self.assertRaises(io.ValidationError):
            r.reject_production_prefreeze(resource_reservation="v2.41", allow_large=True)
        command = [sys.executable, str(r.ROOT / "src/pq_rbbc_cap_unified_tree_recovery_v2_42.py"),
                   "--phase", "production-prefreeze", "--artifact-root", str(self.root),
                   "--output", str(self.out), "--fresh-output"]
        completed = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unavailable", completed.stderr)
        self.assertFalse(self.out.exists())
        self.assertTrue(all(value is False for value in r.claim_boundary().values()))


class RecoveryPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pq-rbbc-v242-publication-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "published.json"

    def test_atomic_publication_rejects_existing_and_dangling_symlink(self):
        for target_exists in (False, True):
            target = self.root / "target"
            if target_exists:
                target.write_bytes(b"retained")
            self.path.symlink_to(target)
            with self.assertRaises(FileExistsError):
                disk.publish(self.path, b"{}\n")
            self.path.unlink()
            if target_exists:
                self.assertEqual(target.read_bytes(), b"retained")

    def test_failure_before_publish_leaves_no_temporary_or_final(self):
        with patch.object(disk.os, "fsync", side_effect=OSError("simulated fsync failure")):
            with self.assertRaises(OSError):
                disk.publish(self.path, b"{}\n")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_real_parallel_exclusive_publish_has_one_winner(self):
        context = multiprocessing.get_context("fork")
        queue = context.Queue()
        processes = [context.Process(target=competing_publisher, args=(self.path, queue)) for _ in range(8)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(10)
            self.assertEqual(process.exitcode, 0)
        results = [queue.get(timeout=2) for _ in processes]
        self.assertEqual(results.count("created"), 1)
        self.assertEqual(results.count("exists"), 7)
        self.assertEqual(self.path.read_bytes(), b"complete publication\n")
        self.assertEqual(self.path.stat().st_nlink, 1)
        self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_process_death_after_link_leaves_one_complete_file_no_staging(self):
        context = multiprocessing.get_context("fork")
        def worker():
            original = disk.os.fsync
            calls = 0
            def stop_after_link(fd):
                nonlocal calls
                calls += 1
                original(fd)
                if calls == 2:  # directory fsync, after exclusive link
                    os._exit(74)
            with patch.object(disk.os, "fsync", side_effect=stop_after_link):
                disk.publish(self.path, b"{}\n")
        process = context.Process(target=worker)
        process.start()
        process.join(10)
        self.assertEqual(process.exitcode, 74)
        self.assertEqual(self.path.read_bytes(), b"{}\n")
        self.assertEqual(self.path.stat().st_nlink, 1)
        self.assertEqual(list(self.root.iterdir()), [self.path])
        with self.assertRaises(FileExistsError):
            disk.publish(self.path, b"changed\n")


if __name__ == "__main__":
    unittest.main()
