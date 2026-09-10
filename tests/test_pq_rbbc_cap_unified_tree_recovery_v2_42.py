from dataclasses import replace
from functools import lru_cache
import errno
import multiprocessing
import os
from pathlib import Path
import subprocess
import stat
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

    def fail_directory_fsync_after_link(self, name):
        original_publish, original_fsync = disk.publish, os.fsync
        publishing = None
        def publish(path, raw):
            nonlocal publishing
            publishing = path
            try:
                return original_publish(path, raw)
            finally:
                publishing = None
        def fsync(fd):
            if (publishing is not None and publishing.name == name
                    and stat.S_ISDIR(os.fstat(fd).st_mode)):
                self.assertTrue(publishing.is_file())  # real linkat already ran
                raise OSError(errno.EIO, "post-link directory fsync")
            return original_fsync(fd)
        with patch.object(disk, "publish", side_effect=publish), \
                patch.object(disk.os, "fsync", side_effect=fsync), \
                self.assertRaisesRegex(OSError, "post-link directory fsync"):
            self.run_stream(fresh_output=True)

    def check_failed_barrier_then_retry(self, directory):
        before = self.snapshot_files()
        inodes = {p: p.stat().st_ino for p in self.out.rglob("*")}
        expected_sha256 = self.latest().identity["sha256"]
        original_fsync = os.fsync
        def still_fails(fd):
            if (stat.S_ISDIR(os.fstat(fd).st_mode)
                    and os.readlink(f"/proc/self/fd/{fd}") == str(directory)):
                raise OSError(errno.EIO, "retry directory fsync still fails")
            return original_fsync(fd)
        # Repeated EIO must not publish anything, including on a fully complete
        # journal whose last evidence entry was linked but not directory-synced.
        for _ in range(2):
            with patch.object(disk.os, "fsync", side_effect=still_fails), \
                    patch.object(disk, "publish") as publish, \
                    self.assertRaisesRegex(OSError, "retry directory fsync still fails"):
                self.resume(expected_checkpoint_sha256=expected_sha256)
            publish.assert_not_called()
            self.assertEqual(self.snapshot_files(), before)
            self.assertTrue(all(p.stat().st_ino == inode for p, inode in inodes.items()))
        events = []
        original_sync, original_publish = disk.sync_directory, disk.publish
        def sync(path, fd):
            original_sync(path, fd)
            events.append(("synced", path))
        def publish(path, raw):
            self.assertIn(("synced", directory), events)
            events.append(("publish", path))
            return original_publish(path, raw)
        with patch.object(disk, "sync_directory", side_effect=sync), \
                patch.object(disk, "publish", side_effect=publish):
            result = self.resume(expected_checkpoint_sha256=expected_sha256)
        self.assertIn(("synced", directory), events)
        self.assertEqual(result["bounded_chunks_materialized"], 15)
        self.assertEqual(events[:3], [("synced", self.out / r.CHUNK_DIRECTORY),
                                     ("synced", self.out / r.JOURNAL_DIRECTORY),
                                     ("synced", self.out)])
        self.assertTrue(all((self.out / name).read_bytes() == raw for name, raw in before.items()))
        self.assertTrue(all(p.stat().st_ino == inode for p, inode in inodes.items()))
        return events

    def test_orphan_link_fsync_eio_retry_requires_barrier_before_prefix(self):
        for ordinal in (0, 14):
            with self.subTest(orphan=ordinal):
                self.out = self.root / f"orphan-fsync-{ordinal}"
                self.fail_directory_fsync_after_link(r.old.chunk_filename(self.chunks[ordinal]))
                self.assertEqual(self.latest().document()["completed_chunk_count"], ordinal)
                events = self.check_failed_barrier_then_retry(self.out / r.CHUNK_DIRECTORY)
                prefix = ("publish", self.out / r.JOURNAL_DIRECTORY / r.prefix_name(ordinal + 1))
                # The immediate orphan-adoption check must be followed by a
                # successful chunks barrier before the successor prefix link.
                self.assertEqual(events[events.index(prefix) - 1],
                                 ("synced", self.out / r.CHUNK_DIRECTORY))

    def test_existing_prefix_and_complete_link_fsync_eio_retry_requires_barrier(self):
        for name in (r.prefix_name(0), r.prefix_name(1), r.prefix_name(15), r.COMPLETE_FILENAME):
            with self.subTest(checkpoint=name):
                self.out = self.root / name
                self.fail_directory_fsync_after_link(name)
                self.check_failed_barrier_then_retry(self.out / r.JOURNAL_DIRECTORY)

    def test_existing_index_and_evidence_link_fsync_eio_retry_requires_barrier(self):
        for name in (r.INDEX_FILENAME, r.EVIDENCE_FILENAME):
            with self.subTest(final=name):
                self.out = self.root / name
                self.fail_directory_fsync_after_link(name)
                events = self.check_failed_barrier_then_retry(self.out)
                publications = [path.name for kind, path in events if kind == "publish"]
                self.assertEqual(publications, [r.EVIDENCE_FILENAME] if name == r.INDEX_FILENAME else [])

    def test_wrong_and_stale_digest_reject_before_fixture_read_or_recompute(self):
        self.run_stream(fresh_output=True, stop_after_chunks=0)
        stale = self.latest().identity["sha256"]
        self.resume(stop_after_chunks=1)
        before = self.snapshot_files()
        for expected in ("0" * 64, stale):
            with self.subTest(digest=expected), \
                    patch.object(io.ArtifactRoot, "read") as read_inputs, \
                    patch.object(r, "bounded_chunks") as recompute, \
                    patch.object(disk, "publish") as publish, \
                    self.assertRaisesRegex(io.ValidationError, "identity mismatch"):
                self.run_stream(resume=True, expected_checkpoint_sha256=expected)
            read_inputs.assert_not_called()
            recompute.assert_not_called()
            publish.assert_not_called()
        self.assertEqual(self.snapshot_files(), before)

    def test_latest_capture_is_locked_once_and_precedes_fixture_reads(self):
        self.run_stream(fresh_output=True, stop_after_chunks=1)
        latest = self.latest()
        events = []
        original_read, original_input_read = disk.read, io.ArtifactRoot.read
        def capture(path):
            if path == latest.location:
                with self.assertRaisesRegex(io.ValidationError, "another bounded writer"):
                    with disk.locked_output(self.out, self.root, fresh=False):
                        self.fail("latest capture ran without output lock")
                events.append("latest")
            return original_read(path)
        def read_input(store, path):
            self.assertEqual(events[0], "latest")
            events.append("input")
            return original_input_read(store, path)
        def chunks(*inputs):
            self.assertEqual(events, ["latest", "input", "input"])
            events.append("chunks")
            return self.cached_chunks(*inputs)
        with patch.object(disk, "read", side_effect=capture), \
                patch.object(io.ArtifactRoot, "read", read_input), \
                patch.object(r, "bounded_chunks", side_effect=chunks):
            self.run_stream(resume=True, expected_checkpoint_sha256=latest.identity["sha256"])
        self.assertEqual(events, ["latest", "input", "input", "chunks"])

    def test_matching_digest_cannot_rescue_bad_latest_snapshot_by_replacing_path(self):
        self.run_stream(fresh_output=True, stop_after_chunks=1)
        latest = self.latest()
        wrong_chain = latest.document()
        wrong_chain["chain_sha256"] = "0" * 64
        wrong_type = latest.document()
        wrong_type["completed_chunk_count"] = True
        variants = (io.canonical_json(wrong_chain), io.canonical_json(wrong_type),
                    latest.raw + b"\n", b"\xff{}\n",
                    latest.raw.replace(b'"complete":false', b'"complete":false,"complete":false'))
        original = disk.read
        for raw in variants:
            latest.location.write_bytes(raw)
            captures = []
            def capture(path):
                snapshot = original(path)
                if path == latest.location:
                    captures.append(snapshot)
                    latest.location.write_bytes(latest.raw)
                return snapshot
            with self.subTest(raw=raw[:32]), patch.object(disk, "read", side_effect=capture), \
                    patch.object(disk, "sync_directory") as sync, \
                    patch.object(disk, "publish") as publish, self.assertRaises(io.ValidationError):
                self.run_stream(resume=True, expected_checkpoint_sha256=r.digest(raw))
            self.assertEqual(len(captures), 1)
            sync.assert_not_called()
            publish.assert_not_called()
        self.assertEqual(self.latest().raw, latest.raw)

    def test_latest_valid_snapshot_is_not_reopened_for_semantic_validation(self):
        self.run_stream(fresh_output=True, stop_after_chunks=0)
        latest = self.latest()
        captures = []
        original = disk.read
        def capture(path):
            snapshot = original(path)
            if path == latest.location:
                captures.append(snapshot)
                latest.location.write_bytes(b"{}\n")
            return snapshot
        try:
            with patch.object(disk, "read", side_effect=capture):
                self.assertIsNone(self.run_stream(resume=True, stop_after_chunks=0,
                                                expected_checkpoint_sha256=latest.identity["sha256"]))
            self.assertEqual(captures, [latest])
            self.assertEqual(latest.location.read_bytes(), b"{}\n")
        finally:
            latest.location.write_bytes(latest.raw)

    def test_latest_namespace_change_after_capture_is_rejected(self):
        self.run_stream(fresh_output=True, stop_after_chunks=0)
        latest = self.latest()
        def changed(*inputs):
            (self.out / r.JOURNAL_DIRECTORY / r.COMPLETE_FILENAME).write_bytes(latest.raw)
            return self.cached_chunks(*inputs)
        with patch.object(r, "bounded_chunks", side_effect=changed), \
                patch.object(disk, "publish") as publish, \
                self.assertRaisesRegex(io.ValidationError, "latest checkpoint location changed"):
            self.run_stream(resume=True, expected_checkpoint_sha256=latest.identity["sha256"])
        publish.assert_not_called()


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

    def test_directory_barrier_rejects_parent_substitution_before_and_after_fsync(self):
        original_fsync = os.fsync
        for when in ("before", "after"):
            with self.subTest(substitution=when):
                parent = self.root / when
                moved = self.root / (when + "-moved")
                parent.mkdir(mode=0o700)
                def substitute():
                    parent.rename(moved)
                    parent.mkdir(mode=0o700)
                with io.directory_fd(parent, external=True) as fd:
                    def fsync(candidate):
                        original_fsync(candidate)
                        substitute()
                    if when == "before":
                        substitute()
                    with patch.object(disk.os, "fsync", side_effect=fsync) as sync, \
                            self.assertRaisesRegex(io.ValidationError, "directory location changed"):
                        disk.sync_directory(parent, fd)
                    self.assertEqual(sync.call_count, 0 if when == "before" else 1)


if __name__ == "__main__":
    unittest.main()
