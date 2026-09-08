"""Synthetic-only validation fixtures. No real reservation/review/freeze output."""

import copy
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest.mock import patch

import pq_rbbc_cap_unified_tree_launch_validation_v2_41 as L
import pq_rbbc_launch_io_v2_41 as IO
from tests.test_pq_rbbc_cap_unified_tree_launch_preflight import valid_resource, valid_review


NOW = datetime(2026, 9, 8, 12, tzinfo=timezone.utc)
CREATED = "2026-09-08T01:00:00Z"


def synthetic_resource(root):
    doc = L._successor(valid_resource())
    doc["reservation_id"] = "TEST-ONLY-reservation"
    doc["launch_batch_id"] = "TEST-ONLY-batch"
    doc["operator"]["identifier"] = "TEST-ONLY-operator"
    doc["operator"]["attestation"]["reference"] = "TEST-ONLY-NOT-AN-ATTESTATION"
    doc["operator"]["approved_at_utc"] = "2026-09-07T12:00:00Z"
    doc["reservation_window"].update(starts_at_utc="2026-09-08T00:00:00Z", ends_at_utc="2026-09-09T00:00:00Z")
    doc["execution_scope"].update(external_output=str(root / "production-prefreeze"), exact_command_sha256=L.command_sha256(root))
    return doc


def synthetic_review(root, resource):
    doc = L._successor(valid_review())
    doc["review_id"] = "TEST-ONLY-review"
    doc["launch_batch_id"] = resource.document()["launch_batch_id"]
    doc["reviewer"].update(identifier="TEST-ONLY-reviewer", affiliation="TEST-ONLY-NOT-A-REAL-LAB", completed_at_utc="2026-09-07T13:00:00Z")
    doc["reviewer"]["attestation"]["reference"] = "TEST-ONLY-NOT-AN-INDEPENDENT-ATTESTATION"
    doc["bound_identities"]["v2_41_candidate_production_command_sha256"] = L.command_sha256(root)
    doc["review_subject"] = L.review_subject(resource)
    return doc


def object_paths(doc, prefix=()):
    if type(doc) is dict:
        yield prefix
        for key, value in doc.items():
            yield from object_paths(value, prefix + (key,))


def at(doc, path):
    for key in path:
        doc = doc[key]
    return doc


class LaunchValidationV241Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pq-rbbc-v241-TEST-ONLY-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.paths = tuple(self.root / L.FILENAMES[k] for k in L.KINDS)
        self.resource = synthetic_resource(self.root)
        self.write(0, self.resource)
        self.review = synthetic_review(self.root, self.snap(0))
        self.write(1, self.review)
        self.launch = self.author()
        self.write(2, self.launch)

    def write(self, index, document):
        self.paths[index].write_bytes(L.canonical_json(document))

    def snap(self, index):
        return IO.ArtifactRoot(self.root).read(self.paths[index])

    def author(self, **kwargs):
        return L.build_launch_manifest(*self.paths[:2], "TEST-ONLY-launch", CREATED,
                                       artifact_root=self.root, clock=kwargs.pop("clock", lambda: NOW), **kwargs)

    def report(self, **kwargs):
        return L.build_preflight(resource_path=self.paths[0], review_path=self.paths[1], launch_path=self.paths[2],
                                 artifact_root=self.root, clock=kwargs.pop("clock", lambda: NOW), **kwargs)

    def assert_rejected(self, report):
        self.assertIs(report["result"]["safe_to_freeze_launch_identity_set"], False)
        for key in ("safe_to_start_production_prefreeze", "safe_to_start_large_replay", "safe_to_start_large_proving_run"):
            self.assertIs(report["result"][key], False)

    def test_f1_positive_single_open_and_read_each_candidate(self):
        real_open, real_fdopen = os.open, os.fdopen
        opens, reads, descriptors = {}, {}, {}

        def open_count(path, *args, **kwargs):
            fd = real_open(path, *args, **kwargs)
            if path in L.FILENAMES.values():
                opens[path] = opens.get(path, 0) + 1
                descriptors[fd] = path
            return fd

        def fdopen_count(fd, *args, **kwargs):
            handle = real_fdopen(fd, *args, **kwargs)
            name = descriptors.pop(fd, None)
            if name is None:
                return handle
            class Counted:
                def __enter__(self): return self
                def __exit__(self, *exc): handle.close()
                def fileno(self): return handle.fileno()
                def read(self, count):
                    self_test.assertEqual(count, IO.MAX_JSON_BYTES + 1)
                    reads[name] = reads.get(name, 0) + 1
                    return handle.read(count)
            return Counted()
        self_test = self
        with patch.object(IO.os, "open", open_count), patch.object(IO.os, "fdopen", fdopen_count):
            report = self.report()
        self.assertIs(report["result"]["safe_to_freeze_launch_identity_set"], True)
        self.assertEqual(opens, {name: 1 for name in L.FILENAMES.values()})
        self.assertEqual(reads, opens)

    def test_f1_negative_hash_unapproved_parse_approved_toctou(self):
        bad = copy.deepcopy(self.resource)
        bad["operator"]["approved"] = False
        self.write(0, bad)
        raw = self.paths[0].read_bytes()
        real_read = IO.ArtifactRoot.read
        def swap(store, path):
            snap = real_read(store, path)
            if path == self.paths[0]:
                self.write(0, self.resource)
            return snap
        with patch.object(IO.ArtifactRoot, "read", swap):
            report = self.report()
        self.assert_rejected(report)
        status = report["external_candidates"]["resource_reservation"]
        self.assertEqual(status["identity"]["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertTrue(status["failures"])

    def test_f1_builder_never_hashes_unvalidated_replacement(self):
        old = self.snap(0).identity
        bad = copy.deepcopy(self.resource)
        bad["operator"]["approved"] = False
        real_read = IO.ArtifactRoot.read
        def swap(store, path):
            snap = real_read(store, path)
            if path == self.paths[1]:
                self.write(0, bad)
            return snap
        with patch.object(IO.ArtifactRoot, "read", swap):
            candidate = self.author()
        self.assertEqual(candidate["attestations"]["resource_reservation"], old)
        self.write(2, candidate)
        self.assert_rejected(self.report())

    def test_f1_snapshot_is_immutable_and_parser_mutation_is_detached(self):
        snapshot = self.snap(0)
        with self.assertRaises(FrozenInstanceError):
            snapshot.raw = b"{}\n"
        parsed = snapshot.document()
        parsed["operator"]["approved"] = False
        self.assertIs(snapshot.document()["operator"]["approved"], True)

    def test_f1_bounded_size_empty_and_nonregular_input_rejected(self):
        for data in (b"", b" " * (IO.MAX_JSON_BYTES + 1)):
            with self.subTest(size=len(data)):
                self.paths[0].write_bytes(data)
                self.assert_rejected(self.report())
        self.paths[0].unlink()
        os.mkfifo(self.paths[0])
        self.assert_rejected(self.report())

    def test_f1_file_replaced_while_reading_rejected(self):
        real_fdopen = os.fdopen
        target_inode = self.paths[0].stat().st_ino
        def swapping(fd, *args, **kwargs):
            handle = real_fdopen(fd, *args, **kwargs)
            if os.fstat(fd).st_ino != target_inode:
                return handle
            class Swapping:
                def __enter__(self): return self
                def __exit__(self, *exc): handle.close()
                def fileno(self): return handle.fileno()
                def read(inner, count):
                    raw = handle.read(count)
                    replacement = self.root / "replacement"
                    replacement.write_bytes(raw)
                    replacement.replace(self.paths[0])
                    return raw
            return Swapping()
        with patch.object(IO.os, "fdopen", swapping):
            self.assert_rejected(self.report())

    def test_f2_positive_command_binds_all_exact_locations(self):
        command = shlex.split(self.launch["execution"]["command"])
        for kind, path in zip(L.KINDS, self.paths):
            flag = "--" + kind.replace("_", "-")
            self.assertEqual(command[command.index(flag) + 1], str(path))
        self.assertEqual(self.launch["execution"]["candidate_locations"], L.locations(self.root))

    def test_f2_same_basename_other_directory_rejected_before_read(self):
        other = self.root / "different-batch"
        other.mkdir(mode=0o700)
        paths = tuple(other / p.name for p in self.paths)
        for old, new in zip(self.paths, paths):
            new.write_bytes(old.read_bytes())
        with patch.object(IO.ArtifactRoot, "read", side_effect=AssertionError("must not read mismapped candidate")):
            report = L.build_preflight(resource_path=paths[0], review_path=paths[1], launch_path=paths[2], artifact_root=self.root, clock=lambda: NOW)
        self.assert_rejected(report)

    def test_f2_command_and_mapping_mutations_rejected(self):
        for kind in L.KINDS:
            doc = copy.deepcopy(self.launch)
            doc["execution"]["candidate_locations"][kind] = str(self.root / "other" / L.FILENAMES[kind])
            self.write(2, doc)
            self.assert_rejected(self.report())
        doc = copy.deepcopy(self.launch)
        doc["execution"]["command"] = doc["execution"]["command"].replace(str(self.root), "/tmp/OTHER")
        doc["execution"]["command_sha256"] = hashlib.sha256(doc["execution"]["command"].encode()).hexdigest()
        self.write(2, doc)
        self.assert_rejected(self.report())

    def test_f2_rebinding_requires_new_attestations(self):
        with tempfile.TemporaryDirectory(prefix="pq-rbbc-v241-rebind-") as directory:
            root = Path(directory)
            paths = tuple(root / p.name for p in self.paths)
            for src, dst in zip(self.paths, paths):
                dst.write_bytes(src.read_bytes())
            report = L.build_preflight(resource_path=paths[0], review_path=paths[1], launch_path=paths[2], artifact_root=root, clock=lambda: NOW)
            self.assert_rejected(report)
            resource = synthetic_resource(root)
            paths[0].write_bytes(L.canonical_json(resource))
            paths[1].write_bytes(L.canonical_json(synthetic_review(root, IO.ArtifactRoot(root).read(paths[0]))))
            doc = L.build_launch_manifest(*paths[:2], "TEST-ONLY-rebind", CREATED, artifact_root=root, clock=lambda: NOW)
            paths[2].write_bytes(L.canonical_json(doc))
            report = L.build_preflight(resource_path=paths[0], review_path=paths[1], launch_path=paths[2], artifact_root=root, clock=lambda: NOW)
            self.assertTrue(report["result"]["safe_to_freeze_launch_identity_set"])

    def test_f3_positive_canonical_utf8_roundtrip(self):
        raw = IO.canonical_json({"text": "繁體中文😀", "integer": 9})
        self.assertEqual(IO.canonical_json(IO.strict_json(raw)), raw)

    def test_f3_all_prereview_encoding_probes_rejected(self):
        raw = IO.canonical_json(self.resource)
        variants = {
            "duplicate_conflicting_approval": raw.replace(b'"approved":true', b'"approved":false,"approved":true'),
            "duplicate_conflicting_format": raw.replace(b'{', b'{"format":"INVALID",', 1),
            "duplicate_same_value": raw.replace(b'"approved":true', b'"approved":true,"approved":true'),
            "pretty_json": json.dumps(self.resource, indent=2).encode(),
            "no_final_newline": raw[:-1], "trailing_whitespace": raw + b" \t\n",
            "trailing_second_object": raw + b"{}", "trailing_garbage": raw + b"JUNK",
            "invalid_utf8": raw.replace(b'TEST-ONLY', b'\xff', 1), "utf8_bom": b"\xef\xbb\xbf" + raw,
            "root_array": b"[]\n", "NaN": b'{"v":NaN}\n', "Infinity": b'{"v":Infinity}\n',
            "minus_Infinity": b'{"v":-Infinity}\n', "float": b'{"v":7390.0}\n',
            "exponent": b'{"v":739e1}\n', "negative_zero": b'{"v":-0}\n',
            "alternate_escape": b'{"v":"\\u0041"}\n', "unsorted": b'{"z":1,"a":2}\n',
            "unpaired_surrogate": b'{"v":"\\ud800"}\n',
            "deep_nesting": b'{"v":' + b'[' * 2000 + b'0' + b']' * 2000 + b'}\n',
        }
        for name, changed in variants.items():
            with self.subTest(name=name):
                self.paths[0].write_bytes(changed)
                self.assert_rejected(self.report())
                with self.assertRaises(IO.ValidationError):
                    IO.strict_json(changed)

    def test_f3_and_f4_malformed_snapshot_cannot_be_rescued_by_replacement(self):
        raw = IO.canonical_json(self.resource)
        variants = [raw + b" ", raw.replace(b'"approved":true', b'"approved":1')]
        real_read = IO.ArtifactRoot.read
        for bad in variants:
            self.paths[0].write_bytes(bad)
            def swap(store, path):
                snap = real_read(store, path)
                if path == self.paths[0]: self.write(0, self.resource)
                return snap
            with patch.object(IO.ArtifactRoot, "read", swap):
                self.assert_rejected(self.report())

    def test_f4_every_boolean_rejects_numeric_and_other_types(self):
        documents = (self.resource, self.review, self.launch)
        for index, original in enumerate(documents):
            schema = L.schemas()[L.KINDS[index]]
            self.assertFalse(L.validate_schema(original, schema))
            for path in object_paths(original):
                for key, value in at(original, path).items():
                    if type(value) is not bool: continue
                    for mutation in (int(value), float(value), str(value), None, [], {}):
                        with self.subTest(kind=index, path=path, key=key, mutation=mutation):
                            doc = copy.deepcopy(original)
                            at(doc, path)[key] = mutation
                            self.assertTrue(L.validate_schema(doc, schema))

    def test_f4_every_nested_identity_rejects_float_bool_and_mutations(self):
        for kind, original in zip(L.KINDS, (self.resource, self.review, self.launch)):
            schema = L.schemas()[kind]
            for path in object_paths(original):
                value = at(original, path)
                if set(value) != {"bytes", "filename", "sha256"}: continue
                for key, mutation in (("bytes", float(value["bytes"])), ("bytes", True), ("bytes", 0),
                                      ("sha256", "not-hex"), ("filename", "")):
                    with self.subTest(kind=kind, path=path, key=key, mutation=mutation):
                        doc = copy.deepcopy(original)
                        at(doc, path)[key] = mutation
                        self.assertTrue(L.validate_schema(doc, schema))

    def test_f4_resource_integer_bounds_and_versions(self):
        for key in ("cpu_cores", "available_memory_bytes", "free_disk_bytes"):
            for value in (True, -1, 0, 1.5, "4", None):
                doc = copy.deepcopy(self.resource)
                doc["reserved_resources"][key] = value
                self.assertTrue(L.validate_resource(doc, self.root, NOW))
        for key, value in (("format", L.historical.v2_38.RESOURCE_FORMAT), ("implementation_version", "2.39"),
                           ("production_profile_fingerprint", "2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38")):
            doc = copy.deepcopy(self.resource)
            doc[key] = value
            self.assertTrue(L.validate_resource(doc, self.root, NOW))

    def test_f4_unhashable_attestation_method_is_structured_rejection(self):
        doc = copy.deepcopy(self.resource)
        doc["operator"]["attestation"]["method"] = []
        self.write(0, doc)
        self.assert_rejected(self.report())

    def test_f5_window_boundaries_and_trusted_now(self):
        start = L._utc(self.resource["reservation_window"]["starts_at_utc"])
        end = L._utc(self.resource["reservation_window"]["ends_at_utc"])
        for now, valid in ((start, True), (end - timedelta(microseconds=1), True),
                           (start - timedelta(microseconds=1), False), (end, False),
                           (datetime(2099, 1, 1, tzinfo=timezone.utc), False)):
            with self.subTest(now=now):
                self.assertEqual(not L.validate_resource(self.resource, self.root, now), valid)
        with self.assertRaises(IO.ValidationError):
            self.report(clock=lambda: NOW.replace(tzinfo=None))
        with self.assertRaises(IO.ValidationError):
            self.report(clock=lambda: "2026-09-08T12:00:00Z")

    def test_f5_expired_and_future_reservations_rejected(self):
        self.assert_rejected(self.report(clock=lambda: NOW + timedelta(days=1)))
        self.assert_rejected(self.report(clock=lambda: NOW - timedelta(days=1)))
        doc = copy.deepcopy(self.resource)
        doc["reservation_window"].update(starts_at_utc="2099-01-01T00:00:00Z", ends_at_utc="2099-01-02T00:00:00Z")
        self.write(0, doc)
        self.assert_rejected(self.report())

    def test_f5_approval_review_and_direct_launch_time_mutations(self):
        for field, value in (("starts_at_utc", "2026-09-09T00:00:00Z"), ("ends_at_utc", "2026-09-07T00:00:00Z"), ("wall_clock_seconds", 1)):
            doc = copy.deepcopy(self.resource)
            doc["reservation_window"][field] = value
            self.assertTrue(L.validate_resource(doc, self.root, NOW))
        doc = copy.deepcopy(self.resource)
        doc["operator"]["approved_at_utc"] = "2026-09-08T01:00:00Z"
        self.assertTrue(L.validate_resource(doc, self.root, NOW))
        for when in ("1970-01-01T00:00:00Z", "2026-09-09T01:00:00Z"):
            doc = copy.deepcopy(self.review)
            doc["reviewer"]["completed_at_utc"] = when
            self.assertTrue(L.validate_review(doc, self.snap(0), self.root, NOW))
            doc = copy.deepcopy(self.launch)
            doc["created_at_utc"] = when
            self.write(2, doc)
            self.assert_rejected(self.report())

    def test_f5_clock_rollover_between_validation_and_builder_rejected(self):
        clock = iter((NOW, NOW + timedelta(days=1)))
        with self.assertRaisesRegex(IO.ValidationError, "inactive_window"):
            self.author(clock=lambda: next(clock))

    def test_f5_clock_sampled_after_candidate_io(self):
        now = [NOW]
        real_read = IO.ArtifactRoot.read
        def slow_read(store, path):
            snap = real_read(store, path)
            if path == self.paths[2]: now[0] += timedelta(days=1)
            return snap
        with patch.object(IO.ArtifactRoot, "read", slow_read):
            self.assert_rejected(self.report(clock=lambda: now[0]))

    def test_f5_prelaunch_revalidation_uses_fresh_clock_and_same_snapshots(self):
        candidates = L.CandidateSet(self.root, *[self.snap(i) for i in range(3)])
        with patch.object(IO.ArtifactRoot, "read", side_effect=AssertionError("must consume snapshots")):
            self.assertIs(L.revalidate_before_launch(candidates, clock=lambda: NOW), candidates)
            with self.assertRaisesRegex(IO.ValidationError, "inactive_window"):
                L.revalidate_before_launch(candidates, clock=lambda: NOW + timedelta(days=1))
        self.assertFalse((self.root / "production-prefreeze").exists())

    def test_f6_positive_exact_reservation_subject_and_batch(self):
        subject = self.review["review_subject"]
        self.assertEqual(subject["resource_reservation"], self.snap(0).identity)
        self.assertEqual(subject["reservation_id"], self.resource["reservation_id"])
        self.assertEqual(self.launch["review_subject_sha256"], L.subject_sha256(subject))
        self.assertFalse(L.validate_launch(self.launch, self.snap(0), self.snap(1), self.root, NOW))

    def test_f6_review_cannot_be_reused_for_changed_reservation(self):
        for path, key, value in (((), "reservation_id", "TEST-ONLY-other"), ((), "launch_batch_id", "TEST-ONLY-other"),
                                  (("reserved_resources",), "cpu_cores", 4096),
                                  (("reserved_resources",), "available_memory_bytes", 1 << 100),
                                  (("operator", "attestation"), "reference", "TEST-ONLY-other")):
            doc = copy.deepcopy(self.resource)
            at(doc, path)[key] = value
            self.write(0, doc)
            self.assert_rejected(self.report())
            with self.assertRaises(IO.ValidationError): self.author()

    def test_f6_review_subject_identity_and_batch_mutations(self):
        for path, key, value in ((("review_subject", "resource_reservation"), "sha256", "0" * 64),
                                  (("review_subject", "resource_reservation"), "bytes", 999),
                                  (("review_subject",), "reservation_id", "TEST-ONLY-other"),
                                  (("review_subject",), "launch_batch_id", "TEST-ONLY-other"),
                                  ((), "launch_batch_id", "TEST-ONLY-other")):
            doc = copy.deepcopy(self.review)
            at(doc, path)[key] = value
            self.write(1, doc)
            self.assert_rejected(self.report())
        for key in ("launch_batch_id", "review_subject_sha256"):
            doc = copy.deepcopy(self.launch)
            doc[key] = "0" * 64
            self.assertTrue(L.validate_launch(doc, self.snap(0), IO.Snapshot(self.paths[1], IO.canonical_json(self.review)), self.root, NOW))

    def test_f6_review_swapped_after_capture_keeps_old_exact_identity(self):
        old = self.snap(1).identity
        other = copy.deepcopy(self.review)
        other["review_subject"]["reservation_id"] = "TEST-ONLY-other"
        real_read = IO.ArtifactRoot.read
        def swap(store, path):
            snap = real_read(store, path)
            if path == self.paths[1]: self.write(1, other)
            return snap
        with patch.object(IO.ArtifactRoot, "read", swap):
            candidate = self.author()
        self.assertEqual(candidate["attestations"]["independent_review"], old)
        self.write(2, candidate)
        self.assert_rejected(self.report())

    def test_prereview_closed_world_all_objects_and_required_fields(self):
        count_objects = count_required = 0
        for kind, original in zip(L.KINDS, (self.resource, self.review, self.launch)):
            schema = L.schemas()[kind]
            for path in object_paths(original):
                changed = copy.deepcopy(original)
                at(changed, path)["UNKNOWN_FIELD"] = True
                self.assertTrue(L.validate_schema(changed, schema), (kind, path))
                count_objects += 1
                for key in at(original, path):
                    changed = copy.deepcopy(original)
                    del at(changed, path)[key]
                    self.assertTrue(L.validate_schema(changed, schema), (kind, path, key))
                    count_required += 1
        self.assertGreaterEqual(count_objects, 23)
        self.assertGreaterEqual(count_required, 112)

    def test_f7_candidates_symlinks_and_hardlinks_rejected(self):
        original = self.paths[0].read_bytes()
        self.paths[0].unlink()
        target = self.root / "target"
        for dangling in (True, False):
            if not dangling: target.write_bytes(original)
            self.paths[0].symlink_to(target)
            self.assert_rejected(self.report())
            self.paths[0].unlink()
        os.link(target, self.paths[0])
        self.assert_rejected(self.report())

    def test_f7_other_worktree_and_untrusted_root_rejected(self):
        store = IO.ArtifactRoot(self.root)
        for path in (L.ROOT / "docs/ARTIFACT_POLICY.md", Path("/home/ucheng0830/Documents/PQC_auth/docs/ARTIFACT_POLICY.md")):
            with self.assertRaises(IO.ValidationError): store.read(path)
        (self.root / ".git").write_text("gitdir: TEST-ONLY")
        self.assert_rejected(self.report())
        (self.root / ".git").unlink()
        self.root.chmod(0o777)
        self.assert_rejected(self.report())
        self.root.chmod(0o700)

    def test_f7_root_symlink_and_parent_swap_rejected(self):
        link = self.root / "alias"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises((OSError, IO.ValidationError)):
            IO.ArtifactRoot(link).read(link / self.paths[0].name)

    def test_f2_and_f7_input_parent_rename_race_cannot_rebind_command(self):
        read = IO._same_directory
        moved = self.root.with_name(self.root.name + "-moved")
        self.addCleanup(lambda: moved.rename(self.root) if moved.exists() else None)
        attacked = []
        def swap(path, fd, **kwargs):
            if path == self.root and not attacked:
                attacked.append(True)
                self.root.rename(moved)
            return read(path, fd, **kwargs)
        with patch.object(IO, "_same_directory", swap):
            self.assert_rejected(self.report())

    def test_prereview_same_operator_reviewer_is_no_authenticity_proof(self):
        doc = copy.deepcopy(self.review)
        doc["reviewer"]["identifier"] = self.resource["operator"]["identifier"]
        self.assertFalse(L.validate_review(doc, self.snap(0), self.root, NOW))
        # Identity equality alone cannot establish the person's relationship to
        # the implementation. Attestation authenticity/independence is still an
        # external review blocker, never a cryptographic claim from JSON.
        self.assertIn("signer authenticity and independence require external verification", self.report()["blockers"])

    def test_f8_exact_contracts_positive_and_missing_predecessor_authoring_negative(self):
        self.assertEqual(L.validate_tracked_contracts(), ())
        missing = self.root / "missing-predecessor"
        report = self.report(predecessor=missing)
        self.assert_rejected(report)
        self.assertIs(report["result"]["safe_to_author_launch_manifest_candidate"], False)
        with self.assertRaises(IO.ValidationError): self.author(predecessor=missing)

    def test_f8_mutated_tracked_contracts_refuse_authoring_and_preflight(self):
        read = L.read_snapshot
        targets = (L.MANIFEST_PATH, *L.SCHEMA_PATHS.values(), L.V2_38_PORTABLE_PATH,
                   L.historical.v2_38.MANIFEST_PATH)
        for target in targets:
            def changed(path):
                snap = read(path)
                if path == target: return IO.Snapshot(path, snap.raw + b" ")
                return snap
            with self.subTest(target=target), patch.object(L, "read_snapshot", changed):
                report = self.report()
                self.assert_rejected(report)
                self.assertFalse(report["result"]["safe_to_author_launch_manifest_candidate"])
                with self.assertRaises(IO.ValidationError): self.author()

    def test_f8_contract_hash_parse_toctou_cannot_rescue_bad_snapshot(self):
        read = L.read_snapshot
        calls = []
        def changed(path):
            snap = read(path)
            if path == L.MANIFEST_PATH:
                calls.append(path)
                # If reopened a second time, return valid bytes: old split I/O
                # would lose the invalid identity/semantics boundary.
                if len(calls) == 1: return IO.Snapshot(path, snap.raw + b" ")
            return snap
        with patch.object(L, "read_snapshot", changed):
            self.assert_rejected(self.report())
        self.assertEqual(len(calls), 1)

    def test_production_refusal_after_success_and_clock_race_creates_no_output(self):
        output = self.root / "production-prefreeze"
        with self.assertRaisesRegex(IO.ValidationError, "does not authorize"):
            L.reject_production(self.paths, output, artifact_root=self.root, clock=lambda: NOW)
        clock = iter((NOW, NOW + timedelta(days=1)))
        with self.assertRaisesRegex(IO.ValidationError, "inactive_window"):
            L.reject_production(self.paths, output, artifact_root=self.root, clock=lambda: next(clock))
        self.assertFalse(output.exists())

    def test_conservative_claims_and_historical_identity_preservation(self):
        for path, identity in L.HISTORICAL_IDENTITIES.items():
            self.assertEqual(IO.read_snapshot(L.ROOT / path).identity, identity)
        claims = L.claim_boundary()
        for key, value in claims.items():
            if key not in ("v2_41_launch_validation_implemented", "historical_evidence_preserved"):
                self.assertIs(value, False, key)
        self.assertFalse(L.build_manifest()["production_command"]["executable_now"])


class ExclusivePublicationV241Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pq-rbbc-v241-IO-TEST-ONLY-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = IO.ArtifactRoot(self.root)
        self.output = self.root / "dummy-report.json"

    def test_f7_positive_exclusive_complete_canonical_output(self):
        self.store.write(self.output, {"TEST-ONLY": True})
        self.assertEqual(self.output.read_bytes(), b'{"TEST-ONLY":true}\n')
        with self.assertRaises(FileExistsError): self.store.write(self.output, {})
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_f7_existing_and_dangling_symlink_never_followed(self):
        target = self.root / "target"
        for dangling in (True, False):
            if not dangling: target.write_bytes(b"DO-NOT-OVERWRITE")
            self.output.symlink_to(target)
            with self.assertRaises(FileExistsError): self.store.write(self.output, {})
            if dangling: self.assertFalse(target.exists())
            else: self.assertEqual(target.read_bytes(), b"DO-NOT-OVERWRITE")
            self.output.unlink()

    def test_f7_competing_writer_at_publication_not_overwritten(self):
        real_link = os.link
        def competing(*args, **kwargs):
            self.output.write_bytes(b"COMPETING-REPORT")
            return real_link(*args, **kwargs)
        with patch.object(IO.os, "link", competing):
            with self.assertRaises(FileExistsError): self.store.write(self.output, {})
        self.assertEqual(self.output.read_bytes(), b"COMPETING-REPORT")
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), [self.output.name])

    def test_f7_real_parallel_writers_have_exactly_one_winner(self):
        barrier = threading.Barrier(12)
        def writer(index):
            barrier.wait()
            try:
                self.store.write(self.output, {"TEST-ONLY-writer": index})
                return index
            except FileExistsError:
                return None
        with ThreadPoolExecutor(max_workers=12) as pool:
            winners = [x for x in pool.map(writer, range(12)) if x is not None]
        self.assertEqual(len(winners), 1)
        self.assertEqual(IO.strict_json(self.output.read_bytes()), {"TEST-ONLY-writer": winners[0]})
        self.assertEqual(len(list(self.root.iterdir())), 1)

    def test_f7_failure_before_publish_leaves_no_partial_final(self):
        with patch.object(IO.os, "link", side_effect=OSError("TEST-ONLY injected failure")):
            with self.assertRaises(OSError): self.store.write(self.output, {"TEST-ONLY": True})
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.iterdir()), [])
        self.store.write(self.output, {})

    def test_f7_parent_rename_symlink_race_never_writes_external_target(self):
        parent, target = self.root / "parent", self.root / "outside"
        parent.mkdir(mode=0o700)
        target.mkdir(mode=0o700)
        moved = self.root / "moved"
        real_link = os.link
        def swap(*args, **kwargs):
            parent.rename(moved)
            parent.symlink_to(target, target_is_directory=True)
            return real_link(*args, **kwargs)
        with patch.object(IO.os, "link", swap):
            with self.assertRaises((OSError, IO.ValidationError)):
                self.store.write(parent / "dummy.json", {})
        self.assertEqual(list(target.iterdir()), [])
        self.assertEqual((moved / "dummy.json").read_bytes(), b"{}\n")


if __name__ == "__main__":
    unittest.main()
