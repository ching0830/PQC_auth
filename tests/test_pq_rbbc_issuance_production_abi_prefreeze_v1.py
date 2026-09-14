from contextlib import ExitStack
from copy import deepcopy
from dataclasses import replace
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import pq_rbbc_issuance_production_abi_prefreeze_v1 as gate
import pq_rbbc_issuance_production_inputs_v1 as inputs
import pq_rbbc_launch_io_v2_41 as io
from tests.test_pq_rbbc_issuance_production_inputs_v1 import complete_structural_candidate


class ProductionABIPrefreezeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prerequisites = gate.capture_prerequisites()
        cls.plan = gate.build_plan(cls.prerequisites)
        cls.raw = gate.canonical_json(cls.plan)

    def snapshot(self, raw):
        return io.Snapshot(Path("/test-only/plan.json"), raw)

    def test_positive_canonical_roundtrip_and_bound_identity(self):
        snapshot = self.snapshot(self.raw)
        self.assertEqual(gate.validate_plan_snapshot(snapshot, self.prerequisites), self.plan)
        self.assertEqual(snapshot.identity["sha256"], gate.sha256(self.raw))
        report = gate.preflight(self.prerequisites, plan_snapshot=snapshot)
        self.assertEqual(report["plan_sha256"], gate.sha256(gate.DOMAIN + self.raw))
        self.assertTrue(report["read_only_abi_preflight_passed"])
        self.assertTrue(report["safe_to_author_bounded_multi_tree_adapter"])
        self.assertFalse(report["production_abi_qualified"])

    def test_42_stage_order_and_fanin(self):
        stages = self.plan["stages"]
        self.assertEqual(len(stages), 42)
        self.assertEqual(stages[20]["stage_id"], "global-tail-phase-a")
        self.assertEqual(stages[39]["stage_id"], "global-tail-phase-b")
        self.assertEqual(stages[20]["data_dependencies"][1:], list(gate.ORDER[2:20]))
        self.assertEqual(stages[39]["data_dependencies"][-18:], list(gate.ORDER[21:39]))
        for ordinal, stage in enumerate(stages):
            self.assertEqual(stage["ordinal"], ordinal)
            self.assertEqual(stage["previous_receipt_stage"], None if not ordinal else gate.ORDER[ordinal-1])
            self.assertFalse(stage["bounded_function_directly_production_usable"])

    def test_planned_wire_ranges_use_per_tree_not_global_cursor(self):
        gate.validate_layout(self.plan)
        tree = self.plan["trees"][0]
        self.assertEqual(tree["planned_pre_interval"], {"start": 40194597, "end_exclusive": 79003159})
        self.assertEqual(tree["planned_post_interval"], {"start": 79003159, "end_exclusive": 79148427})
        self.assertNotEqual(tree["planned_post_interval"]["start"],
                            self.plan["stages"][20]["planned_interval"]["end_exclusive"])
        self.assertIsNone(self.plan["interval_contract"]["parent_interval"])
        self.assertFalse(self.plan["interval_contract"]["production_absolute_intervals_qualified"])

    def test_rho_and_mixed_degrees(self):
        end = 136
        for i, tree in enumerate(self.plan["trees"]):
            self.assertEqual(tree["tree_index"], i)
            self.assertEqual(tree["leaves"], 4096 if i < 2 else 2048)
            self.assertEqual(tree["extension_degree"], 13 if i < 2 else 12)
            self.assertEqual(tree["rho_salt_byte_interval"], [84, 134])
            for span in tree["rho_root_byte_intervals"]:
                self.assertEqual(span["byte_start"], end)
                end += 25
                self.assertEqual(span["byte_end_exclusive"], end)
        self.assertEqual(end, 1036)

    def test_72_relocations_and_same_global_points(self):
        ports = [p for s in self.plan["stages"] for p in s["import_ports"]]
        relocations = [p for p in ports if p["consumer_interval"] is not None]
        self.assertEqual(len(relocations), 72)
        self.assertEqual(sum(p["bit_length"] for p in relocations), 15938520)
        points = [p for p in ports if p["port_id"] == "global.consistency-points"]
        self.assertEqual(len(points), 19)  # 18 post plus shared-alpha/global-B.
        for port in points:
            self.assertEqual(port["producer_interval"], {"start": 39945673, "end_exclusive": 39946059})
            self.assertEqual(port["binding"], "same-wire-ids")
        self.assertEqual(self.plan["global_a_contract"]["correction_pairs"], 17)
        self.assertEqual(self.plan["parent_join_contract"]["equality_widths"], [256, 576, 576])

    def test_plan_semantic_mutations_reject(self):
        mutations = [
            (("format",), "wrong-version"),
            (("implementation_version",), "2.0"),
            (("relation_id",), "wrong-domain"),
            (("profile_fingerprint",), "0" * 64),
            (("predecessor_plan_sha256",), "0" * 64),
            (("stages", 1, "ordinal"), True),
            (("stages", 2, "data_dependencies"), ["global-tail-phase-a"]),
            (("stages", 2, "planned_interval", "start"), 40194598),
            (("stages", 21, "planned_interval", "start"), 39946062),
            (("stages", 20, "import_ports", 0, "bit_length"), 1),
            (("trees", 2, "tree_index"), 1),
            (("trees", 2, "extension_degree"), 13),
            (("trees", 2, "rho_root_byte_intervals", 0, "byte_start"), 136),
            (("global_a_contract", "correction_pairs"), 0),
            (("global_b_contract", "derived_mask_bits"), 256),
            (("parent_join_contract", "full_I1_I5_replayed"), True),
            (("runtime_handoff_schema", "candidate_pathnames_may_be_reopened"), True),
            (("stages", 2, "observed_stream_bytes"), 46392022),
            (("production_execution_started",), True),
        ]
        for path, value in mutations:
            with self.subTest(path=path):
                plan = deepcopy(self.plan)
                target = plan
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(gate.PrefreezeError):
                    gate.validate_plan_snapshot(self.snapshot(gate.canonical_json(plan)), self.prerequisites)
        extra = {**self.plan, "unknown": 1}
        with self.assertRaises(gate.PrefreezeError):
            gate.validate_plan_snapshot(self.snapshot(gate.canonical_json(extra)), self.prerequisites)

    def test_strict_trailing_duplicate_float_and_noncanonical_reject(self):
        for raw in (self.raw + b"\x00", self.raw + b"\n", self.raw[:-1],
                    self.raw.replace(b'"ordinal":1,', b'"ordinal":1.0,', 1),
                    b'{"format":1,"format":2}\n', self.raw.replace(b'"format":', b'"format" :', 1)):
            with self.subTest(raw=raw[:60]), self.assertRaises(io.ValidationError):
                gate.validate_plan_snapshot(self.snapshot(raw), self.prerequisites)

    def test_independent_interval_and_dependency_checks(self):
        for field in ("start", "end_exclusive"):
            plan = deepcopy(self.plan)
            plan["stages"][2]["planned_interval"][field] += 1
            with self.assertRaises(gate.PrefreezeError):
                gate.validate_layout(plan)
        plan = deepcopy(self.plan)
        plan["stages"][2]["data_dependencies"] = ["tree-post[0]"]
        with self.assertRaises(gate.PrefreezeError):
            gate.validate_layout(plan)
        plan = deepcopy(self.plan)
        span = plan["stages"][20]["import_ports"][0]["consumer_interval"]
        span["start"] += 1
        span["end_exclusive"] += 1
        with self.assertRaises(gate.PrefreezeError):
            gate.validate_layout(plan)

    def test_missing_and_synthetic_complete_external_candidates_never_authorize(self):
        report = gate.preflight(self.prerequisites)
        self.assertEqual(report["missing_artifacts"], list(inputs.REQUIRED_EXTERNAL_ARTIFACTS))
        candidates = complete_structural_candidate()
        with patch.object(io, "read_snapshot", side_effect=AssertionError("path reopen")):
            report = gate.preflight(self.prerequisites, candidates)
        self.assertTrue(report["candidate_report"]["structural_candidate_complete"])
        self.assertEqual(report["missing_artifacts"], [])
        for key in ("production_execution_authorized", "safe_to_start_large_replay",
                    "safe_to_start_large_proving_run", "Proof-closed", "Production-closed"):
            self.assertFalse(report[key])
        self.assertIsNone(report["production_execution_command"])
        self.assertTrue(report["blockers"])

    def test_wrong_statement_parameter_binding_remains_rejected(self):
        # Mutate the supplied parameter snapshot, never regenerate a trusted
        # attestation or re-open its pathname. This is not an invocation replay.
        candidates = complete_structural_candidate()
        snap = candidates.common_parameters
        candidates = replace(candidates, common_parameters=replace(snap, raw=snap.raw[:-1] + bytes([snap.raw[-1] ^ 1])))
        report = gate.preflight(self.prerequisites, candidates)
        self.assertFalse(report["candidate_report"]["structural_candidate_complete"])
        self.assertTrue(report["candidate_report"]["validation_failures"])
        self.assertFalse(report["production_execution_authorized"])

    def test_prerequisite_mutation_unknown_duplicate_and_location_reject(self):
        pairs = self.prerequisites.snapshots
        name, snap = pairs[0]
        for updated in (
                ((name, replace(snap, raw=snap.raw + b"\n")),) + pairs[1:],
                ((name, replace(snap, location=snap.location.with_suffix(".py"))),) + pairs[1:],
                pairs[1:], pairs + (pairs[0],), pairs + (("src/unknown.py", snap),)):
            with self.subTest(updated=updated[0][0]):
                with self.assertRaises(gate.PrefreezeError):
                    replace(self.prerequisites, snapshots=updated).validated()

    def test_capture_each_prerequisite_once(self):
        with patch.object(io, "read_snapshot", wraps=io.read_snapshot) as read:
            captured = gate.capture_prerequisites()
        paths = [call.args[0] for call in read.call_args_list]
        self.assertEqual(len(paths), len(set(paths)))
        self.assertEqual(len(paths), len(captured.snapshots))
        self.assertEqual(captured, self.prerequisites)

    def test_preflight_never_calls_builders_publishers_or_reopens(self):
        with ExitStack() as stack:
            for target in (
                    "pq_rbbc_cap_shard_stream.build_streaming_shard",
                    "pq_rbbc_issuance_fragment_producers_v1.bounded_self_check",
                    "pq_rbbc_issuance_cap_child_executor_v1.build_manifest",
                    "pq_rbbc_launch_io_v2_41.read_snapshot",
                    "pq_rbbc_launch_io_v2_41.publish_exclusive",
                    "pathlib.Path.mkdir", "pathlib.Path.open"):
                stack.enter_context(patch(target, side_effect=AssertionError(target)))
            gate.preflight(self.prerequisites)
            gate.build_manifest(self.prerequisites)
            gate.build_portable_evidence(self.prerequisites)

    def test_same_inode_same_length_stale_metadata_accepts_captured_old_bytes(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "plan.json"
            path.write_bytes(self.raw)
            before = path.stat()
            later = self.raw.replace(b'"implementation_version":"1.0"', b'"implementation_version":"2.0"')
            self.assertEqual(len(later), len(self.raw))
            real_fdopen, real_fstat, real_stat = os.fdopen, os.fstat, os.stat
            reads = []

            class ControlledReader:
                def __init__(self, handle):
                    self.handle = handle

                def __enter__(self):
                    self.handle.__enter__()
                    return self

                def __exit__(self, *args):
                    return self.handle.__exit__(*args)

                def fileno(self):
                    return self.handle.fileno()

                def read(self, limit):
                    reads.append(limit)
                    raw = self.handle.read(limit)
                    # Same inode, same final length, AFTER old bytes fully captured.
                    path.write_bytes(later)
                    return raw

            def stale_fstat(fd):
                actual = real_fstat(fd)
                return before if actual.st_ino == before.st_ino else actual

            def stale_stat(name, *args, **kwargs):
                actual = real_stat(name, *args, **kwargs)
                return before if actual.st_ino == before.st_ino else actual

            with patch.object(os, "fdopen", side_effect=lambda *a, **k: ControlledReader(real_fdopen(*a, **k))), \
                    patch.object(os, "fstat", side_effect=stale_fstat), \
                    patch.object(os, "stat", side_effect=stale_stat):
                snapshot = io.read_snapshot(path)
            self.assertEqual(reads, [io.MAX_JSON_BYTES + 1])
            self.assertEqual(path.stat().st_ino, before.st_ino)
            self.assertEqual(path.read_bytes(), later)
            self.assertEqual(snapshot.raw, self.raw)
            self.assertEqual(snapshot.identity["sha256"], gate.sha256(self.raw))
            with patch.object(io, "read_snapshot", side_effect=AssertionError("reopen")):
                self.assertEqual(gate.validate_plan_snapshot(snapshot, self.prerequisites), self.plan)
                report = gate.preflight(self.prerequisites, plan_snapshot=snapshot)
            self.assertEqual(report["plan_sha256"], gate.plan_sha256(self.plan))
            with self.assertRaises(gate.PrefreezeError):
                gate.validate_plan_snapshot(io.Snapshot(path, later), self.prerequisites)
            self.assertFalse(report["production_execution_authorized"])

    def test_production_refuses_before_output_or_argument_access(self):
        with TemporaryDirectory() as temp:
            output = Path(temp) / "never-created"
            with patch.object(Path, "mkdir", side_effect=AssertionError("mkdir")), \
                    patch.object(io, "read_snapshot", side_effect=AssertionError("read")):
                with self.assertRaises(gate.ProductionUnavailable):
                    gate.execute_production(object(), output=output, production=True)
            self.assertFalse(output.exists())

    def test_tracked_manifest_and_portable_evidence_are_exact(self):
        for relative, document in (
                (gate.MANIFEST_PATH, gate.build_manifest(self.prerequisites)),
                (gate.EVIDENCE_PATH, gate.build_portable_evidence(self.prerequisites))):
            raw = (gate.ROOT / relative).read_bytes()
            self.assertEqual(raw, gate.canonical_json(document))
            io.strict_json(raw)
            self.assertNotIn(str(gate.ROOT).encode(), raw)

    def test_cli_read_only_and_invalid_external_root(self):
        command = [sys.executable, str(gate.ROOT / "src/pq_rbbc_issuance_production_abi_prefreeze_v1.py")]
        result = subprocess.run(command, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(io.strict_json(result.stdout)["read_only_abi_preflight_passed"])
        result = subprocess.run(command + ["--artifact-root", "relative"], capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(io.strict_json(result.stdout)["production_execution_authorized"])


if __name__ == "__main__":
    unittest.main()
