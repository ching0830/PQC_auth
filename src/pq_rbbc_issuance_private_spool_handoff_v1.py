#!/usr/bin/env python3
"""Bounded INSECURE-TEST-ONLY private-spool snapshot handoff.

Default CLI is read-only. --self-check runs the fixed two-tree fixture in
memory. No private file publisher, production executor, or durable resume API.
"""
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import argparse

import pq_rbbc_issuance_bounded_multitree_adapter_v1 as base
import pq_rbbc_issuance_private_spool_codec_v1 as codec
import pq_rbbc_issuance_private_spool_native_v1 as native
import pq_rbbc_launch_io_v2_41 as io

ROOT = Path(__file__).resolve().parents[1]
FORMAT = codec.FORMAT
RELATION_ID = codec.RELATION_ID
HANDOFF_NAME = "handoff.private.json"
SPOOL_NAMES = ("tree-0.private-spool.bin", "tree-1.private-spool.bin")
POINT_NAME = "points.private.json"
RECEIPT_NAME = "global-a.private-receipt.json"
HANDOFF_LIMIT = 8192
POINT_LIMIT = 2048
RECEIPT_LIMIT = 8192
MANIFEST_PATH = "manifests/pq_rbbc_issuance_private_spool_handoff_manifest_v1.json"
EVIDENCE_PATH = ("artifacts/metadata/issuance_private_spool_handoff_v1/"
                 "pq_rbbc_issuance_private_spool_handoff_portable_evidence_v1.json")
PREDECESSOR_PINS = {
    "src/pq_rbbc_issuance_bounded_multitree_adapter_v1.py":
        (29064, "a9aae19c0a03ecf620a6196d3be9b3f848c82dba88262ae0872cfcd7be0ed4d7"),
    "src/pq_rbbc_issuance_bounded_multitree_native_v1.py":
        (43914, "91cc8729d4d1acb229404a39a25cd739c8aba9fa5ee007c00bbdc6864aba9a7e"),
    "tests/test_pq_rbbc_issuance_bounded_multitree_adapter_v1.py":
        (13143, "60d47c05cc1534eface6f2a5ec2d4d6287dd1ea258cb43966c65ef1902e09457"),
    base.MANIFEST_PATH: (6290, "aac661c6d32fee9991b8ceb1e28384b9f68df85bfcbdf79e6fa1997feec9db3e"),
    base.EVIDENCE_PATH: (2511, "0c795cc9ae502acb9dfc3ebe5048672882f3771e4dec78c41662f55ab938e50b"),
}
FROZEN = {
    "handoff_identity": {"filename": HANDOFF_NAME, "bytes": 1035,
                         "sha256": "ff95140fe4fc0a34ab41360553ae7bdb0f3bb93b2c1537f5742810da572d0c8d"},
    "private_spool_identities": [
        {"filename": SPOOL_NAMES[0], "bytes": 79423,
         "sha256": "3a41227c83fa34c2eb38922f962c7024a80c432a31e93a74994cca45d97169d0"},
        {"filename": SPOOL_NAMES[1], "bytes": 79423,
         "sha256": "5212a7c1e6ade7882051d223499fa9083fa1a88889a7745f72fc5b9a19946973"}],
    "total_private_capture_bytes": 161908,
    "selected_wire_value_bindings_checked": 19472,
}


def validate_prerequisites():
    base.validate_prerequisites()
    for path, expected in PREDECESSOR_PINS.items():
        snap = io.read_snapshot(ROOT / path)
        if (len(snap.raw), codec.sha256(snap.raw)) != expected:
            raise codec.SpoolError("predecessor identity drift: " + path)


def _snapshot(name, raw):
    return io.Snapshot(Path("/in-memory-insecure-test-only") / name, raw)


def _identity(snapshot, name, limit):
    if (type(snapshot) is not io.Snapshot or snapshot.location.name != name
            or not 0 < len(snapshot.raw) <= limit):
        raise codec.SpoolError("wrong snapshot type, filename or byte bound")
    return snapshot.identity


def _check_identity(snapshot, expected, name, limit):
    actual = _identity(snapshot, name, limit)
    if actual != expected:
        raise codec.SpoolError("captured identity mismatch: " + name)


@dataclass(frozen=True)
class CandidateSet:
    handoff: io.Snapshot
    spools: tuple[io.Snapshot, ...]
    points: io.Snapshot
    receipt: io.Snapshot

    def __post_init__(self):
        if (type(self.spools) is not tuple or len(self.spools) != 2
                or any(type(s) is not io.Snapshot for s in
                       (self.handoff, *self.spools, self.points, self.receipt))):
            raise codec.SpoolError("immutable five-snapshot candidate set required")


def _handoff_document(snapshot, expected_sha256):
    codec.hex_digest(expected_sha256)
    _identity(snapshot, HANDOFF_NAME, HANDOFF_LIMIT)
    if codec.sha256(snapshot.raw) != expected_sha256:
        raise codec.SpoolError("external handoff digest rejected before parsing or dependent reads")
    doc = snapshot.document()
    keys = {"format", "relation_id", "profile_fingerprint", "plan_sha256", "invocation_sha256",
            "stage_id", "next_stage", "spools", "points", "receipt", "production", "durable_resume"}
    if (set(doc) != keys or doc["format"] != FORMAT or doc["relation_id"] != RELATION_ID
            or doc["profile_fingerprint"] != codec.PROFILE or doc["stage_id"] != "global-a"
            or doc["next_stage"] != "tree-post[0]" or doc["production"] is not False
            or doc["durable_resume"] is not False):
        raise codec.SpoolError("handoff schema/version/domain/stage/claim mismatch")
    codec.hex_digest(doc["plan_sha256"])
    codec.hex_digest(doc["invocation_sha256"])
    if type(doc["spools"]) is not list or len(doc["spools"]) != 2:
        raise codec.SpoolError("exactly two ordered spool identities required")
    entries = list(zip(SPOOL_NAMES, doc["spools"], (codec.SPOOL_BYTES,) * 2))
    entries += [(POINT_NAME, doc["points"], POINT_LIMIT), (RECEIPT_NAME, doc["receipt"], RECEIPT_LIMIT)]
    for name, identity, limit in entries:
        if (type(identity) is not dict or set(identity) != {"filename", "bytes", "sha256"}
                or identity["filename"] != name or type(identity["bytes"]) is not int
                or not 0 < identity["bytes"] <= limit
                or name in SPOOL_NAMES and identity["bytes"] != codec.SPOOL_BYTES):
            raise codec.SpoolError("closed-world artifact identity schema")
        codec.hex_digest(identity["sha256"])
    return doc


def capture_candidates(root, *, expected_handoff_sha256):
    """Read-only identity inventory, NOT semantic acceptance or authorization.

    The expected digest comes from a trusted producer handoff. One capture per
    file; all names are constants. read_snapshot enforces its 1 MiB read cap;
    tighter object limits are checked on the captured bytes, never a reread.
    """
    codec.hex_digest(expected_handoff_sha256)
    root = io.exact_path(root)
    handoff = io.read_snapshot(root / HANDOFF_NAME, external=True)
    doc = _handoff_document(handoff, expected_handoff_sha256)
    snapshots = []
    entries = list(zip(SPOOL_NAMES, doc["spools"], (codec.SPOOL_BYTES,) * 2))
    entries += [(POINT_NAME, doc["points"], POINT_LIMIT), (RECEIPT_NAME, doc["receipt"], RECEIPT_LIMIT)]
    for name, expected, limit in entries:
        snap = io.read_snapshot(root / name, external=True)
        _check_identity(snap, expected, name, limit)
        snapshots.append(snap)
    return CandidateSet(handoff, tuple(snapshots[:2]), snapshots[2], snapshots[3])


@dataclass(frozen=True)
class AcceptedHandoffInsecureTestOnly:
    candidates: CandidateSet
    readers: tuple[codec.TreeSpoolSnapshotInsecureTestOnly, ...]


class HandoffSessionInsecureTestOnly(base.BoundedSessionInsecureTestOnly):
    """Live single-caller session; only private tree-post inputs cross the codec.

    Owner cursors, native prefix hash objects, tail state and ordinary assignment
    stay live. This is deliberately NOT a new-session/durable restore function.
    """
    def __init__(self, variant=0):
        validate_prerequisites()
        super().__init__(variant)
        self.spool_snapshots = [None, None]
        self.accepted_handoff = None

    def context(self, index):
        start, end = self.plan["trees"][index]["pre"]
        return codec.Context(index, start, end, base.digest(b"PLAN", self.reference.plan_raw),
                             self.reference.invocation_digest)

    def _advance(self, stage, point_snapshot):
        if stage.startswith("tree-pre"):
            i = int(stage[-2])
            owner = f"tree[{i}]"
            start = self.plan["trees"][i]["pre"][0]
            gen = native._iter_tree_spool_native_insecure_test_only(
                base.PARAMETERS, self.reference.randomness, self.reference.execution, i,
                self.reference.invocation.ticket_message, spool_context=self.context(i),
                external_point_starts=self.plan["point_starts"], local_wire_start=start,
                assignment_writer=base._Writer(self.values, start),
                sink_factory=self._new_sink(owner, stage, self.plan["trees"][i]["pre"]))
            self.generators[owner] = gen
            _, ports, _, raw = next(gen)
            snap = _snapshot(SPOOL_NAMES[i], raw)
            reader = codec.decode_snapshot_insecure_test_only(
                snap, expected_bytes=codec.SPOOL_BYTES, expected_sha256=codec.sha256(raw), context=self.context(i))
            reader.assert_values(self.values)
            self.spool_snapshots[i] = snap
            self.ports[stage] = ports
            self._range_equal(f"binding.tree[{i}].salt", start, self.anchors["salt"], 386)
            self._range_equal(f"binding.tree[{i}].roots", start + 386, self.anchors[f"roots[{i}]"], 386)
            self._relocate(ports, True)
        elif stage.startswith("tree-post"):
            i = int(stage[-2])
            accepted = self.accepted_handoff
            if accepted is None:
                raise codec.SpoolError("accepted snapshot handoff required")
            reader = accepted.readers[i]
            reader.assert_values(self.values)
            points = self.validate_point_snapshot(accepted.candidates.points)
            owner = f"tree[{i}]"
            self.sinks[owner].stage(stage, self.plan["trees"][i]["post"],
                                    [self.plan["trees"][i]["pre"], [points[0][0], points[0][0] + 386]])
            try:
                self.generators[owner].send((*points, reader.snapshot))
            except StopIteration as stop:
                summary = stop.value
            else:
                raise codec.SpoolError("tree did not complete")
            self.summaries[owner] = summary
            self._relocate(summary.ports, False)
        else:
            super()._advance(stage, point_snapshot)

    def step(self, stage, **kwargs):
        if stage.startswith("tree-post") and self.accepted_handoff is None:
            raise codec.SpoolError("tree-post refuses before sink/row changes without handoff")
        return super().step(stage, **kwargs)

    def export_candidates(self):
        if self.closed or self.failed or self.position != 4:
            raise codec.SpoolError("handoff only after exact global-A prefix")
        spools = tuple(self.spool_snapshots)
        points = _snapshot(POINT_NAME, self.point_snapshot.raw)
        receipt = _snapshot(RECEIPT_NAME, self.receipts[3])
        doc = {"format": FORMAT, "relation_id": RELATION_ID, "profile_fingerprint": codec.PROFILE,
               "plan_sha256": base.digest(b"PLAN", self.reference.plan_raw),
               "invocation_sha256": self.reference.invocation_digest,
               "stage_id": "global-a", "next_stage": "tree-post[0]",
               "spools": [_identity(s, name, codec.SPOOL_BYTES) for s, name in zip(spools, SPOOL_NAMES)],
               "points": _identity(points, POINT_NAME, POINT_LIMIT),
               "receipt": _identity(receipt, RECEIPT_NAME, RECEIPT_LIMIT),
               "production": False, "durable_resume": False}
        return CandidateSet(_snapshot(HANDOFF_NAME, io.canonical_json(doc)), spools, points, receipt)

    def accept_handoff(self, candidates, *, expected_handoff_sha256):
        # Input rejection is before any native computation or state mutation.
        if type(candidates) is not CandidateSet or self.accepted_handoff is not None:
            raise codec.SpoolError("one exact handoff per live session")
        doc = _handoff_document(candidates.handoff, expected_handoff_sha256)
        expected = self.export_candidates()
        if candidates.handoff.raw != expected.handoff.raw:
            raise codec.SpoolError("handoff does not match this producer invocation/prefix")
        _check_identity(candidates.receipt, doc["receipt"], RECEIPT_NAME, RECEIPT_LIMIT)
        _check_identity(candidates.points, doc["points"], POINT_NAME, POINT_LIMIT)
        self.validate_receipt(candidates.receipt, 3)
        self.validate_point_snapshot(candidates.points)
        readers = []
        for i, (snap, name) in enumerate(zip(candidates.spools, SPOOL_NAMES)):
            identity = doc["spools"][i]
            _check_identity(snap, identity, name, codec.SPOOL_BYTES)
            reader = codec.decode_snapshot_insecure_test_only(
                snap, expected_bytes=identity["bytes"], expected_sha256=identity["sha256"], context=self.context(i))
            reader.assert_values(self.values)
            readers.append(reader)
        self.accepted_handoff = AcceptedHandoffInsecureTestOnly(candidates, tuple(readers))
        return self.accepted_handoff

    def handoff_evidence(self):
        native_evidence = self.evidence()
        if self.accepted_handoff is None:
            raise codec.SpoolError("missing accepted handoff")
        candidates = self.accepted_handoff.candidates
        return {"format": FORMAT, "relation_id": RELATION_ID, "mode": "INSECURE-TEST-ONLY",
                "native_qualification": native_evidence,
                "private_spool_identities": [s.identity for s in candidates.spools],
                "handoff_identity": candidates.handoff.identity,
                "total_private_capture_bytes": sum(len(s.raw) for s in
                    (candidates.handoff, *candidates.spools, candidates.points, candidates.receipt)),
                "selected_wire_value_bindings_checked": 2 * codec.LEAVES * codec.RECORD_WIRES,
                "same_raw_for_identity_decode_and_consumption": True,
                "native_post_consumes_captured_spools": True,
                "private_payload_embedded": False, "full_session_restore_implemented": False,
                "durable_resume_implemented": False, "production_execution_started": False,
                "Proof-closed": False, "Production-closed": False}


@lru_cache(maxsize=1)
def bounded_self_check():
    session = HandoffSessionInsecureTestOnly()
    try:
        session.run_to("global-a")
        candidates = session.export_candidates()
        session.accept_handoff(candidates, expected_handoff_sha256=codec.sha256(candidates.handoff.raw))
        session.run_to()
        evidence = session.handoff_evidence()
        if any(evidence["native_qualification"][key] != value for key, value in base.FROZEN.items()):
            raise codec.SpoolError("native bounded equivalence drift")
        if any(evidence[key] != value for key, value in FROZEN.items()):
            raise codec.SpoolError("private spool frozen evidence drift")
        return evidence
    finally:
        session.close()


def execute_production(*args, **kwargs):
    raise base.ProductionUnavailable("private-spool test-only codec; no production or durable restore")


def preflight():
    validate_prerequisites()
    return {"format": FORMAT, "relation_id": RELATION_ID, "read_only_preflight_passed": True,
            "safe_to_run_bounded_insecure_test_only": True, "spool_bytes_per_tree": codec.SPOOL_BYTES,
            "production_execution_command": None, "large_replay_command": None, "large_proving_command": None,
            "safe_to_start_large_replay": False, "safe_to_start_large_proving_run": False,
            "production_rows_replayed": 0, "proofs_generated": 0,
            "full_session_restore_implemented": False, "durable_resume_implemented": False,
            "Proof-closed": False, "Production-closed": False,
            "external_inventory_scope": "not provisioned",
            "missing_production_artifacts": list(base.prefreeze.inputs.REQUIRED_EXTERNAL_ARTIFACTS),
            "blockers": list(base.prefreeze.BLOCKERS)}


def build_manifest():
    return {"format": FORMAT, "relation_id": RELATION_ID, "implementation_version": "1.0",
            "implementation_identities": {path: io.read_snapshot(ROOT / path).identity for path in (
                "src/pq_rbbc_issuance_private_spool_codec_v1.py",
                "src/pq_rbbc_issuance_private_spool_native_v1.py",
                "src/pq_rbbc_issuance_private_spool_handoff_v1.py",
                "tests/test_pq_rbbc_issuance_private_spool_handoff_v1.py")},
            "predecessor_identities": {path: {"bytes": size, "sha256": sha}
                                      for path, (size, sha) in PREDECESSOR_PINS.items()},
            "codec": {"magic_hex": codec.MAGIC.hex(), "version": codec.VERSION,
                      "integer_order": "little-endian", "wire_id_bytes": 8,
                      "records_per_tree": codec.LEAVES, "wires_per_record": codec.RECORD_WIRES,
                      "packed_selected_bytes_per_record": codec.PACKED_BYTES,
                      "selected_positions": [[0, 2048], [2064, 2450]], "xi_bits": codec.XI_BITS,
                      "spool_bytes": codec.SPOOL_BYTES, "unused_padding_bits_must_be_zero": True,
                      "all_names_closed_world": [HANDOFF_NAME, *SPOOL_NAMES, POINT_NAME, RECEIPT_NAME]},
            "resource_budget": {"max_wires": base.MAX_WIRES, "max_rows": base.MAX_ROWS,
                                "planned_memory_mib": 512, "planned_seconds": 180,
                                "single_capture_read_limit_bytes": io.MAX_JSON_BYTES,
                                "max_accepted_candidate_bytes": 2 * codec.SPOOL_BYTES + HANDOFF_LIMIT + POINT_LIMIT + RECEIPT_LIMIT,
                                "production_estimate": None},
            "bounded_qualification": bounded_self_check(), "preflight": preflight(),
            "claim_status": {"Defined": True, "Instantiated": "bounded-insecure-test-only",
                             "Implemented": "private-spool-codec-and-live-snapshot-handoff",
                             "Tested": "bounded", "Evidence-sealed": "metadata-only",
                             "Proof-closed": False, "Production-closed": False,
                             "qualified_pq_se_backend_integrated": False,
                             "formal_pi_issue_generated": False, "durable_resume_implemented": False},
            "snapshot_contract": {"single_open_single_bounded_read": True,
                                  "same_raw_for_identity_parse_binding_and_consumer": True,
                                  "future_executor_consumes_same_candidate_set_snapshots": True,
                                  "candidate_pathname_reopen_permitted": False,
                                  "metadata_proves_no_writer": False,
                                  "deployment_trust_writer_quiescence_and_durability_are_external": True},
            "exact_commands": {
                "read_only": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_private_spool_handoff_v1.py",
                "bounded": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_private_spool_handoff_v1.py --self-check",
                "targeted": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_private_spool_handoff_v1 -v",
                "production": None, "large_replay": None, "large_proving": None}}


def build_portable_evidence():
    raw = io.canonical_json(build_manifest())
    return {"format": FORMAT + "-PORTABLE-EVIDENCE", "bounded_qualification": bounded_self_check(),
            "manifest": {"filename": Path(MANIFEST_PATH).name, "bytes": len(raw), "sha256": codec.sha256(raw)},
            "private_assignment_spool_or_resume_state_embedded": False, "production_execution_started": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    print(io.canonical_json(bounded_self_check() if args.self_check else preflight()).decode("ascii"), end="")


if __name__ == "__main__":
    main()
