#!/usr/bin/env python3
"""4+4-leaf INSECURE-TEST-ONLY native adapter and per-owner allocator.

Bounded in-process suspension only; no durable checkpoint, spool publication,
production replay or cryptographic proof. Legacy generators remain immutable.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from functools import lru_cache
import hashlib
from pathlib import Path
from types import MappingProxyType

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_global_tail as tail
import pq_rbbc_cap_shard_stream as shard
import pq_rbbc_cap_tree_producer as tree
import pq_rbbc_issuance_cap_child_executor_v1 as child
import pq_rbbc_issuance_production_abi_prefreeze_v1 as prefreeze
import pq_rbbc_issuance_bounded_multitree_native_v1 as native
import pq_rbbc_launch_io_v2_41 as io


ROOT = Path(__file__).resolve().parents[1]
PARAMETERS = native.PARAMETERS
RELATION_ID = "pq-rbbc/issuance/cap576-native/multitree-4plus4-insecure-test-only/v1"
FORMAT = "PQRBBC-ISSUANCE-BOUNDED-MULTITREE-ADAPTER-1"
DOMAIN = b"PQ-RBBC/ISSUANCE-BOUNDED-MULTITREE-INSECURE-TEST-ONLY/V1/"
ORDER = ("bind-inputs", "tree-pre[0]", "tree-pre[1]", "global-a",
         "tree-post[0]", "tree-post[1]", "global-b", "bind-child-outputs", "final-seal")
MAX_WIRES = 200000
MAX_ROWS = 300000
MANIFEST_PATH = "manifests/pq_rbbc_issuance_bounded_multitree_adapter_manifest_v1.json"
EVIDENCE_PATH = (
    "artifacts/metadata/issuance_bounded_multitree_adapter_v1/"
    "pq_rbbc_issuance_bounded_multitree_adapter_portable_evidence_v1.json"
)
PREDECESSOR_PINS = {
    "src/pq_rbbc_issuance_production_abi_prefreeze_v1.py": (
        27067, "deff7761922766b0c4a1dabfa24dd4eeba6541db6c9260aa05abd62094cad3d0"),
    prefreeze.MANIFEST_PATH: (120443, "4e4757187d3ada9610f8e7d17f96b628d96ac8fefd0537042771a3ba3bacca34"),
    prefreeze.EVIDENCE_PATH: (2590, "c416ae175f15c2e6080263a51959025698c306100e5effbc3f0164479fcc72f7"),
}
FROZEN = {
    "total_rows_checked": 185743, "allocated_wires": 123798, "binding_rows": 12458,
    "plan_sha256": "729418cf1f9400b729ea02798547d260bf508bb775819456193a4e9270087c84",
    "point_snapshot_sha256": "43eceeec2f4b9cda18bc96014bebbaed319e0e7a8a8c04a710a6950828826009",
    "native_binding_rows_sha256": "3b6d9c40756c40aa9e37e49db2e849c313d99790b0bd9dd0b69a2fd435afa3f6",
    "final_receipt_sha256": "e82d57c9edb0b6bf05be5bea5534953e8e91719f2bc049add92635bc50a60801",
}


class AdapterError(ValueError):
    """Bounded identity, namespace, import or constraint violation."""


class ProductionUnavailable(RuntimeError):
    """No production entrypoint is implemented by this bounded gate."""


def canonical_json(value):
    return io.canonical_json(value)


def digest(label: bytes, *parts: bytes) -> str:
    h = hashlib.sha256(DOMAIN + label)
    for part in parts:
        h.update(len(part).to_bytes(8, "little"))
        h.update(part)
    return h.hexdigest()


def validate_prerequisites():
    captured = prefreeze.capture_prerequisites()
    prefreeze.preflight(captured)
    for path, identity in PREDECESSOR_PINS.items():
        if identity is None:
            raise AdapterError("unfrozen predecessor source")
        snap = io.read_snapshot(ROOT / path)
        if (len(snap.raw), hashlib.sha256(snap.raw).hexdigest()) != identity:
            raise AdapterError("predecessor identity mismatch: " + path)
    return captured


def bits(value, width):
    return tuple((value >> bit) & 1 for bit in range(width))


def span(port):
    return port.consumer_wire_start, port.consumer_wire_start + port.bit_length


@dataclass(frozen=True)
class Reference:
    invocation: child.InvocationSnapshotV1
    randomness: cap.CAPRandomness
    execution: cap.CAPExecution
    tail_summary: tail.GlobalTailSummary
    split: tail.TailSplitContract
    trees: tuple[tree.ProducerSummary, ...]
    plan_raw: bytes
    invocation_digest: str

    @property
    def plan(self):
        return io.strict_json(self.plan_raw)


@lru_cache(maxsize=2)
def build_reference_insecure_test_only(variant: int = 0) -> Reference:
    """An independent bounded monolithic reference, NOT a production artifact."""
    if type(variant) is not int or variant not in (0, 1):
        raise AdapterError("only two bounded fixture variants permitted")
    validate_prerequisites()
    invocation = child._fixture_invocation()
    formal = invocation.rho.randomness
    randomness = cap.CAPRandomness(formal.salt, formal.roots[:2])
    if variant:
        # Distinct private fixture; not claimed to be the formal witness's rho.
        randomness = cap.CAPRandomness(formal.salt, (
            (formal.roots[0][0] ^ 1, formal.roots[0][1]), formal.roots[1]))
    execution = cap.execute_cap_commit(PARAMETERS, randomness)
    contracts = []
    tail_summary = tail.build_global_tail(PARAMETERS, randomness, execution,
                                          invocation.ticket_message, split_contract_output=contracts)
    contract = contracts[0]
    point = next(p for p in contract.boundary_ports if p.port_id.endswith("consistency-points"))
    point_starts = (point.consumer_wire_start, point.consumer_wire_start + 193)
    next_wire = tail_summary.wires + 1
    trees = []
    tree_plans = []
    for i in range(2):
        summary = tree.build_tree_producer(
            PARAMETERS, randomness, execution, i, invocation.ticket_message,
            external_point_starts=point_starts, local_wire_start=next_wire)
        pre_end = next(p for p in summary.ports if p.port_id.endswith("mhat-plain"))
        cut = pre_end.wire_start + pre_end.bit_length
        tree_plans.append({"index": i, "pre": [next_wire, cut],
                           "post": [cut, summary.max_wire_id + 1]})
        next_wire = summary.max_wire_id + 1
        trees.append(summary)
    anchors = next_wire
    # 2 salts, 4 roots and 256-bit message, all anchored in native input rows.
    anchor_end = anchors + 6 * 193 + 256
    if anchor_end - 1 > MAX_WIRES:
        raise AdapterError("bounded wire budget exceeded")
    plan = {
        "format": FORMAT, "relation_id": RELATION_ID,
        "profile_fingerprint": cap.profile_fingerprint(PARAMETERS),
        "stage_order": list(ORDER), "trees": tree_plans,
        "tail_inputs": [1, contract.input_prelude_wire_end],
        "global_a": [contract.phases[0].wire_start, contract.phases[0].wire_end],
        "global_b": [contract.phases[1].wire_start, contract.phases[1].wire_end],
        "point_starts": list(point_starts), "anchors": [anchors, anchor_end],
        "max_wires": MAX_WIRES, "max_rows": MAX_ROWS,
        "production": False, "durable_resume": False,
    }
    raw = canonical_json(plan)
    identity = digest(b"INVOCATION", invocation.statement_raw, invocation.witness_raw,
                      invocation.rho.raw, canonical_json({"salt": list(randomness.salt),
                                                         "roots": [list(r) for r in randomness.roots]}), raw)
    return Reference(invocation, randomness, execution, tail_summary, contract, tuple(trees), raw, identity)


class PerOwnerAllocator:
    """Disjoint bounded reservations; a paused tree owns its own saved cursor."""
    def __init__(self, plan):
        self.ranges = {"tail": (1, plan["global_b"][1]), "anchors": tuple(plan["anchors"])}
        for item in plan["trees"]:
            self.ranges[f"tree[{item['index']}]"] = (item["pre"][0], item["post"][1])
        previous = 1
        for start, end in sorted(self.ranges.values()):
            if type(start) is not int or type(end) is not int or not previous == start < end <= MAX_WIRES + 1:
                raise AdapterError("owner interval gap, overlap or bound")
            previous = end
        self.cursors = {name: start for name, (start, _) in self.ranges.items()}

    def allocate(self, owner, cursor, count):
        if (owner not in self.ranges or type(cursor) is not int or type(count) is not int
                or count <= 0 or cursor != self.cursors[owner]
                or cursor + count > self.ranges[owner][1]):
            raise AdapterError("wrong owner cursor or reservation overflow")
        self.cursors[owner] += count


class _Writer:
    def __init__(self, values, start):
        self.values, self.cursor = values, start

    def append_values(self, values):
        for value in values:
            if self.cursor in self.values or not 0 <= value <= field.FIELD_MASK:
                raise AdapterError("assignment overwrite or non-field value")
            self.values[self.cursor] = value
            self.cursor += 1

    def append_encoded(self, raw, count):
        if len(raw) != count * 25:
            raise AdapterError("assignment encoding width")
        self.append_values(int.from_bytes(raw[i:i+25], "little") for i in range(0, len(raw), 25))


class _Sink(tail.BinaryRowSink):
    def __init__(self, session, owner, *args, **kwargs):
        self.session, self.owner = session, owner
        self.stage_interval = session.allocator.ranges[owner]
        self.import_intervals = []
        self.stage_name = "unstarted"
        super().__init__(*args, **kwargs)

    def stage(self, name, interval, imports=()):
        if self.next_wire != interval[0] or self.session.allocator.cursors[self.owner] != interval[0]:
            raise AdapterError("stage must restore its own exact cursor")
        self.stage_name, self.stage_interval, self.import_intervals = name, tuple(interval), tuple(imports)

    def allocate(self, count=1, **kwargs):
        if self.next_wire + count > self.stage_interval[1]:
            raise AdapterError("allocation crosses stage boundary")
        self.session.allocator.allocate(self.owner, self.next_wire, count)
        return super().allocate(count, **kwargs)

    def row(self, label, left, right, output, *, nonlinear):
        if self.session.rows >= MAX_ROWS:
            raise AdapterError("bounded row budget exceeded")
        for form in (left, right, output):
            for wire, _ in form.terms:
                if wire not in self.session.values or not (
                        self.stage_interval[0] <= wire < self.next_wire
                        or any(start <= wire < end for start, end in self.import_intervals)):
                    raise AdapterError(f"undeclared/unallocated import in {self.stage_name}: {wire}")
        row = field.RankOneRow(label, left, right, output)
        if not shard._row_satisfied_fast(row, self.session.values):
            raise AdapterError("native constraint failed: " + label)
        if label.startswith("xof[0].h1.payload[") and label.endswith(".source"):
            self.session.correction_rows.append(row)
        self.session.rows += 1
        super().row(label, left, right, output, nonlinear=nonlinear)


class BoundedSessionInsecureTestOnly:
    """Private in-memory witnesses and live coroutines; never a disk resume API."""
    def __init__(self, variant=0):
        self.reference = build_reference_insecure_test_only(variant)
        self.plan = self.reference.plan
        self.allocator = PerOwnerAllocator(self.plan)
        self.values, self.sinks, self.generators, self.summaries = {}, {}, {}, {}
        self.ports, self.relocation_ports, self.binding_rows, self.correction_rows = {}, [], [], []
        self.rows, self.position = 0, 0
        self._binding_digest = hashlib.sha256(DOMAIN + b"NATIVE-BINDING-ROWS")
        self.receipts = []
        self.closed = False
        self.failed = False
        self.anchors = {}
        self.point_snapshot = None

    def _new_sink(self, owner, stage, interval, imports=()):
        def factory(*args, **kwargs):
            sink = _Sink(self, owner, *args, **kwargs)
            sink.stage(stage, interval, imports)
            self.sinks[owner] = sink
            return sink
        return factory

    def _equal(self, label, left, right):
        if self.rows >= MAX_ROWS or left not in self.values or right not in self.values:
            raise AdapterError("binding budget or unallocated wire")
        row = field.RankOneRow(label, field.LinearForm.wire(left).add(field.LinearForm.wire(right)),
                              field.LinearForm.const(1), field.LinearForm.const(0))
        if not shard._row_satisfied_fast(row, self.values):
            raise AdapterError("native binding failed: " + label)
        for raw in (label.encode("utf-8"), tail._encode_form(row.left),
                    tail._encode_form(row.right), tail._encode_form(row.output)):
            self._binding_digest.update(len(raw).to_bytes(8, "little"))
            self._binding_digest.update(raw)
        self.binding_rows.append(row)
        self.rows += 1

    def _range_equal(self, label, source, target, width):
        for i in range(width):
            self._equal(f"{label}[{i}]", source + i, target + i)

    def _anchors(self):
        start, end = self.plan["anchors"]
        writer = _Writer(self.values, start)
        sink = _Sink(self, "anchors", {"format": FORMAT, "relation_id": RELATION_ID},
                     initial_wire=start, assignment_writer=writer)
        sink.stage("bind-inputs", [start, end])
        randomness = self.reference.randomness
        fields = [("salt", randomness.salt[0] | randomness.salt[1] << 193, 386)]
        fields += [(f"roots[{i}]", roots[0] | roots[1] << 193, 386)
                   for i, roots in enumerate(randomness.roots)]
        fields += [("message", int.from_bytes(self.reference.invocation.ticket_message, "little"), 256)]
        for name, value, width in fields:
            port = sink.allocate(width, values=bits(value, width))
            self.anchors[name] = port
            for offset in range(width):
                sink.bitness(f"anchor.{name}[{offset}]", port + offset)
        self.sinks["anchors"] = sink

    def _relocate(self, ports, before):
        targets = {p.port_id: p for p in self.reference.tail_summary.ports}
        for port in ports:
            if port.direction != "output" or (port.phase == "tree-pre") != before:
                continue
            target = targets[port.port_id]
            if port.bit_length != target.bit_length or port.port_id in self.relocation_ports:
                raise AdapterError("wrong width or repeated relocation")
            self._range_equal("relocation." + port.port_id, port.wire_start,
                              target.consumer_wire_start, port.bit_length)
            self.relocation_ports.append(port.port_id)

    def _point_raw(self):
        starts = self.plan["point_starts"]
        values = [sum(self.values[start + bit] << bit for bit in range(193)) for start in starts]
        return canonical_json({"format": FORMAT + "-POINT-PORT", "relation_id": RELATION_ID,
                               "profile_fingerprint": self.plan["profile_fingerprint"],
                               "invocation_sha256": self.reference.invocation_digest,
                               "plan_sha256": digest(b"PLAN", self.reference.plan_raw),
                               "producer": "global-a", "consumers": ["tree-post[0]", "tree-post[1]", "global-b"],
                               "wire_starts": starts, "field_bits": 193, "values": values})

    def validate_point_snapshot(self, snapshot):
        document = snapshot.document()
        if self.point_snapshot is None or snapshot.raw != self.point_snapshot.raw or snapshot.raw != self._point_raw():
            raise AdapterError("wrong point raw, identity, invocation or wire binding")
        return tuple(document["wire_starts"]), tuple(document["values"])

    def _advance(self, stage, point_snapshot):
        r, p = self.reference, self.plan
        if stage == "bind-inputs":
            self._anchors()
            gen = native._iter_tail_native_insecure_test_only(
                PARAMETERS, r.randomness, r.execution, r.invocation.ticket_message,
                assignment_writer=_Writer(self.values, 1),
                sink_factory=self._new_sink("tail", stage, p["tail_inputs"]))
            self.generators["tail"] = gen
            _, self.ports["tail-inputs"], _ = next(gen)
            self._range_equal("binding.tail.salt", 1, self.anchors["salt"], 386)
            self._range_equal("binding.tail.message", 387, self.anchors["message"], 256)
        elif stage.startswith("tree-pre"):
            i = int(stage[-2])
            owner = f"tree[{i}]"
            gen = native._iter_tree_native_insecure_test_only(
                PARAMETERS, r.randomness, r.execution, i, r.invocation.ticket_message,
                external_point_starts=p["point_starts"], local_wire_start=p["trees"][i]["pre"][0],
                assignment_writer=_Writer(self.values, p["trees"][i]["pre"][0]),
                sink_factory=self._new_sink(owner, stage, p["trees"][i]["pre"]))
            self.generators[owner] = gen
            _, ports, _ = next(gen)
            self.ports[stage] = ports
            start = p["trees"][i]["pre"][0]
            self._range_equal(f"binding.tree[{i}].salt", start, self.anchors["salt"], 386)
            self._range_equal(f"binding.tree[{i}].roots", start + 386, self.anchors[f"roots[{i}]"], 386)
            self._relocate(ports, True)
        elif stage == "global-a":
            if len(self.relocation_ports) != 6:
                raise AdapterError("all pre relocations required before global-A")
            imports = [span(port) for port in r.tail_summary.ports if port.port_id.endswith(
                (".leaf-commitments", ".p-plain", ".mhat-plain"))]
            self.sinks["tail"].stage(stage, p["global_a"], imports)
            _, self.ports[stage], _ = next(self.generators["tail"])
            self.point_snapshot = io.Snapshot(Path("/in-memory-insecure-test-only/points.json"), self._point_raw())
        elif stage.startswith("tree-post"):
            i = int(stage[-2])
            points = self.validate_point_snapshot(self.point_snapshot if point_snapshot is None else point_snapshot)
            owner = f"tree[{i}]"
            self.sinks[owner].stage(stage, p["trees"][i]["post"],
                                    [p["trees"][i]["pre"], [points[0][0], points[0][0] + 386]])
            try:
                self.generators[owner].send(points)
            except StopIteration as stop:
                summary = stop.value
            else:
                raise AdapterError("tree generator did not complete")
            self.summaries[owner] = summary
            self._relocate(summary.ports, False)
        elif stage == "global-b":
            if len(self.relocation_ports) != 8:
                raise AdapterError("all eight relocations required before global-B")
            self.validate_point_snapshot(self.point_snapshot)
            self.sinks["tail"].stage(stage, p["global_b"], [p["tail_inputs"], p["global_a"]])
            try:
                next(self.generators["tail"])
            except StopIteration as stop:
                self.summaries["tail"] = stop.value
            else:
                raise AdapterError("tail generator did not complete")
        elif stage == "bind-child-outputs":
            expected = {"tail": r.tail_summary, **{f"tree[{i}]": value for i, value in enumerate(r.trees)}}
            for owner, summary in self.summaries.items():
                reference = expected[owner]
                if (summary.rows, summary.wires, summary.stream_bytes, summary.stream_sha256) != (
                        reference.rows, reference.wires, reference.stream_bytes, reference.stream_sha256):
                    raise AdapterError("staged stream differs from independent legacy generator")
            if len(self.summaries) != 3:
                raise AdapterError("missing stream")
            if self.summaries["tail"].commitment_bytes != r.execution.commitment.encoded:
                raise AdapterError("commitment/reference mismatch")
        elif stage == "final-seal":
            if any(self.allocator.cursors[owner] != end for owner, (_, end) in self.allocator.ranges.items()):
                raise AdapterError("incomplete owner allocation")
            self.values = MappingProxyType(dict(self.values))

    def step(self, stage: str, *, expected_previous_receipt_sha256: str | None,
             point_snapshot: io.Snapshot | None = None) -> bytes:
        if self.closed or self.failed or self.position >= len(ORDER) or stage != ORDER[self.position]:
            raise AdapterError("wrong, repeated, future or closed stage")
        previous = None if not self.receipts else hashlib.sha256(self.receipts[-1]).hexdigest()
        if expected_previous_receipt_sha256 != previous:
            raise AdapterError("exact previous receipt required before computation")
        # Validate caller-supplied point bytes before any resumed row emission.
        if point_snapshot is not None:
            if not stage.startswith("tree-post"):
                raise AdapterError("point input only permitted at tree-post")
            self.validate_point_snapshot(point_snapshot)
        before = self.rows
        try:
            self._advance(stage, point_snapshot)
        except BaseException:
            self.failed = True
            self.close()
            raise
        receipt = {
            "format": FORMAT + "-RECEIPT", "relation_id": RELATION_ID,
            "profile_fingerprint": self.plan["profile_fingerprint"],
            "plan_sha256": digest(b"PLAN", self.reference.plan_raw),
            "invocation_sha256": self.reference.invocation_digest,
            "ordinal": self.position, "stage_id": stage,
            "previous_receipt_sha256": previous,
            "rows": self.rows - before, "total_rows": self.rows,
            "owner_cursors": dict(self.allocator.cursors),
            "relocation_ports": list(self.relocation_ports),
            "native_binding_rows_sha256": self._binding_digest.hexdigest(),
            "point_snapshot_sha256": None if self.point_snapshot is None else self.point_snapshot.identity["sha256"],
            "native_prefix_identities": {name: sink._digest.copy().hexdigest() for name, sink in self.sinks.items()},
            "production": False, "durable_resume": False,
        }
        raw = canonical_json(receipt)
        self.receipts.append(raw)
        self.position += 1
        return raw

    def validate_receipt(self, snapshot, ordinal):
        document = snapshot.document()
        if type(ordinal) is not int or not 0 <= ordinal < len(self.receipts) or snapshot.raw != self.receipts[ordinal]:
            raise AdapterError("receipt raw, version, domain or invocation mismatch")
        return document

    def run_to(self, stage="final-seal"):
        if stage not in ORDER or ORDER.index(stage) < self.position:
            raise AdapterError("stage not ahead of cursor")
        while self.position <= ORDER.index(stage):
            previous = None if not self.receipts else hashlib.sha256(self.receipts[-1]).hexdigest()
            self.step(ORDER[self.position], expected_previous_receipt_sha256=previous)
        return self.receipts[-1]

    def close(self):
        for gen in self.generators.values():
            gen.close()
        self.closed = True

    def evidence(self):
        if self.position != len(ORDER) or self.failed:
            raise AdapterError("incomplete bounded run")
        r = self.reference
        observations = {name: {"rows": s.rows, "wires": s.wires,
                               "stream_bytes": s.stream_bytes, "stream_sha256": s.stream_sha256}
                        for name, s in self.summaries.items()}
        return {
            "format": FORMAT, "relation_id": RELATION_ID, "mode": "INSECURE-TEST-ONLY",
            "plan_sha256": digest(b"PLAN", r.plan_raw), "invocation_sha256": r.invocation_digest,
            "stage_order": list(ORDER), "stage_rows": [io.strict_json(raw)["rows"] for raw in self.receipts],
            "total_rows_checked": self.rows, "native_streams": observations,
            "allocated_wires": len(self.values), "binding_rows": len(self.binding_rows),
            "native_binding_rows_sha256": self._binding_digest.hexdigest(),
            "relocation_port_count": len(self.relocation_ports), "correction_pair_count": 1,
            "delta_p_sha256": digest(b"DELTA-P", r.execution.commitment.delta_p[0].to_bytes(256, "little")),
            "delta_mhat_sha256": digest(b"DELTA-MHAT", r.execution.commitment.delta_mhat[0].to_bytes(49, "little")),
            "point_snapshot_sha256": self.point_snapshot.identity["sha256"],
            "final_receipt_sha256": hashlib.sha256(self.receipts[-1]).hexdigest(),
            "independent_legacy_native_streams_equal": True,
            "all_native_rows_satisfied": True, "verification_failures": 0,
            "same_global_point_wires": True, "per_owner_pre_post_cursors_checked": True,
            "in_process_suspension_only": True, "durable_resume_implemented": False,
            "production_rows_replayed": 0, "proofs_generated": 0,
            "formal_I1_I5_replayed": False, "formal_pi_issue_generated": False,
            "production_adapter_qualified": False, "Proof-closed": False, "Production-closed": False,
            "production_mixed_degree_12_13_qualified": False,
            "private_values_embedded": False, "other_tree_observed_stream_bytes_used": False,
        }


@lru_cache(maxsize=1)
def bounded_self_check():
    session = BoundedSessionInsecureTestOnly()
    try:
        session.run_to()
        evidence = session.evidence()
        if any(evidence[key] != value for key, value in FROZEN.items()):
            raise AdapterError("frozen bounded qualification drift")
        return evidence
    finally:
        session.close()


def execute_production(*args, **kwargs):
    raise ProductionUnavailable("bounded test-only adapter; production refused before any IO or CAP computation")


def build_manifest():
    return {
        "format": FORMAT, "implementation_version": "1.0", "plan": build_reference_insecure_test_only().plan,
        "implementation_identities": {
            path: io.read_snapshot(ROOT / path).identity for path in (
                "src/pq_rbbc_issuance_bounded_multitree_adapter_v1.py",
                "src/pq_rbbc_issuance_bounded_multitree_native_v1.py",
                "tests/test_pq_rbbc_issuance_bounded_multitree_adapter_v1.py")},
        "predecessor_identities": {path: {"bytes": size, "sha256": sha}
                                  for path, (size, sha) in PREDECESSOR_PINS.items()},
        "bounded_qualification": bounded_self_check(),
        "claim_status": {"Defined": True, "Instantiated": "bounded-insecure-test-only",
                         "Implemented": "bounded-native-adapter-and-per-owner-allocator",
                         "Tested": "bounded", "Evidence-sealed": "bounded-metadata-only",
                         "Proof-closed": False, "Production-closed": False,
                         "qualified_pq_se_backend_integrated": False,
                         "safe_to_start_large_replay": False, "safe_to_start_large_proving_run": False},
        "snapshot_contract": {"same_raw_for_identity_parse_binding": True,
                              "future_executor_must_consume_same_candidate_set_snapshots": True,
                              "candidate_pathnames_may_be_reopened": False,
                              "metadata_proves_no_writer": False,
                              "deployment_trust_and_writer_quiescence_are_external": True},
        "resource_budget": {"max_wires": MAX_WIRES, "max_rows": MAX_ROWS,
                            "planned_memory_mib": 512, "planned_seconds": 180,
                            "large_production_estimate": None},
        "unresolved": list(prefreeze.BLOCKERS),
        "external_inputs": {"provisioned": False, "required": list(prefreeze.inputs.REQUIRED_EXTERNAL_ARTIFACTS)},
        "exact_commands": {
            "bounded": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_bounded_multitree_adapter_v1.py --self-check",
            "targeted": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_bounded_multitree_adapter_v1 -v",
            "production": None, "large_replay": None, "large_proving": None},
    }


def build_portable_evidence():
    raw = canonical_json(build_manifest())
    return {"format": FORMAT + "-PORTABLE-EVIDENCE", "bounded_qualification": bounded_self_check(),
            "manifest": {"filename": Path(MANIFEST_PATH).name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
            "private_assignment_spool_or_resume_state_embedded": False,
            "production_execution_started": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if args.self_check:
        report = bounded_self_check()
    else:
        report = prefreeze.preflight(validate_prerequisites())
    print(canonical_json(report).decode("ascii"), end="")


if __name__ == "__main__":
    main()
