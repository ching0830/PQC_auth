#!/usr/bin/env python3
"""Read-only, definition-only 42-stage issuance producer ABI pre-freeze.

No producer, allocator, replay, prover, publisher or output directory is run by
this module. Planned intervals reuse topology ONLY, in a fresh ABI namespace.
They are not an observed or qualified split production stream.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath

import pq_rbbc_issuance_production_inputs_v1 as inputs
import pq_rbbc_launch_io_v2_41 as io


ROOT = Path(__file__).resolve().parents[1]
FORMAT = "PQRBBC-ISSUANCE-PRODUCTION-ABI-PREFREEZE-1"
PLAN_FORMAT = "PQRBBC-ISSUANCE-PRODUCTION-PRODUCER-ABI-PLAN-1"
VERSION = "1.0"
RELATION_ID = "pq-rbbc/issuance/cap576-native/production-producer-abi/candidate/v1"
PROFILE = "2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38"
DOMAIN = b"PQ-RBBC/ISSUANCE-PRODUCTION-PRODUCER-ABI/PLAN/V1"
MANIFEST_PATH = "manifests/pq_rbbc_issuance_production_abi_prefreeze_manifest_v1.json"
EVIDENCE_PATH = (
    "artifacts/metadata/issuance_production_abi_prefreeze_v1/"
    "pq_rbbc_issuance_production_abi_prefreeze_portable_evidence_v1.json"
)
CHILD_MANIFEST = "manifests/pq_rbbc_issuance_cap_child_executor_manifest_v1.json"
FRAGMENT_MANIFEST = "manifests/pq_rbbc_issuance_fragment_producers_manifest_v1.json"
FROZEN_CHILD_PLAN = "ececfbf8421dc6593498bf0da8d5b1f9aed61ceee041ca7af0ebf19f594c0943"
PINS = {
    CHILD_MANIFEST: (35544, "72ca9390f78c03d31bf4e45e25da3a5cf821d31259782df95e54a3e7c2d4d5e4"),
    FRAGMENT_MANIFEST: (7575, "587e5c6ebf78f8c4d0c74363373b4b8ac68f69171dfa6b53a4166019b4288741"),
    "src/pq_rbbc_issuance_cap_child_executor_v1.py": (
        51223, "930e98f647a7539f9124515931df979cbfe8fb10c4ecda731e6987fcbd15033c"),
    "src/pq_rbbc_issuance_fragment_producers_v1.py": (
        83785, "5695c70364fcbf6f9d04f526e020f81d6a3779e54173642047085ad36f86c6fa"),
    "src/pq_rbbc_issuance_production_inputs_v1.py": (
        40304, "7f57417efcea41bc94f477966dfaf629475b39b0ed1c0a4e389d4de10657357f"),
    "src/pq_rbbc_launch_io_v2_41.py": (
        10564, "d7589d22abf251f9d2297455bafccaed34be7900b9e11e68ac037d9ad4c3a061"),
    "artifacts/metadata/issuance_fragment_producers_v1/"
    "pq_rbbc_issuance_fragment_producers_portable_evidence_v1.json": (
        3709, "0495eab9092e896f59672eb7facf0533bc01f9a7721158649ecc2db04d54ca52"),
}
ORDER = (
    "validate-snapshots", "bind-invocation",
    *(f"tree-pre[{i}]" for i in range(18)), "global-tail-phase-a",
    *(f"tree-post[{i}]" for i in range(18)), "global-tail-phase-b",
    "parent-native-join", "final-seal",
)
BLOCKERS = (
    "production split producer adapter and per-owner allocator not qualified",
    "18-tree corrections and all 72 ordinary equality relocations not freshly replayed",
    "private spool streaming codec, identity-bound handoff and resume not qualified",
    "fresh parent I1-I5 composition and same-input binding not replayed",
    "production scale, source/output identity freeze and independent review absent",
    "qualified PQ simulation-extractable backend not integrated",
    "new operator resource reservation and explicit large-run authorization absent",
    "trusted producer handoff, writer quiescence, owner/mode/ACL, existing writable FDs, "
    "mount namespace and filesystem durability remain external prerequisites",
)


class PrefreezeError(ValueError):
    """Invalid captured prerequisite or ABI plan."""


class ProductionUnavailable(RuntimeError):
    """This gate never authorizes or executes production."""


def canonical_json(value: object) -> bytes:
    return io.canonical_json(value)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _relative(path: object) -> str:
    if type(path) is not str:
        raise PrefreezeError("prerequisite path must be a string")
    parsed = PurePosixPath(path)
    if (parsed.is_absolute() or ".." in parsed.parts or str(parsed) != path
            or parsed.parts[0] not in {"src", "tests", "manifests", "artifacts", "docs", "checksums"}):
        raise PrefreezeError(f"noncanonical prerequisite path: {path}")
    return path


def _dependencies(snapshot: io.Snapshot) -> dict[str, tuple[int, str]]:
    # Legacy manifests may have historical pretty-JSON encodings. They are
    # identity-only leaves, never silently reencoded as a new canonical input.
    if (snapshot.location.suffix != ".json"
            or not snapshot.location.name.startswith("pq_rbbc_issuance_")):
        return {}
    result = {}
    for item in snapshot.document().get("tracked_prerequisites", {}).values():
        path = _relative(item["path"])
        size, digest = item["bytes"], item["sha256"]
        if (type(size) is not int or not 0 < size <= io.MAX_JSON_BYTES
                or type(digest) is not str or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)):
            raise PrefreezeError("invalid prerequisite identity")
        if path in result and result[path] != (size, digest):
            raise PrefreezeError("conflicting prerequisite identities")
        result[path] = (size, digest)
    return result


@dataclass(frozen=True)
class PrerequisiteSet:
    """Same immutable captured raw for identity, parsing and all plan validation."""

    root: Path
    snapshots: tuple[tuple[str, io.Snapshot], ...]

    def validated(self) -> dict[str, io.Snapshot]:
        if type(self.snapshots) is not tuple:
            raise PrefreezeError("immutable prerequisite tuple required")
        captured = dict(self.snapshots)
        io.exact_path(self.root)
        if len(captured) != len(self.snapshots):
            raise PrefreezeError("duplicate prerequisite")
        expected = dict(PINS)
        checked = set()
        while pending := sorted(set(expected) - checked):
            for path in pending:
                snap = captured.get(path)
                if not isinstance(snap, io.Snapshot):
                    raise PrefreezeError(f"missing prerequisite: {path}")
                if snap.location != self.root / path:
                    raise PrefreezeError(f"prerequisite location: {path}")
                if (len(snap.raw), sha256(snap.raw)) != expected[path]:
                    raise PrefreezeError(f"prerequisite identity: {path}")
                checked.add(path)
                for relative, identity in _dependencies(snap).items():
                    if relative in expected and expected[relative] != identity:
                        raise PrefreezeError("conflicting prerequisite closure")
                    expected[relative] = identity
        if set(captured) != checked:
            raise PrefreezeError("unknown prerequisite")
        return captured


def capture_prerequisites(root: Path = ROOT) -> PrerequisiteSet:
    """One capture per tracked path; no producer/manifest-builder invocation."""
    expected = dict(PINS)
    captured = {}
    while pending := sorted(set(expected) - set(captured)):
        for relative in pending:
            snap = io.read_snapshot(root / relative)
            if (len(snap.raw), sha256(snap.raw)) != expected[relative]:
                raise PrefreezeError(f"prerequisite identity: {relative}")
            captured[relative] = snap
            for path, identity in _dependencies(snap).items():
                if path in expected and expected[path] != identity:
                    raise PrefreezeError("conflicting prerequisite closure")
                expected[path] = identity
    result = PrerequisiteSet(root, tuple(sorted(captured.items())))
    result.validated()
    return result


def _interval(start: int, end: int) -> dict:
    return {"start": start, "end_exclusive": end}


def _port(port_id: str, producer: str, consumer: str, width: int,
          start: int | None, target: int | None = None) -> dict:
    return {
        "port_id": port_id, "producer": producer, "consumer": consumer,
        "kind": "private-external-spool-reference" if width == 0 else "native-bit-wires",
        "bit_length": width,
        "producer_interval": None if start is None else _interval(start, start + width),
        "consumer_interval": None if target is None else _interval(target, target + width),
        "binding": "same-wire-ids" if target is None else "ordinary-equality-per-bit",
        "observed_value_sha256": None,
    }


def build_plan(prerequisites: PrerequisiteSet) -> dict:
    captured = prerequisites.validated()
    child = captured[CHILD_MANIFEST].document()["production_plan"]
    if child["sha256"] != FROZEN_CHILD_PLAN or child["stage_order"] != list(ORDER):
        raise PrefreezeError("predecessor plan identity")
    trees, ports, stages = [], [], []
    for row in child["tree_contracts"]:
        i = row["tree_index"]
        pre, post = f"tree-pre[{i}]", f"tree-post[{i}]"
        split = row["outputs"][2]["planned_wire_end"] + 1
        trees.append({
            "tree_index": i, "leaves": row["leaves"],
            "extension_degree": row["extension_degree"],
            "relation_id": f"{RELATION_ID}/tree-{i}",
            "rho_salt_byte_interval": row["rho_salt_byte_interval"],
            "rho_root_byte_intervals": row["rho_root_byte_intervals"],
            "planned_pre_interval": _interval(row["planned_local_wire_start"], split),
            "planned_post_interval": _interval(split, row["planned_local_wire_end"] + 1),
            "historical_total_rows_reference_only": row["planned_rows"],
            "fresh_pre_rows": None, "fresh_post_rows": None,
            "private_spool_records": row["leaves"],
            "private_spool_wire_ids_per_record": 2434,
            "private_spool_binary_codec_frozen": False,
        })
        for output in row["outputs"]:
            before = output["phase"] == "tree-pre"
            ports.append(_port(
                output["port_id"], pre if before else post,
                "global-tail-phase-a" if before else "global-tail-phase-b",
                output["bit_length"], output["planned_wire_start"], output["consumer_wire_start"],
            ))
        ports.append(_port(f"tree[{i}].private-spool", pre, post, 0, None))
        ports.append(_port("global.consistency-points", "global-tail-phase-a", post,
                           386, 39945673))
    ports.extend((
        _port("global.h1", "global-tail-phase-a", "global-tail-phase-b", 386, 39943623),
        _port("global.consistency-points", "global-tail-phase-a", "global-tail-phase-b", 386, 39945673),
    ))
    # Phase B also consumes pre outputs through the SAME validated relocations.
    # No second assignment to these tail input slots is allowed.
    tail_intervals = {
        "bind-invocation": _interval(1, 15939163),
        "global-tail-phase-a": _interval(15939163, 39946062),
        "global-tail-phase-b": _interval(39946062, 40194597),
    }
    for ordinal, name in enumerate(ORDER):
        tree = next((t for t in trees if name in (
            f"tree-pre[{t['tree_index']}]", f"tree-post[{t['tree_index']}]")), None)
        interval = tail_intervals.get(name)
        mapping = None
        data_dependencies = []
        if tree is not None:
            is_pre = name.startswith("tree-pre")
            interval = tree["planned_pre_interval" if is_pre else "planned_post_interval"]
            mapping = "produce_tree_pre" if is_pre else "produce_tree_post"
            data_dependencies = (["bind-invocation"] if is_pre else
                                 [f"tree-pre[{tree['tree_index']}]", "global-tail-phase-a"])
        elif name == "bind-invocation":
            mapping = "produce_input_binding"
            data_dependencies = ["validate-snapshots"]
        elif name == "global-tail-phase-a":
            mapping = "produce_global_a"
            data_dependencies = ["bind-invocation", *(f"tree-pre[{i}]" for i in range(18))]
        elif name == "global-tail-phase-b":
            mapping = "produce_global_b"
            data_dependencies = ["bind-invocation", "global-tail-phase-a",
                                 *(f"tree-pre[{i}]" for i in range(18)),
                                 *(f"tree-post[{i}]" for i in range(18))]
        elif name == "parent-native-join":
            data_dependencies = ["bind-invocation", "global-tail-phase-b"]
        elif name == "final-seal":
            data_dependencies = list(ORDER[:-1])
        stages.append({
            "ordinal": ordinal, "stage_id": name,
            "previous_receipt_stage": None if ordinal == 0 else ORDER[ordinal - 1],
            "data_dependencies": data_dependencies,
            "bounded_function_analogue": mapping,
            "bounded_function_directly_production_usable": False,
            "planned_interval": interval,
            "allocation_owner": f"tree[{tree['tree_index']}]" if tree else (
                "tail" if interval else None),
            "import_ports": [p for p in ports if p["consumer"] == name],
            "export_ports": [p for p in ports if p["producer"] == name],
            "observed_stream_bytes": None, "observed_stream_sha256": None,
            "assignment_identity": None, "fresh_rows": None,
        })
    return {
        "format": PLAN_FORMAT, "implementation_version": VERSION,
        "relation_id": RELATION_ID, "profile_fingerprint": PROFILE,
        "predecessor_plan_sha256": FROZEN_CHILD_PLAN,
        "stage_order": list(ORDER), "stages": stages, "trees": trees,
        "interval_contract": {
            "encoding": "positive uint64 wire IDs; half-open [start,end_exclusive)",
            "wire_zero": "shared constant one; never allocated",
            "status": "topology-derived reservations only; not production emission",
            "tree_split_rule": "first post wire = last pre mhat-plain wire + 1",
            "tail_input_slots": "reservation only; values require same invocation and 72 relocations",
            "allocator": "per-owner cursor; never a single global next_wire",
            "post_cursor": "restore the same tree-pre end; not global-A next_wire",
            "tail_point_imports": [_interval(39945673, 39945866), _interval(39945866, 39946059)],
            "parent_start_lower_bound": 429757233,
            "parent_interval": None,
            "parent_interval_reason": "fresh I1-I5 lowering and extra bindings not qualified",
            "production_absolute_intervals_qualified": False,
        },
        "global_a_contract": {
            "ordered_pre_trees": list(range(18)), "correction_pairs": 17,
            "delta_p_bits_each": 2048, "delta_mhat_bits_each": 386,
            "reference_tree": 0,
            "delta_equations": "p[0] XOR p[i]; mhat[0] XOR mhat[i], i=1..17",
            "global_h1_bits": 386, "consistency_point_bits": 386,
            "tree_pre_may_import_points": False,
        },
        "global_b_contract": {
            "ordered_post_trees": list(range(18)),
            "reuses_same_pre_ports_and_relocations": True,
            "shared_alpha_from": "tree[0].p-plain, tree[0].mhat-plain, same global points",
            "message_bits": 256, "commitment_bits": 43128,
            "derived_mask_bits": 576, "append_base_bits": 1472, "request_hash_bits": 576,
            "fresh_output_intervals": None,
        },
        "parent_join_contract": {
            "native_equalities": ["ticket-message == CAP message",
                                  "witness blind-mask == CAP derived-mask",
                                  "public beta == blind-mask XOR H_RBBC(message,c_r)"],
            "equality_widths": [256, 576, 576], "equality_rows_reference_only": 1408,
            "full_I1_I5_replayed": False, "formal_pi_issue_generated": False,
        },
        "adapter_gaps": [
            "bounded imports contain only tree[0] and four private tape records",
            "production pre must export p-plain/mhat-plain before global-A corrections",
            "bounded post/global-B wire forms differ from legacy 72-port producer layout",
            "fresh salt/root/message equality bindings require explicit qualification",
            "large private spool must not be embedded in cumulative bounded JSON",
        ],
        "runtime_handoff_schema": {
            "status": "requirements only; no accepting runtime codec or publisher",
            "canonical_encoding": "strict canonical JSON, ASCII, sorted keys, LF; <= 1 MiB metadata",
            "unknown_versions_fields_trailing_bytes_rejected": True,
            "required_identity_fields": ["format", "version", "relation_id", "profile_fingerprint",
                                         "plan_sha256", "invocation_sha256", "stage_id", "ordinal",
                                         "previous_receipt_sha256", "ordered_import_identities",
                                         "owner_cursor", "ordered_export_identities"],
            "invocation_digest_inputs": ["CandidateSet identities", "full statement.raw",
                                         "full witness.raw", "rho.raw", "plan digest"],
            "digest_framing": "SHA256(domain || uint64le(length) || component ...)",
            "invocation_domain": "PQ-RBBC/ISSUANCE-PRODUCTION-PRODUCER-ABI/INVOCATION/V1",
            "port_domain": "PQ-RBBC/ISSUANCE-PRODUCTION-PRODUCER-ABI/PORT/V1",
            "receipt_domain": "PQ-RBBC/ISSUANCE-PRODUCTION-PRODUCER-ABI/RECEIPT/V1",
            "port_digest_inputs": ["invocation digest", "plan digest", "producer", "consumer",
                                   "port id", "wire IDs", "bit width", "captured payload identity"],
            "fresh_namespace_and_cache_required": True,
            "resume_exact_external_latest_receipt_required": True,
            "completed_stage_prefix_only": True,
            "private_spool": "per-tree identity-bound external capture; codec and trusted streaming handoff open",
            "same_candidate_set_and_invocation_snapshots_required": True,
            "candidate_pathnames_may_be_reopened": False,
            "metadata_proves_no_writer": False,
        },
        "production_execution_started": False,
        "historical_or_other_tree_observations_reused": False,
    }


def validate_plan_snapshot(snapshot: io.Snapshot, prerequisites: PrerequisiteSet) -> dict:
    """Closed-world plan codec: raw identity, strict parse and binding agree."""
    document = snapshot.document()
    expected = build_plan(prerequisites)
    # Compare canonical bytes, not Python equality (True must not equal 1).
    if snapshot.raw != canonical_json(expected):
        raise PrefreezeError("ABI plan version, domain, binding or layout mismatch")
    validate_layout(document)
    return document


def validate_layout(plan: dict) -> None:
    """Independent arithmetic checks in addition to the exact closed-world codec."""
    intervals = [stage["planned_interval"] for stage in plan["stages"]
                 if stage["planned_interval"] is not None]
    ordered = sorted(intervals, key=lambda item: item["start"])
    next_wire = 1
    for interval in ordered:
        start, end = interval["start"], interval["end_exclusive"]
        if type(start) is not int or type(end) is not int or not start == next_wire < end:
            raise PrefreezeError("interval gap, overlap, type or reversed boundary")
        next_wire = end
    if next_wire != 429757233:
        raise PrefreezeError("planned CAP namespace end")
    seen, relocated, targets = set(), 0, []
    for stage in plan["stages"]:
        if not set(stage["data_dependencies"]) <= seen:
            raise PrefreezeError("future or missing data dependency")
        for port in stage["import_ports"]:
            source = next(s for s in plan["stages"] if s["stage_id"] == port["producer"])
            if port["producer"] not in stage["data_dependencies"]:
                raise PrefreezeError("port producer missing from dependencies")
            span, reservation = port["producer_interval"], source["planned_interval"]
            if span is not None and not (
                    reservation["start"] <= span["start"] < span["end_exclusive"]
                    <= reservation["end_exclusive"]
                    and span["end_exclusive"] - span["start"] == port["bit_length"]):
                raise PrefreezeError("port outside producer interval")
            target = port["consumer_interval"]
            if target is not None:
                if not (643 <= target["start"] < target["end_exclusive"] <= 15939163
                        and target["end_exclusive"] - target["start"] == port["bit_length"]):
                    raise PrefreezeError("relocation target outside tail input reservation")
                relocated += 1
                targets.append(target)
        seen.add(stage["stage_id"])
    if len(seen) != 42 or relocated != 72:
        raise PrefreezeError("stage or relocation count")
    next_target = 643
    for target in sorted(targets, key=lambda item: item["start"]):
        if target["start"] != next_target:
            raise PrefreezeError("relocation target gap or overlap")
        next_target = target["end_exclusive"]
    if next_target != 15939163:
        raise PrefreezeError("relocation input coverage")


def plan_sha256(plan: dict) -> str:
    return sha256(DOMAIN + canonical_json(plan))


def preflight(prerequisites: PrerequisiteSet, candidates: inputs.CandidateSet | None = None,
              plan_snapshot: io.Snapshot | None = None) -> dict:
    """Read only the supplied captures; no path reopen and no external writes."""
    plan = build_plan(prerequisites) if plan_snapshot is None else validate_plan_snapshot(
        plan_snapshot, prerequisites)
    validate_layout(plan)
    candidate_report = None if candidates is None else inputs.evaluate_candidate_set(candidates)
    missing = list(inputs.REQUIRED_EXTERNAL_ARTIFACTS) if candidate_report is None else candidate_report["missing_artifacts"]
    return {
        "format": FORMAT, "implementation_version": VERSION, "relation_id": RELATION_ID,
        "plan_sha256": plan_sha256(plan), "stage_count": 42, "relocation_count": 72,
        "read_only_abi_preflight_passed": True,
        "safe_to_author_bounded_multi_tree_adapter": True,
        "production_abi_qualified": False,
        "external_inventory_scope": "not provisioned" if candidates is None else "supplied CandidateSet only",
        "missing_artifacts": missing, "candidate_report": candidate_report,
        "blockers": list(BLOCKERS) + (missing if candidate_report is None else candidate_report["blockers"]),
        "production_rows_emitted": 0, "production_rows_replayed": 0, "proofs_generated": 0,
        "safe_to_start_large_replay": False, "safe_to_start_large_proving_run": False,
        "production_execution_authorized": False, "production_execution_command": None,
        "large_replay_command": None, "large_proving_command": None,
        "Proof-closed": False, "Production-closed": False,
    }


def execute_production(*args, **kwargs):
    raise ProductionUnavailable("read-only ABI gate; production refused before any input/output access")


def build_manifest(prerequisites: PrerequisiteSet) -> dict:
    plan = build_plan(prerequisites)
    report = preflight(prerequisites)
    return {
        "format": FORMAT, "implementation_version": VERSION, "plan": plan,
        "plan_sha256": plan_sha256(plan), "default_preflight": report,
        "tracked_prerequisites": {
            path: {"path": path, "bytes": len(snap.raw), "sha256": sha256(snap.raw)}
            for path, snap in sorted(prerequisites.validated().items())
        },
        "claim_status": {
            "Defined": True, "Instantiated": {"production_backend": False},
            "Implemented": {"read_only_checker": True, "production_adapter": False},
            "Tested": {"read_only_contract": True, "production": False},
            "Evidence-sealed": {"contract_metadata_only": True, "production": False},
            "Proof-closed": False, "Production-closed": False,
            "qualified_pq_se_backend_integrated": False, "formal_pi_issue_generated": False,
        },
        "resource_estimate": {
            "this_checker_max_capture_bytes_per_input": io.MAX_JSON_BYTES,
            "this_checker_rows_or_proofs": 0, "this_checker_writes": 0,
            "private_wire_spool_u64_body_bytes_planned": 40960 * 2434 * 8,
            "private_spool_figure_excludes_headers_values_rows_and_assignments": True,
            "historical_rows_reference_only": 589030555,
            "historical_memory_bytes_reference_only": 16000000000,
            "historical_disk_bytes_reference_only": 64000000000,
            "historical_seconds_reference_only": [8000, 12000],
            "fresh_production_resource_estimate": None, "new_reservation_obtained": False,
        },
        "exact_commands": {
            "read_only": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_production_abi_prefreeze_v1.py",
            "external_inventory": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_production_abi_prefreeze_v1.py --artifact-root /ABSOLUTE/PRIVATE/ARTIFACT/ROOT",
            "production": None, "large_replay": None, "large_proving": None,
        },
    }


def build_portable_evidence(prerequisites: PrerequisiteSet) -> dict:
    raw = canonical_json(build_manifest(prerequisites))
    return {
        "format": "PQRBBC-ISSUANCE-PRODUCTION-ABI-PREFREEZE-PORTABLE-EVIDENCE-1",
        "manifest": {"filename": Path(MANIFEST_PATH).name, "bytes": len(raw), "sha256": sha256(raw)},
        "plan_sha256": plan_sha256(build_plan(prerequisites)),
        "preflight": preflight(prerequisites),
        "private_values_or_assignments_embedded": False,
        "other_tree_observed_stream_bytes_used": False,
        "metadata_proves_no_concurrent_writer": False,
        "same_snapshot_raw_for_identity_parse_binding": True,
        "historical_files_modified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--plan", action="store_true", help="print definition-only plan to stdout")
    args = parser.parse_args()
    try:
        prerequisites = capture_prerequisites()
        candidates = None if args.artifact_root is None else inputs.read_candidate_set(args.artifact_root)
        result = build_plan(prerequisites) if args.plan else preflight(prerequisites, candidates)
    except (ValueError, OSError, KeyError, TypeError) as error:
        result = {"format": FORMAT, "read_only_abi_preflight_passed": False,
                  "safe_to_author_bounded_multi_tree_adapter": False,
                  "production_execution_authorized": False, "safe_to_start_large_replay": False,
                  "safe_to_start_large_proving_run": False, "error": str(error)}
        print(canonical_json(result).decode("ascii"), end="")
        return 2
    print(canonical_json(result).decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
