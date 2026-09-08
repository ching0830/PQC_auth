#!/usr/bin/env python3
"""PQ-RBBC v2.41 launch validation successor; production always unavailable.

Historical v2.39 is retained byte-for-byte for evidence reconstruction. Only
its pure schema/template descriptions are reused, with explicit version and
binding changes. No historical validator, candidate reader or writer is used.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import shlex
from typing import Callable

import pq_rbbc_cap_unified_tree_launch_preflight as historical
from pq_rbbc_launch_io_v2_41 import (
    ArtifactRoot, MAX_JSON_BYTES, Snapshot, ValidationError, canonical_json,
    exact_path, read_snapshot,
)


IMPLEMENTATION_VERSION = "2.41"
FORMAT = "PQRBBC-CAP-UNIFIED-TREE-LAUNCH-VALIDATION-TRANSITION-1"
REPORT_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-LAUNCH-VALIDATION-REPORT-1"
RELATION_ID = "pq-rbbc/cap/unified-tree/launch-validation/candidate/v2"
RESOURCE_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-RESOURCE-RESERVATION-4"
REVIEW_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-INDEPENDENT-REVIEW-4"
LAUNCH_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-LAUNCH-MANIFEST-3"
SUBJECT_FORMAT = "PQRBBC-CAP-UNIFIED-TREE-LAUNCH-REVIEW-SUBJECT-1"
ROOT = Path(__file__).resolve().parents[1]
EXTERNAL_ROOT = Path("/tmp/pq_rbbc_v2_41_launch_artifacts")
MANIFEST_PATH = ROOT / "manifests/pq_rbbc_cap_unified_tree_launch_validation_manifest_v2_41.json"
V2_38_PORTABLE_PATH = historical.V2_38_PORTABLE_PATH
V2_38_PORTABLE_IDENTITY = historical.V2_38_PORTABLE_IDENTITY
V2_38_MANIFEST_IDENTITY = historical.V2_38_MANIFEST_IDENTITY
PRODUCTION_PROFILE_FINGERPRINT = historical.PRODUCTION_PROFILE_FINGERPRINT
KINDS = ("resource_reservation", "independent_review", "launch_manifest")
FILENAMES = {kind: f"pq_rbbc_cap_unified_tree_{kind}_v2_41.json" for kind in KINDS}
SCHEMA_PATHS = {kind: ROOT / "schemas" / name.replace(".json", ".schema.json")
                for kind, name in FILENAMES.items()}
REPORT_FILENAME = "pq_rbbc_cap_unified_tree_launch_validation_report_v2_41.json"
Clock = Callable[[], datetime]


def trusted_now() -> datetime:
    return datetime.now(timezone.utc)


def check_now(now: datetime) -> datetime:
    if type(now) is not datetime or now.tzinfo is None or now.utcoffset() != timezone.utc.utcoffset(now):
        raise ValidationError("trusted now must be an aware UTC datetime")
    return now


def _utc(value: str) -> datetime:
    if type(value) is not str or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
        raise ValidationError("canonical UTC required")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise ValidationError("invalid UTC calendar time") from error


def locations(root: Path) -> dict[str, str]:
    root = exact_path(root)
    return {kind: str(root / filename) for kind, filename in FILENAMES.items()}


def production_command(root: Path) -> str:
    inputs = locations(root)
    argv = ["python", "-u", "src/pq_rbbc_cap_unified_tree_launch_validation_v2_41.py",
            "--phase", "production-prefreeze", "--trusted-artifact-root", str(root),
            "--v2-38-portable", str(V2_38_PORTABLE_PATH.relative_to(ROOT))]
    for kind in KINDS:
        argv.extend(["--" + kind.replace("_", "-"), inputs[kind]])
    argv.extend(["--output", str(root / "production-prefreeze"), "--fresh-output"])
    return "PYTHONPATH=src " + shlex.join(argv)


def command_sha256(root: Path) -> str:
    return hashlib.sha256(production_command(root).encode("utf-8")).hexdigest()


def _identity_schema(expected=None):
    schema = historical._identity_schema()
    if expected is not None:
        for key, value in expected.items():
            schema["properties"][key]["const"] = value
    return schema


def _object(properties):
    return {"type": "object", "additionalProperties": False,
            "required": list(properties), "properties": properties}


def _string():
    return {"type": "string", "minLength": 1, "x-concrete": True}


def _successor(value):
    """Explicit grammar transition; historical source is pinned by the manifest."""
    replacements = {
        historical.RESOURCE_FORMAT: RESOURCE_FORMAT,
        historical.REVIEW_FORMAT: REVIEW_FORMAT,
        historical.LAUNCH_FORMAT: LAUNCH_FORMAT,
    }
    if isinstance(value, dict):
        result = {_successor(k): _successor(v) for k, v in value.items()}
        if type(result.get("const")) is bool:
            result["type"] = "boolean"
        if type(result.get("const")) is int:
            result["type"] = "integer"
        return result
    if isinstance(value, list):
        return [_successor(v) for v in value]
    if type(value) is str:
        return replacements.get(value, value.replace("2.39", "2.41").replace("v2_39", "v2_41"))
    return value


def schemas() -> dict[str, dict]:
    result = {kind: _successor(factory()) for kind, factory in zip(KINDS, (
        historical.resource_reservation_schema, historical.independent_review_schema,
        historical.launch_manifest_schema))}
    for schema in result.values():
        schema["required"].append("launch_batch_id")
        schema["properties"]["launch_batch_id"] = _string()
    resource, review, launch = (result[k] for k in KINDS)
    resource["properties"]["execution_scope"]["properties"].update({
        "external_output": _string(), "exact_command_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}})
    review["properties"]["bound_identities"]["properties"]["v2_41_candidate_production_command_sha256"] = {
        "type": "string", "pattern": "^[0-9a-f]{64}$"}
    review["required"].append("review_subject")
    review["properties"]["review_subject"] = _object({
        "format": {"const": SUBJECT_FORMAT}, "launch_batch_id": _string(),
        "reservation_id": _string(), "resource_reservation": _identity_schema(),
        "command_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    })
    launch["required"].append("review_subject_sha256")
    launch["properties"]["review_subject_sha256"] = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    execution = launch["properties"]["execution"]
    execution["required"].append("candidate_locations")
    execution["properties"].update({
        "command": _string(), "command_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "external_output": _string(), "candidate_locations": _object({k: _string() for k in KINDS}),
    })
    # Exact integer identities at every depth use the same grammar.
    def tighten(node):
        if isinstance(node, dict):
            props = node.get("properties", {})
            if set(props) == {"filename", "bytes", "sha256"}:
                expected = {k: v["const"] for k, v in props.items() if "const" in v}
                node.update(_identity_schema(expected or None))
                return
            for key, field in props.items():
                if key.endswith("_utc"):
                    field["x-canonical-utc"] = True
                if key in ("identifier", "affiliation", "reference", "role", "reservation_id", "review_id", "launch_id"):
                    field["x-concrete"] = True
            for child in node.values():
                tighten(child)
        elif isinstance(node, list):
            for child in node:
                tighten(child)
    for schema in result.values():
        tighten(schema)
    return result


def strict_equal(value, expected) -> bool:
    if type(value) is not type(expected):
        return False
    if type(expected) is dict:
        return value.keys() == expected.keys() and all(strict_equal(value[k], v) for k, v in expected.items())
    if type(expected) is list:
        return len(value) == len(expected) and all(strict_equal(a, b) for a, b in zip(value, expected))
    return value == expected


def validate_schema(value, schema, label="root") -> tuple[str, ...]:
    """Closed supported grammar, including stricter-than-JSON-Schema integers.

    JSON Schema's mathematical integer permits 7390.0. This encoding contract
    additionally requires Python exact int and forbids decimal/exponent tokens.
    """
    failures = []
    types = {"object": dict, "array": list, "string": str, "boolean": bool, "integer": int}
    if "type" in schema and type(value) is not types[schema["type"]]:
        return (label + ":type",)
    if "const" in schema and not strict_equal(value, schema["const"]):
        failures.append(label + ":const")
    if "enum" in schema and not any(strict_equal(value, v) for v in schema["enum"]):
        failures.append(label + ":enum")
    if schema.get("type") == "object":
        props = schema["properties"]
        failures.extend(label + ":missing:" + key for key in schema["required"] if key not in value)
        failures.extend(label + ":extra:" + key for key in value if key not in props)
        for key in value.keys() & props.keys():
            failures.extend(validate_schema(value[key], props[key], label + ":" + key))
    if schema.get("type") == "array" and len(value) > schema.get("maxItems", len(value)):
        failures.append(label + ":length")
    if type(value) is int and value < schema.get("minimum", value):
        failures.append(label + ":minimum")
    if type(value) is str:
        if len(value) < schema.get("minLength", 0):
            failures.append(label + ":length")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            failures.append(label + ":pattern")
        if schema.get("x-concrete") and (not value.strip() or value.startswith("REPLACE-WITH-")):
            failures.append(label + ":placeholder")
        if schema.get("x-canonical-utc"):
            try:
                _utc(value)
            except ValidationError:
                failures.append(label + ":utc")
    return tuple(sorted(failures))


def review_subject(resource: Snapshot) -> dict:
    document = resource.document()
    return {"format": SUBJECT_FORMAT, "launch_batch_id": document["launch_batch_id"],
            "reservation_id": document["reservation_id"], "resource_reservation": resource.identity,
            "command_sha256": document["execution_scope"]["exact_command_sha256"]}


def subject_sha256(subject: dict) -> str:
    return hashlib.sha256(SUBJECT_FORMAT.encode("ascii") + b"\x00" + canonical_json(subject)).hexdigest()


def validate_resource(document: object, root: Path, now: datetime) -> tuple[str, ...]:
    check_now(now)
    failures = list(validate_schema(document, schemas()["resource_reservation"]))
    if failures:
        return tuple(failures)
    scope = document["execution_scope"]
    if scope["exact_command_sha256"] != command_sha256(root) or scope["external_output"] != str(root / "production-prefreeze"):
        failures.append("resource:execution_binding")
    window = document["reservation_window"]
    start, end = _utc(window["starts_at_utc"]), _utc(window["ends_at_utc"])
    approved = _utc(document["operator"]["approved_at_utc"])
    if not approved <= start < end:
        failures.append("resource:approval_window_order")
    if window["wall_clock_seconds"] != int((end - start).total_seconds()):
        failures.append("resource:window_duration")
    if not start <= now < end:
        failures.append("resource:inactive_window")
    return tuple(failures)


def validate_review(document: object, resource: Snapshot, root: Path, now: datetime) -> tuple[str, ...]:
    check_now(now)
    resource_doc = resource.document()
    failures = list(validate_resource(resource_doc, root, now))
    failures.extend(validate_schema(document, schemas()["independent_review"]))
    if failures:
        return tuple(failures)
    if not strict_equal(document["review_subject"], review_subject(resource)):
        failures.append("review:reservation_subject_binding")
    if document["launch_batch_id"] != resource_doc["launch_batch_id"]:
        failures.append("review:batch_binding")
    if document["bound_identities"]["v2_41_candidate_production_command_sha256"] != command_sha256(root):
        failures.append("review:command_binding")
    if not _utc(resource_doc["operator"]["approved_at_utc"]) <= _utc(document["reviewer"]["completed_at_utc"]) <= now:
        failures.append("review:time_order")
    return tuple(failures)


def validate_launch(document: object, resource: Snapshot, review: Snapshot, root: Path, now: datetime) -> tuple[str, ...]:
    check_now(now)
    review_doc, resource_doc = review.document(), resource.document()
    failures = list(validate_review(review_doc, resource, root, now))
    failures.extend(validate_schema(document, schemas()["launch_manifest"]))
    if failures:
        return tuple(failures)
    for kind, snapshot in (("resource_reservation", resource), ("independent_review", review)):
        if not strict_equal(document["attestations"][kind], snapshot.identity):
            failures.append("launch:identity:" + kind)
    if document["launch_batch_id"] != resource_doc["launch_batch_id"]:
        failures.append("launch:batch_binding")
    if document["review_subject_sha256"] != subject_sha256(review_subject(resource)):
        failures.append("launch:review_subject_binding")
    execution = document["execution"]
    expected = {"command": production_command(root), "command_sha256": command_sha256(root),
                "external_output": str(root / "production-prefreeze"), "candidate_locations": locations(root)}
    if any(not strict_equal(execution[k], v) for k, v in expected.items()):
        failures.append("launch:exact_execution_locations")
    if not _utc(review_doc["reviewer"]["completed_at_utc"]) <= _utc(document["created_at_utc"]) <= now:
        failures.append("launch:time_order")
    return tuple(failures)


def claim_boundary() -> dict:
    return {
        "v2_41_launch_validation_implemented": True, "historical_evidence_preserved": True,
        "operator_resource_reservation_frozen": False, "independent_review_frozen": False,
        "launch_manifest_frozen": False, "production_prefreeze_authorized": False,
        "production_prefreeze_started": False, "production_stream_materialized": False,
        "production_checkpoint_materialized": False, "production_runner_scale_qualified": False,
        "production_relation_replayed": False, "large_replay_started": False,
        "large_proving_run_started": False, "cap_security_qualified": False,
        "fork_security_proof_revalidated": False, "production_closed": False,
    }


# Commit-qualified historical identities; never regenerated from a working file.
HISTORICAL_BASE_COMMIT = "3885b01d2b7bccd8ae0cb5e465c4b63aa48d4442"
HISTORICAL_IDENTITIES = {'artifacts/metadata/cap_unified_tree_launch_preflight_v2_39/pq_rbbc_cap_unified_tree_launch_preflight_portable_evidence_v2_39.json': {'bytes': 6792,
                                                                                                                                       'filename': 'pq_rbbc_cap_unified_tree_launch_preflight_portable_evidence_v2_39.json',
                                                                                                                                       'sha256': 'a4d1f8e2d7f206a070a820a801ceded5edd0f0c4250498124354d9453aa3c978'},
 'artifacts/metadata/cap_unified_tree_streaming_prefreeze_v2_38/pq_rbbc_cap_unified_tree_streaming_prefreeze_portable_evidence_v2_38.json': {'bytes': 7390,
                                                                                                                                             'filename': 'pq_rbbc_cap_unified_tree_streaming_prefreeze_portable_evidence_v2_38.json',
                                                                                                                                             'sha256': '7f846858350deefa6a6d4df2dec43a852f8e6deb9c55c99e289c2062f822979e'},
 'checksums/SHA256SUMS_v2_38_UNIFIED_TREE_STREAMING_PREFREEZE.txt': {'bytes': 2129,
                                                                     'filename': 'SHA256SUMS_v2_38_UNIFIED_TREE_STREAMING_PREFREEZE.txt',
                                                                     'sha256': 'cc058952cc74ce0fa1cfbdbd539327c487dc10df167919ff05930de18574fca7'},
 'checksums/SHA256SUMS_v2_39_UNIFIED_TREE_LAUNCH_PREFLIGHT.txt': {'bytes': 2295,
                                                                  'filename': 'SHA256SUMS_v2_39_UNIFIED_TREE_LAUNCH_PREFLIGHT.txt',
                                                                  'sha256': '904c3cd38f7accd80146a97377b2083e60065e74aa632f8561ffe2f4105310e0'},
 'docs/artifacts/PQ_RBBC_v2_38_UNIFIED_TREE_STREAMING_PREFREEZE_zh-TW.md': {'bytes': 7191,
                                                                            'filename': 'PQ_RBBC_v2_38_UNIFIED_TREE_STREAMING_PREFREEZE_zh-TW.md',
                                                                            'sha256': '424c612fe1f818f245fcbab89e8f0ffd909f0a188ca9c36105847bd67fbd1d51'},
 'docs/artifacts/PQ_RBBC_v2_39_UNIFIED_TREE_LAUNCH_PREFLIGHT_zh-TW.md': {'bytes': 6804,
                                                                         'filename': 'PQ_RBBC_v2_39_UNIFIED_TREE_LAUNCH_PREFLIGHT_zh-TW.md',
                                                                         'sha256': 'fa9f12855bb8838123934053bb919f8e5feed2d20fafa268b53f928a2cb7421a'},
 'manifests/pq_rbbc_cap_unified_tree_launch_preflight_manifest_v2_39.json': {'bytes': 6462,
                                                                             'filename': 'pq_rbbc_cap_unified_tree_launch_preflight_manifest_v2_39.json',
                                                                             'sha256': 'da2e8a80c2391c218b265414648d2877d840c626b6b669ed8d85343e55f2db51'},
 'manifests/pq_rbbc_cap_unified_tree_streaming_prefreeze_manifest_v2_38.json': {'bytes': 7581,
                                                                                'filename': 'pq_rbbc_cap_unified_tree_streaming_prefreeze_manifest_v2_38.json',
                                                                                'sha256': 'b601af812865b190e76a7fe22d184f29ee2036dc907a56ad4dcf8da8fbf9a4a4'},
 'schemas/pq_rbbc_cap_unified_tree_independent_review_v2_39.schema.json': {'bytes': 3729,
                                                                           'filename': 'pq_rbbc_cap_unified_tree_independent_review_v2_39.schema.json',
                                                                           'sha256': '55a6b3a1c5e55cb5d0d6efcae05adbdebaa55c0ad800e0da62b92144dc45693d'},
 'schemas/pq_rbbc_cap_unified_tree_launch_manifest_v2_39.schema.json': {'bytes': 3696,
                                                                        'filename': 'pq_rbbc_cap_unified_tree_launch_manifest_v2_39.schema.json',
                                                                        'sha256': '207bcad1f6f09bdfe56925f2c36f6f71b0718cf2942d5bd6f5e1dbf2a627b2ca'},
 'schemas/pq_rbbc_cap_unified_tree_resource_reservation_v2_39.schema.json': {'bytes': 3679,
                                                                             'filename': 'pq_rbbc_cap_unified_tree_resource_reservation_v2_39.schema.json',
                                                                             'sha256': 'a8234b7c49118f731bb18281f402e39396005f063b49e35050072d9b7bcbee0f'},
 'src/pq_rbbc_cap_unified_tree_launch_preflight.py': {'bytes': 53578,
                                                      'filename': 'pq_rbbc_cap_unified_tree_launch_preflight.py',
                                                      'sha256': 'e19dc7846da1a42a127c79ac6e6f39b358f98edea92642abfccab41e24eb21cd'},
 'src/pq_rbbc_cap_unified_tree_launch_preflight_evidence.py': {'bytes': 12026,
                                                               'filename': 'pq_rbbc_cap_unified_tree_launch_preflight_evidence.py',
                                                               'sha256': '56c349487a387d904480c8041848a3eb4ab6140af026693e990c7b2d3667689a'},
 'src/pq_rbbc_cap_unified_tree_streaming_prefreeze.py': {'bytes': 51495,
                                                         'filename': 'pq_rbbc_cap_unified_tree_streaming_prefreeze.py',
                                                         'sha256': '027eb529dea4e2868989a5d76073085724f1232e84695a7344daf3efc6043bb0'},
 'src/pq_rbbc_cap_unified_tree_streaming_prefreeze_evidence.py': {'bytes': 15345,
                                                                  'filename': 'pq_rbbc_cap_unified_tree_streaming_prefreeze_evidence.py',
                                                                  'sha256': '6453663dddfb3c1cca7392dd88405848ea0e80f332f801dd2502a582006cadea'},
 'tests/test_pq_rbbc_cap_unified_tree_launch_preflight.py': {'bytes': 9250,
                                                             'filename': 'test_pq_rbbc_cap_unified_tree_launch_preflight.py',
                                                             'sha256': 'ef0c05b8c46fe1ac5b12f1ef8f6a403023405056c400a831151fac6472dbfddd'},
 'tests/test_pq_rbbc_cap_unified_tree_launch_preflight_evidence.py': {'bytes': 3164,
                                                                      'filename': 'test_pq_rbbc_cap_unified_tree_launch_preflight_evidence.py',
                                                                      'sha256': 'd2cc0394f16ce451b9ea112dd18a726d63a08e37c643427f237028cc7796d3d1'},
 'tests/test_pq_rbbc_cap_unified_tree_streaming_prefreeze.py': {'bytes': 9314,
                                                                'filename': 'test_pq_rbbc_cap_unified_tree_streaming_prefreeze.py',
                                                                'sha256': 'bc2097e7d128d07c78a28f9aa182a83da0051d504d2e9793fd3035372518f33e'},
 'tests/test_pq_rbbc_cap_unified_tree_streaming_prefreeze_evidence.py': {'bytes': 4085,
                                                                         'filename': 'test_pq_rbbc_cap_unified_tree_streaming_prefreeze_evidence.py',
                                                                         'sha256': '0a40e2acf2f54622bcc5b26267595116e32f197d206fdba876c39c69903ae5b5'}}


def build_manifest() -> dict:
    return {
        "format": FORMAT, "implementation_version": IMPLEMENTATION_VERSION, "relation_id": RELATION_ID,
        "historical_base_commit": HISTORICAL_BASE_COMMIT,
        "historical_identities": HISTORICAL_IDENTITIES,
        "transition": {"predecessor_validation_version": "2.39", "successor_validation_version": "2.41",
                       "historical_validator_for_reconstruction_only": True,
                       "v2_39_freeze_ready_is_not_v2_41_acceptance": True,
                       "automatic_candidate_upgrade_permitted": False},
        "sealed_predecessor": V2_38_PORTABLE_IDENTITY,
        "schemas": {k: {"filename": p.name, "bytes": len(canonical_json(schemas()[k])),
                         "sha256": hashlib.sha256(canonical_json(schemas()[k])).hexdigest()}
                    for k, p in SCHEMA_PATHS.items()},
        "io_policy": {"max_json_bytes": MAX_JSON_BYTES, "single_open_single_read_per_candidate": True,
                      "canonical_raw_bytes_required": True, "symlinks_forbidden": True,
                      "artifact_root_selected_by_trusted_caller_only": True,
                      "all_git_worktree_ancestors_forbidden": True,
                      "rebind_requires_new_reservation_review_and_launch": True,
                      "output_publication": "fsync then atomic exclusive hard link"},
        "time_policy": {"clock": "trusted caller UTC clock; CLI uses system UTC; no candidate now",
                        "order": "approved <= start < expiry; approved <= review <= created <= now; start <= now < expiry",
                        "prelaunch_revalidation_required": True,
                        "future_window_freeze_ready": False},
        "default_candidate_locations": locations(EXTERNAL_ROOT),
        "production_command": {"command": production_command(EXTERNAL_ROOT), "sha256": command_sha256(EXTERNAL_ROOT),
                               "executable_now": False, "authorized_now": False},
        "large_replay_command": None, "large_proving_command": None,
        "claim_boundary": claim_boundary(),
    }


def contract_snapshots(manifest_path=MANIFEST_PATH, predecessor=V2_38_PORTABLE_PATH):
    """Capture each tracked contract once, then compare only those snapshots."""
    expected = {ROOT / path: ident for path, ident in HISTORICAL_IDENTITIES.items()}
    generated = {MANIFEST_PATH: build_manifest(), manifest_path: build_manifest(),
                 **{SCHEMA_PATHS[k]: v for k, v in schemas().items()}}
    failures, snapshots = [], {}
    for path in dict.fromkeys([*expected, *generated, predecessor]):
        try:
            snapshots[path] = read_snapshot(path)
        except (OSError, ValueError) as error:
            failures.append(path.name + ":" + str(error))
    for path, ident in expected.items():
        if path in snapshots and not strict_equal(snapshots[path].identity, ident):
            failures.append(path.name + ":historical_identity")
    for path, document in generated.items():
        if path in snapshots and snapshots[path].raw != canonical_json(document):
            failures.append(path.name + ":tracked_contract")
    if predecessor not in snapshots or not strict_equal(snapshots[predecessor].identity, V2_38_PORTABLE_IDENTITY):
        failures.append("v2_38:predecessor_identity")
    return tuple(failures), snapshots


def validate_tracked_contracts(manifest_path=MANIFEST_PATH, predecessor=V2_38_PORTABLE_PATH):
    return contract_snapshots(manifest_path, predecessor)[0]


@dataclass(frozen=True)
class CandidateSet:
    root: Path
    resource: Snapshot
    review: Snapshot
    launch: Snapshot


def _capture(store: ArtifactRoot, kind: str, path: Path | None):
    if path is None:
        raise ValidationError("not_provided")
    if exact_path(path) != store.root / FILENAMES[kind]:
        raise ValidationError("candidate exact command input location mismatch")
    snapshot = store.read(path)
    snapshot.document()
    return snapshot


def _evaluate(manifest_path, predecessor, paths, store, clock):
    contract_failures, contracts = contract_snapshots(manifest_path, predecessor)
    statuses, snapshots = {}, {}
    for kind, path in zip(KINDS, paths):
        status = {"provided": path is not None, "identity_frozen": False,
                  "candidate_acceptable_for_freeze": False, "failures": []}
        statuses[kind] = status
        try:
            snap = _capture(store, kind, path)
            snapshots[kind] = snap
            status.update({"identity": snap.identity, "location": str(snap.location)})
        except (OSError, ValueError) as error:
            status["failures"].append(str(error))
    resource, review, launch = (snapshots.get(k) for k in KINDS)
    # Sampling after I/O prevents a slow read from using a window that expired
    # while the candidates were being captured.
    now = check_now(clock())
    validators = (
        lambda: validate_resource(resource.document(), store.root, now),
        lambda: validate_review(review.document(), resource, store.root, now) if resource else ("resource_unavailable",),
        lambda: validate_launch(launch.document(), resource, review, store.root, now) if resource and review else ("attestations_unavailable",),
    )
    for kind, validator in zip(KINDS, validators):
        if kind in snapshots:
            try:
                statuses[kind]["failures"].extend(validator())
            except (OSError, ValueError) as error:
                statuses[kind]["failures"].append(str(error))
        statuses[kind]["candidate_acceptable_for_freeze"] = not statuses[kind]["failures"]
    contracts_ok = not contract_failures
    author_ready = contracts_ok and all(statuses[k]["candidate_acceptable_for_freeze"] for k in KINDS[:2])
    ready = author_ready and statuses["launch_manifest"]["candidate_acceptable_for_freeze"]
    report = {
        "format": REPORT_FORMAT, "implementation_version": IMPLEMENTATION_VERSION, "relation_id": RELATION_ID,
        "validated_at_utc": now.isoformat(),
        "manifest": contracts[manifest_path].identity if manifest_path in contracts else None,
        "tracked_contracts": {"verified": contracts_ok, "failures": list(contract_failures)},
        "external_candidates": statuses,
        "result": {"safe_to_run_read_only_preflight": contracts_ok,
                   "safe_to_author_launch_manifest_candidate": author_ready,
                   "safe_to_freeze_launch_identity_set": ready,
                   "safe_to_start_production_prefreeze": False, "safe_to_start_large_replay": False,
                   "safe_to_start_large_proving_run": False},
        "claim_boundary": claim_boundary(),
        "blockers": ["exact external identities are not frozen", "signer authenticity and independence require external verification",
                     "production stream/checkpoint and scale qualification remain absent", "execution authorization is outside v2.41"],
    }
    captured = CandidateSet(store.root, resource, review, launch) if ready else None
    return report, captured, snapshots


def build_preflight(manifest_path=MANIFEST_PATH, predecessor=V2_38_PORTABLE_PATH,
                    resource_path=None, review_path=None, launch_path=None, *,
                    artifact_root=EXTERNAL_ROOT, clock: Clock = trusted_now):
    report, _, _ = _evaluate(manifest_path, predecessor, (resource_path, review_path, launch_path),
                             ArtifactRoot(artifact_root), clock)
    return report


def build_launch_manifest(resource_path: Path, review_path: Path, launch_id: str, created_at_utc: str, *,
                          artifact_root=EXTERNAL_ROOT, predecessor=V2_38_PORTABLE_PATH,
                          manifest_path=MANIFEST_PATH, clock: Clock = trusted_now) -> dict:
    report, _, snapshots = _evaluate(manifest_path, predecessor, (resource_path, review_path, None),
                                     ArtifactRoot(artifact_root), clock)
    if report["result"]["safe_to_author_launch_manifest_candidate"] is not True:
        raise ValidationError("authoring requires exact tracked contracts, predecessor and attestations: " + str(report))
    resource, review = (snapshots[k] for k in KINDS[:2])
    document = _successor(historical.launch_template())
    document.update({"launch_id": launch_id, "created_at_utc": created_at_utc,
                     "launch_batch_id": resource.document()["launch_batch_id"],
                     "review_subject_sha256": subject_sha256(review_subject(resource)),
                     "attestations": {k: snapshots[k].identity for k in KINDS[:2]}})
    document["execution"].update({"command": production_command(artifact_root), "command_sha256": command_sha256(artifact_root),
                                  "external_output": str(artifact_root / "production-prefreeze"),
                                  "candidate_locations": locations(artifact_root)})
    document["authorization_boundary"]["production_prefreeze_only"] = True
    failures = validate_launch(document, resource, review, artifact_root, clock())
    if failures:
        raise ValidationError("launch candidate rejected: " + str(failures))
    return document


def revalidate_before_launch(candidates: CandidateSet, *, clock: Clock = trusted_now):
    """Revalidate immutable inputs at a fresh trusted time, never a prior report.

    A future executor must consume these same snapshots, not reopen their paths.
    This is only a validation primitive, not an authorization or executor.
    """
    failures = validate_tracked_contracts()
    failures += validate_launch(candidates.launch.document(), candidates.resource, candidates.review,
                                candidates.root, clock())
    for kind, snap in zip(KINDS, (candidates.resource, candidates.review, candidates.launch)):
        if snap.location != candidates.root / FILENAMES[kind]:
            failures += ("prelaunch:location_binding",)
    if failures:
        raise ValidationError("prelaunch revalidation rejected: " + str(failures))
    return candidates


def reject_production(paths, output: Path, *, artifact_root=EXTERNAL_ROOT,
                      predecessor=V2_38_PORTABLE_PATH, clock: Clock = trusted_now):
    if exact_path(output) != artifact_root / "production-prefreeze":
        raise ValidationError("production output location mismatch")
    _, captured, _ = _evaluate(MANIFEST_PATH, predecessor, paths, ArtifactRoot(artifact_root), clock)
    if captured is not None:
        revalidate_before_launch(captured, clock=clock)
    raise ValidationError("v2.41 does not authorize production-prefreeze")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("launch-preflight", "author-launch-manifest", "production-prefreeze"), required=True)
    parser.add_argument("--trusted-artifact-root", type=Path, default=EXTERNAL_ROOT)
    parser.add_argument("--v2-38-portable", type=Path, default=V2_38_PORTABLE_PATH)
    for kind in KINDS:
        parser.add_argument("--" + kind.replace("_", "-"), type=Path)
    parser.add_argument("--launch-id")
    parser.add_argument("--created-at-utc")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fresh-output", action="store_true")
    args = parser.parse_args()
    if not args.fresh_output:
        raise ValidationError("--fresh-output required")
    # Relative repository contracts are resolved lexically, never through a symlink.
    predecessor = args.v2_38_portable
    if not predecessor.is_absolute():
        predecessor = ROOT / predecessor
    paths = tuple(getattr(args, k) for k in KINDS)
    if args.phase == "production-prefreeze":
        reject_production(paths, args.output, artifact_root=args.trusted_artifact_root, predecessor=predecessor)
    if args.phase == "author-launch-manifest":
        if args.output != args.trusted_artifact_root / FILENAMES["launch_manifest"]:
            raise ValidationError("launch output must equal exact command input location")
        document = build_launch_manifest(paths[0], paths[1], args.launch_id or "", args.created_at_utc or "",
                                         artifact_root=args.trusted_artifact_root, predecessor=predecessor)
    else:
        document = build_preflight(MANIFEST_PATH, predecessor, *paths, artifact_root=args.trusted_artifact_root)
    ArtifactRoot(args.trusted_artifact_root).write(args.output, document)
    print(canonical_json({"output": str(args.output), "result": document.get("result", {}),
                          "safe_to_start_production_prefreeze": False}).decode(), end="")


if __name__ == "__main__":
    main()
