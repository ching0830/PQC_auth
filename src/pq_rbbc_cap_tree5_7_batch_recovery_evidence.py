#!/usr/bin/env python3
"""Seal the completed PQ-RBBC tree-5 through tree-7 batch replay, v2.25."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_global_tail_recovery_evidence as global_tail_recovery
import pq_rbbc_cap_planned_tree_producer as planned
import pq_rbbc_cap_tree4_planned_recovery_evidence as tree4_evidence
from pq_rbbc_anemoi_f193 import FIELD_DEGREE, FIELD_ELEMENT_BYTES
from pq_rbbc_cap_shard_assignment import (
    ASSIGNMENT_FORMAT,
    ASSIGNMENT_HEADER_BYTES,
    AssignmentArchiveMetadata,
    AssignmentArchiveReader,
)


IMPLEMENTATION_VERSION = "2.25"
FROZEN_RUNNER_IMPLEMENTATION_VERSION = "2.25"
EVIDENCE_FORMAT = "PQRBBC-CAP-TREE5-7-BATCH-RECOVERY-EVIDENCE-1"
RELATION_ID = "pq-rbbc/cap/production-tree5-7-batch-recovery-evidence/v1"
MANIFEST_NAME = "pq_rbbc_cap_tree5_7_batch_recovery_evidence_v2_25.json"

FROZEN_EVIDENCE_SHA256 = "0041ea819434e0099d419757fa217fcfa30b810ef391b4a4603d8aee7ad06c72"
FROZEN_ROWS = 25_666_386
FROZEN_WIRES = 19_478_436
FROZEN_STREAM_BYTES = 8_961_160_824
FROZEN_ARCHIVE_BYTES = 486_961_028
FROZEN_BODY_BYTES = 486_960_900
FROZEN_STANDARD_PROBES = 6
FROZEN_POINT_PROBES = 3

FROZEN_TREES: dict[int, dict[str, object]] = {
    5: {
        "contract_sha256": "49694ee2229c0a99731510b3b9242c7863e2663a0684061fa821132266d27e58",
        "replayed_manifest_sha256": "8f032ced1c11c2acd3554240ab4d6e0e061b0c04fa9b985eb20fc6184a41478f",
        "archive_sha256": "e8717997e1e3d85c5dbbb59602924eeafb2ae7a643433794a8cbfb9966243a18",
        "body_sha256": "7256cd78339cb81c5532841eee1af6df588ddef1b6ee41c5b950345b86dc1fd2",
        "stream_sha256": "34683185ba262e73397532c944b6f70b23ea59a55786535e0cec8473c58f0375",
        "tree_component_sha256": "a3d74bcb6750d3fe8b4e483171da8cdd20074c8676c80fecb9fa4b400f484779",
        "first_wire": 0,
        "last_wire": 0,
        "output_matches": (
            {"port_id": "tree[5].leaf-commitments", "planned_producer_wire_start": 195_148_365, "consumer_wire_start": 5_570_441, "bit_length": 790_528, "value_sha256": "1e86c4aec4589bec77ce02556d9cbc5f335c5d1c36eb9658f0c2a4bd42dcb290", "exact_value_match": True},
            {"port_id": "tree[5].p-plain", "planned_producer_wire_start": 195_938_893, "consumer_wire_start": 6_360_969, "bit_length": 2_048, "value_sha256": "67919aced3e0ddb859e7fcbe481e2183e225c3fe5cd22b6af36693565763b771", "exact_value_match": True},
            {"port_id": "tree[5].mhat-plain", "planned_producer_wire_start": 195_940_941, "consumer_wire_start": 6_363_017, "bit_length": 386, "value_sha256": "d422424fe8ae282c4cafd970c256ed8aae3ef877db42e729d39019bcb25e4ddc", "exact_value_match": True},
            {"port_id": "tree[5].xi-masks", "planned_producer_wire_start": 196_011_369, "consumer_wire_start": 6_363_403, "bit_length": 4_632, "value_sha256": "4c6968af73877708ec1e183791668391dbd32cb1a7549235dd989c63e30a4a59", "exact_value_match": True},
        ),
    },
    6: {
        "contract_sha256": "119d4e6dbe9d6003eac74df3299bfd5e52f6c764c8b3d9bb6cee59b983698028",
        "replayed_manifest_sha256": "0061aaaa11096c4c49af41beb0a9688b9ea4b17a29518212c53e94be7df4553e",
        "archive_sha256": "e112686118690036ffef126bccbbc0fbe69c973e624d86301683aea09dec3abe",
        "body_sha256": "bb501116dc87c0a06c82f99db73806e545ed82b1498522451ffbd0f9c8bf77b3",
        "stream_sha256": "0a08cb7f018135d99dfad6b69712659f71a220424e89987daaea9c74fb6fea25",
        "tree_component_sha256": "520928a648368a71d6ce8a82889ca164d15d14b9a62cb3e8505023bfc852b0c6",
        "first_wire": 0,
        "last_wire": 1,
        "output_matches": (
            {"port_id": "tree[6].leaf-commitments", "planned_producer_wire_start": 214_626_801, "consumer_wire_start": 6_368_035, "bit_length": 790_528, "value_sha256": "0e9498133b14ef04be0133f53b9fc0dff246a705a7fd6e70f886fd45823386cf", "exact_value_match": True},
            {"port_id": "tree[6].p-plain", "planned_producer_wire_start": 215_417_329, "consumer_wire_start": 7_158_563, "bit_length": 2_048, "value_sha256": "3cd0e42090f76778d1b98f562e0ce51f3e3ed9a892ae2ef0cc67213d74445b03", "exact_value_match": True},
            {"port_id": "tree[6].mhat-plain", "planned_producer_wire_start": 215_419_377, "consumer_wire_start": 7_160_611, "bit_length": 386, "value_sha256": "67114bcf0d76f6b44bae46c34898d2a1cafeacb15928b27325708b81662adf2e", "exact_value_match": True},
            {"port_id": "tree[6].xi-masks", "planned_producer_wire_start": 215_489_805, "consumer_wire_start": 7_160_997, "bit_length": 4_632, "value_sha256": "46ba2ff98aa11174b5ed499095f6f601c705bce724acda97d874e9597e6d2d9d", "exact_value_match": True},
        ),
    },
    7: {
        "contract_sha256": "71e8faf784f9c489ea82b09e53799dc7ff205a035baac7e71ec9f0068154b396",
        "replayed_manifest_sha256": "be99ea2986c7c65269d6151c5c8280266110102024ca76e2a88f5579be48ab81",
        "archive_sha256": "3c6670f17ef484c83781d4453f976b68a6159072d5d8cfff418c0afbacf3f6db",
        "body_sha256": "1b3868707b3f8eee77b76d94778d26c68ffd370b48dfe2c6b05cfa1409507903",
        "stream_sha256": "f34bb645f31c8dee51f0a8706c595df07ed465136cfeaec5a20a85cf54328992",
        "tree_component_sha256": "88449591a1a221ebda29235b2e2451b893b33605a1468fce8bbc7dce08705c2b",
        "first_wire": 0,
        "last_wire": 1,
        "output_matches": (
            {"port_id": "tree[7].leaf-commitments", "planned_producer_wire_start": 234_105_237, "consumer_wire_start": 7_165_629, "bit_length": 790_528, "value_sha256": "77720ba089028948e69605e1b9d10ab61e5c0e6854983817d9a6968ddabc80aa", "exact_value_match": True},
            {"port_id": "tree[7].p-plain", "planned_producer_wire_start": 234_895_765, "consumer_wire_start": 7_956_157, "bit_length": 2_048, "value_sha256": "5a353e5b882f4f8544299746197d79f86f55b5ced257bfe10cbfb17a3e595ee3", "exact_value_match": True},
            {"port_id": "tree[7].mhat-plain", "planned_producer_wire_start": 234_897_813, "consumer_wire_start": 7_958_205, "bit_length": 386, "value_sha256": "a6d2d65068f387847cee9568c8bc7f20ca5b0769bc1aad1e9eaebe25160dd1ec", "exact_value_match": True},
            {"port_id": "tree[7].xi-masks", "planned_producer_wire_start": 234_968_241, "consumer_wire_start": 7_958_591, "bit_length": 4_632, "value_sha256": "6a600cfde7ea6c75c96bd47f2d35dba8033f75f2317b3692edb942905db16bff", "exact_value_match": True},
        ),
    },
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(document: Mapping[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def _json_contract(tree_index: int) -> dict[str, object]:
    return json.loads(json.dumps(asdict(planned.load_contract(tree_index))))


def _tree_document(tree_index: int) -> dict[str, object]:
    frozen = FROZEN_TREES[tree_index]
    contract = _json_contract(tree_index)
    return {
        "runner_implementation_version": FROZEN_RUNNER_IMPLEMENTATION_VERSION,
        "runner_relation_id": planned.RELATION_ID,
        "producer_relation_id": contract["producer_relation_id"],
        "contract_sha256": frozen["contract_sha256"],
        "namespace_plan_sha256": contract["namespace_plan_sha256"],
        "tree_index": tree_index,
        "planned_local_wire_start": contract["planned_local_wire_start"],
        "planned_max_wire_id": contract["planned_max_wire_id"],
        "planned_output_wire_starts": contract["planned_output_wire_starts"],
        "global_point_wire_starts": contract["global_point_wire_starts"],
        "rows": FROZEN_ROWS,
        "wires": FROZEN_WIRES,
        "row_stream_bytes": FROZEN_STREAM_BYTES,
        "row_stream_sha256": frozen["stream_sha256"],
        "tree_component_sha256": frozen["tree_component_sha256"],
        "archive_bytes": FROZEN_ARCHIVE_BYTES,
        "archive_sha256": frozen["archive_sha256"],
        "body_bytes": FROZEN_BODY_BYTES,
        "body_sha256": frozen["body_sha256"],
        "first_wire": frozen["first_wire"],
        "last_wire": frozen["last_wire"],
        "output_matches": [dict(item) for item in frozen["output_matches"]],
        "external_assertions": 0,
        "replay_failures": 0,
        "stale_witness_probes": FROZEN_STANDARD_PROBES,
        "point_mutation_probes": FROZEN_POINT_PROBES,
        "all_mutation_probes_rejected": True,
    }


def build_frozen_evidence_document() -> dict[str, object]:
    return {
        "format": EVIDENCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "source_global_tail_recovery": {
            "implementation_version": global_tail_recovery.IMPLEMENTATION_VERSION,
            "relation_id": global_tail_recovery.RELATION_ID,
            "evidence_sha256": global_tail_recovery.FROZEN_EVIDENCE_SHA256,
            "archive_sha256": global_tail_recovery.FROZEN_ARCHIVE_SHA256,
        },
        "prior_tree4_recovery": {
            "implementation_version": tree4_evidence.IMPLEMENTATION_VERSION,
            "relation_id": tree4_evidence.RELATION_ID,
            "evidence_sha256": tree4_evidence.FROZEN_EVIDENCE_SHA256,
            "archive_sha256": tree4_evidence.FROZEN_ARCHIVE_SHA256,
        },
        "production_tree_batch": [_tree_document(i) for i in (5, 6, 7)],
        "replayed_manifests": [
            {"tree_index": i, "sha256": FROZEN_TREES[i]["replayed_manifest_sha256"], "status": "complete", "contract_validation_failures": 0, "configuration_mutation_probes": 10, "configuration_mutations_rejected": True}
            for i in (5, 6, 7)
        ],
        "artifact_policy": {
            "large_artifacts_tracked_in_git": False,
            "portable_evidence_contains_absolute_paths": False,
            "archive_format_is_non_executable_binary": True,
            "trusted_pickle_cache_tracked_in_git": False,
        },
        "claim_boundary": {
            "production_execution_cache_regenerated": True,
            "production_composition_document_revalidated": True,
            "production_global_tail_archive_regenerated": True,
            "production_global_tail_native_closed": True,
            "production_tree2_rebased_assignment_materialized": True,
            "production_tree2_rebased_full_replay_closed": True,
            "production_tree1_planned_assignment_materialized": True,
            "production_tree1_planned_full_replay_closed": True,
            "production_tree3_planned_assignment_materialized": True,
            "production_tree3_planned_full_replay_closed": True,
            "production_tree4_planned_assignment_materialized": True,
            "production_tree4_planned_full_replay_closed": True,
            **{f"production_tree{i}_planned_assignment_materialized": True for i in (5, 6, 7)},
            **{f"production_tree{i}_planned_full_replay_closed": True for i in (5, 6, 7)},
            "materialized_planned_tree_indices": list(range(8)),
            "materialized_planned_tree_count": 8,
            "remaining_planned_tree_producers_materialized": False,
            "all_72_output_relocations_closed": False,
            "complete_18_tree_assignment_replayed": False,
            "cross_segment_wire_identity_closed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }


def validate_evidence_document(document: Mapping[str, object]) -> tuple[str, ...]:
    expected = build_frozen_evidence_document()
    return tuple(f"{key}_identity" for key in expected if document.get(key) != expected[key])


def verify_frozen_evidence(path: Path) -> tuple[str, ...]:
    encoded = path.read_bytes()
    failures: list[str] = []
    if FROZEN_EVIDENCE_SHA256 != "TODO" and hashlib.sha256(encoded).hexdigest() != FROZEN_EVIDENCE_SHA256:
        failures.append("frozen_evidence_sha256")
    try:
        document = json.loads(encoded)
    except json.JSONDecodeError:
        return tuple(failures + ["invalid_json"])
    if not isinstance(document, dict):
        return tuple(failures + ["evidence_root"])
    failures.extend(validate_evidence_document(document))
    return tuple(dict.fromkeys(failures))


def _expected_runner_claims(tree_index: int) -> dict[str, object]:
    claims: dict[str, object] = {
        "planned_tree_runner_preflight_closed": True,
        "planned_offset_reduced_fixture_replayed": True,
        "target_tree_index": tree_index,
        "production_tree1_planned_assignment_materialized": False,
        "production_tree1_planned_full_replay_closed": False,
        "production_tree3_planned_assignment_materialized": False,
        "production_tree3_planned_full_replay_closed": False,
        "production_tree4_planned_assignment_materialized": False,
        "production_tree4_planned_full_replay_closed": False,
    }
    for i in (5, 6, 7):
        claims[f"production_tree{i}_planned_assignment_materialized"] = i == tree_index
        claims[f"production_tree{i}_planned_full_replay_closed"] = i == tree_index
    claims.update({
        "remaining_planned_tree_producers_materialized": False,
        "all_72_output_relocations_closed": False,
        "complete_18_tree_assignment_replayed": False,
        "cross_segment_wire_identity_closed": False,
        "parent_cap_to_h_rbbc_join_closed": False,
        "fork_security_proof_revalidated": False,
        "production_closed": False,
    })
    return claims


def build_evidence_from_artifacts(batch_root: Path, global_manifest_path: Path) -> dict[str, object]:
    global_document = json.loads(global_manifest_path.read_text(encoding="utf-8"))
    if not isinstance(global_document, dict):
        raise ValueError("global manifest must be a JSON object")
    consumers = {str(item.get("port_id")): item for item in global_document.get("ports", []) if isinstance(item, dict)}
    failures: list[str] = []
    for tree_index in (5, 6, 7):
        frozen = FROZEN_TREES[tree_index]
        root = batch_root / f"production_tree{tree_index}_v2_25_batch_planned"
        archive_path = root / f"pq_rbbc_production_tree_{tree_index}_producer_v2_25_batch_planned.f193assign"
        manifest_path = root / f"pq_rbbc_cap_planned_tree{tree_index}_replayed_manifest_v2_25.json"
        replayed = json.loads(manifest_path.read_text(encoding="utf-8"))
        replay = replayed.get("production_replay")
        checks = {
            "manifest_sha256": _sha256_file(manifest_path) == frozen["replayed_manifest_sha256"],
            "implementation_version": replayed.get("implementation_version") == FROZEN_RUNNER_IMPLEMENTATION_VERSION,
            "contract": replayed.get("contract") == _json_contract(tree_index),
            "contract_sha256": replayed.get("contract_sha256") == frozen["contract_sha256"],
            "contract_validation_failures": replayed.get("contract_validation_failures") == [],
            "configuration_mutations": isinstance(replayed.get("configuration_mutation_probes"), list) and len(replayed["configuration_mutation_probes"]) == 10 and all(item.get("rejected") is True for item in replayed["configuration_mutation_probes"]),
            "runner_claims": replayed.get("claim_boundary") == _expected_runner_claims(tree_index),
            "replay": isinstance(replay, dict) and all((replay.get(key) == value) for key, value in {
                "status": "complete", "production_rows_replayed_at_planned_offset": FROZEN_ROWS,
                "planned_row_stream_bytes": FROZEN_STREAM_BYTES, "planned_row_stream_sha256": frozen["stream_sha256"],
                "planned_assignment_bytes": FROZEN_ARCHIVE_BYTES, "planned_assignment_sha256": frozen["archive_sha256"],
                "planned_assignment_body_sha256": frozen["body_sha256"], "tree_component_sha256": frozen["tree_component_sha256"],
                "output_matches": [dict(item) for item in frozen["output_matches"]], "verification_failures": 0,
                "external_assertions": 0, "stale_witness_probes": FROZEN_STANDARD_PROBES, "point_mutation_probes": FROZEN_POINT_PROBES,
                "generation_seconds": 0.0, "resumed_assignment_prefix_wires_this_run": 0, "resumed_execution_cache_this_run": False,
            }.items()),
        }
        for output in frozen["output_matches"]:
            consumer = consumers.get(str(output["port_id"]))
            checks[f"output:{output['port_id']}"] = isinstance(consumer, dict) and all(consumer.get(key) == output[key] for key in ("consumer_wire_start", "bit_length", "value_sha256"))
        expected_archive = AssignmentArchiveMetadata(ASSIGNMENT_FORMAT, ASSIGNMENT_HEADER_BYTES, FIELD_DEGREE, FIELD_ELEMENT_BYTES, FROZEN_WIRES, FROZEN_BODY_BYTES, str(frozen["body_sha256"]), str(frozen["stream_sha256"]), FROZEN_ARCHIVE_BYTES, str(frozen["archive_sha256"]))
        with AssignmentArchiveReader(archive_path, expected=expected_archive, verify_body=True) as archive:
            checks.update({"archive_sha256": _sha256_file(archive_path) == frozen["archive_sha256"], "first_wire": archive[1] == frozen["first_wire"], "last_wire": archive[archive.wires] == frozen["last_wire"]})
        failures.extend(f"tree{tree_index}:{name}" for name, accepted in checks.items() if not accepted)
    if _sha256_file(global_manifest_path) != global_tail_recovery.FROZEN_HISTORICAL_MANIFEST_SHA256:
        failures.append("global_manifest_sha256")
    if failures:
        raise ValueError("tree-5 through tree-7 batch evidence rejected: " + ",".join(failures))
    return build_frozen_evidence_document()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--batch-root", type=Path)
    parser.add_argument("--global-manifest", type=Path)
    parser.add_argument("--verify-frozen", type=Path)
    args = parser.parse_args()
    if args.verify_frozen is not None:
        failures = verify_frozen_evidence(args.verify_frozen)
        if failures:
            raise SystemExit("frozen tree-5 through tree-7 evidence rejected: " + ",".join(failures))
        print("frozen production tree-5 through tree-7 batch evidence accepted")
        return
    if not all((args.manifest, args.batch_root, args.global_manifest)):
        parser.error("--manifest, --batch-root, and --global-manifest are required")
    document = build_evidence_from_artifacts(args.batch_root, args.global_manifest)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_bytes(canonical_json(document))
    print(hashlib.sha256(args.manifest.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
