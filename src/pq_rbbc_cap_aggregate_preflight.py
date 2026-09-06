#!/usr/bin/env python3
"""Fail-closed, read-only preflight for the PQ-RBBC v2.28 aggregate replay."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


IMPLEMENTATION_VERSION = "2.28"
FORMAT = "PQRBBC-CAP-AGGREGATE-PREFLIGHT-1"
RELATION_ID = "pq-rbbc/cap/production-aggregate-preflight/v1"
MANIFEST_NAME = "pq_rbbc_cap_aggregate_preflight_manifest_v2_28.json"
AGGREGATE_RUNNER = "src/pq_rbbc_cap_aggregate_replay.py"
AGGREGATE_RELATION_ID = "pq-rbbc/cap/production-aggregate-replay/v1"
AGGREGATE_RUNNER_SHA256 = "8b7e28ce1afa9040360bf40b75b5a713b14c122626a7c8e623b502a9efac468b"
NAMESPACE_BYTES = 46_870
NAMESPACE_SHA256 = "1429903c9f94c4fd52902d7946eeb34dd580dce39f390b6c8c94f7e463ef110d"
NAMESPACE_PLAN_SHA256 = "810f9feb69df61dd9672d90fe74fcec54c3b28bd126013981aeceb1e9e156c4f"
PRIOR_EVIDENCE_BYTES = 13_641
PRIOR_EVIDENCE_SHA256 = "718dad0fa9c6291e7b4f0c1848121935bab000da485c011dd539f9d377e8cbde"
GLOBAL_ARCHIVE = (1_004_865_028, "946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1")
INCREMENTAL_BR1CS = (49_227_687, "77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799")
TREE_ARCHIVES = {
    0: (973_845_878, "213fa3c90b62db64436ec8e7dd7ee5a6e0ec6b546ae4fa02b3cbfb50fdf502db"),
    1: (973_845_878, "ab75aca6037e47fe38a1364d2c66f90d1a3856da901423b398fa2d8812fa609f"),
    2: (486_961_028, "2d9932cd09848d70fece5d047206f580ed6efe1e7335ac8ff865947e0662d933"),
    3: (486_961_028, "315e83340d10331188d27a99a82de6f1262e36468f1b6f8c6ef97283d83fc02b"),
    4: (486_961_028, "cd2430637f8ca07356727cb4349ca02368f2268f865092c71f3049140bacf52d"),
    5: (486_961_028, "e8717997e1e3d85c5dbbb59602924eeafb2ae7a643433794a8cbfb9966243a18"),
    6: (486_961_028, "e112686118690036ffef126bccbbc0fbe69c973e624d86301683aea09dec3abe"),
    7: (486_961_028, "3c6670f17ef484c83781d4453f976b68a6159072d5d8cfff418c0afbacf3f6db"),
    8: (486_961_028, "bf3c1f6ef1fa34b3d5cb9e11d85e65b33a3dbe80c926cf2cd86be291d19c884c"),
    9: (486_961_028, "6233e0639bfd09b93bfb1967f5a696fad09eadc7ca5e4f2c9df4fc804a015f19"),
    10: (486_961_028, "23ad60862f387387aba139a8465891f7ada0fe4da5be8a318177217094c39bd8"),
    11: (486_961_028, "14be7745a0fe479bbc31b6ee4599ed9ad63a3d6ae108cf73ca885fc7e63c423d"),
    12: (486_961_028, "82d30f21cefbe7ac8add69da068796c589b92896882d2cb8f4eb57c859dfc4cd"),
    13: (486_961_028, "820eeffe222047148a40b7ffe223ab27c166910405f797d9bbc34efad17d27bd"),
    14: (486_961_028, "4302004fe8e1eb03f67f5a1777b7b3b12d975c55ab97c9a3ab532e71fc3ddf5a"),
    15: (486_961_028, "a0165c3398daa1f2d63b84c8de4d9418d3630a3c6ebc08a828a65bebc0c6ccc9"),
    16: (486_961_028, "4bde0cacd62bde6f6b8ed22236f42ad62c8dc7584edb4c67038ef09a6b6f2d11"),
    17: (486_961_028, "9679ff3b93336ad21394725fcf5a89256663d5b97ca8dd3c59f3e5898beff733"),
}
ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(document: dict[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def build_frozen_manifest() -> dict[str, object]:
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "namespace": {
            "manifest_bytes": NAMESPACE_BYTES,
            "manifest_sha256": NAMESPACE_SHA256,
            "plan_sha256": NAMESPACE_PLAN_SHA256,
            "tree_order": list(range(18)),
            "planned_composition_rows": 586_057_567,
            "total_producer_rows": 513_312_336,
            "total_output_relocation_rows": 15_938_520,
            "max_wire_id": 429_757_232,
        },
        "external_requirements": {
            "prior_tree11_17_evidence": {
                "bytes": PRIOR_EVIDENCE_BYTES,
                "sha256": PRIOR_EVIDENCE_SHA256,
            },
            "global_tail_assignment": {"bytes": GLOBAL_ARCHIVE[0], "sha256": GLOBAL_ARCHIVE[1]},
            "incremental_br1cs": {"bytes": INCREMENTAL_BR1CS[0], "sha256": INCREMENTAL_BR1CS[1]},
            "tree_assignments": [
                {"tree_index": i, "bytes": TREE_ARCHIVES[i][0], "sha256": TREE_ARCHIVES[i][1]}
                for i in range(18)
            ],
            "total_tree_assignment_bytes": sum(item[0] for item in TREE_ARCHIVES.values()),
            "total_assignment_bytes_with_global_tail": sum(item[0] for item in TREE_ARCHIVES.values()) + GLOBAL_ARCHIVE[0],
            "downloaded_pickle_accepted": False,
        },
        "runner_requirement": {
            "path": AGGREGATE_RUNNER,
            "relation_id": AGGREGATE_RELATION_ID,
            "implemented_at_preflight_freeze": True,
            "required_features": [
                "stream_all_18_planned_tree_assignments_in_namespace_order",
                "reuse_one_read_only_global_tail_assignment",
                "verify_72_exact_relocated_output_values_and_wire_ids",
                "verify_cross_segment_point_and_boundary_wire_identity",
                "replay_586057567_rows_with_zero_failures",
                "checkpoint_without_loading_untrusted_pickle",
                "emit_path_free_evidence_with_broad_claims_false",
            ],
        },
        "resource_floor": {
            "minimum_free_disk_bytes": 32_000_000_000,
            "recommended_free_disk_bytes": 64_000_000_000,
            "minimum_available_memory_bytes": 16_000_000_000,
            "workers": 8,
        },
        "claim_boundary": {
            "aggregate_preflight_contract_closed": True,
            "aggregate_runner_implemented": True,
            "aggregate_external_artifacts_verified": False,
            "complete_18_tree_assignment_replayed": False,
            "cross_segment_wire_identity_closed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }


def _identity(path: Path | None, expected: tuple[int, str]) -> dict[str, object]:
    failures = []
    if path is None:
        return {"provided": False, "verified": False, "failures": ["not_provided"]}
    if not path.is_file():
        failures.append("missing")
    else:
        if path.stat().st_size != expected[0]: failures.append("bytes")
        if _sha256(path) != expected[1]: failures.append("sha256")
    return {"provided": True, "verified": not failures, "failures": failures}


def parse_tree_archives(values: list[str]) -> dict[int, Path]:
    result = {}
    for value in values:
        index_text, separator, path_text = value.partition("=")
        if not separator or not index_text.isdigit():
            raise ValueError("--tree-archive must use INDEX=PATH")
        index = int(index_text)
        if index not in TREE_ARCHIVES or index in result:
            raise ValueError("tree archive index is invalid or duplicated")
        result[index] = Path(path_text)
    return result


def exact_execution_command() -> str:
    parts = [
        "PYTHONPATH=src python src/pq_rbbc_cap_aggregate_replay.py",
        "  --namespace-manifest manifests/pq_rbbc_cap_production_namespace_manifest_v2_16.json",
        "  --prior-evidence artifacts/metadata/tree11_17_bounded_recovery_v2_27/pq_rbbc_cap_tree11_17_bounded_recovery_evidence_v2_27.json",
        "  --global-archive /external/pq_rbbc_cap_global_tail_assignment_v2_9.f193assign",
        "  --trusted-composer-execution-cache /external/local-recovery/pq_rbbc_cap_composition_execution_v2_8.pkl",
        "  --incremental-br1cs /external/pq_rbbc_incremental_v2_25.br1cs",
    ]
    parts.extend(f"  --tree-archive {i}=/external/tree{i}.f193assign" for i in range(18))
    parts.extend([
        "  --checkpoint-directory /external/v2_28_aggregate/checkpoints",
        "  --manifest /external/v2_28_aggregate/pq_rbbc_cap_aggregate_replay_manifest_v2_28.json",
        "  --workers 8",
        "  --full-row-replay",
    ])
    return " \\\n".join(parts)


def build_environment_report(
    global_archive: Path | None,
    incremental_br1cs: Path | None,
    tree_archives: dict[int, Path],
    free_disk_bytes: int,
    available_memory_bytes: int,
) -> dict[str, object]:
    runner_path = ROOT / AGGREGATE_RUNNER
    runner_failures = []
    if not runner_path.is_file():
        runner_failures.append("not_implemented")
    elif AGGREGATE_RUNNER_SHA256 is None:
        runner_failures.append("runner_identity_not_frozen")
    elif _sha256(runner_path) != AGGREGATE_RUNNER_SHA256:
        runner_failures.append("runner_sha256")
    checks = {
        "namespace_manifest": _identity(ROOT / "manifests/pq_rbbc_cap_production_namespace_manifest_v2_16.json", (NAMESPACE_BYTES, NAMESPACE_SHA256)),
        "prior_tree11_17_evidence": _identity(ROOT / "artifacts/metadata/tree11_17_bounded_recovery_v2_27/pq_rbbc_cap_tree11_17_bounded_recovery_evidence_v2_27.json", (PRIOR_EVIDENCE_BYTES, PRIOR_EVIDENCE_SHA256)),
        "global_tail_assignment": _identity(global_archive, GLOBAL_ARCHIVE),
        "incremental_br1cs": _identity(incremental_br1cs, INCREMENTAL_BR1CS),
        "tree_assignments": {str(i): _identity(tree_archives.get(i), TREE_ARCHIVES[i]) for i in range(18)},
        "aggregate_runner": {
            "provided": True,
            "verified": not runner_failures,
            "failures": runner_failures,
        },
        "resources": {
            "verified": free_disk_bytes >= 32_000_000_000 and available_memory_bytes >= 16_000_000_000,
            "free_disk_bytes": free_disk_bytes,
            "available_memory_bytes": available_memory_bytes,
        },
    }
    trees_ready = all(item["verified"] for item in checks["tree_assignments"].values())
    ready = trees_ready and all(checks[name]["verified"] for name in (
        "namespace_manifest", "prior_tree11_17_evidence", "global_tail_assignment",
        "incremental_br1cs", "aggregate_runner", "resources"
    ))
    return {
        "format": "PQRBBC-CAP-AGGREGATE-ENVIRONMENT-PREFLIGHT-1",
        "implementation_version": IMPLEMENTATION_VERSION,
        "checks": checks,
        "safe_to_start_large_replay": ready,
        "large_replay_started": False,
        "exact_execution_command": exact_execution_command(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print-frozen", action="store_true")
    parser.add_argument("--write-frozen", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--global-archive", type=Path)
    parser.add_argument("--incremental-br1cs", type=Path)
    parser.add_argument("--tree-archive", action="append", default=[])
    parser.add_argument("--free-disk-bytes", type=int, default=0)
    parser.add_argument("--available-memory-bytes", type=int, default=0)
    args = parser.parse_args()
    if args.print_frozen:
        print(canonical_json(build_frozen_manifest()).decode(), end="")
        return
    if args.write_frozen is not None:
        args.write_frozen.parent.mkdir(parents=True, exist_ok=True)
        args.write_frozen.write_bytes(canonical_json(build_frozen_manifest()))
        print(_sha256(args.write_frozen))
        return
    if args.report is None:
        parser.error("--report or --print-frozen is required")
    report = build_environment_report(
        args.global_archive, args.incremental_br1cs,
        parse_tree_archives(args.tree_archive), args.free_disk_bytes,
        args.available_memory_bytes,
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_bytes(canonical_json(report))
    print(json.dumps({"report": str(args.report), "safe_to_start_large_replay": report["safe_to_start_large_replay"]}, sort_keys=True))


if __name__ == "__main__":
    main()
