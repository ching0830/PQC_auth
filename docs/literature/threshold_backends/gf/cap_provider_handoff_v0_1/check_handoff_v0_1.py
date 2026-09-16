#!/usr/bin/env python3
"""Read-only check of one pinned OPEN dependency; never a provider/launch gate."""
from __future__ import annotations

import ast
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent
B_COMMIT = "c1c2b5d2690643fc136e4c39a867e4376cdb9a97"
ABI_SHA = "97e97589fdcb293101e866a3233b38e1f48c9bdbe5ad9ddc1daabe5f2b410158"
CAP_SHA = "2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38"
BOUNDED_SHA = "520980f7518de0c8a22e9fcb66f3d3af1eb4ef50c2df9136b6df873d9f524356"
H_SHA = "4fa0eb276ebba70a9f6c2f38f3f55d197c094121a2b614cc6ef9b7e8522cac87"
MANIFEST = "manifests/pq_rbbc_issuance_bounded_multitree_adapter_manifest_v1.json"


class CheckFailure(ValueError):
    """Public metadata or exact-source mismatch, not a private execution error."""


def require(condition, code):
    if condition is not True:
        raise CheckFailure(code)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    def invalid_constant(_value):
        raise CheckFailure("non_json_constant")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)


def check_identity(raw, row):
    require(len(raw) == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"],
            "source_identity_mismatch:" + row["path"])


def capture_sources(index):
    require(index["b_commit"] == B_COMMIT, "unexpected_B_revision")
    local = {}
    for row in index["local_sources"]:
        raw = (ROOT / row["path"]).read_bytes()
        check_identity(raw, row)
        local[row["path"]] = raw
    inventory = strict_json(local["docs/literature/threshold_backends/source_inventory_v1.json"])
    for row in inventory["repository_sources"]:
        check_identity((ROOT / row["path"]).read_bytes(), row)
    captured = {}
    for row in index["b_sources"]:
        require(row["revision"] == B_COMMIT, "mixed_B_revisions")
        result = subprocess.run(["git", "show", B_COMMIT + ":" + row["path"]],
                                cwd=ROOT, capture_output=True, check=False)
        require(result.returncode == 0, "exact_B_git_object_unavailable")
        check_identity(result.stdout, row)
        captured[row["path"]] = result.stdout
    return local, captured, len(inventory["repository_sources"])


def check_immediate_refusal(raw, name, exception):
    nodes = [n for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef) and n.name == name]
    require(len(nodes) == 1, "missing_refusal_entrypoint")
    node = nodes[0]
    require(not node.decorator_list and len(node.body) == 1, "refusal_has_other_operations")
    statement = node.body[0]
    require(isinstance(statement, ast.Raise) and statement.cause is None, "refusal_not_immediate_raise")
    call = statement.exc
    require(isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
            and call.func.id == exception and len(call.args) == 1 and not call.keywords
            and isinstance(call.args[0], ast.Constant) and type(call.args[0].value) is str,
            "refusal_has_unexpected_exception_expression")


def check_requirements(req):
    require(req["schema"] == "pqc_auth.gf_cap_provider_handoff.v0_1", "requirements_version")
    require(req["status"] == "proposal_dependency_open"
            and set(req["owner_acceptance"]) == {"B", "system"}
            and all(value is False for value in req["owner_acceptance"].values()), "false_owner_acceptance")
    require(req["profiles"] == {"gf_abi_sha256": ABI_SHA, "cap_sha256": CAP_SHA,
                               "h_rbbc_sha256": H_SHA}, "requirements_profiles")
    require(req["private_inputs"] == {"rho_bytes": 1036, "optional_same_d_M_bytes": 32}
            and req["private_outputs"] == {"commitment_bytes": 5391, "derived_mask_bits": 576,
                                          "derived_mask_comparison_bytes": 72}, "provider_widths")
    require(req["current_provider_available"] is False
            and type(req["provider_acceptance_cases_executed"]) is int
            and req["provider_acceptance_cases_executed"] == 0, "false_provider_availability")
    cases = req["acceptance_cases"]
    expected = [f"CP{i:02d}" for i in range(1, 17)] + [f"CN{i:02d}" for i in range(1, 5)]
    require([item["id"] for item in cases] == expected, "acceptance_case_ids")
    require(all(item["status"] == "not_run" for item in cases), "unexecuted_cases_claimed_passed")
    require(all(item["level"] == ("host_provider" if item["id"].startswith("CP") else "native_relation")
                and all(type(item[key]) is str and item[key] for key in ("stimulus", "expected", "observable"))
                for item in cases), "acceptance_case_partition")


def check_bounded_snapshot(captured):
    manifest = strict_json(captured[MANIFEST])
    require(manifest["plan"]["profile_fingerprint"] == BOUNDED_SHA
            and manifest["plan"]["production"] is False, "bounded_profile_mismatch")
    require(manifest["bounded_qualification"]["production_adapter_qualified"] is False
            and manifest["bounded_qualification"]["production_mixed_degree_12_13_qualified"] is False,
            "unexpected_B_capability")
    require(all(manifest["exact_commands"][key] is None for key in ("production", "large_replay", "large_proving")),
            "unexpected_B_execution_command")
    for path, row in manifest["implementation_identities"].items():
        check_identity(captured[path], dict(row, path=path))
    check_immediate_refusal(captured["src/pq_rbbc_issuance_bounded_multitree_adapter_v1.py"],
                            "execute_production", "ProductionUnavailable")
    check_immediate_refusal(captured["src/pq_rbbc_issuance_cap_child_executor_v1.py"],
                            "execute_production_child", "ProductionChildExecutorUnavailable")
    module = ast.parse(captured["src/pq_rbbc_issuance_bounded_multitree_native_v1.py"])
    definitions = [n.value for n in module.body if isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == "PARAMETERS" for t in n.targets)]
    expected = ast.parse('replace(legacy_tree.cap.PRODUCTION_PARAMETERS, '
                         'name="PQ-RBBC issuance 4+4-leaf INSECURE-TEST-ONLY native adapter v1", '
                         'security_bits=0, secure_profile=False, tree_specs=(legacy_tree.cap.TreeSpec(2, 4),))',
                         mode="eval").body
    require(len(definitions) == 1 and ast.dump(definitions[0]) == ast.dump(expected), "bounded_parameter_definition")


def main():
    index = strict_json((HERE / "source_index_v0_1.json").read_bytes())
    local, captured, canonical_count = capture_sources(index)
    check_requirements(strict_json(local[str((HERE / "requirements_v0_1.json").relative_to(ROOT))]))
    check_bounded_snapshot(captured)
    abi = strict_json(local["docs/literature/threshold_backends/gf/abi_v0_1/contract_v0_1.json"])
    canonical = json.dumps(abi, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    require(hashlib.sha256(canonical).hexdigest() == ABI_SHA, "frozen_GF_ABI_mismatch")
    require({name: value["bytes"] for name, value in abi["layouts"].items()} == {
        "trace_binding": 315, "common_pp": 489, "ticket_m": 3005, "issue_statement": 251, "issue_witness": 4324},
        "frozen_GF_layout_mismatch")

    fields = {f["name"]: (f["offset"], f["bytes"]) for f in abi["layouts"]["issue_witness"]["fields"]}
    require(fields["ticket_m"] == (51, 3005) and fields["blind_mask"] == (3056, 72)
            and fields["cap_randomness"] == (3128, 1036), "frozen_witness_offsets")

    # T runtime only; selected sources pinned above. No B code is imported/executed.
    sys.path.insert(0, str(ROOT / "src"))
    import pq_rbbc_cap_commit as cap
    import pq_rbbc_anemoi_sponge as h_rbbc
    from pq_threshold_candidates.contracts import ContractError
    from pq_threshold_candidates.gf.i3_hash_join_v0_1.evaluator import _parse_candidate

    bounded = replace(cap.PRODUCTION_PARAMETERS,
                      name="PQ-RBBC issuance 4+4-leaf INSECURE-TEST-ONLY native adapter v1",
                      security_bits=0, secure_profile=False, tree_specs=(cap.TreeSpec(2, 4),))
    require(cap.profile_fingerprint(cap.PRODUCTION_PARAMETERS) == CAP_SHA
            and cap.profile_fingerprint(bounded) == BOUNDED_SHA, "computed_CAP_profiles")
    require(h_rbbc.profile_fingerprint(cap.field.derive_parameters()) == H_SHA, "computed_H_profile")
    require((cap.commitment_bytes(cap.PRODUCTION_PARAMETERS), cap.commitment_bytes(bounded)) == (5391, 511),
            "computed_commitment_widths")
    shape = lambda p: (p.tree_count, p.leaf_count, p.security_bits, p.mask_bits, p.witness_bits,
                       tuple(spec.extension_degree for spec in p.tree_specs))
    require(shape(cap.PRODUCTION_PARAMETERS) == (18, 40960, 192, 576, 2048, (13, 12))
            and shape(bounded) == (2, 8, 0, 576, 2048, (3,)), "computed_profile_shapes")
    rho_lengths = tuple(len(cap.CAPRandomness((0, 0), ((0, 0),) * p.tree_count).serialize(p))
                        for p in (cap.PRODUCTION_PARAMETERS, bounded))
    require(rho_lengths == (1036, 236), "computed_randomness_widths")
    # Grammar-only zero fixture: never described as a CAP(rho) output.
    grammar_only = cap.serialize_commitment(bounded, (0, 0), 0, 0, (0,), (0,))
    rejected = 0
    for raw in (grammar_only, grammar_only + bytes(5391 - len(grammar_only))):
        try:
            _parse_candidate(raw)
        except ContractError:
            rejected += 1
        else:
            raise CheckFailure("bounded_candidate_crossed_frozen_GF_parser")
    report = {
        "schema": "pqc_auth.gf_cap_provider_handoff_check.v0_1",
        "status": "dependency_open", "checkpoint_consistency_checks_passed": True,
        "b_commit": B_COMMIT, "local_source_identities_checked": len(local),
        "canonical_source_identities_checked": canonical_count, "b_source_identities_checked": len(captured),
        "public_refusal_bodies_statically_checked": 2,
        "bounded_grammar_candidates_rejected_by_GF_parser": rejected,
        "grammar_candidates_are_CAP_execution_outputs": False,
        "provider_acceptance_cases_executed": 0, "provider_acceptance_cases_not_run": 20,
        "provider_available": False, "CAP_executions": 0, "native_rows_replayed": 0,
        "full_I3_verified": False, "production_qualified": False, "owner_acceptance": False,
        "new_paper_verified_claims": 0,
    }
    print(json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (CheckFailure, KeyError, TypeError, OSError, ValueError, SyntaxError) as error:
        # Only public metadata is processed; do not print subprocess stderr/source bytes.
        print(json.dumps({"status": "check_failed", "error_type": type(error).__name__,
                          "provider_available": False}), file=sys.stderr)
        raise SystemExit(1) from None
