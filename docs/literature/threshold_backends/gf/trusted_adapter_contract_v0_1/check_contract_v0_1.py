"""Validate a proposal document and exercise its dependency/partition guards.

No artifact, signature, key-origin evidence, witness, or proof is verified.
This standalone documentation checker imports only the Python standard library.
"""

from copy import deepcopy
import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
ABI_PATH = HERE.parent / "abi_v0_1/contract_v0_1.json"
KEYS = set("""schema status wire_abi_sha256 crypto_profile_sha256 wire_purpose oa_role
configuration_auth_role initialization_auth_domain_hex authentication_scope production_policy
packet_bytes bridge service_order service_owned_inputs forbidden_request_overrides
key_origin_expected_fields construction_dependencies dependency_semantics
per_ticket_inputs_forbidden_in_setup public_statement_semantic private_witness_semantic
research_evaluator_inputs proof_verifier_inputs native_join_requirements owner_deliverables
acceptance_ids claims""".split())
ORDER = ["purpose_gate", "bounded_immutable_capture", "authenticate_initialization",
         "strict_byte_bindings", "verify_key_origin", "qualify_GF_relation_backend", "evaluate_or_verify"]
MIN_DEPS = {
    "profiles": [], "key_material": [], "configuration": ["key_material"],
    "key_origin_evidence": ["profiles", "key_material", "configuration"],
    "trace_binding": ["profiles", "key_material", "configuration", "key_origin_evidence"],
    "gf_relation_manifest": ["profiles", "trace_binding"],
    "issue_backend_pp": ["key_material", "trace_binding", "gf_relation_manifest"],
    "common_pp": ["trace_binding", "gf_relation_manifest", "issue_backend_pp"],
    "initialization_bundle": ["key_material", "configuration", "common_pp"],
    "authenticated_initialization": ["initialization_bundle"],
}
ORIGIN_FIELDS = """abi_sha256 crypto_profile_sha256 configuration_sha256 ctx epoch oa_role
purpose oa_key_id tpk_record_sha256 origin_model_id certifier_policy_id""".split()
SERVICE_INPUTS = ["configuration_trust_anchor_and_key_resolver",
                  "configuration_signature_backend_and_profile_policy",
                  "key_origin_model_and_certifier_policy", "GF_relation_backend_and_setup_policy"]
CLAIMS = """adapter_requirements_defined adapter_requirements_owner_accepted
authentication_adapter_implemented key_origin_verifier_implemented GF_full_relation_integrated
witness_free_proof_verifier_implemented acceptance_matrix_cryptographically_tested
external_independent_review evidence_sealed proof_closed production_closed""".split()


def require(value, label):
    if not value:
        raise ValueError(label)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def invalid_constant(_):
    raise ValueError("nonfinite JSON constant")


def load_json(raw):
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def compact(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def topological_order(graph):
    require(type(graph) is dict and set(graph) == set(MIN_DEPS), "setup graph node set")
    for node, dependencies in graph.items():
        require(type(dependencies) is list and all(type(d) is str for d in dependencies), "dependency list")
        require(len(dependencies) == len(set(dependencies)), "duplicate dependency")
        require(set(dependencies) <= set(graph), "unknown dependency")
        require(set(MIN_DEPS[node]) <= set(dependencies), "missing required dependency")
    result = []
    remaining = set(graph)
    while remaining:
        ready = sorted(n for n in remaining if set(graph[n]) <= set(result))
        require(ready, "cyclic setup identities")
        result.extend(ready)
        remaining.difference_update(ready)
    return result


def validate(document, abi):
    require(type(document) is dict and set(document) == KEYS, "document fields")
    require(document["schema"] == "pqc_auth.gf_trusted_adapter_requirements.v0_1", "schema")
    require(document["status"] == "proposal_only", "proposal status")
    frozen_hash = hashlib.sha256(compact(abi)).hexdigest()
    require(frozen_hash == "97e97589fdcb293101e866a3233b38e1f48c9bdbe5ad9ddc1daabe5f2b410158", "frozen ABI changed")
    require(document["wire_abi_sha256"] == frozen_hash, "wrong wire ABI")
    require(document["crypto_profile_sha256"] == "3077ddb7e9f90c2a551c0fccff8719655b5e852394aa4e9326c9a7801225a9b7", "crypto profile")
    for key, value in (("wire_purpose", 1), ("oa_role", 5), ("configuration_auth_role", 1)):
        require(type(document[key]) is int and document[key] == value, key)
    require(document["initialization_auth_domain_hex"] == b"PQ-RBBC/SYSTEM-INIT-AUTH/V1".hex(), "auth domain")
    require(document["authentication_scope"] == "exact_canonical_public_initialization_bundle", "auth scope")
    require(document["production_policy"] == "unconditionally_unavailable_for_this_research_ABI", "production boundary")
    sizes = {name: item["bytes"] for name, item in abi["layouts"].items()}
    sizes.update(public_key_record=22590, trace_u=128, cap_randomness=1036, blind_mask=72, beta=72)
    require(document["packet_bytes"] == sizes and all(type(v) is int for v in document["packet_bytes"].values()), "packet sizes")
    bridge = {name: abi["bridge"][name] for name in ("cap_profile_sha256", "h_rbbc_profile_sha256", "cap_tree_count")}
    bridge["r_equals_CAP_derived_mask_required"] = True
    require(document["bridge"] == bridge and type(document["bridge"]["cap_tree_count"]) is int
            and document["bridge"]["r_equals_CAP_derived_mask_required"] is True, "CAP bridge")
    require(document["service_order"] == ORDER, "acceptance order")
    require(document["service_owned_inputs"] == SERVICE_INPUTS, "service inputs")
    require(document["forbidden_request_overrides"] == SERVICE_INPUTS + ["accepted_receipt"], "request overrides")
    require(document["key_origin_expected_fields"] == ORIGIN_FIELDS, "key-origin expected fields")
    require(document["dependency_semantics"] == "construction_prerequisites_and_embedded_identities_not_new_wire_fields", "dependency semantics")
    order = topological_order(document["construction_dependencies"])
    require(document["per_ticket_inputs_forbidden_in_setup"] == "sid rid M sn h C d_M r rho u k_hold".split(), "setup privacy")
    require(document["public_statement_semantic"] == abi["partition"]["public_semantic"], "public partition")
    require(document["private_witness_semantic"] == abi["partition"]["private_semantic"], "private partition")
    require(document["research_evaluator_inputs"] == ["common_pp", "tpk_record", "statement", "witness"], "evaluator inputs")
    require(document["proof_verifier_inputs"] == ["common_pp", "statement", "proof"], "verifier private-input leak")
    joins = document["native_join_requirements"]
    require(type(joins) is dict and set(joins) == {f"J{i:02}" for i in range(1, 9)}, "native join coverage")
    require(all(type(value) is str and value for value in joins.values()), "join description")
    require(joins["J04"] == "witness.r == CAP(witness.rho).derived_mask", "CAP mask equality")
    require(joins["J05"] == "statement.beta == witness.r XOR H_RBBC(J03.d_M, J04.CAP_commitment)", "CAP hash join")
    owners = document["owner_deliverables"]
    expected_owners = {"S-AUTH": ["system"], "T-ORIGIN": ["T", "system"],
                       "B-QUAL": ["B"], "B-EVAL": ["B"], "B-VERIFY": ["B"]}
    require(type(owners) is dict and set(owners) == set(expected_owners), "owner boundaries")
    for name, entry in owners.items():
        require(type(entry) is dict and set(entry) == {"owners", "required", "accepted"}, "owner fields")
        require(entry["owners"] == expected_owners[name] and entry["accepted"] is False, "unapproved owner acceptance")
        require(type(entry["required"]) is list and entry["required"]
                and all(type(item) is str and item for item in entry["required"]), "deliverables")
    require(document["acceptance_ids"] == [f"TA{i:02}" for i in range(1, 17)], "acceptance matrix")
    require(type(document["claims"]) is dict and set(document["claims"]) == set(CLAIMS), "claim fields")
    for name, claim in document["claims"].items():
        require(claim is (name == "adapter_requirements_defined"), "claim promotion")
    return order


def main():
    abi = load_json(ABI_PATH.read_text(encoding="utf-8"))
    doc = load_json((HERE / "requirements_v0_1.json").read_text(encoding="utf-8"))
    order = validate(doc, abi)
    # Two graph variants establish that the graph algorithm, not dictionary/list
    # order, determines constructibility. These are document tests only.
    variant = deepcopy(doc)
    variant["construction_dependencies"]["issue_backend_pp"].append("profiles")
    validate(variant, abi)
    variant = deepcopy(doc)
    for deps in variant["construction_dependencies"].values():
        deps.reverse()
    validate(variant, abi)
    mutations = [
        ("unknown_field", lambda d: d.update(unexpected=True)),
        ("bool_role", lambda d: d.update(configuration_auth_role=True)),
        ("wrong_role", lambda d: d.update(oa_role=1)),
        ("production_purpose", lambda d: d.update(wire_purpose=2)),
        ("promoted_production", lambda d: d.update(production_policy="available")),
        ("config_only_auth", lambda d: d.update(authentication_scope="configuration_only")),
        ("wrong_auth_domain", lambda d: d.update(initialization_auth_domain_hex="00")),
        ("old_M_size", lambda d: d["packet_bytes"].update(ticket_m=368)),
        ("old_trace_witness", lambda d: d["packet_bytes"].update(trace_u=836)),
        ("wrong_CAP_count", lambda d: d["bridge"].update(cap_tree_count=1)),
        ("wrong_CAP_profile", lambda d: d["bridge"].update(cap_profile_sha256="00" * 32)),
        ("missing_CAP_mask", lambda d: d["native_join_requirements"].pop("J04")),
        ("missing_CAP_parent_join", lambda d: d["native_join_requirements"].update(J05="beta == caller_value")),
        ("public_d_M", lambda d: d["public_statement_semantic"].append("d_M")),
        ("missing_private_u", lambda d: d["private_witness_semantic"].remove("u")),
        ("witness_in_verifier", lambda d: d["proof_verifier_inputs"].append("witness")),
        ("setup_metadata_leak", lambda d: d["per_ticket_inputs_forbidden_in_setup"].remove("rid")),
        ("origin_missing_epoch", lambda d: d["key_origin_expected_fields"].remove("epoch")),
        ("request_anchor_override", lambda d: d["forbidden_request_overrides"].pop(0)),
        ("private_setup_node", lambda d: d["construction_dependencies"].update(rid=[])),
        ("unknown_dependency", lambda d: d["construction_dependencies"]["profiles"].append("unknown")),
        ("duplicate_dependency", lambda d: d["construction_dependencies"]["configuration"].append("key_material")),
        ("self_cycle", lambda d: d["construction_dependencies"]["key_origin_evidence"].append("key_origin_evidence")),
        ("origin_to_final_pp_cycle", lambda d: d["construction_dependencies"]["key_origin_evidence"].append("common_pp")),
        ("relation_to_final_pp_cycle", lambda d: d["construction_dependencies"]["gf_relation_manifest"].append("common_pp")),
        ("backend_to_envelope_cycle", lambda d: d["construction_dependencies"]["issue_backend_pp"].append("authenticated_initialization")),
        ("missing_key_origin_dependency", lambda d: d["construction_dependencies"]["trace_binding"].remove("key_origin_evidence")),
        ("authentication_delayed", lambda d: d["service_order"].reverse()),
        ("forged_owner_acceptance", lambda d: d["owner_deliverables"]["T-ORIGIN"].update(accepted=True)),
        ("forged_proof_closure", lambda d: d["claims"].update(proof_closed=True)),
    ]
    rejected = []
    for label, mutation in mutations:
        changed = deepcopy(doc)
        mutation(changed)
        try:
            validate(changed, abi)
        except ValueError:
            rejected.append(label)
        else:
            raise ValueError("document mutation unexpectedly accepted: " + label)
    malformed_json = ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', '{"x":-Infinity}', '{}{}')
    for raw in malformed_json:
        try:
            load_json(raw)
        except ValueError:
            pass
        else:
            raise ValueError("malformed JSON unexpectedly accepted")
    print(json.dumps(dict(schema="pqc_auth.gf_adapter_document_check.v0_1",
                          proposal_contract_sha256=hashlib.sha256(compact(doc)).hexdigest(),
                          positive_document_cases=3, negative_document_cases=len(rejected),
                          malformed_JSON_rejected=len(malformed_json), rejected_mutations=rejected,
                          construction_order=order, adapter_cryptography_executed=False,
                          owner_acceptance_verified=False, production_qualified=False), indent=2))


if __name__ == "__main__":
    main()
