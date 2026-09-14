"""Same-author differential review; no raw input/witness material is emitted.

Run directly from the repository root. Inputs are assembled from the frozen
JSON offsets, without runtime codec encoders or existing evaluator fixtures.
The old separately coded GF oracle supplies polynomial/rounding calculations.
Synthetic canonical public matrices are not certified KeyGen outputs.
"""

from collections import Counter
from contextlib import ExitStack
from dataclasses import dataclass, replace
from functools import lru_cache
import hashlib
import itertools
import json
from pathlib import Path
import sys
from unittest.mock import patch

if not __debug__:
    raise RuntimeError("Review assertions require Python without optimization")

ROOT = Path(__file__).resolve().parents[5]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
from pq_threshold_candidates.contracts import ContractError, Unsupported
from pq_threshold_candidates.gf.partial_issuance_v0_1 import evaluator as target
from threshold_candidates.gf.review import oracle

ABI_PATH = ROOT / "docs/literature/threshold_backends/gf/abi_v0_1/contract_v0_1.json"
ABI = json.loads(ABI_PATH.read_text(encoding="utf-8"))
ABI_DIGEST = hashlib.sha256(json.dumps(
    ABI, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
).encode("ascii")).digest()
assert ABI_DIGEST.hex() == "97e97589fdcb293101e866a3233b38e1f48c9bdbe5ad9ddc1daabe5f2b410158"
SHAKE = hashlib.shake_256
NAMES = ("P1_codecs", "P0_statement_pp", "P0_ticket_pp", "P0_trace_key",
         "I1_statement_ctx", "I1_ticket_ctx", "I2_digest", "I3", "I4", "I5")
UNRESOLVED = ("I2_to_I3_join", "I3_CAP_H_RBBC", "configuration_authentication",
              "key_origin_certification", "backend_qualification", "native_constraints",
              "proof_verification", "issuer_identity_session_authorization",
              "witness_freshness", "threshold_cryptography")


def sample(label, size):
    return SHAKE(b"GF-PARTIAL-REVIEW/V0.1/" + label.encode("ascii")).digest(size)


def field(layout, name):
    return next(f for f in ABI["layouts"][layout]["fields"] if f["name"] == name)


def get(raw, layout, name):
    f = field(layout, name)
    return raw[f["offset"]:f["offset"] + f["bytes"]]


def put(raw, layout, name, value):
    f = field(layout, name)
    assert type(value) is bytes and len(value) == f["bytes"]
    return raw[:f["offset"]] + value + raw[f["offset"] + f["bytes"]:]


def packet(layout, **values):
    out = bytearray(ABI["layouts"][layout]["bytes"])
    cursor = 0
    for f in ABI["layouts"][layout]["fields"]:
        assert f["offset"] == cursor
        if "literal_hex" in f:
            value = bytes.fromhex(f["literal_hex"])
        elif "derived" in f:
            value = ABI_DIGEST
        else:
            value = values.pop(f["name"])
        assert type(value) is bytes and len(value) == f["bytes"]
        out[cursor:cursor + len(value)] = value
        cursor += len(value)
    assert cursor == len(out) and not values
    return bytes(out)


def flip(raw, offset=0):
    return raw[:offset] + bytes([raw[offset] ^ 1]) + raw[offset + 1:]


@dataclass(frozen=True, repr=False)
class Inputs:
    common_pp: bytes
    tpk_record: bytes
    statement: bytes
    witness: bytes

    def arguments(self):
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @property
    def m(self):
        return get(self.witness, "issue_witness", "ticket_m")

    @property
    def binding(self):
        return get(self.common_pp, "common_pp", "trace_binding")

    def edit(self, scope, name, value):
        if scope == "m":
            return self.edit("witness", "ticket_m", put(self.m, "ticket_m", name, value))
        if scope == "binding":
            return self.edit("common_pp", "trace_binding", put(self.binding, "trace_binding", name, value))
        layout = {"witness": "issue_witness", "statement": "issue_statement", "common_pp": "common_pp"}[scope]
        return replace(self, **{scope: put(getattr(self, scope), layout, name, value)})

    def repoint(self):
        digest = hashlib.sha256(self.common_pp).digest()
        return self.edit("statement", "common_pp_sha256", digest).edit("m", "common_pp_sha256", digest)


@lru_cache(maxsize=64)
def ciphertext(pk, u, ad, plaintext):
    return oracle.parse_record(oracle.encrypt(pk, u, ad, plaintext), 2)


def synthetic_public_key(label):
    raw = sample(label, 8192 * 4)
    coefficients = [int.from_bytes(raw[i:i + 4], "little") % oracle.Q for i in range(0, len(raw), 4)]
    return oracle.record(1, oracle.pack(coefficients, 22, oracle.Q))


def fixture(label, pk, u):
    ctx, rid, sn, holder = (sample(label + x, n) for x, n in (("ctx", 32), ("rid", 32), ("sn", 16), ("holder", 32)))
    h = SHAKE(b"PQ-RBBC/HOLD" + holder).digest(32)
    binding = packet("trace_binding", configuration_sha256=sample(label + "cfg", 32), ctx=ctx,
                     epoch=(913).to_bytes(8, "little"), oa_key_id=sample(label + "oa", 32),
                     tpk_record_sha256=hashlib.sha256(pk).digest(), issuer_key_id=sample(label + "issuer", 32),
                     issuer_public_key_sha256=sample(label + "ipk", 32), key_origin_evidence_sha256=sample(label + "origin", 32))
    pp = packet("common_pp", trace_binding=binding, issue_backend_pp_sha256=sample(label + "backend", 32),
                gf_full_relation_manifest_sha256=sample(label + "relation", 32))
    pp_hash = hashlib.sha256(pp).digest()
    m = packet("ticket_m", common_pp_sha256=pp_hash, ctx=ctx, sn=sn, h=h,
               ciphertext_payload=ciphertext(pk, u, ctx + sn + h, rid + sn))
    x = packet("issue_statement", common_pp_sha256=pp_hash, ctx=ctx, sid=sample(label + "sid", 32),
               rid=rid, beta=sample(label + "beta", 72))
    fields = [sample(label + "rho" + str(i), 24) + bytes([i & 1]) for i in range(38)]
    rho = (b"PQRBBC-CAP-RANDOM-V1" + ABI["bridge"]["cap_profile_sha256"].encode("ascii")
           + b"".join(fields[:2]) + b"\x12\x00" + b"".join(fields[2:]))
    w = packet("issue_witness", ticket_m=m, blind_mask=sample(label + "r", 72), cap_randomness=rho,
               holder_key=holder, trace_u=u)
    return Inputs(pp, pk, x, w)


def trace_parts(inputs):
    m = inputs.m
    ad = b"".join(get(m, "ticket_m", f) for f in ("ctx", "sn", "h"))
    plaintext = get(inputs.statement, "issue_statement", "rid") + get(m, "ticket_m", "sn")
    return get(inputs.witness, "issue_witness", "trace_u"), ad, plaintext


def expected(inputs, faults):
    """Model the specified local predicates from raw fields, not decoded objects."""
    pp_hash = hashlib.sha256(inputs.common_pp).digest()
    facts = [get(inputs.statement, "issue_statement", "common_pp_sha256") == pp_hash,
             get(inputs.m, "ticket_m", "common_pp_sha256") == pp_hash,
             get(inputs.binding, "trace_binding", "tpk_record_sha256") == hashlib.sha256(inputs.tpk_record).digest(),
             get(inputs.statement, "issue_statement", "ctx") == get(inputs.binding, "trace_binding", "ctx"),
             get(inputs.m, "ticket_m", "ctx") == get(inputs.statement, "issue_statement", "ctx")]
    values = ["passed"] + ["passed" if fact else "failed" for fact in facts]
    values += ["not_evaluated", "open", "not_evaluated", "not_evaluated"]
    if not all(facts):
        return values, []
    events = []
    for stage, index in (("I2", 6), ("I4", 8), ("I5", 9)):
        events.append(stage)
        if stage in faults:
            values[index] = "error"
            break
        if stage == "I2":
            values[index] = "computed_unjoined"
        elif stage == "I4":
            h = SHAKE()
            h.update(b"PQ-RBBC/HOLD")
            h.update(get(inputs.witness, "issue_witness", "holder_key"))
            values[index] = "passed" if h.digest(32) == get(inputs.m, "ticket_m", "h") else "failed"
        else:
            body = ciphertext(inputs.tpk_record, *trace_parts(inputs))
            values[index] = "passed" if body == get(inputs.m, "ticket_m", "ciphertext_payload") else "failed"
    return values, events


def safe_result(result):
    assert tuple(result.__dict__) == ("checks",)
    assert tuple(name for name, _ in result.checks) == NAMES
    assert result.unresolved == UNRESOLVED
    assert all(type(name) is str and type(status) is target.ResearchPartialCheckStatus for name, status in result.checks)
    assert all(getattr(result, name) is False for name in ("full_relation_verified", "authentication_verified", "production_qualified"))
    assert not hasattr(result, "ok") and not hasattr(result, "accepted")
    assert result.failed_checks == tuple(n for n, s in result.checks if s.value == "failed")
    assert result.errored_checks == tuple(n for n, s in result.checks if s.value == "error")
    assert repr(result) == "ResearchPartialIssuanceEvaluation(research_only=True, full_relation_verified=False)"
    for value in (result, *(s for _, s in result.checks)):
        try:
            bool(value)
        except TypeError:
            pass
        else:
            raise AssertionError("boolean acceptance available")


def observe(inputs, faults=None):
    faults = faults or {}
    wanted, wanted_events = expected(inputs, faults)
    events = []
    ticket_hash = SHAKE()
    ticket_hash.update(b"PQ-RBBC/TICKET")
    ticket_hash.update(inputs.m)
    real_i5 = target.check_encryption_relation_reference

    def inject(stage, normal):
        fault = faults.get(stage)
        if fault == "raise":
            raise RuntimeError("PRIVATE REVIEW FAULT SENTINEL")
        return {"short": b"", "mutable": bytearray(32), "int": 1, "none": None}.get(fault, normal)

    def shake_spy(data=b""):
        stage = "I2" if data.startswith(b"PQ-RBBC/TICKET") else "I4" if data.startswith(b"PQ-RBBC/HOLD") else None
        if stage is None:
            return SHAKE(data)
        events.append(stage)
        preimage = (b"PQ-RBBC/TICKET" + inputs.m if stage == "I2" else
                    b"PQ-RBBC/HOLD" + get(inputs.witness, "issue_witness", "holder_key"))
        assert data == preimage

        class Digest:
            def digest(self, size):
                assert size == 32
                value = SHAKE(data).digest(size)
                if stage == "I2":
                    assert value == ticket_hash.digest(32)
                return inject(stage, value)
        return Digest()

    def i5_spy(key, trace, ct, witness):
        events.append("I5")
        u, ad, plaintext = trace_parts(inputs)
        # Runtime encoders only observe actual call arguments, never build fixtures/model.
        assert key.encode() == inputs.tpk_record
        assert trace.associated_data == ad and trace.plaintext == plaintext
        assert ct.encode() == oracle.record(2, get(inputs.m, "ticket_m", "ciphertext_payload"))
        assert witness.encode() == oracle.record(3, u)
        if "I5" in faults:
            return inject("I5", None)
        return real_i5(key, trace, ct, witness)

    with patch.object(target.hashlib, "shake_256", side_effect=shake_spy), patch.object(
        target, "check_encryption_relation_reference", side_effect=i5_spy,
    ):
        result = target.evaluate_partial_issuance_research(**inputs.arguments(), purpose="research")
    assert [s.value for _, s in result.checks] == wanted
    assert events == wanted_events
    safe_result(result)
    return wanted


def rejected(inputs, purpose, error):
    """Require pre-computation rejection; default production must not parse."""
    calls = []
    with ExitStack() as stack:
        for obj, attribute in ((target.hashlib, "shake_256"), (target, "check_encryption_relation_reference")):
            stack.enter_context(patch.object(obj, attribute, side_effect=lambda *a: calls.append(True)))
        if purpose != "research":
            stack.enter_context(patch.object(target.ResearchCommonPP, "decode", side_effect=lambda *a: calls.append(True)))
        args = inputs.arguments()
        if purpose is not DEFAULT:
            args["purpose"] = purpose
        try:
            target.evaluate_partial_issuance_research(**args)
        except error:
            pass
        else:
            raise AssertionError("expected rejection missing")
    assert not calls


DEFAULT = object()


def main():
    counts = Counter()
    statuses = Counter()

    def check(group, inputs, faults=None):
        actual = observe(inputs, faults)
        counts[group] += 1
        statuses[actual[9]] += 1
        return actual

    keys = [synthetic_public_key("matrix-A"), synthetic_public_key("matrix-B")]
    witnesses = (bytes(128), bytes([255]) * 128, bytes([1]) + bytes(127),
                 bytes(127) + bytes([128]), bytes([170]) * 128, sample("u", 128))
    for i, (pk, u) in enumerate(itertools.product(keys, witnesses)):
        check("separately_assembled_positive", fixture("positive" + str(i), pk, u))
    base = fixture("mutation-base", keys[0], witnesses[-1])
    for bits in itertools.product((False, True), repeat=5):
        current = base
        for enabled, scope, name, raw in zip(bits, ("statement", "m", "binding", "statement", "m"),
                ("common_pp_sha256", "common_pp_sha256", "tpk_record_sha256", "ctx", "ctx"),
                (get(base.statement, "issue_statement", "common_pp_sha256"), get(base.m, "ticket_m", "common_pp_sha256"),
                 get(base.binding, "trace_binding", "tpk_record_sha256"), get(base.statement, "issue_statement", "ctx"),
                 get(base.m, "ticket_m", "ctx"))):
            if enabled:
                current = current.edit(scope, name, flip(raw))
        # Preserve selected pointer differences when only the pp key digest changes.
        if bits[2]:
            current = current.repoint()
            for enabled, scope in zip(bits[:2], ("statement", "m")):
                if enabled:
                    current = current.edit(scope, "common_pp_sha256", flip(hashlib.sha256(current.common_pp).digest()))
        check("binding_error_combinations", current)

    u, ad, plaintext = trace_parts(base)
    for bits in itertools.product((False, True), repeat=5):
        parts = [ad[:32], ad[32:48], ad[48:], plaintext[:32], plaintext[32:]]
        parts = [flip(raw) if enabled else raw for raw, enabled in zip(parts, bits)]
        body = ciphertext(keys[0], u, b"".join(parts[:3]), b"".join(parts[3:]))
        values = check("recomputed_ciphertext_field_combinations", base.edit("m", "ciphertext_payload", body))
        assert values[9] == ("failed" if any(bits) else "passed")

    body = get(base.m, "ticket_m", "ciphertext_payload")
    for start, end in ABI["ciphertext_component_ranges"].values():
        for offset in (start, (start + end) // 2, end - 1):
            check("ciphertext_component_mutations", base.edit("m", "ciphertext_payload", flip(body, offset)))
    for name, scope, layout, positions in (
        ("blind_mask", "witness", "issue_witness", (0, 35, 71)),
        ("beta", "statement", "issue_statement", (0, 35, 71)),
        ("sid", "statement", "issue_statement", (0, 31)),
        ("cap_randomness", "witness", "issue_witness", (84, 109, *(136 + 25 * i for i in range(36)))),
    ):
        for offset in positions:
            check("unimplemented_semantic_slots", base.edit(scope, name, flip(get(getattr(base, scope), layout, name), offset)))

    for name, scope, layout in (("configuration_sha256", "binding", "trace_binding"), ("epoch", "binding", "trace_binding"),
        ("oa_key_id", "binding", "trace_binding"), ("issuer_key_id", "binding", "trace_binding"),
        ("issuer_public_key_sha256", "binding", "trace_binding"), ("key_origin_evidence_sha256", "binding", "trace_binding"),
        ("issue_backend_pp_sha256", "common_pp", "common_pp"), ("gf_full_relation_manifest_sha256", "common_pp", "common_pp")):
        raw = base.binding if scope == "binding" else base.common_pp
        check("untrusted_metadata_repointed", base.edit(scope, name, flip(get(raw, layout, name))).repoint())

    zero = fixture("zero-u", keys[0], bytes(128))
    check("zero_u_wrong_key", replace(zero, tpk_record=keys[1]))
    rekeyed = replace(zero, tpk_record=keys[1]).edit("binding", "tpk_record_sha256", hashlib.sha256(keys[1]).digest()).repoint()
    assert check("zero_u_coherent_rekey", rekeyed)[9] == "passed"
    holder_bad = base.edit("witness", "holder_key", flip(get(base.witness, "issue_witness", "holder_key")))
    assert check("holder_only_mismatch", holder_bad)[8:] == ["failed", "passed"]
    for candidate in (base, holder_bad):
        for bits in itertools.product((False, True), repeat=3):
            check("computation_fault_combinations", candidate, {stage: "raise" for stage, flag in zip(("I2", "I4", "I5"), bits) if flag})
        for stage, modes in (("I2", ("short", "mutable")), ("I4", ("short", "mutable")), ("I5", ("int", "none"))):
            for mode in modes:
                check("computation_bad_return_types", candidate, {stage: mode})
    binding_bad = base.edit("m", "common_pp_sha256", flip(get(base.m, "ticket_m", "common_pp_sha256")))
    check("identity_failure_precedes_all_faults", binding_bad, {stage: "raise" for stage in ("I2", "I4", "I5")})

    malformed = []
    for name, raw in base.arguments().items():
        for value in (raw[:-1], raw + b"\0", bytearray(raw), memoryview(raw), flip(raw)):
            malformed.append(replace(base, **{name: value}))
    rho = get(base.witness, "issue_witness", "cap_randomness")
    for offset in (0, 20, 108, 133, 134, 160, 1035):
        value = rho[:offset] + bytes([rho[offset] ^ (2 if offset in (108, 133, 160, 1035) else 1)]) + rho[offset + 1:]
        malformed.append(base.edit("witness", "cap_randomness", value))
    malformed.append(base.edit("m", "magic", flip(get(base.m, "ticket_m", "magic"))))
    for candidate in malformed:
        rejected(candidate, "research", ContractError)
        counts["structural_rejections"] += 1
        for purpose in (DEFAULT, "production"):
            rejected(candidate, purpose, Unsupported)
            counts["production_preparse_rejections"] += 1
    for purpose in (None, True, 1, "", "Research", b"research"):
        rejected(base, purpose, ContractError)
        counts["purpose_type_rejections"] += 1

    print(json.dumps({"schema": "pqc_auth.gf_partial_issuance_review_experiment.v0_1",
        "abi_sha256": ABI_DIGEST.hex(), "cases": dict(sorted(counts.items())),
        "total_cases": sum(counts.values()), "I5_status_counts_for_diagnostics": dict(sorted(statuses.items())),
        "model_status_disagreements": 0, "call_order_disagreements": 0,
        "raw_input_or_private_digest_emitted": False, "synthetic_keys_are_KeyGen_certified": False,
        "full_I3_executed": False, "independent_external_review": False,
        "proof_closed": False, "production_closed": False}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
