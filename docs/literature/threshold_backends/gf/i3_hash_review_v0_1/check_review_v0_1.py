"""Same-author differential review of the private CAP candidate hash consumer.

CAP bytes and sponge framing/padding/packing are assembled separately. Anemoi
parameters/permutation and the earlier raw GF review builder remain shared.
Only aggregate counts and public identities are emitted; no private vectors.
"""

from collections import Counter
from dataclasses import replace
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import sys
from unittest.mock import patch

if not __debug__:
    raise RuntimeError("Review requires enabled Python assertions")

ROOT = Path(__file__).resolve().parents[5]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
import pq_rbbc_anemoi_f193 as permutation
from pq_threshold_candidates import ContractError, Unsupported
from pq_threshold_candidates.gf.i3_hash_join_v0_1 import evaluator as target
from pq_threshold_candidates.gf.partial_issuance_v0_1 import evaluator as partial
from pq_threshold_candidates.gf.research_abi_v0_1 import ResearchTicketM

BUILDER = ROOT / "docs/literature/threshold_backends/gf/partial_issuance_review_v0_1/check_review_v0_1.py"
spec = importlib.util.spec_from_file_location("gf_prior_raw_review_builder", BUILDER)
raw_builder = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = raw_builder
spec.loader.exec_module(raw_builder)

CAP_FP = "2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38"
PREFIX = b"PQRBBC-CAP-COMMIT-V1" + b"\x01\x00" + bytes.fromhex(CAP_FP)
MASKS = {78: 1, 103: 1, 152: 3, 205: 3, **{510 + 305 * i: 3 for i in range(17)}}
PARAMETERS = permutation.derive_parameters()
GET = raw_builder.get
NAMES = ("CAP_candidate_codecs", "CAP_salt_binding", "I2_H_RBBC_consumer",
         "I3_beta_equation", "CAP_rho_execution", "CAP_mask_derivation")


def changed(raw, offset, bit=0):
    return raw[:offset] + bytes([raw[offset] ^ (1 << bit)]) + raw[offset + 1:]


def candidate(inputs, label):
    """Encode the fixed legacy18 grammar without any CAP serializer/parser."""
    rho = GET(inputs.witness, "issue_witness", "cap_randomness")
    raw = bytearray(raw_builder.sample("I3-review-candidate/" + label, 5391))
    raw[:54] = PREFIX
    raw[54:104] = rho[84:134]
    raw[153:157] = (5234).to_bytes(4, "little")
    for offset, mask in MASKS.items():
        raw[offset] &= mask
    return bytes(raw)


def grammar(raw):
    return (type(raw) is bytes and len(raw) == 5391 and raw[:54] == PREFIX
            and raw[153:157] == (5234).to_bytes(4, "little")
            and all(raw[offset] & ~mask == 0 for offset, mask in MASKS.items()))


def parse_case(raw):
    expected = grammar(raw)
    try:
        result = target._parse_candidate(raw)
    except ContractError:
        assert not expected
        return False
    assert expected
    integer = lambda start, end: int.from_bytes(raw[start:end], "little")
    assert result.salt == (integer(54, 79), integer(79, 104))
    assert result.h2 == integer(104, 153) and result.alpha == integer(157, 206)
    assert result.delta_p == tuple(integer(206 + 305 * i, 462 + 305 * i) for i in range(17))
    assert result.delta_mhat == tuple(integer(462 + 305 * i, 511 + 305 * i) for i in range(17))
    return True


def check_grammar(raw):
    counts = Counter()
    invalid_positions = []
    for offset, bit in itertools.product(range(5391), range(8)):
        accepted = parse_case(changed(raw, offset, bit))
        counts["accepted" if accepted else "rejected"] += 1
        if not accepted:
            invalid_positions.append((offset, bit))
    # Zero/maximal numeric fields remain grammar-only candidates.
    for fill in (0, 255):
        edge = bytearray([fill] * 5391)
        edge[:54] = PREFIX
        edge[153:157] = (5234).to_bytes(4, "little")
        for offset, mask in MASKS.items():
            edge[offset] &= mask
        assert parse_case(bytes(edge))
    class AlternateBytes(bytes):
        pass
    for bad in (raw[:-1], raw + b"\0", bytearray(raw), memoryview(raw), AlternateBytes(raw), None):
        assert not parse_case(bad)
    assert counts == {"accepted": 42536, "rejected": 592}
    return dict(counts), invalid_positions


def full_digest(inputs):
    h = hashlib.shake_256()
    h.update(b"PQ-RBBC/TICKET")
    h.update(inputs.m)
    return h.digest(32)


def hash_oracle(message, commitment, *, length_bytes=8):
    """Integer packing differs from the runtime's list-of-bit frame machinery.

Only the existing Anemoi parameters and eight-lane permutation are reused.
The alternate length width exists solely to form a negative transcript.
"""
    transcript = b"PQRBBC-TRANSCRIPT-V1" + (2).to_bytes(2, "little")
    for raw in (message, commitment):
        transcript += len(raw).to_bytes(length_bytes, "little") + raw
    domain = b"PQ-RBBC/v2.0/H_RBBC"
    frame = (b"PQRBBC-SPONGE-V1" + len(domain).to_bytes(2, "little") + domain
             + len(transcript).to_bytes(8, "little") + transcript)
    bit_length = len(frame) * 8
    padded_length = ((bit_length + 2 + 771) // 772) * 772
    stream = int.from_bytes(frame, "little") | (1 << bit_length) | (1 << (padded_length - 1))
    state = (0,) * 8
    field_mask = (1 << 193) - 1
    inputs = []
    for offset in range(0, padded_length, 772):
        block = (stream >> offset) & ((1 << 772) - 1)
        state = tuple(state[lane] ^ ((block >> (193 * lane)) & field_mask) if lane < 4 else state[lane]
                      for lane in range(8))
        inputs.append(state)
        state = permutation.evaluate_permutation(state, PARAMETERS)
    output = sum(state[lane] << (193 * lane) for lane in range(4)) & ((1 << 576) - 1)
    return output.to_bytes(72, "little"), inputs


def with_beta(inputs, image):
    mask = GET(inputs.witness, "issue_witness", "blind_mask")
    beta = (int.from_bytes(mask, "little") ^ int.from_bytes(image, "little")).to_bytes(72, "little")
    return inputs.edit("statement", "beta", beta)


def safe_result(result):
    assert tuple(result.__dict__) == ("partial", "checks")
    raw_builder.safe_result(result.partial)
    assert tuple(label for label, _ in result.checks) == NAMES
    assert all(type(label) is str and type(status) is target.ResearchI3HashStatus for label, status in result.checks)
    assert [result.status(name).value for name in ("CAP_rho_execution", "CAP_mask_derivation")] == ["open", "open"]
    assert all(getattr(result, name) is False for name in
               ("full_I3_verified", "full_relation_verified", "authentication_verified", "production_qualified"))
    assert result.unresolved == ("CAP_candidate_origin", "CAP_rho_execution", "CAP_mask_derivation") + result.partial.unresolved
    assert repr(result) == "ResearchI3HashEvaluation(research_only=True, full_I3_verified=False)"
    assert not hasattr(result, "accepted") and not hasattr(result, "ok")
    for value in (result, *target.ResearchI3HashStatus):
        try:
            bool(value)
        except TypeError:
            pass
        else:
            raise AssertionError("candidate diagnostic has boolean acceptance")


def real_case(inputs, commitment, states, match=True):
    original = permutation.evaluate_permutation
    original_hash = target.h_rbbc.hash_request_binding
    calls = []
    hash_calls = []

    def observe(state, parameters):
        assert parameters == PARAMETERS
        assert tuple(state) == states[len(calls)]
        calls.append(True)
        return original(state, parameters)

    def consume(digest, raw):
        assert digest == full_digest(inputs) and raw == commitment
        hash_calls.append(True)
        return original_hash(digest, raw)

    with patch.object(permutation, "evaluate_permutation", side_effect=observe), patch.object(
        target.h_rbbc, "hash_request_binding", side_effect=consume,
    ), patch.object(target.cap, "execute_cap_commit", side_effect=AssertionError("CAP execution is outside this API")) as cap_call:
        result = target.evaluate_i3_hash_candidate_research(**inputs.arguments(), cap_commitment_candidate=commitment, purpose="research")
    assert len(calls) == len(states) and len(hash_calls) == 1 and cap_call.call_count == 0
    assert result.status("I3_beta_equation").value == ("matched_unverified_cap" if match else "failed")
    assert result.status("I2_H_RBBC_consumer").value == "computed_unverified_cap"
    safe_result(result)
    return len(calls)


def flow_case(base, commitment, image, bits):
    binding_bad, salt_bad, partial_error, digest_error, hash_error, beta_bad, holder_bad = bits
    inputs = base
    if binding_bad:
        inputs = inputs.edit("statement", "ctx", changed(GET(inputs.statement, "issue_statement", "ctx"), 0))
    if beta_bad:
        inputs = inputs.edit("statement", "beta", changed(GET(inputs.statement, "issue_statement", "beta"), 71))
    if holder_bad:
        inputs = inputs.edit("witness", "holder_key", changed(GET(inputs.witness, "issue_witness", "holder_key"), 31))
    supplied = changed(commitment, 54) if salt_bad else commitment
    events = []
    original_parse = target._parse_candidate
    original_partial = target.evaluate_partial_issuance_research
    original_digest = ResearchTicketM.d_M.fget
    original_i5 = partial.check_encryption_relation_reference
    digest_calls = 0

    def parsed(raw):
        events.append("candidate")
        return original_parse(raw)

    def previous(**args):
        events.append("partial")
        return original_partial(**args)

    def digest(m):
        nonlocal digest_calls
        digest_calls += 1
        events.append("I2_partial" if digest_calls == 1 else "I2_consumer")
        assert m.encode() == base.m
        if digest_calls == 2 and digest_error:
            raise RuntimeError("PRIVATE REVIEW DIGEST FAULT")
        return original_digest(m)

    def i5(*args):
        return None if partial_error else original_i5(*args)

    def hashed(message, raw):
        events.append("H_RBBC")
        # This flow-only reuse is valid exclusively for identical oracle inputs.
        assert message == full_digest(base) and raw == commitment
        return bytearray(72) if hash_error else image

    with patch.object(target, "_parse_candidate", side_effect=parsed), patch.object(
        target, "evaluate_partial_issuance_research", side_effect=previous,
    ), patch.object(ResearchTicketM, "d_M", property(digest)), patch.object(
        partial, "check_encryption_relation_reference", side_effect=i5,
    ), patch.object(target.h_rbbc, "hash_request_binding", side_effect=hashed), patch.object(
        target.cap, "execute_cap_commit", side_effect=AssertionError("unexpected CAP execution"),
    ) as cap_call:
        result = target.evaluate_i3_hash_candidate_research(**inputs.arguments(), cap_commitment_candidate=supplied, purpose="research")
    assert cap_call.call_count == 0
    expected = ["passed", "not_evaluated", "not_evaluated", "not_evaluated", "open", "open"]
    order = ["candidate", "partial"]
    if not binding_bad:
        order.append("I2_partial")
        assert result.partial.status("I4").value == ("failed" if holder_bad else "passed")
        assert result.partial.status("I5").value == ("error" if partial_error else "passed")
        if not partial_error:
            expected[1] = "failed" if salt_bad else "passed"
            if not salt_bad:
                order.append("I2_consumer")
                expected[2] = "error"
                if not digest_error:
                    order.append("H_RBBC")
                    if not hash_error:
                        expected[2] = "computed_unverified_cap"
                        expected[3] = "failed" if beta_bad else "matched_unverified_cap"
    assert [status.value for _, status in result.checks] == expected
    assert events == order
    safe_result(result)
    return expected[3]


def public_rejections(inputs, commitment, positions):
    for offset, bit in positions:
        with patch.object(target, "evaluate_partial_issuance_research") as before, patch.object(
            target.h_rbbc, "hash_request_binding",
        ) as hashed:
            try:
                target.evaluate_i3_hash_candidate_research(**inputs.arguments(),
                    cap_commitment_candidate=changed(commitment, offset, bit), purpose="research")
            except ContractError:
                pass
            else:
                raise AssertionError("malformed candidate entered partial crypto")
        assert before.call_count == hashed.call_count == 0
    poison = {key: object() for key in inputs.arguments()}
    poison["cap_commitment_candidate"] = object()
    for purpose in ({}, {"purpose": "production"}, {"purpose": True}, {"purpose": b"research"}):
        error = Unsupported if purpose.get("purpose", "production") == "production" else ContractError
        with patch.object(target, "_check_profiles") as profiles, patch.object(target, "_parse_candidate") as parsed:
            try:
                target.evaluate_i3_hash_candidate_research(**poison, **purpose)
            except error:
                pass
            else:
                raise AssertionError("purpose did not reject")
        assert profiles.call_count == parsed.call_count == 0


def main():
    target._check_profiles()
    pk = raw_builder.synthetic_public_key("I3-review-matrix")
    inputs = raw_builder.fixture("I3-review-inputs", pk, raw_builder.sample("I3-review-u", 128))
    commitment = candidate(inputs, "A")
    shape_counts, invalid = check_grammar(commitment)
    image, states = hash_oracle(full_digest(inputs), commitment)
    base = with_beta(inputs, image)
    permutations = [real_case(base, commitment, states)]
    alternate = candidate(inputs, "B")
    alt_image, alt_states = hash_oracle(full_digest(inputs), alternate)
    permutations.append(real_case(with_beta(inputs, alt_image), alternate, alt_states))
    changed_pp = inputs.edit("common_pp", "issue_backend_pp_sha256", hashlib.sha256(b"I3 review metadata change").digest()).repoint()
    pp_image, pp_states = hash_oracle(full_digest(changed_pp), commitment)
    permutations.append(real_case(with_beta(changed_pp, pp_image), commitment, pp_states))
    wrong_image, _ = hash_oracle(full_digest(inputs), commitment, length_bytes=4)
    assert wrong_image != image
    permutations.append(real_case(with_beta(inputs, wrong_image), commitment, states, match=False))
    flow = Counter(flow_case(base, commitment, image, bits) for bits in itertools.product((False, True), repeat=7))
    public_rejections(base, commitment, invalid)
    print(json.dumps({
        "schema": "pqc_auth.gf_i3_hash_review_experiment.v0_1", "CAP_profile_sha256": CAP_FP,
        "candidate_single_bit_mutations": {"total": 43128, **shape_counts},
        "additional_numeric_boundaries_accepted": 2, "additional_type_length_rejections": 6,
        "public_candidate_rejections_before_partial_crypto": len(invalid), "purpose_preparse_rejections": 4,
        "real_hash_differential_cases": {"matched": 3, "wrong_u32_transcript_beta_rejected": 1,
            "permutation_input_states_compared_per_case": permutations},
        "flow_combinations": 128, "flow_beta_status_counts": dict(sorted(flow.items())),
        "status_or_call_order_disagreements": 0, "candidate_grammar_disagreements": 0,
        "precomputed_oracle_image_reused_for_flow_only": True, "shared_Anemoi_permutation": True,
        "raw_private_values_emitted": False, "CAP_executed": False, "full_I3_verified": False,
        "external_independent_review": False, "proof_closed": False, "production_closed": False,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
