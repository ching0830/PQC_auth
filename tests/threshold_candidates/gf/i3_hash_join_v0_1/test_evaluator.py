from dataclasses import fields, replace
import hashlib
import unittest
from unittest.mock import patch

import pq_rbbc_anemoi_sponge as sponge
import pq_rbbc_cap_commit as cap
from pq_threshold_candidates import ContractError, Unsupported
from pq_threshold_candidates.gf import keygen_reference_for_test
from pq_threshold_candidates.gf.i3_hash_join_v0_1 import (
    ResearchI3HashEvaluation, ResearchI3HashStatus as S,
    evaluate_i3_hash_candidate_research,
)
from pq_threshold_candidates.gf.i3_hash_join_v0_1 import evaluator as join
from pq_threshold_candidates.gf.partial_issuance_v0_1 import ResearchPartialCheckStatus as P
from pq_threshold_candidates.gf.partial_issuance_v0_1 import evaluator as partial
from pq_threshold_candidates.gf.research_abi_v0_1 import ResearchTicketM
from ..research_abi_v0_1._fixtures import fixture, sha


def flip(raw, offset=0, bit=0):
    return raw[:offset] + bytes([raw[offset] ^ (1 << bit)]) + raw[offset + 1:]


def xor(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


class I3HashCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pk, _ = keygen_reference_for_test(sha(b"GF I3 candidate hash tests"))
        cls.f = fixture(cls.pk)
        rho = cls.f.w.cap_randomness
        salts = tuple(int.from_bytes(rho[i:i + 25], "little") for i in (84, 109))
        # A structurally canonical, synthetic commitment. No CAP(rho) execution.
        cls.candidate = cap.serialize_commitment(cap.PRODUCTION_PARAMETERS, salts,
            (1 << 385) + 7, (1 << 385) + 9,
            tuple((1 << 2047) + i for i in range(17)),
            tuple((1 << 385) + i for i in range(17)))
        # Real Anemoi, explicitly framed without hash_request_binding wrapper.
        m = cls.f.m.encode()
        cls.digest = hashlib.shake_256(b"PQ-RBBC/TICKET" + m).digest(32)
        transcript = (b"PQRBBC-TRANSCRIPT-V1" + (2).to_bytes(2, "little")
                      + (32).to_bytes(8, "little") + cls.digest
                      + (5391).to_bytes(8, "little") + cls.candidate)
        cls.image = sponge.evaluate_sponge(b"PQ-RBBC/v2.0/H_RBBC", transcript, 72)
        cls.x = replace(cls.f.statement, beta=xor(cls.f.w.blind_mask, cls.image))

    def args(self, **overrides):
        result = dict(common_pp=self.f.pp.encode(), tpk_record=self.pk.encode(),
                      statement=self.x.encode(), witness=self.f.w.encode(),
                      cap_commitment_candidate=self.candidate, purpose="research")
        result.update(overrides)
        return result

    def limited(self, result):
        self.assertIs(result.partial.status("I3"), P.OPEN)
        self.assertIs(result.status("CAP_rho_execution"), S.OPEN)
        self.assertIs(result.status("CAP_mask_derivation"), S.OPEN)
        for name in ("full_I3_verified", "full_relation_verified", "authentication_verified", "production_qualified"):
            self.assertIs(getattr(result, name), False)
        self.assertIn("CAP_candidate_origin", result.unresolved)
        self.assertIn("native_constraints", result.unresolved)
        return result

    def cached_hash_call(self, **overrides):
        """Reuse the real baseline image only for identical hash inputs."""
        def checked(message, candidate):
            self.assertEqual((message, candidate), (self.digest, self.candidate))
            return self.image
        with patch.object(join.h_rbbc, "hash_request_binding", side_effect=checked) as hashed:
            result = evaluate_i3_hash_candidate_research(**self.args(**overrides))
        self.assertEqual(hashed.call_count, 1)
        return self.limited(result)

    def assert_skipped(self, result):
        self.limited(result)
        self.assertIs(result.status("I2_H_RBBC_consumer"), S.NOT_EVALUATED)
        self.assertIs(result.status("I3_beta_equation"), S.NOT_EVALUATED)

    def test_real_H_RBBC_consumes_full_M_and_exact_candidate(self):
        original = sponge.hash_request_binding
        with patch.object(join.h_rbbc, "hash_request_binding", wraps=original) as hashed, patch.object(
            cap, "execute_cap_commit", side_effect=AssertionError("must not execute CAP"),
        ) as executed:
            result = evaluate_i3_hash_candidate_research(**self.args())
        hashed.assert_called_once_with(self.digest, self.candidate)
        self.assertEqual(executed.call_count, 0)
        self.assertIs(result.status("I2_H_RBBC_consumer"), S.COMPUTED_UNVERIFIED_CAP)
        self.assertIs(result.status("I3_beta_equation"), S.MATCHED_UNVERIFIED_CAP)
        self.assertIs(result.partial.status("I2_digest"), P.COMPUTED_UNJOINED)
        self.limited(result)

    def test_both_digest_calculations_hash_same_full_packet(self):
        original = ResearchTicketM.d_M.fget
        packets = []
        def observe(m):
            packets.append(m.encode())
            return original(m)
        with patch.object(ResearchTicketM, "d_M", property(observe)):
            self.cached_hash_call()
        self.assertEqual(packets, [self.f.m.encode()] * 2)

    def test_real_hash_changes_when_pp_header_changes(self):
        pp = replace(self.f.pp, issue_backend_pp_sha256=sha(b"different unverified backend"))
        m = replace(self.f.m, common_pp_sha256=pp.sha256)
        w = replace(self.f.w, ticket_m=m)
        x = replace(self.x, common_pp_sha256=pp.sha256)
        with patch.object(join.h_rbbc, "hash_request_binding", wraps=sponge.hash_request_binding) as hashed:
            result = evaluate_i3_hash_candidate_research(**self.args(common_pp=pp.encode(), statement=x.encode(), witness=w.encode()))
        hashed.assert_called_once_with(hashlib.shake_256(b"PQ-RBBC/TICKET" + m.encode()).digest(32), self.candidate)
        self.assertNotEqual(hashed.call_args.args[0], self.digest)
        self.assertIs(result.status("I3_beta_equation"), S.FAILED)
        self.assertIs(result.partial.status("I5"), P.PASSED)
        self.limited(result)

    def test_real_hash_includes_all_C_bytes_even_if_I5_fails(self):
        m = replace(self.f.m, ciphertext_payload=flip(self.f.m.ciphertext_payload, 2847))
        result = evaluate_i3_hash_candidate_research(**self.args(witness=replace(self.f.w, ticket_m=m).encode()))
        self.assertIs(result.partial.status("I5"), P.FAILED)
        self.assertIs(result.status("I3_beta_equation"), S.FAILED)
        self.limited(result)

    def test_real_hash_includes_candidate_corrections(self):
        candidate = flip(self.candidate, 5390)
        result = evaluate_i3_hash_candidate_research(**self.args(cap_commitment_candidate=candidate))
        self.assertIs(result.status("CAP_candidate_codecs"), S.PASSED)
        self.assertIs(result.status("I3_beta_equation"), S.FAILED)
        self.assertIs(result.partial.status("I5"), P.PASSED)
        self.limited(result)

    def test_beta_and_mask_mutations_fail_candidate_equation(self):
        for position in (0, 35, 71):
            with self.subTest(position=position):
                result = self.cached_hash_call(statement=replace(self.x, beta=flip(self.x.beta, position)).encode())
                self.assertIs(result.status("I3_beta_equation"), S.FAILED)
                result = self.cached_hash_call(witness=replace(self.f.w, blind_mask=flip(self.f.w.blind_mask, position)).encode())
                self.assertIs(result.status("I3_beta_equation"), S.FAILED)

    def test_coherent_arbitrary_mask_beta_repair_does_not_verify_CAP_mask(self):
        arbitrary_mask = bytes(72)
        w = replace(self.f.w, blind_mask=arbitrary_mask)
        x = replace(self.x, beta=xor(arbitrary_mask, self.image))
        result = self.cached_hash_call(statement=x.encode(), witness=w.encode())
        self.assertIs(result.status("I3_beta_equation"), S.MATCHED_UNVERIFIED_CAP)
        self.assertIs(result.status("CAP_mask_derivation"), S.OPEN)

    def test_changed_rho_roots_can_match_because_CAP_execution_is_open(self):
        for offset in (136, 1011):
            with self.subTest(offset=offset):
                w = replace(self.f.w, cap_randomness=flip(self.f.w.cap_randomness, offset))
                result = self.cached_hash_call(witness=w.encode())
                self.assertIs(result.status("I3_beta_equation"), S.MATCHED_UNVERIFIED_CAP)

    def test_ordinary_I4_and_I5_mismatches_allow_local_hash_diagnostic(self):
        w = replace(self.f.w, holder_key=flip(self.f.w.holder_key))
        result = self.cached_hash_call(witness=w.encode())
        self.assertIs(result.partial.status("I4"), P.FAILED)
        x = replace(self.x, rid=flip(self.x.rid))
        result = self.cached_hash_call(statement=x.encode())
        self.assertIs(result.partial.status("I5"), P.FAILED)
        self.assertIs(result.status("I3_beta_equation"), S.MATCHED_UNVERIFIED_CAP)

    def test_salt_mismatch_skips_hash(self):
        for offset in (54, 79):
            with self.subTest(offset=offset), patch.object(join.h_rbbc, "hash_request_binding") as hashed:
                result = evaluate_i3_hash_candidate_research(**self.args(cap_commitment_candidate=flip(self.candidate, offset)))
                self.assertEqual(hashed.call_count, 0)
                self.assertIs(result.status("CAP_salt_binding"), S.FAILED)
                self.assert_skipped(result)

    def test_binding_mismatches_skip_hash(self):
        cases = [dict(statement=replace(self.x, common_pp_sha256=sha(b"wrong pp")).encode()),
                 dict(witness=replace(self.f.w, ticket_m=replace(self.f.m, common_pp_sha256=sha(b"wrong pp"))).encode()),
                 dict(statement=replace(self.x, ctx=flip(self.x.ctx)).encode()),
                 dict(witness=replace(self.f.w, ticket_m=replace(self.f.m, ctx=flip(self.f.m.ctx))).encode()),
                 dict(common_pp=replace(self.f.pp, trace_binding=replace(self.f.binding, tpk_record_sha256=sha(b"wrong key"))).encode())]
        for override in cases:
            with self.subTest(fields=tuple(override)), patch.object(join.h_rbbc, "hash_request_binding") as hashed:
                self.assert_skipped(evaluate_i3_hash_candidate_research(**self.args(**override)))
                self.assertEqual(hashed.call_count, 0)

    def test_all_inputs_require_exact_bytes_and_lengths(self):
        class AlternateBytes(bytes):
            pass
        for name, raw in self.args().items():
            if name == "purpose":
                continue
            for value in (raw[:-1], raw + b"\0", bytearray(raw), memoryview(raw), AlternateBytes(raw), None):
                with self.subTest(name=name, kind=type(value)), patch.object(partial, "check_encryption_relation_reference") as i5, patch.object(
                    join.h_rbbc, "hash_request_binding",
                ) as hashed:
                    with self.assertRaises(ContractError):
                        evaluate_i3_hash_candidate_research(**self.args(**{name: value}))
                    self.assertEqual((i5.call_count, hashed.call_count), (0, 0))

    def test_candidate_domains_lengths_and_every_padding_field_reject(self):
        bad = [flip(self.candidate, i) for i in (0, 20, 22, 153)]
        # 193-bit salts; 386-bit h2, alpha and all 17 delta_mhat values.
        for last, allowed in ((78, 1), (103, 1), (152, 2), (205, 2),
                              *((510 + 305 * i, 2) for i in range(17))):
            for bit in range(allowed, 8):
                bad.append(flip(self.candidate, last, bit))
        for raw in bad:
            with self.subTest(candidate=sha(raw).hex()), patch.object(join, "evaluate_partial_issuance_research") as before, patch.object(
                join.h_rbbc, "hash_request_binding",
            ) as hashed:
                with self.assertRaises(ContractError):
                    evaluate_i3_hash_candidate_research(**self.args(cap_commitment_candidate=raw))
                self.assertEqual((before.call_count, hashed.call_count), (0, 0))

    def test_candidate_boundary_values_are_grammar_only(self):
        salts = tuple(int.from_bytes(self.f.w.cap_randomness[i:i + 25], "little") for i in (84, 109))
        for maximal in (False, True):
            value = lambda bits: (1 << bits) - 1 if maximal else 0
            raw = cap.serialize_commitment(cap.PRODUCTION_PARAMETERS, salts, value(386), value(386),
                (value(2048),) * 17, (value(386),) * 17)
            with patch.object(join.h_rbbc, "hash_request_binding") as hashed:
                result = evaluate_i3_hash_candidate_research(**self.args(cap_commitment_candidate=raw,
                    statement=replace(self.x, ctx=flip(self.x.ctx)).encode()))
                self.assertIs(result.status("CAP_candidate_codecs"), S.PASSED)
                self.assertEqual(hashed.call_count, 0)
                self.assert_skipped(result)

    def test_reduced_profile_and_alternate_canonical_encoding_reject(self):
        reduced = cap.serialize_commitment(cap.REDUCED_TEST_PARAMETERS, (1, 2), 3, 4, (5,), (6,))
        with self.assertRaises(ContractError):
            evaluate_i3_hash_candidate_research(**self.args(cap_commitment_candidate=reduced))
        with patch.object(cap, "serialize_commitment", return_value=self.candidate + b"\0"):
            with self.assertRaises(ContractError):
                evaluate_i3_hash_candidate_research(**self.args())

    def test_runtime_profile_drift_fails_before_parsing(self):
        for module, method in ((cap, "profile_fingerprint"), (sponge, "profile_fingerprint")):
            with patch.object(module, method, return_value="0" * 64), patch.object(join, "_parse_candidate") as parsed:
                with self.assertRaises(Unsupported):
                    evaluate_i3_hash_candidate_research(**self.args())
                self.assertEqual(parsed.call_count, 0)

    def test_default_and_explicit_production_refuse_before_profile_or_parse(self):
        args = {key: object() for key in self.args() if key != "purpose"}
        for extra in ({}, {"purpose": "production"}):
            with patch.object(join, "_check_profiles") as profiles, patch.object(join, "_parse_candidate") as parsed:
                with self.assertRaises(Unsupported):
                    evaluate_i3_hash_candidate_research(**args, **extra)
                self.assertEqual((profiles.call_count, parsed.call_count), (0, 0))

    def test_unknown_or_alternate_purpose_types_reject_before_profiles(self):
        class AlternateString(str):
            pass
        for value in (None, 1, True, b"research", "Research", AlternateString("research")):
            with patch.object(join, "_check_profiles") as profiles:
                with self.assertRaises(ContractError):
                    evaluate_i3_hash_candidate_research(**self.args(purpose=value))
                self.assertEqual(profiles.call_count, 0)

    def test_partial_I5_computation_fault_skips_hash(self):
        with patch.object(partial, "check_encryption_relation_reference", side_effect=RuntimeError("PRIVATE FAULT")), patch.object(
            join.h_rbbc, "hash_request_binding",
        ) as hashed:
            result = evaluate_i3_hash_candidate_research(**self.args())
        self.assertIs(result.partial.status("I5"), P.ERROR)
        self.assertEqual(hashed.call_count, 0)
        self.assert_skipped(result)

    def test_partial_I2_and_I4_computation_faults_skip_hash(self):
        def broken_digest(m):
            raise RuntimeError("PRIVATE I2 FAULT")
        original = hashlib.shake_256
        def broken_holder(raw=b""):
            if raw.startswith(b"PQ-RBBC/HOLD"):
                raise RuntimeError("PRIVATE I4 FAULT")
            return original(raw)
        for stage, injected in (("I2_digest", patch.object(ResearchTicketM, "d_M", property(broken_digest))),
                                ("I4", patch.object(partial.hashlib, "shake_256", side_effect=broken_holder))):
            with injected, patch.object(join.h_rbbc, "hash_request_binding") as hashed:
                result = evaluate_i3_hash_candidate_research(**self.args())
            self.assertIs(result.partial.status(stage), P.ERROR)
            self.assertEqual(hashed.call_count, 0)
            self.assert_skipped(result)

    def test_second_digest_fault_is_error_and_skips_hash(self):
        count = 0
        def digest(m):
            nonlocal count
            count += 1
            if count == 1:
                return self.digest
            raise RuntimeError("PRIVATE SECOND DIGEST")
        with patch.object(ResearchTicketM, "d_M", property(digest)), patch.object(join.h_rbbc, "hash_request_binding") as hashed:
            result = evaluate_i3_hash_candidate_research(**self.args())
        self.assertEqual((count, hashed.call_count), (2, 0))
        self.assertIs(result.status("I2_H_RBBC_consumer"), S.ERROR)
        self.assertIs(result.status("I3_beta_equation"), S.NOT_EVALUATED)
        self.limited(result)

    def test_hash_fault_or_noncanonical_output_never_matches(self):
        for value in (None, 1, b"", bytes(71), bytes(73), bytearray(72), RuntimeError("PRIVATE HASH FAULT")):
            effects = {"side_effect": value} if isinstance(value, Exception) else {"return_value": value}
            with patch.object(join.h_rbbc, "hash_request_binding", **effects):
                result = evaluate_i3_hash_candidate_research(**self.args())
            self.assertIs(result.status("I2_H_RBBC_consumer"), S.ERROR)
            self.assertIs(result.status("I3_beta_equation"), S.NOT_EVALUATED)
            self.assertNotIn("PRIVATE", repr(result))
            self.limited(result)

    def test_diagnostic_contains_only_statuses_and_refuses_boolean_acceptance(self):
        result = self.cached_hash_call()
        self.assertEqual(tuple(f.name for f in fields(result)), ("partial", "checks"))
        self.assertEqual(tuple(f.name for f in fields(result.partial)), ("checks",))
        self.assertEqual(repr(result), "ResearchI3HashEvaluation(research_only=True, full_I3_verified=False)")
        for value in (result, *S):
            with self.assertRaises(TypeError):
                bool(value)
        for name in ("ok", "accepted", "digest", "candidate", "hash_image", "mask", "expected_beta"):
            self.assertFalse(hasattr(result, name))
        with self.assertRaises(ContractError):
            result.status("unknown")

    def test_constructed_status_cannot_promote_CAP_or_I3(self):
        result = self.cached_hash_call()
        for name in ("CAP_rho_execution", "CAP_mask_derivation", "I2_H_RBBC_consumer", "I3_beta_equation"):
            checks = tuple((key, S.PASSED if key == name else value) for key, value in result.checks)
            with self.assertRaises(ContractError):
                ResearchI3HashEvaluation(result.partial, checks)
        with self.assertRaises(ContractError):
            ResearchI3HashEvaluation(result.partial, list(result.checks))
        with self.assertRaises(ContractError):
            ResearchI3HashEvaluation(object(), result.checks)

    def test_no_caller_provider_or_claim_override_is_accepted(self):
        for name in ("cap_executor", "verifier", "verified", "allow_large", "derived_mask", "partial"):
            with self.assertRaises(TypeError):
                evaluate_i3_hash_candidate_research(**self.args(), **{name: True})


if __name__ == "__main__":
    unittest.main()
