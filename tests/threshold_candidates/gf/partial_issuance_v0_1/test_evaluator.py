from dataclasses import fields, replace
import hashlib
import unittest
from unittest.mock import patch

import pq_rbbc_cap_commit as cap
from pq_threshold_candidates import ContractError, TraceInputs, Unsupported
from pq_threshold_candidates.gf import (
    ReferenceWitness, check_encryption_relation_reference, encrypt_reference,
    keygen_reference_for_test,
)
from pq_threshold_candidates.gf.partial_issuance_v0_1 import (
    ResearchPartialCheckStatus as S, ResearchPartialIssuanceEvaluation,
    evaluate_partial_issuance_research,
)
from pq_threshold_candidates.gf.research_abi_v0_1 import ResearchTicketM
from ..research_abi_v0_1._fixtures import fixture, sha


MODULE = "pq_threshold_candidates.gf.partial_issuance_v0_1.evaluator"


def flip(raw, offset=0):
    return raw[:offset] + bytes([raw[offset] ^ 1]) + raw[offset + 1:]


def arguments(f):
    return dict(common_pp=f.pp.encode(), tpk_record=f.pk.encode(),
                statement=f.statement.encode(), witness=f.w.encode(), purpose="research")


class PartialEvaluatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pk, _ = keygen_reference_for_test(sha(b"partial GF evaluator A"))
        cls.other_pk, _ = keygen_reference_for_test(sha(b"partial GF evaluator B"))
        # Real reference I4/I5, canonical rho; r/beta are NOT a full I3 instance.
        cls.f = fixture(cls.pk)

    def evaluate(self, *, x=None, w=None, pp=None, pk=None):
        return evaluate_partial_issuance_research(
            common_pp=(self.f.pp if pp is None else pp).encode(),
            tpk_record=(self.pk if pk is None else pk).encode(),
            statement=(self.f.statement if x is None else x).encode(),
            witness=(self.f.w if w is None else w).encode(), purpose="research",
        )

    def rebind_pp(self, pp, *, pk=None, f=None):
        f = self.f if f is None else f
        m = replace(f.m, common_pp_sha256=pp.sha256)
        return self.evaluate(pp=pp, pk=pk, x=replace(f.statement, common_pp_sha256=pp.sha256),
                             w=replace(f.w, ticket_m=m))

    def assertPartialOnly(self, result):
        self.assertIs(result.status("I3"), S.OPEN)
        self.assertFalse(result.full_relation_verified)
        self.assertFalse(result.authentication_verified)
        self.assertFalse(result.production_qualified)
        self.assertIn("I2_to_I3_join", result.unresolved)
        self.assertIn("key_origin_certification", result.unresolved)
        self.assertIn("native_constraints", result.unresolved)

    def assertBindingFailure(self, result, label):
        self.assertIs(result.status(label), S.FAILED)
        for name in ("I2_digest", "I4", "I5"):
            self.assertIs(result.status(name), S.NOT_EVALUATED)
        self.assertPartialOnly(result)

    def test_canonical_partial_fixture_never_yields_full_acceptance(self):
        result = self.evaluate()
        for name, status in result.checks:
            expected = S.OPEN if name == "I3" else S.COMPUTED_UNJOINED if name == "I2_digest" else S.PASSED
            self.assertIs(status, expected, name)
        self.assertEqual(result.failed_checks, ())
        self.assertEqual(result.errored_checks, ())
        self.assertPartialOnly(result)
        self.assertFalse(hasattr(result, "ok"))
        self.assertFalse(hasattr(result, "accepted"))

    def test_diagnostic_and_every_status_refuse_boolean_use(self):
        with self.assertRaises(TypeError):
            bool(self.evaluate())
        for status in S:
            with self.assertRaises(TypeError):
                bool(status)

    def test_I2_computes_exact_full_M_and_keeps_digest_private(self):
        seen = []
        original = ResearchTicketM.d_M.fget
        def observe(m):
            digest = original(m)
            seen.append((m.encode(), digest))
            return digest
        with patch.object(ResearchTicketM, "d_M", property(observe)):
            result = self.evaluate()
        self.assertEqual(len(seen), 1)
        raw, digest = seen[0]
        self.assertTrue(raw == self.f.m.encode())
        self.assertTrue(digest == hashlib.shake_256(b"PQ-RBBC/TICKET" + raw).digest(32))
        self.assertTrue(digest != hashlib.shake_256(b"PQ-RBBC/TICKET" + raw[77:]).digest(32))
        self.assertIs(result.status("I2_digest"), S.COMPUTED_UNJOINED)
        self.assertEqual([field.name for field in fields(result)], ["checks"])
        self.assertFalse(hasattr(result, "d_M"))

    def test_PP_header_change_changes_I2_without_implying_verified_join(self):
        seen = []
        original = ResearchTicketM.d_M.fget
        def observe(m):
            digest = original(m)
            seen.append(digest)
            return digest
        with patch.object(ResearchTicketM, "d_M", property(observe)):
            first = self.evaluate()
            second = self.rebind_pp(replace(self.f.pp, issue_backend_pp_sha256=sha(b"other opaque PP")))
        self.assertEqual(len(seen), 2)
        self.assertTrue(seen[0] != seen[1])
        self.assertEqual(first.checks, second.checks)
        self.assertPartialOnly(second)

    def test_default_and_explicit_production_stop_before_input_touch(self):
        poison = object()
        inputs = dict.fromkeys(("common_pp", "tpk_record", "statement", "witness"), poison)
        for optional in ({}, {"purpose": "production"}):
            with patch(MODULE + ".ResearchCommonPP.decode") as decode:
                with patch(MODULE + ".check_encryption_relation_reference") as i5:
                    with self.assertRaises(Unsupported):
                        evaluate_partial_issuance_research(**inputs, **optional)
                    decode.assert_not_called()
                    i5.assert_not_called()
        with self.assertRaises(Unsupported):
            evaluate_partial_issuance_research(**dict(arguments(self.f), purpose="production"))

    def test_unknown_or_alternate_purpose_types_refuse_before_parse(self):
        class AlternateString(str):
            pass
        for purpose in (None, True, 1, b"research", "Research", "test", AlternateString("research")):
            with patch(MODULE + ".ResearchCommonPP.decode") as decode:
                with self.assertRaises(ContractError):
                    evaluate_partial_issuance_research(**dict(arguments(self.f), purpose=purpose))
                decode.assert_not_called()

    def test_strict_immutable_inputs_and_framing_precede_I5(self):
        class AlternateBytes(bytes):
            pass
        inputs = arguments(self.f)
        for name in ("common_pp", "tpk_record", "statement", "witness"):
            raw = inputs[name]
            for changed in (raw[:-1], raw + b"\0", bytearray(raw), memoryview(raw), AlternateBytes(raw), None):
                with self.subTest(input=name, kind=type(changed).__name__):
                    with patch(MODULE + ".check_encryption_relation_reference") as i5:
                        with self.assertRaises(ContractError):
                            evaluate_partial_issuance_research(**dict(inputs, **{name: changed}))
                        i5.assert_not_called()

    def test_nested_M_ABI_and_CAP_padding_mutations_reject(self):
        # W.M starts at 51; M ABI starts at 13. CAP starts at 3128;
        # first field's top byte is 108 bytes into CAP randomness.
        for offset, bit in ((51 + 13, 1), (3128 + 108, 2)):
            raw = bytearray(self.f.w.encode())
            raw[offset] ^= bit
            with patch(MODULE + ".check_encryption_relation_reference") as i5:
                with self.assertRaises(ContractError):
                    evaluate_partial_issuance_research(**dict(arguments(self.f), witness=bytes(raw)))
                i5.assert_not_called()

    def test_statement_and_M_pp_mismatch_skip_crypto(self):
        for label, x, w in (
            ("P0_statement_pp", replace(self.f.statement, common_pp_sha256=sha(b"wrong")), None),
            ("P0_ticket_pp", None, replace(self.f.w, ticket_m=replace(self.f.m, common_pp_sha256=sha(b"wrong")))),
        ):
            with patch(MODULE + ".check_encryption_relation_reference") as i5:
                self.assertBindingFailure(self.evaluate(x=x, w=w), label)
                i5.assert_not_called()

    def test_capsule_digest_is_not_full_common_PP_digest(self):
        wrong = sha(self.f.binding.encode())
        result = self.evaluate(x=replace(self.f.statement, common_pp_sha256=wrong),
                               w=replace(self.f.w, ticket_m=replace(self.f.m, common_pp_sha256=wrong)))
        self.assertBindingFailure(result, "P0_statement_pp")
        self.assertBindingFailure(result, "P0_ticket_pp")

    def test_context_mismatches_skip_crypto(self):
        cases = (
            ("I1_statement_ctx", replace(self.f.statement, ctx=sha(b"other ctx")), None),
            ("I1_ticket_ctx", None, replace(self.f.w, ticket_m=replace(self.f.m, ctx=sha(b"other ctx")))),
        )
        for label, x, w in cases:
            with patch(MODULE + ".check_encryption_relation_reference") as i5:
                self.assertBindingFailure(self.evaluate(x=x, w=w), label)
                i5.assert_not_called()
        pp = replace(self.f.pp, trace_binding=replace(self.f.binding, ctx=sha(b"other binding ctx")))
        self.assertBindingFailure(self.rebind_pp(pp), "I1_statement_ctx")

    def test_zero_u_cross_key_I5_does_not_override_record_mismatch(self):
        f = fixture(self.pk, bytes(128))
        self.assertTrue(check_encryption_relation_reference(
            self.other_pk, f.x, f.m.ciphertext_research(), f.w.trace_witness_research()))
        with patch(MODULE + ".check_encryption_relation_reference") as i5:
            result = evaluate_partial_issuance_research(**dict(arguments(f), tpk_record=self.other_pk.encode()))
            self.assertBindingFailure(result, "P0_trace_key")
            i5.assert_not_called()

    def test_replacing_whole_consistent_setup_is_not_authentication(self):
        f = fixture(self.pk, bytes(128))
        pp = replace(f.pp, trace_binding=replace(f.binding, tpk_record_sha256=sha(self.other_pk.encode())))
        result = self.rebind_pp(pp, pk=self.other_pk, f=f)
        self.assertEqual(result.failed_checks, ())
        self.assertIs(result.status("I5"), S.PASSED)
        self.assertIn("configuration_authentication", result.unresolved)
        self.assertPartialOnly(result)

    def test_statement_rid_changes_I5_plaintext(self):
        result = self.evaluate(x=replace(self.f.statement, rid=flip(self.f.statement.rid)))
        self.assertEqual(result.failed_checks, ("I5",))
        self.assertIs(result.status("I4"), S.PASSED)

    def test_ticket_sn_is_same_AD_and_plaintext_input(self):
        result = self.evaluate(w=replace(self.f.w, ticket_m=replace(self.f.m, sn=flip(self.f.m.sn))))
        self.assertEqual(result.failed_checks, ("I5",))

    def test_ticket_h_mutation_fails_both_I4_and_I5(self):
        result = self.evaluate(w=replace(self.f.w, ticket_m=replace(self.f.m, h=flip(self.f.m.h))))
        self.assertEqual(result.failed_checks, ("I4", "I5"))

    def test_holder_key_mutation_does_not_silently_replace_M_h_in_I5(self):
        result = self.evaluate(w=replace(self.f.w, holder_key=flip(self.f.w.holder_key)))
        self.assertEqual(result.failed_checks, ("I4",))
        self.assertIs(result.status("I5"), S.PASSED)
        self.assertPartialOnly(result)

    def test_trace_u_mutation_fails_I5(self):
        self.assertEqual(self.evaluate(w=replace(self.f.w, trace_u=flip(self.f.w.trace_u))).failed_checks, ("I5",))

    def test_every_ciphertext_component_first_and_last_byte_is_compared(self):
        for start, end in ((0, 2560), (2560, 2688), (2688, 2720), (2720, 2848)):
            for offset in (start, end - 1):
                with self.subTest(offset=offset):
                    m = replace(self.f.m, ciphertext_payload=flip(self.f.m.ciphertext_payload, offset))
                    self.assertEqual(self.evaluate(w=replace(self.f.w, ticket_m=m)).failed_checks, ("I5",))

    def test_changed_consistent_holder_rid_and_sn_pass_local_checks(self):
        holder = sha(b"another test holder")
        h = hashlib.shake_256(b"PQ-RBBC/HOLD" + holder).digest(32)
        trace = TraceInputs(sha(b"another rid"), bytes(16), self.f.x.ctx, h)
        c = encrypt_reference(self.pk, trace, ReferenceWitness(self.f.w.trace_u))
        m = replace(self.f.m, sn=trace.sn, h=trace.h, ciphertext_payload=c.payload)
        result = self.evaluate(x=replace(self.f.statement, rid=trace.rid),
                               w=replace(self.f.w, ticket_m=m, holder_key=holder))
        self.assertEqual(result.failed_checks, ())
        self.assertIs(result.status("I5"), S.PASSED)
        self.assertPartialOnly(result)

    def test_canonical_beta_r_rho_mutations_remain_OPEN_without_CAP_execution(self):
        baseline = self.evaluate()
        cases = (
            (replace(self.f.statement, beta=flip(self.f.statement.beta)), None),
            (None, replace(self.f.w, blind_mask=flip(self.f.w.blind_mask))),
            (None, replace(self.f.w, cap_randomness=flip(self.f.w.cap_randomness, 84))),
        )
        with patch.object(cap, "execute_cap_commit", side_effect=AssertionError("unexpected CAP")) as execute:
            for x, w in cases:
                result = self.evaluate(x=x, w=w)
                self.assertEqual(result.checks, baseline.checks)
                self.assertPartialOnly(result)
            execute.assert_not_called()

    def test_sid_and_opaque_configuration_claims_are_not_authenticated(self):
        self.assertEqual(self.evaluate(x=replace(self.f.statement, sid=bytes(32))).checks, self.evaluate().checks)
        pp = replace(self.f.pp, trace_binding=replace(self.f.binding, epoch=9,
                     configuration_sha256=sha(b"unverified configuration"),
                     key_origin_evidence_sha256=sha(b"unverified origin")))
        result = self.rebind_pp(pp)
        self.assertEqual(result.failed_checks, ())
        self.assertIn("issuer_identity_session_authorization", result.unresolved)
        self.assertPartialOnly(result)

    def test_legal_extreme_u_and_repeat_do_not_imply_freshness(self):
        for u in (bytes(128), b"\xff" * 128):
            f = fixture(self.pk, u)
            with patch("secrets.token_bytes", side_effect=AssertionError("unexpected sampler")) as sampler:
                first = evaluate_partial_issuance_research(**arguments(f))
                second = evaluate_partial_issuance_research(**arguments(f))
                sampler.assert_not_called()
            self.assertEqual(first.checks, second.checks)
            self.assertEqual(first.failed_checks, ())
            self.assertIn("witness_freshness", first.unresolved)

    def test_I5_exception_or_non_boolean_result_is_ERROR(self):
        for value in (1, 0, None, "yes"):
            with patch(MODULE + ".check_encryption_relation_reference", return_value=value):
                result = self.evaluate()
            self.assertEqual(result.errored_checks, ("I5",))
            self.assertPartialOnly(result)
        with patch(MODULE + ".check_encryption_relation_reference", side_effect=RuntimeError("SECRET-FAULT")):
            result = self.evaluate()
        self.assertEqual(result.errored_checks, ("I5",))
        self.assertNotIn("SECRET-FAULT", repr(result))

    def test_I2_failure_skips_holder_and_I5_without_exception_details(self):
        def fail(_):
            raise RuntimeError("SECRET-DIGEST-FAULT")
        with patch.object(ResearchTicketM, "d_M", property(fail)):
            with patch(MODULE + ".check_encryption_relation_reference") as i5:
                result = self.evaluate()
                i5.assert_not_called()
        self.assertEqual(result.errored_checks, ("I2_digest",))
        self.assertIs(result.status("I4"), S.NOT_EVALUATED)
        self.assertIs(result.status("I5"), S.NOT_EVALUATED)
        self.assertNotIn("SECRET-DIGEST-FAULT", repr(result))

    def test_I4_hash_failure_skips_I5(self):
        original = hashlib.shake_256
        def guarded(raw):
            if raw.startswith(b"PQ-RBBC/HOLD"):
                raise RuntimeError("SECRET-HOLDER-FAULT")
            return original(raw)
        with patch(MODULE + ".hashlib.shake_256", side_effect=guarded):
            with patch(MODULE + ".check_encryption_relation_reference") as i5:
                result = self.evaluate()
                i5.assert_not_called()
        self.assertEqual(result.errored_checks, ("I4",))
        self.assertIs(result.status("I5"), S.NOT_EVALUATED)
        self.assertNotIn("SECRET-HOLDER-FAULT", repr(result))

    def test_report_has_only_safe_labels_and_cannot_promote_I2_or_I3(self):
        result = self.evaluate()
        for name, status in result.checks:
            self.assertIs(type(name), str)
            self.assertIs(type(status), S)
        for name, changed in (("I2_digest", S.PASSED), ("I3", S.PASSED)):
            checks = tuple((key, changed if key == name else status) for key, status in result.checks)
            with self.assertRaises(ContractError):
                ResearchPartialIssuanceEvaluation(checks)
        with self.assertRaises(ContractError):
            result.status("not_a_check")
        for secret in (self.f.w.trace_u, self.f.w.holder_key, self.f.w.cap_randomness, self.f.m.sn):
            self.assertNotIn(repr(secret), repr(result))


if __name__ == "__main__":
    unittest.main()
