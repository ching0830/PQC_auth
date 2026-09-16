from dataclasses import replace
import unittest
from unittest.mock import patch

from pq_threshold_candidates import Candidate, ContractError, Unsupported, get_backend
from pq_threshold_candidates.gf import (
    check_encryption_relation_reference, decrypt_reference_for_test,
    keygen_reference_for_test,
)
from pq_threshold_candidates.gf.research_abi_v0_1 import (
    ResearchBindingMatch, ResearchBindingMismatch, check_key_pp_bindings_research,
)
from ._fixtures import arguments, changed_binding_arguments, fixture, sha


MODULE = 'pq_threshold_candidates.gf.research_abi_v0_1.bindings'


class BindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pk_a, cls.sk_a = keygen_reference_for_test(sha(b'GF ABI key A'))
        cls.pk_b, cls.sk_b = keygen_reference_for_test(sha(b'GF ABI key B'))
        cls.f = fixture(cls.pk_a, bytes(128))
        cls.other = fixture(cls.pk_b, bytes(128))

    def assertMismatch(self, code, args):
        with self.assertRaises(ResearchBindingMismatch) as caught:
            check_key_pp_bindings_research(**args)
        self.assertEqual(caught.exception.code, code)

    def test_consistent_research_inputs_return_only_non_boolean_diagnostic(self):
        result = check_key_pp_bindings_research(**arguments(self.f))
        self.assertIs(type(result), ResearchBindingMatch)
        self.assertEqual(result.tpk_record_sha256, sha(self.pk_a.encode()))
        self.assertEqual(result.common_pp_sha256, self.f.pp.sha256)
        self.assertFalse(result.authentication_verified)
        self.assertFalse(result.production_qualified)
        with self.assertRaises(TypeError):
            bool(result)

    def test_production_defaults_reject_before_any_parse_even_for_valid_input(self):
        args = arguments(self.f)
        for explicit in (False, True):
            value = dict(args)
            if explicit:
                value['purpose'] = 'production'
            else:
                value.pop('purpose')
            with patch(MODULE + '.SystemInitializationBundle.decode') as decode:
                with self.assertRaises(Unsupported):
                    check_key_pp_bindings_research(**value)
                decode.assert_not_called()
        for invalid in (None, True, 0, 'Research', 'test', b'research'):
            with self.assertRaises(ContractError):
                check_key_pp_bindings_research(**dict(args, purpose=invalid))

    def test_common_dispatch_stays_unavailable(self):
        with self.assertRaises(ContractError):
            get_backend(Candidate.GF, 'gf-hybrid2-pompeii-d4-shake256-otp-ref-v1', purpose='research')
        with self.assertRaises(Unsupported):
            get_backend(Candidate.GF, 'gf-pompeii-d4-estimate-v1')

    def test_external_bundle_pin_precedes_parsing_or_public_key_touch(self):
        args = dict(arguments(self.f), expected_bundle_sha256=sha(b'wrong pin'))
        with patch(MODULE + '.SystemInitializationBundle.decode') as decode:
            with patch(MODULE + '.public_key_record_sha256_research') as key:
                self.assertMismatch('initialization_bundle_sha256', args)
                decode.assert_not_called()
                key.assert_not_called()
        for pin in (None, True, bytes(32), bytearray(sha(b'x')), b'x' * 31):
            with self.assertRaises(ContractError):
                check_key_pp_bindings_research(**dict(arguments(self.f), expected_bundle_sha256=pin))

    def test_matching_pin_still_requires_canonical_bundle(self):
        raw = self.f.bundle.encode()
        for invalid in (raw + b'x', raw[:-1], b'x' + raw[1:]):
            with self.assertRaises(ContractError):
                check_key_pp_bindings_research(**dict(arguments(self.f), initialization_bundle=invalid,
                                                       expected_bundle_sha256=sha(invalid)))

    def test_zero_u_cross_key_relation_success_does_not_override_key_mismatch(self):
        self.assertEqual(self.f.m.ciphertext_payload, self.other.m.ciphertext_payload)
        self.assertTrue(check_encryption_relation_reference(self.pk_b, self.f.x,
                                                           self.f.m.ciphertext_research(), self.f.w.trace_witness_research()))
        self.assertEqual(decrypt_reference_for_test(self.sk_b, self.f.m.associated_data,
                                                   self.f.m.ciphertext_research()), self.f.x.plaintext)
        self.assertMismatch('tpk_record_sha256', dict(arguments(self.f), tpk_record=self.pk_b.encode()))

    def test_replacing_key_and_self_reported_digest_fails_outer_and_key_bindings(self):
        args = changed_binding_arguments(self.f, tpk_record_sha256=sha(self.pk_b.encode()))
        args['tpk_record'] = self.pk_b.encode()
        # The synthetic bundle has been re-pinned, but still names the actual key A.
        self.assertMismatch('bundle_tpk_record_sha256', args)
        old_bundle = self.f.bundle.encode()
        args.update(initialization_bundle=old_bundle, expected_bundle_sha256=sha(old_bundle))
        with patch(MODULE + '.public_key_record_sha256_research') as key:
            self.assertMismatch('common_pp_sha256', args)
            key.assert_not_called()

    def test_common_parameters_pin_is_full_packet_not_capsule(self):
        bundle = replace(self.f.bundle, common_parameters_digest=sha(self.f.binding.encode()))
        self.assertMismatch('common_pp_sha256', dict(arguments(self.f), initialization_bundle=bundle.encode(),
                                                   expected_bundle_sha256=sha(bundle.encode())))

    def test_every_configuration_and_role_identity_mismatch(self):
        for field, code in (
            ('configuration_sha256', 'configuration_sha256'), ('ctx', 'binding_ctx'),
            ('epoch', 'epoch'), ('oa_key_id', 'oa_key_id'), ('issuer_key_id', 'issuer_key_id'),
            ('issuer_public_key_sha256', 'issuer_public_key_sha256'),
        ):
            value = 8 if field == 'epoch' else sha(b'changed ' + field.encode())
            with self.subTest(field=field):
                self.assertMismatch(code, changed_binding_arguments(self.f, **{field: value}))

    def test_hashing_key_body_instead_of_full_record_rejects(self):
        args = changed_binding_arguments(self.f, tpk_record_sha256=sha(self.pk_a.encode()[-22528:]))
        self.assertMismatch('tpk_record_sha256', args)

    def test_each_required_opaque_artifact_identity_is_checked_but_not_certified(self):
        for name in ('key_origin_evidence', 'issue_backend_pp', 'gf_full_relation_manifest'):
            with self.subTest(artifact=name):
                self.assertMismatch(name + '_sha256', dict(arguments(self.f), **{name: b'changed fake artifact'}))
                for bad in (b'', bytearray(b'x'), None, b'x' * ((1 << 20) + 1)):
                    with self.assertRaises(ContractError):
                        check_key_pp_bindings_research(**dict(arguments(self.f), **{name: bad}))
        # Matching fake evidence deliberately yields identity-only, not qualification.
        self.assertFalse(check_key_pp_bindings_research(**arguments(self.f)).authentication_verified)

    def test_statement_and_M_must_point_to_same_full_pp_and_context(self):
        for obj_name, field, code in (
            ('statement', 'common_pp_sha256', 'statement_common_pp_sha256'),
            ('ticket_m', 'common_pp_sha256', 'ticket_common_pp_sha256'),
            ('statement', 'ctx', 'statement_ctx'), ('ticket_m', 'ctx', 'ticket_ctx'),
        ):
            obj = self.f.statement if obj_name == 'statement' else self.f.m
            changed = replace(obj, **{field: sha(b'other')}).encode()
            with self.subTest(packet=obj_name, field=field):
                self.assertMismatch(code, dict(arguments(self.f), **{obj_name: changed}))

    def test_pp_switch_changes_d_M_even_with_identical_ciphertext(self):
        self.assertNotEqual(self.f.pp.sha256, self.other.pp.sha256)
        self.assertEqual(self.f.m.ciphertext_payload, self.other.m.ciphertext_payload)
        self.assertNotEqual(self.f.m.encode(), self.other.m.encode())
        self.assertNotEqual(self.f.m.d_M, self.other.m.d_M)
        self.assertMismatch('ticket_common_pp_sha256', dict(arguments(self.f), ticket_m=self.other.m.encode()))

    def test_byte_consistency_does_not_claim_I5_or_authenticate_arbitrary_C(self):
        changed = bytearray(self.f.m.ciphertext_payload)
        changed[2688] ^= 1
        m = replace(self.f.m, ciphertext_payload=bytes(changed))
        match = check_key_pp_bindings_research(**dict(arguments(self.f), ticket_m=m.encode()))
        self.assertFalse(match.production_qualified)
        self.assertFalse(check_encryption_relation_reference(self.pk_a, self.f.x,
                                                            m.ciphertext_research(), self.f.w.trace_witness_research()))

    def test_capture_contract_rejects_mutable_bytes_on_every_argument(self):
        args = arguments(self.f)
        for name, value in args.items():
            if type(value) is bytes:
                with self.subTest(argument=name):
                    with self.assertRaises(ContractError):
                        check_key_pp_bindings_research(**dict(args, **{name: bytearray(value)}))

    def test_repinning_entire_fixture_still_never_authenticates_or_qualifies(self):
        # An attacker/test can choose a different self-consistent pin. Authenticity is absent.
        value = check_key_pp_bindings_research(**arguments(self.other))
        self.assertFalse(value.authentication_verified)
        self.assertFalse(value.production_qualified)
        with self.assertRaises(Unsupported):
            check_key_pp_bindings_research(**dict(arguments(self.other), purpose='production'))


if __name__ == '__main__':
    unittest.main()
