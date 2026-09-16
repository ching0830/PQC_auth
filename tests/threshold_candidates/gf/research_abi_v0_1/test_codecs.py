from dataclasses import fields, replace
import hashlib
import json
from pathlib import Path
import unittest

import pq_rbbc_cap_commit as cap
from pq_threshold_candidates import ContractError
from pq_threshold_candidates.gf import (
    ReferenceWitness, check_encryption_relation_reference, keygen_reference_for_test,
)
from pq_threshold_candidates.gf.research_abi_v0_1 import (
    ABI_SHA256, ResearchCommonPP, ResearchIssueStatement, ResearchIssueWitness,
    ResearchTicketM, ResearchTraceBinding, public_key_record_sha256_research,
    validate_cap_randomness_research,
)
from ._fixtures import fixture, sha


ROOT = Path(__file__).resolve().parents[4]
DOCS = ROOT / 'docs/literature/threshold_backends/gf/abi_v0_1'
TYPES = dict(trace_binding=ResearchTraceBinding, common_pp=ResearchCommonPP,
             ticket_m=ResearchTicketM, issue_statement=ResearchIssueStatement,
             issue_witness=ResearchIssueWitness)


class CodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pk, _ = keygen_reference_for_test(sha(b'GF ABI codec fixture'))
        cls.f = fixture(cls.pk)
        cls.objects = dict(trace_binding=cls.f.binding, common_pp=cls.f.pp,
                           ticket_m=cls.f.m, issue_statement=cls.f.statement,
                           issue_witness=cls.f.w)
        cls.contract = json.loads((DOCS / 'contract_v0_1.json').read_text())

    def test_pinned_descriptor_and_every_offset_match_frozen_contract(self):
        compact = json.dumps(self.contract, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
        self.assertEqual(sha(compact), ABI_SHA256)
        for name, obj in self.objects.items():
            raw = obj.encode()
            self.assertEqual(len(raw), self.contract['layouts'][name]['bytes'])
            self.assertEqual(type(obj).decode(raw), obj)
            for field in self.contract['layouts'][name]['fields']:
                got = raw[field['offset']:field['offset'] + field['bytes']]
                if 'literal_hex' in field:
                    want = bytes.fromhex(field['literal_hex'])
                elif field.get('derived') == 'abi_sha256':
                    want = ABI_SHA256
                else:
                    value = getattr(obj, field['name'])
                    want = (value.encode() if 'nested' in field else
                            value.to_bytes(8, 'little') if field.get('encoding') == 'u64le' else value)
                self.assertEqual(got, want, (name, field['name']))

    def test_frozen_document_vectors_and_stricter_rho_boundary(self):
        # Separate byte assembly from frozen JSON, not the runtime encoder schema.
        def assemble(name):
            chunks = []
            for field in self.contract['layouts'][name]['fields']:
                if 'literal_hex' in field:
                    value = bytes.fromhex(field['literal_hex'])
                elif field.get('derived') == 'abi_sha256':
                    value = ABI_SHA256
                elif 'nested' in field:
                    value = assemble(field['nested'])
                else:
                    value = hashlib.shake_256(b'NOT-ATTESTATION/SHAPE-ONLY/' + name.encode() + b'/' + field['name'].encode()).digest(field['bytes'])
                chunks.append(value)
            return b''.join(chunks)
        historical = json.loads((DOCS / 'validation_summary_v0_1.json').read_text())
        vectors = historical['document_check']['result']['synthetic_shape_digests']
        for name, codec in TYPES.items():
            raw = assemble(name)
            self.assertEqual(sha(raw).hex(), vectors[name]['sha256'])
            if name == 'issue_witness':
                # Historical checker documented rho as opaque synthetic bytes.
                with self.assertRaises(ContractError):
                    codec.decode(raw)
            else:
                self.assertEqual(codec.decode(raw).encode(), raw)

    def test_all_truncations_and_trailing_bytes_reject(self):
        for obj in self.objects.values():
            raw = obj.encode()
            for end in range(len(raw)):
                with self.assertRaises(ContractError):
                    type(obj).decode(raw[:end])
            for extra in (b'\0', b'\xff' * 32, raw):
                with self.assertRaises(ContractError):
                    type(obj).decode(raw + extra)

    def test_each_fixed_header_and_nonzero_digest_mutation_rejects(self):
        def mutate_fields(name, start=0):
            for field in self.contract['layouts'][name]['fields']:
                offset = start + field['offset']
                if 'nested' in field:
                    yield from mutate_fields(field['nested'], offset)
                elif 'literal_hex' in field or 'derived' in field or field.get('nonzero'):
                    yield offset, field
        for name, obj in self.objects.items():
            for offset, field in mutate_fields(name):
                raw = bytearray(obj.encode())
                if field.get('nonzero'):
                    raw[offset:offset + field['bytes']] = bytes(field['bytes'])
                else:
                    raw[offset] ^= 1
                with self.subTest(packet=name, field=field['name'], offset=offset):
                    with self.assertRaises(ContractError):
                        type(obj).decode(bytes(raw))

    def test_mutable_and_alternate_types_rejected(self):
        class BytesSubclass(bytes):
            pass
        for obj in self.objects.values():
            for raw in (bytearray(obj.encode()), memoryview(obj.encode()), BytesSubclass(obj.encode()), None, True, 'bytes'):
                with self.assertRaises(ContractError):
                    type(obj).decode(raw)
            for f in fields(obj):
                if type(getattr(obj, f.name)) is bytes:
                    with self.assertRaises(ContractError):
                        replace(obj, **{f.name: bytearray(getattr(obj, f.name))})
        with self.assertRaises(ContractError):
            replace(self.f.pp, trace_binding=self.f.binding.encode())
        with self.assertRaises(ContractError):
            replace(self.f.w, ticket_m=self.f.m.encode())

    def test_uint64_epoch_requires_exact_int_and_canonical_endianness(self):
        for value in (True, False, -1, 1 << 64, 7.0, b'7'):
            with self.assertRaises(ContractError):
                replace(self.f.binding, epoch=value)
        for value in (0, 1, 0x0102030405060708, (1 << 64) - 1):
            obj = replace(self.f.binding, epoch=value)
            self.assertEqual(obj.encode()[144:152], value.to_bytes(8, 'little'))
            self.assertEqual(ResearchTraceBinding.decode(obj.encode()), obj)

    def test_raw_C_and_u_slots_reject_wrapped_or_legacy_records(self):
        for c in (self.f.m.ciphertext_research().encode(), b'x' * 288, b'x' * 2847, b'x' * 2849):
            with self.assertRaises(ContractError):
                replace(self.f.m, ciphertext_payload=c)
        for u in (ReferenceWitness(self.f.w.trace_u).encode(), b'x' * 836, b'x' * 127, b'x' * 129):
            with self.assertRaises(ContractError):
                replace(self.f.w, trace_u=u)

    def test_zero_and_all_one_u_are_canonical_not_weight_constrained(self):
        for u in (bytes(128), b'\xff' * 128):
            w = replace(self.f.w, trace_u=u)
            self.assertEqual(ResearchIssueWitness.decode(w.encode()).trace_witness_research().u, u)
        self.assertEqual(ResearchTicketM.decode(replace(self.f.m, sn=bytes(16)).encode()).sn, bytes(16))

    def test_cap_codec_agrees_with_pinned_serializer_including_extreme_fields(self):
        self.assertEqual(cap.profile_fingerprint(cap.PRODUCTION_PARAMETERS), self.contract['bridge']['cap_profile_sha256'])
        for v in (0, (1 << 193) - 1):
            rho = cap.CAPRandomness((v, v), ((v, v),) * 18).serialize(cap.PRODUCTION_PARAMETERS)
            validate_cap_randomness_research(rho)
            self.assertEqual(ResearchIssueWitness.decode(replace(self.f.w, cap_randomness=rho).encode()).cap_randomness, rho)

    def test_cap_codec_rejects_every_salt_root_unused_bit_and_wrong_profile_count(self):
        rho = self.f.w.cap_randomness
        offset = len(cap.RANDOMNESS_MAGIC) + 64
        tops = [offset + 24, offset + 49]
        roots = offset + 52
        tops += [roots + 25 * i + 24 for i in range(36)]
        for top in tops:
            for bit in range(1, 8):
                changed = bytearray(rho)
                changed[top] |= 1 << bit
                with self.assertRaises(ContractError):
                    replace(self.f.w, cap_randomness=bytes(changed))
        for pos in (0, len(cap.RANDOMNESS_MAGIC), offset + 50, offset + 51):
            changed = bytearray(rho)
            changed[pos] ^= 1
            with self.assertRaises(ContractError):
                replace(self.f.w, cap_randomness=bytes(changed))

    def test_digest_and_trace_views_use_full_M_and_only_canonical_AD(self):
        m = self.f.m
        self.assertEqual(m.d_M, hashlib.shake_256(b'PQ-RBBC/TICKET' + m.encode()).digest(32))
        self.assertNotEqual(m.d_M, hashlib.shake_256(b'PQ-RBBC/TICKET' + m.encode()[77:]).digest(32))
        self.assertEqual(m.associated_data, self.f.x.associated_data)
        self.assertEqual(m.trace_inputs_research(self.f.x.rid), self.f.x)
        self.assertTrue(check_encryption_relation_reference(self.pk, m.trace_inputs_research(self.f.x.rid),
                                                           m.ciphertext_research(), self.f.w.trace_witness_research()))
        other = replace(m, common_pp_sha256=sha(b'other pp'))
        self.assertEqual(other.ciphertext_payload, m.ciphertext_payload)
        self.assertNotEqual(other.d_M, m.d_M)

    def test_public_key_identity_requires_complete_canonical_record(self):
        raw = self.pk.encode()
        self.assertEqual(public_key_record_sha256_research(raw), sha(raw))
        self.assertNotEqual(sha(raw), sha(raw[-22528:]))
        invalid_coeff = bytearray(raw)
        invalid_coeff[-22528] = 0xff
        invalid_coeff[-22527] = 0xff
        invalid_coeff[-22526] |= 0x3f
        for value in (raw[:-1], raw + b'x', raw[-22528:], bytearray(raw), bytes(invalid_coeff)):
            with self.assertRaises(ContractError):
                public_key_record_sha256_research(value)

    def test_private_packet_reprs_and_errors_do_not_include_field_contents(self):
        w = self.f.w
        for value in (w, w.ticket_m):
            self.assertIn('research_only=True', repr(value))
            for secret in (w.trace_u, w.holder_key, w.blind_mask, w.ticket_m.sn):
                self.assertNotIn(repr(secret), repr(value))
        with self.assertRaises(ContractError) as caught:
            replace(w, trace_u=b'SECRET-SHOULD-NOT-APPEAR')
        self.assertNotIn('SECRET-SHOULD-NOT-APPEAR', str(caught.exception))

    def test_statement_partition_contains_no_private_fields(self):
        self.assertEqual([f.name for f in fields(ResearchIssueStatement)],
                         ['common_pp_sha256', 'ctx', 'sid', 'rid', 'beta'])
        self.assertEqual([f.name for f in fields(ResearchIssueWitness)],
                         ['ticket_m', 'blind_mask', 'cap_randomness', 'holder_key', 'trace_u'])


if __name__ == '__main__':
    unittest.main()
