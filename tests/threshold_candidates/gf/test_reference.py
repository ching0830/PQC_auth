from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import random
import unittest
from unittest.mock import patch

from pq_threshold_candidates import Candidate, ContractError, TraceInputs, Unsupported, get_backend
from pq_threshold_candidates.gf import *
from pq_threshold_candidates.gf import reference as impl
from pq_threshold_candidates.gf.arithmetic import (
    centered, nearest_ties_to_zero, negacyclic_mul, pack_coefficients,
    round_q_to_p, unpack_coefficients,
)
from pq_threshold_candidates.gf.profile import (
    CIPHERTEXT_BYTES, D, DEM_BYTES, ELL, G_BYTES, MAGIC, MU_SCALE, N, P,
    POMPEII_BYTES, PROFILE_ID, PUBLIC_KEY_BYTES, Q, U_BYTES, descriptor, descriptor_sha256,
)


def oracle_center(x, modulus):
    return (x + (modulus - 1) // 2) % modulus - (modulus - 1) // 2


def oracle_product(a, b, modulus):
    # Direct coefficient formula; no in-place wraparound convolution.
    n = len(a)
    return tuple(oracle_center(sum(a[i] * b[(k - i) % n] * (1 if i <= k else -1)
                                   for i in range(n)), modulus) for k in range(n))


def oracle_pack(values, bits, modulus):
    stream = [((x % modulus) >> k) & 1 for x in values for k in range(bits)]
    return bytes(sum(bit << k for k, bit in enumerate(stream[i:i + 8])) for i in range(0, len(stream), 8))


def oracle_domain(label, *args):
    # Independent literal framing; catches domain/version/profile changes.
    profile = b"gf-hybrid2-pompeii-d4-shake256-otp-ref-v1"
    return (b"PQ-TH-GF-TB2\x00\x01\x00" + bytes([len(profile)]) + profile
            + bytes([len(label)]) + label
            + b"".join(len(x).to_bytes(4, "little") + x for x in args))


def oracle_hash(label, length, *args):
    return hashlib.shake_256(oracle_domain(label, *args)).digest(length)


class ArithmeticTests(unittest.TestCase):
    def test_centered_endpoint_convention(self):
        self.assertEqual([centered(x, 8) for x in range(8)], [0, 1, 2, 3, 4, -3, -2, -1])
        self.assertEqual(centered(-4, 8), 4)
        self.assertEqual([centered(x, 7) for x in range(7)], [0, 1, 2, 3, -3, -2, -1])

    def test_rational_rounding_exhaustive_and_large_exact_values(self):
        for denominator in range(2, 16):
            for numerator in range(-45, 46):
                value = Fraction(numerator, denominator)
                floor = math.floor(value)
                expected = min(range(floor - 1, floor + 3), key=lambda x: (abs(value - x), abs(x)))
                self.assertEqual(nearest_ties_to_zero(numerator, denominator), expected)
        self.assertEqual(nearest_ties_to_zero(2**100 + 1, 2), 2**99)
        self.assertEqual(nearest_ties_to_zero(-2**100 - 1, 2), -2**99)

    def test_q_to_p_uses_centered_lift_before_rounding(self):
        # q/2 ties for even q use the positive representative; -q/2 is identical.
        self.assertEqual(round_q_to_p(3, 8, 4), 1)
        self.assertEqual(round_q_to_p(5, 8, 4), -1)
        self.assertEqual(round_q_to_p(-4, 8, 4), 2)
        for x in (0, 1, Q // 2, Q // 2 + 1, Q - 1, -Q - 5):
            ratio = Fraction(oracle_center(x, Q) * P, Q)
            floor = math.floor(ratio)
            rounded = min((floor, floor + 1), key=lambda y: (abs(ratio - y), abs(y)))
            self.assertEqual(round_q_to_p(x, Q, P), oracle_center(rounded, P))

    def test_negacyclic_sign_and_independent_product(self):
        self.assertEqual(negacyclic_mul((0, 0, 0, 1), (0, 1, 0, 0), 17), (-1, 0, 0, 0))
        rng = random.Random(542)
        for n in (4, 8, 256):
            a = tuple(rng.randrange(-50, 51) for _ in range(n))
            b = tuple(rng.randrange(-3, 4) for _ in range(n))
            self.assertEqual(negacyclic_mul(a, b, Q), oracle_product(a, b, Q))

    def test_polynomial_packing_and_noncanonical_values(self):
        values = (0, 1, -1, 512, -511)
        data = pack_coefficients(values, 10, P)
        self.assertEqual(data, oracle_pack(values, 10, P))
        self.assertEqual(unpack_coefficients(data, len(values), 10, P), values)
        with self.assertRaises(ContractError):
            unpack_coefficients(data[:-1] + bytes([data[-1] | 128]), len(values), 10, P)
        with self.assertRaises(ContractError):
            unpack_coefficients(((1 << 22) - 1).to_bytes(3, "little"), 1, 22, Q)
        with self.assertRaises(ContractError):
            pack_coefficients((-512,), 10, P)

    def test_arithmetic_rejects_bool_shapes_and_ranges(self):
        for call in (lambda: centered(True, Q), lambda: centered(1, True),
                     lambda: nearest_ties_to_zero(1, 0), lambda: nearest_ties_to_zero(1.0, 2),
                     lambda: negacyclic_mul((1, 2, 3), (1, 2, 3), Q),
                     lambda: negacyclic_mul((True,), (1,), Q),
                     lambda: pack_coefficients((1,), True, 2),
                     lambda: unpack_coefficients(b"", -1, 1, 2)):
            with self.assertRaises(ContractError):
                call()


class ReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pk, cls.sk = keygen_reference_for_test(bytes(range(32)))
        cls.inputs = TraceInputs(b"r" * 32, b"s" * 16, b"c" * 32, b"h" * 32)
        cls.witness = ReferenceWitness(bytes(range(128)))
        cls.ciphertext = encrypt_reference(cls.pk, cls.inputs, cls.witness)

    def test_sampler_exact_cbd_and_rejection(self):
        reader = unittest.mock.Mock()
        reader.read.side_effect = [bytes([x]) for x in (0, 1, 2, 3)]
        self.assertEqual([impl._cbd1(reader) for _ in range(4)], [0, 1, -1, 0])
        reader.read.side_effect = [Q.to_bytes(3, "little"), (Q - 1).to_bytes(3, "little")]
        self.assertEqual(impl._uniform_q(reader), -1)

    def test_xof_stream_does_not_repeat_prefix_when_extended(self):
        seed = bytes(range(32))
        reader = impl._XofReader(b"KEYGEN-A1", seed)
        actual = reader.read(10) + reader.read(18000) + reader.read(25000)
        self.assertEqual(actual, oracle_hash(b"KEYGEN-A1", len(actual), seed))

    def test_key_generation_equation_independently(self):
        r1_bits = oracle_hash(b"KEYGEN-R1", D * D * N, bytes(range(32)))
        expected_r1 = tuple((v & 1) - ((v >> 1) & 1) for v in r1_bits)
        self.assertEqual(tuple(x for row in self.sk.r1 for poly in row for x in poly), expected_r1)
        a1_bytes = oracle_hash(b"KEYGEN-A1", 16384, bytes(range(32)))
        draws = [int.from_bytes(a1_bytes[i:i + 3], 'little') & ((1 << 22) - 1)
                 for i in range(0, len(a1_bytes) - 2, 3)]
        accepted = [oracle_center(x, Q) for x in draws if x < Q]
        self.assertGreaterEqual(len(accepted), D * D * N)
        self.assertEqual(tuple(x for row in self.pk.a1 for poly in row for x in poly), tuple(accepted[:D * D * N]))
        noise = oracle_hash(b"KEYGEN-R2", D * D * N, bytes(range(32)))
        for i in range(D):
            for j in range(D):
                products = [oracle_product(self.pk.a1[i][k], self.sk.r1[k][j], Q) for k in range(D)]
                expected = []
                for k in range(N):
                    v = noise[(i * D + j) * N + k]
                    r2 = (v & 1) - ((v >> 1) & 1)
                    expected.append(oracle_center(sum(poly[k] for poly in products) + r2 + (ELL if i == j and k == 0 else 0), Q))
                self.assertEqual(self.pk.a2[i][j], tuple(expected))

    def test_pompeii_encryption_against_coefficient_formula(self):
        u = self.witness.u
        vector = tuple(tuple((u[(i * N + k) // 8] >> (k % 8)) & 1 for k in range(N)) for i in range(D))
        encoded_values = []
        for matrix in (self.pk.a1, self.pk.a2):
            for j in range(D):
                products = [oracle_product(vector[i], matrix[i][j], Q) for i in range(D)]
                for k in range(N):
                    value = Fraction(oracle_center(sum(poly[k] for poly in products), Q) * P, Q)
                    floor = math.floor(value)
                    rounded = min((floor, floor + 1), key=lambda y: (abs(value - y), abs(y)))
                    encoded_values.append(oracle_center(rounded, P))
        self.assertEqual(self.ciphertext.payload[:POMPEII_BYTES], oracle_pack(encoded_values, 10, P))

    def test_hybrid2_domains_order_and_otp_independently(self):
        body = self.ciphertext.payload
        pad = oracle_hash(b"H", 128, self.witness.u)
        c2 = bytes(x ^ y for x, y in zip(self.inputs.associated_data + self.inputs.plaintext, pad))
        c3 = oracle_hash(b"G", 32, c2, oracle_hash(b"H_prime", 128, self.witness.u))
        c4 = oracle_hash(b"H_double_prime", 128, self.witness.u)
        self.assertEqual(body[POMPEII_BYTES:], c2 + c3 + c4)
        self.assertNotEqual(oracle_hash(b"H_prime", 128, self.witness.u), c4)

    def test_honest_actual_parameter_round_trips(self):
        for u in (bytes(128), bytes([255]) * 128, bytes(range(128)), bytes(reversed(range(128)))):
            w = ReferenceWitness(u)
            c = encrypt_reference(self.pk, self.inputs, w)
            self.assertEqual(decrypt_reference_for_test(self.sk, self.inputs.associated_data, c), self.inputs.plaintext)
            self.assertTrue(check_encryption_relation_reference(self.pk, self.inputs, c, w))

    def test_mutation_of_each_ciphertext_component_rejects(self):
        offsets = (0, POMPEII_BYTES - 1, POMPEII_BYTES, POMPEII_BYTES + DEM_BYTES - 1,
                   POMPEII_BYTES + DEM_BYTES, CIPHERTEXT_BYTES - U_BYTES - 1,
                   CIPHERTEXT_BYTES - U_BYTES, CIPHERTEXT_BYTES - 1)
        for offset in offsets:
            body = bytearray(self.ciphertext.payload)
            body[offset] ^= 1
            mutated = ReferenceCiphertext(bytes(body))
            with self.subTest(offset=offset):
                self.assertIsNone(decrypt_reference_for_test(self.sk, self.inputs.associated_data, mutated))
                self.assertFalse(check_encryption_relation_reference(self.pk, self.inputs, mutated, self.witness))

    def test_pompeii_reencryption_is_required(self):
        body = bytearray(self.ciphertext.payload[:POMPEII_BYTES])
        body[0] ^= 1
        with patch.object(impl, "pompeii_encrypt_reference", wraps=impl.pompeii_encrypt_reference) as reencryption:
            self.assertIsNone(impl.pompeii_decrypt_reference_for_test(self.sk, bytes(body)))
            reencryption.assert_called_once()

    def test_c4_then_c3_before_dem_release(self):
        for offset, forbidden in ((CIPHERTEXT_BYTES - 1, b"G"), (POMPEII_BYTES + DEM_BYTES, b"H")):
            body = bytearray(self.ciphertext.payload)
            body[offset] ^= 1
            with patch.object(impl, "_hash", wraps=impl._hash) as hashes:
                self.assertIsNone(decrypt_reference_for_test(self.sk, self.inputs.associated_data, ReferenceCiphertext(bytes(body))))
                self.assertNotIn(forbidden, [call.args[0] for call in hashes.call_args_list])

    def test_every_ad_field_and_wrong_key_reject(self):
        for offset in (0, 31, 32, 47, 48, 79):
            ad = bytearray(self.inputs.associated_data)
            ad[offset] ^= 1
            self.assertIsNone(decrypt_reference_for_test(self.sk, bytes(ad), self.ciphertext))
        other_pk, other_sk = keygen_reference_for_test(b"z" * 32)
        self.assertIsNone(decrypt_reference_for_test(other_sk, self.inputs.associated_data, self.ciphertext))
        self.assertFalse(check_encryption_relation_reference(other_pk, self.inputs, self.ciphertext, self.witness))

    def test_authentic_dem_with_mismatched_inner_serial_rejects(self):
        # A chosen witness can authenticate an inconsistent inner plaintext.
        message = self.inputs.associated_data + self.inputs.rid + b"x" * 16
        pad = oracle_hash(b"H", 128, self.witness.u)
        c2 = bytes(x ^ y for x, y in zip(message, pad))
        c3 = oracle_hash(b"G", 32, c2, oracle_hash(b"H_prime", 128, self.witness.u))
        body = self.ciphertext.payload[:POMPEII_BYTES] + c2 + c3 + self.ciphertext.payload[-U_BYTES:]
        self.assertIsNone(decrypt_reference_for_test(self.sk, self.inputs.associated_data, ReferenceCiphertext(body)))

    def test_relation_binds_all_inputs_and_witness(self):
        values = dict(rid=self.inputs.rid, sn=self.inputs.sn, ctx=self.inputs.ctx, h=self.inputs.h)
        for name, value in values.items():
            changed = TraceInputs(**dict(values, **{name: bytes([value[0] ^ 1]) + value[1:]}))
            self.assertFalse(check_encryption_relation_reference(self.pk, changed, self.ciphertext, self.witness))
        wrong_witness = ReferenceWitness(b"x" * 128)
        self.assertFalse(check_encryption_relation_reference(self.pk, self.inputs, self.ciphertext, wrong_witness))
        self.assertFalse(check_encryption_relation_reference(self.pk, self.inputs, self.ciphertext, None))

    def test_canonical_records_and_frozen_public_digests(self):
        for value in (self.pk, self.ciphertext, self.witness):
            self.assertEqual(type(value).decode(value.encode()), value)
        vectors = json.loads((Path(__file__).resolve().parents[3] / 'docs/literature/threshold_backends/gf/reference_vectors_v1.json').read_text())
        self.assertEqual(hashlib.sha256(self.pk.encode()).hexdigest(), vectors['public_key_record_sha256'])
        self.assertEqual(hashlib.sha256(self.ciphertext.encode()).hexdigest(), vectors['ciphertext_record_sha256'])
        self.assertEqual(descriptor_sha256(), vectors['profile_descriptor_sha256'])
        profile = json.loads((Path(__file__).resolve().parents[3] / 'docs/literature/threshold_backends/gf/reference_profile_v1.json').read_text())
        self.assertEqual(descriptor(), profile)

    def test_all_record_header_mutations_truncation_and_trailing_reject(self):
        for value in (self.pk, self.ciphertext, self.witness):
            data = value.encode()
            overhead = len(data) - (PUBLIC_KEY_BYTES if type(value) is ReferencePublicKey else CIPHERTEXT_BYTES if type(value) is ReferenceCiphertext else U_BYTES)
            for offset in range(overhead):
                changed = bytearray(data)
                changed[offset] ^= 1
                with self.subTest(kind=type(value).__name__, offset=offset), self.assertRaises(ContractError):
                    type(value).decode(bytes(changed))
            for wrong in (data[:-1], data + b"x", bytearray(data), b"", data[:overhead]):
                with self.assertRaises(ContractError):
                    type(value).decode(wrong)
        with self.assertRaises(ContractError):
            ReferenceWitness.decode(self.ciphertext.encode())

    def test_public_key_out_of_range_coefficient_rejects(self):
        data = self.pk.encode()
        offset = len(data) - PUBLIC_KEY_BYTES
        body = int.from_bytes(data[offset:], "little")
        body = (body & ~((1 << 22) - 1)) | ((1 << 22) - 1)
        with self.assertRaises(ContractError):
            ReferencePublicKey.decode(data[:offset] + body.to_bytes(PUBLIC_KEY_BYTES, "little"))

    def test_bad_inputs_and_secret_repr(self):
        for seed in (True, bytes(31), bytes(33), bytearray(32)):
            with self.assertRaises(ContractError):
                keygen_reference_for_test(seed)
        for value in (None, bytes(127), bytes(129), bytearray(128)):
            with self.assertRaises(ContractError):
                ReferenceWitness(value)
        for ad in (None, bytes(79), bytes(81), bytearray(80)):
            self.assertIsNone(decrypt_reference_for_test(self.sk, ad, self.ciphertext))
        self.assertEqual(repr(self.sk), 'ReferenceSecretKey()')
        self.assertEqual(repr(self.witness), 'ReferenceWitness()')

    def test_common_dispatch_stays_unavailable(self):
        with self.assertRaises(ContractError):
            get_backend(Candidate.GF, PROFILE_ID)
        with self.assertRaises(Unsupported):
            get_backend(Candidate.GF, 'gf-pompeii-d4-estimate-v1')
        common = get_backend(Candidate.GF, 'gf-pompeii-d4-estimate-v1', purpose='research')
        with self.assertRaises(Unsupported):
            common.create_share(context=object())
        self.assertFalse(descriptor()['claims']['production_qualified'])


if __name__ == "__main__":
    unittest.main()
