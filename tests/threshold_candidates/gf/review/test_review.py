import ast
import hashlib
from pathlib import Path
import unittest

from pq_threshold_candidates import TraceInputs
from pq_threshold_candidates.gf import (
    ReferenceCiphertext, ReferenceWitness, check_encryption_relation_reference,
    decrypt_reference_for_test, encrypt_reference, keygen_reference_for_test,
)
from . import oracle


class DifferentialReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = [keygen_reference_for_test(hashlib.sha256(b'GF review fixture ' + bytes([i])).digest()) for i in range(3)]
        cls.x = TraceInputs(b'r' * 32, b's' * 16, b'c' * 32, b'h' * 32)

    def test_oracle_does_not_import_implementation_or_existing_helpers(self):
        tree = ast.parse(Path(oracle.__file__).read_text())
        names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0)
                names.append(node.module)
        self.assertEqual(set(names), {'fractions', 'hashlib', 'struct'})

    def test_carry_free_product_against_hand_polynomial(self):
        self.assertEqual(oracle.product((0, 0, 0, 1), (0, 1, 0, 0), 17), (-1, 0, 0, 0))
        self.assertEqual(oracle.product((1, 2), (3, 4), 101), (-5, 10))
        self.assertEqual(oracle.product((-1, -2), (3, 4), 101), (5, -10))
        a, b = (16,) * 4, (16,) * 4
        self.assertEqual(oracle.product(a, b, 17), (-2, 0, 2, 4))

    def test_full_byte_level_cross_encryption_and_decryption(self):
        witnesses = (bytes(128), bytes([255]) * 128, bytes([170, 85]) * 64,
                     hashlib.shake_256(b'GF review public fixture u').digest(128))
        for key_index, (pk, sk) in enumerate(self.keys):
            for witness_index, u in enumerate(witnesses):
                with self.subTest(key=key_index, witness=witness_index):
                    actual = encrypt_reference(pk, self.x, ReferenceWitness(u))
                    expected = oracle.encrypt(pk.encode(), u, self.x.associated_data, self.x.plaintext)
                    self.assertEqual(actual.encode(), expected)
                    self.assertEqual(oracle.decrypt(pk.encode(), sk.r1, self.x.associated_data, actual.encode()), self.x.plaintext)
                    self.assertEqual(decrypt_reference_for_test(sk, self.x.associated_data, ReferenceCiphertext.decode(expected)), self.x.plaintext)

    def test_differential_rejection_and_malformed_records(self):
        pk, sk = self.keys[0]
        u = hashlib.shake_256(b'GF review mutation fixture').digest(128)
        ciphertext = encrypt_reference(pk, self.x, ReferenceWitness(u))
        for offset in (0, 1279, 1280, 2559, 2560, 2687, 2688, 2719, 2720, 2847):
            changed = bytearray(ciphertext.payload)
            changed[offset] ^= 1
            invalid = ReferenceCiphertext(bytes(changed))
            with self.subTest(offset=offset):
                self.assertIsNone(decrypt_reference_for_test(sk, self.x.associated_data, invalid))
                self.assertIsNone(oracle.decrypt(pk.encode(), sk.r1, self.x.associated_data, invalid.encode()))
        for offset in (0, 31, 32, 47, 48, 79):
            wrong_ad = bytearray(self.x.associated_data)
            wrong_ad[offset] ^= 1
            self.assertIsNone(oracle.decrypt(pk.encode(), sk.r1, bytes(wrong_ad), ciphertext.encode()))
            self.assertIsNone(decrypt_reference_for_test(sk, bytes(wrong_ad), ciphertext))
        invalid_serial = oracle.encrypt(pk.encode(), u, self.x.associated_data, self.x.rid + b'x' * 16)
        self.assertIsNone(oracle.decrypt(pk.encode(), sk.r1, self.x.associated_data, invalid_serial))
        self.assertIsNone(decrypt_reference_for_test(sk, self.x.associated_data, ReferenceCiphertext.decode(invalid_serial)))
        for invalid in (ciphertext.encode()[:-1], ciphertext.encode() + b'x', pk.encode(), b''):
            self.assertIsNone(oracle.decrypt(pk.encode(), sk.r1, self.x.associated_data, invalid))

    def test_zero_witness_is_counterexample_to_key_identity_authentication(self):
        pk1, sk1 = self.keys[0]
        pk2, sk2 = self.keys[1]
        self.assertNotEqual(pk1.encode(), pk2.encode())
        witness = ReferenceWitness(bytes(128))
        c1 = encrypt_reference(pk1, self.x, witness)
        c2 = encrypt_reference(pk2, self.x, witness)
        self.assertEqual(c1.payload[:2560], bytes(2560))
        self.assertEqual(c1, c2)
        # Both are valid encryption relations. Neither authenticates expected tpk identity.
        self.assertTrue(check_encryption_relation_reference(pk2, self.x, c1, witness))
        self.assertEqual(decrypt_reference_for_test(sk2, self.x.associated_data, c1), self.x.plaintext)
        self.assertEqual(oracle.decrypt(pk2.encode(), sk2.r1, self.x.associated_data, c1.encode()), self.x.plaintext)
        self.assertEqual(oracle.decrypt(pk1.encode(), sk1.r1, self.x.associated_data, c2.encode()), self.x.plaintext)

    def test_witness_reuse_remains_an_explicit_research_harness_boundary(self):
        pk, _ = self.keys[0]
        witness = ReferenceWitness(b'w' * 128)
        other = TraceInputs(b'R' * 32, b'S' * 16, b'C' * 32, b'H' * 32)
        first = encrypt_reference(pk, self.x, witness)
        second = encrypt_reference(pk, other, witness)
        xor = lambda left, right: bytes(a ^ b for a, b in zip(left, right))
        self.assertEqual(xor(first.payload[2560:2688], second.payload[2560:2688]),
                         xor(self.x.associated_data + self.x.plaintext, other.associated_data + other.plaintext))
        self.assertTrue(check_encryption_relation_reference(pk, other, second, witness))


if __name__ == '__main__':
    unittest.main()
