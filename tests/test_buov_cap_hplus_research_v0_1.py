"""Public algebra/codec controls, not proof generation or a security theorem."""
from dataclasses import replace
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from pq_rbbc.blind_uov_hplus_research_v0_1 import codec, field, parameters as p, transcript
from pq_rbbc.blind_uov_hplus_research_v0_1.consistency import encode_xi_polynomials
from pq_rbbc.blind_uov_hplus_research_v0_1.evaluation import LinearPolynomial, evaluation_point
from pq_rbbc.blind_uov_hplus_research_v0_1.relation import RepetitionPolynomials, build_consistency_polynomials
from pq_rbbc.blind_uov_hplus_research_v0_1.verifier import _xi_from_opening
from pq_rbbc.blind_uov_pqsat_v0_1 import codec as old_codec, field as old_field

ROOT = Path(__file__).resolve().parents[1]
POINTS = (0, 1, 1 << 63, (1 << 64) - 1)


def multiply(a, b, degree=64, modulus=0x1000000000000001b):
    """Independent full carryless product / long division, not Horner."""
    product = 0
    for bit in range(degree):
        if (b >> bit) & 1:
            product ^= a << bit
    for bit in range(2*degree-2, degree-1, -1):
        if (product >> bit) & 1:
            product ^= modulus << (bit-degree)
    return product


def independent_hash(raw, points=POINTS):
    result = []
    for point in points:
        power, value = point, 0
        for start in range(0, 256, 8):
            value ^= multiply(int.from_bytes(raw[start:start+8], 'little'), power)
            power = multiply(power, point)
        result.append(value.to_bytes(8, 'little'))
    return b''.join(result)


@lru_cache(None)
def matrix_columns(points):
    columns = []
    for point in points:
        power = point
        for _ in range(32):
            columns.append(tuple(multiply(1 << bit, power) for bit in range(64)))
            power = multiply(power, point)
    return tuple(columns)


def matrix_lift(vector, points=POINTS):
    """Apply F2 columns directly to K-valued coordinates; no mixed-field mul."""
    columns = matrix_columns(points)
    out = [0] * 256
    for j, value in enumerate(vector):
        for point in range(4):
            word = columns[32*point+j//64][j%64]
            while word:
                bit = (word & -word).bit_length()-1
                out[point*64+bit] ^= value
                word &= word-1
    return tuple(out)


@lru_cache(None)
def repetitions():
    plain, mask = bytes(range(256)), bytes(range(32))
    out = []
    for r in range(18):
        degree = 12 if r < 2 else 11
        fid = p.FieldId.GF_2_12 if r < 2 else p.FieldId.GF_2_11
        def polys(raw, n):
            return tuple(LinearPolynomial(fid, ((37*j+11*r) ^ (1 << (degree-1))) & ((1 << degree)-1),
                (raw[j//8] >> (j%8)) & 1) for j in range(n))
        out.append(RepetitionPolynomials(polys(plain, 2048),
            polys(bytes(3), 16 if r < 2 else 18), polys(mask, 256)))
    return tuple(out)


class HPlusMathTests(unittest.TestCase):
    def test_independent_polynomial_oracle_and_edge_points(self):
        for raw in (bytes(256), bytes(range(256)), bytes([255])*256,
                    b'\x01'+bytes(255), bytes(248)+b'\x80'+bytes(7)):
            self.assertEqual(field.consistency_hash(raw, POINTS), independent_hash(raw))
        self.assertEqual(field.consistency_hash(b'\x01'+bytes(255), POINTS), struct.pack('<4Q', *POINTS))

    def test_old_fixed_offset_is_not_a_new_identity(self):
        c = 0x0123456789abcdef
        raw, mask = c.to_bytes(8, 'little')+bytes(248), struct.pack('<4Q', *([c]*4))
        chi = (2, 3, 4, 5)
        self.assertEqual(old_field.consistency_hash(raw, chi), mask)
        self.assertNotEqual(field.consistency_hash(raw, chi), mask)
        self.assertEqual(field.consistency_hash(raw, (1,)*4), mask)  # Allowed exceptional key.
        self.assertNotEqual(field.consistency_hash(bytes(256), chi), mask)

    def test_strict_arithmetic_inputs(self):
        for raw, chi in ((bytearray(256), POINTS), (bytes(255), POINTS),
                         (bytes(256), list(POINTS)), (bytes(256), (True, 1, 2, 3)),
                         (bytes(256), (0, 1, 2, 1 << 64))):
            with self.assertRaises((ValueError, TypeError)):
                field.consistency_hash(raw, chi)

    def test_gf11_gf12_prover_and_verifier_match_binary_matrix(self):
        polys = build_consistency_polynomials(repetitions(), POINTS)
        expected_alpha = bytes(a ^ b for a, b in zip(independent_hash(bytes(range(256))), bytes(range(32))))
        for r in (0, 2):
            rep = repetitions()[r]
            expected_slope = tuple(a ^ b.mask for a, b in zip(
                matrix_lift(tuple(v.mask for v in rep.witness_polynomials)), rep.consistency_masks))
            self.assertEqual(polys[r].constant, expected_alpha)
            self.assertEqual(polys[r].linear, expected_slope)
            degree, modulus = (12, 0x1009) if r == 0 else (11, 0x805)
            def at(ps):
                return tuple(v.plain ^ multiply(v.mask, 5, degree, modulus) for v in ps)
            got = _xi_from_opening(evaluation_point(0 if r == 0 else 1, 4),
                at(rep.witness_polynomials), at(rep.consistency_masks), expected_alpha, POINTS)
            self.assertEqual(got, polys[r])


class HPlusIdentityTests(unittest.TestCase):
    def test_frozen_profile_and_canonical_types(self):
        profile = p.load_profile_manifest()
        self.assertEqual(p.profile_fingerprint(profile), p.PROFILE_FINGERPRINT)
        self.assertEqual((profile.relation.degree_d, profile.consistency.polynomial_degree_upper_bound_d), (2, 32))
        for changed in (replace(profile, suite_id_u16=0xff32),
                        replace(profile, fingerprint=bytearray(profile.fingerprint)),
                        replace(profile, consistency=replace(profile.consistency, evaluation_count_t=True))):
            with self.assertRaises(p.ProfileValidationError):
                p.validate_profile(changed)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'profile.json'
            path.write_bytes(p.DEFAULT_PROFILE_MANIFEST.read_bytes()+b' ')
            with self.assertRaises(p.ProfileValidationError):
                p.load_profile_manifest(path)

    def test_both_import_orders_preserve_independent_globals(self):
        for names in [('blind_uov_pqsat_v0_1', 'blind_uov_hplus_research_v0_1'),
                      ('blind_uov_hplus_research_v0_1', 'blind_uov_pqsat_v0_1')]:
            code = ('from importlib import import_module\n'
                f'mods=[import_module("pq_rbbc."+n+".codec") for n in {names!r}]\n'
                'assert mods[0]._PROFILE.fingerprint != mods[1]._PROFILE.fingerprint\n'
                'assert mods[0].CR is not mods[1].CR\n')
            subprocess.run([sys.executable, '-c', code], check=True, capture_output=True)

    def test_codec_rejects_foreign_suite_fingerprint_both_directions(self):
        for src, dst in ((codec, old_codec), (old_codec, codec)):
            for kind, size, decode in ((1, 5024, dst.decode_c_r), (2, 184, dst.decode_c_z),
                                        (3, 1678, dst.decode_pi_2)):
                raw = src._header(kind, size)+bytes(size)
                with self.assertRaises(dst.CodecValidationError):
                    decode(raw)
                # Isolate FP check even after suite is rewritten to receiver's.
                mixed = raw[:12]+dst._SUITE.to_bytes(2, 'big')+raw[14:]
                with self.assertRaises(dst.CodecValidationError):
                    decode(mixed)

    def test_domains_new_fingerprint_and_native_fixed_input_capacity(self):
        profile = p.load_profile_manifest()
        for domain in profile.symmetric.domains:
            self.assertTrue(domain.label.startswith(b'PQSAT-BUOV-CAP-HPLUS-0.1/'))
        self.assertNotEqual(transcript.derive_consistency_points(bytes(48)),
            __import__('pq_rbbc.blind_uov_pqsat_v0_1.transcript', fromlist=['derive_consistency_points']).derive_consistency_points(bytes(48)))
        for purpose, widths in (('seed_derivation', (32, 48, 4, 24)),
                                ('leaf_commitment', (32, 48, 2, 2, 24)),
                                ('tape_expansion', (32, 48, 2, 2, 24))):
            length = len(transcript.encode_tuple(profile.symmetric.domain(purpose), tuple(bytes(n) for n in widths)))
            self.assertLessEqual(length, 192)

    def test_unguarded_worker_fails_before_build_or_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)/'must-not-exist'
            command = [sys.executable, '-m', 'benchmarks.buov_cap_hplus_research_v0_1.regression',
                       '--worker', '--output', str(output)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('worker requires', result.stderr)
            self.assertFalse(output.exists())


class HPlusNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = os.environ.get('BUOV_HPLUS_TEST_BUILD')
        if not directory:
            raise unittest.SkipTest('run the explicit H+ regression entry to build both native controls')
        from pq_rbbc.blind_uov_hplus_research_v0_1 import native_opening as no
        cls.no = no
        cls.path = Path(directory)
        cls.kernel = no.NativeOpeningKernel.load(cls.path/'libopening_hplus.so',
            expected_sha256=hashlib.sha256((cls.path/'libopening_hplus.so').read_bytes()).hexdigest())
        cls.bound = cls.kernel.bind(threads=1)

    @classmethod
    def tearDownClass(cls):
        cls.bound.close(); cls.kernel.close()

    def test_incompatible_native_libraries_rejected_before_inputs(self):
        from pq_rbbc.blind_uov_pqsat_v0_1 import native_opening as old
        for wrapper, name in ((self.no, 'libopening_legacy_control.so'), (old, 'libopening_hplus.so')):
            library = self.path/name
            with self.assertRaises(wrapper.NativeOpeningError):
                wrapper.NativeOpeningKernel.load(library, expected_sha256=hashlib.sha256(library.read_bytes()).hexdigest())

    def test_native_new_profile_tuple_bytes_match_python(self):
        lines = subprocess.check_output([str(self.path/'input_controls')], text=True).splitlines()
        self.assertEqual(len(lines), 3)
        for index, purpose in enumerate(('seed_derivation', 'leaf_commitment', 'tape_expansion')):
            kind, length, hexadecimal = lines[index].split()
            fields = (p.PROFILE_FINGERPRINT, bytes(range(48)))
            fields += ((42).to_bytes(4, 'big'),) if index == 0 else ((2).to_bytes(2, 'big'), (2047).to_bytes(2, 'big'))
            fields += (bytes(range(64, 88)),)
            expected = transcript.encode_tuple(p.load_profile_manifest().symmetric.domain(purpose), fields)
            self.assertEqual((int(kind), int(length), bytes.fromhex(hexadecimal)), (index, len(expected), expected))

    def test_full_xi_native_matches_python_prover_and_verifier(self):
        # Standalone synthetic polynomial data: not an Init or a CAP proof.
        alpha = bytes(a ^ b for a, b in zip(independent_hash(bytes(range(256))), bytes(range(32))))
        all_vectors, raw = [], bytearray()
        for r, rep in enumerate(repetitions()):
            degree, modulus = (12, 0x1009) if r < 2 else (11, 0x805)
            vectors = tuple(tuple(v.plain ^ multiply(v.mask, 1, degree, modulus) for v in ps)
                for ps in (rep.witness_polynomials, rep.relation_masks, rep.consistency_masks))
            all_vectors.append(vectors)
            for vector in vectors:
                raw.extend(struct.pack('<'+'H'*len(vector), *vector))
        coverage = bytearray(b'\1'*40960)
        for r in range(18):
            coverage[r] = 0  # hidden position 0 for each repetition.
        replay = self.no.NativeOpeningReplay((0,)*18, bytes(1966080), bytes(983040),
            bytes(coverage), bytes(raw), (0.0,)*4)
        result = self.bound.build_xi(replay, corrections=bytes(4896), alpha_prime=alpha,
            consistency_points=POINTS, field_ids=(p.FieldId.GF_2_12,)*2+(p.FieldId.GF_2_11,)*16)
        expected = build_consistency_polynomials(repetitions(), POINTS)
        self.assertEqual(result.xi_encoded, encode_xi_polynomials(expected))
        for r, (w, _, m) in enumerate(all_vectors):
            self.assertEqual(_xi_from_opening(evaluation_point(0 if r < 2 else 1, 0), w, m, alpha, POINTS), expected[r])


if __name__ == '__main__':
    unittest.main()
