import unittest

from pq_threshold_candidates import (
    PROFILES, Candidate, ContractError, ResearchCiphertext, TraceInputs,
    Unsupported, decode_ciphertext, decode_trace_inputs, encode_ciphertext,
    get_backend, get_profile,
)
from pq_threshold_candidates.contracts import MAGIC, MAX_PAYLOAD_BYTES, envelope_overhead


class CodecTests(unittest.TestCase):
    candidate = Candidate.NIED
    profile_id = "nied-6688128-estimate-v1"

    def fixture(self):
        # Opaque public codec bytes, not an encryption output or a secret witness.
        return ResearchCiphertext(self.candidate, self.profile_id, b"\x11\x22\x33")

    def decode(self, data, **overrides):
        args = dict(expected_candidate=self.candidate, expected_profile_id=self.profile_id)
        args.update(overrides)
        return decode_ciphertext(data, **args)

    def test_independent_wire_vector(self):
        expected = (b"PQ-THRESHOLD-RESEARCH-CIPHERTEXT\x00\x01\x00"
                    b"\x07TH-NIED\x18nied-6688128-estimate-v1"
                    b"\x03\x00\x00\x00\x11\x22\x33")
        self.assertEqual(encode_ciphertext(self.fixture()), expected)
        self.assertEqual(self.decode(expected), self.fixture())

    def test_all_profile_round_trips_and_overhead(self):
        for profile in PROFILES.values():
            with self.subTest(profile=profile.profile_id):
                value = ResearchCiphertext(profile.candidate, profile.profile_id, b"opaque")
                data = encode_ciphertext(value)
                self.assertEqual(len(data) - 6, envelope_overhead(profile.candidate, profile.profile_id))
                self.assertEqual(decode_ciphertext(data, expected_candidate=profile.candidate,
                                                  expected_profile_id=profile.profile_id), value)

    def test_every_truncation_rejected(self):
        data = encode_ciphertext(self.fixture())
        for offset in range(len(data)):
            with self.subTest(offset=offset), self.assertRaises(ContractError):
                self.decode(data[:offset])

    def test_unknown_version_and_domain_rejected(self):
        data = encode_ciphertext(self.fixture())
        for offset in (0, len(MAGIC), len(MAGIC) + 1):
            mutated = bytearray(data)
            mutated[offset] ^= 0x40
            with self.subTest(offset=offset), self.assertRaises(ContractError):
                self.decode(bytes(mutated))

    def test_unknown_candidate_and_profile_rejected(self):
        data = encode_ciphertext(self.fixture())
        for mutated in (data.replace(b"TH-NIED", b"TH-XXXX"),
                        data.replace(b"estimate-v1", b"estimate-v2"),
                        data.replace(b"TH-NIED", b"TH-NIE\xff")):
            with self.assertRaises(ContractError):
                self.decode(mutated)

    def test_pinned_candidate_and_profile_required(self):
        data = encode_ciphertext(self.fixture())
        with self.assertRaises(ContractError):
            self.decode(data, expected_candidate=Candidate.UT,
                        expected_profile_id="ut-mlkem768-estimate-v1")
        gf = encode_ciphertext(ResearchCiphertext(Candidate.GF, "gf-pompeii-d4-estimate-v1", b"x"))
        with self.assertRaises(ContractError):
            self.decode(gf, expected_candidate=Candidate.GF,
                        expected_profile_id="gf-pompeii-d9-estimate-v1")
        with self.assertRaises(TypeError):
            decode_ciphertext(data)

    def test_lengths_trailing_and_alternate_identifier_rejected(self):
        data = encode_ciphertext(self.fixture())
        length_offset = len(data) - 3 - 4
        for length in (0, 2, 4, MAX_PAYLOAD_BYTES + 1, 2**32 - 1):
            mutated = data[:length_offset] + length.to_bytes(4, "little") + data[length_offset + 4:]
            with self.subTest(length=length), self.assertRaises(ContractError):
                self.decode(mutated)
        with self.assertRaises(ContractError):
            self.decode(data + b"\x00")
        # A longer spelling with a NUL terminator is not an alternate profile encoding.
        start = len(MAGIC) + 2 + 1 + 7
        mutated = data[:start] + bytes([len(self.profile_id) + 1]) + self.profile_id.encode() + b"\x00" + data[length_offset:]
        with self.assertRaises(ContractError):
            self.decode(mutated)

    def test_exact_bytes_type_and_payload_bounds(self):
        for payload in (b"", bytearray(b"x"), "x", b"x" * (MAX_PAYLOAD_BYTES + 1)):
            with self.subTest(kind=type(payload).__name__), self.assertRaises(ContractError):
                ResearchCiphertext(self.candidate, self.profile_id, payload)
        with self.assertRaises(ContractError):
            self.decode(bytearray(encode_ciphertext(self.fixture())))
        value = ResearchCiphertext(self.candidate, self.profile_id, b"x" * MAX_PAYLOAD_BYTES)
        self.assertEqual(self.decode(encode_ciphertext(value)), value)

    def test_integer_bool_overflow_negative_version_rejected(self):
        for version in (True, False, -1, 65536, 1.0, "1", 0, 2):
            with self.subTest(version=version), self.assertRaises(ContractError):
                ResearchCiphertext(self.candidate, self.profile_id, b"x", version)

    def test_profile_identity_is_closed_world(self):
        for candidate, profile in (("TH-NIED", self.profile_id), (True, self.profile_id),
                                   (Candidate.GF, self.profile_id), (self.candidate, None),
                                   (self.candidate, self.profile_id.upper())):
            with self.assertRaises(ContractError):
                get_profile(candidate, profile)
        with self.assertRaises(TypeError):
            PROFILES["attacker-production"] = PROFILES[self.profile_id]


class TraceInputTests(unittest.TestCase):
    def test_fixed_layout_and_round_trip(self):
        value = TraceInputs(bytes(range(32)), b"s" * 16, b"c" * 32, b"h" * 32)
        self.assertEqual(value.plaintext, bytes(range(32)) + b"s" * 16)
        self.assertEqual(value.associated_data, b"c" * 32 + b"s" * 16 + b"h" * 32)
        self.assertEqual(decode_trace_inputs(value.plaintext, value.associated_data), value)

    def test_each_field_wrong_length_or_type(self):
        values = dict(rid=b"r" * 32, sn=b"s" * 16, ctx=b"c" * 32, h=b"h" * 32)
        for name, original in values.items():
            for invalid in (original[:-1], original + b"x", bytearray(original), len(original), None):
                with self.subTest(field=name), self.assertRaises(ContractError):
                    TraceInputs(**dict(values, **{name: invalid}))

    def test_plaintext_and_ad_length_mismatch(self):
        for size in (0, 47, 49, 80):
            with self.assertRaises(ContractError):
                decode_trace_inputs(b"x" * size, b"x" * 80)
        for size in (0, 48, 79, 81):
            with self.assertRaises(ContractError):
                decode_trace_inputs(b"x" * 48, b"x" * size)

    def test_different_serials_rejected(self):
        with self.assertRaises(ContractError):
            decode_trace_inputs(b"r" * 32 + b"a" * 16, b"c" * 32 + b"b" * 16 + b"h" * 32)


class UnavailableTests(unittest.TestCase):
    def test_production_default_and_explicit_reject_every_profile(self):
        for profile in PROFILES.values():
            for kwargs in ({}, {"purpose": "production"}):
                with self.subTest(profile=profile.profile_id), self.assertRaises(Unsupported):
                    get_backend(profile.candidate, profile.profile_id, **kwargs)

    def test_research_fixture_cannot_enable_crypto(self):
        inputs = TraceInputs(b"r" * 32, b"s" * 16, b"c" * 32, b"h" * 32)
        for profile in PROFILES.values():
            backend = get_backend(profile.candidate, profile.profile_id, purpose="research")
            ct = ResearchCiphertext(profile.candidate, profile.profile_id, b"opaque")
            operations = (
                ("encrypt_reference", dict(public_key=b"", inputs=inputs, randomness=b"")),
                ("check_encryption_relation", dict(public_key=b"", inputs=inputs, ciphertext=ct, witness=b"")),
                ("decrypt_reference_for_test", dict(secret_key=b"", ciphertext=ct, associated_data=inputs.associated_data)),
                ("create_share", dict(context=object())),
                ("start_opening", dict(context=object())),
                ("advance_opening", dict(session=object(), message=b"x")),
                ("combine", dict(context=object(), shares=(b"opaque",))),
            )
            for method, kwargs in operations:
                with self.subTest(profile=profile.profile_id, method=method), self.assertRaises(Unsupported):
                    getattr(backend, method)(**kwargs)

    def test_unknown_purpose_and_fake_production_profile_rejected(self):
        for purpose in (True, None, "test", "PRODUCTION", 1):
            with self.assertRaises(ContractError):
                get_backend(Candidate.NIED, "nied-6688128-estimate-v1", purpose=purpose)
        with self.assertRaises(ContractError):
            get_backend(Candidate.NIED, "nied-6688128-production-v1", purpose="research")


if __name__ == "__main__":
    unittest.main()
