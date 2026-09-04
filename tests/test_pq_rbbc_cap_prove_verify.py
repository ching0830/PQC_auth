import unittest

import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_prove_verify as implementation


class CAPProveVerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        parameters = cap.PRODUCTION_PARAMETERS
        cls.c_r = cap.serialize_commitment(
            parameters,
            (1, 2),
            3,
            4,
            (0,) * (parameters.tree_count - 1),
            (0,) * (parameters.tree_count - 1),
        )
        cls.c_x = bytes(range(implementation.C_X_BYTES))
        cls.statement = implementation.CAPStatement(
            bytes.fromhex(implementation.PROFILE_FINGERPRINT),
            bytes(range(32)),
            bytes(range(32, 64)),
            bytes(range(64, 96)),
            bytes(range(72)),
        )
        cls.proof = implementation.CAPProofEnvelope(
            cls.c_r,
            cls.c_x,
            (7).to_bytes(8, "little"),
            b"candidate-pi2-not-an-accepting-proof",
        )

    def test_statement_round_trip_is_exact(self) -> None:
        encoded = self.statement.encode()
        self.assertEqual(implementation.CAPStatement.decode(encoded), self.statement)
        for offset in (-1, 0):
            mutated = encoded[:offset] if offset == -1 else encoded + b"\x00"
            with self.assertRaises(implementation.CAPCodecError):
                implementation.CAPStatement.decode(mutated)

    def test_proof_envelope_round_trip_is_exact(self) -> None:
        encoded = self.proof.encode()
        self.assertEqual(implementation.CAPProofEnvelope.decode(encoded), self.proof)

    def test_proof_parser_rejects_header_and_section_mutations(self) -> None:
        encoded = bytearray(self.proof.encode())
        mutations = []
        wrong_magic = bytearray(encoded)
        wrong_magic[0] ^= 1
        mutations.append(wrong_magic)
        wrong_version = bytearray(encoded)
        wrong_version[len(implementation.PROOF_MAGIC)] ^= 1
        mutations.append(wrong_version)
        wrong_profile = bytearray(encoded)
        wrong_profile[len(implementation.PROOF_MAGIC) + 2] ^= 1
        mutations.append(wrong_profile)
        first_id = len(implementation.PROOF_MAGIC) + 2 + 32 + 2
        reordered = bytearray(encoded)
        reordered[first_id] = 2
        mutations.append(reordered)
        for mutated in mutations:
            with self.assertRaises(implementation.CAPCodecError):
                implementation.CAPProofEnvelope.decode(bytes(mutated))

    def test_proof_parser_rejects_payload_mutations(self) -> None:
        encoded = self.proof.encode()
        with self.assertRaises(implementation.CAPCodecError):
            implementation.CAPProofEnvelope.decode(encoded[:-1])
        with self.assertRaises(implementation.CAPCodecError):
            implementation.CAPProofEnvelope.decode(encoded + b"\x00")
        changed_c_r = bytearray(self.proof.c_r)
        changed_c_r[0] ^= 1
        with self.assertRaises(implementation.CAPCodecError):
            implementation.CAPProofEnvelope(
                bytes(changed_c_r),
                self.proof.c_x,
                self.proof.pow_nonce,
                self.proof.pi_2,
            ).encode()

    def test_candidate_c2_wrapper_is_not_c_x(self) -> None:
        candidate = (
            b"PQRBBC-CAP-APPEND-CANDIDATE-V1"
            + (1).to_bytes(2, "little")
            + bytes.fromhex(implementation.PROFILE_FINGERPRINT)
            + cap.PRODUCTION_PARAMETERS.appended_signature_bits.to_bytes(
                4, "little"
            )
            + self.c_x
        )
        self.assertNotEqual(len(candidate), implementation.C_X_BYTES)
        with self.assertRaises(implementation.CAPCodecError):
            implementation.CAPProofEnvelope(
                self.c_r,
                candidate,
                self.proof.pow_nonce,
                self.proof.pi_2,
            ).encode()

    def test_prove_and_verify_fail_closed(self) -> None:
        with self.assertRaises(implementation.ProductionProverUnavailable):
            implementation.prove(self.statement, object())
        result = implementation.verify(
            self.statement.encode(), self.proof.encode()
        )
        self.assertFalse(result.accepted)
        self.assertIn("production_pow_unavailable", result.failures)


if __name__ == "__main__":
    unittest.main()
