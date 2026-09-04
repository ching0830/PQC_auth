import hashlib
import unittest

import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_straightline_extractor as extractor


class CAPStraightLineExtractorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.parameters = cap.REDUCED_TEST_PARAMETERS
        randomness = cap.deterministic_randomness(
            cls.parameters,
            b"PQ-RBBC/v2.31/extractor-reduced-vector",
        )
        cls.execution = cap.execute_cap_commit(cls.parameters, randomness)
        cls.records = extractor.transcript_records(cls.execution.xof_calls)

    def test_ext1_recovers_mask_from_only_transcript_and_c1(self) -> None:
        recovered = extractor.extract_ext1(
            self.records,
            self.execution.commitment.encoded,
            self.parameters,
        )
        self.assertEqual(recovered, self.execution.commitment.derived_mask)

    def test_ext2_recovers_mask_and_appended_witness(self) -> None:
        bits = self.parameters.appended_signature_bits
        expected_x = int.from_bytes(
            hashlib.shake_256(b"v2.31-reduced-x").digest((bits + 7) // 8),
            "little",
        ) & ((1 << bits) - 1)
        delta = self.execution.commitment.append_signature(expected_x, bits)
        c2 = extractor.serialize_candidate_append(delta, self.parameters)
        self.assertEqual(
            extractor.extract_ext2(
                self.records,
                self.execution.commitment.encoded,
                c2,
                self.parameters,
            ),
            (self.execution.commitment.derived_mask, expected_x),
        )

    def test_extractor_has_no_final_proof_parameter(self) -> None:
        with self.assertRaises(TypeError):
            extractor.extract_ext1(
                self.records,
                self.execution.commitment.encoded,
                self.parameters,
                b"final-proof",
            )

    def test_reordered_or_wrong_width_transcript_rejects(self) -> None:
        reordered = [dict(item) for item in self.records]
        reordered[0], reordered[1] = reordered[1], reordered[0]
        with self.assertRaisesRegex(
            extractor.ExtractionFailure, "non-contiguous order"
        ):
            extractor.extract_ext1(
                reordered,
                self.execution.commitment.encoded,
                self.parameters,
            )
        wrong_width = [dict(item) for item in self.records]
        wrong_width[0]["output_bits"] -= 1
        with self.assertRaisesRegex(
            extractor.ExtractionFailure, "wrong output width"
        ):
            extractor.extract_ext1(
                wrong_width,
                self.execution.commitment.encoded,
                self.parameters,
            )

    def test_conflicting_repeated_query_rejects(self) -> None:
        records = [dict(item) for item in self.records]
        repeated = dict(records[0])
        repeated["sequence_index"] = len(records)
        output = bytearray.fromhex(repeated["canonical_output"])
        output[0] ^= 1
        repeated["canonical_output"] = bytes(output).hex()
        records.append(repeated)
        with self.assertRaisesRegex(
            extractor.ExtractionFailure, "conflicting repeated query"
        ):
            extractor.parse_transcript(records)

    def test_commitment_and_candidate_append_are_strict(self) -> None:
        with self.assertRaisesRegex(
            extractor.ExtractionFailure, "trailing bytes"
        ):
            extractor.parse_commitment(
                self.execution.commitment.encoded + b"\x00",
                self.parameters,
            )
        encoded = extractor.serialize_candidate_append(0, self.parameters)
        mutated = bytearray(encoded)
        mutated[len(extractor.APPEND_MAGIC) + 2] ^= 1
        with self.assertRaisesRegex(
            extractor.ExtractionFailure, "wrong profile fingerprint"
        ):
            extractor.parse_candidate_append(bytes(mutated), self.parameters)


if __name__ == "__main__":
    unittest.main()
