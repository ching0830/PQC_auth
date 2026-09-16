from __future__ import annotations

import unittest
from dataclasses import replace

from pq_rbbc_reference import LABEL_HOLD
from pq_sat_auth.v2.access import (
    REFERENCE_PROOF_SUITE_ID,
    REFERENCE_SUITE_ID,
    AccessRequestV2,
    ChannelBindingMode,
    derive_request_core_digest,
)
from pq_sat_auth.v2.framing import ProtocolEncodingError
from pq_sat_auth.v2.proof import (
    PRODUCTION_READY,
    AccessProofStatementV2,
    AccessProofWitnessV2,
    HOLDER_HASH_LABEL,
    build_access_statement,
    derive_holder_binding_tag,
    derive_holder_hash,
    evaluate_access_relation,
)


def fixed(value: int, size: int = 32) -> bytes:
    return bytes((value,)) * size


class AccessRelationV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = fixed(20)
        request = AccessRequestV2(
            suite_id=REFERENCE_SUITE_ID,
            proof_suite_id=REFERENCE_PROOF_SUITE_ID,
            system_config_digest=fixed(1),
            ctx=fixed(2),
            epoch=7,
            target_fgs_id=fixed(3),
            fgs_auth_key_id=fixed(4),
            serving_context_digest=fixed(5),
            authorization_digest=fixed(6),
            client_time=1_800_000_000,
            ue_nonce=fixed(7),
            attempt_nonce=fixed(8, 16),
            channel_binding_mode=ChannelBindingMode.NONE,
            channel_binding_digest=bytes(32),
            ticket=b"canonical-ticket",
            ue_kem_epk=b"ephemeral-kem-public-key",
            holder_binding_tag=bytes(32),
            access_nizk=b"test-only-access-proof",
        )
        self.request = replace(
            request,
            holder_binding_tag=derive_holder_binding_tag(
                self.secret,
                derive_request_core_digest(request),
            ),
        )
        self.statement = build_access_statement(
            access_profile_digest=fixed(30),
            access_pp_digest=fixed(31),
            holder_hash=derive_holder_hash(self.secret),
            request=self.request,
        )
        self.witness = AccessProofWitnessV2(self.secret)

    def test_statement_round_trip_and_relation_accept(self) -> None:
        encoded = self.statement.encode()
        self.assertEqual(len(encoded), 170)
        self.assertEqual(AccessProofStatementV2.decode(encoded), self.statement)
        result = evaluate_access_relation(self.statement, self.witness)
        self.assertTrue(result.accepted)
        self.assertEqual(result.failures, ())
        self.assertEqual(HOLDER_HASH_LABEL, LABEL_HOLD)
        self.assertFalse(PRODUCTION_READY)

    def test_holder_hash_and_tag_mutations_are_rejected(self) -> None:
        cases = (
            (replace(self.statement, holder_hash=fixed(50)), "holder_hash"),
            (
                replace(self.statement, holder_binding_tag=fixed(51)),
                "holder_binding_tag",
            ),
            (
                replace(self.statement, request_core_digest=fixed(52)),
                "holder_binding_tag",
            ),
        )
        for statement, failure in cases:
            with self.subTest(failure=failure):
                result = evaluate_access_relation(statement, self.witness)
                self.assertFalse(result.accepted)
                self.assertIn(failure, result.failures)

    def test_wrong_witness_fails_both_equalities(self) -> None:
        result = evaluate_access_relation(
            self.statement,
            AccessProofWitnessV2(fixed(60)),
        )
        self.assertFalse(result.accepted)
        self.assertEqual(
            set(result.failures),
            {"holder_hash", "holder_binding_tag"},
        )

    def test_request_core_mutation_is_visible_to_relation(self) -> None:
        changed_request = replace(self.request, target_fgs_id=fixed(70))
        changed_statement = build_access_statement(
            access_profile_digest=self.statement.access_profile_digest,
            access_pp_digest=self.statement.access_pp_digest,
            holder_hash=self.statement.holder_hash,
            request=changed_request,
        )
        self.assertNotEqual(
            changed_statement.request_core_digest,
            self.statement.request_core_digest,
        )
        result = evaluate_access_relation(changed_statement, self.witness)
        self.assertFalse(result.accepted)
        self.assertEqual(result.failures, ("holder_binding_tag",))

    def test_statement_parser_rejects_length_magic_and_version(self) -> None:
        encoded = bytearray(self.statement.encode())
        cases = (bytes(encoded[:-1]), bytes(encoded) + b"\x00")
        for malformed in cases:
            with self.assertRaises(ProtocolEncodingError):
                AccessProofStatementV2.decode(malformed)
        wrong_magic = encoded.copy()
        wrong_magic[0] ^= 1
        with self.assertRaises(ProtocolEncodingError):
            AccessProofStatementV2.decode(bytes(wrong_magic))
        wrong_version = encoded.copy()
        wrong_version[8:10] = (3).to_bytes(2, "big")
        with self.assertRaises(ProtocolEncodingError):
            AccessProofStatementV2.decode(bytes(wrong_version))


if __name__ == "__main__":
    unittest.main()
