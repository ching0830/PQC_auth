import hashlib
import unittest
from dataclasses import replace
from pathlib import Path

import pq_rbbc_issuance_relation_v1 as relation
import pq_rbbc_issuance_zk_backend_preflight as backend_preflight


ROOT = Path(__file__).resolve().parents[1]


class IssuanceRelationV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = relation.fixture()
        self.parameters = relation.TestOnlyIssueRelationParametersV1.decode(
            self.fixture.parameters
        )
        self.statement = backend_preflight.IssueStatementV1.decode(
            self.fixture.statement
        )
        self.witness = backend_preflight.IssueWitnessV1.decode(
            self.fixture.witness
        )

    @staticmethod
    def _flip(value: bytes, offset: int = 0) -> bytes:
        changed = bytearray(value)
        changed[offset] ^= 1
        return bytes(changed)

    def _evaluate(
        self,
        *,
        statement: bytes | None = None,
        witness: bytes | None = None,
        parameters: bytes | None = None,
    ) -> relation.RelationEvaluation:
        return relation.evaluate_relation(
            self.fixture.parameters if parameters is None else parameters,
            self.fixture.statement if statement is None else statement,
            self.fixture.witness if witness is None else witness,
            production=False,
        )

    def test_tracked_prerequisites_are_exact(self) -> None:
        self.assertEqual(relation.validate_tracked_prerequisites(), ())

    def test_frozen_manifest_matches_generator(self) -> None:
        path = ROOT / "manifests/pq_rbbc_issuance_relation_manifest_v1.json"
        self.assertEqual(path.read_bytes(), relation.canonical_json(relation.build_manifest()))

    def test_portable_evidence_matches_generator(self) -> None:
        path = (
            ROOT
            / "artifacts/metadata/issuance_relation_v1/"
            "pq_rbbc_issuance_relation_portable_evidence_v1.json"
        )
        self.assertEqual(
            path.read_bytes(), relation.canonical_json(relation.build_portable_evidence())
        )

    def test_relation_parameters_round_trip_and_profile(self) -> None:
        self.assertEqual(self.parameters.encode(), self.fixture.parameters)
        self.assertEqual(self.parameters.relation_id, relation.RELATION_ID)
        self.assertEqual(self.parameters.mode, relation.TEST_ONLY_MODE)
        self.assertEqual(
            self.parameters.target_cap_profile_digest,
            relation.TARGET_CAP_PROFILE_DIGEST,
        )
        self.assertEqual(
            self.parameters.trace_public_key_digest,
            relation.trace_public_key_digest(self.parameters.matrix_seed),
        )

    def test_parameter_codec_rejects_version_order_trailing_and_truncation(self) -> None:
        cases = []
        wrong_version = bytearray(self.fixture.parameters)
        wrong_version[len(relation.PARAMETERS_MAGIC)] ^= 1
        cases.append(bytes(wrong_version))
        wrong_id = bytearray(self.fixture.parameters)
        wrong_id[len(relation.PARAMETERS_MAGIC) + 4] ^= 1
        cases.append(bytes(wrong_id))
        cases.append(self.fixture.parameters + b"\x00")
        cases.append(self.fixture.parameters[:-1])
        for encoded in cases:
            with self.subTest(length=len(encoded)):
                with self.assertRaises(relation.IssuanceRelationError):
                    relation.TestOnlyIssueRelationParametersV1.decode(encoded)

    def test_positive_structural_relation_maps_every_conjunct(self) -> None:
        result = self._evaluate()
        self.assertTrue(result.ok)
        self.assertFalse(result.production_qualified)
        self.assertEqual(result.failures, ())
        for name in ("P0_parameters", "P1_abi", "I1", "I2", "I3", "I4", "I5"):
            self.assertTrue(result.check(name), name)

    def test_ticket_payload_is_private_statement_excludes_it(self) -> None:
        self.assertNotIn(self.witness.ticket_payload, self.fixture.statement)
        manifest = relation.build_manifest()
        self.assertEqual(
            manifest["formal_contract"]["private_witness"],
            ["M", "r", "rho", "k_hold", "e"],
        )
        self.assertTrue(manifest["formal_contract"]["ticket_payload_is_private"])

    def test_public_parameter_digest_binding_rejects(self) -> None:
        wrong = replace(
            self.statement, public_parameters_digest=bytes(32)
        ).encode()
        result = self._evaluate(statement=wrong)
        self.assertFalse(result.ok)
        self.assertFalse(result.check("P0_parameters"))

    def test_context_mismatch_rejects_i1(self) -> None:
        payload = self._flip(self.witness.ticket_payload, 0)
        wrong = replace(self.witness, ticket_payload=payload).encode()
        result = self._evaluate(witness=wrong)
        self.assertFalse(result.ok)
        self.assertFalse(result.check("I1"))

    def test_ticket_mutation_is_bound_through_i3(self) -> None:
        payload = self._flip(self.witness.ticket_payload, 367)
        wrong = replace(self.witness, ticket_payload=payload).encode()
        result = self._evaluate(witness=wrong)
        self.assertFalse(result.ok)
        self.assertFalse(result.check("I3"))

    def test_request_mutation_rejects_i3(self) -> None:
        wrong = replace(self.statement, beta=self._flip(self.statement.beta)).encode()
        result = self._evaluate(statement=wrong)
        self.assertFalse(result.ok)
        self.assertFalse(result.check("I3"))

    def test_mask_mutation_rejects_i3(self) -> None:
        wrong = replace(
            self.witness, blind_mask=self._flip(self.witness.blind_mask)
        ).encode()
        result = self._evaluate(witness=wrong)
        self.assertFalse(result.ok)
        self.assertFalse(result.check("I3"))

    def test_canonical_cap_randomness_mutation_rejects_i3(self) -> None:
        randomness = bytearray(self.witness.cap_randomness)
        randomness[len(relation.cap.RANDOMNESS_MAGIC) + 64] ^= 1
        wrong = replace(self.witness, cap_randomness=bytes(randomness)).encode()
        result = self._evaluate(witness=wrong)
        self.assertFalse(result.ok)
        self.assertFalse(result.check("I3"))

    def test_holder_key_mutation_rejects_i4_and_trace(self) -> None:
        wrong = replace(
            self.witness, holder_key=self._flip(self.witness.holder_key)
        ).encode()
        result = self._evaluate(witness=wrong)
        self.assertFalse(result.ok)
        self.assertFalse(result.check("I4"))
        self.assertFalse(result.check("I5"))

    def test_identity_mutation_rejects_i5(self) -> None:
        wrong = replace(self.statement, rid=self._flip(self.statement.rid)).encode()
        result = self._evaluate(statement=wrong)
        self.assertFalse(result.ok)
        self.assertFalse(result.check("I5"))

    def test_serial_mutation_rejects_i5_and_i3(self) -> None:
        payload = self._flip(self.witness.ticket_payload, 32)
        wrong = replace(self.witness, ticket_payload=payload).encode()
        result = self._evaluate(witness=wrong)
        self.assertFalse(result.ok)
        self.assertFalse(result.check("I3"))
        self.assertFalse(result.check("I5"))

    def test_error_mutation_rejects_i5(self) -> None:
        wrong = replace(
            self.witness, error_vector=self._flip(self.witness.error_vector)
        ).encode()
        result = self._evaluate(witness=wrong)
        self.assertFalse(result.ok)
        self.assertFalse(result.check("I5"))

    def test_production_relation_refuses_before_evaluation(self) -> None:
        with self.assertRaises(relation.ProductionIssuanceRelationUnavailable):
            relation.evaluate_relation(
                self.fixture.parameters,
                self.fixture.statement,
                self.fixture.witness,
            )

    def test_i3_adapter_is_visibly_test_only_and_not_production_cap(self) -> None:
        self.assertIn("INSECURE-TEST-ONLY", relation.TEST_ONLY_I3_ADAPTER_ID)
        self.assertFalse(relation.InsecureTestOnlyI3Adapter.production_qualified)
        profile = relation.build_manifest()["executable_profile"]
        self.assertFalse(profile["i3_adapter_is_cap_commit"])
        self.assertFalse(profile["i3_adapter_is_h_rbbc"])

    def test_fresh_issuer_sid_candidate_accepts_read_only(self) -> None:
        result = relation.validate_issuer_sid_candidate(
            self.fixture.statement,
            expected_issuer_sid=self.fixture.issuer_sid,
            used_sid_snapshot=frozenset(),
            production=False,
        )
        self.assertTrue(result.ok)
        self.assertFalse(result.state_reserved)
        self.assertFalse(result.freshness_proved_by_relation)

    def test_reused_or_wrong_issuer_sid_rejects(self) -> None:
        reused = relation.validate_issuer_sid_candidate(
            self.fixture.statement,
            expected_issuer_sid=self.fixture.issuer_sid,
            used_sid_snapshot=frozenset((self.fixture.issuer_sid,)),
            production=False,
        )
        wrong = relation.validate_issuer_sid_candidate(
            self.fixture.statement,
            expected_issuer_sid=bytes(32),
            used_sid_snapshot=frozenset(),
            production=False,
        )
        self.assertFalse(reused.ok)
        self.assertIn("sid_already_used", reused.failures)
        self.assertFalse(wrong.ok)
        self.assertIn("issuer_sid_binding", wrong.failures)

    def test_zero_sid_and_noncanonical_registry_snapshot_reject(self) -> None:
        zero_statement = replace(self.statement, sid=bytes(32)).encode()
        zero = relation.validate_issuer_sid_candidate(
            zero_statement,
            expected_issuer_sid=bytes(32),
            used_sid_snapshot=frozenset(),
            production=False,
        )
        malformed = relation.validate_issuer_sid_candidate(
            self.fixture.statement,
            expected_issuer_sid=self.fixture.issuer_sid,
            used_sid_snapshot=frozenset((b"short",)),
            production=False,
        )
        self.assertFalse(zero.ok)
        self.assertIn("zero_sid", zero.failures)
        self.assertFalse(malformed.ok)
        self.assertIn("used_sid_snapshot_encoding", malformed.failures)

    def test_sid_preflight_production_refuses_without_reservation(self) -> None:
        with self.assertRaises(relation.ProductionIssuanceRelationUnavailable):
            relation.validate_issuer_sid_candidate(
                self.fixture.statement,
                expected_issuer_sid=self.fixture.issuer_sid,
                used_sid_snapshot=frozenset(),
            )

    def test_sid_is_statement_bound_but_freshness_is_external(self) -> None:
        changed_sid = hashlib.sha256(b"different issuer session").digest()
        changed = replace(self.statement, sid=changed_sid).encode()
        self.assertTrue(self._evaluate(statement=changed).ok)
        self.assertNotEqual(
            hashlib.sha256(changed).digest(),
            hashlib.sha256(self.fixture.statement).digest(),
        )
        sid_result = relation.validate_issuer_sid_candidate(
            changed,
            expected_issuer_sid=self.fixture.issuer_sid,
            used_sid_snapshot=frozenset(),
            production=False,
        )
        self.assertFalse(sid_result.ok)
        self.assertIn("issuer_sid_binding", sid_result.failures)

    def test_fixture_sid_is_not_legacy_witness_derived_sid(self) -> None:
        payload = relation.decode_ticket_payload(self.witness.ticket_payload)
        legacy = hashlib.sha256(
            b"PQ-RBBC/v2.37/unified-statement/session" + payload.sn
        ).digest()
        self.assertNotEqual(self.fixture.issuer_sid, legacy)

    def test_evidence_contains_no_private_witness_or_large_output(self) -> None:
        evidence = relation.canonical_json(relation.build_portable_evidence())
        self.assertNotIn(self.witness.ticket_payload, evidence)
        self.assertNotIn(self.fixture.witness.hex().encode("ascii"), evidence)
        self.assertNotIn(b"witness_hex", evidence)
        self.assertEqual(
            relation.build_portable_evidence()["bounded_self_check"][
                "relation_constraints_replayed"
            ],
            0,
        )

    def test_bounded_self_check_is_complete_and_fail_closed(self) -> None:
        result = relation.run_bounded_self_check()
        self.assertTrue(result["positive_relation_all_conjuncts"])
        self.assertEqual(result["negative_cases"], result["negative_cases_rejected"])
        self.assertTrue(result["sid_candidate_positive"])
        self.assertTrue(result["sid_replay_rejected"])
        self.assertEqual(
            result["production_entry_points"],
            result["production_entry_points_refused"],
        )
        self.assertEqual(result["relation_constraints_replayed"], 0)
        self.assertEqual(result["cryptographic_proofs_generated"], 0)


if __name__ == "__main__":
    unittest.main()
