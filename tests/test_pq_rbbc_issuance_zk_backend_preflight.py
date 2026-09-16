import hashlib
import unittest
from dataclasses import replace
from pathlib import Path

import pq_rbbc_issuance_zk_backend_preflight as preflight


ROOT = Path(__file__).resolve().parents[1]


class IssuanceZKBackendPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend, self.pp, self.statement, self.witness = preflight.fixture()
        self.proof = preflight.ProveIssue(
            self.backend,
            self.pp,
            self.statement,
            self.witness,
            production=False,
        )

    @staticmethod
    def _wrong_version(encoded: bytes, magic: bytes) -> bytes:
        mutated = bytearray(encoded)
        mutated[len(magic)] ^= 1
        return bytes(mutated)

    @staticmethod
    def _wrong_first_section_id(encoded: bytes, magic: bytes) -> bytes:
        mutated = bytearray(encoded)
        first_id = len(magic) + 4
        mutated[first_id] ^= 1
        return bytes(mutated)

    def test_tracked_prerequisites_are_exact(self) -> None:
        self.assertEqual(preflight.validate_tracked_prerequisites(), ())

    def test_frozen_manifest_matches_generator(self) -> None:
        path = ROOT / "manifests/pq_rbbc_issuance_zk_backend_preflight_manifest_v1.json"
        self.assertEqual(path.read_bytes(), preflight.canonical_json(preflight.build_manifest()))

    def test_portable_evidence_matches_generator(self) -> None:
        path = (
            ROOT
            / "artifacts/metadata/issuance_zk_backend_preflight_v1/"
            "pq_rbbc_issuance_zk_backend_preflight_evidence_v1.json"
        )
        self.assertEqual(
            path.read_bytes(),
            preflight.canonical_json(preflight.build_portable_evidence()),
        )

    def test_statement_round_trip_and_field_contract(self) -> None:
        statement = preflight.IssueStatementV1.decode(self.statement)
        self.assertEqual(statement.encode(), self.statement)
        self.assertEqual(len(statement.ctx), 32)
        self.assertEqual(len(statement.sid), 32)
        self.assertEqual(len(statement.rid), 32)
        self.assertEqual(len(statement.beta), 72)
        self.assertEqual(statement.abi_profile_digest, preflight.ABI_PROFILE_DIGEST)

    def test_witness_round_trip_and_private_partition(self) -> None:
        witness = preflight.IssueWitnessV1.decode(self.witness)
        self.assertEqual(witness.encode(), self.witness)
        self.assertEqual(len(witness.ticket_payload), 368)
        self.assertEqual(len(witness.blind_mask), 72)
        self.assertEqual(len(witness.cap_randomness), preflight.CAP_RANDOMNESS_BYTES)
        preflight.validate_cap_randomness_encoding(witness.cap_randomness)
        self.assertEqual(len(witness.holder_key), 32)
        self.assertEqual(len(witness.error_vector), 836)

    def test_legacy_32_byte_test_nonce_is_not_accepted_as_formal_rho(self) -> None:
        witness = preflight.IssueWitnessV1.decode(self.witness)
        wrong = replace(witness, cap_randomness=bytes(32))
        with self.assertRaises(preflight.CanonicalEncodingError):
            wrong.encode()

    def test_noncanonical_cap_field_element_is_rejected(self) -> None:
        witness = preflight.IssueWitnessV1.decode(self.witness)
        randomness = bytearray(witness.cap_randomness)
        first_salt_last_byte = len(preflight.cap.RANDOMNESS_MAGIC) + 64 + 24
        randomness[first_salt_last_byte] |= 0x80
        wrong = replace(witness, cap_randomness=bytes(randomness))
        with self.assertRaises(preflight.CanonicalEncodingError):
            wrong.encode()

    def test_public_parameters_and_proof_round_trip(self) -> None:
        parameters = preflight.IssuePublicParametersV1.decode(self.pp)
        proof = preflight.IssueProofV1.decode(self.proof)
        self.assertEqual(parameters.encode(), self.pp)
        self.assertEqual(proof.encode(), self.proof)
        self.assertEqual(proof.public_parameters_digest, hashlib.sha256(self.pp).digest())
        self.assertEqual(proof.statement_digest, hashlib.sha256(self.statement).digest())
        self.assertEqual(proof.transcript_domain, preflight.TRANSCRIPT_DOMAIN)

    def test_positive_test_only_flow(self) -> None:
        self.assertTrue(
            preflight.VerifyIssue(
                self.backend,
                self.pp,
                self.statement,
                self.proof,
                production=False,
            )
        )

    def test_test_backend_is_explicitly_insecure(self) -> None:
        self.assertIn("INSECURE-TEST-ONLY", self.backend.backend_id)
        security = self.backend.security
        self.assertTrue(security.test_only)
        self.assertFalse(security.post_quantum)
        self.assertFalse(security.zero_knowledge)
        self.assertFalse(security.knowledge_extractable)
        self.assertFalse(security.simulation_extractable)
        self.assertFalse(security.production_qualified)

    def test_production_setup_refuses_before_output(self) -> None:
        with self.assertRaises(preflight.ProductionBackendUnavailable):
            preflight.Setup(
                self.backend,
                "insecure-test-only-128",
                bytes(32),
            )

    def test_production_prove_and_verify_refuse(self) -> None:
        with self.assertRaises(preflight.ProductionBackendUnavailable):
            preflight.ProveIssue(
                self.backend, self.pp, self.statement, self.witness
            )
        with self.assertRaises(preflight.ProductionBackendUnavailable):
            preflight.VerifyIssue(
                self.backend, self.pp, self.statement, self.proof
            )

    def test_wrong_statement_is_rejected(self) -> None:
        statement = bytearray(self.statement)
        statement[-1] ^= 1
        self.assertFalse(
            preflight.VerifyIssue(
                self.backend,
                self.pp,
                bytes(statement),
                self.proof,
                production=False,
            )
        )

    def test_wrong_domain_is_rejected(self) -> None:
        proof = preflight.IssueProofV1.decode(self.proof)
        wrong = replace(proof, transcript_domain=b"PQ-RBBC/WRONG-DOMAIN/V1").encode()
        self.assertFalse(
            preflight.VerifyIssue(
                self.backend, self.pp, self.statement, wrong, production=False
            )
        )

    def test_proof_mutation_is_rejected(self) -> None:
        proof = bytearray(self.proof)
        proof[-1] ^= 1
        self.assertFalse(
            preflight.VerifyIssue(
                self.backend,
                self.pp,
                self.statement,
                bytes(proof),
                production=False,
            )
        )

    def test_wrong_public_parameters_are_rejected(self) -> None:
        parameters = preflight.IssuePublicParametersV1.decode(self.pp)
        wrong = replace(parameters, backend_payload=bytes(32)).encode()
        self.assertFalse(
            preflight.VerifyIssue(
                self.backend,
                wrong,
                self.statement,
                self.proof,
                production=False,
            )
        )

    def test_wrong_statement_profile_is_rejected_by_prover_and_verifier(self) -> None:
        statement = preflight.IssueStatementV1.decode(self.statement)
        wrong = replace(statement, abi_profile_digest=bytes(32)).encode()
        with self.assertRaises(preflight.CanonicalEncodingError):
            preflight.ProveIssue(
                self.backend, self.pp, wrong, self.witness, production=False
            )
        self.assertFalse(
            preflight.VerifyIssue(
                self.backend, self.pp, wrong, self.proof, production=False
            )
        )

    def test_wrong_witness_profile_is_rejected(self) -> None:
        witness = preflight.IssueWitnessV1.decode(self.witness)
        wrong = replace(witness, abi_profile_digest=bytes(32)).encode()
        with self.assertRaises(preflight.CanonicalEncodingError):
            preflight.ProveIssue(
                self.backend, self.pp, self.statement, wrong, production=False
            )

    def test_wrong_version_is_rejected_for_every_codec(self) -> None:
        cases = (
            (preflight.IssuePublicParametersV1, self.pp, preflight.PP_MAGIC),
            (preflight.IssueStatementV1, self.statement, preflight.STATEMENT_MAGIC),
            (preflight.IssueWitnessV1, self.witness, preflight.WITNESS_MAGIC),
            (preflight.IssueProofV1, self.proof, preflight.PROOF_MAGIC),
        )
        for codec, encoded, magic in cases:
            with self.subTest(codec=codec.__name__):
                with self.assertRaises(preflight.CanonicalEncodingError):
                    codec.decode(self._wrong_version(encoded, magic))

    def test_trailing_bytes_are_rejected_for_every_codec(self) -> None:
        cases = (
            (preflight.IssuePublicParametersV1, self.pp),
            (preflight.IssueStatementV1, self.statement),
            (preflight.IssueWitnessV1, self.witness),
            (preflight.IssueProofV1, self.proof),
        )
        for codec, encoded in cases:
            with self.subTest(codec=codec.__name__):
                with self.assertRaises(preflight.CanonicalEncodingError):
                    codec.decode(encoded + b"\x00")

    def test_reordered_or_unknown_section_is_rejected(self) -> None:
        cases = (
            (preflight.IssuePublicParametersV1, self.pp, preflight.PP_MAGIC),
            (preflight.IssueStatementV1, self.statement, preflight.STATEMENT_MAGIC),
            (preflight.IssueWitnessV1, self.witness, preflight.WITNESS_MAGIC),
            (preflight.IssueProofV1, self.proof, preflight.PROOF_MAGIC),
        )
        for codec, encoded, magic in cases:
            with self.subTest(codec=codec.__name__):
                with self.assertRaises(preflight.CanonicalEncodingError):
                    codec.decode(self._wrong_first_section_id(encoded, magic))

    def test_truncation_is_rejected_for_every_codec(self) -> None:
        cases = (
            (preflight.IssuePublicParametersV1, self.pp),
            (preflight.IssueStatementV1, self.statement),
            (preflight.IssueWitnessV1, self.witness),
            (preflight.IssueProofV1, self.proof),
        )
        for codec, encoded in cases:
            with self.subTest(codec=codec.__name__):
                with self.assertRaises(preflight.CanonicalEncodingError):
                    codec.decode(encoded[:-1])

    def test_statement_public_parameter_binding_is_enforced(self) -> None:
        statement = preflight.IssueStatementV1.decode(self.statement)
        wrong = replace(statement, public_parameters_digest=bytes(32)).encode()
        with self.assertRaises(preflight.CanonicalEncodingError):
            preflight.ProveIssue(
                self.backend, self.pp, wrong, self.witness, production=False
            )
        self.assertFalse(
            preflight.VerifyIssue(
                self.backend, self.pp, wrong, self.proof, production=False
            )
        )

    def test_candidate_table_does_not_overclaim_simulation_extractability(self) -> None:
        candidates = preflight.candidate_backends()
        self.assertGreaterEqual(len(candidates), 4)
        for candidate in candidates:
            self.assertNotEqual(candidate["simulation_extractability"], "established")
            self.assertTrue(candidate["source"].startswith("https://"))

    def test_manifest_keeps_formal_replay_boundary_closed(self) -> None:
        manifest = preflight.build_manifest()
        finding = manifest["relation_partition_findings"]
        gate = manifest["production_gate"]
        claims = manifest["claim_status"]
        self.assertTrue(finding["legacy_payload_is_public_but_formal_M_is_private"])
        self.assertFalse(finding["legacy_replay_is_formal_pi_issue_relation"])
        self.assertTrue(finding["new_relation_namespace_required"])
        self.assertTrue(gate["production_backend_allowlist_empty"])
        self.assertFalse(gate["safe_to_start_large_proving_run"])
        self.assertFalse(claims["Proof-closed"])
        self.assertFalse(claims["Production-closed"])

    def test_bounded_self_check_has_no_relation_replay_or_crypto_proof(self) -> None:
        result = preflight.run_bounded_self_check()
        self.assertTrue(result["positive_verified"])
        self.assertEqual(result["negative_cases_rejected"], result["negative_cases"])
        self.assertEqual(
            result["production_entry_points_refused"],
            result["production_entry_points"],
        )
        self.assertEqual(result["relation_constraints_replayed"], 0)
        self.assertEqual(result["cryptographic_proofs_generated"], 0)


if __name__ == "__main__":
    unittest.main()
