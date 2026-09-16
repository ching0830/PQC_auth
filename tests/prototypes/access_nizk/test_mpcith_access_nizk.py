from __future__ import annotations

import hashlib
import unittest
from dataclasses import replace

from pq_sat_auth.v2.access import (
    REFERENCE_PROOF_SUITE_ID,
    REFERENCE_SUITE_ID,
    AccessRequestV2,
    ChannelBindingMode,
    derive_request_core_digest,
)
from pq_sat_auth.v2.proof import (
    STATEMENT_BYTES,
    AccessProofStatementV2,
    AccessProofWitnessV2,
    build_access_statement,
    derive_holder_binding_tag,
    derive_holder_hash,
)
from pq_sat_auth.v2.prototypes.access_nizk.circuit import (
    build_exact_access_circuit,
)
from pq_sat_auth.v2.prototypes.access_nizk.adapter import (
    EXPERIMENTAL_PROOF_REGISTRY_V01,
    build_verifier_owned_statement_v01,
    prove_request_v01,
    verify_request_v01,
)
from pq_sat_auth.v2.prototypes.access_nizk.mpcith import (
    HEADER,
    MPCITHAccessNIZKBackendV01,
    RelationNotSatisfied,
)
from pq_sat_auth.v2.prototypes.access_nizk.parameters import (
    TEST_PARAMETERS_V01,
    MPCITHParametersV01,
)


def _digest(label: bytes) -> bytes:
    return hashlib.shake_256(
        b"PQ-SAT/R-ACCESS-MPCITH/TEST/v0.1/" + label
    ).digest(32)


def _flip(value: bytes, index: int = 0) -> bytes:
    mutated = bytearray(value)
    mutated[index] ^= 1
    return bytes(mutated)


def _fixture() -> tuple[
    AccessRequestV2,
    AccessProofStatementV2,
    AccessProofWitnessV2,
]:
    witness = AccessProofWitnessV2(bytes(range(32)))
    request = AccessRequestV2(
        suite_id=REFERENCE_SUITE_ID,
        proof_suite_id=REFERENCE_PROOF_SUITE_ID,
        system_config_digest=_digest(b"system-config"),
        ctx=_digest(b"ctx"),
        epoch=20260916,
        target_fgs_id=_digest(b"fgs"),
        fgs_auth_key_id=_digest(b"fgs-auth-key"),
        serving_context_digest=_digest(b"serving-context"),
        authorization_digest=_digest(b"authorization"),
        client_time=1789488000,
        ue_nonce=_digest(b"ue-nonce"),
        attempt_nonce=_digest(b"attempt-nonce")[:16],
        channel_binding_mode=ChannelBindingMode.NONE,
        channel_binding_digest=bytes(32),
        ticket=b"canonical-ticket-fixture",
        ue_kem_epk=b"ml-kem-768-public-key-fixture",
        holder_binding_tag=bytes(32),
        access_nizk=b"prototype-placeholder",
    )
    request = replace(
        request,
        holder_binding_tag=derive_holder_binding_tag(
            witness.holder_secret,
            derive_request_core_digest(request),
        ),
    )
    statement = build_access_statement(
        access_profile_digest=_digest(b"access-profile"),
        access_pp_digest=TEST_PARAMETERS_V01.digest,
        holder_hash=derive_holder_hash(witness.holder_secret),
        request=request,
    )
    return request, statement, witness


class MPCITHAccessNIZKTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.request, cls.statement, cls.witness = _fixture()
        cls.backend = MPCITHAccessNIZKBackendV01(TEST_PARAMETERS_V01)
        cls.proof = cls.backend.prove_deterministic_for_test(
            cls.statement,
            cls.witness,
            _digest(b"deterministic-root"),
        )

    def test_canonical_statement_adapter_is_exact_v2_encoding(self) -> None:
        self.assertEqual(
            self.statement.request_core_digest,
            derive_request_core_digest(self.request),
        )
        encoded = self.statement.encode()
        self.assertEqual(len(encoded), STATEMENT_BYTES)
        self.assertEqual(AccessProofStatementV2.decode(encoded), self.statement)
        self.assertEqual(
            hashlib.sha256(encoded).hexdigest(),
            "e7d5ac7b10bc4b4e6a303bd154829e11216e32d08b5720ff82c5c14989e471a5",
        )

    def test_deterministic_proof_vector_and_honest_acceptance(self) -> None:
        self.assertEqual(len(self.proof), TEST_PARAMETERS_V01.proof_bytes)
        self.assertEqual(
            hashlib.sha256(self.proof).hexdigest(),
            "5d3d7788a0abed28eaeed9d7708cddfbcecc29df9a6c118ccc3358f16309527e",
        )
        self.assertTrue(self.backend.verify(self.statement, self.proof))

    def test_exact_circuit_trace_matches_hashlib_and_statement(self) -> None:
        built = build_exact_access_circuit(self.statement, self.witness)
        self.assertEqual(built.holder_hash, self.statement.holder_hash)
        self.assertEqual(
            built.holder_binding_tag,
            self.statement.holder_binding_tag,
        )
        self.assertEqual(built.metrics.keccak_f1600_permutations, 2)
        self.assertEqual(built.metrics.boolean_and_gates, 76_800)
        self.assertEqual(built.metrics.secret_input_bitness_constraints, 256)
        self.assertEqual(
            built.metrics.nonlinear_constraints_with_bitness,
            77_056,
        )
        self.assertEqual(built.metrics.public_output_equality_assertions, 512)
        self.assertEqual(built.metrics.failed_assertions, 0)
        self.assertEqual(built.metrics.external_assertions, 0)

    def test_wrong_holder_secret_cannot_prove(self) -> None:
        wrong = AccessProofWitnessV2(_flip(self.witness.holder_secret))
        with self.assertRaises(RelationNotSatisfied):
            self.backend.prove_deterministic_for_test(
                self.statement,
                wrong,
                _digest(b"wrong-secret-root"),
            )

    def test_mutated_holder_hash_rejected(self) -> None:
        mutated = replace(
            self.statement,
            holder_hash=_flip(self.statement.holder_hash),
        )
        self.assertFalse(self.backend.verify(mutated, self.proof))

    def test_mutated_request_core_digest_rejected(self) -> None:
        mutated = replace(
            self.statement,
            request_core_digest=_flip(self.statement.request_core_digest),
        )
        self.assertFalse(self.backend.verify(mutated, self.proof))

    def test_mutated_holder_binding_tag_rejected(self) -> None:
        mutated = replace(
            self.statement,
            holder_binding_tag=_flip(self.statement.holder_binding_tag),
        )
        self.assertFalse(self.backend.verify(mutated, self.proof))

    def test_verifier_owned_profile_and_parameter_digests_are_bound(self) -> None:
        profile_mutation = replace(
            self.statement,
            access_profile_digest=_flip(self.statement.access_profile_digest),
        )
        pp_mutation = replace(
            self.statement,
            access_pp_digest=_flip(self.statement.access_pp_digest),
        )
        self.assertFalse(self.backend.verify(profile_mutation, self.proof))
        self.assertFalse(self.backend.verify(pp_mutation, self.proof))

    def test_proof_bit_and_byte_mutations_rejected(self) -> None:
        self.assertFalse(
            self.backend.verify(self.statement, _flip(self.proof, HEADER.size))
        )
        self.assertFalse(
            self.backend.verify(self.statement, _flip(self.proof, len(self.proof) - 1))
        )

    def test_truncated_and_trailing_proofs_rejected(self) -> None:
        self.assertFalse(self.backend.verify(self.statement, self.proof[:-1]))
        self.assertFalse(self.backend.verify(self.statement, self.proof + b"\x00"))

    def test_cross_parameter_and_cross_version_proofs_rejected(self) -> None:
        other_parameters = MPCITHParametersV01(
            name="PQSAT-R-ACCESS-MPCITH-TEST-8-v0.1",
            repetitions=8,
            claimed_classical_soundness_bits=4,
            test_only=True,
        )
        other_backend = MPCITHAccessNIZKBackendV01(other_parameters)
        self.assertFalse(other_backend.verify(self.statement, self.proof))
        mutated = bytearray(self.proof)
        mutated[9] ^= 1  # proof-format version, not a payload byte
        self.assertFalse(self.backend.verify(self.statement, bytes(mutated)))

    def test_proof_does_not_contain_holder_secret_plaintext(self) -> None:
        self.assertNotIn(self.witness.holder_secret, self.proof)

    def test_request_entry_rebuilds_statement_from_verifier_owned_inputs(self) -> None:
        request = replace(
            self.request,
            proof_suite_id=self.backend.proof_suite_id,
            holder_binding_tag=bytes(32),
            access_nizk=b"placeholder",
        )
        request = replace(
            request,
            holder_binding_tag=derive_holder_binding_tag(
                self.witness.holder_secret,
                derive_request_core_digest(
                    request,
                    proof_registry=EXPERIMENTAL_PROOF_REGISTRY_V01,
                ),
            ),
        )
        statement = build_verifier_owned_statement_v01(
            backend=self.backend,
            access_profile_digest=self.statement.access_profile_digest,
            authenticated_access_pp_digest=self.backend.parameters.digest,
            verified_ticket_holder_hash=self.statement.holder_hash,
            request=request,
        )
        proof = prove_request_v01(
            backend=self.backend,
            access_profile_digest=self.statement.access_profile_digest,
            authenticated_access_pp_digest=self.backend.parameters.digest,
            verified_ticket_holder_hash=self.statement.holder_hash,
            request=request,
            holder_secret=self.witness.holder_secret,
        )
        proved_request = replace(request, access_nizk=proof)
        self.assertTrue(
            verify_request_v01(
                backend=self.backend,
                access_profile_digest=self.statement.access_profile_digest,
                authenticated_access_pp_digest=self.backend.parameters.digest,
                verified_ticket_holder_hash=self.statement.holder_hash,
                request=proved_request,
            )
        )
        self.assertEqual(
            statement.request_core_digest,
            derive_request_core_digest(
                proved_request,
                proof_registry=EXPERIMENTAL_PROOF_REGISTRY_V01,
            ),
        )
        mutated_request = replace(
            proved_request,
            authorization_digest=_flip(proved_request.authorization_digest),
        )
        self.assertFalse(
            verify_request_v01(
                backend=self.backend,
                access_profile_digest=self.statement.access_profile_digest,
                authenticated_access_pp_digest=self.backend.parameters.digest,
                verified_ticket_holder_hash=self.statement.holder_hash,
                request=mutated_request,
            )
        )


if __name__ == "__main__":
    unittest.main()
