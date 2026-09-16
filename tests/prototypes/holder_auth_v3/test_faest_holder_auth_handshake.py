from __future__ import annotations

import hashlib
import os
import subprocess
import unittest
from dataclasses import replace
from pathlib import Path

from pq_sat_auth.v2.prototypes.holder_auth_v3.codec import (
    ACCESS_SUITE_ID,
    CHANNEL_BINDING_NONE,
    FAEST_192S_PARAMETER_DIGEST,
    FAEST_192S_PRIVATE_KEY_BYTES,
    FAEST_192S_PUBLIC_KEY_BYTES,
    FAEST_192S_SIGNATURE_BYTES,
    FINISHED_BYTES,
    HOLDER_SUITE_FAEST_192S,
    HOLDER_SUITE_ML_DSA_65,
    ML_DSA_65_SIGNATURE_BYTES,
    ML_KEM_768_CIPHERTEXT_BYTES,
    ML_KEM_768_PUBLIC_KEY_BYTES,
    FirstApplicationRecordV3,
    HolderAccessAcceptV3,
    HolderAccessRequestV3,
    PrototypeEncodingError,
    SessionActivateV3,
    build_candidate_ticket_fixture,
    decode_access_request,
    decode_candidate_ticket,
    derive_attempt_id,
    derive_holder_public_key_binding,
    derive_request_digest,
    encode_access_accept,
    encode_access_request,
    encode_first_application_record,
    encode_session_activate,
    holder_suite_shape,
)
from pq_sat_auth.v2.prototypes.holder_auth_v3.providers import (
    FAEST_REFERENCE_COMMIT,
    FAEST192sReferenceProvider,
    PQCryptoMLDSA65Provider,
    PQCryptoMLKEM768Provider,
    ProviderUnavailable,
)
from pq_sat_auth.v2.prototypes.holder_auth_v3.suite import (
    run_experimental_handshake,
    verify_holder_authenticated_request,
)


FAEST_LIBRARY_ENV = "PQC_AUTH_FAEST_REF_LIBRARY"
FAEST_LIBRARY_SHA256_ENV = "PQC_AUTH_FAEST_REF_LIBRARY_SHA256"
FAEST_SOURCE_DIR_ENV = "PQC_AUTH_FAEST_REF_SOURCE_DIR"
FAEST_API_TEST_ENV = "PQC_AUTH_FAEST_REF_API_TEST"
FAEST_API_TEST_SHA256_ENV = "PQC_AUTH_FAEST_REF_API_TEST_SHA256"


def fixed(label: bytes, size: int) -> bytes:
    return hashlib.shake_256(b"PQ-SAT/D4B-TEST/" + label).digest(size)


def external_provider() -> FAEST192sReferenceProvider:
    library = os.environ.get(FAEST_LIBRARY_ENV)
    digest = os.environ.get(FAEST_LIBRARY_SHA256_ENV)
    if not library or not digest:
        raise ProviderUnavailable("FAEST reference provider environment is incomplete")
    return FAEST192sReferenceProvider(library, digest)


def external_provider_available() -> bool:
    try:
        provider = external_provider()
        provider._library()
        PQCryptoMLDSA65Provider().package_version
        PQCryptoMLKEM768Provider().package_version
    except ProviderUnavailable:
        return False
    return True


class FAESTHolderAuthCodecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.holder_key = fixed(b"faest-public-key", FAEST_192S_PUBLIC_KEY_BYTES)
        self.ticket = build_candidate_ticket_fixture(
            self.holder_key,
            holder_suite_id=HOLDER_SUITE_FAEST_192S,
        )
        self.ticket_bytes = self.ticket.encode()
        self.request = HolderAccessRequestV3(
            access_suite_id=ACCESS_SUITE_ID,
            holder_suite_id=HOLDER_SUITE_FAEST_192S,
            system_config_digest=fixed(b"system-config", 32),
            ctx=self.ticket.payload.ctx,
            epoch=20260916,
            target_fgs_id=fixed(b"fgs", 32),
            fgs_auth_key_id=fixed(b"fgs-key", 32),
            serving_context_digest=fixed(b"serving", 32),
            authorization_digest=fixed(b"authorization", 32),
            client_time=1789488000,
            ue_nonce=fixed(b"ue-nonce", 32),
            attempt_nonce=fixed(b"attempt", 16),
            channel_binding_mode=CHANNEL_BINDING_NONE,
            channel_binding_digest=bytes(32),
            ticket=self.ticket_bytes,
            ue_kem_epk=fixed(b"kem-public-key", ML_KEM_768_PUBLIC_KEY_BYTES),
            holder_public_key=self.holder_key,
            holder_authenticator=fixed(
                b"faest-signature",
                FAEST_192S_SIGNATURE_BYTES,
            ),
        )
        self.response = HolderAccessAcceptV3(
            access_suite_id=ACCESS_SUITE_ID,
            system_config_digest=self.request.system_config_digest,
            ctx=self.request.ctx,
            epoch=self.request.epoch,
            fgs_id=self.request.target_fgs_id,
            fgs_auth_key_id=self.request.fgs_auth_key_id,
            request_digest=fixed(b"request-digest", 32),
            attempt_id=fixed(b"attempt-id", 32),
            session_id=fixed(b"session-id", 32),
            serving_context_digest=self.request.serving_context_digest,
            session_expiry=1789488300,
            activation_deadline=1789488030,
            kem_ciphertext_to_ue=fixed(
                b"kem-ciphertext",
                ML_KEM_768_CIPHERTEXT_BYTES,
            ),
            fgs_authenticator=fixed(b"fgs-signature", ML_DSA_65_SIGNATURE_BYTES),
            server_key_confirmation=fixed(b"server-finished", FINISHED_BYTES),
        )
        self.activation = SessionActivateV3(
            access_suite_id=ACCESS_SUITE_ID,
            request_digest=self.response.request_digest,
            attempt_id=self.response.attempt_id,
            session_id=self.response.session_id,
            response_digest=fixed(b"response-digest", 32),
            client_key_confirmation=fixed(b"client-finished", FINISHED_BYTES),
        )

    def test_faest_v3_shape_ticket_binding_and_cross_suite_rejection(self) -> None:
        shape = holder_suite_shape(HOLDER_SUITE_FAEST_192S)
        self.assertEqual(shape.public_key_bytes, 48)
        self.assertEqual(shape.signature_bytes, 9_410)
        self.assertEqual(shape.parameter_digest, FAEST_192S_PARAMETER_DIGEST)
        self.assertEqual(len(self.ticket_bytes), 12_126)
        self.assertEqual(decode_candidate_ticket(self.ticket_bytes), self.ticket)
        self.assertEqual(
            self.ticket.payload.holder_public_key_binding,
            derive_holder_public_key_binding(
                HOLDER_SUITE_FAEST_192S,
                FAEST_192S_PARAMETER_DIGEST,
                self.holder_key,
            ),
        )

        with self.assertRaises(ValueError):
            build_candidate_ticket_fixture(
                self.holder_key,
                holder_suite_id=HOLDER_SUITE_ML_DSA_65,
            )
        with self.assertRaises(ValueError):
            encode_access_request(
                replace(self.request, holder_suite_id=HOLDER_SUITE_ML_DSA_65)
            )

    def test_exact_faest_wire_ledger_and_frozen_vectors(self) -> None:
        request_bytes = encode_access_request(self.request)
        response_bytes = encode_access_accept(self.response)
        activation_bytes = encode_session_activate(self.activation)
        record = FirstApplicationRecordV3(
            access_suite_id=ACCESS_SUITE_ID,
            request_digest=self.activation.request_digest,
            attempt_id=self.activation.attempt_id,
            session_id=self.activation.session_id,
            response_digest=self.activation.response_digest,
            sequence_number=0,
            activation_bytes=activation_bytes,
            ciphertext=fixed(b"conditional-ciphertext", 17),
        )
        record_bytes = encode_first_application_record(record)

        self.assertEqual(len(self.request.core_bytes()), 13_664)
        self.assertEqual(len(self.request.holder_signing_input()), 13_689)
        self.assertEqual(len(request_bytes), 23_094)
        self.assertEqual(len(response_bytes), 4_755)
        self.assertEqual(len(activation_bytes), 198)
        self.assertEqual(len(record_bytes), 377)
        self.assertEqual(
            len(request_bytes) + len(response_bytes) + len(activation_bytes),
            28_047,
        )
        self.assertEqual(
            len(request_bytes) + len(response_bytes) + len(record_bytes),
            28_226,
        )

        frozen = {
            "ticket": (
                self.ticket_bytes,
                "66b1bbf3cdcf5e5bc4b7b107d1353249dc5ac21f39406b5c156a561dd0c2ab33",
            ),
            "holder_auth_core": (
                self.request.core_bytes(),
                "a2ead75a23180afc2ec14d8e6716a531a30d77a6695c76742cdc469eab2dbc93",
            ),
            "holder_signing_input": (
                self.request.holder_signing_input(),
                "88ab20b8dc6f3a3d53ba9e6fdecb8e27bdd1dafd64b4444533ce39abfb96e882",
            ),
            "request": (
                request_bytes,
                "8754824d3e3388ca7917684f428fd771ef6facd96784ffd4a06b43c5239cc795",
            ),
            "response": (
                response_bytes,
                "98b1339beba817fb5926ccb02a07f5a904a9d737a0d5cba07bae119ea27d11ce",
            ),
            "activation": (
                activation_bytes,
                "14c78614fd8681efce596852ca2d052923886d393e5c0eccee739c9e55fe8e20",
            ),
            "first_record": (
                record_bytes,
                "d5561794625fd52c44b5cbc1977ec4c6777a73d64354f59b64116982a2797c8f",
            ),
        }
        for name, (encoded, expected) in frozen.items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256(encoded).hexdigest(), expected)

    def test_strict_request_round_trip_and_signature_lengths(self) -> None:
        encoded = encode_access_request(self.request)
        self.assertEqual(decode_access_request(encoded), self.request)
        for end in (0, 1, 15, 16, len(encoded) - 1):
            with self.subTest(end=end):
                with self.assertRaises(PrototypeEncodingError):
                    decode_access_request(encoded[:end])
        with self.assertRaises(PrototypeEncodingError):
            decode_access_request(encoded + b"\x00")
        for bad_length in (
            FAEST_192S_SIGNATURE_BYTES - 1,
            FAEST_192S_SIGNATURE_BYTES + 1,
        ):
            with self.subTest(bad_length=bad_length):
                with self.assertRaises(ValueError):
                    encode_access_request(
                        replace(
                            self.request,
                            holder_authenticator=bytes(bad_length),
                        )
                    )

    def test_same_core_resign_has_stable_attempt_identity(self) -> None:
        changed_signature = bytearray(self.request.holder_authenticator)
        changed_signature[-1] ^= 1
        resigned = replace(
            self.request,
            holder_authenticator=bytes(changed_signature),
        )
        self.assertEqual(
            self.request.holder_signing_input(),
            resigned.holder_signing_input(),
        )
        self.assertNotEqual(
            derive_request_digest(self.request),
            derive_request_digest(resigned),
        )
        self.assertEqual(derive_attempt_id(self.request), derive_attempt_id(resigned))


@unittest.skipUnless(
    external_provider_available(),
    "external FAEST reference library or pqcrypto dependencies are unavailable",
)
class RealFAESTProviderAndHandshakeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.faest = external_provider()
        self.fgs = PQCryptoMLDSA65Provider()
        self.kem = PQCryptoMLKEM768Provider()

    def test_real_faest_key_sign_verify_and_mutation_rejection(self) -> None:
        public_key, secret_key = self.faest.generate_keypair()
        self.assertEqual(len(public_key), FAEST_192S_PUBLIC_KEY_BYTES)
        self.assertEqual(len(secret_key), FAEST_192S_PRIVATE_KEY_BYTES)
        message = fixed(b"real-faest-message", 257)
        signature = self.faest.sign(secret_key, message)
        second_signature = self.faest.sign(secret_key, message)
        self.assertEqual(len(signature), FAEST_192S_SIGNATURE_BYTES)
        self.assertNotEqual(signature, second_signature)
        self.assertTrue(self.faest.verify(public_key, message, signature))
        self.assertTrue(self.faest.verify(public_key, message, second_signature))

        changed_message = bytearray(message)
        changed_message[0] ^= 1
        changed_key = bytearray(public_key)
        changed_key[-1] ^= 1
        changed_signature = bytearray(signature)
        changed_signature[-1] ^= 1
        self.assertFalse(self.faest.verify(public_key, bytes(changed_message), signature))
        self.assertFalse(self.faest.verify(bytes(changed_key), message, signature))
        self.assertFalse(self.faest.verify(public_key, message, bytes(changed_signature)))
        self.assertFalse(self.faest.verify(public_key, message, signature[:-1]))
        self.assertFalse(self.faest.verify(public_key, message, signature + b"\x00"))

    def test_real_faest_holder_handshake_and_mutation_matrix(self) -> None:
        artifacts = run_experimental_handshake(
            holder_provider=self.faest,
            fgs_provider=self.fgs,
            kem_provider=self.kem,
            holder_suite_id=HOLDER_SUITE_FAEST_192S,
        )
        self.assertEqual(len(artifacts.ticket_bytes), 12_126)
        self.assertEqual(len(artifacts.request_bytes), 23_094)
        self.assertEqual(len(artifacts.response_bytes), 4_755)
        self.assertEqual(len(artifacts.activation_bytes), 198)
        self.assertEqual(len(artifacts.first_application_record_bytes), 377)
        self.assertEqual(artifacts.explicit_m3_total_bytes, 28_047)
        self.assertEqual(artifacts.first_record_total_bytes, 28_226)
        self.assertTrue(artifacts.shared_secret_match)
        self.assertTrue(artifacts.holder_authentication_verified)
        self.assertTrue(artifacts.fgs_authentication_verified)
        self.assertTrue(artifacts.server_finished_verified)
        self.assertTrue(artifacts.client_finished_verified)
        self.assertFalse(artifacts.production_ready)

        request = decode_access_request(artifacts.request_bytes)
        mutations = (
            replace(request, target_fgs_id=fixed(b"wrong-fgs", 32)),
            replace(request, authorization_digest=fixed(b"wrong-authz", 32)),
            replace(request, serving_context_digest=fixed(b"wrong-serving", 32)),
            replace(request, ue_kem_epk=fixed(b"wrong-epk", 1184)),
        )
        for mutated in mutations:
            self.assertFalse(verify_holder_authenticated_request(mutated, self.faest))

        changed_signature = bytearray(request.holder_authenticator)
        changed_signature[0] ^= 1
        self.assertFalse(
            verify_holder_authenticated_request(
                replace(request, holder_authenticator=bytes(changed_signature)),
                self.faest,
            )
        )

    def test_wrong_ticket_binding_rejected_after_valid_resign(self) -> None:
        public_key, secret_key = self.faest.generate_keypair()
        ticket = build_candidate_ticket_fixture(
            public_key,
            holder_suite_id=HOLDER_SUITE_FAEST_192S,
        )
        fixture = FAESTHolderAuthCodecTests()
        fixture.setUp()
        draft = replace(
            fixture.request,
            ctx=ticket.payload.ctx,
            ticket=ticket.encode(),
            holder_public_key=public_key,
            holder_authenticator=bytes(FAEST_192S_SIGNATURE_BYTES),
        )
        request = replace(
            draft,
            holder_authenticator=self.faest.sign(
                secret_key,
                draft.holder_signing_input(),
            ),
        )
        self.assertTrue(verify_holder_authenticated_request(request, self.faest))

        resigned_request = replace(
            draft,
            holder_authenticator=self.faest.sign(
                secret_key,
                draft.holder_signing_input(),
            ),
        )
        self.assertNotEqual(
            request.holder_authenticator,
            resigned_request.holder_authenticator,
        )
        self.assertNotEqual(
            derive_request_digest(request),
            derive_request_digest(resigned_request),
        )
        self.assertEqual(
            derive_attempt_id(request),
            derive_attempt_id(resigned_request),
        )

        wrong_binding = bytearray(ticket.payload.holder_public_key_binding)
        wrong_binding[0] ^= 1
        wrong_payloads = (
            replace(
                ticket.payload,
                holder_public_key_binding=bytes(wrong_binding),
            ),
            replace(
                ticket.payload,
                holder_parameter_digest=fixed(b"wrong-parameters", 32),
            ),
            replace(
                ticket.payload,
                holder_suite_id=HOLDER_SUITE_ML_DSA_65,
            ),
        )
        for wrong_payload in wrong_payloads:
            wrong_ticket = replace(ticket, payload=wrong_payload)
            wrong_draft = replace(
                request,
                ticket=wrong_ticket.encode(),
                holder_authenticator=bytes(FAEST_192S_SIGNATURE_BYTES),
            )
            wrong_request = replace(
                wrong_draft,
                holder_authenticator=self.faest.sign(
                    secret_key,
                    wrong_draft.holder_signing_input(),
                ),
            )
            self.assertFalse(
                verify_holder_authenticated_request(wrong_request, self.faest)
            )

    def test_external_source_identity_and_official_api_self_test(self) -> None:
        source_dir = os.environ.get(FAEST_SOURCE_DIR_ENV)
        api_test_path = os.environ.get(FAEST_API_TEST_ENV)
        api_test_sha256 = os.environ.get(FAEST_API_TEST_SHA256_ENV)
        if not source_dir or not api_test_path or not api_test_sha256:
            self.skipTest("FAEST source/API-test identity environment is incomplete")

        source = Path(source_dir)
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=source,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        self.assertEqual(revision, FAEST_REFERENCE_COMMIT)
        meson = (source / "meson.build").read_text(encoding="utf-8")
        self.assertIn("version: '3.0.0'", meson)
        self.assertIn("param_192s.set('SIG_SIZE', 9410)", meson)
        self.assertIn("param_192s.set('PK_SIZE', 48)", meson)
        self.assertIn("param_192s.set('SK_SIZE', 40)", meson)

        executable = Path(api_test_path)
        self.assertEqual(
            hashlib.sha256(executable.read_bytes()).hexdigest(),
            api_test_sha256,
        )
        completed = subprocess.run(
            [str(executable)],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self.assertEqual(completed.stdout.strip(), "Sign/Verify test passed")

    def test_library_digest_mismatch_fails_closed(self) -> None:
        wrong_digest = "0" * 64
        if wrong_digest == self.faest.library_sha256:
            wrong_digest = "1" * 64
        provider = FAEST192sReferenceProvider(
            self.faest.library_path,
            wrong_digest,
        )
        with self.assertRaises(ProviderUnavailable):
            provider.generate_keypair()


if __name__ == "__main__":
    unittest.main()
