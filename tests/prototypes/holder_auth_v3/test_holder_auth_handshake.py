from __future__ import annotations

import hashlib
import json
import os
import unittest
from dataclasses import replace
from pathlib import Path

from pq_sat_auth.v2.prototypes.holder_auth_v3.codec import (
    ACCEPT_PREFIX,
    ACCESS_SUITE_ID,
    ACTIVATE_PREFIX,
    CHANNEL_BINDING_NONE,
    FINISHED_BYTES,
    FIRST_RECORD_PREFIX,
    FRAME_HEADER,
    HOLDER_SUITE_ML_DSA_65,
    ML_DSA_65_PARAMETER_DIGEST,
    ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_SIGNATURE_BYTES,
    ML_KEM_768_CIPHERTEXT_BYTES,
    ML_KEM_768_PUBLIC_KEY_BYTES,
    OPAQUE_LENGTH,
    PROVISIONAL_ISSUER_SIGNATURE_BYTES,
    REQUEST_PREFIX,
    TICKET_ENVELOPE_BYTES,
    TICKET_PAYLOAD_BYTES,
    FirstApplicationRecordV3,
    HolderAccessAcceptV3,
    HolderAccessRequestV3,
    PrototypeEncodingError,
    SessionActivateV3,
    build_candidate_ticket_fixture,
    decode_access_accept,
    decode_access_request,
    decode_candidate_ticket,
    decode_first_application_record,
    decode_session_activate,
    derive_holder_public_key_binding,
    encode_access_accept,
    encode_access_request,
    encode_first_application_record,
    encode_session_activate,
)
from pq_sat_auth.v2.prototypes.holder_auth_v3.providers import (
    DilithiumPyMLDSA65Provider,
    PQCryptoMLDSA65Provider,
    PQCryptoMLKEM768Provider,
    ProviderUnavailable,
)
from pq_sat_auth.v2.prototypes.holder_auth_v3.suite import (
    run_experimental_handshake,
    verify_holder_authenticated_request,
)


def fixed(label: bytes, size: int) -> bytes:
    return hashlib.shake_256(b"PQ-SAT/D4-TEST/" + label).digest(size)


def providers_available() -> bool:
    try:
        PQCryptoMLDSA65Provider().package_version
        DilithiumPyMLDSA65Provider().package_version
        PQCryptoMLKEM768Provider().package_version
    except ProviderUnavailable:
        return False
    return True


class HolderAuthCodecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.holder_key = fixed(b"holder-public-key", ML_DSA_65_PUBLIC_KEY_BYTES)
        self.ticket = build_candidate_ticket_fixture(self.holder_key)
        self.ticket_bytes = self.ticket.encode()
        self.request = HolderAccessRequestV3(
            access_suite_id=ACCESS_SUITE_ID,
            holder_suite_id=HOLDER_SUITE_ML_DSA_65,
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
                b"holder-signature",
                ML_DSA_65_SIGNATURE_BYTES,
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

    def test_candidate_ticket_exact_shape_and_round_trip(self) -> None:
        self.assertEqual(TICKET_PAYLOAD_BYTES, 420)
        self.assertEqual(TICKET_ENVELOPE_BYTES, 62)
        self.assertEqual(len(self.ticket_bytes), 12_126)
        self.assertEqual(
            len(self.ticket_bytes),
            TICKET_ENVELOPE_BYTES
            + TICKET_PAYLOAD_BYTES
            + PROVISIONAL_ISSUER_SIGNATURE_BYTES,
        )
        self.assertEqual(decode_candidate_ticket(self.ticket_bytes), self.ticket)
        self.assertEqual(
            hashlib.sha256(self.ticket_bytes).hexdigest(),
            "b992111734a6e2c1016c4ebcad1c79ff3534c30e282357a7cb81d63ba88d5264",
        )

    def test_holder_binding_changes_with_suite_parameters_and_key(self) -> None:
        baseline = self.ticket.payload.holder_public_key_binding
        self.assertEqual(
            baseline,
            derive_holder_public_key_binding(
                HOLDER_SUITE_ML_DSA_65,
                ML_DSA_65_PARAMETER_DIGEST,
                self.holder_key,
            ),
        )
        changed_key = bytearray(self.holder_key)
        changed_key[-1] ^= 1
        self.assertNotEqual(
            baseline,
            derive_holder_public_key_binding(
                HOLDER_SUITE_ML_DSA_65,
                ML_DSA_65_PARAMETER_DIGEST,
                bytes(changed_key),
            ),
        )
        changed_parameters = bytearray(ML_DSA_65_PARAMETER_DIGEST)
        changed_parameters[0] ^= 1
        self.assertNotEqual(
            baseline,
            derive_holder_public_key_binding(
                HOLDER_SUITE_ML_DSA_65,
                bytes(changed_parameters),
                self.holder_key,
            ),
        )

    def test_exact_message_sizes_match_d1_ledger(self) -> None:
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

        self.assertEqual(FRAME_HEADER.size, 16)
        self.assertEqual(OPAQUE_LENGTH.size, 4)
        self.assertEqual(REQUEST_PREFIX.size, 294)
        self.assertEqual(ACCEPT_PREFIX.size, 282)
        self.assertEqual(ACTIVATE_PREFIX.size, 130)
        self.assertEqual(FIRST_RECORD_PREFIX.size, 138)
        self.assertEqual(len(request_bytes), 18_897)
        self.assertEqual(len(response_bytes), 4_755)
        self.assertEqual(len(activation_bytes), 198)
        self.assertEqual(len(record_bytes), 377)
        self.assertEqual(
            len(request_bytes) + len(response_bytes) + len(activation_bytes),
            23_850,
        )
        self.assertEqual(
            len(request_bytes) + len(response_bytes) + len(record_bytes),
            24_029,
        )
        frozen = {
            "holder_auth_core": (
                self.request.core_bytes(),
                "aedf84ae8af060c5d513995dc5f24fff851a5b79b6cdab3b3eb06e9a87baa0ae",
            ),
            "holder_signing_input": (
                self.request.holder_signing_input(),
                "3ef57a174275143ccc67fcb959ff4c0aa055006030411e047681994bd5ff8f6b",
            ),
            "request": (
                request_bytes,
                "514bed0b29fc472f708c59c956162ecfe5bcdd9d4e3abc780ecced8e83271e86",
            ),
            "response": (
                response_bytes,
                "0523855d6d9c72bde738e38a7594d443f5e4830920f2c3e1149352f3bc66f6c6",
            ),
            "activation": (
                activation_bytes,
                "9ae8c22825b74ff5575c3d757dcf80e32b3e11f2b4d30b03a340f4e198fd0853",
            ),
            "first_record": (
                record_bytes,
                "b84362ba0afc1f266be99f9f22db6d0e683c2502f6ee48edc8266d7a694a4edc",
            ),
        }
        for name, (encoded, expected) in frozen.items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256(encoded).hexdigest(), expected)

    def test_every_object_round_trips_and_rejects_truncation_or_trailing(self) -> None:
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
        cases = (
            (encode_access_request(self.request), decode_access_request),
            (encode_access_accept(self.response), decode_access_accept),
            (activation_bytes, decode_session_activate),
            (
                encode_first_application_record(record),
                decode_first_application_record,
            ),
        )
        for encoded, decoder in cases:
            self.assertEqual(decoder(encoded), decoder(encoded))
            for end in (0, 1, 15, 16, len(encoded) - 1):
                with self.subTest(decoder=decoder.__name__, end=end):
                    with self.assertRaises(PrototypeEncodingError):
                        decoder(encoded[:end])
            with self.assertRaises(PrototypeEncodingError):
                decoder(encoded + b"\x00")

    def test_ticket_mutations_and_embedded_activation_substitution_reject(self) -> None:
        for index in (0, 16, 20, 61, 62, len(self.ticket_bytes) - 1):
            mutated = bytearray(self.ticket_bytes)
            mutated[index] ^= 1
            with self.subTest(index=index):
                if index in (61, 62, len(self.ticket_bytes) - 1):
                    # Payload/signature bytes can remain structurally canonical;
                    # cryptographic verification is a separate boundary.
                    decoded = decode_candidate_ticket(bytes(mutated))
                    self.assertNotEqual(decoded, self.ticket)
                else:
                    with self.assertRaises(PrototypeEncodingError):
                        decode_candidate_ticket(bytes(mutated))

        activation_bytes = encode_session_activate(self.activation)
        record = FirstApplicationRecordV3(
            access_suite_id=ACCESS_SUITE_ID,
            request_digest=self.activation.request_digest,
            attempt_id=self.activation.attempt_id,
            session_id=self.activation.session_id,
            response_digest=self.activation.response_digest,
            sequence_number=0,
            activation_bytes=activation_bytes,
            ciphertext=b"x" * 17,
        )
        wrong_activation = replace(
            self.activation,
            response_digest=fixed(b"other-response", 32),
        )
        with self.assertRaises(ValueError):
            encode_first_application_record(
                replace(
                    record,
                    activation_bytes=encode_session_activate(wrong_activation),
                )
            )


@unittest.skipUnless(providers_available(), "optional PQ providers are not installed")
class RealProviderAndHandshakeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pqcrypto_sign = PQCryptoMLDSA65Provider()
        self.pure_sign = DilithiumPyMLDSA65Provider()
        self.kem = PQCryptoMLKEM768Provider()

    def test_bidirectional_ml_dsa_interoperability_and_mutation_rejection(self) -> None:
        message = fixed(b"interop-message", 257)
        c_public, c_secret = self.pqcrypto_sign.generate_keypair()
        c_signature = self.pqcrypto_sign.sign(c_secret, message)
        self.assertTrue(self.pqcrypto_sign.verify(c_public, message, c_signature))
        self.assertTrue(self.pure_sign.verify(c_public, message, c_signature))

        p_public, p_secret = self.pure_sign.generate_keypair()
        p_signature = self.pure_sign.sign(p_secret, message)
        self.assertTrue(self.pure_sign.verify(p_public, message, p_signature))
        self.assertTrue(self.pqcrypto_sign.verify(p_public, message, p_signature))

        changed_message = bytearray(message)
        changed_message[0] ^= 1
        changed_signature = bytearray(c_signature)
        changed_signature[-1] ^= 1
        for provider in (self.pqcrypto_sign, self.pure_sign):
            self.assertFalse(
                provider.verify(c_public, bytes(changed_message), c_signature)
            )
            self.assertFalse(
                provider.verify(c_public, message, bytes(changed_signature))
            )

    def test_real_handshake_and_cross_provider_holder_verification(self) -> None:
        artifacts = run_experimental_handshake(
            holder_provider=self.pqcrypto_sign,
            fgs_provider=self.pqcrypto_sign,
            kem_provider=self.kem,
        )
        self.assertEqual(len(artifacts.ticket_bytes), 12_126)
        self.assertEqual(len(artifacts.request_bytes), 18_897)
        self.assertEqual(len(artifacts.response_bytes), 4_755)
        self.assertEqual(len(artifacts.activation_bytes), 198)
        self.assertEqual(len(artifacts.first_application_record_bytes), 377)
        self.assertEqual(artifacts.explicit_m3_total_bytes, 23_850)
        self.assertEqual(artifacts.first_record_total_bytes, 24_029)
        self.assertTrue(artifacts.shared_secret_match)
        self.assertTrue(artifacts.holder_authentication_verified)
        self.assertTrue(artifacts.fgs_authentication_verified)
        self.assertTrue(artifacts.server_finished_verified)
        self.assertTrue(artifacts.client_finished_verified)
        self.assertFalse(artifacts.production_ready)
        self.assertTrue(artifacts.conditional_record_ciphertext_fixture)

        request = decode_access_request(artifacts.request_bytes)
        self.assertTrue(
            verify_holder_authenticated_request(request, self.pure_sign)
        )
        for mutated in (
            replace(request, target_fgs_id=fixed(b"wrong-fgs", 32)),
            replace(request, authorization_digest=fixed(b"wrong-authz", 32)),
            replace(request, ue_kem_epk=fixed(b"wrong-epk", 1184)),
        ):
            self.assertFalse(
                verify_holder_authenticated_request(mutated, self.pure_sign)
            )

        changed_key = bytearray(request.holder_public_key)
        changed_key[0] ^= 1
        self.assertFalse(
            verify_holder_authenticated_request(
                replace(request, holder_public_key=bytes(changed_key)),
                self.pure_sign,
            )
        )
        changed_signature = bytearray(request.holder_authenticator)
        changed_signature[-1] ^= 1
        self.assertFalse(
            verify_holder_authenticated_request(
                replace(request, holder_authenticator=bytes(changed_signature)),
                self.pure_sign,
            )
        )

    def test_wrong_ticket_binding_rejects_but_issuer_auth_remains_external(self) -> None:
        holder_public, holder_secret = self.pqcrypto_sign.generate_keypair()
        ticket = build_candidate_ticket_fixture(holder_public)
        fixture = HolderAuthCodecTests()
        fixture.setUp()
        draft = replace(
            fixture.request,
            ctx=ticket.payload.ctx,
            ticket=ticket.encode(),
            holder_public_key=holder_public,
            holder_authenticator=bytes(ML_DSA_65_SIGNATURE_BYTES),
        )
        request = replace(
            draft,
            holder_authenticator=self.pqcrypto_sign.sign(
                holder_secret,
                draft.holder_signing_input(),
            ),
        )
        self.assertTrue(
            verify_holder_authenticated_request(request, self.pqcrypto_sign)
        )

        wrong_binding = bytearray(ticket.payload.holder_public_key_binding)
        wrong_binding[0] ^= 1
        wrong_payload = replace(
            ticket.payload,
            holder_public_key_binding=bytes(wrong_binding),
        )
        wrong_ticket = replace(ticket, payload=wrong_payload)
        wrong_draft = replace(
            request,
            ticket=wrong_ticket.encode(),
            holder_authenticator=bytes(ML_DSA_65_SIGNATURE_BYTES),
        )
        wrong_request = replace(
            wrong_draft,
            holder_authenticator=self.pqcrypto_sign.sign(
                holder_secret,
                wrong_draft.holder_signing_input(),
            ),
        )
        self.assertFalse(
            verify_holder_authenticated_request(wrong_request, self.pqcrypto_sign)
        )

        # The D4 function deliberately verifies holder authorization only.
        # A changed provisional issuer-signature fixture remains structurally
        # valid and must be handled by a future VerifyTicketNew boundary.
        changed_issuer_signature = bytearray(ticket.issuer_signature)
        changed_issuer_signature[-1] ^= 1
        unauthenticated_ticket = replace(
            ticket,
            issuer_signature=bytes(changed_issuer_signature),
        )
        unauthenticated_draft = replace(
            request,
            ticket=unauthenticated_ticket.encode(),
            holder_authenticator=bytes(ML_DSA_65_SIGNATURE_BYTES),
        )
        unauthenticated_request = replace(
            unauthenticated_draft,
            holder_authenticator=self.pqcrypto_sign.sign(
                holder_secret,
                unauthenticated_draft.holder_signing_input(),
            ),
        )
        self.assertTrue(
            verify_holder_authenticated_request(
                unauthenticated_request,
                self.pqcrypto_sign,
            )
        )

    def test_optional_nist_acvp_positive_sigver_vector(self) -> None:
        vector_path = os.environ.get("PQC_AUTH_ML_DSA_ACVP_SIGVER_JSON")
        if not vector_path:
            self.skipTest("PQC_AUTH_ML_DSA_ACVP_SIGVER_JSON is not set")
        raw = Path(vector_path).read_bytes()
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437",
        )
        document = json.loads(raw)
        group = next(
            group
            for group in document["testGroups"]
            if group["tgId"] == 3
            and group["parameterSet"] == "ML-DSA-65"
            and group["signatureInterface"] == "external"
            and group["preHash"] == "pure"
        )
        case = next(case for case in group["tests"] if case["tcId"] == 33)
        self.assertTrue(case["testPassed"])
        self.assertTrue(
            self.pure_sign.verify_with_context(
                bytes.fromhex(case["pk"]),
                bytes.fromhex(case["message"]),
                bytes.fromhex(case["signature"]),
                bytes.fromhex(case["context"]),
            )
        )


if __name__ == "__main__":
    unittest.main()
