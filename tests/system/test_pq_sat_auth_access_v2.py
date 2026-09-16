from __future__ import annotations

import unittest
from dataclasses import replace

from pq_sat_auth.identities import TicketUseIdentity
from pq_sat_auth.v2.access import (
    REFERENCE_PROOF_SUITE,
    REFERENCE_PROOF_SUITE_ID,
    REFERENCE_SUITE,
    REFERENCE_SUITE_ID,
    AccessAcceptV2,
    AccessRequestV2,
    ChannelBindingMode,
    ProofLimitsV2,
    ProtocolBindingError,
    SessionActivateV2,
    SuiteLimitsV2,
    decode_access_accept,
    decode_access_request,
    decode_session_activate,
    derive_activation_digest,
    derive_attempt_id,
    derive_request_core_digest,
    derive_request_digest,
    derive_response_digest,
    derive_transcript_digest,
    encode_access_accept,
    encode_access_accept_core,
    encode_access_request,
    encode_access_request_core,
    encode_session_activate,
    validate_activation_binding,
    validate_response_binding,
)
from pq_sat_auth.v2.framing import (
    FrameTypeV2,
    ProtocolEncodingError,
    decode_frame_v2,
    encode_frame_v2,
)
from pq_sat_auth.v2.proof import derive_holder_binding_tag


def fixed(value: int, size: int = 32) -> bytes:
    return bytes((value,)) * size


class AccessV2Fixture(unittest.TestCase):
    def setUp(self) -> None:
        self.holder_secret = fixed(20)
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
            channel_binding_mode=ChannelBindingMode.AUTHENTICATED_EXPORTER,
            channel_binding_digest=fixed(9),
            ticket=b"canonical-ticket",
            ue_kem_epk=b"ephemeral-kem-public-key",
            holder_binding_tag=bytes(32),
            access_nizk=b"test-only-access-proof",
        )
        self.request = replace(
            request,
            holder_binding_tag=derive_holder_binding_tag(
                self.holder_secret,
                derive_request_core_digest(request),
            ),
        )
        self.identity = TicketUseIdentity(
            ctx=self.request.ctx,
            serial=fixed(10, 16),
            ticket_digest=fixed(11),
        )
        self.request_digest = derive_request_digest(self.request)
        self.attempt_id = derive_attempt_id(
            self.identity.use_key,
            self.request_digest,
        )
        self.response = AccessAcceptV2(
            suite_id=REFERENCE_SUITE_ID,
            system_config_digest=self.request.system_config_digest,
            ctx=self.request.ctx,
            epoch=self.request.epoch,
            fgs_id=self.request.target_fgs_id,
            fgs_auth_key_id=self.request.fgs_auth_key_id,
            request_digest=self.request_digest,
            attempt_id=self.attempt_id,
            session_id=fixed(12),
            serving_context_digest=self.request.serving_context_digest,
            session_expiry=1_800_000_600,
            activation_deadline=1_800_000_060,
            kem_ciphertext_to_ue=b"fresh-kem-ciphertext",
            fgs_authenticator=b"test-only-fgs-authenticator",
            server_key_confirmation=b"test-only-server-finished",
        )
        self.response_digest = derive_response_digest(self.response)
        self.activation = SessionActivateV2(
            suite_id=REFERENCE_SUITE_ID,
            request_digest=self.request_digest,
            attempt_id=self.attempt_id,
            session_id=self.response.session_id,
            response_digest=self.response_digest,
            client_key_confirmation=b"test-only-client-finished",
        )


class AccessV2CodecTests(AccessV2Fixture):
    def test_all_objects_round_trip_canonically(self) -> None:
        cases = (
            (self.request, encode_access_request, decode_access_request),
            (self.response, encode_access_accept, decode_access_accept),
            (self.activation, encode_session_activate, decode_session_activate),
        )
        for expected, encoder, decoder in cases:
            with self.subTest(message=type(expected).__name__):
                encoded = encoder(expected)
                self.assertEqual(decoder(encoded), expected)
                self.assertEqual(encoder(decoder(encoded)), encoded)

    def test_frozen_lengths_and_digest_vectors(self) -> None:
        self.assertEqual(len(encode_access_request_core(self.request)), 342)
        self.assertEqual(len(encode_access_request(self.request)), 416)
        self.assertEqual(len(encode_access_accept_core(self.response)), 306)
        self.assertEqual(len(encode_access_accept(self.response)), 382)
        self.assertEqual(len(encode_session_activate(self.activation)), 175)
        self.assertEqual(
            derive_request_core_digest(self.request).hex(),
            "90763fd09a9227e18e06cdc0d2b07bc2ae77797cdceb3b2436edab99e92d7751",
        )
        self.assertEqual(
            self.request_digest.hex(),
            "41f01cc4ea603b802c822465a6aec05d9251a4294ece3a36b2ae2cde9bbbfd3c",
        )
        self.assertEqual(
            self.attempt_id.hex(),
            "40049590cdabb711018d6ed52ada7933c5bd10370e4e808507df03368da7c89d",
        )
        self.assertEqual(
            derive_transcript_digest(self.response).hex(),
            "fe054f0a65ad44982f7b08536f230cc260a4278f58f24ad17ea5cf9b91ba20bf",
        )
        self.assertEqual(
            self.response_digest.hex(),
            "1c60d11f95767f6039b21b82672714c27c066c879c78ec51fd24d39da874009d",
        )
        self.assertEqual(
            derive_activation_digest(self.activation).hex(),
            "f6428b81183fe909ce5aa9416e4004e0471cfa69f18c7a1e8f6be05b8ad67c5b",
        )

    def test_wrong_type_and_trailing_field_are_rejected(self) -> None:
        with self.assertRaises(ProtocolEncodingError):
            decode_access_request(encode_access_accept(self.response))
        frame = decode_frame_v2(encode_access_request(self.request))
        malformed = encode_frame_v2(
            FrameTypeV2.ACCESS_REQUEST,
            frame.body + b"\x00",
        )
        with self.assertRaises(ProtocolEncodingError):
            decode_access_request(malformed)

    def test_every_internal_truncation_is_rejected(self) -> None:
        cases = (
            (self.request, encode_access_request, decode_access_request),
            (self.response, encode_access_accept, decode_access_accept),
            (self.activation, encode_session_activate, decode_session_activate),
        )
        for message, encoder, decoder in cases:
            frame = decode_frame_v2(encoder(message))
            for cut in range(len(frame.body)):
                with self.subTest(message=type(message).__name__, cut=cut):
                    malformed = encode_frame_v2(frame.msg_type, frame.body[:cut])
                    with self.assertRaises(ProtocolEncodingError):
                        decoder(malformed)

    def test_unknown_suites_and_channel_modes_are_rejected(self) -> None:
        with self.assertRaises(ProtocolEncodingError):
            encode_access_request(replace(self.request, suite_id=1))
        with self.assertRaises(ProtocolEncodingError):
            encode_access_request(replace(self.request, proof_suite_id=1))
        frame = decode_frame_v2(encode_access_request(self.request))
        body = bytearray(frame.body)
        channel_mode_offset = 2 + 2 + 32 + 32 + 8 + (4 * 32) + 8 + 32 + 16
        body[channel_mode_offset : channel_mode_offset + 2] = (2).to_bytes(2, "big")
        with self.assertRaises(ProtocolEncodingError):
            decode_access_request(
                encode_frame_v2(FrameTypeV2.ACCESS_REQUEST, bytes(body))
            )

    def test_channel_binding_modes_have_canonical_digest_rules(self) -> None:
        none_request = replace(
            self.request,
            channel_binding_mode=ChannelBindingMode.NONE,
            channel_binding_digest=bytes(32),
        )
        self.assertEqual(
            decode_access_request(encode_access_request(none_request)),
            none_request,
        )
        with self.assertRaises(ValueError):
            replace(
                self.request,
                channel_binding_mode=ChannelBindingMode.NONE,
            )
        with self.assertRaises(ValueError):
            replace(self.request, channel_binding_digest=bytes(32))

    def test_suite_specific_limits_apply_on_encode_and_decode(self) -> None:
        strict_suite = SuiteLimitsV2(
            suite_id=REFERENCE_SUITE_ID,
            max_ticket_bytes=3,
            max_kem_public_key_bytes=REFERENCE_SUITE.max_kem_public_key_bytes,
            max_kem_ciphertext_bytes=REFERENCE_SUITE.max_kem_ciphertext_bytes,
            max_fgs_authenticator_bytes=(
                REFERENCE_SUITE.max_fgs_authenticator_bytes
            ),
            max_key_confirmation_bytes=REFERENCE_SUITE.max_key_confirmation_bytes,
        )
        with self.assertRaises(ValueError):
            encode_access_request(
                self.request,
                {REFERENCE_SUITE_ID: strict_suite},
            )
        honest = encode_access_request(self.request)
        with self.assertRaises(ProtocolEncodingError):
            decode_access_request(
                honest,
                {REFERENCE_SUITE_ID: strict_suite},
            )

        strict_proof = ProofLimitsV2(
            proof_suite_id=REFERENCE_PROOF_SUITE_ID,
            max_access_nizk_bytes=3,
        )
        with self.assertRaises(ValueError):
            encode_access_request(
                self.request,
                proof_registry={REFERENCE_PROOF_SUITE_ID: strict_proof},
            )
        self.assertGreater(REFERENCE_PROOF_SUITE.max_access_nizk_bytes, 3)


class AccessV2BindingTests(AccessV2Fixture):
    def test_response_and_activation_bindings_accept_exact_flow(self) -> None:
        validate_response_binding(
            self.request,
            self.response,
            use_key=self.identity.use_key,
        )
        validate_activation_binding(self.response, self.activation)

    def test_response_context_substitutions_are_rejected(self) -> None:
        mutations = (
            replace(self.response, system_config_digest=fixed(30)),
            replace(self.response, ctx=fixed(31)),
            replace(self.response, epoch=self.response.epoch + 1),
            replace(self.response, fgs_id=fixed(32)),
            replace(self.response, fgs_auth_key_id=fixed(33)),
            replace(self.response, serving_context_digest=fixed(34)),
            replace(self.response, request_digest=fixed(35)),
            replace(self.response, attempt_id=fixed(36)),
        )
        for changed in mutations:
            with self.subTest(response=changed):
                with self.assertRaises(ProtocolBindingError):
                    validate_response_binding(
                        self.request,
                        changed,
                        use_key=self.identity.use_key,
                    )

    def test_request_core_and_full_digest_cover_different_boundaries(self) -> None:
        changed_proof = replace(self.request, access_nizk=b"another-proof")
        self.assertEqual(
            derive_request_core_digest(changed_proof),
            derive_request_core_digest(self.request),
        )
        self.assertNotEqual(
            derive_request_digest(changed_proof),
            self.request_digest,
        )
        changed_key = replace(self.request, ue_kem_epk=b"another-ephemeral-key")
        self.assertNotEqual(
            derive_request_core_digest(changed_key),
            derive_request_core_digest(self.request),
        )

    def test_response_transcript_excludes_authenticator_and_finished(self) -> None:
        changed = replace(
            self.response,
            fgs_authenticator=b"another-authenticator",
            server_key_confirmation=b"another-finished",
        )
        self.assertEqual(
            encode_access_accept_core(changed),
            encode_access_accept_core(self.response),
        )
        self.assertEqual(
            derive_transcript_digest(changed),
            derive_transcript_digest(self.response),
        )
        self.assertNotEqual(
            derive_response_digest(changed),
            self.response_digest,
        )

    def test_cross_session_activation_is_rejected(self) -> None:
        mutations = (
            replace(self.activation, request_digest=fixed(40)),
            replace(self.activation, attempt_id=fixed(41)),
            replace(self.activation, session_id=fixed(42)),
            replace(self.activation, response_digest=fixed(43)),
        )
        for changed in mutations:
            with self.subTest(activation=changed):
                with self.assertRaises(ProtocolBindingError):
                    validate_activation_binding(self.response, changed)


if __name__ == "__main__":
    unittest.main()
