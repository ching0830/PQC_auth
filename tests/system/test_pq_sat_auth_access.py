from __future__ import annotations

import unittest
from dataclasses import replace

from pq_sat_auth.access import (
    REFERENCE_SUITE,
    REFERENCE_SUITE_ID,
    AccessAcceptV1,
    AccessChallengeV1,
    AccessFinishV1,
    AccessInitV1,
    ProtocolBindingError,
    ServingContextV1,
    SuiteLimits,
    access_accept_digest,
    access_challenge_digest,
    access_init_digest,
    access_transcript_digest,
    decode_access_accept,
    decode_access_challenge,
    decode_access_finish,
    decode_access_init,
    derive_attempt_id,
    encode_access_accept,
    encode_access_challenge,
    encode_access_finish,
    encode_access_finish_core,
    encode_access_init,
)
from pq_sat_auth.framing import (
    FrameType,
    ProtocolEncodingError,
    decode_frame,
    encode_frame,
)


def fixed(value: int, size: int = 32) -> bytes:
    return bytes((value,)) * size


class AccessObjectFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.context = ServingContextV1(
            operator_id_digest=fixed(1),
            fgs_id_digest=fixed(2),
            relay_scope_digest=fixed(3),
            cell_scope_digest=fixed(4),
            epoch=5,
            policy_digest=fixed(6),
        )
        self.init = AccessInitV1(
            suite_id=REFERENCE_SUITE_ID,
            ctx=fixed(10),
            serving_context_digest=self.context.digest,
            ue_nonce=fixed(11),
            attempt_nonce=fixed(12, 16),
            ticket=b"ticket",
            ue_key_share=b"ue-key-share",
        )
        self.challenge = AccessChallengeV1(
            suite_id=REFERENCE_SUITE_ID,
            ctx=self.init.ctx,
            serving_context_digest=self.init.serving_context_digest,
            ue_nonce=self.init.ue_nonce,
            fgs_nonce=fixed(13),
            attempt_nonce=self.init.attempt_nonce,
            challenge_expiry=1_700_000_000,
            fgs_key_share=b"fgs-key-share",
            challenge_cookie=b"cookie",
        )
        self.finish = AccessFinishV1(
            suite_id=REFERENCE_SUITE_ID,
            ctx=self.init.ctx,
            serving_context_digest=self.init.serving_context_digest,
            ue_nonce=self.init.ue_nonce,
            fgs_nonce=self.challenge.fgs_nonce,
            attempt_nonce=self.init.attempt_nonce,
            challenge_cookie=self.challenge.challenge_cookie,
            holder_authenticator=b"holder-auth",
            ue_key_confirmation=b"ue-confirm",
        )
        self.transcript_digest = access_transcript_digest(
            self.init,
            self.challenge,
            self.finish,
        )
        self.attempt_id = derive_attempt_id(
            fixed(14),
            self.init.serving_context_digest,
            self.init.ue_nonce,
            self.challenge.fgs_nonce,
            self.init.attempt_nonce,
            self.transcript_digest,
        )
        self.accept = AccessAcceptV1(
            suite_id=REFERENCE_SUITE_ID,
            attempt_id=self.attempt_id,
            session_id=fixed(15),
            serving_context_digest=self.init.serving_context_digest,
            session_expiry=1_700_000_600,
            fgs_key_confirmation=b"fgs-confirm",
        )


class ServingContextTests(AccessObjectFixture):
    def test_fixed_width_round_trip_and_digest_vector(self) -> None:
        encoded = self.context.encode()
        self.assertEqual(len(encoded), 168)
        self.assertEqual(ServingContextV1.decode(encoded), self.context)
        self.assertEqual(
            self.context.digest.hex(),
            "34773f16d12ef3954b4a7c29b59d48448a4e4e3d10f620b37f1a256e0eeb3416",
        )

    def test_noncanonical_context_lengths_are_rejected(self) -> None:
        encoded = self.context.encode()
        for malformed in (encoded[:-1], encoded + b"\x00"):
            with self.subTest(length=len(malformed)):
                with self.assertRaises(ProtocolEncodingError):
                    ServingContextV1.decode(malformed)
        with self.assertRaises(ValueError):
            replace(self.context, policy_digest=fixed(6, 31))


class AccessCodecTests(AccessObjectFixture):
    def test_all_access_objects_round_trip(self) -> None:
        cases = (
            (self.init, encode_access_init, decode_access_init),
            (self.challenge, encode_access_challenge, decode_access_challenge),
            (self.finish, encode_access_finish, decode_access_finish),
            (self.accept, encode_access_accept, decode_access_accept),
        )
        for expected, encoder, decoder in cases:
            with self.subTest(message=type(expected).__name__):
                encoded = encoder(expected)
                self.assertEqual(decoder(encoded), expected)
                self.assertEqual(encoder(decoder(encoded)), encoded)

    def test_frozen_lengths_and_digest_vectors(self) -> None:
        self.assertEqual(len(encode_access_init(self.init)), 156)
        self.assertEqual(len(encode_access_challenge(self.challenge)), 197)
        self.assertEqual(len(encode_access_finish(self.finish)), 201)
        self.assertEqual(len(encode_access_finish_core(self.finish)), 156)
        self.assertEqual(len(encode_access_accept(self.accept)), 137)
        self.assertEqual(
            access_init_digest(self.init).hex(),
            "84924b03bf609e5eed11fff541f197c526e48d8b274c6b776bb9996a11925ed9",
        )
        self.assertEqual(
            access_challenge_digest(self.challenge).hex(),
            "129ee118bdd8637333eb59cd8b02a38d4b4db656e690e1dffd077672d1cf581c",
        )
        self.assertEqual(
            self.transcript_digest.hex(),
            "5ab71fc5285e381b407b818a74d01a145690de64475cd9817c0668c812dc074b",
        )
        self.assertEqual(
            self.attempt_id.hex(),
            "d6c2558c6f11dd07c561736db907d05972d3a43fbaa0936f683e6e99a858a071",
        )
        self.assertEqual(
            access_accept_digest(self.accept).hex(),
            "19aa825e0a2d94b42958827cda4ca6d505ab66779fcd59c324f328ae7e1bc8a6",
        )

    def test_wrong_object_type_is_rejected(self) -> None:
        encoded_accept = encode_access_accept(self.accept)
        with self.assertRaises(ProtocolEncodingError):
            decode_access_init(encoded_accept)

    def test_trailing_field_is_rejected_even_with_valid_outer_length(self) -> None:
        frame = decode_frame(encode_access_init(self.init))
        malformed = encode_frame(FrameType.ACCESS_INIT, frame.body + b"\x00")
        with self.assertRaises(ProtocolEncodingError):
            decode_access_init(malformed)

    def test_unknown_suite_is_rejected(self) -> None:
        unknown = replace(self.init, suite_id=1)
        with self.assertRaises(ProtocolEncodingError):
            encode_access_init(unknown)

    def test_suite_specific_limits_are_enforced_on_encode_and_decode(self) -> None:
        strict = SuiteLimits(
            suite_id=REFERENCE_SUITE_ID,
            max_ticket_bytes=3,
            max_key_share_bytes=REFERENCE_SUITE.max_key_share_bytes,
            max_cookie_bytes=REFERENCE_SUITE.max_cookie_bytes,
            max_holder_authenticator_bytes=(
                REFERENCE_SUITE.max_holder_authenticator_bytes
            ),
            max_key_confirmation_bytes=REFERENCE_SUITE.max_key_confirmation_bytes,
        )
        registry = {REFERENCE_SUITE_ID: strict}
        with self.assertRaises(ValueError):
            encode_access_init(self.init, registry)
        honest = encode_access_init(self.init)
        with self.assertRaises(ProtocolEncodingError):
            decode_access_init(honest, registry)

    def test_opaque_truncation_is_rejected(self) -> None:
        frame = decode_frame(encode_access_init(self.init))
        malformed = encode_frame(FrameType.ACCESS_INIT, frame.body[:-1])
        with self.assertRaises(ProtocolEncodingError):
            decode_access_init(malformed)


class TranscriptBindingTests(AccessObjectFixture):
    def test_shared_flow_fields_are_checked(self) -> None:
        mutations = (
            replace(self.challenge, suite_id=1),
            replace(self.challenge, ctx=fixed(20)),
            replace(self.challenge, serving_context_digest=fixed(21)),
            replace(self.challenge, ue_nonce=fixed(22)),
            replace(self.challenge, attempt_nonce=fixed(23, 16)),
        )
        for changed in mutations:
            with self.subTest(field=changed):
                with self.assertRaises(ProtocolBindingError):
                    access_transcript_digest(self.init, changed, self.finish)

    def test_finish_nonce_and_cookie_are_checked(self) -> None:
        for changed in (
            replace(self.finish, fgs_nonce=fixed(20)),
            replace(self.finish, challenge_cookie=b"other-cookie"),
        ):
            with self.subTest(message=changed):
                with self.assertRaises(ProtocolBindingError):
                    access_transcript_digest(self.init, self.challenge, changed)

    def test_authenticators_are_excluded_from_finish_core(self) -> None:
        changed = replace(
            self.finish,
            holder_authenticator=b"another-holder-auth",
            ue_key_confirmation=b"another-confirmation",
        )
        self.assertEqual(
            encode_access_finish_core(changed),
            encode_access_finish_core(self.finish),
        )
        self.assertEqual(
            access_transcript_digest(self.init, self.challenge, changed),
            self.transcript_digest,
        )

    def test_ticket_and_challenge_mutations_change_transcript(self) -> None:
        changed_ticket = replace(self.init, ticket=b"another-ticket")
        changed_key_share = replace(
            self.challenge,
            fgs_key_share=b"another-key-share",
        )
        self.assertNotEqual(
            access_transcript_digest(
                changed_ticket,
                self.challenge,
                self.finish,
            ),
            self.transcript_digest,
        )
        self.assertNotEqual(
            access_transcript_digest(
                self.init,
                changed_key_share,
                self.finish,
            ),
            self.transcript_digest,
        )


if __name__ == "__main__":
    unittest.main()
