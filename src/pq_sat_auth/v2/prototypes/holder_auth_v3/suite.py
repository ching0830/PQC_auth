"""Executable D4 holder-authentication and PQ-AKE measurement flow."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass, replace

from .codec import (
    ACCESS_SUITE_ID,
    CHANNEL_BINDING_NONE,
    FINISHED_BYTES,
    HOLDER_SUITE_ML_DSA_65,
    ML_DSA_65_PARAMETER_DIGEST,
    ML_DSA_65_SIGNATURE_BYTES,
    FirstApplicationRecordV3,
    HolderAccessAcceptV3,
    HolderAccessRequestV3,
    SessionActivateV3,
    build_candidate_ticket_fixture,
    decode_access_accept,
    decode_access_request,
    decode_candidate_ticket,
    decode_first_application_record,
    decode_session_activate,
    derive_attempt_id,
    derive_holder_public_key_binding,
    derive_request_digest,
    derive_response_digest,
    derive_transcript_digest,
    encode_access_accept,
    encode_access_request,
    encode_first_application_record,
    encode_session_activate,
)
from .providers import MLDSA65Provider, MLKEM768Provider


KDF_EXTRACT_LABEL = b"PQ-SAT/KDF-EXTRACT/v3"
KDF_EXPAND_LABEL = b"PQ-SAT/KDF-EXPAND/v3"
FGS_AUTH_LABEL = b"PQ-SAT/FGS-AUTH/v3"
SERVER_FINISHED_LABEL = b"PQ-SAT/SERVER-FINISHED/v3"
CLIENT_FINISHED_LABEL = b"PQ-SAT/CLIENT-FINISHED/v3"
SCHEDULE_CONTEXT_LABEL = b"PQ-SAT/SCHEDULE-CONTEXT/v3"
CONDITIONAL_RECORD_CIPHERTEXT_LABEL = b"PQ-SAT/D4-CONDITIONAL-AEAD-SIZE/v0.1"

PRODUCTION_READY = False
PROOF_CLOSED = False
PRODUCTION_CLOSED = False


def _fixture(label: bytes, size: int = 32) -> bytes:
    return hashlib.shake_256(b"PQ-SAT/D4-HANDSHAKE/v0.1/" + label).digest(size)


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if not isinstance(prk, bytes) or len(prk) != hashlib.sha384().digest_size:
        raise ValueError("HKDF-SHA384 PRK must be 48 bytes")
    if not isinstance(info, bytes):
        raise TypeError("HKDF info must be bytes")
    if not 1 <= length <= 255 * hashlib.sha384().digest_size:
        raise ValueError("HKDF output length is outside bounds")
    blocks: list[bytes] = []
    previous = b""
    counter = 1
    while sum(len(block) for block in blocks) < length:
        previous = hmac.new(
            prk,
            previous + info + bytes((counter,)),
            hashlib.sha384,
        ).digest()
        blocks.append(previous)
        counter += 1
    return b"".join(blocks)[:length]


@dataclass(frozen=True)
class ExperimentalSessionKeysV3:
    server_finished: bytes
    client_finished: bytes
    application: bytes
    exporter: bytes

    def validate(self) -> None:
        for name in (
            "server_finished",
            "client_finished",
            "application",
            "exporter",
        ):
            value = getattr(self, name)
            if not isinstance(value, bytes) or len(value) != FINISHED_BYTES:
                raise ValueError(f"{name} must be exactly {FINISHED_BYTES} bytes")


def _schedule_context(
    request: HolderAccessRequestV3,
    response: HolderAccessAcceptV3,
    transcript_digest: bytes,
) -> bytes:
    return b"".join(
        (
            SCHEDULE_CONTEXT_LABEL,
            struct.pack(
                ">HHQ",
                request.access_suite_id,
                request.holder_suite_id,
                request.epoch,
            ),
            request.system_config_digest,
            request.ctx,
            response.fgs_id,
            request.fgs_auth_key_id,
            request.serving_context_digest,
            transcript_digest,
        )
    )


def _derive_session_keys(
    shared_secret: bytes,
    schedule_context: bytes,
) -> ExperimentalSessionKeysV3:
    if not isinstance(shared_secret, bytes) or len(shared_secret) != 32:
        raise ValueError("ML-KEM shared secret must be exactly 32 bytes")
    if not isinstance(schedule_context, bytes) or not schedule_context:
        raise ValueError("schedule context must be non-empty bytes")
    salt = hashlib.sha384(
        KDF_EXTRACT_LABEL
        + len(schedule_context).to_bytes(4, "big")
        + schedule_context
    ).digest()
    prk = hmac.new(salt, shared_secret, hashlib.sha384).digest()

    def expand(label: bytes) -> bytes:
        return _hkdf_expand(
            prk,
            KDF_EXPAND_LABEL
            + len(label).to_bytes(2, "big")
            + label
            + len(schedule_context).to_bytes(4, "big")
            + schedule_context,
            FINISHED_BYTES,
        )

    keys = ExperimentalSessionKeysV3(
        server_finished=expand(b"server-finished"),
        client_finished=expand(b"client-finished"),
        application=expand(b"application"),
        exporter=expand(b"exporter"),
    )
    keys.validate()
    return keys


def _fgs_signing_input(transcript_digest: bytes) -> bytes:
    if not isinstance(transcript_digest, bytes) or len(transcript_digest) != 32:
        raise ValueError("transcript digest must be exactly 32 bytes")
    return FGS_AUTH_LABEL + transcript_digest


def _server_finished(
    key: bytes,
    transcript_digest: bytes,
    fgs_authenticator: bytes,
) -> bytes:
    return hmac.new(
        key,
        SERVER_FINISHED_LABEL
        + transcript_digest
        + hashlib.sha384(fgs_authenticator).digest(),
        hashlib.sha384,
    ).digest()


def _client_finished(key: bytes, response_digest: bytes) -> bytes:
    return hmac.new(
        key,
        CLIENT_FINISHED_LABEL + response_digest,
        hashlib.sha384,
    ).digest()


def verify_holder_authenticated_request(
    request: HolderAccessRequestV3,
    provider: MLDSA65Provider,
) -> bool:
    """Verify the experimental ticket/key binding and holder signature.

    The provisional issuer bytes in the fixture are intentionally *not*
    authenticated here.  This function is not a replacement for VerifyTicket.
    """

    try:
        if not isinstance(request, HolderAccessRequestV3):
            return False
        request.validate()
        ticket = decode_candidate_ticket(request.ticket)
        if ticket.payload.ctx != request.ctx:
            return False
        if ticket.payload.holder_suite_id != request.holder_suite_id:
            return False
        if ticket.payload.holder_parameter_digest != ML_DSA_65_PARAMETER_DIGEST:
            return False
        expected_binding = derive_holder_public_key_binding(
            request.holder_suite_id,
            ticket.payload.holder_parameter_digest,
            request.holder_public_key,
        )
        if not hmac.compare_digest(
            expected_binding,
            ticket.payload.holder_public_key_binding,
        ):
            return False
        return provider.verify(
            request.holder_public_key,
            request.holder_signing_input(),
            request.holder_authenticator,
        )
    except Exception:
        return False


@dataclass(frozen=True)
class HandshakeArtifactsV3:
    ticket_bytes: bytes
    request_bytes: bytes
    response_bytes: bytes
    activation_bytes: bytes
    first_application_record_bytes: bytes
    holder_public_key: bytes
    holder_authenticator: bytes
    fgs_public_key: bytes
    fgs_authenticator: bytes
    request_digest: bytes
    response_digest: bytes
    transcript_digest: bytes
    session_id: bytes
    shared_secret_match: bool
    holder_authentication_verified: bool
    fgs_authentication_verified: bool
    server_finished_verified: bool
    client_finished_verified: bool
    conditional_record_ciphertext_fixture: bool = True
    production_ready: bool = False

    @property
    def explicit_m3_total_bytes(self) -> int:
        return len(self.request_bytes) + len(self.response_bytes) + len(
            self.activation_bytes
        )

    @property
    def first_record_total_bytes(self) -> int:
        return len(self.request_bytes) + len(self.response_bytes) + len(
            self.first_application_record_bytes
        )


def run_experimental_handshake(
    *,
    holder_provider: MLDSA65Provider,
    fgs_provider: MLDSA65Provider,
    kem_provider: MLKEM768Provider,
) -> HandshakeArtifactsV3:
    """Execute one real ML-DSA/ML-KEM handshake in the isolated profile."""

    if (
        holder_provider.production_ready
        or fgs_provider.production_ready
        or kem_provider.production_ready
    ):
        raise ValueError("D4 adapters must remain explicitly non-production")

    holder_public_key, holder_secret_key = holder_provider.generate_keypair()
    ticket = build_candidate_ticket_fixture(holder_public_key)
    ticket_bytes = ticket.encode()
    ue_kem_public_key, ue_kem_secret_key = kem_provider.generate_keypair()

    request_draft = HolderAccessRequestV3(
        access_suite_id=ACCESS_SUITE_ID,
        holder_suite_id=HOLDER_SUITE_ML_DSA_65,
        system_config_digest=_fixture(b"system-config"),
        ctx=ticket.payload.ctx,
        epoch=20260916,
        target_fgs_id=_fixture(b"fgs-id"),
        fgs_auth_key_id=_fixture(b"fgs-auth-key-id"),
        serving_context_digest=_fixture(b"serving-context"),
        authorization_digest=_fixture(b"authorization"),
        client_time=1789488000,
        ue_nonce=_fixture(b"ue-nonce"),
        attempt_nonce=_fixture(b"attempt-nonce", 16),
        channel_binding_mode=CHANNEL_BINDING_NONE,
        channel_binding_digest=bytes(32),
        ticket=ticket_bytes,
        ue_kem_epk=ue_kem_public_key,
        holder_public_key=holder_public_key,
        holder_authenticator=bytes(ML_DSA_65_SIGNATURE_BYTES),
    )
    holder_signature = holder_provider.sign(
        holder_secret_key,
        request_draft.holder_signing_input(),
    )
    request = replace(request_draft, holder_authenticator=holder_signature)
    request_bytes = encode_access_request(request)
    decoded_request = decode_access_request(request_bytes)
    holder_verified = verify_holder_authenticated_request(
        decoded_request,
        holder_provider,
    )
    if not holder_verified:
        raise RuntimeError("holder-authenticated request verification failed")

    request_digest = derive_request_digest(request)
    attempt_id = derive_attempt_id(request)
    kem_ciphertext, server_shared_secret = kem_provider.encapsulate(
        ue_kem_public_key
    )
    fgs_public_key, fgs_secret_key = fgs_provider.generate_keypair()
    session_id = secrets.token_bytes(32)
    response_draft = HolderAccessAcceptV3(
        access_suite_id=ACCESS_SUITE_ID,
        system_config_digest=request.system_config_digest,
        ctx=request.ctx,
        epoch=request.epoch,
        fgs_id=request.target_fgs_id,
        fgs_auth_key_id=request.fgs_auth_key_id,
        request_digest=request_digest,
        attempt_id=attempt_id,
        session_id=session_id,
        serving_context_digest=request.serving_context_digest,
        session_expiry=request.client_time + 300,
        activation_deadline=request.client_time + 30,
        kem_ciphertext_to_ue=kem_ciphertext,
        fgs_authenticator=bytes(ML_DSA_65_SIGNATURE_BYTES),
        server_key_confirmation=bytes(FINISHED_BYTES),
    )
    transcript_digest = derive_transcript_digest(request, response_draft)
    schedule_context = _schedule_context(
        request,
        response_draft,
        transcript_digest,
    )
    server_keys = _derive_session_keys(server_shared_secret, schedule_context)
    fgs_authenticator = fgs_provider.sign(
        fgs_secret_key,
        _fgs_signing_input(transcript_digest),
    )
    server_confirmation = _server_finished(
        server_keys.server_finished,
        transcript_digest,
        fgs_authenticator,
    )
    response = replace(
        response_draft,
        fgs_authenticator=fgs_authenticator,
        server_key_confirmation=server_confirmation,
    )
    response_bytes = encode_access_accept(response)
    decoded_response = decode_access_accept(response_bytes)

    client_shared_secret = kem_provider.decapsulate(
        ue_kem_secret_key,
        decoded_response.kem_ciphertext_to_ue,
    )
    shared_secret_match = hmac.compare_digest(
        server_shared_secret,
        client_shared_secret,
    )
    client_keys = _derive_session_keys(client_shared_secret, schedule_context)
    fgs_verified = fgs_provider.verify(
        fgs_public_key,
        _fgs_signing_input(transcript_digest),
        decoded_response.fgs_authenticator,
    )
    server_finished_verified = hmac.compare_digest(
        decoded_response.server_key_confirmation,
        _server_finished(
            client_keys.server_finished,
            transcript_digest,
            decoded_response.fgs_authenticator,
        ),
    )

    response_digest = derive_response_digest(response)
    client_confirmation = _client_finished(
        client_keys.client_finished,
        response_digest,
    )
    activation = SessionActivateV3(
        access_suite_id=ACCESS_SUITE_ID,
        request_digest=request_digest,
        attempt_id=attempt_id,
        session_id=session_id,
        response_digest=response_digest,
        client_key_confirmation=client_confirmation,
    )
    activation_bytes = encode_session_activate(activation)
    decoded_activation = decode_session_activate(activation_bytes)
    client_finished_verified = hmac.compare_digest(
        decoded_activation.client_key_confirmation,
        _client_finished(server_keys.client_finished, response_digest),
    )

    # D1 left the production AEAD undecided.  The 17-byte value below models
    # one application byte plus a 16-byte tag solely for exact wire accounting.
    # It is not accepted as cryptographic AEAD evidence.
    conditional_ciphertext = hashlib.shake_256(
        CONDITIONAL_RECORD_CIPHERTEXT_LABEL + session_id
    ).digest(17)
    first_record = FirstApplicationRecordV3(
        access_suite_id=ACCESS_SUITE_ID,
        request_digest=request_digest,
        attempt_id=attempt_id,
        session_id=session_id,
        response_digest=response_digest,
        sequence_number=0,
        activation_bytes=activation_bytes,
        ciphertext=conditional_ciphertext,
    )
    first_record_bytes = encode_first_application_record(first_record)
    decode_first_application_record(first_record_bytes)

    if not all(
        (
            shared_secret_match,
            holder_verified,
            fgs_verified,
            server_finished_verified,
            client_finished_verified,
        )
    ):
        raise RuntimeError("experimental handshake invariant failed")

    return HandshakeArtifactsV3(
        ticket_bytes=ticket_bytes,
        request_bytes=request_bytes,
        response_bytes=response_bytes,
        activation_bytes=activation_bytes,
        first_application_record_bytes=first_record_bytes,
        holder_public_key=holder_public_key,
        holder_authenticator=holder_signature,
        fgs_public_key=fgs_public_key,
        fgs_authenticator=fgs_authenticator,
        request_digest=request_digest,
        response_digest=response_digest,
        transcript_digest=transcript_digest,
        session_id=session_id,
        shared_secret_match=shared_secret_match,
        holder_authentication_verified=holder_verified,
        fgs_authentication_verified=fgs_verified,
        server_finished_verified=server_finished_verified,
        client_finished_verified=client_finished_verified,
    )
