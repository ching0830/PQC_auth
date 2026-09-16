"""Canonical v0.2 access objects, bindings, and transcript identities.

Only an explicitly test-only suite is registered.  The module freezes the
byte-level interface without selecting a production PQ KEM, access-NIZK, FGS
authentication, KDF, or key-confirmation primitive.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from enum import IntEnum
from types import MappingProxyType
from typing import Mapping

from .framing import (
    FrameTypeV2,
    ProtocolEncodingError,
    decode_frame_v2,
    decode_opaque_v2,
    encode_frame_v2,
    encode_opaque_v2,
    require_uint,
)


DIGEST_BYTES = 32
CONTEXT_BYTES = 32
NONCE_BYTES = 32
ATTEMPT_NONCE_BYTES = 16
SESSION_ID_BYTES = 32
REFERENCE_SUITE_ID = 0xFFFF
REFERENCE_PROOF_SUITE_ID = 0xFFFF
PRODUCTION_READY = False

ACCESS_REQUEST_CORE_LABEL = b"PQ-SAT/ACCESS-REQUEST-CORE/v2"
ACCESS_REQUEST_LABEL = b"PQ-SAT/ACCESS-REQUEST/v2"
ACCESS_ATTEMPT_LABEL = b"PQ-SAT/ACCESS-ATTEMPT/v2"
ACCESS_TRANSCRIPT_LABEL = b"PQ-SAT/ACCESS-TRANSCRIPT/v2"
ACCESS_ACCEPT_LABEL = b"PQ-SAT/ACCESS-ACCEPT/v2"
SESSION_ACTIVATE_LABEL = b"PQ-SAT/SESSION-ACTIVATE/v2"

ACCESS_REQUEST_PREFIX = struct.Struct(
    ">HH32s32sQ32s32s32s32sQ32s16sH32s"
)
ACCESS_ACCEPT_PREFIX = struct.Struct(
    ">H32s32sQ32s32s32s32s32s32sQQ"
)
SESSION_ACTIVATE_PREFIX = struct.Struct(">H32s32s32s32s")


class ProtocolBindingError(ValueError):
    """Raised when valid objects do not form the same v0.2 flow."""


class ChannelBindingMode(IntEnum):
    NONE = 0
    AUTHENTICATED_EXPORTER = 1


def _fixed_bytes(value: bytes, size: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    return value


def _opaque(value: bytes, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if not value:
        raise ValueError(f"{name} must not be empty")
    return value


def _shake(label: bytes, *parts: bytes) -> bytes:
    return hashlib.shake_256(label + b"".join(parts)).digest(DIGEST_BYTES)


@dataclass(frozen=True)
class SuiteLimitsV2:
    """Parser bounds for one explicitly registered access/AKE suite."""

    suite_id: int
    max_ticket_bytes: int
    max_kem_public_key_bytes: int
    max_kem_ciphertext_bytes: int
    max_fgs_authenticator_bytes: int
    max_key_confirmation_bytes: int

    def __post_init__(self) -> None:
        require_uint(self.suite_id, 16, "suite_id")
        for name in (
            "max_ticket_bytes",
            "max_kem_public_key_bytes",
            "max_kem_ciphertext_bytes",
            "max_fgs_authenticator_bytes",
            "max_key_confirmation_bytes",
        ):
            value = getattr(self, name)
            require_uint(value, 32, name)
            if value == 0:
                raise ValueError(f"{name} must be positive")


@dataclass(frozen=True)
class ProofLimitsV2:
    """Parser bounds for one explicitly registered access-NIZK suite."""

    proof_suite_id: int
    max_access_nizk_bytes: int

    def __post_init__(self) -> None:
        require_uint(self.proof_suite_id, 16, "proof_suite_id")
        require_uint(
            self.max_access_nizk_bytes,
            32,
            "max_access_nizk_bytes",
        )
        if self.max_access_nizk_bytes == 0:
            raise ValueError("max_access_nizk_bytes must be positive")


REFERENCE_SUITE = SuiteLimitsV2(
    suite_id=REFERENCE_SUITE_ID,
    max_ticket_bytes=65_536,
    max_kem_public_key_bytes=65_536,
    max_kem_ciphertext_bytes=65_536,
    max_fgs_authenticator_bytes=65_536,
    max_key_confirmation_bytes=65_536,
)
REFERENCE_PROOF_SUITE = ProofLimitsV2(
    proof_suite_id=REFERENCE_PROOF_SUITE_ID,
    max_access_nizk_bytes=262_144,
)
REFERENCE_SUITE_REGISTRY: Mapping[int, SuiteLimitsV2] = MappingProxyType(
    {REFERENCE_SUITE_ID: REFERENCE_SUITE}
)
REFERENCE_PROOF_SUITE_REGISTRY: Mapping[int, ProofLimitsV2] = MappingProxyType(
    {REFERENCE_PROOF_SUITE_ID: REFERENCE_PROOF_SUITE}
)


def _suite(
    suite_id: int,
    registry: Mapping[int, SuiteLimitsV2],
) -> SuiteLimitsV2:
    canonical_id = require_uint(suite_id, 16, "suite_id")
    try:
        profile = registry[canonical_id]
    except KeyError as exc:
        raise ProtocolEncodingError("unknown or disabled access suite") from exc
    if profile.suite_id != canonical_id:
        raise ProtocolEncodingError("inconsistent access suite registry entry")
    return profile


def _proof_suite(
    proof_suite_id: int,
    registry: Mapping[int, ProofLimitsV2],
) -> ProofLimitsV2:
    canonical_id = require_uint(proof_suite_id, 16, "proof_suite_id")
    try:
        profile = registry[canonical_id]
    except KeyError as exc:
        raise ProtocolEncodingError("unknown or disabled proof suite") from exc
    if profile.proof_suite_id != canonical_id:
        raise ProtocolEncodingError("inconsistent proof suite registry entry")
    return profile


@dataclass(frozen=True)
class AccessRequestV2:
    suite_id: int
    proof_suite_id: int
    system_config_digest: bytes
    ctx: bytes
    epoch: int
    target_fgs_id: bytes
    fgs_auth_key_id: bytes
    serving_context_digest: bytes
    authorization_digest: bytes
    client_time: int
    ue_nonce: bytes
    attempt_nonce: bytes
    channel_binding_mode: ChannelBindingMode
    channel_binding_digest: bytes
    ticket: bytes
    ue_kem_epk: bytes
    holder_binding_tag: bytes
    access_nizk: bytes

    def __post_init__(self) -> None:
        require_uint(self.suite_id, 16, "suite_id")
        require_uint(self.proof_suite_id, 16, "proof_suite_id")
        _fixed_bytes(
            self.system_config_digest,
            DIGEST_BYTES,
            "system_config_digest",
        )
        _fixed_bytes(self.ctx, CONTEXT_BYTES, "ctx")
        require_uint(self.epoch, 64, "epoch")
        _fixed_bytes(self.target_fgs_id, DIGEST_BYTES, "target_fgs_id")
        _fixed_bytes(self.fgs_auth_key_id, DIGEST_BYTES, "fgs_auth_key_id")
        _fixed_bytes(
            self.serving_context_digest,
            DIGEST_BYTES,
            "serving_context_digest",
        )
        _fixed_bytes(
            self.authorization_digest,
            DIGEST_BYTES,
            "authorization_digest",
        )
        require_uint(self.client_time, 64, "client_time")
        _fixed_bytes(self.ue_nonce, NONCE_BYTES, "ue_nonce")
        _fixed_bytes(
            self.attempt_nonce,
            ATTEMPT_NONCE_BYTES,
            "attempt_nonce",
        )
        if not isinstance(self.channel_binding_mode, ChannelBindingMode):
            raise TypeError("channel_binding_mode must be a ChannelBindingMode")
        _fixed_bytes(
            self.channel_binding_digest,
            DIGEST_BYTES,
            "channel_binding_digest",
        )
        if self.channel_binding_mode is ChannelBindingMode.NONE:
            if self.channel_binding_digest != bytes(DIGEST_BYTES):
                raise ValueError("mode NONE requires a zero channel binding digest")
        elif self.channel_binding_digest == bytes(DIGEST_BYTES):
            raise ValueError("authenticated exporter digest must not be zero")
        _opaque(self.ticket, "ticket")
        _opaque(self.ue_kem_epk, "ue_kem_epk")
        _fixed_bytes(
            self.holder_binding_tag,
            DIGEST_BYTES,
            "holder_binding_tag",
        )
        _opaque(self.access_nizk, "access_nizk")


@dataclass(frozen=True)
class AccessAcceptV2:
    suite_id: int
    system_config_digest: bytes
    ctx: bytes
    epoch: int
    fgs_id: bytes
    fgs_auth_key_id: bytes
    request_digest: bytes
    attempt_id: bytes
    session_id: bytes
    serving_context_digest: bytes
    session_expiry: int
    activation_deadline: int
    kem_ciphertext_to_ue: bytes
    fgs_authenticator: bytes
    server_key_confirmation: bytes

    def __post_init__(self) -> None:
        require_uint(self.suite_id, 16, "suite_id")
        _fixed_bytes(
            self.system_config_digest,
            DIGEST_BYTES,
            "system_config_digest",
        )
        _fixed_bytes(self.ctx, CONTEXT_BYTES, "ctx")
        require_uint(self.epoch, 64, "epoch")
        _fixed_bytes(self.fgs_id, DIGEST_BYTES, "fgs_id")
        _fixed_bytes(self.fgs_auth_key_id, DIGEST_BYTES, "fgs_auth_key_id")
        _fixed_bytes(self.request_digest, DIGEST_BYTES, "request_digest")
        _fixed_bytes(self.attempt_id, DIGEST_BYTES, "attempt_id")
        _fixed_bytes(self.session_id, SESSION_ID_BYTES, "session_id")
        _fixed_bytes(
            self.serving_context_digest,
            DIGEST_BYTES,
            "serving_context_digest",
        )
        require_uint(self.session_expiry, 64, "session_expiry")
        require_uint(self.activation_deadline, 64, "activation_deadline")
        if self.activation_deadline > self.session_expiry:
            raise ValueError("activation_deadline must not follow session_expiry")
        _opaque(self.kem_ciphertext_to_ue, "kem_ciphertext_to_ue")
        _opaque(self.fgs_authenticator, "fgs_authenticator")
        _opaque(self.server_key_confirmation, "server_key_confirmation")


@dataclass(frozen=True)
class SessionActivateV2:
    suite_id: int
    request_digest: bytes
    attempt_id: bytes
    session_id: bytes
    response_digest: bytes
    client_key_confirmation: bytes

    def __post_init__(self) -> None:
        require_uint(self.suite_id, 16, "suite_id")
        _fixed_bytes(self.request_digest, DIGEST_BYTES, "request_digest")
        _fixed_bytes(self.attempt_id, DIGEST_BYTES, "attempt_id")
        _fixed_bytes(self.session_id, SESSION_ID_BYTES, "session_id")
        _fixed_bytes(self.response_digest, DIGEST_BYTES, "response_digest")
        _opaque(self.client_key_confirmation, "client_key_confirmation")


def encode_access_request_core(
    message: AccessRequestV2,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
    proof_registry: Mapping[
        int, ProofLimitsV2
    ] = REFERENCE_PROOF_SUITE_REGISTRY,
) -> bytes:
    """Encode fields covered by the holder binding and access relation."""

    if not isinstance(message, AccessRequestV2):
        raise TypeError("message must be AccessRequestV2")
    suite = _suite(message.suite_id, suite_registry)
    _proof_suite(message.proof_suite_id, proof_registry)
    body = ACCESS_REQUEST_PREFIX.pack(
        message.suite_id,
        message.proof_suite_id,
        message.system_config_digest,
        message.ctx,
        message.epoch,
        message.target_fgs_id,
        message.fgs_auth_key_id,
        message.serving_context_digest,
        message.authorization_digest,
        message.client_time,
        message.ue_nonce,
        message.attempt_nonce,
        int(message.channel_binding_mode),
        message.channel_binding_digest,
    )
    body += encode_opaque_v2(
        message.ticket,
        max_length=suite.max_ticket_bytes,
    )
    body += encode_opaque_v2(
        message.ue_kem_epk,
        max_length=suite.max_kem_public_key_bytes,
    )
    return body


def encode_access_request(
    message: AccessRequestV2,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
    proof_registry: Mapping[
        int, ProofLimitsV2
    ] = REFERENCE_PROOF_SUITE_REGISTRY,
) -> bytes:
    """Encode an AccessRequestV2 frame."""

    if not isinstance(message, AccessRequestV2):
        raise TypeError("message must be AccessRequestV2")
    proof_suite = _proof_suite(message.proof_suite_id, proof_registry)
    body = encode_access_request_core(message, suite_registry, proof_registry)
    body += message.holder_binding_tag
    body += encode_opaque_v2(
        message.access_nizk,
        max_length=proof_suite.max_access_nizk_bytes,
    )
    return encode_frame_v2(FrameTypeV2.ACCESS_REQUEST, body)


def decode_access_request(
    encoded: bytes,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
    proof_registry: Mapping[
        int, ProofLimitsV2
    ] = REFERENCE_PROOF_SUITE_REGISTRY,
) -> AccessRequestV2:
    """Decode a canonical AccessRequestV2 frame."""

    frame = decode_frame_v2(encoded)
    if frame.msg_type is not FrameTypeV2.ACCESS_REQUEST:
        raise ProtocolEncodingError("expected AccessRequestV2 frame")
    if len(frame.body) < ACCESS_REQUEST_PREFIX.size:
        raise ProtocolEncodingError("truncated AccessRequestV2 prefix")
    values = list(ACCESS_REQUEST_PREFIX.unpack_from(frame.body))
    suite = _suite(values[0], suite_registry)
    proof_suite = _proof_suite(values[1], proof_registry)
    try:
        values[12] = ChannelBindingMode(values[12])
    except ValueError as exc:
        raise ProtocolEncodingError("unknown channel binding mode") from exc
    ticket, offset = decode_opaque_v2(
        frame.body,
        ACCESS_REQUEST_PREFIX.size,
        max_length=suite.max_ticket_bytes,
    )
    kem_public_key, offset = decode_opaque_v2(
        frame.body,
        offset,
        max_length=suite.max_kem_public_key_bytes,
    )
    tag_end = offset + DIGEST_BYTES
    if tag_end > len(frame.body):
        raise ProtocolEncodingError("truncated holder binding tag")
    holder_binding_tag = frame.body[offset:tag_end]
    access_nizk, offset = decode_opaque_v2(
        frame.body,
        tag_end,
        max_length=proof_suite.max_access_nizk_bytes,
    )
    if offset != len(frame.body):
        raise ProtocolEncodingError("trailing AccessRequestV2 fields")
    return AccessRequestV2(
        *values,
        ticket,
        kem_public_key,
        holder_binding_tag,
        access_nizk,
    )


def derive_request_core_digest(
    message: AccessRequestV2,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
    proof_registry: Mapping[
        int, ProofLimitsV2
    ] = REFERENCE_PROOF_SUITE_REGISTRY,
) -> bytes:
    return _shake(
        ACCESS_REQUEST_CORE_LABEL,
        encode_access_request_core(message, suite_registry, proof_registry),
    )


def derive_request_digest(
    message: AccessRequestV2,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
    proof_registry: Mapping[
        int, ProofLimitsV2
    ] = REFERENCE_PROOF_SUITE_REGISTRY,
) -> bytes:
    return _shake(
        ACCESS_REQUEST_LABEL,
        encode_access_request(message, suite_registry, proof_registry),
    )


def derive_attempt_id(use_key: bytes, request_digest: bytes) -> bytes:
    return _shake(
        ACCESS_ATTEMPT_LABEL,
        _fixed_bytes(use_key, DIGEST_BYTES, "use_key"),
        _fixed_bytes(request_digest, DIGEST_BYTES, "request_digest"),
    )


def encode_access_accept_core(
    message: AccessAcceptV2,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
) -> bytes:
    """Encode the response fields covered by the transcript."""

    if not isinstance(message, AccessAcceptV2):
        raise TypeError("message must be AccessAcceptV2")
    suite = _suite(message.suite_id, suite_registry)
    body = ACCESS_ACCEPT_PREFIX.pack(
        message.suite_id,
        message.system_config_digest,
        message.ctx,
        message.epoch,
        message.fgs_id,
        message.fgs_auth_key_id,
        message.request_digest,
        message.attempt_id,
        message.session_id,
        message.serving_context_digest,
        message.session_expiry,
        message.activation_deadline,
    )
    return body + encode_opaque_v2(
        message.kem_ciphertext_to_ue,
        max_length=suite.max_kem_ciphertext_bytes,
    )


def encode_access_accept(
    message: AccessAcceptV2,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
) -> bytes:
    """Encode an AccessAcceptV2 frame."""

    if not isinstance(message, AccessAcceptV2):
        raise TypeError("message must be AccessAcceptV2")
    suite = _suite(message.suite_id, suite_registry)
    body = encode_access_accept_core(message, suite_registry)
    body += encode_opaque_v2(
        message.fgs_authenticator,
        max_length=suite.max_fgs_authenticator_bytes,
    )
    body += encode_opaque_v2(
        message.server_key_confirmation,
        max_length=suite.max_key_confirmation_bytes,
    )
    return encode_frame_v2(FrameTypeV2.ACCESS_ACCEPT, body)


def decode_access_accept(
    encoded: bytes,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
) -> AccessAcceptV2:
    """Decode a canonical AccessAcceptV2 frame."""

    frame = decode_frame_v2(encoded)
    if frame.msg_type is not FrameTypeV2.ACCESS_ACCEPT:
        raise ProtocolEncodingError("expected AccessAcceptV2 frame")
    if len(frame.body) < ACCESS_ACCEPT_PREFIX.size:
        raise ProtocolEncodingError("truncated AccessAcceptV2 prefix")
    values = ACCESS_ACCEPT_PREFIX.unpack_from(frame.body)
    suite = _suite(values[0], suite_registry)
    kem_ciphertext, offset = decode_opaque_v2(
        frame.body,
        ACCESS_ACCEPT_PREFIX.size,
        max_length=suite.max_kem_ciphertext_bytes,
    )
    fgs_authenticator, offset = decode_opaque_v2(
        frame.body,
        offset,
        max_length=suite.max_fgs_authenticator_bytes,
    )
    server_key_confirmation, offset = decode_opaque_v2(
        frame.body,
        offset,
        max_length=suite.max_key_confirmation_bytes,
    )
    if offset != len(frame.body):
        raise ProtocolEncodingError("trailing AccessAcceptV2 fields")
    return AccessAcceptV2(
        *values,
        kem_ciphertext,
        fgs_authenticator,
        server_key_confirmation,
    )


def validate_response_binding(
    request: AccessRequestV2,
    response: AccessAcceptV2,
    *,
    use_key: bytes | None = None,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
    proof_registry: Mapping[
        int, ProofLimitsV2
    ] = REFERENCE_PROOF_SUITE_REGISTRY,
) -> None:
    """Reject a response that is not bound to the supplied exact request."""

    if not isinstance(request, AccessRequestV2):
        raise TypeError("request must be AccessRequestV2")
    if not isinstance(response, AccessAcceptV2):
        raise TypeError("response must be AccessAcceptV2")
    expected = (
        request.suite_id,
        request.system_config_digest,
        request.ctx,
        request.epoch,
        request.target_fgs_id,
        request.fgs_auth_key_id,
        request.serving_context_digest,
    )
    actual = (
        response.suite_id,
        response.system_config_digest,
        response.ctx,
        response.epoch,
        response.fgs_id,
        response.fgs_auth_key_id,
        response.serving_context_digest,
    )
    if actual != expected:
        raise ProtocolBindingError("response context does not match request")
    request_digest = derive_request_digest(
        request,
        suite_registry,
        proof_registry,
    )
    if response.request_digest != request_digest:
        raise ProtocolBindingError("response request digest mismatch")
    if use_key is not None:
        expected_attempt = derive_attempt_id(use_key, request_digest)
        if response.attempt_id != expected_attempt:
            raise ProtocolBindingError("response attempt identifier mismatch")


def derive_transcript_digest(
    response: AccessAcceptV2,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
) -> bytes:
    return _shake(
        ACCESS_TRANSCRIPT_LABEL,
        response.request_digest,
        encode_access_accept_core(response, suite_registry),
    )


def derive_response_digest(
    response: AccessAcceptV2,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
) -> bytes:
    return _shake(
        ACCESS_ACCEPT_LABEL,
        encode_access_accept(response, suite_registry),
    )


def encode_session_activate(
    message: SessionActivateV2,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
) -> bytes:
    """Encode the explicit client-Finished form of SessionActivateV2."""

    if not isinstance(message, SessionActivateV2):
        raise TypeError("message must be SessionActivateV2")
    suite = _suite(message.suite_id, suite_registry)
    body = SESSION_ACTIVATE_PREFIX.pack(
        message.suite_id,
        message.request_digest,
        message.attempt_id,
        message.session_id,
        message.response_digest,
    )
    body += encode_opaque_v2(
        message.client_key_confirmation,
        max_length=suite.max_key_confirmation_bytes,
    )
    return encode_frame_v2(FrameTypeV2.SESSION_ACTIVATE, body)


def decode_session_activate(
    encoded: bytes,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
) -> SessionActivateV2:
    """Decode a canonical SessionActivateV2 frame."""

    frame = decode_frame_v2(encoded)
    if frame.msg_type is not FrameTypeV2.SESSION_ACTIVATE:
        raise ProtocolEncodingError("expected SessionActivateV2 frame")
    if len(frame.body) < SESSION_ACTIVATE_PREFIX.size:
        raise ProtocolEncodingError("truncated SessionActivateV2 prefix")
    values = SESSION_ACTIVATE_PREFIX.unpack_from(frame.body)
    suite = _suite(values[0], suite_registry)
    client_key_confirmation, offset = decode_opaque_v2(
        frame.body,
        SESSION_ACTIVATE_PREFIX.size,
        max_length=suite.max_key_confirmation_bytes,
    )
    if offset != len(frame.body):
        raise ProtocolEncodingError("trailing SessionActivateV2 fields")
    return SessionActivateV2(*values, client_key_confirmation)


def validate_activation_binding(
    response: AccessAcceptV2,
    activation: SessionActivateV2,
    *,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
) -> None:
    """Reject a client confirmation for another response or session."""

    if not isinstance(response, AccessAcceptV2):
        raise TypeError("response must be AccessAcceptV2")
    if not isinstance(activation, SessionActivateV2):
        raise TypeError("activation must be SessionActivateV2")
    expected = (
        response.suite_id,
        response.request_digest,
        response.attempt_id,
        response.session_id,
        derive_response_digest(response, suite_registry),
    )
    actual = (
        activation.suite_id,
        activation.request_digest,
        activation.attempt_id,
        activation.session_id,
        activation.response_digest,
    )
    if actual != expected:
        raise ProtocolBindingError("activation does not match response")


def derive_activation_digest(
    activation: SessionActivateV2,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
) -> bytes:
    return _shake(
        SESSION_ACTIVATE_LABEL,
        encode_session_activate(activation, suite_registry),
    )
