"""Canonical draft access objects and transcript identities for profile v0.1.

The only registered suite is deliberately test-only.  This module freezes the
byte-level interface needed by integration tests without selecting production
holder authentication or PQ AKE primitives.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from .framing import (
    FrameType,
    ProtocolEncodingError,
    decode_frame,
    decode_opaque,
    encode_frame,
    encode_opaque,
)


CONTEXT_BYTES = 32
NONCE_BYTES = 32
ATTEMPT_NONCE_BYTES = 16
DIGEST_BYTES = 32
SESSION_ID_BYTES = 32
REFERENCE_SUITE_ID = 0xFFFF

SERVING_CONTEXT_LABEL = b"PQ-SAT/SERVING-CONTEXT/v1"
ACCESS_INIT_LABEL = b"PQ-SAT/ACCESS-INIT/v1"
ACCESS_CHALLENGE_LABEL = b"PQ-SAT/ACCESS-CHALLENGE/v1"
ACCESS_TRANSCRIPT_LABEL = b"PQ-SAT/ACCESS-TRANSCRIPT/v1"
ACCESS_ATTEMPT_LABEL = b"PQ-SAT/ACCESS-ATTEMPT/v1"
ACCESS_ACCEPT_LABEL = b"PQ-SAT/ACCESS-ACCEPT/v1"

SERVING_CONTEXT_STRUCT = struct.Struct(">32s32s32s32sQ32s")
ACCESS_INIT_PREFIX = struct.Struct(">H32s32s32s16s")
ACCESS_CHALLENGE_PREFIX = struct.Struct(">H32s32s32s32s16sQ")
ACCESS_FINISH_PREFIX = struct.Struct(">H32s32s32s32s16s")
ACCESS_ACCEPT_PREFIX = struct.Struct(">H32s32s32sQ")


class ProtocolBindingError(ValueError):
    """Raised when individually valid access objects do not form one flow."""


def _fixed_bytes(value: bytes, size: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    return value


def _uint(value: int, bits: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value < (1 << bits):
        raise ValueError(f"{name} does not fit uint{bits}")
    return value


def _shake(label: bytes, *parts: bytes) -> bytes:
    return hashlib.shake_256(label + b"".join(parts)).digest(DIGEST_BYTES)


@dataclass(frozen=True)
class SuiteLimits:
    """Per-field parser limits for one explicitly registered suite."""

    suite_id: int
    max_ticket_bytes: int
    max_key_share_bytes: int
    max_cookie_bytes: int
    max_holder_authenticator_bytes: int
    max_key_confirmation_bytes: int

    def __post_init__(self) -> None:
        _uint(self.suite_id, 16, "suite_id")
        for name in (
            "max_ticket_bytes",
            "max_key_share_bytes",
            "max_cookie_bytes",
            "max_holder_authenticator_bytes",
            "max_key_confirmation_bytes",
        ):
            value = getattr(self, name)
            _uint(value, 32, name)
            if value == 0:
                raise ValueError(f"{name} must be positive")


REFERENCE_SUITE = SuiteLimits(
    suite_id=REFERENCE_SUITE_ID,
    max_ticket_bytes=65_536,
    max_key_share_bytes=65_536,
    max_cookie_bytes=16_384,
    max_holder_authenticator_bytes=262_144,
    max_key_confirmation_bytes=65_536,
)

REFERENCE_SUITE_REGISTRY: Mapping[int, SuiteLimits] = MappingProxyType(
    {REFERENCE_SUITE_ID: REFERENCE_SUITE}
)


def _suite(
    suite_id: int,
    registry: Mapping[int, SuiteLimits],
) -> SuiteLimits:
    canonical_id = _uint(suite_id, 16, "suite_id")
    try:
        profile = registry[canonical_id]
    except KeyError as exc:
        raise ProtocolEncodingError("unknown or disabled suite") from exc
    if profile.suite_id != canonical_id:
        raise ProtocolEncodingError("inconsistent suite registry entry")
    return profile


@dataclass(frozen=True)
class ServingContextV1:
    """Draft fixed-width digests for the serving authorization domain.

    Mapping deployment identifiers into these digests remains a deployment
    profile decision and is not frozen by this test-only reference codec.
    """

    operator_id_digest: bytes
    fgs_id_digest: bytes
    relay_scope_digest: bytes
    cell_scope_digest: bytes
    epoch: int
    policy_digest: bytes

    def __post_init__(self) -> None:
        _fixed_bytes(self.operator_id_digest, DIGEST_BYTES, "operator_id_digest")
        _fixed_bytes(self.fgs_id_digest, DIGEST_BYTES, "fgs_id_digest")
        _fixed_bytes(self.relay_scope_digest, DIGEST_BYTES, "relay_scope_digest")
        _fixed_bytes(self.cell_scope_digest, DIGEST_BYTES, "cell_scope_digest")
        _uint(self.epoch, 64, "epoch")
        _fixed_bytes(self.policy_digest, DIGEST_BYTES, "policy_digest")

    def encode(self) -> bytes:
        return SERVING_CONTEXT_STRUCT.pack(
            self.operator_id_digest,
            self.fgs_id_digest,
            self.relay_scope_digest,
            self.cell_scope_digest,
            self.epoch,
            self.policy_digest,
        )

    @classmethod
    def decode(cls, encoded: bytes) -> "ServingContextV1":
        if not isinstance(encoded, bytes):
            raise TypeError("encoded serving context must be bytes")
        if len(encoded) != SERVING_CONTEXT_STRUCT.size:
            raise ProtocolEncodingError("serving context length mismatch")
        return cls(*SERVING_CONTEXT_STRUCT.unpack(encoded))

    @property
    def digest(self) -> bytes:
        return _shake(SERVING_CONTEXT_LABEL, self.encode())


@dataclass(frozen=True)
class AccessInitV1:
    suite_id: int
    ctx: bytes
    serving_context_digest: bytes
    ue_nonce: bytes
    attempt_nonce: bytes
    ticket: bytes
    ue_key_share: bytes

    def __post_init__(self) -> None:
        _uint(self.suite_id, 16, "suite_id")
        _fixed_bytes(self.ctx, CONTEXT_BYTES, "ctx")
        _fixed_bytes(
            self.serving_context_digest,
            DIGEST_BYTES,
            "serving_context_digest",
        )
        _fixed_bytes(self.ue_nonce, NONCE_BYTES, "ue_nonce")
        _fixed_bytes(self.attempt_nonce, ATTEMPT_NONCE_BYTES, "attempt_nonce")
        if not isinstance(self.ticket, bytes):
            raise TypeError("ticket must be bytes")
        if not isinstance(self.ue_key_share, bytes):
            raise TypeError("ue_key_share must be bytes")


@dataclass(frozen=True)
class AccessChallengeV1:
    suite_id: int
    ctx: bytes
    serving_context_digest: bytes
    ue_nonce: bytes
    fgs_nonce: bytes
    attempt_nonce: bytes
    challenge_expiry: int
    fgs_key_share: bytes
    challenge_cookie: bytes

    def __post_init__(self) -> None:
        _uint(self.suite_id, 16, "suite_id")
        _fixed_bytes(self.ctx, CONTEXT_BYTES, "ctx")
        _fixed_bytes(
            self.serving_context_digest,
            DIGEST_BYTES,
            "serving_context_digest",
        )
        _fixed_bytes(self.ue_nonce, NONCE_BYTES, "ue_nonce")
        _fixed_bytes(self.fgs_nonce, NONCE_BYTES, "fgs_nonce")
        _fixed_bytes(self.attempt_nonce, ATTEMPT_NONCE_BYTES, "attempt_nonce")
        _uint(self.challenge_expiry, 64, "challenge_expiry")
        if not isinstance(self.fgs_key_share, bytes):
            raise TypeError("fgs_key_share must be bytes")
        if not isinstance(self.challenge_cookie, bytes):
            raise TypeError("challenge_cookie must be bytes")


@dataclass(frozen=True)
class AccessFinishV1:
    suite_id: int
    ctx: bytes
    serving_context_digest: bytes
    ue_nonce: bytes
    fgs_nonce: bytes
    attempt_nonce: bytes
    challenge_cookie: bytes
    holder_authenticator: bytes
    ue_key_confirmation: bytes

    def __post_init__(self) -> None:
        _uint(self.suite_id, 16, "suite_id")
        _fixed_bytes(self.ctx, CONTEXT_BYTES, "ctx")
        _fixed_bytes(
            self.serving_context_digest,
            DIGEST_BYTES,
            "serving_context_digest",
        )
        _fixed_bytes(self.ue_nonce, NONCE_BYTES, "ue_nonce")
        _fixed_bytes(self.fgs_nonce, NONCE_BYTES, "fgs_nonce")
        _fixed_bytes(self.attempt_nonce, ATTEMPT_NONCE_BYTES, "attempt_nonce")
        if not isinstance(self.challenge_cookie, bytes):
            raise TypeError("challenge_cookie must be bytes")
        if not isinstance(self.holder_authenticator, bytes):
            raise TypeError("holder_authenticator must be bytes")
        if not isinstance(self.ue_key_confirmation, bytes):
            raise TypeError("ue_key_confirmation must be bytes")


@dataclass(frozen=True)
class AccessAcceptV1:
    suite_id: int
    attempt_id: bytes
    session_id: bytes
    serving_context_digest: bytes
    session_expiry: int
    fgs_key_confirmation: bytes

    def __post_init__(self) -> None:
        _uint(self.suite_id, 16, "suite_id")
        _fixed_bytes(self.attempt_id, DIGEST_BYTES, "attempt_id")
        _fixed_bytes(self.session_id, SESSION_ID_BYTES, "session_id")
        _fixed_bytes(
            self.serving_context_digest,
            DIGEST_BYTES,
            "serving_context_digest",
        )
        _uint(self.session_expiry, 64, "session_expiry")
        if not isinstance(self.fgs_key_confirmation, bytes):
            raise TypeError("fgs_key_confirmation must be bytes")


def encode_access_init(
    message: AccessInitV1,
    registry: Mapping[int, SuiteLimits] = REFERENCE_SUITE_REGISTRY,
) -> bytes:
    if not isinstance(message, AccessInitV1):
        raise TypeError("message must be AccessInitV1")
    profile = _suite(message.suite_id, registry)
    body = ACCESS_INIT_PREFIX.pack(
        message.suite_id,
        message.ctx,
        message.serving_context_digest,
        message.ue_nonce,
        message.attempt_nonce,
    )
    body += encode_opaque(message.ticket, max_length=profile.max_ticket_bytes)
    body += encode_opaque(
        message.ue_key_share,
        max_length=profile.max_key_share_bytes,
    )
    return encode_frame(FrameType.ACCESS_INIT, body)


def decode_access_init(
    encoded: bytes,
    registry: Mapping[int, SuiteLimits] = REFERENCE_SUITE_REGISTRY,
) -> AccessInitV1:
    frame = decode_frame(encoded)
    if frame.msg_type is not FrameType.ACCESS_INIT:
        raise ProtocolEncodingError("expected AccessInitV1 frame")
    if len(frame.body) < ACCESS_INIT_PREFIX.size:
        raise ProtocolEncodingError("truncated AccessInitV1 prefix")
    values = ACCESS_INIT_PREFIX.unpack_from(frame.body)
    profile = _suite(values[0], registry)
    ticket, offset = decode_opaque(
        frame.body,
        ACCESS_INIT_PREFIX.size,
        max_length=profile.max_ticket_bytes,
    )
    key_share, offset = decode_opaque(
        frame.body,
        offset,
        max_length=profile.max_key_share_bytes,
    )
    if offset != len(frame.body):
        raise ProtocolEncodingError("trailing AccessInitV1 fields")
    return AccessInitV1(*values, ticket, key_share)


def encode_access_challenge(
    message: AccessChallengeV1,
    registry: Mapping[int, SuiteLimits] = REFERENCE_SUITE_REGISTRY,
) -> bytes:
    if not isinstance(message, AccessChallengeV1):
        raise TypeError("message must be AccessChallengeV1")
    profile = _suite(message.suite_id, registry)
    body = ACCESS_CHALLENGE_PREFIX.pack(
        message.suite_id,
        message.ctx,
        message.serving_context_digest,
        message.ue_nonce,
        message.fgs_nonce,
        message.attempt_nonce,
        message.challenge_expiry,
    )
    body += encode_opaque(
        message.fgs_key_share,
        max_length=profile.max_key_share_bytes,
    )
    body += encode_opaque(
        message.challenge_cookie,
        max_length=profile.max_cookie_bytes,
    )
    return encode_frame(FrameType.ACCESS_CHALLENGE, body)


def decode_access_challenge(
    encoded: bytes,
    registry: Mapping[int, SuiteLimits] = REFERENCE_SUITE_REGISTRY,
) -> AccessChallengeV1:
    frame = decode_frame(encoded)
    if frame.msg_type is not FrameType.ACCESS_CHALLENGE:
        raise ProtocolEncodingError("expected AccessChallengeV1 frame")
    if len(frame.body) < ACCESS_CHALLENGE_PREFIX.size:
        raise ProtocolEncodingError("truncated AccessChallengeV1 prefix")
    values = ACCESS_CHALLENGE_PREFIX.unpack_from(frame.body)
    profile = _suite(values[0], registry)
    key_share, offset = decode_opaque(
        frame.body,
        ACCESS_CHALLENGE_PREFIX.size,
        max_length=profile.max_key_share_bytes,
    )
    cookie, offset = decode_opaque(
        frame.body,
        offset,
        max_length=profile.max_cookie_bytes,
    )
    if offset != len(frame.body):
        raise ProtocolEncodingError("trailing AccessChallengeV1 fields")
    return AccessChallengeV1(*values, key_share, cookie)


def encode_access_finish_core(
    message: AccessFinishV1,
    registry: Mapping[int, SuiteLimits] = REFERENCE_SUITE_REGISTRY,
) -> bytes:
    """Encode the canonical finish fields preceding both authenticators."""

    if not isinstance(message, AccessFinishV1):
        raise TypeError("message must be AccessFinishV1")
    profile = _suite(message.suite_id, registry)
    return ACCESS_FINISH_PREFIX.pack(
        message.suite_id,
        message.ctx,
        message.serving_context_digest,
        message.ue_nonce,
        message.fgs_nonce,
        message.attempt_nonce,
    ) + encode_opaque(
        message.challenge_cookie,
        max_length=profile.max_cookie_bytes,
    )


def encode_access_finish(
    message: AccessFinishV1,
    registry: Mapping[int, SuiteLimits] = REFERENCE_SUITE_REGISTRY,
) -> bytes:
    if not isinstance(message, AccessFinishV1):
        raise TypeError("message must be AccessFinishV1")
    profile = _suite(message.suite_id, registry)
    body = encode_access_finish_core(message, registry)
    body += encode_opaque(
        message.holder_authenticator,
        max_length=profile.max_holder_authenticator_bytes,
    )
    body += encode_opaque(
        message.ue_key_confirmation,
        max_length=profile.max_key_confirmation_bytes,
    )
    return encode_frame(FrameType.ACCESS_FINISH, body)


def decode_access_finish(
    encoded: bytes,
    registry: Mapping[int, SuiteLimits] = REFERENCE_SUITE_REGISTRY,
) -> AccessFinishV1:
    frame = decode_frame(encoded)
    if frame.msg_type is not FrameType.ACCESS_FINISH:
        raise ProtocolEncodingError("expected AccessFinishV1 frame")
    if len(frame.body) < ACCESS_FINISH_PREFIX.size:
        raise ProtocolEncodingError("truncated AccessFinishV1 prefix")
    values = ACCESS_FINISH_PREFIX.unpack_from(frame.body)
    profile = _suite(values[0], registry)
    cookie, offset = decode_opaque(
        frame.body,
        ACCESS_FINISH_PREFIX.size,
        max_length=profile.max_cookie_bytes,
    )
    holder_auth, offset = decode_opaque(
        frame.body,
        offset,
        max_length=profile.max_holder_authenticator_bytes,
    )
    key_confirmation, offset = decode_opaque(
        frame.body,
        offset,
        max_length=profile.max_key_confirmation_bytes,
    )
    if offset != len(frame.body):
        raise ProtocolEncodingError("trailing AccessFinishV1 fields")
    return AccessFinishV1(*values, cookie, holder_auth, key_confirmation)


def encode_access_accept(
    message: AccessAcceptV1,
    registry: Mapping[int, SuiteLimits] = REFERENCE_SUITE_REGISTRY,
) -> bytes:
    if not isinstance(message, AccessAcceptV1):
        raise TypeError("message must be AccessAcceptV1")
    profile = _suite(message.suite_id, registry)
    body = ACCESS_ACCEPT_PREFIX.pack(
        message.suite_id,
        message.attempt_id,
        message.session_id,
        message.serving_context_digest,
        message.session_expiry,
    )
    body += encode_opaque(
        message.fgs_key_confirmation,
        max_length=profile.max_key_confirmation_bytes,
    )
    return encode_frame(FrameType.ACCESS_ACCEPT, body)


def decode_access_accept(
    encoded: bytes,
    registry: Mapping[int, SuiteLimits] = REFERENCE_SUITE_REGISTRY,
) -> AccessAcceptV1:
    frame = decode_frame(encoded)
    if frame.msg_type is not FrameType.ACCESS_ACCEPT:
        raise ProtocolEncodingError("expected AccessAcceptV1 frame")
    if len(frame.body) < ACCESS_ACCEPT_PREFIX.size:
        raise ProtocolEncodingError("truncated AccessAcceptV1 prefix")
    values = ACCESS_ACCEPT_PREFIX.unpack_from(frame.body)
    profile = _suite(values[0], registry)
    key_confirmation, offset = decode_opaque(
        frame.body,
        ACCESS_ACCEPT_PREFIX.size,
        max_length=profile.max_key_confirmation_bytes,
    )
    if offset != len(frame.body):
        raise ProtocolEncodingError("trailing AccessAcceptV1 fields")
    return AccessAcceptV1(*values, key_confirmation)


def access_init_digest(message: AccessInitV1) -> bytes:
    return _shake(ACCESS_INIT_LABEL, encode_access_init(message))


def access_challenge_digest(message: AccessChallengeV1) -> bytes:
    return _shake(ACCESS_CHALLENGE_LABEL, encode_access_challenge(message))


def _require_flow_bindings(
    init: AccessInitV1,
    challenge: AccessChallengeV1,
    finish: AccessFinishV1,
) -> None:
    if not isinstance(init, AccessInitV1):
        raise TypeError("init must be AccessInitV1")
    if not isinstance(challenge, AccessChallengeV1):
        raise TypeError("challenge must be AccessChallengeV1")
    if not isinstance(finish, AccessFinishV1):
        raise TypeError("finish must be AccessFinishV1")
    shared_names = (
        "suite_id",
        "ctx",
        "serving_context_digest",
        "ue_nonce",
        "attempt_nonce",
    )
    for name in shared_names:
        value = getattr(init, name)
        if getattr(challenge, name) != value or getattr(finish, name) != value:
            raise ProtocolBindingError(f"inconsistent access-flow {name}")
    if finish.fgs_nonce != challenge.fgs_nonce:
        raise ProtocolBindingError("inconsistent access-flow fgs_nonce")
    if finish.challenge_cookie != challenge.challenge_cookie:
        raise ProtocolBindingError("inconsistent access-flow challenge_cookie")


def access_transcript_digest(
    init: AccessInitV1,
    challenge: AccessChallengeV1,
    finish: AccessFinishV1,
) -> bytes:
    _require_flow_bindings(init, challenge, finish)
    return _shake(
        ACCESS_TRANSCRIPT_LABEL,
        access_init_digest(init),
        access_challenge_digest(challenge),
        encode_access_finish_core(finish),
    )


def derive_attempt_id(
    ticket_digest: bytes,
    serving_context_digest: bytes,
    ue_nonce: bytes,
    fgs_nonce: bytes,
    attempt_nonce: bytes,
    transcript_digest: bytes,
) -> bytes:
    return _shake(
        ACCESS_ATTEMPT_LABEL,
        _fixed_bytes(ticket_digest, DIGEST_BYTES, "ticket_digest"),
        _fixed_bytes(
            serving_context_digest,
            DIGEST_BYTES,
            "serving_context_digest",
        ),
        _fixed_bytes(ue_nonce, NONCE_BYTES, "ue_nonce"),
        _fixed_bytes(fgs_nonce, NONCE_BYTES, "fgs_nonce"),
        _fixed_bytes(attempt_nonce, ATTEMPT_NONCE_BYTES, "attempt_nonce"),
        _fixed_bytes(transcript_digest, DIGEST_BYTES, "transcript_digest"),
    )


def access_accept_digest(message: AccessAcceptV1) -> bytes:
    return _shake(ACCESS_ACCEPT_LABEL, encode_access_accept(message))
