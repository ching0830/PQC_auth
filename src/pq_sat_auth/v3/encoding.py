"""Frozen canonical encoding primitives for the PQ-SAT V3 measurement ABI.

This module owns only bytes and configuration validation.  The private-use
suite identifiers are deliberately rejected by production-gated callers in
``ticket_verification`` unless the caller explicitly opts into Category A.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from enum import IntEnum


FRAME_MAGIC = b"PQSAT-V3"
FRAME_VERSION = 3
FRAME_HEADER = struct.Struct(">8sHHI")
FRAME_HEADER_BYTES = FRAME_HEADER.size
OPAQUE_LENGTH = struct.Struct(">I")

TICKET_SUITE_BOUNDED_TEST_ONLY = 0xFF30
ACCESS_SUITE_MEASUREMENT = 0xFF31

CONTEXT_BYTES = 32
DIGEST_BYTES = 32
MAX_FRAME_BODY_BYTES = 1_048_576
MAX_OPAQUE_BYTES = 1_048_576
MAX_COMPONENT_BYTES = 262_144

CONFIGURATION_BODY = struct.Struct(">QQQHH32s32s32s32s32s32sIIIIIIIII")
CONFIGURATION_BODY_BYTES = CONFIGURATION_BODY.size
CONFIGURATION_BYTES = FRAME_HEADER_BYTES + CONFIGURATION_BODY_BYTES

CONFIGURATION_HASH_DOMAIN = b"PQSAT/CFG/v3"
HASH_V3_DOMAIN = b"PQSAT/HASH/v3"


class EncodingError(ValueError):
    """Raised for malformed, alternate, truncated, or extended V3 bytes."""


class FrameTypeV3(IntEnum):
    PUBLIC_CONFIGURATION = 0x0300
    TICKET = 0x0301
    ACCESS_REQUEST = 0x0310
    ACCESS_ACCEPT = 0x0311
    SESSION_ACTIVATE = 0x0312


@dataclass(frozen=True, slots=True)
class FrameV3:
    msg_type: FrameTypeV3
    body: bytes
    version: int = FRAME_VERSION


def require_bytes(value: bytes, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    return value


def require_fixed(value: bytes, length: int, name: str) -> bytes:
    raw = require_bytes(value, name)
    if len(raw) != length:
        raise ValueError(f"{name} must be exactly {length} bytes")
    return raw


def require_uint(value: int, bits: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value < (1 << bits):
        raise ValueError(f"{name} does not fit uint{bits}")
    return value


def take(raw: bytes, offset: int, length: int, name: str) -> tuple[bytes, int]:
    if offset < 0 or length < 0 or offset + length > len(raw):
        raise EncodingError(f"truncated {name}")
    return raw[offset : offset + length], offset + length


def encode_frame_v3(msg_type: FrameTypeV3, body: bytes) -> bytes:
    if not isinstance(msg_type, FrameTypeV3):
        raise TypeError("msg_type must be a FrameTypeV3")
    raw = require_bytes(body, "frame body")
    if len(raw) > MAX_FRAME_BODY_BYTES:
        raise ValueError("frame body exceeds V3 implementation bound")
    return FRAME_HEADER.pack(FRAME_MAGIC, FRAME_VERSION, int(msg_type), len(raw)) + raw


def decode_frame_v3(
    encoded: bytes,
    *,
    expected_type: FrameTypeV3 | None = None,
    max_body_bytes: int = MAX_FRAME_BODY_BYTES,
) -> FrameV3:
    raw = require_bytes(encoded, "encoded frame")
    maximum = require_uint(max_body_bytes, 32, "max_body_bytes")
    if len(raw) < FRAME_HEADER_BYTES:
        raise EncodingError("truncated frame header")
    magic, version, raw_type, body_length = FRAME_HEADER.unpack_from(raw)
    if magic != FRAME_MAGIC:
        raise EncodingError("frame magic mismatch")
    if version != FRAME_VERSION:
        raise EncodingError("unsupported frame version")
    try:
        msg_type = FrameTypeV3(raw_type)
    except ValueError as error:
        raise EncodingError("unknown frame type") from error
    if expected_type is not None and msg_type is not expected_type:
        raise EncodingError("unexpected frame type")
    if body_length > maximum:
        raise EncodingError("frame body exceeds configured maximum")
    if len(raw) != FRAME_HEADER_BYTES + body_length:
        raise EncodingError("frame length mismatch or trailing bytes")
    return FrameV3(msg_type=msg_type, body=raw[FRAME_HEADER_BYTES:])


def encode_opaque32(
    value: bytes,
    *,
    max_length: int = MAX_OPAQUE_BYTES,
    allow_empty: bool = False,
) -> bytes:
    raw = require_bytes(value, "opaque value")
    maximum = require_uint(max_length, 32, "max_length")
    if not allow_empty and not raw:
        raise ValueError("opaque value must not be empty")
    if len(raw) > maximum:
        raise ValueError("opaque value exceeds configured maximum")
    return OPAQUE_LENGTH.pack(len(raw)) + raw


def decode_opaque32(
    encoded: bytes,
    offset: int = 0,
    *,
    max_length: int = MAX_OPAQUE_BYTES,
    exact_length: int | None = None,
    allow_empty: bool = False,
    name: str = "opaque value",
) -> tuple[bytes, int]:
    raw = require_bytes(encoded, "encoded opaque fields")
    maximum = require_uint(max_length, 32, "max_length")
    if offset < 0 or offset > len(raw):
        raise EncodingError(f"invalid {name} offset")
    length_bytes, next_offset = take(raw, offset, OPAQUE_LENGTH.size, f"{name} length")
    (length,) = OPAQUE_LENGTH.unpack(length_bytes)
    if not allow_empty and length == 0:
        raise EncodingError(f"{name} must not be empty")
    if length > maximum:
        raise EncodingError(f"{name} exceeds configured maximum")
    if exact_length is not None and length != exact_length:
        raise EncodingError(f"{name} has wrong exact length")
    return take(raw, next_offset, length, name)


def hash_v3(label: bytes, ctx: bytes, value: bytes, out_len: int) -> bytes:
    label_bytes = require_bytes(label, "hash label")
    context = require_fixed(ctx, CONTEXT_BYTES, "ctx")
    payload = require_bytes(value, "hash input")
    length = require_uint(out_len, 32, "out_len")
    if not label_bytes or len(label_bytes) > 0xFFFF:
        raise ValueError("hash label length is outside u16 bounds")
    if not label_bytes.isascii():
        raise ValueError("hash label must be ASCII")
    if length == 0 or length > MAX_COMPONENT_BYTES:
        raise ValueError("hash output length is outside implementation bounds")
    return hashlib.shake_256(
        HASH_V3_DOMAIN
        + len(label_bytes).to_bytes(2, "big")
        + label_bytes
        + context
        + len(payload).to_bytes(8, "big")
        + payload
    ).digest(length)


@dataclass(frozen=True, slots=True)
class PublicConfigurationV3:
    configuration_generation: int
    valid_from: int
    valid_until: int
    ticket_suite_id: int
    access_suite_id: int
    issuer_registry_digest: bytes
    fgs_registry_digest: bytes
    trace_parameter_digest: bytes
    cap_parameter_digest: bytes
    issuance_relation_digest: bytes
    access_policy_digest: bytes
    request_past_slack: int
    request_future_slack: int
    activation_timeout: int
    retention_grace: int
    maximum_ticket_bytes: int
    maximum_s_bytes: int
    maximum_c_r_bytes: int
    maximum_c_z_bytes: int
    maximum_pi_2_bytes: int

    def validate(self) -> None:
        for name in ("configuration_generation", "valid_from", "valid_until"):
            require_uint(getattr(self, name), 64, name)
        if self.valid_from > self.valid_until:
            raise ValueError("configuration validity interval is inverted")
        require_uint(self.ticket_suite_id, 16, "ticket_suite_id")
        require_uint(self.access_suite_id, 16, "access_suite_id")
        if self.ticket_suite_id != TICKET_SUITE_BOUNDED_TEST_ONLY:
            raise ValueError("unsupported V3 ticket suite")
        if self.access_suite_id != ACCESS_SUITE_MEASUREMENT:
            raise ValueError("unsupported V3 access suite")
        for name in (
            "issuer_registry_digest",
            "fgs_registry_digest",
            "trace_parameter_digest",
            "cap_parameter_digest",
            "issuance_relation_digest",
            "access_policy_digest",
        ):
            require_fixed(getattr(self, name), DIGEST_BYTES, name)
        for name in (
            "request_past_slack",
            "request_future_slack",
            "activation_timeout",
            "retention_grace",
            "maximum_ticket_bytes",
            "maximum_s_bytes",
            "maximum_c_r_bytes",
            "maximum_c_z_bytes",
            "maximum_pi_2_bytes",
        ):
            value = require_uint(getattr(self, name), 32, name)
            if value == 0:
                raise ValueError(f"{name} must be nonzero")
        if self.maximum_ticket_bytes > MAX_FRAME_BODY_BYTES:
            raise ValueError("maximum_ticket_bytes exceeds implementation bound")
        for name in (
            "maximum_s_bytes",
            "maximum_c_r_bytes",
            "maximum_c_z_bytes",
            "maximum_pi_2_bytes",
        ):
            if getattr(self, name) > MAX_COMPONENT_BYTES:
                raise ValueError(f"{name} exceeds implementation bound")

    def body_bytes(self) -> bytes:
        self.validate()
        return CONFIGURATION_BODY.pack(
            self.configuration_generation,
            self.valid_from,
            self.valid_until,
            self.ticket_suite_id,
            self.access_suite_id,
            self.issuer_registry_digest,
            self.fgs_registry_digest,
            self.trace_parameter_digest,
            self.cap_parameter_digest,
            self.issuance_relation_digest,
            self.access_policy_digest,
            self.request_past_slack,
            self.request_future_slack,
            self.activation_timeout,
            self.retention_grace,
            self.maximum_ticket_bytes,
            self.maximum_s_bytes,
            self.maximum_c_r_bytes,
            self.maximum_c_z_bytes,
            self.maximum_pi_2_bytes,
        )

    def encode(self) -> bytes:
        return encode_frame_v3(FrameTypeV3.PUBLIC_CONFIGURATION, self.body_bytes())

    @property
    def ctx(self) -> bytes:
        encoded = self.encode()
        return hashlib.shake_256(
            CONFIGURATION_HASH_DOMAIN
            + len(encoded).to_bytes(8, "big")
            + encoded
        ).digest(CONTEXT_BYTES)

    @classmethod
    def decode(cls, encoded: bytes) -> "PublicConfigurationV3":
        frame = decode_frame_v3(
            encoded,
            expected_type=FrameTypeV3.PUBLIC_CONFIGURATION,
            max_body_bytes=CONFIGURATION_BODY_BYTES,
        )
        if len(frame.body) != CONFIGURATION_BODY_BYTES:
            raise EncodingError("public configuration body length mismatch")
        configuration = cls(*CONFIGURATION_BODY.unpack(frame.body))
        try:
            configuration.validate()
        except (TypeError, ValueError) as error:
            raise EncodingError(str(error)) from error
        if configuration.encode() != encoded:
            raise EncodingError("non-canonical public configuration")
        return configuration


__all__ = [
    "ACCESS_SUITE_MEASUREMENT",
    "CONFIGURATION_BODY_BYTES",
    "CONFIGURATION_BYTES",
    "CONTEXT_BYTES",
    "DIGEST_BYTES",
    "EncodingError",
    "FRAME_HEADER_BYTES",
    "FRAME_MAGIC",
    "FRAME_VERSION",
    "FrameTypeV3",
    "FrameV3",
    "MAX_COMPONENT_BYTES",
    "MAX_FRAME_BODY_BYTES",
    "MAX_OPAQUE_BYTES",
    "PublicConfigurationV3",
    "TICKET_SUITE_BOUNDED_TEST_ONLY",
    "decode_frame_v3",
    "decode_opaque32",
    "encode_frame_v3",
    "encode_opaque32",
    "hash_v3",
    "require_bytes",
    "require_fixed",
    "require_uint",
    "take",
]
