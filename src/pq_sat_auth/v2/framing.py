"""Canonical framing for the satellite access protocol v0.2."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum


FRAME_MAGIC = b"PQSAT-A2"
FRAME_VERSION = 2
FRAME_HEADER = struct.Struct(">8sHHI")
FRAME_HEADER_BYTES = FRAME_HEADER.size
MAX_FRAME_BODY_BYTES = 1_048_576
MAX_OPAQUE_BYTES = 1_048_576
OPAQUE_LENGTH = struct.Struct(">I")


class ProtocolEncodingError(ValueError):
    """Raised when a v0.2 protocol object is malformed or non-canonical."""


class FrameTypeV2(IntEnum):
    ACCESS_REQUEST = 0x0101
    ACCESS_ACCEPT = 0x0102
    SESSION_ACTIVATE = 0x0103
    FIRST_APPLICATION_RECORD = 0x0104


@dataclass(frozen=True)
class FrameV2:
    """A decoded, canonical v0.2 frame."""

    msg_type: FrameTypeV2
    body: bytes
    version: int = FRAME_VERSION


def require_uint(value: int, bits: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value < (1 << bits):
        raise ValueError(f"{name} does not fit uint{bits}")
    return value


def require_bytes(value: bytes, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    return value


def encode_frame_v2(msg_type: FrameTypeV2, body: bytes) -> bytes:
    """Encode one canonical FrameV2."""

    if not isinstance(msg_type, FrameTypeV2):
        raise TypeError("msg_type must be a FrameTypeV2")
    encoded_body = require_bytes(body, "body")
    if len(encoded_body) > MAX_FRAME_BODY_BYTES:
        raise ValueError("frame body exceeds v0.2 maximum")
    return FRAME_HEADER.pack(
        FRAME_MAGIC,
        FRAME_VERSION,
        int(msg_type),
        len(encoded_body),
    ) + encoded_body


def decode_frame_v2(
    encoded: bytes,
    *,
    max_body_bytes: int = MAX_FRAME_BODY_BYTES,
) -> FrameV2:
    """Decode FrameV2 and reject unknown, alternate, or trailing encodings."""

    raw = require_bytes(encoded, "encoded frame")
    maximum = require_uint(max_body_bytes, 32, "max_body_bytes")
    if len(raw) < FRAME_HEADER_BYTES:
        raise ProtocolEncodingError("truncated frame header")
    magic, version, raw_type, body_len = FRAME_HEADER.unpack_from(raw)
    if magic != FRAME_MAGIC:
        raise ProtocolEncodingError("frame magic mismatch")
    if version != FRAME_VERSION:
        raise ProtocolEncodingError("unsupported frame version")
    try:
        msg_type = FrameTypeV2(raw_type)
    except ValueError as exc:
        raise ProtocolEncodingError("unknown frame type") from exc
    if body_len > maximum:
        raise ProtocolEncodingError("frame body exceeds configured maximum")
    expected_len = FRAME_HEADER_BYTES + body_len
    if len(raw) != expected_len:
        raise ProtocolEncodingError("frame length mismatch or trailing bytes")
    return FrameV2(msg_type=msg_type, body=raw[FRAME_HEADER_BYTES:])


def encode_opaque_v2(
    value: bytes,
    *,
    max_length: int = MAX_OPAQUE_BYTES,
) -> bytes:
    """Encode a length-prefixed primitive-dependent field."""

    raw = require_bytes(value, "opaque value")
    maximum = require_uint(max_length, 32, "max_length")
    if len(raw) > maximum:
        raise ValueError("opaque value exceeds configured maximum")
    return OPAQUE_LENGTH.pack(len(raw)) + raw


def decode_opaque_v2(
    encoded: bytes,
    offset: int = 0,
    *,
    max_length: int = MAX_OPAQUE_BYTES,
) -> tuple[bytes, int]:
    """Decode one opaque value and return ``(value, next_offset)``."""

    raw = require_bytes(encoded, "encoded opaque field")
    start = require_uint(offset, 32, "offset")
    maximum = require_uint(max_length, 32, "max_length")
    if start > len(raw) or len(raw) - start < OPAQUE_LENGTH.size:
        raise ProtocolEncodingError("truncated opaque length")
    (length,) = OPAQUE_LENGTH.unpack_from(raw, start)
    if length > maximum:
        raise ProtocolEncodingError("opaque value exceeds configured maximum")
    value_start = start + OPAQUE_LENGTH.size
    value_end = value_start + length
    if value_end > len(raw):
        raise ProtocolEncodingError("truncated opaque value")
    return raw[value_start:value_end], value_end
