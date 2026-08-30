"""Canonical framing for the draft PQ satellite access protocol v0.1."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum


FRAME_MAGIC = b"PQSAT-A1"
FRAME_VERSION = 1
FRAME_HEADER = struct.Struct(">8sHHI")
FRAME_HEADER_BYTES = FRAME_HEADER.size
MAX_FRAME_BODY_BYTES = 1_048_576
MAX_OPAQUE_BYTES = 1_048_576
OPAQUE_LENGTH = struct.Struct(">I")


class ProtocolEncodingError(ValueError):
    """Raised when a protocol object is non-canonical or malformed."""


class FrameType(IntEnum):
    ACCESS_INIT = 0x0001
    ACCESS_CHALLENGE = 0x0002
    ACCESS_FINISH = 0x0003
    ACCESS_ACCEPT = 0x0004


@dataclass(frozen=True)
class FrameV1:
    """A decoded, canonical v0.1 frame."""

    msg_type: FrameType
    body: bytes
    version: int = FRAME_VERSION


def _require_uint(value: int, bits: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value < (1 << bits):
        raise ValueError(f"{name} does not fit uint{bits}")
    return value


def _require_bytes(value: bytes, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    return value


def encode_frame(msg_type: FrameType, body: bytes) -> bytes:
    """Encode one canonical FrameV1.

    Unknown integer message types are deliberately rejected.  A new type must
    first be represented in ``FrameType`` and, if semantics change, use a new
    protocol version.
    """

    if not isinstance(msg_type, FrameType):
        raise TypeError("msg_type must be a FrameType")
    encoded_body = _require_bytes(body, "body")
    if len(encoded_body) > MAX_FRAME_BODY_BYTES:
        raise ValueError("frame body exceeds v0.1 maximum")
    return FRAME_HEADER.pack(
        FRAME_MAGIC,
        FRAME_VERSION,
        int(msg_type),
        len(encoded_body),
    ) + encoded_body


def decode_frame(
    encoded: bytes,
    *,
    max_body_bytes: int = MAX_FRAME_BODY_BYTES,
) -> FrameV1:
    """Decode a FrameV1 and reject alternate or trailing encodings."""

    raw = _require_bytes(encoded, "encoded frame")
    maximum = _require_uint(max_body_bytes, 32, "max_body_bytes")
    if len(raw) < FRAME_HEADER_BYTES:
        raise ProtocolEncodingError("truncated frame header")
    magic, version, raw_type, body_len = FRAME_HEADER.unpack_from(raw)
    if magic != FRAME_MAGIC:
        raise ProtocolEncodingError("frame magic mismatch")
    if version != FRAME_VERSION:
        raise ProtocolEncodingError("unsupported frame version")
    try:
        msg_type = FrameType(raw_type)
    except ValueError as exc:
        raise ProtocolEncodingError("unknown frame type") from exc
    if body_len > maximum:
        raise ProtocolEncodingError("frame body exceeds configured maximum")
    expected_len = FRAME_HEADER_BYTES + body_len
    if len(raw) != expected_len:
        raise ProtocolEncodingError("frame length mismatch or trailing bytes")
    return FrameV1(msg_type=msg_type, body=raw[FRAME_HEADER_BYTES:])


def encode_opaque(
    value: bytes,
    *,
    max_length: int = MAX_OPAQUE_BYTES,
) -> bytes:
    """Encode a length-prefixed primitive-dependent field."""

    raw = _require_bytes(value, "opaque value")
    maximum = _require_uint(max_length, 32, "max_length")
    if len(raw) > maximum:
        raise ValueError("opaque value exceeds configured maximum")
    return OPAQUE_LENGTH.pack(len(raw)) + raw


def decode_opaque(
    encoded: bytes,
    offset: int = 0,
    *,
    max_length: int = MAX_OPAQUE_BYTES,
) -> tuple[bytes, int]:
    """Decode one opaque field and return ``(value, next_offset)``.

    The enclosing object parser remains responsible for requiring that its
    final offset equals the body length.
    """

    raw = _require_bytes(encoded, "encoded opaque field")
    start = _require_uint(offset, 32, "offset")
    maximum = _require_uint(max_length, 32, "max_length")
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
