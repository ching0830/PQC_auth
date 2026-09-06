"""Canonical conditional-opening request for system profile v0.1."""

from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import dataclass

from pq_rbbc.contracts.system import (
    CONTEXT_BYTES,
    KEY_ID_BYTES,
    SYSTEM_PROFILE_PROTOCOL_VERSION,
)


OPENING_REQUEST_MAGIC = b"PQRBBC-CONDITIONAL-OPENING-REQUEST-V1"
OPENING_AUTHORIZATION_STATEMENT_MAGIC = b"PQRBBC-OPENING-AUTHORIZATION-STMT-V1"
OPENING_AUTHORIZATION_DOMAIN = b"PQ-RBBC/OPENING-AUTHORIZATION/V1"
OPENING_REQUEST_DIGEST_DOMAIN = b"PQ-RBBC/OPENING-REQUEST-DIGEST/V1"
OPENING_REPLAY_DOMAIN = b"PQ-RBBC/OPENING-REPLAY/V1"
OPENING_SCHEMA_VERSION = 1
DIGEST_BYTES = 32
CASE_ID_BYTES = 32
NONCE_BYTES = 32
MAX_TICKET_BYTES = 1 << 19
MAX_AUTHORIZATION_BYTES = 1 << 16
MAX_PURPOSE_BYTES = 256
MAX_REQUEST_BYTES = 1 << 20


class OpeningCodecError(ValueError):
    """Raised for a non-canonical or invalid opening encoding."""


def _require_uint(value: int, width: int, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise OpeningCodecError(f"{label} must be an integer")
    if not 0 <= value < (1 << (8 * width)):
        raise OpeningCodecError(f"{label} is outside u{8 * width}")


def _require_fixed(
    value: bytes, length: int, label: str, *, nonzero: bool = True
) -> None:
    if not isinstance(value, bytes) or len(value) != length:
        raise OpeningCodecError(f"{label} must be exactly {length} bytes")
    if nonzero and value == bytes(length):
        raise OpeningCodecError(f"{label} must not be all zero")


def _encode_fields(fields: tuple[tuple[int, bytes], ...]) -> bytes:
    result = bytearray()
    for tag, value in fields:
        result.extend(tag.to_bytes(1, "little"))
        result.extend(len(value).to_bytes(4, "little"))
        result.extend(value)
    return bytes(result)


def _take(encoded: bytes, offset: int, length: int, label: str) -> tuple[bytes, int]:
    if length < 0 or offset + length > len(encoded):
        raise OpeningCodecError(f"{label} truncated")
    return encoded[offset : offset + length], offset + length


def _decode_fields(
    encoded: bytes,
    offset: int,
    specifications: tuple[tuple[int, str, int, int], ...],
) -> tuple[dict[str, bytes], int]:
    values: dict[str, bytes] = {}
    seen: set[int] = set()
    known_tags = {tag for tag, _name, _minimum, _maximum in specifications}
    for expected_tag, name, minimum, maximum in specifications:
        raw_tag, offset = _take(encoded, offset, 1, f"{name} tag")
        tag = raw_tag[0]
        if tag != expected_tag:
            if tag in seen:
                raise OpeningCodecError(f"duplicate field tag {tag}")
            if tag in known_tags:
                raise OpeningCodecError("fields are out of canonical order")
            raise OpeningCodecError(f"unknown field tag {tag}")
        seen.add(tag)
        raw_length, offset = _take(encoded, offset, 4, f"{name} length")
        length = int.from_bytes(raw_length, "little")
        if not minimum <= length <= maximum:
            raise OpeningCodecError(f"{name} length is outside bounds")
        value, offset = _take(encoded, offset, length, name)
        values[name] = value
    return values, offset


def canonical_ticket_digest(ticket: bytes) -> bytes:
    if not isinstance(ticket, bytes) or not 0 < len(ticket) <= MAX_TICKET_BYTES:
        raise OpeningCodecError("ticket length is outside bounds")
    return hashlib.sha256(ticket).digest()


_REQUEST_FIELDS = (
    (1, "protocol_version", 2, 2),
    (2, "ticket", 1, MAX_TICKET_BYTES),
    (3, "ctx", CONTEXT_BYTES, CONTEXT_BYTES),
    (4, "epoch", 8, 8),
    (5, "opening_key_id", KEY_ID_BYTES, KEY_ID_BYTES),
    (6, "authorization_key_id", KEY_ID_BYTES, KEY_ID_BYTES),
    (7, "case_id", CASE_ID_BYTES, CASE_ID_BYTES),
    (8, "evidence_digest", DIGEST_BYTES, DIGEST_BYTES),
    (9, "purpose", 1, MAX_PURPOSE_BYTES),
    (10, "expiry", 8, 8),
    (11, "request_nonce", NONCE_BYTES, NONCE_BYTES),
    (12, "authorization", 1, MAX_AUTHORIZATION_BYTES),
)


@dataclass(frozen=True)
class OpeningRequest:
    """A signed, canonical request; the ticket itself remains opaque here."""

    protocol_version: int
    ticket: bytes
    ctx: bytes
    epoch: int
    opening_key_id: bytes
    authorization_key_id: bytes
    case_id: bytes
    evidence_digest: bytes
    purpose: str
    expiry: int
    request_nonce: bytes
    authorization: bytes

    def validate(self) -> None:
        _require_uint(self.protocol_version, 2, "protocol_version")
        if self.protocol_version != SYSTEM_PROFILE_PROTOCOL_VERSION:
            raise OpeningCodecError("unknown opening protocol version")
        canonical_ticket_digest(self.ticket)
        _require_fixed(self.ctx, CONTEXT_BYTES, "ctx", nonzero=False)
        _require_uint(self.epoch, 8, "epoch")
        _require_fixed(self.opening_key_id, KEY_ID_BYTES, "opening_key_id")
        _require_fixed(
            self.authorization_key_id, KEY_ID_BYTES, "authorization_key_id"
        )
        _require_fixed(self.case_id, CASE_ID_BYTES, "case_id")
        _require_fixed(self.evidence_digest, DIGEST_BYTES, "evidence_digest")
        if not isinstance(self.purpose, str):
            raise OpeningCodecError("purpose must be text")
        if unicodedata.normalize("NFC", self.purpose) != self.purpose:
            raise OpeningCodecError("purpose must use Unicode NFC")
        try:
            purpose_bytes = self.purpose.encode("utf-8", "strict")
        except UnicodeError as error:
            raise OpeningCodecError("purpose is not valid UTF-8") from error
        if not 0 < len(purpose_bytes) <= MAX_PURPOSE_BYTES:
            raise OpeningCodecError("purpose length is outside bounds")
        if any(
            ord(character) < 0x20 or ord(character) == 0x7F
            for character in self.purpose
        ):
            raise OpeningCodecError("purpose contains a control character")
        _require_uint(self.expiry, 8, "expiry")
        _require_fixed(self.request_nonce, NONCE_BYTES, "request_nonce")
        if not isinstance(self.authorization, bytes) or not (
            0 < len(self.authorization) <= MAX_AUTHORIZATION_BYTES
        ):
            raise OpeningCodecError("authorization length is outside bounds")

    @property
    def ticket_digest(self) -> bytes:
        return canonical_ticket_digest(self.ticket)

    def _fields(self) -> tuple[tuple[int, bytes], ...]:
        return (
            (1, self.protocol_version.to_bytes(2, "little")),
            (2, self.ticket),
            (3, self.ctx),
            (4, self.epoch.to_bytes(8, "little")),
            (5, self.opening_key_id),
            (6, self.authorization_key_id),
            (7, self.case_id),
            (8, self.evidence_digest),
            (9, self.purpose.encode("utf-8")),
            (10, self.expiry.to_bytes(8, "little")),
            (11, self.request_nonce),
            (12, self.authorization),
        )

    def encode(self) -> bytes:
        self.validate()
        encoded = b"".join(
            (
                OPENING_REQUEST_MAGIC,
                OPENING_SCHEMA_VERSION.to_bytes(2, "little"),
                len(_REQUEST_FIELDS).to_bytes(2, "little"),
                _encode_fields(self._fields()),
            )
        )
        if len(encoded) > MAX_REQUEST_BYTES:
            raise OpeningCodecError("opening request is oversized")
        return encoded

    @classmethod
    def decode(cls, encoded: bytes) -> "OpeningRequest":
        if not isinstance(encoded, bytes):
            raise OpeningCodecError("opening request encoding must be bytes")
        if len(encoded) > MAX_REQUEST_BYTES:
            raise OpeningCodecError("opening request is oversized")
        offset = 0
        magic, offset = _take(
            encoded, offset, len(OPENING_REQUEST_MAGIC), "opening request magic"
        )
        if magic != OPENING_REQUEST_MAGIC:
            raise OpeningCodecError("wrong opening request magic")
        raw_schema, offset = _take(encoded, offset, 2, "opening schema version")
        if int.from_bytes(raw_schema, "little") != OPENING_SCHEMA_VERSION:
            raise OpeningCodecError("unknown opening schema version")
        raw_count, offset = _take(encoded, offset, 2, "opening field count")
        if int.from_bytes(raw_count, "little") != len(_REQUEST_FIELDS):
            raise OpeningCodecError("wrong opening field count")
        values, offset = _decode_fields(encoded, offset, _REQUEST_FIELDS)
        if offset != len(encoded):
            raise OpeningCodecError("opening request trailing bytes")
        try:
            purpose = values["purpose"].decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            raise OpeningCodecError("purpose is not valid UTF-8") from error
        request = cls(
            protocol_version=int.from_bytes(values["protocol_version"], "little"),
            ticket=values["ticket"],
            ctx=values["ctx"],
            epoch=int.from_bytes(values["epoch"], "little"),
            opening_key_id=values["opening_key_id"],
            authorization_key_id=values["authorization_key_id"],
            case_id=values["case_id"],
            evidence_digest=values["evidence_digest"],
            purpose=purpose,
            expiry=int.from_bytes(values["expiry"], "little"),
            request_nonce=values["request_nonce"],
            authorization=values["authorization"],
        )
        request.validate()
        if request.encode() != encoded:
            raise OpeningCodecError("opening request is non-canonical")
        return request

    @property
    def authorization_statement(self) -> bytes:
        """Canonical statement authenticated by the opening-authorization key."""

        self.validate()
        fields = (
            (1, self.protocol_version.to_bytes(2, "little")),
            (2, self.ticket_digest),
            (3, self.ctx),
            (4, self.epoch.to_bytes(8, "little")),
            (5, self.opening_key_id),
            (6, self.authorization_key_id),
            (7, self.case_id),
            (8, self.evidence_digest),
            (9, self.purpose.encode("utf-8")),
            (10, self.expiry.to_bytes(8, "little")),
            (11, self.request_nonce),
        )
        return b"".join(
            (
                OPENING_AUTHORIZATION_STATEMENT_MAGIC,
                OPENING_SCHEMA_VERSION.to_bytes(2, "little"),
                len(fields).to_bytes(2, "little"),
                _encode_fields(fields),
            )
        )

    @property
    def authorization_message(self) -> bytes:
        return OPENING_AUTHORIZATION_DOMAIN + self.authorization_statement

    @property
    def request_digest(self) -> bytes:
        return hashlib.sha256(OPENING_REQUEST_DIGEST_DOMAIN + self.encode()).digest()

    @property
    def replay_key(self) -> bytes:
        # This remains stable across any signature re-encoding or malleability.
        return hashlib.sha256(
            OPENING_REPLAY_DOMAIN
            + self.authorization_key_id
            + self.case_id
            + self.request_nonce
        ).digest()
