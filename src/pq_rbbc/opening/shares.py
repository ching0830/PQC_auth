"""Canonical authenticated OpenShare transport encoding."""

from __future__ import annotations

from dataclasses import dataclass

from pq_rbbc.contracts.system import KEY_ID_BYTES, SYSTEM_PROFILE_PROTOCOL_VERSION
from pq_rbbc.opening.interfaces import (
    MAX_SHARE_AUTHENTICATION_BYTES,
    MAX_SHARE_VALUE_BYTES,
    MEMBER_ID_BYTES,
)
from pq_rbbc.opening.request import (
    CASE_ID_BYTES,
    DIGEST_BYTES,
    OPENING_SCHEMA_VERSION,
    OpeningCodecError,
    _decode_fields,
    _encode_fields,
    _require_fixed,
    _require_uint,
    _take,
)


OPEN_SHARE_MAGIC = b"PQRBBC-OPEN-SHARE-V1"
OPEN_SHARE_AUTHENTICATION_DOMAIN = b"PQ-RBBC/OPEN-SHARE-AUTHENTICATION/V1"
MAX_OPEN_SHARE_BYTES = (1 << 20) + (1 << 17)


_SHARE_FIELDS = (
    (1, "protocol_version", 2, 2),
    (2, "member_id", MEMBER_ID_BYTES, MEMBER_ID_BYTES),
    (3, "opening_key_id", KEY_ID_BYTES, KEY_ID_BYTES),
    (4, "epoch", 8, 8),
    (5, "request_digest", DIGEST_BYTES, DIGEST_BYTES),
    (6, "ticket_digest", DIGEST_BYTES, DIGEST_BYTES),
    (7, "case_id", CASE_ID_BYTES, CASE_ID_BYTES),
    (8, "share_value", 1, MAX_SHARE_VALUE_BYTES),
    (9, "authentication", 1, MAX_SHARE_AUTHENTICATION_BYTES),
)


def share_authentication_message(
    *,
    protocol_version: int,
    member_id: bytes,
    opening_key_id: bytes,
    epoch: int,
    request_digest: bytes,
    ticket_digest: bytes,
    case_id: bytes,
    share_value: bytes,
) -> bytes:
    fields = (
        (1, protocol_version.to_bytes(2, "little")),
        (2, member_id),
        (3, opening_key_id),
        (4, epoch.to_bytes(8, "little")),
        (5, request_digest),
        (6, ticket_digest),
        (7, case_id),
        (8, share_value),
    )
    return OPEN_SHARE_AUTHENTICATION_DOMAIN + _encode_fields(fields)


@dataclass(frozen=True)
class OpenShare:
    protocol_version: int
    member_id: bytes
    opening_key_id: bytes
    epoch: int
    request_digest: bytes
    ticket_digest: bytes
    case_id: bytes
    share_value: bytes
    authentication: bytes

    def validate(self) -> None:
        _require_uint(self.protocol_version, 2, "share protocol_version")
        if self.protocol_version != SYSTEM_PROFILE_PROTOCOL_VERSION:
            raise OpeningCodecError("unknown share protocol version")
        _require_fixed(self.member_id, MEMBER_ID_BYTES, "member_id")
        _require_fixed(self.opening_key_id, KEY_ID_BYTES, "opening_key_id")
        _require_uint(self.epoch, 8, "share epoch")
        _require_fixed(self.request_digest, DIGEST_BYTES, "request_digest")
        _require_fixed(self.ticket_digest, DIGEST_BYTES, "ticket_digest")
        _require_fixed(self.case_id, CASE_ID_BYTES, "case_id")
        if not isinstance(self.share_value, bytes) or not (
            0 < len(self.share_value) <= MAX_SHARE_VALUE_BYTES
        ):
            raise OpeningCodecError("share_value length is outside bounds")
        if not isinstance(self.authentication, bytes) or not (
            0 < len(self.authentication) <= MAX_SHARE_AUTHENTICATION_BYTES
        ):
            raise OpeningCodecError("share authentication length is outside bounds")

    def _fields(self) -> tuple[tuple[int, bytes], ...]:
        return (
            (1, self.protocol_version.to_bytes(2, "little")),
            (2, self.member_id),
            (3, self.opening_key_id),
            (4, self.epoch.to_bytes(8, "little")),
            (5, self.request_digest),
            (6, self.ticket_digest),
            (7, self.case_id),
            (8, self.share_value),
            (9, self.authentication),
        )

    def encode(self) -> bytes:
        self.validate()
        encoded = b"".join(
            (
                OPEN_SHARE_MAGIC,
                OPENING_SCHEMA_VERSION.to_bytes(2, "little"),
                len(_SHARE_FIELDS).to_bytes(2, "little"),
                _encode_fields(self._fields()),
            )
        )
        if len(encoded) > MAX_OPEN_SHARE_BYTES:
            raise OpeningCodecError("open share is oversized")
        return encoded

    @classmethod
    def decode(cls, encoded: bytes) -> "OpenShare":
        if not isinstance(encoded, bytes):
            raise OpeningCodecError("open share encoding must be bytes")
        if len(encoded) > MAX_OPEN_SHARE_BYTES:
            raise OpeningCodecError("open share is oversized")
        offset = 0
        magic, offset = _take(
            encoded, offset, len(OPEN_SHARE_MAGIC), "open share magic"
        )
        if magic != OPEN_SHARE_MAGIC:
            raise OpeningCodecError("wrong open share magic")
        raw_schema, offset = _take(encoded, offset, 2, "open share schema version")
        if int.from_bytes(raw_schema, "little") != OPENING_SCHEMA_VERSION:
            raise OpeningCodecError("unknown open share schema version")
        raw_count, offset = _take(encoded, offset, 2, "open share field count")
        if int.from_bytes(raw_count, "little") != len(_SHARE_FIELDS):
            raise OpeningCodecError("wrong open share field count")
        values, offset = _decode_fields(encoded, offset, _SHARE_FIELDS)
        if offset != len(encoded):
            raise OpeningCodecError("open share trailing bytes")
        share = cls(
            protocol_version=int.from_bytes(values["protocol_version"], "little"),
            member_id=values["member_id"],
            opening_key_id=values["opening_key_id"],
            epoch=int.from_bytes(values["epoch"], "little"),
            request_digest=values["request_digest"],
            ticket_digest=values["ticket_digest"],
            case_id=values["case_id"],
            share_value=values["share_value"],
            authentication=values["authentication"],
        )
        share.validate()
        if share.encode() != encoded:
            raise OpeningCodecError("open share is non-canonical")
        return share

    @property
    def authentication_message(self) -> bytes:
        self.validate()
        return share_authentication_message(
            protocol_version=self.protocol_version,
            member_id=self.member_id,
            opening_key_id=self.opening_key_id,
            epoch=self.epoch,
            request_digest=self.request_digest,
            ticket_digest=self.ticket_digest,
            case_id=self.case_id,
            share_value=self.share_value,
        )
