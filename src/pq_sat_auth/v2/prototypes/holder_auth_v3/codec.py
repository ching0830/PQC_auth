"""Canonical bytes for the isolated holder-signature access prototype.

The byte shapes intentionally parallel satellite access v0.2 so that the D1
byte ledger can be tested.  Magic values, version, suite identifiers, and
Python types are distinct.  Nothing here is registered with the shared v0.2
parser or a production registry.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from enum import IntEnum


FRAME_MAGIC = b"PQSAT-A3"
FRAME_VERSION = 3
FRAME_HEADER = struct.Struct(">8sHHI")
OPAQUE_LENGTH = struct.Struct(">I")
MAX_FRAME_BODY_BYTES = 100_000

ACCESS_SUITE_ID = 0xFF10
HOLDER_SUITE_ML_DSA_65 = 0xFF11
CHANNEL_BINDING_NONE = 0
CHANNEL_BINDING_AUTHENTICATED_EXPORTER = 1

DIGEST_BYTES = 32
CONTEXT_BYTES = 32
SERIAL_BYTES = 16
HOLDER_PARAMETER_DIGEST_BYTES = 32
HOLDER_PUBLIC_KEY_BINDING_BYTES = 48
ML_DSA_65_PUBLIC_KEY_BYTES = 1_952
ML_DSA_65_SIGNATURE_BYTES = 3_309
ML_KEM_768_PUBLIC_KEY_BYTES = 1_184
ML_KEM_768_CIPHERTEXT_BYTES = 1_088
FINISHED_BYTES = 48

TICKET_MAGIC = b"PQRBBC-TICKET-V2"
TICKET_SCHEMA_VERSION = 2
TICKET_PROTOCOL_VERSION = 2
ISSUER_VERIFICATION_ROLE = 4
TICKET_PAYLOAD_PREFIX = struct.Struct(">H32s16sH32s48s208s48s32s")
TICKET_PAYLOAD_BYTES = TICKET_PAYLOAD_PREFIX.size
PROVISIONAL_ISSUER_SIGNATURE_BYTES = 11_644
TICKET_ENVELOPE_BYTES = 62
MAX_TICKET_BYTES = 65_536

REQUEST_PREFIX = struct.Struct(">HH32s32sQ32s32s32s32sQ32s16sH32s")
ACCEPT_PREFIX = struct.Struct(">H32s32sQ32s32s32s32s32s32sQQ")
ACTIVATE_PREFIX = struct.Struct(">H32s32s32s32s")
FIRST_RECORD_PREFIX = struct.Struct(">H32s32s32s32sQ")

HOLDER_BIND_LABEL = b"PQ-SAT/HOLDER-PUBLIC-KEY-BIND/v3"
HOLDER_AUTH_INPUT_LABEL = b"PQ-SAT/HOLDER-AUTH/v3"
TICKET_PAYLOAD_DIGEST_LABEL = b"PQ-RBBC/TICKET-PAYLOAD/v3"
TICKET_CANONICAL_DIGEST_LABEL = b"PQ-RBBC/TICKET-CANONICAL/v3"
REQUEST_DIGEST_LABEL = b"PQ-SAT/ACCESS-REQUEST/v3"
ATTEMPT_ID_LABEL = b"PQ-SAT/ACCESS-ATTEMPT/v3"
USE_KEY_LABEL = b"PQ-SAT/USE-KEY/v1"
TRANSCRIPT_DIGEST_LABEL = b"PQ-SAT/ACCESS-TRANSCRIPT/v3"
RESPONSE_DIGEST_LABEL = b"PQ-SAT/ACCESS-ACCEPT/v3"
ACTIVATION_DIGEST_LABEL = b"PQ-SAT/SESSION-ACTIVATE/v3"
FIRST_RECORD_DIGEST_LABEL = b"PQ-SAT/FIRST-APPLICATION-RECORD/v3"

ML_DSA_65_PARAMETER_DESCRIPTOR = (
    b"FIPS-204:2024/ML-DSA-65/pure/empty-native-context/"
    b"protocol-domain-in-message"
)
ML_DSA_65_PARAMETER_DIGEST = hashlib.sha256(
    ML_DSA_65_PARAMETER_DESCRIPTOR
).digest()


class PrototypeEncodingError(ValueError):
    """Raised when an experimental v3 object is malformed."""


class FrameTypeV3(IntEnum):
    ACCESS_REQUEST = 0x0301
    ACCESS_ACCEPT = 0x0302
    SESSION_ACTIVATE = 0x0303
    FIRST_APPLICATION_RECORD = 0x0304


def _bytes(value: bytes, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    return value


def _fixed(value: bytes, size: int, name: str) -> bytes:
    raw = _bytes(value, name)
    if len(raw) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    return raw


def _uint(value: int, bits: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value < (1 << bits):
        raise ValueError(f"{name} does not fit uint{bits}")
    return value


def _opaque(value: bytes, *, maximum: int = MAX_FRAME_BODY_BYTES) -> bytes:
    raw = _bytes(value, "opaque value")
    if not raw:
        raise ValueError("opaque value must not be empty")
    if len(raw) > maximum:
        raise ValueError("opaque value exceeds prototype bound")
    return OPAQUE_LENGTH.pack(len(raw)) + raw


def _take(raw: bytes, offset: int, size: int, name: str) -> tuple[bytes, int]:
    if offset < 0 or size < 0 or offset + size > len(raw):
        raise PrototypeEncodingError(f"truncated {name}")
    return raw[offset : offset + size], offset + size


def _take_opaque(
    raw: bytes,
    offset: int,
    name: str,
    *,
    maximum: int = MAX_FRAME_BODY_BYTES,
) -> tuple[bytes, int]:
    length_bytes, offset = _take(raw, offset, OPAQUE_LENGTH.size, f"{name} length")
    (length,) = OPAQUE_LENGTH.unpack(length_bytes)
    if length == 0 or length > maximum:
        raise PrototypeEncodingError(f"{name} length is outside bounds")
    return _take(raw, offset, length, name)


def _encode_frame(frame_type: FrameTypeV3, body: bytes) -> bytes:
    if not isinstance(frame_type, FrameTypeV3):
        raise TypeError("frame_type must be FrameTypeV3")
    raw = _bytes(body, "frame body")
    if len(raw) > MAX_FRAME_BODY_BYTES:
        raise ValueError("prototype frame body exceeds bound")
    return FRAME_HEADER.pack(FRAME_MAGIC, FRAME_VERSION, int(frame_type), len(raw)) + raw


def _decode_frame(encoded: bytes, expected: FrameTypeV3) -> bytes:
    raw = _bytes(encoded, "encoded frame")
    if len(raw) < FRAME_HEADER.size:
        raise PrototypeEncodingError("truncated frame header")
    magic, version, frame_type, body_length = FRAME_HEADER.unpack_from(raw)
    if magic != FRAME_MAGIC:
        raise PrototypeEncodingError("frame magic mismatch")
    if version != FRAME_VERSION:
        raise PrototypeEncodingError("frame version mismatch")
    if frame_type != int(expected):
        raise PrototypeEncodingError("unexpected frame type")
    if body_length > MAX_FRAME_BODY_BYTES:
        raise PrototypeEncodingError("frame body exceeds bound")
    if len(raw) != FRAME_HEADER.size + body_length:
        raise PrototypeEncodingError("frame length mismatch or trailing bytes")
    return raw[FRAME_HEADER.size :]


def _shake(label: bytes, *parts: bytes, size: int = DIGEST_BYTES) -> bytes:
    return hashlib.shake_256(label + b"".join(parts)).digest(size)


@dataclass(frozen=True)
class CandidateTicketPayloadV3:
    profile_version: int
    ctx: bytes
    serial: bytes
    holder_suite_id: int
    holder_parameter_digest: bytes
    holder_public_key_binding: bytes
    syndrome: bytes
    masked_identity: bytes
    trace_tag: bytes

    def validate(self) -> None:
        _uint(self.profile_version, 16, "profile_version")
        if self.profile_version != FRAME_VERSION:
            raise ValueError("candidate ticket profile version mismatch")
        _fixed(self.ctx, CONTEXT_BYTES, "ctx")
        _fixed(self.serial, SERIAL_BYTES, "serial")
        _uint(self.holder_suite_id, 16, "holder_suite_id")
        if self.holder_suite_id != HOLDER_SUITE_ML_DSA_65:
            raise ValueError("unsupported experimental holder suite")
        _fixed(
            self.holder_parameter_digest,
            HOLDER_PARAMETER_DIGEST_BYTES,
            "holder_parameter_digest",
        )
        _fixed(
            self.holder_public_key_binding,
            HOLDER_PUBLIC_KEY_BINDING_BYTES,
            "holder_public_key_binding",
        )
        _fixed(self.syndrome, 208, "syndrome")
        _fixed(self.masked_identity, 48, "masked_identity")
        _fixed(self.trace_tag, 32, "trace_tag")

    def encode(self) -> bytes:
        self.validate()
        return TICKET_PAYLOAD_PREFIX.pack(
            self.profile_version,
            self.ctx,
            self.serial,
            self.holder_suite_id,
            self.holder_parameter_digest,
            self.holder_public_key_binding,
            self.syndrome,
            self.masked_identity,
            self.trace_tag,
        )

    @classmethod
    def decode(cls, encoded: bytes) -> "CandidateTicketPayloadV3":
        raw = _bytes(encoded, "candidate ticket payload")
        if len(raw) != TICKET_PAYLOAD_BYTES:
            raise PrototypeEncodingError("candidate ticket payload length mismatch")
        payload = cls(*TICKET_PAYLOAD_PREFIX.unpack(raw))
        try:
            payload.validate()
        except (TypeError, ValueError) as error:
            raise PrototypeEncodingError(str(error)) from error
        if payload.encode() != raw:
            raise PrototypeEncodingError("non-canonical candidate ticket payload")
        return payload

    @property
    def digest(self) -> bytes:
        return _shake(TICKET_PAYLOAD_DIGEST_LABEL, self.encode())


@dataclass(frozen=True)
class CandidateTicketV3:
    issuer_key_id: bytes
    payload: CandidateTicketPayloadV3
    issuer_signature: bytes
    schema_version: int = TICKET_SCHEMA_VERSION
    protocol_version: int = TICKET_PROTOCOL_VERSION
    signing_role: int = ISSUER_VERIFICATION_ROLE

    def validate(self) -> None:
        _uint(self.schema_version, 16, "ticket schema_version")
        _uint(self.protocol_version, 16, "ticket protocol_version")
        _uint(self.signing_role, 16, "ticket signing_role")
        if self.schema_version != TICKET_SCHEMA_VERSION:
            raise ValueError("candidate ticket schema version mismatch")
        if self.protocol_version != TICKET_PROTOCOL_VERSION:
            raise ValueError("candidate ticket protocol version mismatch")
        if self.signing_role != ISSUER_VERIFICATION_ROLE:
            raise ValueError("candidate ticket signing role mismatch")
        _fixed(self.issuer_key_id, DIGEST_BYTES, "issuer_key_id")
        if self.issuer_key_id == bytes(DIGEST_BYTES):
            raise ValueError("issuer_key_id must not be all zero")
        if not isinstance(self.payload, CandidateTicketPayloadV3):
            raise TypeError("payload must be CandidateTicketPayloadV3")
        self.payload.validate()
        _fixed(
            self.issuer_signature,
            PROVISIONAL_ISSUER_SIGNATURE_BYTES,
            "provisional issuer signature fixture",
        )

    def encode(self) -> bytes:
        self.validate()
        payload = self.payload.encode()
        encoded = b"".join(
            (
                TICKET_MAGIC,
                self.schema_version.to_bytes(2, "little"),
                self.protocol_version.to_bytes(2, "little"),
                self.signing_role.to_bytes(2, "little"),
                self.issuer_key_id,
                len(payload).to_bytes(4, "little"),
                payload,
                len(self.issuer_signature).to_bytes(4, "little"),
                self.issuer_signature,
            )
        )
        if len(encoded) > MAX_TICKET_BYTES:
            raise ValueError("candidate ticket exceeds prototype bound")
        return encoded

    @property
    def canonical_digest(self) -> bytes:
        return _shake(TICKET_CANONICAL_DIGEST_LABEL, self.encode())


def encode_candidate_ticket(ticket: CandidateTicketV3) -> bytes:
    if not isinstance(ticket, CandidateTicketV3):
        raise TypeError("ticket must be CandidateTicketV3")
    return ticket.encode()


def decode_candidate_ticket(encoded: bytes) -> CandidateTicketV3:
    raw = _bytes(encoded, "candidate ticket")
    if len(raw) > MAX_TICKET_BYTES:
        raise PrototypeEncodingError("candidate ticket exceeds prototype bound")
    offset = 0
    magic, offset = _take(raw, offset, len(TICKET_MAGIC), "ticket magic")
    if magic != TICKET_MAGIC:
        raise PrototypeEncodingError("candidate ticket magic mismatch")
    fixed, offset = _take(raw, offset, 2 + 2 + 2 + 32 + 4, "ticket envelope")
    schema = int.from_bytes(fixed[0:2], "little")
    protocol = int.from_bytes(fixed[2:4], "little")
    role = int.from_bytes(fixed[4:6], "little")
    issuer_key_id = fixed[6:38]
    payload_length = int.from_bytes(fixed[38:42], "little")
    if payload_length != TICKET_PAYLOAD_BYTES:
        raise PrototypeEncodingError("candidate ticket payload length mismatch")
    payload_bytes, offset = _take(raw, offset, payload_length, "ticket payload")
    signature_length_bytes, offset = _take(raw, offset, 4, "ticket signature length")
    signature_length = int.from_bytes(signature_length_bytes, "little")
    if signature_length != PROVISIONAL_ISSUER_SIGNATURE_BYTES:
        raise PrototypeEncodingError("provisional issuer signature length mismatch")
    signature, offset = _take(raw, offset, signature_length, "ticket signature")
    if offset != len(raw):
        raise PrototypeEncodingError("candidate ticket trailing bytes")
    ticket = CandidateTicketV3(
        schema_version=schema,
        protocol_version=protocol,
        signing_role=role,
        issuer_key_id=issuer_key_id,
        payload=CandidateTicketPayloadV3.decode(payload_bytes),
        issuer_signature=signature,
    )
    try:
        ticket.validate()
    except (TypeError, ValueError) as error:
        raise PrototypeEncodingError(str(error)) from error
    if ticket.encode() != raw:
        raise PrototypeEncodingError("non-canonical candidate ticket")
    return ticket


def derive_holder_public_key_binding(
    holder_suite_id: int,
    holder_parameter_digest: bytes,
    holder_public_key: bytes,
) -> bytes:
    suite = _uint(holder_suite_id, 16, "holder_suite_id")
    parameters = _fixed(
        holder_parameter_digest,
        HOLDER_PARAMETER_DIGEST_BYTES,
        "holder_parameter_digest",
    )
    key = _bytes(holder_public_key, "holder_public_key")
    return _shake(
        HOLDER_BIND_LABEL,
        struct.pack(">H", suite),
        parameters,
        _opaque(key),
        size=HOLDER_PUBLIC_KEY_BINDING_BYTES,
    )


def _fixture_bytes(label: bytes, size: int) -> bytes:
    return hashlib.shake_256(b"PQ-SAT/D4-FIXTURE/v0.1/" + label).digest(size)


def build_candidate_ticket_fixture(holder_public_key: bytes) -> CandidateTicketV3:
    """Build the 12,126-byte size fixture; its issuer bytes are not a signature."""

    key = _fixed(
        holder_public_key,
        ML_DSA_65_PUBLIC_KEY_BYTES,
        "holder_public_key",
    )
    payload = CandidateTicketPayloadV3(
        profile_version=FRAME_VERSION,
        ctx=_fixture_bytes(b"ctx", CONTEXT_BYTES),
        serial=_fixture_bytes(b"serial", SERIAL_BYTES),
        holder_suite_id=HOLDER_SUITE_ML_DSA_65,
        holder_parameter_digest=ML_DSA_65_PARAMETER_DIGEST,
        holder_public_key_binding=derive_holder_public_key_binding(
            HOLDER_SUITE_ML_DSA_65,
            ML_DSA_65_PARAMETER_DIGEST,
            key,
        ),
        syndrome=_fixture_bytes(b"trace-syndrome", 208),
        masked_identity=_fixture_bytes(b"trace-masked-identity", 48),
        trace_tag=_fixture_bytes(b"trace-tag", 32),
    )
    ticket = CandidateTicketV3(
        issuer_key_id=_fixture_bytes(b"issuer-key-id", DIGEST_BYTES),
        payload=payload,
        issuer_signature=_fixture_bytes(
            b"provisional-issuer-signature-not-cryptographic",
            PROVISIONAL_ISSUER_SIGNATURE_BYTES,
        ),
    )
    if len(ticket.encode()) != TICKET_ENVELOPE_BYTES + TICKET_PAYLOAD_BYTES + PROVISIONAL_ISSUER_SIGNATURE_BYTES:
        raise AssertionError("candidate ticket size ledger drift")
    return ticket


@dataclass(frozen=True)
class HolderAccessRequestV3:
    access_suite_id: int
    holder_suite_id: int
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
    channel_binding_mode: int
    channel_binding_digest: bytes
    ticket: bytes
    ue_kem_epk: bytes
    holder_public_key: bytes
    holder_authenticator: bytes

    def validate(self) -> None:
        _uint(self.access_suite_id, 16, "access_suite_id")
        _uint(self.holder_suite_id, 16, "holder_suite_id")
        if self.access_suite_id != ACCESS_SUITE_ID:
            raise ValueError("unsupported experimental access suite")
        if self.holder_suite_id != HOLDER_SUITE_ML_DSA_65:
            raise ValueError("unsupported experimental holder suite")
        for name in (
            "system_config_digest",
            "ctx",
            "target_fgs_id",
            "fgs_auth_key_id",
            "serving_context_digest",
            "authorization_digest",
            "ue_nonce",
            "channel_binding_digest",
        ):
            _fixed(getattr(self, name), DIGEST_BYTES, name)
        _fixed(self.attempt_nonce, 16, "attempt_nonce")
        _uint(self.epoch, 64, "epoch")
        _uint(self.client_time, 64, "client_time")
        mode = _uint(self.channel_binding_mode, 16, "channel_binding_mode")
        if mode not in (
            CHANNEL_BINDING_NONE,
            CHANNEL_BINDING_AUTHENTICATED_EXPORTER,
        ):
            raise ValueError("unknown channel binding mode")
        if mode == CHANNEL_BINDING_NONE and self.channel_binding_digest != bytes(32):
            raise ValueError("channel binding NONE requires a zero digest")
        if mode != CHANNEL_BINDING_NONE and self.channel_binding_digest == bytes(32):
            raise ValueError("authenticated channel binding digest must not be zero")
        ticket = _bytes(self.ticket, "ticket")
        if not ticket or len(ticket) > MAX_TICKET_BYTES:
            raise ValueError("ticket length is outside prototype bounds")
        _fixed(self.ue_kem_epk, ML_KEM_768_PUBLIC_KEY_BYTES, "ue_kem_epk")
        _fixed(
            self.holder_public_key,
            ML_DSA_65_PUBLIC_KEY_BYTES,
            "holder_public_key",
        )
        _fixed(
            self.holder_authenticator,
            ML_DSA_65_SIGNATURE_BYTES,
            "holder_authenticator",
        )

    def core_bytes(self) -> bytes:
        self.validate()
        prefix = REQUEST_PREFIX.pack(
            self.access_suite_id,
            self.holder_suite_id,
            self.system_config_digest,
            self.ctx,
            self.epoch,
            self.target_fgs_id,
            self.fgs_auth_key_id,
            self.serving_context_digest,
            self.authorization_digest,
            self.client_time,
            self.ue_nonce,
            self.attempt_nonce,
            self.channel_binding_mode,
            self.channel_binding_digest,
        )
        return b"".join(
            (
                prefix,
                _opaque(self.ticket, maximum=MAX_TICKET_BYTES),
                _opaque(self.ue_kem_epk),
                _opaque(self.holder_public_key),
            )
        )

    def holder_signing_input(self) -> bytes:
        core = self.core_bytes()
        return HOLDER_AUTH_INPUT_LABEL + len(core).to_bytes(4, "big") + core


def encode_access_request(request: HolderAccessRequestV3) -> bytes:
    if not isinstance(request, HolderAccessRequestV3):
        raise TypeError("request must be HolderAccessRequestV3")
    return _encode_frame(
        FrameTypeV3.ACCESS_REQUEST,
        request.core_bytes() + _opaque(request.holder_authenticator),
    )


def decode_access_request(encoded: bytes) -> HolderAccessRequestV3:
    body = _decode_frame(encoded, FrameTypeV3.ACCESS_REQUEST)
    if len(body) < REQUEST_PREFIX.size:
        raise PrototypeEncodingError("truncated access request prefix")
    values = REQUEST_PREFIX.unpack_from(body)
    ticket, offset = _take_opaque(
        body, REQUEST_PREFIX.size, "ticket", maximum=MAX_TICKET_BYTES
    )
    epk, offset = _take_opaque(body, offset, "ue_kem_epk")
    holder_key, offset = _take_opaque(body, offset, "holder_public_key")
    authenticator, offset = _take_opaque(body, offset, "holder_authenticator")
    if offset != len(body):
        raise PrototypeEncodingError("access request trailing bytes")
    request = HolderAccessRequestV3(
        *values,
        ticket,
        epk,
        holder_key,
        authenticator,
    )
    try:
        request.validate()
    except (TypeError, ValueError) as error:
        raise PrototypeEncodingError(str(error)) from error
    if encode_access_request(request) != encoded:
        raise PrototypeEncodingError("non-canonical access request")
    return request


def derive_request_digest(request: HolderAccessRequestV3) -> bytes:
    return _shake(REQUEST_DIGEST_LABEL, encode_access_request(request))


def derive_use_key(ticket: CandidateTicketV3) -> bytes:
    if not isinstance(ticket, CandidateTicketV3):
        raise TypeError("ticket must be CandidateTicketV3")
    return _shake(
        USE_KEY_LABEL,
        ticket.payload.ctx,
        ticket.payload.serial,
        ticket.payload.digest,
    )


def derive_attempt_id(request: HolderAccessRequestV3) -> bytes:
    ticket = decode_candidate_ticket(request.ticket)
    return _shake(
        ATTEMPT_ID_LABEL,
        derive_use_key(ticket),
        derive_request_digest(request),
    )


@dataclass(frozen=True)
class HolderAccessAcceptV3:
    access_suite_id: int
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

    def validate(self) -> None:
        _uint(self.access_suite_id, 16, "access_suite_id")
        if self.access_suite_id != ACCESS_SUITE_ID:
            raise ValueError("unsupported experimental access suite")
        for name in (
            "system_config_digest",
            "ctx",
            "fgs_id",
            "fgs_auth_key_id",
            "request_digest",
            "attempt_id",
            "session_id",
            "serving_context_digest",
        ):
            _fixed(getattr(self, name), DIGEST_BYTES, name)
        _uint(self.epoch, 64, "epoch")
        _uint(self.session_expiry, 64, "session_expiry")
        _uint(self.activation_deadline, 64, "activation_deadline")
        if self.activation_deadline > self.session_expiry:
            raise ValueError("activation deadline exceeds session expiry")
        _fixed(
            self.kem_ciphertext_to_ue,
            ML_KEM_768_CIPHERTEXT_BYTES,
            "kem_ciphertext_to_ue",
        )
        _fixed(
            self.fgs_authenticator,
            ML_DSA_65_SIGNATURE_BYTES,
            "fgs_authenticator",
        )
        _fixed(
            self.server_key_confirmation,
            FINISHED_BYTES,
            "server_key_confirmation",
        )

    def core_bytes(self) -> bytes:
        self.validate()
        return ACCEPT_PREFIX.pack(
            self.access_suite_id,
            self.system_config_digest,
            self.ctx,
            self.epoch,
            self.fgs_id,
            self.fgs_auth_key_id,
            self.request_digest,
            self.attempt_id,
            self.session_id,
            self.serving_context_digest,
            self.session_expiry,
            self.activation_deadline,
        ) + _opaque(self.kem_ciphertext_to_ue)


def encode_access_accept(response: HolderAccessAcceptV3) -> bytes:
    if not isinstance(response, HolderAccessAcceptV3):
        raise TypeError("response must be HolderAccessAcceptV3")
    return _encode_frame(
        FrameTypeV3.ACCESS_ACCEPT,
        response.core_bytes()
        + _opaque(response.fgs_authenticator)
        + _opaque(response.server_key_confirmation),
    )


def decode_access_accept(encoded: bytes) -> HolderAccessAcceptV3:
    body = _decode_frame(encoded, FrameTypeV3.ACCESS_ACCEPT)
    if len(body) < ACCEPT_PREFIX.size:
        raise PrototypeEncodingError("truncated access accept prefix")
    values = ACCEPT_PREFIX.unpack_from(body)
    ciphertext, offset = _take_opaque(body, ACCEPT_PREFIX.size, "KEM ciphertext")
    authenticator, offset = _take_opaque(body, offset, "FGS authenticator")
    confirmation, offset = _take_opaque(body, offset, "server Finished")
    if offset != len(body):
        raise PrototypeEncodingError("access accept trailing bytes")
    response = HolderAccessAcceptV3(
        *values,
        ciphertext,
        authenticator,
        confirmation,
    )
    try:
        response.validate()
    except (TypeError, ValueError) as error:
        raise PrototypeEncodingError(str(error)) from error
    if encode_access_accept(response) != encoded:
        raise PrototypeEncodingError("non-canonical access accept")
    return response


def derive_transcript_digest(
    request: HolderAccessRequestV3,
    response: HolderAccessAcceptV3,
) -> bytes:
    return _shake(
        TRANSCRIPT_DIGEST_LABEL,
        derive_request_digest(request),
        response.core_bytes(),
    )


def derive_response_digest(response: HolderAccessAcceptV3) -> bytes:
    return _shake(RESPONSE_DIGEST_LABEL, encode_access_accept(response))


@dataclass(frozen=True)
class SessionActivateV3:
    access_suite_id: int
    request_digest: bytes
    attempt_id: bytes
    session_id: bytes
    response_digest: bytes
    client_key_confirmation: bytes

    def validate(self) -> None:
        _uint(self.access_suite_id, 16, "access_suite_id")
        if self.access_suite_id != ACCESS_SUITE_ID:
            raise ValueError("unsupported experimental access suite")
        for name in (
            "request_digest",
            "attempt_id",
            "session_id",
            "response_digest",
        ):
            _fixed(getattr(self, name), DIGEST_BYTES, name)
        _fixed(
            self.client_key_confirmation,
            FINISHED_BYTES,
            "client_key_confirmation",
        )


def encode_session_activate(activation: SessionActivateV3) -> bytes:
    if not isinstance(activation, SessionActivateV3):
        raise TypeError("activation must be SessionActivateV3")
    activation.validate()
    body = ACTIVATE_PREFIX.pack(
        activation.access_suite_id,
        activation.request_digest,
        activation.attempt_id,
        activation.session_id,
        activation.response_digest,
    ) + _opaque(activation.client_key_confirmation)
    return _encode_frame(FrameTypeV3.SESSION_ACTIVATE, body)


def decode_session_activate(encoded: bytes) -> SessionActivateV3:
    body = _decode_frame(encoded, FrameTypeV3.SESSION_ACTIVATE)
    if len(body) < ACTIVATE_PREFIX.size:
        raise PrototypeEncodingError("truncated session activation prefix")
    values = ACTIVATE_PREFIX.unpack_from(body)
    confirmation, offset = _take_opaque(body, ACTIVATE_PREFIX.size, "client Finished")
    if offset != len(body):
        raise PrototypeEncodingError("session activation trailing bytes")
    activation = SessionActivateV3(*values, confirmation)
    try:
        activation.validate()
    except (TypeError, ValueError) as error:
        raise PrototypeEncodingError(str(error)) from error
    if encode_session_activate(activation) != encoded:
        raise PrototypeEncodingError("non-canonical session activation")
    return activation


def derive_activation_digest(activation: SessionActivateV3) -> bytes:
    return _shake(ACTIVATION_DIGEST_LABEL, encode_session_activate(activation))


@dataclass(frozen=True)
class FirstApplicationRecordV3:
    access_suite_id: int
    request_digest: bytes
    attempt_id: bytes
    session_id: bytes
    response_digest: bytes
    sequence_number: int
    activation_bytes: bytes
    ciphertext: bytes

    def validate(self) -> None:
        _uint(self.access_suite_id, 16, "access_suite_id")
        if self.access_suite_id != ACCESS_SUITE_ID:
            raise ValueError("unsupported experimental access suite")
        for name in (
            "request_digest",
            "attempt_id",
            "session_id",
            "response_digest",
        ):
            _fixed(getattr(self, name), DIGEST_BYTES, name)
        _uint(self.sequence_number, 64, "sequence_number")
        if self.sequence_number != 0:
            raise ValueError("first application record sequence must be zero")
        activation = decode_session_activate(self.activation_bytes)
        bindings = (
            (activation.access_suite_id, self.access_suite_id),
            (activation.request_digest, self.request_digest),
            (activation.attempt_id, self.attempt_id),
            (activation.session_id, self.session_id),
            (activation.response_digest, self.response_digest),
        )
        if any(actual != expected for actual, expected in bindings):
            raise ValueError("activation and first-record bindings differ")
        if not isinstance(self.ciphertext, bytes) or not self.ciphertext:
            raise ValueError("ciphertext must be non-empty bytes")


def encode_first_application_record(record: FirstApplicationRecordV3) -> bytes:
    if not isinstance(record, FirstApplicationRecordV3):
        raise TypeError("record must be FirstApplicationRecordV3")
    record.validate()
    body = FIRST_RECORD_PREFIX.pack(
        record.access_suite_id,
        record.request_digest,
        record.attempt_id,
        record.session_id,
        record.response_digest,
        record.sequence_number,
    ) + _opaque(record.activation_bytes) + _opaque(record.ciphertext)
    return _encode_frame(FrameTypeV3.FIRST_APPLICATION_RECORD, body)


def decode_first_application_record(encoded: bytes) -> FirstApplicationRecordV3:
    body = _decode_frame(encoded, FrameTypeV3.FIRST_APPLICATION_RECORD)
    if len(body) < FIRST_RECORD_PREFIX.size:
        raise PrototypeEncodingError("truncated first application record prefix")
    values = FIRST_RECORD_PREFIX.unpack_from(body)
    activation, offset = _take_opaque(body, FIRST_RECORD_PREFIX.size, "activation")
    ciphertext, offset = _take_opaque(body, offset, "ciphertext")
    if offset != len(body):
        raise PrototypeEncodingError("first application record trailing bytes")
    record = FirstApplicationRecordV3(*values, activation, ciphertext)
    try:
        record.validate()
    except (TypeError, ValueError, PrototypeEncodingError) as error:
        raise PrototypeEncodingError(str(error)) from error
    if encode_first_application_record(record) != encoded:
        raise PrototypeEncodingError("non-canonical first application record")
    return record


def derive_first_application_record_digest(record: FirstApplicationRecordV3) -> bytes:
    return _shake(
        FIRST_RECORD_DIGEST_LABEL,
        encode_first_application_record(record),
    )
