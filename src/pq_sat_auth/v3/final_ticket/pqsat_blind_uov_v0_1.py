"""Final-profile PQ-SAT V3 ticket and M1 research codecs.

This module deliberately owns only the final trace/CAP wire join, the
PQ-SAT-owned ``H_RBBC`` mapping, an explicit-public-map CAP adapter, and the
holder-authentication verification boundary.  The ``0xFF32`` ticket suite is
a private research candidate.  It is not a production-registered suite, and
the module does not provide a ticket-bound prover, issuance proof, opening
provider, registry lookup, or global issuer-map fallback.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Callable, Final, TypeVar

from pq_rbbc.blind_uov_pqsat_v0_1.codec import (
    CR,
    CZ,
    Pi2,
    decode_c_r,
    decode_c_z,
    decode_pi_2,
    encode_c_r,
    encode_c_z,
    encode_pi_2,
)
from pq_rbbc.blind_uov_pqsat_v0_1.relation import CAPStatement
from pq_rbbc.blind_uov_pqsat_v0_1.transcript import encode_tuple
from pq_rbbc.blind_uov_pqsat_v0_1.uov import (
    UOVPublicMap,
    decode_public_map,
)
from pq_rbbc.blind_uov_pqsat_v0_1.verifier import verify as _verify_cap

from ..authentication import (
    SignatureRole,
    holder_public_key_binding,
    native_signature_context,
)
from ..encoding import (
    ACCESS_SUITE_MEASUREMENT,
    FRAME_HEADER_BYTES,
    EncodingError,
    FrameTypeV3,
    decode_frame_v3,
    decode_opaque32,
    encode_frame_v3,
    encode_opaque32,
    hash_v3,
    take,
)
from ..providers import (
    ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_SIGNATURE_BYTES,
    ML_KEM_768_PUBLIC_KEY_BYTES,
    MLDSA65Provider,
    NativeContextCapability,
)


class FinalTicketEncodingError(ValueError):
    """Controlled rejection of malformed or noncanonical final-profile bytes."""


PQSAT_BLIND_UOV_RESEARCH_SUITE: Final = 0xFF32
PQSAT_BLIND_UOV_PROFILE_FINGERPRINT: Final = bytes.fromhex(
    "fc6706429f10d3bcc5600d4b427ca604"
    "a19f22c31ec35b171f40513b1a4bcb25"
)

H_RBBC_DOMAIN: Final = b"PQSAT-BUOV-CAP-0.1/H-RBBC"
TICKET_DIGEST_LABEL: Final = b"ticket"

CONTEXT_BYTES: Final = 32
DIGEST_BYTES: Final = 32
SERIAL_BYTES: Final = 16
HOLDER_BINDING_BYTES: Final = 48
TRACE_SYNDROME_BYTES: Final = 208
TRACE_MASKED_IDENTITY_BYTES: Final = 48
TRACE_TAG_BYTES: Final = 32

C_R_BYTES: Final = 5_074
C_Z_BYTES: Final = 234
PI_2_MIN_BYTES: Final = 1_728
PI_2_MAX_BYTES: Final = 5_592
H_RBBC_OUTPUT_BYTES: Final = 72

FINAL_TICKET_FIXED_BYTES: Final = 5_758
FINAL_TICKET_MIN_BYTES: Final = FINAL_TICKET_FIXED_BYTES + PI_2_MIN_BYTES
FINAL_TICKET_MAX_BYTES: Final = FINAL_TICKET_FIXED_BYTES + PI_2_MAX_BYTES
FINAL_TICKET_PAYLOAD_BYTES: Final = 388

NONCE_BYTES: Final = 32
ATTEMPT_NONCE_BYTES: Final = 16
CHANNEL_BINDING_NONE: Final = 0
CHANNEL_BINDING_AUTHENTICATED_EXPORTER: Final = 1

FINAL_REQUEST_CORE_FIXED_BYTES: Final = 3_359
FINAL_REQUEST_CORE_MIN_BYTES: Final = (
    FINAL_REQUEST_CORE_FIXED_BYTES + FINAL_TICKET_MIN_BYTES
)
FINAL_REQUEST_CORE_MAX_BYTES: Final = (
    FINAL_REQUEST_CORE_FIXED_BYTES + FINAL_TICKET_MAX_BYTES
)
FINAL_ACCESS_REQUEST_FIXED_BYTES: Final = 6_688
FINAL_ACCESS_REQUEST_MIN_BYTES: Final = (
    FINAL_ACCESS_REQUEST_FIXED_BYTES + FINAL_TICKET_MIN_BYTES
)
FINAL_ACCESS_REQUEST_MAX_BYTES: Final = (
    FINAL_ACCESS_REQUEST_FIXED_BYTES + FINAL_TICKET_MAX_BYTES
)


def _exact_bytes(value: object, name: str, length: int | None = None) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{name} must be exact bytes")
    if length is not None and len(value) != length:
        raise FinalTicketEncodingError(
            f"{name} must be exactly {length} bytes"
        )
    return value


def _exact_uint(value: object, bits: int, name: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{name} must be an exact int and bool is forbidden")
    if not 0 <= value < (1 << bits):
        raise FinalTicketEncodingError(f"{name} does not fit uint{bits}")
    return value


_ParsedComponent = TypeVar("_ParsedComponent", CR, CZ, Pi2)


def _canonical_component(
    value: object,
    *,
    name: str,
    minimum: int,
    maximum: int,
    decoder: Callable[[bytes], _ParsedComponent],
    encoder: Callable[[_ParsedComponent], bytes],
) -> bytes:
    raw = _exact_bytes(value, name)
    if not minimum <= len(raw) <= maximum:
        if minimum == maximum:
            detail = f"exactly {minimum}"
        else:
            detail = f"in range {minimum}..{maximum}"
        raise FinalTicketEncodingError(f"{name} length must be {detail} bytes")
    try:
        parsed = decoder(raw)
        canonical = encoder(parsed)
    except (TypeError, ValueError) as error:
        raise FinalTicketEncodingError(f"invalid canonical {name}") from error
    if canonical != raw:
        raise FinalTicketEncodingError(f"noncanonical {name}")
    return raw


def _canonical_c_r(value: object) -> bytes:
    return _canonical_component(
        value,
        name="c_r",
        minimum=C_R_BYTES,
        maximum=C_R_BYTES,
        decoder=decode_c_r,
        encoder=encode_c_r,
    )


def _canonical_c_z(value: object) -> bytes:
    return _canonical_component(
        value,
        name="c_z",
        minimum=C_Z_BYTES,
        maximum=C_Z_BYTES,
        decoder=decode_c_z,
        encoder=encode_c_z,
    )


def _canonical_pi_2(value: object) -> bytes:
    return _canonical_component(
        value,
        name="pi_2",
        minimum=PI_2_MIN_BYTES,
        maximum=PI_2_MAX_BYTES,
        decoder=decode_pi_2,
        encoder=encode_pi_2,
    )


def derive_h_rbbc(ctx: bytes, d_m: bytes, c_r: bytes) -> bytes:
    """Derive the sole PQ-SAT-owned research-profile ``H_RBBC`` mapping."""

    context = _exact_bytes(ctx, "ctx", CONTEXT_BYTES)
    payload_digest = _exact_bytes(d_m, "d_M", DIGEST_BYTES)
    canonical_c_r = _canonical_c_r(c_r)
    encoded = encode_tuple(
        H_RBBC_DOMAIN,
        (
            PQSAT_BLIND_UOV_PROFILE_FINGERPRINT,
            context,
            payload_digest,
            canonical_c_r,
        ),
    )
    return hashlib.shake_256(encoded).digest(H_RBBC_OUTPUT_BYTES)


@dataclass(frozen=True, slots=True)
class FinalTicketCiphertextV0_1:
    s: bytes
    c_mu: bytes
    gamma: bytes

    def __post_init__(self) -> None:
        _exact_bytes(self.s, "s", TRACE_SYNDROME_BYTES)
        _exact_bytes(
            self.c_mu,
            "c_mu",
            TRACE_MASKED_IDENTITY_BYTES,
        )
        _exact_bytes(self.gamma, "gamma", TRACE_TAG_BYTES)

    def encode(self) -> bytes:
        _validate_ciphertext(self)
        return (
            encode_opaque32(self.s, max_length=TRACE_SYNDROME_BYTES)
            + self.c_mu
            + self.gamma
        )


def _validate_ciphertext(
    value: object,
) -> FinalTicketCiphertextV0_1:
    if type(value) is not FinalTicketCiphertextV0_1:
        raise TypeError(
            "ciphertext must be exactly FinalTicketCiphertextV0_1"
        )
    _exact_bytes(value.s, "s", TRACE_SYNDROME_BYTES)
    _exact_bytes(
        value.c_mu,
        "c_mu",
        TRACE_MASKED_IDENTITY_BYTES,
    )
    _exact_bytes(value.gamma, "gamma", TRACE_TAG_BYTES)
    return value


@dataclass(frozen=True, slots=True)
class FinalTicketPayloadV0_1:
    ctx: bytes
    serial: bytes
    q: bytes
    ciphertext: FinalTicketCiphertextV0_1

    def __post_init__(self) -> None:
        _validate_payload(self)

    def encode(self) -> bytes:
        _validate_payload(self)
        encoded = self.ctx + self.serial + self.q + self.ciphertext.encode()
        if len(encoded) != FINAL_TICKET_PAYLOAD_BYTES:
            raise AssertionError("final Encode(M) length ledger drift")
        return encoded

    @property
    def digest(self) -> bytes:
        return hash_v3(
            TICKET_DIGEST_LABEL,
            self.ctx,
            self.encode(),
            DIGEST_BYTES,
        )

    @property
    def SN(self) -> bytes:
        return self.serial

    @property
    def C(self) -> FinalTicketCiphertextV0_1:
        return self.ciphertext


def _validate_payload(value: object) -> FinalTicketPayloadV0_1:
    if type(value) is not FinalTicketPayloadV0_1:
        raise TypeError("payload must be exactly FinalTicketPayloadV0_1")
    _exact_bytes(value.ctx, "ticket ctx", CONTEXT_BYTES)
    _exact_bytes(value.serial, "ticket SN", SERIAL_BYTES)
    _exact_bytes(value.q, "ticket q", HOLDER_BINDING_BYTES)
    _validate_ciphertext(value.ciphertext)
    return value


def encode_ticket_signature(c_r: bytes, c_z: bytes, pi_2: bytes) -> bytes:
    """Encode canonical ``sigma_I=(c_r,c_z,pi_2)`` without another frame."""

    commitment = _canonical_c_r(c_r)
    response = _canonical_c_z(c_z)
    proof = _canonical_pi_2(pi_2)
    return b"".join(
        (
            encode_opaque32(commitment, max_length=C_R_BYTES),
            encode_opaque32(response, max_length=C_Z_BYTES),
            encode_opaque32(proof, max_length=PI_2_MAX_BYTES),
        )
    )


def decode_ticket_signature(encoded: bytes) -> tuple[bytes, bytes, bytes]:
    """Strictly decode and completely re-encode one signature tuple."""

    raw = _exact_bytes(encoded, "encoded ticket signature")
    minimum = 12 + C_R_BYTES + C_Z_BYTES + PI_2_MIN_BYTES
    maximum = 12 + C_R_BYTES + C_Z_BYTES + PI_2_MAX_BYTES
    if not minimum <= len(raw) <= maximum:
        raise FinalTicketEncodingError(
            "encoded ticket signature length is outside the final profile"
        )
    try:
        c_r, offset = decode_opaque32(
            raw,
            0,
            max_length=C_R_BYTES,
            exact_length=C_R_BYTES,
            name="signature c_r",
        )
        c_z, offset = decode_opaque32(
            raw,
            offset,
            max_length=C_Z_BYTES,
            exact_length=C_Z_BYTES,
            name="signature c_z",
        )
        pi_2, offset = decode_opaque32(
            raw,
            offset,
            max_length=PI_2_MAX_BYTES,
            name="signature pi_2",
        )
        if offset != len(raw):
            raise FinalTicketEncodingError("ticket signature has trailing bytes")
        result = (
            _canonical_c_r(c_r),
            _canonical_c_z(c_z),
            _canonical_pi_2(pi_2),
        )
        if encode_ticket_signature(*result) != raw:
            raise FinalTicketEncodingError("noncanonical ticket signature")
        return result
    except FinalTicketEncodingError:
        raise
    except (EncodingError, TypeError, ValueError) as error:
        raise FinalTicketEncodingError("invalid ticket signature") from error


@dataclass(frozen=True, slots=True)
class FinalTicketV0_1:
    ticket_suite_id: int
    issuer_key_id: bytes
    payload: FinalTicketPayloadV0_1
    c_r: bytes
    c_z: bytes
    pi_2: bytes

    def __post_init__(self) -> None:
        _validate_ticket(self)

    def body_bytes(self) -> bytes:
        _validate_ticket(self)
        ciphertext = self.payload.ciphertext
        return b"".join(
            (
                self.ticket_suite_id.to_bytes(2, "big"),
                self.payload.ctx,
                self.issuer_key_id,
                self.payload.serial,
                self.payload.q,
                ciphertext.encode(),
                encode_ticket_signature(self.c_r, self.c_z, self.pi_2),
            )
        )

    def encode(self) -> bytes:
        encoded = encode_frame_v3(FrameTypeV3.TICKET, self.body_bytes())
        expected = FINAL_TICKET_FIXED_BYTES + len(self.pi_2)
        if len(encoded) != expected:
            raise AssertionError("final Ticket length ledger drift")
        return encoded

    @property
    def M(self) -> FinalTicketPayloadV0_1:
        return self.payload

    @property
    def signature(self) -> tuple[bytes, bytes, bytes]:
        return self.c_r, self.c_z, self.pi_2


def _validate_ticket(value: object) -> FinalTicketV0_1:
    if type(value) is not FinalTicketV0_1:
        raise TypeError("ticket must be exactly FinalTicketV0_1")
    suite = _exact_uint(value.ticket_suite_id, 16, "ticket_suite_id")
    if suite != PQSAT_BLIND_UOV_RESEARCH_SUITE:
        raise FinalTicketEncodingError("unsupported final ticket suite")
    _exact_bytes(value.issuer_key_id, "issuer_key_id", DIGEST_BYTES)
    _validate_payload(value.payload)
    _canonical_c_r(value.c_r)
    _canonical_c_z(value.c_z)
    _canonical_pi_2(value.pi_2)
    return value


def decode_final_ticket(encoded: bytes) -> FinalTicketV0_1:
    """Strictly decode and completely re-encode a final-profile Ticket."""

    raw = _exact_bytes(encoded, "encoded final Ticket")
    if not FINAL_TICKET_MIN_BYTES <= len(raw) <= FINAL_TICKET_MAX_BYTES:
        raise FinalTicketEncodingError(
            "final Ticket length is outside the profile range"
        )
    try:
        frame = decode_frame_v3(
            raw,
            expected_type=FrameTypeV3.TICKET,
            max_body_bytes=FINAL_TICKET_MAX_BYTES - FRAME_HEADER_BYTES,
        )
        offset = 0
        suite_raw, offset = take(frame.body, offset, 2, "ticket suite")
        ctx, offset = take(frame.body, offset, CONTEXT_BYTES, "ticket ctx")
        issuer_key_id, offset = take(
            frame.body,
            offset,
            DIGEST_BYTES,
            "issuer_key_id",
        )
        serial, offset = take(frame.body, offset, SERIAL_BYTES, "ticket SN")
        q, offset = take(frame.body, offset, HOLDER_BINDING_BYTES, "ticket q")
        syndrome, offset = decode_opaque32(
            frame.body,
            offset,
            max_length=TRACE_SYNDROME_BYTES,
            exact_length=TRACE_SYNDROME_BYTES,
            name="ticket s",
        )
        c_mu, offset = take(
            frame.body,
            offset,
            TRACE_MASKED_IDENTITY_BYTES,
            "ticket c_mu",
        )
        gamma, offset = take(
            frame.body,
            offset,
            TRACE_TAG_BYTES,
            "ticket gamma",
        )
        c_r, c_z, pi_2 = decode_ticket_signature(frame.body[offset:])
        ticket = FinalTicketV0_1(
            ticket_suite_id=int.from_bytes(suite_raw, "big"),
            issuer_key_id=issuer_key_id,
            payload=FinalTicketPayloadV0_1(
                ctx=ctx,
                serial=serial,
                q=q,
                ciphertext=FinalTicketCiphertextV0_1(
                    s=syndrome,
                    c_mu=c_mu,
                    gamma=gamma,
                ),
            ),
            c_r=c_r,
            c_z=c_z,
            pi_2=pi_2,
        )
        if ticket.encode() != raw:
            raise FinalTicketEncodingError("noncanonical final Ticket")
        return ticket
    except FinalTicketEncodingError:
        raise
    except (EncodingError, TypeError, ValueError) as error:
        raise FinalTicketEncodingError("invalid final Ticket") from error


def _canonical_public_map(public_map: object) -> UOVPublicMap:
    if type(public_map) is not UOVPublicMap:
        raise TypeError("public_map must be exactly UOVPublicMap")
    rebuilt = decode_public_map(public_map.canonical_cpk)
    if rebuilt != public_map:
        raise FinalTicketEncodingError(
            "public_map does not equal its canonical expansion"
        )
    return public_map


def verify_ticket_cap(
    public_map: UOVPublicMap,
    ctx: bytes,
    u: bytes,
    encoded_signature: bytes,
) -> bool:
    """Verify one CAP signature using only the caller's explicit UOV map."""

    try:
        canonical_map = _canonical_public_map(public_map)
        context = _exact_bytes(ctx, "ctx", CONTEXT_BYTES)
        target = _exact_bytes(u, "u", H_RBBC_OUTPUT_BYTES)
        c_r, c_z, pi_2 = decode_ticket_signature(encoded_signature)
        statement = CAPStatement(canonical_map, context, target)
        return _verify_cap(statement, c_r, c_z, pi_2) is True
    except AssertionError:
        raise
    except Exception:
        return False


def verify_final_ticket_cap(
    public_map: UOVPublicMap,
    ticket: FinalTicketV0_1,
) -> bool:
    """Recompute ``d_M`` and ``u`` from one ticket before CAP verification."""

    try:
        if type(ticket) is not FinalTicketV0_1:
            return False
        canonical_ticket = decode_final_ticket(ticket.encode())
        d_m = canonical_ticket.payload.digest
        u = derive_h_rbbc(
            canonical_ticket.payload.ctx,
            d_m,
            canonical_ticket.c_r,
        )
        signature = encode_ticket_signature(
            canonical_ticket.c_r,
            canonical_ticket.c_z,
            canonical_ticket.pi_2,
        )
        return verify_ticket_cap(
            public_map,
            canonical_ticket.payload.ctx,
            u,
            signature,
        )
    except AssertionError:
        raise
    except Exception:
        return False


@dataclass(frozen=True, slots=True)
class FinalAccessRequestCoreV0_1:
    access_suite_id: int
    ctx: bytes
    ticket: bytes
    holder_public_key: bytes
    ue_kem_public_key: bytes
    fgs_id: bytes
    service_scope_digest: bytes
    requested_rights_digest: bytes
    request_time: int
    ue_nonce: bytes
    attempt_nonce: bytes
    channel_binding_mode: int
    channel_binding_digest: bytes

    def __post_init__(self) -> None:
        _validate_request_core(self)

    def encode(self) -> bytes:
        _validate_request_core(self)
        encoded = b"".join(
            (
                self.access_suite_id.to_bytes(2, "big"),
                self.ctx,
                encode_opaque32(
                    self.ticket,
                    max_length=FINAL_TICKET_MAX_BYTES,
                ),
                self.holder_public_key,
                self.ue_kem_public_key,
                self.fgs_id,
                self.service_scope_digest,
                self.requested_rights_digest,
                self.request_time.to_bytes(8, "big"),
                self.ue_nonce,
                self.attempt_nonce,
                self.channel_binding_mode.to_bytes(1, "big"),
                self.channel_binding_digest,
            )
        )
        expected = FINAL_REQUEST_CORE_FIXED_BYTES + len(self.ticket)
        if len(encoded) != expected:
            raise AssertionError("final B_U length ledger drift")
        return encoded


def _validate_request_core(
    value: object,
) -> FinalAccessRequestCoreV0_1:
    if type(value) is not FinalAccessRequestCoreV0_1:
        raise TypeError(
            "request core must be exactly FinalAccessRequestCoreV0_1"
        )
    suite = _exact_uint(value.access_suite_id, 16, "access_suite_id")
    if suite != ACCESS_SUITE_MEASUREMENT:
        raise FinalTicketEncodingError("unsupported V3 access suite")
    context = _exact_bytes(value.ctx, "request ctx", CONTEXT_BYTES)
    ticket_bytes = _exact_bytes(value.ticket, "request ticket")
    parsed_ticket = decode_final_ticket(ticket_bytes)
    if parsed_ticket.payload.ctx != context:
        raise FinalTicketEncodingError(
            "embedded ticket ctx does not match request ctx"
        )
    _exact_bytes(
        value.holder_public_key,
        "holder_public_key",
        ML_DSA_65_PUBLIC_KEY_BYTES,
    )
    _exact_bytes(
        value.ue_kem_public_key,
        "ue_kem_public_key",
        ML_KEM_768_PUBLIC_KEY_BYTES,
    )
    for name in (
        "fgs_id",
        "service_scope_digest",
        "requested_rights_digest",
    ):
        _exact_bytes(getattr(value, name), name, DIGEST_BYTES)
    _exact_uint(value.request_time, 64, "request_time")
    _exact_bytes(value.ue_nonce, "ue_nonce", NONCE_BYTES)
    _exact_bytes(value.attempt_nonce, "attempt_nonce", ATTEMPT_NONCE_BYTES)
    mode = _exact_uint(
        value.channel_binding_mode,
        8,
        "channel_binding_mode",
    )
    channel_digest = _exact_bytes(
        value.channel_binding_digest,
        "channel_binding_digest",
        DIGEST_BYTES,
    )
    if mode == CHANNEL_BINDING_NONE:
        if channel_digest != bytes(DIGEST_BYTES):
            raise FinalTicketEncodingError(
                "channel binding NONE requires a zero digest"
            )
    elif mode == CHANNEL_BINDING_AUTHENTICATED_EXPORTER:
        if channel_digest == bytes(DIGEST_BYTES):
            raise FinalTicketEncodingError(
                "authenticated channel binding requires a nonzero digest"
            )
    else:
        raise FinalTicketEncodingError("unknown channel binding mode")
    return value


def decode_final_request_core(encoded: bytes) -> FinalAccessRequestCoreV0_1:
    """Strictly decode and re-encode variable-length final ``B_U`` bytes."""

    raw = _exact_bytes(encoded, "encoded final B_U")
    if not FINAL_REQUEST_CORE_MIN_BYTES <= len(raw) <= FINAL_REQUEST_CORE_MAX_BYTES:
        raise FinalTicketEncodingError("final B_U length is outside profile range")
    try:
        offset = 0
        suite_raw, offset = take(raw, offset, 2, "B_U access suite")
        ctx, offset = take(raw, offset, CONTEXT_BYTES, "B_U ctx")
        ticket, offset = decode_opaque32(
            raw,
            offset,
            max_length=FINAL_TICKET_MAX_BYTES,
            name="B_U ticket",
        )
        holder_public_key, offset = take(
            raw,
            offset,
            ML_DSA_65_PUBLIC_KEY_BYTES,
            "B_U holder_public_key",
        )
        ue_kem_public_key, offset = take(
            raw,
            offset,
            ML_KEM_768_PUBLIC_KEY_BYTES,
            "B_U ue_kem_public_key",
        )
        fgs_id, offset = take(raw, offset, DIGEST_BYTES, "B_U fgs_id")
        service, offset = take(
            raw,
            offset,
            DIGEST_BYTES,
            "B_U service_scope_digest",
        )
        rights, offset = take(
            raw,
            offset,
            DIGEST_BYTES,
            "B_U requested_rights_digest",
        )
        request_time, offset = take(raw, offset, 8, "B_U request_time")
        ue_nonce, offset = take(raw, offset, NONCE_BYTES, "B_U ue_nonce")
        attempt_nonce, offset = take(
            raw,
            offset,
            ATTEMPT_NONCE_BYTES,
            "B_U attempt_nonce",
        )
        channel_mode, offset = take(
            raw,
            offset,
            1,
            "B_U channel_binding_mode",
        )
        channel_digest, offset = take(
            raw,
            offset,
            DIGEST_BYTES,
            "B_U channel_binding_digest",
        )
        if offset != len(raw):
            raise FinalTicketEncodingError("final B_U has trailing bytes")
        core = FinalAccessRequestCoreV0_1(
            access_suite_id=int.from_bytes(suite_raw, "big"),
            ctx=ctx,
            ticket=ticket,
            holder_public_key=holder_public_key,
            ue_kem_public_key=ue_kem_public_key,
            fgs_id=fgs_id,
            service_scope_digest=service,
            requested_rights_digest=rights,
            request_time=int.from_bytes(request_time, "big"),
            ue_nonce=ue_nonce,
            attempt_nonce=attempt_nonce,
            channel_binding_mode=channel_mode[0],
            channel_binding_digest=channel_digest,
        )
        if core.encode() != raw:
            raise FinalTicketEncodingError("noncanonical final B_U")
        return core
    except FinalTicketEncodingError:
        raise
    except (EncodingError, TypeError, ValueError) as error:
        raise FinalTicketEncodingError("invalid final B_U") from error


@dataclass(frozen=True, slots=True)
class FinalAccessRequestV0_1:
    core: FinalAccessRequestCoreV0_1
    holder_signature: bytes

    def __post_init__(self) -> None:
        _validate_access_request(self)

    def encode(self) -> bytes:
        _validate_access_request(self)
        core_bytes = self.core.encode()
        body = (
            encode_opaque32(
                core_bytes,
                max_length=FINAL_REQUEST_CORE_MAX_BYTES,
            )
            + self.holder_signature
        )
        encoded = encode_frame_v3(FrameTypeV3.ACCESS_REQUEST, body)
        expected = FINAL_ACCESS_REQUEST_FIXED_BYTES + len(self.core.ticket)
        if len(encoded) != expected:
            raise AssertionError("final M1 length ledger drift")
        return encoded


def _validate_access_request(value: object) -> FinalAccessRequestV0_1:
    if type(value) is not FinalAccessRequestV0_1:
        raise TypeError("request must be exactly FinalAccessRequestV0_1")
    _validate_request_core(value.core)
    _exact_bytes(
        value.holder_signature,
        "holder_signature",
        ML_DSA_65_SIGNATURE_BYTES,
    )
    return value


def decode_final_access_request(encoded: bytes) -> FinalAccessRequestV0_1:
    """Strictly decode and completely re-encode final-profile M1 bytes."""

    raw = _exact_bytes(encoded, "encoded final M1")
    if not FINAL_ACCESS_REQUEST_MIN_BYTES <= len(raw) <= FINAL_ACCESS_REQUEST_MAX_BYTES:
        raise FinalTicketEncodingError("final M1 length is outside profile range")
    try:
        frame = decode_frame_v3(
            raw,
            expected_type=FrameTypeV3.ACCESS_REQUEST,
            max_body_bytes=FINAL_ACCESS_REQUEST_MAX_BYTES - FRAME_HEADER_BYTES,
        )
        core_bytes, offset = decode_opaque32(
            frame.body,
            0,
            max_length=FINAL_REQUEST_CORE_MAX_BYTES,
            name="M1 B_U",
        )
        holder_signature, offset = take(
            frame.body,
            offset,
            ML_DSA_65_SIGNATURE_BYTES,
            "M1 holder signature",
        )
        if offset != len(frame.body):
            raise FinalTicketEncodingError("final M1 has trailing bytes")
        request = FinalAccessRequestV0_1(
            core=decode_final_request_core(core_bytes),
            holder_signature=holder_signature,
        )
        if request.encode() != raw:
            raise FinalTicketEncodingError("noncanonical final M1")
        return request
    except FinalTicketEncodingError:
        raise
    except (EncodingError, TypeError, ValueError) as error:
        raise FinalTicketEncodingError("invalid final M1") from error


def _verify_holder_signature(
    provider: MLDSA65Provider,
    public_key: bytes,
    ctx: bytes,
    core_bytes: bytes,
    signature: bytes,
) -> bool:
    descriptor = provider.descriptor
    if descriptor.algorithm != "ML-DSA":
        return False
    if descriptor.parameter_set != "ML-DSA-65":
        return False
    if (
        descriptor.native_context_capability
        is not NativeContextCapability.NON_EMPTY
    ):
        return False
    native_context = native_signature_context(SignatureRole.HOLDER, ctx)
    if not native_context:
        raise AssertionError("holder native context must be non-empty")
    return (
        provider.verify(
            public_key,
            core_bytes,
            signature,
            native_context,
        )
        is True
    )


def verify_final_access_request(
    request: FinalAccessRequestV0_1,
    *,
    public_map: UOVPublicMap,
    mldsa_provider: MLDSA65Provider,
) -> bool:
    """Verify strict M1, ticket CAP, holder binding, then holder signature."""

    try:
        if type(request) is not FinalAccessRequestV0_1:
            return False

        # Step 1: force the exact object back through the strict M1 parser.
        canonical_request = decode_final_access_request(request.encode())
        core = canonical_request.core
        core_bytes = core.encode()

        # Steps 2 and 3: independently parse the embedded ticket and join ctx.
        ticket = decode_final_ticket(core.ticket)
        if core.ctx != ticket.payload.ctx:
            return False

        # Step 4: no issuer registry, global map, or ctx-as-seed fallback.
        if not verify_final_ticket_cap(public_map, ticket):
            return False

        # Step 5: bind the exact ML-DSA-65 public key to q.
        expected_q = holder_public_key_binding(
            core.ctx,
            core.holder_public_key,
        )
        if not hmac.compare_digest(ticket.payload.q, expected_q):
            return False

        # Step 6: verify the unchanged B_U bytes under HOLDER native context.
        return _verify_holder_signature(
            mldsa_provider,
            core.holder_public_key,
            core.ctx,
            core_bytes,
            canonical_request.holder_signature,
        )
    except AssertionError:
        raise
    except Exception:
        return False


__all__ = (
    "ACCESS_SUITE_MEASUREMENT",
    "ATTEMPT_NONCE_BYTES",
    "CHANNEL_BINDING_AUTHENTICATED_EXPORTER",
    "CHANNEL_BINDING_NONE",
    "CONTEXT_BYTES",
    "C_R_BYTES",
    "C_Z_BYTES",
    "DIGEST_BYTES",
    "FINAL_ACCESS_REQUEST_FIXED_BYTES",
    "FINAL_ACCESS_REQUEST_MAX_BYTES",
    "FINAL_ACCESS_REQUEST_MIN_BYTES",
    "FINAL_REQUEST_CORE_FIXED_BYTES",
    "FINAL_REQUEST_CORE_MAX_BYTES",
    "FINAL_REQUEST_CORE_MIN_BYTES",
    "FINAL_TICKET_FIXED_BYTES",
    "FINAL_TICKET_MAX_BYTES",
    "FINAL_TICKET_MIN_BYTES",
    "FinalAccessRequestCoreV0_1",
    "FinalAccessRequestV0_1",
    "FinalTicketCiphertextV0_1",
    "FinalTicketEncodingError",
    "FinalTicketPayloadV0_1",
    "FinalTicketV0_1",
    "H_RBBC_DOMAIN",
    "H_RBBC_OUTPUT_BYTES",
    "PI_2_MAX_BYTES",
    "PI_2_MIN_BYTES",
    "PQSAT_BLIND_UOV_PROFILE_FINGERPRINT",
    "PQSAT_BLIND_UOV_RESEARCH_SUITE",
    "TRACE_MASKED_IDENTITY_BYTES",
    "TRACE_SYNDROME_BYTES",
    "TRACE_TAG_BYTES",
    "decode_final_access_request",
    "decode_final_request_core",
    "decode_final_ticket",
    "decode_ticket_signature",
    "derive_h_rbbc",
    "encode_ticket_signature",
    "verify_final_access_request",
    "verify_final_ticket_cap",
    "verify_ticket_cap",
)
