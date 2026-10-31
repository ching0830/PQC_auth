"""Ordinary evaluator for the PQ-SAT V3 final trace research profile.

This module implements one deterministic mathematical profile only.  It does
not generate or certify Classic McEliece keys, implement threshold decoding or
OA DKG, qualify a provider, or provide a production encryption API.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field


N_BITS = 6_688
SYNDROME_BITS = 1_664
TAIL_BITS = 5_024
ERROR_WEIGHT = 128
ERROR_BYTES = 836
SYNDROME_BYTES = 208
TAIL_ROW_BYTES = 628
TAIL_BYTES = 1_044_992
C_MU_BYTES = 48
GAMMA_BYTES = 32

TRACE_PARAMETER_DIGEST = bytes.fromhex(
    "c40fea13591b81dc193109eee38768c7eb198e095bb3639f37b7be7b82b66645"
)

_KDF_DOMAIN = b"PQSAT-V3/TRACE-KDF/v0.1"
_MAC_CUSTOMIZATION = b"PQSAT-V3/TRACE-MAC/v0.1"
_KEY_ID_DOMAIN = b"PQSAT-V3/TRACE-PUBLIC-KEY-ID/v0.1"
_KEY_SERIALIZATION_ID = b"classic-mceliece-T-row-major-lsb0-v2022-10-23"
_CSHAKE256_RATE = 136
_MASK64 = (1 << 64) - 1

_RHO = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

_ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)


class TraceEvaluationError(ValueError):
    """A non-canonical or out-of-profile trace evaluator input."""


def _require_exact_bytes(value: object, expected: int, name: str) -> bytes:
    if type(value) is not bytes:
        raise TraceEvaluationError(f"{name} must be exact bytes")
    if len(value) != expected:
        raise TraceEvaluationError(f"{name} must be exactly {expected} bytes")
    return value


@dataclass(frozen=True, slots=True)
class TracePublicKeyV0_1:
    """The exact row-major, LSB-first serialization of the matrix ``T``."""

    tail: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_exact_bytes(self.tail, TAIL_BYTES, "tail")

    @property
    def sha256(self) -> bytes:
        return hashlib.sha256(self.tail).digest()

    @property
    def key_id(self) -> bytes:
        material = (
            _KEY_ID_DOMAIN
            + b"\x00"
            + len(_KEY_SERIALIZATION_ID).to_bytes(2, "big")
            + _KEY_SERIALIZATION_ID
            + len(self.tail).to_bytes(4, "big")
            + self.tail
        )
        return hashlib.sha256(material).digest()


@dataclass(frozen=True, slots=True)
class TraceCiphertextV0_1:
    s: bytes
    c_mu: bytes
    gamma: bytes

    def __post_init__(self) -> None:
        _require_exact_bytes(self.s, SYNDROME_BYTES, "s")
        _require_exact_bytes(self.c_mu, C_MU_BYTES, "c_mu")
        _require_exact_bytes(self.gamma, GAMMA_BYTES, "gamma")


def encode_error_vector(positions: tuple[int, ...]) -> bytes:
    """Encode exactly 128 increasing error positions using LSB-first bits."""

    if type(positions) is not tuple:
        raise TraceEvaluationError("positions must be an exact tuple")
    if len(positions) != ERROR_WEIGHT:
        raise TraceEvaluationError("positions must contain exactly 128 entries")

    encoded = bytearray(ERROR_BYTES)
    previous = -1
    for position in positions:
        if type(position) is not int:
            raise TraceEvaluationError("each position must be an exact int")
        if not 0 <= position < N_BITS:
            raise TraceEvaluationError("position is outside 0..6687")
        if position <= previous:
            raise TraceEvaluationError("positions must be strictly increasing and unique")
        encoded[position // 8] |= 1 << (position % 8)
        previous = position
    return bytes(encoded)


def validate_error_vector(encoded: bytes) -> None:
    """Reject every non-canonical encoded error outside the fixed profile."""

    canonical = _require_exact_bytes(encoded, ERROR_BYTES, "encoded_error")
    if sum(byte.bit_count() for byte in canonical) != ERROR_WEIGHT:
        raise TraceEvaluationError("encoded_error must have Hamming weight 128")


def _require_public_key(public_key: object) -> TracePublicKeyV0_1:
    if type(public_key) is not TracePublicKeyV0_1:
        raise TraceEvaluationError("public_key must be exact TracePublicKeyV0_1")
    return public_key


def derive_syndrome(
    public_key: TracePublicKeyV0_1,
    encoded_error: bytes,
) -> bytes:
    """Return ``EncodeBits(H_C e^T)`` for ``H_C=(I_1664|T)``."""

    key = _require_public_key(public_key)
    validate_error_vector(encoded_error)

    # The first 1,664 coordinates multiply the systematic identity block.
    syndrome = bytearray(encoded_error[:SYNDROME_BYTES])
    encoded_tail_error = encoded_error[SYNDROME_BYTES:]

    # Each selected tail coordinate addresses the same LSB-first bit in every
    # 628-byte row.  T itself is serialized row by row without padding.
    for byte_index, selected in enumerate(encoded_tail_error):
        while selected:
            low_bit = selected & -selected
            bit_index = low_bit.bit_length() - 1
            tail_column = 8 * byte_index + bit_index
            column_byte = tail_column // 8
            column_mask = 1 << (tail_column % 8)
            for row in range(SYNDROME_BITS):
                if key.tail[row * TAIL_ROW_BYTES + column_byte] & column_mask:
                    syndrome[row // 8] ^= 1 << (row % 8)
            selected ^= low_bit
    return bytes(syndrome)


def _rot64(value: int, amount: int) -> int:
    if amount == 0:
        return value & _MASK64
    return ((value << amount) | (value >> (64 - amount))) & _MASK64


def _keccak_f1600(state: list[int]) -> None:
    for round_constant in _ROUND_CONSTANTS:
        columns = [
            state[x]
            ^ state[x + 5]
            ^ state[x + 10]
            ^ state[x + 15]
            ^ state[x + 20]
            for x in range(5)
        ]
        delta = [
            columns[(x - 1) % 5] ^ _rot64(columns[(x + 1) % 5], 1)
            for x in range(5)
        ]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= delta[x]

        moved = [0] * 25
        for y in range(5):
            for x in range(5):
                moved[y + 5 * ((2 * x + 3 * y) % 5)] = _rot64(
                    state[x + 5 * y], _RHO[x][y]
                )

        for y in range(5):
            row = moved[5 * y : 5 * y + 5]
            for x in range(5):
                state[x + 5 * y] = (
                    row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
                ) & _MASK64
        state[0] ^= round_constant


def _keccak_sponge(data: bytes, output_bytes: int, suffix: int) -> bytes:
    padded = bytearray(data)
    padded.extend(bytes(_CSHAKE256_RATE - len(padded) % _CSHAKE256_RATE))
    padded[len(data)] ^= suffix
    padded[-1] ^= 0x80

    state = [0] * 25
    for offset in range(0, len(padded), _CSHAKE256_RATE):
        block = padded[offset : offset + _CSHAKE256_RATE]
        for lane in range(_CSHAKE256_RATE // 8):
            start = 8 * lane
            state[lane] ^= int.from_bytes(block[start : start + 8], "little")
        _keccak_f1600(state)

    output = bytearray()
    while len(output) < output_bytes:
        rate_bytes = b"".join(
            lane.to_bytes(8, "little")
            for lane in state[: _CSHAKE256_RATE // 8]
        )
        output.extend(rate_bytes[: output_bytes - len(output)])
        if len(output) < output_bytes:
            _keccak_f1600(state)
    return bytes(output)


def _left_encode(value: int) -> bytes:
    width = max(1, (value.bit_length() + 7) // 8)
    return bytes((width,)) + value.to_bytes(width, "big")


def _right_encode(value: int) -> bytes:
    width = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(width, "big") + bytes((width,))


def _encode_string(value: bytes) -> bytes:
    return _left_encode(8 * len(value)) + value


def _bytepad(value: bytes) -> bytes:
    encoded = _left_encode(_CSHAKE256_RATE) + value
    return encoded + bytes((-len(encoded)) % _CSHAKE256_RATE)


def _cshake256(
    data: bytes,
    output_bytes: int,
    function_name: bytes,
    customization: bytes,
) -> bytes:
    prefix = _bytepad(_encode_string(function_name) + _encode_string(customization))
    return _keccak_sponge(prefix + data, output_bytes, 0x04)


def _kmac256(key: bytes, data: bytes) -> bytes:
    new_input = _bytepad(_encode_string(key)) + data + _right_encode(256)
    return _cshake256(new_input, GAMMA_BYTES, b"KMAC", _MAC_CUSTOMIZATION)


def _validate_trace_inputs(
    *, ctx: bytes, sn: bytes, q: bytes, rid: bytes, encoded_error: bytes
) -> None:
    _require_exact_bytes(ctx, 32, "ctx")
    _require_exact_bytes(sn, 16, "sn")
    _require_exact_bytes(q, 48, "q")
    _require_exact_bytes(rid, 32, "rid")
    validate_error_vector(encoded_error)


def derive_trace_ciphertext(
    public_key: TracePublicKeyV0_1,
    *,
    ctx: bytes,
    sn: bytes,
    q: bytes,
    rid: bytes,
    encoded_error: bytes,
) -> TraceCiphertextV0_1:
    """Derive the unique research-profile ciphertext for a valid witness."""

    key = _require_public_key(public_key)
    _validate_trace_inputs(
        ctx=ctx, sn=sn, q=q, rid=rid, encoded_error=encoded_error
    )
    syndrome = derive_syndrome(key, encoded_error)
    associated_data = ctx + sn + q
    stream = hashlib.shake_256(
        _KDF_DOMAIN + ctx + encoded_error + syndrome + associated_data
    ).digest(80)
    pad = stream[:C_MU_BYTES]
    mac_key = stream[C_MU_BYTES:]
    c_mu = bytes(left ^ right for left, right in zip(rid + sn, pad))
    gamma = _kmac256(mac_key, syndrome + c_mu + associated_data)
    return TraceCiphertextV0_1(s=syndrome, c_mu=c_mu, gamma=gamma)


def verify_trace_ciphertext_witness(
    public_key: TracePublicKeyV0_1,
    *,
    ctx: bytes,
    sn: bytes,
    q: bytes,
    rid: bytes,
    encoded_error: bytes,
    ciphertext: TraceCiphertextV0_1,
) -> bool:
    """Recompute a valid witness and compare all ciphertext components."""

    if type(ciphertext) is not TraceCiphertextV0_1:
        raise TraceEvaluationError(
            "ciphertext must be exact TraceCiphertextV0_1"
        )
    expected = derive_trace_ciphertext(
        public_key,
        ctx=ctx,
        sn=sn,
        q=q,
        rid=rid,
        encoded_error=encoded_error,
    )
    return hmac.compare_digest(
        expected.s + expected.c_mu + expected.gamma,
        ciphertext.s + ciphertext.c_mu + ciphertext.gamma,
    )


__all__ = [
    "TraceEvaluationError",
    "TracePublicKeyV0_1",
    "TraceCiphertextV0_1",
    "encode_error_vector",
    "validate_error_vector",
    "derive_syndrome",
    "derive_trace_ciphertext",
    "verify_trace_ciphertext_witness",
]
