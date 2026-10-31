"""Research/reference UOV-III issuer-map layer for PQ-SAT V3.

This module implements the pinned UOV Round-2 ``uov-III-pkc-skc`` map/key
layer and the separately specified PQ-SAT target inverter, issuer-map
registry, resolver, and explicit-map relation ABI.  It intentionally uses
only deterministic local computation: there is no process-global map,
registry, randomness source, benchmark, or file write.

The implementation is pure Python and is *not* constant-time.  Python cannot
provide auditable zeroization for the immutable secret values used here.  It
is therefore a research/reference implementation, not a qualified production
cryptographic provider.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Final


N: Final = 184
M: Final = 72
V: Final = 112
O: Final = 72
MONOMIAL_COUNT: Final = 17_020
P1_POSITIONS: Final = V * (V + 1) // 2
P2_POSITIONS: Final = V * O
P3_POSITIONS: Final = O * (O + 1) // 2
P1_BYTES: Final = P1_POSITIONS * M
P2_BYTES: Final = P2_POSITIONS * M
P3_BYTES: Final = P3_POSITIONS * M
PUBLIC_STREAM_BYTES: Final = P1_BYTES + P2_BYTES
CPK_BYTES: Final = 16 + P3_BYTES
DENSE_BYTES: Final = M * MONOMIAL_COUNT
CSK_BYTES: Final = 32

CONTRACT_ID: Final = b"PQSAT-UOV-III-ISSUER-MAP-CONTRACT-v0.1"
PUBLIC_MAP_DIGEST_DOMAIN: Final = (
    b"PQSAT-UOV-III-ISSUER-MAP/v0.1/PUBLIC-MAP-DIGEST"
)
ISSUER_KEY_ID_DOMAIN: Final = b"PQSAT-UOV-III-ISSUER-MAP/v0.1/ISSUER-KEY-ID"
REGISTRY_DIGEST_DOMAIN: Final = (
    b"PQSAT-UOV-III-ISSUER-MAP/v0.1/REGISTRY-DIGEST"
)
INVERT_VINEGAR_DOMAIN: Final = (
    b"PQSAT-UOV-III-ISSUER-MAP/v0.1/INVERT-VINEGAR"
)

STATUS_ACTIVE: Final = 1
STATUS_REVOKED: Final = 2


class UOVError(Exception):
    """Base class for controlled UOV issuer-map failures."""


class UOVTypeError(UOVError, TypeError):
    """An input did not use the exact canonical Python type."""


class UOVEncodingError(UOVError, ValueError):
    """An input had a noncanonical value, length, or byte encoding."""


class UOVIntegrityError(UOVError):
    """An internal or authenticated identity check failed."""


class UOVInversionError(UOVError):
    """No verified target preimage was produced within the fixed boundary."""


class IssuerMapRegistryError(UOVError, ValueError):
    """An issuer-map registry failed canonical/authenticated validation."""


class IssuerMapResolutionError(UOVError, LookupError):
    """A requested active issuer-map binding could not be resolved."""


def _require_bytes(value: object, length: int, name: str) -> bytes:
    if type(value) is not bytes:
        raise UOVTypeError(f"{name} must be exactly bytes")
    if len(value) != length:
        raise UOVEncodingError(f"{name} must contain exactly {length} bytes")
    return value


def _require_status(value: object, name: str = "status") -> int:
    if type(value) is not int:
        raise UOVTypeError(f"{name} must be exactly int; bool is forbidden")
    if value not in (STATUS_ACTIVE, STATUS_REVOKED):
        raise UOVEncodingError(f"{name} must be 1 (active) or 2 (revoked)")
    return value


def _tuple_encode(domain: bytes, fields: tuple[bytes, ...]) -> bytes:
    if type(domain) is not bytes:
        raise UOVTypeError("domain must be exactly bytes")
    if len(domain) > 0xFFFF:
        raise UOVEncodingError("domain exceeds the u16 length boundary")
    if type(fields) is not tuple:
        raise UOVTypeError("fields must be exactly tuple")
    if len(fields) > 0xFFFF:
        raise UOVEncodingError("field count exceeds the u16 boundary")
    encoded = bytearray(len(domain).to_bytes(2, "big"))
    encoded.extend(domain)
    encoded.extend(len(fields).to_bytes(2, "big"))
    for index, field in enumerate(fields):
        if type(field) is not bytes:
            raise UOVTypeError(f"fields[{index}] must be exactly bytes")
        if len(field) > 0xFFFFFFFF:
            raise UOVEncodingError(f"fields[{index}] exceeds the u32 boundary")
        encoded.extend(len(field).to_bytes(4, "big"))
        encoded.extend(field)
    return bytes(encoded)


def _shake_tuple(domain: bytes, fields: tuple[bytes, ...], output_bytes: int) -> bytes:
    if type(output_bytes) is not int:
        raise UOVTypeError("output_bytes must be exactly int; bool is forbidden")
    if output_bytes < 0:
        raise UOVEncodingError("output_bytes must be nonnegative")
    return hashlib.shake_256(_tuple_encode(domain, fields)).digest(output_bytes)


# ---------------------------------------------------------------------------
# GF(256), fixed to x^8+x^4+x^3+x+1 (0x11B).


def _gf_mul_byte(left: int, right: int) -> int:
    result = 0
    multiplicand = left
    multiplier = right
    for _ in range(8):
        if multiplier & 1:
            result ^= multiplicand
        multiplier >>= 1
        multiplicand = (
            ((multiplicand << 1) & 0xFF)
            ^ (0x1B if multiplicand & 0x80 else 0)
        )
    return result


_GF_ROWS: Final = tuple(
    bytes(_gf_mul_byte(left, right) for right in range(256))
    for left in range(256)
)


def _gf_inverse(value: int) -> int:
    if value == 0:
        raise ZeroDivisionError("zero has no GF(256) inverse")
    result = 1
    base = value
    exponent = 254
    while exponent:
        if exponent & 1:
            result = _GF_ROWS[result][base]
        base = _GF_ROWS[base][base]
        exponent >>= 1
    return result


_PACKED_72_MASK: Final = (1 << (8 * M)) - 1
_PACKED_72_LSB: Final = int.from_bytes(b"\x01" * M, "little")
_PACKED_72_MSB: Final = _PACKED_72_LSB << 7


def _packed_xtime(value: int) -> int:
    high_coefficients = value & _PACKED_72_MSB
    carry = high_coefficients >> 7
    return (
        ((value ^ high_coefficients) << 1)
        ^ carry
        ^ (carry << 1)
        ^ (carry << 3)
        ^ (carry << 4)
    )


def _packed_basis(value: int) -> tuple[int, int, int, int, int, int, int, int]:
    values = [value]
    for _ in range(7):
        values.append(_packed_xtime(values[-1]))
    return (
        values[0],
        values[1],
        values[2],
        values[3],
        values[4],
        values[5],
        values[6],
        values[7],
    )


def _packed_select(
    basis: tuple[int, int, int, int, int, int, int, int], scalar: int
) -> int:
    result = 0
    bit = 0
    remaining = scalar
    while remaining:
        if remaining & 1:
            result ^= basis[bit]
        remaining >>= 1
        bit += 1
    return result


def _packed_mul(value: int, scalar: int) -> int:
    if scalar == 0 or value == 0:
        return 0
    return _packed_select(_packed_basis(value), scalar)


# ---------------------------------------------------------------------------
# Full 10-round AES-128 and the exact official public-input CTR stream.


def _rotl8(value: int, count: int) -> int:
    return ((value << count) | (value >> (8 - count))) & 0xFF


def _aes_sbox_value(value: int) -> int:
    inverse = 0 if value == 0 else _gf_inverse(value)
    return (
        inverse
        ^ _rotl8(inverse, 1)
        ^ _rotl8(inverse, 2)
        ^ _rotl8(inverse, 3)
        ^ _rotl8(inverse, 4)
        ^ 0x63
    )


_AES_SBOX: Final = tuple(_aes_sbox_value(value) for value in range(256))


def _ror32(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & 0xFFFFFFFF


def _aes_table_zero(value: int) -> int:
    substituted = _AES_SBOX[value]
    doubled = _GF_ROWS[2][substituted]
    tripled = doubled ^ substituted
    return (
        (doubled << 24)
        | (substituted << 16)
        | (substituted << 8)
        | tripled
    )


_AES_TE0: Final = tuple(_aes_table_zero(value) for value in range(256))
_AES_TE1: Final = tuple(_ror32(value, 8) for value in _AES_TE0)
_AES_TE2: Final = tuple(_ror32(value, 16) for value in _AES_TE0)
_AES_TE3: Final = tuple(_ror32(value, 24) for value in _AES_TE0)


def _aes128_round_keys(key: bytes) -> tuple[int, ...]:
    _require_bytes(key, 16, "AES-128 key")
    words = [int.from_bytes(key[offset : offset + 4], "big") for offset in range(0, 16, 4)]
    rcon = 1
    while len(words) < 44:
        temporary = words[-1]
        if len(words) % 4 == 0:
            temporary = ((temporary << 8) | (temporary >> 24)) & 0xFFFFFFFF
            temporary = (
                (_AES_SBOX[(temporary >> 24) & 0xFF] << 24)
                | (_AES_SBOX[(temporary >> 16) & 0xFF] << 16)
                | (_AES_SBOX[(temporary >> 8) & 0xFF] << 8)
                | _AES_SBOX[temporary & 0xFF]
            )
            temporary ^= rcon << 24
            rcon = _GF_ROWS[2][rcon]
        words.append(words[-4] ^ temporary)
    return tuple(words)


def _aes128_encrypt_with_round_keys(block: bytes, round_keys: tuple[int, ...]) -> bytes:
    _require_bytes(block, 16, "AES block")
    if type(round_keys) is not tuple or len(round_keys) != 44:
        raise UOVTypeError("AES round_keys must be one exact 44-word tuple")
    state = [
        int.from_bytes(block[offset : offset + 4], "big") ^ round_keys[offset // 4]
        for offset in range(0, 16, 4)
    ]
    for round_index in range(1, 10):
        s0, s1, s2, s3 = state
        base = 4 * round_index
        state = [
            _AES_TE0[(s0 >> 24) & 0xFF]
            ^ _AES_TE1[(s1 >> 16) & 0xFF]
            ^ _AES_TE2[(s2 >> 8) & 0xFF]
            ^ _AES_TE3[s3 & 0xFF]
            ^ round_keys[base],
            _AES_TE0[(s1 >> 24) & 0xFF]
            ^ _AES_TE1[(s2 >> 16) & 0xFF]
            ^ _AES_TE2[(s3 >> 8) & 0xFF]
            ^ _AES_TE3[s0 & 0xFF]
            ^ round_keys[base + 1],
            _AES_TE0[(s2 >> 24) & 0xFF]
            ^ _AES_TE1[(s3 >> 16) & 0xFF]
            ^ _AES_TE2[(s0 >> 8) & 0xFF]
            ^ _AES_TE3[s1 & 0xFF]
            ^ round_keys[base + 2],
            _AES_TE0[(s3 >> 24) & 0xFF]
            ^ _AES_TE1[(s0 >> 16) & 0xFF]
            ^ _AES_TE2[(s1 >> 8) & 0xFF]
            ^ _AES_TE3[s2 & 0xFF]
            ^ round_keys[base + 3],
        ]

    s0, s1, s2, s3 = state
    final_words = (
        (_AES_SBOX[(s0 >> 24) & 0xFF] << 24)
        | (_AES_SBOX[(s1 >> 16) & 0xFF] << 16)
        | (_AES_SBOX[(s2 >> 8) & 0xFF] << 8)
        | _AES_SBOX[s3 & 0xFF],
        (_AES_SBOX[(s1 >> 24) & 0xFF] << 24)
        | (_AES_SBOX[(s2 >> 16) & 0xFF] << 16)
        | (_AES_SBOX[(s3 >> 8) & 0xFF] << 8)
        | _AES_SBOX[s0 & 0xFF],
        (_AES_SBOX[(s2 >> 24) & 0xFF] << 24)
        | (_AES_SBOX[(s3 >> 16) & 0xFF] << 16)
        | (_AES_SBOX[(s0 >> 8) & 0xFF] << 8)
        | _AES_SBOX[s1 & 0xFF],
        (_AES_SBOX[(s3 >> 24) & 0xFF] << 24)
        | (_AES_SBOX[(s0 >> 16) & 0xFF] << 16)
        | (_AES_SBOX[(s1 >> 8) & 0xFF] << 8)
        | _AES_SBOX[s2 & 0xFF],
    )
    return b"".join(
        (word ^ round_keys[40 + index]).to_bytes(4, "big")
        for index, word in enumerate(final_words)
    )


def _aes128_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Internal full-round AES-128 primitive, exposed only for KAT tests."""

    return _aes128_encrypt_with_round_keys(block, _aes128_round_keys(key))


def _expand_public_stream(seedpk: bytes) -> bytes:
    canonical_seed = _require_bytes(seedpk, 16, "seedpk")
    round_keys = _aes128_round_keys(canonical_seed)
    output = bytearray(PUBLIC_STREAM_BYTES)
    for counter in range(PUBLIC_STREAM_BYTES // 16):
        block = b"\x00" * 12 + counter.to_bytes(4, "big")
        offset = counter * 16
        output[offset : offset + 16] = _aes128_encrypt_with_round_keys(
            block, round_keys
        )
    return bytes(output)


# ---------------------------------------------------------------------------
# Official key expansion, P3 derivation, and PQ-SAT dense reorder.


def _vectors(raw: bytes, positions: int, name: str) -> list[int]:
    _require_bytes(raw, positions * M, name)
    return [
        int.from_bytes(raw[offset : offset + M], "little")
        for offset in range(0, len(raw), M)
    ]


def _vectors_bytes(vectors: list[int]) -> bytes:
    return b"".join(value.to_bytes(M, "little") for value in vectors)


def _calculate_p3_and_optional_s(
    p1: list[int], p2: list[int], secret_o: bytes, *, include_s: bool
) -> tuple[list[int], list[int] | None]:
    if type(p1) is not list or len(p1) != P1_POSITIONS:
        raise UOVIntegrityError("P1 vector representation is invalid")
    if type(p2) is not list or len(p2) != P2_POSITIONS:
        raise UOVIntegrityError("P2 vector representation is invalid")
    canonical_o = _require_bytes(secret_o, V * O, "O")

    # A = P1*O + P2.  If requested, build
    # S = (P1+transpose(P1))*O + P2 alongside A.  All packed integers contain
    # the 72 equation coefficients of one Macaulay position.
    a_matrix = p2.copy()
    s_matrix = p2.copy() if include_s else None
    p1_position = 0
    for row in range(V):
        row_base = row * O
        for column in range(row, V):
            coefficient = p1[p1_position]
            p1_position += 1
            basis = _packed_basis(coefficient)
            for oil in range(O):
                product = _packed_select(
                    basis, canonical_o[oil * V + column]
                )
                a_matrix[row_base + oil] ^= product
                if s_matrix is not None and row != column:
                    s_matrix[row_base + oil] ^= product
                    s_matrix[column * O + oil] ^= _packed_select(
                        basis, canonical_o[oil * V + row]
                    )

    # P3 = Upper(O^T*A).  The official ``Upper`` operation folds each lower
    # off-diagonal coefficient into its upper counterpart (XOR in
    # characteristic two); it is not a simple extraction of the upper half.
    # The loop order writes official upper-triangular Macaulay order: oil row
    # first, then oil column.
    p3_matrix = [0] * P3_POSITIONS
    for vinegar in range(V):
        row_bases = tuple(
            _packed_basis(a_matrix[vinegar * O + oil]) for oil in range(O)
        )
        for oil_row in range(O):
            for oil_column in range(oil_row, O):
                position = (
                    oil_row * O
                    - oil_row * (oil_row - 1) // 2
                    + (oil_column - oil_row)
                )
                p3_matrix[position] ^= _packed_select(
                    row_bases[oil_column],
                    canonical_o[oil_row * V + vinegar],
                )
                if oil_row != oil_column:
                    p3_matrix[position] ^= _packed_select(
                        row_bases[oil_row],
                        canonical_o[oil_column * V + vinegar],
                    )
    return p3_matrix, s_matrix


def _dense_from_vectors(
    p1: list[int], p2: list[int], p3: list[int]
) -> bytes:
    if len(p1) != P1_POSITIONS or len(p2) != P2_POSITIONS or len(p3) != P3_POSITIONS:
        raise UOVIntegrityError("expanded public-map component shape is invalid")
    dense = bytearray(DENSE_BYTES)
    monomial = 0
    for first in range(N):
        for second in range(first, N):
            if second < V:
                position = (
                    first * V
                    - first * (first - 1) // 2
                    + (second - first)
                )
                coefficient = p1[position]
            elif first < V:
                coefficient = p2[first * O + (second - V)]
            else:
                local_first = first - V
                local_second = second - V
                position = (
                    local_first * O
                    - local_first * (local_first - 1) // 2
                    + (local_second - local_first)
                )
                coefficient = p3[position]
            dense[monomial::MONOMIAL_COUNT] = coefficient.to_bytes(M, "little")
            monomial += 1
    if monomial != MONOMIAL_COUNT:
        raise UOVIntegrityError("dense public-map reorder did not cover every monomial")
    return bytes(dense)


def _expand_cpk(encoded: bytes) -> tuple[bytes, list[int], list[int], list[int], bytes]:
    canonical = _require_bytes(encoded, CPK_BYTES, "compressed public key")
    seedpk = canonical[:16]
    public_stream = _expand_public_stream(seedpk)
    p1_raw = public_stream[:P1_BYTES]
    p2_raw = public_stream[P1_BYTES:]
    p3_raw = canonical[16:]
    p1 = _vectors(p1_raw, P1_POSITIONS, "P1")
    p2 = _vectors(p2_raw, P2_POSITIONS, "P2")
    p3 = _vectors(p3_raw, P3_POSITIONS, "P3")
    return seedpk, p1, p2, p3, _dense_from_vectors(p1, p2, p3)


def _digest_cpk(canonical_cpk: bytes) -> bytes:
    canonical = _require_bytes(canonical_cpk, CPK_BYTES, "canonical_cpk")
    return _shake_tuple(
        PUBLIC_MAP_DIGEST_DOMAIN,
        (CONTRACT_ID, canonical),
        32,
    )


def _key_id_from_digest(map_digest: bytes) -> bytes:
    canonical = _require_bytes(map_digest, 32, "public_map_digest")
    return _shake_tuple(ISSUER_KEY_ID_DOMAIN, (CONTRACT_ID, canonical), 32)


@dataclass(frozen=True, slots=True, init=False)
class UOVPublicMap:
    """Canonical compressed key plus its proven official dense expansion."""

    canonical_cpk: bytes
    public_map_digest: bytes
    dense_coefficients: bytes

    def __init__(self, canonical_cpk: bytes) -> None:
        canonical = _require_bytes(canonical_cpk, CPK_BYTES, "canonical_cpk")
        _, _, _, _, dense = _expand_cpk(canonical)
        object.__setattr__(self, "canonical_cpk", canonical)
        object.__setattr__(self, "public_map_digest", _digest_cpk(canonical))
        object.__setattr__(self, "dense_coefficients", dense)

    @classmethod
    def _from_expanded(
        cls,
        canonical_cpk: bytes,
        p1: list[int],
        p2: list[int],
        p3: list[int],
    ) -> "UOVPublicMap":
        canonical = _require_bytes(canonical_cpk, CPK_BYTES, "canonical_cpk")
        instance = object.__new__(cls)
        object.__setattr__(instance, "canonical_cpk", canonical)
        object.__setattr__(instance, "public_map_digest", _digest_cpk(canonical))
        object.__setattr__(
            instance, "dense_coefficients", _dense_from_vectors(p1, p2, p3)
        )
        return instance


@dataclass(frozen=True, slots=True)
class UOVPrivateKey:
    """Canonical official compressed secret key (the exact seedsk)."""

    canonical_csk: bytes

    def __post_init__(self) -> None:
        _require_bytes(self.canonical_csk, CSK_BYTES, "canonical_csk")


@dataclass(frozen=True, slots=True)
class IssuerMapRecord:
    """One canonical configuration-bound issuer-map record."""

    ctx: bytes
    issuer_key_id: bytes
    public_map_digest: bytes
    status: int
    canonical_cpk: bytes

    def __post_init__(self) -> None:
        _require_bytes(self.ctx, 32, "record ctx")
        _require_bytes(self.issuer_key_id, 32, "record issuer_key_id")
        _require_bytes(self.public_map_digest, 32, "record public_map_digest")
        _require_status(self.status, "record status")
        canonical = _require_bytes(self.canonical_cpk, CPK_BYTES, "record canonical_cpk")
        expected_digest = _digest_cpk(canonical)
        if self.public_map_digest != expected_digest:
            raise IssuerMapRegistryError("record public-map digest mismatch")
        if self.issuer_key_id != _key_id_from_digest(expected_digest):
            raise IssuerMapRegistryError("record issuer-key identifier mismatch")


def _encode_record(record: IssuerMapRecord) -> bytes:
    if type(record) is not IssuerMapRecord:
        raise UOVTypeError("record must be exactly IssuerMapRecord")
    return b"".join(
        (
            record.ctx,
            record.issuer_key_id,
            record.public_map_digest,
            bytes((record.status,)),
            CPK_BYTES.to_bytes(4, "big"),
            record.canonical_cpk,
        )
    )


def _record_sort_key(record: IssuerMapRecord) -> tuple[bytes, bytes, int, bytes]:
    return (
        record.issuer_key_id,
        record.public_map_digest,
        record.status,
        record.canonical_cpk,
    )


def _registry_digest(ctx: bytes, records: tuple[IssuerMapRecord, ...]) -> bytes:
    canonical_ctx = _require_bytes(ctx, 32, "registry ctx")
    if type(records) is not tuple:
        raise UOVTypeError("records must be exactly tuple")
    if len(records) > 0xFFFFFFFF:
        raise UOVEncodingError("record count exceeds the u32 boundary")
    sequence = bytearray()
    for record in records:
        sequence.extend(_encode_record(record))
    return _shake_tuple(
        REGISTRY_DIGEST_DOMAIN,
        (
            CONTRACT_ID,
            canonical_ctx,
            len(records).to_bytes(4, "big"),
            bytes(sequence),
        ),
        32,
    )


@dataclass(frozen=True, slots=True)
class IssuerMapRegistry:
    """Immutable records verified against an authenticated configuration."""

    authenticated_ctx: bytes
    authenticated_registry_digest: bytes
    records: tuple[IssuerMapRecord, ...]
    authenticated_bindings: tuple[tuple[bytes, bytes, int], ...]

    def __post_init__(self) -> None:
        ctx = _require_bytes(self.authenticated_ctx, 32, "authenticated_ctx")
        authenticated_digest = _require_bytes(
            self.authenticated_registry_digest,
            32,
            "authenticated_registry_digest",
        )
        if type(self.records) is not tuple:
            raise UOVTypeError("records must be exactly tuple")
        if type(self.authenticated_bindings) is not tuple:
            raise UOVTypeError("authenticated_bindings must be exactly tuple")

        record_bindings: list[tuple[bytes, bytes, int]] = []
        prior_sort_key: tuple[bytes, bytes, int, bytes] | None = None
        seen_ids: set[bytes] = set()
        for index, record in enumerate(self.records):
            if type(record) is not IssuerMapRecord:
                raise UOVTypeError(f"records[{index}] must be exactly IssuerMapRecord")
            if record.ctx != ctx:
                raise IssuerMapRegistryError("record ctx does not match authenticated ctx")
            sort_key = _record_sort_key(record)
            if prior_sort_key is not None and sort_key <= prior_sort_key:
                if sort_key == prior_sort_key:
                    raise IssuerMapRegistryError("duplicate issuer-map record")
                raise IssuerMapRegistryError("issuer-map records are not canonically ordered")
            prior_sort_key = sort_key
            if record.issuer_key_id in seen_ids:
                raise IssuerMapRegistryError("ambiguous issuer-key binding")
            seen_ids.add(record.issuer_key_id)
            record_bindings.append(
                (record.issuer_key_id, record.public_map_digest, record.status)
            )

        canonical_bindings: list[tuple[bytes, bytes, int]] = []
        prior_binding: tuple[bytes, bytes, int] | None = None
        for index, binding in enumerate(self.authenticated_bindings):
            if type(binding) is not tuple or len(binding) != 3:
                raise UOVTypeError(
                    f"authenticated_bindings[{index}] must be one exact 3-tuple"
                )
            key_id = _require_bytes(binding[0], 32, f"binding[{index}] issuer_key_id")
            map_digest = _require_bytes(
                binding[1], 32, f"binding[{index}] public_map_digest"
            )
            status = _require_status(binding[2], f"binding[{index}] status")
            canonical_binding = (key_id, map_digest, status)
            if prior_binding is not None and canonical_binding <= prior_binding:
                if canonical_binding == prior_binding:
                    raise IssuerMapRegistryError("duplicate authenticated binding")
                raise IssuerMapRegistryError(
                    "authenticated bindings are not canonically ordered"
                )
            prior_binding = canonical_binding
            canonical_bindings.append(canonical_binding)

        if tuple(record_bindings) != tuple(canonical_bindings):
            raise IssuerMapRegistryError("configuration binding mismatch")
        if _registry_digest(ctx, self.records) != authenticated_digest:
            raise IssuerMapRegistryError("registry digest mismatch")


def encode_public_map(public_map: UOVPublicMap) -> bytes:
    """Return the exact 189,232-byte official compressed public key."""

    if type(public_map) is not UOVPublicMap:
        raise UOVTypeError("public_map must be exactly UOVPublicMap")
    return public_map.canonical_cpk


def decode_public_map(encoded: bytes) -> UOVPublicMap:
    """Strictly decode and expand one canonical official compressed key."""

    return UOVPublicMap(_require_bytes(encoded, CPK_BYTES, "encoded public map"))


def public_map_digest(public_map: UOVPublicMap) -> bytes:
    """Return the PQ-SAT domain-separated digest of the canonical cpk."""

    if type(public_map) is not UOVPublicMap:
        raise UOVTypeError("public_map must be exactly UOVPublicMap")
    return public_map.public_map_digest


def issuer_key_id(public_map: UOVPublicMap) -> bytes:
    """Derive the PQ-SAT issuer key identifier from the map digest."""

    return _key_id_from_digest(public_map_digest(public_map))


def evaluate_public_map(public_map: UOVPublicMap, z: bytes) -> bytes:
    """Evaluate the exact equation-major/lexicographic dense quadratic map."""

    if type(public_map) is not UOVPublicMap:
        raise UOVTypeError("public_map must be exactly UOVPublicMap")
    canonical_z = _require_bytes(z, N, "z")
    dense = public_map.dense_coefficients
    if type(dense) is not bytes or len(dense) != DENSE_BYTES:
        raise UOVIntegrityError("public map has an invalid dense representation")

    accumulator = 0
    monomial = 0
    for first in range(N):
        first_value = canonical_z[first]
        for second in range(first, N):
            scalar = _GF_ROWS[first_value][canonical_z[second]]
            if scalar:
                coefficient_vector = int.from_bytes(
                    dense[monomial::MONOMIAL_COUNT], "little"
                )
                accumulator ^= _packed_mul(coefficient_vector, scalar)
            monomial += 1
    return accumulator.to_bytes(M, "little")


def _expanded_key_material(
    seed: bytes, *, include_s: bool
) -> tuple[UOVPublicMap, bytes, list[int], list[int] | None]:
    seedsk = _require_bytes(seed, CSK_BYTES, "seedsk")
    expanded_secret = hashlib.shake_256(seedsk).digest(16 + V * O)
    seedpk = expanded_secret[:16]
    secret_o = expanded_secret[16:]
    public_stream = _expand_public_stream(seedpk)
    p1 = _vectors(public_stream[:P1_BYTES], P1_POSITIONS, "P1")
    p2 = _vectors(public_stream[P1_BYTES:], P2_POSITIONS, "P2")
    p3, s_matrix = _calculate_p3_and_optional_s(
        p1, p2, secret_o, include_s=include_s
    )
    cpk = seedpk + _vectors_bytes(p3)
    public_map = UOVPublicMap._from_expanded(cpk, p1, p2, p3)
    return public_map, secret_o, p1, s_matrix


def keygen(seed: bytes) -> tuple[UOVPublicMap, UOVPrivateKey]:
    """Official-compatible deterministic UOV-III pkc+skc KeyGen."""

    seedsk = _require_bytes(seed, CSK_BYTES, "seed")
    public_map, _, _, _ = _expanded_key_material(seedsk, include_s=False)
    return public_map, UOVPrivateKey(seedsk)


def _solve_linear_system(rows: tuple[bytes, ...], right_hand_side: bytes) -> bytes | None:
    if type(rows) is not tuple or len(rows) != O:
        raise UOVIntegrityError("linear system must contain exactly 72 rows")
    rhs = _require_bytes(right_hand_side, O, "linear-system right-hand side")
    augmented: list[bytearray] = []
    for index, row in enumerate(rows):
        canonical_row = _require_bytes(row, O, f"linear-system row {index}")
        augmented.append(bytearray(canonical_row + bytes((rhs[index],))))

    for column in range(O):
        pivot = next(
            (row for row in range(column, O) if augmented[row][column]),
            None,
        )
        if pivot is None:
            return None
        if pivot != column:
            augmented[column], augmented[pivot] = augmented[pivot], augmented[column]

        pivot_value = augmented[column][column]
        if pivot_value != 1:
            augmented[column][:] = bytes(augmented[column]).translate(
                _GF_ROWS[_gf_inverse(pivot_value)]
            )
        pivot_row = int.from_bytes(augmented[column], "little")
        for row_index in range(O):
            if row_index == column:
                continue
            factor = augmented[row_index][column]
            if factor:
                product = int.from_bytes(
                    pivot_row.to_bytes(O + 1, "little").translate(_GF_ROWS[factor]),
                    "little",
                )
                current = int.from_bytes(augmented[row_index], "little") ^ product
                augmented[row_index][:] = current.to_bytes(O + 1, "little")
    return bytes(row[-1] for row in augmented)


def _vinegar(
    map_digest: bytes, target: bytes, randomness: bytes, counter: int
) -> bytes:
    if type(counter) is not int:
        raise UOVTypeError("counter must be exactly int; bool is forbidden")
    if not 0 <= counter <= 255:
        raise UOVEncodingError("counter is outside 0..255")
    return _shake_tuple(
        INVERT_VINEGAR_DOMAIN,
        (
            CONTRACT_ID,
            _require_bytes(map_digest, 32, "public_map_digest"),
            _require_bytes(target, M, "target"),
            _require_bytes(randomness, 32, "randomness"),
            counter.to_bytes(2, "big"),
        ),
        V,
    )


def invert(private_key: UOVPrivateKey, target: bytes, randomness: bytes) -> bytes:
    """Invert a supplied target with bounded PQ-SAT vinegar sampling."""

    if type(private_key) is not UOVPrivateKey:
        raise UOVTypeError("private_key must be exactly UOVPrivateKey")
    canonical_target = _require_bytes(target, M, "target")
    canonical_randomness = _require_bytes(randomness, 32, "randomness")
    public_map, secret_o, p1, s_matrix = _expanded_key_material(
        private_key.canonical_csk, include_s=True
    )
    if s_matrix is None or len(s_matrix) != P2_POSITIONS:
        raise UOVIntegrityError("secret central-map expansion failed")

    for counter in range(256):
        vinegar = _vinegar(
            public_map.public_map_digest,
            canonical_target,
            canonical_randomness,
            counter,
        )

        # Each packed column contains L[e,oil] for equations e=0..71.
        packed_columns: list[int] = []
        for oil in range(O):
            column = 0
            for vinegar_index in range(V):
                scalar = vinegar[vinegar_index]
                if scalar:
                    column ^= _packed_mul(
                        s_matrix[vinegar_index * O + oil], scalar
                    )
            packed_columns.append(column)
        rows_buffer = [bytearray(O) for _ in range(O)]
        for oil, packed_column in enumerate(packed_columns):
            column_bytes = packed_column.to_bytes(M, "little")
            for equation, value in enumerate(column_bytes):
                rows_buffer[equation][oil] = value
        rows = tuple(bytes(row) for row in rows_buffer)

        constant = 0
        p1_position = 0
        for first in range(V):
            first_value = vinegar[first]
            for second in range(first, V):
                scalar = _GF_ROWS[first_value][vinegar[second]]
                if scalar:
                    constant ^= _packed_mul(p1[p1_position], scalar)
                p1_position += 1
        right_hand_side = bytes(
            left ^ right
            for left, right in zip(
                canonical_target,
                constant.to_bytes(M, "little"),
                strict=True,
            )
        )
        oil_solution = _solve_linear_system(rows, right_hand_side)
        if oil_solution is None:
            continue

        transformed_vinegar = bytearray(vinegar)
        for oil, oil_value in enumerate(oil_solution):
            if oil_value == 0:
                continue
            column = secret_o[oil * V : (oil + 1) * V]
            multiplication = _GF_ROWS[oil_value]
            for index, coefficient in enumerate(column):
                transformed_vinegar[index] ^= multiplication[coefficient]
        z = bytes(transformed_vinegar) + oil_solution
        if evaluate_public_map(public_map, z) != canonical_target:
            raise UOVIntegrityError("inversion postcondition failed")
        return z
    raise UOVInversionError("all 256 vinegar systems were singular")


def resolve_issuer_map(
    registry: IssuerMapRegistry, ctx: bytes, issuer_key_id: bytes
) -> UOVPublicMap:
    """Resolve exactly one active map from an explicit authenticated registry."""

    if type(registry) is not IssuerMapRegistry:
        raise UOVTypeError("registry must be exactly IssuerMapRegistry")
    canonical_ctx = _require_bytes(ctx, 32, "ctx")
    canonical_key_id = _require_bytes(issuer_key_id, 32, "issuer_key_id")
    if registry.authenticated_ctx != canonical_ctx:
        raise IssuerMapResolutionError("ctx does not match the authenticated registry")
    matches = tuple(
        record
        for record in registry.records
        if record.ctx == canonical_ctx and record.issuer_key_id == canonical_key_id
    )
    if len(matches) != 1:
        if not matches:
            raise IssuerMapResolutionError("issuer-map binding is unknown")
        raise IssuerMapResolutionError("issuer-map binding is duplicate or ambiguous")
    record = matches[0]
    if record.status != STATUS_ACTIVE:
        raise IssuerMapResolutionError("issuer-map binding is revoked")
    public_map = decode_public_map(record.canonical_cpk)
    if public_map.public_map_digest != record.public_map_digest:
        raise IssuerMapResolutionError("resolved public-map digest mismatch")
    if _key_id_from_digest(public_map.public_map_digest) != canonical_key_id:
        raise IssuerMapResolutionError("resolved issuer-key identifier mismatch")
    expected_binding = (
        canonical_key_id,
        public_map.public_map_digest,
        record.status,
    )
    if registry.authenticated_bindings.count(expected_binding) != 1:
        raise IssuerMapResolutionError("authenticated configuration binding mismatch")
    return public_map


def encode_statement_core(ctx: bytes, u: bytes) -> bytes:
    """Encode the unchanged 104-byte ``ctx || u`` statement core."""

    return _require_bytes(ctx, 32, "ctx") + _require_bytes(u, M, "u")


def uov_relation_holds(
    public_map: UOVPublicMap,
    ctx: bytes,
    u: bytes,
    r: bytes,
    z: bytes,
) -> bool:
    """Check ``Q_I(z) == r XOR u`` with an explicit public-map dependency."""

    try:
        if type(public_map) is not UOVPublicMap:
            return False
        _require_bytes(ctx, 32, "ctx")
        canonical_u = _require_bytes(u, M, "u")
        canonical_r = _require_bytes(r, M, "r")
        canonical_z = _require_bytes(z, N, "z")
        expected = bytes(
            left ^ right
            for left, right in zip(canonical_r, canonical_u, strict=True)
        )
        return evaluate_public_map(public_map, canonical_z) == expected
    except UOVError:
        return False


__all__ = (
    "UOVError",
    "UOVTypeError",
    "UOVEncodingError",
    "UOVIntegrityError",
    "UOVInversionError",
    "IssuerMapRegistryError",
    "IssuerMapResolutionError",
    "UOVPublicMap",
    "UOVPrivateKey",
    "IssuerMapRecord",
    "IssuerMapRegistry",
    "encode_public_map",
    "decode_public_map",
    "public_map_digest",
    "issuer_key_id",
    "evaluate_public_map",
    "keygen",
    "invert",
    "resolve_issuer_map",
    "encode_statement_core",
    "uov_relation_holds",
)
