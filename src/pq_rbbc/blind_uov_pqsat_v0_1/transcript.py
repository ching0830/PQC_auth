"""Canonical SHAKE256 transcript for the PQ-SAT Blind-UOV CAP profile.

The module is deliberately independent of field arithmetic.  It consumes the
exact frozen parameters ABI, length-delimits every SHAKE256 input, and exposes
only deterministic transcript derivations.  In particular,
``explicit_pow_passes`` evaluates one received nonce and never searches for a
smaller nonce.
"""

from __future__ import annotations

import hashlib
from typing import Final, TypeAlias

from .consistency import decode_xi_polynomials
from .parameters import load_profile_manifest
from .response import decode_h3_q_and_qbar


_PROFILE: Final = load_profile_manifest()
_FINGERPRINT: Final = _PROFILE.fingerprint

_DOMAIN_H1: Final = _PROFILE.symmetric.domain("fiat_shamir_h1")
_DOMAIN_CONSISTENCY: Final = _PROFILE.symmetric.domain("consistency_matrix")
_DOMAIN_H2_PRIME: Final = _PROFILE.symmetric.domain("fiat_shamir_h2_prime")
_DOMAIN_H2: Final = _PROFILE.symmetric.domain("fiat_shamir_h2")
_DOMAIN_GAMMA: Final = _PROFILE.symmetric.domain("gamma_derivation")
_DOMAIN_H3: Final = _PROFILE.symmetric.domain("fiat_shamir_h3")
_DOMAIN_POW: Final = _PROFILE.symmetric.domain("proof_of_work")
_DOMAIN_OPEN_INDEX: Final = _PROFILE.symmetric.domain("hidden_opening_indices")

_MAX_U16: Final = (1 << 16) - 1
_MAX_U32: Final = (1 << 32) - 1
_MAX_U64: Final = (1 << 64) - 1
_MAX_FIELD_BYTES: Final = _MAX_U32

_CTX_BYTES: Final = 32
_SALT_BYTES: Final = 48
_DIGEST_BYTES: Final = _PROFILE.symmetric.digest_bytes
_U_BYTES: Final = _PROFILE.relation.m_equations
_COMMITMENTS_BYTES: Final = (
    _PROFILE.one_tree.active_leaves * _PROFILE.symmetric.digest_bytes
)
_CORRECTION_DELTAS_BYTES: Final = (
    (_PROFILE.tau - 1)
    * (_PROFILE.relation.witness_bits + _PROFILE.consistency.eta)
    // 8
)
_XI_POLYNOMIALS_BYTES: Final = 6976
_DELTA_R_BYTES: Final = _PROFILE.relation.r_bits // 8
_DELTA_Z_BYTES: Final = _PROFILE.relation.z_bits // 8
_Q_AND_QBAR_BITS: Final = sum(
    group.repetitions
    * group.rho
    * group.mu
    * 2  # one q and one degree-zero Qbar element for d=2
    for group in _PROFILE.tree_groups
)
if _Q_AND_QBAR_BITS % 8:
    raise RuntimeError("the frozen q/Qbar transcript is not byte-aligned")
_Q_AND_QBAR_BYTES: Final = _Q_AND_QBAR_BITS // 8
_CONSTRAINTS: Final = _PROFILE.relation.constraints_over_f2

HiddenPositions: TypeAlias = tuple[int, ...]


def _require_exact_bytes(value: object, name: str, length: int | None = None) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{name} must be exact bytes")
    if length is not None and len(value) != length:
        raise ValueError(f"{name} must be exactly {length} bytes")
    return value


def _require_exact_int(value: object, name: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{name} must be an exact int and bool is forbidden")
    return value


def _require_nonce(nonce: object) -> int:
    value = _require_exact_int(nonce, "nonce")
    if not 0 <= value <= _MAX_U64:
        raise ValueError("nonce must be in the u64 range")
    return value


def _u16be(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _u64be(value: int) -> bytes:
    return value.to_bytes(8, "big")


def encode_tuple(domain: bytes, fields: tuple[bytes, ...]) -> bytes:
    """Encode the one canonical domain-separated tuple grammar."""

    checked_domain = _require_exact_bytes(domain, "domain")
    if not checked_domain:
        raise ValueError("domain must not be empty")
    if len(checked_domain) > _MAX_U16:
        raise ValueError("domain exceeds the u16 length limit")
    if not checked_domain.isascii():
        raise ValueError("domain must contain only ASCII bytes")
    if type(fields) is not tuple:
        raise TypeError("fields must be an exact tuple")
    if len(fields) > _MAX_U16:
        raise ValueError("field count exceeds the u16 limit")

    checked_fields: list[bytes] = []
    for index, field in enumerate(fields):
        checked = _require_exact_bytes(field, f"fields[{index}]")
        if len(checked) > _MAX_FIELD_BYTES:
            raise ValueError(f"fields[{index}] exceeds the u32 length limit")
        checked_fields.append(checked)

    pieces = [_u16be(len(checked_domain)), checked_domain, _u16be(len(checked_fields))]
    for field in checked_fields:
        pieces.extend((len(field).to_bytes(4, "big"), field))
    return b"".join(pieces)


def shake(domain: bytes, fields: tuple[bytes, ...], output_bytes: int) -> bytes:
    """Hash one canonical tuple with CPython's SHAKE256 implementation."""

    output_length = _require_exact_int(output_bytes, "output_bytes")
    if output_length < 0:
        raise ValueError("output_bytes must not be negative")
    encoded = encode_tuple(domain, fields)
    return hashlib.shake_256(encoded).digest(output_length)


def derive_h1(
    ctx: bytes,
    salt: bytes,
    commitments: bytes,
    correction_deltas: bytes,
) -> bytes:
    """Derive the first Fiat-Shamir digest."""

    return shake(
        _DOMAIN_H1,
        (
            _FINGERPRINT,
            _require_exact_bytes(ctx, "ctx", _CTX_BYTES),
            _require_exact_bytes(salt, "salt", _SALT_BYTES),
            _require_exact_bytes(
                commitments, "commitments", _COMMITMENTS_BYTES
            ),
            _require_exact_bytes(
                correction_deltas,
                "correction_deltas",
                _CORRECTION_DELTAS_BYTES,
            ),
        ),
        _DIGEST_BYTES,
    )


def derive_consistency_points(h1: bytes) -> tuple[int, int, int, int]:
    """Derive four consecutive little-endian GF(2^64) point integers."""

    output = shake(
        _DOMAIN_CONSISTENCY,
        (_FINGERPRINT, _require_exact_bytes(h1, "h1", _DIGEST_BYTES)),
        32,
    )
    return tuple(
        int.from_bytes(output[offset : offset + 8], "little")
        for offset in range(0, 32, 8)
    )  # type: ignore[return-value]


def derive_h2_prime(h1: bytes, xi_polynomials: bytes) -> bytes:
    """Derive the serialized ``h2_prime`` digest."""

    decode_xi_polynomials(xi_polynomials)
    checked_xi_polynomials = xi_polynomials
    return shake(
        _DOMAIN_H2_PRIME,
        (
            _FINGERPRINT,
            _require_exact_bytes(h1, "h1", _DIGEST_BYTES),
            checked_xi_polynomials,
        ),
        _DIGEST_BYTES,
    )


def derive_h2(ctx: bytes, u: bytes, h2_prime: bytes, delta_z: bytes) -> bytes:
    """Derive ``h2`` after inserting the profile's 576 zero ``delta_r`` bits."""

    checked_delta_z = _require_exact_bytes(delta_z, "delta_z", _DELTA_Z_BYTES)
    delta_w = bytes(_DELTA_R_BYTES) + checked_delta_z
    return shake(
        _DOMAIN_H2,
        (
            _FINGERPRINT,
            _require_exact_bytes(ctx, "ctx", _CTX_BYTES),
            _require_exact_bytes(u, "u", _U_BYTES),
            _require_exact_bytes(h2_prime, "h2_prime", _DIGEST_BYTES),
            delta_w,
        ),
        _DIGEST_BYTES,
    )


def derive_gammas(h2: bytes, group_id: int) -> tuple[tuple[int, ...], ...]:
    """Return ``gamma[k][j]`` with outer ``k`` and 576 inner constraints."""

    checked_group_id = _require_exact_int(group_id, "group_id")
    group = next(
        (item for item in _PROFILE.tree_groups if item.group_id == checked_group_id),
        None,
    )
    if group is None:
        raise ValueError("unknown group_id")
    raw = shake(
        _DOMAIN_GAMMA,
        (
            _FINGERPRINT,
            _require_exact_bytes(h2, "h2", _DIGEST_BYTES),
            _u16be(checked_group_id),
        ),
        group.rho * _CONSTRAINTS * 2,
    )
    mask = (1 << group.mu) - 1
    matrix: list[tuple[int, ...]] = []
    offset = 0
    for _k in range(group.rho):
        row = tuple(
            int.from_bytes(raw[position : position + 2], "little") & mask
            for position in range(offset, offset + 2 * _CONSTRAINTS, 2)
        )
        matrix.append(row)
        offset += 2 * _CONSTRAINTS
    return tuple(matrix)


def derive_h3(ctx: bytes, u: bytes, h2: bytes, q_and_qbar: bytes) -> bytes:
    """Derive ``h3`` from packed extension-field q/Qbar elements."""

    checked_q_and_qbar = _require_exact_bytes(
        q_and_qbar, "q_and_qbar", _Q_AND_QBAR_BYTES
    )
    decode_h3_q_and_qbar(checked_q_and_qbar)
    return shake(
        _DOMAIN_H3,
        (
            _FINGERPRINT,
            _require_exact_bytes(ctx, "ctx", _CTX_BYTES),
            _require_exact_bytes(u, "u", _U_BYTES),
            _require_exact_bytes(h2, "h2", _DIGEST_BYTES),
            checked_q_and_qbar,
        ),
        _DIGEST_BYTES,
    )


def explicit_pow_passes(h3: bytes, nonce: int) -> bool:
    """Evaluate the 13-MSB explicit PoW predicate for exactly one nonce."""

    checked_nonce = _require_nonce(nonce)
    sample = shake(
        _DOMAIN_POW,
        (
            _FINGERPRINT,
            _require_exact_bytes(h3, "h3", _DIGEST_BYTES),
            _u64be(checked_nonce),
        ),
        2,
    )
    return int.from_bytes(sample, "big") >> (16 - _PROFILE.explicit_pow_bits_w) == 0


def derive_hidden_positions(h3: bytes, nonce: int) -> HiddenPositions:
    """Derive the 18 raw low-``mu`` positions without remapping or resampling."""

    checked_h3 = _require_exact_bytes(h3, "h3", _DIGEST_BYTES)
    checked_nonce = _require_nonce(nonce)
    nonce_bytes = _u64be(checked_nonce)
    positions: list[int] = []
    for group in _PROFILE.tree_groups:
        mask = (1 << group.mu) - 1
        for repetition in group.repetition_indices:
            sample = shake(
                _DOMAIN_OPEN_INDEX,
                (
                    _FINGERPRINT,
                    checked_h3,
                    nonce_bytes,
                    _u16be(repetition),
                ),
                2,
            )
            positions.append(int.from_bytes(sample, "big") & mask)
    return tuple(positions)


def hidden_positions_are_admissible(positions: HiddenPositions) -> bool:
    """Validate the raw grammar and return whether every position is finite.

    Structurally invalid values raise instead of being classified as an
    ordinary inadmissible transcript.  A canonical tuple containing a group
    infinity position is the sole false result.
    """

    if type(positions) is not tuple:
        raise TypeError("positions must be an exact tuple")
    if len(positions) != _PROFILE.tau:
        raise ValueError("positions must contain exactly 18 values")

    admissible = True
    offset = 0
    for group in _PROFILE.hidden_challenge.groups:
        for repetition in group.repetition_indices:
            position = positions[offset]
            if type(position) is not int:
                raise TypeError(
                    f"positions[{repetition}] must be an exact int and bool is forbidden"
                )
            if not group.raw_position_first <= position <= group.raw_position_last:
                raise ValueError(
                    f"positions[{repetition}] is outside the raw group domain"
                )
            if position == group.forbidden_infinity_position:
                admissible = False
            elif not (
                group.accepted_position_first
                <= position
                <= group.accepted_position_last
            ):
                raise ValueError(
                    f"positions[{repetition}] is neither finite nor canonical infinity"
                )
            offset += 1
    if offset != _PROFILE.tau:
        raise AssertionError("unreachable hidden-position group coverage")
    return admissible


def derive_admissible_hidden_positions(h3: bytes, nonce: int) -> HiddenPositions:
    """Perform one raw derivation and reject, rather than remap, infinity."""

    positions = derive_hidden_positions(h3, nonce)
    if not hidden_positions_are_admissible(positions):
        raise ValueError("raw hidden positions contain a forbidden infinity position")
    return positions


__all__ = (
    "derive_consistency_points",
    "derive_gammas",
    "derive_h1",
    "derive_h2",
    "derive_h2_prime",
    "derive_h3",
    "HiddenPositions",
    "derive_admissible_hidden_positions",
    "derive_hidden_positions",
    "encode_tuple",
    "explicit_pow_passes",
    "hidden_positions_are_admissible",
    "shake",
)
