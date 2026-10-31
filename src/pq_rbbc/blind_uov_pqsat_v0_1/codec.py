"""Strict wire codecs for the PQ-SAT Blind-UOV CAP profile.

This module closes only the canonical byte boundary for ``c_r``, ``c_z``,
and ``pi_2``.  The ``pi_2`` codec evaluates the explicit proof-of-work
predicate for the received nonce exactly once and reconstructs the unique
frontier grammar from transcript-derived hidden positions.  It deliberately
does not authenticate frontier seeds or verify the CAP relation; those checks
belong to the later verifier and its ``h1`` binding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .parameters import load_profile_manifest
from .response import decode_tcith_responses
from .transcript import (
    derive_hidden_positions,
    explicit_pow_passes,
    hidden_positions_are_admissible,
)
from .tree import Opening, TreeValidationError, canonical_frontier_indices


class CodecValidationError(ValueError):
    """A controlled rejection of malformed or noncanonical CAP wire data."""


_PROFILE: Final = load_profile_manifest()

_MAGIC: Final = b"PQSCAP01"
_VERSION: Final = 1
_SUITE: Final = _PROFILE.suite_id_u16
_FINGERPRINT: Final = _PROFILE.fingerprint

_TYPE_C_R: Final = 1
_TYPE_C_Z: Final = 2
_TYPE_PI_2: Final = 3

_HEADER_BYTES: Final = 50
_SALT_BYTES: Final = _PROFILE.symmetric.digest_bytes
_DIGEST_BYTES: Final = _PROFILE.symmetric.digest_bytes
_SEED_BYTES: Final = _PROFILE.one_tree.frontier_seed_bytes
_TAU: Final = _PROFILE.tau
_FRONTIER_MINIMUM: Final = _PROFILE.one_tree.frontier_count_minimum
_FRONTIER_MAXIMUM: Final = _PROFILE.opened_seed_upper_bound_topen
_CORRECTION_DATA_BYTES: Final = (
    _PROFILE.consistency.eta
    + (_PROFILE.tau - 1)
    * (_PROFILE.relation.witness_bits + _PROFILE.consistency.eta)
) // 8
_DELTA_Z_BYTES: Final = _PROFILE.relation.z_bits // 8
_HIDDEN_COMMITMENTS_BYTES: Final = _TAU * _DIGEST_BYTES
_TCITH_RESPONSE_BITS: Final = sum(
    group.repetitions
    * group.rho
    * group.mu
    * (_PROFILE.relation.degree_d - 1)
    for group in _PROFILE.tree_groups
)
if _TCITH_RESPONSE_BITS % 8:
    raise RuntimeError("the frozen TCitH response is not byte-aligned")
_TCITH_RESPONSE_BYTES: Final = _TCITH_RESPONSE_BITS // 8
_C_R_PAYLOAD_BYTES: Final = (
    _SALT_BYTES + _DIGEST_BYTES + _CORRECTION_DATA_BYTES
)
_C_Z_PAYLOAD_BYTES: Final = _DELTA_Z_BYTES
_PI_2_FIXED_PAYLOAD_BYTES: Final = (
    _DIGEST_BYTES + 8 + 2 + _HIDDEN_COMMITMENTS_BYTES + _TCITH_RESPONSE_BYTES
)
_MAX_U64: Final = (1 << 64) - 1


def _require_exact_bytes(value: object, name: str, length: int) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{name} must be exact bytes")
    if len(value) != length:
        raise CodecValidationError(f"{name} must be exactly {length} bytes")
    return value


def _require_nonce(value: object) -> int:
    if type(value) is not int:
        raise TypeError("pow_nonce must be an exact int and bool is forbidden")
    if not 0 <= value <= _MAX_U64:
        raise CodecValidationError("pow_nonce must be in the canonical u64 range")
    return value


def _require_opening(value: object) -> Opening:
    if type(value) is not Opening:
        raise TypeError("opening must be an exact Opening")
    if not _FRONTIER_MINIMUM <= len(value.seeds) <= _FRONTIER_MAXIMUM:
        raise CodecValidationError(
            f"opening seed count must be in range {_FRONTIER_MINIMUM}..{_FRONTIER_MAXIMUM}"
        )
    for index, seed in enumerate(value.seeds):
        _require_exact_bytes(seed, f"opening.seeds[{index}]", _SEED_BYTES)
    return value


def _require_hidden_commitments(value: object) -> tuple[bytes, ...]:
    if type(value) is not tuple:
        raise TypeError("hidden_leaf_commitments must be an exact tuple")
    if len(value) != _TAU:
        raise CodecValidationError(
            f"hidden_leaf_commitments must contain exactly {_TAU} values"
        )
    for index, commitment in enumerate(value):
        _require_exact_bytes(
            commitment,
            f"hidden_leaf_commitments[{index}]",
            _DIGEST_BYTES,
        )
    return value


@dataclass(frozen=True, slots=True)
class CR:
    """Canonical ``c_r`` fields before framing."""

    salt: bytes
    h2_prime: bytes
    correction_data: bytes

    def __post_init__(self) -> None:
        _require_exact_bytes(self.salt, "salt", _SALT_BYTES)
        _require_exact_bytes(self.h2_prime, "h2_prime", _DIGEST_BYTES)
        _require_exact_bytes(
            self.correction_data, "correction_data", _CORRECTION_DATA_BYTES
        )


@dataclass(frozen=True, slots=True)
class CZ:
    """Canonical ``c_z`` fields before framing."""

    delta_z: bytes

    def __post_init__(self) -> None:
        _require_exact_bytes(self.delta_z, "delta_z", _DELTA_Z_BYTES)


@dataclass(frozen=True, slots=True)
class Pi2:
    """Canonical seed-only ``pi_2`` representation before framing."""

    h3: bytes
    pow_nonce: int
    opening: Opening
    hidden_leaf_commitments: tuple[bytes, ...]
    tcith_responses: bytes

    def __post_init__(self) -> None:
        _require_exact_bytes(self.h3, "h3", _DIGEST_BYTES)
        _require_nonce(self.pow_nonce)
        _require_opening(self.opening)
        _require_hidden_commitments(self.hidden_leaf_commitments)
        checked_responses = _require_exact_bytes(
            self.tcith_responses, "tcith_responses", _TCITH_RESPONSE_BYTES
        )
        decode_tcith_responses(checked_responses)


def _header(object_type: int, payload_length: int) -> bytes:
    return b"".join(
        (
            _MAGIC,
            _VERSION.to_bytes(2, "big"),
            object_type.to_bytes(2, "big"),
            _SUITE.to_bytes(2, "big"),
            _FINGERPRINT,
            payload_length.to_bytes(4, "big"),
        )
    )


def _decode_payload(
    encoded: object,
    expected_type: int,
    expected_payload_length: int | None,
) -> bytes:
    if type(encoded) is not bytes:
        raise TypeError("encoded must be exact bytes")
    if len(encoded) < _HEADER_BYTES:
        raise CodecValidationError("encoded object has a truncated header")

    if encoded[0:8] != _MAGIC:
        raise CodecValidationError("unknown CAP wire magic")
    if int.from_bytes(encoded[8:10], "big") != _VERSION:
        raise CodecValidationError("unknown CAP wire version")
    if int.from_bytes(encoded[10:12], "big") != expected_type:
        raise CodecValidationError("wrong CAP object type")
    if int.from_bytes(encoded[12:14], "big") != _SUITE:
        raise CodecValidationError("unknown CAP suite")
    if encoded[14:46] != _FINGERPRINT:
        raise CodecValidationError("wrong CAP profile fingerprint")

    declared_length = int.from_bytes(encoded[46:50], "big")
    actual_length = len(encoded) - _HEADER_BYTES
    if declared_length != actual_length:
        raise CodecValidationError(
            "declared payload length does not equal the complete received payload"
        )
    if (
        expected_payload_length is not None
        and declared_length != expected_payload_length
    ):
        raise CodecValidationError("wrong payload length for CAP object type")
    return encoded[_HEADER_BYTES:]


def _validate_pi_2(value: object) -> tuple[Pi2, tuple[int, ...]]:
    if type(value) is not Pi2:
        raise TypeError("value must be an exact Pi2")
    _require_exact_bytes(value.h3, "h3", _DIGEST_BYTES)
    nonce = _require_nonce(value.pow_nonce)
    opening = _require_opening(value.opening)
    _require_hidden_commitments(value.hidden_leaf_commitments)
    checked_responses = _require_exact_bytes(
        value.tcith_responses, "tcith_responses", _TCITH_RESPONSE_BYTES
    )
    decode_tcith_responses(checked_responses)

    # This call is intentionally unique within the encode path.  Verifier work
    # is independent of the numeric value of the received nonce.
    if not explicit_pow_passes(value.h3, nonce):
        raise CodecValidationError("received pow_nonce fails the explicit predicate")
    hidden_positions = derive_hidden_positions(value.h3, nonce)
    if not hidden_positions_are_admissible(hidden_positions):
        raise CodecValidationError(
            "received pow_nonce derives a forbidden infinity hidden position"
        )
    try:
        frontier_indices = canonical_frontier_indices(hidden_positions)
    except TreeValidationError as error:
        raise CodecValidationError(str(error)) from error
    if len(opening.seeds) != len(frontier_indices):
        raise CodecValidationError(
            "opening seed count does not match the derived canonical frontier"
        )
    return value, frontier_indices


def encode_c_r(value: CR) -> bytes:
    """Encode one exact, fixed-length ``c_r`` object."""

    if type(value) is not CR:
        raise TypeError("value must be an exact CR")
    salt = _require_exact_bytes(value.salt, "salt", _SALT_BYTES)
    h2_prime = _require_exact_bytes(value.h2_prime, "h2_prime", _DIGEST_BYTES)
    correction_data = _require_exact_bytes(
        value.correction_data, "correction_data", _CORRECTION_DATA_BYTES
    )
    payload = salt + h2_prime + correction_data
    if len(payload) != _C_R_PAYLOAD_BYTES:
        raise AssertionError("unreachable c_r payload length")
    return _header(_TYPE_C_R, len(payload)) + payload


def decode_c_r(encoded: bytes) -> CR:
    """Decode one complete canonical ``c_r`` object."""

    payload = _decode_payload(encoded, _TYPE_C_R, _C_R_PAYLOAD_BYTES)
    return CR(
        salt=payload[0:_SALT_BYTES],
        h2_prime=payload[_SALT_BYTES : _SALT_BYTES + _DIGEST_BYTES],
        correction_data=payload[_SALT_BYTES + _DIGEST_BYTES :],
    )


def encode_c_z(value: CZ) -> bytes:
    """Encode one exact, fixed-length ``c_z`` object."""

    if type(value) is not CZ:
        raise TypeError("value must be an exact CZ")
    payload = _require_exact_bytes(value.delta_z, "delta_z", _DELTA_Z_BYTES)
    return _header(_TYPE_C_Z, len(payload)) + payload


def decode_c_z(encoded: bytes) -> CZ:
    """Decode one complete canonical ``c_z`` object."""

    payload = _decode_payload(encoded, _TYPE_C_Z, _C_Z_PAYLOAD_BYTES)
    return CZ(delta_z=payload)


def encode_pi_2(value: Pi2) -> bytes:
    """Encode a variable, unpadded ``pi_2`` after one received-nonce check."""

    checked, frontier_indices = _validate_pi_2(value)
    count = len(frontier_indices)
    payload = b"".join(
        (
            checked.h3,
            checked.pow_nonce.to_bytes(8, "big"),
            count.to_bytes(2, "big"),
            b"".join(checked.opening.seeds),
            b"".join(checked.hidden_leaf_commitments),
            checked.tcith_responses,
        )
    )
    expected_length = _PI_2_FIXED_PAYLOAD_BYTES + _SEED_BYTES * count
    if len(payload) != expected_length:
        raise AssertionError("unreachable pi_2 payload length")
    return _header(_TYPE_PI_2, len(payload)) + payload


def decode_pi_2(encoded: bytes) -> Pi2:
    """Decode a complete variable ``pi_2`` and enforce its frontier grammar."""

    payload = _decode_payload(encoded, _TYPE_PI_2, None)
    if len(payload) < _PI_2_FIXED_PAYLOAD_BYTES:
        raise CodecValidationError("pi_2 payload is truncated")

    h3 = payload[0:_DIGEST_BYTES]
    nonce_offset = _DIGEST_BYTES
    nonce = int.from_bytes(payload[nonce_offset : nonce_offset + 8], "big")
    count_offset = nonce_offset + 8
    count = int.from_bytes(payload[count_offset : count_offset + 2], "big")
    if not _FRONTIER_MINIMUM <= count <= _FRONTIER_MAXIMUM:
        raise CodecValidationError(
            f"frontier_count must be in range {_FRONTIER_MINIMUM}..{_FRONTIER_MAXIMUM}"
        )
    expected_payload_length = _PI_2_FIXED_PAYLOAD_BYTES + _SEED_BYTES * count
    if len(payload) != expected_payload_length:
        raise CodecValidationError(
            "pi_2 payload length does not match its frontier_count"
        )

    # This call is intentionally unique within the decode path.  It checks the
    # received nonce only; no earlier nonce or global minimality is examined.
    if not explicit_pow_passes(h3, nonce):
        raise CodecValidationError("received pow_nonce fails the explicit predicate")
    hidden_positions = derive_hidden_positions(h3, nonce)
    if not hidden_positions_are_admissible(hidden_positions):
        raise CodecValidationError(
            "received pow_nonce derives a forbidden infinity hidden position"
        )
    try:
        frontier_indices = canonical_frontier_indices(hidden_positions)
    except TreeValidationError as error:
        raise CodecValidationError(str(error)) from error
    if count != len(frontier_indices):
        raise CodecValidationError(
            "frontier_count does not match the derived canonical frontier"
        )

    seeds_offset = count_offset + 2
    seeds_end = seeds_offset + count * _SEED_BYTES
    commitments_end = seeds_end + _HIDDEN_COMMITMENTS_BYTES
    opening = Opening(
        tuple(
            payload[offset : offset + _SEED_BYTES]
            for offset in range(seeds_offset, seeds_end, _SEED_BYTES)
        )
    )
    commitments = tuple(
        payload[offset : offset + _DIGEST_BYTES]
        for offset in range(seeds_end, commitments_end, _DIGEST_BYTES)
    )
    tcith_responses = payload[commitments_end:]
    decode_tcith_responses(tcith_responses)
    result = Pi2(
        h3=h3,
        pow_nonce=nonce,
        opening=opening,
        hidden_leaf_commitments=commitments,
        tcith_responses=tcith_responses,
    )
    return result


def encode_sigma_i(c_r: CR, c_z: CZ, pi_2: Pi2) -> tuple[bytes, bytes, bytes]:
    """Return the canonical ``sigma_I`` component ordering without an envelope."""

    return encode_c_r(c_r), encode_c_z(c_z), encode_pi_2(pi_2)


__all__ = (
    "CR",
    "CZ",
    "Pi2",
    "CodecValidationError",
    "decode_c_r",
    "decode_c_z",
    "decode_pi_2",
    "encode_c_r",
    "encode_c_z",
    "encode_pi_2",
    "encode_sigma_i",
)
