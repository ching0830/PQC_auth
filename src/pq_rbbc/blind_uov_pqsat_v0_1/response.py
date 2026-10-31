"""Canonical TCitH response packing for the PQ-SAT Blind-UOV CAP profile.

The selected profile has two tree groups.  Callers provide one flattened
tuple per group in repetition-ascending, then ``k``-ascending order.  Field
elements are packed coefficient-bit first, with both bits and bytes in
least-significant-first order and no per-element alignment.
"""

from __future__ import annotations

from typing import Final


TCitHElementGroups = tuple[tuple[int, ...], ...]


class ResponseEncodingError(ValueError):
    """A controlled rejection of a noncanonical TCitH response encoding."""


# (mu, flattened entry count).  The order is the canonical group order.
_GROUP_SPECS: Final = ((12, 2 * 16), (11, 16 * 18))
_RESPONSE_BYTES: Final = 444
_H3_Q_AND_QBAR_BYTES: Final = 888


def _validate_groups(value: object, name: str) -> TCitHElementGroups:
    if type(value) is not tuple:
        raise TypeError(f"{name} must be an exact tuple")
    if len(value) != len(_GROUP_SPECS):
        raise ResponseEncodingError(
            f"{name} must contain exactly {len(_GROUP_SPECS)} groups"
        )

    for group_index, ((mu, entry_count), group) in enumerate(
        zip(_GROUP_SPECS, value, strict=True)
    ):
        if type(group) is not tuple:
            raise TypeError(f"{name}[{group_index}] must be an exact tuple")
        if len(group) != entry_count:
            raise ResponseEncodingError(
                f"{name}[{group_index}] must contain exactly {entry_count} elements"
            )
        upper_bound = 1 << mu
        for element_index, element in enumerate(group):
            if type(element) is not int:
                raise TypeError(
                    f"{name}[{group_index}][{element_index}] must be an exact int"
                )
            if not 0 <= element < upper_bound:
                raise ResponseEncodingError(
                    f"{name}[{group_index}][{element_index}] is outside GF(2^{mu})"
                )
    return value


def _require_encoded(value: object, name: str, length: int) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{name} must be exact bytes")
    if len(value) != length:
        raise ResponseEncodingError(f"{name} must be exactly {length} bytes")
    return value


def _pack_group(elements: tuple[int, ...], mu: int) -> bytes:
    bit_count = len(elements) * mu
    if bit_count % 8:
        raise AssertionError("frozen TCitH group is not byte-aligned")
    accumulator = 0
    bit_offset = 0
    for element in elements:
        accumulator |= element << bit_offset
        bit_offset += mu
    return accumulator.to_bytes(bit_count // 8, "little")


def _unpack_group(encoded: bytes, mu: int, entry_count: int) -> tuple[int, ...]:
    accumulator = int.from_bytes(encoded, "little")
    mask = (1 << mu) - 1
    return tuple(
        (accumulator >> (element_index * mu)) & mask
        for element_index in range(entry_count)
    )


def encode_tcith_responses(qbar_groups: TCitHElementGroups) -> bytes:
    """Encode the two canonical flattened groups of degree-zero Qbar values."""

    checked = _validate_groups(qbar_groups, "qbar_groups")
    encoded = b"".join(
        _pack_group(group, mu)
        for group, (mu, _entry_count) in zip(
            checked, _GROUP_SPECS, strict=True
        )
    )
    if len(encoded) != _RESPONSE_BYTES:
        raise AssertionError("unreachable TCitH response length")
    return encoded


def decode_tcith_responses(encoded: bytes) -> TCitHElementGroups:
    """Decode one complete 444-byte canonical TCitH response."""

    checked = _require_encoded(encoded, "encoded", _RESPONSE_BYTES)
    groups: list[tuple[int, ...]] = []
    byte_offset = 0
    for mu, entry_count in _GROUP_SPECS:
        group_bytes = entry_count * mu // 8
        group_end = byte_offset + group_bytes
        groups.append(
            _unpack_group(checked[byte_offset:group_end], mu, entry_count)
        )
        byte_offset = group_end
    if byte_offset != len(checked):
        raise AssertionError("unreachable TCitH response parse length")
    return tuple(groups)


def encode_h3_q_and_qbar(
    q_groups: TCitHElementGroups,
    qbar_groups: TCitHElementGroups,
) -> bytes:
    """Encode q/Qbar pairs, interleaved within each canonical tree group."""

    checked_q = _validate_groups(q_groups, "q_groups")
    checked_qbar = _validate_groups(qbar_groups, "qbar_groups")
    encoded_groups: list[bytes] = []
    for group_index, (mu, _entry_count) in enumerate(_GROUP_SPECS):
        interleaved = tuple(
            element
            for pair in zip(
                checked_q[group_index],
                checked_qbar[group_index],
                strict=True,
            )
            for element in pair
        )
        encoded_groups.append(_pack_group(interleaved, mu))
    encoded = b"".join(encoded_groups)
    if len(encoded) != _H3_Q_AND_QBAR_BYTES:
        raise AssertionError("unreachable h3 q/Qbar length")
    return encoded


def decode_h3_q_and_qbar(
    encoded: bytes,
) -> tuple[TCitHElementGroups, TCitHElementGroups]:
    """Decode one complete 888-byte group-local interleaved q/Qbar stream."""

    checked = _require_encoded(encoded, "encoded", _H3_Q_AND_QBAR_BYTES)
    q_groups: list[tuple[int, ...]] = []
    qbar_groups: list[tuple[int, ...]] = []
    byte_offset = 0
    for mu, entry_count in _GROUP_SPECS:
        group_bytes = entry_count * 2 * mu // 8
        group_end = byte_offset + group_bytes
        interleaved = _unpack_group(
            checked[byte_offset:group_end], mu, entry_count * 2
        )
        q_groups.append(interleaved[0::2])
        qbar_groups.append(interleaved[1::2])
        byte_offset = group_end
    if byte_offset != len(checked):
        raise AssertionError("unreachable h3 q/Qbar parse length")
    return tuple(q_groups), tuple(qbar_groups)


__all__ = (
    "TCitHElementGroups",
    "ResponseEncodingError",
    "encode_tcith_responses",
    "decode_tcith_responses",
    "encode_h3_q_and_qbar",
    "decode_h3_q_and_qbar",
)
