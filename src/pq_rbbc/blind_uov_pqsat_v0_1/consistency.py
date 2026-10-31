"""Canonical consistency-polynomial packing for Blind-UOV/CAP v0.1.

The constant coefficient of every ``xi`` polynomial is a 256-bit vector over
``F_2``.  Its linear coefficient is instead a vector of 256 elements in the
TCitH extension field bound to the repetition position: ``GF(2^12)`` for
repetitions 0 and 1, and ``GF(2^11)`` for repetitions 2 through 17.

Both the element coefficient bits and the resulting byte stream are packed
least-significant-bit first, without per-element alignment or padding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, TypeAlias


class ConsistencyEncodingError(ValueError):
    """A controlled rejection of a noncanonical ``xi`` representation."""


@dataclass(frozen=True, slots=True)
class XiPolynomial:
    """One degree-one consistency polynomial in canonical coefficient form."""

    constant: bytes
    linear: tuple[int, ...]

    def __post_init__(self) -> None:
        if type(self.constant) is not bytes:
            raise TypeError("constant must be exact bytes")
        if len(self.constant) != 32:
            raise ConsistencyEncodingError("constant must be exactly 32 bytes")
        if type(self.linear) is not tuple:
            raise TypeError("linear must be an exact tuple")
        if len(self.linear) != 256:
            raise ConsistencyEncodingError(
                "linear must contain exactly 256 elements"
            )
        for index, value in enumerate(self.linear):
            if type(value) is not int:
                raise TypeError(f"linear[{index}] must be an exact int")


XiPolynomials: TypeAlias = tuple[XiPolynomial, ...]


_REPETITIONS: Final = 18
_CONSTANT_BYTES: Final = 32
_LINEAR_ELEMENTS: Final = 256
_MU_BY_REPETITION: Final = (12, 12) + (11,) * 16
_ENCODED_BYTES: Final = 6976


def _validate_polynomials(value: object) -> XiPolynomials:
    if type(value) is not tuple:
        raise TypeError("polynomials must be an exact tuple")
    if len(value) != _REPETITIONS:
        raise ConsistencyEncodingError(
            "polynomials must contain exactly 18 repetitions"
        )

    for repetition, polynomial in enumerate(value):
        if type(polynomial) is not XiPolynomial:
            raise TypeError(
                f"polynomials[{repetition}] must be exactly XiPolynomial"
            )
        # Repeat the frozen-dataclass boundary checks so an object constructed
        # through low-level means cannot cross the production encoder.
        if type(polynomial.constant) is not bytes:
            raise TypeError(f"polynomials[{repetition}].constant must be exact bytes")
        if len(polynomial.constant) != _CONSTANT_BYTES:
            raise ConsistencyEncodingError(
                f"polynomials[{repetition}].constant must be exactly 32 bytes"
            )
        if type(polynomial.linear) is not tuple:
            raise TypeError(
                f"polynomials[{repetition}].linear must be an exact tuple"
            )
        if len(polynomial.linear) != _LINEAR_ELEMENTS:
            raise ConsistencyEncodingError(
                f"polynomials[{repetition}].linear must contain exactly 256 elements"
            )
        upper_bound = 1 << _MU_BY_REPETITION[repetition]
        for index, element in enumerate(polynomial.linear):
            if type(element) is not int:
                raise TypeError(
                    f"polynomials[{repetition}].linear[{index}] must be an exact int"
                )
            if not 0 <= element < upper_bound:
                raise ConsistencyEncodingError(
                    f"polynomials[{repetition}].linear[{index}] is outside "
                    f"GF(2^{_MU_BY_REPETITION[repetition]})"
                )
    return value


def _pack_linear(elements: tuple[int, ...], mu: int) -> bytes:
    bit_count = _LINEAR_ELEMENTS * mu
    if bit_count % 8:
        raise AssertionError("frozen xi linear coefficient is not byte-aligned")
    accumulator = 0
    bit_offset = 0
    for element in elements:
        accumulator |= element << bit_offset
        bit_offset += mu
    return accumulator.to_bytes(bit_count // 8, "little")


def _unpack_linear(encoded: bytes, mu: int) -> tuple[int, ...]:
    accumulator = int.from_bytes(encoded, "little")
    mask = (1 << mu) - 1
    return tuple(
        (accumulator >> (index * mu)) & mask
        for index in range(_LINEAR_ELEMENTS)
    )


def encode_xi_polynomials(polynomials: XiPolynomials) -> bytes:
    """Encode all 18 repetitions in their position-bound extension fields."""

    checked = _validate_polynomials(polynomials)
    pieces: list[bytes] = []
    for repetition, polynomial in enumerate(checked):
        pieces.append(polynomial.constant)
        pieces.append(
            _pack_linear(polynomial.linear, _MU_BY_REPETITION[repetition])
        )
    encoded = b"".join(pieces)
    if len(encoded) != _ENCODED_BYTES:
        raise AssertionError("unreachable xi-polynomial encoding length")
    return encoded


def decode_xi_polynomials(encoded: bytes) -> XiPolynomials:
    """Decode one complete canonical 6,976-byte consistency transcript."""

    if type(encoded) is not bytes:
        raise TypeError("encoded must be exact bytes")
    if len(encoded) != _ENCODED_BYTES:
        raise ConsistencyEncodingError(
            f"encoded must be exactly {_ENCODED_BYTES} bytes"
        )

    polynomials: list[XiPolynomial] = []
    offset = 0
    for mu in _MU_BY_REPETITION:
        constant_end = offset + _CONSTANT_BYTES
        linear_end = constant_end + (_LINEAR_ELEMENTS * mu // 8)
        polynomials.append(
            XiPolynomial(
                constant=encoded[offset:constant_end],
                linear=_unpack_linear(encoded[constant_end:linear_end], mu),
            )
        )
        offset = linear_end
    if offset != len(encoded):
        raise AssertionError("unreachable xi-polynomial parse length")
    return tuple(polynomials)


__all__ = (
    "ConsistencyEncodingError",
    "XiPolynomial",
    "XiPolynomials",
    "decode_xi_polynomials",
    "encode_xi_polynomials",
)
