"""Exact integer arithmetic for Z_q[X]/(X^n+1), without floating-point rounding."""

from ..contracts import ContractError, uint


def centered(value: int, modulus: int) -> int:
    if type(value) is not int or type(modulus) is not int or modulus < 2:
        raise ContractError("integer value and modulus >= 2 required")
    residue = value % modulus
    return residue - modulus if 2 * residue > modulus else residue


def nearest_ties_to_zero(numerator: int, denominator: int) -> int:
    if type(numerator) is not int or type(denominator) is not int or denominator <= 0:
        raise ContractError("integer numerator and positive denominator required")
    magnitude, remainder = divmod(abs(numerator), denominator)
    rounded = magnitude + (2 * remainder > denominator)
    return -rounded if numerator < 0 else rounded


def round_q_to_p(value: int, q: int, p: int) -> int:
    return centered(nearest_ties_to_zero(centered(value, q) * p, q), p)


def negacyclic_mul(a: tuple[int, ...], b: tuple[int, ...], modulus: int) -> tuple[int, ...]:
    if type(a) is not tuple or type(b) is not tuple or not a or len(a) != len(b):
        raise ContractError("equal nonempty polynomial tuples required")
    if len(a) & (len(a) - 1) or any(type(x) is not int for x in a + b):
        raise ContractError("power-of-two polynomial length and integer coefficients required")
    centered(0, modulus)
    n = len(a)
    result = [0] * n
    nonzero_b = [(j, y) for j, y in enumerate(b) if y]
    for i, x in enumerate(a):
        if x:
            for j, y in nonzero_b:
                k = i + j
                if k < n:
                    result[k] += x * y
                else:
                    result[k - n] -= x * y
    return tuple(centered(x, modulus) for x in result)


def pack_coefficients(values: tuple[int, ...], bits: int, modulus: int) -> bytes:
    """Map canonical centered coefficients to packed nonnegative residues."""
    if type(values) is not tuple:
        raise ContractError("immutable coefficients required")
    uint(bits, "coefficient width", 32)
    if bits == 0 or type(modulus) is not int or not 2 <= modulus <= 1 << bits:
        raise ContractError("invalid packing modulus")
    if any(type(x) is not int or x != centered(x, modulus) for x in values):
        raise ContractError("noncanonical centered coefficient")
    packed = 0
    for i, value in enumerate(values):
        packed |= (value % modulus) << (bits * i)
    return packed.to_bytes((len(values) * bits + 7) // 8, "little")


def unpack_coefficients(data: bytes, count: int, bits: int, modulus: int) -> tuple[int, ...]:
    uint(count, "coefficient count", 1 << 20)
    uint(bits, "coefficient width", 32)
    if bits == 0 or type(modulus) is not int or not 2 <= modulus <= 1 << bits:
        raise ContractError("invalid packing modulus")
    if type(data) is not bytes or len(data) != (count * bits + 7) // 8:
        raise ContractError("wrong packed polynomial length or type")
    packed = int.from_bytes(data, "little")
    if packed >> (count * bits):
        raise ContractError("nonzero unused packing bits")
    mask = (1 << bits) - 1
    values = tuple((packed >> (bits * i)) & mask for i in range(count))
    if any(value >= modulus for value in values):
        raise ContractError("coefficient outside modulus")
    return tuple(centered(value, modulus) for value in values)
