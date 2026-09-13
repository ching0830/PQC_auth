"""Test-only, separately coded byte-to-plaintext oracle for the frozen GF profile.

No imports from the implementation or its test helpers. Polynomial products use
carry-free integer multiplication, not the implementation's wraparound loops.
This is a second calculation by the same author, not an independent attestation.
"""

from fractions import Fraction
import hashlib
import struct

PROFILE = b"gf-hybrid2-pompeii-d4-shake256-otp-ref-v1"
MAGIC = b"PQ-TH-GF-TB2\x00"
N, D, Q, P, MU = 256, 4, 4188161, 1024, 256
BODY_LENGTHS = {1: 22528, 2: 2848, 3: 128}


def center(x, modulus):
    half = (modulus - 1) // 2
    return (x + half) % modulus - half


def product(a, b, modulus):
    """Pack positive residues into base B > n*(q-1)^2, then fold X^n=-1."""
    n = len(a)
    if not n or n != len(b):
        raise ValueError("mismatched oracle polynomials")
    width = (n * (modulus - 1) ** 2).bit_length()
    mask = (1 << width) - 1
    left = sum((x % modulus) << (i * width) for i, x in enumerate(a))
    right = sum((x % modulus) << (i * width) for i, x in enumerate(b))
    raw = left * right
    return tuple(center(((raw >> (k * width)) & mask)
                        - ((raw >> ((k + n) * width)) & mask), modulus) for k in range(n))


def pack(values, width, modulus):
    bits = [(value % modulus >> j) & 1 for value in values for j in range(width)]
    return bytes(sum(bit << j for j, bit in enumerate(bits[i:i + 8])) for i in range(0, len(bits), 8))


def unpack(body, count, width, modulus):
    if type(body) is not bytes or len(body) != (count * width + 7) // 8:
        raise ValueError("bad oracle coefficient length")
    values = []
    for i in range(count):
        value = sum(((body[(i * width + j) // 8] >> ((i * width + j) % 8)) & 1) << j for j in range(width))
        if value >= modulus:
            raise ValueError("oracle coefficient outside modulus")
        values.append(center(value, modulus))
    for i in range(count * width, len(body) * 8):
        if body[i // 8] & (1 << (i % 8)):
            raise ValueError("nonzero oracle tail bits")
    return tuple(values)


def record(kind, body):
    if type(body) is not bytes or len(body) != BODY_LENGTHS[kind]:
        raise ValueError("bad oracle record body")
    return MAGIC + struct.pack('<HBB', 1, kind, len(PROFILE)) + PROFILE + struct.pack('<I', len(body)) + body


def parse_record(encoded, expected_kind):
    if type(encoded) is not bytes or len(encoded) < len(MAGIC) + 4:
        raise ValueError("short oracle record")
    if encoded[:len(MAGIC)] != MAGIC:
        raise ValueError("wrong oracle domain")
    version, kind, plen = struct.unpack_from('<HBB', encoded, len(MAGIC))
    offset = len(MAGIC) + 4
    if version != 1 or kind != expected_kind or encoded[offset:offset + plen] != PROFILE:
        raise ValueError("wrong oracle identity")
    offset += plen
    if len(encoded) < offset + 4:
        raise ValueError("missing oracle length")
    length, = struct.unpack_from('<I', encoded, offset)
    offset += 4
    if length != BODY_LENGTHS[kind] or len(encoded) != offset + length:
        raise ValueError("wrong oracle length or trailing bytes")
    return encoded[offset:]


def public_key(encoded):
    coeffs = unpack(parse_record(encoded, 1), 8192, 22, Q)
    return tuple(tuple(tuple(coeffs[(h * D * D + i * D + j) * N:(h * D * D + i * D + j + 1) * N]
                             for j in range(D)) for i in range(D)) for h in range(2))


def row_product(row, matrix):
    result = []
    for column in range(D):
        products = [product(row[i], matrix[i][column], Q) for i in range(D)]
        result.append(tuple(center(sum(poly[k] for poly in products), Q) for k in range(N)))
    return tuple(result)


def base_encrypt(pk, u):
    if type(u) is not bytes or len(u) != 128:
        raise ValueError("bad oracle u")
    bits = unpack(u, N * D, 1, 2)
    row = tuple(bits[i * N:(i + 1) * N] for i in range(D))
    coefficients = []
    for matrix in pk:
        for poly in row_product(row, matrix):
            for value in poly:
                rational = Fraction(value * P, Q)
                floor = rational.numerator // rational.denominator
                nearest = min((floor, floor + 1), key=lambda x: (abs(rational - x), abs(x)))
                coefficients.append(center(nearest, P))
    return pack(coefficients, 10, P)


def hash_value(label, output_bytes, *arguments):
    framed = MAGIC + struct.pack('<HB', 1, len(PROFILE)) + PROFILE
    framed += bytes([len(label)]) + label
    for argument in arguments:
        framed += struct.pack('<I', len(argument)) + argument
    return hashlib.shake_256(framed).digest(output_bytes)


def encrypt(pk_record, u, ad, plaintext):
    if type(ad) is not bytes or len(ad) != 80 or type(plaintext) is not bytes or len(plaintext) != 48:
        raise ValueError("bad oracle trace shape")
    # Allows a mismatched serial intentionally, to construct authenticated invalid input.
    c1 = base_encrypt(public_key(pk_record), u)
    c2 = bytes(x ^ y for x, y in zip(ad + plaintext, hash_value(b'H', 128, u)))
    c3 = hash_value(b'G', 32, c2, hash_value(b'H_prime', 128, u))
    c4 = hash_value(b'H_double_prime', 128, u)
    return record(2, c1 + c2 + c3 + c4)


def decrypt(pk_record, r1, ad, ciphertext_record):
    """Return 48-byte plaintext or None. Full key material is test-local input."""
    try:
        if type(ad) is not bytes or len(ad) != 80:
            return None
        pk = public_key(pk_record)
        body = parse_record(ciphertext_record, 2)
        coefficients = unpack(body[:2560], 2048, 10, P)
        left = tuple(coefficients[i * N:(i + 1) * N] for i in range(D))
        right = coefficients[1024:]
        multiplied = tuple(x for poly in row_product(left, r1) for x in poly)
        decoded = []
        for b, a in zip(right, multiplied):
            w = center(b - a, Q)
            e = center(w, P)
            v = center(e, MU)
            coefficient, remainder = divmod(e - v, MU)
            if remainder or coefficient not in (0, 1):
                return None
            decoded.append(coefficient)
        u = pack(decoded, 1, 2)
        if base_encrypt(pk, u) != body[:2560]:
            return None
        c2, c3, c4 = body[2560:2688], body[2688:2720], body[2720:2848]
        if c4 != hash_value(b'H_double_prime', 128, u):
            return None
        if c3 != hash_value(b'G', 32, c2, hash_value(b'H_prime', 128, u)):
            return None
        message = bytes(x ^ y for x, y in zip(c2, hash_value(b'H', 128, u)))
        if message[:80] != ad or message[112:] != ad[32:48]:
            return None
        return message[80:]
    except (ValueError, struct.error):
        return None
