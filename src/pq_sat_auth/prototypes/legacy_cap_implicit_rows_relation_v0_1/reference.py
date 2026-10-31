"""Versioned minimal exact helper copies; no historical/root package imports."""
import hashlib
import struct
from functools import lru_cache
from .contract import FINGERPRINT
TAPE_DOMAIN = b"PQSAT-BUOV-CAP-0.1/TAPE-EXPAND"
REPETITION, POSITION, TAPE_BYTES = 2, 0, 291
DELTA_P2_BYTE = 146 + 32 + 288

DOMAIN = b"PQSAT-BUOV-CAP-0.1/CONSISTENCY-MATRIX"

CR_HEADER = (b"PQSCAP01\x00\x01\x00\x01\xff\x32" + FINGERPRINT +
             (5024).to_bytes(4, "big"))

GF11_MODULUS = 2053

MODULUS = 0x1000000000000001B

def bits(raw):
    return tuple((b >> j) & 1 for b in raw for j in range(8))

def gf_mul(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        b >>= 1
        a <<= 1
        if a >> 64:
            a ^= MODULUS
    return result

def gf11_mul(a, b):
    result = 0
    for _ in range(11):
        if b & 1:
            result ^= a
        b >>= 1
        a <<= 1
        if a & 2048:
            a ^= GF11_MODULUS
    return result

@lru_cache(maxsize=1)
def reciprocal_table():
    """Public immutable constants: inverses(1..2047), then infinity0."""
    table = []
    for value in range(1, 2048):
        inverse, base, exponent = 1, value, 2046
        while exponent:
            if exponent & 1:
                inverse = gf11_mul(inverse, base)
            base = gf11_mul(base, base)
            exponent >>= 1
        table.append(inverse)
    return tuple(table) + (0,)

def aggregate(parties):
    if type(parties) is not bytes or len(parties) != 256:
        raise ValueError("party bits256B")
    plain, slope = 0, 0
    for bit, reciprocal in zip(bits(parties), reciprocal_table()):
        plain ^= bit
        if bit:
            slope ^= reciprocal
    return plain, slope

def alpha_bytes(P, Mhat, h1):
    framed = struct.pack(">H", len(DOMAIN)) + DOMAIN + struct.pack(">HI", 2, 32) + FINGERPRINT + struct.pack(">I", 48) + h1
    points = hashlib.shake_256(framed).digest(32)
    coefficients = [int.from_bytes(P[j:j + 8], "little") for j in range(0, 256, 8)]
    alpha = bytearray()
    for j in range(4):
        point = int.from_bytes(points[8 * j:8 * (j + 1)], "little")
        acc = coefficients[-1]
        for c in reversed(coefficients[:-1]):
            acc = gf_mul(acc, point) ^ c
        acc ^= int.from_bytes(Mhat[8 * j:8 * (j + 1)], "little")
        alpha.extend(acc.to_bytes(8, "little"))
    return bytes(alpha)

def private_input(CR, P, Mhat, h1, r, parties, slopes):
    for value, n in zip((CR, P, Mhat, h1, r, parties, slopes), (5074, 256, 32, 48, 72, 256, 2)):
        if type(value) is not bytes or len(value) != n:
            raise ValueError("private input width")
    if int.from_bytes(slopes, "little") >= 2048:
        raise ValueError("noncanonical slope high bits")
    return CR + P + Mhat + h1 + r + parties + slopes

def bind_private(CR, P, Mhat, h1, parties):
    """Private reference witness builder; no proof/issuance verification."""
    plain, slope = aggregate(parties)
    corrected = plain ^ (CR[DELTA_P2_BYTE] & 1)
    P = bytes([(P[0] & 254) | corrected]) + P[1:]
    alpha = alpha_bytes(P, Mhat, h1)
    CR = CR[:146] + alpha + CR[178:]
    return private_input(CR, P, Mhat, h1, P[:72], parties, slope.to_bytes(2, "little"))

def reference_private(random_bytes):
    """Fresh private fixture. Use cryptographic RNG; pipe5740B, never log."""
    CR = CR_HEADER + random_bytes(5024)
    return bind_private(CR, random_bytes(256), random_bytes(32), random_bytes(48), random_bytes(256))

def canonical_frame(salt, leaf_seed, fingerprint=FINGERPRINT):
    for value, length in ((salt, 48), (leaf_seed, 24), (fingerprint, 32)):
        if type(value) is not bytes or len(value) != length:
            raise ValueError("canonical input widths")
    fields = (fingerprint, salt, REPETITION.to_bytes(2, "big"), POSITION.to_bytes(2, "big"), leaf_seed)
    return (len(TAPE_DOMAIN).to_bytes(2, "big") + TAPE_DOMAIN + len(fields).to_bytes(2, "big") +
            b"".join(len(field).to_bytes(4, "big") + field for field in fields))

def canonical_tape(salt, leaf_seed):
    raw = hashlib.shake_256(canonical_frame(salt, leaf_seed)).digest(TAPE_BYTES)
    return raw[:-1] + bytes([raw[-1] & 3])

RC = (1, 0x8082, 0x800000000000808a, 0x8000000080008000, 0x808b,
      0x80000001, 0x8000000080008081, 0x8000000000008009, 0x8a, 0x88,
      0x80008009, 0x8000000a, 0x8000808b, 0x800000000000008b,
      0x8000000000008089, 0x8000000000008003, 0x8000000000008002,
      0x8000000000000080, 0x800a, 0x800000008000000a,
      0x8000000080008081, 0x8000000000008080, 0x80000001,
      0x8000000080008008)

RHO = (0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
       25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14)
