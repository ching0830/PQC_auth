"""Paper-shaped single-machine reference plus a locally specified Hybrid2 DEM.

Variable-time Python with full secret keys. No threshold, ZK, or production API.
See docs/literature/threshold_backends/gf/ for exact source and claim boundaries.
"""

from dataclasses import dataclass, field
import hashlib
import secrets

from ..contracts import ContractError, TraceInputs, fixed_bytes
from .arithmetic import centered, negacyclic_mul, pack_coefficients, round_q_to_p, unpack_coefficients
from .profile import (
    CIPHERTEXT_BYTES, D, DEM_BYTES, ELL, G_BYTES, MAGIC, MU_SCALE, N, P,
    POMPEII_BYTES, PROFILE_ID, PUBLIC_KEY_BYTES, Q, U_BYTES, VERSION,
)

Poly = tuple[int, ...]
Vector = tuple[Poly, ...]
Matrix = tuple[Vector, ...]
_KINDS = {1: PUBLIC_KEY_BYTES, 2: CIPHERTEXT_BYTES, 3: U_BYTES}


def _domain(label: bytes, *args: bytes) -> bytes:
    prefix = (MAGIC + VERSION.to_bytes(2, "little") + bytes([len(PROFILE_ID)])
              + PROFILE_ID.encode("ascii") + bytes([len(label)]) + label)
    return prefix + b"".join(len(arg).to_bytes(4, "little") + arg for arg in args)


def _hash(label: bytes, length: int, *args: bytes) -> bytes:
    return hashlib.shake_256(_domain(label, *args)).digest(length)


def _encode_record(kind: int, payload: bytes) -> bytes:
    fixed_bytes(payload, _KINDS[kind], "record payload")
    return (MAGIC + VERSION.to_bytes(2, "little") + bytes([kind, len(PROFILE_ID)])
            + PROFILE_ID.encode("ascii") + len(payload).to_bytes(4, "little") + payload)


def _decode_record(data: bytes, kind: int) -> bytes:
    header = _encode_record(kind, b"\x00" * _KINDS[kind])[:-_KINDS[kind]]
    if type(data) is not bytes or len(data) != len(header) + _KINDS[kind] or data[:len(header)] != header:
        raise ContractError("unknown version/profile/kind, noncanonical length, or trailing bytes")
    return data[len(header):]


def _validate_matrix(matrix: Matrix, modulus: int, *, noise: bool = False) -> None:
    if type(matrix) is not tuple or len(matrix) != D:
        raise ContractError("wrong matrix dimension")
    for row in matrix:
        if type(row) is not tuple or len(row) != D:
            raise ContractError("wrong matrix row dimension")
        for poly in row:
            if type(poly) is not tuple or len(poly) != N:
                raise ContractError("wrong polynomial shape")
            if any(type(x) is not int or x != centered(x, modulus) or (noise and x not in (-1, 0, 1)) for x in poly):
                raise ContractError("noncanonical matrix coefficient")


def _flatten(matrix: Matrix) -> tuple[int, ...]:
    return tuple(x for row in matrix for poly in row for x in poly)


def _matrix(values: tuple[int, ...]) -> Matrix:
    return tuple(tuple(values[(i * D + j) * N:(i * D + j + 1) * N] for j in range(D)) for i in range(D))


@dataclass(frozen=True)
class ReferencePublicKey:
    a1: Matrix = field(repr=False)
    a2: Matrix = field(repr=False)

    def __post_init__(self) -> None:
        _validate_matrix(self.a1, Q)
        _validate_matrix(self.a2, Q)

    def encode(self) -> bytes:
        return _encode_record(1, pack_coefficients(_flatten(self.a1) + _flatten(self.a2), 22, Q))

    @classmethod
    def decode(cls, data: bytes) -> "ReferencePublicKey":
        values = unpack_coefficients(_decode_record(data, 1), 2 * D * D * N, 22, Q)
        midpoint = D * D * N
        return cls(_matrix(values[:midpoint]), _matrix(values[midpoint:]))


@dataclass(frozen=True)
class ReferenceSecretKey:
    public_key: ReferencePublicKey = field(repr=False)
    r1: Matrix = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.public_key) is not ReferencePublicKey:
            raise ContractError("reference public key required")
        _validate_matrix(self.r1, Q, noise=True)


@dataclass(frozen=True)
class ReferenceWitness:
    """Secret u in R_2^d. Reusing it repeats the OTP; never log or publish it."""

    u: bytes = field(repr=False)

    def __post_init__(self) -> None:
        fixed_bytes(self.u, U_BYTES, "secret witness u")

    def encode(self) -> bytes:
        return _encode_record(3, self.u)

    @classmethod
    def decode(cls, data: bytes) -> "ReferenceWitness":
        return cls(_decode_record(data, 3))


@dataclass(frozen=True)
class ReferenceCiphertext:
    payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        fixed_bytes(self.payload, CIPHERTEXT_BYTES, "Hybrid2 ciphertext payload")

    def encode(self) -> bytes:
        return _encode_record(2, self.payload)

    @classmethod
    def decode(cls, data: bytes) -> "ReferenceCiphertext":
        return cls(_decode_record(data, 2))


class _XofReader:
    def __init__(self, label: bytes, seed: bytes) -> None:
        self._xof = hashlib.shake_256(_domain(label, seed))
        self._buffer = b""
        self._offset = 0

    def read(self, size: int) -> bytes:
        end = self._offset + size
        if end > len(self._buffer):
            self._buffer = self._xof.digest(max(end, 2 * len(self._buffer), 16384))
        data = self._buffer[self._offset:end]
        self._offset = end
        return data


def _uniform_q(reader: _XofReader) -> int:
    while True:
        value = int.from_bytes(reader.read(3), "little") & ((1 << 22) - 1)
        if value < Q:
            return centered(value, Q)


def _cbd1(reader: _XofReader) -> int:
    value = reader.read(1)[0]
    return (value & 1) - ((value >> 1) & 1)


def _row_times_matrix(vector: Vector, matrix: Matrix, modulus: int) -> Vector:
    result = []
    for j in range(D):
        products = [negacyclic_mul(vector[i], matrix[i][j], modulus) for i in range(D)]
        result.append(tuple(centered(sum(poly[k] for poly in products), modulus) for k in range(N)))
    return tuple(result)


def keygen_reference_for_test(seed: bytes) -> tuple[ReferencePublicKey, ReferenceSecretKey]:
    """Deterministic research harness; the seed reveals the entire secret key."""
    fixed_bytes(seed, 32, "test-only keygen seed")
    readers = [_XofReader(label, seed) for label in (b"KEYGEN-A1", b"KEYGEN-R1", b"KEYGEN-R2")]
    a1 = _matrix(tuple(_uniform_q(readers[0]) for _ in range(D * D * N)))
    r1 = _matrix(tuple(_cbd1(readers[1]) for _ in range(D * D * N)))
    r2 = _matrix(tuple(_cbd1(readers[2]) for _ in range(D * D * N)))
    a2 = []
    for i in range(D):
        row = _row_times_matrix(a1[i], r1, Q)
        a2.append(tuple(tuple(centered(row[j][k] + r2[i][j][k] + (ELL if i == j and k == 0 else 0), Q)
                             for k in range(N)) for j in range(D)))
    public_key = ReferencePublicKey(a1, tuple(a2))
    return public_key, ReferenceSecretKey(public_key, r1)


def keygen_reference() -> tuple[ReferencePublicKey, ReferenceSecretKey]:
    return keygen_reference_for_test(secrets.token_bytes(32))


def sample_witness_reference() -> ReferenceWitness:
    return ReferenceWitness(secrets.token_bytes(U_BYTES))


def _u_vector(u: bytes) -> Vector:
    values = unpack_coefficients(u, N * D, 1, 2)
    return tuple(values[i * N:(i + 1) * N] for i in range(D))


def pompeii_encrypt_reference(public_key: ReferencePublicKey, u: bytes) -> bytes:
    if type(public_key) is not ReferencePublicKey:
        raise ContractError("reference public key required")
    fixed_bytes(u, U_BYTES, "Pompeii message")
    vector = _u_vector(u)
    values = tuple(round_q_to_p(x, Q, P)
                   for matrix in (public_key.a1, public_key.a2)
                   for poly in _row_times_matrix(vector, matrix, Q) for x in poly)
    return pack_coefficients(values, 10, P)


def pompeii_decrypt_reference_for_test(secret_key: ReferenceSecretKey, ciphertext: bytes) -> bytes | None:
    if type(secret_key) is not ReferenceSecretKey:
        raise ContractError("reference secret key required")
    try:
        values = unpack_coefficients(ciphertext, 2 * D * N, 10, P)
    except ContractError:
        return None
    c1 = tuple(values[i * N:(i + 1) * N] for i in range(D))
    c2 = values[D * N:]
    product = tuple(x for poly in _row_times_matrix(c1, secret_key.r1, Q) for x in poly)
    decoded = []
    for c, r in zip(c2, product):
        w = centered(c - r, Q)
        e = centered(w, P)
        v = centered(e, MU_SCALE)
        m = (e - v) // MU_SCALE
        if m not in (0, 1):
            return None
        decoded.append(m)
    u = pack_coefficients(tuple(decoded), 1, 2)
    if not secrets.compare_digest(pompeii_encrypt_reference(secret_key.public_key, u), ciphertext):
        return None
    return u


def encrypt_reference(public_key: ReferencePublicKey, inputs: TraceInputs,
                      witness: ReferenceWitness) -> ReferenceCiphertext:
    if type(inputs) is not TraceInputs or type(witness) is not ReferenceWitness:
        raise ContractError("canonical trace inputs and reference witness required")
    u = witness.u
    c1 = pompeii_encrypt_reference(public_key, u)
    pad = _hash(b"H", DEM_BYTES, u)
    message = inputs.associated_data + inputs.plaintext
    c2 = bytes(x ^ y for x, y in zip(message, pad))
    mu = _hash(b"H_prime", U_BYTES, u)
    c3 = _hash(b"G", G_BYTES, c2, mu)
    c4 = _hash(b"H_double_prime", U_BYTES, u)
    return ReferenceCiphertext(c1 + c2 + c3 + c4)


def decrypt_reference_for_test(secret_key: ReferenceSecretKey, associated_data: bytes,
                               ciphertext: ReferenceCiphertext) -> bytes | None:
    if type(secret_key) is not ReferenceSecretKey:
        raise ContractError("reference secret key required")
    if type(associated_data) is not bytes or len(associated_data) != 80 or type(ciphertext) is not ReferenceCiphertext:
        return None
    body = ciphertext.payload
    c1 = body[:POMPEII_BYTES]
    c2 = body[POMPEII_BYTES:POMPEII_BYTES + DEM_BYTES]
    c3 = body[POMPEII_BYTES + DEM_BYTES:POMPEII_BYTES + DEM_BYTES + G_BYTES]
    c4 = body[-U_BYTES:]
    u = pompeii_decrypt_reference_for_test(secret_key, c1)
    if u is None or not secrets.compare_digest(c4, _hash(b"H_double_prime", U_BYTES, u)):
        return None
    mu = _hash(b"H_prime", U_BYTES, u)
    if not secrets.compare_digest(c3, _hash(b"G", G_BYTES, c2, mu)):
        return None
    message = bytes(x ^ y for x, y in zip(c2, _hash(b"H", DEM_BYTES, u)))
    if not secrets.compare_digest(message[:80], associated_data):
        return None
    plaintext = message[80:]
    if not secrets.compare_digest(plaintext[32:], associated_data[32:48]):
        return None
    return plaintext


def check_encryption_relation_reference(public_key: ReferencePublicKey, inputs: TraceInputs,
                                         ciphertext: ReferenceCiphertext,
                                         witness: ReferenceWitness) -> bool:
    """Witness-bearing I5 evaluator only. It is not VerifyIssue or a ZK proof."""
    if type(ciphertext) is not ReferenceCiphertext:
        return False
    try:
        expected = encrypt_reference(public_key, inputs, witness)
    except ContractError:
        return False
    return secrets.compare_digest(expected.payload, ciphertext.payload)
