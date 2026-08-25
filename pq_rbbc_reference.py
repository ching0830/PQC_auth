#!/usr/bin/env python3
"""Executable v2.12 reference relation for the PQ-RBBC/SGTD research draft.

This module implements the *incremental* five-block issuance relation described
in the accompanying proof document.  It emits a streaming characteristic-two
circuit IR and checks an honest witness.  The separate CAP module implements
the source-grounded reference algorithm, canonical commitment serialization,
and exact byte join to H_RBBC.  This module deliberately does not implement:

* the 18 native tree-producer segments and their exact cross-segment wire
  identities (the shared global tail is native, but a test CAP adapter is
  still used by this incremental relation);
* a proof-system backend or flattened R1CS matrix serialization;
* a certified Goppa parity-check key or threshold decoder.

The deterministic parity-check matrix and forked issuance adapter below are test
fixtures.  They are useful for checking bindings and gate counts, not for
deployment or cryptographic benchmarking.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Iterable, Protocol, Sequence

import pq_rbbc_native_profile as native_profile
from pq_rbbc_blind_uov_abi import (
    BlindUOVAdapter,
    BlindUOVRequest as BlindRequest,
    TestPQRBBC336Adapter,
)


N = 6688
K = 5024
R = N - K
T = 128
RATE = 136
SIGNATURE_BYTES = 11644
BLIND_UOV_PUBLIC_KEY_KILOBYTES = 189.2
CUSTOMIZATION = b"PQ-RBBC/TAG"

LABEL_HOLD = b"PQ-RBBC/HOLD"
LABEL_KDF = b"PQ-RBBC/KDF"
LABEL_TICKET = b"PQ-RBBC/TICKET"

MASK64 = (1 << 64) - 1
RHO = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
ROUND_CONSTANTS = (
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


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("xor operands must have equal length")
    return bytes(a ^ b for a, b in zip(left, right))


def bits_from_bytes(data: bytes) -> list[int]:
    """Return the FIPS-202 bit order: least-significant bit first per byte."""
    return [(byte >> bit) & 1 for byte in data for bit in range(8)]


def bytes_from_bits(bits: Sequence[int]) -> bytes:
    if len(bits) % 8:
        raise ValueError("bit length must be byte aligned")
    out = bytearray(len(bits) // 8)
    for i, bit in enumerate(bits):
        out[i // 8] |= (int(bit) & 1) << (i % 8)
    return bytes(out)


def left_encode(value: int) -> bytes:
    if value < 0:
        raise ValueError("left_encode expects a non-negative integer")
    width = max(1, (value.bit_length() + 7) // 8)
    return bytes([width]) + value.to_bytes(width, "big")


def right_encode(value: int) -> bytes:
    if value < 0:
        raise ValueError("right_encode expects a non-negative integer")
    width = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(width, "big") + bytes([width])


def encode_string(data: bytes) -> bytes:
    return left_encode(8 * len(data)) + data


def bytepad(data: bytes, width: int) -> bytes:
    if width <= 0:
        raise ValueError("bytepad width must be positive")
    encoded = left_encode(width) + data
    return encoded + bytes((-len(encoded)) % width)


def _rot64(value: int, amount: int) -> int:
    if amount == 0:
        return value & MASK64
    return ((value << amount) | (value >> (64 - amount))) & MASK64


def keccak_f1600_lanes(state: list[int]) -> None:
    """In-place Keccak-f[1600], with state indexed as x + 5*y."""
    if len(state) != 25:
        raise ValueError("Keccak state must contain 25 lanes")
    for rc in ROUND_CONSTANTS:
        column = [
            state[x]
            ^ state[x + 5]
            ^ state[x + 10]
            ^ state[x + 15]
            ^ state[x + 20]
            for x in range(5)
        ]
        delta = [column[(x - 1) % 5] ^ _rot64(column[(x + 1) % 5], 1) for x in range(5)]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= delta[x]

        moved = [0] * 25
        for y in range(5):
            for x in range(5):
                moved[y + 5 * ((2 * x + 3 * y) % 5)] = _rot64(
                    state[x + 5 * y], RHO[x][y]
                )

        for y in range(5):
            row = moved[5 * y : 5 * y + 5]
            for x in range(5):
                state[x + 5 * y] = (
                    row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
                ) & MASK64
        state[0] ^= rc


def keccak_sponge(data: bytes, output_bytes: int, suffix: int) -> bytes:
    """Byte-aligned Keccak sponge with the SHAKE/cSHAKE domain suffix."""
    if not 0 <= suffix <= 0x7F:
        raise ValueError("suffix must leave room for the final padding bit")
    padded = bytearray(data)
    pad_len = RATE - (len(padded) % RATE)
    padded.extend(bytes(pad_len))
    padded[len(data)] ^= suffix
    padded[-1] ^= 0x80

    state = [0] * 25
    for offset in range(0, len(padded), RATE):
        block = padded[offset : offset + RATE]
        for lane in range(RATE // 8):
            state[lane] ^= int.from_bytes(block[8 * lane : 8 * lane + 8], "little")
        keccak_f1600_lanes(state)

    out = bytearray()
    while len(out) < output_bytes:
        rate_bytes = b"".join(lane.to_bytes(8, "little") for lane in state[: RATE // 8])
        take = min(output_bytes - len(out), RATE)
        out.extend(rate_bytes[:take])
        if len(out) < output_bytes:
            keccak_f1600_lanes(state)
    return bytes(out)


def shake256(data: bytes, output_bytes: int) -> bytes:
    return keccak_sponge(data, output_bytes, 0x1F)


def cshake256(data: bytes, output_bytes: int, function_name: bytes, customization: bytes) -> bytes:
    if not function_name and not customization:
        return shake256(data, output_bytes)
    prefix = bytepad(encode_string(function_name) + encode_string(customization), RATE)
    return keccak_sponge(prefix + data, output_bytes, 0x04)


def kmac256(key: bytes, data: bytes, output_bytes: int = 32, customization: bytes = CUSTOMIZATION) -> bytes:
    new_input = bytepad(encode_string(key), RATE) + data + right_encode(8 * output_bytes)
    return cshake256(new_input, output_bytes, b"KMAC", customization)


class SystematicParityCheck:
    """Deterministic H=(I|T) test fixture, never a production Goppa key."""

    def __init__(self, seed: bytes = b"PQ-RBBC/v1.4/test-matrix") -> None:
        self.seed = seed
        tail_bits = K
        tail_bytes = (tail_bits + 7) // 8
        tail_mask = (1 << tail_bits) - 1
        self.rows: list[int] = []
        for row in range(R):
            raw = hashlib.shake_256(seed + row.to_bytes(4, "little")).digest(tail_bytes)
            tail = int.from_bytes(raw, "little") & tail_mask
            self.rows.append((1 << row) | (tail << R))

    def syndrome_bits(self, error: int) -> list[int]:
        if error < 0 or error.bit_length() > N:
            raise ValueError("error vector is outside the fixed 6688-bit space")
        return [(row & error).bit_count() & 1 for row in self.rows]

    def syndrome(self, error: int) -> bytes:
        return bytes_from_bits(self.syndrome_bits(error))


def sample_weight_error(seed: bytes, weight: int = T) -> int:
    """Deterministic fixture sampler; it is intentionally not a CSPRNG API."""
    if not 0 <= weight <= N:
        raise ValueError("invalid test weight")
    positions: set[int] = set()
    counter = 0
    bound = (1 << 32) - ((1 << 32) % N)
    while len(positions) < weight:
        raw = hashlib.shake_256(
            b"PQ-RBBC/v1.4/error-sample" + seed + counter.to_bytes(4, "little")
        ).digest(4)
        counter += 1
        candidate = int.from_bytes(raw, "little")
        if candidate < bound:
            positions.add(candidate % N)
    error = 0
    for position in positions:
        error |= 1 << position
    return error


@dataclass(frozen=True)
class TicketPayload:
    ctx: bytes
    sn: bytes
    holder_hash: bytes
    syndrome: bytes
    masked_identity: bytes
    tag: bytes

    def encode(self) -> bytes:
        fields = (
            ("ctx", self.ctx, 32),
            ("sn", self.sn, 16),
            ("holder_hash", self.holder_hash, 32),
            ("syndrome", self.syndrome, 208),
            ("masked_identity", self.masked_identity, 48),
            ("tag", self.tag, 32),
        )
        for name, value, expected in fields:
            if len(value) != expected:
                raise ValueError(f"{name} must be {expected} bytes")
        encoded = b"".join(value for _, value, _ in fields)
        if len(encoded) != 368:
            raise AssertionError("frozen payload encoding is not 368 bytes")
        return encoded


@dataclass(frozen=True)
class IssueStatement:
    common_ctx: bytes
    rid: bytes
    payload: TicketPayload
    blind_request: BlindRequest


@dataclass(frozen=True)
class IssueWitness:
    sn: bytes
    holder_key: bytes
    error: int
    blind_mask: bytes
    blind_randomness: bytes
    blind_hash_image: bytes


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    failures: tuple[str, ...]


def _derive_trace(
    matrix: SystematicParityCheck,
    common_ctx: bytes,
    rid: bytes,
    sn: bytes,
    holder_key: bytes,
    error: int,
) -> TicketPayload:
    holder_hash = hashlib.shake_256(LABEL_HOLD + holder_key).digest(32)
    syndrome = matrix.syndrome(error)
    error_bytes = error.to_bytes(N // 8, "little")
    key_stream = hashlib.shake_256(LABEL_KDF + error_bytes + syndrome + common_ctx).digest(80)
    pad, mac_key = key_stream[:48], key_stream[48:]
    masked_identity = xor_bytes(rid + sn, pad)
    associated_data = common_ctx + sn + holder_hash
    tag = kmac256(mac_key, syndrome + masked_identity + associated_data)
    return TicketPayload(common_ctx, sn, holder_hash, syndrome, masked_identity, tag)


def build_honest_instance(
    matrix: SystematicParityCheck,
    common_ctx: bytes,
    rid: bytes,
    sn: bytes,
    holder_key: bytes,
    error: int,
    blind_mask: bytes,
    blind_randomness: bytes,
    adapter: BlindUOVAdapter,
) -> tuple[IssueStatement, IssueWitness]:
    if len(common_ctx) != 32 or len(rid) != 32:
        raise ValueError("context and identity must each be 32 bytes")
    if len(sn) != 16 or len(holder_key) != 32:
        raise ValueError("serial and holder key must be 16 and 32 bytes")
    payload = _derive_trace(matrix, common_ctx, rid, sn, holder_key, error)
    digest = hashlib.shake_256(LABEL_TICKET + payload.encode()).digest(32)
    request = adapter.create(digest, blind_mask, blind_randomness)
    hash_image = adapter.hash_image(digest, blind_mask, blind_randomness)
    return (
        IssueStatement(common_ctx, rid, payload, request),
        IssueWitness(
            sn,
            holder_key,
            error,
            blind_mask,
            blind_randomness,
            hash_image,
        ),
    )


def verify_relation(
    matrix: SystematicParityCheck,
    statement: IssueStatement,
    witness: IssueWitness,
    adapter: BlindUOVAdapter,
) -> VerificationResult:
    failures: list[str] = []
    try:
        encoded = statement.payload.encode()
    except ValueError:
        return VerificationResult(False, ("payload_layout",))
    if not (len(statement.common_ctx) == len(statement.rid) == 32):
        failures.append("statement_layout")
    if statement.payload.ctx != statement.common_ctx:
        failures.append("context_binding")
    if statement.payload.sn != witness.sn:
        failures.append("serial_binding")
    if witness.error.bit_count() != T:
        failures.append("exact_weight")

    expected = _derive_trace(
        matrix,
        statement.common_ctx,
        statement.rid,
        witness.sn,
        witness.holder_key,
        witness.error,
    )
    if statement.payload.holder_hash != expected.holder_hash:
        failures.append("holder_hash")
    if statement.payload.syndrome != expected.syndrome:
        failures.append("syndrome")
    if statement.payload.masked_identity != expected.masked_identity:
        failures.append("masked_identity")
    if statement.payload.tag != expected.tag:
        failures.append("trace_tag")

    expected_digest = hashlib.shake_256(LABEL_TICKET + encoded).digest(32)
    if not adapter.verify_cap_hash(
        expected_digest,
        witness.blind_mask,
        witness.blind_randomness,
        witness.blind_hash_image,
    ):
        failures.append("blind_cap_hash")
    try:
        expected_target = xor_bytes(
            witness.blind_mask, witness.blind_hash_image
        )
    except ValueError:
        failures.append("blind_witness_layout")
    else:
        if statement.blind_request.masked_target != expected_target:
            failures.append("blind_mask_equation")
    return VerificationResult(not failures, tuple(failures))


@dataclass(frozen=True)
class Wire:
    identifier: int
    value: int


@dataclass
class BlockStats:
    nonlinear_constraints: int = 0
    and_gates: int = 0
    bitness_constraints: int = 0
    linear_definitions: int = 0
    linear_assertions: int = 0
    keccak_permutations: int = 0
    failed_assertions: int = 0


class ConstraintSink(Protocol):
    """Streaming IR boundary; a backend may flatten these events into matrices."""

    def input(self, block: str, wire: Wire, visibility: str, name: str) -> None:
        ...

    def linear_definition(
        self, block: str, output: Wire, inputs: Sequence[int], constant: int
    ) -> None:
        ...

    def multiplication(
        self, block: str, left: Wire, right: Wire, output: Wire, kind: str
    ) -> None:
        ...

    def linear_assertion(
        self, block: str, inputs: Sequence[int], constant: int, satisfied: bool
    ) -> None:
        ...

    def external_assertion(self, block: str, name: str, satisfied: bool) -> None:
        ...

    def keccak_permutation(self, block: str) -> None:
        ...


@dataclass
class CountingSink:
    blocks: dict[str, BlockStats] = field(default_factory=dict)
    public_inputs: int = 0
    secret_inputs: int = 0
    external_assertions: int = 0

    def _stats(self, block: str) -> BlockStats:
        return self.blocks.setdefault(block, BlockStats())

    def input(self, block: str, wire: Wire, visibility: str, name: str) -> None:
        if visibility == "public":
            self.public_inputs += 1
        elif visibility == "secret":
            self.secret_inputs += 1
        else:
            raise ValueError("visibility must be public or secret")

    def linear_definition(
        self, block: str, output: Wire, inputs: Sequence[int], constant: int
    ) -> None:
        self._stats(block).linear_definitions += 1

    def multiplication(
        self, block: str, left: Wire, right: Wire, output: Wire, kind: str
    ) -> None:
        stats = self._stats(block)
        stats.nonlinear_constraints += 1
        if kind == "and":
            stats.and_gates += 1
        elif kind == "bitness":
            stats.bitness_constraints += 1
        else:
            raise ValueError(f"unknown multiplication kind: {kind}")

    def linear_assertion(
        self, block: str, inputs: Sequence[int], constant: int, satisfied: bool
    ) -> None:
        stats = self._stats(block)
        stats.linear_assertions += 1
        if not satisfied:
            stats.failed_assertions += 1

    def external_assertion(self, block: str, name: str, satisfied: bool) -> None:
        self.external_assertions += 1
        if not satisfied:
            self._stats(block).failed_assertions += 1

    def keccak_permutation(self, block: str) -> None:
        self._stats(block).keccak_permutations += 1


class Char2CircuitBuilder:
    """Value-carrying characteristic-two circuit builder with streaming events."""

    def __init__(self, sink: ConstraintSink | None = None) -> None:
        self.sink = sink or CountingSink()
        self.block = "unassigned"
        self._next_identifier = 0
        self.zero = self._new_wire(0)
        self.one = self._new_wire(1)

    @property
    def wire_count(self) -> int:
        return self._next_identifier

    def _new_wire(self, value: int) -> Wire:
        wire = Wire(self._next_identifier, int(value))
        self._next_identifier += 1
        return wire

    def set_block(self, name: str) -> None:
        self.block = name
        if isinstance(self.sink, CountingSink):
            self.sink.blocks.setdefault(name, BlockStats())

    def const_bit(self, value: int) -> Wire:
        if value == 0:
            return self.zero
        if value == 1:
            return self.one
        raise ValueError("constant is not a bit")

    def input_bit(self, value: int, visibility: str, name: str = "") -> Wire:
        if value not in (0, 1):
            raise ValueError("circuit input is not a bit")
        wire = self._new_wire(value)
        self.sink.input(self.block, wire, visibility, name)
        return wire

    def linear(self, inputs: Sequence[Wire], constant: int = 0) -> Wire:
        value = constant & 1
        for wire in inputs:
            value ^= wire.value
        output = self._new_wire(value)
        self.sink.linear_definition(
            self.block, output, tuple(w.identifier for w in inputs), constant & 1
        )
        return output

    def xor(self, *inputs: Wire) -> Wire:
        return self.linear(inputs)

    def invert(self, wire: Wire) -> Wire:
        return self.linear((wire,), 1)

    def and_gate(self, left: Wire, right: Wire) -> Wire:
        output = self._new_wire(left.value & right.value)
        self.sink.multiplication(self.block, left, right, output, "and")
        return output

    def assert_bit(self, wire: Wire) -> None:
        complement = self.invert(wire)
        product = self._new_wire(wire.value * complement.value)
        self.sink.multiplication(self.block, wire, complement, product, "bitness")
        if product.value != 0:
            self.sink.linear_assertion(
                self.block, (product.identifier,), 0, satisfied=False
            )

    def assert_equal(self, left: Wire, right: Wire | int) -> None:
        if isinstance(right, Wire):
            identifiers = (left.identifier, right.identifier)
            satisfied = left.value == right.value
            constant = 0
        else:
            if right not in (0, 1):
                raise ValueError("bit equality target must be zero or one")
            identifiers = (left.identifier,)
            satisfied = left.value == right
            constant = right
        self.sink.linear_assertion(self.block, identifiers, constant, satisfied)

    def assert_xor_zero(self, *wires: Wire) -> None:
        """Assert that the xor of all input wires is zero without a new wire."""
        self.sink.linear_assertion(
            self.block,
            tuple(wire.identifier for wire in wires),
            0,
            satisfied=not bool(sum((wire.value for wire in wires), 0) & 1),
        )

    def external_assert(self, name: str, satisfied: bool) -> None:
        self.sink.external_assertion(self.block, name, satisfied)


def constant_wires(builder: Char2CircuitBuilder, data: bytes) -> list[Wire]:
    return [builder.const_bit(bit) for bit in bits_from_bytes(data)]


def input_wires(
    builder: Char2CircuitBuilder,
    data: bytes,
    visibility: str,
    name: str,
    assert_bitness: bool = False,
) -> list[Wire]:
    wires = [
        builder.input_bit(bit, visibility, f"{name}[{index}]")
        for index, bit in enumerate(bits_from_bytes(data))
    ]
    if assert_bitness:
        for wire in wires:
            builder.assert_bit(wire)
    return wires


def wire_bytes(wires: Sequence[Wire]) -> bytes:
    return bytes_from_bits([wire.value for wire in wires])


def _keccak_f1600_wires(builder: Char2CircuitBuilder, state: list[list[list[Wire]]]) -> None:
    for rc in ROUND_CONSTANTS:
        column = [
            [builder.xor(*(state[x][y][z] for y in range(5))) for z in range(64)]
            for x in range(5)
        ]
        delta = [
            [builder.xor(column[(x - 1) % 5][z], column[(x + 1) % 5][(z - 1) % 64]) for z in range(64)]
            for x in range(5)
        ]
        theta = [
            [
                [builder.xor(state[x][y][z], delta[x][z]) for z in range(64)]
                for y in range(5)
            ]
            for x in range(5)
        ]

        moved: list[list[list[Wire | None]]] = [
            [[None for _ in range(64)] for _ in range(5)] for _ in range(5)
        ]
        for x in range(5):
            for y in range(5):
                new_x = y
                new_y = (2 * x + 3 * y) % 5
                rotation = RHO[x][y]
                for z in range(64):
                    moved[new_x][new_y][(z + rotation) % 64] = theta[x][y][z]

        next_state: list[list[list[Wire]]] = [
            [[builder.zero for _ in range(64)] for _ in range(5)] for _ in range(5)
        ]
        for x in range(5):
            for y in range(5):
                for z in range(64):
                    bx = moved[x][y][z]
                    bx1 = moved[(x + 1) % 5][y][z]
                    bx2 = moved[(x + 2) % 5][y][z]
                    if bx is None or bx1 is None or bx2 is None:
                        raise AssertionError("incomplete rho/pi mapping")
                    product = builder.and_gate(builder.invert(bx1), bx2)
                    next_state[x][y][z] = builder.xor(bx, product)
        for z in range(64):
            if (rc >> z) & 1:
                next_state[0][0][z] = builder.invert(next_state[0][0][z])
        state[:] = next_state
    builder.sink.keccak_permutation(builder.block)


def sponge_wires(
    builder: Char2CircuitBuilder,
    message: Sequence[Wire],
    output_bytes: int,
    suffix: int,
) -> list[Wire]:
    if len(message) % 8:
        raise ValueError("wire sponge input must be byte aligned")
    message_bytes = len(message) // 8
    pad_len = RATE - (message_bytes % RATE)
    padding = bytearray(pad_len)
    padding[0] ^= suffix
    padding[-1] ^= 0x80
    padded = list(message) + constant_wires(builder, bytes(padding))

    state = [
        [[builder.zero for _ in range(64)] for _ in range(5)] for _ in range(5)
    ]
    rate_bits = RATE * 8
    for offset in range(0, len(padded), rate_bits):
        block = padded[offset : offset + rate_bits]
        for bit_index, wire in enumerate(block):
            lane = bit_index // 64
            x = lane % 5
            y = lane // 5
            z = bit_index % 64
            state[x][y][z] = builder.xor(state[x][y][z], wire)
        _keccak_f1600_wires(builder, state)

    output: list[Wire] = []
    while len(output) < output_bytes * 8:
        for bit_index in range(rate_bits):
            lane = bit_index // 64
            x = lane % 5
            y = lane // 5
            z = bit_index % 64
            output.append(state[x][y][z])
            if len(output) == output_bytes * 8:
                break
        if len(output) < output_bytes * 8:
            _keccak_f1600_wires(builder, state)
    return output


def shake256_wires(
    builder: Char2CircuitBuilder, message: Sequence[Wire], output_bytes: int
) -> list[Wire]:
    return sponge_wires(builder, message, output_bytes, 0x1F)


def _bytepad_wires(
    builder: Char2CircuitBuilder, data: Sequence[Wire], width: int
) -> list[Wire]:
    encoded = constant_wires(builder, left_encode(width)) + list(data)
    byte_length = len(encoded) // 8
    encoded.extend(constant_wires(builder, bytes((-byte_length) % width)))
    return encoded


def cshake256_wires(
    builder: Char2CircuitBuilder,
    data: Sequence[Wire],
    output_bytes: int,
    function_name: bytes,
    customization: bytes,
) -> list[Wire]:
    if not function_name and not customization:
        return shake256_wires(builder, data, output_bytes)
    prefix = bytepad(
        encode_string(function_name) + encode_string(customization), RATE
    )
    return sponge_wires(
        builder, constant_wires(builder, prefix) + list(data), output_bytes, 0x04
    )


def kmac256_wires(
    builder: Char2CircuitBuilder,
    key: Sequence[Wire],
    data: Sequence[Wire],
    output_bytes: int = 32,
    customization: bytes = CUSTOMIZATION,
) -> list[Wire]:
    if len(key) % 8:
        raise ValueError("KMAC key wires must be byte aligned")
    encoded_key = constant_wires(builder, left_encode(len(key))) + list(key)
    keyed_prefix = _bytepad_wires(builder, encoded_key, RATE)
    trailer = constant_wires(builder, right_encode(8 * output_bytes))
    return cshake256_wires(
        builder,
        keyed_prefix + list(data) + trailer,
        output_bytes,
        b"KMAC",
        customization,
    )


def _add_counters(
    builder: Char2CircuitBuilder, left: Sequence[Wire], right: Sequence[Wire]
) -> list[Wire]:
    if len(left) != len(right) or not left:
        raise ValueError("counter widths must be equal and nonzero")
    first_xor = builder.xor(left[0], right[0])
    carry = builder.and_gate(left[0], right[0])
    result = [first_xor]
    for index in range(1, len(left)):
        pair_xor = builder.xor(left[index], right[index])
        result.append(builder.xor(pair_xor, carry))
        pair_and = builder.and_gate(left[index], right[index])
        carry_and = builder.and_gate(carry, pair_xor)
        carry = builder.xor(pair_and, carry_and)
    result.append(carry)
    return result


def assert_exact_weight(
    builder: Char2CircuitBuilder, error_bits: Sequence[Wire], target: int
) -> None:
    padded_size = 1 << (len(error_bits) - 1).bit_length()
    counters: list[list[Wire]] = [[wire] for wire in error_bits]
    counters.extend([[builder.zero] for _ in range(padded_size - len(error_bits))])
    while len(counters) > 1:
        counters = [
            _add_counters(builder, counters[index], counters[index + 1])
            for index in range(0, len(counters), 2)
        ]
    final = counters[0]
    for index, wire in enumerate(final):
        builder.assert_equal(wire, (target >> index) & 1)


def syndrome_wires(
    builder: Char2CircuitBuilder,
    matrix: SystematicParityCheck,
    error_bits: Sequence[Wire],
) -> list[Wire]:
    if len(error_bits) != N:
        raise ValueError("wrong error-vector width")
    outputs: list[Wire] = []
    for row in matrix.rows:
        selected: list[Wire] = []
        remaining = row
        while remaining:
            low = remaining & -remaining
            selected.append(error_bits[low.bit_length() - 1])
            remaining ^= low
        outputs.append(builder.linear(selected))
    return outputs


def error_wires_to_bytes(error_bits: Sequence[Wire]) -> list[Wire]:
    if len(error_bits) != N:
        raise ValueError("wrong error-vector width")
    return list(error_bits)


@dataclass(frozen=True)
class CircuitReport:
    satisfied: bool
    wire_count: int
    public_input_bits: int
    secret_input_bits: int
    external_assertions: int
    blocks: dict[str, dict[str, int]]
    totals: dict[str, int]


def _assert_wire_vectors_equal(
    builder: Char2CircuitBuilder, left: Sequence[Wire], right: Sequence[Wire]
) -> None:
    if len(left) != len(right):
        raise ValueError("wire vector lengths differ")
    for a, b in zip(left, right):
        builder.assert_equal(a, b)


def generate_issue_circuit(
    matrix: SystematicParityCheck,
    statement: IssueStatement,
    witness: IssueWitness,
    adapter: BlindUOVAdapter,
    sink: CountingSink | None = None,
) -> CircuitReport:
    """Generate and execute the five incremental circuit blocks."""
    counting = sink or CountingSink()
    builder = Char2CircuitBuilder(counting)

    builder.set_block("shape")
    common_ctx = input_wires(builder, statement.common_ctx, "public", "common_ctx")
    rid = input_wires(builder, statement.rid, "public", "rid")
    payload_ctx = input_wires(builder, statement.payload.ctx, "public", "payload.ctx")
    public_sn = input_wires(builder, statement.payload.sn, "public", "payload.sn")
    public_holder_hash = input_wires(
        builder, statement.payload.holder_hash, "public", "payload.holder_hash"
    )
    public_syndrome = input_wires(
        builder, statement.payload.syndrome, "public", "payload.syndrome"
    )
    public_masked_identity = input_wires(
        builder, statement.payload.masked_identity, "public", "payload.masked_identity"
    )
    public_tag = input_wires(builder, statement.payload.tag, "public", "payload.tag")
    public_blind_target = input_wires(
        builder,
        statement.blind_request.masked_target,
        "public",
        "blind_request.y",
    )
    secret_sn = input_wires(builder, witness.sn, "secret", "witness.sn", True)
    _assert_wire_vectors_equal(builder, common_ctx, payload_ctx)
    _assert_wire_vectors_equal(builder, secret_sn, public_sn)

    payload_wires = (
        payload_ctx
        + public_sn
        + public_holder_hash
        + public_syndrome
        + public_masked_identity
        + public_tag
    )
    builder.set_block("ticket_hash")
    computed_digest = shake256_wires(
        builder, constant_wires(builder, LABEL_TICKET) + payload_wires, 32
    )

    builder.set_block("blind_uov_mask_binding")
    if wire_bytes(public_blind_target) != statement.blind_request.masked_target:
        raise AssertionError("public PQ-RBBC-BUOV-336 target wire encoding changed")
    blind_mask = input_wires(
        builder,
        witness.blind_mask,
        "secret",
        "witness.blind_mask",
        True,
    )
    blind_hash_image = input_wires(
        builder,
        witness.blind_hash_image,
        "secret",
        "witness.blind_hash_image",
        True,
    )
    if not (
        len(public_blind_target) == len(blind_mask) == len(blind_hash_image)
    ):
        raise ValueError("Blind-UOV mask equation widths differ")
    for y_bit, r_bit, h_bit in zip(
        public_blind_target, blind_mask, blind_hash_image
    ):
        builder.assert_xor_zero(y_bit, r_bit, h_bit)
    builder.external_assert(
        "native_pq_rbbc_cap_v1_full_18_tree_row_stream_and_h_rbbc_wire_join",
        adapter.verify_cap_hash(
            wire_bytes(computed_digest),
            witness.blind_mask,
            witness.blind_randomness,
            witness.blind_hash_image,
        ),
    )

    builder.set_block("holder")
    holder_key = input_wires(
        builder, witness.holder_key, "secret", "witness.holder_key", True
    )
    computed_holder_hash = shake256_wires(
        builder, constant_wires(builder, LABEL_HOLD) + holder_key, 32
    )
    _assert_wire_vectors_equal(builder, computed_holder_hash, public_holder_hash)

    builder.set_block("trace")
    error_bits = [
        builder.input_bit((witness.error >> index) & 1, "secret", f"witness.e[{index}]")
        for index in range(N)
    ]
    for wire in error_bits:
        builder.assert_bit(wire)
    computed_syndrome = syndrome_wires(builder, matrix, error_bits)
    _assert_wire_vectors_equal(builder, computed_syndrome, public_syndrome)
    assert_exact_weight(builder, error_bits, T)

    kdf_input = (
        constant_wires(builder, LABEL_KDF)
        + error_wires_to_bytes(error_bits)
        + computed_syndrome
        + common_ctx
    )
    key_stream = shake256_wires(builder, kdf_input, 80)
    pad = key_stream[: 48 * 8]
    mac_key = key_stream[48 * 8 :]
    identity_and_serial = rid + secret_sn
    computed_mask = [builder.xor(a, b) for a, b in zip(identity_and_serial, pad)]
    _assert_wire_vectors_equal(builder, computed_mask, public_masked_identity)

    associated_data = common_ctx + secret_sn + computed_holder_hash
    tag_input = computed_syndrome + computed_mask + associated_data
    computed_tag = kmac256_wires(builder, mac_key, tag_input)
    _assert_wire_vectors_equal(builder, computed_tag, public_tag)

    blocks = {name: asdict(stats) for name, stats in counting.blocks.items()}
    fields = tuple(BlockStats.__dataclass_fields__)
    totals = {name: sum(getattr(stats, name) for stats in counting.blocks.values()) for name in fields}
    return CircuitReport(
        satisfied=totals["failed_assertions"] == 0,
        wire_count=builder.wire_count,
        public_input_bits=counting.public_inputs,
        secret_input_bits=counting.secret_inputs,
        external_assertions=counting.external_assertions,
        blocks=blocks,
        totals=totals,
    )


def reference_fixture() -> tuple[SystematicParityCheck, IssueStatement, IssueWitness, TestPQRBBC336Adapter]:
    matrix = SystematicParityCheck()
    adapter = TestPQRBBC336Adapter()
    common_ctx = hashlib.shake_256(b"PQ-RBBC/v1.4/context").digest(32)
    rid = hashlib.shake_256(b"PQ-RBBC/v1.4/identity").digest(32)
    sn = hashlib.shake_256(b"PQ-RBBC/v1.4/serial").digest(16)
    holder_key = hashlib.shake_256(b"PQ-RBBC/v1.4/holder-key").digest(32)
    error = sample_weight_error(b"reference-vector")
    blind_mask = hashlib.shake_256(b"PQ-RBBC/v2.0/blind-mask").digest(72)
    blind_randomness = hashlib.shake_256(b"PQ-RBBC/v2.0/blind-randomness").digest(32)
    statement, witness = build_honest_instance(
        matrix,
        common_ctx,
        rid,
        sn,
        holder_key,
        error,
        blind_mask,
        blind_randomness,
        adapter,
    )
    return matrix, statement, witness, adapter


def _openssl_kmac(key: bytes, data: bytes, customization: bytes) -> bytes | None:
    executable = shutil.which("openssl")
    if executable is None:
        return None
    command = [
        executable,
        "mac",
        "-macopt",
        f"hexkey:{key.hex()}",
        "-macopt",
        f"custom:{customization.decode('ascii')}",
        "-macopt",
        "size:32",
        "KMAC-256",
    ]
    completed = subprocess.run(command, input=data, capture_output=True, check=False)
    if completed.returncode != 0:
        return None
    return bytes.fromhex(completed.stdout.decode("ascii").strip())


def self_checks() -> dict[str, object]:
    shake_cases = [b"", b"abc", bytes(range(137))]
    shake_ok = all(
        shake256(message, 64) == hashlib.shake_256(message).digest(64)
        for message in shake_cases
    )
    key = bytes(range(32))
    data = b"PQ-RBBC v1.4 KMAC cross-check"
    openssl_result = _openssl_kmac(key, data, CUSTOMIZATION)
    own_result = kmac256(key, data)
    return {
        "shake256_vs_python_hashlib": shake_ok,
        "shake256_cases": len(shake_cases),
        "kmac256_vs_openssl": None if openssl_result is None else own_result == openssl_result,
        "openssl_kmac_available": openssl_result is not None,
    }


def negative_cases(
    matrix: SystematicParityCheck,
    statement: IssueStatement,
    witness: IssueWitness,
    adapter: BlindUOVAdapter,
) -> dict[str, tuple[IssueStatement, IssueWitness]]:
    def flip(data: bytes, index: int = 0) -> bytes:
        changed = bytearray(data)
        changed[index] ^= 1
        return bytes(changed)

    zero_position = next(index for index in range(N) if not ((witness.error >> index) & 1))
    return {
        "wrong_weight": (statement, replace(witness, error=witness.error | (1 << zero_position))),
        "syndrome_tamper": (
            replace(statement, payload=replace(statement.payload, syndrome=flip(statement.payload.syndrome))),
            witness,
        ),
        "masked_identity_tamper": (
            replace(
                statement,
                payload=replace(statement.payload, masked_identity=flip(statement.payload.masked_identity)),
            ),
            witness,
        ),
        "holder_hash_tamper": (
            replace(statement, payload=replace(statement.payload, holder_hash=flip(statement.payload.holder_hash))),
            witness,
        ),
        "tag_tamper": (
            replace(statement, payload=replace(statement.payload, tag=flip(statement.payload.tag))),
            witness,
        ),
        "serial_tamper": (
            replace(statement, payload=replace(statement.payload, sn=flip(statement.payload.sn))),
            witness,
        ),
        "blind_request_tamper": (
            replace(
                statement,
                blind_request=replace(
                    statement.blind_request,
                    masked_target=flip(statement.blind_request.masked_target),
                ),
            ),
            witness,
        ),
        "blind_mask_tamper": (
            statement,
            replace(witness, blind_mask=flip(witness.blind_mask)),
        ),
        "blind_hash_image_tamper": (
            statement,
            replace(
                witness,
                blind_hash_image=flip(witness.blind_hash_image),
            ),
        ),
        "blind_randomness_tamper": (
            statement,
            replace(
                witness,
                blind_randomness=flip(witness.blind_randomness),
            ),
        ),
        "context_tamper": (replace(statement, common_ctx=flip(statement.common_ctx)), witness),
    }


def negative_case_results(
    matrix: SystematicParityCheck,
    statement: IssueStatement,
    witness: IssueWitness,
    adapter: BlindUOVAdapter,
) -> dict[str, list[str]]:
    return {
        name: list(verify_relation(matrix, altered_statement, altered_witness, adapter).failures)
        for name, (altered_statement, altered_witness) in negative_cases(
            matrix, statement, witness, adapter
        ).items()
    }


def build_manifest(full_negative_circuits: bool = False) -> dict[str, object]:
    matrix, statement, witness, adapter = reference_fixture()
    concrete = verify_relation(matrix, statement, witness, adapter)
    circuit = generate_issue_circuit(matrix, statement, witness, adapter)
    negative = negative_case_results(matrix, statement, witness, adapter)
    negative_circuit_results: dict[str, bool] | None = None
    if full_negative_circuits:
        negative_circuit_results = {
            name: not generate_issue_circuit(
                matrix, altered_statement, altered_witness, adapter
            ).satisfied
            for name, (altered_statement, altered_witness) in negative_cases(
                matrix, statement, witness, adapter
            ).items()
        }
    return {
        "implementation_version": "2.11",
        "status": "executable research relation; not a deployment implementation",
        "claim_boundary": {
            "implemented": "incremental relation plus the in-circuit y = r + hash_image mask equation",
            "forked_issuance": "the production reference and native shared global tail are frozen; reduced position-sensitive producers match every tail port, while production producers, point/cross-segment identities, and the parent join remain one external assertion",
            "r1cs_backend": "streaming IR events only; no flattened matrices or proof backend",
            "trace_key": "deterministic systematic test fixture; not a certified Goppa key",
        },
        "fixed_sizes": {
            "payload_bytes": len(statement.payload.encode()),
            "issuance_profile": "PQ-RBBC-BUOV-III / Anemoi-193/336 experimental fork",
            "paper_public_key_kilobytes_provisional_target": BLIND_UOV_PUBLIC_KEY_KILOBYTES,
            "paper_signature_bytes_provisional_target": SIGNATURE_BYTES,
            "issuance_request_bytes_excluding_proof": len(statement.blind_request.encode()),
            "online_ticket_bytes_provisional_target": len(statement.payload.encode()) + SIGNATURE_BYTES,
            "cap_commitment_bytes_hidden_offline": native_profile.cap.commitment_bytes(
                native_profile.cap.PRODUCTION_PARAMETERS
            ),
        },
        "self_checks": self_checks(),
        "honest_relation": {
            "concrete_accepts": concrete.ok,
            "concrete_failures": list(concrete.failures),
            "circuit_accepts": circuit.satisfied,
        },
        "circuit": asdict(circuit),
        "negative_tests": {
            "concrete_all_rejected": all(failures for failures in negative.values()),
            "concrete_cases": negative,
            "full_circuit_executed": full_negative_circuits,
            "full_circuit_all_rejected": (
                None
                if negative_circuit_results is None
                else all(negative_circuit_results.values())
            ),
            "full_circuit_cases": negative_circuit_results,
        },
        "native_import_contract": {
            "relation_id": native_profile.RELATION_ID,
            "target_field": native_profile.TARGET_FIELD,
            "fork_profile_sha256": native_profile.fork_profile_fingerprint(),
            "linear_mask_equation_internalized": True,
            "native_cap_hash_external_assertions": circuit.external_assertions,
            "anemoi_component_relation_id": native_profile.permutation.COMPONENT_RELATION_ID,
            "anemoi_component_nonlinear_rows": native_profile.permutation.NONLINEAR_ROWS,
            "sponge_profile_relation_id": native_profile.sponge.PROFILE_RELATION_ID,
            "request_binding_hash_primitive_implemented": True,
            "production_cap_reference_algorithm_implemented": True,
            "reduced_cap_native_relation_id": native_profile.reduced_native.PROFILE_RELATION_ID,
            "reduced_cap_native_rows": native_profile.reduced_native.FROZEN_REDUCED_ROWS,
            "reduced_cap_native_wires": native_profile.reduced_native.FROZEN_REDUCED_WIRES,
            "reduced_cap_native_external_assertions": 0,
            "reduced_cap_native_row_stream_sha256": native_profile.reduced_native.FROZEN_REDUCED_ROW_STREAM_SHA256,
            "reduced_cap_to_h_rbbc_native_wire_join": True,
            "reduced_cap_profile_is_secure": False,
            "arbitrary_length_multi_squeeze_native": True,
            "production_width_2450_bit_tape_native": True,
            "extended_2450_cap_native_rows": native_profile.reduced_native.FROZEN_EXTENDED_ROWS,
            "extended_2450_cap_native_wires": native_profile.reduced_native.FROZEN_EXTENDED_WIRES,
            "extended_2450_cap_native_external_assertions": 0,
            "extended_2450_cap_native_row_stream_sha256": native_profile.reduced_native.FROZEN_EXTENDED_ROW_STREAM_SHA256,
            "extended_2450_cap_profile_is_secure": False,
            "bit_bound_gf193_multiplication_native": True,
            "generic_multi_coefficient_horner_native": True,
            "production_2048_bit_horner_vector_native": True,
            "production_2048_bit_horner_coefficients": 11,
            "production_2048_bit_horner_multiplication_rows": 20,
            "symbolic_extension_mask_horner_native": True,
            "horner_2450_cap_native_rows": native_profile.reduced_native.FROZEN_HORNER_ROWS,
            "horner_2450_cap_native_wires": native_profile.reduced_native.FROZEN_HORNER_WIRES,
            "horner_2450_cap_native_external_assertions": 0,
            "horner_2450_cap_native_row_stream_sha256": native_profile.reduced_native.FROZEN_HORNER_ROW_STREAM_SHA256,
            "horner_2450_cap_profile_is_secure": False,
            "production_2048_leaf_shard_relation_id": native_profile.shard_stream.PROFILE_RELATION_ID,
            "production_2048_leaf_shard_rows": native_profile.shard_stream.FROZEN_PRODUCTION_ROWS,
            "production_2048_leaf_shard_wires": native_profile.shard_stream.FROZEN_PRODUCTION_WIRES,
            "production_2048_leaf_shard_stream_bytes": native_profile.shard_stream.FROZEN_PRODUCTION_STREAM_BYTES,
            "production_2048_leaf_shard_row_stream_sha256": native_profile.shard_stream.FROZEN_PRODUCTION_STREAM_SHA256,
            "production_2048_leaf_shard_spool_bytes": native_profile.shard_stream.FROZEN_PRODUCTION_SPOOL_BYTES,
            "production_2048_leaf_shard_spool_sha256": native_profile.shard_stream.FROZEN_PRODUCTION_SPOOL_SHA256,
            "production_2048_leaf_shard_external_assertions": 0,
            "production_2048_leaf_shard_executed": True,
            "production_2048_leaf_shard_assignment_materialized": True,
            "production_2048_leaf_shard_assignment_format": native_profile.shard_assignment.ASSIGNMENT_FORMAT,
            "production_2048_leaf_shard_assignment_archive_bytes": native_profile.shard_assignment.FROZEN_PRODUCTION_ASSIGNMENT_ARCHIVE_BYTES,
            "production_2048_leaf_shard_assignment_archive_sha256": native_profile.shard_assignment.FROZEN_PRODUCTION_ASSIGNMENT_ARCHIVE_SHA256,
            "production_2048_leaf_shard_whole_assignment_verified": True,
            "production_2048_leaf_shard_verification_failures": 0,
            "production_2048_leaf_shard_stale_witness_probes": native_profile.shard_assignment.FROZEN_PRODUCTION_STALE_WITNESS_PROBES,
            "production_2048_leaf_shard_stale_witness_rejected": True,
            "production_2048_leaf_shard_profile_is_secure": False,
            "production_4096_leaf_shard_relation_id": native_profile.shard_stream.PROFILE_RELATION_ID_4096,
            "production_4096_leaf_shard_rows": native_profile.shard_stream.FROZEN_PRODUCTION_4096_ROWS,
            "production_4096_leaf_shard_wires": native_profile.shard_stream.FROZEN_PRODUCTION_4096_WIRES,
            "production_4096_leaf_shard_stream_bytes": native_profile.shard_stream.FROZEN_PRODUCTION_4096_STREAM_BYTES,
            "production_4096_leaf_shard_row_stream_sha256": native_profile.shard_stream.FROZEN_PRODUCTION_4096_STREAM_SHA256,
            "production_4096_leaf_shard_spool_bytes": native_profile.shard_stream.FROZEN_PRODUCTION_4096_SPOOL_BYTES,
            "production_4096_leaf_shard_spool_sha256": native_profile.shard_stream.FROZEN_PRODUCTION_4096_SPOOL_SHA256,
            "production_4096_leaf_shard_external_assertions": 0,
            "production_4096_leaf_shard_executed": True,
            "production_4096_leaf_shard_assignment_materialized": True,
            "production_4096_leaf_shard_assignment_format": native_profile.shard_assignment.ASSIGNMENT_FORMAT,
            "production_4096_leaf_shard_assignment_archive_bytes": native_profile.shard_assignment.FROZEN_PRODUCTION_4096_ASSIGNMENT_ARCHIVE_BYTES,
            "production_4096_leaf_shard_assignment_archive_sha256": native_profile.shard_assignment.FROZEN_PRODUCTION_4096_ASSIGNMENT_ARCHIVE_SHA256,
            "production_4096_leaf_shard_whole_assignment_verified": True,
            "production_4096_leaf_shard_verification_failures": 0,
            "production_4096_leaf_shard_stale_witness_probes": native_profile.shard_assignment.FROZEN_PRODUCTION_4096_STALE_WITNESS_PROBES,
            "production_4096_leaf_shard_stale_witness_rejected": True,
            "production_4096_leaf_shard_profile_is_secure": False,
            "both_production_tree_shard_types_closed_separately": True,
            "production_cap_composition_relation_id": native_profile.composer.RELATION_ID,
            "production_cap_composition_document_sha256": native_profile.composer.FROZEN_DOCUMENT_SHA256,
            "production_cap_commitment_sha256": native_profile.composer.FROZEN_COMMITMENT_SHA256,
            "production_cap_request_hash_hex": native_profile.composer.FROZEN_REQUEST_HASH_HEX,
            "production_cap_xof_trace_sha256": native_profile.composer.FROZEN_XOF_TRACE_SHA256,
            "canonical_cap_serialization_implemented": True,
            "canonical_cap_bytes_bound_to_h_rbbc": True,
            "cap_production_accounting": native_profile.cap.production_accounting(),
            "production_cap_full_vector_executed": True,
            "canonical_18_tree_link_schedule_closed": True,
            "production_cap_native_global_tail_materialized": True,
            "production_global_tail_relation_id": native_profile.global_tail.RELATION_ID,
            "production_global_tail_rows": native_profile.global_tail.FROZEN_PRODUCTION_ROWS,
            "production_global_tail_wires": native_profile.global_tail.FROZEN_PRODUCTION_WIRES,
            "production_global_tail_row_stream_sha256": native_profile.global_tail.FROZEN_PRODUCTION_STREAM_SHA256,
            "production_global_tail_assignment_sha256": native_profile.global_tail.FROZEN_PRODUCTION_ASSIGNMENT_SHA256,
            "production_global_tail_replay_failures": 0,
            "production_global_tail_stale_witness_probes": 6,
            "reduced_split_tail_contract_id": native_profile.split_tail.CONTRACT_ID,
            "reduced_split_tail_rows": native_profile.split_tail.FROZEN_REDUCED_ROWS,
            "reduced_split_tail_wires": native_profile.split_tail.FROZEN_REDUCED_WIRES,
            "reduced_split_tail_phase_contract_closed": True,
            "canonical_tail_stream_and_assignment_equivalent": True,
            "h1_and_consistency_point_ports_native_closed": True,
            "tail_phase_a_to_phase_b_wire_identity_closed": True,
            "production_split_tail_contract_id": native_profile.production_split_tail.CONTRACT_ID,
            "production_split_tail_h1_wire_start": native_profile.production_split_tail.FROZEN_H1_WIRE_START,
            "production_split_tail_point_wire_starts": native_profile.production_split_tail.FROZEN_POINT_WIRE_STARTS,
            "production_split_tail_boundary_wire_probes": native_profile.production_split_tail.FROZEN_BOUNDARY_PROBES,
            "production_split_tail_materialized": True,
            "production_h1_and_two_consistency_point_ports_native_closed": True,
            "production_tail_phase_a_to_phase_b_wire_identity_closed": True,
            "reduced_tree_producer_relation_id": native_profile.tree_producer.RELATION_ID,
            "reduced_tree_producer_rows_per_tree": native_profile.tree_producer.FROZEN_REDUCED_ROWS_PER_TREE,
            "reduced_tree_producer_wires_per_tree": native_profile.tree_producer.FROZEN_REDUCED_WIRES_PER_TREE,
            "reduced_tree_producer_segments_native_closed": True,
            "reduced_producer_to_tail_port_values_match": True,
            "reduced_producer_point_wire_identity_closed": False,
            "tree_producer_segments_materialized": False,
            "cross_segment_wire_identity_closed": False,
            "monolithic_18_tree_assignment_verified": False,
            "production_cap_native_rows_materialized": False,
            "production_cap_inter_call_wire_identity": False,
            "complete_cap_hash_implemented": False,
            "blind_uov_bit_exact_compatible": False,
            "paper_240_gap_blocks_fork_engineering": False,
            "fork_security_proof_revalidated": False,
            "signature_size_rebenchmarked": False,
            "production_closed": False,
        },
        "reference_vector": {
            "matrix_seed_sha256": hashlib.sha256(matrix.seed).hexdigest(),
            "payload_sha256": hashlib.sha256(statement.payload.encode()).hexdigest(),
            "ticket_digest": hashlib.shake_256(
                LABEL_TICKET + statement.payload.encode()
            ).digest(32).hex(),
            "error_weight": witness.error.bit_count(),
            "blind_adapter": adapter.name,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compact", action="store_true", help="emit compact JSON")
    parser.add_argument(
        "--full-negative",
        action="store_true",
        help="also run all eight tampered instances through the full circuit",
    )
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    manifest = build_manifest(full_negative_circuits=args.full_negative)
    encoded = json.dumps(
        manifest, indent=None if args.compact else 2, sort_keys=True
    ) + "\n"
    if args.manifest:
        args.manifest.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
