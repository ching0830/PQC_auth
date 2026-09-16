#!/usr/bin/env python3
"""Bounded I1--I5 issuance constraint-composition prototype.

The public statement keeps the production-shaped ``(pp, ctx, sid, rid, beta)``
partition and the private witness keeps ``(M, r, rho, k_hold, e)``.  I1, I2,
I4, and I5 are lowered through the existing characteristic-two circuit.  I3
uses the existing native reduced CAP.Commit-to-H_RBBC trace and explicit port
joins.  Its CAP profile is deliberately insecure/test-only and derives only a
32-bit mask, zero-extended to the 576-bit request ABI.  Production execution
therefore always refuses before decoding inputs or constructing a trace.

No assignment, BR1CS, cache, checkpoint, log, or proof is written by this
module.  The row-shape digest and evidence are bounded metadata only.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, replace
from functools import lru_cache
import hashlib
import json
from pathlib import Path
from typing import Sequence

import pq_rbbc_anemoi_sponge as h_rbbc
import pq_rbbc_anemoi_f193 as field193
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_native as cap_native
import pq_rbbc_issuance_production_inputs_v1 as production_inputs
import pq_rbbc_issuance_zk_backend_preflight as backend_preflight
import pq_rbbc_reference as reference


IMPLEMENTATION_VERSION = "1.0"
FORMAT = "PQRBBC-ISSUANCE-REDUCED-CONSTRAINT-PROTOTYPE-1"
EVIDENCE_FORMAT = "PQRBBC-ISSUANCE-REDUCED-CONSTRAINT-PORTABLE-EVIDENCE-1"
RELATION_ID = "pq-rbbc/issuance/reduced-constraint/test-only/v1"
MODE = "INSECURE-TEST-ONLY-REDUCED-CAP32-FULL-TRACE-V1"
ROOT = Path(__file__).resolve().parents[1]

PARAMETERS_MAGIC = b"PQRBBC-ISSUE-REDUCED-CONSTRAINT-PP-V1"
WITNESS_MAGIC = b"PQRBBC-ISSUE-REDUCED-CONSTRAINT-WITNESS-V1"
CODEC_VERSION = 1
DOMAIN_ABI = b"PQ-RBBC/ISSUANCE-REDUCED-CONSTRAINT/ABI/V1"
DOMAIN_TEST_MATRIX = b"PQ-RBBC/ISSUANCE-REDUCED-CONSTRAINT/TEST-MATRIX/V1"
DOMAIN_FIXTURE = b"PQ-RBBC/ISSUANCE-REDUCED-CONSTRAINT/FIXTURE/V1"

REDUCED_CAP_PARAMETERS = cap.REDUCED_TEST_PARAMETERS
REDUCED_CAP_PROFILE = cap.profile_fingerprint(REDUCED_CAP_PARAMETERS)
REDUCED_MASK_BYTES = REDUCED_CAP_PARAMETERS.mask_bits // 8
REQUEST_BYTES = backend_preflight.BLIND_REQUEST_BYTES
TRACE_KEY_BYTES = production_inputs.TRACE_KEY_BODY_BYTES
CAP_RANDOMNESS_BYTES = len(
    cap.deterministic_randomness(REDUCED_CAP_PARAMETERS).serialize(
        REDUCED_CAP_PARAMETERS
    )
)

ABI_DOCUMENT = {
    "format": "PQRBBC-ISSUANCE-REDUCED-CONSTRAINT-ABI-1",
    "relation_id": RELATION_ID,
    "public_statement": ["pp", "ctx", "sid", "rid", "beta"],
    "private_witness": ["M", "r", "rho", "k_hold", "e"],
    "statement_codec": backend_preflight.STATEMENT_MAGIC.decode("ascii"),
    "ticket_payload_bytes": backend_preflight.TICKET_PAYLOAD_BYTES,
    "request_bytes": REQUEST_BYTES,
    "cap_randomness_bytes": CAP_RANDOMNESS_BYTES,
    "holder_key_bytes": backend_preflight.HOLDER_KEY_BYTES,
    "error_vector_bytes": backend_preflight.ERROR_VECTOR_BYTES,
    "trace_key_codec": production_inputs.TRACE_KEY_MAGIC.decode("ascii"),
    "trace_key_body_bytes": TRACE_KEY_BYTES,
    "cap_profile": REDUCED_CAP_PROFILE,
    "mask_mapping": "reduced-mask[0:4] || zero[4:72]",
}


def canonical_json(document: object) -> bytes:
    return (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


ABI_PROFILE_DIGEST = hashlib.sha256(
    DOMAIN_ABI + canonical_json(ABI_DOCUMENT)
).digest()


TRACKED_PREREQUISITES = {
    "core_proof": (
        "docs/proof/source/pq_rbbc_sgtd_core_proof_v1.tex",
        148_798,
        "cee211e7c6419480c0571b752faebe3574d3309f4e876a75cf325f3027d9f884",
    ),
    "formal_relation": (
        "src/pq_rbbc_issuance_relation_v1.py",
        31_165,
        "4c0db79e896824c77ef869fdfa2c8fc3e26c9942e12c0a49526f2b54bfbbf57e",
    ),
    "formal_relation_manifest": (
        "manifests/pq_rbbc_issuance_relation_manifest_v1.json",
        4_370,
        "18fface2cfffacdb063c17e86dad7be55f194ba60a078d119f2ce98b588e1af1",
    ),
    "production_inputs": (
        "src/pq_rbbc_issuance_production_inputs_v1.py",
        40_304,
        "7f57417efcea41bc94f477966dfaf629475b39b0ed1c0a4e389d4de10657357f",
    ),
    "production_inputs_manifest": (
        "manifests/pq_rbbc_issuance_production_inputs_manifest_v1.json",
        5_728,
        "76272df2d70e2a42d4a7acaf18eea54160f7bb3fb272ffe21d296c7d4bb4e752",
    ),
    "cap_native": (
        "src/pq_rbbc_cap_native.py",
        38_570,
        "8c91a6ffeb17c36a02d12c206babe538d910541337b389e41505949169b84749",
    ),
    "reference_relation": (
        "src/pq_rbbc_reference.py",
        70_542,
        "37da0b9834fd2ecd83b482208ea259e0a17b126bb16f50f4ff538d0699046fab",
    ),
}


class ReducedConstraintError(ValueError):
    """A candidate is noncanonical or does not match the reduced profile."""


class ProductionConstraintUnavailable(RuntimeError):
    """The reduced test-only relation was requested as production."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identity(path: Path) -> dict[str, object]:
    return {
        "filename": path.name,
        "bytes": path.stat().st_size,
        "sha256": _sha256_file(path),
    }


def _validate_text(value: str, label: str) -> bytes:
    if type(value) is not str:
        raise ReducedConstraintError(f"{label} must be text")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ReducedConstraintError(f"{label} must be ASCII") from error
    allowed = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/"
    if not encoded or len(encoded) > 128 or any(x not in allowed for x in encoded):
        raise ReducedConstraintError(f"{label} is not canonical")
    return encoded


def _encode_sections(magic: bytes, sections: Sequence[tuple[int, bytes]]) -> bytes:
    encoded = bytearray(magic)
    encoded.extend(CODEC_VERSION.to_bytes(2, "little"))
    encoded.extend(len(sections).to_bytes(2, "little"))
    for section_id, payload in sections:
        encoded.extend(section_id.to_bytes(2, "little"))
        encoded.extend(len(payload).to_bytes(8, "little"))
        encoded.extend(payload)
    return bytes(encoded)


def _decode_sections(
    encoded: bytes,
    magic: bytes,
    schema: Sequence[tuple[int, str, int, int]],
) -> dict[str, bytes]:
    if not isinstance(encoded, bytes) or not encoded.startswith(magic):
        raise ReducedConstraintError("wrong magic")
    offset = len(magic)
    if offset + 4 > len(encoded):
        raise ReducedConstraintError("truncated header")
    version = int.from_bytes(encoded[offset : offset + 2], "little")
    count = int.from_bytes(encoded[offset + 2 : offset + 4], "little")
    offset += 4
    if version != CODEC_VERSION or count != len(schema):
        raise ReducedConstraintError("wrong version or section count")
    values: dict[str, bytes] = {}
    for expected_id, name, minimum, maximum in schema:
        if offset + 10 > len(encoded):
            raise ReducedConstraintError(f"truncated {name} header")
        section_id = int.from_bytes(encoded[offset : offset + 2], "little")
        length = int.from_bytes(encoded[offset + 2 : offset + 10], "little")
        offset += 10
        if section_id != expected_id:
            raise ReducedConstraintError(f"noncanonical {name} section")
        if not minimum <= length <= maximum or offset + length > len(encoded):
            raise ReducedConstraintError(f"wrong {name} length")
        values[name] = encoded[offset : offset + length]
        offset += length
    if offset != len(encoded):
        raise ReducedConstraintError("trailing bytes")
    return values


@dataclass(frozen=True)
class ReducedConstraintParametersV1:
    trace_public_key: bytes

    def encode(self) -> bytes:
        production_inputs.TracePublicKeyV1.decode(self.trace_public_key)
        return _encode_sections(
            PARAMETERS_MAGIC,
            (
                (1, _validate_text(RELATION_ID, "relation_id")),
                (2, ABI_PROFILE_DIGEST),
                (3, bytes.fromhex(REDUCED_CAP_PROFILE)),
                (4, self.trace_public_key),
                (5, _validate_text(MODE, "mode")),
            ),
        )

    @classmethod
    def decode(cls, encoded: bytes) -> "ReducedConstraintParametersV1":
        values = _decode_sections(
            encoded,
            PARAMETERS_MAGIC,
            (
                (1, "relation_id", 1, 128),
                (2, "abi_profile", 32, 32),
                (3, "cap_profile", 32, 32),
                (
                    4,
                    "trace_public_key",
                    len(production_inputs.TracePublicKeyV1(bytes(TRACE_KEY_BYTES)).encode()),
                    len(production_inputs.TracePublicKeyV1(bytes(TRACE_KEY_BYTES)).encode()),
                ),
                (5, "mode", 1, 128),
            ),
        )
        if values["relation_id"] != RELATION_ID.encode("ascii"):
            raise ReducedConstraintError("wrong relation namespace")
        if values["abi_profile"] != ABI_PROFILE_DIGEST:
            raise ReducedConstraintError("wrong ABI profile")
        if values["cap_profile"] != bytes.fromhex(REDUCED_CAP_PROFILE):
            raise ReducedConstraintError("wrong CAP profile")
        if values["mode"] != MODE.encode("ascii"):
            raise ReducedConstraintError("production mode is not a reduced profile")
        production_inputs.TracePublicKeyV1.decode(values["trace_public_key"])
        result = cls(values["trace_public_key"])
        if result.encode() != encoded:
            raise ReducedConstraintError("noncanonical parameters")
        return result


@dataclass(frozen=True)
class ReducedIssueWitnessV1:
    abi_profile_digest: bytes
    ticket_payload: bytes
    blind_mask: bytes
    cap_randomness: bytes
    holder_key: bytes
    error_vector: bytes

    def encode(self) -> bytes:
        lengths = (
            len(self.abi_profile_digest),
            len(self.ticket_payload),
            len(self.blind_mask),
            len(self.cap_randomness),
            len(self.holder_key),
            len(self.error_vector),
        )
        expected = (
            32,
            backend_preflight.TICKET_PAYLOAD_BYTES,
            REQUEST_BYTES,
            CAP_RANDOMNESS_BYTES,
            backend_preflight.HOLDER_KEY_BYTES,
            backend_preflight.ERROR_VECTOR_BYTES,
        )
        if lengths != expected or self.abi_profile_digest != ABI_PROFILE_DIGEST:
            raise ReducedConstraintError("wrong reduced witness shape or ABI")
        production_inputs.decode_cap_randomness(
            REDUCED_CAP_PARAMETERS, self.cap_randomness
        )
        return _encode_sections(
            WITNESS_MAGIC,
            tuple(
                (index, value)
                for index, value in enumerate(
                    (
                        self.abi_profile_digest,
                        self.ticket_payload,
                        self.blind_mask,
                        self.cap_randomness,
                        self.holder_key,
                        self.error_vector,
                    ),
                    start=1,
                )
            ),
        )

    @classmethod
    def decode(cls, encoded: bytes) -> "ReducedIssueWitnessV1":
        values = _decode_sections(
            encoded,
            WITNESS_MAGIC,
            (
                (1, "abi_profile_digest", 32, 32),
                (
                    2,
                    "ticket_payload",
                    backend_preflight.TICKET_PAYLOAD_BYTES,
                    backend_preflight.TICKET_PAYLOAD_BYTES,
                ),
                (3, "blind_mask", REQUEST_BYTES, REQUEST_BYTES),
                (4, "cap_randomness", CAP_RANDOMNESS_BYTES, CAP_RANDOMNESS_BYTES),
                (
                    5,
                    "holder_key",
                    backend_preflight.HOLDER_KEY_BYTES,
                    backend_preflight.HOLDER_KEY_BYTES,
                ),
                (
                    6,
                    "error_vector",
                    backend_preflight.ERROR_VECTOR_BYTES,
                    backend_preflight.ERROR_VECTOR_BYTES,
                ),
            ),
        )
        result = cls(**values)
        if result.encode() != encoded:
            raise ReducedConstraintError("noncanonical reduced witness")
        return result


class PrototypeSink(reference.CountingSink):
    """Count and hash the relation shape without materializing a row archive."""

    def __init__(self) -> None:
        super().__init__()
        self.internal_inputs = 0
        self._digest = hashlib.sha256()

    @staticmethod
    def _field(value: object) -> bytes:
        raw = str(value).encode("ascii")
        return len(raw).to_bytes(4, "little") + raw

    def _event(self, *values: object) -> None:
        for value in values:
            self._digest.update(self._field(value))

    @property
    def shape_sha256(self) -> str:
        return self._digest.hexdigest()

    def input(
        self,
        block: str,
        wire: reference.Wire,
        visibility: str,
        name: str,
    ) -> None:
        if visibility == "internal":
            self.internal_inputs += 1
        else:
            super().input(block, wire, visibility, name)
        self._event("input", block, wire.identifier, visibility, name)

    def linear_definition(
        self,
        block: str,
        output: reference.Wire,
        inputs: Sequence[int],
        constant: int,
    ) -> None:
        super().linear_definition(block, output, inputs, constant)
        self._event("linear", block, output.identifier, constant, *inputs)

    def multiplication(
        self,
        block: str,
        left: reference.Wire,
        right: reference.Wire,
        output: reference.Wire,
        kind: str,
    ) -> None:
        super().multiplication(block, left, right, output, kind)
        self._event(
            "multiply",
            block,
            left.identifier,
            right.identifier,
            output.identifier,
            kind,
        )

    def linear_assertion(
        self,
        block: str,
        inputs: Sequence[int],
        constant: int,
        satisfied: bool,
    ) -> None:
        super().linear_assertion(block, inputs, constant, satisfied)
        self._event("assert", block, constant, *inputs)

    def external_assertion(self, block: str, name: str, satisfied: bool) -> None:
        super().external_assertion(block, name, satisfied)
        self._event("external", block, name)

    def keccak_permutation(self, block: str) -> None:
        super().keccak_permutation(block)
        self._event("keccak", block)


@dataclass(frozen=True)
class PortBinding:
    name: str
    width_bits: int
    parent_sha256: str
    child_sha256: str
    matched: bool
    constraint_rows: int
    failed_rows: int


@dataclass(frozen=True)
class ReducedConstraintReport:
    satisfied: bool
    relation_id: str
    public_input_bits: int
    secret_witness_bits: int
    internal_bridge_bits: int
    parent_wires: int
    parent_rows: int
    parent_failed_assertions: int
    parent_external_assertions: int
    parent_shape_sha256: str
    child_wires: int
    child_rows: int
    child_failed_rows: int
    child_external_assertions: int
    join_rows: int
    join_failures: int
    combined_rows: int
    blocks: dict[str, dict[str, int]]
    port_bindings: tuple[PortBinding, ...]
    production_qualified: bool = False


@dataclass(frozen=True)
class ReducedConstraintFixture:
    parameters: bytes
    statement: bytes
    witness: bytes


def _wire_values(wires: Sequence[reference.Wire]) -> tuple[int, ...]:
    return tuple(wire.value for wire in wires)


def _native_values(
    trace: cap_native.ReducedNativeCAPTrace, wires: Sequence[int]
) -> tuple[int, ...]:
    return tuple(trace.assignment[wire] for wire in wires)


def _bits_digest(bits: Sequence[int]) -> str:
    packed = bytearray((len(bits) + 7) // 8)
    for index, bit in enumerate(bits):
        if bit not in (0, 1):
            raise ReducedConstraintError("port contains a non-binary value")
        packed[index // 8] |= bit << (index % 8)
    return hashlib.sha256(
        len(bits).to_bytes(8, "little") + bytes(packed)
    ).hexdigest()


def _evaluate_join_rows(
    name: str,
    parent_ids: Sequence[int],
    parent_bits: Sequence[int],
    child_ids: Sequence[int],
    child_bits: Sequence[int],
    child_offset: int,
) -> int:
    """Materialize and evaluate equality rows in one collision-free namespace."""

    if not (
        len(parent_ids) == len(parent_bits) == len(child_ids) == len(child_bits)
    ):
        return 1
    assignment = {
        **dict(zip(parent_ids, parent_bits)),
        **{
            child_offset + identifier: bit
            for identifier, bit in zip(child_ids, child_bits)
        },
    }
    rows = tuple(
        field193.RankOneRow(
            f"join.{name}[{index}]",
            field193.LinearForm.wire(parent_id).add(
                field193.LinearForm.wire(child_offset + child_id)
            ),
            field193.LinearForm.const(1),
            field193.LinearForm.const(0),
        )
        for index, (parent_id, child_id) in enumerate(zip(parent_ids, child_ids))
    )
    return sum(not row.satisfied(assignment) for row in rows)


def _bind_port(
    name: str,
    parent: Sequence[reference.Wire],
    child_trace: cap_native.ReducedNativeCAPTrace,
    child_ids: Sequence[int],
    child_offset: int,
) -> PortBinding:
    parent_bits = _wire_values(parent)
    child_bits = _native_values(child_trace, child_ids)
    failed_rows = _evaluate_join_rows(
        name,
        tuple(wire.identifier for wire in parent),
        parent_bits,
        child_ids,
        child_bits,
        child_offset,
    )
    return PortBinding(
        name=name,
        width_bits=len(parent_bits),
        parent_sha256=_bits_digest(parent_bits),
        child_sha256=_bits_digest(child_bits),
        matched=failed_rows == 0,
        constraint_rows=len(parent_bits),
        failed_rows=failed_rows,
    )


@lru_cache(maxsize=2)
def _test_trace_key() -> bytes:
    matrix = reference.SystematicParityCheck(DOMAIN_TEST_MATRIX)
    body = b"".join(
        (row >> reference.R).to_bytes(production_inputs.TRACE_TAIL_ROW_BYTES, "little")
        for row in matrix.rows
    )
    return production_inputs.TracePublicKeyV1(body).encode()


def _matrix_from_trace_key(encoded: bytes) -> reference.SystematicParityCheck:
    trace_key = production_inputs.TracePublicKeyV1.decode(encoded)
    matrix = reference.SystematicParityCheck.__new__(reference.SystematicParityCheck)
    matrix.seed = b"canonical-trace-key-input"
    matrix.rows = []
    width = production_inputs.TRACE_TAIL_ROW_BYTES
    for row_index in range(reference.R):
        offset = row_index * width
        tail = int.from_bytes(trace_key.body[offset : offset + width], "little")
        matrix.rows.append((1 << row_index) | (tail << reference.R))
    return matrix


def _rho_bits(randomness: cap.CAPRandomness) -> tuple[int, ...]:
    elements = randomness.salt + tuple(x for pair in randomness.roots for x in pair)
    return tuple(
        (value >> bit) & 1
        for value in elements
        for bit in range(cap.field.FIELD_DEGREE)
    )


@lru_cache(maxsize=4)
def _child_trace(
    randomness_bytes: bytes, message: bytes
) -> cap_native.ReducedNativeCAPTrace:
    randomness = production_inputs.decode_cap_randomness(
        REDUCED_CAP_PARAMETERS, randomness_bytes
    )
    return cap_native.build_native_cap_trace(
        randomness=randomness,
        message=message,
        parameters=REDUCED_CAP_PARAMETERS,
    )


def _equal_vectors(
    builder: reference.Char2CircuitBuilder,
    left: Sequence[reference.Wire],
    right: Sequence[reference.Wire],
) -> None:
    if len(left) != len(right):
        raise ReducedConstraintError("constraint vector width mismatch")
    for a, b in zip(left, right):
        builder.assert_equal(a, b)


def _input_bits(
    builder: reference.Char2CircuitBuilder,
    data: bytes,
    visibility: str,
    name: str,
) -> list[reference.Wire]:
    return reference.input_wires(builder, data, visibility, name)


def generate_reduced_constraint_prototype(
    parameters_bytes: bytes,
    statement_bytes: bytes,
    witness_bytes: bytes,
    *,
    production: bool = True,
    request_domain: bytes = h_rbbc.REQUEST_BINDING_DOMAIN,
) -> ReducedConstraintReport:
    """Generate the bounded test-only composition or fail closed immediately."""

    if production:
        raise ProductionConstraintUnavailable(
            "reduced CAP32 relation is test-only; production refuses before input decode"
        )
    if request_domain != h_rbbc.REQUEST_BINDING_DOMAIN:
        raise ReducedConstraintError("wrong H_RBBC request-binding domain")

    parameters = ReducedConstraintParametersV1.decode(parameters_bytes)
    try:
        statement = backend_preflight.IssueStatementV1.decode(statement_bytes)
    except backend_preflight.CanonicalEncodingError as error:
        raise ReducedConstraintError("noncanonical statement") from error
    witness = ReducedIssueWitnessV1.decode(witness_bytes)
    if statement.abi_profile_digest != ABI_PROFILE_DIGEST:
        raise ReducedConstraintError("statement ABI mismatch")
    if statement.public_parameters_digest != hashlib.sha256(parameters_bytes).digest():
        raise ReducedConstraintError("statement parameters digest mismatch")
    payload = reference.TicketPayload(
        ctx=witness.ticket_payload[0:32],
        sn=witness.ticket_payload[32:48],
        holder_hash=witness.ticket_payload[48:80],
        syndrome=witness.ticket_payload[80:288],
        masked_identity=witness.ticket_payload[288:336],
        tag=witness.ticket_payload[336:368],
    )
    if payload.encode() != witness.ticket_payload:
        raise ReducedConstraintError("noncanonical ticket payload")
    matrix = _matrix_from_trace_key(parameters.trace_public_key)

    sink = PrototypeSink()
    builder = reference.Char2CircuitBuilder(sink)

    builder.set_block("P0_public_statement")
    pp = _input_bits(
        builder, statement.public_parameters_digest, "public", "statement.pp"
    )
    ctx = _input_bits(builder, statement.ctx, "public", "statement.ctx")
    _input_bits(builder, statement.sid, "public", "statement.sid")
    rid = _input_bits(builder, statement.rid, "public", "statement.rid")
    beta = _input_bits(builder, statement.beta, "public", "statement.beta")
    expected_pp = reference.constant_wires(
        builder, hashlib.sha256(parameters_bytes).digest()
    )
    _equal_vectors(builder, pp, expected_pp)

    builder.set_block("I1_ticket_shape")
    private_payload = _input_bits(
        builder, witness.ticket_payload, "secret", "witness.M"
    )
    payload_ctx = private_payload[0 : 32 * 8]
    payload_sn = private_payload[32 * 8 : 48 * 8]
    payload_holder = private_payload[48 * 8 : 80 * 8]
    payload_syndrome = private_payload[80 * 8 : 288 * 8]
    payload_masked_identity = private_payload[288 * 8 : 336 * 8]
    payload_tag = private_payload[336 * 8 : 368 * 8]
    _equal_vectors(builder, payload_ctx, ctx)

    builder.set_block("I2_ticket_hash")
    message = reference.shake256_wires(
        builder,
        reference.constant_wires(builder, reference.LABEL_TICKET) + private_payload,
        32,
    )
    message_bytes = reference.wire_bytes(message)

    randomness = production_inputs.decode_cap_randomness(
        REDUCED_CAP_PARAMETERS, witness.cap_randomness
    )
    child = _child_trace(witness.cap_randomness, message_bytes)
    child_hash_bits = _native_values(child, child.request_hash_bit_wires)

    builder.set_block("I3_reduced_cap_h_rbbc_join")
    blind_mask = _input_bits(builder, witness.blind_mask, "secret", "witness.r")
    rho = [
        builder.input_bit(bit, "secret", f"witness.rho[{index}]")
        for index, bit in enumerate(_rho_bits(randomness))
    ]
    for bit in blind_mask[REDUCED_CAP_PARAMETERS.mask_bits :]:
        builder.assert_equal(bit, 0)
    hash_bridge = [
        builder.input_bit(bit, "internal", f"bridge.h_rbbc[{index}]")
        for index, bit in enumerate(child_hash_bits)
    ]
    for y_bit, r_bit, h_bit in zip(beta, blind_mask, hash_bridge):
        builder.assert_xor_zero(y_bit, r_bit, h_bit)

    builder.set_block("I4_holder")
    holder_key = _input_bits(
        builder, witness.holder_key, "secret", "witness.k_hold"
    )
    holder_hash = reference.shake256_wires(
        builder,
        reference.constant_wires(builder, reference.LABEL_HOLD) + holder_key,
        32,
    )
    _equal_vectors(builder, holder_hash, payload_holder)

    builder.set_block("I5_trace")
    error_bits = [
        builder.input_bit(
            (witness.error_vector[index // 8] >> (index % 8)) & 1,
            "secret",
            f"witness.e[{index}]",
        )
        for index in range(reference.N)
    ]
    for bit in error_bits:
        builder.assert_bit(bit)
    syndrome = reference.syndrome_wires(builder, matrix, error_bits)
    _equal_vectors(builder, syndrome, payload_syndrome)
    reference.assert_exact_weight(builder, error_bits, reference.T)
    key_stream = reference.shake256_wires(
        builder,
        reference.constant_wires(builder, reference.LABEL_KDF)
        + reference.error_wires_to_bytes(error_bits)
        + syndrome
        + ctx,
        reference.TRACE_KDF_BYTES,
    )
    pad, mac_key = reference.split_trace_kdf_wires(key_stream)
    identity_serial = rid + payload_sn
    masked_identity = [builder.xor(a, b) for a, b in zip(identity_serial, pad)]
    _equal_vectors(builder, masked_identity, payload_masked_identity)
    tag = reference.kmac256_wires(
        builder,
        mac_key,
        syndrome + masked_identity + ctx + payload_sn + holder_hash,
    )
    _equal_vectors(builder, tag, payload_tag)

    child_offset = builder.wire_count
    port_bindings = (
        _bind_port(
            "message",
            message,
            child,
            child.message_bit_wires,
            child_offset,
        ),
        _bind_port(
            "rho",
            rho,
            child,
            child.randomness_bit_wires,
            child_offset,
        ),
        _bind_port(
            "derived_mask_prefix",
            blind_mask[: REDUCED_CAP_PARAMETERS.mask_bits],
            child,
            child.derived_mask_bit_wires,
            child_offset,
        ),
        _bind_port(
            "request_hash",
            hash_bridge,
            child,
            child.request_hash_bit_wires,
            child_offset,
        ),
    )
    join_rows = sum(item.constraint_rows for item in port_bindings)
    join_failures = sum(item.failed_rows for item in port_bindings)
    totals = {
        name: sum(getattr(stats, name) for stats in sink.blocks.values())
        for name in reference.BlockStats.__dataclass_fields__
    }
    parent_rows = (
        totals["nonlinear_constraints"]
        + totals["linear_definitions"]
        + totals["linear_assertions"]
    )
    child_failures = len(child.failed_rows())
    satisfied = (
        totals["failed_assertions"] == 0
        and sink.external_assertions == 0
        and child_failures == 0
        and child.external_assertions == 0
        and join_failures == 0
    )
    return ReducedConstraintReport(
        satisfied=satisfied,
        relation_id=RELATION_ID,
        public_input_bits=sink.public_inputs,
        secret_witness_bits=sink.secret_inputs,
        internal_bridge_bits=sink.internal_inputs,
        parent_wires=builder.wire_count,
        parent_rows=parent_rows,
        parent_failed_assertions=totals["failed_assertions"],
        parent_external_assertions=sink.external_assertions,
        parent_shape_sha256=sink.shape_sha256,
        child_wires=len(child.assignment),
        child_rows=len(child.rows),
        child_failed_rows=child_failures,
        child_external_assertions=child.external_assertions,
        join_rows=join_rows,
        join_failures=join_failures,
        combined_rows=parent_rows + len(child.rows) + join_rows,
        blocks={name: asdict(stats) for name, stats in sink.blocks.items()},
        port_bindings=port_bindings,
    )


@lru_cache(maxsize=1)
def fixture() -> ReducedConstraintFixture:
    trace_key = _test_trace_key()
    parameters = ReducedConstraintParametersV1(trace_key).encode()
    matrix = _matrix_from_trace_key(trace_key)
    ctx = hashlib.shake_256(DOMAIN_FIXTURE + b"/ctx").digest(32)
    sid = hashlib.shake_256(DOMAIN_FIXTURE + b"/sid").digest(32)
    rid = hashlib.shake_256(DOMAIN_FIXTURE + b"/rid").digest(32)
    serial = hashlib.shake_256(DOMAIN_FIXTURE + b"/serial").digest(16)
    holder_key = hashlib.shake_256(DOMAIN_FIXTURE + b"/holder").digest(32)
    error = reference.sample_weight_error(DOMAIN_FIXTURE + b"/error")
    payload = reference._derive_trace(
        matrix, ctx, rid, serial, holder_key, error
    )
    message = hashlib.shake_256(
        reference.LABEL_TICKET + payload.encode()
    ).digest(32)
    randomness = cap.deterministic_randomness(
        REDUCED_CAP_PARAMETERS, DOMAIN_FIXTURE + b"/rho"
    )
    randomness_bytes = randomness.serialize(REDUCED_CAP_PARAMETERS)
    child = _child_trace(randomness_bytes, message)
    reduced_mask = reference.bytes_from_bits(
        _native_values(child, child.derived_mask_bit_wires)
    )
    blind_mask = reduced_mask + bytes(REQUEST_BYTES - REDUCED_MASK_BYTES)
    beta = reference.xor_bytes(blind_mask, child.request_hash_bytes)
    statement = backend_preflight.IssueStatementV1(
        ABI_PROFILE_DIGEST,
        hashlib.sha256(parameters).digest(),
        ctx,
        sid,
        rid,
        beta,
    ).encode()
    witness = ReducedIssueWitnessV1(
        ABI_PROFILE_DIGEST,
        payload.encode(),
        blind_mask,
        randomness_bytes,
        holder_key,
        error.to_bytes(backend_preflight.ERROR_VECTOR_BYTES, "little"),
    ).encode()
    return ReducedConstraintFixture(parameters, statement, witness)


def _flip(value: bytes, offset: int) -> bytes:
    changed = bytearray(value)
    changed[offset] ^= 1
    return bytes(changed)


@lru_cache(maxsize=1)
def run_bounded_self_check() -> dict[str, object]:
    current = fixture()
    positive = generate_reduced_constraint_prototype(
        current.parameters,
        current.statement,
        current.witness,
        production=False,
    )
    statement = backend_preflight.IssueStatementV1.decode(current.statement)
    witness = ReducedIssueWitnessV1.decode(current.witness)
    beta_mutation = generate_reduced_constraint_prototype(
        current.parameters,
        replace(statement, beta=_flip(statement.beta, 0)).encode(),
        current.witness,
        production=False,
    )
    error_mutation = generate_reduced_constraint_prototype(
        current.parameters,
        current.statement,
        replace(witness, error_vector=_flip(witness.error_vector, 0)).encode(),
        production=False,
    )
    production_refused = False
    try:
        generate_reduced_constraint_prototype(b"", b"", b"", production=True)
    except ProductionConstraintUnavailable:
        production_refused = True
    wrong_domain_refused = False
    try:
        generate_reduced_constraint_prototype(
            current.parameters,
            current.statement,
            current.witness,
            production=False,
            request_domain=b"PQ-RBBC/WRONG-DOMAIN",
        )
    except ReducedConstraintError:
        wrong_domain_refused = True
    return {
        "positive_satisfied": positive.satisfied,
        "public_input_bits": positive.public_input_bits,
        "secret_witness_bits": positive.secret_witness_bits,
        "internal_bridge_bits": positive.internal_bridge_bits,
        "parent_rows": positive.parent_rows,
        "child_rows": positive.child_rows,
        "join_rows": positive.join_rows,
        "combined_rows": positive.combined_rows,
        "external_assertions": (
            positive.parent_external_assertions
            + positive.child_external_assertions
        ),
        "join_failures": positive.join_failures,
        "parent_shape_sha256": positive.parent_shape_sha256,
        "beta_mutation_rejected": not beta_mutation.satisfied,
        "error_mutation_rejected": not error_mutation.satisfied,
        "wrong_domain_refused": wrong_domain_refused,
        "production_refused_before_input_decode": production_refused,
        "cryptographic_proofs_generated": 0,
        "large_relation_rows_replayed": 0,
    }


def validate_tracked_prerequisites() -> tuple[str, ...]:
    failures: list[str] = []
    for name, (relative, expected_size, expected_sha256) in TRACKED_PREREQUISITES.items():
        path = ROOT / relative
        if not path.is_file():
            failures.append(f"{name}:missing")
        elif path.stat().st_size != expected_size:
            failures.append(f"{name}:bytes")
        elif expected_sha256 == "TO_BE_PINNED":
            failures.append(f"{name}:unfrozen")
        elif _sha256_file(path) != expected_sha256:
            failures.append(f"{name}:sha256")
    return tuple(failures)


def build_manifest() -> dict[str, object]:
    result = run_bounded_self_check()
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "abi_profile_digest": ABI_PROFILE_DIGEST.hex(),
        "tracked_prerequisites": {
            name: {"path": path, "bytes": size, "sha256": digest}
            for name, (path, size, digest) in TRACKED_PREREQUISITES.items()
        },
        "tracked_validation_failures": list(validate_tracked_prerequisites()),
        "partition": {
            "public_statement": ["pp", "ctx", "sid", "rid", "beta"],
            "private_witness": ["M", "r", "rho", "k_hold", "e"],
            "ticket_payload_private": True,
            "sid_bound_as_public_input": True,
            "sid_freshness_proved_by_relation": False,
        },
        "trace_key_input_abi": {
            "codec": production_inputs.TRACE_KEY_MAGIC.decode("ascii"),
            "body_bytes": TRACE_KEY_BYTES,
            "matrix": "H=(I_R|T)",
            "binding": "SHA-256(exact reduced parameters bytes) through statement.pp",
            "test_fixture_is_certified_goppa_key": False,
        },
        "constraint_composition": {
            "I1": "native characteristic-two constraints",
            "I2": "native characteristic-two SHAKE256 constraints",
            "I3": "native reduced CAP/H_RBBC GF(2^193) child plus explicit joins",
            "I4": "native characteristic-two SHAKE256 constraints",
            "I5": "native characteristic-two syndrome/weight/SHAKE/KMAC constraints",
            "parent_field": "GF(2) embedded in GF(2^193)",
            "child_field": "GF(2^193)",
            "port_names": ["message", "rho", "derived_mask_prefix", "request_hash"],
            "reduced_cap_profile": REDUCED_CAP_PROFILE,
            "reduced_mask_bits": REDUCED_CAP_PARAMETERS.mask_bits,
            "production_mask_bits": 8 * REQUEST_BYTES,
            "mask_mapping": "32-bit reduced mask followed by 544 constrained zero bits",
            "row_archive_materialized": False,
            "assignment_materialized": False,
            "external_assertions": result["external_assertions"],
            "bounded_accounting": {
                key: result[key]
                for key in (
                    "public_input_bits",
                    "secret_witness_bits",
                    "internal_bridge_bits",
                    "parent_rows",
                    "child_rows",
                    "join_rows",
                    "combined_rows",
                    "parent_shape_sha256",
                )
            },
        },
        "claim_status": {
            "Defined": True,
            "Instantiated": {"reduced_test_only": True, "production": False},
            "Implemented": {"reduced_composition": True, "production": False},
            "Tested": {"bounded_positive_negative_mutation": True, "production": False},
            "Evidence-sealed": {"bounded_metadata": True, "production": False},
            "Proof-closed": False,
            "Production-closed": False,
        },
        "production_gate": {
            "production_entry_point_refuses_before_input_decode": True,
            "production_cap_576_relation_instantiated": False,
            "certified_trace_key_instantiated": False,
            "qualified_pq_se_backend_integrated": False,
            "formal_pi_issue_generated": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
        },
        "resource_estimate": {
            "cpu_cores": 1,
            "peak_memory_mib_upper_bound": 384,
            "elapsed_seconds_upper_bound": 180,
            "large_relation_rows_replayed": 0,
            "cryptographic_proofs_generated": 0,
        },
        "exact_commands": {
            "self_check": "PYTHONPATH=src python -u src/pq_rbbc_issuance_reduced_constraint_v1.py --self-check",
            "targeted_tests": "PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_reduced_constraint_v1 -v",
            "large_replay": None,
            "large_proving": None,
        },
        "next_gate": {
            "production_576_1472_cap_native_lowering": True,
            "certified_trace_key_and_authenticated_input_handoff": True,
            "materialized_reduced_composite_row_stream": False,
            "identity_pinned_backend_integration_after_review": True,
        },
        "artifact_policy": {
            "assignment_or_br1cs_created": False,
            "pickle_cache_checkpoint_resume_or_log_created": False,
            "large_proving_output_created": False,
            "historical_files_modified": False,
            "system_architecture_changed": False,
            "ticket_lifecycle_changed": False,
            "pq_sat_auth_changed": False,
        },
    }


def build_portable_evidence() -> dict[str, object]:
    manifest_path = ROOT / "manifests/pq_rbbc_issuance_reduced_constraint_manifest_v1.json"
    with manifest_path.open("r", encoding="utf-8") as stream:
        manifest = json.load(stream)
    if manifest != build_manifest():
        raise ReducedConstraintError("reduced constraint manifest mismatch")
    self_check = run_bounded_self_check()
    required = (
        self_check["positive_satisfied"],
        self_check["external_assertions"] == 0,
        self_check["join_failures"] == 0,
        self_check["beta_mutation_rejected"],
        self_check["error_mutation_rejected"],
        self_check["wrong_domain_refused"],
        self_check["production_refused_before_input_decode"],
    )
    if not all(required) or validate_tracked_prerequisites():
        raise ReducedConstraintError("bounded reduced constraint qualification failed")
    tracked = {
        "implementation": ROOT / "src/pq_rbbc_issuance_reduced_constraint_v1.py",
        "tests": ROOT / "tests/test_pq_rbbc_issuance_reduced_constraint_v1.py",
        "manifest": manifest_path,
        "artifact_note": ROOT / "docs/artifacts/PQ_RBBC_ISSUANCE_REDUCED_CONSTRAINT_V1_zh-TW.md",
    }
    return {
        "format": EVIDENCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "bound_manifest_sha256": _sha256_file(manifest_path),
        "source_identities": {name: _identity(path) for name, path in tracked.items()},
        "tracked_prerequisites_verified": True,
        "bounded_self_check": self_check,
        "result": {
            "reduced_i1_i5_composition_executed": True,
            "explicit_cross_field_ports_matched": True,
            "external_assertions": 0,
            "production_cap_576_relation_instantiated": False,
            "certified_trace_key_instantiated": False,
            "qualified_backend_integrated": False,
            "formal_pi_issue_generated": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
            "proof_closed": False,
            "production_closed": False,
        },
        "artifact_policy": manifest["artifact_policy"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--self-check", action="store_true")
    actions.add_argument("--print-manifest", action="store_true")
    actions.add_argument("--print-evidence", action="store_true")
    args = parser.parse_args()
    if args.self_check:
        document = run_bounded_self_check()
    elif args.print_manifest:
        document = build_manifest()
    else:
        document = build_portable_evidence()
    print(canonical_json(document).decode("ascii"), end="")


if __name__ == "__main__":
    main()
