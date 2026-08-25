#!/usr/bin/env python3
"""Binary F2-R1CS lowering for the executable PQ-RBBC v2.3 relation.

The format is intentionally small and auditable.  It serializes enough data to
reconstruct ordinary rank-1 constraints over F2:

* MUL(a,b,c) represents a * b = c;
* LINDEF(c, x_1,...,x_n, k) represents
  (c + x_1 + ... + x_n + k) * 1 = 0;
* ASSERT(x_1,...,x_n,k) represents
  (x_1 + ... + x_n + k) * 1 = 0.

Unlike the nonlinear-only research cost model, this portable representation
materializes affine definitions as R1CS rows.  A proof-system-specific compiler
may later eliminate those rows, but it must prove that optimization separately.

The linear PQ-RBBC-BUOV-336 mask equation is materialized.  The CAP reference
algorithm and exact byte-level H_RBBC join exist separately, but their full
18-tree native row stream and inter-call wire identities remain an external
assertion and are not silently converted into R1CS rows here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import BinaryIO, Sequence

import pq_rbbc_reference as core
import pq_rbbc_native_profile as native_profile


MAGIC = b"PQR1CS1\0"
FORMAT_VERSION = 1
FIELD_DEGREE = 1

TAG_INPUT = 1
TAG_LINEAR_DEFINITION = 2
TAG_MULTIPLICATION = 3
TAG_LINEAR_ASSERTION = 4
TAG_EXTERNAL_ASSERTION = 5
TAG_KECCAK_PERMUTATION = 6

VISIBILITY_PUBLIC = 0
VISIBILITY_SECRET = 1
KIND_AND = 0
KIND_BITNESS = 1

# magic, format, field degree, then ten uint64 values and a SHA-256 digest.
HEADER = struct.Struct("<8sHH" + "Q" * 10 + "32s")
HEADER_FIELDS = (
    "wire_count",
    "public_inputs",
    "secret_inputs",
    "linear_definitions",
    "linear_assertions",
    "nonlinear_constraints",
    "total_r1cs_rows",
    "external_assertions",
    "keccak_permutations",
    "body_bytes",
)


class ArchiveError(ValueError):
    """Raised when a binary R1CS archive is malformed or fails its checksum."""


def encode_uvarint(value: int) -> bytes:
    if value < 0:
        raise ValueError("unsigned varint cannot encode a negative value")
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


class _BodyWriter:
    def __init__(self, handle: BinaryIO, flush_threshold: int = 1 << 20) -> None:
        self.handle = handle
        self.flush_threshold = flush_threshold
        self.buffer = bytearray()
        self.hasher = hashlib.sha256()
        self.length = 0

    def write(self, data: bytes | bytearray) -> None:
        self.buffer.extend(data)
        if len(self.buffer) >= self.flush_threshold:
            self.flush()

    def flush(self) -> None:
        if not self.buffer:
            return
        chunk = bytes(self.buffer)
        self.handle.write(chunk)
        self.hasher.update(chunk)
        self.length += len(chunk)
        self.buffer.clear()


@dataclass(frozen=True)
class ArchiveMetadata:
    format: str
    format_version: int
    field: str
    wire_count: int
    public_inputs: int
    secret_inputs: int
    linear_definitions: int
    linear_assertions: int
    nonlinear_constraints: int
    total_r1cs_rows: int
    external_assertions: int
    external_failures: int
    keccak_permutations: int
    body_bytes: int
    archive_bytes: int
    archive_sha256: str
    body_sha256: str
    assignment_sha256: str


class BinaryR1CSSink(core.CountingSink):
    """Stream the relation into a compact binary, standard-R1CS-equivalent IR."""

    def __init__(self, output_path: str | os.PathLike[str]) -> None:
        super().__init__()
        self.output_path = Path(output_path)
        self._handle = self.output_path.open("w+b")
        self._handle.write(bytes(HEADER.size))
        self._body = _BodyWriter(self._handle)
        # Char2CircuitBuilder reserves wire 0 and wire 1 for constants 0 and 1.
        self.assignment = bytearray((0, 1))
        self.external_failures = 0
        self._finalized = False

    def _record_new_wire(self, wire: core.Wire) -> None:
        if wire.identifier != len(self.assignment):
            raise ArchiveError(
                f"wire allocation is not sequential: got {wire.identifier}, "
                f"expected {len(self.assignment)}"
            )
        if wire.value not in (0, 1):
            raise ArchiveError(f"wire {wire.identifier} is not an F2 element")
        self.assignment.append(wire.value)

    @staticmethod
    def _append_ids(record: bytearray, identifiers: Sequence[int]) -> None:
        record.extend(encode_uvarint(len(identifiers)))
        for identifier in identifiers:
            record.extend(encode_uvarint(identifier))

    def input(
        self, block: str, wire: core.Wire, visibility: str, name: str
    ) -> None:
        super().input(block, wire, visibility, name)
        self._record_new_wire(wire)
        if visibility == "public":
            visibility_code = VISIBILITY_PUBLIC
        elif visibility == "secret":
            visibility_code = VISIBILITY_SECRET
        else:
            raise ArchiveError(f"unsupported visibility: {visibility}")
        record = bytearray((TAG_INPUT,))
        record.extend(encode_uvarint(wire.identifier))
        record.append(visibility_code)
        self._body.write(record)

    def linear_definition(
        self,
        block: str,
        output: core.Wire,
        inputs: Sequence[int],
        constant: int,
    ) -> None:
        super().linear_definition(block, output, inputs, constant)
        self._record_new_wire(output)
        record = bytearray((TAG_LINEAR_DEFINITION,))
        record.extend(encode_uvarint(output.identifier))
        record.append(constant & 1)
        self._append_ids(record, inputs)
        self._body.write(record)

    def multiplication(
        self,
        block: str,
        left: core.Wire,
        right: core.Wire,
        output: core.Wire,
        kind: str,
    ) -> None:
        super().multiplication(block, left, right, output, kind)
        self._record_new_wire(output)
        if kind == "and":
            kind_code = KIND_AND
        elif kind == "bitness":
            kind_code = KIND_BITNESS
        else:
            raise ArchiveError(f"unsupported multiplication kind: {kind}")
        record = bytearray((TAG_MULTIPLICATION,))
        record.extend(encode_uvarint(left.identifier))
        record.extend(encode_uvarint(right.identifier))
        record.extend(encode_uvarint(output.identifier))
        record.append(kind_code)
        self._body.write(record)

    def linear_assertion(
        self,
        block: str,
        inputs: Sequence[int],
        constant: int,
        satisfied: bool,
    ) -> None:
        super().linear_assertion(block, inputs, constant, satisfied)
        record = bytearray((TAG_LINEAR_ASSERTION, constant & 1))
        self._append_ids(record, inputs)
        self._body.write(record)

    def external_assertion(self, block: str, name: str, satisfied: bool) -> None:
        super().external_assertion(block, name, satisfied)
        if not satisfied:
            self.external_failures += 1
        record = bytearray((TAG_EXTERNAL_ASSERTION,))
        record.extend(hashlib.sha256(name.encode("utf-8")).digest())
        self._body.write(record)

    def keccak_permutation(self, block: str) -> None:
        super().keccak_permutation(block)
        self._body.write(bytes((TAG_KECCAK_PERMUTATION,)))

    def finalize(self, expected_wire_count: int) -> ArchiveMetadata:
        if self._finalized:
            raise ArchiveError("archive has already been finalized")
        if len(self.assignment) != expected_wire_count:
            raise ArchiveError(
                f"assignment has {len(self.assignment)} wires, "
                f"expected {expected_wire_count}"
            )
        self._body.flush()
        body_digest = self._body.hasher.digest()
        linear_definitions = sum(
            block.linear_definitions for block in self.blocks.values()
        )
        linear_assertions = sum(
            block.linear_assertions for block in self.blocks.values()
        )
        nonlinear_constraints = sum(
            block.nonlinear_constraints for block in self.blocks.values()
        )
        keccak_permutations = sum(
            block.keccak_permutations for block in self.blocks.values()
        )
        total_rows = (
            linear_definitions + linear_assertions + nonlinear_constraints
        )
        header = HEADER.pack(
            MAGIC,
            FORMAT_VERSION,
            FIELD_DEGREE,
            expected_wire_count,
            self.public_inputs,
            self.secret_inputs,
            linear_definitions,
            linear_assertions,
            nonlinear_constraints,
            total_rows,
            self.external_assertions,
            keccak_permutations,
            self._body.length,
            body_digest,
        )
        self._handle.seek(0)
        self._handle.write(header)
        self._handle.flush()
        self._handle.close()
        self._finalized = True
        archive_hasher = hashlib.sha256()
        with self.output_path.open("rb") as archive_handle:
            for chunk in iter(lambda: archive_handle.read(1 << 20), b""):
                archive_hasher.update(chunk)
        return ArchiveMetadata(
            format="PQ-RBBC-BR1CS",
            format_version=FORMAT_VERSION,
            field="F2",
            wire_count=expected_wire_count,
            public_inputs=self.public_inputs,
            secret_inputs=self.secret_inputs,
            linear_definitions=linear_definitions,
            linear_assertions=linear_assertions,
            nonlinear_constraints=nonlinear_constraints,
            total_r1cs_rows=total_rows,
            external_assertions=self.external_assertions,
            external_failures=self.external_failures,
            keccak_permutations=keccak_permutations,
            body_bytes=self._body.length,
            archive_bytes=self.output_path.stat().st_size,
            archive_sha256=archive_hasher.hexdigest(),
            body_sha256=body_digest.hex(),
            assignment_sha256=hashlib.sha256(self.assignment).hexdigest(),
        )

    def close(self) -> None:
        if not self._handle.closed:
            self._handle.close()

    def __enter__(self) -> "BinaryR1CSSink":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


@dataclass(frozen=True)
class ArchiveHeader:
    format_version: int
    field_degree: int
    wire_count: int
    public_inputs: int
    secret_inputs: int
    linear_definitions: int
    linear_assertions: int
    nonlinear_constraints: int
    total_r1cs_rows: int
    external_assertions: int
    keccak_permutations: int
    body_bytes: int
    body_sha256: str


@dataclass(frozen=True)
class EvaluationResult:
    satisfied: bool
    failed_constraints: int
    first_failure: str | None
    rows_checked: int
    wires_defined: int
    external_assertions_unchecked: int
    body_sha256_verified: bool


def read_header(handle: BinaryIO) -> ArchiveHeader:
    raw = handle.read(HEADER.size)
    if len(raw) != HEADER.size:
        raise ArchiveError("truncated BR1CS header")
    unpacked = HEADER.unpack(raw)
    magic, version, field_degree = unpacked[:3]
    if magic != MAGIC:
        raise ArchiveError("invalid BR1CS magic")
    if version != FORMAT_VERSION:
        raise ArchiveError(f"unsupported BR1CS version: {version}")
    if field_degree != FIELD_DEGREE:
        raise ArchiveError(f"unsupported field degree: {field_degree}")
    counts = unpacked[3:13]
    digest = unpacked[13]
    values = dict(zip(HEADER_FIELDS, counts))
    return ArchiveHeader(
        format_version=version,
        field_degree=field_degree,
        body_sha256=digest.hex(),
        **values,
    )


class _HashingReader:
    def __init__(self, handle: BinaryIO, limit: int) -> None:
        self.handle = handle
        self.limit = limit
        self.consumed = 0
        self.hasher = hashlib.sha256()

    def read(self, length: int) -> bytes:
        if length < 0 or self.consumed + length > self.limit:
            raise ArchiveError("record exceeds declared BR1CS body")
        data = self.handle.read(length)
        if len(data) != length:
            raise ArchiveError("truncated BR1CS body")
        self.consumed += length
        self.hasher.update(data)
        return data


def _read_uvarint(reader: _HashingReader) -> int:
    value = 0
    shift = 0
    for _ in range(10):
        byte = reader.read(1)[0]
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return value
        shift += 7
    raise ArchiveError("overlong unsigned varint")


def _read_ids(reader: _HashingReader) -> list[int]:
    count = _read_uvarint(reader)
    if count > 10_000_000:
        raise ArchiveError("unreasonable linear-combination arity")
    return [_read_uvarint(reader) for _ in range(count)]


def evaluate_archive(
    archive_path: str | os.PathLike[str], assignment: Sequence[int]
) -> EvaluationResult:
    """Independently parse and evaluate every serialized R1CS row over F2."""
    with Path(archive_path).open("rb") as handle:
        header = read_header(handle)
        if len(assignment) != header.wire_count:
            raise ArchiveError(
                f"assignment length {len(assignment)} != {header.wire_count}"
            )
        if any(value not in (0, 1) for value in assignment):
            raise ArchiveError("assignment contains a value outside F2")
        if assignment[0] != 0 or assignment[1] != 1:
            raise ArchiveError("reserved constant wires are invalid")

        reader = _HashingReader(handle, header.body_bytes)
        record_count = (
            header.public_inputs
            + header.secret_inputs
            + header.linear_definitions
            + header.linear_assertions
            + header.nonlinear_constraints
            + header.external_assertions
            + header.keccak_permutations
        )
        next_wire = 2
        public_inputs = 0
        secret_inputs = 0
        linear_definitions = 0
        linear_assertions = 0
        nonlinear_constraints = 0
        external_assertions = 0
        keccak_permutations = 0
        failed = 0
        first_failure: str | None = None

        def fail(description: str) -> None:
            nonlocal failed, first_failure
            failed += 1
            if first_failure is None:
                first_failure = description

        def require_prior(identifier: int) -> None:
            if identifier >= next_wire:
                raise ArchiveError(
                    f"wire {identifier} is used before definition {next_wire}"
                )

        for record_index in range(record_count):
            tag = reader.read(1)[0]
            if tag == TAG_INPUT:
                output = _read_uvarint(reader)
                visibility = reader.read(1)[0]
                if output != next_wire:
                    raise ArchiveError(
                        f"input wire {output} is not sequential ({next_wire})"
                    )
                next_wire += 1
                if visibility == VISIBILITY_PUBLIC:
                    public_inputs += 1
                elif visibility == VISIBILITY_SECRET:
                    secret_inputs += 1
                else:
                    raise ArchiveError("unknown input visibility")
            elif tag == TAG_LINEAR_DEFINITION:
                output = _read_uvarint(reader)
                constant = reader.read(1)[0]
                inputs = _read_ids(reader)
                if constant not in (0, 1):
                    raise ArchiveError("linear constant is outside F2")
                if output != next_wire:
                    raise ArchiveError(
                        f"linear output {output} is not sequential ({next_wire})"
                    )
                for identifier in inputs:
                    require_prior(identifier)
                expected = constant
                for identifier in inputs:
                    expected ^= assignment[identifier]
                if assignment[output] != expected:
                    fail(f"linear definition at record {record_index}")
                next_wire += 1
                linear_definitions += 1
            elif tag == TAG_MULTIPLICATION:
                left = _read_uvarint(reader)
                right = _read_uvarint(reader)
                output = _read_uvarint(reader)
                kind = reader.read(1)[0]
                require_prior(left)
                require_prior(right)
                if output != next_wire:
                    raise ArchiveError(
                        f"multiplication output {output} is not sequential ({next_wire})"
                    )
                if kind not in (KIND_AND, KIND_BITNESS):
                    raise ArchiveError("unknown multiplication kind")
                if assignment[left] * assignment[right] != assignment[output]:
                    fail(f"multiplication at record {record_index}")
                next_wire += 1
                nonlinear_constraints += 1
            elif tag == TAG_LINEAR_ASSERTION:
                constant = reader.read(1)[0]
                inputs = _read_ids(reader)
                if constant not in (0, 1):
                    raise ArchiveError("assertion constant is outside F2")
                value = constant
                for identifier in inputs:
                    require_prior(identifier)
                    value ^= assignment[identifier]
                if value:
                    fail(f"linear assertion at record {record_index}")
                linear_assertions += 1
            elif tag == TAG_EXTERNAL_ASSERTION:
                reader.read(32)
                external_assertions += 1
            elif tag == TAG_KECCAK_PERMUTATION:
                keccak_permutations += 1
            else:
                raise ArchiveError(f"unknown record tag {tag} at {record_index}")

        if reader.consumed != header.body_bytes:
            raise ArchiveError(
                f"parsed {reader.consumed} body bytes, expected {header.body_bytes}"
            )
        if handle.read(1):
            raise ArchiveError("trailing data after BR1CS body")
        digest_ok = reader.hasher.hexdigest() == header.body_sha256
        if not digest_ok:
            raise ArchiveError("BR1CS body digest mismatch")
        if next_wire != header.wire_count:
            raise ArchiveError(
                f"defined {next_wire} wires, expected {header.wire_count}"
            )
        observed = (
            public_inputs,
            secret_inputs,
            linear_definitions,
            linear_assertions,
            nonlinear_constraints,
            external_assertions,
            keccak_permutations,
        )
        declared = (
            header.public_inputs,
            header.secret_inputs,
            header.linear_definitions,
            header.linear_assertions,
            header.nonlinear_constraints,
            header.external_assertions,
            header.keccak_permutations,
        )
        if observed != declared:
            raise ArchiveError(f"record counts {observed} != header {declared}")
        if (
            linear_definitions + linear_assertions + nonlinear_constraints
            != header.total_r1cs_rows
        ):
            raise ArchiveError("R1CS row total does not match the header")
        return EvaluationResult(
            satisfied=failed == 0,
            failed_constraints=failed,
            first_failure=first_failure,
            rows_checked=header.total_r1cs_rows,
            wires_defined=next_wire,
            external_assertions_unchecked=external_assertions,
            body_sha256_verified=True,
        )


@dataclass
class LoweredInstance:
    report: core.CircuitReport
    metadata: ArchiveMetadata
    assignment: bytearray


def lower_instance(
    output_path: str | os.PathLike[str],
    matrix: core.SystematicParityCheck,
    statement: core.IssueStatement,
    witness: core.IssueWitness,
    adapter: core.BlindUOVAdapter,
) -> LoweredInstance:
    sink = BinaryR1CSSink(output_path)
    try:
        report = core.generate_issue_circuit(
            matrix, statement, witness, adapter, sink=sink
        )
        metadata = sink.finalize(report.wire_count)
    finally:
        sink.close()
    return LoweredInstance(report, metadata, sink.assignment)


def _corruption_is_rejected(
    archive_path: Path, assignment: Sequence[int]
) -> bool:
    with tempfile.TemporaryDirectory(prefix="pq-rbbc-corrupt-") as directory:
        corrupted = Path(directory) / "corrupted.br1cs"
        shutil.copyfile(archive_path, corrupted)
        with corrupted.open("r+b") as handle:
            handle.seek(HEADER.size + 17)
            original = handle.read(1)
            if len(original) != 1:
                raise ArchiveError("archive is unexpectedly too short")
            handle.seek(HEADER.size + 17)
            handle.write(bytes((original[0] ^ 1,)))
        try:
            evaluate_archive(corrupted, assignment)
        except ArchiveError:
            return True
        return False


def build_backend_manifest(output_path: str | os.PathLike[str]) -> dict[str, object]:
    archive_path = Path(output_path)
    matrix, statement, witness, adapter = core.reference_fixture()
    honest = lower_instance(archive_path, matrix, statement, witness, adapter)
    honest_evaluation = evaluate_archive(archive_path, honest.assignment)

    tampered_assignment = bytearray(honest.assignment)
    tampered_assignment[-1] ^= 1
    assignment_tamper = evaluate_archive(archive_path, tampered_assignment)

    cases = core.negative_cases(matrix, statement, witness, adapter)
    bad_statement, bad_witness = cases["wrong_weight"]
    with tempfile.TemporaryDirectory(prefix="pq-rbbc-invalid-") as directory:
        invalid_path = Path(directory) / "invalid.br1cs"
        invalid = lower_instance(
            invalid_path, matrix, bad_statement, bad_witness, adapter
        )
        invalid_evaluation = evaluate_archive(invalid_path, invalid.assignment)
        structure_is_witness_independent = (
            honest.metadata.body_sha256 == invalid.metadata.body_sha256
            and honest.metadata.body_bytes == invalid.metadata.body_bytes
        )

    corruption_rejected = _corruption_is_rejected(
        archive_path, honest.assignment
    )
    linear_rows = (
        honest.metadata.linear_definitions + honest.metadata.linear_assertions
    )
    return {
        "implementation_version": "2.3",
        "status": "reduced and 2450-bit extended CAP fixtures plus H_RBBC have zero-callback native traces; production multi-coefficient hashing and the full 18-tree row stream remain external",
        "format": {
            "name": honest.metadata.format,
            "version": honest.metadata.format_version,
            "field": honest.metadata.field,
            "semantics": {
                "multiplication": "A*B=C",
                "linear_definition": "(out + XOR(inputs) + constant)*1=0",
                "linear_assertion": "(XOR(inputs) + constant)*1=0",
            },
            "archive_header_bytes": HEADER.size,
            "body_uses_unsigned_leb128_wire_ids": True,
        },
        "archive": asdict(honest.metadata),
        "constraint_accounting": {
            "nonlinear_rows": honest.metadata.nonlinear_constraints,
            "materialized_linear_rows": linear_rows,
            "portable_total_r1cs_rows": honest.metadata.total_r1cs_rows,
            "nonlinear_only_cost_model_total": honest.metadata.nonlinear_constraints,
            "warning": "portable row count is not directly comparable to a backend that soundly eliminates affine wires",
        },
        "round_trip": {
            "honest_assignment_accepts": honest_evaluation.satisfied,
            "rows_checked": honest_evaluation.rows_checked,
            "body_sha256_verified": honest_evaluation.body_sha256_verified,
            "external_assertions_unchecked": honest_evaluation.external_assertions_unchecked,
            "assignment_bit_tamper_rejected": not assignment_tamper.satisfied,
            "assignment_bit_tamper_first_failure": assignment_tamper.first_failure,
            "archive_corruption_rejected": corruption_rejected,
        },
        "witness_independence": {
            "honest_and_wrong_weight_body_digest_equal": structure_is_witness_independent,
            "wrong_weight_assignment_rejected": not invalid_evaluation.satisfied,
            "wrong_weight_failed_constraints": invalid_evaluation.failed_constraints,
        },
        "claim_boundary": {
            "external_assertions": honest.metadata.external_assertions,
            "external_failures_in_honest_vector": honest.metadata.external_failures,
            "external_component": "native PQ-RBBC-CAP-v1 full 18-tree row stream and exact H_RBBC wire join",
            "not_yet_done": [
                "materialize the full 18-tree CAP row stream and exact H_RBBC wire join",
                "lift the complete incremental relation into GF(2^193)",
                "proof-system-specific affine elimination",
                "post-quantum zero-knowledge and simulation-extractability qualification",
                "production Goppa key import and threshold decoder",
            ],
        },
        "native_import_contract": {
            "relation_id": native_profile.RELATION_ID,
            "target_field": native_profile.TARGET_FIELD,
            "fork_profile_sha256": native_profile.fork_profile_fingerprint(),
            "current_archive_field_matches_target": honest.metadata.field
            == native_profile.TARGET_FIELD,
            "linear_mask_equation_internalized": True,
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
            "canonical_cap_serialization_implemented": True,
            "canonical_cap_bytes_bound_to_h_rbbc": True,
            "cap_production_accounting": native_profile.cap.production_accounting(),
            "production_cap_full_vector_executed": False,
            "production_cap_native_rows_materialized": False,
            "production_cap_inter_call_wire_identity": False,
            "complete_cap_hash_implemented": False,
            "blind_uov_bit_exact_compatible": False,
            "paper_240_gap_blocks_fork_engineering": False,
            "fork_security_proof_revalidated": False,
            "signature_size_rebenchmarked": False,
            "production_closed": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", help="path for the generated .br1cs archive")
    parser.add_argument("--compact", action="store_true", help="emit compact JSON")
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    manifest = build_backend_manifest(args.output)
    encoded = json.dumps(
        manifest, indent=None if args.compact else 2, sort_keys=True
    ) + "\n"
    if args.manifest:
        args.manifest.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
