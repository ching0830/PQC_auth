#!/usr/bin/env python3
"""Independent PQ-RBBC Anemoi-193/336 sponge profile, version 2.2.

This module deliberately forks away from the unreproduced 240-constraint
Blind-UOV level-III Anemoi instance.  It freezes a new, explicitly named
profile on top of the source-pinned 14-round permutation implemented in
``pq_rbbc_anemoi_f193``:

    PQ-RBBC-Anemoi-193/336-Sponge-v1

The state contains eight GF(2^193) elements.  Four elements are rate and four
are capacity.  Byte strings are framed with a profile marker, a domain length,
the domain, and a 64-bit payload length, then padded with bit-level ``10*1`` to
the 772-bit rate.  Bytes and field coefficients are both ordered least-
significant bit first.  Request-binding output is 576 bits (72 bytes).

The native trace constrains payload bitness, byte-to-field packing, every
permutation, state chaining, and the 579-bit decomposition of the first three
output field elements.  Only the first 576 output bits are exposed.  This is a
hash primitive and row generator, not a complete CAP/GGM implementation and
not a bit-exact Blind-UOV implementation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping, Sequence

import pq_rbbc_anemoi_f193 as permutation


IMPLEMENTATION_VERSION = "2.2"
PROFILE_NAME = "PQ-RBBC-Anemoi-193/336-Sponge-v1"
PROFILE_RELATION_ID = "pq-rbbc/anemoi-193-336/sponge/v1"
FRAME_MAGIC = b"PQRBBC-SPONGE-V1"
TRANSCRIPT_MAGIC = b"PQRBBC-TRANSCRIPT-V1"
REQUEST_BINDING_DOMAIN = b"PQ-RBBC/v2.0/H_RBBC"

RATE_ELEMENTS = 4
CAPACITY_ELEMENTS = 4
RATE_BITS = RATE_ELEMENTS * permutation.FIELD_DEGREE
CAPACITY_BITS = CAPACITY_ELEMENTS * permutation.FIELD_DEGREE
REQUEST_HASH_BITS = 576
REQUEST_HASH_BYTES = REQUEST_HASH_BITS // 8
DECOMPOSED_OUTPUT_ELEMENTS = 3
DECOMPOSED_OUTPUT_BITS = DECOMPOSED_OUTPUT_ELEMENTS * permutation.FIELD_DEGREE


@dataclass(frozen=True)
class PayloadBit:
    index: int


FrameSymbol = int | PayloadBit


def bytes_to_bits_lsb(data: bytes) -> list[int]:
    return [(byte >> bit) & 1 for byte in data for bit in range(8)]


def bits_to_bytes_lsb(bits: Sequence[int]) -> bytes:
    if len(bits) % 8:
        raise ValueError("bit length must be a multiple of eight")
    result = bytearray(len(bits) // 8)
    for index, bit in enumerate(bits):
        if bit not in (0, 1):
            raise ValueError("non-binary output bit")
        result[index // 8] |= bit << (index % 8)
    return bytes(result)


def encode_transcript(fields: Sequence[bytes]) -> bytes:
    """Injectively encode an ordered byte-string tuple."""

    if len(fields) > 0xFFFF:
        raise ValueError("too many transcript fields")
    encoded = bytearray(TRANSCRIPT_MAGIC)
    encoded.extend(len(fields).to_bytes(2, "little"))
    for field in fields:
        if len(field) >= 1 << 64:
            raise ValueError("transcript field is too long")
        encoded.extend(len(field).to_bytes(8, "little"))
        encoded.extend(field)
    return bytes(encoded)


def _frame_symbols(domain: bytes, payload_bytes: int) -> tuple[FrameSymbol, ...]:
    if not domain:
        raise ValueError("domain must be nonempty")
    if len(domain) > 0xFFFF:
        raise ValueError("domain is too long")
    if payload_bytes < 0 or payload_bytes >= 1 << 64:
        raise ValueError("invalid payload length")

    header = (
        FRAME_MAGIC
        + len(domain).to_bytes(2, "little")
        + domain
        + payload_bytes.to_bytes(8, "little")
    )
    symbols: list[FrameSymbol] = list(bytes_to_bits_lsb(header))
    symbols.extend(PayloadBit(index) for index in range(payload_bytes * 8))

    # Multi-rate 10*1 padding, applied after the length-delimited frame.
    symbols.append(1)
    while len(symbols) % RATE_BITS != RATE_BITS - 1:
        symbols.append(0)
    symbols.append(1)
    if len(symbols) % RATE_BITS:
        raise AssertionError("sponge padding did not align to the rate")
    return tuple(symbols)


def _materialize_symbols(symbols: Sequence[FrameSymbol], payload: bytes) -> list[int]:
    payload_bits = bytes_to_bits_lsb(payload)
    result: list[int] = []
    for symbol in symbols:
        if isinstance(symbol, PayloadBit):
            result.append(payload_bits[symbol.index])
        else:
            result.append(symbol)
    return result


def _pack_field_bits(bits: Sequence[int]) -> int:
    if len(bits) != permutation.FIELD_DEGREE:
        raise ValueError("one field lane must contain exactly 193 bits")
    return sum(bit << index for index, bit in enumerate(bits))


def framed_rate_blocks(domain: bytes, payload: bytes) -> tuple[tuple[int, ...], ...]:
    symbols = _frame_symbols(domain, len(payload))
    bits = _materialize_symbols(symbols, payload)
    blocks: list[tuple[int, ...]] = []
    for block_start in range(0, len(bits), RATE_BITS):
        block_bits = bits[block_start : block_start + RATE_BITS]
        blocks.append(
            tuple(
                _pack_field_bits(
                    block_bits[
                        lane * permutation.FIELD_DEGREE :
                        (lane + 1) * permutation.FIELD_DEGREE
                    ]
                )
                for lane in range(RATE_ELEMENTS)
            )
        )
    return tuple(blocks)


def evaluate_sponge(
    domain: bytes,
    payload: bytes,
    output_bytes: int = REQUEST_HASH_BYTES,
    parameters: permutation.AnemoiParameters | None = None,
) -> bytes:
    if output_bytes <= 0:
        raise ValueError("output length must be positive")
    parameters = parameters or permutation.derive_parameters()
    state = [0] * permutation.STATE_ELEMENTS
    for block in framed_rate_blocks(domain, payload):
        for lane, value in enumerate(block):
            state[lane] ^= value
        state = list(permutation.evaluate_permutation(state, parameters))

    output_bits: list[int] = []
    needed_bits = output_bytes * 8
    while len(output_bits) < needed_bits:
        for lane in range(RATE_ELEMENTS):
            output_bits.extend(
                (state[lane] >> bit) & 1
                for bit in range(permutation.FIELD_DEGREE)
            )
        if len(output_bits) < needed_bits:
            state = list(permutation.evaluate_permutation(state, parameters))
    return bits_to_bytes_lsb(output_bits[:needed_bits])


def hash_request_binding(message: bytes, cap_commitment: bytes) -> bytes:
    """The forked 576-bit request-binding hash H_RBBC(m, c_r)."""

    return evaluate_sponge(
        REQUEST_BINDING_DOMAIN,
        encode_transcript((message, cap_commitment)),
        REQUEST_HASH_BYTES,
    )


def profile_dict(parameters: permutation.AnemoiParameters) -> dict[str, object]:
    return {
        "capacity_bits": CAPACITY_BITS,
        "capacity_elements": CAPACITY_ELEMENTS,
        "field": "GF(2^193)",
        "frame_magic_hex": FRAME_MAGIC.hex(),
        "frame_rule": "magic || u16le(domain_bytes) || domain || u64le(payload_bytes) || payload || pad10*1",
        "output_bit_order": "field lanes in order; polynomial coefficients LSB-first",
        "parameter_fingerprint": parameters.fingerprint(),
        "permutation_relation_id": permutation.COMPONENT_RELATION_ID,
        "profile_name": PROFILE_NAME,
        "profile_relation_id": PROFILE_RELATION_ID,
        "rate_bits": RATE_BITS,
        "rate_elements": RATE_ELEMENTS,
        "request_binding_domain_hex": REQUEST_BINDING_DOMAIN.hex(),
        "request_hash_bits": REQUEST_HASH_BITS,
        "rounds": permutation.UPSTREAM_ROUNDS,
        "rows_per_permutation": permutation.NONLINEAR_ROWS,
        "state_elements": permutation.STATE_ELEMENTS,
        "transcript_encoding": "magic || u16le(field_count) || repeated(u64le(field_bytes) || field)",
        "transcript_magic_hex": TRANSCRIPT_MAGIC.hex(),
    }


def profile_fingerprint(parameters: permutation.AnemoiParameters) -> str:
    encoded = json.dumps(
        profile_dict(parameters), sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _wire_id(form: permutation.LinearForm) -> int:
    if len(form.terms) != 1 or form.terms[0][1] != 1 or form.constant:
        raise ValueError("expected a canonical wire form")
    return form.terms[0][0]


def _remap_form(
    form: permutation.LinearForm, mapping: Mapping[int, int]
) -> permutation.LinearForm:
    return permutation.LinearForm(
        tuple((mapping[wire_id], coefficient) for wire_id, coefficient in form.terms),
        form.constant,
    )


def _append_permutation_trace(
    builder: permutation.NativeRowBuilder,
    trace: permutation.NativeTrace,
    prefix: str,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    mapping: dict[int, int] = {}
    for old_wire_id in sorted(trace.assignment):
        new_form = builder.new_wire(
            trace.assignment[old_wire_id],
            f"{prefix}.{trace.wire_labels[old_wire_id]}",
        )
        mapping[old_wire_id] = _wire_id(new_form)
    for row in trace.rows:
        builder.row(
            f"{prefix}.{row.label}",
            _remap_form(row.left, mapping),
            _remap_form(row.right, mapping),
            _remap_form(row.output, mapping),
        )
    return (
        tuple(mapping[wire_id] for wire_id in trace.input_wires),
        tuple(mapping[wire_id] for wire_id in trace.output_wires),
    )


@dataclass(frozen=True)
class SpongeTrace:
    rows: tuple[permutation.RankOneRow, ...]
    assignment: dict[int, int]
    wire_labels: dict[int, str]
    payload_bit_wires: tuple[int, ...]
    output_bit_wires: tuple[int, ...]
    output_bytes: bytes
    requested_output_bits: int
    absorbed_blocks: int
    permutation_nonlinear_rows: int
    input_bitness_rows: int
    output_bitness_rows: int
    linear_rows: int

    def failed_rows(self, assignment: Mapping[int, int] | None = None) -> list[str]:
        values = self.assignment if assignment is None else assignment
        return [row.label for row in self.rows if not row.satisfied(values)]


def _symbolic_lane_form(
    lane_symbols: Sequence[FrameSymbol], payload_wires: Sequence[int]
) -> permutation.LinearForm:
    if len(lane_symbols) != permutation.FIELD_DEGREE:
        raise ValueError("symbolic lane must contain 193 bits")
    constant = 0
    terms: list[tuple[int, int]] = []
    for coefficient_bit, symbol in enumerate(lane_symbols):
        coefficient = 1 << coefficient_bit
        if isinstance(symbol, PayloadBit):
            terms.append((payload_wires[symbol.index], coefficient))
        elif symbol:
            constant ^= coefficient
    return permutation.LinearForm(tuple(terms), constant)


def build_sponge_trace(
    domain: bytes,
    payload: bytes,
    parameters: permutation.AnemoiParameters | None = None,
    *,
    output_bits: int = REQUEST_HASH_BITS,
) -> SpongeTrace:
    """Build and evaluate a native sponge relation up to one rate block.

    The default remains the frozen 576-bit request hash.  CAP lowering also
    uses the same relation for 193-, 259-, and 386-bit XOF outputs.  Longer
    production tapes require the later streaming squeeze extension and are
    rejected here rather than silently truncated.
    """

    parameters = parameters or permutation.derive_parameters()
    if output_bits <= 0 or output_bits > RATE_BITS:
        raise ValueError("native sponge trace supports 1..772 output bits")
    symbols = _frame_symbols(domain, len(payload))
    concrete_bits = _materialize_symbols(symbols, payload)
    builder = permutation.NativeRowBuilder()

    payload_bits = bytes_to_bits_lsb(payload)
    payload_forms = [
        builder.new_wire(value, f"payload[{index}]")
        for index, value in enumerate(payload_bits)
    ]
    payload_wires = tuple(_wire_id(form) for form in payload_forms)
    for index, form in enumerate(payload_forms):
        builder.row(
            f"payload[{index}].bit",
            form,
            form.add(permutation.LinearForm.const(1)),
            permutation.LinearForm.const(0),
        )

    previous_output_wires: tuple[int, ...] | None = None
    absorbed_blocks = len(symbols) // RATE_BITS
    for block_index in range(absorbed_blocks):
        block_start = block_index * RATE_BITS
        block_symbols = symbols[block_start : block_start + RATE_BITS]
        block_bits = concrete_bits[block_start : block_start + RATE_BITS]
        lane_wires: list[int] = []
        for lane in range(RATE_ELEMENTS):
            lane_start = lane * permutation.FIELD_DEGREE
            lane_symbols = block_symbols[
                lane_start : lane_start + permutation.FIELD_DEGREE
            ]
            lane_bits = block_bits[
                lane_start : lane_start + permutation.FIELD_DEGREE
            ]
            lane_value = _pack_field_bits(lane_bits)
            lane_form = builder.new_wire(
                lane_value, f"block[{block_index}].lane[{lane}]"
            )
            lane_wires.append(_wire_id(lane_form))
            packed_form = _symbolic_lane_form(lane_symbols, payload_wires)
            builder.row(
                f"block[{block_index}].lane[{lane}].pack",
                lane_form.add(packed_form),
                permutation.LinearForm.const(1),
                permutation.LinearForm.const(0),
            )

        input_state = [0] * permutation.STATE_ELEMENTS
        for lane in range(RATE_ELEMENTS):
            input_state[lane] = lane_wires and builder.assignment[lane_wires[lane]]
            if previous_output_wires is not None:
                input_state[lane] ^= builder.assignment[previous_output_wires[lane]]
        if previous_output_wires is not None:
            for lane in range(RATE_ELEMENTS, permutation.STATE_ELEMENTS):
                input_state[lane] = builder.assignment[previous_output_wires[lane]]

        local_trace = permutation.build_native_trace(input_state, parameters)
        input_wires, output_wires = _append_permutation_trace(
            builder, local_trace, f"perm[{block_index}]"
        )
        for lane, input_wire in enumerate(input_wires):
            expected = permutation.LinearForm.const(0)
            if previous_output_wires is not None:
                expected = expected.add(
                    permutation.LinearForm.wire(previous_output_wires[lane])
                )
            if lane < RATE_ELEMENTS:
                expected = expected.add(permutation.LinearForm.wire(lane_wires[lane]))
            builder.row(
                f"perm[{block_index}].input[{lane}].link",
                permutation.LinearForm.wire(input_wire).add(expected),
                permutation.LinearForm.const(1),
                permutation.LinearForm.const(0),
            )
        previous_output_wires = output_wires

    if previous_output_wires is None:
        raise AssertionError("padded sponge must absorb at least one block")

    output_bit_forms: list[permutation.LinearForm] = []
    decomposed_output_elements = (
        output_bits + permutation.FIELD_DEGREE - 1
    ) // permutation.FIELD_DEGREE
    for lane in range(decomposed_output_elements):
        lane_value = builder.assignment[previous_output_wires[lane]]
        lane_bit_forms = [
            builder.new_wire(
                (lane_value >> bit) & 1,
                f"digest.lane[{lane}].bit[{bit}]",
            )
            for bit in range(permutation.FIELD_DEGREE)
        ]
        for bit, form in enumerate(lane_bit_forms):
            builder.row(
                f"digest.lane[{lane}].bit[{bit}].bit",
                form,
                form.add(permutation.LinearForm.const(1)),
                permutation.LinearForm.const(0),
            )
        packed = permutation.add_forms(
            *(
                form.scale(1 << bit)
                for bit, form in enumerate(lane_bit_forms)
            )
        )
        builder.row(
            f"digest.lane[{lane}].pack",
            permutation.LinearForm.wire(previous_output_wires[lane]).add(packed),
            permutation.LinearForm.const(1),
            permutation.LinearForm.const(0),
        )
        output_bit_forms.extend(lane_bit_forms)

    output_forms = output_bit_forms[:output_bits]
    output_wires = tuple(_wire_id(form) for form in output_forms)
    constrained_value = sum(
        builder.assignment[wire_id] << index
        for index, wire_id in enumerate(output_wires)
    )
    output_byte_length = (output_bits + 7) // 8
    constrained_output = constrained_value.to_bytes(output_byte_length, "little")
    direct_value = int.from_bytes(
        evaluate_sponge(domain, payload, output_byte_length, parameters),
        "little",
    ) & ((1 << output_bits) - 1)
    direct_output = direct_value.to_bytes(output_byte_length, "little")
    if constrained_output != direct_output:
        raise AssertionError("constrained and direct sponge outputs disagree")

    input_bitness_rows = len(payload_bits)
    output_bitness_rows = decomposed_output_elements * permutation.FIELD_DEGREE
    permutation_nonlinear_rows = absorbed_blocks * permutation.NONLINEAR_ROWS
    total_nonlinear_rows = (
        input_bitness_rows + output_bitness_rows + permutation_nonlinear_rows
    )
    linear_rows = len(builder.rows) - total_nonlinear_rows
    return SpongeTrace(
        rows=tuple(builder.rows),
        assignment=dict(builder.assignment),
        wire_labels=dict(builder.wire_labels),
        payload_bit_wires=payload_wires,
        output_bit_wires=output_wires,
        output_bytes=constrained_output,
        requested_output_bits=output_bits,
        absorbed_blocks=absorbed_blocks,
        permutation_nonlinear_rows=permutation_nonlinear_rows,
        input_bitness_rows=input_bitness_rows,
        output_bitness_rows=output_bitness_rows,
        linear_rows=linear_rows,
    )


def serialize_sponge_row_stream(
    trace: SpongeTrace,
    domain: bytes,
    payload_bytes: int,
    parameters: permutation.AnemoiParameters,
) -> bytes:
    document = {
        "domain_hex": domain.hex(),
        "format": "F193-R1CS-JSON-1",
        "output_bit_wires": list(trace.output_bit_wires),
        "payload_bit_wires": list(trace.payload_bit_wires),
        "payload_bytes": payload_bytes,
        "profile_fingerprint": profile_fingerprint(parameters),
        "relation_id": PROFILE_RELATION_ID,
        "rows": [row.canonical_dict() for row in trace.rows],
    }
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def build_manifest(
    trace: SpongeTrace,
    domain: bytes,
    payload: bytes,
    parameters: permutation.AnemoiParameters,
    upstream_source_path: Path | None = None,
) -> dict[str, object]:
    row_stream = serialize_sponge_row_stream(
        trace, domain, len(payload), parameters
    )
    observed_source_hash = None
    source_pin_verified = False
    if upstream_source_path is not None:
        observed_source_hash = hashlib.sha256(
            upstream_source_path.read_bytes()
        ).hexdigest()
        source_pin_verified = (
            observed_source_hash == permutation.UPSTREAM_SOURCE_SHA256
        )
    return {
        "implementation_version": IMPLEMENTATION_VERSION,
        "profile": profile_dict(parameters),
        "profile_fingerprint": profile_fingerprint(parameters),
        "fork_decision": {
            "selected_mode": "independent-pq-rbbc-profile",
            "blind_uov_reported_rows": permutation.BLIND_UOV_REPORTED_CONSTRAINTS,
            "fork_rows_per_permutation": permutation.NONLINEAR_ROWS,
            "blind_uov_bit_exact_compatible": False,
            "paper_signature_size_inherited_as_theorem": False,
            "paper_security_reduction_revalidated_for_fork": False,
        },
        "upstream_pin": {
            "repository": permutation.UPSTREAM_REPOSITORY,
            "commit": permutation.UPSTREAM_COMMIT,
            "anemoi_sage_sha256": permutation.UPSTREAM_SOURCE_SHA256,
            "observed_source_sha256": observed_source_hash,
            "source_pin_verified_locally": source_pin_verified,
        },
        "frozen_trace": {
            "domain_hex": domain.hex(),
            "payload_bytes": len(payload),
            "absorbed_blocks": trace.absorbed_blocks,
            "wires": len(trace.assignment),
            "permutation_nonlinear_rows": trace.permutation_nonlinear_rows,
            "input_bitness_rows": trace.input_bitness_rows,
            "output_bitness_rows": trace.output_bitness_rows,
            "linear_rows": trace.linear_rows,
            "total_rows": len(trace.rows),
            "row_stream_sha256": hashlib.sha256(row_stream).hexdigest(),
            "output_hex": trace.output_bytes.hex(),
            "honest_failures": trace.failed_rows(),
            "witness_independent_topology_for_fixed_lengths": True,
        },
        "component_status": {
            "source_pinned_permutation": True,
            "canonical_sponge": True,
            "domain_separation": True,
            "injective_length_framing": True,
            "request_binding_hash_primitive": True,
            "cap_commit": False,
            "ggm_tree": False,
            "fiat_shamir_transcript": False,
            "circuit_message_and_commitment_wires_linked": False,
            "complete_cap_hash": False,
        },
        "claim_boundary": {
            "capacity_bits": CAPACITY_BITS,
            "capacity_margin_is_security_proof": False,
            "independent_cryptanalysis_complete": False,
            "production_closed": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--upstream-source", type=Path)
    args = parser.parse_args()

    parameters = permutation.derive_parameters()
    fixture_message = bytes(32)
    fixture_commitment = bytes(range(48))
    payload = encode_transcript((fixture_message, fixture_commitment))
    trace = build_sponge_trace(REQUEST_BINDING_DOMAIN, payload, parameters)
    if trace.failed_rows():
        raise AssertionError("honest sponge trace failed")
    row_stream = serialize_sponge_row_stream(
        trace, REQUEST_BINDING_DOMAIN, len(payload), parameters
    )
    manifest = build_manifest(
        trace,
        REQUEST_BINDING_DOMAIN,
        payload,
        parameters,
        args.upstream_source,
    )
    if args.output:
        args.output.write_bytes(row_stream)
    if args.manifest:
        args.manifest.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if not args.output and not args.manifest:
        print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
