"""Exact SHAKE256 Boolean-circuit construction for ``R_access``.

The circuit uses the repository's existing FIPS-202 bit ordering and
Keccak-f[1600] builder.  It is used for construction metrics and independent
cross-checking of the word-parallel MPC execution in :mod:`mpcith`.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from pq_rbbc_reference import (
    Char2CircuitBuilder,
    CountingSink,
    constant_wires,
    input_wires,
    shake256_wires,
    wire_bytes,
)

from ...proof import (
    AccessProofStatementV2,
    AccessProofWitnessV2,
    HOLDER_BINDING_LABEL,
    HOLDER_HASH_LABEL,
)


@dataclass(frozen=True)
class AccessCircuitMetricsV01:
    relation: str
    secret_input_bits: int
    public_tuple_input_bits: int
    canonical_statement_bytes: int
    keccak_f1600_permutations: int
    boolean_and_gates: int
    boolean_xor_not_operations: int
    secret_input_bitness_constraints: int
    nonlinear_constraints_with_bitness: int
    public_output_equality_assertions: int
    wire_count: int
    failed_assertions: int
    external_assertions: int

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class AccessCircuitBuildV01:
    holder_hash: bytes
    holder_binding_tag: bytes
    metrics: AccessCircuitMetricsV01


def build_exact_access_circuit(
    statement: AccessProofStatementV2,
    witness: AccessProofWitnessV2,
) -> AccessCircuitBuildV01:
    """Materialize the exact two-SHAKE relation and its counting trace."""

    if not isinstance(statement, AccessProofStatementV2):
        raise TypeError("statement must be AccessProofStatementV2")
    if not isinstance(witness, AccessProofWitnessV2):
        raise TypeError("witness must be AccessProofWitnessV2")

    sink = CountingSink()
    builder = Char2CircuitBuilder(sink)
    builder.set_block("r_access_exact_shake256")

    # All five tuple members cross the canonical public-input boundary.  The
    # first two select the proof profile/parameters and are transcript-bound;
    # the relation equations themselves use the final three values.
    input_wires(
        builder,
        statement.access_profile_digest,
        "public",
        "access_profile_digest",
    )
    input_wires(
        builder,
        statement.access_pp_digest,
        "public",
        "access_pp_digest",
    )
    expected_holder_hash = input_wires(
        builder,
        statement.holder_hash,
        "public",
        "holder_hash",
    )
    request_core_digest = input_wires(
        builder,
        statement.request_core_digest,
        "public",
        "request_core_digest",
    )
    expected_binding_tag = input_wires(
        builder,
        statement.holder_binding_tag,
        "public",
        "holder_binding_tag",
    )
    secret = input_wires(
        builder,
        witness.holder_secret,
        "secret",
        "k_hold",
        assert_bitness=True,
    )

    computed_holder_hash = shake256_wires(
        builder,
        constant_wires(builder, HOLDER_HASH_LABEL) + secret,
        32,
    )
    computed_binding_tag = shake256_wires(
        builder,
        constant_wires(builder, HOLDER_BINDING_LABEL)
        + secret
        + request_core_digest,
        32,
    )
    for computed, expected in zip(computed_holder_hash, expected_holder_hash):
        builder.assert_equal(computed, expected)
    for computed, expected in zip(computed_binding_tag, expected_binding_tag):
        builder.assert_equal(computed, expected)

    block = sink.blocks["r_access_exact_shake256"]
    metrics = AccessCircuitMetricsV01(
        relation="exact R_access: SHAKE256(PQ-RBBC/HOLD || k_hold, 256) and "
        "SHAKE256(PQ-SAT/ACCESS-HOLDER-BIND/v2 || k_hold || "
        "request_core_digest, 256)",
        secret_input_bits=sink.secret_inputs,
        public_tuple_input_bits=sink.public_inputs,
        canonical_statement_bytes=len(statement.encode()),
        keccak_f1600_permutations=block.keccak_permutations,
        boolean_and_gates=block.and_gates,
        boolean_xor_not_operations=block.linear_definitions,
        secret_input_bitness_constraints=block.bitness_constraints,
        nonlinear_constraints_with_bitness=block.nonlinear_constraints,
        public_output_equality_assertions=block.linear_assertions,
        wire_count=builder.wire_count,
        failed_assertions=block.failed_assertions,
        external_assertions=sink.external_assertions,
    )
    return AccessCircuitBuildV01(
        holder_hash=wire_bytes(computed_holder_hash),
        holder_binding_tag=wire_bytes(computed_binding_tag),
        metrics=metrics,
    )
