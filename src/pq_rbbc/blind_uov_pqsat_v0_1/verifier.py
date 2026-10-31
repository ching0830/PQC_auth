"""Fail-closed Blind-UOV CAP verifier for the PQ-SAT v0.1 profile.

The verifier consumes the explicit :class:`CAPStatement.public_map`; it has
no registry lookup, global map, or ``ctx``-as-seed fallback.  Verification is
research/reference code: it is deliberately non-constant-time except for the
two final digest comparisons, and it is not production-qualified.

Only the received proof-of-work nonce is evaluated.  This module never
searches earlier nonces and never attempts to establish global minimality.
"""

from __future__ import annotations

import hmac
from typing import Final

from .codec import (
    CR,
    CZ,
    Pi2,
    CodecValidationError,
    decode_c_r,
    decode_c_z,
    decode_pi_2,
)
from .consistency import (
    ConsistencyEncodingError,
    XiPolynomial,
    encode_xi_polynomials,
)
from .evaluation import (
    FiniteEvaluationPoint,
    evaluation_group,
    evaluation_point,
    reciprocal_coordinate,
)
from .field import consistency_hash, gf_inv, gf_mul
from .parameters import FieldId, load_profile_manifest
from .relation import (
    CAPStatement,
    RelationError,
    decode_correction_data,
    reconstruct_opened_q,
)
from .response import (
    ResponseEncodingError,
    decode_tcith_responses,
    encode_h3_q_and_qbar,
)
from .transcript import (
    derive_consistency_points,
    derive_gammas,
    derive_h1,
    derive_h2,
    derive_h2_prime,
    derive_h3,
    derive_hidden_positions,
    explicit_pow_passes,
    hidden_positions_are_admissible,
)
from .tree import (
    Opening,
    TreeValidationError,
    VerifiedLeaves,
    canonical_frontier_indices,
    verify_opening,
)


class VerifierError(ValueError):
    """Controlled rejection of malformed parsed verifier input."""


_PROFILE: Final = load_profile_manifest()
_REPETITIONS: Final = _PROFILE.tau
_WITNESS_BITS: Final = _PROFILE.relation.witness_bits
_R_BITS: Final = _PROFILE.relation.r_bits
_CONSISTENCY_ELEMENTS: Final = _PROFILE.consistency.eta
_CORRECTIONS: Final = _REPETITIONS - 1
_CORRECTION_DELTAS_BYTES: Final = (
    _CORRECTIONS * (_WITNESS_BITS + _CONSISTENCY_ELEMENTS) // 8
)
_DELTA_Z_BYTES: Final = _PROFILE.relation.z_bits // 8


def _group_id(repetition: int) -> int:
    return 0 if repetition < 2 else 1


def _field_degree(field_id: FieldId) -> int:
    if field_id is FieldId.GF_2_12:
        return 12
    if field_id is FieldId.GF_2_11:
        return 11
    raise VerifierError("opening uses an unsupported extension field")


def _group_rho(group_id: int) -> int:
    return _PROFILE.tree_groups[group_id].rho


def _validate_parsed_inputs(
    statement: object,
    c_r: object,
    c_z: object,
    pi_2: object,
) -> tuple[CAPStatement, CR, CZ, Pi2]:
    """Re-run all exact-type and frozen-shape constructors."""

    if type(statement) is not CAPStatement:
        raise VerifierError("statement must be exactly CAPStatement")
    if type(c_r) is not CR:
        raise VerifierError("c_r must be exactly CR")
    if type(c_z) is not CZ:
        raise VerifierError("c_z must be exactly CZ")
    if type(pi_2) is not Pi2:
        raise VerifierError("pi_2 must be exactly Pi2")

    # Frozen dataclasses can be manufactured through low-level object APIs.
    # Reconstructing each public object repeats the complete public boundary
    # validation without consulting any hidden issuer-map registry.
    CAPStatement(statement.public_map, statement.ctx, statement.u)
    CR(c_r.salt, c_r.h2_prime, c_r.correction_data)
    CZ(c_z.delta_z)
    Pi2(
        pi_2.h3,
        pi_2.pow_nonce,
        pi_2.opening,
        pi_2.hidden_leaf_commitments,
        pi_2.tcith_responses,
    )
    return statement, c_r, c_z, pi_2


def _planes_to_elements(planes: list[int], length: int) -> tuple[int, ...]:
    """Transpose coefficient bit planes into canonical field elements."""

    elements = [0] * length
    for coefficient_bit, plane in enumerate(planes):
        remaining = plane
        coefficient = 1 << coefficient_bit
        while remaining:
            least = remaining & -remaining
            elements[least.bit_length() - 1] |= coefficient
            remaining ^= least
    return tuple(elements)


def _accumulate_tape(
    planes: list[int], tape: bytes, coefficient: int
) -> None:
    """XOR one base-field tape into each selected coefficient bit plane."""

    tape_bits = int.from_bytes(tape, "little")
    selected = coefficient
    while selected:
        least = selected & -selected
        planes[least.bit_length() - 1] ^= tape_bits
        selected ^= least


def _reconstruct_opened_evaluations(
    verified_leaves: VerifiedLeaves,
    repetition: int,
    hidden_position: int,
    hidden_point: FiniteEvaluationPoint,
) -> tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...]]:
    """Stream all opened leaf tapes into ``vP``, ``vM``, and ``vMhat``.

    This is the bit-plane equivalent of calling
    :func:`reconstruct_opening_evaluation` for every tape coordinate.  It
    materializes only ``mu`` large integers per vector family, never an
    ``N-by-2048`` or ``N-by-256`` Python tuple matrix.
    """

    group_id = _group_id(repetition)
    group = evaluation_group(group_id)
    if hidden_point.field_id is not group.field_id:
        raise VerifierError("hidden point has the wrong group field")
    degree = _field_degree(group.field_id)
    p_planes = [0] * degree
    m_planes = [0] * degree
    mhat_planes = [0] * degree

    for position in range(group.party_count):
        if position == hidden_position:
            continue
        point = evaluation_point(group_id, position)
        coefficient = 1 ^ gf_mul(
            group.field_id,
            hidden_point.value,
            reciprocal_coordinate(point),
        )
        tape = verified_leaves.leaf_tape(repetition, position)
        _accumulate_tape(p_planes, tape.p_plain, coefficient)
        _accumulate_tape(m_planes, tape.m_plain, coefficient)
        _accumulate_tape(mhat_planes, tape.mhat_plain, coefficient)

    return (
        _planes_to_elements(p_planes, _WITNESS_BITS),
        _planes_to_elements(m_planes, _group_rho(group_id)),
        _planes_to_elements(mhat_planes, _CONSISTENCY_ELEMENTS),
    )


def _xor_base_field_delta(
    values: tuple[int, ...], delta: bytes, name: str
) -> tuple[int, ...]:
    if type(values) is not tuple:
        raise VerifierError(f"{name} values must be an exact tuple")
    if type(delta) is not bytes:
        raise VerifierError(f"{name} delta must be exact bytes")
    if len(values) != len(delta) * 8:
        raise VerifierError(f"{name} delta has the wrong bit length")
    return tuple(
        value ^ ((delta[index // 8] >> (index % 8)) & 1)
        for index, value in enumerate(values)
    )


def _lift_consistency_hash(
    field_id: FieldId,
    witness_values: tuple[int, ...],
    consistency_values: tuple[int, ...],
    points: tuple[int, int, int, int],
) -> tuple[int, ...]:
    """Evaluate the full scalar extension of ``H(P) XOR Mhat``."""

    degree = _field_degree(field_id)
    if type(witness_values) is not tuple or len(witness_values) != _WITNESS_BITS:
        raise VerifierError("witness evaluation has the wrong shape")
    if (
        type(consistency_values) is not tuple
        or len(consistency_values) != _CONSISTENCY_ELEMENTS
    ):
        raise VerifierError("consistency-mask evaluation has the wrong shape")

    lifted = list(consistency_values)
    upper_bound = 1 << degree
    for index, value in enumerate(witness_values):
        if type(value) is not int or not 0 <= value < upper_bound:
            raise VerifierError(
                f"witness evaluation element {index} is outside the field"
            )
    for index, value in enumerate(lifted):
        if type(value) is not int or not 0 <= value < upper_bound:
            raise VerifierError(
                f"consistency evaluation element {index} is outside the field"
            )

    for coefficient_bit in range(degree):
        plane = bytearray(_WITNESS_BITS // 8)
        for index, value in enumerate(witness_values):
            plane[index // 8] |= (
                (value >> coefficient_bit) & 1
            ) << (index % 8)
        hashed_plane = consistency_hash(bytes(plane), points)
        for output_index in range(_CONSISTENCY_ELEMENTS):
            if (hashed_plane[output_index // 8] >> (output_index % 8)) & 1:
                lifted[output_index] ^= 1 << coefficient_bit
    return tuple(lifted)


def _xi_from_opening(
    point: FiniteEvaluationPoint,
    witness_values: tuple[int, ...],
    consistency_values: tuple[int, ...],
    alpha_prime: bytes,
    consistency_points: tuple[int, int, int, int],
) -> XiPolynomial:
    lifted = _lift_consistency_hash(
        point.field_id,
        witness_values,
        consistency_values,
        consistency_points,
    )
    inverse_x = gf_inv(point.field_id, point.value)
    linear = tuple(
        gf_mul(
            point.field_id,
            inverse_x,
            value ^ ((alpha_prime[index // 8] >> (index % 8)) & 1),
        )
        for index, value in enumerate(lifted)
    )
    return XiPolynomial(alpha_prime, linear)


def _verify_parsed_core(
    statement: CAPStatement,
    c_r: CR,
    c_z: CZ,
    pi_2: Pi2,
) -> bool:
    statement, c_r, c_z, pi_2 = _validate_parsed_inputs(
        statement, c_r, c_z, pi_2
    )

    correction_data = decode_correction_data(c_r.correction_data)

    # Semantic replay is intentional even when these objects came from the
    # strict wire codec.  Exactly the received nonce is tested once.
    if not explicit_pow_passes(pi_2.h3, pi_2.pow_nonce):
        return False
    hidden_positions = derive_hidden_positions(pi_2.h3, pi_2.pow_nonce)
    if not hidden_positions_are_admissible(hidden_positions):
        return False
    frontier_indices = canonical_frontier_indices(hidden_positions)
    if len(frontier_indices) != len(pi_2.opening.seeds):
        return False

    verified_leaves = verify_opening(
        c_r.salt,
        hidden_positions,
        pi_2.opening,
    )
    commitments = verified_leaves.transcript_commitments(
        pi_2.hidden_leaf_commitments
    )

    correction_deltas = b"".join(
        correction.delta_p + correction.delta_mhat
        for correction in correction_data.corrections
    )
    if len(correction_deltas) != _CORRECTION_DELTAS_BYTES:
        raise VerifierError("correction delta transcript has the wrong length")
    h1 = derive_h1(
        statement.ctx,
        c_r.salt,
        commitments,
        correction_deltas,
    )
    consistency_points = derive_consistency_points(h1)

    opened_values: list[
        tuple[FiniteEvaluationPoint, tuple[int, ...], tuple[int, ...]]
    ] = []
    xi_polynomials: list[XiPolynomial] = []
    for repetition, hidden_position in enumerate(hidden_positions):
        point = evaluation_point(_group_id(repetition), hidden_position)
        if type(point) is not FiniteEvaluationPoint:
            raise VerifierError("accepted hidden point is not finite")
        v_p, v_m, v_mhat = _reconstruct_opened_evaluations(
            verified_leaves,
            repetition,
            hidden_position,
            point,
        )
        if repetition:
            correction = correction_data.corrections[repetition - 1]
            v_p = _xor_base_field_delta(
                v_p, correction.delta_p, "delta_P"
            )
            v_mhat = _xor_base_field_delta(
                v_mhat, correction.delta_mhat, "delta_Mhat"
            )
        xi_polynomials.append(
            _xi_from_opening(
                point,
                v_p,
                v_mhat,
                correction_data.alpha_prime,
                consistency_points,
            )
        )
        opened_values.append((point, v_p, v_m))

    xi_bytes = encode_xi_polynomials(tuple(xi_polynomials))
    expected_h2_prime = derive_h2_prime(h1, xi_bytes)
    if not hmac.compare_digest(expected_h2_prime, c_r.h2_prime):
        return False

    h2 = derive_h2(
        statement.ctx,
        statement.u,
        c_r.h2_prime,
        c_z.delta_z,
    )
    qbar_groups = decode_tcith_responses(pi_2.tcith_responses)
    gammas_by_group = (derive_gammas(h2, 0), derive_gammas(h2, 1))
    delta_w = bytes(_R_BITS // 8) + c_z.delta_z
    if len(delta_w) != _WITNESS_BITS // 8:
        raise VerifierError("zero_r || delta_z has the wrong length")

    q_group_lists: tuple[list[int], list[int]] = ([], [])
    for repetition, (point, v_p, v_m) in enumerate(opened_values):
        group_id = _group_id(repetition)
        group = evaluation_group(group_id)
        local_repetition = repetition if group_id == 0 else repetition - 2
        rho = _group_rho(group_id)
        qbar_start = local_repetition * rho
        qbar = qbar_groups[group_id][
            qbar_start : qbar_start + rho
        ]
        if len(qbar) != rho:
            raise VerifierError("Qbar repetition slice has the wrong length")
        v_p_double_prime = _xor_base_field_delta(
            v_p,
            delta_w,
            "zero_r_delta_z",
        )
        q_group_lists[group_id].extend(
            reconstruct_opened_q(
                statement,
                point,
                v_p_double_prime,
                v_m,
                qbar,
                gammas_by_group[group_id],
            )
        )

    q_groups = (tuple(q_group_lists[0]), tuple(q_group_lists[1]))
    q_and_qbar = encode_h3_q_and_qbar(q_groups, qbar_groups)
    expected_h3 = derive_h3(statement.ctx, statement.u, h2, q_and_qbar)
    return hmac.compare_digest(expected_h3, pi_2.h3)


def verify_parsed(
    statement: CAPStatement,
    c_r: CR,
    c_z: CZ,
    pi_2: Pi2,
) -> bool:
    """Verify already-decoded CAP objects against one explicit UOV map.

    Malformed parsed input raises :class:`VerifierError`.  Ordinary semantic
    proof failures return ``False``.  ``AssertionError`` and process-level
    exceptions are deliberately not caught or reclassified.
    """

    try:
        return _verify_parsed_core(statement, c_r, c_z, pi_2)
    except VerifierError:
        raise
    except (TypeError, ValueError) as error:
        raise VerifierError(str(error)) from error


def verify(
    statement: CAPStatement,
    c_r_bytes: bytes,
    c_z_bytes: bytes,
    pi_2_bytes: bytes,
) -> bool:
    """Strictly decode and fail closed on controlled invalid-proof input."""

    try:
        c_r = decode_c_r(c_r_bytes)
        c_z = decode_c_z(c_z_bytes)
        pi_2 = decode_pi_2(pi_2_bytes)
        return verify_parsed(statement, c_r, c_z, pi_2)
    except (
        VerifierError,
        CodecValidationError,
        ConsistencyEncodingError,
        RelationError,
        ResponseEncodingError,
        TreeValidationError,
        TypeError,
    ):
        return False


__all__ = ("VerifierError", "verify", "verify_parsed")
