"""Corrective TCitH evaluation-point ABI for the Blind-UOV/CAP profile.

Party positions use every nonzero element of the group's polynomial-basis
binary field in integer order, followed by a distinct infinity sentinel.  The
committed secret is evaluated at finite point zero, which is not a party
position.  Infinity is never represented by a field integer.

This module is research-only and not constant-time.  It implements only the
evaluation-domain component, not the complete CAP relation, prover, or
verifier.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final, TypeAlias

from .field import gf_inv, gf_mul
from .parameters import (
    EvaluationDomainGroup,
    FieldId,
    load_profile_manifest,
    validate_profile,
)


class InfinityPoint(str, Enum):
    """The unique non-field evaluation point."""

    INFINITY = "infinity"


@dataclass(frozen=True, slots=True)
class FiniteEvaluationPoint:
    """A nonzero finite party evaluation point in one frozen field."""

    field_id: FieldId
    value: int

    def __post_init__(self) -> None:
        if type(self.field_id) is not FieldId:
            raise TypeError("field_id must be exactly FieldId")
        if self.field_id not in (FieldId.GF_2_11, FieldId.GF_2_12):
            raise ValueError("field_id is not a party-evaluation field")
        if type(self.value) is not int:
            raise TypeError("finite evaluation value must be exactly int")
        bound = 1 << (11 if self.field_id is FieldId.GF_2_11 else 12)
        if not 0 < self.value < bound:
            raise ValueError("finite party evaluation point must be nonzero and canonical")


EvaluationPoint: TypeAlias = FiniteEvaluationPoint | InfinityPoint


@dataclass(frozen=True, slots=True)
class LinearPolynomial:
    """The degree-one polynomial ``mask*X + plain`` over one group field."""

    field_id: FieldId
    mask: int
    plain: int


_PROFILE: Final = load_profile_manifest()
validate_profile(_PROFILE)


def evaluation_group(group_id: int) -> EvaluationDomainGroup:
    """Return one frozen group binding for an exact integer group identifier."""

    if type(group_id) is not int:
        raise TypeError("group_id must be exactly int")
    for group in _PROFILE.evaluation_domain.groups:
        if group.group_id == group_id:
            return group
    raise ValueError("unknown evaluation-domain group")


def _position(group: EvaluationDomainGroup, position: int) -> int:
    if type(position) is not int:
        raise TypeError("position must be exactly int")
    if not 0 <= position < group.party_count:
        raise ValueError("position is outside the canonical party domain")
    return position


def _canonical_tape(field_id: FieldId, tape: int, label: str) -> int:
    if type(tape) is not int:
        raise TypeError(f"{label} must be exactly int")
    # Multiplication by one reuses the field module's closed range checks.
    return gf_mul(field_id, tape, 1)


def evaluation_point(group_id: int, position: int) -> EvaluationPoint:
    """Map a canonical zero-based party position to its distinct point."""

    group = evaluation_group(group_id)
    canonical_position = _position(group, position)
    if canonical_position == group.infinity_position:
        return InfinityPoint.INFINITY
    return FiniteEvaluationPoint(group.field_id, canonical_position + 1)


def canonical_party_domain(group_id: int) -> tuple[EvaluationPoint, ...]:
    """Materialize the immutable, complete party domain for one group."""

    group = evaluation_group(group_id)
    return tuple(evaluation_point(group_id, position) for position in range(group.party_count))


def validate_party_domain(
    group_id: int, points: tuple[EvaluationPoint, ...]
) -> None:
    """Reject any domain mutation, including zero, duplicates, or moved infinity."""

    group = evaluation_group(group_id)
    if type(points) is not tuple:
        raise TypeError("points must be exactly tuple")
    if len(points) != group.party_count:
        raise ValueError("party-domain cardinality does not equal N")
    for position, point in enumerate(points):
        expected = evaluation_point(group_id, position)
        if type(point) is not type(expected) or point != expected:
            raise ValueError("party domain does not match the canonical position mapping")


def reciprocal_coordinate(point: EvaluationPoint) -> int:
    """Return the field-lifting reciprocal coordinate for one party point.

    The infinity result is the frozen coordinate zero.  It is not, and must
    not be interpreted as, a field inverse.
    """

    if type(point) is InfinityPoint:
        if point is not InfinityPoint.INFINITY:
            raise ValueError("unknown infinity sentinel")
        return 0
    if type(point) is FiniteEvaluationPoint:
        return gf_inv(point.field_id, point.value)
    raise TypeError("point must be a finite evaluation point or InfinityPoint")


def commit_tapes(group_id: int, tapes: tuple[int, ...]) -> LinearPolynomial:
    """Commit all party tapes as ``P(X)=mask*X+plain`` in characteristic two."""

    group = evaluation_group(group_id)
    if type(tapes) is not tuple:
        raise TypeError("tapes must be exactly tuple")
    if len(tapes) != group.party_count:
        raise ValueError("tapes must contain exactly N field elements")

    plain = 0
    mask = 0
    for position, tape in enumerate(tapes):
        canonical_tape = _canonical_tape(group.field_id, tape, f"tapes[{position}]")
        plain ^= canonical_tape
        point = evaluation_point(group_id, position)
        if type(point) is FiniteEvaluationPoint:
            mask ^= gf_mul(
                group.field_id, canonical_tape, reciprocal_coordinate(point)
            )
    return LinearPolynomial(group.field_id, mask, plain)


def evaluate_linear_polynomial(
    polynomial: LinearPolynomial, point: EvaluationPoint
) -> int:
    """Evaluate at a finite point, or return the leading coefficient at infinity."""

    if type(polynomial) is not LinearPolynomial:
        raise TypeError("polynomial must be exactly LinearPolynomial")
    mask = _canonical_tape(polynomial.field_id, polynomial.mask, "mask")
    plain = _canonical_tape(polynomial.field_id, polynomial.plain, "plain")
    if type(point) is InfinityPoint:
        if point is not InfinityPoint.INFINITY:
            raise ValueError("unknown infinity sentinel")
        return mask
    if type(point) is not FiniteEvaluationPoint:
        raise TypeError("point must be a finite evaluation point or InfinityPoint")
    if point.field_id is not polynomial.field_id:
        raise ValueError("polynomial and evaluation point fields differ")
    return gf_mul(polynomial.field_id, mask, point.value) ^ plain


def reconstruct_opening_evaluation(
    group_id: int,
    hidden_position: int,
    opened_tapes: tuple[tuple[int, int], ...],
) -> int:
    """Reconstruct ``P(phi(hidden))`` from exactly the other ``N-1`` tapes."""

    group = evaluation_group(group_id)
    hidden = _position(group, hidden_position)
    if type(opened_tapes) is not tuple:
        raise TypeError("opened_tapes must be exactly tuple")
    expected_positions = tuple(
        position for position in range(group.party_count) if position != hidden
    )
    if len(opened_tapes) != len(expected_positions):
        raise ValueError("opening must contain exactly N-1 tapes")

    canonical_openings: list[tuple[int, int]] = []
    for index, (item, expected_position) in enumerate(
        zip(opened_tapes, expected_positions, strict=True)
    ):
        if type(item) is not tuple or len(item) != 2:
            raise TypeError("each opened tape must be exactly a (position, value) tuple")
        position, tape = item
        if type(position) is not int or position != expected_position:
            raise ValueError("opened tape positions must be canonical, ordered, and complete")
        canonical_openings.append(
            (position, _canonical_tape(group.field_id, tape, f"opened_tapes[{index}]") )
        )

    hidden_point = evaluation_point(group_id, hidden)
    result = 0
    if type(hidden_point) is InfinityPoint:
        for position, tape in canonical_openings:
            point = evaluation_point(group_id, position)
            if type(point) is not FiniteEvaluationPoint:
                raise ValueError("infinity-hidden opening contains infinity")
            result ^= gf_mul(group.field_id, tape, reciprocal_coordinate(point))
        return result

    for position, tape in canonical_openings:
        point = evaluation_point(group_id, position)
        coefficient = 1 ^ gf_mul(
            group.field_id,
            hidden_point.value,
            reciprocal_coordinate(point),
        )
        result ^= gf_mul(group.field_id, coefficient, tape)
    return result


__all__ = (
    "EvaluationPoint",
    "FiniteEvaluationPoint",
    "InfinityPoint",
    "LinearPolynomial",
    "canonical_party_domain",
    "commit_tapes",
    "evaluate_linear_polynomial",
    "evaluation_group",
    "evaluation_point",
    "reciprocal_coordinate",
    "reconstruct_opening_evaluation",
    "validate_party_domain",
)
