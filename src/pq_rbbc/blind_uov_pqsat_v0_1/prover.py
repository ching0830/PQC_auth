"""Deterministic research/reference prover for the PQ-SAT Blind-UOV CAP.

The prover consumes all commitment randomness explicitly.  It constructs the
complete one-tree, derives every leaf tape and commitment, applies the shared
relation algebra, and emits the canonical production-shape ``c_r``, ``c_z``,
and ``pi_2`` objects.  It never reads an operating-system randomness source.

This module is intentionally pure Python, not constant-time, and not a
qualified production cryptographic implementation.  In particular, the
separate CAP verifier, proof closure, and production closure are out of scope.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from typing import Final

from .codec import CR, CZ, Pi2, encode_c_r, encode_c_z, encode_pi_2
from .consistency import XiPolynomial, XiPolynomials, encode_xi_polynomials
from .evaluation import LinearPolynomial
from .field import gf_inv
from .parameters import FieldId, load_profile_manifest
from .relation import (
    CAPStatement,
    CAPWitness,
    CorrectionData,
    RepetitionCorrection,
    RepetitionPolynomials,
    apply_delta_z,
    build_consistency_polynomials,
    build_q_and_qbar,
    correct_repetitions,
    derive_r_and_delta_z,
    encode_correction_data,
    relation_holds,
)
from .response import encode_h3_q_and_qbar, encode_tcith_responses
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
    TreeState,
    TreeValidationError,
    canonical_frontier_indices,
    derive_leaf_tape,
    expand_one_tree,
    leaf_commitment,
    open_frontier,
)
from .uov import CPK_BYTES, DENSE_BYTES, M, UOVPublicMap, decode_public_map


class ProverError(ValueError):
    """A controlled, fail-closed deterministic-prover rejection."""


_PROFILE: Final = load_profile_manifest()
_TAU: Final = _PROFILE.tau
_ROOT_SEED_BYTES: Final = _PROFILE.symmetric.seed_bytes
_SALT_BYTES: Final = _PROFILE.symmetric.digest_bytes
_DIGEST_BYTES: Final = _PROFILE.symmetric.digest_bytes
_CTX_BYTES: Final = 32
_R_BYTES: Final = _PROFILE.relation.r_bits // 8
_Z_BYTES: Final = _PROFILE.relation.z_bits // 8
_WITNESS_BITS: Final = _PROFILE.relation.witness_bits
_CONSISTENCY_BITS: Final = _PROFILE.consistency.eta
_CORRECTIONS: Final = _TAU - 1
_CORRECTION_DELTAS_BYTES: Final = (
    _CORRECTIONS * (_WITNESS_BITS + _CONSISTENCY_BITS) // 8
)
_XI_BYTES: Final = 6976
_MAX_U64: Final = (1 << 64) - 1
_STATE_ID_DOMAIN: Final = b"PQSAT-BUOV-CAP-0.1/PROVER-STATE-ID"


def _require_bytes(value: object, length: int, name: str) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{name} must be exact bytes")
    if len(value) != length:
        raise ProverError(f"{name} must be exactly {length} bytes")
    return value


def _require_public_map(public_map: object) -> UOVPublicMap:
    if type(public_map) is not UOVPublicMap:
        raise TypeError("public_map must be exactly UOVPublicMap")
    try:
        _require_bytes(public_map.canonical_cpk, CPK_BYTES, "public_map.canonical_cpk")
        _require_bytes(
            public_map.public_map_digest,
            32,
            "public_map.public_map_digest",
        )
        _require_bytes(
            public_map.dense_coefficients,
            DENSE_BYTES,
            "public_map.dense_coefficients",
        )
    except AttributeError as error:
        raise ProverError("public_map is incomplete") from error
    return public_map


def _require_canonical_public_map(public_map: object) -> UOVPublicMap:
    checked = _require_public_map(public_map)
    try:
        rebuilt = decode_public_map(checked.canonical_cpk)
    except (TypeError, ValueError) as error:
        raise ProverError("public_map cannot be canonically reconstructed") from error
    if rebuilt != checked:
        raise ProverError("public_map does not equal its canonical expansion")
    return checked


@dataclass(frozen=True, slots=True)
class ProverRandomness:
    """All external randomness consumed by :func:`cap_init`."""

    root_seed: bytes
    salt: bytes

    def __post_init__(self) -> None:
        _require_bytes(self.root_seed, _ROOT_SEED_BYTES, "root_seed")
        _require_bytes(self.salt, _SALT_BYTES, "salt")


@dataclass(frozen=True, slots=True, init=False)
class ProverState:
    """Immutable state binding both CAP phases to one explicit issuer map."""

    public_map: UOVPublicMap = field(repr=False)
    ctx: bytes
    r: bytes
    tree_state: TreeState = field(repr=False)
    corrected_repetitions: tuple[RepetitionPolynomials, ...] = field(repr=False)
    corrections: tuple[RepetitionCorrection, ...] = field(repr=False)
    c_r: CR
    h1: bytes
    consistency_points: tuple[int, int, int, int]
    xi_polynomials: XiPolynomials = field(repr=False)
    xi_bytes: bytes = field(repr=False)
    commitments_sha256: bytes
    correction_deltas_sha256: bytes
    _state_identity: bytes = field(repr=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ProverState instances are created only by cap_init")

    @classmethod
    def _create(
        cls,
        *,
        public_map: UOVPublicMap,
        ctx: bytes,
        r: bytes,
        tree_state: TreeState,
        corrected_repetitions: tuple[RepetitionPolynomials, ...],
        corrections: tuple[RepetitionCorrection, ...],
        c_r: CR,
        h1: bytes,
        consistency_points: tuple[int, int, int, int],
        xi_polynomials: XiPolynomials,
        xi_bytes: bytes,
        commitments_sha256: bytes,
        correction_deltas_sha256: bytes,
    ) -> "ProverState":
        instance = object.__new__(cls)
        object.__setattr__(instance, "public_map", public_map)
        object.__setattr__(instance, "ctx", ctx)
        object.__setattr__(instance, "r", r)
        object.__setattr__(instance, "tree_state", tree_state)
        object.__setattr__(
            instance,
            "corrected_repetitions",
            corrected_repetitions,
        )
        object.__setattr__(instance, "corrections", corrections)
        object.__setattr__(instance, "c_r", c_r)
        object.__setattr__(instance, "h1", h1)
        object.__setattr__(instance, "consistency_points", consistency_points)
        object.__setattr__(instance, "xi_polynomials", xi_polynomials)
        object.__setattr__(instance, "xi_bytes", xi_bytes)
        object.__setattr__(instance, "commitments_sha256", commitments_sha256)
        object.__setattr__(
            instance,
            "correction_deltas_sha256",
            correction_deltas_sha256,
        )
        object.__setattr__(instance, "_state_identity", bytes(_DIGEST_BYTES))
        identity = _compute_state_identity(instance)
        object.__setattr__(instance, "_state_identity", identity)
        return instance


def _group_parameters(repetition: int) -> tuple[int, FieldId, int, int]:
    if type(repetition) is not int:
        raise TypeError("repetition must be exactly int")
    if not 0 <= repetition < _TAU:
        raise ProverError("repetition must be in range 0..17")
    if repetition < 2:
        return 0, FieldId.GF_2_12, 4096, 16
    return 1, FieldId.GF_2_11, 2048, 18


def _reciprocal_coordinates(field_id: FieldId, party_count: int) -> tuple[int, ...]:
    """Return finite reciprocals followed by the infinity coordinate zero."""

    return tuple(gf_inv(field_id, position + 1) for position in range(party_count - 1)) + (0,)


def _linear_polynomials_from_accumulators(
    field_id: FieldId,
    coordinate_count: int,
    plain_accumulator: int,
    mask_planes: tuple[int, ...],
) -> tuple[LinearPolynomial, ...]:
    return tuple(
        LinearPolynomial(
            field_id,
            sum(
                ((plane >> coordinate) & 1) << coefficient_bit
                for coefficient_bit, plane in enumerate(mask_planes)
            ),
            (plain_accumulator >> coordinate) & 1,
        )
        for coordinate in range(coordinate_count)
    )


def _build_repetition_polynomials(
    tree_state: TreeState,
    repetition: int,
    reciprocals: tuple[int, ...],
) -> RepetitionPolynomials:
    """Accumulate all leaf tapes without a party-by-coordinate matrix."""

    _group_id, field_id, party_count, rho = _group_parameters(repetition)
    if type(reciprocals) is not tuple or len(reciprocals) != party_count:
        raise ProverError("reciprocal coordinate table has the wrong shape")
    mu = 12 if field_id is FieldId.GF_2_12 else 11
    coordinate_count = _WITNESS_BITS + rho + _CONSISTENCY_BITS
    plain_accumulator = 0
    mask_planes = [0] * mu

    for position, reciprocal in enumerate(reciprocals):
        tape = derive_leaf_tape(
            repetition,
            position,
            tree_state.leaf_seed(repetition, position),
            tree_state.salt,
        )
        tape_value = int.from_bytes(tape.encoded, "little")
        if tape_value >= 1 << coordinate_count:
            raise AssertionError("unreachable noncanonical leaf tape")
        plain_accumulator ^= tape_value

        coefficient = reciprocal
        coefficient_bit = 0
        while coefficient:
            if coefficient & 1:
                mask_planes[coefficient_bit] ^= tape_value
            coefficient >>= 1
            coefficient_bit += 1

    polynomials = _linear_polynomials_from_accumulators(
        field_id,
        coordinate_count,
        plain_accumulator,
        tuple(mask_planes),
    )
    witness_end = _WITNESS_BITS
    relation_end = witness_end + rho
    return RepetitionPolynomials(
        witness_polynomials=polynomials[:witness_end],
        relation_masks=polynomials[witness_end:relation_end],
        consistency_masks=polynomials[relation_end:],
    )


def _correction_deltas(
    corrections: tuple[RepetitionCorrection, ...],
) -> bytes:
    if type(corrections) is not tuple:
        raise TypeError("corrections must be an exact tuple")
    if len(corrections) != _CORRECTIONS:
        raise ProverError("corrections must contain exactly 17 entries")
    pieces: list[bytes] = []
    for index, correction in enumerate(corrections):
        if type(correction) is not RepetitionCorrection:
            raise TypeError(f"corrections[{index}] must be RepetitionCorrection")
        pieces.append(_require_bytes(correction.delta_p, 256, "delta_p"))
        pieces.append(_require_bytes(correction.delta_mhat, 32, "delta_mhat"))
    encoded = b"".join(pieces)
    if len(encoded) != _CORRECTION_DELTAS_BYTES:
        raise AssertionError("unreachable correction-delta length")
    return encoded


def _plain_witness_bytes(repetition: RepetitionPolynomials) -> bytes:
    if type(repetition) is not RepetitionPolynomials:
        raise TypeError("repetition must be exactly RepetitionPolynomials")
    if type(repetition.witness_polynomials) is not tuple:
        raise TypeError("witness_polynomials must be an exact tuple")
    if len(repetition.witness_polynomials) != _WITNESS_BITS:
        raise ProverError("witness_polynomials have the wrong shape")
    output = bytearray(_WITNESS_BITS // 8)
    for index, polynomial in enumerate(repetition.witness_polynomials):
        if type(polynomial) is not LinearPolynomial:
            raise TypeError(f"witness_polynomials[{index}] has the wrong type")
        if polynomial.plain not in (0, 1):
            raise ProverError("witness-polynomial constants must be base-field bits")
        output[index // 8] |= polynomial.plain << (index % 8)
    return bytes(output)


def _update_polynomial_identity(
    digest: "hashlib._Hash",
    repetition: RepetitionPolynomials,
    repetition_index: int,
) -> None:
    _group_id, expected_field, _party_count, rho = _group_parameters(repetition_index)
    if type(repetition) is not RepetitionPolynomials:
        raise TypeError(f"corrected_repetitions[{repetition_index}] has the wrong type")
    families = (
        (repetition.witness_polynomials, _WITNESS_BITS, b"P"),
        (repetition.relation_masks, rho, b"M"),
        (repetition.consistency_masks, _CONSISTENCY_BITS, b"H"),
    )
    digest.update(bytes((repetition_index,)))
    digest.update(expected_field.value.encode("ascii"))
    upper_bound = 1 << (12 if expected_field is FieldId.GF_2_12 else 11)
    for family, expected_length, label in families:
        if type(family) is not tuple:
            raise TypeError("polynomial family must be an exact tuple")
        if len(family) != expected_length:
            raise ProverError("polynomial family has the wrong shape")
        digest.update(label)
        for index, polynomial in enumerate(family):
            if type(polynomial) is not LinearPolynomial:
                raise TypeError(f"polynomial {index} has the wrong type")
            if type(polynomial.field_id) is not FieldId or polynomial.field_id is not expected_field:
                raise ProverError("polynomial has the wrong field")
            if type(polynomial.mask) is not int or type(polynomial.plain) is not int:
                raise TypeError("polynomial coefficients must be exact integers")
            if not 0 <= polynomial.mask < upper_bound:
                raise ProverError("polynomial mask is outside the field")
            if not 0 <= polynomial.plain < upper_bound:
                raise ProverError("polynomial constant is outside the field")
            digest.update(polynomial.mask.to_bytes(2, "little"))
            digest.update(polynomial.plain.to_bytes(2, "little"))


def _compute_state_identity(state: ProverState) -> bytes:
    digest = hashlib.sha256(_STATE_ID_DOMAIN)
    public_map = _require_public_map(state.public_map)
    digest.update(public_map.canonical_cpk)
    digest.update(public_map.public_map_digest)
    digest.update(public_map.dense_coefficients)
    digest.update(_require_bytes(state.ctx, _CTX_BYTES, "state.ctx"))
    digest.update(_require_bytes(state.r, _R_BYTES, "state.r"))

    if type(state.tree_state) is not TreeState:
        raise TypeError("state.tree_state must be exactly TreeState")
    tree = state.tree_state
    digest.update(_require_bytes(tree.salt, _SALT_BYTES, "tree_state.salt"))
    if type(tree.node_seeds) is not tuple:
        raise TypeError("tree_state.node_seeds must be an exact tuple")
    if len(tree.node_seeds) != _PROFILE.one_tree.total_nodes:
        raise ProverError("tree_state has the wrong node count")
    for index, seed in enumerate(tree.node_seeds):
        digest.update(_require_bytes(seed, _ROOT_SEED_BYTES, f"node_seeds[{index}]"))

    if type(state.corrected_repetitions) is not tuple:
        raise TypeError("corrected_repetitions must be an exact tuple")
    if len(state.corrected_repetitions) != _TAU:
        raise ProverError("corrected_repetitions must contain exactly 18 entries")
    for index, repetition in enumerate(state.corrected_repetitions):
        _update_polynomial_identity(digest, repetition, index)

    correction_deltas = _correction_deltas(state.corrections)
    digest.update(correction_deltas)
    if type(state.c_r) is not CR:
        raise TypeError("state.c_r must be exactly CR")
    digest.update(encode_c_r(state.c_r))
    digest.update(_require_bytes(state.h1, _DIGEST_BYTES, "state.h1"))

    if type(state.consistency_points) is not tuple or len(state.consistency_points) != 4:
        raise ProverError("consistency_points must contain exactly four values")
    for index, point in enumerate(state.consistency_points):
        if type(point) is not int:
            raise TypeError(f"consistency_points[{index}] must be exactly int")
        if not 0 <= point < 1 << 64:
            raise ProverError("consistency point is outside GF(2^64)")
        digest.update(point.to_bytes(8, "little"))

    encoded_xi = encode_xi_polynomials(state.xi_polynomials)
    if state.xi_bytes != encoded_xi:
        raise ProverError("state xi bytes do not match the xi polynomials")
    digest.update(_require_bytes(state.xi_bytes, _XI_BYTES, "state.xi_bytes"))
    digest.update(
        _require_bytes(
            state.commitments_sha256,
            32,
            "state.commitments_sha256",
        )
    )
    digest.update(
        _require_bytes(
            state.correction_deltas_sha256,
            32,
            "state.correction_deltas_sha256",
        )
    )
    return digest.digest()


def _validate_state(value: object) -> ProverState:
    if type(value) is not ProverState:
        raise TypeError("state must be exactly ProverState")
    try:
        observed_identity = _compute_state_identity(value)
        expected_identity = _require_bytes(
            value._state_identity,
            32,
            "state._state_identity",
        )
        if observed_identity != expected_identity:
            raise ProverError("prover state identity mismatch")
        if value.tree_state.salt != value.c_r.salt:
            raise ProverError("tree salt does not match c_r")
        if value.consistency_points != derive_consistency_points(value.h1):
            raise ProverError("consistency-point identity mismatch")
        if value.c_r.h2_prime != derive_h2_prime(value.h1, value.xi_bytes):
            raise ProverError("h2_prime identity mismatch")
        if not value.xi_polynomials:
            raise ProverError("xi polynomial set is empty")
        correction_data = encode_correction_data(
            CorrectionData(value.xi_polynomials[0].constant, value.corrections)
        )
        if value.c_r.correction_data != correction_data:
            raise ProverError("correction-data identity mismatch")
        correction_deltas = _correction_deltas(value.corrections)
        if hashlib.sha256(correction_deltas).digest() != value.correction_deltas_sha256:
            raise ProverError("correction-delta identity mismatch")
        if _plain_witness_bytes(value.corrected_repetitions[0])[:_R_BYTES] != value.r:
            raise ProverError("state r does not match corrected repetition zero")
    except ProverError:
        raise
    except (AttributeError, TypeError, ValueError) as error:
        raise ProverError("invalid or mutated prover state") from error
    return value


def cap_init(
    public_map: UOVPublicMap,
    ctx: bytes,
    randomness: ProverRandomness,
) -> tuple[bytes, CR, ProverState]:
    """Create ``c_r`` and all immutable state needed by the append phase."""

    checked_map = _require_canonical_public_map(public_map)
    checked_ctx = _require_bytes(ctx, _CTX_BYTES, "ctx")
    if type(randomness) is not ProverRandomness:
        raise TypeError("randomness must be exactly ProverRandomness")
    root_seed = _require_bytes(randomness.root_seed, _ROOT_SEED_BYTES, "root_seed")
    salt = _require_bytes(randomness.salt, _SALT_BYTES, "salt")

    tree_state = expand_one_tree(root_seed, salt)
    reciprocal_tables = {
        0: _reciprocal_coordinates(FieldId.GF_2_12, 4096),
        1: _reciprocal_coordinates(FieldId.GF_2_11, 2048),
    }
    uncorrected = tuple(
        _build_repetition_polynomials(
            tree_state,
            repetition,
            reciprocal_tables[0 if repetition < 2 else 1],
        )
        for repetition in range(_TAU)
    )
    corrected, corrections = correct_repetitions(uncorrected)
    correction_deltas = _correction_deltas(corrections)

    commitments = tree_state.transcript_commitments()
    expected_commitments_bytes = (
        _PROFILE.one_tree.active_leaves * _PROFILE.symmetric.digest_bytes
    )
    if len(commitments) != expected_commitments_bytes:
        raise AssertionError("unreachable commitment transcript length")
    h1 = derive_h1(checked_ctx, salt, commitments, correction_deltas)
    points = derive_consistency_points(h1)
    xi = build_consistency_polynomials(corrected, points)
    xi_bytes = encode_xi_polynomials(xi)
    h2_prime = derive_h2_prime(h1, xi_bytes)
    correction_data = encode_correction_data(CorrectionData(xi[0].constant, corrections))
    c_r = CR(salt=salt, h2_prime=h2_prime, correction_data=correction_data)
    encode_c_r(c_r)

    witness_zero = _plain_witness_bytes(corrected[0])
    r = witness_zero[:_R_BYTES]
    state = ProverState._create(
        public_map=checked_map,
        ctx=checked_ctx,
        r=r,
        tree_state=tree_state,
        corrected_repetitions=corrected,
        corrections=corrections,
        c_r=c_r,
        h1=h1,
        consistency_points=points,
        xi_polynomials=xi,
        xi_bytes=xi_bytes,
        commitments_sha256=hashlib.sha256(commitments).digest(),
        correction_deltas_sha256=hashlib.sha256(correction_deltas).digest(),
    )
    return r, c_r, state


def cap_append(state: ProverState, z: bytes) -> CZ:
    """Append one exact UOV preimage without placing ``z`` on the wire."""

    checked_state = _validate_state(state)
    checked_z = _require_bytes(z, _Z_BYTES, "z")
    derived_r, delta_z = derive_r_and_delta_z(
        checked_state.corrected_repetitions[0],
        checked_z,
    )
    if derived_r != checked_state.r:
        raise ProverError("derived r does not match the committed prover state")
    c_z = CZ(delta_z=delta_z)
    encode_c_z(c_z)
    return c_z


def find_first_admissible_nonce(
    h3: bytes,
) -> tuple[int, tuple[int, ...], tuple[int, ...]]:
    """Return the first u64 nonce passing PoW, finite challenge, and frontier."""

    checked_h3 = _require_bytes(h3, _DIGEST_BYTES, "h3")
    for nonce in range(_MAX_U64 + 1):
        if not explicit_pow_passes(checked_h3, nonce):
            continue
        hidden_positions = derive_hidden_positions(checked_h3, nonce)
        if not hidden_positions_are_admissible(hidden_positions):
            continue
        try:
            frontier_indices = canonical_frontier_indices(hidden_positions)
        except TreeValidationError:
            continue
        if len(frontier_indices) > _PROFILE.opened_seed_upper_bound_topen:
            continue
        return nonce, hidden_positions, frontier_indices
    raise ProverError("the u64 nonce space contains no admissible transcript")


def prove(
    ctx: bytes,
    u: bytes,
    c_r: CR,
    c_z: CZ,
    state: ProverState,
) -> Pi2:
    """Produce one deterministic, canonical, unpadded real CAP ``pi_2``."""

    checked_ctx = _require_bytes(ctx, _CTX_BYTES, "ctx")
    checked_u = _require_bytes(u, M, "u")
    if type(c_r) is not CR:
        raise TypeError("c_r must be exactly CR")
    if type(c_z) is not CZ:
        raise TypeError("c_z must be exactly CZ")
    try:
        encode_c_r(c_r)
        encode_c_z(c_z)
    except (TypeError, ValueError) as error:
        raise ProverError("invalid c_r or c_z") from error
    checked_state = _validate_state(state)
    if checked_ctx != checked_state.ctx:
        raise ProverError("ctx does not match the prover state")
    if c_r != checked_state.c_r:
        raise ProverError("c_r does not match the prover state")

    updated_repetitions = tuple(
        apply_delta_z(repetition, c_z.delta_z)
        for repetition in checked_state.corrected_repetitions
    )
    committed_random_witness = _plain_witness_bytes(
        checked_state.corrected_repetitions[0]
    )
    derived_r = committed_random_witness[:_R_BYTES]
    random_z = committed_random_witness[_R_BYTES:]
    z = bytes(
        left ^ right
        for left, right in zip(random_z, c_z.delta_z, strict=True)
    )
    if derived_r != checked_state.r:
        raise ProverError("reconstructed r does not match the prover state")
    statement = CAPStatement(checked_state.public_map, checked_ctx, checked_u)
    witness = CAPWitness(checked_state.r, z)
    if not relation_holds(statement, witness):
        raise ProverError("reconstructed CAP witness does not satisfy the relation")

    h2 = derive_h2(checked_ctx, checked_u, c_r.h2_prime, c_z.delta_z)
    gammas_0 = derive_gammas(h2, 0)
    gammas_1 = derive_gammas(h2, 1)
    q_results = tuple(
        build_q_and_qbar(
            statement,
            repetition,
            gammas_0 if index < 2 else gammas_1,
        )
        for index, repetition in enumerate(updated_repetitions)
    )
    q_groups = (
        tuple(element for result in q_results[:2] for element in result.q),
        tuple(element for result in q_results[2:] for element in result.q),
    )
    qbar_groups = (
        tuple(element for result in q_results[:2] for element in result.qbar),
        tuple(element for result in q_results[2:] for element in result.qbar),
    )
    q_and_qbar = encode_h3_q_and_qbar(q_groups, qbar_groups)
    h3 = derive_h3(checked_ctx, checked_u, h2, q_and_qbar)
    nonce, hidden_positions, frontier_indices = find_first_admissible_nonce(h3)
    opening = open_frontier(checked_state.tree_state, hidden_positions)
    if len(opening.seeds) != len(frontier_indices):
        raise AssertionError("unreachable frontier-opening mismatch")
    hidden_commitments = tuple(
        leaf_commitment(
            repetition,
            position,
            checked_state.tree_state.leaf_seed(repetition, position),
            checked_state.tree_state.salt,
        )
        for repetition, position in enumerate(hidden_positions)
    )
    tcith_responses = encode_tcith_responses(qbar_groups)
    pi_2 = Pi2(
        h3=h3,
        pow_nonce=nonce,
        opening=opening,
        hidden_leaf_commitments=hidden_commitments,
        tcith_responses=tcith_responses,
    )
    encode_pi_2(pi_2)
    return pi_2


__all__ = (
    "ProverError",
    "ProverRandomness",
    "ProverState",
    "cap_append",
    "cap_init",
    "find_first_admissible_nonce",
    "prove",
)
