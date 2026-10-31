"""Concrete one-tree and leaf material for the PQ-SAT Blind-UOV CAP profile.

The implementation consumes the frozen parameters and canonical transcript
APIs.  It builds exactly the 40,960 active leaves of the non-power-of-two heap;
there are no inactive leaves and no padding nodes.  An :class:`Opening` carries
only frontier seeds.  Node indices are recomputed from the 18 hidden positions
and are never represented as opening data.

Tree reconstruction establishes topology, coverage, and canonical ordering.
It cannot authenticate arbitrary 24-byte frontier seeds.  A later CAP verifier
must compare the reconstructed commitment transcript through ``h1``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .parameters import load_profile_manifest
from .transcript import shake


class TreeValidationError(ValueError):
    """A controlled rejection of invalid or noncanonical tree data."""


_PROFILE: Final = load_profile_manifest()
_FINGERPRINT: Final = _PROFILE.fingerprint
_DOMAIN_SEED_DERIVE: Final = _PROFILE.symmetric.domain("seed_derivation")
_DOMAIN_TAPE_EXPAND: Final = _PROFILE.symmetric.domain("tape_expansion")
_DOMAIN_LEAF_COMMIT: Final = _PROFILE.symmetric.domain("leaf_commitment")

_TAU: Final = _PROFILE.tau
_ACTIVE_LEAVES: Final = _PROFILE.one_tree.active_leaves
_TOTAL_NODES: Final = _PROFILE.one_tree.total_nodes
_LEAF_BASE: Final = _PROFILE.one_tree.leaf_base_index
_LAST_NODE: Final = _PROFILE.one_tree.node_index_last
_FRONTIER_MINIMUM: Final = _PROFILE.one_tree.frontier_count_minimum
_FRONTIER_MAXIMUM: Final = _PROFILE.one_tree.frontier_count_maximum
_SEED_BYTES: Final = _PROFILE.symmetric.seed_bytes
_SALT_BYTES: Final = _PROFILE.symmetric.digest_bytes
_COMMITMENT_BYTES: Final = _PROFILE.symmetric.digest_bytes
_P_BITS: Final = _PROFILE.relation.witness_bits
_MHAT_BITS: Final = _PROFILE.consistency.eta
_LONG_REPETITIONS: Final = frozenset(_PROFILE.tree_groups[0].repetition_indices)


def _require_exact_int(value: object, name: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{name} must be an exact int and bool is forbidden")
    return value


def _require_exact_bytes(value: object, name: str, length: int) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{name} must be exact bytes")
    if len(value) != length:
        raise TreeValidationError(f"{name} must be exactly {length} bytes")
    return value


def _u16be(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _u32be(value: int) -> bytes:
    return value.to_bytes(4, "big")


def _position_count(repetition: int) -> int:
    return 4096 if repetition in _LONG_REPETITIONS else 2048


def _validate_logical(repetition: object, position: object) -> tuple[int, int]:
    checked_repetition = _require_exact_int(repetition, "repetition")
    checked_position = _require_exact_int(position, "position")
    if not 0 <= checked_repetition < _TAU:
        raise TreeValidationError("repetition must be in range 0..17")
    if not 0 <= checked_position < _position_count(checked_repetition):
        raise TreeValidationError("position is outside the repetition leaf range")
    return checked_repetition, checked_position


def logical_to_unified(repetition: int, position: int) -> int:
    """Map one canonical logical leaf to the position-major unified index."""

    checked_repetition, checked_position = _validate_logical(repetition, position)
    if checked_position < 2048:
        return 18 * checked_position + checked_repetition
    # Only repetitions 0 and 1 reach this branch because validation used the
    # frozen group leaf counts.
    return 36864 + 2 * (checked_position - 2048) + checked_repetition


def unified_to_logical(index: int) -> tuple[int, int]:
    """Invert :func:`logical_to_unified` for exactly one active leaf."""

    checked_index = _require_exact_int(index, "index")
    if not 0 <= checked_index < _ACTIVE_LEAVES:
        raise TreeValidationError("unified index must be in range 0..40959")
    if checked_index < 36864:
        return checked_index % 18, checked_index // 18
    offset = checked_index - 36864
    return offset % 2, 2048 + offset // 2


def _derive_children(parent_seed: bytes, salt: bytes, node_index: int) -> tuple[bytes, bytes]:
    checked_seed = _require_exact_bytes(parent_seed, "parent_seed", _SEED_BYTES)
    checked_salt = _require_exact_bytes(salt, "salt", _SALT_BYTES)
    checked_index = _require_exact_int(node_index, "node_index")
    if not 0 <= checked_index < _LEAF_BASE:
        raise TreeValidationError("node_index is not an internal node")
    output = shake(
        _DOMAIN_SEED_DERIVE,
        (_FINGERPRINT, checked_salt, _u32be(checked_index), checked_seed),
        2 * _SEED_BYTES,
    )
    return output[:_SEED_BYTES], output[_SEED_BYTES:]


def _extract_lsb_bits(encoded: bytes, start: int, count: int) -> bytes:
    value = (int.from_bytes(encoded, "little") >> start) & ((1 << count) - 1)
    return value.to_bytes((count + 7) // 8, "little")


def _pack_tape_parts(
    p_plain: bytes,
    m_plain: bytes,
    m_plain_bits: int,
    mhat_plain: bytes,
) -> bytes:
    total_bits = _P_BITS + m_plain_bits + _MHAT_BITS
    value = int.from_bytes(p_plain, "little")
    value |= int.from_bytes(m_plain, "little") << _P_BITS
    value |= int.from_bytes(mhat_plain, "little") << (_P_BITS + m_plain_bits)
    return value.to_bytes((total_bits + 7) // 8, "little")


@dataclass(frozen=True, slots=True)
class LeafTape:
    """Canonical LSB-first tape and its three independently addressable slices."""

    encoded: bytes
    p_plain: bytes
    m_plain: bytes
    mhat_plain: bytes
    m_plain_bits: int

    def __post_init__(self) -> None:
        checked_bits = _require_exact_int(self.m_plain_bits, "m_plain_bits")
        if checked_bits not in (16, 18):
            raise TreeValidationError("m_plain_bits must be 16 or 18")
        _require_exact_bytes(self.p_plain, "p_plain", _P_BITS // 8)
        _require_exact_bytes(
            self.m_plain, "m_plain", (checked_bits + 7) // 8
        )
        _require_exact_bytes(self.mhat_plain, "mhat_plain", _MHAT_BITS // 8)
        total_bits = _P_BITS + checked_bits + _MHAT_BITS
        _require_exact_bytes(self.encoded, "encoded", (total_bits + 7) // 8)
        if int.from_bytes(self.m_plain, "little") >= 1 << checked_bits:
            raise TreeValidationError("m_plain has nonzero unused high bits")
        if int.from_bytes(self.encoded, "little") >= 1 << total_bits:
            raise TreeValidationError("encoded tape has nonzero unused high bits")
        if self.encoded != _pack_tape_parts(
            self.p_plain, self.m_plain, checked_bits, self.mhat_plain
        ):
            raise TreeValidationError("encoded tape does not match its bit partitions")

    @property
    def P_plain(self) -> bytes:
        """Protocol-spelling alias for the 2,048-bit ``P_plain`` slice."""

        return self.p_plain

    @property
    def M_plain(self) -> bytes:
        """Protocol-spelling alias for the 16- or 18-bit ``M_plain`` slice."""

        return self.m_plain

    @property
    def Mhat_plain(self) -> bytes:
        """Protocol-spelling alias for the 256-bit ``Mhat_plain`` slice."""

        return self.mhat_plain

    @property
    def total_bits(self) -> int:
        return _P_BITS + self.m_plain_bits + _MHAT_BITS


def derive_leaf_tape(
    repetition: int,
    position: int,
    leaf_seed: bytes,
    salt: bytes,
) -> LeafTape:
    """Expand one leaf seed and split the non-byte-aligned LSB-first tape."""

    checked_repetition, checked_position = _validate_logical(repetition, position)
    checked_seed = _require_exact_bytes(leaf_seed, "leaf_seed", _SEED_BYTES)
    checked_salt = _require_exact_bytes(salt, "salt", _SALT_BYTES)
    m_bits = 16 if checked_repetition in _LONG_REPETITIONS else 18
    total_bits = _P_BITS + m_bits + _MHAT_BITS
    raw = shake(
        _DOMAIN_TAPE_EXPAND,
        (
            _FINGERPRINT,
            checked_salt,
            _u16be(checked_repetition),
            _u16be(checked_position),
            checked_seed,
        ),
        (total_bits + 7) // 8,
    )
    # SHAKE emits complete bytes.  Masking converts the partial final byte to
    # the unique canonical encoding without byte-aligning the 18-bit M slice.
    encoded = (int.from_bytes(raw, "little") & ((1 << total_bits) - 1)).to_bytes(
        (total_bits + 7) // 8, "little"
    )
    return LeafTape(
        encoded=encoded,
        p_plain=_extract_lsb_bits(encoded, 0, _P_BITS),
        m_plain=_extract_lsb_bits(encoded, _P_BITS, m_bits),
        mhat_plain=_extract_lsb_bits(encoded, _P_BITS + m_bits, _MHAT_BITS),
        m_plain_bits=m_bits,
    )


def leaf_commitment(
    repetition: int,
    position: int,
    leaf_seed: bytes,
    salt: bytes,
) -> bytes:
    """Commit to one canonical logical leaf with the frozen transcript API."""

    checked_repetition, checked_position = _validate_logical(repetition, position)
    checked_seed = _require_exact_bytes(leaf_seed, "leaf_seed", _SEED_BYTES)
    checked_salt = _require_exact_bytes(salt, "salt", _SALT_BYTES)
    return shake(
        _DOMAIN_LEAF_COMMIT,
        (
            _FINGERPRINT,
            checked_salt,
            _u16be(checked_repetition),
            _u16be(checked_position),
            checked_seed,
        ),
        _COMMITMENT_BYTES,
    )


@dataclass(frozen=True, slots=True)
class TreeState:
    """All 81,919 immutable node seeds for one exact non-padded tree."""

    salt: bytes
    node_seeds: tuple[bytes, ...]

    def __post_init__(self) -> None:
        _require_exact_bytes(self.salt, "salt", _SALT_BYTES)
        if type(self.node_seeds) is not tuple:
            raise TypeError("node_seeds must be an exact tuple")
        if len(self.node_seeds) != _TOTAL_NODES:
            raise TreeValidationError(
                f"node_seeds must contain exactly {_TOTAL_NODES} seeds"
            )
        for index, seed in enumerate(self.node_seeds):
            _require_exact_bytes(seed, f"node_seeds[{index}]", _SEED_BYTES)

    @property
    def root_seed(self) -> bytes:
        return self.node_seeds[0]

    def leaf_seed(self, repetition: int, position: int) -> bytes:
        unified = logical_to_unified(repetition, position)
        return self.node_seeds[_LEAF_BASE + unified]

    def commitments_in_transcript_order(self) -> tuple[bytes, ...]:
        """Return commitments ordered by repetition, then logical position."""

        return tuple(
            leaf_commitment(
                repetition,
                position,
                self.leaf_seed(repetition, position),
                self.salt,
            )
            for repetition in range(_TAU)
            for position in range(_position_count(repetition))
        )

    def transcript_commitments(self) -> bytes:
        """Return the exact 40,960-by-48-byte ``h1`` commitment input."""

        encoded = b"".join(self.commitments_in_transcript_order())
        if len(encoded) != _ACTIVE_LEAVES * _COMMITMENT_BYTES:
            raise AssertionError("unreachable commitment transcript length")
        return encoded


def expand_one_tree(root_seed: bytes, salt: bytes) -> TreeState:
    """Expand exactly 40,959 internal nodes into the 81,919-node heap."""

    checked_root = _require_exact_bytes(root_seed, "root_seed", _SEED_BYTES)
    checked_salt = _require_exact_bytes(salt, "salt", _SALT_BYTES)
    nodes: list[bytes | None] = [None] * _TOTAL_NODES
    nodes[0] = checked_root
    for node_index in range(_LEAF_BASE):
        parent = nodes[node_index]
        if parent is None:
            raise AssertionError("unreachable missing parent seed")
        left_seed, right_seed = _derive_children(parent, checked_salt, node_index)
        nodes[2 * node_index + 1] = left_seed
        nodes[2 * node_index + 2] = right_seed
    if any(seed is None for seed in nodes):
        raise AssertionError("unreachable incomplete tree")
    return TreeState(checked_salt, tuple(nodes))  # type: ignore[arg-type]


def _validate_hidden_positions(hidden_positions: object) -> tuple[int, ...]:
    if type(hidden_positions) is not tuple:
        raise TypeError("hidden_positions must be an exact tuple")
    if len(hidden_positions) != _TAU:
        raise TreeValidationError("hidden_positions must contain exactly 18 values")
    checked: list[int] = []
    unified: set[int] = set()
    for repetition, position in enumerate(hidden_positions):
        checked_repetition, checked_position = _validate_logical(repetition, position)
        checked.append(checked_position)
        unified.add(logical_to_unified(checked_repetition, checked_position))
    if len(unified) != _TAU:
        raise TreeValidationError("hidden leaves must map to 18 distinct leaves")
    return tuple(checked)


def _frontier_without_bound(hidden_positions: tuple[int, ...]) -> tuple[int, ...]:
    hidden_nodes = {
        _LEAF_BASE + logical_to_unified(repetition, position)
        for repetition, position in enumerate(hidden_positions)
    }
    blocked = set(hidden_nodes)
    for hidden_node in hidden_nodes:
        node = hidden_node
        while node:
            node = (node - 1) // 2
            blocked.add(node)

    frontier: list[int] = []
    stack = [0]
    while stack:
        node = stack.pop()
        if node not in blocked:
            frontier.append(node)
        elif node < _LEAF_BASE:
            # Push right first so the left child is visited first.  Final sort
            # is still mandatory because heap index, not DFS order, is wire
            # semantics.
            stack.append(2 * node + 2)
            stack.append(2 * node + 1)
    return tuple(sorted(frontier))


def canonical_frontier_indices(
    hidden_positions: tuple[int, ...],
) -> tuple[int, ...]:
    """Return the unique maximal-subtree frontier in increasing heap order."""

    checked_hidden = _validate_hidden_positions(hidden_positions)
    frontier = _frontier_without_bound(checked_hidden)
    if not _FRONTIER_MINIMUM <= len(frontier) <= _FRONTIER_MAXIMUM:
        raise TreeValidationError(
            "canonical frontier count is outside the accepted range 13..174"
        )
    if any(not 0 <= index <= _LAST_NODE for index in frontier):
        raise AssertionError("unreachable frontier node")
    return frontier


@dataclass(frozen=True, slots=True)
class Opening:
    """Wire-semantic opening: frontier seeds only, with no node indices."""

    seeds: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if type(self.seeds) is not tuple:
            raise TypeError("seeds must be an exact tuple")
        if not _FRONTIER_MINIMUM <= len(self.seeds) <= _FRONTIER_MAXIMUM:
            raise TreeValidationError("opening seed count must be in range 13..174")
        for index, seed in enumerate(self.seeds):
            _require_exact_bytes(seed, f"seeds[{index}]", _SEED_BYTES)


def open_frontier(
    state: TreeState,
    hidden_positions: tuple[int, ...],
) -> Opening:
    """Select seeds using verifier-recomputable canonical frontier indices."""

    if type(state) is not TreeState:
        raise TypeError("state must be an exact TreeState")
    indices = canonical_frontier_indices(hidden_positions)
    return Opening(tuple(state.node_seeds[index] for index in indices))


@dataclass(frozen=True, slots=True)
class VerifiedLeaves:
    """Reconstructed non-hidden seeds and commitments with explicit holes."""

    salt: bytes
    hidden_positions: tuple[int, ...]
    leaf_seeds_by_unified: tuple[bytes | None, ...]
    transcript_order_commitments: tuple[bytes | None, ...]

    def __post_init__(self) -> None:
        _require_exact_bytes(self.salt, "salt", _SALT_BYTES)
        checked_hidden = _validate_hidden_positions(self.hidden_positions)
        if checked_hidden != self.hidden_positions:
            raise TreeValidationError("hidden_positions are not canonical")
        if type(self.leaf_seeds_by_unified) is not tuple:
            raise TypeError("leaf_seeds_by_unified must be an exact tuple")
        if len(self.leaf_seeds_by_unified) != _ACTIVE_LEAVES:
            raise TreeValidationError("wrong unified leaf-seed count")
        expected_hidden_unified = {
            logical_to_unified(repetition, position)
            for repetition, position in enumerate(checked_hidden)
        }
        for index, seed in enumerate(self.leaf_seeds_by_unified):
            if index in expected_hidden_unified:
                if seed is not None:
                    raise TreeValidationError("hidden leaf seed was reconstructed")
            else:
                _require_exact_bytes(seed, f"leaf_seeds_by_unified[{index}]", _SEED_BYTES)

        if type(self.transcript_order_commitments) is not tuple:
            raise TypeError("transcript_order_commitments must be an exact tuple")
        if len(self.transcript_order_commitments) != _ACTIVE_LEAVES:
            raise TreeValidationError("wrong transcript commitment count")
        offset = 0
        for repetition in range(_TAU):
            for position in range(_position_count(repetition)):
                commitment = self.transcript_order_commitments[offset]
                if position == checked_hidden[repetition]:
                    if commitment is not None:
                        raise TreeValidationError("hidden commitment slot is not empty")
                else:
                    _require_exact_bytes(
                        commitment,
                        f"transcript_order_commitments[{offset}]",
                        _COMMITMENT_BYTES,
                    )
                offset += 1

    @property
    def opened_leaf_count(self) -> int:
        return _ACTIVE_LEAVES - _TAU

    def leaf_seed(self, repetition: int, position: int) -> bytes:
        unified = logical_to_unified(repetition, position)
        seed = self.leaf_seeds_by_unified[unified]
        if seed is None:
            raise TreeValidationError("hidden leaf seed is unavailable")
        return seed

    def leaf_tape(self, repetition: int, position: int) -> LeafTape:
        return derive_leaf_tape(
            repetition, position, self.leaf_seed(repetition, position), self.salt
        )

    def opened_commitment(self, repetition: int, position: int) -> bytes:
        checked_repetition, checked_position = _validate_logical(repetition, position)
        if checked_position == self.hidden_positions[checked_repetition]:
            raise TreeValidationError("hidden leaf commitment is unavailable")
        offset = sum(_position_count(item) for item in range(checked_repetition))
        commitment = self.transcript_order_commitments[offset + checked_position]
        if commitment is None:
            raise AssertionError("unreachable missing opened commitment")
        return commitment

    def transcript_commitments(
        self, hidden_commitments: tuple[bytes, ...]
    ) -> bytes:
        """Merge 18 externally supplied hidden commitments in transcript order."""

        if type(hidden_commitments) is not tuple:
            raise TypeError("hidden_commitments must be an exact tuple")
        if len(hidden_commitments) != _TAU:
            raise TreeValidationError("hidden_commitments must contain exactly 18 values")
        checked_hidden = tuple(
            _require_exact_bytes(item, f"hidden_commitments[{index}]", _COMMITMENT_BYTES)
            for index, item in enumerate(hidden_commitments)
        )
        result: list[bytes] = []
        hidden_index = 0
        for commitment in self.transcript_order_commitments:
            if commitment is None:
                result.append(checked_hidden[hidden_index])
                hidden_index += 1
            else:
                result.append(commitment)
        if hidden_index != _TAU:
            raise AssertionError("unreachable hidden commitment count")
        encoded = b"".join(result)
        if len(encoded) != _ACTIVE_LEAVES * _COMMITMENT_BYTES:
            raise AssertionError("unreachable commitment transcript length")
        return encoded


def _reconstruct_frontier(
    salt: bytes,
    frontier_indices: tuple[int, ...],
    frontier_seeds: tuple[bytes, ...],
) -> tuple[bytes | None, ...]:
    leaves: list[bytes | None] = [None] * _ACTIVE_LEAVES
    for frontier_index, frontier_seed in zip(frontier_indices, frontier_seeds):
        stack = [(frontier_index, frontier_seed)]
        while stack:
            node_index, node_seed = stack.pop()
            if node_index >= _LEAF_BASE:
                unified = node_index - _LEAF_BASE
                if not 0 <= unified < _ACTIVE_LEAVES:
                    raise TreeValidationError("frontier expansion left the active tree")
                if leaves[unified] is not None:
                    raise TreeValidationError("frontier subtrees overlap")
                leaves[unified] = node_seed
                continue
            left_seed, right_seed = _derive_children(node_seed, salt, node_index)
            stack.append((2 * node_index + 2, right_seed))
            stack.append((2 * node_index + 1, left_seed))
    return tuple(leaves)


def verify_opening(
    salt: bytes,
    hidden_positions: tuple[int, ...],
    opening: Opening,
) -> VerifiedLeaves:
    """Reconstruct all and only non-hidden leaves from a seed-only opening."""

    checked_salt = _require_exact_bytes(salt, "salt", _SALT_BYTES)
    checked_hidden = _validate_hidden_positions(hidden_positions)
    if type(opening) is not Opening:
        raise TypeError("opening must be an exact Opening")
    indices = canonical_frontier_indices(checked_hidden)
    if len(opening.seeds) != len(indices):
        raise TreeValidationError("opening seed count does not match canonical frontier")

    reconstructed = _reconstruct_frontier(checked_salt, indices, opening.seeds)
    hidden_unified = {
        logical_to_unified(repetition, position)
        for repetition, position in enumerate(checked_hidden)
    }
    observed = {index for index, seed in enumerate(reconstructed) if seed is not None}
    expected = set(range(_ACTIVE_LEAVES)) - hidden_unified
    if observed != expected:
        raise TreeValidationError("frontier coverage is not exactly the non-hidden leaves")

    commitments: list[bytes | None] = []
    for repetition in range(_TAU):
        for position in range(_position_count(repetition)):
            if position == checked_hidden[repetition]:
                commitments.append(None)
                continue
            unified = logical_to_unified(repetition, position)
            seed = reconstructed[unified]
            if seed is None:
                raise AssertionError("unreachable missing non-hidden seed")
            commitments.append(
                leaf_commitment(repetition, position, seed, checked_salt)
            )
    return VerifiedLeaves(
        checked_salt,
        checked_hidden,
        reconstructed,
        tuple(commitments),
    )


__all__ = (
    "LeafTape",
    "Opening",
    "TreeState",
    "TreeValidationError",
    "VerifiedLeaves",
    "canonical_frontier_indices",
    "derive_leaf_tape",
    "expand_one_tree",
    "leaf_commitment",
    "logical_to_unified",
    "open_frontier",
    "unified_to_logical",
    "verify_opening",
)
