#!/usr/bin/env python3
"""Bounded unified-GGM BAVC prototype for the PQ-RBBC CAP migration.

The module implements the v2.33 candidate namespace and an executable reduced
profile.  The production profile is descriptive and remains opt-in/disabled;
this module does not compose or replay the production relation.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from typing import Iterable, Sequence

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_anemoi_sponge as sponge


IMPLEMENTATION_VERSION = "2.33"
RELATION_ID = "pq-rbbc/cap/tcith-iii/anemoi-193-336/unified-ggm/candidate/v1"
PROFILE_NAME = "PQ-RBBC-CAP-TCitH-III/Anemoi-193-336-Unified-GGM-CANDIDATE-v1"
REDUCED_PROFILE_NAME = "PQ-RBBC-CAP-UNIFIED-GGM-REDUCED-TEST-ONLY-v1"

COMMITMENT_MAGIC = b"PQRBBC-CAP-UGGM-COMMIT-V1"
OPENING_MAGIC = b"PQRBBC-CAP-UGGM-OPEN-V1"
VERSION = 1

DOMAIN_PREFIX = b"PQ-RBBC/v2.33/CAP-UGGM/"
DOMAIN_SEED_DERIVE = DOMAIN_PREFIX + b"seed-derive"
DOMAIN_SEED_COMMIT = DOMAIN_PREFIX + b"seed-commit"
DOMAIN_TAPE_EXPAND = DOMAIN_PREFIX + b"tape-expand"
DOMAIN_VECTOR_HASH = DOMAIN_PREFIX + b"vector-hash"
DOMAIN_ROOT_HASH = DOMAIN_PREFIX + b"root-hash"
DOMAIN_H3 = DOMAIN_PREFIX + b"h3"
DOMAINS = (
    DOMAIN_SEED_DERIVE,
    DOMAIN_SEED_COMMIT,
    DOMAIN_TAPE_EXPAND,
    DOMAIN_VECTOR_HASH,
    DOMAIN_ROOT_HASH,
    DOMAIN_H3,
)

SEED_BITS = field.FIELD_DEGREE
HASH_BITS = 2 * field.FIELD_DEGREE
SEED_BYTES = field.FIELD_ELEMENT_BYTES
HASH_BYTES = (HASH_BITS + 7) // 8


class UnifiedTreeError(ValueError):
    """Raised on noncanonical or invalid unified-tree data."""


def canonical_json(document: object) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def _u16(value: int) -> bytes:
    if not 0 <= value < 1 << 16:
        raise UnifiedTreeError("u16 out of range")
    return value.to_bytes(2, "little")


def _u32(value: int) -> bytes:
    if not 0 <= value < 1 << 32:
        raise UnifiedTreeError("u32 out of range")
    return value.to_bytes(4, "little")


def _u64(value: int) -> bytes:
    if not 0 <= value < 1 << 64:
        raise UnifiedTreeError("u64 out of range")
    return value.to_bytes(8, "little")


def _field_bytes(value: int) -> bytes:
    if not 0 <= value <= field.FIELD_MASK:
        raise UnifiedTreeError("noncanonical GF(2^193) element")
    return value.to_bytes(SEED_BYTES, "little")


def _hash_bytes(value: int) -> bytes:
    if not 0 <= value < 1 << HASH_BITS:
        raise UnifiedTreeError("noncanonical 386-bit hash")
    return value.to_bytes(HASH_BYTES, "little")


def _decode_field(encoded: bytes) -> int:
    if len(encoded) != SEED_BYTES or encoded[-1] & 0xFE:
        raise UnifiedTreeError("noncanonical GF(2^193) encoding")
    return int.from_bytes(encoded, "little")


def _decode_hash(encoded: bytes) -> int:
    if len(encoded) != HASH_BYTES or encoded[-1] & 0xFC:
        raise UnifiedTreeError("noncanonical 386-bit hash encoding")
    return int.from_bytes(encoded, "little")


@dataclass(frozen=True)
class UnifiedTreeParameters:
    name: str
    logical_leaf_counts: tuple[int, ...]
    tape_bits: int
    t_open: int
    explicit_pow_bits: int
    target_security_bits: int
    secure_profile: bool

    def __post_init__(self) -> None:
        if not self.name or not self.logical_leaf_counts:
            raise UnifiedTreeError("profile name and logical vectors are required")
        for leaves in self.logical_leaf_counts:
            if leaves < 2 or leaves & (leaves - 1):
                raise UnifiedTreeError("logical vector lengths must be powers of two")
        if self.total_leaves < 2 or self.total_leaves >= 1 << 32:
            raise UnifiedTreeError("unsupported total leaf count")
        if not 0 < self.tape_bits < 1 << 32:
            raise UnifiedTreeError("invalid tape width")
        if not 0 < self.t_open < self.total_leaves:
            raise UnifiedTreeError("invalid opening threshold")
        if not 0 <= self.explicit_pow_bits < HASH_BITS:
            raise UnifiedTreeError("invalid explicit PoW width")
        if self.challenge_index_bits + self.explicit_pow_bits > HASH_BITS:
            raise UnifiedTreeError("challenge does not fit h3")

    @property
    def vector_count(self) -> int:
        return len(self.logical_leaf_counts)

    @property
    def total_leaves(self) -> int:
        return sum(self.logical_leaf_counts)

    @property
    def challenge_widths(self) -> tuple[int, ...]:
        return tuple(leaves.bit_length() - 1 for leaves in self.logical_leaf_counts)

    @property
    def challenge_index_bits(self) -> int:
        return sum(self.challenge_widths)


PRODUCTION_PARAMETERS = UnifiedTreeParameters(
    name=PROFILE_NAME,
    logical_leaf_counts=(1 << 12, 1 << 12) + (1 << 11,) * 16,
    tape_bits=2_450,
    t_open=174,
    explicit_pow_bits=9,
    target_security_bits=192,
    secure_profile=True,
)

REDUCED_TEST_PARAMETERS = UnifiedTreeParameters(
    name=REDUCED_PROFILE_NAME,
    logical_leaf_counts=(4, 4, 2, 2),
    tape_bits=32,
    t_open=4,
    explicit_pow_bits=2,
    target_security_bits=0,
    secure_profile=False,
)


def profile_contract(parameters: UnifiedTreeParameters) -> dict[str, object]:
    return {
        "format": "PQRBBC-CAP-UNIFIED-TREE-PROFILE-1",
        "implementation_version": IMPLEMENTATION_VERSION,
        "name": parameters.name,
        "relation_id": RELATION_ID,
        "status": (
            "production_candidate_not_qualified"
            if parameters.secure_profile
            else "reduced_test_only"
        ),
        "field": "GF(2^193)",
        "seed_bits": SEED_BITS,
        "hash_bits": HASH_BITS,
        "logical_leaf_counts": list(parameters.logical_leaf_counts),
        "challenge_widths": list(parameters.challenge_widths),
        "challenge_index_bits": parameters.challenge_index_bits,
        "tape_bits": parameters.tape_bits,
        "t_open": parameters.t_open,
        "explicit_pow_bits": parameters.explicit_pow_bits,
        "target_security_bits": parameters.target_security_bits,
        "root_seed_count": 1,
        "total_leaves": parameters.total_leaves,
        "internal_nodes": parameters.total_leaves - 1,
        "total_nodes": 2 * parameters.total_leaves - 1,
        "heap_rule": "root=0,left=2*i+1,right=2*i+2",
        "leaf_mapping": "position-major over eligible logical vectors",
        "challenge_bit_order": "LSB-first slices in logical-vector order",
        "counter_encoding": "u64le",
        "counter_start": 0,
        "domains_hex": [domain.hex() for domain in DOMAINS],
        "serialization": {
            "integers": "unsigned little-endian",
            "field_elements": "25-byte little-endian with top seven bits zero",
            "hashes": "49-byte little-endian with top six bits zero",
            "frontier_order": "strictly increasing heap node index",
            "trailing_bytes": "forbidden",
        },
    }


def profile_fingerprint(parameters: UnifiedTreeParameters) -> str:
    return hashlib.sha256(canonical_json(profile_contract(parameters))).hexdigest()


def logical_to_unified_index(
    parameters: UnifiedTreeParameters, repetition: int, position: int
) -> int:
    counts = parameters.logical_leaf_counts
    if not 0 <= repetition < len(counts):
        raise UnifiedTreeError("logical repetition out of range")
    if not 0 <= position < counts[repetition]:
        raise UnifiedTreeError("logical position out of range")
    before_positions = sum(min(position, leaves) for leaves in counts)
    rank = sum(
        position < leaves for leaves in counts[:repetition]
    )
    return before_positions + rank


def unified_to_logical_index(
    parameters: UnifiedTreeParameters, unified_index: int
) -> tuple[int, int]:
    if not 0 <= unified_index < parameters.total_leaves:
        raise UnifiedTreeError("unified leaf index out of range")
    counts = parameters.logical_leaf_counts
    low = 0
    high = max(counts)
    while low < high:
        middle = (low + high) // 2
        after_middle = sum(min(middle + 1, leaves) for leaves in counts)
        if unified_index < after_middle:
            high = middle
        else:
            low = middle + 1
    position = low
    before = sum(min(position, leaves) for leaves in counts)
    eligible = tuple(
        repetition
        for repetition, leaves in enumerate(counts)
        if position < leaves
    )
    rank = unified_index - before
    if not 0 <= rank < len(eligible):
        raise AssertionError("unreachable unified leaf index")
    return eligible[rank], position


@dataclass(frozen=True)
class XOFRecord:
    label: str
    domain_hex: str
    field_sha256: str
    output_bits: int
    output_sha256: str


def _xof(
    label: str,
    domain: bytes,
    fields: Sequence[bytes],
    output_bits: int,
    records: list[XOFRecord] | None = None,
) -> int:
    payload = sponge.encode_transcript(tuple(fields))
    raw = sponge.evaluate_sponge(domain, payload, (output_bits + 7) // 8)
    value = int.from_bytes(raw, "little") & ((1 << output_bits) - 1)
    if records is not None:
        records.append(XOFRecord(
            label=label,
            domain_hex=domain.hex(),
            field_sha256=hashlib.sha256(payload).hexdigest(),
            output_bits=output_bits,
            output_sha256=hashlib.sha256(
                value.to_bytes((output_bits + 7) // 8, "little")
            ).hexdigest(),
        ))
    return value


@dataclass(frozen=True)
class UnifiedTreeRandomness:
    salt: tuple[int, int]
    root_seed: int


def deterministic_randomness(
    parameters: UnifiedTreeParameters,
    label: bytes = b"PQ-RBBC/v2.33/CAP-UGGM/reduced/frozen-randomness",
) -> UnifiedTreeRandomness:
    material = hashlib.shake_256(
        label + bytes.fromhex(profile_fingerprint(parameters))
    ).digest(3 * SEED_BYTES)
    values = tuple(
        int.from_bytes(material[index * SEED_BYTES : (index + 1) * SEED_BYTES], "little")
        & field.FIELD_MASK
        for index in range(3)
    )
    return UnifiedTreeRandomness((values[0], values[1]), values[2])


def _salt_bytes(salt: tuple[int, int]) -> bytes:
    return _field_bytes(salt[0]) + _field_bytes(salt[1])


def derive_children(
    parameters: UnifiedTreeParameters,
    salt: tuple[int, int],
    parent_seed: int,
    node_index: int,
    records: list[XOFRecord] | None = None,
) -> tuple[int, int]:
    output = _xof(
        f"node[{node_index}].derive",
        DOMAIN_SEED_DERIVE,
        (
            bytes.fromhex(profile_fingerprint(parameters)),
            _salt_bytes(salt),
            _field_bytes(parent_seed),
            _u32(node_index),
        ),
        2 * SEED_BITS,
        records,
    )
    return output & field.FIELD_MASK, output >> SEED_BITS


def expand_unified_tree(
    parameters: UnifiedTreeParameters,
    randomness: UnifiedTreeRandomness,
    records: list[XOFRecord] | None = None,
) -> tuple[int, ...]:
    nodes = [0] * (2 * parameters.total_leaves - 1)
    nodes[0] = randomness.root_seed
    for node_index in range(parameters.total_leaves - 1):
        left, right = derive_children(
            parameters, randomness.salt, nodes[node_index], node_index, records
        )
        nodes[2 * node_index + 1] = left
        nodes[2 * node_index + 2] = right
    return tuple(nodes)


def leaf_material(
    parameters: UnifiedTreeParameters,
    salt: tuple[int, int],
    seed: int,
    unified_index: int,
    records: list[XOFRecord] | None = None,
) -> tuple[int, int]:
    repetition, position = unified_to_logical_index(parameters, unified_index)
    metadata = _u16(repetition) + _u32(position) + _u32(unified_index)
    common = (
        bytes.fromhex(profile_fingerprint(parameters)),
        _salt_bytes(salt),
        _field_bytes(seed),
        metadata,
    )
    commitment = _xof(
        f"leaf[{unified_index}].commit",
        DOMAIN_SEED_COMMIT,
        common,
        HASH_BITS,
        records,
    )
    tape = _xof(
        f"leaf[{unified_index}].tape",
        DOMAIN_TAPE_EXPAND,
        common,
        parameters.tape_bits,
        records,
    )
    return commitment, tape


def vector_hash(
    parameters: UnifiedTreeParameters,
    repetition: int,
    commitments: Sequence[int],
    records: list[XOFRecord] | None = None,
) -> int:
    expected = parameters.logical_leaf_counts[repetition]
    if len(commitments) != expected:
        raise UnifiedTreeError("wrong logical commitment vector length")
    return _xof(
        f"vector[{repetition}].hash",
        DOMAIN_VECTOR_HASH,
        (
            bytes.fromhex(profile_fingerprint(parameters)),
            _u16(repetition),
            _u32(expected),
            *(_hash_bytes(item) for item in commitments),
        ),
        HASH_BITS,
        records,
    )


def root_hash(
    parameters: UnifiedTreeParameters,
    vector_hashes: Sequence[int],
    records: list[XOFRecord] | None = None,
) -> int:
    if len(vector_hashes) != parameters.vector_count:
        raise UnifiedTreeError("wrong vector hash count")
    return _xof(
        "root-hash",
        DOMAIN_ROOT_HASH,
        (
            bytes.fromhex(profile_fingerprint(parameters)),
            _u16(parameters.vector_count),
            *(_hash_bytes(item) for item in vector_hashes),
        ),
        HASH_BITS,
        records,
    )


@dataclass(frozen=True)
class UnifiedCommitment:
    profile_fingerprint: str
    salt: tuple[int, int]
    root_digest: int

    def encode(self) -> bytes:
        if len(self.profile_fingerprint) != 64:
            raise UnifiedTreeError("invalid profile fingerprint")
        return (
            COMMITMENT_MAGIC
            + _u16(VERSION)
            + bytes.fromhex(self.profile_fingerprint)
            + _salt_bytes(self.salt)
            + _hash_bytes(self.root_digest)
        )

    @classmethod
    def decode(
        cls, parameters: UnifiedTreeParameters, encoded: bytes
    ) -> "UnifiedCommitment":
        expected_size = len(COMMITMENT_MAGIC) + 2 + 32 + 2 * SEED_BYTES + HASH_BYTES
        if len(encoded) != expected_size:
            raise UnifiedTreeError("wrong commitment length")
        offset = 0
        if encoded[: len(COMMITMENT_MAGIC)] != COMMITMENT_MAGIC:
            raise UnifiedTreeError("wrong commitment magic")
        offset += len(COMMITMENT_MAGIC)
        if int.from_bytes(encoded[offset : offset + 2], "little") != VERSION:
            raise UnifiedTreeError("wrong commitment version")
        offset += 2
        fingerprint = encoded[offset : offset + 32].hex()
        if fingerprint != profile_fingerprint(parameters):
            raise UnifiedTreeError("wrong commitment profile")
        offset += 32
        salt = (
            _decode_field(encoded[offset : offset + SEED_BYTES]),
            _decode_field(encoded[offset + SEED_BYTES : offset + 2 * SEED_BYTES]),
        )
        offset += 2 * SEED_BYTES
        digest = _decode_hash(encoded[offset : offset + HASH_BYTES])
        return cls(fingerprint, salt, digest)


@dataclass(frozen=True)
class UnifiedTreeExecution:
    parameters: UnifiedTreeParameters
    randomness: UnifiedTreeRandomness
    commitment: UnifiedCommitment
    nodes: tuple[int, ...]
    leaf_commitments: tuple[int, ...]
    leaf_tapes: tuple[int, ...]
    vector_hashes: tuple[int, ...]
    xof_records: tuple[XOFRecord, ...]


def execute_commit(
    parameters: UnifiedTreeParameters,
    randomness: UnifiedTreeRandomness,
    *,
    allow_large: bool = False,
) -> UnifiedTreeExecution:
    if parameters.secure_profile and not allow_large:
        raise RuntimeError("production unified-tree build is disabled in the bounded prototype")
    records: list[XOFRecord] = []
    nodes = expand_unified_tree(parameters, randomness, records)
    leaf_base = parameters.total_leaves - 1
    leaf_commitments: list[int] = []
    leaf_tapes: list[int] = []
    for unified_index, seed in enumerate(nodes[leaf_base:]):
        commitment, tape = leaf_material(
            parameters, randomness.salt, seed, unified_index, records
        )
        leaf_commitments.append(commitment)
        leaf_tapes.append(tape)
    logical_commitments: list[list[int]] = [
        [0] * leaves for leaves in parameters.logical_leaf_counts
    ]
    for unified_index, commitment in enumerate(leaf_commitments):
        repetition, position = unified_to_logical_index(parameters, unified_index)
        logical_commitments[repetition][position] = commitment
    vector_hashes = tuple(
        vector_hash(parameters, repetition, items, records)
        for repetition, items in enumerate(logical_commitments)
    )
    digest = root_hash(parameters, vector_hashes, records)
    commitment = UnifiedCommitment(
        profile_fingerprint(parameters), randomness.salt, digest
    )
    return UnifiedTreeExecution(
        parameters,
        randomness,
        commitment,
        nodes,
        tuple(leaf_commitments),
        tuple(leaf_tapes),
        vector_hashes,
        tuple(records),
    )


def decode_challenge(
    parameters: UnifiedTreeParameters, h3: int
) -> tuple[tuple[int, ...], int]:
    if not 0 <= h3 < 1 << HASH_BITS:
        raise UnifiedTreeError("h3 out of range")
    cursor = 0
    positions: list[int] = []
    for width in parameters.challenge_widths:
        positions.append((h3 >> cursor) & ((1 << width) - 1))
        cursor += width
    explicit = (h3 >> cursor) & ((1 << parameters.explicit_pow_bits) - 1)
    return tuple(positions), explicit


def challenge_hash(
    parameters: UnifiedTreeParameters,
    challenge_prefix: bytes,
    commitment_bytes: bytes,
    counter: int,
) -> int:
    return _xof(
        "h3",
        DOMAIN_H3,
        (
            bytes.fromhex(profile_fingerprint(parameters)),
            challenge_prefix,
            commitment_bytes,
            _u64(counter),
        ),
        HASH_BITS,
    )


def canonical_frontier_indices(
    parameters: UnifiedTreeParameters, hidden_positions: Sequence[int]
) -> tuple[int, ...]:
    if len(hidden_positions) != parameters.vector_count:
        raise UnifiedTreeError("wrong hidden-position count")
    hidden_unified = {
        logical_to_unified_index(parameters, repetition, position)
        for repetition, position in enumerate(hidden_positions)
    }
    if len(hidden_unified) != parameters.vector_count:
        raise UnifiedTreeError("hidden mapping is not injective")
    leaf_base = parameters.total_leaves - 1
    active = set(range(leaf_base, 2 * parameters.total_leaves - 1))
    active.difference_update(leaf_base + index for index in hidden_unified)
    for node_index in range(parameters.total_leaves - 2, -1, -1):
        left = 2 * node_index + 1
        right = left + 1
        if left in active and right in active:
            active.remove(left)
            active.remove(right)
            active.add(node_index)
    return tuple(sorted(active))


@dataclass(frozen=True)
class OpeningNode:
    node_index: int
    seed: int


@dataclass(frozen=True)
class UnifiedOpening:
    profile_fingerprint: str
    counter: int
    h3: int
    hidden_positions: tuple[int, ...]
    hidden_commitments: tuple[int, ...]
    frontier: tuple[OpeningNode, ...]

    def encode(self, parameters: UnifiedTreeParameters) -> bytes:
        expected_profile = profile_fingerprint(parameters)
        if self.profile_fingerprint != expected_profile:
            raise UnifiedTreeError("wrong opening profile")
        if (
            len(self.hidden_positions) != parameters.vector_count
            or len(self.hidden_commitments) != parameters.vector_count
        ):
            raise UnifiedTreeError("wrong hidden opening count")
        if len(self.frontier) > parameters.t_open:
            raise UnifiedTreeError("opening frontier exceeds T_open")
        indices = tuple(node.node_index for node in self.frontier)
        if indices != tuple(sorted(set(indices))):
            raise UnifiedTreeError("frontier indices are not canonical")
        result = bytearray(OPENING_MAGIC)
        result.extend(_u16(VERSION))
        result.extend(bytes.fromhex(self.profile_fingerprint))
        result.extend(_u64(self.counter))
        result.extend(_hash_bytes(self.h3))
        result.extend(_u16(parameters.vector_count))
        for repetition, (position, commitment) in enumerate(
            zip(self.hidden_positions, self.hidden_commitments)
        ):
            if not 0 <= position < parameters.logical_leaf_counts[repetition]:
                raise UnifiedTreeError("hidden position out of range")
            result.extend(_u16(repetition))
            result.extend(_u32(position))
            result.extend(_hash_bytes(commitment))
        result.extend(_u16(len(self.frontier)))
        for node in self.frontier:
            if not 0 <= node.node_index < 2 * parameters.total_leaves - 1:
                raise UnifiedTreeError("frontier node out of range")
            result.extend(_u32(node.node_index))
            result.extend(_field_bytes(node.seed))
        return bytes(result)

    @classmethod
    def decode(
        cls, parameters: UnifiedTreeParameters, encoded: bytes
    ) -> "UnifiedOpening":
        offset = 0

        def take(length: int, label: str) -> bytes:
            nonlocal offset
            if offset + length > len(encoded):
                raise UnifiedTreeError(f"truncated {label}")
            value = encoded[offset : offset + length]
            offset += length
            return value

        if take(len(OPENING_MAGIC), "opening magic") != OPENING_MAGIC:
            raise UnifiedTreeError("wrong opening magic")
        if int.from_bytes(take(2, "opening version"), "little") != VERSION:
            raise UnifiedTreeError("wrong opening version")
        fingerprint = take(32, "opening profile").hex()
        if fingerprint != profile_fingerprint(parameters):
            raise UnifiedTreeError("wrong opening profile")
        counter = int.from_bytes(take(8, "counter"), "little")
        h3 = _decode_hash(take(HASH_BYTES, "h3"))
        hidden_count = int.from_bytes(take(2, "hidden count"), "little")
        if hidden_count != parameters.vector_count:
            raise UnifiedTreeError("wrong hidden count")
        hidden_positions: list[int] = []
        hidden_commitments: list[int] = []
        for expected_repetition in range(hidden_count):
            repetition = int.from_bytes(take(2, "repetition"), "little")
            if repetition != expected_repetition:
                raise UnifiedTreeError("noncanonical repetition order")
            position = int.from_bytes(take(4, "hidden position"), "little")
            if position >= parameters.logical_leaf_counts[repetition]:
                raise UnifiedTreeError("hidden position out of range")
            hidden_positions.append(position)
            hidden_commitments.append(
                _decode_hash(take(HASH_BYTES, "hidden commitment"))
            )
        frontier_count = int.from_bytes(take(2, "frontier count"), "little")
        if frontier_count > parameters.t_open:
            raise UnifiedTreeError("opening frontier exceeds T_open")
        frontier: list[OpeningNode] = []
        for _ in range(frontier_count):
            node_index = int.from_bytes(take(4, "frontier index"), "little")
            if node_index >= 2 * parameters.total_leaves - 1:
                raise UnifiedTreeError("frontier node out of range")
            frontier.append(OpeningNode(node_index, _decode_field(take(SEED_BYTES, "seed"))))
        if offset != len(encoded):
            raise UnifiedTreeError("trailing opening bytes")
        indices = tuple(node.node_index for node in frontier)
        if indices != tuple(sorted(set(indices))):
            raise UnifiedTreeError("frontier indices are not canonical")
        return cls(
            fingerprint,
            counter,
            h3,
            tuple(hidden_positions),
            tuple(hidden_commitments),
            tuple(frontier),
        )


def opening_candidate(
    execution: UnifiedTreeExecution,
    challenge_prefix: bytes,
    counter: int,
) -> UnifiedOpening:
    parameters = execution.parameters
    h3 = challenge_hash(
        parameters, challenge_prefix, execution.commitment.encode(), counter
    )
    hidden_positions, _ = decode_challenge(parameters, h3)
    hidden_unified = tuple(
        logical_to_unified_index(parameters, repetition, position)
        for repetition, position in enumerate(hidden_positions)
    )
    frontier_indices = canonical_frontier_indices(parameters, hidden_positions)
    hidden_commitments = tuple(
        execution.leaf_commitments[index] for index in hidden_unified
    )
    return UnifiedOpening(
        profile_fingerprint(parameters),
        counter,
        h3,
        hidden_positions,
        hidden_commitments,
        tuple(OpeningNode(index, execution.nodes[index]) for index in frontier_indices),
    )


def opening_is_acceptable(
    parameters: UnifiedTreeParameters, opening: UnifiedOpening
) -> bool:
    _, explicit = decode_challenge(parameters, opening.h3)
    return explicit == 0 and len(opening.frontier) <= parameters.t_open


def grind_opening(
    execution: UnifiedTreeExecution,
    challenge_prefix: bytes,
    *,
    start_counter: int = 0,
    max_trials: int = 1_000_000,
) -> tuple[UnifiedOpening, int]:
    if not 0 <= start_counter < 1 << 64:
        raise UnifiedTreeError("start counter out of range")
    if max_trials <= 0:
        raise UnifiedTreeError("max_trials must be positive")
    for trial in range(max_trials):
        counter = start_counter + trial
        if counter >= 1 << 64:
            raise UnifiedTreeError("counter overflow")
        candidate = opening_candidate(execution, challenge_prefix, counter)
        if opening_is_acceptable(execution.parameters, candidate):
            return candidate, trial + 1
    raise RuntimeError("no acceptable opening in bounded counter range")


def _expand_frontier_node(
    parameters: UnifiedTreeParameters,
    salt: tuple[int, int],
    node_index: int,
    seed: int,
    leaves: dict[int, int],
) -> None:
    leaf_base = parameters.total_leaves - 1
    if node_index >= leaf_base:
        if node_index in leaves:
            raise UnifiedTreeError("overlapping frontier")
        leaves[node_index] = seed
        return
    left_seed, right_seed = derive_children(
        parameters, salt, seed, node_index
    )
    _expand_frontier_node(parameters, salt, 2 * node_index + 1, left_seed, leaves)
    _expand_frontier_node(parameters, salt, 2 * node_index + 2, right_seed, leaves)


@dataclass(frozen=True)
class OpeningVerification:
    accepted: bool
    failures: tuple[str, ...]
    opened_leaf_count: int
    hidden_leaf_count: int
    opened_tape_sha256: str | None


def verify_opening(
    parameters: UnifiedTreeParameters,
    challenge_prefix: bytes,
    commitment_bytes: bytes,
    opening_bytes: bytes,
) -> OpeningVerification:
    failures: list[str] = []
    try:
        commitment = UnifiedCommitment.decode(parameters, commitment_bytes)
    except (UnifiedTreeError, ValueError) as error:
        return OpeningVerification(False, (f"commitment:{error}",), 0, 0, None)
    try:
        opening = UnifiedOpening.decode(parameters, opening_bytes)
    except (UnifiedTreeError, ValueError) as error:
        return OpeningVerification(False, (f"opening:{error}",), 0, 0, None)

    expected_h3 = challenge_hash(
        parameters, challenge_prefix, commitment_bytes, opening.counter
    )
    if opening.h3 != expected_h3:
        failures.append("h3_mismatch")
    expected_positions, explicit = decode_challenge(parameters, expected_h3)
    if opening.hidden_positions != expected_positions:
        failures.append("hidden_positions_mismatch")
    if explicit != 0:
        failures.append("explicit_pow_bits_nonzero")
    expected_frontier = canonical_frontier_indices(parameters, expected_positions)
    observed_frontier = tuple(node.node_index for node in opening.frontier)
    if observed_frontier != expected_frontier:
        failures.append("frontier_not_minimal_canonical")
    if len(expected_frontier) > parameters.t_open:
        failures.append("frontier_exceeds_t_open")
    if failures:
        return OpeningVerification(
            False, tuple(failures), 0, parameters.vector_count, None
        )

    reconstructed: dict[int, int] = {}
    try:
        for node in opening.frontier:
            _expand_frontier_node(
                parameters,
                commitment.salt,
                node.node_index,
                node.seed,
                reconstructed,
            )
    except UnifiedTreeError as error:
        return OpeningVerification(
            False, (f"frontier:{error}",), 0, parameters.vector_count, None
        )
    leaf_base = parameters.total_leaves - 1
    hidden_unified = {
        logical_to_unified_index(parameters, repetition, position)
        for repetition, position in enumerate(expected_positions)
    }
    expected_nodes = {
        leaf_base + index
        for index in range(parameters.total_leaves)
        if index not in hidden_unified
    }
    if set(reconstructed) != expected_nodes:
        return OpeningVerification(
            False,
            ("frontier_leaf_coverage_mismatch",),
            len(reconstructed),
            parameters.vector_count,
            None,
        )

    all_commitments: list[int | None] = [None] * parameters.total_leaves
    opened_tapes: list[tuple[int, int]] = []
    for heap_index in sorted(reconstructed):
        unified_index = heap_index - leaf_base
        leaf_commitment, tape = leaf_material(
            parameters,
            commitment.salt,
            reconstructed[heap_index],
            unified_index,
        )
        all_commitments[unified_index] = leaf_commitment
        opened_tapes.append((unified_index, tape))
    for repetition, (position, hidden_commitment) in enumerate(
        zip(expected_positions, opening.hidden_commitments)
    ):
        unified_index = logical_to_unified_index(parameters, repetition, position)
        all_commitments[unified_index] = hidden_commitment
    if any(item is None for item in all_commitments):
        return OpeningVerification(
            False,
            ("commitment_coverage_mismatch",),
            len(reconstructed),
            parameters.vector_count,
            None,
        )

    logical_commitments: list[list[int]] = [
        [0] * leaves for leaves in parameters.logical_leaf_counts
    ]
    for unified_index, leaf_commitment in enumerate(all_commitments):
        repetition, position = unified_to_logical_index(parameters, unified_index)
        assert leaf_commitment is not None
        logical_commitments[repetition][position] = leaf_commitment
    vector_hashes = tuple(
        vector_hash(parameters, repetition, items)
        for repetition, items in enumerate(logical_commitments)
    )
    if root_hash(parameters, vector_hashes) != commitment.root_digest:
        return OpeningVerification(
            False,
            ("root_commitment_mismatch",),
            len(reconstructed),
            parameters.vector_count,
            None,
        )
    tape_payload = b"".join(
        _u32(index) + tape.to_bytes((parameters.tape_bits + 7) // 8, "little")
        for index, tape in opened_tapes
    )
    return OpeningVerification(
        True,
        (),
        len(reconstructed),
        parameters.vector_count,
        hashlib.sha256(tape_payload).hexdigest(),
    )


def trace_digest(records: Iterable[XOFRecord]) -> str:
    return hashlib.sha256(
        canonical_json([
            {
                "label": item.label,
                "domain_hex": item.domain_hex,
                "field_sha256": item.field_sha256,
                "output_bits": item.output_bits,
                "output_sha256": item.output_sha256,
            }
            for item in records
        ])
    ).hexdigest()
