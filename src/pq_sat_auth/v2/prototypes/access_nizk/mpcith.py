"""Three-party MPC-in-the-Head prototype for the exact access relation.

This is a ZKBoo-family research construction over a Boolean circuit.  Each
repetition commits to three XOR-shared MPC views.  Fiat--Shamir selects two
adjacent views; the verifier recomputes one view gate-by-gate and uses the
other opened transcript as the simulated neighbour.  The hidden view remains
committed, and all three output shares must reconstruct the two exact
SHAKE256 values in :class:`AccessProofStatementV2`.

The construction has not received an independent cryptographic review.  In
particular, this module does not claim QROM Fiat--Shamir security or simulation
extractability and cannot pass a production backend gate.
"""

from __future__ import annotations

import hashlib
import secrets
import struct
import time
from dataclasses import dataclass

from pq_rbbc_reference import RATE, RHO, ROUND_CONSTANTS

from ...proof import (
    AccessProofStatementV2,
    AccessProofWitnessV2,
    HOLDER_BINDING_LABEL,
    HOLDER_HASH_LABEL,
    derive_holder_binding_tag,
    derive_holder_hash,
)
from .parameters import (
    BENCHMARK_PARAMETERS_V01,
    COMMITMENT_BYTES,
    OUTPUT_BYTES,
    PROOF_FORMAT_VERSION,
    PROOF_MAGIC,
    SEED_BYTES,
    VIEW_TRANSCRIPT_BYTES,
    MPCITHParametersV01,
)


MASK64 = (1 << 64) - 1
WORDS_PER_KECCAK = 24 * 25
WORDS_PER_VIEW = 2 * WORDS_PER_KECCAK
INPUT_SHARE_BYTES = 32
HEADER = struct.Struct(">8sHHHHI32s")
ROUND_FIXED = struct.Struct(">B32s64s32s32s32s32s")
ROOT_DOMAIN = b"PQ-SAT/R-ACCESS-MPCITH-ROOT/v0.1"
TAPE_DOMAIN = b"PQ-SAT/R-ACCESS-MPCITH-TAPE/v0.1"
VIEW_COMMITMENT_DOMAIN = b"PQ-SAT/R-ACCESS-MPCITH-VIEW-COMMIT/v0.1"
CHALLENGE_DOMAIN = b"PQ-SAT/R-ACCESS-MPCITH-CHALLENGE/v0.1"
PRODUCTION_READY = False
EXPERIMENTAL_REFERENCE_ONLY = True
SIMULATION_EXTRACTABLE = False
PROOF_CLOSED = False
PRODUCTION_CLOSED = False


class RelationNotSatisfied(ValueError):
    """Raised when the supplied witness does not satisfy the public relation."""


class ProofEncodingError(ValueError):
    """Internal strict parser error; public verification maps it to ``False``."""


@dataclass(frozen=True)
class ProofGenerationMetrics:
    randomness_and_sharing_seconds: float
    mpc_simulation_and_commitment_seconds: float
    fiat_shamir_challenge_seconds: float
    proof_serialization_seconds: float
    online_prove_seconds: float
    proof_bytes: int


@dataclass(frozen=True)
class _RoundViews:
    seeds: tuple[bytes, bytes, bytes]
    input_shares: tuple[bytes, bytes, bytes]
    transcripts: tuple[bytes, bytes, bytes]
    outputs: tuple[bytes, bytes, bytes]
    commitments: tuple[bytes, bytes, bytes]


def _xor_bytes(*values: bytes) -> bytes:
    if not values:
        raise ValueError("xor requires at least one operand")
    size = len(values[0])
    if any(len(value) != size for value in values):
        raise ValueError("xor operands must have equal length")
    result = bytearray(size)
    for value in values:
        for index, byte in enumerate(value):
            result[index] ^= byte
    return bytes(result)


def _statement_digest(statement: AccessProofStatementV2) -> bytes:
    return hashlib.sha256(statement.encode()).digest()


def _derive_round_randomness(
    root_entropy: bytes,
    parameters: MPCITHParametersV01,
    statement_digest: bytes,
    repetition: int,
) -> tuple[tuple[bytes, bytes, bytes], bytes, bytes]:
    material = hashlib.shake_256(
        ROOT_DOMAIN
        + parameters.digest
        + statement_digest
        + repetition.to_bytes(4, "big")
        + root_entropy
    ).digest((3 * SEED_BYTES) + (2 * INPUT_SHARE_BYTES))
    seeds = tuple(
        material[index * SEED_BYTES : (index + 1) * SEED_BYTES]
        for index in range(3)
    )
    offset = 3 * SEED_BYTES
    first = material[offset : offset + INPUT_SHARE_BYTES]
    second = material[offset + INPUT_SHARE_BYTES :]
    return (seeds[0], seeds[1], seeds[2]), first, second


def _random_tape_words(
    seed: bytes,
    parameters: MPCITHParametersV01,
    statement_digest: bytes,
    repetition: int,
    party: int,
) -> tuple[int, ...]:
    if len(seed) != SEED_BYTES:
        raise ProofEncodingError("view seed length mismatch")
    raw = hashlib.shake_256(
        TAPE_DOMAIN
        + parameters.digest
        + statement_digest
        + repetition.to_bytes(4, "big")
        + bytes((party,))
        + seed
    ).digest(VIEW_TRANSCRIPT_BYTES)
    return struct.unpack(f"<{WORDS_PER_VIEW}Q", raw)


def _message_state_shares(
    party_ids: tuple[int, ...],
    input_shares: tuple[bytes, ...],
    *,
    label: bytes,
    public_suffix: bytes,
) -> list[list[int]]:
    message_bytes = len(label) + INPUT_SHARE_BYTES + len(public_suffix)
    if message_bytes >= RATE:
        raise AssertionError("the frozen R_access inputs must use one SHAKE block")
    states: list[list[int]] = []
    for party, input_share in zip(party_ids, input_shares):
        if len(input_share) != INPUT_SHARE_BYTES:
            raise ProofEncodingError("input share length mismatch")
        block = bytearray(RATE)
        secret_offset = len(label)
        block[secret_offset : secret_offset + INPUT_SHARE_BYTES] = input_share
        if party == 0:
            block[: len(label)] = label
            suffix_offset = secret_offset + INPUT_SHARE_BYTES
            block[suffix_offset : suffix_offset + len(public_suffix)] = public_suffix
            block[message_bytes] ^= 0x1F
            block[-1] ^= 0x80
        state = [0] * 25
        for lane in range(RATE // 8):
            state[lane] = int.from_bytes(block[8 * lane : 8 * lane + 8], "little")
        states.append(state)
    return states


def _theta_rho_pi(states: list[list[int]]) -> list[list[int]]:
    moved_states: list[list[int]] = []
    for state in states:
        columns = [
            state[x]
            ^ state[x + 5]
            ^ state[x + 10]
            ^ state[x + 15]
            ^ state[x + 20]
            for x in range(5)
        ]
        delta = [
            columns[(x - 1) % 5]
            ^ (
                ((columns[(x + 1) % 5] << 1)
                 | (columns[(x + 1) % 5] >> 63))
                & MASK64
            )
            for x in range(5)
        ]
        theta = [
            state[x + 5 * y] ^ delta[x]
            for y in range(5)
            for x in range(5)
        ]
        moved = [0] * 25
        for y in range(5):
            for x in range(5):
                value = theta[x + 5 * y]
                rotation = RHO[x][y]
                if rotation:
                    value = (
                        (value << rotation) | (value >> (64 - rotation))
                    ) & MASK64
                moved[y + 5 * ((2 * x + 3 * y) % 5)] = value
        moved_states.append(moved)
    return moved_states


def _simulate_permutation(
    states: list[list[int]],
    tapes: tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...]],
    tape_offset: int,
    transcript_words: list[list[int]],
) -> int:
    for rc in ROUND_CONSTANTS:
        moved = _theta_rho_pi(states)
        next_states = [[0] * 25 for _ in range(3)]
        for y in range(5):
            for x in range(5):
                lane = x + 5 * y
                b = [moved[party][lane] for party in range(3)]
                b1 = [
                    moved[party][((x + 1) % 5) + 5 * y]
                    for party in range(3)
                ]
                b2 = [
                    moved[party][((x + 2) % 5) + 5 * y]
                    for party in range(3)
                ]
                b1[0] ^= MASK64
                masks = [tapes[party][tape_offset] for party in range(3)]
                products = [0, 0, 0]
                for party in range(3):
                    neighbour = (party + 1) % 3
                    products[party] = (
                        (b1[party] & b2[party])
                        ^ (b1[party] & b2[neighbour])
                        ^ (b1[neighbour] & b2[party])
                        ^ masks[party]
                        ^ masks[neighbour]
                    )
                    transcript_words[party].append(products[party])
                    next_states[party][lane] = b[party] ^ products[party]
                tape_offset += 1
        next_states[0][0] ^= rc
        states[:] = next_states
    return tape_offset


def _output_bytes(states: list[list[int]]) -> tuple[bytes, ...]:
    return tuple(
        b"".join(state[lane].to_bytes(8, "little") for lane in range(4))
        for state in states
    )


def _simulate_all_views(
    input_shares: tuple[bytes, bytes, bytes],
    tapes: tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...]],
    request_core_digest: bytes,
) -> tuple[tuple[bytes, bytes, bytes], tuple[bytes, bytes, bytes]]:
    transcript_words: list[list[int]] = [[], [], []]
    holder_states = _message_state_shares(
        (0, 1, 2),
        input_shares,
        label=HOLDER_HASH_LABEL,
        public_suffix=b"",
    )
    tape_offset = _simulate_permutation(
        holder_states,
        tapes,
        0,
        transcript_words,
    )
    holder_outputs = _output_bytes(holder_states)

    binding_states = _message_state_shares(
        (0, 1, 2),
        input_shares,
        label=HOLDER_BINDING_LABEL,
        public_suffix=request_core_digest,
    )
    tape_offset = _simulate_permutation(
        binding_states,
        tapes,
        tape_offset,
        transcript_words,
    )
    if tape_offset != WORDS_PER_VIEW:
        raise AssertionError("unexpected exact R_access nonlinear word count")
    binding_outputs = _output_bytes(binding_states)
    transcripts = tuple(
        struct.pack(f"<{WORDS_PER_VIEW}Q", *words)
        for words in transcript_words
    )
    outputs = tuple(
        holder_outputs[party] + binding_outputs[party]
        for party in range(3)
    )
    return (
        (transcripts[0], transcripts[1], transcripts[2]),
        (outputs[0], outputs[1], outputs[2]),
    )


def _replay_opened_pair(
    *,
    checked_party: int,
    checked_seed: bytes,
    checked_input: bytes,
    neighbour_seed: bytes,
    neighbour_input: bytes,
    neighbour_transcript: bytes,
    parameters: MPCITHParametersV01,
    statement_digest: bytes,
    request_core_digest: bytes,
    repetition: int,
) -> tuple[bytes, bytes, bytes]:
    neighbour_party = (checked_party + 1) % 3
    if len(neighbour_transcript) != VIEW_TRANSCRIPT_BYTES:
        raise ProofEncodingError("opened neighbour transcript length mismatch")
    neighbour_words = struct.unpack(
        f"<{WORDS_PER_VIEW}Q", neighbour_transcript
    )
    tapes = (
        _random_tape_words(
            checked_seed,
            parameters,
            statement_digest,
            repetition,
            checked_party,
        ),
        _random_tape_words(
            neighbour_seed,
            parameters,
            statement_digest,
            repetition,
            neighbour_party,
        ),
    )
    checked_words: list[int] = []
    neighbour_word_index = 0

    def replay_permutation(states: list[list[int]], tape_offset: int) -> int:
        nonlocal neighbour_word_index
        for rc in ROUND_CONSTANTS:
            moved = _theta_rho_pi(states)
            next_states = [[0] * 25 for _ in range(2)]
            for y in range(5):
                for x in range(5):
                    lane = x + 5 * y
                    b = [moved[party][lane] for party in range(2)]
                    b1 = [
                        moved[party][((x + 1) % 5) + 5 * y]
                        for party in range(2)
                    ]
                    b2 = [
                        moved[party][((x + 2) % 5) + 5 * y]
                        for party in range(2)
                    ]
                    if checked_party == 0:
                        b1[0] ^= MASK64
                    if neighbour_party == 0:
                        b1[1] ^= MASK64
                    checked_product = (
                        (b1[0] & b2[0])
                        ^ (b1[0] & b2[1])
                        ^ (b1[1] & b2[0])
                        ^ tapes[0][tape_offset]
                        ^ tapes[1][tape_offset]
                    )
                    checked_words.append(checked_product)
                    neighbour_product = neighbour_words[neighbour_word_index]
                    neighbour_word_index += 1
                    next_states[0][lane] = b[0] ^ checked_product
                    next_states[1][lane] = b[1] ^ neighbour_product
                    tape_offset += 1
            if checked_party == 0:
                next_states[0][0] ^= rc
            if neighbour_party == 0:
                next_states[1][0] ^= rc
            states[:] = next_states
        return tape_offset

    holder_states = _message_state_shares(
        (checked_party, neighbour_party),
        (checked_input, neighbour_input),
        label=HOLDER_HASH_LABEL,
        public_suffix=b"",
    )
    tape_offset = replay_permutation(holder_states, 0)
    holder_outputs = _output_bytes(holder_states)

    binding_states = _message_state_shares(
        (checked_party, neighbour_party),
        (checked_input, neighbour_input),
        label=HOLDER_BINDING_LABEL,
        public_suffix=request_core_digest,
    )
    tape_offset = replay_permutation(binding_states, tape_offset)
    binding_outputs = _output_bytes(binding_states)
    if tape_offset != WORDS_PER_VIEW or neighbour_word_index != WORDS_PER_VIEW:
        raise ProofEncodingError("opened view transcript was not consumed exactly")
    checked_transcript = struct.pack(
        f"<{WORDS_PER_VIEW}Q", *checked_words
    )
    return (
        checked_transcript,
        holder_outputs[0] + binding_outputs[0],
        holder_outputs[1] + binding_outputs[1],
    )


def _view_commitment(
    *,
    parameters: MPCITHParametersV01,
    statement_digest: bytes,
    repetition: int,
    party: int,
    seed: bytes,
    input_share: bytes,
    transcript: bytes,
    output: bytes,
) -> bytes:
    if (
        len(seed) != SEED_BYTES
        or len(input_share) != INPUT_SHARE_BYTES
        or len(transcript) != VIEW_TRANSCRIPT_BYTES
        or len(output) != OUTPUT_BYTES
    ):
        raise ProofEncodingError("view commitment input length mismatch")
    return hashlib.shake_256(
        VIEW_COMMITMENT_DOMAIN
        + parameters.digest
        + statement_digest
        + repetition.to_bytes(4, "big")
        + bytes((party,))
        + seed
        + input_share
        + transcript
        + output
    ).digest(COMMITMENT_BYTES)


def _derive_challenges(
    parameters: MPCITHParametersV01,
    statement: AccessProofStatementV2,
    commitments: list[tuple[bytes, bytes, bytes]],
    outputs: list[tuple[bytes, bytes, bytes]],
) -> tuple[int, ...]:
    transcript = bytearray(
        CHALLENGE_DOMAIN + parameters.digest + statement.encode()
    )
    for round_commitments, round_outputs in zip(commitments, outputs):
        transcript.extend(b"".join(round_commitments))
        transcript.extend(b"".join(round_outputs))
    shake = hashlib.shake_256(bytes(transcript))
    output_length = max(64, 2 * parameters.repetitions)
    while True:
        candidate = shake.digest(output_length)
        challenges = tuple(byte % 3 for byte in candidate if byte < 252)
        if len(challenges) >= parameters.repetitions:
            return challenges[: parameters.repetitions]
        output_length *= 2


def _header(parameters: MPCITHParametersV01) -> bytes:
    return HEADER.pack(
        PROOF_MAGIC,
        PROOF_FORMAT_VERSION,
        parameters.proof_suite_id,
        parameters.parameter_version,
        parameters.claimed_classical_soundness_bits,
        parameters.repetitions,
        parameters.digest,
    )


class MPCITHAccessNIZKBackendV01:
    """Experimental backend implementing the existing V2 NIZK protocol API."""

    production_ready = False
    experimental_reference_only = True
    simulation_extractable = False
    proof_closed = False
    production_closed = False

    def __init__(
        self,
        parameters: MPCITHParametersV01 = BENCHMARK_PARAMETERS_V01,
    ) -> None:
        if not isinstance(parameters, MPCITHParametersV01):
            raise TypeError("parameters must be MPCITHParametersV01")
        self.parameters = parameters
        self.proof_suite_id = parameters.proof_suite_id

    def prove(
        self,
        statement: AccessProofStatementV2,
        witness: AccessProofWitnessV2,
    ) -> bytes:
        proof, _ = self.prove_profiled(statement, witness)
        return proof

    def prove_deterministic_for_test(
        self,
        statement: AccessProofStatementV2,
        witness: AccessProofWitnessV2,
        root_entropy: bytes,
    ) -> bytes:
        """Deterministic test-vector entry; never use for live proving."""

        proof, _ = self.prove_profiled(
            statement,
            witness,
            root_entropy=root_entropy,
        )
        return proof

    def prove_profiled(
        self,
        statement: AccessProofStatementV2,
        witness: AccessProofWitnessV2,
        *,
        root_entropy: bytes | None = None,
    ) -> tuple[bytes, ProofGenerationMetrics]:
        if not isinstance(statement, AccessProofStatementV2):
            raise TypeError("statement must be AccessProofStatementV2")
        if not isinstance(witness, AccessProofWitnessV2):
            raise TypeError("witness must be AccessProofWitnessV2")
        if statement.access_pp_digest != self.parameters.digest:
            raise RelationNotSatisfied(
                "statement access_pp_digest does not select backend parameters"
            )
        if (
            derive_holder_hash(witness.holder_secret) != statement.holder_hash
            or derive_holder_binding_tag(
                witness.holder_secret,
                statement.request_core_digest,
            )
            != statement.holder_binding_tag
        ):
            raise RelationNotSatisfied("witness does not satisfy exact R_access")

        total_start = time.perf_counter_ns()
        sharing_start = total_start
        if root_entropy is None:
            root_entropy = secrets.token_bytes(SEED_BYTES)
        if not isinstance(root_entropy, bytes) or len(root_entropy) != SEED_BYTES:
            raise ValueError("root_entropy must be exactly 32 bytes")
        statement_digest = _statement_digest(statement)
        round_randomness = [
            _derive_round_randomness(
                root_entropy,
                self.parameters,
                statement_digest,
                repetition,
            )
            for repetition in range(self.parameters.repetitions)
        ]
        sharing_end = time.perf_counter_ns()

        views: list[_RoundViews] = []
        simulation_start = sharing_end
        for repetition, (seeds, first, second) in enumerate(round_randomness):
            third = _xor_bytes(witness.holder_secret, first, second)
            input_shares = (first, second, third)
            tapes = tuple(
                _random_tape_words(
                    seeds[party],
                    self.parameters,
                    statement_digest,
                    repetition,
                    party,
                )
                for party in range(3)
            )
            transcripts, outputs = _simulate_all_views(
                input_shares,
                (tapes[0], tapes[1], tapes[2]),
                statement.request_core_digest,
            )
            if _xor_bytes(*outputs) != (
                statement.holder_hash + statement.holder_binding_tag
            ):
                raise AssertionError("MPC output does not reconstruct R_access")
            commitments = tuple(
                _view_commitment(
                    parameters=self.parameters,
                    statement_digest=statement_digest,
                    repetition=repetition,
                    party=party,
                    seed=seeds[party],
                    input_share=input_shares[party],
                    transcript=transcripts[party],
                    output=outputs[party],
                )
                for party in range(3)
            )
            views.append(
                _RoundViews(
                    seeds=seeds,
                    input_shares=input_shares,
                    transcripts=transcripts,
                    outputs=outputs,
                    commitments=(commitments[0], commitments[1], commitments[2]),
                )
            )
        simulation_end = time.perf_counter_ns()

        challenge_start = simulation_end
        challenges = _derive_challenges(
            self.parameters,
            statement,
            [view.commitments for view in views],
            [view.outputs for view in views],
        )
        challenge_end = time.perf_counter_ns()

        serialization_start = challenge_end
        proof = bytearray(_header(self.parameters))
        for challenge, view in zip(challenges, views):
            checked = challenge
            neighbour = (challenge + 1) % 3
            hidden = (challenge + 2) % 3
            proof.extend(
                ROUND_FIXED.pack(
                    challenge,
                    view.commitments[hidden],
                    view.outputs[hidden],
                    view.seeds[checked],
                    view.input_shares[checked],
                    view.seeds[neighbour],
                    view.input_shares[neighbour],
                )
            )
            proof.extend(view.transcripts[neighbour])
        serialized = bytes(proof)
        serialization_end = time.perf_counter_ns()
        if len(serialized) != self.parameters.proof_bytes:
            raise AssertionError("canonical proof length accounting drift")
        metrics = ProofGenerationMetrics(
            randomness_and_sharing_seconds=(sharing_end - sharing_start) / 1e9,
            mpc_simulation_and_commitment_seconds=(
                simulation_end - simulation_start
            )
            / 1e9,
            fiat_shamir_challenge_seconds=(
                challenge_end - challenge_start
            )
            / 1e9,
            proof_serialization_seconds=(
                serialization_end - serialization_start
            )
            / 1e9,
            online_prove_seconds=(serialization_end - total_start) / 1e9,
            proof_bytes=len(serialized),
        )
        return serialized, metrics

    def verify(
        self,
        statement: AccessProofStatementV2,
        proof: bytes,
    ) -> bool:
        try:
            return self._verify_strict(statement, proof)
        except Exception:
            return False

    def _verify_strict(
        self,
        statement: AccessProofStatementV2,
        proof: bytes,
    ) -> bool:
        if not isinstance(statement, AccessProofStatementV2):
            raise TypeError("statement must be AccessProofStatementV2")
        if statement.access_pp_digest != self.parameters.digest:
            raise ProofEncodingError(
                "statement access_pp_digest does not select backend parameters"
            )
        if not isinstance(proof, bytes):
            raise TypeError("proof must be bytes")
        if len(proof) != self.parameters.proof_bytes:
            raise ProofEncodingError("proof length mismatch")
        (
            magic,
            format_version,
            proof_suite_id,
            parameter_version,
            soundness_bits,
            repetitions,
            parameter_digest,
        ) = HEADER.unpack_from(proof)
        expected_header = (
            PROOF_MAGIC,
            PROOF_FORMAT_VERSION,
            self.parameters.proof_suite_id,
            self.parameters.parameter_version,
            self.parameters.claimed_classical_soundness_bits,
            self.parameters.repetitions,
            self.parameters.digest,
        )
        if (
            magic,
            format_version,
            proof_suite_id,
            parameter_version,
            soundness_bits,
            repetitions,
            parameter_digest,
        ) != expected_header:
            raise ProofEncodingError("proof parameter or version mismatch")

        offset = HEADER.size
        parsed_rounds = []
        for _ in range(self.parameters.repetitions):
            if offset + ROUND_FIXED.size + VIEW_TRANSCRIPT_BYTES > len(proof):
                raise ProofEncodingError("truncated round proof")
            fixed = ROUND_FIXED.unpack_from(proof, offset)
            offset += ROUND_FIXED.size
            neighbour_transcript = proof[
                offset : offset + VIEW_TRANSCRIPT_BYTES
            ]
            offset += VIEW_TRANSCRIPT_BYTES
            if fixed[0] not in (0, 1, 2):
                raise ProofEncodingError("invalid ternary challenge")
            parsed_rounds.append((*fixed, neighbour_transcript))
        if offset != len(proof):
            raise ProofEncodingError("trailing proof bytes")

        statement_digest = _statement_digest(statement)
        commitments: list[tuple[bytes, bytes, bytes]] = []
        outputs: list[tuple[bytes, bytes, bytes]] = []
        claimed_challenges: list[int] = []
        expected_output = statement.holder_hash + statement.holder_binding_tag
        for repetition, parsed in enumerate(parsed_rounds):
            (
                challenge,
                hidden_commitment,
                hidden_output,
                checked_seed,
                checked_input,
                neighbour_seed,
                neighbour_input,
                neighbour_transcript,
            ) = parsed
            checked = challenge
            neighbour = (challenge + 1) % 3
            hidden = (challenge + 2) % 3
            checked_transcript, checked_output, neighbour_output = (
                _replay_opened_pair(
                    checked_party=checked,
                    checked_seed=checked_seed,
                    checked_input=checked_input,
                    neighbour_seed=neighbour_seed,
                    neighbour_input=neighbour_input,
                    neighbour_transcript=neighbour_transcript,
                    parameters=self.parameters,
                    statement_digest=statement_digest,
                    request_core_digest=statement.request_core_digest,
                    repetition=repetition,
                )
            )
            round_outputs = [b"", b"", b""]
            round_outputs[checked] = checked_output
            round_outputs[neighbour] = neighbour_output
            round_outputs[hidden] = hidden_output
            if _xor_bytes(*round_outputs) != expected_output:
                return False

            round_commitments = [b"", b"", b""]
            round_commitments[checked] = _view_commitment(
                parameters=self.parameters,
                statement_digest=statement_digest,
                repetition=repetition,
                party=checked,
                seed=checked_seed,
                input_share=checked_input,
                transcript=checked_transcript,
                output=checked_output,
            )
            round_commitments[neighbour] = _view_commitment(
                parameters=self.parameters,
                statement_digest=statement_digest,
                repetition=repetition,
                party=neighbour,
                seed=neighbour_seed,
                input_share=neighbour_input,
                transcript=neighbour_transcript,
                output=neighbour_output,
            )
            round_commitments[hidden] = hidden_commitment
            commitments.append(
                (
                    round_commitments[0],
                    round_commitments[1],
                    round_commitments[2],
                )
            )
            outputs.append(
                (round_outputs[0], round_outputs[1], round_outputs[2])
            )
            claimed_challenges.append(challenge)

        expected_challenges = _derive_challenges(
            self.parameters,
            statement,
            commitments,
            outputs,
        )
        return tuple(claimed_challenges) == expected_challenges
