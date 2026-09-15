"""Closed experimental parameter identities for the access-NIZK prototype."""

from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass


PARAMETER_DOMAIN = b"PQ-SAT/R-ACCESS-MPCITH-PARAMETERS/v0.1"
CONSTRUCTION_ID = b"3-party-ZKBoo-family-XOR-sharing-FS-SHAKE256"
CIRCUIT_ID = b"PQSAT-R-ACCESS-EXACT-SHAKE256-BOOLEAN-v0.1"
PROOF_SUITE_ID = 0xFFFE
PARAMETER_VERSION = 1
SEED_BYTES = 32
COMMITMENT_BYTES = 32
OUTPUT_BYTES = 64
VIEW_TRANSCRIPT_BYTES = 9_600
PROOF_MAGIC = b"PQSAT-Z1"
PROOF_FORMAT_VERSION = 1


@dataclass(frozen=True)
class MPCITHParametersV01:
    """One immutable research parameter set.

    The soundness figure is the classical interactive ``(2/3)^t`` accounting
    only.  It is not a claim about Fiat--Shamir in the QROM, simulation
    extractability, or the security of this unaudited implementation.
    """

    name: str
    repetitions: int
    claimed_classical_soundness_bits: int
    test_only: bool
    proof_suite_id: int = PROOF_SUITE_ID
    parameter_version: int = PARAMETER_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("parameter name must be a non-empty string")
        if isinstance(self.repetitions, bool) or not 1 <= self.repetitions <= 4096:
            raise ValueError("repetitions must be in [1, 4096]")
        if (
            isinstance(self.claimed_classical_soundness_bits, bool)
            or self.claimed_classical_soundness_bits < 0
        ):
            raise ValueError("claimed soundness bits must be non-negative")
        if type(self.test_only) is not bool:
            raise TypeError("test_only must be bool")
        if not 0 <= self.proof_suite_id < (1 << 16):
            raise ValueError("proof_suite_id does not fit uint16")
        if not 0 <= self.parameter_version < (1 << 16):
            raise ValueError("parameter_version does not fit uint16")
        available = math.floor(self.repetitions * math.log2(3 / 2))
        if self.claimed_classical_soundness_bits > available:
            raise ValueError("claimed soundness exceeds (2/3)^t accounting")

    @property
    def descriptor(self) -> bytes:
        name = self.name.encode("ascii")
        return b"".join(
            (
                PARAMETER_DOMAIN,
                struct.pack(
                    ">HHIHB",
                    self.proof_suite_id,
                    self.parameter_version,
                    self.repetitions,
                    self.claimed_classical_soundness_bits,
                    int(self.test_only),
                ),
                len(name).to_bytes(2, "big"),
                name,
                len(CONSTRUCTION_ID).to_bytes(2, "big"),
                CONSTRUCTION_ID,
                len(CIRCUIT_ID).to_bytes(2, "big"),
                CIRCUIT_ID,
                struct.pack(
                    ">HHHI",
                    SEED_BYTES,
                    COMMITMENT_BYTES,
                    OUTPUT_BYTES,
                    VIEW_TRANSCRIPT_BYTES,
                ),
            )
        )

    @property
    def digest(self) -> bytes:
        return hashlib.sha256(self.descriptor).digest()

    @property
    def round_proof_bytes(self) -> int:
        # challenge + hidden commitment/output + two seeds/input shares +
        # the unchecked opened-neighbour transcript.
        return (
            1
            + COMMITMENT_BYTES
            + OUTPUT_BYTES
            + (2 * SEED_BYTES)
            + (2 * 32)
            + VIEW_TRANSCRIPT_BYTES
        )

    @property
    def proof_bytes(self) -> int:
        return 52 + self.repetitions * self.round_proof_bytes


TEST_PARAMETERS_V01 = MPCITHParametersV01(
    name="PQSAT-R-ACCESS-MPCITH-TEST-7-v0.1",
    repetitions=7,
    claimed_classical_soundness_bits=4,
    test_only=True,
)

BENCHMARK_PARAMETERS_V01 = MPCITHParametersV01(
    name="PQSAT-R-ACCESS-MPCITH-L1-219-v0.1",
    repetitions=219,
    claimed_classical_soundness_bits=128,
    test_only=False,
)


def parameters_manifest(parameters: MPCITHParametersV01) -> dict[str, object]:
    return {
        "name": parameters.name,
        "proof_suite_id": parameters.proof_suite_id,
        "parameter_version": parameters.parameter_version,
        "parameter_digest_sha256": parameters.digest.hex(),
        "construction_id": CONSTRUCTION_ID.decode("ascii"),
        "circuit_id": CIRCUIT_ID.decode("ascii"),
        "repetitions": parameters.repetitions,
        "classical_interactive_soundness_error": f"(2/3)^{parameters.repetitions}",
        "claimed_classical_soundness_bits": (
            parameters.claimed_classical_soundness_bits
        ),
        "qrom_fiat_shamir_proof_closed": False,
        "simulation_extractable": False,
        "seed_bytes": SEED_BYTES,
        "commitment_bytes": COMMITMENT_BYTES,
        "output_bytes": OUTPUT_BYTES,
        "opened_neighbour_transcript_bytes_per_round": VIEW_TRANSCRIPT_BYTES,
        "round_proof_bytes": parameters.round_proof_bytes,
        "canonical_proof_bytes": parameters.proof_bytes,
        "test_only": parameters.test_only,
        "experimental_reference_only": True,
        "production_ready": False,
    }
