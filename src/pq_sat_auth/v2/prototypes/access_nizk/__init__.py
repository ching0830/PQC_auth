"""Experimental MPC-in-the-Head proof prototype for exact ``R_access``.

Nothing in this package is approved for a production acceptance path.
"""

from .mpcith import (
    MPCITHAccessNIZKBackendV01,
    ProofGenerationMetrics,
    RelationNotSatisfied,
)
from .parameters import BENCHMARK_PARAMETERS_V01, TEST_PARAMETERS_V01
from .adapter import (
    EXPERIMENTAL_PROOF_REGISTRY_V01,
    build_verifier_owned_statement_v01,
    prove_request_v01,
    verify_request_v01,
)

EXPERIMENTAL_REFERENCE_ONLY = True
PRODUCTION_READY = False
SIMULATION_EXTRACTABLE = False
PROOF_CLOSED = False
PRODUCTION_CLOSED = False

__all__ = [
    "BENCHMARK_PARAMETERS_V01",
    "EXPERIMENTAL_PROOF_REGISTRY_V01",
    "MPCITHAccessNIZKBackendV01",
    "ProofGenerationMetrics",
    "RelationNotSatisfied",
    "TEST_PARAMETERS_V01",
    "build_verifier_owned_statement_v01",
    "prove_request_v01",
    "verify_request_v01",
]
