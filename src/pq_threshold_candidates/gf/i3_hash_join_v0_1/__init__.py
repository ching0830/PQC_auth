"""Private CAP candidate to real H_RBBC consumer; full I3 remains unresolved."""

from .evaluator import (
    ResearchI3HashEvaluation, ResearchI3HashStatus,
    evaluate_i3_hash_candidate_research,
)

__all__ = [
    "ResearchI3HashEvaluation", "ResearchI3HashStatus",
    "evaluate_i3_hash_candidate_research",
]
