"""Frozen public ABI for the PQ-SAT Blind-UOV/CAP v0.1 profile.

The package root exports the frozen parameter, packing, and executable
relation ABIs.  The complete CAP prover, verifier, and ticket adapter remain
unimplemented.
"""

from importlib import import_module

from .parameters import (
    ConcreteProfile,
    ConsistencyProfile,
    DomainSpec,
    EvaluationDomainGroup,
    EvaluationDomainKind,
    EvaluationDomainProfile,
    FieldId,
    FieldSpec,
    HiddenChallengeGroup,
    HiddenChallengeProfile,
    OneTreeProfile,
    ProfileSource,
    ProfileValidationError,
    RelationProfile,
    SymmetricProfile,
    TreeGroup,
    load_profile_manifest,
    profile_fingerprint,
    validate_profile,
)
from .consistency import (
    ConsistencyEncodingError,
    XiPolynomial,
    XiPolynomials,
    decode_xi_polynomials,
    encode_xi_polynomials,
)
from .transcript import (
    HiddenPositions,
    derive_admissible_hidden_positions,
    derive_hidden_positions,
    hidden_positions_are_admissible,
)
from .response import (
    TCitHElementGroups,
    ResponseEncodingError,
    decode_h3_q_and_qbar,
    decode_tcith_responses,
    encode_h3_q_and_qbar,
    encode_tcith_responses,
)

# Keep the pre-existing transcript/field lane import boundary intact.  These
# names are resolved on first package-root access, so ``import ...transcript``
# does not eagerly import the relation and its field arithmetic dependencies.
_RELATION_EXPORTS = frozenset(
    {
        "CAPStatement",
        "CAPWitness",
        "ConstraintPolynomials",
        "CorrectionData",
        "QPolynomials",
        "RelationError",
        "RepetitionCorrection",
        "RepetitionPolynomials",
        "apply_delta_z",
        "build_consistency_polynomials",
        "build_constraint_polynomials",
        "build_q_and_qbar",
        "correct_repetitions",
        "decode_correction_data",
        "derive_r_and_delta_z",
        "encode_correction_data",
        "evaluate_lifted_constraints",
        "reconstruct_opened_q",
        "relation_holds",
        "witness_bits",
        "witness_bytes",
    }
)


def __getattr__(name: str):
    if name in _RELATION_EXPORTS:
        relation = import_module(f"{__name__}.relation")
        value = getattr(relation, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = (
    "ConcreteProfile",
    "CAPStatement",
    "CAPWitness",
    "ConsistencyEncodingError",
    "ConsistencyProfile",
    "ConstraintPolynomials",
    "CorrectionData",
    "DomainSpec",
    "EvaluationDomainGroup",
    "EvaluationDomainKind",
    "EvaluationDomainProfile",
    "FieldId",
    "FieldSpec",
    "HiddenChallengeGroup",
    "HiddenChallengeProfile",
    "HiddenPositions",
    "OneTreeProfile",
    "ProfileSource",
    "ProfileValidationError",
    "QPolynomials",
    "RelationError",
    "RelationProfile",
    "RepetitionCorrection",
    "RepetitionPolynomials",
    "SymmetricProfile",
    "TCitHElementGroups",
    "TreeGroup",
    "XiPolynomial",
    "XiPolynomials",
    "ResponseEncodingError",
    "apply_delta_z",
    "build_consistency_polynomials",
    "build_constraint_polynomials",
    "build_q_and_qbar",
    "correct_repetitions",
    "decode_correction_data",
    "decode_h3_q_and_qbar",
    "decode_xi_polynomials",
    "decode_tcith_responses",
    "encode_h3_q_and_qbar",
    "encode_tcith_responses",
    "encode_xi_polynomials",
    "derive_admissible_hidden_positions",
    "derive_hidden_positions",
    "derive_r_and_delta_z",
    "encode_correction_data",
    "hidden_positions_are_admissible",
    "evaluate_lifted_constraints",
    "load_profile_manifest",
    "profile_fingerprint",
    "reconstruct_opened_q",
    "relation_holds",
    "validate_profile",
    "witness_bits",
    "witness_bytes",
)
