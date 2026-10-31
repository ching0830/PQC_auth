"""Closed, immutable Blind-UOV/CAP parameter profile for PQ-SAT V3.

The loader accepts one exact, repository-tracked concrete-profile manifest.
Parsing is strict before both the SHA-256 and Git-blob identities are checked;
the covered parameter document is then canonicalized and fingerprinted again.
No environment variable, historical profile, or fallback configuration is
consulted.

This module intentionally contains no field arithmetic, transcript, tree,
relation, codec, prover, verifier, or ticket-adapter implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from pathlib import Path
from typing import Final


class ProfileValidationError(ValueError):
    """A controlled, fail-closed profile-manifest rejection."""


class FieldId(str, Enum):
    """Field identifiers frozen by the concrete profile."""

    F_2 = "F_2"
    GF_2_8 = "GF(2^8)"
    GF_2_11 = "GF(2^11)"
    GF_2_12 = "GF(2^12)"
    GF_2_64 = "GF(2^64)"


class EvaluationDomainKind(str, Enum):
    """Frozen party-evaluation-domain construction identifiers."""

    FINITE_NONZERO_THEN_INFINITY = "zero_based_finite_nonzero_then_infinity_v0_1"


@dataclass(frozen=True, slots=True)
class FieldSpec:
    """One polynomial-basis extension field; arithmetic is out of scope."""

    field_id: FieldId
    degree: int
    irreducible_polynomial: str
    irreducible_polynomial_integer: int
    encoded_bytes: int

    @property
    def element_upper_bound(self) -> int:
        """Exclusive upper bound for canonical field-element integers."""

        return 1 << self.degree


@dataclass(frozen=True, slots=True)
class TreeGroup:
    group_id: int
    repetition_indices: tuple[int, ...]
    leaves: int
    mu: int
    rho: int

    @property
    def repetitions(self) -> int:
        return len(self.repetition_indices)


@dataclass(frozen=True, slots=True)
class EvaluationDomainGroup:
    """Evaluation-domain binding for one concrete tree group."""

    group_id: int
    field_id: FieldId
    party_count: int
    mu: int
    finite_position_first: int
    finite_position_last: int
    infinity_position: int


@dataclass(frozen=True, slots=True)
class EvaluationDomainProfile:
    """Frozen corrective TCitH evaluation-point ABI."""

    kind: EvaluationDomainKind
    position_indexing: str
    secret_point: int
    finite_mapping: str
    finite_reciprocal: str
    infinity_reciprocal_coordinate: int
    infinity_evaluation: str
    groups: tuple[EvaluationDomainGroup, ...]
    pqsat_corrective_instantiation: bool
    blind_uov_appendix_a3_bit_exact: bool


@dataclass(frozen=True, slots=True)
class HiddenChallengeGroup:
    """Raw and accepted hidden-position domains for one tree group."""

    group_id: int
    repetition_indices: tuple[int, ...]
    raw_position_first: int
    raw_position_last: int
    raw_challenge_count: int
    accepted_position_first: int
    accepted_position_last: int
    forbidden_infinity_position: int
    effective_challenge_count: int


@dataclass(frozen=True, slots=True)
class HiddenChallengeProfile:
    """Finite-only admissibility and bounded producer/verifier work policy."""

    groups: tuple[HiddenChallengeGroup, ...]
    raw_domain: bytes
    raw_rejection_sampling: bool
    raw_modulo_n_minus_one: bool
    raw_remapping: bool
    infinity_leaf_must_be_opened: bool
    producer_nonce_start: int
    producer_predicate_count: int
    restart_with_fresh_commitment_randomness: bool
    verifier_parse_received_nonce_only: bool
    verifier_enumerate_earlier_nonces: bool
    verifier_require_global_minimality: bool
    verifier_work_depends_on_nonce_numeric_value: bool
    verifier_pow_evaluations: int
    verifier_raw_derivations: int
    verifier_finite_checks: int
    verifier_frontier_derivations: int


@dataclass(frozen=True, slots=True)
class OneTreeProfile:
    active_leaves: int
    total_nodes: int
    root_node_index: int
    leaf_base_index: int
    node_index_first: int
    node_index_last: int
    frontier_count_minimum: int
    frontier_count_maximum: int
    frontier_seed_bytes: int
    inactive_or_padding_leaves: int


@dataclass(frozen=True, slots=True)
class RelationProfile:
    cap_field: FieldId
    cap_field_order_q: int
    uov_field: FieldId
    n_variables: int
    m_equations: int
    vinegar_variables: int
    r_bits: int
    z_bits: int
    witness_bits: int
    constraints_over_f2: int
    degree_d: int


@dataclass(frozen=True, slots=True)
class ConsistencyProfile:
    kappa: int
    evaluation_count_t: int
    eta: int
    witness_elements_over_f2: int
    polynomial_degree_upper_bound_d: int
    exact_numerator: int
    denominator_power_of_two: int
    strict_upper_bound_bits: int


@dataclass(frozen=True, slots=True)
class DomainSpec:
    purpose: str
    label: bytes


@dataclass(frozen=True, slots=True)
class SymmetricProfile:
    primitive: str
    seed_bytes: int
    digest_bytes: int
    profile_fingerprint_bytes: int
    domains: tuple[DomainSpec, ...]

    def domain(self, purpose: str) -> bytes:
        """Return the frozen label for a known purpose; reject unknown uses."""

        if type(purpose) is not str:
            raise ProfileValidationError("domain purpose must be a string")
        for item in self.domains:
            if item.purpose == purpose:
                return item.label
        raise ProfileValidationError(f"unknown domain purpose: {purpose!r}")


@dataclass(frozen=True, slots=True)
class ProfileSource:
    repository_path: str
    sha256: bytes
    git_blob_oid: str
    integration_base: str


@dataclass(frozen=True, slots=True)
class ConcreteProfile:
    """The complete parameter ABI exposed to all later implementation lanes."""

    profile_id: str
    profile_version_u16: int
    suite_id_u16: int
    fingerprint: bytes
    relation: RelationProfile
    fields: tuple[FieldSpec, ...]
    tau: int
    tree_groups: tuple[TreeGroup, ...]
    evaluation_domain: EvaluationDomainProfile
    hidden_challenge: HiddenChallengeProfile
    opened_seed_upper_bound_topen: int
    explicit_pow_bits_w: int
    accounted_frontier_security_bits: int
    one_tree: OneTreeProfile
    consistency: ConsistencyProfile
    symmetric: SymmetricProfile
    source: ProfileSource
    _parameter_document_json: bytes

    def field(self, field_id: FieldId) -> FieldSpec:
        """Return a frozen field specification; reject unknown identifiers."""

        if type(field_id) is not FieldId:
            raise ProfileValidationError("field_id must be a FieldId")
        for item in self.fields:
            if item.field_id is field_id:
                return item
        raise ProfileValidationError(f"field has no extension specification: {field_id.value}")


PROFILE_ID: Final = "pqsat-blind-uov-iii-shorter-tcith-shake256-v0.1"
PROFILE_VERSION_U16: Final = 1
SUITE_ID_U16: Final = 0xFF32
PROFILE_FINGERPRINT: Final = bytes.fromhex(
    "fc6706429f10d3bcc5600d4b427ca604a19f22c31ec35b171f40513b1a4bcb25"
)
PROFILE_FINGERPRINT_DOMAIN: Final = b"PQSAT-BUOV-CAP-0.1/PROFILE-FP"

_REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[3]
_SOURCE_RELATIVE_PATH: Final = (
    "manifests/access_v3/pqsat_blind_uov_cap_concrete_profile_v0_1.json"
)
DEFAULT_PROFILE_MANIFEST: Final = _REPOSITORY_ROOT / _SOURCE_RELATIVE_PATH
_SOURCE_BYTES: Final = 48060
_SOURCE_SHA256: Final = bytes.fromhex(
    "2b1e18dfc3f22c22214985310e71f26ddd78d289133ce52ea126fab5deb38f26"
)
_SOURCE_GIT_BLOB: Final = "dea2e853fb78ddcd0d432f3e5c17d8b804902815"
_INTEGRATION_BASE: Final = "cd0c60fd2bcd9d83eb919c26e27adda848c52a09"
_MAX_MANIFEST_BYTES: Final = 1 << 20

_EXPECTED_FIELDS: Final = (
    FieldSpec(FieldId.GF_2_8, 8, "x^8+x^4+x^3+x+1", 283, 1),
    FieldSpec(FieldId.GF_2_11, 11, "x^11+x^2+1", 2053, 2),
    FieldSpec(FieldId.GF_2_12, 12, "x^12+x^3+1", 4105, 2),
    FieldSpec(
        FieldId.GF_2_64,
        64,
        "x^64+x^4+x^3+x+1",
        0x1000000000000001B,
        8,
    ),
)

_EXPECTED_GROUPS: Final = (
    TreeGroup(0, (0, 1), 4096, 12, 16),
    TreeGroup(1, tuple(range(2, 18)), 2048, 11, 18),
)

_EXPECTED_EVALUATION_GROUPS: Final = (
    EvaluationDomainGroup(0, FieldId.GF_2_12, 4096, 12, 0, 4094, 4095),
    EvaluationDomainGroup(1, FieldId.GF_2_11, 2048, 11, 0, 2046, 2047),
)

_EXPECTED_EVALUATION_DOMAIN: Final = EvaluationDomainProfile(
    EvaluationDomainKind.FINITE_NONZERO_THEN_INFINITY,
    "zero_based_canonical",
    0,
    "phi(position)=position+1",
    "gf_inv(phi(position))",
    0,
    "P(infinity)=mask",
    _EXPECTED_EVALUATION_GROUPS,
    True,
    False,
)

_EXPECTED_HIDDEN_CHALLENGE_GROUPS: Final = (
    HiddenChallengeGroup(0, (0, 1), 0, 4095, 4096, 0, 4094, 4095, 4095),
    HiddenChallengeGroup(
        1, tuple(range(2, 18)), 0, 2047, 2048, 0, 2046, 2047, 2047
    ),
)

_EXPECTED_HIDDEN_CHALLENGE: Final = HiddenChallengeProfile(
    _EXPECTED_HIDDEN_CHALLENGE_GROUPS,
    b"PQSAT-BUOV-CAP-0.1/OPEN-INDEX",
    False,
    False,
    False,
    True,
    0,
    3,
    True,
    True,
    False,
    False,
    False,
    1,
    1,
    1,
    1,
)

_EXPECTED_DOMAINS: Final = (
    DomainSpec("profile_fingerprint", b"PQSAT-BUOV-CAP-0.1/PROFILE-FP"),
    DomainSpec("seed_derivation", b"PQSAT-BUOV-CAP-0.1/SEED-DERIVE"),
    DomainSpec("tape_expansion", b"PQSAT-BUOV-CAP-0.1/TAPE-EXPAND"),
    DomainSpec("leaf_commitment", b"PQSAT-BUOV-CAP-0.1/LEAF-COMMIT"),
    DomainSpec("fiat_shamir_h1", b"PQSAT-BUOV-CAP-0.1/FS-H1"),
    DomainSpec(
        "consistency_matrix", b"PQSAT-BUOV-CAP-0.1/CONSISTENCY-MATRIX"
    ),
    DomainSpec("fiat_shamir_h2_prime", b"PQSAT-BUOV-CAP-0.1/FS-H2-PRIME"),
    DomainSpec("fiat_shamir_h2", b"PQSAT-BUOV-CAP-0.1/FS-H2"),
    DomainSpec("gamma_derivation", b"PQSAT-BUOV-CAP-0.1/GAMMA"),
    DomainSpec("fiat_shamir_h3", b"PQSAT-BUOV-CAP-0.1/FS-H3"),
    DomainSpec("proof_of_work", b"PQSAT-BUOV-CAP-0.1/POW"),
    DomainSpec("hidden_opening_indices", b"PQSAT-BUOV-CAP-0.1/OPEN-INDEX"),
)


def _fail(message: str) -> ProfileValidationError:
    return ProfileValidationError(message)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _fail(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_non_integer_number(value: str) -> object:
    raise _fail(f"non-integer JSON number is forbidden: {value}")


def _reject_surrogates(value: object) -> None:
    if type(value) is str:
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise _fail("unpaired Unicode surrogate is forbidden")
    elif type(value) is dict:
        for key, child in value.items():
            _reject_surrogates(key)
            _reject_surrogates(child)
    elif type(value) is list:
        for child in value:
            _reject_surrogates(child)


def _parse_json(raw: bytes, *, label: str) -> dict[str, object]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_MANIFEST_BYTES:
        raise _fail(f"{label} exceeds the strict JSON byte boundary")
    try:
        parsed = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_non_integer_number,
            parse_constant=_reject_non_integer_number,
        )
        _reject_surrogates(parsed)
    except ProfileValidationError:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise _fail(f"{label} is not one complete strict JSON value: {error}") from error
    if type(parsed) is not dict:
        raise _fail(f"{label} must be a JSON object")
    return parsed


def _require_object(
    value: object, name: str, expected_keys: frozenset[str] | None = None
) -> dict[str, object]:
    if type(value) is not dict:
        raise _fail(f"{name} must be an object")
    if expected_keys is not None and frozenset(value) != expected_keys:
        missing = sorted(expected_keys - value.keys())
        unknown = sorted(value.keys() - expected_keys)
        raise _fail(f"{name} has missing={missing!r}, unknown={unknown!r}")
    return value


def _require_array(value: object, name: str) -> list[object]:
    if type(value) is not list:
        raise _fail(f"{name} must be an array")
    return value


def _require_int(
    value: object, name: str, *, minimum: int = 0, maximum: int | None = None
) -> int:
    if type(value) is not int:
        raise _fail(f"{name} must be an integer and bool is forbidden")
    if value < minimum or (maximum is not None and value > maximum):
        raise _fail(f"{name} is out of range")
    return value


def _require_text(value: object, name: str) -> str:
    if type(value) is not str or not value:
        raise _fail(f"{name} must be a non-empty string")
    return value


def _require_bool(value: object, name: str) -> bool:
    if type(value) is not bool:
        raise _fail(f"{name} must be a boolean")
    return value


def _require_hex_int(value: object, name: str) -> int:
    encoded = _require_text(value, name)
    if not encoded.startswith("0x"):
        raise _fail(f"{name} must use canonical 0x-prefixed hexadecimal")
    try:
        return int(encoded, 16)
    except ValueError as error:
        raise _fail(f"{name} is not a hexadecimal integer") from error


def _canonical_parameter_json(parameters: object) -> bytes:
    try:
        return json.dumps(
            parameters,
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise _fail(f"parameter document cannot be canonicalized: {error}") from error


def _tuple_encode(domain: bytes, fields: tuple[bytes, ...]) -> bytes:
    if type(domain) is not bytes or len(domain) > 0xFFFF:
        raise _fail("fingerprint domain is invalid")
    if type(fields) is not tuple or len(fields) > 0xFFFF:
        raise _fail("fingerprint field tuple is invalid")
    encoded = bytearray(len(domain).to_bytes(2, "big"))
    encoded.extend(domain)
    encoded.extend(len(fields).to_bytes(2, "big"))
    for field in fields:
        if type(field) is not bytes or len(field) > 0xFFFFFFFF:
            raise _fail("fingerprint tuple field is invalid")
        encoded.extend(len(field).to_bytes(4, "big"))
        encoded.extend(field)
    return bytes(encoded)


def _fingerprint_parameter_json(canonical_parameter_json: bytes) -> bytes:
    encoded = _tuple_encode(
        PROFILE_FINGERPRINT_DOMAIN, (canonical_parameter_json,)
    )
    return hashlib.shake_256(encoded).digest(32)


def _git_blob_oid(raw: bytes) -> str:
    header = f"blob {len(raw)}\0".encode("ascii")
    return hashlib.sha1(header + raw, usedforsecurity=False).hexdigest()


def _validate_parameter_document(parameters: object) -> dict[str, object]:
    document = _require_object(
        parameters,
        "profile_parameter_document",
        frozenset(
            {
                "profile_id",
                "profile_version_u16",
                "suite_id_u16",
                "choice_rationale",
                "security",
                "uov",
                "cap",
                "fields",
                "consistency",
                "symmetric",
                "serialization",
            }
        ),
    )
    if document["profile_id"] != PROFILE_ID:
        raise _fail("wrong profile_id")
    if _require_int(
        document["profile_version_u16"], "profile_version_u16", maximum=0xFFFF
    ) != PROFILE_VERSION_U16:
        raise _fail("wrong profile version")
    if _require_int(
        document["suite_id_u16"], "suite_id_u16", maximum=0xFFFF
    ) != SUITE_ID_U16:
        raise _fail("wrong suite identifier")

    security = _require_object(
        document["security"],
        "security",
        frozenset(
            {
                "nist_category",
                "target_security_bits",
                "cap_base_field",
                "cap_base_field_order_q",
            }
        ),
    )
    if security["nist_category"] != "III":
        raise _fail("wrong NIST category")
    if _require_int(security["target_security_bits"], "target security") != 192:
        raise _fail("wrong target security")
    if security["cap_base_field"] != FieldId.F_2.value:
        raise _fail("unknown CAP field identifier")
    if _require_int(security["cap_base_field_order_q"], "q") != 2:
        raise _fail("wrong CAP base-field order")

    uov = _require_object(
        document["uov"],
        "uov",
        frozenset(
            {
                "native_field",
                "native_field_order",
                "irreducible_polynomial",
                "irreducible_polynomial_integer",
                "n_variables",
                "m_equations",
                "cap_relation_constraints_over_F2",
                "cap_relation_constraint_derivation",
                "cap_relation_constraint_order",
                "cap_relation_equation",
                "vinegar_variables",
                "r_bits",
                "z_bits",
                "cap_witness_bits",
                "witness_concatenation",
                "standalone_uov_salt_in_z",
            }
        ),
    )
    if uov["native_field"] != FieldId.GF_2_8.value:
        raise _fail("unknown UOV field identifier")
    expected_uov_integers = (
        ("native_field_order", 256),
        ("irreducible_polynomial_integer", 283),
        ("n_variables", 184),
        ("m_equations", 72),
        ("vinegar_variables", 112),
        ("r_bits", 576),
        ("z_bits", 1472),
        ("cap_witness_bits", 2048),
        ("cap_relation_constraints_over_F2", 576),
    )
    for name, expected in expected_uov_integers:
        if _require_int(uov[name], f"uov.{name}") != expected:
            raise _fail(f"wrong uov.{name}")
    if uov["irreducible_polynomial"] != _EXPECTED_FIELDS[0].irreducible_polynomial:
        raise _fail("wrong GF(2^8) polynomial")
    if _require_bool(uov["standalone_uov_salt_in_z"], "standalone salt"):
        raise _fail("standalone UOV salt must not be part of z")

    cap = _require_object(
        document["cap"],
        "cap",
        frozenset(
            {
                "tradeoff",
                "backend",
                "backend_selection_reason",
                "degree_d",
                "tau",
                "tree_groups",
                "mixed_profile_scalar_rho",
                "opened_seed_upper_bound_topen",
                "explicit_pow_bits_w",
                "accounted_frontier_security_bits",
                "soundness_accounted_total_pow_bits",
                "historical_paper_row_comparison",
                "evaluation_domain",
                "hidden_challenge",
                "one_tree",
            }
        ),
    )
    if cap["tradeoff"] != "Shorter" or cap["backend"] != "TCitH":
        raise _fail("wrong CAP tradeoff or backend")
    for name, expected in (
        ("degree_d", 2),
        ("tau", 18),
        ("opened_seed_upper_bound_topen", 174),
        ("explicit_pow_bits_w", 13),
        ("accounted_frontier_security_bits", 0),
        ("soundness_accounted_total_pow_bits", 13),
    ):
        if _require_int(cap[name], f"cap.{name}") != expected:
            raise _fail(f"wrong cap.{name}")
    if cap["mixed_profile_scalar_rho"] is not None:
        raise _fail("mixed profile must not expose a scalar rho")

    raw_groups = _require_array(cap["tree_groups"], "cap.tree_groups")
    if len(raw_groups) != 2:
        raise _fail("exactly two tree groups are required")
    group_zero = _require_object(
        raw_groups[0],
        "tree_groups[0]",
        frozenset(
            {
                "group_id",
                "repetitions",
                "repetition_indices",
                "leaves_per_tree",
                "mu",
                "rho",
                "rho_derivation",
            }
        ),
    )
    group_one = _require_object(
        raw_groups[1],
        "tree_groups[1]",
        frozenset(
            {
                "group_id",
                "repetitions",
                "repetition_index_first",
                "repetition_index_last",
                "leaves_per_tree",
                "mu",
                "rho",
                "rho_derivation",
            }
        ),
    )
    group_zero_indices = tuple(
        _require_int(item, "group 0 repetition index")
        for item in _require_array(group_zero["repetition_indices"], "indices")
    )
    if group_zero_indices != (0, 1):
        raise _fail("group 0 repetition coverage is wrong")
    for raw_group, expected_group in zip(raw_groups, _EXPECTED_GROUPS, strict=True):
        group = _require_object(raw_group, "tree group")
        for name, expected in (
            ("group_id", expected_group.group_id),
            ("repetitions", expected_group.repetitions),
            ("leaves_per_tree", expected_group.leaves),
            ("mu", expected_group.mu),
            ("rho", expected_group.rho),
        ):
            if _require_int(group[name], f"tree_group.{name}") != expected:
                raise _fail(f"wrong tree_group.{name}")
    if (
        _require_int(group_one["repetition_index_first"], "group 1 first") != 2
        or _require_int(group_one["repetition_index_last"], "group 1 last") != 17
    ):
        raise _fail("group 1 repetition coverage is wrong")

    evaluation = _require_object(
        cap["evaluation_domain"],
        "cap.evaluation_domain",
        frozenset(
            {
                "kind",
                "position_indexing",
                "secret_evaluation_point",
                "groups",
                "cardinality_rule",
                "finite_points",
                "infinity_occurrences_per_group",
                "secret_point_in_party_domain",
                "reciprocal_coordinate",
                "polynomial",
                "commitment",
                "opening",
                "compatibility",
            }
        ),
    )
    if evaluation["kind"] != EvaluationDomainKind.FINITE_NONZERO_THEN_INFINITY.value:
        raise _fail("wrong evaluation-domain kind")
    if evaluation["position_indexing"] != "zero_based_canonical":
        raise _fail("wrong evaluation-domain indexing")
    secret_point = _require_object(
        evaluation["secret_evaluation_point"],
        "evaluation secret point",
        frozenset({"kind", "value"}),
    )
    if secret_point["kind"] != "finite" or _require_int(
        secret_point["value"], "evaluation secret point"
    ) != 0:
        raise _fail("the committed secret evaluation point must be finite zero")
    if _require_bool(
        evaluation["secret_point_in_party_domain"], "secret point membership"
    ):
        raise _fail("secret point zero must not be in the party domain")
    if _require_int(
        evaluation["infinity_occurrences_per_group"], "infinity occurrences"
    ) != 1:
        raise _fail("infinity must occur exactly once per group")
    if evaluation["cardinality_rule"] != "N=(2^mu-1)+1":
        raise _fail("wrong evaluation-domain cardinality rule")
    if evaluation["finite_points"] != (
        "all nonzero field elements exactly once in integer order 1..2^mu-1"
    ):
        raise _fail("wrong finite evaluation-point rule")

    raw_evaluation_groups = _require_array(
        evaluation["groups"], "evaluation-domain groups"
    )
    if len(raw_evaluation_groups) != len(_EXPECTED_EVALUATION_GROUPS):
        raise _fail("wrong evaluation-domain group count")
    evaluation_group_keys = frozenset(
        {
            "group_id",
            "field",
            "field_cardinality",
            "N",
            "mu",
            "party_domain_cardinality",
            "finite_position_first",
            "finite_position_last",
            "finite_mapping",
            "infinity_position",
        }
    )
    for index, (raw_group, expected) in enumerate(
        zip(raw_evaluation_groups, _EXPECTED_EVALUATION_GROUPS, strict=True)
    ):
        item = _require_object(
            raw_group, f"evaluation groups[{index}]", evaluation_group_keys
        )
        if item["field"] != expected.field_id.value:
            raise _fail("wrong evaluation-domain field binding")
        for name, expected_value in (
            ("group_id", expected.group_id),
            ("field_cardinality", 1 << expected.mu),
            ("N", expected.party_count),
            ("mu", expected.mu),
            ("party_domain_cardinality", expected.party_count),
            ("finite_position_first", expected.finite_position_first),
            ("finite_position_last", expected.finite_position_last),
            ("infinity_position", expected.infinity_position),
        ):
            if _require_int(item[name], f"evaluation group {name}") != expected_value:
                raise _fail(f"wrong evaluation-domain {name}")
        if item["finite_mapping"] != "phi(position)=position+1":
            raise _fail("wrong finite evaluation-point mapping")
        if expected.party_count != (1 << expected.mu) - 1 + 1:
            raise _fail("evaluation-domain N/mu binding is invalid")
        if expected.infinity_position != expected.party_count - 1:
            raise _fail("infinity is not in the final canonical position")

    reciprocal = _require_object(
        evaluation["reciprocal_coordinate"],
        "evaluation reciprocal coordinate",
        frozenset(
            {"finite", "infinity", "infinity_coordinate_is_field_inverse"}
        ),
    )
    if reciprocal["finite"] != "gf_inv(phi(position))":
        raise _fail("wrong finite reciprocal convention")
    if _require_int(reciprocal["infinity"], "infinity coordinate") != 0:
        raise _fail("wrong infinity reciprocal coordinate")
    if _require_bool(
        reciprocal["infinity_coordinate_is_field_inverse"],
        "infinity inverse classification",
    ):
        raise _fail("infinity coordinate must not be classified as a field inverse")

    polynomial = _require_object(
        evaluation["polynomial"],
        "evaluation polynomial",
        frozenset({"form", "secret_evaluation", "infinity_evaluation"}),
    )
    if polynomial != {
        "form": "P(X)=mask*X+plain",
        "secret_evaluation": "P(0)=plain",
        "infinity_evaluation": "P(infinity)=mask",
    }:
        raise _fail("wrong degree-one polynomial evaluation convention")
    commitment = _require_object(
        evaluation["commitment"],
        "evaluation commitment",
        frozenset({"plain", "mask"}),
    )
    if commitment != {
        "plain": "sum(all tapes)",
        "mask": "sum(finite-position tapes / phi(position))",
    }:
        raise _fail("wrong evaluation-domain commitment formula")
    opening = _require_object(
        evaluation["opening"],
        "evaluation opening",
        frozenset({"hidden_finite", "hidden_infinity"}),
    )
    if opening != {
        "hidden_finite": (
            "sum over i != h of "
            "(1 + phi(h)*reciprocal_coordinate(phi(i)))*tape_i"
        ),
        "hidden_infinity": "sum over finite i of tape_i/phi(i)",
    }:
        raise _fail("wrong evaluation-domain opening formula")
    compatibility = _require_object(
        evaluation["compatibility"],
        "evaluation compatibility",
        frozenset(
            {
                "pqsat_corrective_instantiation",
                "blind_uov_appendix_a3_bit_exact",
                "reason",
            }
        ),
    )
    if not _require_bool(
        compatibility["pqsat_corrective_instantiation"], "corrective instantiation"
    ):
        raise _fail("PQ-SAT corrective instantiation must be explicit")
    if _require_bool(
        compatibility["blind_uov_appendix_a3_bit_exact"],
        "Blind-UOV bit-exact claim",
    ):
        raise _fail("Blind-UOV Appendix A.3 bit-exact claim must remain false")

    hidden_challenge = _require_object(
        cap["hidden_challenge"],
        "cap.hidden_challenge",
        frozenset(
            {
                "raw_derivation",
                "accepted_finite_domains",
                "admissibility_predicate",
                "infinity_leaf_policy",
                "producer_policy",
                "verifier_single_nonce_rule",
            }
        ),
    )
    raw_derivation = _require_object(
        hidden_challenge["raw_derivation"],
        "hidden_challenge.raw_derivation",
        frozenset(
            {
                "domain",
                "input_fields",
                "output_rule",
                "rejection_sampling",
                "modulo_n_minus_one",
                "remapping",
                "position_spaces",
            }
        ),
    )
    if raw_derivation["domain"] != "PQSAT-BUOV-CAP-0.1/OPEN-INDEX":
        raise _fail("wrong raw hidden-position domain")
    if raw_derivation["input_fields"] != [
        "profile_fingerprint",
        "h3",
        "u64be(pow_nonce)",
        "u16be(repetition_index)",
    ]:
        raise _fail("wrong raw hidden-position input schedule")
    if raw_derivation["output_rule"] != (
        "read the first two XOF bytes as u16be and mask the low mu bits"
    ):
        raise _fail("wrong raw hidden-position derivation")
    for name in ("rejection_sampling", "modulo_n_minus_one", "remapping"):
        if _require_bool(raw_derivation[name], f"raw derivation {name}"):
            raise _fail(f"raw hidden-position {name} must remain false")

    raw_spaces = _require_array(
        raw_derivation["position_spaces"], "raw hidden-position spaces"
    )
    accepted_domains = _require_array(
        hidden_challenge["accepted_finite_domains"],
        "accepted finite domains",
    )
    if len(raw_spaces) != 2 or len(accepted_domains) != 2:
        raise _fail("hidden-challenge profile must contain exactly two groups")
    raw_group_keys = (
        frozenset(
            {
                "group_id",
                "repetition_indices",
                "raw_position_first",
                "raw_position_last",
                "raw_challenge_count",
            }
        ),
        frozenset(
            {
                "group_id",
                "repetition_index_first",
                "repetition_index_last",
                "raw_position_first",
                "raw_position_last",
                "raw_challenge_count",
            }
        ),
    )
    accepted_group_keys = frozenset(
        {
            "group_id",
            "accepted_position_first",
            "accepted_position_last",
            "forbidden_infinity_position",
            "effective_challenge_count",
        }
    )
    for index, expected in enumerate(_EXPECTED_HIDDEN_CHALLENGE_GROUPS):
        raw_group = _require_object(
            raw_spaces[index], f"raw hidden group {index}", raw_group_keys[index]
        )
        accepted_group = _require_object(
            accepted_domains[index],
            f"accepted hidden group {index}",
            accepted_group_keys,
        )
        for name, expected_value in (
            ("group_id", expected.group_id),
            ("raw_position_first", expected.raw_position_first),
            ("raw_position_last", expected.raw_position_last),
            ("raw_challenge_count", expected.raw_challenge_count),
        ):
            if _require_int(raw_group[name], f"raw hidden {name}") != expected_value:
                raise _fail(f"wrong raw hidden-position {name}")
        if index == 0:
            repetitions_for_group = tuple(
                _require_int(item, "raw hidden repetition")
                for item in _require_array(
                    raw_group["repetition_indices"], "raw hidden repetitions"
                )
            )
        else:
            first = _require_int(
                raw_group["repetition_index_first"], "raw hidden first repetition"
            )
            last = _require_int(
                raw_group["repetition_index_last"], "raw hidden last repetition"
            )
            repetitions_for_group = tuple(range(first, last + 1))
        if repetitions_for_group != expected.repetition_indices:
            raise _fail("wrong raw hidden-position repetition coverage")
        for name, expected_value in (
            ("group_id", expected.group_id),
            ("accepted_position_first", expected.accepted_position_first),
            ("accepted_position_last", expected.accepted_position_last),
            ("forbidden_infinity_position", expected.forbidden_infinity_position),
            ("effective_challenge_count", expected.effective_challenge_count),
        ):
            if (
                _require_int(accepted_group[name], f"accepted hidden {name}")
                != expected_value
            ):
                raise _fail(f"wrong accepted hidden-position {name}")
        if (
            expected.raw_challenge_count
            != expected.raw_position_last - expected.raw_position_first + 1
            or expected.forbidden_infinity_position != expected.raw_position_last
            or expected.accepted_position_first != expected.raw_position_first
            or expected.accepted_position_last
            != expected.forbidden_infinity_position - 1
            or expected.effective_challenge_count
            != expected.accepted_position_last - expected.accepted_position_first + 1
        ):
            raise _fail("hidden-challenge group derived counts are inconsistent")
    if hidden_challenge["admissibility_predicate"] != (
        "all 18 raw hidden positions are canonical and finite in their repetition group"
    ):
        raise _fail("wrong finite hidden-challenge admissibility predicate")
    if hidden_challenge["infinity_leaf_policy"] != (
        "the infinity leaf remains in the one-tree party domain and must always be in the opened set"
    ):
        raise _fail("wrong infinity-leaf opening policy")

    producer_policy = _require_object(
        hidden_challenge["producer_policy"],
        "hidden challenge producer policy",
        frozenset({"nonce_start", "selection", "predicates", "exhaustion_rule"}),
    )
    if _require_int(producer_policy["nonce_start"], "producer nonce start") != 0:
        raise _fail("producer nonce search must start at zero")
    if producer_policy["selection"] != "first nonce satisfying all three predicates":
        raise _fail("wrong deterministic producer selection rule")
    if producer_policy["predicates"] != [
        "explicit 13-bit PoW passes",
        "all 18 raw hidden positions are finite",
        "canonical frontier_count<=174",
    ]:
        raise _fail("wrong producer admissibility predicates")
    if producer_policy["exhaustion_rule"] != (
        "restart with fresh commitment randomness if no admissible nonce exists in the u64 range"
    ):
        raise _fail("wrong producer restart rule")

    verifier_policy = _require_object(
        hidden_challenge["verifier_single_nonce_rule"],
        "hidden challenge verifier policy",
        frozenset(
            {
                "parse_received_nonce_only",
                "enumerate_earlier_nonces",
                "require_global_minimality",
                "work_depends_on_nonce_numeric_value",
                "explicit_pow_evaluations",
                "raw_hidden_position_derivations",
                "finite_admissibility_checks",
                "canonical_frontier_derivations",
                "steps",
            }
        ),
    )
    if not _require_bool(
        verifier_policy["parse_received_nonce_only"], "parse received nonce only"
    ):
        raise _fail("verifier must parse only the received nonce")
    for name in (
        "enumerate_earlier_nonces",
        "require_global_minimality",
        "work_depends_on_nonce_numeric_value",
    ):
        if _require_bool(verifier_policy[name], f"verifier policy {name}"):
            raise _fail(f"verifier policy {name} must remain false")
    for name in (
        "explicit_pow_evaluations",
        "raw_hidden_position_derivations",
        "finite_admissibility_checks",
        "canonical_frontier_derivations",
    ):
        if _require_int(verifier_policy[name], f"verifier policy {name}") != 1:
            raise _fail(f"verifier policy {name} must equal one")
    if verifier_policy["steps"] != [
        "decode exactly 8 canonical u64be bytes",
        "evaluate the explicit PoW predicate once for the received nonce",
        "derive the 18 raw hidden positions once from the received nonce",
        "reject if any raw hidden position is the group infinity position",
        "recompute and validate the canonical frontier once and require frontier_count<=174",
        "continue normal proof verification",
    ]:
        raise _fail("wrong verifier single-nonce step order")

    one_tree = _require_object(
        cap["one_tree"],
        "cap.one_tree",
        frozenset(
            {
                "total_active_leaves",
                "total_nodes",
                "root_node_index",
                "left_child",
                "right_child",
                "leaf_node_index",
                "node_index_range_inclusive",
                "logical_leaf_mapping",
                "logical_leaf_mapping_formula",
                "frontier_definition",
                "frontier_order",
                "frontier_node_indices_serialized",
                "frontier_indices_recomputed_from_hidden_positions",
                "frontier_count_minimum",
                "frontier_count_maximum",
                "frontier_seed_bytes",
                "inactive_or_padding_leaves",
            }
        ),
    )
    for name, expected in (
        ("total_active_leaves", 40960),
        ("total_nodes", 81919),
        ("root_node_index", 0),
        ("frontier_count_minimum", 13),
        ("frontier_count_maximum", 174),
        ("frontier_seed_bytes", 24),
        ("inactive_or_padding_leaves", 0),
    ):
        if _require_int(one_tree[name], f"one_tree.{name}") != expected:
            raise _fail(f"wrong one_tree.{name}")
    node_range = _require_array(
        one_tree["node_index_range_inclusive"], "one_tree node range"
    )
    if tuple(node_range) != (0, 81918) or any(type(item) is not int for item in node_range):
        raise _fail("wrong one-tree node range")
    if _require_bool(
        one_tree["frontier_node_indices_serialized"], "serialized frontier indices"
    ):
        raise _fail("frontier node indices must not be serialized")
    if not _require_bool(
        one_tree["frontier_indices_recomputed_from_hidden_positions"],
        "recomputed frontier indices",
    ):
        raise _fail("frontier indices must be recomputed")

    fields = _require_object(
        document["fields"],
        "fields",
        frozenset({"GF_2_11", "GF_2_12", "GF_2_64"}),
    )
    for key, expected in zip(("GF_2_11", "GF_2_12", "GF_2_64"), _EXPECTED_FIELDS[1:], strict=True):
        item = _require_object(
            fields[key],
            f"fields.{key}",
            frozenset(
                {
                    "role",
                    "irreducible_polynomial",
                    (
                        "irreducible_polynomial_integer_hex"
                        if key == "GF_2_64"
                        else "irreducible_polynomial_integer"
                    ),
                    "encoded_bytes",
                }
            ),
        )
        if item["irreducible_polynomial"] != expected.irreducible_polynomial:
            raise _fail(f"wrong {key} polynomial")
        raw_modulus = (
            _require_hex_int(item["irreducible_polynomial_integer_hex"], "modulus")
            if key == "GF_2_64"
            else _require_int(item["irreducible_polynomial_integer"], "modulus")
        )
        if raw_modulus != expected.irreducible_polynomial_integer:
            raise _fail(f"wrong {key} modulus")
        if _require_int(item["encoded_bytes"], "encoded_bytes") != expected.encoded_bytes:
            raise _fail(f"wrong {key} encoded width")

    consistency = _require_object(
        document["consistency"],
        "consistency",
        frozenset(
            {
                "kappa_extension_degree",
                "evaluation_count_t",
                "digest_elements_eta_over_F2",
                "eta_derivation",
                "witness_elements_over_F2",
                "polynomial_degree_upper_bound_D",
                "polynomial_degree_derivation",
                "matrix_derivation_domain",
                "evaluation_point_derivation",
                "xi_polynomial",
            }
        ),
    )
    for name, expected in (
        ("kappa_extension_degree", 64),
        ("evaluation_count_t", 4),
        ("digest_elements_eta_over_F2", 256),
        ("witness_elements_over_F2", 2048),
        ("polynomial_degree_upper_bound_D", 31),
    ):
        if _require_int(consistency[name], f"consistency.{name}") != expected:
            raise _fail(f"wrong consistency.{name}")
    if consistency["matrix_derivation_domain"] != _EXPECTED_DOMAINS[5].label.decode("ascii"):
        raise _fail("consistency domain mismatch")
    xi_polynomial = _require_object(
        consistency["xi_polynomial"],
        "consistency.xi_polynomial",
        frozenset(
            {
                "degree",
                "constant_coefficient_field",
                "constant_elements",
                "constant_encoding",
                "linear_coefficient_field_rule",
                "field_binding_by_repetition",
                "encoding_order",
                "linear_element_order",
                "linear_bit_and_byte_order",
                "group_0_bytes",
                "group_1_bytes",
                "encoded_bytes",
                "historical_base_field_only_bytes",
                "historical_base_field_only_encoding_accepted",
                "repetition_field_selector_serialized",
                "rejection_rules",
            }
        ),
    )
    if xi_polynomial["constant_coefficient_field"] != FieldId.F_2.value:
        raise _fail("xi constant coefficient must remain over F_2")
    for name, expected in (
        ("degree", 1),
        ("constant_elements", 256),
        ("group_0_bytes", 832),
        ("group_1_bytes", 6144),
        ("encoded_bytes", 6976),
        ("historical_base_field_only_bytes", 1152),
    ):
        if _require_int(xi_polynomial[name], f"xi polynomial {name}") != expected:
            raise _fail(f"wrong xi polynomial {name}")
    if _require_bool(
        xi_polynomial["historical_base_field_only_encoding_accepted"],
        "historical xi encoding acceptance",
    ):
        raise _fail("historical 1152-byte xi encoding must be rejected")
    if _require_bool(
        xi_polynomial["repetition_field_selector_serialized"],
        "xi field selector serialization",
    ):
        raise _fail("xi field selector must be bound by repetition position")
    raw_xi_groups = _require_array(
        xi_polynomial["field_binding_by_repetition"], "xi field groups"
    )
    expected_xi_groups = (
        (0, 1, FieldId.GF_2_12.value, 12, 256, 3072, 384, 416),
        (2, 17, FieldId.GF_2_11.value, 11, 256, 2816, 352, 384),
    )
    xi_group_keys = frozenset(
        {
            "repetition_first",
            "repetition_last",
            "field",
            "mu",
            "linear_elements",
            "linear_bits",
            "linear_bytes",
            "bytes_per_polynomial",
        }
    )
    if len(raw_xi_groups) != len(expected_xi_groups):
        raise _fail("wrong xi field-group count")
    for index, (raw_group, expected) in enumerate(
        zip(raw_xi_groups, expected_xi_groups, strict=True)
    ):
        item = _require_object(raw_group, f"xi field groups[{index}]", xi_group_keys)
        if item["field"] != expected[2]:
            raise _fail("wrong xi extension-field binding")
        for name, expected_value in zip(
            (
                "repetition_first",
                "repetition_last",
                "mu",
                "linear_elements",
                "linear_bits",
                "linear_bytes",
                "bytes_per_polynomial",
            ),
            (expected[0], expected[1], *expected[3:]),
            strict=True,
        ):
            if _require_int(item[name], f"xi group {name}") != expected_value:
                raise _fail(f"wrong xi group {name}")
    rejection_rules = _require_array(
        xi_polynomial["rejection_rules"], "xi rejection rules"
    )
    if not any("1152" in rule for rule in rejection_rules if type(rule) is str):
        raise _fail("xi rejection rules do not reject the historical encoding")

    symmetric = _require_object(
        document["symmetric"],
        "symmetric",
        frozenset(
            {
                "primitive",
                "seed_bits",
                "seed_bytes",
                "digest_bits",
                "digest_bytes",
                "profile_fingerprint_bits",
                "profile_fingerprint_bytes",
                "paper_standard_setting_bit_compatible",
                "compatibility_disclosure",
                "tuple_encoding",
                "domains",
                "pow",
                "hidden_index_derivation",
                "tree_seed_and_tape_derivation",
                "transcript_schedule",
            }
        ),
    )
    if symmetric["primitive"] != "SHAKE256":
        raise _fail("wrong symmetric primitive")
    for name, expected in (
        ("seed_bits", 192),
        ("seed_bytes", 24),
        ("digest_bits", 384),
        ("digest_bytes", 48),
        ("profile_fingerprint_bits", 256),
        ("profile_fingerprint_bytes", 32),
    ):
        if _require_int(symmetric[name], f"symmetric.{name}") != expected:
            raise _fail(f"wrong symmetric.{name}")
    if _require_bool(
        symmetric["paper_standard_setting_bit_compatible"], "paper compatibility"
    ):
        raise _fail("paper bit-exact compatibility must remain false")
    raw_domains = _require_array(symmetric["domains"], "symmetric.domains")
    if len(raw_domains) != len(_EXPECTED_DOMAINS):
        raise _fail("wrong domain count")
    observed_domains: list[DomainSpec] = []
    for index, raw_domain in enumerate(raw_domains):
        item = _require_object(
            raw_domain,
            f"domains[{index}]",
            frozenset({"purpose", "label"}),
        )
        purpose = _require_text(item["purpose"], "domain purpose")
        label = _require_text(item["label"], "domain label")
        if not label.isascii():
            raise _fail("domain labels must be ASCII")
        observed_domains.append(DomainSpec(purpose, label.encode("ascii")))
    if tuple(observed_domains) != _EXPECTED_DOMAINS:
        raise _fail("domain label set or order mismatch")

    pow_profile = _require_object(
        symmetric["pow"],
        "symmetric.pow",
        frozenset(
            {
                "nonce_encoding",
                "nonce_bytes",
                "prover_nonce_start",
                "deterministic_producer_policy",
                "explicit_predicate",
                "finite_admissibility_predicate",
                "frontier_predicate",
                "prover_exhaustion_rule",
                "verifier_policy",
            }
        ),
    )
    if pow_profile["nonce_encoding"] != "u64be" or _require_int(
        pow_profile["nonce_bytes"], "PoW nonce bytes"
    ) != 8:
        raise _fail("wrong PoW nonce encoding")
    if _require_int(pow_profile["prover_nonce_start"], "PoW nonce start") != 0:
        raise _fail("PoW producer must start at nonce zero")
    if pow_profile["deterministic_producer_policy"] != (
        "emit the first nonce satisfying the explicit predicate, finite admissibility for all 18 raw hidden positions, and frontier_count<=174"
    ):
        raise _fail("wrong deterministic PoW producer policy")
    if pow_profile["finite_admissibility_predicate"] != (
        "OPEN-INDEX applied with this nonce yields no group infinity position"
    ):
        raise _fail("wrong finite hidden-position predicate")
    if pow_profile["prover_exhaustion_rule"] != (
        "restart with fresh commitment randomness if no nonce in [0,2^64-1] satisfies all three predicates"
    ):
        raise _fail("wrong PoW restart rule")

    hidden_index = _require_object(
        symmetric["hidden_index_derivation"],
        "symmetric.hidden_index_derivation",
        frozenset(
            {
                "input_fields",
                "output_rule",
                "rejection_sampling",
                "reason",
                "semantic_classification",
            }
        ),
    )
    if hidden_index["input_fields"] != [
        "profile_fingerprint",
        "h3",
        "u64be(pow_nonce)",
        "u16be(repetition_index)",
    ]:
        raise _fail("wrong symmetric hidden-index input schedule")
    if _require_bool(hidden_index["rejection_sampling"], "hidden rejection sampling"):
        raise _fail("raw hidden-position derivation must not use rejection sampling")
    if hidden_index["semantic_classification"] != (
        "raw derivation only; finite admissibility is a separate fail-closed predicate"
    ):
        raise _fail("raw and accepted hidden-position semantics are conflated")

    transcript_schedule = _require_object(
        symmetric["transcript_schedule"], "symmetric.transcript_schedule"
    )
    xi_schedule = _require_object(
        transcript_schedule.get("xi_polynomial_encoding"),
        "symmetric.transcript_schedule.xi_polynomial_encoding",
        frozenset(
            {
                "degree",
                "order",
                "constant_field",
                "constant_elements",
                "constant_bytes",
                "constant_bit_order",
                "linear_field_binding",
                "linear_elements_each",
                "linear_packing",
                "group_0_bytes_per_polynomial",
                "group_0_repetitions",
                "group_0_bytes",
                "group_1_bytes_per_polynomial",
                "group_1_repetitions",
                "group_1_bytes",
                "total_bytes",
                "historical_1152_byte_encoding_accepted",
                "alternate_field_selector_serialized",
            }
        ),
    )
    if xi_schedule["constant_field"] != FieldId.F_2.value:
        raise _fail("wrong transcript xi constant field")
    for name, expected in (
        ("degree", 1),
        ("constant_elements", 256),
        ("constant_bytes", 32),
        ("linear_elements_each", 256),
        ("group_0_bytes_per_polynomial", 416),
        ("group_0_repetitions", 2),
        ("group_0_bytes", 832),
        ("group_1_bytes_per_polynomial", 384),
        ("group_1_repetitions", 16),
        ("group_1_bytes", 6144),
        ("total_bytes", 6976),
    ):
        if _require_int(xi_schedule[name], f"xi schedule {name}") != expected:
            raise _fail(f"wrong xi schedule {name}")
    if _require_bool(
        xi_schedule["historical_1152_byte_encoding_accepted"],
        "historical transcript xi acceptance",
    ) or _require_bool(
        xi_schedule["alternate_field_selector_serialized"],
        "alternate xi field selector",
    ):
        raise _fail("xi transcript schedule admits an alternate grammar")
    h3_preimage = _require_object(
        transcript_schedule.get("h3_preimage_polynomials"),
        "symmetric.transcript_schedule.h3_preimage_polynomials",
        frozenset(
            {
                "order",
                "coefficient_field_rule",
                "element_encoding",
                "q_elements_each_entry",
                "qbar_degree",
                "qbar_elements_each_entry",
                "entry_count",
                "groups",
                "encoded_bits",
                "encoded_bytes",
                "paper_size_formula_disclosure",
                "interoperability",
            }
        ),
    )
    if h3_preimage["coefficient_field_rule"] != (
        "for tree group g, q and Qbar coefficients are elements of GF(2^mu_g)"
    ):
        raise _fail("wrong q/Qbar coefficient-field rule")
    for name, expected in (
        ("q_elements_each_entry", 1),
        ("qbar_degree", 0),
        ("qbar_elements_each_entry", 1),
        ("entry_count", 320),
        ("encoded_bits", 7104),
        ("encoded_bytes", 888),
    ):
        if _require_int(h3_preimage[name], f"h3 preimage {name}") != expected:
            raise _fail(f"wrong h3 preimage {name}")
    expected_h3_groups = (
        (0, FieldId.GF_2_12.value, 12, 2, 16, 32, 768, 96),
        (1, FieldId.GF_2_11.value, 11, 16, 18, 288, 6336, 792),
    )
    raw_h3_groups = _require_array(h3_preimage["groups"], "h3 preimage groups")
    if len(raw_h3_groups) != len(expected_h3_groups):
        raise _fail("wrong h3 preimage group count")
    h3_group_keys = frozenset(
        {
            "group_id",
            "field",
            "mu",
            "repetitions",
            "rho",
            "entry_count",
            "q_and_qbar_bits",
            "q_and_qbar_bytes",
        }
    )
    for index, (raw_group, expected) in enumerate(
        zip(raw_h3_groups, expected_h3_groups, strict=True)
    ):
        item = _require_object(raw_group, f"h3 groups[{index}]", h3_group_keys)
        if item["field"] != expected[1]:
            raise _fail("wrong h3 coefficient-field binding")
        for name, expected_value in zip(
            (
                "group_id",
                "mu",
                "repetitions",
                "rho",
                "entry_count",
                "q_and_qbar_bits",
                "q_and_qbar_bytes",
            ),
            (expected[0], *expected[2:]),
            strict=True,
        ):
            if _require_int(item[name], f"h3 group {name}") != expected_value:
                raise _fail(f"wrong h3 group {name}")

    h3_record = _require_object(transcript_schedule.get("h3"), "h3 schedule")
    if h3_record.get("input_fields") != [
        "profile_fingerprint",
        "ctx",
        "u",
        "h2",
        "q_and_qbar",
    ]:
        raise _fail("wrong h3 input-field schedule")

    serialization = _require_object(document["serialization"], "serialization")
    pi_2 = _require_object(serialization.get("pi_2"), "serialization.pi_2")
    for name, expected in (
        ("tcith_response_bits", 3552),
        ("tcith_response_bytes", 444),
        ("payload_fixed_bytes_excluding_frontier_seeds", 1366),
        ("frontier_count_minimum", 13),
        ("frontier_count_maximum", 174),
        ("encoded_bytes_minimum", 1728),
        ("encoded_bytes_maximum", 5592),
    ):
        if _require_int(pi_2.get(name), f"pi_2.{name}") != expected:
            raise _fail(f"wrong pi_2.{name}")
    if pi_2.get("encoded_bytes_formula") != "1416 + 24*frontier_count":
        raise _fail("wrong pi_2 encoded-size formula")
    rejection_rules = _require_array(
        pi_2.get("rejection_rules"), "pi_2 rejection rules"
    )
    if "reject if any raw hidden position is the group infinity position" not in rejection_rules:
        raise _fail("pi_2 grammar does not reject infinity hidden positions")
    expected_response_groups = (
        (0, FieldId.GF_2_12.value, 32, 384, 48),
        (1, FieldId.GF_2_11.value, 288, 3168, 396),
    )
    raw_response_groups = _require_array(
        pi_2.get("tcith_response_groups"), "pi_2 response groups"
    )
    if len(raw_response_groups) != len(expected_response_groups):
        raise _fail("wrong pi_2 response group count")
    response_group_keys = frozenset({"group_id", "field", "entries", "bits", "bytes"})
    for index, (raw_group, expected) in enumerate(
        zip(raw_response_groups, expected_response_groups, strict=True)
    ):
        item = _require_object(
            raw_group, f"pi_2 response groups[{index}]", response_group_keys
        )
        if item["field"] != expected[1]:
            raise _fail("wrong pi_2 response-field binding")
        for name, expected_value in zip(
            ("group_id", "entries", "bits", "bytes"),
            (expected[0], *expected[2:]),
            strict=True,
        ):
            if _require_int(item[name], f"pi_2 response group {name}") != expected_value:
                raise _fail(f"wrong pi_2 response group {name}")
    return document


def _validate_manifest(document: object, raw: bytes) -> dict[str, object]:
    manifest = _require_object(
        document,
        "manifest",
        frozenset(
            {
                "schema",
                "schema_version",
                "repository_base",
                "created_on",
                "status",
                "claims",
                "source_identities",
                "suite_identity",
                "profile_parameter_document",
                "profile_fingerprint",
                "security_analysis",
                "size_ledger",
                "implementation_handoff",
            }
        ),
    )
    if manifest["schema"] != "pq_sat_access_v3_blind_uov_cap_concrete_profile_v0_1":
        raise _fail("wrong manifest schema")
    if manifest["schema_version"] != "0.1":
        raise _fail("wrong manifest schema version")
    claims = _require_object(
        manifest["claims"],
        "claims",
        frozenset(
            {
                "Defined",
                "Instantiated",
                "Implemented",
                "Tested",
                "Evidence_sealed",
                "Proof_closed",
                "Production_closed",
                "evaluation_domain_component",
                "response_field_component",
                "finite_hidden_challenge_component",
                "consistency_packing_component",
                "pqsat_corrective_instantiation",
                "blind_uov_author_paper_bit_exact_interoperability",
                "complete_concrete_cap",
                "claim_boundary",
            }
        ),
    )
    expected_claims = (
        ("Defined", True),
        ("Instantiated", True),
        ("Implemented", False),
        ("Tested", False),
        ("Evidence_sealed", False),
        ("Proof_closed", False),
        ("Production_closed", False),
    )
    for name, expected in expected_claims:
        if _require_bool(claims[name], f"claims.{name}") is not expected:
            raise _fail(f"claim boundary drift: {name}")
    evaluation_claims = _require_object(
        claims["evaluation_domain_component"],
        "evaluation-domain claims",
        frozenset({"Implemented", "Tested"}),
    )
    if not all(
        _require_bool(evaluation_claims[name], f"evaluation claims.{name}")
        for name in ("Implemented", "Tested")
    ):
        raise _fail("evaluation-domain implementation/test claims must be true")
    for component_name in (
        "response_field_component",
        "finite_hidden_challenge_component",
        "consistency_packing_component",
    ):
        component_claims = _require_object(
            claims[component_name],
            f"{component_name} claims",
            frozenset({"Implemented", "Tested"}),
        )
        if not all(
            _require_bool(component_claims[name], f"{component_name}.{name}")
            for name in ("Implemented", "Tested")
        ):
            raise _fail(f"{component_name} implementation/test claims must be true")
    if not _require_bool(
        claims["pqsat_corrective_instantiation"], "corrective-instantiation claim"
    ):
        raise _fail("PQ-SAT corrective-instantiation claim must be true")
    if _require_bool(
        claims["blind_uov_author_paper_bit_exact_interoperability"],
        "Blind-UOV bit-exact claim",
    ):
        raise _fail("Blind-UOV author-paper bit-exact claim must remain false")
    complete_claims = _require_object(
        claims["complete_concrete_cap"],
        "complete-CAP claims",
        frozenset({"Implemented", "Tested"}),
    )
    if any(
        _require_bool(complete_claims[name], f"complete CAP.{name}")
        for name in ("Implemented", "Tested")
    ):
        raise _fail("complete CAP implementation/test claims must remain false")

    parameters = _validate_parameter_document(manifest["profile_parameter_document"])
    fingerprint_record = _require_object(
        manifest["profile_fingerprint"],
        "profile_fingerprint",
        frozenset(
            {
                "covered_value",
                "canonicalization",
                "hash_input",
                "algorithm",
                "output_bytes",
                "hex",
            }
        ),
    )
    if fingerprint_record["covered_value"] != "profile_parameter_document":
        raise _fail("wrong fingerprint coverage")
    if fingerprint_record["algorithm"] != "SHAKE256":
        raise _fail("wrong fingerprint algorithm")
    if _require_int(fingerprint_record["output_bytes"], "fingerprint bytes") != 32:
        raise _fail("wrong fingerprint width")
    declared_hex = _require_text(fingerprint_record["hex"], "declared fingerprint")
    try:
        declared = bytes.fromhex(declared_hex)
    except ValueError as error:
        raise _fail("declared fingerprint is not hexadecimal") from error
    if declared != PROFILE_FINGERPRINT:
        raise _fail("declared fingerprint mismatch")
    canonical_parameters = _canonical_parameter_json(parameters)
    if _fingerprint_parameter_json(canonical_parameters) != declared:
        raise _fail("recomputed fingerprint mismatch")

    if len(raw) != _SOURCE_BYTES:
        raise _fail("altered parameter manifest byte length")
    if hashlib.sha256(raw).digest() != _SOURCE_SHA256:
        raise _fail("altered parameter manifest SHA-256")
    if _git_blob_oid(raw) != _SOURCE_GIT_BLOB:
        raise _fail("altered parameter manifest Git blob identity")
    return parameters


def _build_profile(parameters: dict[str, object]) -> ConcreteProfile:
    cap = _require_object(parameters["cap"], "cap")
    raw_groups = _require_array(cap["tree_groups"], "cap.tree_groups")
    group_zero = _require_object(raw_groups[0], "tree_groups[0]")
    group_one = _require_object(raw_groups[1], "tree_groups[1]")
    evaluation_raw = _require_object(cap["evaluation_domain"], "evaluation domain")
    raw_evaluation_groups = _require_array(
        evaluation_raw["groups"], "evaluation-domain groups"
    )
    hidden_raw = _require_object(cap["hidden_challenge"], "hidden challenge")
    hidden_raw_derivation = _require_object(
        hidden_raw["raw_derivation"], "hidden raw derivation"
    )
    hidden_raw_spaces = _require_array(
        hidden_raw_derivation["position_spaces"], "hidden raw spaces"
    )
    hidden_accepted_domains = _require_array(
        hidden_raw["accepted_finite_domains"], "hidden accepted domains"
    )
    hidden_producer = _require_object(
        hidden_raw["producer_policy"], "hidden producer policy"
    )
    hidden_verifier = _require_object(
        hidden_raw["verifier_single_nonce_rule"], "hidden verifier policy"
    )
    one_tree_raw = _require_object(cap["one_tree"], "one_tree")
    consistency_raw = _require_object(parameters["consistency"], "consistency")
    symmetric_raw = _require_object(parameters["symmetric"], "symmetric")
    uov = _require_object(parameters["uov"], "uov")
    security = _require_object(parameters["security"], "security")
    raw_fields = _require_object(parameters["fields"], "fields")
    gf_2_11 = _require_object(raw_fields["GF_2_11"], "GF_2_11")
    gf_2_12 = _require_object(raw_fields["GF_2_12"], "GF_2_12")
    gf_2_64 = _require_object(raw_fields["GF_2_64"], "GF_2_64")
    loaded_fields = (
        FieldSpec(
            FieldId.GF_2_8,
            8,
            _require_text(uov["irreducible_polynomial"], "GF(2^8) polynomial"),
            _require_int(uov["irreducible_polynomial_integer"], "GF(2^8) modulus"),
            1,
        ),
        FieldSpec(
            FieldId.GF_2_11,
            11,
            _require_text(gf_2_11["irreducible_polynomial"], "GF(2^11) polynomial"),
            _require_int(gf_2_11["irreducible_polynomial_integer"], "GF(2^11) modulus"),
            _require_int(gf_2_11["encoded_bytes"], "GF(2^11) width"),
        ),
        FieldSpec(
            FieldId.GF_2_12,
            12,
            _require_text(gf_2_12["irreducible_polynomial"], "GF(2^12) polynomial"),
            _require_int(gf_2_12["irreducible_polynomial_integer"], "GF(2^12) modulus"),
            _require_int(gf_2_12["encoded_bytes"], "GF(2^12) width"),
        ),
        FieldSpec(
            FieldId.GF_2_64,
            64,
            _require_text(gf_2_64["irreducible_polynomial"], "GF(2^64) polynomial"),
            _require_hex_int(
                gf_2_64["irreducible_polynomial_integer_hex"],
                "GF(2^64) modulus",
            ),
            _require_int(gf_2_64["encoded_bytes"], "GF(2^64) width"),
        ),
    )
    loaded_groups = (
        TreeGroup(
            _require_int(group_zero["group_id"], "group 0 id"),
            tuple(
                _require_int(item, "group 0 repetition")
                for item in _require_array(
                    group_zero["repetition_indices"], "group 0 repetitions"
                )
            ),
            _require_int(group_zero["leaves_per_tree"], "group 0 leaves"),
            _require_int(group_zero["mu"], "group 0 mu"),
            _require_int(group_zero["rho"], "group 0 rho"),
        ),
        TreeGroup(
            _require_int(group_one["group_id"], "group 1 id"),
            tuple(
                range(
                    _require_int(
                        group_one["repetition_index_first"], "group 1 first"
                    ),
                    _require_int(
                        group_one["repetition_index_last"], "group 1 last"
                    )
                    + 1,
                )
            ),
            _require_int(group_one["leaves_per_tree"], "group 1 leaves"),
            _require_int(group_one["mu"], "group 1 mu"),
            _require_int(group_one["rho"], "group 1 rho"),
        ),
    )
    loaded_evaluation_groups = tuple(
        EvaluationDomainGroup(
            _require_int(item["group_id"], "evaluation group id"),
            FieldId(_require_text(item["field"], "evaluation field")),
            _require_int(item["N"], "evaluation party count"),
            _require_int(item["mu"], "evaluation mu"),
            _require_int(item["finite_position_first"], "finite first"),
            _require_int(item["finite_position_last"], "finite last"),
            _require_int(item["infinity_position"], "infinity position"),
        )
        for item in (
            _require_object(raw_item, "evaluation-domain group")
            for raw_item in raw_evaluation_groups
        )
    )
    loaded_hidden_groups: list[HiddenChallengeGroup] = []
    for index, (raw_space, raw_accepted) in enumerate(
        zip(hidden_raw_spaces, hidden_accepted_domains, strict=True)
    ):
        space = _require_object(raw_space, "hidden raw group")
        accepted = _require_object(raw_accepted, "hidden accepted group")
        if index == 0:
            repetition_indices = tuple(
                _require_int(item, "hidden repetition")
                for item in _require_array(
                    space["repetition_indices"], "hidden repetitions"
                )
            )
        else:
            repetition_indices = tuple(
                range(
                    _require_int(
                        space["repetition_index_first"], "hidden first repetition"
                    ),
                    _require_int(
                        space["repetition_index_last"], "hidden last repetition"
                    )
                    + 1,
                )
            )
        loaded_hidden_groups.append(
            HiddenChallengeGroup(
                _require_int(space["group_id"], "hidden group id"),
                repetition_indices,
                _require_int(space["raw_position_first"], "raw position first"),
                _require_int(space["raw_position_last"], "raw position last"),
                _require_int(space["raw_challenge_count"], "raw challenge count"),
                _require_int(
                    accepted["accepted_position_first"], "accepted position first"
                ),
                _require_int(
                    accepted["accepted_position_last"], "accepted position last"
                ),
                _require_int(
                    accepted["forbidden_infinity_position"],
                    "forbidden infinity position",
                ),
                _require_int(
                    accepted["effective_challenge_count"],
                    "effective challenge count",
                ),
            )
        )
    loaded_domains = tuple(
        DomainSpec(
            _require_text(
                _require_object(item, "domain")["purpose"], "domain purpose"
            ),
            _require_text(
                _require_object(item, "domain")["label"], "domain label"
            ).encode("ascii"),
        )
        for item in _require_array(symmetric_raw["domains"], "symmetric.domains")
    )

    profile = ConcreteProfile(
        profile_id=PROFILE_ID,
        profile_version_u16=PROFILE_VERSION_U16,
        suite_id_u16=SUITE_ID_U16,
        fingerprint=PROFILE_FINGERPRINT,
        relation=RelationProfile(
            cap_field=FieldId.F_2,
            cap_field_order_q=_require_int(security["cap_base_field_order_q"], "q"),
            uov_field=FieldId.GF_2_8,
            n_variables=_require_int(uov["n_variables"], "n"),
            m_equations=_require_int(uov["m_equations"], "m"),
            vinegar_variables=_require_int(uov["vinegar_variables"], "v"),
            r_bits=_require_int(uov["r_bits"], "r_bits"),
            z_bits=_require_int(uov["z_bits"], "z_bits"),
            witness_bits=_require_int(uov["cap_witness_bits"], "witness_bits"),
            constraints_over_f2=_require_int(
                uov["cap_relation_constraints_over_F2"], "constraints"
            ),
            degree_d=_require_int(cap["degree_d"], "degree"),
        ),
        fields=loaded_fields,
        tau=_require_int(cap["tau"], "tau"),
        tree_groups=loaded_groups,
        evaluation_domain=EvaluationDomainProfile(
            EvaluationDomainKind(
                _require_text(evaluation_raw["kind"], "evaluation-domain kind")
            ),
            _require_text(
                evaluation_raw["position_indexing"], "evaluation indexing"
            ),
            _require_int(
                _require_object(
                    evaluation_raw["secret_evaluation_point"], "secret point"
                )["value"],
                "secret point",
            ),
            _require_text(
                _require_object(raw_evaluation_groups[0], "evaluation group 0")[
                    "finite_mapping"
                ],
                "finite mapping",
            ),
            _require_text(
                _require_object(
                    evaluation_raw["reciprocal_coordinate"], "reciprocal coordinate"
                )["finite"],
                "finite reciprocal",
            ),
            _require_int(
                _require_object(
                    evaluation_raw["reciprocal_coordinate"], "reciprocal coordinate"
                )["infinity"],
                "infinity coordinate",
            ),
            _require_text(
                _require_object(evaluation_raw["polynomial"], "polynomial")[
                    "infinity_evaluation"
                ],
                "infinity evaluation",
            ),
            loaded_evaluation_groups,
            _require_bool(
                _require_object(
                    evaluation_raw["compatibility"], "evaluation compatibility"
                )["pqsat_corrective_instantiation"],
                "corrective instantiation",
            ),
            _require_bool(
                _require_object(
                    evaluation_raw["compatibility"], "evaluation compatibility"
                )["blind_uov_appendix_a3_bit_exact"],
                "Blind-UOV bit-exact claim",
            ),
        ),
        hidden_challenge=HiddenChallengeProfile(
            tuple(loaded_hidden_groups),
            _require_text(hidden_raw_derivation["domain"], "hidden raw domain").encode(
                "ascii"
            ),
            _require_bool(
                hidden_raw_derivation["rejection_sampling"],
                "hidden rejection sampling",
            ),
            _require_bool(
                hidden_raw_derivation["modulo_n_minus_one"],
                "hidden modulo n minus one",
            ),
            _require_bool(hidden_raw_derivation["remapping"], "hidden remapping"),
            "must always be in the opened set"
            in _require_text(
                hidden_raw["infinity_leaf_policy"], "infinity leaf policy"
            ),
            _require_int(hidden_producer["nonce_start"], "producer nonce start"),
            len(_require_array(hidden_producer["predicates"], "producer predicates")),
            "fresh commitment randomness"
            in _require_text(hidden_producer["exhaustion_rule"], "restart rule"),
            _require_bool(
                hidden_verifier["parse_received_nonce_only"],
                "parse received nonce only",
            ),
            _require_bool(
                hidden_verifier["enumerate_earlier_nonces"],
                "enumerate earlier nonces",
            ),
            _require_bool(
                hidden_verifier["require_global_minimality"],
                "global minimality",
            ),
            _require_bool(
                hidden_verifier["work_depends_on_nonce_numeric_value"],
                "nonce-dependent work",
            ),
            _require_int(
                hidden_verifier["explicit_pow_evaluations"], "PoW evaluations"
            ),
            _require_int(
                hidden_verifier["raw_hidden_position_derivations"],
                "raw hidden derivations",
            ),
            _require_int(
                hidden_verifier["finite_admissibility_checks"], "finite checks"
            ),
            _require_int(
                hidden_verifier["canonical_frontier_derivations"],
                "frontier derivations",
            ),
        ),
        opened_seed_upper_bound_topen=_require_int(
            cap["opened_seed_upper_bound_topen"], "Topen"
        ),
        explicit_pow_bits_w=_require_int(cap["explicit_pow_bits_w"], "w"),
        accounted_frontier_security_bits=_require_int(
            cap["accounted_frontier_security_bits"], "frontier security"
        ),
        one_tree=OneTreeProfile(
            active_leaves=_require_int(one_tree_raw["total_active_leaves"], "leaves"),
            total_nodes=_require_int(one_tree_raw["total_nodes"], "nodes"),
            root_node_index=_require_int(one_tree_raw["root_node_index"], "root"),
            leaf_base_index=40959,
            node_index_first=0,
            node_index_last=81918,
            frontier_count_minimum=_require_int(
                one_tree_raw["frontier_count_minimum"], "frontier minimum"
            ),
            frontier_count_maximum=_require_int(
                one_tree_raw["frontier_count_maximum"], "frontier maximum"
            ),
            frontier_seed_bytes=_require_int(
                one_tree_raw["frontier_seed_bytes"], "frontier seed bytes"
            ),
            inactive_or_padding_leaves=_require_int(
                one_tree_raw["inactive_or_padding_leaves"], "padding leaves"
            ),
        ),
        consistency=ConsistencyProfile(
            kappa=_require_int(
                consistency_raw["kappa_extension_degree"], "kappa"
            ),
            evaluation_count_t=_require_int(
                consistency_raw["evaluation_count_t"], "t"
            ),
            eta=_require_int(
                consistency_raw["digest_elements_eta_over_F2"], "eta"
            ),
            witness_elements_over_f2=_require_int(
                consistency_raw["witness_elements_over_F2"], "witness elements"
            ),
            polynomial_degree_upper_bound_d=_require_int(
                consistency_raw["polynomial_degree_upper_bound_D"], "D"
            ),
            exact_numerator=299220804,
            denominator_power_of_two=256,
            strict_upper_bound_bits=227,
        ),
        symmetric=SymmetricProfile(
            primitive=_require_text(symmetric_raw["primitive"], "primitive"),
            seed_bytes=_require_int(symmetric_raw["seed_bytes"], "seed bytes"),
            digest_bytes=_require_int(symmetric_raw["digest_bytes"], "digest bytes"),
            profile_fingerprint_bytes=_require_int(
                symmetric_raw["profile_fingerprint_bytes"], "fingerprint bytes"
            ),
            domains=loaded_domains,
        ),
        source=ProfileSource(
            repository_path=_SOURCE_RELATIVE_PATH,
            sha256=_SOURCE_SHA256,
            git_blob_oid=_SOURCE_GIT_BLOB,
            integration_base=_INTEGRATION_BASE,
        ),
        _parameter_document_json=_canonical_parameter_json(parameters),
    )
    validate_profile(profile)
    return profile


def profile_fingerprint(profile: ConcreteProfile) -> bytes:
    """Recompute the specification fingerprint from the covered document."""

    if type(profile) is not ConcreteProfile:
        raise _fail("profile must be a ConcreteProfile")
    if type(profile._parameter_document_json) is not bytes:
        raise _fail("profile parameter document must be immutable bytes")
    return _fingerprint_parameter_json(profile._parameter_document_json)


def validate_profile(profile: ConcreteProfile) -> None:
    """Validate the frozen ABI and every required derived invariant."""

    if type(profile) is not ConcreteProfile:
        raise _fail("profile must be a ConcreteProfile")
    if (
        type(profile.relation) is not RelationProfile
        or type(profile.evaluation_domain) is not EvaluationDomainProfile
        or type(profile.hidden_challenge) is not HiddenChallengeProfile
        or type(profile.one_tree) is not OneTreeProfile
        or type(profile.consistency) is not ConsistencyProfile
        or type(profile.symmetric) is not SymmetricProfile
        or type(profile.source) is not ProfileSource
    ):
        raise _fail("profile contains a noncanonical nested type")
    integer_values = (
        profile.profile_version_u16,
        profile.suite_id_u16,
        profile.tau,
        profile.opened_seed_upper_bound_topen,
        profile.explicit_pow_bits_w,
        profile.accounted_frontier_security_bits,
        profile.evaluation_domain.secret_point,
        profile.evaluation_domain.infinity_reciprocal_coordinate,
        profile.hidden_challenge.producer_nonce_start,
        profile.hidden_challenge.producer_predicate_count,
        profile.hidden_challenge.verifier_pow_evaluations,
        profile.hidden_challenge.verifier_raw_derivations,
        profile.hidden_challenge.verifier_finite_checks,
        profile.hidden_challenge.verifier_frontier_derivations,
        profile.relation.cap_field_order_q,
        profile.relation.n_variables,
        profile.relation.m_equations,
        profile.relation.vinegar_variables,
        profile.relation.r_bits,
        profile.relation.z_bits,
        profile.relation.witness_bits,
        profile.relation.constraints_over_f2,
        profile.relation.degree_d,
        profile.one_tree.active_leaves,
        profile.one_tree.total_nodes,
        profile.one_tree.root_node_index,
        profile.one_tree.leaf_base_index,
        profile.one_tree.node_index_first,
        profile.one_tree.node_index_last,
        profile.one_tree.frontier_count_minimum,
        profile.one_tree.frontier_count_maximum,
        profile.one_tree.frontier_seed_bytes,
        profile.one_tree.inactive_or_padding_leaves,
        profile.consistency.kappa,
        profile.consistency.evaluation_count_t,
        profile.consistency.eta,
        profile.consistency.witness_elements_over_f2,
        profile.consistency.polynomial_degree_upper_bound_d,
        profile.consistency.exact_numerator,
        profile.consistency.denominator_power_of_two,
        profile.consistency.strict_upper_bound_bits,
        profile.symmetric.seed_bytes,
        profile.symmetric.digest_bytes,
        profile.symmetric.profile_fingerprint_bytes,
    )
    if any(type(value) is not int for value in integer_values):
        raise _fail("profile integers must not be bool or integer subclasses")
    if (
        type(profile.relation.cap_field) is not FieldId
        or type(profile.relation.uov_field) is not FieldId
    ):
        raise _fail("relation field identifiers must be FieldId values")
    if (
        profile.profile_id != PROFILE_ID
        or type(profile.profile_version_u16) is not int
        or profile.profile_version_u16 != PROFILE_VERSION_U16
        or type(profile.suite_id_u16) is not int
        or profile.suite_id_u16 != SUITE_ID_U16
    ):
        raise _fail("profile identity mismatch")
    if type(profile.fingerprint) is not bytes or profile.fingerprint != PROFILE_FINGERPRINT:
        raise _fail("profile fingerprint mismatch")
    if profile.source != ProfileSource(
        _SOURCE_RELATIVE_PATH, _SOURCE_SHA256, _SOURCE_GIT_BLOB, _INTEGRATION_BASE
    ):
        raise _fail("profile source identity mismatch")
    if profile.relation != RelationProfile(
        FieldId.F_2,
        2,
        FieldId.GF_2_8,
        184,
        72,
        112,
        576,
        1472,
        2048,
        576,
        2,
    ):
        raise _fail("relation constants mismatch")
    if type(profile.fields) is not tuple or profile.fields != _EXPECTED_FIELDS:
        raise _fail("field profile mismatch")
    for field in profile.fields:
        if type(field) is not FieldSpec or type(field.field_id) is not FieldId:
            raise _fail("field entries must be frozen FieldSpec values")
        if any(
            type(value) is not int
            for value in (
                field.degree,
                field.irreducible_polynomial_integer,
                field.encoded_bytes,
            )
        ):
            raise _fail("field integers must not be bool")
        if field.irreducible_polynomial_integer.bit_length() != field.degree + 1:
            raise _fail("field modulus degree mismatch")
        if field.encoded_bytes != (field.degree + 7) // 8:
            raise _fail("field encoded width mismatch")
    if type(profile.tree_groups) is not tuple or profile.tree_groups != _EXPECTED_GROUPS:
        raise _fail("tree-group profile mismatch")
    if any(
        type(group) is not TreeGroup
        or type(group.repetition_indices) is not tuple
        or any(type(value) is not int for value in group.repetition_indices)
        or any(
            type(value) is not int
            for value in (group.group_id, group.leaves, group.mu, group.rho)
        )
        for group in profile.tree_groups
    ):
        raise _fail("tree groups contain noncanonical types")
    repetitions = tuple(
        repetition
        for group in profile.tree_groups
        for repetition in group.repetition_indices
    )
    if repetitions != tuple(range(18)) or len(set(repetitions)) != 18:
        raise _fail("tree-group coverage has a gap or overlap")
    for group in profile.tree_groups:
        if group.leaves != 1 << group.mu:
            raise _fail("tree leaves and mu mismatch")
        if group.mu * group.rho < 192 or group.mu * (group.rho - 1) >= 192:
            raise _fail("rho is not the least value meeting 192 bits")
    if profile.evaluation_domain != _EXPECTED_EVALUATION_DOMAIN:
        raise _fail("evaluation-domain profile mismatch")
    if (
        type(profile.evaluation_domain.kind) is not EvaluationDomainKind
        or type(profile.evaluation_domain.groups) is not tuple
        or type(profile.evaluation_domain.pqsat_corrective_instantiation) is not bool
        or type(profile.evaluation_domain.blind_uov_appendix_a3_bit_exact) is not bool
    ):
        raise _fail("evaluation-domain profile contains noncanonical types")
    for domain_group, tree_group in zip(
        profile.evaluation_domain.groups, profile.tree_groups, strict=True
    ):
        if type(domain_group) is not EvaluationDomainGroup:
            raise _fail("evaluation-domain groups must be frozen canonical values")
        if type(domain_group.field_id) is not FieldId or any(
            type(value) is not int
            for value in (
                domain_group.group_id,
                domain_group.party_count,
                domain_group.mu,
                domain_group.finite_position_first,
                domain_group.finite_position_last,
                domain_group.infinity_position,
            )
        ):
            raise _fail("evaluation-domain group contains noncanonical values")
        if (
            domain_group.group_id != tree_group.group_id
            or domain_group.party_count != tree_group.leaves
            or domain_group.mu != tree_group.mu
            or domain_group.party_count != (1 << domain_group.mu) - 1 + 1
            or domain_group.finite_position_first != 0
            or domain_group.finite_position_last != domain_group.party_count - 2
            or domain_group.infinity_position != domain_group.party_count - 1
        ):
            raise _fail("evaluation-domain group is not bound to its tree group")
        field = profile.field(domain_group.field_id)
        if field.degree != domain_group.mu:
            raise _fail("evaluation-domain group is not bound to its field")
    if profile.hidden_challenge != _EXPECTED_HIDDEN_CHALLENGE:
        raise _fail("hidden-challenge profile mismatch")
    if (
        type(profile.hidden_challenge.groups) is not tuple
        or type(profile.hidden_challenge.raw_domain) is not bytes
        or any(
            type(value) is not bool
            for value in (
                profile.hidden_challenge.raw_rejection_sampling,
                profile.hidden_challenge.raw_modulo_n_minus_one,
                profile.hidden_challenge.raw_remapping,
                profile.hidden_challenge.infinity_leaf_must_be_opened,
                profile.hidden_challenge.restart_with_fresh_commitment_randomness,
                profile.hidden_challenge.verifier_parse_received_nonce_only,
                profile.hidden_challenge.verifier_enumerate_earlier_nonces,
                profile.hidden_challenge.verifier_require_global_minimality,
                profile.hidden_challenge.verifier_work_depends_on_nonce_numeric_value,
            )
        )
    ):
        raise _fail("hidden-challenge profile contains noncanonical types")
    for hidden_group, domain_group, tree_group in zip(
        profile.hidden_challenge.groups,
        profile.evaluation_domain.groups,
        profile.tree_groups,
        strict=True,
    ):
        if (
            type(hidden_group) is not HiddenChallengeGroup
            or type(hidden_group.repetition_indices) is not tuple
            or any(type(value) is not int for value in hidden_group.repetition_indices)
            or any(
                type(value) is not int
                for value in (
                    hidden_group.group_id,
                    hidden_group.raw_position_first,
                    hidden_group.raw_position_last,
                    hidden_group.raw_challenge_count,
                    hidden_group.accepted_position_first,
                    hidden_group.accepted_position_last,
                    hidden_group.forbidden_infinity_position,
                    hidden_group.effective_challenge_count,
                )
            )
        ):
            raise _fail("hidden-challenge group contains noncanonical values")
        if (
            hidden_group.group_id != tree_group.group_id
            or hidden_group.repetition_indices != tree_group.repetition_indices
            or hidden_group.raw_position_first != 0
            or hidden_group.raw_position_last != tree_group.leaves - 1
            or hidden_group.raw_challenge_count != tree_group.leaves
            or hidden_group.accepted_position_first != 0
            or hidden_group.accepted_position_last != tree_group.leaves - 2
            or hidden_group.forbidden_infinity_position
            != domain_group.infinity_position
            or hidden_group.effective_challenge_count != tree_group.leaves - 1
            or hidden_group.effective_challenge_count
            != hidden_group.accepted_position_last
            - hidden_group.accepted_position_first
            + 1
        ):
            raise _fail("hidden-challenge boundaries or derived counts mismatch")
    if profile.tau != 18 or sum(group.repetitions for group in profile.tree_groups) != 18:
        raise _fail("tau mismatch")
    if (
        profile.opened_seed_upper_bound_topen != 174
        or profile.explicit_pow_bits_w != 13
        or profile.accounted_frontier_security_bits != 0
    ):
        raise _fail("CAP opening or PoW constants mismatch")
    if profile.one_tree != OneTreeProfile(40960, 81919, 0, 40959, 0, 81918, 13, 174, 24, 0):
        raise _fail("one-tree profile mismatch")
    if profile.one_tree.total_nodes != 2 * profile.one_tree.active_leaves - 1:
        raise _fail("one-tree node count mismatch")
    if profile.one_tree.leaf_base_index != profile.one_tree.active_leaves - 1:
        raise _fail("one-tree leaf base mismatch")
    consistency = profile.consistency
    if consistency != ConsistencyProfile(64, 4, 256, 2048, 31, 299220804, 256, 227):
        raise _fail("consistency constants mismatch")
    expected_degree = (consistency.witness_elements_over_f2 + consistency.kappa - 1) // consistency.kappa - 1
    expected_numerator = profile.tau**2 * expected_degree**consistency.evaluation_count_t
    if (
        consistency.eta != consistency.kappa * consistency.evaluation_count_t
        or expected_degree != consistency.polynomial_degree_upper_bound_d
        or expected_numerator != consistency.exact_numerator
        or consistency.denominator_power_of_two
        != consistency.kappa * consistency.evaluation_count_t
        or not expected_numerator
        < 1 << (consistency.denominator_power_of_two - consistency.strict_upper_bound_bits)
    ):
        raise _fail("consistency derived arithmetic mismatch")
    if profile.symmetric != SymmetricProfile("SHAKE256", 24, 48, 32, _EXPECTED_DOMAINS):
        raise _fail("symmetric profile mismatch")
    if type(profile.symmetric.domains) is not tuple or any(
        type(item) is not DomainSpec
        or type(item.purpose) is not str
        or type(item.label) is not bytes
        for item in profile.symmetric.domains
    ):
        raise _fail("domain entries contain noncanonical types")
    if len({item.purpose for item in profile.symmetric.domains}) != len(_EXPECTED_DOMAINS):
        raise _fail("duplicate domain purpose")
    if len({item.label for item in profile.symmetric.domains}) != len(_EXPECTED_DOMAINS):
        raise _fail("duplicate domain label")
    if any(not item.label.isascii() for item in profile.symmetric.domains):
        raise _fail("non-ASCII domain label")

    parameter_document = _parse_json(
        profile._parameter_document_json, label="profile parameter document"
    )
    _validate_parameter_document(parameter_document)
    if _canonical_parameter_json(parameter_document) != profile._parameter_document_json:
        raise _fail("stored parameter document is not canonical JSON")
    if profile_fingerprint(profile) != PROFILE_FINGERPRINT:
        raise _fail("recomputed profile fingerprint mismatch")


def load_profile_manifest(path: Path | None = None) -> ConcreteProfile:
    """Load only the exact canonical profile manifest and return frozen data."""

    if path is None:
        selected_path = DEFAULT_PROFILE_MANIFEST
    elif isinstance(path, Path):
        selected_path = path
    else:
        raise _fail("path must be pathlib.Path or None")
    try:
        raw = selected_path.read_bytes()
    except (OSError, ValueError) as error:
        raise _fail(f"cannot read profile manifest: {error}") from error
    document = _parse_json(raw, label="profile manifest")
    parameters = _validate_manifest(document, raw)
    return _build_profile(parameters)


__all__ = (
    "ConcreteProfile",
    "ConsistencyProfile",
    "DomainSpec",
    "EvaluationDomainGroup",
    "EvaluationDomainKind",
    "EvaluationDomainProfile",
    "FieldId",
    "FieldSpec",
    "HiddenChallengeGroup",
    "HiddenChallengeProfile",
    "OneTreeProfile",
    "ProfileSource",
    "ProfileValidationError",
    "RelationProfile",
    "SymmetricProfile",
    "TreeGroup",
    "load_profile_manifest",
    "profile_fingerprint",
    "validate_profile",
)
