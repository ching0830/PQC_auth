#!/usr/bin/env python3
"""Bounded formal-contract checkpoint for the PQ-RBBC issuance relation.

This module maps the formal public statement ``(pp, ctx, sid, rid, beta)`` and
private witness ``(M, r, rho, k_hold, e)`` to the five I1--I5 conjuncts.  It
does not instantiate the production CAP relation, a certified Goppa key, a
stateful issuer SID registry, or a proof backend.  The only executable relation
adapter is deliberately named insecure/test-only and is rejected by every
production entry point.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import AbstractSet, Mapping, Sequence

import pq_rbbc_cap_commit as cap
import pq_rbbc_issuance_zk_backend_preflight as backend_preflight
import pq_rbbc_reference as reference


IMPLEMENTATION_VERSION = "1.0"
MANIFEST_FORMAT = "PQRBBC-ISSUANCE-RELATION-FORMAL-CONTRACT-1"
EVIDENCE_FORMAT = "PQRBBC-ISSUANCE-RELATION-PORTABLE-EVIDENCE-1"
RELATION_ID = "pq-rbbc/issuance/formal-relation/candidate/v1"
ROOT = Path(__file__).resolve().parents[1]

PARAMETERS_MAGIC = b"PQRBBC-ISSUE-RELATION-PP-V1"
PARAMETERS_VERSION = 1
TEST_ONLY_MODE = "INSECURE-TEST-ONLY-STRUCTURAL-RELATION"
TEST_ONLY_I3_ADAPTER_ID = "INSECURE-TEST-ONLY-CAP-HASH-SHAPE-V1"
TEST_MATRIX_SEED = b"PQ-RBBC/issuance-relation/v1/test-matrix"

SID_BYTES = 32
DOMAIN_TEST_SID = b"PQ-RBBC/ISSUANCE-RELATION/INSECURE-TEST-ONLY-SID/V1"
DOMAIN_TEST_I3_COMMITMENT = (
    b"PQ-RBBC/ISSUANCE-RELATION/INSECURE-TEST-ONLY-CAP-COMMIT/V1"
)
DOMAIN_TEST_I3_HASH = b"PQ-RBBC/ISSUANCE-RELATION/INSECURE-TEST-ONLY-H/V1"
DOMAIN_TRACE_PROFILE = b"PQ-RBBC/ISSUANCE-RELATION/TRACE-PROFILE/V1"
DOMAIN_TRACE_PUBLIC_KEY = b"PQ-RBBC/ISSUANCE-RELATION/TEST-MATRIX/V1"

TRACE_PROFILE_DOCUMENT = {
    "format": "PQRBBC-TRACE-RELATION-PROFILE-1",
    "n": reference.N,
    "k": reference.K,
    "t": reference.T,
    "ctx_bytes": 32,
    "rid_bytes": 32,
    "serial_bytes": 16,
    "error_bytes": reference.N // 8,
    "ticket_payload_bytes": backend_preflight.TICKET_PAYLOAD_BYTES,
    "ticket_hash_domain_hex": reference.LABEL_TICKET.hex(),
    "holder_hash_domain_hex": reference.LABEL_HOLD.hex(),
    "trace_kdf_domain_hex": reference.LABEL_KDF.hex(),
    "trace_kdf_split": {
        "pad": [reference.TRACE_PAD_OFFSET, reference.TRACE_MAC_KEY_OFFSET],
        "mac_key": [reference.TRACE_MAC_KEY_OFFSET, reference.TRACE_KDF_BYTES],
    },
    "kmac_customization_hex": reference.CUSTOMIZATION.hex(),
    "production_opening_implemented": reference.PRODUCTION_OPENING_IMPLEMENTED,
}


TRACKED_PREREQUISITES = {
    "core_proof": (
        "docs/proof/source/pq_rbbc_sgtd_core_proof_v1.tex",
        148_798,
        "cee211e7c6419480c0571b752faebe3574d3309f4e876a75cf325f3027d9f884",
    ),
    "reference_relation": (
        "src/pq_rbbc_reference.py",
        70_542,
        "37da0b9834fd2ecd83b482208ea259e0a17b126bb16f50f4ff538d0699046fab",
    ),
    "cap_commit": (
        "src/pq_rbbc_cap_commit.py",
        32_526,
        "be3a2a767561f009acc2a274a85410ae6e02e23abd24145aa1d61883dd2dceee",
    ),
    "backend_preflight": (
        "src/pq_rbbc_issuance_zk_backend_preflight.py",
        47_151,
        "00c0119596983b94bdfd1dcaffe58f0c2f847ca0092c5c53d8f073285092e836",
    ),
    "backend_preflight_manifest": (
        "manifests/pq_rbbc_issuance_zk_backend_preflight_manifest_v1.json",
        10_795,
        "07fc3fb24e129cfe15fdb1d8b3b414271bec906ae76ff071823de1f405ef2324",
    ),
    "backend_preflight_evidence": (
        "artifacts/metadata/issuance_zk_backend_preflight_v1/"
        "pq_rbbc_issuance_zk_backend_preflight_evidence_v1.json",
        3_164,
        "b0939939ea64239e8694d0549b1af7865f140ce14f941f1e0a857ea7a2003294",
    ),
}


class IssuanceRelationError(ValueError):
    """Raised for noncanonical or inconsistent relation inputs."""


class ProductionIssuanceRelationUnavailable(RuntimeError):
    """Raised before evaluation when production relation closure is absent."""


def canonical_json(document: object) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def sha256_bytes(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identity(path: Path) -> dict[str, object]:
    return {
        "filename": path.name,
        "bytes": path.stat().st_size,
        "sha256": _sha256_file(path),
    }


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise IssuanceRelationError(f"{path.name} root must be an object")
    return document


def _validate_ascii(value: str, label: str) -> bytes:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise IssuanceRelationError(f"{label} must be ASCII") from error
    allowed = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/"
    if not encoded or len(encoded) > 96 or any(byte not in allowed for byte in encoded):
        raise IssuanceRelationError(f"{label} is not canonical")
    return encoded


def _read_uint(
    encoded: bytes, offset: int, width: int, label: str
) -> tuple[int, int]:
    end = offset + width
    if end > len(encoded):
        raise IssuanceRelationError(f"truncated {label}")
    return int.from_bytes(encoded[offset:end], "little"), end


def _encode_sections(sections: Sequence[tuple[int, bytes]]) -> bytes:
    result = bytearray(PARAMETERS_MAGIC)
    result.extend(PARAMETERS_VERSION.to_bytes(2, "little"))
    result.extend(len(sections).to_bytes(2, "little"))
    for section_id, payload in sections:
        result.extend(section_id.to_bytes(2, "little"))
        result.extend(len(payload).to_bytes(8, "little"))
        result.extend(payload)
    return bytes(result)


def _decode_sections(
    encoded: bytes,
    schema: Sequence[tuple[int, str, int, int]],
) -> dict[str, bytes]:
    if not encoded.startswith(PARAMETERS_MAGIC):
        raise IssuanceRelationError("wrong relation-parameter magic")
    offset = len(PARAMETERS_MAGIC)
    version, offset = _read_uint(encoded, offset, 2, "parameter version")
    if version != PARAMETERS_VERSION:
        raise IssuanceRelationError("wrong relation-parameter version")
    count, offset = _read_uint(encoded, offset, 2, "parameter section count")
    if count != len(schema):
        raise IssuanceRelationError("wrong relation-parameter section count")
    values: dict[str, bytes] = {}
    for expected_id, name, minimum, maximum in schema:
        section_id, offset = _read_uint(encoded, offset, 2, f"{name} id")
        if section_id != expected_id:
            raise IssuanceRelationError(f"noncanonical {name} section")
        length, offset = _read_uint(encoded, offset, 8, f"{name} length")
        if length < minimum or length > maximum:
            raise IssuanceRelationError(f"wrong {name} length")
        end = offset + length
        if end > len(encoded):
            raise IssuanceRelationError(f"truncated {name}")
        values[name] = encoded[offset:end]
        offset = end
    if offset != len(encoded):
        raise IssuanceRelationError("trailing relation-parameter bytes")
    return values


TRACE_PROFILE_DIGEST = sha256_bytes(
    DOMAIN_TRACE_PROFILE + canonical_json(TRACE_PROFILE_DOCUMENT)
)
TARGET_CAP_PROFILE_DIGEST = bytes.fromhex(backend_preflight.CAP_RANDOMNESS_PROFILE)


def trace_public_key_digest(matrix_seed: bytes) -> bytes:
    if not matrix_seed or len(matrix_seed) > 96:
        raise IssuanceRelationError("test matrix seed length is invalid")
    return sha256_bytes(
        DOMAIN_TRACE_PUBLIC_KEY
        + reference.N.to_bytes(4, "little")
        + reference.K.to_bytes(4, "little")
        + reference.T.to_bytes(4, "little")
        + len(matrix_seed).to_bytes(2, "little")
        + matrix_seed
    )


@dataclass(frozen=True)
class TestOnlyIssueRelationParametersV1:
    relation_id: str
    statement_abi_digest: bytes
    target_cap_profile_digest: bytes
    trace_profile_digest: bytes
    trace_public_key_digest: bytes
    mode: str
    matrix_seed: bytes

    def encode(self) -> bytes:
        sections = (
            (1, _validate_ascii(self.relation_id, "relation_id")),
            (2, self.statement_abi_digest),
            (3, self.target_cap_profile_digest),
            (4, self.trace_profile_digest),
            (5, self.trace_public_key_digest),
            (6, _validate_ascii(self.mode, "mode")),
            (7, self.matrix_seed),
        )
        if self.relation_id != RELATION_ID:
            raise IssuanceRelationError("wrong relation namespace")
        if self.statement_abi_digest != backend_preflight.ABI_PROFILE_DIGEST:
            raise IssuanceRelationError("wrong statement ABI profile")
        if self.target_cap_profile_digest != TARGET_CAP_PROFILE_DIGEST:
            raise IssuanceRelationError("wrong target CAP profile")
        if self.trace_profile_digest != TRACE_PROFILE_DIGEST:
            raise IssuanceRelationError("wrong trace profile")
        if self.trace_public_key_digest != trace_public_key_digest(self.matrix_seed):
            raise IssuanceRelationError("test trace public-key digest mismatch")
        if self.mode != TEST_ONLY_MODE:
            raise IssuanceRelationError("relation parameters are not test-only")
        return _encode_sections(sections)

    @classmethod
    def decode(cls, encoded: bytes) -> "TestOnlyIssueRelationParametersV1":
        values = _decode_sections(
            encoded,
            (
                (1, "relation_id", 1, 96),
                (2, "statement_abi_digest", 32, 32),
                (3, "target_cap_profile_digest", 32, 32),
                (4, "trace_profile_digest", 32, 32),
                (5, "trace_public_key_digest", 32, 32),
                (6, "mode", 1, 96),
                (7, "matrix_seed", 1, 96),
            ),
        )
        try:
            relation_id = values["relation_id"].decode("ascii")
            mode = values["mode"].decode("ascii")
        except UnicodeDecodeError as error:
            raise IssuanceRelationError("parameter identifiers must be ASCII") from error
        result = cls(
            relation_id,
            values["statement_abi_digest"],
            values["target_cap_profile_digest"],
            values["trace_profile_digest"],
            values["trace_public_key_digest"],
            mode,
            values["matrix_seed"],
        )
        if result.encode() != encoded:
            raise IssuanceRelationError("noncanonical relation parameters")
        return result


def test_only_parameters() -> TestOnlyIssueRelationParametersV1:
    return TestOnlyIssueRelationParametersV1(
        RELATION_ID,
        backend_preflight.ABI_PROFILE_DIGEST,
        TARGET_CAP_PROFILE_DIGEST,
        TRACE_PROFILE_DIGEST,
        trace_public_key_digest(TEST_MATRIX_SEED),
        TEST_ONLY_MODE,
        TEST_MATRIX_SEED,
    )


def decode_ticket_payload(encoded: bytes) -> reference.TicketPayload:
    if len(encoded) != backend_preflight.TICKET_PAYLOAD_BYTES:
        raise IssuanceRelationError("ticket payload must be exactly 368 bytes")
    payload = reference.TicketPayload(
        ctx=encoded[0:32],
        sn=encoded[32:48],
        holder_hash=encoded[48:80],
        syndrome=encoded[80:288],
        masked_identity=encoded[288:336],
        tag=encoded[336:368],
    )
    if payload.encode() != encoded:
        raise IssuanceRelationError("noncanonical ticket payload")
    return payload


class InsecureTestOnlyI3Adapter:
    """Shape-only I3 adapter; this is not CAP.Commit or H_RBBC."""

    adapter_id = TEST_ONLY_I3_ADAPTER_ID
    production_qualified = False

    @staticmethod
    def commitment(mask: bytes, randomness: bytes) -> bytes:
        if len(mask) != backend_preflight.BLIND_REQUEST_BYTES:
            raise IssuanceRelationError("I3 mask must be 72 bytes")
        backend_preflight.validate_cap_randomness_encoding(randomness)
        return hashlib.shake_256(
            DOMAIN_TEST_I3_COMMITMENT + mask + randomness
        ).digest(96)

    @classmethod
    def request(cls, message: bytes, mask: bytes, randomness: bytes) -> bytes:
        if len(message) != 32:
            raise IssuanceRelationError("I3 ticket message must be 32 bytes")
        commitment = cls.commitment(mask, randomness)
        hash_image = hashlib.shake_256(
            DOMAIN_TEST_I3_HASH + message + commitment
        ).digest(backend_preflight.BLIND_REQUEST_BYTES)
        return reference.xor_bytes(mask, hash_image)


@dataclass(frozen=True)
class RelationEvaluation:
    ok: bool
    checks: tuple[tuple[str, bool], ...]
    failures: tuple[str, ...]
    production_qualified: bool = False

    def check(self, name: str) -> bool:
        return dict(self.checks)[name]


def _failed_evaluation(label: str) -> RelationEvaluation:
    names = ("P0_parameters", "P1_abi", "I1", "I2", "I3", "I4", "I5")
    checks = tuple((name, False) for name in names)
    return RelationEvaluation(False, checks, (label,))


def evaluate_relation(
    parameters_bytes: bytes,
    statement_bytes: bytes,
    witness_bytes: bytes,
    *,
    production: bool = True,
) -> RelationEvaluation:
    """Evaluate the bounded structural profile or refuse production use."""
    if production:
        raise ProductionIssuanceRelationUnavailable(
            "production I3 CAP/H_RBBC relation and certified trace key are not instantiated"
        )
    try:
        parameters = TestOnlyIssueRelationParametersV1.decode(parameters_bytes)
        statement = backend_preflight.IssueStatementV1.decode(statement_bytes)
        witness = backend_preflight.IssueWitnessV1.decode(witness_bytes)
        payload = decode_ticket_payload(witness.ticket_payload)
    except (IssuanceRelationError, backend_preflight.CanonicalEncodingError, ValueError):
        return _failed_evaluation("encoding")

    parameter_binding = statement.public_parameters_digest == sha256_bytes(
        parameters_bytes
    )
    abi_binding = (
        statement.abi_profile_digest == backend_preflight.ABI_PROFILE_DIGEST
        and witness.abi_profile_digest == statement.abi_profile_digest
        and parameters.statement_abi_digest == statement.abi_profile_digest
    )
    i1 = payload.ctx == statement.ctx
    encoded_payload = payload.encode()
    message = hashlib.shake_256(
        reference.LABEL_TICKET + encoded_payload
    ).digest(32)
    i2 = len(message) == 32 and encoded_payload == witness.ticket_payload

    try:
        expected_beta = InsecureTestOnlyI3Adapter.request(
            message, witness.blind_mask, witness.cap_randomness
        )
    except (IssuanceRelationError, ValueError):
        i3 = False
    else:
        i3 = statement.beta == expected_beta

    expected_holder_hash = hashlib.shake_256(
        reference.LABEL_HOLD + witness.holder_key
    ).digest(32)
    i4 = payload.holder_hash == expected_holder_hash

    error = int.from_bytes(witness.error_vector, "little")
    try:
        matrix = reference.SystematicParityCheck(parameters.matrix_seed)
        expected_payload = reference._derive_trace(
            matrix,
            statement.ctx,
            statement.rid,
            payload.sn,
            witness.holder_key,
            error,
        )
    except ValueError:
        i5 = False
    else:
        i5 = error.bit_count() == reference.T and expected_payload == payload

    checks = (
        ("P0_parameters", parameter_binding),
        ("P1_abi", abi_binding),
        ("I1", i1),
        ("I2", i2),
        ("I3", i3),
        ("I4", i4),
        ("I5", i5),
    )
    failures = tuple(name for name, accepted in checks if not accepted)
    return RelationEvaluation(not failures, checks, failures)


@dataclass(frozen=True)
class SIDCandidateEvaluation:
    ok: bool
    failures: tuple[str, ...]
    state_reserved: bool = False
    freshness_proved_by_relation: bool = False


def validate_issuer_sid_candidate(
    statement_bytes: bytes,
    *,
    expected_issuer_sid: bytes,
    used_sid_snapshot: AbstractSet[bytes],
    production: bool = True,
) -> SIDCandidateEvaluation:
    """Read-only SID check; never reserves or consumes issuer state."""
    if production:
        raise ProductionIssuanceRelationUnavailable(
            "read-only SID preflight cannot replace a linearizable issuer reservation"
        )
    failures: list[str] = []
    try:
        statement = backend_preflight.IssueStatementV1.decode(statement_bytes)
    except (backend_preflight.CanonicalEncodingError, ValueError):
        return SIDCandidateEvaluation(False, ("statement_encoding",))
    if len(expected_issuer_sid) != SID_BYTES:
        failures.append("expected_sid_width")
    if statement.sid == bytes(SID_BYTES):
        failures.append("zero_sid")
    if statement.sid != expected_issuer_sid:
        failures.append("issuer_sid_binding")
    if any(not isinstance(item, bytes) or len(item) != SID_BYTES for item in used_sid_snapshot):
        failures.append("used_sid_snapshot_encoding")
    elif statement.sid in used_sid_snapshot:
        failures.append("sid_already_used")
    return SIDCandidateEvaluation(not failures, tuple(failures))


@dataclass(frozen=True)
class IssueRelationFixture:
    parameters: bytes
    statement: bytes
    witness: bytes
    issuer_sid: bytes


def fixture() -> IssueRelationFixture:
    parameters = test_only_parameters().encode()
    matrix = reference.SystematicParityCheck(TEST_MATRIX_SEED)
    ctx = hashlib.shake_256(b"PQ-RBBC/issuance-relation/v1/ctx").digest(32)
    rid = hashlib.shake_256(b"PQ-RBBC/issuance-relation/v1/rid").digest(32)
    sid = hashlib.sha256(DOMAIN_TEST_SID + b"fixture-issuer-counter-1").digest()
    sn = hashlib.shake_256(b"PQ-RBBC/issuance-relation/v1/sn").digest(16)
    holder_key = hashlib.shake_256(
        b"PQ-RBBC/issuance-relation/v1/holder-key"
    ).digest(32)
    error = reference.sample_weight_error(
        b"PQ-RBBC/issuance-relation/v1/error"
    )
    payload = reference._derive_trace(matrix, ctx, rid, sn, holder_key, error)
    message = hashlib.shake_256(
        reference.LABEL_TICKET + payload.encode()
    ).digest(32)
    mask = hashlib.shake_256(b"PQ-RBBC/issuance-relation/v1/r").digest(
        backend_preflight.BLIND_REQUEST_BYTES
    )
    randomness = cap.deterministic_randomness(
        cap.PRODUCTION_PARAMETERS,
        b"PQ-RBBC/ISSUANCE-RELATION/INSECURE-TEST-ONLY-RHO/V1",
    ).serialize(cap.PRODUCTION_PARAMETERS)
    beta = InsecureTestOnlyI3Adapter.request(message, mask, randomness)
    statement = backend_preflight.IssueStatementV1(
        backend_preflight.ABI_PROFILE_DIGEST,
        sha256_bytes(parameters),
        ctx,
        sid,
        rid,
        beta,
    ).encode()
    witness = backend_preflight.IssueWitnessV1(
        backend_preflight.ABI_PROFILE_DIGEST,
        payload.encode(),
        mask,
        randomness,
        holder_key,
        error.to_bytes(reference.N // 8, "little"),
    ).encode()
    return IssueRelationFixture(parameters, statement, witness, sid)


def _flip(value: bytes, offset: int = 0) -> bytes:
    changed = bytearray(value)
    changed[offset] ^= 1
    return bytes(changed)


def run_bounded_self_check() -> dict[str, object]:
    current = fixture()
    positive = evaluate_relation(
        current.parameters,
        current.statement,
        current.witness,
        production=False,
    )
    statement = backend_preflight.IssueStatementV1.decode(current.statement)
    witness = backend_preflight.IssueWitnessV1.decode(current.witness)

    negative_cases = {
        "I1_context": (
            replace(statement, ctx=_flip(statement.ctx)).encode(),
            current.witness,
        ),
        "I3_request": (
            replace(statement, beta=_flip(statement.beta)).encode(),
            current.witness,
        ),
        "I4_holder": (
            current.statement,
            replace(witness, holder_key=_flip(witness.holder_key)).encode(),
        ),
        "I5_error": (
            current.statement,
            replace(witness, error_vector=_flip(witness.error_vector)).encode(),
        ),
    }
    rejected = [
        label
        for label, (candidate_statement, candidate_witness) in negative_cases.items()
        if not evaluate_relation(
            current.parameters,
            candidate_statement,
            candidate_witness,
            production=False,
        ).ok
    ]
    sid_positive = validate_issuer_sid_candidate(
        current.statement,
        expected_issuer_sid=current.issuer_sid,
        used_sid_snapshot=frozenset(),
        production=False,
    )
    sid_replay = validate_issuer_sid_candidate(
        current.statement,
        expected_issuer_sid=current.issuer_sid,
        used_sid_snapshot=frozenset((current.issuer_sid,)),
        production=False,
    )
    production_refusals = 0
    for action in (
        lambda: evaluate_relation(
            current.parameters, current.statement, current.witness
        ),
        lambda: validate_issuer_sid_candidate(
            current.statement,
            expected_issuer_sid=current.issuer_sid,
            used_sid_snapshot=frozenset(),
        ),
    ):
        try:
            action()
        except ProductionIssuanceRelationUnavailable:
            production_refusals += 1
    return {
        "positive_relation_all_conjuncts": positive.ok,
        "negative_cases": len(negative_cases),
        "negative_cases_rejected": len(rejected),
        "negative_case_ids": rejected,
        "sid_candidate_positive": sid_positive.ok,
        "sid_replay_rejected": not sid_replay.ok,
        "production_entry_points": 2,
        "production_entry_points_refused": production_refusals,
        "relation_constraints_replayed": 0,
        "cryptographic_proofs_generated": 0,
    }


def validate_tracked_prerequisites() -> tuple[str, ...]:
    failures: list[str] = []
    for name, (relative, expected_size, expected_sha256) in TRACKED_PREREQUISITES.items():
        path = ROOT / relative
        if not path.is_file():
            failures.append(f"{name}:missing")
        elif path.stat().st_size != expected_size:
            failures.append(f"{name}:bytes")
        elif _sha256_file(path) != expected_sha256:
            failures.append(f"{name}:sha256")
    if failures:
        return tuple(failures)
    predecessor = _read_json(
        ROOT
        / "artifacts/metadata/issuance_zk_backend_preflight_v1/"
        "pq_rbbc_issuance_zk_backend_preflight_evidence_v1.json"
    )
    result = predecessor.get("result", {})
    if not isinstance(result, dict) or (
        result.get("qualified_production_backend_selected"),
        result.get("formal_pi_issue_generated"),
        result.get("safe_to_integrate_major_backend"),
    ) != (False, False, False):
        failures.append("backend_preflight_evidence:claim_boundary")
    return tuple(failures)


def build_manifest() -> dict[str, object]:
    return {
        "format": MANIFEST_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "tracked_prerequisites": {
            name: {"path": relative, "bytes": size, "sha256": digest}
            for name, (relative, size, digest) in TRACKED_PREREQUISITES.items()
        },
        "tracked_validation_failures": list(validate_tracked_prerequisites()),
        "formal_contract": {
            "public_statement": ["pp", "ctx", "sid", "rid", "beta"],
            "private_witness": ["M", "r", "rho", "k_hold", "e"],
            "conjuncts": {
                "I1": "TicketShape(M,ctx)",
                "I2": "m=H_ticket(Encode(M))",
                "I3": "R_req(beta;m,r,rho)",
                "I4": "M.h=H_hold(k_hold)",
                "I5": "R_Ntr(tpk,M.C,ctx,M.h;rid,M.sn,e)",
            },
            "ticket_payload_is_private": True,
            "sid_is_public_but_absent_from_ticket": True,
            "sid_freshness_is_not_an_np_conjunct": True,
            "proof_must_bind_every_statement_byte": True,
        },
        "executable_profile": {
            "mode": TEST_ONLY_MODE,
            "i3_adapter_id": TEST_ONLY_I3_ADAPTER_ID,
            "i3_adapter_is_cap_commit": False,
            "i3_adapter_is_h_rbbc": False,
            "target_cap_profile_digest": TARGET_CAP_PROFILE_DIGEST.hex(),
            "canonical_cap_randomness_bytes": backend_preflight.CAP_RANDOMNESS_BYTES,
            "trace_profile_digest": TRACE_PROFILE_DIGEST.hex(),
            "trace_matrix_is_certified_goppa_key": False,
            "production_qualified": False,
        },
        "sid_contract": {
            "bytes": SID_BYTES,
            "source": "fresh issuer-side authenticated session controller",
            "must_not_be_derived_from_witness": True,
            "read_only_snapshot_can_prove_global_freshness": False,
            "linearizable_reservation_required_before_response": True,
            "relation_itself_proves_freshness": False,
            "state_reservation_implemented_here": False,
        },
        "production_gate": {
            "production_relation_instantiated": False,
            "production_evaluation_refuses_before_output": True,
            "production_i3_cap_h_rbbc_relation_instantiated": False,
            "certified_trace_public_key_instantiated": False,
            "stateful_sid_registry_integrated": False,
            "backend_integration_authorized": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
        },
        "claim_status": {
            "Defined": {
                "formal_i1_i5_mapping": True,
                "fresh_issuer_sid_boundary": True,
                "canonical_relation_parameter_encoding": True,
            },
            "Instantiated": {
                "insecure_test_only_structural_profile": True,
                "production_relation": False,
            },
            "Implemented": {
                "bounded_structural_evaluator": True,
                "production_i3": False,
                "production_sid_reservation": False,
            },
            "Tested": {
                "bounded_positive_negative_mutation": True,
                "production_relation": False,
            },
            "Evidence-sealed": {
                "bounded_formal_contract_checkpoint": True,
                "production_relation": False,
            },
            "Proof-closed": False,
            "Production-closed": False,
        },
        "resource_estimate": {
            "cpu_cores": 1,
            "peak_memory_mib_upper_bound": 256,
            "elapsed_seconds_upper_bound": 60,
            "relation_constraints_replayed": 0,
            "cryptographic_proofs_generated": 0,
        },
        "exact_commands": {
            "self_check": "PYTHONPATH=src python -u src/pq_rbbc_issuance_relation_v1.py --self-check",
            "targeted_tests": "PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_relation_v1 -v",
            "large_replay": None,
            "large_proving": None,
        },
        "next_gate": {
            "production_trace_key_and_parameter_encoding": True,
            "production_cap_h_rbbc_relation_adapter": True,
            "fresh_sid_linearizable_reservation_interface": True,
            "reduced_backend_adapter_after_relation_closure": True,
            "independent_review": True,
        },
        "artifact_policy": {
            "assignment_or_br1cs_created": False,
            "pickle_cache_checkpoint_resume_or_log_created": False,
            "large_proving_output_created": False,
            "historical_files_modified": False,
            "system_architecture_changed": False,
            "ticket_lifecycle_changed": False,
            "pq_sat_auth_changed": False,
        },
    }


def build_portable_evidence() -> dict[str, object]:
    manifest_path = ROOT / "manifests/pq_rbbc_issuance_relation_manifest_v1.json"
    manifest = _read_json(manifest_path)
    if manifest != build_manifest():
        raise IssuanceRelationError("issuance relation manifest mismatch")
    self_check = run_bounded_self_check()
    if not (
        self_check["positive_relation_all_conjuncts"]
        and self_check["negative_cases"] == self_check["negative_cases_rejected"]
        and self_check["sid_candidate_positive"]
        and self_check["sid_replay_rejected"]
        and self_check["production_entry_points"]
        == self_check["production_entry_points_refused"]
    ):
        raise IssuanceRelationError("bounded issuance relation self-check failed")
    tracked = {
        "implementation": ROOT / "src/pq_rbbc_issuance_relation_v1.py",
        "tests": ROOT / "tests/test_pq_rbbc_issuance_relation_v1.py",
        "manifest": manifest_path,
        "artifact_note": ROOT / "docs/artifacts/PQ_RBBC_ISSUANCE_RELATION_V1_zh-TW.md",
    }
    return {
        "format": EVIDENCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": "pq-rbbc/issuance/formal-relation/evidence/v1",
        "bound_manifest_sha256": _sha256_file(manifest_path),
        "source_identities": {
            name: _identity(path) for name, path in tracked.items()
        },
        "tracked_prerequisites_verified": not validate_tracked_prerequisites(),
        "bounded_self_check": self_check,
        "result": {
            "formal_i1_i5_contract_mapped": True,
            "private_ticket_partition_exercised": True,
            "fresh_sid_external_boundary_defined": True,
            "insecure_test_only_structural_profile_executed": True,
            "production_i3_instantiated": False,
            "certified_trace_key_instantiated": False,
            "stateful_sid_reservation_integrated": False,
            "qualified_backend_integrated": False,
            "formal_pi_issue_generated": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
            "proof_closed": False,
            "production_closed": False,
        },
        "artifact_policy": build_manifest()["artifact_policy"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--self-check", action="store_true")
    actions.add_argument("--print-manifest", action="store_true")
    actions.add_argument("--print-evidence", action="store_true")
    args = parser.parse_args()
    if args.self_check:
        print(canonical_json(run_bounded_self_check()).decode("ascii"), end="")
    elif args.print_manifest:
        print(canonical_json(build_manifest()).decode("ascii"), end="")
    else:
        print(canonical_json(build_portable_evidence()).decode("ascii"), end="")


if __name__ == "__main__":
    main()
