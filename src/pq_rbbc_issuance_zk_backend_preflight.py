#!/usr/bin/env python3
"""Bounded PQ-RBBC issuance ZK-backend interface and fail-closed preflight.

This module does not implement a cryptographically secure proof system.  It
freezes canonical interface encodings, records the mismatch between the formal
issuance relation and the historical replayed circuit, and provides an
explicitly insecure test-only backend for interface regression tests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol, Sequence

import pq_rbbc_cap_commit as cap


IMPLEMENTATION_VERSION = "1.0"
MANIFEST_FORMAT = "PQRBBC-ISSUANCE-ZK-BACKEND-PREFLIGHT-1"
EVIDENCE_FORMAT = "PQRBBC-ISSUANCE-ZK-BACKEND-PREFLIGHT-EVIDENCE-1"
RELATION_ID = "pq-rbbc/issuance-zk-backend/preflight/v1"
ROOT = Path(__file__).resolve().parents[1]

CODEC_VERSION = 1
PP_MAGIC = b"PQRBBC-ISSUE-PP-V1"
STATEMENT_MAGIC = b"PQRBBC-ISSUE-STATEMENT-V1"
WITNESS_MAGIC = b"PQRBBC-ISSUE-WITNESS-V1"
PROOF_MAGIC = b"PQRBBC-ISSUE-PROOF-V1"
TRANSCRIPT_DOMAIN = b"PQ-RBBC/ISSUE-PROOF/V1"
ABI_PROFILE_DIGEST = hashlib.sha256(
    b"pq-rbbc/issuance-zk-backend/statement-witness-proof/v1"
).digest()

TICKET_PAYLOAD_BYTES = 368
BLIND_REQUEST_BYTES = 72
HOLDER_KEY_BYTES = 32
ERROR_VECTOR_BYTES = 836  # 6688 bits
CAP_RANDOMNESS_BYTES = 1_036
CAP_RANDOMNESS_PROFILE = cap.profile_fingerprint(cap.PRODUCTION_PARAMETERS)
MAX_TEXT_BYTES = 96
MAX_BACKEND_PAYLOAD_BYTES = 1 << 20

LEGACY_PARENT_ROWS = 2_971_580
COMPLETE_REPLAY_ROWS = 589_030_555
COMPLETE_REPLAY_TRANSCRIPT_SHA256 = (
    "1f0113f965a03351b6d62c4801a9d15d0255640282b90215397170b87ad6a514"
)

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
    "reference_manifest_v2_25": (
        "manifests/pq_rbbc_reference_manifest_v2_25.json",
        28_423,
        "00a14727d570cc04b2ed2370399f5076a7d3cf45986655c5d2af1aea94589479",
    ),
    "br1cs_manifest_v2_25": (
        "manifests/pq_rbbc_br1cs_manifest_v2_25.json",
        26_488,
        "e19442b08b4f4a596cf001d057d3e5c016efca938a1a4814661a2691aa054737",
    ),
    "parent_join_evidence_v2_29": (
        "artifacts/metadata/parent_join_recovery_v2_29/"
        "pq_rbbc_parent_join_recovery_evidence_v2_29.json",
        5_695,
        "1281afaee1d5d784390ee51c96c66ecc7f486ef4b4b7933590826a708f81b20e",
    ),
    "unified_statement_abi_v2_37": (
        "src/pq_rbbc_cap_unified_statement_parent_abi.py",
        36_238,
        "334b0668ec1de9370cf3e80d5d72273dca78b78ad623f6f91003c8a2664395a9",
    ),
    "unified_statement_manifest_v2_37": (
        "manifests/pq_rbbc_cap_unified_statement_parent_abi_manifest_v2_37.json",
        4_300,
        "32ae1132a69a1ca97458d53a0efd66891ba2efad771967983319a75d4427ba36",
    ),
    "unified_statement_evidence_v2_37": (
        "artifacts/metadata/cap_unified_statement_parent_abi_v2_37/"
        "pq_rbbc_cap_unified_statement_parent_abi_portable_evidence_v2_37.json",
        5_188,
        "672c27f8ed0bfc567d3080c9645c079d9009ce7ff815957c9384dc0246b3c8b7",
    ),
}


class CanonicalEncodingError(ValueError):
    """Raised when a backend interface object is not canonically encoded."""


class ProductionBackendUnavailable(RuntimeError):
    """Raised before output when no qualified production backend is available."""


def canonical_json(document: Mapping[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


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
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} root must be an object")
    return document


def _validate_text(value: str, label: str) -> bytes:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise CanonicalEncodingError(f"{label} must be ASCII") from error
    allowed = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/"
    if not encoded or len(encoded) > MAX_TEXT_BYTES or any(c not in allowed for c in encoded):
        raise CanonicalEncodingError(f"{label} is not a canonical identifier")
    return encoded


def _decode_text(value: bytes, label: str) -> str:
    try:
        decoded = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise CanonicalEncodingError(f"{label} must be ASCII") from error
    if _validate_text(decoded, label) != value:
        raise CanonicalEncodingError(f"{label} is not canonical")
    return decoded


def _encode_sections(magic: bytes, sections: Sequence[tuple[int, bytes]]) -> bytes:
    result = bytearray(magic)
    result.extend(CODEC_VERSION.to_bytes(2, "little"))
    result.extend(len(sections).to_bytes(2, "little"))
    for section_id, payload in sections:
        result.extend(section_id.to_bytes(2, "little"))
        result.extend(len(payload).to_bytes(8, "little"))
        result.extend(payload)
    return bytes(result)


def _read_uint(encoded: bytes, offset: int, width: int, label: str) -> tuple[int, int]:
    end = offset + width
    if end > len(encoded):
        raise CanonicalEncodingError(f"truncated {label}")
    return int.from_bytes(encoded[offset:end], "little"), end


def _decode_sections(
    encoded: bytes,
    magic: bytes,
    schema: Sequence[tuple[int, str, int, int]],
) -> dict[str, bytes]:
    if not encoded.startswith(magic):
        raise CanonicalEncodingError("wrong magic")
    offset = len(magic)
    version, offset = _read_uint(encoded, offset, 2, "version")
    if version != CODEC_VERSION:
        raise CanonicalEncodingError("wrong version")
    count, offset = _read_uint(encoded, offset, 2, "section count")
    if count != len(schema):
        raise CanonicalEncodingError("wrong section count")
    values: dict[str, bytes] = {}
    for expected_id, name, minimum, maximum in schema:
        section_id, offset = _read_uint(encoded, offset, 2, f"{name} id")
        if section_id != expected_id:
            raise CanonicalEncodingError(f"noncanonical {name} section id")
        length, offset = _read_uint(encoded, offset, 8, f"{name} length")
        if length < minimum or length > maximum:
            raise CanonicalEncodingError(f"wrong {name} length")
        end = offset + length
        if end > len(encoded):
            raise CanonicalEncodingError(f"truncated {name}")
        values[name] = encoded[offset:end]
        offset = end
    if offset != len(encoded):
        raise CanonicalEncodingError("trailing bytes")
    return values


def validate_cap_randomness_encoding(encoded: bytes) -> None:
    """Validate the existing production CAP salt/root serialization for rho."""
    if len(encoded) != CAP_RANDOMNESS_BYTES:
        raise CanonicalEncodingError("wrong production CAP randomness length")
    if not encoded.startswith(cap.RANDOMNESS_MAGIC):
        raise CanonicalEncodingError("wrong production CAP randomness magic")
    offset = len(cap.RANDOMNESS_MAGIC)
    profile = encoded[offset : offset + 64]
    if profile != CAP_RANDOMNESS_PROFILE.encode("ascii"):
        raise CanonicalEncodingError("wrong production CAP randomness profile")
    offset += 64
    field_bytes = cap.field.FIELD_ELEMENT_BYTES
    for label in ("salt[0]", "salt[1]"):
        value = int.from_bytes(encoded[offset : offset + field_bytes], "little")
        if value > cap.field.FIELD_MASK:
            raise CanonicalEncodingError(f"noncanonical {label}")
        offset += field_bytes
    tree_count, offset = _read_uint(encoded, offset, 2, "CAP tree count")
    if tree_count != cap.PRODUCTION_PARAMETERS.tree_count:
        raise CanonicalEncodingError("wrong production CAP tree count")
    for tree_index in range(tree_count):
        for side in ("left", "right"):
            value = int.from_bytes(encoded[offset : offset + field_bytes], "little")
            if value > cap.field.FIELD_MASK:
                raise CanonicalEncodingError(
                    f"noncanonical tree[{tree_index}].{side} root"
                )
            offset += field_bytes
    if offset != len(encoded):
        raise CanonicalEncodingError("trailing production CAP randomness bytes")


@dataclass(frozen=True)
class IssuePublicParametersV1:
    backend_id: str
    backend_version: str
    security_profile_id: str
    abi_profile_digest: bytes
    relation_manifest_sha256: bytes
    setup_kind: str
    backend_payload: bytes

    def encode(self) -> bytes:
        sections = (
            (1, _validate_text(self.backend_id, "backend_id")),
            (2, _validate_text(self.backend_version, "backend_version")),
            (3, _validate_text(self.security_profile_id, "security_profile_id")),
            (4, self.abi_profile_digest),
            (5, self.relation_manifest_sha256),
            (6, _validate_text(self.setup_kind, "setup_kind")),
            (7, self.backend_payload),
        )
        if len(self.abi_profile_digest) != 32:
            raise CanonicalEncodingError("abi_profile_digest must be 32 bytes")
        if len(self.relation_manifest_sha256) != 32:
            raise CanonicalEncodingError("relation_manifest_sha256 must be 32 bytes")
        if len(self.backend_payload) > MAX_BACKEND_PAYLOAD_BYTES:
            raise CanonicalEncodingError("public parameter payload is too large")
        return _encode_sections(PP_MAGIC, sections)

    @classmethod
    def decode(cls, encoded: bytes) -> "IssuePublicParametersV1":
        values = _decode_sections(encoded, PP_MAGIC, (
            (1, "backend_id", 1, MAX_TEXT_BYTES),
            (2, "backend_version", 1, MAX_TEXT_BYTES),
            (3, "security_profile_id", 1, MAX_TEXT_BYTES),
            (4, "abi_profile_digest", 32, 32),
            (5, "relation_manifest_sha256", 32, 32),
            (6, "setup_kind", 1, MAX_TEXT_BYTES),
            (7, "backend_payload", 0, MAX_BACKEND_PAYLOAD_BYTES),
        ))
        result = cls(
            _decode_text(values["backend_id"], "backend_id"),
            _decode_text(values["backend_version"], "backend_version"),
            _decode_text(values["security_profile_id"], "security_profile_id"),
            values["abi_profile_digest"],
            values["relation_manifest_sha256"],
            _decode_text(values["setup_kind"], "setup_kind"),
            values["backend_payload"],
        )
        if result.encode() != encoded:
            raise CanonicalEncodingError("noncanonical public parameters")
        return result


@dataclass(frozen=True)
class IssueStatementV1:
    abi_profile_digest: bytes
    public_parameters_digest: bytes
    ctx: bytes
    sid: bytes
    rid: bytes
    beta: bytes

    def encode(self) -> bytes:
        sections = (
            (1, self.abi_profile_digest),
            (2, self.public_parameters_digest),
            (3, self.ctx),
            (4, self.sid),
            (5, self.rid),
            (6, self.beta),
        )
        expected = (32, 32, 32, 32, 32, BLIND_REQUEST_BYTES)
        if tuple(len(value) for _, value in sections) != expected:
            raise CanonicalEncodingError("wrong issuance statement field length")
        return _encode_sections(STATEMENT_MAGIC, sections)

    @classmethod
    def decode(cls, encoded: bytes) -> "IssueStatementV1":
        values = _decode_sections(encoded, STATEMENT_MAGIC, (
            (1, "abi_profile_digest", 32, 32),
            (2, "public_parameters_digest", 32, 32),
            (3, "ctx", 32, 32),
            (4, "sid", 32, 32),
            (5, "rid", 32, 32),
            (6, "beta", BLIND_REQUEST_BYTES, BLIND_REQUEST_BYTES),
        ))
        result = cls(**values)
        if result.encode() != encoded:
            raise CanonicalEncodingError("noncanonical issuance statement")
        return result


@dataclass(frozen=True)
class IssueWitnessV1:
    abi_profile_digest: bytes
    ticket_payload: bytes
    blind_mask: bytes
    cap_randomness: bytes
    holder_key: bytes
    error_vector: bytes

    def encode(self) -> bytes:
        sections = (
            (1, self.abi_profile_digest),
            (2, self.ticket_payload),
            (3, self.blind_mask),
            (4, self.cap_randomness),
            (5, self.holder_key),
            (6, self.error_vector),
        )
        expected = (
            32,
            TICKET_PAYLOAD_BYTES,
            BLIND_REQUEST_BYTES,
            CAP_RANDOMNESS_BYTES,
            HOLDER_KEY_BYTES,
            ERROR_VECTOR_BYTES,
        )
        if tuple(len(value) for _, value in sections) != expected:
            raise CanonicalEncodingError("wrong issuance witness field length")
        validate_cap_randomness_encoding(self.cap_randomness)
        return _encode_sections(WITNESS_MAGIC, sections)

    @classmethod
    def decode(cls, encoded: bytes) -> "IssueWitnessV1":
        values = _decode_sections(encoded, WITNESS_MAGIC, (
            (1, "abi_profile_digest", 32, 32),
            (2, "ticket_payload", TICKET_PAYLOAD_BYTES, TICKET_PAYLOAD_BYTES),
            (3, "blind_mask", BLIND_REQUEST_BYTES, BLIND_REQUEST_BYTES),
            (4, "cap_randomness", CAP_RANDOMNESS_BYTES, CAP_RANDOMNESS_BYTES),
            (5, "holder_key", HOLDER_KEY_BYTES, HOLDER_KEY_BYTES),
            (6, "error_vector", ERROR_VECTOR_BYTES, ERROR_VECTOR_BYTES),
        ))
        result = cls(**values)
        validate_cap_randomness_encoding(result.cap_randomness)
        if result.encode() != encoded:
            raise CanonicalEncodingError("noncanonical issuance witness")
        return result


@dataclass(frozen=True)
class IssueProofV1:
    abi_profile_digest: bytes
    backend_id: str
    backend_version: str
    public_parameters_digest: bytes
    statement_digest: bytes
    transcript_domain: bytes
    backend_payload: bytes

    def encode(self) -> bytes:
        sections = (
            (1, self.abi_profile_digest),
            (2, _validate_text(self.backend_id, "backend_id")),
            (3, _validate_text(self.backend_version, "backend_version")),
            (4, self.public_parameters_digest),
            (5, self.statement_digest),
            (6, self.transcript_domain),
            (7, self.backend_payload),
        )
        if len(self.abi_profile_digest) != 32:
            raise CanonicalEncodingError("proof abi_profile_digest must be 32 bytes")
        if len(self.public_parameters_digest) != 32 or len(self.statement_digest) != 32:
            raise CanonicalEncodingError("proof digests must be 32 bytes")
        if not self.transcript_domain or len(self.transcript_domain) > MAX_TEXT_BYTES:
            raise CanonicalEncodingError("wrong transcript domain length")
        if len(self.backend_payload) > MAX_BACKEND_PAYLOAD_BYTES:
            raise CanonicalEncodingError("proof payload is too large")
        return _encode_sections(PROOF_MAGIC, sections)

    @classmethod
    def decode(cls, encoded: bytes) -> "IssueProofV1":
        values = _decode_sections(encoded, PROOF_MAGIC, (
            (1, "abi_profile_digest", 32, 32),
            (2, "backend_id", 1, MAX_TEXT_BYTES),
            (3, "backend_version", 1, MAX_TEXT_BYTES),
            (4, "public_parameters_digest", 32, 32),
            (5, "statement_digest", 32, 32),
            (6, "transcript_domain", 1, MAX_TEXT_BYTES),
            (7, "backend_payload", 0, MAX_BACKEND_PAYLOAD_BYTES),
        ))
        result = cls(
            values["abi_profile_digest"],
            _decode_text(values["backend_id"], "backend_id"),
            _decode_text(values["backend_version"], "backend_version"),
            values["public_parameters_digest"],
            values["statement_digest"],
            values["transcript_domain"],
            values["backend_payload"],
        )
        if result.encode() != encoded:
            raise CanonicalEncodingError("noncanonical issuance proof")
        return result


@dataclass(frozen=True)
class BackendSecurityProperties:
    post_quantum: bool
    zero_knowledge: bool
    knowledge_extractable: bool
    simulation_extractable: bool
    non_interactive: bool
    production_qualified: bool
    test_only: bool


class IssueZKBackend(Protocol):
    backend_id: str
    backend_version: str
    security: BackendSecurityProperties

    def Setup(self, security_profile_id: str, relation_manifest_sha256: bytes) -> IssuePublicParametersV1: ...

    def ProveIssue(
        self,
        public_parameters: IssuePublicParametersV1,
        statement: IssueStatementV1,
        witness: IssueWitnessV1,
    ) -> IssueProofV1: ...

    def VerifyIssue(
        self,
        public_parameters: IssuePublicParametersV1,
        statement: IssueStatementV1,
        proof: IssueProofV1,
    ) -> bool: ...


# Empty by design.  Production qualification requires a separate reviewed
# checkpoint that pins backend source, parameters, proof, license, and evidence.
PRODUCTION_BACKEND_ALLOWLIST: frozenset[tuple[str, str]] = frozenset()


def _authorize_backend(backend: IssueZKBackend, production: bool) -> None:
    identity = (backend.backend_id, backend.backend_version)
    if production and (
        identity not in PRODUCTION_BACKEND_ALLOWLIST
        or not backend.security.production_qualified
        or backend.security.test_only
        or not backend.security.post_quantum
        or not backend.security.zero_knowledge
        or not backend.security.knowledge_extractable
        or not backend.security.simulation_extractable
        or not backend.security.non_interactive
    ):
        raise ProductionBackendUnavailable(
            "no identity-pinned PQ ZK simulation-extractable issuance backend is qualified"
        )


def _validate_parameter_binding(
    backend: IssueZKBackend, public_parameters: IssuePublicParametersV1
) -> None:
    if (
        public_parameters.backend_id != backend.backend_id
        or public_parameters.backend_version != backend.backend_version
        or public_parameters.abi_profile_digest != ABI_PROFILE_DIGEST
    ):
        raise CanonicalEncodingError("backend/public-parameter binding mismatch")


def Setup(
    backend: IssueZKBackend,
    security_profile_id: str,
    relation_manifest_sha256: bytes,
    *,
    production: bool = True,
) -> bytes:
    """Create canonical public parameters or fail before producing output."""
    _authorize_backend(backend, production)
    _validate_text(security_profile_id, "security_profile_id")
    if len(relation_manifest_sha256) != 32:
        raise CanonicalEncodingError("relation manifest digest must be 32 bytes")
    parameters = backend.Setup(security_profile_id, relation_manifest_sha256)
    _validate_parameter_binding(backend, parameters)
    if (
        parameters.security_profile_id != security_profile_id
        or parameters.relation_manifest_sha256 != relation_manifest_sha256
    ):
        raise CanonicalEncodingError("setup result does not bind requested profile/relation")
    return parameters.encode()


def ProveIssue(
    backend: IssueZKBackend,
    public_parameters_bytes: bytes,
    statement_bytes: bytes,
    witness_bytes: bytes,
    *,
    production: bool = True,
) -> bytes:
    """Produce a canonical proof only through an authorized backend."""
    _authorize_backend(backend, production)
    public_parameters = IssuePublicParametersV1.decode(public_parameters_bytes)
    statement = IssueStatementV1.decode(statement_bytes)
    witness = IssueWitnessV1.decode(witness_bytes)
    _validate_parameter_binding(backend, public_parameters)
    if statement.abi_profile_digest != ABI_PROFILE_DIGEST:
        raise CanonicalEncodingError("unsupported statement ABI profile")
    if witness.abi_profile_digest != statement.abi_profile_digest:
        raise CanonicalEncodingError("statement/witness ABI profile mismatch")
    if statement.public_parameters_digest != sha256_bytes(public_parameters_bytes):
        raise CanonicalEncodingError("statement/public-parameter digest mismatch")
    proof = backend.ProveIssue(public_parameters, statement, witness)
    proof_bytes = proof.encode()
    if (
        proof.abi_profile_digest != statement.abi_profile_digest
        or proof.backend_id != backend.backend_id
        or proof.backend_version != backend.backend_version
        or proof.public_parameters_digest != sha256_bytes(public_parameters_bytes)
        or proof.statement_digest != sha256_bytes(statement_bytes)
        or proof.transcript_domain != TRANSCRIPT_DOMAIN
    ):
        raise CanonicalEncodingError("backend returned an unbound issuance proof")
    return proof_bytes


def VerifyIssue(
    backend: IssueZKBackend,
    public_parameters_bytes: bytes,
    statement_bytes: bytes,
    proof_bytes: bytes,
    *,
    production: bool = True,
) -> bool:
    """Strictly parse and verify; malformed or cross-domain input is rejected."""
    _authorize_backend(backend, production)
    try:
        public_parameters = IssuePublicParametersV1.decode(public_parameters_bytes)
        statement = IssueStatementV1.decode(statement_bytes)
        proof = IssueProofV1.decode(proof_bytes)
        _validate_parameter_binding(backend, public_parameters)
    except (CanonicalEncodingError, ValueError):
        return False
    if (
        statement.abi_profile_digest != ABI_PROFILE_DIGEST
        or statement.public_parameters_digest != sha256_bytes(public_parameters_bytes)
        or proof.abi_profile_digest != statement.abi_profile_digest
        or proof.backend_id != backend.backend_id
        or proof.backend_version != backend.backend_version
        or proof.public_parameters_digest != sha256_bytes(public_parameters_bytes)
        or proof.statement_digest != sha256_bytes(statement_bytes)
        or proof.transcript_domain != TRANSCRIPT_DOMAIN
    ):
        return False
    try:
        return backend.VerifyIssue(public_parameters, statement, proof) is True
    except Exception:
        return False


class InsecureTestOnlyIssueBackend:
    """Deterministic binding stub; proves no relation and provides no privacy."""

    backend_id = "INSECURE-TEST-ONLY-PQ-RBBC-ISSUE"
    backend_version = "1"
    security = BackendSecurityProperties(
        post_quantum=False,
        zero_knowledge=False,
        knowledge_extractable=False,
        simulation_extractable=False,
        non_interactive=False,
        production_qualified=False,
        test_only=True,
    )
    _setup_domain = b"PQ-RBBC/INSECURE-TEST-ONLY/SETUP/V1"
    _proof_domain = b"PQ-RBBC/INSECURE-TEST-ONLY/PROOF/V1"

    def Setup(
        self, security_profile_id: str, relation_manifest_sha256: bytes
    ) -> IssuePublicParametersV1:
        payload = sha256_bytes(
            self._setup_domain
            + security_profile_id.encode("ascii")
            + relation_manifest_sha256
        )
        return IssuePublicParametersV1(
            self.backend_id,
            self.backend_version,
            security_profile_id,
            ABI_PROFILE_DIGEST,
            relation_manifest_sha256,
            "insecure-test-only-transparent",
            payload,
        )

    def ProveIssue(
        self,
        public_parameters: IssuePublicParametersV1,
        statement: IssueStatementV1,
        witness: IssueWitnessV1,
    ) -> IssueProofV1:
        # Witness parsing and profile binding are exercised by the wrapper, but
        # this stub deliberately does not check or encode the witness.
        del witness
        pp_bytes = public_parameters.encode()
        statement_bytes = statement.encode()
        payload = sha256_bytes(self._proof_domain + pp_bytes + statement_bytes)
        return IssueProofV1(
            ABI_PROFILE_DIGEST,
            self.backend_id,
            self.backend_version,
            sha256_bytes(pp_bytes),
            sha256_bytes(statement_bytes),
            TRANSCRIPT_DOMAIN,
            payload,
        )

    def VerifyIssue(
        self,
        public_parameters: IssuePublicParametersV1,
        statement: IssueStatementV1,
        proof: IssueProofV1,
    ) -> bool:
        expected = sha256_bytes(
            self._proof_domain + public_parameters.encode() + statement.encode()
        )
        return proof.backend_payload == expected


def fixture() -> tuple[InsecureTestOnlyIssueBackend, bytes, bytes, bytes]:
    backend = InsecureTestOnlyIssueBackend()
    relation_digest = sha256_bytes(b"INSECURE-TEST-ONLY-RELATION-V1")
    pp = Setup(backend, "insecure-test-only-128", relation_digest, production=False)
    statement = IssueStatementV1(
        ABI_PROFILE_DIGEST,
        sha256_bytes(pp),
        hashlib.shake_256(b"fixture-ctx").digest(32),
        hashlib.shake_256(b"fixture-issuer-side-sid").digest(32),
        hashlib.shake_256(b"fixture-rid").digest(32),
        hashlib.shake_256(b"fixture-beta").digest(BLIND_REQUEST_BYTES),
    ).encode()
    witness = IssueWitnessV1(
        ABI_PROFILE_DIGEST,
        hashlib.shake_256(b"fixture-ticket-payload").digest(TICKET_PAYLOAD_BYTES),
        hashlib.shake_256(b"fixture-r").digest(BLIND_REQUEST_BYTES),
        cap.deterministic_randomness(
            cap.PRODUCTION_PARAMETERS,
            b"PQ-RBBC/ISSUANCE-ZK-BACKEND/INSECURE-TEST-ONLY-RHO/V1",
        ).serialize(cap.PRODUCTION_PARAMETERS),
        hashlib.shake_256(b"fixture-holder-key").digest(HOLDER_KEY_BYTES),
        hashlib.shake_256(b"fixture-error-vector").digest(ERROR_VECTOR_BYTES),
    ).encode()
    return backend, pp, statement, witness


def run_bounded_self_check() -> dict[str, object]:
    backend, pp, statement, witness = fixture()
    proof = ProveIssue(backend, pp, statement, witness, production=False)
    rejected: list[str] = []

    changed_statement = bytearray(statement)
    changed_statement[-1] ^= 1
    if not VerifyIssue(backend, pp, bytes(changed_statement), proof, production=False):
        rejected.append("wrong_statement")

    decoded_proof = IssueProofV1.decode(proof)
    wrong_domain = IssueProofV1(
        decoded_proof.abi_profile_digest,
        decoded_proof.backend_id,
        decoded_proof.backend_version,
        decoded_proof.public_parameters_digest,
        decoded_proof.statement_digest,
        b"PQ-RBBC/WRONG-DOMAIN/V1",
        decoded_proof.backend_payload,
    ).encode()
    if not VerifyIssue(backend, pp, statement, wrong_domain, production=False):
        rejected.append("wrong_domain")

    changed_payload = bytearray(proof)
    changed_payload[-1] ^= 1
    if not VerifyIssue(backend, pp, statement, bytes(changed_payload), production=False):
        rejected.append("proof_mutation")
    if not VerifyIssue(backend, pp, statement, proof + b"\x00", production=False):
        rejected.append("proof_trailing_bytes")

    wrong_version = bytearray(proof)
    wrong_version[len(PROOF_MAGIC)] ^= 1
    if not VerifyIssue(backend, pp, statement, bytes(wrong_version), production=False):
        rejected.append("proof_wrong_version")

    production_refusals = 0
    for action in (
        lambda: Setup(backend, "insecure-test-only-128", bytes(32)),
        lambda: ProveIssue(backend, pp, statement, witness),
        lambda: VerifyIssue(backend, pp, statement, proof),
    ):
        try:
            action()
        except ProductionBackendUnavailable:
            production_refusals += 1

    return {
        "positive_verified": VerifyIssue(
            backend, pp, statement, proof, production=False
        ),
        "negative_cases": 5,
        "negative_cases_rejected": len(rejected),
        "rejected_case_ids": rejected,
        "production_entry_points": 3,
        "production_entry_points_refused": production_refusals,
        "relation_constraints_replayed": 0,
        "cryptographic_proofs_generated": 0,
    }


def validate_tracked_prerequisites() -> tuple[str, ...]:
    failures: list[str] = []
    for name, (relative, expected_size, expected_digest) in TRACKED_PREREQUISITES.items():
        path = ROOT / relative
        if not path.is_file():
            failures.append(f"{name}:missing")
        elif path.stat().st_size != expected_size:
            failures.append(f"{name}:bytes")
        elif _sha256_file(path) != expected_digest:
            failures.append(f"{name}:sha256")
    if failures:
        return tuple(failures)

    reference = _read_json(ROOT / TRACKED_PREREQUISITES["reference_manifest_v2_25"][0])
    br1cs = _read_json(ROOT / TRACKED_PREREQUISITES["br1cs_manifest_v2_25"][0])
    replay = _read_json(ROOT / TRACKED_PREREQUISITES["parent_join_evidence_v2_29"][0])
    unified = _read_json(
        ROOT / TRACKED_PREREQUISITES["unified_statement_manifest_v2_37"][0]
    )
    circuit = reference.get("circuit", {})
    archive = br1cs.get("archive", {})
    accounting = replay.get("accounting", {})
    statement_contract = unified.get("statement_contract", {})
    ticket_mapping = unified.get("ticket_mapping", {})
    if not isinstance(circuit, dict) or (
        circuit.get("public_input_bits"),
        circuit.get("secret_input_bits"),
        circuit.get("external_assertions"),
    ) != (4_032, 8_224, 1):
        failures.append("reference_manifest_v2_25:accounting")
    if not isinstance(archive, dict) or (
        archive.get("total_r1cs_rows"), archive.get("external_assertions")
    ) != (LEGACY_PARENT_ROWS, 1):
        failures.append("br1cs_manifest_v2_25:accounting")
    if not isinstance(accounting, dict) or (
        accounting.get("combined_rows"),
        accounting.get("external_assertions"),
        accounting.get("verification_failures"),
        accounting.get("ordered_replay_transcript_sha256"),
    ) != (COMPLETE_REPLAY_ROWS, 0, 0, COMPLETE_REPLAY_TRANSCRIPT_SHA256):
        failures.append("parent_join_evidence_v2_29:accounting")
    fields = statement_contract.get("fields", []) if isinstance(statement_contract, dict) else []
    if [item.get("name") for item in fields if isinstance(item, dict)] != [
        "common_parameters_digest", "ctx", "sid", "rid", "y"
    ]:
        failures.append("unified_statement_manifest_v2_37:fields")
    if not isinstance(ticket_mapping, dict) or ticket_mapping.get("sid") != (
        "SHA256(v2.37 session domain || IssueWitness.sn)"
    ):
        failures.append("unified_statement_manifest_v2_37:sid_semantics")
    return tuple(failures)


def candidate_backends() -> list[dict[str, object]]:
    return [
        {
            "name": "Aurora/libiop",
            "assumption_and_setup": "transparent hash/ROM; QROM claim in official implementation",
            "relation_fit": "R1CS; official implementation lists binary extension fields",
            "cost": "O(n log n) prover; O(n) verifier; O(log^2 n) argument",
            "license": "MIT",
            "post_quantum": "claimed",
            "zero_knowledge": "implemented research prototype",
            "knowledge_extractability": "claimed via BCS preservation",
            "simulation_extractability": "not established for this protocol",
            "maturity": "academic proof-of-concept; not production reviewed",
            "source": "https://github.com/scipr-lab/libiop",
        },
        {
            "name": "Brakedown/Shockwave",
            "assumption_and_setup": "transparent hash/random-oracle",
            "relation_fit": "Brakedown is field-agnostic R1CS; Shockwave requires FFT-friendly field",
            "cost": "linear Brakedown prover; sublinear proof and verifier",
            "license": "MIT reference branch; exact commit/license must be pinned",
            "post_quantum": "plausible",
            "zero_knowledge": "not implemented in cited prototype",
            "knowledge_extractability": "paper analysis only",
            "simulation_extractability": "not established",
            "maturity": "research branch; not production reviewed",
            "source": "https://eprint.iacr.org/2021/1043",
        },
        {
            "name": "STARK/Winterfell",
            "assumption_and_setup": "transparent hash-based",
            "relation_fit": "requires a new AIR translation rather than direct streamed R1CS consumption",
            "cost": "relation-specific; no 589030555-row estimate",
            "license": "MIT",
            "post_quantum": "plausible family-level target",
            "zero_knowledge": "current official implementation says not perfect ZK",
            "knowledge_extractability": "not qualified for this relation",
            "simulation_extractability": "not established",
            "maturity": "unaudited research implementation; not production",
            "source": "https://github.com/facebook/winterfell",
        },
        {
            "name": "LaBRADOR/lattirust",
            "assumption_and_setup": "Module-SIS",
            "relation_fit": "published R1CS is mod 2^64+1; binary/ring reductions remain in progress",
            "cost": "58 KB reported for 2^20 constraints at 128-bit security; not transferable",
            "license": "MIT OR Apache-2.0",
            "post_quantum": "claimed quantum-safe",
            "zero_knowledge": "not qualified for this protocol",
            "knowledge_extractability": "paper knowledge proof",
            "simulation_extractability": "not established",
            "maturity": "0.0.1-alpha research implementation; not audited",
            "source": "https://research.ibm.com/publications/labrador-compact-proofs-for-r1cs-from-module-sis",
        },
        {
            "name": "Binius64",
            "assumption_and_setup": "transparent hash-based",
            "relation_fit": "64-bit-word constraint system; requires re-arithmetization",
            "cost": "official task-specific benchmarks only; no 589030555-row estimate",
            "license": "MIT OR Apache-2.0",
            "post_quantum": "claimed",
            "zero_knowledge": "documentation status must be commit-pinned and reconciled",
            "knowledge_extractability": "not qualified for this protocol",
            "simulation_extractability": "not established",
            "maturity": "rapidly evolving; no production qualification here",
            "source": "https://github.com/binius-zk/binius64",
        },
    ]


def build_manifest() -> dict[str, object]:
    failures = list(validate_tracked_prerequisites())
    return {
        "format": MANIFEST_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "tracked_prerequisites": {
            name: {"path": relative, "bytes": size, "sha256": digest}
            for name, (relative, size, digest) in TRACKED_PREREQUISITES.items()
        },
        "tracked_validation_failures": failures,
        "actual_implementation_inventory": {
            "reference_relation": "src/pq_rbbc_reference.py:IssueStatement/IssueWitness/verify_relation",
            "incremental_circuit": "src/pq_rbbc_reference.py:generate_issue_circuit",
            "binary_r1cs_lowering": "src/pq_rbbc_br1cs.py",
            "blind_uov_abi": "src/pq_rbbc_blind_uov_abi.py",
            "parent_join_replay": "src/pq_rbbc_parent_join_replay.py",
            "legacy_parent_rows": LEGACY_PARENT_ROWS,
            "complete_replay_rows": COMPLETE_REPLAY_ROWS,
            "complete_replay_failures": 0,
            "complete_replay_external_assertions": 0,
            "formal_pi_issue_generated": False,
        },
        "formal_relation_contract": {
            "public_statement": ["pp", "ctx", "sid", "rid", "beta"],
            "private_witness": ["M", "r", "rho", "k_hold", "e"],
            "conjuncts": ["I1_ticket_shape", "I2_ticket_digest", "I3_request_relation", "I4_holder_binding", "I5_trace_encryption"],
            "pi_issue_replaces_native_well_built_request_proof": True,
            "pi_issue_is_final_cap_pi_2": False,
        },
        "relation_partition_findings": {
            "legacy_public_statement": ["common_ctx", "rid", "payload", "blind_request"],
            "legacy_private_witness": ["sn", "holder_key", "error", "blind_mask", "blind_randomness", "blind_hash_image"],
            "legacy_payload_is_public_but_formal_M_is_private": True,
            "legacy_statement_has_pp": False,
            "legacy_statement_has_sid": False,
            "v2_37_statement_shape_available": True,
            "v2_37_sid_is_fresh_issuer_side_sid": False,
            "v2_37_statement_joined_to_complete_relation": False,
            "legacy_replay_is_formal_pi_issue_relation": False,
            "new_relation_namespace_required": True,
        },
        "required_security_properties": {
            "post_quantum": True,
            "zero_knowledge": True,
            "knowledge_soundness_or_extractability": True,
            "simulation_extractability": {
                "required_for_full_current_protocol_claim": True,
                "reason": "concurrent issuance and the gated-CCA/GCCA simulated-transcript extraction hybrid",
                "standalone_decoder_safety_can_use_knowledge_soundness_only": True,
                "claim_reduction_authorized": False,
            },
            "non_interactive": True,
            "fiat_shamir_conditions": [
                "a scheme-specific QROM proof",
                "canonical transcript grammar and ordering",
                "domain separation across protocol, backend, version, profile, relation, and proof role",
                "exact binding of public parameters and statement bytes",
                "no inference of simulation extractability from naming or plain Fiat-Shamir use",
            ],
            "setup_conditions": [
                "transparent setup or an explicitly reviewed CRS ceremony",
                "simulation/extraction trapdoors exist only in the proof model and are unavailable in the real protocol",
                "public parameters have a canonical identity-pinned serialization",
            ],
        },
        "candidate_backends": candidate_backends(),
        "recommendation": {
            "production_backend_selected": False,
            "bounded_engineering_baseline": "Aurora/libiop",
            "performance_comparator": "Brakedown",
            "major_backend_integration_authorized": False,
            "reason": "no candidate is qualified for PQ+ZK+SE, the formal public/private partition, the 193-bit target field, 589030555-row scale, and production maturity together",
        },
        "canonical_interface": {
            "operations": ["Setup", "ProveIssue", "VerifyIssue"],
            "codec_version": CODEC_VERSION,
            "integer_encoding": "unsigned little-endian",
            "section_length_encoding": "u64le",
            "abi_profile_digest": ABI_PROFILE_DIGEST.hex(),
            "statement_fields": ["abi_profile_digest", "public_parameters_digest", "ctx", "sid", "rid", "beta"],
            "witness_fields": ["abi_profile_digest", "ticket_payload_M", "blind_mask_r", "canonical_cap_randomness_rho", "holder_key", "error_vector_e"],
            "cap_randomness_bytes": CAP_RANDOMNESS_BYTES,
            "cap_randomness_profile": CAP_RANDOMNESS_PROFILE,
            "test_adapter_32_byte_nonce_accepted_as_rho": False,
            "proof_fields": ["abi_profile_digest", "backend_id", "backend_version", "public_parameters_digest", "statement_digest", "transcript_domain", "backend_payload"],
            "transcript_domain_hex": TRANSCRIPT_DOMAIN.hex(),
            "unknown_reordered_duplicate_truncated_or_trailing_sections_rejected": True,
            "private_witness_must_not_be_written_to_artifacts": True,
        },
        "production_gate": {
            "production_backend_allowlist_empty": True,
            "test_backend_id": InsecureTestOnlyIssueBackend.backend_id,
            "test_backend_is_cryptographically_secure": False,
            "test_backend_can_enter_production": False,
            "production_api_fails_before_output": True,
            "safe_to_integrate_major_backend": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
        },
        "future_external_requirements": [
            "identity-pinned selected-backend specification and security proof",
            "explicit PQ simulation-extractability theorem mapped to the exact transform/transcript",
            "pinned official implementation source, version, license, build, and dependency inventory",
            "frozen field/parameter/security profile and concrete bound",
            "canonical public-parameter and proof serialization specification with vectors",
            "reduced relation integration evidence and independent cryptographic review",
            "operator-approved resources and separate authorization before any large proving run",
        ],
        "resource_estimate": {
            "cpu_cores": 1,
            "peak_memory_mib_upper_bound": 256,
            "elapsed_seconds_upper_bound": 60,
            "relation_constraints_replayed": 0,
            "cryptographic_proofs_generated": 0,
        },
        "exact_commands": {
            "bounded_self_check": "PYTHONPATH=src python -u src/pq_rbbc_issuance_zk_backend_preflight.py --self-check",
            "targeted_tests": "PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_zk_backend_preflight -v",
            "large_proving": None,
        },
        "claim_status": {
            "Defined": {
                "formal_backend_requirements": True,
                "canonical_interface_and_encodings": True,
            },
            "Instantiated": {
                "insecure_test_only_backend": True,
                "qualified_production_backend": False,
            },
            "Implemented": {
                "interface_codec_and_fail_closed_gate": True,
                "cryptographically_secure_backend": False,
            },
            "Tested": {
                "bounded_interface_regressions_defined": True,
                "large_relation_proving_tested": False,
            },
            "Evidence-sealed": {
                "preflight_contract": True,
                "production_backend": False,
            },
            "Proof-closed": False,
            "Production-closed": False,
        },
        "artifact_policy": {
            "assignment_or_br1cs_created": False,
            "pickle_cache_checkpoint_resume_or_log_created": False,
            "large_proving_output_created": False,
            "historical_v2_25_v2_29_v2_37_bytes_modified": False,
            "other_tree_observed_stream_bytes_reused": False,
            "system_architecture_changed": False,
            "ticket_lifecycle_changed": False,
            "pq_sat_auth_changed": False,
        },
    }


def build_portable_evidence() -> dict[str, object]:
    manifest_path = ROOT / "manifests/pq_rbbc_issuance_zk_backend_preflight_manifest_v1.json"
    manifest = _read_json(manifest_path)
    if manifest != build_manifest():
        raise ValueError("issuance ZK backend preflight manifest mismatch")
    self_check = run_bounded_self_check()
    if (
        self_check["positive_verified"] is not True
        or self_check["negative_cases_rejected"] != self_check["negative_cases"]
        or self_check["production_entry_points_refused"]
        != self_check["production_entry_points"]
    ):
        raise ValueError("bounded interface self-check failed")
    tracked = {
        "implementation": ROOT / "src/pq_rbbc_issuance_zk_backend_preflight.py",
        "tests": ROOT / "tests/test_pq_rbbc_issuance_zk_backend_preflight.py",
        "manifest": manifest_path,
        "artifact_note": ROOT / "docs/artifacts/PQ_RBBC_ISSUANCE_ZK_BACKEND_PREFLIGHT_zh-TW.md",
    }
    return {
        "format": EVIDENCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": "pq-rbbc/issuance-zk-backend/preflight-evidence/v1",
        "source_identities": {name: _identity(path) for name, path in tracked.items()},
        "bound_manifest_sha256": _sha256_file(manifest_path),
        "tracked_prerequisites_verified": not validate_tracked_prerequisites(),
        "bounded_self_check": self_check,
        "result": {
            "formal_relation_inventory_completed": True,
            "formal_legacy_partition_mismatch_detected": True,
            "simulation_extractability_required_for_full_claim": True,
            "canonical_backend_interface_defined": True,
            "insecure_test_only_backend_implemented": True,
            "qualified_production_backend_selected": False,
            "formal_pi_issue_generated": False,
            "safe_to_integrate_major_backend": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
            "proof_closed": False,
            "production_closed": False,
        },
        "claim_status": manifest["claim_status"],
        "remaining_blockers": [
            "formal statement/witness partition is not joined to the complete relation",
            "fresh issuer-side sid semantics are not frozen in the relation",
            "no identity-pinned PQ ZK simulation-extractable backend is qualified",
            "production public-parameter/proof serialization and parameters are absent",
            "reduced backend integration evidence and independent review are absent",
        ],
        "resource_observation": {
            "relation_constraints_replayed": 0,
            "cryptographic_proofs_generated": 0,
            "large_artifacts_created": 0,
        },
        "artifact_policy": manifest["artifact_policy"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print-manifest", action="store_true")
    parser.add_argument("--print-evidence", action="store_true")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    selected = sum((args.print_manifest, args.print_evidence, args.self_check))
    if selected != 1:
        parser.error("select exactly one bounded operation")
    if args.print_manifest:
        print(canonical_json(build_manifest()).decode(), end="")
    elif args.print_evidence:
        print(canonical_json(build_portable_evidence()).decode(), end="")
    else:
        print(canonical_json(run_bounded_self_check()).decode(), end="")


if __name__ == "__main__":
    main()
