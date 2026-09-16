#!/usr/bin/env python3
"""Production-input qualification gate for the PQ-RBBC issuance relation.

This checkpoint defines canonical bytes for the trace public key and issuance
common parameters, inventories the external certification inputs, and exposes
a general CAP.Commit-to-H_RBBC adapter.  The adapter is exercised only with an
explicitly insecure bounded topology.  Production evaluation refuses before
the 18-tree computation because no certified trace key, authenticated system
initialization, or independently reviewed candidate set is installed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
from pathlib import Path
from typing import Mapping, Sequence

import pq_rbbc_anemoi_sponge as h_rbbc
import pq_rbbc_blind_uov_abi as blind_uov
import pq_rbbc_cap_commit as cap
import pq_rbbc_issuance_relation_v1 as relation
import pq_rbbc_issuance_zk_backend_preflight as backend_preflight
import pq_rbbc_launch_io_v2_41 as launch_io
import pq_rbbc_reference as reference
from pq_rbbc.contracts.system import KeyRole
from pq_rbbc.governance.system_init import AuthenticatedSystemInitialization


IMPLEMENTATION_VERSION = "1.0"
FORMAT = "PQRBBC-ISSUANCE-PRODUCTION-INPUTS-PREFLIGHT-1"
EVIDENCE_FORMAT = "PQRBBC-ISSUANCE-PRODUCTION-INPUTS-PORTABLE-EVIDENCE-1"
GATE_ID = "pq-rbbc/issuance/production-inputs/preflight/v1"
ROOT = Path(__file__).resolve().parents[1]

TRACE_KEY_MAGIC = b"PQRBBC-TRACE-PUBLIC-KEY-V1"
COMMON_PARAMETERS_MAGIC = b"PQRBBC-ISSUE-COMMON-PARAMETERS-V1"
CODEC_VERSION = 1
TRACE_SCHEME_ID = "PQ-RBBC-BINARY-GOPPA-6688128-CANDIDATE-V1"
TRACE_KEY_ENCODING_ID = "SYSTEMATIC-H-I-THEN-T-ROW-MAJOR-LSB0-V1"
COMMON_PARAMETERS_PROFILE_ID = "PQ-RBBC-ISSUANCE-COMMON-PARAMETERS-CANDIDATE-V1"

CAP_PROFILE_FINGERPRINT = cap.profile_fingerprint(cap.PRODUCTION_PARAMETERS)
H_RBBC_PROFILE_FINGERPRINT = h_rbbc.profile_fingerprint(
    h_rbbc.permutation.derive_parameters()
)
TRACE_TAIL_ROW_BYTES = reference.K // 8
TRACE_KEY_BODY_BYTES = reference.R * TRACE_TAIL_ROW_BYTES
MAX_TRACE_KEY_BYTES = launch_io.MAX_JSON_BYTES

TRACE_KEY_FILENAME = "pq_rbbc_trace_public_key_v1.bin"
COMMON_PARAMETERS_FILENAME = "pq_rbbc_issuance_common_parameters_v1.bin"
INITIALIZATION_FILENAME = "pq_rbbc_authenticated_system_initialization_v1.bin"
TRACE_CERTIFICATION_FILENAME = "pq_rbbc_trace_public_key_certification_v1.json"
INDEPENDENT_REVIEW_FILENAME = (
    "pq_rbbc_issuance_production_inputs_independent_review_v1.json"
)

REQUIRED_EXTERNAL_ARTIFACTS = (
    TRACE_KEY_FILENAME,
    TRACE_CERTIFICATION_FILENAME,
    INITIALIZATION_FILENAME,
    COMMON_PARAMETERS_FILENAME,
    INDEPENDENT_REVIEW_FILENAME,
)

DOMAIN_TRACE_PROFILE = b"PQ-RBBC/ISSUANCE-PRODUCTION-INPUTS/TRACE-PROFILE/V1"
DOMAIN_COMMON_PARAMETERS = (
    b"PQ-RBBC/ISSUANCE-PRODUCTION-INPUTS/COMMON-PARAMETERS/V1"
)

TRACE_PROFILE_DOCUMENT = {
    "format": "PQRBBC-TRACE-PUBLIC-KEY-PROFILE-1",
    "scheme_id": TRACE_SCHEME_ID,
    "encoding_id": TRACE_KEY_ENCODING_ID,
    "n": reference.N,
    "k": reference.K,
    "r": reference.R,
    "t": reference.T,
    "matrix": "H=(I_R|T)",
    "tail_row_bytes": TRACE_TAIL_ROW_BYTES,
    "tail_rows": reference.R,
    "tail_body_bytes": TRACE_KEY_BODY_BYTES,
    "bit_order": "least-significant-bit first within each byte",
    "trace_kdf_order": "P[0:48] || K_mac[48:80]",
}


TRACKED_PREREQUISITES = {
    "core_proof": (
        "docs/proof/source/pq_rbbc_sgtd_core_proof_v1.tex",
        148_798,
        "cee211e7c6419480c0571b752faebe3574d3309f4e876a75cf325f3027d9f884",
    ),
    "formal_relation": (
        "src/pq_rbbc_issuance_relation_v1.py",
        31_165,
        "4c0db79e896824c77ef869fdfa2c8fc3e26c9942e12c0a49526f2b54bfbbf57e",
    ),
    "formal_relation_manifest": (
        "manifests/pq_rbbc_issuance_relation_manifest_v1.json",
        4_370,
        "18fface2cfffacdb063c17e86dad7be55f194ba60a078d119f2ce98b588e1af1",
    ),
    "formal_relation_evidence": (
        "artifacts/metadata/issuance_relation_v1/"
        "pq_rbbc_issuance_relation_portable_evidence_v1.json",
        2_068,
        "3830e35cb82c979b72e1760ff122caeb8cd5509abe19f2c61298875536bf3f85",
    ),
    "cap_commit": (
        "src/pq_rbbc_cap_commit.py",
        32_526,
        "be3a2a767561f009acc2a274a85410ae6e02e23abd24145aa1d61883dd2dceee",
    ),
    "cap_h_rbbc_abi": (
        "src/pq_rbbc_blind_uov_abi.py",
        47_227,
        "575de440a2477e24e562ceb0f3049a13deff6031f3aa434609b7752b631491a2",
    ),
    "h_rbbc": (
        "src/pq_rbbc_anemoi_sponge.py",
        25_336,
        "6d4e604cd937357cd76f9c127fa9fe94392bbc89b1a0b7972196545ab36424ec",
    ),
    "snapshot_io": (
        "src/pq_rbbc_launch_io_v2_41.py",
        10_564,
        "d7589d22abf251f9d2297455bafccaed34be7900b9e11e68ac037d9ad4c3a061",
    ),
    "system_contract": (
        "src/pq_rbbc/contracts/system.py",
        14_030,
        "4063a8ef0ad45e74f52abe4423c396b1668176d2f9ada4b24bea2724af17c4fc",
    ),
    "system_initialization": (
        "src/pq_rbbc/governance/system_init.py",
        7_610,
        "d31867c4520ba9ba28fcac5578b53c147245270f3645a05cb5d03991e4e93df2",
    ),
}


class ProductionInputsError(ValueError):
    """A noncanonical or inconsistent production-input candidate."""


class ProductionInputsUnavailable(RuntimeError):
    """Production evaluation was requested before qualification."""


def canonical_json(document: object) -> bytes:
    return (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def sha256_bytes(raw: bytes) -> bytes:
    return hashlib.sha256(raw).digest()


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


def _validate_ascii(value: str, label: str, maximum: int = 128) -> bytes:
    if type(value) is not str:
        raise ProductionInputsError(f"{label} must be text")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ProductionInputsError(f"{label} must be ASCII") from error
    allowed = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/"
    if (
        not encoded
        or len(encoded) > maximum
        or any(byte not in allowed for byte in encoded)
    ):
        raise ProductionInputsError(f"{label} is not canonical")
    return encoded


def _read_uint(
    encoded: bytes, offset: int, width: int, label: str
) -> tuple[int, int]:
    end = offset + width
    if end > len(encoded):
        raise ProductionInputsError(f"truncated {label}")
    return int.from_bytes(encoded[offset:end], "little"), end


def _read_bytes(
    encoded: bytes, offset: int, length: int, label: str
) -> tuple[bytes, int]:
    end = offset + length
    if length < 0 or end > len(encoded):
        raise ProductionInputsError(f"truncated {label}")
    return encoded[offset:end], end


def _encode_sections(magic: bytes, sections: Sequence[tuple[int, bytes]]) -> bytes:
    result = bytearray(magic)
    result.extend(CODEC_VERSION.to_bytes(2, "little"))
    result.extend(len(sections).to_bytes(2, "little"))
    for section_id, payload in sections:
        result.extend(section_id.to_bytes(2, "little"))
        result.extend(len(payload).to_bytes(8, "little"))
        result.extend(payload)
    return bytes(result)


def _decode_sections(
    encoded: bytes,
    magic: bytes,
    schema: Sequence[tuple[int, str, int, int]],
) -> dict[str, bytes]:
    if not isinstance(encoded, bytes) or not encoded.startswith(magic):
        raise ProductionInputsError("wrong magic")
    offset = len(magic)
    version, offset = _read_uint(encoded, offset, 2, "version")
    if version != CODEC_VERSION:
        raise ProductionInputsError("wrong version")
    count, offset = _read_uint(encoded, offset, 2, "section count")
    if count != len(schema):
        raise ProductionInputsError("wrong section count")
    values: dict[str, bytes] = {}
    for expected_id, name, minimum, maximum in schema:
        section_id, offset = _read_uint(encoded, offset, 2, f"{name} id")
        if section_id != expected_id:
            raise ProductionInputsError(f"noncanonical {name} section")
        length, offset = _read_uint(encoded, offset, 8, f"{name} length")
        if not minimum <= length <= maximum:
            raise ProductionInputsError(f"wrong {name} length")
        values[name], offset = _read_bytes(encoded, offset, length, name)
    if offset != len(encoded):
        raise ProductionInputsError("trailing bytes")
    return values


TRACE_PROFILE_DIGEST = sha256_bytes(
    DOMAIN_TRACE_PROFILE + canonical_json(TRACE_PROFILE_DOCUMENT)
)


@dataclass(frozen=True)
class TracePublicKeyV1:
    """Canonical systematic parity-check public key bytes.

    Parsing this object establishes only shape and byte identity.  It does not
    establish that the matrix was generated from a binary Goppa secret key.
    That property requires a separately authenticated producer certificate.
    """

    body: bytes

    def encode(self) -> bytes:
        if not isinstance(self.body, bytes) or len(self.body) != TRACE_KEY_BODY_BYTES:
            raise ProductionInputsError("wrong trace public-key body length")
        sections = (
            (1, _validate_ascii(TRACE_SCHEME_ID, "trace scheme")),
            (2, _validate_ascii(TRACE_KEY_ENCODING_ID, "trace encoding")),
            (3, TRACE_PROFILE_DIGEST),
            (4, reference.N.to_bytes(4, "little")),
            (5, reference.K.to_bytes(4, "little")),
            (6, reference.T.to_bytes(4, "little")),
            (7, self.body),
        )
        encoded = _encode_sections(TRACE_KEY_MAGIC, sections)
        if len(encoded) > MAX_TRACE_KEY_BYTES:
            raise AssertionError("trace key exceeds bounded snapshot limit")
        return encoded

    @classmethod
    def decode(cls, encoded: bytes) -> "TracePublicKeyV1":
        values = _decode_sections(
            encoded,
            TRACE_KEY_MAGIC,
            (
                (1, "scheme_id", 1, 128),
                (2, "encoding_id", 1, 128),
                (3, "profile_digest", 32, 32),
                (4, "n", 4, 4),
                (5, "k", 4, 4),
                (6, "t", 4, 4),
                (7, "matrix_body", TRACE_KEY_BODY_BYTES, TRACE_KEY_BODY_BYTES),
            ),
        )
        if values["scheme_id"] != TRACE_SCHEME_ID.encode("ascii"):
            raise ProductionInputsError("wrong trace scheme")
        if values["encoding_id"] != TRACE_KEY_ENCODING_ID.encode("ascii"):
            raise ProductionInputsError("wrong trace key encoding")
        if values["profile_digest"] != TRACE_PROFILE_DIGEST:
            raise ProductionInputsError("wrong trace profile digest")
        dimensions = tuple(
            int.from_bytes(values[name], "little") for name in ("n", "k", "t")
        )
        if dimensions != (reference.N, reference.K, reference.T):
            raise ProductionInputsError("wrong trace parameters")
        result = cls(values["matrix_body"])
        if result.encode() != encoded:
            raise ProductionInputsError("noncanonical trace public key")
        return result


@dataclass(frozen=True)
class ProductionIssuanceCommonParametersV1:
    """Canonical digest binding consumed by the formal issuance statement."""

    trace_public_key_sha256: bytes
    trace_certification_sha256: bytes
    issuer_verification_key_digest: bytes

    def encode(self) -> bytes:
        fixed = (
            self.trace_public_key_sha256,
            self.trace_certification_sha256,
            self.issuer_verification_key_digest,
        )
        if any(
            not isinstance(value, bytes)
            or len(value) != 32
            or value == bytes(32)
            for value in fixed
        ):
            raise ProductionInputsError("common-parameter digests must be 32 bytes")
        sections = (
            (1, _validate_ascii(COMMON_PARAMETERS_PROFILE_ID, "parameter profile")),
            (2, _validate_ascii(relation.RELATION_ID, "formal relation")),
            (3, backend_preflight.ABI_PROFILE_DIGEST),
            (4, _validate_ascii(cap.PROFILE_RELATION_ID, "CAP relation")),
            (5, bytes.fromhex(CAP_PROFILE_FINGERPRINT)),
            (6, _validate_ascii(h_rbbc.PROFILE_RELATION_ID, "H_RBBC relation")),
            (7, bytes.fromhex(H_RBBC_PROFILE_FINGERPRINT)),
            (8, TRACE_PROFILE_DIGEST),
            (9, self.trace_public_key_sha256),
            (10, self.trace_certification_sha256),
            (11, self.issuer_verification_key_digest),
            (
                12,
                bytes.fromhex(
                    TRACKED_PREREQUISITES["formal_relation_manifest"][2]
                ),
            ),
        )
        return _encode_sections(COMMON_PARAMETERS_MAGIC, sections)

    @classmethod
    def decode(cls, encoded: bytes) -> "ProductionIssuanceCommonParametersV1":
        values = _decode_sections(
            encoded,
            COMMON_PARAMETERS_MAGIC,
            (
                (1, "profile_id", 1, 128),
                (2, "relation_id", 1, 128),
                (3, "statement_abi", 32, 32),
                (4, "cap_relation", 1, 128),
                (5, "cap_profile", 32, 32),
                (6, "h_rbbc_relation", 1, 128),
                (7, "h_rbbc_profile", 32, 32),
                (8, "trace_profile", 32, 32),
                (9, "trace_key", 32, 32),
                (10, "trace_certificate", 32, 32),
                (11, "issuer_key", 32, 32),
                (12, "relation_manifest", 32, 32),
            ),
        )
        expected = {
            "profile_id": COMMON_PARAMETERS_PROFILE_ID.encode("ascii"),
            "relation_id": relation.RELATION_ID.encode("ascii"),
            "statement_abi": backend_preflight.ABI_PROFILE_DIGEST,
            "cap_relation": cap.PROFILE_RELATION_ID.encode("ascii"),
            "cap_profile": bytes.fromhex(CAP_PROFILE_FINGERPRINT),
            "h_rbbc_relation": h_rbbc.PROFILE_RELATION_ID.encode("ascii"),
            "h_rbbc_profile": bytes.fromhex(H_RBBC_PROFILE_FINGERPRINT),
            "trace_profile": TRACE_PROFILE_DIGEST,
            "relation_manifest": bytes.fromhex(
                TRACKED_PREREQUISITES["formal_relation_manifest"][2]
            ),
        }
        for name, wanted in expected.items():
            if values[name] != wanted:
                raise ProductionInputsError(f"wrong common-parameter {name}")
        result = cls(
            values["trace_key"],
            values["trace_certificate"],
            values["issuer_key"],
        )
        if result.encode() != encoded:
            raise ProductionInputsError("noncanonical common parameters")
        return result


def decode_cap_randomness(
    parameters: cap.CAPParameters, encoded: bytes
) -> cap.CAPRandomness:
    """Strictly decode CAP salt/root bytes for any explicitly supplied profile."""
    if not isinstance(encoded, bytes) or not encoded.startswith(cap.RANDOMNESS_MAGIC):
        raise ProductionInputsError("wrong CAP randomness magic")
    offset = len(cap.RANDOMNESS_MAGIC)
    fingerprint, offset = _read_bytes(encoded, offset, 64, "CAP profile")
    if fingerprint != cap.profile_fingerprint(parameters).encode("ascii"):
        raise ProductionInputsError("wrong CAP randomness profile")

    def field_element(label: str) -> int:
        nonlocal offset
        raw, offset = _read_bytes(
            encoded, offset, cap.field.FIELD_ELEMENT_BYTES, label
        )
        value = int.from_bytes(raw, "little")
        if value > cap.field.FIELD_MASK:
            raise ProductionInputsError(f"noncanonical {label}")
        return value

    salt = (field_element("salt[0]"), field_element("salt[1]"))
    tree_count, offset = _read_uint(encoded, offset, 2, "tree count")
    if tree_count != parameters.tree_count:
        raise ProductionInputsError("wrong CAP randomness tree count")
    roots = tuple(
        (field_element(f"root[{index}][0]"), field_element(f"root[{index}][1]"))
        for index in range(tree_count)
    )
    if offset != len(encoded):
        raise ProductionInputsError("trailing CAP randomness bytes")
    result = cap.CAPRandomness(salt, roots)
    if result.serialize(parameters) != encoded:
        raise ProductionInputsError("noncanonical CAP randomness")
    return result


@dataclass(frozen=True)
class CAPToHRBBCResult:
    request: bytes
    mask: bytes
    commitment: bytes
    hash_image: bytes
    cap_profile_fingerprint: str
    production_qualified: bool


class CAPToHRBBCAdapterV1:
    """General direct adapter over the actual CAP and H_RBBC implementations."""

    def __init__(
        self,
        parameters: cap.CAPParameters,
    ) -> None:
        self.parameters = parameters

    def derive_request(
        self, message: bytes, mask: bytes, randomness_bytes: bytes
    ) -> CAPToHRBBCResult:
        if not isinstance(message, bytes) or len(message) != blind_uov.MESSAGE_BYTES:
            raise ProductionInputsError("ticket message must be 32 bytes")
        if not isinstance(mask, bytes) or len(mask) != blind_uov.MASK_BYTES:
            raise ProductionInputsError("blind mask must be 72 bytes")
        is_production = self.parameters == cap.PRODUCTION_PARAMETERS
        if is_production:
            raise ProductionInputsUnavailable(
                "production adapter is disabled in this checkpoint; refusing before 18-tree CAP execution"
            )
        if self.parameters.mask_bits != 8 * blind_uov.MASK_BYTES:
            raise ProductionInputsError("CAP profile does not derive a 576-bit mask")
        randomness = decode_cap_randomness(self.parameters, randomness_bytes)
        execution = cap.execute_cap_commit(
            self.parameters,
            randomness,
            allow_large=False,
        )
        commitment = execution.commitment
        derived_mask = commitment.derived_mask.to_bytes(blind_uov.MASK_BYTES, "little")
        if derived_mask != mask:
            raise ProductionInputsError("formal witness r does not equal CAP-derived mask")
        hash_image = h_rbbc.hash_request_binding(message, commitment.encoded)
        request = blind_uov.xor_bytes(mask, hash_image)
        return CAPToHRBBCResult(
            request=request,
            mask=mask,
            commitment=commitment.encoded,
            hash_image=hash_image,
            cap_profile_fingerprint=cap.profile_fingerprint(self.parameters),
            production_qualified=False,
        )


# Same witness width and hash join as production, but deliberately tiny trees.
# This is an interface/control-flow fixture, never a security parameter set.
INSECURE_TEST_ONLY_ADAPTER_PARAMETERS = cap.CAPParameters(
    name="PQ-RBBC-ISSUANCE-I3-ADAPTER-INSECURE-TEST-ONLY",
    security_bits=0,
    mask_bits=576,
    appended_signature_bits=1472,
    degree=2,
    rho=2,
    consistency_points=2,
    tree_specs=(cap.TreeSpec(2, 4),),
    secure_profile=False,
)


@dataclass(frozen=True)
class CandidateSet:
    """Immutable captures; validation never reopens their pathnames."""

    root: Path
    trace_key: launch_io.Snapshot | None = None
    trace_certification: launch_io.Snapshot | None = None
    initialization: launch_io.Snapshot | None = None
    common_parameters: launch_io.Snapshot | None = None
    independent_review: launch_io.Snapshot | None = None
    capture_failures: tuple[str, ...] = ()


def read_candidate_set(root: Path) -> CandidateSet:
    artifact_root = launch_io.ArtifactRoot(root)
    failures: list[str] = []

    def read_optional(filename: str) -> launch_io.Snapshot | None:
        try:
            return artifact_root.read(root / filename)
        except FileNotFoundError:
            return None
        except launch_io.ValidationError as error:
            failures.append(f"{filename}:capture:{error}")
            return None

    return CandidateSet(
        root=root,
        trace_key=read_optional(TRACE_KEY_FILENAME),
        trace_certification=read_optional(TRACE_CERTIFICATION_FILENAME),
        initialization=read_optional(INITIALIZATION_FILENAME),
        common_parameters=read_optional(COMMON_PARAMETERS_FILENAME),
        independent_review=read_optional(INDEPENDENT_REVIEW_FILENAME),
        capture_failures=tuple(failures),
    )


def _exact_keys(document: Mapping[str, object], keys: set[str], label: str) -> None:
    if type(document) is not dict or set(document) != keys:
        raise ProductionInputsError(f"{label} fields are not closed-world canonical")


def _validate_identity(value: object, label: str) -> dict[str, object]:
    if type(value) is not dict:
        raise ProductionInputsError(f"{label} identity must be an object")
    _exact_keys(value, {"filename", "bytes", "sha256"}, f"{label} identity")
    filename = value["filename"]
    size = value["bytes"]
    digest = value["sha256"]
    if (
        type(filename) is not str
        or "/" in filename
        or filename in ("", ".", "..")
        or type(size) is not int
        or isinstance(size, bool)
        or size <= 0
        or type(digest) is not str
        or len(digest) != 64
    ):
        raise ProductionInputsError(f"{label} identity is invalid")
    try:
        bytes.fromhex(digest)
    except ValueError as error:
        raise ProductionInputsError(f"{label} SHA-256 is invalid") from error
    return dict(value)


def _validate_trace_certification(
    snapshot: launch_io.Snapshot, trace_identity: Mapping[str, object]
) -> None:
    document = snapshot.document()
    _exact_keys(
        document,
        {
            "format",
            "gate_id",
            "trace_key_identity",
            "trace_profile_digest",
            "parameter_set",
            "generation",
            "ceremony_transcript_identity",
            "producer_attestation_identity",
            "claim_boundary",
        },
        "trace certification",
    )
    if document["format"] != "PQRBBC-TRACE-PUBLIC-KEY-CERTIFICATION-1":
        raise ProductionInputsError("wrong trace certification format")
    if document["gate_id"] != GATE_ID:
        raise ProductionInputsError("wrong trace certification gate")
    if _validate_identity(document["trace_key_identity"], "trace key") != dict(
        trace_identity
    ):
        raise ProductionInputsError("trace certification key identity mismatch")
    if document["trace_profile_digest"] != TRACE_PROFILE_DIGEST.hex():
        raise ProductionInputsError("trace certification profile mismatch")
    if document["parameter_set"] != {
        "encoding_id": TRACE_KEY_ENCODING_ID,
        "k": reference.K,
        "n": reference.N,
        "scheme_id": TRACE_SCHEME_ID,
        "t": reference.T,
    }:
        raise ProductionInputsError("trace certification parameter mismatch")
    generation = document["generation"]
    if type(generation) is not dict:
        raise ProductionInputsError("trace generation must be an object")
    _exact_keys(
        generation,
        {
            "implementation_id",
            "implementation_version",
            "source_identity",
            "test_fixture",
        },
        "trace generation",
    )
    _validate_ascii(generation["implementation_id"], "generator id")
    _validate_ascii(generation["implementation_version"], "generator version")
    _validate_identity(generation["source_identity"], "generator source")
    if generation["test_fixture"] is not False:
        raise ProductionInputsError("test trace key cannot be production-certified")
    _validate_identity(document["ceremony_transcript_identity"], "ceremony")
    _validate_identity(document["producer_attestation_identity"], "producer attestation")
    if document["claim_boundary"] != {
        "goppa_construction_attested": True,
        "production_use_authorized": True,
        "structural_encoding_validated": True,
    }:
        raise ProductionInputsError("trace certification claim boundary rejected")


def _validate_independent_review(
    snapshot: launch_io.Snapshot,
    identities: Mapping[str, Mapping[str, object]],
) -> None:
    document = snapshot.document()
    _exact_keys(
        document,
        {
            "format",
            "gate_id",
            "reviewed_identities",
            "scope",
            "disposition",
            "reviewer",
            "attestation_identity",
            "claim_boundary",
        },
        "independent review",
    )
    if document["format"] != "PQRBBC-ISSUANCE-PRODUCTION-INPUTS-REVIEW-1":
        raise ProductionInputsError("wrong independent-review format")
    if document["gate_id"] != GATE_ID:
        raise ProductionInputsError("wrong independent-review gate")
    reviewed = document["reviewed_identities"]
    if type(reviewed) is not dict or set(reviewed) != set(identities):
        raise ProductionInputsError("independent-review identity set mismatch")
    for name, identity in identities.items():
        if _validate_identity(reviewed[name], f"reviewed {name}") != dict(identity):
            raise ProductionInputsError(f"independent-review {name} mismatch")
    required_scope = [
        "canonical_common_parameters",
        "certified_trace_public_key",
        "authenticated_system_initialization",
        "CAP.Commit-to-H_RBBC-adapter",
    ]
    if document["scope"] != required_scope or document["disposition"] != "accept":
        raise ProductionInputsError("independent-review scope/disposition rejected")
    reviewer = document["reviewer"]
    if type(reviewer) is not dict:
        raise ProductionInputsError("reviewer must be an object")
    _exact_keys(reviewer, {"reviewer_id", "organization"}, "reviewer")
    _validate_ascii(reviewer["reviewer_id"], "reviewer id")
    _validate_ascii(reviewer["organization"], "reviewer organization")
    _validate_identity(document["attestation_identity"], "review attestation")
    if document["claim_boundary"] != {
        "cryptographic_proof_closed": False,
        "independent_review_completed": True,
        "production_inputs_accepted": True,
        "production_relation_closed": False,
    }:
        raise ProductionInputsError("independent-review claim boundary rejected")


def evaluate_candidate_set(candidates: CandidateSet) -> dict[str, object]:
    """Validate captured bytes and report blockers without authorizing use.

    Artifact schema and identity closure are necessary but not sufficient.
    Trusted producer/reviewer handoff and real signature verification remain
    external blockers in this checkpoint, so the safe-to-instantiate flag is
    deliberately always false.
    """
    snapshots = {
        TRACE_KEY_FILENAME: candidates.trace_key,
        TRACE_CERTIFICATION_FILENAME: candidates.trace_certification,
        INITIALIZATION_FILENAME: candidates.initialization,
        COMMON_PARAMETERS_FILENAME: candidates.common_parameters,
        INDEPENDENT_REVIEW_FILENAME: candidates.independent_review,
    }
    missing = tuple(name for name, snapshot in snapshots.items() if snapshot is None)
    failures: list[str] = list(candidates.capture_failures)
    for filename, snapshot in snapshots.items():
        if snapshot is not None and snapshot.location != candidates.root / filename:
            failures.append(f"{filename}:snapshot location mismatch")
    structural_complete = False
    if not missing:
        assert candidates.trace_key is not None
        assert candidates.trace_certification is not None
        assert candidates.initialization is not None
        assert candidates.common_parameters is not None
        assert candidates.independent_review is not None
        try:
            TracePublicKeyV1.decode(candidates.trace_key.raw)
            initialization = AuthenticatedSystemInitialization.decode(
                candidates.initialization.raw
            )
            common = ProductionIssuanceCommonParametersV1.decode(
                candidates.common_parameters.raw
            )
            identities = {
                "trace_key": candidates.trace_key.identity,
                "trace_certification": candidates.trace_certification.identity,
                "initialization": candidates.initialization.identity,
                "common_parameters": candidates.common_parameters.identity,
            }
            _validate_trace_certification(
                candidates.trace_certification, candidates.trace_key.identity
            )
            _validate_independent_review(candidates.independent_review, identities)
            issuer_key = initialization.bundle.key_for(KeyRole.ISSUER_VERIFICATION)
            if initialization.bundle.common_parameters_digest != sha256_bytes(
                candidates.common_parameters.raw
            ):
                raise ProductionInputsError(
                    "system initialization common-parameter digest mismatch"
                )
            if common.trace_public_key_sha256 != sha256_bytes(
                candidates.trace_key.raw
            ):
                raise ProductionInputsError("common parameters trace-key mismatch")
            if common.trace_certification_sha256 != sha256_bytes(
                candidates.trace_certification.raw
            ):
                raise ProductionInputsError(
                    "common parameters trace-certificate mismatch"
                )
            if common.issuer_verification_key_digest != issuer_key.public_key_digest:
                raise ProductionInputsError("common parameters issuer-key mismatch")
            structural_complete = not failures
        except (
            ProductionInputsError,
            launch_io.ValidationError,
            ValueError,
        ) as error:
            failures.append(str(error))
    blockers = list(missing)
    blockers.extend(failures)
    blockers.extend(
        (
            "trusted trace-key producer attestation verification not integrated",
            "trusted federation configuration authentication verifier not integrated",
            "trusted independent-review attestation verification not integrated",
            "production CAP/fork security qualification remains false",
        )
    )
    return {
        "format": FORMAT,
        "gate_id": GATE_ID,
        "captured_artifacts": sorted(
            [
                snapshot.identity
                for snapshot in snapshots.values()
                if snapshot is not None
            ],
            key=lambda identity: identity["filename"],
        ),
        "missing_artifacts": list(missing),
        "validation_failures": failures,
        "structural_candidate_complete": structural_complete,
        "trusted_handoff_complete": False,
        "production_cap_security_qualified": False,
        "safe_to_instantiate_production_relation": False,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
        "blockers": blockers,
    }


@lru_cache(maxsize=1)
def bounded_adapter_self_check() -> dict[str, object]:
    parameters = INSECURE_TEST_ONLY_ADAPTER_PARAMETERS
    message = hashlib.sha256(b"PQ-RBBC/production-inputs/v1/message").digest()
    randomness = cap.deterministic_randomness(
        parameters, b"PQ-RBBC/production-inputs/v1/rho-a"
    )
    encoded_randomness = randomness.serialize(parameters)
    execution = cap.execute_cap_commit(parameters, randomness)
    mask = execution.commitment.derived_mask.to_bytes(blind_uov.MASK_BYTES, "little")
    adapter = CAPToHRBBCAdapterV1(parameters)
    result = adapter.derive_request(message, mask, encoded_randomness)
    alternate_randomness = cap.deterministic_randomness(
        parameters, b"PQ-RBBC/production-inputs/v1/rho-b"
    )
    alternate_execution = cap.execute_cap_commit(parameters, alternate_randomness)
    alternate_mask = alternate_execution.commitment.derived_mask.to_bytes(
        blind_uov.MASK_BYTES, "little"
    )
    alternate = adapter.derive_request(
        message, alternate_mask, alternate_randomness.serialize(parameters)
    )
    production_refused = False
    try:
        CAPToHRBBCAdapterV1(cap.PRODUCTION_PARAMETERS).derive_request(
            message,
            bytes(blind_uov.MASK_BYTES),
            cap.deterministic_randomness(cap.PRODUCTION_PARAMETERS).serialize(
                cap.PRODUCTION_PARAMETERS
            ),
        )
    except ProductionInputsUnavailable:
        production_refused = True
    return {
        "profile": cap.profile_fingerprint(parameters),
        "test_only": True,
        "secure_profile": False,
        "same_cap_and_h_rbbc_code_paths": True,
        "first_commitment_bytes": len(result.commitment),
        "first_request_sha256": hashlib.sha256(result.request).hexdigest(),
        "second_request_sha256": hashlib.sha256(alternate.request).hexdigest(),
        "distinct_rho_supported": result.request != alternate.request,
        "production_refused_before_large_execution": production_refused,
        "relation_constraints_replayed": 0,
        "cryptographic_proofs_generated": 0,
    }


def validate_tracked_prerequisites() -> tuple[str, ...]:
    failures = []
    for name, (relative, expected_bytes, expected_sha256) in TRACKED_PREREQUISITES.items():
        path = ROOT / relative
        if not path.is_file():
            failures.append(f"{name}:missing")
            continue
        if path.stat().st_size != expected_bytes:
            failures.append(f"{name}:bytes")
        if _sha256_file(path) != expected_sha256:
            failures.append(f"{name}:sha256")
    return tuple(failures)


def build_manifest() -> dict[str, object]:
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "gate_id": GATE_ID,
        "predecessor": {
            "relation_id": relation.RELATION_ID,
            "manifest_sha256": TRACKED_PREREQUISITES[
                "formal_relation_manifest"
            ][2],
        },
        "common_parameters_contract": {
            "magic_hex": COMMON_PARAMETERS_MAGIC.hex(),
            "version": CODEC_VERSION,
            "profile_id": COMMON_PARAMETERS_PROFILE_ID,
            "statement_binding": "IssueStatementV1.public_parameters_digest = SHA-256(exact common-parameter bytes)",
            "cap_relation_id": cap.PROFILE_RELATION_ID,
            "cap_profile_fingerprint": CAP_PROFILE_FINGERPRINT,
            "h_rbbc_relation_id": h_rbbc.PROFILE_RELATION_ID,
            "h_rbbc_profile_fingerprint": H_RBBC_PROFILE_FINGERPRINT,
            "trace_profile_digest": TRACE_PROFILE_DIGEST.hex(),
            "issuer_verification_key_bound": True,
            "authenticated_system_initialization_binds_common_parameters": True,
        },
        "trace_public_key_contract": {
            **TRACE_PROFILE_DOCUMENT,
            "magic_hex": TRACE_KEY_MAGIC.hex(),
            "version": CODEC_VERSION,
            "encoded_bytes": len(TracePublicKeyV1(bytes(TRACE_KEY_BODY_BYTES)).encode()),
            "shape_validation_is_goppa_certification": False,
            "producer_attestation_required": True,
        },
        "cap_to_h_rbbc_adapter": {
            "general_rho_decoder_implemented": True,
            "formal_r_must_equal_cap_derived_mask": True,
            "canonical_commitment_bytes": cap.commitment_bytes(
                cap.PRODUCTION_PARAMETERS
            ),
            "h_rbbc_output_bytes": blind_uov.HASH_IMAGE_BYTES,
            "bounded_same_code_path_tested": True,
            "bounded_profile_is_insecure": True,
            "production_execution_enabled": False,
        },
        "snapshot_contract": {
            "single_open_single_bounded_read": True,
            "identity_parse_and_binding_use_same_immutable_raw": True,
            "metadata_only_best_effort_signal": True,
            "metadata_proves_no_concurrent_writer": False,
            "future_executor_must_consume_candidate_set_snapshots": True,
            "future_executor_may_reopen_pathnames": False,
        },
        "required_external_artifacts": list(REQUIRED_EXTERNAL_ARTIFACTS),
        "external_inventory": {
            "installed_in_checkpoint_environment": [],
            "missing": list(REQUIRED_EXTERNAL_ARTIFACTS),
        },
        "trust_requirements": [
            "trusted trace-key producer handoff and authenticated attestation",
            "writer quiescence plus owner/mode/ACL/writable-FD/mount controls",
            "out-of-band trusted federation configuration key",
            "qualified federation authentication verifier",
            "authenticated independent review bound to exact snapshots",
        ],
        "claim_boundary": {
            "Defined": True,
            "Instantiated": False,
            "Implemented": True,
            "Tested": True,
            "Evidence-sealed": True,
            "Proof-closed": False,
            "Production-closed": False,
            "production_common_parameters_instantiated": False,
            "certified_trace_public_key_instantiated": False,
            "production_cap_h_rbbc_adapter_qualified": False,
            "production_relation_instantiated": False,
            "formal_pi_issue_generated": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
            "system_architecture_changed": False,
            "ticket_lifecycle_changed": False,
            "pq_sat_auth_changed": False,
        },
        "resource_estimate": {
            "cpu_cores": 1,
            "peak_memory_mib_upper_bound": 256,
            "elapsed_seconds_upper_bound": 60,
            "relation_constraints_replayed": 0,
            "cryptographic_proofs_generated": 0,
        },
        "exact_read_only_command": (
            "PYTHONPATH=src python -u src/"
            "pq_rbbc_issuance_production_inputs_v1.py --artifact-root "
            "/ABSOLUTE/PRIVATE/ARTIFACT/ROOT"
        ),
        "tracked_prerequisites": {
            name: {"path": path, "bytes": size, "sha256": digest}
            for name, (path, size, digest) in TRACKED_PREREQUISITES.items()
        },
        "tracked_validation_failures": list(validate_tracked_prerequisites()),
    }


def build_portable_evidence() -> dict[str, object]:
    manifest_path = ROOT / "manifests/pq_rbbc_issuance_production_inputs_manifest_v1.json"
    manifest_identity = (
        _identity(manifest_path)
        if manifest_path.is_file()
        else {
            "filename": manifest_path.name,
            "bytes": len(canonical_json(build_manifest())),
            "sha256": hashlib.sha256(canonical_json(build_manifest())).hexdigest(),
        }
    )
    return {
        "format": EVIDENCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "gate_id": GATE_ID,
        "manifest": manifest_identity,
        "tracked_prerequisites_valid": not validate_tracked_prerequisites(),
        "bounded_adapter_self_check": bounded_adapter_self_check(),
        "external_artifacts_present": 0,
        "external_artifacts_required": len(REQUIRED_EXTERNAL_ARTIFACTS),
        "missing_external_artifacts": list(REQUIRED_EXTERNAL_ARTIFACTS),
        "production_common_parameters_instantiated": False,
        "certified_trace_public_key_instantiated": False,
        "production_relation_instantiated": False,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
        "private_witness_bytes_embedded": False,
        "large_artifacts_embedded": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", type=Path, required=True)
    args = parser.parse_args()
    candidates = read_candidate_set(args.artifact_root)
    print(canonical_json(evaluate_candidate_set(candidates)).decode("ascii"), end="")


if __name__ == "__main__":
    main()
