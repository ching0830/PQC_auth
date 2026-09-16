#!/usr/bin/env python3
"""Fresh bounded parent I1--I5 CandidateSet read-only preflight.

The checkpoint consumes the finding-free Global-tail completion CandidateSet,
adds canonical bounded parent parameters/statement/witness snapshots, and
validates the five issuance conjuncts with direct host reference operations.
It emits no circuit row, assignment, checkpoint, proof, or production output.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from functools import lru_cache
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from types import MappingProxyType
from typing import Mapping, Sequence

import pq_rbbc_anemoi_f193 as field193
import pq_rbbc_anemoi_sponge as h_rbbc
import pq_rbbc_cap_commit as cap
import pq_rbbc_issuance_bounded_multitree_adapter_v1 as adapter
import pq_rbbc_issuance_global_tail_completion_sealer_v1 as completion
import pq_rbbc_issuance_relation_v1 as formal_relation
import pq_rbbc_issuance_zk_backend_preflight as backend
import pq_rbbc_launch_io_v2_41 as io
import pq_rbbc_reference as reference


ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION_VERSION = "1.0"
FORMAT = "PQRBBC-ISSUANCE-PARENT-I1-I5-CANDIDATESET-PREFLIGHT-1"
RELATION_ID = (
    "pq-rbbc/issuance/parent-i1-i5-candidateset/"
    "multitree-4plus4-insecure-test-only/v1"
)
MODE = "INSECURE-TEST-ONLY"
HANDOFF_FORMAT = FORMAT + "-HANDOFF"
PARAMETERS_MAGIC = b"PQRBBC-ISSUE-PARENT-I1-I5-PP-V1"
WITNESS_MAGIC = b"PQRBBC-ISSUE-PARENT-I1-I5-WITNESS-V1"
CODEC_VERSION = 1
HANDOFF_NAME = "parent-i1-i5-candidateset.private.json"
PARAMETERS_NAME = "parent-i1-i5-parameters.private.bin"
STATEMENT_NAME = "parent-i1-i5-statement.private.bin"
WITNESS_NAME = "parent-i1-i5-witness.private.bin"
HANDOFF_LIMIT = 96 * 1024
PARAMETERS_LIMIT = 4 * 1024
STATEMENT_LIMIT = 4 * 1024
WITNESS_LIMIT = 16 * 1024
PROFILE_FINGERPRINT = cap.profile_fingerprint(adapter.PARAMETERS)
DOMAIN_ABI = b"PQ-RBBC/ISSUANCE/PARENT-I1-I5-CANDIDATESET/ABI/V1"
DOMAIN_INVENTORY = b"PQ-RBBC/ISSUANCE/PARENT-I1-I5-CANDIDATESET/INVENTORY/V1"

MANIFEST_PATH = (
    "manifests/pq_rbbc_issuance_parent_i1_i5_candidateset_preflight_manifest_v1.json"
)
EVIDENCE_PATH = (
    "artifacts/metadata/issuance_parent_i1_i5_candidateset_preflight_v1/"
    "pq_rbbc_issuance_parent_i1_i5_candidateset_preflight_portable_evidence_v1.json"
)

# Exact predecessor and semantic-definition pins.  They are updated only by a
# new successor checkpoint, never by accepting similarly named inputs.
PREDECESSOR_PINS = {
    "src/pq_rbbc_issuance_global_tail_completion_sealer_v1.py": (
        46_898,
        "a6fb3e19bd6a1c9d8e492bf99d0edf25ce50e119bdbb5aa5d7e7abea942349e2",
    ),
    "tests/test_pq_rbbc_issuance_global_tail_completion_sealer_v1.py": (
        16_712,
        "732d4d1afd06b1cc2fa299dfd4d7ba406f2a5e8b675de30911fdf6ebf98a6c97",
    ),
    completion.MANIFEST_PATH: (
        8_204,
        "c3363fd605e0e8112f42a9207a505829fd0d7eb62c7f9d4e575a7c74eb13fb8e",
    ),
    completion.EVIDENCE_PATH: (
        4_844,
        "fc30d006e889be07ade016fb6b18819721fe74abb39f2ed2d10575bcc41dbffe",
    ),
    "docs/artifacts/PQ_RBBC_ISSUANCE_GLOBAL_TAIL_COMPLETION_SEALER_V1_zh-TW.md": (
        7_454,
        "96526a8419e744e55bbd2739a7247495155a90e80e85d43765831c076128ae71",
    ),
    "docs/proof/source/pq_rbbc_sgtd_core_proof_v1.tex": (
        148_798,
        "cee211e7c6419480c0571b752faebe3574d3309f4e876a75cf325f3027d9f884",
    ),
    "src/pq_rbbc_issuance_zk_backend_preflight.py": (
        47_151,
        "00c0119596983b94bdfd1dcaffe58f0c2f847ca0092c5c53d8f073285092e836",
    ),
    "src/pq_rbbc_issuance_relation_v1.py": (
        31_165,
        "4c0db79e896824c77ef869fdfa2c8fc3e26c9942e12c0a49526f2b54bfbbf57e",
    ),
    "src/pq_rbbc_issuance_reduced_constraint_v1.py": (
        41_428,
        "8b6e71119a70f7a9bf78875fb8a93cf86e7ecfbb7e2184e0880977a62e668620",
    ),
    "src/pq_rbbc_issuance_bounded_multitree_adapter_v1.py": (
        29_064,
        "a9aae19c0a03ecf620a6196d3be9b3f848c82dba88262ae0872cfcd7be0ed4d7",
    ),
    "src/pq_rbbc_issuance_bounded_multitree_native_v1.py": (
        43_914,
        "91cc8729d4d1acb229404a39a25cd739c8aba9fa5ee007c00bbdc6864aba9a7e",
    ),
    "src/pq_rbbc_cap_commit.py": (
        32_526,
        "be3a2a767561f009acc2a274a85410ae6e02e23abd24145aa1d61883dd2dceee",
    ),
    "src/pq_rbbc_anemoi_sponge.py": (
        25_336,
        "6d4e604cd937357cd76f9c127fa9fe94392bbc89b1a0b7972196545ab36424ec",
    ),
    "src/pq_rbbc_reference.py": (
        70_542,
        "37da0b9834fd2ecd83b482208ea259e0a17b126bb16f50f4ff538d0699046fab",
    ),
}

ABI_DOCUMENT = {
    "format": "PQRBBC-ISSUANCE-PARENT-I1-I5-ABI-1",
    "relation_id": RELATION_ID,
    "public_statement": ["pp", "ctx", "sid", "rid", "beta"],
    "private_witness": ["M", "r", "rho", "k_hold", "e"],
    "statement_codec": backend.STATEMENT_MAGIC.decode("ascii"),
    "witness_codec": WITNESS_MAGIC.decode("ascii"),
    "cap_profile_fingerprint": PROFILE_FINGERPRINT,
    "ticket_payload_bytes": backend.TICKET_PAYLOAD_BYTES,
    "blind_mask_bytes": backend.BLIND_REQUEST_BYTES,
    "cap_randomness_bytes": len(
        cap.deterministic_randomness(adapter.PARAMETERS).serialize(adapter.PARAMETERS)
    ),
    "holder_key_bytes": backend.HOLDER_KEY_BYTES,
    "error_vector_bytes": backend.ERROR_VECTOR_BYTES,
    "integer_encoding": "unsigned-little-endian",
    "bit_order": "LSB-first-within-byte",
}
ABI_PROFILE_DIGEST = hashlib.sha256(
    DOMAIN_ABI + io.canonical_json(ABI_DOCUMENT)
).digest()

PUBLIC_INPUT_BITS = 1_600
SECRET_WITNESS_BITS = 11_622
PLANNED_NATIVE_JOIN_BITS = 6_654
PARENT_LOCAL_INPUT_END = 18_143


def _interval(start: int, width: int) -> dict[str, int]:
    return {"start": start, "end_exclusive": start + width, "bits": width}


# Exact local input/import reservations.  The computed-wire interval is not
# guessed; it remains open until a fresh lowerer observes it in the next gate.
WIRE_PLAN = (
    ("statement.pp", "public", _interval(1, 256)),
    ("statement.ctx", "public", _interval(257, 256)),
    ("statement.sid", "public", _interval(513, 256)),
    ("statement.rid", "public", _interval(769, 256)),
    ("statement.beta", "public", _interval(1_025, 576)),
    ("witness.M", "secret", _interval(1_601, 2_944)),
    ("witness.r", "secret", _interval(4_545, 576)),
    ("witness.rho", "secret", _interval(5_121, 1_158)),
    ("witness.k_hold", "secret", _interval(6_279, 256)),
    ("witness.e", "secret", _interval(6_535, 6_688)),
    ("import.c_r", "private-import", _interval(13_223, 4_088)),
    ("import.request_hash", "private-import", _interval(17_311, 576)),
    ("import.ticket_message", "private-import", _interval(17_887, 256)),
)

JOIN_PLAN = (
    ("ticket-message", 256, "I2 output == captured CAP message"),
    ("cap-randomness", 1_158, "witness rho == CAP child salt/root inputs"),
    ("derived-mask", 576, "witness r == CAP child derived mask"),
    ("cap-commitment", 4_088, "import c_r == CAP child commitment bytes"),
    ("request-hash", 576, "import hash == H_RBBC(message,c_r) output"),
)

SNAPSHOT_ROLE_ORDER = (
    "completion-handoff",
    *completion.SNAPSHOT_ROLE_ORDER,
    "parent-parameters",
    "parent-statement",
    "parent-witness",
)

# Filled after source/test and deterministic fixture identities are stable.
FROZEN = {
    "handoff_identity": {
        "filename": HANDOFF_NAME,
        "bytes": 12_231,
        "sha256": "5e8cc00a9d314c428ff678d563065f2401c3bc9afb853d10a0353ff5849bae37",
    },
    "parameters_identity": {
        "filename": PARAMETERS_NAME,
        "bytes": 330,
        "sha256": "5d5e0f6669538836bd380f78d55e79f10f53967535458b7d3e938dc949bb1d49",
    },
    "statement_identity": {
        "filename": STATEMENT_NAME,
        "bytes": 321,
        "sha256": "58abad8ca1c79805139bcf02884fb873753bde4aa515188a58d7568dae9af1da",
    },
    "witness_identity": {
        "filename": WITNESS_NAME,
        "bytes": 1_676,
        "sha256": "c4a7d22aa6089d1e855262f60371456ff3065bbf58b680d7179e15cc3de75f3a",
    },
    "snapshot_inventory_sha256": (
        "589bdebf17c124ec0576ae9f3e733c1a0744a08b0e1757045a9a810778d84d79"
    ),
    "snapshot_roles": len(SNAPSHOT_ROLE_ORDER),
    "host_reference_conjuncts_checked": 5,
    "parent_constraints_replayed": 0,
    "native_join_rows_replayed": 0,
}


class ParentCandidateError(ValueError):
    """A parent candidate, encoding, identity, or binding was rejected."""


class ParentProductionUnavailable(RuntimeError):
    """This bounded preflight exposes no production or relation executor."""


@dataclass(frozen=True)
class ParentParametersV1:
    relation_id: str
    abi_profile_digest: bytes
    cap_profile_digest: bytes
    trace_profile_digest: bytes
    matrix_seed: bytes
    mode: str

    def encode(self) -> bytes:
        if (
            self.relation_id != RELATION_ID
            or self.abi_profile_digest != ABI_PROFILE_DIGEST
            or self.cap_profile_digest != bytes.fromhex(PROFILE_FINGERPRINT)
            or self.trace_profile_digest != formal_relation.TRACE_PROFILE_DIGEST
            or self.matrix_seed != formal_relation.TEST_MATRIX_SEED
            or self.mode != MODE
        ):
            raise ParentCandidateError("wrong bounded parent parameter contract")
        return _encode_sections(
            PARAMETERS_MAGIC,
            (
                (1, _ascii(self.relation_id, "relation id")),
                (2, self.abi_profile_digest),
                (3, self.cap_profile_digest),
                (4, self.trace_profile_digest),
                (5, self.matrix_seed),
                (6, _ascii(self.mode, "mode")),
            ),
        )

    @classmethod
    def decode(cls, raw: bytes) -> "ParentParametersV1":
        values = _decode_sections(
            raw,
            PARAMETERS_MAGIC,
            (
                (1, "relation_id", 1, 128),
                (2, "abi_profile_digest", 32, 32),
                (3, "cap_profile_digest", 32, 32),
                (4, "trace_profile_digest", 32, 32),
                (5, "matrix_seed", 1, 96),
                (6, "mode", 1, 96),
            ),
        )
        try:
            result = cls(
                values["relation_id"].decode("ascii"),
                values["abi_profile_digest"],
                values["cap_profile_digest"],
                values["trace_profile_digest"],
                values["matrix_seed"],
                values["mode"].decode("ascii"),
            )
        except UnicodeDecodeError as error:
            raise ParentCandidateError("parameter identifier must be ASCII") from error
        if result.encode() != raw:
            raise ParentCandidateError("noncanonical parent parameters")
        return result


@dataclass(frozen=True)
class ParentWitnessV1:
    abi_profile_digest: bytes
    ticket_payload: bytes
    blind_mask: bytes
    cap_randomness: bytes
    holder_key: bytes
    error_vector: bytes

    def encode(self) -> bytes:
        expected = (
            32,
            backend.TICKET_PAYLOAD_BYTES,
            backend.BLIND_REQUEST_BYTES,
            ABI_DOCUMENT["cap_randomness_bytes"],
            backend.HOLDER_KEY_BYTES,
            backend.ERROR_VECTOR_BYTES,
        )
        values = (
            self.abi_profile_digest,
            self.ticket_payload,
            self.blind_mask,
            self.cap_randomness,
            self.holder_key,
            self.error_vector,
        )
        if tuple(len(value) for value in values) != expected:
            raise ParentCandidateError("wrong parent witness field length")
        if self.abi_profile_digest != ABI_PROFILE_DIGEST:
            raise ParentCandidateError("wrong parent witness ABI profile")
        _decode_cap_randomness(self.cap_randomness)
        return _encode_sections(
            WITNESS_MAGIC,
            tuple((index, value) for index, value in enumerate(values, start=1)),
        )

    @classmethod
    def decode(cls, raw: bytes) -> "ParentWitnessV1":
        rho_bytes = int(ABI_DOCUMENT["cap_randomness_bytes"])
        values = _decode_sections(
            raw,
            WITNESS_MAGIC,
            (
                (1, "abi_profile_digest", 32, 32),
                (2, "ticket_payload", 368, 368),
                (3, "blind_mask", 72, 72),
                (4, "cap_randomness", rho_bytes, rho_bytes),
                (5, "holder_key", 32, 32),
                (6, "error_vector", 836, 836),
            ),
        )
        result = cls(**values)
        if result.encode() != raw:
            raise ParentCandidateError("noncanonical parent witness")
        return result


@dataclass(frozen=True)
class ParentI1I5CandidateSetInsecureTestOnly:
    handoff: io.Snapshot
    parameters: io.Snapshot
    statement: io.Snapshot
    witness: io.Snapshot
    completion_candidate: completion.GlobalTailParentCandidateSetInsecureTestOnly

    def __post_init__(self) -> None:
        if (
            type(self.handoff) is not io.Snapshot
            or type(self.parameters) is not io.Snapshot
            or type(self.statement) is not io.Snapshot
            or type(self.witness) is not io.Snapshot
            or type(self.completion_candidate)
            is not completion.GlobalTailParentCandidateSetInsecureTestOnly
        ):
            raise ParentCandidateError("exact immutable parent CandidateSet required")


@dataclass(frozen=True)
class DecodedParentCandidateSetInsecureTestOnly:
    handoff: Mapping[str, object]
    parameters: ParentParametersV1
    statement: backend.IssueStatementV1
    witness: ParentWitnessV1
    snapshot_identities: tuple[Mapping[str, object], ...]
    ticket_message: bytes
    c_r: bytes
    request_hash: bytes


def canonical_json(document: object) -> bytes:
    return io.canonical_json(document)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _ascii(value: str, label: str) -> bytes:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ParentCandidateError(label + " must be ASCII") from error
    allowed = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/"
    if not encoded or len(encoded) > 128 or any(byte not in allowed for byte in encoded):
        raise ParentCandidateError(label + " is not canonical")
    return encoded


def _encode_sections(magic: bytes, sections: Sequence[tuple[int, bytes]]) -> bytes:
    result = bytearray(magic)
    result.extend(CODEC_VERSION.to_bytes(2, "little"))
    result.extend(len(sections).to_bytes(2, "little"))
    for section_id, payload in sections:
        result.extend(section_id.to_bytes(2, "little"))
        result.extend(len(payload).to_bytes(8, "little"))
        result.extend(payload)
    return bytes(result)


def _read_uint(raw: bytes, offset: int, width: int, label: str) -> tuple[int, int]:
    end = offset + width
    if end > len(raw):
        raise ParentCandidateError("truncated " + label)
    return int.from_bytes(raw[offset:end], "little"), end


def _decode_sections(
    raw: bytes,
    magic: bytes,
    schema: Sequence[tuple[int, str, int, int]],
) -> dict[str, bytes]:
    if type(raw) is not bytes or not raw.startswith(magic):
        raise ParentCandidateError("wrong parent codec magic")
    offset = len(magic)
    version, offset = _read_uint(raw, offset, 2, "version")
    if version != CODEC_VERSION:
        raise ParentCandidateError("wrong parent codec version")
    count, offset = _read_uint(raw, offset, 2, "section count")
    if count != len(schema):
        raise ParentCandidateError("wrong parent section count")
    values: dict[str, bytes] = {}
    for expected_id, name, minimum, maximum in schema:
        section_id, offset = _read_uint(raw, offset, 2, name + " id")
        if section_id != expected_id:
            raise ParentCandidateError("noncanonical " + name + " section")
        length, offset = _read_uint(raw, offset, 8, name + " length")
        if not minimum <= length <= maximum:
            raise ParentCandidateError("wrong " + name + " length")
        end = offset + length
        if end > len(raw):
            raise ParentCandidateError("truncated " + name)
        values[name] = raw[offset:end]
        offset = end
    if offset != len(raw):
        raise ParentCandidateError("trailing parent codec bytes")
    return values


def _decode_cap_randomness(raw: bytes) -> cap.CAPRandomness:
    expected_bytes = int(ABI_DOCUMENT["cap_randomness_bytes"])
    if type(raw) is not bytes or len(raw) != expected_bytes:
        raise ParentCandidateError("wrong bounded CAP randomness length")
    if not raw.startswith(cap.RANDOMNESS_MAGIC):
        raise ParentCandidateError("wrong bounded CAP randomness magic")
    offset = len(cap.RANDOMNESS_MAGIC)
    profile = raw[offset : offset + 64]
    if profile != PROFILE_FINGERPRINT.encode("ascii"):
        raise ParentCandidateError("wrong bounded CAP randomness profile")
    offset += 64
    values = []
    for _ in range(2):
        value = int.from_bytes(raw[offset : offset + field193.FIELD_ELEMENT_BYTES], "little")
        if value > field193.FIELD_MASK:
            raise ParentCandidateError("noncanonical CAP salt")
        values.append(value)
        offset += field193.FIELD_ELEMENT_BYTES
    tree_count, offset = _read_uint(raw, offset, 2, "CAP tree count")
    if tree_count != adapter.PARAMETERS.tree_count:
        raise ParentCandidateError("wrong bounded CAP tree count")
    roots = []
    for _ in range(tree_count):
        pair = []
        for _ in range(2):
            value = int.from_bytes(
                raw[offset : offset + field193.FIELD_ELEMENT_BYTES], "little"
            )
            if value > field193.FIELD_MASK:
                raise ParentCandidateError("noncanonical CAP root")
            pair.append(value)
            offset += field193.FIELD_ELEMENT_BYTES
        roots.append(tuple(pair))
    result = cap.CAPRandomness(tuple(values), tuple(roots))
    if offset != len(raw) or result.serialize(adapter.PARAMETERS) != raw:
        raise ParentCandidateError("noncanonical bounded CAP randomness")
    return result


def _snapshot(filename: str, raw: bytes, limit: int) -> io.Snapshot:
    if type(raw) is not bytes or not 0 < len(raw) <= limit:
        raise ParentCandidateError("parent snapshot byte limit")
    return io.Snapshot(Path(filename), raw)


def _identity(snapshot: io.Snapshot, filename: str, limit: int) -> None:
    if (
        type(snapshot) is not io.Snapshot
        or snapshot.location.name != filename
        or not 0 < len(snapshot.raw) <= limit
        or snapshot.identity
        != {"filename": filename, "bytes": len(snapshot.raw), "sha256": sha256(snapshot.raw)}
    ):
        raise ParentCandidateError("parent snapshot identity mismatch: " + filename)


def _identity_document(value: object, label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != {"filename", "bytes", "sha256"}:
        raise ParentCandidateError(label + " identity schema")
    if (
        type(value["filename"]) is not str
        or not value["filename"]
        or "/" in value["filename"]
        or type(value["bytes"]) is not int
        or value["bytes"] <= 0
        or type(value["sha256"]) is not str
        or len(value["sha256"]) != 64
        or any(character not in "0123456789abcdef" for character in value["sha256"])
    ):
        raise ParentCandidateError(label + " identity value")
    return value


def _freeze(value: object) -> object:
    if type(value) is dict:
        return MappingProxyType({key: _freeze(child) for key, child in value.items()})
    if type(value) is list:
        return tuple(_freeze(child) for child in value)
    return value


def validate_prerequisites() -> None:
    for path, (expected_bytes, expected_sha256) in PREDECESSOR_PINS.items():
        snapshot = io.read_snapshot(ROOT / path)
        if expected_bytes <= 0 or not expected_sha256:
            raise ParentCandidateError("unfrozen prerequisite pin: " + path)
        if (len(snapshot.raw), sha256(snapshot.raw)) != (
            expected_bytes,
            expected_sha256,
        ):
            raise ParentCandidateError("prerequisite identity mismatch: " + path)


def _parameters_snapshot() -> io.Snapshot:
    parameters = ParentParametersV1(
        RELATION_ID,
        ABI_PROFILE_DIGEST,
        bytes.fromhex(PROFILE_FINGERPRINT),
        formal_relation.TRACE_PROFILE_DIGEST,
        formal_relation.TEST_MATRIX_SEED,
        MODE,
    )
    return _snapshot(PARAMETERS_NAME, parameters.encode(), PARAMETERS_LIMIT)


def _source_roles(
    candidate: ParentI1I5CandidateSetInsecureTestOnly,
) -> tuple[tuple[str, io.Snapshot], ...]:
    predecessor = candidate.completion_candidate
    roles = [("completion-handoff", predecessor.handoff)]
    roles.extend(
        completion._snapshot_roles(
            predecessor.source_candidate,
            predecessor.global_b_result,
            predecessor.parent_input,
        )
    )
    roles.extend(
        (
            ("parent-parameters", candidate.parameters),
            ("parent-statement", candidate.statement),
            ("parent-witness", candidate.witness),
        )
    )
    frozen = tuple(roles)
    if tuple(role for role, _ in frozen) != SNAPSHOT_ROLE_ORDER:
        raise ParentCandidateError("canonical 40-role parent order required")
    return frozen


def _inventory_document(
    roles: Sequence[tuple[str, io.Snapshot]],
) -> list[dict[str, object]]:
    return [
        {"ordinal": ordinal, "role": role, "snapshot_identity": snapshot.identity}
        for ordinal, (role, snapshot) in enumerate(roles)
    ]


def _inventory_digest(inventory: Sequence[Mapping[str, object]]) -> str:
    raw = canonical_json(list(inventory))
    return sha256(DOMAIN_INVENTORY + len(raw).to_bytes(8, "little") + raw)


def _evaluate_host_bindings(
    candidate: ParentI1I5CandidateSetInsecureTestOnly,
    decoded_completion: completion.DecodedGlobalTailParentCandidateSetInsecureTestOnly,
) -> tuple[
    ParentParametersV1,
    backend.IssueStatementV1,
    ParentWitnessV1,
    bytes,
]:
    _identity(candidate.parameters, PARAMETERS_NAME, PARAMETERS_LIMIT)
    _identity(candidate.statement, STATEMENT_NAME, STATEMENT_LIMIT)
    _identity(candidate.witness, WITNESS_NAME, WITNESS_LIMIT)
    parameters = ParentParametersV1.decode(candidate.parameters.raw)
    try:
        statement = backend.IssueStatementV1.decode(candidate.statement.raw)
    except backend.CanonicalEncodingError as error:
        raise ParentCandidateError("noncanonical parent statement") from error
    witness = ParentWitnessV1.decode(candidate.witness.raw)
    if (
        statement.abi_profile_digest != ABI_PROFILE_DIGEST
        or witness.abi_profile_digest != ABI_PROFILE_DIGEST
        or statement.public_parameters_digest != hashlib.sha256(candidate.parameters.raw).digest()
    ):
        raise ParentCandidateError("parent ABI or parameters binding mismatch")
    try:
        payload = formal_relation.decode_ticket_payload(witness.ticket_payload)
    except formal_relation.IssuanceRelationError as error:
        raise ParentCandidateError("noncanonical ticket payload") from error
    message = hashlib.shake_256(
        reference.LABEL_TICKET + witness.ticket_payload
    ).digest(32)
    shared = completion.candidateset._shared_inputs_document(
        candidate.completion_candidate.source_candidate.shared_inputs
    )
    captured_message = sum(
        bit << index for index, bit in enumerate(shared["message"])
    ).to_bytes(32, "little")
    randomness = _decode_cap_randomness(witness.cap_randomness)
    execution = cap.execute_cap_commit(adapter.PARAMETERS, randomness)
    expected_mask = execution.commitment.derived_mask.to_bytes(72, "little")
    expected_hash = h_rbbc.hash_request_binding(message, execution.commitment.encoded)
    expected_beta = reference.xor_bytes(expected_mask, expected_hash)
    holder_hash = hashlib.shake_256(
        reference.LABEL_HOLD + witness.holder_key
    ).digest(32)
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
    except ValueError as cause:
        raise ParentCandidateError("I5 trace evaluation rejected") from cause
    checks = {
        "I1": payload.ctx == statement.ctx,
        "I2": message == captured_message,
        "I3": (
            witness.blind_mask == expected_mask
            and execution.commitment.encoded == decoded_completion.c_r
            and expected_hash == decoded_completion.request_hash
            and statement.beta == expected_beta
        ),
        "I4": payload.holder_hash == holder_hash,
        "I5": error.bit_count() == reference.T and expected_payload == payload,
    }
    if statement.sid == bytes(32):
        raise ParentCandidateError("zero issuer sid is not a fresh candidate")
    failures = [name for name, accepted in checks.items() if not accepted]
    if failures:
        raise ParentCandidateError("host reference conjunct mismatch: " + ",".join(failures))
    return parameters, statement, witness, message


def _handoff_document(
    candidate: ParentI1I5CandidateSetInsecureTestOnly,
    decoded_completion: completion.DecodedGlobalTailParentCandidateSetInsecureTestOnly,
    ticket_message: bytes,
) -> dict[str, object]:
    roles = _source_roles(candidate)
    inventory = _inventory_document(roles)
    return {
        "format": HANDOFF_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "mode": MODE,
        "relation_id": RELATION_ID,
        "profile_fingerprint": PROFILE_FINGERPRINT,
        "abi_profile_digest": ABI_PROFILE_DIGEST.hex(),
        "stage_id": "parent-i1-i5-candidateset-preflight",
        "next_stage": "bounded-parent-i1-i5-relation-consumer",
        "source_completion_handoff_identity": candidate.completion_candidate.handoff.identity,
        "parameters_identity": candidate.parameters.identity,
        "statement_identity": candidate.statement.identity,
        "witness_identity": candidate.witness.identity,
        "snapshot_inventory": inventory,
        "snapshot_inventory_sha256": _inventory_digest(inventory),
        "source_bindings": {
            "ticket_message_sha256": sha256(ticket_message),
            "c_r_bytes": len(decoded_completion.c_r),
            "c_r_sha256": sha256(decoded_completion.c_r),
            "request_hash_bytes": len(decoded_completion.request_hash),
            "request_hash_sha256": sha256(decoded_completion.request_hash),
        },
        "formal_contract": {
            "public_statement": ["pp", "ctx", "sid", "rid", "beta"],
            "private_witness": ["M", "r", "rho", "k_hold", "e"],
            "conjuncts": ["I1", "I2", "I3", "I4", "I5"],
            "host_reference_conjuncts_checked": 5,
            "constraint_rows_replayed": 0,
            "sid_freshness_proved": False,
            "sid_reserved": False,
        },
        "wire_plan": {
            "namespace": "fresh-parent-local-planning-only",
            "wire_zero": "constant-one-not-allocated",
            "input_and_import_intervals": [
                {"field": name, "visibility": visibility, "interval": interval}
                for name, visibility, interval in WIRE_PLAN
            ],
            "input_and_import_end_exclusive": PARENT_LOCAL_INPUT_END,
            "computed_interval": None,
            "absolute_composed_interval": None,
            "production_intervals_qualified": False,
        },
        "join_plan": {
            "bindings": [
                {"port": port, "bits": bits, "meaning": meaning}
                for port, bits, meaning in JOIN_PLAN
            ],
            "planned_native_join_bits": PLANNED_NATIVE_JOIN_BITS,
            "native_join_rows_replayed": 0,
        },
        "all_identity_parse_binding_use_same_raw": True,
        "future_consumer_must_use_same_snapshots": True,
        "candidate_pathname_reopen_permitted": False,
        "metadata_proves_no_writer": False,
        "full_execution_receipt_chain_verified": False,
        "private_payload": True,
        "production": False,
    }


def _validate_inventory(
    value: object,
    roles: Sequence[tuple[str, io.Snapshot]],
) -> tuple[Mapping[str, object], ...]:
    if type(value) is not list or len(value) != len(SNAPSHOT_ROLE_ORDER):
        raise ParentCandidateError("parent inventory length")
    result = []
    for ordinal, (item, (role, snapshot)) in enumerate(zip(value, roles)):
        if type(item) is not dict or set(item) != {
            "ordinal",
            "role",
            "snapshot_identity",
        }:
            raise ParentCandidateError("parent inventory descriptor schema")
        _identity_document(item["snapshot_identity"], "parent inventory")
        if (
            type(item["ordinal"]) is not int
            or item["ordinal"] != ordinal
            or item["role"] != SNAPSHOT_ROLE_ORDER[ordinal]
            or item["role"] != role
            or item["snapshot_identity"] != snapshot.identity
        ):
            raise ParentCandidateError("parent inventory role, ordinal, or identity")
        result.append(MappingProxyType(dict(item)))
    return tuple(result)


def build_candidate_set_insecure_test_only(
    *,
    completion_candidate: completion.GlobalTailParentCandidateSetInsecureTestOnly,
    parameters_raw: bytes,
    statement_raw: bytes,
    witness_raw: bytes,
) -> ParentI1I5CandidateSetInsecureTestOnly:
    """Build only immutable in-memory snapshots; no filesystem output."""
    validate_prerequisites()
    provisional = ParentI1I5CandidateSetInsecureTestOnly(
        io.Snapshot(Path(HANDOFF_NAME), b"{}\n"),
        _snapshot(PARAMETERS_NAME, bytes(parameters_raw), PARAMETERS_LIMIT),
        _snapshot(STATEMENT_NAME, bytes(statement_raw), STATEMENT_LIMIT),
        _snapshot(WITNESS_NAME, bytes(witness_raw), WITNESS_LIMIT),
        completion_candidate,
    )
    decoded_completion = completion.validate_parent_candidate_set_insecure_test_only(
        completion_candidate,
        expected_handoff_sha256=completion_candidate.handoff.identity["sha256"],
    )
    _, _, _, message = _evaluate_host_bindings(provisional, decoded_completion)
    handoff = _snapshot(
        HANDOFF_NAME,
        canonical_json(_handoff_document(provisional, decoded_completion, message)),
        HANDOFF_LIMIT,
    )
    candidate = ParentI1I5CandidateSetInsecureTestOnly(
        handoff,
        provisional.parameters,
        provisional.statement,
        provisional.witness,
        completion_candidate,
    )
    validate_candidate_set_insecure_test_only(
        candidate, expected_handoff_sha256=handoff.identity["sha256"]
    )
    return candidate


def validate_candidate_set_insecure_test_only(
    candidate: ParentI1I5CandidateSetInsecureTestOnly,
    *,
    expected_handoff_sha256: str,
) -> DecodedParentCandidateSetInsecureTestOnly:
    """Validate captured raws only; never reopen a candidate pathname."""
    if type(candidate) is not ParentI1I5CandidateSetInsecureTestOnly:
        raise ParentCandidateError("exact parent CandidateSet type required")
    if (
        type(expected_handoff_sha256) is not str
        or len(expected_handoff_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_handoff_sha256)
    ):
        raise ParentCandidateError("external parent handoff digest encoding")
    _identity(candidate.handoff, HANDOFF_NAME, HANDOFF_LIMIT)
    if candidate.handoff.identity["sha256"] != expected_handoff_sha256:
        raise ParentCandidateError("parent handoff digest rejected before dependencies")
    try:
        handoff = candidate.handoff.document()
    except io.ValidationError as error:
        raise ParentCandidateError("parent handoff is not strict canonical JSON") from error
    validate_prerequisites()
    expected_completion = handoff.get("source_completion_handoff_identity")
    _identity_document(expected_completion, "source completion handoff")
    if expected_completion != candidate.completion_candidate.handoff.identity:
        raise ParentCandidateError("source completion handoff identity mismatch")
    # Reject inventory confusion before any bounded CAP or trace computation.
    roles = _source_roles(candidate)
    identities = _validate_inventory(handoff.get("snapshot_inventory"), roles)
    decoded_completion = completion.validate_parent_candidate_set_insecure_test_only(
        candidate.completion_candidate,
        expected_handoff_sha256=str(expected_completion["sha256"]),
    )
    parameters, statement, witness, message = _evaluate_host_bindings(
        candidate, decoded_completion
    )
    expected = _handoff_document(candidate, decoded_completion, message)
    if candidate.handoff.raw != canonical_json(expected):
        raise ParentCandidateError("parent handoff schema, order, binding, or claim mismatch")
    return DecodedParentCandidateSetInsecureTestOnly(
        _freeze(handoff),
        parameters,
        statement,
        witness,
        identities,
        message,
        decoded_completion.c_r,
        decoded_completion.request_hash,
    )


def candidate_evidence(
    candidate: ParentI1I5CandidateSetInsecureTestOnly,
) -> dict[str, object]:
    decoded = validate_candidate_set_insecure_test_only(
        candidate, expected_handoff_sha256=candidate.handoff.identity["sha256"]
    )
    return {
        "format": FORMAT,
        "relation_id": RELATION_ID,
        "mode": MODE,
        "handoff_identity": candidate.handoff.identity,
        "parameters_identity": candidate.parameters.identity,
        "statement_identity": candidate.statement.identity,
        "witness_identity": candidate.witness.identity,
        "source_completion_handoff_identity": candidate.completion_candidate.handoff.identity,
        "snapshot_inventory_sha256": decoded.handoff["snapshot_inventory_sha256"],
        "snapshot_roles": len(decoded.snapshot_identities),
        "host_reference_conjuncts_checked": 5,
        "public_input_bits": PUBLIC_INPUT_BITS,
        "secret_witness_bits": SECRET_WITNESS_BITS,
        "planned_native_join_bits": PLANNED_NATIVE_JOIN_BITS,
        "parent_constraints_replayed": 0,
        "native_join_rows_replayed": 0,
        "cryptographic_proofs_generated": 0,
        "same_raw_for_identity_parse_binding_and_future_consumption": True,
        "candidate_pathname_reopen_permitted": False,
        "sid_freshness_proved": False,
        "sid_reserved": False,
        "full_execution_receipt_chain_verified": False,
        "private_snapshot_raws_embedded": False,
        "production": False,
    }


def execute_parent_relation(*_args: object, **_kwargs: object) -> None:
    raise ParentProductionUnavailable(
        "read-only parent CandidateSet gate refuses before I/O or relation replay"
    )


def execute_production(*_args: object, **_kwargs: object) -> None:
    raise ParentProductionUnavailable(
        "bounded test-only parent profile refuses production before I/O"
    )


def preflight() -> dict[str, object]:
    validate_prerequisites()
    return {
        "format": FORMAT,
        "relation_id": RELATION_ID,
        "read_only_preflight_passed": True,
        "finding_free_completion_sealer_pinned": True,
        "fresh_parent_candidate_contract_defined": True,
        "canonical_source_snapshot_roles": len(SNAPSHOT_ROLE_ORDER),
        "public_input_bits": PUBLIC_INPUT_BITS,
        "secret_witness_bits": SECRET_WITNESS_BITS,
        "planned_native_join_bits": PLANNED_NATIVE_JOIN_BITS,
        "parent_local_input_end_exclusive": PARENT_LOCAL_INPUT_END,
        "parent_computed_interval": None,
        "host_reference_conjuncts_checked_by_frozen_fixture": 5,
        "parent_constraints_replayed": 0,
        "native_join_rows_replayed": 0,
        "safe_to_author_bounded_parent_consumer_after_finding_free_review": True,
        "safe_to_execute_parent_relation_now": False,
        "safe_to_start_large_replay": False,
        "safe_to_start_large_proving_run": False,
        "production_execution_command": None,
        "parent_replay_command": None,
        "large_replay_command": None,
        "large_proving_command": None,
        "formal_pi_issue_generated": False,
        "production_legacy18_provider_implemented": False,
        "qualified_pq_se_backend_integrated": False,
        "Proof-closed": False,
        "Production-closed": False,
        "blockers": [
            "this exact commit requires finding-free independent technical/security re-review",
            "fresh parent circuit lowering, computed-wire interval, native joins, and replay are not implemented",
            "issuer sid freshness and linearizable reservation are external stateful requirements",
            "bounded 4+4-leaf profile is insecure-test-only and is not the production legacy18 provider",
            "receipt evidence remains a branch graph rather than one complete linear execution chain",
            "qualified PQ simulation-extractable backend and formal pi_issue are absent",
            "production artifacts, independent cryptographic review, reservation, and large-run authorization are absent",
            "trusted handoff, writer quiescence, permissions, writable FDs, and mount controls are external",
        ],
    }


def _fixture_candidate_insecure_test_only() -> tuple[
    object,
    TemporaryDirectory[str],
    ParentI1I5CandidateSetInsecureTestOnly,
]:
    session, temporary, predecessor = completion._fixture_candidate_insecure_test_only()
    try:
        source = adapter.build_reference_insecure_test_only(0)
        original_statement = source.invocation.statement
        original_witness = source.invocation.witness
        decoded_completion = completion.validate_parent_candidate_set_insecure_test_only(
            predecessor,
            expected_handoff_sha256=predecessor.handoff.identity["sha256"],
        )
        parameters = _parameters_snapshot()
        randomness_raw = source.randomness.serialize(adapter.PARAMETERS)
        execution = cap.execute_cap_commit(adapter.PARAMETERS, source.randomness)
        if execution.commitment.encoded != decoded_completion.c_r:
            raise ParentCandidateError("fixture CAP commitment differs from completion")
        blind_mask = execution.commitment.derived_mask.to_bytes(72, "little")
        beta = reference.xor_bytes(blind_mask, decoded_completion.request_hash)
        statement = backend.IssueStatementV1(
            ABI_PROFILE_DIGEST,
            hashlib.sha256(parameters.raw).digest(),
            original_statement.ctx,
            original_statement.sid,
            original_statement.rid,
            beta,
        ).encode()
        witness = ParentWitnessV1(
            ABI_PROFILE_DIGEST,
            original_witness.ticket_payload,
            blind_mask,
            randomness_raw,
            original_witness.holder_key,
            original_witness.error_vector,
        ).encode()
        candidate = build_candidate_set_insecure_test_only(
            completion_candidate=predecessor,
            parameters_raw=parameters.raw,
            statement_raw=statement,
            witness_raw=witness,
        )
        return session, temporary, candidate
    except BaseException:
        session.close()
        temporary.cleanup()
        raise


@lru_cache(maxsize=1)
def bounded_self_check() -> dict[str, object]:
    session, temporary, candidate = _fixture_candidate_insecure_test_only()
    try:
        evidence = candidate_evidence(candidate)
        expected = {
            "handoff_identity": FROZEN["handoff_identity"],
            "parameters_identity": FROZEN["parameters_identity"],
            "statement_identity": FROZEN["statement_identity"],
            "witness_identity": FROZEN["witness_identity"],
            "snapshot_inventory_sha256": FROZEN["snapshot_inventory_sha256"],
            "snapshot_roles": FROZEN["snapshot_roles"],
            "host_reference_conjuncts_checked": FROZEN[
                "host_reference_conjuncts_checked"
            ],
            "parent_constraints_replayed": FROZEN["parent_constraints_replayed"],
            "native_join_rows_replayed": FROZEN["native_join_rows_replayed"],
        }
        if int(FROZEN["handoff_identity"]["bytes"]) > 0:
            for key, value in expected.items():
                if evidence[key] != value:
                    raise ParentCandidateError("frozen parent evidence drift: " + key)
        return evidence
    finally:
        session.close()
        temporary.cleanup()


def build_manifest() -> dict[str, object]:
    qualification = bounded_self_check()
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "mode": MODE,
        "implementation_identities": {
            path: io.read_snapshot(ROOT / path).identity
            for path in (
                "src/pq_rbbc_issuance_parent_i1_i5_candidateset_preflight_v1.py",
                "tests/test_pq_rbbc_issuance_parent_i1_i5_candidateset_preflight_v1.py",
            )
        },
        "predecessor_identities": {
            path: {"bytes": size, "sha256": digest}
            for path, (size, digest) in PREDECESSOR_PINS.items()
        },
        "abi": {**ABI_DOCUMENT, "abi_profile_digest": ABI_PROFILE_DIGEST.hex()},
        "frozen_bounded_qualification": qualification,
        "contract": {
            "snapshot_role_order": list(SNAPSHOT_ROLE_ORDER),
            "wire_plan": [
                {"field": name, "visibility": visibility, "interval": interval}
                for name, visibility, interval in WIRE_PLAN
            ],
            "join_plan": [
                {"port": port, "bits": bits, "meaning": meaning}
                for port, bits, meaning in JOIN_PLAN
            ],
            "parent_computed_interval": None,
            "absolute_composed_interval": None,
            "same_raw_for_identity_parse_binding_and_future_consumption": True,
            "candidate_pathname_reopen_permitted": False,
            "host_reference_check_is_not_constraint_replay": True,
            "metadata_proves_no_writer": False,
            "trusted_handoff_and_writer_quiescence_external": True,
        },
        "claim_status": {
            "Defined": True,
            "Instantiated": "two-tree-4plus4-insecure-test-only",
            "Implemented": "read-only-parent-candidateset-and-host-binding-validator",
            "Tested": "positive-negative-mutation-wrong-version-domain-order-binding-precompute",
            "Evidence-sealed": "metadata-only",
            "Proof-closed": False,
            "Production-closed": False,
            "fresh_parent_i1_i5_candidate_composed": True,
            "host_reference_conjuncts_checked": 5,
            "parent_relation_consumer_implemented": False,
            "parent_constraints_replayed": 0,
            "native_join_rows_replayed": 0,
            "sid_freshness_proved": False,
            "sid_reserved": False,
            "formal_pi_issue_generated": False,
            "production_legacy18_provider_implemented": False,
            "qualified_pq_se_backend_integrated": False,
        },
        "artifact_policy": {
            "private_snapshot_statement_or_witness_embedded": False,
            "assignment_br1cs_cache_checkpoint_resume_or_log_created": False,
            "large_replay_or_proving_output_created": False,
            "other_tree_observed_stream_bytes_used": False,
            "historical_v238_v239_rewritten": False,
            "system_architecture_ticket_lifecycle_or_pq_sat_auth_changed": False,
        },
        "resource_estimate": {
            "bounded_source_rows_already_checked": completion.SOURCE_ROWS_CHECKED,
            "host_reference_conjuncts": 5,
            "new_relation_rows": 0,
            "planned_native_join_bits_not_replayed": PLANNED_NATIVE_JOIN_BITS,
            "parent_rows_planning_upper_bound_not_observed": 3_100_000,
            "expected_wall_seconds_upper_bound": 180,
            "expected_peak_rss_mib_upper_bound": 1_024,
            "production_estimate": None,
        },
        "exact_commands": {
            "read_only": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_parent_i1_i5_candidateset_preflight_v1.py",
            "bounded": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_parent_i1_i5_candidateset_preflight_v1.py --bounded-self-check",
            "targeted": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_parent_i1_i5_candidateset_preflight_v1 -v",
            "parent_replay": None,
            "production": None,
            "large_replay": None,
            "large_proving": None,
        },
        "preflight": preflight(),
    }


def build_portable_evidence() -> dict[str, object]:
    manifest = build_manifest()
    raw = canonical_json(manifest)
    return {
        "format": FORMAT + "-PORTABLE-EVIDENCE",
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "mode": MODE,
        "manifest": {
            "filename": Path(MANIFEST_PATH).name,
            "bytes": len(raw),
            "sha256": sha256(raw),
        },
        "implementation_identities": manifest["implementation_identities"],
        "predecessor_identities": manifest["predecessor_identities"],
        "bounded_qualification": manifest["frozen_bounded_qualification"],
        "claim_status": manifest["claim_status"],
        "portable_metadata_only": True,
        "private_snapshot_statement_or_witness_embedded": False,
        "absolute_paths_embedded": False,
        "assignment_br1cs_cache_checkpoint_resume_or_log_embedded": False,
        "parent_constraints_replayed": 0,
        "native_join_rows_replayed": 0,
        "proofs_generated": 0,
        "formal_pi_issue_generated": False,
        "Proof-closed": False,
        "Production-closed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bounded-self-check", action="store_true")
    arguments = parser.parse_args()
    try:
        result = bounded_self_check() if arguments.bounded_self_check else preflight()
    except (ParentCandidateError, OSError, ValueError, TypeError, KeyError) as error:
        result = {
            "format": FORMAT,
            "read_only_preflight_passed": False,
            "safe_to_execute_parent_relation_now": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
            "error": str(error),
        }
        print(canonical_json(result).decode("ascii"), end="")
        return 2
    print(canonical_json(result).decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
