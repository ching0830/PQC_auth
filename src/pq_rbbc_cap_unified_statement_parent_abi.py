#!/usr/bin/env python3
"""V2.37 canonical unified-profile statement and parent-input ABI.

The production profile is used only to freeze a deterministic statement
serialization test vector.  A parent envelope is materialized and qualified
only for the v2.36 40-leaf bounded checkpoint.  This module never executes the
production tree, relation, or prover, and it does not replace the legacy
18-tree statement or evidence namespace.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
from typing import Mapping

import pq_rbbc_cap_unified_tree as unified
import pq_rbbc_cap_unified_tree_bounded_relation as v2_36
import pq_rbbc_cap_unified_tree_production_runner as v2_35
import pq_rbbc_reference as reference


IMPLEMENTATION_VERSION = "2.37"
FORMAT = "PQRBBC-CAP-UNIFIED-STATEMENT-PARENT-ABI-AUTHORING-1"
RELATION_ID = "pq-rbbc/cap/unified-tree/statement-parent-abi/candidate/v1"
ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = (
    ROOT / "manifests/pq_rbbc_cap_unified_statement_parent_abi_manifest_v2_37.json"
)

STATEMENT_MAGIC = b"PQRBBC-CAP-UGGM-STATEMENT-V1"
PARENT_MAGIC = b"PQRBBC-CAP-UGGM-PARENT-INPUT-V1"
CODEC_VERSION = 1
STATEMENT_FIELDS = (
    (1, "common_parameters_digest", 32),
    (2, "ctx", 32),
    (3, "sid", 32),
    (4, "rid", 32),
    (5, "y", 72),
)
PARENT_SECTIONS = (
    (1, "statement"),
    (2, "c_r"),
    (3, "ticket_message"),
    (4, "binding_digest"),
)

DOMAIN_COMMON_PARAMETERS = b"PQ-RBBC/v2.37/unified-statement/common-parameters"
DOMAIN_SESSION = b"PQ-RBBC/v2.37/unified-statement/session"
DOMAIN_PARENT_BINDING = b"PQ-RBBC/v2.37/unified-statement/parent-binding"

PRODUCTION_PROFILE_FINGERPRINT = unified.profile_fingerprint(
    unified.PRODUCTION_PARAMETERS
)
BOUNDED_PROFILE_FINGERPRINT = unified.profile_fingerprint(
    v2_35.QUALIFICATION_PARAMETERS
)
SUPPORTED_PROFILES = {
    PRODUCTION_PROFILE_FINGERPRINT: unified.PRODUCTION_PARAMETERS,
    BOUNDED_PROFILE_FINGERPRINT: v2_35.QUALIFICATION_PARAMETERS,
}

V2_36_PORTABLE_EVIDENCE = {
    "filename": "pq_rbbc_cap_unified_tree_bounded_relation_portable_evidence_v2_36.json",
    "bytes": 5_719,
    "sha256": "660d4c0d9cf36bbb5ecf02dc66d65721e077171de5b1e9c6b010d19871235fad",
}
V2_36_CHECKPOINT_IDENTITY = {
    "filename": v2_36.CHECKPOINT_FILENAME,
    "bytes": 21_530,
    "sha256": "a605d18efa8f23eec3c89da1e4497ddff2c29790c0ea3cb0b7017808cfa39a17",
}

PRODUCTION_VECTOR_FILENAME = (
    "pq_rbbc_cap_unified_statement_production_vector_v2_37.json"
)
BOUNDED_VECTOR_FILENAME = (
    "pq_rbbc_cap_unified_parent_input_bounded_vector_v2_37.json"
)
EVIDENCE_FILENAME = "pq_rbbc_cap_unified_statement_parent_abi_evidence_v2_37.json"
QUALIFICATION_FILENAME = (
    "pq_rbbc_cap_unified_statement_parent_abi_qualification_v2_37.json"
)
PRODUCTION_VECTOR_FORMAT = "PQRBBC-CAP-UNIFIED-STATEMENT-PRODUCTION-VECTOR-1"
BOUNDED_VECTOR_FORMAT = "PQRBBC-CAP-UNIFIED-PARENT-INPUT-BOUNDED-VECTOR-1"
EVIDENCE_FORMAT = "PQRBBC-CAP-UNIFIED-STATEMENT-PARENT-ABI-EVIDENCE-1"
QUALIFICATION_FORMAT = (
    "PQRBBC-CAP-UNIFIED-STATEMENT-PARENT-ABI-QUALIFICATION-1"
)


class UnifiedStatementABIError(ValueError):
    """Raised when v2.37 statement or parent-input bytes are noncanonical."""


def canonical_json(document: object) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def identity(path: Path) -> dict[str, object]:
    return {
        "filename": path.name,
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def _read_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise UnifiedStatementABIError(f"{path.name} root must be an object")
    return document


def _atomic_json(path: Path, document: object) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(canonical_json(document))
    temporary.replace(path)


def _outside_repository(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT.resolve())
    except ValueError:
        return True
    return False


def _read_bytes(
    encoded: bytes, offset: int, length: int, label: str
) -> tuple[bytes, int]:
    if length < 0 or offset + length > len(encoded):
        raise UnifiedStatementABIError(f"{label} truncated")
    return encoded[offset : offset + length], offset + length


def _read_uint(
    encoded: bytes, offset: int, length: int, label: str
) -> tuple[int, int]:
    value, offset = _read_bytes(encoded, offset, length, label)
    return int.from_bytes(value, "little"), offset


def _expect_prefix(encoded: bytes, offset: int, value: bytes, label: str) -> int:
    observed, offset = _read_bytes(encoded, offset, len(value), label)
    if observed != value:
        raise UnifiedStatementABIError(f"wrong {label}")
    return offset


def _profile_parameters(
    profile_fingerprint: str,
) -> unified.UnifiedTreeParameters:
    try:
        return SUPPORTED_PROFILES[profile_fingerprint]
    except KeyError as error:
        raise UnifiedStatementABIError("unsupported unified profile") from error


def _length_prefix(value: bytes) -> bytes:
    return len(value).to_bytes(8, "little") + value


@dataclass(frozen=True)
class UnifiedCAPStatement:
    profile_fingerprint: str
    common_parameters_digest: bytes
    ctx: bytes
    sid: bytes
    rid: bytes
    y: bytes

    def encode(self) -> bytes:
        _profile_parameters(self.profile_fingerprint)
        values = {
            "common_parameters_digest": self.common_parameters_digest,
            "ctx": self.ctx,
            "sid": self.sid,
            "rid": self.rid,
            "y": self.y,
        }
        result = bytearray(STATEMENT_MAGIC)
        result.extend(CODEC_VERSION.to_bytes(2, "little"))
        result.extend(bytes.fromhex(self.profile_fingerprint))
        result.extend(len(STATEMENT_FIELDS).to_bytes(2, "little"))
        for field_id, name, expected_length in STATEMENT_FIELDS:
            value = values[name]
            if len(value) != expected_length:
                raise UnifiedStatementABIError(
                    f"statement {name} must be {expected_length} bytes"
                )
            result.extend(field_id.to_bytes(2, "little"))
            result.extend(_length_prefix(value))
        return bytes(result)

    @classmethod
    def decode(
        cls, encoded: bytes, *, expected_profile_fingerprint: str | None = None
    ) -> "UnifiedCAPStatement":
        offset = _expect_prefix(encoded, 0, STATEMENT_MAGIC, "statement magic")
        version, offset = _read_uint(encoded, offset, 2, "statement version")
        if version != CODEC_VERSION:
            raise UnifiedStatementABIError("statement wrong version")
        fingerprint, offset = _read_bytes(
            encoded, offset, 32, "statement profile fingerprint"
        )
        profile_fingerprint = fingerprint.hex()
        _profile_parameters(profile_fingerprint)
        if (
            expected_profile_fingerprint is not None
            and profile_fingerprint != expected_profile_fingerprint
        ):
            raise UnifiedStatementABIError("statement wrong expected profile")
        count, offset = _read_uint(encoded, offset, 2, "statement field count")
        if count != len(STATEMENT_FIELDS):
            raise UnifiedStatementABIError("statement wrong field count")
        values: dict[str, bytes] = {}
        for expected_id, name, expected_length in STATEMENT_FIELDS:
            field_id, offset = _read_uint(
                encoded, offset, 2, f"statement {name} id"
            )
            if field_id != expected_id:
                raise UnifiedStatementABIError(
                    f"statement noncanonical field {name}"
                )
            length, offset = _read_uint(
                encoded, offset, 8, f"statement {name} length"
            )
            if length != expected_length:
                raise UnifiedStatementABIError(f"statement wrong {name} length")
            values[name], offset = _read_bytes(
                encoded, offset, length, f"statement {name}"
            )
        if offset != len(encoded):
            raise UnifiedStatementABIError("statement trailing bytes")
        statement = cls(profile_fingerprint=profile_fingerprint, **values)
        if statement.encode() != encoded:
            raise UnifiedStatementABIError("statement noncanonical encoding")
        return statement


def parent_binding_digest(
    profile_fingerprint: str,
    statement: bytes,
    c_r: bytes,
    ticket_message: bytes,
) -> bytes:
    _profile_parameters(profile_fingerprint)
    return hashlib.sha256(
        DOMAIN_PARENT_BINDING
        + bytes.fromhex(profile_fingerprint)
        + _length_prefix(statement)
        + _length_prefix(c_r)
        + _length_prefix(ticket_message)
    ).digest()


@dataclass(frozen=True)
class UnifiedParentInput:
    profile_fingerprint: str
    statement: bytes
    c_r: bytes
    ticket_message: bytes
    binding_digest: bytes

    @classmethod
    def create(
        cls,
        profile_fingerprint: str,
        statement: bytes,
        c_r: bytes,
        ticket_message: bytes,
    ) -> "UnifiedParentInput":
        return cls(
            profile_fingerprint,
            statement,
            c_r,
            ticket_message,
            parent_binding_digest(
                profile_fingerprint, statement, c_r, ticket_message
            ),
        )

    def encode(self) -> bytes:
        parameters = _profile_parameters(self.profile_fingerprint)
        decoded_statement = UnifiedCAPStatement.decode(
            self.statement,
            expected_profile_fingerprint=self.profile_fingerprint,
        )
        del decoded_statement
        try:
            commitment = unified.UnifiedCommitment.decode(parameters, self.c_r)
        except unified.UnifiedTreeError as error:
            raise UnifiedStatementABIError("parent c_r rejected") from error
        if commitment.profile_fingerprint != self.profile_fingerprint:
            raise UnifiedStatementABIError("parent c_r profile mismatch")
        if len(self.ticket_message) != 32:
            raise UnifiedStatementABIError("parent ticket_message must be 32 bytes")
        expected_binding = parent_binding_digest(
            self.profile_fingerprint,
            self.statement,
            self.c_r,
            self.ticket_message,
        )
        if self.binding_digest != expected_binding:
            raise UnifiedStatementABIError("parent binding digest mismatch")
        values = {
            "statement": self.statement,
            "c_r": self.c_r,
            "ticket_message": self.ticket_message,
            "binding_digest": self.binding_digest,
        }
        result = bytearray(PARENT_MAGIC)
        result.extend(CODEC_VERSION.to_bytes(2, "little"))
        result.extend(bytes.fromhex(self.profile_fingerprint))
        result.extend(len(PARENT_SECTIONS).to_bytes(2, "little"))
        for section_id, name in PARENT_SECTIONS:
            result.extend(section_id.to_bytes(2, "little"))
            result.extend(_length_prefix(values[name]))
        return bytes(result)

    @classmethod
    def decode(
        cls, encoded: bytes, *, expected_profile_fingerprint: str | None = None
    ) -> "UnifiedParentInput":
        offset = _expect_prefix(encoded, 0, PARENT_MAGIC, "parent magic")
        version, offset = _read_uint(encoded, offset, 2, "parent version")
        if version != CODEC_VERSION:
            raise UnifiedStatementABIError("parent wrong version")
        fingerprint, offset = _read_bytes(
            encoded, offset, 32, "parent profile fingerprint"
        )
        profile_fingerprint = fingerprint.hex()
        _profile_parameters(profile_fingerprint)
        if (
            expected_profile_fingerprint is not None
            and profile_fingerprint != expected_profile_fingerprint
        ):
            raise UnifiedStatementABIError("parent wrong expected profile")
        count, offset = _read_uint(encoded, offset, 2, "parent section count")
        if count != len(PARENT_SECTIONS):
            raise UnifiedStatementABIError("parent wrong section count")
        values: dict[str, bytes] = {}
        for expected_id, name in PARENT_SECTIONS:
            section_id, offset = _read_uint(
                encoded, offset, 2, f"parent {name} id"
            )
            if section_id != expected_id:
                raise UnifiedStatementABIError(
                    f"parent noncanonical section {name}"
                )
            length, offset = _read_uint(
                encoded, offset, 8, f"parent {name} length"
            )
            if name in ("ticket_message", "binding_digest") and length != 32:
                raise UnifiedStatementABIError(f"parent wrong {name} length")
            values[name], offset = _read_bytes(
                encoded, offset, length, f"parent {name}"
            )
        if offset != len(encoded):
            raise UnifiedStatementABIError("parent trailing bytes")
        result = cls(profile_fingerprint=profile_fingerprint, **values)
        if result.encode() != encoded:
            raise UnifiedStatementABIError("parent noncanonical encoding")
        return result


def _common_parameters_digest(profile_fingerprint: str) -> bytes:
    return hashlib.sha256(
        DOMAIN_COMMON_PARAMETERS
        + bytes.fromhex(profile_fingerprint)
        + bytes.fromhex(V2_36_PORTABLE_EVIDENCE["sha256"])
    ).digest()


def fixture_statement(profile_fingerprint: str) -> UnifiedCAPStatement:
    inputs = v2_36.bounded_inputs()
    return UnifiedCAPStatement(
        profile_fingerprint=profile_fingerprint,
        common_parameters_digest=_common_parameters_digest(profile_fingerprint),
        ctx=inputs.statement.common_ctx,
        sid=hashlib.sha256(DOMAIN_SESSION + inputs.witness.sn).digest(),
        rid=inputs.statement.rid,
        y=inputs.statement.blind_request.masked_target,
    )


def fixture_ticket_message() -> bytes:
    payload = v2_36.bounded_inputs().statement.payload.encode()
    return hashlib.shake_256(reference.LABEL_TICKET + payload).digest(32)


def validate_ticket_mapping(statement: UnifiedCAPStatement) -> None:
    inputs = v2_36.bounded_inputs()
    v2_36.validate_ticket_inputs(inputs)
    expected = fixture_statement(statement.profile_fingerprint)
    if statement != expected:
        raise UnifiedStatementABIError("unified statement ticket mapping mismatch")
    if len(fixture_ticket_message()) != 32:
        raise AssertionError("ticket message width changed")


def validate_bounded_parent_mapping(
    parent: UnifiedParentInput, expected_c_r: bytes
) -> None:
    if parent.profile_fingerprint != BOUNDED_PROFILE_FINGERPRINT:
        raise UnifiedStatementABIError("bounded parent profile mismatch")
    statement = UnifiedCAPStatement.decode(
        parent.statement,
        expected_profile_fingerprint=BOUNDED_PROFILE_FINGERPRINT,
    )
    validate_ticket_mapping(statement)
    if parent.c_r != expected_c_r:
        raise UnifiedStatementABIError("bounded parent checkpoint commitment mismatch")
    if parent.ticket_message != fixture_ticket_message():
        raise UnifiedStatementABIError("bounded parent ticket message mismatch")
    if UnifiedParentInput.decode(parent.encode()) != parent:
        raise UnifiedStatementABIError("bounded parent round-trip mismatch")


def _checkpoint_tree_snapshot(
    checkpoint: Mapping[str, object]
) -> Mapping[str, object]:
    records = checkpoint.get("stage_records")
    if not isinstance(records, list):
        raise UnifiedStatementABIError("v2.36 checkpoint records missing")
    for record in records:
        if isinstance(record, dict) and record.get("stage") == "unified-tree":
            data = record.get("data")
            if isinstance(data, dict):
                return data
    raise UnifiedStatementABIError("v2.36 unified-tree checkpoint stage missing")


def load_bounded_commitment(checkpoint_path: Path) -> bytes:
    if identity(checkpoint_path) != V2_36_CHECKPOINT_IDENTITY:
        raise UnifiedStatementABIError("v2.36 checkpoint identity mismatch")
    checkpoint = _read_json(checkpoint_path)
    v2_36.validate_checkpoint_document(
        checkpoint, v2_36.state_contract(v2_36.MANIFEST_PATH)
    )
    snapshot = _checkpoint_tree_snapshot(checkpoint)
    try:
        c_r = bytes.fromhex(snapshot["commitment_hex"])
        commitment = unified.UnifiedCommitment.decode(
            v2_35.QUALIFICATION_PARAMETERS, c_r
        )
    except (KeyError, TypeError, ValueError, unified.UnifiedTreeError) as error:
        raise UnifiedStatementABIError("v2.36 checkpoint commitment rejected") from error
    if commitment.profile_fingerprint != BOUNDED_PROFILE_FINGERPRINT:
        raise UnifiedStatementABIError("v2.36 commitment profile mismatch")
    return c_r


def claim_boundary() -> dict[str, bool]:
    return {
        "v2_37_unified_statement_codec_implemented": True,
        "v2_37_production_profile_statement_vector_frozen": True,
        "v2_37_parent_input_abi_implemented": True,
        "v2_37_bounded_parent_input_qualified": False,
        "production_parent_commitment_materialized": False,
        "production_parent_envelope_materialized": False,
        "production_parent_join_replayed": False,
        "production_runner_qualified": False,
        "resource_reservation_frozen": False,
        "independent_review_frozen": False,
        "production_prefreeze_authorized": False,
        "production_prefreeze_started": False,
        "large_replay_started": False,
        "large_proving_run_started": False,
        "cap_security_qualified": False,
        "fork_security_proof_revalidated": False,
        "legacy_18_tree_profile_preserved": True,
        "system_architecture_changed": False,
        "ticket_lifecycle_changed": False,
        "pq_sat_auth_changed": False,
        "production_closed": False,
    }


def exact_qualification_command() -> str:
    return (
        "PYTHONPATH=src python -u "
        "src/pq_rbbc_cap_unified_statement_parent_abi.py "
        "--manifest manifests/"
        "pq_rbbc_cap_unified_statement_parent_abi_manifest_v2_37.json "
        "--phase qualification "
        "--checkpoint-payload /tmp/pq_rbbc_external_artifacts_rebuilt/"
        "v2_36_unified_tree_relation/qualification/"
        "pq_rbbc_cap_unified_tree_checkpoint_payload_v2_36.json "
        "--output /tmp/pq_rbbc_external_artifacts_rebuilt/"
        "v2_37_unified_statement_parent_abi/qualification --fresh-output"
    )


def prospective_production_command() -> str:
    return (
        "PYTHONPATH=src python -u "
        "src/pq_rbbc_cap_unified_statement_parent_abi.py "
        "--manifest manifests/"
        "pq_rbbc_cap_unified_statement_parent_abi_manifest_v2_37.json "
        "--phase production-prefreeze "
        "--checkpoint-payload /tmp/pq_rbbc_external_artifacts_rebuilt/"
        "v2_37_unified_statement_parent_abi/production-checkpoint.json "
        "--output /tmp/pq_rbbc_external_artifacts_rebuilt/"
        "v2_37_unified_statement_parent_abi/production-prefreeze --fresh-output"
    )


def build_manifest() -> dict[str, object]:
    qualification_command = exact_qualification_command()
    production_command = prospective_production_command()
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "namespace": {
            "new_unified_profile": True,
            "legacy_v2_32_statement_codec_overwritten": False,
            "legacy_18_tree_profile_preserved": True,
        },
        "profiles": {
            "production": PRODUCTION_PROFILE_FINGERPRINT,
            "bounded": BOUNDED_PROFILE_FINGERPRINT,
            "cross_profile_decode_forbidden": True,
        },
        "statement_contract": {
            "magic_hex": STATEMENT_MAGIC.hex(),
            "version": CODEC_VERSION,
            "profile_fingerprint_bytes": 32,
            "fields": [
                {"id": field_id, "name": name, "bytes": length}
                for field_id, name, length in STATEMENT_FIELDS
            ],
            "integer_encoding": "unsigned little-endian",
            "field_order_is_canonical": True,
            "trailing_bytes_forbidden": True,
            "private_witness_serialized": False,
        },
        "parent_input_contract": {
            "magic_hex": PARENT_MAGIC.hex(),
            "version": CODEC_VERSION,
            "sections": [
                {"id": section_id, "name": name}
                for section_id, name in PARENT_SECTIONS
            ],
            "statement_and_commitment_profiles_must_match": True,
            "ticket_message_derivation": "SHAKE256(PQ-RBBC/TICKET || payload)[0:32]",
            "binding_digest": (
                "SHA256(domain || profile || len(statement)||statement || "
                "len(c_r)||c_r || len(ticket_message)||ticket_message)"
            ),
            "production_c_r_required_before_production_envelope": True,
        },
        "ticket_mapping": {
            "ctx": "IssueStatement.common_ctx",
            "rid": "IssueStatement.rid",
            "y": "IssueStatement.blind_request.masked_target",
            "sid": "SHA256(v2.37 session domain || IssueWitness.sn)",
            "ticket_lifecycle_changed": False,
        },
        "inputs": {
            "v2_36_portable_evidence": V2_36_PORTABLE_EVIDENCE,
            "v2_36_checkpoint_payload": V2_36_CHECKPOINT_IDENTITY,
            "other_tree_observed_stream_bytes_reused": False,
            "v2_29_transcript_reused_as_observation": False,
        },
        "execution_gate": {
            "qualification_command": qualification_command,
            "qualification_command_sha256": sha256_bytes(
                qualification_command.encode("ascii")
            ),
            "production_command": production_command,
            "production_command_sha256": sha256_bytes(
                production_command.encode("ascii")
            ),
            "production_command_executable_now": False,
            "production_branch_always_rejects": True,
        },
        "claim_boundary": claim_boundary(),
    }


def validate_manifest(path: Path) -> dict[str, object]:
    document = _read_json(path)
    if document != build_manifest():
        raise UnifiedStatementABIError("manifest is not the frozen v2.37 contract")
    return document


def _production_vector() -> dict[str, object]:
    statement = fixture_statement(PRODUCTION_PROFILE_FINGERPRINT)
    validate_ticket_mapping(statement)
    encoded = statement.encode()
    UnifiedCAPStatement.decode(
        encoded, expected_profile_fingerprint=PRODUCTION_PROFILE_FINGERPRINT
    )
    return {
        "format": PRODUCTION_VECTOR_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "profile_fingerprint": PRODUCTION_PROFILE_FINGERPRINT,
        "statement_hex": encoded.hex(),
        "statement_bytes": len(encoded),
        "statement_sha256": sha256_bytes(encoded),
        "logical_fields": {
            "common_parameters_digest": statement.common_parameters_digest.hex(),
            "ctx": statement.ctx.hex(),
            "sid": statement.sid.hex(),
            "rid": statement.rid.hex(),
            "y": statement.y.hex(),
        },
        "test_vector_only": True,
        "production_tree_executed": False,
        "production_commitment_materialized": False,
        "production_parent_envelope_materialized": False,
    }


def _bounded_vector(c_r: bytes) -> dict[str, object]:
    statement = fixture_statement(BOUNDED_PROFILE_FINGERPRINT)
    validate_ticket_mapping(statement)
    statement_bytes = statement.encode()
    ticket_message = fixture_ticket_message()
    parent = UnifiedParentInput.create(
        BOUNDED_PROFILE_FINGERPRINT, statement_bytes, c_r, ticket_message
    )
    validate_bounded_parent_mapping(parent, c_r)
    encoded = parent.encode()
    UnifiedParentInput.decode(
        encoded, expected_profile_fingerprint=BOUNDED_PROFILE_FINGERPRINT
    )
    return {
        "format": BOUNDED_VECTOR_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "profile_fingerprint": BOUNDED_PROFILE_FINGERPRINT,
        "statement_hex": statement_bytes.hex(),
        "statement_bytes": len(statement_bytes),
        "statement_sha256": sha256_bytes(statement_bytes),
        "c_r_hex": c_r.hex(),
        "c_r_bytes": len(c_r),
        "c_r_sha256": sha256_bytes(c_r),
        "ticket_message_hex": ticket_message.hex(),
        "binding_digest_hex": parent.binding_digest.hex(),
        "parent_input_hex": encoded.hex(),
        "parent_input_bytes": len(encoded),
        "parent_input_sha256": sha256_bytes(encoded),
        "reference_ticket_relation_accepted": True,
        "bounded_fixture_only": True,
        "production_observation": False,
    }


def validate_production_vector(document: Mapping[str, object]) -> None:
    if document != _production_vector():
        raise UnifiedStatementABIError("production statement vector mismatch")


def validate_bounded_vector(
    document: Mapping[str, object], expected_c_r: bytes
) -> None:
    if document != _bounded_vector(expected_c_r):
        raise UnifiedStatementABIError("bounded parent-input vector mismatch")


def _expect_rejected(action: object) -> bool:
    try:
        action()  # type: ignore[operator]
    except UnifiedStatementABIError:
        return True
    return False


def mutation_checks(
    statement: UnifiedCAPStatement, parent: UnifiedParentInput
) -> dict[str, bool]:
    statement_bytes = statement.encode()
    parent_bytes = parent.encode()
    wrong_profile_statement = bytearray(statement_bytes)
    wrong_profile_statement[len(STATEMENT_MAGIC) + 2] ^= 1
    wrong_order_statement = bytearray(statement_bytes)
    first_id = len(STATEMENT_MAGIC) + 2 + 32 + 2
    wrong_order_statement[first_id] = 2
    wrong_length_statement = bytearray(statement_bytes)
    first_length = first_id + 2
    wrong_length_statement[first_length] ^= 1
    wrong_binding = replace(
        parent, binding_digest=bytes([parent.binding_digest[0] ^ 1]) + parent.binding_digest[1:]
    )
    wrong_ticket = replace(
        parent, ticket_message=bytes([parent.ticket_message[0] ^ 1]) + parent.ticket_message[1:]
    )
    wrong_c_r = replace(parent, c_r=parent.c_r[:-1] + bytes([parent.c_r[-1] ^ 1]))
    changed_ticket = (
        bytes([parent.ticket_message[0] ^ 1]) + parent.ticket_message[1:]
    )
    rebound_wrong_ticket = UnifiedParentInput.create(
        parent.profile_fingerprint,
        parent.statement,
        parent.c_r,
        changed_ticket,
    )
    changed_c_r = parent.c_r[:-1] + bytes([parent.c_r[-1] ^ 1])
    rebound_wrong_c_r = UnifiedParentInput.create(
        parent.profile_fingerprint,
        parent.statement,
        changed_c_r,
        parent.ticket_message,
    )
    expected = fixture_statement(statement.profile_fingerprint)
    return {
        "statement_wrong_magic_rejected": _expect_rejected(
            lambda: UnifiedCAPStatement.decode(b"X" + statement_bytes[1:])
        ),
        "statement_wrong_profile_rejected": _expect_rejected(
            lambda: UnifiedCAPStatement.decode(bytes(wrong_profile_statement))
        ),
        "statement_wrong_order_rejected": _expect_rejected(
            lambda: UnifiedCAPStatement.decode(bytes(wrong_order_statement))
        ),
        "statement_wrong_length_rejected": _expect_rejected(
            lambda: UnifiedCAPStatement.decode(bytes(wrong_length_statement))
        ),
        "statement_trailing_bytes_rejected": _expect_rejected(
            lambda: UnifiedCAPStatement.decode(statement_bytes + b"\x00")
        ),
        "statement_cross_profile_rejected": _expect_rejected(
            lambda: UnifiedCAPStatement.decode(
                statement_bytes,
                expected_profile_fingerprint=PRODUCTION_PROFILE_FINGERPRINT,
            )
        ),
        "parent_wrong_magic_rejected": _expect_rejected(
            lambda: UnifiedParentInput.decode(b"X" + parent_bytes[1:])
        ),
        "parent_binding_mutation_rejected": _expect_rejected(wrong_binding.encode),
        "parent_ticket_mutation_rejected": _expect_rejected(wrong_ticket.encode),
        "parent_commitment_mutation_rejected": _expect_rejected(wrong_c_r.encode),
        "parent_rebound_ticket_mapping_rejected": _expect_rejected(
            lambda: validate_bounded_parent_mapping(
                rebound_wrong_ticket, parent.c_r
            )
        ),
        "parent_rebound_checkpoint_commitment_rejected": _expect_rejected(
            lambda: validate_bounded_parent_mapping(
                rebound_wrong_c_r, parent.c_r
            )
        ),
        "parent_trailing_bytes_rejected": _expect_rejected(
            lambda: UnifiedParentInput.decode(parent_bytes + b"\x00")
        ),
        "mapping_ctx_mutation_rejected": _expect_rejected(
            lambda: validate_ticket_mapping(
                replace(expected, ctx=bytes([expected.ctx[0] ^ 1]) + expected.ctx[1:])
            )
        ),
        "mapping_rid_mutation_rejected": _expect_rejected(
            lambda: validate_ticket_mapping(
                replace(expected, rid=bytes([expected.rid[0] ^ 1]) + expected.rid[1:])
            )
        ),
        "mapping_y_mutation_rejected": _expect_rejected(
            lambda: validate_ticket_mapping(
                replace(expected, y=bytes([expected.y[0] ^ 1]) + expected.y[1:])
            )
        ),
    }


def qualify(
    manifest_path: Path, checkpoint_path: Path, output: Path
) -> tuple[dict[str, object], dict[str, object]]:
    validate_manifest(manifest_path)
    if not _outside_repository(output):
        raise UnifiedStatementABIError("qualification output must be external")
    if output.exists():
        raise FileExistsError("fresh-output directory already exists")
    c_r = load_bounded_commitment(checkpoint_path)
    production_vector = _production_vector()
    bounded_vector = _bounded_vector(c_r)
    statement = fixture_statement(BOUNDED_PROFILE_FINGERPRINT)
    parent = UnifiedParentInput.create(
        BOUNDED_PROFILE_FINGERPRINT,
        statement.encode(),
        c_r,
        fixture_ticket_message(),
    )
    checks = mutation_checks(statement, parent)
    if not checks or not all(checks.values()):
        raise UnifiedStatementABIError("one or more ABI mutation checks failed")
    output.mkdir(parents=True)
    production_path = output / PRODUCTION_VECTOR_FILENAME
    bounded_path = output / BOUNDED_VECTOR_FILENAME
    _atomic_json(production_path, production_vector)
    _atomic_json(bounded_path, bounded_vector)
    validate_production_vector(_read_json(production_path))
    validate_bounded_vector(_read_json(bounded_path), c_r)
    evidence = {
        "format": EVIDENCE_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "manifest": identity(manifest_path),
        "v2_36_portable_evidence": V2_36_PORTABLE_EVIDENCE,
        "v2_36_checkpoint_payload": identity(checkpoint_path),
        "production_statement_vector": identity(production_path),
        "bounded_parent_input_vector": identity(bounded_path),
        "observations": {
            "statement_profiles_serialized": 2,
            "bounded_parent_envelopes_materialized": 1,
            "production_parent_envelopes_materialized": 0,
            "production_leaves_expanded": 0,
            "production_relation_rows": 0,
            "br1cs_rows": 0,
            "proofs_generated": 0,
            "other_tree_observed_stream_bytes_reused": False,
            "v2_29_transcript_reused_as_observation": False,
        },
        "claim_boundary": claim_boundary(),
    }
    evidence_path = output / EVIDENCE_FILENAME
    _atomic_json(evidence_path, evidence)
    qualification = {
        "format": QUALIFICATION_FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "implementation": identity(Path(__file__)),
        "manifest": identity(manifest_path),
        "external_inputs": {
            "v2_36_checkpoint_payload": identity(checkpoint_path),
        },
        "external_outputs": {
            "production_statement_vector": identity(production_path),
            "bounded_parent_input_vector": identity(bounded_path),
            "run_evidence": identity(evidence_path),
        },
        "checks": checks,
        "result": {
            "production_profile_statement_serialization_qualified": True,
            "bounded_parent_input_abi_qualified": True,
            "ticket_mapping_qualified_on_bounded_fixture": True,
            "production_parent_input_qualified": False,
            "safe_to_author_production_streaming_path": True,
            "safe_to_start_production_prefreeze": False,
            "safe_to_start_large_replay": False,
            "safe_to_start_large_proving_run": False,
        },
        "claim_boundary": claim_boundary(),
    }
    _atomic_json(output / QUALIFICATION_FILENAME, qualification)
    return evidence, qualification


def reject_production_prefreeze(
    manifest_path: Path, checkpoint_path: Path, output: Path
) -> None:
    validate_manifest(manifest_path)
    if output.exists():
        raise FileExistsError("production output already exists")
    if not _outside_repository(output):
        raise UnifiedStatementABIError("production output must be external")
    details = {
        "checkpoint_payload_provided": checkpoint_path.is_file(),
        "output_created": False,
        "reasons": [
            "production unified-tree checkpoint has not been materialized",
            "production parent commitment c_r is absent",
            "production streaming path has not been implemented or qualified",
            "operator resource reservation identity is not frozen",
            "independent review identity is not frozen",
            "production pre-freeze is not authorized",
        ],
    }
    raise RuntimeError(
        "production-prefreeze unavailable: "
        + canonical_json(details).decode().strip()
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--phase", choices=("qualification", "production-prefreeze"), required=True
    )
    parser.add_argument("--checkpoint-payload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fresh-output", action="store_true")
    args = parser.parse_args()
    if not args.fresh_output:
        raise UnifiedStatementABIError("v2.37 requires --fresh-output")
    if args.phase == "production-prefreeze":
        reject_production_prefreeze(
            args.manifest, args.checkpoint_payload, args.output
        )
    evidence, qualification = qualify(
        args.manifest, args.checkpoint_payload, args.output
    )
    result = {
        "phase": args.phase,
        "output": str(args.output),
        "production_statement_vector": evidence["production_statement_vector"],
        "bounded_parent_input_vector": evidence["bounded_parent_input_vector"],
        "evidence": identity(args.output / EVIDENCE_FILENAME),
        "qualification": identity(args.output / QUALIFICATION_FILENAME),
        "bounded_parent_input_abi_qualified": qualification["result"][
            "bounded_parent_input_abi_qualified"
        ],
        "production_parent_input_qualified": False,
        "safe_to_start_production_prefreeze": False,
    }
    print(canonical_json(result).decode(), end="")


if __name__ == "__main__":
    main()
