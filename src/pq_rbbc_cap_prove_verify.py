#!/usr/bin/env python3
"""Fail-closed v2.32 CAP statement and proof-envelope implementation.

This module deliberately implements only the byte-level boundary that can be
fixed without inventing the missing TCitH response phase.  In particular,
``prove`` is unavailable and ``verify`` never accepts: production acceptance
must remain fail closed until the unified-GGM opening, Fiat--Shamir grinding,
and Protocol-11 polynomial checks are implemented and reviewed.
"""

from __future__ import annotations

from dataclasses import dataclass

import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_straightline_extractor as extractor


IMPLEMENTATION_VERSION = "2.32"
PROFILE_FINGERPRINT = cap.profile_fingerprint(cap.PRODUCTION_PARAMETERS)

STATEMENT_MAGIC = b"PQRBBC-CAP-STATEMENT-V1"
STATEMENT_VERSION = 1
STATEMENT_FIELDS = (
    (1, "common_parameters_digest", 32),
    (2, "ctx", 32),
    (3, "sid", 32),
    (4, "rid", 32),
    (5, "y", 72),
)

PROOF_MAGIC = b"PQRBBC-CAP-PROOF-V1"
PROOF_VERSION = 1
PROOF_SECTIONS = (
    (1, "c_r"),
    (2, "c_x"),
    (3, "pow_nonce"),
    (4, "pi_2"),
)
C_R_BYTES = cap.commitment_bytes(cap.PRODUCTION_PARAMETERS)
C_X_BYTES = cap.PRODUCTION_PARAMETERS.appended_signature_bits // 8
POW_NONCE_BYTES = 8
MAX_PI_2_BYTES = 1 << 24


class CAPCodecError(ValueError):
    """Raised when candidate v2.32 bytes are not canonical."""


class ProductionProverUnavailable(RuntimeError):
    """Raised rather than silently substituting a non-production prover."""


@dataclass(frozen=True)
class CAPStatement:
    common_parameters_digest: bytes
    ctx: bytes
    sid: bytes
    rid: bytes
    y: bytes

    def encode(self) -> bytes:
        values = {
            "common_parameters_digest": self.common_parameters_digest,
            "ctx": self.ctx,
            "sid": self.sid,
            "rid": self.rid,
            "y": self.y,
        }
        result = bytearray(STATEMENT_MAGIC)
        result.extend(STATEMENT_VERSION.to_bytes(2, "little"))
        result.extend(bytes.fromhex(PROFILE_FINGERPRINT))
        result.extend(len(STATEMENT_FIELDS).to_bytes(2, "little"))
        for section_id, name, expected_bytes in STATEMENT_FIELDS:
            value = values[name]
            if len(value) != expected_bytes:
                raise CAPCodecError(
                    f"statement {name} must be {expected_bytes} bytes"
                )
            result.extend(section_id.to_bytes(2, "little"))
            result.extend(len(value).to_bytes(8, "little"))
            result.extend(value)
        return bytes(result)

    @classmethod
    def decode(cls, encoded: bytes) -> "CAPStatement":
        offset = 0
        offset = _expect_prefix(encoded, offset, STATEMENT_MAGIC, "statement magic")
        version, offset = _read_uint(encoded, offset, 2, "statement version")
        if version != STATEMENT_VERSION:
            raise CAPCodecError("statement wrong version")
        fingerprint, offset = _read_bytes(
            encoded, offset, 32, "statement profile fingerprint"
        )
        if fingerprint.hex() != PROFILE_FINGERPRINT:
            raise CAPCodecError("statement wrong profile fingerprint")
        count, offset = _read_uint(encoded, offset, 2, "statement field count")
        if count != len(STATEMENT_FIELDS):
            raise CAPCodecError("statement wrong field count")
        values: dict[str, bytes] = {}
        for expected_id, name, expected_bytes in STATEMENT_FIELDS:
            section_id, offset = _read_uint(
                encoded, offset, 2, f"statement {name} id"
            )
            if section_id != expected_id:
                raise CAPCodecError(f"statement noncanonical field {name}")
            length, offset = _read_uint(
                encoded, offset, 8, f"statement {name} length"
            )
            if length != expected_bytes:
                raise CAPCodecError(f"statement wrong {name} length")
            values[name], offset = _read_bytes(
                encoded, offset, length, f"statement {name}"
            )
        if offset != len(encoded):
            raise CAPCodecError("statement trailing bytes")
        statement = cls(**values)
        if statement.encode() != encoded:
            raise CAPCodecError("statement noncanonical encoding")
        return statement


@dataclass(frozen=True)
class CAPProofEnvelope:
    c_r: bytes
    c_x: bytes
    pow_nonce: bytes
    pi_2: bytes

    def encode(self) -> bytes:
        _validate_proof_payloads(self)
        values = {
            "c_r": self.c_r,
            "c_x": self.c_x,
            "pow_nonce": self.pow_nonce,
            "pi_2": self.pi_2,
        }
        result = bytearray(PROOF_MAGIC)
        result.extend(PROOF_VERSION.to_bytes(2, "little"))
        result.extend(bytes.fromhex(PROFILE_FINGERPRINT))
        result.extend(len(PROOF_SECTIONS).to_bytes(2, "little"))
        for section_id, name in PROOF_SECTIONS:
            value = values[name]
            result.extend(section_id.to_bytes(2, "little"))
            result.extend(len(value).to_bytes(8, "little"))
            result.extend(value)
        return bytes(result)

    @classmethod
    def decode(cls, encoded: bytes) -> "CAPProofEnvelope":
        offset = 0
        offset = _expect_prefix(encoded, offset, PROOF_MAGIC, "proof magic")
        version, offset = _read_uint(encoded, offset, 2, "proof version")
        if version != PROOF_VERSION:
            raise CAPCodecError("proof wrong version")
        fingerprint, offset = _read_bytes(
            encoded, offset, 32, "proof profile fingerprint"
        )
        if fingerprint.hex() != PROFILE_FINGERPRINT:
            raise CAPCodecError("proof wrong profile fingerprint")
        count, offset = _read_uint(encoded, offset, 2, "proof section count")
        if count != len(PROOF_SECTIONS):
            raise CAPCodecError("proof wrong section count")
        values: dict[str, bytes] = {}
        for expected_id, name in PROOF_SECTIONS:
            section_id, offset = _read_uint(encoded, offset, 2, f"proof {name} id")
            if section_id != expected_id:
                raise CAPCodecError(f"proof noncanonical section {name}")
            length, offset = _read_uint(encoded, offset, 8, f"proof {name} length")
            expected_length = {
                "c_r": C_R_BYTES,
                "c_x": C_X_BYTES,
                "pow_nonce": POW_NONCE_BYTES,
            }.get(name)
            if expected_length is not None and length != expected_length:
                raise CAPCodecError(f"proof wrong {name} length")
            if name == "pi_2" and (length == 0 or length > MAX_PI_2_BYTES):
                raise CAPCodecError("proof invalid pi_2 length")
            values[name], offset = _read_bytes(
                encoded, offset, length, f"proof {name}"
            )
        if offset != len(encoded):
            raise CAPCodecError("proof trailing bytes")
        proof = cls(**values)
        _validate_proof_payloads(proof)
        if proof.encode() != encoded:
            raise CAPCodecError("proof noncanonical encoding")
        return proof


@dataclass(frozen=True)
class VerifyResult:
    accepted: bool
    failures: tuple[str, ...]


def _read_bytes(
    encoded: bytes, offset: int, length: int, label: str
) -> tuple[bytes, int]:
    if length < 0 or offset + length > len(encoded):
        raise CAPCodecError(f"{label} truncated")
    return encoded[offset : offset + length], offset + length


def _read_uint(
    encoded: bytes, offset: int, length: int, label: str
) -> tuple[int, int]:
    value, offset = _read_bytes(encoded, offset, length, label)
    return int.from_bytes(value, "little"), offset


def _expect_prefix(encoded: bytes, offset: int, prefix: bytes, label: str) -> int:
    value, offset = _read_bytes(encoded, offset, len(prefix), label)
    if value != prefix:
        raise CAPCodecError(f"wrong {label}")
    return offset


def _validate_proof_payloads(proof: CAPProofEnvelope) -> None:
    if len(proof.c_r) != C_R_BYTES:
        raise CAPCodecError(f"proof c_r must be {C_R_BYTES} bytes")
    try:
        extractor.parse_commitment(proof.c_r, cap.PRODUCTION_PARAMETERS)
    except extractor.ExtractionFailure as error:
        raise CAPCodecError(f"proof c_r rejected: {error}") from error
    if len(proof.c_x) != C_X_BYTES:
        raise CAPCodecError(f"proof c_x must be {C_X_BYTES} bytes")
    if len(proof.pow_nonce) != POW_NONCE_BYTES:
        raise CAPCodecError(
            f"proof pow_nonce must be {POW_NONCE_BYTES} bytes"
        )
    if not proof.pi_2 or len(proof.pi_2) > MAX_PI_2_BYTES:
        raise CAPCodecError("proof pi_2 length is outside candidate bounds")


def prove(*_args: object, **_kwargs: object) -> bytes:
    """Refuse to fabricate a proof before the production backend exists."""

    raise ProductionProverUnavailable(
        "v2.32 production TCitH prover is unavailable: unified-GGM opening, "
        "counter grinding, and Protocol-11 polynomial response are missing"
    )


def verify(statement_bytes: bytes, proof_bytes: bytes) -> VerifyResult:
    """Parse strictly, then fail closed before any acceptance is possible."""

    failures: list[str] = []
    try:
        CAPStatement.decode(statement_bytes)
    except CAPCodecError as error:
        failures.append(f"statement:{error}")
    try:
        CAPProofEnvelope.decode(proof_bytes)
    except CAPCodecError as error:
        failures.append(f"proof:{error}")
    if failures:
        return VerifyResult(False, tuple(failures))
    return VerifyResult(
        False,
        (
            "production_pow_unavailable",
            "unified_ggm_opening_unavailable",
            "protocol_11_polynomial_verifier_unavailable",
        ),
    )
