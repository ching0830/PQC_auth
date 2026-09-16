"""Strict research codecs for the frozen GF v0.1 candidate ABI.

Decoding establishes canonical shape, not authentication, a valid relation,
KeyGen certification, or production qualification. No runtime file loading.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import ClassVar

from ...contracts import ContractError, TraceInputs, fixed_bytes, uint
from ..reference import ReferenceCiphertext, ReferencePublicKey, ReferenceWitness


ABI_SHA256 = bytes.fromhex("97e97589fdcb293101e866a3233b38e1f48c9bdbe5ad9ddc1daabe5f2b410158")
CRYPTO_PROFILE_SHA256 = bytes.fromhex("3077ddb7e9f90c2a551c0fccff8719655b5e852394aa4e9326c9a7801225a9b7")
CAP_PROFILE_SHA256 = bytes.fromhex("2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38")
H_RBBC_PROFILE_SHA256 = bytes.fromhex("4fa0eb276ebba70a9f6c2f38f3f55d197c094121a2b614cc6ef9b7e8522cac87")
_VERSION = b"\x01\x00"
_CAP_MAGIC = b"PQRBBC-CAP-RANDOM-V1"


def require_digest(value: bytes, name: str) -> bytes:
    fixed_bytes(value, 32, name)
    if value == bytes(32):
        raise ContractError(f"{name} must be nonzero")
    return value


def validate_cap_randomness_research(encoded: bytes) -> None:
    """Check the pinned legacy 18-tree salt/root codec, without running CAP."""
    fixed_bytes(encoded, 1036, "CAP randomness")
    prefix = _CAP_MAGIC + CAP_PROFILE_SHA256.hex().encode("ascii")
    if not encoded.startswith(prefix):
        raise ContractError("wrong CAP randomness magic/profile")
    offset = len(prefix)
    # Each GF(2^193) value uses 25 bytes; high seven bits must be zero.
    for _ in range(2):
        if encoded[offset + 24] & 0xFE:
            raise ContractError("noncanonical CAP salt")
        offset += 25
    if encoded[offset:offset + 2] != b"\x12\x00":
        raise ContractError("wrong CAP tree count")
    offset += 2
    for _ in range(36):
        if encoded[offset + 24] & 0xFE:
            raise ContractError("noncanonical CAP root")
        offset += 25
    if offset != len(encoded):
        raise ContractError("wrong CAP randomness length")


@dataclass(frozen=True)
class _Field:
    name: str
    size: int
    literal: bytes | None = None
    nonzero: bool = False
    integer: bool = False
    nested: type[_ResearchPacket] | None = None


class _ResearchPacket:
    _MAGIC: ClassVar[bytes]
    _SIZE: ClassVar[int]
    _FIELDS: ClassVar[tuple[_Field, ...]]

    def __post_init__(self) -> None:
        self.encode()

    def __repr__(self) -> str:
        return f"{type(self).__name__}(research_only=True)"

    @classmethod
    def _prefix(cls) -> bytes:
        return cls._MAGIC + _VERSION + ABI_SHA256

    def _validate_specific(self) -> None:
        pass

    def encode(self) -> bytes:
        parts = [self._prefix()]
        for spec in self._FIELDS:
            if spec.literal is not None:
                raw = spec.literal
            else:
                value = getattr(self, spec.name)
                if spec.nested is not None:
                    if type(value) is not spec.nested:
                        raise ContractError(f"{spec.name} requires the exact research packet type")
                    raw = value.encode()
                elif spec.integer:
                    raw = uint(value, spec.name, (1 << (8 * spec.size)) - 1).to_bytes(spec.size, "little")
                else:
                    raw = fixed_bytes(value, spec.size, spec.name)
                    if spec.nonzero:
                        require_digest(raw, spec.name)
            parts.append(raw)
        self._validate_specific()
        encoded = b"".join(parts)
        if len(encoded) != self._SIZE:
            raise ContractError("wrong research packet length")
        return encoded

    @classmethod
    def decode(cls, encoded: bytes):
        fixed_bytes(encoded, cls._SIZE, "research packet")
        prefix = cls._prefix()
        if encoded[:len(prefix)] != prefix:
            raise ContractError("unknown research magic/version/ABI")
        offset = len(prefix)
        values = {}
        for spec in cls._FIELDS:
            raw = encoded[offset:offset + spec.size]
            offset += spec.size
            if spec.literal is not None:
                if raw != spec.literal:
                    raise ContractError(f"wrong {spec.name}")
            elif spec.nested is not None:
                values[spec.name] = spec.nested.decode(raw)
            elif spec.integer:
                values[spec.name] = int.from_bytes(raw, "little")
            else:
                values[spec.name] = raw
        result = cls(**values)
        if offset != len(encoded) or result.encode() != encoded:
            raise ContractError("noncanonical research packet")
        return result


@dataclass(frozen=True, repr=False)
class ResearchTraceBinding(_ResearchPacket):
    configuration_sha256: bytes
    ctx: bytes
    epoch: int
    oa_key_id: bytes
    tpk_record_sha256: bytes
    issuer_key_id: bytes
    issuer_public_key_sha256: bytes
    key_origin_evidence_sha256: bytes

    _MAGIC = b"PQ-TH-GF-BIND\x00"
    _SIZE = 315
    _FIELDS = (
        _Field("crypto_profile_sha256", 32, literal=CRYPTO_PROFILE_SHA256),
        _Field("configuration_sha256", 32, nonzero=True),
        _Field("ctx", 32), _Field("epoch", 8, integer=True),
        _Field("oa_role", 2, literal=b"\x05\x00"),
        _Field("purpose", 1, literal=b"\x01"),
        _Field("oa_key_id", 32, nonzero=True),
        _Field("tpk_record_sha256", 32, nonzero=True),
        _Field("issuer_key_id", 32, nonzero=True),
        _Field("issuer_public_key_sha256", 32, nonzero=True),
        _Field("key_origin_evidence_sha256", 32, nonzero=True),
    )


@dataclass(frozen=True, repr=False)
class ResearchTicketM(_ResearchPacket):
    common_pp_sha256: bytes
    ctx: bytes
    sn: bytes
    h: bytes
    ciphertext_payload: bytes

    _MAGIC = b"PQ-TH-GF-M\x00"
    _SIZE = 3005
    _FIELDS = (
        _Field("common_pp_sha256", 32, nonzero=True), _Field("ctx", 32),
        _Field("sn", 16), _Field("h", 32), _Field("ciphertext_payload", 2848),
    )

    @property
    def d_M(self) -> bytes:
        return hashlib.shake_256(b"PQ-RBBC/TICKET" + self.encode()).digest(32)

    @property
    def associated_data(self) -> bytes:
        self.encode()
        return self.ctx + self.sn + self.h

    def trace_inputs_research(self, rid: bytes) -> TraceInputs:
        self.encode()
        return TraceInputs(rid, self.sn, self.ctx, self.h)

    def ciphertext_research(self) -> ReferenceCiphertext:
        self.encode()
        return ReferenceCiphertext(self.ciphertext_payload)


@dataclass(frozen=True, repr=False)
class ResearchCommonPP(_ResearchPacket):
    trace_binding: ResearchTraceBinding
    issue_backend_pp_sha256: bytes
    gf_full_relation_manifest_sha256: bytes

    _MAGIC = b"PQ-TH-GF-PP\x00"
    _SIZE = 489
    _FIELDS = (
        _Field("trace_binding", 315, nested=ResearchTraceBinding),
        _Field("issue_backend_pp_sha256", 32, nonzero=True),
        _Field("gf_full_relation_manifest_sha256", 32, nonzero=True),
        _Field("cap_profile_sha256", 32, literal=CAP_PROFILE_SHA256),
        _Field("h_rbbc_profile_sha256", 32, literal=H_RBBC_PROFILE_SHA256),
    )

    @property
    def sha256(self) -> bytes:
        return hashlib.sha256(self.encode()).digest()


@dataclass(frozen=True, repr=False)
class ResearchIssueStatement(_ResearchPacket):
    common_pp_sha256: bytes
    ctx: bytes
    sid: bytes
    rid: bytes
    beta: bytes

    _MAGIC = b"PQ-TH-GF-ISSUE-X\x00"
    _SIZE = 251
    _FIELDS = (
        _Field("common_pp_sha256", 32, nonzero=True), _Field("ctx", 32),
        _Field("sid", 32), _Field("rid", 32), _Field("beta", 72),
    )


@dataclass(frozen=True, repr=False)
class ResearchIssueWitness(_ResearchPacket):
    ticket_m: ResearchTicketM
    blind_mask: bytes
    cap_randomness: bytes
    holder_key: bytes
    trace_u: bytes

    _MAGIC = b"PQ-TH-GF-ISSUE-W\x00"
    _SIZE = 4324
    _FIELDS = (
        _Field("ticket_m", 3005, nested=ResearchTicketM),
        _Field("blind_mask", 72), _Field("cap_randomness", 1036),
        _Field("holder_key", 32), _Field("trace_u", 128),
    )

    def _validate_specific(self) -> None:
        validate_cap_randomness_research(self.cap_randomness)

    def trace_witness_research(self) -> ReferenceWitness:
        self.encode()
        return ReferenceWitness(self.trace_u)


def public_key_record_sha256_research(encoded: bytes) -> bytes:
    """Identity of strict full TB2 pk bytes, not a KeyGen validity certificate."""
    fixed_bytes(encoded, 22590, "GF public-key record")
    key = ReferencePublicKey.decode(encoded)
    if key.encode() != encoded:
        raise ContractError("noncanonical GF public-key record")
    return hashlib.sha256(encoded).digest()
