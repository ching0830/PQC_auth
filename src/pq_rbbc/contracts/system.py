"""Canonical system-initialization contracts for system profile v0.1.

This module fixes public byte encodings and cross-module role separation.  It
does not generate keys, run a DKG, or instantiate a threshold signature or
threshold decryption scheme.  Those cryptographic backends remain explicit
inputs to the system-initialization ceremony.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import IntEnum


CONFIG_MAGIC = b"PQRBBC-SYSTEM-CONFIG-V1"
SYSTEM_BUNDLE_MAGIC = b"PQRBBC-SYSTEM-INIT-BUNDLE-V1"
SCHEMA_VERSION = 1
SYSTEM_PROFILE_PROTOCOL_VERSION = 1
CONTEXT_DOMAIN = b"PQ-RBBC/CTX"
CONTEXT_BYTES = 32
IDENTIFIER_BYTES = 32
KEY_ID_BYTES = IDENTIFIER_BYTES
PUBLIC_KEY_DIGEST_BYTES = 32
COMMON_PARAMETERS_DIGEST_BYTES = 32


class ContractError(ValueError):
    """Raised when a cross-module byte contract is non-canonical or invalid."""


class KeyRole(IntEnum):
    """Separated public-key roles in the system-initialization bundle."""

    FEDERATION_CONFIGURATION = 1
    ISSUER_AUTHORIZATION = 2
    OPENING_AUTHORIZATION = 3
    ISSUER_VERIFICATION = 4
    OPENING_ENCRYPTION = 5


KEY_ROLE_ORDER = tuple(KeyRole)


def _require_uint(value: int, width: int, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ContractError(f"{label} must be an integer")
    maximum = (1 << (8 * width)) - 1
    if not 0 <= value <= maximum:
        raise ContractError(f"{label} is outside u{8 * width}")


def _require_fixed_bytes(value: bytes, length: int, label: str) -> None:
    if not isinstance(value, bytes) or len(value) != length:
        raise ContractError(f"{label} must be exactly {length} bytes")


def _require_identifier(value: bytes, label: str) -> None:
    _require_fixed_bytes(value, IDENTIFIER_BYTES, label)
    if value == bytes(IDENTIFIER_BYTES):
        raise ContractError(f"{label} must not be all zero")


def _take(encoded: bytes, offset: int, length: int, label: str) -> tuple[bytes, int]:
    if length < 0 or offset + length > len(encoded):
        raise ContractError(f"{label} truncated")
    return encoded[offset : offset + length], offset + length


def _take_uint(
    encoded: bytes, offset: int, length: int, label: str
) -> tuple[int, int]:
    raw, offset = _take(encoded, offset, length, label)
    return int.from_bytes(raw, "little"), offset


def _expect_magic(encoded: bytes, offset: int, magic: bytes, label: str) -> int:
    raw, offset = _take(encoded, offset, len(magic), label)
    if raw != magic:
        raise ContractError(f"wrong {label}")
    return offset


@dataclass(frozen=True)
class SystemConfiguration:
    """Federation-wide common information used to derive the 32-byte ``ctx``.

    ``domain`` and ``policy_digest`` are fixed-size federation values.  They
    must be common to the intended anonymity set and must not contain
    per-holder metadata.
    """

    protocol_version: int
    epoch: int
    domain: bytes
    policy_digest: bytes
    expiry_bucket: int
    oa_key_id: bytes
    issuer_key_id: bytes

    def validate(self) -> None:
        _require_uint(self.protocol_version, 2, "protocol_version")
        if self.protocol_version != SYSTEM_PROFILE_PROTOCOL_VERSION:
            raise ContractError("unsupported system profile protocol_version")
        _require_uint(self.epoch, 8, "epoch")
        _require_identifier(self.domain, "domain")
        _require_identifier(self.policy_digest, "policy_digest")
        _require_uint(self.expiry_bucket, 8, "expiry_bucket")
        _require_identifier(self.oa_key_id, "oa_key_id")
        _require_identifier(self.issuer_key_id, "issuer_key_id")

    def encode(self) -> bytes:
        self.validate()
        return b"".join(
            (
                CONFIG_MAGIC,
                SCHEMA_VERSION.to_bytes(2, "little"),
                self.protocol_version.to_bytes(2, "little"),
                self.epoch.to_bytes(8, "little"),
                self.domain,
                self.policy_digest,
                self.expiry_bucket.to_bytes(8, "little"),
                self.oa_key_id,
                self.issuer_key_id,
            )
        )

    @classmethod
    def decode(cls, encoded: bytes) -> "SystemConfiguration":
        if not isinstance(encoded, bytes):
            raise ContractError("configuration encoding must be bytes")
        offset = _expect_magic(encoded, 0, CONFIG_MAGIC, "configuration magic")
        schema_version, offset = _take_uint(
            encoded, offset, 2, "configuration schema version"
        )
        if schema_version != SCHEMA_VERSION:
            raise ContractError("wrong configuration schema version")
        protocol_version, offset = _take_uint(
            encoded, offset, 2, "configuration protocol version"
        )
        epoch, offset = _take_uint(encoded, offset, 8, "configuration epoch")
        domain, offset = _take(encoded, offset, IDENTIFIER_BYTES, "configuration domain")
        policy_digest, offset = _take(
            encoded, offset, IDENTIFIER_BYTES, "configuration policy digest"
        )
        expiry_bucket, offset = _take_uint(
            encoded, offset, 8, "configuration expiry bucket"
        )
        oa_key_id, offset = _take(
            encoded, offset, KEY_ID_BYTES, "configuration OA key ID"
        )
        issuer_key_id, offset = _take(
            encoded, offset, KEY_ID_BYTES, "configuration issuer key ID"
        )
        if offset != len(encoded):
            raise ContractError("configuration trailing bytes")
        configuration = cls(
            protocol_version=protocol_version,
            epoch=epoch,
            domain=domain,
            policy_digest=policy_digest,
            expiry_bucket=expiry_bucket,
            oa_key_id=oa_key_id,
            issuer_key_id=issuer_key_id,
        )
        configuration.validate()
        if configuration.encode() != encoded:
            raise ContractError("configuration encoding is non-canonical")
        return configuration

    @property
    def ctx(self) -> bytes:
        return hashlib.shake_256(CONTEXT_DOMAIN + self.encode()).digest(
            CONTEXT_BYTES
        )


@dataclass(frozen=True)
class KeyReference:
    """Public identity of a key produced by an external key ceremony."""

    role: KeyRole
    key_id: bytes
    public_key_digest: bytes

    def validate(self) -> None:
        if not isinstance(self.role, KeyRole):
            raise ContractError("key role must be a KeyRole")
        _require_identifier(self.key_id, f"{self.role.name} key_id")
        _require_identifier(
            self.public_key_digest, f"{self.role.name} public_key_digest"
        )

    def encode(self) -> bytes:
        self.validate()
        return b"".join(
            (
                int(self.role).to_bytes(2, "little"),
                self.key_id,
                self.public_key_digest,
            )
        )

    @classmethod
    def decode(cls, encoded: bytes) -> "KeyReference":
        expected = 2 + KEY_ID_BYTES + PUBLIC_KEY_DIGEST_BYTES
        if not isinstance(encoded, bytes) or len(encoded) != expected:
            raise ContractError(f"key reference must be exactly {expected} bytes")
        role_value = int.from_bytes(encoded[:2], "little")
        try:
            role = KeyRole(role_value)
        except ValueError as error:
            raise ContractError("unknown key role") from error
        reference = cls(
            role=role,
            key_id=encoded[2 : 2 + KEY_ID_BYTES],
            public_key_digest=encoded[2 + KEY_ID_BYTES :],
        )
        reference.validate()
        return reference


@dataclass(frozen=True)
class ThresholdPolicy:
    member_count: int
    threshold: int

    def validate(self, label: str) -> None:
        _require_uint(self.member_count, 2, f"{label} member_count")
        _require_uint(self.threshold, 2, f"{label} threshold")
        if self.member_count == 0:
            raise ContractError(f"{label} member_count must be nonzero")
        if not 1 <= self.threshold <= self.member_count:
            raise ContractError(f"{label} threshold must be within member_count")

    def encode(self, label: str) -> bytes:
        self.validate(label)
        return self.member_count.to_bytes(2, "little") + self.threshold.to_bytes(
            2, "little"
        )


@dataclass(frozen=True)
class SystemInitializationBundle:
    """Canonical public output of external key-generation ceremonies.

    The bundle contains only public references and digests.  It deliberately
    contains no issuer secret key, OA share, FAC share, DKG transcript secret,
    or proof-system trapdoor.
    """

    configuration: SystemConfiguration
    common_parameters_digest: bytes
    federation_policy: ThresholdPolicy
    opening_policy: ThresholdPolicy
    keys: tuple[KeyReference, ...]

    def validate(self) -> None:
        self.configuration.validate()
        _require_identifier(
            self.common_parameters_digest, "common_parameters_digest"
        )
        self.federation_policy.validate("federation_policy")
        self.opening_policy.validate("opening_policy")
        if tuple(reference.role for reference in self.keys) != KEY_ROLE_ORDER:
            raise ContractError("keys must contain every role once in canonical order")
        for reference in self.keys:
            reference.validate()
        key_ids = tuple(reference.key_id for reference in self.keys)
        if len(set(key_ids)) != len(key_ids):
            raise ContractError("key IDs must be distinct across roles")
        key_digests = tuple(reference.public_key_digest for reference in self.keys)
        if len(set(key_digests)) != len(key_digests):
            raise ContractError("public key digests must be distinct across roles")
        if self.configuration.issuer_key_id != self.key_for(
            KeyRole.ISSUER_VERIFICATION
        ).key_id:
            raise ContractError("configuration issuer key ID mismatch")
        if self.configuration.oa_key_id != self.key_for(
            KeyRole.OPENING_ENCRYPTION
        ).key_id:
            raise ContractError("configuration OA key ID mismatch")

    def key_for(self, role: KeyRole) -> KeyReference:
        for reference in self.keys:
            if reference.role is role:
                return reference
        raise ContractError(f"missing key role {role.name}")

    @property
    def ctx(self) -> bytes:
        return self.configuration.ctx

    def encode(self) -> bytes:
        self.validate()
        configuration_bytes = self.configuration.encode()
        result = bytearray(SYSTEM_BUNDLE_MAGIC)
        result.extend(SCHEMA_VERSION.to_bytes(2, "little"))
        result.extend(len(configuration_bytes).to_bytes(4, "little"))
        result.extend(configuration_bytes)
        result.extend(self.ctx)
        result.extend(self.common_parameters_digest)
        result.extend(self.federation_policy.encode("federation_policy"))
        result.extend(self.opening_policy.encode("opening_policy"))
        result.extend(len(self.keys).to_bytes(2, "little"))
        for reference in self.keys:
            result.extend(reference.encode())
        return bytes(result)

    @classmethod
    def decode(cls, encoded: bytes) -> "SystemInitializationBundle":
        if not isinstance(encoded, bytes):
            raise ContractError("initialization bundle must be bytes")
        offset = _expect_magic(encoded, 0, SYSTEM_BUNDLE_MAGIC, "bundle magic")
        schema_version, offset = _take_uint(encoded, offset, 2, "bundle version")
        if schema_version != SCHEMA_VERSION:
            raise ContractError("wrong bundle schema version")
        configuration_length, offset = _take_uint(
            encoded, offset, 4, "configuration length"
        )
        configuration_bytes, offset = _take(
            encoded, offset, configuration_length, "configuration"
        )
        configuration = SystemConfiguration.decode(configuration_bytes)
        encoded_ctx, offset = _take(encoded, offset, CONTEXT_BYTES, "ctx")
        common_parameters_digest, offset = _take(
            encoded,
            offset,
            COMMON_PARAMETERS_DIGEST_BYTES,
            "common parameters digest",
        )
        federation_members, offset = _take_uint(
            encoded, offset, 2, "federation member count"
        )
        federation_threshold, offset = _take_uint(
            encoded, offset, 2, "federation threshold"
        )
        opening_members, offset = _take_uint(
            encoded, offset, 2, "opening member count"
        )
        opening_threshold, offset = _take_uint(
            encoded, offset, 2, "opening threshold"
        )
        key_count, offset = _take_uint(encoded, offset, 2, "key count")
        keys: list[KeyReference] = []
        key_bytes = 2 + KEY_ID_BYTES + PUBLIC_KEY_DIGEST_BYTES
        for index in range(key_count):
            raw, offset = _take(encoded, offset, key_bytes, f"key reference {index}")
            keys.append(KeyReference.decode(raw))
        if offset != len(encoded):
            raise ContractError("initialization bundle trailing bytes")
        if encoded_ctx != configuration.ctx:
            raise ContractError("initialization bundle ctx mismatch")
        bundle = cls(
            configuration=configuration,
            common_parameters_digest=common_parameters_digest,
            federation_policy=ThresholdPolicy(
                member_count=federation_members,
                threshold=federation_threshold,
            ),
            opening_policy=ThresholdPolicy(
                member_count=opening_members,
                threshold=opening_threshold,
            ),
            keys=tuple(keys),
        )
        bundle.validate()
        if bundle.encode() != encoded:
            raise ContractError("initialization bundle encoding is non-canonical")
        return bundle

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.encode()).hexdigest()
