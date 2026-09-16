"""Operator-owned trust registry for system-governance authentication.

The registry is captured once at service startup.  Request callers never get
to supply a trust anchor, public-key bytes, or a pre-verified flag.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pq_rbbc.contracts.system import KeyReference, KeyRole


TRUST_REGISTRY_FILENAME = "trust-registry-v1.json"
TRUST_REGISTRY_FORMAT = "PQRBBC-SYSTEM-GOVERNANCE-TRUST-REGISTRY-V1"
TRUST_REGISTRY_SCHEMA_VERSION = 1
MLDSA65_STAGING_PROFILE = (
    "PQRBBC-OPENSSL-ML-DSA-65-NON-THRESHOLD-STAGING-V1"
)
TRUSTED_AUTHENTICATION_ROLES = (
    KeyRole.FEDERATION_CONFIGURATION,
    KeyRole.ISSUER_AUTHORIZATION,
)
_MAX_REGISTRY_BYTES = 64 * 1024
_MAX_PUBLIC_KEY_BYTES = 64 * 1024
_SAFE_BASENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class TrustRegistryError(RuntimeError):
    """Raised when operator trust material is unsafe or non-canonical."""


@dataclass(frozen=True)
class TrustedPublicKey:
    """A captured public key and the reference bound to protocol messages."""

    reference: KeyReference
    profile: str
    public_key_der: bytes
    source_filename: str


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TrustRegistryError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def canonical_registry_bytes(document: dict[str, Any]) -> bytes:
    """Encode the exact JSON representation accepted by the loader."""

    return (
        json.dumps(
            document,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def trust_registry_document(entries: tuple[TrustedPublicKey, ...]) -> dict[str, Any]:
    """Return public deployment metadata suitable for canonical serialization."""

    return {
        "entries": [
            {
                "key_id": entry.reference.key_id.hex(),
                "profile": entry.profile,
                "public_key_file": entry.source_filename,
                "public_key_sha256": hashlib.sha256(
                    entry.public_key_der
                ).hexdigest(),
                "role": entry.reference.role.name,
            }
            for entry in entries
        ],
        "format": TRUST_REGISTRY_FORMAT,
        "schema_version": TRUST_REGISTRY_SCHEMA_VERSION,
    }


def _read_bounded(fd: int, maximum: int, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, min(65536, maximum + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise TrustRegistryError(f"{label} exceeds size limit")


def _open_captured_file(directory_fd: int, filename: str, maximum: int) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(filename, flags, dir_fd=directory_fd)
    except OSError as error:
        raise TrustRegistryError(f"cannot safely open {filename}") from error
    try:
        properties = os.fstat(fd)
        if not stat.S_ISREG(properties.st_mode):
            raise TrustRegistryError(f"{filename} is not a regular file")
        if stat.S_IMODE(properties.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
            raise TrustRegistryError(f"{filename} is group/world writable")
        return _read_bounded(fd, maximum, filename)
    finally:
        os.close(fd)


def _decode_hex(value: Any, length: int, label: str) -> bytes:
    if not isinstance(value, str) or len(value) != length * 2:
        raise TrustRegistryError(f"{label} must be lowercase {length}-byte hex")
    if value != value.lower():
        raise TrustRegistryError(f"{label} must be lowercase hex")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise TrustRegistryError(f"{label} is not hexadecimal") from error
    if len(decoded) != length or decoded == bytes(length):
        raise TrustRegistryError(f"{label} is invalid")
    return decoded


class PinnedTrustRegistry:
    """Immutable role-to-public-key mapping loaded through safe file handles."""

    def __init__(self, entries: tuple[TrustedPublicKey, ...]) -> None:
        if tuple(entry.reference.role for entry in entries) != (
            TRUSTED_AUTHENTICATION_ROLES
        ):
            raise TrustRegistryError("authentication roles are incomplete or unordered")
        if any(entry.profile != MLDSA65_STAGING_PROFILE for entry in entries):
            raise TrustRegistryError("unsupported authentication profile")
        key_ids = tuple(entry.reference.key_id for entry in entries)
        digests = tuple(entry.reference.public_key_digest for entry in entries)
        key_bytes = tuple(entry.public_key_der for entry in entries)
        if len(set(key_ids)) != len(key_ids):
            raise TrustRegistryError("authentication key IDs must be distinct")
        if len(set(digests)) != len(digests):
            raise TrustRegistryError("authentication key digests must be distinct")
        if len(set(key_bytes)) != len(key_bytes):
            raise TrustRegistryError("authentication public keys must be distinct")
        self._entries = entries

    @classmethod
    def load(cls, directory: str | os.PathLike[str]) -> "PinnedTrustRegistry":
        path = Path(directory)
        if not path.is_absolute():
            raise TrustRegistryError("trust registry directory must be absolute")
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            directory_fd = os.open(os.fspath(path), flags)
        except OSError as error:
            raise TrustRegistryError("cannot safely open trust registry directory") from error
        try:
            properties = os.fstat(directory_fd)
            if not stat.S_ISDIR(properties.st_mode):
                raise TrustRegistryError("trust registry path is not a directory")
            if stat.S_IMODE(properties.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
                raise TrustRegistryError("trust registry directory is group/world writable")
            encoded = _open_captured_file(
                directory_fd, TRUST_REGISTRY_FILENAME, _MAX_REGISTRY_BYTES
            )
            try:
                document = json.loads(
                    encoded.decode("ascii"), object_pairs_hook=_reject_duplicate_keys
                )
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise TrustRegistryError("trust registry JSON is invalid") from error
            if not isinstance(document, dict):
                raise TrustRegistryError("trust registry must be a JSON object")
            if canonical_registry_bytes(document) != encoded:
                raise TrustRegistryError("trust registry JSON is non-canonical")
            if set(document) != {"entries", "format", "schema_version"}:
                raise TrustRegistryError("trust registry members are not exact")
            if document["format"] != TRUST_REGISTRY_FORMAT:
                raise TrustRegistryError("wrong trust registry format")
            if document["schema_version"] != TRUST_REGISTRY_SCHEMA_VERSION:
                raise TrustRegistryError("unsupported trust registry schema version")
            raw_entries = document["entries"]
            if not isinstance(raw_entries, list) or len(raw_entries) != 2:
                raise TrustRegistryError("trust registry requires exactly two entries")

            entries: list[TrustedPublicKey] = []
            for index, expected_role in enumerate(TRUSTED_AUTHENTICATION_ROLES):
                raw = raw_entries[index]
                if not isinstance(raw, dict) or set(raw) != {
                    "key_id",
                    "profile",
                    "public_key_file",
                    "public_key_sha256",
                    "role",
                }:
                    raise TrustRegistryError("trust registry entry members are not exact")
                if raw["role"] != expected_role.name:
                    raise TrustRegistryError("trust registry roles are unordered or wrong")
                if raw["profile"] != MLDSA65_STAGING_PROFILE:
                    raise TrustRegistryError("unsupported authentication profile")
                filename = raw["public_key_file"]
                if (
                    not isinstance(filename, str)
                    or not _SAFE_BASENAME.fullmatch(filename)
                    or filename in {".", "..", TRUST_REGISTRY_FILENAME}
                ):
                    raise TrustRegistryError("unsafe public-key filename")
                public_key = _open_captured_file(
                    directory_fd, filename, _MAX_PUBLIC_KEY_BYTES
                )
                declared_digest = _decode_hex(
                    raw["public_key_sha256"], 32, "public_key_sha256"
                )
                actual_digest = hashlib.sha256(public_key).digest()
                if not hmac.compare_digest(actual_digest, declared_digest):
                    raise TrustRegistryError("public-key digest mismatch")
                key_id = _decode_hex(raw["key_id"], 32, "key_id")
                entries.append(
                    TrustedPublicKey(
                        reference=KeyReference(
                            role=expected_role,
                            key_id=key_id,
                            public_key_digest=actual_digest,
                        ),
                        profile=raw["profile"],
                        public_key_der=public_key,
                        source_filename=filename,
                    )
                )
            return cls(tuple(entries))
        finally:
            os.close(directory_fd)

    @property
    def entries(self) -> tuple[TrustedPublicKey, ...]:
        return self._entries

    def trusted_key(self, role: KeyRole) -> TrustedPublicKey:
        for entry in self._entries:
            if entry.reference.role is role:
                return entry
        raise TrustRegistryError("role is not an authentication trust anchor")

    def resolve(self, reference: KeyReference) -> TrustedPublicKey:
        """Resolve only an exact, pinned role/key-id/key-digest tuple."""

        if not isinstance(reference, KeyReference):
            raise TrustRegistryError("key reference has wrong type")
        entry = self.trusted_key(reference.role)
        if not hmac.compare_digest(entry.reference.key_id, reference.key_id):
            raise TrustRegistryError("key ID does not match pinned trust")
        if not hmac.compare_digest(
            entry.reference.public_key_digest, reference.public_key_digest
        ):
            raise TrustRegistryError("key digest does not match pinned trust")
        return entry
