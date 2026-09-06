"""Fail-closed verification of an authenticated system-initialization bundle.

Key generation, DKG, and signing are backend responsibilities.  This module
fixes the envelope and verifies an externally produced federation
authentication over the exact canonical public bundle.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol

from pq_rbbc.contracts.system import (
    ContractError,
    KeyReference,
    KeyRole,
    SCHEMA_VERSION,
    SystemInitializationBundle,
    _expect_magic,
    _take,
    _take_uint,
)


AUTHENTICATED_INITIALIZATION_MAGIC = b"PQRBBC-SYSTEM-INIT-AUTH-V1"
INITIALIZATION_AUTH_DOMAIN = b"PQ-RBBC/SYSTEM-INIT-AUTH/V1"
MAX_BUNDLE_BYTES = 1 << 20
MAX_AUTHENTICATION_BYTES = 1 << 20


class ConfigurationAuthenticationVerifier(Protocol):
    """Backend boundary for the future PQ federation authentication scheme."""

    def verify(
        self,
        key: KeyReference,
        message: bytes,
        authentication: bytes,
    ) -> bool: ...


@dataclass(frozen=True)
class AuthenticatedSystemInitialization:
    bundle: SystemInitializationBundle
    authentication: bytes

    @property
    def authentication_message(self) -> bytes:
        return INITIALIZATION_AUTH_DOMAIN + self.bundle.encode()

    def encode(self) -> bytes:
        bundle_bytes = self.bundle.encode()
        if not 0 < len(bundle_bytes) <= MAX_BUNDLE_BYTES:
            raise ContractError("initialization bundle length is outside bounds")
        if not isinstance(self.authentication, bytes) or not (
            0 < len(self.authentication) <= MAX_AUTHENTICATION_BYTES
        ):
            raise ContractError("configuration authentication length is outside bounds")
        return b"".join(
            (
                AUTHENTICATED_INITIALIZATION_MAGIC,
                SCHEMA_VERSION.to_bytes(2, "little"),
                len(bundle_bytes).to_bytes(4, "little"),
                bundle_bytes,
                len(self.authentication).to_bytes(4, "little"),
                self.authentication,
            )
        )

    @classmethod
    def decode(cls, encoded: bytes) -> "AuthenticatedSystemInitialization":
        if not isinstance(encoded, bytes):
            raise ContractError("authenticated initialization must be bytes")
        offset = _expect_magic(
            encoded, 0, AUTHENTICATED_INITIALIZATION_MAGIC, "initialization magic"
        )
        schema_version, offset = _take_uint(
            encoded, offset, 2, "authenticated initialization version"
        )
        if schema_version != SCHEMA_VERSION:
            raise ContractError("wrong authenticated initialization version")
        bundle_length, offset = _take_uint(encoded, offset, 4, "bundle length")
        if not 0 < bundle_length <= MAX_BUNDLE_BYTES:
            raise ContractError("bundle length is outside bounds")
        bundle_bytes, offset = _take(encoded, offset, bundle_length, "bundle")
        authentication_length, offset = _take_uint(
            encoded, offset, 4, "authentication length"
        )
        if not 0 < authentication_length <= MAX_AUTHENTICATION_BYTES:
            raise ContractError("authentication length is outside bounds")
        authentication, offset = _take(
            encoded, offset, authentication_length, "authentication"
        )
        if offset != len(encoded):
            raise ContractError("authenticated initialization trailing bytes")
        envelope = cls(
            bundle=SystemInitializationBundle.decode(bundle_bytes),
            authentication=authentication,
        )
        if envelope.encode() != encoded:
            raise ContractError("authenticated initialization is non-canonical")
        return envelope


@dataclass(frozen=True)
class InitializationVerification:
    accepted: bool
    failures: tuple[str, ...]
    bundle: SystemInitializationBundle | None


def verify_initialization(
    encoded: bytes,
    trusted_configuration_key: KeyReference,
    verifier: ConfigurationAuthenticationVerifier,
) -> InitializationVerification:
    """Strictly parse and authenticate a system initialization publication.

    The federation configuration key is an out-of-band trust anchor.  A key
    reference carried by an untrusted bundle must never be allowed to
    authenticate itself.
    """

    try:
        envelope = AuthenticatedSystemInitialization.decode(encoded)
    except ContractError as error:
        return InitializationVerification(False, (f"encoding:{error}",), None)
    try:
        trusted_configuration_key.validate()
    except ContractError as error:
        return InitializationVerification(
            False, (f"trust_anchor:{error}",), None
        )
    if trusted_configuration_key.role is not KeyRole.FEDERATION_CONFIGURATION:
        return InitializationVerification(
            False, ("trust_anchor:wrong_key_role",), None
        )
    advertised_key = envelope.bundle.key_for(KeyRole.FEDERATION_CONFIGURATION)
    if advertised_key != trusted_configuration_key:
        return InitializationVerification(
            False, ("configuration_trust_anchor_mismatch",), None
        )
    try:
        valid = verifier.verify(
            trusted_configuration_key,
            envelope.authentication_message,
            envelope.authentication,
        )
    except Exception as error:  # Fail closed across an external backend boundary.
        return InitializationVerification(
            False,
            (f"configuration_authentication_backend:{type(error).__name__}",),
            None,
        )
    if valid is not True:
        return InitializationVerification(
            False,
            ("configuration_authentication_invalid",),
            None,
        )
    return InitializationVerification(True, (), envelope.bundle)


def initialization_manifest(
    envelope: AuthenticatedSystemInitialization,
) -> dict[str, object]:
    """Return public, path-free metadata without embedding key or signature bytes."""

    bundle = envelope.bundle
    encoded = envelope.encode()
    return {
        "format": "PQRBBC-SYSTEM-INITIALIZATION-CONTRACT-CHECKPOINT-1",
        "system_profile": "0.1",
        "ctx": bundle.ctx.hex(),
        "configuration_sha256": hashlib.sha256(
            bundle.configuration.encode()
        ).hexdigest(),
        "bundle_bytes": len(bundle.encode()),
        "bundle_sha256": bundle.sha256,
        "authenticated_envelope_bytes": len(encoded),
        "authenticated_envelope_sha256": hashlib.sha256(encoded).hexdigest(),
        "common_parameters_digest": bundle.common_parameters_digest.hex(),
        "federation_threshold": {
            "members": bundle.federation_policy.member_count,
            "threshold": bundle.federation_policy.threshold,
        },
        "opening_threshold": {
            "members": bundle.opening_policy.member_count,
            "threshold": bundle.opening_policy.threshold,
        },
        "key_roles": [reference.role.name for reference in bundle.keys],
        "claim_boundary": {
            "canonical_configuration_codec_implemented": True,
            "canonical_initialization_bundle_codec_implemented": True,
            "explicit_configuration_trust_anchor_required": True,
            "configuration_authentication_backend_abstract": True,
            "fac_threshold_signature_instantiated": False,
            "fac_dkg_implemented": False,
            "opening_dkg_implemented": False,
            "threshold_decoder_implemented": False,
            "production_system_initialized": False,
        },
    }
