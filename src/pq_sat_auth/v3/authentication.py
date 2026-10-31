"""Exact holder/FGS ML-DSA authentication for the PQ-SAT V3 ABI."""

from __future__ import annotations

import hashlib
from enum import Enum

from .providers import (
    ML_DSA_65_PUBLIC_KEY_BYTES,
    MLDSA65Provider,
    NativeContextCapability,
    ProviderCapabilityError,
)


HASH_DOMAIN = b"PQSAT/HASH/v3"
CONTEXT_BYTES = 32
HOLDER_BINDING_BYTES = 48
TRANSCRIPT_HASH_BYTES = 48

HOLDER_CONTEXT_LABEL = b"PQSAT/HOLDER/v3"
FGS_CONTEXT_LABEL = b"PQSAT/FGS/v3"


class SignatureRole(str, Enum):
    HOLDER = "holder"
    FGS = "fgs"


class HashV3Label(Enum):
    BIND = (b"bind", 48)
    TICKET = (b"ticket", 32)
    ATTEMPT = (b"attempt", 32)
    SID = (b"sid", 32)
    TRANSCRIPT = (b"transcript", 48)

    @property
    def encoded(self) -> bytes:
        return self.value[0]

    @property
    def output_bytes(self) -> int:
        return self.value[1]


def _exact_bytes(value: bytes, size: int, label: str) -> bytes:
    if not isinstance(value, bytes):
        raise ValueError(f"{label} must be bytes")
    if len(value) != size:
        raise ValueError(f"{label} has invalid length")
    return value


def _core_message(value: bytes) -> bytes:
    if not isinstance(value, bytes) or not value:
        raise ValueError("signature core must be non-empty bytes")
    return value


def hash_v3(label: HashV3Label, ctx: bytes, data: bytes) -> bytes:
    """Compute the frozen, length-delimited P0 ``HashV3`` construction."""

    if not isinstance(label, HashV3Label):
        raise ValueError("hash label is not a frozen V3 label")
    configuration_context = _exact_bytes(ctx, CONTEXT_BYTES, "ctx")
    if not isinstance(data, bytes):
        raise ValueError("hash input must be bytes")
    encoded_label = label.encoded
    preimage = b"".join(
        (
            HASH_DOMAIN,
            len(encoded_label).to_bytes(2, "big"),
            encoded_label,
            configuration_context,
            len(data).to_bytes(8, "big"),
            data,
        )
    )
    return hashlib.shake_256(preimage).digest(label.output_bytes)


def holder_public_key_binding(ctx: bytes, public_key: bytes) -> bytes:
    """Return ``q = HashV3('bind', ctx, pk_H, 48)``."""

    key = _exact_bytes(
        public_key, ML_DSA_65_PUBLIC_KEY_BYTES, "ML-DSA public key"
    )
    return hash_v3(HashV3Label.BIND, ctx, key)


def native_signature_context(role: SignatureRole, ctx: bytes) -> bytes:
    """Build the exact FIPS 204 native context for one signature role."""

    configuration_context = _exact_bytes(ctx, CONTEXT_BYTES, "ctx")
    if role is SignatureRole.HOLDER:
        return HOLDER_CONTEXT_LABEL + configuration_context
    if role is SignatureRole.FGS:
        return FGS_CONTEXT_LABEL + configuration_context
    raise ValueError("signature role is invalid")


def _require_provider(provider: MLDSA65Provider) -> None:
    descriptor = provider.descriptor
    if descriptor.algorithm != "ML-DSA" or descriptor.parameter_set != "ML-DSA-65":
        raise ProviderCapabilityError("provider does not implement ML-DSA-65")
    if (
        descriptor.native_context_capability
        is not NativeContextCapability.NON_EMPTY
    ):
        raise ProviderCapabilityError(
            "profile requires non-empty native-context capability"
        )


def sign_for_role(
    provider: MLDSA65Provider,
    role: SignatureRole,
    secret_key: bytes,
    ctx: bytes,
    message: bytes,
) -> bytes:
    """Sign the unmodified core under the exact role-specific native context."""

    _require_provider(provider)
    payload = _core_message(message)
    context = native_signature_context(role, ctx)
    return provider.sign(secret_key, payload, context)


def verify_for_role(
    provider: MLDSA65Provider,
    role: SignatureRole,
    public_key: bytes,
    ctx: bytes,
    message: bytes,
    signature: bytes,
) -> bool:
    """Fail closed on provider, role, context, key, message, or signature drift."""

    try:
        _require_provider(provider)
        payload = _core_message(message)
        context = native_signature_context(role, ctx)
        return provider.verify(public_key, payload, signature, context)
    except Exception:
        return False
