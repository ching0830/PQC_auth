"""Pinned real-cryptography providers for the PQ-SAT V3 measurement profile.

The adapters in this module are deliberately narrow.  They expose only the
algorithms and parameter sets frozen by the V3 P0 contract, reject version or
length drift, and never substitute a checksum, classical signature, or fake
KEM.  All providers remain measurement-only and are not production-qualified.
"""

from __future__ import annotations

import hashlib
import hmac
import platform
from dataclasses import dataclass
from enum import Enum
from importlib.metadata import PackageNotFoundError, version
from typing import Protocol, runtime_checkable


ML_DSA_65_PUBLIC_KEY_BYTES = 1_952
ML_DSA_65_SECRET_KEY_BYTES = 4_032
ML_DSA_65_SIGNATURE_BYTES = 3_309
ML_DSA_NATIVE_CONTEXT_MAX_BYTES = 255

ML_KEM_768_PUBLIC_KEY_BYTES = 1_184
ML_KEM_768_SECRET_KEY_BYTES = 2_400
ML_KEM_768_CIPHERTEXT_BYTES = 1_088
ML_KEM_SHARED_SECRET_BYTES = 32

SHA384_BYTES = 48

DILITHIUM_PY_VERSION = "1.4.0"
PQCRYPTO_VERSION = "0.3.3"


class ProviderClaim(str, Enum):
    """The strongest claim carried by a provider descriptor."""

    MEASUREMENT_ONLY = "measurement-only"
    INTEROPERABLE = "interoperable"
    QUALIFIED = "qualified"


class NativeContextCapability(str, Enum):
    """How a provider handles the FIPS 204 native context parameter."""

    NON_EMPTY = "non-empty-native-context"
    UNSUPPORTED = "unsupported"
    NOT_APPLICABLE = "not-applicable"


@dataclass(frozen=True)
class ProviderDescriptor:
    """Public, non-secret provider identity and capability metadata."""

    provider_id: str
    algorithm: str
    parameter_set: str
    package: str
    package_version: str
    native_context_capability: NativeContextCapability
    claim: ProviderClaim
    constant_time: bool | None
    production_qualified: bool
    public_key_bytes: int | None = None
    secret_key_bytes: int | None = None
    signature_bytes: int | None = None
    ciphertext_bytes: int | None = None
    shared_secret_bytes: int | None = None
    digest_bytes: int | None = None


class CryptoProviderError(RuntimeError):
    """Base class for fail-closed provider errors with non-secret messages."""


class ProviderUnavailable(CryptoProviderError):
    """Raised when a pinned package is absent or has the wrong version."""


class ProviderCapabilityError(CryptoProviderError):
    """Raised when a provider cannot implement the frozen V3 profile."""


class InvalidCryptoInput(CryptoProviderError):
    """Raised for type or length errors without echoing input material."""


class CryptoOperationError(CryptoProviderError):
    """Raised when a real provider operation fails."""


class DecapsulationError(CryptoOperationError):
    """Raised when ML-KEM decapsulation cannot be executed."""


def _installed_exact(package: str, expected: str) -> str:
    try:
        installed = version(package)
    except PackageNotFoundError:
        raise ProviderUnavailable("required cryptographic package is unavailable") from None
    if installed != expected:
        raise ProviderUnavailable("cryptographic package version does not match profile")
    return installed


def _exact_bytes(value: bytes, size: int, label: str) -> bytes:
    if not isinstance(value, bytes):
        raise InvalidCryptoInput(f"{label} must be bytes")
    if len(value) != size:
        raise InvalidCryptoInput(f"{label} has invalid length")
    return value


def _message(value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise InvalidCryptoInput("message must be bytes")
    if not value:
        raise InvalidCryptoInput("message must be non-empty")
    return value


def _native_context(value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise InvalidCryptoInput("native context must be bytes")
    if not 1 <= len(value) <= ML_DSA_NATIVE_CONTEXT_MAX_BYTES:
        raise ProviderCapabilityError(
            "profile requires a non-empty FIPS 204 native context"
        )
    return value


@runtime_checkable
class MLDSA65Provider(Protocol):
    @property
    def descriptor(self) -> ProviderDescriptor: ...

    def generate_keypair(self) -> tuple[bytes, bytes]: ...

    def sign(self, secret_key: bytes, message: bytes, context: bytes) -> bytes: ...

    def verify(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
        context: bytes,
    ) -> bool: ...


@runtime_checkable
class MLKEM768Provider(Protocol):
    @property
    def descriptor(self) -> ProviderDescriptor: ...

    def generate_keypair(self) -> tuple[bytes, bytes]: ...

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]: ...

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes: ...


@runtime_checkable
class SHA384Provider(Protocol):
    @property
    def descriptor(self) -> ProviderDescriptor: ...

    def hmac_digest(self, key: bytes, message: bytes) -> bytes: ...


@dataclass(frozen=True)
class DilithiumPyMLDSA65Provider:
    """Research-only ML-DSA-65 provider with real native-context support.

    ``dilithium-py`` describes itself as educational; it is not constant-time
    and has not been qualified for production use by this project.
    """

    @staticmethod
    def _scheme():
        _installed_exact("dilithium-py", DILITHIUM_PY_VERSION)
        try:
            from dilithium_py.ml_dsa import ML_DSA_65
        except (ImportError, ModuleNotFoundError):
            raise ProviderUnavailable(
                "required cryptographic package is unavailable"
            ) from None
        return ML_DSA_65

    @property
    def descriptor(self) -> ProviderDescriptor:
        return ProviderDescriptor(
            provider_id="dilithium_py.ml_dsa.ML_DSA_65",
            algorithm="ML-DSA",
            parameter_set="ML-DSA-65",
            package="dilithium-py",
            package_version=_installed_exact(
                "dilithium-py", DILITHIUM_PY_VERSION
            ),
            native_context_capability=NativeContextCapability.NON_EMPTY,
            claim=ProviderClaim.MEASUREMENT_ONLY,
            constant_time=False,
            production_qualified=False,
            public_key_bytes=ML_DSA_65_PUBLIC_KEY_BYTES,
            secret_key_bytes=ML_DSA_65_SECRET_KEY_BYTES,
            signature_bytes=ML_DSA_65_SIGNATURE_BYTES,
        )

    def generate_keypair(self) -> tuple[bytes, bytes]:
        try:
            public_key, secret_key = self._scheme().keygen()
        except Exception:
            raise CryptoOperationError("ML-DSA key generation failed") from None
        return (
            _exact_bytes(
                public_key, ML_DSA_65_PUBLIC_KEY_BYTES, "ML-DSA public key"
            ),
            _exact_bytes(
                secret_key, ML_DSA_65_SECRET_KEY_BYTES, "ML-DSA secret key"
            ),
        )

    def sign(self, secret_key: bytes, message: bytes, context: bytes) -> bytes:
        key = _exact_bytes(
            secret_key, ML_DSA_65_SECRET_KEY_BYTES, "ML-DSA secret key"
        )
        payload = _message(message)
        native_context = _native_context(context)
        try:
            signature = self._scheme().sign(key, payload, ctx=native_context)
        except Exception:
            raise CryptoOperationError("ML-DSA signing failed") from None
        return _exact_bytes(
            signature, ML_DSA_65_SIGNATURE_BYTES, "ML-DSA signature"
        )

    def verify(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
        context: bytes,
    ) -> bool:
        try:
            key = _exact_bytes(
                public_key, ML_DSA_65_PUBLIC_KEY_BYTES, "ML-DSA public key"
            )
            payload = _message(message)
            sig = _exact_bytes(
                signature, ML_DSA_65_SIGNATURE_BYTES, "ML-DSA signature"
            )
            native_context = _native_context(context)
            return self._scheme().verify(
                key, payload, sig, ctx=native_context
            ) is True
        except Exception:
            return False


@dataclass(frozen=True)
class PQCryptoMLKEM768Provider:
    """Pinned pqcrypto ML-KEM-768 provider for bounded measurement."""

    @staticmethod
    def _module():
        _installed_exact("pqcrypto", PQCRYPTO_VERSION)
        try:
            from pqcrypto.kem import ml_kem_768
        except (ImportError, ModuleNotFoundError):
            raise ProviderUnavailable(
                "required cryptographic package is unavailable"
            ) from None
        return ml_kem_768

    @property
    def descriptor(self) -> ProviderDescriptor:
        return ProviderDescriptor(
            provider_id="pqcrypto.kem.ml_kem_768",
            algorithm="ML-KEM",
            parameter_set="ML-KEM-768",
            package="pqcrypto",
            package_version=_installed_exact("pqcrypto", PQCRYPTO_VERSION),
            native_context_capability=NativeContextCapability.NOT_APPLICABLE,
            claim=ProviderClaim.MEASUREMENT_ONLY,
            constant_time=None,
            production_qualified=False,
            public_key_bytes=ML_KEM_768_PUBLIC_KEY_BYTES,
            secret_key_bytes=ML_KEM_768_SECRET_KEY_BYTES,
            ciphertext_bytes=ML_KEM_768_CIPHERTEXT_BYTES,
            shared_secret_bytes=ML_KEM_SHARED_SECRET_BYTES,
        )

    def generate_keypair(self) -> tuple[bytes, bytes]:
        try:
            public_key, secret_key = self._module().generate_keypair()
        except Exception:
            raise CryptoOperationError("ML-KEM key generation failed") from None
        return (
            _exact_bytes(
                public_key, ML_KEM_768_PUBLIC_KEY_BYTES, "ML-KEM public key"
            ),
            _exact_bytes(
                secret_key, ML_KEM_768_SECRET_KEY_BYTES, "ML-KEM secret key"
            ),
        )

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        key = _exact_bytes(
            public_key, ML_KEM_768_PUBLIC_KEY_BYTES, "ML-KEM public key"
        )
        try:
            ciphertext, shared_secret = self._module().encrypt(key)
        except Exception:
            raise CryptoOperationError("ML-KEM encapsulation failed") from None
        return (
            _exact_bytes(
                ciphertext,
                ML_KEM_768_CIPHERTEXT_BYTES,
                "ML-KEM ciphertext",
            ),
            _exact_bytes(
                shared_secret, ML_KEM_SHARED_SECRET_BYTES, "shared secret"
            ),
        )

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        key = _exact_bytes(
            secret_key, ML_KEM_768_SECRET_KEY_BYTES, "ML-KEM secret key"
        )
        encapsulation = _exact_bytes(
            ciphertext,
            ML_KEM_768_CIPHERTEXT_BYTES,
            "ML-KEM ciphertext",
        )
        try:
            shared_secret = self._module().decrypt(key, encapsulation)
        except Exception:
            raise DecapsulationError("ML-KEM decapsulation failed") from None
        return _exact_bytes(
            shared_secret, ML_KEM_SHARED_SECRET_BYTES, "shared secret"
        )


@dataclass(frozen=True)
class PythonStdlibSHA384Provider:
    """CPython stdlib HMAC-SHA384 used by the exact V3 key schedule."""

    @property
    def descriptor(self) -> ProviderDescriptor:
        return ProviderDescriptor(
            provider_id="python.hmac+hashlib.sha384",
            algorithm="HKDF/HMAC",
            parameter_set="SHA-384",
            package=f"{platform.python_implementation()} stdlib",
            package_version=platform.python_version(),
            native_context_capability=NativeContextCapability.NOT_APPLICABLE,
            claim=ProviderClaim.INTEROPERABLE,
            constant_time=None,
            production_qualified=False,
            digest_bytes=SHA384_BYTES,
        )

    def hmac_digest(self, key: bytes, message: bytes) -> bytes:
        if not isinstance(key, bytes) or not key:
            raise InvalidCryptoInput("HMAC key must be non-empty bytes")
        if not isinstance(message, bytes):
            raise InvalidCryptoInput("HMAC message must be bytes")
        return hmac.new(key, message, hashlib.sha384).digest()
