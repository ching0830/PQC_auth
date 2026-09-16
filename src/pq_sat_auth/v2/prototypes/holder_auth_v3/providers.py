"""Optional real primitive providers for the D4 measurement prototype.

Imports are lazy so the repository remains usable without third-party PQ
packages.  Provider absence is explicit; no classical or checksum fallback is
permitted.  Both adapters remain experimental and ``production_ready=False``.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from typing import Protocol, runtime_checkable

from .codec import (
    ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_SIGNATURE_BYTES,
    ML_KEM_768_CIPHERTEXT_BYTES,
    ML_KEM_768_PUBLIC_KEY_BYTES,
)


ML_DSA_65_SECRET_KEY_BYTES = 4_032
ML_KEM_768_SECRET_KEY_BYTES = 2_400
ML_KEM_SHARED_SECRET_BYTES = 32


class ProviderUnavailable(RuntimeError):
    """Raised when an explicitly requested experimental provider is absent."""


def _package_version(name: str) -> str:
    try:
        return version(name)
    except PackageNotFoundError as error:
        raise ProviderUnavailable(f"required package {name!r} is not installed") from error


def _exact(value: bytes, size: int, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    return value


@runtime_checkable
class MLDSA65Provider(Protocol):
    name: str
    package: str
    package_version: str
    production_ready: bool

    def generate_keypair(self) -> tuple[bytes, bytes]: ...

    def sign(self, secret_key: bytes, message: bytes) -> bytes: ...

    def verify(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> bool: ...


@runtime_checkable
class MLKEM768Provider(Protocol):
    name: str
    package: str
    package_version: str
    production_ready: bool

    def generate_keypair(self) -> tuple[bytes, bytes]: ...

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]: ...

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes: ...


@dataclass(frozen=True)
class PQCryptoMLDSA65Provider:
    """PQClean-derived ML-DSA-65 exposed by ``pqcrypto``."""

    name: str = "pqcrypto.sign.ml_dsa_65"
    package: str = "pqcrypto"
    production_ready: bool = False

    @property
    def package_version(self) -> str:
        return _package_version(self.package)

    @staticmethod
    def _module():
        try:
            from pqcrypto.sign import ml_dsa_65
        except (ImportError, ModuleNotFoundError) as error:
            raise ProviderUnavailable(
                "pqcrypto ML-DSA-65 provider is unavailable"
            ) from error
        return ml_dsa_65

    def generate_keypair(self) -> tuple[bytes, bytes]:
        public_key, secret_key = self._module().generate_keypair()
        return (
            _exact(public_key, ML_DSA_65_PUBLIC_KEY_BYTES, "ML-DSA public key"),
            _exact(secret_key, ML_DSA_65_SECRET_KEY_BYTES, "ML-DSA secret key"),
        )

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        key = _exact(secret_key, ML_DSA_65_SECRET_KEY_BYTES, "ML-DSA secret key")
        if not isinstance(message, bytes):
            raise TypeError("ML-DSA message must be bytes")
        signature = self._module().sign(key, message)
        return _exact(signature, ML_DSA_65_SIGNATURE_BYTES, "ML-DSA signature")

    def verify(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> bool:
        try:
            key = _exact(
                public_key,
                ML_DSA_65_PUBLIC_KEY_BYTES,
                "ML-DSA public key",
            )
            sig = _exact(signature, ML_DSA_65_SIGNATURE_BYTES, "ML-DSA signature")
            if not isinstance(message, bytes):
                return False
            return self._module().verify(key, message, sig) is True
        except (TypeError, ValueError, RuntimeError, ProviderUnavailable):
            return False


@dataclass(frozen=True)
class DilithiumPyMLDSA65Provider:
    """Pure-Python FIPS 204 experiment provider.

    The implementation is explicitly educational and not constant-time.  The
    public adapter uses the pure ML-DSA API with an empty native context; the
    protocol domain is encoded in the signed message by ``codec.py``.
    """

    name: str = "dilithium_py.ml_dsa.ML_DSA_65"
    package: str = "dilithium-py"
    production_ready: bool = False

    @property
    def package_version(self) -> str:
        return _package_version(self.package)

    @staticmethod
    def _scheme():
        try:
            from dilithium_py.ml_dsa import ML_DSA_65
        except (ImportError, ModuleNotFoundError) as error:
            raise ProviderUnavailable(
                "dilithium-py ML-DSA-65 provider is unavailable"
            ) from error
        return ML_DSA_65

    def generate_keypair(self) -> tuple[bytes, bytes]:
        public_key, secret_key = self._scheme().keygen()
        return (
            _exact(public_key, ML_DSA_65_PUBLIC_KEY_BYTES, "ML-DSA public key"),
            _exact(secret_key, ML_DSA_65_SECRET_KEY_BYTES, "ML-DSA secret key"),
        )

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        key = _exact(secret_key, ML_DSA_65_SECRET_KEY_BYTES, "ML-DSA secret key")
        if not isinstance(message, bytes):
            raise TypeError("ML-DSA message must be bytes")
        signature = self._scheme().sign(key, message, ctx=b"")
        return _exact(signature, ML_DSA_65_SIGNATURE_BYTES, "ML-DSA signature")

    def verify(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> bool:
        try:
            key = _exact(
                public_key,
                ML_DSA_65_PUBLIC_KEY_BYTES,
                "ML-DSA public key",
            )
            sig = _exact(signature, ML_DSA_65_SIGNATURE_BYTES, "ML-DSA signature")
            if not isinstance(message, bytes):
                return False
            return self._scheme().verify(key, message, sig, ctx=b"") is True
        except (TypeError, ValueError, RuntimeError, ProviderUnavailable):
            return False

    def verify_with_context(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
        context: bytes,
    ) -> bool:
        """Expose the FIPS context API solely for official-vector checking."""

        try:
            key = _exact(
                public_key,
                ML_DSA_65_PUBLIC_KEY_BYTES,
                "ML-DSA public key",
            )
            sig = _exact(signature, ML_DSA_65_SIGNATURE_BYTES, "ML-DSA signature")
            if not isinstance(message, bytes) or not isinstance(context, bytes):
                return False
            return self._scheme().verify(key, message, sig, ctx=context) is True
        except (TypeError, ValueError, RuntimeError, ProviderUnavailable):
            return False


@dataclass(frozen=True)
class PQCryptoMLKEM768Provider:
    """PQClean-derived ML-KEM-768 exposed by ``pqcrypto``."""

    name: str = "pqcrypto.kem.ml_kem_768"
    package: str = "pqcrypto"
    production_ready: bool = False

    @property
    def package_version(self) -> str:
        return _package_version(self.package)

    @staticmethod
    def _module():
        try:
            from pqcrypto.kem import ml_kem_768
        except (ImportError, ModuleNotFoundError) as error:
            raise ProviderUnavailable(
                "pqcrypto ML-KEM-768 provider is unavailable"
            ) from error
        return ml_kem_768

    def generate_keypair(self) -> tuple[bytes, bytes]:
        public_key, secret_key = self._module().generate_keypair()
        return (
            _exact(public_key, ML_KEM_768_PUBLIC_KEY_BYTES, "ML-KEM public key"),
            _exact(secret_key, ML_KEM_768_SECRET_KEY_BYTES, "ML-KEM secret key"),
        )

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        key = _exact(public_key, ML_KEM_768_PUBLIC_KEY_BYTES, "ML-KEM public key")
        ciphertext, shared_secret = self._module().encrypt(key)
        return (
            _exact(ciphertext, ML_KEM_768_CIPHERTEXT_BYTES, "ML-KEM ciphertext"),
            _exact(shared_secret, ML_KEM_SHARED_SECRET_BYTES, "shared secret"),
        )

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        key = _exact(secret_key, ML_KEM_768_SECRET_KEY_BYTES, "ML-KEM secret key")
        encapsulation = _exact(
            ciphertext,
            ML_KEM_768_CIPHERTEXT_BYTES,
            "ML-KEM ciphertext",
        )
        return _exact(
            self._module().decrypt(key, encapsulation),
            ML_KEM_SHARED_SECRET_BYTES,
            "shared secret",
        )
