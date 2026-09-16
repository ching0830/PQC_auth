"""Optional real primitive providers for the D4 measurement prototype.

Imports are lazy so the repository remains usable without third-party PQ
packages.  Provider absence is explicit; no classical or checksum fallback is
permitted.  Both adapters remain experimental and ``production_ready=False``.
"""

from __future__ import annotations

import ctypes
import hashlib
from dataclasses import dataclass
from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Protocol, runtime_checkable

from .codec import (
    FAEST_192S_PRIVATE_KEY_BYTES,
    FAEST_192S_PUBLIC_KEY_BYTES,
    FAEST_192S_SIGNATURE_BYTES,
    ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_SIGNATURE_BYTES,
    ML_KEM_768_CIPHERTEXT_BYTES,
    ML_KEM_768_PUBLIC_KEY_BYTES,
)


ML_DSA_65_SECRET_KEY_BYTES = 4_032
ML_KEM_768_SECRET_KEY_BYTES = 2_400
ML_KEM_SHARED_SECRET_BYTES = 32
FAEST_REFERENCE_VERSION = "3.0.0"
FAEST_REFERENCE_COMMIT = "9236611c42d1a761a58a44cabef7aeedd40d85bb"


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


def _ctypes_bytes(value: bytes):
    if not isinstance(value, bytes):
        raise TypeError("native provider input must be bytes")
    if not value:
        return (ctypes.c_uint8 * 1)()
    return (ctypes.c_uint8 * len(value)).from_buffer_copy(value)


@lru_cache(maxsize=4)
def _load_faest_reference_library(
    library_path: str,
    expected_sha256: str,
) -> ctypes.CDLL:
    path = Path(library_path)
    if not path.is_absolute():
        raise ProviderUnavailable("FAEST library path must be absolute")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ProviderUnavailable("FAEST reference library is unavailable") from error
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if actual_sha256 != expected_sha256:
        raise ProviderUnavailable("FAEST reference library SHA-256 mismatch")
    try:
        library = ctypes.CDLL(str(path))
    except OSError as error:
        raise ProviderUnavailable("FAEST reference library cannot be loaded") from error

    pointer = ctypes.POINTER(ctypes.c_uint8)
    library.faest_192s_keygen.argtypes = [pointer, pointer]
    library.faest_192s_keygen.restype = ctypes.c_int
    library.faest_192s_sign.argtypes = [
        pointer,
        pointer,
        ctypes.c_size_t,
        pointer,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    library.faest_192s_sign.restype = ctypes.c_int
    library.faest_192s_verify.argtypes = [
        pointer,
        pointer,
        ctypes.c_size_t,
        pointer,
        ctypes.c_size_t,
    ]
    library.faest_192s_verify.restype = ctypes.c_int
    return library


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
class FAEST192sReferenceProvider:
    """Pinned FAEST v3 reference implementation loaded from an external build.

    The shared library is deliberately not bundled.  Callers must provide an
    absolute path and its exact SHA-256 identity.  The provider is a research
    measurement adapter, not a production-qualified cryptographic module.
    """

    library_path: str
    library_sha256: str
    name: str = "faest-ref/faest_192s"
    package: str = "faest-ref"
    source_commit: str = FAEST_REFERENCE_COMMIT
    production_ready: bool = False

    def __post_init__(self) -> None:
        if len(self.library_sha256) != 64:
            raise ValueError("FAEST library SHA-256 must be 64 hex characters")
        try:
            bytes.fromhex(self.library_sha256)
        except ValueError as error:
            raise ValueError("FAEST library SHA-256 must be hexadecimal") from error
        if self.source_commit != FAEST_REFERENCE_COMMIT:
            raise ValueError("FAEST source commit does not match the frozen D4b revision")

    @property
    def package_version(self) -> str:
        return f"{FAEST_REFERENCE_VERSION}+{self.source_commit}"

    def _library(self) -> ctypes.CDLL:
        return _load_faest_reference_library(
            self.library_path,
            self.library_sha256,
        )

    def generate_keypair(self) -> tuple[bytes, bytes]:
        public_key = (ctypes.c_uint8 * FAEST_192S_PUBLIC_KEY_BYTES)()
        secret_key = (ctypes.c_uint8 * FAEST_192S_PRIVATE_KEY_BYTES)()
        result = self._library().faest_192s_keygen(public_key, secret_key)
        if result != 0:
            raise RuntimeError("FAEST-192s key generation failed")
        return bytes(public_key), bytes(secret_key)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        key = _exact(
            secret_key,
            FAEST_192S_PRIVATE_KEY_BYTES,
            "FAEST-192s private key",
        )
        if not isinstance(message, bytes):
            raise TypeError("FAEST message must be bytes")
        key_buffer = _ctypes_bytes(key)
        message_buffer = _ctypes_bytes(message)
        signature = (ctypes.c_uint8 * FAEST_192S_SIGNATURE_BYTES)()
        signature_length = ctypes.c_size_t(FAEST_192S_SIGNATURE_BYTES)
        result = self._library().faest_192s_sign(
            key_buffer,
            message_buffer,
            len(message),
            signature,
            ctypes.byref(signature_length),
        )
        if result != 0 or signature_length.value != FAEST_192S_SIGNATURE_BYTES:
            raise RuntimeError("FAEST-192s signing failed")
        return bytes(signature)

    def verify(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> bool:
        try:
            key = _exact(
                public_key,
                FAEST_192S_PUBLIC_KEY_BYTES,
                "FAEST-192s public key",
            )
            sig = _exact(
                signature,
                FAEST_192S_SIGNATURE_BYTES,
                "FAEST-192s signature",
            )
            if not isinstance(message, bytes):
                return False
            result = self._library().faest_192s_verify(
                _ctypes_bytes(key),
                _ctypes_bytes(message),
                len(message),
                _ctypes_bytes(sig),
                len(sig),
            )
            return result == 0
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
