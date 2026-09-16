"""Pinned OpenSSL ML-DSA-65 adapter for the non-threshold S2 profile."""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import stat
import subprocess
import tempfile
from pathlib import Path

from pq_rbbc.contracts.system import KeyReference, KeyRole

from .trust_registry import (
    MLDSA65_STAGING_PROFILE,
    PinnedTrustRegistry,
    TrustRegistryError,
)


MLDSA65_PUBLIC_KEY_DER_BYTES = 1974
MLDSA65_SIGNATURE_BYTES = 3309
MLDSA65_RAW_PUBLIC_KEY_BYTES = 1952
MLDSA65_SPKI_PREFIX = bytes.fromhex("308207b2300b0609608648016503040312038207a100")
SYSTEM_GOVERNANCE_MLDSA_CONTEXT = b"PQ-RBBC/SYSTEM-GOVERNANCE/STAGING/V1"
MAX_AUTHENTICATED_MESSAGE_BYTES = 1 << 20
DEFAULT_COMMAND_TIMEOUT_SECONDS = 10.0


class MLDSABackendError(RuntimeError):
    """Raised when the pinned cryptographic backend cannot operate safely."""


def mldsa65_spki_from_raw(raw_public_key: bytes) -> bytes:
    """Wrap a FIPS 204 raw ML-DSA-65 public key in its fixed DER SPKI."""

    if not isinstance(raw_public_key, bytes) or len(raw_public_key) != (
        MLDSA65_RAW_PUBLIC_KEY_BYTES
    ):
        raise MLDSABackendError("ML-DSA-65 raw public key has wrong length")
    return MLDSA65_SPKI_PREFIX + raw_public_key


def _validate_message(message: bytes) -> None:
    if not isinstance(message, bytes) or not (
        0 < len(message) <= MAX_AUTHENTICATED_MESSAGE_BYTES
    ):
        raise MLDSABackendError("authenticated message length is outside bounds")


def _validate_context(context: bytes) -> None:
    if not isinstance(context, bytes) or len(context) > 255:
        raise MLDSABackendError("ML-DSA context must be at most 255 bytes")


def _secure_write(directory: str, filename: str, value: bytes) -> str:
    path = os.path.join(directory, filename)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(value)
        while view:
            written = os.write(fd, view)
            view = view[written:]
    finally:
        os.close(fd)
    return path


class PinnedOpenSSLMLDSA65:
    """One-shot ML-DSA-65 operations under an exact OpenSSL executable."""

    def __init__(
        self,
        executable: str | os.PathLike[str],
        *,
        expected_sha256: str,
        expected_version_line: str,
        timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
    ) -> None:
        path = Path(executable)
        if not path.is_absolute():
            raise MLDSABackendError("OpenSSL executable path must be absolute")
        if (
            not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
            or expected_sha256 != expected_sha256.lower()
        ):
            raise MLDSABackendError("expected OpenSSL SHA-256 must be lowercase hex")
        try:
            bytes.fromhex(expected_sha256)
        except ValueError as error:
            raise MLDSABackendError("expected OpenSSL SHA-256 is invalid") from error
        if not isinstance(expected_version_line, str) or not expected_version_line:
            raise MLDSABackendError("expected OpenSSL version line is required")
        if not isinstance(timeout_seconds, (int, float)) or isinstance(
            timeout_seconds, bool
        ) or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 60:
            raise MLDSABackendError("OpenSSL timeout must be within 60 seconds")
        self._executable = os.fspath(path)
        self._expected_sha256 = expected_sha256
        self._expected_version_line = expected_version_line
        self._timeout_seconds = float(timeout_seconds)
        version = self._run(("version",), accepted_returncodes=(0,))
        try:
            actual_version = version.stdout.decode("ascii").rstrip("\n")
        except UnicodeDecodeError as error:
            raise MLDSABackendError("OpenSSL version output is not ASCII") from error
        if actual_version != self._expected_version_line:
            raise MLDSABackendError("OpenSSL version does not match pinned version")
        algorithms = self._run(
            ("list", "-signature-algorithms"), accepted_returncodes=(0,)
        )
        if b"ML-DSA-65" not in algorithms.stdout:
            raise MLDSABackendError("pinned OpenSSL lacks ML-DSA-65")

    @property
    def profile(self) -> str:
        return MLDSA65_STAGING_PROFILE

    def _open_executable(self) -> int:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self._executable, flags)
        except OSError as error:
            raise MLDSABackendError("cannot safely open pinned OpenSSL") from error
        try:
            properties = os.fstat(fd)
            if not stat.S_ISREG(properties.st_mode):
                raise MLDSABackendError("pinned OpenSSL is not a regular file")
            if not properties.st_mode & stat.S_IXUSR:
                raise MLDSABackendError("pinned OpenSSL is not owner-executable")
            if stat.S_IMODE(properties.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
                raise MLDSABackendError("pinned OpenSSL is group/world writable")
            with os.fdopen(os.dup(fd), "rb") as executable_file:
                digest = hashlib.file_digest(executable_file, "sha256")
            if not hmac.compare_digest(digest.hexdigest(), self._expected_sha256):
                raise MLDSABackendError("OpenSSL executable digest mismatch")
            os.lseek(fd, 0, os.SEEK_SET)
            return fd
        except Exception:
            os.close(fd)
            raise

    def _run(
        self,
        arguments: tuple[str, ...],
        *,
        pass_fds: tuple[int, ...] = (),
        accepted_returncodes: tuple[int, ...] = (0,),
    ) -> subprocess.CompletedProcess[bytes]:
        executable_fd = self._open_executable()
        command = (f"/proc/self/fd/{executable_fd}",) + arguments
        environment = {
            "LANG": "C",
            "LC_ALL": "C",
            "OPENSSL_CONF": os.devnull,
        }
        try:
            try:
                result = subprocess.run(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=environment,
                    pass_fds=(executable_fd,) + pass_fds,
                    timeout=self._timeout_seconds,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise MLDSABackendError("OpenSSL execution failed") from error
        finally:
            os.close(executable_fd)
        if result.returncode not in accepted_returncodes:
            raise MLDSABackendError(
                f"OpenSSL command failed with exit status {result.returncode}"
            )
        return result

    def validate_public_key(self, public_key_der: bytes) -> None:
        if not isinstance(public_key_der, bytes) or len(public_key_der) != (
            MLDSA65_PUBLIC_KEY_DER_BYTES
        ):
            raise MLDSABackendError("ML-DSA-65 public key has wrong DER length")
        if not public_key_der.startswith(MLDSA65_SPKI_PREFIX):
            raise MLDSABackendError("public key is not canonical ML-DSA-65 SPKI")
        with tempfile.TemporaryDirectory(prefix="pqrbbc-mldsa-public-") as directory:
            public_path = _secure_write(directory, "public.der", public_key_der)
            result = self._run(
                (
                    "pkey",
                    "-pubin",
                    "-inform",
                    "DER",
                    "-in",
                    public_path,
                    "-pubout",
                    "-outform",
                    "DER",
                ),
                accepted_returncodes=(0,),
            )
        if not hmac.compare_digest(result.stdout, public_key_der):
            raise MLDSABackendError("ML-DSA-65 public key DER is non-canonical")

    def verify(
        self,
        public_key_der: bytes,
        message: bytes,
        signature: bytes,
        *,
        context: bytes = SYSTEM_GOVERNANCE_MLDSA_CONTEXT,
    ) -> bool:
        self.validate_public_key(public_key_der)
        _validate_message(message)
        _validate_context(context)
        if not isinstance(signature, bytes) or len(signature) != MLDSA65_SIGNATURE_BYTES:
            return False
        with tempfile.TemporaryDirectory(prefix="pqrbbc-mldsa-verify-") as directory:
            public_path = _secure_write(directory, "public.der", public_key_der)
            message_path = _secure_write(directory, "message.bin", message)
            signature_path = _secure_write(directory, "signature.bin", signature)
            result = self._run(
                (
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    public_path,
                    "-keyform",
                    "DER",
                    "-rawin",
                    "-in",
                    message_path,
                    "-sigfile",
                    signature_path,
                    "-pkeyopt",
                    f"hexcontext-string:{context.hex()}",
                ),
                accepted_returncodes=(0, 1),
            )
        return result.returncode == 0

    def public_key_from_private_fd(self, private_key_fd: int) -> bytes:
        result = self._run(
            (
                "pkey",
                "-in",
                f"/proc/self/fd/{private_key_fd}",
                "-pubout",
                "-outform",
                "DER",
            ),
            pass_fds=(private_key_fd,),
            accepted_returncodes=(0,),
        )
        self.validate_public_key(result.stdout)
        return result.stdout

    def sign_with_private_fd(
        self,
        private_key_fd: int,
        message: bytes,
        *,
        context: bytes = SYSTEM_GOVERNANCE_MLDSA_CONTEXT,
    ) -> bytes:
        _validate_message(message)
        _validate_context(context)
        with tempfile.TemporaryDirectory(prefix="pqrbbc-mldsa-sign-") as directory:
            message_path = _secure_write(directory, "message.bin", message)
            signature_path = _secure_write(directory, "signature.bin", b"")
            self._run(
                (
                    "pkeyutl",
                    "-sign",
                    "-inkey",
                    f"/proc/self/fd/{private_key_fd}",
                    "-rawin",
                    "-in",
                    message_path,
                    "-out",
                    signature_path,
                    "-pkeyopt",
                    f"hexcontext-string:{context.hex()}",
                ),
                pass_fds=(private_key_fd,),
                accepted_returncodes=(0,),
            )
            try:
                signature_fd = os.open(
                    signature_path,
                    os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                )
            except OSError as error:
                raise MLDSABackendError("cannot read ML-DSA signature") from error
            try:
                signature = os.read(signature_fd, MLDSA65_SIGNATURE_BYTES + 1)
            finally:
                os.close(signature_fd)
        if len(signature) != MLDSA65_SIGNATURE_BYTES:
            raise MLDSABackendError("OpenSSL returned wrong ML-DSA-65 signature length")
        return signature


class RegistryBackedMLDSA65Verifier:
    """Existing verifier-protocol adapter backed by captured operator trust."""

    def __init__(
        self, registry: PinnedTrustRegistry, backend: PinnedOpenSSLMLDSA65
    ) -> None:
        self._registry = registry
        self._backend = backend
        for entry in registry.entries:
            if entry.profile != backend.profile:
                raise MLDSABackendError("trust entry/backend profile mismatch")
            backend.validate_public_key(entry.public_key_der)

    def verify(
        self, key: KeyReference, message: bytes, authentication: bytes
    ) -> bool:
        entry = self._registry.resolve(key)
        return self._backend.verify(entry.public_key_der, message, authentication)


class OpenSSLMLDSA65NonThresholdSigner:
    """Staging-only single-secret signer; this is not a FAC threshold signer."""

    def __init__(
        self,
        backend: PinnedOpenSSLMLDSA65,
        trusted_key: KeyReference,
        public_key_der: bytes,
        private_key_path: str | os.PathLike[str],
    ) -> None:
        if trusted_key.role not in (
            KeyRole.FEDERATION_CONFIGURATION,
            KeyRole.ISSUER_AUTHORIZATION,
        ):
            raise MLDSABackendError("signer has wrong governance role")
        backend.validate_public_key(public_key_der)
        if not hmac.compare_digest(
            hashlib.sha256(public_key_der).digest(),
            trusted_key.public_key_digest,
        ):
            raise MLDSABackendError("signer public key digest mismatch")
        path = Path(private_key_path)
        if not path.is_absolute():
            raise MLDSABackendError("private key path must be absolute")
        self._backend = backend
        self._trusted_key = trusted_key
        self._public_key_der = public_key_der
        self._private_key_path = os.fspath(path)
        private_fd = self._open_private_key()
        try:
            derived = backend.public_key_from_private_fd(private_fd)
        finally:
            os.close(private_fd)
        if not hmac.compare_digest(derived, public_key_der):
            raise MLDSABackendError("private key does not match trusted public key")

    @property
    def key_reference(self) -> KeyReference:
        return self._trusted_key

    def _open_private_key(self) -> int:
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self._private_key_path, flags)
        except OSError as error:
            raise MLDSABackendError("cannot safely open private key") from error
        try:
            properties = os.fstat(fd)
            if not stat.S_ISREG(properties.st_mode):
                raise MLDSABackendError("private key is not a regular file")
            if stat.S_IMODE(properties.st_mode) != 0o600:
                raise MLDSABackendError("private key mode must be 0600")
            return fd
        except Exception:
            os.close(fd)
            raise

    def sign(self, message: bytes) -> bytes:
        private_fd = self._open_private_key()
        try:
            derived = self._backend.public_key_from_private_fd(private_fd)
            if not hmac.compare_digest(derived, self._public_key_der):
                raise MLDSABackendError("private key changed after signer initialization")
            return self._backend.sign_with_private_fd(private_fd, message)
        finally:
            os.close(private_fd)
