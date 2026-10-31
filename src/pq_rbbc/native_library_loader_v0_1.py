"""Captured native-library loader with process-lifetime pathname identities.

Every caller supplies an exact absolute path, a lowercase SHA-256 digest, and
an ABI namespace fixed by the provider implementation.  The source is opened
once without following symlinks, verified through that descriptor, copied to a
sealed memfd, and loaded from the sealed image.  Successful cache entries keep
their memfd open for the process lifetime so glibc can never observe the same
``/proc/self/fd/N`` pathname naming another shared object.

The cache is bounded by unique ``(ABI namespace, SHA-256, image size)`` keys.
Closing a :class:`CapturedNativeLibraryV0_1` closes only that logical wrapper;
it deliberately does not unload the shared object or release the retained
descriptor.  This is a bounded process-lifetime resource, not a per-load FD
leak.  Importing this module performs no discovery, compilation, or loading.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import fcntl
import hashlib
import hmac
import os
from pathlib import Path
import stat
import threading
from typing import Callable


MAX_NATIVE_LIBRARY_BYTES_V0_1 = 64 * 1024 * 1024
_SHA256_HEX = frozenset("0123456789abcdef")
_CACHE_LOCK = threading.RLock()
# Keep the real constructor available for the libc memfd fallback.  Provider
# tests intentionally patch ``ctypes.CDLL`` to exercise symbol-gate failures;
# that patch must affect the image load, not the loader's syscall shim.
_SYSTEM_CDLL = ctypes.CDLL


class NativeLibraryLoadErrorV0_1(RuntimeError):
    """Fail-closed capture, identity, sealing, or dynamic-load rejection."""


@dataclass(frozen=True, slots=True)
class NativeLibraryIdentityV0_1:
    """Public identity of one retained image; never contains library bytes."""

    abi_namespace: str
    sha256: str
    image_size: int

    def __post_init__(self) -> None:
        if (
            type(self.abi_namespace) is not str
            or not self.abi_namespace
            or len(self.abi_namespace) > 160
            or not self.abi_namespace.isascii()
            or any(character.isspace() for character in self.abi_namespace)
        ):
            raise NativeLibraryLoadErrorV0_1(
                "abi_namespace must be non-empty bounded ASCII without whitespace"
            )
        if (
            type(self.sha256) is not str
            or len(self.sha256) != 64
            or any(character not in _SHA256_HEX for character in self.sha256)
        ):
            raise NativeLibraryLoadErrorV0_1(
                "sha256 must be canonical lowercase SHA-256 hex"
            )
        if (
            type(self.image_size) is not int
            or not 1 <= self.image_size <= MAX_NATIVE_LIBRARY_BYTES_V0_1
        ):
            raise NativeLibraryLoadErrorV0_1(
                "image_size must identify a non-empty bounded image"
            )


@dataclass(frozen=True, slots=True)
class NativeLibraryCacheObservationV0_1:
    """Test-only cache metadata that cannot expose captured image bytes."""

    entry_count: int
    retained_descriptor_count: int
    identities: tuple[NativeLibraryIdentityV0_1, ...]


@dataclass(slots=True)
class _CacheEntryV0_1:
    identity: NativeLibraryIdentityV0_1
    library: ctypes.CDLL
    retained_descriptor: int


_CACHE: dict[
    tuple[str, str, int],
    _CacheEntryV0_1,
] = {}


class CapturedNativeLibraryV0_1:
    """Logical handle to one process-cached captured native image."""

    __slots__ = ("_entry", "_library", "_closed", "_lock")

    def __init__(self, entry: _CacheEntryV0_1, library: ctypes.CDLL) -> None:
        self._entry = entry
        # Each logical wrapper receives a fresh ctypes object around the same
        # retained dlopen pathname.  This isolates Python-side function
        # signature/attribute mutation while reusing the same captured image.
        self._library = library
        self._closed = False
        self._lock = threading.RLock()

    @property
    def identity(self) -> NativeLibraryIdentityV0_1:
        return self._entry.identity

    @property
    def library(self) -> ctypes.CDLL:
        with self._lock:
            if self._closed:
                raise NativeLibraryLoadErrorV0_1(
                    "captured native-library wrapper is closed"
                )
            return self._library

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def close(self) -> None:
        """Close this wrapper without unloading or recycling the cache FD."""

        with self._lock:
            self._closed = True

    def __enter__(self) -> "CapturedNativeLibraryV0_1":
        self.library
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _exact_path(value: object) -> Path:
    if type(value) is not type(Path()) or not value.is_absolute():
        raise NativeLibraryLoadErrorV0_1(
            "library_path must be an exact absolute pathlib.Path"
        )
    return value


def _canonical_digest(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in _SHA256_HEX for character in value)
    ):
        raise NativeLibraryLoadErrorV0_1(
            "expected_sha256 must be canonical lowercase SHA-256 hex"
        )
    return value


def _namespace(value: object) -> str:
    # Reuse the public identity validator so key construction and observations
    # cannot disagree about the namespace language.
    return NativeLibraryIdentityV0_1(
        abi_namespace=value,  # type: ignore[arg-type]
        sha256="0" * 64,
        image_size=1,
    ).abi_namespace


def _create_memfd(identity: NativeLibraryIdentityV0_1) -> int:
    name = (
        "pqsat-native-v1-"
        + hashlib.sha256(identity.abi_namespace.encode("ascii")).hexdigest()[:12]
        + "-"
        + identity.sha256[:12]
    ).encode("ascii")
    flags = getattr(os, "MFD_CLOEXEC", 0x0001) | getattr(
        os, "MFD_ALLOW_SEALING", 0x0002
    )
    if hasattr(os, "memfd_create"):
        return os.memfd_create(name.decode("ascii"), flags)
    libc = _SYSTEM_CDLL(None, use_errno=True)
    create = libc.memfd_create
    create.argtypes = [ctypes.c_char_p, ctypes.c_uint]
    create.restype = ctypes.c_int
    descriptor = int(create(name, flags))
    if descriptor < 0:
        raise OSError(ctypes.get_errno(), "memfd_create failed")
    return descriptor


def _capture_source(
    library_path: Path,
    expected_sha256: str,
) -> tuple[bytes, NativeLibraryIdentityV0_1]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        source_descriptor = os.open(library_path, flags)
    except OSError as error:
        raise NativeLibraryLoadErrorV0_1(
            "cannot open explicit native library without following symlinks"
        ) from error
    try:
        metadata = os.fstat(source_descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
            raise NativeLibraryLoadErrorV0_1(
                "native library must be a non-empty regular file"
            )
        if metadata.st_size > MAX_NATIVE_LIBRARY_BYTES_V0_1:
            raise NativeLibraryLoadErrorV0_1(
                "native library exceeds the 64 MiB capture bound"
            )
        captured = bytearray()
        digest = hashlib.sha256()
        while len(captured) < metadata.st_size:
            block = os.read(
                source_descriptor,
                min(1024 * 1024, metadata.st_size - len(captured)),
            )
            if not block:
                break
            captured.extend(block)
            digest.update(block)
        if len(captured) != metadata.st_size or os.read(source_descriptor, 1):
            raise NativeLibraryLoadErrorV0_1(
                "native library size changed or truncated during capture"
            )
        observed = digest.hexdigest()
        if not hmac.compare_digest(observed, expected_sha256):
            raise NativeLibraryLoadErrorV0_1("native library SHA-256 mismatch")
        _validate_elf_image(bytes(captured))
        identity = NativeLibraryIdentityV0_1(
            abi_namespace="capture-placeholder",
            sha256=observed,
            image_size=len(captured),
        )
        return bytes(captured), identity
    finally:
        os.close(source_descriptor)


def _validate_elf_image(image: bytes) -> None:
    """Reject malformed/truncated ELF64 images before the dynamic loader.

    A truncated PT_LOAD can make some loaders fault while mapping the sealed
    descriptor.  These structural checks do not replace provider ABI gates;
    they only ensure every declared file-backed program segment is present.
    """

    if (
        len(image) < 64
        or image[:4] != b"\x7fELF"
        or image[4:7] != b"\x02\x01\x01"
        or int.from_bytes(image[16:18], "little") != 3
        or int.from_bytes(image[18:20], "little") != 62
        or int.from_bytes(image[20:24], "little") != 1
    ):
        raise NativeLibraryLoadErrorV0_1(
            "native library is not an x86-64 ELF shared object"
        )
    program_offset = int.from_bytes(image[32:40], "little")
    header_size = int.from_bytes(image[52:54], "little")
    entry_size = int.from_bytes(image[54:56], "little")
    entry_count = int.from_bytes(image[56:58], "little")
    if (
        header_size < 64
        or header_size > len(image)
        or entry_size < 56
        or entry_count == 0
        or program_offset > len(image)
        or entry_count > (len(image) - program_offset) // entry_size
    ):
        raise NativeLibraryLoadErrorV0_1(
            "native library has a malformed or truncated ELF program table"
        )
    for index in range(entry_count):
        offset = program_offset + index * entry_size
        file_offset = int.from_bytes(image[offset + 8 : offset + 16], "little")
        file_size = int.from_bytes(image[offset + 32 : offset + 40], "little")
        if file_offset > len(image) or file_size > len(image) - file_offset:
            raise NativeLibraryLoadErrorV0_1(
                "native library has a truncated ELF program segment"
            )


def _release_failed_library(library: ctypes.CDLL | None, descriptor: int) -> None:
    handle = getattr(library, "_handle", None)
    if type(handle) is int and handle != 0:
        import _ctypes

        _ctypes.dlclose(handle)
    os.close(descriptor)


def _logical_library(
    entry: _CacheEntryV0_1,
    validator: Callable[[ctypes.CDLL], None] | None,
) -> ctypes.CDLL:
    """Return an attribute-isolated ctypes wrapper for one retained image."""

    try:
        library = ctypes.CDLL(f"/proc/self/fd/{entry.retained_descriptor}")
    except OSError as error:
        raise NativeLibraryLoadErrorV0_1(
            "retained captured image is not loadable"
        ) from error
    if validator is not None:
        validator(library)
    return library


def load_captured_native_library_v0_1(
    library_path: Path,
    expected_sha256: str,
    *,
    abi_namespace: str,
    validator: Callable[[ctypes.CDLL], None] | None = None,
) -> CapturedNativeLibraryV0_1:
    """Capture, validate, cache, and logically open one native library.

    ``validator`` is provider-owned and runs before a new entry becomes
    visible in the process cache.  It is where the provider preserves its
    symbol, ABI, version, size, CPU, and OpenMP gates.  A failing validator is
    never cached.
    """

    path = _exact_path(library_path)
    expected = _canonical_digest(expected_sha256)
    namespace = _namespace(abi_namespace)
    if validator is not None and not callable(validator):
        raise NativeLibraryLoadErrorV0_1("validator must be callable or None")

    # Serializing the first capture/load is intentional: it makes cache entry
    # creation and pathname retention atomic and rules out duplicate memfds.
    with _CACHE_LOCK:
        captured, placeholder = _capture_source(path, expected)
        identity = NativeLibraryIdentityV0_1(
            abi_namespace=namespace,
            sha256=placeholder.sha256,
            image_size=placeholder.image_size,
        )
        key = (identity.abi_namespace, identity.sha256, identity.image_size)
        existing = _CACHE.get(key)
        if existing is not None:
            return CapturedNativeLibraryV0_1(
                existing,
                _logical_library(existing, validator),
            )

        descriptor = -1
        library: ctypes.CDLL | None = None
        try:
            descriptor = _create_memfd(identity)
            offset = 0
            while offset < len(captured):
                written = os.write(descriptor, captured[offset:])
                if written <= 0:
                    raise NativeLibraryLoadErrorV0_1(
                        "captured native-library image write failed"
                    )
                offset += written
            add_seals = getattr(fcntl, "F_ADD_SEALS", 1033)
            get_seals = getattr(fcntl, "F_GET_SEALS", 1034)
            required_seals = (
                getattr(fcntl, "F_SEAL_SEAL", 0x0001)
                | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
                | getattr(fcntl, "F_SEAL_GROW", 0x0004)
                | getattr(fcntl, "F_SEAL_WRITE", 0x0008)
            )
            fcntl.fcntl(descriptor, add_seals, required_seals)
            if fcntl.fcntl(descriptor, get_seals) & required_seals != required_seals:
                raise NativeLibraryLoadErrorV0_1(
                    "captured native-library image sealing failed"
                )
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                library = ctypes.CDLL(f"/proc/self/fd/{descriptor}")
            except OSError as error:
                raise NativeLibraryLoadErrorV0_1(
                    "verified captured image is not a loadable shared library"
                ) from error
            if validator is not None:
                validator(library)
            entry = _CacheEntryV0_1(identity, library, descriptor)
            logical_library = _logical_library(entry, validator)
            _CACHE[key] = entry
            descriptor = -1
            return CapturedNativeLibraryV0_1(entry, logical_library)
        finally:
            if descriptor >= 0:
                _release_failed_library(library, descriptor)


def native_library_cache_observation_for_tests_v0_1(
) -> NativeLibraryCacheObservationV0_1:
    """Return bounded cache metadata for regression tests, never image bytes."""

    with _CACHE_LOCK:
        identities = tuple(
            sorted(
                (entry.identity for entry in _CACHE.values()),
                key=lambda item: (
                    item.abi_namespace,
                    item.sha256,
                    item.image_size,
                ),
            )
        )
        return NativeLibraryCacheObservationV0_1(
            entry_count=len(identities),
            retained_descriptor_count=len(identities),
            identities=identities,
        )


__all__ = (
    "CapturedNativeLibraryV0_1",
    "MAX_NATIVE_LIBRARY_BYTES_V0_1",
    "NativeLibraryCacheObservationV0_1",
    "NativeLibraryIdentityV0_1",
    "NativeLibraryLoadErrorV0_1",
    "load_captured_native_library_v0_1",
    "native_library_cache_observation_for_tests_v0_1",
)
