"""Explicit research-only native opening/consistency H+ ABI 2.

No discovery, compiler, native load, profile IO or evaluation on import. No
Python fallback or global context cache. Linux captured/sealed library image;
trusted native code and its system dependencies remain caller prerequisites.
Not constant-time, qualified, integrated into a verifier or production-ready.
"""
from __future__ import annotations
import ctypes
from dataclasses import dataclass
from pathlib import Path
import struct
import threading
import weakref

from pq_rbbc.native_library_loader_v0_1 import (
    NativeLibraryLoadErrorV0_1,
    load_captured_native_library_v0_1,
)

from .parameters import FieldId, PROFILE_FINGERPRINT

class NativeOpeningError(RuntimeError):
    """Controlled fail-closed native boundary rejection."""

_FIELDS = (FieldId.GF_2_12,) * 2 + (FieldId.GF_2_11,) * 16
_U8P = ctypes.POINTER(ctypes.c_uint8)
_HANDLE = ctypes.c_void_p
_EVAL_BYTES = 83584
_LIBRARY_ABI_NAMESPACE = "pq-rbbc.blind-uov-pqsat.cap-opening-hplus-research.abi-v2"


def _checked(status):
    if status:
        raise NativeOpeningError(f"native opening error {status}")


def _bytes(value, size, name):
    if type(value) is not bytes or len(value) != size:
        raise NativeOpeningError(f"{name}: expected exact bytes of length {size}")
    return value


def _tuple(value, size, name):
    if type(value) is not tuple or len(value) != size:
        raise NativeOpeningError(f"{name}: expected exact tuple of length {size}")
    return value


def _integer(value, bound, name):
    if type(value) is not int or not 0 <= value < bound:
        raise NativeOpeningError(f"{name}: expected exact in-range int")
    return value


def _hidden(value):
    _tuple(value, 18, "hidden_positions")
    for r, p in enumerate(value):
        _integer(p, 4095 if r < 2 else 2047, "finite hidden position")
    return struct.pack('<18H', *value)


def _u8(raw):
    return (ctypes.c_uint8 * len(raw)).from_buffer_copy(raw)


def _configure(lib):
    for name in ('opening_abi_version', 'opening_cpu_compatible', 'opening_openmp_version'):
        f = getattr(lib, name)
        f.argtypes = []
        f.restype = ctypes.c_uint32
    for name in ('opening_backend', 'opening_headers'):
        f = getattr(lib, name)
        f.argtypes = []
        f.restype = ctypes.c_char_p
    lib.opening_profile_fingerprint.argtypes = []
    lib.opening_profile_fingerprint.restype = _U8P
    lib.opening_create.argtypes = [ctypes.POINTER(_HANDLE), ctypes.POINTER(ctypes.c_double)]
    lib.opening_create.restype = ctypes.c_int
    lib.opening_free.argtypes = [ctypes.POINTER(_HANDLE)]
    lib.opening_free.restype = ctypes.c_int
    pair = [_U8P, ctypes.c_size_t]
    lib.opening_reconstruct.argtypes = [_HANDLE] + pair * 5 + [ctypes.c_uint32] + pair * 4 + [ctypes.POINTER(ctypes.c_double), ctypes.c_size_t]
    lib.opening_reconstruct.restype = ctypes.c_int
    lib.opening_xi.argtypes = [_HANDLE] + pair * 6 + [ctypes.c_uint32] + pair * 2 + [ctypes.POINTER(ctypes.c_double), ctypes.c_size_t]
    lib.opening_xi.restype = ctypes.c_int


def _vectors(raw):
    _bytes(raw, _EVAL_BYTES, 'evaluations')
    result = []
    offset = 0
    for r in range(18):
        rho = 16 if r < 2 else 18
        size = 2048 + rho + 256
        values = struct.unpack_from('<' + str(size) + 'H', raw, offset)
        if any(v >= (4096 if r < 2 else 2048) for v in values):
            raise NativeOpeningError('native evaluation outside canonical field')
        result.append((values[:2048], values[2048:2048+rho], values[2048+rho:]))
        offset += size * 2
    return tuple(result)


@dataclass(frozen=True, slots=True)
class NativeOpeningReplay:
    hidden_positions: tuple[int, ...]
    commitment_transcript: bytes
    leaf_seeds: bytes
    coverage: bytes
    evaluations: bytes
    phase_seconds: tuple[float, ...]

    def __post_init__(self):
        _hidden(self.hidden_positions)
        _bytes(self.commitment_transcript, 1966080, 'commitment transcript')
        _bytes(self.leaf_seeds, 983040, 'leaf seeds')
        _bytes(self.coverage, 40960, 'coverage')
        holes = set()
        for r, p in enumerate(self.hidden_positions):
            holes.add(18*p+r if p < 2048 else 36864+2*(p-2048)+r)
        if self.coverage.count(b'\x01') != 40942 or self.coverage.count(b'\x00') != 18:
            raise NativeOpeningError('malformed native coverage')
        if any(self.coverage[i] or self.leaf_seeds[24*i:24*(i+1)] != bytes(24) for i in holes):
            raise NativeOpeningError('hidden seed disclosure')
        _vectors(self.evaluations)
        _timings(self.phase_seconds, 4)

    @property
    def vectors(self):
        return _vectors(self.evaluations)


@dataclass(frozen=True, slots=True)
class NativeConsistencyReplay:
    corrected_evaluations: bytes
    xi_encoded: bytes
    phase_seconds: tuple[float, ...]

    def __post_init__(self):
        _vectors(self.corrected_evaluations)
        _bytes(self.xi_encoded, 6976, 'Xi')
        _timings(self.phase_seconds, 2)

    @property
    def vectors(self):
        return _vectors(self.corrected_evaluations)


def _timings(values, count):
    import math
    _tuple(values, count, 'phase timings')
    if any(type(v) is not float or not math.isfinite(v) or v < 0 for v in values):
        raise NativeOpeningError('malformed native timing')


class NativeOpeningKernel:
    """Explicit library lifetime. bind() owns reciprocal tables until close.

    Successful library images/descriptors live until exit for OpenMP safety.
    close() prevents new binds; existing bound contexts retain their lifetime.
    """
    __slots__ = (
        '_lib', '_library_path', '_sha256', '_captured_library', '_lock', '_closed'
    )

    def __init__(self):
        raise NativeOpeningError('use NativeOpeningKernel.load')

    @classmethod
    def load(cls, library_path: Path, *, expected_sha256: str) -> NativeOpeningKernel:
        if type(library_path) is not type(Path()):
            raise NativeOpeningError("library_path must be an exact platform pathlib.Path")
        if not library_path.is_absolute():
            raise NativeOpeningError("library_path must be absolute")
        if (type(expected_sha256) is not str or len(expected_sha256) != 64
                or any(c not in "0123456789abcdef" for c in expected_sha256)):
            raise NativeOpeningError("expected_sha256 must be canonical lowercase SHA-256 hex")
        def validate(lib: ctypes.CDLL) -> None:
            _configure(lib)
            if lib.opening_abi_version() != 2:
                raise NativeOpeningError("native ABI version mismatch")
            if bytes(lib.opening_profile_fingerprint()[:32]) != PROFILE_FINGERPRINT:
                raise NativeOpeningError("native H+ profile mismatch")
            if lib.opening_cpu_compatible() != 1:
                raise NativeOpeningError("unsupported CPU")

        try:
            captured = load_captured_native_library_v0_1(
                library_path,
                expected_sha256,
                abi_namespace=_LIBRARY_ABI_NAMESPACE,
                validator=validate,
            )
            result = object.__new__(cls)
            result._lib = captured.library
            result._library_path = library_path
            result._sha256 = expected_sha256
            result._captured_library = captured
            result._lock = threading.RLock()
            result._closed = False
            return result
        except (NativeLibraryLoadErrorV0_1, OSError, ValueError, AttributeError) as error:
            raise NativeOpeningError(f"cannot load native library: {error}") from error

    @property
    def library_sha256(self):
        return self._sha256

    @property
    def backend(self):
        return self._lib.opening_backend().decode('ascii')

    def bind(self, *, threads=6):
        _integer(threads, 19, 'threads')
        if not threads:
            raise NativeOpeningError('threads must be 1..18')
        with self._lock:
            if self._closed:
                raise NativeOpeningError('use after close')
            handle = _HANDLE()
            elapsed = ctypes.c_double()
            _checked(self._lib.opening_create(ctypes.byref(handle), ctypes.byref(elapsed)))
            if not handle.value:
                raise NativeOpeningError('null native context')
            try:
                return BoundNativeOpening._create(self, handle, threads, elapsed.value)
            except BaseException:
                _checked(self._lib.opening_free(ctypes.byref(handle)))
                raise

    def close(self):
        with self._lock:
            self._captured_library.close()
            self._closed = True

    def __enter__(self):
        with self._lock:
            if self._closed:
                raise NativeOpeningError('use after close')
            return self

    def __exit__(self, *args):
        self.close()


def _release_context(kernel, handle):
    _checked(kernel._lib.opening_free(ctypes.byref(handle)))


class BoundNativeOpening:
    """Serialized use/close; independent contexts have independent tables.

    Results contain immutable copies only. Native calls retain no caller
    pointers. Explicit close is required; finalizer is a resource safety net.
    """
    __slots__ = ('_kernel', '_handle', '_threads', '_lock', '_release',
                 'table_seconds', '__weakref__')

    def __init__(self):
        raise NativeOpeningError('use kernel.bind')

    @classmethod
    def _create(cls, kernel, handle, threads, elapsed):
        result = object.__new__(cls)
        result._kernel, result._handle, result._threads = kernel, handle, threads
        result._lock = threading.RLock()
        result.table_seconds = elapsed
        result._release = weakref.finalize(result, _release_context, kernel, handle)
        return result

    def _live(self):
        if not self._release.alive:
            raise NativeOpeningError('use after close')

    def reconstruct(self, *, salt, hidden_positions, frontier_indices,
                    frontier_seeds, hidden_commitments):
        with self._lock:
            self._live()
            _bytes(salt, 48, 'salt')
            hidden = _hidden(hidden_positions)
            if type(frontier_indices) is not tuple or not 13 <= len(frontier_indices) <= 174:
                raise NativeOpeningError('frontier must be exact 13..174 tuple')
            for index in frontier_indices:
                _integer(index, 81919, 'frontier index')
            if any(a >= b for a, b in zip(frontier_indices, frontier_indices[1:])):
                raise NativeOpeningError('frontier must be strictly increasing')
            _tuple(frontier_seeds, len(frontier_indices), 'frontier seeds')
            for seed in frontier_seeds:
                _bytes(seed, 24, 'seed')
            _tuple(hidden_commitments, 18, 'hidden commitments')
            for commitment in hidden_commitments:
                _bytes(commitment, 48, 'hidden commitment')
            inputs = (salt, hidden, struct.pack('<' + str(len(frontier_indices)) + 'I', *frontier_indices),
                      b''.join(frontier_seeds), b''.join(hidden_commitments))
            outputs = tuple((ctypes.c_uint8 * n)() for n in (983040, 40960, 1966080, _EVAL_BYTES))
            timings = (ctypes.c_double * 4)()
            args = [self._handle]
            for raw in inputs:
                args.extend((_u8(raw), len(raw)))
            args.append(self._threads)
            for out in outputs:
                args.extend((out, len(out)))
            _checked(self._kernel._lib.opening_reconstruct(*args, timings, 4))
            leaves, coverage, commitments, evaluations = map(bytes, outputs)
            return NativeOpeningReplay(hidden_positions, commitments, leaves, coverage,
                                       evaluations, tuple(timings))

    def build_xi(self, replay, *, corrections, alpha_prime, consistency_points, field_ids):
        with self._lock:
            self._live()
            if type(replay) is not NativeOpeningReplay:
                raise NativeOpeningError('expected exact NativeOpeningReplay')
            # Repeat checks: frozen dataclasses can be forged with object APIs.
            replay.__post_init__()
            _bytes(corrections, 4896, '17 delta_P || delta_Mhat records')
            _bytes(alpha_prime, 32, 'alpha_prime')
            _tuple(consistency_points, 4, 'consistency points')
            for p in consistency_points:
                _integer(p, 1 << 64, 'GF(2^64) point')
            _tuple(field_ids, 18, 'field order')
            if any(type(f) is not FieldId or f is not e for f, e in zip(field_ids, _FIELDS)):
                raise NativeOpeningError('wrong field order')
            inputs = (_hidden(replay.hidden_positions), bytes((12, 12) + (11,) * 16),
                      replay.evaluations, corrections, alpha_prime, struct.pack('<4Q', *consistency_points))
            corrected = (ctypes.c_uint8 * _EVAL_BYTES)()
            xi = (ctypes.c_uint8 * 6976)()
            timings = (ctypes.c_double * 2)()
            args = [self._handle]
            for raw in inputs:
                args.extend((_u8(raw), len(raw)))
            _checked(self._kernel._lib.opening_xi(*args, self._threads, corrected, len(corrected),
                                                xi, len(xi), timings, 2))
            result = NativeConsistencyReplay(bytes(corrected), bytes(xi), tuple(timings))
            at = 0
            for r in range(18):
                if result.xi_encoded[at:at+32] != alpha_prime:
                    raise NativeOpeningError('malformed native Xi constant')
                at += 416 if r < 2 else 384
            return result

    def close(self):
        with self._lock:
            self._release()

    def __enter__(self):
        with self._lock:
            self._live()
            return self

    def __exit__(self, *args):
        self.close()
