"""Explicit research-only native relation API, ABI v1.

Non-constant-time until independently audited; unqualified; not a production
provider. No verifier adapter, discovery, compiler, registry or Python fallback.
Import performs no native loading. Linux load uses a sealed, captured library
image: the SHA-256-checked bytes are exactly those passed to the dynamic loader.
The library and its system dependencies must themselves be trusted code.
"""
from __future__ import annotations

import ctypes
import hashlib
from pathlib import Path
import threading
from typing import TYPE_CHECKING
import weakref

from pq_rbbc.native_library_loader_v0_1 import (
    CapturedNativeLibraryV0_1,
    NativeLibraryLoadErrorV0_1,
    load_captured_native_library_v0_1,
)

from .parameters import FieldId, PROFILE_FINGERPRINT

if TYPE_CHECKING:
    from .relation import CAPStatement


class NativeRelationError(RuntimeError):
    """Fail-closed rejection by the explicit native boundary."""


_ERRORS = {
    1: "null pointer", 2: "length", 3: "field order", 4: "element range",
    5: "allocation failure", 6: "context state", 7: "length overflow",
    8: "statement binding", 9: "thread count", 10: "internal invariant",
}
_FIELDS = (FieldId.GF_2_12,) * 2 + (FieldId.GF_2_11,) * 16
_U8P = ctypes.POINTER(ctypes.c_uint8)
_U16P = ctypes.POINTER(ctypes.c_uint16)
_HANDLE = ctypes.c_void_p
_DOMAIN = b"PQSAT-BUOV-CAP-NATIVE-RELATION/v0.1/STATEMENT\x00"
_LIBRARY_ABI_NAMESPACE = "pq-rbbc.blind-uov-pqsat.cap-relation.abi-v1"


def _checked(status: int) -> None:
    if status:
        raise NativeRelationError(f"native error {status}: {_ERRORS.get(status, 'unknown error')}")


def _bytes(value: object, size: int, name: str) -> bytes:
    if type(value) is not bytes or len(value) != size:
        raise NativeRelationError(f"{name} must be exact bytes of length {size}")
    return value


def _u8(raw: bytes):
    return (ctypes.c_uint8 * len(raw)).from_buffer_copy(raw)


def _release_context(kernel: NativeRelationKernel, handle: _HANDLE) -> None:
    _checked(kernel._lib.pqsat_cap_context_free(ctypes.byref(handle)))


class NativeRelationKernel:
    """A library factory. Every bind allocates an independent immutable context.

    Explicit context close is required; a finalizer is a resource safety net.
    Loaded images and one sealed descriptor per successful load live until
    process exit, as required by the OpenMP runtime's persistent worker pool.
    There is no global statement/context cache; close frees all bound data.
    """

    __slots__ = (
        "_lib",
        "_library_path",
        "_sha256",
        "_captured_library",
        "_lock",
        "_closed",
        "__weakref__",
    )

    def __init__(self) -> None:
        raise NativeRelationError("use NativeRelationKernel.load with an explicit path and digest")

    @classmethod
    def load(cls, library_path: Path, *, expected_sha256: str) -> NativeRelationKernel:
        if type(library_path) is not type(Path()):
            raise NativeRelationError("library_path must be an exact platform pathlib.Path")
        if not library_path.is_absolute():
            raise NativeRelationError("library_path must be absolute")
        if (type(expected_sha256) is not str or len(expected_sha256) != 64
                or any(c not in "0123456789abcdef" for c in expected_sha256)):
            raise NativeRelationError("expected_sha256 must be canonical lowercase SHA-256 hex")
        def validate(lib: ctypes.CDLL) -> None:
            lib.pqsat_cap_abi_version.argtypes = []
            lib.pqsat_cap_abi_version.restype = ctypes.c_uint32
            if lib.pqsat_cap_abi_version() != 1:
                raise NativeRelationError("native ABI version mismatch")
            lib.pqsat_cap_cpu_compatible.argtypes = []
            lib.pqsat_cap_cpu_compatible.restype = ctypes.c_int
            if lib.pqsat_cap_cpu_compatible() != 1:
                raise NativeRelationError(
                    "native library CPU capabilities are unsupported"
                )
            lib.pqsat_cap_openmp_version.argtypes = []
            lib.pqsat_cap_openmp_version.restype = ctypes.c_uint32
            lib.pqsat_cap_probe_threads.argtypes = [ctypes.c_uint32]
            lib.pqsat_cap_probe_threads.restype = ctypes.c_uint32
            lib.pqsat_cap_context_create.argtypes = [
                _U8P, ctypes.c_size_t, _U8P, ctypes.c_size_t,
                _U8P, ctypes.c_size_t, _U8P, ctypes.c_size_t,
                ctypes.c_uint32, ctypes.POINTER(_HANDLE),
            ]
            lib.pqsat_cap_context_create.restype = ctypes.c_int
            lib.pqsat_cap_evaluate_batch.argtypes = [
                _HANDLE, _U8P, ctypes.c_size_t, _U8P, ctypes.c_size_t,
                _U16P, ctypes.c_size_t, _U16P, ctypes.c_size_t,
            ]
            lib.pqsat_cap_evaluate_batch.restype = ctypes.c_int
            lib.pqsat_cap_context_free.argtypes = [ctypes.POINTER(_HANDLE)]
            lib.pqsat_cap_context_free.restype = ctypes.c_int

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
            raise NativeRelationError(f"cannot load native library: {error}") from error

    @property
    def library_sha256(self) -> str:
        return self._sha256

    def bind(self, statement: CAPStatement, *, threads: int = 6) -> BoundNativeRelationKernel:
        from .relation import CAPStatement
        from .uov import UOVPublicMap, CPK_BYTES, DENSE_BYTES, _digest_cpk
        with self._lock:
            if self._closed:
                raise NativeRelationError("use after close")
        if type(statement) is not CAPStatement:
            raise NativeRelationError("statement must be exactly CAPStatement")
        if type(statement.public_map) is not UOVPublicMap:
            raise NativeRelationError("public_map must be exactly UOVPublicMap")
        if type(threads) is not int or not 1 <= threads <= 18:
            raise NativeRelationError("threads must be an exact int in 1..18")
        public = statement.public_map
        cpk = _bytes(public.canonical_cpk, CPK_BYTES, "canonical_cpk")
        dense = _bytes(public.dense_coefficients, DENSE_BYTES, "dense map")
        digest = _bytes(public.public_map_digest, 32, "public-map digest")
        ctx = _bytes(statement.ctx, 32, "statement ctx")
        u = _bytes(statement.u, 72, "statement u")
        if digest != _digest_cpk(cpk):
            raise NativeRelationError("public-map digest does not bind canonical_cpk")
        # Preserve the CAPStatement contract: no issuer registry lookup or cpk
        # re-expansion. Include the exact dense snapshot as well as the cpk digest
        # so low-level forged/mutated Python objects cannot alias a cached map.
        dense_sha = hashlib.sha256(dense).digest()
        binding = hashlib.sha256(_DOMAIN + PROFILE_FINGERPRINT + digest + dense_sha + ctx + u).digest()
        handle = _HANDLE()
        _checked(self._lib.pqsat_cap_context_create(
            _u8(dense), len(dense), _u8(u), len(u),
            _u8(digest), len(digest), _u8(binding), len(binding),
            threads, ctypes.byref(handle),
        ))
        if not handle.value:
            raise NativeRelationError("native create returned a null context")
        try:
            return BoundNativeRelationKernel._create(self, handle, binding, digest, dense_sha, threads)
        except BaseException:
            _release_context(self, handle)
            raise

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._captured_library.close()
            self._closed = True


class BoundNativeRelationKernel:
    """Thread-safe lifetime for one copied statement; close is idempotent.

    Calls on this object serialize with each other and with close. Distinct
    contexts have independent memory. The C kernel parallelizes repetitions.
    """

    __slots__ = ("_kernel", "_handle", "_binding", "_map_digest", "_dense_sha",
                 "_threads", "_lock", "_release", "__weakref__")

    def __init__(self) -> None:
        raise NativeRelationError("use NativeRelationKernel.bind")

    @classmethod
    def _create(cls, kernel, handle, binding, map_digest, dense_sha, threads):
        result = object.__new__(cls)
        result._kernel = kernel
        result._handle = handle
        result._binding = binding
        result._map_digest = map_digest
        result._dense_sha = dense_sha
        result._threads = threads
        result._lock = threading.RLock()
        result._release = weakref.finalize(result, _release_context, kernel, handle)
        return result

    @property
    def statement_binding_sha256(self) -> str:
        return self._binding.hex()

    @property
    def public_map_digest(self) -> bytes:
        return self._map_digest

    def evaluate_batch(self, field_ids: tuple[FieldId, ...],
                       witness_vectors: tuple[tuple[int, ...], ...]) -> tuple[tuple[int, ...], ...]:
        with self._lock:
            if not self._release.alive:
                raise NativeRelationError("use after close")
            if type(field_ids) is not tuple or len(field_ids) != 18:
                raise NativeRelationError("field_ids must be an exact 18-tuple")
            if any(type(f) is not FieldId or f is not expected
                   for f, expected in zip(field_ids, _FIELDS, strict=True)):
                raise NativeRelationError("field order must be two GF(2^12) then sixteen GF(2^11)")
            if type(witness_vectors) is not tuple or len(witness_vectors) != 18:
                raise NativeRelationError("witness_vectors must be an exact 18-tuple")
            for r, vector in enumerate(witness_vectors):
                if type(vector) is not tuple or len(vector) != 2048:
                    raise NativeRelationError("each witness must be an exact 2048-tuple")
                upper = 4096 if r < 2 else 2048
                if any(type(v) is not int or not 0 <= v < upper for v in vector):
                    raise NativeRelationError("witness elements must be exact in-range ints")
            # Validation is complete before ctypes can truncate/convert values.
            values = (ctypes.c_uint16 * (18 * 2048))(
                *(v for row in witness_vectors for v in row))
            output = (ctypes.c_uint16 * (18 * 576))()
            _checked(self._kernel._lib.pqsat_cap_evaluate_batch(
                self._handle, _u8(self._binding), 32, _u8(bytes((12, 12) + (11,) * 16)), 18,
                values, len(values), output, len(output),
            ))
            result = tuple(tuple(output[r * 576:(r + 1) * 576]) for r in range(18))
            for r, row in enumerate(result):
                if any(not 0 <= v < (4096 if r < 2 else 2048) for v in row):
                    raise NativeRelationError("native output outside canonical field range")
            return result

    def reconstruct_q_batch(self, field_ids, points, constraints, masks, qbar_groups, gammas):
        """Additive q ABI v1; never evaluates the relation or falls back."""
        from .evaluation import FiniteEvaluationPoint
        with self._lock:
            if not self._release.alive:
                raise NativeRelationError("use after close")
            if type(field_ids) is not tuple or field_ids != _FIELDS or any(type(f) is not FieldId for f in field_ids):
                raise NativeRelationError("wrong field order")
            for value, length, name in ((points,18,'points'), (constraints,18,'constraints'),
                                         (masks,18,'masks'), (qbar_groups,2,'qbar'), (gammas,2,'gammas')):
                if type(value) is not tuple or len(value) != length:
                    raise NativeRelationError(name + " shape")
            def vector(value, size, upper):
                if type(value) is not tuple or len(value) != size or any(
                        type(v) is not int or not 0 <= v < upper for v in value):
                    raise NativeRelationError("q input type, shape or field range")
            for r in range(18):
                upper, rho = (4096,16) if r < 2 else (2048,18)
                p = points[r]
                if type(p) is not FiniteEvaluationPoint or p.field_id is not _FIELDS[r] or type(p.value) is not int or not 0 < p.value < upper:
                    raise NativeRelationError("invalid finite point")
                vector(constraints[r],576,upper)
                vector(masks[r],rho,upper)
            for g, (upper,rho,count) in enumerate(((4096,16,32),(2048,18,288))):
                vector(qbar_groups[g],count,upper)
                if type(gammas[g]) is not tuple or len(gammas[g]) != rho:
                    raise NativeRelationError("gamma shape")
                for row in gammas[g]:
                    vector(row,576,upper)
            def array(values):
                return (ctypes.c_uint16 * len(values))(*values)
            arrays = (array(tuple(p.value for p in points)),
                      array(tuple(v for row in constraints for v in row)),
                      array(tuple(v for row in masks for v in row)),
                      array(qbar_groups[0]+qbar_groups[1]),
                      array(tuple(v for group in gammas for row in group for v in row)))
            out = (ctypes.c_uint16 * 320)()
            args = [self._handle, _u8(self._binding), 32, _u8(bytes((12,12)+(11,)*16)), 18]
            for a in arrays:
                args.extend((a,len(a)))
            _configure_q(self._kernel._lib)
            _checked(self._kernel._lib.pqsat_cap_reconstruct_q_batch_v1(*args,out,320))
            result = (tuple(out[:32]),tuple(out[32:]))
            for group, upper in zip(result,(4096,2048)):
                if any(v >= upper for v in group):
                    raise NativeRelationError("native q output outside canonical field")
            return result

    def close(self) -> None:
        with self._lock:
            self._release()

    def __enter__(self) -> BoundNativeRelationKernel:
        with self._lock:
            if not self._release.alive:
                raise NativeRelationError("use after close")
            return self

    def __exit__(self, *args) -> None:
        self.close()


__all__ = ("NativeRelationError", "NativeRelationKernel", "BoundNativeRelationKernel")


def _configure_q(lib):
    """Require additive ABI explicitly; old evaluate-only libraries still load."""
    try:
        lib.pqsat_cap_q_abi_version.argtypes = []
        lib.pqsat_cap_q_abi_version.restype = ctypes.c_uint32
        if lib.pqsat_cap_q_abi_version() != 1:
            raise NativeRelationError("q ABI mismatch")
        lib.pqsat_cap_reconstruct_q_batch_v1.argtypes = [
            _HANDLE, _U8P, ctypes.c_size_t, _U8P, ctypes.c_size_t,
        ] + [_U16P, ctypes.c_size_t] * 6
        lib.pqsat_cap_reconstruct_q_batch_v1.restype = ctypes.c_int
    except AttributeError as error:
        raise NativeRelationError("missing q ABI") from error
