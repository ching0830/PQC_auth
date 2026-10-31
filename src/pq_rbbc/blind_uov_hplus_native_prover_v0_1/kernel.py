"""Captured-library ABI v1 with an independent native-prover namespace.

The existing immutable relation context owns the copied full issuer map.
No auto-discovery, compiler, fallback or native load runs during import.
"""
from __future__ import annotations
import ctypes
from pathlib import Path
import threading

from pq_rbbc.native_library_loader_v0_1 import load_captured_native_library_v0_1, NativeLibraryLoadErrorV0_1
from pq_rbbc.blind_uov_hplus_research_v0_1.native_relation import (
    NativeRelationKernel, NativeRelationError, _U8P, _U16P, _HANDLE, _u8, _FIELDS,
)
from pq_rbbc.blind_uov_hplus_research_v0_1.parameters import PROFILE_FINGERPRINT

class NativeProverError(RuntimeError):
    """Fail-closed backend/lifetime rejection; never an implicit fallback."""


def _configure(lib):
    for name,expected in (('pqsat_cap_abi_version',1),('pqsat_prover_abi_version_v1',1),
                          ('pqsat_cap_cpu_compatible',1)):
        function=getattr(lib,name)
        function.argtypes=[]
        function.restype=ctypes.c_uint32
        if function()!=expected:
            raise NativeProverError(name+' gate mismatch')
    lib.pqsat_prover_profile_v1.argtypes=[]
    lib.pqsat_prover_profile_v1.restype=ctypes.c_char_p
    if lib.pqsat_prover_profile_v1()!=PROFILE_FINGERPRINT.hex().encode('ascii'):
        raise NativeProverError('native prover profile mismatch')
    lib.pqsat_cap_openmp_version.argtypes=[]
    lib.pqsat_cap_openmp_version.restype=ctypes.c_uint32
    if lib.pqsat_cap_openmp_version()==0:
        raise NativeProverError('missing OpenMP')
    lib.pqsat_cap_probe_threads.argtypes=[ctypes.c_uint32]
    lib.pqsat_cap_probe_threads.restype=ctypes.c_uint32
    lib.pqsat_cap_context_create.argtypes=[_U8P,ctypes.c_size_t]*4+[ctypes.c_uint32,ctypes.POINTER(_HANDLE)]
    lib.pqsat_cap_context_create.restype=ctypes.c_int
    lib.pqsat_cap_context_free.argtypes=[ctypes.POINTER(_HANDLE)]
    lib.pqsat_cap_context_free.restype=ctypes.c_int
    lib.pqsat_cap_evaluate_batch.argtypes=[_HANDLE,_U8P,ctypes.c_size_t,_U8P,ctypes.c_size_t]+[_U16P,ctypes.c_size_t]*2
    lib.pqsat_cap_evaluate_batch.restype=ctypes.c_int
    lib.pqsat_prover_q_batch_v1.argtypes=[_HANDLE,_U8P,ctypes.c_size_t,_U8P,ctypes.c_size_t]+[_U16P,ctypes.c_size_t]*7
    lib.pqsat_prover_q_batch_v1.restype=ctypes.c_int


class NativeCAPProver(NativeRelationKernel):
    """Explicit factory. prove includes a fresh context bind and free each call.

    Successful captured images remain process-resident for OpenMP safety.
    Independent calls allocate disjoint workspaces. A factory close rejects new
    calls; contexts already bound retain their existing independent lifetime.
    """
    __slots__=()

    @classmethod
    def load(cls, library_path: Path, *, expected_sha256: str):
        try:
            captured=load_captured_native_library_v0_1(library_path,expected_sha256,
                abi_namespace='pq-rbbc.blind-uov-hplus-research.native-prover.abi-v1',validator=_configure)
        except (NativeLibraryLoadErrorV0_1,AttributeError,OSError,ValueError) as error:
            raise NativeProverError('native prover load rejected: '+str(error)) from error
        result=object.__new__(cls)
        result._lib=captured.library
        result._library_path=library_path
        result._sha256=expected_sha256
        result._captured_library=captured
        result._lock=threading.RLock()
        result._closed=False
        return result

    def prove(self, ctx, u, c_r, c_z, state, *, threads=1):
        from .api import prove
        with self._lock:
            if self._closed:
                raise NativeProverError('use after close')
        return prove(ctx,u,c_r,c_z,state,kernel=self,threads=threads)

    def q_batch(self, statement, repetitions, gammas, *, threads=1):
        """All 18 q/qbar values, not a reduced circuit or compressed relation."""
        from pq_rbbc.blind_uov_hplus_research_v0_1.relation import (
            _require_statement,_validate_repetitions,_validate_gammas,QPolynomials,
        )
        _require_statement(statement)
        rows=_validate_repetitions(repetitions)
        if type(gammas) is not tuple or len(gammas)!=2:
            raise NativeProverError('gamma group shape')
        for group,f in zip(gammas,(_FIELDS[0],_FIELDS[2]),strict=True):
            _validate_gammas(group,f)
        def array(values):
            values=tuple(values)
            return (ctypes.c_uint16*len(values))(*values)
        # All values are validated before ctypes can truncate/convert them.
        arrays=(array(p.plain for row in rows for p in row.witness_polynomials),
                array(p.mask for row in rows for p in row.witness_polynomials),
                array(p.plain for row in rows for p in row.relation_masks),
                array(p.mask for row in rows for p in row.relation_masks),
                array(v for group in gammas for row in group for v in row))
        q=(ctypes.c_uint16*320)()
        qbar=(ctypes.c_uint16*320)()
        try:
            with self.bind(statement,threads=threads) as bound:
                # Serialize use against close on this context, like the base ABI.
                with bound._lock:
                    args=[bound._handle,_u8(bound._binding),32,_u8(bytes((12,12)+(11,)*16)),18]
                    for a in (*arrays,q,qbar):
                        args.extend((a,len(a)))
                    status=self._lib.pqsat_prover_q_batch_v1(*args)
                    if status:
                        raise NativeProverError('native prover q rejection, status '+str(status))
        except NativeRelationError as error:
            raise NativeProverError(str(error)) from error
        results=[]
        offset=0
        for r in range(18):
            rho=16 if r<2 else 18
            # QPolynomials independently revalidates output shapes/ranges/types.
            results.append(QPolynomials(_FIELDS[r],tuple(q[offset:offset+rho]),tuple(qbar[offset:offset+rho])))
            offset+=rho
        return tuple(results)
