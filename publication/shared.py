"""Existing public I/O helpers, extracted without changing function bodies.

See provenance/source_inventory.json for original source identities.
"""
from contextlib import contextmanager
import ctypes
import fcntl
import hashlib
import os
import resource
import stat
import sys

def bounded(path, cap):
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as source:
        info=os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>cap:
            raise ValueError('bounded regular public input')
        raw=source.read(cap+1)
    if len(raw)>cap:raise ValueError('public input grew beyond cap')
    return raw

@contextmanager
def sealed_public(raw, cap):
    """Bind native verification to the exact bytes the NCC just reconstructed."""
    if type(raw) is not bytes or not 0<len(raw)<=cap:raise ValueError('bounded immutable public snapshot')
    if sys.platform!='linux':raise ValueError('Linux sealed public snapshot required')
    # This Conda Python omits os.memfd_create and the fcntl seal constants.
    # Use libc with Linux UAPI values checked against local linux/{memfd,fcntl}.h.
    libc=ctypes.CDLL(None,use_errno=True)
    create=libc.memfd_create;create.argtypes=[ctypes.c_char_p,ctypes.c_uint];create.restype=ctypes.c_int
    fd=create(b'NCC-public-NIFS',0x0001|0x0002)  # MFD_CLOEXEC | MFD_ALLOW_SEALING
    if fd<0:raise OSError(ctypes.get_errno(),'sealed public snapshot unavailable')
    try:
        view=memoryview(raw)
        while view:
            written=os.write(fd,view)
            if written<=0:raise ValueError('public snapshot write')
            view=view[written:]
        os.lseek(fd,0,os.SEEK_SET)
        required=0x0008|0x0004|0x0002|0x0001  # WRITE | GROW | SHRINK | SEAL
        fcntl.fcntl(fd,1033,required)  # F_ADD_SEALS
        if fcntl.fcntl(fd,1034)&required!=required:raise ValueError('public snapshot sealing')
        yield fd
    finally:os.close(fd)

def wire_measurement(setup_bytes, request_bytes, response_bytes, issuer, proof_bytes, statement_bytes):
    if ([setup_bytes, request_bytes, response_bytes] !=
            [issuer['setup_wire_bytes'], issuer['request_wire_bytes'], issuer['response_wire_bytes']]
            or request_bytes != 11 + 8 + statement_bytes + proof_bytes or response_bytes != 11 + 32 + 184):
        raise ValueError('both peers agree on actual framed bytes')
    if any(type(x) is not int or x <= 0 for x in (setup_bytes, request_bytes, response_bytes)):
        raise ValueError('actual integer wire counters')
    return dict(codec='NIC1/v1 binary RAM pipe', setup_NCC_to_UE_bytes=setup_bytes,
        request_UE_to_NCC_bytes=request_bytes, response_NCC_to_UE_bytes=response_bytes,
        issuance_both_directions_without_setup_bytes=request_bytes + response_bytes,
        issuance_both_directions_including_setup_bytes=setup_bytes + request_bytes + response_bytes,
        issuer_telemetry_in_codec=False, final_CAP_verifier_IPC_in_issuance_codec=False,
        network_overhead_bytes=None, complete_production_issuance_bytes=None)

def validate_transfer(proof, statement, native_prove, proof_pin, statement_pin):
    """Bind the actual outgoing bytes to the measured public producer outputs."""
    for raw, pin, length in ((proof, proof_pin, native_prove['proof_body_bytes']),
                             (statement, statement_pin, native_prove['statement_bytes'])):
        if len(raw) != length or dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) != pin:
            raise ValueError('measured producer and outgoing bytes differ')

def check_limits():
    if os.environ.get('BUOV_CAP_EXPLORATION_GUARDED')!='1':raise ValueError('invoke through qualified shared-lock runner')
    for kind,maximum in ((resource.RLIMIT_AS,8<<30),(resource.RLIMIT_FSIZE,1<<30),(resource.RLIMIT_CPU,1802)):
        soft=resource.getrlimit(kind)[0]
        if soft==resource.RLIM_INFINITY or not 0<soft<=maximum:
            raise ValueError('inherited finite resource cap required')
