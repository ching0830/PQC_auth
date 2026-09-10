"""Linux-only append-only publication for bounded recovery, never authorization.

An unnamed O_TMPFILE is fsynced then linked if absent. No named staging file or
extra hard link survives process death. Directory flock serializes cooperating
writers and is released on process death. It does NOT exclude a malicious writer
with the same credentials, writable FDs, ACLs or mount control; trusted producer
handoff and writer quiescence remain deployment prerequisites.
"""

from contextlib import contextmanager
import ctypes
import fcntl
import os
from pathlib import Path

import pq_rbbc_launch_io_v2_41 as io


@contextmanager
def locked_output(output: Path, artifact_root: Path, *, fresh: bool):
    root = io.ArtifactRoot(artifact_root)
    output = root.require_location(output)
    if output.parent != root.root:
        raise io.ValidationError("output must be a direct child of trusted root")
    with io.directory_fd(root.root, external=True) as parent:
        if fresh:
            os.mkdir(output.name, mode=0o700, dir_fd=parent)
            os.fsync(parent)
        with io.directory_fd(output, external=True) as fd:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise io.ValidationError("another bounded writer holds output") from error
            try:
                io._same_directory(output, fd, external=True)
                yield fd
                io._same_directory(output, fd, external=True)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)


def publish(path: Path, raw: bytes):
    """Atomic exclusive creation; EEXIST includes dangling destination symlinks.

Requires Linux O_TMPFILE, procfs FD links and linkat. Unsupported filesystems
fail closed; there is no truncate/replace fallback. fsync errors propagate.
"""
    if type(raw) is not bytes or not 0 < len(raw) <= io.MAX_JSON_BYTES:
        raise io.ValidationError("bounded publication byte limit")
    with io.directory_fd(path.parent, external=True) as parent:
        fd = os.open(".", os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        try:
            with os.fdopen(os.dup(fd), "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            io._same_directory(path.parent, parent, external=True)
            libc = ctypes.CDLL(None, use_errno=True)
            linkat = libc.linkat
            linkat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                               ctypes.c_char_p, ctypes.c_int]
            linkat.restype = ctypes.c_int
            # AT_FDCWD and AT_SYMLINK_FOLLOW refer only to our own open FD.
            # The destination name is never dereferenced or replaced.
            if linkat(-100, f"/proc/self/fd/{fd}".encode(), parent,
                      os.fsencode(path.name), 0x400) != 0:
                code = ctypes.get_errno()
                raise OSError(code, os.strerror(code), str(path))
            os.fsync(parent)
            io._same_directory(path.parent, parent, external=True)
        finally:
            os.close(fd)


def read(path: Path) -> io.Snapshot:
    return io.read_snapshot(path, external=True)


def sync_directory(path: Path, fd: int):
    """Persist validated existing entries through their pinned parent directory.

    A prior publisher may have died after linkat but before directory fsync.
    Reading exact bytes does not discharge that missing durability barrier.
    Validate the pinned directory before and after fsync; errors propagate.
    This neither rewrites files nor proves writer quiescence or mount safety.
    """
    io._same_directory(path, fd, external=True)
    os.fsync(fd)
    io._same_directory(path, fd, external=True)
