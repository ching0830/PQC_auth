"""Bounded immutable JSON snapshots and exclusive publication for v2.41.

Linux/POSIX filesystem boundary. The caller provisions the trusted artifact
root; candidate documents cannot select it. No pickle or shell execution.
"""

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid


MAX_JSON_BYTES = 1 << 20


class ValidationError(ValueError):
    """A controlled, fail-closed artifact rejection."""


def canonical_json(document: object) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("duplicate JSON key")
        result[key] = value
    return result


def _no_number(value):
    raise ValidationError("non-integer JSON number")


def _unicode_scalars(value):
    if type(value) is str:
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise ValidationError("unpaired Unicode surrogate")
    elif type(value) is dict:
        for key, child in value.items():
            _unicode_scalars(key)
            _unicode_scalars(child)
    elif type(value) is list:
        for child in value:
            _unicode_scalars(child)


def strict_json(raw: bytes) -> dict:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_JSON_BYTES:
        raise ValidationError("JSON byte limit")
    try:
        document = json.loads(raw.decode("utf-8", errors="strict"),
                              object_pairs_hook=_pairs, parse_constant=_no_number,
                              parse_float=_no_number)
        _unicode_scalars(document)
        if type(document) is not dict or raw != canonical_json(document):
            raise ValidationError("noncanonical JSON object")
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValidationError("strict JSON rejected: " + str(error)) from error
    return document


@dataclass(frozen=True)
class Snapshot:
    location: Path
    raw: bytes

    def __post_init__(self):
        if type(self.raw) is not bytes:
            raise ValidationError("snapshot requires immutable bytes")

    @property
    def identity(self) -> dict:
        return {"filename": self.location.name, "bytes": len(self.raw),
                "sha256": hashlib.sha256(self.raw).hexdigest()}

    def document(self) -> dict:
        # A fresh parse prevents caller mutation of a cached parsed object from
        # changing the meaning attached to this immutable byte identity.
        return strict_json(self.raw)


def exact_path(path: Path) -> Path:
    path = Path(path)
    if not path.is_absolute() or path.anchor != "/" or ".." in path.parts:
        raise ValidationError("canonical absolute location required")
    return path


def _inode(info):
    return info.st_dev, info.st_ino


@contextmanager
def directory_fd(path: Path, *, external: bool):
    """Walk without following any symlink; retain the destination directory FD.

    External paths reject every Git worktree ancestor, untrusted owners and
    writable non-sticky ancestors. The final artifact directory must be owned
    by this uid and have no group/other write permission. Root-owned sticky
    /tmp is an allowed ancestor, never an allowed artifact root.
    """
    path = exact_path(path)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    # User namespaces can map the system root owner to an overflow uid.
    # Anchor trust in the opened filesystem root, not a guessed numeric uid.
    root_owner = os.fstat(fd).st_uid
    try:
        for part in (None, *path.parts[1:]):
            if part is not None:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            if external:
                try:
                    git_info = os.stat(".git", dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    if not stat.S_ISDIR(git_info.st_mode):
                        raise ValidationError("repository worktree is not an artifact root")
                    git_fd = os.open(".git", os.O_RDONLY | os.O_DIRECTORY |
                                     os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    try:
                        # Empty sandbox protection mounts are not repositories.
                        # An actual Git directory has HEAD/config; linked
                        # worktree gitfiles were rejected above.
                        for marker in ("HEAD", "config"):
                            try:
                                os.stat(marker, dir_fd=git_fd, follow_symlinks=False)
                            except FileNotFoundError:
                                continue
                            raise ValidationError("repository worktree is not an artifact root")
                    finally:
                        os.close(git_fd)
                if info.st_uid not in (root_owner, os.geteuid()):
                    raise ValidationError("untrusted directory owner")
                if info.st_mode & 0o022 and not (
                    info.st_uid == root_owner and info.st_mode & stat.S_ISVTX
                ):
                    raise ValidationError("writable artifact ancestor")
        if external and (info.st_uid != os.geteuid() or info.st_mode & 0o022):
            raise ValidationError("artifact directory must be privately writable")
        yield fd
    finally:
        os.close(fd)


def _same_directory(path: Path, fd: int, *, external: bool):
    with directory_fd(path, external=external) as current:
        if _inode(os.fstat(current)) != _inode(os.fstat(fd)):
            raise ValidationError("directory location changed during operation")


def read_snapshot(path: Path, *, external: bool = False) -> Snapshot:
    path = exact_path(path)
    with directory_fd(path.parent, external=external) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                     os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, "rb", buffering=0) as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ValidationError("single-link regular file required")
            if before.st_size > MAX_JSON_BYTES:
                raise ValidationError("artifact byte limit")
            # One open, one bounded read: stat is never used as the byte length
            # in an identity. All subsequent operations consume only raw.
            raw = handle.read(MAX_JSON_BYTES + 1)
            after = os.fstat(handle.fileno())
            signature = lambda s: (_inode(s), s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if signature(before) != signature(after) or len(raw) != after.st_size:
                raise ValidationError("file changed during snapshot read")
            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if signature(current) != signature(after):
                raise ValidationError("file location changed during snapshot read")
        _same_directory(path.parent, parent, external=external)
    if not 0 < len(raw) <= MAX_JSON_BYTES:
        raise ValidationError("artifact byte limit")
    return Snapshot(path, raw)


class ArtifactRoot:
    """An explicitly selected trust root, not an untrusted document field."""

    def __init__(self, root: Path):
        self.root = exact_path(root)

    def require_location(self, path: Path):
        path = exact_path(path)
        if not path.is_relative_to(self.root) or path == self.root:
            raise ValidationError("location outside trusted artifact root")
        # Check the root itself even if the requested parent is a descendant.
        with directory_fd(self.root, external=True):
            pass
        return path

    def read(self, path: Path) -> Snapshot:
        return read_snapshot(self.require_location(path), external=True)

    def write(self, path: Path, document: object):
        publish_exclusive(self.require_location(path), canonical_json(document),
                          external=True)


def publish_exclusive(path: Path, raw: bytes, *, external: bool):
    """Publish complete bytes using atomic link-if-absent; never truncate.

    Both existing and dangling destination symlinks make link fail with EEXIST.
    A failed/crashed writer cannot expose a partially written final JSON file.
    A crash can leave an unreferenced temporary file, never a valid final report.
    """
    path = exact_path(path)
    with directory_fd(path.parent, external=external) as parent:
        temporary = ".pq-rbbc-v241-" + uuid.uuid4().hex + ".tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            _same_directory(path.parent, parent, external=external)
            os.link(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent,
                    follow_symlinks=False)
            _same_directory(path.parent, parent, external=external)
        finally:
            os.unlink(temporary, dir_fd=parent)
            os.fsync(parent)
