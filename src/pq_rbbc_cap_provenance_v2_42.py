"""Read-only exact PDF provenance verification; no security or review approval."""

import argparse
import os
from pathlib import Path
import stat

import pq_rbbc_cap_unified_tree_recovery_v2_42 as recovery
import pq_rbbc_launch_io_v2_41 as io


MAX_PDF_BYTES = 2 << 20


def validate_pdf(snapshot: io.Snapshot, source: str):
    _, provenance = recovery.contract_snapshots()
    document = provenance.document()
    if source not in document["sources"]:
        raise io.ValidationError("unknown provenance source role")
    expected = document["sources"][source]["pdf_identity"]
    if snapshot.identity != expected or not snapshot.raw.startswith(b"%PDF-"):
        raise io.ValidationError("exact PDF revision/bytes/SHA-256 required")
    return snapshot.identity


def capture_pdf(path: Path, *, artifact_root: Path):
    root = io.ArtifactRoot(artifact_root)
    path = root.require_location(path)
    with io.directory_fd(path.parent, external=True) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        with os.fdopen(fd, "rb", buffering=0) as handle:
            before = os.fstat(handle.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or not 0 < before.st_size <= MAX_PDF_BYTES):
                raise io.ValidationError("bounded single-link regular PDF required")
            raw = handle.read(MAX_PDF_BYTES + 1)
            after = os.fstat(handle.fileno())
            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if (signature(before) != signature(after) or signature(after) != signature(current)
                    or not 0 < len(raw) <= MAX_PDF_BYTES or len(raw) != after.st_size):
                raise io.ValidationError("PDF capture changed or exceeded bound")
        io._same_directory(path.parent, parent, external=True)
    # As in v2.41, metadata signals are best effort; only captured raw defines
    # identity. No PDF deserializer, network fetch or latest-revision fallback.
    return io.Snapshot(path, raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", type=Path, required=True)
    args = parser.parse_args()
    _, snapshot = recovery.contract_snapshots()
    provenance = snapshot.document()
    verified = {}
    for source, entry in provenance["sources"].items():
        path = args.artifact_root / entry["pdf_identity"]["filename"]
        verified[source] = validate_pdf(capture_pdf(path, artifact_root=args.artifact_root), source)
    print(io.canonical_json({"verified_pdf_identities": verified,
                             "cap_security_qualified": False,
                             "production_closed": False}).decode(), end="")


if __name__ == "__main__":
    main()
