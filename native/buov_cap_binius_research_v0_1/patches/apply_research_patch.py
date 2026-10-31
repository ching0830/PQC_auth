#!/usr/bin/env python3
"""Apply the identity-checked research patch to a clean explicit local fork only."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


PACKAGE = Path(__file__).resolve().parent
PATCH_NAMES = ("shared_cs_streaming_wiring_v0_1", "streaming_keys_v0_1")
PINNED_BASENAME = "binius64-4428e759"


def digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"not a regular non-symlink source: {path.name}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(fork: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(fork), *args], text=True, stderr=subprocess.PIPE
    ).strip()


def apply(fork: Path, *, check_only: bool, workspace: bool = False, bounded: bool = False, parallel: bool = False) -> dict:
    fork = fork.resolve(strict=True)
    if not fork.is_dir() or fork.name == PINNED_BASENAME:
        raise ValueError("an explicit clean research fork is required; pinned upstream is immutable")
    names = PATCH_NAMES + (("masked_encode_workspace_v0_1", "compact_operands_v0_1") if workspace else ())
    if bounded:
        if not workspace: raise ValueError("bounded profile requires workspace overlays")
        names += ("research_oracle_schedule_v0_1", "bounded_prover_workspace_v0_1", "checkpoint_merkle_v0_1", "regenerated_masks_v0_1")
    if parallel:
        if not bounded: raise ValueError("parallel profile requires bounded overlays")
        names += ("bounded_parallel_v0_1",)
    identities = [json.loads((PACKAGE / f"{name}.json").read_text()) for name in names]
    identity = identities[0]
    patches = [PACKAGE / f"{name}.patch" for name in names]
    for patch, current in zip(patches, identities, strict=True):
        if current["upstream_commit"] != identity["upstream_commit"]:
            raise ValueError("patch bundle has inconsistent bases")
        if digest(patch) != current["patch_sha256"]:
            raise ValueError("patch identity mismatch")
    if command(fork, "rev-parse", "--show-toplevel") != str(fork):
        raise ValueError("fork must be its own Git checkout")
    if command(fork, "rev-parse", "HEAD") != identity["upstream_commit"]:
        raise ValueError("fork base commit mismatch")
    if command(fork, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("fork must have no tracked changes")
    # Validate ordered overlays in a bounded public-only staging directory.
    # No target source is written until all patches and per-step hashes pass.
    final = {}
    first = {}
    for current in identities:
        for item in current["files"]:
            relative = Path(item["path"])
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("non-canonical inventory source path")
            path = fork / relative
            if path.is_symlink() or not path.resolve().is_relative_to(fork):
                raise ValueError("source path escapes fork")
            if item["path"] not in first:
                first[item["path"]] = item["base_sha256"]
            expected = final.get(item["path"], item["base_sha256"])
            if expected != item["base_sha256"]:
                raise ValueError("ordered patch base identity mismatch")
            final[item["path"]] = item["patched_sha256"]
    if len(final) > 64:
        raise ValueError("bounded research patch file set")
    with tempfile.TemporaryDirectory(prefix="binius-public-patch-", dir=fork.parent) as temporary:
        stage = Path(temporary)
        for name, base in first.items():
            source, destination = fork / name, stage / name
            if base is None:
                if source.exists() or source.is_symlink():
                    raise ValueError("new patch source already exists")
            else:
                if digest(source) != base or source.stat().st_size > 1 << 20:
                    raise ValueError("bounded source base identity mismatch")
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(source.read_bytes())
        for patch, current in zip(patches, identities, strict=True):
            command(stage, "apply", "--check", str(patch))
            command(stage, "apply", str(patch))
            for item in current["files"]:
                if digest(stage / item["path"]) != item["patched_sha256"]:
                    raise ValueError("patched source mismatch")
        if not check_only:
            for name, expected in final.items():
                target = fork / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((stage / name).read_bytes())
                if digest(target) != expected:
                    raise ValueError("final patched source mismatch")
    return {
        "schema": "pqsat.binius-research-patch-application.v0.1",
        "upstream_commit": identity["upstream_commit"],
        "patches": [
            {"name": name, "sha256": current["patch_sha256"]}
            for name, current in zip(names, identities, strict=True)
        ],
        "files": len(final),
        "check_only": check_only,
        "applied": not check_only,
        "security_parameters_changed": False,
        "research_commitment_layout_changed": bounded,
        "production_profile": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fork", type=Path)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--workspace", action="store_true")
    parser.add_argument("--bounded", action="store_true")
    parser.add_argument("--parallel", action="store_true")
    args = parser.parse_args()
    print(json.dumps(apply(args.fork, check_only=args.check_only, workspace=args.workspace, bounded=args.bounded, parallel=args.parallel), sort_keys=True))


if __name__ == "__main__":
    main()
