"""Explicit C17 build; importing this module never invokes the compiler."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
BUILD = Path("/tmp/pqsat_cap_native_relation_build_v0_1")
FLAGS = ("-O3", "-std=c17", "-fPIC", "-shared", "-fopenmp", "-Wall", "-Wextra", "-Werror")


def build(profile: str) -> dict:
    if profile not in ("portable", "native", "ubsan", "asan", "allocation-failure"):
        raise ValueError("unknown build profile")
    compiler = str(Path(shutil.which("gcc") or "/missing/gcc").resolve())
    flags = list(FLAGS)
    if profile == "native":
        flags.append("-march=native")
    elif profile in ("ubsan", "asan"):
        flags += ["-g", "-fno-omit-frame-pointer", "-fno-sanitize-recover=all",
                  "-fsanitize=" + ("undefined" if profile == "ubsan" else "address,undefined")]
    elif profile == "allocation-failure":
        flags.append("-DPQSAT_CAP_TEST_ALLOC_FAIL=1")
    BUILD.mkdir(parents=True, exist_ok=True)
    output = BUILD / ("libpqsat_cap_relation_" + profile + ".so")
    command = [compiler, *flags, str(ROOT / "native/blind_uov_cap_v0_1/relation.c"), "-o", str(output)]
    subprocess.run(command, check=True, cwd=BUILD)
    raw = output.read_bytes()
    record = {
        "profile": profile, "compiler_path": compiler,
        "compiler_version": subprocess.check_output([compiler, "--version"], text=True).strip(),
        "flags": flags, "command": command, "library_path": str(output),
        "library_bytes": len(raw), "library_sha256": hashlib.sha256(raw).hexdigest(),
        "dynamic_dependencies": subprocess.check_output(["ldd", str(output)], text=True).strip(),
        "cross_compiler_reproducible_claim": False,
    }
    (BUILD / ("build_" + profile + ".json")).write_text(json.dumps(record, indent=2) + "\n")
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=("portable", "native", "ubsan", "asan", "allocation-failure"))
    print(json.dumps(build(parser.parse_args().profile), indent=2))
