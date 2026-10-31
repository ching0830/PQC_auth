"""Explicit ASan/UBSan smoke execution; never used for performance timing."""
import json
import os
from pathlib import Path
import subprocess
import sys

from build import BUILD, ROOT, build


def main():
    records = []
    for profile in ("ubsan", "asan"):
        record = build(profile)
        executable = BUILD / (profile + "-smoke")
        flags = [flag for flag in record["flags"] if flag not in ("-shared", "-fPIC")]
        # PIE ASan startup can conflict with address randomization on some
        # hosts. A fixed non-PIE test harness changes no kernel library flags.
        command = [record["compiler_path"], *flags, "-no-pie",
                   str(ROOT / "native/blind_uov_cap_v0_1/sanitizer_smoke.c"),
                   "-L" + str(BUILD), "-Wl,-rpath," + str(BUILD),
                   "-lpqsat_cap_relation_" + profile, "-o", str(executable)]
        subprocess.run(command, check=True, cwd=BUILD)
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",
                   UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
        result = subprocess.run([str(executable)], env=env, capture_output=True, text=True, cwd=BUILD)
        record.update(harness_command=command, run_command=[str(executable)],
                      exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr,
                      sanitizer_options={key: env[key] for key in ("ASAN_OPTIONS", "UBSAN_OPTIONS")})
        records.append(record)
        print(profile, "exit", result.returncode, result.stderr, flush=True)
    (BUILD / "sanitizers.json").write_text(json.dumps(records, indent=2) + "\n")
    return int(any(record["exit_code"] for record in records))


if __name__ == "__main__":
    sys.exit(main())
