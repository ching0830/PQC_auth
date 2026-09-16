#!/usr/bin/env python3
"""Reproducible benchmark for the exact experimental R_access proof.

The parent process runs each measured iteration in a fresh Python worker.  The
worker reports internal wall-clock phases and Linux whole-process peak RSS;
proof bytes never leave the worker and are not written to disk.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import resource
import statistics
import subprocess
import sys
import time
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from pq_sat_auth.v2.access import (
    ACCESS_REQUEST_PREFIX,
    REFERENCE_PROOF_SUITE_ID,
    REFERENCE_SUITE_ID,
    AccessRequestV2,
    ChannelBindingMode,
    derive_request_core_digest,
)
from pq_sat_auth.v2.framing import FRAME_HEADER
from pq_sat_auth.v2.proof import (
    AccessProofWitnessV2,
    build_access_statement,
    derive_holder_binding_tag,
    derive_holder_hash,
)
from pq_sat_auth.v2.prototypes.access_nizk.circuit import (
    build_exact_access_circuit,
)
from pq_sat_auth.v2.prototypes.access_nizk.mpcith import (
    MPCITHAccessNIZKBackendV01,
)
from pq_sat_auth.v2.prototypes.access_nizk.parameters import (
    BENCHMARK_PARAMETERS_V01,
    parameters_manifest,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_SEED_ID = "PQ-SAT/R-ACCESS-MPCITH/BENCHMARK-FIXTURE/v0.1"
ML_KEM_768_PUBLIC_KEY_BYTES = 1_184


def _digest(label: bytes) -> bytes:
    return hashlib.shake_256(BENCHMARK_SEED_ID.encode("ascii") + b"/" + label).digest(
        32
    )


def _fixture():
    witness = AccessProofWitnessV2(_digest(b"holder-secret"))
    request = AccessRequestV2(
        suite_id=REFERENCE_SUITE_ID,
        proof_suite_id=REFERENCE_PROOF_SUITE_ID,
        system_config_digest=_digest(b"system-config"),
        ctx=_digest(b"ctx"),
        epoch=20260916,
        target_fgs_id=_digest(b"fgs"),
        fgs_auth_key_id=_digest(b"fgs-auth-key"),
        serving_context_digest=_digest(b"serving-context"),
        authorization_digest=_digest(b"authorization"),
        client_time=1789488000,
        ue_nonce=_digest(b"ue-nonce"),
        attempt_nonce=_digest(b"attempt-nonce")[:16],
        channel_binding_mode=ChannelBindingMode.NONE,
        channel_binding_digest=bytes(32),
        ticket=b"canonical-ticket-length-not-benchmarked",
        ue_kem_epk=b"ml-kem-768-ek-length-accounted-separately",
        holder_binding_tag=bytes(32),
        access_nizk=b"proof-length-accounted-separately",
    )
    request = replace(
        request,
        holder_binding_tag=derive_holder_binding_tag(
            witness.holder_secret,
            derive_request_core_digest(request),
        ),
    )
    statement = build_access_statement(
        access_profile_digest=_digest(b"access-profile"),
        access_pp_digest=BENCHMARK_PARAMETERS_V01.digest,
        holder_hash=derive_holder_hash(witness.holder_secret),
        request=request,
    )
    return statement, witness


def _worker() -> int:
    worker_start = time.perf_counter_ns()
    setup_start = worker_start
    statement, witness = _fixture()
    backend = MPCITHAccessNIZKBackendV01(BENCHMARK_PARAMETERS_V01)
    setup_end = time.perf_counter_ns()

    circuit_start = setup_end
    circuit = build_exact_access_circuit(statement, witness)
    circuit_end = time.perf_counter_ns()

    proof, proving = backend.prove_profiled(statement, witness)
    verify_start = time.perf_counter_ns()
    verified = backend.verify(statement, proof)
    verify_end = time.perf_counter_ns()
    secret_plaintext_present = witness.holder_secret in proof
    peak_rss_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    result = {
        "setup_seconds": (setup_end - setup_start) / 1e9,
        "circuit_construction_seconds": (circuit_end - circuit_start) / 1e9,
        "preprocessing": {
            "applicable": False,
            "seconds": None,
            "reason": "this prototype has no reusable offline preprocessing phase",
        },
        "proving": asdict(proving),
        "verification_seconds": (verify_end - verify_start) / 1e9,
        "worker_wall_seconds": (verify_end - worker_start) / 1e9,
        "proof_sha256": hashlib.sha256(proof).hexdigest(),
        "proof_bytes": len(proof),
        "verified": verified,
        "holder_secret_plaintext_present": secret_plaintext_present,
        "circuit": circuit.metrics.as_dict(),
        "peak_rss_kib": peak_rss_kib,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if verified and not secret_plaintext_present else 1


def _run_worker(timeout_seconds: int) -> dict[str, object]:
    command = [sys.executable, str(Path(__file__).resolve()), "--worker"]
    completed = subprocess.run(
        command,
        cwd=REPOSITORY_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_seconds,
        check=False,
        env=dict(os.environ),
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"benchmark worker failed ({completed.returncode}): "
            f"{completed.stderr.strip()}"
        )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("benchmark worker returned non-JSON output") from error
    if not isinstance(result, dict):
        raise RuntimeError("benchmark worker returned non-object JSON")
    return result


def _stats(values: Sequence[float], *, scale: float = 1.0) -> dict[str, float]:
    if not values:
        raise ValueError("statistics require at least one sample")
    scaled = sorted(float(value) * scale for value in values)
    p95_index = max(0, math.ceil(0.95 * len(scaled)) - 1)
    return {
        "min": scaled[0],
        "median": statistics.median(scaled),
        "p95_nearest_rank": scaled[p95_index],
        "max": scaled[-1],
    }


def _git(command: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *command],
            cwd=REPOSITORY_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return completed.stdout.strip()


def _cpu_model() -> str | None:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        return None
    return None


def _memory_total_kib() -> int | None:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1])
    except (OSError, ValueError):
        return None
    return None


def _source_identities() -> dict[str, str]:
    relative_paths = (
        "src/pq_sat_auth/v2/proof.py",
        "src/pq_sat_auth/v2/prototypes/access_nizk/parameters.py",
        "src/pq_sat_auth/v2/prototypes/access_nizk/circuit.py",
        "src/pq_sat_auth/v2/prototypes/access_nizk/mpcith.py",
        "benchmarks/access_nizk/benchmark_r_access.py",
    )
    result = {}
    for relative in relative_paths:
        raw = (REPOSITORY_ROOT / relative).read_bytes()
        result[relative] = hashlib.sha256(raw).hexdigest()
    return result


def _main(warmups: int, iterations: int, timeout_seconds: int) -> int:
    if not 0 <= warmups <= 100:
        raise ValueError("warmups must be in [0, 100]")
    if not 1 <= iterations <= 100:
        raise ValueError("iterations must be in [1, 100]")

    benchmark_start = time.perf_counter_ns()
    warmup_failures = 0
    for _ in range(warmups):
        try:
            warmup = _run_worker(timeout_seconds)
            if warmup.get("verified") is not True:
                warmup_failures += 1
        except Exception:
            warmup_failures += 1

    measured: list[dict[str, object]] = []
    failures: list[str] = []
    for index in range(iterations):
        try:
            result = _run_worker(timeout_seconds)
        except Exception as error:
            failures.append(f"iteration {index}: {type(error).__name__}: {error}")
            continue
        if (
            result.get("verified") is not True
            or result.get("holder_secret_plaintext_present") is not False
        ):
            failures.append(f"iteration {index}: proof validation invariant failed")
        measured.append(result)
    benchmark_end = time.perf_counter_ns()
    if not measured:
        raise RuntimeError("no benchmark iteration completed")

    proving = [result["proving"] for result in measured]
    proof_sizes = sorted(set(int(result["proof_bytes"]) for result in measured))
    circuit_metrics = measured[0]["circuit"]
    for result in measured[1:]:
        if result["circuit"] != circuit_metrics:
            failures.append("circuit metrics differed across workers")
    if proof_sizes != [BENCHMARK_PARAMETERS_V01.proof_bytes]:
        failures.append("canonical proof length differed from parameters")

    fixed_framing_bytes = (
        FRAME_HEADER.size
        + ACCESS_REQUEST_PREFIX.size
        + 32  # holder_binding_tag
        + 12  # three uint32 Opaque length prefixes
    )
    subtotal_without_ticket = (
        fixed_framing_bytes
        + ML_KEM_768_PUBLIC_KEY_BYTES
        + BENCHMARK_PARAMETERS_V01.proof_bytes
    )
    git_status = _git(["status", "--short"])
    command = (
        "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python "
        "benchmarks/access_nizk/benchmark_r_access.py "
        f"--warmups {warmups} --iterations {iterations} "
        f"--timeout-seconds {timeout_seconds}"
    )
    output = {
        "format": "PQ-SAT-R-ACCESS-MPCITH-BENCHMARK-v0.1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "command": command,
        "benchmark_fixture_seed_id": BENCHMARK_SEED_ID,
        "git": {
            "head": _git(["rev-parse", "HEAD"]),
            "branch": _git(["branch", "--show-current"]),
            "working_tree_dirty": bool(git_status),
            "status_short": git_status.splitlines() if git_status else [],
            "source_file_sha256": _source_identities(),
        },
        "host": {
            "os": platform.platform(),
            "kernel": platform.release(),
            "machine": platform.machine(),
            "cpu_model": _cpu_model(),
            "logical_cpu_count": os.cpu_count(),
            "memory_total_kib": _memory_total_kib(),
            "python": sys.version,
            "python_implementation": platform.python_implementation(),
            "compiler_flags": "not applicable; pure Python prototype",
            "external_runtime_dependencies": [],
        },
        "parameters": parameters_manifest(BENCHMARK_PARAMETERS_V01),
        "sampling": {
            "warmup_iterations": warmups,
            "warmup_failures": warmup_failures,
            "measured_iterations_requested": iterations,
            "measured_iterations_completed": len(measured),
            "failures": len(failures),
            "failure_messages": failures,
            "success_rate": (iterations - len(failures)) / iterations,
            "wall_clock_seconds_including_workers": (
                benchmark_end - benchmark_start
            )
            / 1e9,
            "worker_model": "one fresh Python process per warmup/iteration",
        },
        "exact_measured": {
            "canonical_proof_bytes": proof_sizes[0],
            "proof_sha256_per_iteration": [
                result["proof_sha256"] for result in measured
            ],
            "setup_ms": _stats(
                [float(result["setup_seconds"]) for result in measured],
                scale=1000,
            ),
            "circuit_construction_ms": _stats(
                [
                    float(result["circuit_construction_seconds"])
                    for result in measured
                ],
                scale=1000,
            ),
            "preprocessing": measured[0]["preprocessing"],
            "randomness_and_sharing_ms": _stats(
                [
                    float(item["randomness_and_sharing_seconds"])
                    for item in proving
                ],
                scale=1000,
            ),
            "mpc_simulation_and_commitment_ms": _stats(
                [
                    float(item["mpc_simulation_and_commitment_seconds"])
                    for item in proving
                ],
                scale=1000,
            ),
            "fiat_shamir_challenge_ms": _stats(
                [
                    float(item["fiat_shamir_challenge_seconds"])
                    for item in proving
                ],
                scale=1000,
            ),
            "proof_serialization_ms": _stats(
                [
                    float(item["proof_serialization_seconds"])
                    for item in proving
                ],
                scale=1000,
            ),
            "ue_side_prover_workload_proxy_ms": _stats(
                [float(item["online_prove_seconds"]) for item in proving],
                scale=1000,
            ),
            "fgs_verification_workload_proxy_ms": _stats(
                [float(result["verification_seconds"]) for result in measured],
                scale=1000,
            ),
            "fresh_worker_total_ms": _stats(
                [float(result["worker_wall_seconds"]) for result in measured],
                scale=1000,
            ),
            "fresh_worker_peak_rss_kib": _stats(
                [float(result["peak_rss_kib"]) for result in measured]
            ),
            "peak_rss_scope": (
                "Linux ru_maxrss for a fresh worker; includes interpreter, setup, "
                "circuit construction, proof generation, proof bytes, and verification"
            ),
            "circuit": circuit_metrics,
        },
        "analytical_estimates": {
            "classical_interactive_soundness_bits": (
                BENCHMARK_PARAMETERS_V01.claimed_classical_soundness_bits
            ),
            "soundness_basis": (
                "floor(t*log2(3/2)); excludes Fiat-Shamir/QROM and implementation review"
            ),
            "m1_bytes": {
                "ticket_bytes": None,
                "ticket_status": "unmeasured; not assumed to be zero",
                "access_request_v2_fixed_and_framing_bytes": fixed_framing_bytes,
                "ml_kem_768_ue_public_key_bytes": ML_KEM_768_PUBLIC_KEY_BYTES,
                "measured_pi_access_bytes": BENCHMARK_PARAMETERS_V01.proof_bytes,
                "subtotal_excluding_ticket_bytes": subtotal_without_ticket,
                "full_formula": f"ticket_bytes + {subtotal_without_ticket}",
                "fits_current_262144_byte_reference_proof_limit": (
                    BENCHMARK_PARAMETERS_V01.proof_bytes <= 262_144
                ),
            },
        },
        "unmeasured": {
            "real_mobile_or_satellite_ue_latency": True,
            "ue_energy": True,
            "satellite_path_latency": True,
            "satellite_or_mobile_peak_memory": True,
            "production_ticket_bytes": True,
        },
        "interpretation": {
            "host_specific": True,
            "prover_timing_label": "UE-side prover workload proxy",
            "verification_timing_label": "FGS verification workload proxy",
            "exact_r_access_proved": True,
            "experimental_reference_only": True,
            "production_ready": False,
            "simulation_extractable": False,
            "proof_closed": False,
            "production_closed": False,
            "ake_material_5629_bytes_is_not_full_access_total": True,
        },
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if not failures and warmup_failures == 0 else 1


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args(sys.argv[1:])
    if args.worker:
        raise SystemExit(_worker())
    raise SystemExit(_main(args.warmups, args.iterations, args.timeout_seconds))
