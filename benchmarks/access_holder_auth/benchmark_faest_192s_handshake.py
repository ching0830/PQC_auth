#!/usr/bin/env python3
"""Benchmark the isolated FAEST-192s holder-authentication handshake."""

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
from datetime import datetime, timezone
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Callable, Sequence

from pq_sat_auth.v2.prototypes.holder_auth_v3.codec import (
    ACCESS_SUITE_ID,
    FAEST_192S_PARAMETER_DIGEST,
    HOLDER_SUITE_FAEST_192S,
    decode_access_request,
)
from pq_sat_auth.v2.prototypes.holder_auth_v3.providers import (
    FAEST_REFERENCE_COMMIT,
    FAEST192sReferenceProvider,
    PQCryptoMLDSA65Provider,
    PQCryptoMLKEM768Provider,
)
from pq_sat_auth.v2.prototypes.holder_auth_v3.suite import (
    run_experimental_handshake,
)


ROOT = Path(__file__).resolve().parents[2]
D4_BASELINE_PATH = (
    ROOT
    / "benchmarks/access_holder_auth/results_ml_dsa_65_handshake_d4_20260916.json"
)
D4_BASELINE_SHA256 = (
    "c974994a65f9d4b01d40d7db8184f9ce02bfa403ef9f185111ea3911f4f29be2"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _measure(operation: Callable[[], object], iterations: int) -> list[float]:
    values = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        operation()
        values.append((time.perf_counter_ns() - started) / 1e6)
    return values


def _stats(values: Sequence[float]) -> dict[str, float]:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        raise ValueError("statistics require at least one sample")
    p95 = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return {
        "min_ms": ordered[0],
        "median_ms": statistics.median(ordered),
        "p95_nearest_rank_ms": ordered[p95],
        "max_ms": ordered[-1],
    }


def _git(cwd: Path, *arguments: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=cwd,
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
    paths = (
        "src/pq_sat_auth/v2/prototypes/holder_auth_v3/codec.py",
        "src/pq_sat_auth/v2/prototypes/holder_auth_v3/providers.py",
        "src/pq_sat_auth/v2/prototypes/holder_auth_v3/suite.py",
        "tests/prototypes/holder_auth_v3/test_faest_holder_auth_handshake.py",
        "benchmarks/access_holder_auth/benchmark_faest_192s_handshake.py",
    )
    return {
        path: _sha256(ROOT / path)
        for path in paths
    }


def _validate_faest_external_inputs(
    *,
    library: Path,
    library_sha256: str,
    source_dir: Path,
    api_test: Path,
    api_test_sha256: str,
) -> dict[str, object]:
    if not library.is_absolute() or not source_dir.is_absolute() or not api_test.is_absolute():
        raise ValueError("FAEST external input paths must be absolute")
    if _sha256(library) != library_sha256:
        raise ValueError("FAEST shared-library identity mismatch")
    if _sha256(api_test) != api_test_sha256:
        raise ValueError("FAEST API-test identity mismatch")

    revision = _git(source_dir, "rev-parse", "HEAD")
    if revision != FAEST_REFERENCE_COMMIT:
        raise ValueError("FAEST source revision mismatch")
    source_status = _git(source_dir, "status", "--short")
    if source_status:
        raise ValueError("FAEST source checkout must be clean")

    meson_path = source_dir / "meson.build"
    meson = meson_path.read_text(encoding="utf-8")
    required_fragments = (
        "version: '3.0.0'",
        "param_192s.set('SIG_SIZE', 9410)",
        "param_192s.set('PK_SIZE', 48)",
        "param_192s.set('SK_SIZE', 40)",
    )
    if any(fragment not in meson for fragment in required_fragments):
        raise ValueError("FAEST source parameter identity mismatch")

    completed = subprocess.run(
        [str(api_test)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if completed.stdout.strip() != "Sign/Verify test passed":
        raise RuntimeError("official FAEST API self-test did not report success")

    build_dir = library.parent
    config_path = build_dir / "config.h"
    header_path = build_dir / "faest_192s.h"
    return {
        "source_repository": "https://github.com/faest-sign/faest-ref",
        "source_commit": revision,
        "source_release_tag": None,
        "source_version": "3.0.0",
        "source_clean": True,
        "source_meson_sha256": _sha256(meson_path),
        "library_path_external_not_committed": str(library),
        "library_bytes": library.stat().st_size,
        "library_sha256": library_sha256,
        "api_test_path_external_not_committed": str(api_test),
        "api_test_bytes": api_test.stat().st_size,
        "api_test_sha256": api_test_sha256,
        "official_api_self_test_passed": True,
        "official_known_answer_test_checked": False,
        "build_config_sha256": _sha256(config_path),
        "generated_faest_192s_header_sha256": _sha256(header_path),
        "build_features": {
            "buildtype": "release",
            "march_native": True,
            "aesni": True,
            "avx2_available": True,
            "sha3": "opt64",
        },
    }


def _load_d4_baseline() -> dict[str, object]:
    if _sha256(D4_BASELINE_PATH) != D4_BASELINE_SHA256:
        raise ValueError("D4 ML-DSA baseline identity mismatch")
    return json.loads(D4_BASELINE_PATH.read_text(encoding="utf-8"))


def _main(
    *,
    iterations: int,
    warmups: int,
    library: Path,
    library_sha256: str,
    source_dir: Path,
    api_test: Path,
    api_test_sha256: str,
) -> dict[str, object]:
    if not 1 <= iterations <= 1_000:
        raise ValueError("iterations must be in [1, 1000]")
    if not 0 <= warmups <= 100:
        raise ValueError("warmups must be in [0, 100]")

    external = _validate_faest_external_inputs(
        library=library,
        library_sha256=library_sha256,
        source_dir=source_dir,
        api_test=api_test,
        api_test_sha256=api_test_sha256,
    )
    d4_baseline = _load_d4_baseline()
    faest = FAEST192sReferenceProvider(str(library), library_sha256)
    fgs = PQCryptoMLDSA65Provider()
    kem = PQCryptoMLKEM768Provider()

    for _ in range(warmups):
        run_experimental_handshake(
            holder_provider=faest,
            fgs_provider=fgs,
            kem_provider=kem,
            holder_suite_id=HOLDER_SUITE_FAEST_192S,
        )

    artifacts = run_experimental_handshake(
        holder_provider=faest,
        fgs_provider=fgs,
        kem_provider=kem,
        holder_suite_id=HOLDER_SUITE_FAEST_192S,
    )
    request = decode_access_request(artifacts.request_bytes)
    signing_input = request.holder_signing_input()
    public_key, secret_key = faest.generate_keypair()

    keygen_ms = _measure(faest.generate_keypair, iterations)
    signatures: list[bytes] = []

    def sign_operation() -> None:
        signatures.append(faest.sign(secret_key, signing_input))

    sign_ms = _measure(sign_operation, iterations)
    signature_index = 0

    def verify_operation() -> None:
        nonlocal signature_index
        signature = signatures[signature_index % len(signatures)]
        signature_index += 1
        if not faest.verify(public_key, signing_input, signature):
            raise RuntimeError("FAEST-192s verification failed")

    verify_ms = _measure(verify_operation, iterations)

    handshake_sizes: set[tuple[int, ...]] = set()

    def handshake_operation() -> None:
        result = run_experimental_handshake(
            holder_provider=faest,
            fgs_provider=fgs,
            kem_provider=kem,
            holder_suite_id=HOLDER_SUITE_FAEST_192S,
        )
        handshake_sizes.add(
            (
                len(result.ticket_bytes),
                len(result.request_bytes),
                len(result.response_bytes),
                len(result.activation_bytes),
                len(result.first_application_record_bytes),
                result.explicit_m3_total_bytes,
                result.first_record_total_bytes,
            )
        )

    full_handshake_ms = _measure(handshake_operation, iterations)
    expected_sizes = {(12_126, 23_094, 4_755, 198, 377, 28_047, 28_226)}
    if handshake_sizes != expected_sizes:
        raise RuntimeError("FAEST wire sizes drifted across handshake iterations")

    status = _git(ROOT, "status", "--short")
    ml_dsa_wire = d4_baseline["wire_bytes"]
    ml_dsa_timing = d4_baseline["timing"]
    result = {
        "format": "PQ-SAT-R-ACCESS-HOLDER-AUTH-D4B-FAEST-BENCHMARK-v0.1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "git": {
            "head": _git(ROOT, "rev-parse", "HEAD"),
            "branch": _git(ROOT, "branch", "--show-current"),
            "working_tree_dirty": bool(status),
            "status_short": status.splitlines() if status else [],
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
            "python_executable": sys.executable,
            "process_peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        },
        "dependencies": {
            "faest_reference": faest.package_version,
            "pqcrypto": fgs.package_version,
            "cffi": package_version("cffi"),
            "provider_production_ready": False,
        },
        "external_faest_provider": external,
        "profile": {
            "access_suite_id": ACCESS_SUITE_ID,
            "holder_suite_id": HOLDER_SUITE_FAEST_192S,
            "holder_suite": "FAEST-192s-v3",
            "holder_parameter_digest_sha256": FAEST_192S_PARAMETER_DIGEST.hex(),
            "holder_signing_input_bytes": len(signing_input),
            "issuer_signature_bytes_status": (
                "11,644-byte provisional size fixture; not a generated PQ-RBBC signature"
            ),
            "first_record_ciphertext_status": (
                "17-byte conditional size fixture; production AEAD not instantiated"
            ),
        },
        "sampling": {"warmups": warmups, "iterations": iterations},
        "wire_bytes": {
            "candidate_ticket_fixture": 12_126,
            "holder_public_key": len(artifacts.holder_public_key),
            "holder_authenticator": len(artifacts.holder_authenticator),
            "fgs_public_key_preconfigured_not_on_wire": len(artifacts.fgs_public_key),
            "fgs_authenticator": len(artifacts.fgs_authenticator),
            "m1_access_request": len(artifacts.request_bytes),
            "m2_access_accept": len(artifacts.response_bytes),
            "m3_session_activate": len(artifacts.activation_bytes),
            "first_application_record_conditional": len(
                artifacts.first_application_record_bytes
            ),
            "explicit_m3_complete_handshake": artifacts.explicit_m3_total_bytes,
            "first_record_complete_handshake": artifacts.first_record_total_bytes,
            "explicit_m3_margin_below_50000": 50_000
            - artifacts.explicit_m3_total_bytes,
            "first_record_margin_below_50000": 50_000
            - artifacts.first_record_total_bytes,
        },
        "timing": {
            "faest_keygen_reference": _stats(keygen_ms),
            "ue_holder_sign_faest_reference": _stats(sign_ms),
            "fgs_holder_verify_faest_reference": _stats(verify_ms),
            "full_handshake_faest_reference": _stats(full_handshake_ms),
            "scope": (
                "host wall-clock; full handshake includes FAEST holder keygen/sign/verify, "
                "ML-DSA FGS keygen/sign/verify, ML-KEM keygen/encap/decap, codecs and Finished"
            ),
        },
        "d4_ml_dsa_comparator": {
            "artifact_path": str(D4_BASELINE_PATH.relative_to(ROOT)),
            "artifact_sha256": D4_BASELINE_SHA256,
            "same_host_identity": d4_baseline["host"]["cpu_model"] == _cpu_model(),
            "wire_delta_bytes": {
                "holder_public_key": len(artifacts.holder_public_key)
                - ml_dsa_wire["holder_public_key"],
                "holder_authenticator": len(artifacts.holder_authenticator)
                - ml_dsa_wire["holder_authenticator"],
                "m1": len(artifacts.request_bytes) - ml_dsa_wire["m1_access_request"],
                "explicit_complete_handshake": artifacts.explicit_m3_total_bytes
                - ml_dsa_wire["explicit_m3_complete_handshake"],
            },
            "ml_dsa_median_ms_from_frozen_d4": {
                "holder_sign": ml_dsa_timing["ue_holder_sign_pqcrypto"]["median_ms"],
                "holder_verify": ml_dsa_timing["fgs_holder_verify_pqcrypto"]["median_ms"],
                "full_handshake": ml_dsa_timing["full_handshake_pqcrypto"]["median_ms"],
            },
            "timing_comparison_caveat": (
                "separate runs and different providers; descriptive host comparison only"
            ),
        },
        "claim_boundary": {
            "real_faest_192s_holder_signature_generated": True,
            "real_ml_kem_shared_secret_established": True,
            "faest_official_api_self_test_passed": True,
            "faest_official_known_answer_test_checked": False,
            "faest_second_provider_interoperability_tested": False,
            "issuer_signature_generated": False,
            "production_aead_instantiated": False,
            "new_r_issue_implemented": False,
            "r_key_circuit_implemented": False,
            "access_composition_proof_closed": False,
            "production_ready": False,
            "production_closed": False,
        },
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--faest-library", type=Path, required=True)
    parser.add_argument("--faest-library-sha256", required=True)
    parser.add_argument("--faest-source-dir", type=Path, required=True)
    parser.add_argument("--faest-api-test", type=Path, required=True)
    parser.add_argument("--faest-api-test-sha256", required=True)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    result = _main(
        iterations=arguments.iterations,
        warmups=arguments.warmups,
        library=arguments.faest_library,
        library_sha256=arguments.faest_library_sha256,
        source_dir=arguments.faest_source_dir,
        api_test=arguments.faest_api_test,
        api_test_sha256=arguments.faest_api_test_sha256,
    )
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
