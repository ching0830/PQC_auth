#!/usr/bin/env python3
"""Benchmark the isolated ML-DSA holder-authentication handshake prototype."""

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
    ML_DSA_65_PARAMETER_DIGEST,
    decode_access_request,
)
from pq_sat_auth.v2.prototypes.holder_auth_v3.providers import (
    DilithiumPyMLDSA65Provider,
    PQCryptoMLDSA65Provider,
    PQCryptoMLKEM768Provider,
)
from pq_sat_auth.v2.prototypes.holder_auth_v3.suite import (
    run_experimental_handshake,
)


ROOT = Path(__file__).resolve().parents[2]
ACVP_SIGVER_SHA256 = (
    "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437"
)


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


def _git(*arguments: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=ROOT,
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
        "tests/prototypes/holder_auth_v3/test_holder_auth_handshake.py",
        "benchmarks/access_holder_auth/benchmark_ml_dsa_handshake.py",
    )
    return {
        path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        for path in paths
    }


def _run_acvp_positive_vector(path: Path, pure_provider) -> dict[str, object]:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != ACVP_SIGVER_SHA256:
        raise ValueError("ACVP sigVer source identity mismatch")
    document = json.loads(raw)
    group = next(
        group
        for group in document["testGroups"]
        if group["tgId"] == 3
        and group["parameterSet"] == "ML-DSA-65"
        and group["signatureInterface"] == "external"
        and group["preHash"] == "pure"
    )
    case = next(case for case in group["tests"] if case["tcId"] == 33)
    accepted = pure_provider.verify_with_context(
        bytes.fromhex(case["pk"]),
        bytes.fromhex(case["message"]),
        bytes.fromhex(case["signature"]),
        bytes.fromhex(case["context"]),
    )
    return {
        "source": (
            "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/"
            "gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json"
        ),
        "source_bytes": len(raw),
        "source_sha256": digest,
        "test_group_id": group["tgId"],
        "test_case_id": case["tcId"],
        "parameter_set": group["parameterSet"],
        "signature_interface": group["signatureInterface"],
        "pre_hash": group["preHash"],
        "context_bytes": len(bytes.fromhex(case["context"])),
        "expected": bool(case["testPassed"]),
        "dilithium_py_accepted": accepted,
        "pqcrypto_checked": False,
        "pqcrypto_reason": (
            "pqcrypto 0.3.3 high-level API does not expose the non-empty "
            "FIPS 204 context input used by this vector"
        ),
    }


def _main(iterations: int, warmups: int, acvp_path: Path | None) -> dict[str, object]:
    if not 1 <= iterations <= 1_000:
        raise ValueError("iterations must be in [1, 1000]")
    if not 0 <= warmups <= 100:
        raise ValueError("warmups must be in [0, 100]")

    native_sign = PQCryptoMLDSA65Provider()
    pure_sign = DilithiumPyMLDSA65Provider()
    kem = PQCryptoMLKEM768Provider()

    for _ in range(warmups):
        run_experimental_handshake(
            holder_provider=native_sign,
            fgs_provider=native_sign,
            kem_provider=kem,
        )

    artifacts = run_experimental_handshake(
        holder_provider=native_sign,
        fgs_provider=native_sign,
        kem_provider=kem,
    )
    request = decode_access_request(artifacts.request_bytes)
    signing_input = request.holder_signing_input()

    native_public, native_secret = native_sign.generate_keypair()
    pure_public, pure_secret = pure_sign.generate_keypair()
    native_signature = native_sign.sign(native_secret, signing_input)
    pure_signature = pure_sign.sign(pure_secret, signing_input)

    interop = {
        "pqcrypto_signature_verified_by_pqcrypto": native_sign.verify(
            native_public, signing_input, native_signature
        ),
        "pqcrypto_signature_verified_by_dilithium_py": pure_sign.verify(
            native_public, signing_input, native_signature
        ),
        "dilithium_py_signature_verified_by_dilithium_py": pure_sign.verify(
            pure_public, signing_input, pure_signature
        ),
        "dilithium_py_signature_verified_by_pqcrypto": native_sign.verify(
            pure_public, signing_input, pure_signature
        ),
    }
    if not all(interop.values()):
        raise RuntimeError("ML-DSA provider interoperability failed")

    native_signatures: list[bytes] = []

    def native_sign_operation() -> None:
        native_signatures.append(native_sign.sign(native_secret, signing_input))

    native_sign_ms = _measure(native_sign_operation, iterations)
    signature_index = 0

    def native_verify_operation() -> None:
        nonlocal signature_index
        signature = native_signatures[signature_index % len(native_signatures)]
        signature_index += 1
        if not native_sign.verify(native_public, signing_input, signature):
            raise RuntimeError("native ML-DSA verification failed")

    native_verify_ms = _measure(native_verify_operation, iterations)

    pure_signatures: list[bytes] = []

    def pure_sign_operation() -> None:
        pure_signatures.append(pure_sign.sign(pure_secret, signing_input))

    pure_sign_ms = _measure(pure_sign_operation, iterations)
    pure_index = 0

    def pure_verify_operation() -> None:
        nonlocal pure_index
        signature = pure_signatures[pure_index % len(pure_signatures)]
        pure_index += 1
        if not pure_sign.verify(pure_public, signing_input, signature):
            raise RuntimeError("pure ML-DSA verification failed")

    pure_verify_ms = _measure(pure_verify_operation, iterations)

    handshake_sizes: set[tuple[int, ...]] = set()

    def handshake_operation() -> None:
        result = run_experimental_handshake(
            holder_provider=native_sign,
            fgs_provider=native_sign,
            kem_provider=kem,
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
    if handshake_sizes != {(12_126, 18_897, 4_755, 198, 377, 23_850, 24_029)}:
        raise RuntimeError("wire sizes drifted across handshake iterations")

    acvp = None
    if acvp_path is not None:
        acvp = _run_acvp_positive_vector(acvp_path, pure_sign)
        if acvp["dilithium_py_accepted"] is not True:
            raise RuntimeError("official ACVP positive vector was rejected")

    status = _git("status", "--short")
    result = {
        "format": "PQ-SAT-R-ACCESS-HOLDER-AUTH-D4-BENCHMARK-v0.1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "git": {
            "head": _git("rev-parse", "HEAD"),
            "branch": _git("branch", "--show-current"),
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
            "pqcrypto": native_sign.package_version,
            "dilithium-py": pure_sign.package_version,
            "cffi": package_version("cffi"),
            "provider_production_ready": False,
        },
        "profile": {
            "access_suite_id": ACCESS_SUITE_ID,
            "holder_suite": "ML-DSA-65",
            "holder_parameter_digest_sha256": ML_DSA_65_PARAMETER_DIGEST.hex(),
            "native_context": "empty",
            "protocol_domain_encoded_in_signed_message": True,
            "holder_signing_input_bytes": len(signing_input),
            "issuer_signature_bytes_status": (
                "11,644-byte provisional size fixture; not a generated PQ-RBBC signature"
            ),
            "first_record_ciphertext_status": (
                "17-byte conditional size fixture; production AEAD not instantiated"
            ),
        },
        "sampling": {
            "warmups": warmups,
            "iterations": iterations,
        },
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
            "ue_holder_sign_pqcrypto": _stats(native_sign_ms),
            "fgs_holder_verify_pqcrypto": _stats(native_verify_ms),
            "holder_sign_dilithium_py": _stats(pure_sign_ms),
            "holder_verify_dilithium_py": _stats(pure_verify_ms),
            "full_handshake_pqcrypto": _stats(full_handshake_ms),
            "scope": (
                "host wall-clock; full handshake includes two ML-DSA keygens, "
                "two signatures, ML-KEM keygen/encap/decap, codecs and Finished"
            ),
        },
        "interoperability": interop,
        "official_acvp": acvp,
        "claim_boundary": {
            "real_ml_dsa_holder_signature_generated": True,
            "real_ml_kem_shared_secret_established": True,
            "two_ml_dsa_providers_interoperable": True,
            "official_positive_acvp_vector_checked": acvp is not None,
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
    parser.add_argument("--acvp-sigver-json", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    result = _main(
        arguments.iterations,
        arguments.warmups,
        arguments.acvp_sigver_json,
    )
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
