"""Measure a bounded, variable-time TH-GF single-machine research reference."""

import argparse
import json
import platform
import secrets
import statistics
import time

from ..contracts import TraceInputs
from .profile import CIPHERTEXT_BYTES, PROFILE_ID, PUBLIC_KEY_BYTES, descriptor_sha256
from .reference import (
    check_encryption_relation_reference, decrypt_reference_for_test, encrypt_reference,
    keygen_reference, sample_witness_reference,
)


def sample_count(value: str) -> int:
    try:
        count = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("samples must be an integer from 1 to 16") from exc
    if not 1 <= count <= 16:
        raise argparse.ArgumentTypeError("samples must be an integer from 1 to 16")
    return count


def run_reference_experiment(samples: int) -> dict:
    if type(samples) is not int or not 1 <= samples <= 16:
        raise ValueError("samples must be an integer from 1 to 16")
    start = time.perf_counter_ns()
    pk, sk = keygen_reference()
    keygen_ns = time.perf_counter_ns() - start
    times = {"encrypt_ns": [], "decrypt_ns": [], "relation_evaluator_ns": []}
    for _ in range(samples):
        inputs = TraceInputs(secrets.token_bytes(32), secrets.token_bytes(16),
                             secrets.token_bytes(32), secrets.token_bytes(32))
        witness = sample_witness_reference()
        start = time.perf_counter_ns()
        ciphertext = encrypt_reference(pk, inputs, witness)
        times["encrypt_ns"].append(time.perf_counter_ns() - start)
        start = time.perf_counter_ns()
        plaintext = decrypt_reference_for_test(sk, inputs.associated_data, ciphertext)
        times["decrypt_ns"].append(time.perf_counter_ns() - start)
        start = time.perf_counter_ns()
        relation_ok = check_encryption_relation_reference(pk, inputs, ciphertext, witness)
        times["relation_evaluator_ns"].append(time.perf_counter_ns() - start)
        if plaintext != inputs.plaintext or not relation_ok:
            raise RuntimeError("honest reference experiment failed; no success report emitted")
    return {
        "schema": "pq-th-gf-tb2-reference-measurement-v1", "profile_id": PROFILE_ID,
        "profile_descriptor_sha256": descriptor_sha256(),
        "environment": {"python": platform.python_version(), "platform": platform.system(),
                        "machine": platform.machine()},
        "observed": {
            "evidence_kind": "measured_reference", "keypairs": 1, "samples": samples,
            "successful_decryptions": samples, "successful_relation_evaluations": samples,
            "public_key_payload_bytes": PUBLIC_KEY_BYTES, "public_key_record_bytes": len(pk.encode()),
            "ciphertext_payload_bytes": len(ciphertext.payload),
            "ciphertext_record_bytes": len(ciphertext.encode()), "keygen_ns": keygen_ns,
            "median_ns": {name: statistics.median_low(values) for name, values in times.items()},
        },
        "estimated": {"evidence_kind": "estimated", "sigma_bytes": 11644,
                      "sigma_status": "provisional_estimate", "extra_bytes": None,
                      "known_ticket_bytes": 80 + CIPHERTEXT_BYTES + 11644,
                      "total_ticket_bytes": None},
        "measured_threshold": None, "satellite_online_observation": None,
        "claims": {"non_threshold_reference_only": True, "constant_time": False,
                   "empirical_failure_probability_bound": None, "proof_closed": False,
                   "production_qualified": False},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=sample_count, default=3)
    args = parser.parse_args()
    print(json.dumps(run_reference_experiment(args.samples), indent=2, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
