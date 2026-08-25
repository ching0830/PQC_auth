#!/usr/bin/env python3
"""Reproducible v1.3 circuit and wire-size audit for PQ-RBBC/SGTD.

The script deliberately separates exact counts from paper-derived estimates.
It writes no files; redirect its JSON output only for independent comparison.
"""

from __future__ import annotations

import json
import math


PROFILE = {
    "blind_uov": {
        "revision": "IACR ePrint 2025/895, revision 2025-10-31",
        "parameter_set": "Blind-UOV-Is / NIST I / Shorter / TCitH",
        "signature_bytes": 3772,
        "public_key_bytes_reported": 66_600,
        "mask_bits": 256,
        "signature_vector_bits": 640,
        "tcih": {
            "tau": 12,
            "trees": [
                {"count": 10, "leaves": 2**11},
                {"count": 2, "leaves": 2**10},
            ],
            "opened_seeds_upper_bound": 111,
            "explicit_pow_bits": 9,
            "total_pow_bits": 14.0,
        },
        "shockwave_anemoi_baseline": {
            "r1cs_constraints_reported_rounded": 16_000_000,
            "proof_mb_reported": 2.8,
            "prover_seconds_reported": 32.0,
            "verifier_seconds_reported": 2.5,
        },
    },
    "trace": {
        "parameter_anchor": "mceliece6688128 (provisional only)",
        "n": 6688,
        "k": 5024,
        "t": 128,
        "public_key_bytes": 1_044_992,
        "syndrome_bytes": 208,
        "identity_bytes": 32,
        "serial_bytes": 16,
        "holder_hash_bytes": 32,
        "context_digest_bytes": 32,
        "masked_plaintext_bytes": 48,
        "tag_bytes": 32,
    },
}


KECCAK_R1CS_PERMUTATION = 24 * 1600
SHAKE256_RATE_BYTES = 136


def shake_absorb_permutations(message_bytes: int) -> int:
    """Keccak-f calls to absorb a SHAKE256 message including pad10*1."""
    return message_bytes // SHAKE256_RATE_BYTES + 1


def padded_popcount_and_gates(n: int) -> tuple[int, int, list[dict[str, int]]]:
    """Exact AND count for the specified power-of-two binary adder tree.

    Two j-bit counters are combined with one half-adder and j-1 full adders.
    XOR is linear; the cost is therefore 1 + 2(j-1) = 2j-1 AND gates.
    """
    padded = 1 << (n - 1).bit_length()
    levels = []
    total = 0
    for width in range(1, int(math.log2(padded)) + 1):
        additions = padded // (2**width)
        per_addition = 2 * width - 1
        gates = additions * per_addition
        total += gates
        levels.append(
            {
                "input_width_bits": width,
                "additions": additions,
                "and_gates_per_addition": per_addition,
                "and_gates": gates,
            }
        )
    return padded, total, levels


def build_audit() -> dict:
    buov = PROFILE["blind_uov"]
    trace = PROFILE["trace"]

    trace_ciphertext_bytes = (
        trace["syndrome_bytes"]
        + trace["masked_plaintext_bytes"]
        + trace["tag_bytes"]
    )
    ticket_payload_bytes = (
        trace["context_digest_bytes"]
        + trace["serial_bytes"]
        + trace["holder_hash_bytes"]
        + trace_ciphertext_bytes
    )
    online_ticket_bytes = ticket_payload_bytes + buov["signature_bytes"]

    # Fixed v1.3 encodings.
    ticket_hash_input_bytes = len(b"PQ-RBBC/TICKET") + ticket_payload_bytes
    holder_hash_input_bytes = len(b"PQ-RBBC/HOLD") + 32
    kdf_input_bytes = (
        len(b"PQ-RBBC/KDF")
        + trace["n"] // 8
        + trace["syndrome_bytes"]
        + trace["context_digest_bytes"]
    )
    associated_data_bytes = (
        trace["context_digest_bytes"]
        + trace["serial_bytes"]
        + trace["holder_hash_bytes"]
    )

    # KMAC256 = cSHAKE prefix block || bytepad(key) block || X || right_encode(256).
    kmac_absorb_bytes = (
        SHAKE256_RATE_BYTES
        + SHAKE256_RATE_BYTES
        + trace["syndrome_bytes"]
        + trace["masked_plaintext_bytes"]
        + associated_data_bytes
        + 3
    )

    permutations = {
        "ticket_hash": shake_absorb_permutations(ticket_hash_input_bytes),
        "holder_hash": shake_absorb_permutations(holder_hash_input_bytes),
        "trace_kdf": shake_absorb_permutations(kdf_input_bytes),
        "trace_kmac": shake_absorb_permutations(kmac_absorb_bytes),
    }
    permutations["total"] = sum(permutations.values())

    padded_n, weight_ands, popcount_levels = padded_popcount_and_gates(trace["n"])
    bitness_constraints = trace["n"] + 8 * trace["serial_bytes"] + 256

    blocks = {
        "shape": {
            "nonlinear_constraints": 8 * trace["serial_bytes"],
            "reason": "128 serial-number bitness checks; fixed-width wiring is linear",
        },
        "ticket_hash": {
            "nonlinear_constraints": permutations["ticket_hash"]
            * KECCAK_R1CS_PERMUTATION,
            "reason": "three SHAKE256/Keccak-f permutations",
        },
        "blind_uov_mask_increment": {
            "nonlinear_constraints": 0,
            "reason": "already included in the paper's Blind-UOV-Is pi_1 baseline",
        },
        "holder": {
            "nonlinear_constraints": 256
            + permutations["holder_hash"] * KECCAK_R1CS_PERMUTATION,
            "reason": "256 key-bit checks plus one SHAKE256 permutation",
        },
        "trace": {
            "nonlinear_constraints": trace["n"]
            + weight_ands
            + (permutations["trace_kdf"] + permutations["trace_kmac"])
            * KECCAK_R1CS_PERMUTATION,
            "reason": "error bitness, exact-weight adder tree, SHAKE KDF and KMAC",
        },
    }
    added_nonlinear = sum(v["nonlinear_constraints"] for v in blocks.values())
    baseline = buov["shockwave_anemoi_baseline"]
    augmented_constraints = baseline["r1cs_constraints_reported_rounded"] + added_nonlinear
    ratio = augmented_constraints / baseline["r1cs_constraints_reported_rounded"]

    return {
        "audit_version": "1.3",
        "status": "research estimate; not a deployment parameter freeze",
        "profile": PROFILE,
        "fixed_wire_sizes": {
            "trace_ciphertext_bytes": trace_ciphertext_bytes,
            "ticket_payload_bytes": ticket_payload_bytes,
            "blind_uov_signature_bytes": buov["signature_bytes"],
            "online_ticket_bytes_excluding_transport_framing": online_ticket_bytes,
        },
        "keccak_accounting": {
            "r1cs_constraints_per_permutation": KECCAK_R1CS_PERMUTATION,
            "shake256_rate_bytes": SHAKE256_RATE_BYTES,
            "absorbed_message_bytes": {
                "ticket_hash": ticket_hash_input_bytes,
                "holder_hash": holder_hash_input_bytes,
                "trace_kdf": kdf_input_bytes,
                "trace_kmac_including_cshake_prefixes": kmac_absorb_bytes,
            },
            "permutations": permutations,
            "nonlinear_constraints": permutations["total"]
            * KECCAK_R1CS_PERMUTATION,
        },
        "exact_weight_gadget": {
            "input_bits": trace["n"],
            "padded_input_bits": padded_n,
            "target_weight": trace["t"],
            "and_gates": weight_ands,
            "levels": popcount_levels,
        },
        "circuit_blocks": blocks,
        "incremental_relation_cost": {
            "bitness_constraints": bitness_constraints,
            "syndrome_linear_equalities": trace["n"] - trace["k"],
            "nonlinear_constraints_exact_for_specified_gadgets": added_nonlinear,
        },
        "paper_anchored_total_estimate": {
            "baseline_constraints_rounded": baseline[
                "r1cs_constraints_reported_rounded"
            ],
            "augmented_constraints_approx": augmented_constraints,
            "constraint_ratio": ratio,
            "shockwave_proof_mb_sqrt_scaled": baseline["proof_mb_reported"]
            * math.sqrt(ratio),
            "prover_seconds_linear_scaled": baseline["prover_seconds_reported"]
            * ratio,
            "verifier_seconds_conservative_linear_scale": baseline[
                "verifier_seconds_reported"
            ]
            * ratio,
        },
        "unresolved_security_blockers": [
            "The paper's Shockwave figures are illustrative and the benchmarked implementation is not shown to satisfy the simulation-extractability required by the GCCA proof.",
            "mceliece6688128 is only a size anchor pending independent review of ePrint 2026/1630.",
            "Robust threshold-share verification and constant-time decoder integration remain unbenchmarked.",
        ],
    }


if __name__ == "__main__":
    print(json.dumps(build_audit(), indent=2, sort_keys=True))
