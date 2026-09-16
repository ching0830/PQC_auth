"""Local TB2 instantiation; it is not a paper-qualified or production profile."""

import hashlib
import json

PROFILE_ID = "gf-hybrid2-pompeii-d4-shake256-otp-ref-v1"
N = 256
D = 4
Q = 4188161
P = 1024
ELL = 1048576
MU_SCALE = 256
U_BYTES = N * D // 8
PUBLIC_KEY_BYTES = 2 * D * D * N * 22 // 8
POMPEII_BYTES = 2 * D * N * 10 // 8
DEM_BYTES = 128
G_BYTES = 32
CIPHERTEXT_BYTES = POMPEII_BYTES + DEM_BYTES + G_BYTES + U_BYTES
MAGIC = b"PQ-TH-GF-TB2\x00"
VERSION = 1


def descriptor() -> dict:
    return {
        "schema": "pq-th-gf-reference-profile-v1", "profile_id": PROFILE_ID,
        "candidate": "TH-GF", "purpose": "non_threshold_research_only",
        "parameters": {"n": N, "d": D, "t": 2, "q": Q, "p": P,
                       "ell": ELL, "mu_scale": MU_SCALE, "noise": "CBD1",
                       "noise_variance": "1/2"},
        "paper": {"filename": "2021-096.pdf",
                  "sha256": "b730d4640218b5ea86b019a52501be2e4682b562e61a468abd08658ee393678e",
                  "locators": ["pp. 8-9 centered representatives, CBD sampling, rounding",
                               "Fig. 5 p. 24 Hybrid2", "Fig. 14 p. 45 Pompeii",
                               "Table 2 p. 46 prime-q d4 without LVP row"]},
        "project_choices": {
            "hash": "SHAKE256; independent H, H_prime, H_double_prime, G domains",
            "H_output_bytes": DEM_BYTES, "H_prime_output_bytes": U_BYTES,
            "H_double_prime_output_bytes": U_BYTES, "G_output_bytes": G_BYTES,
            "DEM": "one-use 128-byte XOR pad H(u); message ad||rid||sn; no DEM coins",
            "hash_framing": "MAGIC||uint16le(1)||u8(len(profile))||profile||u8(len(label))||label||each(u32le(len(arg))||arg)",
            "packing": "row-major matrices; ascending polynomial coefficients; little-endian contiguous bits; nonnegative residues",
            "rounding": "center input mod q, nearest rational p*x/q, ties toward zero, center result mod p",
            "keygen_sampler": "domain-separated SHAKE256(seed32); A1 masked 22-bit rejection; R1/R2 CBD1 from two low bits per byte",
        },
        "witness_descriptor": {"name": "u", "payload_bytes": U_BYTES,
                               "encoding": "d polynomials, n bits each; coefficients in {0,1}",
                               "secret": True, "deterministic_encryption_given_witness": True},
        "payload_bytes": {"public_key": PUBLIC_KEY_BYTES, "ciphertext": CIPHERTEXT_BYTES,
                          "c1": POMPEII_BYTES, "c2": DEM_BYTES, "c3": G_BYTES, "c4": U_BYTES},
        "claims": {"paper_verified_full_instantiation": False,
                   "security_assessment": "OPEN", "threshold_execution": "not_implemented",
                   "constant_time": False, "production_qualified": False,
                   "B_issuance_ABI_integrated": False, "opening_ABI_integrated": False},
    }


def descriptor_sha256() -> str:
    encoded = json.dumps(descriptor(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()
