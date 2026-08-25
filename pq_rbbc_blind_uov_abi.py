#!/usr/bin/env python3
"""Hidden-state ABI for the single-lane Blind-UOV-III issuance boundary.

Protocols 3 and 4 of the 31 October 2025 revision of ePrint 2025/895 send
only ``(y, pi_1)`` to the signer.  The CAP commitment ``c_r``, message ``mu``,
mask ``r`` and CAP randomness ``rho`` remain hidden until finalization.

Version 1.8 splits the request relation into an in-circuit linear mask equation
``y = r + h`` and one narrower native boundary
``h = H(mu, CAP.Commit(r; rho))``.  Its 576-bit masked target avoids
the invalid parallel-repetition argument in v1.6: under CAP unique-witness
soundness, J_mu(r,rho)=r+H(mu,CAP.Commit(r;rho)) is a pointwise shift of a
576-bit random function on admissible (mu,c_r) inputs.  Its SHAKE adapter is
test-only and does not implement the paper's TCitH/Anemoi CAP construction.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Protocol


MESSAGE_BYTES = 32
MASK_BYTES = 72
TARGET_BYTES = 72
HASH_IMAGE_BYTES = 72
TEST_CAP_RANDOMNESS_BYTES = 32


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("xor operands must have equal length")
    return bytes(a ^ b for a, b in zip(left, right))


@dataclass(frozen=True)
class BlindUOVRequest:
    """The complete public signer request, excluding pi_issue."""

    masked_target: bytes

    def encode(self) -> bytes:
        if len(self.masked_target) != TARGET_BYTES:
            raise ValueError("Blind-UOV-III masked target must be 72 bytes")
        return self.masked_target


@dataclass(frozen=True)
class TestHiddenState:
    """Test-only values that must never be serialized into the request."""

    message_digest: bytes
    mask: bytes
    cap_randomness: bytes
    cap_commitment: bytes
    hash_image: bytes


class BlindUOVAdapter(Protocol):
    name: str

    def create(
        self, message: bytes, mask: bytes, cap_randomness: bytes
    ) -> BlindUOVRequest:
        ...

    def verify(
        self,
        request: BlindUOVRequest,
        message: bytes,
        mask: bytes,
        cap_randomness: bytes,
    ) -> bool:
        ...

    def hash_image(
        self, message: bytes, mask: bytes, cap_randomness: bytes
    ) -> bytes:
        """Return H(message, CAP.Commit(mask; randomness))."""
        ...

    def verify_cap_hash(
        self,
        message: bytes,
        mask: bytes,
        cap_randomness: bytes,
        hash_image: bytes,
    ) -> bool:
        """Verify only the native CAP.Commit-plus-hash subrelation."""
        ...


class TestBlindUOVAdapter:
    """Non-cryptographic adapter respecting the paper's hidden-state ABI."""

    name = "TEST-ONLY-BLIND-UOV-III-HIDDEN-CAP-SHAKE-ADAPTER"
    _commit_label = b"PQ-RBBC/v1.8/TEST-BUOV-III/CAP-COMMIT"
    _hash_label = b"PQ-RBBC/v1.8/TEST-BUOV-III/H"

    @staticmethod
    def _check_lengths(message: bytes, mask: bytes, cap_randomness: bytes) -> None:
        if len(message) != MESSAGE_BYTES:
            raise ValueError("message digest must be 32 bytes")
        if len(mask) != MASK_BYTES:
            raise ValueError("Blind-UOV-III mask must be 72 bytes")
        if len(cap_randomness) != TEST_CAP_RANDOMNESS_BYTES:
            raise ValueError("test CAP randomness must be 32 bytes")

    def hidden_state(
        self, message: bytes, mask: bytes, cap_randomness: bytes
    ) -> TestHiddenState:
        self._check_lengths(message, mask, cap_randomness)
        commitment = hashlib.shake_256(
            self._commit_label + mask + cap_randomness
        ).digest(32)
        hash_image = hashlib.shake_256(
            self._hash_label + message + commitment
        ).digest(HASH_IMAGE_BYTES)
        return TestHiddenState(
            message, mask, cap_randomness, commitment, hash_image
        )

    def hash_image(
        self, message: bytes, mask: bytes, cap_randomness: bytes
    ) -> bytes:
        return self.hidden_state(message, mask, cap_randomness).hash_image

    def verify_cap_hash(
        self,
        message: bytes,
        mask: bytes,
        cap_randomness: bytes,
        hash_image: bytes,
    ) -> bool:
        if len(hash_image) != HASH_IMAGE_BYTES:
            return False
        return hash_image == self.hash_image(message, mask, cap_randomness)

    def create(
        self, message: bytes, mask: bytes, cap_randomness: bytes
    ) -> BlindUOVRequest:
        return BlindUOVRequest(
            xor_bytes(mask, self.hash_image(message, mask, cap_randomness))
        )

    def verify(
        self,
        request: BlindUOVRequest,
        message: bytes,
        mask: bytes,
        cap_randomness: bytes,
    ) -> bool:
        request.encode()
        return request == self.create(message, mask, cap_randomness)


def build_abi_manifest() -> dict[str, object]:
    adapter = TestBlindUOVAdapter()
    message = hashlib.shake_256(b"PQ-RBBC/v1.8/abi/message").digest(32)
    mask = hashlib.shake_256(b"PQ-RBBC/v1.8/abi/mask").digest(MASK_BYTES)
    randomness = hashlib.shake_256(b"PQ-RBBC/v1.8/abi/randomness").digest(32)
    request = adapter.create(message, mask, randomness)
    hidden = adapter.hidden_state(message, mask, randomness)
    changed_message = bytes((message[0] ^ 1,)) + message[1:]
    return {
        "implementation_version": "1.8",
        "paper_anchor": "IACR ePrint 2025/895, revision 2025-10-31, Protocols 3, 4, 8-10, Tables 2 and 4",
        "profile": "Blind-UOV-III / NIST III / identity F / Shorter / TCitH",
        "paper_parameters": {
            "security_level_bits": 192,
            "mask_bits": 576,
            "hash_and_sign_signature_bits": 1472,
            "public_key_kilobytes": 189.2,
            "final_signature_bytes": 11644,
            "cap_parallel_repetitions": 18,
            "cap_tree_groups": [
                {"trees": 2, "leaves_per_tree": 4096},
                {"trees": 16, "leaves_per_tree": 2048}
            ],
            "cap_opened_seeds_upper_bound": 174,
            "explicit_pow_bits": 9,
            "total_pow_bits": 13.9,
            "anemoi_binary_field_degree": 193,
            "anemoi_state_elements": 8,
            "anemoi_constraints_per_permutation": 240,
        },
        "public_signer_view": {
            "request_fields_excluding_proof": ["y"],
            "request_bytes": len(request.encode()),
            "pi_issue_public_inputs": [
                "common parameters",
                "ctx",
                "sid",
                "rid",
                "y",
            ],
        },
        "hidden_pi_issue_witness": [
            "ticket payload M",
            "ticket digest m",
            "576-bit mask r",
            "CAP randomness rho",
            "derived hidden CAP commitment c_r",
            "576-bit hash image H_BUOV(m,c_r)",
            "holder key",
            "trace error vector",
        ],
        "final_signature_view": ["c_r", "c_x", "pi_2"],
        "regression_checks": {
            "honest_request_accepts": adapter.verify(
                request, message, mask, randomness
            ),
            "changed_hidden_message_rejects": not adapter.verify(
                request, changed_message, mask, randomness
            ),
            "request_has_cap_commitment_field": hasattr(request, "cap_commitment"),
            "request_has_message_digest_field": hasattr(request, "message_digest"),
            "request_encoding_equals_y_only": request.encode()
            == request.masked_target,
            "hidden_state_not_in_request_dataclass": set(asdict(hidden)).isdisjoint(
                asdict(request)
            ),
            "native_cap_hash_accepts": adapter.verify_cap_hash(
                message, mask, randomness, hidden.hash_image
            ),
            "linear_mask_equation_holds": request.masked_target
            == xor_bytes(mask, hidden.hash_image),
        },
        "binding_reduction": {
            "name": "single-lane QROM cross-message request collision resistance",
            "map": "J_m(r,rho)=r+H_BUOV(m,CAP.Commit(r;rho))",
            "unique_witness_step": "CAP unique-witness soundness makes r a well-defined value for every admissible c_r",
            "random_function_step": "Z(m,c_r)=H_BUOV(m,c_r)+r(c_r) is a pointwise shift of a 576-bit random function",
            "qrom_bound": "O(q_H^3/2^576) plus CAP unique-witness/extraction failure",
            "at_2_pow_128_queries": "the random-function term is O(2^-192)",
            "generic_quantum_collision_cost": "about 2^(576/3)=2^192 queries",
            "status": "paper-level QROM reduction in the stated ideal model; native CAP/backend qualification remains external",
        },
        "v1_6_correction": {
            "independent_parallel_lanes_amplify_security_bits": False,
            "reason": "two independently openable 256-bit claw instances can be solved separately for one fixed message pair",
        },
        "claim_boundary": {
            "test_adapter_is_native_blind_uov": False,
            "paper_supplies_executable_constraint_generator": False,
            "native_tcih_anemoi_constraint_import_complete": False,
            "linear_y_equals_r_plus_h_internalized": True,
            "test_cap_randomness_bytes": TEST_CAP_RANDOMNESS_BYTES,
            "native_cap_randomness_is_not_fixed_to_test_nonce": True,
        },
    }


def main() -> None:
    print(json.dumps(build_abi_manifest(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
