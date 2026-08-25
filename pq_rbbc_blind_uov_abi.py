#!/usr/bin/env python3
"""Hidden-state ABI for the single-lane PQ-RBBC-BUOV-336 fork.

Protocols 3 and 4 of the 31 October 2025 revision of ePrint 2025/895 send
only ``(y, pi_1)`` to the signer.  The CAP commitment ``c_r``, message ``mu``,
mask ``r`` and CAP randomness ``rho`` remain hidden until finalization.

Version 1.8 split the request relation into an in-circuit linear mask equation
``y = r + h`` and one narrower native boundary
``h = H(mu, CAP.Commit(r; rho))``.  Its 576-bit masked target avoids
the invalid parallel-repetition argument in v1.6: under CAP unique-witness
soundness, J_mu(r,rho)=r+H(mu,CAP.Commit(r;rho)) is a pointwise shift of a
576-bit random function on admissible (mu,c_r) inputs.  Version 2.0 retains the
72-byte hidden-state ABI but explicitly forks the hash instantiation to
PQ-RBBC-Anemoi-193/336-Sponge-v1.  The CAP commitment remains a test fixture;
the fork is not bit-exact Blind-UOV and the paper's signature size is only a
provisional target until the fork is re-benchmarked.  Version 2.1 adds the
strict byte-level join from the independently serialized 5,391-byte production
CAP profile to ``H_RBBC``; it deliberately rejects the reduced CAP fixture and
does not claim that the full 18-tree native trace has been materialized.
Version 2.2 supplies a zero-callback native row stream for the explicitly
non-secure reduced CAP fixture and its exact ``H_RBBC`` wire join.  That
component validates the lowering architecture but is not production evidence.
Version 2.3 extends the same native relation across four squeeze blocks and
freezes an extended CAP fixture whose eight leaf tapes are each 2,450 bits.
The fixture remains non-secure because its witness has only one GF(2^193)
coefficient and its tree topology is deliberately tiny.
Version 2.4 adds a bit-bound native GF(2^193) multiplication gadget, freezes
the production-width 2,048-bit/11-coefficient Horner vector, and integrates
the same generic lowering with symbolic extension-mask slices in a 386-bit,
two-coefficient, two-point, 2,450-bit-tape CAP fixture.  The full 18-tree
production relation remains outside the closed boundary.
Version 2.5 executes one real 2,048-leaf production tree shape with the full
2,048-bit witness, degree-12 extension masks, two consistency points, and
2,450-bit tapes.  Its 26,126,283 rows are hashed through a bounded-memory
stream; the complete assignment, 4,096-leaf shard, other 17 trees, and parent
archive join remain outside the closed boundary.
Version 2.6 materializes all 19,903,324 field-wire values in a fixed-width
assignment archive, replays all 26,126,283 rows from that archive with zero
failures, and rejects five stale-witness probes.  The shard remains a
non-secure one-tree fixture; the 4,096-leaf shard, other 17 trees, and parent
archive join remain outside the closed boundary.
Version 2.7 repeats the same assignment-backed discipline for one real
4,096-leaf degree-13 tree: 39,789,564 wires and 52,224,501 rows replay with
zero failures, and five stale-witness probes reject.  Both production tree
shapes are now closed separately; their 18-tree composition remains external.
Version 2.9 also materializes and replays the shared production global tail
that consumes all 18 tree outputs: 17 correction pairs, H1, consistency
points, alpha, xi, H2, one 5,391-byte commitment, and the request hash.  The
tree-producer segments and their exact wire identities remain the next gap.
Version 2.8 executed the actual mixed 18-tree production reference and froze
all 122,847 CAP XOF calls, 17 correction pairs, one 5,391-byte commitment and
one request hash in a canonical linked schedule.  The global native tail and
monolithic assignment remain open, so parent closure is not claimed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

import pq_rbbc_anemoi_sponge as fork_sponge
import pq_rbbc_cap_commit as fork_cap
import pq_rbbc_cap_composer as cap_composer
import pq_rbbc_cap_global_tail as cap_global_tail
import pq_rbbc_cap_native as reduced_native_cap
import pq_rbbc_cap_shard_assignment as shard_assignment
import pq_rbbc_cap_shard_stream as shard_stream
import pq_rbbc_horner_native as horner_native


MESSAGE_BYTES = 32
MASK_BYTES = 72
TARGET_BYTES = 72
HASH_IMAGE_BYTES = 72
TEST_CAP_RANDOMNESS_BYTES = 32
TEST_FORK_CAP_COMMITMENT_BYTES = 48


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
            raise ValueError("PQ-RBBC-BUOV-336 masked target must be 72 bytes")
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


class ProductionCAPCommitmentView(Protocol):
    """Minimal canonical output needed by the request-binding ABI."""

    parameters_fingerprint: str
    derived_mask: int
    encoded: bytes


@dataclass(frozen=True)
class CAPBoundRequestState:
    request: BlindUOVRequest
    mask: bytes
    cap_commitment: bytes
    hash_image: bytes


def request_from_production_cap(
    message: bytes,
    commitment: ProductionCAPCommitmentView,
) -> CAPBoundRequestState:
    """Join a canonical production-profile CAP output to ``H_RBBC``.

    This function closes the byte-level ABI join only.  It rejects reduced
    fixtures and malformed lengths, and does not claim that the full 18-tree
    CAP row stream has been materialized in the parent circuit.
    """

    if len(message) != MESSAGE_BYTES:
        raise ValueError("message digest must be 32 bytes")
    expected_fingerprint = fork_cap.profile_fingerprint(
        fork_cap.PRODUCTION_PARAMETERS
    )
    if commitment.parameters_fingerprint != expected_fingerprint:
        raise ValueError("CAP commitment uses the wrong fork profile")
    if len(commitment.encoded) != fork_cap.commitment_bytes(
        fork_cap.PRODUCTION_PARAMETERS
    ):
        raise ValueError("CAP commitment has the wrong canonical length")
    if not 0 <= commitment.derived_mask < 1 << (8 * MASK_BYTES):
        raise ValueError("derived CAP mask is not 576 bits")
    mask = commitment.derived_mask.to_bytes(MASK_BYTES, "little")
    hash_image = fork_sponge.hash_request_binding(message, commitment.encoded)
    request = BlindUOVRequest(xor_bytes(mask, hash_image))
    return CAPBoundRequestState(
        request=request,
        mask=mask,
        cap_commitment=commitment.encoded,
        hash_image=hash_image,
    )


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


class TestPQRBBC336Adapter:
    """Fork adapter: test CAP commitment plus the real v2.0 sponge hash."""

    name = "TEST-ONLY-PQ-RBBC-BUOV-336-CAP-WITH-ANEMOI-SPONGE"
    _commit_label = b"PQ-RBBC/v2.0/TEST-CAP-COMMIT"

    @staticmethod
    def _check_lengths(message: bytes, mask: bytes, cap_randomness: bytes) -> None:
        if len(message) != MESSAGE_BYTES:
            raise ValueError("message digest must be 32 bytes")
        if len(mask) != MASK_BYTES:
            raise ValueError("PQ-RBBC-BUOV-336 mask must be 72 bytes")
        if len(cap_randomness) != TEST_CAP_RANDOMNESS_BYTES:
            raise ValueError("test CAP randomness must be 32 bytes")

    def hidden_state(
        self, message: bytes, mask: bytes, cap_randomness: bytes
    ) -> TestHiddenState:
        self._check_lengths(message, mask, cap_randomness)
        commitment = hashlib.shake_256(
            self._commit_label + mask + cap_randomness
        ).digest(TEST_FORK_CAP_COMMITMENT_BYTES)
        hash_image = fork_sponge.hash_request_binding(message, commitment)
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
    adapter = TestPQRBBC336Adapter()
    message = hashlib.shake_256(b"PQ-RBBC/v2.0/abi/message").digest(32)
    mask = hashlib.shake_256(b"PQ-RBBC/v2.0/abi/mask").digest(MASK_BYTES)
    randomness = hashlib.shake_256(b"PQ-RBBC/v2.0/abi/randomness").digest(32)
    request = adapter.create(message, mask, randomness)
    hidden = adapter.hidden_state(message, mask, randomness)
    changed_message = bytes((message[0] ^ 1,)) + message[1:]
    return {
        "implementation_version": "2.9",
        "paper_anchor": "Blind-UOV ePrint 2025/895 is a framework and size comparator, not a bit-exact implementation claim",
        "profile": "PQ-RBBC-BUOV-III/Anemoi-193-336 experimental fork",
        "fork_profile": {
            "relation_id": fork_sponge.PROFILE_RELATION_ID,
            "profile_fingerprint": fork_sponge.profile_fingerprint(
                fork_sponge.permutation.derive_parameters()
            ),
            "blind_uov_bit_exact_compatible": False,
            "paper_security_reduction_revalidated": False,
            "paper_signature_size_rebenchmarked": False,
            "cap_relation_id": fork_cap.PROFILE_RELATION_ID,
            "cap_profile_fingerprint": fork_cap.profile_fingerprint(
                fork_cap.PRODUCTION_PARAMETERS
            ),
            "canonical_cap_commitment_bytes": fork_cap.commitment_bytes(
                fork_cap.PRODUCTION_PARAMETERS
            ),
            "reduced_native_relation_id": reduced_native_cap.PROFILE_RELATION_ID,
            "reduced_native_row_stream_sha256": reduced_native_cap.FROZEN_REDUCED_ROW_STREAM_SHA256,
            "extended_2450_native_row_stream_sha256": reduced_native_cap.FROZEN_EXTENDED_ROW_STREAM_SHA256,
            "horner_relation_id": horner_native.PROFILE_RELATION_ID,
            "production_width_horner_row_stream_sha256": "0c9d742d44808a20a35838be84a638924dc5b2f9183bba731eefba1cb9069850",
            "horner_2450_native_relation_id": reduced_native_cap.HORNER_PROFILE_RELATION_ID,
            "horner_2450_native_row_stream_sha256": reduced_native_cap.FROZEN_HORNER_ROW_STREAM_SHA256,
            "production_2048_leaf_shard_relation_id": shard_stream.PROFILE_RELATION_ID,
            "production_2048_leaf_shard_row_stream_sha256": shard_stream.FROZEN_PRODUCTION_STREAM_SHA256,
            "production_4096_leaf_shard_relation_id": shard_stream.PROFILE_RELATION_ID_4096,
            "production_4096_leaf_shard_row_stream_sha256": shard_stream.FROZEN_PRODUCTION_4096_STREAM_SHA256,
            "production_cap_composition_relation_id": cap_composer.RELATION_ID,
            "production_cap_composition_document_sha256": cap_composer.FROZEN_DOCUMENT_SHA256,
            "production_global_tail_relation_id": cap_global_tail.RELATION_ID,
            "production_global_tail_row_stream_sha256": cap_global_tail.FROZEN_PRODUCTION_STREAM_SHA256,
            "production_global_tail_assignment_sha256": cap_global_tail.FROZEN_PRODUCTION_ASSIGNMENT_SHA256,
        },
        "paper_parameters": {
            "security_level_bits": 192,
            "mask_bits": 576,
            "hash_and_sign_signature_bits": 1472,
            "public_key_kilobytes": 189.2,
            "final_signature_bytes_provisional_target": 11644,
            "cap_parallel_repetitions": 18,
            "fork_cap_consistency_bits": fork_cap.PRODUCTION_PARAMETERS.consistency_bits,
            "fork_cap_rho": fork_cap.PRODUCTION_PARAMETERS.rho,
            "cap_tree_groups": [
                {"trees": 2, "leaves_per_tree": 4096},
                {"trees": 16, "leaves_per_tree": 2048}
            ],
            "cap_opened_seeds_upper_bound": 174,
            "explicit_pow_bits": 9,
            "total_pow_bits": 13.9,
            "anemoi_binary_field_degree": 193,
            "anemoi_state_elements": 8,
            "blind_uov_reported_anemoi_constraints_per_permutation": 240,
            "fork_anemoi_constraints_per_permutation": 336,
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
            "576-bit hash image H_RBBC(m,c_r)",
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
            "map": "J_m(r,rho)=r+H_RBBC(m,CAP.Commit(r;rho))",
            "unique_witness_step": "CAP unique-witness soundness makes r a well-defined value for every admissible c_r",
            "random_function_step": "Z(m,c_r)=H_RBBC(m,c_r)+r(c_r) is a pointwise shift of a 576-bit random function",
            "qrom_bound": "O(q_H^3/2^576) plus CAP unique-witness/extraction failure",
            "at_2_pow_128_queries": "the random-function term is O(2^-192)",
            "generic_quantum_collision_cost": "about 2^(576/3)=2^192 queries",
            "status": "generic QROM argument in the ideal model; the concrete forked hash and complete CAP/backend still require independent qualification",
        },
        "v1_6_correction": {
            "independent_parallel_lanes_amplify_security_bits": False,
            "reason": "two independently openable 256-bit claw instances can be solved separately for one fixed message pair",
        },
        "claim_boundary": {
            "test_adapter_is_native_blind_uov": False,
            "test_adapter_uses_forked_anemoi_request_hash": True,
            "test_cap_commitment_is_production_cap": False,
            "blind_uov_bit_exact_compatibility": False,
            "paper_supplies_executable_constraint_generator": False,
            "native_tcih_anemoi_constraint_import_complete": False,
            "production_cap_reference_algorithm_implemented": True,
            "production_cap_canonical_serialization_bound_to_h_rbbc": True,
            "reduced_cap_to_h_rbbc_native_wire_join_complete": True,
            "reduced_cap_native_external_assertions": 0,
            "reduced_cap_profile_is_secure": False,
            "arbitrary_length_multi_squeeze_native": True,
            "production_width_2450_bit_tape_native": True,
            "extended_2450_cap_native_rows": reduced_native_cap.FROZEN_EXTENDED_ROWS,
            "extended_2450_cap_native_wires": reduced_native_cap.FROZEN_EXTENDED_WIRES,
            "extended_2450_cap_native_external_assertions": 0,
            "extended_2450_cap_profile_is_secure": False,
            "bit_bound_gf193_multiplication_native": True,
            "generic_multi_coefficient_horner_native": True,
            "production_2048_bit_horner_vector_native": True,
            "production_2048_bit_horner_coefficients": 11,
            "production_2048_bit_horner_multiplication_rows": 20,
            "symbolic_extension_mask_horner_native": True,
            "horner_2450_cap_native_rows": reduced_native_cap.FROZEN_HORNER_ROWS,
            "horner_2450_cap_native_wires": reduced_native_cap.FROZEN_HORNER_WIRES,
            "horner_2450_cap_native_external_assertions": 0,
            "horner_2450_cap_profile_is_secure": False,
            "production_2048_leaf_shard_rows": shard_stream.FROZEN_PRODUCTION_ROWS,
            "production_2048_leaf_shard_wires": shard_stream.FROZEN_PRODUCTION_WIRES,
            "production_2048_leaf_shard_stream_bytes": shard_stream.FROZEN_PRODUCTION_STREAM_BYTES,
            "production_2048_leaf_shard_external_assertions": 0,
            "production_2048_leaf_shard_executed": True,
            "production_2048_leaf_shard_assignment_materialized": True,
            "production_2048_leaf_shard_assignment_format": shard_assignment.ASSIGNMENT_FORMAT,
            "production_2048_leaf_shard_assignment_archive_bytes": shard_assignment.FROZEN_PRODUCTION_ASSIGNMENT_ARCHIVE_BYTES,
            "production_2048_leaf_shard_assignment_archive_sha256": shard_assignment.FROZEN_PRODUCTION_ASSIGNMENT_ARCHIVE_SHA256,
            "production_2048_leaf_shard_whole_assignment_verified": True,
            "production_2048_leaf_shard_verification_failures": 0,
            "production_2048_leaf_shard_stale_witness_probes": shard_assignment.FROZEN_PRODUCTION_STALE_WITNESS_PROBES,
            "production_2048_leaf_shard_stale_witness_rejected": True,
            "production_2048_leaf_shard_profile_is_secure": False,
            "production_4096_leaf_shard_rows": shard_stream.FROZEN_PRODUCTION_4096_ROWS,
            "production_4096_leaf_shard_wires": shard_stream.FROZEN_PRODUCTION_4096_WIRES,
            "production_4096_leaf_shard_stream_bytes": shard_stream.FROZEN_PRODUCTION_4096_STREAM_BYTES,
            "production_4096_leaf_shard_external_assertions": 0,
            "production_4096_leaf_shard_executed": True,
            "production_4096_leaf_shard_assignment_materialized": True,
            "production_4096_leaf_shard_assignment_format": shard_assignment.ASSIGNMENT_FORMAT,
            "production_4096_leaf_shard_assignment_archive_bytes": shard_assignment.FROZEN_PRODUCTION_4096_ASSIGNMENT_ARCHIVE_BYTES,
            "production_4096_leaf_shard_assignment_archive_sha256": shard_assignment.FROZEN_PRODUCTION_4096_ASSIGNMENT_ARCHIVE_SHA256,
            "production_4096_leaf_shard_whole_assignment_verified": True,
            "production_4096_leaf_shard_verification_failures": 0,
            "production_4096_leaf_shard_stale_witness_probes": shard_assignment.FROZEN_PRODUCTION_4096_STALE_WITNESS_PROBES,
            "production_4096_leaf_shard_stale_witness_rejected": True,
            "production_4096_leaf_shard_profile_is_secure": False,
            "both_production_tree_shard_types_closed_separately": True,
            "production_cap_full_vector_executed": True,
            "canonical_18_tree_link_schedule_closed": True,
            "production_cap_commitment_sha256": cap_composer.FROZEN_COMMITMENT_SHA256,
            "production_cap_request_hash_hex": cap_composer.FROZEN_REQUEST_HASH_HEX,
            "production_cap_xof_trace_sha256": cap_composer.FROZEN_XOF_TRACE_SHA256,
            "production_cap_native_global_tail_materialized": True,
            "production_global_tail_rows": cap_global_tail.FROZEN_PRODUCTION_ROWS,
            "production_global_tail_wires": cap_global_tail.FROZEN_PRODUCTION_WIRES,
            "production_global_tail_replay_failures": 0,
            "production_global_tail_stale_witness_probes": 6,
            "tree_producer_segments_materialized": False,
            "cross_segment_wire_identity_closed": False,
            "complete_18_tree_assignment_replayed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "monolithic_18_tree_assignment_verified": False,
            "full_production_cap_vector_executed": True,
            "full_production_cap_native_rows_materialized": False,
            "production_cap_inter_call_wire_identity_proved": False,
            "linear_y_equals_r_plus_h_internalized": True,
            "test_cap_randomness_bytes": TEST_CAP_RANDOMNESS_BYTES,
            "native_cap_randomness_is_not_fixed_to_test_nonce": True,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(build_abi_manifest(), indent=2, sort_keys=True) + "\n"
    if args.manifest:
        args.manifest.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
