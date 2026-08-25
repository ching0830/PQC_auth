#!/usr/bin/env python3
"""Dual-lane hidden-state ABI for the Blind-UOV issuance boundary.

The 31 October 2025 revision of ePrint 2025/895 sends only ``(y, pi_1)`` to
the signer.  The CAP commitment ``c_r``, message ``mu``, mask ``r`` and CAP
randomness ``rho`` are witnesses of pi_1; ``c_r`` appears publicly only later,
inside the finalized Blind-UOV signature.

This module fixes that visibility boundary and applies two independently
randomized, domain-separated Blind-UOV-Is lanes.  A single 256-bit lane does
not provide a 128-bit post-quantum *cross-message claw* target when both
openings may be chosen by an attacker; the pair gives a 512-bit joint target.
Its SHAKE adapter is test-only and does not implement the paper's TCitH/Anemoi
CAP construction.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Protocol


MESSAGE_BYTES = 32
MASK_BYTES = 32
TARGET_BYTES = 32
LANES = 2


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("xor operands must have equal length")
    return bytes(a ^ b for a, b in zip(left, right))


@dataclass(frozen=True)
class BlindUOVRequest:
    """The public signer request, excluding the zero-knowledge proof."""

    masked_targets: tuple[bytes, bytes]

    def encode(self) -> bytes:
        if len(self.masked_targets) != LANES:
            raise ValueError("dual Blind-UOV request must contain two lanes")
        if any(len(target) != TARGET_BYTES for target in self.masked_targets):
            raise ValueError("each Blind-UOV-Is masked target must be 32 bytes")
        return b"".join(self.masked_targets)


@dataclass(frozen=True)
class TestHiddenState:
    """Test-only values that must never be serialized into the signer request."""

    lane: int
    message_digest: bytes
    mask: bytes
    cap_randomness: bytes
    cap_commitment: bytes


class BlindUOVAdapter(Protocol):
    name: str

    def create(
        self,
        message: bytes,
        masks: tuple[bytes, bytes],
        cap_randomness: tuple[bytes, bytes],
    ) -> BlindUOVRequest:
        ...

    def verify_lane(
        self,
        request: BlindUOVRequest,
        lane: int,
        message: bytes,
        mask: bytes,
        cap_randomness: bytes,
    ) -> bool:
        ...

    def verify(
        self,
        request: BlindUOVRequest,
        message: bytes,
        masks: tuple[bytes, bytes],
        cap_randomness: tuple[bytes, bytes],
    ) -> bool:
        ...


class TestBlindUOVAdapter:
    """Non-cryptographic adapter that respects the paper's visibility ABI."""

    name = "TEST-ONLY-HIDDEN-CAP-SHAKE-ADAPTER"
    _commit_label = b"PQ-RBBC/v1.6/TEST-BUOV/CAP-COMMIT"
    _hash_label = b"PQ-RBBC/v1.6/TEST-BUOV/H"

    @staticmethod
    def _check_lengths(
        lane: int, message: bytes, mask: bytes, cap_randomness: bytes
    ) -> None:
        if lane not in range(LANES):
            raise ValueError("Blind-UOV lane must be 0 or 1")
        if len(message) != MESSAGE_BYTES:
            raise ValueError("message digest must be 32 bytes")
        if len(mask) != MASK_BYTES:
            raise ValueError("Blind-UOV-Is mask must be 32 bytes")
        if len(cap_randomness) != 32:
            raise ValueError("test CAP randomness must be 32 bytes")

    def hidden_state(
        self, lane: int, message: bytes, mask: bytes, cap_randomness: bytes
    ) -> TestHiddenState:
        self._check_lengths(lane, message, mask, cap_randomness)
        lane_tag = lane.to_bytes(1, "little")
        commitment = hashlib.shake_256(
            self._commit_label + lane_tag + mask + cap_randomness
        ).digest(32)
        return TestHiddenState(lane, message, mask, cap_randomness, commitment)

    def _create_lane(
        self, lane: int, message: bytes, mask: bytes, cap_randomness: bytes
    ) -> bytes:
        hidden = self.hidden_state(lane, message, mask, cap_randomness)
        digest = hashlib.shake_256(
            self._hash_label
            + lane.to_bytes(1, "little")
            + message
            + hidden.cap_commitment
        ).digest(32)
        return xor_bytes(mask, digest)

    def create(
        self,
        message: bytes,
        masks: tuple[bytes, bytes],
        cap_randomness: tuple[bytes, bytes],
    ) -> BlindUOVRequest:
        if len(masks) != LANES or len(cap_randomness) != LANES:
            raise ValueError("dual Blind-UOV request needs two masks and two randomness values")
        return BlindUOVRequest(
            tuple(
                self._create_lane(lane, message, masks[lane], cap_randomness[lane])
                for lane in range(LANES)
            )
        )

    def verify_lane(
        self,
        request: BlindUOVRequest,
        lane: int,
        message: bytes,
        mask: bytes,
        cap_randomness: bytes,
    ) -> bool:
        if lane not in range(LANES):
            raise ValueError("Blind-UOV lane must be 0 or 1")
        request.encode()
        return request.masked_targets[lane] == self._create_lane(
            lane, message, mask, cap_randomness
        )

    def verify(
        self,
        request: BlindUOVRequest,
        message: bytes,
        masks: tuple[bytes, bytes],
        cap_randomness: tuple[bytes, bytes],
    ) -> bool:
        return all(
            self.verify_lane(
                request, lane, message, masks[lane], cap_randomness[lane]
            )
            for lane in range(LANES)
        )


def build_abi_manifest() -> dict[str, object]:
    adapter = TestBlindUOVAdapter()
    message = hashlib.shake_256(b"PQ-RBBC/v1.6/abi/message").digest(32)
    masks = tuple(
        hashlib.shake_256(b"PQ-RBBC/v1.6/abi/mask" + bytes((lane,))).digest(32)
        for lane in range(LANES)
    )
    randomness = tuple(
        hashlib.shake_256(b"PQ-RBBC/v1.6/abi/randomness" + bytes((lane,))).digest(32)
        for lane in range(LANES)
    )
    request = adapter.create(message, masks, randomness)
    hidden = tuple(
        adapter.hidden_state(lane, message, masks[lane], randomness[lane])
        for lane in range(LANES)
    )
    changed_message = bytes((message[0] ^ 1,)) + message[1:]
    return {
        "implementation_version": "1.6",
        "paper_anchor": "IACR ePrint 2025/895, revision 2025-10-31, Protocols 3 and 4",
        "profile": "Blind-UOV-Is / NIST I / identity F / Shorter / TCitH",
        "public_signer_view": {
            "request_fields_excluding_proof": ["y_0", "y_1"],
            "request_bytes": len(request.encode()),
            "pi_issue_public_inputs": ["common parameters", "ctx", "sid", "rid", "y_0", "y_1"],
        },
        "hidden_pi_issue_witness": [
            "ticket payload M",
            "ticket digest m",
            "independent masks r_0 and r_1",
            "independent CAP randomness rho_0 and rho_1",
            "derived hidden CAP commitments c_r,0 and c_r,1",
            "holder key",
            "trace error vector",
        ],
        "final_signature_view": ["sigma_0=(c_r,0,c_x,0,pi_2,0)", "sigma_1=(c_r,1,c_x,1,pi_2,1)"],
        "final_signed_messages": [
            "mu_0=Encode(PQ-RBBC/BUOV-LANE,0,m)",
            "mu_1=Encode(PQ-RBBC/BUOV-LANE,1,m)",
        ],
        "regression_checks": {
            "honest_request_accepts": adapter.verify(
                request, message, masks, randomness
            ),
            "changed_hidden_message_rejects": not adapter.verify(
                request, changed_message, masks, randomness
            ),
            "request_has_cap_commitment_field": hasattr(request, "cap_commitment"),
            "request_has_message_digest_field": hasattr(request, "message_digest"),
            "request_encoding_equals_two_y_values_only": request.encode()
            == b"".join(request.masked_targets),
            "lane_masks_are_independent": masks[0] != masks[1],
            "lane_randomness_is_independent": randomness[0] != randomness[1],
            "hidden_state_not_in_request_dataclass": all(
                set(asdict(lane_state)).isdisjoint(asdict(request))
                for lane_state in hidden
            ),
        },
        "binding_proof_obligation": {
            "name": "dual-lane cross-message request claw resistance",
            "map": "mu_i=Encode(PQ-RBBC/BUOV-LANE,i,m); J^i_m(r_i,rho_i)=r_i+H_BUOV(mu_i,CAP.Commit_i(r_i;rho_i))",
            "game": "find m!=m' and independent openings whose two-component J vectors are equal",
            "single_lane_warning": "a freely chosen collision/claw on one 256-bit lane has generic quantum cost about 2^(256/3)=2^85",
            "dual_lane_qrom_target": "two domain-separated lanes give a 512-bit joint target and generic quantum collision cost about 2^(512/3)=2^170",
            "status": "required assumption/reduction; not implied by CAP binding plus hash collision resistance",
        },
        "claim_boundary": {
            "test_adapter_is_native_blind_uov": False,
            "paper_supplies_executable_constraint_generator": False,
            "native_tcih_anemoi_constraint_import_complete": False,
            "dual_lane_qrom_reduction_complete": False,
        },
    }


def main() -> None:
    print(json.dumps(build_abi_manifest(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
