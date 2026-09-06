#!/usr/bin/env python3
"""Versioned source-identity transition for the canonical trace-KDF split."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Mapping


IMPLEMENTATION_VERSION = "2.40"
FORMAT = "PQRBBC-TRACE-KDF-SOURCE-TRANSITION-1"
RELATION_ID = "pq-rbbc/trace-kdf/source-transition/v1"
ROOT = Path(__file__).resolve().parents[1]

BASE_MAIN_COMMIT = "7769a2e1c9c5aba625d32bb1f9849a81ef111e31"
ORIGINAL_FIX_COMMIT = "6b3d54bcf4918d9706e6f067eedb8aa552c09b96"
CORRECTIVE_CONTENT_COMMIT = "13c0524618b1036063f4cb51f8d3b1147fcf595e"

HISTORICAL_IDENTITIES = {
    "conditional_proof_source": {
        "path": "docs/proof/source/pq_rbbc_sgtd_core_proof_v1.tex",
        "bytes": 148_253,
        "sha256": "c4babfd2070cec9f825d8e6d3692c29b248249a89bf41381258fb1b46827c997",
        "checkpoint": "v2.30",
    },
    "reference_source": {
        "path": "src/pq_rbbc_reference.py",
        "bytes": 69_264,
        "sha256": "4bb9967a56893cf982ffa5189c71f2f50a88a868a1f932f7159dd7613bf80806",
        "checkpoint": "v2.29",
    },
    "reference_tests": {
        "path": "tests/test_pq_rbbc_reference.py",
        "bytes": 20_067,
        "sha256": "839892cde0679050671a578d35cb2e641a70421c4523b148fd4f9f0fd4d0e18d",
        "checkpoint": "pre-corrective main",
    },
}

CANONICAL_IDENTITIES = {
    "conditional_proof_source": {
        "path": "docs/proof/source/pq_rbbc_sgtd_core_proof_v1.tex",
        "bytes": 148_798,
        "sha256": "cee211e7c6419480c0571b752faebe3574d3309f4e876a75cf325f3027d9f884",
    },
    "reference_source": {
        "path": "src/pq_rbbc_reference.py",
        "bytes": 70_542,
        "sha256": "37da0b9834fd2ecd83b482208ea259e0a17b126bb16f50f4ff538d0699046fab",
    },
    "reference_tests": {
        "path": "tests/test_pq_rbbc_reference.py",
        "bytes": 24_844,
        "sha256": "597219c7bb7de2c01593d2505c791a93db9fc1a66dd8ab9512c54be6bfefd6e9",
    },
}


def canonical_json(document: Mapping[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def identity(path: Path | None) -> dict[str, object]:
    if path is None or not path.is_file():
        return {"bytes": None, "sha256": None}
    return {"bytes": path.stat().st_size, "sha256": _sha256(path)}


def identity_matches(path: Path | None, expected: Mapping[str, object]) -> bool:
    observed = identity(path)
    return (
        observed["bytes"] == expected.get("bytes")
        and observed["sha256"] == expected.get("sha256")
    )


def build_transition_manifest() -> dict[str, object]:
    return {
        "format": FORMAT,
        "implementation_version": IMPLEMENTATION_VERSION,
        "relation_id": RELATION_ID,
        "transition": {
            "base_main_commit": BASE_MAIN_COMMIT,
            "original_fix_commit": ORIGINAL_FIX_COMMIT,
            "corrective_content_commit": CORRECTIVE_CONTENT_COMMIT,
            "reason": "correct fix was in ancestry but absent from the effective main tree",
            "historical_manifests_and_checksums_rewritten": False,
        },
        "historical_identities": HISTORICAL_IDENTITIES,
        "canonical_identities": CANONICAL_IDENTITIES,
        "canonical_split": {
            "kdf_output_bytes": 80,
            "byte_indexing": "zero-based half-open",
            "ordering": "Z = P || K_mac",
            "pad": {"name": "P", "offset": [0, 48], "bytes": 48},
            "mac_key": {"name": "K_mac", "offset": [48, 80], "bytes": 32},
            "direct_helper": "split_trace_kdf_output",
            "constraint_helper": "split_trace_kdf_wires",
            "alternate_order_is_a_new_profile": True,
        },
        "frozen_vectors": {
            "pad_hex": (
                "05d55d5c53c03ecbbf4d3b2fc1a85bed27270f8a2c223abcc1c22c42b1886cbc"
                "99a87a12adc761f070f3d5ac82efbde8"
            ),
            "mac_key_hex": (
                "8fe834eaf1b9709306ad6bb5d7e92da6429e952c33aa53c5e0991390ae5465cb"
            ),
            "masked_identity_hex": (
                "d25e40637cfdc440d8f18f199f4fbfdd341667a16574343d7d1d0aca21eb2c2"
                "f0d6f660ca2ef999e5337d9d77add8319"
            ),
            "tag_hex": (
                "02719cd84e00ea323270bdf0dd634771ef8f3e93eba0662b7f193afcf27acedb"
            ),
            "ticket_payload_sha256": (
                "8d88e08b4c5283723803906e00e47064b75cfe5e134faed9ef2be72fb46aa3e0"
            ),
            "ticket_digest_hex": (
                "ef49a7a0ba4788c062ccfa21dab6d0bfd35ba2c20bb19b0fbadc0e205ee44870"
            ),
        },
        "qualification": {
            "targeted_test_module": "tests.test_pq_rbbc_reference",
            "targeted_test_count": 14,
            "required_tests": [
                "test_trace_kdf_canonical_split_and_frozen_vector",
                "test_trace_kdf_split_rejects_noncanonical_boundaries",
                "test_trace_kdf_wrong_order_rejected_by_direct_relation",
                "test_trace_kdf_wrong_order_rejected_by_constraint_circuit",
            ],
            "rejected_byte_lengths": [79, 81],
            "rejected_bit_lengths": [639, 641],
            "frozen_vectors_changed": False,
        },
        "claim_boundary": {
            "source_transition_contract_closed": True,
            "canonical_trace_kdf_split_implemented_and_tested": True,
            "historical_v2_29_v2_30_evidence_rewritten": False,
            "production_opening_implemented": False,
            "qualified_pq_se_nizk_backend_selected": False,
            "fork_security_proof_revalidated": False,
            "production_closed": False,
        },
    }


def validate_current_tree(root: Path = ROOT) -> tuple[str, ...]:
    failures: list[str] = []
    for label, expected in CANONICAL_IDENTITIES.items():
        path = root / str(expected["path"])
        if not identity_matches(path, expected):
            failures.append(f"{label}_identity")
    return tuple(failures)


def validate_transition(
    manifest_path: Path,
    expected_manifest_identity: tuple[int, str],
    root: Path = ROOT,
) -> tuple[str, ...]:
    failures: list[str] = []
    expected = {
        "bytes": expected_manifest_identity[0],
        "sha256": expected_manifest_identity[1],
    }
    if not identity_matches(manifest_path, expected):
        failures.append("transition_manifest_identity")
    elif manifest_path.read_bytes() != canonical_json(build_transition_manifest()):
        failures.append("transition_manifest_contract")
    failures.extend(validate_current_tree(root))
    return tuple(failures)
