import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pq_rbbc_parent_join_recovery_evidence as evidence


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_PATH = (
    ROOT
    / "artifacts/metadata/parent_join_recovery_v2_29"
    / "pq_rbbc_parent_join_recovery_evidence_v2_29.json"
)


def valid_replay_document() -> tuple[dict[str, object], str]:
    trees = [
        {
            "tree_index": index,
            "rows": 51_325_080 if index < 2 else 25_666_386,
            "verification_failures": 0,
            "row_stream_sha256": f"{index:064x}",
            "component_sha256": f"{index + 18:064x}",
        }
        for index in range(18)
    ]
    tail = {
        "message_sha256": evidence.preflight.PARENT_BOUND_MESSAGE_SHA256,
        "request_hash_sha256": evidence.preflight.PARENT_BOUND_HASH_IMAGE_SHA256,
        "row_stream_sha256": evidence.replay.global_tail.FROZEN_PRODUCTION_STREAM_SHA256,
        "rows": evidence.replay.global_tail.FROZEN_PRODUCTION_ROWS,
        "verification_failures": 0,
    }
    parent = {
        "archive_body_sha256_verified": True,
        "assignment_body_sha256_verified": True,
        "external_assertions": 0,
        "failed_constraints": 0,
        "first_failure": None,
        "join_rows_checked": evidence.replay.JOIN_ROWS,
        "rows_checked": evidence.replay.PARENT_JOIN_ROWS,
        "satisfied": True,
    }
    transcript = {
        "tree_results": trees,
        "relocation_rows": 15_938_520,
        "global_tail_result": tail,
        "parent_join_result": parent,
    }
    digest = hashlib.sha256(evidence.canonical_json(transcript)).hexdigest()
    return {
        "format": evidence.REPLAY_FORMAT,
        "implementation_version": evidence.IMPLEMENTATION_VERSION,
        "relation_id": evidence.replay.RELATION_ID,
        "input_identity": evidence.FROZEN_INPUT_IDENTITY,
        "ordered_replay_transcript_sha256": digest,
        "tree_order": list(range(18)),
        "tree_results": trees,
        "producer_rows": 513_312_336,
        "relocation_rows": 15_938_520,
        "global_tail_result": tail,
        "parent_join_result": parent,
        "aggregate_rows_replayed": evidence.replay.AGGREGATE_ROWS,
        "combined_rows_replayed": evidence.replay.COMBINED_ROWS,
        "verification_failures": 0,
        "external_assertions": 0,
        "claim_boundary": evidence.claim_boundary(),
    }, digest


class ParentJoinRecoveryEvidenceTests(unittest.TestCase):
    def test_frozen_input_identity_reconstructs(self) -> None:
        self.assertEqual(
            evidence.reconstruct_input_identity(), evidence.FROZEN_INPUT_IDENTITY
        )

    def test_replay_contract_accepts_exact_accounting(self) -> None:
        document, digest = valid_replay_document()
        with mock.patch.object(evidence, "FROZEN_TRANSCRIPT_SHA256", digest):
            evidence.validate_replay_document(document)

    def test_parent_join_mutation_is_rejected(self) -> None:
        document, digest = valid_replay_document()
        document["parent_join_result"]["join_rows_checked"] += 1
        with mock.patch.object(evidence, "FROZEN_TRANSCRIPT_SHA256", digest):
            with self.assertRaises(ValueError):
                evidence.validate_replay_document(document)

    def test_claim_expansion_is_rejected(self) -> None:
        document, digest = valid_replay_document()
        document["claim_boundary"]["production_closed"] = True
        with mock.patch.object(evidence, "FROZEN_TRANSCRIPT_SHA256", digest):
            with self.assertRaises(ValueError):
                evidence.validate_replay_document(document)

    def test_tree_reordering_is_rejected(self) -> None:
        document, digest = valid_replay_document()
        document["tree_results"][0], document["tree_results"][1] = (
            document["tree_results"][1],
            document["tree_results"][0],
        )
        with mock.patch.object(evidence, "FROZEN_TRANSCRIPT_SHA256", digest):
            with self.assertRaises(ValueError):
                evidence.validate_replay_document(document)

    def test_file_identity_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact"
            path.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                evidence._require_identity(path, (7, "00" * 32), "fixture")

    def test_portable_evidence_has_no_absolute_paths(self) -> None:
        document = json.loads(EVIDENCE_PATH.read_text())
        self.assertNotIn("/tmp/", json.dumps(document, sort_keys=True))
        self.assertFalse(
            document["artifact_policy"]["portable_evidence_contains_absolute_paths"]
        )
        self.assertTrue(
            document["claim_boundary"]["parent_cap_to_h_rbbc_join_closed"]
        )
        self.assertFalse(document["claim_boundary"]["production_closed"])


if __name__ == "__main__":
    unittest.main()
