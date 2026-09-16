from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

import pq_rbbc_cap_unified_tree_launch_validation_v2_41 as historical
import pq_rbbc_issuance_parent_i1_i5_candidateset_preflight_v1 as parent
import pq_rbbc_launch_io_v2_41 as io


class ParentI1I5CandidateSetPreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.session, cls.temporary, cls.candidate = (
            parent._fixture_candidate_insecure_test_only()
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.session.close()
        cls.temporary.cleanup()

    def _snapshot(self, original: io.Snapshot, raw: bytes) -> io.Snapshot:
        return io.Snapshot(original.location, raw)

    def _candidate(self, **changes: object) -> parent.ParentI1I5CandidateSetInsecureTestOnly:
        return replace(self.candidate, **changes)

    def _mutate_handoff(self, mutate) -> parent.ParentI1I5CandidateSetInsecureTestOnly:
        document = self.candidate.handoff.document()
        mutate(document)
        handoff = self._snapshot(self.candidate.handoff, parent.canonical_json(document))
        return self._candidate(handoff=handoff)

    def _validate(self, candidate=None, digest=None):
        candidate = self.candidate if candidate is None else candidate
        digest = candidate.handoff.identity["sha256"] if digest is None else digest
        return parent.validate_candidate_set_insecure_test_only(
            candidate, expected_handoff_sha256=digest
        )

    def test_read_only_preflight_and_production_refusal(self) -> None:
        report = parent.preflight()
        self.assertTrue(report["read_only_preflight_passed"])
        self.assertEqual(report["canonical_source_snapshot_roles"], 40)
        self.assertEqual(report["public_input_bits"], 1_600)
        self.assertEqual(report["secret_witness_bits"], 11_622)
        self.assertEqual(report["planned_native_join_bits"], 6_654)
        self.assertEqual(report["parent_constraints_replayed"], 0)
        self.assertFalse(report["safe_to_execute_parent_relation_now"])
        for entrypoint in (parent.execute_parent_relation, parent.execute_production):
            with self.assertRaises(parent.ParentProductionUnavailable):
                entrypoint(Path("/must-not-be-read"), Path("/must-not-be-created"))

    def test_positive_candidate_and_frozen_evidence(self) -> None:
        decoded = self._validate()
        self.assertEqual(len(decoded.snapshot_identities), 40)
        self.assertEqual(len(decoded.c_r), 511)
        self.assertEqual(len(decoded.request_hash), 72)
        evidence = parent.candidate_evidence(self.candidate)
        for key in (
            "handoff_identity",
            "parameters_identity",
            "statement_identity",
            "witness_identity",
            "snapshot_inventory_sha256",
            "snapshot_roles",
            "host_reference_conjuncts_checked",
            "parent_constraints_replayed",
            "native_join_rows_replayed",
        ):
            self.assertEqual(evidence[key], parent.FROZEN[key])

    def test_external_handoff_digest_precedes_dependencies(self) -> None:
        with mock.patch.object(
            parent, "validate_prerequisites", side_effect=AssertionError("dependency touched")
        ):
            with self.assertRaisesRegex(parent.ParentCandidateError, "before dependencies"):
                self._validate(digest="0" * 64)

    def test_parameters_wrong_magic_version_order_and_trailing_rejected(self) -> None:
        raw = self.candidate.parameters.raw
        mutations = []
        changed = bytearray(raw)
        changed[0] ^= 1
        mutations.append(bytes(changed))
        changed = bytearray(raw)
        changed[len(parent.PARAMETERS_MAGIC)] = 2
        mutations.append(bytes(changed))
        offset = len(parent.PARAMETERS_MAGIC) + 4
        changed = bytearray(raw)
        changed[offset] = 2
        mutations.append(bytes(changed))
        mutations.append(raw + b"x")
        for mutation in mutations:
            with self.subTest(sha256=hashlib.sha256(mutation).hexdigest()):
                candidate = self._candidate(
                    parameters=self._snapshot(self.candidate.parameters, mutation)
                )
                with self.assertRaises(parent.ParentCandidateError):
                    self._validate(candidate)

    def test_statement_wrong_version_trailing_and_beta_rejected(self) -> None:
        raw = self.candidate.statement.raw
        changed = bytearray(raw)
        changed[len(parent.backend.STATEMENT_MAGIC)] = 2
        variants = [bytes(changed), raw + b"x"]
        statement = parent.backend.IssueStatementV1.decode(raw)
        variants.append(
            replace(
                statement,
                beta=bytes((statement.beta[0] ^ 1,)) + statement.beta[1:],
            ).encode()
        )
        for mutation in variants:
            with self.subTest(sha256=hashlib.sha256(mutation).hexdigest()):
                candidate = self._candidate(
                    statement=self._snapshot(self.candidate.statement, mutation)
                )
                with self.assertRaises(parent.ParentCandidateError):
                    self._validate(candidate)

    def test_witness_field_mutations_and_trailing_rejected(self) -> None:
        witness = parent.ParentWitnessV1.decode(self.candidate.witness.raw)

        def flip(raw: bytes) -> bytes:
            return bytes((raw[0] ^ 1,)) + raw[1:]

        rho = bytearray(witness.cap_randomness)
        rho[len(parent.cap.RANDOMNESS_MAGIC) + 64] ^= 1

        variants = (
            replace(witness, ticket_payload=flip(witness.ticket_payload)).encode(),
            replace(witness, blind_mask=flip(witness.blind_mask)).encode(),
            replace(witness, cap_randomness=bytes(rho)).encode(),
            replace(witness, holder_key=flip(witness.holder_key)).encode(),
            replace(witness, error_vector=flip(witness.error_vector)).encode(),
            self.candidate.witness.raw + b"x",
        )
        for mutation in variants:
            with self.subTest(sha256=hashlib.sha256(mutation).hexdigest()):
                candidate = self._candidate(
                    witness=self._snapshot(self.candidate.witness, mutation)
                )
                with self.assertRaises(parent.ParentCandidateError):
                    self._validate(candidate)

    def test_inventory_pair_swap_repin_and_bool_ordinal_rejected(self) -> None:
        def swap(document):
            inventory = document["snapshot_inventory"]
            inventory[0], inventory[1] = inventory[1], inventory[0]
            inventory[0]["ordinal"] = 0
            inventory[1]["ordinal"] = 1
            document["snapshot_inventory_sha256"] = parent._inventory_digest(inventory)

        candidate = self._mutate_handoff(swap)
        with self.assertRaises(parent.ParentCandidateError):
            self._validate(candidate)

        def boolean(document):
            document["snapshot_inventory"][0]["ordinal"] = False
            document["snapshot_inventory_sha256"] = parent._inventory_digest(
                document["snapshot_inventory"]
            )

        candidate = self._mutate_handoff(boolean)
        with self.assertRaises(parent.ParentCandidateError):
            self._validate(candidate)

    def test_handoff_unknown_duplicate_and_trailing_rejected(self) -> None:
        candidate = self._mutate_handoff(lambda document: document.update({"unknown": 1}))
        with self.assertRaises(parent.ParentCandidateError):
            self._validate(candidate)
        raw = self.candidate.handoff.raw
        duplicate = raw[:-2] + b',"format":"duplicate"}\n'
        candidate = self._candidate(
            handoff=self._snapshot(self.candidate.handoff, duplicate)
        )
        with self.assertRaises(parent.ParentCandidateError):
            self._validate(candidate)
        candidate = self._candidate(
            handoff=self._snapshot(self.candidate.handoff, raw + b"\n")
        )
        with self.assertRaises(parent.ParentCandidateError):
            self._validate(candidate)

    def test_source_completion_identity_repin_rejected(self) -> None:
        def mutate(document):
            document["source_completion_handoff_identity"]["sha256"] = "0" * 64

        candidate = self._mutate_handoff(mutate)
        with self.assertRaises(parent.ParentCandidateError):
            self._validate(candidate)

    def test_captured_raw_survives_later_pathname_rewrite(self) -> None:
        with TemporaryDirectory(prefix="pq-rbbc-parent-snapshot-") as directory:
            path = Path(directory) / parent.STATEMENT_NAME
            path.write_bytes(self.candidate.statement.raw)
            captured = io.read_snapshot(path)
            path.write_bytes(b"later-pathname-content")
            candidate = self._candidate(statement=captured)
            decoded = self._validate(candidate)
            self.assertEqual(decoded.statement.encode(), self.candidate.statement.raw)

    def test_wire_and_join_plans_are_exact_and_contiguous(self) -> None:
        cursor = 1
        for _, _, interval in parent.WIRE_PLAN:
            self.assertEqual(type(interval["start"]), int)
            self.assertEqual(interval["start"], cursor)
            self.assertEqual(
                interval["end_exclusive"] - interval["start"], interval["bits"]
            )
            cursor = interval["end_exclusive"]
        self.assertEqual(cursor, parent.PARENT_LOCAL_INPUT_END)
        self.assertEqual(sum(bits for _, bits, _ in parent.JOIN_PLAN), 6_654)

    def test_manifest_and_portable_evidence_keep_claims_closed(self) -> None:
        manifest = parent.build_manifest()
        claims = manifest["claim_status"]
        self.assertTrue(claims["fresh_parent_i1_i5_candidate_composed"])
        self.assertFalse(claims["parent_relation_consumer_implemented"])
        self.assertEqual(claims["parent_constraints_replayed"], 0)
        self.assertFalse(claims["Proof-closed"])
        self.assertFalse(claims["Production-closed"])
        evidence = parent.build_portable_evidence()
        self.assertTrue(evidence["portable_metadata_only"])
        self.assertFalse(evidence["private_snapshot_statement_or_witness_embedded"])
        self.assertFalse(evidence["absolute_paths_embedded"])
        self.assertEqual(evidence["parent_constraints_replayed"], 0)
        self.assertEqual(evidence["proofs_generated"], 0)

    def test_historical_v238_v239_identities_unchanged(self) -> None:
        self.assertEqual(len(historical.HISTORICAL_IDENTITIES), 19)
        for relative, expected in historical.HISTORICAL_IDENTITIES.items():
            raw = (parent.ROOT / relative).read_bytes()
            self.assertEqual(len(raw), expected["bytes"], relative)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), expected["sha256"], relative)

    def test_tracked_manifest_and_evidence_match_generators(self) -> None:
        self.assertEqual(
            (parent.ROOT / parent.MANIFEST_PATH).read_bytes(),
            parent.canonical_json(parent.build_manifest()),
        )
        self.assertEqual(
            (parent.ROOT / parent.EVIDENCE_PATH).read_bytes(),
            parent.canonical_json(parent.build_portable_evidence()),
        )


if __name__ == "__main__":
    unittest.main()
