import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path

import pq_rbbc_anemoi_sponge as h_rbbc
import pq_rbbc_cap_commit as cap
import pq_rbbc_issuance_reduced_constraint_v1 as reduced
import pq_rbbc_issuance_zk_backend_preflight as backend_preflight


class ReducedConstraintCodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = reduced.fixture()

    def test_parameter_and_witness_round_trip(self):
        parameters = reduced.ReducedConstraintParametersV1.decode(
            self.fixture.parameters
        )
        witness = reduced.ReducedIssueWitnessV1.decode(self.fixture.witness)
        self.assertEqual(parameters.encode(), self.fixture.parameters)
        self.assertEqual(witness.encode(), self.fixture.witness)
        self.assertEqual(len(parameters.trace_public_key), 1_045_216)
        self.assertEqual(len(witness.cap_randomness), reduced.CAP_RANDOMNESS_BYTES)

    def test_statement_keeps_public_production_shape(self):
        statement = backend_preflight.IssueStatementV1.decode(
            self.fixture.statement
        )
        self.assertEqual(statement.abi_profile_digest, reduced.ABI_PROFILE_DIGEST)
        self.assertEqual(
            statement.public_parameters_digest,
            hashlib.sha256(self.fixture.parameters).digest(),
        )
        self.assertEqual(
            tuple(map(len, (statement.ctx, statement.sid, statement.rid, statement.beta))),
            (32, 32, 32, 72),
        )

    def test_parameter_wrong_version_and_trailing_bytes_rejected(self):
        wrong_version = bytearray(self.fixture.parameters)
        wrong_version[len(reduced.PARAMETERS_MAGIC)] = 2
        for candidate in (bytes(wrong_version), self.fixture.parameters + b"\x00"):
            with self.assertRaises(reduced.ReducedConstraintError):
                reduced.ReducedConstraintParametersV1.decode(candidate)

    def test_parameter_section_reordering_rejected(self):
        changed = bytearray(self.fixture.parameters)
        first_section = len(reduced.PARAMETERS_MAGIC) + 4
        changed[first_section : first_section + 2] = (2).to_bytes(2, "little")
        with self.assertRaises(reduced.ReducedConstraintError):
            reduced.ReducedConstraintParametersV1.decode(bytes(changed))

    def test_witness_wrong_version_and_trailing_bytes_rejected(self):
        wrong_version = bytearray(self.fixture.witness)
        wrong_version[len(reduced.WITNESS_MAGIC)] = 2
        for candidate in (bytes(wrong_version), self.fixture.witness + b"\x00"):
            with self.assertRaises(reduced.ReducedConstraintError):
                reduced.ReducedIssueWitnessV1.decode(candidate)

    def test_wrong_cap_profile_rejected(self):
        witness = reduced.ReducedIssueWitnessV1.decode(self.fixture.witness)
        wrong_rho = cap.deterministic_randomness(
            cap.PRODUCTION_PARAMETERS, b"wrong-profile"
        ).serialize(cap.PRODUCTION_PARAMETERS)
        with self.assertRaises(reduced.ReducedConstraintError):
            replace(witness, cap_randomness=wrong_rho).encode()

    def test_trace_key_identity_is_bound_by_statement_pp(self):
        parameters = reduced.ReducedConstraintParametersV1.decode(
            self.fixture.parameters
        )
        trace_key = bytearray(parameters.trace_public_key)
        trace_key[-1] ^= 1
        alternate = reduced.ReducedConstraintParametersV1(bytes(trace_key)).encode()
        with self.assertRaisesRegex(
            reduced.ReducedConstraintError, "parameters digest mismatch"
        ):
            reduced.generate_reduced_constraint_prototype(
                alternate,
                self.fixture.statement,
                self.fixture.witness,
                production=False,
            )


class ReducedConstraintExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = reduced.fixture()
        cls.self_check = reduced.run_bounded_self_check()
        cls.positive = reduced.generate_reduced_constraint_prototype(
            cls.fixture.parameters,
            cls.fixture.statement,
            cls.fixture.witness,
            production=False,
        )

    def test_bounded_self_check(self):
        self.assertTrue(self.self_check["positive_satisfied"])
        self.assertTrue(self.self_check["beta_mutation_rejected"])
        self.assertTrue(self.self_check["error_mutation_rejected"])
        self.assertTrue(self.self_check["wrong_domain_refused"])
        self.assertTrue(self.self_check["production_refused_before_input_decode"])
        self.assertEqual(self.self_check["external_assertions"], 0)
        self.assertEqual(self.self_check["join_failures"], 0)
        self.assertEqual(self.self_check["large_relation_rows_replayed"], 0)
        self.assertEqual(self.self_check["cryptographic_proofs_generated"], 0)

    def test_exact_public_private_partition(self):
        self.assertEqual(self.positive.public_input_bits, 1_600)
        self.assertEqual(self.positive.secret_witness_bits, 11_622)
        self.assertEqual(self.positive.internal_bridge_bits, 576)
        self.assertEqual(
            set(self.positive.blocks),
            {
                "P0_public_statement",
                "I1_ticket_shape",
                "I2_ticket_hash",
                "I3_reduced_cap_h_rbbc_join",
                "I4_holder",
                "I5_trace",
            },
        )

    def test_native_child_and_all_ports_are_closed(self):
        self.assertTrue(self.positive.satisfied)
        self.assertEqual(self.positive.child_rows, 88_282)
        self.assertEqual(self.positive.child_failed_rows, 0)
        self.assertEqual(self.positive.child_external_assertions, 0)
        self.assertEqual(self.positive.join_rows, 2_022)
        self.assertEqual(self.positive.join_failures, 0)
        self.assertEqual(
            [binding.name for binding in self.positive.port_bindings],
            ["message", "rho", "derived_mask_prefix", "request_hash"],
        )
        self.assertTrue(all(binding.matched for binding in self.positive.port_bindings))

    def test_parent_shape_and_bounded_accounting_are_frozen(self):
        self.assertEqual(self.positive.parent_rows, 2_969_180)
        self.assertEqual(self.positive.combined_rows, 3_059_484)
        self.assertEqual(
            self.positive.parent_shape_sha256,
            "1903f27ab2b6c2f5033aef51e8292cc12a48d8dfeaa10896418a66af8f44c773",
        )

    def test_nonzero_mask_tail_is_rejected(self):
        witness = reduced.ReducedIssueWitnessV1.decode(self.fixture.witness)
        changed = bytearray(witness.blind_mask)
        changed[reduced.REDUCED_MASK_BYTES] = 1
        report = reduced.generate_reduced_constraint_prototype(
            self.fixture.parameters,
            self.fixture.statement,
            replace(witness, blind_mask=bytes(changed)).encode(),
            production=False,
        )
        self.assertFalse(report.satisfied)
        self.assertGreater(report.parent_failed_assertions, 0)

    def test_wrong_domain_refuses_before_trace(self):
        with self.assertRaisesRegex(reduced.ReducedConstraintError, "wrong H_RBBC"):
            reduced.generate_reduced_constraint_prototype(
                self.fixture.parameters,
                self.fixture.statement,
                self.fixture.witness,
                production=False,
                request_domain=b"PQ-RBBC/WRONG",
            )

    def test_production_refuses_before_input_decode_or_output(self):
        with self.assertRaisesRegex(
            reduced.ProductionConstraintUnavailable, "before input decode"
        ):
            reduced.generate_reduced_constraint_prototype(b"", b"", b"")

    def test_stale_child_port_and_assignment_mutations_reject(self):
        failed = reduced._evaluate_join_rows(
            "stale.request_hash",
            (2, 3),
            (0, 1),
            (1, 2),
            (1, 1),
            10,
        )
        self.assertEqual(failed, 1)

        witness = reduced.ReducedIssueWitnessV1.decode(self.fixture.witness)
        payload = witness.ticket_payload
        message = hashlib.shake_256(
            b"PQ-RBBC/TICKET" + payload
        ).digest(32)
        child = reduced._child_trace(witness.cap_randomness, message)
        changed = dict(child.assignment)
        output_wire = child.request_hash_bit_wires[0]
        changed[output_wire] ^= 1
        self.assertTrue(child.failed_rows(changed))

    def test_manifest_claims_remain_fail_closed(self):
        manifest = reduced.build_manifest()
        gate = manifest["production_gate"]
        self.assertFalse(gate["production_cap_576_relation_instantiated"])
        self.assertFalse(gate["certified_trace_key_instantiated"])
        self.assertFalse(gate["qualified_pq_se_backend_integrated"])
        self.assertFalse(gate["formal_pi_issue_generated"])
        self.assertFalse(gate["safe_to_start_large_replay"])
        self.assertFalse(gate["safe_to_start_large_proving_run"])
        self.assertFalse(manifest["claim_status"]["Proof-closed"])
        self.assertFalse(manifest["claim_status"]["Production-closed"])
        self.assertEqual(manifest["tracked_validation_failures"], [])

    def test_manifest_is_canonical_json(self):
        manifest = reduced.build_manifest()
        encoded = reduced.canonical_json(manifest)
        tracked = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "manifests/pq_rbbc_issuance_reduced_constraint_manifest_v1.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(json.loads(encoded), manifest)
        self.assertEqual(tracked, manifest)
        self.assertTrue(encoded.endswith(b"\n"))

    def test_portable_evidence_matches_builder(self):
        tracked = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "artifacts/metadata/issuance_reduced_constraint_v1/"
                "pq_rbbc_issuance_reduced_constraint_portable_evidence_v1.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(tracked, reduced.build_portable_evidence())


if __name__ == "__main__":
    unittest.main()
