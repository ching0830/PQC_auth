#!/usr/bin/env python3
"""Tests for the fail-closed PQ-RBBC v2.15 fork import contract."""

from __future__ import annotations

import unittest

import pq_rbbc_native_profile as native


class ForkNativeProfileTests(unittest.TestCase):
    def test_selected_profile_is_not_blind_uov_bit_exact(self) -> None:
        manifest = native.build_native_profile_manifest()
        compatibility = manifest["compatibility"]
        self.assertFalse(compatibility["blind_uov_bit_exact_compatible"])
        self.assertFalse(
            compatibility["paper_security_reduction_automatically_inherited"]
        )
        self.assertFalse(
            compatibility["paper_signature_size_automatically_inherited"]
        )
        self.assertFalse(
            compatibility["reported_240_constraint_gap_blocks_fork_engineering"]
        )
        self.assertFalse(manifest["claim_boundary"]["production_closed"])
        self.assertTrue(
            manifest["implemented_primitives"]["production_cap_reference_algorithm"]
        )
        self.assertTrue(
            manifest["implemented_primitives"]["cap_to_h_rbbc_byte_join"]
        )
        self.assertFalse(
            manifest["implemented_primitives"][
                "production_cap_native_rows_materialized"
            ]
        )
        self.assertEqual(manifest["fork_profile"]["cap_commitment_bytes"], 5_391)
        reduced = manifest["fork_profile"]["reduced_native_component"]
        self.assertEqual(reduced["rows"], 88_282)
        self.assertEqual(reduced["wires"], 59_602)
        self.assertEqual(reduced["external_assertions"], 0)
        self.assertTrue(
            manifest["implemented_primitives"][
                "reduced_cap_to_h_rbbc_native_wire_join"
            ]
        )
        self.assertTrue(manifest["claim_boundary"]["reduced_fixture_native_closed"])
        self.assertFalse(manifest["claim_boundary"]["reduced_fixture_security_profile"])
        extended = manifest["fork_profile"]["extended_2450_native_component"]
        self.assertEqual(extended["production_width_tape_bits"], 2_450)
        self.assertEqual(extended["rows"], 113_802)
        self.assertEqual(extended["wires"], 85_034)
        self.assertEqual(extended["anemoi_permutations"], 81)
        self.assertEqual(extended["external_assertions"], 0)
        self.assertTrue(
            manifest["implemented_primitives"][
                "arbitrary_length_multi_squeeze_native"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "extended_2450_fixture_native_closed"
            ]
        )
        arithmetic = manifest["fork_profile"][
            "production_width_horner_component"
        ]
        self.assertEqual(arithmetic["vector_bits"], 2_048)
        self.assertEqual(arithmetic["coefficients"], 11)
        self.assertEqual(arithmetic["multiplication_rows"], 20)
        self.assertEqual(arithmetic["external_assertions"], 0)
        combined = manifest["fork_profile"]["horner_2450_native_component"]
        self.assertEqual(combined["witness_bits"], 386)
        self.assertEqual(combined["consistency_points"], 2)
        self.assertEqual(combined["rows"], 125_401)
        self.assertEqual(combined["wires"], 92_816)
        self.assertEqual(combined["multiplication_rows"], 14)
        self.assertEqual(combined["external_assertions"], 0)
        shard = manifest["fork_profile"][
            "production_2048_leaf_shard_component"
        ]
        self.assertEqual(shard["leaves"], 2_048)
        self.assertEqual(shard["extension_degree"], 12)
        self.assertEqual(shard["witness_bits"], 2_048)
        self.assertEqual(shard["coefficients"], 11)
        self.assertEqual(shard["tape_bits"], 2_450)
        self.assertEqual(shard["rows"], 26_126_283)
        self.assertEqual(shard["wires"], 19_903_324)
        self.assertEqual(shard["external_assertions"], 0)
        self.assertTrue(shard["assignment_materialized"])
        self.assertEqual(shard["assignment_archive_bytes"], 497_583_228)
        self.assertEqual(shard["whole_shard_rows_verified"], 26_126_283)
        self.assertEqual(shard["whole_shard_verification_failures"], 0)
        self.assertEqual(shard["stale_witness_probes"], 5)
        self.assertTrue(shard["stale_witness_probes_rejected"])
        self.assertTrue(
            manifest["claim_boundary"]["arithmetic_primitive_native_closed"]
        )
        self.assertTrue(
            manifest["claim_boundary"]["horner_2450_fixture_native_closed"]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "production_polynomial_hash_blocker_closed"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "production_2048_bit_cap_integration_closed"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "production_2048_leaf_tree_shard_closed"
            ]
        )
        self.assertFalse(
            manifest["claim_boundary"][
                "production_2048_leaf_tree_shard_security_profile"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"]["production_shard_full_assignment_closed"]
        )
        shard_4096 = manifest["fork_profile"][
            "production_4096_leaf_shard_component"
        ]
        self.assertEqual(shard_4096["leaves"], 4_096)
        self.assertEqual(shard_4096["extension_degree"], 13)
        self.assertEqual(shard_4096["rows"], 52_224_501)
        self.assertEqual(shard_4096["wires"], 39_789_564)
        self.assertEqual(shard_4096["external_assertions"], 0)
        self.assertTrue(shard_4096["assignment_materialized"])
        self.assertEqual(shard_4096["assignment_archive_bytes"], 994_739_228)
        self.assertEqual(shard_4096["whole_shard_rows_verified"], 52_224_501)
        self.assertEqual(shard_4096["whole_shard_verification_failures"], 0)
        self.assertEqual(shard_4096["stale_witness_probes"], 5)
        self.assertTrue(shard_4096["stale_witness_probes_rejected"])
        self.assertTrue(
            manifest["claim_boundary"][
                "production_4096_leaf_tree_shard_closed"
            ]
        )
        self.assertFalse(
            manifest["claim_boundary"][
                "production_4096_leaf_tree_shard_security_profile"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "both_production_tree_shard_types_closed_separately"
            ]
        )
        self.assertTrue(
            manifest["implemented_primitives"][
                "production_cap_full_vector_executed"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "full_18_tree_reference_composition_closed"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "canonical_18_tree_link_schedule_closed"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "production_global_tail_native_closed"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "reduced_split_tail_phase_contract_closed"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "canonical_tail_stream_and_assignment_equivalent"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "h1_and_consistency_point_ports_native_closed"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "tail_phase_a_to_phase_b_wire_identity_closed"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"]["production_split_tail_materialized"]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "production_h1_and_two_consistency_point_ports_native_closed"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "production_tail_phase_a_to_phase_b_wire_identity_closed"
            ]
        )
        tree0 = manifest["implemented_primitives"][
            "production_tree0_producer_component"
        ]
        self.assertEqual(tree0["tree_index"], 0)
        self.assertEqual(tree0["leaves"], 4_096)
        self.assertEqual(tree0["extension_degree"], 13)
        self.assertEqual(tree0["rows"], 51_325_080)
        self.assertEqual(tree0["local_wires"], 38_953_830)
        self.assertEqual(tree0["max_wire_id"], 79_148_426)
        self.assertEqual(tuple(tree0["point_wire_starts"]), (39_945_673, 39_945_866))
        self.assertTrue(
            manifest["claim_boundary"][
                "production_index0_4096_degree13_producer_native_closed"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "production_index0_point_wire_identity_closed"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "production_index0_output_values_match_tail"
            ]
        )
        tree2 = manifest["implemented_primitives"][
            "production_tree2_producer_component"
        ]
        self.assertEqual(tree2["tree_index"], 2)
        self.assertEqual(tree2["leaves"], 2_048)
        self.assertEqual(tree2["extension_degree"], 12)
        self.assertEqual(tree2["rows"], 25_666_386)
        self.assertEqual(tree2["local_wires"], 19_478_436)
        self.assertEqual(tree2["max_wire_id"], 59_673_032)
        self.assertEqual(tuple(tree2["point_wire_starts"]), (39_945_673, 39_945_866))
        self.assertEqual(
            tuple(tree2["output_wire_starts"]),
            (58_805_397, 59_595_925, 59_597_973, 59_668_401),
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "production_index2_2048_degree12_producer_native_closed"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "production_index2_point_wire_identity_closed"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "production_index2_output_values_match_tail"
            ]
        )
        relocation = manifest["implemented_primitives"][
            "production_output_relocation_component"
        ]
        self.assertEqual(relocation["representative_tree_indices"], (0, 2))
        self.assertEqual(relocation["relocations"], 8)
        self.assertEqual(relocation["rows"], 2_386_102)
        self.assertEqual(relocation["wires"], 4_772_204)
        self.assertEqual(relocation["external_assertions"], 0)
        self.assertEqual(relocation["verification_failures"], 0)
        for name in (
            "production_representative_output_relocation_contract_closed",
            "production_index0_all_four_output_relocations_closed",
            "production_index2_all_four_output_relocations_closed",
            "all_four_output_relocations_closed",
            "representative_cross_segment_wire_relation_closed",
        ):
            self.assertTrue(manifest["claim_boundary"][name], name)
        namespace = manifest["implemented_primitives"][
            "production_namespace_component"
        ]
        self.assertEqual(namespace["tree_order"], tuple(range(18)))
        self.assertEqual(namespace["point_wire_starts"], (39_945_673, 39_945_866))
        self.assertEqual(namespace["total_producer_wires"], 389_562_636)
        self.assertEqual(namespace["total_producer_rows"], 513_312_336)
        self.assertEqual(namespace["total_output_relocation_rows"], 15_938_520)
        self.assertEqual(namespace["planned_composition_rows"], 586_057_567)
        self.assertEqual(namespace["max_wire_id"], 429_757_232)
        for name in (
            "production_18_tree_namespace_plan_closed",
            "production_namespace_intervals_nonoverlapping",
            "production_global_point_imports_preserved",
            "representative_rebase_rule_fixture_verified",
            "production_tree2_planned_offset_execution_gate_closed",
            "planned_offset_reduced_fixture_replayed",
        ):
            self.assertTrue(manifest["claim_boundary"][name], name)
        rebase = manifest["implemented_primitives"][
            "production_tree2_planned_offset_component"
        ]
        self.assertEqual(rebase["planned_local_wire_start"], 118_102_257)
        self.assertEqual(rebase["planned_max_wire_id"], 137_580_692)
        self.assertEqual(rebase["production_rows_replayed_at_planned_offset"], 0)
        self.assertFalse(rebase["production_assignment_materialized"])
        self.assertFalse(
            manifest["claim_boundary"][
                "production_tree2_rebased_assignment_materialized"
            ]
        )
        self.assertFalse(
            manifest["claim_boundary"]["production_tree2_rebased_full_replay_closed"]
        )
        recovery = manifest["implemented_primitives"][
            "production_composer_recovery_component"
        ]
        self.assertEqual(recovery["production_derivation_levels_checkpointed"], 182)
        self.assertEqual(recovery["production_derivations_checkpointed"], 40_924)
        self.assertEqual(recovery["production_seed_nodes_checkpointed"], 40_960)
        self.assertEqual(recovery["production_leaf_outputs_checkpointed"], 40_960)
        self.assertEqual(
            recovery["evidence_sha256"],
            native.recovery_evidence.FROZEN_EVIDENCE_SHA256,
        )
        self.assertTrue(recovery["production_execution_cache_regenerated"])
        self.assertTrue(recovery["production_composition_document_revalidated"])
        self.assertTrue(
            manifest["claim_boundary"][
                "production_composer_checkpoint_recovery_gate_closed"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"]["reduced_checkpoint_resume_bit_exact"]
        )
        self.assertTrue(
            manifest["claim_boundary"]["production_execution_cache_regenerated"]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "production_composition_document_revalidated"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "production_global_tail_archive_regenerated"
            ]
        )
        self.assertFalse(
            manifest["claim_boundary"]["representative_producers_rebased_replayed"]
        )
        self.assertFalse(
            manifest["claim_boundary"]["all_72_output_relocations_closed"]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "reduced_tree_producer_segments_native_closed"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "reduced_producer_to_tail_port_values_match"
            ]
        )
        self.assertFalse(
            manifest["claim_boundary"][
                "reduced_producer_point_wire_identity_closed"
            ]
        )
        self.assertFalse(
            manifest["claim_boundary"]["tree_producer_segments_materialized"]
        )
        self.assertFalse(
            manifest["claim_boundary"]["cross_segment_wire_identity_closed"]
        )
        self.assertFalse(
            manifest["claim_boundary"]["full_18_tree_composition_closed"]
        )

    def test_missing_import_is_fail_closed(self) -> None:
        audit = native.audit_fork_import(None)
        self.assertFalse(audit.closed)
        self.assertEqual(
            audit.failures, ("fork_native_import_evidence_missing",)
        )

    def test_missing_component_rejects(self) -> None:
        component_rows = {name: 1 for name in native.REQUIRED_NATIVE_COMPONENTS}
        component_rows.pop("ggm_seed_expansion")
        evidence = self._complete_synthetic_evidence(component_rows=component_rows)
        audit = native.audit_fork_import(evidence)
        self.assertFalse(audit.closed)
        self.assertTrue(
            any(item.startswith("missing_native_components:") for item in audit.failures)
        )

    def test_unreviewed_fork_security_rejects(self) -> None:
        evidence = self._complete_synthetic_evidence(
            fork_security_proof_revalidated=False
        )
        audit = native.audit_fork_import(evidence)
        self.assertFalse(audit.closed)
        self.assertIn("fork_security_proof_revalidated", audit.failures)

    def test_unbenchmarked_signature_size_rejects(self) -> None:
        evidence = self._complete_synthetic_evidence(
            signature_size_rebenchmarked=False
        )
        audit = native.audit_fork_import(evidence)
        self.assertFalse(audit.closed)
        self.assertIn("signature_size_rebenchmarked", audit.failures)

    def test_false_bit_exact_claim_rejects(self) -> None:
        evidence = self._complete_synthetic_evidence(
            claims_blind_uov_bit_exact_compatibility=True
        )
        audit = native.audit_fork_import(evidence)
        self.assertFalse(audit.closed)
        self.assertIn("forbidden_blind_uov_bit_exact_claim", audit.failures)

    def test_structurally_complete_synthetic_evidence_passes(self) -> None:
        evidence = self._complete_synthetic_evidence()
        audit = native.audit_fork_import(evidence)
        self.assertTrue(audit.closed, audit.failures)

    @staticmethod
    def _complete_synthetic_evidence(
        **changes: object,
    ) -> native.ForkNativeImportEvidence:
        components = {name: 1 for name in native.REQUIRED_NATIVE_COMPONENTS}
        values: dict[str, object] = {
            "relation_id": native.RELATION_ID,
            "fork_profile_sha256": native.fork_profile_fingerprint(),
            "target_field": native.TARGET_FIELD,
            "generator_source_sha256": "11" * 32,
            "parameter_file_sha256": "22" * 32,
            "row_stream_sha256": "33" * 32,
            "native_rows": len(components),
            "external_assertions": 0,
            "witness_independent_topology": True,
            "honest_accepts": True,
            "tamper_rejections": {
                "message": True,
                "mask": True,
                "cap_randomness": True,
                "hash_image": True,
            },
            "component_rows": components,
            "circuit_ticket_digest_is_native_message": True,
            "circuit_mask_is_native_mask": True,
            "circuit_hash_image_is_native_output": True,
            "domain_separation_locked": True,
            "serialization_locked": True,
            "fork_vectors_verified_independently": True,
            "cap_unique_witness_reviewed": True,
            "cap_straightline_extraction_reviewed": True,
            "fork_security_proof_revalidated": True,
            "signature_size_rebenchmarked": True,
            "claims_blind_uov_bit_exact_compatibility": False,
        }
        values.update(changes)
        if "component_rows" in changes and "native_rows" not in changes:
            values["native_rows"] = sum(
                int(value) for value in values["component_rows"].values()
            )
        return native.ForkNativeImportEvidence(**values)


if __name__ == "__main__":
    unittest.main(verbosity=2)
