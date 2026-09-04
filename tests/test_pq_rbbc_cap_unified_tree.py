import dataclasses
import itertools
import unittest

import pq_rbbc_cap_commit as legacy
import pq_rbbc_cap_unified_tree as unified


class UnifiedTreeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.parameters = unified.REDUCED_TEST_PARAMETERS
        cls.randomness = unified.deterministic_randomness(cls.parameters)
        cls.execution = unified.execute_commit(cls.parameters, cls.randomness)
        cls.challenge_prefix = b"PQ-RBBC/v2.33/reduced/challenge-prefix"
        cls.opening, cls.trials = unified.grind_opening(
            cls.execution, cls.challenge_prefix
        )
        cls.commitment_bytes = cls.execution.commitment.encode()
        cls.opening_bytes = cls.opening.encode(cls.parameters)
        cls.verification = unified.verify_opening(
            cls.parameters,
            cls.challenge_prefix,
            cls.commitment_bytes,
            cls.opening_bytes,
        )

    def test_namespace_and_profiles_are_independent(self) -> None:
        self.assertEqual(len(set(unified.DOMAINS)), len(unified.DOMAINS))
        self.assertTrue(all(item.startswith(unified.DOMAIN_PREFIX) for item in unified.DOMAINS))
        legacy_domains = {
            legacy.DOMAIN_SEED_DERIVE,
            legacy.DOMAIN_SEED_COMMIT,
            legacy.DOMAIN_TAPE_EXPAND,
            legacy.DOMAIN_H1,
            legacy.DOMAIN_H2,
        }
        self.assertTrue(legacy_domains.isdisjoint(unified.DOMAINS))
        self.assertNotEqual(
            unified.profile_fingerprint(unified.PRODUCTION_PARAMETERS),
            legacy.profile_fingerprint(legacy.PRODUCTION_PARAMETERS),
        )

    def test_production_mapping_is_an_exact_bijection(self) -> None:
        parameters = unified.PRODUCTION_PARAMETERS
        observed = set()
        for repetition, leaves in enumerate(parameters.logical_leaf_counts):
            for position in range(leaves):
                index = unified.logical_to_unified_index(
                    parameters, repetition, position
                )
                self.assertEqual(
                    unified.unified_to_logical_index(parameters, index),
                    (repetition, position),
                )
                observed.add(index)
        self.assertEqual(observed, set(range(40_960)))
        self.assertEqual(parameters.challenge_widths, (12, 12) + (11,) * 16)
        self.assertEqual(parameters.challenge_index_bits, 200)

    def test_single_root_expands_every_internal_node(self) -> None:
        parameters = self.parameters
        derive_records = [
            item
            for item in self.execution.xof_records
            if item.domain_hex == unified.DOMAIN_SEED_DERIVE.hex()
        ]
        self.assertEqual(len(derive_records), parameters.total_leaves - 1)
        self.assertEqual(len(self.execution.nodes), 2 * parameters.total_leaves - 1)
        self.assertEqual(self.execution.nodes[0], self.randomness.root_seed)

    def test_reduced_positive_vector_is_frozen(self) -> None:
        self.assertEqual(
            unified.profile_fingerprint(self.parameters),
            "8f6d0e474f96f6fe907ed08f76dc81ff424f1c4405bda971c92e9541daa5c3e8",
        )
        self.assertEqual(self.trials, 12)
        self.assertEqual(self.opening.counter, 11)
        self.assertEqual(self.opening.hidden_positions, (0, 0, 1, 1))
        self.assertEqual(len(self.opening.frontier), 3)
        self.assertEqual(len(self.commitment_bytes), 158)
        self.assertEqual(len(self.opening_bytes), 425)
        self.assertTrue(self.verification.accepted)
        self.assertEqual(self.verification.failures, ())
        self.assertEqual(self.verification.opened_leaf_count, 8)
        self.assertEqual(
            unified.trace_digest(self.execution.xof_records),
            "3b478eb9177887c8934a48913fe54dbc20335dc2c4e46d25aae049571f0fa7a0",
        )

    def test_opening_frontier_distribution_exercises_rejection(self) -> None:
        parameters = self.parameters
        counts: dict[int, int] = {}
        for positions in itertools.product(
            *(range(leaves) for leaves in parameters.logical_leaf_counts)
        ):
            size = len(unified.canonical_frontier_indices(parameters, positions))
            counts[size] = counts.get(size, 0) + 1
        self.assertEqual(counts, {1: 1, 2: 1, 3: 6, 4: 20, 5: 16, 6: 20})
        self.assertEqual(sum(value for size, value in counts.items() if size <= 4), 28)

    def test_commitment_and_opening_codecs_are_strict(self) -> None:
        self.assertEqual(
            unified.UnifiedCommitment.decode(self.parameters, self.commitment_bytes),
            self.execution.commitment,
        )
        self.assertEqual(
            unified.UnifiedOpening.decode(self.parameters, self.opening_bytes),
            self.opening,
        )
        for encoded in (
            self.commitment_bytes[:-1],
            self.commitment_bytes + b"\x00",
            bytes([self.commitment_bytes[0] ^ 1]) + self.commitment_bytes[1:],
        ):
            with self.assertRaises(unified.UnifiedTreeError):
                unified.UnifiedCommitment.decode(self.parameters, encoded)
        for encoded in (
            self.opening_bytes[:-1],
            self.opening_bytes + b"\x00",
            bytes([self.opening_bytes[0] ^ 1]) + self.opening_bytes[1:],
        ):
            with self.assertRaises(unified.UnifiedTreeError):
                unified.UnifiedOpening.decode(self.parameters, encoded)

    def test_transcript_and_frontier_mutations_reject(self) -> None:
        changed_prefix = b"X" + self.challenge_prefix[1:]
        result = unified.verify_opening(
            self.parameters,
            changed_prefix,
            self.commitment_bytes,
            self.opening_bytes,
        )
        self.assertFalse(result.accepted)
        self.assertIn("h3_mismatch", result.failures)

        changed_position = dataclasses.replace(
            self.opening,
            hidden_positions=(
                (self.opening.hidden_positions[0] + 1)
                % self.parameters.logical_leaf_counts[0],
                *self.opening.hidden_positions[1:],
            ),
        )
        result = unified.verify_opening(
            self.parameters,
            self.challenge_prefix,
            self.commitment_bytes,
            changed_position.encode(self.parameters),
        )
        self.assertFalse(result.accepted)
        self.assertIn("hidden_positions_mismatch", result.failures)

        changed_seed = dataclasses.replace(
            self.opening,
            frontier=(
                dataclasses.replace(
                    self.opening.frontier[0],
                    seed=self.opening.frontier[0].seed ^ 1,
                ),
                *self.opening.frontier[1:],
            ),
        )
        result = unified.verify_opening(
            self.parameters,
            self.challenge_prefix,
            self.commitment_bytes,
            changed_seed.encode(self.parameters),
        )
        self.assertFalse(result.accepted)
        self.assertIn("root_commitment_mismatch", result.failures)

    def test_explicit_pow_and_t_open_are_both_enforced(self) -> None:
        bad = None
        for counter in range(self.opening.counter):
            candidate = unified.opening_candidate(
                self.execution, self.challenge_prefix, counter
            )
            if not unified.opening_is_acceptable(self.parameters, candidate):
                bad = candidate
                break
        self.assertIsNotNone(bad)
        result = unified.verify_opening(
            self.parameters,
            self.challenge_prefix,
            self.commitment_bytes,
            bad.encode(self.parameters),
        )
        self.assertFalse(result.accepted)
        self.assertTrue(
            {"explicit_pow_bits_nonzero", "frontier_exceeds_t_open"}
            & set(result.failures)
        )

    def test_production_profile_is_disabled(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "disabled"):
            unified.execute_commit(
                unified.PRODUCTION_PARAMETERS,
                unified.deterministic_randomness(unified.PRODUCTION_PARAMETERS),
            )


if __name__ == "__main__":
    unittest.main()
