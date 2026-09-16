import json
import os
import subprocess
import sys
import unittest

from pq_threshold_candidates import Candidate
from pq_threshold_candidates.accounting import SizeEstimate, comparison_report, estimate_sizes


class AccountingTests(unittest.TestCase):
    def test_paper_derived_component_arithmetic(self):
        rows = comparison_report(extra_bytes=0)["profiles"]
        expected = [(2816, 14540, None), (6752, 18476, None), (1136, 12860, None), (288, 12012, 12012)]
        for row, (cipher_known, ticket_known, ticket_total) in zip(rows, expected):
            with self.subTest(profile=row["profile_id"]):
                estimate = row["estimated"]
                self.assertEqual(estimate["ciphertext"]["known_bytes"], cipher_known)
                self.assertEqual(estimate["ticket"]["known_bytes"], ticket_known)
                self.assertEqual(estimate["ticket"]["total_bytes"], ticket_total)
                self.assertEqual(estimate["sigma_status"], "provisional_estimate")

    def test_unknowns_survive_json_without_zero_substitution(self):
        report = json.loads(json.dumps(comparison_report()))
        for row in report["profiles"]:
            ticket = row["estimated"]["ticket"]
            self.assertIsNone(ticket["total_bytes"])
            self.assertIsNone(ticket["components"]["extra_bytes"])
            self.assertIn("extra_bytes", ticket["unknown_terms"])
        self.assertIn("g_bytes", report["profiles"][0]["estimated"]["ciphertext"]["unknown_terms"])
        self.assertIn("Delta_bytes", report["profiles"][2]["estimated"]["ciphertext"]["unknown_terms"])

    def test_explicit_assumptions_do_not_become_observations(self):
        report = comparison_report(g_bytes=32, delta_bytes=28, extra_bytes=0)
        expected = [14572, 18508, 12888, 12012]
        for row, size in zip(report["profiles"], expected):
            self.assertEqual(row["estimated"]["ticket"]["total_bytes"], size)
            self.assertEqual(row["estimated"]["evidence_kind"], "estimated")
            self.assertEqual(row["literature_reported"], [])
            for name, value in row["observed"].items():
                self.assertEqual(value, "observed" if name == "evidence_kind" else None)

    def test_estimate_cannot_be_supplied_as_observation(self):
        # This generator deliberately has no observation-import/promotion API.
        with self.assertRaises(TypeError):
            comparison_report(observed={"ticket_bytes": 12012})
        with self.assertRaises(TypeError):
            SizeEstimate((("x", 1),), evidence_kind="observed")

    def test_unknown_sigma_and_explicit_zero_remain_distinct(self):
        unknown = comparison_report(sigma_bytes=None, extra_bytes=0)["profiles"][-1]["estimated"]
        self.assertIsNone(unknown["ticket"]["total_bytes"])
        zero = comparison_report(sigma_bytes=0, extra_bytes=0)["profiles"][-1]["estimated"]
        self.assertEqual(zero["ticket"]["total_bytes"], 368)
        self.assertEqual(zero["sigma_status"], "provisional_estimate")

    def test_all_size_inputs_reject_invalid_integers(self):
        for name in ("sigma_bytes", "extra_bytes", "g_bytes", "delta_bytes"):
            for invalid in (True, False, -1, 2**64, 1.0, "1", float("nan")):
                with self.subTest(name=name, value=invalid), self.assertRaises(ValueError):
                    comparison_report(**{name: invalid})

    def test_aggregate_overflow_rejected(self):
        with self.assertRaises(ValueError):
            SizeEstimate((("a", 2**64 - 1), ("b", 1)))
        with self.assertRaises(ValueError):
            comparison_report(sigma_bytes=2**64 - 1)

    def test_duplicate_and_mutable_components_rejected(self):
        for terms in ((("x", 1), ("x", 2)), ((True, 1),), [], (), (["x", 1],)):
            with self.assertRaises(ValueError):
                SizeEstimate(terms)

    def test_irrelevant_candidate_expansion_rejected(self):
        with self.assertRaises(ValueError):
            estimate_sizes(Candidate.NIED, "nied-6688128-estimate-v1", g_bytes=32)
        with self.assertRaises(ValueError):
            estimate_sizes(Candidate.GF, "gf-pompeii-d4-estimate-v1", delta_bytes=28)

    def test_envelope_is_reported_separately_from_payload(self):
        row = comparison_report()["profiles"][-1]["estimated"]
        self.assertGreater(row["research_envelope_overhead_bytes"], 0)
        self.assertEqual(row["ciphertext"]["total_bytes"], 288)
        overhead = row["research_envelope_overhead_bytes"]
        wrapped = comparison_report(extra_bytes=overhead)["profiles"][-1]["estimated"]
        self.assertEqual(wrapped["ticket"]["total_bytes"], 12012 + overhead)

    def test_cli_estimate_and_invalid_input(self):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run([sys.executable, "-m", "pq_threshold_candidates", "--delta-bytes", "28", "--extra-bytes", "0"],
                                capture_output=True, text=True, env=env, check=True)
        report = json.loads(result.stdout)
        self.assertEqual(report["profiles"][2]["estimated"]["ticket"]["total_bytes"], 12888)
        for invalid in ("-1", "True", str(2**64), str(2**64 - 1)):
            failed = subprocess.run([sys.executable, "-m", "pq_threshold_candidates", "--sigma-bytes", invalid],
                                    capture_output=True, text=True, env=env)
            self.assertEqual(failed.returncode, 2)
            self.assertEqual(failed.stdout, "")


if __name__ == "__main__":
    unittest.main()
