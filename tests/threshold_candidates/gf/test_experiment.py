import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from pq_threshold_candidates.gf.__main__ import run_reference_experiment


class ExperimentTests(unittest.TestCase):
    def test_cli_reports_reference_only_without_secret_material(self):
        result = subprocess.run([sys.executable, '-m', 'pq_threshold_candidates.gf', '--samples', '1'],
                                env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'),
                                check=True, capture_output=True, text=True)
        report = json.loads(result.stdout)
        observed = report['observed']
        self.assertEqual(observed['evidence_kind'], 'measured_reference')
        self.assertEqual(observed['successful_decryptions'], 1)
        self.assertEqual(observed['ciphertext_payload_bytes'], 2848)
        self.assertEqual(observed['ciphertext_record_bytes'], 2910)
        self.assertIsNone(report['measured_threshold'])
        self.assertIsNone(report['estimated']['total_ticket_bytes'])
        self.assertFalse(report['claims']['production_qualified'])
        self.assertEqual(set(report), {'schema', 'profile_id', 'profile_descriptor_sha256', 'environment',
                                       'observed', 'estimated', 'measured_threshold', 'satellite_online_observation', 'claims'})
        self.assertEqual(set(observed), {'evidence_kind', 'keypairs', 'samples', 'successful_decryptions',
                                         'successful_relation_evaluations', 'public_key_payload_bytes',
                                         'public_key_record_bytes', 'ciphertext_payload_bytes',
                                         'ciphertext_record_bytes', 'keygen_ns', 'median_ns'})

    def test_invalid_sample_limits_and_production_option_rejected(self):
        for value in (True, 0, 17, -1, 1.0):
            with self.assertRaises(ValueError):
                run_reference_experiment(value)
        for args in (['--samples', '0'], ['--samples', '17'], ['--production']):
            failed = subprocess.run([sys.executable, '-m', 'pq_threshold_candidates.gf'] + args,
                                    capture_output=True, text=True)
            self.assertEqual(failed.returncode, 2)
            self.assertEqual(failed.stdout, '')

    def test_failed_correctness_emits_no_success_report(self):
        with patch('pq_threshold_candidates.gf.__main__.decrypt_reference_for_test', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'no success report'):
                run_reference_experiment(1)


if __name__ == '__main__':
    unittest.main()
