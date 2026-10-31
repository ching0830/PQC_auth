"""Actual-setup metadata boundaries. These tests never verify an issuance proof."""
from copy import deepcopy
from dataclasses import replace
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from pq_sat_auth.prototypes.buov_cap_hplus_research_v0_1 import public_setup as p


class HPlusSetupMetadataTests(unittest.TestCase):
    def test_cold_and_reload_agree_with_own_frozen_checkpoint(self):
        data = p.checkpoint()
        for name in ('cold','reload'):
            p.validate_public_setup_result(data['measurements'][name])
        actual = data['actual_symbolic_setup']
        self.assertEqual([(s['len'],s['log_msg_len'],s['is_zk']) for s in actual['merged']],
            [(863,10,True),(9933087,24,True),(98715,17,True),(512,9,True)])
        self.assertEqual(actual['outer']['mask_dims'],[7,2])
        self.assertEqual(actual['n_test_queries'],309)

    def test_own_pins_reject_foreign_setup_and_noncanonical_types(self):
        own = p.public_setup_pins()
        for changes in (dict(compiler_id=bytes(32)),dict(setup_id=bytes(32)),
                        dict(trace_digest=bytes(32)),dict(setup_id=bytearray(own.setup_id)),
                        dict(setup_id=bytes.fromhex('6e64167b50e9fcd8a9d82add92fcbc121eac0d3521a8699402541947a0bb168c'))):
            with self.assertRaises(ValueError):
                replace(own,**changes)

    def test_profile_cs_compiler_and_setup_mixing_rejected(self):
        good = p.checkpoint()['measurements']['cold']
        for field in ('compiler_id','setup_id','profile_fingerprint','relation_id','trace_sha256'):
            changed = deepcopy(good);changed[field] = '00'*32
            with self.assertRaises(ValueError):
                p.validate_public_setup_result(changed)
        changed = deepcopy(good);changed['public_CS_identity']['sha256'] = '00'*32
        with self.assertRaises(ValueError):
            p.validate_public_setup_result(changed)
        for key in ('cache_sha256','source_sha256'):
            changed = deepcopy(good);changed['cache'][key] = '00'*32
            with self.assertRaises(ValueError):
                p.validate_public_setup_result(changed)

    def test_query_mask_schedule_and_counts_mutations_reject(self):
        good = p.checkpoint()['measurements']['cold']
        for field,value in (('n_test_queries',232),('security_bits',96),('fold_arities',[4,4,3,2])):
            changed = deepcopy(good);changed['actual_symbolic_setup'][field] = value
            with self.assertRaises(ValueError):
                p.validate_public_setup_result(changed)
        changed = deepcopy(good);changed['actual_symbolic_setup']['outer']['mask_dims'] = [6,2]
        with self.assertRaises(ValueError):
            p.validate_public_setup_result(changed)
        changed = deepcopy(good);changed['actual_symbolic_setup']['merged'][1]['len'] = 9932038
        with self.assertRaises(ValueError):
            p.validate_public_setup_result(changed)
        changed = deepcopy(good);changed['counts']['public_words'] = True
        with self.assertRaises(ValueError):
            p.validate_public_setup_result(changed)

    def test_setup_cannot_be_relabelled_as_proof_or_witness_result(self):
        good = p.checkpoint()['measurements']['cold']
        for field,value in (('Prove',1),('Verify',1),('Prove',False),('private_values_received',True),
                            ('private_ValueVec_allocated',True),('satisfiability_checked',True),
                            ('proof_body_bytes',995632),('mode','full-verify'),('schema','unknown')):
            changed = deepcopy(good);changed[field] = value
            with self.assertRaises(ValueError):
                p.validate_public_setup_result(changed)

    def test_header_rejects_old_magic_source_cs_T_shape_and_length(self):
        raw = bytes.fromhex(p.checkpoint()['cache_header_hex'])
        p.validate_cache_header(raw)
        for offset in (0,8,12,16,24,56,88,120,148,156):
            changed = bytearray(raw);changed[offset] ^= 1
            with self.assertRaises(ValueError):
                p.validate_cache_header(bytes(changed))
        for changed in (b'BCSCACH1'+raw[8:],raw[:-1],raw+b'\0',bytearray(raw)):
            with self.assertRaises(ValueError):
                p.validate_cache_header(changed)

    def test_duplicate_and_unbounded_public_metadata_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'metadata.json'
            for raw in (b'{"x":1,"x":2}',b'{"x":NaN}'):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    p._json(path)
            path.write_bytes(b' '*100)
            with self.assertRaises(ValueError):
                p._json(path,cap=99)


@unittest.skipUnless(os.environ.get('BUOV_HPLUS_SETUP_EXTERNAL')=='1','explicit local H+ setup inputs not requested')
class HPlusSetupActualInputsTests(unittest.TestCase):
    def test_pinned_actual_binary_shared_sources_and_readonly_cache(self):
        p.audit_native_build();p.audit_public_cache()

    def test_setup_binary_rejects_proof_dispatch_before_T_or_large_allocation(self):
        p.audit_native_build()
        for mode in ('full-prove','full-verify'):
            result = subprocess.run([str(p.DEFAULT_BUILD/'hplus_setup'),mode,'unused'],
                stdin=subprocess.DEVNULL,capture_output=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn(b'public-only modes',result.stderr)


if __name__ == '__main__':
    unittest.main()
