"""Portable I/O, artifact absence and source-identity controls."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from publication import runtime, shared
from publication.compare import recompute

ROOT = Path(__file__).resolve().parents[1]


class PublicationTests(unittest.TestCase):
    def test_extracted_wire_helpers_positive_and_mutation(self):
        issuer = dict(setup_wire_bytes=200, request_wire_bytes=37, response_wire_bytes=227)
        result = shared.wire_measurement(200, 37, 227, issuer, 10, 8)
        self.assertEqual(result['issuance_both_directions_without_setup_bytes'], 264)
        with self.assertRaises(ValueError):
            shared.wire_measurement(200, 38, 227, issuer, 10, 8)
        def pin(raw):
            return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        shared.validate_transfer(b'proof', b'statement', dict(proof_body_bytes=5, statement_bytes=9),
                                 pin(b'proof'), pin(b'statement'))
        with self.assertRaises(ValueError):
            shared.validate_transfer(b'proog', b'statement', dict(proof_body_bytes=5, statement_bytes=9),
                                     pin(b'proof'), pin(b'statement'))

    def test_sealed_snapshot_is_immutable_and_bounded(self):
        with shared.sealed_public(b'public-only', 11) as fd:
            self.assertEqual(os.read(fd, 11), b'public-only')
            with self.assertRaises(OSError):
                os.write(fd, b'X')
        with self.assertRaises(ValueError):
            with shared.sealed_public(b'too-long', 1):
                pass

    def test_guard_helper_rejects_unbounded_and_accepts_finite_child(self):
        code = 'from publication.shared import check_limits; check_limits()'
        env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE='1')
        env.pop('BUOV_CAP_EXPLORATION_GUARDED', None)
        self.assertNotEqual(subprocess.run([sys.executable, '-B', '-c', code], env=env, capture_output=True).returncode, 0)
        child = "import os,resource; os.environ['BUOV_CAP_EXPLORATION_GUARDED']='1'; "+\
                "[(resource.setrlimit(k,(n,n))) for k,n in [(resource.RLIMIT_AS,8<<30),(resource.RLIMIT_FSIZE,1<<30),(resource.RLIMIT_CPU,1802)]]; "+code
        self.assertEqual(subprocess.run([sys.executable, '-B', '-c', child], env=env, capture_output=True).returncode, 0)

    def test_missing_artifacts_fail_before_runtime_or_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cfg = root/'config.json'
            cfg.write_text(json.dumps(dict(schema='PQSAT.ThesisCode.Runtime.v0.1', artifacts=str(root/'empty'),
                                           run_root='/tmp/pqsat-buov-cap-hplus-publication-test')))
            result = subprocess.run([sys.executable, '-B', str(ROOT/'release.py'), 'doctor', '--config', str(cfg)],
                                    cwd=temporary, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            record = json.loads(result.stdout)
            self.assertFalse(record['ready'])
            self.assertEqual((record['verified'], record['required']), (0, len(json.loads((ROOT/'provenance/external_artifacts.json').read_text())['artifacts'])))
            self.assertIn('setup-cache/public.hplus-cs-cache', {v['artifact'] for v in record['errors']})

    def test_configuration_cannot_override_gate_or_resource_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'config.json'
            data = dict(schema='PQSAT.ThesisCode.Runtime.v0.1', artifacts=temporary,
                        run_root='/tmp/pqsat-buov-cap-hplus-publication-test')
            for key in ('gate', 'qualified2PC', 'POLICY'):
                path.write_text(json.dumps(dict(data, **{key: True})))
                with self.assertRaises(ValueError):
                    runtime.configuration(path)
            path.write_text('{"schema":"a","schema":"b"}')
            with self.assertRaises(ValueError):
                runtime.configuration(path)

    def test_frozen_source_audit_and_separate_result_recomputation(self):
        from pq_sat_auth.prototypes.buov_cap_hplus_research_v0_1 import public_setup
        public_setup.audit_sources()
        result = recompute()
        self.assertEqual(result['old30']['complete'], 30)
        self.assertFalse(result['HplusFullAccessMeasured'])

    def test_snapshot_provenance_pins(self):
        inventory = json.loads((ROOT/'provenance/source_inventory.json').read_text())
        for name, expected in inventory.items():
            raw = (ROOT/name).read_bytes()
            self.assertEqual(dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()),
                             expected['publication_pin'], name)

    def test_role_bootstrap_relocates_paths_with_frozen_gates(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary)/'config.json'
            run = '/tmp/pqsat-buov-cap-hplus-bootstrap-smoke'
            config.write_text(json.dumps(dict(schema='PQSAT.ThesisCode.Runtime.v0.1', artifacts=temporary,
                                              run_root=run)))
            env = dict(PATH='/usr/bin:/bin', PYTHONDONTWRITEBYTECODE='1',
                       PYTHONPATH=os.pathsep.join((str(ROOT/'publication/bootstrap'), str(ROOT/'src'), str(ROOT))),
                       PQSAT_PUBLICATION_CONFIG=str(config))
            code = "from benchmarks.buov_cap_hplus_research_v0_1 import regression as r,native_build as n,proof_runtime as p; "+\
                   "from pq_sat_auth.prototypes.buov_cap_hplus_research_v0_1 import public_setup as s; "+\
                   "assert str(r.DEFAULT_EXPLORATION)=='"+run+"'; "+\
                   "assert str(r.RUSTC)=='"+temporary+"/toolchain/bin/rustc'; "+\
                   "assert p.PUBLIC_T==r.PUBLIC_T; assert s.audit_native_build.__defaults__==(s.DEFAULT_BUILD,); "+\
                   "assert n.audit.__defaults__==(n.DEFAULT,); s.audit_sources(); print('relocated')"
            result = subprocess.run([sys.executable, '-B', '-c', code], cwd=temporary, env=env, capture_output=True, text=True)
            self.assertEqual((result.returncode, result.stdout.strip()), (0, 'relocated'), result.stderr)
            bad = json.loads(config.read_text()); bad['gate'] = 'OPEN'
            config.write_text(json.dumps(bad))
            result = subprocess.run([sys.executable, '-B', '-c', "print('must not execute')"],
                                    cwd=temporary, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 78)
            self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
