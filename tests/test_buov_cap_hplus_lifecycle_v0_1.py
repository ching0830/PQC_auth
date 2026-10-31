"""H+ role/codec/profile controls; no Init, inversion, proof or secret fixtures."""
import dataclasses
import os
import unittest
from pathlib import Path
from pq_sat_auth.prototypes.buov_cap_hplus_research_v0_1 import full_statement as n,full_witness as w,public_setup as ps
from pq_sat_auth.prototypes.buov_cap_hplus_research_v0_1 import ticket_consumer as tc,nonhash_census as layout
from pq_sat_auth.prototypes.buov_cap_hplus_research_v0_1.continuation import request_digest
from pq_rbbc.blind_uov_hplus_research_v0_1 import parameters as profile
from pq_rbbc.blind_uov_hplus_research_v0_1.uov import UOVPublicMap,CPK_BYTES
from pq_rbbc.blind_uov_hplus_native_prover_v0_1 import NativeCAPProver
from benchmarks.buov_cap_hplus_research_v0_1.proof_runtime import own_records,reconstruct,beta_from_statement,validate
from benchmarks.buov_cap_hplus_research_v0_1 import native_build

class HplusRoles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ids=ps.public_setup_pins();cls.setup=n.FullPublicSetup(ids.compiler_id,ids.setup_id,ids.trace_digest)
        cls.public_map=UOVPublicMap(bytes(CPK_BYTES));cls.records=own_records(cls.public_map,cls.setup)
        cls.snapshot=n.FullNCCSnapshot.from_records(cls.records)
        cls.raw=n.statement(cls.snapshot,bytes(72),cls.setup)
    def test_01_new_profile_and_frames(self):
        self.assertEqual((n.FRAME_BYTES,w.FRAME_BYTES),(1037,2030298));tc._fixed_profile()
        self.assertEqual(n.x18.FINGERPRINT,profile.PROFILE_FINGERPRINT)
        self.assertEqual(layout.CR_HEADER[12:14],b'\xff\x33')
    def test_02_reconstruct(self):
        self.assertEqual(beta_from_statement(self.raw),bytes(72))
        self.assertEqual(reconstruct(self.raw,self.snapshot,self.setup),self.raw[-846:])
    def test_03_foreign_setup_rejected(self):
        for k in ('compiler_id','setup_id','trace_digest'):
            with self.assertRaises(ValueError):dataclasses.replace(self.setup,**{k:bytes(32)})
    def test_04_changed_own_records_rejected(self):
        for k,v in self.records.items():
            changed=dict(self.records);changed[k]=bytes([v[0]^1])+v[1:]
            with self.subTest(k=k),self.assertRaises(ValueError):
                snap=n.FullNCCSnapshot.from_records(changed);reconstruct(self.raw,snap,self.setup)
    def test_05_statement_canonical(self):
        for at in (0,5,9,13,14,len(self.raw)-846,len(self.raw)-32):
            changed=self.raw[:at]+bytes([self.raw[at]^1])+self.raw[at+1:]
            with self.subTest(at=at),self.assertRaises(ValueError):reconstruct(changed,self.snapshot,self.setup)
        for raw in (self.raw[:-1],self.raw+b'\0'):
            with self.assertRaises(ValueError):reconstruct(raw,self.snapshot,self.setup)
    def test_06_request_digest(self):
        self.assertNotEqual(request_digest(self.raw,bytes(32)),request_digest(self.raw,b'\1'+bytes(31)))
        with self.assertRaises(ValueError):request_digest(self.raw+b'\0',bytes(32))
    def test_07_private_frame(self):
        values={name:bytes(width) for name,_,width in w.FIELD_LAYOUT};values['CR']=layout.CR_HEADER+bytes(5024)
        witness=w.pack_fields(values,compiler_id=self.setup.compiler_id);raw=w.encode_frame(witness)
        self.assertEqual(w.decode_frame(raw,compiler_id=self.setup.compiler_id).semantic_body,witness.semantic_body)
        self.assertNotIn(values['CR'].hex(),repr(witness))
        for changed in (raw[:-1],raw+b'\0',raw[:44]+b'X'+raw[45:]):
            with self.assertRaises(ValueError):w.decode_frame(changed,compiler_id=self.setup.compiler_id)
    def test_08_legacy_CR_rejected(self):
        with self.assertRaises(ValueError):w.validate_syntax(layout.CR_HEADER[:12]+b'\xff\x32'+layout.CR_HEADER[14:]+bytes(w.SEMANTIC_BYTES-50))
    def test_09_own_consumer_scope(self):
        config=tc.ResearchPublicConfig.from_records(self.public_map,{k:self.records[k] for k in n.x18.SCOPE_FIELDS})
        self.assertEqual(config.scope,self.snapshot.reconstruct(bytes(72))[1])
        with self.assertRaises(ValueError):tc.ResearchPublicConfig.from_records(self.public_map,dict(config.records(),RID=bytes(32)))
    def test_10_legacy_types_rejected(self):
        from pq_rbbc.blind_uov_pqsat_v0_1.uov import UOVPublicMap as Old
        with self.assertRaises(ValueError):tc.ResearchPublicConfig.from_records(Old(bytes(CPK_BYTES)),{k:self.records[k] for k in n.x18.SCOPE_FIELDS})
    def test_11_false_verifier_metadata_rejected(self):
        data=ps.checkpoint();record={k:data[k] for k in ('compiler_id','setup_id','actual_symbolic_setup','public_CS_identity','counts')}
        record.update(schema='BUOVCAPHPlusProofExecutionV1',private_values_received=False,compute_cores=1,security_bits=128,
            statement_bytes=1037,Prove=0,proof_Verify=1,accepted=False,proof_body_bytes=100)
        validate(record,False,100)
        for k,v in [('private_values_received',True),('accepted',1),('proof_Verify',0),('compiler_id','00'*32)]:
            with self.assertRaises(ValueError):validate(dict(record,**{k:v}),False,100)
    @unittest.skipUnless(os.environ.get('BUOV_HPLUS_LIFECYCLE_EXTERNAL')=='1','exact external H+ lifecycle libraries not requested')
    def test_12_native_profile_gate(self):
        libs=native_build.provision()
        kernel=NativeCAPProver.load(**native_build.prover_kwargs(libs));kernel.close()
        from pq_rbbc.blind_uov_native_prover_v0_1 import NativeCAPProver as Old
        with self.assertRaises(RuntimeError):Old.load(**native_build.prover_kwargs(libs))

    def test_13_strict_new_transport(self):
        import io
        from benchmarks.buov_cap_hplus_research_v0_1 import channel as c
        from benchmarks.buov_cap_research_v0_1 import single_issuance_channel as old
        stream=io.BytesIO();count=c.write_request(stream,self.raw,b'public-proof-body')
        stream.seek(0);statement,proof,received=c.read_request(stream)
        self.assertEqual((statement,proof,count,received),(self.raw,b'public-proof-body',count,count))
        stream.seek(0)
        with self.assertRaises(ValueError):old.read_request(stream)
        for bad in (self.raw[:-6],self.raw+b'\0'):
            with self.assertRaises(ValueError):c.write_request(io.BytesIO(),bad,b'x')
        stream=io.BytesIO();c.write_response(stream)
        stream.seek(0);self.assertEqual(c.read_response(stream),(None,None,11))

if __name__=='__main__':unittest.main()
