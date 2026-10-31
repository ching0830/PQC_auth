"""H+ actual native pi2 producer, using the same prepared CAP state only."""
import time
from .native_build import prover_kwargs
from pq_rbbc.blind_uov_hplus_native_prover_v0_1 import NativeCAPProver
from pq_rbbc.blind_uov_hplus_research_v0_1.codec import encode_pi_2

class FinalCAPKernel:
    def __init__(self,libraries,exploration):
        begin=time.monotonic();self.kernel=NativeCAPProver.load(**prover_kwargs(libraries))
        self.load_seconds=time.monotonic()-begin;self.exploration=exploration
        self.prove_calls=0;self.verify_calls=0;self.verifier_record=None
    def prove(self,ctx,u,c_r,c_z,state):
        self.prove_calls+=1
        return encode_pi_2(self.kernel.prove(ctx,u,c_r,c_z,state,threads=1))
    def close(self):self.kernel.close()
