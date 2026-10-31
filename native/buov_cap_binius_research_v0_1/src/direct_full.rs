//! Complete CS replay/setup only. This module has no full Prove entry.
use std::{io::{self,Read},time::Instant};
use anyhow::{ensure,Result};
use bytes::{BufMut,buf::UninitSlice};
use sha3::Digest;
use serde_json::{Value,json};
use binius_core::constraint_system::ConstraintSystem;
use binius_utils::SerializeBytes;
use binius_iop::merkle_tree::BinaryMerkleTreeScheme;
use binius_verifier::config::B128;
use crate::{direct_core::DirectBuilder,direct_relation,read,hex,memory,counts,ZV};

/// Bounded streaming sink for the PUBLIC CS codec; never holds the large encoding.
struct CSHash {digest:binius_hash::StdDigest,buffer:[u8;65536],used:usize,bytes:usize}
impl CSHash {
    fn new()->Self {Self{digest:Default::default(),buffer:[0;65536],used:0,bytes:0}}
    fn flush(&mut self) {self.digest.update(&self.buffer[..self.used]);self.used=0;}
    fn finish(mut self)->(String,usize) {self.flush();(hex(&self.digest.finalize()),self.bytes)}
}
// SAFETY: chunk_mut exposes only this sink's initialized byte buffer. The caller
// initializes exactly n bytes before advance_mut, per BufMut's contract. We only
// hash that initialized prefix, and never expose storage beyond its capacity.
unsafe impl BufMut for CSHash {
    fn remaining_mut(&self)->usize {(4usize<<30).checked_sub(self.bytes).expect("bounded public codec hash")}
    unsafe fn advance_mut(&mut self,n:usize) {assert!(n<=self.buffer.len()-self.used && n<=self.remaining_mut());self.used+=n;self.bytes+=n;}
    fn chunk_mut(&mut self)->&mut UninitSlice {
        if self.used==self.buffer.len(){self.flush();}
        let n=(self.buffer.len()-self.used).min(self.remaining_mut());
        UninitSlice::new(&mut self.buffer[self.used..self.used+n])
    }
}
pub(crate) fn cs_identity(cs:&ConstraintSystem)->Result<Value> {
    let mut hash=CSHash::new();cs.serialize(&mut hash)?;let (sha256,bytes)=hash.finish();
    Ok(json!({"sha256":sha256,"serialized_bytes_streamed_to_hash":bytes,"encoding_persisted":false}))
}
pub(crate) fn private_body(compiler_id:&[u8])->Result<Vec<u8>> {
    const DOMAIN:&[u8]=b"PQSAT-BUOV-CAP-RESEARCH/FULL-WITNESS/v0.1\0";
    let width=44+DOMAIN.len()+direct_relation::PRIVATE_BYTES;
    let mut raw=Vec::new();io::stdin().take((width+1)as u64).read_to_end(&mut raw)?;
    ensure!(raw.len()==width && &raw[..8]==b"NIFW\0\x01\0\x17","exact private input ABI");
    ensure!(&raw[8..40]==compiler_id,"private input compiler identity");
    ensure!(u32::from_be_bytes(raw[40..44].try_into().unwrap())as usize==direct_relation::PRIVATE_BYTES
        && &raw[44..44+DOMAIN.len()]==DOMAIN,"private input domain/length");
    Ok(raw.split_off(44+DOMAIN.len()))
}
pub(crate) fn setup_record(v:&ZV)->Value {
    let spec=|s:&binius_iop::channel::OracleSpec|json!({"len":s.len,"log_msg_len":s.log_msg_len,"is_zk":s.is_zk});
    let schedule=v.oracle_schedule();let params=v.basefold_compiler().fri_params();
    let scheme=BinaryMerkleTreeScheme::<B128,binius_hash::StdHashSuite>::new();
    json!({"rounds":schedule.rounds().map(|r|r.iter().map(&spec).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "merged":schedule.merged_specs().iter().map(&spec).collect::<Vec<_>>(),
        "max_log_domain_size":v.basefold_compiler().max_log_domain_size(),
        "security_bits":binius_verifier::SECURITY_BITS,"log_inv_rate":v.log_inv_rate(),
        "n_test_queries":params.n_test_queries(),"fold_arities":params.fold_arities(),
        "FRI_component_exact_format_bytes":binius_iop::fri::proof_size(params,&scheme),
        "full_proof_body_bytes":Value::Null,"full_proof_size_includes_unaccounted_IP_messages":true})
}
pub fn run(mode:&str,public_path:&str,tail_path:&str)->Result<()> {
    let start=Instant::now();let prover=mode=="full-replay";
    let public=read(public_path,direct_relation::PUBLIC_BYTES)?;
    let tail=read(tail_path,direct_relation::TAIL_BYTES)?;
    let trace:[u8;32]=binius_hash::StdDigest::digest(&tail).into();
    ensure!(hex(&trace)==crate::TRACE_SHA,"trusted raw T");
    let abi:Vec<u8>=(0..32).map(|i|u8::from_str_radix(&"a69b30be67c77ac06464fe654e3c834625fa1c0db43ac0020b40437a88557b7d"[2*i..2*i+2],16).unwrap()).collect();
    let secret=if prover {Some(private_body(&abi)?)}else{
        ensure!(io::stdin().read(&mut[0u8;1])?==0,"public setup receives no witness");None
    };
    let b=DirectBuilder::new(prover);
    direct_relation::compile(&b,&public,secret.as_deref(),&tail,&trace)?;
    let shape=counts(&b.counts());let compiled=b.finish();
    drop(secret);
    let mut result=json!({"mode":mode,"counts":shape,"build_seconds":start.elapsed().as_secs_f64(),
        "after_build":memory()?,"private_values_received":prover,"Prove":0,"proof_Verify":0,
        "full_functional_pi_iss_research":false,"classification":"complete CS replay/public verifier setup, NOT a full proof"});
    if let Some(values)=compiled.values {
        let replay=Instant::now();compiled.cs.verify(&values)?;
        result["replay_seconds"]=json!(replay.elapsed().as_secs_f64());
        result["complete_constraints_satisfied"]=json!(true);drop(values);
    }
    let hashing=Instant::now();result["public_CS_identity"]=cs_identity(&compiled.cs)?;
    result["CS_hash_seconds"]=json!(hashing.elapsed().as_secs_f64());
    if !prover {
        let setup=Instant::now();let verifier=ZV::setup(compiled.cs,1)?;
        result["setup_seconds"]=json!(setup.elapsed().as_secs_f64());
        result["actual_symbolic_setup"]=setup_record(&verifier);
    }
    result["whole_seconds"]=json!(start.elapsed().as_secs_f64());result["final_memory"]=memory()?;
    println!("DIRECT_RESULT {result}");Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_codec_hash_sink_matches_digest_across_buffer_boundaries() {
        let mut end=CSHash::new();end.bytes=(4usize<<30)-3;assert_eq!(end.chunk_mut().len(),3);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(||end.put_slice(&[0;4]))).is_err());
        for n in [0,1,65535,65536,65537,131109] {
            let data:Vec<_>=(0..n).map(|i|(i*17)as u8).collect();
            let mut sink=CSHash::new();sink.put_slice(&data);let (hash,bytes)=sink.finish();
            assert_eq!(hash,hex(&binius_hash::StdDigest::digest(&data)));assert_eq!(bytes,n);
        }
    }
}
