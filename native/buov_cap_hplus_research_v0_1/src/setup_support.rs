//! Public-only setup helpers derived from pinned direct_full.rs; no dispatcher/witness parser.
use anyhow::Result;
use bytes::{BufMut,buf::UninitSlice};
use sha3::Digest;
use serde_json::{Value,json};
use binius_core::constraint_system::ConstraintSystem;
use binius_utils::SerializeBytes;
use binius_iop::merkle_tree::BinaryMerkleTreeScheme;
use binius_verifier::config::B128;
use crate::{hex,ZV};
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
