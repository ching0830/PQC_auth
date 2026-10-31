//! Full public count-only lowering. Never retains a CS, witness, or proof.
#[path="lib.rs"]
mod implementation;
pub use implementation::*;
use std::{io::{self,Read},time::Instant};
use anyhow::{ensure,Result};
use serde_json::json;
use sha2::{Digest,Sha256};

fn main()->Result<()>{
    let start=Instant::now();
    let mut tail=Vec::new();io::stdin().take((direct_relation::TAIL_BYTES+1)as u64).read_to_end(&mut tail)?;
    ensure!(tail.len()==direct_relation::TAIL_BYTES,"exact captured public T width");
    let digest:[u8;32]=Sha256::digest(&tail).into();
    let hexadecimal:String=digest.iter().map(|x|format!("{x:02x}")).collect();
    ensure!(hexadecimal=="4ce48825d1e78c704b89a160be8d47932ae9bc7948d282d0c7c12c8ccc63c986","pinned public T identity");
    // Public VALUES below are dummy. Shape is independent of those values;
    // count-only mode cannot finish as a CS or claim any satisfying witness.
    let mut public=vec![0;direct_relation::PUBLIC_BYTES];
    public[..32].copy_from_slice(direct_relation_profile::FINGERPRINT);
    public[272..304].copy_from_slice(direct_relation_profile::FINGERPRINT);
    public[240..272].copy_from_slice(direct_relation_profile::RELATION_ID);
    public[814..846].copy_from_slice(direct_relation_profile::BINDING_ID);
    let b=direct_core::DirectBuilder::new_counting();
    direct_relation::compile(&b,&public,None,&tail,&digest)?;
    let c=b.finish_counting();
    let q=binius_iop::fri::calculate_n_test_queries(128,1);
    ensure!(binius_verifier::SECURITY_BITS==128 && q==309,"recomputed query-target128 only");
    let memory=std::fs::read_to_string("/proc/self/status")?;
    let hwm=memory.lines().find(|s|s.starts_with("VmHWM:")).unwrap().split_whitespace().nth(1).unwrap().parse::<u64>()?*1024;
    println!("{}",json!({"schema":"BUOVCAPHPlusFullCountV1","counts":{
        "constants":c.constants,"public_words":c.inout,"private_words":c.private,
        "AND":c.and,"ZERO":c.zero,"operand_terms":c.operand_terms,
        "max_operand_support":c.max_operand_support,"native_len_bytes":c.native_len_bytes,
        "serialized_bytes":c.serialized_bytes,"templates":{"unique":c.unique_templates,
        "terms":c.template_terms,"payload_bytes":c.template_payload_bytes}},
        "public_T_sha256":hexadecimal,"query_target_bits":128,"n_test_queries":q,
        "count_seconds":start.elapsed().as_secs_f64(),"process_hwm_bytes":hwm,
        "CS_materialized":false,"private_values_received":false,"Prove":0,"Verify":0,
        "satisfiability_checked":false,"new_full_setup_instantiated":false,
        "proof_bytes":null,"setup_id":null,"compiler_id":null,
        "counts_bytes_are_format_arithmetic_not_RSS":true}));
    Ok(())
}
