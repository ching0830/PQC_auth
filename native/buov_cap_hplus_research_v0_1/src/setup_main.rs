//! Full H+ PUBLIC setup/cache. No private parser or proof producer/consumer.
#[path="lib.rs"] mod implementation;
pub use implementation::*;
mod setup_support;
mod public_cache;
use std::{fs,io::{self,Read},time::Instant};
use anyhow::{ensure,Result};
use serde_json::{Value,json};
use sha3::Digest;
type ZV=binius_verifier::zk_config::ZKVerifier<binius_hash::StdHashSuite>;
const TRACE_SHA:&str="4ce48825d1e78c704b89a160be8d47932ae9bc7948d282d0c7c12c8ccc63c986";
const COMPILER_DOMAIN:&[u8]=b"PQSAT/BINIUS-HPLUS-WORD-COMPILER/v0.1\0";
const SETUP_DOMAIN:&[u8]=b"PQSAT/BINIUS-HPLUS-UNMERGED-ZK-SETUP/v0.1\0";

fn hex(raw:&[u8])->String{raw.iter().map(|v|format!("{v:02x}")).collect()}
fn digest(parts:&[&[u8]])->Vec<u8>{
    let mut h=binius_hash::StdDigest::default();for p in parts{h.update(p);}h.finalize().to_vec()
}
fn memory()->Result<Value>{
    let raw=fs::read_to_string("/proc/self/status")?;
    let get=|name:&str|->Result<u64>{Ok(raw.lines().find(|v|v.starts_with(name)).unwrap()
        .split_whitespace().nth(1).unwrap().parse::<u64>()?*1024)};
    Ok(json!({"RSS_bytes":get("VmRSS:")?,"RSS_HWM_bytes":get("VmHWM:")?,"AS_bytes":get("VmSize:")?}))
}
fn public_tail(reader:&mut impl Read)->Result<Vec<u8>>{
    let mut tail=Vec::new();reader.take((direct_relation::TAIL_BYTES+1)as u64).read_to_end(&mut tail)?;
    ensure!(tail.len()==direct_relation::TAIL_BYTES && hex(&digest(&[&tail]))==TRACE_SHA,
        "exact captured public T only; no witness/trailing input");Ok(tail)
}
fn public_slots()->Vec<u8>{
    let mut raw=vec![0;direct_relation::PUBLIC_BYTES];
    raw[..32].copy_from_slice(direct_relation_profile::FINGERPRINT);
    raw[272..304].copy_from_slice(direct_relation_profile::FINGERPRINT);
    raw[240..272].copy_from_slice(direct_relation_profile::RELATION_ID);
    raw[814..846].copy_from_slice(direct_relation_profile::BINDING_ID);raw
}
fn counts(c:&direct_core::DirectCounts)->Value{json!({"constants":c.constants,"public_words":c.inout,
    "private_words":c.private,"AND":c.and,"ZERO":c.zero,"operand_terms":c.operand_terms,
    "max_operand_support":c.max_operand_support,"native_len_bytes":c.native_len_bytes,
    "serialized_bytes":c.serialized_bytes,"templates":{"unique":c.unique_templates,
    "terms":c.template_terms,"payload_bytes":c.template_payload_bytes},"allocator_and_Vec_spare_included":false})}
fn actual_setup(verifier:&ZV)->Result<Value>{
    ensure!(binius_verifier::SECURITY_BITS==128 && verifier.is_research_unmerged()
        && verifier.log_inv_rate()==1 && verifier.basefold_compiler().max_log_domain_size()<=25,
        "H+ explicit query-target128 research setup admission");
    let specs=verifier.oracle_schedule().merged_specs();
    ensure!(specs.len()==4 && specs.iter().all(|s|s.is_zk),"all four actual oracles must be ZK");
    let cs=verifier.outer_iop_verifier().constraint_system();
    let blind=cs.blinding_info();
    ensure!(verifier.basefold_compiler().fri_params().n_test_queries()==309
        && blind.n_dummy_wires==310 && blind.n_dummy_constraints==2 && cs.mask_dims()==(7,2),
        "recomputed query/blinding/mask checks");
    let mut actual=setup_support::setup_record(verifier);
    actual["outer"]=json!({"n_public":cs.n_public(),"n_precommit":cs.n_precommit(),
        "n_private":cs.n_private(),"precommit_len":cs.precommit_len(),"private_len":cs.private_len(),
        "log_precommit":cs.log_precommit(),"log_private":cs.log_private(),
        "padded_mul_constraints":cs.mul_constraints().len(),"mask_dims":cs.mask_dims(),
        "dummy_wires":blind.n_dummy_wires,"dummy_constraints_per_segment":blind.n_dummy_constraints});
    actual["prover_memory_profile"]=json!("checkpoint4/on_the_fly/no_pool_retention/regenerated_private_masks/v0.1");
    Ok(actual)
}
fn main()->Result<()>{
    let args:Vec<_>=std::env::args().collect();
    ensure!(std::env::var_os("BINIUS_DUMP_PROOF").is_none(),"no debug proof dump");
    ensure!(args.len()==3 || args.len()==5,"public setup command shape");
    let mode=&args[1];ensure!((mode=="build"&&args.len()==3)||(mode=="load"&&args.len()==5),"public-only modes");
    ensure!(binius_utils::rayon::config::adjust_research_thread_pool(1).is_ok()
        && binius_utils::rayon::current_num_threads()==1,"single research setup core");
    let whole=Instant::now();let tail=public_tail(&mut io::stdin().lock())?;
    let trace:[u8;32]=digest(&[&tail]).try_into().unwrap();
    let mut record=json!({"schema":"BUOVCAPHPlusActualSetupV1","mode":mode,
        "profile_fingerprint":hex(direct_relation_profile::FINGERPRINT),
        "relation_id":hex(direct_relation_profile::RELATION_ID),"private_values_received":false,
        "private_ValueVec_allocated":false,"satisfiability_checked":false,"Prove":0,"Verify":0,
        "proof_body_bytes":null,"trace_sha256":TRACE_SHA,"compute_cores":1});
    let (cs,cs_id)=if mode=="build"{
        let start=Instant::now();let builder=direct_core::DirectBuilder::new(false);
        direct_relation::compile(&builder,&public_slots(),None,&tail,&trace)?;
        let c=builder.counts();record["counts"]=counts(&c);
        ensure!((c.constants,c.inout,c.private,c.and,c.zero)==(8487,106,19866173,16361386,3263533),"frozen H+ census");
        let compiled=builder.finish();ensure!(compiled.values.is_none(),"no public setup witness vector");
        record["build_seconds"]=json!(start.elapsed().as_secs_f64());record["after_build"]=memory()?;
        let start=Instant::now();let id=setup_support::cs_identity(&compiled.cs)?;
        ensure!(id["serialized_bytes_streamed_to_hash"]==2718916370u64,"new canonical CS exact size");
        record["CS_hash_seconds"]=json!(start.elapsed().as_secs_f64());
        record["cache"]=public_cache::write_current(&compiled.cs,id["sha256"].as_str().unwrap(),&args[2])?;
        (compiled.cs,id)
    }else{
        let loaded=public_cache::load(&args[2],&args[3],&args[4])?;
        record["counts"]=loaded.counts;record["cache"]=loaded.record;
        let id=record["cache"]["public_CS_identity"].clone();(loaded.cs,id)
    };
    drop(tail);record["public_CS_identity"]=cs_id.clone();
    let compiler=digest(&[COMPILER_DOMAIN,direct_relation_profile::FINGERPRINT,
        direct_relation_profile::RELATION_ID,cs_id["sha256"].as_str().unwrap().as_bytes()]);
    let start=Instant::now();let verifier=ZV::setup_research_unmerged(cs,1)?;
    let actual=actual_setup(&verifier)?;
    let setup_id=digest(&[SETUP_DOMAIN,&compiler,&serde_json::to_vec(&actual)?]);
    record["compiler_id"]=json!(hex(&compiler));record["setup_id"]=json!(hex(&setup_id));
    record["actual_symbolic_setup"]=actual;record["setup_seconds"]=json!(start.elapsed().as_secs_f64());
    record["after_setup"]=memory()?;record["whole_seconds"]=json!(whole.elapsed().as_secs_f64());
    println!("HPLUS_SETUP {record}");Ok(())
}
#[cfg(test)]
mod setup_tests{
    use super::*;
    #[test]fn foreign_identities_and_public_tail_shape_reject_before_large_build(){
        let p=public_slots();direct_relation::validate_public_profile(&p).unwrap();
        for at in [0,240,272,814]{let mut bad=p.clone();bad[at]^=1;assert!(direct_relation::validate_public_profile(&bad).is_err());}
        for n in [0,1,direct_relation::TAIL_BYTES-1,direct_relation::TAIL_BYTES,direct_relation::TAIL_BYTES+1]{
            assert!(public_tail(&mut &vec![0u8;n][..]).is_err());}
    }
}
