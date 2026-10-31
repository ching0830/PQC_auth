//! Isolated H+ full research Prove/Verify. Private stdin exists only in UE mode.
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
use std::io::Write;
use binius_core::word::Word;
use binius_prover::{OptimalPackedB128,zk_config::ZKProver};
use binius_transcript::{Options,ProverTranscript,VerifierTranscript};
use binius_verifier::config::StdChallenger;
type ZP=ZKProver<OptimalPackedB128,binius_hash::StdHashSuite>;
const DOMAIN:&[u8]=b"PQSAT-BUOV-CAP-HPLUS-RESEARCH/FULL-NCC-STMT/v0.1\0";
const PRIVATE_DOMAIN:&[u8]=b"PQSAT-BUOV-CAP-HPLUS-RESEARCH/FULL-WITNESS/v0.1\0";
const FRAME:usize=14+DOMAIN.len()+128+direct_relation::PUBLIC_BYTES;
const PROOF_CAP:usize=8<<20;
const CHECKPOINT:&str=include_str!("../../../manifests/buov_cap_hplus_research_v0_1/actual_setup.json");
fn read(path:&str,cap:usize)->Result<Vec<u8>>{
    let f=fs::File::open(path)?;ensure!(f.metadata()?.is_file()&&f.metadata()?.len()<=cap as u64,"bounded regular public file");
    let mut raw=Vec::new();f.take((cap+1)as u64).read_to_end(&mut raw)?;ensure!(raw.len()<=cap,"bounded public read");Ok(raw)
}
fn statement(raw:&[u8])->Result<(&[u8],&[u8],&[u8],&[u8])>{
    ensure!(raw.len()==FRAME && &raw[..10]==b"NIFS\0\x01\0\x17\0\x02","H+ NIFS exact profile");
    ensure!(u32::from_be_bytes(raw[10..14].try_into().unwrap())as usize==FRAME-14
        && &raw[14..14+DOMAIN.len()]==DOMAIN,"H+ NIFS canonical domain/length");
    let at=14+DOMAIN.len();let public=&raw[at+128..];direct_relation::validate_public_profile(public)?;
    Ok((&raw[at..at+32],&raw[at+32..at+64],&raw[at+64..at+96],public))
}
fn private_body(compiler:&[u8])->Result<Vec<u8>>{
    let width=44+PRIVATE_DOMAIN.len()+direct_relation::PRIVATE_BYTES;
    let mut raw=Vec::new();io::stdin().take((width+1)as u64).read_to_end(&mut raw)?;
    ensure!(raw.len()==width && &raw[..8]==b"NIFW\0\x01\0\x17","H+ private input ABI/EOF");
    ensure!(&raw[8..40]==compiler && u32::from_be_bytes(raw[40..44].try_into().unwrap())as usize==direct_relation::PRIVATE_BYTES
        && &raw[44..44+PRIVATE_DOMAIN.len()]==PRIVATE_DOMAIN,"H+ private compiler/domain/length");
    Ok(raw.split_off(44+PRIVATE_DOMAIN.len()))
}
fn main()->Result<()>{
    let args:Vec<_>=std::env::args().collect();ensure!(args.len()==5||args.len()==6,"H+ command arguments");
    let proving=args[1]=="full-prove";ensure!((proving&&args.len()==5)||(args[1]=="full-verify"&&args.len()==6),"explicit H+ proof modes");
    ensure!(std::env::var_os("BINIUS_DUMP_PROOF").is_none(),"no debug proof dump");
    ensure!(binius_utils::rayon::config::adjust_research_thread_pool(1).is_ok()
        && binius_utils::rayon::current_num_threads()==1,"single-core new relation integration");
    let whole=Instant::now();let expected:Value=serde_json::from_str(CHECKPOINT)?;
    let input=read(&args[2],FRAME)?;let (claimed_compiler,claimed_setup,claimed_trace,public)=statement(&input)?;
    ensure!(hex(claimed_compiler)==expected["compiler_id"].as_str().unwrap()
        && hex(claimed_setup)==expected["setup_id"].as_str().unwrap(),"own checkpoint identities before large work");
    let tail=read(&args[3],direct_relation::TAIL_BYTES)?;let trace:[u8;32]=digest(&[&tail]).try_into().unwrap();
    ensure!(hex(&trace)==TRACE_SHA && claimed_trace==trace,"captured public trace identity");
    let mut record=json!({"schema":"BUOVCAPHPlusProofExecutionV1","mode":args[1],"Prove":0,"proof_Verify":0,
        "private_values_received":proving,"compute_cores":1,"statement_bytes":input.len(),"security_bits":128,
        "security_classification":"FRI query-target only; overall security unqualified"});
    let (cs,values,cs_id)=if proving{
        let secret=private_body(claimed_compiler)?;let start=Instant::now();let b=direct_core::DirectBuilder::new(true);
        direct_relation::compile(&b,public,Some(&secret),&tail,&trace)?;record["counts"]=counts(&b.counts());
        let compiled=b.finish();drop(secret);record["build_seconds"]=json!(start.elapsed().as_secs_f64());
        let start=Instant::now();compiled.cs.verify(compiled.values.as_ref().unwrap())?;
        record["constraint_replay_seconds"]=json!(start.elapsed().as_secs_f64());
        let start=Instant::now();let id=setup_support::cs_identity(&compiled.cs)?;
        record["CS_hash_seconds"]=json!(start.elapsed().as_secs_f64());(compiled.cs,compiled.values,id)
    }else{
        ensure!(io::stdin().read(&mut[0u8;1])?==0,"NCC has EOF stdin, no private witness");
        let loaded=public_cache::load(&args[5],expected["public_cache"]["sha256"].as_str().unwrap(),
            expected["public_CS_identity"]["sha256"].as_str().unwrap())?;
        record["counts"]=loaded.counts;let id=loaded.record["public_CS_identity"].clone();record["cache"]=loaded.record;
        (loaded.cs,None,id)
    };
    drop(tail);ensure!(record["counts"]==expected["counts"]&&cs_id==expected["public_CS_identity"],"frozen H+ compiled shape/CS");
    record["public_CS_identity"]=cs_id.clone();let compiler=digest(&[COMPILER_DOMAIN,direct_relation_profile::FINGERPRINT,
        direct_relation_profile::RELATION_ID,cs_id["sha256"].as_str().unwrap().as_bytes()]);
    let start=Instant::now();let verifier=ZV::setup_research_unmerged(cs,1)?;let actual=actual_setup(&verifier)?;
    let setup_id=digest(&[SETUP_DOMAIN,&compiler,&serde_json::to_vec(&actual)?]);
    ensure!(claimed_compiler==compiler&&claimed_setup==setup_id&&actual==expected["actual_symbolic_setup"],"actual own H+ setup");
    record["compiler_id"]=json!(hex(&compiler));record["setup_id"]=json!(hex(&setup_id));
    record["actual_symbolic_setup"]=actual;record["after_verifier_setup"]=memory()?;
    if let Some(values)=values{
        let prover=ZP::setup(&verifier)?;ensure!(prover.is_research_unmerged(),"explicit research prover");drop(verifier);
        record["setup_seconds"]=json!(start.elapsed().as_secs_f64());record["after_prover_setup"]=memory()?;
        let core=Instant::now();let mut transcript=ProverTranscript::with_opts(StdChallenger::default(),Options{debug_assertions:false});
        prover.prove_sig(&values,&input,&mut rand::rng(),&mut transcript)?;let proof=transcript.finalize();
        ensure!(proof.len()<=PROOF_CAP,"H+ output proof cap");record["prove_seconds"]=json!(core.elapsed().as_secs_f64());
        fs::OpenOptions::new().write(true).create_new(true).open(&args[4])?.write_all(&proof)?;
        record["Prove"]=json!(1);record["proof_body_bytes"]=json!(proof.len());
    }else{
        record["setup_seconds"]=json!(start.elapsed().as_secs_f64());let proof=read(&args[4],PROOF_CAP)?;
        record["proof_body_bytes"]=json!(proof.len());let words:Vec<_>=public.chunks(8).map(|chunk|{
            let mut w=[0;8];w[..chunk.len()].copy_from_slice(chunk);Word(u64::from_le_bytes(w))}).collect();
        let core=Instant::now();let mut transcript=VerifierTranscript::with_opts(StdChallenger::default(),proof,Options{debug_assertions:false});
        let accepted=verifier.verify_sig(&words,&input,&mut transcript).is_ok() && transcript.finalize().is_ok();
        record["verify_seconds"]=json!(core.elapsed().as_secs_f64());record["proof_Verify"]=json!(1);
        record["accepted"]=json!(accepted);
    }
    record["whole_seconds"]=json!(whole.elapsed().as_secs_f64());record["final_memory"]=memory()?;
    println!("HPLUS_PROOF {record}");Ok(())
}
#[cfg(test)]mod proof_tests{
    use super::*;
    #[test]fn statement_canonical_profile(){
        let mut raw=Vec::from(&b"NIFS\0\x01\0\x17\0\x02"[..]);raw.extend_from_slice(&((FRAME-14)as u32).to_be_bytes());
        raw.extend_from_slice(DOMAIN);raw.resize(FRAME-direct_relation::PUBLIC_BYTES,0);raw.extend_from_slice(&public_slots());
        assert!(statement(&raw).is_ok());
        for at in [5,9,13,14,FRAME-846,FRAME-846+240,FRAME-846+272,FRAME-32]{let mut bad=raw.clone();bad[at]^=1;assert!(statement(&bad).is_err());}
        assert!(statement(&raw[..FRAME-1]).is_err());raw.push(0);assert!(statement(&raw).is_err());
    }
}
