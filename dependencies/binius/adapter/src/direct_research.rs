//! Explicit full-relation research profile. No production adapter.
use std::{fs,io::{self,Read,Write},time::Instant};
use anyhow::{ensure,Result};
use binius_core::word::Word;
use binius_transcript::{Options,ProverTranscript,VerifierTranscript};
use binius_verifier::config::StdChallenger;
use serde_json::json;
use sha3::Digest;
use crate::{direct_core::DirectBuilder,direct_full,direct_relation,read,hex,memory,counts,ZV,ZP,PROOF_CAP,TRACE_SHA};

const DOMAIN:&[u8]=b"PQSAT-BUOV-CAP-RESEARCH/FULL-NCC-STMT/v0.1\0";
const COMPILER_DOMAIN:&[u8]=b"PQSAT/BINIUS-FULL-WORD-COMPILER/v0.1\0";
const SETUP_DOMAIN:&[u8]=b"PQSAT/BINIUS-UNMERGED-FULL-ZK-SETUP/v0.1\0";
const FRAME:usize=14+DOMAIN.len()+128+direct_relation::PUBLIC_BYTES;

pub(crate) fn digest(parts:&[&[u8]])->Vec<u8> {
    let mut h=binius_hash::StdDigest::default();for p in parts {h.update(p);}h.finalize().to_vec()
}
pub(crate) fn statement(raw:&[u8])->Result<(&[u8],&[u8],&[u8],&[u8])> {
    ensure!(raw.len()==FRAME && &raw[..10]==b"NIFS\0\x01\0\x17\0\x02","canonical full statement");
    ensure!(u32::from_be_bytes(raw[10..14].try_into().unwrap()) as usize==FRAME-14
        && &raw[14..14+DOMAIN.len()]==DOMAIN,"statement domain/length");
    let at=14+DOMAIN.len();
    Ok((&raw[at..at+32],&raw[at+32..at+64],&raw[at+64..at+96],&raw[at+128..]))
}

pub fn run(mode:&str,first:&str,tail_path:&str,proof_path:Option<&str>)->Result<()> {
    let start=Instant::now();let proving=mode=="full-prove";let setup_only=mode=="full-research-setup";
    let input=read(first,if setup_only{direct_relation::PUBLIC_BYTES}else{FRAME})?;
    let (claimed_compiler,claimed_setup,claimed_trace,public)=if setup_only {(&[][..],&[][..],&[][..],input.as_slice())}else{statement(&input)?};
    ensure!(public.len()==direct_relation::PUBLIC_BYTES,"public846");
    let tail=read(tail_path,direct_relation::TAIL_BYTES)?;
    let trace=digest(&[&tail]);ensure!(hex(&trace)==TRACE_SHA,"trusted raw T");
    if !setup_only {ensure!(claimed_trace==trace,"statement trace identity");}
    let secret=if proving {Some(direct_full::private_body(claimed_compiler)?)}else{
        ensure!(io::stdin().read(&mut[0u8;1])?==0,"NCC receives no witness");None
    };
    let b=DirectBuilder::new(proving);
    direct_relation::compile(&b,public,secret.as_deref(),&tail,&trace.clone().try_into().unwrap())?;
    let shape=counts(&b.counts());let compiled=b.finish();drop(secret);drop(tail);
    let mut record=json!({"mode":mode,"counts":shape,"build_seconds":start.elapsed().as_secs_f64(),
        "after_build":memory()?,"profile":"research_unmerged_target128_checkpoint_v0_1","security_bits":binius_verifier::SECURITY_BITS,
        "security_classification":"query-target128 research; complete security qualification pending","private_values_received":proving,"compute_cores":binius_utils::rayon::current_num_threads(),
        "statement_bytes":if setup_only{0}else{input.len()},"Prove":0,"proof_Verify":0,
        "full_functional_pi_iss_research":false});
    if let Some(ref values)=compiled.values {let check=Instant::now();compiled.cs.verify(values)?;
        record["constraint_replay_seconds"]=json!(check.elapsed().as_secs_f64());}
    let hash=Instant::now();let cs_id=direct_full::cs_identity(&compiled.cs)?;
    let compiler=digest(&[COMPILER_DOMAIN,cs_id["sha256"].as_str().unwrap().as_bytes()]);
    record["CS_hash_seconds"]=json!(hash.elapsed().as_secs_f64());record["public_CS_identity"]=cs_id;
    let setup=Instant::now();let verifier=ZV::setup_research_unmerged(compiled.cs,1)?;
    ensure!(verifier.is_research_unmerged() && verifier.basefold_compiler().max_log_domain_size()<=25,"full research setup admission");
    let mut actual=direct_full::setup_record(&verifier);
    actual["prover_memory_profile"]=json!("checkpoint4/on_the_fly/no_pool_retention/regenerated_private_masks/v0.1");
    let setup_id=digest(&[SETUP_DOMAIN,&compiler,&serde_json::to_vec(&actual)?]);
    crate::target128_profile::require_full_setup(&verifier,&actual,&setup_id)?;
    if !setup_only {ensure!(claimed_compiler==compiler && claimed_setup==setup_id,"locally rebuilt compiler/setup identity");}
    record["compiler_id"]=json!(hex(&compiler));record["setup_id"]=json!(hex(&setup_id));
    record["actual_symbolic_setup"]=actual;record["after_verifier_setup"]=memory()?;
    if let Some(values)=compiled.values {
        let prover=ZP::setup(&verifier)?;ensure!(prover.is_research_unmerged(),"explicit research prover");drop(verifier);
        record["setup_seconds"]=json!(setup.elapsed().as_secs_f64());record["after_prover_setup"]=memory()?;
        let core=Instant::now();let mut transcript=ProverTranscript::with_opts(StdChallenger::default(),Options{debug_assertions:false});
        prover.prove_sig(&values,&input,&mut rand::rng(),&mut transcript)?;
        let proof=transcript.finalize();record["prove_seconds"]=json!(core.elapsed().as_secs_f64());
        ensure!(proof.len()<=PROOF_CAP && proof.len()==crate::target128_profile::FULL_PROOF_BYTES,"target128 proof exact body/cap");
        fs::OpenOptions::new().write(true).create_new(true).open(proof_path.unwrap())?.write_all(&proof)?;
        record["Prove"]=json!(1);record["proof_body_bytes"]=json!(proof.len());
    }else if !setup_only {
        record["setup_seconds"]=json!(setup.elapsed().as_secs_f64());
        let proof=read(proof_path.unwrap(),PROOF_CAP)?;record["proof_body_bytes"]=json!(proof.len());
        let words:Vec<_>=public.chunks(8).map(|chunk|{let mut word=[0u8;8];word[..chunk.len()].copy_from_slice(chunk);Word(u64::from_le_bytes(word))}).collect();
        let core=Instant::now();let mut transcript=VerifierTranscript::with_opts(StdChallenger::default(),proof,Options{debug_assertions:false});
        verifier.verify_sig(&words,&input,&mut transcript)?;transcript.finalize()?;
        record["verify_seconds"]=json!(core.elapsed().as_secs_f64());record["proof_Verify"]=json!(1);record["accepted"]=json!(true);
        record["full_functional_pi_iss_research"]=json!(true);
    }else{record["setup_seconds"]=json!(setup.elapsed().as_secs_f64());}
    record["whole_seconds"]=json!(start.elapsed().as_secs_f64());record["final_memory"]=memory()?;
    println!("DIRECT_RESULT {record}");Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_statement_rejects_alternate_version_length_and_trailing_bytes() {
        let mut raw=Vec::from(&b"NIFS\0\x01\0\x17\0\x02"[..]);raw.extend_from_slice(&((FRAME-14)as u32).to_be_bytes());
        raw.extend_from_slice(DOMAIN);raw.resize(FRAME,0);assert!(statement(&raw).is_ok());
        for (offset,mask) in [(5,1),(9,1),(13,1),(14,1)] {let mut bad=raw.clone();bad[offset]^=mask;assert!(statement(&bad).is_err());}
        assert!(statement(&raw[..FRAME-1]).is_err());raw.push(0);assert!(statement(&raw).is_err());
    }
}
