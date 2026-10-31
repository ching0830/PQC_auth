// Research direct-CS integration. Full count is NOT a full issuance proof.
mod sponge;
mod direct_core;
mod direct_sponge;
mod direct_relation;
mod direct_relation_profile;
mod direct_full;
mod direct_research;
mod direct_cached;
mod direct_cs_cache;
mod target128_profile;
#[cfg(test)]
mod target128_tests;
#[cfg(test)]
mod direct_parallel_tests;
#[cfg(test)]
mod direct_workspace_tests;
#[cfg(test)]
mod direct_schedule_tests;
#[cfg(test)]
mod direct_checkpoint_tests;
#[cfg(test)]
mod direct_mask_tests;
#[cfg(test)]
mod direct_backend_tests;
use std::{fs,io::{self,Read,Write},sync::Arc,time::Instant};
use anyhow::{Result,ensure};
use binius_core::{constraint_system::InoutSegment,word::Word};
use binius_hash::StdHashSuite;
use binius_prover::{OptimalPackedB128,zk_config::ZKProver};
use binius_verifier::{config::StdChallenger,zk_config::ZKVerifier};
use binius_transcript::{Options,ProverTranscript,VerifierTranscript};
use serde_json::{Value,json};
use sha3::Digest;
use direct_core::{DirectBuilder,DirectCounts};
const PROOF_CAP:usize=128<<20;
const TRACE_SHA:&str="4ce48825d1e78c704b89a160be8d47932ae9bc7948d282d0c7c12c8ccc63c986";
type ZV=ZKVerifier<StdHashSuite>;
type ZP=ZKProver<OptimalPackedB128,StdHashSuite>;

fn read(path:&str,cap:usize)->Result<Vec<u8>>{
    let f=fs::File::open(path)?;ensure!(f.metadata()?.is_file()&&f.metadata()?.len()<=cap as u64,"bounded regular input");
    let mut out=Vec::new();f.take((cap+1)as u64).read_to_end(&mut out)?;ensure!(out.len()<=cap,"input cap");Ok(out)
}
fn hex(v:&[u8])->String{v.iter().map(|x|format!("{x:02x}")).collect()}
fn memory()->Result<Value>{
    let s=fs::read_to_string("/proc/self/status")?;
    let get=|p:&str|->Result<usize>{Ok(s.lines().find(|x|x.starts_with(p)).ok_or_else(||anyhow::anyhow!("memory"))?
        .split_whitespace().nth(1).unwrap().parse::<usize>()?*1024)};
    Ok(json!({"RSS_bytes":get("VmRSS:")?,"RSS_HWM_bytes":get("VmHWM:")?,"AS_bytes":get("VmSize:")?}))
}
fn counts(c:&DirectCounts)->Value{json!({"constants":c.constants,"public_words":c.inout,"private_words":c.private,
    "AND":c.and,"ZERO":c.zero,"operand_terms":c.operand_terms,"unshifted_terms":c.unshifted_terms,
    "singly_shifted_terms":c.singly_shifted_terms,"doubly_shifted_terms":c.doubly_shifted_terms,
    "max_operand_support":c.max_operand_support,"native_len_bytes":c.native_len_bytes,"serialized_bytes":c.serialized_bytes,
    "legacy_native_len_bytes":c.legacy_native_len_bytes,
    "templates":{"unique":c.unique_templates,"terms":c.template_terms,"payload_bytes":c.template_payload_bytes,"hash_capacity":c.interner_hash_capacity},
    "allocator_and_Vec_spare_included":false})}
fn public_shake(message:&[u8])->[u8;32]{
    let mut padded=message.to_vec();padded.push(0x1f);padded.resize(padded.len().div_ceil(136)*136,0);*padded.last_mut().unwrap()^=0x80;
    let mut state=[0u64;25];for block in padded.chunks_exact(136){
        for(i,c)in block.chunks_exact(8).enumerate(){state[i]^=u64::from_le_bytes(c.try_into().unwrap());}
        binius_circuits::keccak::ref_keccak_f1600(&mut state);
    }
    let mut out=[0u8;32];for i in 0..4{out[8*i..8*i+8].copy_from_slice(&state[i].to_le_bytes());}out
}
fn control(b:&DirectBuilder,n:usize,digest:&[u8;32]){
    let message:Vec<u8>=(0..136*n-1).map(|i|((i*17+3)^(i>>8))as u8).collect();
    let inputs:Vec<_>=message.chunks(8).map(|c|{
        let mut a=[0u8;8];a[..c.len()].copy_from_slice(c);b.private_input(b.is_prover().then(||u64::from_le_bytes(a)))
    }).collect();
    let outputs:Vec<_>=digest.chunks_exact(8).map(|c|b.public_input(u64::from_le_bytes(c.try_into().unwrap()))).collect();
    let computed=direct_sponge::shake256_fixed(b,&inputs,message.len(),32);
    for(a,c)in computed.iter().zip(&outputs){b.assert_eq(a,c);}
}
fn main_inner()->Result<()>{
    let width:usize=std::env::var("RAYON_NUM_THREADS")?.parse()?;
    ensure!([1,2,4].contains(&width),"bounded research width");
    ensure!(std::env::var_os("BINIUS_DUMP_PROOF").is_none(),"no dump");
    ensure!(binius_verifier::SECURITY_BITS==128,"explicit target128 query profile");
    ensure!(binius_utils::rayon::config::adjust_research_thread_pool(width).is_ok()
        &&binius_utils::rayon::current_num_threads()==width,"bounded research pool");
    let args:Vec<_>=std::env::args().collect();ensure!((4..=6).contains(&args.len()),"exact command shape");
    let mode=&args[1];let start=Instant::now();
    if mode=="cache-build" {
        ensure!(args.len()==4,"cache build command shape");
        return direct_cs_cache::build(&args[2],&args[3]);
    }
    if mode=="cache-load" {
        ensure!(args.len()==5,"cache load command shape");
        return direct_cs_cache::setup_only(&args[2],&args[3],&args[4]);
    }
    if mode=="cache-verify-batch" {
        ensure!(args.len()==6,"cache verify command shape");
        return direct_cached::run_with_cache(&args[2],&args[3],Some((&args[4],&args[5])));
    }
    if ["full-prove","full-verify"].contains(&mode.as_str()) {
        ensure!(args.len()==5,"full proof command shape");
        return direct_research::run(mode,&args[2],&args[3],Some(&args[4]));
    }
    ensure!(args.len()==4,"exact non-proof command shape");
    if mode=="full-verify-batch" {return direct_cached::run(&args[2],&args[3]);}
    if mode=="full-research-setup" {return direct_research::run(mode,&args[2],&args[3],None);}
    if ["full-replay","full-setup"].contains(&mode.as_str()){return direct_full::run(mode,&args[2],&args[3]);}
    ensure!(io::stdin().read(&mut[0u8;1])?==0,"public shape/control stdin EOF");
    if mode=="full-count"{
        let public=read(&args[2],direct_relation::PUBLIC_BYTES)?;
        let tail=read(&args[3],direct_relation::TAIL_BYTES)?;
        let trace:[u8;32]=binius_hash::StdDigest::digest(&tail).into();ensure!(hex(&trace)==TRACE_SHA,"externally pinned raw T");
        let b=DirectBuilder::new_counting();direct_relation::compile(&b,&public,None,&tail,&trace)?;
        println!("DIRECT_RESULT {}",json!({"mode":mode,"classification":"complete direct relation COUNT ONLY; no CS or witness retained, no proof",
            "counts":counts(&b.finish_counting()),"seconds":start.elapsed().as_secs_f64(),"memory":memory()?,
            "private_values_received":false,"full_Prove":0,"full_Verify":0,"full_functional_pi_iss_research":false}));
        return Ok(());
    }
    ensure!(["control-count","control-prove","control-verify"].contains(&mode.as_str()),"mode");
    let n:usize=args[2].parse()?;ensure!((1..=2048).contains(&n),"bounded address regression");
    let message:Vec<_>=(0..136*n-1).map(|i|((i*17+3)^(i>>8))as u8).collect();let digest=public_shake(&message);
    let mut statement=b"PQSAT/BINIUS-DIRECT-CORE-CONTROL/v0.1\0".to_vec();statement.extend_from_slice(&(n as u32).to_be_bytes());statement.extend_from_slice(&digest);
    let b=if mode=="control-count"{DirectBuilder::new_counting()}else{DirectBuilder::new(mode=="control-prove")};
    control(&b,n,&digest);let shape=counts(&b.counts());
    let mut record=json!({"mode":mode,"permutations":n,"shape":shape,"build_seconds":start.elapsed().as_secs_f64(),
        "classification":"PUBLIC address/representation regression, NOT issuance proof coverage","statement_bytes":statement.len(),
        "public_digest_hex":hex(&digest),"security_bits_source_constant":binius_verifier::SECURITY_BITS,"proof_threads":width,"after_build":memory()?});
    if mode=="control-count"{let _=b.finish_counting();println!("DIRECT_RESULT {record}");return Ok(());}
    let compiled=b.finish();let values=compiled.values;
    if let Some(ref values)=values{compiled.cs.verify(values)?;}
    let address_bits=22+binius_verifier::reduction::log_constraint_point(&compiled.cs)
        +compiled.cs.log_segment_words(InoutSegment::Public);record["wiring_address_bits"]=json!(address_bits);
    ensure!(address_bits<128,"checked wide address");
    let setup=Instant::now();let verifier=ZV::setup(compiled.cs,1)?;
    let max_domain=verifier.basefold_compiler().max_log_domain_size();ensure!(max_domain<=23,"component domain admission");
    record["max_log_domain_size"]=json!(max_domain);record["after_verifier_setup"]=memory()?;
    if let Some(values)=values{
        let prover=ZP::setup(&verifier)?;
        let left=verifier.inner_iop_verifier().constraint_system_arc();
        let right=prover.inner_iop_prover().constraint_system_arc();
        ensure!(Arc::ptr_eq(&left,&right)&&prover.key_collection().is_streaming(),"shared CS and streamed keys");
        record["same_core_CS_allocation"]=json!(true);record["streaming_keys"]=json!(true);
        drop(left);drop(right);drop(verifier);
        record["setup_seconds"]=json!(setup.elapsed().as_secs_f64());record["after_prover_setup"]=memory()?;
        let core=Instant::now();let mut transcript=ProverTranscript::with_opts(StdChallenger::default(),Options{debug_assertions:false});
        prover.prove_sig(&values,&statement,&mut rand::rng(),&mut transcript)?;
        let proof=transcript.finalize();record["prove_seconds"]=json!(core.elapsed().as_secs_f64());record["proof_body_bytes"]=json!(proof.len());
        ensure!(proof.len()<=PROOF_CAP,"proof cap");fs::OpenOptions::new().write(true).create_new(true).open(&args[3])?.write_all(&proof)?;
    }else{
        record["setup_seconds"]=json!(setup.elapsed().as_secs_f64());let proof=read(&args[3],PROOF_CAP)?;
        record["proof_body_bytes"]=json!(proof.len());let public:Vec<_>=digest.chunks_exact(8).map(|c|Word(u64::from_le_bytes(c.try_into().unwrap()))).collect();
        let core=Instant::now();let mut transcript=VerifierTranscript::with_opts(StdChallenger::default(),proof,Options{debug_assertions:false});
        verifier.verify_sig(&public,&statement,&mut transcript)?;transcript.finalize()?;
        record["verify_seconds"]=json!(core.elapsed().as_secs_f64());record["accepted"]=json!(true);
        record["private_values_received"]=json!(false);
    }
    record["whole_seconds"]=json!(start.elapsed().as_secs_f64());record["final_memory"]=memory()?;
    println!("DIRECT_RESULT {record}");Ok(())
}
fn main(){std::panic::set_hook(Box::new(|info|{
    if let Some(m)=info.payload().downcast_ref::<binius_core::constraint_system::TemplateMetrics>() {
        eprintln!("BINIUS_DIRECT_TEMPLATE_LIMIT {}",json!({"unique_templates":m.unique_templates,"payload_bytes":m.payload_bytes,
            "operand_count":m.operand_count,"referenced_terms":m.referenced_terms,"classification":"public source-shape only"}));
    } else {eprintln!("BINIUS_DIRECT_PANIC_REJECT");}
}));
    if main_inner().is_err(){eprintln!("BINIUS_DIRECT_REJECT");std::process::exit(2);}}
