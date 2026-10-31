//! Public-data backend capacity diagnostic, NOT an issuance proof interface.
mod compact_keccak;
mod gf64;
mod sponge;
use std::{fs,io::{self,Read},mem::size_of,time::Instant};
use anyhow::{Result,ensure};
use binius_core::{constraint_system::{ConstraintSystem,AndConstraint,ZeroConstraint,ShiftedValueIndex,InoutSegment},word::Word};
use binius_frontend::{CircuitBuilder,Wire};
use binius_hash::StdHashSuite;
use binius_prover::{OptimalPackedB128,zk_config::ZKProver};
use binius_transcript::{Options,ProverTranscript,VerifierTranscript};
use binius_verifier::{config::StdChallenger,zk_config::ZKVerifier};
use serde_json::{json,Value};

// Public API cap only. The controller must additionally admit each scale
// using the prior measured phase; this is never full-profile admission.
const MAX_PERMUTATIONS:usize=4096;
const PROOF_CAP:usize=128<<20;
type ZV=ZKVerifier<StdHashSuite>;
type ZP=ZKProver<OptimalPackedB128,StdHashSuite>;

fn public_shake(message:&[u8])->[u8;32]{
    let mut padded=message.to_vec();padded.push(0x1f);
    padded.resize(padded.len().div_ceil(136)*136,0);
    *padded.last_mut().unwrap()^=0x80;
    let mut state=[0u64;25];
    for block in padded.chunks_exact(136){
        for (i,chunk) in block.chunks_exact(8).enumerate(){state[i]^=u64::from_le_bytes(chunk.try_into().unwrap());}
        binius_circuits::keccak::ref_keccak_f1600(&mut state);
    }
    let mut result=[0u8;32];
    for i in 0..4{result[8*i..8*i+8].copy_from_slice(&state[i].to_le_bytes());}
    result
}

fn memory()->Result<Value>{
    let text=fs::read_to_string("/proc/self/status")?;
    let get=|label:&str|->Result<u64>{
        Ok(text.lines().find(|s|s.starts_with(label)).ok_or_else(||anyhow::anyhow!("memory field"))?
           .split_whitespace().nth(1).unwrap().parse::<u64>()?*1024)
    };
    Ok(json!({"RSS_bytes":get("VmRSS:")?,"RSS_HWM_bytes":get("VmHWM:")?,"AS_bytes":get("VmSize:")?}))
}

fn stats(cs:&ConstraintSystem)->Value{
    let log_constraints=binius_verifier::reduction::log_constraint_point(cs);
    let log_segment=cs.log_segment_words(InoutSegment::Public);
    let wiring_bits=binius_verifier::reduction::LOG_OPERANDS
        +2*binius_verifier::protocols::shift::LOG_SHIFT_COUNT+log_constraints+log_segment;
    let ops=cs.zero_constraints.iter().flat_map(|c|c.0.iter())
        .chain(cs.and_constraints.iter().flat_map(|c|c.0.iter()))
        .chain(cs.imul_constraints.iter().flat_map(|c|c.0.iter()))
        .chain(cs.bmul_constraints.iter().flat_map(|c|c.0.iter()));
    let (mut terms,mut capacity,mut max_support)=(0usize,0usize,0usize);
    for op in ops {terms+=op.len();capacity+=op.capacity();max_support=max_support.max(op.len());}
    let base=size_of::<ConstraintSystem>();
    let native_len=base+8*cs.constants.len()+24*cs.zero_constraints.len()+72*cs.and_constraints.len()
        +96*cs.imul_constraints.len()+144*cs.bmul_constraints.len()+8*terms;
    let native_capacity=base+8*cs.constants.capacity()+24*cs.zero_constraints.capacity()+72*cs.and_constraints.capacity()
        +96*cs.imul_constraints.capacity()+144*cs.bmul_constraints.capacity()+8*capacity;
    let operands=cs.zero_constraints.len()+3*cs.and_constraints.len()+4*cs.imul_constraints.len()+6*cs.bmul_constraints.len();
    let serialized=32+8*cs.constants.len()+4*operands+14*terms;
    json!({"constants":cs.constants.len(),"public_words":cs.n_inout,"private_words":cs.n_private,
        "AND":cs.and_constraints.len(),"ZERO":cs.zero_constraints.len(),"IMUL":cs.imul_constraints.len(),"BMUL":cs.bmul_constraints.len(),
        "operand_terms":terms,"operand_capacity":capacity,"max_operand_support":max_support,
        "native_len_bytes":native_len,"native_capacity_bytes":native_capacity,
        "serialized_bytes_source_formula":serialized,"allocator_overhead_included":false,
        "log_constraint_point":log_constraints,"log_segment_words":log_segment,
        "zk_wiring_address_bits":wiring_bits,"zk_wiring_admitted":wiring_bits<64,
        "struct_bytes":base,"AND_struct_bytes":size_of::<AndConstraint>(),"ZERO_struct_bytes":size_of::<ZeroConstraint>(),
        "shifted_index_bytes":size_of::<ShiftedValueIndex>()})
}

fn main_inner()->Result<()>{
    ensure!(std::env::var("RAYON_NUM_THREADS").as_deref()==Ok("1"),"single thread");
    ensure!(std::env::var_os("BINIUS_DUMP_PROOF").is_none(),"dump forbidden");
    ensure!(binius_verifier::SECURITY_BITS==96,"diagnostic profile");
    ensure!(binius_utils::rayon::config::adjust_thread_pool().is_ok(),"calling-thread pool");
    ensure!(binius_utils::rayon::current_num_threads()==1,"single thread");
    ensure!(io::stdin().read(&mut[0u8;1])?==0,"public diagnostic stdin EOF");
    let args:Vec<_>=std::env::args().collect();
    ensure!(args.len()==5,"mode permutations encoding proof-path");
    let mode=&args[1];let n:usize=args[2].parse()?;let encoding=&args[3];
    ensure!((1..=MAX_PERMUTATIONS).contains(&n),"bounded public capacity shape");
    ensure!(["shape","prove","verify"].contains(&mode.as_str()),"mode");
    ensure!(["default","compact"].contains(&encoding.as_str()),"encoding");
    let start=Instant::now();
    let message:Vec<u8>=(0..136*n-1).map(|i|((i*17+3)^(i>>8)) as u8).collect();
    let digest=public_shake(&message);
    let mut statement=b"PQSAT/BINIUS-CAPACITY-ZK96/v0.1\0".to_vec();
    statement.extend_from_slice(&(n as u32).to_be_bytes());
    statement.extend_from_slice(&[if encoding=="compact" {1} else {0}]);
    statement.extend_from_slice(&digest);
    // All bytes here are deterministic PUBLIC controls, including the data
    // filled into witness-role wires. No CAP or issuance fixture is generated.
    let b=CircuitBuilder::new();
    let inputs:Vec<Wire>=(0..message.len().div_ceil(8)).map(|_|b.add_witness()).collect();
    let outputs:Vec<Wire>=(0..4).map(|_|b.add_inout()).collect();
    let permutation=if encoding=="compact" {compact_keccak::permute} else {binius_circuits::keccak::keccak_f1600};
    let computed=sponge::shake256_fixed_with_permutation(&b,&inputs,message.len(),32,permutation);
    for i in 0..4 {b.assert_eq("public_SHAKE_capacity_digest",computed[i],outputs[i]);}
    let circuit=b.build();
    let shape=stats(circuit.constraint_system());
    let mut record=json!({"mode":mode,"permutations":n,"message_bytes":message.len(),"encoding":encoding,
        "classification":"public-data capacity diagnostic, NOT pi_iss_research",
        "public_digest_hex":digest.iter().map(|b|format!("{b:02x}")).collect::<String>(),
        "proof_threads":1,"security_bits_source_constant":96,"statement_bytes":statement.len(),
        "shape":shape,"build_seconds":start.elapsed().as_secs_f64(),"after_build":memory()?});
    println!("CAPACITY_STAGE {}",json!({"stage":"build","record":record}));
    if mode=="shape" {record["whole_seconds"]=json!(start.elapsed().as_secs_f64());println!("CAPACITY_RESULT {record}");return Ok(());}
    // Match the pinned upstream's checked u64 sparse-address layout BEFORE
    // witness evaluation or ZK setup. Do not truncate or bypass its boundary.
    ensure!(record["shape"]["zk_wiring_admitted"]==true,"ZK sparse wiring address capacity");
    let witness=if mode=="prove" {
        let mut filler=circuit.new_witness_filler();
        filler.pack_bytes_le(&inputs,&message);filler.pack_bytes_le(&outputs,&digest);
        circuit.populate_wire_witness(&mut filler).map_err(|_|anyhow::anyhow!("control assignment"))?;
        let mut witness=filler.into_value_vec();
        circuit.constraint_system().verify(&witness).map_err(|_|anyhow::anyhow!("control constraints"))?;
        let position=circuit.witness_index(inputs[0]);
        witness[position]=Word(witness[position].as_u64()^1);
        ensure!(circuit.constraint_system().verify(&witness).is_err(),"post-fill input mutation must reject");
        witness[position]=Word(witness[position].as_u64()^1);
        Some(witness)
    }else{None};
    // Release Circuit before ZK setup. It carries an independent CS and
    // evaluator; the resulting owned witness is sufficient for Prove.
    let cs=circuit.constraint_system().clone();drop(circuit);
    let setup=Instant::now();
    let verifier=ZV::setup(cs,1)?;
    let max_domain=verifier.basefold_compiler().max_log_domain_size();
    record["max_log_domain_size"]=json!(max_domain);
    record["after_verifier_setup"]=memory()?;
    ensure!(max_domain<=22,"bounded capacity domain admission");
    println!("CAPACITY_STAGE {}",json!({"stage":"verifier_setup","max_log_domain_size":max_domain,"memory":memory()?}));
    let public:Vec<_>=digest.chunks_exact(8).map(|c|Word(u64::from_le_bytes(c.try_into().unwrap()))).collect();
    if let Some(witness)=witness {
        let prover=ZP::setup(&verifier)?;
        record["after_prover_setup"]=memory()?;
        // Drop the external verifier after constructing the prover. Two inner
        // CS owners remain in the upstream prover; this is not Arc sharing.
        drop(verifier);
        record["setup_seconds"]=json!(setup.elapsed().as_secs_f64());
        let prove=Instant::now();
        let mut transcript=ProverTranscript::with_opts(StdChallenger::default(),Options{debug_assertions:false});
        prover.prove_sig(&witness,&statement,&mut rand::rng(),&mut transcript)?;
        let proof=transcript.finalize();
        record["prove_seconds"]=json!(prove.elapsed().as_secs_f64());record["proof_body_bytes"]=json!(proof.len());
        ensure!(proof.len()<=PROOF_CAP && !std::path::Path::new(&args[4]).exists(),"fresh bounded proof");
        fs::write(&args[4],proof)?;
        record["post_fill_constraint_mutations_rejected"]=json!(1);
    }else{
        record["setup_seconds"]=json!(setup.elapsed().as_secs_f64());
        let file=fs::File::open(&args[4])?;
        ensure!(file.metadata()?.len()<=PROOF_CAP as u64,"proof cap");
        let mut proof=Vec::new();file.take((PROOF_CAP+1)as u64).read_to_end(&mut proof)?;
        ensure!(proof.len()<=PROOF_CAP,"proof cap");record["proof_body_bytes"]=json!(proof.len());
        let verify=Instant::now();
        let mut transcript=VerifierTranscript::with_opts(StdChallenger::default(),proof,Options{debug_assertions:false});
        verifier.verify_sig(&public,&statement,&mut transcript)?;transcript.finalize()?;
        record["verify_seconds"]=json!(verify.elapsed().as_secs_f64());record["accepted"]=json!(true);
    }
    record["whole_seconds"]=json!(start.elapsed().as_secs_f64());record["final_memory"]=memory()?;
    println!("CAPACITY_RESULT {record}");
    Ok(())
}

fn main(){
    // This executable accepts no private payload: stdin is EOF and every
    // input byte is a fixed PUBLIC control. Bounded panic text is therefore
    // usable to diagnose an upstream capacity boundary. Never copy this hook
    // into the UE F7/private-witness executable.
    std::panic::set_hook(Box::new(|p|{
        let text=if let Some(s)=p.payload().downcast_ref::<String>(){s.as_str()}
            else if let Some(s)=p.payload().downcast_ref::<&str>(){s}else{"non-text panic"};
        eprintln!("BINIUS_PUBLIC_CAPACITY_PANIC {:?}: {}",p.location(),text.chars().take(512).collect::<String>());
    }));
    if main_inner().is_err(){eprintln!("BINIUS_CAPACITY_REJECT");std::process::exit(2);}
}
