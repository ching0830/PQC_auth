//! Bounded F7-only ZK capability experiment. Never a production issuance entry.
mod shake;

use std::{fs, io::{self, Read}, path::Path, time::Instant};
use anyhow::{Result, ensure};
use binius_core::word::Word;
use binius_frontend::{Circuit, CircuitBuilder, Wire};
use binius_hash::StdHashSuite;
use binius_prover::{OptimalPackedB128, zk_config::ZKProver};
use binius_transcript::{Options, ProverTranscript, VerifierTranscript};
use binius_utils::SerializeBytes;
use binius_verifier::{config::StdChallenger, zk_config::ZKVerifier};
use serde_json::{Value, json};

const DOMAIN: &[u8] = b"PQSAT-V3/ISSUANCE-FINAL-PPT/FULL-MESSAGE/v0.1";
const PROFILE: &str = "c42127d42bbc03f1382657eec8becc812151275127502d342b094e3af9644a25";
const STATEMENT_BYTES: usize = 1103;
const PRIVATE_BYTES: usize = 5534; // CR5074 || r72 || M388, stdin only.
const PROOF_CAP: usize = 128 << 20;
type ZV = ZKVerifier<StdHashSuite>;
type ZP = ZKProver<OptimalPackedB128, StdHashSuite>;

struct F7 {
    circuit: Circuit,
    message: Vec<Wire>,
    r: Vec<Wire>,
    scope: Vec<Wire>,
    beta: Vec<Wire>,
}

fn byte_slice(b: &CircuitBuilder, words: &[Wire], start: usize, bytes: usize) -> Vec<Wire> {
    (0..bytes).step_by(8).map(|offset| {
        let position = start + offset;
        let shift = (position % 8) * 8;
        let count = (bytes-offset).min(8);
        let mut word = if shift == 0 { words[position/8] }
            else { b.shr(words[position/8], shift as u32) };
        if shift + count*8 > 64 {
            word = b.bxor(word, b.shl(words[position/8+1], (64-shift) as u32));
        }
        if count < 8 {
            word = b.band(word, b.add_constant(Word((1u64 << (count*8))-1)));
        }
        word
    }).collect()
}

fn fixed_bytes(b: &CircuitBuilder, words: &[Wire], start: usize, expected: &[u8], label: &str) {
    for (i, (actual, chunk)) in byte_slice(b, words, start, expected.len()).into_iter()
        .zip(expected.chunks(8)).enumerate() {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        b.assert_eq(format!("{label}_{i}"), actual, b.add_constant(Word(u64::from_le_bytes(buf))));
    }
}

fn build() -> F7 {
    let b = CircuitBuilder::new();
    let scope: Vec<_> = (0..35).map(|_| b.add_inout()).collect();
    let beta: Vec<_> = (0..9).map(|_| b.add_inout()).collect();
    let message: Vec<_> = (0..725).map(|_| b.add_witness()).collect();
    let r: Vec<_> = (0..9).map(|_| b.add_witness()).collect();
    fixed_bytes(&b, &message, 0, DOMAIN, "fullH_domain");
    for (i, word) in byte_slice(&b, &message, 45, 276).into_iter().enumerate() {
        b.assert_eq(format!("fullH_scope_{i}"), word, scope[i]);
    }
    fixed_bytes(&b, &message, 321, &388u64.to_be_bytes(), "M_length");
    fixed_bytes(&b, &message, 717, &5074u64.to_be_bytes(), "CR_length");
    let u = shake::shake256_fixed(&b, &message, 5799, 72);
    for i in 0..9 {
        b.assert_eq(format!("beta_r_xor_u_{i}"), b.bxor(r[i], u[i]), beta[i]);
    }
    F7 { circuit: b.build(), message, r, scope, beta }
}

fn read_file(path: &str, cap: usize) -> Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    ensure!(file.metadata()?.is_file() && file.metadata()?.len() <= cap as u64, "public file cap");
    let mut data = Vec::new();
    file.take((cap+1) as u64).read_to_end(&mut data)?;
    ensure!(data.len() <= cap, "public file cap");
    Ok(data)
}

fn profile_bytes() -> Vec<u8> {
    (0..PROFILE.len()).step_by(2).map(|i| u8::from_str_radix(&PROFILE[i..i+2],16).unwrap()).collect()
}

fn statement(path: &str) -> Result<Vec<u8>> {
    let data = read_file(path, STATEMENT_BYTES)?;
    ensure!(data.len() == STATEMENT_BYTES && &data[..8] == b"BF7S\0\x01\0\x07", "F7 statement grammar");
    ensure!(data[8..40] == profile_bytes(), "F7 fixed profile");
    let n = &data[72..];
    ensure!(&n[..10] == b"NIFS\0\x01\0\x17\0\x02", "NIFS context grammar");
    ensure!(u32::from_be_bytes(n[10..14].try_into()?) as usize == 1017, "NIFS context length");
    ensure!(&n[14..57] == b"PQSAT-BUOV-CAP-RESEARCH/FULL-NCC-STMT/v0.1\0", "NIFS domain");
    ensure!(data[40..72] == n[89..121] && data[40..72] != [0u8;32], "setup join");
    ensure!(&n[755..765] == b"LCAPSCP1\0\x01", "Scope grammar");
    Ok(data)
}

fn words(data: &[u8]) -> Vec<Word> {
    data.chunks(8).map(|chunk| {
        let mut buf = [0u8;8]; buf[..chunk.len()].copy_from_slice(chunk);
        Word(u64::from_le_bytes(buf))
    }).collect()
}

fn public_words(frame: &[u8]) -> Vec<Word> {
    let n = &frame[72..];
    words(&n[755..1031]).into_iter().chain(words(&n[313..385])).collect()
}

fn eof() -> Result<()> {
    ensure!(io::stdin().read(&mut [0u8;1])? == 0, "public-only NCC stdin must be EOF");
    Ok(())
}

fn rss() -> Result<u64> {
    let text = fs::read_to_string("/proc/self/status")?;
    let row = text.lines().find(|r| r.starts_with("VmHWM:")).ok_or_else(|| anyhow::anyhow!("RSS unavailable"))?;
    Ok(row.split_whitespace().nth(1).unwrap().parse::<u64>()? * 1024)
}

fn cs_stats(f: &F7) -> Value {
    let cs = f.circuit.constraint_system();
    json!({"inner_constants":cs.constants.len(),"inner_public_words":cs.n_inout,
        "inner_private_words":cs.n_private,"inner_and":cs.and_constraints.len(),
        "inner_zero":cs.zero_constraints.len(),"inner_imul":cs.imul_constraints.len(),
        "inner_bmul":cs.bmul_constraints.len(),"keccak_permutations":shake::permutation_count(5799,72)})
}

fn setup_stats(v: &ZV) -> Value {
    let cs = v.outer_iop_verifier().constraint_system();
    json!({"outer_public":cs.n_public(),"outer_precommit":cs.n_precommit(),
        "outer_private":cs.n_private(),"outer_mul_constraints":cs.mul_constraints().len(),
        "outer_precommit_size":cs.precommit_size(),"outer_private_size":cs.private_size(),
        "max_log_domain_size":v.basefold_compiler().max_log_domain_size(),
        "oracle_specs":format!("{:?}", v.basefold_compiler().oracle_specs()),
        "fri_params":format!("{:?}",v.basefold_compiler().fri_params()),
        "security_bits_source_constant":binius_verifier::SECURITY_BITS,
        "log_inv_rate":1,"explicit_ZK_wrapper":true,"target128_qualified":false})
}

fn main_inner() -> Result<()> {
    // Guard every mode before any use of Rayon, and disable proof-dump side effects.
    ensure!(std::env::var("RAYON_NUM_THREADS").as_deref() == Ok("1"), "single-thread profile");
    ensure!(std::env::var_os("BINIUS_DUMP_PROOF").is_none(), "proof dump forbidden");
    ensure!(binius_verifier::SECURITY_BITS == 96, "fixed diagnostic profile");
    ensure!(binius_utils::rayon::config::adjust_thread_pool().is_ok(), "calling-thread pool initialization");
    ensure!(binius_utils::rayon::current_num_threads() == 1, "single-thread pool");
    let args: Vec<_> = std::env::args().collect();
    ensure!(args.len() >= 2, "explicit research mode");
    let mode = &args[1];
    ensure!(["public-setup", "UE-check", "UE-prove", "NCC-verify"].contains(&mode.as_str()), "research mode");
    ensure!(args.len() == if mode == "NCC-verify" {5} else if mode == "UE-check" {3} else {4}, "exact args");
    let start = Instant::now();
    let own = statement(&args[2])?;
    if mode == "NCC-verify" {
        eof()?;
        ensure!(read_file(&args[3],STATEMENT_BYTES)? == own, "NCC own statement differs");
    } else if mode == "public-setup" { eof()?; }
    let f = build();
    let build_seconds = start.elapsed().as_secs_f64();
    let stats = cs_stats(&f);
    let mut result = json!({"mode":mode,"build_seconds":build_seconds,"cs":stats,
        "classification":"F7-only explicit-ZK96 diagnostic; not full pi_iss_research",
        "proof_threads":1,"statement_bytes":STATEMENT_BYTES});
    if mode == "UE-check" || mode == "UE-prove" {
        let mut secret = Vec::new();
        io::stdin().take((PRIVATE_BYTES+1) as u64).read_to_end(&mut secret)?;
        ensure!(secret.len() == PRIVATE_BYTES, "exact private pipe input");
        let mut message = Vec::with_capacity(5799);
        message.extend_from_slice(DOMAIN);
        message.extend_from_slice(&own[72+755..]);
        message.extend_from_slice(&388u64.to_be_bytes());
        message.extend_from_slice(&secret[5146..]);
        message.extend_from_slice(&5074u64.to_be_bytes());
        message.extend_from_slice(&secret[..5074]);
        let mut filler = f.circuit.new_witness_filler();
        filler.pack_bytes_le(&f.message,&message);
        filler.pack_bytes_le(&f.r,&secret[5074..5146]);
        filler.pack_bytes_le(&f.scope,&own[72+755..]);
        filler.pack_bytes_le(&f.beta,&own[72+313..72+385]);
        // Never print PopulateError, ValueVec, or any witness-derived detail.
        f.circuit.populate_wire_witness(&mut filler).map_err(|_|anyhow::anyhow!("assignment rejected"))?;
        let witness = filler.into_value_vec();
        f.circuit.constraint_system().verify(&witness).map_err(|_|anyhow::anyhow!("constraint rejection"))?;
        result["assignment_seconds"] = json!(start.elapsed().as_secs_f64()-build_seconds);
        if mode == "UE-prove" {
            let setup_start = Instant::now();
            let verifier = ZV::setup(f.circuit.constraint_system().clone(),1)?;
            result["zk_setup"] = setup_stats(&verifier);
            // Domain twiddle capacity is one component, not an RSS bound.
            ensure!(verifier.basefold_compiler().max_log_domain_size() <= 24, "bounded prover domain admission");
            let prover = ZP::setup(&verifier)?;
            result["setup_seconds"] = json!(setup_start.elapsed().as_secs_f64());
            let mut transcript = ProverTranscript::with_opts(StdChallenger::default(),Options{debug_assertions:false});
            let prove_start = Instant::now();
            prover.prove_sig(&witness,&own,&mut rand::rng(),&mut transcript)?;
            let proof = transcript.finalize();
            result["prove_seconds"] = json!(prove_start.elapsed().as_secs_f64());
            ensure!(proof.len() <= PROOF_CAP, "proof output cap");
            result["proof_body_bytes"] = json!(proof.len());
            ensure!(!Path::new(&args[3]).exists(), "fresh proof path");
            fs::write(&args[3],proof)?;
        }
    } else {
        let setup_start = Instant::now();
        let verifier = ZV::setup(f.circuit.constraint_system().clone(),1)?;
        result["setup_seconds"] = json!(setup_start.elapsed().as_secs_f64());
        result["zk_setup"] = setup_stats(&verifier);
        if mode == "public-setup" {
            fs::create_dir(&args[3])?;
            let mut graph = Vec::new(); f.circuit.constraint_system().serialize(&mut graph)?;
            let mut setup = Vec::new(); verifier.serialize(&mut setup)?;
            ensure!(graph.len() <= PROOF_CAP && setup.len() <= PROOF_CAP,"public output cap");
            result["public_graph_bytes"] = json!(graph.len());
            result["reusable_verifier_bytes"] = json!(setup.len());
            fs::write(Path::new(&args[3]).join("F7.public.cs"),graph)?;
            fs::write(Path::new(&args[3]).join("F7.public.verifier"),setup)?;
        } else {
            let proof = read_file(&args[4],PROOF_CAP)?;
            result["proof_body_bytes"] = json!(proof.len());
            let mut transcript = VerifierTranscript::with_opts(StdChallenger::default(),proof,Options{debug_assertions:false});
            let verify_start = Instant::now();
            verifier.verify_sig(&public_words(&own),&own,&mut transcript)?;
            transcript.finalize()?; // Includes exact EOF/advice consumption.
            result["verify_seconds"] = json!(verify_start.elapsed().as_secs_f64());
            result["NCC_private_input_bytes"] = json!(0);
            result["accepted"] = json!(true);
        }
    }
    result["whole_seconds"] = json!(start.elapsed().as_secs_f64());
    result["OS_RSS_HWM_bytes"] = json!(rss()?);
    println!("BINIUS_RESULT {}",result);
    Ok(())
}

fn main() {
    // No panic/debug/error path may serialize private values into diagnostics.
    std::panic::set_hook(Box::new(|_|eprintln!("BINIUS_RESEARCH_PANIC_REJECT")));
    if main_inner().is_err() {
        eprintln!("BINIUS_RESEARCH_REJECT");
        std::process::exit(2);
    }
}
