//! Public-only, bounded batch verification with one immutable full-research setup.
//! Each request gets its own proof bytes and VerifierTranscript. No witness reader is used.
use std::{io::{self, Read}, time::Instant};

use anyhow::{ensure, Result};
use binius_core::word::Word;
use binius_transcript::{Options, VerifierTranscript};
use binius_verifier::config::StdChallenger;
use serde_json::{json, Value};

use crate::{direct_core::DirectBuilder, direct_full, direct_research, direct_relation,
    counts, hex, memory, read, PROOF_CAP, TRACE_SHA, ZV};

pub(crate) const MANIFEST_CAP: usize = 64 << 10;
pub(crate) const MAX_REQUESTS: usize = 8;
const PATH_CAP: usize = 4096;
const FRAME: usize = 1031;
const COMPILER_DOMAIN: &[u8] = b"PQSAT/BINIUS-FULL-WORD-COMPILER/v0.1\0";
const SETUP_DOMAIN: &[u8] = b"PQSAT/BINIUS-UNMERGED-FULL-ZK-SETUP/v0.1\0";

struct CachedSetup {
    verifier: ZV,
    compiler: Vec<u8>,
    setup_id: Vec<u8>,
    trace: Vec<u8>,
    record: Value,
}

/// The same full-research CS and setup identities as direct_research::run. Values of public
/// inout slots are not CS constants, so zero-valued public slots build the identical graph.
/// This path never constructs a prover builder or private ValueVec.
fn cached_setup(tail_path: &str) -> Result<CachedSetup> {
    let whole = Instant::now();
    let tail = read(tail_path, direct_relation::TAIL_BYTES)?;
    let trace = direct_research::digest(&[&tail]);
    ensure!(hex(&trace) == TRACE_SHA, "trusted raw T");
    let trace_array: [u8; 32] = trace.as_slice().try_into()?;
    let builder = DirectBuilder::new(false);
    direct_relation::compile(&builder, &[0u8; direct_relation::PUBLIC_BYTES], None, &tail, &trace_array)?;
    let shape = counts(&builder.counts());
    let compiled = builder.finish();
    ensure!(compiled.values.is_none(), "public setup cannot retain private values");
    drop(tail);
    let build_seconds = whole.elapsed().as_secs_f64();
    let after_build = memory()?;
    let hash = Instant::now();
    let cs_id = direct_full::cs_identity(&compiled.cs)?;
    let compiler = direct_research::digest(&[COMPILER_DOMAIN,
        cs_id["sha256"].as_str().ok_or_else(|| anyhow::anyhow!("public CS identity"))?.as_bytes()]);
    let hash_seconds = hash.elapsed().as_secs_f64();
    let setup = Instant::now();
    let verifier = ZV::setup_research_unmerged(compiled.cs, 1)?;
    ensure!(verifier.is_research_unmerged() && verifier.basefold_compiler().max_log_domain_size() <= 25,
        "full research setup admission");
    let mut actual = direct_full::setup_record(&verifier);
    actual["prover_memory_profile"] =
        json!("checkpoint4/on_the_fly/no_pool_retention/regenerated_private_masks/v0.1");
    let setup_id = direct_research::digest(&[SETUP_DOMAIN, &compiler, &serde_json::to_vec(&actual)?]);
    let setup_seconds = setup.elapsed().as_secs_f64();
    let record = json!({"counts": shape, "build_seconds": build_seconds,
        "CS_hash_seconds": hash_seconds, "setup_seconds": setup_seconds,
        "public_CS_identity": cs_id, "actual_symbolic_setup": actual,
        "after_build": after_build, "after_verifier_setup": memory()?,
        "whole_seconds": whole.elapsed().as_secs_f64(), "private_values_received": false,
        "private_ValueVec_allocated": false, "public_slot_bytes": direct_relation::PUBLIC_BYTES});
    Ok(CachedSetup { verifier, compiler, setup_id, trace, record })
}

#[derive(PartialEq, Eq)]
pub(crate) struct Request {
    statement: String,
    proof: String,
}

/// This narrow grammar deliberately does not deserialize into a map: duplicate keys (including
/// escaped spellings of the same key) must be rejected rather than silently overwritten.
struct Manifest<'a> { raw: &'a [u8], at: usize }
impl Manifest<'_> {
    fn whitespace(&mut self) {
        while self.raw.get(self.at).is_some_and(|b| matches!(b, b' ' | b'\r' | b'\n' | b'\t')) {
            self.at += 1;
        }
    }
    fn take(&mut self, byte: u8) -> bool {
        self.whitespace();
        if self.raw.get(self.at) == Some(&byte) { self.at += 1; true } else { false }
    }
    fn expect(&mut self, byte: u8) -> Result<()> {
        ensure!(self.take(byte), "batch manifest grammar"); Ok(())
    }
    fn string(&mut self) -> Result<String> {
        self.whitespace();
        let start = self.at;
        ensure!(self.raw.get(self.at) == Some(&b'"'), "batch manifest string");
        self.at += 1;
        let mut escaped = false;
        while let Some(&byte) = self.raw.get(self.at) {
            self.at += 1;
            if escaped { escaped = false; continue; }
            if byte == b'\\' { escaped = true; continue; }
            if byte == b'"' {
                // serde_json validates escaping, UTF-8, surrogate pairs and control bytes.
                // Its detailed error is never exposed by the batch command.
                let value: String = serde_json::from_slice(&self.raw[start..self.at])?;
                ensure!(value.len() <= PATH_CAP, "batch path cap");
                return Ok(value);
            }
        }
        anyhow::bail!("batch manifest string")
    }
    fn request(&mut self) -> Result<Request> {
        self.expect(b'{')?;
        let (mut statement, mut proof) = (None, None);
        for field in 0..2 {
            if field > 0 { self.expect(b',')?; }
            let key = self.string()?;
            self.expect(b':')?;
            let value = self.string()?;
            match key.as_str() {
                "statement" => { ensure!(statement.is_none(), "duplicate batch key"); statement = Some(value); }
                "proof" => { ensure!(proof.is_none(), "duplicate batch key"); proof = Some(value); }
                _ => anyhow::bail!("unknown batch key"),
            }
        }
        self.expect(b'}')?;
        Ok(Request {
            statement: statement.ok_or_else(|| anyhow::anyhow!("missing batch key"))?,
            proof: proof.ok_or_else(|| anyhow::anyhow!("missing batch key"))?,
        })
    }
}

pub(crate) fn parse_manifest(raw: &[u8]) -> Result<Vec<Request>> {
    ensure!(raw.len() <= MANIFEST_CAP, "batch manifest cap");
    let mut parser = Manifest { raw, at: 0 };
    parser.expect(b'[')?;
    let mut requests = Vec::new();
    ensure!(!parser.take(b']'), "nonempty batch manifest");
    loop {
        ensure!(requests.len() < MAX_REQUESTS, "batch request count cap");
        requests.push(parser.request()?);
        if parser.take(b']') { break; }
        parser.expect(b',')?;
    }
    parser.whitespace();
    ensure!(parser.at == raw.len(), "trailing batch JSON");
    Ok(requests)
}

pub(crate) fn statement_fd(path: &str) -> Result<i32> {
    let digits = path.strip_prefix("/proc/self/fd/")
        .ok_or_else(|| anyhow::anyhow!("sealed public statement path"))?;
    ensure!(!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()), "public fd spelling");
    let fd: i32 = digits.parse()?;
    ensure!(fd >= 3 && fd.to_string() == digits, "canonical public fd");
    Ok(fd)
}

pub(crate) fn require_eof(reader: &mut impl Read) -> Result<()> {
    ensure!(reader.read(&mut [0u8; 1])? == 0, "NCC receives no witness"); Ok(())
}

struct Attempt {
    verify_called: bool,
    verify_seconds: Option<f64>,
    statement_bytes: Option<usize>,
    proof_bytes: Option<usize>,
}

fn verify_request(
    setup: &CachedSetup, request: &Request, attempt: &mut Attempt,
) -> Result<()> {
    let _fd = statement_fd(&request.statement)?;
    let raw = read(&request.statement, FRAME)?;
    attempt.statement_bytes = Some(raw.len());
    let (compiler, setup_id, trace, public) = direct_research::statement(&raw)?;
    ensure!(compiler == setup.compiler.as_slice() && setup_id == setup.setup_id.as_slice()
        && trace == setup.trace.as_slice(),
        "locally rebuilt public setup identity");
    ensure!(public.len() == direct_relation::PUBLIC_BYTES, "full public width");
    let proof = read(&request.proof, PROOF_CAP)?;
    attempt.proof_bytes = Some(proof.len());
    let words: Vec<_> = public.chunks(8).map(|chunk| {
        let mut word = [0u8; 8]; word[..chunk.len()].copy_from_slice(chunk);
        Word(u64::from_le_bytes(word))
    }).collect();
    let core = Instant::now();
    // Set the counter immediately before the actual verifier call. A bad statement/path must
    // never be counted as a cryptographic Verify; a malformed proof that reaches it is counted.
    let mut transcript = VerifierTranscript::with_opts(StdChallenger::default(), proof,
        Options { debug_assertions: false });
    attempt.verify_called = true;
    let checked = setup.verifier.verify_sig(&words, &raw, &mut transcript)
        .map_err(anyhow::Error::from).and_then(|()| transcript.finalize().map_err(anyhow::Error::from));
    attempt.verify_seconds = Some(core.elapsed().as_secs_f64());
    checked
}

pub(crate) fn run(manifest_path: &str, tail_path: &str) -> Result<()> {
    let whole = Instant::now();
    require_eof(&mut io::stdin().lock())?;
    let manifest = read(manifest_path, MANIFEST_CAP)?;
    let requests = parse_manifest(&manifest)?;
    // This factory uses only zero-valued public slots, immutable trusted T and public metadata.
    // It is independent of every request, including the first potentially invalid statement.
    let setup = cached_setup(tail_path)?;
    let mut results = Vec::with_capacity(requests.len());
    let (mut accepted, mut verifies) = (0usize, 0usize);
    for (index, request) in requests.iter().enumerate() {
        let started = Instant::now();
        let mut attempt = Attempt { verify_called: false, verify_seconds: None,
            statement_bytes: None, proof_bytes: None };
        // Expected proof failures are per-request. An unexpected backend panic
        // aborts the batch through the binary's redacted fail-closed hook.
        let ok = verify_request(&setup, request, &mut attempt).is_ok();
        accepted += usize::from(ok); verifies += usize::from(attempt.verify_called);
        let row: Value = json!({"request_index": index, "status": if ok {"accepted"} else {"rejected"},
            "accepted": ok, "verify_called": attempt.verify_called, "verify_seconds": attempt.verify_seconds,
            "proof_Verify": usize::from(attempt.verify_called),
            "statement_bytes": attempt.statement_bytes, "proof_body_bytes": attempt.proof_bytes,
            "whole_seconds": started.elapsed().as_secs_f64(), "memory": memory()?});
        results.push(row);
    }
    ensure!(verifies <= MAX_REQUESTS, "batch verification call cap");
    println!("DIRECT_RESULT {}", json!({"mode": "full-verify-batch", "request_count": requests.len(),
        "compute_cores": binius_utils::rayon::current_num_threads(),
        "accepted_count": accepted, "rejected_count": requests.len() - accepted,
        "Prove": 0, "proof_Verify": verifies, "shared_setup_count": 1, "shared_setup": setup.record,
        "compiler_id": hex(&setup.compiler), "setup_id": hex(&setup.setup_id), "trace_id": hex(&setup.trace),
        "private_values_received": false, "profile": "research_unmerged_checkpoint_v0_1", "security_bits": 96,
        "security_classification": "diagnostic; no target128 qualification", "requests": results,
        "whole_seconds": whole.elapsed().as_secs_f64(), "final_memory": memory()?}));
    Ok(())
}

#[cfg(test)]
#[path = "direct_cached_tests.rs"]
mod tests;
