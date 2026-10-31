//! Public CS cache only. No ValueVec, witness, private-word value or proof is serialized.
//! This separate format wraps original 14-byte v10 terms and shared public templates.
use std::{collections::{HashMap, HashSet}, fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write}, os::unix::fs::{OpenOptionsExt, PermissionsExt},
    sync::Arc, time::Instant};
use anyhow::{ensure, Result};
use binius_core::{constraint_system::{AndConstraint, ConstraintSystem, ShiftedValueIndex,
    StoredOperand, ValueSegment, ZeroConstraint}, word::Word};
use binius_utils::{DeserializeBytes, SerializeBytes};
use serde_json::{json, Value};
use sha3::Digest;
use crate::{direct_core::DirectBuilder, direct_full, direct_relation, direct_research,
    hex, memory, read, TRACE_SHA, ZV};

const MAGIC: &[u8; 8] = b"BCSCACH1";
pub(crate) const HEADER_BYTES: usize = 160;
const STREAM_BYTES: usize = 65536;
const FILE_CAP: u64 = 1 << 30;
const CS_SHA: &str = "693f241fdef46e2209aec1c01e48ced667f2b56594f5d9a25b6bf80978aba7ff";
const COMPILER_DOMAIN: &[u8] = b"PQSAT/BINIUS-FULL-WORD-COMPILER/v0.1\0";
const SETUP_DOMAIN: &[u8] = b"PQSAT/BINIUS-UNMERGED-FULL-ZK-SETUP/v0.1\0";
// C, inout, private, ZERO, AND, IMUL, BMUL, unique templates, template terms, max support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Shape([u32; 10]);
const FULL_SHAPE: Shape = Shape([10541, 106, 19864076, 3267532, 16359385, 0, 0,
                                17010, 4312778, 2631]);
impl Shape {
    fn operands(self) -> Result<u64> {
        u64::from(self.0[4]).checked_mul(3).and_then(|n| n.checked_add(u64::from(self.0[3])))
            .ok_or_else(|| anyhow::anyhow!("cache operand count overflow"))
    }
    fn file_bytes(self) -> Result<u64> {
        let terms = u64::from(self.0[8]).checked_mul(14);
        let records = self.operands()?.checked_mul(12);
        let total = Some(HEADER_BYTES as u64)
            .and_then(|n| n.checked_add(8 * u64::from(self.0[0])))
            .and_then(|n| n.checked_add(4 * u64::from(self.0[7])))
            .and_then(|n| n.checked_add(terms?))
            .and_then(|n| n.checked_add(records?));
        total.ok_or_else(|| anyhow::anyhow!("cache length overflow"))
    }
    fn admit(self) -> Result<()> {
        ensure!(self.0[0] <= 10541 && self.0[1] <= 106 && self.0[2] < (1 << 26)
            && self.0[3] <= 3267532 && self.0[4] <= 16359385
            && self.0[5] == 0 && self.0[6] == 0
            && self.0[7] <= 1_000_000 && self.0[8] <= 4312778
            && self.0[9] <= 8193, "cache declared allocation bounds");
        ensure!(40 * u64::from(self.0[7]) + 8 * u64::from(self.0[8]) <= 256 << 20,
            "cache template allocation budget");
        ensure!(self.file_bytes()? <= FILE_CAP, "cache file cap");
        Ok(())
    }
}

#[derive(Clone)]
struct Pins { shape: Shape, cs: [u8; 32], source: [u8; 32], trace: [u8; 32] }
fn parse_sha(raw: &str) -> Result<[u8; 32]> {
    ensure!(raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "canonical lowercase SHA256");
    let mut out = [0; 32];
    for (i, byte) in out.iter_mut().enumerate() { *byte = u8::from_str_radix(&raw[2*i..2*i+2], 16)?; }
    Ok(out)
}
fn full_pins() -> Result<Pins> {
    // These are public, identity-checked staged compiler sources. Cache adapter
    // code is intentionally excluded so its addition cannot change old CS IDs.
    let source: [u8; 32] = direct_research::digest(&[
        b"PQSAT/BINIUS-PUBLIC-CS-COMPILER-SOURCE/v0.1\0",
        include_bytes!("direct_core.rs"), include_bytes!("direct_sponge.rs"),
        include_bytes!("direct_relation.rs"), include_bytes!("direct_relation_profile.rs"),
        include_bytes!("sponge.rs")]).as_slice().try_into()?;
    Ok(Pins { shape: FULL_SHAPE, cs: parse_sha(CS_SHA)?, source, trace: parse_sha(TRACE_SHA)? })
}
fn put_u32(out: &mut impl Write, n: u32) -> Result<()> { out.write_all(&n.to_be_bytes())?; Ok(()) }
fn get_u32(input: &mut impl Read) -> Result<u32> {
    let mut raw = [0; 4]; input.read_exact(&mut raw)?; Ok(u32::from_be_bytes(raw))
}
fn header(out: &mut impl Write, pins: &Pins) -> Result<()> {
    out.write_all(MAGIC)?; out.write_all(&1u16.to_be_bytes())?; out.write_all(&0u16.to_be_bytes())?;
    put_u32(out, ConstraintSystem::SERIALIZATION_VERSION)?;
    out.write_all(&pins.shape.file_bytes()?.to_be_bytes())?;
    out.write_all(&pins.cs)?; out.write_all(&pins.source)?; out.write_all(&pins.trace)?;
    for n in pins.shape.0 { put_u32(out, n)?; } Ok(())
}
fn check_header(input: &mut impl Read, file_bytes: u64, pins: &Pins) -> Result<()> {
    let mut raw = [0; HEADER_BYTES]; input.read_exact(&mut raw)?;
    ensure!(&raw[..8] == MAGIC && raw[8..12] == [0,1,0,0]
        && u32::from_be_bytes(raw[12..16].try_into()?) == ConstraintSystem::SERIALIZATION_VERSION,
        "cache format/version/flags");
    let shape = Shape(std::array::from_fn(|i|
        u32::from_be_bytes(raw[120+4*i..124+4*i].try_into().unwrap())));
    shape.admit()?;
    ensure!(shape == pins.shape && raw[24..56] == pins.cs && raw[56..88] == pins.source
        && raw[88..120] == pins.trace, "independently pinned cache source/T/CS/shape");
    ensure!(file_bytes <= FILE_CAP && file_bytes == shape.file_bytes()?
        && u64::from_be_bytes(raw[16..24].try_into()?) == file_bytes,
        "cache exact inner/outer file length");
    Ok(())
}
fn operands(cs: &ConstraintSystem) -> impl Iterator<Item = &StoredOperand> {
    cs.zero_constraints.iter().flat_map(|row| row.0.iter())
        .chain(cs.and_constraints.iter().flat_map(|row| row.0.iter()))
}

fn encode(out: &mut impl Write, cs: &ConstraintSystem, pins: &Pins) -> Result<()> {
    pins.shape.admit()?;
    let s = pins.shape.0;
    ensure!([cs.constants.len(),cs.n_inout,cs.n_private,cs.zero_constraints.len(),
        cs.and_constraints.len(),cs.imul_constraints.len(),cs.bmul_constraints.len()]
        .into_iter().eq(s[..7].iter().map(|&n| n as usize)), "cache source shape");
    let mut ids = HashMap::<usize,u32>::new(); ids.try_reserve(s[7] as usize)?;
    let mut templates = Vec::<Arc<Vec<ShiftedValueIndex>>>::new(); templates.try_reserve_exact(s[7] as usize)?;
    let (mut terms,mut max_support) = (0u64,0usize);
    for operand in operands(cs) {
        let (template,_) = operand.public_compact_parts();
        let key = Arc::as_ptr(template) as usize;
        if !ids.contains_key(&key) {
            ensure!(templates.len() < s[7] as usize, "cache template cap");
            ids.insert(key,templates.len() as u32); templates.push(Arc::clone(template));
            terms += template.len() as u64; max_support = max_support.max(template.len());
        }
    }
    ensure!(templates.len() == s[7] as usize && terms == u64::from(s[8]) && max_support == s[9] as usize,
        "cache exact unique-template census");
    header(out,pins)?;
    for word in &cs.constants { let mut raw = [0;8]; word.serialize(&mut &mut raw[..])?; out.write_all(&raw)?; }
    for template in &templates {
        put_u32(out,template.len().try_into()?)?;
        for term in template.iter() {
            let mut raw = [0;14]; term.serialize(&mut &mut raw[..])?; out.write_all(&raw)?;
        }
    }
    for operand in operands(cs) {
        let (template,bases) = operand.public_compact_parts();
        put_u32(out,ids[&(Arc::as_ptr(template) as usize)])?;
        put_u32(out,bases[0])?; put_u32(out,bases[1])?;
    }
    Ok(())
}

fn decode(input: &mut impl Read, file_bytes: u64, pins: &Pins) -> Result<(ConstraintSystem,Value)> {
    check_header(input,file_bytes,pins)?; // Every inner allocation is bounded before reserve.
    let s = pins.shape.0;
    let mut cs = ConstraintSystem { constants:Vec::new(), n_inout:s[1] as usize, n_private:s[2] as usize,
        zero_constraints:Vec::new(),and_constraints:Vec::new(),imul_constraints:Vec::new(),bmul_constraints:Vec::new() };
    cs.constants.try_reserve_exact(s[0] as usize)?;
    for _ in 0..s[0] { let mut raw=[0;8]; input.read_exact(&mut raw)?; cs.constants.push(Word::deserialize(&raw[..])?); }
    let mut templates=Vec::<Arc<Vec<ShiftedValueIndex>>>::new(); templates.try_reserve_exact(s[7] as usize)?;
    let mut unique=HashSet::new(); unique.try_reserve(s[7] as usize)?;
    let (mut total_terms,mut max_support)=(0u64,0usize);
    for _ in 0..s[7] {
        let len=get_u32(input)? as usize;
        ensure!(len<=s[9] as usize, "cache template support cap");
        total_terms=total_terms.checked_add(len as u64).ok_or_else(||anyhow::anyhow!("template terms overflow"))?;
        ensure!(total_terms<=u64::from(s[8]), "cache cumulative template cap");
        let mut terms=Vec::new(); terms.try_reserve_exact(len)?;
        for _ in 0..len {
            let mut raw=[0;14]; input.read_exact(&mut raw)?;
            let term=ShiftedValueIndex::deserialize(&raw[..])?;
            // Validate shifts using the original core checker with a harmless
            // private placeholder: normalized indices are deltas until a row supplies bases.
            let mut checked=term;
            if term.value_index.segment()==ValueSegment::Private {
                checked.value_index=binius_core::constraint_system::ValueIndex::private(0);
            }
            ensure!(cs.operand_fault([checked]).is_none(), "cache template shift/segment/index canonicality");
            terms.push(term);
        }
        max_support=max_support.max(len);
        let template=Arc::new(terms);
        ensure!(unique.insert(Arc::clone(&template)), "duplicate cache template");
        templates.push(template);
    }
    ensure!(total_terms==u64::from(s[8]) && max_support==s[9] as usize, "cache exact template census");
    drop(unique);
    cs.zero_constraints.try_reserve_exact(s[3] as usize)?;
    cs.and_constraints.try_reserve_exact(s[4] as usize)?;
    let (mut next_id,mut referenced_terms)=(0u32,0u64);
    let mut get_operand = |input:&mut dyn Read| -> Result<StoredOperand> {
        let mut raw=[0;12]; input.read_exact(&mut raw)?;
        let id=u32::from_be_bytes(raw[..4].try_into()?);
        ensure!(id<s[7] && id<=next_id, "cache template reference/order");
        if id==next_id {next_id+=1;}
        let bases=[u32::from_be_bytes(raw[4..8].try_into()?),u32::from_be_bytes(raw[8..12].try_into()?)];
        let operand=StoredOperand::try_from_public_compact_parts(Arc::clone(&templates[id as usize]),bases)?;
        referenced_terms=referenced_terms.checked_add(operand.len() as u64)
            .ok_or_else(||anyhow::anyhow!("cache referenced terms overflow"))?;
        Ok(operand)
    };
    for _ in 0..s[3] { cs.zero_constraints.push(ZeroConstraint([get_operand(input)?])); }
    for _ in 0..s[4] { cs.and_constraints.push(AndConstraint([get_operand(input)?,get_operand(input)?,get_operand(input)?])); }
    drop(get_operand);
    ensure!(next_id==s[7], "unused cache template");
    ensure!(input.read(&mut [0;1])?==0, "trailing cache bytes");
    cs.validate()?;
    let native_bytes=std::mem::size_of::<ConstraintSystem>() as u64+8*u64::from(s[0])
        +16*pins.shape.operands()?+40*u64::from(s[7])+8*u64::from(s[8]);
    let shape=json!({"constants":s[0],"public_words":s[1],"private_words":s[2],
        "ZERO":s[3],"AND":s[4],"operand_terms":referenced_terms,"max_operand_support":s[9],
        "native_len_bytes":native_bytes,"serialized_bytes":32+8*u64::from(s[0])+4*pins.shape.operands()?+14*referenced_terms,
        "templates":{"unique":s[7],"terms":s[8],"payload_bytes":40*u64::from(s[7])+8*u64::from(s[8])},
        "allocator_and_Vec_spare_included":false});
    Ok((cs,shape))
}

struct HashRead<R> { inner:R, digest:binius_hash::StdDigest, bytes:u64 }
impl<R:Read> Read for HashRead<R> {
    fn read(&mut self,out:&mut [u8])->io::Result<usize> {
        let n=self.inner.read(out)?; self.digest.update(&out[..n]); self.bytes+=n as u64; Ok(n)
    }
}
struct HashWrite<W> { inner:W, digest:binius_hash::StdDigest, bytes:u64 }
impl<W:Write> Write for HashWrite<W> {
    fn write(&mut self,data:&[u8])->io::Result<usize> {
        if self.bytes.checked_add(data.len() as u64).is_none_or(|n|n>FILE_CAP) {
            return Err(io::Error::new(io::ErrorKind::InvalidData,"public cache output cap"));
        }
        let n=self.inner.write(data)?; self.digest.update(&data[..n]); self.bytes+=n as u64; Ok(n)
    }
    fn flush(&mut self)->io::Result<()> {self.inner.flush()}
}

pub(crate) struct Loaded { pub cs:ConstraintSystem,pub counts:Value,pub record:Value }
pub(crate) fn load(path:&str,expected_sha:&str)->Result<Loaded> {
    let started=Instant::now(); let expected=parse_sha(expected_sha)?; let pins=full_pins()?;
    let file=File::open(path)?;let metadata=file.metadata()?;
    ensure!(metadata.is_file() && metadata.len()<=FILE_CAP,"bounded regular public cache");
    let wrapped=HashRead {inner:file,digest:Default::default(),bytes:0};
    let mut input=BufReader::with_capacity(STREAM_BYTES,wrapped);
    let (cs,counts)=decode(&mut input,metadata.len(),&pins)?;
    let wrapped=input.into_inner();
    ensure!(wrapped.bytes==metadata.len(),"cache stream exact bytes");
    let cache_sha=wrapped.digest.finalize();ensure!(cache_sha.as_slice()==expected,"pinned compact cache SHA256");
    let load_seconds=started.elapsed().as_secs_f64();
    let hash_started=Instant::now();let cs_id=direct_full::cs_identity(&cs)?;
    ensure!(cs_id["sha256"].as_str()==Some(CS_SHA),"decoded canonical v10 CS identity");
    let record=json!({"cache_bytes":metadata.len(),"cache_sha256":hex(&cache_sha),
        "load_seconds":load_seconds,"CS_hash_seconds":hash_started.elapsed().as_secs_f64(),
        "public_CS_identity":cs_id,"source_sha256":hex(&pins.source),"stream_buffer_bytes":STREAM_BYTES,
        "private_values_received":false,"private_ValueVec_allocated":false,"cold_graph_constructed":false});
    Ok(Loaded {cs,counts,record})
}
fn trusted_tail(path:&str)->Result<(Vec<u8>,[u8;32])> {
    let tail=read(path,direct_relation::TAIL_BYTES)?;ensure!(tail.len()==direct_relation::TAIL_BYTES,"exact T bytes");
    let digest=direct_research::digest(&[&tail]);ensure!(hex(&digest)==TRACE_SHA,"trusted raw T");
    Ok((tail,digest.as_slice().try_into()?))
}
pub(crate) fn build(output:&str,tail_path:&str)->Result<()> {
    crate::direct_cached::require_eof(&mut io::stdin().lock())?;
    let started=Instant::now();let (tail,trace)=trusted_tail(tail_path)?;
    let b=DirectBuilder::new(false);
    direct_relation::compile(&b,&[0;direct_relation::PUBLIC_BYTES],None,&tail,&trace)?;
    let counts=crate::counts(&b.counts());let compiled=b.finish();
    ensure!(compiled.values.is_none(),"public cache build cannot hold private values");drop(tail);
    let build_seconds=started.elapsed().as_secs_f64();
    let hash_started=Instant::now();let identity=direct_full::cs_identity(&compiled.cs)?;
    ensure!(identity["sha256"].as_str()==Some(CS_SHA),"cache source canonical v10 CS identity");
    let hash_seconds=hash_started.elapsed().as_secs_f64();let pins=full_pins()?;
    let file=OpenOptions::new().write(true).create_new(true).mode(0o600).open(output)?;
    let wrapped=HashWrite {inner:file,digest:Default::default(),bytes:0};
    let mut out=BufWriter::with_capacity(STREAM_BYTES,wrapped);let writing=Instant::now();
    encode(&mut out,&compiled.cs,&pins)?;out.flush()?;
    let wrapped=out.into_inner().map_err(|_|anyhow::anyhow!("cache flush"))?;
    ensure!(wrapped.bytes==pins.shape.file_bytes()?,"actual cache output length");
    wrapped.inner.sync_all()?;wrapped.inner.set_permissions(fs::Permissions::from_mode(0o400))?;
    println!("DIRECT_RESULT {}",json!({"mode":"cache-build","cache_bytes":wrapped.bytes,
        "cache_sha256":hex(&wrapped.digest.finalize()),"counts":counts,"public_CS_identity":identity,
        "source_sha256":hex(&pins.source),"build_seconds":build_seconds,"CS_hash_seconds":hash_seconds,
        "cache_write_seconds":writing.elapsed().as_secs_f64(),"whole_seconds":started.elapsed().as_secs_f64(),
        "Prove":0,"proof_Verify":0,"private_values_received":false,"private_ValueVec_allocated":false,
        "stream_buffer_bytes":STREAM_BYTES,"final_memory":memory()?}));Ok(())
}
pub(crate) fn setup_only(path:&str,tail_path:&str,sha:&str)->Result<()> {
    crate::direct_cached::require_eof(&mut io::stdin().lock())?;
    let whole=Instant::now();drop(trusted_tail(tail_path)?);
    let loaded=load(path,sha)?;let setup=Instant::now();
    let verifier=ZV::setup_research_unmerged(loaded.cs,1)?;
    ensure!(verifier.is_research_unmerged() && verifier.basefold_compiler().max_log_domain_size()<=25,
        "unchanged full research setup admission");
    let mut actual=direct_full::setup_record(&verifier);
    actual["prover_memory_profile"]=json!("checkpoint4/on_the_fly/no_pool_retention/regenerated_private_masks/v0.1");
    let compiler=direct_research::digest(&[COMPILER_DOMAIN,CS_SHA.as_bytes()]);
    let setup_id=direct_research::digest(&[SETUP_DOMAIN,&compiler,&serde_json::to_vec(&actual)?]);
    crate::target128_profile::require_full_setup(&verifier,&actual,&setup_id)?;
    println!("DIRECT_RESULT {}",json!({"mode":"cache-load","counts":loaded.counts,"cache":loaded.record,
        "actual_symbolic_setup":actual,"compiler_id":hex(&compiler),"setup_id":hex(&setup_id),
        "setup_seconds":setup.elapsed().as_secs_f64(),"whole_seconds":whole.elapsed().as_secs_f64(),
        "Prove":0,"proof_Verify":0,"private_values_received":false,"private_ValueVec_allocated":false,
        "final_memory":memory()?}));Ok(())
}

#[cfg(test)]
#[path="direct_cs_cache_tests.rs"]
mod tests;
