//! Small public codec/shape/negative controls; actual full P/V is run by the guarded runner.
use super::*;
use crate::setup_support as direct_full;
use binius_core::constraint_system::{Shift, TemplateInterner, ValueIndex};

fn fixture() -> (ConstraintSystem,Pins,Vec<u8>) {
    let mut interner=TemplateInterner::new(32,8192);
    let make=|a,b|vec![ShiftedValueIndex::rotr(ValueIndex::private(a),7),
                       ShiftedValueIndex::new(ValueIndex::private(b),[Shift::srl(3),Shift::sll(3)])];
    let a=interner.intern(make(10,10000)).unwrap();
    let b=interner.intern(make(20,20000)).unwrap();
    assert!(a.shares_template_with(&b));
    let zero=interner.intern(vec![]).unwrap();
    let one=interner.intern(vec![ShiftedValueIndex::plain(ValueIndex::constant(0))]).unwrap();
    let cs=ConstraintSystem {constants:vec![Word(0)],n_inout:1,n_private:20001,
        zero_constraints:vec![ZeroConstraint([a.clone()]),ZeroConstraint([b]),ZeroConstraint([zero.clone()])],
        and_constraints:vec![AndConstraint([one,a,zero])],imul_constraints:vec![],bmul_constraints:vec![]};
    cs.validate().unwrap();
    let m=interner.metrics();
    let identity=direct_full::cs_identity(&cs).unwrap();
    let pins=Pins {shape:Shape([1,1,20001,3,1,0,0,m.unique_templates as u32,m.template_terms as u32,2]),
        cs:parse_sha(identity["sha256"].as_str().unwrap()).unwrap(),source:[1;32],trace:[2;32]};
    let mut raw=Vec::new();encode(&mut raw,&cs,&pins).unwrap();
    (cs,pins,raw)
}
fn rows_at(pins:&Pins)->usize {
    HEADER_BYTES+8*pins.shape.0[0] as usize+4*pins.shape.0[7] as usize+14*pins.shape.0[8] as usize
}
#[test]
fn compact_cache_format_exact_full_arithmetic_and_original_v10_roundtrip() {
    assert_eq!(FULL_SHAPE.file_bytes().unwrap(),688968080);
    let (cs,pins,raw)=fixture();
    assert_eq!(raw.len() as u64,pins.shape.file_bytes().unwrap());
    assert_eq!(&raw[..8],b"BCSHPL01");
    let (loaded,counts)=decode(&mut raw.as_slice(),raw.len() as u64,&pins).unwrap();
    assert_eq!(direct_full::cs_identity(&cs).unwrap(),direct_full::cs_identity(&loaded).unwrap());
    assert_eq!(counts["operand_terms"],7);
    assert!(loaded.zero_constraints[0].0[0].shares_template_with(&loaded.zero_constraints[1].0[0]));
    assert!(loaded.zero_constraints[0].0[0].shares_template_with(&loaded.and_constraints[0].0[1]));
    let mut repeated=Vec::new();encode(&mut repeated,&loaded,&pins).unwrap();assert_eq!(raw,repeated);
    let witness=cs.value_vec_from_data(&[Word(0)],&vec![Word(0);cs.n_private]);
    cs.verify(&witness).unwrap();loaded.verify(&witness).unwrap();
    let mut mutated=cs.value_vec_from_data(&[Word(0)],&vec![Word(0);cs.n_private]);
    mutated[ValueIndex::private(10)]=Word(1);
    assert!(cs.verify(&mutated).is_err());assert!(loaded.verify(&mutated).is_err());
}
#[test]
fn compact_cache_rejects_profile_source_T_shape_length_and_EOF() {
    let (_,pins,raw)=fixture();
    for offset in [0,8,10,12,16,24,56,88,120,128,148,152,156] {
        let mut bad=raw.clone();bad[offset]^=1;
        assert!(decode(&mut bad.as_slice(),bad.len() as u64,&pins).is_err(),"header offset {offset}");
    }
    for len in [0,1,HEADER_BYTES-1,raw.len()-1] {
        assert!(decode(&mut &raw[..len],len as u64,&pins).is_err());
    }
    let mut bad=raw.clone();bad.push(0);
    assert!(decode(&mut bad.as_slice(),raw.len() as u64,&pins).is_err());
    assert!(decode(&mut raw.as_slice(),FILE_CAP+1,&pins).is_err());
    for text in ["",&"0".repeat(63),&"A".repeat(64),&"g".repeat(64)] {assert!(parse_sha(text).is_err());}
}
#[test]
fn compact_cache_rejects_reference_order_unknown_unused_and_private_aliases() {
    let (_,pins,raw)=fixture();let start=rows_at(&pins);
    for id in [1,pins.shape.0[7],u32::MAX] {
        let mut bad=raw.clone();bad[start..start+4].copy_from_slice(&id.to_be_bytes());
        assert!(decode(&mut bad.as_slice(),bad.len() as u64,&pins).is_err());
    }
    // The final template is introduced by the first AND operand. Naming the
    // prior empty template instead leaves it unused, rather than accepting it.
    let mut bad=raw.clone();let and=start+12*pins.shape.0[3] as usize;
    bad[and..and+4].copy_from_slice(&1u32.to_be_bytes());
    assert!(decode(&mut bad.as_slice(),bad.len() as u64,&pins).is_err());
    for (offset,base) in [(4,1u32<<26),(8,10u32),(8,4096u32)] {
        let mut bad=raw.clone();bad[start+offset..start+offset+4].copy_from_slice(&base.to_be_bytes());
        assert!(decode(&mut bad.as_slice(),bad.len() as u64,&pins).is_err());
    }
    // A different valid address basis is structurally valid, but its decoded
    // canonical v10 SHA must differ and is rejected by load's independent pin.
    let mut changed=raw.clone();changed[start+8..start+12].copy_from_slice(&5000u32.to_be_bytes());
    let (different,_)=decode(&mut changed.as_slice(),changed.len() as u64,&pins).unwrap();
    let expected=hex(&pins.cs);
    assert_ne!(direct_full::cs_identity(&different).unwrap()["sha256"].as_str(),
               Some(expected.as_str()));
}
#[test]
fn compact_cache_rejects_template_shift_scratch_support_and_duplicate() {
    let (_,pins,raw)=fixture();let first=HEADER_BYTES+8*pins.shape.0[0] as usize;
    // Each template term remains exactly the upstream 14B serialization:
    // ValueIndex u32LE, then variant u8/amount u32LE twice.
    for (delta,value) in [(4,0xff),(5,0xff)] {
        let mut bad=raw.clone();bad[first+4+delta]=value;
        assert!(decode(&mut bad.as_slice(),bad.len() as u64,&pins).is_err());
    }
    let mut bad=raw.clone();bad[first+4+3]=0xc0;
    assert!(decode(&mut bad.as_slice(),bad.len() as u64,&pins).is_err());
    let mut bad=raw.clone();bad[first..first+4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(decode(&mut bad.as_slice(),bad.len() as u64,&pins).is_err());
    // Dictionary order: two-term template, empty template, singleton constant.
    // Replacing the singleton by an already present empty template is rejected
    // before allocating any row, even with exact header/file length supplied.
    let mut bad=raw.clone();let third=first+4+28+4;
    bad[third..third+4].copy_from_slice(&0u32.to_be_bytes());
    assert!(decode(&mut bad.as_slice(),bad.len() as u64,&pins).is_err());
}
#[test]
fn compact_cache_caps_are_checked_before_inner_allocation() {
    let (_,pins,raw)=fixture();
    for (field,cap) in [(0,8488),(1,107),(2,1<<26),(3,3263534),(4,16361387),
                        (5,1),(6,1),(7,1000001),(8,4333415),(9,8194)] {
        let mut bad=raw.clone();bad[120+4*field..124+4*field].copy_from_slice(&(cap as u32).to_be_bytes());
        assert!(decode(&mut bad.as_slice(),bad.len() as u64,&pins).is_err());
    }
}

#[test]
fn legacy_magic_is_rejected_before_large_allocation(){
    let (_,pins,mut raw)=fixture();raw[..8].copy_from_slice(b"BCSCACH1");
    assert!(decode(&mut raw.as_slice(),raw.len()as u64,&pins).is_err());
}
