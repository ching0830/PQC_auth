use super::*;
use binius_core::constraint_system::ValueIndex;
use binius_utils::serialization::SerializeBytes;

fn hex(s:&str)->Vec<u8> {(0..s.len()).step_by(2).map(|i|u8::from_str_radix(&s[i..i+2],16).unwrap()).collect()}
fn private_words(b:&DirectBuilder,bytes:&[u8])->Vec<Expr> {
    bytes.chunks(8).map(|chunk| {
        let mut word=[0u8;8];word[..chunk.len()].copy_from_slice(chunk);
        b.private_input(b.is_prover().then_some(u64::from_le_bytes(word)))
    }).collect()
}
fn bind_digest(b:&DirectBuilder,out:&[Expr],expected:&[u8]) {
    assert_eq!(out.len(),expected.len().div_ceil(8));
    for (word,chunk) in out.iter().zip(expected.chunks(8)) {
        let mut bytes=[0u8;8];bytes[..chunk.len()].copy_from_slice(chunk);
        let expected=u64::from_le_bytes(bytes);
        if b.is_prover() {assert_eq!(b.eval(word),Some(expected));}
        b.assert_eq(word,&b.public_input(expected));
    }
}
#[test]
fn nist_cshake_and_kmac_share_actual_constrained_input() {
    let b=DirectBuilder::new(true);
    let x=private_words(&b,&[0,1,2,3]);
    let digest=cshake256_fixed(&b,&x,4,64,b"",b"Email Signature");
    bind_digest(&b,&digest,&hex("d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c"));
    let key:Vec<u8>=(0x40..=0x5f).collect();let key=private_words(&b,&key);
    let digest=kmac256_fixed(&b,&key,32,&x,4,64,b"My Tagged Application");
    bind_digest(&b,&digest,&hex("20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd"));
    let compiled=b.finish();compiled.cs.verify(compiled.values.as_ref().unwrap()).unwrap();
    let mut values=compiled.values.unwrap();values[ValueIndex::private(0)].0^=1;
    assert!(compiled.cs.verify(&values).is_err());
}
#[test]
fn rate_boundary_multi_squeeze_and_witness_free_same_cs() {
    fn build(prover:bool)->crate::direct_core::DirectCompiled {
        let b=DirectBuilder::new(prover);
        let message:Vec<u8>=(0..137).map(|i|((17*i+3)%256) as u8).collect();
        let x=private_words(&b,&message);
        let shake=shake256_fixed(&b,&x,137,137);
        let cshake=cshake256_fixed(&b,&x,137,137,b"",b"");
        for (a,c) in shake.iter().zip(&cshake) {b.assert_eq(a,c);}
        bind_digest(&b,&shake,&hex("afd9177d8c6dda1cebc6411cf5a693c9481401bcad12dd898b3e33128bfafd5d1a7d1cd3f807152b5b18a3db2f38594b0f9b0d4b157e2aeac4d0eda287788c900334fc830f4dbad44b9cf645382f226b32d95f9f1a6b60f9efe0a94ee663d25b451151f3766e5f881c056cfb77ff2c02c2c4240dd960d9fc67040034b6e3ba691704d0c936cc8abe35"));
        b.finish()
    }
    let p=build(true);let v=build(false);assert!(v.values.is_none());
    let mut pb=Vec::new();p.cs.serialize(&mut pb).unwrap();
    let mut vb=Vec::new();v.cs.serialize(&mut vb).unwrap();assert_eq!(pb,vb);
    p.cs.verify(p.values.as_ref().unwrap()).unwrap();
    let mut values=p.values.unwrap();values[ValueIndex::inout(16)].0^=1;
    assert!(p.cs.verify(&values).is_err());
}
#[test]
fn canonical_tail_and_unaligned_byte_concatenation() {
    let b=DirectBuilder::new(true);
    let first=private_words(&b,&[1,2,3]);let second=private_words(&b,&[4,5,6,7,8,9,10,11,12]);
    let words=pack_parts(&b,&[(&first,3),(&second,9)]);
    assert_eq!(words.len(),2);
    assert_eq!(b.eval(&words[0]),Some(0x0807_0605_0403_0201));
    assert_eq!(b.eval(&words[1]),Some(0x0000_0000_0c0b_0a09));
    for (word,value) in words.iter().zip([0x0807_0605_0403_0201,0x0000_0000_0c0b_0a09]) {
        b.assert_eq(word,&b.public_input(value));
    }
    let compiled=b.finish();compiled.cs.verify(compiled.values.as_ref().unwrap()).unwrap();
    let mut values=compiled.values.unwrap();values[ValueIndex::private(0)].0^=1u64<<56;
    assert!(compiled.cs.verify(&values).is_err());
}

#[test]
fn invalid_tail_is_rejected_without_host_precheck() {
    let b=DirectBuilder::new(true);
    let x=vec![b.private_input(Some(0x8000_0000_0003_0201))];
    let _=shake256_fixed(&b,&x,3,32);
    let compiled=b.finish();
    assert!(compiled.cs.verify(compiled.values.as_ref().unwrap()).is_err());
}
