//! Public algebra/constraint controls; no ticket or proof generation.
use crate::{direct_core::{DirectBuilder,DirectCompiled},direct_relation::masked_consistency_word};
use binius_core::constraint_system::ValueIndex;
use binius_utils::serialization::SerializeBytes;

// Carryless full product then polynomial long division; no circuit Horner.
fn mul(a:u64,b:u64)->u64{
    let mut v=0u128;
    for i in 0..64{if b>>i&1!=0{v^=(a as u128)<<i;}}
    for i in (64..=126).rev(){if v>>i&1!=0{v^=((1u128<<64)|0x1b)<<(i-64);}}
    v as u64
}
fn reference(c:&[u64],x:u64,m:u64)->u64{
    let mut power=x;let mut out=m;
    for &a in c{out^=mul(a,power);power=mul(power,x);}out
}
fn build(prover:bool,c:&[u64],x:u64,m:u64,target:u64)->DirectCompiled{
    let b=DirectBuilder::new(prover);
    let coeff:Vec<_>=c.iter().map(|&a|b.private_input(prover.then_some(a))).collect();
    let chi=b.private_input(prover.then_some(x));let mask=b.private_input(prover.then_some(m));
    let out=masked_consistency_word(&b,&coeff,&chi,&mask);
    b.assert_eq(&out,&b.public_input(target));b.finish()
}
fn encoded(c:&DirectCompiled)->Vec<u8>{let mut out=Vec::new();c.cs.serialize(&mut out).unwrap();out}
#[test]
fn hplus_cross_language_kat_and_unscaled_mask(){
    let c:Vec<_>=(0..32).map(|i|u64::from_le_bytes(std::array::from_fn(|j|(8*i+j)as u8))).collect();
    for x in [0,1,1<<63,u64::MAX,0x0123456789abcdef]{
        let m=0xfedcba9876543210;let target=reference(&c,x,m);
        let p=build(true,&c,x,m,target);p.cs.verify(p.values.as_ref().unwrap()).unwrap();
        let v=build(false,&c,x,m,target);assert!(v.values.is_none());assert_eq!(encoded(&p),encoded(&v));
        let bad=build(true,&c,x,m,target^1);assert!(bad.cs.verify(bad.values.as_ref().unwrap()).is_err());
    }
    let p=build(true,&[0;32],0,0x1234,0x1234);p.cs.verify(p.values.as_ref().unwrap()).unwrap();
}
#[test]
fn hplus_input_and_new_multiplication_intermediate_are_constrained(){
    let mut c=[0u64;32];c[0]=0x1234;
    let p=build(true,&c,2,0x1234,reference(&c,2,0x1234));
    let values=p.values.as_ref().unwrap();
    for index in [0,32,33,p.cs.n_private-1]{
        let mut changed=values.clone();changed[ValueIndex::private(index.try_into().unwrap())].0^=1;
        assert!(p.cs.verify(&changed).is_err(),"unconstrained private word {index}");
    }
}
#[test]
fn hplus_old_fixed_cancellation_is_rejected(){
    let c=0x0123456789abcdef;let mut coeff=[0u64;32];coeff[0]=c;
    for chi in [0,2,3,4,5,u64::MAX]{
        let p=build(true,&coeff,chi,c,0);assert!(p.cs.verify(p.values.as_ref().unwrap()).is_err());
    }
    // chi=1 is an allowed exceptional collision, not deterministic rejection.
    let p=build(true,&coeff,1,c,0);p.cs.verify(p.values.as_ref().unwrap()).unwrap();
}

#[test]
fn hplus_rejects_mixed_public_identities_before_compilation(){
    use crate::{direct_relation::validate_public_profile,direct_relation_profile as p};
    let mut public=vec![0u8;846];
    public[..32].copy_from_slice(p::FINGERPRINT);public[272..304].copy_from_slice(p::FINGERPRINT);
    public[240..272].copy_from_slice(p::RELATION_ID);public[814..846].copy_from_slice(p::BINDING_ID);
    validate_public_profile(&public).unwrap();
    for at in [0,240,272,814]{let mut changed=public.clone();changed[at]^=1;
        assert!(validate_public_profile(&changed).is_err());}
    assert!(validate_public_profile(&public[..845]).is_err());
}
