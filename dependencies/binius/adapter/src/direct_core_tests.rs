//! Public diagnostic controls. Constraint replay does not claim a ZK proof.
use super::*;
use binius_utils::serialization::SerializeBytes;

fn encoded(cs:&ConstraintSystem)->Vec<u8> {let mut bytes=Vec::new();cs.serialize(&mut bytes).unwrap();bytes}
fn independent_gf(a:u64,b:u64)->u64 {
    let mut product=0u128;
    for i in 0..64 {if (b>>i)&1!=0 {product^=(a as u128)<<i;}}
    for degree in (64..=126).rev() {
        if (product>>degree)&1!=0 {product^=((1u128<<64)|0x1b)<<(degree-64);}
    }
    product as u64
}
#[test]
fn shared_private_registry_and_no_verifier_witness() {
    fn build(prover:bool,value:u64)->DirectCompiled {
        let b=DirectBuilder::new(prover);
        let x=b.private_input(prover.then_some(value));
        let one=b.constant(1);let y=b.xor(&x,&one);
        let out=b.public_input(value^1);
        b.assert_eq(&y,&out);
        // The SAME input is used twice; cancellation does not allocate a second secret.
        b.assert_zero(&b.xor(&x,&x));
        assert_eq!(b.eval(&y),prover.then_some(value^1));b.finish()
    }
    let p=build(true,0x8911);let v=build(false,0x8911);
    assert!(v.values.is_none());assert_eq!(encoded(&p.cs),encoded(&v.cs));
    assert_eq!(p.cs.n_private,1);assert_eq!(p.cs.n_inout,1);
    p.cs.verify(p.values.as_ref().unwrap()).unwrap();
    let different_private=build(true,0x1893);
    assert_eq!(encoded(&p.cs),encoded(&different_private.cs));
    let mut values=p.values.unwrap();values[ValueIndex::private(0)].0^=1;
    assert!(p.cs.verify(&values).is_err());
}
#[test]
fn shifted_affine_and_materialization_constraints() {
    let b=DirectBuilder::new(true);let value=0xf123_4567_89ab_cdef;
    let x=b.private_input(Some(value));
    let a=b.shr(&b.shl(&x,9),7);
    let a=b.rotl(&a,13); // third shift must be privately pinned, not discarded.
    let z=b.xor(&a,&b.sar(&x,63));
    let expected=((value<<9)>>7).rotate_left(13)^u64::MAX;
    let out=b.public_input(expected);b.assert_eq(&z,&out);
    assert_eq!(b.eval(&z),Some(expected));
    let compiled=b.finish();compiled.cs.verify(compiled.values.as_ref().unwrap()).unwrap();
    assert!(compiled.cs.n_private>=2);
    let mut values=compiled.values.unwrap();values[ValueIndex::private(1)].0^=1;
    assert!(compiled.cs.verify(&values).is_err());
}
#[test]
fn keccak_f1600_zero_known_answer_and_intermediate_rejection() {
    let expected=[
        0xf1258f7940e1dde7,0x84d5ccf933c0478a,0xd598261ea65aa9ee,0xbd1547306f80494d,0x8b284e056253d057,
        0xff97a42d7f8e6fd4,0x90fee5a0a44647c4,0x8c5bda0cd6192e76,0xad30a6f71b19059c,0x30935ab7d08ffc64,
        0xeb5aa93f2317d635,0xa9a6e6260d712103,0x81a57c16dbcf555f,0x43b831cd0347c826,0x01f22f1a11a5569f,
        0x05e5635a21d9ae61,0x64befef28cc970f2,0x613670957bc46611,0xb87c5a554fd00ecb,0x8c3ee88a1ccf32c8,
        0x940c7922ae3a2614,0x1841f924a2c509e4,0x16f53526e70465c2,0x75f644e97f30a13b,0xeaf1ff7b5ceca249];
    let b=DirectBuilder::new(true);
    let mut state:[Expr;25]=std::array::from_fn(|_|b.private_input(Some(0)));
    b.keccak(&mut state);
    for i in 0..25 {assert_eq!(b.eval(&state[i]),Some(expected[i]));b.assert_eq(&state[i],&b.public_input(expected[i]));}
    let compiled=b.finish();compiled.cs.verify(compiled.values.as_ref().unwrap()).unwrap();
    assert_eq!(compiled.cs.n_inout,25);
    // First private theta-D and the last chi result are both constrained.
    for i in [25,compiled.cs.n_private-1] {
        let mut values=compiled.values.as_ref().unwrap().clone();
        values[ValueIndex::private(i as u32)].0^=1;
        assert!(compiled.cs.verify(&values).is_err());
    }
}
#[test]
fn gf64_polynomial_basis_products_and_public_specialization() {
    let b=DirectBuilder::new(true);
    let pairs=[(0,0),(1,u64::MAX),(0x8000_0000_0000_0000,2),
        (0x1234_5678_9abc_def0,0xfedc_ba98_7654_3210),(u64::MAX,u64::MAX),
        (0x82c3_5fac_71b0_289e,0x11f0_0088_51ca_a291)];
    for (a,c) in pairs {
        let x=b.private_input(Some(a));let y=b.private_input(Some(c));
        let variable=b.gf64_mul(&x,&y);let fixed=b.gf64_mul_const(&x,c);
        let expected=independent_gf(a,c);
        assert_eq!(b.eval(&variable),Some(expected));assert_eq!(b.eval(&fixed),Some(expected));
        let public=b.public_input(expected);b.assert_eq(&variable,&public);b.assert_eq(&fixed,&public);
    }
    let compiled=b.finish();compiled.cs.verify(compiled.values.as_ref().unwrap()).unwrap();
    let mut values=compiled.values.unwrap();values[ValueIndex::inout(3)].0^=1;
    assert!(compiled.cs.verify(&values).is_err());
}

#[test]
#[should_panic(expected="verifier must not receive private values")]
fn verifier_rejects_secret_input() {DirectBuilder::new(false).private_input(Some(17));}

#[test]
fn exact_count_sink_matches_materialized_core_format() {
    fn relation(b:&DirectBuilder) {
        let mut state:[Expr;25]=std::array::from_fn(|_|b.private_input(None));
        b.keccak(&mut state);
        b.assert_eq(&state[4],&b.public_input(0));
    }
    let counting=DirectBuilder::new_counting();relation(&counting);
    let counts=counting.finish_counting();
    let materialized=DirectBuilder::new(false);relation(&materialized);
    assert_eq!(counts,materialized.counts());
    let compiled=materialized.finish();
    assert_eq!(counts.and,compiled.cs.and_constraints.len());
    assert_eq!(counts.zero,compiled.cs.zero_constraints.len());
    assert_eq!(counts.private,compiled.cs.n_private);
    assert_eq!(counts.serialized_bytes,encoded(&compiled.cs).len());
    assert_eq!(counts.operand_terms,counts.unshifted_terms+counts.singly_shifted_terms+counts.doubly_shifted_terms);
    assert!(counts.max_operand_support<=DirectBuilder::MAX_SUPPORT+2);
}

#[test]
#[should_panic(expected="count-only builder cannot produce a constraint system or proof")]
fn count_sink_cannot_escape_as_empty_proof_relation() {DirectBuilder::new_counting().finish();}

#[test]
fn column_basis_matches_d_pinned_and_constrains_column_parity() {
    let b=DirectBuilder::new_column_basis(true);
    let mut column:[Expr;25]=std::array::from_fn(|i|b.private_input(Some(
        (0x91ad_3882_107f_51e9u64.wrapping_mul((i+1) as u64)).rotate_left(i as u32))));
    let mut reference=column.clone();b.keccak(&mut column);
    let after_column=b.counts();
    assert_eq!(after_column.private,25+600);
    assert_eq!(after_column.and,600);assert_eq!(after_column.zero,0);
    b.keccak_d_pinned(&mut reference);
    for i in 0..25 {
        assert_eq!(b.eval(&column[i]),b.eval(&reference[i]));
        b.assert_eq(&column[i],&reference[i]);
    }
    let compiled=b.finish();compiled.cs.verify(compiled.values.as_ref().unwrap()).unwrap();
    let mut values=compiled.values.unwrap();values[ValueIndex::private(25)].0^=0x8000_0000_0000_0000;
    assert!(compiled.cs.verify(&values).is_err());
}

#[test]
fn entirely_public_keccak_has_no_private_basis_words() {
    let b=DirectBuilder::new(true);
    let mut state:[Expr;25]=std::array::from_fn(|_|b.constant(0));
    b.keccak(&mut state);
    assert_eq!(b.eval(&state[0]),Some(0xf1258f7940e1dde7));
    let counts=b.counts();assert_eq!(counts.private,0);assert_eq!(counts.and,0);assert_eq!(counts.zero,0);
    let compiled=b.finish();compiled.cs.verify(compiled.values.as_ref().unwrap()).unwrap();
}

#[test]
fn bounded_wide_reduction_has_one_real_constraint_and_rejects_mutation() {
    fn relation(b:&DirectBuilder)->Option<u64> {
        let input:Vec<_>=(0..80).map(|i|b.private_input(b.is_prover().then_some(
            (0x8ba9_1703_2a88_c1e1u64.wrapping_mul((i+1) as u64)).rotate_left(i%64)))).collect();
        let wide=b.xor_many_wide_pin(&input);
        let before=b.counts();assert_eq!(before.private,81);assert_eq!(before.zero,1);
        assert_eq!(before.max_operand_support,81);
        let expected=input.iter().try_fold(0u64,|acc,e|b.eval(e).map(|v|acc^v));
        assert_eq!(b.eval(&wide),expected);
        b.assert_eq(&wide,&b.xor_many(&input));expected
    }
    let p=DirectBuilder::new(true);relation(&p);let counts=p.counts();let p=p.finish();
    let c=DirectBuilder::new_counting();relation(&c);assert_eq!(c.finish_counting(),counts);
    p.cs.verify(p.values.as_ref().unwrap()).unwrap();
    let mut values=p.values.unwrap();values[ValueIndex::private(80)].0^=1;
    assert!(p.cs.verify(&values).is_err());
}

#[test]
#[should_panic(expected="bounded wide XOR input count")]
fn wide_reduction_rejects_oversized_shape_before_allocation() {
    let b=DirectBuilder::new_counting();
    let words=vec![b.constant(0);DirectBuilder::MAX_WIDE_INPUT_TERMS+1];
    b.xor_many_wide_pin(&words);
}

#[test]
fn explicit_encoding_selection_matches_its_count_sink() {
    fn relation(b:&DirectBuilder) {
        let mut state:[Expr;25]=std::array::from_fn(|_|b.private_input(None));b.keccak(&mut state);
    }
    let ordinary=DirectBuilder::new(false);relation(&ordinary);
    let ordinary_counts=ordinary.counts();ordinary.finish();
    let counted=DirectBuilder::new_counting();relation(&counted);
    assert_eq!(ordinary_counts,counted.finish_counting());
    assert_eq!(ordinary_counts.private,25+720);
    let alternative=DirectBuilder::new_column_basis(false);relation(&alternative);
    let alternative_counts=alternative.counts();alternative.finish();
    let counted=DirectBuilder::new_counting_column_basis();relation(&counted);
    assert_eq!(alternative_counts,counted.finish_counting());
    assert_eq!(alternative_counts.private,25+600);
    assert_eq!(ordinary_counts.and,alternative_counts.and);
}
