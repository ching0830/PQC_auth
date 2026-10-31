//! Differential controls for the research fork, not security qualification.
use std::sync::Arc;
use binius_core::{constraint_system::{AndConstraint,ZeroConstraint,ConstraintSystem,InoutSegment,Shift,
    ShiftedValueIndex,ValueIndex},word::Word};
use binius_field::{Field,Ghash128b as F,PackedGhash2x128b as P};
use binius_math::multilinear::sparse::{SparseBitVector,evaluate_sparse_b1_multilinear_native,
    evaluate_sparse_b1_multilinear_streaming,evaluate_sparse_b1_multilinear_streaming_native};
use binius_prover::protocols::shift::{KeyCollection,PreparedOperandClaims,SegmentWords,ShiftChallenge};
use binius_compute::GlobalAllocator;
use binius_utils::SerializeBytes;

fn f(i:usize)->F{F::new(0xacf3a59b20451337u128.wrapping_mul(i as u128+1))}
fn naive(point:&[F],indices:&[u128])->F{
    indices.iter().map(|&i|point.iter().enumerate().map(|(k,x)|if i>>k&1==1{*x}else{F::ONE+*x}).product::<F>()).sum()
}
#[test]
fn wide_streaming_is_same_polynomial_and_preserves_high_coordinates(){
    for n in [7,63,64,71,127]{
        let point:Vec<_>=(0..n).map(f).collect();
        let terms=[0,7,1u128<<(n-1),(1u128<<(n-1))|3,11,11];
        let expected=naive(&point,&terms);
        assert_eq!(evaluate_sparse_b1_multilinear_streaming(&point,terms.len(),terms),expected);
        assert_eq!(evaluate_sparse_b1_multilinear_streaming_native(&point,terms.len(),terms),expected);
        if n<64{
            let old=SparseBitVector::new(n,terms.iter().map(|&i|i as u64).collect());
            assert_eq!(evaluate_sparse_b1_multilinear_native(&old,&point),expected);
        }
    }
    let mut point=vec![F::ZERO;71];point[64]=F::ONE;
    assert_eq!(evaluate_sparse_b1_multilinear_streaming_native(&point,1,[1u128<<64]),F::ONE);
    assert_eq!(evaluate_sparse_b1_multilinear_streaming_native(&point,1,[0]),F::ZERO);
    assert_eq!(evaluate_sparse_b1_multilinear_streaming_native(&point,2,[1u128<<64;2]),F::ZERO);
    assert!(std::panic::catch_unwind(||evaluate_sparse_b1_multilinear_streaming_native(&vec![F::ZERO;128],0,[])).is_err());
    assert!(std::panic::catch_unwind(||evaluate_sparse_b1_multilinear_streaming_native(&vec![F::ZERO;64],1,[1u128<<64])).is_err());
}
fn system()->ConstraintSystem{
    let a=ShiftedValueIndex::plain(ValueIndex::private(0));
    let c=ShiftedValueIndex::new(ValueIndex::private(1),[Shift::sar(7),Shift::rotr(11)]);
    let input=ShiftedValueIndex::sll(ValueIndex::inout(1),3);
    ConstraintSystem{constants:vec![Word(0),Word(0x8765432101234567)],n_inout:3,n_private:5,
        zero_constraints:vec![ZeroConstraint([vec![a,c,c,input].into()]),ZeroConstraint([vec![].into()])],
        and_constraints:vec![AndConstraint([vec![a,input].into(),vec![c].into(),vec![a].into()])],imul_constraints:vec![],bmul_constraints:vec![]}
}
#[test]
fn streamed_keys_match_indexed_g_and_monster_both_segment_layouts(){
    for inout in [InoutSegment::Public,InoutSegment::Hidden]{
        let cs=Arc::new(system());let old=KeyCollection::build(&cs,inout);let new=KeyCollection::from_shared(Arc::clone(&cs),inout);
        assert!(new.is_streaming());assert_eq!(new.public.keys.len()+new.hidden.keys.len(),0);
        assert_eq!(new.public.key_ranges.len()+new.hidden.key_ranges.len(),0);
        assert_eq!(new.public.constraint_indices.len()+new.hidden.constraint_indices.len(),0);
        let prepared=PreparedOperandClaims{batched_eval:F::ONE,r_zhat_prime:F::ONE,
            r_x_tensor:(0..1<<binius_verifier::reduction::log_constraint_point(&cs)).map(f).collect(),
            operand_weights:(0..16).map(|i|f(i+31)).collect()};
        let public=vec![Word(0x1234fe500032abba);cs.n_public_words(inout)];let hidden=vec![Word(0xf10002347891cabc);cs.n_hidden_words(inout)];
        let words=||SegmentWords{public:&public,hidden:&hidden};
        assert_eq!(old.build_g::<_,P>(words(),&prepared),new.build_g::<_,P>(words(),&prepared));
        let challenge=|at|ShiftChallenge::new((at+3..at+9).map(f).collect(),(at..at+3).map(f).collect());
        let(inner,outer)=(challenge(83),challenge(101));
        let x=old.build_monster_segments::<_,P,_>(&GlobalAllocator,&prepared,f(131),&inner,&outer);
        let y=new.build_monster_segments::<_,P,_>(&GlobalAllocator,&prepared,f(131),&inner,&outer);
        assert_eq!(x.0.as_ref(),y.0.as_ref());assert_eq!(x.1.as_ref(),y.1.as_ref());
        let mut bytes=Vec::new();assert!(new.serialize(&mut bytes).is_err());assert!(bytes.is_empty());
    }
}
#[test]
fn zk_prover_shares_core_source_and_serialization_fails_before_output(){
    let b=crate::direct_core::DirectBuilder::new(false);
    let a=b.private_input(None);let out=b.public_input(0);b.assert_eq(&b.and(&a,&a),&out);
    let verifier=crate::ZV::setup(b.finish().cs,1).unwrap();let prover=crate::ZP::setup(&verifier).unwrap();
    assert!(Arc::ptr_eq(&verifier.inner_iop_verifier().constraint_system_arc(),&prover.inner_iop_prover().constraint_system_arc()));
    assert!(prover.key_collection().is_streaming());
    let mut bytes=Vec::new();assert!(prover.serialize(&mut bytes).is_err());assert!(bytes.is_empty());
}
