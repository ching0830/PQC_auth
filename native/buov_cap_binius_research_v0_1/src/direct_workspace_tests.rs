//! Storage/encoding equivalence controls for the selected research fork.
use std::sync::atomic::{AtomicUsize,Ordering};
use binius_compute::{Allocator,GlobalAllocator};
use binius_core::constraint_system::{Operand,StoredOperand,TemplateInterner,ShiftedValueIndex as T,ValueIndex as I,Shift};
use binius_field::{Random,PackedField,Ghash128b as F,PackedGhash1x128b as P1,PackedGhash2x128b as P2,PackedGhash4x128b as P4};
use binius_iop::fri::{FRIParams,CodewordSpec};
use binius_iop_prover::fri::{encode_masked,encode_masked_legacy};
use binius_math::{FieldBuffer,reed_solomon::ReedSolomonCode,ntt::{NeighborsLastSingleThread,domain_context::GaoMateerOnTheFly}};
use binius_utils::{SerializeBytes,DeserializeBytes};
use rand::{SeedableRng,Rng,rngs::StdRng};

#[test]
fn public_template_census_roundtrips_all_terms_and_caps_growth() {
    let terms=|base|vec![T::plain(I::constant(2)),T::rotr(I::private(base),7),
        T::new(I::private(base-3),[Shift::srl(3),Shift::sll(3)]),T::plain(I::inout(1)),T::plain(I::private(base))];
    let mut pool=TemplateInterner::new(1,4096);
    let a=pool.intern(terms(10)).unwrap();let b=pool.intern(terms(910)).unwrap();
    assert!(a.shares_template_with(&b));assert_eq!(b.iter().collect::<Operand>(),terms(910));
    assert_eq!(std::mem::size_of::<StoredOperand>(),16);
    let mut old=Vec::new();terms(910).serialize(&mut old).unwrap();
    let mut new=Vec::new();b.serialize(&mut new).unwrap();assert_eq!(old,new);
    assert_eq!(StoredOperand::deserialize(new.as_slice()).unwrap(),b);
    assert!(pool.intern(vec![T::plain(I::constant(3))]).is_err());
    assert_eq!(pool.metrics().unique_templates,1);
    let mut retained=b.clone();retained.retain(|t|t.value_index!=I::private(910));
    assert_eq!(retained.iter().collect::<Operand>(),terms(910).into_iter().filter(|t|t.value_index!=I::private(910)).collect::<Operand>());
    assert_eq!(b.iter().collect::<Operand>(),terms(910));
}

#[derive(Clone,Copy)]
struct CountAlloc<'a>(&'a AtomicUsize);
impl Allocator for CountAlloc<'_> {
    type Vec<T:Send>=Vec<T>;
    fn alloc<T:Send>(&self,capacity:usize)->Vec<T> {self.0.fetch_add(1,Ordering::Relaxed);Vec::with_capacity(capacity)}
}
fn check<P:PackedField<Scalar=F>+std::panic::RefUnwindSafe>(log_len:usize,rate:usize,lift:usize) {
    let params=FRIParams::new_batch(ReedSolomonCode::new(log_len+lift,rate),
        vec![CodewordSpec{log_lift:lift,log_early_batch_size:1,log_later_batch_size:0}],vec![],1);
    let ntt=NeighborsLastSingleThread::new(GaoMateerOnTheFly::generate((log_len+lift+rate).max(1)));
    let mut input_rng=StdRng::seed_from_u64(441);
    let message=FieldBuffer::new(log_len,(0..1usize<<log_len.saturating_sub(P::LOG_WIDTH)).map(|_|P::random(&mut input_rng)).collect::<Vec<_>>());
    let saved=message.clone();let mut old_rng=StdRng::seed_from_u64(442);let mut new_rng=StdRng::seed_from_u64(442);
    let old_n=AtomicUsize::new(0);let new_n=AtomicUsize::new(0);
    if log_len+rate==0 {
        assert!(std::panic::catch_unwind(||encode_masked_legacy(&params,0,&ntt,message.as_view(),StdRng::seed_from_u64(442),&GlobalAllocator)).is_err());
        assert!(std::panic::catch_unwind(||encode_masked(&params,0,&ntt,message.as_view(),StdRng::seed_from_u64(442),&GlobalAllocator)).is_err());return;
    }
    let old=encode_masked_legacy(&params,0,&ntt,message.as_view(),&mut old_rng,&CountAlloc(&old_n));
    let new=encode_masked(&params,0,&ntt,message.as_view(),&mut new_rng,&CountAlloc(&new_n));
    assert_eq!(new.mask,old.mask);assert_eq!(new.codeword,old.codeword);assert_eq!(message,saved);
    assert_eq!(old_n.load(Ordering::Relaxed),3);assert_eq!(new_n.load(Ordering::Relaxed),2);
    let(mut x,mut y)=([0;64],[0;64]);old_rng.fill_bytes(&mut x);new_rng.fill_bytes(&mut y);assert_eq!(x,y);
}
#[test]
fn packed_mask_codeword_and_rng_equal_legacy_without_concat_allocation() {
    for n in [0,1,2,3,6] {for rate in [0,1,2] {for lift in [0,2] {
        check::<P1>(n,rate,lift);check::<P2>(n,rate,lift);check::<P4>(n,rate,lift);
    }}}
}
#[test]
fn owned_rs_transform_reuses_final_allocation() {
    for n in [0,1,3,6] {for batch in [0,1,2] {for rate in [0,1,2] {
        if n+rate==0 {continue;} // Both original encoders reject zero-dimensional domains.
        let rs=ReedSolomonCode::<F>::new(n,rate);
        let ntt=NeighborsLastSingleThread::new(GaoMateerOnTheFly::generate((n+rate).max(1)));
        let mut rng=StdRng::seed_from_u64(333);
        let input=FieldBuffer::new(n+batch,(0..1usize<<(n+batch).saturating_sub(P4::LOG_WIDTH)).map(|_|P4::random(&mut rng)).collect::<Vec<_>>());
        let expected=rs.encode_batch(&ntt,input.as_view(),batch,&GlobalAllocator);
        let workspace=FieldBuffer::from_view_with_capacity_in(&GlobalAllocator,input.as_view(),n+batch+rate);
        let ptr=workspace.as_ref().as_ptr();let actual=rs.encode_batch_inplace(&ntt,workspace,batch);
        assert_eq!(ptr,actual.as_ref().as_ptr());assert_eq!(actual,expected);
    }}}
}
#[test]
fn masked_shape_and_owned_capacity_fail_closed() {
    let params=FRIParams::new_batch(ReedSolomonCode::new(3,1),
        vec![CodewordSpec{log_lift:0,log_early_batch_size:0,log_later_batch_size:0}],vec![],1);
    let ntt=NeighborsLastSingleThread::new(GaoMateerOnTheFly::generate(4));
    let message=FieldBuffer::<P1>::zeros(3);
    for index in [0,1] {assert!(std::panic::catch_unwind(||encode_masked(&params,index,&ntt,message.as_view(),StdRng::seed_from_u64(1),&GlobalAllocator)).is_err());}
    assert!(std::panic::catch_unwind(||ReedSolomonCode::<F>::new(3,1).encode_batch_inplace(&ntt,message.clone(),0)).is_err());
}

#[test]
fn two_private_clusters_share_across_different_gaps_without_aliasing() {
    let terms=|a,b|vec![T::plain(I::constant(2)),T::plain(I::private(a)),
        T::rotr(I::private(b),7),T::new(I::private(b+4),[Shift::srl(3),Shift::sll(3)]),T::plain(I::inout(1))];
    let mut pool=TemplateInterner::new(8,4096);
    let x=pool.intern(terms(10,10000)).unwrap();let y=pool.intern(terms(110,1000000)).unwrap();
    assert!(x.shares_template_with(&y));assert_eq!(y.iter().collect::<Operand>(),terms(110,1000000));
    let mut a=Vec::new();terms(110,1000000).serialize(&mut a).unwrap();let mut b=Vec::new();y.serialize(&mut b).unwrap();assert_eq!(a,b);
    let edge=vec![T::plain(I::private((1<<26)-1)),T::plain(I::private(0)),T::plain(I::private((1<<26)-5))];
    assert_eq!(pool.intern(edge.clone()).unwrap().iter().collect::<Operand>(),edge);
    let invalid=vec![T::plain(I::private(1<<26))];assert!(pool.intern(invalid.clone()).is_err());
    let mut bytes=Vec::new();invalid.serialize(&mut bytes).unwrap();assert!(StoredOperand::deserialize(bytes.as_slice()).is_err());
}

#[test]
fn non_recycling_pool_releases_dropped_blocks_and_preserves_alignment() {
    use binius_compute::BufferPool;
    let retained=BufferPool::new();let released=BufferPool::non_recycling();
    assert!(retained.is_recycling());assert!(!released.is_recycling());
    for pool in [&retained,&released] {let mut values=pool.alloc_vec::<u64>(17);
        assert_eq!(values.capacity(),32);assert_eq!(values.as_ptr()as usize%64,0);
        values.extend_from_slice(&[1,2,3]);assert_eq!(&*values,&[1,2,3]);}
    assert_eq!(retained.retained_bytes(),256);assert_eq!(released.retained_bytes(),0);
}

#[test]
fn bounded_research_ntt_matches_preexpanded_domain_and_codewords() {
    use binius_prover::research_domain::ProverDomain;
    use binius_math::ntt::DomainContext;
    for n in 1..=12 {
        let old=ProverDomain::<F>::generate(n,false);let new=ProverDomain::<F>::generate(n,true);
        for l in 0..n {assert_eq!(old.subspace(l).basis(),new.subspace(l).basis());
            for b in 0..1<<l {assert_eq!(old.twiddle(l,b),new.twiddle(l,b));}
            for step in 0..=l {assert_eq!(old.iter_twiddles(l,step).collect::<Vec<_>>(),new.iter_twiddles(l,step).collect::<Vec<_>>());}}
        if n<2 {continue;}
        let old=NeighborsLastSingleThread::new(old);let new=NeighborsLastSingleThread::new(new);
        let rs=ReedSolomonCode::<F>::new(n-1,1);
        let mut rng=StdRng::seed_from_u64(918);
        let input=FieldBuffer::<P4>::new(n,(0..1usize<<n.saturating_sub(P4::LOG_WIDTH)).map(|_|P4::random(&mut rng)).collect::<Vec<_>>());
        assert_eq!(rs.encode_batch(&old,input.as_view(),1,&GlobalAllocator),rs.encode_batch(&new,input.as_view(),1,&GlobalAllocator));
    }
}
