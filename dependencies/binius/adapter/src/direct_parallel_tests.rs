//! Bounded PUBLIC differential controls. Local pools run successively, never
//! concurrently with another heavy experiment. Fixed seeds are test coins only.
use binius_compute::GlobalAllocator;
use binius_field::{Ghash128b as F,PackedField,PackedGhash1x128b as P1,
    PackedGhash2x128b as P2,PackedGhash4x128b as P4};
use binius_hash::StdHashSuite;
use binius_iop::fri::{CodewordSpec,FRIParams};
use binius_iop_prover::{fri::{encode_masked,regenerate_mask_from_seed},
    merkle_tree::{MerkleTreeProver,prover::BinaryMerkleTreeProver}};
use binius_math::{FieldBuffer,reed_solomon::ReedSolomonCode,
    ntt::{NeighborsLastMultiThread,domain_context::GaoMateerOnTheFly}};
use binius_utils::rayon::{ThreadPoolBuilder,config::{research_log_num_shares,RESEARCH_WORKER_STACK_BYTES}};
use rand::{SeedableRng,rngs::StdRng};

fn control<P:PackedField<Scalar=F>>(width:usize,log_len:usize,lift:usize)
    ->(FieldBuffer<P>,FieldBuffer<P>,Vec<u8>) {
    ThreadPoolBuilder::new().num_threads(width).stack_size(RESEARCH_WORKER_STACK_BYTES)
        .build_scoped(|thread|thread.run(),|pool|pool.install(|| {
        assert_eq!(binius_utils::rayon::current_num_threads(),width);
        let shares=research_log_num_shares(width);
        let params=FRIParams::new_batch(ReedSolomonCode::new(log_len+lift,1),
            vec![CodewordSpec{log_lift:lift,log_early_batch_size:1,log_later_batch_size:0}],vec![],1);
        let ntt=NeighborsLastMultiThread::new(GaoMateerOnTheFly::generate(log_len+lift+1),shares);
        let mut input_rng=StdRng::seed_from_u64(51);
        let message=FieldBuffer::new(log_len,(0..1usize<<log_len.saturating_sub(P::LOG_WIDTH))
            .map(|_|P::random(&mut input_rng)).collect::<Vec<_>>());
        let seed=[0x65;32];
        let encoded=encode_masked(&params,0,&ntt,message.as_view(),StdRng::from_seed(seed),&GlobalAllocator);
        let regenerated=regenerate_mask_from_seed::<P,_>(log_len,&seed,&GlobalAllocator);
        assert_eq!(encoded.mask,regenerated);
        let merkle=BinaryMerkleTreeProver::<F,StdHashSuite>::new();
        let (checkpointed,_)=merkle.commit_field_buffer_checkpointed(encoded.codeword.as_view(),1);
        let (full,_)=merkle.commit_field_buffer(encoded.codeword.as_view(),1);
        assert_eq!(checkpointed.root,full.root);assert_eq!(checkpointed.depth,full.depth);
        (encoded.mask,encoded.codeword,checkpointed.root.to_vec())
    })).unwrap()
}
fn widths<P:PackedField<Scalar=F>>() {
    for n in [0,1,2,3,6,10] {for lift in [0,2] {
        let one=control::<P>(1,n,lift);
        for width in [2,4] {
            let other=control::<P>(width,n,lift);
            assert_eq!(one.0,other.0);assert_eq!(one.1,other.1);assert_eq!(one.2,other.2);
        }
    }}
}
#[test]
fn same_seed_mask_rs_codeword_and_checkpoint_root_are_exact_for_1_2_4_workers() {
    widths::<P1>();widths::<P2>();widths::<P4>();
}
#[test]
fn only_authorized_widths_map_to_ntt_shares() {
    for (width,shares) in [(1,0),(2,1),(4,2)] {assert_eq!(research_log_num_shares(width),shares);}
    for width in [0,3,5,8,16,usize::MAX] {
        assert!(std::panic::catch_unwind(||research_log_num_shares(width)).is_err());
    }
    assert_eq!(RESEARCH_WORKER_STACK_BYTES,2*1024*1024);
}
