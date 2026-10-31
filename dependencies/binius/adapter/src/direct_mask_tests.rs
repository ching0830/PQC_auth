//! Public sampler regression only. Seeds below are frozen test coins, never
//! a real issuance API. The existing research profile fresh-P/V test must also
//! be rerun: its ZKProver now automatically selects mask regeneration.
use binius_compute::GlobalAllocator;
use binius_field::{Ghash128b as F,PackedField,PackedGhash1x128b as P1,
    PackedGhash2x128b as P2,PackedGhash4x128b as P4};
use binius_iop::fri::{CodewordSpec,FRIParams};
use binius_iop_prover::fri::{encode_masked,regenerate_mask_from_seed};
use binius_math::{FieldBuffer,reed_solomon::ReedSolomonCode,
    ntt::{NeighborsLastSingleThread,domain_context::GaoMateerOnTheFly}};
use rand::{SeedableRng,rngs::StdRng};

fn compare<P:PackedField<Scalar=F>>(log_len:usize,lift:usize) {
    let params=FRIParams::new_batch(ReedSolomonCode::new(log_len+lift,1),
        vec![CodewordSpec{log_lift:lift,log_early_batch_size:1,log_later_batch_size:0}],vec![],1);
    let ntt=NeighborsLastSingleThread::new(GaoMateerOnTheFly::generate(log_len+lift+1));
    let message=FieldBuffer::<P>::zeros(log_len);
    let seed=[0x63;32];
    let encoded=encode_masked(&params,0,&ntt,message.as_view(),StdRng::from_seed(seed),&GlobalAllocator);
    let rebuilt=regenerate_mask_from_seed::<P,_>(log_len,&seed,&GlobalAllocator);
    assert_eq!(encoded.mask,rebuilt);
    // Compare all packed bytes, including unused lanes when the live scalar
    // length is less than the packed width. Encoding handles those separately.
    assert_eq!(encoded.mask.as_ref(),rebuilt.as_ref());
    let again=regenerate_mask_from_seed::<P,_>(log_len,&seed,&GlobalAllocator);
    assert_eq!(rebuilt,again);
    let other=regenerate_mask_from_seed::<P,_>(log_len,&[0x64;32],&GlobalAllocator);
    assert_ne!(rebuilt,other);
}
#[test]
fn seed_helper_matches_original_sampler_for_each_packed_width_and_partial_word() {
    for n in [0,1,2,3,6] {for lift in [0,2] {
        compare::<P1>(n,lift);compare::<P2>(n,lift);compare::<P4>(n,lift);
    }}
}
#[test]
#[should_panic(expected="bounded regenerated-mask scalar dimension")]
fn regeneration_rejects_overflowing_shape_before_allocation() {
    let _=regenerate_mask_from_seed::<P1,_>(usize::BITS as usize,&[0;32],&GlobalAllocator);
}
