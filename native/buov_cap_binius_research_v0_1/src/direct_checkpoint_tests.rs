//! Public differential controls for checkpoint Merkle storage, not security qualification.
//!
//! For N=2^25 leaves and 32-byte digests, the omitted bottom height is four:
//! full requested nodes = (2N-1)*32 = 2_147_483_616 bytes;
//! retained requested nodes = (2*(N/16)-1)*32 = 134_217_696 bytes;
//! the pool's power-of-two block is 134_217_728 bytes. No leaf hash array is retained.
//! Per-worker local components are 31 initialized + 16 MaybeUninit digest slots (1504 bytes),
//! plus hash implementation scratch. This is not a process RSS bound.
//! Retained caps borrow storage. A cap in an omitted level owns a temporary 2^cap digests;
//! it supports every depth but must be admitted from the fixed actual query schedule.

use std::sync::Mutex;
use binius_compute::{Allocator, BufferPool, GlobalAllocator};
use binius_core::word::Word;
use binius_field::{Field, Ghash128b as F, PackedField, PackedGhash2x128b, PackedGhash4x128b};
use binius_hash::Sha256HashSuite as H;
use binius_iop::{merkle_channel::{MerkleIPVerifierChannel, VerifierMerkleTranscriptChannel}, merkle_tree::MerkleTreeScheme};
use binius_iop_prover::{merkle_channel::{MerkleIPProverChannel, ProverMerkleTranscriptChannel},
    merkle_tree::{MerkleTreeProver, prover::{BinaryMerkleTreeProver, CHECKPOINT_LOG_DEPTH}}};
use binius_math::FieldBuffer;
use binius_transcript::{ProverTranscript, VerifierTranscript};
use binius_verifier::config::StdChallenger;

fn data<P: PackedField<Scalar=F>>(log_len:usize)->FieldBuffer<P> {
    FieldBuffer::from_values(&(0..1usize<<log_len).map(|i| F::new((i as u128 + 13)*0x183ad53)).collect::<Vec<_>>())
}

fn all_layers_and_branches<P: PackedField<Scalar=F>>() {
    let prover=BinaryMerkleTreeProver::<F,H>::new();
    for log_len in 0..=8 {
        let data=data::<P>(log_len);
        for log_leaf in 0..=log_len.min(3) {
            let depth=log_len-log_leaf;
            let (full_c,full)=prover.commit_field_buffer(data.as_view(),log_leaf);
            let (new_c,new)=prover.commit_field_buffer_checkpointed(data.as_view(),log_leaf);
            assert_eq!(new_c.root,full_c.root);assert_eq!(new_c.depth,depth);
            assert_eq!(new.root(),full.root());assert_eq!(new.log_len(),depth);
            assert_eq!(new.is_checkpointed(),depth>=CHECKPOINT_LOG_DEPTH);
            let retained_depth=depth.saturating_sub(CHECKPOINT_LOG_DEPTH);
            let expected=if new.is_checkpointed(){(2usize<<retained_depth)-1}else{(2usize<<depth)-1};
            assert_eq!(new.stored_nodes(),expected);
            for cap in 0..=depth {
                let layer=prover.layer_from_data(&new,data.as_view(),log_leaf,cap).unwrap();
                assert_eq!(layer.as_ref(),full.layer(cap).unwrap());
                prover.scheme().verify_layer(&new_c.root,cap,layer.as_ref()).unwrap();
                if !new.is_checkpointed() || cap<=retained_depth {assert!(matches!(layer,std::borrow::Cow::Borrowed(_)));}
                for index in 0..1usize<<depth {
                    let branch=prover.branch_from_data(&new,data.as_view(),log_leaf,cap,index).unwrap();
                    assert_eq!(branch,full.branch(index,cap).unwrap(),"shape={log_len}/{log_leaf} cap={cap} index={index}");
                }
            }
            assert!(prover.layer_from_data(&new,data.as_view(),log_leaf,depth+1).is_err());
            assert!(prover.branch_from_data(&new,data.as_view(),log_leaf,0,1usize<<depth).is_err());
            assert!(prover.branch_from_data(&new,data.as_view(),log_leaf,depth+1,0).is_err());
        }
    }
}

#[test]
fn checkpoint_merkle_matches_every_layer_branch_and_packing() {
    all_layers_and_branches::<PackedGhash2x128b>();
    all_layers_and_branches::<PackedGhash4x128b>();
}

fn transcript(checkpointed:bool,n_queries:usize)->(Vec<u8>,Vec<Word>) {
    let data=data::<PackedGhash4x128b>(9);
    let transcript=ProverTranscript::new(StdChallenger::default());
    let prover=BinaryMerkleTreeProver::<F,H>::new();
    let mut channel:ProverMerkleTranscriptChannel<_,StdChallenger,F,H>=if checkpointed {
        ProverMerkleTranscriptChannel::with_merkle_prover(transcript,prover)
    }else{ProverMerkleTranscriptChannel::with_full_merkle_prover(transcript,prover)};
    let commitment=channel.send_merkle_commitment(data.as_view(),2);
    let indices=(0..n_queries).map(|i|Word(((17*i+3)%256)as u64)).collect::<Vec<_>>();
    channel.send_openings(&commitment,data.as_view(),&indices);
    (channel.into_transcript().finalize(),indices)
}

fn verify(bytes:Vec<u8>,indices:&[Word])->bool {
    let transcript=VerifierTranscript::new(StdChallenger::default(),bytes);
    let mut channel:VerifierMerkleTranscriptChannel<_,StdChallenger,F,H>=VerifierMerkleTranscriptChannel::new(transcript);
    let commitment=match channel.recv_merkle_commitment(2,8){Ok(c)=>c,Err(_)=>return false};
    if channel.recv_openings(&commitment,indices).is_err(){return false;}
    channel.into_transcript().finalize().is_ok()
}

#[test]
fn checkpoint_merkle_transcript_and_verify_match_full_for_caps_and_queries() {
    for queries in [0,1,2,3,5,17,33,129,257] {
        let(old,old_indices)=transcript(false,queries);
        let(new,new_indices)=transcript(true,queries);
        assert_eq!(new_indices,old_indices);assert_eq!(new,old);
        assert!(verify(new,&new_indices));
    }
}

#[test]
fn checkpoint_merkle_rejects_changed_codeword_and_proof() {
    let mut data=data::<PackedGhash2x128b>(9);
    let prover=BinaryMerkleTreeProver::<F,H>::new();
    let(_,tree)=prover.commit_field_buffer_checkpointed(data.as_view(),1);
    data.set(0,data.get(0)+F::ONE);
    assert!(prover.branch_from_data(&tree,data.as_view(),1,0,0).is_err());
    assert!(prover.branch_from_data(&tree,data.as_view(),1,8,0).is_err());
    assert!(prover.layer_from_data(&tree,data.as_view(),1,8).is_err());
    // A different query outside this changed subtree remains openable, exactly as normal Merkle
    // soundness requires; a full-vector claim would bind the whole codeword separately.
    assert!(prover.branch_from_data(&tree,data.as_view(),1,0,32).is_ok());
    let(mut proof,indices)=transcript(true,5);
    assert!(verify(proof.clone(),&indices));
    *proof.last_mut().unwrap()^=1;
    assert!(!verify(proof,&indices));
    let(proof,mut wrong)=transcript(true,5);wrong[0]=Word(0);
    assert!(!verify(proof,&wrong));
}

#[derive(Clone,Copy)]
struct CountAlloc<'a>(&'a Mutex<Vec<usize>>);
impl Allocator for CountAlloc<'_> {
    type Vec<T:Send>=Vec<T>;
    fn alloc<T:Send>(&self,capacity:usize)->Vec<T> {
        self.0.lock().unwrap().push(capacity*std::mem::size_of::<T>());
        Vec::with_capacity(capacity)
    }
}

#[test]
fn checkpoint_merkle_allocates_only_the_final_retained_tree_and_pool_agrees() {
    let data=data::<PackedGhash4x128b>(13);
    let events=Mutex::new(Vec::new());
    let prover=BinaryMerkleTreeProver::<F,H,_>::with_allocator(CountAlloc(&events));
    let(reference,tree)=prover.commit_field_buffer_checkpointed(data.as_view(),1);
    let depth=12;
    let requested=((2usize<<(depth-CHECKPOINT_LOG_DEPTH))-1)*32;
    assert_eq!(*events.lock().unwrap(),[requested]);
    assert_eq!(tree.stored_nodes()*32,requested);
    let pool=BufferPool::new();
    let pooled=BinaryMerkleTreeProver::<F,H,_>::with_allocator(&pool);
    let(commitment,tree)=pooled.commit_field_buffer_checkpointed(data.as_view(),1);
    assert_eq!(commitment.root,reference.root);
    assert!(tree.stored_capacity()>=tree.stored_nodes());
    assert!(tree.stored_capacity()*32 < ((2usize<<depth)-1)*32);
    let branch=pooled.branch_from_data(&tree,data.as_view(),1,3,13).unwrap();
    let global=BinaryMerkleTreeProver::<F,H,_>::with_allocator(GlobalAllocator);
    let(_,full)=global.commit_field_buffer(data.as_view(),1);
    assert_eq!(branch,full.branch(13,3).unwrap());
}
