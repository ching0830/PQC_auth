//! Dedicated query-target128 controls. Toy P/V is not a full issuance/security result.
use binius_core::{constraint_system::{AndConstraint,ConstraintSystem,ValueIndex,ZeroConstraint},word::Word};
use binius_hash::StdHashSuite;
use binius_iop::{channel::OracleSpec,fri::{FRIParams,calculate_n_test_queries},merkle_tree::BinaryMerkleTreeScheme};
use binius_transcript::{Options,ProverTranscript,VerifierTranscript};
use binius_utils::SerializeBytes;
use binius_verifier::config::{B128,StdChallenger};
use rand::{SeedableRng,rngs::StdRng};
use serde_json::json;
use crate::target128_profile::*;

fn small_cs()->ConstraintSystem {
    ConstraintSystem{constants:vec![Word(u64::MAX)],n_inout:1,n_private:4,
        and_constraints:vec![AndConstraint::plain_abc([ValueIndex::private(0)],
            [ValueIndex::private(1)],[ValueIndex::private(2)])],
        zero_constraints:vec![ZeroConstraint::plain([ValueIndex::private(2),ValueIndex::inout(0)]),
            ZeroConstraint::plain([ValueIndex::private(3)])],imul_constraints:vec![],bmul_constraints:vec![]}
}

#[test]
fn target128_query_blinding_arity_domain_and_field_format() {
    assert_eq!(binius_verifier::SECURITY_BITS,128);
    assert_eq!(calculate_n_test_queries(128,1),309);
    assert_eq!(calculate_n_test_queries(96,1),232); // Arithmetic comparison, not a 96-bit proof test.
    let scheme=BinaryMerkleTreeScheme::<B128,StdHashSuite>::new();
    let oracles:Vec<_>=FULL_ORACLES.iter().map(|&(len,log_msg_len)|OracleSpec{len,log_msg_len,is_zk:true}).collect();
    let (params,_)=FRIParams::optimal_for_batch(&scheme,&oracles,1,FULL_QUERIES);
    assert_eq!(params.fold_arities(),[4,4,3,3]);assert_eq!(params.n_final_challenges(),10);
    assert_eq!(params.rs_code().log_len(),25);
    assert_eq!(binius_iop::fri::proof_size(&params,&scheme),FULL_FRI_BYTES);
    let mut field=Vec::new();B128::default().serialize(&mut field).unwrap();assert_eq!(field.len(),16);
    let verifier=crate::ZV::setup_research_unmerged(small_cs(),1).unwrap();
    assert_eq!(verifier.basefold_compiler().fri_params().n_test_queries(),309);
    let blinding=verifier.outer_iop_verifier().constraint_system().blinding_info();
    assert_eq!(blinding.n_dummy_wires,310);assert_eq!(blinding.n_dummy_constraints,2);
}

#[test]
fn target128_derived_full_setup_id_is_sensitive_to_query_and_blinding_metadata() {
    // Public parameter arithmetic only. The actual full cache-load separately
    // checks this identity against a freshly instantiated full verifier.
    let specs:Vec<_>=FULL_ORACLES.iter().map(|&(len,log_msg_len)|json!({"len":len,"log_msg_len":log_msg_len,"is_zk":true})).collect();
    let rounds:Vec<_>=specs.iter().map(|s|vec![s.clone()]).collect();
    let mut actual=json!({"rounds":rounds,"merged":specs,"max_log_domain_size":25,
        "security_bits":128,"log_inv_rate":1,"n_test_queries":309,"fold_arities":[4,4,3,3],
        "FRI_component_exact_format_bytes":984832,"full_proof_body_bytes":null,
        "full_proof_size_includes_unaccounted_IP_messages":true,
        "prover_memory_profile":"checkpoint4/on_the_fly/no_pool_retention/regenerated_private_masks/v0.1"});
    let compiler=crate::direct_research::digest(&[b"PQSAT/BINIUS-FULL-WORD-COMPILER/v0.1\0",
        b"693f241fdef46e2209aec1c01e48ced667f2b56594f5d9a25b6bf80978aba7ff"]);
    let derive=|record:&serde_json::Value|crate::direct_research::digest(&[
        b"PQSAT/BINIUS-UNMERGED-FULL-ZK-SETUP/v0.1\0",&compiler,&serde_json::to_vec(record).unwrap()]);
    require_setup_id(&derive(&actual)).unwrap();
    actual["security_bits"]=json!(96);assert!(require_setup_id(&derive(&actual)).is_err());
    actual["security_bits"]=json!(128);actual["n_test_queries"]=json!(232);
    assert!(require_setup_id(&derive(&actual)).is_err());
    assert!(require_setup_id(&[0;32]).is_err());assert!(require_setup_id(&[0;31]).is_err());
}

#[test]
fn target128_toy_real_prove_fresh_verify_wrong_setup_input_profile_and_proof_reject() {
    let cs=small_cs();let public=[Word(0x30)];
    let values=cs.value_vec_from_data(&public,&[Word(0xf0),Word(0x3c),Word(0x30),Word(0)]);
    cs.verify(&values).unwrap();
    let verifier=crate::ZV::setup_research_unmerged(cs,1).unwrap();
    let prover=crate::ZP::setup(&verifier).unwrap();
    assert!(prover.is_research_unmerged());
    let mut dumped=Vec::new();assert!(prover.serialize(&mut dumped).is_err());assert!(dumped.is_empty());
    let mut context=b"PQSAT/TARGET128/PUBLIC-TOY-CONTROL/v0.1\0".to_vec();context.extend_from_slice(FULL_SETUP_ID.as_bytes());
    let mut tx=ProverTranscript::with_opts(StdChallenger::default(),Options{debug_assertions:false});
    prover.prove_sig(&values,&context,&mut StdRng::seed_from_u64(0x128),&mut tx).unwrap();
    let proof=tx.finalize();drop(prover);drop(verifier);drop(values);
    let fresh=crate::ZV::setup_research_unmerged(small_cs(),1).unwrap();
    let check=|v:&crate::ZV,input:&[Word],message:&[u8],body:Vec<u8>| -> anyhow::Result<()> {
        let mut rx=VerifierTranscript::with_opts(StdChallenger::default(),body,Options{debug_assertions:false});
        v.verify_sig(input,message,&mut rx)?;rx.finalize()?;Ok(())
    };
    check(&fresh,&public,&context,proof.clone()).unwrap();
    assert!(check(&fresh,&[Word(0x31)],&context,proof.clone()).is_err());
    let mut wrong_setup=context.clone();*wrong_setup.last_mut().unwrap()^=1;
    assert!(check(&fresh,&public,&wrong_setup,proof.clone()).is_err());
    let ordinary=crate::ZV::setup(small_cs(),1).unwrap();
    assert!(check(&ordinary,&public,&context,proof.clone()).is_err());
    let mut bad=proof.clone();bad[0]^=1;assert!(check(&fresh,&public,&context,bad).is_err());
    let mut trailing=proof;trailing.push(0);assert!(check(&fresh,&public,&context,trailing).is_err());
}
