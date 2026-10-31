//! Public small-relation regression, compiled by the research native test target.
//! No issuance coverage or private CAP fixture is claimed.
use super::*;
use binius_core::constraint_system::ConstraintSystem;
use binius_utils::SerializeBytes;
    use binius_core::{constraint_system::{AndConstraint,ValueIndex,ZeroConstraint},word::Word};
    use binius_hash::StdHashSuite;
    use binius_transcript::{Options,VerifierTranscript};
    use binius_verifier::config::StdChallenger;
    use rand::{SeedableRng,rngs::StdRng};
    fn small_cs()->ConstraintSystem {
        ConstraintSystem{constants:vec![Word(u64::MAX)],n_inout:1,n_private:4,
            and_constraints:vec![AndConstraint::plain_abc([ValueIndex::private(0)],
                [ValueIndex::private(1)],[ValueIndex::private(2)])],
            zero_constraints:vec![ZeroConstraint::plain([ValueIndex::private(2),ValueIndex::inout(0)]),
                ZeroConstraint::plain([ValueIndex::private(3)])],
            imul_constraints:Vec::new(),bmul_constraints:Vec::new()}
    }
    /// Public small-relation control. Fixed test coins are NOT an issuance API.
    #[test]
    fn research_true_zk_prove_fresh_verify_bad_statement_and_profile_reject() {
        let cs=small_cs();let values=cs.value_vec_from_data(&[Word(0x30)],&[Word(0xf0),Word(0x3c),Word(0x30),Word(0)]);
        cs.verify(&values).unwrap();
        let verifier=ZKVerifier::<StdHashSuite>::setup_research_unmerged(cs.clone(),1).unwrap();
        let prover=ZKProver::<binius_prover::OptimalPackedB128,StdHashSuite>::setup(&verifier).unwrap();
        assert!(prover.is_research_unmerged());
        let mut bytes=Vec::new();assert!(prover.serialize(&mut bytes).is_err());assert!(bytes.is_empty());
        let mut transcript=ProverTranscript::with_opts(StdChallenger::default(),Options{debug_assertions:false});
        prover.prove_sig(&values,b"PUBLIC research control",&mut StdRng::seed_from_u64(7),&mut transcript).unwrap();
        let proof=transcript.finalize();drop(prover);drop(verifier);
        let fresh=ZKVerifier::<StdHashSuite>::setup_research_unmerged(small_cs(),1).unwrap();
        let mut transcript=VerifierTranscript::with_opts(StdChallenger::default(),proof.clone(),Options{debug_assertions:false});
        fresh.verify_sig(&[Word(0x30)],b"PUBLIC research control",&mut transcript).unwrap();transcript.finalize().unwrap();
        let mut bad=VerifierTranscript::with_opts(StdChallenger::default(),proof.clone(),Options{debug_assertions:false});
        assert!(fresh.verify_sig(&[Word(0x31)],b"PUBLIC research control",&mut bad).is_err());
        let ordinary=ZKVerifier::<StdHashSuite>::setup(cs,1).unwrap();
        let mut cross=VerifierTranscript::with_opts(StdChallenger::default(),proof,Options{debug_assertions:false});
        assert!(ordinary.verify_sig(&[Word(0x30)],b"PUBLIC research control",&mut cross).is_err());
    }
