//! Explicit query-target128 admission; this is not complete security qualification.
use anyhow::{ensure,Result};
use serde_json::Value;

pub(crate) const FULL_PROOF_BYTES:usize=995632;
pub(crate) const FULL_SETUP_ID:&str="6e64167b50e9fcd8a9d82add92fcbc121eac0d3521a8699402541947a0bb168c";
pub(crate) const FULL_QUERIES:usize=309;
pub(crate) const FULL_FRI_BYTES:usize=984832;
pub(crate) const FULL_ORACLES:[(usize,usize);4]=[(863,10),(9932038,24),(98715,17),(512,9)];

pub(crate) fn require_setup_id(id:&[u8])->Result<()> {
    ensure!(id.len()==32 && crate::hex(id)==FULL_SETUP_ID,"explicit target128 setup identity");Ok(())
}

pub(crate) fn require_full_setup(verifier:&crate::ZV,actual:&Value,id:&[u8])->Result<()> {
    ensure!(binius_verifier::SECURITY_BITS==128 && verifier.is_research_unmerged(),
        "explicit target128 research backend");
    ensure!(verifier.log_inv_rate()==1 && verifier.basefold_compiler().max_log_domain_size()==25,
        "target128 unchanged rate/domain admission");
    let params=verifier.basefold_compiler().fri_params();
    ensure!(params.n_test_queries()==FULL_QUERIES && params.fold_arities()==[4,4,3,3],
        "target128 rebuilt query/arity parameters");
    let specs=verifier.oracle_schedule().merged_specs();
    ensure!(specs.len()==FULL_ORACLES.len() && specs.iter().zip(FULL_ORACLES).all(|(s,(len,log))|
        s.len==len && s.log_msg_len==log && s.is_zk),"target128 naturally rebuilt oracle shapes");
    ensure!(actual["security_bits"].as_u64()==Some(128)
        && actual["FRI_component_exact_format_bytes"].as_u64()==Some(FULL_FRI_BYTES as u64),
        "target128 actual public parameter record");
    let blinding=verifier.outer_iop_verifier().constraint_system().blinding_info();
    ensure!(blinding.n_dummy_wires==310 && blinding.n_dummy_constraints==2,
        "target128 query-dependent blinding");
    require_setup_id(id)
}
