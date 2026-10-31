"""Full oracle validation/transcript flow; only the q batch is native.

Historical prover source remains byte-identical. This deliberately preserves
state identity, ordinary relation replay, every correction, nonce enumeration,
frontier, leaf commitment and canonical output check. Research-only.
"""
from __future__ import annotations
from .kernel import NativeCAPProver
from pq_rbbc.blind_uov_hplus_research_v0_1.prover import (
    ProverState, ProverError, _require_bytes, _validate_state, _plain_witness_bytes,
    _CTX_BYTES, _R_BYTES, _PROFILE, find_first_admissible_nonce,
)
from pq_rbbc.blind_uov_hplus_research_v0_1.codec import CR, CZ, Pi2, encode_c_r, encode_c_z, encode_pi_2
from pq_rbbc.blind_uov_hplus_research_v0_1.relation import CAPStatement, CAPWitness, apply_delta_z, relation_holds
from pq_rbbc.blind_uov_hplus_research_v0_1.transcript import derive_h2, derive_gammas, derive_h3
from pq_rbbc.blind_uov_hplus_research_v0_1.response import encode_h3_q_and_qbar, encode_tcith_responses
from pq_rbbc.blind_uov_hplus_research_v0_1.tree import open_frontier, leaf_commitment
from pq_rbbc.blind_uov_hplus_research_v0_1.uov import M

def prove(
    ctx: bytes,
    u: bytes,
    c_r: CR,
    c_z: CZ,
    state: ProverState,
    *,
    kernel: NativeCAPProver,
    threads: int = 1,
) -> Pi2:
    """Produce one deterministic, canonical, unpadded real CAP ``pi_2``."""

    checked_ctx = _require_bytes(ctx, _CTX_BYTES, "ctx")
    checked_u = _require_bytes(u, M, "u")
    if type(c_r) is not CR:
        raise TypeError("c_r must be exactly CR")
    if type(c_z) is not CZ:
        raise TypeError("c_z must be exactly CZ")
    try:
        encode_c_r(c_r)
        encode_c_z(c_z)
    except (TypeError, ValueError) as error:
        raise ProverError("invalid c_r or c_z") from error
    checked_state = _validate_state(state)
    if checked_ctx != checked_state.ctx:
        raise ProverError("ctx does not match the prover state")
    if c_r != checked_state.c_r:
        raise ProverError("c_r does not match the prover state")

    updated_repetitions = tuple(
        apply_delta_z(repetition, c_z.delta_z)
        for repetition in checked_state.corrected_repetitions
    )
    committed_random_witness = _plain_witness_bytes(
        checked_state.corrected_repetitions[0]
    )
    derived_r = committed_random_witness[:_R_BYTES]
    random_z = committed_random_witness[_R_BYTES:]
    z = bytes(
        left ^ right
        for left, right in zip(random_z, c_z.delta_z, strict=True)
    )
    if derived_r != checked_state.r:
        raise ProverError("reconstructed r does not match the prover state")
    statement = CAPStatement(checked_state.public_map, checked_ctx, checked_u)
    witness = CAPWitness(checked_state.r, z)
    if not relation_holds(statement, witness):
        raise ProverError("reconstructed CAP witness does not satisfy the relation")

    h2 = derive_h2(checked_ctx, checked_u, c_r.h2_prime, c_z.delta_z)
    gammas_0 = derive_gammas(h2, 0)
    gammas_1 = derive_gammas(h2, 1)
    q_results = kernel.q_batch(
        statement, updated_repetitions, (gammas_0, gammas_1), threads=threads,
    )
    q_groups = (
        tuple(element for result in q_results[:2] for element in result.q),
        tuple(element for result in q_results[2:] for element in result.q),
    )
    qbar_groups = (
        tuple(element for result in q_results[:2] for element in result.qbar),
        tuple(element for result in q_results[2:] for element in result.qbar),
    )
    q_and_qbar = encode_h3_q_and_qbar(q_groups, qbar_groups)
    h3 = derive_h3(checked_ctx, checked_u, h2, q_and_qbar)
    nonce, hidden_positions, frontier_indices = find_first_admissible_nonce(h3)
    opening = open_frontier(checked_state.tree_state, hidden_positions)
    if len(opening.seeds) != len(frontier_indices):
        raise AssertionError("unreachable frontier-opening mismatch")
    hidden_commitments = tuple(
        leaf_commitment(
            repetition,
            position,
            checked_state.tree_state.leaf_seed(repetition, position),
            checked_state.tree_state.salt,
        )
        for repetition, position in enumerate(hidden_positions)
    )
    tcith_responses = encode_tcith_responses(qbar_groups)
    pi_2 = Pi2(
        h3=h3,
        pow_nonce=nonce,
        opening=opening,
        hidden_leaf_commitments=hidden_commitments,
        tcith_responses=tcith_responses,
    )
    encode_pi_2(pi_2)
    return pi_2
