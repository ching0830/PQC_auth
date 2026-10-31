"""UE-only witness preparation for a partial ``pi_iss_research`` relation.

``make_private`` runs one actual CAP.Init and joins its immutable state to the
LC14 ports and the full-message binding.  It returns private bytes in memory;
callers must pipe them only to the UE prover, never to the NCC or a log/file.
Honest host preparation of content does not prove F1--F4 or the omitted CAP
rules.  This module has no production entry point or success adapter.
"""

from pq_rbbc.blind_uov_pqsat_v0_1.codec import encode_c_r
from pq_rbbc.blind_uov_pqsat_v0_1.parameters import FieldId
from pq_rbbc.blind_uov_pqsat_v0_1.prover import (
    ProverRandomness,
    ProverState,
    _validate_state,
    cap_init,
)
from pq_rbbc.blind_uov_pqsat_v0_1.tree import derive_leaf_tape
from pq_rbbc.blind_uov_pqsat_v0_1.uov import UOVPublicMap
from pq_sat_auth.v3.authentication import holder_public_key_binding
from pq_sat_auth.v3.final_ticket.trace_mceliece6688128_research_v0_1 import (
    TracePublicKeyV0_1,
    derive_trace_ciphertext,
)

from ..legacy_cap_implicit_rows_relation_v0_1 import contract as lc14_contract
from ..legacy_cap_implicit_rows_relation_v0_1 import graph as lc14
from ..legacy_cap_prefix_relations_v0_1.contract import full_message_u


SELECTED_REPETITION = 2
SELECTED_PARTIES = 2048
SELECTED_POSITIONS = tuple(range(24)) + tuple(range(2047, 2067))
PRIVATE_BYTES = lc14_contract.PRIVATE_BYTES + 388 + 72
_SCOPE_HEADER = b"LCAPSCP1\x00\x01"


def _bytes(value: object, width: int, name: str) -> bytes:
    if type(value) is not bytes or len(value) != width:
        raise ValueError(name + " width/type")
    return value


def _scope_ctx(scope: bytes) -> bytes:
    _bytes(scope, 276, "ScopeEnc")
    if scope[:10] != _SCOPE_HEADER:
        raise ValueError("ScopeEnc version")
    if scope[108:140] != lc14_contract.FINGERPRINT:
        raise ValueError("ScopeEnc CAP profile")
    return scope[12:44]


def honest_message(
    *,
    ctx: bytes,
    sn: bytes,
    canonical_pk_H: bytes,
    rid: bytes,
    trace_public_key: TracePublicKeyV0_1,
    trace_error: bytes,
) -> bytes:
    """Prepare actual M bytes on the UE; this is not a proof of content rules.

    No holder KeyGen-image condition is added: the caller supplies the
    syntax-canonical 1,952-byte ML-DSA-65 public key required by the research
    relation.  The existing trace evaluator checks the integer weight 128.
    """
    _bytes(ctx, 32, "ctx")
    _bytes(sn, 16, "SN")
    _bytes(canonical_pk_H, 1952, "canonical_pk_H")
    _bytes(rid, 32, "RID")
    q = holder_public_key_binding(ctx, canonical_pk_H)
    trace = derive_trace_ciphertext(
        trace_public_key,
        ctx=ctx,
        sn=sn,
        q=q,
        rid=rid,
        encoded_error=trace_error,
    )
    return ctx + sn + q + (208).to_bytes(4, "big") + trace.s + trace.c_mu + trace.gamma


def _columns(tapes) -> tuple[bytes, ...]:
    """Transpose only the 44 LC14 positions, retaining no full tape matrix."""
    result = tuple(bytearray(256) for _ in SELECTED_POSITIONS)
    count = 0
    for party, tape in enumerate(tapes):
        if party >= SELECTED_PARTIES:
            raise ValueError("selected party count")
        _bytes(tape, 291, "selected tape")
        if tape[-1] & 252:
            raise ValueError("selected tape padding")
        byte, shift = divmod(party, 8)
        for column, position in zip(result, SELECTED_POSITIONS):
            column[byte] |= ((tape[position // 8] >> (position % 8)) & 1) << shift
        count += 1
    if count != SELECTED_PARTIES:
        raise ValueError("selected party count")
    return tuple(bytes(column) for column in result)


def _pack_legacy(
    CR: bytes,
    P: bytes,
    Mhat: bytes,
    h1: bytes,
    r: bytes,
    columns: tuple[bytes, ...],
    seed: bytes,
    tape: bytes,
    mplain: bytes,
) -> bytes:
    """Package ports while rejecting a helper that would repair the input.

    The historical binders can overwrite corrected ports.  Here those writes
    must be identities: neither a different CR nor a repaired P/r is accepted.
    """
    for value, width, name in (
        (CR, 5074, "CR"), (P, 256, "P"), (Mhat, 32, "Mhat"),
        (h1, 48, "h1"), (r, 72, "r"), (seed, 24, "selected seed"),
        (tape, 291, "selected tape"), (mplain, 3, "Mplain"),
    ):
        _bytes(value, width, name)
    if CR[:50] != lc14.lc2.CR_HEADER:
        raise ValueError("canonical CR header")
    if type(columns) is not tuple or len(columns) != 44:
        raise ValueError("selected columns")
    for column in columns:
        _bytes(column, 256, "selected column")
    if int.from_bytes(mplain, "little") >= 1 << 18:
        raise ValueError("Mplain padding")
    if r != P[:72]:
        raise ValueError("same-state r/P join")
    if lc14.lc3.canonical_tape(CR[50:98], seed) != tape:
        raise ValueError("same-state seed/tape join")
    if any((column[0] & 1) != ((tape[p // 8] >> (p % 8)) & 1)
           for column, p in zip(columns, SELECTED_POSITIONS)):
        raise ValueError("same-state party0 column join")
    base = lc14.bind_legacy_private(CR, P, Mhat, h1, columns[:24], seed, tape)
    prefix = CR + P + Mhat + h1 + r
    if base[:len(prefix)] != prefix:
        raise ValueError("legacy binder changed same-state CR/P/r")
    body = lc14.bind_bridge(base, columns[24:])
    if body[:len(prefix)] != prefix or body[lc14_contract.MPLAIN_OFFSET:] != mplain:
        raise ValueError("bridge binder changed same-state CR/P/r/Mplain")
    if len(body) != lc14_contract.PRIVATE_BYTES:
        raise ValueError("legacy private width")
    return body


def _plain(polynomials, width: int) -> bytes:
    if len(polynomials) > width * 8:
        raise ValueError("plain polynomial count")
    value = 0
    for position, polynomial in enumerate(polynomials):
        if type(polynomial.plain) is not int or polynomial.plain not in (0, 1):
            raise ValueError("plain coefficient is not a bit")
        value |= polynomial.plain << position
    return value.to_bytes(width, "little")


def _from_state(state: ProverState, scope: bytes, message: bytes) -> tuple[bytes, bytes]:
    """Internal same-state join; private state never crosses the UE boundary."""
    ctx = _scope_ctx(scope)
    _bytes(message, 388, "M")
    if message[:32] != ctx or message[96:100] != (208).to_bytes(4, "big"):
        raise ValueError("canonical M context/ciphertext length")
    checked = _validate_state(state)
    if checked.ctx != ctx or scope[76:108] != checked.public_map.public_map_digest:
        raise ValueError("same-state public context/map join")
    repetition = checked.corrected_repetitions[SELECTED_REPETITION]
    polynomials = (repetition.witness_polynomials + repetition.relation_masks +
                   repetition.consistency_masks)
    if len(polynomials) != 2322 or any(p.field_id is not FieldId.GF_2_11 for p in polynomials):
        raise ValueError("selected repetition shape/field")

    def selected_tapes():
        for party in range(SELECTED_PARTIES):
            yield derive_leaf_tape(
                SELECTED_REPETITION, party,
                checked.tree_state.leaf_seed(SELECTED_REPETITION, party),
                checked.tree_state.salt,
            ).encoded

    columns = _columns(selected_tapes())
    # In addition to the in-proof port constraints, verify that the packaged
    # slopes are exactly those of the one Init state used by this UE worker.
    for column, position in zip(columns, SELECTED_POSITIONS):
        if lc14.lc2.aggregate(column)[1] != polynomials[position].mask:
            raise ValueError("same-state selected slope join")
    P = _plain(repetition.witness_polynomials, 256)
    Mhat = _plain(repetition.consistency_masks, 32)
    mplain = _plain(repetition.relation_masks, 3)
    CR = encode_c_r(checked.c_r)
    seed = checked.tree_state.leaf_seed(SELECTED_REPETITION, 0)
    tape = derive_leaf_tape(SELECTED_REPETITION, 0, seed, checked.tree_state.salt).encoded
    body = _pack_legacy(CR, P, Mhat, checked.h1, checked.r, columns, seed, tape, mplain)
    u = full_message_u(scope, message, CR)
    beta = bytes(left ^ right for left, right in zip(checked.r, u, strict=True))
    private = body + message + u
    if len(private) != PRIVATE_BYTES:
        raise ValueError("research private width")
    return beta, private


def make_private(
    public_map: UOVPublicMap,
    scope: bytes,
    message: bytes,
    randomness: ProverRandomness,
) -> tuple[bytes, bytes]:
    """Run one real CAP.Init and return ``(public beta72, UE secret17612)``.

    This is a research-only, single-threaded host preparation routine.  The
    caller must admit and monitor the entire UE process before invoking it.
    It creates no files, proof, mock verification result, or NCC witness API.
    """
    ctx = _scope_ctx(scope)
    _bytes(message, 388, "M")
    if type(public_map) is not UOVPublicMap or type(randomness) is not ProverRandomness:
        raise ValueError("explicit public map/CAP randomness required")
    if message[:32] != ctx or message[96:100] != (208).to_bytes(4, "big"):
        raise ValueError("canonical M context/ciphertext length")
    if scope[76:108] != public_map.public_map_digest:
        raise ValueError("ScopeEnc issuer map")
    r, c_r, state = cap_init(public_map, ctx, randomness)
    if r != state.r or c_r != state.c_r:
        raise ValueError("CAP.Init state/output join")
    return _from_state(state, scope, message)
