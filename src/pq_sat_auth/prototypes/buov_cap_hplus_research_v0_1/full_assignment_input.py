"""UE-only preparation of one same-state case23 assignment input.

This calls the existing content/trace and CAP implementations.  It does not
generate assignment wires, evaluate the complete relation, call native code,
or produce/verify a proof.  Host checks do not add proof coverage or an R1
common-root condition.  No production entry point or success flag is provided.

The returned state, witness and private_frame must remain inside the UE.  Only
beta, public846 and NIFS are public.  This module performs no file, log, secret
hash-output, randomness-generation or subprocess I/O.  The caller supplies all
private inputs/randomness and independently pinned public setup identities.
"""

from dataclasses import dataclass
import os
import resource

from pq_rbbc.blind_uov_hplus_research_v0_1.codec import encode_c_r
from pq_rbbc.blind_uov_hplus_research_v0_1.prover import ProverRandomness, ProverState, cap_init
from pq_rbbc.blind_uov_hplus_research_v0_1.uov import UOVPublicMap, issuer_key_id
from pq_sat_auth.v3.final_ticket.trace_mceliece6688128_research_v0_1 import (
    TracePublicKeyV0_1, validate_error_vector,
)
from .contract import full_message_u
from . import full_statement as statement_codec, full_witness as witness_codec
from ..buov_cap_research_v0_1.ue_witness import honest_message  # Content-only helper; CAP-independent.


def _bytes(value, width, name):
    if type(value) is not bytes or len(value) != width:
        raise ValueError(name + " exact bytes/width")
    return value


def _inputs(*, snapshot, setup, SN, pk_H, e, trace_public_key):
    if type(snapshot) is not statement_codec.FullNCCSnapshot:
        raise ValueError("exact full NCC own snapshot")
    if type(setup) is not statement_codec.FullPublicSetup:
        raise ValueError("exact externally pinned full public setup")
    _bytes(SN, 16, "SN")
    _bytes(pk_H, 1952, "pk_H")
    _bytes(e, 836, "e")
    validate_error_vector(e)  # Integer weight128, never parity-only.
    if type(trace_public_key) is not TracePublicKeyV0_1:
        raise ValueError("exact trace public key")
    records = snapshot.records()
    # This research ABI uses raw T SHA256, not the production-style key_id.
    if not (trace_public_key.sha256 == setup.trace_digest
            == records["trace_public_key_digest"]):
        raise ValueError("trusted raw-T/NCC/setup identity join")
    return records


def _check_map(public_map, records):
    if type(public_map) is not UOVPublicMap:
        raise ValueError("exact issuer public map")
    if (public_map.public_map_digest != records["issuer_map_digest"]
            or issuer_key_id(public_map) != records["issuer_key_id"]):
        raise ValueError("same-state issuer map/NCC key identity join")


def _content(*, snapshot, setup, SN, pk_H, e, trace_public_key):
    """Private preparation only; no supplied M, q, u or encryption outputs."""
    records = _inputs(snapshot=snapshot, setup=setup, SN=SN, pk_H=pk_H, e=e,
                      trace_public_key=trace_public_key)
    # Scope excludes beta and the request-core digest, avoiding circularity.
    scope = snapshot.reconstruct(bytes(72))[1]
    message = honest_message(ctx=records["ctx"], sn=SN, canonical_pk_H=pk_H,
                             rid=records["RID"], trace_public_key=trace_public_key,
                             trace_error=e)
    _bytes(message, 388, "prepared M")
    return records, scope, message


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class PreparedFullAssignment:
    """UE-private container retaining the exact CAP continuation state."""

    state: ProverState
    witness: witness_codec.FullWitness
    beta: bytes
    public: bytes
    statement: bytes

    def __repr__(self):
        return "<PreparedFullAssignment UE-private case=23; not a proof>"

    @property
    def private_frame(self):
        """UE-only stdin payload; never a file, NCC input or logged value."""
        return witness_codec.encode_frame(self.witness)


def prepare_from_state(state, *, snapshot, setup, SN, pk_H, e, trace_public_key,
                       commitments=None):
    """Join actual content and full-H to one existing validated CAP state.

    Context, RID and issuer-map identities come from the NCC's own snapshot.
    A retained commitment transcript may be supplied; full_witness validates
    its private identity against this same state.  Otherwise the existing tree
    implementation reconstructs A.  Neither path calls CAP.Init.
    """
    records, scope, message = _content(snapshot=snapshot, setup=setup, SN=SN,
                                      pk_H=pk_H, e=e, trace_public_key=trace_public_key)
    if type(state) is not ProverState:
        raise TypeError("state must be exactly ProverState")
    _check_map(state.public_map, records)
    witness = witness_codec.from_cap_state(
        state, compiler_id=setup.compiler_id, ctx=records["ctx"],
        public_map_digest=records["issuer_map_digest"], SN=SN, pk_H=pk_H, e=e,
        commitments=commitments)
    CR = bytes(witness.field("CR"))
    r = bytes(witness.field("r"))
    u = full_message_u(scope, message, CR)
    beta = bytes(left ^ right for left, right in zip(r, u, strict=True))
    if snapshot.reconstruct(beta)[1] != scope:
        raise ValueError("Scope changed after final beta reconstruction")
    public = statement_codec.reconstruct_public(snapshot, beta)
    frame = statement_codec.statement(snapshot, beta, setup)
    return PreparedFullAssignment(state, witness, beta, public, frame)


def _require_admitted_init():
    """Reuse the qualified exploration runner's existing admission contract.

    The marker/limits do not prove a lock or an RSS bound: the caller must run
    under that runner's shared lock, tree RSS and MemAvailable monitoring.
    """
    if os.environ.get("BUOV_CAP_EXPLORATION_GUARDED") != "1":
        raise ValueError("CAP.Init requires qualified shared-lock exploration runner")
    for kind, maximum in ((resource.RLIMIT_AS, 8 << 30),
                          (resource.RLIMIT_FSIZE, 1 << 30),
                          (resource.RLIMIT_CPU, 1802)):
        soft = resource.getrlimit(kind)[0]
        if soft == resource.RLIM_INFINITY or not 0 < soft <= maximum:
            raise ValueError("CAP.Init requires inherited finite exploration limits")


def initialize_and_prepare(public_map, randomness, *, snapshot, setup, SN, pk_H, e,
                           trace_public_key):
    """Run exactly one real CAP.Init under the qualified runner, then prepare.

    All canonical content/public-identity checks precede Init.  The returned
    opaque state is the same object used for packaging and later CAP.Append;
    no second state or independent successful fixture is stitched into it.
    """
    _require_admitted_init()
    records = _inputs(snapshot=snapshot, setup=setup, SN=SN, pk_H=pk_H, e=e,
                      trace_public_key=trace_public_key)
    _check_map(public_map, records)
    if type(randomness) is not ProverRandomness:
        raise ValueError("explicit exact CAP randomness")
    r, c_r, state = cap_init(public_map, records["ctx"], randomness)
    if (state.public_map is not public_map or r != state.r
            or encode_c_r(c_r) != encode_c_r(state.c_r)):
        raise ValueError("one-CAP.Init output/state join")
    return prepare_from_state(state, snapshot=snapshot, setup=setup, SN=SN, pk_H=pk_H,
                              e=e, trace_public_key=trace_public_key)
