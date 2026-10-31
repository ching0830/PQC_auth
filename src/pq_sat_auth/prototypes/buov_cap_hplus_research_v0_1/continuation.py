"""UE-only, research-only continuation of one case23 CAP state.

The independent issuer must actually verify pi_iss_research before returning
the UOV preimage through its private RAM transport.  ``request_digest`` binds
that response to public request/proof bytes; it is NOT an authenticated NCC
verdict.  There is deliberately no accepted flag, issuer secret key, inversion
callback, production adapter, or proof-success substitute in this module.

After checking the original preparation and map(z) == beta, this code calls
CAP.Append on that exact state, then the supplied research native kernel.
``kernel.prove(ctx, u, CR, CZ, state)`` returns canonical pi_2 bytes.
``kernel.verify(CAPStatement, CR_bytes, CZ_bytes, pi_2_bytes)`` must return an
exact bool from the independent public-only CAP verifier.  Choosing those
trusted native callbacks and authenticating the issuer transport remain the
embedding's responsibility; callback injection is not a cryptographic gate.

State, witnesses, z and output payloads stay in UE RAM.  No I/O or secret
fingerprint output is performed.  Host identity checks add no in-proof rule,
Init-image claim, security qualification, or production closure.  pi_2 is a
subsequent CAP proof, not part of pi_iss_research.
"""

from dataclasses import dataclass
import hashlib
import struct
from time import perf_counter

from pq_rbbc.blind_uov_hplus_research_v0_1.codec import (
    decode_pi_2, encode_c_r, encode_c_z, encode_pi_2,
)
from pq_rbbc.blind_uov_hplus_research_v0_1.prover import ProverState, _validate_state, cap_append
from pq_rbbc.blind_uov_hplus_research_v0_1.relation import CAPStatement
from pq_rbbc.blind_uov_hplus_research_v0_1.uov import M, N, evaluate_public_map
from .contract import full_message_u
from . import full_assignment_input as assignment
from . import full_statement as statement_codec, full_witness as witness_codec


REQUEST_DOMAIN = b"PQSAT-BUOV-CAP-HPLUS-RESEARCH/CONTINUATION-REQUEST/v0.1\0"


class ResearchContinuationError(ValueError):
    """A research continuation rejection, without secret payload diagnostics."""


def _bytes(value, width, label):
    if type(value) is not bytes or len(value) != width:
        raise ResearchContinuationError(label + " exact bytes/width")
    return value


def request_digest(statement, proof_digest):
    """Public identity binding; proof_digest is SHA256 of exact proof bytes.

    Canonical statement framing is checked here.  Its correspondence to NCC
    records is checked by the real verifier and again by the continuation.
    This function neither verifies the proof nor authenticates a response.
    """
    _bytes(statement, statement_codec.FRAME_BYTES, "statement")
    _bytes(proof_digest, 32, "proof digest")
    if statement_codec.HEADER.unpack_from(statement) != (
            statement_codec.MAGIC, statement_codec.FRAME_VERSION,
            statement_codec.CASE, statement_codec.ABI_VERSION,
            statement_codec.BODY_BYTES):
        raise ResearchContinuationError("statement canonical profile")
    start = statement_codec.HEADER.size
    if statement[start:start + len(statement_codec.DOMAIN)] != statement_codec.DOMAIN:
        raise ResearchContinuationError("statement canonical domain")
    return hashlib.sha256(REQUEST_DOMAIN + struct.pack(">I", len(statement))
                          + statement + proof_digest).digest()


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class ResearchContinuationResult:
    """UE-private output; callers may report only timings and wire lengths."""

    u: bytes
    c_r: bytes
    c_z: bytes
    pi_2: bytes
    preflight_seconds: float
    append_seconds: float
    native_prove_seconds: float
    verify_seconds: float
    whole_seconds: float

    def __repr__(self):
        return "<ResearchContinuationResult UE-private; research-only>"

    @property
    def wire_lengths(self):
        """Lengths only; z, state and private identities are never returned."""
        return dict(u=len(self.u), c_r=len(self.c_r), c_z=len(self.c_z),
                    pi_2=len(self.pi_2), response_z=N)


def continue_from_response(prepared, *, snapshot, setup, statement, proof_digest,
                           response_z, response_request_digest, trace_public_key,
                           kernel):
    """Check a bound issuer response, Append the original state, prove/verify.

    A returned result means this local sequence completed using the supplied
    native kernel.  It does not itself attest that the issuer verified a
    proof; only the independent issuer's actual execution establishes that.
    All preflight failures precede Append and both native calls.  Component
    times measure actual calls separately; whole_seconds also includes codec
    and post-callback state checks, so the components need not sum to it.
    """
    started = perf_counter()
    if type(prepared) is not assignment.PreparedFullAssignment:
        raise ResearchContinuationError("exact prepared full assignment")
    if type(snapshot) is not statement_codec.FullNCCSnapshot:
        raise ResearchContinuationError("exact NCC snapshot")
    if type(setup) is not statement_codec.FullPublicSetup:
        raise ResearchContinuationError("exact public setup")
    if type(prepared.witness) is not witness_codec.FullWitness:
        raise ResearchContinuationError("exact full witness")
    _bytes(prepared.beta, M, "prepared beta")
    _bytes(prepared.public, statement_codec.PUBLIC_BYTES, "prepared public")
    _bytes(prepared.statement, statement_codec.FRAME_BYTES, "prepared statement")
    _bytes(response_z, N, "issuer response z")
    _bytes(response_request_digest, 32, "response request digest")
    if response_request_digest != request_digest(statement, proof_digest):
        raise ResearchContinuationError("response request/proof identity mismatch")
    if prepared.statement != statement:
        raise ResearchContinuationError("prepared/request statement mismatch")
    if not callable(getattr(kernel, "prove", None)) or not callable(getattr(kernel, "verify", None)):
        raise ResearchContinuationError("explicit native research prove/verify kernel")

    state, witness = prepared.state, prepared.witness
    if type(state) is not ProverState:
        raise ResearchContinuationError("exact original CAP state")
    if witness.compiler_id != setup.compiler_id:
        raise ResearchContinuationError("witness/public compiler mismatch")
    original_body = witness.semantic_body
    witness_codec.validate_syntax(original_body)
    records, scope, message = assignment._content(
        snapshot=snapshot, setup=setup, SN=bytes(witness.field("SN")),
        pk_H=bytes(witness.field("pk_H")), e=bytes(witness.field("e")),
        trace_public_key=trace_public_key)
    assignment._check_map(state.public_map, records)
    if state.ctx != records["ctx"]:
        raise ResearchContinuationError("original CAP/NCC context mismatch")
    c_r, r = encode_c_r(state.c_r), _bytes(state.r, M, "original CAP r")
    for label, actual in (("CR", c_r), ("r", r), ("h1", state.h1), ("Xi", state.xi_bytes)):
        if witness.field(label) != actual:
            raise ResearchContinuationError("witness/original CAP field mismatch")
    # Reuse the existing exact same-state packer: it validates state integrity,
    # retained private A identity, and every selected seed against this state.
    # It does not run Init, reconstruct A, or turn host checks into proof rules.
    rebuilt = witness_codec.from_cap_state(
        state, compiler_id=setup.compiler_id, ctx=records["ctx"],
        public_map_digest=records["issuer_map_digest"],
        SN=bytes(witness.field("SN")), pk_H=bytes(witness.field("pk_H")),
        e=bytes(witness.field("e")), commitments=bytes(witness.field("A")))
    if rebuilt.semantic_body != original_body:
        raise ResearchContinuationError("witness/original CAP identity mismatch")
    del rebuilt
    u = full_message_u(scope, message, c_r)
    beta = bytes(left ^ right for left, right in zip(r, u, strict=True))
    if prepared.beta != beta or snapshot.reconstruct(beta)[1] != scope:
        raise ResearchContinuationError("same-state beta/Scope mismatch")
    public = statement_codec.decode_statement(statement, snapshot=snapshot,
                                               beta=beta, setup=setup)
    if public != prepared.public:
        raise ResearchContinuationError("prepared public statement mismatch")
    if evaluate_public_map(state.public_map, response_z) != beta:
        raise ResearchContinuationError("issuer response does not map to beta")
    # This private identity is used only in RAM and is neither returned nor
    # printed.  _validate_state below recomputes it, rather than trusting it.
    original_identity = _bytes(state._state_identity, 32, "original state identity")
    original_map, original_c_r, ctx = state.public_map, state.c_r, state.ctx

    def check_original():
        checked = _validate_state(state)
        if (prepared.state is not state or checked is not state
                or state._state_identity != original_identity
                or state.public_map is not original_map or state.c_r is not original_c_r
                or state.ctx != ctx or state.r != r or encode_c_r(state.c_r) != c_r
                or prepared.witness is not witness or witness.semantic_body is not original_body
                or witness.compiler_id != setup.compiler_id or prepared.beta != beta
                or prepared.statement != statement or prepared.public != public):
            raise ResearchContinuationError("original preparation changed during continuation")

    preflight_seconds = perf_counter() - started
    append_started = perf_counter()
    c_z_object = cap_append(state, response_z)
    append_seconds = perf_counter() - append_started
    c_z = encode_c_z(c_z_object)
    prove_started = perf_counter()
    pi_2 = kernel.prove(ctx, u, original_c_r, c_z_object, state)
    native_prove_seconds = perf_counter() - prove_started
    check_original()
    if type(pi_2) is not bytes:
        raise ResearchContinuationError("native prover must return canonical pi_2 bytes")
    if encode_pi_2(decode_pi_2(pi_2)) != pi_2:
        raise ResearchContinuationError("native prover returned noncanonical pi_2")
    cap_statement = CAPStatement(original_map, ctx, u)
    verify_started = perf_counter()
    verdict = kernel.verify(cap_statement, c_r, c_z, pi_2)
    verify_seconds = perf_counter() - verify_started
    if verdict is not True:
        raise ResearchContinuationError("independent CAP verifier rejected pi_2")
    check_original()
    return ResearchContinuationResult(
        u, c_r, c_z, pi_2, preflight_seconds, append_seconds,
        native_prove_seconds, verify_seconds, perf_counter() - started)
