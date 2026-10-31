"""UE-private codec for the complete R_PC2/content *input* ABI, case 23.

This syntax codec does not evaluate or prove the research relation.  In
particular, accepting bytes does not authenticate seeds, commitments, Xi,
trace-error weight, holder keys or issuer records.  The complete compiler
must constrain those rules using these same input wires.  R1/Init-image,
post-Append pi_2 and production interfaces are deliberately absent.

Bodies, frames and field views are secrets.  Keep them in the admitted UE
process; never send them to the NCC, serialize them to logs, or commit them.
The optional state packer consumes one existing CAP state and never runs Init.
"""

from dataclasses import dataclass
import hashlib
import struct

from . import nonhash_census as census


MAGIC = b"NIFW"
FRAME_VERSION = 1
COMPILER_ABI_VERSION = 2
CASE = 23
DOMAIN = b"PQSAT-BUOV-CAP-HPLUS-RESEARCH/FULL-WITNESS/v0.1\0"
HEADER = struct.Struct(">4sHH32sI")
SEMANTIC_BYTES = census.PRIVATE_BYTES
SEMANTIC_BITS = census.PRIVATE_BITS
PUBLIC_BYTES = census.PUBLIC_BYTES
PRIMARY = census.PRIMARY
PRIVATE_BIT_START = census.PUBLIC_CELLS
BEGIN = census.BEGIN
SELECTED_REPETITION = 2
SELECTED_PARTIES = 2048
SEED_BYTES = 24
COMMITMENT_BYTES = 48
SELECTED_A_INDEX = 8192
BIT_ORDER = "LSB0"
FRAME_BYTES = HEADER.size + len(DOMAIN) + SEMANTIC_BYTES


def _layout():
    cursor, result = 0, []
    for name, size in census.SEMANTIC_LAYOUT:
        result.append((name, cursor, size))
        cursor += size
    if cursor != SEMANTIC_BYTES or BEGIN != PRIVATE_BIT_START + SEMANTIC_BITS:
        raise ValueError("complete witness ABI dimensions changed")
    return tuple(result)


# Public metadata only: offsets are relative to the semantic body, not frame.
FIELD_LAYOUT = _layout()


def _bytes(value, size, name):
    if type(value) is not bytes or len(value) != size:
        raise ValueError(name + " exact bytes/width")
    return value


def _index(value, count, name):
    if type(value) is not int or not 0 <= value < count:
        raise ValueError(name + " exact bounded index")
    return value


def field_span(name):
    """Return a public ``[start,end)`` semantic-body byte span."""
    if type(name) is not str:
        raise ValueError("exact field name")
    for label, start, size in FIELD_LAYOUT:
        if name == label:
            return start, start + size
    raise ValueError("unknown complete witness field")


def field_bit_start(name):
    """Global compiler input wire for the field's first, least-significant bit."""
    return PRIVATE_BIT_START + 8 * field_span(name)[0]


def selected_seed_span(party):
    party = _index(party, SELECTED_PARTIES, "selected party")
    start = field_span("selected_seeds")[0] + SEED_BYTES * party
    return start, start + SEED_BYTES


def selected_commitment_span(party):
    """A uses repetition-major transcript order, never physical tree order."""
    party = _index(party, SELECTED_PARTIES, "selected party")
    start = field_span("A")[0] + COMMITMENT_BYTES * (SELECTED_A_INDEX + party)
    return start, start + COMMITMENT_BYTES


def xi_component_span(repetition, component):
    repetition = _index(repetition, 18, "Xi repetition")
    if type(component) is not str or component not in ("constant", "linear"):
        raise ValueError("Xi component")
    row = census.xi_layout()[repetition]
    base = field_span("Xi")[0]
    if component == "constant":
        start, size = base + row["constant_offset"], 32
    else:
        start, size = base + row["linear_offset"], row["linear_bits"] // 8
    return start, start + size


def cr_component_span(component, *, repetition=None):
    """Shared CR views, including correction delta pairs numbered 1..17."""
    if type(component) is not str:
        raise ValueError("CR component")
    fixed = {"header": (0, 50), "salt": (50, 98),
             "h2_prime": (98, 146), "alpha": (146, 178),
             "deltas": (178, 5074)}
    if component in fixed and repetition is None:
        return fixed[component]  # CR is the first semantic field.
    if component in ("delta_P", "delta_Mhat"):
        repetition = _index(repetition, 18, "correction repetition")
        if repetition == 0:
            raise ValueError("repetition zero has no correction delta")
        start = 178 + (repetition - 1) * 288
        if component == "delta_Mhat":
            start += 256
        return start, start + (256 if component == "delta_P" else 32)
    raise ValueError("CR component/repetition")


def validate_syntax(body):
    """Check fixed canonical packing only; deliberately no relation verdict.

    Xi has 2*(32+384)+16*(32+352) bytes: every bit is used, without
    per-element padding.  Each linear element is exactly 12 or 11 packed
    bits.  Similarly every pk_H bit belongs to rho32 or a ten-bit t1 word.
    Thus fixed lengths, rather than semantic value restrictions, establish
    their byte syntax.  The selected-seed count is exactly 2048*24 bytes.
    """
    _bytes(body, SEMANTIC_BYTES, "semantic body")
    if body[:50] != census.CR_HEADER:
        raise ValueError("canonical CR header")
    return None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class FullWitness:
    """Immutable UE-private bytes; its representation never contains secrets."""

    compiler_id: bytes
    _body: bytes

    def __post_init__(self):
        _bytes(self.compiler_id, 32, "compiler_id")
        validate_syntax(self._body)

    def __repr__(self):
        return "<FullWitness UE-private case=23 semantic_bytes=2030206>"

    @property
    def semantic_body(self):
        """UE-private body; not a public artifact or NCC input."""
        return self._body

    def field(self, name):
        start, end = field_span(name)
        return memoryview(self._body)[start:end]  # immutable bytes => readonly


def pack_fields(values, *, compiler_id):
    """Pack an exact field dictionary, validating syntax rather than truth."""
    _bytes(compiler_id, 32, "compiler_id")
    if type(values) is not dict or any(type(key) is not str for key in values):
        raise ValueError("exact semantic field dictionary")
    if set(values) != {name for name, _, _ in FIELD_LAYOUT}:
        raise ValueError("exact complete semantic field set")
    body = b"".join(_bytes(values[name], size, name)
                    for name, _, size in FIELD_LAYOUT)
    return FullWitness(compiler_id, body)


def encode_frame(witness):
    if type(witness) is not FullWitness:
        raise ValueError("exact FullWitness")
    return (HEADER.pack(MAGIC, FRAME_VERSION, CASE, witness.compiler_id,
                        SEMANTIC_BYTES) + DOMAIN + witness.semantic_body)


def decode_frame(raw, *, compiler_id):
    _bytes(compiler_id, 32, "compiler_id")
    _bytes(raw, FRAME_BYTES, "full witness frame")
    magic, version, case, observed_id, length = HEADER.unpack_from(raw)
    if (magic, version, case, length) != (MAGIC, FRAME_VERSION, CASE, SEMANTIC_BYTES):
        raise ValueError("full witness frame profile")
    if observed_id != compiler_id:
        raise ValueError("full witness compiler identity")
    start = HEADER.size
    if raw[start:start + len(DOMAIN)] != DOMAIN:
        raise ValueError("full witness domain")
    return FullWitness(compiler_id, raw[start + len(DOMAIN):])


def from_cap_state(state, *, compiler_id, ctx, public_map_digest, SN, pk_H, e,
                   commitments=None):
    """Package one existing validated state on the UE, without running Init.

    Use only inside an admitted UE process.  If the caller retained A from
    that same Init, pass it as ``commitments`` to avoid reconstructing it;
    its private digest must match this state's recorded digest.  Otherwise
    commitments are derived using the original tree implementation.  The
    digest is an in-memory host identity check, not an in-proof source rule.

    No common-root condition is added to R_PC2.  State validation and this
    preparation path do not promote syntax or host checks to proof coverage.
    """
    from pq_rbbc.blind_uov_hplus_research_v0_1.codec import encode_c_r
    from pq_rbbc.blind_uov_hplus_research_v0_1.prover import _validate_state

    _bytes(compiler_id, 32, "compiler_id")
    _bytes(ctx, 32, "ctx")
    _bytes(public_map_digest, 32, "public_map_digest")
    _bytes(SN, 16, "SN")
    _bytes(pk_H, 1952, "pk_H")
    _bytes(e, 836, "e")
    checked = _validate_state(state)
    if checked.ctx != ctx or checked.public_map.public_map_digest != public_map_digest:
        raise ValueError("same-state context/map join")
    if commitments is None:
        commitments = checked.tree_state.transcript_commitments()
    _bytes(commitments, 1966080, "commitments")
    if hashlib.sha256(commitments).digest() != checked.commitments_sha256:
        raise ValueError("same-state commitment transcript identity")
    selected_seeds = b"".join(checked.tree_state.leaf_seed(SELECTED_REPETITION, party)
                              for party in range(SELECTED_PARTIES))
    return pack_fields(dict(CR=encode_c_r(checked.c_r), r=checked.r, h1=checked.h1,
                            A=commitments, Xi=checked.xi_bytes,
                            selected_seeds=selected_seeds, SN=SN, pk_H=pk_H, e=e),
                       compiler_id=compiler_id)
