"""Public-input preparation for the case-23 research ticket consumer only.

The embedding supplies its own trusted public configuration.  Received tickets
carry only M, CR, CZ and pi2: no u, Scope, issuer key, issuance/session join data
or claimed verdict.  This module strictly decodes those bytes and reconstructs
fullH and CAPStatement.  A prepared result is NOT a verified ticket.  The
research worker must subsequently call the real public-only CAP verifier.

This is not the production Ticket/Access entry point and does not authenticate
configuration provisioning, check policy/expiry, verify holder signatures,
consume a ticket, or establish cross-proof binding/security qualifications.
There is no prover, private state, callback, randomness or I/O in this module.
"""

from dataclasses import dataclass
import struct

from pq_rbbc.blind_uov_hplus_research_v0_1 import codec as cap
from pq_rbbc.blind_uov_hplus_research_v0_1.relation import CAPStatement
from pq_rbbc.blind_uov_hplus_research_v0_1.uov import UOVPublicMap, issuer_key_id
from pq_sat_auth.v3.final_ticket.pqsat_blind_uov_v0_1 import (
    FinalTicketCiphertextV0_1, FinalTicketPayloadV0_1,
)
from . import contract
from . import full_statement


class ResearchTicketError(ValueError):
    """Controlled rejection by the research-only public-input boundary."""


MAGIC = b"BCTKRS01"
VERSION, CASE, ABI_VERSION = 1, 23, 2
HEADER = struct.Struct(">8sHHHIIII")
M_BYTES, CR_BYTES, CZ_BYTES = 388, 5074, 234
PI2_MIN_BYTES, PI2_MAX_BYTES = 1728, 5592
NATIVE_PROOF_CAP, TICKET_CAP = 16 << 10, 32 << 10
RELATION_ID = bytes.fromhex(
    "2640c97a96cb34febf8c2f4844f43ec16d0c6664b051342e8f2b5e80c3f37c9c")
BINDING_ID = bytes.fromhex(
    "6f74ae31aefd848081ff766c0e43bedc1cb790240d5019d3276f4a23dcf26d82")
FINGERPRINT = bytes.fromhex(
    "8579638797c2fa6f9ef09aef518e81213e566115e042744e5b782d8c49c5f07d")
# Scope carries the system issuance suite.  CAP's nested object codec has its
# own separate suite namespace; neither value can substitute for the other.
SUITE_ID = b"\x00\x01"
CAP_SUITE_ID = b"\xff\x33"
SCOPE_FIELDS = (
    ("suite_id", 2), ("ctx", 32), ("issuer_key_id", 32),
    ("issuer_map_digest", 32), ("cap_profile_fingerprint", 32),
    ("relation_profile_digest", 32), ("configuration_digest", 32),
    ("configuration_generation", 8), ("trace_public_key_digest", 32),
)
_SCOPE_HEADER = b"LCAPSCP1\x00\x01"


def _fixed_profile():
    if ((full_statement.CASE, full_statement.ABI_VERSION,
         full_statement.RELATION_ID, full_statement.BINDING_ID,
         contract.FINGERPRINT, tuple(contract.SCOPE_FIELDS))
            != (CASE, ABI_VERSION, RELATION_ID, BINDING_ID, FINGERPRINT,
                tuple(name for name, _ in SCOPE_FIELDS))):
        raise ResearchTicketError("fixed case23 research profile changed")
    profile = cap._PROFILE
    actual_bounds = tuple(cap._HEADER_BYTES + cap._PI_2_FIXED_PAYLOAD_BYTES
                          + cap._SEED_BYTES * count for count in
                          (profile.one_tree.frontier_count_minimum,
                           profile.opened_seed_upper_bound_topen))
    if (profile.fingerprint != FINGERPRINT
            or profile.suite_id_u16.to_bytes(2, "big") != CAP_SUITE_ID
            or actual_bounds != (PI2_MIN_BYTES, PI2_MAX_BYTES)
            or PI2_MAX_BYTES > NATIVE_PROOF_CAP
            or HEADER.size + M_BYTES + CR_BYTES + CZ_BYTES + PI2_MAX_BYTES > TICKET_CAP):
        raise ResearchTicketError("fixed CAP research codec bounds changed")


def _bytes(value, width, name):
    if type(value) is not bytes or len(value) != width:
        raise ResearchTicketError(name + " must be exact fixed-width bytes")
    return value


@dataclass(frozen=True, slots=True, repr=False)
class ResearchPublicConfig:
    """Own public map and nine Scope fields; their provenance is the embedding's duty.

    No SID, RID, request/session digest, beta or accepted flag is retained.
    Construction independently checks the compressed public key's expansion
    and its two distinct issuer identities.  It does not prove KeyGen image.
    """

    public_map: UOVPublicMap
    values: tuple

    def __post_init__(self):
        _fixed_profile()
        if type(self.public_map) is not UOVPublicMap:
            raise ResearchTicketError("exact own UOV public map required")
        if type(self.values) is not tuple or len(self.values) != len(SCOPE_FIELDS):
            raise ResearchTicketError("exact immutable own Scope fields required")
        for value, (name, width) in zip(self.values, SCOPE_FIELDS):
            _bytes(value, width, name)
        records = self.records()
        if (records["suite_id"] != SUITE_ID
                or records["cap_profile_fingerprint"] != FINGERPRINT
                or records["relation_profile_digest"] != RELATION_ID):
            raise ResearchTicketError("wrong own research suite/profile/relation")
        try:
            canonical_map = UOVPublicMap(self.public_map.canonical_cpk)
        except (TypeError, ValueError) as error:
            raise ResearchTicketError("invalid own canonical CPK") from error
        if (self.public_map != canonical_map
                or records["issuer_map_digest"] != canonical_map.public_map_digest
                or records["issuer_key_id"] != issuer_key_id(canonical_map)):
            raise ResearchTicketError("own CPK/map/key identities do not match")
        object.__setattr__(self, "public_map", canonical_map)

    @classmethod
    def from_records(cls, public_map, scope_records):
        if (type(scope_records) is not dict
                or any(type(name) is not str for name in scope_records)
                or set(scope_records) != {name for name, _ in SCOPE_FIELDS}):
            raise ResearchTicketError("exact own Scope fields; no UE/session inputs")
        return cls(public_map, tuple(scope_records[name] for name, _ in SCOPE_FIELDS))

    def records(self):
        """Return a detached copy of only the nine public fields."""
        return dict(zip((name for name, _ in SCOPE_FIELDS), self.values))

    @property
    def scope(self):
        # Deliberately no full X18 with fabricated SID/RID/request placeholders.
        scope = _SCOPE_HEADER + b"".join(self.values) + BINDING_ID
        if len(scope) != 276:
            raise ResearchTicketError("own canonical Scope276")
        return scope

    def __repr__(self):
        return "<ResearchPublicConfig research-only case=23; own public configuration>"


def _canonical_message(raw):
    _bytes(raw, M_BYTES, "M")
    if int.from_bytes(raw[96:100], "big") != 208:
        raise ResearchTicketError("M must contain exactly the 208-byte syndrome")
    # Reuse only the established M388 data codec, never its old digest-binding
    # ticket verifier or H_RBBC function.  There is no caller-supplied d_M.
    payload = FinalTicketPayloadV0_1(
        raw[:32], raw[32:48], raw[48:96],
        FinalTicketCiphertextV0_1(raw[100:308], raw[308:356], raw[356:388]))
    if payload.encode() != raw:
        raise ResearchTicketError("noncanonical research M")
    return payload


def _canonical_cap(raw, width, decoder, encoder, name):
    _bytes(raw, width, name)
    try:
        if encoder(decoder(raw)) != raw:
            raise ResearchTicketError("noncanonical " + name)
    except (TypeError, ValueError) as error:
        raise ResearchTicketError("invalid canonical " + name) from error
    return raw


def _components(M, cr, cz, pi2):
    _canonical_message(M)
    _canonical_cap(cr, CR_BYTES, cap.decode_c_r, cap.encode_c_r, "CR")
    _canonical_cap(cz, CZ_BYTES, cap.decode_c_z, cap.encode_c_z, "CZ")
    if type(pi2) is not bytes or not PI2_MIN_BYTES <= len(pi2) <= PI2_MAX_BYTES:
        raise ResearchTicketError("pi2 outside fixed research codec bounds")
    _canonical_cap(pi2, len(pi2), cap.decode_pi_2, cap.encode_pi_2, "pi2")


def encode_ticket(M, cr, cz, pi2):
    """Encode only canonical research M/CR/CZ/pi2, without claiming validity."""
    _fixed_profile()
    _components(M, cr, cz, pi2)
    return (HEADER.pack(MAGIC, VERSION, CASE, ABI_VERSION,
                        M_BYTES, CR_BYTES, CZ_BYTES, len(pi2)) + M + cr + cz + pi2)


@dataclass(frozen=True, slots=True, repr=False)
class PreparedResearchTicket:
    """Public native inputs only; this object carries no acceptance verdict."""

    statement: CAPStatement
    cr: bytes
    cz: bytes
    pi2: bytes
    M: bytes

    def __repr__(self):
        return "<PreparedResearchTicket research-only public CAP inputs; NOT verified>"


def prepare_ticket(config, raw):
    """Decode the received ticket and recompute u from own Scope and actual M/CR.

    This only prepares the native inputs.  Valid grammar or successful return
    must never be interpreted as CAP acceptance, correct content issuance or
    authorization.  The caller must use a real, independent CAP verifier.
    """
    _fixed_profile()
    if type(config) is not ResearchPublicConfig:
        raise ResearchTicketError("exact own research public configuration")
    if type(raw) is not bytes or not HEADER.size <= len(raw) <= TICKET_CAP:
        raise ResearchTicketError("bounded exact research ticket bytes")
    magic, version, case, abi, m_len, cr_len, cz_len, pi_len = HEADER.unpack_from(raw)
    if ((magic, version, case, abi) != (MAGIC, VERSION, CASE, ABI_VERSION)
            or (m_len, cr_len, cz_len) != (M_BYTES, CR_BYTES, CZ_BYTES)
            or not PI2_MIN_BYTES <= pi_len <= PI2_MAX_BYTES
            or pi_len > NATIVE_PROOF_CAP
            or len(raw) != HEADER.size + m_len + cr_len + cz_len + pi_len):
        raise ResearchTicketError("ticket profile/length/EOF mismatch")
    cursor = HEADER.size
    M = raw[cursor:cursor + m_len]; cursor += m_len
    cr = raw[cursor:cursor + cr_len]; cursor += cr_len
    cz = raw[cursor:cursor + cz_len]; cursor += cz_len
    pi2 = raw[cursor:]
    payload = _canonical_message(M)
    if payload.ctx != config.records()["ctx"]:
        raise ResearchTicketError("ticket ctx differs from own configuration")
    _components(M, cr, cz, pi2)
    u = contract.full_message_u(config.scope, M, cr)
    return PreparedResearchTicket(CAPStatement(config.public_map, payload.ctx, u),
                                  cr, cz, pi2, M)
