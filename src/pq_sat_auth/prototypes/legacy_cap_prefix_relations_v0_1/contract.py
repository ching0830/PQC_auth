"""New research-only X18/W frames. This is not the legacy issuance wire.

These strict codecs define memory/pipe contracts, not full relation checks.
The issuer must rebuild X from its authenticated and durable records.
"""
import hashlib
import struct

BASE = "58d163ce609f776a4486b6280af366f6409c3659"
FINGERPRINT = bytes.fromhex("fc6706429f10d3bcc5600d4b427ca604a19f22c31ec35b171f40513b1a4bcb25")
R1 = "R_FULL_INIT_REVIEWED_v1"
R2 = "R_PC2_PROPOSED_v1"
KINDS = {R1: 1, R2: 2}
HEADER = struct.Struct(">8sHBBI")
X18 = (("ctx", 32), ("SID", 32), ("RID", 32), ("beta", 72),
       ("configuration_digest", 32), ("configuration_generation", 8),
       ("relation_profile_digest", 32), ("cap_profile_fingerprint", 32),
       ("issuer_map_digest", 32), ("trace_public_key_digest", 32),
       ("issuer_key_id", 32), ("issue_session_request_digest", 32),
       ("blind_request_core_digest", 32), ("authenticated_holder_session_digest", 32),
       ("issuance_authorization_digest", 32), ("quota_reservation_id", 32),
       ("suite_id", 2), ("session_expiry", 8))
COMMON_W = (("SN", 16), ("canonical_pk_H", 1952), ("trace_error", 836))
W = {R1: COMMON_W + (("root", 24), ("salt", 48)),
     R2: COMMON_W + (("CR", 5074), ("r", 72), ("h1", 48), ("A", 1966080),
                    ("Xi", 6976), ("selected_seeds", 49152))}
SCOPE_FIELDS = ("suite_id", "ctx", "issuer_key_id", "issuer_map_digest",
                "cap_profile_fingerprint", "relation_profile_digest",
                "configuration_digest", "configuration_generation", "trace_public_key_digest")
FULL_DOMAIN = b"PQSAT-V3/ISSUANCE-FINAL-PPT/FULL-MESSAGE/v0.1"


def _kind(relation):
    if type(relation) is not str or relation not in KINDS:
        raise ValueError("unknown relation/version")
    return KINDS[relation]


def _payload(layout, values):
    if type(values) is not dict or set(values) != {name for name, _ in layout}:
        raise ValueError("exact ordered-schema field set required")
    chunks = []
    for name, width in layout:
        value = values[name]
        if type(value) is not bytes or len(value) != width:
            raise ValueError("exact fixed-width bytes required: " + name)
        chunks.append(value)
    return b"".join(chunks)


def _frame(magic, relation, layout, values):
    body = _payload(layout, values)
    return HEADER.pack(magic, 1, _kind(relation), 0, len(body)) + body


def _parse(magic, relation, layout, raw):
    size = sum(n for _, n in layout)
    if type(raw) is not bytes or len(raw) != HEADER.size + size:
        raise ValueError("length/trailing bytes")
    if raw[:HEADER.size] != HEADER.pack(magic, 1, _kind(relation), 0, size):
        raise ValueError("magic/version/relation/flags/length")
    result, cursor = {}, HEADER.size
    for name, width in layout:
        result[name] = raw[cursor:cursor + width]
        cursor += width
    return result


def encode_x(relation, values):
    _payload(X18, values)
    if values["SID"] == bytes(32) or values["cap_profile_fingerprint"] != FINGERPRINT:
        raise ValueError("SID/fingerprint")
    return _frame(b"LCAPX181", relation, X18, values)


def parse_x(relation, raw):
    result = _parse(b"LCAPX181", relation, X18, raw)
    if encode_x(relation, result) != raw:
        raise ValueError("noncanonical X")
    return result


def rebuild_x(relation, authenticated_records, beta):
    """Only beta is UE-derived; caller supplies the issuer's own exact records.

    Python cannot attest record provenance. No untrusted X input is accepted.
    In particular blind_request_core_digest is recomputed by the issuer.
    """
    expected = {name for name, _ in X18} - {"beta"}
    if type(authenticated_records) is not dict or set(authenticated_records) != expected:
        raise ValueError("issuer record snapshot required")
    return encode_x(relation, dict(authenticated_records, beta=beta))


def encode_w(relation, values):
    """Explicit private pipe encoding; never log or place in public artifacts."""
    _kind(relation)
    _payload(W[relation], values)
    if int.from_bytes(values["trace_error"], "little").bit_count() != 128:
        raise ValueError("trace error weight128")
    if relation == R2:
        cr_header = (b"PQSCAP01\x00\x01\x00\x01\xff\x32" + FINGERPRINT +
                     (5024).to_bytes(4, "big"))
        if values["CR"][:50] != cr_header:
            raise ValueError("canonical CR header/version/length")
    # FIPS204 pk: rho32 + exactly 1536 packed 10-bit t1 values (1920B).
    # Every fixed-width bitstring is syntax-canonical; no KeyGen-image claim.
    return _frame(b"LCAPW001", relation, W[relation], values)


def parse_w(relation, raw):
    _kind(relation)
    result = _parse(b"LCAPW001", relation, W[relation], raw)
    if encode_w(relation, result) != raw:
        raise ValueError("noncanonical W")
    return result


def scope_encoding(x, binding_profile_digest):
    """Frozen diagnostic scope; no SID/RID/quota/expiry/request digest."""
    _payload(X18, x)
    if type(binding_profile_digest) is not bytes or len(binding_profile_digest) != 32:
        raise ValueError("binding profile32")
    return b"LCAPSCP1\x00\x01" + b"".join(x[n] for n in SCOPE_FIELDS) + binding_profile_digest


def full_message_u(scope, M, CR):
    if type(scope) is not bytes or len(scope) != 276 or scope[:10] != b"LCAPSCP1\x00\x01":
        raise ValueError("canonical diagnostic ScopeEnc")
    if type(M) is not bytes or len(M) != 388 or type(CR) is not bytes or len(CR) != 5074:
        raise ValueError("full M/CR widths")
    return hashlib.shake_256(FULL_DOMAIN + scope + struct.pack(">Q", len(M)) + M +
                            struct.pack(">Q", len(CR)) + CR).digest(72)
