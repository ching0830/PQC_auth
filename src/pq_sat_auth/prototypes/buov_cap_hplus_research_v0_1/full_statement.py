"""NCC-owned, public-only statement codec for full research case 23.

The NCC supplies authenticated public records and independently pinned public
compiler/setup identities.  This codec does not authenticate those records or
an untrusted descriptor, construct a native setup, or verify a proof.  A
decoded statement means only that its canonical bytes match NCC reconstruction.
The explicit Binius research consumer reconstructs these bytes before calling
the native full-relation prover/verifier. This syntax codec itself never
verifies a proof. Case21/22, the old Ligero route and production interfaces are
not enabled by the new research consumer.

No witness, CR, A, Xi, seed, error, SN, holder key or CAP state is accepted.
Only beta72 is UE-derived.  The request-core digest is always rebuilt locally.
"""

from dataclasses import dataclass
import hashlib
import struct

from . import contract as x18
from . import relation_profile as relation


MAGIC = b"NIFS"
FRAME_VERSION = 1
CASE = 23
ABI_VERSION = 2
HEADER = struct.Struct(">4sHHHI")
DOMAIN = b"PQSAT-BUOV-CAP-HPLUS-RESEARCH/FULL-NCC-STMT/v0.1\0"
CORE_DOMAIN = b"PQSAT-BUOV-CAP-HPLUS-RESEARCH/FULL-REQUEST-CORE/v0.1\0"
RELATION_ID = relation.RELATION_ID
BINDING_ID = relation.BINDING_ID
OWN_FIELDS = tuple((name, size) for name, size in x18.X18
                   if name not in ("beta", "blind_request_core_digest"))
PUBLIC_BYTES = 846
PUBLIC_LAYOUT = (("FP", 0, 32), ("X", 32, 538), ("Scope", 570, 276))
IDENTITY_FIELDS = ("compiler_id", "setup_id", "trace_digest", "session_id")
BODY_BYTES = len(DOMAIN) + 32 * len(IDENTITY_FIELDS) + PUBLIC_BYTES
FRAME_BYTES = HEADER.size + BODY_BYTES
CAP = 2048
if (relation.CASE, relation.ABI_VERSION) != (CASE, ABI_VERSION):
    raise ValueError("full statement/compiler ABI mismatch")
if sum(width for _, width in x18.X18) != 538 or FRAME_BYTES > CAP:
    raise ValueError("full statement fixed dimensions changed")


def _bytes(value, size, label):
    if type(value) is not bytes or len(value) != size:
        raise ValueError(label + " exact fixed-width bytes")
    return value


@dataclass(frozen=True, slots=True)
class FullPublicSetup:
    """Externally pinned public IDs; not an assertion of native availability.

    setup_id identifies the caller's explicit public research setup record.
    It is not synthesized from a UE descriptor or a claimed success flag.
    No default, unknown/zero setup ID or native-availability flag is provided.
    trace_digest is the raw trusted T digest used by the case-23 compiler.
    """

    compiler_id: bytes
    setup_id: bytes
    trace_digest: bytes

    def __post_init__(self):
        from .public_setup import PublicSetupPins
        PublicSetupPins(self.compiler_id, self.setup_id, self.trace_digest)
        for label in ("compiler_id", "setup_id", "trace_digest"):
            if _bytes(getattr(self, label), 32, label) == bytes(32):
                raise ValueError("nonzero externally pinned public identity")


@dataclass(frozen=True, slots=True)
class FullNCCSnapshot:
    """Immutable public own records, whose provenance is an embedding duty."""

    values: tuple

    def __post_init__(self):
        if type(self.values) is not tuple or len(self.values) != len(OWN_FIELDS):
            raise ValueError("full NCC exact public snapshot")
        for value, (name, width) in zip(self.values, OWN_FIELDS):
            _bytes(value, width, name)
        records = self.records()
        if records["relation_profile_digest"] != RELATION_ID:
            raise ValueError("full NCC case23 relation identity")
        if records["cap_profile_fingerprint"] != x18.FINGERPRINT:
            raise ValueError("full NCC CAP fingerprint")
        if records["SID"] == bytes(32):
            raise ValueError("nonzero NCC issuance session")

    @classmethod
    def from_records(cls, records):
        if (type(records) is not dict or any(type(name) is not str for name in records)
                or set(records) != {name for name, _ in OWN_FIELDS}):
            raise ValueError("exact NCC own records; no UE X or private fields")
        return cls(tuple(records[name] for name, _ in OWN_FIELDS))

    def records(self):
        return dict(zip((name for name, _ in OWN_FIELDS), self.values))

    def reconstruct(self, beta):
        """Rebuild canonical X18 frame554 and Scope276 from NCC records."""
        _bytes(beta, 72, "beta")
        records = self.records()
        pieces = [CORE_DOMAIN]
        for name, width in x18.X18:
            if name == "blind_request_core_digest":
                continue
            value = beta if name == "beta" else records[name]
            label = name.encode("ascii")
            pieces.extend((struct.pack(">H", len(label)), label,
                           struct.pack(">I", width), value))
        records["blind_request_core_digest"] = hashlib.sha256(b"".join(pieces)).digest()
        encoded = x18.rebuild_x(x18.R2, records, beta)
        parsed = x18.parse_x(x18.R2, encoded)
        scope = x18.scope_encoding(parsed, BINDING_ID)
        if len(encoded) != 554 or len(scope) != 276:
            raise ValueError("full X18/Scope fixed widths")
        return encoded, scope


def reconstruct_public(snapshot, beta):
    """Return exactly FP32 || X18-payload538 || Scope276 (no X header)."""
    if type(snapshot) is not FullNCCSnapshot:
        raise ValueError("exact full NCC public snapshot")
    encoded, scope = snapshot.reconstruct(beta)
    public = x18.FINGERPRINT + encoded[x18.HEADER.size:] + scope
    if len(public) != PUBLIC_BYTES:
        raise ValueError("full public846")
    return public


def statement(snapshot, beta, setup):
    """Encode NCC-reconstructed public data; never a proof-acceptance result."""
    if type(snapshot) is not FullNCCSnapshot or type(setup) is not FullPublicSetup:
        raise ValueError("exact full NCC snapshot/public setup")
    if snapshot.records()["trace_public_key_digest"] != setup.trace_digest:
        raise ValueError("trusted T differs from NCC own trace identity")
    encoded, scope = snapshot.reconstruct(beta)
    public = x18.FINGERPRINT + encoded[x18.HEADER.size:] + scope
    if len(public) != PUBLIC_BYTES:
        raise ValueError("full public846")
    session_id = hashlib.sha256(encoded).digest()
    payload = (DOMAIN + setup.compiler_id + setup.setup_id + setup.trace_digest
               + session_id + public)
    return HEADER.pack(MAGIC, FRAME_VERSION, CASE, ABI_VERSION, BODY_BYTES) + payload


def decode_statement(raw, *, snapshot, beta, setup):
    """Return public846 only after exact NCC reconstruction; no proof Verify.

    The caller must pin compiler_id/setup_id itself and obtain the snapshot
    from its own authority records.  A received descriptor or UE X is not an
    input.  A native proof verifier must be called separately; the explicit
    binius_ncc_verify consumer supplies that step after this reconstruction.
    """
    _bytes(raw, FRAME_BYTES, "full public statement/EOF")
    if HEADER.unpack_from(raw) != (MAGIC, FRAME_VERSION, CASE, ABI_VERSION, BODY_BYTES):
        raise ValueError("full public statement profile/version/length")
    if raw[HEADER.size:HEADER.size + len(DOMAIN)] != DOMAIN:
        raise ValueError("full public statement domain")
    expected = statement(snapshot, beta, setup)
    if raw != expected:
        raise ValueError("statement differs from NCC own reconstruction/pinned identities")
    return expected[-PUBLIC_BYTES:]
