"""Version 1 research envelope, fixed trace fields, and unavailable backends.

Successful decoding establishes shape and dispatch identity only. It never
authenticates a ticket, validates an encryption relation, or authorizes opening.
"""

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import NoReturn


class ContractError(ValueError):
    """Noncanonical or unsupported contract input."""


class Unsupported(RuntimeError):
    """The requested cryptographic capability has not been implemented."""


class Candidate(str, Enum):
    GF = "TH-GF"
    UT = "TH-UT"
    NIED = "TH-NIED"


@dataclass(frozen=True)
class ResearchProfile:
    candidate: Candidate
    profile_id: str
    setup_model: str
    open_parameters: tuple[str, ...]
    implementation_stage: str = "contract_only"
    security_assessment: str = "OPEN"
    threshold_execution: str = "not_implemented"
    opening_capability: str = "interactive_required_adapter_open"
    production_qualified: bool = False


_PROFILE_ROWS = (
    ResearchProfile(Candidate.GF, "gf-pompeii-d4-estimate-v1",
                    "draft_paper_DKG_not_instantiated",
                    ("full_Fulham_profile", "g", "hash_domains", "DKG", "transcript")),
    ResearchProfile(Candidate.GF, "gf-pompeii-d9-estimate-v1",
                    "draft_paper_DKG_not_instantiated",
                    ("full_Fulham_profile", "g", "hash_domains", "DKG", "transcript")),
    ResearchProfile(Candidate.UT, "ut-mlkem768-estimate-v1",
                    "draft_TFHE_PZK_commitment_setup_not_instantiated",
                    ("CAE", "Delta", "TFHE", "PZK", "commitment", "transcript")),
    ResearchProfile(Candidate.NIED, "nied-6688128-estimate-v1",
                    "draft_distributed_key_setup_not_instantiated",
                    ("final_parameters", "DKG", "decoder", "transcript", "adaptation_proof")),
)
PROFILES = MappingProxyType({row.profile_id: row for row in _PROFILE_ROWS})

MAGIC = b"PQ-THRESHOLD-RESEARCH-CIPHERTEXT\x00"
VERSION = 1
MAX_PAYLOAD_BYTES = 1 << 20
MAX_U64 = (1 << 64) - 1


def uint(value: int, name: str, maximum: int = MAX_U64) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ContractError(f"{name} must be an integer in [0, {maximum}]")
    return value


def fixed_bytes(value: bytes, length: int, name: str) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise ContractError(f"{name} must be exactly {length} bytes")
    return value


def get_profile(candidate: Candidate, profile_id: str) -> ResearchProfile:
    if type(candidate) is not Candidate or type(profile_id) is not str:
        raise ContractError("explicit Candidate and canonical profile string required")
    profile = PROFILES.get(profile_id)
    if profile is None or profile.candidate is not candidate:
        raise ContractError("unknown or mismatched candidate/profile")
    return profile


@dataclass(frozen=True)
class TraceInputs:
    """Fixed research input fields; their origin has not been authenticated."""

    rid: bytes
    sn: bytes
    ctx: bytes
    h: bytes

    def __post_init__(self) -> None:
        for name, length in (("rid", 32), ("sn", 16), ("ctx", 32), ("h", 32)):
            fixed_bytes(getattr(self, name), length, name)

    @property
    def plaintext(self) -> bytes:
        return self.rid + self.sn

    @property
    def associated_data(self) -> bytes:
        return self.ctx + self.sn + self.h


def decode_trace_inputs(plaintext: bytes, associated_data: bytes) -> TraceInputs:
    fixed_bytes(plaintext, 48, "plaintext")
    fixed_bytes(associated_data, 80, "associated_data")
    if plaintext[32:] != associated_data[32:48]:
        raise ContractError("plaintext and associated data serials differ")
    return TraceInputs(plaintext[:32], plaintext[32:], associated_data[:32], associated_data[48:])


@dataclass(frozen=True)
class ResearchCiphertext:
    candidate: Candidate
    profile_id: str
    payload: bytes
    version: int = VERSION

    def __post_init__(self) -> None:
        uint(self.version, "version", 65535)
        if self.version != VERSION:
            raise ContractError("unknown envelope version")
        get_profile(self.candidate, self.profile_id)
        if type(self.payload) is not bytes or not 1 <= len(self.payload) <= MAX_PAYLOAD_BYTES:
            raise ContractError("payload must be 1..1048576 opaque bytes")


def envelope_overhead(candidate: Candidate, profile_id: str) -> int:
    get_profile(candidate, profile_id)
    return len(MAGIC) + 2 + 1 + len(candidate.value) + 1 + len(profile_id) + 4


def encode_ciphertext(ciphertext: ResearchCiphertext) -> bytes:
    if type(ciphertext) is not ResearchCiphertext:
        raise ContractError("ResearchCiphertext required")
    candidate = ciphertext.candidate.value.encode("ascii")
    profile = ciphertext.profile_id.encode("ascii")
    return (MAGIC + ciphertext.version.to_bytes(2, "little")
            + bytes([len(candidate)]) + candidate + bytes([len(profile)]) + profile
            + len(ciphertext.payload).to_bytes(4, "little") + ciphertext.payload)


def decode_ciphertext(data: bytes, *, expected_candidate: Candidate,
                      expected_profile_id: str) -> ResearchCiphertext:
    """A caller must pin the expected dispatch identity independently of data."""
    get_profile(expected_candidate, expected_profile_id)
    if type(data) is not bytes or len(data) > MAX_PAYLOAD_BYTES + 1024:
        raise ContractError("invalid envelope type or size")
    offset = 0

    def take(length: int) -> bytes:
        nonlocal offset
        if offset + length > len(data):
            raise ContractError("truncated envelope")
        result = data[offset:offset + length]
        offset += length
        return result

    if take(len(MAGIC)) != MAGIC:
        raise ContractError("wrong envelope domain")
    version = int.from_bytes(take(2), "little")
    if version != VERSION:
        raise ContractError("unknown envelope version")
    try:
        candidate = Candidate(take(take(1)[0]).decode("ascii"))
        profile_id = take(take(1)[0]).decode("ascii")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ContractError("unknown candidate or non-ASCII identifier") from exc
    get_profile(candidate, profile_id)
    if candidate is not expected_candidate or profile_id != expected_profile_id:
        raise ContractError("envelope differs from pinned dispatch identity")
    payload_length = int.from_bytes(take(4), "little")
    if not 1 <= payload_length <= MAX_PAYLOAD_BYTES:
        raise ContractError("payload length out of bounds")
    payload = take(payload_length)
    if offset != len(data):
        raise ContractError("trailing envelope bytes")
    return ResearchCiphertext(candidate, profile_id, payload, version)


@dataclass(frozen=True)
class UnavailableBackend:
    """Reserved research entry points. No success path, even with valid codecs.

    Multi-round messages and validated authorization are deliberately not encoded
    in V1. A future integration contract must define them before implementation.
    """

    candidate: Candidate
    profile_id: str

    def __post_init__(self) -> None:
        get_profile(self.candidate, self.profile_id)

    def _unsupported(self, operation: str) -> NoReturn:
        raise Unsupported(f"{self.candidate.value}/{self.profile_id}: {operation} is OPEN")

    def encrypt_reference(self, *, public_key: bytes, inputs: TraceInputs,
                          randomness: bytes) -> NoReturn:
        self._unsupported("encrypt_reference")

    def check_encryption_relation(self, *, public_key: bytes, inputs: TraceInputs,
                                  ciphertext: ResearchCiphertext, witness: bytes) -> NoReturn:
        self._unsupported("I5 encryption relation")

    def decrypt_reference_for_test(self, *, secret_key: bytes,
                                   ciphertext: ResearchCiphertext,
                                   associated_data: bytes) -> NoReturn:
        self._unsupported("test-only reference decryption")

    def create_share(self, *, context: object) -> NoReturn:
        self._unsupported("single-shot share creation")

    def start_opening(self, *, context: object) -> NoReturn:
        self._unsupported("authorized interactive opening")

    def advance_opening(self, *, session: object, message: bytes) -> NoReturn:
        self._unsupported("interactive transcript transition")

    def combine(self, *, context: object, shares: tuple[bytes, ...]) -> NoReturn:
        self._unsupported("robust threshold reconstruction")


def get_backend(candidate: Candidate, profile_id: str, *,
                purpose: str = "production") -> UnavailableBackend:
    get_profile(candidate, profile_id)
    if type(purpose) is not str or purpose not in ("research", "production"):
        raise ContractError("unknown backend purpose")
    if purpose == "production":
        raise Unsupported("no production-qualified threshold candidate exists")
    return UnavailableBackend(candidate, profile_id)
