"""Stateless VerifyTicket contract for PQ-RBBC system profile v0.1.

The canonical transport wraps the already-frozen 368-byte ``TicketPayload``
encoding and an opaque issuer signature.  It does not redefine the payload,
derive another system context, invoke CAP, verify an online issuance proof, or
consume ticket state.  The Blind-UOV-compatible authentication backend remains
an explicit dependency until a qualified production implementation exists.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol

from pq_rbbc.contracts.system import (
    CONTEXT_BYTES,
    KEY_ID_BYTES,
    SCHEMA_VERSION,
    SYSTEM_PROFILE_PROTOCOL_VERSION,
    ContractError,
    KeyReference,
    KeyRole,
    SystemInitializationBundle,
    _expect_magic,
    _require_identifier,
    _require_uint,
    _take,
    _take_uint,
)
from pq_rbbc.governance.system_init import (
    ConfigurationAuthenticationVerifier,
    verify_initialization,
)
from pq_rbbc.opening.interfaces import TicketView
from pq_rbbc_reference import LABEL_TICKET, TicketPayload


TICKET_MAGIC = b"PQRBBC-TICKET-V1"
TICKET_PAYLOAD_DIGEST_DOMAIN = LABEL_TICKET
TICKET_PAYLOAD_BYTES = 368
TICKET_DIGEST_BYTES = 32
SERIAL_BYTES = 16
HOLDER_HASH_BYTES = 32
SYNDROME_BYTES = 208
MASKED_IDENTITY_BYTES = 48
TRACE_TAG_BYTES = 32
TRACE_CIPHERTEXT_BYTES = (
    SYNDROME_BYTES + MASKED_IDENTITY_BYTES + TRACE_TAG_BYTES
)
MAX_TICKET_SIGNATURE_BYTES = 1 << 16
MAX_CANONICAL_TICKET_BYTES = 1 << 17


class TicketAuthenticationVerifier(Protocol):
    """Backend boundary for issuer verification of ``d_M``.

    The supplied key is always the authenticated initialization bundle's
    ``ISSUER_VERIFICATION`` reference.  Implementations own signature parsing
    and suite-specific canonicality checks.
    """

    def verify(
        self,
        key: KeyReference,
        message_digest: bytes,
        signature: bytes,
    ) -> bool: ...


class TicketClock(Protocol):
    """Trusted time boundary used to enforce the configuration expiry bucket."""

    def now(self) -> int: ...


def decode_ticket_payload(encoded: bytes) -> TicketPayload:
    """Strictly decode the frozen ``TicketPayload.encode()`` byte layout.

    ``pq_rbbc_reference.TicketPayload`` remains the sole payload representation.
    This adapter only adds the missing inverse operation at the system boundary.
    """

    if not isinstance(encoded, bytes):
        raise ContractError("ticket payload encoding must be bytes")
    if len(encoded) != TICKET_PAYLOAD_BYTES:
        raise ContractError(
            f"ticket payload must be exactly {TICKET_PAYLOAD_BYTES} bytes"
        )
    offset = 0
    ctx, offset = _take(encoded, offset, CONTEXT_BYTES, "ticket payload ctx")
    serial, offset = _take(encoded, offset, SERIAL_BYTES, "ticket payload serial")
    holder_hash, offset = _take(
        encoded, offset, HOLDER_HASH_BYTES, "ticket payload holder hash"
    )
    syndrome, offset = _take(
        encoded, offset, SYNDROME_BYTES, "ticket payload syndrome"
    )
    masked_identity, offset = _take(
        encoded,
        offset,
        MASKED_IDENTITY_BYTES,
        "ticket payload masked identity",
    )
    tag, offset = _take(encoded, offset, TRACE_TAG_BYTES, "ticket payload trace tag")
    if offset != len(encoded):
        raise ContractError("ticket payload trailing bytes")
    payload = TicketPayload(
        ctx=ctx,
        sn=serial,
        holder_hash=holder_hash,
        syndrome=syndrome,
        masked_identity=masked_identity,
        tag=tag,
    )
    if payload.encode() != encoded:
        raise ContractError("ticket payload encoding is non-canonical")
    return payload


def ticket_payload_digest(payload: TicketPayload) -> bytes:
    """Return the existing core identity ``d_M = H_ticket(Encode(M))``."""

    return hashlib.shake_256(
        TICKET_PAYLOAD_DIGEST_DOMAIN + payload.encode()
    ).digest(TICKET_DIGEST_BYTES)


@dataclass(frozen=True)
class CanonicalTicket:
    """Canonical transport envelope for ``T = (M, sigma)``.

    The role and key ID are redundant, explicit routing metadata.  Verification
    accepts them only when they equal the authenticated bundle's separated
    issuer-verification key; the signature itself authenticates ``d_M``.
    """

    protocol_version: int
    signing_role: KeyRole
    issuer_key_id: bytes
    payload: TicketPayload
    signature: bytes

    def validate(self) -> None:
        _require_uint(self.protocol_version, 2, "ticket protocol_version")
        if self.protocol_version != SYSTEM_PROFILE_PROTOCOL_VERSION:
            raise ContractError("unsupported ticket protocol_version")
        if not isinstance(self.signing_role, KeyRole):
            raise ContractError("ticket signing role must be a KeyRole")
        _require_identifier(self.issuer_key_id, "ticket issuer_key_id")
        if not isinstance(self.payload, TicketPayload):
            raise ContractError("ticket payload must be a TicketPayload")
        payload_bytes = self.payload.encode()
        if len(payload_bytes) != TICKET_PAYLOAD_BYTES:
            raise ContractError("ticket payload has the wrong canonical length")
        if not isinstance(self.signature, bytes) or not (
            0 < len(self.signature) <= MAX_TICKET_SIGNATURE_BYTES
        ):
            raise ContractError("ticket signature length is outside bounds")

    def encode(self) -> bytes:
        self.validate()
        payload_bytes = self.payload.encode()
        encoded = b"".join(
            (
                TICKET_MAGIC,
                SCHEMA_VERSION.to_bytes(2, "little"),
                self.protocol_version.to_bytes(2, "little"),
                int(self.signing_role).to_bytes(2, "little"),
                self.issuer_key_id,
                len(payload_bytes).to_bytes(4, "little"),
                payload_bytes,
                len(self.signature).to_bytes(4, "little"),
                self.signature,
            )
        )
        if len(encoded) > MAX_CANONICAL_TICKET_BYTES:
            raise ContractError("canonical ticket is oversized")
        return encoded

    @classmethod
    def decode(cls, encoded: bytes) -> "CanonicalTicket":
        if not isinstance(encoded, bytes):
            raise ContractError("canonical ticket encoding must be bytes")
        if len(encoded) > MAX_CANONICAL_TICKET_BYTES:
            raise ContractError("canonical ticket is oversized")
        offset = _expect_magic(encoded, 0, TICKET_MAGIC, "ticket magic")
        schema_version, offset = _take_uint(
            encoded, offset, 2, "ticket schema version"
        )
        if schema_version != SCHEMA_VERSION:
            raise ContractError("wrong ticket schema version")
        protocol_version, offset = _take_uint(
            encoded, offset, 2, "ticket protocol version"
        )
        role_value, offset = _take_uint(encoded, offset, 2, "ticket signing role")
        try:
            signing_role = KeyRole(role_value)
        except ValueError as error:
            raise ContractError("unknown ticket signing role") from error
        issuer_key_id, offset = _take(
            encoded, offset, KEY_ID_BYTES, "ticket issuer key ID"
        )
        payload_length, offset = _take_uint(
            encoded, offset, 4, "ticket payload length"
        )
        if payload_length != TICKET_PAYLOAD_BYTES:
            raise ContractError("ticket payload has the wrong canonical length")
        payload_bytes, offset = _take(
            encoded, offset, payload_length, "ticket payload"
        )
        signature_length, offset = _take_uint(
            encoded, offset, 4, "ticket signature length"
        )
        if not 0 < signature_length <= MAX_TICKET_SIGNATURE_BYTES:
            raise ContractError("ticket signature length is outside bounds")
        signature, offset = _take(
            encoded, offset, signature_length, "ticket signature"
        )
        if offset != len(encoded):
            raise ContractError("canonical ticket trailing bytes")
        ticket = cls(
            protocol_version=protocol_version,
            signing_role=signing_role,
            issuer_key_id=issuer_key_id,
            payload=decode_ticket_payload(payload_bytes),
            signature=signature,
        )
        ticket.validate()
        if ticket.encode() != encoded:
            raise ContractError("canonical ticket encoding is non-canonical")
        return ticket

    @property
    def payload_digest(self) -> bytes:
        return ticket_payload_digest(self.payload)

    @property
    def canonical_digest(self) -> bytes:
        """Digest of exact transport bytes used by conditional opening v0.1."""

        return hashlib.sha256(self.encode()).digest()

    @property
    def trace_ciphertext(self) -> bytes:
        return b"".join(
            (
                self.payload.syndrome,
                self.payload.masked_identity,
                self.payload.tag,
            )
        )


@dataclass(frozen=True)
class TicketVerification:
    accepted: bool
    failures: tuple[str, ...]
    ticket: TicketView | None
    payload_digest: bytes | None


def _binding_failure(
    ticket: CanonicalTicket,
    bundle: SystemInitializationBundle,
) -> str | None:
    issuer_key = bundle.key_for(KeyRole.ISSUER_VERIFICATION)
    bindings = (
        (
            ticket.signing_role is KeyRole.ISSUER_VERIFICATION,
            "ticket_wrong_key_role",
        ),
        (
            ticket.protocol_version == bundle.configuration.protocol_version,
            "ticket_protocol_version_mismatch",
        ),
        (ticket.issuer_key_id == issuer_key.key_id, "ticket_issuer_key_id_mismatch"),
        (ticket.payload.ctx == bundle.ctx, "ticket_ctx_mismatch"),
    )
    return next((failure for matches, failure in bindings if not matches), None)


def verify_ticket(
    authenticated_initialization: bytes,
    canonical_ticket: bytes,
    *,
    trusted_configuration_key: KeyReference,
    initialization_verifier: ConfigurationAuthenticationVerifier,
    ticket_verifier: TicketAuthenticationVerifier,
    clock: TicketClock,
) -> TicketVerification:
    """Authenticate initialization, then strictly parse and verify one ticket.

    This operation is stateless.  It does not reserve or consume the ticket.
    """

    initialization = verify_initialization(
        authenticated_initialization,
        trusted_configuration_key,
        initialization_verifier,
    )
    if not initialization.accepted or initialization.bundle is None:
        return TicketVerification(
            False,
            tuple(f"initialization:{failure}" for failure in initialization.failures),
            None,
            None,
        )
    bundle = initialization.bundle

    try:
        ticket = CanonicalTicket.decode(canonical_ticket)
    except ContractError as error:
        return TicketVerification(False, (f"ticket_encoding:{error}",), None, None)

    payload_digest = ticket.payload_digest
    binding_failure = _binding_failure(ticket, bundle)
    if binding_failure is not None:
        return TicketVerification(False, (binding_failure,), None, payload_digest)

    try:
        now = clock.now()
    except Exception as error:  # Fail closed across the trusted-time boundary.
        return TicketVerification(
            False, (f"clock_backend:{type(error).__name__}",), None, payload_digest
        )
    try:
        _require_uint(now, 8, "ticket verification time")
    except ContractError as error:
        return TicketVerification(
            False, (f"clock_backend:{error}",), None, payload_digest
        )
    if now >= bundle.configuration.expiry_bucket:
        return TicketVerification(False, ("ticket_expired",), None, payload_digest)

    issuer_key = bundle.key_for(KeyRole.ISSUER_VERIFICATION)
    try:
        valid = ticket_verifier.verify(
            issuer_key,
            payload_digest,
            ticket.signature,
        )
    except Exception as error:  # Fail closed across the signature boundary.
        return TicketVerification(
            False,
            (f"ticket_authentication_backend:{type(error).__name__}",),
            None,
            payload_digest,
        )
    if valid is not True:
        return TicketVerification(
            False, ("ticket_authentication_invalid",), None, payload_digest
        )

    view = TicketView(
        ticket_digest=ticket.canonical_digest,
        ctx=ticket.payload.ctx,
        visible_serial=ticket.payload.sn,
        trace_ciphertext=ticket.trace_ciphertext,
        issuer_key_id=issuer_key.key_id,
    )
    try:
        view.validate()
    except Exception as error:
        return TicketVerification(
            False,
            (f"ticket_view:{type(error).__name__}",),
            None,
            payload_digest,
        )
    return TicketVerification(True, (), view, payload_digest)


class SystemTicketVerifier:
    """Adapter implementing the conditional-opening ``TicketVerifier`` API."""

    def __init__(
        self,
        *,
        authenticated_initialization: bytes,
        trusted_configuration_key: KeyReference,
        initialization_verifier: ConfigurationAuthenticationVerifier,
        ticket_verifier: TicketAuthenticationVerifier,
        clock: TicketClock,
    ) -> None:
        self._authenticated_initialization = authenticated_initialization
        self._trusted_configuration_key = trusted_configuration_key
        self._initialization_verifier = initialization_verifier
        self._ticket_verifier = ticket_verifier
        self._clock = clock

    def verify(self, canonical_ticket: bytes) -> TicketView | None:
        outcome = verify_ticket(
            self._authenticated_initialization,
            canonical_ticket,
            trusted_configuration_key=self._trusted_configuration_key,
            initialization_verifier=self._initialization_verifier,
            ticket_verifier=self._ticket_verifier,
            clock=self._clock,
        )
        return outcome.ticket if outcome.accepted else None


def verify_ticket_manifest(ticket: CanonicalTicket) -> dict[str, object]:
    """Return public metadata for the deterministic contract test vector."""

    payload_bytes = ticket.payload.encode()
    ticket_bytes = ticket.encode()
    return {
        "format": "PQRBBC-VERIFY-TICKET-CONTRACT-CHECKPOINT-1",
        "system_profile": "0.1",
        "schema_version": SCHEMA_VERSION,
        "protocol_version": ticket.protocol_version,
        "ticket_magic": TICKET_MAGIC.decode("ascii"),
        "ticket_payload_digest_domain": TICKET_PAYLOAD_DIGEST_DOMAIN.decode(
            "ascii"
        ),
        "signing_role": ticket.signing_role.name,
        "issuer_key_id": ticket.issuer_key_id.hex(),
        "payload_bytes": len(payload_bytes),
        "payload_encoding_hex": payload_bytes.hex(),
        "payload_digest": ticket.payload_digest.hex(),
        "signature_bytes": len(ticket.signature),
        "canonical_ticket_bytes": len(ticket_bytes),
        "canonical_ticket_sha256": ticket.canonical_digest.hex(),
        "payload_offsets": {
            "ctx": [0, 32],
            "visible_serial": [32, 48],
            "holder_hash": [48, 80],
            "syndrome": [80, 288],
            "masked_identity": [288, 336],
            "trace_tag": [336, 368],
        },
        "claim_boundary": {
            "canonical_ticket_transport_codec_implemented": True,
            "frozen_reference_payload_encoding_reused": True,
            "stateless_verify_ticket_control_flow_implemented": True,
            "authenticated_initialization_required": True,
            "explicit_configuration_trust_anchor_required": True,
            "issuer_verification_role_enforced": True,
            "issuer_authentication_backend_abstract": True,
            "test_signature_is_cryptographic": False,
            "production_signature_encoding_frozen": False,
            "configuration_expiry_enforced": True,
            "ticket_consumption_implemented": False,
            "holder_authentication_implemented": False,
            "cap_prove_or_verify_called": False,
            "online_issuance_proof_expected": False,
            "blind_uov_backend_instantiated": False,
            "production_verify_ticket_complete": False,
        },
    }
