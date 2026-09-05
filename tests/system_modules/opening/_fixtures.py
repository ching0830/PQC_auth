"""Deterministic test-only adapters; none implements threshold cryptography."""

from __future__ import annotations

import hashlib
from dataclasses import replace

from pq_rbbc.contracts.system import (
    KeyReference,
    KeyRole,
    SystemConfiguration,
    SystemInitializationBundle,
    ThresholdPolicy,
)
from pq_rbbc.governance.system_init import (
    INITIALIZATION_AUTH_DOMAIN,
    AuthenticatedSystemInitialization,
)
from pq_rbbc.opening.gate import OpenShareService
from pq_rbbc.opening.interfaces import (
    DecodedTrace,
    ReplayReservation,
    ThresholdOpeningContext,
    ThresholdShareMaterial,
    TicketView,
)
from pq_rbbc.opening.request import OpeningRequest, canonical_ticket_digest
from pq_rbbc.opening.shares import OpenShare, share_authentication_message


def fixed_bytes(label: bytes) -> bytes:
    return hashlib.sha256(b"PQ-RBBC/conditional-opening-test/" + label).digest()


TICKET_BYTES = b"PQRBBC-TEST-ONLY-CANONICAL-TICKET-V1" + fixed_bytes(b"ticket-body")
VISIBLE_SERIAL = fixed_bytes(b"visible-serial")[:16]
IDENTITY = fixed_bytes(b"decoded-identity")
TRACE_CIPHERTEXT = b"TEST-ONLY-OPAQUE-TRACE-CIPHERTEXT" + fixed_bytes(b"trace")


def reference_bundle() -> SystemInitializationBundle:
    references = tuple(
        KeyReference(
            role=role,
            key_id=fixed_bytes(b"key-id/" + role.name.encode("ascii")),
            public_key_digest=fixed_bytes(
                b"public-key/" + role.name.encode("ascii")
            ),
        )
        for role in KeyRole
    )
    issuer_key = next(
        key for key in references if key.role is KeyRole.ISSUER_VERIFICATION
    )
    opening_key = next(
        key for key in references if key.role is KeyRole.OPENING_ENCRYPTION
    )
    configuration = SystemConfiguration(
        protocol_version=1,
        epoch=73,
        domain=fixed_bytes(b"domain"),
        policy_digest=fixed_bytes(b"policy"),
        expiry_bucket=2_000_000_000,
        oa_key_id=opening_key.key_id,
        issuer_key_id=issuer_key.key_id,
    )
    return SystemInitializationBundle(
        configuration=configuration,
        common_parameters_digest=fixed_bytes(b"common-parameters"),
        federation_policy=ThresholdPolicy(member_count=5, threshold=3),
        opening_policy=ThresholdPolicy(member_count=7, threshold=5),
        keys=references,
    )


class DigestConfigurationVerifier:
    """Test checksum adapter, not a signature implementation."""

    @staticmethod
    def sign(key: KeyReference, message: bytes) -> bytes:
        return hashlib.sha256(
            b"test-config-auth" + key.public_key_digest + message
        ).digest()

    def verify(self, key: KeyReference, message: bytes, authentication: bytes) -> bool:
        return authentication == self.sign(key, message)


def reference_envelope() -> AuthenticatedSystemInitialization:
    bundle = reference_bundle()
    key = bundle.key_for(KeyRole.FEDERATION_CONFIGURATION)
    message = INITIALIZATION_AUTH_DOMAIN + bundle.encode()
    return AuthenticatedSystemInitialization(
        bundle,
        DigestConfigurationVerifier.sign(key, message),
    )


def reference_ticket_view() -> TicketView:
    bundle = reference_bundle()
    return TicketView(
        ticket_digest=canonical_ticket_digest(TICKET_BYTES),
        ctx=bundle.ctx,
        visible_serial=VISIBLE_SERIAL,
        trace_ciphertext=TRACE_CIPHERTEXT,
        issuer_key_id=bundle.key_for(KeyRole.ISSUER_VERIFICATION).key_id,
    )


class FixedTicketVerifier:
    """Accept one fixture; it is intentionally not a full VerifyTicket."""

    def __init__(self, *, reject: bool = False, broken: bool = False) -> None:
        self.reject = reject
        self.broken = broken
        self.calls = 0

    def verify(self, canonical_ticket: bytes) -> TicketView | None:
        self.calls += 1
        if self.broken:
            raise RuntimeError("test ticket verifier failure")
        if self.reject or canonical_ticket != TICKET_BYTES:
            return None
        return reference_ticket_view()


class DigestAuthorizationVerifier:
    """Test checksum adapter, not an opening-authorization signature."""

    def __init__(self, *, reject: bool = False, broken: bool = False) -> None:
        self.reject = reject
        self.broken = broken
        self.calls = 0
        self.roles: list[KeyRole] = []

    @staticmethod
    def sign(key: KeyReference, message: bytes) -> bytes:
        return hashlib.sha256(
            b"test-opening-auth" + key.public_key_digest + message
        ).digest()

    def verify(self, key: KeyReference, message: bytes, authentication: bytes) -> bool:
        self.calls += 1
        self.roles.append(key.role)
        if self.broken:
            raise RuntimeError("test authorization verifier failure")
        return not self.reject and authentication == self.sign(key, message)


def reference_request() -> OpeningRequest:
    bundle = reference_bundle()
    authorization_key = bundle.key_for(KeyRole.OPENING_AUTHORIZATION)
    draft = OpeningRequest(
        protocol_version=1,
        ticket=TICKET_BYTES,
        ctx=bundle.ctx,
        epoch=bundle.configuration.epoch,
        opening_key_id=bundle.key_for(KeyRole.OPENING_ENCRYPTION).key_id,
        authorization_key_id=authorization_key.key_id,
        case_id=fixed_bytes(b"case-id"),
        evidence_digest=fixed_bytes(b"evidence"),
        purpose="court-authorized-investigation",
        expiry=1_900_000_000,
        request_nonce=fixed_bytes(b"request-nonce"),
        authorization=b"unsigned-test-placeholder",
    )
    return replace(
        draft,
        authorization=DigestAuthorizationVerifier.sign(
            authorization_key, draft.authorization_message
        ),
    )


class FixedClock:
    def __init__(self, timestamp: int = 1_800_000_000) -> None:
        self.timestamp = timestamp

    def now(self) -> int:
        return self.timestamp


class MemoryReplayStore:
    """Single-process model of the required atomic state machine."""

    def __init__(self) -> None:
        self.states: dict[bytes, tuple[str, bytes]] = {}
        self.abort_calls = 0
        self.commit_calls = 0
        self.break_begin = False
        self.break_commit = False
        self.break_abort = False

    def begin(self, replay_key: bytes) -> ReplayReservation | None:
        if self.break_begin:
            raise OSError("test begin failure")
        if replay_key in self.states:
            return None
        token = fixed_bytes(b"replay-token/" + replay_key)
        self.states[replay_key] = ("in_progress", token)
        return ReplayReservation(replay_key, token)

    def commit(self, reservation: ReplayReservation) -> None:
        self.commit_calls += 1
        if self.break_commit:
            raise OSError("test commit failure")
        state = self.states.get(reservation.replay_key)
        if state != ("in_progress", reservation.token):
            raise RuntimeError("wrong replay reservation")
        self.states[reservation.replay_key] = ("committed", reservation.token)

    def abort(self, reservation: ReplayReservation) -> None:
        self.abort_calls += 1
        if self.break_abort:
            raise OSError("test abort failure")
        state = self.states.get(reservation.replay_key)
        if state != ("in_progress", reservation.token):
            raise RuntimeError("wrong replay reservation")
        del self.states[reservation.replay_key]


class FixtureShareBackend:
    """Returns fixture material only; this is not threshold decryption."""

    def __init__(self, *, broken: bool = False) -> None:
        self.broken = broken
        self.calls = 0

    def create_share(self, context: ThresholdOpeningContext) -> ThresholdShareMaterial:
        self.calls += 1
        if self.broken:
            raise RuntimeError("test threshold backend failure")
        value = hashlib.sha256(
            b"test-only-share-value" + context.member_id + context.request_digest
        ).digest()
        message = share_authentication_message(
            protocol_version=1,
            member_id=context.member_id,
            opening_key_id=context.opening_key.key_id,
            epoch=context.epoch,
            request_digest=context.request_digest,
            ticket_digest=context.ticket_digest,
            case_id=context.case_id,
            share_value=value,
        )
        authentication = DigestShareVerifier.sign(context.opening_key, message)
        return ThresholdShareMaterial(value, authentication)


class DigestShareVerifier:
    """Test checksum adapter, not a share proof system."""

    @staticmethod
    def sign(key: KeyReference, message: bytes) -> bytes:
        return hashlib.sha256(
            b"test-share-auth" + key.public_key_digest + message
        ).digest()

    def verify(self, key: KeyReference, message: bytes, authentication: bytes) -> bool:
        return authentication == self.sign(key, message)


class FixtureReconstructionBackend:
    """Returns fixture plaintext only; it is not a threshold decoder."""

    def __init__(self, *, serial: bytes = VISIBLE_SERIAL, broken: bool = False) -> None:
        self.serial = serial
        self.broken = broken
        self.calls = 0

    def reconstruct(
        self, ticket: TicketView, shares: tuple[OpenShare, ...]
    ) -> DecodedTrace:
        self.calls += 1
        if self.broken:
            raise RuntimeError("test reconstruction failure")
        authentication = hashlib.sha256(
            b"test-trace-auth" + ticket.trace_ciphertext + IDENTITY + self.serial
        ).digest()
        return DecodedTrace(IDENTITY, self.serial, authentication)


class FixtureTraceAuthenticationVerifier:
    def __init__(self, *, reject: bool = False, broken: bool = False) -> None:
        self.reject = reject
        self.broken = broken

    def verify(self, ticket: TicketView, decoded: DecodedTrace) -> bool:
        if self.broken:
            raise RuntimeError("test trace authentication failure")
        expected = hashlib.sha256(
            b"test-trace-auth"
            + ticket.trace_ciphertext
            + decoded.identity
            + decoded.serial
        ).digest()
        return not self.reject and decoded.authentication_material == expected


def service(
    *,
    member_label: bytes = b"member-1",
    ticket_verifier: FixedTicketVerifier | None = None,
    authorization_verifier: DigestAuthorizationVerifier | None = None,
    replay_store: MemoryReplayStore | None = None,
    backend: FixtureShareBackend | None = None,
    configuration_verifier: DigestConfigurationVerifier | None = None,
    clock: FixedClock | None = None,
) -> tuple[
    OpenShareService,
    FixedTicketVerifier,
    DigestAuthorizationVerifier,
    MemoryReplayStore,
    FixtureShareBackend,
]:
    ticket_verifier = ticket_verifier or FixedTicketVerifier()
    authorization_verifier = authorization_verifier or DigestAuthorizationVerifier()
    replay_store = replay_store or MemoryReplayStore()
    backend = backend or FixtureShareBackend()
    envelope = reference_envelope()
    result = OpenShareService(
        authenticated_initialization=envelope.encode(),
        trusted_configuration_key=envelope.bundle.key_for(
            KeyRole.FEDERATION_CONFIGURATION
        ),
        configuration_verifier=configuration_verifier
        or DigestConfigurationVerifier(),
        ticket_verifier=ticket_verifier,
        authorization_verifier=authorization_verifier,
        replay_store=replay_store,
        threshold_backend=backend,
        clock=clock or FixedClock(),
        member_id=fixed_bytes(member_label),
    )
    return result, ticket_verifier, authorization_verifier, replay_store, backend


def honest_share(member_number: int) -> OpenShare:
    opener, _ticket, _authorization, _replay, _backend = service(
        member_label=f"member-{member_number}".encode("ascii")
    )
    outcome = opener.open_share(reference_request().encode())
    assert outcome.accepted and outcome.share is not None
    return outcome.share


def resign_share(share: OpenShare) -> OpenShare:
    opening_key = reference_bundle().key_for(KeyRole.OPENING_ENCRYPTION)
    draft = replace(share, authentication=b"test-placeholder")
    return replace(
        draft,
        authentication=DigestShareVerifier.sign(
            opening_key, draft.authentication_message
        ),
    )
