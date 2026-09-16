from __future__ import annotations

import hashlib
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from pq_rbbc.contracts.system import KeyRole
from pq_rbbc.tickets.verification import CanonicalTicket
from pq_sat_auth.access import (
    REFERENCE_SUITE_ID,
    REFERENCE_SUITE_REGISTRY,
    AccessChallengeV1,
    AccessFinishV1,
    AccessInitV1,
    ServingContextV1,
    access_transcript_digest,
    decode_access_accept,
    encode_access_challenge,
    encode_access_finish,
    encode_access_init,
)
from pq_sat_auth.admission import (
    PUBLIC_ACCESS_REJECTION,
    AccessAdmissionOutcome,
    AdmissionDisposition,
    OneTimeAccessAdmissionService,
    PreparedAccessSession,
    SessionPreparationContext,
    one_time_access_admission_manifest,
)
from pq_sat_auth.identities import TicketUseIdentity
from pq_sat_auth.replay import (
    Consumption,
    InMemoryLinearizableReplayStore,
    Reservation,
)
from tests.system_modules.tickets.test_verification import (
    DeterministicConfigurationVerifier,
    DeterministicTicketVerifier,
    FixedClock,
    authenticated_initialization,
    authenticated_ticket,
    fixed_bytes,
    reference_bundle,
    reference_payload,
)


ROOT = Path(__file__).resolve().parents[2]
FROZEN_MANIFEST = (
    ROOT / "manifests" / "pq_sat_auth_one_time_access_admission_v0_1.json"
)
VALID_TIME = 1_800_000_000


def _digest(label: bytes, *parts: bytes) -> bytes:
    return hashlib.sha256(b"TEST-ONLY/ACCESS-ADMISSION/" + label + b"".join(parts)).digest()


def reference_serving_context() -> ServingContextV1:
    bundle = reference_bundle()
    return ServingContextV1(
        operator_id_digest=fixed_bytes(b"access/operator"),
        fgs_id_digest=fixed_bytes(b"access/fgs"),
        relay_scope_digest=fixed_bytes(b"access/relay"),
        cell_scope_digest=fixed_bytes(b"access/cell"),
        epoch=bundle.configuration.epoch,
        policy_digest=bundle.configuration.policy_digest,
    )


def _cookie_authentication(
    init: AccessInitV1,
    challenge: AccessChallengeV1,
) -> bytes:
    unsigned = replace(challenge, challenge_cookie=b"")
    return _digest(
        b"COOKIE/",
        encode_access_init(init),
        encode_access_challenge(unsigned),
    )


def _holder_authentication(
    holder_hash: bytes,
    ticket_payload_digest: bytes,
    ctx: bytes,
    serving_context_digest: bytes,
    transcript_digest: bytes,
) -> bytes:
    return _digest(
        b"HOLDER/",
        holder_hash,
        ticket_payload_digest,
        ctx,
        serving_context_digest,
        transcript_digest,
    )


def _ue_confirmation(
    ticket_payload_digest: bytes,
    ctx: bytes,
    serving_context_digest: bytes,
    transcript_digest: bytes,
    ue_key_share: bytes,
    fgs_key_share: bytes,
) -> bytes:
    return _digest(
        b"UE-CONFIRM/",
        ticket_payload_digest,
        ctx,
        serving_context_digest,
        transcript_digest,
        ue_key_share,
        fgs_key_share,
    )


class DeterministicCookieVerifier:
    """Deterministic test checksum; not an authenticated production cookie."""

    def __init__(self, *, result: object = True, broken: bool = False) -> None:
        self.result = result
        self.broken = broken
        self.calls = 0

    def verify(
        self,
        init: AccessInitV1,
        challenge: AccessChallengeV1,
        now: int,
    ) -> bool:
        self.calls += 1
        if self.broken:
            raise OSError("test cookie backend failure")
        if self.result is not True:
            return self.result  # type: ignore[return-value]
        return challenge.challenge_cookie == _cookie_authentication(init, challenge)


class DeterministicHolderVerifier:
    """Deterministic test checksum; not a holder-possession proof."""

    def __init__(
        self,
        *,
        result: object = True,
        broken: bool = False,
        before_return: object | None = None,
    ) -> None:
        self.result = result
        self.broken = broken
        self.before_return = before_return
        self.calls = 0

    def verify(
        self,
        holder_hash: bytes,
        ticket_payload_digest: bytes,
        ctx: bytes,
        serving_context_digest: bytes,
        transcript_digest: bytes,
        authenticator: bytes,
    ) -> bool:
        self.calls += 1
        if self.broken:
            raise RuntimeError("test holder backend failure")
        if self.before_return is not None:
            self.before_return()  # type: ignore[operator]
        if self.result is not True:
            return self.result  # type: ignore[return-value]
        return authenticator == _holder_authentication(
            holder_hash,
            ticket_payload_digest,
            ctx,
            serving_context_digest,
            transcript_digest,
        )


class DeterministicKeyConfirmationVerifier:
    """Deterministic test checksum; not PQ AKE key confirmation."""

    def __init__(self, *, result: object = True, broken: bool = False) -> None:
        self.result = result
        self.broken = broken
        self.calls = 0

    def verify(
        self,
        ticket_payload_digest: bytes,
        ctx: bytes,
        serving_context_digest: bytes,
        transcript_digest: bytes,
        ue_key_share: bytes,
        fgs_key_share: bytes,
        confirmation: bytes,
    ) -> bool:
        self.calls += 1
        if self.broken:
            raise RuntimeError("test key-confirmation backend failure")
        if self.result is not True:
            return self.result  # type: ignore[return-value]
        return confirmation == _ue_confirmation(
            ticket_payload_digest,
            ctx,
            serving_context_digest,
            transcript_digest,
            ue_key_share,
            fgs_key_share,
        )


class DeterministicPolicyVerifier:
    """Test-only policy decision with no resource side effects."""

    def __init__(self, *, result: object = True, broken: bool = False) -> None:
        self.result = result
        self.broken = broken
        self.calls = 0

    def authorize(self, *args: object) -> bool:
        self.calls += 1
        if self.broken:
            raise RuntimeError("test policy backend failure")
        return self.result  # type: ignore[return-value]


class DeterministicSessionBackend:
    """Produces inert deterministic material; it does not activate a session."""

    def __init__(
        self,
        *,
        broken: bool = False,
        before_return: object | None = None,
    ) -> None:
        self.broken = broken
        self.before_return = before_return
        self.calls = 0

    def prepare(self, context: SessionPreparationContext) -> PreparedAccessSession:
        self.calls += 1
        if self.broken:
            raise RuntimeError("test session preparation failure")
        if self.before_return is not None:
            self.before_return(context)  # type: ignore[operator]
        return PreparedAccessSession(
            session_id=_digest(
                b"SESSION-ID/", context.attempt_id, context.transcript_digest
            ),
            session_expiry=context.now + 600,
            fgs_key_confirmation=_digest(
                b"FGS-CONFIRM/", context.attempt_id, context.transcript_digest
            ),
        )


class CountingStore(InMemoryLinearizableReplayStore):
    def __init__(self, *, broken: str | None = None) -> None:
        super().__init__()
        self.broken = broken
        self.snapshot_calls = 0
        self.reserve_calls = 0
        self.commit_calls = 0

    def snapshot_revocation(self, identity: TicketUseIdentity):
        self.snapshot_calls += 1
        if self.broken == "snapshot":
            raise TimeoutError("test revocation partition")
        return super().snapshot_revocation(identity)

    def reserve(self, identity: TicketUseIdentity, **kwargs: object):
        self.reserve_calls += 1
        if self.broken == "reserve":
            raise TimeoutError("test reserve partition")
        return super().reserve(identity, **kwargs)  # type: ignore[arg-type]

    def commit(self, identity: TicketUseIdentity, **kwargs: object):
        self.commit_calls += 1
        if self.broken == "commit":
            raise TimeoutError("test commit partition")
        result = super().commit(identity, **kwargs)  # type: ignore[arg-type]
        if self.broken == "after_commit":
            raise TimeoutError("test lost commit acknowledgement")
        return result


def reference_flow(
    *,
    ticket: CanonicalTicket | None = None,
    attempt_label: bytes = b"primary",
    serving_context: ServingContextV1 | None = None,
    challenge_expiry: int = 1_800_001_000,
) -> tuple[AccessInitV1, AccessChallengeV1, AccessFinishV1]:
    ticket = authenticated_ticket() if ticket is None else ticket
    serving_context = reference_serving_context() if serving_context is None else serving_context
    init = AccessInitV1(
        suite_id=REFERENCE_SUITE_ID,
        ctx=ticket.payload.ctx,
        serving_context_digest=serving_context.digest,
        ue_nonce=fixed_bytes(b"access/ue-nonce/" + attempt_label),
        attempt_nonce=fixed_bytes(b"access/attempt/" + attempt_label)[:16],
        ticket=ticket.encode(),
        ue_key_share=_digest(b"UE-KEY-SHARE/", attempt_label),
    )
    unsigned_challenge = AccessChallengeV1(
        suite_id=REFERENCE_SUITE_ID,
        ctx=init.ctx,
        serving_context_digest=init.serving_context_digest,
        ue_nonce=init.ue_nonce,
        fgs_nonce=fixed_bytes(b"access/fgs-nonce/" + attempt_label),
        attempt_nonce=init.attempt_nonce,
        challenge_expiry=challenge_expiry,
        fgs_key_share=_digest(b"FGS-KEY-SHARE/", attempt_label),
        challenge_cookie=b"",
    )
    challenge = replace(
        unsigned_challenge,
        challenge_cookie=_cookie_authentication(init, unsigned_challenge),
    )
    draft_finish = AccessFinishV1(
        suite_id=REFERENCE_SUITE_ID,
        ctx=init.ctx,
        serving_context_digest=init.serving_context_digest,
        ue_nonce=init.ue_nonce,
        fgs_nonce=challenge.fgs_nonce,
        attempt_nonce=init.attempt_nonce,
        challenge_cookie=challenge.challenge_cookie,
        holder_authenticator=b"",
        ue_key_confirmation=b"",
    )
    transcript = access_transcript_digest(init, challenge, draft_finish)
    finish = replace(
        draft_finish,
        holder_authenticator=_holder_authentication(
            ticket.payload.holder_hash,
            ticket.payload_digest,
            ticket.payload.ctx,
            init.serving_context_digest,
            transcript,
        ),
        ue_key_confirmation=_ue_confirmation(
            ticket.payload_digest,
            ticket.payload.ctx,
            init.serving_context_digest,
            transcript,
            init.ue_key_share,
            challenge.fgs_key_share,
        ),
    )
    return init, challenge, finish


def encode_flow(
    flow: tuple[AccessInitV1, AccessChallengeV1, AccessFinishV1]
) -> tuple[bytes, bytes, bytes]:
    init, challenge, finish = flow
    return (
        encode_access_init(init),
        encode_access_challenge(challenge),
        encode_access_finish(finish),
    )


def service_fixture(
    *,
    initialization_verifier: object | None = None,
    ticket_verifier: object | None = None,
    clock: object | None = None,
    serving_context: ServingContextV1 | None = None,
    cookie_verifier: object | None = None,
    holder_verifier: object | None = None,
    key_confirmation_verifier: object | None = None,
    policy_verifier: object | None = None,
    store: CountingStore | None = None,
    session_backend: object | None = None,
    trusted_configuration_key: object | None = None,
) -> tuple[OneTimeAccessAdmissionService, dict[str, object]]:
    initialization = authenticated_initialization()
    backends: dict[str, object] = {
        "initialization": initialization_verifier
        or DeterministicConfigurationVerifier(),
        "ticket": ticket_verifier or DeterministicTicketVerifier(),
        "clock": clock or FixedClock(VALID_TIME),
        "cookie": cookie_verifier or DeterministicCookieVerifier(),
        "holder": holder_verifier or DeterministicHolderVerifier(),
        "key_confirmation": key_confirmation_verifier
        or DeterministicKeyConfirmationVerifier(),
        "policy": policy_verifier or DeterministicPolicyVerifier(),
        "store": CountingStore() if store is None else store,
        "session": session_backend or DeterministicSessionBackend(),
    }
    service = OneTimeAccessAdmissionService(
        authenticated_initialization=initialization.encode(),
        trusted_configuration_key=(
            initialization.bundle.key_for(KeyRole.FEDERATION_CONFIGURATION)
            if trusted_configuration_key is None
            else trusted_configuration_key  # type: ignore[arg-type]
        ),
        initialization_verifier=backends["initialization"],  # type: ignore[arg-type]
        ticket_verifier=backends["ticket"],  # type: ignore[arg-type]
        clock=backends["clock"],  # type: ignore[arg-type]
        serving_context=serving_context or reference_serving_context(),
        suite_registry=REFERENCE_SUITE_REGISTRY,
        cookie_verifier=backends["cookie"],  # type: ignore[arg-type]
        holder_verifier=backends["holder"],  # type: ignore[arg-type]
        key_confirmation_verifier=backends["key_confirmation"],  # type: ignore[arg-type]
        policy_verifier=backends["policy"],  # type: ignore[arg-type]
        store=backends["store"],  # type: ignore[arg-type]
        session_backend=backends["session"],  # type: ignore[arg-type]
        reservation_lease=30,
        maximum_clock_skew=5,
        replay_grace=60,
    )
    return service, backends


def admit(
    service: OneTimeAccessAdmissionService,
    flow: tuple[AccessInitV1, AccessChallengeV1, AccessFinishV1],
) -> AccessAdmissionOutcome:
    return service.admit(*encode_flow(flow))


class OneTimeAccessAdmissionTests(unittest.TestCase):
    def test_honest_admission_consumes_payload_identity(self) -> None:
        flow = reference_flow()
        ticket = CanonicalTicket.decode(flow[0].ticket)
        service, backends = service_fixture()

        outcome = admit(service, flow)

        self.assertEqual(outcome.disposition, AdmissionDisposition.ACCEPTED)
        self.assertTrue(outcome.accepted)
        self.assertIsNotNone(outcome.response)
        identity = TicketUseIdentity(
            ticket.payload.ctx,
            ticket.payload.sn,
            ticket.payload_digest,
        )
        self.assertEqual(outcome.use_key, identity.use_key)
        self.assertNotEqual(ticket.payload_digest, ticket.canonical_digest)
        record = backends["store"].lookup(identity)  # type: ignore[attr-defined]
        self.assertIsInstance(record, Consumption)
        self.assertEqual(backends["initialization"].calls, 2)  # type: ignore[attr-defined]
        self.assertEqual(backends["ticket"].calls, 1)  # type: ignore[attr-defined]
        self.assertEqual(backends["session"].calls, 1)  # type: ignore[attr-defined]

    def test_same_attempt_retry_recovers_exact_response(self) -> None:
        flow = reference_flow()
        service, backends = service_fixture()
        first = admit(service, flow)
        retry = admit(service, flow)

        self.assertEqual(first.disposition, AdmissionDisposition.ACCEPTED)
        self.assertEqual(retry.disposition, AdmissionDisposition.IDEMPOTENT_RETRY)
        self.assertEqual(retry.response, first.response)
        self.assertEqual(retry.attempt_id, first.attempt_id)
        self.assertEqual(backends["session"].calls, 1)  # type: ignore[attr-defined]
        self.assertEqual(len(backends["store"]), 1)  # type: ignore[arg-type]

    def test_different_attempt_cannot_reuse_consumed_ticket(self) -> None:
        service, backends = service_fixture()
        first = admit(service, reference_flow(attempt_label=b"first"))
        second = admit(service, reference_flow(attempt_label=b"second"))

        self.assertTrue(first.accepted)
        self.assertEqual(second.disposition, AdmissionDisposition.REJECTED)
        self.assertEqual(second.public_failure, PUBLIC_ACCESS_REJECTION)
        self.assertIsNone(second.response)
        self.assertEqual(backends["session"].calls, 1)  # type: ignore[attr-defined]
        self.assertEqual(len(backends["store"]), 1)  # type: ignore[arg-type]

    def test_parallel_distinct_attempts_have_exactly_one_session(self) -> None:
        workers = 16
        service, backends = service_fixture()
        flows = [
            reference_flow(attempt_label=f"parallel-{index}".encode("ascii"))
            for index in range(workers)
        ]
        barrier = threading.Barrier(workers)

        def compete(flow):
            barrier.wait()
            return admit(service, flow)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            outcomes = list(executor.map(compete, flows))

        self.assertEqual(
            sum(item.disposition is AdmissionDisposition.ACCEPTED for item in outcomes),
            1,
        )
        self.assertEqual(sum(item.accepted for item in outcomes), 1)
        self.assertEqual(backends["session"].calls, 1)  # type: ignore[attr-defined]
        self.assertEqual(len(backends["store"]), 1)  # type: ignore[arg-type]

    def test_invalid_ticket_signature_never_touches_consumption_store(self) -> None:
        ticket = authenticated_ticket()
        ticket = replace(
            ticket,
            signature=ticket.signature[:-1] + bytes([ticket.signature[-1] ^ 1]),
        )
        service, backends = service_fixture()
        outcome = admit(service, reference_flow(ticket=ticket))

        self.assertEqual(outcome.public_failure, PUBLIC_ACCESS_REJECTION)
        self.assertEqual(outcome.audit_reason, "ticket_invalid")
        store = backends["store"]
        self.assertEqual(store.snapshot_calls, 0)  # type: ignore[attr-defined]
        self.assertEqual(store.reserve_calls, 0)  # type: ignore[attr-defined]
        self.assertEqual(len(store), 0)  # type: ignore[arg-type]

    def test_context_flow_and_expiry_mutations_do_not_consume(self) -> None:
        honest = reference_flow()
        init, challenge, finish = honest
        mutations = (
            (replace(init, ctx=fixed_bytes(b"wrong/access/ctx")), challenge, finish),
            (init, replace(challenge, ue_nonce=fixed_bytes(b"wrong/ue-nonce")), finish),
            reference_flow(challenge_expiry=VALID_TIME),
        )
        for changed in mutations:
            with self.subTest(changed=changed):
                service, backends = service_fixture()
                outcome = admit(service, changed)
                self.assertFalse(outcome.accepted)
                self.assertEqual(len(backends["store"]), 0)  # type: ignore[arg-type]

        wrong_context = replace(
            reference_serving_context(),
            policy_digest=fixed_bytes(b"wrong/access/policy"),
        )
        service, backends = service_fixture(serving_context=wrong_context)
        outcome = admit(service, honest)
        self.assertFalse(outcome.accepted)
        self.assertEqual(len(backends["store"]), 0)  # type: ignore[arg-type]

    def test_unknown_version_truncation_and_trailing_bytes_fail_closed(self) -> None:
        encoded = list(encode_flow(reference_flow()))
        wrong_version = encoded[0][:8] + b"\x00\x02" + encoded[0][10:]
        unknown_suite = encoded[0][:16] + b"\x00\x01" + encoded[0][18:]
        cases = (
            wrong_version,
            unknown_suite,
            encoded[0][:-1],
            encoded[0] + b"\x00",
        )
        for malformed in cases:
            with self.subTest(length=len(malformed)):
                service, backends = service_fixture()
                outcome = service.admit(malformed, encoded[1], encoded[2])
                self.assertFalse(outcome.accepted)
                self.assertEqual(len(backends["store"]), 0)  # type: ignore[arg-type]

    def test_each_pure_validation_backend_fails_before_reservation(self) -> None:
        cases = (
            ("cookie_verifier", DeterministicCookieVerifier(result=False)),
            ("holder_verifier", DeterministicHolderVerifier(result=False)),
            (
                "key_confirmation_verifier",
                DeterministicKeyConfirmationVerifier(result=False),
            ),
            ("policy_verifier", DeterministicPolicyVerifier(result=False)),
        )
        for name, backend in cases:
            with self.subTest(backend=name):
                service, backends = service_fixture(**{name: backend})
                outcome = admit(service, reference_flow())
                self.assertFalse(outcome.accepted)
                store = backends["store"]
                self.assertEqual(store.reserve_calls, 0)  # type: ignore[attr-defined]
                self.assertEqual(len(store), 0)  # type: ignore[arg-type]

    def test_authentication_backend_exceptions_fail_closed(self) -> None:
        cases = (
            (
                "initialization_verifier",
                DeterministicConfigurationVerifier(broken=True),
            ),
            ("clock", FixedClock(broken=True)),
            ("ticket_verifier", DeterministicTicketVerifier(broken=True)),
            ("cookie_verifier", DeterministicCookieVerifier(broken=True)),
            ("holder_verifier", DeterministicHolderVerifier(broken=True)),
            (
                "key_confirmation_verifier",
                DeterministicKeyConfirmationVerifier(broken=True),
            ),
            ("policy_verifier", DeterministicPolicyVerifier(broken=True)),
        )
        for name, backend in cases:
            with self.subTest(backend=name):
                service, backends = service_fixture(**{name: backend})
                outcome = admit(service, reference_flow())
                self.assertFalse(outcome.accepted)
                self.assertEqual(len(backends["store"]), 0)  # type: ignore[arg-type]

    def test_non_boolean_backend_success_is_rejected(self) -> None:
        cases = (
            ("cookie_verifier", DeterministicCookieVerifier(result=1)),
            ("holder_verifier", DeterministicHolderVerifier(result=1)),
            (
                "key_confirmation_verifier",
                DeterministicKeyConfirmationVerifier(result=1),
            ),
            ("policy_verifier", DeterministicPolicyVerifier(result=1)),
        )
        for name, backend in cases:
            with self.subTest(backend=name):
                service, backends = service_fixture(**{name: backend})
                outcome = admit(service, reference_flow())
                self.assertFalse(outcome.accepted)
                self.assertEqual(len(backends["store"]), 0)  # type: ignore[arg-type]

    def test_wrong_pinned_initialization_trust_anchor_fails_closed(self) -> None:
        correct = reference_bundle().key_for(KeyRole.FEDERATION_CONFIGURATION)
        wrong = replace(
            correct,
            key_id=fixed_bytes(b"wrong/access/trust-anchor"),
            public_key_digest=fixed_bytes(b"wrong/access/trust-key"),
        )
        service, backends = service_fixture(trusted_configuration_key=wrong)

        outcome = admit(service, reference_flow())

        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.audit_reason, "initialization_invalid")
        self.assertEqual(len(backends["store"]), 0)  # type: ignore[arg-type]

    def test_revoked_ticket_and_revocation_race_fail_closed(self) -> None:
        ticket = authenticated_ticket()
        identity = TicketUseIdentity(
            ticket.payload.ctx,
            ticket.payload.sn,
            ticket.payload_digest,
        )
        revoked_store = CountingStore()
        revoked_store.revoke(identity)
        service, _backends = service_fixture(store=revoked_store)
        outcome = admit(service, reference_flow(ticket=ticket))
        self.assertFalse(outcome.accepted)
        self.assertEqual(revoked_store.reserve_calls, 0)
        self.assertEqual(len(revoked_store), 0)

        racing_store = CountingStore()
        holder = DeterministicHolderVerifier(
            before_return=lambda: racing_store.revoke(identity)
        )
        service, _backends = service_fixture(
            store=racing_store,
            holder_verifier=holder,
        )
        outcome = admit(service, reference_flow(ticket=ticket))
        self.assertFalse(outcome.accepted)
        self.assertIn("RevocationChanged", outcome.audit_reason or "")
        self.assertEqual(racing_store.reserve_calls, 1)
        self.assertEqual(len(racing_store), 0)

        commit_racing_store = CountingStore()
        session = DeterministicSessionBackend(
            before_return=lambda context: commit_racing_store.revoke(
                context.identity
            )
        )
        service, _backends = service_fixture(
            store=commit_racing_store,
            session_backend=session,
        )
        outcome = admit(service, reference_flow(ticket=ticket))
        self.assertFalse(outcome.accepted)
        self.assertIn("RevocationChanged", outcome.audit_reason or "")
        self.assertEqual(commit_racing_store.commit_calls, 1)
        self.assertEqual(len(commit_racing_store), 1)
        self.assertIsInstance(
            commit_racing_store.lookup(identity),
            Reservation,
        )

    def test_session_preparation_failure_stays_reserved(self) -> None:
        session = DeterministicSessionBackend(broken=True)
        service, backends = service_fixture(session_backend=session)
        flow = reference_flow()

        first = admit(service, flow)
        retry = admit(service, flow)

        self.assertFalse(first.accepted)
        self.assertEqual(retry.disposition, AdmissionDisposition.PENDING)
        self.assertEqual(session.calls, 1)
        store = backends["store"]
        self.assertEqual(len(store), 1)  # type: ignore[arg-type]
        ticket = CanonicalTicket.decode(flow[0].ticket)
        identity = TicketUseIdentity(
            ticket.payload.ctx, ticket.payload.sn, ticket.payload_digest
        )
        self.assertIsInstance(store.lookup(identity), Reservation)  # type: ignore[attr-defined]

    def test_lost_commit_acknowledgement_recovers_same_response(self) -> None:
        store = CountingStore(broken="after_commit")
        service, backends = service_fixture(store=store)
        flow = reference_flow()

        first = admit(service, flow)
        store.broken = None
        retry = admit(service, flow)

        self.assertFalse(first.accepted)
        self.assertEqual(retry.disposition, AdmissionDisposition.IDEMPOTENT_RETRY)
        self.assertIsNotNone(retry.response)
        self.assertEqual(backends["session"].calls, 1)  # type: ignore[attr-defined]
        self.assertEqual(len(store), 1)

    def test_store_partition_at_every_boundary_fails_closed(self) -> None:
        for stage in ("snapshot", "reserve", "commit"):
            with self.subTest(stage=stage):
                store = CountingStore(broken=stage)
                service, backends = service_fixture(store=store)
                outcome = admit(service, reference_flow())
                self.assertFalse(outcome.accepted)
                self.assertIsNone(outcome.response)
                if stage in ("snapshot", "reserve"):
                    self.assertEqual(len(store), 0)
                else:
                    self.assertEqual(len(store), 1)
                    self.assertEqual(backends["session"].calls, 1)  # type: ignore[attr-defined]

    def test_same_serial_with_different_payload_digest_is_rejected(self) -> None:
        first_ticket = authenticated_ticket()
        changed_payload = replace(
            reference_payload(),
            tag=fixed_bytes(b"different/trace-tag"),
        )
        second_ticket = authenticated_ticket(payload=changed_payload)
        self.assertEqual(first_ticket.payload.sn, second_ticket.payload.sn)
        self.assertNotEqual(first_ticket.payload_digest, second_ticket.payload_digest)
        service, backends = service_fixture()

        first = admit(service, reference_flow(ticket=first_ticket, attempt_label=b"one"))
        second = admit(service, reference_flow(ticket=second_ticket, attempt_label=b"two"))

        self.assertTrue(first.accepted)
        self.assertFalse(second.accepted)
        self.assertIn("IdentityConflict", second.audit_reason or "")
        self.assertEqual(len(backends["store"]), 1)  # type: ignore[arg-type]

    def test_exact_frozen_manifest_and_conservative_claims(self) -> None:
        flow = reference_flow()
        service, _backends = service_fixture()
        outcome = admit(service, flow)
        self.assertTrue(outcome.accepted)
        assert outcome.response is not None
        ticket = CanonicalTicket.decode(flow[0].ticket)
        manifest = one_time_access_admission_manifest(
            *flow,
            ticket.payload_digest,
            outcome.response,
            suite_registry=REFERENCE_SUITE_REGISTRY,
        )

        self.assertEqual(manifest, json.loads(FROZEN_MANIFEST.read_text()))
        claims = manifest["claim_boundary"]
        self.assertTrue(claims["real_verify_ticket_integrated"])
        self.assertTrue(claims["payload_identity_used_for_consumption"])
        self.assertFalse(claims["test_only_suite_is_cryptographic"])
        self.assertFalse(claims["production_holder_authentication_implemented"])
        self.assertFalse(claims["production_pq_ake_implemented"])
        self.assertFalse(claims["durable_or_distributed_store_implemented"])
        self.assertFalse(claims["cross_fgs_strictly_one_use_proven"])
        self.assertFalse(claims["production_access_admission_complete"])


if __name__ == "__main__":
    unittest.main()
