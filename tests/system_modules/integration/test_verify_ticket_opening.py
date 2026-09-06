#!/usr/bin/env python3
"""VerifyTicket-to-Conditional-Opening integration checkpoint tests."""

from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path

from pq_rbbc.contracts.system import KeyReference, KeyRole
from pq_rbbc.governance.system_init import verify_initialization
from pq_rbbc.opening.combiner import OpeningCombiner
from pq_rbbc.opening.gate import OpenShareService
from pq_rbbc.opening.request import OpeningRequest
from pq_rbbc.tickets.verification import CanonicalTicket, SystemTicketVerifier

from tests.system_modules.opening._fixtures import (
    DigestAuthorizationVerifier,
    DigestShareVerifier,
    FixtureReconstructionBackend,
    FixtureShareBackend,
    FixtureTraceAuthenticationVerifier,
    MemoryReplayStore,
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


ROOT = Path(__file__).resolve().parents[3]
FROZEN_MANIFEST = (
    ROOT
    / "manifests"
    / "pq_rbbc_verify_ticket_opening_integration_v0_1.json"
)
VALID_TIME = 1_800_000_000


def reference_request(
    canonical_ticket: bytes,
    *,
    case_label: bytes = b"case-id/primary",
    nonce_label: bytes = b"request-nonce/primary",
) -> OpeningRequest:
    bundle = reference_bundle()
    authorization_key = bundle.key_for(KeyRole.OPENING_AUTHORIZATION)
    draft = OpeningRequest(
        protocol_version=bundle.configuration.protocol_version,
        ticket=canonical_ticket,
        ctx=bundle.ctx,
        epoch=bundle.configuration.epoch,
        opening_key_id=bundle.key_for(KeyRole.OPENING_ENCRYPTION).key_id,
        authorization_key_id=authorization_key.key_id,
        case_id=fixed_bytes(case_label),
        evidence_digest=fixed_bytes(b"opening-evidence"),
        purpose="federation-authorized-trace",
        expiry=1_890_000_000,
        request_nonce=fixed_bytes(nonce_label),
        authorization=b"unsigned-test-placeholder",
    )
    return replace(
        draft,
        authorization=DigestAuthorizationVerifier.sign(
            authorization_key,
            draft.authorization_message,
        ),
    )


def integration_service(
    *,
    member_label: bytes = b"member-1",
    ticket_backend: DeterministicTicketVerifier | None = None,
    ticket_clock: FixedClock | None = None,
    ticket_trust_anchor: KeyReference | None = None,
) -> tuple[
    OpenShareService,
    DeterministicConfigurationVerifier,
    DeterministicTicketVerifier,
    DigestAuthorizationVerifier,
    MemoryReplayStore,
    FixtureShareBackend,
]:
    initialization = authenticated_initialization()
    bundle = initialization.bundle
    configuration_backend = DeterministicConfigurationVerifier()
    ticket_backend = ticket_backend or DeterministicTicketVerifier()
    clock = ticket_clock or FixedClock(VALID_TIME)
    ticket_adapter = SystemTicketVerifier(
        authenticated_initialization=initialization.encode(),
        trusted_configuration_key=(
            bundle.key_for(KeyRole.FEDERATION_CONFIGURATION)
            if ticket_trust_anchor is None
            else ticket_trust_anchor
        ),
        initialization_verifier=configuration_backend,
        ticket_verifier=ticket_backend,
        clock=clock,
    )
    authorization_backend = DigestAuthorizationVerifier()
    replay_store = MemoryReplayStore()
    share_backend = FixtureShareBackend()
    service = OpenShareService(
        authenticated_initialization=initialization.encode(),
        trusted_configuration_key=bundle.key_for(
            KeyRole.FEDERATION_CONFIGURATION
        ),
        configuration_verifier=configuration_backend,
        ticket_verifier=ticket_adapter,
        authorization_verifier=authorization_backend,
        replay_store=replay_store,
        threshold_backend=share_backend,
        clock=clock,
        member_id=fixed_bytes(member_label),
    )
    return (
        service,
        configuration_backend,
        ticket_backend,
        authorization_backend,
        replay_store,
        share_backend,
    )


def integration_manifest(
    ticket: CanonicalTicket,
    request: OpeningRequest,
    share_bytes: bytes,
) -> dict[str, object]:
    canonical_ticket = ticket.encode()
    request_bytes = request.encode()
    return {
        "format": "PQRBBC-VERIFY-TICKET-OPENING-INTEGRATION-CHECKPOINT-1",
        "system_profile": "0.1",
        "parent_verify_ticket_commit": (
            "28980cfdcac030abc2fbcb0b84288c47dcd72fda"
        ),
        "ticket": {
            "bytes": len(canonical_ticket),
            "sha256": hashlib.sha256(canonical_ticket).hexdigest(),
            "payload_digest": ticket.payload_digest.hex(),
            "ctx": ticket.payload.ctx.hex(),
            "visible_serial": ticket.payload.sn.hex(),
            "issuer_key_id": ticket.issuer_key_id.hex(),
        },
        "opening_request": {
            "bytes": len(request_bytes),
            "sha256": hashlib.sha256(request_bytes).hexdigest(),
            "request_digest": request.request_digest.hex(),
            "ticket_digest": request.ticket_digest.hex(),
        },
        "open_share": {
            "bytes": len(share_bytes),
            "sha256": hashlib.sha256(share_bytes).hexdigest(),
        },
        "cross_module_bindings": {
            "request_ticket_digest_equals_verified_transport_digest": True,
            "share_ticket_digest_equals_verified_transport_digest": True,
            "ticket_ctx_equals_authenticated_bundle_ctx": True,
            "ticket_issuer_key_equals_bundle_issuer_verification_key": True,
            "threshold_combiner_accepts_gate_outputs": True,
        },
        "validation_order": [
            "parse_opening_request",
            "verify_opening_service_initialization",
            "verify_ticket_initialization",
            "strict_parse_canonical_ticket",
            "check_ticket_ctx_role_key_and_configuration_expiry",
            "verify_ticket_payload_digest_under_issuer_verification_key",
            "check_opening_request_ctx_epoch_keys_and_ticket_digest",
            "verify_opening_authorization",
            "atomic_opening_replay_begin",
            "test_only_share_backend",
            "atomic_opening_replay_commit",
            "validate_threshold_shares",
            "test_only_reconstruction_and_trace_authentication",
        ],
        "claim_boundary": {
            "verify_ticket_to_open_share_connected": True,
            "threshold_combiner_control_flow_connected": True,
            "fixed_ticket_verifier_used": False,
            "production_source_modified": False,
            "deterministic_backends_test_only": True,
            "ticket_verification_stateless": True,
            "ticket_consumption_implemented": False,
            "holder_authentication_implemented": False,
            "production_blind_uov_backend_instantiated": False,
            "production_threshold_opening_instantiated": False,
            "production_verify_ticket_complete": False,
            "production_opening_complete": False,
        },
    }


class VerifyTicketOpeningIntegrationTests(unittest.TestCase):
    def test_honest_ticket_reaches_signature_gated_open_share(self) -> None:
        ticket = authenticated_ticket()
        request = reference_request(ticket.encode())
        (
            service,
            configuration_backend,
            ticket_backend,
            authorization_backend,
            replay_store,
            share_backend,
        ) = integration_service()

        outcome = service.open_share(request.encode())

        self.assertTrue(outcome.accepted, outcome.failure)
        self.assertIsNotNone(outcome.share)
        assert outcome.share is not None
        self.assertEqual(outcome.share.ticket_digest, ticket.canonical_digest)
        self.assertEqual(outcome.share.ticket_digest, request.ticket_digest)
        self.assertEqual(configuration_backend.calls, 2)
        self.assertEqual(ticket_backend.calls, 1)
        self.assertEqual(
            ticket_backend.keys[0],
            reference_bundle().key_for(KeyRole.ISSUER_VERIFICATION),
        )
        self.assertEqual(ticket_backend.message_digests, [ticket.payload_digest])
        self.assertEqual(authorization_backend.calls, 1)
        self.assertEqual(
            authorization_backend.roles,
            [KeyRole.OPENING_AUTHORIZATION],
        )
        self.assertEqual(replay_store.commit_calls, 1)
        self.assertEqual(share_backend.calls, 1)

    def test_threshold_gate_outputs_reach_existing_combiner(self) -> None:
        ticket = authenticated_ticket()
        encoded_ticket = ticket.encode()
        request = reference_request(encoded_ticket)
        bundle = reference_bundle()
        shares = []
        for member_number in range(1, bundle.opening_policy.threshold + 1):
            service, *_backends = integration_service(
                member_label=f"member-{member_number}".encode("ascii")
            )
            outcome = service.open_share(request.encode())
            self.assertTrue(outcome.accepted, outcome.failure)
            assert outcome.share is not None
            shares.append(outcome.share.encode())

        initialization = authenticated_initialization()
        verification = verify_initialization(
            initialization.encode(),
            initialization.bundle.key_for(KeyRole.FEDERATION_CONFIGURATION),
            DeterministicConfigurationVerifier(),
        )
        self.assertTrue(verification.accepted, verification.failures)
        assert verification.bundle is not None
        ticket_view = SystemTicketVerifier(
            authenticated_initialization=initialization.encode(),
            trusted_configuration_key=initialization.bundle.key_for(
                KeyRole.FEDERATION_CONFIGURATION
            ),
            initialization_verifier=DeterministicConfigurationVerifier(),
            ticket_verifier=DeterministicTicketVerifier(),
            clock=FixedClock(VALID_TIME),
        ).verify(encoded_ticket)
        self.assertIsNotNone(ticket_view)
        assert ticket_view is not None

        reconstruction = FixtureReconstructionBackend(
            serial=ticket.payload.sn
        )
        combiner = OpeningCombiner(
            bundle=verification.bundle,
            share_verifier=DigestShareVerifier(),
            reconstruction_backend=reconstruction,
            trace_authentication_verifier=(
                FixtureTraceAuthenticationVerifier()
            ),
        )
        combined = combiner.combine(ticket_view, shares)

        self.assertTrue(combined.accepted, combined.failure)
        self.assertIsNotNone(combined.decoded)
        assert combined.decoded is not None
        self.assertEqual(combined.decoded.serial, ticket.payload.sn)
        self.assertEqual(reconstruction.calls, 1)

    def test_signature_mutation_rejects_before_opening_authorization(self) -> None:
        encoded = authenticated_ticket().encode()
        mutated = encoded[:-1] + bytes([encoded[-1] ^ 1])
        request = reference_request(mutated)
        (
            service,
            _configuration,
            ticket_backend,
            authorization_backend,
            replay_store,
            share_backend,
        ) = integration_service()

        outcome = service.open_share(request.encode())

        self.assertEqual(outcome.failure, "ticket_invalid")
        self.assertEqual(ticket_backend.calls, 1)
        self.assertEqual(authorization_backend.calls, 0)
        self.assertEqual(replay_store.commit_calls, 0)
        self.assertEqual(share_backend.calls, 0)

    def test_reauthenticated_wrong_ctx_ticket_rejects_before_opening(self) -> None:
        payload = reference_payload()
        mutated_payload = replace(
            payload,
            ctx=bytes([payload.ctx[0] ^ 1]) + payload.ctx[1:],
        )
        ticket = authenticated_ticket(payload=mutated_payload)
        request = reference_request(ticket.encode())
        (
            service,
            _configuration,
            ticket_backend,
            authorization_backend,
            replay_store,
            share_backend,
        ) = integration_service()

        outcome = service.open_share(request.encode())

        self.assertEqual(outcome.failure, "ticket_invalid")
        self.assertEqual(ticket_backend.calls, 0)
        self.assertEqual(authorization_backend.calls, 0)
        self.assertEqual(replay_store.commit_calls, 0)
        self.assertEqual(share_backend.calls, 0)

    def test_wrong_ticket_role_and_inner_trust_anchor_reject(self) -> None:
        wrong_role = authenticated_ticket(
            signing_role=KeyRole.OPENING_AUTHORIZATION
        )
        service, *_backends = integration_service()
        outcome = service.open_share(
            reference_request(wrong_role.encode()).encode()
        )
        self.assertEqual(outcome.failure, "ticket_invalid")

        advertised = reference_bundle().key_for(
            KeyRole.FEDERATION_CONFIGURATION
        )
        wrong_anchor = replace(
            advertised,
            key_id=fixed_bytes(b"wrong-inner-anchor/key-id"),
            public_key_digest=fixed_bytes(b"wrong-inner-anchor/public-key"),
        )
        service, *_backends = integration_service(
            ticket_trust_anchor=wrong_anchor
        )
        ticket = authenticated_ticket()
        outcome = service.open_share(
            reference_request(ticket.encode()).encode()
        )
        self.assertEqual(outcome.failure, "ticket_invalid")

    def test_ticket_backend_exception_and_expiry_fail_closed(self) -> None:
        ticket = authenticated_ticket()
        request = reference_request(ticket.encode())
        service, *_backends = integration_service(
            ticket_backend=DeterministicTicketVerifier(broken=True)
        )
        outcome = service.open_share(request.encode())
        self.assertEqual(outcome.failure, "ticket_invalid")

        expiry = reference_bundle().configuration.expiry_bucket
        service, *_backends = integration_service(
            ticket_clock=FixedClock(expiry)
        )
        outcome = service.open_share(request.encode())
        self.assertEqual(outcome.failure, "ticket_invalid")

    def test_distinct_opening_cases_do_not_consume_stateless_ticket(self) -> None:
        ticket = authenticated_ticket()
        service, _configuration, ticket_backend, *_rest = integration_service()
        first = reference_request(ticket.encode())
        second = reference_request(
            ticket.encode(),
            case_label=b"case-id/secondary",
            nonce_label=b"request-nonce/secondary",
        )

        first_outcome = service.open_share(first.encode())
        second_outcome = service.open_share(second.encode())

        self.assertTrue(first_outcome.accepted, first_outcome.failure)
        self.assertTrue(second_outcome.accepted, second_outcome.failure)
        self.assertEqual(ticket_backend.calls, 2)

    def test_exact_integration_manifest_and_conservative_claims(self) -> None:
        ticket = authenticated_ticket()
        request = reference_request(ticket.encode())
        service, *_backends = integration_service()
        outcome = service.open_share(request.encode())
        self.assertTrue(outcome.accepted, outcome.failure)
        assert outcome.share is not None

        manifest = integration_manifest(
            ticket,
            request,
            outcome.share.encode(),
        )
        self.assertEqual(manifest, json.loads(FROZEN_MANIFEST.read_text()))
        claims = manifest["claim_boundary"]
        self.assertFalse(claims["fixed_ticket_verifier_used"])
        self.assertFalse(claims["production_source_modified"])
        self.assertFalse(claims["ticket_consumption_implemented"])
        self.assertFalse(claims["production_verify_ticket_complete"])
        self.assertFalse(claims["production_opening_complete"])


if __name__ == "__main__":
    unittest.main()
