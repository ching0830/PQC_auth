"""Signature-gated OpenShare service with fail-closed validation ordering."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from pq_rbbc.contracts.system import KeyReference, KeyRole
from pq_rbbc.governance.system_init import (
    ConfigurationAuthenticationVerifier,
    verify_initialization,
)
from pq_rbbc.opening.interfaces import (
    Clock,
    OpeningAuthorizationVerifier,
    OpeningReplayStore,
    MEMBER_ID_BYTES,
    ReplayReservation,
    ThresholdOpeningContext,
    ThresholdShareBackend,
    TicketVerifier,
)
from pq_rbbc.opening.request import OpeningRequest
from pq_rbbc.opening.shares import OpenShare


@dataclass(frozen=True)
class OpenShareOutcome:
    accepted: bool
    failure: str | None
    share: OpenShare | None


class OpenShareService:
    """The sole OA-member operation exposed by the opening gate.

    The threshold backend is intentionally retained only in a private
    attribute and is invoked after every validation and replay reservation.
    """

    def __init__(
        self,
        *,
        authenticated_initialization: bytes,
        trusted_configuration_key: KeyReference,
        configuration_verifier: ConfigurationAuthenticationVerifier,
        ticket_verifier: TicketVerifier,
        authorization_verifier: OpeningAuthorizationVerifier,
        replay_store: OpeningReplayStore,
        threshold_backend: ThresholdShareBackend,
        clock: Clock,
        member_id: bytes,
    ) -> None:
        if (
            not isinstance(member_id, bytes)
            or len(member_id) != MEMBER_ID_BYTES
            or member_id == bytes(MEMBER_ID_BYTES)
        ):
            raise ValueError(
                f"member_id must be a nonzero {MEMBER_ID_BYTES}-byte value"
            )
        self._authenticated_initialization = authenticated_initialization
        self._trusted_configuration_key = trusted_configuration_key
        self._configuration_verifier = configuration_verifier
        self._ticket_verifier = ticket_verifier
        self._authorization_verifier = authorization_verifier
        self._replay_store = replay_store
        self._threshold_backend = threshold_backend
        self._clock = clock
        self._member_id = member_id

    @staticmethod
    def _reject(failure: str) -> OpenShareOutcome:
        return OpenShareOutcome(False, failure, None)

    def _abort_or_reject(
        self, reservation: ReplayReservation, original_failure: str
    ) -> OpenShareOutcome:
        try:
            self._replay_store.abort(reservation)
        except Exception as error:
            return self._reject(f"replay_abort_backend:{type(error).__name__}")
        return self._reject(original_failure)

    def open_share(self, opening_request: bytes) -> OpenShareOutcome:
        """Validate a canonical signed request and return one bound share.

        The code order below is the protocol order.  In particular, no method
        on ``_threshold_backend`` is reachable before the replay reservation.
        """

        # a. Parse the complete canonical request.
        try:
            request = OpeningRequest.decode(opening_request)
        except Exception as error:
            return self._reject(f"request_encoding:{type(error).__name__}")

        # b. Authenticate initialization against the pinned out-of-band anchor.
        initialization = verify_initialization(
            self._authenticated_initialization,
            self._trusted_configuration_key,
            self._configuration_verifier,
        )
        if not initialization.accepted or initialization.bundle is None:
            detail = (
                initialization.failures[0]
                if initialization.failures
                else "rejected"
            )
            return self._reject(f"initialization:{detail}")
        bundle = initialization.bundle

        # c. Verify the ticket before trusting any view extracted from it.
        try:
            ticket = self._ticket_verifier.verify(request.ticket)
            if ticket is None:
                return self._reject("ticket_invalid")
            ticket.validate()
        except Exception as error:
            return self._reject(f"ticket_backend:{type(error).__name__}")

        # d. Match context, epoch, and every independently role-separated key.
        opening_key = bundle.key_for(KeyRole.OPENING_ENCRYPTION)
        authorization_key = bundle.key_for(KeyRole.OPENING_AUTHORIZATION)
        issuer_key = bundle.key_for(KeyRole.ISSUER_VERIFICATION)
        if request.ctx != bundle.ctx or ticket.ctx != bundle.ctx:
            return self._reject("ctx_mismatch")
        if request.epoch != bundle.configuration.epoch:
            return self._reject("epoch_mismatch")
        if request.opening_key_id != opening_key.key_id:
            return self._reject("opening_key_id_mismatch")
        if request.authorization_key_id != authorization_key.key_id:
            return self._reject("authorization_key_id_mismatch")
        if ticket.issuer_key_id != issuer_key.key_id:
            return self._reject("issuer_key_id_mismatch")

        # e. Bind the case authorization to ticket/evidence/purpose/expiry/nonce.
        if ticket.ticket_digest != request.ticket_digest:
            return self._reject("ticket_digest_mismatch")
        try:
            now = self._clock.now()
        except Exception as error:
            return self._reject(f"clock_backend:{type(error).__name__}")
        if not isinstance(now, int) or isinstance(now, bool) or now < 0:
            return self._reject("clock_backend:invalid_time")
        if request.expiry <= now:
            return self._reject("authorization_expired")
        try:
            authorized = self._authorization_verifier.verify(
                authorization_key,
                request.authorization_message,
                request.authorization,
            )
        except Exception as error:
            return self._reject(f"authorization_backend:{type(error).__name__}")
        if authorized is not True:
            return self._reject("authorization_invalid")

        # f. Atomically reserve the case/key/nonce replay identifier.
        try:
            reservation = self._replay_store.begin(request.replay_key)
            if reservation is None:
                return self._reject("request_replay")
            reservation.validate()
            if reservation.replay_key != request.replay_key:
                return self._reject("replay_backend:wrong_reservation_key")
        except Exception as error:
            return self._reject(f"replay_begin_backend:{type(error).__name__}")

        # g. This is the first and only threshold-backend touch point.
        context = ThresholdOpeningContext(
            member_id=self._member_id,
            opening_key=opening_key,
            epoch=request.epoch,
            request_digest=request.request_digest,
            ticket_digest=ticket.ticket_digest,
            case_id=request.case_id,
            trace_ciphertext=ticket.trace_ciphertext,
        )
        try:
            context.validate()
            material = self._threshold_backend.create_share(context)
            material.validate()
            share = OpenShare(
                protocol_version=request.protocol_version,
                member_id=self._member_id,
                opening_key_id=opening_key.key_id,
                epoch=request.epoch,
                request_digest=request.request_digest,
                ticket_digest=ticket.ticket_digest,
                case_id=request.case_id,
                share_value=material.share_value,
                authentication=material.authentication,
            )
            share.encode()
        except Exception as error:
            return self._abort_or_reject(
                reservation, f"threshold_backend:{type(error).__name__}"
            )

        # Commit before exposing the share.  Commit failure is indeterminate;
        # do not abort it, because a successful commit may have raced the error.
        try:
            self._replay_store.commit(reservation)
        except Exception as error:
            return self._reject(f"replay_commit_backend:{type(error).__name__}")
        return OpenShareOutcome(True, None, share)


def conditional_opening_manifest(
    request: OpeningRequest, share: OpenShare
) -> dict[str, object]:
    """Return deterministic checkpoint metadata without secret share material."""

    request_bytes = request.encode()
    share_bytes = share.encode()
    return {
        "format": "PQRBBC-CONDITIONAL-OPENING-GATE-CHECKPOINT-1",
        "system_profile": "0.1",
        "request": {
            "bytes": len(request_bytes),
            "sha256": hashlib.sha256(request_bytes).hexdigest(),
            "request_digest": request.request_digest.hex(),
            "ticket_digest": request.ticket_digest.hex(),
            "authorization_statement_sha256": hashlib.sha256(
                request.authorization_statement
            ).hexdigest(),
        },
        "share": {
            "bytes": len(share_bytes),
            "sha256": hashlib.sha256(share_bytes).hexdigest(),
            "member_id": share.member_id.hex(),
        },
        "validation_order": [
            "parse_request",
            "verify_authenticated_initialization_and_pinned_trust_anchor",
            "verify_ticket",
            "check_ctx_epoch_and_key_ids",
            "verify_case_authorization_and_all_bindings",
            "atomic_replay_begin",
            "threshold_backend",
            "atomic_replay_commit_before_share_release",
        ],
        "claim_boundary": {
            "canonical_request_and_share_codecs_implemented": True,
            "signature_gated_control_flow_implemented": True,
            "atomic_replay_interface_defined": True,
            "combiner_control_flow_implemented": True,
            "full_verify_ticket_implemented": False,
            "oa_dkg_implemented": False,
            "robust_threshold_decoder_implemented": False,
            "production_opening_implemented": False,
        },
        "integration_blockers": {
            "trace_kdf_80_byte_split_order_unresolved": True,
            "ciphertext_decoding_kept_behind_backend_boundary": True,
        },
    }
