"""Fail-closed threshold-share combiner control-flow prototype."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from pq_rbbc.contracts.system import KeyRole, SystemInitializationBundle
from pq_rbbc.opening.interfaces import (
    DecodedTrace,
    ShareVerifier,
    ThresholdReconstructionBackend,
    TicketView,
    TraceAuthenticationVerifier,
)
from pq_rbbc.opening.shares import OpenShare


@dataclass(frozen=True)
class CombineOutcome:
    accepted: bool
    failure: str | None
    decoded: DecodedTrace | None


class OpeningCombiner:
    """Validate authenticated shares before abstract trace reconstruction.

    ``bundle`` must be the output of authenticated initialization verification,
    and ``ticket`` passed to ``combine`` must be a trusted ``TicketView`` from
    ``TicketVerifier``.  Those preconditions prevent this control-flow layer
    from silently becoming a second incomplete ticket verifier.
    """

    def __init__(
        self,
        *,
        bundle: SystemInitializationBundle,
        share_verifier: ShareVerifier,
        reconstruction_backend: ThresholdReconstructionBackend,
        trace_authentication_verifier: TraceAuthenticationVerifier,
    ) -> None:
        bundle.validate()
        self._bundle = bundle
        self._share_verifier = share_verifier
        self._reconstruction_backend = reconstruction_backend
        self._trace_authentication_verifier = trace_authentication_verifier

    @staticmethod
    def _reject(failure: str) -> CombineOutcome:
        return CombineOutcome(False, failure, None)

    def combine(
        self, ticket: TicketView, encoded_shares: Iterable[bytes]
    ) -> CombineOutcome:
        try:
            ticket.validate()
        except Exception as error:
            return self._reject(f"ticket_view:{type(error).__name__}")
        if ticket.ctx != self._bundle.ctx:
            return self._reject("ticket_ctx_mismatch")
        issuer_key = self._bundle.key_for(KeyRole.ISSUER_VERIFICATION)
        if ticket.issuer_key_id != issuer_key.key_id:
            return self._reject("ticket_issuer_key_id_mismatch")

        try:
            raw_shares = tuple(encoded_shares)
        except Exception as error:
            return self._reject(f"share_input:{type(error).__name__}")
        shares: list[OpenShare] = []
        try:
            for encoded in raw_shares:
                shares.append(OpenShare.decode(encoded))
        except Exception as error:
            return self._reject(f"invalid_share_encoding:{type(error).__name__}")

        threshold = self._bundle.opening_policy.threshold
        if len(shares) < threshold:
            return self._reject("fewer_than_threshold")
        if len(shares) > self._bundle.opening_policy.member_count:
            return self._reject("too_many_shares")
        members = [share.member_id for share in shares]
        if len(set(members)) != len(members):
            return self._reject("duplicate_member")

        first = shares[0]
        opening_key = self._bundle.key_for(KeyRole.OPENING_ENCRYPTION)
        if first.opening_key_id != opening_key.key_id:
            return self._reject("wrong_opening_key")
        if first.epoch != self._bundle.configuration.epoch:
            return self._reject("stale_epoch")
        if first.ticket_digest != ticket.ticket_digest:
            return self._reject("ticket_digest_mismatch")
        for share in shares[1:]:
            if share.request_digest != first.request_digest:
                return self._reject("mixed_request")
            if share.ticket_digest != first.ticket_digest:
                return self._reject("mixed_ticket")
            if share.epoch != first.epoch:
                return self._reject("mixed_epoch")
            if share.opening_key_id != first.opening_key_id:
                return self._reject("mixed_opening_key")
            if share.case_id != first.case_id:
                return self._reject("mixed_case")

        for share in shares:
            try:
                valid = self._share_verifier.verify(
                    opening_key,
                    share.authentication_message,
                    share.authentication,
                )
            except Exception as error:
                return self._reject(f"share_verifier_backend:{type(error).__name__}")
            if valid is not True:
                return self._reject("invalid_share")

        try:
            decoded = self._reconstruction_backend.reconstruct(ticket, tuple(shares))
            decoded.validate()
        except Exception as error:
            return self._reject(f"reconstruction_backend:{type(error).__name__}")
        try:
            trace_valid = self._trace_authentication_verifier.verify(ticket, decoded)
        except Exception as error:
            return self._reject(
                f"trace_authentication_backend:{type(error).__name__}"
            )
        if trace_valid is not True:
            return self._reject("trace_authentication_invalid")
        if decoded.serial != ticket.visible_serial:
            return self._reject("serial_mismatch")
        return CombineOutcome(True, None, decoded)
