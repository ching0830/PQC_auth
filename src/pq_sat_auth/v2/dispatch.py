"""Idempotent application-dispatch contract for the FGS durable inbox."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from .access import DIGEST_BYTES, SESSION_ID_BYTES
from .application import (
    FirstApplicationInboxEntryV2,
    FirstApplicationInboxStateV2,
    FirstApplicationInboxStoreV2,
    FirstRecordOutboxConflictError,
    MAX_APPLICATION_RECEIPT_BYTES,
    derive_first_application_plaintext_digest,
)


PRODUCTION_READY = False


def _fixed(value: bytes, size: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    return value


def _receipt(value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError("application receipt must be bytes")
    if not value:
        raise ValueError("application receipt must not be empty")
    if len(value) > MAX_APPLICATION_RECEIPT_BYTES:
        raise ValueError("application receipt exceeds the v0.2 maximum")
    return value


class ApplicationApplyDispositionV2(Enum):
    APPLIED = "applied"
    EXISTING = "existing"


@dataclass(frozen=True)
class ApplicationApplyResultV2:
    disposition: ApplicationApplyDispositionV2
    idempotency_key: bytes
    plaintext_digest: bytes
    receipt: bytes

    def validate(self) -> None:
        if not isinstance(self.disposition, ApplicationApplyDispositionV2):
            raise TypeError("application apply disposition has the wrong type")
        _fixed(self.idempotency_key, DIGEST_BYTES, "idempotency_key")
        _fixed(self.plaintext_digest, DIGEST_BYTES, "plaintext_digest")
        _receipt(self.receipt)


class IdempotentApplicationBackendV2(Protocol):
    production_ready: bool
    durable: bool

    def apply_once(
        self,
        idempotency_key: bytes,
        plaintext: bytes,
    ) -> ApplicationApplyResultV2: ...


class ApplicationDispatchDispositionV2(Enum):
    COMPLETED = "completed"
    RECOVERED_COMPLETION = "recovered_completion"
    ALREADY_COMPLETED = "already_completed"
    REJECTED = "rejected"
    COMMIT_UNCERTAIN = "commit_uncertain"


@dataclass(frozen=True)
class ApplicationDispatchResultV2:
    accepted: bool
    disposition: ApplicationDispatchDispositionV2
    failures: tuple[str, ...]
    session_id: bytes | None
    record_digest: bytes | None
    receipt: bytes | None


class FGSApplicationInboxDispatcherV2:
    """Recover one inbox item through an idempotent application adapter."""

    production_ready = False

    def __init__(
        self,
        *,
        inbox_store: FirstApplicationInboxStoreV2,
        application_backend: IdempotentApplicationBackendV2,
    ) -> None:
        self._inbox_store = inbox_store
        self._application_backend = application_backend

    @staticmethod
    def _failure(
        disposition: ApplicationDispatchDispositionV2,
        failure: str,
    ) -> ApplicationDispatchResultV2:
        return ApplicationDispatchResultV2(
            False,
            disposition,
            (failure,),
            None,
            None,
            None,
        )

    @staticmethod
    def _completed(
        disposition: ApplicationDispatchDispositionV2,
        entry: FirstApplicationInboxEntryV2,
    ) -> ApplicationDispatchResultV2:
        entry.validate()
        if entry.state is not FirstApplicationInboxStateV2.COMPLETED:
            raise ValueError("dispatch completion is not completed")
        assert entry.receipt is not None
        return ApplicationDispatchResultV2(
            True,
            disposition,
            (),
            entry.session_id,
            entry.record_digest,
            entry.receipt,
        )

    def process(self, session_id: bytes) -> ApplicationDispatchResultV2:
        try:
            session = _fixed(session_id, SESSION_ID_BYTES, "session_id")
            entry = self._inbox_store.load(session)
            if entry is None:
                return self._failure(
                    ApplicationDispatchDispositionV2.REJECTED,
                    "inbox_missing",
                )
            if not isinstance(entry, FirstApplicationInboxEntryV2):
                raise TypeError("inbox store returned the wrong type")
            entry.validate()
            if entry.session_id != session:
                raise ValueError("inbox store changed session identity")
        except Exception as error:
            return self._failure(
                ApplicationDispatchDispositionV2.COMMIT_UNCERTAIN,
                f"inbox_load:{type(error).__name__}",
            )

        if entry.state is FirstApplicationInboxStateV2.COMPLETED:
            try:
                return self._completed(
                    ApplicationDispatchDispositionV2.ALREADY_COMPLETED,
                    entry,
                )
            except Exception as error:
                return self._failure(
                    ApplicationDispatchDispositionV2.COMMIT_UNCERTAIN,
                    f"completed_output:{type(error).__name__}",
                )

        expected_plaintext_digest = derive_first_application_plaintext_digest(
            entry.plaintext
        )
        try:
            applied = self._application_backend.apply_once(
                entry.record_digest,
                entry.plaintext,
            )
            if not isinstance(applied, ApplicationApplyResultV2):
                raise TypeError("application backend returned the wrong type")
            applied.validate()
            if (
                applied.idempotency_key != entry.record_digest
                or applied.plaintext_digest != expected_plaintext_digest
            ):
                raise ValueError("application backend changed operation identity")
        except FirstRecordOutboxConflictError:
            return self._failure(
                ApplicationDispatchDispositionV2.REJECTED,
                "application_conflict",
            )
        except Exception as error:
            return self._failure(
                ApplicationDispatchDispositionV2.COMMIT_UNCERTAIN,
                f"application_apply:{type(error).__name__}",
            )

        try:
            completed = self._inbox_store.complete(
                entry.session_id,
                entry.record_digest,
                applied.receipt,
            )
            if not isinstance(completed, FirstApplicationInboxEntryV2):
                raise TypeError("inbox completion returned the wrong type")
            completed.validate()
            if (
                completed.session_id,
                completed.record_digest,
                completed.plaintext,
                completed.receipt,
            ) != (
                entry.session_id,
                entry.record_digest,
                entry.plaintext,
                applied.receipt,
            ):
                raise ValueError("inbox completion changed operation identity")
        except FirstRecordOutboxConflictError:
            return self._failure(
                ApplicationDispatchDispositionV2.REJECTED,
                "inbox_completion_conflict",
            )
        except Exception as error:
            return self._failure(
                ApplicationDispatchDispositionV2.COMMIT_UNCERTAIN,
                f"inbox_complete:{type(error).__name__}",
            )

        disposition = (
            ApplicationDispatchDispositionV2.COMPLETED
            if applied.disposition is ApplicationApplyDispositionV2.APPLIED
            else ApplicationDispatchDispositionV2.RECOVERED_COMPLETION
        )
        try:
            return self._completed(disposition, completed)
        except Exception as error:
            return self._failure(
                ApplicationDispatchDispositionV2.COMMIT_UNCERTAIN,
                f"dispatch_output:{type(error).__name__}",
            )


def application_dispatch_manifest() -> dict[str, object]:
    return {
        "format": "PQ-SAT-FGS-APPLICATION-DISPATCH-v0.2",
        "idempotency_key": "first_application_record_digest",
        "states": [state.name for state in FirstApplicationInboxStateV2],
        "ordering": [
            "load_and_authenticate_pending_inbox_item",
            "application_apply_once_by_record_digest",
            "validate_stable_receipt",
            "mark_inbox_completed",
        ],
        "claims": {
            "restart_pending_recovery_implemented": True,
            "application_apply_once_contract_defined": True,
            "apply_ack_loss_recovery_supported": True,
            "completion_ack_loss_recovery_supported": True,
            "reference_dispatch_implemented": True,
            "production_application_adapter_instantiated": False,
            "external_application_exactly_once_proven": False,
            "distributed": False,
            "production_ready": False,
        },
    }
