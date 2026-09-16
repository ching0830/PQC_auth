"""Persistent intent/receipt boundary for reservation reconciliation runs.

The journaled runner records an immutable intent before invoking the replay
coordinator and an immutable receipt before returning a completed result.  An
intent without a receipt is deliberately not auto-replayed: it marks a crash
window that requires a later recovery checkpoint or explicit operator action.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from .reconciliation import (
    DIGEST_BYTES,
    MAX_RECONCILIATION_BATCH,
    ReconciliationItemDispositionV2,
    ReconciliationRunDispositionV2,
    ReservationReconciliationInvocationV2,
    ReservationReconciliationItemResultV2,
    ReservationReconciliationPolicyV2,
    ReservationReconciliationRunResultV2,
)


AUDIT_INTENT_FORMAT = "PQ-SAT/FGS-RECONCILIATION-AUDIT-INTENT/v0.2"
AUDIT_RECEIPT_FORMAT = "PQ-SAT/FGS-RECONCILIATION-AUDIT-RECEIPT/v0.2"
MAX_AUDIT_INTENT_BYTES = 2_048
MAX_AUDIT_RECEIPT_BYTES = 8_388_608
MAX_AUDIT_DETAIL_BYTES = 256
PRODUCTION_READY = False


def _fixed(value: bytes, size: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    return value


def _integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _optional_integer(value: object, name: str) -> int | None:
    return None if value is None else _integer(value, name)


def _hex(value: bytes, name: str) -> str:
    return _fixed(value, DIGEST_BYTES, name).hex()


def _unhex(value: object, name: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a hex string")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{name} is not hexadecimal") from error
    if decoded.hex() != value:
        raise ValueError(f"{name} is not canonical lowercase hex")
    return _fixed(decoded, DIGEST_BYTES, name)


def _mapping(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) for key in value
    ):
        raise TypeError(f"{name} must be a string-keyed object")
    return value


def _exact_keys(value: dict[str, object], keys: set[str], name: str) -> None:
    if set(value) != keys:
        raise ValueError(f"{name} has unknown or missing fields")


def _bounded_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise TypeError(f"{name} must be a non-empty string")
    if len(value.encode("utf-8")) > MAX_AUDIT_DETAIL_BYTES:
        raise ValueError(f"{name} exceeds the audit bound")
    return value


def _optional_text(value: object, name: str) -> str | None:
    return None if value is None else _bounded_text(value, name)


def _canonical_json(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _decoded_object(encoded: bytes, maximum: int, name: str) -> dict[str, object]:
    if not isinstance(encoded, bytes):
        raise TypeError(f"{name} must be bytes")
    if not 0 < len(encoded) <= maximum:
        raise ValueError(f"{name} is empty or exceeds its bound")
    try:
        value = json.loads(encoded.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{name} is not canonical JSON") from error
    return _mapping(value, name)


@dataclass(frozen=True)
class ReconciliationAuditIntentV2:
    invocation_id: bytes
    batch_limit: int
    minimum_stale_seconds: int

    def __post_init__(self) -> None:
        _fixed(self.invocation_id, DIGEST_BYTES, "audit invocation_id")
        ReservationReconciliationPolicyV2(
            self.batch_limit,
            self.minimum_stale_seconds,
        )

    @classmethod
    def create(
        cls,
        invocation: ReservationReconciliationInvocationV2,
        policy: ReservationReconciliationPolicyV2,
    ) -> "ReconciliationAuditIntentV2":
        if not isinstance(invocation, ReservationReconciliationInvocationV2):
            raise TypeError("invocation has the wrong type")
        if not isinstance(policy, ReservationReconciliationPolicyV2):
            raise TypeError("policy has the wrong type")
        return cls(
            invocation.invocation_id,
            policy.batch_limit,
            policy.minimum_stale_seconds,
        )


def encode_reconciliation_audit_intent(
    intent: ReconciliationAuditIntentV2,
) -> bytes:
    if not isinstance(intent, ReconciliationAuditIntentV2):
        raise TypeError("intent has the wrong type")
    encoded = _canonical_json(
        {
            "batch_limit": intent.batch_limit,
            "format": AUDIT_INTENT_FORMAT,
            "invocation_id": _hex(intent.invocation_id, "invocation_id"),
            "minimum_stale_seconds": intent.minimum_stale_seconds,
        }
    )
    if len(encoded) > MAX_AUDIT_INTENT_BYTES:
        raise ValueError("encoded audit intent exceeds its bound")
    return encoded


def decode_reconciliation_audit_intent(
    encoded: bytes,
) -> ReconciliationAuditIntentV2:
    item = _decoded_object(
        encoded,
        MAX_AUDIT_INTENT_BYTES,
        "audit intent",
    )
    _exact_keys(
        item,
        {
            "batch_limit",
            "format",
            "invocation_id",
            "minimum_stale_seconds",
        },
        "audit intent",
    )
    if item["format"] != AUDIT_INTENT_FORMAT:
        raise ValueError("audit intent format is unknown")
    intent = ReconciliationAuditIntentV2(
        invocation_id=_unhex(item["invocation_id"], "invocation_id"),
        batch_limit=_integer(item["batch_limit"], "batch_limit"),
        minimum_stale_seconds=_integer(
            item["minimum_stale_seconds"],
            "minimum_stale_seconds",
        ),
    )
    if encode_reconciliation_audit_intent(intent) != encoded:
        raise ValueError("audit intent encoding is not canonical")
    return intent


def _item_to_object(
    item: ReservationReconciliationItemResultV2,
) -> dict[str, object]:
    if item.detail is not None:
        _bounded_text(item.detail, "item detail")
    return {
        "attempt_id": _hex(item.attempt_id, "attempt_id"),
        "detail": item.detail,
        "disposition": item.disposition.value,
        "fence_generation": item.fence_generation,
        "prior_fencing_generation": item.prior_fencing_generation,
        "use_key": _hex(item.use_key, "use_key"),
    }


def _item_from_object(
    value: object,
) -> ReservationReconciliationItemResultV2:
    item = _mapping(value, "audit receipt item")
    _exact_keys(
        item,
        {
            "attempt_id",
            "detail",
            "disposition",
            "fence_generation",
            "prior_fencing_generation",
            "use_key",
        },
        "audit receipt item",
    )
    try:
        disposition = ReconciliationItemDispositionV2(item["disposition"])
    except (TypeError, ValueError) as error:
        raise ValueError("audit item disposition is unknown") from error
    return ReservationReconciliationItemResultV2(
        use_key=_unhex(item["use_key"], "item use_key"),
        attempt_id=_unhex(item["attempt_id"], "item attempt_id"),
        prior_fencing_generation=_integer(
            item["prior_fencing_generation"],
            "prior_fencing_generation",
        ),
        fence_generation=_optional_integer(
            item["fence_generation"],
            "fence_generation",
        ),
        disposition=disposition,
        detail=_optional_text(item["detail"], "item detail"),
    )


def encode_reconciliation_audit_receipt(
    result: ReservationReconciliationRunResultV2,
) -> bytes:
    if not isinstance(result, ReservationReconciliationRunResultV2):
        raise TypeError("audit receipt result has the wrong type")
    failures = [
        _bounded_text(failure, "run failure") for failure in result.failures
    ]
    encoded = _canonical_json(
        {
            "accepted": result.accepted,
            "disposition": result.disposition.value,
            "failures": failures,
            "format": AUDIT_RECEIPT_FORMAT,
            "invocation_id": _hex(result.invocation_id, "invocation_id"),
            "items": [_item_to_object(item) for item in result.items],
            "observed_at": result.observed_at,
            "scan_cutoff": result.scan_cutoff,
            "scanned_count": result.scanned_count,
        }
    )
    if len(encoded) > MAX_AUDIT_RECEIPT_BYTES:
        raise ValueError("encoded audit receipt exceeds its bound")
    return encoded


def decode_reconciliation_audit_receipt(
    encoded: bytes,
) -> ReservationReconciliationRunResultV2:
    item = _decoded_object(
        encoded,
        MAX_AUDIT_RECEIPT_BYTES,
        "audit receipt",
    )
    _exact_keys(
        item,
        {
            "accepted",
            "disposition",
            "failures",
            "format",
            "invocation_id",
            "items",
            "observed_at",
            "scan_cutoff",
            "scanned_count",
        },
        "audit receipt",
    )
    if item["format"] != AUDIT_RECEIPT_FORMAT:
        raise ValueError("audit receipt format is unknown")
    if not isinstance(item["accepted"], bool):
        raise TypeError("audit receipt accepted must be a boolean")
    try:
        disposition = ReconciliationRunDispositionV2(item["disposition"])
    except (TypeError, ValueError) as error:
        raise ValueError("audit run disposition is unknown") from error
    raw_items = item["items"]
    if not isinstance(raw_items, list):
        raise TypeError("audit receipt items must be a list")
    if len(raw_items) > MAX_RECONCILIATION_BATCH:
        raise ValueError("audit receipt has too many items")
    raw_failures = item["failures"]
    if not isinstance(raw_failures, list):
        raise TypeError("audit receipt failures must be a list")
    result = ReservationReconciliationRunResultV2(
        accepted=item["accepted"],
        disposition=disposition,
        invocation_id=_unhex(item["invocation_id"], "invocation_id"),
        observed_at=_optional_integer(item["observed_at"], "observed_at"),
        scan_cutoff=_optional_integer(item["scan_cutoff"], "scan_cutoff"),
        scanned_count=_integer(item["scanned_count"], "scanned_count"),
        items=tuple(_item_from_object(value) for value in raw_items),
        failures=tuple(
            _bounded_text(value, "run failure") for value in raw_failures
        ),
    )
    if encode_reconciliation_audit_receipt(result) != encoded:
        raise ValueError("audit receipt encoding is not canonical")
    return result


def validate_reconciliation_audit_binding(
    intent: ReconciliationAuditIntentV2,
    receipt: ReservationReconciliationRunResultV2,
) -> None:
    if not isinstance(intent, ReconciliationAuditIntentV2):
        raise TypeError("audit binding intent has the wrong type")
    if not isinstance(receipt, ReservationReconciliationRunResultV2):
        raise TypeError("audit binding receipt has the wrong type")
    if receipt.invocation_id != intent.invocation_id:
        raise ValueError("audit receipt invocation does not match intent")
    if receipt.scanned_count > intent.batch_limit:
        raise ValueError("audit receipt exceeds intent batch_limit")
    if receipt.observed_at is None:
        if receipt.scan_cutoff is not None:
            raise ValueError("audit receipt has cutoff without observation")
        if (
            receipt.disposition is not ReconciliationRunDispositionV2.REJECTED
            or receipt.scanned_count != 0
            or receipt.items
        ):
            raise ValueError("unobserved audit receipt contains processed state")
        return
    expected_cutoff = max(
        0,
        receipt.observed_at - intent.minimum_stale_seconds,
    )
    if receipt.scan_cutoff != expected_cutoff:
        raise ValueError("audit receipt cutoff does not match intent policy")


class ReconciliationAuditAppendDispositionV2(Enum):
    NEW = "new"
    EXISTING = "existing"


@dataclass(frozen=True)
class ReconciliationAuditIntentWriteResultV2:
    disposition: ReconciliationAuditAppendDispositionV2
    intent: ReconciliationAuditIntentV2

    def __post_init__(self) -> None:
        if not isinstance(
            self.disposition,
            ReconciliationAuditAppendDispositionV2,
        ):
            raise TypeError("audit intent write disposition has the wrong type")
        if not isinstance(self.intent, ReconciliationAuditIntentV2):
            raise TypeError("audit intent write value has the wrong type")


@dataclass(frozen=True)
class ReconciliationAuditReceiptWriteResultV2:
    disposition: ReconciliationAuditAppendDispositionV2
    receipt: ReservationReconciliationRunResultV2

    def __post_init__(self) -> None:
        if not isinstance(
            self.disposition,
            ReconciliationAuditAppendDispositionV2,
        ):
            raise TypeError("audit receipt write disposition has the wrong type")
        if not isinstance(self.receipt, ReservationReconciliationRunResultV2):
            raise TypeError("audit receipt write value has the wrong type")


class ReconciliationAuditJournalV2(Protocol):
    def load_intent(
        self,
        invocation_id: bytes,
    ) -> ReconciliationAuditIntentV2 | None: ...

    def load_receipt(
        self,
        invocation_id: bytes,
    ) -> ReservationReconciliationRunResultV2 | None: ...

    def begin_intent(
        self,
        intent: ReconciliationAuditIntentV2,
    ) -> ReconciliationAuditIntentWriteResultV2: ...

    def append_receipt(
        self,
        receipt: ReservationReconciliationRunResultV2,
    ) -> ReconciliationAuditReceiptWriteResultV2: ...


class ReconciliationCoordinatorV2(Protocol):
    @property
    def policy(self) -> ReservationReconciliationPolicyV2: ...

    def run_once(
        self,
        invocation: ReservationReconciliationInvocationV2,
    ) -> ReservationReconciliationRunResultV2: ...


class JournaledReconciliationDispositionV2(Enum):
    EXECUTED_AND_RECORDED = "executed_and_recorded"
    EXECUTED_RECEIPT_RECOVERED = "executed_receipt_recovered"
    RECORDED_REPLAY = "recorded_replay"
    RECOVERY_REQUIRED = "recovery_required"
    REJECTED = "rejected"
    AUDIT_UNCERTAIN = "audit_uncertain"


@dataclass(frozen=True)
class JournaledReconciliationResultV2:
    disposition: JournaledReconciliationDispositionV2
    result: ReservationReconciliationRunResultV2 | None
    failures: tuple[str, ...]

    @property
    def completed(self) -> bool:
        return self.disposition in (
            JournaledReconciliationDispositionV2.EXECUTED_AND_RECORDED,
            JournaledReconciliationDispositionV2.EXECUTED_RECEIPT_RECOVERED,
            JournaledReconciliationDispositionV2.RECORDED_REPLAY,
        )

    def __post_init__(self) -> None:
        if not isinstance(self.disposition, JournaledReconciliationDispositionV2):
            raise TypeError("journaled disposition has the wrong type")
        if self.result is not None and not isinstance(
            self.result,
            ReservationReconciliationRunResultV2,
        ):
            raise TypeError("journaled result has the wrong type")
        if not isinstance(self.failures, tuple) or not all(
            isinstance(failure, str) and failure for failure in self.failures
        ):
            raise TypeError("journaled failures must be non-empty strings")
        if len(self.failures) > 1:
            raise ValueError("journaled result has too many failures")
        if self.completed != (not self.failures and self.result is not None):
            raise ValueError("journaled result completion fields disagree")


class JournaledReservationReconciliationRunnerV2:
    """Require durable intent and exact receipt around one coordinator run."""

    production_ready = False

    def __init__(
        self,
        *,
        coordinator: ReconciliationCoordinatorV2,
        journal: ReconciliationAuditJournalV2,
    ) -> None:
        policy = getattr(coordinator, "policy", None)
        if not isinstance(policy, ReservationReconciliationPolicyV2):
            raise TypeError("coordinator must expose an exact policy")
        self._coordinator = coordinator
        self._journal = journal
        self._policy = policy

    @staticmethod
    def _outcome(
        disposition: JournaledReconciliationDispositionV2,
        *,
        result: ReservationReconciliationRunResultV2 | None = None,
        failure: str | None = None,
    ) -> JournaledReconciliationResultV2:
        return JournaledReconciliationResultV2(
            disposition,
            result,
            () if failure is None else (failure,),
        )

    def _existing(
        self,
        intent: ReconciliationAuditIntentV2,
    ) -> JournaledReconciliationResultV2 | None:
        try:
            stored_intent = self._journal.load_intent(intent.invocation_id)
        except Exception as error:
            return self._outcome(
                JournaledReconciliationDispositionV2.REJECTED,
                failure=f"audit_intent_load:{type(error).__name__}",
            )
        if stored_intent is None:
            return None
        if stored_intent != intent:
            return self._outcome(
                JournaledReconciliationDispositionV2.REJECTED,
                failure="audit_intent_conflict",
            )
        try:
            receipt = self._journal.load_receipt(intent.invocation_id)
        except Exception as error:
            return self._outcome(
                JournaledReconciliationDispositionV2.REJECTED,
                failure=f"audit_receipt_load:{type(error).__name__}",
            )
        if receipt is None:
            return self._outcome(
                JournaledReconciliationDispositionV2.RECOVERY_REQUIRED,
                failure="audit_intent_without_receipt",
            )
        if receipt.invocation_id != intent.invocation_id:
            return self._outcome(
                JournaledReconciliationDispositionV2.REJECTED,
                failure="audit_receipt_invocation_mismatch",
            )
        return self._outcome(
            JournaledReconciliationDispositionV2.RECORDED_REPLAY,
            result=receipt,
        )

    def run_once(
        self,
        invocation: ReservationReconciliationInvocationV2,
    ) -> JournaledReconciliationResultV2:
        if not isinstance(invocation, ReservationReconciliationInvocationV2):
            raise TypeError("invocation has the wrong type")
        intent = ReconciliationAuditIntentV2.create(invocation, self._policy)
        existing = self._existing(intent)
        if existing is not None:
            return existing

        try:
            write = self._journal.begin_intent(intent)
        except Exception as error:
            return self._outcome(
                JournaledReconciliationDispositionV2.AUDIT_UNCERTAIN,
                failure=f"audit_intent_commit:{type(error).__name__}",
            )
        if not isinstance(write, ReconciliationAuditIntentWriteResultV2):
            return self._outcome(
                JournaledReconciliationDispositionV2.AUDIT_UNCERTAIN,
                failure="audit_intent_output:TypeError",
            )
        if write.intent != intent:
            return self._outcome(
                JournaledReconciliationDispositionV2.AUDIT_UNCERTAIN,
                failure="audit_intent_output:mismatch",
            )
        if write.disposition is ReconciliationAuditAppendDispositionV2.EXISTING:
            raced = self._existing(intent)
            if raced is None:
                return self._outcome(
                    JournaledReconciliationDispositionV2.AUDIT_UNCERTAIN,
                    failure="audit_intent_race:missing",
                )
            return raced
        if write.disposition is not ReconciliationAuditAppendDispositionV2.NEW:
            return self._outcome(
                JournaledReconciliationDispositionV2.AUDIT_UNCERTAIN,
                failure="audit_intent_output:disposition",
            )
        try:
            stored_intent = self._journal.load_intent(intent.invocation_id)
            early_receipt = self._journal.load_receipt(intent.invocation_id)
        except Exception as error:
            return self._outcome(
                JournaledReconciliationDispositionV2.AUDIT_UNCERTAIN,
                failure=f"audit_intent_readback:{type(error).__name__}",
            )
        if stored_intent != intent or early_receipt is not None:
            return self._outcome(
                JournaledReconciliationDispositionV2.AUDIT_UNCERTAIN,
                failure="audit_intent_readback:mismatch",
            )

        try:
            result = self._coordinator.run_once(invocation)
        except Exception as error:
            return self._outcome(
                JournaledReconciliationDispositionV2.RECOVERY_REQUIRED,
                failure=f"coordinator:{type(error).__name__}",
            )
        if not isinstance(result, ReservationReconciliationRunResultV2):
            return self._outcome(
                JournaledReconciliationDispositionV2.RECOVERY_REQUIRED,
                failure="coordinator_output:TypeError",
            )
        if result.invocation_id != intent.invocation_id:
            return self._outcome(
                JournaledReconciliationDispositionV2.RECOVERY_REQUIRED,
                failure="coordinator_output:invocation_mismatch",
            )

        try:
            receipt_write = self._journal.append_receipt(result)
        except Exception as error:
            try:
                recovered = self._journal.load_receipt(intent.invocation_id)
            except Exception:
                recovered = None
            if recovered == result:
                return self._outcome(
                    JournaledReconciliationDispositionV2.EXECUTED_RECEIPT_RECOVERED,
                    result=result,
                )
            return self._outcome(
                JournaledReconciliationDispositionV2.AUDIT_UNCERTAIN,
                result=result,
                failure=f"audit_receipt_commit:{type(error).__name__}",
            )
        if not isinstance(receipt_write, ReconciliationAuditReceiptWriteResultV2):
            return self._outcome(
                JournaledReconciliationDispositionV2.AUDIT_UNCERTAIN,
                result=result,
                failure="audit_receipt_output:TypeError",
            )
        if receipt_write.receipt != result:
            return self._outcome(
                JournaledReconciliationDispositionV2.AUDIT_UNCERTAIN,
                result=result,
                failure="audit_receipt_output:mismatch",
            )
        try:
            readback = self._journal.load_receipt(intent.invocation_id)
        except Exception as error:
            return self._outcome(
                JournaledReconciliationDispositionV2.AUDIT_UNCERTAIN,
                result=result,
                failure=f"audit_receipt_readback:{type(error).__name__}",
            )
        if readback != result:
            return self._outcome(
                JournaledReconciliationDispositionV2.AUDIT_UNCERTAIN,
                result=result,
                failure="audit_receipt_readback:mismatch",
            )
        disposition = (
            JournaledReconciliationDispositionV2.EXECUTED_AND_RECORDED
            if receipt_write.disposition
            is ReconciliationAuditAppendDispositionV2.NEW
            else JournaledReconciliationDispositionV2.EXECUTED_RECEIPT_RECOVERED
        )
        return self._outcome(disposition, result=result)


def reconciliation_audit_manifest() -> dict[str, object]:
    return {
        "format": "PQ-SAT-FGS-RECONCILIATION-AUDIT-v0.2",
        "processing_order": [
            "load_exact_intent_and_receipt",
            "append_intent_before_coordinator",
            "read_back_exact_intent",
            "execute_bounded_coordinator_once",
            "append_exact_receipt",
            "read_back_exact_receipt_before_return",
        ],
        "claim_boundary": {
            "intent_before_replay_mutation": True,
            "receipt_before_completed_return": True,
            "intent_receipt_policy_binding_enforced": True,
            "exact_recorded_retry_avoids_coordinator_rerun": True,
            "incomplete_intent_blocks_automatic_rerun": True,
            "lost_receipt_ack_readback_recovery": True,
            "single_host_persistent_intent_receipt_journal": True,
            "append_only_public_api": True,
            "separate_journal_and_replay_databases": True,
            "journal_and_replay_atomic_transaction": False,
            "incomplete_run_automatic_reconstruction": False,
            "operator_authentication_instantiated": False,
            "production_clock_instantiated": False,
            "automatic_background_scheduler_implemented": False,
            "distributed_coordination_implemented": False,
            "production_record_protection_instantiated": False,
            "physical_power_loss_tested": False,
            "rollback_resistance": False,
            "production_ready": False,
        },
    }
