"""SQLite journal for resumable FGS reservation reconciliation."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from ..reconciliation import (
    DIGEST_BYTES,
    ReconciliationItemDispositionV2,
    ReconciliationRunDispositionV2,
    ReservationReconciliationCoordinatorV2,
    ReservationReconciliationPlanV2,
    ReservationReconciliationRunResultV2,
)
from ..reconciliation_audit import (
    MAX_AUDIT_INTENT_BYTES,
    MAX_AUDIT_RECEIPT_BYTES,
    ReconciliationAuditAppendDispositionV2,
    ReconciliationAuditIntentV2,
    ReconciliationAuditIntentWriteResultV2,
    ReconciliationAuditReceiptWriteResultV2,
    decode_reconciliation_audit_intent,
    decode_reconciliation_audit_receipt,
    encode_reconciliation_audit_intent,
    encode_reconciliation_audit_receipt,
    validate_reconciliation_audit_binding,
)
from ..reconciliation_resume import (
    MAX_PLAN_BYTES,
    MAX_PROGRESS_BYTES,
    ReconciliationPlanWriteResultV2,
    ReconciliationProgressV2,
    ReconciliationProgressWriteResultV2,
    decode_reconciliation_plan,
    decode_reconciliation_progress,
    encode_reconciliation_plan,
    encode_reconciliation_progress,
    validate_plan_intent,
    validate_progress_plan,
)
from .sqlite_reconciliation_audit import (
    ReconciliationAuditJournalConflict,
    ReconciliationAuditJournalIntegrityError,
    ReconciliationAuditRecordProtectionV2,
)


APPLICATION_ID = 0x50515352
SCHEMA_VERSION = 1
MAX_PROTECTED_INTENT_BYTES = 16_384
MAX_PROTECTED_PLAN_BYTES = 18_874_368
MAX_PROTECTED_PROGRESS_BYTES = 16_384
MAX_PROTECTED_RECEIPT_BYTES = 9_437_184
INTENT_AAD = b"PQ-SAT/FGS-RECONCILIATION-RESUME-INTENT-AAD/v0.2\x00"
PLAN_AAD = b"PQ-SAT/FGS-RECONCILIATION-RESUME-PLAN-AAD/v0.2\x00"
PROGRESS_AAD = b"PQ-SAT/FGS-RECONCILIATION-RESUME-PROGRESS-AAD/v0.2\x00"
RECEIPT_AAD = b"PQ-SAT/FGS-RECONCILIATION-RESUME-RECEIPT-AAD/v0.2\x00"
PRODUCTION_READY = False


_INTENT_SCHEMA_SQL = """CREATE TABLE reconciliation_resume_intents (
    invocation_id BLOB PRIMARY KEY NOT NULL
        CHECK(typeof(invocation_id) = 'blob' AND length(invocation_id) = 32),
    protection_id TEXT NOT NULL
        CHECK(typeof(protection_id) = 'text' AND length(protection_id) BETWEEN 1 AND 128),
    protected_intent BLOB NOT NULL
        CHECK(typeof(protected_intent) = 'blob' AND length(protected_intent) BETWEEN 1 AND 16384)
) WITHOUT ROWID"""

_PLAN_SCHEMA_SQL = """CREATE TABLE reconciliation_resume_plans (
    invocation_id BLOB PRIMARY KEY NOT NULL
        CHECK(typeof(invocation_id) = 'blob' AND length(invocation_id) = 32),
    protection_id TEXT NOT NULL
        CHECK(typeof(protection_id) = 'text' AND length(protection_id) BETWEEN 1 AND 128),
    protected_plan BLOB NOT NULL
        CHECK(typeof(protected_plan) = 'blob' AND length(protected_plan) BETWEEN 1 AND 18874368),
    FOREIGN KEY(invocation_id) REFERENCES reconciliation_resume_intents(invocation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) WITHOUT ROWID"""

_PROGRESS_SCHEMA_SQL = """CREATE TABLE reconciliation_resume_progress (
    invocation_id BLOB NOT NULL
        CHECK(typeof(invocation_id) = 'blob' AND length(invocation_id) = 32),
    item_index INTEGER NOT NULL
        CHECK(typeof(item_index) = 'integer' AND item_index BETWEEN 0 AND 9999),
    protection_id TEXT NOT NULL
        CHECK(typeof(protection_id) = 'text' AND length(protection_id) BETWEEN 1 AND 128),
    protected_progress BLOB NOT NULL
        CHECK(typeof(protected_progress) = 'blob' AND length(protected_progress) BETWEEN 1 AND 16384),
    PRIMARY KEY(invocation_id, item_index),
    FOREIGN KEY(invocation_id) REFERENCES reconciliation_resume_plans(invocation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) WITHOUT ROWID"""

_RECEIPT_SCHEMA_SQL = """CREATE TABLE reconciliation_resume_receipts (
    invocation_id BLOB PRIMARY KEY NOT NULL
        CHECK(typeof(invocation_id) = 'blob' AND length(invocation_id) = 32),
    protection_id TEXT NOT NULL
        CHECK(typeof(protection_id) = 'text' AND length(protection_id) BETWEEN 1 AND 128),
    protected_receipt BLOB NOT NULL
        CHECK(typeof(protected_receipt) = 'blob' AND length(protected_receipt) BETWEEN 1 AND 9437184),
    FOREIGN KEY(invocation_id) REFERENCES reconciliation_resume_intents(invocation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) WITHOUT ROWID"""


def _fixed(value: object, size: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    return value


def _normalized_sql(value: str) -> str:
    return "".join(value.split())


class SQLiteResumableReconciliationJournalV2:
    """Append-only single-host intent/plan/progress/receipt journal."""

    durable = True
    distributed = False
    production_ready = False

    def __init__(
        self,
        path: str | os.PathLike[str],
        protection_backend: ReconciliationAuditRecordProtectionV2,
        *,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        candidate = Path(path)
        if not candidate.is_absolute():
            raise ValueError("resume database path must be absolute")
        if not candidate.parent.is_dir():
            raise ValueError("resume database parent must exist")
        if candidate.exists() and (candidate.is_symlink() or not candidate.is_file()):
            raise ValueError("resume database must be a regular non-symlink file")
        if isinstance(busy_timeout_ms, bool) or not isinstance(busy_timeout_ms, int):
            raise TypeError("busy_timeout_ms must be an integer")
        if not 1 <= busy_timeout_ms <= 60_000:
            raise ValueError("busy_timeout_ms is outside bounds")
        protection_id = getattr(protection_backend, "protection_id", None)
        if (
            not isinstance(protection_id, str)
            or not protection_id
            or not protection_id.isascii()
            or len(protection_id) > 128
        ):
            raise ValueError("resume protection_id is invalid")
        self._path = candidate
        self._protection = protection_backend
        self._protection_id = protection_id
        self._busy_timeout_ms = busy_timeout_ms
        self._initialize()

    @property
    def path(self) -> Path:
        return self._path

    def _raw_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._path,
            timeout=self._busy_timeout_ms / 1000,
            isolation_level=None,
        )
        connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @staticmethod
    def _pragma(connection: sqlite3.Connection, name: str) -> int:
        row = connection.execute(f"PRAGMA {name}").fetchone()
        if row is None:
            raise ReconciliationAuditJournalIntegrityError(
                f"resume SQLite {name} is unavailable"
            )
        return int(row[0])

    @staticmethod
    def _tables(connection: sqlite3.Connection) -> dict[str, str]:
        return {
            str(name): str(sql)
            for name, sql in connection.execute(
                "SELECT name, sql FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }

    def _verify(self, connection: sqlite3.Connection) -> None:
        if self._pragma(connection, "application_id") != APPLICATION_ID:
            raise ReconciliationAuditJournalIntegrityError(
                "resume database application_id mismatch"
            )
        if self._pragma(connection, "user_version") != SCHEMA_VERSION:
            raise ReconciliationAuditJournalIntegrityError(
                "resume database schema version mismatch"
            )
        expected = {
            "reconciliation_resume_intents": _INTENT_SCHEMA_SQL,
            "reconciliation_resume_plans": _PLAN_SCHEMA_SQL,
            "reconciliation_resume_progress": _PROGRESS_SCHEMA_SQL,
            "reconciliation_resume_receipts": _RECEIPT_SCHEMA_SQL,
        }
        tables = self._tables(connection)
        if set(tables) != set(expected):
            raise ReconciliationAuditJournalIntegrityError(
                "resume database table set mismatch"
            )
        for name, sql in expected.items():
            if _normalized_sql(tables[name]) != _normalized_sql(sql):
                raise ReconciliationAuditJournalIntegrityError(
                    f"resume database {name} schema mismatch"
                )
        mode = connection.execute("PRAGMA journal_mode").fetchone()
        if mode is None or str(mode[0]).lower() != "wal":
            raise ReconciliationAuditJournalIntegrityError(
                "resume database is not in WAL mode"
            )
        if self._pragma(connection, "synchronous") != 2:
            raise ReconciliationAuditJournalIntegrityError(
                "resume database is not FULL synchronous"
            )

    def _initialize(self) -> None:
        existed = self._path.exists()
        connection = self._raw_connection()
        try:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
            if mode is None or str(mode[0]).lower() != "wal":
                raise ReconciliationAuditJournalIntegrityError(
                    "SQLite WAL mode is unavailable"
                )
            connection.execute("BEGIN IMMEDIATE")
            if not self._tables(connection):
                if (
                    self._pragma(connection, "application_id") != 0
                    or self._pragma(connection, "user_version") != 0
                ):
                    raise ReconciliationAuditJournalIntegrityError(
                        "empty resume database has unexpected identity"
                    )
                connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                for schema in (
                    _INTENT_SCHEMA_SQL,
                    _PLAN_SCHEMA_SQL,
                    _PROGRESS_SCHEMA_SQL,
                    _RECEIPT_SCHEMA_SQL,
                ):
                    connection.execute(schema)
            self._verify(connection)
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        if not existed:
            os.chmod(self._path, 0o600)
            directory = os.open(self._path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)

    def _connect(self) -> sqlite3.Connection:
        if self._path.is_symlink() or not self._path.is_file():
            raise ReconciliationAuditJournalIntegrityError(
                "resume database path changed type"
            )
        connection = self._raw_connection()
        try:
            self._verify(connection)
        except Exception:
            connection.close()
            raise
        return connection

    def _seal(self, plaintext: bytes, aad: bytes, maximum: int) -> bytes:
        try:
            protected = self._protection.seal(plaintext, aad=aad)
        except Exception as error:
            raise ReconciliationAuditJournalIntegrityError(
                "resume record sealing failed"
            ) from error
        if not isinstance(protected, bytes) or not 0 < len(protected) <= maximum:
            raise ReconciliationAuditJournalIntegrityError(
                "protected resume record is invalid"
            )
        return protected

    def _open(self, protected: object, aad: bytes, maximum: int) -> bytes:
        if not isinstance(protected, bytes) or not 0 < len(protected) <= maximum:
            raise ReconciliationAuditJournalIntegrityError(
                "stored protected resume record is invalid"
            )
        try:
            plaintext = self._protection.open(protected, aad=aad)
        except Exception as error:
            raise ReconciliationAuditJournalIntegrityError(
                "resume record authentication failed"
            ) from error
        if not isinstance(plaintext, bytes):
            raise ReconciliationAuditJournalIntegrityError(
                "resume protector returned non-bytes"
            )
        return plaintext

    @staticmethod
    def _aad(
        label: bytes,
        invocation_id: bytes,
        item_index: int | None = None,
    ) -> bytes:
        value = label + _fixed(invocation_id, DIGEST_BYTES, "invocation_id")
        return value if item_index is None else value + item_index.to_bytes(8, "big")

    def _decode_row(
        self,
        row: tuple[object, ...],
        *,
        label: bytes,
        maximum: int,
        plaintext_maximum: int,
        decoder,
        index: int | None = None,
    ):
        invocation_id = _fixed(row[0], DIGEST_BYTES, "stored invocation_id")
        if row[-2] != self._protection_id:
            raise ReconciliationAuditJournalIntegrityError(
                "resume protection identity mismatch"
            )
        plaintext = self._open(row[-1], self._aad(label, invocation_id, index), maximum)
        if not 0 < len(plaintext) <= plaintext_maximum:
            raise ReconciliationAuditJournalIntegrityError(
                "resume plaintext exceeds its bound"
            )
        try:
            return decoder(plaintext)
        except Exception as error:
            raise ReconciliationAuditJournalIntegrityError(
                "stored resume record is invalid"
            ) from error

    def _select_intent(self, connection: sqlite3.Connection, invocation_id: bytes):
        row = connection.execute(
            "SELECT invocation_id, protection_id, protected_intent "
            "FROM reconciliation_resume_intents WHERE invocation_id=?",
            (invocation_id,),
        ).fetchone()
        if row is None:
            return None
        value = self._decode_row(
            row,
            label=INTENT_AAD,
            maximum=MAX_PROTECTED_INTENT_BYTES,
            plaintext_maximum=MAX_AUDIT_INTENT_BYTES,
            decoder=decode_reconciliation_audit_intent,
        )
        if value.invocation_id != invocation_id:
            raise ReconciliationAuditJournalIntegrityError(
                "resume intent metadata mismatch"
            )
        return value

    def _select_plan(self, connection: sqlite3.Connection, invocation_id: bytes):
        row = connection.execute(
            "SELECT invocation_id, protection_id, protected_plan "
            "FROM reconciliation_resume_plans WHERE invocation_id=?",
            (invocation_id,),
        ).fetchone()
        if row is None:
            return None
        value = self._decode_row(
            row,
            label=PLAN_AAD,
            maximum=MAX_PROTECTED_PLAN_BYTES,
            plaintext_maximum=MAX_PLAN_BYTES,
            decoder=decode_reconciliation_plan,
        )
        if value.invocation_id != invocation_id:
            raise ReconciliationAuditJournalIntegrityError(
                "resume plan metadata mismatch"
            )
        return value

    def _select_progress(
        self,
        connection: sqlite3.Connection,
        invocation_id: bytes,
    ) -> tuple[ReconciliationProgressV2, ...]:
        rows = connection.execute(
            "SELECT invocation_id, item_index, protection_id, "
            "protected_progress FROM reconciliation_resume_progress "
            "WHERE invocation_id=? ORDER BY item_index",
            (invocation_id,),
        ).fetchall()
        output = []
        for expected, row in enumerate(rows):
            if row[1] != expected:
                raise ReconciliationAuditJournalIntegrityError(
                    "resume progress is not contiguous"
                )
            value = self._decode_row(
                row,
                label=PROGRESS_AAD,
                maximum=MAX_PROTECTED_PROGRESS_BYTES,
                plaintext_maximum=MAX_PROGRESS_BYTES,
                decoder=decode_reconciliation_progress,
                index=expected,
            )
            if value.invocation_id != invocation_id or value.item_index != expected:
                raise ReconciliationAuditJournalIntegrityError(
                    "resume progress metadata mismatch"
                )
            output.append(value)
            if (
                value.item.disposition
                is ReconciliationItemDispositionV2.UNRESOLVED
                and expected != len(rows) - 1
            ):
                raise ReconciliationAuditJournalIntegrityError(
                    "resume progress follows terminal item"
                )
        return tuple(output)

    def _select_receipt(self, connection: sqlite3.Connection, invocation_id: bytes):
        row = connection.execute(
            "SELECT invocation_id, protection_id, protected_receipt "
            "FROM reconciliation_resume_receipts WHERE invocation_id=?",
            (invocation_id,),
        ).fetchone()
        if row is None:
            return None
        value = self._decode_row(
            row,
            label=RECEIPT_AAD,
            maximum=MAX_PROTECTED_RECEIPT_BYTES,
            plaintext_maximum=MAX_AUDIT_RECEIPT_BYTES,
            decoder=decode_reconciliation_audit_receipt,
        )
        if value.invocation_id != invocation_id:
            raise ReconciliationAuditJournalIntegrityError(
                "resume receipt metadata mismatch"
            )
        return value

    def load_intent(self, invocation_id: bytes):
        return self._load_one(invocation_id, self._select_intent)

    def load_plan(self, invocation_id: bytes):
        canonical = _fixed(invocation_id, DIGEST_BYTES, "invocation_id")
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            intent = self._select_intent(connection, canonical)
            plan = self._select_plan(connection, canonical)
            if plan is not None:
                if intent is None:
                    raise ReconciliationAuditJournalIntegrityError(
                        "resume plan has no intent"
                    )
                try:
                    validate_plan_intent(intent, plan)
                except Exception as error:
                    raise ReconciliationAuditJournalIntegrityError(
                        "resume plan and intent binding is invalid"
                    ) from error
            connection.execute("COMMIT")
            return plan
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def load_progress(self, invocation_id: bytes):
        canonical = _fixed(invocation_id, DIGEST_BYTES, "invocation_id")
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            intent = self._select_intent(connection, canonical)
            plan = self._select_plan(connection, canonical)
            progress = self._select_progress(connection, canonical)
            if progress and plan is None:
                raise ReconciliationAuditJournalIntegrityError(
                    "resume progress has no plan"
                )
            if plan is not None:
                try:
                    if intent is None:
                        raise ValueError("resume plan has no intent")
                    validate_plan_intent(intent, plan)
                    for entry in progress:
                        validate_progress_plan(plan, entry)
                except Exception as error:
                    raise ReconciliationAuditJournalIntegrityError(
                        "resume progress and plan binding is invalid"
                    ) from error
            connection.execute("COMMIT")
            return progress
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def load_receipt(self, invocation_id: bytes):
        canonical = _fixed(invocation_id, DIGEST_BYTES, "invocation_id")
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            intent = self._select_intent(connection, canonical)
            plan = self._select_plan(connection, canonical)
            progress = self._select_progress(connection, canonical)
            receipt = self._select_receipt(connection, canonical)
            if receipt is not None:
                try:
                    self._validate_terminal(intent, plan, progress, receipt)
                except Exception as error:
                    raise ReconciliationAuditJournalIntegrityError(
                        "resume terminal binding is invalid"
                    ) from error
            connection.execute("COMMIT")
            return receipt
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _load_one(self, invocation_id: bytes, selector):
        canonical = _fixed(invocation_id, DIGEST_BYTES, "invocation_id")
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            value = selector(connection, canonical)
            connection.execute("COMMIT")
            return value
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def begin_intent(self, intent: ReconciliationAuditIntentV2):
        if not isinstance(intent, ReconciliationAuditIntentV2):
            raise TypeError("intent has the wrong type")
        protected = self._seal(
            encode_reconciliation_audit_intent(intent),
            self._aad(INTENT_AAD, intent.invocation_id),
            MAX_PROTECTED_INTENT_BYTES,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._select_intent(connection, intent.invocation_id)
            if existing is None:
                connection.execute(
                    "INSERT INTO reconciliation_resume_intents "
                    "VALUES (?, ?, ?)",
                    (intent.invocation_id, self._protection_id, protected),
                )
                disposition = ReconciliationAuditAppendDispositionV2.NEW
                value = intent
            elif existing == intent:
                disposition = ReconciliationAuditAppendDispositionV2.EXISTING
                value = existing
            else:
                raise ReconciliationAuditJournalConflict(
                    "resume invocation belongs to another intent"
                )
            connection.execute("COMMIT")
            return ReconciliationAuditIntentWriteResultV2(disposition, value)
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def append_plan(self, plan: ReservationReconciliationPlanV2):
        if not isinstance(plan, ReservationReconciliationPlanV2):
            raise TypeError("plan has the wrong type")
        protected = self._seal(
            encode_reconciliation_plan(plan),
            self._aad(PLAN_AAD, plan.invocation_id),
            MAX_PROTECTED_PLAN_BYTES,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            intent = self._select_intent(connection, plan.invocation_id)
            if intent is None:
                raise ReconciliationAuditJournalConflict("resume plan has no intent")
            try:
                validate_plan_intent(intent, plan)
            except Exception as error:
                raise ReconciliationAuditJournalConflict(
                    "resume plan does not match intent"
                ) from error
            if self._select_receipt(connection, plan.invocation_id) is not None:
                raise ReconciliationAuditJournalConflict(
                    "resume invocation is already terminal"
                )
            existing = self._select_plan(connection, plan.invocation_id)
            if existing is None:
                connection.execute(
                    "INSERT INTO reconciliation_resume_plans VALUES (?, ?, ?)",
                    (plan.invocation_id, self._protection_id, protected),
                )
                disposition, value = ReconciliationAuditAppendDispositionV2.NEW, plan
            elif existing == plan:
                disposition = ReconciliationAuditAppendDispositionV2.EXISTING
                value = existing
            else:
                raise ReconciliationAuditJournalConflict(
                    "resume invocation belongs to another plan"
                )
            connection.execute("COMMIT")
            return ReconciliationPlanWriteResultV2(disposition, value)
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def append_progress(self, progress: ReconciliationProgressV2):
        if not isinstance(progress, ReconciliationProgressV2):
            raise TypeError("progress has the wrong type")
        protected = self._seal(
            encode_reconciliation_progress(progress),
            self._aad(
                PROGRESS_AAD,
                progress.invocation_id,
                progress.item_index,
            ),
            MAX_PROTECTED_PROGRESS_BYTES,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            intent = self._select_intent(connection, progress.invocation_id)
            plan = self._select_plan(connection, progress.invocation_id)
            if plan is None:
                raise ReconciliationAuditJournalConflict("resume progress has no plan")
            try:
                if intent is None:
                    raise ValueError("resume plan has no intent")
                validate_plan_intent(intent, plan)
                validate_progress_plan(plan, progress)
            except Exception as error:
                raise ReconciliationAuditJournalConflict(
                    "resume progress does not match plan"
                ) from error
            if self._select_receipt(connection, progress.invocation_id) is not None:
                raise ReconciliationAuditJournalConflict(
                    "resume invocation is already terminal"
                )
            existing_progress = self._select_progress(
                connection,
                progress.invocation_id,
            )
            if progress.item_index < len(existing_progress):
                existing = existing_progress[progress.item_index]
                if existing != progress:
                    raise ReconciliationAuditJournalConflict(
                        "resume progress identity conflicts"
                    )
                disposition = ReconciliationAuditAppendDispositionV2.EXISTING
                value = existing
            elif (
                existing_progress
                and existing_progress[-1].item.disposition
                is ReconciliationItemDispositionV2.UNRESOLVED
            ):
                raise ReconciliationAuditJournalConflict(
                    "resume progress already terminated"
                )
            elif progress.item_index == len(existing_progress):
                connection.execute(
                    "INSERT INTO reconciliation_resume_progress "
                    "VALUES (?, ?, ?, ?)",
                    (
                        progress.invocation_id,
                        progress.item_index,
                        self._protection_id,
                        protected,
                    ),
                )
                disposition = ReconciliationAuditAppendDispositionV2.NEW
                value = progress
            else:
                raise ReconciliationAuditJournalConflict(
                    "resume progress is not contiguous"
                )
            connection.execute("COMMIT")
            return ReconciliationProgressWriteResultV2(disposition, value)
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @staticmethod
    def _validate_terminal(intent, plan, progress, receipt) -> None:
        if intent is None:
            raise ReconciliationAuditJournalIntegrityError(
                "resume receipt has no intent"
            )
        validate_reconciliation_audit_binding(intent, receipt)
        if plan is None:
            if (
                progress
                or receipt.disposition
                is not ReconciliationRunDispositionV2.REJECTED
            ):
                raise ReconciliationAuditJournalIntegrityError(
                    "unplanned resume receipt is not a preparation rejection"
                )
            return
        validate_plan_intent(intent, plan)
        for entry in progress:
            validate_progress_plan(plan, entry)
        expected = ReservationReconciliationCoordinatorV2.finalize_plan(
            plan,
            tuple(entry.item for entry in progress),
        )
        if receipt != expected:
            raise ReconciliationAuditJournalIntegrityError(
                "resume receipt does not match exact plan progress"
            )

    def append_receipt(self, receipt: ReservationReconciliationRunResultV2):
        if not isinstance(receipt, ReservationReconciliationRunResultV2):
            raise TypeError("receipt has the wrong type")
        protected = self._seal(
            encode_reconciliation_audit_receipt(receipt),
            self._aad(RECEIPT_AAD, receipt.invocation_id),
            MAX_PROTECTED_RECEIPT_BYTES,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            intent = self._select_intent(connection, receipt.invocation_id)
            plan = self._select_plan(connection, receipt.invocation_id)
            progress = self._select_progress(connection, receipt.invocation_id)
            try:
                self._validate_terminal(intent, plan, progress, receipt)
            except Exception as error:
                raise ReconciliationAuditJournalConflict(
                    "resume receipt is not terminally bound"
                ) from error
            existing = self._select_receipt(connection, receipt.invocation_id)
            if existing is None:
                connection.execute(
                    "INSERT INTO reconciliation_resume_receipts "
                    "VALUES (?, ?, ?)",
                    (receipt.invocation_id, self._protection_id, protected),
                )
                disposition, value = ReconciliationAuditAppendDispositionV2.NEW, receipt
            elif existing == receipt:
                disposition = ReconciliationAuditAppendDispositionV2.EXISTING
                value = existing
            else:
                raise ReconciliationAuditJournalConflict(
                    "resume receipt identity conflicts"
                )
            connection.execute("COMMIT")
            return ReconciliationAuditReceiptWriteResultV2(disposition, value)
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def counts(self) -> tuple[int, int, int, int]:
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            values = tuple(
                int(connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0])
                for name in (
                    "reconciliation_resume_intents",
                    "reconciliation_resume_plans",
                    "reconciliation_resume_progress",
                    "reconciliation_resume_receipts",
                )
            )
            connection.execute("COMMIT")
            return values
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()


def sqlite_reconciliation_resume_manifest() -> dict[str, object]:
    return {
        "format": "PQ-SAT-FGS-RECONCILIATION-RESUME-SQLITE-v0.2",
        "application_id": f"0x{APPLICATION_ID:08X}",
        "schema_version": SCHEMA_VERSION,
        "journal_mode": "WAL",
        "synchronous": "FULL",
        "tables": [
            "reconciliation_resume_intents",
            "reconciliation_resume_plans",
            "reconciliation_resume_progress",
            "reconciliation_resume_receipts",
        ],
        "claims": {
            "append_only_public_api": True,
            "intent_plan_progress_receipt_binding": True,
            "contiguous_progress_enforced": True,
            "exact_retry_idempotent": True,
            "record_protection_backend_boundary": True,
            "single_host_restart_durable_reference": True,
            "cross_process_intent_serialization": True,
            "separate_from_receipt_only_audit_database": True,
            "atomic_with_replay_state": False,
            "single_active_executor_enforced": False,
            "production_record_protection_instantiated": False,
            "physical_power_loss_tested": False,
            "rollback_resistance": False,
            "distributed": False,
            "production_ready": False,
        },
    }
