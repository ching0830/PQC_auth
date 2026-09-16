"""Append-only SQLite intent/receipt journal for FGS reconciliation."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Protocol

from ..reconciliation import DIGEST_BYTES
from ..reconciliation_audit import (
    MAX_AUDIT_INTENT_BYTES,
    MAX_AUDIT_RECEIPT_BYTES,
    ReconciliationAuditAppendDispositionV2,
    ReconciliationAuditIntentV2,
    ReconciliationAuditIntentWriteResultV2,
    ReconciliationAuditReceiptWriteResultV2,
    ReservationReconciliationRunResultV2,
    decode_reconciliation_audit_intent,
    decode_reconciliation_audit_receipt,
    encode_reconciliation_audit_intent,
    encode_reconciliation_audit_receipt,
    validate_reconciliation_audit_binding,
)


APPLICATION_ID = 0x5051534A
SCHEMA_VERSION = 1
INTENT_AAD_LABEL = b"PQ-SAT/FGS-RECONCILIATION-AUDIT-INTENT-AAD/v0.2\x00"
RECEIPT_AAD_LABEL = b"PQ-SAT/FGS-RECONCILIATION-AUDIT-RECEIPT-AAD/v0.2\x00"
MAX_PROTECTED_INTENT_BYTES = 16_384
MAX_PROTECTED_RECEIPT_BYTES = 9_437_184
PRODUCTION_READY = False


_INTENT_SCHEMA_SQL = """CREATE TABLE reconciliation_audit_intents (
    invocation_id BLOB PRIMARY KEY NOT NULL
        CHECK(typeof(invocation_id) = 'blob' AND length(invocation_id) = 32),
    protection_id TEXT NOT NULL
        CHECK(typeof(protection_id) = 'text'
              AND length(protection_id) BETWEEN 1 AND 128),
    protected_intent BLOB NOT NULL
        CHECK(typeof(protected_intent) = 'blob'
              AND length(protected_intent) BETWEEN 1 AND 16384)
) WITHOUT ROWID"""

_RECEIPT_SCHEMA_SQL = """CREATE TABLE reconciliation_audit_receipts (
    invocation_id BLOB PRIMARY KEY NOT NULL
        CHECK(typeof(invocation_id) = 'blob' AND length(invocation_id) = 32),
    protection_id TEXT NOT NULL
        CHECK(typeof(protection_id) = 'text'
              AND length(protection_id) BETWEEN 1 AND 128),
    protected_receipt BLOB NOT NULL
        CHECK(typeof(protected_receipt) = 'blob'
              AND length(protected_receipt) BETWEEN 1 AND 9437184),
    FOREIGN KEY(invocation_id) REFERENCES reconciliation_audit_intents(invocation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) WITHOUT ROWID"""


class ReconciliationAuditRecordProtectionV2(Protocol):
    protection_id: str
    production_ready: bool

    def seal(self, plaintext: bytes, *, aad: bytes) -> bytes: ...

    def open(self, protected_record: bytes, *, aad: bytes) -> bytes: ...


class ReconciliationAuditJournalError(RuntimeError):
    pass


class ReconciliationAuditJournalConflict(ReconciliationAuditJournalError):
    pass


class ReconciliationAuditJournalIntegrityError(ReconciliationAuditJournalError):
    pass


def _fixed(value: bytes, size: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    return value


def _protection_id(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise TypeError("audit protection_id must be a non-empty string")
    if len(value) > 128 or not value.isascii():
        raise ValueError("audit protection_id exceeds the ASCII bound")
    return value


def _normalized_sql(value: str) -> str:
    return "".join(value.split())


class SQLiteReconciliationAuditJournalV2:
    """Single-host append-only intent/receipt journal."""

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
            raise ValueError("audit database path must be absolute")
        if not candidate.parent.is_dir():
            raise ValueError("audit database parent must exist")
        if candidate.exists() and (
            candidate.is_symlink() or not candidate.is_file()
        ):
            raise ValueError("audit database must be a regular non-symlink file")
        if isinstance(busy_timeout_ms, bool) or not isinstance(
            busy_timeout_ms,
            int,
        ):
            raise TypeError("busy_timeout_ms must be an integer")
        if not 1 <= busy_timeout_ms <= 60_000:
            raise ValueError("busy_timeout_ms is outside bounds")
        self._path = candidate
        self._protection_backend = protection_backend
        self._protection_id = _protection_id(
            getattr(protection_backend, "protection_id", None)
        )
        self._busy_timeout_ms = busy_timeout_ms
        self._initialize()

    @property
    def path(self) -> Path:
        return self._path

    def _raw_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._path,
            timeout=self._busy_timeout_ms / 1_000,
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
                f"SQLite {name} is unavailable"
            )
        return int(row[0])

    @staticmethod
    def _tables(connection: sqlite3.Connection) -> dict[str, str]:
        rows = connection.execute(
            "SELECT name, sql FROM sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        return {str(name): str(sql) for name, sql in rows}

    def _verify_database(self, connection: sqlite3.Connection) -> None:
        if self._pragma(connection, "application_id") != APPLICATION_ID:
            raise ReconciliationAuditJournalIntegrityError(
                "audit database application_id mismatch"
            )
        if self._pragma(connection, "user_version") != SCHEMA_VERSION:
            raise ReconciliationAuditJournalIntegrityError(
                "audit database schema version mismatch"
            )
        tables = self._tables(connection)
        expected = {
            "reconciliation_audit_intents": _INTENT_SCHEMA_SQL,
            "reconciliation_audit_receipts": _RECEIPT_SCHEMA_SQL,
        }
        if set(tables) != set(expected):
            raise ReconciliationAuditJournalIntegrityError(
                "audit database table set mismatch"
            )
        for name, sql in expected.items():
            if _normalized_sql(tables[name]) != _normalized_sql(sql):
                raise ReconciliationAuditJournalIntegrityError(
                    f"audit database {name} schema mismatch"
                )
        mode = connection.execute("PRAGMA journal_mode").fetchone()
        if mode is None or str(mode[0]).lower() != "wal":
            raise ReconciliationAuditJournalIntegrityError(
                "audit database is not in WAL mode"
            )
        if self._pragma(connection, "synchronous") != 2:
            raise ReconciliationAuditJournalIntegrityError(
                "audit database is not FULL synchronous"
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
                if self._pragma(connection, "application_id") != 0:
                    raise ReconciliationAuditJournalIntegrityError(
                        "empty audit database has unexpected application_id"
                    )
                if self._pragma(connection, "user_version") != 0:
                    raise ReconciliationAuditJournalIntegrityError(
                        "empty audit database has unexpected schema version"
                    )
                connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                connection.execute(_INTENT_SCHEMA_SQL)
                connection.execute(_RECEIPT_SCHEMA_SQL)
            self._verify_database(connection)
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
                "audit database path changed type"
            )
        connection = self._raw_connection()
        try:
            self._verify_database(connection)
        except Exception:
            connection.close()
            raise
        return connection

    def _seal(self, plaintext: bytes, *, aad: bytes, maximum: int) -> bytes:
        try:
            protected = self._protection_backend.seal(plaintext, aad=aad)
        except Exception as error:
            raise ReconciliationAuditJournalIntegrityError(
                "audit record sealing failed"
            ) from error
        if not isinstance(protected, bytes) or not 0 < len(protected) <= maximum:
            raise ReconciliationAuditJournalIntegrityError(
                "protected audit record is invalid"
            )
        return protected

    def _open(self, protected: object, *, aad: bytes, maximum: int) -> bytes:
        if not isinstance(protected, bytes) or not 0 < len(protected) <= maximum:
            raise ReconciliationAuditJournalIntegrityError(
                "stored protected audit record is invalid"
            )
        try:
            plaintext = self._protection_backend.open(protected, aad=aad)
        except Exception as error:
            raise ReconciliationAuditJournalIntegrityError(
                "audit record authentication failed"
            ) from error
        if not isinstance(plaintext, bytes):
            raise ReconciliationAuditJournalIntegrityError(
                "audit protector returned non-bytes"
            )
        return plaintext

    @staticmethod
    def _intent_aad(invocation_id: bytes) -> bytes:
        return INTENT_AAD_LABEL + _fixed(
            invocation_id,
            DIGEST_BYTES,
            "invocation_id",
        )

    @staticmethod
    def _receipt_aad(invocation_id: bytes) -> bytes:
        return RECEIPT_AAD_LABEL + _fixed(
            invocation_id,
            DIGEST_BYTES,
            "invocation_id",
        )

    def _decode_intent_row(
        self,
        row: tuple[object, ...],
    ) -> ReconciliationAuditIntentV2:
        if len(row) != 3:
            raise ReconciliationAuditJournalIntegrityError(
                "audit intent row has wrong width"
            )
        invocation_id = _fixed(row[0], DIGEST_BYTES, "stored invocation_id")  # type: ignore[arg-type]
        if row[1] != self._protection_id:
            raise ReconciliationAuditJournalIntegrityError(
                "audit intent protection identity mismatch"
            )
        plaintext = self._open(
            row[2],
            aad=self._intent_aad(invocation_id),
            maximum=MAX_PROTECTED_INTENT_BYTES,
        )
        if not 0 < len(plaintext) <= MAX_AUDIT_INTENT_BYTES:
            raise ReconciliationAuditJournalIntegrityError(
                "audit intent plaintext exceeds its bound"
            )
        try:
            intent = decode_reconciliation_audit_intent(plaintext)
        except Exception as error:
            raise ReconciliationAuditJournalIntegrityError(
                "stored audit intent is invalid"
            ) from error
        if intent.invocation_id != invocation_id:
            raise ReconciliationAuditJournalIntegrityError(
                "audit intent metadata binding mismatch"
            )
        return intent

    def _decode_receipt_row(
        self,
        row: tuple[object, ...],
    ) -> ReservationReconciliationRunResultV2:
        if len(row) != 3:
            raise ReconciliationAuditJournalIntegrityError(
                "audit receipt row has wrong width"
            )
        invocation_id = _fixed(row[0], DIGEST_BYTES, "stored invocation_id")  # type: ignore[arg-type]
        if row[1] != self._protection_id:
            raise ReconciliationAuditJournalIntegrityError(
                "audit receipt protection identity mismatch"
            )
        plaintext = self._open(
            row[2],
            aad=self._receipt_aad(invocation_id),
            maximum=MAX_PROTECTED_RECEIPT_BYTES,
        )
        if not 0 < len(plaintext) <= MAX_AUDIT_RECEIPT_BYTES:
            raise ReconciliationAuditJournalIntegrityError(
                "audit receipt plaintext exceeds its bound"
            )
        try:
            receipt = decode_reconciliation_audit_receipt(plaintext)
        except Exception as error:
            raise ReconciliationAuditJournalIntegrityError(
                "stored audit receipt is invalid"
            ) from error
        if receipt.invocation_id != invocation_id:
            raise ReconciliationAuditJournalIntegrityError(
                "audit receipt metadata binding mismatch"
            )
        return receipt

    def _select_intent(
        self,
        connection: sqlite3.Connection,
        invocation_id: bytes,
    ) -> ReconciliationAuditIntentV2 | None:
        row = connection.execute(
            "SELECT invocation_id, protection_id, protected_intent "
            "FROM reconciliation_audit_intents WHERE invocation_id = ?",
            (invocation_id,),
        ).fetchone()
        return None if row is None else self._decode_intent_row(row)

    def _select_receipt(
        self,
        connection: sqlite3.Connection,
        invocation_id: bytes,
    ) -> ReservationReconciliationRunResultV2 | None:
        row = connection.execute(
            "SELECT invocation_id, protection_id, protected_receipt "
            "FROM reconciliation_audit_receipts WHERE invocation_id = ?",
            (invocation_id,),
        ).fetchone()
        return None if row is None else self._decode_receipt_row(row)

    def load_intent(
        self,
        invocation_id: bytes,
    ) -> ReconciliationAuditIntentV2 | None:
        canonical = _fixed(invocation_id, DIGEST_BYTES, "invocation_id")
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            intent = self._select_intent(connection, canonical)
            connection.execute("COMMIT")
            return intent
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def load_receipt(
        self,
        invocation_id: bytes,
    ) -> ReservationReconciliationRunResultV2 | None:
        canonical = _fixed(invocation_id, DIGEST_BYTES, "invocation_id")
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            intent = self._select_intent(connection, canonical)
            receipt = self._select_receipt(connection, canonical)
            if receipt is not None:
                if intent is None:
                    raise ReconciliationAuditJournalIntegrityError(
                        "audit receipt has no readable intent"
                    )
                try:
                    validate_reconciliation_audit_binding(intent, receipt)
                except Exception as error:
                    raise ReconciliationAuditJournalIntegrityError(
                        "audit receipt and intent binding is invalid"
                    ) from error
            connection.execute("COMMIT")
            return receipt
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def begin_intent(
        self,
        intent: ReconciliationAuditIntentV2,
    ) -> ReconciliationAuditIntentWriteResultV2:
        if not isinstance(intent, ReconciliationAuditIntentV2):
            raise TypeError("intent has the wrong type")
        plaintext = encode_reconciliation_audit_intent(intent)
        protected = self._seal(
            plaintext,
            aad=self._intent_aad(intent.invocation_id),
            maximum=MAX_PROTECTED_INTENT_BYTES,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._select_intent(connection, intent.invocation_id)
            if existing is None:
                connection.execute(
                    "INSERT INTO reconciliation_audit_intents "
                    "(invocation_id, protection_id, protected_intent) "
                    "VALUES (?, ?, ?)",
                    (intent.invocation_id, self._protection_id, protected),
                )
                connection.execute("COMMIT")
                return ReconciliationAuditIntentWriteResultV2(
                    ReconciliationAuditAppendDispositionV2.NEW,
                    intent,
                )
            if existing != intent:
                raise ReconciliationAuditJournalConflict(
                    "invocation_id belongs to another reconciliation intent"
                )
            connection.execute("COMMIT")
            return ReconciliationAuditIntentWriteResultV2(
                ReconciliationAuditAppendDispositionV2.EXISTING,
                existing,
            )
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def append_receipt(
        self,
        receipt: ReservationReconciliationRunResultV2,
    ) -> ReconciliationAuditReceiptWriteResultV2:
        if not isinstance(receipt, ReservationReconciliationRunResultV2):
            raise TypeError("receipt has the wrong type")
        plaintext = encode_reconciliation_audit_receipt(receipt)
        protected = self._seal(
            plaintext,
            aad=self._receipt_aad(receipt.invocation_id),
            maximum=MAX_PROTECTED_RECEIPT_BYTES,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            intent = self._select_intent(connection, receipt.invocation_id)
            if intent is None:
                raise ReconciliationAuditJournalConflict(
                    "audit receipt has no committed intent"
                )
            try:
                validate_reconciliation_audit_binding(intent, receipt)
            except Exception as error:
                raise ReconciliationAuditJournalConflict(
                    "audit receipt does not match its intent"
                ) from error
            existing = self._select_receipt(connection, receipt.invocation_id)
            if existing is None:
                connection.execute(
                    "INSERT INTO reconciliation_audit_receipts "
                    "(invocation_id, protection_id, protected_receipt) "
                    "VALUES (?, ?, ?)",
                    (receipt.invocation_id, self._protection_id, protected),
                )
                connection.execute("COMMIT")
                return ReconciliationAuditReceiptWriteResultV2(
                    ReconciliationAuditAppendDispositionV2.NEW,
                    receipt,
                )
            if existing != receipt:
                raise ReconciliationAuditJournalConflict(
                    "invocation_id belongs to another reconciliation receipt"
                )
            connection.execute("COMMIT")
            return ReconciliationAuditReceiptWriteResultV2(
                ReconciliationAuditAppendDispositionV2.EXISTING,
                existing,
            )
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def counts(self) -> tuple[int, int]:
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            intents = connection.execute(
                "SELECT COUNT(*) FROM reconciliation_audit_intents"
            ).fetchone()
            receipts = connection.execute(
                "SELECT COUNT(*) FROM reconciliation_audit_receipts"
            ).fetchone()
            connection.execute("COMMIT")
            if intents is None or receipts is None:
                raise ReconciliationAuditJournalIntegrityError(
                    "audit journal counts are unavailable"
                )
            return int(intents[0]), int(receipts[0])
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()


def sqlite_reconciliation_audit_manifest() -> dict[str, object]:
    return {
        "format": "PQ-SAT-FGS-RECONCILIATION-AUDIT-SQLITE-v0.2",
        "application_id": f"0x{APPLICATION_ID:08X}",
        "schema_version": SCHEMA_VERSION,
        "journal_mode": "WAL",
        "synchronous": "FULL",
        "tables": [
            "reconciliation_audit_intents",
            "reconciliation_audit_receipts",
        ],
        "claims": {
            "append_only_intent_receipt_api": True,
            "intent_primary_key_unique": True,
            "receipt_requires_intent": True,
            "intent_receipt_policy_binding_enforced": True,
            "exact_retry_idempotent": True,
            "canonical_bounded_records": True,
            "record_protection_backend_boundary": True,
            "single_host_restart_durable_reference": True,
            "cross_process_serialization": True,
            "separate_from_replay_database": True,
            "atomic_with_replay_state": False,
            "incomplete_intent_reconstruction_implemented": False,
            "production_record_protection_instantiated": False,
            "physical_power_loss_tested": False,
            "rollback_resistance": False,
            "distributed": False,
            "production_ready": False,
        },
    }
