"""Protected single-host SQLite inbox for first application work items.

The inbox atomically binds a session and record digest to authenticated
plaintext before the FGS reports the record as queued.  Pending work survives
process restart and can be completed with a stable application receipt.  The
external application must separately honor the idempotency-key contract.
"""

from __future__ import annotations

import json
import os
import sqlite3
import struct
from dataclasses import replace
from pathlib import Path
from typing import Protocol

from ..access import DIGEST_BYTES, SESSION_ID_BYTES
from ..application import (
    FirstApplicationInboxEntryV2,
    FirstApplicationInboxStateV2,
    FirstRecordOutboxConflictError,
    InboxEnqueueDispositionV2,
    InboxEnqueueResultV2,
    MAX_APPLICATION_PLAINTEXT_BYTES,
    MAX_APPLICATION_RECEIPT_BYTES,
)


APPLICATION_ID = 0x50515349
SCHEMA_VERSION = 1
INBOX_RECORD_FORMAT = "PQ-SAT-FGS-APPLICATION-INBOX-RECORD-v0.2"
INBOX_RECORD_AAD_LABEL = b"PQ-SAT/FGS-APPLICATION-INBOX-AAD/v0.2"
MAX_CANONICAL_RECORD_BYTES = 2_400_000
MAX_PROTECTED_RECORD_BYTES = 2_800_000
PRODUCTION_READY = False

_SCHEMA_SQL = """CREATE TABLE first_application_inbox (
    session_id BLOB PRIMARY KEY NOT NULL
        CHECK(typeof(session_id) = 'blob' AND length(session_id) = 32),
    record_digest BLOB NOT NULL
        CHECK(typeof(record_digest) = 'blob' AND length(record_digest) = 32),
    state INTEGER NOT NULL CHECK(state IN (1, 2)),
    revision INTEGER NOT NULL CHECK(revision IN (1, 2)),
    protection_id TEXT NOT NULL
        CHECK(typeof(protection_id) = 'text'
              AND length(protection_id) BETWEEN 1 AND 128),
    protected_record BLOB NOT NULL
        CHECK(typeof(protected_record) = 'blob'
              AND length(protected_record) BETWEEN 1 AND 2800000),
    CHECK(state = revision)
) WITHOUT ROWID"""


class ApplicationInboxStorageError(RuntimeError):
    pass


class ApplicationInboxIntegrityError(RuntimeError):
    pass


class FGSApplicationInboxProtectionV2(Protocol):
    protection_id: str
    production_ready: bool

    def seal(self, plaintext: bytes, *, aad: bytes) -> bytes: ...

    def open(self, protected_record: bytes, *, aad: bytes) -> bytes: ...


def _fixed(value: bytes, size: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    return value


def _bounded_bytes(value: object, maximum: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if not value:
        raise ValueError(f"{name} must not be empty")
    if len(value) > maximum:
        raise ValueError(f"{name} exceeds its size bound")
    return value


def _integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _hex(value: bytes) -> str:
    if not isinstance(value, bytes):
        raise TypeError("canonical byte field must be bytes")
    return value.hex()


def _unhex(value: object, name: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a hex string")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{name} is not hexadecimal") from error
    if decoded.hex() != value:
        raise ValueError(f"{name} is not canonical lowercase hex")
    return decoded


def _mapping(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) for key in value
    ):
        raise TypeError(f"{name} must be a string-keyed object")
    return value


def _canonical_json(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def encode_application_inbox_entry(entry: FirstApplicationInboxEntryV2) -> bytes:
    if not isinstance(entry, FirstApplicationInboxEntryV2):
        raise TypeError("entry must be a FirstApplicationInboxEntryV2")
    entry.validate()
    value: dict[str, object] = {
        "format": INBOX_RECORD_FORMAT,
        "plaintext": _hex(entry.plaintext),
        "receipt": None if entry.receipt is None else _hex(entry.receipt),
        "record_digest": _hex(entry.record_digest),
        "revision": entry.revision,
        "session_id": _hex(entry.session_id),
        "state": entry.state.name,
    }
    encoded = _canonical_json(value)
    if len(encoded) > MAX_CANONICAL_RECORD_BYTES:
        raise ValueError("application inbox record exceeds the size bound")
    return encoded


def decode_application_inbox_entry(
    encoded: bytes,
) -> FirstApplicationInboxEntryV2:
    if not isinstance(encoded, bytes) or not encoded:
        raise TypeError("application inbox record must be non-empty bytes")
    if len(encoded) > MAX_CANONICAL_RECORD_BYTES:
        raise ApplicationInboxIntegrityError(
            "application inbox record exceeds the size bound"
        )
    try:
        item = _mapping(json.loads(encoded.decode("ascii")), "inbox record")
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ApplicationInboxIntegrityError(
            "application inbox record is not canonical JSON"
        ) from error
    expected = {
        "format",
        "plaintext",
        "receipt",
        "record_digest",
        "revision",
        "session_id",
        "state",
    }
    if set(item) != expected:
        raise ApplicationInboxIntegrityError(
            "application inbox record has unknown or missing fields"
        )
    if item["format"] != INBOX_RECORD_FORMAT:
        raise ApplicationInboxIntegrityError(
            "application inbox record format mismatch"
        )
    try:
        state = FirstApplicationInboxStateV2[item["state"]]  # type: ignore[index]
        receipt_value = item["receipt"]
        receipt = (
            None
            if receipt_value is None
            else _bounded_bytes(
                _unhex(receipt_value, "receipt"),
                MAX_APPLICATION_RECEIPT_BYTES,
                "receipt",
            )
        )
        entry = FirstApplicationInboxEntryV2(
            state=state,
            revision=_integer(item["revision"], "revision"),
            session_id=_fixed(
                _unhex(item["session_id"], "session_id"),
                SESSION_ID_BYTES,
                "session_id",
            ),
            record_digest=_fixed(
                _unhex(item["record_digest"], "record_digest"),
                DIGEST_BYTES,
                "record_digest",
            ),
            plaintext=_bounded_bytes(
                _unhex(item["plaintext"], "plaintext"),
                MAX_APPLICATION_PLAINTEXT_BYTES,
                "plaintext",
            ),
            receipt=receipt,
        )
        entry.validate()
    except Exception as error:
        raise ApplicationInboxIntegrityError(
            "application inbox record is invalid"
        ) from error
    if encode_application_inbox_entry(entry) != encoded:
        raise ApplicationInboxIntegrityError(
            "application inbox record encoding is non-canonical"
        )
    return entry


def _protection_id(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("protection_id must be a string")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("protection_id must be ASCII") from error
    if not 1 <= len(encoded) <= 128:
        raise ValueError("protection_id length is outside bounds")
    if any(byte < 0x21 or byte > 0x7E for byte in encoded):
        raise ValueError("protection_id contains invalid characters")
    return value


def _record_aad(
    session_id: bytes,
    record_digest: bytes,
    state: FirstApplicationInboxStateV2,
) -> bytes:
    return b"".join(
        (
            INBOX_RECORD_AAD_LABEL,
            _fixed(session_id, SESSION_ID_BYTES, "session_id"),
            _fixed(record_digest, DIGEST_BYTES, "record_digest"),
            struct.pack(">HH", int(state), int(state)),
        )
    )


def _normalized_sql(value: str) -> str:
    return "".join(value.split())


class SQLiteFirstApplicationInboxV2:
    durable = True
    distributed = False
    production_ready = False

    def __init__(
        self,
        path: str | os.PathLike[str],
        protection_backend: FGSApplicationInboxProtectionV2,
        *,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        candidate = Path(path)
        if not candidate.is_absolute():
            raise ValueError("inbox database path must be absolute")
        if not candidate.parent.is_dir():
            raise ValueError("inbox database parent must exist")
        if candidate.exists() and (
            candidate.is_symlink() or not candidate.is_file()
        ):
            raise ValueError("inbox database must be a regular non-symlink file")
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
            raise ApplicationInboxStorageError(f"SQLite {name} is unavailable")
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
            raise ApplicationInboxIntegrityError(
                "inbox database application_id mismatch"
            )
        if self._pragma(connection, "user_version") != SCHEMA_VERSION:
            raise ApplicationInboxIntegrityError(
                "inbox database schema version mismatch"
            )
        tables = self._tables(connection)
        if set(tables) != {"first_application_inbox"}:
            raise ApplicationInboxIntegrityError(
                "inbox database table set mismatch"
            )
        if _normalized_sql(
            tables["first_application_inbox"]
        ) != _normalized_sql(_SCHEMA_SQL):
            raise ApplicationInboxIntegrityError("inbox database schema mismatch")
        mode = connection.execute("PRAGMA journal_mode").fetchone()
        if mode is None or str(mode[0]).lower() != "wal":
            raise ApplicationInboxIntegrityError("inbox is not in WAL mode")
        if self._pragma(connection, "synchronous") != 2:
            raise ApplicationInboxIntegrityError(
                "inbox is not FULL synchronous"
            )

    def _initialize(self) -> None:
        existed = self._path.exists()
        connection = self._raw_connection()
        try:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
            if mode is None or str(mode[0]).lower() != "wal":
                raise ApplicationInboxStorageError("SQLite WAL mode is unavailable")
            connection.execute("BEGIN IMMEDIATE")
            if not self._tables(connection):
                if self._pragma(connection, "application_id") != 0:
                    raise ApplicationInboxIntegrityError(
                        "empty inbox has unexpected application_id"
                    )
                if self._pragma(connection, "user_version") != 0:
                    raise ApplicationInboxIntegrityError(
                        "empty inbox has unexpected schema version"
                    )
                connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                connection.execute(_SCHEMA_SQL)
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
            raise ApplicationInboxIntegrityError("inbox path changed type")
        connection = self._raw_connection()
        try:
            self._verify_database(connection)
        except Exception:
            connection.close()
            raise
        return connection

    def _protect(self, entry: FirstApplicationInboxEntryV2) -> bytes:
        plaintext = encode_application_inbox_entry(entry)
        try:
            protected = self._protection_backend.seal(
                plaintext,
                aad=_record_aad(
                    entry.session_id,
                    entry.record_digest,
                    entry.state,
                ),
            )
        except Exception as error:
            raise ApplicationInboxIntegrityError(
                "application inbox record sealing failed"
            ) from error
        if not isinstance(protected, bytes) or not protected:
            raise ApplicationInboxIntegrityError(
                "application inbox protector returned an invalid record"
            )
        if len(protected) > MAX_PROTECTED_RECORD_BYTES:
            raise ApplicationInboxIntegrityError(
                "protected application inbox record exceeds bounds"
            )
        return protected

    def _decode_row(self, row: tuple[object, ...]) -> FirstApplicationInboxEntryV2:
        if len(row) != 6:
            raise ApplicationInboxIntegrityError("inbox row has wrong width")
        session_id, record_digest, state_value, revision, protection_id, protected = row
        try:
            session = _fixed(session_id, SESSION_ID_BYTES, "stored session_id")  # type: ignore[arg-type]
            digest = _fixed(record_digest, DIGEST_BYTES, "stored record_digest")  # type: ignore[arg-type]
            state = FirstApplicationInboxStateV2(
                _integer(state_value, "stored inbox state")
            )
            stored_revision = _integer(revision, "stored inbox revision")
            if stored_revision != int(state):
                raise ValueError("stored inbox state and revision differ")
            if protection_id != self._protection_id:
                raise ValueError("application inbox protection identity mismatch")
            if not isinstance(protected, bytes) or not protected:
                raise TypeError("protected application inbox record is invalid")
            if len(protected) > MAX_PROTECTED_RECORD_BYTES:
                raise ValueError("protected application inbox record exceeds bounds")
            opened = self._protection_backend.open(
                protected,
                aad=_record_aad(session, digest, state),
            )
            if not isinstance(opened, bytes) or not opened:
                raise TypeError("application inbox protector returned invalid plaintext")
            entry = decode_application_inbox_entry(opened)
            if (
                entry.session_id,
                entry.record_digest,
                entry.state,
                entry.revision,
            ) != (session, digest, state, stored_revision):
                raise ValueError("inbox row and protected record differ")
            return entry
        except Exception as error:
            raise ApplicationInboxIntegrityError(
                "stored application inbox entry is invalid"
            ) from error

    def _select(
        self,
        connection: sqlite3.Connection,
        session_id: bytes,
    ) -> FirstApplicationInboxEntryV2 | None:
        row = connection.execute(
            "SELECT session_id, record_digest, state, revision, "
            "protection_id, protected_record FROM first_application_inbox "
            "WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        return None if row is None else self._decode_row(row)

    def load(self, session_id: bytes) -> FirstApplicationInboxEntryV2 | None:
        session = _fixed(session_id, SESSION_ID_BYTES, "session_id")
        connection = self._connect()
        try:
            return self._select(connection, session)
        finally:
            connection.close()

    def enqueue(
        self,
        session_id: bytes,
        record_digest: bytes,
        plaintext: bytes,
    ) -> InboxEnqueueResultV2:
        candidate = FirstApplicationInboxEntryV2(
            state=FirstApplicationInboxStateV2.PENDING,
            revision=1,
            session_id=session_id,
            record_digest=record_digest,
            plaintext=plaintext,
        )
        candidate.validate()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._select(connection, candidate.session_id)
            if existing is not None:
                if (
                    existing.record_digest != candidate.record_digest
                    or existing.plaintext != candidate.plaintext
                ):
                    raise FirstRecordOutboxConflictError(
                        "session inbox already contains another first record"
                    )
                disposition = (
                    InboxEnqueueDispositionV2.EXISTING_PENDING
                    if existing.state is FirstApplicationInboxStateV2.PENDING
                    else InboxEnqueueDispositionV2.EXISTING_COMPLETED
                )
                connection.execute("COMMIT")
                return InboxEnqueueResultV2(
                    disposition,
                    existing.session_id,
                    existing.record_digest,
                )
            protected = self._protect(candidate)
            cursor = connection.execute(
                "INSERT INTO first_application_inbox "
                "(session_id, record_digest, state, revision, protection_id, "
                "protected_record) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    candidate.session_id,
                    candidate.record_digest,
                    int(candidate.state),
                    candidate.revision,
                    self._protection_id,
                    protected,
                ),
            )
            if cursor.rowcount != 1:
                raise ApplicationInboxStorageError(
                    "inbox enqueue changed an unexpected row count"
                )
            connection.execute("COMMIT")
            result = InboxEnqueueResultV2(
                InboxEnqueueDispositionV2.NEW,
                candidate.session_id,
                candidate.record_digest,
            )
            result.validate()
            return result
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def complete(
        self,
        session_id: bytes,
        record_digest: bytes,
        receipt: bytes,
    ) -> FirstApplicationInboxEntryV2:
        session = _fixed(session_id, SESSION_ID_BYTES, "session_id")
        digest = _fixed(record_digest, DIGEST_BYTES, "record_digest")
        completed_receipt = _bounded_bytes(
            receipt,
            MAX_APPLICATION_RECEIPT_BYTES,
            "receipt",
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._select(connection, session)
            if existing is None:
                raise FirstRecordOutboxConflictError(
                    "cannot complete a missing application inbox item"
                )
            if existing.record_digest != digest:
                raise FirstRecordOutboxConflictError(
                    "application receipt belongs to another first record"
                )
            if existing.state is FirstApplicationInboxStateV2.COMPLETED:
                if existing.receipt != completed_receipt:
                    raise FirstRecordOutboxConflictError(
                        "completed application receipt cannot change"
                    )
                connection.execute("COMMIT")
                return existing
            completed = replace(
                existing,
                state=FirstApplicationInboxStateV2.COMPLETED,
                revision=2,
                receipt=completed_receipt,
            )
            completed.validate()
            protected = self._protect(completed)
            cursor = connection.execute(
                "UPDATE first_application_inbox SET state = ?, revision = ?, "
                "protected_record = ? WHERE session_id = ? AND state = 1 "
                "AND revision = 1",
                (
                    int(completed.state),
                    completed.revision,
                    protected,
                    completed.session_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ApplicationInboxStorageError(
                    "inbox completion changed an unexpected row count"
                )
            connection.execute("COMMIT")
            return completed
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def pending(self, *, limit: int = 100) -> tuple[bytes, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("pending limit must be an integer")
        if not 1 <= limit <= 1_000:
            raise ValueError("pending limit is outside bounds")
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT session_id, record_digest, state, revision, "
                "protection_id, protected_record FROM first_application_inbox "
                "WHERE state = 1 ORDER BY session_id LIMIT ?",
                (limit,),
            ).fetchall()
            entries = tuple(self._decode_row(row) for row in rows)
            return tuple(entry.session_id for entry in entries)
        finally:
            connection.close()

    def __len__(self) -> int:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT COUNT(*) FROM first_application_inbox"
            ).fetchone()
            if row is None:
                raise ApplicationInboxStorageError("inbox count is unavailable")
            return int(row[0])
        finally:
            connection.close()


def sqlite_first_application_inbox_manifest() -> dict[str, object]:
    return {
        "format": "PQ-SAT-FGS-APPLICATION-INBOX-SQLITE-v0.2",
        "application_id": f"0x{APPLICATION_ID:08x}",
        "schema_version": SCHEMA_VERSION,
        "journal_mode": "WAL",
        "synchronous": "FULL",
        "record_format": INBOX_RECORD_FORMAT,
        "record_aad_domain": INBOX_RECORD_AAD_LABEL.decode("ascii"),
        "states": [state.name for state in FirstApplicationInboxStateV2],
        "claims": {
            "single_host_cross_process_durable_reference": True,
            "plaintext_protection_backend_boundary": True,
            "pending_scan_for_restart_recovery": True,
            "exact_enqueue_and_completion_idempotent": True,
            "competing_record_or_receipt_rejected": True,
            "production_plaintext_protection_instantiated": False,
            "application_apply_once_required": True,
            "external_application_exactly_once_proven": False,
            "hostile_filesystem_protection": False,
            "rollback_resistance": False,
            "physical_power_loss_tested": False,
            "distributed": False,
            "production_ready": False,
        },
    }
