"""Single-host SQLite outbox for the exact first application record.

The outbox stores only public header material and authenticated ciphertext.
It prevents a competing plaintext from using sequence zero for the same
session and releases exact wire bytes only after a FULL synchronous commit.
It does not provide rollback resistance or physical-power-loss evidence.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import replace
from pathlib import Path

from ..access import DIGEST_BYTES, SESSION_ID_BYTES
from ..application import (
    FirstRecordOutboxConflictError,
    FirstRecordOutboxEntryV2,
    FirstRecordOutboxStateV2,
    FirstRecordOutboxTransitionKindV2,
    FirstRecordOutboxTransitionV2,
    decode_first_application_record,
    derive_first_application_record_digest,
)


APPLICATION_ID = 0x5051534F
SCHEMA_VERSION = 1
MAX_RECORD_BYTES = 1_048_592
PRODUCTION_READY = False

_SCHEMA_SQL = """CREATE TABLE first_record_outbox (
    session_id BLOB PRIMARY KEY NOT NULL
        CHECK(typeof(session_id) = 'blob' AND length(session_id) = 32),
    state INTEGER NOT NULL CHECK(state IN (1, 2)),
    revision INTEGER NOT NULL CHECK(revision IN (1, 2)),
    suite_id INTEGER NOT NULL CHECK(suite_id BETWEEN 0 AND 65535),
    request_digest BLOB NOT NULL
        CHECK(typeof(request_digest) = 'blob' AND length(request_digest) = 32),
    attempt_id BLOB NOT NULL
        CHECK(typeof(attempt_id) = 'blob' AND length(attempt_id) = 32),
    response_digest BLOB NOT NULL
        CHECK(typeof(response_digest) = 'blob' AND length(response_digest) = 32),
    activation_digest BLOB NOT NULL
        CHECK(typeof(activation_digest) = 'blob' AND length(activation_digest) = 32),
    plaintext_digest BLOB NOT NULL
        CHECK(typeof(plaintext_digest) = 'blob' AND length(plaintext_digest) = 32),
    record_digest BLOB
        CHECK(record_digest IS NULL
              OR (typeof(record_digest) = 'blob' AND length(record_digest) = 32)),
    record_bytes BLOB
        CHECK(record_bytes IS NULL
              OR (typeof(record_bytes) = 'blob'
                  AND length(record_bytes) BETWEEN 1 AND 1048592)),
    CHECK((state = 1 AND revision = 1
           AND record_digest IS NULL AND record_bytes IS NULL)
          OR (state = 2 AND revision = 2
              AND record_digest IS NOT NULL AND record_bytes IS NOT NULL))
) WITHOUT ROWID"""


class FirstRecordOutboxStorageError(RuntimeError):
    pass


class FirstRecordOutboxIntegrityError(RuntimeError):
    pass


def _fixed(value: bytes, size: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    return value


def _integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    return value


def _normalized_sql(value: str) -> str:
    return "".join(value.split())


class SQLiteFirstRecordOutboxV2:
    durable_reference = True
    distributed = False
    production_ready = False

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        candidate = Path(path)
        if not candidate.is_absolute():
            raise ValueError("outbox database path must be absolute")
        if not candidate.parent.is_dir():
            raise ValueError("outbox database parent must exist")
        if candidate.exists() and (candidate.is_symlink() or not candidate.is_file()):
            raise ValueError("outbox database must be a regular non-symlink file")
        if isinstance(busy_timeout_ms, bool) or not isinstance(
            busy_timeout_ms,
            int,
        ):
            raise TypeError("busy_timeout_ms must be an integer")
        if not 1 <= busy_timeout_ms <= 60_000:
            raise ValueError("busy_timeout_ms is outside bounds")
        self._path = candidate
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
            raise FirstRecordOutboxStorageError(f"SQLite {name} is unavailable")
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
            raise FirstRecordOutboxIntegrityError(
                "outbox database application_id mismatch"
            )
        if self._pragma(connection, "user_version") != SCHEMA_VERSION:
            raise FirstRecordOutboxIntegrityError(
                "outbox database schema version mismatch"
            )
        tables = self._tables(connection)
        if set(tables) != {"first_record_outbox"}:
            raise FirstRecordOutboxIntegrityError(
                "outbox database table set mismatch"
            )
        if _normalized_sql(tables["first_record_outbox"]) != _normalized_sql(
            _SCHEMA_SQL
        ):
            raise FirstRecordOutboxIntegrityError("outbox database schema mismatch")
        mode = connection.execute("PRAGMA journal_mode").fetchone()
        if mode is None or str(mode[0]).lower() != "wal":
            raise FirstRecordOutboxIntegrityError("outbox is not in WAL mode")
        if self._pragma(connection, "synchronous") != 2:
            raise FirstRecordOutboxIntegrityError(
                "outbox is not FULL synchronous"
            )

    def _initialize(self) -> None:
        existed = self._path.exists()
        connection = self._raw_connection()
        try:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
            if mode is None or str(mode[0]).lower() != "wal":
                raise FirstRecordOutboxStorageError("SQLite WAL mode is unavailable")
            connection.execute("BEGIN IMMEDIATE")
            if not self._tables(connection):
                if self._pragma(connection, "application_id") != 0:
                    raise FirstRecordOutboxIntegrityError(
                        "empty outbox has unexpected application_id"
                    )
                if self._pragma(connection, "user_version") != 0:
                    raise FirstRecordOutboxIntegrityError(
                        "empty outbox has unexpected schema version"
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
            raise FirstRecordOutboxIntegrityError("outbox path changed type")
        connection = self._raw_connection()
        try:
            self._verify_database(connection)
        except Exception:
            connection.close()
            raise
        return connection

    @staticmethod
    def _decode_row(row: tuple[object, ...]) -> FirstRecordOutboxEntryV2:
        if len(row) != 11:
            raise FirstRecordOutboxIntegrityError("outbox row has wrong width")
        try:
            state = FirstRecordOutboxStateV2(
                _integer(row[0], "stored outbox state")
            )
            record_digest = row[9]
            record_bytes = row[10]
            if record_digest is not None and not isinstance(record_digest, bytes):
                raise TypeError("stored record_digest must be bytes")
            if record_bytes is not None and not isinstance(record_bytes, bytes):
                raise TypeError("stored record_bytes must be bytes")
            entry = FirstRecordOutboxEntryV2(
                state=state,
                revision=_integer(row[1], "stored outbox revision"),
                suite_id=_integer(row[2], "stored suite_id"),
                request_digest=_fixed(row[3], DIGEST_BYTES, "request_digest"),  # type: ignore[arg-type]
                attempt_id=_fixed(row[4], DIGEST_BYTES, "attempt_id"),  # type: ignore[arg-type]
                session_id=_fixed(row[5], SESSION_ID_BYTES, "session_id"),  # type: ignore[arg-type]
                response_digest=_fixed(row[6], DIGEST_BYTES, "response_digest"),  # type: ignore[arg-type]
                activation_digest=_fixed(row[7], DIGEST_BYTES, "activation_digest"),  # type: ignore[arg-type]
                plaintext_digest=_fixed(row[8], DIGEST_BYTES, "plaintext_digest"),  # type: ignore[arg-type]
                record_digest=record_digest,
                record_bytes=record_bytes,
            )
            entry.validate()
            return entry
        except Exception as error:
            raise FirstRecordOutboxIntegrityError(
                "stored outbox entry is invalid"
            ) from error

    @staticmethod
    def _select(
        connection: sqlite3.Connection,
        session_id: bytes,
    ) -> FirstRecordOutboxEntryV2 | None:
        row = connection.execute(
            "SELECT state, revision, suite_id, request_digest, attempt_id, "
            "session_id, response_digest, activation_digest, plaintext_digest, "
            "record_digest, record_bytes FROM first_record_outbox "
            "WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        return None if row is None else SQLiteFirstRecordOutboxV2._decode_row(row)

    def load(self, session_id: bytes) -> FirstRecordOutboxEntryV2 | None:
        canonical = _fixed(session_id, SESSION_ID_BYTES, "session_id")
        connection = self._connect()
        try:
            return self._select(connection, canonical)
        finally:
            connection.close()

    def reserve(
        self,
        candidate: FirstRecordOutboxEntryV2,
    ) -> FirstRecordOutboxTransitionV2:
        candidate.validate()
        if candidate.state is not FirstRecordOutboxStateV2.RESERVED:
            raise ValueError("outbox reservation candidate must be RESERVED")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._select(connection, candidate.session_id)
            if existing is not None:
                if existing.identity != candidate.identity:
                    raise FirstRecordOutboxConflictError(
                        "session is reserved for another first record"
                    )
                connection.execute("COMMIT")
                return FirstRecordOutboxTransitionV2(
                    FirstRecordOutboxTransitionKindV2.EXISTING,
                    existing,
                )
            connection.execute(
                "INSERT INTO first_record_outbox "
                "(session_id, state, revision, suite_id, request_digest, "
                "attempt_id, response_digest, activation_digest, "
                "plaintext_digest, record_digest, record_bytes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                (
                    candidate.session_id,
                    int(candidate.state),
                    candidate.revision,
                    candidate.suite_id,
                    candidate.request_digest,
                    candidate.attempt_id,
                    candidate.response_digest,
                    candidate.activation_digest,
                    candidate.plaintext_digest,
                ),
            )
            connection.execute("COMMIT")
            return FirstRecordOutboxTransitionV2(
                FirstRecordOutboxTransitionKindV2.CREATED,
                candidate,
            )
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def finalize(
        self,
        candidate: FirstRecordOutboxEntryV2,
        record_bytes: bytes,
    ) -> FirstRecordOutboxTransitionV2:
        candidate.validate()
        if candidate.state is not FirstRecordOutboxStateV2.RESERVED:
            raise ValueError("outbox finalization candidate must be RESERVED")
        if not isinstance(record_bytes, bytes) or not record_bytes:
            raise TypeError("record_bytes must be non-empty bytes")
        if len(record_bytes) > MAX_RECORD_BYTES:
            raise ValueError("record_bytes exceeds the outbox maximum")
        record = decode_first_application_record(record_bytes)
        record_digest = derive_first_application_record_digest(record)
        ready = replace(
            candidate,
            state=FirstRecordOutboxStateV2.READY,
            revision=2,
            record_digest=record_digest,
            record_bytes=record_bytes,
        )
        ready.validate()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._select(connection, candidate.session_id)
            if existing is None:
                raise FirstRecordOutboxConflictError(
                    "outbox reservation is missing"
                )
            if existing.identity != candidate.identity:
                raise FirstRecordOutboxConflictError(
                    "outbox reservation identity changed"
                )
            if existing.state is FirstRecordOutboxStateV2.READY:
                if existing != ready:
                    raise FirstRecordOutboxConflictError(
                        "session already finalized another first record"
                    )
                connection.execute("COMMIT")
                return FirstRecordOutboxTransitionV2(
                    FirstRecordOutboxTransitionKindV2.EXISTING,
                    existing,
                )
            connection.execute(
                "UPDATE first_record_outbox SET state = 2, revision = 2, "
                "record_digest = ?, record_bytes = ? "
                "WHERE session_id = ? AND state = 1 AND revision = 1",
                (record_digest, record_bytes, candidate.session_id),
            )
            if connection.total_changes != 1:
                raise FirstRecordOutboxStorageError(
                    "outbox finalization changed an unexpected row count"
                )
            connection.execute("COMMIT")
            return FirstRecordOutboxTransitionV2(
                FirstRecordOutboxTransitionKindV2.CREATED,
                ready,
            )
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()


def sqlite_first_record_outbox_manifest() -> dict[str, object]:
    return {
        "format": "PQ-SAT-FIRST-RECORD-OUTBOX-SQLITE-v0.2",
        "application_id": f"0x{APPLICATION_ID:08x}",
        "schema_version": SCHEMA_VERSION,
        "journal_mode": "WAL",
        "synchronous": "FULL",
        "states": [state.name for state in FirstRecordOutboxStateV2],
        "claims": {
            "single_host_reference_durability": True,
            "exact_record_committed_before_release": True,
            "competing_sequence_zero_plaintext_rejected": True,
            "record_contains_secrets_at_rest": False,
            "rollback_resistance": False,
            "physical_power_loss_tested": False,
            "distributed": False,
            "production_ready": False,
        },
    }
