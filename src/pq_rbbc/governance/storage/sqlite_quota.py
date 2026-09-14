"""SQLite issuer quota/SID store for one host and multiple processes.

The store preserves :class:`IssuerQuotaStore` semantics across process
restarts.  Each call uses a fresh connection and one ``BEGIN IMMEDIATE``
transaction.  Grant initialization/quota consistency, replay lookup, SID
insertion, and quota decrement therefore share one SQLite commit boundary.

This is not a distributed store.  All cooperating processes must open the
same database on a local filesystem whose locking and fsync behavior satisfy
SQLite's requirements.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path

from pq_rbbc.contracts.system import ContractError, _require_fixed_bytes, _require_uint
from pq_rbbc.governance.issuer_authorization import (
    GRANT_DIGEST_BYTES,
    MAX_ISSUER_SID_BYTES,
    QuotaConsumeResult,
    QuotaConsumeStatus,
    _validate_issuer_sid,
)


SQLITE_APPLICATION_ID = 0x50514731  # ASCII "PQG1".
SQLITE_SCHEMA_VERSION = 1
DEFAULT_BUSY_TIMEOUT_MS = 5_000
MAX_BUSY_TIMEOUT_MS = (1 << 31) - 1
STORE_FORMAT = "PQRBBC-ISSUER-QUOTA-SQLITE-V1"

_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE quota_store_metadata (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        format TEXT NOT NULL CHECK (format = 'PQRBBC-ISSUER-QUOTA-SQLITE-V1'),
        schema_version INTEGER NOT NULL CHECK (schema_version = 1),
        schema_sha256 TEXT NOT NULL CHECK (length(schema_sha256) = 64)
    ) STRICT
    """,
    """
    CREATE TABLE issuer_grants (
        grant_digest BLOB PRIMARY KEY
            CHECK (typeof(grant_digest) = 'blob' AND length(grant_digest) = 32),
        initial_quota BLOB NOT NULL
            CHECK (typeof(initial_quota) = 'blob' AND length(initial_quota) = 8),
        remaining_quota BLOB NOT NULL
            CHECK (typeof(remaining_quota) = 'blob' AND length(remaining_quota) = 8)
    ) STRICT
    """,
    """
    CREATE TABLE consumed_issuer_sids (
        grant_digest BLOB NOT NULL
            CHECK (typeof(grant_digest) = 'blob' AND length(grant_digest) = 32),
        issuer_sid BLOB NOT NULL
            CHECK (
                typeof(issuer_sid) = 'blob'
                AND length(issuer_sid) BETWEEN 1 AND 65536
            ),
        PRIMARY KEY (grant_digest, issuer_sid),
        FOREIGN KEY (grant_digest) REFERENCES issuer_grants(grant_digest)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    ) STRICT
    """,
)

_SCHEMA_TABLES = (
    ("quota_store_metadata", _SCHEMA_STATEMENTS[0]),
    ("issuer_grants", _SCHEMA_STATEMENTS[1]),
    ("consumed_issuer_sids", _SCHEMA_STATEMENTS[2]),
)


def _schema_sql_digest(schema_sql: tuple[str, ...]) -> str:
    return hashlib.sha256(
        b"\x00".join(sql.strip().encode("utf-8") for sql in schema_sql)
    ).hexdigest()


SCHEMA_SHA256 = _schema_sql_digest(
    tuple(statement for _, statement in _SCHEMA_TABLES)
)

_EXPECTED_SCHEMA_RECORDS = tuple(
    sorted(
        (
            "table",
            table,
            table,
            statement.strip(),
        )
        for table, statement in _SCHEMA_TABLES
    )
)

_EXPECTED_TABLE_COLUMNS = {
    "quota_store_metadata": (
        (0, "singleton", "INTEGER", 0, None, 1, 0),
        (1, "format", "TEXT", 1, None, 0, 0),
        (2, "schema_version", "INTEGER", 1, None, 0, 0),
        (3, "schema_sha256", "TEXT", 1, None, 0, 0),
    ),
    "issuer_grants": (
        (0, "grant_digest", "BLOB", 1, None, 1, 0),
        (1, "initial_quota", "BLOB", 1, None, 0, 0),
        (2, "remaining_quota", "BLOB", 1, None, 0, 0),
    ),
    "consumed_issuer_sids": (
        (0, "grant_digest", "BLOB", 1, None, 1, 0),
        (1, "issuer_sid", "BLOB", 1, None, 2, 0),
    ),
}

_EXPECTED_TABLE_PROPERTIES = {
    "quota_store_metadata": ("table", 4, 0, 1),
    "issuer_grants": ("table", 3, 0, 1),
    "consumed_issuer_sids": ("table", 2, 0, 1),
}

_EXPECTED_FOREIGN_KEYS = {
    "quota_store_metadata": (),
    "issuer_grants": (),
    "consumed_issuer_sids": (
        (
            0,
            0,
            "issuer_grants",
            "grant_digest",
            "grant_digest",
            "RESTRICT",
            "RESTRICT",
            "NONE",
        ),
    ),
}


class SQLiteQuotaStoreError(RuntimeError):
    """Base class for fail-closed SQLite backend failures."""


class SQLiteQuotaStoreBusyError(SQLiteQuotaStoreError):
    """The writer lock was not obtained within the configured timeout."""


class SQLiteQuotaStoreCorruptError(SQLiteQuotaStoreError):
    """SQLite reported corrupt or non-database bytes."""


class SQLiteQuotaStoreSchemaError(SQLiteQuotaStoreError):
    """The database is not the exact supported schema."""


def _quota_bytes(quota: int) -> bytes:
    return quota.to_bytes(8, "little")


def _quota_from_bytes(raw: object, label: str) -> int:
    if not isinstance(raw, bytes) or len(raw) != 8:
        raise SQLiteQuotaStoreCorruptError(f"{label} is not canonical u64le")
    return int.from_bytes(raw, "little")


def _database_error(error: sqlite3.Error) -> SQLiteQuotaStoreError:
    code = getattr(error, "sqlite_errorcode", None)
    primary_code = code & 0xFF if isinstance(code, int) else None
    if primary_code in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
        return SQLiteQuotaStoreBusyError("SQLite database is busy or locked")
    if primary_code in (sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB):
        return SQLiteQuotaStoreCorruptError("SQLite database is corrupt or invalid")
    return SQLiteQuotaStoreError(f"SQLite backend failure: {type(error).__name__}")


class SQLiteIssuerQuotaStore:
    """Persistent ``IssuerQuotaStore`` for one host.

    ``database_path`` must be an absolute filesystem path.  The caller owns
    provisioning of its parent directory and must keep the database, ``-wal``,
    and ``-shm`` files outside the repository with deployment-appropriate
    access controls.
    """

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    ) -> None:
        path_value = os.fspath(database_path)
        if not isinstance(path_value, str) or not path_value or "\x00" in path_value:
            raise ValueError("database_path must be a nonempty text path")
        if path_value == ":memory:" or path_value.startswith("file:"):
            raise ValueError("database_path must name a persistent filesystem file")
        path = Path(path_value)
        if not path.is_absolute():
            raise ValueError("database_path must be absolute")
        _require_uint(busy_timeout_ms, 4, "busy_timeout_ms")
        if busy_timeout_ms > MAX_BUSY_TIMEOUT_MS:
            raise ContractError("busy_timeout_ms is outside SQLite range")
        self._database_path = str(path)
        self._busy_timeout_ms = busy_timeout_ms
        self._initialize()

    @property
    def database_path(self) -> str:
        return self._database_path

    @property
    def busy_timeout_ms(self) -> int:
        return self._busy_timeout_ms

    def _raw_connection(self) -> sqlite3.Connection:
        return sqlite3.connect(
            self._database_path,
            timeout=self._busy_timeout_ms / 1_000,
            isolation_level=None,
        )

    def _configure_connection(self, connection: sqlite3.Connection) -> None:
        connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA synchronous = FULL")

    @staticmethod
    def _database_identity(connection: sqlite3.Connection) -> tuple[int, int]:
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        return application_id, user_version

    @staticmethod
    def _user_objects(connection: sqlite3.Connection) -> tuple[tuple[str, str], ...]:
        rows = connection.execute(
            """
            SELECT type, name
            FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name
            """
        ).fetchall()
        return tuple((str(row[0]), str(row[1])) for row in rows)

    @staticmethod
    def _user_schema_records(
        connection: sqlite3.Connection,
    ) -> tuple[tuple[str, str, str, str], ...]:
        rows = connection.execute(
            """
            SELECT type, name, tbl_name, sql
            FROM sqlite_schema
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name
            """
        ).fetchall()
        if any(not all(isinstance(value, str) for value in row) for row in rows):
            raise SQLiteQuotaStoreSchemaError("non-text SQLite schema record")
        return tuple(
            (str(row[0]), str(row[1]), str(row[2]), str(row[3]).strip())
            for row in rows
        )

    @classmethod
    def _is_unclaimed_empty(cls, connection: sqlite3.Connection) -> bool:
        return cls._database_identity(connection) == (0, 0) and not cls._user_objects(
            connection
        )

    @classmethod
    def _require_known_identity(cls, connection: sqlite3.Connection) -> None:
        application_id, user_version = cls._database_identity(connection)
        if application_id != SQLITE_APPLICATION_ID:
            raise SQLiteQuotaStoreSchemaError("unknown SQLite application_id")
        if user_version != SQLITE_SCHEMA_VERSION:
            raise SQLiteQuotaStoreSchemaError("unknown SQLite schema version")

    @classmethod
    def _validate_schema(cls, connection: sqlite3.Connection) -> None:
        cls._require_known_identity(connection)
        expected_objects = tuple(
            ("table", name) for name in sorted(_EXPECTED_TABLE_COLUMNS)
        )
        if cls._user_objects(connection) != expected_objects:
            raise SQLiteQuotaStoreSchemaError("unexpected SQLite schema objects")

        schema_records = cls._user_schema_records(connection)
        if schema_records != _EXPECTED_SCHEMA_RECORDS:
            raise SQLiteQuotaStoreSchemaError(
                "SQLite CREATE statements do not match canonical schema"
            )
        schema_sql_by_table = {record[1]: record[3] for record in schema_records}
        actual_schema_sha256 = _schema_sql_digest(
            tuple(schema_sql_by_table[table] for table, _ in _SCHEMA_TABLES)
        )
        if actual_schema_sha256 != SCHEMA_SHA256:
            raise SQLiteQuotaStoreSchemaError("actual SQLite schema digest mismatch")

        table_properties = {
            str(row[1]): (str(row[2]), int(row[3]), int(row[4]), int(row[5]))
            for row in connection.execute("PRAGMA main.table_list").fetchall()
            if str(row[0]) == "main" and not str(row[1]).startswith("sqlite_")
        }
        if table_properties != _EXPECTED_TABLE_PROPERTIES:
            raise SQLiteQuotaStoreSchemaError(
                "SQLite table properties, including STRICT, do not match"
            )

        for table, expected_columns in _EXPECTED_TABLE_COLUMNS.items():
            rows = connection.execute(f"PRAGMA main.table_xinfo({table})").fetchall()
            actual_columns = tuple(
                (
                    int(row[0]),
                    str(row[1]),
                    str(row[2]).upper(),
                    int(row[3]),
                    row[4],
                    int(row[5]),
                    int(row[6]),
                )
                for row in rows
            )
            if actual_columns != expected_columns:
                raise SQLiteQuotaStoreSchemaError(
                    f"unexpected SQLite columns for {table}"
                )
            actual_foreign_keys = tuple(
                (
                    int(row[0]),
                    int(row[1]),
                    str(row[2]),
                    str(row[3]),
                    str(row[4]),
                    str(row[5]),
                    str(row[6]),
                    str(row[7]),
                )
                for row in connection.execute(
                    f"PRAGMA main.foreign_key_list({table})"
                ).fetchall()
            )
            if actual_foreign_keys != _EXPECTED_FOREIGN_KEYS[table]:
                raise SQLiteQuotaStoreSchemaError(
                    f"unexpected SQLite foreign keys for {table}"
                )
        metadata = connection.execute(
            """
            SELECT format, schema_version, schema_sha256
            FROM quota_store_metadata
            WHERE singleton = 1
            """
        ).fetchall()
        expected_metadata = [
            (STORE_FORMAT, SQLITE_SCHEMA_VERSION, actual_schema_sha256)
        ]
        if metadata != expected_metadata:
            raise SQLiteQuotaStoreSchemaError("SQLite schema metadata mismatch")
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise SQLiteQuotaStoreCorruptError("SQLite foreign-key check failed")

    def _initialize(self) -> None:
        connection: sqlite3.Connection | None = None
        try:
            connection = self._raw_connection()
            self._configure_connection(connection)
            identity = self._database_identity(connection)
            if identity != (SQLITE_APPLICATION_ID, SQLITE_SCHEMA_VERSION):
                if not self._is_unclaimed_empty(connection):
                    raise SQLiteQuotaStoreSchemaError(
                        "database is not an empty or supported quota store"
                    )
            journal_mode = str(
                connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            ).lower()
            if journal_mode != "wal":
                raise SQLiteQuotaStoreError("SQLite WAL mode is unavailable")
            connection.execute("BEGIN IMMEDIATE")
            if self._is_unclaimed_empty(connection):
                for statement in _SCHEMA_STATEMENTS:
                    connection.execute(statement)
                connection.execute(
                    """
                    INSERT INTO quota_store_metadata(
                        singleton, format, schema_version, schema_sha256
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (1, STORE_FORMAT, SQLITE_SCHEMA_VERSION, SCHEMA_SHA256),
                )
                connection.execute(f"PRAGMA application_id = {SQLITE_APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version = {SQLITE_SCHEMA_VERSION}")
            self._validate_schema(connection)
            self._commit_transaction(connection)
            quick_check = connection.execute("PRAGMA quick_check(1)").fetchall()
            if quick_check != [("ok",)]:
                raise SQLiteQuotaStoreCorruptError("SQLite quick_check failed")
        except sqlite3.Error as error:
            if connection is not None and connection.in_transaction:
                try:
                    connection.rollback()
                except sqlite3.Error:
                    pass
            raise _database_error(error) from error
        except Exception:
            if connection is not None and connection.in_transaction:
                try:
                    connection.rollback()
                except sqlite3.Error:
                    pass
            raise
        finally:
            if connection is not None:
                connection.close()

    def _open_transaction(self) -> sqlite3.Connection:
        connection = self._raw_connection()
        try:
            self._configure_connection(connection)
            journal_mode = str(
                connection.execute("PRAGMA journal_mode").fetchone()[0]
            ).lower()
            if journal_mode != "wal":
                raise SQLiteQuotaStoreSchemaError("SQLite WAL mode changed")
            connection.execute("BEGIN IMMEDIATE")
            self._validate_schema(connection)
            return connection
        except sqlite3.Error as error:
            if connection.in_transaction:
                try:
                    connection.rollback()
                except sqlite3.Error:
                    pass
            connection.close()
            raise _database_error(error) from error
        except Exception:
            if connection.in_transaction:
                try:
                    connection.rollback()
                except sqlite3.Error:
                    pass
            connection.close()
            raise

    def _commit_transaction(self, connection: sqlite3.Connection) -> None:
        """Commit seam overridden only by controlled crash/rollback tests."""

        connection.commit()

    def consume(
        self,
        grant_digest: bytes,
        issuer_sid: bytes,
        quota: int,
    ) -> QuotaConsumeResult:
        _require_fixed_bytes(grant_digest, GRANT_DIGEST_BYTES, "grant digest")
        _validate_issuer_sid(issuer_sid)
        _require_uint(quota, 8, "grant quota")
        if quota == 0:
            raise ContractError("grant quota must be nonzero")

        connection: sqlite3.Connection | None = None
        committed = False
        try:
            connection = self._open_transaction()
            row = connection.execute(
                """
                SELECT initial_quota, remaining_quota
                FROM issuer_grants
                WHERE grant_digest = ?
                """,
                (grant_digest,),
            ).fetchone()
            if row is None:
                encoded_quota = _quota_bytes(quota)
                connection.execute(
                    """
                    INSERT INTO issuer_grants(
                        grant_digest, initial_quota, remaining_quota
                    ) VALUES (?, ?, ?)
                    """,
                    (grant_digest, encoded_quota, encoded_quota),
                )
                initial_quota = quota
                remaining = quota
            else:
                initial_quota = _quota_from_bytes(row[0], "initial_quota")
                remaining = _quota_from_bytes(row[1], "remaining_quota")
            if initial_quota != quota:
                raise ContractError("grant quota changed for existing digest")
            if remaining > initial_quota:
                raise SQLiteQuotaStoreCorruptError(
                    "remaining quota exceeds initial quota"
                )

            replay = connection.execute(
                """
                SELECT 1
                FROM consumed_issuer_sids
                WHERE grant_digest = ? AND issuer_sid = ?
                """,
                (grant_digest, issuer_sid),
            ).fetchone()
            if replay is not None:
                result = QuotaConsumeResult(QuotaConsumeStatus.REPLAY, remaining)
            elif remaining == 0:
                result = QuotaConsumeResult(QuotaConsumeStatus.EXHAUSTED, 0)
            else:
                connection.execute(
                    """
                    INSERT INTO consumed_issuer_sids(grant_digest, issuer_sid)
                    VALUES (?, ?)
                    """,
                    (grant_digest, issuer_sid),
                )
                remaining -= 1
                connection.execute(
                    """
                    UPDATE issuer_grants
                    SET remaining_quota = ?
                    WHERE grant_digest = ?
                    """,
                    (_quota_bytes(remaining), grant_digest),
                )
                result = QuotaConsumeResult(QuotaConsumeStatus.CONSUMED, remaining)

            self._commit_transaction(connection)
            committed = True
            return result
        except sqlite3.Error as error:
            raise _database_error(error) from error
        finally:
            if connection is not None:
                if not committed and connection.in_transaction:
                    try:
                        connection.rollback()
                    except sqlite3.Error:
                        pass
                connection.close()


def sqlite_quota_store_manifest() -> dict[str, object]:
    """Return path-free implementation metadata and the bounded claim set."""

    return {
        "format": "PQRBBC-SYSTEM-GOVERNANCE-SQLITE-QUOTA-STORE-1",
        "system_profile": "0.1",
        "schema_version": SQLITE_SCHEMA_VERSION,
        "sqlite_application_id": SQLITE_APPLICATION_ID,
        "schema_sha256": SCHEMA_SHA256,
        "schema_digest_source": "canonical-actual-sqlite_schema-create-table-sql",
        "schema_validation_profile": "PQRBBC-SQLITE-SCHEMA-VALIDATION-V1",
        "journal_mode": "WAL",
        "synchronous": "FULL",
        "transaction_begin": "IMMEDIATE",
        "consumption_identity": ["grant_digest", "issuer_sid"],
        "grant_digest_bytes": GRANT_DIGEST_BYTES,
        "issuer_sid_max_bytes": MAX_ISSUER_SID_BYTES,
        "quota_encoding": "u64le-blob",
        "default_busy_timeout_ms": DEFAULT_BUSY_TIMEOUT_MS,
        "schema_validation": {
            "actual_create_sql_digest_verified": True,
            "canonical_create_sql_verified": True,
            "check_constraints_verified": True,
            "columns_defaults_pk_and_hidden_verified": True,
            "extra_tables_indexes_triggers_views_rejected": True,
            "foreign_key_definitions_and_actions_verified": True,
            "strict_tables_verified": True,
        },
        "claim_boundary": {
            "single_host_multi_process_store_implemented": True,
            "restart_persistence_implemented": True,
            "atomic_replay_quota_sid_transaction_implemented": True,
            "cross_host_consistency_implemented": False,
            "physical_power_loss_qualified": False,
            "fac_authentication_instantiated": False,
            "blind_signing_response_produced": False,
            "production_issuance_complete": False,
        },
    }
