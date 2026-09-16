"""Single-host durable delivery claims for the first application record.

The store serializes one sequence-zero record identity per session and keeps
that decision across process restarts.  It is an at-most-once capability gate,
not an application transaction: a crash after a successful claim can lose the
work, and no retry may release the plaintext capability again.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path

from ..access import DIGEST_BYTES, SESSION_ID_BYTES
from ..application import (
    DeliveryClaimDispositionV2,
    DeliveryClaimResultV2,
    FirstRecordOutboxConflictError,
)


APPLICATION_ID = 0x50515344
SCHEMA_VERSION = 1
CLAIM_REVISION = 1
CLAIM_CHECKSUM_LABEL = b"PQ-SAT/FGS-FIRST-DELIVERY-CLAIM/v0.2"
PRODUCTION_READY = False

_SCHEMA_SQL = """CREATE TABLE first_application_delivery_claims (
    session_id BLOB PRIMARY KEY NOT NULL
        CHECK(typeof(session_id) = 'blob' AND length(session_id) = 32),
    revision INTEGER NOT NULL CHECK(revision = 1),
    record_digest BLOB NOT NULL
        CHECK(typeof(record_digest) = 'blob' AND length(record_digest) = 32),
    claim_checksum BLOB NOT NULL
        CHECK(typeof(claim_checksum) = 'blob' AND length(claim_checksum) = 32)
) WITHOUT ROWID"""


class FirstApplicationDeliveryStorageError(RuntimeError):
    pass


class FirstApplicationDeliveryIntegrityError(RuntimeError):
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


def derive_delivery_claim_checksum(
    session_id: bytes,
    record_digest: bytes,
) -> bytes:
    """Return the public corruption-detection identity for one claim.

    This checksum is deliberately not a MAC and does not protect a hostile
    filesystem.  The bounded reference assumes a trusted single host.
    """

    session = _fixed(session_id, SESSION_ID_BYTES, "session_id")
    digest = _fixed(record_digest, DIGEST_BYTES, "record_digest")
    return hashlib.shake_256(
        CLAIM_CHECKSUM_LABEL
        + CLAIM_REVISION.to_bytes(8, "big")
        + session
        + digest
    ).digest(DIGEST_BYTES)


def _normalized_sql(value: str) -> str:
    return "".join(value.split())


class SQLiteFirstApplicationDeliveryStoreV2:
    """Cross-process, restart-durable at-most-once claim store on one host."""

    durable = True
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
            raise ValueError("delivery database path must be absolute")
        if not candidate.parent.is_dir():
            raise ValueError("delivery database parent must exist")
        if candidate.exists() and (
            candidate.is_symlink() or not candidate.is_file()
        ):
            raise ValueError(
                "delivery database must be a regular non-symlink file"
            )
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
            raise FirstApplicationDeliveryStorageError(
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
            raise FirstApplicationDeliveryIntegrityError(
                "delivery database application_id mismatch"
            )
        if self._pragma(connection, "user_version") != SCHEMA_VERSION:
            raise FirstApplicationDeliveryIntegrityError(
                "delivery database schema version mismatch"
            )
        tables = self._tables(connection)
        if set(tables) != {"first_application_delivery_claims"}:
            raise FirstApplicationDeliveryIntegrityError(
                "delivery database table set mismatch"
            )
        if _normalized_sql(
            tables["first_application_delivery_claims"]
        ) != _normalized_sql(_SCHEMA_SQL):
            raise FirstApplicationDeliveryIntegrityError(
                "delivery database schema mismatch"
            )
        mode = connection.execute("PRAGMA journal_mode").fetchone()
        if mode is None or str(mode[0]).lower() != "wal":
            raise FirstApplicationDeliveryIntegrityError(
                "delivery database is not in WAL mode"
            )
        if self._pragma(connection, "synchronous") != 2:
            raise FirstApplicationDeliveryIntegrityError(
                "delivery database is not FULL synchronous"
            )

    def _initialize(self) -> None:
        existed = self._path.exists()
        connection = self._raw_connection()
        try:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
            if mode is None or str(mode[0]).lower() != "wal":
                raise FirstApplicationDeliveryStorageError(
                    "SQLite WAL mode is unavailable"
                )
            connection.execute("BEGIN IMMEDIATE")
            if not self._tables(connection):
                if self._pragma(connection, "application_id") != 0:
                    raise FirstApplicationDeliveryIntegrityError(
                        "empty delivery database has unexpected application_id"
                    )
                if self._pragma(connection, "user_version") != 0:
                    raise FirstApplicationDeliveryIntegrityError(
                        "empty delivery database has unexpected schema version"
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
            raise FirstApplicationDeliveryIntegrityError(
                "delivery database path changed type"
            )
        connection = self._raw_connection()
        try:
            self._verify_database(connection)
        except Exception:
            connection.close()
            raise
        return connection

    @staticmethod
    def _decode_row(row: tuple[object, ...]) -> DeliveryClaimResultV2:
        if len(row) != 4:
            raise FirstApplicationDeliveryIntegrityError(
                "delivery claim row has wrong width"
            )
        try:
            session = _fixed(row[0], SESSION_ID_BYTES, "stored session_id")  # type: ignore[arg-type]
            revision = _integer(row[1], "stored claim revision")
            digest = _fixed(row[2], DIGEST_BYTES, "stored record_digest")  # type: ignore[arg-type]
            checksum = _fixed(row[3], DIGEST_BYTES, "stored claim_checksum")  # type: ignore[arg-type]
            if revision != CLAIM_REVISION:
                raise ValueError("stored claim revision is unknown")
            if checksum != derive_delivery_claim_checksum(session, digest):
                raise ValueError("stored claim checksum mismatch")
            result = DeliveryClaimResultV2(
                DeliveryClaimDispositionV2.EXISTING,
                session,
                digest,
            )
            result.validate()
            return result
        except Exception as error:
            raise FirstApplicationDeliveryIntegrityError(
                "stored delivery claim is invalid"
            ) from error

    @staticmethod
    def _select(
        connection: sqlite3.Connection,
        session_id: bytes,
    ) -> DeliveryClaimResultV2 | None:
        row = connection.execute(
            "SELECT session_id, revision, record_digest, claim_checksum "
            "FROM first_application_delivery_claims WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if row is None:
            return None
        return SQLiteFirstApplicationDeliveryStoreV2._decode_row(row)

    def load(self, session_id: bytes) -> DeliveryClaimResultV2 | None:
        session = _fixed(session_id, SESSION_ID_BYTES, "session_id")
        connection = self._connect()
        try:
            return self._select(connection, session)
        finally:
            connection.close()

    def claim(
        self,
        session_id: bytes,
        record_digest: bytes,
    ) -> DeliveryClaimResultV2:
        session = _fixed(session_id, SESSION_ID_BYTES, "session_id")
        digest = _fixed(record_digest, DIGEST_BYTES, "record_digest")
        checksum = derive_delivery_claim_checksum(session, digest)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._select(connection, session)
            if existing is not None:
                if existing.record_digest != digest:
                    raise FirstRecordOutboxConflictError(
                        "session already delivered another sequence-zero record"
                    )
                connection.execute("COMMIT")
                return existing
            cursor = connection.execute(
                "INSERT INTO first_application_delivery_claims "
                "(session_id, revision, record_digest, claim_checksum) "
                "VALUES (?, ?, ?, ?)",
                (session, CLAIM_REVISION, digest, checksum),
            )
            if cursor.rowcount != 1:
                raise FirstApplicationDeliveryStorageError(
                    "delivery claim changed an unexpected row count"
                )
            connection.execute("COMMIT")
            result = DeliveryClaimResultV2(
                DeliveryClaimDispositionV2.NEW,
                session,
                digest,
            )
            result.validate()
            return result
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def __len__(self) -> int:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT COUNT(*) FROM first_application_delivery_claims"
            ).fetchone()
            if row is None:
                raise FirstApplicationDeliveryStorageError(
                    "delivery claim count is unavailable"
                )
            return int(row[0])
        finally:
            connection.close()


def sqlite_first_application_delivery_manifest() -> dict[str, object]:
    return {
        "format": "PQ-SAT-FGS-FIRST-DELIVERY-SQLITE-v0.2",
        "application_id": f"0x{APPLICATION_ID:08x}",
        "schema_version": SCHEMA_VERSION,
        "journal_mode": "WAL",
        "synchronous": "FULL",
        "claim_checksum_domain": CLAIM_CHECKSUM_LABEL.decode("ascii"),
        "claims": {
            "single_host_cross_process_durable_reference": True,
            "claim_committed_before_new_capability_release": True,
            "exact_retry_returns_existing_without_plaintext": True,
            "competing_record_digest_rejected": True,
            "process_exit_recovery_tested": True,
            "claim_ack_loss_can_drop_work": True,
            "activation_and_claim_same_transaction": False,
            "external_side_effect_exactly_once": False,
            "hostile_filesystem_protection": False,
            "rollback_resistance": False,
            "physical_power_loss_tested": False,
            "distributed": False,
            "production_ready": False,
        },
    }
