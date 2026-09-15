"""Single-host authoritative revocation fence for FGS activation.

The store is a successor to the unified activation/inbox profile.  A current
activation-revocation record is re-read in the same SQLite write transaction
that activates the session and creates its protected inbox item.  This gives
revocation publication and activation one single-host linearization order,
without claiming an authenticated production writer or distributed state.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import struct
from dataclasses import dataclass

from pq_sat_auth.replay import InvalidTransition

from ..activation import (
    ActivationCommitRequestV2,
    ActivationRevocationQueryV2,
    ActivationRevocationSnapshotV2,
)
from ..replay import GrantRecordV2
from .sqlite_inbox import (
    FGSApplicationInboxProtectionV2,
    _SCHEMA_SQL as INBOX_SCHEMA_SQL,
    _normalized_sql,
)
from .sqlite_replay import (
    FGSReplayRecordProtectionV2,
    _SCHEMA_SQL as REPLAY_SCHEMA_SQL,
)
from .sqlite_unified import (
    SQLiteFGSUnifiedActivationInboxStoreV2,
    UnifiedActivationInboxIntegrityError,
    UnifiedActivationInboxStorageError,
)


APPLICATION_ID = 0x50515356
SCHEMA_VERSION = 1
PRODUCTION_READY = False
SQLITE_INT_MAX = (1 << 63) - 1
FENCE_RECORD_MAGIC = b"PQ-SAT/ACTIVATION-REVOCATION-FENCE/v0.2\x00"
FENCE_CHECKSUM_LABEL = b"PQ-SAT/ACTIVATION-REVOCATION-FENCE-CHECKSUM/v0.2"
FENCE_RECORD_BODY = struct.Struct(">32sQQQQBBBB")
FENCE_RECORD_BYTES = len(FENCE_RECORD_MAGIC) + FENCE_RECORD_BODY.size


_FENCE_SCHEMA_SQL = """CREATE TABLE activation_revocation_fences (
    query_digest BLOB PRIMARY KEY NOT NULL
        CHECK(typeof(query_digest) = 'blob' AND length(query_digest) = 32),
    generation INTEGER NOT NULL CHECK(generation >= 0),
    revision INTEGER NOT NULL CHECK(revision >= 1),
    effective_at INTEGER NOT NULL CHECK(effective_at >= 0),
    valid_until INTEGER NOT NULL CHECK(valid_until >= 0),
    configuration_revoked INTEGER NOT NULL
        CHECK(configuration_revoked IN (0, 1)),
    fgs_key_revoked INTEGER NOT NULL CHECK(fgs_key_revoked IN (0, 1)),
    ticket_revoked INTEGER NOT NULL CHECK(ticket_revoked IN (0, 1)),
    session_revoked INTEGER NOT NULL CHECK(session_revoked IN (0, 1)),
    canonical_record BLOB NOT NULL
        CHECK(typeof(canonical_record) = 'blob'),
    record_checksum BLOB NOT NULL
        CHECK(typeof(record_checksum) = 'blob' AND length(record_checksum) = 32),
    CHECK(effective_at < valid_until)
) WITHOUT ROWID"""


class ActivationRevocationFenceUnavailable(RuntimeError):
    pass


class ActivationRevocationFenceChanged(RuntimeError):
    pass


@dataclass(frozen=True)
class ActivationRevocationFenceRecordV2:
    snapshot: ActivationRevocationSnapshotV2
    revision: int

    def validate(self) -> None:
        if not isinstance(self.snapshot, ActivationRevocationSnapshotV2):
            raise TypeError(
                "snapshot must be an ActivationRevocationSnapshotV2"
            )
        self.snapshot.validate()
        if isinstance(self.revision, bool) or not isinstance(self.revision, int):
            raise TypeError("revision must be an integer")
        if not 1 <= self.revision <= SQLITE_INT_MAX:
            raise ValueError("revision is outside the SQLite bound")
        for name in ("generation", "effective_at", "valid_until"):
            if getattr(self.snapshot, name) > SQLITE_INT_MAX:
                raise ValueError(f"{name} is outside the SQLite bound")


def encode_activation_revocation_fence(
    record: ActivationRevocationFenceRecordV2,
) -> bytes:
    if not isinstance(record, ActivationRevocationFenceRecordV2):
        raise TypeError("record must be an ActivationRevocationFenceRecordV2")
    record.validate()
    snapshot = record.snapshot
    return FENCE_RECORD_MAGIC + FENCE_RECORD_BODY.pack(
        snapshot.query_digest,
        snapshot.generation,
        record.revision,
        snapshot.effective_at,
        snapshot.valid_until,
        int(snapshot.configuration_revoked),
        int(snapshot.fgs_key_revoked),
        int(snapshot.ticket_revoked),
        int(snapshot.session_revoked),
    )


def decode_activation_revocation_fence(
    encoded: bytes,
) -> ActivationRevocationFenceRecordV2:
    if not isinstance(encoded, bytes):
        raise TypeError("encoded revocation fence must be bytes")
    if len(encoded) != FENCE_RECORD_BYTES:
        raise UnifiedActivationInboxIntegrityError(
            "revocation fence record length mismatch"
        )
    if not encoded.startswith(FENCE_RECORD_MAGIC):
        raise UnifiedActivationInboxIntegrityError(
            "revocation fence record format mismatch"
        )
    try:
        values = FENCE_RECORD_BODY.unpack(encoded[len(FENCE_RECORD_MAGIC) :])
        query_digest = values[0]
        generation, revision, effective_at, valid_until = values[1:5]
        flags = values[5:]
        if any(flag not in (0, 1) for flag in flags):
            raise ValueError("revocation flag is not canonical")
        record = ActivationRevocationFenceRecordV2(
            ActivationRevocationSnapshotV2(
                query_digest=query_digest,
                generation=generation,
                effective_at=effective_at,
                valid_until=valid_until,
                configuration_revoked=bool(flags[0]),
                fgs_key_revoked=bool(flags[1]),
                ticket_revoked=bool(flags[2]),
                session_revoked=bool(flags[3]),
            ),
            revision,
        )
        record.validate()
    except Exception as error:
        raise UnifiedActivationInboxIntegrityError(
            "revocation fence record is invalid"
        ) from error
    if encode_activation_revocation_fence(record) != encoded:
        raise UnifiedActivationInboxIntegrityError(
            "revocation fence record is non-canonical"
        )
    return record


def derive_activation_revocation_fence_checksum(encoded: bytes) -> bytes:
    if not isinstance(encoded, bytes) or len(encoded) != FENCE_RECORD_BYTES:
        raise ValueError("canonical revocation fence record is required")
    return hashlib.shake_256(FENCE_CHECKSUM_LABEL + encoded).digest(32)


class SQLiteFGSAuthoritativeActivationInboxStoreV2(
    SQLiteFGSUnifiedActivationInboxStoreV2
):
    """Unified store with an in-transaction authoritative revocation fence."""

    production_ready = False
    durable = True
    distributed = False

    def __init__(
        self,
        path: str | os.PathLike[str],
        replay_protection_backend: FGSReplayRecordProtectionV2,
        inbox_protection_backend: FGSApplicationInboxProtectionV2,
        *,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        super().__init__(
            path,
            replay_protection_backend,
            inbox_protection_backend,
            busy_timeout_ms=busy_timeout_ms,
        )

    def _verify_database(self, connection: sqlite3.Connection) -> None:
        if self._pragma(connection, "application_id") != APPLICATION_ID:
            raise UnifiedActivationInboxIntegrityError(
                "authoritative database application_id mismatch"
            )
        if self._pragma(connection, "user_version") != SCHEMA_VERSION:
            raise UnifiedActivationInboxIntegrityError(
                "authoritative database schema version mismatch"
            )
        tables = self._tables(connection)
        expected = {
            "fgs_replay_records": REPLAY_SCHEMA_SQL,
            "first_application_inbox": INBOX_SCHEMA_SQL,
            "activation_revocation_fences": _FENCE_SCHEMA_SQL,
        }
        if set(tables) != set(expected):
            raise UnifiedActivationInboxIntegrityError(
                "authoritative database table set mismatch"
            )
        for name, schema in expected.items():
            if _normalized_sql(tables[name]) != _normalized_sql(schema):
                raise UnifiedActivationInboxIntegrityError(
                    f"authoritative {name} schema mismatch"
                )
        mode = connection.execute("PRAGMA journal_mode").fetchone()
        if mode is None or str(mode[0]).lower() != "wal":
            raise UnifiedActivationInboxIntegrityError(
                "authoritative database is not in WAL mode"
            )
        if self._pragma(connection, "synchronous") != 2:
            raise UnifiedActivationInboxIntegrityError(
                "authoritative database is not FULL synchronous"
            )

    def _initialize(self) -> None:
        existed = self._path.exists()
        connection = self._raw_connection()
        try:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
            if mode is None or str(mode[0]).lower() != "wal":
                raise UnifiedActivationInboxStorageError(
                    "SQLite WAL mode is unavailable"
                )
            connection.execute("BEGIN IMMEDIATE")
            if not self._tables(connection):
                if self._pragma(connection, "application_id") != 0:
                    raise UnifiedActivationInboxIntegrityError(
                        "empty authoritative database has unexpected application_id"
                    )
                if self._pragma(connection, "user_version") != 0:
                    raise UnifiedActivationInboxIntegrityError(
                        "empty authoritative database has unexpected schema version"
                    )
                connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                connection.execute(REPLAY_SCHEMA_SQL)
                connection.execute(INBOX_SCHEMA_SQL)
                connection.execute(_FENCE_SCHEMA_SQL)
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

    @staticmethod
    def _decode_fence_row(
        row: tuple[object, ...],
    ) -> ActivationRevocationFenceRecordV2:
        if len(row) != 11:
            raise UnifiedActivationInboxIntegrityError(
                "authoritative revocation row has wrong width"
            )
        metadata = row[:9]
        canonical_record, checksum = row[9:]
        try:
            if not isinstance(canonical_record, bytes):
                raise TypeError("canonical revocation record must be bytes")
            if not isinstance(checksum, bytes) or len(checksum) != 32:
                raise TypeError("revocation fence checksum must be 32 bytes")
            expected_checksum = derive_activation_revocation_fence_checksum(
                canonical_record
            )
            if not hmac.compare_digest(checksum, expected_checksum):
                raise ValueError("revocation fence checksum mismatch")
            record = decode_activation_revocation_fence(canonical_record)
            snapshot = record.snapshot
            expected_metadata = (
                snapshot.query_digest,
                snapshot.generation,
                record.revision,
                snapshot.effective_at,
                snapshot.valid_until,
                int(snapshot.configuration_revoked),
                int(snapshot.fgs_key_revoked),
                int(snapshot.ticket_revoked),
                int(snapshot.session_revoked),
            )
            if metadata != expected_metadata:
                raise ValueError("revocation row and canonical record differ")
            return record
        except Exception as error:
            raise UnifiedActivationInboxIntegrityError(
                "stored authoritative revocation fence is invalid"
            ) from error

    def _select_fence(
        self,
        connection: sqlite3.Connection,
        query_digest: bytes,
    ) -> ActivationRevocationFenceRecordV2 | None:
        row = connection.execute(
            "SELECT query_digest, generation, revision, effective_at, "
            "valid_until, configuration_revoked, fgs_key_revoked, "
            "ticket_revoked, session_revoked, canonical_record, "
            "record_checksum FROM activation_revocation_fences "
            "WHERE query_digest = ?",
            (query_digest,),
        ).fetchone()
        return None if row is None else self._decode_fence_row(row)

    @staticmethod
    def _write_values(
        record: ActivationRevocationFenceRecordV2,
    ) -> tuple[object, ...]:
        encoded = encode_activation_revocation_fence(record)
        snapshot = record.snapshot
        return (
            snapshot.query_digest,
            snapshot.generation,
            record.revision,
            snapshot.effective_at,
            snapshot.valid_until,
            int(snapshot.configuration_revoked),
            int(snapshot.fgs_key_revoked),
            int(snapshot.ticket_revoked),
            int(snapshot.session_revoked),
            encoded,
            derive_activation_revocation_fence_checksum(encoded),
        )

    def publish_activation_revocation(
        self,
        snapshot: ActivationRevocationSnapshotV2,
    ) -> ActivationRevocationFenceRecordV2:
        """Publish local authoritative state; caller authentication is external."""

        candidate = ActivationRevocationFenceRecordV2(snapshot, 1)
        candidate.validate()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._select_fence(connection, snapshot.query_digest)
            if existing is None:
                connection.execute(
                    "INSERT INTO activation_revocation_fences "
                    "(query_digest, generation, revision, effective_at, "
                    "valid_until, configuration_revoked, fgs_key_revoked, "
                    "ticket_revoked, session_revoked, canonical_record, "
                    "record_checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    self._write_values(candidate),
                )
                result = candidate
            elif existing.snapshot == snapshot:
                result = existing
            else:
                if snapshot.generation <= existing.snapshot.generation:
                    raise InvalidTransition(
                        "revocation generation must advance"
                    )
                old_flags = (
                    existing.snapshot.configuration_revoked,
                    existing.snapshot.fgs_key_revoked,
                    existing.snapshot.ticket_revoked,
                    existing.snapshot.session_revoked,
                )
                new_flags = (
                    snapshot.configuration_revoked,
                    snapshot.fgs_key_revoked,
                    snapshot.ticket_revoked,
                    snapshot.session_revoked,
                )
                if any(old and not new for old, new in zip(old_flags, new_flags)):
                    raise InvalidTransition("revocation flag cannot be cleared")
                result = ActivationRevocationFenceRecordV2(
                    snapshot,
                    existing.revision + 1,
                )
                result.validate()
                cursor = connection.execute(
                    "UPDATE activation_revocation_fences SET generation = ?, "
                    "revision = ?, effective_at = ?, valid_until = ?, "
                    "configuration_revoked = ?, fgs_key_revoked = ?, "
                    "ticket_revoked = ?, session_revoked = ?, "
                    "canonical_record = ?, record_checksum = ? "
                    "WHERE query_digest = ? AND revision = ?",
                    self._write_values(result)[1:]
                    + (snapshot.query_digest, existing.revision),
                )
                if cursor.rowcount != 1:
                    raise UnifiedActivationInboxStorageError(
                        "revocation publication changed an unexpected row count"
                    )
            connection.execute("COMMIT")
            return result
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def snapshot(
        self,
        query: ActivationRevocationQueryV2,
    ) -> ActivationRevocationSnapshotV2:
        if not isinstance(query, ActivationRevocationQueryV2):
            raise TypeError("query must be an ActivationRevocationQueryV2")
        query.encode()
        connection = self._connect()
        try:
            record = self._select_fence(connection, query.digest)
            if record is None:
                raise ActivationRevocationFenceUnavailable(
                    "authoritative revocation fence is missing"
                )
            if record.snapshot.query_digest != query.digest:
                raise UnifiedActivationInboxIntegrityError(
                    "authoritative revocation query binding mismatch"
                )
            return record.snapshot
        finally:
            connection.close()

    def _validate_activation_fence(
        self,
        connection: sqlite3.Connection,
        request: ActivationCommitRequestV2,
        grant: GrantRecordV2,
    ) -> None:
        query = request.revocation_query
        checked = request.revocation_snapshot
        if not isinstance(query, ActivationRevocationQueryV2) or not isinstance(
            checked,
            ActivationRevocationSnapshotV2,
        ):
            raise ActivationRevocationFenceUnavailable(
                "authoritative activation requires checked revocation context"
            )
        bindings = (
            (query.ctx, request.identity.ctx),
            (query.ticket_use_key, request.identity.use_key),
            (query.request_digest, request.request_digest),
            (query.response_digest, request.response_digest),
            (query.session_id, request.session_id),
            (query.fgs_id, grant.fgs_id),
            (checked.query_digest, query.digest),
        )
        if any(actual != expected for actual, expected in bindings):
            raise InvalidTransition(
                "activation revocation context and grant differ"
            )
        current = self._select_fence(connection, query.digest)
        if current is None:
            raise ActivationRevocationFenceUnavailable(
                "authoritative revocation fence is missing at commit"
            )
        if current.snapshot != checked:
            raise ActivationRevocationFenceChanged(
                "revocation fence changed before activation commit"
            )
        if checked.generation < grant.revocation_generation:
            raise InvalidTransition("activation revocation generation is stale")
        if not checked.effective_at <= request.activated_at < checked.valid_until:
            raise InvalidTransition("activation revocation fence is inactive")
        if checked.revoked:
            raise InvalidTransition("activation is revoked")


def sqlite_authoritative_activation_inbox_manifest() -> dict[str, object]:
    return {
        "format": "PQ-SAT-FGS-AUTHORITATIVE-ACTIVATION-INBOX-SQLITE-v0.2",
        "application_id": f"0x{APPLICATION_ID:08x}",
        "schema_version": SCHEMA_VERSION,
        "journal_mode": "WAL",
        "synchronous": "FULL",
        "tables": [
            "fgs_replay_records",
            "first_application_inbox",
            "activation_revocation_fences",
        ],
        "linearization_order": [
            "read_exact_local_snapshot",
            "begin_immediate_on_one_database",
            "revalidate_exact_authoritative_fence",
            "transition_grant_to_consumed_active",
            "insert_protected_pending_inbox_item",
            "commit_once",
        ],
        "claims": {
            "single_host_authoritative_revocation_fence": True,
            "revocation_publish_and_activation_linearizable": True,
            "revocation_fence_and_activation_same_transaction": True,
            "query_and_exact_snapshot_commit_bound": True,
            "monotonic_generation_and_flags": True,
            "single_database_connection": True,
            "sqlite_attach_used": False,
            "activation_and_inbox_same_transaction": True,
            "authenticated_production_writer_instantiated": False,
            "general_scope_revocation_fanout_implemented": False,
            "distributed_revocation_store": False,
            "external_application_same_transaction": False,
            "production_record_protection_instantiated": False,
            "production_plaintext_protection_instantiated": False,
            "physical_power_loss_tested": False,
            "distributed": False,
            "production_ready": False,
        },
    }
