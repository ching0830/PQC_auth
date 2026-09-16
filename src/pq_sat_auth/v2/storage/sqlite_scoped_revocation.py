"""Authenticated single-host revocation ingestion and scope fanout.

This successor profile keeps authenticated revocation commands, registered
activation queries, materialized revocation fences, replay state, and the
protected first-application inbox in one SQLite database.  Command ingestion
and activation therefore have one single-host write order.  The federation
configuration key is a provisional control-plane authority selected from the
existing system-initialization ABI; concrete PQ authentication, key rotation,
and distributed replication remain outside this reference implementation.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
from dataclasses import dataclass, replace
from enum import Enum, IntEnum
from typing import Protocol

from pq_rbbc.contracts.system import KeyReference, KeyRole
from pq_rbbc.governance.system_init import (
    ConfigurationAuthenticationVerifier,
    verify_initialization,
)
from pq_sat_auth.replay import InvalidTransition

from ..activation import (
    ActivationCommitRequestV2,
    ActivationRevocationQueryV2,
    ActivationRevocationSnapshotV2,
)
from ..grant import GrantCommitRequestV2
from ..replay import GrantRecordV2, ReservationV2
from .sqlite_authoritative import (
    ActivationRevocationFenceRecordV2,
    ActivationRevocationFenceUnavailable,
    SQLiteFGSAuthoritativeActivationInboxStoreV2,
    _FENCE_SCHEMA_SQL,
)
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
    UnifiedActivationInboxIntegrityError,
    UnifiedActivationInboxStorageError,
)


APPLICATION_ID = 0x50515357
SCHEMA_VERSION = 2
ACCESS_PROTOCOL_VERSION = 2
PRODUCTION_READY = False
SQLITE_INT_MAX = (1 << 63) - 1
QUERY_BYTES = 2 + (10 * 32)
MAX_AUTHENTICATION_BYTES = 1 << 20
REVOCATION_COMMAND_MAGIC = b"PQ-SAT/REVOCATION-COMMAND/v0.2\x00"
AUTHENTICATED_COMMAND_MAGIC = b"PQ-SAT/REVOCATION-COMMAND-AUTH/v0.2\x00"
REVOCATION_COMMAND_AUTH_DOMAIN = (
    b"PQ-SAT/REVOCATION-COMMAND-AUTHENTICATION/v0.2\x00"
)
REVOCATION_COMMAND_DIGEST_DOMAIN = (
    b"PQ-SAT/REVOCATION-COMMAND-DIGEST/v0.2\x00"
)
QUERY_CHECKSUM_DOMAIN = b"PQ-SAT/REVOCATION-QUERY-CHECKSUM/v0.2\x00"
COMMAND_CHECKSUM_DOMAIN = b"PQ-SAT/REVOCATION-COMMAND-CHECKSUM/v0.2\x00"


_QUERY_SCHEMA_SQL = f"""CREATE TABLE activation_revocation_queries (
    query_digest BLOB PRIMARY KEY NOT NULL
        CHECK(typeof(query_digest) = 'blob' AND length(query_digest) = 32),
    canonical_query BLOB NOT NULL
        CHECK(typeof(canonical_query) = 'blob'
              AND length(canonical_query) = {QUERY_BYTES}),
    query_checksum BLOB NOT NULL
        CHECK(typeof(query_checksum) = 'blob' AND length(query_checksum) = 32)
) WITHOUT ROWID"""


_COMMAND_SCHEMA_SQL = """CREATE TABLE authenticated_revocation_commands (
    command_id BLOB PRIMARY KEY NOT NULL
        CHECK(typeof(command_id) = 'blob' AND length(command_id) = 32),
    ctx BLOB NOT NULL CHECK(typeof(ctx) = 'blob' AND length(ctx) = 32),
    generation INTEGER NOT NULL CHECK(generation >= 1),
    command_digest BLOB UNIQUE NOT NULL
        CHECK(typeof(command_digest) = 'blob' AND length(command_digest) = 32),
    canonical_envelope BLOB NOT NULL
        CHECK(typeof(canonical_envelope) = 'blob'),
    envelope_checksum BLOB NOT NULL
        CHECK(typeof(envelope_checksum) = 'blob'
              AND length(envelope_checksum) = 32),
    UNIQUE(ctx, generation)
) WITHOUT ROWID"""


class RevocationCommandError(ValueError):
    pass


class RevocationScopeV2(IntEnum):
    ACCESS_CONFIGURATION = 1
    FGS_AUTHENTICATION_KEY = 2
    TICKET_USE = 3
    SESSION = 4


@dataclass(frozen=True)
class RevocationCommandV2:
    access_protocol_version: int
    ctx: bytes
    system_bundle_digest: bytes
    epoch: int
    policy_digest: bytes
    signer_key_id: bytes
    scope: RevocationScopeV2
    scope_target: bytes
    generation: int
    issued_at: int
    authorization_expires_at: int
    command_id: bytes
    reason_digest: bytes

    def validate(self) -> None:
        _uint(self.access_protocol_version, 2, "access_protocol_version")
        if self.access_protocol_version != ACCESS_PROTOCOL_VERSION:
            raise RevocationCommandError("unsupported access protocol version")
        for name in (
            "ctx",
            "system_bundle_digest",
            "policy_digest",
            "signer_key_id",
            "scope_target",
            "command_id",
            "reason_digest",
        ):
            _fixed(getattr(self, name), 32, name, nonzero=True)
        for name in (
            "epoch",
            "generation",
            "issued_at",
            "authorization_expires_at",
        ):
            _sqlite_uint(getattr(self, name), name)
        if self.generation == 0:
            raise RevocationCommandError("generation must be nonzero")
        if self.authorization_expires_at <= self.issued_at:
            raise RevocationCommandError(
                "authorization expiry must follow issued_at"
            )
        if not isinstance(self.scope, RevocationScopeV2):
            raise RevocationCommandError("scope must be a RevocationScopeV2")

    def encode(self) -> bytes:
        self.validate()
        return b"".join(
            (
                REVOCATION_COMMAND_MAGIC,
                self.access_protocol_version.to_bytes(2, "big"),
                self.ctx,
                self.system_bundle_digest,
                self.epoch.to_bytes(8, "big"),
                self.policy_digest,
                self.signer_key_id,
                int(self.scope).to_bytes(2, "big"),
                self.scope_target,
                self.generation.to_bytes(8, "big"),
                self.issued_at.to_bytes(8, "big"),
                self.authorization_expires_at.to_bytes(8, "big"),
                self.command_id,
                self.reason_digest,
            )
        )

    @classmethod
    def decode(cls, encoded: bytes) -> "RevocationCommandV2":
        if not isinstance(encoded, bytes):
            raise RevocationCommandError("revocation command must be bytes")
        offset = _expect(encoded, 0, REVOCATION_COMMAND_MAGIC, "command magic")
        protocol_version, offset = _take_uint(
            encoded,
            offset,
            2,
            "access protocol version",
        )
        ctx, offset = _take(encoded, offset, 32, "ctx")
        bundle_digest, offset = _take(
            encoded,
            offset,
            32,
            "system bundle digest",
        )
        epoch, offset = _take_uint(encoded, offset, 8, "epoch")
        policy_digest, offset = _take(encoded, offset, 32, "policy digest")
        signer_key_id, offset = _take(encoded, offset, 32, "signer key ID")
        scope_value, offset = _take_uint(encoded, offset, 2, "scope")
        try:
            scope = RevocationScopeV2(scope_value)
        except ValueError as error:
            raise RevocationCommandError("unknown revocation scope") from error
        scope_target, offset = _take(encoded, offset, 32, "scope target")
        generation, offset = _take_uint(encoded, offset, 8, "generation")
        issued_at, offset = _take_uint(encoded, offset, 8, "issued_at")
        expires_at, offset = _take_uint(
            encoded,
            offset,
            8,
            "authorization expiry",
        )
        command_id, offset = _take(encoded, offset, 32, "command ID")
        reason_digest, offset = _take(encoded, offset, 32, "reason digest")
        if offset != len(encoded):
            raise RevocationCommandError("revocation command trailing bytes")
        command = cls(
            access_protocol_version=protocol_version,
            ctx=ctx,
            system_bundle_digest=bundle_digest,
            epoch=epoch,
            policy_digest=policy_digest,
            signer_key_id=signer_key_id,
            scope=scope,
            scope_target=scope_target,
            generation=generation,
            issued_at=issued_at,
            authorization_expires_at=expires_at,
            command_id=command_id,
            reason_digest=reason_digest,
        )
        command.validate()
        if command.encode() != encoded:
            raise RevocationCommandError("revocation command is non-canonical")
        return command

    @property
    def digest(self) -> bytes:
        return hashlib.sha256(
            REVOCATION_COMMAND_DIGEST_DOMAIN + self.encode()
        ).digest()


@dataclass(frozen=True)
class AuthenticatedRevocationCommandV2:
    command: RevocationCommandV2
    signing_role: KeyRole
    authentication: bytes

    @property
    def authentication_message(self) -> bytes:
        if not isinstance(self.signing_role, KeyRole):
            raise RevocationCommandError("signing role must be a KeyRole")
        return b"".join(
            (
                REVOCATION_COMMAND_AUTH_DOMAIN,
                int(self.signing_role).to_bytes(2, "big"),
                self.command.encode(),
            )
        )

    def encode(self) -> bytes:
        if not isinstance(self.signing_role, KeyRole):
            raise RevocationCommandError("signing role must be a KeyRole")
        command_bytes = self.command.encode()
        if not isinstance(self.authentication, bytes) or not (
            0 < len(self.authentication) <= MAX_AUTHENTICATION_BYTES
        ):
            raise RevocationCommandError(
                "command authentication length is outside bounds"
            )
        return b"".join(
            (
                AUTHENTICATED_COMMAND_MAGIC,
                ACCESS_PROTOCOL_VERSION.to_bytes(2, "big"),
                int(self.signing_role).to_bytes(2, "big"),
                len(command_bytes).to_bytes(4, "big"),
                command_bytes,
                len(self.authentication).to_bytes(4, "big"),
                self.authentication,
            )
        )

    @classmethod
    def decode(cls, encoded: bytes) -> "AuthenticatedRevocationCommandV2":
        if not isinstance(encoded, bytes):
            raise RevocationCommandError(
                "authenticated revocation command must be bytes"
            )
        offset = _expect(
            encoded,
            0,
            AUTHENTICATED_COMMAND_MAGIC,
            "authenticated command magic",
        )
        version, offset = _take_uint(encoded, offset, 2, "envelope version")
        if version != ACCESS_PROTOCOL_VERSION:
            raise RevocationCommandError("wrong authenticated command version")
        role_value, offset = _take_uint(encoded, offset, 2, "signing role")
        try:
            signing_role = KeyRole(role_value)
        except ValueError as error:
            raise RevocationCommandError("unknown command signing role") from error
        command_length, offset = _take_uint(
            encoded,
            offset,
            4,
            "command length",
        )
        if command_length != _command_bytes():
            raise RevocationCommandError("command length is non-canonical")
        command_bytes, offset = _take(
            encoded,
            offset,
            command_length,
            "command",
        )
        authentication_length, offset = _take_uint(
            encoded,
            offset,
            4,
            "authentication length",
        )
        if not 0 < authentication_length <= MAX_AUTHENTICATION_BYTES:
            raise RevocationCommandError(
                "command authentication length is outside bounds"
            )
        authentication, offset = _take(
            encoded,
            offset,
            authentication_length,
            "authentication",
        )
        if offset != len(encoded):
            raise RevocationCommandError(
                "authenticated revocation command trailing bytes"
            )
        envelope = cls(
            RevocationCommandV2.decode(command_bytes),
            signing_role,
            authentication,
        )
        if envelope.encode() != encoded:
            raise RevocationCommandError(
                "authenticated revocation command is non-canonical"
            )
        return envelope


class RevocationCommandAuthenticationVerifierV2(Protocol):
    def verify(
        self,
        key: KeyReference,
        message: bytes,
        authentication: bytes,
    ) -> bool: ...


class RevocationIngestDispositionV2(Enum):
    INGESTED = "ingested"
    REPLAY = "replay"


@dataclass(frozen=True)
class RevocationIngestResultV2:
    accepted: bool
    disposition: RevocationIngestDispositionV2 | None
    failures: tuple[str, ...]
    command_digest: bytes | None = None
    matching_registered_queries: int | None = None


def decode_registered_activation_query(
    encoded: bytes,
) -> ActivationRevocationQueryV2:
    if not isinstance(encoded, bytes) or len(encoded) != QUERY_BYTES:
        raise UnifiedActivationInboxIntegrityError(
            "registered activation query length mismatch"
        )
    offset = 0
    suite_id, offset = _take_uint(encoded, offset, 2, "query suite ID")
    fields: list[bytes] = []
    for name in (
        "system configuration digest",
        "acceptance domain digest",
        "ctx",
        "ticket use key",
        "original revocation query digest",
        "FGS ID",
        "FGS authentication key ID",
        "request digest",
        "response digest",
        "session ID",
    ):
        value, offset = _take(encoded, offset, 32, name)
        fields.append(value)
    query = ActivationRevocationQueryV2(suite_id, *fields)
    try:
        if query.encode() != encoded:
            raise ValueError("registered activation query is non-canonical")
    except Exception as error:
        raise UnifiedActivationInboxIntegrityError(
            "registered activation query is invalid"
        ) from error
    return query


def derive_registered_query_checksum(encoded: bytes) -> bytes:
    if not isinstance(encoded, bytes) or len(encoded) != QUERY_BYTES:
        raise ValueError("canonical activation query is required")
    return hashlib.shake_256(QUERY_CHECKSUM_DOMAIN + encoded).digest(32)


def derive_revocation_envelope_checksum(encoded: bytes) -> bytes:
    if not isinstance(encoded, bytes) or not encoded:
        raise ValueError("canonical authenticated command is required")
    return hashlib.shake_256(COMMAND_CHECKSUM_DOMAIN + encoded).digest(32)


class SQLiteFGSScopedRevocationStoreV2(
    SQLiteFGSAuthoritativeActivationInboxStoreV2
):
    """Successor store with authenticated append-only commands and fanout."""

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
                "scoped revocation database application_id mismatch"
            )
        if self._pragma(connection, "user_version") != SCHEMA_VERSION:
            raise UnifiedActivationInboxIntegrityError(
                "scoped revocation database schema version mismatch"
            )
        tables = self._tables(connection)
        expected = {
            "fgs_replay_records": REPLAY_SCHEMA_SQL,
            "first_application_inbox": INBOX_SCHEMA_SQL,
            "activation_revocation_fences": _FENCE_SCHEMA_SQL,
            "activation_revocation_queries": _QUERY_SCHEMA_SQL,
            "authenticated_revocation_commands": _COMMAND_SCHEMA_SQL,
        }
        if set(tables) != set(expected):
            raise UnifiedActivationInboxIntegrityError(
                "scoped revocation database table set mismatch"
            )
        for name, schema in expected.items():
            if _normalized_sql(tables[name]) != _normalized_sql(schema):
                raise UnifiedActivationInboxIntegrityError(
                    f"scoped revocation {name} schema mismatch"
                )
        mode = connection.execute("PRAGMA journal_mode").fetchone()
        if mode is None or str(mode[0]).lower() != "wal":
            raise UnifiedActivationInboxIntegrityError(
                "scoped revocation database is not in WAL mode"
            )
        if self._pragma(connection, "synchronous") != 2:
            raise UnifiedActivationInboxIntegrityError(
                "scoped revocation database is not FULL synchronous"
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
                        "empty scoped database has unexpected application_id"
                    )
                if self._pragma(connection, "user_version") != 0:
                    raise UnifiedActivationInboxIntegrityError(
                        "empty scoped database has unexpected schema version"
                    )
                connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                connection.execute(REPLAY_SCHEMA_SQL)
                connection.execute(INBOX_SCHEMA_SQL)
                connection.execute(_FENCE_SCHEMA_SQL)
                connection.execute(_QUERY_SCHEMA_SQL)
                connection.execute(_COMMAND_SCHEMA_SQL)
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
    def _decode_query_row(row: tuple[object, ...]) -> ActivationRevocationQueryV2:
        if len(row) != 3:
            raise UnifiedActivationInboxIntegrityError(
                "registered activation query row has wrong width"
            )
        query_digest, encoded, checksum = row
        try:
            if not isinstance(query_digest, bytes) or len(query_digest) != 32:
                raise TypeError("registered query digest is invalid")
            if not isinstance(encoded, bytes):
                raise TypeError("registered query must be bytes")
            if not isinstance(checksum, bytes) or len(checksum) != 32:
                raise TypeError("registered query checksum is invalid")
            if not hmac.compare_digest(
                checksum,
                derive_registered_query_checksum(encoded),
            ):
                raise ValueError("registered query checksum mismatch")
            query = decode_registered_activation_query(encoded)
            if query.digest != query_digest:
                raise ValueError("registered query digest mismatch")
            return query
        except Exception as error:
            raise UnifiedActivationInboxIntegrityError(
                "stored activation query is invalid"
            ) from error

    def _select_query(
        self,
        connection: sqlite3.Connection,
        query_digest: bytes,
    ) -> ActivationRevocationQueryV2 | None:
        row = connection.execute(
            "SELECT query_digest, canonical_query, query_checksum "
            "FROM activation_revocation_queries WHERE query_digest = ?",
            (query_digest,),
        ).fetchone()
        return None if row is None else self._decode_query_row(row)

    def _registered_queries(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[ActivationRevocationQueryV2, ...]:
        rows = connection.execute(
            "SELECT query_digest, canonical_query, query_checksum "
            "FROM activation_revocation_queries ORDER BY query_digest"
        ).fetchall()
        return tuple(self._decode_query_row(row) for row in rows)

    @staticmethod
    def _decode_command_row(
        row: tuple[object, ...],
    ) -> AuthenticatedRevocationCommandV2:
        if len(row) != 6:
            raise UnifiedActivationInboxIntegrityError(
                "authenticated revocation command row has wrong width"
            )
        command_id, ctx, generation, command_digest, encoded, checksum = row
        try:
            if not isinstance(encoded, bytes):
                raise TypeError("stored command envelope must be bytes")
            if not isinstance(checksum, bytes) or len(checksum) != 32:
                raise TypeError("stored command checksum is invalid")
            if not hmac.compare_digest(
                checksum,
                derive_revocation_envelope_checksum(encoded),
            ):
                raise ValueError("stored command checksum mismatch")
            envelope = AuthenticatedRevocationCommandV2.decode(encoded)
            command = envelope.command
            metadata = (
                command.command_id,
                command.ctx,
                command.generation,
                command.digest,
            )
            if metadata != (command_id, ctx, generation, command_digest):
                raise ValueError("stored command metadata mismatch")
            return envelope
        except Exception as error:
            raise UnifiedActivationInboxIntegrityError(
                "stored authenticated revocation command is invalid"
            ) from error

    def _select_command(
        self,
        connection: sqlite3.Connection,
        command_id: bytes,
    ) -> AuthenticatedRevocationCommandV2 | None:
        row = connection.execute(
            "SELECT command_id, ctx, generation, command_digest, "
            "canonical_envelope, envelope_checksum "
            "FROM authenticated_revocation_commands WHERE command_id = ?",
            (command_id,),
        ).fetchone()
        return None if row is None else self._decode_command_row(row)

    def _commands_for_ctx(
        self,
        connection: sqlite3.Connection,
        ctx: bytes,
    ) -> tuple[AuthenticatedRevocationCommandV2, ...]:
        rows = connection.execute(
            "SELECT command_id, ctx, generation, command_digest, "
            "canonical_envelope, envelope_checksum "
            "FROM authenticated_revocation_commands WHERE ctx = ? "
            "ORDER BY generation",
            (ctx,),
        ).fetchall()
        return tuple(self._decode_command_row(row) for row in rows)

    @staticmethod
    def _scope_matches(
        command: RevocationCommandV2,
        query: ActivationRevocationQueryV2,
    ) -> bool:
        if command.ctx != query.ctx:
            return False
        target = {
            RevocationScopeV2.ACCESS_CONFIGURATION: (
                query.system_config_digest
            ),
            RevocationScopeV2.FGS_AUTHENTICATION_KEY: (
                query.fgs_auth_key_id
            ),
            RevocationScopeV2.TICKET_USE: query.ticket_use_key,
            RevocationScopeV2.SESSION: query.session_id,
        }[command.scope]
        return command.scope_target == target

    @staticmethod
    def _apply_command(
        snapshot: ActivationRevocationSnapshotV2,
        command: RevocationCommandV2,
    ) -> ActivationRevocationSnapshotV2:
        changes: dict[str, object] = {
            "generation": max(snapshot.generation, command.generation),
        }
        flag = {
            RevocationScopeV2.ACCESS_CONFIGURATION: "configuration_revoked",
            RevocationScopeV2.FGS_AUTHENTICATION_KEY: "fgs_key_revoked",
            RevocationScopeV2.TICKET_USE: "ticket_revoked",
            RevocationScopeV2.SESSION: "session_revoked",
        }[command.scope]
        changes[flag] = True
        updated = replace(snapshot, **changes)
        updated.validate()
        return updated

    def _replace_fence(
        self,
        connection: sqlite3.Connection,
        existing: ActivationRevocationFenceRecordV2,
        snapshot: ActivationRevocationSnapshotV2,
    ) -> ActivationRevocationFenceRecordV2:
        updated = ActivationRevocationFenceRecordV2(
            snapshot,
            existing.revision + 1,
        )
        updated.validate()
        cursor = connection.execute(
            "UPDATE activation_revocation_fences SET generation = ?, "
            "revision = ?, effective_at = ?, valid_until = ?, "
            "configuration_revoked = ?, fgs_key_revoked = ?, "
            "ticket_revoked = ?, session_revoked = ?, canonical_record = ?, "
            "record_checksum = ? WHERE query_digest = ? AND revision = ?",
            self._write_values(updated)[1:]
            + (snapshot.query_digest, existing.revision),
        )
        if cursor.rowcount != 1:
            raise UnifiedActivationInboxStorageError(
                "revocation fanout changed an unexpected fence row count"
            )
        return updated

    def _register_activation_query_in_transaction(
        self,
        connection: sqlite3.Connection,
        query: ActivationRevocationQueryV2,
        base_generation: int,
    ) -> ActivationRevocationSnapshotV2:
        if not isinstance(query, ActivationRevocationQueryV2):
            raise TypeError("query must be an ActivationRevocationQueryV2")
        encoded = query.encode()
        _sqlite_uint(base_generation, "base_generation")
        existing_query = self._select_query(connection, query.digest)
        if existing_query is not None:
            if existing_query != query:
                raise UnifiedActivationInboxIntegrityError(
                    "registered query digest collision"
                )
            existing_fence = self._select_fence(connection, query.digest)
            if existing_fence is None:
                raise UnifiedActivationInboxIntegrityError(
                    "registered query lacks a revocation fence"
                )
            if existing_fence.snapshot.generation < base_generation:
                raise InvalidTransition(
                    "registered query base generation advanced"
                )
            return existing_fence.snapshot

        for registered in self._registered_queries(connection):
            if (
                registered.session_id == query.session_id
                or registered.ticket_use_key == query.ticket_use_key
            ):
                raise InvalidTransition(
                    "session or ticket already has another activation query"
                )

        snapshot = ActivationRevocationSnapshotV2(
            query_digest=query.digest,
            generation=base_generation,
            effective_at=0,
            valid_until=SQLITE_INT_MAX,
        )
        for envelope in self._commands_for_ctx(connection, query.ctx):
            if self._scope_matches(envelope.command, query):
                snapshot = self._apply_command(snapshot, envelope.command)
        record = ActivationRevocationFenceRecordV2(snapshot, 1)
        record.validate()
        connection.execute(
            "INSERT INTO activation_revocation_queries "
            "(query_digest, canonical_query, query_checksum) "
            "VALUES (?, ?, ?)",
            (
                query.digest,
                encoded,
                derive_registered_query_checksum(encoded),
            ),
        )
        connection.execute(
            "INSERT INTO activation_revocation_fences "
            "(query_digest, generation, revision, effective_at, "
            "valid_until, configuration_revoked, fgs_key_revoked, "
            "ticket_revoked, session_revoked, canonical_record, "
            "record_checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            self._write_values(record),
        )
        return snapshot

    def register_activation_query(
        self,
        query: ActivationRevocationQueryV2,
        *,
        base_generation: int,
    ) -> ActivationRevocationSnapshotV2:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            snapshot = self._register_activation_query_in_transaction(
                connection,
                query,
                base_generation,
            )
            connection.execute("COMMIT")
            return snapshot
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @staticmethod
    def _validate_grant_query_binding(
        record: GrantRecordV2,
        query: ActivationRevocationQueryV2,
    ) -> None:
        bindings = (
            (query.ctx, record.identity.ctx),
            (query.ticket_use_key, record.identity.use_key),
            (query.fgs_id, record.fgs_id),
            (query.request_digest, record.request_digest),
            (query.response_digest, record.response_digest),
            (query.session_id, record.session_id),
        )
        if any(actual != expected for actual, expected in bindings):
            raise InvalidTransition(
                "registered activation query and grant differ"
            )

    def _registered_query_for_grant(
        self,
        connection: sqlite3.Connection,
        record: GrantRecordV2,
    ) -> ActivationRevocationQueryV2:
        matching = tuple(
            query
            for query in self._registered_queries(connection)
            if query.session_id == record.session_id
        )
        if len(matching) != 1:
            raise ActivationRevocationFenceUnavailable(
                "grant does not have exactly one registered activation query"
            )
        query = matching[0]
        self._validate_grant_query_binding(record, query)
        fence = self._select_fence(connection, query.digest)
        if fence is None:
            raise ActivationRevocationFenceUnavailable(
                "registered grant query lacks a revocation fence"
            )
        if fence.snapshot.generation < record.revocation_generation:
            raise InvalidTransition(
                "registered grant revocation generation is stale"
            )
        return query

    def commit_grant(self, *_args: object, **_kwargs: object) -> GrantRecordV2:
        raise InvalidTransition(
            "scoped store requires atomic grant and query registration"
        )

    def commit_grant_and_register(
        self,
        request: GrantCommitRequestV2,
    ) -> GrantRecordV2:
        if not isinstance(request, GrantCommitRequestV2):
            raise TypeError("request must be a GrantCommitRequestV2")
        request.validate()
        candidate = request.record
        query = request.activation_revocation_query
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            record = self._commit_grant_candidate(
                connection,
                candidate,
                request.fencing_generation,
            )
            snapshot = self._register_activation_query_in_transaction(
                connection,
                query,
                record.revocation_generation,
            )
            self._validate_grant_query_binding(record, query)
            if snapshot.revoked:
                raise InvalidTransition(
                    "matching revocation precedes grant commit"
                )
            connection.execute("COMMIT")
            return record
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def validate_registered_grant(self, record: GrantRecordV2) -> None:
        if not isinstance(record, GrantRecordV2):
            raise TypeError("record must be a GrantRecordV2")
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            _, stored = self._check_identity_bindings(
                connection,
                record.identity,
            )
            if not isinstance(stored, GrantRecordV2) or stored != record:
                raise UnifiedActivationInboxIntegrityError(
                    "stored grant changed before query validation"
                )
            self._registered_query_for_grant(connection, stored)
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _validate_reservation_abort_transaction(
        self,
        connection: sqlite3.Connection,
        reservation: ReservationV2,
    ) -> None:
        for query in self._registered_queries(connection):
            if query.ticket_use_key == reservation.identity.use_key:
                raise InvalidTransition(
                    "reservation with activation query cannot be released"
                )

    def publish_activation_revocation(self, *_args: object, **_kwargs: object):
        raise InvalidTransition(
            "scoped store requires authenticated revocation ingestion"
        )

    def ingest_authenticated_revocation(
        self,
        authenticated_initialization: bytes,
        encoded_command: bytes,
        *,
        trusted_configuration_key: KeyReference,
        initialization_verifier: ConfigurationAuthenticationVerifier,
        command_verifier: RevocationCommandAuthenticationVerifierV2,
        now: int,
    ) -> RevocationIngestResultV2:
        initialization = verify_initialization(
            authenticated_initialization,
            trusted_configuration_key,
            initialization_verifier,
        )
        if not initialization.accepted or initialization.bundle is None:
            return _ingest_rejection(
                *(
                    "initialization:" + failure
                    for failure in initialization.failures
                )
            )
        try:
            envelope = AuthenticatedRevocationCommandV2.decode(encoded_command)
        except Exception as error:
            return _ingest_rejection(f"command_encoding:{type(error).__name__}")
        command = envelope.command
        bundle = initialization.bundle
        configuration = bundle.configuration
        configuration_key = bundle.key_for(KeyRole.FEDERATION_CONFIGURATION)
        expected_bundle_digest = bytes.fromhex(bundle.sha256)
        bindings = (
            (command.ctx, bundle.ctx, "command_ctx_mismatch"),
            (
                command.system_bundle_digest,
                expected_bundle_digest,
                "command_system_bundle_mismatch",
            ),
            (command.epoch, configuration.epoch, "command_epoch_mismatch"),
            (
                command.policy_digest,
                configuration.policy_digest,
                "command_policy_mismatch",
            ),
            (
                command.signer_key_id,
                configuration_key.key_id,
                "command_signer_key_mismatch",
            ),
        )
        for actual, expected, failure in bindings:
            if actual != expected:
                return _ingest_rejection(failure)
        if envelope.signing_role is not KeyRole.FEDERATION_CONFIGURATION:
            return _ingest_rejection("command_wrong_key_role")
        try:
            checked_now = _sqlite_uint(now, "now")
        except Exception as error:
            return _ingest_rejection(f"command_clock:{type(error).__name__}")
        if checked_now < command.issued_at:
            return _ingest_rejection("command_not_yet_valid")
        if checked_now >= command.authorization_expires_at:
            return _ingest_rejection("command_authorization_expired")
        if command.authorization_expires_at > configuration.expiry_bucket:
            return _ingest_rejection("command_exceeds_configuration_expiry")
        try:
            authentication_valid = command_verifier.verify(
                configuration_key,
                envelope.authentication_message,
                envelope.authentication,
            )
        except Exception as error:
            return _ingest_rejection(
                f"command_authentication_backend:{type(error).__name__}"
            )
        if authentication_valid is not True:
            return _ingest_rejection("command_authentication_invalid")
        try:
            disposition, matching = self._commit_authenticated_command(envelope)
        except Exception as error:
            return _ingest_rejection(f"command_commit:{type(error).__name__}")
        return RevocationIngestResultV2(
            True,
            disposition,
            (),
            command.digest,
            matching,
        )

    def _commit_authenticated_command(
        self,
        envelope: AuthenticatedRevocationCommandV2,
    ) -> tuple[RevocationIngestDispositionV2, int]:
        encoded = envelope.encode()
        command = envelope.command
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._select_command(connection, command.command_id)
            registered = self._registered_queries(connection)
            matching_queries = tuple(
                query
                for query in registered
                if self._scope_matches(command, query)
            )
            if existing is not None:
                if existing != envelope:
                    raise InvalidTransition(
                        "revocation command identifier cannot change"
                    )
                connection.execute("COMMIT")
                return RevocationIngestDispositionV2.REPLAY, len(
                    matching_queries
                )

            prior = self._commands_for_ctx(connection, command.ctx)
            if prior:
                previous = prior[-1].command
                if command.system_bundle_digest != previous.system_bundle_digest:
                    raise InvalidTransition(
                        "revocation authority bundle cannot change"
                    )
                if command.signer_key_id != previous.signer_key_id:
                    raise InvalidTransition(
                        "revocation authority key cannot change"
                    )
                if command.generation <= previous.generation:
                    raise InvalidTransition(
                        "revocation command generation must advance"
                    )
            connection.execute(
                "INSERT INTO authenticated_revocation_commands "
                "(command_id, ctx, generation, command_digest, "
                "canonical_envelope, envelope_checksum) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    command.command_id,
                    command.ctx,
                    command.generation,
                    command.digest,
                    encoded,
                    derive_revocation_envelope_checksum(encoded),
                ),
            )
            for query in matching_queries:
                existing_fence = self._select_fence(connection, query.digest)
                if existing_fence is None:
                    raise UnifiedActivationInboxIntegrityError(
                        "registered query lacks a revocation fence"
                    )
                snapshot = self._apply_command(
                    existing_fence.snapshot,
                    command,
                )
                self._replace_fence(connection, existing_fence, snapshot)
            connection.execute("COMMIT")
            return RevocationIngestDispositionV2.INGESTED, len(
                matching_queries
            )
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
            registered = self._select_query(connection, query.digest)
            if registered is None:
                raise ActivationRevocationFenceUnavailable(
                    "activation query is not registered"
                )
            if registered != query:
                raise UnifiedActivationInboxIntegrityError(
                    "registered activation query changed"
                )
            record = self._select_fence(connection, query.digest)
            if record is None:
                raise ActivationRevocationFenceUnavailable(
                    "registered query lacks a revocation fence"
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
        if not isinstance(query, ActivationRevocationQueryV2):
            raise ActivationRevocationFenceUnavailable(
                "scoped activation requires a registered query"
            )
        registered = self._select_query(connection, query.digest)
        if registered is None:
            raise ActivationRevocationFenceUnavailable(
                "activation query is not registered at commit"
            )
        if registered != query:
            raise UnifiedActivationInboxIntegrityError(
                "registered activation query changed at commit"
            )
        super()._validate_activation_fence(connection, request, grant)

    def registered_query_count(self) -> int:
        return self._count("activation_revocation_queries")

    def command_count(self) -> int:
        return self._count("authenticated_revocation_commands")

    def _count(self, table: str) -> int:
        if table not in {
            "activation_revocation_queries",
            "authenticated_revocation_commands",
        }:
            raise ValueError("unsupported scoped revocation table")
        connection = self._connect()
        try:
            row = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            if row is None:
                raise UnifiedActivationInboxStorageError(
                    "scoped revocation count is unavailable"
                )
            return int(row[0])
        finally:
            connection.close()


def sqlite_scoped_revocation_manifest() -> dict[str, object]:
    return {
        "format": "PQ-SAT-FGS-SCOPED-REVOCATION-SQLITE-v0.2",
        "application_id": f"0x{APPLICATION_ID:08x}",
        "schema_version": SCHEMA_VERSION,
        "journal_mode": "WAL",
        "synchronous": "FULL",
        "authority_key_role": KeyRole.FEDERATION_CONFIGURATION.name,
        "authority_key_selection": "provisional_existing_system_bundle_role",
        "scopes": [scope.name for scope in RevocationScopeV2],
        "tables": [
            "fgs_replay_records",
            "first_application_inbox",
            "activation_revocation_fences",
            "activation_revocation_queries",
            "authenticated_revocation_commands",
        ],
        "claims": {
            "canonical_authenticated_command_implemented": True,
            "explicit_configuration_trust_anchor_required": True,
            "system_bundle_epoch_policy_and_key_bound": True,
            "append_only_command_replay_and_generation_control": True,
            "registered_current_query_fanout_implemented": True,
            "future_query_rule_application_implemented": True,
            "grant_and_query_registration_same_transaction": True,
            "source_access_revocation_query_bound_at_commit": True,
            "matching_preexisting_revocation_rejects_grant_commit": True,
            "existing_grant_query_validation_before_retry_release": True,
            "direct_grant_commit_without_query_disabled": True,
            "expired_reservation_reconciliation_available": True,
            "bounded_expired_reservation_scan": True,
            "persistent_monotonic_worker_fencing": True,
            "reservation_query_dependency_guard": True,
            "schema_migration_from_v1_implemented": False,
            "configuration_scope_implemented": True,
            "fgs_authentication_key_scope_implemented": True,
            "ticket_use_scope_implemented": True,
            "session_scope_implemented": True,
            "command_ingest_and_fanout_same_transaction": True,
            "command_ingest_and_grant_commit_linearizable": True,
            "command_ingest_and_activation_linearizable": True,
            "activation_inbox_and_fence_same_transaction": True,
            "unauthenticated_direct_publication_disabled": True,
            "unrevocation_implemented": False,
            "authority_key_rotation_implemented": False,
            "production_pq_authentication_instantiated": False,
            "distributed_replication_implemented": False,
            "scope_fanout_scale_benchmarked": False,
            "physical_power_loss_tested": False,
            "external_application_same_transaction": False,
            "production_record_protection_instantiated": False,
            "production_plaintext_protection_instantiated": False,
            "distributed": False,
            "production_ready": False,
        },
    }


def _ingest_rejection(*failures: str) -> RevocationIngestResultV2:
    return RevocationIngestResultV2(False, None, tuple(failures))


def _fixed(
    value: bytes,
    size: int,
    name: str,
    *,
    nonzero: bool = False,
) -> bytes:
    if not isinstance(value, bytes) or len(value) != size:
        raise RevocationCommandError(f"{name} must be exactly {size} bytes")
    if nonzero and value == bytes(size):
        raise RevocationCommandError(f"{name} must not be all zero")
    return value


def _uint(value: int, width: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RevocationCommandError(f"{name} must be an integer")
    if not 0 <= value < (1 << (width * 8)):
        raise RevocationCommandError(f"{name} does not fit uint{width * 8}")
    return value


def _sqlite_uint(value: int, name: str) -> int:
    _uint(value, 8, name)
    if value > SQLITE_INT_MAX:
        raise RevocationCommandError(f"{name} exceeds the SQLite integer bound")
    return value


def _take(
    encoded: bytes,
    offset: int,
    length: int,
    name: str,
) -> tuple[bytes, int]:
    if length < 0 or offset + length > len(encoded):
        raise RevocationCommandError(f"{name} truncated")
    return encoded[offset : offset + length], offset + length


def _take_uint(
    encoded: bytes,
    offset: int,
    length: int,
    name: str,
) -> tuple[int, int]:
    raw, offset = _take(encoded, offset, length, name)
    return int.from_bytes(raw, "big"), offset


def _expect(
    encoded: bytes,
    offset: int,
    expected: bytes,
    name: str,
) -> int:
    actual, offset = _take(encoded, offset, len(expected), name)
    if actual != expected:
        raise RevocationCommandError(f"wrong {name}")
    return offset


def _command_bytes() -> int:
    return len(REVOCATION_COMMAND_MAGIC) + 2 + (7 * 32) + (4 * 8) + 2
