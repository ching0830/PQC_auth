"""Single-host durable SQLite replay store for satellite access v0.2.

This module implements the same state machine as the process-local reference
store with cross-process SQLite serialization and restart recovery.  A
separate record-protection backend authenticates each canonical record.  The
profile remains non-production because it is neither distributed nor tested
against hostile filesystems or physical power loss.
"""

from __future__ import annotations

import json
import os
import sqlite3
import struct
from dataclasses import replace
from pathlib import Path
from typing import Protocol

from pq_sat_auth.identities import TicketUseIdentity
from pq_sat_auth.replay import (
    IdentityConflict,
    InvalidTransition,
    ReservationNotFound,
    TicketUnavailable,
)

from ..replay import (
    ActivateDispositionV2,
    ActivateResultV2,
    GrantRecordV2,
    GrantStateV2,
    ReservationAbortEvidenceV2,
    ReservationV2,
    ReserveDispositionV2,
    ReserveResultV2,
    UseRecordV2,
    _commit_identity,
)


APPLICATION_ID = 0x50515352
SCHEMA_VERSION = 1
RECORD_FORMAT = "PQ-SAT-FGS-REPLAY-RECORD-v0.2"
RECORD_AAD_LABEL = b"PQ-SAT/FGS-REPLAY-RECORD-AAD/v0.2"
MAX_RECORD_BYTES = 4_500_000
MAX_PROTECTED_RECORD_BYTES = 5_000_000
MAX_EXPIRY_REASON_BYTES = 4_096
PRODUCTION_READY = False

STATE_RESERVED = 1
STATE_PENDING = 2
STATE_ACTIVE = 3
STATE_EXPIRED = 4

_SCHEMA_SQL = """CREATE TABLE fgs_replay_records (
    use_key BLOB PRIMARY KEY NOT NULL
        CHECK(typeof(use_key) = 'blob' AND length(use_key) = 32),
    ctx BLOB NOT NULL
        CHECK(typeof(ctx) = 'blob' AND length(ctx) = 32),
    serial BLOB NOT NULL
        CHECK(typeof(serial) = 'blob' AND length(serial) = 16),
    ticket_digest BLOB NOT NULL
        CHECK(typeof(ticket_digest) = 'blob' AND length(ticket_digest) = 32),
    state INTEGER NOT NULL CHECK(state IN (1, 2, 3, 4)),
    revision INTEGER NOT NULL CHECK(revision IN (1, 2, 3, 4)),
    protection_id TEXT NOT NULL
        CHECK(typeof(protection_id) = 'text'
              AND length(protection_id) BETWEEN 1 AND 128),
    session_id BLOB
        CHECK(session_id IS NULL
              OR (typeof(session_id) = 'blob' AND length(session_id) = 32)),
    protected_record BLOB NOT NULL
        CHECK(typeof(protected_record) = 'blob'
              AND length(protected_record) BETWEEN 1 AND 5000000),
    UNIQUE(ctx, ticket_digest),
    UNIQUE(ctx, serial),
    UNIQUE(session_id),
    CHECK(state = revision),
    CHECK((state = 1 AND session_id IS NULL)
          OR (state IN (2, 3, 4) AND session_id IS NOT NULL))
) WITHOUT ROWID"""


class FGSReplayStoreError(RuntimeError):
    pass


class FGSReplayStorageError(FGSReplayStoreError):
    pass


class FGSReplayIntegrityError(FGSReplayStoreError):
    pass


class FGSReplayRecordProtectionV2(Protocol):
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


def _exact_keys(value: dict[str, object], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise ValueError(f"{name} has unknown or missing fields")


def _canonical_json(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _reason(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("expiry_reason must be a string")
    encoded = value.encode("utf-8")
    if not encoded:
        raise ValueError("expiry_reason must not be empty")
    if len(encoded) > MAX_EXPIRY_REASON_BYTES:
        raise ValueError("expiry_reason exceeds the storage bound")
    return value


def _identity_to_object(identity: TicketUseIdentity) -> dict[str, object]:
    if not isinstance(identity, TicketUseIdentity):
        raise TypeError("identity must be a TicketUseIdentity")
    return {
        "ctx": _hex(identity.ctx),
        "serial": _hex(identity.serial),
        "ticket_digest": _hex(identity.ticket_digest),
    }


def _identity_from_object(value: object) -> TicketUseIdentity:
    item = _mapping(value, "identity")
    _exact_keys(item, {"ctx", "serial", "ticket_digest"}, "identity")
    return TicketUseIdentity(
        ctx=_unhex(item["ctx"], "identity ctx"),
        serial=_unhex(item["serial"], "identity serial"),
        ticket_digest=_unhex(item["ticket_digest"], "identity ticket_digest"),
    )


def _optional_hex(value: object, name: str) -> bytes | None:
    return None if value is None else _unhex(value, name)


def _optional_integer(value: object, name: str) -> int | None:
    return None if value is None else _integer(value, name)


def _state_code(record: UseRecordV2) -> int:
    if isinstance(record, ReservationV2):
        return STATE_RESERVED
    if not isinstance(record, GrantRecordV2):
        raise TypeError("record has the wrong type")
    return {
        GrantStateV2.CONSUMED_PENDING_CONFIRM: STATE_PENDING,
        GrantStateV2.CONSUMED_ACTIVE: STATE_ACTIVE,
        GrantStateV2.CONSUMED_EXPIRED: STATE_EXPIRED,
    }[record.state]


def _session_id(record: UseRecordV2) -> bytes | None:
    return None if isinstance(record, ReservationV2) else record.session_id


def encode_replay_record(record: UseRecordV2) -> bytes:
    if isinstance(record, ReservationV2):
        value: dict[str, object] = {
            "attempt_id": _hex(record.attempt_id),
            "format": RECORD_FORMAT,
            "identity": _identity_to_object(record.identity),
            "kind": "RESERVATION",
            "lease_deadline": record.lease_deadline,
            "request_digest": _hex(record.request_digest),
            "reserved_at": record.reserved_at,
            "revocation_generation": record.revocation_generation,
            "serving_context_digest": _hex(record.serving_context_digest),
        }
    elif isinstance(record, GrantRecordV2):
        if record.expiry_reason is not None:
            _reason(record.expiry_reason)
        value = {
            "activated_at": record.activated_at,
            "activation_deadline": record.activation_deadline,
            "attempt_id": _hex(record.attempt_id),
            "client_confirmation_digest": (
                None
                if record.client_confirmation_digest is None
                else _hex(record.client_confirmation_digest)
            ),
            "consumed_at": record.consumed_at,
            "expired_at": record.expired_at,
            "expiry_reason": record.expiry_reason,
            "fgs_id": _hex(record.fgs_id),
            "format": RECORD_FORMAT,
            "identity": _identity_to_object(record.identity),
            "kind": "GRANT",
            "request_digest": _hex(record.request_digest),
            "response_digest": _hex(record.response_digest),
            "retention_deadline": record.retention_deadline,
            "revocation_generation": record.revocation_generation,
            "sealed_response": _hex(record.sealed_response),
            "sealed_session_state": _hex(record.sealed_session_state),
            "serving_context_digest": _hex(record.serving_context_digest),
            "session_expiry": record.session_expiry,
            "session_id": _hex(record.session_id),
            "state": record.state.name,
            "transcript_digest": _hex(record.transcript_digest),
        }
    else:
        raise TypeError("record has the wrong type")
    encoded = _canonical_json(value)
    if len(encoded) > MAX_RECORD_BYTES:
        raise ValueError("replay record exceeds the canonical size bound")
    return encoded


def decode_replay_record(encoded: bytes) -> UseRecordV2:
    if not isinstance(encoded, bytes) or not encoded:
        raise TypeError("replay record must be non-empty bytes")
    if len(encoded) > MAX_RECORD_BYTES:
        raise FGSReplayIntegrityError("replay record exceeds the size bound")
    try:
        value = json.loads(encoded.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FGSReplayIntegrityError("replay record is not canonical JSON") from error
    item = _mapping(value, "replay record")
    kind = item.get("kind")
    if kind == "RESERVATION":
        _exact_keys(
            item,
            {
                "attempt_id",
                "format",
                "identity",
                "kind",
                "lease_deadline",
                "request_digest",
                "reserved_at",
                "revocation_generation",
                "serving_context_digest",
            },
            "reservation record",
        )
        record: UseRecordV2 = ReservationV2(
            identity=_identity_from_object(item["identity"]),
            attempt_id=_unhex(item["attempt_id"], "attempt_id"),
            request_digest=_unhex(item["request_digest"], "request_digest"),
            serving_context_digest=_unhex(
                item["serving_context_digest"],
                "serving_context_digest",
            ),
            reserved_at=_integer(item["reserved_at"], "reserved_at"),
            lease_deadline=_integer(item["lease_deadline"], "lease_deadline"),
            revocation_generation=_integer(
                item["revocation_generation"],
                "revocation_generation",
            ),
        )
    elif kind == "GRANT":
        _exact_keys(
            item,
            {
                "activated_at",
                "activation_deadline",
                "attempt_id",
                "client_confirmation_digest",
                "consumed_at",
                "expired_at",
                "expiry_reason",
                "fgs_id",
                "format",
                "identity",
                "kind",
                "request_digest",
                "response_digest",
                "retention_deadline",
                "revocation_generation",
                "sealed_response",
                "sealed_session_state",
                "serving_context_digest",
                "session_expiry",
                "session_id",
                "state",
                "transcript_digest",
            },
            "grant record",
        )
        try:
            state = GrantStateV2[item["state"]]  # type: ignore[index]
        except (KeyError, TypeError) as error:
            raise FGSReplayIntegrityError("grant state is unknown") from error
        expiry_reason = item["expiry_reason"]
        if expiry_reason is not None:
            expiry_reason = _reason(expiry_reason)
        record = GrantRecordV2(
            state=state,
            identity=_identity_from_object(item["identity"]),
            attempt_id=_unhex(item["attempt_id"], "attempt_id"),
            request_digest=_unhex(item["request_digest"], "request_digest"),
            transcript_digest=_unhex(
                item["transcript_digest"],
                "transcript_digest",
            ),
            session_id=_unhex(item["session_id"], "session_id"),
            response_digest=_unhex(item["response_digest"], "response_digest"),
            sealed_response=_unhex(item["sealed_response"], "sealed_response"),
            sealed_session_state=_unhex(
                item["sealed_session_state"],
                "sealed_session_state",
            ),
            serving_context_digest=_unhex(
                item["serving_context_digest"],
                "serving_context_digest",
            ),
            fgs_id=_unhex(item["fgs_id"], "fgs_id"),
            revocation_generation=_integer(
                item["revocation_generation"],
                "revocation_generation",
            ),
            consumed_at=_integer(item["consumed_at"], "consumed_at"),
            activation_deadline=_integer(
                item["activation_deadline"],
                "activation_deadline",
            ),
            session_expiry=_integer(item["session_expiry"], "session_expiry"),
            retention_deadline=_integer(
                item["retention_deadline"],
                "retention_deadline",
            ),
            client_confirmation_digest=_optional_hex(
                item["client_confirmation_digest"],
                "client_confirmation_digest",
            ),
            activated_at=_optional_integer(item["activated_at"], "activated_at"),
            expired_at=_optional_integer(item["expired_at"], "expired_at"),
            expiry_reason=expiry_reason,  # type: ignore[arg-type]
        )
    else:
        raise FGSReplayIntegrityError("replay record kind is unknown")
    if item["format"] != RECORD_FORMAT:
        raise FGSReplayIntegrityError("replay record format mismatch")
    if encode_replay_record(record) != encoded:
        raise FGSReplayIntegrityError("replay record encoding is non-canonical")
    return record


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
    identity: TicketUseIdentity,
    state: int,
    session_id: bytes | None,
) -> bytes:
    encoded_session = bytes(32) if session_id is None else _fixed(
        session_id,
        32,
        "session_id",
    )
    return b"".join(
        (
            RECORD_AAD_LABEL,
            identity.use_key,
            identity.ctx,
            identity.serial,
            identity.ticket_digest,
            struct.pack(">HH", state, state),
            b"\x00" if session_id is None else b"\x01",
            encoded_session,
        )
    )


def _normalized_sql(value: str) -> str:
    return "".join(value.split())


class SQLiteFGSReplayStoreV2:
    """Cross-process, restart-durable reference store on one SQLite host."""

    production_ready = False
    durable = True
    distributed = False

    def __init__(
        self,
        path: str | os.PathLike[str],
        protection_backend: FGSReplayRecordProtectionV2,
        *,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        candidate = Path(path)
        if not candidate.is_absolute():
            raise ValueError("replay database path must be absolute")
        if not candidate.parent.is_dir():
            raise ValueError("replay database parent must exist")
        if candidate.exists() and (candidate.is_symlink() or not candidate.is_file()):
            raise ValueError("replay database must be a regular non-symlink file")
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
            raise FGSReplayStorageError(f"SQLite {name} is unavailable")
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
            raise FGSReplayIntegrityError("replay database application_id mismatch")
        if self._pragma(connection, "user_version") != SCHEMA_VERSION:
            raise FGSReplayIntegrityError("replay database schema version mismatch")
        tables = self._tables(connection)
        if set(tables) != {"fgs_replay_records"}:
            raise FGSReplayIntegrityError("replay database table set mismatch")
        if _normalized_sql(tables["fgs_replay_records"]) != _normalized_sql(
            _SCHEMA_SQL
        ):
            raise FGSReplayIntegrityError("replay database schema mismatch")
        mode = connection.execute("PRAGMA journal_mode").fetchone()
        if mode is None or str(mode[0]).lower() != "wal":
            raise FGSReplayIntegrityError("replay database is not in WAL mode")
        if self._pragma(connection, "synchronous") != 2:
            raise FGSReplayIntegrityError(
                "replay database is not FULL synchronous"
            )

    def _initialize(self) -> None:
        existed = self._path.exists()
        connection = self._raw_connection()
        try:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
            if mode is None or str(mode[0]).lower() != "wal":
                raise FGSReplayStorageError("SQLite WAL mode is unavailable")
            connection.execute("BEGIN IMMEDIATE")
            if not self._tables(connection):
                if self._pragma(connection, "application_id") != 0:
                    raise FGSReplayIntegrityError(
                        "empty replay database has unexpected application_id"
                    )
                if self._pragma(connection, "user_version") != 0:
                    raise FGSReplayIntegrityError(
                        "empty replay database has unexpected schema version"
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
            raise FGSReplayIntegrityError("replay database path changed type")
        connection = self._raw_connection()
        try:
            self._verify_database(connection)
        except Exception:
            connection.close()
            raise
        return connection

    def _protect(self, record: UseRecordV2) -> bytes:
        plaintext = encode_replay_record(record)
        state = _state_code(record)
        try:
            protected = self._protection_backend.seal(
                plaintext,
                aad=_record_aad(record.identity, state, _session_id(record)),
            )
        except Exception as error:
            raise FGSReplayIntegrityError("replay record sealing failed") from error
        if not isinstance(protected, bytes) or not protected:
            raise FGSReplayIntegrityError(
                "replay protector returned an invalid record"
            )
        if len(protected) > MAX_PROTECTED_RECORD_BYTES:
            raise FGSReplayIntegrityError("protected replay record exceeds bounds")
        return protected

    def _decode_row(self, row: tuple[object, ...]) -> UseRecordV2:
        if len(row) != 9:
            raise FGSReplayIntegrityError("replay row has the wrong width")
        use_key, ctx, serial, ticket_digest = row[:4]
        state = _integer(row[4], "stored replay state")
        revision = _integer(row[5], "stored replay revision")
        protection_id, session_id, protected = row[6:]
        if state != revision or state not in (
            STATE_RESERVED,
            STATE_PENDING,
            STATE_ACTIVE,
            STATE_EXPIRED,
        ):
            raise FGSReplayIntegrityError("stored replay state is invalid")
        identity = TicketUseIdentity(
            ctx=_fixed(ctx, 32, "stored ctx"),  # type: ignore[arg-type]
            serial=_fixed(serial, 16, "stored serial"),  # type: ignore[arg-type]
            ticket_digest=_fixed(  # type: ignore[arg-type]
                ticket_digest,
                32,
                "stored ticket_digest",
            ),
        )
        if _fixed(use_key, 32, "stored use_key") != identity.use_key:  # type: ignore[arg-type]
            raise FGSReplayIntegrityError("stored replay use_key mismatch")
        if protection_id != self._protection_id:
            raise FGSReplayIntegrityError("replay protection identity mismatch")
        if session_id is not None:
            session_id = _fixed(session_id, 32, "stored session_id")  # type: ignore[arg-type]
        if not isinstance(protected, bytes) or not protected:
            raise FGSReplayIntegrityError("protected replay record is invalid")
        if len(protected) > MAX_PROTECTED_RECORD_BYTES:
            raise FGSReplayIntegrityError("protected replay record exceeds bounds")
        try:
            plaintext = self._protection_backend.open(
                protected,
                aad=_record_aad(identity, state, session_id),
            )
        except Exception as error:
            raise FGSReplayIntegrityError(
                "replay record authentication failed"
            ) from error
        if not isinstance(plaintext, bytes) or not plaintext:
            raise FGSReplayIntegrityError(
                "replay protector returned invalid plaintext"
            )
        try:
            record = decode_replay_record(plaintext)
        except Exception as error:
            raise FGSReplayIntegrityError("stored replay record is invalid") from error
        expected = (
            identity,
            state,
            session_id,
        )
        actual = (
            record.identity,
            _state_code(record),
            _session_id(record),
        )
        if actual != expected:
            raise FGSReplayIntegrityError("replay row and protected record differ")
        return record

    def _select_where(
        self,
        connection: sqlite3.Connection,
        clause: str,
        value: bytes,
    ) -> UseRecordV2 | None:
        if clause not in {"use_key", "session_id"}:
            raise ValueError("unsupported replay lookup column")
        row = connection.execute(
            "SELECT use_key, ctx, serial, ticket_digest, state, revision, "
            "protection_id, session_id, protected_record "
            f"FROM fgs_replay_records WHERE {clause} = ?",
            (value,),
        ).fetchone()
        return None if row is None else self._decode_row(row)

    def _check_identity_bindings(
        self,
        connection: sqlite3.Connection,
        identity: TicketUseIdentity,
    ) -> tuple[bytes, UseRecordV2 | None]:
        if not isinstance(identity, TicketUseIdentity):
            raise TypeError("identity must be a TicketUseIdentity")
        use_key = identity.use_key
        for columns, values, failure in (
            (
                "ctx = ? AND ticket_digest = ?",
                (identity.ctx, identity.ticket_digest),
                "ticket digest is bound to another serial",
            ),
            (
                "ctx = ? AND serial = ?",
                (identity.ctx, identity.serial),
                "ticket serial is bound to another digest",
            ),
        ):
            row = connection.execute(
                "SELECT use_key FROM fgs_replay_records WHERE " + columns,
                values,
            ).fetchone()
            if row is not None and row[0] != use_key:
                raise IdentityConflict(failure)
        existing = self._select_where(connection, "use_key", use_key)
        if existing is not None and existing.identity != identity:
            raise IdentityConflict("use-key collision or inconsistent identity")
        return use_key, existing

    def _insert(self, connection: sqlite3.Connection, record: UseRecordV2) -> None:
        state = _state_code(record)
        protected = self._protect(record)
        connection.execute(
            "INSERT INTO fgs_replay_records "
            "(use_key, ctx, serial, ticket_digest, state, revision, "
            "protection_id, session_id, protected_record) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.identity.use_key,
                record.identity.ctx,
                record.identity.serial,
                record.identity.ticket_digest,
                state,
                state,
                self._protection_id,
                _session_id(record),
                protected,
            ),
        )

    def _replace(self, connection: sqlite3.Connection, record: GrantRecordV2) -> None:
        state = _state_code(record)
        protected = self._protect(record)
        cursor = connection.execute(
            "UPDATE fgs_replay_records SET state = ?, revision = ?, "
            "session_id = ?, protected_record = ? WHERE use_key = ?",
            (
                state,
                state,
                record.session_id,
                protected,
                record.identity.use_key,
            ),
        )
        if cursor.rowcount != 1:
            raise FGSReplayStorageError("replay transition changed wrong row count")

    def reserve(
        self,
        identity: TicketUseIdentity,
        *,
        attempt_id: bytes,
        request_digest: bytes,
        serving_context_digest: bytes,
        reserved_at: int,
        lease_deadline: int,
        revocation_generation: int,
    ) -> ReserveResultV2:
        candidate = ReservationV2(
            identity=identity,
            attempt_id=attempt_id,
            request_digest=request_digest,
            serving_context_digest=serving_context_digest,
            reserved_at=reserved_at,
            lease_deadline=lease_deadline,
            revocation_generation=revocation_generation,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            _, existing = self._check_identity_bindings(connection, identity)
            if existing is None:
                self._insert(connection, candidate)
                connection.execute("COMMIT")
                return ReserveResultV2(ReserveDispositionV2.NEW, candidate)
            if (
                existing.attempt_id == candidate.attempt_id
                and existing.request_digest == candidate.request_digest
            ):
                disposition = (
                    ReserveDispositionV2.EXISTING_RESERVATION
                    if isinstance(existing, ReservationV2)
                    else ReserveDispositionV2.EXISTING_GRANT
                )
                connection.execute("COMMIT")
                return ReserveResultV2(disposition, existing)
            raise TicketUnavailable("ticket belongs to another access attempt")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def commit_grant(
        self,
        identity: TicketUseIdentity,
        *,
        attempt_id: bytes,
        request_digest: bytes,
        transcript_digest: bytes,
        session_id: bytes,
        response_digest: bytes,
        sealed_response: bytes,
        sealed_session_state: bytes,
        serving_context_digest: bytes,
        fgs_id: bytes,
        revocation_generation: int,
        consumed_at: int,
        activation_deadline: int,
        session_expiry: int,
        retention_deadline: int,
    ) -> GrantRecordV2:
        candidate = GrantRecordV2(
            state=GrantStateV2.CONSUMED_PENDING_CONFIRM,
            identity=identity,
            attempt_id=attempt_id,
            request_digest=request_digest,
            transcript_digest=transcript_digest,
            session_id=session_id,
            response_digest=response_digest,
            sealed_response=sealed_response,
            sealed_session_state=sealed_session_state,
            serving_context_digest=serving_context_digest,
            fgs_id=fgs_id,
            revocation_generation=revocation_generation,
            consumed_at=consumed_at,
            activation_deadline=activation_deadline,
            session_expiry=session_expiry,
            retention_deadline=retention_deadline,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            use_key, existing = self._check_identity_bindings(connection, identity)
            if existing is None:
                raise ReservationNotFound("cannot commit an unreserved ticket")
            if isinstance(existing, GrantRecordV2):
                if _commit_identity(existing) == _commit_identity(candidate):
                    connection.execute("COMMIT")
                    return existing
                raise InvalidTransition("consumed ticket cannot change grant")
            session_owner = connection.execute(
                "SELECT use_key FROM fgs_replay_records WHERE session_id = ?",
                (candidate.session_id,),
            ).fetchone()
            if session_owner is not None and session_owner[0] != use_key:
                raise IdentityConflict("session ID belongs to another ticket")
            if (
                existing.attempt_id != candidate.attempt_id
                or existing.request_digest != candidate.request_digest
                or existing.serving_context_digest
                != candidate.serving_context_digest
                or existing.revocation_generation > candidate.revocation_generation
            ):
                raise ReservationNotFound("reservation belongs to another request")
            if candidate.consumed_at < existing.reserved_at:
                raise InvalidTransition("grant predates reservation")
            if candidate.consumed_at > existing.lease_deadline:
                raise InvalidTransition("reservation lease expired before commit")
            self._replace(connection, candidate)
            connection.execute("COMMIT")
            return candidate
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def activate_session(
        self,
        identity: TicketUseIdentity,
        *,
        attempt_id: bytes,
        request_digest: bytes,
        session_id: bytes,
        response_digest: bytes,
        client_confirmation_digest: bytes,
        activated_at: int,
    ) -> ActivateResultV2:
        canonical_attempt = _fixed(attempt_id, 32, "attempt_id")
        canonical_request = _fixed(request_digest, 32, "request_digest")
        canonical_session = _fixed(session_id, 32, "session_id")
        canonical_response = _fixed(response_digest, 32, "response_digest")
        canonical_confirmation = _fixed(
            client_confirmation_digest,
            32,
            "client_confirmation_digest",
        )
        canonical_time = _integer(activated_at, "activated_at")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            _, existing = self._check_identity_bindings(connection, identity)
            if existing is None or isinstance(existing, ReservationV2):
                raise ReservationNotFound("no committed grant exists")
            if (
                existing.attempt_id,
                existing.request_digest,
                existing.session_id,
                existing.response_digest,
            ) != (
                canonical_attempt,
                canonical_request,
                canonical_session,
                canonical_response,
            ):
                raise InvalidTransition("activation belongs to another grant")
            if existing.state is GrantStateV2.CONSUMED_EXPIRED:
                raise InvalidTransition("expired grant cannot activate")
            if existing.state is GrantStateV2.CONSUMED_ACTIVE:
                if existing.client_confirmation_digest != canonical_confirmation:
                    raise InvalidTransition("active grant confirmation cannot change")
                connection.execute("COMMIT")
                return ActivateResultV2(
                    ActivateDispositionV2.EXISTING_ACTIVE,
                    existing,
                )
            if canonical_time > existing.activation_deadline:
                raise InvalidTransition("activation deadline has passed")
            active = replace(
                existing,
                state=GrantStateV2.CONSUMED_ACTIVE,
                client_confirmation_digest=canonical_confirmation,
                activated_at=canonical_time,
            )
            self._replace(connection, active)
            connection.execute("COMMIT")
            return ActivateResultV2(ActivateDispositionV2.NEW, active)
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def activate(self, *args: object, **kwargs: object) -> GrantRecordV2:
        return self.activate_session(*args, **kwargs).record  # type: ignore[arg-type]

    def expire(
        self,
        identity: TicketUseIdentity,
        *,
        expired_at: int,
        reason: str,
    ) -> GrantRecordV2:
        canonical_time = _integer(expired_at, "expired_at")
        canonical_reason = _reason(reason)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            _, existing = self._check_identity_bindings(connection, identity)
            if existing is None or isinstance(existing, ReservationV2):
                raise InvalidTransition("only a committed grant may expire")
            if existing.state is GrantStateV2.CONSUMED_EXPIRED:
                connection.execute("COMMIT")
                return existing
            deadline = (
                existing.activation_deadline
                if existing.state is GrantStateV2.CONSUMED_PENDING_CONFIRM
                else existing.session_expiry
            )
            if canonical_time <= deadline:
                raise InvalidTransition("grant deadline has not passed")
            expired = replace(
                existing,
                state=GrantStateV2.CONSUMED_EXPIRED,
                expired_at=canonical_time,
                expiry_reason=canonical_reason,
            )
            self._replace(connection, expired)
            connection.execute("COMMIT")
            return expired
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def terminate(
        self,
        identity: TicketUseIdentity,
        *,
        terminated_at: int,
        reason: str,
    ) -> GrantRecordV2:
        canonical_time = _integer(terminated_at, "terminated_at")
        canonical_reason = _reason(reason)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            _, existing = self._check_identity_bindings(connection, identity)
            if existing is None or isinstance(existing, ReservationV2):
                raise InvalidTransition("only a committed grant may terminate")
            if existing.state is GrantStateV2.CONSUMED_EXPIRED:
                connection.execute("COMMIT")
                return existing
            earliest = (
                existing.consumed_at
                if existing.state is GrantStateV2.CONSUMED_PENDING_CONFIRM
                else existing.activated_at
            )
            if earliest is None or canonical_time < earliest:
                raise InvalidTransition("termination predates committed state")
            expired = replace(
                existing,
                state=GrantStateV2.CONSUMED_EXPIRED,
                expired_at=canonical_time,
                expiry_reason=canonical_reason,
            )
            self._replace(connection, expired)
            connection.execute("COMMIT")
            return expired
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def abort_reservation(
        self,
        identity: TicketUseIdentity,
        *,
        attempt_id: bytes,
        request_digest: bytes,
        evidence: ReservationAbortEvidenceV2,
    ) -> None:
        canonical_attempt = _fixed(attempt_id, 32, "attempt_id")
        canonical_request = _fixed(request_digest, 32, "request_digest")
        if not isinstance(evidence, ReservationAbortEvidenceV2):
            raise TypeError("evidence must be ReservationAbortEvidenceV2")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            use_key, existing = self._check_identity_bindings(connection, identity)
            if existing is None:
                raise ReservationNotFound("cannot abort an unreserved ticket")
            if isinstance(existing, GrantRecordV2):
                raise InvalidTransition("consumed ticket cannot be released")
            if (
                existing.attempt_id != canonical_attempt
                or existing.request_digest != canonical_request
            ):
                raise ReservationNotFound("reservation belongs to another request")
            cursor = connection.execute(
                "DELETE FROM fgs_replay_records WHERE use_key = ?",
                (use_key,),
            )
            if cursor.rowcount != 1:
                raise FGSReplayStorageError("abort changed wrong row count")
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def lookup(self, identity: TicketUseIdentity) -> UseRecordV2 | None:
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            _, record = self._check_identity_bindings(connection, identity)
            connection.execute("COMMIT")
            return record
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def lookup_session(self, session_id: bytes) -> GrantRecordV2 | None:
        canonical_session = _fixed(session_id, 32, "session_id")
        connection = self._connect()
        try:
            record = self._select_where(
                connection,
                "session_id",
                canonical_session,
            )
            if record is None:
                return None
            if not isinstance(record, GrantRecordV2):
                raise InvalidTransition("session index has no committed grant")
            if record.session_id != canonical_session:
                raise IdentityConflict("session index binding mismatch")
            return record
        finally:
            connection.close()

    def __len__(self) -> int:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT COUNT(*) FROM fgs_replay_records"
            ).fetchone()
            if row is None:
                raise FGSReplayStorageError("replay count is unavailable")
            return int(row[0])
        finally:
            connection.close()


def sqlite_fgs_replay_manifest() -> dict[str, object]:
    return {
        "format": "PQ-SAT-FGS-REPLAY-SQLITE-v0.2",
        "application_id": f"0x{APPLICATION_ID:08x}",
        "schema_version": SCHEMA_VERSION,
        "journal_mode": "WAL",
        "synchronous": "FULL",
        "states": [
            "RESERVED",
            "CONSUMED_PENDING_CONFIRM",
            "CONSUMED_ACTIVE",
            "CONSUMED_EXPIRED",
        ],
        "claims": {
            "single_host_cross_process_linearizable_reference": True,
            "restart_durable_reference": True,
            "record_protection_backend_boundary": True,
            "exact_m2_and_sealed_session_state_persisted": True,
            "session_index_unique": True,
            "production_record_protection_instantiated": False,
            "hostile_filesystem_protection": False,
            "rollback_resistance": False,
            "physical_power_loss_tested": False,
            "distributed": False,
            "production_ready": False,
        },
    }
