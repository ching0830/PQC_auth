"""Single-host SQLite reference store for UE access wallet state.

SQLite supplies the atomic transaction and restart boundary.  A separate
backend must protect each canonical record before it reaches SQLite.  This
module does not claim hostile-filesystem protection, rollback resistance,
secure erasure, physical-power-loss evidence, or production key management.
"""

from __future__ import annotations

import json
import os
import sqlite3
import struct
from dataclasses import fields
from pathlib import Path
from typing import Mapping, Protocol

from pq_sat_auth.identities import TicketUseIdentity

from ..access import (
    DIGEST_BYTES,
    REFERENCE_PROOF_SUITE_REGISTRY,
    REFERENCE_SUITE_REGISTRY,
    ProofLimitsV2,
    SuiteLimitsV2,
    decode_session_activate,
)
from ..processor import (
    AccessConfigurationSnapshotV2,
    ChannelBindingPolicyV2,
)
from ..ue import UEAccessAttemptStateV2, UEAcceptedSessionV2
from ..wallet import (
    UEWalletRecordV2,
    UEWalletStateV2,
    UEWalletTransitionKindV2,
    UEWalletTransitionV2,
    ue_wallet_checkpoint_manifest,
)


APPLICATION_ID = 0x50515357
SCHEMA_VERSION = 2
RECORD_FORMAT = "PQ-SAT-UE-WALLET-RECORD-v0.2"
RECORD_AAD_LABEL = b"PQ-SAT/UE-WALLET-RECORD-AAD/v0.2"
MAX_RECORD_BYTES = 2 * 1024 * 1024
MAX_PROTECTED_RECORD_BYTES = MAX_RECORD_BYTES + 256 * 1024
PRODUCTION_READY = False

_SCHEMA_SQL = """CREATE TABLE ue_wallet_records (
    use_key BLOB PRIMARY KEY NOT NULL
        CHECK(typeof(use_key) = 'blob' AND length(use_key) = 32),
    state INTEGER NOT NULL CHECK(state IN (1, 2)),
    revision INTEGER NOT NULL CHECK(revision IN (1, 2)),
    protection_id TEXT NOT NULL
        CHECK(typeof(protection_id) = 'text'
              AND length(protection_id) BETWEEN 1 AND 128),
    protected_record BLOB NOT NULL
        CHECK(typeof(protected_record) = 'blob'
              AND length(protected_record) BETWEEN 1 AND 2359296),
    CHECK((state = 1 AND revision = 1)
          OR (state = 2 AND revision = 2))
) WITHOUT ROWID"""

_CONFIG_BYTES_FIELDS = frozenset(
    {
        "system_config_digest",
        "initialization_configuration_digest",
        "ctx",
        "access_profile_digest",
        "access_pp_digest",
        "fgs_id",
        "fgs_auth_key_id",
        "issuer_verification_key_id",
        "serving_context_digest",
        "authorization_digest",
        "acceptance_domain_digest",
    }
)
_CONFIG_TUPLE_FIELDS = frozenset(
    {"allowed_suite_ids", "allowed_proof_suite_ids"}
)
_CONFIG_ENUM_FIELDS = frozenset({"channel_binding_policy"})
_CONFIG_FIELD_NAMES = tuple(item.name for item in fields(AccessConfigurationSnapshotV2))


class UEWalletError(RuntimeError):
    pass


class UEWalletStorageError(UEWalletError):
    pass


class UEWalletIntegrityError(UEWalletError):
    pass


class UEWalletConflictError(UEWalletError):
    pass


class UEWalletRecordProtectionV2(Protocol):
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
    return value


def _mapping(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) for key in value
    ):
        raise TypeError(f"{name} must be a string-keyed object")
    return value


def _exact_keys(value: dict[str, object], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise ValueError(f"{name} has unknown or missing fields")


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


def _canonical_json(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _configuration_to_object(
    configuration: AccessConfigurationSnapshotV2,
) -> dict[str, object]:
    configuration.validate()
    output: dict[str, object] = {}
    for name in _CONFIG_FIELD_NAMES:
        value = getattr(configuration, name)
        if name in _CONFIG_BYTES_FIELDS:
            output[name] = _hex(value)
        elif name in _CONFIG_TUPLE_FIELDS:
            output[name] = list(value)
        elif name in _CONFIG_ENUM_FIELDS:
            output[name] = int(value)
        else:
            output[name] = value
    return output


def _configuration_from_object(value: object) -> AccessConfigurationSnapshotV2:
    item = _mapping(value, "configuration")
    _exact_keys(item, set(_CONFIG_FIELD_NAMES), "configuration")
    arguments: dict[str, object] = {}
    for name in _CONFIG_FIELD_NAMES:
        field_value = item[name]
        if name in _CONFIG_BYTES_FIELDS:
            arguments[name] = _unhex(field_value, f"configuration {name}")
        elif name in _CONFIG_TUPLE_FIELDS:
            if not isinstance(field_value, list):
                raise TypeError(f"configuration {name} must be a list")
            arguments[name] = tuple(
                _integer(entry, f"configuration {name} entry")
                for entry in field_value
            )
        elif name in _CONFIG_ENUM_FIELDS:
            arguments[name] = ChannelBindingPolicyV2(
                _integer(field_value, f"configuration {name}")
            )
        else:
            arguments[name] = _integer(field_value, f"configuration {name}")
    configuration = AccessConfigurationSnapshotV2(**arguments)  # type: ignore[arg-type]
    configuration.validate()
    return configuration


def _attempt_to_object(attempt: UEAccessAttemptStateV2) -> dict[str, object]:
    attempt.validate()
    return {
        "attempt_id": _hex(attempt.attempt_id),
        "configuration": _configuration_to_object(attempt.configuration),
        "created_at": attempt.created_at,
        "request_bytes": _hex(attempt.request_bytes),
        "request_digest": _hex(attempt.request_digest),
        "ticket_expires_at": attempt.ticket_expires_at,
        "ue_kem_secret_key": _hex(attempt.ue_kem_secret_key),
    }


def _attempt_from_object(value: object) -> UEAccessAttemptStateV2:
    item = _mapping(value, "attempt")
    _exact_keys(
        item,
        {
            "attempt_id",
            "configuration",
            "created_at",
            "request_bytes",
            "request_digest",
            "ticket_expires_at",
            "ue_kem_secret_key",
        },
        "attempt",
    )
    attempt = UEAccessAttemptStateV2(
        request_bytes=_unhex(item["request_bytes"], "request_bytes"),
        configuration=_configuration_from_object(item["configuration"]),
        request_digest=_unhex(item["request_digest"], "request_digest"),
        attempt_id=_unhex(item["attempt_id"], "attempt_id"),
        ticket_expires_at=_integer(
            item["ticket_expires_at"],
            "ticket_expires_at",
        ),
        created_at=_integer(item["created_at"], "created_at"),
        ue_kem_secret_key=_unhex(
            item["ue_kem_secret_key"],
            "ue_kem_secret_key",
        ),
    )
    attempt.validate()
    return attempt


def _session_to_object(session: UEAcceptedSessionV2) -> dict[str, object]:
    session.validate()
    return {
        "acceptance_domain_digest": _hex(session.acceptance_domain_digest),
        "accepted_at": session.accepted_at,
        "activation_bytes": _hex(session.activation_bytes),
        "activation_deadline": session.activation_deadline,
        "application_key": _hex(session.application_key),
        "attempt_id": _hex(session.attempt_id),
        "exporter_key": _hex(session.exporter_key),
        "identity": {
            "ctx": _hex(session.identity.ctx),
            "serial": _hex(session.identity.serial),
            "ticket_digest": _hex(session.identity.ticket_digest),
        },
        "request_digest": _hex(session.request_digest),
        "response_digest": _hex(session.response_digest),
        "session_expiry": session.session_expiry,
        "session_id": _hex(session.session_id),
        "suite_id": session.suite_id,
        "system_config_digest": _hex(session.system_config_digest),
        "transcript_digest": _hex(session.transcript_digest),
    }


def _session_from_object(
    value: object,
    suite_registry: Mapping[int, SuiteLimitsV2],
) -> UEAcceptedSessionV2:
    item = _mapping(value, "session")
    _exact_keys(
        item,
        {
            "acceptance_domain_digest",
            "accepted_at",
            "activation_bytes",
            "activation_deadline",
            "application_key",
            "attempt_id",
            "exporter_key",
            "identity",
            "request_digest",
            "response_digest",
            "session_expiry",
            "session_id",
            "suite_id",
            "system_config_digest",
            "transcript_digest",
        },
        "session",
    )
    identity_item = _mapping(item["identity"], "session identity")
    _exact_keys(
        identity_item,
        {"ctx", "serial", "ticket_digest"},
        "session identity",
    )
    activation_bytes = _unhex(item["activation_bytes"], "activation_bytes")
    session = UEAcceptedSessionV2(
        suite_id=_integer(item["suite_id"], "suite_id"),
        identity=TicketUseIdentity(
            ctx=_unhex(identity_item["ctx"], "identity ctx"),
            serial=_unhex(identity_item["serial"], "identity serial"),
            ticket_digest=_unhex(
                identity_item["ticket_digest"],
                "identity ticket_digest",
            ),
        ),
        system_config_digest=_unhex(
            item["system_config_digest"],
            "system_config_digest",
        ),
        acceptance_domain_digest=_unhex(
            item["acceptance_domain_digest"],
            "acceptance_domain_digest",
        ),
        request_digest=_unhex(item["request_digest"], "request_digest"),
        attempt_id=_unhex(item["attempt_id"], "attempt_id"),
        transcript_digest=_unhex(
            item["transcript_digest"],
            "transcript_digest",
        ),
        response_digest=_unhex(item["response_digest"], "response_digest"),
        session_id=_unhex(item["session_id"], "session_id"),
        accepted_at=_integer(item["accepted_at"], "accepted_at"),
        activation_deadline=_integer(
            item["activation_deadline"],
            "activation_deadline",
        ),
        session_expiry=_integer(item["session_expiry"], "session_expiry"),
        activation=decode_session_activate(activation_bytes, suite_registry),
        activation_bytes=activation_bytes,
        application_key=_unhex(item["application_key"], "application_key"),
        exporter_key=_unhex(item["exporter_key"], "exporter_key"),
    )
    session.validate()
    return session


def encode_wallet_record(
    record: UEWalletRecordV2,
    *,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
    proof_registry: Mapping[
        int, ProofLimitsV2
    ] = REFERENCE_PROOF_SUITE_REGISTRY,
) -> bytes:
    record.validate(
        suite_registry=suite_registry,
        proof_registry=proof_registry,
    )
    value: dict[str, object] = {
        "attempt": _attempt_to_object(record.attempt),
        "format": RECORD_FORMAT,
        "response_bytes": (
            None if record.response_bytes is None else _hex(record.response_bytes)
        ),
        "revision": record.revision,
        "session": (
            None if record.session is None else _session_to_object(record.session)
        ),
        "state": record.state.name,
    }
    encoded = _canonical_json(value)
    if len(encoded) > MAX_RECORD_BYTES:
        raise ValueError("wallet record exceeds the canonical size bound")
    return encoded


def decode_wallet_record(
    encoded: bytes,
    *,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
    proof_registry: Mapping[
        int, ProofLimitsV2
    ] = REFERENCE_PROOF_SUITE_REGISTRY,
) -> UEWalletRecordV2:
    if not isinstance(encoded, bytes) or not encoded:
        raise TypeError("wallet record must be non-empty bytes")
    if len(encoded) > MAX_RECORD_BYTES:
        raise UEWalletIntegrityError("wallet record exceeds the size bound")
    try:
        value = json.loads(encoded.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise UEWalletIntegrityError("wallet record is not canonical JSON") from error
    item = _mapping(value, "wallet record")
    _exact_keys(
        item,
        {"attempt", "format", "response_bytes", "revision", "session", "state"},
        "wallet record",
    )
    if item["format"] != RECORD_FORMAT:
        raise UEWalletIntegrityError("wallet record format mismatch")
    try:
        state = UEWalletStateV2[item["state"]]  # type: ignore[index]
    except (KeyError, TypeError) as error:
        raise UEWalletIntegrityError("wallet record state is unknown") from error
    response_value = item["response_bytes"]
    session_value = item["session"]
    record = UEWalletRecordV2(
        state=state,
        revision=_integer(item["revision"], "wallet revision"),
        attempt=_attempt_from_object(item["attempt"]),
        response_bytes=(
            None
            if response_value is None
            else _unhex(response_value, "response_bytes")
        ),
        session=(
            None
            if session_value is None
            else _session_from_object(session_value, suite_registry)
        ),
    )
    record.validate(
        suite_registry=suite_registry,
        proof_registry=proof_registry,
    )
    if encode_wallet_record(
        record,
        suite_registry=suite_registry,
        proof_registry=proof_registry,
    ) != encoded:
        raise UEWalletIntegrityError("wallet record encoding is non-canonical")
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


def _record_aad(use_key: bytes, state: UEWalletStateV2, revision: int) -> bytes:
    return b"".join(
        (
            RECORD_AAD_LABEL,
            _fixed(use_key, DIGEST_BYTES, "use_key"),
            struct.pack(">HQ", int(state), _integer(revision, "revision")),
        )
    )


def _normalized_sql(value: str) -> str:
    return "".join(value.split())


class SQLiteUEWalletStoreV2:
    """Per-operation SQLite connections with FULL synchronous WAL commits."""

    durable_reference = True
    distributed = False
    production_ready = False

    def __init__(
        self,
        path: str | os.PathLike[str],
        protection_backend: UEWalletRecordProtectionV2,
        *,
        busy_timeout_ms: int = 5_000,
        suite_registry: Mapping[
            int, SuiteLimitsV2
        ] = REFERENCE_SUITE_REGISTRY,
        proof_registry: Mapping[
            int, ProofLimitsV2
        ] = REFERENCE_PROOF_SUITE_REGISTRY,
    ) -> None:
        candidate = Path(path)
        if not candidate.is_absolute():
            raise ValueError("wallet database path must be absolute")
        if not candidate.parent.is_dir():
            raise ValueError("wallet database parent must exist")
        if candidate.exists() and (candidate.is_symlink() or not candidate.is_file()):
            raise ValueError("wallet database must be a regular non-symlink file")
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
        self._suite_registry = suite_registry
        self._proof_registry = proof_registry
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
    def _application_id(connection: sqlite3.Connection) -> int:
        row = connection.execute("PRAGMA application_id").fetchone()
        if row is None:
            raise UEWalletStorageError("SQLite application_id is unavailable")
        return int(row[0])

    @staticmethod
    def _user_version(connection: sqlite3.Connection) -> int:
        row = connection.execute("PRAGMA user_version").fetchone()
        if row is None:
            raise UEWalletStorageError("SQLite user_version is unavailable")
        return int(row[0])

    @staticmethod
    def _tables(connection: sqlite3.Connection) -> dict[str, str]:
        rows = connection.execute(
            "SELECT name, sql FROM sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        return {str(name): str(sql) for name, sql in rows}

    def _verify_database(self, connection: sqlite3.Connection) -> None:
        if self._application_id(connection) != APPLICATION_ID:
            raise UEWalletIntegrityError("wallet database application_id mismatch")
        if self._user_version(connection) != SCHEMA_VERSION:
            raise UEWalletIntegrityError("wallet database schema version mismatch")
        tables = self._tables(connection)
        if set(tables) != {"ue_wallet_records"}:
            raise UEWalletIntegrityError("wallet database table set mismatch")
        if _normalized_sql(tables["ue_wallet_records"]) != _normalized_sql(
            _SCHEMA_SQL
        ):
            raise UEWalletIntegrityError("wallet database schema mismatch")
        mode = connection.execute("PRAGMA journal_mode").fetchone()
        if mode is None or str(mode[0]).lower() != "wal":
            raise UEWalletIntegrityError("wallet database is not in WAL mode")
        synchronous = connection.execute("PRAGMA synchronous").fetchone()
        if synchronous is None or int(synchronous[0]) != 2:
            raise UEWalletIntegrityError("wallet database is not FULL synchronous")

    def _initialize(self) -> None:
        existed = self._path.exists()
        connection = self._raw_connection()
        try:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
            if mode is None or str(mode[0]).lower() != "wal":
                raise UEWalletStorageError("SQLite WAL mode is unavailable")
            connection.execute("BEGIN IMMEDIATE")
            tables = self._tables(connection)
            if not tables:
                if self._application_id(connection) != 0:
                    raise UEWalletIntegrityError(
                        "empty wallet has unexpected application_id"
                    )
                if self._user_version(connection) != 0:
                    raise UEWalletIntegrityError(
                        "empty wallet has unexpected schema version"
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
            raise UEWalletIntegrityError("wallet database path changed type")
        connection = self._raw_connection()
        try:
            self._verify_database(connection)
        except Exception:
            connection.close()
            raise
        return connection

    def _protect(self, record: UEWalletRecordV2) -> bytes:
        plaintext = encode_wallet_record(
            record,
            suite_registry=self._suite_registry,
            proof_registry=self._proof_registry,
        )
        aad = _record_aad(
            self._record_use_key(record),
            record.state,
            record.revision,
        )
        try:
            protected = self._protection_backend.seal(plaintext, aad=aad)
        except Exception as error:
            raise UEWalletIntegrityError("wallet record sealing failed") from error
        if not isinstance(protected, bytes) or not protected:
            raise UEWalletIntegrityError(
                "wallet protector returned an invalid sealed record"
            )
        if len(protected) > MAX_PROTECTED_RECORD_BYTES:
            raise UEWalletIntegrityError("protected wallet record exceeds bounds")
        return protected

    def _decode_row(
        self,
        use_key: bytes,
        row: tuple[object, ...],
    ) -> UEWalletRecordV2:
        if len(row) != 4:
            raise UEWalletIntegrityError("wallet row has the wrong width")
        state_value = _integer(row[0], "stored wallet state")
        revision = _integer(row[1], "stored wallet revision")
        protection_id = row[2]
        protected = row[3]
        try:
            state = UEWalletStateV2(state_value)
        except ValueError as error:
            raise UEWalletIntegrityError("stored wallet state is unknown") from error
        if protection_id != self._protection_id:
            raise UEWalletIntegrityError("wallet protection identity mismatch")
        if not isinstance(protected, bytes) or not protected:
            raise UEWalletIntegrityError("protected wallet record is invalid")
        if len(protected) > MAX_PROTECTED_RECORD_BYTES:
            raise UEWalletIntegrityError("protected wallet record exceeds bounds")
        aad = _record_aad(use_key, state, revision)
        try:
            plaintext = self._protection_backend.open(protected, aad=aad)
        except Exception as error:
            raise UEWalletIntegrityError("wallet record authentication failed") from error
        if not isinstance(plaintext, bytes) or not plaintext:
            raise UEWalletIntegrityError("wallet protector returned invalid plaintext")
        try:
            record = decode_wallet_record(
                plaintext,
                suite_registry=self._suite_registry,
                proof_registry=self._proof_registry,
            )
        except Exception as error:
            raise UEWalletIntegrityError("wallet record validation failed") from error
        if (
            self._record_use_key(record) != use_key
            or int(record.state) != state_value
            or record.revision != revision
        ):
            raise UEWalletIntegrityError("wallet row and protected record differ")
        return record

    def _record_use_key(self, record: UEWalletRecordV2) -> bytes:
        return record.derive_use_key(
            suite_registry=self._suite_registry,
            proof_registry=self._proof_registry,
        )

    @staticmethod
    def _select(
        connection: sqlite3.Connection,
        use_key: bytes,
    ) -> tuple[object, ...] | None:
        row = connection.execute(
            "SELECT state, revision, protection_id, protected_record "
            "FROM ue_wallet_records WHERE use_key = ?",
            (use_key,),
        ).fetchone()
        return None if row is None else tuple(row)

    def load(self, use_key: bytes) -> UEWalletRecordV2 | None:
        canonical_use_key = _fixed(use_key, DIGEST_BYTES, "use_key")
        try:
            connection = self._connect()
            try:
                row = self._select(connection, canonical_use_key)
            finally:
                connection.close()
        except sqlite3.Error as error:
            raise UEWalletStorageError("wallet load failed") from error
        if row is None:
            return None
        return self._decode_row(canonical_use_key, row)

    def prepare(
        self,
        attempt: UEAccessAttemptStateV2,
    ) -> UEWalletTransitionV2:
        proposed = UEWalletRecordV2(
            state=UEWalletStateV2.PREPARED,
            revision=1,
            attempt=attempt,
        )
        proposed.validate(
            suite_registry=self._suite_registry,
            proof_registry=self._proof_registry,
        )
        protected = self._protect(proposed)
        use_key = self._record_use_key(proposed)
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            row = self._select(connection, use_key)
            if row is None:
                connection.execute(
                    "INSERT INTO ue_wallet_records "
                    "(use_key, state, revision, protection_id, protected_record) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        use_key,
                        int(proposed.state),
                        proposed.revision,
                        self._protection_id,
                        protected,
                    ),
                )
                result = UEWalletTransitionV2(
                    UEWalletTransitionKindV2.CREATED,
                    proposed,
                )
            else:
                existing = self._decode_row(use_key, row)
                if existing.attempt != proposed.attempt:
                    raise UEWalletConflictError(
                        "ticket already has a different wallet attempt"
                    )
                result = UEWalletTransitionV2(
                    UEWalletTransitionKindV2.EXISTING,
                    existing,
                )
            connection.execute("COMMIT")
            return result
        except sqlite3.Error as error:
            if connection is not None and connection.in_transaction:
                connection.execute("ROLLBACK")
            raise UEWalletStorageError("wallet prepare transaction failed") from error
        except Exception:
            if connection is not None and connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            if connection is not None:
                connection.close()

    def accept(
        self,
        attempt: UEAccessAttemptStateV2,
        response_bytes: bytes,
        session: UEAcceptedSessionV2,
    ) -> UEWalletTransitionV2:
        proposed = UEWalletRecordV2(
            state=UEWalletStateV2.ACCEPTED_PENDING_ACTIVATION,
            revision=2,
            attempt=attempt,
            response_bytes=response_bytes,
            session=session,
        )
        proposed.validate(
            suite_registry=self._suite_registry,
            proof_registry=self._proof_registry,
        )
        protected = self._protect(proposed)
        use_key = self._record_use_key(proposed)
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            row = self._select(connection, use_key)
            if row is None:
                raise UEWalletConflictError("wallet attempt was not prepared")
            existing = self._decode_row(use_key, row)
            if existing.attempt != proposed.attempt:
                raise UEWalletConflictError(
                    "wallet attempt differs from prepared state"
                )
            if existing.state is UEWalletStateV2.ACCEPTED_PENDING_ACTIVATION:
                if existing != proposed:
                    raise UEWalletConflictError(
                        "wallet already contains a different accepted session"
                    )
                result = UEWalletTransitionV2(
                    UEWalletTransitionKindV2.EXISTING,
                    existing,
                )
            elif existing.state is UEWalletStateV2.PREPARED:
                changed = connection.execute(
                    "UPDATE ue_wallet_records SET state = ?, revision = ?, "
                    "protection_id = ?, protected_record = ? "
                    "WHERE use_key = ? AND state = ? AND revision = ?",
                    (
                        int(proposed.state),
                        proposed.revision,
                        self._protection_id,
                        protected,
                        use_key,
                        int(UEWalletStateV2.PREPARED),
                        existing.revision,
                    ),
                )
                if changed.rowcount != 1:
                    raise UEWalletStorageError(
                        "wallet accepted transition lost serialization"
                    )
                result = UEWalletTransitionV2(
                    UEWalletTransitionKindV2.CREATED,
                    proposed,
                )
            else:
                raise UEWalletConflictError("wallet state cannot accept a response")
            connection.execute("COMMIT")
            return result
        except sqlite3.Error as error:
            if connection is not None and connection.in_transaction:
                connection.execute("ROLLBACK")
            raise UEWalletStorageError("wallet accept transaction failed") from error
        except Exception:
            if connection is not None and connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            if connection is not None:
                connection.close()

    def integrity_check(self) -> None:
        try:
            connection = self._connect()
            try:
                row = connection.execute("PRAGMA integrity_check").fetchone()
            finally:
                connection.close()
        except sqlite3.Error as error:
            raise UEWalletStorageError("wallet integrity check failed") from error
        if row != ("ok",):
            raise UEWalletIntegrityError("SQLite integrity check failed")


def sqlite_ue_wallet_manifest() -> dict[str, object]:
    manifest = ue_wallet_checkpoint_manifest()
    return {
        **manifest,
        "sqlite_profile": {
            "application_id": APPLICATION_ID,
            "schema_version": SCHEMA_VERSION,
            "journal_mode": "WAL",
            "synchronous": "FULL",
            "canonical_record_format": RECORD_FORMAT,
            "record_aad_domain": RECORD_AAD_LABEL.decode("ascii"),
            "maximum_record_bytes": MAX_RECORD_BYTES,
            "maximum_protected_record_bytes": MAX_PROTECTED_RECORD_BYTES,
        },
    }
