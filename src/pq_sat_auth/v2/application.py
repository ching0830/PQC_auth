"""First protected UE-to-FGS application record for access profile v0.2.

The module freezes record bytes, AAD, sequence zero, UE outbox ordering, and
mutually exclusive direct-delivery or durable-inbox FGS sinks.  It deliberately
does not instantiate a production AEAD or claim an exactly-once external side
effect.
"""

from __future__ import annotations

import hashlib
import struct
import threading
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Mapping, Protocol

from .access import (
    DIGEST_BYTES,
    REFERENCE_SUITE_REGISTRY,
    SESSION_ID_BYTES,
    SessionActivateV2,
    SuiteLimitsV2,
    decode_session_activate,
    derive_activation_digest,
    encode_session_activate,
)
from .activation import (
    ActivatedSessionCapabilityV2,
    ActivationDispositionV2,
    FGSActivationProcessorV2,
)
from .framing import (
    FrameTypeV2,
    ProtocolEncodingError,
    decode_frame_v2,
    decode_opaque_v2,
    encode_frame_v2,
    encode_opaque_v2,
    require_uint,
)
from .processor import AccessClockV2
from .ue import UEAcceptedSessionV2


FIRST_APPLICATION_SEQUENCE = 0
MAX_APPLICATION_PLAINTEXT_BYTES = 900_000
MAX_APPLICATION_RECEIPT_BYTES = 262_144
# Leaves room inside the global FrameV2 body bound for the largest registered
# SessionActivateV2 and both Opaque length fields.
MAX_APPLICATION_CIPHERTEXT_BYTES = 982_744
FIRST_APPLICATION_AAD_LABEL = b"PQ-SAT/FIRST-APPLICATION-AAD/v2"
FIRST_APPLICATION_NONCE_LABEL = b"PQ-SAT/FIRST-APPLICATION-NONCE/v2"
FIRST_APPLICATION_RECORD_LABEL = b"PQ-SAT/FIRST-APPLICATION-RECORD/v2"
FIRST_APPLICATION_PLAINTEXT_LABEL = b"PQ-SAT/FIRST-APPLICATION-PLAINTEXT/v2"
FIRST_APPLICATION_PREFIX = struct.Struct(">H32s32s32s32sQ")
PRODUCTION_READY = False


def _fixed(value: bytes, size: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    return value


def _plaintext(value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError("application plaintext must be bytes")
    if not value:
        raise ValueError("application plaintext must not be empty")
    if len(value) > MAX_APPLICATION_PLAINTEXT_BYTES:
        raise ValueError("application plaintext exceeds the v0.2 maximum")
    return value


def derive_first_application_plaintext_digest(plaintext: bytes) -> bytes:
    return hashlib.shake_256(
        FIRST_APPLICATION_PLAINTEXT_LABEL + _plaintext(plaintext)
    ).digest(DIGEST_BYTES)


@dataclass(frozen=True)
class FirstApplicationRecordV2:
    suite_id: int
    request_digest: bytes
    attempt_id: bytes
    session_id: bytes
    response_digest: bytes
    sequence_number: int
    activation_bytes: bytes
    ciphertext: bytes

    def validate(
        self,
        suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
    ) -> SessionActivateV2:
        require_uint(self.suite_id, 16, "suite_id")
        if self.suite_id not in suite_registry:
            raise ValueError("application record suite is not registered")
        for name in ("request_digest", "attempt_id", "response_digest"):
            _fixed(getattr(self, name), DIGEST_BYTES, name)
        _fixed(self.session_id, SESSION_ID_BYTES, "session_id")
        require_uint(self.sequence_number, 64, "sequence_number")
        if self.sequence_number != FIRST_APPLICATION_SEQUENCE:
            raise ValueError("first application record sequence must be zero")
        if not isinstance(self.activation_bytes, bytes) or not self.activation_bytes:
            raise ValueError("activation_bytes must be non-empty bytes")
        activation = decode_session_activate(self.activation_bytes, suite_registry)
        if encode_session_activate(activation, suite_registry) != self.activation_bytes:
            raise ValueError("embedded activation is non-canonical")
        bindings = (
            (activation.suite_id, self.suite_id),
            (activation.request_digest, self.request_digest),
            (activation.attempt_id, self.attempt_id),
            (activation.session_id, self.session_id),
            (activation.response_digest, self.response_digest),
        )
        if any(actual != expected for actual, expected in bindings):
            raise ValueError("embedded activation and record header differ")
        if not isinstance(self.ciphertext, bytes) or not self.ciphertext:
            raise ValueError("application ciphertext must be non-empty bytes")
        if len(self.ciphertext) > MAX_APPLICATION_CIPHERTEXT_BYTES:
            raise ValueError("application ciphertext exceeds the v0.2 maximum")
        return activation


def _encode_first_application_authenticated_header(
    record: FirstApplicationRecordV2,
    suite_registry: Mapping[int, SuiteLimitsV2],
) -> bytes:
    record.validate(suite_registry)
    return FIRST_APPLICATION_PREFIX.pack(
        record.suite_id,
        record.request_digest,
        record.attempt_id,
        record.session_id,
        record.response_digest,
        record.sequence_number,
    ) + encode_opaque_v2(record.activation_bytes)


def derive_first_application_aad(
    record: FirstApplicationRecordV2,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
) -> bytes:
    """Bind the exact flow, sequence, and client Finished, excluding ciphertext."""

    return FIRST_APPLICATION_AAD_LABEL + _encode_first_application_authenticated_header(
        record,
        suite_registry,
    )


def derive_first_application_nonce_context(
    suite_id: int,
    session_id: bytes,
    sequence_number: int = FIRST_APPLICATION_SEQUENCE,
) -> bytes:
    suite = require_uint(suite_id, 16, "suite_id")
    sequence = require_uint(sequence_number, 64, "sequence_number")
    if sequence != FIRST_APPLICATION_SEQUENCE:
        raise ValueError("first application record sequence must be zero")
    return hashlib.shake_256(
        FIRST_APPLICATION_NONCE_LABEL
        + struct.pack(">H", suite)
        + _fixed(session_id, SESSION_ID_BYTES, "session_id")
        + struct.pack(">Q", sequence)
    ).digest(DIGEST_BYTES)


def encode_first_application_record(
    record: FirstApplicationRecordV2,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
) -> bytes:
    header = _encode_first_application_authenticated_header(record, suite_registry)
    return encode_frame_v2(
        FrameTypeV2.FIRST_APPLICATION_RECORD,
        header + encode_opaque_v2(
            record.ciphertext,
            max_length=MAX_APPLICATION_CIPHERTEXT_BYTES,
        ),
    )


def decode_first_application_record(
    encoded: bytes,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
) -> FirstApplicationRecordV2:
    frame = decode_frame_v2(encoded)
    if frame.msg_type is not FrameTypeV2.FIRST_APPLICATION_RECORD:
        raise ProtocolEncodingError("frame is not a first application record")
    if len(frame.body) < FIRST_APPLICATION_PREFIX.size:
        raise ProtocolEncodingError("first application record prefix is truncated")
    values = FIRST_APPLICATION_PREFIX.unpack_from(frame.body)
    activation_bytes, offset = decode_opaque_v2(
        frame.body,
        FIRST_APPLICATION_PREFIX.size,
    )
    ciphertext, offset = decode_opaque_v2(
        frame.body,
        offset,
        max_length=MAX_APPLICATION_CIPHERTEXT_BYTES,
    )
    if offset != len(frame.body):
        raise ProtocolEncodingError("first application record has trailing bytes")
    record = FirstApplicationRecordV2(*values, activation_bytes, ciphertext)
    record.validate(suite_registry)
    return record


def derive_first_application_record_digest(
    record: FirstApplicationRecordV2,
    suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
) -> bytes:
    return hashlib.shake_256(
        FIRST_APPLICATION_RECORD_LABEL
        + encode_first_application_record(record, suite_registry)
    ).digest(DIGEST_BYTES)


class ApplicationProtectionBackendV2(Protocol):
    suite_id: int
    production_ready: bool

    def seal(
        self,
        key: bytes,
        *,
        nonce_context: bytes,
        aad: bytes,
        plaintext: bytes,
    ) -> bytes: ...

    def open(
        self,
        key: bytes,
        *,
        nonce_context: bytes,
        aad: bytes,
        ciphertext: bytes,
    ) -> bytes: ...


class FirstRecordOutboxStateV2(IntEnum):
    RESERVED = 1
    READY = 2


@dataclass(frozen=True)
class FirstRecordOutboxEntryV2:
    state: FirstRecordOutboxStateV2
    revision: int
    suite_id: int
    request_digest: bytes
    attempt_id: bytes
    session_id: bytes
    response_digest: bytes
    activation_digest: bytes
    plaintext_digest: bytes
    record_digest: bytes | None = None
    record_bytes: bytes | None = None

    @property
    def identity(self) -> tuple[object, ...]:
        return (
            self.suite_id,
            self.request_digest,
            self.attempt_id,
            self.session_id,
            self.response_digest,
            self.activation_digest,
            self.plaintext_digest,
        )

    def validate(
        self,
        suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
    ) -> None:
        if not isinstance(self.state, FirstRecordOutboxStateV2):
            raise TypeError("outbox state has the wrong type")
        require_uint(self.revision, 64, "outbox revision")
        expected_revision = {
            FirstRecordOutboxStateV2.RESERVED: 1,
            FirstRecordOutboxStateV2.READY: 2,
        }[self.state]
        if self.revision != expected_revision:
            raise ValueError("outbox state has the wrong revision")
        require_uint(self.suite_id, 16, "suite_id")
        if self.suite_id not in suite_registry:
            raise ValueError("outbox suite is not registered")
        for name in (
            "request_digest",
            "attempt_id",
            "response_digest",
            "activation_digest",
            "plaintext_digest",
        ):
            _fixed(getattr(self, name), DIGEST_BYTES, name)
        _fixed(self.session_id, SESSION_ID_BYTES, "session_id")
        if self.state is FirstRecordOutboxStateV2.RESERVED:
            if self.record_digest is not None or self.record_bytes is not None:
                raise ValueError("reserved outbox entry contains a ready record")
            return
        _fixed(self.record_digest, DIGEST_BYTES, "record_digest")  # type: ignore[arg-type]
        if not isinstance(self.record_bytes, bytes) or not self.record_bytes:
            raise ValueError("ready outbox entry lacks exact record bytes")
        record = decode_first_application_record(self.record_bytes, suite_registry)
        if encode_first_application_record(record, suite_registry) != self.record_bytes:
            raise ValueError("outbox record is non-canonical")
        activation = decode_session_activate(record.activation_bytes, suite_registry)
        bindings = (
            (record.suite_id, self.suite_id),
            (record.request_digest, self.request_digest),
            (record.attempt_id, self.attempt_id),
            (record.session_id, self.session_id),
            (record.response_digest, self.response_digest),
            (derive_activation_digest(activation, suite_registry), self.activation_digest),
            (derive_first_application_record_digest(record, suite_registry), self.record_digest),
        )
        if any(actual != expected for actual, expected in bindings):
            raise ValueError("ready outbox record differs from reservation")


class FirstRecordOutboxTransitionKindV2(Enum):
    CREATED = "created"
    EXISTING = "existing"


@dataclass(frozen=True)
class FirstRecordOutboxTransitionV2:
    kind: FirstRecordOutboxTransitionKindV2
    entry: FirstRecordOutboxEntryV2

    def validate(self) -> None:
        if not isinstance(self.kind, FirstRecordOutboxTransitionKindV2):
            raise TypeError("outbox transition kind has the wrong type")
        if not isinstance(self.entry, FirstRecordOutboxEntryV2):
            raise TypeError("outbox transition entry has the wrong type")
        self.entry.validate()


class FirstRecordOutboxStoreV2(Protocol):
    durable_reference: bool
    distributed: bool
    production_ready: bool

    def load(self, session_id: bytes) -> FirstRecordOutboxEntryV2 | None: ...

    def reserve(
        self,
        candidate: FirstRecordOutboxEntryV2,
    ) -> FirstRecordOutboxTransitionV2: ...

    def finalize(
        self,
        candidate: FirstRecordOutboxEntryV2,
        record_bytes: bytes,
    ) -> FirstRecordOutboxTransitionV2: ...


class FirstRecordOutboxConflictError(RuntimeError):
    pass


class UEFirstRecordDispositionV2(Enum):
    PREPARED_NEW = "prepared_new"
    PREPARED_RECOVERED = "prepared_recovered"
    REJECTED = "rejected"
    COMMIT_UNCERTAIN = "commit_uncertain"


@dataclass(frozen=True)
class UEFirstRecordProcessResultV2:
    accepted: bool
    disposition: UEFirstRecordDispositionV2
    failures: tuple[str, ...]
    entry: FirstRecordOutboxEntryV2 | None
    record: FirstApplicationRecordV2 | None
    record_bytes: bytes | None


class UEFirstApplicationRecordProcessorV2:
    """Persist an exact sequence-zero record before releasing wire bytes."""

    production_ready = False

    def __init__(
        self,
        *,
        outbox: FirstRecordOutboxStoreV2,
        clock: AccessClockV2,
        protection_backend: ApplicationProtectionBackendV2,
        suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
    ) -> None:
        self._outbox = outbox
        self._clock = clock
        self._protection_backend = protection_backend
        self._suite_registry = suite_registry

    @staticmethod
    def _result(
        disposition: UEFirstRecordDispositionV2,
        failure: str,
    ) -> UEFirstRecordProcessResultV2:
        return UEFirstRecordProcessResultV2(
            False,
            disposition,
            (failure,),
            None,
            None,
            None,
        )

    @staticmethod
    def _candidate(
        session: UEAcceptedSessionV2,
        plaintext_digest: bytes,
    ) -> FirstRecordOutboxEntryV2:
        return FirstRecordOutboxEntryV2(
            state=FirstRecordOutboxStateV2.RESERVED,
            revision=1,
            suite_id=session.suite_id,
            request_digest=session.request_digest,
            attempt_id=session.attempt_id,
            session_id=session.session_id,
            response_digest=session.response_digest,
            activation_digest=derive_activation_digest(session.activation),
            plaintext_digest=plaintext_digest,
        )

    def _ready_result(
        self,
        entry: FirstRecordOutboxEntryV2,
        disposition: UEFirstRecordDispositionV2,
    ) -> UEFirstRecordProcessResultV2:
        entry.validate(self._suite_registry)
        if entry.state is not FirstRecordOutboxStateV2.READY:
            raise ValueError("outbox did not return a ready record")
        assert entry.record_bytes is not None
        record = decode_first_application_record(
            entry.record_bytes,
            self._suite_registry,
        )
        return UEFirstRecordProcessResultV2(
            True,
            disposition,
            (),
            entry,
            record,
            entry.record_bytes,
        )

    def process(
        self,
        session: UEAcceptedSessionV2,
        plaintext: bytes,
    ) -> UEFirstRecordProcessResultV2:
        try:
            session.validate()
            content = _plaintext(plaintext)
            plaintext_digest = derive_first_application_plaintext_digest(content)
            candidate = self._candidate(session, plaintext_digest)
            candidate.validate(self._suite_registry)
            now = self._clock.now()
            require_uint(now, 64, "outbox time")
        except Exception as error:
            return self._result(
                UEFirstRecordDispositionV2.REJECTED,
                f"input:{type(error).__name__}",
            )
        if now > session.session_expiry:
            return self._result(
                UEFirstRecordDispositionV2.REJECTED,
                "session_expired",
            )

        try:
            existing = self._outbox.load(session.session_id)
        except Exception as error:
            return self._result(
                UEFirstRecordDispositionV2.COMMIT_UNCERTAIN,
                f"outbox_load:{type(error).__name__}",
            )
        if existing is not None:
            try:
                existing.validate(self._suite_registry)
                if existing.identity != candidate.identity:
                    raise FirstRecordOutboxConflictError(
                        "session already reserved for another first record"
                    )
                if existing.state is FirstRecordOutboxStateV2.READY:
                    return self._ready_result(
                        existing,
                        UEFirstRecordDispositionV2.PREPARED_RECOVERED,
                    )
                if now > session.activation_deadline:
                    return self._result(
                        UEFirstRecordDispositionV2.REJECTED,
                        "activation_deadline_expired",
                    )
            except FirstRecordOutboxConflictError:
                return self._result(
                    UEFirstRecordDispositionV2.REJECTED,
                    "outbox_conflict",
                )
            except Exception as error:
                return self._result(
                    UEFirstRecordDispositionV2.COMMIT_UNCERTAIN,
                    f"outbox_existing:{type(error).__name__}",
                )
        elif now > session.activation_deadline:
            return self._result(
                UEFirstRecordDispositionV2.REJECTED,
                "activation_deadline_expired",
            )

        try:
            reserved = self._outbox.reserve(candidate)
            reserved.validate()
            if reserved.entry.identity != candidate.identity:
                raise FirstRecordOutboxConflictError(
                    "outbox reservation changed identity"
                )
            if reserved.entry.state is FirstRecordOutboxStateV2.READY:
                return self._ready_result(
                    reserved.entry,
                    UEFirstRecordDispositionV2.PREPARED_RECOVERED,
                )
        except FirstRecordOutboxConflictError:
            return self._result(
                UEFirstRecordDispositionV2.REJECTED,
                "outbox_conflict",
            )
        except Exception as error:
            return self._result(
                UEFirstRecordDispositionV2.COMMIT_UNCERTAIN,
                f"outbox_reserve:{type(error).__name__}",
            )

        if getattr(self._protection_backend, "suite_id", None) != session.suite_id:
            return self._result(
                UEFirstRecordDispositionV2.REJECTED,
                "application_protection_suite_mismatch",
            )
        prototype = FirstApplicationRecordV2(
            suite_id=session.suite_id,
            request_digest=session.request_digest,
            attempt_id=session.attempt_id,
            session_id=session.session_id,
            response_digest=session.response_digest,
            sequence_number=FIRST_APPLICATION_SEQUENCE,
            activation_bytes=session.activation_bytes,
            ciphertext=b"placeholder",
        )
        try:
            aad = derive_first_application_aad(prototype, self._suite_registry)
            nonce_context = derive_first_application_nonce_context(
                session.suite_id,
                session.session_id,
            )
            ciphertext = self._protection_backend.seal(
                session.application_key,
                nonce_context=nonce_context,
                aad=aad,
                plaintext=content,
            )
            if not isinstance(ciphertext, bytes) or not ciphertext:
                raise TypeError("application protector returned invalid ciphertext")
            record = FirstApplicationRecordV2(
                suite_id=session.suite_id,
                request_digest=session.request_digest,
                attempt_id=session.attempt_id,
                session_id=session.session_id,
                response_digest=session.response_digest,
                sequence_number=FIRST_APPLICATION_SEQUENCE,
                activation_bytes=session.activation_bytes,
                ciphertext=ciphertext,
            )
            record_bytes = encode_first_application_record(
                record,
                self._suite_registry,
            )
        except Exception as error:
            return self._result(
                UEFirstRecordDispositionV2.REJECTED,
                f"application_protection:{type(error).__name__}",
            )

        try:
            committed = self._outbox.finalize(candidate, record_bytes)
            committed.validate()
            loaded = self._outbox.load(session.session_id)
            if loaded != committed.entry:
                raise ValueError("outbox read-back differs from commit output")
            return self._ready_result(
                committed.entry,
                (
                    UEFirstRecordDispositionV2.PREPARED_NEW
                    if committed.kind is FirstRecordOutboxTransitionKindV2.CREATED
                    else UEFirstRecordDispositionV2.PREPARED_RECOVERED
                ),
            )
        except FirstRecordOutboxConflictError:
            return self._result(
                UEFirstRecordDispositionV2.REJECTED,
                "outbox_conflict",
            )
        except Exception as error:
            return self._result(
                UEFirstRecordDispositionV2.COMMIT_UNCERTAIN,
                f"outbox_finalize:{type(error).__name__}",
            )


class DeliveryClaimDispositionV2(Enum):
    NEW = "new"
    EXISTING = "existing"


@dataclass(frozen=True)
class DeliveryClaimResultV2:
    disposition: DeliveryClaimDispositionV2
    session_id: bytes
    record_digest: bytes

    def validate(self) -> None:
        if not isinstance(self.disposition, DeliveryClaimDispositionV2):
            raise TypeError("delivery claim disposition has the wrong type")
        _fixed(self.session_id, SESSION_ID_BYTES, "session_id")
        _fixed(self.record_digest, DIGEST_BYTES, "record_digest")


class FirstApplicationDeliveryStoreV2(Protocol):
    durable: bool
    distributed: bool
    production_ready: bool

    def claim(
        self,
        session_id: bytes,
        record_digest: bytes,
    ) -> DeliveryClaimResultV2: ...


class FirstApplicationInboxStateV2(IntEnum):
    PENDING = 1
    COMPLETED = 2


@dataclass(frozen=True)
class FirstApplicationInboxEntryV2:
    state: FirstApplicationInboxStateV2
    revision: int
    session_id: bytes
    record_digest: bytes
    plaintext: bytes
    receipt: bytes | None = None

    def validate(self) -> None:
        if not isinstance(self.state, FirstApplicationInboxStateV2):
            raise TypeError("inbox state has the wrong type")
        require_uint(self.revision, 64, "inbox revision")
        if self.revision != int(self.state):
            raise ValueError("inbox state and revision differ")
        _fixed(self.session_id, SESSION_ID_BYTES, "session_id")
        _fixed(self.record_digest, DIGEST_BYTES, "record_digest")
        _plaintext(self.plaintext)
        if self.state is FirstApplicationInboxStateV2.PENDING:
            if self.receipt is not None:
                raise ValueError("pending inbox entry contains a receipt")
            return
        if not isinstance(self.receipt, bytes) or not self.receipt:
            raise ValueError("completed inbox entry lacks a receipt")
        if len(self.receipt) > MAX_APPLICATION_RECEIPT_BYTES:
            raise ValueError("application receipt exceeds the v0.2 maximum")


class InboxEnqueueDispositionV2(Enum):
    NEW = "new"
    EXISTING_PENDING = "existing_pending"
    EXISTING_COMPLETED = "existing_completed"


@dataclass(frozen=True)
class InboxEnqueueResultV2:
    disposition: InboxEnqueueDispositionV2
    session_id: bytes
    record_digest: bytes

    def validate(self) -> None:
        if not isinstance(self.disposition, InboxEnqueueDispositionV2):
            raise TypeError("inbox enqueue disposition has the wrong type")
        _fixed(self.session_id, SESSION_ID_BYTES, "session_id")
        _fixed(self.record_digest, DIGEST_BYTES, "record_digest")


class FirstApplicationInboxStoreV2(Protocol):
    durable: bool
    distributed: bool
    production_ready: bool

    def enqueue(
        self,
        session_id: bytes,
        record_digest: bytes,
        plaintext: bytes,
    ) -> InboxEnqueueResultV2: ...

    def load(
        self,
        session_id: bytes,
    ) -> FirstApplicationInboxEntryV2 | None: ...

    def complete(
        self,
        session_id: bytes,
        record_digest: bytes,
        receipt: bytes,
    ) -> FirstApplicationInboxEntryV2: ...

    def pending(self, *, limit: int = 100) -> tuple[bytes, ...]: ...


class InMemoryFirstApplicationDeliveryStoreV2:
    durable = False
    distributed = False
    production_ready = False

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._claims: dict[bytes, bytes] = {}

    def claim(
        self,
        session_id: bytes,
        record_digest: bytes,
    ) -> DeliveryClaimResultV2:
        session = _fixed(session_id, SESSION_ID_BYTES, "session_id")
        digest = _fixed(record_digest, DIGEST_BYTES, "record_digest")
        with self._lock:
            existing = self._claims.get(session)
            if existing is None:
                self._claims[session] = digest
                return DeliveryClaimResultV2(
                    DeliveryClaimDispositionV2.NEW,
                    session,
                    digest,
                )
            if existing != digest:
                raise FirstRecordOutboxConflictError(
                    "session already delivered another sequence-zero record"
                )
            return DeliveryClaimResultV2(
                DeliveryClaimDispositionV2.EXISTING,
                session,
                digest,
            )


class FGSFirstRecordDispositionV2(Enum):
    DELIVERED = "delivered"
    ALREADY_DELIVERED = "already_delivered"
    QUEUED = "queued"
    ALREADY_QUEUED = "already_queued"
    ALREADY_COMPLETED = "already_completed"
    REJECTED = "rejected"
    COMMIT_UNCERTAIN = "commit_uncertain"


@dataclass(frozen=True)
class FirstApplicationDeliveryV2:
    session: ActivatedSessionCapabilityV2
    record_digest: bytes
    sequence_number: int
    plaintext: bytes

    def validate(self) -> None:
        self.session.validate()
        _fixed(self.record_digest, DIGEST_BYTES, "record_digest")
        if self.sequence_number != FIRST_APPLICATION_SEQUENCE:
            raise ValueError("first delivery sequence must be zero")
        _plaintext(self.plaintext)


@dataclass(frozen=True)
class FGSFirstRecordProcessResultV2:
    accepted: bool
    disposition: FGSFirstRecordDispositionV2
    failures: tuple[str, ...]
    record: FirstApplicationRecordV2 | None
    delivery: FirstApplicationDeliveryV2 | None
    inbox: InboxEnqueueResultV2 | None = None


class FGSFirstApplicationRecordProcessorV2:
    """Activate a session and commit one authenticated post-activation sink."""

    production_ready = False

    def __init__(
        self,
        *,
        activation_processor: FGSActivationProcessorV2,
        protection_backend: ApplicationProtectionBackendV2,
        delivery_store: FirstApplicationDeliveryStoreV2 | None = None,
        inbox_store: FirstApplicationInboxStoreV2 | None = None,
        suite_registry: Mapping[int, SuiteLimitsV2] = REFERENCE_SUITE_REGISTRY,
    ) -> None:
        if (delivery_store is None) == (inbox_store is None):
            raise ValueError(
                "exactly one delivery_store or inbox_store must be configured"
            )
        self._activation_processor = activation_processor
        self._protection_backend = protection_backend
        self._delivery_store = delivery_store
        self._inbox_store = inbox_store
        self._suite_registry = suite_registry

    @staticmethod
    def _result(
        disposition: FGSFirstRecordDispositionV2,
        failure: str,
    ) -> FGSFirstRecordProcessResultV2:
        return FGSFirstRecordProcessResultV2(
            False,
            disposition,
            (failure,),
            None,
            None,
        )

    def process(self, encoded_record: bytes) -> FGSFirstRecordProcessResultV2:
        try:
            record = decode_first_application_record(
                encoded_record,
                self._suite_registry,
            )
            if (
                encode_first_application_record(record, self._suite_registry)
                != encoded_record
            ):
                raise ValueError("first application record is non-canonical")
        except Exception as error:
            return self._result(
                FGSFirstRecordDispositionV2.REJECTED,
                f"record_encoding:{type(error).__name__}",
            )

        if getattr(self._protection_backend, "suite_id", None) != record.suite_id:
            return self._result(
                FGSFirstRecordDispositionV2.REJECTED,
                "application_protection_suite_mismatch",
            )

        plaintext_output: bytes | None = None
        record_digest_output: bytes | None = None

        def authenticate_record(
            capability: ActivatedSessionCapabilityV2,
        ) -> bool:
            nonlocal plaintext_output, record_digest_output
            capability.validate()
            if (
                capability.session_id != record.session_id
                or capability.response_digest != record.response_digest
            ):
                raise ValueError(
                    "activation capability and application record differ"
                )
            plaintext_output = _plaintext(
                self._protection_backend.open(
                    capability.application_key,
                    nonce_context=derive_first_application_nonce_context(
                        record.suite_id,
                        record.session_id,
                    ),
                    aad=derive_first_application_aad(
                        record,
                        self._suite_registry,
                    ),
                    ciphertext=record.ciphertext,
                )
            )
            record_digest_output = derive_first_application_record_digest(
                record,
                self._suite_registry,
            )
            return True

        activation_result = self._activation_processor.process(
            record.activation_bytes,
            pre_activate_check=authenticate_record,
        )
        if activation_result.accepted is not True:
            disposition = (
                FGSFirstRecordDispositionV2.COMMIT_UNCERTAIN
                if activation_result.disposition
                is ActivationDispositionV2.COMMIT_UNCERTAIN
                else FGSFirstRecordDispositionV2.REJECTED
            )
            return self._result(
                disposition,
                "activation:" + activation_result.failures[0],
            )
        capability = activation_result.capability
        if not isinstance(capability, ActivatedSessionCapabilityV2):
            return self._result(
                FGSFirstRecordDispositionV2.COMMIT_UNCERTAIN,
                "activation_capability_missing",
            )
        try:
            capability.validate()
            bindings = (
                (capability.session_id, record.session_id),
                (capability.response_digest, record.response_digest),
                (capability.identity.use_key, activation_result.record.identity.use_key),  # type: ignore[union-attr]
            )
            if any(actual != expected for actual, expected in bindings):
                raise ValueError("activation capability and application record differ")
        except Exception as error:
            return self._result(
                FGSFirstRecordDispositionV2.COMMIT_UNCERTAIN,
                f"activation_output:{type(error).__name__}",
            )
        if not isinstance(plaintext_output, bytes) or not isinstance(
            record_digest_output,
            bytes,
        ):
            return self._result(
                FGSFirstRecordDispositionV2.COMMIT_UNCERTAIN,
                "pre_activation_output_missing",
            )
        plaintext = plaintext_output
        record_digest = record_digest_output

        if self._inbox_store is not None:
            try:
                enqueue = self._inbox_store.enqueue(
                    record.session_id,
                    record_digest,
                    plaintext,
                )
                if not isinstance(enqueue, InboxEnqueueResultV2):
                    raise TypeError("inbox store returned the wrong type")
                enqueue.validate()
                if (
                    enqueue.session_id != record.session_id
                    or enqueue.record_digest != record_digest
                ):
                    raise ValueError("inbox store changed record identity")
            except FirstRecordOutboxConflictError:
                return self._result(
                    FGSFirstRecordDispositionV2.REJECTED,
                    "inbox_conflict",
                )
            except Exception as error:
                return self._result(
                    FGSFirstRecordDispositionV2.COMMIT_UNCERTAIN,
                    f"inbox_enqueue:{type(error).__name__}",
                )
            disposition = {
                InboxEnqueueDispositionV2.NEW: FGSFirstRecordDispositionV2.QUEUED,
                InboxEnqueueDispositionV2.EXISTING_PENDING: (
                    FGSFirstRecordDispositionV2.ALREADY_QUEUED
                ),
                InboxEnqueueDispositionV2.EXISTING_COMPLETED: (
                    FGSFirstRecordDispositionV2.ALREADY_COMPLETED
                ),
            }[enqueue.disposition]
            return FGSFirstRecordProcessResultV2(
                True,
                disposition,
                (),
                record,
                None,
                enqueue,
            )

        try:
            assert self._delivery_store is not None
            claim = self._delivery_store.claim(record.session_id, record_digest)
            if not isinstance(claim, DeliveryClaimResultV2):
                raise TypeError("delivery store returned the wrong type")
            claim.validate()
            if (
                claim.session_id != record.session_id
                or claim.record_digest != record_digest
            ):
                raise ValueError("delivery store changed record identity")
        except FirstRecordOutboxConflictError:
            return self._result(
                FGSFirstRecordDispositionV2.REJECTED,
                "delivery_conflict",
            )
        except Exception as error:
            return self._result(
                FGSFirstRecordDispositionV2.COMMIT_UNCERTAIN,
                f"delivery_claim:{type(error).__name__}",
            )

        if claim.disposition is DeliveryClaimDispositionV2.EXISTING:
            return FGSFirstRecordProcessResultV2(
                True,
                FGSFirstRecordDispositionV2.ALREADY_DELIVERED,
                (),
                record,
                None,
            )
        if claim.disposition is not DeliveryClaimDispositionV2.NEW:
            return self._result(
                FGSFirstRecordDispositionV2.COMMIT_UNCERTAIN,
                "delivery_claim:ValueError",
            )
        delivery = FirstApplicationDeliveryV2(
            capability,
            record_digest,
            record.sequence_number,
            plaintext,
        )
        try:
            delivery.validate()
        except Exception as error:
            return self._result(
                FGSFirstRecordDispositionV2.COMMIT_UNCERTAIN,
                f"delivery_output:{type(error).__name__}",
            )
        return FGSFirstRecordProcessResultV2(
            True,
            FGSFirstRecordDispositionV2.DELIVERED,
            (),
            record,
            delivery,
        )


def first_application_checkpoint_manifest() -> dict[str, object]:
    return {
        "format": "PQ-SAT-FIRST-APPLICATION-CHECKPOINT-v0.2",
        "access_protocol_version": 2,
        "frame_type": "0x0104",
        "sequence_number": FIRST_APPLICATION_SEQUENCE,
        "aad_domain": FIRST_APPLICATION_AAD_LABEL.decode("ascii"),
        "nonce_context_domain": FIRST_APPLICATION_NONCE_LABEL.decode("ascii"),
        "record_digest_domain": FIRST_APPLICATION_RECORD_LABEL.decode("ascii"),
        "ue_order": [
            "accepted_session_validation",
            "plaintext_identity_reservation",
            "suite_bound_protection",
            "exact_record_finalize",
            "read_back_validation",
            "release_wire_bytes_after_commit",
        ],
        "fgs_order": [
            "canonical_record_and_embedded_activation",
            "suite_bound_application_authentication",
            "client_finished_and_application_authentication",
            "atomic_session_activation",
            "durable_single_host_inbox_enqueue",
            "idempotent_application_dispatch",
        ],
        "claim_boundary": {
            "canonical_first_application_record_implemented": True,
            "activation_in_authenticated_header_implemented": True,
            "sequence_zero_enforced": True,
            "durable_ue_exact_record_outbox_reference_implemented": True,
            "outbox_restart_and_race_tested": True,
            "fgs_one_time_delivery_capability_implemented": True,
            "fgs_delivery_store_durable_or_distributed": True,
            "fgs_delivery_store_single_host_durable_reference_implemented": True,
            "fgs_delivery_store_distributed": False,
            "fgs_protected_plaintext_inbox_reference_implemented": True,
            "fgs_pending_inbox_restart_recovery_implemented": True,
            "application_apply_once_contract_implemented": True,
            "activation_and_delivery_same_transaction": False,
            "external_side_effect_exactly_once": False,
            "production_aead_instantiated": False,
            "physical_power_loss_tested": False,
            "production_ready": False,
            "proof_closed": False,
        },
    }
