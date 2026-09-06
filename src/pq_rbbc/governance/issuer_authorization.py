"""Bounded issuer authorization for the PQ-RBBC system profile v0.1.

This module is a control-plane prototype.  It authenticates an initialization
bundle, verifies a bounded grant under that bundle's separated
``ISSUER_AUTHORIZATION`` key, and atomically consumes issuer-local quota.  It
does not call CAP, produce an issuance proof, or implement blind signing.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from threading import Lock
from typing import Protocol

from pq_rbbc.contracts.system import (
    CONTEXT_BYTES,
    KEY_ID_BYTES,
    SCHEMA_VERSION,
    SYSTEM_PROFILE_PROTOCOL_VERSION,
    ContractError,
    KeyReference,
    KeyRole,
    SystemInitializationBundle,
    _expect_magic,
    _require_fixed_bytes,
    _require_identifier,
    _require_uint,
    _take,
    _take_uint,
)
from pq_rbbc.governance.system_init import (
    ConfigurationAuthenticationVerifier,
    verify_initialization,
)


ISSUER_GRANT_MAGIC = b"PQRBBC-ISSUER-GRANT-V1"
AUTHENTICATED_ISSUER_GRANT_MAGIC = b"PQRBBC-ISSUER-GRANT-AUTH-V1"
ISSUER_AUTHORIZATION_DOMAIN = b"PQ-RBBC/ISSUER-AUTHORIZATION/V1"
GRANT_IDENTIFIER_BYTES = 32
GRANT_DIGEST_BYTES = 32
MAX_GRANT_BYTES = 1 << 16
MAX_AUTHENTICATION_BYTES = 1 << 20
MAX_ISSUER_SID_BYTES = 1 << 16


@dataclass(frozen=True)
class IssuerGrant:
    """Canonical federation authorization for bounded issuer activity."""

    ctx: bytes
    protocol_version: int
    epoch: int
    policy_digest: bytes
    issuer_key_id: bytes
    issuer_authorization_key_id: bytes
    quota: int
    not_before: int
    expiry: int
    grant_identifier: bytes

    def validate(self) -> None:
        _require_fixed_bytes(self.ctx, CONTEXT_BYTES, "grant ctx")
        _require_uint(self.protocol_version, 2, "grant protocol_version")
        if self.protocol_version != SYSTEM_PROFILE_PROTOCOL_VERSION:
            raise ContractError("unsupported grant protocol_version")
        _require_uint(self.epoch, 8, "grant epoch")
        _require_identifier(self.policy_digest, "grant policy_digest")
        _require_identifier(self.issuer_key_id, "grant issuer_key_id")
        _require_identifier(
            self.issuer_authorization_key_id,
            "grant issuer_authorization_key_id",
        )
        _require_uint(self.quota, 8, "grant quota")
        if self.quota == 0:
            raise ContractError("grant quota must be nonzero")
        _require_uint(self.not_before, 8, "grant not_before")
        _require_uint(self.expiry, 8, "grant expiry")
        if self.expiry <= self.not_before:
            raise ContractError("grant expiry must be after not_before")
        _require_identifier(self.grant_identifier, "grant_identifier")

    def encode(self) -> bytes:
        self.validate()
        return b"".join(
            (
                ISSUER_GRANT_MAGIC,
                SCHEMA_VERSION.to_bytes(2, "little"),
                self.ctx,
                self.protocol_version.to_bytes(2, "little"),
                self.epoch.to_bytes(8, "little"),
                self.policy_digest,
                self.issuer_key_id,
                self.issuer_authorization_key_id,
                self.quota.to_bytes(8, "little"),
                self.not_before.to_bytes(8, "little"),
                self.expiry.to_bytes(8, "little"),
                self.grant_identifier,
            )
        )

    @classmethod
    def decode(cls, encoded: bytes) -> "IssuerGrant":
        if not isinstance(encoded, bytes):
            raise ContractError("issuer grant encoding must be bytes")
        offset = _expect_magic(encoded, 0, ISSUER_GRANT_MAGIC, "issuer grant magic")
        schema_version, offset = _take_uint(
            encoded, offset, 2, "issuer grant schema version"
        )
        if schema_version != SCHEMA_VERSION:
            raise ContractError("wrong issuer grant schema version")
        ctx, offset = _take(encoded, offset, CONTEXT_BYTES, "issuer grant ctx")
        protocol_version, offset = _take_uint(
            encoded, offset, 2, "issuer grant protocol version"
        )
        epoch, offset = _take_uint(encoded, offset, 8, "issuer grant epoch")
        policy_digest, offset = _take(
            encoded, offset, 32, "issuer grant policy digest"
        )
        issuer_key_id, offset = _take(
            encoded, offset, KEY_ID_BYTES, "issuer grant issuer key ID"
        )
        issuer_authorization_key_id, offset = _take(
            encoded,
            offset,
            KEY_ID_BYTES,
            "issuer grant authorization key ID",
        )
        quota, offset = _take_uint(encoded, offset, 8, "issuer grant quota")
        not_before, offset = _take_uint(
            encoded, offset, 8, "issuer grant not_before"
        )
        expiry, offset = _take_uint(encoded, offset, 8, "issuer grant expiry")
        grant_identifier, offset = _take(
            encoded,
            offset,
            GRANT_IDENTIFIER_BYTES,
            "issuer grant identifier",
        )
        if offset != len(encoded):
            raise ContractError("issuer grant trailing bytes")
        grant = cls(
            ctx=ctx,
            protocol_version=protocol_version,
            epoch=epoch,
            policy_digest=policy_digest,
            issuer_key_id=issuer_key_id,
            issuer_authorization_key_id=issuer_authorization_key_id,
            quota=quota,
            not_before=not_before,
            expiry=expiry,
            grant_identifier=grant_identifier,
        )
        grant.validate()
        if grant.encode() != encoded:
            raise ContractError("issuer grant encoding is non-canonical")
        return grant

    @property
    def digest(self) -> bytes:
        """SHA-256 digest used as the grant half of consumption identity."""

        return hashlib.sha256(self.encode()).digest()


def issuer_grant_authentication_message(
    grant: IssuerGrant,
    signing_role: KeyRole = KeyRole.ISSUER_AUTHORIZATION,
) -> bytes:
    """Return the domain-separated bytes authenticated by the grant backend."""

    if not isinstance(signing_role, KeyRole):
        raise ContractError("issuer grant signing role must be a KeyRole")
    return b"".join(
        (
            ISSUER_AUTHORIZATION_DOMAIN,
            int(signing_role).to_bytes(2, "little"),
            grant.encode(),
        )
    )


@dataclass(frozen=True)
class AuthenticatedIssuerGrant:
    """Canonical envelope around an externally authenticated issuer grant."""

    grant: IssuerGrant
    signing_role: KeyRole
    authentication: bytes

    @property
    def authentication_message(self) -> bytes:
        return issuer_grant_authentication_message(self.grant, self.signing_role)

    def encode(self) -> bytes:
        if not isinstance(self.signing_role, KeyRole):
            raise ContractError("issuer grant signing role must be a KeyRole")
        grant_bytes = self.grant.encode()
        if not 0 < len(grant_bytes) <= MAX_GRANT_BYTES:
            raise ContractError("issuer grant length is outside bounds")
        if not isinstance(self.authentication, bytes) or not (
            0 < len(self.authentication) <= MAX_AUTHENTICATION_BYTES
        ):
            raise ContractError("issuer grant authentication length is outside bounds")
        return b"".join(
            (
                AUTHENTICATED_ISSUER_GRANT_MAGIC,
                SCHEMA_VERSION.to_bytes(2, "little"),
                int(self.signing_role).to_bytes(2, "little"),
                len(grant_bytes).to_bytes(4, "little"),
                grant_bytes,
                len(self.authentication).to_bytes(4, "little"),
                self.authentication,
            )
        )

    @classmethod
    def decode(cls, encoded: bytes) -> "AuthenticatedIssuerGrant":
        if not isinstance(encoded, bytes):
            raise ContractError("authenticated issuer grant must be bytes")
        offset = _expect_magic(
            encoded,
            0,
            AUTHENTICATED_ISSUER_GRANT_MAGIC,
            "authenticated issuer grant magic",
        )
        schema_version, offset = _take_uint(
            encoded, offset, 2, "authenticated issuer grant version"
        )
        if schema_version != SCHEMA_VERSION:
            raise ContractError("wrong authenticated issuer grant version")
        role_value, offset = _take_uint(
            encoded, offset, 2, "issuer grant signing role"
        )
        try:
            signing_role = KeyRole(role_value)
        except ValueError as error:
            raise ContractError("unknown issuer grant signing role") from error
        grant_length, offset = _take_uint(encoded, offset, 4, "issuer grant length")
        if not 0 < grant_length <= MAX_GRANT_BYTES:
            raise ContractError("issuer grant length is outside bounds")
        grant_bytes, offset = _take(encoded, offset, grant_length, "issuer grant")
        authentication_length, offset = _take_uint(
            encoded, offset, 4, "issuer grant authentication length"
        )
        if not 0 < authentication_length <= MAX_AUTHENTICATION_BYTES:
            raise ContractError("issuer grant authentication length is outside bounds")
        authentication, offset = _take(
            encoded,
            offset,
            authentication_length,
            "issuer grant authentication",
        )
        if offset != len(encoded):
            raise ContractError("authenticated issuer grant trailing bytes")
        envelope = cls(
            grant=IssuerGrant.decode(grant_bytes),
            signing_role=signing_role,
            authentication=authentication,
        )
        if envelope.encode() != encoded:
            raise ContractError("authenticated issuer grant is non-canonical")
        return envelope


class IssuerGrantAuthenticationVerifier(Protocol):
    """Backend boundary for the future PQ issuer-authorization primitive."""

    def verify(
        self,
        key: KeyReference,
        message: bytes,
        authentication: bytes,
    ) -> bool: ...


class QuotaConsumeStatus(Enum):
    CONSUMED = "consumed"
    REPLAY = "replay"
    EXHAUSTED = "exhausted"


@dataclass(frozen=True)
class QuotaConsumeResult:
    status: QuotaConsumeStatus
    remaining: int


class IssuerQuotaStore(Protocol):
    """Atomic quota/replay state boundary owned by the issuer.

    Implementations must check replay, check remaining quota, record the SID,
    and decrement quota as one atomic operation.
    """

    def consume(
        self,
        grant_digest: bytes,
        issuer_sid: bytes,
        quota: int,
    ) -> QuotaConsumeResult: ...


class SingleProcessMemoryQuotaStore:
    """Locked in-memory reference store for tests and single-process demos only.

    It is not durable and does not coordinate multiple processes or machines.
    Production deployments need a transactional shared store implementing
    :class:`IssuerQuotaStore`.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._remaining: dict[bytes, int] = {}
        self._initial_quota: dict[bytes, int] = {}
        self._consumed: set[tuple[bytes, bytes]] = set()

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
        identity = (grant_digest, issuer_sid)
        with self._lock:
            initial_quota = self._initial_quota.setdefault(grant_digest, quota)
            if initial_quota != quota:
                raise ContractError("grant quota changed for existing digest")
            remaining = self._remaining.setdefault(grant_digest, quota)
            if identity in self._consumed:
                return QuotaConsumeResult(QuotaConsumeStatus.REPLAY, remaining)
            if remaining == 0:
                return QuotaConsumeResult(QuotaConsumeStatus.EXHAUSTED, 0)
            remaining -= 1
            self._remaining[grant_digest] = remaining
            self._consumed.add(identity)
            return QuotaConsumeResult(QuotaConsumeStatus.CONSUMED, remaining)


@dataclass(frozen=True)
class IssuerAuthorizationDecision:
    accepted: bool
    failures: tuple[str, ...]
    remaining_quota: int | None
    grant_digest: bytes | None


def _validate_issuer_sid(issuer_sid: bytes) -> None:
    if not isinstance(issuer_sid, bytes) or not (
        0 < len(issuer_sid) <= MAX_ISSUER_SID_BYTES
    ):
        raise ContractError("issuer_sid length is outside bounds")


def _binding_failure(
    grant: IssuerGrant,
    bundle: SystemInitializationBundle,
) -> str | None:
    configuration = bundle.configuration
    expected_authorization_key = bundle.key_for(KeyRole.ISSUER_AUTHORIZATION)
    bindings = (
        (grant.ctx == bundle.ctx, "grant_ctx_mismatch"),
        (
            grant.protocol_version == configuration.protocol_version,
            "grant_protocol_version_mismatch",
        ),
        (grant.epoch == configuration.epoch, "grant_epoch_mismatch"),
        (
            grant.policy_digest == configuration.policy_digest,
            "grant_policy_digest_mismatch",
        ),
        (
            grant.issuer_key_id == configuration.issuer_key_id,
            "grant_issuer_key_id_mismatch",
        ),
        (
            grant.issuer_authorization_key_id
            == expected_authorization_key.key_id,
            "grant_authorization_key_id_mismatch",
        ),
    )
    return next((failure for matches, failure in bindings if not matches), None)


def authorize_issuance(
    authenticated_initialization: bytes,
    authenticated_grant: bytes,
    *,
    trusted_configuration_key: KeyReference,
    initialization_verifier: ConfigurationAuthenticationVerifier,
    grant_verifier: IssuerGrantAuthenticationVerifier,
    quota_store: IssuerQuotaStore,
    issuer_sid: bytes,
    now: int,
) -> IssuerAuthorizationDecision:
    """Authorize one issuance-side SID without producing issuance material.

    Authentication of the system initialization is deliberately the first
    operation.  No grant supplied beside an unauthenticated configuration is
    parsed, verified, or allowed to touch quota state.
    """

    initialization = verify_initialization(
        authenticated_initialization,
        trusted_configuration_key,
        initialization_verifier,
    )
    if not initialization.accepted or initialization.bundle is None:
        return IssuerAuthorizationDecision(
            False,
            tuple(f"initialization:{failure}" for failure in initialization.failures),
            None,
            None,
        )

    try:
        envelope = AuthenticatedIssuerGrant.decode(authenticated_grant)
    except ContractError as error:
        return IssuerAuthorizationDecision(
            False, (f"grant_encoding:{error}",), None, None
        )

    grant = envelope.grant
    grant_digest = grant.digest
    if envelope.signing_role is not KeyRole.ISSUER_AUTHORIZATION:
        return IssuerAuthorizationDecision(
            False, ("grant_wrong_key_role",), None, grant_digest
        )

    binding_failure = _binding_failure(grant, initialization.bundle)
    if binding_failure is not None:
        return IssuerAuthorizationDecision(
            False, (binding_failure,), None, grant_digest
        )

    try:
        _require_uint(now, 8, "authorization time")
        _validate_issuer_sid(issuer_sid)
    except ContractError as error:
        return IssuerAuthorizationDecision(
            False, (f"authorization_input:{error}",), None, grant_digest
        )
    if now < grant.not_before:
        return IssuerAuthorizationDecision(
            False, ("grant_not_yet_valid",), None, grant_digest
        )
    if now >= grant.expiry:
        return IssuerAuthorizationDecision(
            False, ("grant_expired",), None, grant_digest
        )

    authorization_key = initialization.bundle.key_for(
        KeyRole.ISSUER_AUTHORIZATION
    )
    try:
        valid = grant_verifier.verify(
            authorization_key,
            envelope.authentication_message,
            envelope.authentication,
        )
    except Exception as error:  # Fail closed across the authentication boundary.
        return IssuerAuthorizationDecision(
            False,
            (f"grant_authentication_backend:{type(error).__name__}",),
            None,
            grant_digest,
        )
    if valid is not True:
        return IssuerAuthorizationDecision(
            False, ("grant_authentication_invalid",), None, grant_digest
        )

    try:
        consumption = quota_store.consume(grant_digest, issuer_sid, grant.quota)
    except Exception as error:  # Fail closed across the atomic store boundary.
        return IssuerAuthorizationDecision(
            False,
            (f"quota_store:{type(error).__name__}",),
            None,
            grant_digest,
        )
    if (
        not isinstance(consumption, QuotaConsumeResult)
        or not isinstance(consumption.status, QuotaConsumeStatus)
        or not isinstance(consumption.remaining, int)
        or isinstance(consumption.remaining, bool)
        or not 0 <= consumption.remaining <= grant.quota
    ):
        return IssuerAuthorizationDecision(
            False, ("quota_store:invalid_result",), None, grant_digest
        )
    if consumption.status is QuotaConsumeStatus.REPLAY:
        return IssuerAuthorizationDecision(
            False, ("quota_replay",), consumption.remaining, grant_digest
        )
    if consumption.status is QuotaConsumeStatus.EXHAUSTED:
        return IssuerAuthorizationDecision(
            False, ("quota_exhausted",), consumption.remaining, grant_digest
        )
    if consumption.status is not QuotaConsumeStatus.CONSUMED:
        return IssuerAuthorizationDecision(
            False, ("quota_store:invalid_status",), None, grant_digest
        )
    return IssuerAuthorizationDecision(
        True, (), consumption.remaining, grant_digest
    )


def issuer_authorization_manifest(
    envelope: AuthenticatedIssuerGrant,
) -> dict[str, object]:
    """Return public metadata for a fixed control-plane test vector."""

    grant = envelope.grant
    grant_bytes = grant.encode()
    envelope_bytes = envelope.encode()
    return {
        "format": "PQRBBC-ISSUER-AUTHORIZATION-CONTROL-PLANE-1",
        "system_profile": "0.1",
        "grant_schema_version": SCHEMA_VERSION,
        "issuer_authorization_domain": ISSUER_AUTHORIZATION_DOMAIN.decode("ascii"),
        "signing_role": envelope.signing_role.name,
        "grant_encoding_hex": grant_bytes.hex(),
        "grant_bytes": len(grant_bytes),
        "grant_sha256": grant.digest.hex(),
        "authenticated_grant_bytes": len(envelope_bytes),
        "authenticated_grant_sha256": hashlib.sha256(envelope_bytes).hexdigest(),
        "ctx": grant.ctx.hex(),
        "protocol_version": grant.protocol_version,
        "epoch": grant.epoch,
        "policy_digest": grant.policy_digest.hex(),
        "issuer_key_id": grant.issuer_key_id.hex(),
        "issuer_authorization_key_id": grant.issuer_authorization_key_id.hex(),
        "quota": grant.quota,
        "not_before": grant.not_before,
        "expiry": grant.expiry,
        "grant_identifier": grant.grant_identifier.hex(),
        "claim_boundary": {
            "canonical_issuer_grant_codec_implemented": True,
            "authenticated_initialization_required": True,
            "explicit_configuration_trust_anchor_required": True,
            "issuer_authorization_backend_abstract": True,
            "atomic_quota_store_protocol_defined": True,
            "memory_store_single_process_only": True,
            "cap_prove_or_verify_called": False,
            "blind_signing_response_produced": False,
            "fac_threshold_signature_instantiated": False,
            "fac_dkg_implemented": False,
            "production_issuer_authorization_complete": False,
        },
    }
