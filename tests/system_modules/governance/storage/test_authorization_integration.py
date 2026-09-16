#!/usr/bin/env python3
"""Authorize-issuance control flow with the persistent SQLite store."""

from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from pq_rbbc.contracts.system import (
    KeyReference,
    KeyRole,
    SystemConfiguration,
    SystemInitializationBundle,
    ThresholdPolicy,
)
from pq_rbbc.governance.issuer_authorization import (
    AuthenticatedIssuerGrant,
    IssuerGrant,
    authorize_issuance,
    issuer_grant_authentication_message,
)
from pq_rbbc.governance.storage import SQLiteIssuerQuotaStore
from pq_rbbc.governance.system_init import (
    INITIALIZATION_AUTH_DOMAIN,
    AuthenticatedSystemInitialization,
)


VALID_TIME = 1_750_000_000


def _fixed(label: bytes) -> bytes:
    return hashlib.sha256(b"PQRBBC/sqlite-authorization-test/" + label).digest()


class _DeterministicTestAuthentication:
    """Test-only digest fixture; this is not a cryptographic signature."""

    @staticmethod
    def sign(key: KeyReference, message: bytes) -> bytes:
        return hashlib.sha256(key.public_key_digest + message).digest()

    def verify(
        self, key: KeyReference, message: bytes, authentication: bytes
    ) -> bool:
        return authentication == self.sign(key, message)


def _bundle() -> SystemInitializationBundle:
    keys = tuple(
        KeyReference(
            role=role,
            key_id=_fixed(b"key-id/" + role.name.encode("ascii")),
            public_key_digest=_fixed(b"public-key/" + role.name.encode("ascii")),
        )
        for role in KeyRole
    )
    issuer_key = next(
        key for key in keys if key.role is KeyRole.ISSUER_VERIFICATION
    )
    opening_key = next(
        key for key in keys if key.role is KeyRole.OPENING_ENCRYPTION
    )
    return SystemInitializationBundle(
        configuration=SystemConfiguration(
            protocol_version=1,
            epoch=71,
            domain=_fixed(b"domain"),
            policy_digest=_fixed(b"policy"),
            expiry_bucket=1_900_000_000,
            oa_key_id=opening_key.key_id,
            issuer_key_id=issuer_key.key_id,
        ),
        common_parameters_digest=_fixed(b"common-parameters"),
        federation_policy=ThresholdPolicy(member_count=5, threshold=3),
        opening_policy=ThresholdPolicy(member_count=7, threshold=5),
        keys=keys,
    )


def _initialization() -> AuthenticatedSystemInitialization:
    bundle = _bundle()
    key = bundle.key_for(KeyRole.FEDERATION_CONFIGURATION)
    message = INITIALIZATION_AUTH_DOMAIN + bundle.encode()
    return AuthenticatedSystemInitialization(
        bundle=bundle,
        authentication=_DeterministicTestAuthentication.sign(key, message),
    )


def _grant(quota: int = 2) -> IssuerGrant:
    bundle = _bundle()
    return IssuerGrant(
        ctx=bundle.ctx,
        protocol_version=bundle.configuration.protocol_version,
        epoch=bundle.configuration.epoch,
        policy_digest=bundle.configuration.policy_digest,
        issuer_key_id=bundle.configuration.issuer_key_id,
        issuer_authorization_key_id=bundle.key_for(
            KeyRole.ISSUER_AUTHORIZATION
        ).key_id,
        quota=quota,
        not_before=1_700_000_000,
        expiry=1_800_000_000,
        grant_identifier=_fixed(b"grant-id"),
    )


def _authenticated_grant(
    grant: IssuerGrant | None = None,
    *,
    role: KeyRole = KeyRole.ISSUER_AUTHORIZATION,
) -> AuthenticatedIssuerGrant:
    grant = _grant() if grant is None else grant
    key = _bundle().key_for(KeyRole.ISSUER_AUTHORIZATION)
    message = issuer_grant_authentication_message(grant, role)
    return AuthenticatedIssuerGrant(
        grant=grant,
        signing_role=role,
        authentication=_DeterministicTestAuthentication.sign(key, message),
    )


def _authorize(
    store: SQLiteIssuerQuotaStore,
    initialization: bytes,
    grant: bytes,
    *,
    now: int = VALID_TIME,
):
    trusted_key = _bundle().key_for(KeyRole.FEDERATION_CONFIGURATION)
    verifier = _DeterministicTestAuthentication()
    return authorize_issuance(
        initialization,
        grant,
        trusted_configuration_key=trusted_key,
        initialization_verifier=verifier,
        grant_verifier=verifier,
        quota_store=store,
        issuer_sid=b"same-validation-sid",
        now=now,
    )


class PersistentAuthorizationControlFlowTests(unittest.TestCase):
    def test_all_validation_failures_precede_atomic_consumption(self) -> None:
        initialization = _initialization()
        good_grant = _authenticated_grant()
        base_grant = good_grant.grant

        bad_initialization = bytearray(initialization.encode())
        bad_initialization[-1] ^= 1
        bad_authentication = bytearray(good_grant.encode())
        bad_authentication[-1] ^= 1
        cases = {
            "initialization_authentication": (
                bytes(bad_initialization),
                good_grant.encode(),
                VALID_TIME,
            ),
            "grant_role": (
                initialization.encode(),
                _authenticated_grant(
                    base_grant, role=KeyRole.OPENING_AUTHORIZATION
                ).encode(),
                VALID_TIME,
            ),
            "ctx": (
                initialization.encode(),
                _authenticated_grant(
                    replace(
                        base_grant,
                        ctx=bytes([base_grant.ctx[0] ^ 1]) + base_grant.ctx[1:],
                    )
                ).encode(),
                VALID_TIME,
            ),
            "policy": (
                initialization.encode(),
                _authenticated_grant(
                    replace(base_grant, policy_digest=_fixed(b"other-policy"))
                ).encode(),
                VALID_TIME,
            ),
            "epoch": (
                initialization.encode(),
                _authenticated_grant(
                    replace(base_grant, epoch=base_grant.epoch + 1)
                ).encode(),
                VALID_TIME,
            ),
            "issuer_key": (
                initialization.encode(),
                _authenticated_grant(
                    replace(base_grant, issuer_key_id=_fixed(b"other-issuer"))
                ).encode(),
                VALID_TIME,
            ),
            "authorization_key": (
                initialization.encode(),
                _authenticated_grant(
                    replace(
                        base_grant,
                        issuer_authorization_key_id=_fixed(b"other-auth-key"),
                    )
                ).encode(),
                VALID_TIME,
            ),
            "not_before": (
                initialization.encode(),
                good_grant.encode(),
                base_grant.not_before - 1,
            ),
            "expiry": (
                initialization.encode(),
                good_grant.encode(),
                base_grant.expiry,
            ),
            "grant_authentication": (
                initialization.encode(),
                bytes(bad_authentication),
                VALID_TIME,
            ),
        }

        for name, (initialization_bytes, grant_bytes, now) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                store = SQLiteIssuerQuotaStore(str(Path(directory) / "quota.sqlite3"))
                rejected = _authorize(
                    store, initialization_bytes, grant_bytes, now=now
                )
                self.assertFalse(rejected.accepted)
                accepted = _authorize(
                    store,
                    initialization.encode(),
                    good_grant.encode(),
                )
                self.assertTrue(accepted.accepted, accepted.failures)
                self.assertEqual(accepted.remaining_quota, 1)

    def test_store_busy_error_never_reports_authorization_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_path = str(Path(directory) / "quota.sqlite3")
            store = SQLiteIssuerQuotaStore(database_path, busy_timeout_ms=25)
            locker = sqlite3.connect(database_path, isolation_level=None)
            try:
                locker.execute("BEGIN IMMEDIATE")
                decision = _authorize(
                    store,
                    _initialization().encode(),
                    _authenticated_grant().encode(),
                )
                self.assertFalse(decision.accepted)
                self.assertEqual(
                    decision.failures,
                    ("quota_store:SQLiteQuotaStoreBusyError",),
                )
                locker.rollback()
            finally:
                locker.close()

            accepted = _authorize(
                store,
                _initialization().encode(),
                _authenticated_grant().encode(),
            )
            self.assertTrue(accepted.accepted, accepted.failures)
            self.assertEqual(accepted.remaining_quota, 1)


if __name__ == "__main__":
    unittest.main()
