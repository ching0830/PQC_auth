from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from pq_rbbc.contracts.system import KeyReference, KeyRole
from pq_rbbc.governance.system_init import (
    INITIALIZATION_AUTH_DOMAIN,
    AuthenticatedSystemInitialization,
)
from pq_sat_auth.replay import InvalidTransition
from pq_sat_auth.v2.activation import FGSActivationProcessorV2
from pq_sat_auth.v2.application import (
    FGSFirstApplicationRecordProcessorV2,
    FGSFirstRecordDispositionV2,
)
from pq_sat_auth.v2.replay import GrantStateV2
from pq_sat_auth.v2.storage.sqlite_scoped_revocation import (
    ACCESS_PROTOCOL_VERSION,
    APPLICATION_ID,
    QUERY_BYTES,
    SCHEMA_VERSION,
    AuthenticatedRevocationCommandV2,
    RevocationCommandV2,
    RevocationIngestDispositionV2,
    RevocationScopeV2,
    SQLiteFGSScopedRevocationStoreV2,
    decode_registered_activation_query,
    derive_registered_query_checksum,
    sqlite_scoped_revocation_manifest,
)
from pq_sat_auth.v2.storage.sqlite_unified import (
    UnifiedActivationInboxIntegrityError,
)
from tests.system.test_pq_sat_auth_activation_v2 import ActivationKeySchedule
from tests.system.test_pq_sat_auth_application_inbox_v2 import (
    InboxProtectionTestBackend,
)
from tests.system.test_pq_sat_auth_first_application_v2 import (
    PLAINTEXT,
    FirstApplicationFixture,
)
from tests.system.test_pq_sat_auth_grant_v2 import GrantClock
from tests.system.test_pq_sat_auth_processor_v2 import (
    NOW,
    ConfigurationAuthenticationTestBackend,
    fixed,
)
from tests.system.test_pq_sat_auth_sqlite_replay_v2 import (
    ReplayProtectionTestBackend,
)


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = (
    ROOT / "manifests" / "pq_sat_auth_fgs_scoped_revocation_sqlite_v0_2.json"
)


class RevocationAuthenticationTestBackend:
    production_ready = False

    def __init__(self) -> None:
        self.calls = 0
        self.broken = False
        self.result: object | None = None

    @staticmethod
    def sign(key: KeyReference, message: bytes) -> bytes:
        return hashlib.sha256(
            b"TEST-ONLY/SCOPED-REVOCATION/"
            + key.public_key_digest
            + message
        ).digest()

    def verify(
        self,
        key: KeyReference,
        message: bytes,
        authentication: bytes,
    ):
        self.calls += 1
        if self.broken:
            raise RuntimeError("test revocation verifier failure")
        if self.result is not None:
            return self.result
        return authentication == self.sign(key, message)


class IngestAfterSnapshot:
    def __init__(self, fixture, envelope) -> None:
        self.fixture = fixture
        self.envelope = envelope

    def snapshot(self, query):
        checked = self.fixture.scoped.snapshot(query)
        result = self.fixture.ingest(self.envelope)
        if not result.accepted:
            raise AssertionError(result.failures)
        return checked


class ScopedRevocationFixture(FirstApplicationFixture):
    def setUp(self) -> None:
        super().setUp()
        self.scoped_path = Path(self.temporary.name) / "fgs-scoped.sqlite3"
        self.replay_protection = ReplayProtectionTestBackend()
        self.inbox_protection = InboxProtectionTestBackend()
        self.scoped = self.open_scoped(self.scoped_path)
        self.install_pending_grant(self.scoped)
        assert self.recovery.last_state is not None
        self.query = FGSActivationProcessorV2._activation_revocation_query(
            self.response,
            self.grant_record,
            self.recovery.last_state,
        )
        self.snapshot = self.scoped.register_activation_query(
            self.query,
            base_generation=self.grant_record.revocation_generation,
        )
        self.configuration_key = self.bundle.key_for(
            KeyRole.FEDERATION_CONFIGURATION
        )
        self.command_verifier = RevocationAuthenticationTestBackend()

    def open_scoped(self, path: Path) -> SQLiteFGSScopedRevocationStoreV2:
        return SQLiteFGSScopedRevocationStoreV2(
            path,
            self.replay_protection,
            self.inbox_protection,
            busy_timeout_ms=20_000,
        )

    def install_pending_grant(
        self,
        store: SQLiteFGSScopedRevocationStoreV2,
    ) -> None:
        grant = self.grant_record
        store.reserve(
            grant.identity,
            attempt_id=grant.attempt_id,
            request_digest=grant.request_digest,
            serving_context_digest=grant.serving_context_digest,
            reserved_at=max(0, grant.consumed_at - 1),
            lease_deadline=grant.consumed_at,
            revocation_generation=grant.revocation_generation,
        )
        store.commit_grant(
            grant.identity,
            attempt_id=grant.attempt_id,
            request_digest=grant.request_digest,
            transcript_digest=grant.transcript_digest,
            session_id=grant.session_id,
            response_digest=grant.response_digest,
            sealed_response=grant.sealed_response,
            sealed_session_state=grant.sealed_session_state,
            serving_context_digest=grant.serving_context_digest,
            fgs_id=grant.fgs_id,
            revocation_generation=grant.revocation_generation,
            consumed_at=grant.consumed_at,
            activation_deadline=grant.activation_deadline,
            session_expiry=grant.session_expiry,
            retention_deadline=grant.retention_deadline,
        )

    def command(
        self,
        scope: RevocationScopeV2 = RevocationScopeV2.SESSION,
        *,
        target: bytes | None = None,
        generation: int = 20,
        command_label: bytes = b"command-20",
        issued_at: int = NOW - 1,
        expires_at: int = NOW + 1_000,
        **changes: object,
    ) -> RevocationCommandV2:
        scope_target = (
            {
                RevocationScopeV2.ACCESS_CONFIGURATION: (
                    self.query.system_config_digest
                ),
                RevocationScopeV2.FGS_AUTHENTICATION_KEY: (
                    self.query.fgs_auth_key_id
                ),
                RevocationScopeV2.TICKET_USE: self.query.ticket_use_key,
                RevocationScopeV2.SESSION: self.query.session_id,
            }[scope]
            if target is None
            else target
        )
        command = RevocationCommandV2(
            access_protocol_version=ACCESS_PROTOCOL_VERSION,
            ctx=self.bundle.ctx,
            system_bundle_digest=bytes.fromhex(self.bundle.sha256),
            epoch=self.bundle.configuration.epoch,
            policy_digest=self.bundle.configuration.policy_digest,
            signer_key_id=self.configuration_key.key_id,
            scope=scope,
            scope_target=scope_target,
            generation=generation,
            issued_at=issued_at,
            authorization_expires_at=expires_at,
            command_id=fixed(command_label),
            reason_digest=fixed(b"reason/" + command_label),
        )
        return replace(command, **changes)

    def authenticated_command(
        self,
        command: RevocationCommandV2 | None = None,
        *,
        signing_role: KeyRole = KeyRole.FEDERATION_CONFIGURATION,
        signing_key: KeyReference | None = None,
    ) -> AuthenticatedRevocationCommandV2:
        command = self.command() if command is None else command
        key = self.configuration_key if signing_key is None else signing_key
        draft = AuthenticatedRevocationCommandV2(
            command,
            signing_role,
            b"unsigned-test-placeholder",
        )
        return replace(
            draft,
            authentication=RevocationAuthenticationTestBackend.sign(
                key,
                draft.authentication_message,
            ),
        )

    def ingest(
        self,
        envelope: AuthenticatedRevocationCommandV2,
        *,
        store: SQLiteFGSScopedRevocationStoreV2 | None = None,
        initialization: bytes | None = None,
        trusted_key: KeyReference | None = None,
        verifier: object | None = None,
        now: int = NOW,
    ):
        return (self.scoped if store is None else store).ingest_authenticated_revocation(
            (
                self.initialization.encode()
                if initialization is None
                else initialization
            ),
            envelope.encode(),
            trusted_configuration_key=(
                self.configuration_key if trusted_key is None else trusted_key
            ),
            initialization_verifier=ConfigurationAuthenticationTestBackend(),
            command_verifier=(
                self.command_verifier if verifier is None else verifier
            ),
            now=now,
        )

    def scoped_activation_processor(
        self,
        provider=None,
    ) -> FGSActivationProcessorV2:
        return FGSActivationProcessorV2(
            replay_store=self.scoped,
            clock=GrantClock(),
            revocation_provider=self.scoped if provider is None else provider,
            key_schedule_backend=ActivationKeySchedule(),
            recovery_backend=self.recovery,
        )

    def scoped_first_processor(
        self,
        provider=None,
    ) -> FGSFirstApplicationRecordProcessorV2:
        return FGSFirstApplicationRecordProcessorV2(
            activation_processor=self.scoped_activation_processor(provider),
            protection_backend=self.application_protection,
            atomic_inbox_store=self.scoped,
        )


class ScopedRevocationCodecTests(ScopedRevocationFixture):
    def test_manifest_matches_implementation(self) -> None:
        self.assertEqual(
            json.loads(MANIFEST.read_text(encoding="utf-8")),
            sqlite_scoped_revocation_manifest(),
        )

    def test_command_and_envelope_are_canonical_and_strict(self) -> None:
        command = self.command()
        encoded = command.encode()
        self.assertEqual(len(encoded), 291)
        self.assertEqual(RevocationCommandV2.decode(encoded), command)
        envelope = self.authenticated_command(command)
        wire = envelope.encode()
        self.assertEqual(
            AuthenticatedRevocationCommandV2.decode(wire),
            envelope,
        )
        self.assertEqual(
            hashlib.sha256(wire).hexdigest(),
            "a82a979b7274ba3fb4f24bcf01e673ec60f34a8d19b062ab883c9c5acdbedf91",
        )
        for candidate in (
            encoded[:-1],
            encoded + b"\x00",
            wire[:-1],
            wire + b"\x00",
        ):
            with self.subTest(length=len(candidate)):
                decoder = (
                    RevocationCommandV2.decode
                    if len(candidate) <= len(encoded) + 1
                    else AuthenticatedRevocationCommandV2.decode
                )
                with self.assertRaises(Exception):
                    decoder(candidate)

        unknown_scope = bytearray(encoded)
        scope_offset = len(encoded) - (32 + 8 + 8 + 8 + 32 + 32) - 2
        unknown_scope[scope_offset : scope_offset + 2] = (65535).to_bytes(
            2,
            "big",
        )
        with self.assertRaisesRegex(Exception, "scope"):
            RevocationCommandV2.decode(bytes(unknown_scope))

    def test_registered_query_codec_and_checksum_are_exact(self) -> None:
        encoded = self.query.encode()
        self.assertEqual(len(encoded), QUERY_BYTES)
        self.assertEqual(decode_registered_activation_query(encoded), self.query)
        self.assertEqual(len(derive_registered_query_checksum(encoded)), 32)
        for changed in (encoded[:-1], encoded + b"\x00"):
            with self.assertRaises(UnifiedActivationInboxIntegrityError):
                decode_registered_activation_query(changed)

    def test_schema_has_exact_five_tables_and_distinct_identity(self) -> None:
        connection = sqlite3.connect(self.scoped_path)
        try:
            self.assertEqual(
                connection.execute("PRAGMA application_id").fetchone(),
                (APPLICATION_ID,),
            )
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone(),
                (SCHEMA_VERSION,),
            )
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' "
                    "AND name NOT LIKE 'sqlite_%'"
                )
            }
        finally:
            connection.close()
        self.assertEqual(
            tables,
            {
                "fgs_replay_records",
                "first_application_inbox",
                "activation_revocation_fences",
                "activation_revocation_queries",
                "authenticated_revocation_commands",
            },
        )


class ScopedRevocationIngestTests(ScopedRevocationFixture):
    def test_each_scope_fans_out_only_to_matching_registered_queries(self) -> None:
        q1 = self.query
        q2 = replace(
            q1,
            ticket_use_key=fixed(b"scope/q2-ticket"),
            request_digest=fixed(b"scope/q2-request"),
            response_digest=fixed(b"scope/q2-response"),
            session_id=fixed(b"scope/q2-session"),
        )
        q3 = replace(
            q1,
            fgs_auth_key_id=fixed(b"scope/q3-fgs-key"),
            ticket_use_key=fixed(b"scope/q3-ticket"),
            request_digest=fixed(b"scope/q3-request"),
            response_digest=fixed(b"scope/q3-response"),
            session_id=fixed(b"scope/q3-session"),
        )
        q4 = replace(
            q1,
            system_config_digest=fixed(b"scope/q4-config"),
            ticket_use_key=fixed(b"scope/q4-ticket"),
            request_digest=fixed(b"scope/q4-request"),
            response_digest=fixed(b"scope/q4-response"),
            session_id=fixed(b"scope/q4-session"),
        )
        cases = (
            (
                RevocationScopeV2.ACCESS_CONFIGURATION,
                q1.system_config_digest,
                "configuration_revoked",
                (True, True, True, False),
            ),
            (
                RevocationScopeV2.FGS_AUTHENTICATION_KEY,
                q1.fgs_auth_key_id,
                "fgs_key_revoked",
                (True, True, False, True),
            ),
            (
                RevocationScopeV2.TICKET_USE,
                q1.ticket_use_key,
                "ticket_revoked",
                (True, False, False, False),
            ),
            (
                RevocationScopeV2.SESSION,
                q1.session_id,
                "session_revoked",
                (True, False, False, False),
            ),
        )
        for index, (scope, target, flag, expected) in enumerate(cases):
            with self.subTest(scope=scope.name):
                path = Path(self.temporary.name) / f"scope-{index}.sqlite3"
                store = self.open_scoped(path)
                for query in (q1, q2, q3, q4):
                    store.register_activation_query(
                        query,
                        base_generation=self.grant_record.revocation_generation,
                    )
                command = self.command(
                    scope,
                    target=target,
                    command_label=f"scope-{index}".encode("ascii"),
                )
                result = self.ingest(
                    self.authenticated_command(command),
                    store=store,
                )
                self.assertTrue(result.accepted, result.failures)
                self.assertEqual(
                    result.matching_registered_queries,
                    sum(expected),
                )
                actual = tuple(
                    getattr(store.snapshot(query), flag)
                    for query in (q1, q2, q3, q4)
                )
                self.assertEqual(actual, expected)

    def test_command_applies_to_matching_query_registered_later(self) -> None:
        path = Path(self.temporary.name) / "future-query.sqlite3"
        store = self.open_scoped(path)
        command = self.command(
            RevocationScopeV2.TICKET_USE,
            command_label=b"future-ticket",
        )
        result = self.ingest(
            self.authenticated_command(command),
            store=store,
        )
        self.assertTrue(result.accepted, result.failures)
        self.assertEqual(result.matching_registered_queries, 0)
        snapshot = store.register_activation_query(
            self.query,
            base_generation=self.grant_record.revocation_generation,
        )
        self.assertTrue(snapshot.ticket_revoked)
        self.assertEqual(snapshot.generation, command.generation)

    def test_exact_replay_is_idempotent_and_generation_must_advance(self) -> None:
        envelope = self.authenticated_command()
        first = self.ingest(envelope)
        replay = self.ingest(envelope)
        self.assertTrue(first.accepted, first.failures)
        self.assertTrue(replay.accepted, replay.failures)
        self.assertIs(
            first.disposition,
            RevocationIngestDispositionV2.INGESTED,
        )
        self.assertIs(replay.disposition, RevocationIngestDispositionV2.REPLAY)
        self.assertEqual(self.scoped.command_count(), 1)

        stale_command = self.command(
            generation=envelope.command.generation,
            command_label=b"stale-generation",
        )
        stale = self.ingest(self.authenticated_command(stale_command))
        self.assertFalse(stale.accepted)
        self.assertEqual(stale.failures, ("command_commit:InvalidTransition",))
        self.assertEqual(self.scoped.command_count(), 1)

        changed_identity = replace(
            envelope.command,
            reason_digest=fixed(b"changed-reason"),
        )
        changed = self.ingest(self.authenticated_command(changed_identity))
        self.assertFalse(changed.accepted)
        self.assertEqual(
            changed.failures,
            ("command_commit:InvalidTransition",),
        )
        self.assertEqual(self.scoped.command_count(), 1)

    def test_command_and_materialized_fence_survive_database_restart(self) -> None:
        envelope = self.authenticated_command()
        first = self.ingest(envelope)
        self.assertTrue(first.accepted, first.failures)

        reopened = self.open_scoped(self.scoped_path)
        self.assertEqual(reopened.command_count(), 1)
        self.assertTrue(reopened.snapshot(self.query).session_revoked)
        replay = self.ingest(envelope, store=reopened)
        self.assertTrue(replay.accepted, replay.failures)
        self.assertIs(replay.disposition, RevocationIngestDispositionV2.REPLAY)
        self.assertEqual(reopened.command_count(), 1)

    def test_authority_bundle_or_key_rotation_is_not_implicitly_accepted(
        self,
    ) -> None:
        first = self.ingest(self.authenticated_command())
        self.assertTrue(first.accepted, first.failures)

        alternate_key = KeyReference(
            KeyRole.FEDERATION_CONFIGURATION,
            fixed(b"alternate-configuration-key-id"),
            fixed(b"alternate-configuration-public-key"),
        )
        alternate_bundle = replace(
            self.bundle,
            keys=tuple(
                alternate_key
                if key.role is KeyRole.FEDERATION_CONFIGURATION
                else key
                for key in self.bundle.keys
            ),
        )
        alternate_initialization = AuthenticatedSystemInitialization(
            alternate_bundle,
            ConfigurationAuthenticationTestBackend.sign(
                alternate_key,
                INITIALIZATION_AUTH_DOMAIN + alternate_bundle.encode(),
            ),
        )
        rotated_command = replace(
            self.command(
                generation=21,
                command_label=b"rotated-authority",
            ),
            system_bundle_digest=bytes.fromhex(alternate_bundle.sha256),
            signer_key_id=alternate_key.key_id,
        )
        result = self.ingest(
            self.authenticated_command(
                rotated_command,
                signing_key=alternate_key,
            ),
            initialization=alternate_initialization.encode(),
            trusted_key=alternate_key,
        )
        self.assertFalse(result.accepted)
        self.assertEqual(
            result.failures,
            ("command_commit:InvalidTransition",),
        )
        self.assertEqual(self.scoped.command_count(), 1)

    def test_initialization_binding_authentication_and_time_fail_closed(
        self,
    ) -> None:
        envelope = self.authenticated_command()
        bad_initialization = bytearray(self.initialization.encode())
        bad_initialization[-1] ^= 1
        bad_init = self.ingest(
            envelope,
            initialization=bytes(bad_initialization),
        )
        self.assertFalse(bad_init.accepted)
        self.assertTrue(bad_init.failures[0].startswith("initialization:"))
        self.assertEqual(self.command_verifier.calls, 0)

        mutations = (
            ("command_ctx_mismatch", {"ctx": fixed(b"wrong-ctx")}),
            (
                "command_system_bundle_mismatch",
                {"system_bundle_digest": fixed(b"wrong-bundle")},
            ),
            ("command_epoch_mismatch", {"epoch": 92}),
            (
                "command_policy_mismatch",
                {"policy_digest": fixed(b"wrong-policy")},
            ),
            (
                "command_signer_key_mismatch",
                {"signer_key_id": fixed(b"wrong-signer")},
            ),
        )
        for failure, changes in mutations:
            with self.subTest(failure=failure):
                command = replace(envelope.command, **changes)
                result = self.ingest(self.authenticated_command(command))
                self.assertEqual(result.failures, (failure,))

        wrong_role = self.authenticated_command(
            envelope.command,
            signing_role=KeyRole.OPENING_AUTHORIZATION,
        )
        self.assertEqual(
            self.ingest(wrong_role).failures,
            ("command_wrong_key_role",),
        )
        future = self.authenticated_command(
            self.command(issued_at=NOW + 1, expires_at=NOW + 2)
        )
        self.assertEqual(
            self.ingest(future).failures,
            ("command_not_yet_valid",),
        )
        expired = self.authenticated_command(
            self.command(issued_at=NOW - 2, expires_at=NOW)
        )
        self.assertEqual(
            self.ingest(expired).failures,
            ("command_authorization_expired",),
        )
        too_long = self.authenticated_command(
            self.command(
                expires_at=self.bundle.configuration.expiry_bucket + 1
            )
        )
        self.assertEqual(
            self.ingest(too_long).failures,
            ("command_exceeds_configuration_expiry",),
        )

        mutated_signature = replace(
            envelope,
            authentication=bytes([envelope.authentication[0] ^ 1])
            + envelope.authentication[1:],
        )
        self.assertEqual(
            self.ingest(mutated_signature).failures,
            ("command_authentication_invalid",),
        )
        self.command_verifier.broken = True
        self.assertEqual(
            self.ingest(envelope).failures,
            ("command_authentication_backend:RuntimeError",),
        )
        self.assertEqual(self.scoped.command_count(), 0)

    def test_command_and_fanout_roll_back_together(self) -> None:
        connection = sqlite3.connect(self.scoped_path)
        try:
            connection.execute(
                "DELETE FROM activation_revocation_fences "
                "WHERE query_digest = ?",
                (self.query.digest,),
            )
            connection.commit()
        finally:
            connection.close()
        result = self.ingest(self.authenticated_command())
        self.assertFalse(result.accepted)
        self.assertEqual(
            result.failures,
            ("command_commit:UnifiedActivationInboxIntegrityError",),
        )
        self.assertEqual(self.scoped.command_count(), 0)

    def test_direct_unauthenticated_publication_is_disabled(self) -> None:
        with self.assertRaisesRegex(InvalidTransition, "authenticated"):
            self.scoped.publish_activation_revocation(self.snapshot)

    def test_query_and_command_row_mutations_fail_closed(self) -> None:
        envelope = self.authenticated_command()
        accepted = self.ingest(envelope)
        self.assertTrue(accepted.accepted, accepted.failures)

        connection = sqlite3.connect(self.scoped_path)
        try:
            connection.execute(
                "UPDATE activation_revocation_queries "
                "SET query_checksum = ? WHERE query_digest = ?",
                (b"x" * 32, self.query.digest),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(UnifiedActivationInboxIntegrityError):
            self.scoped.snapshot(self.query)

        command_path = Path(self.temporary.name) / "command-corrupt.sqlite3"
        command_store = self.open_scoped(command_path)
        result = self.ingest(envelope, store=command_store)
        self.assertTrue(result.accepted, result.failures)
        connection = sqlite3.connect(command_path)
        try:
            connection.execute(
                "UPDATE authenticated_revocation_commands "
                "SET envelope_checksum = ?",
                (b"x" * 32,),
            )
            connection.commit()
        finally:
            connection.close()
        retry = self.ingest(envelope, store=command_store)
        self.assertFalse(retry.accepted)
        self.assertEqual(
            retry.failures,
            ("command_commit:UnifiedActivationInboxIntegrityError",),
        )


class ScopedRevocationActivationTests(ScopedRevocationFixture):
    def test_revoked_session_is_rejected_without_activation(self) -> None:
        result = self.ingest(self.authenticated_command())
        self.assertTrue(result.accepted, result.failures)
        prepared = self.prepare()
        rejected = self.scoped_first_processor().process(prepared.record_bytes)
        self.assertFalse(rejected.accepted)
        self.assertEqual(
            rejected.failures,
            ("activation:activation_revoked",),
        )
        replay = self.scoped.lookup(self.grant_record.identity)
        self.assertIs(  # type: ignore[union-attr]
            replay.state,
            GrantStateV2.CONSUMED_PENDING_CONFIRM,
        )
        self.assertEqual(self.scoped.inbox_count(), 0)

    def test_ingest_between_snapshot_and_commit_rolls_back_activation(self) -> None:
        prepared = self.prepare()
        envelope = self.authenticated_command()
        result = self.scoped_first_processor(
            IngestAfterSnapshot(self, envelope)
        ).process(prepared.record_bytes)
        self.assertFalse(result.accepted)
        self.assertIs(
            result.disposition,
            FGSFirstRecordDispositionV2.COMMIT_UNCERTAIN,
        )
        self.assertIn("ActivationRevocationFenceChanged", result.failures[0])
        replay = self.scoped.lookup(self.grant_record.identity)
        self.assertIs(  # type: ignore[union-attr]
            replay.state,
            GrantStateV2.CONSUMED_PENDING_CONFIRM,
        )
        self.assertEqual(self.scoped.inbox_count(), 0)

    def test_nonmatching_authenticated_command_does_not_block_activation(
        self,
    ) -> None:
        command = self.command(
            target=fixed(b"another-session"),
            command_label=b"unrelated-session",
        )
        result = self.ingest(self.authenticated_command(command))
        self.assertTrue(result.accepted, result.failures)
        self.assertEqual(result.matching_registered_queries, 0)
        prepared = self.prepare()
        accepted = self.scoped_first_processor().process(prepared.record_bytes)
        self.assertTrue(accepted.accepted, accepted.failures)
        self.assertIs(accepted.disposition, FGSFirstRecordDispositionV2.QUEUED)

    def test_concurrent_ingest_and_activation_have_one_valid_order(self) -> None:
        prepared = self.prepare()
        envelope = self.authenticated_command()
        start = threading.Barrier(2)

        def activate():
            start.wait()
            return self.scoped_first_processor().process(prepared.record_bytes)

        def revoke():
            start.wait()
            return self.ingest(envelope)

        with ThreadPoolExecutor(max_workers=2) as executor:
            activation_future = executor.submit(activate)
            revocation_future = executor.submit(revoke)
            activation = activation_future.result(timeout=10)
            revocation = revocation_future.result(timeout=10)
        self.assertTrue(revocation.accepted, revocation.failures)
        replay = self.scoped.lookup(self.grant_record.identity)
        if activation.accepted:
            self.assertIs(activation.disposition, FGSFirstRecordDispositionV2.QUEUED)
            self.assertIs(  # type: ignore[union-attr]
                replay.state,
                GrantStateV2.CONSUMED_ACTIVE,
            )
            self.assertEqual(self.scoped.inbox_count(), 1)
        else:
            self.assertIn(
                activation.disposition,
                (
                    FGSFirstRecordDispositionV2.REJECTED,
                    FGSFirstRecordDispositionV2.COMMIT_UNCERTAIN,
                ),
            )
            self.assertIs(  # type: ignore[union-attr]
                replay.state,
                GrantStateV2.CONSUMED_PENDING_CONFIRM,
            )
            self.assertEqual(self.scoped.inbox_count(), 0)


if __name__ == "__main__":
    unittest.main()
